//! Drives one-time PIN pairing: accepts inbound connections, initiates outbound
//! ones, derives the PIN, and - once both sides confirm - persists trust.
//! Framework-agnostic: callers supply a plain callback for pairing events, so
//! this crate stays Tauri-free.

use ft_core::discovery::DiscoveredDevice;
use ft_core::identity::Identity;
use ft_core::pairing::{confirm_and_wait_for_peer, derive_pin, exchange_hello, LocalIdentity, PairingError};
use ft_core::tls::{client_config_trust_anyone, peer_certificate, server_config_trust_anyone};
use ft_core::trust_store::TrustStore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};

const CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(120);

/// How to run a future to completion in the background. Tauri's `.setup()` hook runs
/// before any Tokio runtime is entered on its thread, so a plain `tokio::spawn` panics
/// there ("no reactor running") - callers must supply something that routes to their
/// actual runtime (e.g. `tauri::async_runtime::spawn`), keeping this crate Tauri-free.
pub type Spawner = Arc<dyn Fn(Pin<Box<dyn Future<Output = ()> + Send>>) + Send + Sync>;

#[derive(Debug, Clone, Serialize)]
pub struct PairingRequested {
    pub device_id: String,
    pub device_name: String,
    pub os: String,
    pub pin: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct PairingResult {
    pub device_id: String,
    pub success: bool,
    pub reason: Option<String>,
}

pub enum PairingEvent {
    Requested(PairingRequested),
    Result(PairingResult),
}

struct PendingSession {
    decision_tx: Option<oneshot::Sender<bool>>,
}

pub struct PairingService {
    identity: Arc<Identity>,
    local: LocalIdentity,
    trust_store: Arc<TrustStore>,
    sessions: Arc<Mutex<HashMap<String, PendingSession>>>,
    on_event: Arc<dyn Fn(PairingEvent) + Send + Sync>,
    spawn: Spawner,
}

impl PairingService {
    pub fn new<F>(
        identity: Arc<Identity>,
        local: LocalIdentity,
        trust_store: Arc<TrustStore>,
        spawn: Spawner,
        on_event: F,
    ) -> Self
    where
        F: Fn(PairingEvent) + Send + Sync + 'static,
    {
        Self {
            identity,
            local,
            trust_store,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            on_event: Arc::new(on_event),
            spawn,
        }
    }

    /// Starts accepting inbound pairing connections on `port` in the background.
    pub fn start_listener(&self, port: u16) {
        let identity = self.identity.clone();
        let local = self.local.clone();
        let trust_store = self.trust_store.clone();
        let sessions = self.sessions.clone();
        let on_event = self.on_event.clone();
        let spawn_inner = self.spawn.clone();

        (self.spawn)(Box::pin(async move {
            let listener = match TcpListener::bind(("0.0.0.0", port)).await {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("pairing listener failed to bind port {port}: {e}");
                    return;
                }
            };
            let acceptor = TlsAcceptor::from(server_config_trust_anyone(&identity));

            loop {
                let (tcp, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => continue,
                };
                let acceptor = acceptor.clone();
                let local = local.clone();
                let local_cert_der = identity.cert_der.to_vec();
                let trust_store = trust_store.clone();
                let sessions = sessions.clone();
                let on_event = on_event.clone();

                spawn_inner(Box::pin(async move {
                    let tls: TlsStream<TcpStream> = match acceptor.accept(tcp).await {
                        Ok(s) => s.into(),
                        Err(_) => return,
                    };
                    run_session(tls, local, local_cert_der, trust_store, sessions, on_event).await;
                }));
            }
        }));
    }

    /// Connects to a discovered device and starts pairing. Returns once the PIN has
    /// been derived; both sides then receive the same `PairingEvent::Requested`.
    pub async fn initiate(&self, device: &DiscoveredDevice) -> Result<(), PairingError> {
        let ip = device
            .addresses
            .iter()
            .find(|a| a.is_ipv4())
            .or_else(|| device.addresses.first())
            .copied()
            .ok_or(PairingError::NoAddress)?;

        let tcp = TcpStream::connect(SocketAddr::new(ip, device.port)).await?;
        let connector = TlsConnector::from(client_config_trust_anyone(&self.identity));
        let server_name = rustls::pki_types::ServerName::try_from("localhost")
            .expect("\"localhost\" is always a valid ServerName");
        let tls: TlsStream<TcpStream> = connector.connect(server_name, tcp).await?.into();

        let local = self.local.clone();
        let local_cert_der = self.identity.cert_der.to_vec();
        let trust_store = self.trust_store.clone();
        let sessions = self.sessions.clone();
        let on_event = self.on_event.clone();
        (self.spawn)(Box::pin(run_session(tls, local, local_cert_der, trust_store, sessions, on_event)));
        Ok(())
    }

    /// Delivers the local user's confirm/reject decision for a pending session.
    /// Returns `false` if there's no pending session for that device (e.g. it
    /// already timed out).
    pub fn confirm(&self, device_id: &str, confirmed: bool) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        match sessions.get_mut(device_id).and_then(|s| s.decision_tx.take()) {
            Some(tx) => tx.send(confirmed).is_ok(),
            None => false,
        }
    }
}

async fn run_session(
    mut tls: TlsStream<TcpStream>,
    local: LocalIdentity,
    local_cert_der: Vec<u8>,
    trust_store: Arc<TrustStore>,
    sessions: Arc<Mutex<HashMap<String, PendingSession>>>,
    on_event: Arc<dyn Fn(PairingEvent) + Send + Sync>,
) {
    let Some(peer_cert) = peer_certificate(&tls).map(|c| c.to_vec()) else {
        return;
    };
    let Ok(peer_hello) = exchange_hello(&mut tls, &local).await else {
        return;
    };

    let pin = derive_pin(&local_cert_der, &peer_cert);
    let peer_fingerprint = {
        let mut hasher = Sha256::new();
        hasher.update(&peer_cert);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    };

    let (decision_tx, decision_rx) = oneshot::channel();
    sessions
        .lock()
        .unwrap()
        .insert(peer_hello.device_id.clone(), PendingSession { decision_tx: Some(decision_tx) });

    on_event(PairingEvent::Requested(PairingRequested {
        device_id: peer_hello.device_id.clone(),
        device_name: peer_hello.device_name.clone(),
        os: peer_hello.os.clone(),
        pin,
    }));

    let locally_confirmed = match tokio::time::timeout(CONFIRMATION_TIMEOUT, decision_rx).await {
        Ok(Ok(decision)) => decision,
        _ => {
            sessions.lock().unwrap().remove(&peer_hello.device_id);
            emit_failure(&on_event, &peer_hello.device_id, "timed out waiting for local confirmation");
            return;
        }
    };
    sessions.lock().unwrap().remove(&peer_hello.device_id);

    match confirm_and_wait_for_peer(&mut tls, locally_confirmed, CONFIRMATION_TIMEOUT).await {
        Ok(true) => {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
            match trust_store.pin(&peer_hello.device_id, &peer_hello.device_name, &peer_fingerprint, &peer_hello.os, now) {
                Ok(()) => on_event(PairingEvent::Result(PairingResult {
                    device_id: peer_hello.device_id,
                    success: true,
                    reason: None,
                })),
                Err(e) => emit_failure(&on_event, &peer_hello.device_id, &format!("failed to save trust: {e}")),
            }
        }
        Ok(false) => emit_failure(&on_event, &peer_hello.device_id, "pairing was rejected"),
        Err(_) => emit_failure(&on_event, &peer_hello.device_id, "connection lost during pairing"),
    }
}

fn emit_failure(on_event: &Arc<dyn Fn(PairingEvent) + Send + Sync>, device_id: &str, reason: &str) {
    on_event(PairingEvent::Result(PairingResult {
        device_id: device_id.to_string(),
        success: false,
        reason: Some(reason.to_string()),
    }));
}
