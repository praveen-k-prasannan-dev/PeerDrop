use ft_app::discovery_service::DiscoveryService;
use ft_app::pairing_service::{PairingEvent, PairingService};
use ft_core::identity::Identity;
use ft_core::pairing::LocalIdentity;
use ft_core::settings::Settings;
use ft_core::trust_store::TrustStore;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Manager};

pub struct AppState {
    pub settings: Mutex<Settings>,
    // Also held by `pairing`; kept here too for the transfer connections landing in Milestone 5+.
    #[allow(dead_code)]
    pub identity: Arc<Identity>,
    pub trust_store: Arc<TrustStore>,
    pub discovery: Mutex<Option<DiscoveryService>>,
    pub pairing: PairingService,
}

pub fn init_state(app: &AppHandle) -> Result<AppState, Box<dyn std::error::Error>> {
    let app_data_dir = app.path().app_data_dir()?;
    std::fs::create_dir_all(&app_data_dir)?;
    let settings = Settings::load_or_create(&app_data_dir.join("settings.json"))?;
    let identity = Arc::new(Identity::load_or_create(
        &app_data_dir.join("identity/device.crt"),
        &app_data_dir.join("identity/device.key"),
        &settings.device_id,
    )?);
    let trust_store = Arc::new(TrustStore::open(&app_data_dir.join("trust.db"))?);

    eprintln!(
        "Device identity ready, fingerprint {}",
        hex_fingerprint(&identity.fingerprint())
    );

    let local = LocalIdentity {
        device_id: settings.device_id.clone(),
        device_name: settings.device_name.clone(),
        os: std::env::consts::OS.to_string(),
    };
    let listen_port = settings.listen_port;

    let app_handle = app.clone();
    let spawner: ft_app::pairing_service::Spawner = Arc::new(|fut| {
        tauri::async_runtime::spawn(fut);
    });
    let pairing = PairingService::new(identity.clone(), local, trust_store.clone(), spawner, move |event| {
        match event {
            PairingEvent::Requested(r) => {
                let _ = app_handle.emit("pairing-requested", r);
            }
            PairingEvent::Result(r) => {
                let _ = app_handle.emit("pairing-result", r);
            }
        }
    });
    pairing.start_listener(listen_port);

    Ok(AppState {
        settings: Mutex::new(settings),
        identity,
        trust_store,
        discovery: Mutex::new(None),
        pairing,
    })
}

fn hex_fingerprint(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
