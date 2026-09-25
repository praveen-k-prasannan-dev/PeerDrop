//! End-to-end proof of Milestone 4: two independently-generated identities
//! establish a real TLS 1.3 connection, exchange Hello, derive the same PIN
//! from their live certificates, and - once both "users" confirm - pin each
//! other's certificate fingerprint in their own trust store.

use ft_core::identity::Identity;
use ft_core::pairing::{confirm_and_wait_for_peer, derive_pin, exchange_hello, LocalIdentity};
use ft_core::tls::{client_config_trust_anyone, peer_certificate, server_config_trust_anyone};
use ft_core::trust_store::TrustStore;
use rcgen::CertifiedKey;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn generated_identity(device_id: &str) -> Identity {
    let CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec![format!("{device_id}.local")]).unwrap();
    Identity {
        cert_der: cert.der().clone(),
        key_der: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der())),
    }
}

fn fingerprint_of(der: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(der);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

#[tokio::test]
async fn two_devices_pair_and_pin_each_other() {
    let mac_identity = generated_identity("mac-device");
    let win_identity = generated_identity("win-device");
    let mac_cert_fingerprint = fingerprint_of(&mac_identity.cert_der);
    let win_cert_fingerprint = fingerprint_of(&win_identity.cert_der);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(server_config_trust_anyone(&mac_identity));
    let connector = TlsConnector::from(client_config_trust_anyone(&win_identity));

    let temp_dir = tempfile::tempdir().unwrap();
    let mac_db_path = temp_dir.path().join("mac-trust.db");
    let win_db_path = temp_dir.path().join("win-trust.db");

    let mac_side = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls: tokio_rustls::TlsStream<_> = acceptor.accept(tcp).await.unwrap().into();

        let peer_cert = peer_certificate(&tls).expect("client presented a certificate");
        let local = LocalIdentity {
            device_id: "mac-device".into(),
            device_name: "Praveen's MacBook Pro".into(),
            os: "macos".into(),
        };
        let peer_hello = exchange_hello(&mut tls, &local).await.unwrap();
        assert_eq!(peer_hello.device_id, "win-device");

        let pin = derive_pin(&mac_identity.cert_der, &peer_cert);
        let confirmed = confirm_and_wait_for_peer(&mut tls, true, Duration::from_secs(2)).await.unwrap();
        assert!(confirmed);

        let store = TrustStore::open(&mac_db_path).unwrap();
        store
            .pin(&peer_hello.device_id, &peer_hello.device_name, &fingerprint_of(&peer_cert), &peer_hello.os, 1)
            .unwrap();

        (pin, store.get("win-device").unwrap().unwrap().cert_fingerprint)
    });

    let win_side = tokio::spawn(async move {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let server_name = ServerName::try_from("localhost").unwrap();
        let mut tls: tokio_rustls::TlsStream<_> = connector.connect(server_name, tcp).await.unwrap().into();

        let peer_cert = peer_certificate(&tls).expect("server presented a certificate");
        let local = LocalIdentity {
            device_id: "win-device".into(),
            device_name: "Kuttathara-Home".into(),
            os: "windows".into(),
        };
        let peer_hello = exchange_hello(&mut tls, &local).await.unwrap();
        assert_eq!(peer_hello.device_id, "mac-device");

        let pin = derive_pin(&win_identity.cert_der, &peer_cert);
        let confirmed = confirm_and_wait_for_peer(&mut tls, true, Duration::from_secs(2)).await.unwrap();
        assert!(confirmed);

        let store = TrustStore::open(&win_db_path).unwrap();
        store
            .pin(&peer_hello.device_id, &peer_hello.device_name, &fingerprint_of(&peer_cert), &peer_hello.os, 1)
            .unwrap();

        (pin, store.get("mac-device").unwrap().unwrap().cert_fingerprint)
    });

    let (mac_result, win_result) = tokio::join!(mac_side, win_side);
    let (mac_pin, mac_pinned_fingerprint) = mac_result.unwrap();
    let (win_pin, win_pinned_fingerprint) = win_result.unwrap();

    // The crux of PIN pairing: both sides land on the identical PIN despite
    // deriving it independently from what each locally saw over the wire.
    assert_eq!(mac_pin, win_pin);
    assert!(mac_pin < 1_000_000);

    // Each side pinned the other's *actual* certificate fingerprint.
    assert_eq!(mac_pinned_fingerprint, win_cert_fingerprint);
    assert_eq!(win_pinned_fingerprint, mac_cert_fingerprint);
}

/// If either human clicks "reject", neither side should end up with a pin -
/// this is what stops a rushed/incomplete pairing from silently trusting.
#[tokio::test]
async fn rejecting_on_one_side_prevents_pinning_on_both() {
    let mac_identity = generated_identity("mac-device-2");
    let win_identity = generated_identity("win-device-2");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(server_config_trust_anyone(&mac_identity));
    let connector = TlsConnector::from(client_config_trust_anyone(&win_identity));

    let mac_side = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls: tokio_rustls::TlsStream<_> = acceptor.accept(tcp).await.unwrap().into();
        let local = LocalIdentity { device_id: "mac-device-2".into(), device_name: "Mac".into(), os: "macos".into() };
        exchange_hello(&mut tls, &local).await.unwrap();
        // The Mac user confirms...
        confirm_and_wait_for_peer(&mut tls, true, Duration::from_secs(2)).await.unwrap()
    });

    let win_side = tokio::spawn(async move {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let server_name = ServerName::try_from("localhost").unwrap();
        let mut tls: tokio_rustls::TlsStream<_> = connector.connect(server_name, tcp).await.unwrap().into();
        let local = LocalIdentity { device_id: "win-device-2".into(), device_name: "Win".into(), os: "windows".into() };
        exchange_hello(&mut tls, &local).await.unwrap();
        // ...but the Windows user rejects.
        confirm_and_wait_for_peer(&mut tls, false, Duration::from_secs(2)).await.unwrap()
    });

    let (mac_confirmed, win_confirmed) = tokio::join!(mac_side, win_side);
    assert!(!mac_confirmed.unwrap(), "Mac must not treat pairing as successful when the peer rejected");
    assert!(!win_confirmed.unwrap(), "Windows must not treat pairing as successful when it rejected locally");
}
