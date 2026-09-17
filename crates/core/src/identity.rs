//! This device's long-lived self-signed TLS identity, persisted across restarts.
//! Trust in this identity is established later (Milestone 4's PIN pairing +
//! certificate pinning) - generating/loading it doesn't require that yet.

use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("failed to generate certificate: {0}")]
    Generate(#[from] rcgen::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub struct Identity {
    pub cert_der: CertificateDer<'static>,
    pub key_der: PrivateKeyDer<'static>,
}

impl Identity {
    /// Loads the identity from `cert_path`/`key_path`, generating and persisting
    /// a new self-signed cert/key pair on first run.
    pub fn load_or_create(
        cert_path: &Path,
        key_path: &Path,
        device_id: &str,
    ) -> Result<Self, IdentityError> {
        if cert_path.exists() && key_path.exists() {
            let cert_bytes = std::fs::read(cert_path)?;
            let key_bytes = std::fs::read(key_path)?;
            return Ok(Self {
                cert_der: CertificateDer::from(cert_bytes),
                key_der: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_bytes)),
            });
        }

        // Trust is pin-based (Milestone 4), not CA/hostname based, so these SANs only need
        // to be present/well-formed - their content isn't itself a security boundary.
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec![format!("{device_id}.local"), "localhost".to_string()])?;
        let cert_bytes = cert.der().to_vec();
        let key_bytes = key_pair.serialize_der();

        if let Some(parent) = cert_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(cert_path, &cert_bytes)?;
        write_private_key(key_path, &key_bytes)?;

        Ok(Self {
            cert_der: CertificateDer::from(cert_bytes),
            key_der: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_bytes)),
        })
    }

    /// SHA-256 fingerprint of this device's certificate, used for trust pinning (Milestone 4).
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.cert_der.as_ref());
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }
}

fn write_private_key(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
