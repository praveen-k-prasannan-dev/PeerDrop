//! Pure networking/crypto/protocol logic for FileTransfer, independent of Tauri.
//! Filled in milestone by milestone: discovery, identity/TLS, pairing, transfer protocol, storage.

pub mod discovery;
pub mod identity;
pub mod settings;
pub mod tls;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
