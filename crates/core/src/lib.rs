//! Pure networking/crypto/protocol logic for FileTransfer, independent of Tauri.
//! Filled in milestone by milestone: discovery, identity/TLS, pairing, transfer protocol, storage.

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
