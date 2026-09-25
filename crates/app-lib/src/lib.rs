//! Orchestration layer used by Tauri commands: wires ft-core's discovery/pairing/transfer
//! primitives into app state and events. Filled in milestone by milestone.

pub mod discovery_service;
pub mod pairing_service;

pub fn core_version() -> &'static str {
    ft_core::version()
}
