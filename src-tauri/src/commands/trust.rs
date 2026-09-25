use crate::setup::AppState;
use ft_core::trust_store::TrustedDevice;
use serde::Serialize;
use tauri::State;

#[derive(Serialize)]
pub struct TrustedDeviceView {
    pub device_id: String,
    pub display_name: String,
    pub os: String,
    pub auto_accept: bool,
    pub paired_at: i64,
    pub last_seen_at: Option<i64>,
}

impl From<TrustedDevice> for TrustedDeviceView {
    fn from(d: TrustedDevice) -> Self {
        Self {
            device_id: d.device_id,
            display_name: d.display_name,
            os: d.os,
            auto_accept: d.auto_accept,
            paired_at: d.paired_at,
            last_seen_at: d.last_seen_at,
        }
    }
}

#[tauri::command]
pub fn list_trusted_devices(state: State<AppState>) -> Result<Vec<TrustedDeviceView>, String> {
    state
        .trust_store
        .list()
        .map(|devices| devices.into_iter().map(Into::into).collect())
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn forget_device(state: State<AppState>, device_id: String) -> Result<bool, String> {
    state.trust_store.forget(&device_id).map_err(|e| e.to_string())
}
