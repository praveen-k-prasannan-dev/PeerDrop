use crate::setup::AppState;
use ft_app::discovery_service::DiscoveryService;
use tauri::State;

#[tauri::command]
pub async fn initiate_pairing(state: State<'_, AppState>, device_id: String) -> Result<(), String> {
    let device = {
        let discovery_guard = state.discovery.lock().map_err(|e| e.to_string())?;
        discovery_guard
            .as_ref()
            .map(DiscoveryService::snapshot)
            .unwrap_or_default()
            .into_iter()
            .find(|d| d.id == device_id)
            .ok_or_else(|| "device is no longer visible on the network".to_string())?
    };

    state.pairing.initiate(&device).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub fn confirm_pairing(state: State<AppState>, device_id: String, confirmed: bool) -> Result<(), String> {
    if state.pairing.confirm(&device_id, confirmed) {
        Ok(())
    } else {
        Err("no pending pairing session for that device".to_string())
    }
}
