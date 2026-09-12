use crate::setup::AppState;
use ft_app::discovery_service::DiscoveryService;
use ft_core::discovery::DiscoveredDevice;
use tauri::{AppHandle, Emitter, State};

#[tauri::command]
pub fn start_discovery(app: AppHandle, state: State<AppState>) -> Result<(), String> {
    let mut discovery_guard = state.discovery.lock().map_err(|e| e.to_string())?;
    if discovery_guard.is_some() {
        return Ok(());
    }

    let settings = state.settings.lock().map_err(|e| e.to_string())?.clone();
    let service = DiscoveryService::start(&settings, move |devices| {
        let _ = app.emit("devices-updated", devices);
    })
    .map_err(|e| e.to_string())?;

    *discovery_guard = Some(service);
    Ok(())
}

#[tauri::command]
pub fn get_discovered_devices(state: State<AppState>) -> Result<Vec<DiscoveredDevice>, String> {
    let discovery_guard = state.discovery.lock().map_err(|e| e.to_string())?;
    Ok(discovery_guard.as_ref().map(DiscoveryService::snapshot).unwrap_or_default())
}
