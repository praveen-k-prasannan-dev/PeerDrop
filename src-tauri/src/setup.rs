use ft_app::discovery_service::DiscoveryService;
use ft_core::settings::Settings;
use std::sync::Mutex;
use tauri::{AppHandle, Manager};

pub struct AppState {
    pub settings: Mutex<Settings>,
    pub discovery: Mutex<Option<DiscoveryService>>,
}

pub fn init_state(app: &AppHandle) -> Result<AppState, Box<dyn std::error::Error>> {
    let app_data_dir = app.path().app_data_dir()?;
    std::fs::create_dir_all(&app_data_dir)?;
    let settings = Settings::load_or_create(&app_data_dir.join("settings.json"))?;

    Ok(AppState {
        settings: Mutex::new(settings),
        discovery: Mutex::new(None),
    })
}
