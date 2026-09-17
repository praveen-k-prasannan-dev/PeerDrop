use ft_app::discovery_service::DiscoveryService;
use ft_core::identity::Identity;
use ft_core::settings::Settings;
use std::sync::Mutex;
use tauri::{AppHandle, Manager};

pub struct AppState {
    pub settings: Mutex<Settings>,
    // Read by the pairing/TLS commands landing in Milestone 4.
    #[allow(dead_code)]
    pub identity: Identity,
    pub discovery: Mutex<Option<DiscoveryService>>,
}

pub fn init_state(app: &AppHandle) -> Result<AppState, Box<dyn std::error::Error>> {
    let app_data_dir = app.path().app_data_dir()?;
    std::fs::create_dir_all(&app_data_dir)?;
    let settings = Settings::load_or_create(&app_data_dir.join("settings.json"))?;
    let identity = Identity::load_or_create(
        &app_data_dir.join("identity/device.crt"),
        &app_data_dir.join("identity/device.key"),
        &settings.device_id,
    )?;

    eprintln!(
        "Device identity ready, fingerprint {}",
        hex_fingerprint(&identity.fingerprint())
    );

    Ok(AppState {
        settings: Mutex::new(settings),
        identity,
        discovery: Mutex::new(None),
    })
}

fn hex_fingerprint(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
