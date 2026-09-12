mod commands;
mod setup;

use tauri::Manager;

// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
#[tauri::command]
fn greet(name: &str) -> String {
    format!(
        "Hello, {}! You've been greeted from Rust (ft-core v{}).",
        name,
        ft_app::core_version()
    )
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let state = setup::init_state(app.handle())?;
            app.manage(state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            greet,
            commands::discovery::start_discovery,
            commands::discovery::get_discovered_devices
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
