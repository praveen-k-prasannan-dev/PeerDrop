//! Persisted per-device settings (app-data JSON file).
//! Starts minimal (identity + port); grows as later milestones add
//! download directory, concurrency limits, etc.

use serde::{Deserialize, Serialize};
use std::path::Path;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub device_id: String,
    pub device_name: String,
    pub listen_port: u16,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            device_id: Uuid::new_v4().to_string(),
            device_name: whoami::devicename(),
            listen_port: 53317,
        }
    }
}

impl Settings {
    /// Load settings from `path`, creating them with defaults on first run.
    pub fn load_or_create(path: &Path) -> std::io::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(contents) => Ok(serde_json::from_str(&contents).unwrap_or_default()),
            Err(_) => {
                let settings = Settings::default();
                settings.save(path)?;
                Ok(settings)
            }
        }
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(self)?)
    }
}
