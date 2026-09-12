//! Bridges ft-core's discovery primitives into a live, queryable device list.
//! Framework-agnostic: callers (the Tauri commands layer) supply a plain
//! callback to be notified of updates, so this crate stays Tauri-free.

use ft_core::discovery::{Discovery, DiscoveredDevice, DiscoveryError, DiscoveryEvent, LocalDeviceInfo};
use ft_core::settings::Settings;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub struct DiscoveryService {
    // Kept alive for the lifetime of the service: dropping it shuts down the mDNS daemon.
    _discovery: Discovery,
    devices: Arc<Mutex<HashMap<String, DiscoveredDevice>>>,
}

impl DiscoveryService {
    /// Advertises the local device and starts browsing for peers. `on_update` is called
    /// with a full snapshot of currently-known peers whenever the set changes.
    pub fn start<F>(settings: &Settings, on_update: F) -> Result<Self, DiscoveryError>
    where
        F: Fn(Vec<DiscoveredDevice>) + Send + 'static,
    {
        let discovery = Discovery::new()?;

        discovery.advertise(&LocalDeviceInfo {
            id: settings.device_id.clone(),
            name: settings.device_name.clone(),
            os: std::env::consts::OS.to_string(),
            port: settings.listen_port,
        })?;

        let devices: Arc<Mutex<HashMap<String, DiscoveredDevice>>> = Arc::new(Mutex::new(HashMap::new()));
        let devices_for_browse = devices.clone();
        let local_id = settings.device_id.clone();

        discovery.browse(move |event| {
            let changed = {
                let mut map = devices_for_browse.lock().unwrap();
                match event {
                    DiscoveryEvent::Updated(device) => {
                        if device.id == local_id {
                            false
                        } else {
                            map.insert(device.id.clone(), device);
                            true
                        }
                    }
                    DiscoveryEvent::Removed(id) => map.remove(&id).is_some(),
                }
            };
            if changed {
                let snapshot: Vec<DiscoveredDevice> =
                    devices_for_browse.lock().unwrap().values().cloned().collect();
                on_update(snapshot);
            }
        })?;

        Ok(Self {
            _discovery: discovery,
            devices,
        })
    }

    pub fn snapshot(&self) -> Vec<DiscoveredDevice> {
        self.devices.lock().unwrap().values().cloned().collect()
    }
}
