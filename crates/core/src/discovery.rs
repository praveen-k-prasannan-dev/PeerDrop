//! LAN discovery of other FileTransfer devices via mDNS.

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use thiserror::Error;

pub const SERVICE_TYPE: &str = "_filetransfer._tcp.local.";
pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("mDNS error: {0}")]
    Mdns(#[from] mdns_sd::Error),
}

/// What this device advertises about itself on the network.
#[derive(Debug, Clone)]
pub struct LocalDeviceInfo {
    pub id: String,
    pub name: String,
    pub os: String,
    pub port: u16,
}

/// A peer device found on the LAN.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiscoveredDevice {
    pub id: String,
    pub name: String,
    pub os: String,
    pub port: u16,
    pub addresses: Vec<IpAddr>,
}

pub enum DiscoveryEvent {
    Updated(DiscoveredDevice),
    Removed(String),
}

/// Owns the mDNS daemon: advertises this device and browses for peers.
pub struct Discovery {
    daemon: ServiceDaemon,
}

impl Discovery {
    pub fn new() -> Result<Self, DiscoveryError> {
        Ok(Self {
            daemon: ServiceDaemon::new()?,
        })
    }

    /// Advertise this device on the LAN so peers can find it.
    pub fn advertise(&self, info: &LocalDeviceInfo) -> Result<(), DiscoveryError> {
        let mut props: HashMap<String, String> = HashMap::new();
        props.insert("id".to_string(), info.id.clone());
        props.insert("name".to_string(), info.name.clone());
        props.insert("os".to_string(), info.os.clone());
        props.insert("v".to_string(), PROTOCOL_VERSION.to_string());

        // Instance/host names must be unique on the network; the device id guarantees that.
        let host_name = format!("{}.local.", info.id);
        let service = ServiceInfo::new(
            SERVICE_TYPE,
            &info.id,
            &host_name,
            "", // no fixed IP; auto-detect and keep in sync with host addresses
            info.port,
            props,
        )?
        .enable_addr_auto();

        self.daemon.register(service)?;
        Ok(())
    }

    /// Start browsing for peers. Events are delivered on a background thread via `on_event`
    /// until this `Discovery` is dropped (which shuts down the daemon).
    pub fn browse<F>(&self, mut on_event: F) -> Result<(), DiscoveryError>
    where
        F: FnMut(DiscoveryEvent) + Send + 'static,
    {
        let receiver = self.daemon.browse(SERVICE_TYPE)?;
        std::thread::spawn(move || {
            while let Ok(event) = receiver.recv() {
                match event {
                    ServiceEvent::ServiceResolved(info) => {
                        if let Some(device) = device_from_service_info(&info) {
                            on_event(DiscoveryEvent::Updated(device));
                        }
                    }
                    ServiceEvent::ServiceRemoved(_ty_domain, fullname) => {
                        if let Some(id) = fullname.split('.').next() {
                            on_event(DiscoveryEvent::Removed(id.to_string()));
                        }
                    }
                    _ => {}
                }
            }
        });
        Ok(())
    }
}

fn device_from_service_info(info: &ServiceInfo) -> Option<DiscoveredDevice> {
    let id = info.get_property_val_str("id")?.to_string();
    let name = info
        .get_property_val_str("name")
        .unwrap_or("Unknown device")
        .to_string();
    let os = info
        .get_property_val_str("os")
        .unwrap_or("unknown")
        .to_string();
    let addresses = info.get_addresses().iter().copied().collect();
    Some(DiscoveredDevice {
        id,
        name,
        os,
        port: info.get_port(),
        addresses,
    })
}
