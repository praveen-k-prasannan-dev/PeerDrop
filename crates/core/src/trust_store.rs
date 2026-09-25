//! Persisted trust-on-first-use pinning: which devices we've paired with,
//! and the certificate fingerprint we expect them to keep presenting.

use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::Mutex;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TrustStoreError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq)]
pub struct TrustedDevice {
    pub device_id: String,
    pub display_name: String,
    pub cert_fingerprint: [u8; 32],
    pub os: String,
    pub auto_accept: bool,
    pub paired_at: i64,
    pub last_seen_at: Option<i64>,
}

pub struct TrustStore {
    conn: Mutex<Connection>,
}

impl TrustStore {
    pub fn open(path: &Path) -> Result<Self, TrustStoreError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS trusted_devices (
                device_id        TEXT PRIMARY KEY,
                display_name     TEXT NOT NULL,
                cert_fingerprint BLOB NOT NULL,
                os               TEXT NOT NULL,
                auto_accept      INTEGER NOT NULL DEFAULT 0,
                paired_at        INTEGER NOT NULL,
                last_seen_at     INTEGER
            )",
            [],
        )?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    pub fn get(&self, device_id: &str) -> Result<Option<TrustedDevice>, TrustStoreError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT device_id, display_name, cert_fingerprint, os, auto_accept, paired_at, last_seen_at
             FROM trusted_devices WHERE device_id = ?1",
            params![device_id],
            row_to_trusted_device,
        )
        .optional()
        .map_err(TrustStoreError::from)
    }

    pub fn list(&self) -> Result<Vec<TrustedDevice>, TrustStoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT device_id, display_name, cert_fingerprint, os, auto_accept, paired_at, last_seen_at
             FROM trusted_devices ORDER BY paired_at DESC",
        )?;
        let rows = stmt.query_map([], row_to_trusted_device)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(TrustStoreError::from)
    }

    /// Pin a device's identity after a successful pairing. Overwrites any prior pin
    /// for the same device id (re-pairing after a "device identity changed" event).
    pub fn pin(
        &self,
        device_id: &str,
        display_name: &str,
        cert_fingerprint: &[u8; 32],
        os: &str,
        paired_at: i64,
    ) -> Result<(), TrustStoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO trusted_devices (device_id, display_name, cert_fingerprint, os, auto_accept, paired_at, last_seen_at)
             VALUES (?1, ?2, ?3, ?4, 0, ?5, ?5)
             ON CONFLICT(device_id) DO UPDATE SET
                display_name = excluded.display_name,
                cert_fingerprint = excluded.cert_fingerprint,
                os = excluded.os,
                paired_at = excluded.paired_at,
                last_seen_at = excluded.last_seen_at",
            params![device_id, display_name, cert_fingerprint.as_slice(), os, paired_at],
        )?;
        Ok(())
    }

    pub fn forget(&self, device_id: &str) -> Result<bool, TrustStoreError> {
        let conn = self.conn.lock().unwrap();
        let changed = conn.execute("DELETE FROM trusted_devices WHERE device_id = ?1", params![device_id])?;
        Ok(changed > 0)
    }

    pub fn set_auto_accept(&self, device_id: &str, enabled: bool) -> Result<(), TrustStoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE trusted_devices SET auto_accept = ?2 WHERE device_id = ?1",
            params![device_id, enabled],
        )?;
        Ok(())
    }

    pub fn touch_last_seen(&self, device_id: &str, at: i64) -> Result<(), TrustStoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE trusted_devices SET last_seen_at = ?2 WHERE device_id = ?1",
            params![device_id, at],
        )?;
        Ok(())
    }
}

fn row_to_trusted_device(row: &rusqlite::Row) -> rusqlite::Result<TrustedDevice> {
    let fingerprint_bytes: Vec<u8> = row.get(2)?;
    let mut cert_fingerprint = [0u8; 32];
    if fingerprint_bytes.len() == 32 {
        cert_fingerprint.copy_from_slice(&fingerprint_bytes);
    }
    Ok(TrustedDevice {
        device_id: row.get(0)?,
        display_name: row.get(1)?,
        cert_fingerprint,
        os: row.get(3)?,
        auto_accept: row.get(4)?,
        paired_at: row.get(5)?,
        last_seen_at: row.get(6)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (TrustStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = TrustStore::open(&dir.path().join("trust.db")).unwrap();
        (store, dir)
    }

    #[test]
    fn unknown_device_is_not_pinned() {
        let (store, _dir) = temp_store();
        assert_eq!(store.get("nope").unwrap(), None);
    }

    #[test]
    fn pin_then_get_round_trips() {
        let (store, _dir) = temp_store();
        let fingerprint = [7u8; 32];
        store.pin("dev-1", "Alice's Mac", &fingerprint, "macos", 1000).unwrap();

        let device = store.get("dev-1").unwrap().unwrap();
        assert_eq!(device.device_id, "dev-1");
        assert_eq!(device.display_name, "Alice's Mac");
        assert_eq!(device.cert_fingerprint, fingerprint);
        assert_eq!(device.os, "macos");
        assert!(!device.auto_accept);
    }

    #[test]
    fn re_pinning_overwrites_the_fingerprint() {
        let (store, _dir) = temp_store();
        store.pin("dev-1", "Alice's Mac", &[1u8; 32], "macos", 1000).unwrap();
        store.pin("dev-1", "Alice's Mac", &[2u8; 32], "macos", 2000).unwrap();

        let device = store.get("dev-1").unwrap().unwrap();
        assert_eq!(device.cert_fingerprint, [2u8; 32]);
        assert_eq!(device.paired_at, 2000);
    }

    #[test]
    fn forget_removes_the_device() {
        let (store, _dir) = temp_store();
        store.pin("dev-1", "Alice's Mac", &[1u8; 32], "macos", 1000).unwrap();
        assert!(store.forget("dev-1").unwrap());
        assert_eq!(store.get("dev-1").unwrap(), None);
        assert!(!store.forget("dev-1").unwrap());
    }

    #[test]
    fn set_auto_accept_updates_the_flag() {
        let (store, _dir) = temp_store();
        store.pin("dev-1", "Alice's Mac", &[1u8; 32], "macos", 1000).unwrap();
        store.set_auto_accept("dev-1", true).unwrap();
        assert!(store.get("dev-1").unwrap().unwrap().auto_accept);
    }
}
