//! Flash-conscious lifetime traffic accounting for the x86 TC-BPF collector.
//!
//! The BPF maps remain the source for live counters. This ledger converts map
//! deltas into lifetime totals and checkpoints only dirty rows in a batched
//! SQLite transaction. Reload candidates fork the in-memory ledger without
//! becoming storage owners, so a rejected candidate can never write totals.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rusqlite::{params, Connection, OpenFlags};

use crate::model::Client;

pub(crate) const DEFAULT_TRAFFIC_DB_PATH: &str = "/etc/lanspeed/traffic.db";
const FLUSH_INTERVAL_MS: u64 = 5 * 60 * 1_000;
const RETRY_INTERVAL_MS: u64 = 60 * 1_000;
const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Debug, Default)]
struct TrafficEntry {
    mac: String,
    zone: String,
    tx_bytes: u64,
    rx_bytes: u64,
    last_raw_tx_bytes: Option<u64>,
    last_raw_rx_bytes: Option<u64>,
    updated_at: u64,
    dirty: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct TrafficLedger {
    path: PathBuf,
    entries: BTreeMap<String, TrafficEntry>,
    next_flush_ms: u64,
    storage_owner: bool,
    last_error: Option<String>,
}

impl TrafficLedger {
    pub(crate) fn open_default(now_ms: u64) -> Self {
        Self::open(DEFAULT_TRAFFIC_DB_PATH, now_ms)
    }

    fn open(path: impl Into<PathBuf>, now_ms: u64) -> Self {
        let path = path.into();
        let (entries, last_error) = match load_entries(&path) {
            Ok(entries) => (entries, None),
            Err(error) => (BTreeMap::new(), Some(error)),
        };
        Self {
            path,
            entries,
            next_flush_ms: now_ms.saturating_add(FLUSH_INTERVAL_MS),
            storage_owner: true,
            last_error,
        }
    }

    pub(crate) fn fork_for_reload(&self) -> Self {
        let mut fork = self.clone();
        fork.storage_owner = false;
        fork
    }

    pub(crate) fn activate_storage_owner(&mut self) {
        self.storage_owner = true;
    }

    pub(crate) fn deactivate_storage_owner(&mut self) {
        self.storage_owner = false;
    }

    pub(crate) fn overlay_clients(&mut self, clients: &mut [Client]) {
        for client in clients {
            let (Some(raw_tx_bytes), Some(raw_rx_bytes)) = (client.tx_bytes, client.rx_bytes)
            else {
                continue;
            };
            if client.collector_mode != "bpf" {
                continue;
            }
            let (tx_bytes, rx_bytes) = self.observe_raw(
                &client.identity_key,
                &client.mac,
                &client.zone,
                raw_tx_bytes,
                raw_rx_bytes,
            );
            client.tx_bytes = Some(tx_bytes);
            client.rx_bytes = Some(rx_bytes);
        }
    }

    pub(crate) fn flush_committed(&mut self, now_ms: u64) {
        if now_ms >= self.next_flush_ms {
            self.flush_now(now_ms);
        }
    }

    pub(crate) fn flush_shutdown(&mut self, now_ms: u64) {
        self.flush_now(now_ms);
    }

    #[cfg(test)]
    fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    fn observe_raw(
        &mut self,
        identity_key: &str,
        mac: &str,
        zone: &str,
        raw_tx_bytes: u64,
        raw_rx_bytes: u64,
    ) -> (u64, u64) {
        let entry = self.entries.entry(identity_key.to_owned()).or_default();
        let tx_delta = counter_delta(entry.last_raw_tx_bytes, raw_tx_bytes);
        let rx_delta = counter_delta(entry.last_raw_rx_bytes, raw_rx_bytes);
        let metadata_changed = entry.mac != mac || entry.zone != zone;

        entry.tx_bytes = entry.tx_bytes.saturating_add(tx_delta);
        entry.rx_bytes = entry.rx_bytes.saturating_add(rx_delta);
        entry.last_raw_tx_bytes = Some(raw_tx_bytes);
        entry.last_raw_rx_bytes = Some(raw_rx_bytes);
        entry.mac.clear();
        entry.mac.push_str(mac);
        entry.zone.clear();
        entry.zone.push_str(zone);
        if tx_delta != 0 || rx_delta != 0 || metadata_changed {
            entry.updated_at = unix_time_seconds();
            entry.dirty = true;
        }
        (entry.tx_bytes, entry.rx_bytes)
    }

    fn flush_now(&mut self, now_ms: u64) {
        if !self.storage_owner {
            return;
        }
        if !self.entries.values().any(|entry| entry.dirty) {
            self.next_flush_ms = now_ms.saturating_add(FLUSH_INTERVAL_MS);
            return;
        }
        match persist_entries(&self.path, &self.entries) {
            Ok(()) => {
                for entry in self.entries.values_mut() {
                    entry.dirty = false;
                }
                self.last_error = None;
                self.next_flush_ms = now_ms.saturating_add(FLUSH_INTERVAL_MS);
            }
            Err(error) => {
                self.last_error = Some(error);
                self.next_flush_ms = now_ms.saturating_add(RETRY_INTERVAL_MS);
            }
        }
    }
}

fn counter_delta(previous: Option<u64>, current: u64) -> u64 {
    match previous {
        Some(previous) if current >= previous => current - previous,
        Some(_) | None => current,
    }
}

fn unix_time_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn open_database(path: &Path) -> Result<Connection, String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create traffic database directory: {error}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }
    }
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| format!("open traffic database: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("secure traffic database: {error}"))?;
    }
    connection
        .busy_timeout(SQLITE_BUSY_TIMEOUT)
        .map_err(|error| format!("configure traffic database timeout: {error}"))?;
    connection
        .execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA temp_store=MEMORY;
             PRAGMA wal_autocheckpoint=100;
             CREATE TABLE IF NOT EXISTS client_traffic (
                 identity_key TEXT PRIMARY KEY NOT NULL,
                 mac TEXT NOT NULL,
                 zone TEXT NOT NULL,
                 tx_bytes INTEGER NOT NULL CHECK (tx_bytes >= 0),
                 rx_bytes INTEGER NOT NULL CHECK (rx_bytes >= 0),
                 updated_at INTEGER NOT NULL CHECK (updated_at >= 0)
             ) WITHOUT ROWID;
             PRAGMA user_version=1;",
        )
        .map_err(|error| format!("initialize traffic database: {error}"))?;
    Ok(connection)
}

fn load_entries(path: &Path) -> Result<BTreeMap<String, TrafficEntry>, String> {
    let connection = open_database(path)?;
    let mut statement = connection
        .prepare(
            "SELECT identity_key, mac, zone, tx_bytes, rx_bytes, updated_at
             FROM client_traffic",
        )
        .map_err(|error| format!("prepare traffic database read: {error}"))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })
        .map_err(|error| format!("query traffic database: {error}"))?;
    let mut entries = BTreeMap::new();
    for row in rows {
        let (identity_key, mac, zone, tx_bytes, rx_bytes, updated_at) =
            row.map_err(|error| format!("read traffic database row: {error}"))?;
        entries.insert(
            identity_key,
            TrafficEntry {
                mac,
                zone,
                tx_bytes: nonnegative_u64(tx_bytes),
                rx_bytes: nonnegative_u64(rx_bytes),
                updated_at: nonnegative_u64(updated_at),
                ..TrafficEntry::default()
            },
        );
    }
    Ok(entries)
}

fn persist_entries(path: &Path, entries: &BTreeMap<String, TrafficEntry>) -> Result<(), String> {
    let mut connection = open_database(path)?;
    let transaction = connection
        .transaction()
        .map_err(|error| format!("start traffic database transaction: {error}"))?;
    {
        let mut statement = transaction
            .prepare_cached(
                "INSERT INTO client_traffic
                    (identity_key, mac, zone, tx_bytes, rx_bytes, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(identity_key) DO UPDATE SET
                    mac=excluded.mac,
                    zone=excluded.zone,
                    tx_bytes=excluded.tx_bytes,
                    rx_bytes=excluded.rx_bytes,
                    updated_at=excluded.updated_at",
            )
            .map_err(|error| format!("prepare traffic database write: {error}"))?;
        for (identity_key, entry) in entries.iter().filter(|(_, entry)| entry.dirty) {
            statement
                .execute(params![
                    identity_key,
                    entry.mac,
                    entry.zone,
                    sqlite_integer(entry.tx_bytes),
                    sqlite_integer(entry.rx_bytes),
                    sqlite_integer(entry.updated_at),
                ])
                .map_err(|error| format!("write traffic database row: {error}"))?;
        }
    }
    transaction
        .commit()
        .map_err(|error| format!("commit traffic database: {error}"))
}

fn sqlite_integer(value: u64) -> i64 {
    value.min(i64::MAX as u64) as i64
}

fn nonnegative_u64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::TrafficLedger;

    fn test_path(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "lanspeedd-traffic-{name}-{}-{}",
            std::process::id(),
            super::unix_time_seconds()
        ));
        let _ = fs::remove_dir_all(&path);
        path.join("traffic.db")
    }

    #[test]
    fn converts_monotonic_and_reset_raw_counters_into_lifetime_totals() {
        let path = test_path("counter-delta");
        let mut ledger = TrafficLedger::open(&path, 0);
        assert_eq!(
            ledger.observe_raw("mac@lan", "mac", "lan", 100, 200),
            (100, 200)
        );
        assert_eq!(
            ledger.observe_raw("mac@lan", "mac", "lan", 140, 260),
            (140, 260)
        );
        assert_eq!(
            ledger.observe_raw("mac@lan", "mac", "lan", 12, 8),
            (152, 268)
        );
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn reload_fork_does_not_double_count_the_same_raw_snapshot() {
        let path = test_path("reload-fork");
        let mut current = TrafficLedger::open(&path, 0);
        assert_eq!(
            current.observe_raw("mac@lan", "mac", "lan", 100, 200),
            (100, 200)
        );
        let mut candidate = current.fork_for_reload();
        assert_eq!(
            candidate.observe_raw("mac@lan", "mac", "lan", 100, 200),
            (100, 200)
        );
        assert!(!candidate.storage_owner);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn sqlite_checkpoint_survives_a_new_daemon_ledger() {
        let path = test_path("restart");
        {
            let mut first = TrafficLedger::open(&path, 0);
            assert_eq!(
                first.observe_raw("mac@lan", "mac", "lan", 100, 200),
                (100, 200)
            );
            first.flush_shutdown(1);
            assert!(first.last_error().is_none());
        }
        {
            let mut restarted = TrafficLedger::open(&path, 2);
            assert_eq!(
                restarted.observe_raw("mac@lan", "mac", "lan", 20, 30),
                (120, 230)
            );
        }
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }
}
