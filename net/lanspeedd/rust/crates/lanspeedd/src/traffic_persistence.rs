//! Flash-conscious lifetime traffic accounting for the x86 TC-BPF collector.
//!
//! The BPF maps remain the source for live counters. This ledger converts map
//! deltas into lifetime totals and checkpoints only dirty rows in a batched
//! SQLite transaction. Reload candidates can collect for validation without
//! becoming storage owners, so a rejected candidate can never write totals.
//! SQLite is opened lazily after the first successful live sample rather than
//! during daemon startup; filesystem/database failures therefore never block
//! live counters.

use std::{
    collections::BTreeMap,
    ffi::{CStr, CString},
    fs,
    os::raw::{c_char, c_int, c_void},
    path::{Path, PathBuf},
    ptr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::model::Client;

pub(crate) const DEFAULT_TRAFFIC_DB_PATH: &str = "/etc/lanspeed/traffic.db";
const FLUSH_INTERVAL_MS: u64 = 5 * 60 * 1_000;
const RETRY_INTERVAL_MS: u64 = 60 * 1_000;
const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(2);

const SQLITE_OK: c_int = 0;
const SQLITE_ROW: c_int = 100;
const SQLITE_DONE: c_int = 101;
const SQLITE_OPEN_READ_WRITE: c_int = 0x0000_0002;
const SQLITE_OPEN_CREATE: c_int = 0x0000_0004;
const SQLITE_OPEN_NO_MUTEX: c_int = 0x0000_8000;

#[repr(C)]
struct SqliteHandle {
    _private: [u8; 0],
}

#[repr(C)]
struct SqliteStatementHandle {
    _private: [u8; 0],
}

#[link(name = "sqlite3")]
extern "C" {
    fn sqlite3_open_v2(
        filename: *const c_char,
        database: *mut *mut SqliteHandle,
        flags: c_int,
        vfs: *const c_char,
    ) -> c_int;
    fn sqlite3_close_v2(database: *mut SqliteHandle) -> c_int;
    fn sqlite3_busy_timeout(database: *mut SqliteHandle, milliseconds: c_int) -> c_int;
    fn sqlite3_errmsg(database: *mut SqliteHandle) -> *const c_char;
    fn sqlite3_exec(
        database: *mut SqliteHandle,
        sql: *const c_char,
        callback: Option<unsafe extern "C" fn(*mut c_void, c_int, *mut *mut c_char, *mut *mut c_char) -> c_int>,
        callback_argument: *mut c_void,
        error_message: *mut *mut c_char,
    ) -> c_int;
    fn sqlite3_free(pointer: *mut c_void);
    fn sqlite3_prepare_v2(
        database: *mut SqliteHandle,
        sql: *const c_char,
        bytes: c_int,
        statement: *mut *mut SqliteStatementHandle,
        tail: *mut *const c_char,
    ) -> c_int;
    fn sqlite3_step(statement: *mut SqliteStatementHandle) -> c_int;
    fn sqlite3_finalize(statement: *mut SqliteStatementHandle) -> c_int;
    fn sqlite3_reset(statement: *mut SqliteStatementHandle) -> c_int;
    fn sqlite3_clear_bindings(statement: *mut SqliteStatementHandle) -> c_int;
    fn sqlite3_bind_text(
        statement: *mut SqliteStatementHandle,
        index: c_int,
        value: *const c_char,
        bytes: c_int,
        destructor: Option<unsafe extern "C" fn(*mut c_void)>,
    ) -> c_int;
    fn sqlite3_bind_int64(statement: *mut SqliteStatementHandle, index: c_int, value: i64) -> c_int;
    fn sqlite3_column_text(statement: *mut SqliteStatementHandle, column: c_int) -> *const u8;
    fn sqlite3_column_int64(statement: *mut SqliteStatementHandle, column: c_int) -> i64;
}

struct SqliteConnection {
    handle: *mut SqliteHandle,
}

impl Drop for SqliteConnection {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: this connection exclusively owns the handle and all
            // statements are dropped before their parent connection.
            unsafe { sqlite3_close_v2(self.handle) };
        }
    }
}

impl SqliteConnection {
    fn error(&self, context: &str) -> String {
        // SAFETY: sqlite3_errmsg returns storage owned by the live connection.
        let message = unsafe {
            let pointer = sqlite3_errmsg(self.handle);
            if pointer.is_null() {
                "unknown SQLite error".to_owned()
            } else {
                CStr::from_ptr(pointer).to_string_lossy().into_owned()
            }
        };
        format!("{context}: {message}")
    }

    fn execute_batch(&self, sql: &str, context: &str) -> Result<(), String> {
        let sql = CString::new(sql).map_err(|_| format!("{context}: SQL contains NUL"))?;
        let mut error_message = ptr::null_mut();
        // SAFETY: the connection and SQL string are valid for the call; no
        // callback is installed and SQLite owns any returned error message.
        let result = unsafe {
            sqlite3_exec(
                self.handle,
                sql.as_ptr(),
                None,
                ptr::null_mut(),
                &mut error_message,
            )
        };
        if result == SQLITE_OK {
            return Ok(());
        }
        let message = if error_message.is_null() {
            self.error(context)
        } else {
            // SAFETY: sqlite3_exec allocated this NUL-terminated error string.
            let message = unsafe { CStr::from_ptr(error_message) }
                .to_string_lossy()
                .into_owned();
            // SAFETY: sqlite3_free is the required allocator pair.
            unsafe { sqlite3_free(error_message.cast()) };
            format!("{context}: {message}")
        };
        Err(message)
    }

    fn prepare<'connection>(
        &'connection self,
        sql: &str,
        context: &str,
    ) -> Result<SqliteStatement<'connection>, String> {
        let sql = CString::new(sql).map_err(|_| format!("{context}: SQL contains NUL"))?;
        let mut handle = ptr::null_mut();
        // SAFETY: SQLite copies/compiles the SQL before this call returns.
        let result = unsafe {
            sqlite3_prepare_v2(self.handle, sql.as_ptr(), -1, &mut handle, ptr::null_mut())
        };
        if result != SQLITE_OK || handle.is_null() {
            return Err(self.error(context));
        }
        Ok(SqliteStatement {
            connection: self,
            handle,
        })
    }
}

struct SqliteStatement<'connection> {
    connection: &'connection SqliteConnection,
    handle: *mut SqliteStatementHandle,
}

impl Drop for SqliteStatement<'_> {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: this statement exclusively owns its prepared handle.
            unsafe { sqlite3_finalize(self.handle) };
        }
    }
}

impl SqliteStatement<'_> {
    fn step(&mut self, context: &str) -> Result<c_int, String> {
        // SAFETY: the prepared statement is live and exclusively borrowed.
        let result = unsafe { sqlite3_step(self.handle) };
        if result == SQLITE_ROW || result == SQLITE_DONE {
            Ok(result)
        } else {
            Err(self.connection.error(context))
        }
    }

    fn reset(&mut self, context: &str) -> Result<(), String> {
        // SAFETY: resetting and clearing a live prepared statement is valid.
        let reset = unsafe { sqlite3_reset(self.handle) };
        let clear = unsafe { sqlite3_clear_bindings(self.handle) };
        if reset == SQLITE_OK && clear == SQLITE_OK {
            Ok(())
        } else {
            Err(self.connection.error(context))
        }
    }

    fn bind_text(&mut self, index: c_int, value: &CString, context: &str) -> Result<(), String> {
        // SAFETY: value remains alive through the following sqlite3_step call.
        let result = unsafe {
            sqlite3_bind_text(self.handle, index, value.as_ptr(), -1, None)
        };
        if result == SQLITE_OK {
            Ok(())
        } else {
            Err(self.connection.error(context))
        }
    }

    fn bind_i64(&mut self, index: c_int, value: i64, context: &str) -> Result<(), String> {
        // SAFETY: binding an integer to a live statement is valid.
        let result = unsafe { sqlite3_bind_int64(self.handle, index, value) };
        if result == SQLITE_OK {
            Ok(())
        } else {
            Err(self.connection.error(context))
        }
    }

    fn column_text(&self, column: c_int, context: &str) -> Result<String, String> {
        // SAFETY: called only while sqlite3_step is positioned on SQLITE_ROW.
        let pointer = unsafe { sqlite3_column_text(self.handle, column) };
        if pointer.is_null() {
            return Err(format!("{context}: NULL text column {column}"));
        }
        // SAFETY: SQLite exposes a NUL-terminated UTF-8 byte sequence here.
        Ok(unsafe { CStr::from_ptr(pointer.cast()) }
            .to_string_lossy()
            .into_owned())
    }

    fn column_i64(&self, column: c_int) -> i64 {
        // SAFETY: called only while sqlite3_step is positioned on SQLITE_ROW.
        unsafe { sqlite3_column_int64(self.handle, column) }
    }
}

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
            // The runtime becomes the storage owner only after its first
            // collection has been validated and committed. This also keeps
            // reload candidates read/compute-only until activation.
            storage_owner: false,
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

fn open_database(path: &Path) -> Result<SqliteConnection, String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create traffic database directory: {error}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }
    }
    let path_string = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| "open traffic database: path contains NUL".to_owned())?;
    let mut handle = ptr::null_mut();
    // SAFETY: path_string is NUL-terminated and handle is a valid out pointer.
    let open_result = unsafe {
        sqlite3_open_v2(
            path_string.as_ptr(),
            &mut handle,
            SQLITE_OPEN_READ_WRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NO_MUTEX,
            ptr::null(),
        )
    };
    if open_result != SQLITE_OK || handle.is_null() {
        let error = if handle.is_null() {
            format!("open traffic database: SQLite result {open_result}")
        } else {
            let connection = SqliteConnection { handle };
            connection.error("open traffic database")
        };
        return Err(error);
    }
    let connection = SqliteConnection { handle };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("secure traffic database: {error}"))?;
    }
    // SAFETY: the connection is live and the timeout fits in c_int.
    let busy_result = unsafe {
        sqlite3_busy_timeout(
            connection.handle,
            SQLITE_BUSY_TIMEOUT.as_millis().min(c_int::MAX as u128) as c_int,
        )
    };
    if busy_result != SQLITE_OK {
        return Err(connection.error("configure traffic database timeout"));
    }
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
            "initialize traffic database",
        )?;
    Ok(connection)
}

fn load_entries(path: &Path) -> Result<BTreeMap<String, TrafficEntry>, String> {
    let connection = open_database(path)?;
    let mut statement = connection
        .prepare(
            "SELECT identity_key, mac, zone, tx_bytes, rx_bytes, updated_at
             FROM client_traffic",
            "prepare traffic database read",
        )
        ?;
    let mut entries = BTreeMap::new();
    while statement.step("query traffic database")? == SQLITE_ROW {
        let identity_key = statement.column_text(0, "read traffic database row")?;
        let mac = statement.column_text(1, "read traffic database row")?;
        let zone = statement.column_text(2, "read traffic database row")?;
        let tx_bytes = statement.column_i64(3);
        let rx_bytes = statement.column_i64(4);
        let updated_at = statement.column_i64(5);
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
    let connection = open_database(path)?;
    connection.execute_batch("BEGIN IMMEDIATE", "start traffic database transaction")?;
    let result = (|| {
        let mut statement = connection.prepare(
            "INSERT INTO client_traffic
                (identity_key, mac, zone, tx_bytes, rx_bytes, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(identity_key) DO UPDATE SET
                mac=excluded.mac,
                zone=excluded.zone,
                tx_bytes=excluded.tx_bytes,
                rx_bytes=excluded.rx_bytes,
                updated_at=excluded.updated_at",
            "prepare traffic database write",
        )?;
        for (identity_key, entry) in entries.iter().filter(|(_, entry)| entry.dirty) {
            let identity_key = sqlite_text(identity_key, "identity key")?;
            let mac = sqlite_text(&entry.mac, "MAC")?;
            let zone = sqlite_text(&entry.zone, "zone")?;
            statement.bind_text(1, &identity_key, "bind traffic identity")?;
            statement.bind_text(2, &mac, "bind traffic MAC")?;
            statement.bind_text(3, &zone, "bind traffic zone")?;
            statement.bind_i64(4, sqlite_integer(entry.tx_bytes), "bind traffic upload")?;
            statement.bind_i64(5, sqlite_integer(entry.rx_bytes), "bind traffic download")?;
            statement.bind_i64(6, sqlite_integer(entry.updated_at), "bind traffic timestamp")?;
            if statement.step("write traffic database row")? != SQLITE_DONE {
                return Err("write traffic database row: unexpected SQLite row".to_owned());
            }
            statement.reset("reset traffic database write")?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => connection.execute_batch("COMMIT", "commit traffic database"),
        Err(error) => {
            let _ = connection.execute_batch("ROLLBACK", "rollback traffic database");
            Err(error)
        }
    }
}

fn sqlite_text(value: &str, field: &str) -> Result<CString, String> {
    CString::new(value).map_err(|_| format!("write traffic database row: {field} contains NUL"))
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
            first.activate_storage_owner();
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
