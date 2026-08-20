use std::path::Path;

use anyhow::Result;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{de::DeserializeOwned, Serialize};

use crate::event::AuditEvent;

const EVENTS: TableDefinition<&str, &str> = TableDefinition::new("events");
const TECHNIQUES: TableDefinition<&str, &str> = TableDefinition::new("techniques");
const VERDICTS: TableDefinition<&str, &str> = TableDefinition::new("verdicts");

/// Append-only store backing the audit log: one `redb` database with three
/// tables (events, the ingested technique queue, and verdict summaries).
pub struct AuditStore {
    db: Database,
}

impl AuditStore {
    /// Opens (creating if absent) the audit database at `path`, and ensures
    /// all tables exist so later read-only scans never fail with
    /// "table does not exist" on a fresh database.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = Database::create(path)?;
        let write_txn = db.begin_write()?;
        {
            write_txn.open_table(EVENTS)?;
            write_txn.open_table(TECHNIQUES)?;
            write_txn.open_table(VERDICTS)?;
        }
        write_txn.commit()?;
        Ok(Self { db })
    }

    /// Logs one audit event. Never sampled, never summarized before write —
    /// see CONTEXT.md section 5.
    pub fn log_event(&self, event: &AuditEvent) -> Result<()> {
        let key = format!(
            "{:020}-{}",
            event.timestamp.timestamp_nanos_opt().unwrap_or_default(),
            event.technique_id
        );
        let value = serde_json::to_string(event)?;
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(EVENTS)?;
            table.insert(key.as_str(), value.as_str())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// All logged events, in chronological order (keys are zero-padded
    /// nanosecond timestamps, so byte order is chronological order).
    pub fn events(&self) -> Result<Vec<AuditEvent>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(EVENTS)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (_, value) = entry?;
            out.push(serde_json::from_str(value.value())?);
        }
        Ok(out)
    }

    /// Persists a technique queue entry (research-agent's ingestion output),
    /// keyed by the caller-supplied key (the atomic test's guid).
    pub fn put_technique<T: Serialize>(&self, key: &str, technique: &T) -> Result<()> {
        let value = serde_json::to_string(technique)?;
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(TECHNIQUES)?;
            table.insert(key, value.as_str())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Reads back every persisted technique queue entry.
    pub fn techniques<T: DeserializeOwned>(&self) -> Result<Vec<(String, T)>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(TECHNIQUES)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            out.push((key.value().to_string(), serde_json::from_str(value.value())?));
        }
        Ok(out)
    }

    /// Persists one verdict summary record, keyed by technique guid.
    pub fn put_verdict<T: Serialize>(&self, key: &str, verdict: &T) -> Result<()> {
        let value = serde_json::to_string(verdict)?;
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(VERDICTS)?;
            table.insert(key, value.as_str())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Reads back every persisted verdict summary record.
    pub fn verdicts<T: DeserializeOwned>(&self) -> Result<Vec<(String, T)>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(VERDICTS)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            out.push((key.value().to_string(), serde_json::from_str(value.value())?));
        }
        Ok(out)
    }
}
