use std::collections::BTreeSet;

use audit::{AuditEvent, AuditStore, EventKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Detected,
    Missed,
    Blocked { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictRecord {
    pub technique_id: String,
    pub verdict: Verdict,
    pub timestamp: DateTime<Utc>,
}

/// Pure deterministic verdict computation over the audit log — no model
/// call anywhere in this function. See CONTEXT.md section 1.
///
/// A capability denial, or a grant with no execution path implemented
/// (see `lab-agents`'s crate docs), both resolve to `Blocked`. `Detected`
/// and `Missed` are only reachable once a technique is actually granted
/// AND executed AND checked by the defender — none of which happens this
/// session, since `host::evaluate` denies everything under the current
/// `lab/scope.toml`. That branch is implemented for structural
/// completeness, not because it fires today.
pub fn verify(store: &AuditStore) -> anyhow::Result<Vec<VerdictRecord>> {
    let events = store.events()?;

    let mut technique_ids: BTreeSet<String> = BTreeSet::new();
    for event in &events {
        if !event.technique_id.is_empty() {
            technique_ids.insert(event.technique_id.clone());
        }
    }

    let mut records = Vec::with_capacity(technique_ids.len());
    for id in technique_ids {
        let technique_events: Vec<&AuditEvent> = events.iter().filter(|e| e.technique_id == id).collect();

        let denied = technique_events.iter().find(|e| e.kind == EventKind::CapabilityDenied);
        let blocked = technique_events.iter().find(|e| e.kind == EventKind::ExecutionBlocked);
        let granted = technique_events.iter().find(|e| e.kind == EventKind::CapabilityGranted);
        let detection_checked = technique_events.iter().rev().find(|e| e.kind == EventKind::DetectionChecked);

        let verdict = if let Some(event) = denied {
            Verdict::Blocked { reason: event.detail.clone() }
        } else if let Some(event) = blocked {
            Verdict::Blocked { reason: event.detail.clone() }
        } else if granted.is_some() {
            // Unreachable this session — see doc comment above.
            match detection_checked {
                Some(event) if event.detail.contains("present: true") => Verdict::Detected,
                Some(_) => Verdict::Missed,
                None => Verdict::Blocked {
                    reason: "capability was granted but no detection check was recorded".to_string(),
                },
            }
        } else {
            Verdict::Blocked {
                reason: "no capability decision or execution event found for this technique".to_string(),
            }
        };

        let timestamp = technique_events.last().map(|e| e.timestamp).unwrap_or_else(Utc::now);
        records.push(VerdictRecord { technique_id: id, verdict, timestamp });
    }

    Ok(records)
}

/// Writes every verdict back to the audit store's verdict table, keyed by
/// technique ID.
pub fn persist(store: &AuditStore, records: &[VerdictRecord]) -> anyhow::Result<()> {
    for record in records {
        store.put_verdict(&record.technique_id, record)?;
    }
    Ok(())
}
