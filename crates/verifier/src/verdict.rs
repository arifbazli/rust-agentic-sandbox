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

#[cfg(test)]
mod tests {
    use super::*;
    use host::ScopeConfig;
    use research_agent::Technique;

    fn fake_technique(id: &str, guid: &str) -> Technique {
        Technique {
            id: id.to_string(),
            guid: guid.to_string(),
            name: "Test Technique".to_string(),
            description: "unit-test fixture, not a real ingested technique".to_string(),
            source: "atomic-red-team".to_string(),
            test_command: "echo should-never-run".to_string(),
            platform: "windows".to_string(),
        }
    }

    /// End-to-end over the real Step 2/3 pipeline against the real
    /// `lab/scope.toml`: the technique must verify as `Blocked`, with a
    /// reason that traces back to the actual denial (the expired validity
    /// window), not a generic placeholder string.
    #[test]
    fn real_pipeline_run_yields_blocked_with_a_traceable_reason() {
        let scope = ScopeConfig::load("../../lab/scope.toml").expect("lab/scope.toml should parse");
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();
        store.put_technique("test-guid-1", &fake_technique("T1059", "test-guid-1")).unwrap();

        lab_agents::attempt_all(&scope, &store).unwrap();
        lab_agents::check_all(&store).unwrap();

        let records = verify(&store).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].technique_id, "T1059");
        match &records[0].verdict {
            Verdict::Blocked { reason } => {
                assert!(
                    reason.contains("validity window"),
                    "expected the verdict's reason to trace back to the expired validity window, got: {reason}"
                );
            }
            other => panic!("expected Blocked, got {other:?}"),
        }
    }

    /// Synthetic fixture: a capability grant followed by a detection check
    /// that found the signal present must classify as `Detected`. This
    /// path is unreachable via real execution today (the scope denies
    /// everything), but the classification logic itself must still be
    /// correct — otherwise a future bug here would go unnoticed.
    #[test]
    fn synthetic_grant_with_signal_present_yields_detected() {
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();
        let now = Utc::now();
        store
            .log_event(&AuditEvent {
                timestamp: now,
                actor: "test-fixture".to_string(),
                technique_id: "T9001".to_string(),
                kind: EventKind::CapabilityGranted,
                detail: "synthetic grant for test".to_string(),
            })
            .unwrap();
        store
            .log_event(&AuditEvent {
                timestamp: now,
                actor: "test-fixture".to_string(),
                technique_id: "T9001".to_string(),
                kind: EventKind::DetectionChecked,
                detail: "expected signal: synthetic — present: true".to_string(),
            })
            .unwrap();

        let records = verify(&store).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].verdict, Verdict::Detected);
    }

    /// Synthetic fixture: a capability grant followed by a detection check
    /// that did NOT find the signal must classify as `Missed` — proving
    /// Detected and Missed are genuinely distinguishable, not both
    /// aliases for the same fallthrough.
    #[test]
    fn synthetic_grant_with_signal_absent_yields_missed() {
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();
        let now = Utc::now();
        store
            .log_event(&AuditEvent {
                timestamp: now,
                actor: "test-fixture".to_string(),
                technique_id: "T9002".to_string(),
                kind: EventKind::CapabilityGranted,
                detail: "synthetic grant for test".to_string(),
            })
            .unwrap();
        store
            .log_event(&AuditEvent {
                timestamp: now,
                actor: "test-fixture".to_string(),
                technique_id: "T9002".to_string(),
                kind: EventKind::DetectionChecked,
                detail: "expected signal: synthetic — present: false".to_string(),
            })
            .unwrap();

        let records = verify(&store).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].verdict, Verdict::Missed);
    }

    /// `persist` must write records that are byte-for-byte retrievable via
    /// the audit store's verdict table.
    #[test]
    fn persist_writes_verdicts_that_are_retrievable() {
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();
        let record = VerdictRecord {
            technique_id: "T1059".to_string(),
            verdict: Verdict::Blocked { reason: "test reason".to_string() },
            timestamp: Utc::now(),
        };

        persist(&store, std::slice::from_ref(&record)).unwrap();

        let retrieved: Vec<(String, VerdictRecord)> = store.verdicts().unwrap();
        assert_eq!(retrieved.len(), 1);
        assert_eq!(retrieved[0].0, "T1059");
        assert_eq!(retrieved[0].1.verdict, record.verdict);
    }
}
