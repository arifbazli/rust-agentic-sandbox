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
/// A capability denial, an `ExecutionBlocked` (granted but no execution
/// path implemented — see `lab-agents`'s crate docs), or an
/// `ExecutionFailed` (a real execution attempt that didn't succeed) all
/// resolve to `Blocked` — nothing real happened for a defense to have
/// caught. `Detected`/`Missed` require a technique that was actually
/// executed — either `CapabilityGranted` (the old, still-supported signal)
/// or `ExecutionSucceeded` (the real execution engine — currently only the
/// synthetic proving technique reaches this, see
/// `research_agent::synthetic`) — AND checked by the defender.
/// `Detected`/`Missed` are genuinely reachable today for that technique,
/// no longer only structurally complete-but-unreachable.
pub fn verify(store: &AuditStore) -> anyhow::Result<Vec<VerdictRecord>> {
    let events = store.events()?;

    let mut subject_ids: BTreeSet<String> = BTreeSet::new();
    for event in &events {
        if !event.subject_id.is_empty() {
            subject_ids.insert(event.subject_id.clone());
        }
    }

    let mut records = Vec::with_capacity(subject_ids.len());
    for id in subject_ids {
        let subject_events: Vec<&AuditEvent> = events.iter().filter(|e| e.subject_id == id).collect();

        let denied = subject_events.iter().find(|e| e.kind == EventKind::CapabilityDenied);
        let blocked = subject_events.iter().find(|e| e.kind == EventKind::ExecutionBlocked);
        let execution_failed = subject_events.iter().find(|e| e.kind == EventKind::ExecutionFailed);
        let executed = subject_events.iter().find(|e| matches!(e.kind, EventKind::CapabilityGranted | EventKind::ExecutionSucceeded));
        let detection_checked = subject_events.iter().rev().find(|e| e.kind == EventKind::DetectionChecked);

        let verdict = if let Some(event) = denied {
            Verdict::Blocked { reason: event.detail.clone() }
        } else if let Some(event) = blocked {
            Verdict::Blocked { reason: event.detail.clone() }
        } else if let Some(event) = execution_failed {
            Verdict::Blocked { reason: event.detail.clone() }
        } else if executed.is_some() {
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

        let timestamp = subject_events.last().map(|e| e.timestamp).unwrap_or_else(Utc::now);
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

    /// End-to-end over the real pipeline against the real, now-populated
    /// `lab/scope.toml`: the technique must still verify as `Blocked`, but
    /// for a different, real reason than before. `lab/scope.toml` now
    /// genuinely grants T1059 (Step 2a/2b's path enforcement), so the
    /// technique is no longer denied by scope — it's blocked at the
    /// execution stage instead, since `lab-agents` still has no
    /// wasmtime/WASI-P2 execution engine. Path enforcement and execution
    /// capability are separate gaps; this test's reason-string assertion
    /// changed from the old expired-validity-window text to this new,
    /// verified-real one, not the other way around.
    #[test]
    fn real_pipeline_run_yields_blocked_with_a_traceable_reason() {
        let scope = ScopeConfig::load("../../lab/scope.toml").expect("lab/scope.toml should parse");
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();
        store.put_technique("test-guid-1", &fake_technique("T1059", "test-guid-1")).unwrap();

        lab_agents::attempt_all(&scope, std::path::Path::new("../.."), &store).unwrap();
        lab_agents::check_all(&scope, std::path::Path::new("../.."), &store).unwrap();

        let records = verify(&store).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].technique_id, "T1059");
        match &records[0].verdict {
            Verdict::Blocked { reason } => {
                assert!(
                    reason.contains("no wasmtime/WASI-P2 sandbox execution path implemented"),
                    "expected the verdict's reason to trace back to the missing execution engine, not scope denial, got: {reason}"
                );
            }
            other => panic!("expected Blocked, got {other:?}"),
        }
    }

    fn scope_with_synthetic_target_toml() -> &'static str {
        r#"
            [environment]
            name = "test-lab"
            [[environment.targets]]
            id = "t1"
            type = "local-directory"
            identifier = "target"
            [techniques]
            allowed_categories = ["SYNTH-0001"]
            allowed_sources = ["synthetic-proving"]
        "#
    }

    /// Fully real, end to end, zero fabricated events: the synthetic
    /// proving technique actually executes (real wasmtime sandbox, real
    /// marker write), the real defender finds the marker genuinely on
    /// disk, and `verify()` must classify this as `Detected` — the first
    /// time in this project's history this verdict is reachable through
    /// the real pipeline rather than only a hand-built fixture.
    #[test]
    fn real_synthetic_pipeline_with_marker_on_disk_yields_detected() {
        let scope: ScopeConfig = toml::from_str(scope_with_synthetic_target_toml()).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        std::fs::create_dir(workspace.path().join("target")).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();

        let technique = research_agent::synthetic_proving_technique();
        store.put_technique(&technique.guid, &technique).unwrap();

        lab_agents::attempt_all(&scope, workspace.path(), &store).unwrap();
        lab_agents::check_all(&scope, workspace.path(), &store).unwrap();

        let records = verify(&store).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].technique_id, "SYNTH-0001");
        assert_eq!(records[0].verdict, Verdict::Detected);
    }

    /// Fully real, end to end, zero fabricated events: the synthetic
    /// technique actually executes for real, then the marker file is
    /// genuinely deleted from disk before the real defender check runs —
    /// `verify()` must classify this as `Missed`, proving the path is
    /// really reachable, not just theoretically wired.
    #[test]
    fn real_synthetic_pipeline_with_marker_removed_yields_missed() {
        let scope: ScopeConfig = toml::from_str(scope_with_synthetic_target_toml()).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let target_dir = workspace.path().join("target");
        std::fs::create_dir(&target_dir).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();

        let technique = research_agent::synthetic_proving_technique();
        store.put_technique(&technique.guid, &technique).unwrap();

        lab_agents::attempt_all(&scope, workspace.path(), &store).unwrap();
        std::fs::remove_file(target_dir.join(lab_agents::MARKER_FILE_NAME)).unwrap();
        lab_agents::check_all(&scope, workspace.path(), &store).unwrap();

        let records = verify(&store).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].technique_id, "SYNTH-0001");
        assert_eq!(records[0].verdict, Verdict::Missed);
    }

    /// Synthetic fixture: a capability grant followed by a detection check
    /// that found the signal present must classify as `Detected`. This
    /// specific event combination (a bare `CapabilityGranted`, with no
    /// `ExecutionSucceeded`) is not produced by any real code path in the
    /// lab loop today, but the classification logic must still handle it
    /// correctly — this is a distinct case from the real pipeline test
    /// above, not a duplicate of it.
    #[test]
    fn synthetic_grant_with_signal_present_yields_detected() {
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();
        let now = Utc::now();
        store
            .log_event(&AuditEvent {
                timestamp: now,
                actor: "test-fixture".to_string(),
                subject_id: "T9001".to_string(),
                kind: EventKind::CapabilityGranted,
                detail: "synthetic grant for test".to_string(),
            })
            .unwrap();
        store
            .log_event(&AuditEvent {
                timestamp: now,
                actor: "test-fixture".to_string(),
                subject_id: "T9001".to_string(),
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
    /// aliases for the same fallthrough. Distinct from the real-pipeline
    /// test above: this exercises the bare `CapabilityGranted` event kind
    /// directly, not `ExecutionSucceeded`.
    #[test]
    fn synthetic_grant_with_signal_absent_yields_missed() {
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();
        let now = Utc::now();
        store
            .log_event(&AuditEvent {
                timestamp: now,
                actor: "test-fixture".to_string(),
                subject_id: "T9002".to_string(),
                kind: EventKind::CapabilityGranted,
                detail: "synthetic grant for test".to_string(),
            })
            .unwrap();
        store
            .log_event(&AuditEvent {
                timestamp: now,
                actor: "test-fixture".to_string(),
                subject_id: "T9002".to_string(),
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
