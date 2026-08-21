use audit::{AuditStore, EventKind};

use crate::broker::CapabilityDecision;

/// Deterministic final verdict for one harness-gate proposal, computed
/// purely by reading `gate-pipeline`'s logged evidence for `subject_id` in
/// the shared audit log — the same read-log-then-decide shape as
/// `verifier::verify()` uses for the lab loop.
///
/// This function is the **only** connection between `host` and
/// `gate-pipeline`: the audit log. `host` does not, and must not, depend
/// on the `gate-pipeline` crate directly — `gate-pipeline` already depends
/// on `host` (for `evaluate_file_write`), so a reverse dependency would
/// create a cycle. Evidence flows from `gate-pipeline` to `host` entirely
/// through `audit::AuditStore`, tagged by `subject_id`, never through a
/// Rust type shared between the two crates.
///
/// No model call anywhere in this function — see CONTEXT.md section 1.
pub fn evaluate(store: &AuditStore, subject_id: &str) -> anyhow::Result<CapabilityDecision> {
    let events = store.events()?;
    let subject_events: Vec<_> = events.into_iter().filter(|e| e.subject_id == subject_id).collect();

    // Any denial event, regardless of stage (static analysis, capability,
    // or sandbox), results in a Denied verdict — the checks below are
    // ordered for clarity, not because order affects the outcome (the
    // event kinds are mutually exclusive per proposal type).
    if let Some(event) = subject_events.iter().find(|e| e.kind == EventKind::StaticAnalysisFlagged) {
        return Ok(CapabilityDecision::Denied { reason: event.detail.clone() });
    }
    if let Some(event) = subject_events.iter().find(|e| e.kind == EventKind::CapabilityDenied) {
        return Ok(CapabilityDecision::Denied { reason: event.detail.clone() });
    }
    if let Some(event) = subject_events.iter().find(|e| e.kind == EventKind::SandboxDryRunDenied) {
        return Ok(CapabilityDecision::Denied { reason: event.detail.clone() });
    }
    if subject_events.iter().any(|e| matches!(e.kind, EventKind::StaticAnalysisClean | EventKind::CapabilityGranted)) {
        return Ok(CapabilityDecision::Granted);
    }

    Ok(CapabilityDecision::Denied { reason: format!("no evidence found in the audit log for subject {subject_id}") })
}

#[cfg(test)]
mod tests {
    use super::*;
    use audit::AuditEvent;
    use chrono::Utc;

    fn log(store: &AuditStore, subject_id: &str, kind: EventKind, detail: &str) {
        store
            .log_event(&AuditEvent {
                timestamp: Utc::now(),
                actor: "test-fixture".to_string(),
                subject_id: subject_id.to_string(),
                kind,
                detail: detail.to_string(),
            })
            .unwrap();
    }

    #[test]
    fn static_analysis_flagged_denies() {
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();
        log(&store, "p1", EventKind::StaticAnalysisFlagged, "matched deny pattern");
        assert!(matches!(evaluate(&store, "p1").unwrap(), CapabilityDecision::Denied { .. }));
    }

    #[test]
    fn capability_denied_denies() {
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();
        log(&store, "p1", EventKind::CapabilityDenied, "outside the workspace root");
        assert!(matches!(evaluate(&store, "p1").unwrap(), CapabilityDecision::Denied { .. }));
    }

    #[test]
    fn sandbox_dry_run_denied_denies() {
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();
        log(&store, "p1", EventKind::CapabilityGranted, "inside workspace");
        log(&store, "p1", EventKind::SandboxDryRunDenied, "wasi rejected the write");
        assert!(matches!(evaluate(&store, "p1").unwrap(), CapabilityDecision::Denied { .. }));
    }

    #[test]
    fn clean_static_analysis_grants() {
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();
        log(&store, "p1", EventKind::StaticAnalysisClean, "no deny pattern matched");
        assert_eq!(evaluate(&store, "p1").unwrap(), CapabilityDecision::Granted);
    }

    #[test]
    fn granted_capability_and_successful_sandbox_grants() {
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();
        log(&store, "p1", EventKind::CapabilityGranted, "inside workspace");
        log(&store, "p1", EventKind::SandboxDryRunSucceeded, "write succeeded");
        assert_eq!(evaluate(&store, "p1").unwrap(), CapabilityDecision::Granted);
    }

    #[test]
    fn no_evidence_denies() {
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();
        assert!(matches!(evaluate(&store, "never-reviewed").unwrap(), CapabilityDecision::Denied { .. }));
    }
}
