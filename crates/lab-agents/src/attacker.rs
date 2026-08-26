use std::path::Path;

use audit::{AuditEvent, AuditStore, EventKind};
use chrono::Utc;
use host::{evaluate, CapabilityDecision, ScopeConfig};
use research_agent::{Technique, SYNTHETIC_SOURCE};

use crate::sandbox::{execute_synthetic_marker_write, ExecutionOutcome};

/// Outcome of one attacker attempt against a single queued technique.
///
/// `decision` is only the capability check's result (Granted/Denied) — it
/// does NOT by itself say whether anything actually executed. Callers that
/// need to know the real outcome (e.g. to print an accurate message) must
/// use `outcome_kind`/`detail` instead, which reflect the exact
/// `EventKind`/detail this attempt logged: `ExecutionSucceeded`/
/// `ExecutionFailed` for the synthetic proving technique's real execution,
/// `ExecutionBlocked` for a granted technique with no execution path (every
/// real Atomic Red Team technique today), or `CapabilityDenied` for a
/// denied one. A `Granted` decision with `outcome_kind: ExecutionBlocked`
/// and a `Granted` decision with `outcome_kind: ExecutionSucceeded` are
/// both "Granted" but mean very different things.
#[derive(Debug)]
pub struct AttackAttempt {
    pub technique_id: String,
    pub guid: String,
    pub decision: CapabilityDecision,
    pub outcome_kind: EventKind,
    pub detail: String,
}

/// Pulls every queued technique from the audit store and attempts each one
/// in turn, gated by `host::evaluate`. No technique's `test_command` is
/// ever executed by this v1: real wasmtime/WASI-Preview-2 sandbox
/// execution is not implemented yet — see the crate-level doc comment for
/// why that's a deliberate, disclosed gap rather than an oversight. Every
/// attempt (granted or denied) is logged via `audit`, matching CONTEXT.md
/// section 5.
///
/// Every attempt is checked against the same declared local-directory
/// target, if `scope` declares one — this v1 has no per-technique target
/// path (`research_agent::Technique` carries none), so every attempt is
/// understood to operate on the lab's own declared target directory as a
/// whole, resolved relative to `workspace_root`. No declared local-directory
/// target at all means no path is checked (unchanged, category-only
/// behavior), matching every scope from before this path check existed.
pub fn attempt_all(scope: &ScopeConfig, workspace_root: &Path, store: &AuditStore) -> anyhow::Result<Vec<AttackAttempt>> {
    let queued: Vec<(String, Technique)> = store.techniques()?;
    let mut attempts = Vec::with_capacity(queued.len());

    let target_path =
        scope.environment.targets.iter().find(|t| t.kind == "local-directory").map(|t| workspace_root.join(&t.identifier));

    for (guid, technique) in queued {
        let now = Utc::now();
        let decision = evaluate(scope, &technique.id, workspace_root, target_path.as_deref(), now);

        // Real execution is wired up ONLY for the synthetic proving
        // technique (see research_agent::synthetic) — every real,
        // ingested technique (including T1059) has no execution path yet
        // and must keep logging ExecutionBlocked exactly as before. A
        // Granted decision alone is not enough to execute: it must also be
        // the synthetic technique specifically, and there must be a real
        // target directory to execute against.
        let executable_target =
            if technique.source == SYNTHETIC_SOURCE { target_path.as_deref() } else { None };

        let (kind, detail) = match (&decision, executable_target) {
            (CapabilityDecision::Granted, Some(target_dir)) => match execute_synthetic_marker_write(workspace_root, target_dir) {
                Ok(ExecutionOutcome::Succeeded { detail }) => (EventKind::ExecutionSucceeded, detail),
                Ok(ExecutionOutcome::Failed { detail }) => (EventKind::ExecutionFailed, detail),
                Err(e) => (EventKind::ExecutionFailed, format!("sandbox construction error: {e}")),
            },
            (CapabilityDecision::Granted, None) => (
                EventKind::ExecutionBlocked,
                "capability granted by scope, but this v1 has no wasmtime/WASI-P2 sandbox execution path implemented — test_command was NOT run".to_string(),
            ),
            (CapabilityDecision::Denied { reason }, _) => (EventKind::CapabilityDenied, reason.clone()),
        };

        store.log_event(&AuditEvent {
            timestamp: now,
            actor: "lab-agents::attacker".to_string(),
            subject_id: technique.id.clone(),
            kind,
            detail: detail.clone(),
        })?;

        attempts.push(AttackAttempt {
            technique_id: technique.id.clone(),
            guid,
            decision,
            outcome_kind: kind,
            detail,
        });
    }

    Ok(attempts)
}

#[cfg(test)]
mod tests {
    use super::*;
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

    /// `lab/scope.toml` is no longer a permanent-deny placeholder — it now
    /// genuinely grants T1059 (real path enforcement, Step 2a/2b). This
    /// test used to prove every attempt was denied outright; it now proves
    /// the opposite half of the real behavior: granted, fully logged, but
    /// still never actually executed, since there is no wasmtime/WASI-P2
    /// execution engine yet (see this module's doc comment). Path
    /// enforcement and execution capability are separate gaps — this test
    /// exercises the first being real without implying the second is.
    #[test]
    fn every_attempt_against_real_scope_is_granted_but_blocked_at_execution() {
        let scope = ScopeConfig::load("../../lab/scope.toml").expect("lab/scope.toml should parse");
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();

        store.put_technique("test-guid-1", &fake_technique("T1059", "test-guid-1")).unwrap();

        let attempts = attempt_all(&scope, Path::new("../.."), &store).unwrap();

        assert_eq!(attempts.len(), 1);
        assert_eq!(
            attempts[0].decision,
            CapabilityDecision::Granted,
            "expected Granted under the real, populated lab/scope.toml, got {:?}",
            attempts[0].decision
        );

        let events = store.events().unwrap();
        assert_eq!(events.len(), 1, "every attempt must produce exactly one logged event");
        assert_eq!(events[0].kind, EventKind::ExecutionBlocked);
        assert_eq!(events[0].subject_id, "T1059");
        assert!(
            events[0].detail.contains("NOT run"),
            "granted must still not execute, since there is no execution engine yet"
        );
    }

    /// A capability grant is not enough to execute a technique in this v1
    /// — there is no wasmtime/WASI-P2 sandbox execution path yet, so a
    /// granted decision must still result in zero execution and an
    /// explicit ExecutionBlocked log entry, never a silent unsandboxed run.
    #[test]
    fn a_hypothetically_granted_decision_still_never_executes() {
        let scope_toml = r#"
            [environment]
            name = "test-lab"
            [techniques]
            allowed_categories = ["T1059"]
            allowed_sources = ["atomic-red-team"]
        "#;
        let scope: ScopeConfig = toml::from_str(scope_toml).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();
        store.put_technique("test-guid-2", &fake_technique("T1059", "test-guid-2")).unwrap();

        let attempts = attempt_all(&scope, Path::new("."), &store).unwrap();

        assert_eq!(attempts[0].decision, CapabilityDecision::Granted);
        let events = store.events().unwrap();
        assert_eq!(events[0].kind, EventKind::ExecutionBlocked);
        assert!(events[0].detail.contains("NOT run"));
    }

    /// Regression: adding real execution for the synthetic proving
    /// technique must not change behavior for any real, non-synthetic
    /// technique one bit — a Granted, atomic-red-team-sourced technique
    /// (T1059 included) must still log the exact same ExecutionBlocked
    /// event, byte-for-byte, that it did before this engine existed.
    #[test]
    fn granted_non_synthetic_technique_still_logs_execution_blocked_unchanged() {
        let scope_toml = r#"
            [environment]
            name = "test-lab"
            [[environment.targets]]
            id = "t1"
            type = "local-directory"
            identifier = "target"
            [techniques]
            allowed_categories = ["T1059"]
            allowed_sources = ["atomic-red-team"]
        "#;
        let scope: ScopeConfig = toml::from_str(scope_toml).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        std::fs::create_dir(workspace.path().join("target")).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();
        store.put_technique("test-guid-3", &fake_technique("T1059", "test-guid-3")).unwrap();

        let attempts = attempt_all(&scope, workspace.path(), &store).unwrap();

        assert_eq!(attempts[0].decision, CapabilityDecision::Granted);
        let events = store.events().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, EventKind::ExecutionBlocked);
        assert_eq!(
            events[0].detail,
            "capability granted by scope, but this v1 has no wasmtime/WASI-P2 sandbox execution path implemented — test_command was NOT run",
            "the real-technique ExecutionBlocked detail text must stay byte-for-byte unchanged"
        );
        assert!(
            !workspace.path().join("target").join(crate::sandbox::MARKER_FILE_NAME).exists(),
            "a non-synthetic technique must never trigger the execution engine, even with a real target dir present"
        );
    }

    /// The synthetic proving technique, and only it, actually executes:
    /// granted against a real target directory, it runs the guest module
    /// for real, writes the real marker file to disk, and logs
    /// `ExecutionSucceeded` — the first time this project's attacker
    /// actually executes anything rather than just logging that it didn't.
    #[test]
    fn granted_synthetic_proving_technique_actually_executes_and_writes_the_marker() {
        let scope_toml = r#"
            [environment]
            name = "test-lab"
            [[environment.targets]]
            id = "t1"
            type = "local-directory"
            identifier = "target"
            [techniques]
            allowed_categories = ["SYNTH-0001"]
            allowed_sources = ["synthetic-proving"]
        "#;
        let scope: ScopeConfig = toml::from_str(scope_toml).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let target_dir = workspace.path().join("target");
        std::fs::create_dir(&target_dir).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();

        let technique = research_agent::synthetic_proving_technique();
        store.put_technique(&technique.guid, &technique).unwrap();

        let attempts = attempt_all(&scope, workspace.path(), &store).unwrap();

        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].decision, CapabilityDecision::Granted);

        let events = store.events().unwrap();
        assert_eq!(events.len(), 1, "every attempt must produce exactly one logged event");
        assert_eq!(events[0].kind, EventKind::ExecutionSucceeded);
        assert_eq!(events[0].subject_id, "SYNTH-0001");

        let written = std::fs::read_to_string(target_dir.join(crate::sandbox::MARKER_FILE_NAME)).unwrap();
        assert_eq!(
            written,
            research_agent::MARKER_CONTENT,
            "the marker must actually land on disk with the real, unmodified content"
        );
    }
}
