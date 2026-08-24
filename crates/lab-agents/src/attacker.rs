use std::path::Path;

use audit::{AuditEvent, AuditStore, EventKind};
use chrono::Utc;
use host::{evaluate, CapabilityDecision, ScopeConfig};
use research_agent::Technique;

/// Outcome of one attacker attempt against a single queued technique.
#[derive(Debug)]
pub struct AttackAttempt {
    pub technique_id: String,
    pub guid: String,
    pub decision: CapabilityDecision,
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

        let (kind, detail) = match &decision {
            CapabilityDecision::Granted => (
                EventKind::ExecutionBlocked,
                "capability granted by scope, but this v1 has no wasmtime/WASI-P2 sandbox execution path implemented — test_command was NOT run".to_string(),
            ),
            CapabilityDecision::Denied { reason } => (EventKind::CapabilityDenied, reason.clone()),
        };

        store.log_event(&AuditEvent {
            timestamp: now,
            actor: "lab-agents::attacker".to_string(),
            subject_id: technique.id.clone(),
            kind,
            detail,
        })?;

        attempts.push(AttackAttempt {
            technique_id: technique.id.clone(),
            guid,
            decision,
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

    /// Against the real (expired, placeholder) `lab/scope.toml`, every
    /// attempt must be denied, fully logged, and never reach an
    /// execution branch — see CONTEXT.md sections 2, 3, and 5.
    #[test]
    fn every_attempt_against_real_scope_is_denied_and_fully_logged() {
        let scope = ScopeConfig::load("../../lab/scope.toml").expect("lab/scope.toml should parse");
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();

        store.put_technique("test-guid-1", &fake_technique("T1059", "test-guid-1")).unwrap();

        let attempts = attempt_all(&scope, Path::new("../.."), &store).unwrap();

        assert_eq!(attempts.len(), 1);
        assert!(
            matches!(attempts[0].decision, CapabilityDecision::Denied { .. }),
            "expected Denied under the current expired/placeholder scope, got {:?}",
            attempts[0].decision
        );

        let events = store.events().unwrap();
        assert_eq!(events.len(), 1, "every attempt must produce exactly one logged event");
        assert_eq!(events[0].kind, EventKind::CapabilityDenied);
        assert_eq!(events[0].subject_id, "T1059");

        let reached_execution = events
            .iter()
            .any(|e| matches!(e.kind, EventKind::ExecutionAttempted | EventKind::ExecutionBlocked | EventKind::CapabilityGranted));
        assert!(!reached_execution, "no execution branch should be reachable under a denying scope");
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
}
