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
pub fn attempt_all(scope: &ScopeConfig, store: &AuditStore) -> anyhow::Result<Vec<AttackAttempt>> {
    let queued: Vec<(String, Technique)> = store.techniques()?;
    let mut attempts = Vec::with_capacity(queued.len());

    for (guid, technique) in queued {
        let now = Utc::now();
        let decision = evaluate(scope, &technique.id, now);

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
            technique_id: technique.id.clone(),
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
