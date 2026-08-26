//! Pi (pi.dev) TypeScript extension hook adapter.
//!
//! Pi extensions run in-process as TypeScript inside Pi's own Node.js
//! process (confirmed against https://github.com/earendil-works/pi) —
//! not a stdin/stdout hook like the other two adapters. This crate is
//! the Rust half of a bridge: `bin/pi_bridge.rs` runs a small, local,
//! persistent HTTP server; the companion TS extension
//! (`extension/pi-gate.ts`) intercepts Pi's `tool_call` event and POSTs
//! it here. `handle_hook` parses the proposal, calls the same
//! `gate_pipeline::review` + `host::gate_verdict::evaluate` used by the
//! other two adapters, translates the verdict to `BridgeDecision`, and
//! logs it — unchanged verdict standard, per CONTEXT.md section 7
//! (harness-adapter parity).

mod hook_io;

pub use hook_io::{to_proposal, BridgeDecision, BridgeRequest};

use std::path::Path;

use audit::{AuditEvent, AuditStore, EventKind};
use chrono::Utc;
use host::CapabilityDecision;

/// Handles one intercepted `tool_call` event end to end.
///
/// For a gated tool (`bash`/`write`/`edit`, see `to_proposal`'s doc
/// comment), runs the proposal through `gate_pipeline::review` (evidence) and
/// `host::gate_verdict::evaluate` (verdict), tagged by the `subject_id`
/// `review` generates. For every other tool, passes through as granted
/// without invoking gate-pipeline at all — a disclosed v1 gap, not a
/// silent bypass of the pipeline.
///
/// Either way, the final decision is logged via the shared audit log as
/// an `EventKind::Verdict` event under `actor: "adapter-pi"`, so every
/// intercepted tool call is instrumented, not just the gated ones.
pub fn handle_hook(
    tool_name: &str,
    input: &serde_json::Value,
    workspace_root: &Path,
    store: &AuditStore,
) -> anyhow::Result<BridgeDecision> {
    let proposal = to_proposal(tool_name, input)?;

    let Some(proposal) = proposal else {
        let subject_id = format!("ungated-{}", Utc::now().timestamp_nanos_opt().unwrap_or_default());
        let decision = BridgeDecision::granted(format!("'{tool_name}' is not yet gated by adapter-pi"));
        log_verdict(store, &subject_id, tool_name, &decision)?;
        return Ok(decision);
    };

    let subject_id = gate_pipeline::review(&proposal, workspace_root, store)?;
    let capability_decision = host::gate_verdict::evaluate(store, &subject_id)?;

    let decision = match capability_decision {
        CapabilityDecision::Granted => BridgeDecision::granted("gate-pipeline granted this proposal"),
        CapabilityDecision::Denied { reason } => BridgeDecision::denied(reason),
    };
    log_verdict(store, &subject_id, tool_name, &decision)?;

    Ok(decision)
}

fn log_verdict(store: &AuditStore, subject_id: &str, tool_name: &str, decision: &BridgeDecision) -> anyhow::Result<()> {
    store.log_event(&AuditEvent {
        timestamp: Utc::now(),
        actor: "adapter-pi".to_string(),
        subject_id: subject_id.to_string(),
        kind: EventKind::Verdict,
        detail: format!("tool_call for tool '{tool_name}': granted={} ({})", decision.granted, decision.reason),
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gate_pipeline::Proposal;

    /// A safe, in-scope shell command must be allowed end to end, using
    /// the real `gate-pipeline::review` + `host::gate_verdict::evaluate`
    /// calls — no mocks.
    #[test]
    fn safe_bash_command_is_allowed() {
        let workspace = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();

        let decision = handle_hook("bash", &serde_json::json!({ "command": "echo hello" }), workspace.path(), &store).unwrap();

        assert_eq!(decision, BridgeDecision::granted("gate-pipeline granted this proposal"));
        let events = store.events().unwrap();
        assert!(events.iter().any(|e| e.kind == EventKind::Verdict && e.actor == "adapter-pi"));
    }

    /// A shell command matching gate-pipeline's deny-pattern table must
    /// be denied, with the denial reason surfaced verbatim.
    #[test]
    fn destructive_bash_command_is_denied_by_static_analysis() {
        let workspace = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();

        let decision =
            handle_hook("bash", &serde_json::json!({ "command": "rm -rf /tmp/scratch" }), workspace.path(), &store).unwrap();

        assert!(!decision.granted);
        assert!(!decision.reason.is_empty());
        let events = store.events().unwrap();
        assert!(events.iter().any(|e| e.kind == EventKind::StaticAnalysisFlagged));
    }

    /// A `write` proposal inside the workspace root must reach and
    /// complete the real WASI sandbox dry-run stage, not just the
    /// capability check.
    ///
    /// Honest disclosure (CONTEXT.md section 6, "Honest negative
    /// results"): this test does NOT exercise a sandbox-stage *denial*,
    /// and it can't, through this call path — same gap as
    /// `adapter-claude-code`'s equivalent test. `dry_run_write`
    /// re-derives the same capability check as its own guard, and
    /// `review` only calls it after that check already granted, so by
    /// the time the sandbox stage runs here, it always succeeds. This
    /// test proves the granted path is driven correctly as far as it
    /// can go, not that a denial there was ever exercised — recording
    /// that gap explicitly rather than letting the test name imply more
    /// than it verifies.
    #[test]
    fn granted_write_reaches_and_completes_the_sandbox_stage() {
        let workspace = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();
        let file_path = workspace.path().join("out.txt");

        let decision = handle_hook(
            "write",
            &serde_json::json!({ "path": file_path.to_str().unwrap(), "content": "hello" }),
            workspace.path(),
            &store,
        )
        .unwrap();

        assert_eq!(decision, BridgeDecision::granted("gate-pipeline granted this proposal"));
        let events = store.events().unwrap();
        assert!(events.iter().any(|e| e.kind == EventKind::SandboxDryRunSucceeded));
    }

    /// A `write` proposal outside the workspace root must be denied
    /// before the sandbox stage ever runs.
    #[test]
    fn write_outside_workspace_is_denied_by_capability_check() {
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();
        let file_path = outside.path().join("out.txt");

        let decision = handle_hook(
            "write",
            &serde_json::json!({ "path": file_path.to_str().unwrap(), "content": "should never run" }),
            workspace.path(),
            &store,
        )
        .unwrap();

        assert!(!decision.granted);
        let events = store.events().unwrap();
        assert!(!events.iter().any(|e| matches!(e.kind, EventKind::SandboxDryRunSucceeded | EventKind::SandboxDryRunDenied)));
    }

    /// A tool this v1 doesn't gate (e.g. `view`) must pass through as an
    /// explicit, logged grant — never silently ungated.
    #[test]
    fn ungated_tool_passes_through_as_logged_grant() {
        let workspace = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();

        let decision = handle_hook("view", &serde_json::json!({ "path": "out.txt" }), workspace.path(), &store).unwrap();

        assert!(decision.granted);
        let events = store.events().unwrap();
        assert!(events.iter().any(|e| e.kind == EventKind::Verdict && e.detail.contains("not yet gated")));
    }

    /// An `edit` proposal inside the workspace root must reach and
    /// complete the real WASI sandbox dry-run stage — proving the
    /// reconstructed full-file content actually drives gate-pipeline's
    /// full pipeline. Same sandbox-stage-denial disclosure as the
    /// `write` test above: unreachable through this call path for the
    /// same structural reason.
    #[test]
    fn granted_edit_reaches_and_completes_the_sandbox_stage() {
        let workspace = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();
        let file_path = workspace.path().join("out.txt");
        std::fs::write(&file_path, "hello world").unwrap();

        let decision = handle_hook(
            "edit",
            &serde_json::json!({ "path": file_path.to_str().unwrap(), "edits": [{ "oldText": "world", "newText": "there" }] }),
            workspace.path(),
            &store,
        )
        .unwrap();

        assert_eq!(decision, BridgeDecision::granted("gate-pipeline granted this proposal"));
        let events = store.events().unwrap();
        assert!(events.iter().any(|e| e.kind == EventKind::SandboxDryRunSucceeded));
        assert_eq!(std::fs::read_to_string(&file_path).unwrap(), "hello world", "a dry-run must never touch the real file");
    }

    /// An `edit` proposal targeting a file outside the workspace root
    /// must be denied before the sandbox stage ever runs.
    #[test]
    fn edit_outside_workspace_is_denied_by_capability_check() {
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();
        let file_path = outside.path().join("out.txt");
        std::fs::write(&file_path, "hello world").unwrap();

        let decision = handle_hook(
            "edit",
            &serde_json::json!({ "path": file_path.to_str().unwrap(), "edits": [{ "oldText": "world", "newText": "there" }] }),
            workspace.path(),
            &store,
        )
        .unwrap();

        assert!(!decision.granted);
        let events = store.events().unwrap();
        assert!(!events.iter().any(|e| matches!(e.kind, EventKind::SandboxDryRunSucceeded | EventKind::SandboxDryRunDenied)));
    }

    #[test]
    fn to_proposal_is_reexported_for_callers_that_only_need_translation() {
        assert!(matches!(
            to_proposal("bash", &serde_json::json!({ "command": "echo hi" })).unwrap(),
            Some(Proposal::ShellCommand { .. })
        ));
    }
}
