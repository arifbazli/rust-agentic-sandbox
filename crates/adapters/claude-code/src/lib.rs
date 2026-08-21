//! Claude Code `PreToolUse` hook adapter.
//!
//! Translates Claude Code's `PreToolUse` hook payloads (proposed file
//! writes and shell commands) into `gate-pipeline` requests, and relays
//! the resulting deterministic verdict back as the hook's allow/deny
//! decision. No verdict logic lives here — every decision comes from
//! `gate_pipeline::review` + `host::gate_verdict::evaluate`, unchanged,
//! per CONTEXT.md section 7 (harness-adapter parity). This crate only
//! translates the payload shape on the way in and out.

mod hook_io;

pub use hook_io::{to_proposal, HookInput, HookOutput, HookSpecificOutput};

use std::path::Path;

use audit::{AuditEvent, AuditStore, EventKind};
use chrono::Utc;
use host::CapabilityDecision;

/// Handles one `PreToolUse` hook invocation end to end.
///
/// For a gated tool (`Bash`/`Write`, see `to_proposal`'s doc comment), runs
/// the proposal through `gate_pipeline::review` (evidence) and
/// `host::gate_verdict::evaluate` (verdict), tagged by the `subject_id`
/// `review` generates. For every other tool, passes through as `allow`
/// without invoking gate-pipeline at all — a disclosed v1 gap, not a
/// silent bypass of the pipeline (CONTEXT.md section 7 forbids the
/// latter).
///
/// Either way, the final decision is logged via the shared audit log as
/// an `EventKind::Verdict` event (the one variant no other crate emits
/// yet — verifier's equivalent goes through `put_verdict` instead, since
/// it persists a summary table rather than logging a log-shaped event),
/// so every hook invocation is instrumented, not just the gated ones.
pub fn handle_hook(input: &HookInput, workspace_root: &Path, store: &AuditStore) -> anyhow::Result<HookOutput> {
    let proposal = to_proposal(input)?;

    let Some(proposal) = proposal else {
        let subject_id = if input.tool_use_id.is_empty() {
            format!("ungated-{}", Utc::now().timestamp_nanos_opt().unwrap_or_default())
        } else {
            input.tool_use_id.clone()
        };
        let output = HookOutput::allow(format!("'{}' is not yet gated by adapter-claude-code", input.tool_name));
        log_verdict(store, &subject_id, input, &output)?;
        return Ok(output);
    };

    let subject_id = gate_pipeline::review(&proposal, workspace_root, store)?;
    let decision = host::gate_verdict::evaluate(store, &subject_id)?;

    let output = match decision {
        CapabilityDecision::Granted => HookOutput::allow("gate-pipeline granted this proposal"),
        CapabilityDecision::Denied { reason } => HookOutput::deny(reason),
    };
    log_verdict(store, &subject_id, input, &output)?;

    Ok(output)
}

fn log_verdict(store: &AuditStore, subject_id: &str, input: &HookInput, output: &HookOutput) -> anyhow::Result<()> {
    store.log_event(&AuditEvent {
        timestamp: Utc::now(),
        actor: "adapter-claude-code".to_string(),
        subject_id: subject_id.to_string(),
        kind: EventKind::Verdict,
        detail: format!(
            "PreToolUse hook for tool '{}': {} ({})",
            input.tool_name,
            output.hook_specific_output.permission_decision,
            output.hook_specific_output.permission_decision_reason
        ),
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gate_pipeline::Proposal;

    fn input_with(tool_name: &str, cwd: &str, tool_input: serde_json::Value) -> HookInput {
        HookInput {
            session_id: "test-session".to_string(),
            prompt_id: "test-prompt".to_string(),
            cwd: cwd.to_string(),
            permission_mode: "default".to_string(),
            hook_event_name: "PreToolUse".to_string(),
            tool_name: tool_name.to_string(),
            tool_input,
            tool_use_id: "toolu_test".to_string(),
        }
    }

    /// A safe, in-scope shell command must be allowed end to end, using
    /// the real `gate-pipeline::review` + `host::gate_verdict::evaluate`
    /// calls — no mocks.
    #[test]
    fn safe_bash_command_is_allowed() {
        let workspace = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();
        let input = input_with("Bash", workspace.path().to_str().unwrap(), serde_json::json!({ "command": "echo hello" }));

        let output = handle_hook(&input, workspace.path(), &store).unwrap();

        assert_eq!(output, HookOutput::allow("gate-pipeline granted this proposal"));
        let events = store.events().unwrap();
        assert!(events.iter().any(|e| e.kind == EventKind::Verdict && e.actor == "adapter-claude-code"));
    }

    /// A shell command matching gate-pipeline's deny-pattern table must be
    /// denied, with the denial reason surfaced verbatim in the hook
    /// output's `permissionDecisionReason`.
    #[test]
    fn destructive_bash_command_is_denied_by_static_analysis() {
        let workspace = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();
        let input =
            input_with("Bash", workspace.path().to_str().unwrap(), serde_json::json!({ "command": "rm -rf /tmp/scratch" }));

        let output = handle_hook(&input, workspace.path(), &store).unwrap();

        assert!(output.is_deny());
        assert!(!output.hook_specific_output.permission_decision_reason.is_empty());
        let events = store.events().unwrap();
        assert!(events.iter().any(|e| e.kind == EventKind::StaticAnalysisFlagged));
    }

    /// A `Write` proposal inside the workspace root must reach and
    /// complete the real WASI sandbox dry-run stage, not just the
    /// capability check — proving the adapter drives gate-pipeline's full
    /// two-stage pipeline, not a shortcut.
    ///
    /// Honest disclosure (CONTEXT.md section 6, "Honest negative
    /// results"): this test does NOT exercise a sandbox-stage *denial*,
    /// and it can't, through this call path. `dry_run_write` re-derives
    /// the same capability check as its own guard, and `review` only
    /// calls it after that check already granted — so by the time the
    /// sandbox stage runs here, it always succeeds. That path is
    /// unreachable via the real adapter today, same category as the lab
    /// loop's already-disclosed Detected/Missed unreachability
    /// (`verifier::verdict`'s doc comment). This test proves the granted
    /// path is driven correctly as far as it can go, not that a denial
    /// there was ever exercised — recording that gap explicitly rather
    /// than letting the test name imply more than it verifies.
    #[test]
    fn granted_file_write_reaches_and_completes_the_sandbox_stage() {
        let workspace = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();
        let file_path = workspace.path().join("out.txt");
        let input = input_with(
            "Write",
            workspace.path().to_str().unwrap(),
            serde_json::json!({ "file_path": file_path.to_str().unwrap(), "content": "hello" }),
        );

        let output = handle_hook(&input, workspace.path(), &store).unwrap();

        assert_eq!(output, HookOutput::allow("gate-pipeline granted this proposal"));
        let events = store.events().unwrap();
        assert!(events.iter().any(|e| e.kind == EventKind::SandboxDryRunSucceeded));
    }

    /// A `FileWrite` proposal outside the workspace root must be denied
    /// before the sandbox stage ever runs.
    #[test]
    fn file_write_outside_workspace_is_denied_by_capability_check() {
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();
        let file_path = outside.path().join("out.txt");
        let input = input_with(
            "Write",
            workspace.path().to_str().unwrap(),
            serde_json::json!({ "file_path": file_path.to_str().unwrap(), "content": "should never run" }),
        );

        let output = handle_hook(&input, workspace.path(), &store).unwrap();

        assert!(output.is_deny());
        let events = store.events().unwrap();
        assert!(!events.iter().any(|e| matches!(e.kind, EventKind::SandboxDryRunSucceeded | EventKind::SandboxDryRunDenied)));
    }

    /// A tool this v1 doesn't gate (e.g. `Edit`) must pass through as an
    /// explicit, logged allow — never silently ungated and never crashing
    /// the hook.
    #[test]
    fn ungated_tool_passes_through_as_logged_allow() {
        let workspace = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();
        let input = input_with(
            "Edit",
            workspace.path().to_str().unwrap(),
            serde_json::json!({ "file_path": "out.txt", "old_string": "a", "new_string": "b" }),
        );

        let output = handle_hook(&input, workspace.path(), &store).unwrap();

        assert!(!output.is_deny());
        let events = store.events().unwrap();
        assert!(events.iter().any(|e| e.kind == EventKind::Verdict && e.detail.contains("not yet gated")));
    }

    #[test]
    fn to_proposal_is_reexported_for_callers_that_only_need_translation() {
        let workspace = tempfile::tempdir().unwrap();
        let input = input_with("Bash", workspace.path().to_str().unwrap(), serde_json::json!({ "command": "echo hi" }));
        assert!(matches!(to_proposal(&input).unwrap(), Some(Proposal::ShellCommand { .. })));
    }
}
