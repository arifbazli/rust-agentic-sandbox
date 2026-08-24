//! GitHub Copilot CLI `preToolUse` hook adapter.
//!
//! Translates Copilot CLI's `preToolUse` hook payloads (currently, only
//! proposed shell commands — see `hook_io::to_proposal`'s doc comment for
//! why file-write proposals aren't gated yet) into `gate-pipeline`
//! requests, and relays the resulting deterministic verdict back as the
//! hook's allow/deny decision. No verdict logic lives here — every
//! decision comes from `gate_pipeline::review` + `host::gate_verdict::evaluate`,
//! unchanged, per CONTEXT.md section 7 (harness-adapter parity).

mod hook_io;

pub use hook_io::{to_proposal, HookInput, HookOutput};

use std::path::Path;

use audit::{AuditEvent, AuditStore, EventKind};
use chrono::Utc;
use host::CapabilityDecision;

/// Handles one `preToolUse` hook invocation end to end.
///
/// For a gated tool (`bash`, see `to_proposal`'s doc comment), runs the
/// proposal through `gate_pipeline::review` (evidence) and
/// `host::gate_verdict::evaluate` (verdict), tagged by the `subject_id`
/// `review` generates. For every other tool, passes through as `allow`
/// without invoking gate-pipeline at all — a disclosed v1 gap, not a
/// silent bypass of the pipeline.
///
/// Either way, the final decision is logged via the shared audit log as
/// an `EventKind::Verdict` event under `actor: "adapter-copilot-cli"`,
/// so every hook invocation is instrumented, not just the gated ones.
pub fn handle_hook(input: &HookInput, workspace_root: &Path, store: &AuditStore) -> anyhow::Result<HookOutput> {
    let proposal = to_proposal(input)?;

    let Some(proposal) = proposal else {
        let subject_id = if input.session_id.is_empty() {
            format!("ungated-{}", Utc::now().timestamp_nanos_opt().unwrap_or_default())
        } else {
            format!("{}-{}", input.session_id, input.timestamp)
        };
        let output = HookOutput::allow(format!("'{}' is not yet gated by adapter-copilot-cli", input.tool_name));
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
        actor: "adapter-copilot-cli".to_string(),
        subject_id: subject_id.to_string(),
        kind: EventKind::Verdict,
        detail: format!(
            "preToolUse hook for tool '{}': {} ({})",
            input.tool_name, output.permission_decision, output.permission_decision_reason
        ),
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gate_pipeline::Proposal;

    fn input_with(tool_name: &str, cwd: &str, tool_args: serde_json::Value) -> HookInput {
        HookInput {
            session_id: "test-session".to_string(),
            timestamp: 1704614400000,
            cwd: cwd.to_string(),
            tool_name: tool_name.to_string(),
            tool_args,
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
        let input = input_with("bash", workspace.path().to_str().unwrap(), serde_json::json!({ "command": "echo hello" }));

        let output = handle_hook(&input, workspace.path(), &store).unwrap();

        assert_eq!(output, HookOutput::allow("gate-pipeline granted this proposal"));
        let events = store.events().unwrap();
        assert!(events.iter().any(|e| e.kind == EventKind::Verdict && e.actor == "adapter-copilot-cli"));
    }

    /// A shell command matching gate-pipeline's deny-pattern table must
    /// be denied, with the denial reason surfaced verbatim in the hook
    /// output's `permissionDecisionReason`.
    #[test]
    fn destructive_bash_command_is_denied_by_static_analysis() {
        let workspace = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();
        let input =
            input_with("bash", workspace.path().to_str().unwrap(), serde_json::json!({ "command": "rm -rf /tmp/scratch" }));

        let output = handle_hook(&input, workspace.path(), &store).unwrap();

        assert!(output.is_deny());
        assert!(!output.permission_decision_reason.is_empty());
        let events = store.events().unwrap();
        assert!(events.iter().any(|e| e.kind == EventKind::StaticAnalysisFlagged));
    }

    /// Honest disclosure (CONTEXT.md section 6, "Honest negative
    /// results"): unlike `adapter-claude-code`, this adapter has NO
    /// gated tool that ever produces a `Proposal::FileWrite` — `create`
    /// (Copilot CLI's file-write tool) isn't gated at all, since its
    /// `toolArgs` schema is undocumented (see `to_proposal`'s doc
    /// comment). That means the sandbox dry-run stage is entirely
    /// unreachable through this adapter's real call path today — not
    /// just its denial case, as with the lab loop's already-disclosed
    /// Detected/Missed gap, but the whole stage, granted or denied. This
    /// test records that as an explicit, checked fact rather than
    /// omitting the case silently: `bash`'s proposals never produce a
    /// `SandboxDryRunSucceeded`/`SandboxDryRunDenied` event, for any
    /// input.
    #[test]
    fn sandbox_stage_is_unreachable_through_this_adapter_today() {
        let workspace = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();
        let input = input_with("bash", workspace.path().to_str().unwrap(), serde_json::json!({ "command": "echo hello" }));

        handle_hook(&input, workspace.path(), &store).unwrap();

        let events = store.events().unwrap();
        assert!(
            !events.iter().any(|e| matches!(e.kind, EventKind::SandboxDryRunSucceeded | EventKind::SandboxDryRunDenied)),
            "no gated Copilot CLI tool produces a FileWrite proposal today, so the sandbox stage must never fire"
        );
    }

    /// A tool this v1 doesn't gate (e.g. `create`) must pass through as
    /// an explicit, logged allow — never silently ungated and never
    /// crashing the hook.
    #[test]
    fn ungated_tool_passes_through_as_logged_allow() {
        let workspace = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();
        let input = input_with("create", workspace.path().to_str().unwrap(), serde_json::json!({ "path": "out.txt" }));

        let output = handle_hook(&input, workspace.path(), &store).unwrap();

        assert!(!output.is_deny());
        let events = store.events().unwrap();
        assert!(events.iter().any(|e| e.kind == EventKind::Verdict && e.detail.contains("not yet gated")));
    }

    #[test]
    fn to_proposal_is_reexported_for_callers_that_only_need_translation() {
        let workspace = tempfile::tempdir().unwrap();
        let input = input_with("bash", workspace.path().to_str().unwrap(), serde_json::json!({ "command": "echo hi" }));
        assert!(matches!(to_proposal(&input).unwrap(), Some(Proposal::ShellCommand { .. })));
    }
}
