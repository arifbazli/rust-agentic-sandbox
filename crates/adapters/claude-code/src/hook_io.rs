use std::path::PathBuf;

use gate_pipeline::Proposal;
use serde::{Deserialize, Serialize};

/// Claude Code's real `PreToolUse` hook input, delivered as JSON on stdin.
/// Field names and shape confirmed against the current hooks reference
/// (code.claude.com/docs/en/hooks.md), not assumed from memory — this
/// schema has changed over time. `tool_input`'s shape varies by
/// `tool_name`, so it's kept as raw JSON here and parsed per-tool in
/// `to_proposal`.
#[derive(Debug, Clone, Deserialize)]
pub struct HookInput {
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub prompt_id: String,
    pub cwd: String,
    #[serde(default)]
    pub permission_mode: String,
    #[serde(default)]
    pub hook_event_name: String,
    pub tool_name: String,
    pub tool_input: serde_json::Value,
    #[serde(default)]
    pub tool_use_id: String,
}

/// Claude Code's real `PreToolUse` hook output shape, confirmed field for
/// field against the current hooks reference
/// (https://code.claude.com/docs/en/hooks.md): `hookSpecificOutput`
/// nesting `hookEventName`/`permissionDecision`/`permissionDecisionReason`,
/// all camelCase. `permission_decision` is `"allow"` or `"deny"` here —
/// this adapter never emits the third documented value, `"escalate"`,
/// since `host::CapabilityDecision` is strictly binary (Granted/Denied)
/// with no third state to map it to. The schema also documents optional
/// fields this adapter doesn't set (`retry`, `additionalContext`,
/// `systemMessage`, `continue`, `terminalSequence`) — omitted here since
/// nothing in this adapter's decision needs them, not because they were
/// missed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HookOutput {
    #[serde(rename = "hookSpecificOutput")]
    pub hook_specific_output: HookSpecificOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HookSpecificOutput {
    #[serde(rename = "hookEventName")]
    pub hook_event_name: String,
    #[serde(rename = "permissionDecision")]
    pub permission_decision: String,
    #[serde(rename = "permissionDecisionReason")]
    pub permission_decision_reason: String,
}

impl HookOutput {
    pub fn allow(reason: impl Into<String>) -> Self {
        Self {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "allow".to_string(),
                permission_decision_reason: reason.into(),
            },
        }
    }

    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "deny".to_string(),
                permission_decision_reason: reason.into(),
            },
        }
    }

    pub fn is_deny(&self) -> bool {
        self.hook_specific_output.permission_decision == "deny"
    }
}

/// Translates a hook invocation into a `gate-pipeline` `Proposal`, for the
/// tools this v1 actually gates.
///
/// Only `Bash` (a direct `command` string) and `Write` (a direct
/// `file_path` + full `content`) are handled — both confirmed against the
/// current hooks reference. `Edit`'s `tool_input` carries an
/// `old_string`/`new_string` diff against an existing file, not a full new
/// file body; `Proposal::FileWrite` needs the whole intended content for
/// the sandbox dry-run, and reconstructing that from a diff is real,
/// separate work this v1 doesn't attempt. `Edit`, and every other tool,
/// fall through to `Ok(None)` — a disclosed gap (passthrough-allow, never
/// silently gated), not a guess. See CONTEXT.md section 7.
pub fn to_proposal(input: &HookInput) -> anyhow::Result<Option<Proposal>> {
    match input.tool_name.as_str() {
        "Bash" => {
            let command = input
                .tool_input
                .get("command")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("Bash tool_input missing string field 'command'"))?
                .to_string();
            Ok(Some(Proposal::ShellCommand { command }))
        }
        "Write" => {
            let file_path = input
                .tool_input
                .get("file_path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("Write tool_input missing string field 'file_path'"))?;
            let content = input
                .tool_input
                .get("content")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("Write tool_input missing string field 'content'"))?
                .to_string();
            Ok(Some(Proposal::FileWrite { path: PathBuf::from(file_path), content }))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input_with(tool_name: &str, tool_input: serde_json::Value) -> HookInput {
        HookInput {
            session_id: "test-session".to_string(),
            prompt_id: "test-prompt".to_string(),
            cwd: "/workspace".to_string(),
            permission_mode: "default".to_string(),
            hook_event_name: "PreToolUse".to_string(),
            tool_name: tool_name.to_string(),
            tool_input,
            tool_use_id: "toolu_test".to_string(),
        }
    }

    #[test]
    fn bash_tool_input_becomes_shell_command_proposal() {
        let input = input_with("Bash", serde_json::json!({ "command": "echo hello" }));
        let proposal = to_proposal(&input).unwrap();
        assert!(matches!(proposal, Some(Proposal::ShellCommand { command }) if command == "echo hello"));
    }

    #[test]
    fn write_tool_input_becomes_file_write_proposal() {
        let input = input_with("Write", serde_json::json!({ "file_path": "/workspace/out.txt", "content": "hi" }));
        let proposal = to_proposal(&input).unwrap();
        match proposal {
            Some(Proposal::FileWrite { path, content }) => {
                assert_eq!(path, PathBuf::from("/workspace/out.txt"));
                assert_eq!(content, "hi");
            }
            other => panic!("expected FileWrite, got {other:?}"),
        }
    }

    #[test]
    fn edit_tool_is_not_gated_in_this_v1() {
        let input = input_with("Edit", serde_json::json!({ "file_path": "/workspace/out.txt", "old_string": "a", "new_string": "b" }));
        let proposal = to_proposal(&input).unwrap();
        assert!(proposal.is_none());
    }

    #[test]
    fn bash_missing_command_field_errors_instead_of_guessing() {
        let input = input_with("Bash", serde_json::json!({}));
        assert!(to_proposal(&input).is_err());
    }
}
