use gate_pipeline::Proposal;
use serde::{Deserialize, Serialize};

/// Copilot CLI's real `preToolUse` hook input, delivered as JSON on
/// stdin, in its native camelCase format (there's also a separate
/// "VS Code compatible" snake_case alias format documented, not used
/// here). Confirmed against the current hooks reference
/// (https://docs.github.com/en/copilot/reference/hooks-reference).
/// Deliberately NOT the same shape as Claude Code's `HookInput` —
/// `toolName`/`toolArgs` here, not `tool_name`/`tool_input`, and no
/// `hook_event_name`/`permission_mode`/`tool_use_id` fields exist at all.
#[derive(Debug, Clone, Deserialize)]
pub struct HookInput {
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub timestamp: i64,
    pub cwd: String,
    pub tool_name: String,
    pub tool_args: serde_json::Value,
}

/// Copilot CLI's real `preToolUse` hook output shape — a flat top-level
/// object, unlike Claude Code's `hookSpecificOutput`-nested shape.
/// `permission_decision` is `"allow"` or `"deny"` here — this adapter
/// never emits the third documented value, `"ask"` (which Copilot CLI
/// itself treats as `"deny"` under a cloud agent anyway, since
/// `host::CapabilityDecision` is strictly binary with no third state to
/// map it to. `modifiedArgs` (documented, optional) is never set — this
/// adapter only allows/denies, it never rewrites a proposal's arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HookOutput {
    #[serde(rename = "permissionDecision")]
    pub permission_decision: String,
    #[serde(rename = "permissionDecisionReason")]
    pub permission_decision_reason: String,
}

impl HookOutput {
    pub fn allow(reason: impl Into<String>) -> Self {
        Self { permission_decision: "allow".to_string(), permission_decision_reason: reason.into() }
    }

    pub fn deny(reason: impl Into<String>) -> Self {
        Self { permission_decision: "deny".to_string(), permission_decision_reason: reason.into() }
    }

    pub fn is_deny(&self) -> bool {
        self.permission_decision == "deny"
    }
}

/// Resolves `tool_args` to a JSON object, tolerating either encoding the
/// current docs leave ambiguous: a native nested object, or a
/// JSON-encoded string (the one concrete sample in the hooks reference's
/// "test it locally" snippet shows `"toolArgs":"{\"command\":\"ls\"}"` —
/// a string containing escaped JSON, not a directly nested object). This
/// isn't a guess about field names (`command` is confirmed by that
/// sample); it's defensive handling of a genuinely ambiguous wire
/// encoding the docs never disambiguate.
fn resolve_tool_args(tool_args: &serde_json::Value) -> anyhow::Result<serde_json::Value> {
    match tool_args {
        serde_json::Value::Object(_) => Ok(tool_args.clone()),
        serde_json::Value::String(s) => {
            serde_json::from_str(s).map_err(|e| anyhow::anyhow!("toolArgs string did not contain valid JSON: {e}"))
        }
        other => Err(anyhow::anyhow!("toolArgs was neither an object nor a string: {other:?}")),
    }
}

/// Translates a hook invocation into a `gate-pipeline` `Proposal`, for
/// the tools this v1 actually gates.
///
/// Only `bash` is handled — its `command` field is confirmed by the
/// hooks reference's own "test it locally" sample. `create` (Copilot
/// CLI's file-write tool) and `edit` both have NO documented `toolArgs`
/// schema anywhere in the current reference.
///
/// Re-investigated 2026-08-26, wider than the prior two checks: the
/// full docs hub, the hooks conceptual page, `hooks-reference`,
/// `allowing-tools`, the `using-copilot-cli` overview,
/// `configure-copilot-cli`, the sandboxes page, and the "Agent Plugins
/// 1.0" changelog entry — none document `create`'s fields. Two things
/// this pass found that the earlier checks didn't:
///   - `hooks-reference`'s own TypeScript types declare `toolArgs` (and
///     its snake_case alias `tool_input`) as `unknown` — a stronger
///     fact than "undocumented": GitHub's own reference deliberately
///     leaves it untyped, not merely silent on it.
///   - That same page's Claude-tool-name compatibility table maps
///     `create` -> `Write` and `edit`/`str_replace_editor`/`apply_patch`
///     -> `Edit`. Useful context on how the hook layer is structured,
///     but it's a *name* mapping, not an argument schema — no field
///     names surface anywhere in it.
///
/// `github/copilot-cli` (a real, public, 11k+-star repo) was checked
/// directly this round — its contents are only `.github/`,
/// `LICENSE.md`, `README.md`, `changelog.md`, `install.sh`: a
/// distribution/issue-tracker repo, not a source repo, confirming (not
/// overturning) that there's no public source to read a real schema
/// from instead, unlike Pi. Its issue tracker was searched: issue
/// https://github.com/github/copilot-cli/issues/3349 ("Document safe
/// parsing for preToolUse.toolArgs when it is a JSON-encoded string")
/// confirms this ambiguity is an acknowledged upstream gap, not just
/// something this project failed to find.
///
/// Not attempted this round: dumping the real payload from a live
/// `create` call via an actual local Copilot CLI install — none was
/// available in this environment. That's a genuine limitation of this
/// investigation, not a closed door on a future one.
///
/// So both `create` and `edit` stay ungated — a disclosed gap rather
/// than a guessed shape. `edit` and every other tool name fall through
/// to `Ok(None)` for the same reason. See CONTEXT.md section 7.
pub fn to_proposal(input: &HookInput) -> anyhow::Result<Option<Proposal>> {
    match input.tool_name.as_str() {
        "bash" => {
            let args = resolve_tool_args(&input.tool_args)?;
            let command = args
                .get("command")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("bash toolArgs missing string field 'command'"))?
                .to_string();
            Ok(Some(Proposal::ShellCommand { command }))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input_with(tool_name: &str, tool_args: serde_json::Value) -> HookInput {
        HookInput {
            session_id: "test-session".to_string(),
            timestamp: 1704614400000,
            cwd: "/workspace".to_string(),
            tool_name: tool_name.to_string(),
            tool_args,
        }
    }

    #[test]
    fn bash_with_native_object_tool_args_becomes_shell_command_proposal() {
        let input = input_with("bash", serde_json::json!({ "command": "echo hello" }));
        let proposal = to_proposal(&input).unwrap();
        assert!(matches!(proposal, Some(Proposal::ShellCommand { command }) if command == "echo hello"));
    }

    #[test]
    fn bash_with_string_encoded_tool_args_becomes_shell_command_proposal() {
        let input = input_with("bash", serde_json::Value::String(r#"{"command":"ls"}"#.to_string()));
        let proposal = to_proposal(&input).unwrap();
        assert!(matches!(proposal, Some(Proposal::ShellCommand { command }) if command == "ls"));
    }

    #[test]
    fn create_tool_is_not_gated_in_this_v1() {
        let input = input_with("create", serde_json::json!({ "path": "/workspace/out.txt" }));
        let proposal = to_proposal(&input).unwrap();
        assert!(proposal.is_none());
    }

    #[test]
    fn bash_missing_command_field_errors_instead_of_guessing() {
        let input = input_with("bash", serde_json::json!({}));
        assert!(to_proposal(&input).is_err());
    }
}
