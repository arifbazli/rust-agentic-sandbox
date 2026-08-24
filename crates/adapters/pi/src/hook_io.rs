use gate_pipeline::Proposal;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// The JSON body the companion TS extension (`extension/pi-gate.ts`)
/// POSTs to this bridge for every intercepted `tool_call` event. Field
/// names confirmed against Pi's real extension API
/// (https://github.com/earendil-works/pi/tree/main/packages/coding-agent) —
/// `tool_name`/`input` mirror the TS `event.toolName`/`event.input`
/// fields exactly; `cwd` is supplied by the TS side via Node's own
/// `process.cwd()`, not a Pi API field (see `extension/pi-gate.ts`'s doc
/// comment for why).
#[derive(Debug, Clone, Deserialize)]
pub struct BridgeRequest {
    #[serde(rename = "toolName")]
    pub tool_name: String,
    pub input: serde_json::Value,
    pub cwd: String,
}

/// The bridge's own response protocol. This is NOT Pi's actual hook
/// wire format — Pi's real decision channel is the TS extension's own
/// return value (`undefined` or `{ block: true, reason }`); this JSON
/// is only the internal contract between this Rust process and its TS
/// shim, which translates `granted`/`reason` into that shape itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BridgeDecision {
    pub granted: bool,
    pub reason: String,
}

impl BridgeDecision {
    pub fn granted(reason: impl Into<String>) -> Self {
        Self { granted: true, reason: reason.into() }
    }

    pub fn denied(reason: impl Into<String>) -> Self {
        Self { granted: false, reason: reason.into() }
    }
}

/// Translates one intercepted `tool_call` event into a `gate-pipeline`
/// `Proposal`, for the tools this v1 actually gates.
///
/// `bash` -> `ShellCommand`, using the confirmed `command` field (see
/// `examples/extensions/permission-gate.ts` in Pi's repo). `write` ->
/// `FileWrite`, using the confirmed `path`/`content` fields (Pi's own
/// built-in tool schema, `src/core/tools/write.ts`) — this is the only
/// one of the three adapters where a real `content` field is confirmed,
/// so `write` genuinely reaches gate-pipeline's sandbox stage, unlike
/// Copilot CLI's `create`. `edit` only has a confirmed `path` field (via
/// `examples/extensions/protected-paths.ts`), no content/diff fields —
/// same disclosed gap as the other two adapters' `Edit`/`create`, so it
/// falls through to `Ok(None)` along with every other tool name. See
/// CONTEXT.md section 7.
pub fn to_proposal(tool_name: &str, input: &serde_json::Value) -> anyhow::Result<Option<Proposal>> {
    match tool_name {
        "bash" => {
            let command = input
                .get("command")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("bash input missing string field 'command'"))?
                .to_string();
            Ok(Some(Proposal::ShellCommand { command }))
        }
        "write" => {
            let path = input
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("write input missing string field 'path'"))?;
            let content = input
                .get("content")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("write input missing string field 'content'"))?
                .to_string();
            Ok(Some(Proposal::FileWrite { path: PathBuf::from(path), content }))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bash_input_becomes_shell_command_proposal() {
        let proposal = to_proposal("bash", &serde_json::json!({ "command": "echo hello" })).unwrap();
        assert!(matches!(proposal, Some(Proposal::ShellCommand { command }) if command == "echo hello"));
    }

    #[test]
    fn write_input_becomes_file_write_proposal() {
        let proposal = to_proposal("write", &serde_json::json!({ "path": "/workspace/out.txt", "content": "hi" })).unwrap();
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
        let proposal = to_proposal("edit", &serde_json::json!({ "path": "/workspace/out.txt" })).unwrap();
        assert!(proposal.is_none());
    }

    #[test]
    fn bash_missing_command_field_errors_instead_of_guessing() {
        let result = to_proposal("bash", &serde_json::json!({}));
        assert!(result.is_err());
    }
}
