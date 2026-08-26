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

/// Reconstructs the full resulting file content for Pi's `edit` tool,
/// whose schema (confirmed directly from source,
/// `src/core/tools/edit.ts`) is an array of non-overlapping targeted
/// replacements applied against the *original* file, not incrementally:
/// each `oldText` "must be unique in the original file and must not
/// overlap with any other edits[].oldText in the same call" (quoted from
/// `edit.ts`'s own schema description). Validates uniqueness and
/// non-overlap against the true original content, then applies every
/// replacement in one pass — errors rather than guessing if either
/// constraint is violated, since silently applying overlapping or
/// non-unique edits could produce content Pi's own tool would have
/// rejected.
fn apply_pi_edits(original: &str, edits: &[(String, String)]) -> anyhow::Result<String> {
    let mut ranges: Vec<(usize, usize, &str)> = Vec::with_capacity(edits.len());
    for (old_text, new_text) in edits {
        let occurrences: Vec<usize> = original.match_indices(old_text.as_str()).map(|(i, _)| i).collect();
        match occurrences.len() {
            0 => return Err(anyhow::anyhow!("oldText not found in file: {old_text:?}")),
            1 => ranges.push((occurrences[0], occurrences[0] + old_text.len(), new_text.as_str())),
            n => return Err(anyhow::anyhow!("oldText appears {n} times in the file, must be unique: {old_text:?}")),
        }
    }

    ranges.sort_by_key(|&(start, _, _)| start);
    for i in 1..ranges.len() {
        if ranges[i].0 < ranges[i - 1].1 {
            return Err(anyhow::anyhow!("edits[] entries overlap, which the schema forbids"));
        }
    }

    let mut result = String::with_capacity(original.len());
    let mut cursor = 0;
    for (start, end, new_text) in ranges {
        result.push_str(&original[cursor..start]);
        result.push_str(new_text);
        cursor = end;
    }
    result.push_str(&original[cursor..]);
    Ok(result)
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
/// Copilot CLI's `create`. `edit` -> `FileWrite` too, reconstructed via
/// `apply_pi_edits` from the confirmed `path`/`edits: [{oldText, newText}]`
/// schema (`src/core/tools/edit.ts`) — a genuinely different shape from
/// Claude Code's single `old_string`/`new_string`/`replace_all`, not
/// assumed to match it. Every other tool name falls through to `Ok(None)`
/// — a disclosed gap, not a guess. See CONTEXT.md section 7.
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
        "edit" => {
            let path = input
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("edit input missing string field 'path'"))?;
            let edits_value = input
                .get("edits")
                .and_then(|v| v.as_array())
                .ok_or_else(|| anyhow::anyhow!("edit input missing array field 'edits'"))?;

            let mut edits = Vec::with_capacity(edits_value.len());
            for entry in edits_value {
                let old_text = entry
                    .get("oldText")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("edits[] entry missing string field 'oldText'"))?
                    .to_string();
                let new_text = entry
                    .get("newText")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("edits[] entry missing string field 'newText'"))?
                    .to_string();
                edits.push((old_text, new_text));
            }

            let current_content = std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("failed to read '{path}' to reconstruct the edit proposal: {e}"))?;
            let new_content = apply_pi_edits(&current_content, &edits)?;

            Ok(Some(Proposal::FileWrite { path: PathBuf::from(path), content: new_content }))
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
    fn bash_missing_command_field_errors_instead_of_guessing() {
        let result = to_proposal("bash", &serde_json::json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn edit_input_reconstructs_full_resulting_content() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("out.txt");
        std::fs::write(&file_path, "hello world").unwrap();
        let input = serde_json::json!({
            "path": file_path.to_str().unwrap(),
            "edits": [{ "oldText": "world", "newText": "there" }],
        });

        let proposal = to_proposal("edit", &input).unwrap();

        match proposal {
            Some(Proposal::FileWrite { path, content }) => {
                assert_eq!(path, file_path);
                assert_eq!(content, "hello there");
            }
            other => panic!("expected FileWrite, got {other:?}"),
        }
    }

    #[test]
    fn edit_applies_multiple_non_overlapping_edits_against_the_original() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("out.txt");
        std::fs::write(&file_path, "one two three").unwrap();
        let input = serde_json::json!({
            "path": file_path.to_str().unwrap(),
            "edits": [
                { "oldText": "one", "newText": "1" },
                { "oldText": "three", "newText": "3" },
            ],
        });

        let proposal = to_proposal("edit", &input).unwrap();

        match proposal {
            Some(Proposal::FileWrite { content, .. }) => assert_eq!(content, "1 two 3"),
            other => panic!("expected FileWrite, got {other:?}"),
        }
    }

    #[test]
    fn edit_with_non_unique_old_text_errors_instead_of_guessing() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("out.txt");
        std::fs::write(&file_path, "a a").unwrap();
        let input = serde_json::json!({
            "path": file_path.to_str().unwrap(),
            "edits": [{ "oldText": "a", "newText": "b" }],
        });

        assert!(to_proposal("edit", &input).is_err());
    }

    #[test]
    fn edit_missing_edits_field_errors_instead_of_guessing() {
        let input = serde_json::json!({ "path": "/workspace/out.txt" });
        assert!(to_proposal("edit", &input).is_err());
    }
}
