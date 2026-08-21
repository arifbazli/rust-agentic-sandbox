use std::path::PathBuf;

/// A file write/edit or shell command an AI coding agent has proposed,
/// before it touches disk or executes. See CONTEXT.md sections 1-3 — this
/// is the evidence `gate-pipeline` reviews; it never decides anything
/// itself, `host` does.
#[derive(Debug, Clone)]
pub enum Proposal {
    FileWrite { path: PathBuf, content: String },
    ShellCommand { command: String },
}
