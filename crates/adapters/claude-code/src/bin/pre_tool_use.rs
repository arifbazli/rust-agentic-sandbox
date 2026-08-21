//! Real Claude Code `PreToolUse` hook entry point: reads the hook's JSON
//! payload from stdin, runs it through `adapter_claude_code::handle_hook`,
//! and writes the hook's expected JSON to stdout.
//!
//! Fails closed, not open. Per the current hooks reference
//! (https://code.claude.com/docs/en/hooks.md), exit 2 is an unconditional
//! block — the tool call is prevented regardless of what JSON is present,
//! with the message coming from `permissionDecisionReason` if set or
//! stderr otherwise. Any other exit code (1, 3, ...) is a non-blocking
//! error: the action proceeds, JSON decision fields are honored only if
//! present, and otherwise Claude Code just shows a generic hook-error
//! notice. A crashing or panicking hook that never gets to print anything
//! and exits with one of those other codes would let the proposed action
//! through unchecked — so every error path here (unreadable stdin,
//! malformed JSON, an audit-store failure, an error from `handle_hook`
//! itself) is caught in ordinary `Result` control flow and turned into an
//! explicit deny + exit 2, never left to fall through to an uncontrolled
//! exit code, per CONTEXT.md section 2 (capability-default-deny).

use std::io::{self, Read};
use std::path::Path;

use adapter_claude_code::{handle_hook, HookInput, HookOutput};
use audit::AuditStore;

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let mut raw_input = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut raw_input) {
        return respond(&HookOutput::deny(format!("failed to read hook input from stdin: {e}")));
    }

    let input: HookInput = match serde_json::from_str(&raw_input) {
        Ok(input) => input,
        Err(e) => return respond(&HookOutput::deny(format!("failed to parse hook input JSON: {e}"))),
    };

    let store = match AuditStore::open(".audit/store.redb") {
        Ok(store) => store,
        Err(e) => return respond(&HookOutput::deny(format!("failed to open audit store: {e}"))),
    };

    let workspace_root = Path::new(&input.cwd);
    match handle_hook(&input, workspace_root, &store) {
        Ok(output) => respond(&output),
        Err(e) => respond(&HookOutput::deny(format!("adapter error, failing closed: {e}"))),
    }
}

fn respond(output: &HookOutput) -> i32 {
    match serde_json::to_string(output) {
        Ok(json) => println!("{json}"),
        Err(_) => println!(
            r#"{{"hookSpecificOutput":{{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"adapter failed to serialize its own output"}}}}"#
        ),
    }
    if output.is_deny() { 2 } else { 0 }
}
