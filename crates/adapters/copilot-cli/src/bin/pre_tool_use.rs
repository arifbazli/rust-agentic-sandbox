//! Real Copilot CLI `preToolUse` hook entry point: reads the hook's JSON
//! payload from stdin, runs it through `adapter_copilot_cli::handle_hook`,
//! and writes the hook's expected flat JSON to stdout.
//!
//! Fails closed, not open — and more robustly than the Claude Code
//! adapter can, per the current hooks reference
//! (https://docs.github.com/en/copilot/reference/hooks-reference): for
//! `preToolUse` specifically, exit 2 is an unconditional deny (forces
//! deny even if stdout JSON said allow), and *any other nonzero exit* is
//! ALSO fail-closed by default — the opposite of Claude Code's "other
//! codes proceed" model. The one real fail-open case Copilot CLI
//! documents is a hook timeout, which falls through to the normal
//! permission flow; this binary never blocks on anything unbounded
//! (stdin read ends when the pipe closes, the WASI dry-run write is a
//! bounded trivial operation), so that case isn't expected to occur in
//! practice, but it's a residual risk worth naming rather than pretending
//! away. Every explicit error path here (unreadable stdin, malformed
//! JSON, an audit-store failure, an error from `handle_hook` itself) is
//! caught and turned into an explicit deny + exit 2, per CONTEXT.md
//! section 2 (capability-default-deny).

use std::io::{self, Read};
use std::path::Path;

use adapter_copilot_cli::{handle_hook, HookInput, HookOutput};
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
        Err(_) => println!(r#"{{"permissionDecision":"deny","permissionDecisionReason":"adapter failed to serialize its own output"}}"#),
    }
    if output.is_deny() { 2 } else { 0 }
}
