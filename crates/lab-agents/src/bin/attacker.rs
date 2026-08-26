//! Step 2 entry point. Run from the workspace root:
//! `cargo run -p lab-agents --bin attacker`.

use audit::{AuditStore, EventKind};
use host::ScopeConfig;

fn main() -> anyhow::Result<()> {
    let scope = ScopeConfig::load("lab/scope.toml")?;
    let workspace_root = std::env::current_dir()?;
    let store = AuditStore::open(".audit/store.redb")?;

    let attempts = lab_agents::attempt_all(&scope, &workspace_root, &store)?;

    for attempt in &attempts {
        let label = match attempt.outcome_kind {
            EventKind::ExecutionSucceeded => "GRANTED, EXECUTED (succeeded)",
            EventKind::ExecutionFailed => "GRANTED, EXECUTED (failed)",
            EventKind::ExecutionBlocked => "GRANTED (no sandbox execution path implemented)",
            EventKind::CapabilityDenied => "DENIED",
            other => unreachable!("attempt_all never logs {other:?} for an attempt"),
        };
        println!("[{}] guid {} — {label}: {}", attempt.technique_id, attempt.guid, attempt.detail);
    }

    println!("\n{} attempt(s) logged to .audit/store.redb", attempts.len());
    Ok(())
}
