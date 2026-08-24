//! Step 2 entry point. Run from the workspace root:
//! `cargo run -p lab-agents --bin attacker`.

use audit::AuditStore;
use host::{CapabilityDecision, ScopeConfig};

fn main() -> anyhow::Result<()> {
    let scope = ScopeConfig::load("lab/scope.toml")?;
    let workspace_root = std::env::current_dir()?;
    let store = AuditStore::open(".audit/store.redb")?;

    let attempts = lab_agents::attempt_all(&scope, &workspace_root, &store)?;

    for attempt in &attempts {
        match &attempt.decision {
            CapabilityDecision::Granted => {
                println!("[{}] guid {} — GRANTED (no sandbox execution path implemented — see lab-agents crate docs)", attempt.technique_id, attempt.guid)
            }
            CapabilityDecision::Denied { reason } => {
                println!("[{}] guid {} — DENIED: {reason}", attempt.technique_id, attempt.guid)
            }
        }
    }

    println!("\n{} attempt(s) logged to .audit/store.redb", attempts.len());
    Ok(())
}
