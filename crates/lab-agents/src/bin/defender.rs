//! Step 3 entry point. Run from the workspace root:
//! `cargo run -p lab-agents --bin defender`.

use audit::AuditStore;

fn main() -> anyhow::Result<()> {
    let store = AuditStore::open(".audit/store.redb")?;
    let results = lab_agents::check_all(&store)?;

    for r in &results {
        println!(
            "[{}] expected: {} — present: {}{}",
            r.technique_id,
            r.expected_signal,
            r.signal_present,
            r.referenced_event
                .as_ref()
                .map(|e| format!(" — log entry: {:?} at {} ({})", e.kind, e.timestamp, e.detail))
                .unwrap_or_default()
        );
    }

    Ok(())
}
