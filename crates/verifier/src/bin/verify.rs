//! Step 4 entry point. Run from the workspace root:
//! `cargo run -p verifier --bin verify`.

use audit::AuditStore;

fn main() -> anyhow::Result<()> {
    let store = AuditStore::open(".audit/store.redb")?;

    let records = verifier::verify(&store)?;
    verifier::persist(&store, &records)?;

    for r in &records {
        let verdict_str = match &r.verdict {
            verifier::Verdict::Detected => "Detected".to_string(),
            verifier::Verdict::Missed => "Missed".to_string(),
            verifier::Verdict::Blocked { reason } => format!("Blocked ({reason})"),
        };
        println!("[{}] {} at {}", r.technique_id, verdict_str, r.timestamp);
    }

    Ok(())
}
