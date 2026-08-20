//! Step 1 entry point: ingest Atomic Red Team techniques declared in
//! `lab/scope.toml` into the shared audit store's technique queue.
//! Run from the workspace root: `cargo run -p research-agent --bin ingest`.

use audit::AuditStore;
use host::ScopeConfig;

fn main() -> anyhow::Result<()> {
    let scope = ScopeConfig::load("lab/scope.toml")?;
    let store = AuditStore::open(".audit/store.redb")?;

    let report = research_agent::ingest(&scope, &store)?;

    println!("ingested: {}", report.ingested.len());
    for t in &report.ingested {
        println!(
            "  [{}] {} ({}) — guid {} — platform: {}",
            t.id, t.name, t.source, t.guid, t.platform
        );
    }

    println!("excluded by scope (never fetched): {:?}", report.excluded_by_scope);
    println!(
        "allowed but no upstream definition found (honest negative result): {:?}",
        report.not_found_upstream
    );

    Ok(())
}
