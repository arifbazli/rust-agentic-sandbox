//! Harness gate review pipeline for proposed file writes/edits and shell
//! commands.
//!
//! Runs each proposal through static analysis (clippy/cargo-audit for
//! Rust, semgrep for other languages) and then a capability-scoped
//! `wasmtime`/WASI-Preview-2 sandbox dry-run, producing the evidence that
//! `host` uses to compute a deterministic verdict.

mod proposal;
mod review;
mod sandbox;
mod static_analysis;

pub use proposal::Proposal;
pub use review::review;
pub use sandbox::{dry_run_write, SandboxOutcome};
pub use static_analysis::static_analyze;
