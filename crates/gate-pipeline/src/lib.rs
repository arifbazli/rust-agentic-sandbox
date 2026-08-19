//! Harness gate review pipeline for proposed file writes/edits and shell
//! commands.
//!
//! Runs each proposal through static analysis (clippy/cargo-audit for
//! Rust, semgrep for other languages) and then a capability-scoped
//! `wasmtime`/WASI-Preview-2 sandbox dry-run, producing the evidence that
//! `host` uses to compute a deterministic verdict.
