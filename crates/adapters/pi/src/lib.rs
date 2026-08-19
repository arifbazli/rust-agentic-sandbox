//! Pi (pi.dev) TypeScript extension hook adapter.
//!
//! A thin Rust<->TS bridge: forwards Pi's extension hook events (proposed
//! file writes/edits and shell commands) into `gate-pipeline` and relays
//! the resulting deterministic verdict back to the TypeScript extension as
//! its allow/block decision.
