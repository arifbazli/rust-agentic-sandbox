//! Trusted orchestrator: capability broker and deterministic verdict engine.
//!
//! `host` sits at the center of both the harness gate and the attack/defend
//! lab. It is the only component authorized to grant sandbox capabilities
//! or emit a final pass/fail/block verdict; every other crate in this
//! workspace feeds proposals or evidence into it and receives a verdict
//! back. LLM-backed agents may summarize a verdict but never author or
//! override one.
