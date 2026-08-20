//! Attacker and defender agents for the attack/defend lab.
//!
//! Both agents are capability-scoped to the environment declared in
//! `lab/scope.toml`, enforced by `host`'s deterministic capability broker
//! (`host::evaluate`) — not by convention, and not by asking either agent
//! to stay in scope.
//!
//! **v1 scope gap, disclosed on purpose:** the attacker does not execute
//! any technique inside a `wasmtime`/WASI-Preview-2 sandbox yet. A native
//! Atomic Red Team `test_command` (a PowerShell/cmd/bash one-liner) cannot
//! literally run as WASM bytecode without either rewriting it into a wasm
//! probe (forbidden — commands must run verbatim or not at all) or
//! embedding a WASI-compiled shell interpreter (a separate, substantial
//! piece of work). Since `host::evaluate` currently denies every
//! technique against the real `lab/scope.toml` (its validity window has
//! already expired, and it is explicitly an unpopulated placeholder), that
//! execution branch is unreachable this session regardless — so it was not
//! built. Every attempt is still capability-checked and logged in full.

mod attacker;
mod defender;

pub use attacker::{attempt_all, AttackAttempt};
pub use defender::{check_all, DetectionResult};
