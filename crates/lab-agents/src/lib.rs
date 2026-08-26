//! Attacker and defender agents for the attack/defend lab.
//!
//! Both agents are capability-scoped to the environment declared in
//! `lab/scope.toml`, enforced by `host`'s deterministic capability broker
//! (`host::evaluate`) — not by convention, and not by asking either agent
//! to stay in scope.
//!
//! **Real execution status:** a real `wasmtime`/WASI-Preview-1 execution
//! engine exists (`sandbox::execute_synthetic_marker_write`) — but it only
//! ever runs the synthetic proving technique
//! (`research_agent::synthetic_proving_technique`), a deliberately
//! trivial, self-authored operation built solely to prove the
//! execution-and-capture mechanism works end to end, not a real attack
//! technique.
//!
//! Every real, ingested Atomic Red Team technique — T1059 included —
//! still has no execution path, and still logs `ExecutionBlocked`
//! unchanged. A native `test_command` (a PowerShell/cmd/bash one-liner)
//! cannot literally run as WASM bytecode without either rewriting it into
//! a wasm probe (forbidden — commands must run verbatim or not at all) or
//! embedding a WASI-compiled shell interpreter, which itself can't invoke
//! arbitrary external binaries under WASI's process-free model (no
//! `fork`/`exec` exists at any WASI phase). Closing this for real
//! techniques is an open policy question, not yet decided or scheduled —
//! see `DESIGN-execution-engine.md`'s Option B (an OS-level sandboxed
//! subprocess, a materially different mechanism than wasmtime/WASI,
//! needing its own CONTEXT.md section 2 conversation first, not a
//! unilateral code change). Every attempt — executed or not — is still
//! capability-checked and logged in full.

mod attacker;
mod defender;
mod sandbox;

pub use attacker::{attempt_all, AttackAttempt};
pub use defender::{check_all, DetectionResult};
pub use sandbox::{execute_synthetic_marker_write, ExecutionOutcome, MARKER_FILE_NAME};
