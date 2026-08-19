//! Attacker and defender agent stubs for the attack/defend lab.
//!
//! Both agents are wasm-sandboxed and capability-scoped to the environment
//! declared in `lab/scope.toml`. Neither may reason about or act on
//! anything outside that declared scope; the boundary is enforced by
//! `host`'s capability grants, not by convention.
