//! Deterministic outcome verification for the attack/defend lab.
//!
//! Confirms whether an attack succeeded and whether a defense actually
//! blocked it using real, checkable post-conditions against the lab
//! environment. Never an LLM judge.

mod verdict;

pub use verdict::{persist, verify, Verdict, VerdictRecord};
