//! Append-only audit logging shared by the harness gate and the
//! attack/defend lab.
//!
//! Every capability grant, denial, and verdict is recorded via `tracing`
//! and persisted to a `redb`-backed store — not sampled, and not
//! LLM-summarized before logging.
