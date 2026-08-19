//! Claude Code `PreToolUse` hook adapter.
//!
//! Translates Claude Code's `PreToolUse` hook payloads (proposed file
//! writes/edits and shell commands) into `gate-pipeline` requests, and
//! relays the resulting deterministic verdict back as the hook's
//! allow/block decision.
