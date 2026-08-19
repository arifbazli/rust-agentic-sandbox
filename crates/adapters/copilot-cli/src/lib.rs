//! GitHub Copilot CLI `preToolUse` hook adapter.
//!
//! Translates Copilot CLI's `preToolUse` hook payloads (proposed file
//! writes/edits and shell commands) into `gate-pipeline` requests, and
//! relays the resulting deterministic verdict back as the hook's
//! allow/block decision.
