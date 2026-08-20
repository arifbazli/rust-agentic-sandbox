use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A single deterministically-logged occurrence: a capability grant/denial,
/// an execution attempt, a detection check, or a verdict. See CONTEXT.md
/// section 5 ("Deterministic instrumentation") — every one of these is
/// logged in full, never sampled or LLM-summarized before being written.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: DateTime<Utc>,
    /// Which component emitted this, e.g. "lab-agents::attacker", "host::broker".
    pub actor: String,
    /// ATT&CK technique ID this event concerns, empty if not applicable.
    pub technique_id: String,
    pub kind: EventKind,
    /// Human-readable reason/context for the event.
    pub detail: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventKind {
    CapabilityGranted,
    CapabilityDenied,
    ExecutionAttempted,
    ExecutionBlocked,
    DetectionChecked,
    Verdict,
}
