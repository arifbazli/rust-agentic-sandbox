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
    /// Identifier of the subject this event concerns — an ATT&CK technique
    /// ID for lab-loop events, or a harness-gate proposal ID for
    /// gate-pipeline events. Empty if not applicable.
    pub subject_id: String,
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
    /// `gate-pipeline`'s deny-pattern static analysis found nothing (used
    /// for `ShellCommand` proposals only — `FileWrite` proposals log
    /// `CapabilityGranted`/`CapabilityDenied` instead, since their check is
    /// a genuine capability decision, not a deny-pattern scan).
    StaticAnalysisClean,
    /// `gate-pipeline`'s deny-pattern static analysis matched a rule.
    StaticAnalysisFlagged,
    /// `gate-pipeline`'s real WASI sandbox dry-run write succeeded.
    SandboxDryRunSucceeded,
    /// `gate-pipeline`'s real WASI sandbox dry-run write was denied —
    /// either the capability check failed before any sandbox was
    /// constructed, or the WASI runtime itself rejected the write.
    SandboxDryRunDenied,
}
