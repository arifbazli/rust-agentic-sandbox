use audit::{AuditEvent, AuditStore, EventKind};
use chrono::Utc;

/// Fixed, deterministic table of what audit-log signal we'd expect for a
/// given ATT&CK category's execution attempt. This is plain Rust data, not
/// agent reasoning — see CONTEXT.md section 1 ("Verdict authority").
fn expected_signal(category: &str) -> &'static str {
    match category {
        "T1059" => "a CapabilityGranted or CapabilityDenied event for a Command and Scripting Interpreter attempt",
        "T1078" => "a CapabilityGranted or CapabilityDenied event for a Valid Accounts attempt",
        _ => "a CapabilityGranted or CapabilityDenied event for this technique's attempt",
    }
}

#[derive(Debug)]
pub struct DetectionResult {
    pub technique_id: String,
    pub expected_signal: &'static str,
    pub signal_present: bool,
    /// The specific log entry that satisfied the check, if any.
    pub referenced_event: Option<AuditEvent>,
}

/// For every queued technique, checks whether the expected capability-
/// decision signal was logged. Note on what this currently proves: since
/// every attempt this session was denied before execution (see
/// attacker.rs), a "present" result here means "the denial itself was
/// observably logged" — not "a real intrusion attempt was detected". The
/// two only become distinguishable once `lab/scope.toml` grants real
/// capabilities and executions can actually proceed.
pub fn check_all(store: &AuditStore) -> anyhow::Result<Vec<DetectionResult>> {
    let events = store.events()?;
    let queued: Vec<(String, research_agent::Technique)> = store.techniques()?;

    let mut results = Vec::with_capacity(queued.len());
    for (_, technique) in queued {
        let referenced_event = events
            .iter()
            .rev()
            .find(|e| {
                e.technique_id == technique.id
                    && matches!(e.kind, EventKind::CapabilityGranted | EventKind::CapabilityDenied)
            })
            .cloned();

        let signal_present = referenced_event.is_some();
        store.log_event(&AuditEvent {
            timestamp: Utc::now(),
            actor: "lab-agents::defender".to_string(),
            technique_id: technique.id.clone(),
            kind: EventKind::DetectionChecked,
            detail: format!(
                "expected signal: {} — present: {signal_present}",
                expected_signal(&technique.id)
            ),
        })?;

        results.push(DetectionResult {
            technique_id: technique.id.clone(),
            expected_signal: expected_signal(&technique.id),
            signal_present,
            referenced_event,
        });
    }

    Ok(results)
}
