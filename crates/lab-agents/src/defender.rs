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
                e.subject_id == technique.id
                    && matches!(e.kind, EventKind::CapabilityGranted | EventKind::CapabilityDenied)
            })
            .cloned();

        let signal_present = referenced_event.is_some();
        store.log_event(&AuditEvent {
            timestamp: Utc::now(),
            actor: "lab-agents::defender".to_string(),
            subject_id: technique.id.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use host::ScopeConfig;
    use research_agent::Technique;

    fn fake_technique(id: &str, guid: &str) -> Technique {
        Technique {
            id: id.to_string(),
            guid: guid.to_string(),
            name: "Test Technique".to_string(),
            description: "unit-test fixture, not a real ingested technique".to_string(),
            source: "atomic-red-team".to_string(),
            test_command: "echo should-never-run".to_string(),
            platform: "windows".to_string(),
        }
    }

    /// Against the real (denied) audit log produced by Step 2's attacker
    /// run, the defender must report the signal present and reference the
    /// actual CapabilityDenied event — never a CapabilityGranted one, since
    /// nothing can be granted under the current scope.
    #[test]
    fn reports_present_and_references_the_real_capability_denied_event() {
        let scope = ScopeConfig::load("../../lab/scope.toml").expect("lab/scope.toml should parse");
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();
        store.put_technique("test-guid-1", &fake_technique("T1059", "test-guid-1")).unwrap();

        crate::attacker::attempt_all(&scope, &store).unwrap();
        let results = check_all(&store).unwrap();

        assert_eq!(results.len(), 1);
        assert!(results[0].signal_present);
        let referenced = results[0].referenced_event.as_ref().expect("signal_present implies a referenced event");
        assert_eq!(referenced.kind, EventKind::CapabilityDenied);
    }

    /// A technique that was queued but never attempted (no capability
    /// event exists for it at all) must report signal_present: false —
    /// proving the check isn't trivially always-true.
    #[test]
    fn reports_absent_when_no_capability_event_exists_for_the_technique() {
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();
        store.put_technique("never-attempted-guid", &fake_technique("T1078", "never-attempted-guid")).unwrap();

        // Note: attacker::attempt_all is deliberately never called here.
        let results = check_all(&store).unwrap();

        assert_eq!(results.len(), 1);
        assert!(!results[0].signal_present);
        assert!(results[0].referenced_event.is_none());
    }
}
