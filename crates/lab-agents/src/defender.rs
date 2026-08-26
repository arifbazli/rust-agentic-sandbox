use std::path::Path;

use audit::{AuditEvent, AuditStore, EventKind};
use chrono::Utc;
use host::ScopeConfig;

/// Fixed, deterministic table of what audit-log signal we'd expect for a
/// given ATT&CK category's execution attempt. This is plain Rust data, not
/// agent reasoning — see CONTEXT.md section 1 ("Verdict authority").
fn expected_signal(category: &str) -> &'static str {
    match category {
        "T1059" => {
            "a CapabilityGranted, CapabilityDenied, or ExecutionBlocked event for a Command and Scripting Interpreter attempt"
        }
        "T1078" => "a CapabilityGranted, CapabilityDenied, or ExecutionBlocked event for a Valid Accounts attempt",
        research_agent::SYNTHETIC_TECHNIQUE_ID => {
            "a CapabilityGranted, CapabilityDenied, ExecutionBlocked, ExecutionSucceeded, or ExecutionFailed event for the synthetic proving technique's attempt"
        }
        _ => "a CapabilityGranted, CapabilityDenied, ExecutionBlocked, ExecutionSucceeded, or ExecutionFailed event for this technique's attempt",
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
/// decision signal was logged.
///
/// The matcher recognizes `ExecutionBlocked` alongside
/// `CapabilityGranted`/`CapabilityDenied`, found while preparing to
/// populate a real `lab/scope.toml` for the first time: once a technique
/// is genuinely granted but still blocked at the execution stage (no
/// wasmtime/WASI-P2 engine exists yet — see attacker.rs's doc comment),
/// the old matcher would have incorrectly reported `signal_present: false`
/// for a technique that genuinely was attempted. `signal_present` means
/// "the attempt was observably logged" — granted-but-blocked, denied
/// outright, whichever — not "a real intrusion attempt was detected".
///
/// `ExecutionSucceeded`/`ExecutionFailed` are recognized the same way,
/// added once a real execution path existed (the synthetic proving
/// technique — see `research_agent::synthetic`): either one means the
/// attempt was genuinely, observably logged, regardless of whether the
/// sandboxed operation itself succeeded or failed.
///
/// For most techniques, `signal_present` is still a pure event-presence
/// check — any technique `attacker::attempt_all` actually processes will
/// always log exactly one recognized event, so `signal_present` is only
/// ever `false` for a technique that was queued but never attempted at
/// all. **The synthetic proving technique is the one exception, and is
/// genuinely content-aware**: `signal_present` is true only if BOTH (a) a
/// recognized event was logged for it, AND (b) the real marker file this
/// crate's sandbox actually writes still exists on disk, at the expected
/// path, with exactly the expected content — checked fresh from disk on
/// every call, not cached or inferred from the audit log. This makes
/// `Missed` genuinely reachable: an `ExecutionSucceeded` event with the
/// marker file deleted or tampered with afterward correctly reports
/// `signal_present: false`, since the log claims something happened but
/// the real, checkable world state says otherwise. Every other
/// technique — everything from Atomic Red Team, including T1059 — has no
/// defined "expected content" to check, so it keeps the original,
/// unchanged event-presence-only behavior; content-awareness is never
/// forced onto a technique that doesn't declare one.
pub fn check_all(scope: &ScopeConfig, workspace_root: &Path, store: &AuditStore) -> anyhow::Result<Vec<DetectionResult>> {
    let events = store.events()?;
    let queued: Vec<(String, research_agent::Technique)> = store.techniques()?;

    let target_dir =
        scope.environment.targets.iter().find(|t| t.kind == "local-directory").map(|t| workspace_root.join(&t.identifier));

    let mut results = Vec::with_capacity(queued.len());
    for (_, technique) in queued {
        let referenced_event = events
            .iter()
            .rev()
            .find(|e| {
                e.subject_id == technique.id
                    && matches!(
                        e.kind,
                        EventKind::CapabilityGranted
                            | EventKind::CapabilityDenied
                            | EventKind::ExecutionBlocked
                            | EventKind::ExecutionSucceeded
                            | EventKind::ExecutionFailed
                    )
            })
            .cloned();

        let event_logged = referenced_event.is_some();
        let signal_present = if technique.source == research_agent::SYNTHETIC_SOURCE {
            event_logged && marker_file_matches_expected_content(target_dir.as_deref())
        } else {
            event_logged
        };

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

/// Real, on-disk post-condition check for the synthetic proving
/// technique's declared operation: does the expected marker file actually
/// exist at the expected path inside the lab's declared target directory,
/// with exactly the expected content? `None` (no declared local-directory
/// target) is treated as "no" — there is nothing to check against.
fn marker_file_matches_expected_content(target_dir: Option<&Path>) -> bool {
    let Some(target_dir) = target_dir else { return false };
    let marker_path = target_dir.join(crate::sandbox::MARKER_FILE_NAME);
    std::fs::read_to_string(marker_path).map(|content| content == research_agent::MARKER_CONTENT).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
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

    /// Against the real (now-populated) `lab/scope.toml`, T1059 is granted
    /// but still has no execution engine to actually run it — the defender
    /// must still report the signal present, referencing the real
    /// `ExecutionBlocked` event, proving `check_all`'s matcher recognizes a
    /// granted-but-blocked attempt as a genuine signal, not just an
    /// outright denial. Before Step 2a/2b's path enforcement and populated
    /// scope, this technique was denied outright instead; this test's
    /// name and assertion changed to match that real, verified shift, not
    /// a guess about what would happen.
    #[test]
    fn reports_present_and_references_the_real_execution_blocked_event() {
        let scope = ScopeConfig::load("../../lab/scope.toml").expect("lab/scope.toml should parse");
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();
        store.put_technique("test-guid-1", &fake_technique("T1059", "test-guid-1")).unwrap();

        crate::attacker::attempt_all(&scope, std::path::Path::new("../.."), &store).unwrap();
        let results = check_all(&scope, std::path::Path::new("../.."), &store).unwrap();

        assert_eq!(results.len(), 1);
        assert!(results[0].signal_present);
        let referenced = results[0].referenced_event.as_ref().expect("signal_present implies a referenced event");
        assert_eq!(referenced.kind, EventKind::ExecutionBlocked);
    }

    /// A technique that was queued but never attempted (no capability
    /// event exists for it at all) must report signal_present: false —
    /// proving the check isn't trivially always-true.
    #[test]
    fn reports_absent_when_no_capability_event_exists_for_the_technique() {
        let scope_toml = r#"
            [environment]
            name = "test-lab"
            [techniques]
            allowed_categories = ["T1078"]
            allowed_sources = ["atomic-red-team"]
        "#;
        let scope: ScopeConfig = toml::from_str(scope_toml).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();
        store.put_technique("never-attempted-guid", &fake_technique("T1078", "never-attempted-guid")).unwrap();

        // Note: attacker::attempt_all is deliberately never called here.
        let results = check_all(&scope, workspace.path(), &store).unwrap();

        assert_eq!(results.len(), 1);
        assert!(!results[0].signal_present);
        assert!(results[0].referenced_event.is_none());
    }

    fn scope_with_synthetic_target_toml() -> &'static str {
        r#"
            [environment]
            name = "test-lab"
            [[environment.targets]]
            id = "t1"
            type = "local-directory"
            identifier = "target"
            [techniques]
            allowed_categories = ["SYNTH-0001"]
            allowed_sources = ["synthetic-proving"]
        "#
    }

    /// Detected precursor, fully real: the synthetic technique actually
    /// executes (real wasmtime sandbox, real marker write), and the
    /// content-aware check finds the real marker file on disk with the
    /// exact expected content — `signal_present` must be true.
    #[test]
    fn synthetic_technique_with_marker_genuinely_on_disk_reports_signal_present() {
        let scope: ScopeConfig = toml::from_str(scope_with_synthetic_target_toml()).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        std::fs::create_dir(workspace.path().join("target")).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();

        let technique = research_agent::synthetic_proving_technique();
        store.put_technique(&technique.guid, &technique).unwrap();
        crate::attacker::attempt_all(&scope, workspace.path(), &store).unwrap();

        let results = check_all(&scope, workspace.path(), &store).unwrap();

        assert_eq!(results.len(), 1);
        assert!(results[0].signal_present, "the marker genuinely exists on disk, signal must be present");
        assert_eq!(results[0].referenced_event.as_ref().unwrap().kind, EventKind::ExecutionSucceeded);
    }

    /// Missed made real: the synthetic technique actually executes (real
    /// `ExecutionSucceeded` logged, real marker written), but the marker
    /// file is then genuinely deleted from disk before the defender ever
    /// checks — proving `signal_present` reflects real, checkable world
    /// state, not just "was an event logged". Zero fabricated events.
    #[test]
    fn synthetic_technique_with_marker_removed_after_execution_reports_signal_absent() {
        let scope: ScopeConfig = toml::from_str(scope_with_synthetic_target_toml()).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let target_dir = workspace.path().join("target");
        std::fs::create_dir(&target_dir).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();

        let technique = research_agent::synthetic_proving_technique();
        store.put_technique(&technique.guid, &technique).unwrap();
        crate::attacker::attempt_all(&scope, workspace.path(), &store).unwrap();

        // The marker genuinely exists on disk at this point -- remove it
        // for real before the defender checks, simulating tampering or
        // cleanup between the real attack and the real defense check.
        std::fs::remove_file(target_dir.join(crate::sandbox::MARKER_FILE_NAME)).unwrap();

        let results = check_all(&scope, workspace.path(), &store).unwrap();

        assert_eq!(results.len(), 1);
        assert!(!results[0].signal_present, "the marker is genuinely gone, signal must be absent despite the logged ExecutionSucceeded event");
        assert_eq!(
            results[0].referenced_event.as_ref().unwrap().kind,
            EventKind::ExecutionSucceeded,
            "an event was still logged -- the gap is real-world content, not the audit log"
        );
    }

    /// Regression: content-awareness must never apply to a non-synthetic
    /// technique. T1059 (and anything else without a defined "expected
    /// content" check) keeps the original event-presence-only behavior,
    /// completely unaffected by this addition -- even with a real target
    /// directory present and no marker file in it at all.
    #[test]
    fn non_synthetic_technique_is_unaffected_by_content_awareness() {
        let scope_toml = r#"
            [environment]
            name = "test-lab"
            [[environment.targets]]
            id = "t1"
            type = "local-directory"
            identifier = "target"
            [techniques]
            allowed_categories = ["T1059"]
            allowed_sources = ["atomic-red-team"]
        "#;
        let scope: ScopeConfig = toml::from_str(scope_toml).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        std::fs::create_dir(workspace.path().join("target")).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();
        store.put_technique("test-guid-regression", &fake_technique("T1059", "test-guid-regression")).unwrap();

        crate::attacker::attempt_all(&scope, workspace.path(), &store).unwrap();
        let results = check_all(&scope, workspace.path(), &store).unwrap();

        assert_eq!(results.len(), 1);
        assert!(
            results[0].signal_present,
            "T1059's ExecutionBlocked event must still count as present, with no marker file involved at all"
        );
        assert_eq!(results[0].referenced_event.as_ref().unwrap().kind, EventKind::ExecutionBlocked);
    }
}
