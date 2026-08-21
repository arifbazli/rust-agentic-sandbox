use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use audit::{AuditEvent, AuditStore, EventKind};
use chrono::Utc;
use host::CapabilityDecision;

use crate::sandbox::{dry_run_write, SandboxOutcome};
use crate::static_analysis::static_analyze;
use crate::Proposal;

static SUBJECT_SEQ: AtomicU64 = AtomicU64::new(0);

fn generate_subject_id() -> String {
    format!(
        "proposal-{:020}-{}",
        Utc::now().timestamp_nanos_opt().unwrap_or_default(),
        SUBJECT_SEQ.fetch_add(1, Ordering::SeqCst)
    )
}

/// Reviews one proposal end-to-end and logs every stage's evidence to the
/// shared audit log, tagged by a freshly generated `subject_id` (returned
/// to the caller). This function produces and logs evidence ONLY — it
/// never computes a final verdict itself. `host::gate_verdict::evaluate`
/// reads this same log, by `subject_id`, to compute Allow/Block — mirroring
/// how the lab loop separates `lab-agents` (evidence) from
/// `verifier::verify()` (verdict). See CONTEXT.md section 1.
///
/// Stage 1 (always runs): `static_analyze`. For a `ShellCommand`, this is
/// a deny-pattern check, logged as `StaticAnalysisClean`/`StaticAnalysisFlagged`.
/// For a `FileWrite`, `static_analyze` delegates entirely to
/// `host::evaluate_file_write` (a genuine capability decision, not a
/// deny-pattern check), so it's logged as `CapabilityGranted`/`CapabilityDenied`
/// instead — the more accurate label for what the check actually is.
///
/// Stage 2 (`FileWrite` only, and only if stage 1 granted): the real WASI
/// sandbox dry-run (`dry_run_write`), logged as
/// `SandboxDryRunSucceeded`/`SandboxDryRunDenied`. If stage 1 denies,
/// this stage is skipped entirely — `review` never even calls
/// `dry_run_write` for a denied proposal.
pub fn review(proposal: &Proposal, workspace_root: &Path, store: &AuditStore) -> anyhow::Result<String> {
    let subject_id = generate_subject_id();

    let static_decision = static_analyze(proposal, workspace_root);
    let (kind, detail) = match (proposal, &static_decision) {
        (Proposal::ShellCommand { .. }, CapabilityDecision::Granted) => {
            (EventKind::StaticAnalysisClean, "static analysis found no matching deny pattern".to_string())
        }
        (Proposal::ShellCommand { .. }, CapabilityDecision::Denied { reason }) => {
            (EventKind::StaticAnalysisFlagged, reason.clone())
        }
        (Proposal::FileWrite { .. }, CapabilityDecision::Granted) => {
            (EventKind::CapabilityGranted, "proposed path resolves inside the workspace root".to_string())
        }
        (Proposal::FileWrite { .. }, CapabilityDecision::Denied { reason }) => {
            (EventKind::CapabilityDenied, reason.clone())
        }
    };
    store.log_event(&AuditEvent {
        timestamp: Utc::now(),
        actor: "gate-pipeline::review".to_string(),
        subject_id: subject_id.clone(),
        kind,
        detail,
    })?;

    if matches!(static_decision, CapabilityDecision::Denied { .. }) {
        return Ok(subject_id);
    }

    // TODO: consolidate -- evaluate_file_write currently runs twice for a
    // granted FileWrite (once here via static_analyze, once inside
    // dry_run_write). Deterministic and cheap, accepted as a known
    // redundancy rather than touching Step 3's approved sandbox.rs.
    if let Proposal::FileWrite { path, content } = proposal {
        let outcome = dry_run_write(workspace_root, path, content)?;
        let (kind, detail) = match outcome {
            SandboxOutcome::WriteSucceeded => (
                EventKind::SandboxDryRunSucceeded,
                "dry-run write succeeded inside the scratch capability boundary".to_string(),
            ),
            SandboxOutcome::WriteDenied { detail } => (EventKind::SandboxDryRunDenied, detail),
        };
        store.log_event(&AuditEvent {
            timestamp: Utc::now(),
            actor: "gate-pipeline::review".to_string(),
            subject_id: subject_id.clone(),
            kind,
            detail,
        })?;
    }

    Ok(subject_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shell(command: &str) -> Proposal {
        Proposal::ShellCommand { command: command.to_string() }
    }

    #[test]
    fn granted_shell_command_logs_clean_static_analysis_only() {
        let workspace = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();

        let subject_id = review(&shell("echo hello"), workspace.path(), &store).unwrap();

        let events = store.events().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].subject_id, subject_id);
        assert_eq!(events[0].kind, EventKind::StaticAnalysisClean);

        let decision = host::gate_verdict::evaluate(&store, &subject_id).unwrap();
        assert_eq!(decision, CapabilityDecision::Granted);
    }

    #[test]
    fn denied_shell_command_never_reaches_sandbox_stage() {
        let workspace = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();

        let subject_id = review(&shell("rm -rf /tmp/scratch"), workspace.path(), &store).unwrap();

        let events = store.events().unwrap();
        assert_eq!(events.len(), 1, "a denied proposal must produce exactly one logged event");
        assert_eq!(events[0].kind, EventKind::StaticAnalysisFlagged);
        assert!(
            !events.iter().any(|e| matches!(e.kind, EventKind::SandboxDryRunSucceeded | EventKind::SandboxDryRunDenied)),
            "the sandbox stage must be skipped entirely for a denied proposal, not attempted and failed"
        );

        let decision = host::gate_verdict::evaluate(&store, &subject_id).unwrap();
        assert!(matches!(decision, CapabilityDecision::Denied { .. }));
    }

    #[test]
    fn granted_file_write_inside_workspace_logs_both_stages_and_allows() {
        let workspace = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();
        let proposal = Proposal::FileWrite { path: workspace.path().join("file.txt"), content: "hello".to_string() };

        let subject_id = review(&proposal, workspace.path(), &store).unwrap();

        let events = store.events().unwrap();
        assert_eq!(events.len(), 2, "a granted FileWrite must log both the capability check and the sandbox dry-run");
        assert!(events.iter().any(|e| e.kind == EventKind::CapabilityGranted));
        assert!(events.iter().any(|e| e.kind == EventKind::SandboxDryRunSucceeded));

        let decision = host::gate_verdict::evaluate(&store, &subject_id).unwrap();
        assert_eq!(decision, CapabilityDecision::Granted);
    }

    #[test]
    fn denied_file_write_outside_workspace_never_reaches_sandbox_stage() {
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(dir.path().join("store.redb")).unwrap();
        let proposal = Proposal::FileWrite { path: outside.path().join("file.txt"), content: "should never run".to_string() };

        let subject_id = review(&proposal, workspace.path(), &store).unwrap();

        let events = store.events().unwrap();
        assert_eq!(events.len(), 1, "a denied FileWrite must produce exactly one logged event");
        assert_eq!(events[0].kind, EventKind::CapabilityDenied);
        assert!(
            !events.iter().any(|e| matches!(e.kind, EventKind::SandboxDryRunSucceeded | EventKind::SandboxDryRunDenied)),
            "the sandbox stage must be skipped entirely for a denied FileWrite, not attempted and failed"
        );

        let decision = host::gate_verdict::evaluate(&store, &subject_id).unwrap();
        assert!(matches!(decision, CapabilityDecision::Denied { .. }));
    }
}
