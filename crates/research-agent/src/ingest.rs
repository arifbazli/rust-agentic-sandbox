use audit::AuditStore;
use host::ScopeConfig;

use crate::atomic_red_team::fetch_category;
use crate::technique::Technique;

/// Full result of one ingestion run, kept deliberately explicit about
/// what was skipped and why — see CONTEXT.md section 6 ("Honest negative
/// results"): an excluded or not-found category is not an error, it's a
/// fact to report.
#[derive(Debug, Default)]
pub struct IngestReport {
    pub ingested: Vec<Technique>,
    /// Allowed categories that are also present in `[exclusions]` —
    /// skipped without ever being fetched.
    pub excluded_by_scope: Vec<String>,
    /// Allowed, non-excluded categories with no top-level Atomic Red Team
    /// definition upstream (e.g. fully split into sub-techniques not
    /// covered by the exact declared ID).
    pub not_found_upstream: Vec<String>,
}

/// Ingests every category declared in `lab/scope.toml`'s
/// `[techniques].allowed_categories`, minus anything in `[exclusions]`,
/// from Atomic Red Team only. Persists each resulting `Technique` to the
/// audit store's technique queue, keyed by its atomic-test guid.
pub fn ingest(scope: &ScopeConfig, store: &AuditStore) -> anyhow::Result<IngestReport> {
    anyhow::ensure!(
        scope.allows_source("atomic-red-team"),
        "atomic-red-team is not in lab/scope.toml's [techniques].allowed_sources — refusing to ingest"
    );

    let mut report = IngestReport::default();

    for category in &scope.techniques.allowed_categories {
        if scope.exclusions.technique_categories.contains(category) {
            report.excluded_by_scope.push(category.clone());
            continue;
        }

        let outcome = fetch_category(category)?;
        if outcome.not_found_upstream || outcome.techniques.is_empty() {
            report.not_found_upstream.push(category.clone());
            continue;
        }

        for technique in outcome.techniques {
            store.put_technique(&technique.guid, &technique)?;
            report.ingested.push(technique);
        }
    }

    Ok(report)
}
