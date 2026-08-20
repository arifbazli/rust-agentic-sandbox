use chrono::{DateTime, Utc};

use crate::scope::ScopeConfig;

/// The result of evaluating one technique category against a `ScopeConfig`.
/// This is the entire capability-grant decision surface for the lab: if
/// it's `Denied`, no capability exists for the caller to use, structurally
/// — see CONTEXT.md sections 2 and 3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityDecision {
    Granted,
    Denied { reason: String },
}

/// Deterministic capability evaluation — no model call, no heuristic
/// judgment, just data checks against the declared scope. Order matters
/// for the reason reported, not for the outcome: an excluded-and-expired
/// category is still `Denied`, just with the first-matched reason.
pub fn evaluate(scope: &ScopeConfig, category: &str, now: DateTime<Utc>) -> CapabilityDecision {
    if !scope.is_temporally_valid(now) {
        return CapabilityDecision::Denied {
            reason: format!(
                "lab scope validity window does not cover {now} — the scope is expired, not yet active, or (per lab/scope.toml's header) still an unpopulated placeholder"
            ),
        };
    }
    if scope.exclusions.technique_categories.iter().any(|c| c == category) {
        return CapabilityDecision::Denied {
            reason: format!("category {category} is explicitly excluded in lab/scope.toml's [exclusions]"),
        };
    }
    if !scope.techniques.allowed_categories.iter().any(|c| c == category) {
        return CapabilityDecision::Denied {
            reason: format!("category {category} is not listed in lab/scope.toml's [techniques].allowed_categories"),
        };
    }
    CapabilityDecision::Granted
}
