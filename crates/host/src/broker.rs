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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    const VALID_WINDOW_TOML: &str = r#"
        [environment]
        name = "test-lab"
        [techniques]
        allowed_categories = ["T1059"]
        allowed_sources = ["atomic-red-team"]
        [exclusions]
        technique_categories = ["T1499"]
        [validity]
        starts_at = "2020-01-01T00:00:00Z"
        ends_at = "2099-01-01T00:00:00Z"
    "#;

    fn parse(toml_str: &str) -> ScopeConfig {
        toml::from_str(toml_str).expect("test scope toml should parse")
    }

    #[test]
    fn real_repo_scope_is_expired_and_denies_everything() {
        let scope = ScopeConfig::load("../../lab/scope.toml")
            .expect("lab/scope.toml should exist and parse from the host crate's directory");
        let decision = evaluate(&scope, "T1059", Utc::now());
        assert!(
            matches!(decision, CapabilityDecision::Denied { .. }),
            "the real lab/scope.toml has an expired validity window and must deny every category"
        );
    }

    #[test]
    fn expired_validity_window_denies_before_any_other_check() {
        let scope = parse(VALID_WINDOW_TOML);
        // Force `now` outside the window even though the category is allowed and not excluded.
        let long_after = Utc.with_ymd_and_hms(2100, 1, 1, 0, 0, 0).unwrap();
        let decision = evaluate(&scope, "T1059", long_after);
        assert!(matches!(decision, CapabilityDecision::Denied { .. }));
    }

    #[test]
    fn excluded_category_is_denied_even_within_a_valid_window() {
        let scope = parse(VALID_WINDOW_TOML);
        let now = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let decision = evaluate(&scope, "T1499", now);
        match decision {
            CapabilityDecision::Denied { reason } => assert!(reason.contains("excluded")),
            CapabilityDecision::Granted => panic!("T1499 is explicitly excluded and must never be granted"),
        }
    }

    #[test]
    fn category_not_in_allowlist_is_denied() {
        let scope = parse(VALID_WINDOW_TOML);
        let now = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let decision = evaluate(&scope, "T9999", now);
        assert!(matches!(decision, CapabilityDecision::Denied { .. }));
    }

    #[test]
    fn allowed_non_excluded_category_within_a_valid_window_is_granted() {
        let scope = parse(VALID_WINDOW_TOML);
        let now = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let decision = evaluate(&scope, "T1059", now);
        assert_eq!(decision, CapabilityDecision::Granted);
    }
}
