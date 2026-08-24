use std::path::Path;

use chrono::{DateTime, Utc};

use crate::gate_policy;
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
///
/// `target_path` is the real file/command target this attempt would touch,
/// if the caller has one — `None` skips the path check entirely (category
/// and validity are still enforced), matching every call site before this
/// path check existed. When `Some`, the resolved path (symlinks and `..`
/// included, via the same `gate_policy::evaluate_file_write` primitive
/// `gate-pipeline` uses for the harness gate) must land inside at least one
/// of `scope`'s declared `[[environment.targets]]` entries whose `kind` is
/// `"local-directory"` — resolved relative to `workspace_root`. No
/// declared local-directory target at all is itself a denial: there's
/// nothing to check the path against, so it can't be granted.
pub fn evaluate(
    scope: &ScopeConfig,
    category: &str,
    workspace_root: &Path,
    target_path: Option<&Path>,
    now: DateTime<Utc>,
) -> CapabilityDecision {
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

    let Some(path) = target_path else {
        return CapabilityDecision::Granted;
    };

    let mut found_local_target = false;
    for target in scope.environment.targets.iter().filter(|t| t.kind == "local-directory") {
        found_local_target = true;
        let target_dir = workspace_root.join(&target.identifier);
        if matches!(gate_policy::evaluate_file_write(&target_dir, path), CapabilityDecision::Granted) {
            return CapabilityDecision::Granted;
        }
    }

    if !found_local_target {
        return CapabilityDecision::Denied {
            reason: format!(
                "path {} cannot be granted: lab/scope.toml declares no local-directory target to check it against",
                path.display()
            ),
        };
    }

    CapabilityDecision::Denied {
        reason: format!(
            "path outside declared lab scope: {} does not resolve inside any declared local-directory target in lab/scope.toml",
            path.display()
        ),
    }
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
        let decision = evaluate(&scope, "T1059", Path::new("../.."), None, Utc::now());
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
        let decision = evaluate(&scope, "T1059", Path::new("."), None, long_after);
        assert!(matches!(decision, CapabilityDecision::Denied { .. }));
    }

    #[test]
    fn excluded_category_is_denied_even_within_a_valid_window() {
        let scope = parse(VALID_WINDOW_TOML);
        let now = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let decision = evaluate(&scope, "T1499", Path::new("."), None, now);
        match decision {
            CapabilityDecision::Denied { reason } => assert!(reason.contains("excluded")),
            CapabilityDecision::Granted => panic!("T1499 is explicitly excluded and must never be granted"),
        }
    }

    #[test]
    fn category_not_in_allowlist_is_denied() {
        let scope = parse(VALID_WINDOW_TOML);
        let now = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let decision = evaluate(&scope, "T9999", Path::new("."), None, now);
        assert!(matches!(decision, CapabilityDecision::Denied { .. }));
    }

    #[test]
    fn allowed_non_excluded_category_within_a_valid_window_is_granted_when_no_path_is_checked() {
        let scope = parse(VALID_WINDOW_TOML);
        let now = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let decision = evaluate(&scope, "T1059", Path::new("."), None, now);
        assert_eq!(decision, CapabilityDecision::Granted);
    }

    const SCOPE_WITH_LOCAL_TARGET_TOML: &str = r#"
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

    #[test]
    fn path_inside_declared_local_target_is_granted() {
        let workspace = tempfile::tempdir().unwrap();
        std::fs::create_dir(workspace.path().join("target")).unwrap();
        let scope = parse(SCOPE_WITH_LOCAL_TARGET_TOML);
        let now = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let inside = workspace.path().join("target").join("file.txt");

        let decision = evaluate(&scope, "T1059", workspace.path(), Some(&inside), now);

        assert_eq!(decision, CapabilityDecision::Granted);
    }

    #[test]
    fn path_outside_declared_local_target_is_denied_with_a_distinct_reason() {
        let workspace = tempfile::tempdir().unwrap();
        std::fs::create_dir(workspace.path().join("target")).unwrap();
        let scope = parse(SCOPE_WITH_LOCAL_TARGET_TOML);
        let now = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let outside = workspace.path().join("elsewhere.txt");

        let decision = evaluate(&scope, "T1059", workspace.path(), Some(&outside), now);

        match decision {
            CapabilityDecision::Denied { reason } => assert!(
                reason.contains("path outside declared lab scope"),
                "expected a path-specific denial reason, distinguishable from a category or validity denial, got: {reason}"
            ),
            CapabilityDecision::Granted => panic!("a path outside every declared local-directory target must never be granted"),
        }
    }

    #[test]
    fn path_check_with_no_declared_local_target_is_denied() {
        let scope = parse(VALID_WINDOW_TOML); // no [[environment.targets]] at all
        let now = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let any_path = workspace.path().join("file.txt");

        let decision = evaluate(&scope, "T1059", workspace.path(), Some(&any_path), now);

        match decision {
            CapabilityDecision::Denied { reason } => {
                assert!(reason.contains("no local-directory target"), "got: {reason}")
            }
            CapabilityDecision::Granted => panic!("a path check with no declared target to check against must never be granted"),
        }
    }
}
