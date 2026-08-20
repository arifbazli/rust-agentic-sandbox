use serde::Deserialize;

use crate::technique::Technique;

const REPO_RAW_BASE: &str = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics";

/// Mirrors only the fields of an `atomics/<ID>/<ID>.yaml` file this crate
/// actually uses. Everything else in the real file (dependencies,
/// input_arguments, elevation_required, etc.) is deliberately not modeled —
/// we read `executor.command` verbatim and pass it through unparsed, per
/// the "no rewriting, no reinterpreting" constraint.
#[derive(Debug, Deserialize)]
struct AtomicFile {
    attack_technique: String,
    #[serde(default)]
    atomic_tests: Vec<AtomicTest>,
}

#[derive(Debug, Deserialize)]
struct AtomicTest {
    name: String,
    #[serde(default)]
    auto_generated_guid: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    supported_platforms: Vec<String>,
    executor: Executor,
}

#[derive(Debug, Deserialize)]
struct Executor {
    #[serde(default)]
    command: Option<String>,
}

/// Outcome of attempting to fetch one declared category's atomics
/// definition. `not_found_upstream` distinguishes "this category has no
/// top-level Atomic Red Team file" (e.g. it was fully split into
/// sub-techniques not covered by the exact declared ID) from a genuine
/// fetch/parse error, so callers can report an honest negative result
/// instead of treating it as a failure.
#[derive(Debug, Default)]
pub struct FetchOutcome {
    pub category: String,
    pub techniques: Vec<Technique>,
    pub not_found_upstream: bool,
}

/// Fetches and parses `atomics/<category>/<category>.yaml` from the public
/// Atomic Red Team repository. `category` must be the exact ATT&CK ID as
/// declared in `lab/scope.toml` — no sub-technique expansion, no fallback
/// search. Every `atomic_test` with a runnable `executor.command` becomes
/// one `Technique`; tests with no command (manual-only steps) are skipped.
pub fn fetch_category(category: &str) -> anyhow::Result<FetchOutcome> {
    let url = format!("{REPO_RAW_BASE}/{category}/{category}.yaml");
    let response = ureq::get(&url).call();
    let text = match response {
        Ok(resp) => resp.into_string()?,
        Err(ureq::Error::Status(404, _)) => {
            return Ok(FetchOutcome {
                category: category.to_string(),
                not_found_upstream: true,
                ..Default::default()
            })
        }
        Err(e) => return Err(e.into()),
    };

    let parsed: AtomicFile = serde_yaml::from_str(&text)?;
    let techniques = parsed
        .atomic_tests
        .into_iter()
        .filter_map(|test| {
            let command = test.executor.command?;
            Some(Technique {
                id: parsed.attack_technique.clone(),
                guid: test.auto_generated_guid,
                name: test.name,
                description: test.description.trim().to_string(),
                source: "atomic-red-team".to_string(),
                test_command: command,
                platform: test.supported_platforms.into_iter().next().unwrap_or_default(),
            })
        })
        .collect();

    Ok(FetchOutcome {
        category: category.to_string(),
        techniques,
        not_found_upstream: false,
    })
}
