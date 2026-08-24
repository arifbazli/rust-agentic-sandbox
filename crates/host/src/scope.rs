use std::path::Path;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Deserialize;

/// Mirrors `lab/scope.toml`'s shape exactly. See CONTEXT.md section 3
/// ("Lab scope lock") — this is the structural boundary lab capability
/// grants are derived from, parsed as-is with no defaults invented beyond
/// what the file itself declares optional.
#[derive(Debug, Clone, Deserialize)]
pub struct ScopeConfig {
    pub environment: Environment,
    pub techniques: Techniques,
    #[serde(default)]
    pub exclusions: Exclusions,
    #[serde(default)]
    pub validity: Option<Validity>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Environment {
    pub name: String,
    /// `None` when the environment has no cloud account at all (e.g. a
    /// local/container-only lab target) — genuinely absent, not defaulted
    /// to a fake or empty account. `host::evaluate` has never read this
    /// field for any capability decision; it exists for documentation.
    #[serde(default)]
    pub account: Option<Account>,
    /// Same absence semantics as `account` — `None` when there's no
    /// network boundary to declare (e.g. no VPC for a local target).
    #[serde(default)]
    pub network: Option<Network>,
    #[serde(default)]
    pub targets: Vec<Target>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Account {
    pub provider: String,
    pub account_id: String,
    pub region: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Network {
    pub vpc_id: String,
    #[serde(default)]
    pub allowed_cidrs: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Target {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub identifier: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Techniques {
    #[serde(default)]
    pub allowed_categories: Vec<String>,
    #[serde(default)]
    pub allowed_sources: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Exclusions {
    #[serde(default)]
    pub technique_categories: Vec<String>,
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Validity {
    pub starts_at: DateTime<Utc>,
    pub ends_at: DateTime<Utc>,
}

impl ScopeConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&text)?)
    }

    /// A category is in scope only if it's both declared allowed AND not
    /// explicitly excluded. Exclusions always win — see `lab/scope.toml`'s
    /// own comment: "Exclusions always take precedence over allowances."
    pub fn allows_category(&self, category: &str) -> bool {
        self.techniques.allowed_categories.iter().any(|c| c == category)
            && !self.exclusions.technique_categories.iter().any(|c| c == category)
    }

    pub fn allows_source(&self, source: &str) -> bool {
        self.techniques.allowed_sources.iter().any(|s| s == source)
    }

    /// `None` validity means open-ended (per the file's own comment: "Leave
    /// unset for an open-ended scope"). A `Some` window must contain `now`.
    pub fn is_temporally_valid(&self, now: DateTime<Utc>) -> bool {
        match &self.validity {
            None => true,
            Some(v) => now >= v.starts_at && now <= v.ends_at,
        }
    }
}
