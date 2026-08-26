//! Threat-intel ingestion for the attack/defend lab's technique queue.
//!
//! Pulls structured, vetted technique data from allowlisted sources only
//! (MITRE ATT&CK, CVE/NVD, Atomic Red Team, Sigma rules) and produces a
//! structured technique reference. Never generates novel exploit code or
//! freeform "how would I attack X" reasoning.

mod atomic_red_team;
mod ingest;
mod synthetic;
mod technique;

pub use atomic_red_team::{fetch_category, FetchOutcome};
pub use ingest::{ingest, IngestReport};
pub use synthetic::{synthetic_proving_technique, MARKER_CONTENT, SYNTHETIC_SOURCE, SYNTHETIC_TECHNIQUE_ID};
pub use technique::Technique;
