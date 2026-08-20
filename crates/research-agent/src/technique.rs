use serde::{Deserialize, Serialize};

/// One ingested, ready-to-queue Atomic Red Team atomic test.
///
/// Deviation from the original spec worth flagging: a technique's YAML
/// file often contains multiple `atomic_tests`, each with its own command
/// and platform — so the queue key is `guid` (the atomic test's
/// `auto_generated_guid`), not `id` (the shared ATT&CK technique ID).
/// Keying by `id` alone would silently overwrite all but the last test per
/// technique.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Technique {
    /// ATT&CK technique ID, e.g. "T1059".
    pub id: String,
    /// The atomic test's own stable identifier — the redb queue key.
    pub guid: String,
    pub name: String,
    pub description: String,
    /// Fixed: "atomic-red-team".
    pub source: String,
    /// The exact, unmodified `executor.command` text from the YAML —
    /// never rewritten, "improved", or reinterpreted, including any
    /// unresolved `#{input_argument}` placeholders.
    pub test_command: String,
    /// First entry of `supported_platforms` (e.g. "windows").
    pub platform: String,
}
