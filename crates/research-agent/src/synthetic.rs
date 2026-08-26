use crate::technique::Technique;

/// Fixed marker content the synthetic proving technique's guest module
/// writes verbatim. Shared here so the execution engine (which writes it)
/// and any code checking for its presence (defender/verifier signal
/// checks) reference the same constant instead of duplicating a magic
/// string.
pub const MARKER_CONTENT: &str = "synthetic-proving-technique-executed";

/// The ATT&CK-shaped ID this technique uses. Deliberately not a real ATT&CK
/// ID (no "T" prefix followed by real MITRE numbering) — `SYNTH-` makes it
/// unmistakable in logs and in the audit store's technique queue.
pub const SYNTHETIC_TECHNIQUE_ID: &str = "SYNTH-0001";

/// The `Technique.source` value for every synthetic proving technique.
/// Callers that need to gate real-execution behavior on "is this the
/// synthetic technique, not real threat intel" (e.g.
/// `lab_agents::attacker`) should match on this constant rather than a bare
/// string literal.
pub const SYNTHETIC_SOURCE: &str = "synthetic-proving";

/// Builds the synthetic proving technique.
///
/// **This is NOT a real attack technique and must never be confused with
/// one.** It exists solely to prove that the attacker -> sandbox
/// execution-and-capture mechanism works end to end (capability gate ->
/// real wasmtime/WASI execution -> outcome capture -> audit log -> a real
/// `Detected`/`Missed` verdict) — see `DESIGN-execution-engine.md`,
/// Option C. Its declared operation is trivial, safe, and fully contained:
/// write [`MARKER_CONTENT`] to a fixed file inside the lab's declared
/// target directory.
///
/// `source: "synthetic-proving"` is deliberately distinct from
/// `"atomic-red-team"` (the only source string `ingest`/`fetch_category`
/// ever produce) so this can never be mistaken for ingested threat intel in
/// the audit log, and so it is trivially greppable/filterable everywhere
/// downstream. This function is a standalone entry point — nothing in the
/// real ingestion path calls it, and it never calls
/// `ScopeConfig::allows_source` itself, because CONTEXT.md section 4's
/// research-agent allowlist governs real threat-intel sources, not this.
///
/// `test_command` here is **descriptive metadata for audit-log
/// readability, not literal shell text to be executed** — unlike a real
/// `Technique`'s `test_command`, nothing ever passes this string to a
/// shell interpreter. The actual operation is defined by the execution
/// engine's guest module, not by parsing this field.
pub fn synthetic_proving_technique() -> Technique {
    Technique {
        id: SYNTHETIC_TECHNIQUE_ID.to_string(),
        guid: "synthetic-proving-marker-write".to_string(),
        name: "Synthetic Proving Technique — Marker File Write".to_string(),
        description: "NOT a real attack technique. Exists solely to prove the \
            attacker->sandbox execution-and-capture mechanism works end to end. \
            Writes a fixed marker string to a file inside the declared lab \
            target directory."
            .to_string(),
        source: SYNTHETIC_SOURCE.to_string(),
        test_command: format!("(synthetic, not literal shell text) write marker {MARKER_CONTENT:?}"),
        platform: "wasm".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_technique_is_clearly_labeled_and_distinct_from_real_sources() {
        let technique = synthetic_proving_technique();

        assert_eq!(technique.id, "SYNTH-0001");
        assert_eq!(technique.source, SYNTHETIC_SOURCE);
        assert_ne!(technique.source, "atomic-red-team");
        assert_eq!(technique.platform, "wasm");
        assert!(technique.description.contains("NOT a real attack technique"));
    }
}
