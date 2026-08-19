//! Threat-intel ingestion for the attack/defend lab's technique queue.
//!
//! Pulls structured, vetted technique data from allowlisted sources only
//! (MITRE ATT&CK, CVE/NVD, Atomic Red Team, Sigma rules) and produces a
//! structured technique reference. Never generates novel exploit code or
//! freeform "how would I attack X" reasoning.
