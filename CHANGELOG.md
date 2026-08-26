# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Entries are grouped by date rather than version, since this project has not
yet cut a release.

## [Unreleased]

### 2026-08-26

- **Added** `edit` gating for `adapter-claude-code`: reconstructs the
  full resulting file content by reading the target file and applying
  Claude Code's confirmed `old_string`/`new_string`/`replace_all`
  replacement, mirroring Claude Code's own uniqueness contract exactly
  — errors rather than guessing if `old_string` isn't unique and
  `replace_all` isn't set (#19).
- **Added** `edit` gating for `adapter-pi`: reconstructs full content
  from Pi's confirmed `path` + `edits: [{oldText, newText}]` schema
  (read straight from `src/core/tools/edit.ts`) — a genuinely different
  shape from Claude Code's, not assumed to match it. Validates
  uniqueness and non-overlap against the original file before applying
  every replacement in one pass (#19).
- Re-verified Copilot CLI's `edit` schema against its current docs —
  still undocumented, and unlike Pi there's no source repo to check
  instead since Copilot CLI is closed-source; stays an explicit,
  disclosed passthrough gap, not carried over unchecked (#19).
- Shortened README's Status section: one capability sentence, one
  known-gaps sentence, links to both `CONTEXT.md` and `CHANGELOG.md`
  (#18).

### 2026-08-24

- **Added** real path-containment enforcement in `host::evaluate`: a
  technique attempt with a target path must resolve (canonicalized,
  symlink-safe) inside a declared `[[environment.targets]]`
  local-directory entry, or is denied with a distinct reason.
- **Added** the first real (non-placeholder) `lab/scope.toml`: a
  Codespace-contained lab with no cloud account or credentials,
  declaring `lab/target/` as the sole real target and T1059 as the only
  allowed technique; and `lab/target/` itself, gitignored except for its
  explanatory `README.md` (#16).
- **Changed** `ScopeConfig`'s `account`/`network` fields to `Option` —
  genuinely absent for a scope with no cloud account, instead of
  requiring fake placeholder values (#16).
- **Fixed** `lab-agents::defender::check_all` to recognize
  `ExecutionBlocked` as a valid detection signal alongside
  `CapabilityGranted`/`CapabilityDenied` — previously, a technique
  granted but blocked at the execution stage would have been silently
  misreported as never attempted at all (#16).
- **Known limitation**: no wasmtime/WASI-P2 command-execution sandbox
  exists yet for `lab-agents::attacker` — a granted, path-clean
  technique still doesn't actually run. `verifier::verify` can currently
  only produce `Blocked` verdicts; `Detected`/`Missed` remain
  unreachable until this exists (#16).
- `adapter-copilot-cli`: real `preToolUse` hook, verified against
  Copilot CLI's live docs — flat JSON output schema, fail-closed-by-
  default exit codes (the opposite of Claude Code's model); `create`
  (file write) left ungated, no documented `toolArgs` schema exists for
  it (#14).
- `adapter-pi`: real Rust/TS bridge — Pi's extensions run in-process as
  TypeScript, not a stdin/stdout hook, so this is a persistent local
  `tiny_http` server paired with a reference-only TS extension; gates
  `bash` and `write` (the first adapter to reach `gate-pipeline`'s
  sandbox stage for a real file write) (#14).
- README: all three adapters now real, 75/75 tests, states the
  both-halves-real-end-to-end milestone plainly (#15).

### 2026-08-21

- Harness-gate, four steps in one PR: `host::gate_policy::evaluate_file_write`
  (capability check for proposed file writes); `gate-pipeline` static
  analysis (`Proposal` types + a fixed deny-pattern table for destructive
  shell commands); a real WASI sandbox dry-run (wasmtime/wasmtime-wasi,
  default-deny, scratch-dir preopen); `gate-pipeline::review()` +
  `host::gate_verdict::evaluate()` wiring over the shared audit log.
  `AuditEvent.technique_id` renamed to `subject_id` since the field is now
  shared between the lab loop and the harness gate (#10).
- README rewritten post-harness-gate; corrected the architecture diagram
  to show `host::gate_verdict` and `verifier` as independent parallel
  readers of one shared audit log, not a chain (#11).
- `adapter-claude-code`: real `PreToolUse` hook wired to `gate-pipeline`,
  fail-closed, verified against Claude Code's live hook docs — the first
  adapter to actually call `gate-pipeline` (#12).
- README: `adapter-claude-code` moves from stub to real, 56/56 tests (#13).

### 2026-08-20

- Verified every README claim against actual repo state: removed an
  aspirational stack table (every `Cargo.toml` still had empty
  `[dependencies]` at the time), stated the real branch-protection review
  count (0); trimmed to 43 lines (#3).
- Added `.devcontainer/devcontainer.json` for GitHub Codespaces
  development (#4), then added the `sshd` feature so
  `gh codespace ssh`/`logs` work (#6), then fixed a cargo registry
  volume permission error (`chown` in `postCreateCommand`) (#7).
- `research-agent`: real Atomic Red Team ingestion lands; `lab-agents`
  attacker begins (completed below) (#5).
- Completed attack/defend loop v1 end-to-end and tested: attacker
  (every attempt against `lab/scope.toml` denied via `host::evaluate`,
  fully logged), defender (detection-signal table verified against real
  `CapabilityDenied` events), verifier (real run produces
  `Verdict::Blocked` with a traceable reason; `Detected`/`Missed`
  classification proven correct via synthetic fixtures even though
  unreachable via real execution at the time) (#8).
- **Fixed** `audit::AuditStore` event-key collisions: events sharing a
  timestamp could silently overwrite each other in `redb`; fixed with a
  per-store monotonic sequence counter, caught by the synthetic-fixture
  tests for the Detected/Missed paths (#8).
- README rewritten from scratch, audited against current repo state,
  with a real/stub-annotated layout tree (#9).

### 2026-08-19

- Initial scaffold: Cargo workspace with 9 crate stubs (empty `lib.rs`,
  purpose-only doc comments, no logic), `README.md`, `CONTEXT.md`,
  `lab/scope.toml` template, `.gitignore`, CI stub.
- README polish: Mermaid architecture diagram, stack table, quickstart,
  contributing section (#1).
- **Fixed** Mermaid diagram clipping (removed `<br/>`/`<small>` HTML and
  a bare `&` in "ATT&CK" from node labels); trimmed README for
  scannability (#2).
