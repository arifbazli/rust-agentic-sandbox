# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Cargo workspace scaffold with 9 crate stubs (empty `lib.rs`, purpose-only doc
  comments, no logic): `host`, `adapter-claude-code`, `adapter-copilot-cli`,
  `adapter-pi`, `gate-pipeline`, `research-agent`, `lab-agents`, `verifier`,
  `audit`.
- `README.md`: pitch, architecture summary, stack table, quickstart placeholder.
- `CONTEXT.md`: non-negotiable policy document (verdict authority,
  capability-default-deny, lab scope lock, research agent allowlist,
  deterministic instrumentation, honest negative results, harness-adapter
  parity).
- `lab/scope.toml`: template for the lab scope declaration that lab
  capability grants will be derived from (not yet wired to any grant logic).
- `.gitignore` for build artifacts.

No capability broker, sandbox execution, agent logic, or harness-adapter
logic is implemented yet — scaffolding and documentation only.
