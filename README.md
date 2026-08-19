# rust-agentic-sandbox

A trusted Rust orchestrator that puts AI coding agents and AI security agents behind the same deterministic gate: it intercepts every file write, edit, and shell command an agent proposes and every attack/defense move in an isolated lab, runs it through static analysis and a capability-scoped WebAssembly sandbox, and lets a non-LLM verdict engine — never the model itself — decide what actually happens.

## Architecture

Two capabilities, one verdict core.

```
                         ┌───────────────────────┐
   Claude Code ─────┐    │                       │
   Copilot CLI ─────┼───▶│   host (verdict       │◀──── research-agent
   Pi extension ────┘    │   engine + capability │      (ATT&CK / CVE /
        (hooks)          │   broker)             │       Atomic Red Team)
                         └──────────┬────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    ▼                                ▼
            gate-pipeline                       lab-agents
      (static analysis + wasm                (attacker + defender,
        sandbox dry-run)                    scope-locked to lab/scope.toml)
                    │                                │
                    └───────────────┬────────────────┘
                                    ▼
                              verifier + audit
                       (deterministic checks, redb + tracing)
```

- **Harness gate** — `adapters/{claude-code,copilot-cli,pi}` catch proposed writes/edits/commands via each tool's native pre-execution hook, before anything touches disk or a shell. `gate-pipeline` runs static analysis (clippy/cargo-audit, semgrep) and a `wasmtime`/WASI-P2 dry-run. `host` computes the allow/block verdict.
- **Attack/defend lab** — `research-agent` ingests known techniques from vetted sources into a queue. `lab-agents` (attacker + defender, both wasm-sandboxed and hard-scoped to `lab/scope.toml`) run them against each other. `verifier` checks real outcomes, not model opinion.
- **Shared core** — both paths terminate in the same `host` verdict engine and the same `audit` log. No LLM authors or overrides a verdict; it may only summarize one after the fact. See [`CONTEXT.md`](CONTEXT.md) for the non-negotiable policies behind this.

## Stack

| Concern | Crate(s) | Tech |
|---|---|---|
| Sandbox execution | `gate-pipeline`, `lab-agents` | `wasmtime`, `wasmtime-wasi` (Preview 2 / Component Model), `wit-bindgen` |
| Orchestration | `host`, `research-agent` | `tokio`, `petgraph` |
| Agent reasoning (host-side only) | `host`, `research-agent`, `lab-agents` | `aws-sdk-bedrockruntime` (or equivalent) |
| Serialization | all | `serde`, `serde_json` |
| Audit log | `audit` | `tracing` + `tracing-subscriber`, `redb` |

## Layout

```
crates/
├── host/                 # orchestrator, capability broker, verdict engine
├── adapters/              # claude-code, copilot-cli, pi hook adapters
├── gate-pipeline/          # static analysis + sandbox dry-run
├── research-agent/         # ATT&CK/CVE/Atomic Red Team ingestion
├── lab-agents/               # attacker + defender stubs, lab-scoped only
├── verifier/                   # deterministic outcome verification
└── audit/                       # tracing + redb-backed logging
lab/scope.toml                    # declared lab environment boundary
```

## Quickstart

> Scaffolding stage — no runnable binary yet. Once the broker and adapters land, this section will cover: installing the harness hook for your agent (Claude Code / Copilot CLI / Pi), pointing it at `host`, and declaring a lab scope in `lab/scope.toml` before running the attack/defend lab.

```sh
cargo check --workspace
```

## Status

Scaffolding only. See [`CHANGELOG.md`](CHANGELOG.md) for what's actually implemented.
