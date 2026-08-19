# CONTEXT.md

This file is the source of truth for the non-negotiable policies behind `rust-agentic-sandbox`. It governs both the harness gate (Claude Code / Copilot CLI / Pi adapters) and the attack/defend lab.

> **Read this first if you're resuming work** — especially in a different CLI/harness than the one that started it. Policy lives here, not in any single session's prompt history. If a request conflicts with a section below, the section wins; flag the conflict instead of resolving it silently.

**At a glance** — seven non-negotiable policies:

1. [Verdict authority](#1-verdict-authority) — deterministic Rust only; LLMs summarize but never decide.
2. [Capability-default-deny](#2-capability-default-deny) — zero capabilities until explicitly granted.
3. [Lab scope lock](#3-lab-scope-lock) — hard-capped to `lab/scope.toml`, enforced structurally.
4. [Research agent allowlist](#4-research-agent-allowlist) — MITRE ATT&CK / CVE-NVD / Atomic Red Team / Sigma only.
5. [Deterministic instrumentation](#5-deterministic-instrumentation) — every grant, denial, and verdict logged in full.
6. [Honest negative results](#6-honest-negative-results) — no finding is a valid, recorded outcome.
7. [Harness-adapter parity](#7-harness-adapter-parity) — same verdict standard across every adapter.

---

## 1. Verdict authority

All pass/fail/block determinations are deterministic Rust logic: static rule matches, sandbox capability violations, real post-condition checks. That logic lives in `host` (verdict engine) and `verifier` (outcome checks).

LLMs may **summarize or explain** a verdict after it is produced. They may never **author or override** one — no model output is ever consulted as an input to the allow/block/pass/fail decision itself, directly or indirectly (e.g. "ask the model if this looks safe" is not a verdict path).

**Why this is non-negotiable:** an LLM-authored verdict makes the gate and the lab only as trustworthy as the model's judgment on that call, which defeats the point of a deterministic broker. If a future feature seems to need model judgment in the verdict path, the answer is to add a new deterministic check, not to let the model decide.

## 2. Capability-default-deny

Every sandbox instance (`wasmtime`/WASI-Preview-2) starts with zero capabilities. No filesystem access, no network access, no environment variables, no host function imports — nothing — until `host` explicitly grants each one for that specific run.

Grants are scoped to the minimum needed for the proposal or technique under evaluation, and are never broadened "just in case." A capability not explicitly granted is denied; there is no implicit or inherited access.

**Why this is non-negotiable:** default-deny is what makes the sandbox dry-run in `gate-pipeline` and the attacker/defender agents in `lab-agents` safe to run at all. Any default-allow capability turns the sandbox into a suggestion rather than a boundary.

## 3. Lab scope lock

Attacker and defender agents (`lab-agents`) are hard-capped to the environment declared in [`lab/scope.toml`](lab/scope.toml). No attack agent may reason about, query, or act on anything outside that declared scope — not adjacent hosts, not other accounts, not "just to check."

This is enforced **structurally**, via the capabilities `host` grants to each lab sandbox instance, not merely documented as policy or hoped for via prompting. If `lab/scope.toml` doesn't declare it, no capability grant exists for it, and the sandbox has no way to reach it regardless of what the agent is instructed or wants to do.

**Why this is non-negotiable:** a security research lab that relies on an LLM agent "staying in scope" because it was told to is not a lab, it's an incident waiting to happen. Scope must be a wall the agent cannot see past, not a fence it's asked not to jump.

## 4. Research agent allowlist

`research-agent` ingests structured, vetted threat-intel only from an explicit source allowlist:

- MITRE ATT&CK
- CVE / NVD
- Atomic Red Team test definitions
- Sigma rules

Only published, known techniques — never novel exploit generation, never freeform "how would I attack X" reasoning. The output of `research-agent` is a structured technique reference (queue entries with technique IDs, metadata, and references back to the source), not prose or generated attack code.

**Why this is non-negotiable:** the lab exercises known, documented techniques against a scoped environment the operator owns — it is not a vehicle for discovering or generating new exploits. Sticking to the allowlist keeps that boundary real.

## 5. Deterministic instrumentation

Every capability grant, every denial, and every verdict is logged via `audit` (`tracing` + `redb`) — in full, not sampled, and not summarized by an LLM before being written. The audit log is the ground truth of what the system did; if it isn't logged, it didn't happen as far as the system is concerned.

**Why this is non-negotiable:** sampling or LLM-summarizing before logging turns the audit trail into a lossy, model-mediated account of security-relevant events, which is unacceptable for something meant to be evidence.

## 6. Honest negative results

If a technique, category, or run yields no finding — an attack didn't land, a defense had nothing to catch, a source had nothing new — that absence is recorded explicitly as a negative result. Do not force, embellish, or manufacture a finding to make a run look more productive than it was.

**Why this is non-negotiable:** a "no result" that gets silently dropped or padded out is worse than no data at all — it corrupts the record the lab exists to produce.

## 7. Harness-adapter parity

`adapter-claude-code`, `adapter-copilot-cli`, and `adapter-pi` all feed the same `gate-pipeline` and the same `host` verdict engine. No adapter applies a looser or stricter standard than the others, and no adapter is allowed to short-circuit the pipeline or add a side channel that bypasses `host`.

If a harness's hook payload needs adapter-specific translation, that translation happens on the way *in* (normalizing the payload into `gate-pipeline`'s request shape); it never changes the verdict standard applied on the way *out*.

**Why this is non-negotiable:** the moment one harness gets a different bar, the gate's guarantee becomes "safe, except when you use that other tool," which isn't a guarantee.

---

## Scope of this session

> **Status**: this document describes policy for a system whose capability broker, sandbox execution, agent logic, and adapter logic are **not yet implemented**. Scaffolding sessions must not implement any of the above mechanisms — only document them here, in the workspace layout, and in `lab/scope.toml`'s template shape. See [`CHANGELOG.md`](CHANGELOG.md) for what actually exists today.
