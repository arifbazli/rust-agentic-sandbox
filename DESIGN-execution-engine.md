# Design: a real execution engine for `lab-agents::attacker`

**Status:** research + design proposal only. No code, no branch, no `Cargo.toml`
changes. Written 2026-08-26 for technical-debt item 3/3 ("no wasmtime/WASI-P2
sandbox execution path exists yet" — the last remaining disclosed gap in
`README.md`'s known-gaps line and `lab-agents`' crate-level doc comment).

Everything below rests on live verification done today (the ingested
technique's real content, the current WASI proposal list, and
`gate-pipeline`'s actual sandbox source), called out explicitly where it
matters, plus stable WASI architecture facts (the absence of a process/exec
model) that are foundational to the spec rather than something that could
have quietly changed.

---

## 1. The core problem, precisely

CONTEXT.md never states "must use wasmtime" as a goal in itself — section 2
("Capability-default-deny") names `wasmtime`/WASI-Preview-2 as the mechanism
*because* it's what makes default-deny real for the harness-gate's file-write
dry-run. The actual non-negotiable constraint that matters for this phase is
narrower and comes from `lab-agents`' own doc comment: an Atomic Red Team
`test_command` must run **verbatim, unmodified, or not at all** — never
rewritten into a different, "equivalent" probe. That constraint, not the
literal word "wasmtime," is what any design here has to satisfy.

The tension: `test_command`s are native shell one-liners (`powershell`,
`bash`, `command_prompt`), and WASM bytecode is not native shell. Something
has to bridge that gap, or the gap has to be declared out of scope for a
named, bounded reason.

## 2. What was actually checked today

**The current technique queue's real content** (`atomics/T1059/T1059.yaml`,
fetched live from `raw.githubusercontent.com`, not assumed):

> Exactly **one** atomic_test exists in the file as of today: **"AutoIt Script
> Execution"**, `supported_platforms: [windows]`, executor `powershell`,
> command present. Zero bash/linux tests exist in this file at all.

This matches `research-agent::ingest`'s real behavior (`ingest.rs` stores
every atomic_test with a runnable `executor.command`, keyed by guid) and the
real lab-loop run from PR #21 (`ingested: 1`). **The only technique actually
in the queue today is 100% Windows PowerShell.** Any design option scoped to
bash/Linux only would cover **zero percent** of what's really ingested right
now — this has to be stated plainly rather than glossed over, per CONTEXT.md
section 6.

**WASI's current process model** (WASI's own `docs/Proposals.md`, fetched
live today): every proposal at every phase (0 through 5) is listed —
Filesystem, Sockets, Clocks, Random, CLI, and HTTP are the only Phase 3
("Implementation") proposals; Phase 0-2 add things like Key-Value Store,
Machine Learning, I2C, Threads, TLS, Crypto, etc. **No proposal, at any
phase, is about subprocess spawning, `fork`, `exec`, or child-process
creation.** The "CLI" proposal (`wasi-cli`) defines how a WASM guest itself
behaves as a command-line program (stdin/stdout/stderr/args/env/exit for
*that* guest) — it is not about that guest launching other processes.

This isn't a fast-moving detail that could have changed since a stale
memory — the absence of a process model is a foundational, deliberate
property of WASI's sandboxing design (a WASM module only ever gets the
host functions/imports its `Linker` explicitly wires up; "spawn an arbitrary
native binary" is not a capability any WASI proposal defines, and giving a
guest that capability would defeat most of what a WASI sandbox is for). So:
**no current or draft WASI proposal supports subprocess exec, and none is
positioned to.**

**`gate-pipeline`'s existing WASI sandbox** (`crates/gate-pipeline/src/sandbox.rs`
and `review.rs`, read directly): `dry_run_write` builds a real
`wasmtime::Engine` + `Linker` + `WasiCtxBuilder`, preopens one scratch
directory, and runs a small, purpose-built guest module
(`guest/dry_run_write.rs`, compiled at build time to `wasm32-wasip1`) whose
entire job is "write these bytes to this preopened path and exit." Critically,
per `review.rs`, **this sandbox is only ever invoked for `Proposal::FileWrite`
— never for `Proposal::ShellCommand`.** Shell commands go through
`static_analyze`'s deny-pattern check only; they never reach a sandbox at
all today, in either the harness-gate or the lab. So there is no existing
"run an arbitrary command in WASM" code to extend — only a capability-check-
before-sandbox-construction *pattern* (never instantiate an `Engine`/`WasiCtx`
without a grant) that's worth reusing, and a guest module that solves a much
narrower, already-fully-specified problem (one fixed operation, not an
arbitrary shell interpreter).

## 3. Three real options

### Option A — WASI-compiled shell interpreter, `platform: linux`/bash only

Compile a POSIX shell (e.g. porting `mvdan/sh` or a `busybox ash`-equivalent)
to `wasm32-wasip2`, embed it as the guest module, and feed a bash-platform
`test_command` to it as literal, unmodified input text — the shell parses and
runs it, not this project.

- **Verbatim, unmodified?** Yes, for the command *text* fed in. But the text
  itself often isn't self-contained — a real bash one-liner routinely shells
  out to `curl`, `python3`, `openssl`, `nc`, etc. WASI has no `exec`/`fork`
  (section 2 above), so the interpreter can only ever run its own builtins
  (`cd`, variable ops, conditionals, string/arithmetic expansion) — it cannot
  invoke an external binary that isn't itself compiled into the same WASM
  module and wired up as a builtin. So this only genuinely satisfies
  "verbatim, unmodified execution" for the subset of bash one-liners that
  use shell builtins exclusively — most real Atomic Red Team bash tests do
  not qualify, because they call real external tools.
- **Genuinely WASI-based?** Yes — this is the most literal reading of
  "wasmtime/WASI-Preview-2 execution."
- **Coverage:** **0% of what's currently ingested** (the real queue entry is
  Windows PowerShell, not bash). Even under a hypothetical future
  bash-platform ingestion, coverage would be a minority of real ART bash
  tests, since most invoke external binaries a WASI sandbox structurally
  cannot exec.
- **Size:** weeks, not days. Porting/vendoring a POSIX shell to
  `wasm32-wasip2` isn't an off-the-shelf solved problem today; then there's
  building the argv/stdio/exit-code capture harness around it, and it still
  never touches the one technique actually in the queue.

### Option B — reconsider the mechanism: OS-level resource-limited subprocess

Have `host` launch the technique's `test_command` as a real native
subprocess, in its own declared interpreter (`powershell.exe`, `bash`, `cmd`),
under OS-level containment instead of a WASM linear-memory sandbox: no
network, a disposable/ephemeral working directory, a hard timeout, and
(platform-permitting) namespace/cgroup or Job-Object-style resource limits —
the same default-deny *intent* CONTEXT.md section 2 describes, implemented
with a different primitive.

- **Verbatim, unmodified?** Yes, completely and literally — the actual
  `test_command` string runs, unedited, in the interpreter it declares.
- **Genuinely WASI-based?** **No.** This is the honest tradeoff: it's a real,
  legitimate sandboxing mechanism, but it is not `wasmtime`/WASM bytecode.
  CONTEXT.md section 2 names `wasmtime`/WASI-Preview-2 specifically as the
  broker's mechanism — swapping the actual isolation technology for command
  execution is a policy question, not something this design doc can decide
  unilaterally. **Flagging this explicitly for your call, not proceeding on
  it myself.**
- **Coverage:** potentially 100% of realistic ART content, including the
  one technique that's actually in the queue today — this is the only
  option of the three that could ever run it.
- **Size:** real weeks, not days, and doubled by platform: Linux containment
  (namespaces/cgroups/seccomp) and Windows containment (Job Objects/
  AppContainer/restricted tokens) are different code paths, and the queue's
  one real entry today is Windows. A minimal, non-hardened version (spawn +
  timeout + scratch cwd, no real namespace/Job-Object isolation) could land
  in days, but that version is a materially weaker safety boundary than
  CONTEXT.md section 2 currently promises — worth being explicit that "days"
  and "weeks" here buy very different actual guarantees.

### Option C — scope down to a synthetic, self-authored proving technique

Defer real Atomic Red Team execution entirely. Build the
execute-and-capture engine (launch, capture stdout/exit code, log a real
`ExecutionSucceeded`/`ExecutionFailed`-style audit event, let `verifier`
finally compute real `Detected`/`Missed` instead of only ever `Blocked`)
against one deliberately trivial, self-authored technique — e.g. "write a
known marker string to a file inside `lab/target/`" — not a real ART
`test_command`.

- **Verbatim, unmodified?** Trivially yes — the synthetic technique is
  authored to be simple enough to run as-is regardless of mechanism.
- **Genuinely WASI-based?** Can be, cleanly, with **zero policy exception
  needed**: since this technique doesn't have to be a real shell one-liner,
  it can be defined *as* a small Rust program compiled to `wasm32-wasip2`
  from the start — reusing `gate-pipeline::sandbox`'s exact proven pattern
  (purpose-built guest module, preopened scratch dir, capability-gate before
  `Engine`/`WasiCtx` construction) instead of needing a general-purpose shell
  interpreter or the exec-model workaround Option A needs.
- **Coverage:** 0% of real Atomic Red Team content, by design — this
  is explicitly a plumbing-proving phase, not a content-coverage phase. It
  does not resolve "how do we ever run the real ingested PowerShell
  technique," and shouldn't be reported as if it does.
- **Size:** smallest of the three — days, not weeks. It reuses proven
  scaffolding, sidesteps both the WASI exec-model wall and cross-platform OS
  sandboxing, and unblocks `verifier`'s `Detected`/`Missed` paths (currently
  provably unreachable via real execution — see `verifier`'s doc comments)
  without touching the harder, real-content problem at all.

## 4. Recommendation

Option A is close to a dead end *for this project specifically*: it's the
most literal "WASI execution," but it would cover none of what's actually
ingested today and a minority of realistic bash content even in a
hypothetical future. I'd only revisit it if `lab/scope.toml` ever shifted
toward bash/Linux-only ART categories, and even then only for
builtins-only tests.

Options B and C aren't actually competing — they answer different questions
and could both happen, in this order:

1. **Build Option C now.** It's the smallest, needs no CONTEXT.md
   conversation, and proves the entire engine's plumbing (capability gate →
   sandboxed execution → capture → audit → real verdict) end-to-end using
   the exact wasmtime pattern this codebase has already proven once in
   `gate-pipeline::sandbox`. This alone closes the "verifier can only ever
   produce Blocked" gap that `verifier`'s own doc comments disclose.
2. **Separately, open the Option B policy conversation** for real ART
   execution, since it's the only mechanism of the three that could ever
   honestly run the technique that's actually in the queue. That's a
   CONTEXT.md section 2 amendment discussion (redefining the *mechanism*
   while preserving the *intent* — contained, capability-scoped, fully
   audited), not an implementation detail, and belongs to you to decide, not
   something to resolve inside a design doc.

## 5. One unrelated finding, noted but not fixed this session

`crates/lab-agents/src/lib.rs`'s crate-level doc comment is stale: it still
says `host::evaluate` "currently denies every technique against the real
`lab/scope.toml` (its validity window has already expired... an unpopulated
placeholder)" and that the execution branch is "unreachable this session
regardless." That was true before PR #16 (2026-08-24); it hasn't been true
since — `lab/scope.toml` is real and populated, and T1059 is genuinely
`Granted` today (confirmed live via the PR #21 lab-loop run). Not touching it
this session per the no-code constraint, but it should be corrected the next
time any code in this crate is touched, since it currently misdescribes why
the execution gap exists (it's "not built yet," not "unreachable").
