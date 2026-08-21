use std::path::Path;

use host::CapabilityDecision;
use wasmtime::{Config, Engine, Linker, Module, Store};
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::{FsPerms, WasiCtxBuilder};

const GUEST_WASM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/dry_run_write.wasm"));

struct SandboxState {
    wasi: WasiP1Ctx,
}

/// Outcome of one sandboxed dry-run write attempt.
#[derive(Debug)]
pub enum SandboxOutcome {
    /// The guest wrote successfully inside the preopened scratch boundary.
    WriteSucceeded,
    /// Either the capability check denied the proposal before any sandbox
    /// was constructed, or the WASI runtime itself rejected the guest's
    /// write (a confinement violation). `detail` distinguishes the two: a
    /// denial-before-sandbox carries the exact `host::evaluate_file_write`
    /// reason unchanged; a real sandbox rejection carries a WASI/wasmtime
    /// error string instead.
    WriteDenied { detail: String },
}

/// Runs a real WASI-guest write attempt against a single preopened,
/// throwaway scratch directory (created and torn down entirely inside this
/// function — never the real target), gated by Step 1's
/// `host::evaluate_file_write`.
///
/// If that capability check denies the proposed path, this function
/// returns `WriteDenied` immediately and **never constructs a
/// `wasmtime::Engine`, `WasiCtx`, or any sandbox object at all** — matching
/// CONTEXT.md's capability-default-deny: nothing is instantiated without a
/// grant.
///
/// **Known limitation, disclosed on purpose (TOCTOU):** this proves the
/// write succeeds against a *copy* of the capability boundary at dry-run
/// time. It does not prove the real target path is unchanged between this
/// check and whatever real write eventually happens in Step 4 — the real
/// filesystem could change in between. Closing that gap requires either
/// performing the real write inside this same sandboxed step (not wired up
/// yet) or a freshness re-check immediately before the real write. Same
/// style of honest disclosure as the wasmtime-execution gap in
/// `lab-agents`.
pub fn dry_run_write(workspace_root: &Path, proposed_path: &Path, content: &str) -> anyhow::Result<SandboxOutcome> {
    let reason = match host::evaluate_file_write(workspace_root, proposed_path) {
        CapabilityDecision::Granted => None,
        CapabilityDecision::Denied { reason } => Some(reason),
    };
    if let Some(reason) = reason {
        return Ok(SandboxOutcome::WriteDenied { detail: reason });
    }

    let file_name = proposed_path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("proposed path {} has no file name", proposed_path.display()))?
        .to_string_lossy()
        .into_owned();

    let scratch = tempfile::tempdir()?;

    let engine = Engine::new(&Config::new())?;
    let module = Module::new(&engine, GUEST_WASM)?;

    let mut linker = Linker::new(&engine);
    p1::add_to_linker_sync(&mut linker, |s: &mut SandboxState| &mut s.wasi)?;

    let mut builder = WasiCtxBuilder::new();
    builder.preopened_dir(scratch.path(), "/sandbox", FsPerms::ReadWrite)?;
    builder.arg("dry_run_write");
    builder.arg(format!("/sandbox/{file_name}"));
    builder.arg(content);
    let wasi = builder.build_p1();

    let mut store = Store::new(&engine, SandboxState { wasi });
    let instance = linker.instantiate(&mut store, &module)?;
    let start = instance.get_typed_func::<(), ()>(&mut store, "_start")?;

    match start.call(&mut store, ()) {
        Ok(()) => Ok(SandboxOutcome::WriteSucceeded),
        Err(e) => Ok(SandboxOutcome::WriteDenied { detail: e.to_string() }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn granted_file_write_dry_runs_successfully() {
        let workspace = tempfile::tempdir().unwrap();
        let proposed = workspace.path().join("file.txt");

        let outcome = dry_run_write(workspace.path(), &proposed, "hello from dry-run").unwrap();

        assert!(matches!(outcome, SandboxOutcome::WriteSucceeded));
    }

    #[test]
    fn denied_file_write_never_reaches_sandbox_construction() {
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let proposed = outside.path().join("file.txt");

        let outcome = dry_run_write(workspace.path(), &proposed, "should never run").unwrap();

        match outcome {
            SandboxOutcome::WriteDenied { detail } => {
                assert!(
                    detail.contains("outside the workspace root"),
                    "expected the original host::evaluate_file_write denial reason, got: {detail}"
                );
            }
            SandboxOutcome::WriteSucceeded => panic!("a denied file write must never succeed"),
        }
    }

    #[test]
    fn sandbox_has_no_ambient_authority_beyond_the_scratch_preopen() {
        let scratch = tempfile::tempdir().unwrap();

        let engine = Engine::new(&Config::new()).unwrap();
        let module = Module::new(&engine, GUEST_WASM).unwrap();
        let mut linker = Linker::new(&engine);
        p1::add_to_linker_sync(&mut linker, |s: &mut SandboxState| &mut s.wasi).unwrap();

        let mut builder = WasiCtxBuilder::new();
        builder.preopened_dir(scratch.path(), "/sandbox", FsPerms::ReadWrite).unwrap();
        builder.arg("dry_run_write");
        builder.arg("/sandbox/../escape.txt");
        builder.arg("should never land");
        let wasi = builder.build_p1();

        let mut store = Store::new(&engine, SandboxState { wasi });
        let instance = linker.instantiate(&mut store, &module).unwrap();
        let start = instance.get_typed_func::<(), ()>(&mut store, "_start").unwrap();

        assert!(start.call(&mut store, ()).is_err());
    }
}
