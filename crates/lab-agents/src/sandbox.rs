use std::path::Path;

use host::CapabilityDecision;
use wasmtime::{Config, Engine, Linker, Module, Store};
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::{FsPerms, WasiCtxBuilder};

const GUEST_WASM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/execute_marker_write.wasm"));

/// The synthetic proving technique's fixed marker file name, written
/// inside the declared lab target directory.
pub const MARKER_FILE_NAME: &str = "synthetic-proving-marker.txt";

struct SandboxState {
    wasi: WasiP1Ctx,
}

/// Outcome of actually executing the synthetic proving technique's guest
/// module — a real execution and a real write, not a dry-run validation
/// like `gate_pipeline::sandbox::dry_run_write`.
#[derive(Debug)]
pub enum ExecutionOutcome {
    /// The guest wrote the marker successfully inside the capability-scoped
    /// target directory.
    Succeeded { detail: String },
    /// Either the capability check denied the write before any sandbox was
    /// constructed, or the WASI runtime itself rejected it.
    Failed { detail: String },
}

/// Actually executes the synthetic proving technique inside a real
/// wasmtime/WASI-Preview-1 sandbox (the same WASI level
/// `gate_pipeline::sandbox` uses — `wasmtime-wasi`'s `p1` module, not the
/// `p2`/Preview-2 API; CONTEXT.md section 2 names "WASI-Preview-2"
/// generically as the broker's mechanism, but the actual proven,
/// reusable pattern already in this codebase is Preview 1, so that is
/// what this reuses rather than introducing a second, untested WASI
/// generation), preopened only on `target_dir` (the lab's declared
/// `[[environment.targets]]` local-directory, resolved by the caller).
///
/// Reuses `host::evaluate_file_write`'s real path-containment check before
/// constructing any sandbox object, mirroring
/// `gate_pipeline::sandbox::dry_run_write`'s exact capability-default-deny
/// discipline (CONTEXT.md section 2): if the marker path somehow resolves
/// outside `target_dir`, this returns `Failed` immediately and never
/// builds an `Engine`/`WasiCtx` at all. In practice `attacker::attempt_all`
/// only calls this after `host::evaluate` has already granted the
/// technique against this same `target_dir`, so this is a second,
/// redundant-but-cheap check — the same accepted redundancy
/// `gate_pipeline::review`'s doc comment already discloses for its own
/// call to `dry_run_write`.
pub fn execute_synthetic_marker_write(workspace_root: &Path, target_dir: &Path) -> anyhow::Result<ExecutionOutcome> {
    let marker_path = target_dir.join(MARKER_FILE_NAME);

    if let CapabilityDecision::Denied { reason } = host::evaluate_file_write(workspace_root, &marker_path) {
        return Ok(ExecutionOutcome::Failed { detail: reason });
    }

    let engine = Engine::new(&Config::new())?;
    let module = Module::new(&engine, GUEST_WASM)?;

    let mut linker = Linker::new(&engine);
    p1::add_to_linker_sync(&mut linker, |s: &mut SandboxState| &mut s.wasi)?;

    let mut builder = WasiCtxBuilder::new();
    builder.preopened_dir(target_dir, "/target", FsPerms::ReadWrite)?;
    builder.arg("execute_marker_write");
    builder.arg(format!("/target/{MARKER_FILE_NAME}"));
    builder.arg(research_agent::MARKER_CONTENT);
    let wasi = builder.build_p1();

    let mut store = Store::new(&engine, SandboxState { wasi });
    let instance = linker.instantiate(&mut store, &module)?;
    let start = instance.get_typed_func::<(), ()>(&mut store, "_start")?;

    match start.call(&mut store, ()) {
        Ok(()) => Ok(ExecutionOutcome::Succeeded { detail: format!("wrote marker to {}", marker_path.display()) }),
        Err(e) => Ok(ExecutionOutcome::Failed { detail: e.to_string() }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn granted_marker_write_actually_executes_and_lands_on_disk() {
        let workspace = tempfile::tempdir().unwrap();
        let target_dir = workspace.path().join("target");
        std::fs::create_dir(&target_dir).unwrap();

        let outcome = execute_synthetic_marker_write(workspace.path(), &target_dir).unwrap();

        assert!(matches!(outcome, ExecutionOutcome::Succeeded { .. }));
        let written = std::fs::read_to_string(target_dir.join(MARKER_FILE_NAME)).unwrap();
        assert_eq!(written, research_agent::MARKER_CONTENT);
    }

    #[test]
    fn marker_path_outside_workspace_root_is_denied_before_sandbox_construction() {
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();

        let outcome = execute_synthetic_marker_write(workspace.path(), outside.path()).unwrap();

        match outcome {
            ExecutionOutcome::Failed { detail } => {
                assert!(detail.contains("outside the workspace root"), "got: {detail}")
            }
            ExecutionOutcome::Succeeded { .. } => panic!("a marker path outside the workspace root must never succeed"),
        }
        assert!(
            !outside.path().join(MARKER_FILE_NAME).exists(),
            "a denied write must never touch disk"
        );
    }
}
