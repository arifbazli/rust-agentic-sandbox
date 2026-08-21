use std::path::PathBuf;
use std::process::Command;

fn main() {
    let guest_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("guest/dry_run_write.rs");
    println!("cargo:rerun-if-changed={}", guest_src.display());

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR is set by cargo"));
    let out_wasm = out_dir.join("dry_run_write.wasm");

    let status = Command::new("rustc")
        .args(["--target", "wasm32-wasip1", "--edition", "2021", "-O"])
        .arg(&guest_src)
        .arg("-o")
        .arg(&out_wasm)
        .status()
        .expect(
            "failed to invoke rustc to build the WASI dry-run guest — is the wasm32-wasip1 \
             target installed? (rustup target add wasm32-wasip1)",
        );

    assert!(
        status.success(),
        "failed to compile the WASI dry-run guest module ({})",
        guest_src.display()
    );
}
