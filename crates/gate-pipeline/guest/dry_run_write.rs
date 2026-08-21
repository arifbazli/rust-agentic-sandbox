//! Minimal WASI Preview 1 guest compiled to wasm32-wasip1 and embedded into
//! `gate-pipeline` via `build.rs`. Its only job is to prove, for real, that
//! a write succeeds or fails inside a capability-scoped WASI sandbox —
//! nothing else. Takes the target path and content as argv and writes
//! exactly that.
fn main() {
    let mut args = std::env::args();
    args.next(); // skip argv[0]
    let path = args.next().expect("expected <path> arg");
    let content = args.next().expect("expected <content> arg");
    std::fs::write(&path, &content).expect("write should succeed if capability granted");
}
