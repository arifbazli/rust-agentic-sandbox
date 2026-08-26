//! Minimal WASI Preview 1 guest compiled to wasm32-wasip1 and embedded into
//! `lab-agents` via `build.rs`. Performs the synthetic proving technique's
//! one real operation: write a fixed marker string to a path inside the
//! preopened, capability-scoped target directory. Unlike
//! `gate_pipeline::sandbox`'s guest (a dry run against a throwaway scratch
//! copy), this write is real and lands in the actual declared lab target —
//! the same primitive (write these bytes to this preopened path), reused
//! for a different, real purpose.
fn main() {
    let mut args = std::env::args();
    args.next(); // skip argv[0]
    let path = args.next().expect("expected <path> arg");
    let content = args.next().expect("expected <content> arg");
    std::fs::write(&path, &content).expect("write should succeed if capability granted");
}
