//! Real Pi bridge server entry point: a small, local, persistent HTTP
//! server the companion TS extension (`extension/pi-gate.ts`) POSTs
//! every intercepted `tool_call` event to. Long-running by design —
//! unlike the stdin/stdout, one-shot-per-invocation binaries the other
//! two adapters use, spinning up a fresh `wasmtime::Engine` and
//! `AuditStore` per Pi tool call would be wasteful and racy for
//! concurrent calls within a session, so this process is started once
//! and reused.
//!
//! Always responds HTTP 200 with a well-formed `{granted, reason}` body
//! — internal errors (bad JSON, an error from `handle_hook` itself)
//! become `granted: false` rather than an HTTP error code, so the TS
//! shim's own fail-closed fallback (treating a non-OK response as a
//! block) is a pure backup for "the server itself is unreachable," not
//! the primary error path, per CONTEXT.md section 2
//! (capability-default-deny).

use std::path::Path;

use adapter_pi::{handle_hook, BridgeDecision, BridgeRequest};
use audit::AuditStore;

const DEFAULT_PORT: u16 = 8787;

fn main() -> anyhow::Result<()> {
    let port: u16 =
        std::env::var("ADAPTER_PI_BRIDGE_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_PORT);

    let store = AuditStore::open(".audit/store.redb")?;
    let server = tiny_http::Server::http(("127.0.0.1", port))
        .map_err(|e| anyhow::anyhow!("failed to bind bridge server to 127.0.0.1:{port}: {e}"))?;

    eprintln!("adapter-pi bridge listening on http://127.0.0.1:{port}");

    for mut request in server.incoming_requests() {
        let mut body = String::new();
        let decision = match request.as_reader().read_to_string(&mut body) {
            Ok(_) => handle_request(&body, &store),
            Err(e) => BridgeDecision::denied(format!("failed to read request body: {e}")),
        };

        let response_body = serde_json::to_string(&decision)
            .unwrap_or_else(|_| r#"{"granted":false,"reason":"adapter failed to serialize its own output"}"#.to_string());
        let content_type = tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
            .expect("static header name/value is always valid");
        let response = tiny_http::Response::from_string(response_body).with_header(content_type);
        let _ = request.respond(response);
    }

    Ok(())
}

fn handle_request(body: &str, store: &AuditStore) -> BridgeDecision {
    let request: BridgeRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => return BridgeDecision::denied(format!("failed to parse request JSON: {e}")),
    };

    match handle_hook(&request.tool_name, &request.input, Path::new(&request.cwd), store) {
        Ok(decision) => decision,
        Err(e) => BridgeDecision::denied(format!("adapter error, failing closed: {e}")),
    }
}
