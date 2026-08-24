/**
 * Pi extension: the TypeScript-side counterpart to `adapter-pi`'s Rust
 * bridge server (`src/bin/pi_bridge.rs`).
 *
 * This file is NOT part of the Cargo build and is not wired into CI —
 * there is no TypeScript/Node toolchain anywhere else in this
 * workspace. It's a reference implementation showing how a real Pi
 * installation would load this adapter: copy (or symlink) it into
 * `.pi/extensions/` or `~/.pi/agent/extensions/`, alongside a running
 * `pi_bridge` process (`cargo run -p adapter-pi --bin pi_bridge`).
 *
 * Confirmed against Pi's real extension API
 * (https://github.com/earendil-works/pi/tree/main/packages/coding-agent#extensions,
 * examples/extensions/permission-gate.ts, examples/extensions/protected-paths.ts):
 * extensions run in-process inside Pi's own Node.js process via
 * `pi.on("tool_call", async (event, ctx) => {...})`, returning either
 * `undefined` (allow, no opinion) or `{ block: true, reason }` (deny).
 * There is no third "ask" state.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const GATED_TOOLS = new Set(["bash", "write"]);

export default function (pi: ExtensionAPI) {
	const bridgeUrl = process.env.ADAPTER_PI_BRIDGE_URL ?? "http://127.0.0.1:8787/";

	pi.on("tool_call", async (event, ctx) => {
		if (!GATED_TOOLS.has(event.toolName)) return undefined;

		// cwd comes from Node's own process.cwd(), not a Pi `ctx` field --
		// deliberate, since the exact shape of `ctx` wasn't independently
		// confirmed against the docs before writing this file.
		const body = JSON.stringify({
			toolName: event.toolName,
			input: event.input,
			cwd: process.cwd(),
		});

		try {
			const response = await fetch(bridgeUrl, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body,
			});

			if (!response.ok) {
				// Fail closed: the bridge server responded with a transport-
				// level error, not just a denied proposal.
				return { block: true, reason: `adapter-pi bridge returned HTTP ${response.status}` };
			}

			const decision = (await response.json()) as { granted: boolean; reason: string };
			if (decision.granted) return undefined;
			return { block: true, reason: decision.reason };
		} catch (err) {
			// Fail closed: network error, timeout, or the bridge process
			// isn't running at all -- never let a gated proposal through
			// unchecked just because the bridge couldn't be reached.
			return { block: true, reason: `adapter-pi bridge unreachable: ${err}` };
		}
	});
}
