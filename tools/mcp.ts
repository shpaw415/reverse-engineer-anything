#!/usr/bin/env bun
// reverse-engineer-anything — session-lock CLI for the REA MCP gate.
//
//   ob-plugin-reverse-engineer-anything-mcp open [--ttl N]   unlock the MCP for this thread's work
//   ob-plugin-reverse-engineer-anything-mcp close            lock it again (always do this after analysis)
//   ob-plugin-reverse-engineer-anything-mcp status           lock state, REA version, readiness, gate log tail
//   ob-plugin-reverse-engineer-anything-mcp gate             speak MCP JSON-RPC to the gate directly (fallback
//                                                            for threads that do not see rea_* tools yet)
//
// The gate (MCP server) reads ~/.open-bot/plugin-reverse-engineer-anything/session.json;
// this CLI is the only writer. No secrets involved.
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";

const PLUGIN_ID = "reverse-engineer-anything";
const HOME = process.env.HOME || "/home/agent";
const STATE_DIR = `${HOME}/.open-bot/plugin-${PLUGIN_ID}`;
const SESSION_FILE = `${STATE_DIR}/session.json`;
const LOG_FILE = `${STATE_DIR}/gate.log`;
const CONFIG_FILE = `${HOME}/.config/open-bot/plugin-${PLUGIN_ID}.json`;
const PIN_FALLBACK = "6.7.0";

function settings(): Record<string, string> {
  try { return JSON.parse(readFileSync(CONFIG_FILE, "utf8")).settings || {}; } catch { return {}; }
}
function defaultTtlMinutes(): number {
  const n = Number(settings().ttl_minutes ?? 240);
  return Number.isFinite(n) && n > 0 ? n : 240;
}
// Daemon-spawned contexts may run with a minimal PATH that lacks /usr/local/bin,
// so fall back to the standard global-install locations before giving up.
const REA_FALLBACKS = ["/usr/local/bin/rea", "/usr/bin/rea", `${HOME}/.local/bin/rea`];
function reaBin(): string | null {
  const found = Bun.which("rea");
  if (found) return found;
  for (const p of REA_FALLBACKS) {
    try { if (existsSync(p)) return p; } catch { /* ignore */ }
  }
  return null;
}
function reaVersion(): string {
  const p = reaBin();
  if (!p) return "NOT INSTALLED";
  try {
    const r = Bun.spawnSync([p, "--version"]);
    return r.stdout.toString().trim() || "installed (version unknown)";
  } catch { return "installed (version check failed)"; }
}
function psOk(): boolean { return !!Bun.which("ps") || existsSync("/usr/bin/ps"); }
function session(): { expires: number } | null {
  try {
    const s = JSON.parse(readFileSync(SESSION_FILE, "utf8"));
    return typeof s.expires === "number" ? s : null;
  } catch { return null; }
}
function isOpen(): boolean { const s = session(); return !!s && s.expires > Date.now(); }
function gateLogTail(lines = 8): string[] {
  try {
    return readFileSync(LOG_FILE, "utf8").trimEnd().split("\n").slice(-lines);
  } catch { return []; }
}

const [, , cmd = "status"] = process.argv;

if (cmd === "open") {
  const ttlIdx = process.argv.indexOf("--ttl");
  const explicit = ttlIdx > -1 ? Number(process.argv[ttlIdx + 1]) : undefined;
  const minutes = Math.min(1440, Math.max(1, explicit && Number.isFinite(explicit) ? explicit : defaultTtlMinutes()));
  if (!reaBin()) {
    console.error("The REA CLI is NOT installed. Reinstall the plugin (its setup installs rea-agents), then retry.");
    process.exit(1);
  }
  mkdirSync(STATE_DIR, { recursive: true });
  const expires = Date.now() + minutes * 60_000;
  writeFileSync(SESSION_FILE, JSON.stringify({ expires, openedAt: new Date().toISOString() }, null, 2));
  console.log(`REA MCP session OPEN for ${minutes} min (until ${new Date(expires).toISOString()}).`);
  console.log(`Work through the rea_* MCP tools (rea_catalog to discover, rea_cli to run), then run \`ob-plugin-${PLUGIN_ID}-mcp close\` when the analysis is delivered.`);
  process.exit(0);
}

if (cmd === "close") {
  try { rmSync(SESSION_FILE); } catch { /* already closed */ }
  console.log("REA MCP session CLOSED (gate locked).");
  process.exit(0);
}

if (cmd === "gate") {
  // Fallback endpoint: speak MCP JSON-RPC (one message per line) through the gate's lock.
  // For threads whose tool list does not show rea_* yet (e.g. right after install,
  // before the desktop restarts). Same enforcement as the registered MCP server.
  const gate = `${HOME}/.open-bot/plugin-${PLUGIN_ID}/gate.ts`;
  const gatePath = existsSync(gate) ? gate : `/usr/local/bin/ob-plugin-${PLUGIN_ID}-gate.ts`;
  const child = Bun.spawn(["bun", gatePath], { stdin: "inherit", stdout: "inherit", stderr: "inherit" });
  process.exit(await child.exited);
}

if (cmd === "status") {
  const s = session();
  const open = isOpen();
  const minsLeft = open && s ? Math.max(0, Math.round((s.expires - Date.now()) / 60_000)) : 0;
  console.log(`gate:   ${open ? `OPEN (${minsLeft} min left)` : s ? "EXPIRED (run open again)" : "LOCKED"}`);
  console.log(`rea:    ${reaVersion()}`);
  console.log(`procps: ${psOk() ? "ok" : "MISSING — apt-get install procps (Linux prerequisite)"}`);
  console.log(`settings: ttl_minutes=${settings().ttl_minutes ?? "240 (default)"} timeout_minutes=${settings().timeout_minutes ?? "15 (default)"} rea_version=${settings().rea_version ?? `${PIN_FALLBACK} (default)`} rea_env=${settings().rea_env ? "(set)" : "(none)"}`);
  const tail = gateLogTail();
  if (tail.length) console.log(`gate.log (last ${tail.length}):\n  ` + tail.join("\n  "));
  process.exit(0);
}

console.error(`usage: ob-plugin-${PLUGIN_ID}-mcp open [--ttl N] | close | status | gate`);
process.exit(2);
