#!/usr/bin/env bun
/**
 * reverse-engineer-anything — MCP stdio gate for REA (morluto/rea, rea-agents CLI).
 *
 * Sits between opencode (MCP client) and the `rea` CLI. The daemon registers this
 * gate globally, so the gate — not opencode — enforces the lock AND the context budget:
 *
 *  - REA's real MCP catalog is 207 tools (~2.6 MB ≈ 640k tokens). Injecting it raw
 *    would blow every thread's context. The gate therefore advertises exactly five
 *    tiny meta-tools and drives the `rea` CLI underneath:
 *      rea_status   — lock state, REA version, readiness pointers (no lock needed)
 *      rea_catalog  — discover the 207 backend tools by name/query (no lock needed)
 *      rea_cli      — run any `rea ...` CLI command, bounded output, full JSON to file
 *      rea_mcp_call — call a backend MCP tool by name (full parity, same bounds)
 *      rea_ghidra   — gated Ghidra headless passthrough (readiness verdict / run
 *                     analyzeHeadless with the plugin-managed Ghidra + JDK env), for
 *                     existing-project re-reads the REA CLI does not expose
 *
 *  - Locked (default): rea_cli, rea_mcp_call and rea_ghidra run calls get a clear refusal.
 *  - Unlocked: session file ~/.open-bot/plugin-reverse-engineer-anything/session.json
 *    holds {"expires": <epochMs>} in the future; only the plugin CLI
 *    (ob-plugin-reverse-engineer-anything-mcp open|close) writes or removes it.
 *
 * Degradation: if `rea` is missing, every call gets a clean error (never a crash).
 */
import { createInterface } from "node:readline";
import { appendFileSync, closeSync, existsSync, mkdirSync, openSync, readdirSync, readFileSync, statSync, unlinkSync, writeFileSync, writeSync } from "node:fs";

const PLUGIN_ID = "reverse-engineer-anything";
const HOME = process.env.HOME || "/home/agent";
const STATE_DIR = `${HOME}/.open-bot/plugin-${PLUGIN_ID}`;
const SESSION_FILE = `${STATE_DIR}/session.json`;
const LOG_FILE = `${STATE_DIR}/gate.log`;
const CATALOG_FILE = `${STATE_DIR}/catalog.json`;
const CONFIG_FILE = `${HOME}/.config/open-bot/plugin-${PLUGIN_ID}.json`;
const PIN_FALLBACK = "6.7.0";
// Always advertise the real (meta) toolset: clients fetch tools/list once at daemon
// boot while we are locked — an empty list would be cached forever.
const LIST_WHILE_LOCKED = true;
const STDOUT_CAP = 256 * 1024; // inline stdout cap (~64k tokens worst case; file has the rest)
const STDERR_CAP = 64 * 1024;
const RAM_CAP = 16 * 1024 * 1024; // hard collect cap before we cut the stream

function settings(): Record<string, string> {
  try { return JSON.parse(readFileSync(CONFIG_FILE, "utf8")).settings || {}; } catch { return {}; }
}
function timeoutMinutes(explicit?: unknown): number {
  const n = Number(explicit ?? settings().timeout_minutes ?? 15);
  if (!Number.isFinite(n)) return 15;
  return Math.min(60, Math.max(1, Math.round(n)));
}
function extraEnv(): Record<string, string> {
  const out: Record<string, string> = {};
  const raw = String(settings().rea_env ?? "").trim();
  if (!raw) return out;
  for (const pair of raw.split(",")) {
    const eq = pair.indexOf("=");
    if (eq <= 0) continue;
    const k = pair.slice(0, eq).trim();
    const v = pair.slice(eq + 1).trim();
    if (/^[A-Z_][A-Z0-9_]*$/i.test(k)) out[k] = v;
  }
  return out;
}

type JsonRpcId = number | string | null;
interface Msg { jsonrpc: "2.0"; id?: JsonRpcId; method?: string; params?: any; result?: any; error?: any }

function log(line: string) {
  try {
    mkdirSync(STATE_DIR, { recursive: true });
    try { if (statSync(LOG_FILE).size > 200_000) appendFileSync(LOG_FILE, "--- rotated ---\n"); } catch { /* first write */ }
    appendFileSync(LOG_FILE, `${new Date().toISOString()} ${line}\n`);
  } catch { /* never crash the gate for logging */ }
}

function readSession(): { expires: number } | null {
  try {
    const s = JSON.parse(readFileSync(SESSION_FILE, "utf8"));
    return typeof s.expires === "number" ? s : null;
  } catch { return null; }
}
function isOpen(): boolean {
  const s = readSession();
  return !!s && s.expires > Date.now();
}

function send(msg: object) { process.stdout.write(JSON.stringify(msg) + "\n"); }
function result(id: JsonRpcId, result: object) { send({ jsonrpc: "2.0", id, result }); }
function errResult(id: JsonRpcId, text: string) {
  send({ jsonrpc: "2.0", id, result: { isError: true, content: [{ type: "text", text }] } });
}
function protoError(id: JsonRpcId, message: string, code = -32601) {
  send({ jsonrpc: "2.0", id, error: { code, message } });
}

const OPEN_CMD = "ob-plugin-reverse-engineer-anything-mcp";
const LOCK_MSG =
  `REA MCP is locked by the ${PLUGIN_ID} plugin. It unlocks only for the Reverse Engineer persona: ` +
  `in a Reverse Engineer thread run \`${OPEN_CMD} open\`, do the analysis work through the rea_* tools, ` +
  `then \`${OPEN_CMD} close\`. Check state any time with \`${OPEN_CMD} status\`.`;
const EXPIRED_MSG =
  `REA MCP session expired. In the Reverse Engineer thread run \`${OPEN_CMD} open\` again to renew it.`;
const MISSING_MSG =
  "The REA CLI (rea-agents) is not installed. Reinstall the plugin " +
  `(ob-plugin install ${PLUGIN_ID} — local checkout: ob-plugin install --path ~/plugins-create/${PLUGIN_ID}) ` +
  `so its setup runs, then check \`${OPEN_CMD} status\`.`;

// ---------------------------------------------------------------------------
// The five meta-tools (tiny schemas on purpose — this is the whole context cost)
// ---------------------------------------------------------------------------
const META_TOOLS = [
  {
    name: "rea_status",
    description:
      "REA (Reverse Engineer Anything) readiness: lock state, installed REA CLI version, procps prerequisite, " +
      "and which native providers (ghidra/hopper/ida) to verify before native analysis. Safe to call any time; " +
      "does not require an open session.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "rea_catalog",
    description:
      "Search REA's backend tool catalog (200+ analysis tools: native, JavaScript/Electron, .NET, Android, web, " +
      "firmware, pcap, evidence, reconstruction). Returns matching tool names with one-line summaries so you can " +
      "pick the right `rea` CLI command. Does not require an open session.",
    inputSchema: {
      type: "object",
      properties: { query: { type: "string", description: "Optional case-insensitive substring, e.g. 'android', 'decompile', 'pcap'." } },
      additionalProperties: false,
    },
  },
  {
    name: "rea_cli",
    description:
      "Run a REA CLI command (the same workflows as REA's MCP tools) and return its result. " +
      "Examples: args ['doctor','--json'], ['analyze-javascript-application','/abs/path','--json'], " +
      "['doctor','--provider','ghidra','--json']. Output beyond 256 KB is saved to a file whose path is returned — " +
      "read that file instead of re-running. Requires an open session (Reverse Engineer persona).",
    inputSchema: {
      type: "object",
      properties: {
        args: { type: "array", items: { type: "string" }, description: "Arguments after `rea`, without the binary name." },
        timeout_minutes: { type: "number", description: "Optional cap for this run (default 15, max 60). Native analysis can be slow." },
      },
      required: ["args"],
      additionalProperties: false,
    },
  },
  {
    name: "rea_mcp_call",
    description:
      "Call any of REA's 200+ backend MCP tools directly by name (full MCP parity without injecting the huge catalog): " +
      "e.g. tool 'binary_session' with {} for readiness, 'open_binary' {path}, 'procedure_pseudo_code', " +
      "'analyze_javascript_application', 'export_evidence_bundle'. Discover names with rea_catalog. " +
      "Huge results are saved to a file. Requires an open session (Reverse Engineer persona).",
    inputSchema: {
      type: "object",
      properties: {
        tool: { type: "string", description: "REA backend tool name, e.g. binary_session, open_binary, procedure_pseudo_code." },
        arguments: { type: "object", description: "Arguments object passed to the backend tool." },
      },
      required: ["tool"],
      additionalProperties: false,
    },
  },
  {
    name: "rea_ghidra",
    description:
      "Ghidra headless passthrough (analyzeHeadless with the plugin-managed Ghidra + JDK env) — for workflows the REA CLI does not expose, " +
      "above all re-reading an EXISTING Ghidra project without re-analysis: args [PROJECT_DIR, PROJECT_NAME, '-process', PROGRAM, " +
      "'-noanalysis', '-scriptPath', DIR, '-postScript', 'Script.java', ...script args]. " +
      "mode 'readiness' returns a ghidra-only verdict (no session needed); mode 'run' executes analyzeHeadless and requires an open session " +
      "(Reverse Engineer persona). One native analysis at a time; output beyond 256 KB is saved to a file.",
    inputSchema: {
      type: "object",
      properties: {
        mode: { type: "string", enum: ["readiness", "run"], description: "readiness: ghidra-only verdict, no lock. run: execute analyzeHeadless with args." },
        args: { type: "array", items: { type: "string" }, description: "For mode run: analyzeHeadless arguments (project dir, project name, -process/-noanalysis/-postScript...)." },
        timeout_minutes: { type: "number", description: "For mode run: cap for this run (default 15, max 60)." },
      },
      required: ["mode"],
      additionalProperties: false,
    },
  },
];

// ---------------------------------------------------------------------------
// rea binary + catalog (cached; throwaway child only on cache miss)
// ---------------------------------------------------------------------------
let reaVersionCache: string | null | undefined; // undefined = not probed yet
// Daemon-spawned gates may run with a minimal PATH that lacks /usr/local/bin,
// so fall back to the standard global-install locations before giving up.
const REA_FALLBACKS = ["/usr/local/bin/rea", "/usr/bin/rea", `${HOME}/.local/bin/rea`];
function reaPath(): string | null {
  const found = Bun.which("rea");
  if (found) return found;
  for (const p of REA_FALLBACKS) {
    try { if (require("node:fs").existsSync(p)) return p; } catch { /* ignore */ }
  }
  return null;
}
// The `rea` shim runs `#!/usr/bin/env node`; daemon-spawned gates may have a PATH
// that cannot resolve node, so prepend the shim's directory and standard bins.
function childEnv(): Record<string, string> {
  const p = reaPath();
  const dir = p ? p.slice(0, p.lastIndexOf("/")) : "";
  const extra = [dir, "/opt/rea-tools/bin", "/usr/local/bin", "/usr/bin", "/bin"].filter(Boolean).join(":");
  return { ...process.env, PATH: `${extra}:${process.env.PATH || ""}` };
}

// Native analysis engines: point REA at the Ghidra install the plugin setup lays
// down (/opt/ghidra/current) unless the user overrides it in settings, and pick a
// JDK 21+ home for it. REA's doctor sees these through every gate-spawned child.
function nativeEnv(): Record<string, string> {
  const e: Record<string, string> = {};
  const ghidra = String(settings().ghidra_install_dir ?? "").trim() ||
    (existsSync("/opt/ghidra/current") ? "/opt/ghidra/current" : "");
  if (ghidra) e.GHIDRA_INSTALL_DIR = ghidra;
  if (existsSync("/opt/rea-tools/wabt/bin") && !process.env.REA_WABT_BIN_DIRECTORY) {
    e.REA_WABT_BIN_DIRECTORY = "/opt/rea-tools/wabt/bin";
  }
  if (e.GHIDRA_INSTALL_DIR && !process.env.JAVA_HOME) {
    if (existsSync("/opt/java/current")) {
      e.JAVA_HOME = "/opt/java/current";
    } else {
      try {
        const pick = readdirSync("/usr/lib/jvm")
          .filter((d) => /java-2[1-9]-openjdk/.test(d))
          .sort()
          .pop();
        if (pick) e.JAVA_HOME = `/usr/lib/jvm/${pick}`;
      } catch { /* no jvm dir */ }
    }
  }
  return e;
}
// ---------------------------------------------------------------------------
// Ghidra headless (rea_ghidra): resolution, ghidra-only readiness, single-flight.
// REA 6.7.0 exposes no `ghidra` CLI subcommand, so existing-project re-reads
// (-process -noanalysis -postScript) go through analyzeHeadless directly, with the
// same plugin-managed env every gate child sees. Degradation: absent Ghidra/JDK is
// a clean verdict, never a crash.
// ---------------------------------------------------------------------------
function ghidraDir(): string {
  const s = String(settings().ghidra_install_dir ?? "").trim();
  if (s) return s; // configured (even if missing — readiness surfaces the gap)
  if (existsSync("/opt/ghidra/current/support/analyzeHeadless")) return "/opt/ghidra/current";
  return "";
}
function javaHomeDir(): string {
  const envHome = String(process.env.JAVA_HOME ?? "").trim();
  if (envHome && existsSync(envHome)) return envHome;
  if (existsSync("/opt/java/current")) return "/opt/java/current";
  try {
    const pick = readdirSync("/usr/lib/jvm")
      .filter((d) => /java-2[1-9]-openjdk/.test(d))
      .sort()
      .pop();
    if (pick) return `/usr/lib/jvm/${pick}`;
  } catch { /* no jvm dir */ }
  return "";
}
function javaOnPath(): boolean { return !!Bun.which("java"); }
function ghidraReadiness() {
  const dir = ghidraDir();
  const headless = dir ? `${dir}/support/analyzeHeadless` : "";
  const home = javaHomeDir();
  const ready = !!dir && existsSync(headless) && ((!!home && existsSync(`${home}/bin/java`)) || javaOnPath());
  return {
    ready,
    ghidra_dir: dir || null,
    analyzeHeadless: dir && existsSync(headless) ? headless : null,
    java_home: home || null,
    java_on_path: javaOnPath(),
  };
}
function ghidraRunEnv(): Record<string, string> {
  const env: Record<string, string> = { ...childEnv(), ...extraEnv() };
  const home = javaHomeDir();
  if (home) { env.JAVA_HOME = home; env.PATH = `${home}/bin:${env.PATH || ""}`; }
  return env;
}
const GHIDRA_LOCK = `${STATE_DIR}/ghidra.lock`;
function pidAlive(pid: number): boolean {
  try { process.kill(pid, 0); return true; } catch (e: any) { return e?.code !== "ESRCH"; }
}
function acquireGhidraLock(): { ok: boolean; holder: string } {
  mkdirSync(STATE_DIR, { recursive: true });
  try {
    const { pid, at } = JSON.parse(readFileSync(GHIDRA_LOCK, "utf8"));
    const stale = typeof pid !== "number" || !pidAlive(pid) || Date.now() - (at ?? 0) > 65 * 60_000;
    if (!stale) return { ok: false, holder: `pid ${pid} since ${new Date(at ?? 0).toISOString()}` };
    try { unlinkSync(GHIDRA_LOCK); } catch { /* raced */ }
  } catch { /* no lock held */ }
  try {
    const fd = openSync(GHIDRA_LOCK, "wx");
    writeSync(fd, JSON.stringify({ pid: process.pid, at: Date.now() }));
    closeSync(fd);
    return { ok: true, holder: "" };
  } catch {
    return { ok: false, holder: "another ghidra run just started" };
  }
}
function releaseGhidraLock() { try { unlinkSync(GHIDRA_LOCK); } catch { /* gone */ } }

function reaVersion(): string | null {
  if (reaVersionCache !== undefined) return reaVersionCache;
  const p = reaPath();
  if (!p) { reaVersionCache = null; return null; }
  try {
    const r = Bun.spawnSync([p, "--version"]);
    const v = r.stdout.toString().trim();
    reaVersionCache = v || null;
  } catch { reaVersionCache = null; }
  return reaVersionCache;
}

interface CatalogEntry { name: string; description: string }

function readLines(stream: ReadableStream<Uint8Array>, onLine: (line: string) => void) {
  const dec = new TextDecoder();
  let buf = "";
  const reader = stream.getReader();
  (async () => {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let idx: number;
      while ((idx = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, idx).replace(/\r$/, "");
        buf = buf.slice(idx + 1);
        if (line) onLine(line);
      }
    }
  })().catch((e) => log(`catalog reader ended: ${e}`));
}

/** One-shot `rea mcp` child: fetch tools/list for the catalog cache, then die. */
async function fetchCatalog(): Promise<CatalogEntry[]> {
  const p = reaPath();
  const args = p ? [p, "mcp"] : ["npx", "-y", `rea-agents@${PIN_FALLBACK}`, "mcp"];
  let child: ReturnType<typeof Bun.spawn>;
  try {
    child = Bun.spawn(args, { stdin: "pipe", stdout: "pipe", stderr: "pipe", env: childEnv() });
  } catch (e) { log(`catalog spawn failed: ${e}`); return []; }
  return await new Promise<CatalogEntry[]>((resolve) => {
    const timer = setTimeout(() => { try { child.kill(); } catch { /* gone */ } resolve([]); }, 60_000);
    readLines(child.stdout as ReadableStream<Uint8Array>, (line) => {
      let m: Msg;
      try { m = JSON.parse(line); } catch { return; }
      if (m.id !== 1) return;
      const tools = (m.result as any)?.tools ?? [];
      const entries: CatalogEntry[] = tools
        .filter((t: any) => typeof t?.name === "string")
        .map((t: any) => ({ name: t.name, description: String(t?.description ?? "").slice(0, 300) }));
      clearTimeout(timer);
      try { child.kill(); } catch { /* gone */ }
      resolve(entries);
    });
    try {
      child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }) + "\n");
    } catch { clearTimeout(timer); resolve([]); }
  });
}

let catalogMemo: CatalogEntry[] | null | undefined;
async function catalog(): Promise<CatalogEntry[]> {
  if (catalogMemo !== undefined) return catalogMemo;
  try {
    const c = JSON.parse(readFileSync(CATALOG_FILE, "utf8"));
    if (Array.isArray(c.tools) && c.tools.length && c.rea_version === reaVersion()) {
      catalogMemo = c.tools;
      return catalogMemo;
    }
  } catch { /* no cache yet */ }
  const fresh = await fetchCatalog();
  if (fresh.length) {
    catalogMemo = fresh;
    try {
      mkdirSync(STATE_DIR, { recursive: true });
      writeFileSync(CATALOG_FILE, JSON.stringify({ rea_version: reaVersion(), tools: fresh }));
    } catch { /* cache write is best-effort */ }
  }
  return catalogMemo ?? [];
}

// ---------------------------------------------------------------------------
// Bounded runner (rea_cli AND rea_ghidra): bounded inline output, full copy to file.
// ---------------------------------------------------------------------------
interface CliOutcome { exit_code: number | null; timed_out: boolean; duration_ms: number; output_path: string; truncated: boolean; stdout: string; stderr: string }

async function runCapture(bin: string, args: string[], env: Record<string, string>, explicitTimeout: unknown, prefix: string): Promise<CliOutcome> {
  const cap = timeoutMinutes(explicitTimeout);
  const t0 = Date.now();
  mkdirSync(STATE_DIR, { recursive: true });
  const outPath = `${STATE_DIR}/${prefix}-${Date.now()}.json`;
  const proc = Bun.spawn([bin, ...args], {
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
    env,
  });
  let out = "";
  let err = "";
  let over = false;
  const readCap = (stream: ReadableStream<Uint8Array> | null, sink: (s: string) => void) => {
    if (!stream) return;
    const dec = new TextDecoder();
    let total = 0;
    const reader = stream.getReader();
    (async () => {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value?.byteLength ?? 0;
        if (total > RAM_CAP) { over = true; try { proc.kill(); } catch { /* gone */ } break; }
        const chunk = dec.decode(value, { stream: true });
        sink(chunk);
      }
    })().catch(() => { /* stream ended */ });
  };
  readCap(proc.stdout as ReadableStream<Uint8Array>, (s) => { out += s; });
  readCap(proc.stderr as ReadableStream<Uint8Array>, (s) => { err += s; });
  const timer = setTimeout(() => { try { proc.kill(); } catch { /* gone */ } }, cap * 60_000);
  const exit_code = await proc.exited;
  clearTimeout(timer);
  const duration_ms = Date.now() - t0;
  const timed_out = exit_code === null || exit_code === 143; // SIGTERM
  const stdout = out.length > STDOUT_CAP ? out.slice(0, STDOUT_CAP) : out;
  const stderr = err.length > STDERR_CAP ? err.slice(0, STDERR_CAP) : err;
  const truncated = out.length > STDOUT_CAP || err.length > STDERR_CAP || over;
  try { writeFileSync(outPath, JSON.stringify({ args, exit_code, timed_out, duration_ms, stdout: out, stderr: err })); } catch { /* best-effort */ }
  return { exit_code, timed_out, duration_ms, output_path: outPath, truncated, stdout, stderr };
}

async function runRea(args: string[], explicitTimeout?: unknown): Promise<CliOutcome> {
  const p = reaPath();
  if (!p) throw new Error("missing");
  return runCapture(p, args, { ...childEnv(), ...nativeEnv(), ...extraEnv() }, explicitTimeout, "cli");
}

async function runGhidra(args: string[], explicitTimeout?: unknown): Promise<CliOutcome> {
  const headless = `${ghidraDir()}/support/analyzeHeadless`;
  if (!existsSync(headless)) throw new Error("ghidra missing");
  return runCapture(headless, args, ghidraRunEnv(), explicitTimeout, "ghidra");
}

function pruneOldCliOutputs(pattern: string) {
  try {
    const files = Array.from(new Bun.Glob(pattern).scanSync({ cwd: STATE_DIR }));
    if (files.length <= 20) return;
    for (const f of files.slice(0, files.length - 20)) {
      try { require("node:fs").unlinkSync(`${STATE_DIR}/${f}`); } catch { /* raced */ }
    }
  } catch { /* no state dir yet */ }
}

// ---------------------------------------------------------------------------
// Backend MCP child (`rea mcp`) — full REA tool parity through rea_mcp_call.
// Lazily spawned on first unlocked call, idle-reaped after 15 quiet minutes.
// ---------------------------------------------------------------------------
let mcpChild: ReturnType<typeof Bun.spawn> | null = null;
let mcpReady: Promise<boolean> | null = null;
let mcpReaper: ReturnType<typeof setTimeout> | null = null;
const MCP_IDLE_REAP_MS = 15 * 60 * 1000;
const mcpPending = new Map<JsonRpcId, { clientId: JsonRpcId; tool: string }>(); // backend req id -> client routing
const mcpTaps = new Map<JsonRpcId, (payload: any) => void>(); // internal probes

function armMcpReaper() {
  if (mcpReaper) clearTimeout(mcpReaper);
  mcpReaper = setTimeout(() => killMcpChild("idle 15min"), MCP_IDLE_REAP_MS);
  mcpReaper.unref?.();
}
function killMcpChild(why: string) {
  if (mcpChild) { try { mcpChild.kill(); } catch { /* already gone */ } }
  mcpChild = null; mcpReady = null; mcpPending.clear(); mcpTaps.clear();
  if (why) log(`mcp backend stopped (${why})`);
}

async function ensureMcp(): Promise<boolean> {
  if (mcpChild && mcpReady) return await mcpReady;
  const p = reaPath();
  if (!p) return false;
  try {
    mcpChild = Bun.spawn([p, "mcp"], { stdin: "pipe", stdout: "pipe", stderr: "pipe", env: { ...childEnv(), ...nativeEnv(), ...extraEnv() } });
  } catch (e) {
    log(`mcp spawn failed: ${e}`);
    mcpChild = null; mcpReady = null;
    return false;
  }
  log(`mcp backend spawned: ${p} mcp`);
  const c = mcpChild;
  readLines(c.stdout as ReadableStream<Uint8Array>, (line) => {
    let m: Msg;
    try { m = JSON.parse(line); } catch { return; }
    if (m.id !== undefined && mcpTaps.has(m.id as JsonRpcId)) {
      mcpTaps.get(m.id as JsonRpcId)!(m.result ?? m.error);
      return;
    }
    if (m.id !== undefined && mcpPending.has(m.id as JsonRpcId)) {
      const route = mcpPending.get(m.id as JsonRpcId)!;
      mcpPending.delete(m.id as JsonRpcId);
      if (m.error !== undefined) {
        send({ jsonrpc: "2.0", id: route.clientId, error: m.error });
      } else {
        send({ jsonrpc: "2.0", id: route.clientId, ...boundResult(route.tool, m.result) });
      }
    } else if (m.method && m.id === undefined) {
      send(m as object); // backend -> client notification passthrough
    }
  });
  readLines(c.stderr as ReadableStream<Uint8Array>, (line) => log(`[rea-mcp] ${line.slice(0, 300)}`));
  c.exited.then(() => { if (mcpChild === c) killMcpChild("backend exit"); });

  mcpReady = (async () => {
    try {
      const probe = `gate-init-${Date.now()}`;
      const ok = await new Promise<boolean>((resolve) => {
        const timer = setTimeout(() => { mcpTaps.delete(probe); resolve(false); }, 45_000);
        mcpTaps.set(probe as JsonRpcId, (payload) => { clearTimeout(timer); resolve(true); });
        try {
          c.stdin!.write(JSON.stringify({ jsonrpc: "2.0", id: probe, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "rea-gate", version: "0.1.0" } } }) + "\n");
        } catch { clearTimeout(timer); mcpTaps.delete(probe); resolve(false); }
      });
      if (!ok) { return false; }
      c.stdin!.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
      return c.exitCode === null;
    } catch { return false; }
  })();
  return await mcpReady;
}

async function forwardToMcp(clientId: JsonRpcId, tool: string, args: object): Promise<boolean> {
  const ok = await ensureMcp();
  if (!ok || !mcpChild) return false;
  const childId = `c-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  mcpPending.set(childId as JsonRpcId, { clientId, tool });
  try {
    mcpChild.stdin!.write(JSON.stringify({ jsonrpc: "2.0", id: childId, method: "tools/call", params: { name: tool, arguments: args } }) + "\n");
  } catch (e) {
    mcpPending.delete(childId as JsonRpcId);
    log(`mcp forward write failed: ${e}`);
    return false;
  }
  armMcpReaper();
  return true;
}

/** Bound a backend result: huge Evidence payloads go to disk, a preview stays inline. */
function boundResult(tool: string, result: any): { result: any } {
  const raw = JSON.stringify(result);
  if (!raw || raw.length <= STDOUT_CAP) return { result };
  const path = `${STATE_DIR}/mcp-${Date.now()}.json`;
  try { writeFileSync(path, raw); } catch { /* best-effort */ }
  return {
    result: {
      isError: false,
      content: [{
        type: "text",
        text: `TOOL RESULT TRUNCATED (${tool}: full ${raw.length}-char payload saved at ${path}).\n--- preview ---\n${raw.slice(0, 4096)}`,
      }],
    },
  };
}

// ---------------------------------------------------------------------------
// Tool handlers
// ---------------------------------------------------------------------------
async function handleStatus(): Promise<object> {
  const s = readSession();
  const open = isOpen();
  const minsLeft = open && s ? Math.max(0, Math.round((s.expires - Date.now()) / 60_000)) : 0;
  const ver = reaVersion();
  const psOk = !!Bun.which("ps") || existsSync("/usr/bin/ps");
  const ghidraDir = String(settings().ghidra_install_dir ?? "").trim() ||
    (existsSync("/opt/ghidra/current") ? "/opt/ghidra/current" : "");
  const native = ghidraDir ? `READY (ghidra at ${ghidraDir})` : "NOT INSTALLED (static analyses still work)";
  return {
    content: [{
      type: "text",
      text: JSON.stringify({
        gate: open ? `OPEN (${minsLeft} min left)` : s ? "EXPIRED (open again)" : "LOCKED",
        rea_cli: ver ?? "NOT INSTALLED",
        procps_ps: psOk ? "ok" : "MISSING (Linux prerequisite: apt-get install procps)",
        native_engine: native,
        rea_version_pin: String(settings().rea_version ?? PIN_FALLBACK),
        timeout_minutes_default: timeoutMinutes(),
        hint: ver
          ? "Use rea_catalog to discover commands, rea_cli to run them (session required), rea_mcp_call for backend tools. Native engine verdict above is authoritative. NEVER run `rea doctor` in a bare shell (env not injected) and NEVER judge native readiness from audit-wide doctor healthy:false — optional engines (hopper/ida/jadx/kuna) are expected missing. Scoped check only: rea_cli ['doctor','--provider','ghidra','--json']. Ghidra headless re-reads of an existing project (-process -noanalysis -postScript) go through rea_ghidra (the REA CLI has no ghidra subcommand); rea_ghidra mode 'readiness' is the ghidra-only verdict scripts can rely on."
          : "Reinstall the plugin so its setup installs rea-agents, then re-check.",
      }, null, 2),
    }],
  };
}

async function handleCatalog(params: any): Promise<object> {
  const q = String(params?.query ?? "").toLowerCase().trim();
  const entries = await catalog();
  if (!entries.length) {
    return { content: [{ type: "text", text: "Catalog unavailable (REA CLI missing or fetch failed). Reinstall the plugin, or browse https://rea.tools guides." }] };
  }
  const hits = q ? entries.filter((e) => e.name.toLowerCase().includes(q) || e.description.toLowerCase().includes(q)) : entries;
  const shown = hits.slice(0, 50);
  const lines = shown.map((e) => `- ${e.name}: ${e.description.split("\n")[0]}`);
  return {
    content: [{
      type: "text",
      text: `${hits.length} match(es)${hits.length > 50 ? " (first 50 shown)" : ""} of ${entries.length} tools:\n${lines.join("\n")}` +
        `\nRun a command with rea_cli args ["<command>", ...] — most REA commands map 1:1 from these tool names.`,
    }],
  };
}

function validateArgs(args: unknown): string[] | null {
  if (!Array.isArray(args) || args.length === 0 || args.length > 32) return null;
  const out: string[] = [];
  for (const a of args) {
    if (typeof a !== "string" || a.length === 0 || a.length > 300) return null;
    out.push(a);
  }
  return out;
}

// analyzeHeadless lines carry project dir + name + flags + script args: a wider cap than rea_cli.
function validateGhidraArgs(args: unknown): string[] | null {
  if (!Array.isArray(args) || args.length === 0 || args.length > 48) return null;
  const out: string[] = [];
  for (const a of args) {
    if (typeof a !== "string" || a.length === 0 || a.length > 500) return null;
    out.push(a);
  }
  return out;
}

const GHIDRA_POINTER =
  "REA 6.7.0 has no `ghidra` subcommand (that path existed only in an older log). " +
  "For Ghidra headless re-reads of an existing project use the rea_ghidra tool " +
  "(mode 'run' with args [PROJECT_DIR, PROJECT_NAME, '-process', PROGRAM, '-noanalysis', '-scriptPath', DIR, '-postScript', 'Script.java', ...]), " +
  "or the ob-plugin-reverse-engineer-anything-ghidra CLI in a shell.";

// ---------------------------------------------------------------------------
// Client loop
// ---------------------------------------------------------------------------
const rl = createInterface({ input: process.stdin });
rl.on("line", (line) => {
  let m: Msg;
  try { m = JSON.parse(line); } catch { return; }
  if (!m.method) return;
  const id = m.id ?? null;
  const isNotification = m.id === undefined;
  const { method, params } = m;

  if (method === "initialize") {
    result(id, {
      protocolVersion: params?.protocolVersion || "2025-03-26",
      capabilities: { tools: { listChanged: false } },
      serverInfo: { name: "rea-gate", version: "0.3.0" },
      instructions:
        "REA (Reverse Engineer Anything) behind the reverse-engineer-anything gate. REA's full catalog is 200+ tools, " +
        "far too large to inject, so this server exposes five meta-tools: rea_status (readiness), rea_catalog " +
        "(discover backend tools), rea_cli (run any REA CLI command), rea_mcp_call (call a backend MCP tool by name), " +
        "rea_ghidra (gated Ghidra headless passthrough: readiness verdict or run analyzeHeadless on an existing project). " +
        "Locked by default: rea_cli, rea_mcp_call and rea_ghidra run unlock only for the " +
        "Reverse Engineer persona via ob-plugin-reverse-engineer-anything-mcp open, and re-locks on close or TTL expiry. " +
        "One native analysis at a time. Analyze only software you own or are authorized to examine.",
    });
    return;
  }
  if (method === "ping") { if (!isNotification) result(id, {}); return; }

  if (method === "tools/list") {
    if (!LIST_WHILE_LOCKED && !isOpen()) { result(id, { tools: [] }); return; }
    result(id, { tools: META_TOOLS });
    return;
  }

  if (method === "tools/call") {
    const name = String(params?.name ?? "");
    if (name === "rea_status") {
      handleStatus().then((r) => result(id, r)).catch((e) => errResult(id, `rea_status failed: ${e}`));
      return;
    }
    if (name === "rea_catalog") {
      handleCatalog(params?.arguments).then((r) => result(id, r)).catch((e) => errResult(id, `rea_catalog failed: ${e}`));
      return;
    }
    if (name === "rea_cli") {
      if (!isOpen()) {
        const hadSession = !!readSession();
        log(`refused rea_cli (${hadSession ? "expired" : "locked"})`);
        errResult(id, hadSession ? EXPIRED_MSG : LOCK_MSG);
        return;
      }
      const args = validateArgs(params?.arguments?.args);
      if (!args) { errResult(id, "rea_cli: args must be a non-empty array of short strings (max 32 items)."); return; }
      if (args[0] === "ghidra") { log(`refused rea_cli ghidra (pointer)`); errResult(id, GHIDRA_POINTER); return; }
      if (!reaPath()) { errResult(id, MISSING_MSG); return; }
      log(`rea_cli: ${args.join(" ")}`);
      runRea(args, params?.arguments?.timeout_minutes)
        .then((o) => {
          pruneOldCliOutputs("cli-*.json");
          const text =
            `exit_code=${o.exit_code}${o.timed_out ? " (TIMED OUT — partial output)" : ""} duration_ms=${o.duration_ms}\n` +
            (o.truncated ? `OUTPUT TRUNCATED — full copy at ${o.output_path}\n` : `full copy at ${o.output_path}\n`) +
            `\n--- stdout ---\n${o.stdout || "(empty)"}\n` +
            (o.stderr ? `\n--- stderr ---\n${o.stderr}` : "");
          result(id, { content: [{ type: "text", text }] });
        })
        .catch(() => errResult(id, MISSING_MSG));
      return;
    }
    if (name === "rea_mcp_call") {
      if (!isOpen()) {
        const hadSession = !!readSession();
        log(`refused rea_mcp_call (${hadSession ? "expired" : "locked"})`);
        errResult(id, hadSession ? EXPIRED_MSG : LOCK_MSG);
        return;
      }
      const tool = params?.arguments?.tool;
      if (typeof tool !== "string" || !/^[a-zA-Z_][a-zA-Z0-9_]{0,79}$/.test(tool)) {
        errResult(id, "rea_mcp_call: 'tool' must be a REA backend tool name (discover them with rea_catalog).");
        return;
      }
      const args = params?.arguments?.arguments ?? {};
      if (typeof args !== "object" || args === null || Array.isArray(args)) {
        errResult(id, "rea_mcp_call: 'arguments' must be an object.");
        return;
      }
      log(`rea_mcp_call: ${tool}`);
      forwardToMcp(id, tool, args).then((sent) => {
        if (!sent) errResult(id, "The REA MCP backend could not be started. Check `ob-plugin-reverse-engineer-anything-mcp status` (gate log) and retry.");
      });
      return;
    }
    if (name === "rea_ghidra") {
      const mode = String(params?.arguments?.mode ?? "");
      if (mode === "readiness") {
        const r = ghidraReadiness();
        result(id, { content: [{ type: "text", text: JSON.stringify({
          ready: r.ready,
          ghidra_dir: r.ghidra_dir,
          analyzeHeadless: r.analyzeHeadless,
          java_home: r.java_home,
          java_on_path: r.java_on_path,
          remediation: r.ready ? null :
            "Set the plugin setting ghidra_install_dir (Plugins tab → reverse-engineer-anything → Settings) to a Ghidra install containing support/analyzeHeadless, and provide a JDK 21+ (JAVA_HOME or java on PATH). The plugin setup normally lays both down at /opt/ghidra and /opt/java.",
        }, null, 2) }] });
        return;
      }
      if (mode === "run") {
        if (!isOpen()) {
          const hadSession = !!readSession();
          log(`refused rea_ghidra run (${hadSession ? "expired" : "locked"})`);
          errResult(id, hadSession ? EXPIRED_MSG : LOCK_MSG);
          return;
        }
        const args = validateGhidraArgs(params?.arguments?.args);
        if (!args) { errResult(id, "rea_ghidra run: args must be a non-empty array of short strings (max 48 items), starting with the project directory and project name."); return; }
        if (!ghidraReadiness().ready) {
          errResult(id, "Ghidra is not ready (analyzeHeadless or JDK missing). Call rea_ghidra {mode:'readiness'} for the exact gap and remediation.");
          return;
        }
        const lock = acquireGhidraLock();
        if (!lock.ok) {
          errResult(id, `Another Ghidra analysis is already running (${lock.holder}). One native analysis at a time — wait for it to finish.`);
          return;
        }
        log(`rea_ghidra run: ${args.join(" ")}`);
        runGhidra(args, params?.arguments?.timeout_minutes)
          .then((o) => {
            releaseGhidraLock();
            pruneOldCliOutputs("ghidra-*.json");
            const text =
              `exit_code=${o.exit_code}${o.timed_out ? " (TIMED OUT — partial output)" : ""} duration_ms=${o.duration_ms}\n` +
              (o.truncated ? `OUTPUT TRUNCATED — full copy at ${o.output_path}\n` : `full copy at ${o.output_path}\n`) +
              `\n--- stdout ---\n${o.stdout || "(empty)"}\n` +
              (o.stderr ? `\n--- stderr ---\n${o.stderr}` : "");
            result(id, { content: [{ type: "text", text }] });
          })
          .catch((e) => {
            releaseGhidraLock();
            errResult(id, `rea_ghidra failed: ${e}. Call rea_ghidra {mode:'readiness'} to check the install.`);
          });
        return;
      }
      errResult(id, "rea_ghidra: mode must be 'readiness' or 'run'.");
      return;
    }
    errResult(id, `Unknown tool ${name}. This gate exposes only rea_status, rea_catalog, rea_cli, rea_mcp_call, rea_ghidra.`);
    return;
  }

  if (method.startsWith("notifications/")) return; // nothing to forward; CLI runs are self-contained
  if (isNotification) return;
  protoError(id, `rea-gate: ${method} is not supported; use tools rea_status, rea_catalog, rea_cli, rea_ghidra.`);
});

rl.on("close", () => { killMcpChild("client gone"); process.exit(0); });
process.on("SIGTERM", () => { killMcpChild("sigterm"); process.exit(0); });
process.on("SIGINT", () => { killMcpChild("sigint"); process.exit(0); });

log(`gate started (pid ${process.pid})`);
