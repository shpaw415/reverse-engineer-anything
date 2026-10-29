#!/usr/bin/env bun
// reverse-engineer-anything — Ghidra headless companion CLI.
//
//   ob-plugin-reverse-engineer-anything-ghidra readiness
//     Prints a ghidra-only verdict as JSON. Exit 0 = ready, 1 = not ready.
//     Shell scripts can test the exit code (rea doctor exits 1 whenever ANY
//     optional engine is missing, which is the normal state here).
//
//   ob-plugin-reverse-engineer-anything-ghidra run [--timeout MIN] -- <analyzeHeadless args...>
//     Runs analyzeHeadless with the plugin-managed env (Ghidra dir + JDK 21+),
//     inheriting stdio, e.g. an existing-project re-read without re-analysis:
//       run -- /path/ghidra-proj MyProj -process D2Game.dll -noanalysis \
//            -scriptPath /path/scripts -postScript DisasmOne.java 6fcb8200 /tmp/out.asm
//     Exit codes: 0 ok · 1 ghidra/JDK not ready · 2 another Ghidra run holds the
//     lock · 3 usage · 124 timed out · otherwise analyzeHeadless's own code.
//
// The same lock file gates the rea_ghidra MCP tool: one native analysis at a time
// across both entry points. No secrets involved. Companion-optional by design:
// nothing here requires the rea CLI to exist.
import { closeSync, existsSync, mkdirSync, openSync, readdirSync, readFileSync, unlinkSync, writeSync } from "node:fs";

const PLUGIN_ID = "reverse-engineer-anything";
const HOME = process.env.HOME || "/home/agent";
const STATE_DIR = `${HOME}/.open-bot/plugin-${PLUGIN_ID}`;
const LOCK_FILE = `${STATE_DIR}/ghidra.lock`;
const CONFIG_FILE = `${HOME}/.config/open-bot/plugin-${PLUGIN_ID}.json`;

function settings(): Record<string, string> {
  try { return JSON.parse(readFileSync(CONFIG_FILE, "utf8")).settings || {}; } catch { return {}; }
}
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
function readiness() {
  const dir = ghidraDir();
  const headless = dir ? `${dir}/support/analyzeHeadless` : "";
  const home = javaHomeDir();
  const javaOnPath = !!Bun.which("java");
  const ready = !!dir && existsSync(headless) && ((!!home && existsSync(`${home}/bin/java`)) || javaOnPath);
  return {
    ready,
    ghidra_dir: dir || null,
    analyzeHeadless: dir && existsSync(headless) ? headless : null,
    java_home: home || null,
    java_on_path: javaOnPath,
    remediation: ready ? null :
      "Set the plugin setting ghidra_install_dir to a Ghidra install containing support/analyzeHeadless, and provide a JDK 21+ (JAVA_HOME or java on PATH). The plugin setup normally lays both down at /opt/ghidra and /opt/java.",
  };
}
function pidAlive(pid: number): boolean {
  try { process.kill(pid, 0); return true; } catch (e: any) { return e?.code !== "ESRCH"; }
}
function acquireLock(): { ok: boolean; holder: string } {
  mkdirSync(STATE_DIR, { recursive: true });
  try {
    const { pid, at } = JSON.parse(readFileSync(LOCK_FILE, "utf8"));
    const stale = typeof pid !== "number" || !pidAlive(pid) || Date.now() - (at ?? 0) > 65 * 60_000;
    if (!stale) return { ok: false, holder: `pid ${pid} since ${new Date(at ?? 0).toISOString()}` };
    try { unlinkSync(LOCK_FILE); } catch { /* raced */ }
  } catch { /* no lock held */ }
  try {
    const fd = openSync(LOCK_FILE, "wx");
    writeSync(fd, JSON.stringify({ pid: process.pid, at: Date.now() }));
    closeSync(fd);
    return { ok: true, holder: "" };
  } catch {
    return { ok: false, holder: "another ghidra run just started" };
  }
}
function releaseLock() { try { unlinkSync(LOCK_FILE); } catch { /* gone */ } }

const USAGE =
  "usage: ob-plugin-reverse-engineer-anything-ghidra readiness\n" +
  "       ob-plugin-reverse-engineer-anything-ghidra run [--timeout MIN] -- <analyzeHeadless args...>";

const [, , cmd] = process.argv;

if (cmd === "readiness") {
  const r = readiness();
  console.log(JSON.stringify(r, null, 2));
  process.exit(r.ready ? 0 : 1);
}

if (cmd === "run") {
  const rest = process.argv.slice(3);
  const sep = rest.indexOf("--");
  if (sep < 0) { console.error(USAGE); process.exit(3); }
  let timeoutMin = 15;
  const flags = rest.slice(0, sep);
  for (let i = 0; i < flags.length; i++) {
    if (flags[i] === "--timeout") {
      const n = Number(flags[i + 1]);
      if (!Number.isFinite(n) || n <= 0) { console.error("run: --timeout expects minutes > 0"); process.exit(3); }
      timeoutMin = Math.min(60, n);
      i++;
    } else { console.error(USAGE); process.exit(3); }
  }
  const args = rest.slice(sep + 1).filter((a) => a.length > 0);
  if (!args.length) { console.error(USAGE); process.exit(3); }
  const r = readiness();
  if (!r.ready || !r.analyzeHeadless) {
    console.error(JSON.stringify(r, null, 2));
    process.exit(1);
  }
  const lock = acquireLock();
  if (!lock.ok) {
    console.error(`Another Ghidra analysis is already running (${lock.holder}). One native analysis at a time.`);
    process.exit(2);
  }
  const env: Record<string, string> = { ...process.env };
  if (r.java_home) {
    env.JAVA_HOME = r.java_home;
    env.PATH = `${r.java_home}/bin:${env.PATH || ""}`;
  }
  let timedOut = false;
  let child: ReturnType<typeof Bun.spawn> | null = null;
  const timer = setTimeout(() => { timedOut = true; try { child?.kill(); } catch { /* gone */ } }, timeoutMin * 60_000);
  child = Bun.spawn([r.analyzeHeadless, ...args], { stdin: "inherit", stdout: "inherit", stderr: "inherit", env });
  const code = await child.exited;
  clearTimeout(timer);
  releaseLock();
  process.exit(timedOut ? 124 : (code ?? 1));
}

console.error(USAGE);
process.exit(3);
