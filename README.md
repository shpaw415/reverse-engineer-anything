# REA — Reverse Engineer Anything (open-bot plugin)

Investigate how software works — app features, JavaScript/Electron apps, .NET assemblies,
Android APKs, firmware, native binaries — with evidence, then rebuild what you need.
Powered by [REA (morluto/rea)](https://github.com/morluto/rea), MIT.

## Why a gate

REA's MCP server advertises 200+ tools (~2.6 MB of JSON). Injecting that into every
thread would waste enormous context. This plugin registers a **gate** instead:

- exactly **five tiny meta-tools** (`rea_status`, `rea_catalog`, `rea_cli`, `rea_mcp_call` — the last one reaches all 207 backend REA MCP tools by name — and `rea_ghidra`) — a few
  hundred tokens of context, in every thread;
- the full REA power stays reachable through `rea_cli` (REA's CLI runs the same
  workflows as its MCP tools) and `rea_catalog` (discover the backend tools);
- **Ghidra headless passthrough**: REA 6.7.0 has no `ghidra` CLI subcommand, so
  `rea_ghidra` (MCP) and the `ob-plugin-reverse-engineer-anything-ghidra` shell CLI
  re-read an **existing** Ghidra project without re-analysis
  (`-process <prog> -noanalysis -scriptPath <dir> -postScript <Script.java> ...`)
  with the plugin-managed Ghidra + JDK env, under the same session lock and a
  one-native-analysis-at-a-time lock shared by both entry points. The shell CLI's
  `readiness` subcommand prints a ghidra-only verdict and exits 0/1 (scripts can
  test the code — `rea doctor` exits 1 whenever any optional engine is missing,
  which is the normal state here);
- **locked by default**: analysis calls are refused outside an open session, which
  only the **Reverse Engineer** persona opens (`ob-plugin-reverse-engineer-anything-mcp
  open|close|status`).

Other plugins or personas that want REA can call the same meta-tools once a session
is open — or be added to the roster by giving them the skill.

## What you can analyze (via REA)

Static JavaScript/Electron apps and .NET assemblies, websites and web bundles,
model artifacts (GGUF/safetensors), Go/Rust binaries, GPU code objects, Godot PCK,
IL2CPP metadata — no extra engines needed. Native pseudocode/assembly needs Ghidra,
Hopper or IDA installed (user-provided, licensed separately). Android APKs need
headless JADX + JDK; firmware needs Binwalk/Unblob; pcap needs TShark. Check
readiness any time with `rea_cli ["doctor","--json"]`.

## Install

```sh
ob-plugin validate ~/plugins-create/reverse-engineer-anything
ob-plugin install --path ~/plugins-create/reverse-engineer-anything   # local dev
```

Setup is idempotent: it installs `procps` (REA Linux prerequisite), the pinned
`rea-agents` npm package (needs Node.js 22.19+/24.11+/26+ with npm), the official
REA skill + references (readable on demand from `/usr/local/bin/ob-plugin-reverse-engineer-anything-rea-*.md`),
Ghidra 12.1.4 (`/opt/ghidra/current`) and a Temurin JDK 21 (`/opt/java/current`) —
native decompilation works out of the box. After a fresh install, threads see the `rea_*` tools once the
desktop restarts; until then, `ob-plugin-reverse-engineer-anything-mcp gate` speaks
MCP JSON-RPC through the same lock.

## Raw REA MCP server (manual opt-in)

REA ships exactly one MCP server (`rea mcp`). The plugin registers it behind the
gate (as `rea`); it does **not** register the raw server because its 207-tool
catalog (~2.6 MB) would land in every thread. Power users can add it themselves
in the Config page MCP settings, in a dedicated thread only:

```sh
rea mcp   # stdio MCP server, full catalog
```

## Responsible use

REA is for lawful research, education, interoperability, software preservation, and
analysis of software you own or are authorized to examine. This plugin's skill and
persona instruct the agent to refuse unauthorized targets. REA itself is © its
authors, MIT-licensed; Hopper, Ghidra, IDA and JEB remain subject to their own
licenses — this plugin installs none of them.

## License

MIT — see LICENSE. REA and its third-party dependencies keep their own notices.
