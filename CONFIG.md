# Configuring reverse-engineer-anything with the user

You are configuring the `reverse-engineer-anything` open-bot plugin on this desktop for
the user. Walk them through it step by step. This plugin has **no vault keys and no
secrets**: REA analyzes locally and needs no API keys. Configuration is settings only.

## What the plugin installs

1. The **REA CLI** (`rea`, npm package `rea-agents`, version pinned by the `rea_version`
   setting) plus the `procps` Linux prerequisite — done by the plugin setup, idempotent.
2. A gated MCP server named **`rea`** with three meta-tools: `rea_status`, `rea_catalog`,
   `rea_cli`.
3. The **Reverse Engineer** persona and the `reverse-engineer-anything` skill.

## Settings (Plugins tab → reverse-engineer-anything → Settings)

Ask the user only what you cannot decide yourself. Defaults suit a first run.

- **`ttl_minutes`** (default 240): how long an open session stays open. Reverse
  engineering sessions run long; 240 min is a good default. Range 5–1440.
- **`timeout_minutes`** (default 15): default cap per `rea_cli` run. Native analysis
  (Ghidra/Hopper) can be slow; raise to 30–60 for large binaries. Range 1–60.
- **`rea_version`** (default `6.7.0`): the pinned rea-agents version the setup installs.
  Change only deliberately, then reinstall the plugin so setup runs.
- **`rea_env`** (default empty): optional `KEY=VALUE` pairs passed to every `rea` run,
  comma-separated. Typical use: `REA_GHIDRA_STARTUP_TIMEOUT_MS=300000` for large
  binaries, or `REA_MCP_INPUT_SCHEMA_PROFILE=full` if you also register REA's raw MCP
  server elsewhere. Keys must be valid environment-variable names.

Apply with `ob-plugin settings reverse-engineer-anything <key>=<value>` (validated
against the manifest) or the Settings dialog.

## Native analysis engines (installed by setup)

Setup installs Ghidra 12.1.4 (`/opt/ghidra/current`) and a Temurin JDK 21
(`/opt/java/current`) alongside the REA CLI, so native decompilation works out of
the box. The gate injects `GHIDRA_INSTALL_DIR`/`JAVA_HOME` automatically. If a
user already has a Ghidra they prefer, set **`ghidra_install_dir`** to its path —
the gate will use it instead. Hopper, IDA and JADX remain optional
caller-supplied providers; none are installed by this plugin.

## Verification order

1. `ob-plugin-reverse-engineer-anything-mcp status` → expect `gate: LOCKED`,
   `rea: 6.7.0` (or the pinned version), `procps: ok`.
2. `ob-plugin settings reverse-engineer-anything` → settings match what you agreed.
3. Open a thread with the **Reverse Engineer** persona and ask for a smoke test, e.g.
   "analyze this JavaScript app directory": the agent should run `status` → `open` →
   `rea_cli` → `close` and deliver evidence.
4. Threads that do not yet show `rea_*` tools (fresh install, daemon not restarted)
   use the fallback `ob-plugin-reverse-engineer-anything-mcp gate` — that is normal
   until the next desktop restart.

## If something fails

- `rea: NOT INSTALLED` → reinstall the plugin (`ob-plugin install
  reverse-engineer-anything` or `--path` for local dev) so setup runs. Never
  npm-install by hand.
- `procps: MISSING` → the setup's `apt-get install procps` failed; check network or
  install procps manually, then re-run status.
- Native analysis refuses with a provider error → no Ghidra/Hopper/IDA installed.
  Static analyses still work; say which path you took.
