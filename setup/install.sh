#!/usr/bin/env bash
# reverse-engineer-anything — idempotent setup (runs as root at install and after desktop recreate).
# Installs REA's runtime prerequisites, the pinned rea-agents CLI, and the native analysis
# engine stack REA verifies against (Ghidra 12.1.4 + JDK 21). No secrets involved.
set -uo pipefail

PIN="6.7.0"            # keep in sync with the manifest config rea_version
GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip"
GHIDRA_ROOT="/opt/ghidra"
LOG_TAG="[rea-setup]"

echo "$LOG_TAG ensuring procps (REA Linux prerequisite for process ownership checks)..."
export DEBIAN_FRONTEND=noninteractive
apt-get install -y procps >/dev/null 2>&1 || echo "$LOG_TAG WARNING: apt-get procps failed (may already be present)"

if ! command -v npm >/dev/null 2>&1; then
  echo "$LOG_TAG ERROR: npm not found — REA needs Node.js 22.19+/24.11+/26+ with npm."
  exit 1
fi

current=""
if command -v rea >/dev/null 2>&1; then
  current="$(rea --version 2>/dev/null || true)"
fi

if [ "$current" = "$PIN" ]; then
  echo "$LOG_TAG rea-agents ${PIN} already installed."
else
  echo "$LOG_TAG installing rea-agents@${PIN} (current: ${current:-none})..."
  npm install --global "rea-agents@${PIN}" >/dev/null 2>&1 \
    || npm install --global "rea-agents@${PIN}" || { echo "$LOG_TAG ERROR: npm install failed"; exit 1; }
fi

echo "$LOG_TAG ensuring JDK 21 (Ghidra 12.1.x requirement — Temurin, self-contained in /opt/java)..."
if [ -x /opt/java/current/bin/java ] || { command -v java >/dev/null 2>&1 && java -version 2>&1 | grep -q 'version "2[1-9]'; }; then
  echo "$LOG_TAG JDK 21+ already present."
else
  TMPTGZ="$(mktemp -u /tmp/jdk-XXXXXX.tar.gz)"
  if curl -fsSL --retry 3 -o "$TMPTGZ" "https://api.adoptium.net/v3/binary/latest/21/ga/linux/x64/jdk/hotspot/normal/eclipse"; then
    mkdir -p /opt/java
    tar -xzf "$TMPTGZ" -C /opt/java && rm -f "$TMPTGZ"
    DIR="$(find /opt/java -maxdepth 1 -type d -name 'jdk-21*' | sort | tail -1)"
    if [ -n "$DIR" ]; then
      ln -sfn "$DIR" /opt/java/current
      echo "$LOG_TAG JDK 21 installed: ${DIR} -> /opt/java/current"
    else
      echo "$LOG_TAG WARNING: JDK archive extracted but no jdk-21* directory found"
    fi
  else
    echo "$LOG_TAG WARNING: JDK download failed — install a JDK 21+ manually for native analysis"
  fi
fi

echo "$LOG_TAG ensuring Ghidra 12.1.4 (native decompilation engine)..."
if [ -x "${GHIDRA_ROOT}/current/support/analyzeHeadless" ] || [ -d "${GHIDRA_ROOT}/current" ]; then
  echo "$LOG_TAG Ghidra already installed at ${GHIDRA_ROOT}/current."
else
  TMPZIP="$(mktemp -u /tmp/ghidra-XXXXXX.zip)"
  if curl -fsSL --retry 3 -o "$TMPZIP" "$GHIDRA_URL"; then
    mkdir -p "$GHIDRA_ROOT"
    unzip -q -o "$TMPZIP" -d "$GHIDRA_ROOT" && rm -f "$TMPZIP"
    DIR="$(find "$GHIDRA_ROOT" -maxdepth 1 -type d -name 'ghidra_*' | sort | tail -1)"
    if [ -n "$DIR" ]; then
      ln -sfn "$DIR" "${GHIDRA_ROOT}/current"
      echo "$LOG_TAG Ghidra installed: ${DIR} -> ${GHIDRA_ROOT}/current"
    else
      echo "$LOG_TAG WARNING: Ghidra archive extracted but no ghidra_* directory found"
    fi
  else
    echo "$LOG_TAG WARNING: Ghidra download failed — native analysis stays unavailable;"
    echo "$LOG_TAG   install manually and set the ghidra_install_dir setting. Static analyses are unaffected."
  fi
fi


# ---------------------------------------------------------------------------
# Open-source companion analysis tools REA knows how to drive (best-effort:
# a failed optional tool never blocks the install — static analysis stays usable)
# ---------------------------------------------------------------------------
TOOLS="/opt/rea-tools"
mkdir -p "$TOOLS/bin"

echo "$LOG_TAG installing apt-packaged analysis tools (objdump, tshark, binwalk, pwntools, sigrok, apktool, gdb)..."
apt-get install -y binutils tshark binwalk python3-pwntools sigrok-cli apktool gdb >/dev/null 2>&1 \
  || echo "$LOG_TAG WARNING: some apt analysis tools failed to install (optional)"

echo "$LOG_TAG ensuring WABT 1.0.42 (WASM inspection)..."
if [ -x "$TOOLS/wabt/bin/wasm2wat" ]; then
  echo "$LOG_TAG WABT already installed."
else
  TMPW="$(mktemp -u /tmp/wabt-XXXXXX.tar.gz)"
  if curl -fsSL --retry 3 -o "$TMPW" "https://github.com/WebAssembly/wabt/releases/download/1.0.42/wabt-1.0.42-linux-x64.tar.gz"; then
    tar -xzf "$TMPW" -C "$TOOLS" && rm -f "$TMPW"
    ln -sfn "$TOOLS"/wabt-1.0.42 "$TOOLS/wabt" 2>/dev/null || true
    for b in "$TOOLS"/wabt/bin/*; do ln -sf "$b" "$TOOLS/bin/$(basename "$b")"; done
    echo "$LOG_TAG WABT 1.0.42 installed."
  else
    echo "$LOG_TAG WARNING: WABT download failed — WASM inspection stays unavailable"
  fi
fi

echo "$LOG_TAG ensuring JADX 1.5.6 (Android decompiler)..."
if [ -x "$TOOLS/jadx/bin/jadx" ]; then
  echo "$LOG_TAG JADX already installed."
else
  TMPJ="$(mktemp -u /tmp/jadx-XXXXXX.zip)"
  if curl -fsSL --retry 3 -o "$TMPJ" "https://github.com/skylot/jadx/releases/download/v1.5.6/jadx-1.5.6.zip"; then
    mkdir -p "$TOOLS/jadx"
    unzip -q -o "$TMPJ" -d "$TOOLS/jadx" && rm -f "$TMPJ"
    for b in "$TOOLS"/jadx/bin/*; do ln -sf "$b" "$TOOLS/bin/$(basename "$b")"; done
    echo "$LOG_TAG JADX installed (JADX 1.5.6; the jadx-headless-mcp bridge JAR stays caller-supplied per REA docs)."
  else
    echo "$LOG_TAG WARNING: JADX download failed — Android decompilation stays unavailable"
  fi
fi

echo "$LOG_TAG companion tools ready (PATH entries under $TOOLS/bin are wired by the gate)."

echo "$LOG_TAG rea version: $(rea --version 2>/dev/null || echo UNKNOWN)"
echo "$LOG_TAG done."
