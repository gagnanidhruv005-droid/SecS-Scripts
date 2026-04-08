#!/usr/bin/env bash
# =============================================================================
# Suricata - STEP 2: Build & Install Script (MSYS2 UCRT64)
# =============================================================================
# Run this INSIDE the "MSYS2 UCRT64" terminal (from Start Menu).
#
# Usage:
#   bash /2_build_suricata.sh
#
# What this does:
#   1. Installs all required pacman packages
#   2. Configures the Npcap SDK (placed by step 1 at C:\msys64\npcap-sdk)
#   3. Clones Suricata + libhtp from GitHub
#   4. Builds and installs Suricata
#   5. Copies config files and sets up log directory
# =============================================================================
set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
NPCAP_SDK_DIR="/npcap-sdk"          # C:\msys64\npcap-sdk placed by step 1
BUILD_DIR="$HOME/suricata-build"
PREFIX="/usr/local"
CONF_DIR="$PREFIX/etc/suricata"
LOG_DIR="$PREFIX/var/log/suricata"

# ── Helpers ───────────────────────────────────────────────────────────────────
log()  { echo -e "\n\033[36m==> $*\033[0m"; }
ok()   { echo -e "    \033[32m[OK]\033[0m $*"; }
warn() { echo -e "    \033[33m[WARN]\033[0m $*"; }
die()  { echo -e "\n\033[31m[ERROR]\033[0m $*" >&2; exit 1; }

# ── Preflight checks ──────────────────────────────────────────────────────────
log "Preflight checks..."

# Make sure we are in a UCRT64 environment
if [[ "${MSYSTEM:-}" != "UCRT64" ]]; then
    die "Wrong MSYS2 environment: '$MSYSTEM'. Please open 'MSYS2 UCRT64' from the Start Menu and re-run."
fi
ok "Running in UCRT64 environment"

# Make sure Npcap SDK was placed by step 1
if [[ ! -d "$NPCAP_SDK_DIR/Include" ]]; then
    die "Npcap SDK not found at $NPCAP_SDK_DIR. Did you run 1_windows_prep.ps1 first?"
fi
ok "Npcap SDK found at $NPCAP_SDK_DIR"

# ── 1. Install pacman packages ────────────────────────────────────────────────
log "Step 1/5 — Installing build dependencies..."
pacman -S --noconfirm --needed \
    autoconf \
    automake \
    git \
    make \
    unzip \
    mingw-w64-ucrt-x86_64-cbindgen \
    mingw-w64-ucrt-x86_64-jansson \
    mingw-w64-ucrt-x86_64-libpcap \
    mingw-w64-ucrt-x86_64-libtool \
    mingw-w64-ucrt-x86_64-libyaml \
    mingw-w64-ucrt-x86_64-pcre2 \
    mingw-w64-ucrt-x86_64-rust \
    mingw-w64-ucrt-x86_64-toolchain
ok "All dependencies installed"

# ── 2. Clone Suricata + libhtp ────────────────────────────────────────────────
log "Step 2/5 — Cloning source code..."
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

if [[ -d "suricata/.git" ]]; then
    warn "Suricata repo already exists — pulling latest changes..."
    cd suricata
    git pull
    cd ..
else
    git clone https://github.com/OISF/suricata
    ok "Suricata cloned"
fi

if [[ -d "suricata/libhtp/.git" ]]; then
    warn "libhtp already exists — skipping clone"
else
    git clone https://github.com/OISF/libhtp suricata/libhtp
    ok "libhtp cloned"
fi

# ── 3. Configure ──────────────────────────────────────────────────────────────
log "Step 3/5 — Configuring build..."
cd "$BUILD_DIR/suricata"

./autogen.sh

./configure \
    --prefix="$PREFIX" \
    --with-libpcap-includes="$NPCAP_SDK_DIR/Include" \
    --with-libpcap-libraries="$NPCAP_SDK_DIR/Lib/x64"

ok "Configure complete"

# ── 4. Compile ────────────────────────────────────────────────────────────────
log "Step 4/5 — Compiling Suricata (this takes 10-30 minutes)..."
make -j"$(nproc)"
ok "Compilation complete"

# ── 5. Install + config files ─────────────────────────────────────────────────
log "Step 5/5 — Installing..."
make install
ok "Suricata installed to $PREFIX"

# Copy config files manually (make install-conf is broken on Windows)
log "Copying configuration files..."
mkdir -p "$CONF_DIR"
mkdir -p "$LOG_DIR"

for f in suricata.yaml classification.config reference.config threshold.config; do
    if [[ -f "$BUILD_DIR/suricata/$f" ]]; then
        cp "$BUILD_DIR/suricata/$f" "$CONF_DIR/"
        ok "Copied $f"
    else
        warn "$f not found in source tree, skipping"
    fi
done

if [[ -d "$BUILD_DIR/suricata/rules" ]]; then
    cp -r "$BUILD_DIR/suricata/rules" "$CONF_DIR/"
    ok "Copied default rules"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "\033[32m============================================================\033[0m"
echo -e "\033[32m  Suricata build & install complete!\033[0m"
echo -e "\033[32m============================================================\033[0m"
echo ""
echo "  Binary  : $PREFIX/bin/suricata"
echo "  Config  : $CONF_DIR/suricata.yaml"
echo "  Logs    : $LOG_DIR"
echo ""
echo "  Verify installation:"
echo "    suricata --build-info"
echo ""
echo "  List available network interfaces:"
echo "    suricata --list-interfaces"
echo ""
echo "  Run in IDS mode:"
echo "    suricata -c $CONF_DIR/suricata.yaml -i <interface>"
echo ""
