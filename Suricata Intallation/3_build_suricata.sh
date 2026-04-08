#!/usr/bin/env bash
# =============================================================================
# Suricata Setup - STEP 3: Build & Install (MSYS2 UCRT64)
# =============================================================================
# Run inside MSYS2 UCRT64 terminal:
#   bash /3_build_suricata.sh
#
# What this does:
#   1. Verifies environment and Npcap SDK
#   2. Installs pacman build dependencies (NOT the pacman suricata package)
#   3. Removes pacman suricata if accidentally installed
#   4. Clones Suricata + libhtp
#   5. Builds with correct Npcap flags
#   6. make install -> /usr/local/
#   7. Copies config files
#   8. Verifies live capture is compiled in
# =============================================================================
set -euo pipefail

NPCAP_SDK_DIR="/npcap-sdk"
BUILD_DIR="$HOME/suricata-build"
PREFIX="/usr/local"
CONF_DIR="$PREFIX/etc/suricata"
LOG_DIR="$PREFIX/var/log/suricata"

log()  { echo -e "\n\033[36m==> $*\033[0m"; }
ok()   { echo -e "    \033[32m[OK]\033[0m $*"; }
warn() { echo -e "    \033[33m[WARN]\033[0m $*"; }
die()  { echo -e "\n\033[31m[ERROR]\033[0m $*" >&2; exit 1; }

# =============================================================================
# 1. Preflight
# =============================================================================
log "Step 1/8 - Preflight checks..."

[[ "${MSYSTEM:-}" == "UCRT64" ]] || die "Wrong environment: '$MSYSTEM'. Open 'MSYS2 UCRT64' from Start Menu."
ok "Running in UCRT64"

[[ -f "$NPCAP_SDK_DIR/Include/pcap.h" ]]      || die "Npcap SDK missing: $NPCAP_SDK_DIR/Include/pcap.h -- run 2_windows_prep.ps1 first"
[[ -f "$NPCAP_SDK_DIR/Lib/x64/wpcap.lib" ]]   || die "Npcap SDK missing: $NPCAP_SDK_DIR/Lib/x64/wpcap.lib"
[[ -f "$NPCAP_SDK_DIR/Lib/x64/Packet.lib" ]]  || die "Npcap SDK missing: $NPCAP_SDK_DIR/Lib/x64/Packet.lib"
ok "Npcap SDK verified at $NPCAP_SDK_DIR"

# =============================================================================
# 2. Install pacman build dependencies (explicitly NO suricata package)
# =============================================================================
log "Step 2/8 - Installing build dependencies..."

# Sync package database first with retry (mirrors can time out)
for attempt in 1 2 3; do
    echo "    pacman -Sy attempt $attempt of 3..."
    pacman -Sy --noconfirm && break || {
        warn "Mirror timeout on attempt $attempt - retrying in 5 seconds..."
        sleep 5
    }
done

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

ok "Dependencies installed"

# =============================================================================
# 3. Remove pacman suricata if present (it shadows our build in PATH)
# =============================================================================
log "Step 3/8 - Checking for conflicting pacman suricata..."

if pacman -Q mingw-w64-ucrt-x86_64-suricata &>/dev/null; then
    warn "Found pacman suricata - removing it to avoid PATH conflict..."
    pacman -R --noconfirm mingw-w64-ucrt-x86_64-suricata
    ok "Pacman suricata removed"
else
    ok "No pacman suricata installed - no conflict"
fi

# Confirm suricata is gone from /ucrt64/bin
if [[ -f "/ucrt64/bin/suricata.exe" ]]; then
    die "/ucrt64/bin/suricata.exe still exists after removal - check manually"
fi

# =============================================================================
# 4. Clone Suricata + libhtp
# =============================================================================
log "Step 4/8 - Cloning source code..."
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

if [[ -d "suricata/.git" ]]; then
    warn "Suricata repo already exists - pulling latest..."
    cd suricata && git pull && cd ..
else
    git clone https://github.com/OISF/suricata
    ok "Suricata cloned"
fi

if [[ -d "suricata/libhtp/.git" ]]; then
    warn "libhtp already exists - skipping"
else
    git clone https://github.com/OISF/libhtp suricata/libhtp
    ok "libhtp cloned"
fi

# =============================================================================
# 5. Configure with Npcap
# =============================================================================
log "Step 5/8 - Configuring build..."
cd "$BUILD_DIR/suricata"

# Clean any previous configure state
[[ -f "Makefile" ]] && make clean 2>/dev/null || true
rm -f config.cache config.status

./autogen.sh

# Set LDFLAGS and CPPFLAGS so the linker also finds the SDK
export LDFLAGS="-L$NPCAP_SDK_DIR/Lib/x64"
export CPPFLAGS="-I$NPCAP_SDK_DIR/Include"

./configure \
    --prefix="$PREFIX" \
    --with-libpcap-includes="$NPCAP_SDK_DIR/Include" \
    --with-libpcap-libraries="$NPCAP_SDK_DIR/Lib/x64"

# Verify configure actually found pcap
if grep -qi "checking for pcap_close.*yes\|libpcap.*yes\|HAVE_LIBPCAP" config.log 2>/dev/null; then
    ok "Configure confirmed: libpcap/Npcap detected"
else
    warn "Could not auto-confirm pcap in config.log - checking for failure..."
    if grep -qi "live capture.*disabled\|pcap.*not found\|cannot find.*pcap" config.log 2>/dev/null; then
        echo ""
        echo "Relevant config.log lines:"
        grep -i "pcap" config.log | tail -20
        die "Configure failed to find Npcap. See above."
    fi
    warn "Proceeding - will verify in build-info after install"
fi

ok "Configure complete"

# =============================================================================
# 6. Compile
# =============================================================================
log "Step 6/8 - Compiling (10-30 minutes)..."
make -j"$(nproc)"
ok "Compilation complete"

# =============================================================================
# 7. Install
# =============================================================================
log "Step 7/8 - Installing to $PREFIX..."
make install
ok "Installed to $PREFIX"

# Verify binary is now in the right place
[[ -f "$PREFIX/bin/suricata.exe" ]] || die "Binary not found at $PREFIX/bin/suricata.exe after install"
ok "Binary confirmed at $PREFIX/bin/suricata.exe"

# Copy config files (make install-conf is broken on Windows)
log "Copying config files..."
mkdir -p "$CONF_DIR" "$LOG_DIR"

for f in suricata.yaml classification.config reference.config threshold.config; do
    if [[ -f "$BUILD_DIR/suricata/$f" ]]; then
        cp "$BUILD_DIR/suricata/$f" "$CONF_DIR/"
        ok "Copied $f"
    else
        warn "$f not found in source - skipping"
    fi
done

if [[ -d "$BUILD_DIR/suricata/rules" ]]; then
    cp -r "$BUILD_DIR/suricata/rules" "$CONF_DIR/"
    ok "Copied default rules"
fi

# =============================================================================
# 8. Verify
# =============================================================================
log "Step 8/8 - Verifying installation..."

# Confirm which suricata is in PATH
SURI_PATH=$(which suricata 2>/dev/null || echo "NOT IN PATH")
echo "    which suricata : $SURI_PATH"

if [[ "$SURI_PATH" == "$PREFIX/bin/suricata" ]]; then
    ok "Correct suricata is first in PATH"
else
    warn "suricata in PATH is: $SURI_PATH"
    warn "Expected: $PREFIX/bin/suricata"
    warn "Open a fresh MSYS2 UCRT64 window and re-run: which suricata"
fi

# Check build-info for live capture
BUILD_INFO=$("$PREFIX/bin/suricata" --build-info 2>&1 || true)
echo ""
echo "    -- build-info pcap section --"
echo "$BUILD_INFO" | grep -i "pcap\|npcap\|live\|capture" || echo "    (nothing matched)"
echo ""

if echo "$BUILD_INFO" | grep -qi "npcap\|pcap.*yes\|libpcap"; then
    ok "Live capture support confirmed in build-info"
else
    warn "Live capture not confirmed in build-info - try running:"
    warn "  $PREFIX/bin/suricata --build-info | grep -i pcap"
fi

echo ""
echo -e "\033[32m============================================================\033[0m"
echo -e "\033[32m  Suricata install complete!\033[0m"
echo -e "\033[32m============================================================\033[0m"
echo ""
echo "  Binary : $PREFIX/bin/suricata.exe"
echo "  Config : $CONF_DIR/suricata.yaml"
echo "  Logs   : $LOG_DIR"
echo ""
echo "  List interfaces:"
echo "    suricata --list-interfaces"
echo ""
echo "  Run Suricata:"
echo "    suricata -c $CONF_DIR/suricata.yaml -i 'Ethernet 3'"
echo ""
