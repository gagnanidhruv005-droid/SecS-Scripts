# =============================================================================
# Suricata Setup - STEP 2: Windows Preparation
# =============================================================================
# Run as Administrator in PowerShell.
#
# Installs:
#   - MSYS2 to C:\msys64
#   - Npcap driver
#   - Npcap SDK to C:\msys64\npcap-sdk (one location only)
#   - Copies 3_build_suricata.sh into C:\msys64\
#
# After this script:
#   Open MSYS2 UCRT64 from Start Menu and run: bash /3_build_suricata.sh
# =============================================================================
#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

$MSYS2_DIR           = "C:\msys64"
$MSYS2_INSTALLER_URL = "https://github.com/msys2/msys2-installer/releases/download/2024-01-13/msys2-x86_64-20240113.exe"
$MSYS2_INSTALLER     = "$env:TEMP\msys2-installer.exe"

$NPCAP_DRIVER_URL    = "https://npcap.com/dist/npcap-1.79.exe"
$NPCAP_DRIVER_INST   = "$env:TEMP\npcap-installer.exe"

$NPCAP_SDK_URL       = "https://npcap.com/dist/npcap-sdk-1.15.zip"
$NPCAP_SDK_ZIP       = "$env:TEMP\npcap-sdk.zip"
$NPCAP_SDK_DEST      = "$MSYS2_DIR\npcap-sdk"   # ONE location: /npcap-sdk inside MSYS2

$BUILD_SCRIPT_SRC    = "$PSScriptRoot\3_build_suricata.sh"
$BUILD_SCRIPT_DEST   = "$MSYS2_DIR\3_build_suricata.sh"

function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-OK($msg)   { Write-Host "    [OK] $msg" -ForegroundColor Green }
function Write-Info($msg) { Write-Host "    [..] $msg" -ForegroundColor Gray }
function Write-Warn($msg) { Write-Host "    [WARN] $msg" -ForegroundColor Yellow }

function Download-File($url, $dest) {
    if (Test-Path $dest) {
        Write-OK "Already downloaded: $(Split-Path $dest -Leaf)"
        return
    }
    Write-Info "Downloading $(Split-Path $dest -Leaf)..."
    Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
    Write-OK "Downloaded"
}

# =============================================================================
# Preflight: confirm C:\msys64 is gone before proceeding
# =============================================================================
Write-Step "Preflight check..."
if (Test-Path "$MSYS2_DIR\usr\bin\bash.exe") {
    Write-Host "`n[ERROR] MSYS2 already exists at $MSYS2_DIR" -ForegroundColor Red
    Write-Host "        Run 1_uninstall.ps1 first to start clean." -ForegroundColor Red
    exit 1
}
Write-OK "Clean slate confirmed - no existing MSYS2"

if (-not (Test-Path $BUILD_SCRIPT_SRC)) {
    Write-Host "`n[ERROR] 3_build_suricata.sh not found at: $BUILD_SCRIPT_SRC" -ForegroundColor Red
    Write-Host "        Keep all 3 scripts in the same folder." -ForegroundColor Red
    exit 1
}
Write-OK "3_build_suricata.sh found"

# =============================================================================
# 1. Install MSYS2
# =============================================================================
Write-Step "Step 1/4 - Installing MSYS2..."
Download-File $MSYS2_INSTALLER_URL $MSYS2_INSTALLER

Write-Info "Running MSYS2 installer (silent)..."
Start-Process -FilePath $MSYS2_INSTALLER `
    -ArgumentList "install --root $MSYS2_DIR --confirm-command" `
    -Wait -NoNewWindow

if (-not (Test-Path "$MSYS2_DIR\usr\bin\bash.exe")) {
    Write-Host "`n[ERROR] MSYS2 install failed." -ForegroundColor Red
    exit 1
}
Write-OK "MSYS2 installed at $MSYS2_DIR"

Write-Info "Running initial pacman database sync (will retry up to 3 times)..."
$pacmanOK = $false
for ($i = 1; $i -le 3; $i++) {
    Write-Info "Attempt $i of 3..."
    $result = & "$MSYS2_DIR\usr\bin\bash.exe" -lc "pacman -Sy --noconfirm" 2>&1
    if ($LASTEXITCODE -eq 0) {
        $pacmanOK = $true
        break
    }
    Write-Warn "Attempt $i failed (SSL timeout or mirror issue) - waiting 5 seconds..."
    Start-Sleep -Seconds 5
}
if ($pacmanOK) {
    Write-OK "pacman synced"
} else {
    Write-Warn "pacman sync failed after 3 attempts - continuing anyway"
    Write-Warn "The build script will retry pacman when it runs inside MSYS2"
}

# =============================================================================
# 2. Install Npcap driver
# =============================================================================
Write-Step "Step 2/4 - Installing Npcap driver..."

$npcapSvc = Get-Service -Name "npcap" -ErrorAction SilentlyContinue
if ($npcapSvc) {
    Write-OK "Npcap driver already installed"
} else {
    Download-File $NPCAP_DRIVER_URL $NPCAP_DRIVER_INST
    Write-Host "    [!!] Npcap GUI installer will open - click through to install." -ForegroundColor Yellow
    Start-Process -FilePath $NPCAP_DRIVER_INST -Wait
    Write-OK "Npcap driver installed"
}

# =============================================================================
# 3. Install Npcap SDK (single location only: C:\msys64\npcap-sdk)
# =============================================================================
Write-Step "Step 3/4 - Installing Npcap SDK..."

if (Test-Path "$NPCAP_SDK_DEST\Include\pcap.h") {
    Write-OK "Npcap SDK already at $NPCAP_SDK_DEST"
} else {
    Download-File $NPCAP_SDK_URL $NPCAP_SDK_ZIP
    Write-Info "Extracting to $NPCAP_SDK_DEST..."
    Expand-Archive -Path $NPCAP_SDK_ZIP -DestinationPath $NPCAP_SDK_DEST -Force
    Write-OK "Npcap SDK extracted"
}

# Verify required files
$checks = @(
    "$NPCAP_SDK_DEST\Include\pcap.h",
    "$NPCAP_SDK_DEST\Lib\x64\wpcap.lib",
    "$NPCAP_SDK_DEST\Lib\x64\Packet.lib"
)
foreach ($f in $checks) {
    if (Test-Path $f) {
        Write-OK "Verified: $(Split-Path $f -Leaf)"
    } else {
        Write-Host "`n[ERROR] Missing SDK file: $f" -ForegroundColor Red
        Write-Host "        The SDK zip may be corrupt. Delete $NPCAP_SDK_ZIP and retry." -ForegroundColor Red
        exit 1
    }
}

# =============================================================================
# 4. Copy build script into MSYS2
# =============================================================================
Write-Step "Step 4/4 - Copying build script..."

$content = [System.IO.File]::ReadAllText($BUILD_SCRIPT_SRC) -replace "`r`n", "`n" -replace "`r", "`n"
[System.IO.File]::WriteAllText($BUILD_SCRIPT_DEST, $content, [System.Text.UTF8Encoding]::new($false))
Write-OK "3_build_suricata.sh copied to $BUILD_SCRIPT_DEST"
Write-Info "Inside MSYS2 this is visible as: /3_build_suricata.sh"

# =============================================================================
# Summary
# =============================================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  Windows preparation complete!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Installed:" -ForegroundColor Cyan
Write-Host "    MSYS2   : $MSYS2_DIR"
Write-Host "    Npcap   : driver installed"
Write-Host "    SDK     : $NPCAP_SDK_DEST"
Write-Host "      pcap.h    : $NPCAP_SDK_DEST\Include\pcap.h"
Write-Host "      wpcap.lib : $NPCAP_SDK_DEST\Lib\x64\wpcap.lib"
Write-Host ""
Write-Host "  NEXT STEP:" -ForegroundColor Yellow
Write-Host "  1. Open 'MSYS2 UCRT64' from the Start Menu"
Write-Host "  2. Run: bash /3_build_suricata.sh"
Write-Host ""
