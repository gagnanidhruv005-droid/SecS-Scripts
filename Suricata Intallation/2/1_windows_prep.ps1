# =============================================================================
# Suricata - STEP 1: Windows Preparation Script (PowerShell)
# =============================================================================
# Run this as Administrator in PowerShell.
#
# This script will:
#   1. Install MSYS2 to C:\msys64 (if not already installed)
#   2. Install the Npcap driver (if not already installed)
#   3. Download the Npcap SDK and place it at C:\msys64\npcap-sdk
#   4. Copy the build script (2_build_suricata.sh) into C:\msys64\
#
# After this script finishes:
#   - Open "MSYS2 UCRT64" from the Start Menu
#   - Run: bash /2_build_suricata.sh
# =============================================================================
#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

# -- Configuration -------------------------------------------------------------
$MSYS2_DIR           = "C:\msys64"
$MSYS2_INSTALLER_URL = "https://github.com/msys2/msys2-installer/releases/download/2024-01-13/msys2-x86_64-20240113.exe"
$MSYS2_INSTALLER     = "$env:TEMP\msys2-installer.exe"

$NPCAP_DRIVER_URL    = "https://npcap.com/dist/npcap-1.79.exe"
$NPCAP_DRIVER_INST   = "$env:TEMP\npcap-installer.exe"

$NPCAP_SDK_URL       = "https://npcap.com/dist/npcap-sdk-1.15.zip"
$NPCAP_SDK_ZIP       = "$env:TEMP\npcap-sdk.zip"
$NPCAP_SDK_DEST      = "$MSYS2_DIR\npcap-sdk"

$BUILD_SCRIPT_SRC    = "$PSScriptRoot\2_build_suricata.sh"
$BUILD_SCRIPT_DEST   = "$MSYS2_DIR\2_build_suricata.sh"

# -- Helpers -------------------------------------------------------------------
function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-OK($msg)   { Write-Host "    [OK] $msg" -ForegroundColor Green }
function Write-Info($msg) { Write-Host "    [..] $msg" -ForegroundColor Gray }

function Download-File($url, $dest) {
    if (Test-Path $dest) {
        Write-OK "Already downloaded: $(Split-Path $dest -Leaf)"
        return
    }
    Write-Info "Downloading $(Split-Path $dest -Leaf) ..."
    Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
    Write-OK "Downloaded to $dest"
}

# -- Step 1: MSYS2 -------------------------------------------------------------
Write-Step "Step 1/4 - MSYS2"
if (Test-Path "$MSYS2_DIR\usr\bin\bash.exe") {
    Write-OK "MSYS2 already installed at $MSYS2_DIR"
} else {
    Download-File $MSYS2_INSTALLER_URL $MSYS2_INSTALLER
    Write-Info "Running MSYS2 silent installer..."
    Start-Process -FilePath $MSYS2_INSTALLER `
        -ArgumentList "install --root $MSYS2_DIR --confirm-command" `
        -Wait -NoNewWindow
    if (-not (Test-Path "$MSYS2_DIR\usr\bin\bash.exe")) {
        Write-Error "MSYS2 install failed. Try manually: https://www.msys2.org/"
        exit 1
    }
    Write-OK "MSYS2 installed at $MSYS2_DIR"

    Write-Info "Running initial pacman sync..."
    & "$MSYS2_DIR\usr\bin\bash.exe" -lc "pacman -Sy --noconfirm" 2>&1 | Out-Null
    Write-OK "pacman database synced"
}

# -- Step 2: Npcap Driver ------------------------------------------------------
Write-Step "Step 2/4 - Npcap Driver"
$npcapSvc = Get-Service -Name "npcap" -ErrorAction SilentlyContinue
if ($npcapSvc) {
    Write-OK "Npcap driver already installed"
} else {
    Download-File $NPCAP_DRIVER_URL $NPCAP_DRIVER_INST
    Write-Host "    [!!] The Npcap GUI installer will open. Click through to install." -ForegroundColor Yellow
    Start-Process -FilePath $NPCAP_DRIVER_INST -Wait
    Write-OK "Npcap driver installed"
}

# -- Step 3: Npcap SDK ---------------------------------------------------------
Write-Step "Step 3/4 - Npcap SDK"
if (Test-Path "$NPCAP_SDK_DEST\Include") {
    Write-OK "Npcap SDK already at $NPCAP_SDK_DEST"
} else {
    Download-File $NPCAP_SDK_URL $NPCAP_SDK_ZIP
    Write-Info "Extracting Npcap SDK to $NPCAP_SDK_DEST ..."
    Expand-Archive -Path $NPCAP_SDK_ZIP -DestinationPath $NPCAP_SDK_DEST -Force
    Write-OK "Npcap SDK ready at $NPCAP_SDK_DEST"
}

# -- Step 4: Copy build script -------------------------------------------------
Write-Step "Step 4/4 - Copying build script"
if (-not (Test-Path $BUILD_SCRIPT_SRC)) {
    Write-Error "Cannot find 2_build_suricata.sh next to this script at: $BUILD_SCRIPT_SRC`nMake sure both files are in the same folder."
    exit 1
}

# Copy and convert to Unix line endings (LF) so bash can read it
$content = [System.IO.File]::ReadAllText($BUILD_SCRIPT_SRC) -replace "`r`n", "`n" -replace "`r", "`n"
[System.IO.File]::WriteAllText($BUILD_SCRIPT_DEST, $content, [System.Text.UTF8Encoding]::new($false))
Write-OK "Build script copied to $BUILD_SCRIPT_DEST"

# -- Done ----------------------------------------------------------------------
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  Windows preparation complete!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  NEXT STEP:" -ForegroundColor Yellow
Write-Host "  1. Open 'MSYS2 UCRT64' from the Start Menu" -ForegroundColor Yellow
Write-Host "  2. Run the following command:" -ForegroundColor Yellow
Write-Host ""
Write-Host "       bash /2_build_suricata.sh" -ForegroundColor White
Write-Host ""
