# =============================================================================
# Suricata Setup - STEP 1: Full Uninstall
# =============================================================================
# Run as Administrator in PowerShell.
#
# Removes:
#   - MSYS2 (C:\msys64)
#   - Npcap driver
#   - Npcap SDK (any leftover copies)
#   - Any stale temp installers
#
# After this script: run 2_windows_prep.ps1
# =============================================================================
#Requires -RunAsAdministrator

$ErrorActionPreference = "SilentlyContinue"

function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-OK($msg)   { Write-Host "    [OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "    [WARN] $msg" -ForegroundColor Yellow }
function Write-Info($msg) { Write-Host "    [..] $msg" -ForegroundColor Gray }

# =============================================================================
# 1. Uninstall Npcap driver
# =============================================================================
Write-Step "Uninstalling Npcap driver..."

$npcapUninstaller = @(
    "C:\Program Files\Npcap\uninstall.exe",
    "C:\Program Files (x86)\Npcap\uninstall.exe"
)

$npcapFound = $false
foreach ($u in $npcapUninstaller) {
    if (Test-Path $u) {
        Write-Info "Found uninstaller at $u"
        Start-Process -FilePath $u -ArgumentList "/S" -Wait
        Write-OK "Npcap uninstalled"
        $npcapFound = $true
        break
    }
}

if (-not $npcapFound) {
    # Try via installed programs list
    $npcapPkg = Get-Package -Name "*Npcap*" -ErrorAction SilentlyContinue
    if ($npcapPkg) {
        $npcapPkg | Uninstall-Package -Force
        Write-OK "Npcap removed via package manager"
    } else {
        Write-Warn "Npcap not found - already uninstalled or never installed"
    }
}

# Stop and remove npcap service if still lingering
$svc = Get-Service -Name "npcap" -ErrorAction SilentlyContinue
if ($svc) {
    Stop-Service -Name "npcap" -Force -ErrorAction SilentlyContinue
    sc.exe delete npcap | Out-Null
    Write-OK "Npcap service removed"
}

# =============================================================================
# 2. Remove MSYS2 (entire C:\msys64)
# =============================================================================
Write-Step "Removing MSYS2 at C:\msys64..."

if (Test-Path "C:\msys64") {
    # Try MSYS2 uninstaller first
    $msys2Uninst = "C:\msys64\uninstall.exe"
    if (Test-Path $msys2Uninst) {
        Write-Info "Running MSYS2 uninstaller..."
        Start-Process -FilePath $msys2Uninst -ArgumentList "--confirm-command purge" -Wait -NoNewWindow
    }

    # Force remove whatever remains
    if (Test-Path "C:\msys64") {
        Write-Info "Force removing C:\msys64 (this may take a moment)..."
        Remove-Item -Path "C:\msys64" -Recurse -Force -ErrorAction SilentlyContinue

        # If still there, use robocopy empty-dir trick
        if (Test-Path "C:\msys64") {
            $emptyDir = "$env:TEMP\empty_dir_$(Get-Random)"
            New-Item -ItemType Directory -Path $emptyDir -Force | Out-Null
            robocopy $emptyDir "C:\msys64" /MIR /NFL /NDL /NJH /NJS | Out-Null
            Remove-Item -Path "C:\msys64" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $emptyDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    if (-not (Test-Path "C:\msys64")) {
        Write-OK "C:\msys64 fully removed"
    } else {
        Write-Warn "Some files in C:\msys64 could not be removed (may be in use)"
        Write-Warn "Reboot and re-run this script, or delete C:\msys64 manually"
    }
} else {
    Write-Warn "C:\msys64 not found - already removed"
}

# =============================================================================
# 3. Clean up temp files
# =============================================================================
Write-Step "Cleaning up temp installers..."

$tempFiles = @(
    "$env:TEMP\msys2-installer.exe",
    "$env:TEMP\npcap-installer.exe",
    "$env:TEMP\npcap-sdk.zip"
)

foreach ($f in $tempFiles) {
    if (Test-Path $f) {
        Remove-Item $f -Force
        Write-OK "Removed $f"
    }
}

# =============================================================================
# 4. Summary
# =============================================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  Uninstall complete!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Removed:" -ForegroundColor Cyan
Write-Host "    - Npcap driver"
Write-Host "    - MSYS2 (C:\msys64)"
Write-Host "    - Temp installer files"
Write-Host ""
Write-Host "  NEXT STEP:" -ForegroundColor Yellow
Write-Host "  Run 2_windows_prep.ps1 as Administrator"
Write-Host ""
