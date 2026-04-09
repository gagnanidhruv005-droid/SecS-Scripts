<#
.SYNOPSIS
    Automated Installer for ZeekNSM (Zeek-Inspired Network Security Monitor)
    
.DESCRIPTION
    This script prepares the C:\zeek directory, copies the binary and config,
    sets the interface to 'auto' for portability, and installs the service.
    Must be run as Administrator.
#>

$ErrorActionPreference = "Stop"

# 1. Check for Admin Privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script MUST be run as an Administrator!"
    exit 1
}

$InstallDir = "C:\zeek"
$LogDir = "$InstallDir\logs"
$CurrentDir = Get-Location

Write-Host "--- ZeekNSM Installer ---" -ForegroundColor Cyan

# 2. Create Directories
if (-not (Test-Path $LogDir)) {
    Write-Host "[*] Creating $LogDir ..."
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

# 3. Stop existing service if it exists
if (Get-Service ZeekNSM -ErrorAction SilentlyContinue) {
    Write-Host "[*] Stopping existing ZeekNSM service..."
    Stop-Service ZeekNSM -ErrorAction SilentlyContinue
}

# 4. Copy Files
Write-Host "[*] Copying files to $InstallDir ..."
if (Test-Path "$CurrentDir\build\zeek-nsm.exe") {
    Copy-Item "$CurrentDir\build\zeek-nsm.exe" "$InstallDir\zeek-nsm.exe" -Force
} elseif (Test-Path "$CurrentDir\zeek-nsm.exe") {
    Copy-Item "$CurrentDir\zeek-nsm.exe" "$InstallDir\zeek-nsm.exe" -Force
} else {
    Write-Error "Could not find zeek-nsm.exe in $CurrentDir or $CurrentDir\build"
    exit 1
}

# Copy config if not already there, or update it
if (Test-Path "$CurrentDir\zeek.conf") {
    Copy-Item "$CurrentDir\zeek.conf" "$InstallDir\zeek.conf" -Force
}

# 5. Optimize config for portability (Set interface to auto)
Write-Host "[*] Optimizing config for local machine (interface=auto) ..."
$confPath = "$InstallDir\zeek.conf"
(Get-Content $confPath) -replace '^interface\s*=.*', 'interface = auto' | Set-Content $confPath

# 6. Install / Re-install the Service
Write-Host "[*] Registering Windows Service..."
# If service exists, uninstall first to ensure paths are correct
if (Get-Service ZeekNSM -ErrorAction SilentlyContinue) {
    & "$InstallDir\zeek-nsm.exe" --uninstall | Out-Null
}
& "$InstallDir\zeek-nsm.exe" --install --config "$InstallDir\zeek.conf" | Out-Null

# 7. Start the Service
Write-Host "[*] Starting ZeekNSM..." -ForegroundColor Green
Start-Service ZeekNSM

Write-Host "`nInstallation Successful!" -ForegroundColor Green
Write-Host "Logs are being generated at: $LogDir"
Write-Host "Service Status: $( (Get-Service ZeekNSM).Status )"
