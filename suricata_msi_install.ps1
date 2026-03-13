# =============================================================================
# Suricata MSI Installer + Wazuh Integration Script
# =============================================================================
# Run as Administrator in PowerShell:
#   Set-ExecutionPolicy -Scope Process Bypass
#   .\suricata_msi_install.ps1
#
# What this does:
#   1. Downloads and installs Npcap
#   2. Downloads and installs Suricata MSI
#   3. Updates rules via suricata-update
#   4. Detects network interface GUID
#   5. Creates auto-start scheduled task
#   6. Integrates with Wazuh agent
# =============================================================================
#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

# -- Configuration ------------------------------------------------------------
$SURICATA_DIR     = "C:\Program Files\Suricata"
$SURICATA_EXE     = "$SURICATA_DIR\suricata.exe"
$SURICATA_YAML    = "$SURICATA_DIR\suricata.yaml"
$EVE_JSON         = "$SURICATA_DIR\log\eve.json"
$SURICATA_LOG_DIR = "$SURICATA_DIR\log"
$INTERFACE_NAME   = "Ethernet 3"   # Change this to your interface name
$TASK_NAME        = "SuricataIDS"
$OSSEC_CONF       = "C:\Program Files (x86)\ossec-agent\ossec.conf"
$WAZUH_SVC        = "WazuhSvc"

$NPCAP_URL        = "https://npcap.com/dist/npcap-1.79.exe"
$SURICATA_URL     = "https://www.openinfosecfoundation.org/download/windows/Suricata-7.0.8-1-64bit.msi"
$DOWNLOAD_DIR     = "$env:TEMP\suricata-install"

# -- Helpers ------------------------------------------------------------------
function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-OK($msg)   { Write-Host "    [OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "    [WARN] $msg" -ForegroundColor Yellow }
function Write-Info($msg) { Write-Host "    [..] $msg" -ForegroundColor Gray }

# -- Preflight ----------------------------------------------------------------
Write-Step "Preflight checks..."
New-Item -ItemType Directory -Path $DOWNLOAD_DIR -Force | Out-Null
Write-OK "Download directory: $DOWNLOAD_DIR"

# -- Step 1: Install Npcap ----------------------------------------------------
Write-Step "Step 1 - Installing Npcap..."

$npcapInstalled = Get-Package -Name "Npcap" -ErrorAction SilentlyContinue
if ($npcapInstalled) {
    Write-OK "Npcap already installed - skipping"
} else {
    Write-Info "Downloading Npcap..."
    $npcapPath = "$DOWNLOAD_DIR\npcap.exe"
    Invoke-WebRequest -Uri $NPCAP_URL -OutFile $npcapPath -UseBasicParsing
    Write-Info "Installing Npcap silently..."
    Start-Process -FilePath $npcapPath -ArgumentList "/winpcap_mode=yes /loopback_support=yes /S" -Wait
    Write-OK "Npcap installed"
}

# -- Step 2: Install Suricata MSI ---------------------------------------------
Write-Step "Step 2 - Installing Suricata..."

if (Test-Path $SURICATA_EXE) {
    Write-OK "Suricata already installed at $SURICATA_EXE"
} else {
    Write-Info "Downloading Suricata MSI..."
    $msiPath = "$DOWNLOAD_DIR\suricata.msi"
    Invoke-WebRequest -Uri $SURICATA_URL -OutFile $msiPath -UseBasicParsing
    Write-Info "Installing Suricata..."
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$msiPath`" /quiet /norestart" -Wait
    Write-OK "Suricata installed"
}

# Verify installation
if (-not (Test-Path $SURICATA_EXE)) {
    Write-Host "`n[ERROR] Suricata not found at $SURICATA_EXE" -ForegroundColor Red
    Write-Host "Please install manually from https://suricata.io/download/" -ForegroundColor Yellow
    exit 1
}

$version = & $SURICATA_EXE --version 2>&1 | Select-Object -First 1
Write-OK "Version: $version"

# -- Step 3: Create log directory ---------------------------------------------
Write-Step "Step 3 - Creating log directory..."
New-Item -ItemType Directory -Path $SURICATA_LOG_DIR -Force | Out-Null
Write-OK "Log directory: $SURICATA_LOG_DIR"

# -- Step 4: Get interface GUID -----------------------------------------------
Write-Step "Step 4 - Detecting network interface..."

$adapter = Get-NetAdapter -Name $INTERFACE_NAME -ErrorAction SilentlyContinue
if (-not $adapter) {
    Write-Warn "Interface '$INTERFACE_NAME' not found. Available interfaces:"
    Get-NetAdapter | Where-Object Status -eq "Up" | ForEach-Object {
        Write-Host "    $($_.Name) - $($_.InterfaceDescription)" -ForegroundColor Yellow
    }
    Write-Host ""
    $INTERFACE_NAME = Read-Host "Enter your interface name exactly as shown above"
    $adapter = Get-NetAdapter -Name $INTERFACE_NAME
}

$GUID = $adapter.InterfaceGuid
$NPF_DEVICE = "\Device\NPF_$GUID"
Write-OK "Interface : $INTERFACE_NAME"
Write-OK "GUID      : $GUID"
Write-OK "NPF Device: $NPF_DEVICE"

# -- Step 5: Update rules -----------------------------------------------------
Write-Step "Step 5 - Updating Suricata rules..."

$env:Path += ";$SURICATA_DIR"
try {
    Write-Info "Running suricata-update (this may take a few minutes)..."
    & "$SURICATA_DIR\suricata-update.exe" 2>&1 | Tail -5
    Write-OK "Rules updated"
} catch {
    Write-Warn "suricata-update failed - you can run it manually later"
    Write-Warn "  cd `"$SURICATA_DIR`" && suricata-update"
}

# -- Step 6: Test run ---------------------------------------------------------
Write-Step "Step 6 - Testing Suricata..."

Write-Info "Running quick test (5 seconds)..."
$testProc = Start-Process -FilePath $SURICATA_EXE `
    -ArgumentList "-c `"$SURICATA_YAML`" -i `"$NPF_DEVICE`"" `
    -WorkingDirectory $SURICATA_DIR `
    -PassThru -WindowStyle Hidden

Start-Sleep -Seconds 5

if (-not $testProc.HasExited) {
    Write-OK "Suricata started successfully"
    Stop-Process -Id $testProc.Id -Force
} else {
    Write-Warn "Suricata exited early - check config manually"
    Write-Warn "Run: suricata -c `"$SURICATA_YAML`" -i `"$NPF_DEVICE`""
}

# -- Step 7: Auto-start scheduled task ---------------------------------------
Write-Step "Step 7 - Setting up auto-start on boot..."

$existing = Get-ScheduledTask -TaskName $TASK_NAME -ErrorAction SilentlyContinue
if ($existing) {
    Write-Warn "Task '$TASK_NAME' already exists - removing and recreating..."
    Unregister-ScheduledTask -TaskName $TASK_NAME -Confirm:$false
}

$action = New-ScheduledTaskAction `
    -Execute $SURICATA_EXE `
    -Argument "-c `"$SURICATA_YAML`" -i `"$NPF_DEVICE`"" `
    -WorkingDirectory $SURICATA_DIR

$trigger = New-ScheduledTaskTrigger -AtStartup

$principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit 0 `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask `
    -TaskName $TASK_NAME `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings `
    -Description "Suricata IDS - auto-start on boot" | Out-Null

Write-OK "Scheduled task '$TASK_NAME' created"

# Start it now
Start-ScheduledTask -TaskName $TASK_NAME
Start-Sleep -Seconds 3
$task = Get-ScheduledTask -TaskName $TASK_NAME
Write-OK "Task state: $($task.State)"

# -- Step 8: Wazuh integration ------------------------------------------------
Write-Step "Step 8 - Wazuh integration..."

if (-not (Test-Path $OSSEC_CONF)) {
    Write-Warn "Wazuh agent not found at: $OSSEC_CONF"
    Write-Warn "Install Wazuh agent first then add this to ossec.conf manually:"
    Write-Host ""
    Write-Host "  <localfile>" -ForegroundColor Yellow
    Write-Host "    <log_format>json</log_format>" -ForegroundColor Yellow
    Write-Host "    <location>$EVE_JSON</location>" -ForegroundColor Yellow
    Write-Host "  </localfile>" -ForegroundColor Yellow
} else {
    $ossec = [System.IO.File]::ReadAllText($OSSEC_CONF)

    if ($ossec -match [regex]::Escape($EVE_JSON)) {
        Write-OK "eve.json already in ossec.conf"
    } else {
        $backup = "$OSSEC_CONF.bak_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        Copy-Item $OSSEC_CONF $backup
        Write-Info "Backup: $backup"

        $block = @"

  <!-- Suricata eve.json - added by install script -->
  <localfile>
    <log_format>json</log_format>
    <location>$EVE_JSON</location>
  </localfile>

"@
        $ossec = $ossec -replace '(</ossec_config>\s*)$', "$block`$1"
        [System.IO.File]::WriteAllText($OSSEC_CONF, $ossec, [System.Text.UTF8Encoding]::new($false))
        Write-OK "eve.json added to ossec.conf"
    }

    # Restart Wazuh agent
    $svc = Get-Service -Name $WAZUH_SVC -ErrorAction SilentlyContinue
    if ($svc) {
        Restart-Service -Name $WAZUH_SVC -Force
        Start-Sleep -Seconds 3
        $svc.Refresh()
        Write-OK "Wazuh agent restarted: $($svc.Status)"
    } else {
        Write-Warn "Wazuh service not found - restart manually"
    }
}

# -- Summary ------------------------------------------------------------------
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  Suricata Installation Complete!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  KEY PATHS:" -ForegroundColor Cyan
Write-Host "    Suricata EXE  : $SURICATA_EXE"
Write-Host "    Config        : $SURICATA_YAML"
Write-Host "    Rules         : $SURICATA_DIR\rules\"
Write-Host "    eve.json      : $EVE_JSON"
Write-Host "    Interface     : $NPF_DEVICE"
Write-Host ""
Write-Host "  MANAGE SURICATA:" -ForegroundColor Cyan
Write-Host "    Start : Start-ScheduledTask -TaskName SuricataIDS"
Write-Host "    Stop  : Stop-ScheduledTask  -TaskName SuricataIDS"
Write-Host "    Status: Get-ScheduledTask   -TaskName SuricataIDS"
Write-Host ""
Write-Host "  VERIFY ALERTS:" -ForegroundColor Cyan
Write-Host "    Get-Content '$EVE_JSON' | Select-Object -Last 10"
Write-Host ""
