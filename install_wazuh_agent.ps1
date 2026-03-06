# ============================================================
# Wazuh Agent Installer for Windows - v2 (Updated)
# Run this script as Administrator in PowerShell
# ============================================================

$RED    = "Red"
$GREEN  = "Green"
$YELLOW = "Yellow"
$CYAN   = "Cyan"
$script:SERVICE_NAME = ""

function Print-Banner {
    Write-Host "========================================" -ForegroundColor $CYAN
    Write-Host "   Wazuh Agent Installer - Windows      " -ForegroundColor $CYAN
    Write-Host "              v2 Updated                " -ForegroundColor $CYAN
    Write-Host "========================================" -ForegroundColor $CYAN
    Write-Host ""
}

function Check-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal   = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "[ERROR] Please run this script as Administrator." -ForegroundColor $RED
        exit 1
    }
    Write-Host "[OK] Running as Administrator." -ForegroundColor $GREEN
}

function Get-IPs {
    Write-Host "--- IP Configuration ---" -ForegroundColor $YELLOW
    Write-Host ""

    do {
        $script:WAZUH_MANAGER = Read-Host "  Enter Wazuh MANAGER IP (server)"
        if ($script:WAZUH_MANAGER -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
            Write-Host "  [!] Invalid IP format. Try again." -ForegroundColor $RED
        }
    } while ($script:WAZUH_MANAGER -notmatch '^\d{1,3}(\.\d{1,3}){3}$')

    do {
        $script:AGENT_IP = Read-Host "  Enter this machine's AGENT IP"
        if ($script:AGENT_IP -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
            Write-Host "  [!] Invalid IP format. Try again." -ForegroundColor $RED
        }
    } while ($script:AGENT_IP -notmatch '^\d{1,3}(\.\d{1,3}){3}$')

    Write-Host ""
    Write-Host "  Manager IP : $script:WAZUH_MANAGER" -ForegroundColor $GREEN
    Write-Host "  Agent IP   : $script:AGENT_IP"      -ForegroundColor $GREEN
    Write-Host ""

    $confirm = Read-Host "  Confirm? (Y/N)"
    if ($confirm -ne "Y" -and $confirm -ne "y") {
        Write-Host "  Re-entering IPs..." -ForegroundColor $YELLOW
        Get-IPs
    }
}

function Uninstall-Existing {
    Write-Host ""
    Write-Host "[STEP 1] Checking for existing Wazuh installation..." -ForegroundColor $YELLOW

    $existing = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" |
        ForEach-Object { Get-ItemProperty $_.PSPath } |
        Where-Object { $_.DisplayName -like "*Wazuh*" -or $_.DisplayName -like "*ossec*" }

    if ($existing) {
        Write-Host "  [!] Found existing: $($existing.DisplayName) - removing..." -ForegroundColor $YELLOW
        if ($existing.UninstallString -match '\{[A-Z0-9\-]+\}') {
            $productCode = $matches[0]
            Start-Process "msiexec.exe" -ArgumentList "/x $productCode /q" -Wait
            Write-Host "  [OK] Existing installation removed." -ForegroundColor $GREEN
        }
    } else {
        Write-Host "  [*] No existing installation found." -ForegroundColor $CYAN
    }

    # Stop any running Wazuh/ossec processes
    Get-Process | Where-Object {
        $_.Path -like "*ossec*" -or $_.Path -like "*wazuh*"
    } | Stop-Process -Force -ErrorAction SilentlyContinue

    # Remove leftover services
    $svcNames = @("WazuhSvc", "OssecSvc", "ossec", "Wazuh", "wazuh-agent")
    foreach ($svc in $svcNames) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($s) {
            Write-Host "  [*] Removing leftover service: $svc" -ForegroundColor $YELLOW
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            sc.exe delete $svc | Out-Null
            Write-Host "  [OK] Service $svc removed." -ForegroundColor $GREEN
        }
    }

    # Remove leftover folder
    $agentPath = "C:\Program Files (x86)\ossec-agent"
    if (Test-Path $agentPath) {
        Write-Host "  [*] Removing leftover folder..." -ForegroundColor $YELLOW
        Start-Sleep -Seconds 2
        Remove-Item $agentPath -Recurse -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path $agentPath)) {
            Write-Host "  [OK] Folder removed." -ForegroundColor $GREEN
        } else {
            Write-Host "  [!] Folder could not be fully removed, continuing..." -ForegroundColor $YELLOW
        }
    }

    Start-Sleep -Seconds 2
}

function Download-Agent {
    Write-Host ""
    Write-Host "[STEP 2] Downloading Wazuh Agent..." -ForegroundColor $YELLOW

    $url       = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.3-1.msi"
    $installer = "$env:TEMP\wazuh-agent.msi"

    if (Test-Path $installer) { Remove-Item $installer -Force }

    Write-Host "  URL: $url" -ForegroundColor $CYAN

    try {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $url -OutFile $installer -UseBasicParsing
        Write-Host "  [OK] Download complete." -ForegroundColor $GREEN
    } catch {
        Write-Host "  [ERROR] Download failed: $_" -ForegroundColor $RED
        exit 1
    }

    return $installer
}

function Install-Agent {
    param($installer)

    Write-Host ""
    Write-Host "[STEP 3] Installing Wazuh Agent..." -ForegroundColor $YELLOW
    Write-Host "  Manager IP : $script:WAZUH_MANAGER" -ForegroundColor $CYAN
    Write-Host "  Agent IP   : $script:AGENT_IP"      -ForegroundColor $CYAN

    $msiArgs = "/i `"$installer`" /q " +
               "WAZUH_MANAGER=`"$script:WAZUH_MANAGER`" " +
               "WAZUH_AGENT_IP=`"$script:AGENT_IP`" " +
               "WAZUH_REGISTRATION_SERVER=`"$script:WAZUH_MANAGER`" " +
               "WAZUH_PROTOCOL=`"TCP`""

    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru

    if ($process.ExitCode -eq 0) {
        Write-Host "  [OK] Installation successful." -ForegroundColor $GREEN
    } else {
        Write-Host "  [ERROR] Installation failed. Exit code: $($process.ExitCode)" -ForegroundColor $RED
        exit 1
    }

    Start-Sleep -Seconds 5
}

function Configure-OssecConf {
    Write-Host ""
    Write-Host "[STEP 4] Configuring ossec.conf..." -ForegroundColor $YELLOW

    $ossecConf = "C:\Program Files (x86)\ossec-agent\ossec.conf"

    if (-not (Test-Path $ossecConf)) {
        Write-Host "  [ERROR] ossec.conf not found at: $ossecConf" -ForegroundColor $RED
        exit 1
    }

    $content = Get-Content $ossecConf -Raw
    $content = $content -replace '<address>.*?</address>', "<address>$script:WAZUH_MANAGER</address>"
    Set-Content -Path $ossecConf -Value $content -Encoding UTF8

    Write-Host "  [OK] Manager IP set to: $script:WAZUH_MANAGER" -ForegroundColor $GREEN
}

function Configure-Firewall {
    Write-Host ""
    Write-Host "[STEP 5] Configuring Windows Firewall Rules..." -ForegroundColor $YELLOW
    Write-Host ""

    # Remove old Wazuh rules first
    Write-Host "  [*] Clearing old Wazuh firewall rules..." -ForegroundColor $CYAN
    Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*Wazuh*" } |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue

    # --- INBOUND RULES ---
    Write-Host "  [+] Adding INBOUND rules..." -ForegroundColor $CYAN

    New-NetFirewallRule `
        -DisplayName "Wazuh Agent - Allow Manager Inbound 1514 TCP" `
        -Direction Inbound -Protocol TCP -LocalPort 1514 `
        -RemoteAddress $script:WAZUH_MANAGER `
        -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null

    New-NetFirewallRule `
        -DisplayName "Wazuh Agent - Allow Manager Inbound 1514 UDP" `
        -Direction Inbound -Protocol UDP -LocalPort 1514 `
        -RemoteAddress $script:WAZUH_MANAGER `
        -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null

    New-NetFirewallRule `
        -DisplayName "Wazuh Agent - Allow Manager Inbound 1515 TCP" `
        -Direction Inbound -Protocol TCP -LocalPort 1515 `
        -RemoteAddress $script:WAZUH_MANAGER `
        -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null

    Write-Host "  [OK] Inbound rules added." -ForegroundColor $GREEN

    # --- OUTBOUND RULES ---
    Write-Host "  [+] Adding OUTBOUND rules..." -ForegroundColor $CYAN

    New-NetFirewallRule `
        -DisplayName "Wazuh Agent - Allow Outbound to Manager 1514 TCP" `
        -Direction Outbound -Protocol TCP -RemotePort 1514 `
        -RemoteAddress $script:WAZUH_MANAGER `
        -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null

    New-NetFirewallRule `
        -DisplayName "Wazuh Agent - Allow Outbound to Manager 1514 UDP" `
        -Direction Outbound -Protocol UDP -RemotePort 1514 `
        -RemoteAddress $script:WAZUH_MANAGER `
        -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null

    New-NetFirewallRule `
        -DisplayName "Wazuh Agent - Allow Outbound to Manager 1515 TCP" `
        -Direction Outbound -Protocol TCP -RemotePort 1515 `
        -RemoteAddress $script:WAZUH_MANAGER `
        -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null

    New-NetFirewallRule `
        -DisplayName "Wazuh Agent - Allow Outbound Syslog 514 UDP" `
        -Direction Outbound -Protocol UDP -RemotePort 514 `
        -RemoteAddress $script:WAZUH_MANAGER `
        -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null

    Write-Host "  [OK] Outbound rules added." -ForegroundColor $GREEN
    Write-Host ""
    Write-Host "  Firewall Port Summary:" -ForegroundColor $CYAN
    Write-Host "  +--------+----------+---------------------------+" -ForegroundColor $CYAN
    Write-Host "  | Port   | Protocol | Purpose                   |" -ForegroundColor $CYAN
    Write-Host "  +--------+----------+---------------------------+" -ForegroundColor $CYAN
    Write-Host "  | 1514   | TCP/UDP  | Agent <-> Manager comms   |" -ForegroundColor $CYAN
    Write-Host "  | 1515   | TCP      | Agent registration        |" -ForegroundColor $CYAN
    Write-Host "  | 514    | UDP      | Syslog (optional)         |" -ForegroundColor $CYAN
    Write-Host "  +--------+----------+---------------------------+" -ForegroundColor $CYAN
}

function Start-WazuhService {
    Write-Host ""
    Write-Host "[STEP 6] Finding and Starting Wazuh Agent Service..." -ForegroundColor $YELLOW

    Start-Sleep -Seconds 3

    # Try all known service names
    $possibleNames = @("WazuhSvc", "Wazuh", "OssecSvc", "ossec", "wazuh-agent")
    $foundService  = $null

    foreach ($name in $possibleNames) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($svc) {
            $foundService = $name
            Write-Host "  [OK] Found service: $name" -ForegroundColor $GREEN
            break
        }
    }

    # Broad search fallback
    if (-not $foundService) {
        Write-Host "  [*] Searching broadly for service..." -ForegroundColor $YELLOW
        $svc = Get-Service | Where-Object {
            $_.DisplayName -like "*Wazuh*" -or
            $_.DisplayName -like "*ossec*" -or
            $_.Name -like "*Wazuh*" -or
            $_.Name -like "*ossec*"
        }
        if ($svc) {
            $foundService = $svc.Name
            Write-Host "  [OK] Found service: $foundService ($($svc.DisplayName))" -ForegroundColor $GREEN
        }
    }

    # Last resort: register from exe
    if (-not $foundService) {
        Write-Host "  [!] Service not found. Trying manual registration from exe..." -ForegroundColor $YELLOW
        $exePaths = @(
            "C:\Program Files (x86)\ossec-agent\wazuh-agent.exe",
            "C:\Program Files (x86)\ossec-agent\ossec-agent.exe",
            "C:\Program Files\ossec-agent\wazuh-agent.exe"
        )
        foreach ($exe in $exePaths) {
            if (Test-Path $exe) {
                Write-Host "  [*] Registering from: $exe" -ForegroundColor $CYAN
                & $exe "install-service" 2>$null
                Start-Sleep -Seconds 3
                $svc = Get-Service | Where-Object {
                    $_.DisplayName -like "*Wazuh*" -or $_.Name -like "*ossec*"
                }
                if ($svc) {
                    $foundService = $svc.Name
                    Write-Host "  [OK] Service registered: $foundService" -ForegroundColor $GREEN
                    break
                }
            }
        }
    }

    if (-not $foundService) {
        Write-Host "  [ERROR] Could not find or register Wazuh service." -ForegroundColor $RED
        Write-Host "  [TIP]   Reboot and run: Start-Service WazuhSvc" -ForegroundColor $YELLOW
        exit 1
    }

    try {
        Set-Service   -Name $foundService -StartupType Automatic
        Start-Service -Name $foundService -ErrorAction Stop
        Write-Host "  [OK] Service started and set to Automatic." -ForegroundColor $GREEN
        $script:SERVICE_NAME = $foundService
    } catch {
        Write-Host "  [ERROR] Could not start service: $_" -ForegroundColor $RED
        exit 1
    }
}

function Verify-Installation {
    Write-Host ""
    Write-Host "[STEP 7] Verifying Installation..." -ForegroundColor $YELLOW

    Start-Sleep -Seconds 3

    $service = Get-Service -Name $script:SERVICE_NAME -ErrorAction SilentlyContinue

    if ($service -and $service.Status -eq "Running") {
        Write-Host ""
        Write-Host "========================================" -ForegroundColor $GREEN
        Write-Host "  [SUCCESS] Wazuh Agent is RUNNING!    " -ForegroundColor $GREEN
        Write-Host "========================================" -ForegroundColor $GREEN
        Write-Host "  Manager IP : $script:WAZUH_MANAGER"          -ForegroundColor $GREEN
        Write-Host "  Agent IP   : $script:AGENT_IP"               -ForegroundColor $GREEN
        Write-Host "  Service    : $script:SERVICE_NAME (Running)"  -ForegroundColor $GREEN
        Write-Host "========================================" -ForegroundColor $GREEN
    } else {
        Write-Host "  [ERROR] Wazuh Agent is NOT running." -ForegroundColor $RED
        Write-Host "  Check logs:" -ForegroundColor $YELLOW
        Write-Host "  Get-Content 'C:\Program Files (x86)\ossec-agent\ossec.log' -Tail 30" -ForegroundColor $CYAN
        exit 1
    }

    # Test connectivity to manager
    Write-Host ""
    Write-Host "  [*] Testing connection to Manager on port 1514..." -ForegroundColor $YELLOW
    $conn = Test-NetConnection -ComputerName $script:WAZUH_MANAGER -Port 1514 -WarningAction SilentlyContinue
    if ($conn.TcpTestSucceeded) {
        Write-Host "  [OK] Port 1514 reachable on Manager!" -ForegroundColor $GREEN
    } else {
        Write-Host "  [!] Port 1514 not reachable - check Manager-side firewall." -ForegroundColor $YELLOW
    }
}

function Cleanup {
    Write-Host ""
    Write-Host "[INFO] Cleaning up temp files..." -ForegroundColor $YELLOW
    Remove-Item "$env:TEMP\wazuh-agent.msi" -Force -ErrorAction SilentlyContinue
    Write-Host "  [OK] Done." -ForegroundColor $GREEN
}

# ─── MAIN ────────────────────────────────────────────────────
Print-Banner
Check-Admin
Get-IPs
Uninstall-Existing
$installer = Download-Agent
Install-Agent      -installer $installer
Configure-OssecConf
Configure-Firewall
Start-WazuhService
Verify-Installation
Cleanup