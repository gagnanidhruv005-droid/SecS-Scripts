# Run PowerShell as Administrator

$downloadPath = "C:\sysmon"
New-Item -ItemType Directory -Force -Path $downloadPath

Write-Host "Downloading Sysmon..."

Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$downloadPath\sysmon.zip"

Write-Host "Downloading Sysmon Config..."

Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "$downloadPath\sysmonconfig.xml"

Write-Host "Extracting Sysmon..."

Expand-Archive "$downloadPath\sysmon.zip" -DestinationPath $downloadPath -Force

Write-Host "Installing Sysmon..."

cd $downloadPath
.\Sysmon64.exe -accepteula -i sysmonconfig.xml

Write-Host "Configuring Wazuh Agent..."

$ossecPath = "C:\Program Files (x86)\ossec-agent\ossec.conf"

[xml]$ossec = Get-Content $ossecPath

$log = $ossec.CreateElement("localfile")

$location = $ossec.CreateElement("location")
$location.InnerText = "Microsoft-Windows-Sysmon/Operational"

$logformat = $ossec.CreateElement("log_format")
$logformat.InnerText = "eventchannel"

$log.AppendChild($location) | Out-Null
$log.AppendChild($logformat) | Out-Null

$ossec.ossec_config.AppendChild($log) | Out-Null

$ossec.Save($ossecPath)

Write-Host "Restarting Wazuh Agent..."

Restart-Service -Name wazuh

Write-Host "Sysmon + Wazuh integration complete!"