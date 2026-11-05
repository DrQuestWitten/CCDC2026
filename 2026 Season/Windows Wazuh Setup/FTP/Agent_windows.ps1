#powershell.exe -ExecutionPolicy Bypass .\Agent_windows.ps1
# 1. Configuration
$ManagerIP = "172.20.242.20"
$AgentName = "FTP" 
#$AgentName = "wsk" 
#$AgentKey  = "MDAzIHdpbmRvd3MtMTEgYW55IGIzOTE2Nzk0ZTZiOWJkMDRiMGE4Yzk5YmQ3ZDk3YjJjNGU0Y2NlOGUwOGQ3MzNkMGE0Y2JkYzBhNTNiYTY4MmM="
$AgentKey  = "MDAzIEZUUCBhbnkgZjMwZjEzNDZhMDQxMzlhZjc0ZmJlOTE4YWMzMjRhZmVlOTlkZTkwNzM5ZTdjMGIwMWFiNjQzMmVlZDVhNDY1MQ=="

# Download to C:\ directly to avoid Temp folder path/permission issues
$MsiPath   = "C:\Windows\Temp\wazuh-agent.msi"

# 2. Download the installer
Write-Host "[*] Downloading Wazuh Agent..." -ForegroundColor Cyan
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.3-1.msi" -OutFile $MsiPath

# 3. Install silently (Using an ArgumentList array fixes the 1619 path error)
Write-Host "[*] Installing Wazuh Agent (Wait)..." -ForegroundColor Cyan
$MsiArgs = @(
    "/i", "`"$MsiPath`"",
    "/q",
    "WAZUH_MANAGER=`"$ManagerIP`"",
    "WAZUH_AGENT_GROUP='default'",
    "WAZUH_AGENT_NAME=`"$AgentName`""
)

$process = Start-Process msiexec.exe -ArgumentList $MsiArgs -Wait -PassThru

if ($process.ExitCode -ne 0) {
    Write-Host "Installation failed with exit code $($process.ExitCode)" -ForegroundColor Red
    return
}

# 4. Give Windows 2 seconds to register the files
Start-Sleep -Seconds 2

# 5. Stop the service
Stop-Service -Name "Wazuh" -Force -ErrorAction SilentlyContinue

# 6. Inject custom ossec.conf 
# IMPORTANT: This looks for ossec.conf in the SAME folder where you saved this script
$LocalConfig = Join-Path $PSScriptRoot "ossec.conf"
if (Test-Path $LocalConfig) {
    Write-Host "[*] Injecting custom ossec.conf..." -ForegroundColor Cyan
    Copy-Item -Path $LocalConfig -Destination "C:\Program Files (x86)\ossec-agent\ossec.conf" -Force
}

# 7. Inject the pre-generated key 
$ManageAgents = "C:\Program Files (x86)\ossec-agent\manage_agents.exe"
if (Test-Path $ManageAgents) {
    Write-Host "[*] Importing pre-generated key..." -ForegroundColor Cyan
    # 'echo y' bypasses the "Are you sure?" prompt
    echo y | & $ManageAgents -i $AgentKey
}

# 8. Start the service
Write-Host "[*] Starting Wazuh Service..." -ForegroundColor Cyan
Start-Service -Name "Wazuh"

# Cleanup
Remove-Item $MsiPath -ErrorAction SilentlyContinue

Write-Host "-------------------------------------------------------"
Write-Host "SUCCESS! Agent installed and configured." -ForegroundColor Green