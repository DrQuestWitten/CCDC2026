# ==============================
# CCDC Phase 0 – Emergency Triage
# ==============================

Write-Host "Starting Phase 0 Triage..."

# Create IR folder
New-Item -ItemType Directory -Path "C:\IR" -Force | Out-Null

# Snapshot processes
Get-Process | Out-File "C:\IR\process_snapshot.txt"

# Snapshot services
Get-Service | Out-File "C:\IR\services_snapshot.txt"

# Snapshot listening ports
netstat -ano | Out-File "C:\IR\netstat_snapshot.txt"

# Change Administrator password
# net user Administrator P@ssw0rdCCDC!2026

# Disable Guest
net user Guest /active:no

# Disable RDP temporarily
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1 -Type DWord

# Enable firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

Write-Host "Phase 0 Complete."
