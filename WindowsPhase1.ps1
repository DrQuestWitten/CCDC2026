# ==============================
# CCDC Phase 1 – OS Hardening
# ==============================

Write-Host "Starting OS Hardening..."

# Disable SMBv1
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue

# Disable PowerShell v2
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart -ErrorAction SilentlyContinue

# Enforce password policy
net accounts /minpwlen:14 /maxpwage:60 /lockoutthreshold:5

# Enable Defender real-time monitoring
Set-MpPreference -DisableRealtimeMonitoring $false

# Remove unknown local admins (manual review recommended)
Get-LocalGroupMember Administrators | Out-File C:\IR\local_admins.txt

Write-Host "OS Hardening Complete."
