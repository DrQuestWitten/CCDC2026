# ==============================
# CCDC Phase 0 – Emergency Triage
# ==============================

Write-Host "Starting Phase 0 Triage..." -ForegroundColor Cyan

New-Item -ItemType Directory -Path "C:\IR" -Force | Out-Null

Write-Host "Saving process snapshot..." -ForegroundColor Yellow
Get-Process | Out-File "C:\IR\process_snapshot.txt"

Write-Host "Saving service snapshot..." -ForegroundColor Yellow
Get-Service | Out-File "C:\IR\services_snapshot.txt"

Write-Host "Saving listening ports snapshot..." -ForegroundColor Yellow
netstat -ano | Out-File "C:\IR\netstat_snapshot.txt"

Write-Host "Saving scheduled tasks snapshot..." -ForegroundColor Yellow
schtasks /query /fo LIST /v | Out-File "C:\IR\schtasks_snapshot.txt"

Write-Host "Saving local users snapshot..." -ForegroundColor Yellow
net user | Out-File "C:\IR\local_users.txt"

Write-Host "Disabling Guest account..." -ForegroundColor Yellow
net user Guest /active:no | Out-Null

Write-Host "Disabling RDP temporarily..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1 -Type DWord

Write-Host "Enabling Windows Firewall..." -ForegroundColor Yellow
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

Write-Host "Phase 0 Complete." -ForegroundColor Green
