# ==========================================
# CCDC Phase 1 – OS Hardening
# Windows Server 2019
# ==========================================

Write-Host "Starting Phase 1 OS Hardening..." -ForegroundColor Cyan

New-Item -ItemType Directory -Path "C:\IR" -Force | Out-Null

Write-Host "Disabling SMBv1..." -ForegroundColor Yellow
try {
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
} catch {
    Write-Warning "Could not disable SMBv1."
}

# Disable PowerShell v2
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart -ErrorAction SilentlyContinue

Write-Host "Enabling Windows Defender real-time monitoring..." -ForegroundColor Yellow
try {
    Set-MpPreference -DisableRealtimeMonitoring $false
} catch {
    Write-Warning "Windows Defender settings could not be changed."
}

Write-Host "Turning on UAC..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 5 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1 -Type DWord

Write-Host "Disabling AutoRun..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord

Write-Host "Disabling Remote Assistance..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0 -Type DWord

Write-Host "Disabling LLMNR..." -ForegroundColor Yellow
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord

Write-Host "Disabling WPAD..." -ForegroundColor Yellow
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -Value 1 -Type DWord

Write-Host "Auditing admin memberships..." -ForegroundColor Yellow
try {
    net localgroup Administrators | Out-File "C:\IR\local_admins.txt"
} catch {
    "Could not enumerate local Administrators group." | Out-File "C:\IR\local_admins.txt"
}

try {
    net group "Domain Admins" /domain | Out-File "C:\IR\domain_admins.txt"
} catch {
    "Could not enumerate Domain Admins." | Out-File "C:\IR\domain_admins.txt"
}

Write-Host "Listing startup commands..." -ForegroundColor Yellow
try {
    Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User | Out-File "C:\IR\startup_items.txt"
} catch {
    Write-Warning "Could not enumerate startup commands."
}

Write-Host "Phase 1 Complete." -ForegroundColor Green
