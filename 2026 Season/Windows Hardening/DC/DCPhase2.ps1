# ==========================================
# CCDC Phase 2 – AD / Account / Service Hardening
# Windows Server 2019
# ==========================================

Write-Host "Starting Phase 2 Hardening..." -ForegroundColor Cyan

New-Item -ItemType Directory -Path "C:\IR" -Force | Out-Null

Write-Host "Enumerating local users..." -ForegroundColor Yellow
net user | Out-File "C:\IR\phase2_users.txt"

Write-Host "Enumerating local groups..." -ForegroundColor Yellow
net localgroup | Out-File "C:\IR\phase2_groups.txt"

Write-Host "Checking enabled local accounts..." -ForegroundColor Yellow
try {
    Get-LocalUser | Select-Object Name, Enabled, LastLogon | Out-File "C:\IR\local_user_status.txt"
} catch {
    Write-Warning "Could not enumerate local users with Get-LocalUser."
}

Write-Host "Disabling built-in Guest account..." -ForegroundColor Yellow
net user Guest /active:no | Out-Null

Write-Host "Restricting cached logons..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Value "0"

Write-Host "Disabling anonymous SID/Name translation..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "TurnOffAnonymousBlock" -Value 0 -Type DWord

Write-Host "Requiring CTRL+ALT+DEL..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Value 0 -Type DWord

Write-Host "Disabling unnecessary services if present..." -ForegroundColor Yellow
$servicesToDisable = @("RemoteRegistry","XblGameSave","XboxNetApiSvc")
foreach ($svc in $servicesToDisable) {
    try {
        if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Host "Disabled service: $svc" -ForegroundColor Green
        }
    } catch {
        Write-Warning "Could not disable service $svc"
    }
}

Write-Host "Saving share enumeration..." -ForegroundColor Yellow
try {
    Get-SmbShare | Select-Object Name, Path, Description | Out-File "C:\IR\smb_shares.txt"
} catch {
    Write-Warning "Could not enumerate SMB shares."
}

Write-Host "Phase 2 Complete." -ForegroundColor Green
