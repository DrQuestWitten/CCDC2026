# ================================================
# CCDC Phase 3 – Active Directory Domain Controller Hardening
# Windows Server 2019
# ================================================

Write-Host "Starting Phase 3 Domain Controller Hardening..." -ForegroundColor Cyan

Write-Host "Enforcing LDAP Signing..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Value 2 -Type DWord

Write-Host "Disabling Anonymous Enumeration..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1 -Type DWord

Write-Host "Enabling LSASS Protection..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord

Write-Host "Enabling Security Auditing..." -ForegroundColor Yellow
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Account Management" /success:enable /failure:enable
auditpol /set /category:"Policy Change" /success:enable /failure:enable
auditpol /set /category:"Directory Service Access" /success:enable /failure:enable

Write-Host "Auditing Domain Admin membership..." -ForegroundColor Yellow
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Get-ADGroupMember "Domain Admins" | Select-Object Name, SamAccountName, ObjectClass | Out-File "C:\IR\domain_admin_members.txt"
} catch {
    Write-Warning "Could not load AD module or enumerate Domain Admins."
}

Write-Host "Disabling Print Spooler..." -ForegroundColor Yellow
try {
    Stop-Service Spooler -Force -ErrorAction SilentlyContinue
    Set-Service Spooler -StartupType Disabled -ErrorAction SilentlyContinue
} catch {
    Write-Warning "Could not disable Print Spooler."
}

Write-Host "Hardening DNS..." -ForegroundColor Yellow
try {
    Set-DnsServerRecursion -Enable $false -ErrorAction Stop
} catch {
    Write-Warning "Could not disable DNS recursion."
}

try {
    Set-DnsServerCache -LockingPercent 100 -ErrorAction Stop
} catch {
    Write-Warning "Could not set DNS cache locking."
}

try {
    Set-DnsServerResponseRateLimiting -ResponsesPerSec 5 -ErrorsPerSec 5 -WindowInSec 5 -Enable $true -ErrorAction Stop
} catch {
    Write-Warning "Could not configure DNS Response Rate Limiting."
}

Write-Host "Disabling NTLMv1..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5 -Type DWord

Write-Host "Hardening Kerberos..." -ForegroundColor Yellow
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos" -Name "Parameters" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "SupportedEncryptionTypes" -Value 2147483640 -Type DWord

Write-Host "Phase 3 Complete." -ForegroundColor Green
