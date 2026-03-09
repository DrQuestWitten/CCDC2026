# ================================================

# CCDC Phase 3 – Active Directory Domain Controller Hardening

# Windows Server 2019

# Author: Blue Team

# ================================================



Write-Host "Starting Phase 3 Domain Controller Hardening..."



# ------------------------------------------------

# 2. Enforce LDAP Signing

# Prevents LDAP relay attacks

# ------------------------------------------------

Write-Host "Enforcing LDAP Signing..."



New-ItemProperty `

 -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `

 -Name "LDAPServerIntegrity" `

 -Value 2 `

 -PropertyType DWORD -Force





# ------------------------------------------------

# 3. Disable Anonymous Enumeration

# ------------------------------------------------

Write-Host "Disabling Anonymous Enumeration..."



New-ItemProperty `

 -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `

 -Name "RestrictAnonymous" `

 -Value 1 `

 -PropertyType DWORD -Force



New-ItemProperty `

 -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `

 -Name "RestrictAnonymousSAM" `

 -Value 1 `

 -PropertyType DWORD -Force





# ------------------------------------------------

# 4. Protect LSASS

# Prevent credential dumping (Mimikatz)

# ------------------------------------------------

Write-Host "Enabling LSASS Protection..."



New-ItemProperty `

 -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `

 -Name "RunAsPPL" `

 -Value 1 `

 -PropertyType DWORD -Force





# ------------------------------------------------

# 5. Enable Advanced Auditing

# ------------------------------------------------

Write-Host "Enabling Security Auditing..."



auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable

auditpol /set /category:"Account Logon" /success:enable /failure:enable

auditpol /set /category:"Account Management" /success:enable /failure:enable

auditpol /set /category:"Policy Change" /success:enable /failure:enable

auditpol /set /category:"Directory Service Access" /success:enable /failure:enable





# ------------------------------------------------

# 6. Protect Domain Admins Group

# ------------------------------------------------

Write-Host "Auditing Domain Admin membership..."



Import-Module ActiveDirectory



Get-ADGroupMember "Domain Admins"





# ------------------------------------------------

# 7. Disable Print Spooler (Prevents PrintNightmare)

# ------------------------------------------------

Write-Host "Disabling Print Spooler..."



Stop-Service Spooler -Force

Set-Service Spooler -StartupType Disabled





# ------------------------------------------------

# 8. DNS Security

# ------------------------------------------------

Write-Host "Hardening DNS..."



Set-DnsServerRecursion -Enable $false



Set-DnsServerCache -LockingPercent 100



Set-DnsServerResponseRateLimiting `

 -ResponsesPerSec 5 `

 -ErrorsPerSec 5 `

 -WindowInSec 5 `

 -Enable $true





# ------------------------------------------------

# 9. Disable NTLM v1

# ------------------------------------------------

Write-Host "Disabling NTLMv1..."



New-ItemProperty `

 -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `

 -Name "LmCompatibilityLevel" `

 -Value 5 `

 -PropertyType DWORD -Force





# ------------------------------------------------

# 10. Force Kerberos Only

# ------------------------------------------------

Write-Host "Hardening Kerberos..."



Set-ItemProperty `

 -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" `

 -Name "SupportedEncryptionTypes" `

 -Value 2147483640 `

 -Type DWORD





Write-Host "Domain Controller Hardening Complete."