Write-Host "Starting Domain Controller Firewall Lockdown..."



# Enable firewall

Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True



# Remove weak rules

Get-NetFirewallRule | Where {$_.Enabled -eq "True"} | Disable-NetFirewallRule



# ----------------------------------------

# Required Active Directory Ports

# ----------------------------------------



# DNS

New-NetFirewallRule -DisplayName "DNS TCP" `

Direction Inbound `

Protocol TCP `

LocalPort 53 `

Action Allow



New-NetFirewallRule -DisplayName "DNS UDP" `

Direction Inbound `

Protocol UDP `

LocalPort 53 `

Action Allow





# Kerberos

New-NetFirewallRule -DisplayName "Kerberos TCP" `

Direction Inbound `

Protocol TCP `

LocalPort 88 `

Action Allow



New-NetFirewallRule -DisplayName "Kerberos UDP" `

Direction Inbound `

Protocol UDP `

LocalPort 88 `

Action Allow





# LDAP

New-NetFirewallRule -DisplayName "LDAP TCP" `

Direction Inbound `

Protocol TCP `

LocalPort 389 `

Action Allow



New-NetFirewallRule -DisplayName "LDAP UDP" `

Direction Inbound `

Protocol UDP `

LocalPort 389 `

Action Allow





# LDAPS

New-NetFirewallRule -DisplayName "LDAPS" `

Direction Inbound `

Protocol TCP `

LocalPort 636 `

Action Allow





# Global Catalog

New-NetFirewallRule -DisplayName "Global Catalog" `

Direction Inbound `

Protocol TCP `

LocalPort 3268 `

Action Allow



New-NetFirewallRule -DisplayName "Global Catalog SSL" `

Direction Inbound `

Protocol TCP `

LocalPort 3269 `

Action Allow





# SMB / SYSVOL / Netlogon

New-NetFirewallRule -DisplayName "SMB" `

Direction Inbound `

Protocol TCP `

LocalPort 445 `

Action Allow





# RPC Endpoint Mapper

New-NetFirewallRule -DisplayName "RPC Endpoint Mapper" `

Direction Inbound `

Protocol TCP `

LocalPort 135 `

Action Allow





# NTP

New-NetFirewallRule -DisplayName "NTP" `

Direction Inbound `

Protocol UDP `

LocalPort 123 `

Action Allow





Write-Host "Firewall Lockdown Complete."