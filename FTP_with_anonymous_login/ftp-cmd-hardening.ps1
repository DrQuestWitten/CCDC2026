Import-Module WebAdministration
Set-Service ftpsvc -StartupType Automatic; Start-Service ftpsvc
Set-WebConfigurationProperty -Filter "/system.ftpServer/security/authentication/anonymousAuthentication" -PSPath IIS:\Sites\* -Name enabled -Value $true
Set-WebConfigurationProperty -Filter "/system.ftpServer/security/authentication/basicAuthentication" -PSPath IIS:\Sites\* -Name enabled -Value $true
Set-WebConfigurationProperty -PSPath MACHINE/WEBROOT/APPHOST -Filter "/system.ftpServer/firewallSupport" -Name lowDataChannelPort -Value 50000
Set-WebConfigurationProperty -PSPath MACHINE/WEBROOT/APPHOST -Filter "/system.ftpServer/firewallSupport" -Name highDataChannelPort -Value 51000
New-NetFirewallRule -DisplayName "Allow FTP 21" -Direction Inbound -Protocol TCP -LocalPort 21 -Action Allow
New-NetFirewallRule -DisplayName "Allow FTP Passive" -Direction Inbound -Protocol TCP -LocalPort 50000-51000 -Action Allow
auditpol /set /subcategory:"Logon" /success:enable /failure:enable; auditpol /set /subcategory:"Account Logon" /success:enable /failure:enable
Get-ChildItem IIS:\Sites | Where {$_.bindings.Collection.protocol -contains "ftp"} | Select Name,State,PhysicalPath; Get-WebConfiguration -Filter "/system.ftpServer/security/authorization" -PSPath IIS:\Sites\*