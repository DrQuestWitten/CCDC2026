================= RECON.PS1 =================
# This script ONLY looks. It changes nothing. Safe to run anytime.
# It saves everything it finds to a file on your Desktop too.

Start-Transcript -Path "$env:USERPROFILE\Desktop\recon_output.txt" -Force

Write-Host "`n===== WHO AM I / THIS BOX =====" -ForegroundColor Cyan
whoami; hostname; ipconfig /all

Write-Host "`n===== WHO IS LOGGED IN (unknown = red team!) =====" -ForegroundColor Cyan
quser

Write-Host "`n===== WHO HAS ADMIN (remove anyone you don't know) =====" -ForegroundColor Cyan
"Domain Admins","Enterprise Admins","Schema Admins","Administrators","Account Operators","Backup Operators","Group Policy Creator Owners" | ForEach-Object {
    Write-Host "`n--- $_ ---" -ForegroundColor Yellow
    Get-ADGroupMember $_ | Select-Object Name,SamAccountName | Format-Table -AutoSize
}

Write-Host "`n===== NEWEST ACCOUNTS (look for ones you didn't make) =====" -ForegroundColor Cyan
Get-ADUser -Filter * -Properties whenCreated,adminCount,Enabled | Sort-Object whenCreated -Descending | Select-Object Name,SamAccountName,whenCreated,adminCount,Enabled | Format-Table -AutoSize

Write-Host "`n===== ACCOUNTS WITH RISKY SETTINGS =====" -ForegroundColor Cyan
Get-ADUser -Filter {PasswordNeverExpires -eq $true -or PasswordNotRequired -eq $true} -Properties PasswordNeverExpires,PasswordNotRequired | Select-Object Name,SamAccountName,PasswordNeverExpires,PasswordNotRequired | Format-Table -AutoSize

Write-Host "`n===== SCHEDULED TASKS (backdoors hide here) =====" -ForegroundColor Cyan
Get-ScheduledTask | Where-Object State -ne Disabled | Select-Object TaskName,TaskPath,State | Format-Table -AutoSize

Write-Host "`n===== SERVICES (check the path + who it runs as) =====" -ForegroundColor Cyan
Get-CimInstance Win32_Service | Select-Object Name,StartName,StartMode,State,PathName | Format-Table -AutoSize

Write-Host "`n===== STARTUP ITEMS =====" -ForegroundColor Cyan
Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location | Format-Table -AutoSize

Write-Host "`n===== REGISTRY RUN KEYS =====" -ForegroundColor Cyan
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

Write-Host "`n===== DNS: FORWARDERS + ZONES (look for ones you didn't add) =====" -ForegroundColor Cyan
Get-DnsServerForwarder
Get-DnsServerZone | Format-Table -AutoSize

Write-Host "`n===== LISTENING PORTS (just a count, so you know it's not empty) =====" -ForegroundColor Cyan
(netstat -ano | Select-String "LISTENING").Count

Write-Host "`n===== ACTIVE CONNECTIONS (the part worth actually checking) =====" -ForegroundColor Cyan
netstat -ano | Select-String "ESTABLISHED"

Write-Host "`n===== DONE. Saved to Desktop\recon_output.txt =====" -ForegroundColor Green
Stop-Transcript

------------------