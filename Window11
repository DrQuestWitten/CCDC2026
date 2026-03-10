<#
.SYNOPSIS
  Harden Windows 11 workstation for an AD + IIS Web + FTP server lab environment (defensive).
.DESCRIPTION
  - Supports Audit (WhatIf) and Apply modes
  - Creates a restore point (when possible)
  - Writes a log file
  - Hardens Defender, firewall, SMB, credential protections, logging, and attack surface
.PARAMETER Mode
  Audit = preview (WhatIf). Apply = make changes.
.PARAMETER DomainName
  AD domain name (e.g., example.local). Optional but recommended.
.PARAMETER DC
  Domain Controller IP/hostname (for allowlisting).
.PARAMETER Web
  Web server IP/hostname (for allowlisting).
.PARAMETER FTP
  FTP server IP/hostname (for allowlisting).
.PARAMETER AllowRDP
  If set, allows inbound RDP from specified management subnets only (default OFF).
.PARAMETER MgmtSubnets
  Subnets allowed to RDP in if AllowRDP is set. Default: none.
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
  [ValidateSet("Audit","Apply")]
  [string]$Mode = "Audit",

  [string]$DomainName = "",
  [Parameter(Mandatory=$true)][string]$DC,
  [Parameter(Mandatory=$true)][string]$Web,
  [Parameter(Mandatory=$true)][string]$FTP,

  [switch]$AllowRDP,
  [string[]]$MgmtSubnets = @()
)

# -------------------------
# Helpers
# -------------------------
$ErrorActionPreference = "Stop"
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogDir = "C:\Hardening"
$LogFile = Join-Path $LogDir "Harden-Workstation-$stamp.log"

if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }

Start-Transcript -Path $LogFile -Append | Out-Null

function Write-Info($msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }

function Set-RegDword($Path,$Name,$Value) {
  if ($PSCmdlet.ShouldProcess("$Path\$Name","Set DWORD=$Value")) {
    if (!(Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
  }
}

function Disable-FeatureIfExists($FeatureName) {
  $feature = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction SilentlyContinue
  if ($null -ne $feature -and $feature.State -ne "Disabled") {
    if ($PSCmdlet.ShouldProcess($FeatureName,"Disable Windows Optional Feature")) {
      Disable-WindowsOptionalFeature -Online -FeatureName $FeatureName -NoRestart | Out-Null
    }
  }
}

function Ensure-Service($Name,$StartupType,$State) {
  $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
  if ($null -eq $svc) { return }
  if ($PSCmdlet.ShouldProcess($Name,"Set service StartupType=$StartupType, State=$State")) {
    Set-Service -Name $Name -StartupType $StartupType
    if ($State -eq "Running") { Start-Service $Name -ErrorAction SilentlyContinue }
    if ($State -eq "Stopped") { Stop-Service $Name -Force -ErrorAction SilentlyContinue }
  }
}

# WhatIf behavior
if ($Mode -eq "Audit") {
  Write-Warn "MODE = Audit (WhatIf). No changes will be applied."
  $WhatIfPreference = $true
} else {
  Write-Info "MODE = Apply. Changes WILL be applied."
  $WhatIfPreference = $false
}

Write-Info "Logging to: $LogFile"

# -------------------------
# Pre-flight checks
# -------------------------
Write-Info "Pre-flight checks..."
$admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw "Run this script as Administrator." }

# Create restore point (may fail if disabled by policy)
try {
  if ($PSCmdlet.ShouldProcess("System Restore","Create restore point")) {
    Checkpoint-Computer -Description "Pre-Hardening $stamp" -RestorePointType "MODIFY_SETTINGS" | Out-Null
    Write-Ok "Restore point created."
  }
} catch {
  Write-Warn "Could not create restore point (often disabled). Continuing..."
}

# -------------------------
# 1) Windows Defender baseline + ASR
# -------------------------
Write-Info "Hardening Microsoft Defender..."

# Ensure Defender services (if present)
Ensure-Service -Name "WinDefend" -StartupType Automatic -State Running

if ($PSCmdlet.ShouldProcess("Defender","Enable real-time protections")) {
  Set-MpPreference -DisableRealtimeMonitoring $false
  Set-MpPreference -DisableBehaviorMonitoring $false
  Set-MpPreference -DisableIOAVProtection $false
  Set-MpPreference -DisableScriptScanning $false
  Set-MpPreference -PUAProtection Enabled
  Set-MpPreference -EnableControlledFolderAccess Enabled
}

# Enable Attack Surface Reduction rules (block common red-team tradecraft)
# Note: Some rules can be noisy in dev environments; set to "AuditMode" first if desired.
$asrRules = @{
  # Block Office from creating child processes
  "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = "Enabled"
  # Block credential stealing from LSASS
  "9E6A2F5D-88A8-4E10-8C45-2F7C5B5B1F7E" = "Enabled"
  # Block executable content from email/webmail
  "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = "Enabled"
  # Block process creation from PSExec/WMI (useful against lateral movement)
  "D1E49AAC-8F56-4280-B9BA-993A6D77406C" = "Enabled"
  # Block untrusted/unsigned processes from USB
  "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" = "Enabled"
}

if ($PSCmdlet.ShouldProcess("Defender","Apply ASR rules")) {
  $ids   = $asrRules.Keys
  $modes = $asrRules.Values
  Set-MpPreference -AttackSurfaceReductionRules_Ids $ids -AttackSurfaceReductionRules_Actions $modes
}

Write-Ok "Defender hardened (CFA + PUA + ASR)."

# -------------------------
# 2) Credential hardening
# -------------------------
Write-Info "Hardening credentials and logon protections..."

# Enable LSA protection (RunAsPPL)
Set-RegDword "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL" 1

# Disable WDigest (prevents plaintext creds in memory)
Set-RegDword "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential" 0

# Reduce credential caching (set to 0–2 based on offline needs; 2 is a reasonable compromise)
Set-RegDword "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "CachedLogonsCount" 2

Write-Ok "Credential protections applied."

# -------------------------
# 3) Network name resolution hardening (LLMNR / NBNS)
# -------------------------
Write-Info "Hardening name resolution (prevents spoofing like Responder attacks)..."

# Disable LLMNR
Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" 0

# Disable NetBIOS over TCP/IP on all adapters (NBNS)
# WARNING: may break old legacy discovery in flat networks.
try {
  $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE"
  foreach ($a in $adapters) {
    if ($PSCmdlet.ShouldProcess($a.Description,"Disable NetBIOS over TCP/IP")) {
      $null = $a.SetTcpipNetbios(2)  # 2 = Disable
    }
  }
  Write-Ok "LLMNR disabled; NetBIOS disabled on adapters."
} catch {
  Write-Warn "Could not set NetBIOS settings via WMI. Continuing..."
}

# -------------------------
# 4) SMB hardening
# -------------------------
Write-Info "Hardening SMB..."

# Disable SMBv1 client
Disable-FeatureIfExists "SMB1Protocol"

# Require SMB signing (client)
Set-RegDword "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature" 1
Set-RegDword "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "EnableSecuritySignature" 1

Write-Ok "SMB hardened (SMBv1 off, signing required)."

# -------------------------
# 5) Windows Firewall: default deny inbound, allow necessary
# -------------------------
Write-Info "Configuring Windows Firewall..."

if ($PSCmdlet.ShouldProcess("Firewall","Set profiles & logging")) {
  foreach ($profile in @("Domain","Private","Public")) {
    Set-NetFirewallProfile -Profile $profile -Enabled True `
      -DefaultInboundAction Block -DefaultOutboundAction Allow `
      -NotifyOnListen True `
      -LogAllowed True -LogBlocked True `
      -LogFileName "C:\Hardening\pfirewall.log" -LogMaxSizeKilobytes 32767
  }
}

# Outbound allowlisting is optional; by default we keep outbound allow (to reduce breakage).
# But we DO explicitly allow the known server flows and ensure required Windows traffic isn’t blocked by custom rules.

# Allow DNS + Kerberos + LDAP + SMB to DC (domain operations)
$dcRules = @(
  @{Name="Allow-DC-DNS";     Proto="UDP"; Ports="53";  Remote=$DC},
  @{Name="Allow-DC-DNS-TCP"; Proto="TCP"; Ports="53";  Remote=$DC},
  @{Name="Allow-DC-Kerberos";Proto="TCP"; Ports="88";  Remote=$DC},
  @{Name="Allow-DC-Kerberos-UDP";Proto="UDP"; Ports="88"; Remote=$DC},
  @{Name="Allow-DC-LDAP";    Proto="TCP"; Ports="389"; Remote=$DC},
  @{Name="Allow-DC-LDAPS";   Proto="TCP"; Ports="636"; Remote=$DC},
  @{Name="Allow-DC-GC";      Proto="TCP"; Ports="3268";Remote=$DC},
  @{Name="Allow-DC-SMB";     Proto="TCP"; Ports="445"; Remote=$DC},
  @{Name="Allow-DC-Kpasswd"; Proto="TCP"; Ports="464"; Remote=$DC},
  @{Name="Allow-DC-Kpasswd-UDP";Proto="UDP"; Ports="464"; Remote=$DC}
)

# Allow web to web server
$webRules = @(
  @{Name="Allow-Web-HTTP";  Proto="TCP"; Ports="80";  Remote=$Web},
  @{Name="Allow-Web-HTTPS"; Proto="TCP"; Ports="443"; Remote=$Web}
)

# Allow FTP client to FTP server
# NOTE: Plain FTP uses 21 + dynamic data ports. Prefer FTPS/SFTP if possible.
# This rule allows control channel only. If you need passive FTP, you must allow the server’s passive port range too.
$ftpRules = @(
  @{Name="Allow-FTP-Control"; Proto="TCP"; Ports="21"; Remote=$FTP}
)

function Ensure-OutboundRule($r) {
  $existing = Get-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue
  if ($null -eq $existing) {
    if ($PSCmdlet.ShouldProcess($r.Name,"Create outbound firewall rule")) {
      New-NetFirewallRule -DisplayName $r.Name -Direction Outbound -Action Allow `
        -Protocol $r.Proto -RemoteAddress $r.Remote -RemotePort $r.Ports `
        -Profile Any | Out-Null
    }
  }
}

$dcRules  | ForEach-Object { Ensure-OutboundRule $_ }
$webRules | ForEach-Object { Ensure-OutboundRule $_ }
$ftpRules | ForEach-Object { Ensure-OutboundRule $_ }

# Inbound: block risky remote admin surfaces unless explicitly allowed
if (-not $AllowRDP) {
  if ($PSCmdlet.ShouldProcess("Firewall","Disable inbound RDP rules")) {
    Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue | Disable-NetFirewallRule -ErrorAction SilentlyContinue
  }
} else {
  if ($MgmtSubnets.Count -eq 0) { throw "AllowRDP was specified but no MgmtSubnets were provided." }
  if ($PSCmdlet.ShouldProcess("Firewall","Enable inbound RDP from management subnets only")) {
    Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue | Enable-NetFirewallRule -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName "Allow-RDP-From-Mgmt" -Direction Inbound -Action Allow `
      -Protocol TCP -LocalPort 3389 -RemoteAddress $MgmtSubnets -Profile Any | Out-Null
  }
}

Write-Ok "Firewall configured (inbound block; explicit outbound allows to DC/Web/FTP)."

# -------------------------
# 6) Remote management tightening (WinRM, RemoteRegistry)
# -------------------------
Write-Info "Tightening remote management services..."

# RemoteRegistry is rarely needed on endpoints
Ensure-Service -Name "RemoteRegistry" -StartupType Disabled -State Stopped

# WinRM: set to Manual unless you rely on it
# If your management requires WinRM, change to Automatic and restrict firewall.
Ensure-Service -Name "WinRM" -StartupType Manual -State Stopped

Write-Ok "Remote management tightened (RemoteRegistry off, WinRM manual/stopped)."

# -------------------------
# 7) Local security / UAC / basic policies
# -------------------------
Write-Info "Applying baseline local security policies..."

# UAC hardening
Set-RegDword "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA" 1
Set-RegDword "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin" 2  # Prompt on secure desktop
Set-RegDword "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "PromptOnSecureDesktop" 1

# Disable anonymous enumeration
Set-RegDword "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous" 1
Set-RegDword "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymousSAM" 1

Write-Ok "UAC and anonymous access hardened."

# -------------------------
# 8) Audit policy (visibility)
# -------------------------
Write-Info "Enabling advanced audit policy categories..."
if ($PSCmdlet.ShouldProcess("Audit Policy","Enable common categories")) {
  auditpol /set /category:"Account Logon" /success:enable /failure:enable | Out-Null
  auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable | Out-Null
  auditpol /set /category:"Account Management" /success:enable /failure:enable | Out-Null
  auditpol /set /category:"Policy Change" /success:enable /failure:enable | Out-Null
  auditpol /set /category:"Privilege Use" /success:enable /failure:enable | Out-Null
  auditpol /set /category:"System" /success:enable /failure:enable | Out-Null
  auditpol /set /category:"Object Access" /success:enable /failure:enable | Out-Null
  auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable | Out-Null
}

# Enable command-line logging for process creation (4688 includes cmdline)
Set-RegDword "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" "ProcessCreationIncludeCmdLine_Enabled" 1

Write-Ok "Audit policy enabled (including process creation cmdline)."

# -------------------------
# 9) Windows Update basics
# -------------------------
Write-Info "Ensuring Windows Update services are enabled..."
Ensure-Service -Name "wuauserv" -StartupType Manual -State Running
Ensure-Service -Name "UsoSvc"   -StartupType Automatic -State Running

Write-Ok "Update services enabled (does not force immediate updates)."

# -------------------------
# 10) Summary + next steps
# -------------------------
Write-Info "Hardening complete (Mode=$Mode)."

Write-Host ""
Write-Host "Review logs: $LogFile" -ForegroundColor Magenta
Write-Host "Firewall log: C:\Hardening\pfirewall.log" -ForegroundColor Magenta
Write-Host ""

Write-Warn "Some changes require restart to fully apply (SMB features, LSA protections). Reboot recommended."

Stop-Transcript | Out-Null
