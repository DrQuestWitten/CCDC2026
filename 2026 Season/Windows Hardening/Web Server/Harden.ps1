# ============================================
# Windows IIS Web Server Hardening Baseline
# No Helper Functions Version
# Competition-Friendly Site Handling
# ============================================

$ErrorActionPreference = "Stop"

# -----------------------------
# Admin Check
# -----------------------------
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentUser)

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this script in an elevated PowerShell session."
    exit 1
}

# -----------------------------
# Start Logging
# -----------------------------
$logDir = "C:\HardeningLogs"
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

$transcript = Join-Path $logDir ("IIS_Hardening_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
Start-Transcript -Path $transcript -Force

try {
    Write-Host "`n[+] Importing IIS module" -ForegroundColor Cyan
    Import-Module WebAdministration -ErrorAction Stop

    # -----------------------------
    # Backup IIS Configuration
    # -----------------------------
    Write-Host "`n[+] Backing up IIS configuration" -ForegroundColor Cyan
    $backupName = "PreHardening_{0}" -f (Get-Date -Format "yyyyMMdd_HHmmss")
    & "$env:WinDir\System32\inetsrv\appcmd.exe" add backup $backupName | Out-Null

    # -----------------------------
    # Disable Directory Browsing
    # -----------------------------
    Write-Host "`n[+] Disabling directory browsing" -ForegroundColor Cyan
    try {
        Set-WebConfigurationProperty -PSPath "IIS:\" -Filter "system.webServer/directoryBrowse" -Name "enabled" -Value $false
    }
    catch {
        Write-Warning "Could not disable directory browsing. $_"
    }

    # -----------------------------
    # Remove X-Powered-By Header
    # -----------------------------
    Write-Host "`n[+] Removing X-Powered-By header" -ForegroundColor Cyan
    try {
        Remove-WebConfigurationProperty `
            -PSPath "IIS:\" `
            -Filter "system.webServer/httpProtocol/customHeaders" `
            -Name "." `
            -AtElement @{name='X-Powered-By'} `
            -ErrorAction SilentlyContinue
    }
    catch {
        Write-Warning "Could not remove X-Powered-By header. $_"
    }

    # -----------------------------
    # Remove Server Header
    # -----------------------------
    Write-Host "`n[+] Attempting to remove Server header" -ForegroundColor Cyan
    try {
        Set-WebConfigurationProperty `
            -PSPath "IIS:\" `
            -Filter "system.webServer/security/requestFiltering" `
            -Name "removeServerHeader" `
            -Value $true
    }
    catch {
        Write-Warning "removeServerHeader may not be supported on this IIS version. $_"
    }

    # -----------------------------
    # Request Filtering
    # -----------------------------
    Write-Host "`n[+] Configuring request filtering" -ForegroundColor Cyan
    try {
        Set-WebConfigurationProperty `
            -PSPath "IIS:\" `
            -Filter "system.webServer/security/requestFiltering" `
            -Name "allowDoubleEscaping" `
            -Value $false
    }
    catch {
        Write-Warning "Could not set allowDoubleEscaping. $_"
    }

    try {
        Set-WebConfigurationProperty `
            -PSPath "IIS:\" `
            -Filter "system.webServer/security/requestFiltering/requestLimits" `
            -Name "maxAllowedContentLength" `
            -Value 31457280
    }
    catch {
        Write-Warning "Could not set maxAllowedContentLength. $_"
    }

    # -----------------------------
    # Deny URL Sequences
    # -----------------------------
    Write-Host "`n[+] Adding denied URL sequences" -ForegroundColor Cyan
    try {
        Add-WebConfigurationProperty `
            -PSPath "IIS:\" `
            -Filter "system.webServer/security/requestFiltering/denyUrlSequences" `
            -Name "." `
            -Value @{sequence=".."} `
            -ErrorAction SilentlyContinue
    }
    catch {
        Write-Warning "Could not add denied URL sequence '..'. $_"
    }

    # -----------------------------
    # Hidden Segments
    # -----------------------------
    Write-Host "`n[+] Adding hidden segments" -ForegroundColor Cyan
    $hiddenSegments = @("bin", "App_Data", "App_Code", ".git")

    foreach ($segment in $hiddenSegments) {
        try {
            Add-WebConfigurationProperty `
                -PSPath "IIS:\" `
                -Filter "system.webServer/security/requestFiltering/hiddenSegments" `
                -Name "." `
                -Value @{segment=$segment} `
                -ErrorAction SilentlyContinue
        }
        catch {
            Write-Warning "Could not add hidden segment $segment. $_"
        }
    }

    # -----------------------------
    # Deny Sensitive File Extensions
    # -----------------------------
    Write-Host "`n[+] Denying sensitive file extensions" -ForegroundColor Cyan
    $denyExtensions = @(
        ".config", ".bak", ".old", ".cmd", ".bat", ".ps1", ".sql",
        ".zip", ".7z", ".tar", ".gz", ".log", ".ini"
    )

    foreach ($ext in $denyExtensions) {
        try {
            Add-WebConfigurationProperty `
                -PSPath "IIS:\" `
                -Filter "system.webServer/security/requestFiltering/fileExtensions" `
                -Name "." `
                -Value @{fileExtension=$ext; allowed=$false} `
                -ErrorAction SilentlyContinue
        }
        catch {
            Write-Warning "Could not deny extension $ext. $_"
        }
    }

    # -----------------------------
    # Configure IIS Logging for All Sites
    # -----------------------------
    Write-Host "`n[+] Configuring IIS logging for all sites" -ForegroundColor Cyan
    try {
        $sites = Get-ChildItem IIS:\Sites

        foreach ($site in $sites) {
            Write-Host "    -> Configuring logging for site: $($site.Name)" -ForegroundColor Yellow

            try {
                Set-ItemProperty "IIS:\Sites\$($site.Name)" -Name logfile.logFormat -Value "W3C" -ErrorAction SilentlyContinue
                Set-ItemProperty "IIS:\Sites\$($site.Name)" -Name logfile.period -Value "Daily" -ErrorAction SilentlyContinue
                Set-ItemProperty "IIS:\Sites\$($site.Name)" -Name logfile.directory -Value "C:\inetpub\logs\LogFiles" -ErrorAction SilentlyContinue
            }
            catch {
                Write-Warning "Could not fully configure logging for site $($site.Name). $_"
            }
        }
    }
    catch {
        Write-Warning "Could not enumerate IIS sites for logging configuration. $_"
    }

    # -----------------------------
    # Disable WebDAV
    # -----------------------------
    Write-Host "`n[+] Disabling WebDAV if present" -ForegroundColor Cyan
    try {
        Set-WebConfigurationProperty `
            -PSPath "IIS:\" `
            -Filter "system.webServer/webdav/authoring" `
            -Name "enabled" `
            -Value $false `
            -ErrorAction SilentlyContinue
    }
    catch {
        Write-Warning "Could not disable WebDAV authoring. $_"
    }

    try {
        Disable-WebGlobalModule -Name "WebDAVModule" -ErrorAction SilentlyContinue
    }
    catch {
        Write-Warning "Could not disable WebDAV module. $_"
    }

    # -----------------------------
    # TLS / SSL Hardening
    # -----------------------------
    Write-Host "`n[+] Disabling old SSL/TLS protocols and enabling TLS 1.2" -ForegroundColor Cyan
    $protocolBase = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

    if (-not (Test-Path "$protocolBase\SSL 2.0\Server")) { New-Item -Path "$protocolBase\SSL 2.0\Server" -Force | Out-Null }
    New-ItemProperty -Path "$protocolBase\SSL 2.0\Server" -Name "Enabled" -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path "$protocolBase\SSL 2.0\Server" -Name "DisabledByDefault" -Value 1 -PropertyType DWord -Force | Out-Null

    if (-not (Test-Path "$protocolBase\SSL 2.0\Client")) { New-Item -Path "$protocolBase\SSL 2.0\Client" -Force | Out-Null }
    New-ItemProperty -Path "$protocolBase\SSL 2.0\Client" -Name "Enabled" -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path "$protocolBase\SSL 2.0\Client" -Name "DisabledByDefault" -Value 1 -PropertyType DWord -Force | Out-Null

    if (-not (Test-Path "$protocolBase\SSL 3.0\Server")) { New-Item -Path "$protocolBase\SSL 3.0\Server" -Force | Out-Null }
    New-ItemProperty -Path "$protocolBase\SSL 3.0\Server" -Name "Enabled" -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path "$protocolBase\SSL 3.0\Server" -Name "DisabledByDefault" -Value 1 -PropertyType DWord -Force | Out-Null

    if (-not (Test-Path "$protocolBase\SSL 3.0\Client")) { New-Item -Path "$protocolBase\SSL 3.0\Client" -Force | Out-Null }
    New-ItemProperty -Path "$protocolBase\SSL 3.0\Client" -Name "Enabled" -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path "$protocolBase\SSL 3.0\Client" -Name "DisabledByDefault" -Value 1 -PropertyType DWord -Force | Out-Null

    if (-not (Test-Path "$protocolBase\TLS 1.0\Server")) { New-Item -Path "$protocolBase\TLS 1.0\Server" -Force | Out-Null }
    New-ItemProperty -Path "$protocolBase\TLS 1.0\Server" -Name "Enabled" -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path "$protocolBase\TLS 1.0\Server" -Name "DisabledByDefault" -Value 1 -PropertyType DWord -Force | Out-Null

    if (-not (Test-Path "$protocolBase\TLS 1.0\Client")) { New-Item -Path "$protocolBase\TLS 1.0\Client" -Force | Out-Null }
    New-ItemProperty -Path "$protocolBase\TLS 1.0\Client" -Name "Enabled" -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path "$protocolBase\TLS 1.0\Client" -Name "DisabledByDefault" -Value 1 -PropertyType DWord -Force | Out-Null

    if (-not (Test-Path "$protocolBase\TLS 1.1\Server")) { New-Item -Path "$protocolBase\TLS 1.1\Server" -Force | Out-Null }
    New-ItemProperty -Path "$protocolBase\TLS 1.1\Server" -Name "Enabled" -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path "$protocolBase\TLS 1.1\Server" -Name "DisabledByDefault" -Value 1 -PropertyType DWord -Force | Out-Null

    if (-not (Test-Path "$protocolBase\TLS 1.1\Client")) { New-Item -Path "$protocolBase\TLS 1.1\Client" -Force | Out-Null }
    New-ItemProperty -Path "$protocolBase\TLS 1.1\Client" -Name "Enabled" -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path "$protocolBase\TLS 1.1\Client" -Name "DisabledByDefault" -Value 1 -PropertyType DWord -Force | Out-Null

    if (-not (Test-Path "$protocolBase\TLS 1.2\Server")) { New-Item -Path "$protocolBase\TLS 1.2\Server" -Force | Out-Null }
    New-ItemProperty -Path "$protocolBase\TLS 1.2\Server" -Name "Enabled" -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path "$protocolBase\TLS 1.2\Server" -Name "DisabledByDefault" -Value 0 -PropertyType DWord -Force | Out-Null

    if (-not (Test-Path "$protocolBase\TLS 1.2\Client")) { New-Item -Path "$protocolBase\TLS 1.2\Client" -Force | Out-Null }
    New-ItemProperty -Path "$protocolBase\TLS 1.2\Client" -Name "Enabled" -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path "$protocolBase\TLS 1.2\Client" -Name "DisabledByDefault" -Value 0 -PropertyType DWord -Force | Out-Null

    # -----------------------------
    # Disable SMBv1
    # -----------------------------
    Write-Host "`n[+] Disabling SMBv1" -ForegroundColor Cyan
    try {
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
    }
    catch {
        Write-Warning "Could not disable SMB1 optional feature. $_"
    }

    try {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue | Out-Null
    }
    catch {
        Write-Warning "Could not disable SMB1 at SMB server configuration. $_"
    }

    # -----------------------------
    # Firewall Rules for Web
    # -----------------------------
    Write-Host "`n[+] Ensuring firewall rules exist for HTTP/HTTPS" -ForegroundColor Cyan
    try {
        if (-not (Get-NetFirewallRule -DisplayName "Allow HTTP 80 Inbound" -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule `
                -DisplayName "Allow HTTP 80 Inbound" `
                -Direction Inbound `
                -Protocol TCP `
                -LocalPort 80 `
                -Action Allow | Out-Null
        }

        if (-not (Get-NetFirewallRule -DisplayName "Allow HTTPS 443 Inbound" -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule `
                -DisplayName "Allow HTTPS 443 Inbound" `
                -Direction Inbound `
                -Protocol TCP `
                -LocalPort 443 `
                -Action Allow | Out-Null
        }
    }
    catch {
        Write-Warning "Could not create firewall rules for HTTP/HTTPS. $_"
    }

    # -----------------------------
    # Service Check
    # -----------------------------
    Write-Host "`n[+] Checking IIS services" -ForegroundColor Cyan
    Get-Service W3SVC, WAS | Select-Object Name, Status, StartType | Format-Table -AutoSize

    # -----------------------------
    # Restart IIS
    # -----------------------------
    Write-Host "`n[+] Restarting IIS" -ForegroundColor Cyan
    iisreset | Out-Null

    Write-Host "`n[+] Hardening complete" -ForegroundColor Green
    Write-Host "Log file: $transcript" -ForegroundColor Green
    Write-Host "IIS backup: $backupName" -ForegroundColor Green
    Write-Host "Reboot recommended for TLS/SMB changes to fully apply." -ForegroundColor Yellow
}
catch {
    Write-Error $_
}
finally {
    Stop-Transcript | Out-Null
}