# FTP-CCDC-Audit-Hardening.ps1
# Windows Server 2022 IIS FTP - CCDC focused audit/hardening helper
# Run as Administrator

Import-Module ServerManager -ErrorAction SilentlyContinue
Import-Module WebAdministration -ErrorAction SilentlyContinue

$ErrorActionPreference = "Continue"

# =========================
# CONFIG
# =========================
$ApplyChanges = $false
$PassivePortRange = "50000-51000"
$FTPControlPort = 21
$LogRoot = "C:\HardeningReports"
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$ReportFile = Join-Path $LogRoot "FTP-CCDC-Report-$Timestamp.txt"

# suspicious extensions commonly abused by red team
$SuspiciousExtensions = @(
    ".aspx", ".asp", ".php", ".jsp", ".jspx", ".ashx",
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".hta", ".scr", ".msi", ".zip", ".7z", ".rar"
)

# how many recent files to show
$RecentFileCount = 30

# =========================
# PREP
# =========================
if (-not (Test-Path $LogRoot)) {
    New-Item -Path $LogRoot -ItemType Directory -Force | Out-Null
}

function Write-Report {
    param([string]$Text)
    $Text | Tee-Object -FilePath $ReportFile -Append
}

function Write-Section {
    param([string]$Title)
    Write-Report ""
    Write-Report ("=" * 70)
    Write-Report $Title
    Write-Report ("=" * 70)
}

Write-Report "FTP CCDC AUDIT / HARDENING REPORT"
Write-Report "Generated: $(Get-Date)"
Write-Report "ApplyChanges: $ApplyChanges"

# =========================
# SECTION 1 - CRITICAL SERVICES MUST NOT BREAK
# =========================
Write-Section "SECTION 1 - CRITICAL SERVICES (MUST NOT BREAK)"

# 1A. FTP service status
try {
    $ftpSvc = Get-Service ftpsvc -ErrorAction Stop
    $ftpCim = Get-CimInstance Win32_Service -Filter "Name='ftpsvc'"
    Write-Report "FTP Service Name: $($ftpSvc.Name)"
    Write-Report "FTP Service Status: $($ftpSvc.Status)"
    Write-Report "FTP Service StartMode: $($ftpCim.StartMode)"

    if ($ApplyChanges -and $ftpCim.StartMode -ne "Auto") {
        Set-Service ftpsvc -StartupType Automatic
        Write-Report "Changed ftpsvc startup type to Automatic"
    }
} catch {
    Write-Report "WARNING: FTP service ftpsvc not found or inaccessible. $($_.Exception.Message)"
}

# 1B. FTP sites
$ftpSites = @()
try {
    $ftpSites = Get-ChildItem IIS:\Sites | Where-Object {
        try { $_.Bindings.Collection.protocol -contains "ftp" } catch { $false }
    }

    if (-not $ftpSites -or $ftpSites.Count -eq 0) {
        Write-Report "WARNING: No FTP sites found in IIS."
    } else {
        foreach ($site in $ftpSites) {
            Write-Report "FTP Site: $($site.Name)"
            Write-Report "  State: $($site.State)"
            Write-Report "  PhysicalPath: $($site.physicalPath)"
            foreach ($binding in $site.Bindings.Collection) {
                if ($binding.protocol -eq "ftp") {
                    Write-Report "  Binding: $($binding.bindingInformation)"
                }
            }
        }
    }
} catch {
    Write-Report "WARNING: Could not enumerate FTP sites. $($_.Exception.Message)"
}

# 1C. Port listeners
try {
    Write-Report "Port listener check:"
    $listeners = netstat -ano | Select-String ":21 "
    if ($listeners) {
        $listeners | ForEach-Object { Write-Report $_.Line }
    } else {
        Write-Report "WARNING: No listener found on port 21"
    }
} catch {
    Write-Report "WARNING: Could not check port listeners. $($_.Exception.Message)"
}

# =========================
# SECTION 2 - MANUAL HEALTH VERIFICATION REMINDER
# =========================
Write-Section "SECTION 2 - MANUAL HEALTH VERIFICATION (YOU MUST TEST MANUALLY)"
Write-Report "The script cannot safely prove business functionality."
Write-Report "After changes, manually verify from a client:"
Write-Report "  1. FTP service is reachable"
Write-Report "  2. Login works"
Write-Report "  3. Directory listing works if business requires it"
Write-Report "  4. Upload works if business requires it"
Write-Report "  5. Download works"
Write-Report "  6. FTPS works if required"

# =========================
# SECTION 3 - AUTHENTICATION / ANONYMOUS ACCESS
# =========================
Write-Section "SECTION 3 - AUTHENTICATION / ANONYMOUS ACCESS"

foreach ($site in $ftpSites) {
    $siteName = $site.Name
    $psPath = "IIS:\Sites\$siteName"
    Write-Report "Checking authentication for site: $siteName"

    try {
        $basicFilter = "/system.ftpServer/security/authentication/basicAuthentication"
        $anonFilter  = "/system.ftpServer/security/authentication/anonymousAuthentication"

        $basicEnabled = (Get-WebConfigurationProperty -PSPath $psPath -Filter $basicFilter -Name enabled).Value
        $anonEnabled  = (Get-WebConfigurationProperty -PSPath $psPath -Filter $anonFilter  -Name enabled).Value

        Write-Report "  Before: Basic=$basicEnabled Anonymous=$anonEnabled"

        if ($ApplyChanges) {
            if ($anonEnabled -eq $false) {
                Set-WebConfigurationProperty -PSPath $psPath -Filter $anonFilter -Name enabled -Value $true
                Write-Report "  Changed: Anonymous Authentication enabled"
            }
            if ($basicEnabled -eq $false) {
                Set-WebConfigurationProperty -PSPath $psPath -Filter $basicFilter -Name enabled -Value $true
                Write-Report "  Changed: Basic Authentication enabled"
            }
        }

        $basicAfter = (Get-WebConfigurationProperty -PSPath $psPath -Filter $basicFilter -Name enabled).Value
        $anonAfter  = (Get-WebConfigurationProperty -PSPath $psPath -Filter $anonFilter  -Name enabled).Value
        Write-Report "  After: Basic=$basicAfter Anonymous=$anonAfter"

        # Anonymous is now intentionally allowed
        # if ($anonAfter -eq $true) {
        #     Write-Report "  WARNING: Anonymous authentication is still enabled."
        # }
    } catch {
        Write-Report "  WARNING: Authentication audit failed. $($_.Exception.Message)"
    }
}

# =========================
# SECTION 4 - FTP AUTHORIZATION RULES / BACKDOOR FTP USER HUNT
# =========================
Write-Section "SECTION 4 - FTP AUTHORIZATION RULES / BACKDOOR FTP USER HUNT"

$allAuthorizedPrincipals = New-Object System.Collections.Generic.List[string]

foreach ($site in $ftpSites) {
    $siteName = $site.Name
    $psPath = "IIS:\Sites\$siteName"
    Write-Report "Authorization rules for site: $siteName"

    try {
        $authz = Get-WebConfiguration -PSPath $psPath -Filter "/system.ftpServer/security/authorization"

        if ($authz.Collection.Count -eq 0) {
            Write-Report "  WARNING: No FTP authorization rules found."
        } else {
            foreach ($rule in $authz.Collection) {
                $line = "  accessType=$($rule.accessType) users=$($rule.users) roles=$($rule.roles) permissions=$($rule.permissions)"
                Write-Report $line

                if ($rule.users) { [void]$allAuthorizedPrincipals.Add($rule.users) }
                if ($rule.roles) { [void]$allAuthorizedPrincipals.Add($rule.roles) }

                if ($rule.users -match "All Users|\*" -or $rule.roles -match "Everyone|Users|Authenticated Users|Domain Users") {
                    Write-Report "  WARNING: Broad FTP authorization principal detected."
                }

                if ($rule.permissions -match "Write") {
                    Write-Report "  NOTE: Write permission exists in FTP authorization. Confirm this is required."
                }
            }
        }
    } catch {
        Write-Report "  WARNING: Could not audit authorization rules. $($_.Exception.Message)"
    }
}

# =========================
# SECTION 5 - LOCAL USERS / GROUPS / ADMINS
# =========================
Write-Section "SECTION 5 - LOCAL USERS / GROUPS / ADMINS"

try {
    Write-Report "Local users:"
    Get-LocalUser | Sort-Object Name | ForEach-Object {
        Write-Report ("  User={0} Enabled={1} LastLogon={2}" -f $_.Name, $_.Enabled, $_.LastLogon)
    }
} catch {
    Write-Report "WARNING: Could not enumerate local users. $($_.Exception.Message)"
}

try {
    Write-Report "Local groups:"
    Get-LocalGroup | Sort-Object Name | ForEach-Object {
        Write-Report ("  Group={0}" -f $_.Name)
    }
} catch {
    Write-Report "WARNING: Could not enumerate local groups. $($_.Exception.Message)"
}

try {
    Write-Report "Local Administrators group members:"
    Get-LocalGroupMember -Group "Administrators" | ForEach-Object {
        Write-Report ("  {0} ({1})" -f $_.Name, $_.ObjectClass)
    }
} catch {
    Write-Report "WARNING: Could not enumerate local Administrators members. $($_.Exception.Message)"
}

try {
    Write-Report "Users in built-in FTP-related groups if present:"
    $candidateGroups = @("IIS_IUSRS","Users","Remote Desktop Users")
    foreach ($groupName in $candidateGroups) {
        try {
            $group = Get-LocalGroup -Name $groupName -ErrorAction Stop
            Write-Report "  Group: $groupName"
            Get-LocalGroupMember -Group $groupName -ErrorAction SilentlyContinue | ForEach-Object {
                Write-Report ("    {0} ({1})" -f $_.Name, $_.ObjectClass)
            }
        } catch {}
    }
} catch {
    Write-Report "WARNING: Could not enumerate FTP-adjacent groups. $($_.Exception.Message)"
}

if ($allAuthorizedPrincipals.Count -gt 0) {
    Write-Report "FTP authorization principals observed:"
    $allAuthorizedPrincipals | Sort-Object -Unique | ForEach-Object {
        Write-Report "  $_"
    }
}

# =========================
# SECTION 6 - FTPS / SSL
# =========================
Write-Section "SECTION 6 - FTPS / SSL"

foreach ($site in $ftpSites) {
    $siteName = $site.Name
    $psPath = "IIS:\Sites\$siteName"
    Write-Report "SSL settings for site: $siteName"

    try {
        $controlPolicy = (Get-WebConfigurationProperty -PSPath $psPath -Filter "/system.ftpServer/security/ssl" -Name controlChannelPolicy).Value
        $dataPolicy    = (Get-WebConfigurationProperty -PSPath $psPath -Filter "/system.ftpServer/security/ssl" -Name dataChannelPolicy).Value
        $certHash      = (Get-WebConfigurationProperty -PSPath $psPath -Filter "/system.applicationHost/sites/site[@name='$siteName']/ftpServer/security/ssl" -Name serverCertHash -ErrorAction SilentlyContinue).Value

        Write-Report "  controlChannelPolicy=$controlPolicy"
        Write-Report "  dataChannelPolicy=$dataPolicy"
        Write-Report "  serverCertHash=$certHash"

        if ([string]::IsNullOrWhiteSpace($certHash)) {
            Write-Report "  WARNING: No FTP certificate bound."
        }
        if ($controlPolicy -eq "SslAllow" -or $dataPolicy -eq "SslAllow") {
            Write-Report "  NOTE: SSL is allowed but not required."
        }
    } catch {
        Write-Report "  WARNING: Could not audit SSL settings. $($_.Exception.Message)"
    }
}

# =========================
# SECTION 7 - PASSIVE MODE / FIREWALL
# =========================
Write-Section "SECTION 7 - PASSIVE MODE / FIREWALL"

try {
    $globalPSPath = "MACHINE/WEBROOT/APPHOST"
    $lowPort  = (Get-WebConfigurationProperty -PSPath $globalPSPath -Filter "/system.ftpServer/firewallSupport" -Name lowDataChannelPort).Value
    $highPort = (Get-WebConfigurationProperty -PSPath $globalPSPath -Filter "/system.ftpServer/firewallSupport" -Name highDataChannelPort).Value

    Write-Report "Configured passive range before changes: $lowPort-$highPort"

    $rangeParts = $PassivePortRange.Split("-")
    $newLow = [int]$rangeParts[0]
    $newHigh = [int]$rangeParts[1]

    if ($ApplyChanges) {
        Set-WebConfigurationProperty -PSPath $globalPSPath -Filter "/system.ftpServer/firewallSupport" -Name lowDataChannelPort -Value $newLow
        Set-WebConfigurationProperty -PSPath $globalPSPath -Filter "/system.ftpServer/firewallSupport" -Name highDataChannelPort -Value $newHigh
        Write-Report "Changed passive range to: $PassivePortRange"
    }

    $lowAfter  = (Get-WebConfigurationProperty -PSPath $globalPSPath -Filter "/system.ftpServer/firewallSupport" -Name lowDataChannelPort).Value
    $highAfter = (Get-WebConfigurationProperty -PSPath $globalPSPath -Filter "/system.ftpServer/firewallSupport" -Name highDataChannelPort).Value
    Write-Report "Configured passive range after changes: $lowAfter-$highAfter"
} catch {
    Write-Report "WARNING: Could not audit/set passive range. $($_.Exception.Message)"
}

try {
    $rule21 = Get-NetFirewallRule -DisplayName "FTP Control Port 21" -ErrorAction SilentlyContinue
    if ($ApplyChanges -and -not $rule21) {
        New-NetFirewallRule -DisplayName "FTP Control Port 21" -Direction Inbound -Protocol TCP -LocalPort $FTPControlPort -Action Allow | Out-Null
        Write-Report "Created firewall rule: FTP Control Port 21"
    }

    $rulePassive = Get-NetFirewallRule -DisplayName "FTP Passive Ports" -ErrorAction SilentlyContinue
    if ($ApplyChanges -and -not $rulePassive) {
        New-NetFirewallRule -DisplayName "FTP Passive Ports" -Direction Inbound -Protocol TCP -LocalPort $PassivePortRange -Action Allow | Out-Null
        Write-Report "Created firewall rule: FTP Passive Ports"
    }

    Write-Report "Firewall rules containing 'FTP':"
    Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*FTP*" } | ForEach-Object {
        Write-Report ("  {0} Enabled={1} Direction={2} Action={3}" -f $_.DisplayName, $_.Enabled, $_.Direction, $_.Action)
    }
} catch {
    Write-Report "WARNING: Could not audit/create FTP firewall rules. $($_.Exception.Message)"
}

# =========================
# SECTION 8 - LOGGING / AUDITING
# =========================
Write-Section "SECTION 8 - LOGGING / AUDITING"

foreach ($site in $ftpSites) {
    $siteName = $site.Name
    $psPath = "IIS:\Sites\$siteName"

    try {
        $logFormat = (Get-WebConfigurationProperty -PSPath $psPath -Filter "/system.applicationHost/sites/site[@name='$siteName']/logFile" -Name logFormat -ErrorAction SilentlyContinue).Value
        $logDir    = (Get-WebConfigurationProperty -PSPath $psPath -Filter "/system.applicationHost/sites/site[@name='$siteName']/logFile" -Name directory -ErrorAction SilentlyContinue).Value

        Write-Report "Site=$siteName LogFormat=$logFormat LogDirectory=$logDir"

        if ($ApplyChanges -and $logFormat -ne "W3C") {
            Set-WebConfigurationProperty -PSPath $psPath -Filter "/system.applicationHost/sites/site[@name='$siteName']/logFile" -Name logFormat -Value "W3C"
            Write-Report "Changed log format to W3C on $siteName"
        }
    } catch {
        Write-Report "WARNING: Could not audit logging on $siteName. $($_.Exception.Message)"
    }
}

try {
    if ($ApplyChanges) {
        auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
        auditpol /set /subcategory:"Account Logon" /success:enable /failure:enable | Out-Null
    }
    Write-Report "Audit policy snapshot:"
    (auditpol /get /subcategory:"Logon","Account Logon") | ForEach-Object { Write-Report $_ }
} catch {
    Write-Report "WARNING: Could not set/query audit policy. $($_.Exception.Message)"
}

# =========================
# SECTION 9 - NTFS / UNDERLYING STORAGE PERMISSIONS
# =========================
Write-Section "SECTION 9 - NTFS / UNDERLYING STORAGE PERMISSIONS"

foreach ($site in $ftpSites) {
    $siteName = $site.Name
    $physicalPath = $site.physicalPath

    Write-Report "NTFS audit for site: $siteName"
    Write-Report "  PhysicalPath: $physicalPath"

    try {
        if (-not (Test-Path $physicalPath)) {
            Write-Report "  WARNING: Physical path does not exist."
            continue
        }

        $acl = Get-Acl $physicalPath
        foreach ($ace in $acl.Access) {
            Write-Report ("  Identity={0} Rights={1} Type={2} Inherited={3}" -f `
                $ace.IdentityReference, $ace.FileSystemRights, $ace.AccessControlType, $ace.IsInherited)
        }

        $badEntries = $acl.Access | Where-Object {
            $_.IdentityReference -match "Everyone|Users|Authenticated Users|Domain Users"
        }

        if ($badEntries) {
            Write-Report "  WARNING: Broad principals detected on FTP root:"
            foreach ($entry in $badEntries) {
                Write-Report ("    {0} Rights={1} Type={2}" -f `
                    $entry.IdentityReference, $entry.FileSystemRights, $entry.AccessControlType)
            }
        }

        $writeBroad = $acl.Access | Where-Object {
            $_.IdentityReference -match "Everyone|Users|Authenticated Users|Domain Users" -and
            $_.FileSystemRights.ToString() -match "Write|Modify|FullControl"
        }

        if ($writeBroad) {
            Write-Report "  WARNING: Broad principal has write-capable rights. High risk for privilege escalation or malicious upload."
        }
    } catch {
        Write-Report "  WARNING: Could not audit NTFS permissions. $($_.Exception.Message)"
    }
}

# =========================
# SECTION 10 - MALICIOUS UPLOAD / WEBSHELL HUNT
# =========================
Write-Section "SECTION 10 - MALICIOUS UPLOAD / WEBSHELL HUNT"

foreach ($site in $ftpSites) {
    $siteName = $site.Name
    $physicalPath = $site.physicalPath
    Write-Report "Malicious file hunt for site: $siteName"
    Write-Report "  Path: $physicalPath"

    try {
        if (-not (Test-Path $physicalPath)) {
            Write-Report "  WARNING: Path does not exist."
            continue
        }

        Write-Report "  Recent files:"
        Get-ChildItem -Path $physicalPath -Recurse -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First $RecentFileCount |
            ForEach-Object {
                Write-Report ("    {0} | {1} | {2} bytes" -f $_.LastWriteTime, $_.FullName, $_.Length)
            }

        Write-Report "  Suspicious extension hits:"
        $hits = Get-ChildItem -Path $physicalPath -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $SuspiciousExtensions -contains $_.Extension.ToLower() }

        if ($hits) {
            foreach ($file in $hits) {
                Write-Report ("    HIT: {0} | {1} | {2} bytes" -f $file.LastWriteTime, $file.FullName, $file.Length)
            }
        } else {
            Write-Report "    No suspicious extension hits found."
        }

        Write-Report "  Hidden files:"
        $hidden = Get-ChildItem -Path $physicalPath -Recurse -Force -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Attributes -match "Hidden" }

        if ($hidden) {
            foreach ($file in $hidden) {
                Write-Report ("    HIDDEN: {0} | {1}" -f $file.LastWriteTime, $file.FullName)
            }
        } else {
            Write-Report "    No hidden files found."
        }

        Write-Report "  Hashes for suspicious files:"
        if ($hits) {
            foreach ($file in $hits) {
                try {
                    $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction Stop
                    Write-Report ("    HASH: {0} | {1}" -f $hash.Hash, $file.FullName)
                } catch {
                    Write-Report ("    Could not hash: {0}" -f $file.FullName)
                }
            }
        }
    } catch {
        Write-Report "  WARNING: Could not perform malicious upload hunt. $($_.Exception.Message)"
    }
}

# =========================
# SECTION 11 - PERSISTENCE HUNT
# =========================
Write-Section "SECTION 11 - PERSISTENCE HUNT"

try {
    Write-Report "Scheduled tasks:"
    Get-ScheduledTask | Sort-Object TaskPath, TaskName | ForEach-Object {
        Write-Report ("  {0}{1} State={2}" -f $_.TaskPath, $_.TaskName, $_.State)
    }
} catch {
    Write-Report "WARNING: Could not enumerate scheduled tasks. $($_.Exception.Message)"
}

try {
    Write-Report "Services snapshot:"
    Get-Service | Sort-Object Name | ForEach-Object {
        Write-Report ("  {0} Status={1} StartType={2}" -f $_.Name, $_.Status, $_.StartType)
    }
} catch {
    Write-Report "WARNING: Could not enumerate services. $($_.Exception.Message)"
}

try {
    Write-Report "Run keys snapshot:"
    $runPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    foreach ($path in $runPaths) {
        if (Test-Path $path) {
            Write-Report "  Registry path: $path"
            Get-ItemProperty -Path $path | Format-List * | Out-String | ForEach-Object {
                $_ -split "`r?`n" | ForEach-Object {
                    if ($_.Trim()) { Write-Report "    $_" }
                }
            }
        }
    }
} catch {
    Write-Report "WARNING: Could not inspect Run keys. $($_.Exception.Message)"
}

# =========================
# SECTION 12 - INSTALLED ROLES / FEATURES
# =========================
Write-Section "SECTION 12 - INSTALLED ROLES / FEATURES (REVIEW BEFORE REMOVAL)"

try {
    Get-WindowsFeature | Where-Object Installed -eq $true | ForEach-Object {
        Write-Report ("  {0}" -f $_.Name)
    }
    Write-Report "Review unnecessary roles manually before removing anything."
} catch {
    Write-Report "WARNING: Could not enumerate installed roles/features. $($_.Exception.Message)"
}

Write-Section "END OF REPORT"
Write-Report "Report saved to: $ReportFile"
Write-Host "Done. Report saved to: $ReportFile"