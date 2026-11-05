# ================================================
# CCDC Phase 4 – Domain Controller Firewall Lockdown
# Windows Server 2019
# ================================================

Write-Host "Starting Domain Controller Firewall Lockdown..." -ForegroundColor Cyan

Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow

$rules = @(
    @{ Name="DNS TCP"; Protocol="TCP"; Port="53" },
    @{ Name="DNS UDP"; Protocol="UDP"; Port="53" },
    @{ Name="Kerberos TCP"; Protocol="TCP"; Port="88" },
    @{ Name="Kerberos UDP"; Protocol="UDP"; Port="88" },
    @{ Name="LDAP TCP"; Protocol="TCP"; Port="389" },
    @{ Name="LDAP UDP"; Protocol="UDP"; Port="389" },
    @{ Name="LDAPS"; Protocol="TCP"; Port="636" },
    @{ Name="Global Catalog"; Protocol="TCP"; Port="3268" },
    @{ Name="Global Catalog SSL"; Protocol="TCP"; Port="3269" },
    @{ Name="SMB"; Protocol="TCP"; Port="445" },
    @{ Name="RPC Endpoint Mapper"; Protocol="TCP"; Port="135" },
    @{ Name="RPC Dynamic Ports"; Protocol="TCP"; Port="49152-65535" },
    @{ Name="NTP"; Protocol="UDP"; Port="123" },
    @{ Name="AD Web Services"; Protocol="TCP"; Port="9389" }
)

foreach ($rule in $rules) {
    $existing = Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue

    if ($existing) {
        Set-NetFirewallRule -DisplayName $rule.Name -Enabled True -Direction Inbound -Action Allow
        Write-Host "Rule already exists / enabled: $($rule.Name)" -ForegroundColor Yellow
    }
    else {
        New-NetFirewallRule -DisplayName $rule.Name -Direction Inbound -Protocol $rule.Protocol -LocalPort $rule.Port -Action Allow -Profile Domain | Out-Null
        Write-Host "Created rule: $($rule.Name)" -ForegroundColor Green
    }
}

Write-Host "Phase 4 Complete." -ForegroundColor Green
