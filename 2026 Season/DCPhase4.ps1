Write-Host "Starting Domain Controller Firewall Lockdown..." -ForegroundColor Cyan



# Enable firewall on all profiles

Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True



# Optional: set a stricter default posture

Set-NetFirewallProfile -Profile Domain,Public,Private `

    -DefaultInboundAction Block `

    -DefaultOutboundAction Allow



# ----------------------------------------

# Required Active Directory / DNS / DC Ports

# ----------------------------------------



$rules = @(

    @{ Name="DNS TCP";                Protocol="TCP"; Port=53   },

    @{ Name="DNS UDP";                Protocol="UDP"; Port=53   },

    @{ Name="Kerberos TCP";           Protocol="TCP"; Port=88   },

    @{ Name="Kerberos UDP";           Protocol="UDP"; Port=88   },

    @{ Name="LDAP TCP";               Protocol="TCP"; Port=389  },

    @{ Name="LDAP UDP";               Protocol="UDP"; Port=389  },

    @{ Name="LDAPS";                  Protocol="TCP"; Port=636  },

    @{ Name="Global Catalog";         Protocol="TCP"; Port=3268 },

    @{ Name="Global Catalog SSL";     Protocol="TCP"; Port=3269 },

    @{ Name="SMB";                    Protocol="TCP"; Port=445  },

    @{ Name="RPC Endpoint Mapper";    Protocol="TCP"; Port=135  },

    @{ Name="NTP";                    Protocol="UDP"; Port=123  }

)



foreach ($rule in $rules) {

    $existing = Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue



    if ($existing) {

        Write-Host "Rule already exists: $($rule.Name)" -ForegroundColor Yellow

        Set-NetFirewallRule -DisplayName $rule.Name -Enabled True -Action Allow -Direction Inbound

    }

    else {

        New-NetFirewallRule `

            -DisplayName $rule.Name `

            -Direction Inbound `

            -Protocol $rule.Protocol `

            -LocalPort $rule.Port `

            -Action Allow `

            -Profile Domain

        Write-Host "Created rule: $($rule.Name)" -ForegroundColor Green

    }

}



Write-Host "Firewall Lockdown Complete." -ForegroundColor Green
