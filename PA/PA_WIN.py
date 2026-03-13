#!/usr/bin/env python3
#
# SecureBaseScript.py 
# Modified for custom IP/Port objects, dynamic zones, and stripped interface/routing config.

#set deviceconfig system permitted-ip 172.20.240.200
#delete admin-sessions
print("--- PAN-OS Configuration Script Generator ---")

trusted_zone = input("Enter the name of the Trusted (Inside) zone (e.g., Internal, LAN): ")
untrusted_zone = input("Enter the name of the Untrusted (Outside) zone (e.g., External, WAN): ")


# ==========================================
# NAT RULES (Bi-directional Static)
# ==========================================
#delete rulebase nat
#set rulebase nat rules NAT-DNS nat-type ipv4 from {trusted_zone} to {untrusted_zone} source DNS_PRIVATE destination any service any source-translation static-ip bi-directional yes #translated-address DNS_PUBLIC
#set rulebase nat rules NAT-IIS nat-type ipv4 from {trusted_zone} to {untrusted_zone} source IIS_PRIVATE destination any service any source-translation static-ip bi-directional yes #translated-address IIS_PUBLIC
#set rulebase nat rules NAT-FTP nat-type ipv4 from {trusted_zone} to {untrusted_zone} source FTP_PRIVATE destination any service any source-translation static-ip bi-directional yes #translated-address FTP_PUBLIC
#set rulebase nat rules NAT-WIN11 nat-type ipv4 from {trusted_zone} to {untrusted_zone} source WIN11_PRIVATE destination any service any source-translation static-ip bi-directional #yes translated-address WIN11_PUBLIC




with open("PAConfig.txt", "w") as command_file:
    commands = f"""configure

set deviceconfig system dns-setting servers primary 9.9.9.9
set deviceconfig system dns-setting servers secondary 149.112.112.112


set deviceconfig system service disable-telnet yes
set deviceconfig system service disable-http yes
set deviceconfig system service disable-https no
set deviceconfig system service disable-ssh no
set deviceconfig system service disable-snmp yes
set deviceconfig system login-banner "UNAUTHORIZED ACCESS TO THIS DEVICE IS PROHIBITED. All activities performed on this device are logged and monitored."
set deviceconfig system timezone US/Central

set address DNS_PRIVATE ip-netmask 172.20.240.102
set address DNS_PUBLIC ip-netmask 172.25.31.155

set address IIS_PRIVATE ip-netmask 172.20.240.101
set address IIS_PUBLIC ip-netmask 172.25.31.140

set address FTP_PRIVATE ip-netmask 172.20.240.104
set address FTP_PUBLIC ip-netmask 172.25.31.162

set address WIN11_PRIVATE ip-netmask 172.20.240.100
set address WIN11_PUBLIC ip-netmask 172.25.31.144

set service IIS_service protocol tcp port 80,443
set service DNS_udp protocol udp port 53
set service FTP_service protocol tcp port 21,50000-50100
set service TFTP_service protocol udp port 69

set service General_Ports_TCP protocol tcp port 80,443,1514,1515
set service General_Ports_UDP protocol udp port 53,123



delete rulebase security

set rulebase security rules Allow-Outbound action allow from {trusted_zone} to {untrusted_zone} source any destination any
set rulebase security rules Allow-Outbound application any service [ General_Ports_TCP General_Ports_UDP ]

set rulebase security rules Allow-Inbound-FTP action allow from {untrusted_zone} to {trusted_zone} source any destination FTP_PUBLIC
set rulebase security rules Allow-Inbound-FTP application any service FTP_service

set rulebase security rules Allow-Inbound-IIS action allow from {untrusted_zone} to {trusted_zone} source any destination IIS_PUBLIC
set rulebase security rules Allow-Inbound-IIS application any service IIS_service

set rulebase security rules Allow-Inbound-DNS action allow from {untrusted_zone} to {trusted_zone} source any destination DNS_PUBLIC
set rulebase security rules Allow-Inbound-DNS application any service DNS_udp

set rulebase security rules Deny-All action deny from any to any source any destination any
set rulebase security rules Deny-All application any service any

delete rulebase dos
set profiles dos-protection CCDC_Protection type aggregate flood icmp enable yes
set profiles dos-protection CCDC_Protection type aggregate flood udp enable yes
set profiles dos-protection CCDC_Protection type aggregate flood other-ip enable yes
set profiles dos-protection CCDC_Protection type aggregate flood icmpv6 enable yes
set profiles dos-protection CCDC_Protection type aggregate flood tcp-syn enable yes

set rulebase dos rules DOS-DNS from {untrusted_zone}
set rulebase dos rules DOS-DNS to {trusted_zone}
set rulebase dos rules DOS-DNS source any
set rulebase dos rules DOS-DNS destination DNS_PUBLIC
set rulebase dos rules DOS-DNS service DNS_udp
set rulebase dos rules DOS-DNS action protect
set rulebase dos rules DOS-DNS protection aggregate profile CCDC_Protection

set rulebase dos rules DOS-IIS from {untrusted_zone}
set rulebase dos rules DOS-IIS to {trusted_zone}
set rulebase dos rules DOS-IIS source any
set rulebase dos rules DOS-IIS destination IIS_PUBLIC
set rulebase dos rules DOS-IIS service IIS_service
set rulebase dos rules DOS-IIS action protect
set rulebase dos rules DOS-IIS protection aggregate profile CCDC_Protection

set rulebase dos rules DOS-FTP from {untrusted_zone}
set rulebase dos rules DOS-FTP to {trusted_zone}
set rulebase dos rules DOS-FTP source any
set rulebase dos rules DOS-FTP destination FTP_PUBLIC
set rulebase dos rules DOS-FTP service FTP_service
set rulebase dos rules DOS-FTP action protect
set rulebase dos rules DOS-FTP protection aggregate profile CCDC_Protection

set rulebase dos rules ProtectDefault from any
set rulebase dos rules ProtectDefault to any
set rulebase dos rules ProtectDefault source any
set rulebase dos rules ProtectDefault destination any
set rulebase dos rules ProtectDefault service any
set rulebase dos rules ProtectDefault action protect
set rulebase dos rules ProtectDefault protection aggregate profile default

commit
set mgt-config users admin password
"""
    command_file.write(commands)
    print("\nFile is written to PAConfig.txt")
    print("Copy and paste the output of the script into the Palo Alto CLI.")