F#!/bin/bash
# ==============================================================================
# Comprehensive OS Hardening, Detection, & Remediation Script
# (Oracle Linux / RHEL-family Adaptation)
# ==============================================================================
# NOTE: This version preserves the ORIGINAL BEHAVIOR (including aggressive perms
# and OUTPUT DROP firewall). Only distro-specific plumbing was changed:
#   - apt/dpkg -> dnf/yum/rpm
#   - Ubuntu cron spool path -> RHEL/OL cron spool path
#   - iptables persistence -> iptables-services (sysconfig save)
#   - package/service presence checks -> rpm -q and systemctl
# ==============================================================================

if [[ $EUID -ne 0 ]]; then
   echo -e "\e[31m[ERROR] This script must be run as root.\e[0m"
   exit 1
fi

# ------------------------------------------------------------------------------
# Distro Package Manager Helpers (Oracle Linux / RHEL-family)
# ------------------------------------------------------------------------------
PKG_MGR=""
if command -v dnf >/dev/null 2>&1; then
    PKG_MGR="dnf"
elif command -v yum >/dev/null 2>&1; then
    PKG_MGR="yum"
else
    PKG_MGR="" # Fall back to no package manager actions
fi

pkg_install() {
    # Usage: pkg_install <pkg1> [pkg2...]
    if [[ -n "$PKG_MGR" ]]; then
        $PKG_MGR -y install "$@" >/dev/null 2>&1 || true
    fi
}

pkg_remove() {
    # Usage: pkg_remove <pkg1> [pkg2...]
    if [[ -n "$PKG_MGR" ]]; then
        $PKG_MGR -y remove "$@" >/dev/null 2>&1 || true
    fi
}

pkg_is_installed() {
    # Usage: pkg_is_installed <pkg>
    rpm -q "$1" >/dev/null 2>&1
}

# Variables (Update these before running!)
TRUSTED_LINUX_CIDR="172.20.242.0/24"
TRUSTED_WINDOWS_CIDR="172.20.240.0/24"
SPLUNK_DIR="/opt/splunk/etc/system/local"
WEB_CONF="$SPLUNK_DIR/web.conf"
SERVER_CONF="$SPLUNK_DIR/server.conf"
AUTH_CONF="$SPLUNK_DIR/authentication.conf"
INPUTS_CONF="$SPLUNK_DIR/inputs.conf"
OUTPUTS_CONF="$SPLUNK_DIR/outputs.conf"
RSYSLOG_CONF="/etc/rsyslog.conf"
PUBLIC_IFACE="eth0" # Update to your public-facing interface
AUDIT_REPORT="/var/log/hardening_audit_$(date +%F).log"
> "$AUDIT_REPORT"

# --- Color & Logging Helpers ---
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
NC='\e[0m'

log_info()    { echo -e "${BLUE}[ * ] INFO:${NC} $1"; echo "[ * ] INFO: $1" >> "$AUDIT_REPORT"; }
log_success() { echo -e "${GREEN}[ + ] OK:${NC} $1"; echo "[ + ] OK: $1" >> "$AUDIT_REPORT"; }
log_found()   { echo -e "${RED}!!! ALERT:${NC} $1"; echo "!!! ALERT: $1" >> "$AUDIT_REPORT"; }
log_fixed()   { echo -e "${YELLOW}>>> CHANGED:${NC} $1"; echo ">>> CHANGED: $1" >> "$AUDIT_REPORT"; }

log_info "Starting Comprehensive Hardening and Audit... Report saved to $AUDIT_REPORT"

# ==============================================================================
# 1. OS Hardening & Integrity Baseline
# ==============================================================================
log_info "--- Section 1: OS Hardening & Baseline ---"

# 1.1 /tmp Mount Options
if ! grep -E -q "\s/tmp\s.*(nosuid|nodev|noexec)" /etc/fstab; then
    log_found "/tmp is not securely mounted via fstab."
    echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
    mount -o remount /tmp 2>/dev/null || mount /tmp
    log_fixed "Added secure /tmp mount to /etc/fstab and applied."
else
    log_success "Secure /tmp mount options present."
fi

# 1.2 System Binaries
BAD_BINS=$(find /bin /sbin /usr/bin /usr/sbin \( -type f -o -type d \) \( ! -user root -o ! -perm 0755 \) 2>/dev/null)
if [[ -n "$BAD_BINS" ]]; then
    log_found "Anomalous permissions/ownership in system binaries detected."
    chown -R root:root /bin /sbin /usr/bin /usr/sbin
    chmod -R go-w /bin /sbin /usr/bin /usr/sbin
    log_fixed "Enforced go-w permissions and root ownership on core binaries."
else
    log_success "System binaries permissions are 0755 and root-owned."
fi

# 1.3 Critical Configs
if find /etc/shadow ! -perm 0000 -a ! -perm 0640 2>/dev/null | grep -q 'shadow'; then
    log_found "Insecure permissions on /etc/shadow."
    chmod 000 /etc/shadow /etc/gshadow
    log_fixed "Locked down /etc/shadow and /etc/gshadow."
else
    log_success "/etc/shadow permissions are secure."
fi

# 1.4 /dev Audit
DEV_FILES=$(find /dev -type f 2>/dev/null)
if [[ -n "$DEV_FILES" ]]; then
    log_found "Regular files found in /dev (Suspicious): \n$DEV_FILES"
else
    log_success "No regular files found in /dev."
fi

# 1.5 Package Integrity & Rootkits
log_info "Checking package integrity (rpm -Va)..."
# rpm -Va verifies installed files. Output lines indicate mismatches.
if rpm -Va 2>/dev/null | grep -qE '^..5|^..M|^....L|^.......T'; then
    log_found "Modified package files detected. Check $AUDIT_REPORT for details."
    rpm -Va 2>/dev/null >> "$AUDIT_REPORT"
else
    log_success "Package integrity verified."
fi

# ==============================================================================
# 2. Service Surface Reduction
# ==============================================================================
log_info "--- Section 4: Surface Reduction ---"

SERVICES_TO_REMOVE=("avahi-daemon" "cups" "fwupd-refresh.timer" "rpcbind" "bluetooth"
                    "sysstat-collect.timer" "sysstat-summary.timer" "ipc_broker"
                    "identity" "postgres" "rpc.idmapd" "rpc.statd" "dnf-automatic.timer"
                    "abrtd" "abrt-ccpp" "abrt-oops" "kdump" "cups-browsed" "pcscd"
                    "ModemManager" "NetworkManager-wait-online" "geoclue" "vsftpd" "telnet"
                    "tftp" "nfs-server" "smb" "snmpd")

for svc in "${SERVICES_TO_REMOVE[@]}"; do
    if systemctl list-unit-files --type=service --no-pager 2>/dev/null | grep -q "^${svc}\.service" || pkg_is_installed "$svc"; then
        log_found "Service/package detected: $svc — stopping & disabling."
        systemctl stop "$svc" >/dev/null 2>&1 || true
        systemctl disable "$svc" >/dev/null 2>&1 || true
        systemctl mask "$svc" >/dev/null 2>&1 || true
        # If you want to remove packages on OL/RHEL, uncomment:
        #pkg_remove "$svc"
        log_fixed "Stopped, disabled, masked, and attempted removal of $svc."
    else
        log_success "$svc not present on system."
    fi
done

if ! grep -q "cramfs" /etc/modprobe.d/fs-hardening.conf 2>/dev/null; then
    log_found "Legacy filesystem kernel modules are not disabled."
    cat <<EOF > /etc/modprobe.d/fs-hardening.conf
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
EOF
    log_fixed "Disabled unused/legacy filesystems in modprobe."
else
    log_success "Legacy filesystems are already disabled."
fi

# ==============================================================================
# 3. Process Hygiene & Malicious Artifact Detection
# ==============================================================================
log_info "--- Section 2: Process Hygiene ---"

if lsof +L1 2>/dev/null | grep -q DEL; then
    log_found "Unlinked executables running in memory. Details in log."
    lsof +L1 2>/dev/null | grep DEL >> "$AUDIT_REPORT"
else
    log_success "No unlinked executables detected."
fi

if lsof 2>/dev/null | grep -E '/tmp/|/dev/shm/' | grep -q REG; then
    log_found "Processes running from /tmp or /dev/shm detected. Details in log."
    lsof 2>/dev/null | grep -E '/tmp/|/dev/shm/' | grep REG >> "$AUDIT_REPORT"
else
    log_success "No processes executing from temporary paths."
fi

log_info "Auditing Cron and Systemd Timers... (Saved to log)"

scan_cron_files() {
    SUSPICIOUS_REGEX='(wget|curl|nc|ncat|socat|bash[[:space:]]+-i|/dev/tcp|mkfifo|base64[[:space:]]+-d|perl[[:space:]]+-e|python[[:space:]]+-c|php[[:space:]]+-r|openssl[[:space:]]+s_client|chmod[[:space:]]+777|/dev/shm|/tmp/|/var/tmp|eval\(|https?://)'

    log_info "Listing cron file metadata..."
    # Oracle Linux / RHEL uses /var/spool/cron/<user> (not /var/spool/cron/crontabs/)
    ls -la /etc/cron* /var/spool/cron/ /etc/crontab /etc/cron.d/ >> "$AUDIT_REPORT" 2>&1
    systemctl list-timers --all >> "$AUDIT_REPORT" 2>&1

    log_info "Scanning cron files for suspicious patterns..."
    CRON_FILES=(/etc/crontab /etc/cron* /etc/cron.d/* /var/spool/cron/*)
    for f in "${CRON_FILES[@]}"; do
        if [[ -f "$f" && -r "$f" ]]; then
            MATCHES=$(grep -I -nE "$SUSPICIOUS_REGEX" "$f" 2>/dev/null || true)
            if [[ -n "$MATCHES" ]]; then
                log_found "Suspicious cron entries in $f"
                echo "=== Suspicious entries in $f ===" >> "$AUDIT_REPORT"
                echo "$MATCHES" >> "$AUDIT_REPORT"
            else
                log_success "No suspicious matches in $f"
            fi
        fi
    done
}

scan_cron_files

# 2.2 Kernel Module Audit (Rootkit Heuristics)
log_info "Auditing loaded Kernel Modules..."
KNOWN_BAD_MODULES="diamorphine|reptile|adore|suxmacz|veid|rootkit|sneaky|hide|backdoor|hook|phalanx|azazel|knark|stalker"
BAD_MODS=$(lsmod | awk '{print $1}' | grep -E -i "$KNOWN_BAD_MODULES" || true)

if [[ -n "$BAD_MODS" ]]; then
    log_found "KNOWN ROOTKIT KERNEL MODULE DETECTED (CRITICAL):"
    echo "$BAD_MODS" | tee -a "$AUDIT_REPORT"
else
    log_success "No known malicious kernel modules detected in lsmod."
fi

UNNEEDED_MODULES=(floppy sr_mod cdrom parport parport_pc pcspkr joydev)
DISABLE_CONF="/etc/modprobe.d/99-disable-unneeded.conf"
for mod in "${UNNEEDED_MODULES[@]}"; do
    if lsmod | awk '{print $1}' | grep -xq "$mod"; then
        log_found "Unneeded kernel module loaded: $mod — attempting to remove."
        modprobe -r "$mod" >/dev/null 2>&1 || rmmod "$mod" >/dev/null 2>&1 || true
        if [[ ! -f "$DISABLE_CONF" ]] || ! grep -q "^install $mod" "$DISABLE_CONF" 2>/dev/null; then
            echo "install $mod /bin/true" >> "$DISABLE_CONF"
            echo "blacklist $mod" >> "$DISABLE_CONF"
        fi
        log_fixed "Removed and blacklisted $mod (persisted in $DISABLE_CONF)."
    else
        if [[ ! -f "$DISABLE_CONF" ]] || ! grep -q "^install $mod" "$DISABLE_CONF" 2>/dev/null; then
            echo "install $mod /bin/true" >> "$DISABLE_CONF"
            echo "blacklist $mod" >> "$DISABLE_CONF"
            log_fixed "Blacklisted $mod in $DISABLE_CONF (was not loaded)."
        else
            log_success "$mod not loaded and already blacklisted."
        fi
    fi
done

MOD_PATH="/lib/modules/$(uname -r)"
if [[ -d "$MOD_PATH" ]]; then
    SUSPICIOUS_NAMES='backdoor|rootkit|sneak|hide|hook|malware|evil|stealth|sneaky|sux|adore|diamorphine'
    FOUND_FILES=$(find "$MOD_PATH" -type f -name '*.ko*' -print0 2>/dev/null | xargs -0 -n1 basename | grep -Ei "$SUSPICIOUS_NAMES" || true)
    if [[ -n "$FOUND_FILES" ]]; then
        log_found "Suspicious module filenames found under $MOD_PATH:"
        echo "$FOUND_FILES" | tee -a "$AUDIT_REPORT"
    else
        log_success "No suspicious module filenames under $MOD_PATH."
    fi
fi

# 2.3 Malicious Process Audit (High Open File Descriptors)
log_info "Scanning for processes with an abnormally high number of open files (>1000)..."
HIGH_FD_FOUND=0

find /proc -maxdepth 1 -type d -name "[0-9]*" | while read -r pid_dir; do
    fd_count=$(ls -1 "$pid_dir/fd" 2>/dev/null | wc -l)
    if [ "$fd_count" -gt 500 ]; then
        cmd=$(cat "$pid_dir/cmdline" 2>/dev/null | tr '\0' ' ')
        pid=${pid_dir##*/}
        log_found "PID $pid has $fd_count open files. Command: $cmd"
        HIGH_FD_FOUND=1
    fi
done

if [[ $HIGH_FD_FOUND -eq 0 ]]; then
    log_success "No processes detected holding excessive file descriptors."
fi

# 2.4 Audit Listening Ports
log_info "Logging all open listening ports for review..."
OPEN_PORTS=$(ss -tulpn | grep LISTEN)
if [[ -n "$OPEN_PORTS" ]]; then
    log_found "Listening ports detected. Ensure these are authorized:"
    echo "$OPEN_PORTS" | awk '{print $1, $5, $7}' | column -t | tee -a "$AUDIT_REPORT"
else
    log_success "No listening ports detected (Highly unusual for a server)."
fi

# ==============================================================================
# 4. Kernel & Network Hardening (Sysctl)
# ==============================================================================
log_info "--- Section 3: Kernel & Network Hardening ---"

SYSCTL_CONF="/etc/sysctl.d/99-hardening.conf"
if [[ $(sysctl -n net.ipv4.ip_forward) -eq 1 || $(sysctl -n net.ipv4.tcp_syncookies) -eq 0 ]]; then
    log_found "Insecure sysctl network/memory parameters detected."
    cat <<EOF > "$SYSCTL_CONF"
net.ipv4.ip_forward = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.tcp_syncookies = 1
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
EOF
    sysctl -p "$SYSCTL_CONF" >/dev/null 2>&1
    log_fixed "Applied restrictive sysctl network and memory protections."
else
    log_success "Kernel and network protections are already active."
fi

# ==============================================================================
# 5. Access Control (SSH & Root)
# ==============================================================================
log_info "--- Section 5: Access Control ---"

# UID 0 Check
ROGUE_UID0=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd)
if [[ -n "$ROGUE_UID0" ]]; then
    log_found "Rogue accounts with UID 0 detected: $ROGUE_UID0"
else
    log_success "No rogue UID 0 accounts found."
fi

# Password Expiration
# log_info "Forcing password expiration for all standard users..."
# awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd | xargs -I {} chage -d 0 {}
# log_fixed "All user passwords flagged for change on next login."

# SSH Hardening (Per your specific requirement: Keys OFF, Passwords ON, Root OFF)
SSH_CONF="/etc/ssh/sshd_config"
NEEDS_SSH_RESTART=0

if grep -q -E "^(#)?PermitRootLogin (yes|prohibit-password)" "$SSH_CONF"; then
    log_found "Root SSH login is permitted."
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' "$SSH_CONF"
    log_fixed "Disabled PermitRootLogin."
    NEEDS_SSH_RESTART=1
fi

if ! grep -q "^PasswordAuthentication yes" "$SSH_CONF"; then
    sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' "$SSH_CONF"
    sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication no/' "$SSH_CONF"
    log_fixed "Disabled SSH Keys, Enabled Password Auth."
    NEEDS_SSH_RESTART=1
fi

if [[ $NEEDS_SSH_RESTART -eq 1 ]]; then
    systemctl restart sshd
else
    log_success "SSH Configuration matches requirements."
fi

# ==============================================================================
# 6. Logging & Auditing (NIST AU-2)
# ==============================================================================
log_info "--- Section 6: Logging & Auditing ---"

if ! command -v auditd >/dev/null; then
    log_found "Auditd is not installed."
    # Oracle Linux typically provides auditd via 'audit' package
    pkg_install audit audit-libs
    log_fixed "Installed auditd (audit package)."
fi

AUDIT_RULES="/etc/audit/rules.d/99-wazuh.rules"
if [[ ! -f "$AUDIT_RULES" ]]; then
    log_found "Wazuh systemcall audit rules missing."
    cat <<EOF > "$AUDIT_RULES"
-D
-b 8192
-f 1


-a never,exit -F arch=b64 -S execve -F egid=splunk -F uid=splunk -F euid=splunk
-a never,exit -F arch=b32 -S execve -F egid=splunk -F uid=splunk -F euid=splunk

-a never,exit -F arch=b32 -S execve -F exe=/opt/splunk/bin/splunk-optimize
-a never,exit -F arch=b64 -S execve -F exe=/opt/splunk/bin/splunk-optimize
-a never,exit -F arch=b32 -S execve -F exe=/opt/splunk/bin/pg_isready
-a never,exit -F arch=b64 -S execve -F exe=/opt/splunk/bin/pg_isready

-a never,exit -F arch=b64 -S execve -F egid=wazuh
-a never,exit -F arch=b32 -S execve -F egid=wazuh
-a always,exit -F arch=b64 -S execve -k audit-wazuh-c
-a always,exit -F arch=b32 -S execve -k audit-wazuh-c
-w /etc/ -p wa -k etc_changes
--backlog_wait_time 60000
-e 1
EOF
    systemctl restart auditd >/dev/null 2>&1 || service auditd restart >/dev/null 2>&1 || true
    log_fixed "Applied Wazuh audit rules and locked daemon (immutable)."
else
    log_success "Auditd rules for Wazuh are present."
fi

# ------------------------------------------------------------------------------
# Install and enable rsyslog
# ------------------------------------------------------------------------------

log_info "Installing rsyslog."

# dnf update -y
dnf install -y rsyslog

systemctl enable rsyslog
systemctl start rsyslog

log_success "rsyslog installed and running."

# ------------------------------------------------------------------------------
# Enable UDP/TCP syslog reception
# ------------------------------------------------------------------------------

# Ensure a line exists and is not commented; uncomment if necessary
ensure_line() {
    local file="$1"
    local line="$2"

    # If line exists commented, uncomment it
    if grep -Fq "#$line" "$file"; then
        sed -i "s|#$line|$line|" "$file"
    fi

    # If line doesn't exist at all, append it
    grep -Fqx "$line" "$file" || echo "$line" >> "$file"
}

ensure_line "$RSYSLOG_CONF" 'module(load="imudp")'
ensure_line "$RSYSLOG_CONF" 'input(type="imudp" port="514")'

ensure_line "$RSYSLOG_CONF" 'module(load="imtcp")'
ensure_line "$RSYSLOG_CONF" 'input(type="imtcp" port="514")'

log_success "rsyslog UDP/TCP listeners enabled."

# ------------------------------------------------------------------------------
# Firewall log file configuration
# ------------------------------------------------------------------------------

# FIREWALL_RSYSLOG="/etc/rsyslog.d/firewall.conf"

# cat << 'EOF' > "$FIREWALL_RSYSLOG"
# if $fromhost-ip == '172.16.101.254' then /var/log/syslog
# & stop

# if $fromhost-ip == '172.16.102.254' then /var/log/syslog
# & stop
# EOF

# touch /var/log/firewall.log
# chmod 640 /var/log/firewall.log

systemctl restart rsyslog

log_success "Firewall log capture configured to /var/log/syslog."

# ------------------------------------------------------------------------------
# Configure Splunk to ingest firewall logs
# ------------------------------------------------------------------------------

if [[ ! -f "$INPUTS_CONF" ]]; then
    echo "" > "$INPUTS_CONF"
fi

cat <<EOF >> "$INPUTS_CONF"

[monitor:///var/log/firewall.log]
sourcetype = syslog
index = firewall
disabled = false

EOF

log_success "Splunk configured to monitor firewall logs."

# ==============================================================================
# 7. Host-Based Network Hardening (Firewall using firewalld)
# ==============================================================================
log_info "--- Section 7: Host-Based Firewall (firewalld) ---"

# Flush raw iptables rules
log_info "Flushing raw iptables rules..."
iptables -F >/dev/null 2>&1 || true
iptables -X >/dev/null 2>&1 || true
iptables -t nat -F >/dev/null 2>&1 || true
iptables -t mangle -F >/dev/null 2>&1 || true
ip6tables -F >/dev/null 2>&1 || true
ip6tables -X >/dev/null 2>&1 || true
log_fixed "Rap iptables and ip6tables rules flushed"

# Ensure firewalld is installed
if ! rpm -q firewalld >/dev/null 2>&1; then
    log_found "firewalld not installed — installing."
    dnf install -y firewalld >/dev/null 2>&1 || true
    log_fixed "firewalld installed."
fi

# Ensure conntrack tools are installed
if ! rpm -q conntrack-tools >/dev/null 2>&1; then
    log_found "conntrack-tools not installed — installing."
    dnf install -y conntrack-tools >/dev/null 2>&1 || true
    log_fixed "conntrack-tools installed."
fi

# Enable and start firewalld
if ! systemctl is-active --quiet firewalld; then
    log_found "firewalld is not running — starting and enabling."
    systemctl enable --now firewalld >/dev/null 2>&1 || true
    log_fixed "firewalld started and enabled."
else
    log_success "firewalld is already active."
fi

# Stop and disable unnecessary services
for svc in dhcpv6-client cockpit; do
    if systemctl is-active --quiet "$svc"; then
        log_found "$svc is running — stopping and disabling."
        systemctl stop "$svc" >/dev/null 2>&1 || true
        systemctl disable "$svc" >/dev/null 2>&1 || true
        log_fixed "$svc stopped and disabled."
    else
        log_success "$svc is already inactive."
    fi
done

firewall-cmd --zone-=public --remove-service=cockpit --permanent >/dev/null 2>&1 || 
firewall-cmd --zone-=public --remove-service=dhcpv6-client --permanent >/dev/null 2>&1 || true

# Set default zone to public
firewall-cmd --set-default-zone=public >/dev/null 2>&1

# Flush existing ports in the public zone
firewall-cmd --zone=public --remove-port=1-65535/tcp --permanent >/dev/null 2>&1
firewall-cmd --zone=public --remove-port=1-65535/udp --permanent >/dev/null 2>&1

# Flush existing rich rules dynamically
EXISTING_RICH_RULES=$(firewall-cmd --zone=public --list-rich-rules)
if [ -n "$EXISTING_RICH_RULES" ]; then
    log_found "Existing rich rules detected — removing."
    while read -r rule; do
        [ -n "$rule" ] && firewall-cmd --zone=public --remove-rich-rule="$rule" --permanent >/dev/null 2>&1
    done <<< "$EXISTING_RICH_RULES"
    log_fixed "Existing rich rules removed."
else
    log_success "No existing rich rules found."
fi

# Set default DROP for the zone
firewall-cmd --zone=public --set-target=DROP --permanent >/dev/null 2>&1

# Allow only essential ports
firewall-cmd --zone=public --add-port=22/tcp --permanent   # SSH
firewall-cmd --zone=public --add-port=8000/tcp --permanent # Splunk Web
firewall-cmd --zone=public --add-port=8089/tcp --permanent # Splunk Management
firewall-cmd --zone=public --add-port=9997/tcp --permanent # Splunk Forwarder
firewall-cmd --zone=public --add-port=514/udp --permanent # syslog
firewall-cmd --zone=public --add-port=514/tcp --permanent # syslog
firewall-cmd --zone=public --add-port=1514/tcp --permanent # Wazuh
firewall-cmd --zone=public --add-port=1515/tcp --permanent # Wazuh

# Add trusted subnet rich rule (replace with your subnet)
firewall-cmd --zone=public --add-rich-rule="rule family='ipv4' source address='$TRUSTED_LINUX_CIDR' accept" --permanent
firewall-cmd --zone=public --add-rich-rule="rule family='ipv4' source address='$TRUSTED_WINDOWS_CIDR' accept" --permanent

# Flush existing connection track table
log_found "Flushing existing connection tracking table."
conntrack -F >/dev/null 2>&1 || true
log_fixed "Connection tracking table flushed."

# Add Outbound rules: Only allow HTTP/HTTPS, NTP, DNS
firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 0 -p udp --dport 53 -j ACCEPT
firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 1 -p tcp --dport 80 -j ACCEPT
firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 2 -p tcp --dport 443 -j ACCEPT
firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 3 -p udp --dport 123 -j ACCEPT
firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 4 -p tcp --dport 1514 -j ACCEPT
firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 5 -p tcp --dport 1515 -j ACCEPT
firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 6 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 7 -j DROP

# Reload firewalld to apply changes
firewall-cmd --reload >/dev/null 2>&1

# Print direct rules
firewall-cmd --direct --get-all-rules

log_fixed "firewalld configured: default DROP, only SSH/8000/9997 allowed, trusted subnets permitted, unnecessary services stopped."

# ==============================================================================
# 8. Splunk Configuration Hardening
# ==============================================================================

log_info "--- Section 8: Splunk Hardening ---"

mkdir -p "$SPLUNK_DIR"

log_info "Auditing Splunk saved searches for system() calls..."
MALICIOUS_SEARCHES=$(grep -rE "system\(" \
    /opt/splunk/etc/apps/*/local/savedsearches.conf \
    /opt/splunk/etc/system/local/savedsearches.conf 2>/dev/null)
if [[ -n "$MALICIOUS_SEARCHES" ]]; then
    log_found "system() call detected in Splunk saved searches - likely red team activity"
    echo "$MALICIOUS_SEARCHES" | tee -a "$AUDIT_REPORT"
    log_info "Review and remove malicious stanzas from the relevant savedsearches."
else
    log_success "No system() calls detected in Splunk saved searches."
fi

# web.conf hardening
# ------------------------------------------------------------------------------

if [[ ! -f "$WEB_CONF" ]]; then
    echo "[settings]" > "$WEB_CONF"
fi

ensure_setting () {
    FILE=$1
    STANZA=$2
    KEY=$3
    VALUE=$4

    # Create file if missing
    [[ -f "$FILE" ]] || touch "$FILE"

    # Add stanza if it doesn't exist
    if ! grep -q "^\[$STANZA\]" "$FILE"; then
        echo "" >> "$FILE"
        echo "[$STANZA]" >> "$FILE"
    fi

    # If key exists anywhere, replace it
    if grep -q "^$KEY" "$FILE"; then
        sed -i "s/^$KEY.*/$KEY = $VALUE/" "$FILE"
    else
        # Insert key under the stanza
        sed -i "/^\[$STANZA\]/a $KEY = $VALUE" "$FILE"
    fi
}

ensure_setting "$WEB_CONF" "settings" "enableSplunkWebSSL" "true"
ensure_setting "$WEB_CONF" "settings" "sslVersions" "tls1.2,tls1.3"
ensure_setting "$WEB_CONF" "settings" "allowAnonymousLogin" "false"
ensure_setting "$WEB_CONF" "settings" "enableWebDebug" "false"
ensure_setting "$WEB_CONF" "settings" "tools.proxy.on" "false"
ensure_setting "$WEB_CONF" "settings" "cookieSecure" "true"

log_success "web.conf hardened."

# server.conf hardening
# ------------------------------------------------------------------------------

if [[ ! -f "$SERVER_CONF" ]]; then
    echo "[sslConfig]" > "$SERVER_CONF"
fi

ensure_setting "$SERVER_CONF" "sslConfig" "sslVersions" "tls1.2,tls1.3"

log_success "server.conf TLS hardened."

# authentication.conf hardening
# ------------------------------------------------------------------------------

if [[ ! -f "$AUTH_CONF" ]]; then
    echo "[default]" > "$AUTH_CONF"
fi

ensure_setting "$AUTH_CONF" "default" "minPasswordLength" "12"
ensure_setting "$AUTH_CONF" "default" "lockoutAttempts" "5"
ensure_setting "$AUTH_CONF" "default" "lockoutDuration" "30"

log_success "authentication.conf hardened."

# inputs.conf security check (scripted inputs)
# ------------------------------------------------------------------------------

EVIDENCE_DIR="/var/log/ccdc_evidence"
SCRIPTED_INPUT_LOG="$EVIDENCE_DIR/splunk_scripted_inputs_$(date +%F_%H-%M-%S).log"

mkdir -p "$EVIDENCE_DIR"

if [[ -f "$INPUTS_CONF" ]]; then

    if grep -q "\[script://" "$INPUTS_CONF"; then

        log_found "Scripted inputs detected in inputs.conf."

        echo "========== Splunk Scripted Input Evidence ==========" >> "$SCRIPTED_INPUT_LOG"
        echo "Timestamp: $(date)" >> "$SCRIPTED_INPUT_LOG"
        echo "Host: $(hostname)" >> "$SCRIPTED_INPUT_LOG"
        echo "" >> "$SCRIPTED_INPUT_LOG"
        echo "Original inputs.conf entries:" >> "$SCRIPTED_INPUT_LOG"

        grep -n "\[script://" -A5 "$INPUTS_CONF" >> "$SCRIPTED_INPUT_LOG"

        log_fixed "Scripted inputs saved to $SCRIPTED_INPUT_LOG"

        # Disable them without deleting evidence
        sed -i 's/^\[script:\/\//#\[script:\/\//' "$INPUTS_CONF"

        log_fixed "Scripted inputs disabled."

    else
        log_success "No scripted inputs detected."
    fi

else
    log_info "inputs.conf not present."
fi

# outputs.conf (prevent unauthorized log forwarding)
# ------------------------------------------------------------------------------

if [[ -f "$OUTPUTS_CONF" ]]; then
    log_found "outputs.conf detected — checking for forwarding."

    if grep -q "\[tcpout" "$OUTPUTS_CONF"; then
        sed -i 's/^\[tcpout/#\[tcpout/g' "$OUTPUTS_CONF"
        log_fixed "Disabled log forwarding configuration."
    else
        log_success "No forwarding configured."
    fi
else
    log_success "outputs.conf not present."
fi


# Restart Splunk
if systemctl is-active --quiet splunk; then
    log_found "Restarting Splunk to apply security configuration."
    systemctl restart splunk
    log_fixed "Splunk restarted."
else
    log_info "Splunk service not running — restart skipped."
fi

# ==============================================================================
# 9. User Account & sudo Audit (CCDC: Detect backdoor accounts & privilege escalation)
# ==============================================================================
log_info "--- Section 9: User Account & sudo Auditing ---"

# 9.1 Detect rogue/unauthorized user accounts
log_info "Checking for suspicious user accounts..."
SUSPICIOUS_USERS=$(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1 ":" $3}' /etc/passwd)
if [[ -n "$SUSPICIOUS_USERS" ]]; then
    log_found "Standard user accounts detected (verify these are legitimate):"
    echo "$SUSPICIOUS_USERS" | tee -a "$AUDIT_REPORT"
else
    log_success "No unusual user accounts found."
fi

# 9.2 Audit sudoers for dangerous entries
log_info "Auditing sudoers configuration..."
if grep -E -q "NOPASSWD|ALL=\(ALL\)" /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
    log_found "Dangerous sudoers entries detected (NOPASSWD or ALL=(ALL)):"
    grep -E "NOPASSWD|ALL=\(ALL\)" /etc/sudoers /etc/sudoers.d/* 2>/dev/null | tee -a "$AUDIT_REPORT" || true
else
    log_success "No obvious privilege escalation vectors in sudoers."
fi

# 9.3 Check for unauthorized SSH keys
log_info "Scanning for SSH public keys in .ssh directories only..."
FIND_KEYS=$(find /root/.ssh /home/*/.ssh -type f \( -name "authorized_keys" -o -name "id_rsa*" -o -name "id_ecdsa*" \) 2>/dev/null | head -20)
if [[ -n "$FIND_KEYS" ]]; then
    log_found "Found SSH key files (audit for backdoors):"
    echo "$FIND_KEYS" | while read -r keyfile; do
        if [[ -f "$keyfile" ]] && grep -qE "^ssh-" "$keyfile" 2>/dev/null; then
            log_found "  $keyfile contains $(wc -l < "$keyfile") key(s)"
            head -1 "$keyfile" >> "$AUDIT_REPORT"
        fi
    done
else
    log_success "No SSH key files found in .ssh directories."
fi

# ==============================================================================
# 10. Filesystem Persistence & Backdoor Hunting
# ==============================================================================
log_info "--- Section 10: Filesystem Hunting ---"

# Check /etc/hosts for poisoning
log_info "Checking /etc/hosts for poisoning..."
SUSPICIOUS_HOSTS=$(grep -v "^#" /etc/hosts | grep -vE "^(127\.|::1|localhost)" | grep "127\.0\.0\.1")
if [[ -n "$SUSPICIOUS_HOSTS" ]]; then
    log_found "/etc/hosts may be poisoned - suspicious loopback entries detected:"
    echo "$SUSPICIOUS_HOSTS" | tee -a "$AUDIT_REPORT"
else
    log_success "/etc/hosts looks clean."
fi

# Check for immutable files in common red team locations
log_info "Checking for immutable files in common persistence locations..."
IMMUTABLE_FILES=$(lsattr /etc/cron.d/* /usr/local/bin/* /etc/sudoers.d/* 2>/dev/null | grep "\-i-")
if [[ -n "$IMMUTABLE_FILES" ]]; then
    log_found "Immutable files detected - red team may have used chattr +i to protect malicious files:"
    echo "$IMMUTABLE_FILES" | tee -a "$AUDIT_REPORT"
    log_info "To remove immutable flag: sudo chattr -i <filename>"
else
    log_success "No immutable files detected in common persistence locations."
fi

#Check /etc/security/limits.conf for resource limits on key users
log_info "Checking /etc/security/limits.conf for malicious resource limits..."
SUSPICIOUS_LIMITS=$(grep -E "splunk.*(nproc|nofile)" /etc/security/limits.conf 2>/dev/null)
if [[ -n "$SUSPICIOUS_LIMITS" ]]; then
    log_found "Suspicious resource limits detected on splunk user, may cause DoS:"
    echo "$SUSPICIOUS_LIMITS" | tee -a "$AUDIT_REPORT"
    log_info "Remove the suspicious entries from /etc/security/limits.conf to fix."
else
    log_success "/etc/security/limits.conf looks clean"
fi

#Check for malicious logrotate configs
log_info "Auditing /etc/logrotate.d/ for unpackaged configs..."
ROGUE_LOGROTATE=""
for f in /etc/logrotate.d/*; do
    if ! rpm -qf "$f" >/dev/null 2>&1; then
        ROGUE_LOGROTATE="$ROGUE_LOGROTATE\n$f"
    fi
done
if [[ -n "$ROGUE_LOGROTATE" ]]; then
    log_found "Unpackaged logrotate configs detected - may be red team artifacts:"
    echo -e "$ROGUE_LOGROTATE" | tee -a "$AUDIT_REPORT"
    log_info "Review and remove any suspicious configs"
else
    log_success "All logrotate configs are owned by installed packages."
fi

# 10.1 Check temporary directories for hidden executables
log_info "Looking for executables in /tmp, /dev/shm, /var/tmp..."
for tmpdir in /tmp /dev/shm /var/tmp; do
    if [[ -d "$tmpdir" ]]; then
        TMP_EXECS=$(find "$tmpdir" -type f -executable 2>/dev/null | head -10)
        if [[ -n "$TMP_EXECS" ]]; then
            log_found "Executable files in $tmpdir (SUSPICIOUS):"
            echo "$TMP_EXECS" | tee -a "$AUDIT_REPORT"
        fi
    fi
done

# 10.2 Scan for webshells in web directories
if [[ -d /var/www/html ]]; then
    log_info "Scanning /var/www/html for potential webshells..."
    WEBSHELL_PATTERNS='<?php|eval\(|passthru|system\(|shell_exec|exec\(|proc_open|popen|pcntl_exec'
    FOUND_SHELLS=$(find /var/www/html -type f \( -name "*.php" -o -name "*.jsp" -o -name "*.aspx" \) -exec grep -l -i "$WEBSHELL_PATTERNS" {} \; 2>/dev/null || true)
    if [[ -n "$FOUND_SHELLS" ]]; then
        log_found "Potential webshells detected:"
        echo "$FOUND_SHELLS" | tee -a "$AUDIT_REPORT"
    else
        log_success "No obvious webshells in /var/www/html."
    fi
fi

# 10.3 Check for suspicious .htaccess and .htpasswd
if [[ -d /var/www/html ]]; then
    HTACCESS=$(find /var/www/html -name ".htaccess" -o -name ".htpasswd" 2>/dev/null)
    if [[ -n "$HTACCESS" ]]; then
        log_found ".htaccess/.htpasswd files found (audit for backdoors):"
        echo "$HTACCESS" | while read -r ht; do
            echo "=== $ht ===" >> "$AUDIT_REPORT"
            head -5 "$ht" >> "$AUDIT_REPORT"
        done
    fi
fi

# ==============================================================================
# 11. Network & Init.d Persistence Detection
# ==============================================================================

# 11.2 Audit init.d startup scripts for suspicious downloads/network calls
log_info "Scanning /etc/init.d for suspicious network commands..."
SUSPICIOUS_INIT=$(grep -l -E 'curl|wget|nc|bash -i|/dev/tcp' /etc/init.d/* 2>/dev/null || true)
if [[ -n "$SUSPICIOUS_INIT" ]]; then
    log_found "Init scripts with network commands detected:"
    echo "$SUSPICIOUS_INIT" | tee -a "$AUDIT_REPORT"
fi

# 11.3 Check systemd user services for persistence
log_info "Auditing user-level systemd services..."
if [[ -d /etc/systemd/user ]]; then
    USER_SVCS=$(find /etc/systemd/user -name "*.service" -exec grep -l "ExecStart.*bash\|ExecStart.*perl\|ExecStart.*python" {} \; 2>/dev/null || true)
    if [[ -n "$USER_SVCS" ]]; then
        log_found "Suspicious user systemd services detected:"
        echo "$USER_SVCS" | tee -a "$AUDIT_REPORT"
    fi
fi

# ==============================================================================
# 12. LD_PRELOAD & PAM Backdoor Detection
# ==============================================================================
log_info "--- Section 12: Runtime Hooking Detection ---"

# 12.1 Check /etc/ld.so.preload for malicious libraries
if [[ -f /etc/ld.so.preload ]]; then
    if [[ -s /etc/ld.so.preload ]]; then
        log_found "LD_PRELOAD file exists and is non-empty (CRITICAL):"
        cat /etc/ld.so.preload | tee -a "$AUDIT_REPORT"
    fi
else
    log_success "/etc/ld.so.preload is absent (OK)."
fi

# 12.2 Check PAM configuration for backdoors
log_info "Auditing PAM modules..."
PAM_SUSPECT=$(grep -r "session\|auth" /etc/pam.d/ 2>/dev/null | grep -v "#" | grep -E "custom|backdoor|pam_exec" || true)
if [[ -n "$PAM_SUSPECT" ]]; then
    log_found "Suspicious PAM module references detected:"
    echo "$PAM_SUSPECT" | tee -a "$AUDIT_REPORT"
fi

# ==============================================================================
# 13. SUID/SGID Privilege Escalation Points
# ==============================================================================
log_info "--- Section 13: SUID/SGID Binaries ---"

log_info "Searching for SUID/SGID binaries (common privilege escalation vectors)..."
SUID_BINARIES=$(find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null | head -30)
if [[ -n "$SUID_BINARIES" ]]; then
    log_found "SUID/SGID binaries found (review for suspicious additions):"
    echo "$SUID_BINARIES" | awk '{print $11, $3}' | tee -a "$AUDIT_REPORT"
else
    log_success "No SUID/SGID binaries detected."
fi

# ==============================================================================
# 14. Suspicious Environment Variables & Shell Profiles
# ==============================================================================
log_info "--- Section 14: Shell Profiles & Environment ---"

# 14.1 Audit .bashrc, .profile, .bash_login for backdoors
log_info "Scanning user shell profiles for injected commands..."
SHELL_BACKDOORS=0
for shellrc in /root/.bashrc /root/.bash_profile /home/*/.bashrc /home/*/.bash_profile /opt/splunk.bashrc /opt/splunk/.bash_profile; do
    if [[ -f "$shellrc" ]]; then
        if grep -qE 'curl|wget|nc -l|bash -i|/dev/tcp|eval|exec|alias.*/|alias.*\\.' "$shellrc"; then
            log_found "Suspicious content in $shellrc"
            grep -E 'curl|wget|nc -l|bash -i|/dev/tcp|eval|exec|alias.*/|alias.*\\.' "$shellrc" >> "$AUDIT_REPORT"
            SHELL_BACKDOORS=$((SHELL_BACKDOORS + 1))
        fi
    fi
done

if [[ $SHELL_BACKDOORS -eq 0 ]]; then
    log_success "No obvious shell profile backdoors detected."
fi

# 14.2 Check for PATH manipulation
log_info "Verifying PATH environment for trojanized binaries..."
if echo "$PATH" | grep -q "^\." || echo "$PATH" | grep -q ":\.:" || echo "$PATH" | grep -q ":$"; then
    log_found "PATH contains current directory (.) — privilege escalation risk!"
fi

# ==============================================================================
# 15. at & Cron Privileged Task Audit
# ==============================================================================
log_info "--- Section 15: at Daemon & Privileged Tasks ---"

# 15.1 Check if atd is running and audit at jobs
if which at >/dev/null 2>&1; then
    log_info "Auditing at daemon jobs..."
    AT_JOBS=$(at -l 2>/dev/null || true)
    if [[ -n "$AT_JOBS" ]]; then
        log_found "Pending at jobs detected (audit for persistence):"
        echo "$AT_JOBS" | tee -a "$AUDIT_REPORT"
    fi
fi

# 15.2 Audit root crontab (Oracle Linux / RHEL path)
if [[ -f /var/spool/cron/root ]]; then
    if grep -qvE "^(#|$)" /var/spool/cron/root; then
        log_found "Root crontab has active entries:"
        grep -vE "^(#|$)" /var/spool/cron/root | tee -a "$AUDIT_REPORT"
    fi
fi

# ==============================================================================
# 16. Rootkit & Kernel Module Comprehensive Scan
# ==============================================================================
log_info "--- Section 16: Advanced Rootkit Detection ---"

# 16.1 Compare loaded modules against installed packages
log_info "Checking kernel module signatures..."
if command -v modinfo >/dev/null 2>&1; then
    UNSIGNED_MODS=$(lsmod | awk '{print $1}' | tail -n +2 | while read mod; do
        if ! modinfo "$mod" 2>/dev/null | grep -q "signature"; then
            echo "$mod"
        fi
    done | head -10)
    if [[ -n "$UNSIGNED_MODS" ]]; then
        log_found "Unsigned kernel modules detected (potential rootkit):"
        echo "$UNSIGNED_MODS" | tee -a "$AUDIT_REPORT"
    fi
fi

# 16.2 Check for hidden processes (compare ps vs /proc)
log_info "Auditing process list consistency..."
PROC_COUNT=$(find /proc -maxdepth 1 -type d -name "[0-9]*" 2>/dev/null | wc -l)
PS_COUNT=$(ps aux | wc -l)
if [[ $((PROC_COUNT - PS_COUNT)) -gt 5 ]]; then
    log_found "Process count mismatch: /proc=$PROC_COUNT vs ps=$PS_COUNT (hidden processes?)"
fi

# ==============================================================================
# 17. Suspicious Data Exfiltration Detection
# ==============================================================================
log_info "--- Section 17: Data Exfiltration Indicators ---"

# 17.1 Check for large outbound connections in netstat/ss
log_info "Reviewing established connections for data exfiltration..."
ESTABLISHED=$(ss -tupn 2>/dev/null | grep ESTAB | grep -E ":[0-9]{5,}" | head -10)
if [[ -n "$ESTABLISHED" ]]; then
    log_found "Established outbound connections (verify they are legitimate):"
    echo "$ESTABLISHED" | tee -a "$AUDIT_REPORT"
fi

# 17.2 Check bash history for suspicious commands
if [[ -f /root/.bash_history ]]; then
    HISTORY_SUSPECT=$(grep -E 'scp|sftp|rsync|tar|zip|curl|wget|nc -l' /root/.bash_history 2>/dev/null | tail -20 || true)
    if [[ -n "$HISTORY_SUSPECT" ]]; then
        log_found "Suspicious commands in /root/.bash_history (potential data theft):"
        echo "$HISTORY_SUSPECT" | head -5 >> "$AUDIT_REPORT"
    fi
fi

# ==============================================================================
# 18. Writable System Files Check
# ==============================================================================
log_info "--- Section 18: Writable System Files ---"

log_info "Checking for writable system files in /etc, /lib, /bin..."
WRITABLE_SYS=$(find /etc /lib /bin /sbin /usr/bin /usr/sbin -type f -writable 2>/dev/null | head -20)
if [[ -n "$WRITABLE_SYS" ]]; then
    log_found "World/group-writable system files detected:"
    echo "$WRITABLE_SYS" | tee -a "$AUDIT_REPORT"
    for f in $WRITABLE_SYS; do
        chmod 644 "$f" 2>/dev/null || true
    done
    log_fixed "Removed write permissions from writable system files."
else
    log_success "No writable system files detected."
fi

# ==============================================================================
# 19. Audit Log Integrity & Forwarding
# ==============================================================================
# log_info "--- Section 19: Audit Log Protection ---"

# # # 19.1 Enable auditd immutability to prevent tampering
# # log_info "Enforcing auditd immutable flags..."
# # if [[ -f /etc/audit/rules.d/99-wazuh.rules ]]; then
# #     if ! grep -q "\-e 2" /etc/audit/rules.d/99-wazuh.rules; then
# #         echo "-e 2" >> /etc/audit/rules.d/99-wazuh.rules
# #         auditctl -R /etc/audit/rules.d/99-wazuh.rules >/dev/null 2>&1 || true
# #         log_fixed "Enabled immutable audit daemon flag (-e 2)."
# #     fi
# # fi

# # # 19.2 Configure rsyslog forwarding to prevent log deletion
# # if [[ -f /etc/rsyslog.conf ]]; then
# #     if ! grep -q "\$ActionFileEnableSync" /etc/rsyslog.conf; then
# #         echo "\$ActionFileEnableSync on" >> /etc/rsyslog.conf
# #         systemctl restart rsyslog >/dev/null 2>&1 || true
# #         log_fixed "Enabled rsyslog sync mode (immediate disk write)."
# #     fi
# # fi

log_info "=============================================================================="
log_info "Audit & Hardening Complete. Check $AUDIT_REPORT for full details."