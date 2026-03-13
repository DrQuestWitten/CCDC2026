#!/bin/bash
# ==============================================================================
# Comprehensive OS Hardening, Detection, & Remediation Script
# ==============================================================================

if [[ $EUID -ne 0 ]]; then
   echo -e "\e[31m[ERROR] This script must be run as root.\e[0m" 
   exit 1
fi

# Variables (Update these before running!)
TRUSTED_PRIVATE_CIDR="172.20.242.0/24" 
PUBLIC_IFACE="ens18" # Update to your public-facing interface
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
BAD_BINS=$(find /bin /sbin /usr/bin /usr/sbin\ \( -type f -o -type d \) \( ! -user root -o ! -perm 0755 \) 2>/dev/null)
if [[ -n "$BAD_BINS" ]]; then
    log_found "Anomalous permissions/ownership in system binaries detected."
    chown -R root:root /bin /sbin /usr/bin /usr/sbin
    chmod -R go-w /bin /sbin /usr/bin /usr/sbin
    log_fixed "Enforced 0755 permissions and root ownership on core binaries."
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
log_info "Checking package integrity (dpkg -V)..."
if dpkg -V 2>/dev/null | grep -q '^..5'; then
    log_found "Modified package binaries detected. Check $AUDIT_REPORT for details."
    dpkg -V 2>/dev/null | grep '^..5' >> "$AUDIT_REPORT"
else
    log_success "Package integrity verified."
fi

# ==============================================================================
# 2. Service Surface Reduction
# ==============================================================================
log_info "--- Section 4: Surface Reduction ---"

SERVICES_TO_REMOVE=("avahi-daemon" "cups" "apport-autoreport.timer" 
                    "motd-news.timer" "apt-daily.timer" "update-notifier-download.timer"
                    "update-notifier-motd.timer" "dpkg-db-backup.timer" "fwupd-refresh.timer"
                    "sysstat-collect.timer" "fstrim.timer" "apt-daily-upgrade.timer"
                    "snpad.snap-repair.timer" "sysstat-summary.timer" "man-db.timer")

for svc in "${SERVICES_TO_REMOVE[@]}"; do
    if systemctl list-unit-files --type=service --no-pager | grep -q "^${svc}\.service" || dpkg -l | grep -qw "$svc"; then
        log_found "Service/package detected: $svc — stopping & disabling."
        systemctl stop "$svc" >/dev/null 2>&1 || true
        systemctl disable "$svc" >/dev/null 2>&1 || true
        systemctl mask "$svc" >/dev/null 2>&1 || true
        #if command -v apt-get >/dev/null 2>&1; then
        #    apt-get purge -y "$svc" >/dev/null 2>&1 || true
        #    apt-get autoremove -y >/dev/null 2>&1 || true
        #fi
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
    ls -la /etc/cron* /var/spool/cron/crontabs/ /etc/crontab /etc/cron.d/ >> "$AUDIT_REPORT" 2>&1
    systemctl list-timers --all >> "$AUDIT_REPORT" 2>&1

    log_info "Scanning cron files for suspicious patterns..."
    CRON_FILES=(/etc/crontab /etc/cron* /etc/cron.d/* /var/spool/cron/crontabs/*)
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
# Expanded list of known or commonly-seen malicious/obfuscated module name fragments
KNOWN_BAD_MODULES="diamorphine|reptile|adore|suxmacz|veid|rootkit|sneaky|hide|backdoor|hook|phalanx|azazel|knark|stalker"
BAD_MODS=$(lsmod | awk '{print $1}' | grep -E -i "$KNOWN_BAD_MODULES" || true)

if [[ -n "$BAD_MODS" ]]; then
    log_found "KNOWN ROOTKIT KERNEL MODULE DETECTED (CRITICAL):"
    echo "$BAD_MODS" | tee -a "$AUDIT_REPORT"
else
    log_success "No known malicious kernel modules detected in lsmod."
fi




# Proactively disable/remove modules that are typically not needed on most servers
# (examples: floppy or cd/dvd drivers). We remove if loaded and blacklist to persist.
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

# Heuristic scan: look for suspicious module filenames under /lib/modules
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

# Loop through all PID directories in /proc to count file descriptors
find /proc -maxdepth 1 -type d -name "[0-9]*" | while read -r pid_dir; do
    # Count open files, suppressing permission denied errors
    fd_count=$(ls -1 "$pid_dir/fd" 2>/dev/null | wc -l)
    
    if [ "$fd_count" -gt 100 ]; then
        cmd=$(cat "$pid_dir/cmdline" 2>/dev/null | tr '\0' ' ')
        pid=${pid_dir##*/}
        log_found "PID $pid has $fd_count open files. Command: $cmd"
        HIGH_FD_FOUND=1
    fi
done

if [[ $HIGH_FD_FOUND -eq 0 ]]; then
    log_success "No processes detected holding excessive file descriptors."
fi

# 2.4 Check for processes accessing critical configuration files
log_info "Checking for processes with critical configuration files open..."
CRITICAL_CONFIG_FILES=("/etc/passwd" "/etc/shadow" "/etc/group" "/etc/gshadow" "/etc/sudoers" "/root/.ssh/authorized_keys" "/etc/ssh/sshd_config")
FOUND_OPEN_CRITICALS=0

for cfile in "${CRITICAL_CONFIG_FILES[@]}"; do
    if [[ -e "$cfile" ]]; then
        PROCESSES=$(lsof "$cfile" 2>/dev/null | grep -v COMMAND)
        if [[ -n "$PROCESSES" ]]; then
            log_found "Processes accessing critical file $cfile:"
            echo "$PROCESSES" | awk '{print $1, $2, $3}' | column -t | tee -a "$AUDIT_REPORT"
            FOUND_OPEN_CRITICALS=1
        fi
    fi
done

if [[ $FOUND_OPEN_CRITICALS -eq 0 ]]; then
    log_success "No suspicious processes detected accessing critical configuration files."
fi

# 2.5 Audit Listening Ports
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
    apt-get install -y auditd >/dev/null 2>&1
    log_fixed "Installed auditd."
fi


## for splunk add this
#-a never,exit -F arch=b64 -S execve -F exe=/opt/splunk/bin/splunk-optimize
#-a never,exit -F arch=b32 -S execve -F exe=/opt/splunk/bin/splunk-optimize
#-a never,exit -F arch=b64 -S execve -F exe=/opt/splunk/bin/pg_isready
#-a never,exit -F arch=b32 -S execve -F exe=/opt/splunk/bin/pg_isready
#-a never,exit -F arch=b64 -S execve -F egid=splunk -F uid=splunk -F suid=splunk
#-a never,exit -F arch=b32 -S execve -F egid=splunk -F uid=splunk -F suid=splunk

AUDIT_RULES="/etc/audit/rules.d/99-wazuh.rules"
if [[ ! -f "$AUDIT_RULES" ]]; then
    log_found "Wazuh systemcall audit rules missing."
    cat <<EOF > "$AUDIT_RULES"
-a never,exit -F arch=b64 -S execve -F egid=wazuh
-a never,exit -F arch=b32 -S execve -F egid=wazuh
-a always,exit -F arch=b64 -S execve -k audit-wazuh-c
-a always,exit -F arch=b32 -S execve -k audit-wazuh-c
-w /etc/ -p wa -k etc_changes
-e 1
EOF
    service auditd restart
    log_fixed "Applied Wazuh audit rules and locked daemon (immutable)."
else
    log_success "Auditd rules for Wazuh are present."
fi

# ==============================================================================
# 7. Host-Based Network Hardening (Firewall)
# ==============================================================================
log_info "--- Section 7: Host-Based Firewall ---"

if ! iptables -S | grep -q "P INPUT DROP"; then
    log_found "Firewall default policies are not restrictive."
    iptables -F
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    
    # Restrict Ingress
    iptables -A INPUT -p tcp --dport 22 -s $TRUSTED_PRIVATE_CIDR -j ACCEPT
    
    # Restrict Egress
    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -p udp --dport 123 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 1514 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 1515 -j ACCEPT
    
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP
    
    apt-get install -y iptables-persistent >/dev/null 2>&1
    netfilter-persistent save >/dev/null 2>&1
    log_fixed "Applied default DROP firewall, allowed essential egress, and restricted SSH ingress."
else
    log_success "Firewall default DROP policies are already active."
fi

# ==============================================================================
# 8. Service Configuration Hardening
# ==============================================================================
log_info "--- Section 8: Service Configuration ---"

# Example targeting Nginx (if installed)
if [[ -f /etc/nginx/nginx.conf ]]; then
    if ! grep -q "server_tokens off" /etc/nginx/nginx.conf; then
        log_found "Nginx is exposing its version (Banner Grabbing vulnerable)."
        sed -i 's/http {/http {\n\tserver_tokens off;/g' /etc/nginx/nginx.conf
        systemctl reload nginx
        log_fixed "Disabled Nginx server_tokens."
    else
        log_success "Nginx server_tokens already disabled."
    fi

    if grep -q "TLSv1 " /etc/nginx/nginx.conf || grep -q "TLSv1.1" /etc/nginx/nginx.conf; then
        log_found "Weak TLS protocols found in Nginx."
        sed -i 's/ssl_protocols.*/ssl_protocols TLSv1.2 TLSv1.3;/g' /etc/nginx/nginx.conf
        systemctl reload nginx
        log_fixed "Enforced TLSv1.2/1.3 only in Nginx."
    else
         log_success "Nginx TLS protocols are reasonably secure."
    fi
else
    log_info "Nginx not found. Skipping web service config checks."
fi

# ==============================================================================
# 9. User Account & sudo Audit (CCDC: Detect backdoor accounts & privilege escalation)
# ==============================================================================
log_info "--- Section 9: User Account & sudo Auditing ---"

# 9.1 Detect rogue/unauthorized user accounts
log_info "Checking for suspicious user accounts with login access..."
SUSPICIOUS_USERS=$(awk -F: '$7 !~ "(nologin|false)$" {print $1 ":" $7}' /etc/passwd)
if [[ -n "$SUSPICIOUS_USERS" ]]; then
    log_found "Users with login shells detected (verify these are legitimate):"
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

# Find all SUID/SGID binaries in standard system directories (faster than /)
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
for shellrc in /root/.bashrc /root/.bash_profile /home/*/.bashrc /home/*/.bash_profile; do
    if [[ -f "$shellrc" ]]; then
        if grep -qE 'curl|wget|nc -l|bash -i|/dev/tcp|eval|exec' "$shellrc"; then
            log_found "Suspicious content in $shellrc"
            grep -E 'curl|wget|nc -l|bash -i|/dev/tcp|eval|exec' "$shellrc" >> "$AUDIT_REPORT"
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

# 15.2 Audit root crontab
if [[ -f /var/spool/cron/crontabs/root ]]; then
    if grep -qvE "^(#|$)" /var/spool/cron/crontabs/root; then
        log_found "Root crontab has active entries:"
        grep -vE "^(#|$)" /var/spool/cron/crontabs/root | tee -a "$AUDIT_REPORT"
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
#log_info "--- Section 19: Audit Log Protection ---"

## 19.1 Enable auditd immutability to prevent tampering
#log_info "Enforcing auditd immutable flags..."
#if [[ -f /etc/audit/rules.d/99-wazuh.rules ]]; then
#    if ! grep -q "\-e 2" /etc/audit/rules.d/99-wazuh.rules; then
#        #echo "-e 2" >> /etc/audit/rules.d/99-wazuh.rules
#        auditctl -R /etc/audit/rules.d/99-wazuh.rules >/dev/null 2>&1 || true
#        log_fixed "Enabled immutable audit daemon flag (-e 2)."
#    fi
#fi

## 19.2 Configure rsyslog forwarding to prevent log deletion
#if [[ -f /etc/rsyslog.conf ]]; then
    #if ! grep -q "\$ActionFileEnableSync" /etc/rsyslog.conf; then
        #echo "\$ActionFileEnableSync on" >> /etc/rsyslog.conf
        #systemctl restart rsyslog >/dev/null 2>&1 || true
        #log_fixed "Enabled rsyslog sync mode (immediate disk write)."
    #fi
#fi

## ==============================================================================
## 20. Immutable Flag Protection
## ==============================================================================
#log_info "--- Section 20: Immutable File Protection ---"
#
#CRITICAL_FILES=("/etc/passwd" "/etc/shadow" "/etc/group" "/etc/gshadow" "/etc/audit/rules.d/")
#for crit in "${CRITICAL_FILES[@]}"; do
#    if [[ -e "$crit" ]]; then
#        if ! lsattr "$crit" 2>/dev/null | grep -q '\-i\-'; then
#            chattr +i "$crit" 2>/dev/null || true
#            log_fixed "Set immutable flag on $crit."
#        fi
#    fi
#done

log_info "=============================================================================="
log_info "Audit & Hardening Complete. Check $AUDIT_REPORT for full details."