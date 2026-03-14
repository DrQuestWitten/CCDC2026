#!/usr/bin/env bash
# ================================================================
#  MWCCDC System Hardening + IR Script — Ubuntu LAMP / ECOM
#  Based on Lynis 3.0.9 audit (Baseline hardening index: 69/100)
#
#  Usage:
#    sudo bash harden.sh --ir          # Incident Response audit (run FIRST)
#    sudo bash harden.sh --apply       # Apply all hardening fixes
#    sudo bash harden.sh --check       # Dry-run: show what would change
#    sudo bash harden.sh --verify      # Re-run Lynis and report score
#    sudo bash harden.sh --aide        # Initialize AIDE database (slow)
#    sudo bash harden.sh --watch       # Live color-coded security log monitor
#    bash harden.sh --ir-help          # IR false-positive reference guide
#    bash harden.sh --cheatsheet       # Quick competition command reference
#    bash harden.sh --help             # Show all modes
#
#  Recommended competition workflow:
#    1. sudo bash harden.sh --ir         (detect red team presence)
#    2. sudo bash harden.sh --apply      (harden everything)
#    3. sudo bash harden.sh --verify     (confirm Lynis score improved)
#    4. sudo bash harden.sh --aide &     (background when free)
# ================================================================

set -uo pipefail

# ── Colors ──────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Globals ──────────────────────────────────────────────────────
MODE="${1:---apply}"
BACKUP_DIR="/root/hardening-backups/$(date +%Y%m%d-%H%M%S)"
LOG_FILE="/root/hardening.log"

# Mode validation runs AFTER all functions are defined (bottom of script).
# This ensures show_ir_help / show_cheatsheet are callable from the case statement.
PASS=0
FAIL=0
SKIP=0
REBOOT_REQUIRED=0
IR_CRITICAL=0
IR_WARNINGS=0
IR_FIXED=0
IR_REPORT="/dev/null"

# ── Logging ──────────────────────────────────────────────────────
log()  { echo -e "$(date '+%H:%M:%S') $*" | tee -a "$LOG_FILE" 2>/dev/null || echo -e "$(date '+%H:%M:%S') $*"; }
info() { log "${BLUE}[INFO]${NC}  $*"; }
ok()   { log "${GREEN}[PASS]${NC}  $*"; ((PASS++)) || true; }
warn() { log "${YELLOW}[WARN]${NC}  $*"; }
fail() { log "${RED}[FAIL]${NC}  $*"; ((FAIL++)) || true; }
skip() { log "${CYAN}[SKIP]${NC}  $*"; ((SKIP++)) || true; }
section() { echo -e "\n${BOLD}${BLUE}═══ $* ═══${NC}" | tee -a "$LOG_FILE"; }

show_ir_help() {
    local B="$BOLD" N="$NC" R="$RED" Y="$YELLOW" G="$GREEN" C="$CYAN" BL="$BLUE"
    echo -e "\n${B}${BL}════════════════════════════════════════════════════════${N}"
    echo -e "${B}  MWCCDC IR MODE — SEVERITY GUIDE & FALSE POSITIVE REFERENCE${N}"
    echo -e "${B}${BL}════════════════════════════════════════════════════════${N}"
    echo -e "${B}${R}[CRITICAL]${N} = Act immediately — high-confidence indicator of compromise"
    echo -e "${B}${Y}[WARNING] ${N} = Suspicious but could be legitimate — verify before acting"
    echo -e "${B}${G}[CLEAN]   ${N} = Check passed, nothing found\n"

    echo -e "${B}${BL}── CHECK 1: User Accounts ───────────────────────────────${N}"
    echo -e "  ${R}CRITICAL${N} More than 1 UID 0 account"
    echo -e "           ${C}Why:${N} Only root should ever be UID 0. Extra ones = backdoor."
    echo -e "           ${C}FP?${N}  Very low. Verify: ${B}awk -F: '\$3==0' /etc/passwd${N}"
    echo -e "  ${R}CRITICAL${N} Account with empty /etc/shadow password field"
    echo -e "           ${C}Why:${N} Empty field = no password required to log in."
    echo -e "           ${C}FP?${N}  None. Always wrong. Fix: ${B}passwd <user>${N}"
    echo -e "  ${Y}WARNING ${N} Service account (UID 1-999) with a login shell"
    echo -e "           ${C}Why:${N} Services like www-data/mysql should use /sbin/nologin."
    echo -e "           ${C}FP?${N}  Medium. Some apps (git, postgres) need login shells."
    echo -e "           ${C}Fix:${N} ${B}usermod -s /usr/sbin/nologin <user>${N} if not needed."
    echo -e "  ${Y}WARNING ${N} /etc/passwd or /etc/shadow modified in last 7 days"
    echo -e "           ${C}FP?${N}  HIGH on comp day — your own --apply run triggers this."
    echo -e "           ${C}Rule:${N} Run --ir BEFORE --apply to get a clean baseline.\n"

    echo -e "${B}${BL}── CHECK 2: SSH Authorized Keys ─────────────────────────${N}"
    echo -e "  ${R}CRITICAL${N} /root/.ssh/authorized_keys is non-empty"
    echo -e "           ${C}Why:${N} Any key here gives passwordless root SSH access."
    echo -e "           ${C}FP?${N}  Medium. Your admin key might be there legitimately."
    echo -e "           ${C}Verify:${N} ${B}ssh-keygen -lf /root/.ssh/authorized_keys${N}"
    echo -e "           ${C}Fix:${N}  ${B}> /root/.ssh/authorized_keys${N} (clears all keys)"
    echo -e "  ${Y}WARNING ${N} authorized_keys modified in last 7 days"
    echo -e "           ${C}FP?${N}  Medium. You may have added it. Check the timestamp.\n"

    echo -e "${B}${BL}── CHECK 3: Cron Persistence ────────────────────────────${N}"
    echo -e "  ${R}CRITICAL${N} Cron entry matches: wget|curl|nc|bash -i|/tmp/|base64|python -c"
    echo -e "           ${C}Why:${N} These are classic red team callback/dropper patterns."
    echo -e "           ${C}FP?${N}  Medium. Legit admin scripts sometimes use curl or /tmp."
    echo -e "           ${C}Verify:${N} Read the full line printed — is the destination known?"
    echo -e "           ${C}Fix:${N}  ${B}crontab -r -u <user>${N} or edit ${B}/etc/cron.d/<file>${N}"
    echo -e "  ${Y}WARNING ${N} Cron file modified in last 3 days"
    echo -e "           ${C}FP?${N}  High. Package updates frequently touch /etc/cron.d/.\n"

    echo -e "${B}${BL}── CHECK 4: Systemd Services ────────────────────────────${N}"
    echo -e "  ${R}CRITICAL${N} ExecStart matches /tmp/|wget|bash -i|base64..."
    echo -e "           ${C}FP?${N}  Low. No real service should run from /tmp."
    echo -e "  ${R}CRITICAL${N} .service file found in /tmp, /var/tmp, /dev/shm"
    echo -e "           ${C}FP?${N}  None. Never legitimate."
    echo -e "           ${C}Fix:${N}  ${B}systemctl stop <name> && systemctl disable <name>${N}"
    echo -e "           ${C}Then:${N} ${B}rm <unit-file> && systemctl daemon-reload${N}"
    echo -e "  ${Y}WARNING ${N} Service in /etc/systemd/system modified in last 7 days"
    echo -e "           ${C}FP?${N}  High. --apply and package installs drop files here.\n"

    echo -e "${B}${BL}── CHECK 5: Sudo Configuration ──────────────────────────${N}"
    echo -e "  ${R}CRITICAL${N} Wildcard (/*) or NOPASSWD:ALL in sudoers"
    echo -e "           ${C}Why:${N} Gives anyone that user full root without a password."
    echo -e "           ${C}FP?${N}  Low. Almost always a backdoor or misconfiguration."
    echo -e "           ${C}Fix:${N}  ${B}visudo${N} — remove the offending line."
    echo -e "  ${Y}WARNING ${N} NOPASSWD for specific commands"
    echo -e "           ${C}FP?${N}  High. Ansible, monitoring agents use this legitimately."
    echo -e "           ${C}Rule:${N} Specific-command NOPASSWD is OK. NOPASSWD:ALL is not."
    echo -e "  ${Y}WARNING ${N} User has ALL=(ALL) ALL (full sudo)"
    echo -e "           ${C}FP?${N}  Medium. Verify the user is a known admin account.\n"

    echo -e "${B}${BL}── CHECK 6: Listening Ports ─────────────────────────────${N}"
    echo -e "  ${R}CRITICAL${N} MySQL listening on 0.0.0.0 (not 127.0.0.1)"
    echo -e "           ${C}Fix:${N}  bind-address = 127.0.0.1 in /etc/mysql/mysql.conf.d/mysqld.cnf"
    echo -e "  ${Y}WARNING ${N} Port not in expected list [22,80,443,25,587,3306] is open"
    echo -e "           ${C}FP?${N}  High. Comp machine may run extra services."
    echo -e "           ${C}Verify:${N} ${B}ss -tlnp${N} — check the 'users:(...)' column for the process."
    echo -e "           ${C}Rule:${N} If you can't identify who owns the port, kill and block it.\n"

    echo -e "${B}${BL}── CHECK 7: Webshell Detection ──────────────────────────${N}"
    echo -e "  ${R}CRITICAL${N} PHP file matches: eval(base64_decode|system(\$_|assert(\$_|..."
    echo -e "           ${C}Why:${N} These are high-confidence webshell execution patterns."
    echo -e "           ${C}FP?${N}  Medium. Some cache/obfuscation plugins look similar."
    echo -e "           ${C}Verify:${N} Read the exact lines printed. Is it obfuscated? Delete it."
    echo -e "  ${R}CRITICAL${N} PHP file in uploads/, files/, media/, tmp/ directory"
    echo -e "           ${C}FP?${N}  Low. PHP never belongs in upload dirs."
    echo -e "           ${C}Fix:${N}  ${B}rm <file>${N} then block PHP in that dir with Apache config."
    echo -e "  ${Y}WARNING ${N} PHP file modified in last 24 hours"
    echo -e "           ${C}FP?${N}  High on comp day. Deployments and WP updates trigger this."
    echo -e "           ${C}Verify:${N} Compare against git: ${B}git diff HEAD <file>${N}\n"

    echo -e "${B}${BL}── CHECK 8: Suspicious Processes ────────────────────────${N}"
    echo -e "  ${R}CRITICAL${N} Process running from /tmp, /dev/shm, /var/tmp"
    echo -e "           ${C}FP?${N}  Very low. ${C}Fix:${N} ${B}kill -9 <PID>${N}"
    echo -e "  ${R}CRITICAL${N} Process binary shows as '(deleted)' from disk"
    echo -e "           ${C}FP?${N}  Medium. Happens after a system update (old binary still running)."
    echo -e "           ${C}Verify:${N} ${B}ls -la /proc/<PID>/exe${N} — if it says 'deleted', check cmdline."
    echo -e "  ${R}CRITICAL${N} nc / ncat / socat / msfconsole process running"
    echo -e "           ${C}FP?${N}  Medium. nc/socat are sometimes used by admins for diagnostics."
    echo -e "           ${C}Verify:${N} ${B}ps aux | grep nc${N} — check the full command for destination."
    echo -e "  ${R}CRITICAL${N} www-data/apache spawned /bin/sh or /bin/bash"
    echo -e "           ${C}FP?${N}  Low. Apache spawning a shell = active webshell execution."
    echo -e "  ${Y}WARNING ${N} Process using >80% CPU"
    echo -e "           ${C}FP?${N}  High. Could be backup, build job, or anything legit."
    echo -e "           ${C}Verify:${N} ${B}ps aux --sort=-pcpu | head -5${N}\n"

    echo -e "${B}${BL}── CHECK 9: SUID/SGID Binaries ──────────────────────────${N}"
    echo -e "  ${Y}WARNING ${N} SUID/SGID binary not in known-good list"
    echo -e "           ${C}FP?${N}  High. Different Ubuntu versions and packages add binaries"
    echo -e "                not in our hardcoded list (e.g. snap, docker, ping)."
    echo -e "           ${C}Verify:${N} ${B}dpkg -S <binary-path>${N} — if it belongs to a package, it's fine."
    echo -e "           ${C}If none:${N} ${B}chmod u-s <file>${N} to remove SUID.\n"

    echo -e "${B}${BL}── CHECK 10: Rootkit Detection ──────────────────────────${N}"
    echo -e "  ${R}CRITICAL${N} chkrootkit reports INFECTED/Vulnerable"
    echo -e "           ${C}FP?${N}  Medium. 'bindshell INFECTED' is a well-known false positive."
    echo -e "           ${C}Rule:${N} Cross-check with rkhunter. If only one tool flags it, verify manually."
    echo -e "  ${R}CRITICAL${N} Known rootkit indicator files found (/dev/.udev, /usr/bin/.sshd...)"
    echo -e "           ${C}FP?${N}  Very low."
    echo -e "  ${R}CRITICAL${N} /etc/ld.so.preload is non-empty (LD_PRELOAD hijack)"
    echo -e "           ${C}FP?${N}  Medium. Some perf/profiling tools use this."
    echo -e "           ${C}Verify:${N} ${B}cat /etc/ld.so.preload${N} — if unknown library, it's a rootkit."
    echo -e "  ${Y}WARNING ${N} rkhunter reports warnings"
    echo -e "           ${C}FP?${N}  High. Commonly fires on recently updated binaries.\n"

    echo -e "${B}${BL}── CHECK 11: Persistence Mechanisms ────────────────────${N}"
    echo -e "  ${R}CRITICAL${N} Executable file in /tmp, /var/tmp, /dev/shm"
    echo -e "           ${C}FP?${N}  Medium. Package installers stage here temporarily."
    echo -e "           ${C}Verify:${N} ${B}file <path>${N} and ${B}stat <path>${N} — check age and type."
    echo -e "  ${R}CRITICAL${N} wget/curl/base64//tmp/ in .bashrc, .profile, or rc.local"
    echo -e "           ${C}FP?${N}  Low. Read the exact line. Outbound callback = red team."
    echo -e "  ${R}CRITICAL${N} LD_PRELOAD/LD_LIBRARY_PATH in /etc/environment or /etc/bash.bashrc"
    echo -e "           ${C}FP?${N}  Low. Never normal in system-wide shell init files."
    echo -e "  ${Y}WARNING ${N} rc.local exists with non-comment content"
    echo -e "           ${C}FP?${N}  Medium. Some comp machines use rc.local legitimately. Read it."
    echo -e "  ${Y}WARNING ${N} profile.d script modified in last 7 days"
    echo -e "           ${C}FP?${N}  High. Packages drop scripts here on install.\n"

    echo -e "${B}${BL}── CHECK 12: Active Network Connections ─────────────────${N}"
    echo -e "  ${R}CRITICAL${N} www-data/apache/mysql has established outbound connection"
    echo -e "           ${C}Why:${N} Web servers receive connections — they don't initiate them."
    echo -e "           ${C}FP?${N}  Low. Could be a legit API call, but investigate immediately."
    echo -e "           ${C}Verify:${N} ${B}ss -tp | grep www-data${N} — check the remote IP/port."
    echo -e "  ${R}CRITICAL${N} bash/sh process has established external TCP connection"
    echo -e "           ${C}Why:${N} A shell with an open socket = almost certainly a reverse shell."
    echo -e "           ${C}Fix:${N}  ${B}kill -9 <PID>${N} then block the remote IP with UFW.\n"

    echo -e "${B}${BL}── CHECK 13: Log Analysis ───────────────────────────────${N}"
    echo -e "  ${R}CRITICAL${N} Root SSH login found in auth.log"
    echo -e "           ${C}FP?${N}  Medium. Your own admin login triggers this."
    echo -e "           ${C}Verify:${N} Check the source IP. Unexpected IP = compromised key or brute-force win."
    echo -e "  ${R}CRITICAL${N} Webshell URL patterns in Apache log (c99, r57, .php?cmd=)"
    echo -e "           ${C}FP?${N}  Very low. These are known webshell names."
    echo -e "  ${Y}WARNING ${N} >50 failed SSH login attempts"
    echo -e "           ${C}FP?${N}  High. Internet-facing SSH is brute-forced constantly."
    echo -e "           ${C}Rule:${N} High count alone is normal. Worry if followed by a success."
    echo -e "  ${Y}WARNING ${N} SQLi/LFI patterns in Apache log"
    echo -e "           ${C}FP?${N}  High. Scanners hit everyone. Focus on 200/302 responses"
    echo -e "           ${C}Verify:${N} ${B}grep '200' /var/log/apache2/access.log | grep -i 'union.*select'${N}\n"

    echo -e "${B}${BL}── CHECK 14: File Integrity ──────────────────────────────${N}"
    echo -e "  ${R}CRITICAL${N} World-writable file in /etc, /bin, /sbin, /usr/bin"
    echo -e "           ${C}FP?${N}  Very low. ${C}Fix:${N} ${B}chmod o-w <file>${N}"
    echo -e "  ${R}CRITICAL${N} debsums reports altered package file checksum"
    echo -e "           ${C}FP?${N}  Medium. Config files in packages are expected to change."
    echo -e "           ${C}Rule:${N} Focus on /usr/bin/ and /usr/sbin/ failures — those are real tampering."
    echo -e "           ${C}Fix:${N}  ${B}apt install --reinstall <package>${N}"
    echo -e "  ${Y}WARNING ${N} System file in /etc//bin//sbin modified in last 7 days"
    echo -e "           ${C}FP?${N}  Very high. --apply itself touches many of these.\n"

    echo -e "${B}${BL}════════════════════════════════════════════════════════${N}"
    echo -e "${B}  KEY RULES FOR COMPETITION${N}"
    echo -e "${B}${BL}════════════════════════════════════════════════════════${N}"
    echo -e "  ${B}1.${N} Run ${B}--ir BEFORE --apply${N} — hardening triggers 'modified recently' warnings."
    echo -e "  ${B}2.${N} CRITICAL on a timestamp check = investigate ${B}file content${N}, not just the date."
    echo -e "  ${B}3.${N} Unexpected SUID? Run ${B}dpkg -S <path>${N}. Package-owned = likely fine."
    echo -e "  ${B}4.${N} chkrootkit 'bindshell INFECTED' = known false positive. Cross-check rkhunter."
    echo -e "  ${B}5.${N} debsums failures in /etc = expected (configs change). /usr/bin failures = bad."
    echo -e "  ${B}6.${N} SQLi/LFI WARNING alone = normal scanner noise. Only act if HTTP 200 response."
    echo -e "  ${B}7.${N} Any bash/sh process with an open external socket = kill it immediately.\n"
}

show_cheatsheet() {
    local B="$BOLD" N="$NC" R="$RED" Y="$YELLOW" G="$GREEN" C="$CYAN" BL="$BLUE"
    echo -e "\n${B}${BL}════════════════════════════════════════════════════════${N}"
    echo -e "${B}  MWCCDC COMPETITION CHEAT SHEET — Quick Reference${N}"
    echo -e "${B}${BL}════════════════════════════════════════════════════════${N}\n"

    echo -e "${B}${BL}── THIS SCRIPT ──────────────────────────────────────────${N}"
    echo -e "  ${B}sudo bash harden.sh --ir${N}          Incident response audit"
    echo -e "  ${B}sudo bash harden.sh --apply${N}       Apply all hardening"
    echo -e "  ${B}sudo bash harden.sh --check${N}       Dry-run (no changes)"
    echo -e "  ${B}sudo bash harden.sh --verify${N}      Re-run Lynis, show score"
    echo -e "  ${B}sudo bash harden.sh --aide &${N}      Init AIDE in background"
    echo -e "  ${B}sudo bash harden.sh --watch${N}       Live color-coded log monitor"
    echo -e "  ${B}bash harden.sh --ir-help${N}          IR false-positive guide"
    echo -e "  ${B}bash harden.sh --cheatsheet${N}       This page\n"

    echo -e "${B}${BL}── USERS & ACCOUNTS ─────────────────────────────────────${N}"
    echo -e "  ${C}List all users with login shells:${N}"
    echo -e "    ${B}grep -vE '/nologin|/false' /etc/passwd${N}"
    echo -e "  ${C}List all UID 0 accounts (should only be root):${N}"
    echo -e "    ${B}awk -F: '\$3==0' /etc/passwd${N}"
    echo -e "  ${C}List users in sudo/admin groups:${N}"
    echo -e "    ${B}getent group sudo adm${N}"
    echo -e "  ${C}Lock a suspicious account:${N}"
    echo -e "    ${B}usermod -L -s /usr/sbin/nologin <user>${N}"
    echo -e "  ${C}Delete a backdoor account:${N}"
    echo -e "    ${B}userdel -r <user>${N}"
    echo -e "  ${C}Force password change on next login:${N}"
    echo -e "    ${B}chage -d 0 <user>${N}"
    echo -e "  ${C}Check who is currently logged in:${N}"
    echo -e "    ${B}w${N} or ${B}who${N}\n"

    echo -e "${B}${BL}── SSH ───────────────────────────────────────────────────${N}"
    echo -e "  ${C}View current SSH config:${N}     ${B}sshd -T | grep -E 'permit|auth|root'${N}"
    echo -e "  ${C}Reload SSH after config change:${N}  ${B}systemctl reload ssh${N}"
    echo -e "  ${C}Find all authorized_keys files:${N}"
    echo -e "    ${B}find /root /home -name authorized_keys 2>/dev/null${N}"
    echo -e "  ${C}Wipe root authorized_keys:${N}   ${B}> /root/.ssh/authorized_keys${N}"
    echo -e "  ${C}Kill a specific SSH session:${N}"
    echo -e "    ${B}who${N}  (find pts/X)  then  ${B}pkill -9 -t pts/X${N}"
    echo -e "  ${C}Block an IP immediately:${N}     ${B}ufw deny from <IP>${N}\n"

    echo -e "${B}${BL}── PROCESSES & CONNECTIONS ──────────────────────────────${N}"
    echo -e "  ${C}Show all listening TCP ports with processes:${N}"
    echo -e "    ${B}ss -tlnp${N}"
    echo -e "  ${C}Show all established external connections:${N}"
    echo -e "    ${B}ss -tp | grep ESTAB | grep -v '127.0.0.1\|::1'${N}"
    echo -e "  ${C}Find process on a specific port:${N}"
    echo -e "    ${B}ss -tlnp | grep :<PORT>${N}"
    echo -e "  ${C}Find what a PID is running:${N}"
    echo -e "    ${B}ls -la /proc/<PID>/exe && cat /proc/<PID>/cmdline | tr '\\0' ' '${N}"
    echo -e "  ${C}Kill a process immediately:${N}  ${B}kill -9 <PID>${N}"
    echo -e "  ${C}Top CPU/memory consumers:${N}   ${B}ps aux --sort=-%cpu | head -10${N}"
    echo -e "  ${C}Find process by name:${N}        ${B}pgrep -a <name>${N}\n"

    echo -e "${B}${BL}── FIREWALL (UFW) ───────────────────────────────────────${N}"
    echo -e "  ${C}Show current rules:${N}          ${B}ufw status verbose${N}"
    echo -e "  ${C}Block an attacking IP:${N}       ${B}ufw deny from <IP> to any${N}"
    echo -e "  ${C}Block a specific port:${N}       ${B}ufw deny <PORT>/tcp${N}"
    echo -e "  ${C}Remove a rule:${N}               ${B}ufw delete deny from <IP>${N}"
    echo -e "  ${C}Re-apply competition rules:${N}  ${B}sudo bash harden.sh --apply${N}"
    echo -e "  ${C}Nuclear option — reset UFW:${N}  ${B}ufw --force reset && ufw --force enable${N}\n"

    echo -e "${B}${BL}── FILES & WEBSHELLS ────────────────────────────────────${N}"
    echo -e "  ${C}Find PHP files modified in last hour:${N}"
    echo -e "    ${B}find /var/www -name '*.php' -mmin -60${N}"
    echo -e "  ${C}Find world-writable files in web root:${N}"
    echo -e "    ${B}find /var/www -perm -0002 -type f${N}"
    echo -e "  ${C}Scan for webshell patterns:${N}"
    echo -e "    ${B}grep -rl 'eval(base64_decode\|system(\$_\|assert(\$_' /var/www${N}"
    echo -e "  ${C}Find PHP in upload directories:${N}"
    echo -e "    ${B}find /var/www -path '*/upload*' -name '*.php'${N}"
    echo -e "  ${C}Check file type (is it really a PHP?):${N}"
    echo -e "    ${B}file <path>${N}"
    echo -e "  ${C}Lock down upload directory (block PHP execution):${N}"
    echo -e "    Add to VirtualHost: ${B}<Directory /var/www/.../uploads>${N}"
    echo -e "                        ${B}php_admin_flag engine off${N}"
    echo -e "                        ${B}</Directory>${N}\n"

    echo -e "${B}${BL}── CRON & PERSISTENCE ───────────────────────────────────${N}"
    echo -e "  ${C}List all user crontabs:${N}"
    echo -e "    ${B}for u in \$(cut -d: -f1 /etc/passwd); do crontab -l -u \$u 2>/dev/null && echo \"--- \$u\"; done${N}"
    echo -e "  ${C}List system cron jobs:${N}       ${B}ls -la /etc/cron*${N}"
    echo -e "  ${C}View crontab contents:${N}       ${B}cat /etc/cron.d/<file>${N}"
    echo -e "  ${C}List systemd services (enabled):${N}"
    echo -e "    ${B}systemctl list-unit-files --type=service --state=enabled${N}"
    echo -e "  ${C}Inspect a suspicious service:${N}"
    echo -e "    ${B}systemctl cat <service>${N}"
    echo -e "  ${C}Disable and stop a service:${N}"
    echo -e "    ${B}systemctl stop <service> && systemctl disable <service>${N}"
    echo -e "  ${C}Check rc.local and profile persistence:${N}"
    echo -e "    ${B}cat /etc/rc.local ; ls /etc/profile.d/${N}\n"

    echo -e "${B}${BL}── LOGS ─────────────────────────────────────────────────${N}"
    echo -e "  ${C}Live auth log (SSH logins, sudo use):${N}"
    echo -e "    ${B}tail -f /var/log/auth.log${N}"
    echo -e "  ${C}Last successful logins:${N}      ${B}last | head -20${N}"
    echo -e "  ${C}Last failed logins:${N}          ${B}lastb | head -20${N}"
    echo -e "  ${C}Failed SSH attempts + IPs:${N}"
    echo -e "    ${B}grep 'Failed password' /var/log/auth.log | awk '{print \$11}' | sort | uniq -c | sort -rn | head -10${N}"
    echo -e "  ${C}Apache access log (live):${N}    ${B}tail -f /var/log/apache2/access.log${N}"
    echo -e "  ${C}Apache error log:${N}            ${B}tail -50 /var/log/apache2/error.log${N}"
    echo -e "  ${C}UFW blocked connections:${N}     ${B}grep 'UFW BLOCK' /var/log/ufw.log | tail -20${N}"
    echo -e "  ${C}MySQL error log:${N}             ${B}tail -50 /var/log/mysql/error.log${N}"
    echo -e "  ${C}All journal errors (live):${N}   ${B}journalctl -f -p err${N}\n"

    echo -e "${B}${BL}── MYSQL QUICK COMMANDS ─────────────────────────────────${N}"
    echo -e "  ${C}Connect to MySQL:${N}            ${B}sudo mysql${N}"
    echo -e "  ${C}List all users:${N}              ${B}SELECT user,host,plugin FROM mysql.user;${N}"
    echo -e "  ${C}Show grants for a user:${N}      ${B}SHOW GRANTS FOR '<user>'@'<host>';${N}"
    echo -e "  ${C}Kill a MySQL connection:${N}     ${B}SHOW PROCESSLIST;${N}  then  ${B}KILL <id>;${N}"
    echo -e "  ${C}Drop a suspicious user:${N}      ${B}DROP USER '<user>'@'<host>'; FLUSH PRIVILEGES;${N}"
    echo -e "  ${C}Reset root password:${N}"
    echo -e "    ${B}ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'NewPass!';${N}"
    echo -e "    ${B}FLUSH PRIVILEGES;${N}"
    echo -e "  ${C}Check for users with all privs:${N}"
    echo -e "    ${B}SELECT user,host FROM mysql.user WHERE Super_priv='Y';${N}\n"

    echo -e "${B}${BL}── APACHE QUICK COMMANDS ────────────────────────────────${N}"
    echo -e "  ${C}Test config syntax:${N}          ${B}apache2ctl configtest${N}"
    echo -e "  ${C}Reload Apache:${N}               ${B}systemctl reload apache2${N}"
    echo -e "  ${C}List loaded modules:${N}         ${B}apache2ctl -M${N}"
    echo -e "  ${C}Enable/disable a module:${N}     ${B}a2enmod <mod> / a2dismod <mod>${N}"
    echo -e "  ${C}Enable/disable a site:${N}       ${B}a2ensite <site> / a2dissite <site>${N}"
    echo -e "  ${C}View virtual hosts:${N}          ${B}apache2ctl -S${N}"
    echo -e "  ${C}Check ModSecurity status:${N}    ${B}grep SecRuleEngine /etc/modsecurity/modsecurity.conf${N}\n"

    echo -e "${B}${BL}── SUID/SGID & FILE PERMS ───────────────────────────────${N}"
    echo -e "  ${C}Find all SUID binaries:${N}      ${B}find / -xdev -perm -4000 -type f 2>/dev/null${N}"
    echo -e "  ${C}Find all SGID binaries:${N}      ${B}find / -xdev -perm -2000 -type f 2>/dev/null${N}"
    echo -e "  ${C}Remove SUID from a binary:${N}   ${B}chmod u-s <file>${N}"
    echo -e "  ${C}Verify binary belongs to package:${N} ${B}dpkg -S <file-path>${N}"
    echo -e "  ${C}Restore a tampered binary:${N}   ${B}apt install --reinstall <package>${N}"
    echo -e "  ${C}Check file checksum:${N}         ${B}sha256sum <file>${N}\n"

    echo -e "${B}${BL}── SERVICE STATUS OVERVIEW ──────────────────────────────${N}"
    echo -e "  ${B}systemctl status apache2${N}     ${B}systemctl status mysql${N}"
    echo -e "  ${B}systemctl status ssh${N}          ${B}systemctl status ufw${N}"
    echo -e "  ${B}systemctl status php8.3-fpm${N}  ${B}systemctl status postfix${N}"
    echo -e "  ${B}systemctl status apparmor${N}    ${B}systemctl status fail2ban${N}\n"

    echo -e "${B}${BL}── SCORING AWARENESS ────────────────────────────────────${N}"
    echo -e "  ${Y}Keep these services UP and responding:${N} Apache (80/443), SSH (22), MySQL"
    echo -e "  ${Y}Injects to watch for:${N} web defacement, MySQL data changes, new admin accounts"
    echo -e "  ${Y}After any incident:${N}"
    echo -e "    1. ${B}sudo bash harden.sh --ir${N}    (assess damage)"
    echo -e "    2. Fix the specific issue manually"
    echo -e "    3. ${B}sudo bash harden.sh --apply${N} (re-harden anything the RT changed)"
    echo -e "    4. Verify services are still running with ${B}systemctl status <service>${N}\n"
}

# ════════════════════════════════════════════════════════════════
# LIVE LOG MONITOR  (--watch)
# Tails auth, UFW, Apache access/error, ModSecurity, and MySQL logs
# simultaneously. Every line is color-coded by threat level and
# prefixed with a source tag. Run in a dedicated terminal window.
# ════════════════════════════════════════════════════════════════
run_watch() {
    local FIFO="/tmp/.harden_watch_$$"

    # ── Header ────────────────────────────────────────────────────
    clear
    echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${BLUE}║  MWCCDC LIVE LOG MONITOR                    Ctrl-C to stop  ║${NC}"
    echo -e "${BOLD}${BLUE}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${BOLD}${BLUE}║${NC}  ${RED}${BOLD}[CRITICAL]${NC} Active attack / confirmed compromise             ${BOLD}${BLUE}║${NC}"
    echo -e "${BOLD}${BLUE}║${NC}  ${YELLOW}[WARNING ]${NC}  Suspicious / needs review                        ${BOLD}${BLUE}║${NC}"
    echo -e "${BOLD}${BLUE}║${NC}  ${GREEN}[LOGIN   ]${NC}  Successful SSH login                              ${BOLD}${BLUE}║${NC}"
    echo -e "${BOLD}${BLUE}║${NC}  ${CYAN}[INFO    ]${NC}  Normal activity                                   ${BOLD}${BLUE}║${NC}"
    echo -e "${BOLD}${BLUE}╠══════════════════════════════════════════════════════════════╣${NC}"

    # ── Discover which logs exist ─────────────────────────────────
    local -A WATCH_LOGS=(
        [AUTH]="/var/log/auth.log"
        [UFW ]="/var/log/ufw.log"
        [WEB ]="/var/log/apache2/access.log"
        [AERR]="/var/log/apache2/error.log"
        [MSEC]="/var/log/apache2/modsec_audit.log"
        [SQL ]="/var/log/mysql/error.log"
    )

    local found_any=0
    for tag in "${!WATCH_LOGS[@]}"; do
        local f="${WATCH_LOGS[$tag]}"
        if [[ -f "$f" ]]; then
            echo -e "${BOLD}${BLUE}║${NC}  ${BOLD}[${tag}]${NC} $f"
            ((found_any++)) || true
        else
            echo -e "${BOLD}${BLUE}║${NC}  ${CYAN}[${tag}]${NC} ${YELLOW}(not found — skipping)${NC} $f"
        fi
    done

    echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo -e "${CYAN}Watching $found_any log source(s). Waiting for events...${NC}\n"

    if (( found_any == 0 )); then
        echo -e "${RED}No log files found. Nothing to watch.${NC}"
        return 1
    fi

    # ── Named pipe ────────────────────────────────────────────────
    mkfifo "$FIFO" 2>/dev/null || { echo -e "${RED}Cannot create FIFO${NC}"; return 1; }

    local -a watch_pids=()

    cleanup_watch() {
        echo -e "\n${CYAN}Stopping log monitor...${NC}"
        for pid in "${watch_pids[@]}"; do
            kill "$pid" 2>/dev/null || true
        done
        rm -f "$FIFO"
    }
    trap cleanup_watch EXIT INT TERM

    # ── Start one tail per log ────────────────────────────────────
    # tail -F handles log rotation (uppercase F = retry if file disappears)
    # Each line is written as "TAG|raw log line" to the shared FIFO
    for tag in "${!WATCH_LOGS[@]}"; do
        local f="${WATCH_LOGS[$tag]}"
        [[ -f "$f" ]] || continue
        (
            tail -F -n 0 "$f" 2>/dev/null | while IFS= read -r line; do
                # Write atomically (single printf call = single write syscall for short lines)
                printf '%s|%s\n' "$tag" "$line"
            done
        ) >> "$FIFO" &
        watch_pids+=($!)
    done

    # ── Classify and colorize each incoming line ──────────────────
    local color label msg

    while IFS='|' read -r tag line; do
        color="$NC"
        label=""
        msg="$line"

        case "$tag" in

          AUTH)
            if echo "$line" | grep -qE "Accepted.*(publickey|password).*root"; then
                color="$RED";    label="[CRITICAL] ROOT LOGIN  "
            elif echo "$line" | grep -qE "sudo.*COMMAND="; then
                # Extract just the user and command for brevity
                local sudo_who sudo_cmd
                sudo_who=$(echo "$line" | grep -oE 'sudo.*USER=[^ ]+' | head -1 || echo "")
                sudo_cmd=$(echo "$line" | grep -oE 'COMMAND=.*' | head -1 || echo "$line")
                label="[WARNING ] SUDO USE    "
                color="$YELLOW"
                msg="$sudo_cmd"
            elif echo "$line" | grep -qE "Accepted (publickey|password) for "; then
                color="$GREEN";  label="[LOGIN   ] SSH LOGIN   "
            elif echo "$line" | grep -qE "Invalid user|authentication failure"; then
                color="$YELLOW"; label="[WARNING ] BAD USER    "
            elif echo "$line" | grep -qE "Failed password|FAILED"; then
                color="$YELLOW"; label="[WARNING ] FAIL AUTH   "
            elif echo "$line" | grep -qE "session opened for user root"; then
                color="$RED";    label="[CRITICAL] ROOT SESSION"
            elif echo "$line" | grep -qE "session opened|session closed"; then
                color="$CYAN";   label="[INFO    ] SESSION     "
            else
                continue  # skip routine auth noise (PAM, CRON, etc.)
            fi
            ;;

          "UFW ")
            if echo "$line" | grep -q "UFW BLOCK"; then
                # Parse SRC IP and destination port for clean display
                local src dpt proto
                src=$(echo  "$line" | grep -oE 'SRC=[0-9.a-f:]+' | cut -d= -f2 || echo "?")
                dpt=$(echo  "$line" | grep -oE 'DPT=[0-9]+'       | cut -d= -f2 || echo "?")
                proto=$(echo "$line" | grep -oE 'PROTO=[A-Z]+'     | cut -d= -f2 || echo "?")
                color="$YELLOW"; label="[WARNING ] UFW BLOCK  "
                msg="$src → port $dpt/$proto"
            elif echo "$line" | grep -q "UFW ALLOW"; then
                continue  # skip allowed traffic — too noisy
            else
                continue
            fi
            ;;

          "WEB ")
            # Parse Apache combined log: IP - user [date] "METHOD URI PROTO" STATUS size
            local web_ip web_req web_status
            web_ip=$(echo     "$line" | awk '{print $1}')
            web_req=$(echo    "$line" | grep -oE '"[^"]*"' | head -1 | tr -d '"')
            web_status=$(echo "$line" | awk '{print $9}')

            if echo "$web_req" | grep -qiE 'c99|r57|wso\.|b374k|\.php\?cmd=|\.php\?exec=|shell\.php|cmd\.php'; then
                color="$RED";    label="[CRITICAL] WEBSHELL   "
                msg="$web_ip → $web_req [$web_status]"
            elif echo "$web_req" | grep -qiE "union.{0,20}select|select.{0,20}from|'.{0,10}(or|and).{0,10}'.*=|xp_cmdshell|waitfor.delay|benchmark\("; then
                color="$RED";    label="[CRITICAL] SQL INJECT "
                msg="$web_ip → $web_req [$web_status]"
            elif echo "$web_req" | grep -qiE '(\.\./){2,}|/etc/passwd|/proc/self|php://input|php://filter|data://text|expect://'; then
                color="$RED";    label="[CRITICAL] LFI/RFI    "
                msg="$web_ip → $web_req [$web_status]"
            elif echo "$web_req" | grep -qiE "<script|javascript:|onerror=|onload=|alert\(|document\.cookie"; then
                color="$RED";    label="[CRITICAL] XSS ATTEMPT"
                msg="$web_ip → $web_req [$web_status]"
            elif echo "$line" | grep -qiE 'sqlmap|nikto|masscan|nmap|dirbuster|gobuster|wfuzz|burpsuite|hydra|metasploit'; then
                color="$YELLOW"; label="[WARNING ] SCANNER    "
                msg="$web_ip → $web_req [$web_status]"
            elif echo "$web_req" | grep -qiE '\.php\?[a-z]+=http|base64_decode|eval\(|system\(|passthru\('; then
                color="$RED";    label="[CRITICAL] PHP EXPLOIT"
                msg="$web_ip → $web_req [$web_status]"
            elif [[ "$web_status" =~ ^[45] ]]; then
                color="$YELLOW"; label="[WARNING ] HTTP $web_status    "
                msg="$web_ip → $web_req"
            elif [[ "$web_status" == "200" ]]; then
                color="$CYAN";   label="[INFO    ] HTTP 200   "
                msg="$web_ip → $web_req"
            else
                continue  # skip other status codes
            fi
            ;;

          AERR)
            if echo "$line" | grep -qiE '\[(error|crit|emerg|alert)\]'; then
                color="$RED";    label="[CRITICAL] APACHE ERR "
            elif echo "$line" | grep -qiE '\[warn\]'; then
                color="$YELLOW"; label="[WARNING ] APACHE WARN"
            else
                continue
            fi
            ;;

          MSEC)
            # ModSecurity audit log — any new entry means a rule fired
            if echo "$line" | grep -qE '^--[a-f0-9]+-A--'; then
                color="$RED";    label="[CRITICAL] MODSEC RULE"
                msg="ModSecurity rule triggered — check modsec_audit.log"
            else
                continue
            fi
            ;;

          "SQL ")
            if echo "$line" | grep -qiE 'error|warning|denied|failed|crash'; then
                color="$YELLOW"; label="[WARNING ] MYSQL      "
            else
                continue
            fi
            ;;

          *) continue ;;
        esac

        # Truncate very long messages to keep output scannable
        msg="${msg:0:120}"

        echo -e "$(date '+%H:%M:%S') ${BOLD}${color}[${tag}]${NC} ${color}${label}${NC} $msg"

    done < "$FIFO"
}

# ── Helpers ──────────────────────────────────────────────────────
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}ERROR: This script must be run as root. Use: sudo bash harden.sh${NC}"
        exit 1
    fi
}

is_check_mode() { [[ "$MODE" == "--check" ]]; }

backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        local dest="$BACKUP_DIR$(dirname "$file")"
        if mkdir -p "$dest" 2>/dev/null; then
            cp -p "$file" "$dest/" && log "  Backed up: $file -> $dest/"
        else
            warn "  Could not create backup dir $dest — skipping backup of $file"
        fi
    fi
}

# Apply a sysctl value (idempotent)
apply_sysctl() {
    local key="$1" val="$2"
    local current
    current=$(sysctl -n "$key" 2>/dev/null || echo "UNKNOWN")
    if [[ "$current" == "$val" ]]; then
        ok "sysctl $key = $val (already set)"
        return
    fi
    if is_check_mode; then
        warn "[CHECK] Would set: $key = $val (currently: $current)"
        return
    fi
    if sysctl -w "$key=$val" &>/dev/null; then
        ok "sysctl $key = $val (was: $current)"
    else
        fail "sysctl $key — failed to set"
    fi
}

# Ensure a line exists in a file (idempotent)
ensure_line() {
    local file="$1" line="$2"
    if grep -qxF "$line" "$file" 2>/dev/null; then
        return 0  # already there
    fi
    echo "$line" >> "$file"
}

# Replace or append a key=value in a config file
# Detection uses [[:space:]=] to cover both whitespace-separated and =-separated configs.
set_config_value() {
    local file="$1" key="$2" value="$3" separator="${4:- }"
    if grep -qE "^[[:space:]]*#?[[:space:]]*${key}[[:space:]=]" "$file" 2>/dev/null; then
        sed -i "s|^[[:space:]]*#\?[[:space:]]*${key}[[:space:]=].*|${key}${separator}${value}|" "$file"
    else
        echo "${key}${separator}${value}" >> "$file"
    fi
}

# ════════════════════════════════════════════════════════════════
# 1. KERNEL SYSCTL HARDENING  [KRNL-6000]
# ════════════════════════════════════════════════════════════════
harden_sysctl() {
    section "Kernel sysctl Hardening [KRNL-6000]"
    local conf="/etc/sysctl.d/99-hardening.conf"

    if is_check_mode; then
        warn "[CHECK] Would create $conf with hardened sysctl values"
        local params=(
            "kernel.sysrq=0"
            "fs.suid_dumpable=0"
            "kernel.core_uses_pid=1"
            "kernel.kptr_restrict=2"
            "kernel.unprivileged_bpf_disabled=1"
            "kernel.perf_event_paranoid=3"
            "dev.tty.ldisc_autoload=0"
            "fs.protected_fifos=2"
            "net.ipv4.conf.all.send_redirects=0"
            "net.ipv4.conf.all.log_martians=1"
            "net.ipv4.conf.all.rp_filter=1"
            "net.ipv4.conf.default.accept_source_route=0"
            "net.ipv4.conf.default.log_martians=1"
        )
        for p in "${params[@]}"; do
            key="${p%%=*}"
            expected="${p##*=}"
            current=$(sysctl -n "$key" 2>/dev/null || echo "UNKNOWN")
            if [[ "$current" != "$expected" ]]; then
                warn "[CHECK]   $key: $current → $expected"
            else
                ok "$key = $expected (already set)"
            fi
        done
        return
    fi

    backup_file "$conf"
    cat > "$conf" << 'EOF'
# MWCCDC Hardening — kernel parameters
kernel.sysrq = 0
fs.suid_dumpable = 0
kernel.core_uses_pid = 1
kernel.kptr_restrict = 2
kernel.unprivileged_bpf_disabled = 1
kernel.perf_event_paranoid = 3
dev.tty.ldisc_autoload = 0
fs.protected_fifos = 2
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.log_martians = 1
EOF
    if sysctl --system &>/dev/null; then
        ok "sysctl --system applied successfully"
    else
        fail "sysctl --system failed"
    fi

    # Verify each value
    apply_sysctl "kernel.sysrq"                      "0"
    apply_sysctl "fs.suid_dumpable"                  "0"
    apply_sysctl "kernel.core_uses_pid"              "1"
    apply_sysctl "kernel.kptr_restrict"              "2"
    apply_sysctl "kernel.unprivileged_bpf_disabled"  "1"
    apply_sysctl "kernel.perf_event_paranoid"        "3"
    apply_sysctl "dev.tty.ldisc_autoload"            "0"
    apply_sysctl "fs.protected_fifos"                "2"
    apply_sysctl "net.ipv4.conf.all.send_redirects"  "0"
    apply_sysctl "net.ipv4.conf.all.log_martians"    "1"
    apply_sysctl "net.ipv4.conf.all.rp_filter"       "1"
    apply_sysctl "net.ipv4.conf.default.accept_source_route" "0"
    apply_sysctl "net.ipv4.conf.default.log_martians" "1"
}

# ════════════════════════════════════════════════════════════════
# 2. SSH HARDENING  [SSH-7408]
# ════════════════════════════════════════════════════════════════
harden_ssh() {
    section "SSH Hardening [SSH-7408]"
    local conf="/etc/ssh/sshd_config"

    if ! [[ -f "$conf" ]]; then
        fail "sshd_config not found at $conf"
        return
    fi

    if is_check_mode; then
        warn "[CHECK] Would harden $conf with missing security options"
        local opts=(
            "LoginGraceTime 60"
            "ClientAliveInterval 300"
            "ClientAliveCountMax 2"
            "LogLevel VERBOSE"
            "StrictModes yes"
            "IgnoreRhosts yes"
            "PermitEmptyPasswords no"
            "PrintLastLog yes"
            "UseDNS no"
            "Banner /etc/issue.net"
        )
        for opt in "${opts[@]}"; do
            key="${opt%% *}"
            if grep -qiE "^[[:space:]]*${key}[[:space:]]" "$conf"; then
                ok "$key already explicitly set"
            else
                warn "[CHECK]   Missing: $opt"
            fi
        done
        return
    fi

    backup_file "$conf"

    # Drop in a hardening include file so we don't clobber the main config
    local include_conf="/etc/ssh/sshd_config.d/99-hardening.conf"
    mkdir -p /etc/ssh/sshd_config.d
    cat > "$include_conf" << 'EOF'
# MWCCDC SSH Hardening
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
StrictModes yes
IgnoreRhosts yes
PermitEmptyPasswords no
PrintLastLog yes
UseDNS no
Banner /etc/issue.net
EOF

    # Verify the include directory is loaded
    if ! grep -q "Include /etc/ssh/sshd_config.d" "$conf"; then
        echo "Include /etc/ssh/sshd_config.d/*.conf" >> "$conf"
        info "Added Include directive to sshd_config"
    fi

    if sshd -t 2>/dev/null; then
        if systemctl restart ssh 2>/dev/null; then
            ok "SSH hardening applied and service restarted"
        else
            fail "SSH restart failed — check sshd -t"
        fi
    else
        fail "sshd config test failed — not restarting"
    fi
}

# ════════════════════════════════════════════════════════════════
# 3. APPARMOR  [MACF-6208]
# ════════════════════════════════════════════════════════════════
harden_apparmor() {
    section "AppArmor Enforcement [MACF-6208]"

    if is_check_mode; then
        local status
        status=$(aa-status 2>/dev/null | head -1 || echo "unknown")
        warn "[CHECK] AppArmor status: $status — would enforce all profiles"
        return
    fi

    if ! command -v aa-status &>/dev/null; then
        fail "AppArmor not installed"
        return
    fi

    systemctl enable apparmor &>/dev/null
    systemctl start apparmor 2>/dev/null || true

    local enforced=0 total=0
    while IFS= read -r profile; do
        aa-enforce "$profile" &>/dev/null && ((enforced++)) || true
        ((total++)) || true
    done < <(find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null)

    local complain_count
    complain_count=$(aa-status 2>/dev/null | grep -c "complain mode" 2>/dev/null || echo "0")
    complain_count=${complain_count:-0}

    ok "AppArmor: $enforced/$total profiles enforced, $complain_count in complain mode"
}

# ════════════════════════════════════════════════════════════════
# 4. PASSWORD POLICY  [AUTH-9286, AUTH-9230, AUTH-9328]
# ════════════════════════════════════════════════════════════════
harden_password_policy() {
    section "Password Policy [AUTH-9286 / AUTH-9230 / AUTH-9328]"
    local defs="/etc/login.defs"

    if is_check_mode; then
        local max_days min_days warn_age umask_val
        max_days=$(grep "^PASS_MAX_DAYS" "$defs" | awk '{print $2}')
        min_days=$(grep "^PASS_MIN_DAYS" "$defs" | awk '{print $2}')
        warn_age=$(grep "^PASS_WARN_AGE" "$defs" | awk '{print $2}')
        umask_val=$(grep "^UMASK" "$defs" | awk '{print $2}')
        warn "[CHECK] PASS_MAX_DAYS=${max_days:-unset} (want 90), PASS_MIN_DAYS=${min_days:-unset} (want 1), UMASK=${umask_val:-unset} (want 027)"
        return
    fi

    backup_file "$defs"

    set_config_value "$defs" "PASS_MAX_DAYS"  "90"   "\t"
    set_config_value "$defs" "PASS_MIN_DAYS"  "1"    "\t"
    set_config_value "$defs" "PASS_WARN_AGE"  "7"    "\t"
    set_config_value "$defs" "UMASK"          "027"  "\t\t"
    set_config_value "$defs" "SHA512_CRYPT_MIN_ROUNDS" "65536" "\t"
    set_config_value "$defs" "SHA512_CRYPT_MAX_ROUNDS" "65536" "\t"

    ok "Password aging: MAX=90 MIN=1 WARN=7"
    ok "Password hashing rounds: 65536"
    ok "Default umask: 027"

    # Apply to existing users (non-system, UID >= 1000)
    local updated=0
    while IFS=: read -r user _ uid _; do
        if (( uid >= 1000 )); then
            chage --maxdays 90 --mindays 1 --warndays 7 "$user" 2>/dev/null && ((updated++)) || true
        fi
    done < /etc/passwd
    ok "Password aging applied to $updated user account(s)"
}

# ════════════════════════════════════════════════════════════════
# 5. FILE PERMISSIONS  [FILE-7524]
# ════════════════════════════════════════════════════════════════
harden_file_perms() {
    section "File Permissions [FILE-7524]"

    local -A perms=(
        ["/etc/crontab"]="600"
        ["/etc/ssh/sshd_config"]="600"
        ["/etc/cron.d"]="700"
        ["/etc/cron.daily"]="700"
        ["/etc/cron.hourly"]="700"
        ["/etc/cron.weekly"]="700"
        ["/etc/cron.monthly"]="700"
        ["/etc/passwd"]="644"
        ["/etc/shadow"]="640"
        ["/etc/group"]="644"
        ["/etc/gshadow"]="640"
    )

    for path in "${!perms[@]}"; do
        local desired="${perms[$path]}"
        if [[ ! -e "$path" ]]; then
            skip "$path not found"
            continue
        fi
        local current
        current=$(stat -c "%a" "$path" 2>/dev/null)
        if [[ "$current" == "$desired" ]]; then
            ok "  $path: $current (already $desired)"
            continue
        fi
        if is_check_mode; then
            warn "[CHECK] $path: $current → $desired"
            continue
        fi
        chmod "$desired" "$path" && ok "$path → $desired (was $current)" || fail "$path chmod failed"
    done
}

# ════════════════════════════════════════════════════════════════
# 6. POSTFIX VRFY COMMAND  [MAIL-8820]
# ════════════════════════════════════════════════════════════════
harden_postfix() {
    section "Postfix VRFY Disable [MAIL-8820]"

    if ! command -v postconf &>/dev/null; then
        skip "Postfix not installed"
        return
    fi

    local current
    current=$(postconf disable_vrfy_command 2>/dev/null | awk '{print $3}')

    if [[ "$current" == "yes" ]]; then
        ok "disable_vrfy_command already set to yes"
        return
    fi

    if is_check_mode; then
        warn "[CHECK] Would set: disable_vrfy_command=yes (currently: $current)"
        return
    fi

    if postconf -e disable_vrfy_command=yes && systemctl restart postfix 2>/dev/null; then
        ok "Postfix VRFY command disabled"
    else
        fail "Failed to disable Postfix VRFY"
    fi
}

# ════════════════════════════════════════════════════════════════
# 7. AIDE DATABASE INITIALIZATION  [FINT-4316]
# ════════════════════════════════════════════════════════════════
harden_aide() {
    section "AIDE File Integrity Database [FINT-4316]"

    if ! command -v aide &>/dev/null; then
        skip "AIDE not installed — run: apt install aide"
        return
    fi

    # Check if AIDE config needs SHA256/SHA512 fix [FINT-4402]
    local aide_conf="/etc/aide/aide.conf"
    if [[ -f "$aide_conf" ]]; then
        if ! grep -qE "sha256|sha512|SHA256|SHA512" "$aide_conf"; then
            if ! is_check_mode; then
                backup_file "$aide_conf"
                # Add SHA256 to the NORMAL group if it exists
                sed -i 's/^NORMAL[[:space:]]*=.*/NORMAL = p+i+n+u+g+s+m+acl+selinux+xattrs+sha256/' "$aide_conf" 2>/dev/null || true
                ok "AIDE config updated to use SHA256"
            else
                warn "[CHECK] Would update AIDE config to use SHA256"
            fi
        else
            ok "AIDE config uses strong checksums"
        fi
    fi

    local db="/var/lib/aide/aide.db"
    local new_db="/var/lib/aide/aide.db.new"

    if [[ -f "$db" ]]; then
        ok "AIDE database already exists at $db"
        return
    fi

    if is_check_mode; then
        warn "[CHECK] Would initialize AIDE database (aide --init) — takes several minutes"
        return
    fi

    info "Initializing AIDE database — this may take a few minutes..."
    local aide_init_ok=0
    # Try aideinit (Debian/Ubuntu wrapper) first, then aide --init
    if command -v aideinit &>/dev/null; then
        aideinit -y &>/dev/null && aide_init_ok=1 || true
    fi
    if (( aide_init_ok == 0 )); then
        aide --init &>/dev/null && aide_init_ok=1 || true
    fi
    if (( aide_init_ok == 1 )); then
        # aide --init creates aide.db.new; copy to active db location
        if [[ -f "$new_db" ]]; then
            cp "$new_db" "$db"
            ok "AIDE database initialized at $db"
        elif [[ -f "/var/lib/aide/aide.db.new.gz" ]]; then
            cp "/var/lib/aide/aide.db.new.gz" "${db}.gz"
            ok "AIDE database initialized at ${db}.gz"
        else
            warn "AIDE init ran but database not found at expected path — check aide.conf"
        fi
    else
        fail "AIDE initialization failed — run manually: aide --init"
    fi
}

# ════════════════════════════════════════════════════════════════
# 8. LOGIN BANNERS  [BANN-7126 / BANN-7130]
# ════════════════════════════════════════════════════════════════
harden_banners() {
    section "Login Banners [BANN-7126 / BANN-7130]"

    local banner_text="WARNING: Unauthorized access to this system is prohibited.
All connections are monitored and recorded.
Disconnect immediately if you are not an authorized user."

    for f in /etc/issue /etc/issue.net; do
        local current_content
        current_content=$(cat "$f" 2>/dev/null || echo "")
        if echo "$current_content" | grep -q "WARNING.*Unauthorized"; then
            ok "$f already has legal banner"
            continue
        fi
        if is_check_mode; then
            warn "[CHECK] $f has weak content — would replace with legal banner"
            continue
        fi
        backup_file "$f"
        echo "$banner_text" > "$f"
        ok "$f updated with legal warning banner"
    done
}

# ════════════════════════════════════════════════════════════════
# 9. DISABLE UNUSED NETWORK PROTOCOLS  [NETW-3200]
# ════════════════════════════════════════════════════════════════
harden_protocols() {
    section "Disable Unused Network Protocols [NETW-3200]"
    local conf="/etc/modprobe.d/disable-protocols.conf"

    local protocols=("dccp" "sctp" "rds" "tipc")

    if is_check_mode; then
        for proto in "${protocols[@]}"; do
            if grep -q "install $proto /bin/true" "$conf" 2>/dev/null; then
                ok "$proto already disabled"
            else
                warn "[CHECK] Would blacklist: $proto"
            fi
        done
        return
    fi

    backup_file "$conf"
    {
        echo "# MWCCDC — disable unused/dangerous network protocols"
        for proto in "${protocols[@]}"; do
            echo "install $proto /bin/true"
        done
    } > "$conf"

    for proto in "${protocols[@]}"; do
        if grep -q "install $proto /bin/true" "$conf"; then
            ok "Protocol $proto blacklisted"
            # Try to unload if currently loaded
            modprobe -r "$proto" 2>/dev/null || true
        else
            fail "Failed to blacklist $proto"
        fi
    done
    REBOOT_REQUIRED=1
}

# ════════════════════════════════════════════════════════════════
# 10. /proc hidepid  [FILE-6336]
# ════════════════════════════════════════════════════════════════
harden_proc() {
    section "/proc hidepid [FILE-6336]"
    local fstab="/etc/fstab"

    # Check for either hidepid=2 or hidepid=invisible (Ubuntu 22.04+ preferred)
    if grep -qE "hidepid=(2|invisible)" "$fstab" 2>/dev/null; then
        ok "/proc hidepid already configured in fstab"
        mount -o remount,hidepid=2 /proc 2>/dev/null || true
        return
    fi

    if is_check_mode; then
        warn "[CHECK] Would add hidepid=2 to /proc mount in fstab"
        return
    fi

    backup_file "$fstab"

    # Use hidepid=2 for compatibility across Ubuntu 18.04-24.04
    if grep -q "^proc " "$fstab"; then
        # Append hidepid=2 to the OPTIONS field (4th column) using awk
        local tmp_fstab
        tmp_fstab=$(awk 'BEGIN{OFS="\t"} /^proc[[:space:]]/{$4=$4",hidepid=2"} {print}' "$fstab")
        echo "$tmp_fstab" > "$fstab"
    else
        echo "proc /proc proc defaults,hidepid=2 0 0" >> "$fstab"
    fi

    if mount -o remount,hidepid=2 /proc 2>/dev/null; then
        ok "/proc remounted with hidepid=2"
    else
        # On Ubuntu 22.04+, /proc is managed by systemd — fstab entry takes effect at reboot
        warn "/proc hidepid=2 added to fstab — takes effect after reboot (systemd manages /proc)"
        REBOOT_REQUIRED=1
    fi
}

# ════════════════════════════════════════════════════════════════
# 11. SHELL SESSION TIMEOUT
# ════════════════════════════════════════════════════════════════
harden_session_timeout() {
    section "Shell Session Timeout"
    local timeout_file="/etc/profile.d/99-timeout.sh"

    if [[ -f "$timeout_file" ]] && grep -q "TMOUT" "$timeout_file"; then
        ok "Session timeout already configured"
        return
    fi

    if is_check_mode; then
        warn "[CHECK] Would create $timeout_file with TMOUT=900"
        return
    fi

    cat > "$timeout_file" << 'EOF'
# MWCCDC — auto-logout idle sessions after 15 minutes
TMOUT=900
readonly TMOUT
export TMOUT
EOF
    chmod 644 "$timeout_file"
    ok "Session timeout set to 900s (15 min) in $timeout_file"
}

# ════════════════════════════════════════════════════════════════
# 12. RESTRICT COMPILER ACCESS  [HRDN-7222]
# ════════════════════════════════════════════════════════════════
harden_compilers() {
    section "Restrict Compiler Access [HRDN-7222]"

    local compilers=()
    for bin in gcc gcc-* g++ g++-* cc cpp; do
        local path
        path=$(which "$bin" 2>/dev/null || true)
        [[ -n "$path" ]] && compilers+=("$path")
    done

    if [[ ${#compilers[@]} -eq 0 ]]; then
        skip "No compilers found"
        return
    fi

    for compiler in "${compilers[@]}"; do
        local perms
        perms=$(stat -c "%a" "$compiler" 2>/dev/null)
        # Check if others have execute permission (perms should be 3-4 octal digits)
        [[ "$perms" =~ ^[0-7]+$ ]] || { warn "Could not stat $compiler — skipping"; continue; }
        local other_exec
        other_exec=$(( 8#${perms} & 1 ))
        if [[ "$other_exec" -eq 0 ]]; then
            ok "$compiler — others cannot execute (already restricted)"
            continue
        fi
        if is_check_mode; then
            warn "[CHECK] Would remove other-execute from $compiler (current: $perms)"
            continue
        fi
        chmod o-rx "$compiler" && ok "$compiler — restricted to root/group only" || fail "$compiler chmod failed"
    done
}

# ════════════════════════════════════════════════════════════════
# 13. DISABLE CORE DUMPS  [KRNL-5820]
# ════════════════════════════════════════════════════════════════
harden_core_dumps() {
    section "Disable Core Dumps [KRNL-5820]"
    local limits="/etc/security/limits.conf"
    local systemd_conf="/etc/systemd/coredump.conf"

    if is_check_mode; then
        grep -qE "^\*.*hard.*core.*0" "$limits" 2>/dev/null \
            && ok "limits.conf already disables core dumps" \
            || warn "[CHECK] Would add core dump limits to $limits"
        return
    fi

    backup_file "$limits"
    if ! grep -qE "^\*.*hard.*core.*0" "$limits"; then
        echo "# MWCCDC — disable core dumps" >> "$limits"
        echo "* hard core 0" >> "$limits"
        echo "* soft core 0" >> "$limits"
        ok "Core dumps disabled in limits.conf"
    else
        ok "Core dump limit already in limits.conf"
    fi

    # Also via systemd
    if [[ -f "$systemd_conf" ]]; then
        backup_file "$systemd_conf"
        set_config_value "$systemd_conf" "Storage" "none" "="
        set_config_value "$systemd_conf" "ProcessSizeMax" "0" "="
        ok "systemd coredump disabled"
    fi
}

# ════════════════════════════════════════════════════════════════
# 14. INSTALL SECURITY PACKAGES  [DEB-0280, DEB-0831, PKGS-7370]
# ════════════════════════════════════════════════════════════════
harden_packages() {
    section "Security Package Installation [DEB-0280 / DEB-0831]"

    local packages=("libpam-tmpdir" "needrestart" "debsums" "apt-show-versions")

    if is_check_mode; then
        for pkg in "${packages[@]}"; do
            dpkg -l "$pkg" 2>/dev/null | grep -q "^ii" \
                && ok "$pkg already installed" \
                || warn "[CHECK] Would install: $pkg"
        done
        return
    fi

    apt-get update -qq 2>/dev/null || warn "apt update failed — continuing"

    for pkg in "${packages[@]}"; do
        if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
            ok "$pkg already installed"
        else
            if apt-get install -y -qq "$pkg" 2>/dev/null; then
                ok "$pkg installed"
            else
                fail "$pkg installation failed"
            fi
        fi
    done
}

# ════════════════════════════════════════════════════════════════
# 15. DISABLE USB STORAGE  [USB-1000]
# ════════════════════════════════════════════════════════════════
harden_usb() {
    section "Disable USB Storage [USB-1000]"
    local conf="/etc/modprobe.d/disable-usb-storage.conf"

    if grep -q "install usb-storage /bin/true" "$conf" 2>/dev/null; then
        ok "USB storage already disabled"
        return
    fi

    if is_check_mode; then
        warn "[CHECK] Would disable usb-storage kernel module"
        return
    fi

    echo "install usb-storage /bin/true" > "$conf"
    modprobe -r usb-storage 2>/dev/null || true
    ok "USB storage module disabled"
    REBOOT_REQUIRED=1
}

# ════════════════════════════════════════════════════════════════
# 16. UMASK SYSTEM-WIDE  [AUTH-9328]
# ════════════════════════════════════════════════════════════════
harden_umask() {
    section "System-wide umask [AUTH-9328]"

    local files=("/etc/profile" "/etc/bash.bashrc")

    for f in "${files[@]}"; do
        [[ -f "$f" ]] || continue
        if grep -q "umask 027" "$f" 2>/dev/null; then
            ok "$f already has umask 027"
            continue
        fi
        if is_check_mode; then
            warn "[CHECK] Would add 'umask 027' to $f"
            continue
        fi
        backup_file "$f"
        echo "" >> "$f"
        echo "# MWCCDC — stricter default umask" >> "$f"
        echo "umask 027" >> "$f"
        ok "umask 027 added to $f"
    done
}

# ════════════════════════════════════════════════════════════════
# 17. PASSWORD FILE CONSISTENCY  [AUTH-9228]
# ════════════════════════════════════════════════════════════════
harden_pwck() {
    section "Password File Consistency [AUTH-9228]"

    if is_check_mode; then
        warn "[CHECK] Would run: pwck -r (read-only check)"
        pwck -r 2>&1 | head -5 || true
        return
    fi

    local output
    output=$(pwck -r 2>&1 || true)
    if echo "$output" | grep -qi "no changes"; then
        ok "Password file is consistent"
    elif [[ -z "$output" ]]; then
        ok "Password file is consistent"
    else
        warn "pwck found issues: $output"
        warn "Review with: sudo pwck"
    fi
}

# ════════════════════════════════════════════════════════════════
# 18. POSTFIX SMTP HARDENING (extra)
# ════════════════════════════════════════════════════════════════
harden_postfix_extra() {
    section "Postfix Extra Hardening"

    if ! command -v postconf &>/dev/null; then
        skip "Postfix not installed"
        return
    fi

    if is_check_mode; then
        local banner
        banner=$(postconf smtpd_banner 2>/dev/null | awk -F= '{print $2}')
        warn "[CHECK] Current smtpd_banner: $banner"
        return
    fi

    # Hide version info from banner
    postconf -e "smtpd_banner = \$myhostname ESMTP" 2>/dev/null && ok "Postfix version hidden from banner" || true
    # Disable open relay
    postconf -e "smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, defer_unauth_destination" 2>/dev/null || true
    ok "Postfix relay restrictions set"
    systemctl restart postfix 2>/dev/null || true
}

# ════════════════════════════════════════════════════════════════
# 19. UFW FIREWALL HARDENING
# ════════════════════════════════════════════════════════════════
harden_ufw() {
    section "UFW Firewall Hardening"

    # Install UFW if missing
    if ! command -v ufw &>/dev/null; then
        if [[ "$MODE" == "--apply" ]]; then
            apt-get install -y ufw &>/dev/null \
                && ok "ufw installed" \
                || { fail "ufw install failed — skipping firewall hardening"; return; }
        else
            skip "ufw not installed (would install)"
            return
        fi
    fi

    if [[ "$MODE" != "--apply" ]]; then
        local ufw_status
        ufw_status=$(ufw status 2>/dev/null || echo "unknown")
        if echo "$ufw_status" | grep -q "Status: active"; then
            ok "UFW is active"
            for port in 22 80 443; do
                if echo "$ufw_status" | grep -qE "^${port}[/ ].*ALLOW"; then
                    ok "Port $port is allowed"
                else
                    fail "Port $port is NOT explicitly allowed in UFW"
                fi
            done
        else
            fail "UFW is not active"
        fi
        return
    fi

    # ── Reset to known-good state ─────────────────────────────────
    # Disable first so reset doesn't prompt interactively
    ufw --force disable &>/dev/null || true
    ufw --force reset  &>/dev/null \
        && ok "UFW rules reset to clean slate" \
        || warn "UFW reset had warnings (continuing)"

    # ── Default policies ──────────────────────────────────────────
    ufw default deny incoming  &>/dev/null && ok "UFW default: deny incoming"
    ufw default allow outgoing &>/dev/null && ok "UFW default: allow outgoing"
    ufw default deny forward   &>/dev/null && ok "UFW default: deny forward"

    # ── Allow required LAMP / competition ports ───────────────────
    # SSH — rate-limit to slow brute-force attempts (max 6 attempts/30s)
    ufw limit 22/tcp comment "SSH (rate-limited)" &>/dev/null \
        && ok "Port 22/tcp allowed (rate-limited)" \
        || fail "Failed to allow port 22"

    # HTTP
    ufw allow 80/tcp comment "HTTP" &>/dev/null \
        && ok "Port 80/tcp allowed (HTTP)" \
        || fail "Failed to allow port 80"

    # HTTPS
    ufw allow 443/tcp comment "HTTPS" &>/dev/null \
        && ok "Port 443/tcp allowed (HTTPS)" \
        || fail "Failed to allow port 443"

    # ── Logging ───────────────────────────────────────────────────
    ufw logging on &>/dev/null \
        && ok "UFW logging enabled"

    # ── Enable firewall ───────────────────────────────────────────
    ufw --force enable &>/dev/null \
        && ok "UFW enabled and active" \
        || fail "UFW failed to enable — check 'ufw status' manually"

    # ── Verify final state ────────────────────────────────────────
    local final_status
    final_status=$(ufw status verbose 2>/dev/null || true)

    if echo "$final_status" | grep -q "Status: active"; then
        ok "UFW status: active"
    else
        fail "UFW is not active after enable attempt"
    fi

    # Confirm each required port is listed as ALLOW
    for port in 22 80 443; do
        if echo "$final_status" | grep -qE "^${port}[/ ]"; then
            ok "Verified port $port in UFW ruleset"
        else
            fail "Port $port missing from UFW ruleset"
        fi
    done

    # Warn if MySQL port is exposed externally (should never be)
    if echo "$final_status" | grep -qE "^3306[/ ].*ALLOW"; then
        warn "CRITICAL: MySQL port 3306 is open in UFW — close it immediately!"
    else
        ok "MySQL port 3306 not exposed (correct)"
    fi
}

# ════════════════════════════════════════════════════════════════
# 20. APACHE HARDENING  [HTTP-6640 / BOOT-5264]
# ════════════════════════════════════════════════════════════════
harden_apache() {
    section "Apache Hardening [HTTP-6640]"

    if ! command -v apache2 &>/dev/null; then
        skip "Apache2 not installed"
        return
    fi

    # ── Install mod_evasive if missing ──────────────────────────
    if ! dpkg -l libapache2-mod-evasive 2>/dev/null | grep -q "^ii"; then
        if is_check_mode; then
            warn "[CHECK] Would install: libapache2-mod-evasive"
        else
            apt-get install -y -qq libapache2-mod-evasive 2>/dev/null \
                && ok "mod_evasive installed" \
                || warn "mod_evasive install failed — continuing"
        fi
    else
        ok "mod_evasive already installed"
    fi

    local conf="/etc/apache2/conf-available/99-hardening.conf"
    local evasive_conf="/etc/apache2/mods-available/evasive.conf"

    if is_check_mode; then
        warn "[CHECK] Would create $conf with Apache security hardening"
        [[ -f "$conf" ]] && ok "  $conf already exists" || warn "  $conf missing"
        return
    fi

    # ── Core security config ─────────────────────────────────────
    backup_file "$conf"
    cat > "$conf" << 'APACHEEOF'
# ── MWCCDC Apache Hardening ──────────────────────────────────
# Hide server identity
ServerTokens Prod
ServerSignature Off
TraceEnable Off

# Security headers (requires mod_headers)
<IfModule mod_headers.c>
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "geolocation=(), camera=(), microphone=()"
    Header always unset X-Powered-By
    # Uncomment after confirming HTTPS is working:
    # Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
</IfModule>

# Deny access to filesystem root — more specific Directory blocks below will grant access.
# NOTE: If your DocumentRoot is outside /var/www/, add a matching <Directory> block below.
<Directory />
    Options -Indexes -FollowSymLinks
    AllowOverride None
    Require all denied
</Directory>

# Lock down web root — grant access to standard web root paths
<Directory /var/www/>
    Options -Indexes -FollowSymLinks -MultiViews
    AllowOverride All
    Require all granted
    # Block non-standard HTTP methods within web root
    <LimitExcept GET POST PUT DELETE PATCH OPTIONS HEAD>
        Require all denied
    </LimitExcept>
</Directory>

# NOTE: If your DocumentRoot is outside /var/www/ (e.g., /srv/www/, /opt/app/www/),
# add a matching <Directory> block here to grant access. Example:
# <Directory /srv/www/>
#     Options -Indexes -FollowSymLinks -MultiViews
#     AllowOverride All
#     Require all granted
#     <LimitExcept GET POST PUT DELETE PATCH OPTIONS HEAD>
#         Require all denied
#     </LimitExcept>
# </Directory>

# Block access to sensitive files anywhere in web root
<FilesMatch "(\.env|\.git|wp-config\.php|config\.php|database\.php|settings\.php|\.htpasswd|\.bak|\.sql|~$)">
    Require all denied
</FilesMatch>

# Limit request body size to 10MB (adjust for file upload needs)
LimitRequestBody 10485760
LimitRequestFields 100
LimitRequestFieldSize 8190
LimitRequestLine 8190

# Timeout settings
Timeout 60
KeepAlive On
KeepAliveTimeout 15
MaxKeepAliveRequests 100

# Disable server-status and server-info (info disclosure)
<Location /server-status>
    Require all denied
</Location>
<Location /server-info>
    Require all denied
</Location>
APACHEEOF

    # ── mod_evasive config (anti-DoS/brute-force) ───────────────
    if [[ -d /etc/apache2/mods-available ]]; then
        cat > "$evasive_conf" << 'EVASIVEEOF'
<IfModule mod_evasive24.c>
    DOSHashTableSize    3097
    DOSPageCount        5
    DOSSiteCount        50
    DOSPageInterval     1
    DOSSiteInterval     1
    DOSBlockingPeriod   300
    DOSLogDir           /var/log/apache2/
</IfModule>
EVASIVEEOF
    fi

    # ── Enable required modules ──────────────────────────────────
    local mods_enable=("headers" "evasive")
    local mods_disable=("autoindex" "status" "info" "userdir")

    for mod in "${mods_enable[@]}"; do
        a2enmod "$mod" </dev/null &>/dev/null && ok "mod_$mod enabled" || warn "mod_$mod enable failed (may not be installed)"
    done

    # Check module state via filesystem — avoids apache2ctl -M which can hang
    # A module is enabled when its .load symlink exists in mods-enabled/
    # </dev/null prevents a2dismod from silently waiting for keyboard confirmation
    for mod in "${mods_disable[@]}"; do
        if [[ -e "/etc/apache2/mods-enabled/${mod}.load" ]]; then
            a2dismod "$mod" </dev/null &>/dev/null && ok "mod_$mod disabled" || warn "mod_$mod disable failed"
        else
            ok "mod_$mod already disabled"
        fi
    done

    # ── Enable hardening conf ────────────────────────────────────
    a2enconf 99-hardening </dev/null &>/dev/null && ok "Apache hardening conf enabled" || warn "a2enconf failed"

    # ── Test and reload ──────────────────────────────────────────
    local _configtest_out
    _configtest_out=$(timeout 20 apache2ctl configtest 2>&1 || true)
    if echo "$_configtest_out" | grep -q "Syntax OK"; then
        timeout 30 systemctl reload apache2 2>/dev/null \
            && ok "Apache reloaded with hardened config" \
            || fail "Apache reload failed"
    else
        fail "Apache config test failed — hardening conf NOT applied"
        echo "$_configtest_out" | while read -r line; do warn "  $line"; done
        warn "Fix errors in $conf then run: apache2ctl configtest && systemctl reload apache2"
    fi
}

# ════════════════════════════════════════════════════════════════
# 20. MODSECURITY CONFIGURATION
# ════════════════════════════════════════════════════════════════
harden_modsecurity() {
    section "ModSecurity WAF Configuration"

    local modsec_conf="/etc/modsecurity/modsecurity.conf"

    if [[ ! -f "$modsec_conf" ]]; then
        # Try to create from example
        if [[ -f "${modsec_conf}-recommended" ]]; then
            cp "${modsec_conf}-recommended" "$modsec_conf"
            info "Created modsecurity.conf from recommended template"
        else
            skip "ModSecurity config not found — skipping"
            return
        fi
    fi

    if is_check_mode; then
        local engine_mode
        engine_mode=$(grep "^SecRuleEngine" "$modsec_conf" | awk '{print $2}')
        warn "[CHECK] SecRuleEngine currently: ${engine_mode:-DetectionOnly} — would set to On"
        return
    fi

    backup_file "$modsec_conf"

    # Enable enforcement mode (change from DetectionOnly to On)
    local current_mode
    current_mode=$(grep "^SecRuleEngine" "$modsec_conf" | awk '{print $2}')
    if [[ "$current_mode" == "On" ]]; then
        ok "ModSecurity already in enforcement mode"
    else
        sed -i 's/^SecRuleEngine.*/SecRuleEngine On/' "$modsec_conf"
        ok "ModSecurity set to enforcement mode (was: ${current_mode:-DetectionOnly})"
    fi

    # Ensure request/response body inspection is on
    sed -i 's/^SecRequestBodyAccess.*/SecRequestBodyAccess On/'   "$modsec_conf"
    sed -i 's/^SecResponseBodyAccess.*/SecResponseBodyAccess On/' "$modsec_conf"

    # Set reasonable limits
    grep -q "^SecRequestBodyLimit" "$modsec_conf" \
        || echo "SecRequestBodyLimit 10485760" >> "$modsec_conf"
    grep -q "^SecRequestBodyNoFilesLimit" "$modsec_conf" \
        || echo "SecRequestBodyNoFilesLimit 131072" >> "$modsec_conf"

    ok "ModSecurity request/response body inspection enabled"

    # Enable mod_security2 in Apache
    a2enmod security2 </dev/null &>/dev/null && ok "mod_security2 enabled in Apache" || true

    # Check for OWASP CRS
    if [[ -d /etc/modsecurity/crs ]] || [[ -d /usr/share/modsecurity-crs ]]; then
        ok "OWASP Core Rule Set found — using existing CRS"
    else
        warn "OWASP CRS not found — consider: apt install modsecurity-crs"
    fi

    # Reload Apache if configtest passes
    if timeout 20 apache2ctl configtest 2>&1 | grep -q "Syntax OK"; then
        timeout 30 systemctl reload apache2 &>/dev/null && ok "Apache reloaded with ModSecurity config" || true
    else
        warn "Apache configtest failed after ModSecurity changes — reload manually after fixing errors"
    fi
}

# ════════════════════════════════════════════════════════════════
# 21. SSL/TLS HARDENING
# ════════════════════════════════════════════════════════════════
harden_ssl() {
    section "SSL/TLS Protocol Hardening"

    if [[ ! -e "/etc/apache2/mods-enabled/ssl.load" ]]; then
        # Check if SSL module is available to enable
        if [[ -f /etc/apache2/mods-available/ssl.load ]]; then
            if is_check_mode; then
                warn "[CHECK] Would enable mod_ssl"
            else
                a2enmod ssl </dev/null &>/dev/null && ok "mod_ssl enabled" || skip "mod_ssl enable failed"
            fi
        else
            skip "mod_ssl not available — skipping SSL hardening"
            return
        fi
    else
        ok "mod_ssl already loaded"
    fi

    local ssl_conf="/etc/apache2/conf-available/99-ssl-hardening.conf"

    if is_check_mode; then
        warn "[CHECK] Would create $ssl_conf with TLS 1.2/1.3 only and strong ciphers"
        return
    fi

    backup_file "$ssl_conf"
    cat > "$ssl_conf" << 'SSLEOF'
# ── MWCCDC SSL/TLS Hardening ─────────────────────────────────
<IfModule mod_ssl.c>
    # Disable SSLv2, SSLv3, TLS 1.0 and TLS 1.1 — allow only TLS 1.2+
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1

    # Strong cipher suite only
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384

    # Server chooses cipher, not client
    SSLHonorCipherOrder off

    # Disable SSL compression (CRIME attack)
    SSLCompression off

    # Enable OCSP stapling
    SSLUseStapling off

    # Session tickets (disable for perfect forward secrecy)
    SSLSessionTickets off
</IfModule>
SSLEOF

    a2enconf 99-ssl-hardening </dev/null &>/dev/null && ok "SSL hardening conf enabled" || warn "a2enconf ssl-hardening failed"

    if timeout 20 apache2ctl configtest 2>&1 | grep -q "Syntax OK"; then
        timeout 30 systemctl reload apache2 &>/dev/null && ok "Apache reloaded with SSL hardening" || warn "Apache reload failed"
    else
        warn "Apache configtest failed — SSL hardening conf written but NOT active, check manually"
    fi
}

# ════════════════════════════════════════════════════════════════
# 22. PHP HARDENING
# ════════════════════════════════════════════════════════════════
harden_php() {
    section "PHP Hardening"

    # Find all PHP ini files (CLI, FPM, Apache2)
    local php_inis=()
    local php_version
    php_version=$(php --version 2>/dev/null | grep -oP '^\S+\s+\K\d+\.\d+' | head -1)

    if [[ -z "$php_version" ]]; then
        # Try to find it manually from /etc/php directory structure
        local _php_dir
        _php_dir=$(find /etc/php -maxdepth 1 -mindepth 1 -type d 2>/dev/null | sort -V | tail -1)
        [[ -n "$_php_dir" ]] && php_version=$(basename "$_php_dir")
    fi
    if [[ -z "$php_version" ]]; then
        # Last resort: look for any php binary
        local _php_bin
        _php_bin=$(find /usr/bin /usr/local/bin -name "php*" -type f 2>/dev/null | sort -V | tail -1)
        [[ -n "$_php_bin" ]] && php_version=$("$_php_bin" --version 2>/dev/null | grep -oE "[0-9]+\.[0-9]+" | head -1)
    fi

    if [[ -z "$php_version" ]]; then
        skip "PHP not found"
        return
    fi

    info "PHP version detected: $php_version"

    # Collect all php.ini paths that exist
    for sapi in fpm apache2 cli; do
        local ini="/etc/php/${php_version}/${sapi}/php.ini"
        [[ -f "$ini" ]] && php_inis+=("$ini")
    done

    if [[ ${#php_inis[@]} -eq 0 ]]; then
        skip "No PHP ini files found"
        return
    fi

    # Settings to apply: "key" "value"
    local -a php_settings=(
        "expose_php"                  "Off"
        "display_errors"              "Off"
        "display_startup_errors"      "Off"
        "log_errors"                  "On"
        "allow_url_fopen"             "Off"
        "allow_url_include"           "Off"
        "session.cookie_httponly"     "1"
        "session.cookie_secure"       "1"
        "session.use_strict_mode"     "1"
        "session.cookie_samesite"     "Strict"
        "max_execution_time"          "30"
        "max_input_time"              "60"
        "memory_limit"                "256M"
        "post_max_size"               "20M"
        "upload_max_filesize"         "16M"
        "error_log"                   "/var/log/php_errors.log"
    )

    # Dangerous functions to disable (safe for e-commerce — preserves curl)
    local disable_fns="exec,passthru,shell_exec,system,proc_open,popen,show_source,posix_kill,posix_mkfifo,posix_setpgid,posix_setsid,posix_setuid,proc_close,proc_terminate,dl,pcntl_exec"

    for ini in "${php_inis[@]}"; do
        if is_check_mode; then
            warn "[CHECK] Would harden: $ini"
            continue
        fi

        backup_file "$ini"

        # Apply each setting — sed to uncomment and set, or append if not found
        local i=0
        while (( i < ${#php_settings[@]} )); do
            local key="${php_settings[$i]}"
            local val="${php_settings[$((i+1))]}"
            # Escape dots in key for use as regex (e.g., session.cookie_httponly)
            local key_re="${key//./\\.}"
            if grep -qE "^[;[:space:]]*${key_re}[[:space:]]*=" "$ini"; then
                sed -i "s|^[;[:space:]]*${key_re}[[:space:]]*=.*|${key} = ${val}|" "$ini"
            else
                echo "${key} = ${val}" >> "$ini"
            fi
            (( i += 2 )) || true
        done

        # Handle disable_functions: merge with existing, don't wipe app-needed ones
        local current_disable
        current_disable=$(grep -E "^disable_functions" "$ini" | cut -d= -f2 | tr -d ' ' || echo "")
        if [[ -z "$current_disable" ]]; then
            echo "disable_functions = ${disable_fns}" >> "$ini"
        else
            # Merge (avoid duplicates)
            local merged
            merged=$(echo "${current_disable},${disable_fns}" | tr ',' '\n' | sort -u | tr '\n' ',' | sed 's/,$//')
            sed -i "s|^disable_functions.*|disable_functions = ${merged}|" "$ini"
        fi

        ok "PHP hardened: $ini"
    done

    # Restart PHP-FPM if running
    if systemctl is-active "php${php_version}-fpm" &>/dev/null; then
        systemctl restart "php${php_version}-fpm" 2>/dev/null \
            && ok "php${php_version}-fpm restarted" \
            || fail "php${php_version}-fpm restart failed"
    fi

    # Reload Apache for mod_php changes
    timeout 20 apache2ctl configtest 2>&1 | grep -q "Syntax OK" \
        && { timeout 30 systemctl reload apache2 &>/dev/null; } || true
}

# ════════════════════════════════════════════════════════════════
# 23. MYSQL HARDENING
# ════════════════════════════════════════════════════════════════
harden_mysql() {
    section "MySQL/MariaDB Hardening"

    # Support both mysql and mariadb client commands
    local mysql_cmd="mysql"
    if ! command -v mysql &>/dev/null; then
        if command -v mariadb &>/dev/null; then
            mysql_cmd="mariadb"
        else
            skip "MySQL/MariaDB client not installed"
            return
        fi
    fi

    # Test if we can connect (socket auth as root)
    if ! $mysql_cmd -u root --connect-timeout=3 -e "SELECT 1;" &>/dev/null; then
        warn "Cannot connect to MySQL/MariaDB as root via socket — skipping automated fixes"
        warn "Run manually: sudo mysql_secure_installation"
        ((FAIL++)) || true
        return
    fi

    # ── my.cnf hardening ────────────────────────────────────────
    # Detect MySQL vs MariaDB config path
    local mycnf=""
    for _candidate in "/etc/mysql/mysql.conf.d/mysqld.cnf"                       "/etc/mysql/mariadb.conf.d/50-server.cnf"                       "/etc/mysql/conf.d/mysql.cnf"                       "/etc/mysql/my.cnf"; do
        if [[ -f "$_candidate" ]]; then
            mycnf="$_candidate"
            break
        fi
    done
    [[ -z "$mycnf" ]] && mycnf="/etc/mysql/my.cnf"  # fallback: will be created if needed

    if is_check_mode; then
        warn "[CHECK] Would harden $mycnf (bind-address, local-infile, skip-symbolic-links)"
        $mysql_cmd -u root -e "SELECT User,Host,authentication_string FROM mysql.user WHERE (authentication_string='' OR authentication_string IS NULL) AND User != '';" 2>/dev/null \
            | grep -v "^User" | while read -r line; do
                warn "[CHECK] User with no password: $line"
            done
        return
    fi

    backup_file "$mycnf"

    # Ensure these settings are in [mysqld] section
    # Note: skip-symbolic-links deprecated in MySQL 8.0+ (safe to ignore warning)
    local mysqld_settings=(
        "bind-address            = 127.0.0.1"
        "local-infile            = 0"
        "skip-symbolic-links     = 1"
        "skip-show-database      = 1"
    )
    for setting in "${mysqld_settings[@]}"; do
        local key
        key=$(echo "$setting" | awk -F= '{print $1}' | tr -d ' ')
        if grep -qE "^[#[:space:]]*${key}[[:space:]]*=" "$mycnf" 2>/dev/null; then
            sed -i "s|^[#[:space:]]*${key}[[:space:]]*=.*|${setting}|" "$mycnf"
        else
            # Add under [mysqld] section (create section if missing)
            if grep -q "^\[mysqld\]" "$mycnf" 2>/dev/null; then
                sed -i "/^\[mysqld\]/a ${setting}" "$mycnf"
            else
                printf "\n[mysqld]\n%s\n" "$setting" >> "$mycnf"
            fi
        fi
    done
    ok "MySQL config hardened (bind=127.0.0.1, local-infile=0)"

    # ── Security queries ─────────────────────────────────────────
    local mysql_cmds="
-- Remove anonymous users
DELETE FROM mysql.user WHERE User = '';

-- Remove remote root login
DELETE FROM mysql.user WHERE User = 'root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');

-- Remove test database
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db = 'test' OR Db = 'test\\_%';

-- Flush
FLUSH PRIVILEGES;
"
    if $mysql_cmd -u root -e "$mysql_cmds" 2>/dev/null; then
        ok "MySQL: anonymous users removed, remote root disabled, test DB dropped"
    else
        fail "MySQL security queries failed — run mysql_secure_installation manually"
    fi

    # ── Set MySQL root password interactively ────────────────────
    # Requires a real terminal — skip gracefully if running non-interactively.
    # Test by actually opening /dev/tty (exists as a device node even when unusable).
    local _tty_ok=false
    { true </dev/tty; } 2>/dev/null && _tty_ok=true
    if ! $_tty_ok; then
        warn "No terminal available — skipping interactive MySQL password setup"
        warn "Run manually: sudo mysql -e \"ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'Password';\""
    else
        local root_auth_plugin
        root_auth_plugin=$($mysql_cmd -u root --skip-column-names -e \
            "SELECT plugin FROM mysql.user WHERE User='root' AND Host='localhost';" 2>/dev/null || echo "unknown")

        echo ""
        if [[ "$root_auth_plugin" == "auth_socket" || "$root_auth_plugin" == "unix_socket" ]]; then
            echo -e "${YELLOW}${BOLD}MySQL root uses socket auth (no password set).${NC}"
            echo -e "${YELLOW}Set a strong password to prevent unauthorized access.${NC}"
        else
            echo -e "${YELLOW}${BOLD}MySQL root auth plugin: $root_auth_plugin${NC}"
        fi

        local do_set_pw=""
        echo -ne "${BOLD}Set/change MySQL root password now? [Y/n]: ${NC}"
        read -r do_set_pw </dev/tty 2>/dev/null || do_set_pw="n"
        do_set_pw="${do_set_pw:-Y}"

        if [[ "${do_set_pw^^}" == "Y" ]]; then
            local mysql_pass="" mysql_pass2=""
            while true; do
                echo -ne "${BOLD}  Enter new MySQL root password (min 8 chars): ${NC}"
                read -rs mysql_pass </dev/tty 2>/dev/null || mysql_pass=""
                echo ""
                echo -ne "${BOLD}  Confirm password: ${NC}"
                read -rs mysql_pass2 </dev/tty 2>/dev/null || mysql_pass2=""
                echo ""
                if [[ -z "$mysql_pass" ]]; then
                    echo -e "${RED}  Password cannot be empty. Try again.${NC}"
                elif [[ "$mysql_pass" != "$mysql_pass2" ]]; then
                    echo -e "${RED}  Passwords do not match. Try again.${NC}"
                elif (( ${#mysql_pass} < 8 )); then
                    echo -e "${RED}  Password must be at least 8 characters. Try again.${NC}"
                else
                    break
                fi
            done

            # Escape single quotes in password for SQL
            local mysql_pass_escaped="${mysql_pass//\'/\'\'}"

            # Switch root to password auth and set the password
            if $mysql_cmd -u root -e \
                "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '${mysql_pass_escaped}'; FLUSH PRIVILEGES;" \
                2>/dev/null; then
                ok "MySQL root password set — auth switched to mysql_native_password"
                # Save credentials to root-only .my.cnf for easy CLI access during competition
                printf '[client]\nuser=root\npassword=%s\n' "$mysql_pass" > /root/.my.cnf
                chmod 600 /root/.my.cnf
                ok "Credentials saved to /root/.my.cnf (chmod 600, root only)"
                # Update mysql_cmd for remaining queries in this function
                mysql_cmd="$mysql_cmd -u root -p${mysql_pass_escaped}"
            else
                fail "Failed to set MySQL root password"
                warn "Set it manually: sudo mysql -e \"ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'YourPassword';\""
            fi
        else
            warn "MySQL root password NOT changed — set one before competition starts!"
        fi
    fi

    # ── Audit accounts with no password ─────────────────────────
    local no_pass_users
    no_pass_users=$($mysql_cmd --skip-column-names -e \
        "SELECT CONCAT(User,'@',Host) FROM mysql.user WHERE (authentication_string='' OR authentication_string IS NULL) AND User != '' AND User != 'root';" 2>/dev/null)
    if [[ -n "$no_pass_users" ]]; then
        warn "MySQL accounts with no password (set passwords!):"
        echo "$no_pass_users" | while read -r acct; do warn "  $acct"; done
    else
        ok "No MySQL accounts with empty passwords"
    fi

    # ── Audit accounts with all privileges ──────────────────────
    local superusers
    superusers=$($mysql_cmd --skip-column-names -e \
        "SELECT CONCAT(User,'@',Host) FROM mysql.user WHERE Super_priv='Y' AND User NOT IN ('root','debian-sys-maint','mysql.session','mysql.sys');" 2>/dev/null)
    if [[ -n "$superusers" ]]; then
        warn "Unexpected MySQL accounts with SUPER privilege (review these!):"
        echo "$superusers" | while read -r acct; do warn "  $acct"; done
    else
        ok "No unexpected SUPER privilege accounts"
    fi

    # ── Lock anonymous and unused built-in accounts ──────────────
    for svc_user in "mysql.sys" "mysql.infoschema"; do
        local exists
        exists=$($mysql_cmd --skip-column-names -e \
            "SELECT COUNT(*) FROM mysql.user WHERE User='${svc_user%@*}';" 2>/dev/null || echo 0)
        if (( exists > 0 )); then
            $mysql_cmd -e "ALTER USER '${svc_user%@*}'@'localhost' ACCOUNT LOCK;" 2>/dev/null && \
                ok "Locked built-in service account: $svc_user" || true
        fi
    done

    # ── Restart MySQL to apply config changes ────────────────────
    systemctl restart mysql 2>/dev/null \
        && ok "MySQL restarted with hardened config" \
        || fail "MySQL restart failed"
}

# ════════════════════════════════════════════════════════════════
# 24. WEB FILE PERMISSIONS AND AUDIT
# ════════════════════════════════════════════════════════════════
harden_web_files() {
    section "Web Root File Permissions Audit"

    local webroot="/var/www"
    if [[ ! -d "$webroot" ]]; then
        skip "/var/www not found"
        return
    fi

    if is_check_mode; then
        warn "[CHECK] Would audit and fix web root permissions in $webroot"
        # Report problems only
        local ww_files
        ww_files=$(find "$webroot" -type f -perm -0002 2>/dev/null | head -20)
        [[ -n "$ww_files" ]] && warn "[CHECK] World-writable files found:" && echo "$ww_files"
        local git_dirs
        git_dirs=$(find "$webroot" -name ".git" -type d 2>/dev/null)
        [[ -n "$git_dirs" ]] && warn "[CHECK] .git directories exposed in web root:" && echo "$git_dirs"
        return
    fi

    # ── Fix ownership ────────────────────────────────────────────
    local webuser="www-data"
    id "$webuser" &>/dev/null || webuser="apache"
    chown -R "root:${webuser}" "$webroot" 2>/dev/null \
        && ok "Web root ownership set to root:${webuser}" \
        || warn "chown on $webroot failed"

    # ── Set directory/file permissions ───────────────────────────
    find "$webroot" -type d -exec chmod 755 {} \; 2>/dev/null
    find "$webroot" -type f -exec chmod 644 {} \; 2>/dev/null
    ok "Web files: directories=755, files=644"

    # ── Protect sensitive config files ───────────────────────────
    local sensitive_patterns=("wp-config.php" ".env" "config.php" "database.php" "settings.php" "db_config.php")
    for pattern in "${sensitive_patterns[@]}"; do
        while IFS= read -r f; do
            chmod 640 "$f" 2>/dev/null
            chown "root:${webuser}" "$f" 2>/dev/null
            ok "Protected config: $f (640)"
        done < <(find "$webroot" -name "$pattern" -type f 2>/dev/null)
    done

    # ── Remove world-writable on PHP files ───────────────────────
    local ww_count=0
    while IFS= read -r f; do
        chmod o-w "$f" 2>/dev/null
        ((ww_count++)) || true
    done < <(find "$webroot" -name "*.php" -perm -0002 -type f 2>/dev/null)
    [[ $ww_count -gt 0 ]] \
        && ok "Removed world-write from $ww_count PHP file(s)" \
        || ok "No world-writable PHP files found"

    # ── Detect exposed .git directories ─────────────────────────
    local git_dirs
    git_dirs=$(find "$webroot" -name ".git" -type d 2>/dev/null)
    if [[ -n "$git_dirs" ]]; then
        warn "DANGER: .git directories found inside web root — source code exposed!"
        echo "$git_dirs" | while read -r d; do
            warn "  $d"
            # Block web access to .git
            local htaccess="${d%/.git}/.htaccess"
            if ! grep -q "\.git" "$htaccess" 2>/dev/null; then
                echo -e "\n# Block .git access\n<FilesMatch \"\\.git\">\n    Require all denied\n</FilesMatch>" >> "$htaccess"
                ok "  Added .htaccess protection for $d"
            fi
        done
    else
        ok "No exposed .git directories in web root"
    fi

    # ── Detect potential webshells (modified in last 7 days) ────
    local suspicious
    suspicious=$(find "$webroot" -name "*.php" -mtime -7 -type f 2>/dev/null | head -20)
    if [[ -n "$suspicious" ]]; then
        warn "Recently modified PHP files (verify these are legitimate):"
        echo "$suspicious" | while read -r f; do warn "  $f"; done
    else
        ok "No recently modified PHP files detected"
    fi

    # ── Detect PHP in upload directories ────────────────────────
    local upload_php
    upload_php=$(find "$webroot" -path "*/upload*/*.php" -o -path "*/uploads*/*.php" 2>/dev/null | head -10)
    if [[ -n "$upload_php" ]]; then
        warn "PHP files found in upload directories (LIKELY WEBSHELLS — investigate!):"
        echo "$upload_php" | while read -r f; do warn "  $f"; done
        ((FAIL++)) || true
    else
        ok "No PHP files in upload directories"
    fi

    # ── Block PHP execution in upload dirs via Apache ────────────
    while IFS= read -r dir; do
        local htaccess="${dir}/.htaccess"
        if ! grep -q "php_flag engine off" "$htaccess" 2>/dev/null; then
            cat >> "$htaccess" << 'HTEOF'
# Block PHP execution in upload directory
php_flag engine off
<FilesMatch "\.ph(p[2-9]?|tml)$">
    Require all denied
</FilesMatch>
HTEOF
            ok "PHP execution blocked in upload dir: $dir"
        else
            ok "PHP already blocked in: $dir"
        fi
    done < <(find "$webroot" -type d \( -name "uploads" -o -name "upload" -o -name "files" \) 2>/dev/null)
}

# ════════════════════════════════════════════════════════════════
# INCIDENT RESPONSE MODE  (--ir)
# ════════════════════════════════════════════════════════════════

# IR-specific output helpers — write to screen AND report file
ir_crit() {
    local msg="$*"
    echo -e "$(date '+%H:%M:%S') ${RED}${BOLD}[CRITICAL]${NC} $msg" | tee -a "$IR_REPORT"
    ((IR_CRITICAL++)) || true
}
ir_warn() {
    local msg="$*"
    echo -e "$(date '+%H:%M:%S') ${YELLOW}[WARNING] ${NC} $msg" | tee -a "$IR_REPORT"
    ((IR_WARNINGS++)) || true
}
ir_ok() {
    local msg="$*"
    echo -e "$(date '+%H:%M:%S') ${GREEN}[CLEAN]   ${NC} $msg" | tee -a "$IR_REPORT"
}
ir_info() {
    local msg="$*"
    echo -e "$(date '+%H:%M:%S') ${CYAN}[INFO]    ${NC} $msg" | tee -a "$IR_REPORT"
}
ir_fixed() {
    local msg="$*"
    echo -e "$(date '+%H:%M:%S') ${GREEN}${BOLD}[FIXED]   ${NC} $msg" | tee -a "$IR_REPORT"
    ((IR_FIXED++)) || true
}
ir_section() {
    local msg="$*"
    echo -e "\n${BOLD}${BLUE}── $msg ──${NC}" | tee -a "$IR_REPORT"
}

# ── IR Check 1: User Accounts ────────────────────────────────────
ir_check_users() {
    ir_section "User Account Audit"

    # Multiple UID 0 accounts (root backdoors)
    local uid0_accounts
    uid0_accounts=$(awk -F: '$3==0 {print $1}' /etc/passwd 2>/dev/null)
    local uid0_count
    uid0_count=$(echo "$uid0_accounts" | grep -c '[^[:space:]]' || true)
    if (( uid0_count > 1 )); then
        ir_crit "Multiple UID 0 accounts found (root backdoors!):"
        echo "$uid0_accounts" | while read -r u; do
            [[ "$u" != "root" ]] && ir_crit "  REMOVE: $u (UID 0 backdoor)"
        done
    else
        ir_ok "Only root has UID 0"
    fi

    # List all human accounts (UID >= 1000, not nobody)
    ir_info "Human accounts on this system:"
    while IFS=: read -r user _ uid _ _ home shell; do
        if (( uid >= 1000 )) && (( uid < 65534 )); then
            ir_info "  $user (UID=$uid, home=$home, shell=$shell)"
        fi
    done < /etc/passwd

    # Accounts with login shells that are unexpected service accounts
    local suspicious_shells=()
    while IFS=: read -r user _ uid _ _ _ shell; do
        if (( uid > 0 )) && (( uid < 1000 )); then
            if [[ "$shell" != "/usr/sbin/nologin" && "$shell" != "/bin/false" && \
                  "$shell" != "/sbin/nologin"     && "$shell" != "/bin/sync" && \
                  -n "$shell" ]]; then
                suspicious_shells+=("$user (UID=$uid shell=$shell)")
            fi
        fi
    done < /etc/passwd
    if [[ ${#suspicious_shells[@]} -gt 0 ]]; then
        ir_warn "Service accounts with login shells (review these):"
        for entry in "${suspicious_shells[@]}"; do
            ir_warn "  $entry"
        done
    else
        ir_ok "No service accounts with unexpected login shells"
    fi

    # Check for accounts with truly empty password fields in /etc/shadow
    # "!" and "*" mean locked/disabled (safe); empty string means no password (dangerous)
    local empty_pass_found=0
    while IFS=: read -r user pass _; do
        if [[ -z "$pass" ]]; then
            ir_crit "Account '$user' has NO PASSWORD (empty shadow field) — set one immediately!"
            ((empty_pass_found++)) || true
        fi
    done < /etc/shadow 2>/dev/null
    (( empty_pass_found == 0 )) && ir_ok "No accounts with empty password fields in /etc/shadow"

    # Check if /etc/passwd was modified recently (within 7 days)
    if [[ -f /etc/passwd ]]; then
        local mod_days
        mod_days=$(( ( $(date +%s) - $(stat -c %Y /etc/passwd 2>/dev/null || echo 0) ) / 86400 ))
        if (( mod_days < 7 )); then
            ir_warn "/etc/passwd modified ${mod_days} day(s) ago — verify no accounts were added"
        else
            ir_ok "/etc/passwd last modified ${mod_days} days ago"
        fi
    fi

    # Check /etc/shadow modification
    if [[ -f /etc/shadow ]]; then
        local shadow_days
        shadow_days=$(( ( $(date +%s) - $(stat -c %Y /etc/shadow 2>/dev/null || echo 0) ) / 86400 ))
        if (( shadow_days < 7 )); then
            ir_warn "/etc/shadow modified ${shadow_days} day(s) ago — passwords may have been changed"
        fi
    fi
}

# ── IR Check 2: SSH Authorized Keys ──────────────────────────────
ir_check_ssh_keys() {
    ir_section "SSH Authorized Keys Audit"

    local key_files=()
    # Collect all authorized_keys files
    while IFS= read -r -d '' f; do
        key_files+=("$f")
    done < <(find /root /home -name "authorized_keys" -type f -print0 2>/dev/null)

    if [[ ${#key_files[@]} -eq 0 ]]; then
        ir_ok "No authorized_keys files found"
        return
    fi

    for keyfile in "${key_files[@]}"; do
        local key_count
        key_count=$(grep -cv '^[[:space:]]*#' "$keyfile" 2>/dev/null) || key_count=0
        key_count=$(( ${key_count%%$'\n'*} + 0 ))  # strip any newline, force numeric
        local owner
        owner=$(stat -c '%U' "$keyfile" 2>/dev/null || echo "unknown")

        if (( key_count == 0 )); then
            ir_ok "$keyfile — empty"
            continue
        fi

        if [[ "$keyfile" == /root/* ]]; then
            ir_warn "$keyfile — root has $key_count key(s) authorized (review!):"
        else
            ir_info "$keyfile — $key_count key(s) for $owner:"
        fi

        # Print each key (truncated)
        while IFS= read -r key_line; do
            [[ -z "$key_line" || "$key_line" =~ ^# ]] && continue
            local key_type key_comment
            key_type=$(echo "$key_line" | awk '{print $1}')
            key_comment=$(echo "$key_line" | awk '{print $NF}')
            ir_info "  Type: $key_type  Comment: $key_comment"
        done < "$keyfile"

        # Flag if modified recently
        local key_days
        key_days=$(( ( $(date +%s) - $(stat -c %Y "$keyfile" 2>/dev/null || echo 0) ) / 86400 ))
        if (( key_days < 7 )); then
            ir_warn "  ^ This file was modified $key_days day(s) ago!"
        fi
    done

    # Check if root has authorized_keys (persistent backdoor if SSH key-only)
    if [[ -f /root/.ssh/authorized_keys ]] && grep -qv '^#' /root/.ssh/authorized_keys 2>/dev/null; then
        ir_crit "Root authorized_keys is populated — confirm these keys are legitimate!"
        ir_info "  To remove all root SSH keys: > /root/.ssh/authorized_keys"
    fi
}

# ── IR Check 3: Cron Persistence ─────────────────────────────────
ir_check_crontabs() {
    ir_section "Cron Persistence Audit"

    # Suspicious pattern: download/execution commands in cron
    # nc is word-bounded to avoid matching cron lines containing 'rsync', 'sync', etc.
    local suspicious_pattern='wget|curl|\bnc\b|ncat|netcat|socat|bash -i|/tmp/|/dev/shm|base64|python.*-c|perl.*-e|ruby.*-e|php.*-r|powershell|/bin/bash.*&|mkfifo|/dev/tcp|xterm.*-display'

    # Known-good security tool cron files that legitimately use wget/curl for updates.
    # These are whitelisted to prevent false positives.
    local -a cron_whitelist=(
        "/etc/cron.weekly/rkhunter"
        "/etc/cron.daily/rkhunter"
        "/etc/cron.weekly/chkrootkit"
        "/etc/cron.daily/chkrootkit"
    )

    local found_suspicious=0

    # System crontab
    local cron_files=("/etc/crontab")

    # /etc/cron.d files
    while IFS= read -r -d '' f; do
        cron_files+=("$f")
    done < <(find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly -type f -print0 2>/dev/null)

    # User crontabs (need root)
    while IFS= read -r -d '' f; do
        cron_files+=("$f")
    done < <(find /var/spool/cron/crontabs -type f -print0 2>/dev/null)

    for cfile in "${cron_files[@]}"; do
        [[ -f "$cfile" ]] || continue

        # Skip known-good security tool cron files
        local skip=false
        for wl in "${cron_whitelist[@]}"; do
            [[ "$cfile" == "$wl" ]] && skip=true && break
        done
        if $skip; then
            ir_ok "$cfile — whitelisted security tool cron (uses wget/curl legitimately)"
            continue
        fi

        # Check for suspicious commands
        local matches
        matches=$(grep -Pv '^\s*#|^\s*$' "$cfile" 2>/dev/null | grep -P "$suspicious_pattern" || true)
        if [[ -n "$matches" ]]; then
            ir_crit "SUSPICIOUS cron entries in $cfile:"
            echo "$matches" | while read -r line; do
                ir_crit "  $line"
            done
            ((found_suspicious++)) || true
        else
            ir_ok "$cfile — no suspicious patterns"
        fi

        # Flag if modified recently
        local cron_days
        cron_days=$(( ( $(date +%s) - $(stat -c %Y "$cfile" 2>/dev/null || echo 0) ) / 86400 ))
        if (( cron_days < 3 )); then
            ir_warn "$cfile modified ${cron_days} day(s) ago — review contents:"
            grep -Ev '^\s*#|^\s*$' "$cfile" 2>/dev/null | while read -r line; do
                ir_warn "  $line"
            done
        fi
    done

    if (( found_suspicious == 0 )); then
        ir_ok "No obviously malicious cron entries detected"
    fi
}

# ── IR Check 4: Systemd Services ─────────────────────────────────
ir_check_systemd() {
    ir_section "Systemd Service Audit"

    # 'nc ' pattern is intentionally word-bounded (\bnc\b) to avoid matching binaries
    # like rsync or sbkeysync whose names end in 'nc'.
    # /lib/systemd/system is a symlink to /usr/lib/systemd/system on Ubuntu 22+,
    # so we only search /usr/lib to avoid double-reporting.
    local suspicious_svc_pattern='/tmp/|/dev/shm|/var/tmp|wget|curl|\bnc\b|bash -i|base64|python.*-c|perl.*-e'

    # Check all enabled service unit files for suspicious ExecStart
    local suspicious_found=0
    while IFS= read -r unit_file; do
        [[ -f "$unit_file" ]] || continue
        local exec_lines
        exec_lines=$(grep -i "^ExecStart\|^ExecStartPre\|^ExecStartPost" "$unit_file" 2>/dev/null | grep -P "$suspicious_svc_pattern" || true)
        if [[ -n "$exec_lines" ]]; then
            ir_crit "Suspicious ExecStart in $unit_file:"
            echo "$exec_lines" | while read -r line; do ir_crit "  $line"; done
            ((suspicious_found++)) || true
        fi
    done < <(find /etc/systemd/system /usr/lib/systemd/system -name "*.service" -type f 2>/dev/null)

    # Flag unit files in non-standard locations
    local nonstandard
    while IFS= read -r unit_file; do
        ir_crit "Unit file in non-standard location: $unit_file"
        ((suspicious_found++)) || true
    done < <(find /tmp /var/tmp /dev/shm /home -name "*.service" -type f 2>/dev/null)

    # Recently added enabled services (check /etc/systemd/system for recent files)
    while IFS= read -r f; do
        local svc_days
        svc_days=$(( ( $(date +%s) - $(stat -c %Y "$f" 2>/dev/null || echo 0) ) / 86400 ))
        if (( svc_days < 7 )); then
            ir_warn "Recently added/modified service: $f (${svc_days}d ago)"
            grep -E "^Description|^ExecStart" "$f" 2>/dev/null | while read -r line; do
                ir_warn "  $line"
            done
            ((suspicious_found++)) || true
        fi
    done < <(find /etc/systemd/system -name "*.service" -not -type l 2>/dev/null)

    if (( suspicious_found == 0 )); then
        ir_ok "No suspicious systemd services detected"
    fi
}

# ── IR Check 5: Sudo Configuration ───────────────────────────────
ir_check_sudoers() {
    ir_section "Sudo Configuration Audit"

    local sudoers_files=("/etc/sudoers")
    while IFS= read -r -d '' f; do
        sudoers_files+=("$f")
    done < <(find /etc/sudoers.d -type f -print0 2>/dev/null)

    local nopasswd_found=0
    for sfile in "${sudoers_files[@]}"; do
        [[ -f "$sfile" ]] || continue

        # NOPASSWD entries
        local nopasswd_entries
        nopasswd_entries=$(grep -v '^\s*#' "$sfile" 2>/dev/null | grep -i 'NOPASSWD' || true)
        if [[ -n "$nopasswd_entries" ]]; then
            ir_warn "NOPASSWD sudo entries in $sfile:"
            echo "$nopasswd_entries" | while read -r line; do
                ir_warn "  $line"
            done
            ((nopasswd_found++)) || true
        fi

        # ALL=(ALL) ALL wildcard entries for non-root
        local all_entries
        all_entries=$(grep -v '^\s*#' "$sfile" 2>/dev/null | grep -E 'ALL=\(ALL(:ALL)?\)\s+ALL' | grep -v '^root' || true)
        if [[ -n "$all_entries" ]]; then
            ir_warn "Users with full sudo access in $sfile:"
            echo "$all_entries" | while read -r line; do ir_warn "  $line"; done
        fi

        # Wildcard commands (dangerous)
        local wildcard_entries
        wildcard_entries=$(grep -v '^\s*#' "$sfile" 2>/dev/null | grep -E '/\*|ALL.*NOPASSWD.*ALL' || true)
        if [[ -n "$wildcard_entries" ]]; then
            ir_crit "Wildcard or full NOPASSWD:ALL sudo in $sfile:"
            echo "$wildcard_entries" | while read -r line; do ir_crit "  $line"; done
        fi

        # Sudoers modified recently
        local sudo_days
        sudo_days=$(( ( $(date +%s) - $(stat -c %Y "$sfile" 2>/dev/null || echo 0) ) / 86400 ))
        if (( sudo_days < 7 )); then
            ir_warn "$sfile modified ${sudo_days} day(s) ago!"
        fi
    done

    if (( nopasswd_found == 0 )); then
        ir_ok "No NOPASSWD sudo entries found"
    fi
}

# ── IR Check 6: Listening Ports ──────────────────────────────────
ir_check_ports() {
    ir_section "Listening Ports Audit"

    # Expected ports on a LAMP machine
    local expected_tcp_ports=(22 80 443 25 587)
    # MySQL should only be 127.0.0.1:3306 — handled separately

    # Use ss (preferred) or netstat
    local port_cmd=""
    if command -v ss &>/dev/null; then
        port_cmd="ss -tlnp"
    elif command -v netstat &>/dev/null; then
        port_cmd="netstat -tlnp"
    else
        ir_warn "Neither ss nor netstat found — skipping port audit"
        return
    fi

    ir_info "All listening TCP ports:"
    $port_cmd 2>/dev/null | tee -a "$IR_REPORT"

    # Check for MySQL listening on all interfaces (should be 127.0.0.1 only)
    local ss_tcp_out
    ss_tcp_out=$(ss -tlnp 2>/dev/null)
    local mysql_listeners
    mysql_listeners=$(echo "$ss_tcp_out" | grep ':3306' || true)
    if [[ -n "$mysql_listeners" ]]; then
        if echo "$mysql_listeners" | grep -qE '127\.0\.0\.1:3306|\[::1\]:3306'; then
            ir_ok "MySQL listening on localhost only"
        else
            ir_crit "MySQL is listening on ALL interfaces (not localhost only) — check bind-address!"
        fi
    fi

    # Flag unexpected listening services (anything not expected on a LAMP box)
    local suspicious_ports
    suspicious_ports=$(echo "$ss_tcp_out" | grep LISTEN | grep -vE ':22|:80|:443|:25|:587|:3306|:8080|:8443|:53|:68|:67|127\.0\.0\.1|::1' || true)
    if [[ -n "$suspicious_ports" ]]; then
        ir_warn "Unexpected listening ports (possible backdoors):"
        echo "$suspicious_ports" | while read -r line; do ir_warn "  $line"; done
    else
        ir_ok "No unexpected listening ports detected"
    fi

    # Check UDP listeners too
    ir_info "UDP listeners:"
    ss -ulnp 2>/dev/null | grep -v '127.0.0.1\|::1\|:68\|:123\|:53\|:5353' | tee -a "$IR_REPORT" || true
}

# ── IR Check 7: Webshell Detection ───────────────────────────────
ir_check_webshells() {
    ir_section "Webshell Detection"

    local webroot="/var/www"
    if [[ ! -d "$webroot" ]]; then
        ir_warn "Web root $webroot not found — skipping"
        return
    fi

    local found_shells=0

    # High-confidence webshell patterns
    local -a shell_patterns=(
        'eval(base64_decode'
        'eval(gzinflate'
        'eval(str_rot13'
        'eval(gzuncompress'
        'eval(rawurldecode'
        '\$_GET\[.*\].*eval'
        '\$_POST\[.*\].*eval'
        '\$_REQUEST\[.*\].*eval'
        '\$_COOKIE\[.*\].*eval'
        'assert\(\$_'
        'preg_replace.*\/e.*\$_'
        'create_function.*\$_'
        'system\(\$_'
        'passthru\(\$_'
        'shell_exec\(\$_'
        'exec\(\$_'
        'popen\(\$_'
        'proc_open\(\$_'
        '\$_FILES.*\.\./'
        'move_uploaded_file.*\.\.\/'
        'php_uname\|phpinfo\|posix_getpwuid.*0'
    )

    ir_info "Scanning $webroot for webshell patterns (this may take a moment)..."

    # Build a single combined pattern for efficiency (one grep pass instead of 21)
    local combined_pattern
    combined_pattern=$(printf '%s|' "${shell_patterns[@]}")
    combined_pattern="${combined_pattern%|}"  # strip trailing |

    local -A seen_files=()  # track files already reported
    while IFS= read -r match_file; do
        # Skip if already reported
        [[ -n "${seen_files[$match_file]+x}" ]] && continue
        seen_files[$match_file]=1
        ir_crit "WEBSHELL PATTERN found in: $match_file"
        grep -nE "$combined_pattern" "$match_file" 2>/dev/null | head -5 | while read -r line; do
            ir_crit "  Line: $line"
        done
        ((found_shells++)) || true
    done < <(grep -rl --include="*.php" --include="*.phtml" --include="*.php5" \
                 -E "$combined_pattern" "$webroot" 2>/dev/null | head -100)

    # PHP files in upload directories
    local upload_php
    upload_php=$(find "$webroot" -type f -name "*.php" \
        \( -path "*/upload*" -o -path "*/files/*" -o -path "*/media/*" -o -path "*/tmp/*" \) 2>/dev/null)
    if [[ -n "$upload_php" ]]; then
        ir_crit "PHP files found in upload/media directories (likely webshells):"
        echo "$upload_php" | while read -r f; do ir_crit "  $f"; done
        ((found_shells++)) || true
    fi

    # Recently modified PHP files (last 24 hours)
    local recent_php
    recent_php=$(find "$webroot" -name "*.php" -mtime -1 -type f 2>/dev/null | head -30)
    if [[ -n "$recent_php" ]]; then
        ir_warn "PHP files modified in last 24 hours (verify legitimacy):"
        echo "$recent_php" | while read -r f; do ir_warn "  $f"; done
    fi

    # World-writable PHP files
    local ww_php
    ww_php=$(find "$webroot" -name "*.php" -perm -0002 -type f 2>/dev/null)
    if [[ -n "$ww_php" ]]; then
        ir_warn "World-writable PHP files:"
        echo "$ww_php" | while read -r f; do ir_warn "  $f"; done
    fi

    # Hidden files in web root (PHP files with leading dot)
    local hidden_php
    hidden_php=$(find "$webroot" -name ".*.php" -o -name "*.php.bak" -o -name "*.php~" 2>/dev/null | head -20)
    if [[ -n "$hidden_php" ]]; then
        ir_warn "Hidden or backup PHP files found:"
        echo "$hidden_php" | while read -r f; do ir_warn "  $f"; done
    fi

    if (( found_shells == 0 )); then
        ir_ok "No high-confidence webshell patterns detected"
    else
        ir_crit "$found_shells webshell indicator(s) found — investigate immediately!"
    fi
}

# ── IR Check 8: Suspicious Processes ─────────────────────────────
ir_check_processes() {
    ir_section "Process Audit"

    # Processes running from suspicious locations.
    # NOTE: exe paths ending in ' (deleted)' are normal after package upgrades —
    # the binary was replaced on disk but the old version stays in memory.
    # We only flag (deleted) if the exe was also in a suspicious directory.
    local suspicious_procs=0
    while IFS= read -r pid; do
        local exe cmdline
        exe=$(readlink "/proc/$pid/exe" 2>/dev/null || echo "")
        [[ -z "$exe" ]] && continue
        # Use cat so the redirect error is suppressed by cat's own 2>/dev/null
        cmdline=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ' | cut -c1-120 || echo "")
        # (deleted) suffix is normal after apt upgrades — binary replaced on disk
        # but old version stays resident in memory. Only flag if path is suspicious.
        local exe_path="${exe% (deleted)}"
        if [[ "$exe_path" =~ ^(/tmp|/dev/shm|/var/tmp|/run/user) ]]; then
            ir_crit "Process running from suspicious location: PID=$pid exe=$exe"
            ir_crit "  Cmdline: $cmdline"
            ((suspicious_procs++)) || true
        fi
    done < <(ls /proc 2>/dev/null | grep -E '^[0-9]+$')

    # Known reverse-shell tools
    local shell_tools=("nc" "ncat" "netcat" "socat" "msfconsole" "meterpreter")
    for tool in "${shell_tools[@]}"; do
        local pids
        pids=$(pgrep -x "$tool" 2>/dev/null || true)
        if [[ -n "$pids" ]]; then
            ir_crit "Reverse shell tool running: $tool (PID(s): $pids)"
            ((suspicious_procs++)) || true
        fi
    done

    # Web server child processes spawning shells (webshell indicator)
    local web_shell_procs
    web_shell_procs=$(ps -eo user,pid,ppid,cmd 2>/dev/null | grep -E '(www-data|apache|nginx).*(/bin/sh|/bin/bash|/bin/dash)' | grep -v grep || true)
    if [[ -n "$web_shell_procs" ]]; then
        ir_crit "Web server process spawned a shell (active webshell!):"
        echo "$web_shell_procs" | while read -r line; do ir_crit "  $line"; done
        ((suspicious_procs++)) || true
    fi

    # Processes with high CPU that might be crypto miners
    local cpu_hogs
    cpu_hogs=$(ps -eo pid,pcpu,user,cmd --sort=-pcpu 2>/dev/null | awk 'NR>1 && $2>80 {print}' | grep -v 'ps -eo' | head -5 || true)
    if [[ -n "$cpu_hogs" ]]; then
        ir_warn "High CPU processes (possible crypto miners):"
        echo "$cpu_hogs" | while read -r line; do ir_warn "  $line"; done
    fi

    if (( suspicious_procs == 0 )); then
        ir_ok "No obviously suspicious processes detected"
    fi
}

# ── IR Check 9: SUID/SGID Binaries ───────────────────────────────
ir_check_suid() {
    ir_section "SUID/SGID Binary Audit"

    # Known-good SUID binaries on Ubuntu LAMP systems
    local -a known_suid=(
        "/usr/bin/sudo"
        "/usr/bin/su"
        "/usr/bin/passwd"
        "/usr/bin/chsh"
        "/usr/bin/chfn"
        "/usr/bin/gpasswd"
        "/usr/bin/newgrp"
        "/usr/bin/mount"
        "/usr/bin/umount"
        "/usr/bin/pkexec"
        "/usr/bin/fusermount3"
        "/usr/bin/fusermount"
        "/usr/bin/crontab"
        "/usr/bin/wall"
        "/usr/bin/write"
        "/usr/bin/ssh-agent"
        "/usr/bin/at"
        "/usr/bin/dotlockfile"
        "/usr/bin/expiry"
        "/usr/bin/newuidmap"
        "/usr/bin/newgidmap"
        "/usr/sbin/pppd"
        "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
        "/usr/lib/openssh/ssh-keysign"
        "/usr/lib/eject/dmcrypt-get-device"
        "/usr/lib/snapd/snap-confine"
        "/usr/libexec/polkit-agent-helper-1"
        "/sbin/mount.nfs"
        "/sbin/unix_chkpwd"
    )

    local unexpected_suid=0
    while IFS= read -r suid_file; do
        local known=0
        for known_file in "${known_suid[@]}"; do
            [[ "$suid_file" == "$known_file" ]] && known=1 && break
        done
        if (( known == 0 )); then
            ir_warn "Unexpected SUID binary: $suid_file"
            ls -la "$suid_file" 2>/dev/null | while read -r line; do ir_warn "  $line"; done
            ((unexpected_suid++)) || true
        fi
    done < <(timeout 60 find / -xdev -perm -4000 -type f 2>/dev/null | sort)

    if (( unexpected_suid == 0 )); then
        ir_ok "All SUID binaries match expected list"
    else
        ir_warn "$unexpected_suid unexpected SUID file(s) — verify or remove with: chmod u-s <file>"
    fi

    # SGID files audit
    local unexpected_sgid=0
    local -a known_sgid=(
        "/usr/bin/wall"
        "/usr/bin/write"
        "/usr/bin/bsd-write"
        "/usr/bin/crontab"
        "/usr/bin/dotlockfile"
        "/usr/bin/expiry"
        "/usr/bin/mlocate"
        "/usr/bin/locate"
        "/usr/sbin/exim4"
        "/usr/sbin/postdrop"
        "/usr/sbin/postqueue"
        "/usr/lib/openssh/ssh-keysign"
    )
    while IFS= read -r sgid_file; do
        local known=0
        for known_file in "${known_sgid[@]}"; do
            [[ "$sgid_file" == "$known_file" ]] && known=1 && break
        done
        if (( known == 0 )); then
            ir_warn "Unexpected SGID binary: $sgid_file"
            ((unexpected_sgid++)) || true
        fi
    done < <(timeout 60 find / -xdev -perm -2000 -type f 2>/dev/null | sort)

    if (( unexpected_sgid == 0 )); then
        ir_ok "All SGID binaries match expected list"
    fi
}

# ── IR Check 10: Rootkit Detection ───────────────────────────────
ir_check_rootkits() {
    ir_section "Rootkit Detection"

    # Run chkrootkit
    if command -v chkrootkit &>/dev/null; then
        ir_info "Running chkrootkit (60s timeout)..."
        local ckrk_output
        # -q may not exist on all versions; fall back to full output filtered for findings
        ckrk_output=$(timeout 60 chkrootkit 2>/dev/null | grep -iE "INFECTED|Vulnerable|suspicious|Warning" | grep -iv "not infected\|not found" || true)
        if [[ -n "$ckrk_output" ]]; then
            ir_crit "chkrootkit findings:"
            echo "$ckrk_output" | while read -r line; do ir_crit "  $line"; done
        else
            ir_ok "chkrootkit found nothing suspicious"
        fi
    else
        ir_warn "chkrootkit not installed — consider: apt install chkrootkit"
    fi

    # Run rkhunter
    if command -v rkhunter &>/dev/null; then
        ir_info "Running rkhunter (quick check, 60s timeout)..."
        # --update makes a network request; use timeout to prevent hanging
        timeout 15 rkhunter --update --quiet 2>/dev/null || true
        local rkh_output
        # --sk = --skip-keypress, --rwo = --report-warnings-only
        rkh_output=$(timeout 60 rkhunter --check --sk --rwo 2>/dev/null || true)
        if [[ -n "$rkh_output" ]]; then
            ir_warn "rkhunter warnings:"
            echo "$rkh_output" | while read -r line; do ir_warn "  $line"; done
        else
            ir_ok "rkhunter found no warnings"
        fi
    else
        ir_warn "rkhunter not installed — consider: apt install rkhunter"
    fi

    # Manual rootkit indicators: known backdoor locations
    local -a rootkit_files=(
        "/dev/.udev"
        "/dev/.hdparm"
        "/dev/cgroup"
        "/etc/cron.d/.systemd"
        "/.bash_history"
        "/etc/rc.d/init.d/hdparm"
        "/usr/bin/bsd-port"
        "/usr/bin/.sshd"
        "/usr/lib/libpcprofile.so"
    )
    local rootkit_found=0
    for f in "${rootkit_files[@]}"; do
        if [[ -e "$f" ]]; then
            ir_crit "Known rootkit indicator found: $f"
            ((rootkit_found++)) || true
        fi
    done
    (( rootkit_found == 0 )) && ir_ok "No known rootkit indicator files found"

    # Check for LD_PRELOAD hijacking
    if [[ -s /etc/ld.so.preload ]]; then
        ir_crit "LD_PRELOAD set in /etc/ld.so.preload — possible library hijack:"
        cat /etc/ld.so.preload | while read -r line; do ir_crit "  $line"; done
    else
        ir_ok "/etc/ld.so.preload is empty (no library preloading)"
    fi

    # Check for unusual kernel modules
    if command -v lsmod &>/dev/null; then
        ir_info "Loaded kernel modules (review for unusual entries):"
        lsmod 2>/dev/null | grep -v "^Module" | awk '{print $1}' | sort | tee -a "$IR_REPORT" || true
    fi
}

# ── IR Check 11: Persistence Mechanisms ──────────────────────────
ir_check_persistence() {
    ir_section "Persistence Mechanism Audit"

    # 'eval' alone is intentionally excluded — it appears in standard Ubuntu .bashrc
    # (lesspipe, dircolors) and profile.d locale helpers. Only flag eval when combined
    # with a downloader or encoder, which is the actual attacker pattern.
    local suspicious_persist_pattern='wget|curl|\bnc\b|ncat|netcat|socat|bash -i|/tmp/|/dev/shm|base64|python.*-c|perl.*-e|php.*-r|mkfifo|/dev/tcp|eval.*(base64|curl|wget|\$\(curl|\$\(wget)'

    # /etc/rc.local
    if [[ -f /etc/rc.local ]] && [[ -s /etc/rc.local ]]; then
        local rc_suspicious
        rc_suspicious=$(grep -Pi "$suspicious_persist_pattern" /etc/rc.local 2>/dev/null || true)
        if [[ -n "$rc_suspicious" ]]; then
            ir_crit "Suspicious content in /etc/rc.local:"
            echo "$rc_suspicious" | while read -r line; do ir_crit "  $line"; done
        else
            ir_warn "/etc/rc.local exists with content — review:"
            grep -v '^\s*#\|^\s*$' /etc/rc.local | while read -r line; do ir_warn "  $line"; done
        fi
    else
        ir_ok "/etc/rc.local is empty or absent"
    fi

    # /etc/profile.d scripts
    while IFS= read -r f; do
        local prd_suspicious
        prd_suspicious=$(grep -Pi "$suspicious_persist_pattern" "$f" 2>/dev/null || true)
        if [[ -n "$prd_suspicious" ]]; then
            ir_crit "Suspicious content in profile.d script $f:"
            echo "$prd_suspicious" | while read -r line; do ir_crit "  $line"; done
        fi
        # Recently modified
        local f_days
        f_days=$(( ( $(date +%s) - $(stat -c %Y "$f" 2>/dev/null || echo 0) ) / 86400 ))
        if (( f_days < 7 )); then
            ir_warn "Recently modified profile.d script: $f (${f_days}d ago)"
        fi
    done < <(find /etc/profile.d -type f 2>/dev/null)

    # User shell startup files (~/.bashrc, ~/.profile, ~/.bash_profile)
    while IFS= read -r -d '' startup_file; do
        local su_suspicious
        su_suspicious=$(grep -Pi "$suspicious_persist_pattern" "$startup_file" 2>/dev/null || true)
        if [[ -n "$su_suspicious" ]]; then
            ir_crit "Suspicious content in $startup_file:"
            echo "$su_suspicious" | while read -r line; do ir_crit "  $line"; done
        fi
    done < <(find /root /home -maxdepth 2 \
        \( -name ".bashrc" -o -name ".bash_profile" -o -name ".profile" \
           -o -name ".zshrc" -o -name ".bash_login" \) -print0 2>/dev/null)

    # Check /etc/environment and /etc/bash.bashrc for LD_PRELOAD or PATH hijacking
    for f in /etc/environment /etc/bash.bashrc; do
        [[ -f "$f" ]] || continue
        if grep -qE 'LD_PRELOAD|LD_LIBRARY_PATH' "$f" 2>/dev/null; then
            ir_crit "Library path manipulation in $f:"
            grep -E 'LD_PRELOAD|LD_LIBRARY_PATH' "$f" | while read -r line; do ir_crit "  $line"; done
        fi
    done

    # Check for at(1) jobs
    if command -v atq &>/dev/null; then
        local at_jobs
        at_jobs=$(atq 2>/dev/null || true)
        if [[ -n "$at_jobs" ]]; then
            ir_warn "Pending at(1) jobs scheduled:"
            echo "$at_jobs" | while read -r line; do ir_warn "  $line"; done
        else
            ir_ok "No pending at(1) jobs"
        fi
    fi

    # Check for executable files in /tmp, /var/tmp, /dev/shm (red team staging areas)
    ir_info "Executable files in staging directories (/tmp, /var/tmp, /dev/shm):"
    local staging_exec
    staging_exec=$(find /tmp /var/tmp /dev/shm -maxdepth 3 -type f -executable 2>/dev/null | head -30 || true)
    if [[ -n "$staging_exec" ]]; then
        ir_crit "Executable files found in temp/staging directories (red team tools?):"
        echo "$staging_exec" | while read -r f; do
            local ftype
            ftype=$(file -b "$f" 2>/dev/null | cut -c1-60 || echo "unknown")
            ir_crit "  $f  [$ftype]"
        done
    else
        ir_ok "No executable files in /tmp, /var/tmp, /dev/shm"
    fi
}

# ── IR Check 12: Active Network Connections ───────────────────────
ir_check_connections() {
    ir_section "Active Network Connection Audit"

    # Established outbound connections from web/db service accounts
    local suspicious_conns
    suspicious_conns=$(ss -tp 2>/dev/null | grep -E 'ESTAB' | grep -v '127.0.0.1\|::1' || true)

    if [[ -n "$suspicious_conns" ]]; then
        ir_info "Established external connections:"
        echo "$suspicious_conns" | tee -a "$IR_REPORT"

        # Flag connections from www-data/apache/mysql processes
        local service_conns
        service_conns=$(ss -tp 2>/dev/null | grep -E 'ESTAB' | grep -E 'www-data|apache|nginx|mysql' | grep -v '127.0.0.1\|::1' || true)
        if [[ -n "$service_conns" ]]; then
            ir_crit "CRITICAL: Web/DB service has established outbound connection (reverse shell?):"
            echo "$service_conns" | while read -r line; do ir_crit "  $line"; done
        fi
    else
        ir_ok "No suspicious established connections detected"
    fi

    # Check for bash/sh processes that have established outbound network connections
    # (indicator of a bash reverse shell using /dev/tcp or similar)
    local bash_conns
    bash_conns=$(ss -tnp 2>/dev/null | grep ESTAB | grep -E '"(bash|sh|dash)"' | grep -v '127\.0\.0\.1\|::1' || true)
    if [[ -n "$bash_conns" ]]; then
        ir_crit "Shell process (bash/sh) has established network connection (reverse shell indicator!):"
        echo "$bash_conns" | while read -r line; do ir_crit "  $line"; done
    fi
}

# ── IR Check 13: Log Analysis ─────────────────────────────────────
ir_check_logs() {
    ir_section "Security Log Analysis"

    # Auth log — recent successful logins
    if [[ -f /var/log/auth.log ]]; then
        ir_info "Last 10 successful SSH logins:"
        grep "Accepted" /var/log/auth.log 2>/dev/null | tail -10 | \
            while read -r line; do ir_info "  $line"; done

        # Failed login spikes
        local failed_count
        failed_count=$(grep -c "Failed password" /var/log/auth.log 2>/dev/null || echo 0)
        failed_count=${failed_count:-0}
        if (( failed_count > 50 )); then
            ir_warn "High failed login count in auth.log: $failed_count failures"
        else
            ir_ok "Failed login count in auth.log: $failed_count"
        fi

        # Root login attempts
        local root_logins
        root_logins=$(grep "Accepted.*root" /var/log/auth.log 2>/dev/null | tail -5 || true)
        if [[ -n "$root_logins" ]]; then
            ir_crit "Root logins detected in auth.log:"
            echo "$root_logins" | while read -r line; do ir_crit "  $line"; done
        fi
    else
        ir_warn "/var/log/auth.log not found — check journalctl -u ssh"
    fi

    # Apache access log — attack patterns
    local apache_log="/var/log/apache2/access.log"
    if [[ -f "$apache_log" ]]; then
        # SQL injection attempts
        local sqli_count
        sqli_count=$(grep -ciE "union.*select|select.*from|insert.*into|drop.*table|'.*or.*'.*=|1=1|xp_cmdshell|waitfor.*delay" "$apache_log" 2>/dev/null || echo 0)
        sqli_count=${sqli_count:-0}
        if (( sqli_count > 0 )); then
            ir_warn "SQL injection attempts in Apache log: $sqli_count request(s)"
            grep -iE "union.*select|select.*from|drop.*table|1=1|xp_cmdshell" "$apache_log" 2>/dev/null | \
                tail -5 | while read -r line; do ir_warn "  $line"; done
        fi

        # Webshell upload/access
        local ws_access_count
        ws_access_count=$(grep -ciE "\.php\?.*=(http|ftp|https)://|\.php\?cmd=|\.php\?exec=|c99|r57|wso\." "$apache_log" 2>/dev/null || echo 0)
        if (( ws_access_count > 0 )); then
            ir_crit "Webshell access patterns in Apache log: $ws_access_count hit(s)"
        fi

        # LFI/RFI attempts
        local lfi_count
        lfi_count=$(grep -ciE "\.\./\.\./|etc/passwd|/proc/self|php://input|php://filter|data://text" "$apache_log" 2>/dev/null || echo 0)
        if (( lfi_count > 0 )); then
            ir_warn "LFI/RFI attempts in Apache log: $lfi_count request(s)"
        fi

        ir_ok "Apache log analysis complete — check above for findings"
    else
        ir_warn "Apache access log not found at $apache_log"
    fi
}

# ── IR Check 14: Modified System Files ───────────────────────────
ir_check_integrity() {
    ir_section "System File Integrity"

    # Files modified in last 7 days in sensitive locations
    # Use find -mtime -7 (7 days) rather than -newer <reference> since reference files
    # like /etc/os-release are updated by package upgrades and are unreliable.
    ir_info "Recently modified files in /etc /bin /sbin /usr/bin /usr/sbin (last 7 days):"
    local recent_sys_files
    recent_sys_files=$(find /etc /bin /sbin /usr/bin /usr/sbin -mtime -7 \
        -not -path "/etc/mtab" -not -path "/etc/resolv.conf" -not -path "/etc/hosts" \
        -not -path "/etc/ld.so.cache" -not -path "/etc/cron*" \
        -type f 2>/dev/null | head -30 || true)

    if [[ -n "$recent_sys_files" ]]; then
        echo "$recent_sys_files" | while read -r f; do
            local days
            days=$(( ( $(date +%s) - $(stat -c %Y "$f" 2>/dev/null || echo 0) ) / 86400 ))
            ir_warn "  Modified ${days}d ago: $f"
        done
    else
        ir_ok "No unusual recently modified system files"
    fi

    # Use debsums if available (verify package file integrity)
    if command -v debsums &>/dev/null; then
        ir_info "Running debsums package integrity check (may take a moment)..."
        local debsum_fails
        # debsums --silent only prints changed/missing files (failures); no filtering needed
        debsum_fails=$(debsums --silent 2>/dev/null | head -20 || true)
        if [[ -n "$debsum_fails" ]]; then
            ir_crit "Package files with altered checksums (possible rootkit/tampering):"
            echo "$debsum_fails" | while read -r line; do ir_crit "  $line"; done
        else
            ir_ok "debsums: all package files match expected checksums"
        fi
    else
        ir_warn "debsums not installed — install for binary integrity verification: apt install debsums"
    fi

    # World-writable files in sensitive paths
    local ww_sys
    ww_sys=$(find /etc /bin /sbin /usr/bin /usr/sbin -perm -0002 -type f 2>/dev/null | head -10 || true)
    if [[ -n "$ww_sys" ]]; then
        ir_crit "World-writable files in system directories:"
        echo "$ww_sys" | while read -r f; do ir_crit "  $f"; done
    else
        ir_ok "No world-writable files in system directories"
    fi
}

# ── Master IR Runner ──────────────────────────────────────────────
run_ir() {
    IR_REPORT="/root/ir-report-$(date +%Y%m%d-%H%M%S).txt"
    touch "$IR_REPORT" 2>/dev/null || IR_REPORT="/tmp/ir-report-$(date +%Y%m%d-%H%M%S).txt"

    echo "" | tee "$IR_REPORT"
    echo -e "${BOLD}${RED}╔══════════════════════════════════════════════════╗${NC}" | tee -a "$IR_REPORT"
    echo -e "${BOLD}${RED}║   MWCCDC INCIDENT RESPONSE AUDIT                ║${NC}" | tee -a "$IR_REPORT"
    echo -e "${BOLD}${RED}║   $(date)              ║${NC}" | tee -a "$IR_REPORT"
    echo -e "${BOLD}${RED}╚══════════════════════════════════════════════════╝${NC}" | tee -a "$IR_REPORT"
    echo ""

    ir_check_users
    ir_check_ssh_keys
    ir_check_crontabs
    ir_check_systemd
    ir_check_sudoers
    ir_check_ports
    ir_check_webshells
    ir_check_processes
    ir_check_suid
    ir_check_rootkits
    ir_check_persistence
    ir_check_connections
    ir_check_logs
    ir_check_integrity

    # ── IR Summary ────────────────────────────────────────────────
    echo "" | tee -a "$IR_REPORT"
    echo -e "${BOLD}╔══════════════════════════════════════════════════╗${NC}" | tee -a "$IR_REPORT"
    echo -e "${BOLD}║  IR AUDIT COMPLETE                               ║${NC}" | tee -a "$IR_REPORT"
    echo -e "${BOLD}╠══════════════════════════════════════════════════╣${NC}" | tee -a "$IR_REPORT"
    echo -e "${BOLD}║  ${RED}CRITICAL findings : $IR_CRITICAL${NC}${BOLD}                          ║${NC}" | tee -a "$IR_REPORT"
    echo -e "${BOLD}║  ${YELLOW}WARNINGS          : $IR_WARNINGS${NC}${BOLD}                          ║${NC}" | tee -a "$IR_REPORT"
    echo -e "${BOLD}║  ${GREEN}FIXED             : $IR_FIXED${NC}${BOLD}                           ║${NC}" | tee -a "$IR_REPORT"
    echo -e "${BOLD}╠══════════════════════════════════════════════════╣${NC}" | tee -a "$IR_REPORT"
    echo -e "${BOLD}║  Full report saved to: $IR_REPORT" | tee -a "$IR_REPORT"
    echo -e "${BOLD}╚══════════════════════════════════════════════════╝${NC}" | tee -a "$IR_REPORT"
    echo ""

    if (( IR_CRITICAL > 0 )); then
        echo -e "${RED}${BOLD}ACTION REQUIRED: $IR_CRITICAL critical finding(s) detected.${NC}"
        echo -e "${RED}Review the report above, then run: sudo bash harden.sh --apply${NC}"
    elif (( IR_WARNINGS > 0 )); then
        echo -e "${YELLOW}${BOLD}$IR_WARNINGS warning(s) found. Review and run: sudo bash harden.sh --apply${NC}"
    else
        echo -e "${GREEN}${BOLD}No critical findings. Run: sudo bash harden.sh --apply to harden the system.${NC}"
    fi
    echo ""
}

# ════════════════════════════════════════════════════════════════
# VERIFY — Re-run Lynis and report delta
# ════════════════════════════════════════════════════════════════
run_verify() {
    section "Running Lynis Verification Scan"

    if ! command -v lynis &>/dev/null; then
        fail "lynis not found"
        return
    fi

    info "Running lynis audit — this may take 2-3 minutes..."
    local report
    report=$(lynis audit system --no-colors --quiet 2>/dev/null)

    local index warnings suggestions
    # Extract hardening index — format: "Hardening index : 85 [####]"
    index=$(echo "$report" | grep "Hardening index" | grep -oP '\d+(?= \[)' 2>/dev/null ||             echo "$report" | grep "Hardening index" | grep -oE '[0-9]+' | head -1)
    warnings=$(echo "$report"    | grep -i "^[[:space:]]*Warnings"   | grep -oE '[0-9]+' | head -1)
    suggestions=$(echo "$report" | grep -i "^[[:space:]]*Suggestions" | grep -oE '[0-9]+' | head -1)

    echo ""
    echo -e "${BOLD}════════════ Lynis Score After Hardening ════════════${NC}"
    echo -e "  Hardening Index : ${BOLD}${index:-unknown}/100${NC}  (baseline was 69)"
    echo -e "  Warnings        : ${warnings:-unknown}  (baseline was 1)"
    echo -e "  Suggestions     : ${suggestions:-unknown}  (baseline was 41)"
    echo ""

    # List remaining warnings
    local remaining_warnings
    remaining_warnings=$(echo "$report" | awk '/Warnings \(/{p=1} p && /^  !/{print} /Suggestions \(/{p=0}')
    if [[ -n "$remaining_warnings" ]]; then
        warn "Remaining warnings:"
        echo "$remaining_warnings" | while read -r line; do
            echo -e "  ${RED}$line${NC}"
        done
    else
        ok "No warnings remaining!"
    fi
}

# ════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════
main() {
    check_root

    echo "" | tee "$LOG_FILE"
    echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════${NC}" | tee -a "$LOG_FILE"
    echo -e "${BOLD}${BLUE}  MWCCDC System Hardening — Ubuntu 24.04 LAMP/ECOM  ${NC}" | tee -a "$LOG_FILE"
    echo -e "${BOLD}${BLUE}  Mode: $MODE                                        ${NC}" | tee -a "$LOG_FILE"
    echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════${NC}" | tee -a "$LOG_FILE"
    echo ""

    if [[ "$MODE" == "--verify" ]]; then
        run_verify
        exit 0
    fi

    if [[ "$MODE" == "--ir" ]]; then
        run_ir
        exit 0
    fi

    if [[ "$MODE" == "--aide" ]]; then
        harden_aide
        exit 0
    fi

    if [[ "$MODE" == "--apply" ]]; then
        mkdir -p "$BACKUP_DIR"
        info "Backups will be saved to: $BACKUP_DIR"
    fi

    # Run all hardening functions
    harden_sysctl
    harden_ssh
    harden_apparmor
    harden_password_policy
    harden_file_perms
    harden_postfix
    harden_postfix_extra
    harden_banners
    harden_protocols
    harden_proc
    harden_session_timeout
    harden_compilers
    harden_core_dumps
    harden_packages
    harden_usb
    harden_umask
    harden_pwck

    # ── Firewall ──────────────────────────────────────────────────
    harden_ufw

    # ── LAMP Stack Hardening ─────────────────────────────────────
    harden_apache
    harden_modsecurity
    harden_ssl
    harden_php
    harden_mysql
    harden_web_files

    # ── Final Report ─────────────────────────────────────────────
    echo ""
    echo -e "${BOLD}════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  HARDENING COMPLETE — SUMMARY${NC}"
    echo -e "${BOLD}════════════════════════════════════════════════════${NC}"
    echo -e "  ${GREEN}PASSED${NC}  : $PASS checks"
    echo -e "  ${RED}FAILED${NC}  : $FAIL checks"
    echo -e "  ${CYAN}SKIPPED${NC} : $SKIP checks"
    echo -e "  Log file  : $LOG_FILE"
    if [[ "$MODE" == "--apply" ]]; then
        echo -e "  Backups   : $BACKUP_DIR"
    fi
    echo ""

    if (( FAIL == 0 )); then
        echo -e "  ${GREEN}${BOLD}All checks passed.${NC}"
    else
        echo -e "  ${YELLOW}${BOLD}$FAIL item(s) need manual attention — review $LOG_FILE${NC}"
    fi

    if (( REBOOT_REQUIRED == 1 )); then
        echo ""
        echo -e "  ${YELLOW}${BOLD}NOTE: Some changes require a reboot to take full effect.${NC}"
        echo -e "  ${YELLOW}(modprobe blacklists, fstab hidepid)${NC}"
    fi

    echo ""
    echo -e "  Run ${BOLD}sudo bash harden.sh --verify${NC} to re-run Lynis and see your new score."
    echo ""
    echo -e "  ${YELLOW}${BOLD}AIDE:${NC} File integrity database not initialized (skipped — takes 5-10 min)."
    echo -e "  ${YELLOW}When you have a free moment, run in the background:${NC}"
    echo -e "  ${BOLD}  sudo bash harden.sh --aide &${NC}"
    echo ""
}

# ── Mode validation & early-exit handlers ────────────────────────
# Placed here so show_ir_help / show_cheatsheet are already defined above.
case "$MODE" in
    --ir|--apply|--check|--verify|--aide) ;;
    --help|-h)
        echo "Usage: sudo bash harden.sh [MODE]"
        echo ""
        echo "  --ir          Incident response audit (run first on a new machine)"
        echo "  --apply       Apply all hardening fixes (default)"
        echo "  --check       Dry-run: show what would change without changing anything"
        echo "  --verify      Re-run Lynis and report score"
        echo "  --aide        Initialize AIDE integrity database (slow, run when idle)"
        echo "  --watch       Live color-coded monitor for all security logs"
        echo "  --ir-help     IR false-positive guide: what each check flags and why"
        echo "  --cheatsheet  Quick competition command reference (also --cs)"
        echo ""
        echo "  Recommended competition workflow:"
        echo "    1. sudo bash harden.sh --ir"
        echo "    2. sudo bash harden.sh --apply"
        echo "    3. sudo bash harden.sh --verify"
        echo "    4. sudo bash harden.sh --aide &"
        exit 0
        ;;
    --watch)
        check_root
        run_watch
        exit 0
        ;;
    --ir-help)
        show_ir_help
        exit 0
        ;;
    --cheatsheet|--cs)
        show_cheatsheet
        exit 0
        ;;
    *) echo "Unknown mode '$MODE' — defaulting to --apply" >&2; MODE="--apply" ;;
esac

main
