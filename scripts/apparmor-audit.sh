#!/bin/bash
# apparmor-audit.sh
# =============================================================================
# Comprehensive AppArmor security audit for Kali/Debian systems
# Usage: sudo bash apparmor-audit.sh
# =============================================================================

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root (sudo)."
    exit 1
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

ISSUES=()
WARNINGS=()
GOOD=()

section() { echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; echo -e "${BOLD}${BLUE}$1${NC}"; echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }
good()    { echo -e "  ${GREEN}✓${NC} $1"; GOOD+=("$1"); }
warn()    { echo -e "  ${YELLOW}⚠${NC} $1"; WARNINGS+=("$1"); }
bad()     { echo -e "  ${RED}✗${NC} $1"; ISSUES+=("$1"); }
info()    { echo -e "  ${CYAN}ℹ${NC} $1"; }

echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║           AppArmor Security Audit Report                     ║${NC}"
echo -e "${BOLD}${BLUE}║           $(date '+%Y-%m-%d %H:%M:%S %Z')                         ║${NC}"
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"

# =========================================================================
# 1. KERNEL & BOOT CONFIGURATION
# =========================================================================
section "1. Kernel & Boot Configuration"

# Check LSM stack
lsm_stack=$(cat /sys/kernel/security/lsm 2>/dev/null)
if echo "$lsm_stack" | grep -q "apparmor"; then
    good "AppArmor is in the LSM stack: $lsm_stack"
else
    bad "AppArmor is NOT in the LSM stack: $lsm_stack"
fi

# Check kernel boot params
cmdline=$(cat /proc/cmdline)
if echo "$cmdline" | grep -q "apparmor=1"; then
    good "AppArmor enabled via kernel parameter (apparmor=1)"
else
    warn "apparmor=1 not found in kernel parameters"
fi
if echo "$cmdline" | grep -q "security=apparmor"; then
    good "AppArmor set as primary security module (security=apparmor)"
else
    warn "security=apparmor not found in kernel parameters"
fi
if echo "$cmdline" | grep -q "audit=1"; then
    good "Audit logging enabled (audit=1)"
else
    warn "audit=1 not found — AppArmor denials may not be logged"
fi

# Check lockdown mode
if echo "$lsm_stack" | grep -q "lockdown"; then
    lockdown=$(cat /sys/kernel/security/lockdown 2>/dev/null || echo "unknown")
    info "Kernel lockdown available: $lockdown"
fi

# =========================================================================
# 2. APPARMOR SERVICE STATUS
# =========================================================================
section "2. AppArmor Service Status"

if systemctl is-active --quiet apparmor 2>/dev/null; then
    good "AppArmor service is active"
else
    bad "AppArmor service is NOT active"
fi

if systemctl is-enabled --quiet apparmor 2>/dev/null; then
    good "AppArmor service is enabled at boot"
else
    bad "AppArmor service is NOT enabled at boot"
fi

# =========================================================================
# 3. PROFILE ENFORCEMENT STATUS
# =========================================================================
section "3. Profile Enforcement Status"

aa_status_output=$(/usr/sbin/aa-status 2>/dev/null)
if [ -n "$aa_status_output" ]; then
    echo "$aa_status_output" | head -5
    echo ""

    total_profiles=$(echo "$aa_status_output" | grep "profiles are loaded" | awk '{print $1}')
    enforce_count=$(echo "$aa_status_output" | grep "profiles are in enforce mode" | awk '{print $1}')
    complain_count=$(echo "$aa_status_output" | grep "profiles are in complain mode" | awk '{print $1}')
    unconfined_count=$(echo "$aa_status_output" | grep "profiles are in unconfined mode" | awk '{print $1}' || echo "0")

    info "Total loaded profiles: ${total_profiles:-unknown}"
    if [ -n "$enforce_count" ] && [ "$enforce_count" -gt 0 ] 2>/dev/null; then
        good "$enforce_count profiles in enforce mode"
    else
        warn "No profiles in enforce mode"
    fi
    if [ -n "$complain_count" ] && [ "$complain_count" -gt 0 ] 2>/dev/null; then
        warn "$complain_count profiles in complain mode (logging only, not blocking)"
    fi
    if [ -n "$unconfined_count" ] && [ "$unconfined_count" -gt 0 ] 2>/dev/null; then
        info "$unconfined_count profiles in unconfined mode (named but not restricted)"
    fi

    # List enforce mode profiles
    echo ""
    echo -e "  ${GREEN}Profiles in ENFORCE mode:${NC}"
    in_enforce=false
    while IFS= read -r line; do
        if echo "$line" | grep -q "profiles are in enforce mode"; then
            in_enforce=true
            continue
        fi
        if $in_enforce; then
            if echo "$line" | grep -q "^\s*[0-9]"; then
                in_enforce=false
                continue
            fi
            if [ -n "$line" ]; then
                echo -e "    ${GREEN}•${NC} $(echo "$line" | sed 's/^\s*//')"
            fi
        fi
    done <<< "$aa_status_output"

    # List complain mode profiles
    echo ""
    echo -e "  ${YELLOW}Profiles in COMPLAIN mode:${NC}"
    in_complain=false
    while IFS= read -r line; do
        if echo "$line" | grep -q "profiles are in complain mode"; then
            in_complain=true
            continue
        fi
        if $in_complain; then
            if echo "$line" | grep -q "^\s*[0-9]"; then
                in_complain=false
                continue
            fi
            if [ -n "$line" ]; then
                echo -e "    ${YELLOW}•${NC} $(echo "$line" | sed 's/^\s*//')"
            fi
        fi
    done <<< "$aa_status_output"

    # List unconfined profiles
    echo ""
    echo -e "  ${CYAN}Profiles in UNCONFINED mode (named only):${NC}"
    in_unconfined=false
    while IFS= read -r line; do
        if echo "$line" | grep -q "profiles are in unconfined mode"; then
            in_unconfined=true
            continue
        fi
        if $in_unconfined; then
            if echo "$line" | grep -q "^\s*[0-9]"; then
                in_unconfined=false
                continue
            fi
            if [ -n "$line" ]; then
                echo -e "    ${CYAN}•${NC} $(echo "$line" | sed 's/^\s*//')"
            fi
        fi
    done <<< "$aa_status_output"

else
    bad "Could not retrieve aa-status output"
fi

# =========================================================================
# 4. BROKEN PLACEHOLDER PROFILES (ABI 4.0 without flags=(unconfined))
# =========================================================================
section "4. Broken Placeholder Profiles Check"

broken_installed=0
broken_notinstalled=0

for profile in /etc/apparmor.d/*; do
    [ -f "$profile" ] || continue
    name=$(basename "$profile")
    case "$name" in abi|abstractions|apache2.d|disable|force-complain|local|tunables) continue ;; esac

    grep -q 'abi <abi/4.0>' "$profile" 2>/dev/null || continue
    grep -q 'flags=(unconfined)' "$profile" 2>/dev/null && continue
    grep -q 'flags=(' "$profile" 2>/dev/null && continue

    # Count substantive rules
    rule_count=$(grep -cvP '^\s*(#|$|\}|abi |include |profile |userns,|pivot_root,)' "$profile" 2>/dev/null || true)
    rule_count="${rule_count:-0}"
    rule_count=$(echo "$rule_count" | tr -d '[:space:]')
    [ "$rule_count" -le 1 ] 2>/dev/null || continue

    # Extract binary
    binary=$(grep '^\s*profile ' "$profile" 2>/dev/null | head -1 | awk '{print $3}' | sed 's/{.*//' | tr -d '[:space:]')
    clean_binary=$(echo "$binary" | sed 's|{[^}]*}||g; s|@{[^}]*}||g; s|\*||g; s|//|/|g')

    if [ -f "$binary" ] 2>/dev/null || [ -f "$clean_binary" ] 2>/dev/null; then
        bad "BROKEN profile for INSTALLED app: $name → $binary (denies everything!)"
        broken_installed=$((broken_installed + 1))
    else
        broken_notinstalled=$((broken_notinstalled + 1))
    fi
done

if [ "$broken_installed" -eq 0 ]; then
    good "No broken profiles found for installed applications"
else
    bad "$broken_installed broken profiles found for installed applications — run fix-apparmor-profiles.sh"
fi
info "$broken_notinstalled broken profiles for uninstalled applications (harmless)"

# =========================================================================
# 5. UNCONFINED PROCESSES WITH NETWORK ACCESS
# =========================================================================
section "5. Unconfined Processes with Network Access"

info "Checking for unconfined processes with open network sockets..."
unconfined_output=$(/usr/sbin/aa-unconfined 2>/dev/null)
if [ -n "$unconfined_output" ]; then
    unconfined_count=$(echo "$unconfined_output" | grep -c "not confined" || true)
    confined_count=$(echo "$unconfined_output" | grep -c "confined by" || true)

    if [ "$unconfined_count" -gt 0 ]; then
        warn "$unconfined_count processes with network access are NOT confined by AppArmor:"
        echo "$unconfined_output" | grep "not confined" | while IFS= read -r line; do
            echo -e "    ${YELLOW}•${NC} $line"
        done
    fi
    if [ "$confined_count" -gt 0 ]; then
        good "$confined_count processes with network access ARE confined:"
        echo "$unconfined_output" | grep "confined by" | while IFS= read -r line; do
            echo -e "    ${GREEN}•${NC} $line"
        done
    fi
else
    warn "Could not check unconfined processes"
fi

# =========================================================================
# 6. KEY APPLICATION PROFILE ANALYSIS
# =========================================================================
section "6. Key Application Profile Analysis"

check_app_profile() {
    local app_name="$1"
    local binary="$2"
    local profile_file="$3"

    if ! [ -f "$binary" ]; then
        return  # App not installed, skip
    fi

    if ! [ -f "$profile_file" ]; then
        warn "$app_name ($binary) — NO AppArmor profile exists"
        return
    fi

    if grep -q 'flags=(unconfined)' "$profile_file" 2>/dev/null; then
        info "$app_name — profile exists but is UNCONFINED (named only, no restrictions)"
    elif grep -q 'flags=(complain)' "$profile_file" 2>/dev/null; then
        warn "$app_name — profile in COMPLAIN mode (logging only, not enforcing)"
    else
        # Check if it has real rules
        local rule_count
        rule_count=$(grep -cvP '^\s*(#|$|\}|abi |include |profile |userns,|pivot_root,)' "$profile_file" 2>/dev/null || true)
        rule_count=$(echo "${rule_count:-0}" | tr -d '[:space:]')
        if [ "$rule_count" -gt 3 ] 2>/dev/null; then
            good "$app_name — profile in ENFORCE mode with $rule_count rules"
        else
            warn "$app_name — profile has very few rules ($rule_count)"
        fi
    fi
}

# Check important applications
check_app_profile "Nautilus (Files)"    "/usr/bin/nautilus"     "/etc/apparmor.d/nautilus"
check_app_profile "Loupe (Image Viewer)" "/usr/bin/loupe"      "/etc/apparmor.d/loupe"
check_app_profile "Xorg"                "/usr/lib/xorg/Xorg"   "/etc/apparmor.d/Xorg"
check_app_profile "Evince (PDF Viewer)" "/usr/bin/evince"      "/etc/apparmor.d/usr.bin.evince"
check_app_profile "Flatpak"             "/usr/bin/flatpak"     "/etc/apparmor.d/flatpak"
check_app_profile "BusyBox"             "/usr/bin/busybox"     "/etc/apparmor.d/busybox"
check_app_profile "Totem (Video)"       "/usr/bin/totem"       "/etc/apparmor.d/usr.bin.totem"
check_app_profile "LibreOffice"         "/usr/lib/libreoffice/program/soffice.bin" "/etc/apparmor.d/usr.lib.libreoffice.program.soffice.bin"
check_app_profile "tcpdump"             "/usr/bin/tcpdump"     "/etc/apparmor.d/usr.bin.tcpdump"
check_app_profile "dnsmasq"             "/usr/sbin/dnsmasq"    "/etc/apparmor.d/usr.sbin.dnsmasq"
check_app_profile "cupsd (Printing)"    "/usr/sbin/cupsd"      "/etc/apparmor.d/usr.sbin.cupsd"

# Check for browsers, chat apps, etc.
for browser_bin in /usr/bin/firefox /usr/bin/chromium /opt/google/chrome/chrome /opt/brave.com/brave/brave /usr/bin/codium; do
    if [ -f "$browser_bin" ]; then
        app=$(basename "$browser_bin")
        profile_found=false
        for prof in /etc/apparmor.d/*; do
            if [ -f "$prof" ] && grep -q "$browser_bin" "$prof" 2>/dev/null; then
                profile_found=true
                prof_name=$(basename "$prof")
                if grep -q 'flags=(unconfined)' "$prof" 2>/dev/null; then
                    info "$app — profile exists but UNCONFINED"
                else
                    good "$app — confined by profile $prof_name"
                fi
                break
            fi
        done
        if ! $profile_found; then
            warn "$app ($browser_bin) — INSTALLED but has NO AppArmor profile"
        fi
    fi
done

# =========================================================================
# 7. YAMA & OTHER LSM SETTINGS
# =========================================================================
section "7. Additional Security Settings (Yama, Landlock, etc.)"

# Yama ptrace scope
ptrace_scope=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo "N/A")
case "$ptrace_scope" in
    0) warn "Yama ptrace_scope=0 — any process can ptrace any other (WEAK)" ;;
    1) good "Yama ptrace_scope=1 — only parent processes can ptrace children" ;;
    2) good "Yama ptrace_scope=2 — only admin can ptrace (STRONG)" ;;
    3) good "Yama ptrace_scope=3 — no ptrace allowed at all (MAXIMUM)" ;;
    *) info "Yama ptrace_scope=$ptrace_scope" ;;
esac

# Protected symlinks/hardlinks
prot_sym=$(cat /proc/sys/fs/protected_symlinks 2>/dev/null || echo "N/A")
prot_hard=$(cat /proc/sys/fs/protected_hardlinks 2>/dev/null || echo "N/A")
prot_reg=$(cat /proc/sys/fs/protected_regular 2>/dev/null || echo "N/A")
prot_fifos=$(cat /proc/sys/fs/protected_fifos 2>/dev/null || echo "N/A")

[ "$prot_sym" = "1" ] && good "Protected symlinks enabled" || warn "Protected symlinks: $prot_sym"
[ "$prot_hard" = "1" ] && good "Protected hardlinks enabled" || warn "Protected hardlinks: $prot_hard"
[ "$prot_reg" -ge 1 ] 2>/dev/null && good "Protected regular files: $prot_reg" || warn "Protected regular files: $prot_reg"
[ "$prot_fifos" -ge 1 ] 2>/dev/null && good "Protected FIFOs: $prot_fifos" || warn "Protected FIFOs: $prot_fifos"

# Unprivileged user namespaces
userns_enabled=$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || echo "N/A")
if [ "$userns_enabled" = "1" ]; then
    warn "Unprivileged user namespaces ENABLED (required by some apps, but increases attack surface)"
elif [ "$userns_enabled" = "0" ]; then
    good "Unprivileged user namespaces DISABLED"
else
    info "Unprivileged user namespaces setting: $userns_enabled"
fi

# Check if Landlock is available
if echo "$lsm_stack" | grep -q "landlock"; then
    landlock_status=$(cat /sys/kernel/security/landlock/status 2>/dev/null || echo "unknown")
    if [ "$landlock_status" = "1" ]; then
        good "Landlock LSM is active"
    else
        info "Landlock LSM is in the stack (status: $landlock_status)"
    fi
fi

# =========================================================================
# 8. AUDIT LOG CHECK
# =========================================================================
section "8. Recent AppArmor Denials (Last 24h)"

denial_count=0
if [ -f /var/log/audit/audit.log ]; then
    denial_count=$(grep -c "apparmor=\"DENIED\"" /var/log/audit/audit.log 2>/dev/null || true)
    if [ "$denial_count" -gt 0 ]; then
        warn "$denial_count AppArmor DENIED events in audit.log"
        echo -e "  ${YELLOW}Recent denials:${NC}"
        grep "apparmor=\"DENIED\"" /var/log/audit/audit.log 2>/dev/null | tail -5 | while IFS= read -r line; do
            echo -e "    ${YELLOW}•${NC} $line"
        done
    else
        good "No AppArmor denials found in audit.log"
    fi
fi

journal_denials=$(journalctl -k --since "24 hours ago" --no-pager 2>/dev/null | grep -c "apparmor=\"DENIED\"" || true)
if [ "$journal_denials" -gt 0 ]; then
    warn "$journal_denials AppArmor DENIED events in journal (last 24h)"
    journalctl -k --since "24 hours ago" --no-pager 2>/dev/null | grep "apparmor=\"DENIED\"" | tail -5 | while IFS= read -r line; do
        echo -e "    ${YELLOW}•${NC} $line"
    done
elif [ "$denial_count" -eq 0 ]; then
    good "No AppArmor denials in journal (last 24h)"
fi

# =========================================================================
# 9. PROFILE FILE PERMISSIONS
# =========================================================================
section "9. Profile File Permissions"

bad_perms=0
for profile in /etc/apparmor.d/*; do
    [ -f "$profile" ] || continue
    owner=$(stat -c '%U' "$profile")
    perms=$(stat -c '%a' "$profile")
    if [ "$owner" != "root" ]; then
        bad "$(basename "$profile") owned by $owner (should be root)"
        bad_perms=$((bad_perms + 1))
    fi
    # Profiles should not be world-writable (check if others write bit is set)
    # Others digit is last digit of octal perms; write bit = 2
    others_digit=$((perms % 10))
    if [ $((others_digit & 2)) -ne 0 ]; then
        bad "$(basename "$profile") is world-writable (perms: $perms)"
        bad_perms=$((bad_perms + 1))
    fi
done

if [ "$bad_perms" -eq 0 ]; then
    good "All profile files have correct ownership and permissions"
fi

# =========================================================================
# SUMMARY
# =========================================================================
section "AUDIT SUMMARY"

echo -e "  ${GREEN}Passed checks:${NC}  ${#GOOD[@]}"
echo -e "  ${YELLOW}Warnings:${NC}       ${#WARNINGS[@]}"
echo -e "  ${RED}Issues:${NC}         ${#ISSUES[@]}"
echo ""

if [ ${#ISSUES[@]} -gt 0 ]; then
    echo -e "${RED}${BOLD}Critical Issues (action required):${NC}"
    for issue in "${ISSUES[@]}"; do
        echo -e "  ${RED}✗${NC} $issue"
    done
    echo ""
fi

if [ ${#WARNINGS[@]} -gt 0 ]; then
    echo -e "${YELLOW}${BOLD}Warnings (consider addressing):${NC}"
    for w in "${WARNINGS[@]}"; do
        echo -e "  ${YELLOW}⚠${NC} $w"
    done
    echo ""
fi

# Overall score
total=$((${#GOOD[@]} + ${#WARNINGS[@]} + ${#ISSUES[@]}))
if [ "$total" -gt 0 ]; then
    score=$(( (${#GOOD[@]} * 100) / total ))
    if [ "$score" -ge 80 ]; then
        echo -e "${GREEN}${BOLD}Overall Security Score: ${score}% — GOOD${NC}"
    elif [ "$score" -ge 60 ]; then
        echo -e "${YELLOW}${BOLD}Overall Security Score: ${score}% — FAIR${NC}"
    else
        echo -e "${RED}${BOLD}Overall Security Score: ${score}% — NEEDS IMPROVEMENT${NC}"
    fi
fi

echo ""
echo -e "${CYAN}Recommendations:${NC}"
echo -e "  1. Apps with network access should ideally have enforcing AppArmor profiles"
echo -e "  2. Run 'sudo aa-enforce /etc/apparmor.d/<profile>' to enforce complain-mode profiles"
echo -e "  3. Consider 'sudo aa-genprof <app>' to generate profiles for unconfined apps"
echo -e "  4. Monitor /var/log/audit/audit.log regularly for DENIED events"
echo -e "  5. Remove unneeded profiles: sudo bash fix-apparmor-profiles.sh --remove-uninstalled"
echo ""
