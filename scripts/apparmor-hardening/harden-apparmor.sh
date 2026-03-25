#!/bin/bash
# harden-apparmor.sh
# =============================================================================
# Master AppArmor Hardening Script for Debian
# Addresses all 5 warnings from apparmor-audit.sh:
#   1. Unconfined processes with network access
#   2. Flatpak profile in complain mode
#   3. Firefox has no AppArmor profile
#   4. Codium has no AppArmor profile
#   5. Unprivileged user namespaces enabled
#
# Usage:
#   sudo bash harden-apparmor.sh                    # Run all phases
#   sudo bash harden-apparmor.sh --phase 1          # Run specific phase
#   sudo bash harden-apparmor.sh --phase 1,2,3      # Run multiple phases
#   sudo bash harden-apparmor.sh --dry-run           # Preview changes
#   sudo bash harden-apparmor.sh --rollback          # Restore from backup
#   sudo bash harden-apparmor.sh --enforce           # Switch complain→enforce
#   sudo bash harden-apparmor.sh --status            # Show current status
#
# Phases:
#   1 — Backup current configuration
#   2 — Enforce Flatpak profile
#   3 — Deploy Firefox AppArmor profile (complain mode)
#   4 — Deploy Codium AppArmor profile (complain mode)
#   5 — Deploy wpa_supplicant, NetworkManager, docker-proxy profiles
#   6 — Restrict unprivileged user namespaces
#   7 — Verify all changes
#
# =============================================================================

set -u

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE_SRC="${SCRIPT_DIR}/profiles"
PROFILE_DST="/etc/apparmor.d"
LOCAL_DIR="${PROFILE_DST}/local"
BACKUP_BASE="/root/apparmor-backups"
SYSCTL_FILE="/etc/sysctl.d/99-disable-userns.conf"

# Profiles we manage
PROFILES=(
    "usr.bin.firefox"
    "usr.bin.codium"
    "usr.sbin.wpa_supplicant"
    "usr.sbin.NetworkManager"
    "usr.bin.docker-proxy"
)

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------
DRY_RUN=false
RUN_PHASES=""
DO_ROLLBACK=false
DO_ENFORCE=false
DO_STATUS=false

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
info()    { echo -e "  ${CYAN}ℹ${NC} $1"; }
good()    { echo -e "  ${GREEN}✓${NC} $1"; }
warn()    { echo -e "  ${YELLOW}⚠${NC} $1"; }
bad()     { echo -e "  ${RED}✗${NC} $1"; }
section() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${BLUE}$1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

dry_run_prefix() {
    if $DRY_RUN; then
        echo -e "  ${YELLOW}[DRY RUN]${NC} "
    fi
}

should_run_phase() {
    local phase="$1"
    if [ -z "$RUN_PHASES" ]; then
        return 0  # Run all phases
    fi
    echo "$RUN_PHASES" | grep -qw "$phase"
}

confirm() {
    if $DRY_RUN; then return 0; fi
    local prompt="$1"
    echo -e -n "  ${YELLOW}?${NC} ${prompt} [y/N] "
    read -r response
    case "$response" in
        [yY][eE][sS]|[yY]) return 0 ;;
        *) return 1 ;;
    esac
}

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --phase)
            shift
            RUN_PHASES="${1:-}"
            shift
            ;;
        --rollback)
            DO_ROLLBACK=true
            shift
            ;;
        --enforce)
            DO_ENFORCE=true
            shift
            ;;
        --status)
            DO_STATUS=true
            shift
            ;;
        --help|-h)
            echo "Usage: sudo bash $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --phase N[,N,...]  Run specific phase(s) only (1-7)"
            echo "  --dry-run          Preview changes without applying"
            echo "  --rollback         Restore from most recent backup"
            echo "  --enforce          Switch all managed profiles from complain to enforce"
            echo "  --status           Show current status of all managed profiles"
            echo "  --help             Show this help"
            echo ""
            echo "Phases:"
            echo "  1  Backup current configuration"
            echo "  2  Enforce Flatpak profile (complain → enforce)"
            echo "  3  Deploy Firefox AppArmor profile (complain mode)"
            echo "  4  Deploy Codium AppArmor profile (complain mode)"
            echo "  5  Deploy wpa_supplicant, NetworkManager, docker-proxy profiles"
            echo "  6  Restrict unprivileged user namespaces"
            echo "  7  Verify all changes"
            exit 0
            ;;
        *)
            echo "Unknown option: $1 (try --help)"
            exit 1
            ;;
    esac
done

# Must run as root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}ERROR: This script must be run as root (sudo).${NC}"
    exit 1
fi

# Check source profiles exist
if [ ! -d "$PROFILE_SRC" ]; then
    echo -e "${RED}ERROR: Profile source directory not found: ${PROFILE_SRC}${NC}"
    echo "Run this script from the apparmor-hardening directory."
    exit 1
fi

# =========================================================================
# HEADER
# =========================================================================
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║          AppArmor Hardening Script                           ║${NC}"
echo -e "${BOLD}${BLUE}║          $(date '+%Y-%m-%d %H:%M:%S %Z')                         ║${NC}"
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
if $DRY_RUN; then
    echo -e "${YELLOW}${BOLD}>>> DRY RUN MODE — no changes will be made <<<${NC}"
fi

# =========================================================================
# SPECIAL MODES: --status, --rollback, --enforce
# =========================================================================

# --- STATUS ---
if $DO_STATUS; then
    section "Current Status of Managed Profiles"

    for profile_name in "${PROFILES[@]}"; do
        if [ -f "${PROFILE_DST}/${profile_name}" ]; then
            mode="unknown"
            if grep -q 'flags=(enforce)' "${PROFILE_DST}/${profile_name}" 2>/dev/null; then
                mode="enforce"
            elif grep -q 'flags=(complain)' "${PROFILE_DST}/${profile_name}" 2>/dev/null; then
                mode="complain"
            elif grep -q 'flags=(unconfined)' "${PROFILE_DST}/${profile_name}" 2>/dev/null; then
                mode="unconfined"
            else
                # Check aa-status for runtime mode
                if aa-status 2>/dev/null | grep -q "${profile_name}"; then
                    mode=$(aa-status 2>/dev/null | grep -A1 "enforce" | grep "${profile_name}" > /dev/null && echo "enforce" || echo "loaded")
                fi
            fi
            case "$mode" in
                enforce)    good "${profile_name}: ${GREEN}ENFORCE${NC}" ;;
                complain)   warn "${profile_name}: ${YELLOW}COMPLAIN${NC}" ;;
                unconfined) info "${profile_name}: UNCONFINED" ;;
                *)          info "${profile_name}: installed (mode: $mode)" ;;
            esac
        else
            bad "${profile_name}: NOT INSTALLED"
        fi
    done

    # Flatpak
    if [ -f "${PROFILE_DST}/flatpak" ]; then
        if grep -q 'flags=(complain)' "${PROFILE_DST}/flatpak" 2>/dev/null; then
            warn "flatpak: ${YELLOW}COMPLAIN${NC}"
        else
            good "flatpak: likely enforce or custom"
        fi
    fi

    # Userns
    userns=$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || echo "N/A")
    if [ "$userns" = "0" ]; then
        good "Unprivileged user namespaces: DISABLED"
    elif [ "$userns" = "1" ]; then
        warn "Unprivileged user namespaces: ENABLED"
    else
        info "Unprivileged user namespaces: $userns"
    fi

    echo ""
    exit 0
fi

# --- ROLLBACK ---
if $DO_ROLLBACK; then
    section "Rollback — Restoring from Backup"

    if [ ! -d "$BACKUP_BASE" ]; then
        bad "No backup directory found at ${BACKUP_BASE}"
        exit 1
    fi

    # Find most recent backup
    latest=$(ls -1dt "${BACKUP_BASE}"/apparmor-backup-* 2>/dev/null | head -1)
    if [ -z "$latest" ]; then
        bad "No backups found in ${BACKUP_BASE}"
        exit 1
    fi

    info "Most recent backup: ${latest}"
    info "Contents:"
    ls -la "$latest/"

    if confirm "Restore AppArmor config from this backup?"; then
        # Remove our profiles
        for profile_name in "${PROFILES[@]}"; do
            if [ -f "${PROFILE_DST}/${profile_name}" ]; then
                info "Removing ${profile_name}"
                # Unload from kernel first
                apparmor_parser -R "${PROFILE_DST}/${profile_name}" 2>/dev/null || true
                rm -f "${PROFILE_DST}/${profile_name}"
            fi
            rm -f "${LOCAL_DIR}/${profile_name}"
        done

        # Restore backed-up profiles
        if [ -d "${latest}/apparmor.d" ]; then
            cp -a "${latest}/apparmor.d/"* "${PROFILE_DST}/" 2>/dev/null || true
            good "Restored profiles from backup"
        fi

        # Restore userns sysctl
        if [ -f "${latest}/sysctl-userns.txt" ]; then
            original_value=$(cat "${latest}/sysctl-userns.txt" | awk -F= '{print $2}' | tr -d ' ')
            if [ -n "$original_value" ]; then
                sysctl -w "kernel.unprivileged_userns_clone=${original_value}" > /dev/null
                rm -f "$SYSCTL_FILE"
                good "Restored unprivileged_userns_clone=${original_value}"
            fi
        fi

        # Reload AppArmor
        systemctl reload apparmor 2>/dev/null || apparmor_parser -r "${PROFILE_DST}"/* 2>/dev/null
        good "AppArmor reloaded"
        echo ""
        good "Rollback complete."
    else
        info "Rollback cancelled."
    fi
    exit 0
fi

# --- ENFORCE ---
if $DO_ENFORCE; then
    section "Switching All Managed Profiles to ENFORCE Mode"

    warn "This will convert complain-mode profiles to enforce mode."
    warn "Ensure you have tested all applications first!"
    echo ""

    if ! confirm "Proceed with enforcement?"; then
        info "Cancelled."
        exit 0
    fi

    for profile_name in "${PROFILES[@]}"; do
        profile_path="${PROFILE_DST}/${profile_name}"
        if [ ! -f "$profile_path" ]; then
            warn "${profile_name}: not installed, skipping"
            continue
        fi

        if grep -q 'flags=(enforce)' "$profile_path" 2>/dev/null; then
            good "${profile_name}: already in enforce mode"
            continue
        fi

        if grep -q 'flags=(complain)' "$profile_path" 2>/dev/null; then
            if ! $DRY_RUN; then
                # Replace flags=(complain) with flags=(enforce) in profile source
                sed -i 's/flags=(complain)/flags=(enforce)/' "$profile_path"
                # Use aa-enforce to also update the kernel state
                aa-enforce "$profile_path" 2>/dev/null || apparmor_parser -r "$profile_path" 2>/dev/null
                good "${profile_name}: switched to ENFORCE"
            else
                info "${profile_name}: would switch to ENFORCE"
            fi
        else
            warn "${profile_name}: no complain flag found, using aa-enforce"
            if ! $DRY_RUN; then
                aa-enforce "$profile_path" 2>/dev/null || true
            fi
        fi
    done

    echo ""
    good "Enforcement complete. Monitor for denials:"
    info "  journalctl -k --since '1 hour ago' | grep DENIED"
    exit 0
fi

# =========================================================================
# PHASE 1: BACKUP
# =========================================================================
if should_run_phase 1; then
    section "Phase 1: Backup Current Configuration"

    BACKUP_DIR="${BACKUP_BASE}/apparmor-backup-$(date +%Y%m%d-%H%M%S)"

    if ! $DRY_RUN; then
        mkdir -p "$BACKUP_DIR"

        # Backup profiles
        cp -a "${PROFILE_DST}/" "${BACKUP_DIR}/apparmor.d/" 2>/dev/null && \
            good "Backed up ${PROFILE_DST}/ → ${BACKUP_DIR}/apparmor.d/" || \
            warn "Could not backup ${PROFILE_DST}/"

        # Backup aa-status
        aa-status > "${BACKUP_DIR}/aa-status-before.txt" 2>&1 && \
            good "Saved aa-status → ${BACKUP_DIR}/aa-status-before.txt" || \
            warn "Could not save aa-status"

        # Backup userns sysctl
        sysctl kernel.unprivileged_userns_clone > "${BACKUP_DIR}/sysctl-userns.txt" 2>&1 && \
            good "Saved userns sysctl → ${BACKUP_DIR}/sysctl-userns.txt" || \
            warn "Could not save userns sysctl (may not exist on this kernel)"

        # Backup GRUB
        if [ -f /etc/default/grub ]; then
            cp /etc/default/grub "${BACKUP_DIR}/grub.default"
            good "Saved GRUB config"
        fi

        # Record what we have
        aa-unconfined > "${BACKUP_DIR}/aa-unconfined-before.txt" 2>&1 || true
        good "Saved aa-unconfined output"

        info "Backup location: ${BACKUP_DIR}"
    else
        info "$(dry_run_prefix)Would create backup at: ${BACKUP_BASE}/apparmor-backup-YYYYMMDD-HHMMSS"
    fi
fi

# =========================================================================
# PHASE 2: ENFORCE FLATPAK
# =========================================================================
if should_run_phase 2; then
    section "Phase 2: Enforce Flatpak Profile"

    flatpak_profile="${PROFILE_DST}/flatpak"

    if [ ! -f "$flatpak_profile" ]; then
        warn "Flatpak profile not found at ${flatpak_profile} — skipping"
    else
        current_mode="unknown"
        if grep -q 'flags=(complain)' "$flatpak_profile" 2>/dev/null; then
            current_mode="complain"
        elif grep -q 'flags=(enforce)' "$flatpak_profile" 2>/dev/null; then
            current_mode="enforce"
        fi

        if [ "$current_mode" = "enforce" ]; then
            good "Flatpak profile is already in enforce mode"
        elif [ "$current_mode" = "complain" ]; then
            if ! $DRY_RUN; then
                # Switch from complain to enforce
                sed -i 's/flags=(complain)/flags=(enforce)/' "$flatpak_profile"
                aa-enforce "$flatpak_profile" 2>/dev/null || apparmor_parser -r "$flatpak_profile" 2>/dev/null
                if grep -q 'flags=(enforce)' "$flatpak_profile" 2>/dev/null; then
                    good "Flatpak profile switched to ENFORCE mode"
                else
                    # Profile may not have the flag in the file, use aa-enforce
                    aa-enforce "$flatpak_profile" 2>/dev/null
                    good "Flatpak profile enforced via aa-enforce"
                fi
            else
                info "$(dry_run_prefix)Would switch Flatpak profile from complain → enforce"
            fi
        else
            # No explicit flag — just enforce it
            if ! $DRY_RUN; then
                aa-enforce "$flatpak_profile" 2>/dev/null && \
                    good "Flatpak profile set to ENFORCE via aa-enforce" || \
                    warn "Could not enforce Flatpak profile"
            else
                info "$(dry_run_prefix)Would enforce Flatpak profile via aa-enforce"
            fi
        fi
    fi
fi

# =========================================================================
# PHASE 3: DEPLOY FIREFOX PROFILE
# =========================================================================
if should_run_phase 3; then
    section "Phase 3: Deploy Firefox AppArmor Profile"

    if [ ! -f /usr/bin/firefox ] && [ ! -f /usr/bin/firefox-esr ]; then
        warn "Firefox not installed — skipping profile deployment"
    else
        src_profile="${PROFILE_SRC}/usr.bin.firefox"
        dst_profile="${PROFILE_DST}/usr.bin.firefox"
        src_local="${PROFILE_SRC}/local/usr.bin.firefox"
        dst_local="${LOCAL_DIR}/usr.bin.firefox"

        if [ ! -f "$src_profile" ]; then
            bad "Source profile not found: ${src_profile}"
        else
            already_exists=false
            if [ -f "$dst_profile" ]; then
                already_exists=true
                warn "Firefox profile already exists at ${dst_profile}"
                if ! confirm "Overwrite existing Firefox profile?"; then
                    info "Skipping Firefox profile deployment"
                    already_exists="skip"
                fi
            fi

            if [ "$already_exists" != "skip" ]; then
                if ! $DRY_RUN; then
                    # Install profile
                    cp "$src_profile" "$dst_profile"
                    chmod 644 "$dst_profile"
                    chown root:root "$dst_profile"
                    good "Installed Firefox profile → ${dst_profile}"

                    # Install local override (only if not already present)
                    mkdir -p "$LOCAL_DIR"
                    if [ ! -f "$dst_local" ] && [ -f "$src_local" ]; then
                        cp "$src_local" "$dst_local"
                        chmod 644 "$dst_local"
                        chown root:root "$dst_local"
                        good "Installed local override → ${dst_local}"
                    fi

                    # Load profile in complain mode
                    apparmor_parser -r "$dst_profile" 2>/dev/null && \
                        good "Firefox profile loaded in COMPLAIN mode" || \
                        bad "Failed to load Firefox profile"
                else
                    info "$(dry_run_prefix)Would install Firefox profile to ${dst_profile}"
                    info "$(dry_run_prefix)Would load in complain mode"
                fi
            fi
        fi
    fi
fi

# =========================================================================
# PHASE 4: DEPLOY CODIUM PROFILE
# =========================================================================
if should_run_phase 4; then
    section "Phase 4: Deploy Codium AppArmor Profile"

    if [ ! -f /usr/bin/codium ]; then
        warn "Codium not installed — skipping profile deployment"
    else
        src_profile="${PROFILE_SRC}/usr.bin.codium"
        dst_profile="${PROFILE_DST}/usr.bin.codium"
        src_local="${PROFILE_SRC}/local/usr.bin.codium"
        dst_local="${LOCAL_DIR}/usr.bin.codium"

        if [ ! -f "$src_profile" ]; then
            bad "Source profile not found: ${src_profile}"
        else
            already_exists=false
            if [ -f "$dst_profile" ]; then
                already_exists=true
                warn "Codium profile already exists at ${dst_profile}"
                if ! confirm "Overwrite existing Codium profile?"; then
                    info "Skipping Codium profile deployment"
                    already_exists="skip"
                fi
            fi

            if [ "$already_exists" != "skip" ]; then
                if ! $DRY_RUN; then
                    cp "$src_profile" "$dst_profile"
                    chmod 644 "$dst_profile"
                    chown root:root "$dst_profile"
                    good "Installed Codium profile → ${dst_profile}"

                    mkdir -p "$LOCAL_DIR"
                    if [ ! -f "$dst_local" ] && [ -f "$src_local" ]; then
                        cp "$src_local" "$dst_local"
                        chmod 644 "$dst_local"
                        chown root:root "$dst_local"
                        good "Installed local override → ${dst_local}"
                    fi

                    apparmor_parser -r "$dst_profile" 2>/dev/null && \
                        good "Codium profile loaded in COMPLAIN mode" || \
                        bad "Failed to load Codium profile"

                    echo ""
                    warn "IMPORTANT: Test MCP server connectivity before proceeding!"
                    info "  1. Open VSCodium"
                    info "  2. Verify all MCP servers respond (use Roo to call a tool)"
                    info "  3. Check for denials: journalctl -k | grep codium | grep DENIED"
                    info "  4. Add missing rules to ${dst_local} if needed"
                else
                    info "$(dry_run_prefix)Would install Codium profile to ${dst_profile}"
                    info "$(dry_run_prefix)Would load in complain mode"
                fi
            fi
        fi
    fi
fi

# =========================================================================
# PHASE 5: DEPLOY SYSTEM DAEMON PROFILES
# =========================================================================
if should_run_phase 5; then
    section "Phase 5: Deploy System Daemon Profiles"

    deploy_profile() {
        local name="$1"
        local binary="$2"
        local src="${PROFILE_SRC}/${name}"
        local dst="${PROFILE_DST}/${name}"
        local src_local="${PROFILE_SRC}/local/${name}"
        local dst_local="${LOCAL_DIR}/${name}"

        if [ ! -f "$binary" ]; then
            info "${name}: binary ${binary} not found — skipping"
            return
        fi

        if [ ! -f "$src" ]; then
            bad "${name}: source profile not found at ${src}"
            return
        fi

        if [ -f "$dst" ]; then
            # Check if it's one of our profiles (has our header comment)
            if grep -q "Deployed by harden-apparmor.sh" "$dst" 2>/dev/null; then
                info "${name}: our profile already installed, updating"
            else
                warn "${name}: a different profile already exists"
                if ! confirm "Overwrite existing ${name} profile?"; then
                    info "Skipping ${name}"
                    return
                fi
            fi
        fi

        if ! $DRY_RUN; then
            cp "$src" "$dst"
            chmod 644 "$dst"
            chown root:root "$dst"

            mkdir -p "$LOCAL_DIR"
            if [ ! -f "$dst_local" ] && [ -f "$src_local" ]; then
                cp "$src_local" "$dst_local"
                chmod 644 "$dst_local"
                chown root:root "$dst_local"
            fi

            apparmor_parser -r "$dst" 2>/dev/null && \
                good "${name}: loaded in COMPLAIN mode" || \
                bad "${name}: failed to load"
        else
            info "$(dry_run_prefix)Would install ${name} to ${dst}"
        fi
    }

    deploy_profile "usr.sbin.wpa_supplicant" "/usr/sbin/wpa_supplicant"
    deploy_profile "usr.sbin.NetworkManager"  "/usr/sbin/NetworkManager"
    deploy_profile "usr.bin.docker-proxy"     "/usr/bin/docker-proxy"
fi

# =========================================================================
# PHASE 6: RESTRICT UNPRIVILEGED USER NAMESPACES
# =========================================================================
if should_run_phase 6; then
    section "Phase 6: Restrict Unprivileged User Namespaces"

    current_userns=$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || echo "N/A")

    if [ "$current_userns" = "0" ]; then
        good "Unprivileged user namespaces already DISABLED"
    elif [ "$current_userns" = "1" ]; then
        warn "Unprivileged user namespaces currently ENABLED"
        echo ""

        # Check dependency: Firefox and Codium profiles must be deployed
        missing_deps=false
        for dep_profile in "usr.bin.firefox" "usr.bin.codium"; do
            if [ ! -f "${PROFILE_DST}/${dep_profile}" ]; then
                bad "DEPENDENCY: ${dep_profile} profile not deployed!"
                missing_deps=true
            else
                # Verify userns permission is in the profile
                if grep -q 'userns,' "${PROFILE_DST}/${dep_profile}" 2>/dev/null; then
                    good "${dep_profile} has userns permission ✓"
                else
                    bad "${dep_profile} is MISSING userns permission!"
                    missing_deps=true
                fi
            fi
        done

        if $missing_deps; then
            bad "Cannot disable userns: required profiles not deployed with userns permission"
            warn "Run phases 3 and 4 first, test applications, then run phase 6"
            if $DRY_RUN; then
                warn "[DRY RUN] In live mode, this phase would BLOCK until profiles are deployed"
            elif ! confirm "Override dependency check and disable anyway? (DANGEROUS)"; then
                info "Skipping userns restriction"
                missing_deps="skip"
            else
                warn "Proceeding despite missing dependencies!"
            fi
        fi

        if [ "$missing_deps" != "skip" ]; then
            if ! $DRY_RUN; then
                # Create sysctl config
                echo "# Disable unprivileged user namespaces for security" > "$SYSCTL_FILE"
                echo "# AppArmor profiles grant userns to specific apps (Firefox, Codium, etc.)" >> "$SYSCTL_FILE"
                echo "# Deployed by harden-apparmor.sh on $(date '+%Y-%m-%d %H:%M:%S')" >> "$SYSCTL_FILE"
                echo "kernel.unprivileged_userns_clone = 0" >> "$SYSCTL_FILE"

                # Apply immediately
                sysctl -p "$SYSCTL_FILE" > /dev/null 2>&1

                new_value=$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null)
                if [ "$new_value" = "0" ]; then
                    good "Unprivileged user namespaces DISABLED"
                    good "Sysctl config written to ${SYSCTL_FILE}"
                    echo ""
                    warn "CRITICAL: Test Firefox and Codium immediately!"
                    info "  If either app fails to launch, run:"
                    info "    sudo sysctl kernel.unprivileged_userns_clone=1"
                    info "  Then check the AppArmor profile has 'userns,' permission"
                else
                    bad "Failed to disable unprivileged user namespaces"
                fi
            else
                info "$(dry_run_prefix)Would write sysctl config to ${SYSCTL_FILE}"
                info "$(dry_run_prefix)Would set kernel.unprivileged_userns_clone=0"
            fi
        fi
    else
        info "Unprivileged user namespaces setting: ${current_userns} (not applicable)"
    fi
fi

# =========================================================================
# PHASE 7: VERIFICATION
# =========================================================================
if should_run_phase 7; then
    section "Phase 7: Verification"

    # Check each managed profile
    echo ""
    echo -e "  ${BOLD}Managed Profile Status:${NC}"
    for profile_name in "${PROFILES[@]}"; do
        profile_path="${PROFILE_DST}/${profile_name}"
        if [ -f "$profile_path" ]; then
            # Check if loaded in kernel
            if aa-status 2>/dev/null | grep -q "$(basename "$profile_path" | sed 's/usr\./\/usr\//' | sed 's/\./\//g' | sed 's/bin\//bin\//' | sed 's/sbin\//sbin\//')" 2>/dev/null; then
                mode="loaded"
            fi

            if grep -q 'flags=(enforce)' "$profile_path" 2>/dev/null; then
                good "${profile_name}: ${GREEN}ENFORCE${NC} ✓"
            elif grep -q 'flags=(complain)' "$profile_path" 2>/dev/null; then
                warn "${profile_name}: ${YELLOW}COMPLAIN${NC} (testing mode — run --enforce when ready)"
            else
                info "${profile_name}: installed"
            fi
        else
            bad "${profile_name}: NOT INSTALLED"
        fi
    done

    # Check Flatpak
    echo ""
    echo -e "  ${BOLD}Flatpak Profile:${NC}"
    if [ -f "${PROFILE_DST}/flatpak" ]; then
        if grep -q 'flags=(complain)' "${PROFILE_DST}/flatpak" 2>/dev/null; then
            warn "Flatpak: still in COMPLAIN mode"
        else
            good "Flatpak: ENFORCE (or custom mode)"
        fi
    else
        bad "Flatpak: no profile found"
    fi

    # Check unconfined processes
    echo ""
    echo -e "  ${BOLD}Unconfined Network Processes:${NC}"
    unconfined_output=$(aa-unconfined 2>/dev/null)
    if [ -n "$unconfined_output" ]; then
        unconfined_count=$(echo "$unconfined_output" | grep -c "not confined" || true)
        confined_count=$(echo "$unconfined_output" | grep -c "confined by" || true)

        if [ "$unconfined_count" -eq 0 ]; then
            good "All network processes are confined! (${confined_count} confined)"
        else
            warn "${unconfined_count} processes still unconfined:"
            echo "$unconfined_output" | grep "not confined" | while IFS= read -r line; do
                echo -e "    ${YELLOW}•${NC} $line"
            done
        fi
        if [ "$confined_count" -gt 0 ]; then
            good "${confined_count} processes ARE confined"
        fi
    fi

    # Check userns
    echo ""
    echo -e "  ${BOLD}User Namespaces:${NC}"
    userns_val=$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || echo "N/A")
    if [ "$userns_val" = "0" ]; then
        good "Unprivileged user namespaces: DISABLED ✓"
    elif [ "$userns_val" = "1" ]; then
        warn "Unprivileged user namespaces: still ENABLED"
    fi

    # Check for recent denials
    echo ""
    echo -e "  ${BOLD}Recent AppArmor Denials:${NC}"
    denial_count=$(journalctl -k --since "1 hour ago" --no-pager 2>/dev/null | grep -c "apparmor=\"DENIED\"" || true)
    if [ "$denial_count" -gt 0 ]; then
        warn "${denial_count} denial(s) in the last hour:"
        journalctl -k --since "1 hour ago" --no-pager 2>/dev/null | grep "apparmor=\"DENIED\"" | tail -10 | while IFS= read -r line; do
            echo -e "    ${YELLOW}•${NC} $line"
        done
        echo ""
        info "Review denials and add rules to /etc/apparmor.d/local/<profile> as needed"
    else
        good "No AppArmor denials in the last hour"
    fi

    # Summary
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${BLUE}Verification Summary${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    all_good=true
    for profile_name in "${PROFILES[@]}"; do
        if [ ! -f "${PROFILE_DST}/${profile_name}" ]; then
            all_good=false
        fi
    done

    if $all_good && [ "$userns_val" = "0" ] && [ "$unconfined_count" -eq 0 ] 2>/dev/null; then
        echo -e "  ${GREEN}${BOLD}ALL WARNINGS RESOLVED ✓${NC}"
    else
        echo -e "  ${YELLOW}${BOLD}Some items still need attention — see above${NC}"
    fi

    echo ""
    echo -e "  ${CYAN}Next steps:${NC}"
    echo -e "  1. Test all applications (Firefox, Codium+MCP, WiFi, Docker)"
    echo -e "  2. Monitor denials: ${CYAN}journalctl -k -f | grep DENIED${NC}"
    echo -e "  3. When satisfied, enforce: ${CYAN}sudo bash $0 --enforce${NC}"
    echo -e "  4. If problems occur: ${CYAN}sudo bash $0 --rollback${NC}"
fi

echo ""
