#!/bin/bash
# fix-apparmor-profiles.sh
# =============================================================================
# Fixes broken AppArmor 4.0 "unconfined" profiles on Kali/Debian systems.
#
# Problem: Many profiles shipped with apparmor-profiles use abi <abi/4.0> and
# claim to "allow everything" but are missing flags=(unconfined). In AppArmor
# 4.0, an empty profile body means DENY ALL by default, breaking applications.
#
# This script:
#   1. Scans /etc/apparmor.d/ for broken "placeholder" profiles
#   2. Cross-references with actually installed binaries
#   3. Fixes installed app profiles by adding flags=(unconfined)
#   4. Optionally removes profiles for apps that aren't installed
#   5. Reloads all modified profiles
#
# Usage: sudo bash fix-apparmor-profiles.sh [--remove-uninstalled] [--dry-run]
# =============================================================================

# Only use -u (unset variable check), NOT -e or pipefail.
# Many grep/sed operations legitimately return non-zero when patterns don't match.
set -u

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No color

PROFILE_DIR="/etc/apparmor.d"
DRY_RUN=false
REMOVE_UNINSTALLED=false

FIXED=()
ALREADY_OK=()
SKIPPED_NOT_INSTALLED=()
REMOVED=()
SKIPPED_REAL_PROFILE=()
ERRORS=()

# Parse arguments
for arg in "$@"; do
    case "$arg" in
        --dry-run)            DRY_RUN=true ;;
        --remove-uninstalled) REMOVE_UNINSTALLED=true ;;
        --help|-h)
            echo "Usage: sudo bash $0 [--remove-uninstalled] [--dry-run]"
            echo ""
            echo "  --dry-run              Show what would be changed without modifying anything"
            echo "  --remove-uninstalled   Remove profiles for applications that are not installed"
            exit 0
            ;;
        *) echo "Unknown option: $arg"; exit 1 ;;
    esac
done

# Must run as root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}ERROR: This script must be run as root (sudo).${NC}"
    exit 1
fi

echo -e "${BLUE}=== AppArmor Profile Fixer ===${NC}"
echo -e "Scanning ${PROFILE_DIR} for broken ABI 4.0 profiles..."
if $DRY_RUN; then
    echo -e "${YELLOW}DRY RUN MODE - no changes will be made${NC}"
fi
echo ""

# ---------------------------------------------------------------------------
# Helper: Determine if a profile is a "placeholder" (broken unconfined) type
# vs a real confining profile with actual rules.
#
# Placeholder profiles typically look like:
#   profile foo /usr/bin/foo {
#     userns,
#     include if exists <local/foo>
#   }
#
# Real confining profiles have actual capability/file/network rules.
# ---------------------------------------------------------------------------
is_placeholder_profile() {
    local file="$1"
    # Count substantive rules: lines that are NOT comments, blanks, closing brace,
    # abi declarations, include directives, profile declarations, userns, or pivot_root
    local rule_count
    rule_count=$(grep -cvP '^\s*(#|$|\}|abi |include |profile |userns,|pivot_root,)' "$file" 2>/dev/null || true)
    rule_count="${rule_count:-0}"
    # Trim any whitespace
    rule_count=$(echo "$rule_count" | tr -d '[:space:]')
    [ "$rule_count" -le 1 ] 2>/dev/null
}

# ---------------------------------------------------------------------------
# Helper: Extract the binary path from a profile's "profile" directive.
# Placeholder profiles use simple paths: /usr/bin/foo, /opt/App/app
# Complex profiles use AppArmor globs: /{usr/,}bin/{,iputils-}ping
# We return the raw path token; is_binary_installed handles resolution.
# ---------------------------------------------------------------------------
get_profile_binary() {
    local file="$1"
    local line
    line=$(grep '^\s*profile ' "$file" 2>/dev/null | head -1) || true

    if [ -z "$line" ]; then
        echo ""
        return
    fi

    # The profile line format is: profile <name> <path> [flags] {
    # Extract the 3rd whitespace-delimited token (the path)
    local path_token
    path_token=$(echo "$line" | awk '{print $3}') || true

    # Clean up: remove trailing { if it's attached
    path_token="${path_token%%\{*}"
    # Remove trailing whitespace
    path_token=$(echo "$path_token" | tr -d '[:space:]')

    echo "$path_token"
}

# ---------------------------------------------------------------------------
# Helper: Check if a binary path (possibly with AppArmor globs) is installed.
# Handles simple paths, brace alternations, and @{} variables.
# ---------------------------------------------------------------------------
is_binary_installed() {
    local path="$1"

    [ -z "$path" ] && return 1

    # 1. Try the path directly (works for simple paths like /usr/bin/foo)
    [ -f "$path" ] && return 0

    # 2. Strip all AppArmor glob/alternation patterns and check
    local clean
    clean=$(echo "$path" | sed 's|{[^}]*}||g; s|@{[^}]*}||g; s|\*||g; s|//|/|g')
    [ -n "$clean" ] && [ -f "$clean" ] && return 0

    # 3. Try to expand simple brace alternations like /usr/share/code{/bin,}/code
    #    by using bash brace expansion via eval
    local expanded
    expanded=$(eval echo "$path" 2>/dev/null) || true
    if [ -n "$expanded" ]; then
        for p in $expanded; do
            [ -f "$p" ] && return 0
        done
    fi

    # 4. For paths with {a,b} alternations, try the first option
    local first_expansion
    first_expansion=$(echo "$path" | sed 's|{\([^,}]*\)[,}][^}]*}|\1|g')
    [ -n "$first_expansion" ] && [ -f "$first_expansion" ] && return 0

    return 1
}

# ---------------------------------------------------------------------------
# Main scan loop
# ---------------------------------------------------------------------------
for profile in "$PROFILE_DIR"/*; do
    [ -f "$profile" ] || continue
    name=$(basename "$profile")

    # Skip directories, abstractions, and meta-files
    case "$name" in
        abi|abstractions|apache2.d|disable|force-complain|local|tunables) continue ;;
    esac

    # Only target profiles with ABI 4.0 (the problematic version)
    grep -q 'abi <abi/4.0>' "$profile" 2>/dev/null || continue

    # Already has flags=(unconfined) — already fixed
    if grep -q 'flags=(unconfined)' "$profile" 2>/dev/null; then
        binary=$(get_profile_binary "$profile")
        ALREADY_OK+=("$name ($binary)")
        continue
    fi

    # Check if this is a real confining profile (with actual rules) vs placeholder.
    # Do this BEFORE extracting binary, since real profiles have complex paths.
    if ! is_placeholder_profile "$profile"; then
        binary=$(get_profile_binary "$profile") || true
        # Has other flags like flags=(complain) or flags=(attach_disconnected)?
        if grep -q 'flags=(' "$profile" 2>/dev/null; then
            SKIPPED_REAL_PROFILE+=("$name ($binary) — has custom flags")
        else
            SKIPPED_REAL_PROFILE+=("$name ($binary) — has real confining rules")
        fi
        continue
    fi

    # Has flags=(complain) or flags=(attach_disconnected) — intentional, skip
    if grep -q 'flags=(' "$profile" 2>/dev/null; then
        binary=$(get_profile_binary "$profile") || true
        SKIPPED_REAL_PROFILE+=("$name ($binary) — has custom flags")
        continue
    fi

    # This is a placeholder profile with no flags — broken.
    binary=$(get_profile_binary "$profile") || true
    if [ -z "$binary" ]; then
        SKIPPED_REAL_PROFILE+=("$name — could not parse binary path")
        continue
    fi

    # Check if the app is installed.
    if is_binary_installed "$binary"; then
        echo -e "  ${GREEN}[FIX]${NC} $name → $binary ${GREEN}(installed)${NC}"

        if ! $DRY_RUN; then
            # Add flags=(unconfined) before the opening brace on the profile line
            # Handle paths with special characters by matching generously
            sed -i -E '/^\s*profile\s/{ s/\s*\{/ flags=(unconfined) {/; }' "$profile"

            # Verify the fix was applied
            if grep -q 'flags=(unconfined)' "$profile"; then
                FIXED+=("$name")
            else
                echo -e "    ${RED}WARNING: sed replacement may not have worked for $name${NC}"
                ERRORS+=("$name — sed replacement failed")
            fi
        else
            FIXED+=("$name (dry-run)")
        fi
    else
        if $REMOVE_UNINSTALLED; then
            echo -e "  ${RED}[REMOVE]${NC} $name → $binary ${YELLOW}(not installed)${NC}"
            if ! $DRY_RUN; then
                rm -f "$profile"
                REMOVED+=("$name")
            else
                REMOVED+=("$name (dry-run)")
            fi
        else
            echo -e "  ${YELLOW}[SKIP]${NC} $name → $binary ${YELLOW}(not installed)${NC}"
            SKIPPED_NOT_INSTALLED+=("$name ($binary)")
        fi
    fi
done

# ---------------------------------------------------------------------------
# Reload fixed profiles
# ---------------------------------------------------------------------------
if [ ${#FIXED[@]} -gt 0 ] && ! $DRY_RUN; then
    echo ""
    echo -e "${BLUE}=== Reloading fixed profiles ===${NC}"
    for name in "${FIXED[@]}"; do
        if [ -f "$PROFILE_DIR/$name" ]; then
            if apparmor_parser -r "$PROFILE_DIR/$name" 2>/dev/null; then
                echo -e "  ${GREEN}✓${NC} Reloaded: $name"
            else
                echo -e "  ${RED}✗${NC} Failed to reload: $name"
                ERRORS+=("$name — reload failed")
            fi
        fi
    done
fi

# Unload removed profiles from the kernel
if [ ${#REMOVED[@]} -gt 0 ] && ! $DRY_RUN; then
    echo ""
    echo -e "${BLUE}=== Unloading removed profiles ===${NC}"
    for name in "${REMOVED[@]}"; do
        if apparmor_parser -R "$PROFILE_DIR/$name" 2>/dev/null; then
            echo -e "  ${GREEN}✓${NC} Unloaded: $name"
        else
            echo -e "  ${YELLOW}~${NC} Could not unload: $name (may not have been loaded)"
        fi
    done
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo -e "${BLUE}=== Summary ===${NC}"
echo -e "  ${GREEN}Fixed:${NC}                  ${#FIXED[@]} profiles"
echo -e "  ${GREEN}Already correct:${NC}        ${#ALREADY_OK[@]} profiles"
echo -e "  ${YELLOW}Skipped (not installed):${NC} ${#SKIPPED_NOT_INSTALLED[@]} profiles"
echo -e "  ${YELLOW}Skipped (real profiles):${NC} ${#SKIPPED_REAL_PROFILE[@]} profiles"
if [ ${#REMOVED[@]} -gt 0 ]; then
    echo -e "  ${RED}Removed:${NC}                ${#REMOVED[@]} profiles"
fi
if [ ${#ERRORS[@]} -gt 0 ]; then
    echo -e "  ${RED}Errors:${NC}                 ${#ERRORS[@]}"
    for err in "${ERRORS[@]}"; do
        echo -e "    ${RED}→${NC} $err"
    done
fi

# Show details
if [ ${#ALREADY_OK[@]} -gt 0 ]; then
    echo ""
    echo -e "${GREEN}Already correct (flags=(unconfined) present):${NC}"
    for item in "${ALREADY_OK[@]}"; do
        echo "  ✓ $item"
    done
fi

if [ ${#SKIPPED_NOT_INSTALLED[@]} -gt 0 ]; then
    echo ""
    echo -e "${YELLOW}Skipped (app not installed) — re-run with --remove-uninstalled to clean up:${NC}"
    for item in "${SKIPPED_NOT_INSTALLED[@]}"; do
        echo "  ~ $item"
    done
fi

echo ""
if $DRY_RUN; then
    echo -e "${YELLOW}This was a dry run. Re-run without --dry-run to apply changes.${NC}"
else
    echo -e "${GREEN}Done! Applications should now launch correctly.${NC}"
fi
