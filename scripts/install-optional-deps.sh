#!/usr/bin/env bash
# install-optional-deps.sh — Install optional third-party security tools
#
# SECURITY: This script NEVER uses curl|sh patterns. All downloads go to
# temp files, are verified (SHA256/GPG), then installed.
#
# See docs/adr/third-party-tool-installation.md for design rationale.
#
# Usage:
#   ./scripts/install-optional-deps.sh              # Install all tools (interactive)
#   ./scripts/install-optional-deps.sh --dry-run     # Show what would be done
#   ./scripts/install-optional-deps.sh --tool grype   # Install just one tool
#   ./scripts/install-optional-deps.sh --yes          # Skip confirmations

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ── Globals ───────────────────────────────────────────────────────────────────

DRY_RUN=false
YES=false
TOOL_FILTER=""
LOG_FILE="/var/log/defense-mcp-install.log"
TEMP_DIR=""

# ── Version Pins (must match src/core/third-party-manifest.ts) ────────────────

FALCO_VERSION="0.39.2"
TRIVY_VERSION="0.58.1"
GRYPE_VERSION="0.86.1"
SYFT_VERSION="1.18.1"
TRUFFLEHOG_VERSION="3.88.1"
SLSA_VERIFIER_VERSION="2.6.0"
CDXGEN_VERSION="11.1.7"

# SHA256 checksums (must match src/core/third-party-manifest.ts)
GRYPE_SHA256_AMD64="2d1533dae213a27b741e0cb31b2cd354159a283325475512ae90c1c2412f4098"
GRYPE_SHA256_ARM64="f65d7a8bb4c08a3b2dad02b35e6f5729dc8a317a51955052ca2a9ce57d430e54"
SYFT_SHA256_AMD64="066c251652221e4d44fcc4d115ce3df33a91769da38c830a8533199db2f65aab"
SYFT_SHA256_ARM64="cd228306e5cb0654baecb454f76611606b84899d27fa9ceb7da4df46b94fe84e"
TRUFFLEHOG_SHA256_AMD64="0de286551c75b2f890f2c577ca97d761510641ecf3cabfdcdf4897c2c9901794"
TRUFFLEHOG_SHA256_ARM64="c85a0c1ce3a4d2e4f2b6f9cd4a40446e9294214b31f55edd548e66769e10cf32"
SLSA_VERIFIER_SHA256_AMD64="1c9c0d6a272063f3def6d233fa3372adbaff1f5a3480611a07c744e73246b62d"
SLSA_VERIFIER_SHA256_ARM64="92b28eb2db998f9a6a048336928b29a38cb100076cd587e443ca0a2543d7c93d"

# GPG fingerprints
FALCO_GPG_FINGERPRINT="15ED05F191E40D74BA47109F9F76B25D35785F62"
TRIVY_GPG_FINGERPRINT="232079315D25CF3BB7B0B81BCF44E8B631B27462"

# ── Helpers ───────────────────────────────────────────────────────────────────

log_info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*"; }

log_to_file() {
  if [[ -w "$(dirname "$LOG_FILE")" ]] || [[ -w "$LOG_FILE" ]]; then
    echo "$(date -Iseconds) $*" >> "$LOG_FILE" 2>/dev/null || true
  fi
}

detect_arch() {
  local arch
  arch=$(uname -m)
  case "$arch" in
    x86_64)  echo "amd64" ;;
    aarch64) echo "arm64" ;;
    *)       log_error "Unsupported architecture: $arch"; exit 1 ;;
  esac
}

cleanup() {
  if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
    rm -rf "$TEMP_DIR"
  fi
}
trap cleanup EXIT

create_temp_dir() {
  TEMP_DIR=$(mktemp -d /tmp/defense-mcp-install-XXXXXX)
  chmod 700 "$TEMP_DIR"
}

confirm() {
  if $YES; then return 0; fi
  local prompt="$1"
  read -rp "$prompt [y/N] " answer
  [[ "$answer" =~ ^[Yy]$ ]]
}

is_installed() {
  command -v "$1" &>/dev/null
}

verify_sha256() {
  local file="$1"
  local expected="$2"
  local actual
  actual=$(sha256sum "$file" | awk '{print $1}')
  if [[ "$actual" != "$expected" ]]; then
    log_error "SHA256 MISMATCH!"
    log_error "  Expected: $expected"
    log_error "  Got:      $actual"
    return 1
  fi
  log_success "SHA256 verified: $actual"
  return 0
}

# ── Install Functions ─────────────────────────────────────────────────────────

install_falco() {
  log_info "Installing Falco v${FALCO_VERSION}..."

  if is_installed falco; then
    log_warn "Falco is already installed: $(falco --version 2>/dev/null | head -1)"
    if ! confirm "  Reinstall?"; then return 0; fi
  fi

  if $DRY_RUN; then
    log_info "[DRY RUN] Would add Falco APT repo and install falco"
    return 0
  fi

  create_temp_dir
  local key_file="$TEMP_DIR/falco-key.asc"

  # Step 1: Download GPG key to file (NOT piped to gpg)
  log_info "Downloading Falco GPG key..."
  curl -fsSL -o "$key_file" https://falco.org/repo/falcosecurity-packages.asc

  # Step 2: Verify GPG fingerprint
  log_info "Verifying GPG fingerprint..."
  local fingerprint
  fingerprint=$(gpg --with-fingerprint --with-colons --import-options show-only --import "$key_file" 2>/dev/null | grep fpr | head -1 | cut -d: -f10)
  if [[ "$fingerprint" != "$FALCO_GPG_FINGERPRINT" ]]; then
    log_error "GPG fingerprint mismatch for Falco!"
    log_error "  Expected: $FALCO_GPG_FINGERPRINT"
    log_error "  Got:      $fingerprint"
    return 1
  fi
  log_success "GPG fingerprint verified: $fingerprint"

  # Step 3: Install keyring
  sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg "$key_file" 2>/dev/null || \
    (sudo rm -f /usr/share/keyrings/falco-archive-keyring.gpg && \
     sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg "$key_file")

  # Step 4: Add APT source with signed-by
  echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" | \
    sudo tee /etc/apt/sources.list.d/falco.list > /dev/null

  # Step 5: Install
  sudo apt-get update -qq
  sudo apt-get install -y falco

  log_success "Falco v${FALCO_VERSION} installed"
  log_to_file "INSTALLED falco v${FALCO_VERSION} via APT repo (GPG verified)"
}

install_trivy() {
  log_info "Installing Trivy v${TRIVY_VERSION}..."

  if is_installed trivy; then
    log_warn "Trivy is already installed: $(trivy --version 2>/dev/null | head -1)"
    if ! confirm "  Reinstall?"; then return 0; fi
  fi

  if $DRY_RUN; then
    log_info "[DRY RUN] Would add Trivy APT repo and install trivy"
    return 0
  fi

  create_temp_dir
  local key_file="$TEMP_DIR/trivy-key.asc"

  # Step 1: Download GPG key to file
  log_info "Downloading Trivy GPG key..."
  curl -fsSL -o "$key_file" https://aquasecurity.github.io/trivy-repo/deb/public.key

  # Step 2: Verify GPG fingerprint
  log_info "Verifying GPG fingerprint..."
  local fingerprint
  fingerprint=$(gpg --with-fingerprint --with-colons --import-options show-only --import "$key_file" 2>/dev/null | grep fpr | head -1 | cut -d: -f10)
  if [[ "$fingerprint" != "$TRIVY_GPG_FINGERPRINT" ]]; then
    log_error "GPG fingerprint mismatch for Trivy!"
    log_error "  Expected: $TRIVY_GPG_FINGERPRINT"
    log_error "  Got:      $fingerprint"
    return 1
  fi
  log_success "GPG fingerprint verified: $fingerprint"

  # Step 3: Install keyring
  sudo gpg --dearmor -o /usr/share/keyrings/trivy-archive-keyring.gpg "$key_file" 2>/dev/null || \
    (sudo rm -f /usr/share/keyrings/trivy-archive-keyring.gpg && \
     sudo gpg --dearmor -o /usr/share/keyrings/trivy-archive-keyring.gpg "$key_file")

  # Step 4: Add APT source with signed-by
  echo "deb [signed-by=/usr/share/keyrings/trivy-archive-keyring.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | \
    sudo tee /etc/apt/sources.list.d/trivy.list > /dev/null

  # Step 5: Install
  sudo apt-get update -qq
  sudo apt-get install -y trivy

  log_success "Trivy v${TRIVY_VERSION} installed"
  log_to_file "INSTALLED trivy v${TRIVY_VERSION} via APT repo (GPG verified)"
}

install_github_binary() {
  local name="$1"
  local binary="$2"
  local version="$3"
  local url="$4"
  local expected_sha256="$5"
  local is_tarball="$6"

  log_info "Installing ${name} v${version}..."

  if is_installed "$binary"; then
    log_warn "${name} is already installed: $($binary --version 2>/dev/null | head -1)"
    if ! confirm "  Reinstall?"; then return 0; fi
  fi

  if $DRY_RUN; then
    log_info "[DRY RUN] Would download ${name} from GitHub, verify SHA256, install to /usr/local/bin"
    return 0
  fi

  create_temp_dir

  if [[ "$is_tarball" == "true" ]]; then
    local download_file="$TEMP_DIR/${binary}.tar.gz"
  else
    local download_file="$TEMP_DIR/${binary}"
  fi

  # Step 1: Download to temp file
  log_info "Downloading from ${url}..."
  curl -fsSL -o "$download_file" --max-time 120 "$url"

  # Step 2: Verify SHA256
  log_info "Verifying SHA256 checksum..."
  verify_sha256 "$download_file" "$expected_sha256" || return 1

  # Step 3: Extract or prepare
  if [[ "$is_tarball" == "true" ]]; then
    log_info "Extracting tarball..."
    tar -xzf "$download_file" -C "$TEMP_DIR"
    local binary_path="$TEMP_DIR/$binary"
  else
    local binary_path="$download_file"
    chmod +x "$binary_path"
  fi

  if [[ ! -f "$binary_path" ]]; then
    log_error "Binary '$binary' not found after extraction"
    return 1
  fi

  # Step 4: Install
  sudo install -m 755 "$binary_path" "/usr/local/bin/$binary"

  log_success "${name} v${version} installed to /usr/local/bin/$binary"
  log_to_file "INSTALLED ${binary} v${version} from GitHub release (SHA256 verified)"
}

install_grype() {
  local arch
  arch=$(detect_arch)
  local sha256_var="GRYPE_SHA256_${arch^^}"
  local sha256="${!sha256_var}"
  local url="https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_${arch}.tar.gz"
  install_github_binary "Grype" "grype" "$GRYPE_VERSION" "$url" "$sha256" "true"
}

install_syft() {
  local arch
  arch=$(detect_arch)
  local sha256_var="SYFT_SHA256_${arch^^}"
  local sha256="${!sha256_var}"
  local url="https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${arch}.tar.gz"
  install_github_binary "Syft" "syft" "$SYFT_VERSION" "$url" "$sha256" "true"
}

install_trufflehog() {
  local arch
  arch=$(detect_arch)
  local sha256_var="TRUFFLEHOG_SHA256_${arch^^}"
  local sha256="${!sha256_var}"
  local url="https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${arch}.tar.gz"
  install_github_binary "TruffleHog" "trufflehog" "$TRUFFLEHOG_VERSION" "$url" "$sha256" "true"
}

install_slsa_verifier() {
  local arch
  arch=$(detect_arch)
  local sha256_var="SLSA_VERIFIER_SHA256_${arch^^}"
  local sha256="${!sha256_var}"
  local url="https://github.com/slsa-framework/slsa-verifier/releases/download/v${SLSA_VERIFIER_VERSION}/slsa-verifier-linux-${arch}"
  install_github_binary "SLSA Verifier" "slsa-verifier" "$SLSA_VERIFIER_VERSION" "$url" "$sha256" "false"
}

install_cdxgen() {
  log_info "Installing cdxgen v${CDXGEN_VERSION}..."

  if is_installed cdxgen; then
    log_warn "cdxgen is already installed: $(cdxgen --version 2>/dev/null | head -1)"
    if ! confirm "  Reinstall?"; then return 0; fi
  fi

  if $DRY_RUN; then
    log_info "[DRY RUN] Would install @cyclonedx/cdxgen@${CDXGEN_VERSION} via npm"
    return 0
  fi

  if ! is_installed npm; then
    log_error "npm is not installed. Install Node.js/npm first."
    return 1
  fi

  sudo npm install -g "@cyclonedx/cdxgen@${CDXGEN_VERSION}"

  log_success "cdxgen v${CDXGEN_VERSION} installed via npm"
  log_to_file "INSTALLED cdxgen v${CDXGEN_VERSION} via npm"
}

# ── Main ──────────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Install optional third-party security tools for defense-mcp-server.

Options:
  --dry-run       Show what would be done without making changes
  --tool <name>   Install only the specified tool
                  Available: falco, trivy, grype, syft, trufflehog, slsa-verifier, cdxgen
  --yes           Skip confirmation prompts
  --help          Show this help message

Security:
  - All downloads go to temp files first (NEVER piped to sh)
  - APT repos verified via GPG fingerprint
  - GitHub binaries verified via SHA256 checksum
  - All actions logged to $LOG_FILE

EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run)  DRY_RUN=true; shift ;;
      --yes)      YES=true; shift ;;
      --tool)     TOOL_FILTER="$2"; shift 2 ;;
      --help|-h)  usage; exit 0 ;;
      *)          log_error "Unknown option: $1"; usage; exit 1 ;;
    esac
  done
}

install_tool() {
  local tool="$1"
  case "$tool" in
    falco)          install_falco ;;
    trivy)          install_trivy ;;
    grype)          install_grype ;;
    syft)           install_syft ;;
    trufflehog)     install_trufflehog ;;
    slsa-verifier)  install_slsa_verifier ;;
    cdxgen)         install_cdxgen ;;
    *)              log_error "Unknown tool: $tool"; return 1 ;;
  esac
}

main() {
  parse_args "$@"

  echo ""
  echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
  echo -e "${BLUE}║  defense-mcp-server — Optional Dependencies Installer  ║${NC}"
  echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
  echo ""

  if $DRY_RUN; then
    log_warn "DRY RUN MODE — no changes will be made"
    echo ""
  fi

  local tools=(falco trivy grype syft trufflehog slsa-verifier cdxgen)

  if [[ -n "$TOOL_FILTER" ]]; then
    # Validate tool name
    local valid=false
    for t in "${tools[@]}"; do
      if [[ "$t" == "$TOOL_FILTER" ]]; then valid=true; break; fi
    done
    if ! $valid; then
      log_error "Unknown tool: $TOOL_FILTER"
      log_info "Available tools: ${tools[*]}"
      exit 1
    fi
    tools=("$TOOL_FILTER")
  fi

  echo "Tools to install:"
  for tool in "${tools[@]}"; do
    local status
    if is_installed "$tool"; then
      status="${GREEN}installed${NC}"
    else
      status="${YELLOW}missing${NC}"
    fi
    echo -e "  • $tool ($status)"
  done
  echo ""

  if ! $DRY_RUN && ! $YES; then
    if ! confirm "Proceed with installation?"; then
      log_info "Aborted."
      exit 0
    fi
    echo ""
  fi

  local succeeded=0
  local failed=0

  for tool in "${tools[@]}"; do
    echo -e "${BLUE}────────────────────────────────────────${NC}"
    if install_tool "$tool"; then
      ((succeeded++))
    else
      ((failed++))
      log_error "Failed to install $tool"
    fi
    echo ""
  done

  echo -e "${BLUE}════════════════════════════════════════${NC}"
  echo -e "Results: ${GREEN}${succeeded} succeeded${NC}, ${RED}${failed} failed${NC}"

  if [[ $failed -gt 0 ]]; then
    exit 1
  fi
}

main "$@"
