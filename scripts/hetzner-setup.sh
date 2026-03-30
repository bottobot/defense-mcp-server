#!/usr/bin/env bash
# =============================================================================
# Defense MCP Server — Hetzner VPS Setup Script
# =============================================================================
# Run this on a fresh Hetzner VPS (Debian 12 / Ubuntu 24.04) as root.
#
# Usage (on the server):
#   bash hetzner-setup.sh
#
# Environment overrides:
#   MCP_PORT=3100       Port for the MCP server (default: 3100)
# =============================================================================

set -euo pipefail

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[x]${NC} $*" >&2; }

# --- Preflight checks ---
if [[ $EUID -ne 0 ]]; then
  err "Run this script as root (or with sudo)."
  exit 1
fi

if ! grep -qiE 'debian|ubuntu' /etc/os-release 2>/dev/null; then
  err "This script targets Debian/Ubuntu. Detected something else."
  exit 1
fi

REPO_URL="https://github.com/bottobot/defense-mcp-server.git"
INSTALL_DIR="/opt/defense-mcp-server"
SERVICE_USER="defense"
SERVICE_NAME="defense-mcp-server"
MCP_PORT="${MCP_PORT:-3100}"
NODE_MAJOR=22

echo ""
echo -e "${CYAN}=============================================${NC}"
echo -e "${CYAN}  Defense MCP Server — Hetzner Setup${NC}"
echo -e "${CYAN}=============================================${NC}"
echo ""

# =============================================================================
# 1. System update
# =============================================================================
log "Updating system packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get upgrade -y -qq

# =============================================================================
# 2. Install Node.js 22
# =============================================================================
if command -v node &>/dev/null && [[ "$(node -v | cut -d. -f1 | tr -d v)" -ge $NODE_MAJOR ]]; then
  log "Node.js $(node -v) already installed — skipping."
else
  log "Installing Node.js ${NODE_MAJOR}..."
  apt-get install -y -qq ca-certificates curl gnupg
  mkdir -p /etc/apt/keyrings
  curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
    | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
  echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main" \
    > /etc/apt/sources.list.d/nodesource.list
  apt-get update -qq
  apt-get install -y -qq nodejs
  log "Installed Node.js $(node -v), npm $(npm -v)"
fi

# =============================================================================
# 3. Install core security tools (tolerate missing packages on minimal images)
# =============================================================================
log "Installing core security dependencies..."

# Split into groups so one missing package doesn't block everything
CORE_PKGS=(
  git curl lsof jq openssl gnupg ca-certificates
  htop strace logrotate sysstat
)
SECURITY_PKGS=(
  aide rkhunter chkrootkit clamav clamav-daemon lynis
  nmap tcpdump nftables fail2ban
  apparmor apparmor-utils libpam-pwquality
  debsums inotify-tools
  wireguard-tools ufw cryptsetup
)
# These may not exist on all Debian versions — install best-effort
OPTIONAL_PKGS=(
  auditd suricata acct uidmap
)

apt-get install -y -qq "${CORE_PKGS[@]}"
apt-get install -y -qq "${SECURITY_PKGS[@]}" || warn "Some security packages failed — continuing."
for pkg in "${OPTIONAL_PKGS[@]}"; do
  apt-get install -y -qq "$pkg" 2>/dev/null || warn "Optional package '${pkg}' not available — skipping."
done

log "Core packages installed."

# =============================================================================
# 4. Install third-party security tools
# =============================================================================
log "Installing third-party tools..."

install_if_missing() {
  local name="$1" url="$2"
  if command -v "$name" &>/dev/null; then
    log "${name} already installed — skipping."
  else
    if curl -sSfL "$url" | sh -s -- -b /usr/local/bin 2>/dev/null; then
      log "${name} installed."
    else
      warn "${name} install failed — skipping (can be installed later)."
    fi
  fi
}

install_if_missing trivy "https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh"
install_if_missing grype "https://raw.githubusercontent.com/anchore/grype/main/install.sh"
install_if_missing syft "https://raw.githubusercontent.com/anchore/syft/main/install.sh"
install_if_missing trufflehog "https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh"

# =============================================================================
# 5. Create service user
# =============================================================================
if id "$SERVICE_USER" &>/dev/null; then
  log "User '${SERVICE_USER}' already exists — skipping."
else
  log "Creating service user '${SERVICE_USER}'..."
  useradd --system --shell /usr/sbin/nologin --home-dir "$INSTALL_DIR" "$SERVICE_USER"
fi

# Grant the service user passwordless sudo for security tools
cat > /etc/sudoers.d/defense-mcp <<'SUDOERS'
# Defense MCP Server — allow the service user to run security tools
defense ALL=(ALL) NOPASSWD: /usr/sbin/iptables, /usr/sbin/ip6tables, /usr/sbin/nft, \
  /usr/sbin/ufw, /usr/sbin/auditctl, /usr/sbin/aureport, /usr/sbin/ausearch, \
  /usr/sbin/aideinit, /usr/sbin/aide, /usr/bin/rkhunter, /usr/bin/chkrootkit, \
  /usr/bin/lynis, /usr/bin/clamscan, /usr/bin/freshclam, /usr/sbin/fail2ban-client, \
  /usr/bin/nmap, /usr/sbin/tcpdump, /usr/bin/ss, /usr/sbin/sysctl, \
  /usr/bin/systemctl, /usr/sbin/apparmor_parser, /usr/bin/aa-status, \
  /usr/bin/debsums, /usr/bin/wg, /usr/sbin/suricata, \
  /usr/bin/apt-get, /usr/bin/dpkg, /usr/local/bin/trivy, /usr/local/bin/grype, \
  /usr/local/bin/syft, /usr/local/bin/trufflehog
SUDOERS
chmod 0440 /etc/sudoers.d/defense-mcp
log "Sudoers configured for service user."

# =============================================================================
# 6. Clone and build the server
# =============================================================================
git config --global --add safe.directory "$INSTALL_DIR" 2>/dev/null || true

if [[ -d "$INSTALL_DIR/.git" ]]; then
  log "Repo already cloned — pulling latest..."
  cd "$INSTALL_DIR"
  git pull --ff-only
else
  log "Cloning defense-mcp-server..."
  git clone "$REPO_URL" "$INSTALL_DIR"
  cd "$INSTALL_DIR"
fi

log "Installing npm dependencies..."
npm ci --quiet

log "Building..."
npx tsc

# Prune dev dependencies after build
npm prune --omit=dev --quiet 2>/dev/null || true

chown -R "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR"
log "Build complete."

# =============================================================================
# 7. Create systemd service
# =============================================================================
log "Creating systemd service..."
cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=Defense MCP Server
After=network.target
Documentation=https://github.com/bottobot/defense-mcp-server

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/node ${INSTALL_DIR}/build/index.js
Restart=on-failure
RestartSec=5
Environment=NODE_ENV=production
Environment=MCP_TRANSPORT=http
Environment=MCP_PORT=${MCP_PORT}

# Hardening
NoNewPrivileges=false
ProtectSystem=full
ProtectHome=true
PrivateTmp=true

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl start "$SERVICE_NAME"
log "Service started and enabled on boot."

# =============================================================================
# 8. Basic firewall setup
# =============================================================================
log "Configuring firewall..."
ufw --force reset >/dev/null 2>&1
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment "SSH"
ufw allow ${MCP_PORT}/tcp comment "Defense MCP Server"
ufw --force enable
log "Firewall active — SSH (22) and MCP (${MCP_PORT}) open."

# =============================================================================
# 9. Verify
# =============================================================================
echo ""
echo -e "${CYAN}=============================================${NC}"
echo -e "${CYAN}  Setup Complete${NC}"
echo -e "${CYAN}=============================================${NC}"
echo ""
log "Node.js:    $(node -v)"
log "npm:        $(npm -v)"
log "Install:    ${INSTALL_DIR}"
log "Service:    ${SERVICE_NAME}"
log "Port:       ${MCP_PORT}"
log "User:       ${SERVICE_USER}"
echo ""

if systemctl is-active --quiet "$SERVICE_NAME"; then
  log "Service status: ${GREEN}running${NC}"
else
  warn "Service may not be running. Check: journalctl -u ${SERVICE_NAME} -f"
fi

echo ""
log "Useful commands:"
echo "  journalctl -u ${SERVICE_NAME} -f     # watch logs"
echo "  systemctl restart ${SERVICE_NAME}     # restart"
echo "  systemctl status ${SERVICE_NAME}      # status"
echo "  cd ${INSTALL_DIR} && git pull && npm ci && npx tsc && npm prune --omit=dev && systemctl restart ${SERVICE_NAME}  # update"
echo ""
log "Done! Your Defense MCP Server is live."
