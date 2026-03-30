#!/usr/bin/env bash
# =============================================================================
# Defense MCP Server — One-command Hetzner Deploy
# =============================================================================
# Creates a Hetzner VPS and deploys the Defense MCP Server automatically.
#
# Prerequisites:
#   1. hcloud CLI installed (https://github.com/hetznercloud/cli)
#   2. A Hetzner API token (https://console.hetzner.cloud → Security → API Tokens)
#
# Usage:
#   ./scripts/deploy-hetzner.sh
#
# Environment overrides:
#   HCLOUD_TOKEN=xxx      Hetzner API token (or will prompt)
#   SERVER_NAME=xxx       Server name (default: defense-mcp)
#   SERVER_TYPE=xxx       Instance size (default: cpx11)
#   SERVER_LOCATION=xxx   Datacenter (default: fsn1)
#   SERVER_IMAGE=xxx      OS image (default: debian-12)
#   MCP_PORT=xxx          Port for MCP server (default: 3100)
#   SSH_KEY_NAME=xxx      Name of SSH key in Hetzner (default: defense-mcp-key)
# =============================================================================

set -euo pipefail

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[x]${NC} $*" >&2; }
step() { echo -e "\n${CYAN}${BOLD}==> $*${NC}"; }

# --- Config ---
SERVER_NAME="${SERVER_NAME:-defense-mcp}"
SERVER_TYPE="${SERVER_TYPE:-cpx11}"
SERVER_LOCATION="${SERVER_LOCATION:-fsn1}"
SERVER_IMAGE="${SERVER_IMAGE:-debian-12}"
MCP_PORT="${MCP_PORT:-3100}"
SSH_KEY_NAME="${SSH_KEY_NAME:-defense-mcp-key}"

# Use the invoking user's home when run via sudo
REAL_HOME="${SUDO_USER:+$(eval echo "~$SUDO_USER")}"
REAL_HOME="${REAL_HOME:-$HOME}"
SSH_KEY_PATH="${REAL_HOME}/.ssh/defense-mcp-key"

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"

# --- Find hcloud ---
HCLOUD=""
for candidate in \
  "$(command -v hcloud 2>/dev/null)" \
  "$HOME/.local/bin/hcloud" \
  "/home/${SUDO_USER:-$USER}/.local/bin/hcloud" \
  "${REAL_HOME}/.local/bin/hcloud" \
  "/usr/local/bin/hcloud" \
  "/usr/bin/hcloud"; do
  if [[ -n "$candidate" && -x "$candidate" ]]; then
    HCLOUD="$candidate"
    break
  fi
done

if [[ -z "$HCLOUD" ]]; then
  err "hcloud CLI not found. Install it:"
  err "  curl -sL https://github.com/hetznercloud/cli/releases/latest/download/hcloud-linux-amd64.tar.gz | tar xz -C ~/.local/bin"
  exit 1
fi
log "Using hcloud: ${HCLOUD}"

# --- Auth ---
if [[ -z "${HCLOUD_TOKEN:-}" ]]; then
  echo ""
  echo -e "${CYAN}=============================================${NC}"
  echo -e "${CYAN}  Defense MCP Server — Hetzner Deploy${NC}"
  echo -e "${CYAN}=============================================${NC}"
  echo ""
  echo "You need a Hetzner Cloud API token."
  echo "Get one at: https://console.hetzner.cloud → Security → API Tokens"
  echo ""
  read -rsp "Paste your Hetzner API token: " HCLOUD_TOKEN
  echo ""

  if [[ -z "$HCLOUD_TOKEN" ]]; then
    err "No token provided."
    exit 1
  fi
fi
export HCLOUD_TOKEN

# Verify token works
if ! "$HCLOUD" server list &>/dev/null; then
  err "Invalid API token or network issue."
  exit 1
fi
log "Authenticated with Hetzner."

# =============================================================================
# 1. SSH Key
# =============================================================================
step "Setting up SSH key"

if [[ -f "$SSH_KEY_PATH" ]]; then
  log "SSH key already exists at ${SSH_KEY_PATH}"
else
  log "Generating SSH key pair..."
  mkdir -p "$(dirname "$SSH_KEY_PATH")"
  ssh-keygen -t ed25519 -f "$SSH_KEY_PATH" -N "" -C "defense-mcp-server"
  # If run via sudo, fix ownership so the real user can access it
  if [[ -n "${SUDO_USER:-}" ]]; then
    chown "${SUDO_USER}:${SUDO_USER}" "$SSH_KEY_PATH" "${SSH_KEY_PATH}.pub"
  fi
  log "Key generated: ${SSH_KEY_PATH}"
fi

# Upload to Hetzner if not already there
if "$HCLOUD" ssh-key describe "$SSH_KEY_NAME" &>/dev/null; then
  log "SSH key '${SSH_KEY_NAME}' already registered in Hetzner."
else
  log "Uploading SSH key to Hetzner..."
  "$HCLOUD" ssh-key create --name "$SSH_KEY_NAME" --public-key-from-file "${SSH_KEY_PATH}.pub"
  log "SSH key uploaded."
fi

# =============================================================================
# 2. Create server
# =============================================================================
step "Creating Hetzner server"

if "$HCLOUD" server describe "$SERVER_NAME" &>/dev/null; then
  warn "Server '${SERVER_NAME}' already exists."
  SERVER_IP=$("$HCLOUD" server ip "$SERVER_NAME")
  log "Using existing server at ${SERVER_IP}"
else
  echo ""
  echo -e "  ${BOLD}Name:${NC}      $SERVER_NAME"
  echo -e "  ${BOLD}Type:${NC}      $SERVER_TYPE"
  echo -e "  ${BOLD}Image:${NC}     $SERVER_IMAGE"
  echo -e "  ${BOLD}Location:${NC}  $SERVER_LOCATION"
  echo ""
  read -rp "Create this server? [y/N] " confirm
  if [[ "${confirm,,}" != "y" ]]; then
    err "Aborted."
    exit 0
  fi

  log "Creating server (this takes ~30 seconds)..."
  "$HCLOUD" server create \
    --name "$SERVER_NAME" \
    --type "$SERVER_TYPE" \
    --image "$SERVER_IMAGE" \
    --location "$SERVER_LOCATION" \
    --ssh-key "$SSH_KEY_NAME"

  SERVER_IP=$("$HCLOUD" server ip "$SERVER_NAME")
  log "Server created at ${SERVER_IP}"
fi

# =============================================================================
# 3. Wait for SSH
# =============================================================================
step "Waiting for SSH to be ready"

MAX_WAIT=180
WAITED=0
log "Using key: ${SSH_KEY_PATH}"
while ! ssh $SSH_OPTS -o ConnectTimeout=5 -o BatchMode=yes \
  -i "$SSH_KEY_PATH" root@"$SERVER_IP" "echo ok" &>/dev/null; do
  if [[ $WAITED -ge $MAX_WAIT ]]; then
    err "SSH not ready after ${MAX_WAIT}s. Try manually:"
    err "  ssh -i ${SSH_KEY_PATH} root@${SERVER_IP}"
    exit 1
  fi
  sleep 5
  WAITED=$((WAITED + 5))
  echo -n "."
done
echo ""
log "SSH is ready."

# =============================================================================
# 4. Run setup script on the server
# =============================================================================
step "Deploying Defense MCP Server"

LOCAL_SETUP="$(cd "$(dirname "$0")" && pwd)/hetzner-setup.sh"

if [[ -f "$LOCAL_SETUP" ]]; then
  log "Uploading local setup script..."
  scp $SSH_OPTS -i "$SSH_KEY_PATH" "$LOCAL_SETUP" root@"$SERVER_IP":/tmp/hetzner-setup.sh
  ssh $SSH_OPTS -i "$SSH_KEY_PATH" root@"$SERVER_IP" \
    "MCP_PORT=${MCP_PORT} bash /tmp/hetzner-setup.sh"
else
  warn "Local setup script not found at ${LOCAL_SETUP}"
  err "Cannot deploy — run this script from the defense-mcp-server repo root."
  exit 1
fi

# =============================================================================
# 5. Summary
# =============================================================================
echo ""
echo -e "${CYAN}=============================================${NC}"
echo -e "${CYAN}  Deployment Complete${NC}"
echo -e "${CYAN}=============================================${NC}"
echo ""
echo -e "  ${BOLD}Server IP:${NC}     ${SERVER_IP}"
echo -e "  ${BOLD}MCP Port:${NC}      ${MCP_PORT}"
echo -e "  ${BOLD}SSH:${NC}           ssh -i ${SSH_KEY_PATH} root@${SERVER_IP}"
echo -e "  ${BOLD}MCP Endpoint:${NC}  http://${SERVER_IP}:${MCP_PORT}"
echo ""
echo -e "  ${BOLD}Manage:${NC}"
echo "    hcloud server status ${SERVER_NAME}       # check status"
echo "    hcloud server stop ${SERVER_NAME}         # stop (stops billing)"
echo "    hcloud server start ${SERVER_NAME}        # start"
echo "    hcloud server delete ${SERVER_NAME}       # destroy"
echo ""
echo -e "  ${BOLD}On the server:${NC}"
echo "    journalctl -u defense-mcp-server -f      # watch logs"
echo "    systemctl restart defense-mcp-server      # restart"
echo ""
log "Your Defense MCP Server is live at http://${SERVER_IP}:${MCP_PORT}"
