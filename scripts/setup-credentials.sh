#!/usr/bin/env bash
# Defense MCP Server — One-Time Credential Setup
#
# Stores the host user's sudo password in GNOME Keyring (preferred) or an
# AES-256 encrypted file (fallback).  Run this ONCE from an interactive
# terminal before starting the MCP server for the first time.
#
# The credential stored here is YOUR OWN system sudo password.  The Docker
# image is built with your uid/gid baked in (via HOST_USER/HOST_UID/HOST_GID
# build args), so the MCP server runs as you inside the container and uses
# your password for sudo_session elevation.
#
# Usage:
#   bash /path/to/defense-mcp-server/scripts/setup-credentials.sh
#
# After this runs, start the server via:
#   /path/to/defense-mcp-server/scripts/start-docker-mcp.sh
set -euo pipefail

# Resolve the project root relative to this script (works from any working dir)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKERFILE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

CURRENT_USER=$(whoami)
HOST_UID=$(id -u)
HOST_GID=$(id -g)
LABEL="Defense MCP Server ${CURRENT_USER}"
SERVICE="defense-mcp-server"
USERNAME="${CURRENT_USER}"
IMAGE="defense-mcp-server:latest"
FALLBACK_CRED_FILE="${HOME}/.config/defense-mcp-server/.${CURRENT_USER}-cred"

echo "=== Defense MCP Server — Credential Setup ==="
echo "  Running as: ${CURRENT_USER} (uid=${HOST_UID}, gid=${HOST_GID})"
echo ""

# ── Check secret-tool availability ───────────────────────────────────────────
if command -v secret-tool &>/dev/null; then
    STORAGE_METHOD="keychain"
    echo "✓ GNOME Keyring (secret-tool) available — using system keychain"
else
    STORAGE_METHOD="file"
    echo "⚠ secret-tool not found. Install with: sudo apt install libsecret-tools"
    echo "  Falling back to encrypted credential file: ${FALLBACK_CRED_FILE}"
    echo "  For best security, install libsecret-tools and re-run this script."
    echo ""
fi

# ── Prompt for password (obscured, no echo) ──────────────────────────────────
echo "  The Docker container will run as YOU (${CURRENT_USER}, uid=${HOST_UID})."
echo "  Enter your own system sudo password so the MCP server can use it"
echo "  for privilege elevation inside the container."
echo ""
while true; do
    read -s -p "Enter your sudo password for ${CURRENT_USER}: " PW
    echo ""
    read -s -p "Confirm password: " PW2
    echo ""
    if [[ "$PW" == "$PW2" ]]; then
        break
    fi
    echo "❌ Passwords do not match. Try again."
    echo ""
done
PW2=$(printf '%0.s\000' {1..128}); unset PW2   # zero confirm copy immediately

# ── Store the credential ──────────────────────────────────────────────────────
if [[ "$STORAGE_METHOD" == "keychain" ]]; then
    printf '%s' "$PW" | secret-tool store \
        --label="$LABEL" \
        service  "$SERVICE" \
        username "$USERNAME"
    echo "✓ Password stored in GNOME Keyring (label: '${LABEL}')"
    echo "  View with:   secret-tool lookup  service ${SERVICE} username ${USERNAME}"
    echo "  Delete with: secret-tool clear   service ${SERVICE} username ${USERNAME}"
else
    mkdir -p "$(dirname "$FALLBACK_CRED_FILE")"
    chmod 700 "$(dirname "$FALLBACK_CRED_FILE")"
    # Encrypt with AES-256-CBC using a key derived from the user's UID as salt.
    # This ties the encrypted blob to this user account on this machine.
    SALT=$(id -u)
    printf '%s' "$PW" | openssl enc -aes-256-cbc -pbkdf2 -iter 100000 \
        -pass "pass:${SALT}-defense-mcp-local-key" \
        -out "$FALLBACK_CRED_FILE"
    chmod 600 "$FALLBACK_CRED_FILE"
    echo "✓ Password stored encrypted at: ${FALLBACK_CRED_FILE}"
    echo "  Encrypted with AES-256-CBC + PBKDF2 (uid-salted key)"
fi

# ── Zero the password variable ────────────────────────────────────────────────
PW=$(printf '%0.s\000' {1..128}); unset PW

echo ""
echo "=== Building Docker Image ==="
echo "  Building with: HOST_USER=${CURRENT_USER}, HOST_UID=${HOST_UID}, HOST_GID=${HOST_GID}"
if docker image inspect "$IMAGE" &>/dev/null; then
    echo "✓ Image ${IMAGE} already exists. Rebuilding to pick up latest changes..."
fi

# Ensure the TypeScript source is compiled before building the image
echo "  Compiling TypeScript source..."
if command -v npm &>/dev/null && [[ -f "${DOCKERFILE_DIR}/package.json" ]]; then
    (cd "$DOCKERFILE_DIR" && npm run build 2>&1) || {
        echo "  ⚠ npm run build failed — attempting Docker build anyway"
    }
fi

# Pass host user identity as build args so the container runs as the same
# uid/gid as the operator — sudo_session elevation uses the operator's own
# system password, not a separate container-user password.
docker build \
    --build-arg HOST_USER="${CURRENT_USER}" \
    --build-arg HOST_UID="${HOST_UID}" \
    --build-arg HOST_GID="${HOST_GID}" \
    -t "$IMAGE" \
    "$DOCKERFILE_DIR"
echo "✓ Docker image built: ${IMAGE}"
echo "  Container runtime user: ${CURRENT_USER} (uid=${HOST_UID}, gid=${HOST_GID})"

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next: The MCP server will start automatically when Roo connects."
echo "To start manually:"
echo "  ${SCRIPT_DIR}/start-docker-mcp.sh"
echo ""
echo "To verify credential retrieval works:"
if [[ "$STORAGE_METHOD" == "keychain" ]]; then
    echo "  secret-tool lookup service ${SERVICE} username ${USERNAME}"
else
    SALT=$(id -u)
    echo "  openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 \\"
    echo "    -pass 'pass:${SALT}-defense-mcp-local-key' \\"
    echo "    -in '${FALLBACK_CRED_FILE}'"
fi
echo ""
echo "To verify the container runs as you:"
echo "  docker run --rm ${IMAGE} id"
echo "  (Expected: uid=${HOST_UID}(${CURRENT_USER}) gid=${HOST_GID}(${CURRENT_USER}) ...)"
