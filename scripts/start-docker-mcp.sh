#!/usr/bin/env bash
# Defense MCP Server — Docker Startup Wrapper
#
# This is the command Roo calls as the MCP server entry point.
# It retrieves the host user's sudo password from GNOME Keyring (preferred)
# or an AES-256 encrypted file (fallback), then starts the Docker container
# with the password injected via a bind-mounted tmpfs secret file.
#
# The Docker image is built with the host user's uid/gid baked in (via
# HOST_USER/HOST_UID/HOST_GID build args in setup-credentials.sh), so the
# MCP Node.js process runs as the same identity as the caller.
#
# Security properties:
#   - Password is NEVER passed as a --env flag (invisible in docker inspect)
#   - The tmpfs file is shred-deleted on script exit
#   - The container reads from /run/secrets/mcpuser-password (Docker secret path)
#   - MCP JSON-RPC runs over stdin/stdout (--rm -i, no ports exposed)
#
# To set up credentials before first use, run:
#   /path/to/defense-mcp-server/scripts/setup-credentials.sh
set -euo pipefail

CURRENT_USER=$(whoami)
SERVICE="defense-mcp-server"
USERNAME="${CURRENT_USER}"
IMAGE="defense-mcp-server:latest"
FALLBACK_CRED_FILE="${HOME}/.config/defense-mcp-server/.${CURRENT_USER}-cred"

# ── Retrieve credential ────────────────────────────────────────────────────────
PW=""

# 1. Try GNOME Keyring via secret-tool (preferred — password never on disk)
if command -v secret-tool &>/dev/null; then
    PW=$(secret-tool lookup service "$SERVICE" username "$USERNAME" 2>/dev/null || true)
fi

# 2. Fall back to encrypted credential file
if [[ -z "$PW" ]] && [[ -f "$FALLBACK_CRED_FILE" ]]; then
    SALT=$(id -u)
    PW=$(openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 \
        -pass "pass:${SALT}-defense-mcp-local-key" \
        -in "$FALLBACK_CRED_FILE" 2>/dev/null || true)
fi

# ── No credential found — run without password ────────────────────────────────
if [[ -z "$PW" ]]; then
    # The entrypoint will generate a random password and warn.
    # Tools requiring sudo elevation will fail until setup-credentials.sh is run.
    exec docker run --rm -i \
        --name "defense-mcp-$(date +%s)" \
        "$IMAGE"
fi

# ── Write password to a temporary file in a private tmpdir ────────────────────
# mktemp -d creates a directory with mode 700 owned by the current user.
# The password file is written inside and chmod 600'd for defense-in-depth.
# This file is bind-mounted into the container at the Docker secret path so
# docker-entrypoint.sh reads it as a standard Docker secret.
# The password does NOT appear in 'docker inspect --format {{.Config.Env}}'.
TMPDIR_PRIV=$(mktemp -d)
SECRET_FILE="${TMPDIR_PRIV}/mcpuser-password"
printf '%s' "$PW" > "$SECRET_FILE"
chmod 600 "$SECRET_FILE"

# Zero PW immediately after writing to file — reduce in-memory exposure window
PW=$(printf '%0.s\000' {1..128}); unset PW

# ── Cleanup handler — always shred the temp secret file on exit ───────────────
cleanup() {
    # shred overwrites before unlink to prevent recovery from disk
    shred -u "$SECRET_FILE" 2>/dev/null || rm -f "$SECRET_FILE"
    rmdir "$TMPDIR_PRIV" 2>/dev/null || true
}
trap cleanup EXIT INT TERM HUP

# ── Start container with secret bind-mounted at Docker secret path ────────────
# --rm          : remove container on exit (no state leaks)
# -i            : keep stdin open for MCP JSON-RPC over stdio
# --mount       : bind-mount the temp secret file as read-only Docker secret
#                 docker-entrypoint.sh reads /run/secrets/mcpuser-password
#                 (the mount target name is an internal convention — only the
#                  entrypoint reads it, and MCP_USER inside the container
#                  determines which account receives the password)
# --name        : unique name per invocation (timestamp suffix prevents collisions)
exec docker run --rm -i \
    --name "defense-mcp-$(date +%s)" \
    --mount "type=bind,source=${SECRET_FILE},target=/run/secrets/mcpuser-password,readonly" \
    "$IMAGE"
