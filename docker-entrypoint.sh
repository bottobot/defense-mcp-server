#!/bin/bash
# Defense MCP Server — Container Entrypoint
#
# Runs as root at container startup.
# Sets the host-user's password from Docker secret or env var, then drops to
# that user. The MCP_USER env var (baked in at image build time via ARG HOST_USER)
# determines which account receives the password and which identity the Node.js
# process runs as.
#
# Security properties:
#   - Password is read from /run/secrets/mcpuser-password (preferred) or
#     MCPUSER_PASSWORD env var (acceptable for dev/CI)
#   - Password is passed to chpasswd via stdin (not command-line arguments)
#   - MCPUSER_PASSWORD env var is unset after use to prevent exposure in /proc
#   - If no password source is available, falls back to a random password and
#     warns. Tools requiring sudo will fail until the correct password is provided
#     via sudo_elevate with the matching credential.
#   - Core dumps are disabled to prevent password extraction from crash dumps
#
# Usage:
#   docker run --secret mcpuser-password defense-mcp-server
#   docker run -e MCPUSER_PASSWORD='...' defense-mcp-server
set -euo pipefail

# MCP_USER is baked into the image at build time via ENV MCP_USER=${HOST_USER}.
# This env var must be set — it is provided automatically by the Dockerfile.
if [[ -z "${MCP_USER:-}" ]]; then
  echo "[entrypoint] ERROR: MCP_USER env var is not set." >&2
  echo "[entrypoint] This image must be built with --build-arg HOST_USER=\$(whoami)." >&2
  echo "[entrypoint] Run scripts/setup-credentials.sh to rebuild correctly." >&2
  exit 1
fi
MCPUSER="${MCP_USER}"
SECRET_FILE="/run/secrets/mcpuser-password"
LOG_PREFIX="[entrypoint]"

log()  { echo "${LOG_PREFIX} $*" >&2; }
warn() { echo "${LOG_PREFIX} WARNING: $*" >&2; }
err()  { echo "${LOG_PREFIX} ERROR: $*" >&2; }

# ── Disable core dumps (prevents credential extraction from crash dumps) ──────
ulimit -c 0 2>/dev/null || warn "Could not disable core dumps (ulimit -c 0 failed)"

# ── Password Source Resolution ────────────────────────────────────────────────
PW=""

if [[ -f "${SECRET_FILE}" ]]; then
  PW=$(cat "${SECRET_FILE}")
  log "Password loaded from Docker secret (${SECRET_FILE})."

elif [[ -n "${MCPUSER_PASSWORD:-}" ]]; then
  PW="${MCPUSER_PASSWORD}"
  warn "Password loaded from environment variable MCPUSER_PASSWORD."
  warn "This exposes the password in 'docker inspect' and /proc/<pid>/environ."
  warn "Use Docker secrets in production: docker run --secret mcpuser-password ..."

else
  # Generate a random unguessable password.
  # sudo_elevate will always fail because the operator has no way to know
  # what random password was set. This is intentional — it prevents the
  # container from silently accepting no authentication.
  PW=$(openssl rand -base64 32 2>/dev/null || tr -dc 'A-Za-z0-9!@#$%^&*' < /dev/urandom | head -c 32)
  err "No password source found."
  err "  - No Docker secret at: ${SECRET_FILE}"
  err "  - No MCPUSER_PASSWORD environment variable set"
  err "A random unguessable password has been set for ${MCPUSER}."
  err "sudo_elevate will ALWAYS fail until the container is restarted"
  err "with a proper password source."
  err "Fix with: docker run --secret mcpuser-password defense-mcp-server"
  err "  OR:     docker run -e MCPUSER_PASSWORD='...' defense-mcp-server"
fi

# ── Set the host user's password ──────────────────────────────────────────────
if [[ -n "${PW}" ]]; then
  # Use printf to avoid shell interpretation of password metacharacters.
  # chpasswd reads "username:password" from stdin — the password is NEVER
  # passed as a command-line argument (which would be visible in /proc).
  printf '%s:%s\n' "${MCPUSER}" "${PW}" | chpasswd
  log "Password set for ${MCPUSER}."
else
  err "Empty password — cannot set. This should not happen."
  exit 1
fi

# ── Zero and unset credentials from this process's memory ────────────────────
# Overwrite the variable with a fixed-length string before unsetting.
# This is best-effort in bash (strings may be copied internally), but
# it reduces the window during which the credential is in memory.
PW=$(printf '%0.s*' {1..64})
unset PW
unset MCPUSER_PASSWORD 2>/dev/null || true
log "Credentials cleared from entrypoint environment."

# ── Ensure sudo audit log exists with correct permissions ─────────────────────
mkdir -p /var/log
touch /var/log/sudo-mcpuser.log
chown root:root /var/log/sudo-mcpuser.log
chmod 640 /var/log/sudo-mcpuser.log
log "Sudo audit log initialized at /var/log/sudo-mcpuser.log."

# ── Validate sudoers configuration before drop ───────────────────────────────
SUDOERS_FILE="/etc/sudoers.d/${MCPUSER}"
if command -v visudo >/dev/null 2>&1 && [[ -f "${SUDOERS_FILE}" ]]; then
  if visudo -c -f "${SUDOERS_FILE}" >/dev/null 2>&1; then
    log "Sudoers configuration valid (${SUDOERS_FILE})."
  else
    err "Sudoers configuration INVALID — sudo will not work!"
    err "Check ${SUDOERS_FILE} for syntax errors."
    # Continue anyway — the server still starts, but sudo tools will fail
  fi
fi

# ── Drop to the host user and exec the MCP server ────────────────────────────
log "Dropping privileges to ${MCPUSER} and starting MCP server..."

# Prefer su-exec (minimal setuid binary, no shell escape surface)
# Fall back to gosu, then setpriv (part of util-linux, standard on Debian)
if command -v su-exec >/dev/null 2>&1; then
  exec su-exec "${MCPUSER}" "$@"
elif command -v gosu >/dev/null 2>&1; then
  exec gosu "${MCPUSER}" "$@"
elif command -v setpriv >/dev/null 2>&1; then
  exec setpriv --reuid="${MCPUSER}" --regid="${MCPUSER}" --init-groups "$@"
else
  err "No privilege-drop binary found (su-exec, gosu, or setpriv required)."
  err "Install one of these in the Dockerfile and rebuild."
  exit 1
fi
