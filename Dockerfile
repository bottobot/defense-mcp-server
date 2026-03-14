# Defense MCP Server — Docker Image
# Builds from local source since this is the development copy.
# For production: replace the COPY/build steps with: RUN npm install -g defense-mcp-server
#
# IMPORTANT: This image must be built with host user identity args so the
# MCP server process runs as the same uid/gid as the caller.  Always build
# via scripts/setup-credentials.sh which passes these automatically, or run:
#
#   docker build \
#     --build-arg HOST_USER=$(whoami) \
#     --build-arg HOST_UID=$(id -u) \
#     --build-arg HOST_GID=$(id -g) \
#     -t defense-mcp-server:latest .

FROM node:22-slim

LABEL org.opencontainers.image.title="defense-mcp-server"
LABEL org.opencontainers.image.description="Defensive security MCP server — 94 tools for system hardening"
LABEL org.opencontainers.image.version="0.7.0"
LABEL org.opencontainers.image.licenses="MIT"

# Install Linux security tools that the MCP server wraps
# gosu is the primary privilege-drop helper (purpose-built for root→user drop,
# correctly clears capabilities).  util-linux/setpriv is kept as a fallback.
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core utilities
    curl \
    git \
    gosu \
    iproute2 \
    iputils-ping \
    net-tools \
    procps \
    sudo \
    # Privilege drop helper — gosu is purpose-built for clean root→user drops
    # (correctly clears Linux capabilities; su-exec/setpriv do not reliably do so)
    # util-linux provides setpriv as a secondary fallback
    util-linux \
    # Firewall
    iptables \
    nftables \
    ufw \
    # Kernel hardening — mokutil manages UEFI Secure Boot keys
    mokutil \
    # NOTE: systemd (systemctl, systemd-analyze, journalctl) is intentionally
    # NOT installed — systemd does not function as an init system inside Docker.
    # The harden_host and log_management tools will report partial warnings for
    # these binaries; that is expected and unavoidable in a container environment.
    # Intrusion detection
    aide \
    chkrootkit \
    rkhunter \
    # Malware scanning
    clamav \
    clamav-daemon \
    yara \
    # Compliance — openscap-scanner provides the `oscap` CLI binary
    openscap-scanner \
    # Audit
    auditd \
    audispd-plugins \
    lynis \
    # Crypto tools — fix `crypto` tool warnings (openssl, gpg, cryptsetup)
    cryptsetup-bin \
    gnupg \
    openssl \
    # System hardening
    fail2ban \
    # SSH — openssh-server provides sshd (fixes access_control warning)
    openssh-client \
    openssh-server \
    # Log management — rsyslog fixes log_management warning
    rsyslog \
    # Mandatory Access Control helpers
    apparmor \
    selinux-utils \
    # Network tools
    nmap \
    tcpdump \
    # File integrity tools
    debsums \
    && rm -rf /var/lib/apt/lists/*

# Accept host user identity as build args.
# These MUST be passed at build time — no hardcoded defaults.
# Use scripts/setup-credentials.sh which passes them automatically, or:
#   docker build --build-arg HOST_USER=$(whoami) --build-arg HOST_UID=$(id -u) \
#                --build-arg HOST_GID=$(id -g) -t defense-mcp-server:latest .
ARG HOST_USER
ARG HOST_UID
ARG HOST_GID

# Validate that all required build args were provided
RUN : "${HOST_USER:?Build arg HOST_USER is required. Pass --build-arg HOST_USER=\$(whoami)}" && \
    : "${HOST_UID:?Build arg HOST_UID is required. Pass --build-arg HOST_UID=\$(id -u)}" && \
    : "${HOST_GID:?Build arg HOST_GID is required. Pass --build-arg HOST_GID=\$(id -g)}"

# Create a group and user matching the host user.
# The MCP Node.js process runs as this identity — same uid/gid as the host caller.
# NOTE: No NOPASSWD sudo — real password set at runtime via docker-entrypoint.sh
#
# node:22-slim ships with a 'node' user/group at UID/GID 1000.
# Remove any pre-existing account whose UID/GID conflicts with the target before
# creating the host-user account.  userdel -f removes home dir conflicts too.
RUN for conflicting_user in $(getent passwd "${HOST_UID}" | cut -d: -f1); do \
        userdel -f "$conflicting_user" 2>/dev/null || true; \
    done && \
    for conflicting_group in $(getent group "${HOST_GID}" | cut -d: -f1); do \
        groupdel "$conflicting_group" 2>/dev/null || true; \
    done && \
    groupadd -g ${HOST_GID} ${HOST_USER} && \
    useradd -u ${HOST_UID} -g ${HOST_GID} -m -s /bin/bash ${HOST_USER} && \
    usermod -aG sudo ${HOST_USER}

# Install scoped sudoers allowlist (password required for all commands).
# Source file is etc/sudoers.d/mcpuser; sed replaces 'mcpuser' with the
# actual runtime username so the allowlist applies to the correct account.
# This REPLACES the former 'NOPASSWD: ALL' grant — see etc/sudoers.d/mcpuser
COPY etc/sudoers.d/mcpuser /etc/sudoers.d/${HOST_USER}
RUN chmod 0440 /etc/sudoers.d/${HOST_USER} && \
    chown root:root /etc/sudoers.d/${HOST_USER} && \
    sed -i "s/mcpuser/${HOST_USER}/g" /etc/sudoers.d/${HOST_USER} && \
    visudo -c -f /etc/sudoers.d/${HOST_USER} && \
    echo "sudoers allowlist syntax validated for user: ${HOST_USER}"

# Disable OS-level sudo credential caching
# (SudoSession manages its own in-memory TTL; OS caching would allow
#  stale credentials to linger and is a security risk)
RUN printf 'Defaults timestamp_timeout=0\nDefaults log_output\n' \
        > /etc/sudoers.d/99-timestamp-zero && \
    chmod 0440 /etc/sudoers.d/99-timestamp-zero && \
    chown root:root /etc/sudoers.d/99-timestamp-zero

WORKDIR /app

# Copy package files first for layer caching
COPY package.json package-lock.json ./

# Install production dependencies only, skip lifecycle scripts (husky is a devDep and not present)
RUN npm ci --omit=dev --ignore-scripts

# Copy pre-built artifacts (run `npm run build` before `docker build`)
COPY build/ ./build/
COPY README.md CHANGELOG.md LICENSE ./
COPY docs/TOOLS-REFERENCE.md docs/SAFEGUARDS.md ./docs/

# Set ownership to the host-matching user
RUN chown -R ${HOST_USER}:${HOST_USER} /app

# Copy and configure the entrypoint script
# Runs as root to set the host user's password at startup, then drops to that user
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh && \
    chown root:root /usr/local/bin/docker-entrypoint.sh

# NOTE: Do NOT set 'USER' here — the entrypoint runs as root to set
# the password (from Docker secret or env var), then drops to MCP_USER via
# setpriv/su-exec. The final Node.js process runs as the unprivileged host user.

# MCP servers communicate via stdio — no port needed
# Environment variables for configuration
ENV NODE_ENV=production
ENV DEFENSE_MCP_DRY_RUN=false
ENV DEFENSE_MCP_AUTO_INSTALL=false
ENV DEFENSE_MCP_PREFLIGHT=true

# Bake the host username into the image so docker-entrypoint.sh knows which
# user account to set the password on and drop privileges to.
ENV MCP_USER=${HOST_USER}

# Health check — verify the process starts without error
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD node -e "require('./build/index.js')" 2>/dev/null || exit 1

# Entrypoint runs as root, sets the host user's password, then drops privileges
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["node", "build/index.js"]
