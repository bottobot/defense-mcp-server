# Defense MCP Server — Docker Image
# Builds from local source since this is the development copy.
# For production: replace the COPY/build steps with: RUN npm install -g defense-mcp-server

FROM node:22-slim

LABEL org.opencontainers.image.title="defense-mcp-server"
LABEL org.opencontainers.image.description="Defensive security MCP server — 94 tools for system hardening"
LABEL org.opencontainers.image.version="0.7.0"
LABEL org.opencontainers.image.licenses="MIT"

# Install Linux security tools that the MCP server wraps
# util-linux provides setpriv for privilege drop in the entrypoint
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core utilities
    sudo \
    procps \
    iproute2 \
    net-tools \
    iputils-ping \
    # Privilege drop helper (setpriv is part of util-linux, standard on Debian)
    util-linux \
    # Firewall
    iptables \
    nftables \
    ufw \
    # Intrusion detection
    rkhunter \
    chkrootkit \
    aide \
    # Malware scanning
    clamav \
    clamav-daemon \
    # Audit
    auditd \
    audispd-plugins \
    lynis \
    # System hardening
    fail2ban \
    # SSH
    openssh-client \
    # Network tools
    nmap \
    tcpdump \
    # File tools
    debsums \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for the server process
# NOTE: No NOPASSWD sudo — real password set at runtime via docker-entrypoint.sh
RUN groupadd --gid 1001 mcpuser && \
    useradd --uid 1001 --gid mcpuser --shell /bin/bash --create-home mcpuser

# Install scoped sudoers allowlist (password required for all commands)
# This REPLACES the former 'NOPASSWD: ALL' grant — see etc/sudoers.d/mcpuser
COPY etc/sudoers.d/mcpuser /etc/sudoers.d/mcpuser
RUN chmod 0440 /etc/sudoers.d/mcpuser && \
    chown root:root /etc/sudoers.d/mcpuser && \
    visudo -c -f /etc/sudoers.d/mcpuser && \
    echo "sudoers allowlist syntax validated"

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

# Set ownership
RUN chown -R mcpuser:mcpuser /app

# Copy and configure the entrypoint script
# Runs as root to set mcpuser password at startup, then drops to mcpuser via setpriv
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh && \
    chown root:root /usr/local/bin/docker-entrypoint.sh

# NOTE: Do NOT set 'USER mcpuser' here — the entrypoint runs as root to set
# the password (from Docker secret or env var), then drops to mcpuser via
# setpriv/su-exec. The final Node.js process runs as unprivileged mcpuser.

# MCP servers communicate via stdio — no port needed
# Environment variables for configuration
ENV NODE_ENV=production
ENV KALI_DEFENSE_DRY_RUN=false
ENV KALI_DEFENSE_AUTO_INSTALL=false
ENV KALI_DEFENSE_PREFLIGHT=true

# Health check — verify the process starts without error
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD node -e "require('./build/index.js')" 2>/dev/null || exit 1

# Entrypoint runs as root, sets mcpuser password, then drops privileges
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["node", "build/index.js"]
