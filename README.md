# Defense MCP Server

A Model Context Protocol (MCP) server that gives AI assistants access to 78 defensive security tools on Kali Linux. Connect it to Claude Desktop, Cursor, or any MCP-compatible client to harden systems, manage firewalls, scan for vulnerabilities, and enforce compliance — all through natural language conversation.

## What It Does

This server exposes Linux security tools as MCP tools that an AI assistant can invoke on your behalf. Instead of memorizing command syntax for dozens of security utilities, you describe what you want in plain English and the assistant calls the right tool with the right parameters.

The 78 tools are organized into 21 modules:

| Module | What It Does |
|--------|-------------|
| **Firewall** | Manage iptables, nftables, and UFW rules |
| **Hardening** | Apply sysctl settings, file permissions, kernel security |
| **Compliance** | Run CIS benchmarks, HIPAA/SOC2/ISO27001 checks |
| **Patch Management** | Check for updates, apply patches, track CVEs |
| **Access Control** | Configure SSH, PAM, user account policies |
| **Malware** | Scan with ClamAV, manage quarantine, deploy YARA rules |
| **IDS** | Configure AIDE, Falco, rootkit detection |
| **Logging** | Set up auditd rules, log rotation, fail2ban |
| **Encryption** | Manage TLS certificates, LUKS volumes, GPG keys |
| **Backup** | Create and restore system state snapshots |
| **Container Security** | AppArmor profiles, seccomp policies, image scanning |
| **Network Defense** | Packet capture, connection monitoring, port scanning |
| **Secrets** | Scan for leaked credentials, audit SSH keys |
| **Incident Response** | Collect forensic evidence, timeline analysis |
| **eBPF Security** | Deploy Falco rules, list eBPF programs |
| **Drift Detection** | Track configuration changes against baselines |
| **Supply Chain** | SBOM generation, package integrity verification |
| **Zero Trust Network** | WireGuard tunnels, mTLS, microsegmentation |
| **App Hardening** | Harden Apache, Nginx, MySQL, PostgreSQL, Docker |
| **Sudo Management** | Manage sudo elevation, session tracking |
| **Meta/Workflow** | Security posture assessment, defense workflows |

Every tool runs with safety guardrails:
- **Dry-run by default** — tools preview what they would do before making changes
- **Command allowlist** — only pre-approved binaries can execute (no shell interpreters)
- **Input sanitization** — all parameters validated against injection attacks
- **Backup before changes** — system state backed up before modifications
- **Rate limiting** — prevents runaway tool invocations

## Automatic Tool Installation

You don't need to pre-install every security tool. The server automatically detects missing dependencies and installs them when needed.

**How it works:**

1. Each tool declares which system binaries it requires (e.g., `firewall_status` needs `iptables` or `ufw`)
2. Before executing a tool, the server checks if the required binary is installed
3. If it's missing, the server installs it using your system's package manager (`apt` on Kali/Debian, `dnf` on RHEL, `pacman` on Arch)
4. The tool then runs normally

**Example:** If you ask the assistant to scan for malware but ClamAV isn't installed, the server will run `apt install clamav` automatically, then proceed with the scan.

**Security controls on auto-installation:**

- System packages are installed via the official package manager only
- npm/pip packages are restricted to a hardcoded allowlist (e.g., `yara-python`, `cdxgen`) — arbitrary packages cannot be installed
- Auto-installation requires sudo privileges — if running without elevated access, the server will report what needs to be installed manually
- All installation actions are logged

To disable auto-installation entirely, run with:
```bash
KALI_DEFENSE_AUTO_INSTALL=false node dist/index.js
```

## Requirements

- **Kali Linux** (or Debian-based Linux with security tools installed)
- **Node.js 20+**
- **npm 9+**

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/YOUR_GITHUB_USERNAME/defense-mcp-server.git
   cd defense-mcp-server
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Build:
   ```bash
   npm run build
   ```

## Connecting to Claude Desktop

Add this to your Claude Desktop configuration file (`~/.config/claude/claude_desktop_config.json` on Linux):

```json
{
  "mcpServers": {
    "defense-mcp-server": {
      "command": "node",
      "args": ["/path/to/defense-mcp-server/dist/index.js"]
    }
  }
}
```

Replace `/path/to/` with the actual path where you cloned the repo.

Restart Claude Desktop. The server will appear in the MCP tools panel.

## Connecting to Other MCP Clients

Any MCP client that supports stdio transport can connect. The server communicates over stdin/stdout using the MCP protocol. Launch it with:

```bash
node dist/index.js
```

## Usage Examples

Once connected, talk to your AI assistant naturally:

- **"Check my firewall status"** → calls `firewall_status`
- **"Harden SSH to disable root login and password auth"** → calls `access_ssh` with appropriate settings
- **"Run a CIS benchmark on this system"** → calls `compliance_check` with CIS framework
- **"Scan /var/www for malware"** → calls `malware_scan` on the specified path
- **"Show me what patches are available"** → calls `patch_check`
- **"Create a backup before I make changes"** → calls `backup_state_snapshot`
- **"Set up fail2ban for SSH"** → calls `log_fail2ban` to configure jail

The assistant handles parameter construction, error interpretation, and follow-up actions automatically.

## Configuration

Configuration is via environment variables. All have secure defaults:

| Variable | Default | Description |
|----------|---------|-------------|
| `KALI_DEFENSE_DRY_RUN` | `true` | Preview changes without applying |
| `KALI_DEFENSE_REQUIRE_CONFIRMATION` | `true` | Require confirmation for destructive actions |
| `KALI_DEFENSE_ALLOWED_DIRS` | `/tmp,/home,/var/log` | Directories the server can access |
| `KALI_DEFENSE_LOG_LEVEL` | `info` | Log verbosity (debug/info/warn/error) |
| `KALI_DEFENSE_BACKUP_ENABLED` | `true` | Auto-backup before system changes |
| `KALI_DEFENSE_AUTO_INSTALL` | `true` | Auto-install missing tool dependencies |

To apply changes for real (not just preview), set:
```bash
KALI_DEFENSE_DRY_RUN=false node dist/index.js
```

## Security

This server is designed to be safe by default:

- Commands execute with `shell: false` — no shell interpretation
- All binaries resolved against a 153-entry allowlist at startup
- Input validated with Zod schemas before execution
- Passwords handled as Buffers (zeroed after use, never logged)
- Rate limited to prevent abuse (30/tool/min, 100 global/min)
- All file writes go through secure-fs with audit trail

For the full security architecture, see [ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Development

```bash
# Run tests
npm test

# Run with coverage
npm run test -- --coverage

# Type check
npm run build:verify

# Security lint
npm run lint:security
```

## License

MIT — see [LICENSE](LICENSE)
