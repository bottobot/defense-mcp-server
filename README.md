# Defense MCP Server

A Model Context Protocol (MCP) server that gives AI assistants access to **94 defensive security tools** on Linux. Connect it to Claude Desktop, Cursor, or any MCP-compatible client to harden systems, manage firewalls, scan for vulnerabilities, and enforce compliance — all through natural language conversation.

## Why I Made This
Basically I'm a total noob when it comes to really serious system hardening so I thought I'd test the latest LLM models and see how far I could get. Turns out they're pretty helpful! I got tired of hardening my new systems by hand every time I spun up a new one so I made this MCP server to make it pretty easy. I jam packed as many security tools as I could into this thing so be prepared to burn tokens using it. Hopefully it helps you about half as much as its helped me. 

## So What It Does

This server exposes Linux security tools as MCP tools that an AI assistant can invoke on your behalf. Instead of memorizing command syntax for dozens of security utilities, you describe what you want in plain English and the assistant calls the right tool with the right parameters. Sounds pretty good right!

Here are the tools:

| Module | What It Does |
|--------|-------------|
| **Firewall** | Manage iptables, nftables, and UFW rules |
| **Hardening** | Apply sysctl settings, file permissions, kernel security, USB device control |
| **Compliance** | Run CIS benchmarks, HIPAA/SOC2/ISO27001 checks |
| **Patch Management** | Check for updates, apply patches, track CVEs |
| **Access Control** | Configure SSH, PAM, user account policies |
| **Malware** | Scan with ClamAV, manage quarantine, deploy YARA rules |
| **IDS** | Configure AIDE, Falco, rootkit detection |
| **Logging** | Set up auditd rules, log rotation, fail2ban |
| **Encryption** | Manage TLS certificates, LUKS volumes, GPG keys |
| **Certificate Lifecycle** | Inventory certs, check renewal, audit CA trust store, OCSP, CT logs |
| **Backup** | Create and restore system state snapshots |
| **Container Security** | AppArmor profiles, seccomp policies, image scanning |
| **Network Defense** | Packet capture, connection monitoring, port scanning |
| **Network Segmentation** | Map zones, verify isolation, test paths, audit VLANs |
| **Secrets** | Scan for leaked credentials, audit SSH keys |
| **Incident Response** | Collect volatile evidence, IOC scan, filesystem timeline |
| **Forensics** | Memory dumps, disk imaging, evidence chain of custody |
| **eBPF Security** | Deploy Falco rules, list eBPF programs |
| **Drift Detection** | Track configuration changes against baselines |
| **Supply Chain** | SBOM generation, package integrity verification |
| **Zero Trust Network** | WireGuard tunnels, mTLS, microsegmentation |
| **App Hardening** | Harden Apache, Nginx, MySQL, PostgreSQL, Docker |
| **Sudo Management** | Manage sudo elevation, session tracking |
| **Meta/Workflow** | Security posture assessment, defense workflows, auto-remediation |
| **Reporting** | Generate consolidated security reports (Markdown/HTML/JSON/CSV) |
| **DNS Security** | DNSSEC validation, tunneling detection, domain blocklists, query log analysis |
| **Vulnerability Management** | nmap/nikto scanning, vulnerability lifecycle tracking, risk prioritization |
| **Process Security** | Capability auditing, namespace isolation, anomaly detection |
| **WAF Management** | ModSecurity audit/rules, OWASP CRS deployment, rate limiting |
| **Threat Intelligence** | IP/hash/domain checks against feeds, blocklist application |
| **Cloud Security** | AWS/GCP/Azure detection, IMDS security, IAM credential scanning |
| **API Security** | Local API discovery, auth auditing, rate-limit testing, CORS checking |
| **Deception/Honeypots** | Canary token deployment, honeyport listeners, trigger monitoring |
| **Wireless Security** | Bluetooth/WiFi auditing, rogue AP detection, interface disabling |
| **SIEM Integration** | rsyslog/Filebeat configuration, log forwarding audit, connectivity testing |

Every tool runs with safety guardrails:
- **Dry-run by default** — tools preview what they would do before making changes
- **Command allowlist** — only pre-approved binaries can execute (no shell interpreters)
- **Input sanitization** — all parameters validated against injection attacks
- **Backup before changes** — system state backed up before modifications
- **Rate limiting** — prevents runaway tool invocations

## Automatic Tool Installation

You don't need to pre-install every security tool. The server automatically detects missing dependencies and installs them when needed.

**How it works:**

1. Each tool declares which system binaries it requires (e.g., `firewall_iptables` needs `iptables` or `ufw`)
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
DEFENSE_MCP_AUTO_INSTALL=false node build/index.js
```

## Requirements

- **Linux** (Kali, Debian, Ubuntu, RHEL, Arch, or any systemd-based distro)
- **Node.js 18+**
- **npm 9+**

## Installation

### Option A: npm (recommended)

```bash
npm install -g defense-mcp-server
```

### Option B: Clone and build

1. Clone the repository:
   ```bash
   git clone https://github.com/bottobot/defense-mcp-server.git
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

**If installed globally via npm:**
```json
{
  "mcpServers": {
    "defense-mcp-server": {
      "command": "defense-mcp-server"
    }
  }
}
```

**If cloned and built locally:**
```json
{
  "mcpServers": {
    "defense-mcp-server": {
      "command": "node",
      "args": ["/path/to/defense-mcp-server/build/index.js"]
    }
  }
}
```

Replace `/path/to/` with the actual path where you cloned the repo.

Restart Claude Desktop. The server will appear in the MCP tools panel.

## Connecting to Other MCP Clients

Any MCP client that supports stdio transport can connect. The server communicates over stdin/stdout using the MCP protocol. Launch it with:

```bash
node build/index.js
```

## Usage Examples

Once connected, talk to your AI assistant naturally:

- **"Check my firewall status"** → calls `firewall_iptables` with `action: list`
- **"Harden SSH to disable root login and password auth"** → calls `access_ssh` with harden action and appropriate settings
- **"Run a CIS benchmark on this system"** → calls `compliance_check` with CIS framework
- **"Scan /var/www for malware"** → calls `malware_clamav` on the specified path
- **"Show me what patches are available"** → calls `patch_update_audit`
- **"Create a backup before I make changes"** → calls `backup` with state action
- **"Set up fail2ban for SSH"** → calls `log_fail2ban` to configure jail
- **"Check if any cloud credentials are exposed"** → calls `cloud_security` with `check_iam_creds`
- **"Detect rogue access points on the network"** → calls `wireless_security` with `rogue_ap_detect`
- **"Generate a security report"** → calls `report_export` with generate action

The assistant handles parameter construction, error interpretation, and follow-up actions automatically.

## Sudo Elevation

Many tools require elevated privileges. The server provides a secure sudo management system:

- **`sudo_elevate`** — provide your password once; it's stored in a zeroable Buffer (never logged)
- **`sudo_elevate_gui`** — use a native GUI dialog (zenity/kdialog) so the password is never visible to the AI
- **`sudo_status`** — check if the session is currently elevated
- **`sudo_drop`** — immediately zero the cached password and drop elevation
- **`sudo_extend`** — extend the session timeout without re-entering the password
- **`preflight_batch_check`** — check multiple tools' sudo requirements before running them

## Configuration

Configuration is via environment variables. All have secure defaults:

| Variable | Default | Description |
|----------|---------|-------------|
| `DEFENSE_MCP_DRY_RUN` | `true` | Preview changes without applying |
| `DEFENSE_MCP_REQUIRE_CONFIRMATION` | `true` | Require confirmation for destructive actions |
| `DEFENSE_MCP_ALLOWED_DIRS` | `/tmp,/home,/var/log` | Directories the server can access |
| `DEFENSE_MCP_LOG_LEVEL` | `info` | Log verbosity (debug/info/warn/error) |
| `DEFENSE_MCP_BACKUP_ENABLED` | `true` | Auto-backup before system changes |
| `DEFENSE_MCP_AUTO_INSTALL` | `true` | Auto-install missing tool dependencies |
| `DEFENSE_MCP_PREFLIGHT` | `true` | Enable pre-flight dependency checks |
| `DEFENSE_MCP_PREFLIGHT_BANNERS` | `true` | Show pre-flight status in tool output |

To apply changes for real (not just preview), set:
```bash
DEFENSE_MCP_DRY_RUN=false node build/index.js
```

## Security

This server is designed to be safe by default:

- Commands execute with `shell: false` — no shell interpretation
- All binaries resolved against a 190-entry allowlist at startup
- Input validated with Zod schemas before execution
- Passwords handled as Buffers (zeroed after use, never logged)
- Rate limited to prevent abuse (30/tool/min, 100 global/min)
- All file writes go through secure-fs with audit trail
- Encrypted state storage (AES-256-GCM) for sensitive runtime data
- Atomic file writes (write-to-temp-then-rename) to prevent corruption

For the full security architecture, see [ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Development

```bash
# Run tests
npm test

# Run with coverage
npm run test:coverage

# Type check
npm run build:verify

# Security lint
npm run lint:security

# Security audit
npm run audit:security
```

## Test Coverage

- **1,801+ tests** across 60+ test files
- Every source module (core + tools) has a corresponding test file
- Coverage enforced in CI pipeline

## License

MIT — see [LICENSE](LICENSE)
