# Defense MCP Server

[![Smithery](https://smithery.ai/badge/@bottobot/defense-mcp-server)](https://smithery.ai/server/@bottobot/defense-mcp-server)
[![npm version](https://img.shields.io/npm/v/defense-mcp-server)](https://www.npmjs.com/package/defense-mcp-server)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**31 defensive security tools. 250+ actions. One MCP server.**

A Model Context Protocol (MCP) server that gives AI assistants access to **31 defensive security tools** (with 250+ actions) on Linux. Connect it to Claude Desktop, Cursor, Smithery, or any MCP-compatible client to harden systems, manage firewalls, scan for vulnerabilities, and enforce compliance — all through natural language conversation.

##**The Story Of This Thing**##
I started experimenting with Kali and I had a weird thought that if someone ever gained control of that system they could do some damage in my network. I found it came with all sorts of interesting defensive tools besides the obvious offensive ones and so I started messing around with automating the hardening process. Eventually I left Kali to the hackers and just switched to a Debian 13 vanilla type setup on my daily driver. All those hacker tools just made me nervous! However I have spent an incredible amount of time learning about system security on Linux building this thing and I think its ready to see the light of day for others to use. 

Please don't hesitate to leave feedback or if you think there's a good tool I should include. 

## Testing So Far ##
So my stack for this that I've tested is VS Codium on Kali and Debian 13 using Roo Code and Claude Code using Anthropic Models. I gotta say I'm pretty happy with how well it does. I've really tried to get it to be a simple all-in-one hardening tool that'll at least plug the major gaps in anyones system. If you're using API's then its really gonna chug down some tokens so be warned. It did go through a few rounds of token efficiecny optimisation but it'll eat em up like their Girl Guides Thin Mint cookies. 

---

## Install via Smithery

The fastest way to get started — no clone, no build:

```bash
npx -y @smithery/cli install @bottobot/defense-mcp-server --client claude
```

Or connect directly via the hosted server:

```
https://server.defensemcp.net/mcp
```

---

## Why I Made This

I got tired of hardening my new systems by hand every time I spun up a new one so I made this MCP server to make it pretty easy. I jam packed as many security tools as I could into this thwing so be prepared to burn tokens using it. Hopefully it helps you about half as much as its helped me.

## So What It Does

This server exposes Linux security tools as MCP tools that an AI assistant can invoke on your behalf. Instead of memorizing command syntax for dozens of security utilities, you describe what you want in plain English and the assistant calls the right tool with the right parameters. Sounds pretty good right?

Here are the tools:

| Module | What It Does |
|--------|-------------|
| **Firewall** | Manage iptables, nftables, and UFW rules |
| **Hardening** | Apply sysctl settings, file permissions, kernel security, USB device control |
| **Compliance** | Run CIS benchmarks, HIPAA/SOC2/ISO27001 checks |
| **Patch Management** | Check for updates, apply patches, track CVEs |
| **Access Control** | Configure SSH, PAM, user account policies |
| **Malware** | Scan with ClamAV, manage quarantine, deploy YARA rules |
| **File Integrity** | AIDE, rootkit detection, file hashing, drift baselines |
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
| **Supply Chain** | SBOM generation, package integrity verification |
| **Zero Trust Network** | WireGuard tunnels, mTLS, microsegmentation |
| **App Hardening** | Harden Apache, Nginx, MySQL, PostgreSQL, Docker |
| **Sudo Management** | Manage sudo elevation, session tracking |
| **Meta/Workflow** | Security posture assessment, defense workflows, auto-remediation |
| **DNS Security** | DNSSEC validation, tunneling detection, domain blocklists, query log analysis |
| **Vulnerability Management** | nmap/nikto scanning, vulnerability lifecycle tracking, risk prioritization |
| **Process Security** | Capability auditing, namespace isolation, anomaly detection |
| **WAF Management** | ModSecurity audit/rules, OWASP CRS deployment, rate limiting |
| **Threat Intelligence** | IP/hash/domain checks against feeds, blocklist application |
| **Cloud Security** | AWS/GCP/Azure detection, IMDS security, IAM credential scanning |
| **API Security** | Local API discovery, auth auditing, rate-limit testing, CORS checking |
| **Deception/Honeypots** | Canary token deployment, honeyport listeners, trigger monitoring |
| **Wireless Security** | Bluetooth/WiFi auditing, rogue AP detection, interface disabling |

### Safety Guardrails

Every tool runs with safety guardrails — you won't blow up your box:

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
- **Node.js 22+**
- **npm 9+**

## System Dependencies

Most tools will be auto-installed on first use, but you can pre-install everything for faster startup:

### Standard Packages (apt)

```bash
sudo apt-get install -y \
  aide rkhunter chkrootkit clamav clamav-daemon lynis auditd \
  nmap tcpdump nftables fail2ban apparmor apparmor-utils \
  libpam-pwquality suricata bpftool gitleaks cosign checksec \
  wireguard-tools debsums acct uidmap inotify-tools sysstat \
  htop strace logrotate openssl gnupg cryptsetup curl lsof
```

### Third-Party Tools

These are **not available** in standard Debian/Ubuntu repos. The instructions below avoid piping remote scripts into a shell (`curl | sh`) — each binary is downloaded, verified, and installed as a discrete step.

> **Note:** The MCP server can auto-install these tools for you when `DEFENSE_MCP_AUTO_INSTALL=true` (the default). It uses GPG fingerprint and SHA256 verification internally. The manual steps below are for pre-installation or air-gapped environments.

#### Falco (eBPF runtime security)

```bash
# Import GPG key and verify fingerprint
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc -o /tmp/falco.asc
gpg --show-keys /tmp/falco.asc  # Verify: 478B 2FBB C75F 4237 B731 DA43 6510 6822 B35B 1B1F
sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg /tmp/falco.asc
rm /tmp/falco.asc

# Add signed repo and install
echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" \
  | sudo tee /etc/apt/sources.list.d/falcosecurity.list
sudo apt-get update && sudo apt-get install -y falco
```

#### Trivy (container image scanning)

```bash
# Import GPG key and verify fingerprint
curl -fsSL https://aquasecurity.github.io/trivy-repo/deb/public.key -o /tmp/trivy.asc
gpg --show-keys /tmp/trivy.asc  # Verify: 2E2D 3567 4616 32C8 4BB6 CD6F E9D0 A361 6276 FA6C
sudo gpg --dearmor -o /usr/share/keyrings/trivy-archive-keyring.gpg /tmp/trivy.asc
rm /tmp/trivy.asc

# Add signed repo and install
echo "deb [signed-by=/usr/share/keyrings/trivy-archive-keyring.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
  | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install -y trivy
```

#### Grype (vulnerability scanning)

```bash
VERSION=v0.110.0
curl -fsSL -o /tmp/grype.tar.gz \
  "https://github.com/anchore/grype/releases/download/${VERSION}/grype_${VERSION#v}_linux_amd64.tar.gz"
curl -fsSL -o /tmp/grype.tar.gz.sha256 \
  "https://github.com/anchore/grype/releases/download/${VERSION}/grype_${VERSION#v}_checksums.txt"

# Verify checksum
cd /tmp && grep "linux_amd64.tar.gz" grype.tar.gz.sha256 | sha256sum -c -
tar xzf grype.tar.gz grype && sudo install grype /usr/local/bin/grype
rm -f /tmp/grype /tmp/grype.tar.gz /tmp/grype.tar.gz.sha256
```

#### Syft (SBOM generation)

```bash
VERSION=v1.42.3
curl -fsSL -o /tmp/syft.tar.gz \
  "https://github.com/anchore/syft/releases/download/${VERSION}/syft_${VERSION#v}_linux_amd64.tar.gz"
curl -fsSL -o /tmp/syft_checksums.txt \
  "https://github.com/anchore/syft/releases/download/${VERSION}/syft_${VERSION#v}_checksums.txt"

# Verify checksum
cd /tmp && grep "linux_amd64.tar.gz" syft_checksums.txt | sha256sum -c -
tar xzf syft.tar.gz syft && sudo install syft /usr/local/bin/syft
rm -f /tmp/syft /tmp/syft.tar.gz /tmp/syft_checksums.txt
```

#### TruffleHog (secret scanning)

```bash
VERSION=v3.94.1
curl -fsSL -o /tmp/trufflehog.tar.gz \
  "https://github.com/trufflesecurity/trufflehog/releases/download/${VERSION}/trufflehog_${VERSION#v}_linux_amd64.tar.gz"
curl -fsSL -o /tmp/trufflehog_checksums.txt \
  "https://github.com/trufflesecurity/trufflehog/releases/download/${VERSION}/trufflehog_${VERSION#v}_checksums.txt"

# Verify checksum
cd /tmp && grep "linux_amd64.tar.gz" trufflehog_checksums.txt | sha256sum -c -
tar xzf trufflehog.tar.gz trufflehog && sudo install trufflehog /usr/local/bin/trufflehog
rm -f /tmp/trufflehog /tmp/trufflehog.tar.gz /tmp/trufflehog_checksums.txt
```

#### slsa-verifier (supply chain verification)

```bash
VERSION=v2.7.1
curl -fsSL -o /tmp/slsa-verifier \
  "https://github.com/slsa-framework/slsa-verifier/releases/download/${VERSION}/slsa-verifier-linux-amd64"
curl -fsSL -o /tmp/slsa-verifier.sha256 \
  "https://github.com/slsa-framework/slsa-verifier/releases/download/${VERSION}/slsa-verifier-linux-amd64.sha256"

# Verify checksum
cd /tmp && echo "$(cat slsa-verifier.sha256)  slsa-verifier" | sha256sum -c -
sudo install slsa-verifier /usr/local/bin/slsa-verifier
rm -f /tmp/slsa-verifier /tmp/slsa-verifier.sha256
```

#### cdxgen (CycloneDX SBOM generation)

```bash
npm install -g @cyclonedx/cdxgen
```

### Important Notes

- **`snort` → `suricata`**: Snort has been **removed from Debian Trixie (13+)** repositories. Suricata is the recommended IDS replacement and is available in standard repos.
- **`ufw` vs `nftables`**: UFW **conflicts with `iptables-persistent`** — they cannot coexist on the same system. For modern Debian systems, prefer `nftables` (the `nft` command) for firewall management.
- **`bpftool`**: On Debian Trixie, install the `bpftool` package directly (NOT `linux-tools-generic` which is Ubuntu-specific).
- **`pam_pwquality`**: This is a PAM module (`libpam-pwquality`), not a standalone binary. Install via `apt-get install libpam-pwquality`.

## Quick Start

### Step 1: Install the server

Pick one method:

**npm (recommended):**
```bash
npm install -g defense-mcp-server
```

**Or clone and build from source:**
```bash
git clone https://github.com/bottobot/defense-mcp-server.git
cd defense-mcp-server
npm install && npm run build
```

### Step 2: Connect to your AI client

The server supports any MCP client. Pick your client below and add the configuration:

**Claude Code (CLI / VS Code / JetBrains):**

Create a `.mcp.json` file in your project root (or `~/.claude/` for global):
```json
{
  "mcpServers": {
    "defense-mcp-server": {
      "command": "defense-mcp-server",
      "env": {
        "DEFENSE_MCP_DRY_RUN": "true",
        "DEFENSE_MCP_ALLOWED_DIRS": "/tmp,/home,/var/log"
      }
    }
  }
}
```

**Claude Desktop:**

Edit `~/.config/claude/claude_desktop_config.json` (Linux) or `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):
```json
{
  "mcpServers": {
    "defense-mcp-server": {
      "command": "defense-mcp-server"
    }
  }
}
```
Restart Claude Desktop. The server will appear in the MCP tools panel.

**Cursor / Other MCP clients:**
```json
{
  "mcpServers": {
    "defense-mcp-server": {
      "command": "defense-mcp-server"
    }
  }
}
```

**If you cloned and built from source**, replace `"defense-mcp-server"` in the command field with:
```json
"command": "node",
"args": ["/path/to/defense-mcp-server/build/index.js"]
```

### Step 3: Verify it works

Open your AI client and ask:

> "Check my firewall status"

The assistant should call the `firewall` tool and return your iptables/UFW rules. If it does, you're all set.

### Step 4: Elevate when needed

Most audit tools (listing firewall rules, checking patches, reading logs) work without sudo. When a tool needs elevated privileges, the server will tell you. Elevate securely:

> "Elevate sudo with GUI dialog"

This opens a native password dialog (zenity/kdialog) — your password never passes through the AI conversation. The session auto-expires after 15 minutes, or you can drop it anytime:

> "Drop sudo privileges"

### What happens on first run

1. **Dry-run mode is on by default** — tools preview what they would do without changing anything
2. **Missing tools are auto-installed** — if you ask for a malware scan but ClamAV isn't installed, the server installs it via apt/dnf automatically
3. **All file access is restricted** — only `/tmp`, `/home`, and `/var/log` are accessible by default

To enable live changes (not just previews), set `DEFENSE_MCP_DRY_RUN=false` in the env config above.

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
| `MCP_TRANSPORT` | `stdio` | Transport mode: `stdio` or `http` |
| `MCP_PORT` | `3100` | HTTP server port (when `MCP_TRANSPORT=http`) |

To apply changes for real (not just preview), set:
```bash
DEFENSE_MCP_DRY_RUN=false node build/index.js
```

## Security

A security tool that isn't secure itself is worse than useless. This server implements defense-in-depth across 10 layers, from configuration defaults down to cryptographic verification.

### MCP Specification Compliance

The [MCP spec](https://modelcontextprotocol.io/) defines security requirements for servers. Here's how this project meets them:

| MCP Requirement | Implementation |
|----------------|---------------|
| **Validate all tool inputs** | Zod schemas on every parameter + 15 specialized validators (paths, IPs, ports, service names, etc.) |
| **Implement access controls** | 200+ entry command allowlist, `shell: false` enforced, sudo session management |
| **Rate limit tool invocations** | 30/tool/min, 100 global/min, auth failure throttling (5 attempts per 5 minutes) |
| **Sanitize tool outputs** | Error sanitization strips paths, stack traces, and truncates to 500 chars |

### Layer 1: Safe Defaults

Everything is locked down out of the box. You have to explicitly opt in to making changes:

- **Dry-run mode on by default** — every tool previews what it would do before touching anything
- **Backups before changes** — system state is backed up automatically before any modification
- **Confirmation required** — destructive actions need explicit confirmation
- **Restricted directories** — the server can only access explicitly allowed paths; root `/`, `/etc`, `/usr`, `/bin`, `/sbin` are blocked by default
- **Protected paths** — system-critical files are blocked from modification regardless of directory config

### Layer 2: Command Execution

No tool can run arbitrary commands. Every command goes through multiple gates:

- **Binary allowlist** — 200+ pre-approved binaries across 18 categories. If a binary isn't on the list, it doesn't run. Period.
- **Absolute path resolution** — binaries are resolved to absolute paths at startup via `fs.existsSync()`, never through `which` or PATH
- **`shell: false` enforced** — hardcoded, cannot be overridden. Shell metacharacters (`;`, `|`, `&`, `` ` ``, `$`, etc.) have no effect
- **TOCTOU detection** — binary inodes are recorded at startup and verified before execution to detect replacement
- **No fallback** — if a binary can't be resolved to a known path, execution is refused entirely

### Layer 3: Input Validation

Every parameter is validated before it reaches any tool handler:

- **Zod schemas** — runtime type checking with string length limits, enum constraints, numeric ranges, array bounds
- **Path traversal protection** — `../` sequences rejected, null bytes blocked, symlinks resolved and re-validated
- **Shell metacharacter blocking** — `[;|&$\`(){}<>!\\\n\r]` stripped from all inputs
- **Control character rejection** — `[\x00-\x08\x0e-\x1f\x7f]` blocked
- **Specialized validators** for: targets (hostname/IP/CIDR), ports, service names, sysctl keys, package names, iptables chains, network interfaces, usernames, YARA rules, certificate paths, firewall zones, auditd keys
- **ReDoS protection** — regex patterns limited to 200 characters, nested quantifiers and excessive alternation rejected

### Layer 4: Sudo & Privilege Management

The server never asks for your password in a way an AI can see:

- **GUI elevation** — `sudo_elevate_gui` opens a native zenity/kdialog dialog. The password goes directly to sudo, never through the AI conversation
- **Buffer storage** — passwords are stored as Node.js Buffers (not V8 strings), which can be explicitly zeroed from memory
- **Auto-zeroing** — password buffer is zeroed on session drop, timeout expiry, and process exit
- **Credential validation** — password is tested with `sudo -S -k -v` before being accepted
- **Auth rate limiting** — 5 failed attempts per 5 minutes, then locked out
- **Session UID guard** — session is dropped immediately if the OS user ID changes
- **NOPASSWD:ALL rejection** — the sudoers management tool explicitly refuses to write `NOPASSWD: ALL` rules
- **`sudo -S` stdin piping** — passwords are piped via stdin, never passed as command-line arguments (which would be visible in `ps`)
- **40+ permission error patterns** — detected and surfaced with clear elevation prompts instead of cryptic failures

### Layer 5: Secure File Operations

Every file write is atomic and permission-hardened:

- **Atomic writes** — write to temp file, then rename. No partial writes, no corruption on crash
- **Owner-only permissions** — files created with `0o600`, directories with `0o700`
- **Explicit chmod** — permissions enforced independently of umask
- **Symlink protection** — real paths resolved and re-validated against allowed directories
- **Backup before modify** — timestamped backups with manifest tracking under `~/.defense-mcp/backups/`

### Layer 6: Encrypted State Storage

Sensitive runtime data is encrypted at rest:

- **Algorithm**: AES-256-GCM (authenticated encryption)
- **Key derivation**: PBKDF2 with 100,000 iterations, SHA-512
- **IV**: 96-bit (GCM-recommended)
- **Auth tag**: 128-bit
- **Salt**: 128-bit per file
- **Fallback**: plaintext JSON with warning when no key is configured (`DEFENSE_MCP_STATE_KEY`)

### Layer 7: Supply Chain Security

Auto-installed tools are verified, not blindly trusted:

- **System packages** — installed only via official package manager (apt/dnf/pacman)
- **pip allowlist** — only 9 pre-approved packages (yara-python, python-nmap, etc.)
- **npm allowlist** — only 2 pre-approved packages (cdxgen, snyk)
- **Third-party tools** (Falco, Trivy, Grype, Syft, TruffleHog, slsa-verifier):
  - Never uses `curl | sh` — all downloads verified before execution
  - SHA256 checksums hardcoded in manifest
  - GPG fingerprints verified against known-good values
  - Cosign verification where available
  - Requires explicit `DEFENSE_MCP_THIRD_PARTY_INSTALL=true` to enable

### Layer 8: Rate Limiting & Safeguards

Protection against runaway or abusive tool invocations:

- **Per-tool limit**: 30 invocations per 60 seconds
- **Global limit**: 100 invocations per 60 seconds
- **Running service detection** — detects VS Code, Docker, databases, web servers, MCP servers, SSH sessions before operations that could affect them
- **Pre-flight validation** — every tool checks dependencies, privileges, and safeguards before executing

### Layer 9: Audit Trail & Rollback

Every change is recorded and reversible:

- **Structured changelog** — JSON entries with tool name, action, target, before/after values, timestamp
- **Rollback commands** — stored with each change, validated against command allowlist
- **Structured logging** — JSON-formatted security events to stderr with file rotation (10 MB, 5 files)
- **Security log level** — critical events always logged regardless of log level setting

### Layer 10: Policy Engine

Hardening policies are enforced safely:

- **No shell interpreters** — policy check and remediation commands use direct binary invocation only
- **Regex safety** — pattern length limits (200 chars), nested quantifier rejection
- **Severity classification** — critical, high, medium, low, info
- **Secure policy storage** — policy files created with `0o700` directory permissions

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

- **2,048+ tests** across 62 test files
- Every source module (core + tools) has a corresponding test file
- Coverage enforced in CI pipeline

## License

MIT — see [LICENSE](LICENSE)
