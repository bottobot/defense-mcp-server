# defense-mcp-server — Technical Specification

## Metadata

| Field | Value |
|-------|-------|
| **Name** | defense-mcp-server |
| **Version** | 0.6.0 |
| **Language** | TypeScript 5.9+ |
| **Target** | ES2022 |
| **Module System** | Node16 (ESM with `.js` extensions in imports) |
| **Runtime** | Node.js ≥ 18 |
| **Framework** | `@modelcontextprotocol/sdk` 1.27.1 |
| **Validation** | `zod` 3.25.76 |
| **Runtime Dependencies** | 2 (`@modelcontextprotocol/sdk`, `zod`) |
| **Transport** | stdio (StdioServerTransport) |
| **OS** | Linux only |
| **License** | MIT |
| **Repository** | `github.com/YOUR_GITHUB_USERNAME/defense-mcp-server` |

---

## 1. Overview

The defense-mcp-server is a Model Context Protocol (MCP) server that exposes **94 defensive security tools** across **32 modules**, backed by **26 core modules**. It enables AI agents (Claude, Roo Code, etc.) to perform system hardening, compliance auditing, intrusion detection, malware scanning, firewall management, container security, secrets scanning, drift detection, zero-trust networking, eBPF security monitoring, cloud security, API security, threat intelligence, WAF management, wireless security, and incident response on Linux systems.

The server runs as a child process communicating over stdio JSON-RPC. It wraps Linux security binaries (iptables, lynis, aide, rkhunter, ClamAV, etc.) with input validation, command allowlist enforcement, privilege management, rate limiting, structured logging, and audit trails.

### Key Metrics

| Metric | Value |
|--------|-------|
| Tool count | 78 |
| Tool modules (`src/tools/`) | 21 files |
| Core modules (`src/core/`) | 26 files |
| Test files | 47 |
| Test count | 873 |
| Runtime dependencies | 2 |
| Allowlisted binaries | 115 |

### Security Model Summary

All commands execute with `shell: false`. Every binary must be in a static allowlist resolved to absolute paths at startup with runtime TOCTOU re-verification. Passwords are stored in zeroable Buffers, never V8 strings. All state files are written with `0o600`/`0o700` permissions via [`secure-fs.ts`](src/core/secure-fs.ts). Dry-run is the default for all mutating operations. Every change is logged to an append-only changelog with before/after state and rollback metadata. Rate limiting protects against both per-tool and global abuse. Structured JSON logging to stderr with a dedicated `security` event level ensures audit trail integrity.

---

## 2. Architecture

### 2.1 Module Map

```
src/
├── index.ts                    — Entry point: startup sequence, tool registration
├── core/                       — 26 core modules
│   ├── executor.ts             — Safe command execution (spawn, shell:false, timeouts)
│   ├── spawn-safe.ts           — Low-level spawn layer (no circular deps)
│   ├── command-allowlist.ts    — Binary allowlist with path resolution & TOCTOU verification
│   ├── config.ts               — Environment-based configuration with defaults
│   ├── safeguards.ts           — Application detection + safety checking
│   ├── tool-registry.ts        — ToolManifest registry (78 entries)
│   ├── tool-wrapper.ts         — Proxy-based McpServer middleware
│   ├── policy-engine.ts        — Compliance policy evaluation with Zod + ReDoS protection
│   ├── backup-manager.ts       — File backup with manifest tracking
│   ├── rollback.ts             — Change tracking with rollback capability
│   ├── changelog.ts            — Versioned audit trail (JSON, append-only)
│   ├── sanitizer.ts            — Input validation (14 validators)
│   ├── secure-fs.ts            — Permission-enforcing file I/O (0o600/0o700)
│   ├── sudo-session.ts         — Password Buffer lifecycle, elevation, expiry
│   ├── sudo-guard.ts           — Permission error detection + elevation prompts
│   ├── privilege-manager.ts    — UID/capability/sudo status detection
│   ├── preflight.ts            — Pre-flight validation pipeline
│   ├── auto-installer.ts       — Multi-package-manager dependency resolver
│   ├── installer.ts            — DEFENSIVE_TOOLS catalog with package mappings
│   ├── dependency-validator.ts — Binary availability checking
│   ├── distro.ts               — Linux distribution detection
│   ├── distro-adapter.ts       — Cross-distro abstraction layer
│   ├── parsers.ts              — Output parsing utilities
│   ├── tool-dependencies.ts    — Tool-to-binary dependency mappings
│   ├── rate-limiter.ts         — Sliding-window rate limiter (per-tool + global)
│   └── logger.ts               — Structured JSON logging with security level
└── tools/                      — 32 tool modules
    ├── access-control.ts       — 6 tools: SSH, sudo, users, passwords, PAM, shell
    ├── app-hardening.ts        — 1 tool: audit/recommend/firewall/systemd
    ├── backup.ts               — 1 tool: unified backup (config/state/restore/verify/list)
    ├── compliance.ts           — 7 tools: lynis, oscap, CIS, policy, cron, tmp
    ├── container-security.ts   — 6 tools: Docker, AppArmor, SELinux, namespaces, images, seccomp
    ├── drift-detection.ts      — 1 tool: create/compare/list baselines
    ├── ebpf-security.ts        — 2 tools: ebpf_list_programs, ebpf_falco
    ├── encryption.ts           — 4 tools: TLS, GPG, LUKS, file hash
    ├── firewall.ts             — 5 tools: iptables, ufw, nftables, persist, audit
    ├── hardening.ts            — 8 tools: sysctl, services, permissions, kernel, etc.
    ├── ids.ts                  — 3 tools: AIDE, rootkit scan, file integrity
    ├── incident-response.ts    — 1 tool: collect/ioc_scan/timeline
    ├── logging.ts              — 4 tools: auditd, journalctl, fail2ban, syslog
    ├── malware.ts              — 4 tools: ClamAV, YARA, file scan, quarantine
    ├── meta.ts                 — 5 tools: check tools, workflow, history, posture, scheduled
    ├── network-defense.ts      — 3 tools: connections, capture, security audit
    ├── patch-management.ts     — 5 tools: updates, unattended, integrity, kernel, vulns
    ├── secrets.ts              — 4 tools: scan, env audit, SSH key sprawl, git history
    ├── sudo-management.ts      — 6 tools: elevate, elevate_gui, status, drop, extend, batch
    ├── supply-chain-security.ts — 1 tool: sbom/sign/verify_slsa
    └── zero-trust-network.ts   — 1 tool: wireguard/wg_peers/mtls/microsegment
```

### 2.2 Dependency Graph

The module dependency graph is structured to avoid circular imports:

```
spawn-safe.ts ─────────────► command-allowlist.ts ◄──── executor.ts
    │                                                        │
    │                                                        ├── config.ts
    │                                                        ├── sudo-session.ts ──► spawn-safe.ts
    │                                                        └── sudo-guard.ts ──► sudo-session.ts
    │
sudo-session.ts ──► spawn-safe.ts (NOT executor.ts)
auto-installer.ts ──► spawn-safe.ts (NOT executor.ts)

preflight.ts ──► tool-registry.ts ──► tool-dependencies.ts
             ──► privilege-manager.ts ──► sudo-session.ts
             ──► auto-installer.ts
             ──► dependency-validator.ts
             ──► safeguards.ts ──► executor.ts

tool-wrapper.ts ──► preflight.ts
                ──► tool-registry.ts
                ──► privilege-manager.ts
                ──► sudo-guard.ts
                ──► rate-limiter.ts

changelog.ts ──► secure-fs.ts
             ──► backup-manager.ts ──► secure-fs.ts

rollback.ts ──► secure-fs.ts
            ──► executor.ts

logger.ts ──► (no internal deps — standalone)
rate-limiter.ts ──► (no internal deps — standalone)
```

Key design constraint: [`sudo-session.ts`](src/core/sudo-session.ts) and [`auto-installer.ts`](src/core/auto-installer.ts) use [`spawn-safe.ts`](src/core/spawn-safe.ts) instead of [`executor.ts`](src/core/executor.ts) to avoid circular dependencies. The executor depends on sudo-session for transparent credential injection.

### 2.3 Startup Sequence

Defined in [`src/index.ts`](src/index.ts). The `main()` function executes these phases in order:

1. **Phase 0a — Initialize command allowlist**: [`initializeAllowlist()`](src/core/command-allowlist.ts) resolves all 115 allowlisted binary names to absolute paths via `fs.existsSync()`. Must run before any command execution.

2. **Phase 0b — Harden state directories**: [`hardenDirPermissions()`](src/core/secure-fs.ts) fixes permissions on `~/.kali-defense/` and `~/.kali-defense/backups/` to `0o700`. Best-effort; silently skips if directories don't exist yet.

3. **Phase 0 — Detect distribution**: [`getDistroAdapter()`](src/core/distro-adapter.ts) detects the Linux distribution, package manager, init system, and firewall backend. Cached for process lifetime.

4. **Phase 1 — Dependency validation**: [`validateAllDependencies()`](src/core/dependency-validator.ts) checks all required system binaries. If `KALI_DEFENSE_AUTO_INSTALL=true`, missing tools are automatically installed via the system package manager. Non-fatal: missing tools generate warnings but don't prevent startup.

5. **Phase 0.5 — Initialize pre-flight registry**: [`initializeRegistry()`](src/core/tool-registry.ts) populates the `ToolRegistry` singleton by migrating legacy `TOOL_DEPENDENCIES` and overlaying sudo/privilege metadata from `SUDO_OVERLAYS`.

6. **Phase 2 — Create pre-flight proxy**: [`createPreflightServer(server)`](src/core/tool-wrapper.ts) wraps the `McpServer` in a `Proxy` that intercepts `.tool()` registrations. Returns a `Proxy<McpServer>`.

7. **Phase 3 — Register tool modules**: All 21 `registerXxxTools(wrappedServer)` functions are called. Tools register on the proxy; handlers are automatically wrapped with pre-flight validation and rate limiting.

8. **Phase 4 — Connect transport**: `server.connect(new StdioServerTransport())` starts the JSON-RPC transport on stdin/stdout.

---

## 3. Security Architecture

These are non-negotiable security rules enforced throughout the codebase.

### 3.1 Command Allowlist with TOCTOU Verification

Every binary executed must be in [`ALLOWLIST_DEFINITIONS`](src/core/command-allowlist.ts) (115 entries). Bare command names are resolved to absolute paths at startup. The enforcement points are:

- [`executor.ts`](src/core/executor.ts): Calls `resolveCommand()` / `resolveSudoCommand()` before spawning
- [`spawn-safe.ts`](src/core/spawn-safe.ts): Calls `resolveCommand()` before spawning
- For `sudo` commands: both `sudo` itself AND the target binary are resolved against the allowlist
- Runtime TOCTOU re-verification ensures the resolved path still points to the expected binary at execution time

**Resolution flow:**

1. [`initializeAllowlist()`](src/core/command-allowlist.ts) — called once at startup, checks `existsSync()` for each candidate path
2. [`resolveCommand(command)`](src/core/command-allowlist.ts) — returns resolved absolute path; throws if not allowlisted or not found
3. [`resolveSudoCommand(args)`](src/core/command-allowlist.ts) — resolves both `sudo` and the target binary (skipping sudo flags)

### 3.2 `shell: false` Always

Every process spawn uses `shell: false`:

- [`executor.ts`](src/core/executor.ts): `spawn(command, args, { shell: false, ... })`
- [`spawn-safe.ts`](src/core/spawn-safe.ts): `shell: false` — comment: `// ALWAYS false — non-negotiable`

No exception exists. Shell metacharacters in arguments are rejected by [`sanitizer.ts`](src/core/sanitizer.ts) before they reach the executor.

### 3.3 Spawn-Safe with Argument Redaction

[`spawn-safe.ts`](src/core/spawn-safe.ts) is the low-level spawn layer with **no dependencies on executor.ts or sudo-session.ts**. It provides:

- `spawnSafe(command, args, options)` — async process spawn
- `execFileSafe(command, args, options)` — sync execution

Both functions resolve through the allowlist, enforce `shell: false`, and redact sensitive arguments in log output. Used by [`sudo-session.ts`](src/core/sudo-session.ts) and [`auto-installer.ts`](src/core/auto-installer.ts) to avoid circular dependencies.

### 3.4 Password as Buffer (Never String)

The [`SudoSession`](src/core/sudo-session.ts) stores the user's password in a `Buffer`:

```typescript
private passwordBuf: Buffer | null = null;
```

- [`getPassword()`](src/core/sudo-session.ts) returns a **copy** of the Buffer; callers must zero it with `.fill(0)` after use
- [`drop()`](src/core/sudo-session.ts) zeroes the buffer contents with `passwordBuf.fill(0)`
- Process exit handlers (SIGINT, SIGTERM, uncaughtException) call `drop()` automatically
- The executor zeroes stdin buffers after writing: `stdinBuf.fill(0)`
- SUDO_ASKPASS integrity validation ensures the askpass helper hasn't been tampered with

### 3.5 Input Sanitization with Path Traversal Protection

[`sanitizer.ts`](src/core/sanitizer.ts) provides 14 typed validators, all of which reject shell metacharacters via `SHELL_METACHAR_RE = /[;|&$\`(){}<>\n\r]/`:

| Validator | Pattern |
|-----------|---------|
| `validateTarget()` | hostname/IPv4/IPv6/CIDR |
| `validatePort()` | 1–65535 integer |
| `validatePortRange()` | `"80,443,1-1024"` |
| `validateFilePath()` | No traversal (`..`), within allowed dirs, no null bytes |
| `sanitizeArgs()` | Array of strings, no metacharacters |
| `validateServiceName()` | `[a-zA-Z0-9._@-]+` |
| `validateSysctlKey()` | `word.word.word` pattern |
| `validateConfigKey()` | `[a-zA-Z0-9._-]+` |
| `validatePackageName()` | `[a-zA-Z0-9._+:-]+` |
| `validateIptablesChain()` | `[A-Za-z_][A-Za-z0-9_-]{0,28}` |
| `validateInterface()` | `[a-zA-Z0-9._-]+`, max 16 chars |
| `validateUsername()` | `[a-zA-Z0-9._-]+`, max 32 chars |
| `validateYaraRule()` | Must end in `.yar`/`.yara` |
| `validateCertPath()` | Must end in `.pem`/`.crt`/`.key`/`.p12`/`.pfx` |

Key rejection patterns:

- `SHELL_METACHAR_RE = /[;|&$\`(){}<>\n\r]/`
- `CONTROL_CHAR_RE = /[\x00-\x08\x0e-\x1f\x7f]/`
- `PATH_TRAVERSAL_RE = /(^|[\/\\])\.\.([\/\\]|$)/`

`validateFilePath()` additionally checks:
- No null bytes
- Path resolves within `config.allowedDirs` (default: `/tmp,/home,/var/log,/etc`)
- Path is not within `config.protectedPaths` (default: `/boot,/usr/lib/systemd,/usr/bin,/usr/sbin`)

### 3.6 Safeguard System (Dry-Run, Confirmation, Backup)

**Dry-run by default**: Individual tool parameters default `dry_run` to `true` via Zod schemas:

```typescript
dry_run: z.boolean().optional().default(true).describe("Preview changes")
```

Every mutating tool call requires the caller to explicitly set `dry_run: false` to apply changes.

**Confirmation requirement**: Configurable via `KALI_DEFENSE_REQUIRE_CONFIRMATION`.

**Automatic backup**: Files are backed up before modification via [`backup-manager.ts`](src/core/backup-manager.ts). Backup paths stored in changelog entries for rollback.

**Application detection**: The [`SafeguardRegistry`](src/core/safeguards.ts) detects running applications (VS Code, Docker, databases, web servers, MCP servers) and evaluates operation safety with blocker conditions (SSH lockout, database service stop, etc.) and warnings.

### 3.7 Policy Engine with Zod Validation and ReDoS Protection

The [`policy-engine.ts`](src/core/policy-engine.ts) evaluates compliance policies using Zod schema validation. Pattern matching includes ReDoS protection to prevent denial-of-service via maliciously crafted regular expressions in policy definitions.

### 3.8 Rate Limiting (Per-Tool and Global)

The [`RateLimiter`](src/core/rate-limiter.ts) provides sliding-window rate limiting:

| Parameter | Environment Variable | Default |
|-----------|---------------------|---------|
| Per-tool max | `KALI_DEFENSE_RATE_LIMIT_PER_TOOL` | 30 invocations/window |
| Global max | `KALI_DEFENSE_RATE_LIMIT_GLOBAL` | 100 invocations/window |
| Window size | `KALI_DEFENSE_RATE_LIMIT_WINDOW` | 60 seconds |

Set any limit to `0` to disable that particular limit. Rate limit breaches are logged as security events.

### 3.9 Structured JSON Logging with Security Event Level

The [`Logger`](src/core/logger.ts) outputs single-line JSON log entries to stderr (avoiding interference with MCP protocol on stdout):

```typescript
interface LogEntry {
  timestamp: string;    // ISO 8601 UTC
  level: LogLevel;      // "debug" | "info" | "warn" | "error" | "security"
  component: string;    // Subsystem (e.g., "executor", "preflight")
  action: string;       // Action identifier (e.g., "command_executed")
  message: string;      // Human-readable description
  details?: Record<string, unknown>;  // Structured metadata
}
```

The `security` level (severity 999) is **always emitted** regardless of configured minimum log level. It covers:
- Authentication / privilege escalation events
- Policy violations
- Rate limit breaches
- Suspicious input patterns
- Configuration changes with security impact

### 3.10 Secure File Operations (0o600/0o700)

[`secure-fs.ts`](src/core/secure-fs.ts) enforces owner-only permissions with audit trail:

| Function | Permission | Purpose |
|----------|-----------|---------|
| `secureWriteFileSync()` | 0o600 | Write file, create parent dirs at 0o700 |
| `secureMkdirSync()` | 0o700 | Create directory |
| `secureCopyFileSync()` | 0o600 | Copy file with secure dest permissions |
| `verifySecurePermissions()` | — | Check `(mode & 0o077) === 0` |
| `hardenFilePermissions()` | 0o600 | Fix existing file permissions |
| `hardenDirPermissions()` | 0o700 | Fix existing directory permissions |

All functions call `chmodSync()` explicitly after the operation to override any umask interference.

### 3.11 Auto-Install Supply Chain Protection

The [`AutoInstaller`](src/core/auto-installer.ts) enforces a supply-chain protection chain:

1. Binary must exist in [`DEFENSIVE_TOOLS`](src/core/installer.ts) catalog
2. Package name is resolved from the catalog (no raw binary name fallback)
3. Package name is validated against `validatePackageName()` regex
4. Package must be in the approved packages allowlist (built from `DEFENSIVE_TOOLS`)
5. Every successful install is logged to the audit changelog

---

## 4. Core Modules Reference

### 4.1 Executor ([`executor.ts`](src/core/executor.ts))

The primary command execution engine. All tool modules call `executeCommand()` to run system binaries.

```typescript
interface ExecuteOptions {
  command: string;              // Binary name (resolved via allowlist)
  args: string[];               // Pre-sanitized argument array
  timeout?: number;             // Override default (ms)
  cwd?: string;                 // Working directory
  env?: Record<string, string>; // Additional env vars
  stdin?: string | Buffer;      // Data to pipe (Buffer for passwords)
  maxBuffer?: number;           // Max output buffer (bytes)
  toolName?: string;            // Per-tool timeout lookup key
  skipSudoInjection?: boolean;  // Used internally by sudo-session
}

interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;             // 124 on timeout
  timedOut: boolean;
  duration: number;             // Wall-clock ms
  permissionDenied: boolean;    // Detected by SudoGuard patterns
}
```

**Execution flow:**

1. Resolve command via `resolveCommand()` or `resolveSudoCommand()` (allowlist enforcement)
2. Call `prepareSudoOptions()` for transparent credential injection
3. Spawn with `shell: false`, `AbortController` for timeout, buffer capping
4. Zero stdin buffer after writing (may contain password)
5. Detect permission errors via `SudoGuard.isPermissionError()` on combined output

### 4.2 Configuration ([`config.ts`](src/core/config.ts))

All configuration via environment variables with defensive defaults:

```typescript
interface DefenseConfig {
  defaultTimeout: number;             // KALI_DEFENSE_TIMEOUT_DEFAULT (s→ms), default: 120s
  maxBuffer: number;                  // KALI_DEFENSE_MAX_OUTPUT_SIZE, default: 10MB
  allowedDirs: string[];              // KALI_DEFENSE_ALLOWED_DIRS, default: /tmp,/home,/var/log,/etc
  logLevel: string;                   // KALI_DEFENSE_LOG_LEVEL, default: "info"
  dryRun: boolean;                    // KALI_DEFENSE_DRY_RUN, default: false
  changelogPath: string;              // KALI_DEFENSE_CHANGELOG_PATH
  backupDir: string;                  // KALI_DEFENSE_BACKUP_DIR
  autoInstall: boolean;               // KALI_DEFENSE_AUTO_INSTALL, default: false
  protectedPaths: string[];           // KALI_DEFENSE_PROTECTED_PATHS
  requireConfirmation: boolean;       // KALI_DEFENSE_REQUIRE_CONFIRMATION, default: true
  quarantineDir: string;              // KALI_DEFENSE_QUARANTINE_DIR
  policyDir: string;                  // KALI_DEFENSE_POLICY_DIR
  toolTimeouts: Record<string, number>; // KALI_DEFENSE_TIMEOUT_<TOOL>
  sudoSessionTimeout: number;         // KALI_DEFENSE_SUDO_TIMEOUT (min→ms), default: 15 min
}
```

### 4.3 Sudo Session ([`sudo-session.ts`](src/core/sudo-session.ts))

**Singleton** managing elevated privilege credentials for non-interactive environments.

**Lifecycle:**

1. **Elevate**: User calls `sudo_elevate` or `sudo_elevate_gui` tool
2. **Validate**: `elevate()` runs `sudo -S -k -v -p ""` with password piped via stdin
3. **Store**: Password stored in a `Buffer` — `Buffer.from(password, "utf-8")`
4. **Timer**: Auto-expiry timer set (default 15 minutes), `unref()`'d
5. **Use**: `getPassword()` returns a **copy**; executor pipes it to `sudo -S` via stdin
6. **Drop**: `drop()` zeroes buffer, clears state, fires `sudo -k`
7. **Cleanup**: Process exit/signal handlers call `drop()` automatically

### 4.4 Pre-flight System ([`preflight.ts`](src/core/preflight.ts) + [`tool-wrapper.ts`](src/core/tool-wrapper.ts))

The [`createPreflightServer()`](src/core/tool-wrapper.ts) creates a `Proxy<McpServer>` that intercepts the `tool` property. Pipeline stages:

1. **Cache check**: Return cached passing result if available (60s TTL)
2. **Manifest resolution**: Look up `ToolManifest` from the registry
3. **Dependency checking**: Check binaries, Python modules, npm packages, libraries, files
4. **Auto-installation**: If enabled, attempt installation via `AutoInstaller.resolveAll()`
5. **Privilege validation**: Check sudo requirements via `PrivilegeManager.checkForTool()`
6. **Safeguard checks**: If params provided, run `SafeguardRegistry.checkSafety()`
7. **Result assembly**: Determine pass/fail, generate human-readable summary

**Caching:**

| Cache | TTL | Invalidation |
|-------|-----|-------------|
| `PreflightEngine.resultCache` | 60s | `invalidatePreflightCaches()` after sudo elevate/drop |
| `PrivilegeManager.cachedStatus` | 30s | Same invalidation trigger |
| `dependency-validator` binary cache | Startup | `clearDependencyCache()` after auto-install |

### 4.5 Changelog & Rollback

**Changelog** ([`changelog.ts`](src/core/changelog.ts)):

```typescript
interface ChangeEntry {
  id: string;                // UUID v4
  timestamp: string;         // ISO 8601
  tool: string;              // MCP tool name
  action: string;            // Description of action
  target: string;            // File, service, etc.
  before?: string;           // State before change
  after?: string;            // State after change
  backupPath?: string;       // Path to backup file
  dryRun: boolean;           // Whether this was dry-run
  success: boolean;          // Whether action succeeded
  error?: string;            // Error message if failed
  rollbackCommand?: string;  // Command to undo
}
```

Stored at `~/.kali-defense/changelog.json` with version 1 schema. Max 10,000 entries with rotation.

**Rollback** ([`rollback.ts`](src/core/rollback.ts)):

Change record types: `"file" | "sysctl" | "service" | "firewall"`. Stored at `~/.kali-defense/rollback-state.json`. Supports rollback by operation ID or session ID.

**Backup Manager** ([`backup-manager.ts`](src/core/backup-manager.ts)):

Stored at `~/.kali-defense/backups/manifest.json`. Supports backup, restore by ID, listing, and pruning by age.

### 4.6 Distro Support ([`distro.ts`](src/core/distro.ts), [`distro-adapter.ts`](src/core/distro-adapter.ts))

**Detection cascade:**

1. `process.platform === "darwin"` → macOS
2. `/proc/version` contains "microsoft" → WSL
3. Parse `/etc/os-release` (ID, PRETTY_NAME, VERSION_ID)
4. Fall back to `lsb_release -a`
5. Fall back to distro-specific files

**Supported families:**

| Family | Distros | Package Manager | Init System |
|--------|---------|----------------|-------------|
| debian | Debian, Ubuntu, Kali, Mint, Pop, Elementary, Parrot | apt | systemd |
| rhel | RHEL, CentOS, Fedora, Rocky, AlmaLinux, Amazon | dnf/yum | systemd |
| arch | Arch, Manjaro | pacman | systemd |
| alpine | Alpine | apk | openrc |
| suse | openSUSE, SLES | zypper | systemd |

**DistroAdapter** provides unified access to: package manager commands, service manager commands, firewall backend commands, distro-specific paths, package integrity checking, auto-update configuration, and firewall persistence setup.

---

## 5. Tool System

### 5.1 Tool Registration Pattern

Every tool module exports a single function:

```typescript
export function registerXxxTools(server: McpServer): void {
  server.tool(
    "tool_name",               // Tool name (snake_case)
    "Description",             // Description string
    {                          // Zod schema (plain object, NOT z.object())
      action: z.enum(["list", "add", "delete"]).describe("..."),
      param: z.string().optional().describe("..."),
      dry_run: z.boolean().optional().default(true).describe("Preview changes"),
    },
    async (params) => {        // Handler function
      // 1. Validate inputs via sanitizer
      // 2. Build command args
      // 3. Execute via executeCommand()
      // 4. Log change via logChange()
      // 5. Return { content: [{ type: "text", text: "..." }] }
    },
  );
}
```

**Action parameter pattern**: Most tools use a single `action` enum parameter to consolidate related operations. This pattern reduced the tool count from 157 (pre-v0.5.0) to 78, then grew to 94 with v0.6.0 additions.

### 5.2 Tool Naming Convention

All tools use a `prefix_subject` snake_case pattern. Prefixes match module names:

| Prefix | Module | Example |
|--------|--------|---------|
| `firewall_` | Firewall | `firewall_iptables`, `firewall_ufw` |
| `harden_` | Hardening | `harden_sysctl`, `harden_service` |
| `ids_` | IDS | `ids_aide_manage`, `ids_rootkit_scan` |
| `log_` | Logging | `log_auditd`, `log_fail2ban` |
| `netdef_` | Network Defense | `netdef_connections`, `netdef_capture` |
| `compliance_` | Compliance | `compliance_lynis_audit`, `compliance_check` |
| `malware_` | Malware | `malware_clamav`, `malware_yara_scan` |
| `backup` | Backup | `backup` |
| `access_` | Access Control | `access_ssh`, `access_pam` |
| `crypto_` | Encryption | `crypto_tls`, `crypto_luks_manage` |
| `container_` | Container Security | `container_docker`, `container_apparmor` |
| `patch_` | Patch Management | `patch_update_audit`, `patch_kernel_audit` |
| `secrets_` | Secrets | `secrets_scan`, `secrets_env_audit` |
| `incident_` | Incident Response | `incident_response` |
| `defense_` | Meta | `defense_check_tools`, `defense_security_posture` |
| `sudo_` | Sudo Management | `sudo_elevate`, `sudo_status` |
| `supply_` | Supply Chain | `supply_chain` |
| `drift_` | Drift Detection | `drift_baseline` |
| `zero_` | Zero Trust | `zero_trust` |
| `ebpf_` | eBPF Security | `ebpf_list_programs`, `ebpf_falco` |
| `app_` | App Hardening | `app_harden` |

### 5.3 Tool Modules (32 files, 94 tools)

| # | Module | File | Tools | Tool Names |
|---|--------|------|:-----:|------------|
| 1 | Sudo Management | `sudo-management.ts` | 6 | `sudo_elevate`, `sudo_elevate_gui`, `sudo_status`, `sudo_drop`, `sudo_extend`, `preflight_batch_check` |
| 2 | Firewall | `firewall.ts` | 5 | `firewall_iptables`, `firewall_ufw`, `firewall_persist`, `firewall_nftables_list`, `firewall_policy_audit` |
| 3 | Hardening | `hardening.ts` | 9 | `harden_sysctl`, `harden_service`, `harden_permissions`, `harden_systemd`, `harden_kernel`, `harden_bootloader`, `harden_misc`, `harden_memory`, `usb_device_control` |
| 4 | IDS | `ids.ts` | 3 | `ids_aide_manage`, `ids_rootkit_scan`, `ids_file_integrity_check` |
| 5 | Logging | `logging.ts` | 4 | `log_auditd`, `log_journalctl_query`, `log_fail2ban`, `log_system` |
| 6 | Network Defense | `network-defense.ts` | 4 | `netdef_connections`, `netdef_capture`, `netdef_security_audit`, `network_segmentation_audit` |
| 7 | Compliance | `compliance.ts` | 7 | `compliance_lynis_audit`, `compliance_oscap_scan`, `compliance_check`, `compliance_policy_evaluate`, `compliance_report`, `compliance_cron_restrict`, `compliance_tmp_hardening` |
| 8 | Malware | `malware.ts` | 4 | `malware_clamav`, `malware_yara_scan`, `malware_file_scan`, `malware_quarantine_manage` |
| 9 | Backup | `backup.ts` | 1 | `backup` |
| 10 | Access Control | `access-control.ts` | 6 | `access_ssh`, `access_sudo_audit`, `access_user_audit`, `access_password_policy`, `access_pam`, `access_restrict_shell` |
| 11 | Encryption | `encryption.ts` | 5 | `crypto_tls`, `crypto_gpg_keys`, `crypto_luks_manage`, `crypto_file_hash`, `certificate_lifecycle` |
| 12 | Container Security | `container-security.ts` | 6 | `container_docker`, `container_apparmor`, `container_selinux_manage`, `container_namespace_check`, `container_image_scan`, `container_security_config` |
| 13 | Meta | `meta.ts` | 6 | `defense_check_tools`, `defense_workflow`, `defense_change_history`, `defense_security_posture`, `defense_scheduled_audit`, `auto_remediate` |
| 14 | Patch Management | `patch-management.ts` | 5 | `patch_update_audit`, `patch_unattended_audit`, `patch_integrity_check`, `patch_kernel_audit`, `patch_vulnerability_intel` |
| 15 | Secrets | `secrets.ts` | 4 | `secrets_scan`, `secrets_env_audit`, `secrets_ssh_key_sprawl`, `secrets_git_history_scan` |
| 16 | Incident Response | `incident-response.ts` | 2 | `incident_response`, `ir_forensics` |
| 17 | Supply Chain | `supply-chain-security.ts` | 1 | `supply_chain` |
| 18 | Drift Detection | `drift-detection.ts` | 1 | `drift_baseline` |
| 19 | Zero Trust | `zero-trust-network.ts` | 1 | `zero_trust` |
| 20 | eBPF Security | `ebpf-security.ts` | 2 | `ebpf_list_programs`, `ebpf_falco` |
| 21 | App Hardening | `app-hardening.ts` | 1 | `app_harden` |
| 22 | Reporting | `reporting.ts` | 1 | `report_export` |
| 23 | DNS Security | `dns-security.ts` | 1 | `dns_security` |
| 24 | Vulnerability Management | `vulnerability-management.ts` | 1 | `vuln_manage` |
| 25 | Process Security | `process-security.ts` | 1 | `process_security` |
| 26 | WAF Management | `waf.ts` | 1 | `waf_manage` |
| 27 | Threat Intelligence | `threat-intel.ts` | 1 | `threat_intel` |
| 28 | Cloud Security | `cloud-security.ts` | 1 | `cloud_security` |
| 29 | API Security | `api-security.ts` | 1 | `api_security` |
| 30 | Deception/Honeypots | `deception.ts` | 1 | `honeypot_manage` |
| 31 | Wireless Security | `wireless-security.ts` | 1 | `wireless_security` |
| 32 | SIEM Integration | `siem-integration.ts` | 1 | `siem_export` |

---

## 6. State Management

### 6.1 Directory Layout (`~/.kali-defense/`)

```
~/.kali-defense/                      [0o700]
├── changelog.json                    [0o600] — Versioned audit trail
├── rollback-state.json               [0o600] — Change tracking for rollback
├── backups/                          [0o700]
│   ├── manifest.json                 [0o600] — Backup inventory
│   └── <timestamp>_<filename>        [0o600] — Individual file backups
├── quarantine/                       [0o700] — Isolated malware samples
├── policies/                         [0o700] — Custom compliance policies
└── baselines/                        [0o700] — Drift detection baselines
```

### 6.2 Changelog Schema (version 1)

```json
{
  "version": 1,
  "entries": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "timestamp": "2026-03-04T10:30:00.000Z",
      "tool": "harden_sysctl",
      "action": "Set sysctl parameter",
      "target": "net.ipv4.ip_forward",
      "before": "1",
      "after": "0",
      "backupPath": null,
      "dryRun": false,
      "success": true,
      "error": null,
      "rollbackCommand": "sysctl -w net.ipv4.ip_forward=1"
    }
  ]
}
```

### 6.3 Rollback State Schema (version 1)

```json
{
  "version": 1,
  "changes": [
    {
      "id": "uuid",
      "operationId": "uuid",
      "sessionId": "uuid",
      "type": "sysctl",
      "target": "net.ipv4.ip_forward",
      "originalValue": "1",
      "timestamp": "2026-03-04T10:30:00.000Z",
      "rolledBack": false,
      "changelogRef": "changelog-entry-uuid"
    }
  ]
}
```

### 6.4 Backup Manifest Schema (version 1)

```json
{
  "version": 1,
  "backups": [
    {
      "id": "uuid",
      "originalPath": "/etc/ssh/sshd_config",
      "backupPath": "/home/user/.kali-defense/backups/2026-03-04T10-30-00-000Z_sshd_config",
      "timestamp": "2026-03-04T10:30:00.000Z",
      "sizeBytes": 3452
    }
  ]
}
```

---

## 7. Testing

### 7.1 Framework

| Component | Version |
|-----------|---------|
| Test runner | vitest ^4.0.18 |
| Coverage | @vitest/coverage-v8 ^4.0.18 |
| Config | [`vitest.config.ts`](vitest.config.ts) |

### 7.2 Test Structure

Every source module has a corresponding test file:

```
tests/
├── core/                              — 26 test files
│   ├── auto-installer.test.ts
│   ├── backup-manager.test.ts
│   ├── changelog.test.ts
│   ├── command-allowlist.test.ts
│   ├── config.test.ts
│   ├── dependency-validator.test.ts
│   ├── distro-adapter.test.ts
│   ├── distro.test.ts
│   ├── executor.test.ts
│   ├── installer.test.ts
│   ├── logger.test.ts
│   ├── parsers.test.ts
│   ├── policy-engine.test.ts
│   ├── preflight.test.ts
│   ├── privilege-manager.test.ts
│   ├── rate-limiter.test.ts
│   ├── rollback.test.ts
│   ├── safeguards.test.ts
│   ├── sanitizer.test.ts
│   ├── secure-fs.test.ts
│   ├── spawn-safe.test.ts
│   ├── sudo-guard.test.ts
│   ├── sudo-session.test.ts
│   ├── tool-dependencies.test.ts
│   ├── tool-registry.test.ts
│   └── tool-wrapper.test.ts
└── tools/                             — 21 test files
    ├── access-control.test.ts
    ├── app-hardening.test.ts
    ├── backup.test.ts
    ├── compliance.test.ts
    ├── container-security.test.ts
    ├── drift-detection.test.ts
    ├── ebpf-security.test.ts
    ├── encryption.test.ts
    ├── firewall.test.ts
    ├── hardening.test.ts
    ├── ids.test.ts
    ├── incident-response.test.ts
    ├── logging.test.ts
    ├── malware.test.ts
    ├── meta.test.ts
    ├── network-defense.test.ts
    ├── patch-management.test.ts
    ├── secrets.test.ts
    ├── sudo-management.test.ts
    ├── supply-chain-security.test.ts
    └── zero-trust-network.test.ts
```

**Totals**: 47 test files, 873 tests.

### 7.3 Coverage Configuration

From [`vitest.config.ts`](vitest.config.ts):

```typescript
coverage: {
  provider: "v8",
  include: ["src/core/**/*.ts"],
  exclude: ["src/tools/**/*.ts", "src/index.ts"],
  thresholds: {
    lines: 60,
    functions: 60,
    branches: 50,
    statements: 60,
  },
},
testTimeout: 10000,
```

Coverage targets `src/core/**/*.ts` only. Tool modules and the entry point are excluded from coverage thresholds.

---

## 8. CI/CD

### 8.1 GitHub Actions — CI Pipeline ([`.github/workflows/ci.yml`](.github/workflows/ci.yml))

| Step | Description |
|------|-------------|
| **Checkout** | `actions/checkout` (SHA-pinned: `11bd7190...`) |
| **Node Setup** | `actions/setup-node` (SHA-pinned: `49933ea5...`) with npm caching |
| **Matrix** | ubuntu-latest × Node 18, 20, 22 |
| **npm audit** | `npm audit --audit-level=high` — security vulnerability check |
| **Type check** | `npx tsc --noEmit` — TypeScript compilation |
| **Strict type check** | `npx tsc --noEmit --strict` — SAST / static analysis |
| **Tests + coverage** | `npx vitest run --coverage` — with threshold enforcement |
| **Build** | `npm run build` — production build verification |

### 8.2 CodeQL SAST ([`.github/workflows/codeql.yml`](.github/workflows/codeql.yml))

- Runs on push, PR, and weekly schedule (Mondays 6am UTC)
- Language: `javascript-typescript`
- Queries: `security-and-quality`
- SHA-pinned `actions/checkout`

### 8.3 ESLint Security Plugin

[`eslint.config.mjs`](eslint.config.mjs) uses `eslint-plugin-security` with the `recommended` preset, detecting:
- `eval()` usage
- Non-literal `RegExp`
- Non-literal `require()`
- Other common security anti-patterns

### 8.4 Husky Pre-Commit Hooks

[`.husky/pre-commit`](.husky/pre-commit) runs `npx tsc --noEmit` to catch type errors before commit.

### 8.5 License Compliance

`npm run license:check` uses `license-checker` to fail on `GPL-3.0` and `AGPL-3.0` licenses in production dependencies.

### 8.6 npm Audit

`npm run audit:security` runs `npm audit --audit-level=high` for dependency vulnerability detection.

---

## 9. Configuration

### 9.1 Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KALI_DEFENSE_TIMEOUT_DEFAULT` | `120` (seconds) | Default command timeout |
| `KALI_DEFENSE_MAX_OUTPUT_SIZE` | `10485760` (10MB) | Max stdout/stderr buffer |
| `KALI_DEFENSE_ALLOWED_DIRS` | `/tmp,/home,/var/log,/etc` | Directories allowed for file operations |
| `KALI_DEFENSE_LOG_LEVEL` | `info` | Log level: debug, info, warn, error, security |
| `KALI_DEFENSE_DRY_RUN` | `false`* | Global dry-run mode (*tools default `true` individually) |
| `KALI_DEFENSE_CHANGELOG_PATH` | `~/.kali-defense/changelog.json` | Changelog file location |
| `KALI_DEFENSE_BACKUP_DIR` | `~/.kali-defense/backups` | Backup directory |
| `KALI_DEFENSE_AUTO_INSTALL` | `false` | Auto-install missing tools via package manager |
| `KALI_DEFENSE_PROTECTED_PATHS` | `/boot,/usr/lib/systemd,/usr/bin,/usr/sbin` | Paths protected from modification |
| `KALI_DEFENSE_REQUIRE_CONFIRMATION` | `true` | Require confirmation for destructive actions |
| `KALI_DEFENSE_QUARANTINE_DIR` | `~/.kali-defense/quarantine` | Malware quarantine directory |
| `KALI_DEFENSE_POLICY_DIR` | `~/.kali-defense/policies` | Custom compliance policy files |
| `KALI_DEFENSE_SUDO_TIMEOUT` | `15` (minutes) | Sudo session expiry timeout |
| `KALI_DEFENSE_PREFLIGHT` | `true` | Enable/disable pre-flight validation |
| `KALI_DEFENSE_PREFLIGHT_BANNERS` | `true` | Prepend status banners to tool output |
| `KALI_DEFENSE_RATE_LIMIT_PER_TOOL` | `30` | Max invocations per tool per window (0=disabled) |
| `KALI_DEFENSE_RATE_LIMIT_GLOBAL` | `100` | Max total invocations per window (0=disabled) |
| `KALI_DEFENSE_RATE_LIMIT_WINDOW` | `60` (seconds) | Rate limit window size |
| `KALI_DEFENSE_TIMEOUT_<TOOL>` | — | Per-tool timeout in seconds |

Per-tool timeout overrides support: `LYNIS`, `AIDE`, `CLAMAV`, `OSCAP`, `SNORT`, `SURICATA`, `RKHUNTER`, `CHKROOTKIT`, `TCPDUMP`, `AUDITD`, `NMAP`, `FAIL2BAN-CLIENT`, `DEBSUMS`, `YARA`.

### 9.2 Secure Defaults

| Default | Rationale |
|---------|-----------|
| `dryRun: true` (per-tool) | Prevents accidental system modification |
| `/etc` not writable by default | `allowedDirs` permits reading `/etc` but `protectedPaths` blocks write to critical system dirs |
| `autoInstall: false` | No automatic package installation without explicit opt-in |
| `requireConfirmation: true` | Destructive operations require explicit confirmation |
| `preflight: true` | All tool invocations validated before execution |
| Rate limits enabled | Per-tool (30/min) and global (100/min) limits prevent abuse |

---

## 10. Dependencies

### 10.1 Runtime (2 packages)

| Package | Version | Purpose |
|---------|---------|---------|
| `@modelcontextprotocol/sdk` | 1.27.1 | MCP server framework (McpServer, StdioServerTransport) |
| `zod` | 3.25.76 | Schema validation for tool parameters |

### 10.2 Development

| Package | Version | Purpose |
|---------|---------|---------|
| `typescript` | ^5.8.3 | TypeScript compiler |
| `@types/node` | ^22.15.0 | Node.js type definitions |
| `vitest` | ^4.0.18 | Test runner |
| `@vitest/coverage-v8` | ^4.0.18 | Code coverage |
| `tsx` | ^4.19.4 | TypeScript execution for development |
| `eslint` | ^9.22.0 | Linter |
| `@eslint/js` | ^9.22.0 | ESLint JavaScript config |
| `eslint-plugin-security` | ^3.0.1 | Security anti-pattern detection |
| `husky` | ^9.1.7 | Git hooks |
| `license-checker` | ^25.0.1 | License compliance checking |

### 10.3 System (External Binaries)

The server operates on 115 allowlisted binaries. Key categories:

| Category | Required Binaries | Optional Binaries |
|----------|------------------|-------------------|
| Firewall | iptables, ufw | ip6tables, nft, netfilter-persistent |
| Hardening | sysctl, systemctl, stat, cat | lsmod, modprobe, readelf, checksec |
| IDS | sha256sum | aide, rkhunter, chkrootkit |
| Logging | journalctl | auditctl, ausearch, aureport, fail2ban-client |
| Network | ss | tcpdump, nmap, ip |
| Compliance | — | lynis, oscap |
| Malware | — | clamscan, freshclam, yara |
| Access | cat | sshd, passwd, usermod, chage |
| Crypto | openssl | gpg, cryptsetup |
| Container | — | docker, trivy, grype, apparmor_status |
| Package Mgmt | — | apt, dpkg, dnf, rpm, pacman, apk, zypper |
| Supply Chain | — | syft, cosign, slsa-verifier |
| Secrets | grep, find | gitleaks, trufflehog |
| eBPF | — | bpftool, falco |

---

## 11. Cross-Distro Support Matrix

| Tool / Feature | Debian/Ubuntu/Kali | RHEL/CentOS/Fedora | Arch | Alpine | SUSE |
|----------------|:---:|:---:|:---:|:---:|:---:|
| iptables | ✅ | ✅ | ✅ | ✅ | ✅ |
| nftables | ✅ | ✅ | ✅ | ✅ | ✅ |
| ufw | ✅ | ⚠️ | ⚠️ | ⚠️ | ⚠️ |
| firewalld | ⚠️ | ✅ | ⚠️ | ❌ | ✅ |
| systemctl | ✅ | ✅ | ✅ | ❌* | ✅ |
| auditd | ✅ | ✅ | ✅ | ✅ | ✅ |
| fail2ban | ✅ | ✅ | ✅ | ✅ | ✅ |
| lynis | ✅ | ✅ | ✅ | ✅ | ✅ |
| OpenSCAP | ✅ | ✅ | ⚠️ | ❌ | ✅ |
| ClamAV | ✅ | ✅ | ✅ | ✅ | ✅ |
| AIDE | ✅ | ✅ | ✅ | ✅ | ✅ |
| rkhunter | ✅ | ✅ | ✅ | ✅ | ✅ |
| AppArmor | ✅ | ❌ | ⚠️ | ❌ | ✅ |
| SELinux | ⚠️ | ✅ | ❌ | ❌ | ⚠️ |
| Docker | ✅ | ✅ | ✅ | ✅ | ✅ |
| Trivy/Grype | ✅ | ✅ | ✅ | ✅ | ✅ |
| eBPF/bpftool | ✅ | ✅ | ✅ | ❌ | ✅ |
| WireGuard | ✅ | ✅ | ✅ | ✅ | ✅ |

✅ = full support  ⚠️ = available but not default  ❌ = not available
\* Alpine uses OpenRC; tools fall back to `rc-service`/`rc-update`

---

## 12. Future Considerations

Items intentionally deferred from the current implementation:

- **Multi-user sessions**: `SudoSession` is a process-wide singleton; no per-user credential isolation
- **Network transport**: Only stdio supported; no HTTP/SSE/WebSocket transport
- **Network timeouts**: No connect-timeout for remote TLS checks or port probes
- **Tool-level RBAC**: No role-based access control per tool
- **Encrypted state files**: State files use permission-based security only (0o600), not encryption at rest
- **Atomic state file writes**: No write-then-rename pattern for crash safety
- **Metrics/telemetry**: No Prometheus, OpenTelemetry, or other metrics export
- **Plugin system**: Tool modules are statically imported; no dynamic loading
- **Time-based retention**: 10,000 entry cap exists but no time-based retention policy for changelog
- **Cross-platform**: Linux only; macOS detection exists in `distro.ts` but tools are Linux-specific
