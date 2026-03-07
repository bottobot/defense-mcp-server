# kali-defense-mcp-server — Technical Specification

## Metadata

| Field | Value |
|-------|-------|
| **Version** | 0.5.0-beta.1 |
| **Language** | TypeScript 5.8+ |
| **Target** | ES2022 |
| **Module System** | Node16 (ESM with `.js` extensions in imports) |
| **Runtime** | Node.js ≥ 18 (recommended ≥ 20) |
| **Framework** | `@modelcontextprotocol/sdk` ^1.12.1 |
| **Validation** | `zod` ^3.25.0 |
| **Transport** | stdio (StdioServerTransport) |
| **OS** | Linux only |
| **License** | MIT |
| **Repository** | `github.com/bottobot/kali-defense-mcp-server` |

---

## 1. Overview

The kali-defense-mcp-server is a Model Context Protocol (MCP) server that exposes 78 defensive security tools across 21 modules. It enables AI agents (Claude, etc.) to perform system hardening, compliance auditing, intrusion detection, malware scanning, firewall management, container security, and incident response on Linux systems.

The server runs as a child process communicating over stdio JSON-RPC. It wraps Linux security binaries (iptables, lynis, aide, rkhunter, ClamAV, etc.) with input validation, command allowlist enforcement, privilege management, and audit logging.

### Security Model Summary

All commands execute with `shell: false`. Every binary must be in a static allowlist resolved to absolute paths at startup. Passwords are stored in zeroable Buffers, never V8 strings. All state files are written with `0o600`/`0o700` permissions. Dry-run is the default for all mutating operations. Every change is logged to an append-only changelog with before/after state and rollback metadata.

---

## 2. Architecture

### 2.1 Module Map

```
src/
├── index.ts                    — Entry point: startup sequence, tool registration
├── core/
│   ├── executor.ts             — Safe command execution (spawn, shell:false, timeouts)
│   ├── config.ts               — Environment-based configuration with defaults
│   ├── sanitizer.ts            — Input validation (13 validators)
│   ├── command-allowlist.ts    — Binary allowlist with path resolution
│   ├── spawn-safe.ts           — Low-level spawn layer (no circular deps)
│   ├── sudo-session.ts         — Password Buffer lifecycle, elevation, expiry
│   ├── sudo-guard.ts           — Permission error detection + elevation prompts
│   ├── preflight.ts            — Pre-flight validation pipeline
│   ├── tool-wrapper.ts         — Proxy-based McpServer middleware
│   ├── safeguards.ts           — Application detection + safety checking
│   ├── tool-registry.ts        — ToolManifest registry (78 entries)
│   ├── tool-dependencies.ts    — Tool-to-binary dependency mappings
│   ├── privilege-manager.ts    — UID/capability/sudo status detection
│   ├── auto-installer.ts       — Multi-package-manager dependency resolver
│   ├── dependency-validator.ts — Binary availability checking
│   ├── installer.ts            — DEFENSIVE_TOOLS catalog with package mappings
│   ├── changelog.ts            — Versioned audit trail (JSON, append-only)
│   ├── rollback.ts             — Change tracking with rollback capability
│   ├── backup-manager.ts       — File backup with manifest tracking
│   ├── secure-fs.ts            — Permission-enforcing file I/O (0o600/0o700)
│   ├── distro.ts               — Linux distribution detection
│   ├── distro-adapter.ts       — Cross-distro abstraction layer
│   ├── parsers.ts              — Output parsing utilities
│   ├── policy-engine.ts        — Compliance policy evaluation
│   └── [4 more modules]
└── tools/
    ├── firewall.ts             — 5 tools: iptables, ufw, nftables, persist, audit
    ├── hardening.ts            — 8 tools: sysctl, services, permissions, kernel, etc.
    ├── ids.ts                  — 3 tools: AIDE, rootkit scan, file integrity
    ├── logging.ts              — 4 tools: auditd, journalctl, fail2ban, syslog
    ├── network-defense.ts      — 3 tools: connections, capture, security audit
    ├── compliance.ts           — 7 tools: lynis, oscap, CIS, policy, cron, tmp
    ├── malware.ts              — 4 tools: ClamAV, YARA, file scan, quarantine
    ├── backup.ts               — 1 tool: unified backup (config/state/restore/verify/list)
    ├── access-control.ts       — 6 tools: SSH, sudo, users, passwords, PAM, shell
    ├── encryption.ts           — 4 tools: TLS, GPG, LUKS, file hash
    ├── container-security.ts   — 6 tools: Docker, AppArmor, SELinux, namespaces, images, seccomp
    ├── meta.ts                 — 5 tools: check tools, workflow, history, posture, scheduled
    ├── patch-management.ts     — 5 tools: updates, unattended, integrity, kernel, vulns
    ├── secrets.ts              — 4 tools: scan, env audit, SSH key sprawl, git history
    ├── incident-response.ts    — 1 tool: collect/ioc_scan/timeline
    ├── sudo-management.ts      — 6 tools: elevate, elevate_gui, status, drop, extend, batch
    ├── supply-chain-security.ts — 1 tool: sbom/sign/verify_slsa
    ├── drift-detection.ts      — 1 tool: create/compare/list baselines
    ├── zero-trust-network.ts   — 1 tool: wireguard/wg_peers/mtls/microsegment
    ├── ebpf-security.ts        — 2 tools: list_ebpf_programs, falco
    └── app-hardening.ts        — 1 tool: audit/recommend/firewall/systemd
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

changelog.ts ──► secure-fs.ts
             ──► backup-manager.ts ──► secure-fs.ts

rollback.ts ──► secure-fs.ts
            ──► executor.ts
```

Key design constraint: [`sudo-session.ts`](src/core/sudo-session.ts) and [`auto-installer.ts`](src/core/auto-installer.ts) use [`spawn-safe.ts`](src/core/spawn-safe.ts) instead of [`executor.ts`](src/core/executor.ts) to avoid circular dependencies. The executor depends on sudo-session for transparent credential injection.

### 2.3 Startup Sequence

Defined in [`src/index.ts`](src/index.ts:48). The `main()` function executes these phases in order:

1. **Phase 0a — Initialize command allowlist**: [`initializeAllowlist()`](src/core/command-allowlist.ts:289) resolves all allowlisted binary names to absolute paths via `fs.existsSync()`. Must run before any command execution.

2. **Phase 0b — Harden state directories**: [`hardenDirPermissions()`](src/core/secure-fs.ts:80) fixes permissions on `~/.kali-defense/` and `~/.kali-defense/backups/` to `0o700`. Best-effort; silently skips if directories don't exist yet.

3. **Phase 0 — Detect distribution**: [`getDistroAdapter()`](src/core/distro-adapter.ts:633) detects the Linux distribution, package manager, init system, and firewall backend. Cached for process lifetime.

4. **Phase 1 — Dependency validation**: [`validateAllDependencies()`](src/core/dependency-validator.ts) checks all required system binaries. If `KALI_DEFENSE_AUTO_INSTALL=true`, missing tools are automatically installed via the system package manager. Non-fatal: missing tools generate warnings but don't prevent startup.

5. **Phase 0.5 — Initialize pre-flight registry**: [`initializeRegistry()`](src/core/tool-registry.ts:745) populates the [`ToolRegistry`](src/core/tool-registry.ts:82) singleton by migrating legacy `TOOL_DEPENDENCIES` and overlaying sudo/privilege metadata from `SUDO_OVERLAYS`.

6. **Phase 2 — Create pre-flight proxy**: [`createPreflightServer(server)`](src/core/tool-wrapper.ts:96) wraps the `McpServer` in a `Proxy` that intercepts `.tool()` registrations. Returns a `Proxy<McpServer>`.

7. **Phase 3 — Register tool modules**: All 21 `registerXxxTools(wrappedServer)` functions are called. Tools register on the proxy; handlers are automatically wrapped with pre-flight validation.

8. **Phase 4 — Connect transport**: `server.connect(new StdioServerTransport())` starts the JSON-RPC transport on stdin/stdout.

---

## 3. Security Invariants

These are non-negotiable security rules enforced throughout the codebase:

### 3.1 `shell: false` Always

Every process spawn uses `shell: false`:

- [`executor.ts`](src/core/executor.ts:256): `spawn(command, args, { shell: false, ... })`
- [`spawn-safe.ts`](src/core/spawn-safe.ts:57): `shell: false` — comment: `// ALWAYS false — non-negotiable`

No exception exists. Shell metacharacters in arguments are rejected by [`sanitizer.ts`](src/core/sanitizer.ts:8) before they reach the executor.

### 3.2 Command Allowlist Enforcement

Every binary executed must be in [`ALLOWLIST_DEFINITIONS`](src/core/command-allowlist.ts:46) (currently 115 entries). Bare command names are resolved to absolute paths at startup. The enforcement points are:

- [`executor.ts`](src/core/executor.ts:207): Calls `resolveCommand()` / `resolveSudoCommand()` before spawning
- [`spawn-safe.ts`](src/core/spawn-safe.ts:54): Calls `resolveCommand()` before spawning
- For `sudo` commands: both `sudo` itself AND the target binary are resolved against the allowlist

### 3.3 Password as Buffer (Never String)

The [`SudoSession`](src/core/sudo-session.ts:96) stores the user's password in a `Buffer`:

```typescript
private passwordBuf: Buffer | null = null;  // line 100
```

- [`getPassword()`](src/core/sudo-session.ts:210) returns a **copy** of the Buffer; callers must zero it with `.fill(0)` after use
- [`drop()`](src/core/sudo-session.ts:262) zeroes the buffer contents with `passwordBuf.fill(0)`
- Process exit handlers (SIGINT, SIGTERM, uncaughtException) call `drop()` automatically
- The executor zeroes stdin buffers after writing: [`stdinBuf.fill(0)`](src/core/executor.ts:325)

### 3.4 Input Sanitization

[`sanitizer.ts`](src/core/sanitizer.ts) provides 13 typed validators, all of which reject shell metacharacters via `SHELL_METACHAR_RE = /[;|&$\`(){}<>\n\r]/`:

| Validator | Pattern | File Reference |
|-----------|---------|----------------|
| `validateTarget()` | hostname/IPv4/IPv6/CIDR | [sanitizer.ts:25](src/core/sanitizer.ts:25) |
| `validatePort()` | 1–65535 integer | [sanitizer.ts:81](src/core/sanitizer.ts:81) |
| `validatePortRange()` | `"80,443,1-1024"` | [sanitizer.ts:93](src/core/sanitizer.ts:93) |
| `validateFilePath()` | No traversal, within allowed dirs | [sanitizer.ts:140](src/core/sanitizer.ts:140) |
| `sanitizeArgs()` | Array of strings, no metacharacters | [sanitizer.ts:209](src/core/sanitizer.ts:209) |
| `validateServiceName()` | `[a-zA-Z0-9._@-]+` | [sanitizer.ts:239](src/core/sanitizer.ts:239) |
| `validateSysctlKey()` | `word.word.word` pattern | [sanitizer.ts:259](src/core/sanitizer.ts:259) |
| `validateConfigKey()` | `[a-zA-Z0-9._-]+` | [sanitizer.ts:280](src/core/sanitizer.ts:280) |
| `validatePackageName()` | `[a-zA-Z0-9._+:-]+` | [sanitizer.ts:301](src/core/sanitizer.ts:301) |
| `validateIptablesChain()` | `[A-Za-z_][A-Za-z0-9_-]{0,28}` | [sanitizer.ts:323](src/core/sanitizer.ts:323) |
| `validateInterface()` | `[a-zA-Z0-9._-]+`, max 16 chars | [sanitizer.ts:345](src/core/sanitizer.ts:345) |
| `validateUsername()` | `[a-zA-Z0-9._-]+`, max 32 chars | [sanitizer.ts:372](src/core/sanitizer.ts:372) |
| `validateYaraRule()` | Must end in `.yar`/`.yara` | [sanitizer.ts:396](src/core/sanitizer.ts:396) |
| `validateCertPath()` | Must end in `.pem`/`.crt`/`.key`/`.p12`/`.pfx` | [sanitizer.ts:432](src/core/sanitizer.ts:432) |

### 3.5 Dry-Run by Default

The global default is `dryRun: false` in config (env `KALI_DEFENSE_DRY_RUN`), but individual tool parameters default `dry_run` to `true` via Zod schemas:

```typescript
dry_run: z.boolean().optional().default(true).describe("Preview changes")
```

This means every mutating tool call requires the caller to explicitly set `dry_run: false` to apply changes.

### 3.6 State File Permissions (0o600/0o700)

[`secure-fs.ts`](src/core/secure-fs.ts) enforces:

- Files: `0o600` (owner read/write only) — [`SECURE_FILE_MODE`](src/core/secure-fs.ts:11)
- Directories: `0o700` (owner read/write/execute only) — [`SECURE_DIR_MODE`](src/core/secure-fs.ts:14)
- `chmodSync()` is called explicitly after write/mkdir to override umask

All state file writes go through `secureWriteFileSync()`, `secureMkdirSync()`, or `secureCopyFileSync()`.

### 3.7 Auto-Install Package Validation

The [`AutoInstaller`](src/core/auto-installer.ts:296) enforces a supply-chain protection chain:

1. Binary must exist in [`DEFENSIVE_TOOLS`](src/core/installer.ts) catalog — [auto-installer.ts:477](src/core/auto-installer.ts:477)
2. Package name is resolved from the catalog (no raw binary name fallback) — [auto-installer.ts:491](src/core/auto-installer.ts:491)
3. Package name is validated against `validatePackageName()` regex — [auto-installer.ts:510](src/core/auto-installer.ts:510)
4. Package must be in the approved packages allowlist (built from `DEFENSIVE_TOOLS`) — [auto-installer.ts:525](src/core/auto-installer.ts:525)
5. Every successful install is logged to the audit changelog — [auto-installer.ts:587](src/core/auto-installer.ts:587)

---

## 4. Core Modules

### 4.1 Executor ([`executor.ts`](src/core/executor.ts))

The primary command execution engine. All tool modules call `executeCommand()` to run system binaries.

**Interface:**

```typescript
interface ExecuteOptions {
  command: string;           // Binary name (resolved via allowlist)
  args: string[];            // Pre-sanitized argument array
  timeout?: number;          // Override default (ms)
  cwd?: string;              // Working directory
  env?: Record<string, string>;  // Additional env vars
  stdin?: string | Buffer;   // Data to pipe (Buffer for passwords)
  maxBuffer?: number;        // Max output buffer (bytes)
  toolName?: string;         // Per-tool timeout lookup key
  skipSudoInjection?: boolean; // Used internally by sudo-session
}

interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;          // 124 on timeout
  timedOut: boolean;
  duration: number;          // Wall-clock ms
  permissionDenied: boolean; // Detected by SudoGuard patterns
}
```

**Execution flow:**

1. Resolve command via `resolveCommand()` or `resolveSudoCommand()` (allowlist enforcement)
2. Call `prepareSudoOptions()` for transparent credential injection:
   - Strategy 1: If `SudoSession` has a cached password → inject `-S -p ""` and pipe password via stdin
   - Strategy 2: If no session but askpass helper available → inject `-A` with `SUDO_ASKPASS` env
   - Strategy 3: Let sudo fail naturally (error caught by SudoGuard)
3. Spawn with `shell: false`, `AbortController` for timeout, buffer capping
4. Zero stdin buffer after writing (may contain password)
5. Detect permission errors via `SudoGuard.isPermissionError()` on combined output

### 4.2 Sanitizer ([`sanitizer.ts`](src/core/sanitizer.ts))

See [Section 3.4](#34-input-sanitization) for the complete validator table. Key rejection patterns:

- `SHELL_METACHAR_RE = /[;|&$\`(){}<>\n\r]/` — [line 8](src/core/sanitizer.ts:8)
- `CONTROL_CHAR_RE = /[\x00-\x08\x0e-\x1f\x7f]/` — [line 14](src/core/sanitizer.ts:14)
- `PATH_TRAVERSAL_RE = /(^|[\/\\])\.\.([\/\\]|$)/` — [line 19](src/core/sanitizer.ts:19)

`validateFilePath()` additionally checks:
- No null bytes
- Path resolves within `config.allowedDirs` (default: `/tmp,/home,/var/log,/etc`)
- Path is not within `config.protectedPaths` (default: `/boot,/usr/lib/systemd,/usr/bin,/usr/sbin`)

### 4.3 Command Allowlist ([`command-allowlist.ts`](src/core/command-allowlist.ts))

**Structure:**

```typescript
interface AllowlistEntry {
  binary: string;          // e.g. "iptables"
  candidates: string[];    // e.g. ["/usr/sbin/iptables", "/sbin/iptables"]
  resolvedPath?: string;   // Filled at startup; undefined if not found
}
```

The allowlist contains 115 binary definitions organized into categories: privilege management, firewall, kernel/sysctl, systemd, networking, logging/audit, IDS/rootkit, malware, compliance, container, encryption, WireGuard, SSH, user management, package managers, coreutils, hashing, process inspection, boot, supply chain, secrets scanners, eBPF, and GUI askpass helpers.

**Resolution:**

- [`initializeAllowlist()`](src/core/command-allowlist.ts:289): Called once at startup. Iterates all entries, checks `existsSync()` for each candidate path. First match wins.
- [`resolveCommand(command)`](src/core/command-allowlist.ts:323): Returns the resolved absolute path. Throws if not allowlisted or not found on disk.
- [`resolveSudoCommand(args)`](src/core/command-allowlist.ts:397): Resolves both `sudo` itself and the target binary in the args (skipping sudo flags like `-S`, `-p`, `-A`, `-k`, `-n`, `-v`).
- Bare names already in use as absolute paths are validated against candidate lists.
- Lazy resolution: if `initializeAllowlist()` hasn't run, `resolveCommand()` tries candidates on-the-fly.

### 4.4 Sudo Session ([`sudo-session.ts`](src/core/sudo-session.ts))

**Singleton** managing elevated privilege credentials for non-interactive (no-TTY) environments.

**Lifecycle:**

1. **Elevate**: User calls `sudo_elevate` tool with their password
2. **Validate**: `elevate()` runs `sudo -S -k -v -p ""` with password piped on stdin to test credentials
3. **Store**: Password stored in a `Buffer` (not a V8 string) — `this.passwordBuf = Buffer.from(password, "utf-8")`
4. **Timer**: Auto-expiry timer set (default 15 minutes). Timer is `unref()`'d to avoid keeping the process alive.
5. **Use**: `getPassword()` returns a **copy** of the buffer. Executor pipes it to `sudo -S` via stdin.
6. **Drop**: `drop()` zeroes the buffer (`passwordBuf.fill(0)`), clears state, fires `sudo -k` to invalidate system cache.
7. **Cleanup**: Process exit/signal handlers call `drop()` automatically.

**Status interface:**

```typescript
interface SudoSessionStatus {
  elevated: boolean;
  username: string | null;
  expiresAt: string | null;       // ISO 8601
  remainingSeconds: number | null;
}
```

### 4.5 Pre-flight ([`preflight.ts`](src/core/preflight.ts) + [`tool-wrapper.ts`](src/core/tool-wrapper.ts))

#### The Proxy Pattern

[`createPreflightServer()`](src/core/tool-wrapper.ts:96) creates a `Proxy<McpServer>` that intercepts only the `tool` property:

```typescript
return new Proxy(server, {
  get(target, prop, receiver) {
    if (prop === "tool") {
      return createWrappedToolMethod(target, ctx);
    }
    return Reflect.get(target, prop, receiver);
  },
});
```

The wrapped `.tool()` method:
1. Reads `args[0]` as tool name, `args[args.length - 1]` as handler (works for all 6 SDK overloads)
2. Checks bypass set (sudo management tools: `sudo_elevate`, `sudo_elevate_gui`, `sudo_status`, `sudo_drop`, `sudo_extend`, `preflight_batch_check`)
3. Wraps the handler in a pre-flight function
4. Forwards all args (with wrapped handler) to the real `server.tool()`

#### Pipeline Stages

The [`PreflightEngine.runPreflight()`](src/core/preflight.ts:241) method executes:

1. **Cache check**: Return cached passing result if available (60s TTL). Skipped when params are provided (safeguard checks depend on runtime params).
2. **Manifest resolution**: Look up [`ToolManifest`](src/core/tool-registry.ts:22) from the registry. Missing manifest → pass with warning.
3. **Dependency checking**: Check binaries, Python modules, npm packages, libraries, required files.
4. **Auto-installation**: If enabled and dependencies missing, attempt installation via `AutoInstaller.resolveAll()`.
5. **Privilege validation**: Check sudo requirements via `PrivilegeManager.checkForTool()`.
6. **Safeguard checks**: If params provided, run `SafeguardRegistry.checkSafety()` for blocking/warning conditions.
7. **Result assembly**: Determine pass/fail, generate human-readable summary.

#### Caching

| Cache | TTL | Invalidation |
|-------|-----|-------------|
| `PreflightEngine.resultCache` | 60s | `invalidatePreflightCaches()` after sudo elevate/drop |
| `PrivilegeManager.cachedStatus` | 30s | Same invalidation trigger |
| `dependency-validator` binary cache | Startup | `clearDependencyCache()` after auto-install |

### 4.6 Safeguards ([`safeguards.ts`](src/core/safeguards.ts))

The [`SafeguardRegistry`](src/core/safeguards.ts:140) singleton detects running applications and evaluates operation safety.

**Detection domains** (all run in parallel):
- VS Code (process, config dir, IPC sockets)
- Docker (socket, running containers)
- MCP servers (workspace config, node processes)
- Databases (TCP port probing: PostgreSQL:5432, MySQL:3306, MongoDB:27017, Redis:6379)
- Web servers (nginx, apache2, httpd process detection)

**Blocker conditions** (prevent execution):

| Condition | Trigger |
|-----------|---------|
| SSH lockout | SSH config modification while connected via SSH |
| SSH port block | Firewall rule dropping port 22 during SSH session |
| INPUT DROP policy | Setting INPUT default to DROP during SSH session |
| Password auth disable | Disabling PasswordAuthentication without authorized_keys |
| Database service stop | Stopping a database service with active connections |

**Warnings** (non-blocking): Docker networking impact, database connectivity, web server traffic, MCP server communication.

**Result interface:**

```typescript
interface SafetyResult {
  safe: boolean;           // true if no blockers
  warnings: string[];      // Non-blocking concerns
  blockers: string[];      // Fatal: operation should not proceed
  impactedApps: string[];  // Affected application categories
}
```

### 4.7 Changelog & Rollback ([`changelog.ts`](src/core/changelog.ts), [`rollback.ts`](src/core/rollback.ts), [`backup-manager.ts`](src/core/backup-manager.ts))

#### Changelog

**Entry schema:**

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

**State file schema (version 1):**

```typescript
interface ChangelogState {
  version: 1;
  entries: ChangeEntry[];
}
```

Stored at `~/.kali-defense/changelog.json`. Migrates from bare-array format (pre-v0.5.0). Max 10,000 entries with rotation.

#### Rollback Manager

**Change record types:** `"file" | "sysctl" | "service" | "firewall"`

```typescript
interface RollbackState {
  version: 1;
  changes: ChangeRecord[];
}
```

Stored at `~/.kali-defense/rollback-state.json`. Supports rollback by operation ID or session ID. Rollback strategies:
- **file**: Copy backup file back to original location
- **sysctl**: `sysctl -w <key>=<originalValue>`
- **service**: `systemctl start|stop <service>` (inverse of change)
- **firewall**: Execute the stored rollback command string

#### Backup Manager

```typescript
interface BackupManifest {
  version: 1;
  backups: BackupEntry[];
}

interface BackupEntry {
  id: string;           // UUID v4
  originalPath: string;
  backupPath: string;   // ~/.kali-defense/backups/<timestamp>_<filename>
  timestamp: string;    // ISO 8601
  sizeBytes: number;
}
```

Stored at `~/.kali-defense/backups/manifest.json`. Supports backup, restore by ID, listing, and pruning by age.

### 4.8 Secure FS ([`secure-fs.ts`](src/core/secure-fs.ts))

Six functions enforcing owner-only permissions:

| Function | Permission | Purpose |
|----------|-----------|---------|
| `secureWriteFileSync()` | 0o600 | Write file, create parent dirs at 0o700 |
| `secureMkdirSync()` | 0o700 | Create directory |
| `secureCopyFileSync()` | 0o600 | Copy file with secure dest permissions |
| `verifySecurePermissions()` | — | Check `(mode & 0o077) === 0` |
| `hardenFilePermissions()` | 0o600 | Fix existing file permissions |
| `hardenDirPermissions()` | 0o700 | Fix existing directory permissions |

All functions call `chmodSync()` explicitly after the operation to override any umask interference.

### 4.9 Spawn Safe ([`spawn-safe.ts`](src/core/spawn-safe.ts))

Low-level process spawning layer with **no dependencies on executor.ts or sudo-session.ts**. Used by modules that can't import the executor due to circular dependency concerns.

**Exports:**

- `spawnSafe(command, args, options)` → async `ChildProcess`
- `execFileSafe(command, args, options)` → sync `Buffer | string`

Both functions:
1. Resolve the command through the allowlist (`resolveCommand()`)
2. Force `shell: false` (non-negotiable)
3. Log to stderr
4. Fall back to `isAllowlisted()` if allowlist not yet initialized (early startup)

**Users:** [`sudo-session.ts`](src/core/sudo-session.ts:52) and [`auto-installer.ts`](src/core/auto-installer.ts:21)

### 4.10 Configuration ([`config.ts`](src/core/config.ts))

All configuration via environment variables with defensive defaults. `getConfig()` is called fresh each invocation.

```typescript
interface DefenseConfig {
  defaultTimeout: number;         // KALI_DEFENSE_TIMEOUT_DEFAULT (seconds→ms), default: 120s
  maxBuffer: number;              // KALI_DEFENSE_MAX_OUTPUT_SIZE, default: 10MB
  allowedDirs: string[];          // KALI_DEFENSE_ALLOWED_DIRS, default: /tmp,/home,/var/log,/etc
  logLevel: string;               // KALI_DEFENSE_LOG_LEVEL, default: "info"
  dryRun: boolean;                // KALI_DEFENSE_DRY_RUN, default: false (tools default true individually)
  changelogPath: string;          // KALI_DEFENSE_CHANGELOG_PATH, default: ~/.kali-defense/changelog.json
  backupDir: string;              // KALI_DEFENSE_BACKUP_DIR, default: ~/.kali-defense/backups
  autoInstall: boolean;           // KALI_DEFENSE_AUTO_INSTALL, default: false
  protectedPaths: string[];       // KALI_DEFENSE_PROTECTED_PATHS, default: /boot,/usr/lib/systemd,...
  requireConfirmation: boolean;   // KALI_DEFENSE_REQUIRE_CONFIRMATION, default: true
  quarantineDir: string;          // KALI_DEFENSE_QUARANTINE_DIR, default: ~/.kali-defense/quarantine
  policyDir: string;              // KALI_DEFENSE_POLICY_DIR, default: ~/.kali-defense/policies
  toolTimeouts: Record<string, number>; // KALI_DEFENSE_TIMEOUT_<TOOL>
  sudoSessionTimeout: number;     // KALI_DEFENSE_SUDO_TIMEOUT (minutes→ms), default: 15 min
}
```

Per-tool timeout overrides support 14 known tools: lynis, aide, clamav, oscap, snort, suricata, rkhunter, chkrootkit, tcpdump, auditd, nmap, fail2ban-client, debsums, yara.

### 4.11 Auto-Installer ([`auto-installer.ts`](src/core/auto-installer.ts))

Singleton multi-package-manager dependency resolver. Supports:

- **System packages**: apt, dnf, yum, pacman, apk, zypper, brew (7 managers)
- **Python modules**: pip3/pip with user-site fallback then sudo
- **npm packages**: `npm install -g` with user-level fallback then sudo
- **Libraries**: Dev-package pattern resolution per distro family

**Supply chain protections:**

1. Binary must be in `DEFENSIVE_TOOLS` catalog
2. Package name resolved from catalog (never raw binary name)
3. Package name validated via regex
4. Package must be in approved allowlist (built from catalog)
5. All installs logged to audit changelog

### 4.12 Distro Support ([`distro.ts`](src/core/distro.ts), [`distro-adapter.ts`](src/core/distro-adapter.ts))

**Detection cascade:**

1. `process.platform === "darwin"` → macOS
2. `/proc/version` contains "microsoft" → WSL
3. Parse `/etc/os-release` (ID, PRETTY_NAME, VERSION_ID)
4. Fall back to `lsb_release -a`
5. Fall back to distro-specific files (`/etc/debian_version`, `/etc/redhat-release`, etc.)

**Supported families:**

| Family | Distros | Package Manager | Init System |
|--------|---------|----------------|-------------|
| debian | Debian, Ubuntu, Kali, Mint, Pop, Elementary, Parrot | apt | systemd |
| rhel | RHEL, CentOS, Fedora, Rocky, AlmaLinux, Amazon | dnf/yum | systemd |
| arch | Arch, Manjaro | pacman | systemd |
| alpine | Alpine | apk | openrc |
| suse | openSUSE, SLES | zypper | systemd |

**DistroAdapter** provides unified access to:
- Package manager commands (`installCmd`, `removeCmd`, `updateCmd`, etc.)
- Service manager commands (`startCmd`, `stopCmd`, `enableCmd`, etc.)
- Firewall backend commands (iptables, nftables, ufw, firewalld)
- Distro-specific paths (syslog, auth log, PAM configs, GRUB, etc.)
- Package integrity checking (debsums, rpm -V, pacman -Qk)
- Auto-update configuration
- Firewall persistence setup

---

## 5. Tool System

### 5.1 Tool Registration Pattern

Every tool module exports a single function:

```typescript
export function registerXxxTools(server: McpServer): void {
  server.tool(
    "tool_name",               // 1st arg: tool name (string)
    "Description",             // 2nd arg: description (string)
    {                          // 3rd arg: Zod schema (plain object, NOT z.object())
      action: z.enum(["list", "add", "delete"]).describe("..."),
      param: z.string().optional().describe("..."),
      dry_run: z.boolean().optional().default(true).describe("Preview changes"),
    },
    async (params) => {        // 4th arg: handler function
      // 1. Validate inputs via sanitizer
      // 2. Build command args
      // 3. Execute via executeCommand()
      // 4. Log change via logChange()
      // 5. Return { content: [{ type: "text", text: "..." }] }
    },
  );
}
```

**Action parameter pattern**: Most tools use a single `action` enum parameter to consolidate related operations. For example, `firewall_iptables` accepts `action: "list" | "add" | "delete" | "set_policy" | "create_chain"`. This pattern reduced the tool count from 157 (pre-v0.5.0) to 78.

### 5.2 Tool Modules (21 files, 78 tools)

| # | Module | File | Tools | Tool Names |
|---|--------|------|-------|------------|
| 1 | Sudo Management | `sudo-management.ts` | 6 | sudo_elevate, sudo_elevate_gui, sudo_status, sudo_drop, sudo_extend, preflight_batch_check |
| 2 | Firewall | `firewall.ts` | 5 | firewall_iptables, firewall_ufw, firewall_persist, firewall_nftables_list, firewall_policy_audit |
| 3 | Hardening | `hardening.ts` | 8 | harden_sysctl, harden_service, harden_permissions, harden_systemd, harden_kernel, harden_bootloader, harden_misc, memory_protection |
| 4 | IDS | `ids.ts` | 3 | ids_aide_manage, ids_rootkit_scan, ids_file_integrity_check |
| 5 | Logging | `logging.ts` | 4 | log_auditd, log_journalctl_query, log_fail2ban, log_system |
| 6 | Network Defense | `network-defense.ts` | 3 | netdef_connections, netdef_capture, netdef_security_audit |
| 7 | Compliance | `compliance.ts` | 7 | compliance_lynis_audit, compliance_oscap_scan, compliance_check, compliance_policy_evaluate, compliance_report, compliance_cron_restrict, compliance_tmp_hardening |
| 8 | Malware | `malware.ts` | 4 | malware_clamav, malware_yara_scan, malware_file_scan, malware_quarantine_manage |
| 9 | Backup | `backup.ts` | 1 | backup |
| 10 | Access Control | `access-control.ts` | 6 | access_ssh, access_sudo_audit, access_user_audit, access_password_policy, access_pam, access_restrict_shell |
| 11 | Encryption | `encryption.ts` | 4 | crypto_tls, crypto_gpg_keys, crypto_luks_manage, crypto_file_hash |
| 12 | Container Security | `container-security.ts` | 6 | container_docker, container_apparmor, container_selinux_manage, container_namespace_check, container_image_scan, container_security_config |
| 13 | Meta | `meta.ts` | 5 | defense_check_tools, defense_workflow, defense_change_history, security_posture, scheduled_audit |
| 14 | Patch Management | `patch-management.ts` | 5 | patch_update_audit, patch_unattended_audit, patch_integrity_check, patch_kernel_audit, vulnerability_intel |
| 15 | Secrets | `secrets.ts` | 4 | secrets_scan, secrets_env_audit, secrets_ssh_key_sprawl, scan_git_history |
| 16 | Incident Response | `incident-response.ts` | 1 | incident_response |
| 17 | Supply Chain | `supply-chain-security.ts` | 1 | supply_chain |
| 18 | Drift Detection | `drift-detection.ts` | 1 | drift_baseline |
| 19 | Zero Trust | `zero-trust-network.ts` | 1 | zero_trust |
| 20 | eBPF Security | `ebpf-security.ts` | 2 | list_ebpf_programs, falco |
| 21 | App Hardening | `app-hardening.ts` | 1 | app_harden |

### 5.3 Tool Naming Convention

Tools follow a `category_action` or `category_subject` pattern:

- `firewall_iptables` — category + subject (action is a parameter)
- `harden_sysctl` — category + subject
- `access_ssh` — category + subject
- `ids_rootkit_scan` — category + specific_action
- `sudo_elevate` — category + action

Multi-word categories use underscores. The naming is consistent enough for the [`inferCategory()`](src/core/tool-registry.ts:215) function to map tool names to categories via prefix matching.

---

## 6. State Management

### 6.1 Directory Layout (`~/.kali-defense/`)

```
~/.kali-defense/                      [0o700]
├── changelog.json                    [0o600] — Versioned audit trail
├── rollback-state.json               [0o600] — Change tracking for rollback
├── backups/                          [0o700]
│   ├── manifest.json                 [0o600] — Backup inventory
│   ├── 2026-03-04T10-30-00-000Z_sshd_config  [0o600]
│   └── ...
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

- **Test runner**: vitest ^4.0.18
- **Coverage**: @vitest/coverage-v8 ^4.0.18
- **Config**: [`vitest.config.ts`](vitest.config.ts)

### 7.2 Test Structure

```
tests/
└── core/
    ├── changelog.test.ts
    ├── command-allowlist.test.ts
    ├── config.test.ts
    ├── safeguards.test.ts
    ├── sanitizer.test.ts
    └── secure-fs.test.ts
```

Tests cover `src/core/**/*.ts` only. Tool modules (`src/tools/**/*.ts`) and the entry point (`src/index.ts`) are excluded from coverage.

### 7.3 Coverage Targets

From [`vitest.config.ts`](vitest.config.ts:12):

```typescript
thresholds: {
  lines: 50,
  functions: 50,
  branches: 40,
  statements: 50,
}
```

Test timeout: 10,000ms. Environment: `node`. Globals enabled.

---

## 8. Dependencies

### 8.1 Runtime

| Package | Version | Purpose |
|---------|---------|---------|
| `@modelcontextprotocol/sdk` | ^1.12.1 | MCP server framework (McpServer, StdioServerTransport) |
| `zod` | ^3.25.0 | Schema validation for tool parameters |

### 8.2 Dev

| Package | Version | Purpose |
|---------|---------|---------|
| `typescript` | ^5.8.3 | TypeScript compiler |
| `@types/node` | ^22.15.0 | Node.js type definitions |
| `vitest` | ^4.0.18 | Test runner |
| `@vitest/coverage-v8` | ^4.0.18 | Code coverage |
| `tsx` | ^4.19.4 | TypeScript execution for development (`npm run dev`) |

### 8.3 System (External Binaries)

The server operates on 115 allowlisted binaries. Key categories:

| Category | Required Binaries | Optional Binaries |
|----------|------------------|-------------------|
| Firewall | iptables, ufw | ip6tables, nft, netfilter-persistent |
| Hardening | sysctl, systemctl, stat, cat | lsmod, modprobe, readelf, checksec |
| IDS | sha256sum | aide, rkhunter, chkrootkit |
| Logging | journalctl | auditctl, ausearch, aureport, fail2ban-client |
| Network | ss | tcpdump, nmap, ip |
| Compliance | | lynis, oscap |
| Malware | | clamscan, freshclam, yara |
| Access | cat | sshd, passwd, usermod, chage |
| Crypto | openssl | gpg, cryptsetup |
| Container | | docker, trivy, grype, apparmor_status |
| Package Mgmt | | apt, dpkg, dnf, rpm, pacman, apk, zypper |

---

## 9. Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KALI_DEFENSE_TIMEOUT_DEFAULT` | `120` (seconds) | Default command timeout |
| `KALI_DEFENSE_MAX_OUTPUT_SIZE` | `10485760` (10MB) | Max stdout/stderr buffer |
| `KALI_DEFENSE_ALLOWED_DIRS` | `/tmp,/home,/var/log,/etc` | Directories allowed for file operations |
| `KALI_DEFENSE_LOG_LEVEL` | `info` | Log level: debug, info, warn, error |
| `KALI_DEFENSE_DRY_RUN` | `false`* | Global dry-run mode (*tools default true individually) |
| `KALI_DEFENSE_CHANGELOG_PATH` | `~/.kali-defense/changelog.json` | Changelog file location |
| `KALI_DEFENSE_BACKUP_DIR` | `~/.kali-defense/backups` | Backup directory |
| `KALI_DEFENSE_AUTO_INSTALL` | `false` | Auto-install missing tools via package manager |
| `KALI_DEFENSE_PROTECTED_PATHS` | `/boot,/usr/lib/systemd,/usr/bin,/usr/sbin` | Paths protected from modification |
| `KALI_DEFENSE_REQUIRE_CONFIRMATION` | `true` | Require confirmation for destructive actions |
| `KALI_DEFENSE_QUARANTINE_DIR` | `~/.kali-defense/quarantine` | Malware quarantine directory |
| `KALI_DEFENSE_POLICY_DIR` | `~/.kali-defense/policies` | Custom compliance policy files |
| `KALI_DEFENSE_TIMEOUT_<TOOL>` | — | Per-tool timeout in seconds (e.g., `KALI_DEFENSE_TIMEOUT_LYNIS=300`) |
| `KALI_DEFENSE_SUDO_TIMEOUT` | `15` (minutes) | Sudo session expiry timeout |
| `KALI_DEFENSE_PREFLIGHT` | `true` | Enable/disable pre-flight validation |
| `KALI_DEFENSE_PREFLIGHT_BANNERS` | `true` | Prepend status banners to tool output |

---

## 10. Future Considerations

Items intentionally deferred from the current implementation:

- **Rate limiting**: `config.ts` has no rate limit implementation (placeholder removed)
- **Multi-user sessions**: `SudoSession` is a process-wide singleton; no per-user credential isolation
- **Network transport**: Only stdio supported; no HTTP/SSE/WebSocket transport
- **Network timeouts**: No connect-timeout for remote TLS checks or port probes
- **Tool-level RBAC**: No role-based access control per tool
- **Encrypted state files**: State files use permission-based security only (0o600), not encryption at rest
- **Atomic state file writes**: No write-then-rename pattern for crash safety
- **Structured logging**: All logging goes to stderr as unstructured text (`console.error`)
- **Metrics/telemetry**: No Prometheus, OpenTelemetry, or other metrics export
- **Plugin system**: Tool modules are statically imported; no dynamic loading
- **Changelog size limits**: 10,000 entry cap exists but no time-based retention policy
- **Cross-platform**: Linux only; macOS detection exists in `distro.ts` but tools are Linux-specific
