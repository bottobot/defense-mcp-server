# Changelog

All notable changes to the defense-mcp-server are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [0.7.1] — 2026-03-14

### v0.7.1 — Critical PAM Hardening Fix

#### Security Fix
- **CRITICAL**: Fixed `pam_configure` action corrupting `/etc/pam.d/common-auth` — sed commands stripped whitespace separators between PAM fields, breaking ALL authentication system-wide (required GRUB recovery to fix)
- **CRITICAL**: Fixed `[success=N]` jump count not being updated after faillock rule insertion — would cause authentication denial on Debian/Ubuntu systems

#### New Module: `src/core/pam-utils.ts`
- Safe in-memory PAM config parser/serializer replacing fragile sed-based manipulation
- `parsePamConfig()` — Lossless parser handling comments, blanks, `@include`, bracket-style controls
- `serializePamConfig()` — Serializer with proper formatting (matching `pam-auth-update` canonical format)
- `validatePamConfig()` — Triple validation: field formatting, module existence, and `[success=N]` jump count correctness
- `adjustJumpCounts()` — Automatically updates bracket-control jump counts when rules are inserted/removed
- Manipulation helpers: `removeModuleRules()`, `insertBeforeModule()`, `insertAfterModule()` with pamType filter
- Sudo-aware I/O: `readPamFile()`, `writePamFile()` (atomic via `sudo install`), `backupPamFile()`, `restorePamFile()`

#### Safety Layers (Defense-in-Depth)
- Mandatory backup before any PAM file modification
- In-memory validation before writing (catches corrupted fields, missing pam_unix.so, wrong jump counts)
- Atomic file write using `sudo install -m 644 -o root -g root` (no partial state)
- Post-write re-read validation
- Auto-rollback on ANY failure (restores from backup automatically)

#### Security Review Remediations
- Fixed partial write state on chmod/chown failure (atomic `sudo install`)
- Fixed temp file symlink race (secure `mkdtempSync`)
- Fixed insert helpers matching by module only (added pamType filter)
- Fixed `backupPamFile` mutating BackupEntry internal state
- Fixed `restorePamFile` leaking PAM content to stdout via `tee`
- Added PAM modification warning to SafeguardRegistry

#### Testing
- 63 new tests in `tests/core/pam-utils.test.ts` covering parser, serializer, validator, jump count adjustment, manipulation helpers, and full faillock integration flow
- 7 new tests in `tests/tools/access-control.test.ts` for pam_configure regression testing
- Critical regression test: verifies concatenated PAM fields (the original lockout bug) can never be produced

## [0.7.0] — 2026-03-12

### v0.7.0 — Tool Consolidation & Sudo Hardening Overhaul

#### Tool Consolidation (94 → 31 tools, −67%, zero capability loss)
- Merged all 94 granular MCP tools into 31 domain-grouped tools using action discriminators
- Every previous capability preserved via `action` parameters within each consolidated tool
- Reduces MCP registration overhead by 67% while maintaining full security coverage
- All 1,802 tests passing across 62 test files

#### Sudo Hardening
- **Removed `NOPASSWD: ALL`** sudoers grant — eliminated overly-broad privilege escalation
- **Scoped allowlist** (`etc/sudoers.d/mcpuser`): 94-command explicit allowlist covering only required security binaries (iptables, ufw, aide, rkhunter, clamav, auditd, etc.)
- **NOPASSWD regression detection**: `SudoGuard.checkNopasswdConfiguration()` runs at server startup to detect any re-introduction of broad sudo grants
- **Rate limiting** on sudo elevation: `RateLimiter` wired into `SudoSession.elevate()` (5 attempts per 5-minute window)
- **Structured audit trail**: `logger.security()` emits JSON audit events for all elevation, drop, extension, and timeout events

#### Docker Entrypoint
- New `docker-entrypoint.sh`: sets `mcpuser` password from Docker secret (`/run/secrets/mcpuser_password`) or `MCPUSER_PASSWORD` env var at container startup
- Credentials zeroed from environment after use, privileges dropped before handing off to the MCP server process
- Prevents hardcoded or empty passwords in container images

#### New Modules
- `src/tools/integrity.ts` — Absorbs and supersedes `ids.ts` + `drift-detection.ts`; unified integrity checking with IDS baseline management, drift detection, and file integrity verification
- `etc/sudoers.d/mcpuser` — Scoped sudoers allowlist (94 commands, no wildcards)
- `docker-entrypoint.sh` — Secure container password bootstrap script

#### Infrastructure
- `src/core/sudo-session.ts` — Integrated `RateLimiter` for elevation throttling
- `src/core/sudo-guard.ts` — Added `checkNopasswdConfiguration()` startup regression check
- `src/core/rate-limiter.ts` — Extended to support sudo-specific rate limiting context
- Updated `TOOLS-REFERENCE.md` and `TOOL-CONSOLIDATION-PLAN.md` to reflect 31-tool architecture

---

## [0.6.0] — 2026-03-09

### v0.6.0 — 16 New Security Tools

#### Added
- **Reporting** — `report_export` tool: generate consolidated security reports in Markdown/HTML/JSON/CSV
- **DNS Security** — `dns_security` tool: DNSSEC validation, DNS tunneling detection, domain blocklists, query log analysis
- **Vulnerability Management** — `vuln_manage` tool: nmap/nikto vulnerability scanning, vulnerability lifecycle tracking, risk prioritization
- **Forensics** — `ir_forensics` tool: memory acquisition, forensic disk imaging, evidence chain-of-custody
- **Process Security** — `process_security` tool: capability auditing, namespace isolation, anomaly detection (deleted binaries, shell spawning)
- **WAF Management** — `waf_manage` tool: ModSecurity audit/rules, OWASP CRS deployment, rate limiting, WAF log analysis
- **Network Segmentation** — `network_segmentation_audit` tool: zone mapping, isolation verification, path testing, VLAN auditing
- **Threat Intelligence** — `threat_intel` tool: IP/hash/domain checking against feeds, blocklist application to iptables/fail2ban
- **Auto-Remediation** — `auto_remediate` tool: consolidated remediation planning, batch safe-fix application with rollback sessions
- **Cloud Security** — `cloud_security` tool: AWS/GCP/Azure detection, IMDS security, IAM credential scanning, cloud storage audit
- **API Security** — `api_security` tool: local API discovery, auth auditing, rate-limit testing, TLS verification, CORS checking
- **Deception/Honeypots** — `honeypot_manage` tool: canary token deployment, honeyport listeners, trigger monitoring
- **Wireless Security** — `wireless_security` tool: Bluetooth/WiFi auditing, rogue AP detection, interface disabling
- **Certificate Lifecycle** — `certificate_lifecycle` tool: cert inventory, Let's Encrypt renewal check, CA trust store audit, OCSP, CT logs
- **SIEM Integration** — `siem_export` tool: rsyslog/Filebeat configuration, log forwarding audit, connectivity testing
- **USB Device Control** — `usb_device_control` tool: device auditing, storage blocking (modprobe/udev), whitelisting, event monitoring

#### Infrastructure
- Added 37 new binary entries to command allowlist
- Added 16 new tool dependency declarations
- Updated TOOLS-REFERENCE.md with documentation for all 16 new tools
- 1,801 total tests passing across 60 test files

---

## [0.5.2] — 2026-03-09

### Security
- Upgraded `@modelcontextprotocol/sdk` from 1.12.3 to 1.27.1 (fixes 3 high-severity CVEs: ReDoS, cross-client data leak, DNS rebinding)
- Removed accidental self-referential dependency
- `npm audit` now reports 0 vulnerabilities

---

## [0.5.1] — 2026-03-09

### Stable Release
First stable release incorporating complete security audit remediation.

- **78 security findings resolved** (12 Critical, 22 High, 29 Medium, 15 Low)
- **1054 tests** across 49 test files (71.66% line coverage)
- **78 defensive security tools** across 21 modules
- Clean TypeScript build with zero errors
- Pinned runtime dependencies for reproducible builds
- Published to npm as stable release

See [CHANGELOG for 0.5.0-beta.3 through 0.5.0-beta.6](CHANGELOG.md) for detailed remediation history.

---

## [0.5.0-beta.5] — 2026-03-08

### GA Readiness — Phase 10
- **Tool naming consistency:** 7 tools renamed to follow `prefix_subject` convention
- **Specification rewrite:** Complete rewrite of defense-mcp-server-spec.md (12 sections)
- **Dependency pinning:** Runtime deps pinned to exact versions, dev deps to tilde ranges
- **Encrypted state storage:** New `src/core/encrypted-state.ts` — AES-256-GCM with PBKDF2 key derivation
- **Atomic file writes:** New `atomicWriteFileSync()` in `src/core/secure-fs.ts` with write-to-temp-then-rename
- **Test coverage:** 1054 tests across 49 files (up from 421/12 at audit baseline)
- **Pen test requirements:** Documented in docs/PENTEST-REQUIREMENTS.md
- **Documentation sync:** All 7 documentation files updated to v0.5.0 with accurate module/tool counts

### Summary Since Audit (v0.5.0-beta.2 → v0.5.0-beta.5)
- **78/78 security findings** resolved (12 Critical, 22 High, 29 Medium, 15 Low)
- **Security score:** 36/100 → target 80+ (pending re-assessment)
- **Tests:** 421 → 1054 (+150%)
- **New security infrastructure:** Rate limiter, structured logger, encrypted state, atomic writes, CodeQL SAST, ESLint security, husky pre-commit

---

## [0.5.0-rc.1] — 2026-03-07

### Security — Complete Audit Remediation (Phases 7-9)

#### Phase 7: Medium-Severity Fixes (29/29) ✅
- **Core hardening (7):** stdin buffer zeroing on error (CORE-011), config rejects `/` in allowedDirs (CORE-012), policy savePolicy uses secure-fs (CORE-013), resolveCommandSafe fails hard instead of bare fallback (CORE-014), backup manager path traversal protection (CORE-015), askpass candidate verification (CORE-016), safe Python module detection via pip show (CORE-017)
- **Tool validation (12):** Path traversal protection in logging/IDS/firewall/drift-detection/backup tools (TOOL-015/016/017/024/026), BPF filter injection prevention (TOOL-018), privilege pre-checks in hardening (TOOL-019), secure-fs enforcement (TOOL-020), error message sanitization in secrets (TOOL-021), network parameter validation (TOOL-022), encryption algorithm allowlist (TOOL-023), supply chain package name & URL validation (TOOL-025)
- **CI/CD hardening (10):** Multi-OS matrix (CICD-002), dependency caching (CICD-003), ESLint security plugin (CICD-009), build verification script (CICD-010), secure defaults (CICD-014), signed commits note (CICD-015), architecture doc sync (CICD-017), tilde version ranges for runtime deps (CICD-022), rate limiter (CICD-024), structured JSON logger (CICD-027)

#### Phase 8: Low-Severity Fixes (15/15) ✅
- **Core robustness (4):** Argument redaction in spawn-safe logs (CORE-018), shell metachar regex backslash fix (CORE-019), sync-only uncaughtException handler (CORE-020), singleton protection via module-scoped instances (CORE-021)
- **Tool consistency (6):** All dry_run defaults standardized to true (TOOL-027), dry-run parameter additions (TOOL-028), error sanitization helper (TOOL-029), strict identifier regex (TOOL-030), eliminated empty catch blocks (TOOL-031), Zod .min(1) constraints (TOOL-032)
- **CI/CD & DX (5):** Changelog check script (CICD-004), license compliance checker (CICD-011), test naming convention docs (CICD-016), husky pre-commit hooks (CICD-018), sudo session user tracking (CICD-028)

#### Phase 9: Test Coverage Push
- 6 new core test files: installer, dependency-validator, distro-adapter, tool-dependencies, rate-limiter, logger
- 13 new tool test files: all remaining tool modules now have test coverage
- **Total: 873 tests across 47 test files** (up from 421/12 at audit time)
- Every source module (26 core + 21 tools) now has a corresponding test file

### New Modules
- `src/core/rate-limiter.ts` — Per-tool and global invocation rate limiting
- `src/core/logger.ts` — Structured JSON logging with security event level
- `eslint.config.mjs` — ESLint security plugin configuration
- `.husky/pre-commit` — Type-check pre-commit hook
- `.github/workflows/codeql.yml` — CodeQL SAST workflow

---

## [0.5.0-beta.3] — 2026-03-07

### Security — Audit Remediation Phase 6
- **CRITICAL fixes (12 findings):** Hardened rollback command validation (CORE-003), eliminated shell invocations across 5 tool modules (TOOL-001–005), fixed printf format string injection in mcp-call.sh (CICD-020), added npm audit script (CICD-006), synchronized lockfile (CICD-023)
- **HIGH fixes (22 findings):** Password Buffer handling (CORE-005), SUDO_ASKPASS integrity checks (CORE-006), TOCTOU binary path verification (CORE-007), auto-installer package allowlists (CORE-008), ReDoS regex limits (CORE-009), removed hardcoded paths (CORE-010), path traversal protection in malware/hardening tools (TOOL-006/007), nftables table validation (TOOL-008), secure-fs enforcement for AppArmor/Falco/seccomp writes (TOOL-009/010/011), SSH config input validation (TOOL-012), safe dry_run defaults in compliance tools (TOOL-013/014), disabled source maps (CICD-001), pinned Actions to SHA (CICD-005), added CodeQL SAST (CICD-007), CI coverage enforcement (CICD-008), removed /etc from default allowedDirs (CICD-013), secured run-assessment.mjs distribution (CICD-021)

### Testing
- 242 new tests across 16 new test files (8 core + 8 tool modules)
- Total: 663 tests across 28 test files (up from 421/12)
- All security remediation code paths covered

### CI/CD
- GitHub Actions pinned to immutable commit SHAs
- CodeQL SAST workflow added (.github/workflows/codeql.yml)
- Coverage enforcement step in CI pipeline
- npm audit security check script added
- .npmignore created to exclude dev-only files from distribution

---

## [0.5.0-beta.2] — 2026-03-07

### Phase 5: Hardening & Robustness

- **Fix 5.1: Startup Error Isolation** — Each of the 21 tool module registrations is wrapped in try/catch. Failed modules are logged but don't crash the server. Summary shows registered/failed count.
- **Fix 5.2: Graceful Shutdown** — SIGTERM/SIGINT handlers zero the sudo password buffer, log shutdown to changelog. uncaughtException and unhandledRejection handlers prevent silent crashes.
- **Fix 5.3: Network Timeout Handling** — Added `commandTimeout` (120s) and `networkTimeout` (30s) config options. Executor enforces SIGTERM→SIGKILL escalation on timeout. `spawn-safe.ts` passes timeout to `execFileSync`. NVD API calls use configurable timeout.
- **Fix 5.4: Binary Integrity Verification** — 14 critical security binaries verified against expected distro packages at startup via `dpkg -S`/`rpm -qf`/`pacman -Qo`. Warnings logged for unverified or unexpected ownership.
- **Fix 5.5: Expanded Test Coverage** — Added 87 new tests (executor, rollback, spawn-safe, backup-manager). Total: 323 tests across 10 test files. All passing.
- **Fix 5.6: Changelog User Attribution** — `ChangeEntry` now includes `user` (OS username, auto-populated) and `sessionId` (optional MCP session identifier) fields.

### Changed

- `src/index.ts` — `safeRegister()` wrapper, graceful shutdown handlers, binary integrity verification at startup
- `src/core/config.ts` — Added `commandTimeout` and `networkTimeout` configuration options
- `src/core/executor.ts` — Timeout enforcement with SIGTERM→SIGKILL escalation
- `src/core/spawn-safe.ts` — Timeout passthrough to `execFileSync`
- `src/core/command-allowlist.ts` — `verifyBinaryOwnership()` and `verifyAllBinaries()` functions
- `src/core/changelog.ts` — `user` and `sessionId` fields on `ChangeEntry`
- `src/tools/patch-management.ts` — NVD API calls use configurable network timeout
- `package.json` — Version `0.5.0-beta.2`

---

## [0.5.0-beta.1] — 2026-03-06

### Summary

Major security remediation release consolidating 157 tools down to 78 action-based tools across 21 modules. Introduces security hardening of the server itself including password buffer security, command allowlisting, auto-install safeguards, secure file permissions, comprehensive test infrastructure, and unified backup/rollback.

### Security Fixes (Phase 1)

- **Fix 1.1: Password Buffer Pipeline** — Sudo password now stored in a zeroable `Buffer` (not V8-interned strings). Auto-expires after configurable timeout. Temp files overwritten with random bytes before deletion.
- **Fix 1.2: Command Allowlist** — All commands executed via `spawn()` are resolved against a strict allowlist of known-safe binaries. Unknown binaries are rejected before execution. Paths resolved to absolute at startup.
- **Fix 1.3: Auto-Install Hardening** — `KALI_DEFENSE_AUTO_INSTALL` now defaults to `false`. When enabled, only packages from the `DEFENSIVE_TOOLS` catalog are installable — arbitrary package names are blocked.
- **Fix 1.4: Secure File Permissions** — All state files (`changelog.json`, `rollback-state.json`, backups, quarantine) created with `0o600`/`0o700` permissions. Existing directories hardened at startup via `hardenDirPermissions()`.

### Test Infrastructure (Phase 2)

- **Fix 2.1: Vitest Test Suite** — 221 tests across 6 test files covering sanitizer, config, command-allowlist, secure-fs, changelog, and safeguards modules. All tests pass with zero failures.
- **Fix 2.2: Backup/Rollback Unification** — `BackupManager` and `RollbackManager` consolidated under `~/.kali-defense/` with consistent secure file permissions.
- **Fix 2.3: Safeguards Real Blockers** — `SafeguardRegistry.checkSafety()` now produces real blocking conditions, not just advisory warnings.
- **Fix 2.4: spawn-safe.ts Circular Dependency** — Extracted safe spawn helper to break circular dependency between `executor.ts` and `sudo-session.ts`.

### Tool Consolidation (Phase 3)

- **Fix 3.1: Tool Consolidation 157 → 78** — Merged granular single-purpose tools into action-based tools with `action` parameters. For example, `harden_sysctl_get`, `harden_sysctl_set`, and `harden_sysctl_audit` became `harden_sysctl` with `action: "get" | "set" | "audit"`. This reduces MCP tool registration overhead while maintaining all functionality.
- **Fix 3.2: Document Synchronization** — All documentation (`README.md`, `ARCHITECTURE.md`, `TOOLS-REFERENCE.md`, `PREFLIGHT-ARCHITECTURE.md`, `SAFEGUARDS.md`, `CHANGELOG.md`) updated to reflect 78 tools across 21 modules. Version strings synchronized to `0.5.0-beta.1`.

### Changed

- `src/core/tool-dependencies.ts` — Rewritten for 78 consolidated tool names with union of absorbed tool dependencies
- `src/core/tool-registry.ts` — Rewritten with 78 tool sudo overlays matching new consolidated names
- `src/index.ts` — Version bumped to `0.5.0-beta.1`; tool count updated to 78
- `package.json` — Version `0.5.0-beta.1`; description updated to "78 defensive security tools"
- All 21 tool modules in `src/tools/` — Consolidated from fine-grained tools to action-based tools

---

## [0.4.0-beta.2] — 2026-03-04

**Critical Fix — `firewall_set_policy`:**
- Auto-injects loopback (`lo` ACCEPT) and established/related connection ACCEPT rules before setting INPUT or FORWARD default policy to DROP — prevents network lockout
- Aborts with clear error if prerequisite safety rules fail to add
- IPv6 safety rules also injected when `ipv6=true`

**Bug Fixes — `compliance_cis_check` (5 detection improvements):**
- CIS-1.1.4: Now checks `/etc/fstab` for `noexec` in addition to live mount options
- CIS-1.5.1-limits: Uses `sudo grep` across `limits.conf` and `limits.d/`
- CIS-5.5.5: Checks `login.defs`, `/etc/profile`, and `/etc/bash.bashrc` for umask
- CIS-5.1.8: Uses `sudo test` for root-owned 600-perm `cron.allow`
- CIS-5.1.9: Uses `sudo test` for root-owned 600-perm `at.allow`

These fixes improve CIS detection accuracy from ~71% to ~87% on hardened systems.

---

## [0.4.0-beta.1] — 2026-03-03

**New Features:**
- 🔐 `sudo_elevate_gui` — Secure two-phase GUI password elevation. Password never visible to the AI.
- 📋 Updated README with Getting Started guide, MCP client setup instructions, and sudo security documentation
- 🔢 Synced all version references to beta versioning scheme

**Sudo Management:**
- Added `sudo_elevate_gui` tool with native zenity/kdialog password dialog
- Two-phase flow: GUI captures password to temp file → MCP server reads, elevates, and securely wipes (2x random overwrite + unlink)
- File permission validation (rejects non-600 files)
- Added to pre-flight bypass list in tool-wrapper.ts

---

## [0.3.0] — 2026-03-03

### Summary

Adds a comprehensive pre-flight validation system that automatically checks dependencies, detects privilege requirements, and optionally auto-installs missing packages before every tool invocation — transparently, with zero changes to existing tool handlers.

---

### Added

#### Pre-flight Validation Middleware (`src/core/tool-wrapper.ts`)
- `createPreflightServer()` — Proxy-based middleware that wraps `McpServer` to intercept `.tool()` registrations and inject pre-flight validation before every tool handler
- Transparent integration via JavaScript `Proxy` pattern — all 29 existing tool registration files work without modification
- Configurable bypass set for sudo management tools (`sudo_elevate`, `sudo_status`, `sudo_drop`, `sudo_extend`)
- Optional status banners prepended to tool output when there are warnings or auto-installed dependencies
- Safety net: if pre-flight itself throws unexpectedly, falls through to the original handler

#### Enhanced Tool Manifest Registry (`src/core/tool-registry.ts`)
- `ToolRegistry` singleton with O(1) manifest lookup for all 155 tools
- `ToolManifest` type supporting: required/optional binaries, Python modules, npm packages, system libraries, required files, sudo level (`never`/`always`/`conditional`), Linux capabilities, category, and tags
- `SUDO_OVERLAYS` — static privilege annotations for all 155 tools derived from handler analysis
- `initializeRegistry()` — merges legacy `TOOL_DEPENDENCIES` binary data with privilege overlays
- Category inference from tool name prefixes

#### Privilege Detection (`src/core/privilege-manager.ts`)
- `PrivilegeManager` singleton with 30-second cached status
- Detects UID/EUID via `process.getuid()`/`process.geteuid()`
- Parses Linux capabilities from `/proc/self/status` CapEff hex bitmask (41 capability names mapped)
- Tests passwordless sudo via `sudo -n true`
- Checks active `SudoSession` cached credentials
- Reads user group memberships via `id -Gn`
- `checkForTool(manifest)` evaluates tool's privilege requirements against current state

#### Auto-Dependency Resolution (`src/core/auto-installer.ts`)
- `AutoInstaller` singleton supporting 8+ package managers: apt, dnf, yum, pacman, apk, zypper, brew, pip, and npm
- Resolves distro-specific package names from the `DEFENSIVE_TOOLS` catalog
- Python module installation: tries user-site (`--user`) first, falls back to sudo
- npm package installation: tries non-sudo first, falls back to sudo
- Library installation: generates distro-family-specific dev package name candidates
- Post-install verification for all dependency types

#### Pre-flight Orchestration Engine (`src/core/preflight.ts`)
- `PreflightEngine` singleton with 60-second result cache (passing results only)
- Full pipeline: manifest resolution → dependency checking (binary, Python, npm, library, file) → auto-installation → privilege validation → pass/fail determination
- Structured `PreflightResult` with checked/missing/installed deps, privilege issues, errors, warnings
- `formatSummary()` — human-readable pass/fail output with install hints and resolution steps
- `formatStatusMessage()` — compact one-line status for prepending to tool output

#### New Environment Variables
- `KALI_DEFENSE_PREFLIGHT` (default: `true`) — enable/disable pre-flight checks entirely
- `KALI_DEFENSE_PREFLIGHT_BANNERS` (default: `true`) — show pre-flight status banners in tool output

### Changed

- `src/index.ts` — Wraps `McpServer` with `createPreflightServer()` proxy; initializes the tool registry at startup
- `src/tools/sudo-management.ts` — Calls `invalidatePreflightCaches()` on `sudo_elevate` and `sudo_drop` to clear stale privilege/dependency caches

---

## [2.0.0] — 2026-02-21

### Summary

Major release expanding the server from 69 tools across 12 categories to 130+ tools across 26 categories. Introduces application safeguards, rollback infrastructure, a dedicated BackupManager, 11 new tool modules, and multi-framework compliance support.

---

### New Tool Modules (11 modules, ~65 new tools)

#### Supply Chain Security (`supply-chain-security.ts`)
- `generate_sbom` — Generate Software Bill of Materials using syft, cdxgen, or dpkg/rpm fallback
- `verify_package_integrity` — Verify installed package checksums (debsums/rpm -V)
- `setup_cosign_signing` — Sign container images or artifacts with cosign (keyless or key-based)
- `check_slsa_attestation` — Verify SLSA provenance attestation for binaries or artifacts

#### Memory Protection (`memory-protection.ts`)
- `audit_memory_protections` — Audit ASLR, PIE, RELRO, NX, stack canary on specified binaries
- `enforce_aslr` — Enable full ASLR by setting kernel.randomize_va_space=2
- `report_exploit_mitigations` — Report system-wide exploit mitigation status (SMEP, SMAP, PTI, KASLR)

#### Drift Detection (`drift-detection.ts`)
- `create_baseline` — Create system baseline (file hashes, sysctl state, service states)
- `compare_to_baseline` — Compare current system state against a saved baseline
- `list_drift_alerts` — List available baselines and summarize changes since last baseline

#### Vulnerability Intelligence (`vulnerability-intel.ts`)
- `lookup_cve` — Look up CVE details from the NVD API
- `scan_packages_cves` — Scan installed packages for known CVEs
- `get_patch_urgency` — Get patch urgency for a specific package

#### Security Posture (`security-posture.ts`)
- `calculate_security_score` — Weighted security score (0-100) across 7 security domains
- `get_posture_trend` — Compare current score against historical scores
- `generate_posture_dashboard` — Structured posture dashboard with findings and recommendations

#### Secrets Scanner (`secrets-scanner.ts`)
- `scan_for_secrets` — Directory secrets scan using truffleHog, gitleaks, or built-in grep patterns
- `audit_env_vars` — Audit current process environment variables for potential secrets
- `scan_git_history` — Scan git repository history for leaked secrets

#### Zero-Trust Network (`zero-trust-network.ts`)
- `setup_wireguard` — Set up WireGuard VPN interface with key generation and configuration
- `manage_wg_peers` — Add, remove, or list WireGuard peers
- `setup_mtls` — Generate CA, server, and client certificates for mutual TLS authentication
- `configure_microsegmentation` — Configure iptables/nftables rules for service-level microsegmentation

#### Container Advanced (`container-advanced.ts`)
- `generate_seccomp_profile` — Generate custom seccomp profile JSON from allowed syscall list
- `apply_apparmor_container` — Generate and optionally load an AppArmor profile for a container
- `setup_rootless_containers` — Configure rootless container support (newuidmap/newgidmap, user namespaces)
- `scan_image_trivy` — Scan container image for vulnerabilities using Trivy

#### Compliance Extended (`compliance-extended.ts`)
- `run_compliance_check` — Run structured compliance checks against PCI-DSS v4, HIPAA, SOC 2, ISO 27001, or GDPR frameworks

#### eBPF Security (`ebpf-security.ts`)
- `list_ebpf_programs` — List loaded eBPF programs and pinned maps
- `check_falco` — Check Falco runtime security status, version, and configuration
- `deploy_falco_rules` — Deploy custom Falco rules to /etc/falco/rules.d/
- `get_ebpf_events` — Read recent Falco events from the JSON log

#### Automation Workflows (`automation-workflows.ts`)
- `setup_scheduled_audit` — Create scheduled security audit using systemd timer or cron
- `list_scheduled_audits` — List all scheduled security audits
- `remove_scheduled_audit` — Remove a scheduled security audit by name
- `get_audit_history` — Read historical output from scheduled audit jobs

---

### New Tools in Existing Modules

#### Firewall Management (5 new tools, 12 total)
- `firewall_nftables_list` — List nftables ruleset; nftables is the modern replacement for iptables
- `firewall_set_policy` — Set default chain policy (INPUT/FORWARD/OUTPUT) with rollback tracking
- `firewall_create_chain` — Create custom iptables chain with optional ip6tables mirror
- `firewall_persistence` — Manage iptables-persistent: install, save, and check persistence status
- `firewall_policy_audit` — Audit firewall configuration for default policy issues and misconfigurations

#### System Hardening (12 new tools, 19 total)
- `harden_systemd_audit` — Audit service units using systemd-analyze security; scores 40+ properties
- `harden_kernel_security_audit` — Audit CPU vulnerability mitigations, Landlock, lockdown mode, ASLR
- `harden_bootloader_audit` — Audit GRUB: password protection, Secure Boot status, kernel parameters
- `harden_module_audit` — Audit kernel module blacklisting per CIS benchmark
- `harden_cron_audit` — Audit cron and at access control configuration (cron.allow/deny)
- `harden_umask_audit` — Audit default umask in login.defs, profile, bashrc
- `harden_banner_audit` — Audit login warning banners per CIS benchmark
- `harden_umask_set` — Set default umask across login.defs, /etc/profile, /etc/bash.bashrc
- `harden_coredump_disable` — Disable core dumps via limits.conf, coredump.conf, and sysctl
- `harden_banner_set` — Set CIS-compliant login warning banner content
- `harden_bootloader_configure` — Configure GRUB kernel parameters (add_kernel_params/status)
- `harden_systemd_apply` — Apply systemd security hardening overrides (basic/strict preset)

#### Logging and Monitoring (3 new tools, 10 total)
- `log_auditd_cis_rules` — Check or deploy complete set of CIS Benchmark-required auditd rules
- `log_rotation_audit` — Audit logrotate configuration and journald persistence settings
- `log_fail2ban_audit` — Audit fail2ban jail configurations for weak ban times and missing jails

#### Network Defense (2 new tools, 8 total)
- `netdef_ipv6_audit` — Audit IPv6 configuration, firewall status, and whether IPv6 should be disabled
- `netdef_self_scan` — Run nmap self-scan to discover exposed services from a network perspective

#### Compliance and Benchmarking (2 new tools, 7 total)
- `compliance_cron_restrict` — Create/manage /etc/cron.allow and /etc/at.allow (CIS 5.1.8, 5.1.9)
- `compliance_tmp_hardening` — Audit and apply /tmp mount hardening with nodev,nosuid,noexec

#### Malware Analysis (1 new tool, 6 total)
- `malware_webshell_detect` — Scan web server directories for web shells using pattern matching

#### Access Control (3 new tools, 9 total)
- `access_ssh_cipher_audit` — Audit SSH cryptographic algorithms against Mozilla/NIST recommendations
- `access_pam_configure` — Configure PAM modules: pam_pwquality (complexity) and pam_faillock (lockout)
- `access_restrict_shell` — Restrict a user's login shell to nologin or /bin/false

#### Container Security (4 new tools, 9 total)
- `container_image_scan` — Scan Docker images for vulnerabilities using Trivy or Grype
- `container_seccomp_audit` — Audit Docker containers for seccomp profile configuration
- `container_daemon_configure` — Audit/apply Docker daemon security settings in /etc/docker/daemon.json
- `container_apparmor_install` — Install AppArmor profile packages and list loaded profiles

---

### New Core Infrastructure

#### `src/core/safeguards.ts` — SafeguardRegistry
- Singleton that detects running applications before modifying operations execute
- Parallel detection of VS Code (process + `.vscode` dir + IPC sockets), Docker (socket + container list), MCP servers (`.mcp.json` + node processes), databases (TCP port probes: PostgreSQL 5432, MySQL 3306, MongoDB 27017, Redis 6379), and web servers (nginx/apache2/httpd via pgrep)
- `checkSafety(operation, params)` returns `SafetyResult` with `warnings[]`, `blockers[]`, and `impactedApps[]`
- `appSafetyReport()` generates a full detection report across all application categories
- All detection errors are caught gracefully and converted to warnings rather than failures

#### `src/core/backup-manager.ts` — BackupManager
- Manages file backups with manifest tracking under `~/.kali-mcp-backups/`
- Each backup entry has a UUID, original path, backup path, timestamp, and size
- `manifest.json` maintains the full backup inventory for list and restore operations
- `backup(filePath)` — creates timestamped copy and adds to manifest, returns UUID
- `restore(backupId)` — restores by UUID with target directory auto-creation
- `listBackups()` — returns all entries sorted by timestamp (newest first)
- `pruneOldBackups(daysOld)` — removes backups older than N days and updates manifest

#### `src/core/rollback.ts` — RollbackManager
- Singleton that tracks system changes within and across sessions
- State persisted to `~/.kali-defense/rollback-state.json`
- Supports four change types: `file` (backup path), `sysctl` (previous value), `service` (previous state), `firewall` (rollback command)
- `rollback(operationId)` — reverses all changes for a specific operation in reverse order
- `rollbackSession(sessionId)` — reverses all changes from the current session
- `listChanges()` — returns all tracked changes sorted by timestamp

---

### Documentation Added

- `SAFEGUARDS.md` — Complete SafeguardRegistry reference: detection methods, operation trigger mapping, warning vs blocker levels, dry-run examples, backup storage layout, rollback and restore guide
- `TOOLS-REFERENCE.md` — Alphabetical table of all 130+ tools with MCP tool name, description, key parameters, dryRun support, OS compatibility, and safety level
- `STANDARDS.md` — Security standards mapping covering CIS Benchmark section-by-section, NIST SP 800-53 control families, and five compliance frameworks (PCI-DSS v4, HIPAA, SOC 2, ISO 27001, GDPR) with coverage estimates and evidence types
- `CHANGELOG.md` — This file; version history beginning at v2.0.0
- `README.md` — Updated with new tool categories, application safeguards section, OS compatibility matrix, and quick-start examples for each new tool category

---

### Changed

- `src/index.ts` — Updated server version to `2.0.0`, added imports and registration calls for all 11 new modules; server now registers 26 tool modules
- `README.md` — Complete rewrite to reflect 130+ tools; added OS matrix, safeguards section, quick-start examples for all new categories
- Tool count in server startup message updated to `130+`

---

## [1.0.0] — 2025 (initial release)

### Initial Release

69 defensive security tools across 12 categories:

- Firewall Management (7 tools): iptables list/add/delete, UFW status/rule, save, restore
- System Hardening (7 tools): sysctl get/set/audit, service manage/audit, file permissions, permissions audit
- Intrusion Detection (5 tools): AIDE, rkhunter, chkrootkit, file integrity check, rootkit summary
- Log Analysis (7 tools): auditd rules/search/report, journalctl, fail2ban status/manage, syslog analyze
- Network Defense (6 tools): connections, port scan detect, tcpdump, DNS monitor, ARP monitor, open ports audit
- Compliance (5 tools): lynis, oscap, CIS check, policy evaluate, report
- Malware Analysis (5 tools): ClamAV scan/update, YARA scan, suspicious files, quarantine manage
- Backup and Recovery (5 tools): config backup, system state, restore, verify, list
- Access Control (6 tools): SSH audit/harden, sudo audit, user audit, password policy, PAM audit
- Encryption and PKI (6 tools): TLS audit, cert expiry, GPG keys, LUKS manage, file hash, TLS config audit
- Container Security (5 tools): Docker audit/bench, AppArmor manage, SELinux manage, namespace check
- Meta and Orchestration (5 tools): check tools, suggest workflow, security posture, change history, run workflow

Core infrastructure: executor (spawn with shell:false), sanitizer (17+ validators), config (env-based), parsers, distro detection, installer, changelog, policy engine
