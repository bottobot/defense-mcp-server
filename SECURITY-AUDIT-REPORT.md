# Security Audit Report — kali-defense-mcp-server

**Project:** kali-defense-mcp-server v0.5.0-beta.2  
**Audit Date:** 2026-03-07  
**Auditor:** Automated Security Audit Pipeline (6-Phase)  
**Classification:** CONFIDENTIAL  
**Report Version:** 1.0  

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Audit Scope & Methodology](#2-audit-scope--methodology)
3. [Overall Security Score](#3-overall-security-score)
4. [Finding Summary Dashboard](#4-finding-summary-dashboard)
5. [Critical & High Findings](#5-critical--high-findings)
6. [Medium Findings Summary](#6-medium-findings-summary)
7. [Low & Info Findings Summary](#7-low--info-findings-summary)
8. [Test Coverage Assessment](#8-test-coverage-assessment)
9. [Positive Security Controls](#9-positive-security-controls)
10. [Prioritized Remediation Roadmap](#10-prioritized-remediation-roadmap)
11. [Appendix: Files Reviewed](#11-appendix-files-reviewed)

---

## 1. Executive Summary

### Overall Security Posture: 🔴 HIGH RISK

The kali-defense-mcp-server project — a Model Context Protocol server exposing 78 defensive security tools across 21 modules — demonstrates **strong security architecture at the design level** but suffers from **critical implementation gaps** that undermine its defensive posture. The project's core premise of executing privileged system commands makes its attack surface inherently large, and several control bypasses exist that could allow arbitrary command execution.

### Key Metrics

| Metric | Value |
|---|---|
| **Total Findings** | **89** |
| Critical | 12 |
| High | 22 |
| Medium | 29 |
| Low | 15 |
| Info | 11 |
| **Test Coverage (Lines)** | **29.0%** — all thresholds fail |
| Core Modules with Zero Coverage | 13 of 24 (54%) |
| Tool Modules with Any Coverage | 0 of 21 (0%) |
| Runtime Dependencies | 2 (minimal) |
| System Binaries Allowlisted | 115 |

### Top-Level Recommendation

**This project should not be deployed in production or multi-tenant environments until the 12 CRITICAL findings are remediated.** The most urgent issues are the shell injection vectors (`sh`/`bash` in the command allowlist, `sh -c`/`bash -c` invocations with user-controlled interpolation) which collectively represent the highest-impact attack surface. Test coverage must be raised above 60% with specific focus on the security-critical modules that currently have zero coverage.

---

## 2. Audit Scope & Methodology

### What Was Reviewed

- **24 core modules** in `src/core/`
- **21 tool modules** in `src/tools/`
- **11 test files** in `tests/core/`
- **CI/CD pipeline** (`.github/workflows/ci.yml`)
- **Build configuration** (`tsconfig.json`, `vitest.config.ts`)
- **Package manifests** (`package.json`, `package-lock.json`)
- **Helper scripts** (`mcp-call.sh`, `run-assessment.mjs`)
- **Documentation** (10 markdown documents)
- **Configuration defaults** (`src/core/config.ts`)

### 6-Phase Methodology

| Phase | Focus | Findings |
|---|---|---|
| **Phase 1** | Project Overview & Dependency Audit | Structural/dependency issues identified |
| **Phase 2** | Core Module Security Review | 24 findings (4C, 6H, 7M, 4L, 3I) |
| **Phase 3** | Tool Implementation Security Review | 37 findings (5C, 9H, 12M, 6L, 5I) |
| **Phase 4** | Test Coverage & Gap Analysis | Coverage metrics, 10 critical untested vulns |
| **Phase 5** | Build, CI/CD & Configuration Security | 28 findings (3C, 7H, 10M, 5L, 3I) |
| **Phase 6** | Consolidated Report (this document) | — |

### Severity Classification

| Severity | Definition |
|---|---|
| **CRITICAL** | Exploitable vulnerability allowing arbitrary command execution, full security bypass, or data compromise with no mitigating controls |
| **HIGH** | Significant vulnerability that could lead to privilege escalation, data exposure, or partial security bypass |
| **MEDIUM** | Weakness that could be exploited under specific conditions or contributes to defense-in-depth degradation |
| **LOW** | Minor issue with limited direct security impact |
| **INFO** | Informational observation or positive finding |

---

## 3. Overall Security Score

### Weighted Scoring Methodology

Each finding severity is assigned a weight, and scores are calculated per category:

| Category | Max Score | Deductions | Final Score |
|---|---|---|---|
| **Command Execution Safety** | 25 | -22 (7 CRITICAL shell injection vectors) | **3/25** |
| **Input Validation & Sanitization** | 20 | -12 (path traversal, missing validation) | **8/20** |
| **Privilege & Access Control** | 15 | -8 (bypass options, sudo gaps) | **7/15** |
| **Configuration Security** | 10 | -5 (permissive defaults, hardcoded paths) | **5/10** |
| **CI/CD & Build Security** | 10 | -6 (no audit, no SAST, no SHA pins) | **4/10** |
| **Test Coverage** | 10 | -8 (29% coverage, 54% zero-coverage modules) | **2/10** |
| **Documentation & Standards** | 5 | -1 (version drift) | **4/5** |
| **Dependency Management** | 5 | -2 (lockfile mismatch, caret ranges) | **3/5** |
| **TOTAL** | **100** | **-64** | **36/100** |

### Rating

| Score Range | Rating | This Project |
|---|---|---|
| 90-100 | Excellent | |
| 75-89 | Good | |
| 60-74 | Acceptable | |
| 40-59 | Poor | |
| 0-39 | **Critical** | **✅ 36/100** |

---

## 4. Finding Summary Dashboard

### By Phase and Severity

| Phase | Critical | High | Medium | Low | Info | Total |
|---|---|---|---|---|---|---|
| Phase 2: Core Modules | 4 | 6 | 7 | 4 | 3 | **24** |
| Phase 3: Tool Implementations | 5 | 9 | 12 | 6 | 5 | **37** |
| Phase 5: Build/CI/Config | 3 | 7 | 10 | 5 | 3 | **28** |
| **TOTAL** | **12** | **22** | **29** | **15** | **11** | **89** |

### By Category

| Category | Count | Highest Severity |
|---|---|---|
| Shell Injection / Command Execution | 14 | CRITICAL |
| Path Traversal / File Write | 9 | HIGH |
| Security Control Bypass | 5 | CRITICAL |
| Input Validation | 8 | HIGH |
| CI/CD Pipeline Gaps | 7 | CRITICAL |
| Privilege Management | 5 | HIGH |
| Configuration Issues | 6 | HIGH |
| Test Coverage Gaps | 10 | CRITICAL (untested) |
| Information Exposure | 4 | MEDIUM |
| Other | 21 | MEDIUM |

---

## 5. Critical & High Findings

### 5.1 CRITICAL Findings (12)

#### CORE-001: `sh` and `bash` in Command Allowlist

| Attribute | Detail |
|---|---|
| **ID** | CORE-001 |
| **Phase** | 2 — Core Modules |
| **Severity** | 🔴 CRITICAL |
| **File** | `src/core/command-allowlist.ts` |
| **Description** | The command allowlist includes `sh` and `bash` as permitted binaries. Since `spawn-safe.ts` enforces `shell: false`, commands are expected to be executed directly. However, if `sh` or `bash` is invoked as the command with `-c` and a shell string as arguments, the entire allowlist-based security boundary is circumvented — the shell will interpret the string with full shell expansion. |
| **Impact** | Complete bypass of command allowlist security control. Any command can be executed by invoking `sh -c "arbitrary command"`. |
| **Remediation** | Remove `sh` and `bash` from the command allowlist. Refactor all call sites that depend on shell interpretation to use direct binary invocations with explicit argument arrays. |

#### CORE-002: Policy Engine Executes Arbitrary Commands from JSON

| Attribute | Detail |
|---|---|
| **ID** | CORE-002 |
| **Phase** | 2 — Core Modules |
| **Severity** | 🔴 CRITICAL |
| **File** | `src/core/policy-engine.ts` |
| **Description** | The policy engine loads rules from JSON files and can execute commands specified in those rules without schema validation. A malicious or tampered policy file can trigger arbitrary command execution. |
| **Impact** | Arbitrary command execution if policy files are writable by an attacker or loaded from an untrusted source. |
| **Remediation** | Implement strict JSON schema validation using Zod for all policy files. Restrict policy commands to an explicit allowlist. Add integrity checks (e.g., checksums) for policy files. |

#### CORE-003: Rollback Firewall Command Injection via String Split

| Attribute | Detail |
|---|---|
| **ID** | CORE-003 |
| **Phase** | 2 — Core Modules |
| **Severity** | 🔴 CRITICAL |
| **File** | `src/core/rollback.ts` |
| **Description** | Rollback reconstructs firewall commands by splitting `originalValue` on whitespace via `originalValue.split(/\s+/)`. If the original value was crafted to contain shell metacharacters or was tampered with in the rollback state, this parsing approach enables command injection during rollback operations. |
| **Impact** | Command injection during rollback operations, potentially restoring a malicious firewall configuration. |
| **Remediation** | Store rollback state as structured data (command + arguments array) rather than a single string. Validate all rollback parameters against the command allowlist before execution. |

#### CORE-004: `bypassAllowlist` Option in spawn-safe

| Attribute | Detail |
|---|---|
| **ID** | CORE-004 |
| **Phase** | 2 — Core Modules |
| **Severity** | 🔴 CRITICAL |
| **File** | `src/core/spawn-safe.ts` |
| **Description** | The `spawn-safe` function accepts a `bypassAllowlist` option that completely disables the command allowlist security boundary. Any caller with access to this option can execute any binary on the system. |
| **Impact** | Complete bypass of the command allowlist — the primary security control of the entire project. |
| **Remediation** | Remove the `bypassAllowlist` option entirely. If specific binaries need to be executed outside the standard allowlist, add them to the allowlist with appropriate documentation and justification. |

#### TOOL-001: `sh -c` Shell Invocation in Tool Modules (11 instances)

| Attribute | Detail |
|---|---|
| **ID** | TOOL-001 |
| **Phase** | 3 — Tool Implementations |
| **Severity** | 🔴 CRITICAL |
| **Files** | `src/tools/container-security.ts`, `src/tools/secrets.ts`, `src/tools/incident-response.ts` |
| **Description** | Eleven instances of `sh -c` invocations across three tool modules pass user-influenced strings directly to a shell for interpretation. This leverages CORE-001 (shell binaries in the allowlist) to achieve full shell command injection. |
| **Impact** | Remote command execution via crafted tool parameters. |
| **Remediation** | Replace all `sh -c` invocations with direct binary execution using argument arrays. Parse complex pipelines into sequential command invocations. |

#### TOOL-002: `bash -c` with String Interpolation (10+ instances)

| Attribute | Detail |
|---|---|
| **ID** | TOOL-002 |
| **Phase** | 3 — Tool Implementations |
| **Severity** | 🔴 CRITICAL |
| **Files** | `src/tools/hardening.ts`, `src/tools/compliance.ts`, `src/tools/access-control.ts` |
| **Description** | Over ten instances of `bash -c` with template literal string interpolation pass user-controlled values directly into shell commands. Variables from tool parameters are embedded without escaping. |
| **Impact** | Direct shell injection via user-controlled tool parameters. |
| **Remediation** | Eliminate all `bash -c` invocations. Use direct binary execution with explicit argument arrays. Where shell features are genuinely needed, use a safe command builder pattern with strict input validation. |

#### TOOL-003: Firewall Persistence via `bash -c` with Concatenation

| Attribute | Detail |
|---|---|
| **ID** | TOOL-003 |
| **Phase** | 3 — Tool Implementations |
| **Severity** | 🔴 CRITICAL |
| **File** | `src/tools/firewall.ts` |
| **Description** | Firewall persistence operations use `bash -c` with command concatenation to chain multiple firewall save/restore commands. The concatenated string includes values derived from user input or system state without proper escaping. |
| **Impact** | Command injection during firewall persistence operations, which typically run with elevated privileges. |
| **Remediation** | Refactor to sequential direct binary invocations. Use `spawn-safe` for each individual command rather than concatenating them into a shell string. |

#### TOOL-004: `scheduled_audit` Allows Arbitrary Command Execution

| Attribute | Detail |
|---|---|
| **ID** | TOOL-004 |
| **Phase** | 3 — Tool Implementations |
| **Severity** | 🔴 CRITICAL |
| **File** | `src/tools/compliance.ts` |
| **Description** | The `scheduled_audit` tool accepts parameters that configure cron jobs or systemd timers to run commands. Insufficient validation of the command parameter allows arbitrary command execution via the scheduling mechanism. |
| **Impact** | Persistent arbitrary command execution via scheduled tasks, potentially surviving server restarts. |
| **Remediation** | Restrict scheduled commands to a predefined set of audit scripts. Validate all scheduling parameters against a strict schema. Require explicit dry-run approval before creating scheduled tasks. |

#### TOOL-005: `defense_workflow` Runs Hardcoded Commands Without Safeguards

| Attribute | Detail |
|---|---|
| **ID** | TOOL-005 |
| **Phase** | 3 — Tool Implementations |
| **Severity** | 🔴 CRITICAL |
| **File** | `src/tools/incident-response.ts` |
| **Description** | The `defense_workflow` tool executes a sequence of hardcoded commands without applying the standard safeguard checks (dry-run, allowlist verification, privilege validation). These commands run with whatever privileges the MCP server has. |
| **Impact** | Uncontrolled privileged command execution bypassing all safety mechanisms. |
| **Remediation** | Route all workflow commands through the standard `spawn-safe` execution path with full safeguard enforcement. Add dry-run support for workflow operations. |

#### CICD-006: No `npm audit` in CI Pipeline

| Attribute | Detail |
|---|---|
| **ID** | CICD-006 |
| **Phase** | 5 — Build/CI/Config |
| **Severity** | 🔴 CRITICAL |
| **File** | `.github/workflows/ci.yml` |
| **Description** | The CI pipeline does not run `npm audit` to check for known vulnerabilities in dependencies. For a security-focused project, this is a critical omission. |
| **Impact** | Known vulnerable dependencies could be merged and deployed without detection. |
| **Remediation** | Add `npm audit --audit-level=high` as a required CI step. Consider adding `npm audit signatures` for supply chain verification. |

#### CICD-020: Shell Injection via printf Format String in mcp-call.sh

| Attribute | Detail |
|---|---|
| **ID** | CICD-020 |
| **Phase** | 5 — Build/CI/Config |
| **Severity** | 🔴 CRITICAL |
| **File** | `mcp-call.sh` |
| **Description** | The `mcp-call.sh` helper script uses `printf` with user-supplied format strings, enabling shell injection. An attacker who controls the tool name or arguments can inject format specifiers or shell commands. |
| **Impact** | Arbitrary command execution via the helper script. |
| **Remediation** | Use `printf '%s'` with explicit format specifiers. Validate all inputs before use. Consider rewriting in a safer language. |

#### CICD-023: Lockfile Version Mismatch

| Attribute | Detail |
|---|---|
| **ID** | CICD-023 |
| **Phase** | 5 — Build/CI/Config |
| **Severity** | 🔴 CRITICAL |
| **File** | `package-lock.json` |
| **Description** | `package-lock.json` specifies version `0.4.0-beta.2` while `package.json` specifies `0.5.0-beta.2`. This indicates the lockfile was not regenerated after the version bump, meaning `npm ci` in CI may install different dependencies than expected. |
| **Impact** | Reproducibility and supply chain integrity are compromised. CI builds may not match developer environments. |
| **Remediation** | Regenerate `package-lock.json` with `npm install`. Add a CI check to verify lockfile consistency (e.g., `npm ci` will fail if out of sync, but version field mismatches may not trigger this). |

---

### 5.2 HIGH Findings (22)

#### Phase 2 — Core Module HIGH Findings (6)

| ID | Title | File | Description | Remediation |
|---|---|---|---|---|
| CORE-005 | Password String Interning in V8 | `src/core/sudo-session.ts` | JavaScript strings are immutable and interned by V8. Password strings cannot be reliably zeroed from memory, leaving credentials potentially accessible via heap inspection or core dumps. | Use `Buffer` exclusively for credential handling. Minimize credential lifetime. Disable core dumps in production. |
| CORE-006 | SUDO_ASKPASS Trusted Without Integrity Check | `src/core/sudo-guard.ts` | The `SUDO_ASKPASS` environment variable points to a helper script that provides the sudo password. This path is trusted without verifying the script's integrity (hash, ownership, permissions). | Verify ownership (root or current user), permissions (0700), and optionally a cryptographic hash of the askpass script before use. |
| CORE-007 | TOCTOU in Binary Path Resolution | `src/core/command-allowlist.ts` | Binary paths are resolved at startup (via `which`/`command -v`) but used at runtime. Between resolution and execution, a binary could be replaced (symlink attack, PATH manipulation). | Re-resolve or verify binary hash at execution time. Use absolute paths stored during resolution and verify inode/checksum before exec. |
| CORE-008 | npm/pip Auto-Installer Has No Package Allowlist | `src/core/auto-installer.ts` | The auto-installer installs npm/pip packages specified by tool dependencies without restricting which packages are allowed. Any package name can be installed, enabling supply-chain attacks. | Implement a strict package allowlist. Require integrity hashes for allowed packages. Prefer system packages over npm/pip installs. |
| CORE-009 | ReDoS via Policy Rule expectedOutput Regex | `src/core/policy-engine.ts` | Policy rules can specify `expectedOutput` as a regex pattern. Maliciously crafted regex patterns can cause catastrophic backtracking (ReDoS), leading to denial of service. | Use the `re2` library for regex evaluation, or implement regex complexity limits (e.g., max length, disallow nested quantifiers). Add a timeout for regex evaluation. |
| CORE-010 | Hardcoded User Path in safeguards.ts | `src/core/safeguards.ts` | The file contains a hardcoded path `/home/robert/...` which is developer-specific and will fail on any other system. This indicates insufficient environment abstraction. | Replace hardcoded paths with environment-aware resolution (e.g., `os.homedir()`, `XDG_CONFIG_HOME`). Add tests for path resolution on different systems. |

#### Phase 3 — Tool Implementation HIGH Findings (9)

| ID | Title | File | Description | Remediation |
|---|---|---|---|---|
| TOOL-006 | Path Traversal in malware_quarantine_manage | `src/tools/malware.ts` | The `file_id` parameter in quarantine management is not validated for path traversal sequences (`../`). An attacker can reference files outside the quarantine directory. | Validate `file_id` against path traversal. Use `path.resolve()` and verify the result is within the quarantine base directory. |
| TOOL-007 | Path Traversal in harden_permissions | `src/tools/hardening.ts` | The `path` parameter in permission hardening check/fix operations is not validated, allowing traversal to arbitrary filesystem locations. | Validate paths against an allowed directory list. Reject any path containing `..` sequences. Use `path.resolve()` with base directory containment checks. |
| TOOL-008 | Missing Validation on nftables Table Name | `src/tools/firewall.ts` | The `table` parameter in `nftables_list` is passed directly to the nftables command without validation, allowing injection of arbitrary nftables commands. | Validate table names against a strict regex pattern (e.g., `^[a-zA-Z0-9_-]+$`). Reject any input containing whitespace or special characters. |
| TOOL-009 | container_apparmor Writes to /etc/apparmor.d/ | `src/tools/container-security.ts` | Uses `writeFileSync` to write AppArmor profiles directly to `/etc/apparmor.d/`, bypassing the project's `secure-fs` module and its audit trail. | Use `secure-fs` module for all file writes. Implement dry-run support. Validate profile content before writing. |
| TOOL-010 | falco deploy_rules Writes to /etc/falco/rules.d/ | `src/tools/ids.ts` | Uses `writeFileSync` to deploy Falco rules directly to the system rules directory, bypassing `secure-fs` audit controls. | Route through `secure-fs`. Add backup/rollback support. Validate rule syntax before deployment. |
| TOOL-011 | container_security_config Arbitrary File Write | `src/tools/container-security.ts` | The `seccomp_profile` parameter allows writing a seccomp profile to an arbitrary path via `writeFileSync`, bypassing security controls. | Restrict output paths to a predefined directory. Use `secure-fs` for writes. Validate seccomp JSON schema. |
| TOOL-012 | access_ssh Unsanitized Key/Value in Shell Command | `src/tools/access-control.ts` | SSH configuration keys and values are interpolated into shell commands without sanitization, enabling injection via crafted SSH config parameters. | Use direct file manipulation (read, modify, write) instead of shell commands for SSH config changes. Validate keys against a known-good list. |
| TOOL-013 | compliance_tmp_hardening dry_run Defaults to false | `src/tools/compliance.ts` | The `tmp_hardening` tool defaults `dry_run` to `false`, meaning it will make system changes by default. For a compliance tool that modifies mount points, this is dangerous. | Default `dry_run` to `true` for all system-modifying operations. Require explicit opt-in for live execution. |
| TOOL-014 | compliance_cron_restrict dry_run Defaults to false | `src/tools/compliance.ts` | The `cron_restrict` tool defaults `dry_run` to `false`, modifying cron access controls by default without preview. | Default `dry_run` to `true`. Require explicit opt-in for live execution. |

#### Phase 5 — Build/CI/Config HIGH Findings (7)

| ID | Title | File | Description | Remediation |
|---|---|---|---|---|
| CICD-001 | Source Maps Enabled in Production Build | `tsconfig.json` | Source maps are generated for the production build, exposing source code structure and potentially sensitive logic to anyone with access to the build artifacts. | Disable `sourceMap` in `tsconfig.json` for production builds. Use a separate `tsconfig.prod.json` with `"sourceMap": false`. |
| CICD-005 | GitHub Actions Not Pinned by SHA | `.github/workflows/ci.yml` | Actions are referenced by mutable tags (e.g., `actions/checkout@v4`) rather than immutable commit SHAs. A compromised action tag could inject malicious code into CI. | Pin all actions to full commit SHAs (e.g., `actions/checkout@<sha>`). Use Dependabot or Renovate to manage SHA updates. |
| CICD-007 | No SAST/Static Analysis in CI | `.github/workflows/ci.yml` | The CI pipeline has no static application security testing (SAST). For a security tool project, this is a significant gap. | Add CodeQL or Semgrep as a CI step. Configure rules for command injection, path traversal, and other relevant vulnerability classes. |
| CICD-008 | No Coverage Enforcement in CI | `.github/workflows/ci.yml`, `vitest.config.ts` | Although `vitest.config.ts` defines coverage thresholds, they are not enforced in CI (no coverage step in the workflow). All thresholds currently fail. | Add `npm run test -- --coverage` as a CI step. Enforce threshold failures as CI failures. |
| CICD-013 | Default allowedDirs Includes /etc | `src/core/config.ts` | The default configuration includes `/etc` in `allowedDirs`, granting the server read/write access to system configuration files by default. | Remove `/etc` from default `allowedDirs`. Require explicit opt-in configuration for sensitive directories. Use read-only access where possible. |
| CICD-021 | run-assessment.mjs Spawns Uncontrolled Child Processes | `run-assessment.mjs` | The assessment helper script spawns child processes without the safety controls provided by `spawn-safe`. | Route all process spawning through `spawn-safe` or remove the script from the distribution. |
| CICD-026 | Hardcoded Developer Path in Source Code | `src/core/safeguards.ts` | Same as CORE-010 — hardcoded `/home/robert/` path in production source code. | Replace with environment-aware path resolution. |

---

## 6. Medium Findings Summary

| ID | Phase | Title | File | Description |
|---|---|---|---|---|
| CORE-011 | 2 | stdin Buffer Not Zeroed on Error Paths | `src/core/spawn-safe.ts` | Buffer containing sensitive data (passwords) may not be properly zeroed when an error occurs during command execution. |
| CORE-012 | 2 | Config Allows Unrestricted allowedDirs | `src/core/config.ts` | Configuration schema allows `allowedDirs` to be set to `/`, granting access to the entire filesystem. |
| CORE-013 | 2 | Policy savePolicy Uses Insecure mkdirSync | `src/core/policy-engine.ts` | Policy save operations use `mkdirSync` instead of the project's `secure-fs` module, bypassing audit controls. |
| CORE-014 | 2 | resolveCommandSafe Fallback Uses Bare Command | `src/core/command-allowlist.ts` | When full path resolution fails, the fallback uses the bare command name, potentially resolving to a different binary via PATH. |
| CORE-015 | 2 | Backup Manager Path Validation Insufficient | `src/core/backup-manager.ts` | Path validation only checks string length, not for traversal sequences or symlinks. |
| CORE-016 | 2 | Askpass Candidates Not Verified | `src/core/sudo-guard.ts` | Askpass helper candidates are checked for existence but not for ownership, permissions, or integrity. |
| CORE-017 | 2 | Python Import Execution in Preflight | `src/core/preflight.ts` | Python import checks execute `__init__.py` files, which could contain arbitrary code. |
| TOOL-015 | 3 | Path Traversal in Logging Config | `src/tools/logging.ts` | Log output path not validated for traversal sequences. |
| TOOL-016 | 3 | Path Traversal in IDS Config | `src/tools/ids.ts` | IDS configuration paths not validated. |
| TOOL-017 | 3 | Firewall Paths Not Validated | `src/tools/firewall.ts` | Firewall rule file paths lack traversal validation. |
| TOOL-018 | 3 | BPF Filter Validation Insufficient | `src/tools/ebpf-security.ts` | eBPF filter expressions not validated for injection. |
| TOOL-019 | 3 | Privilege Gaps in Tool Operations | `src/tools/hardening.ts` | Some operations require elevated privileges but do not check for them before executing. |
| TOOL-020 | 3 | writeFileSync Bypasses secure-fs | `src/tools/container-security.ts` | Direct `writeFileSync` calls bypass audit trail. |
| TOOL-021 | 3 | Environment Variable Exposure | `src/tools/secrets.ts` | Sensitive environment variables may be logged or exposed in error messages. |
| TOOL-022 | 3 | Insufficient Input Validation on Network Parameters | `src/tools/network-defense.ts` | Network addresses and port ranges lack strict validation. |
| TOOL-023 | 3 | Missing Validation on Encryption Parameters | `src/tools/encryption.ts` | Encryption key paths and algorithm parameters not fully validated. |
| TOOL-024 | 3 | Drift Detection File Access | `src/tools/drift-detection.ts` | Drift baselines read from unvalidated paths. |
| TOOL-025 | 3 | Supply Chain Tool Input Validation | `src/tools/supply-chain-security.ts` | Package names and registry URLs insufficiently validated. |
| TOOL-026 | 3 | Backup Path Validation Gap | `src/tools/backup.ts` | Backup destination paths not checked for traversal. |
| CICD-002 | 5 | No Multi-OS CI Matrix | `.github/workflows/ci.yml` | CI only runs on Ubuntu; cross-platform issues may go undetected. |
| CICD-003 | 5 | No Dependency Caching Validation | `.github/workflows/ci.yml` | npm cache not verified for integrity. |
| CICD-009 | 5 | No Security-Focused Linting Rules | `package.json` | No ESLint security plugin configured. |
| CICD-010 | 5 | Build Output Not Verified | `package.json` | Build output integrity not checked post-compilation. |
| CICD-014 | 5 | Permissive Default Configuration | `src/core/config.ts` | Default configuration is overly permissive for a security tool. |
| CICD-015 | 5 | No Signed Commits Required | `.github/workflows/ci.yml` | CI does not enforce GPG-signed commits. |
| CICD-017 | 5 | Documentation Version Drift | `ARCHITECTURE.md` | Architecture doc references v1.0.0 and has inconsistent tool counts. |
| CICD-022 | 5 | Caret Version Ranges in Dependencies | `package.json` | Caret ranges may introduce unintended updates; pin for GA release. |
| CICD-024 | 5 | Missing Rate Limiting | `src/core/` | No request rate limiting for tool invocations. |
| CICD-027 | 5 | No Structured Logging | `src/core/` | Logging is unstructured, making security event correlation difficult. |

---

## 7. Low & Info Findings Summary

### LOW Findings (15)

| ID | Phase | Title | File |
|---|---|---|---|
| CORE-018 | 2 | spawn-safe Logs Full Command Arguments | `src/core/spawn-safe.ts` |
| CORE-019 | 2 | Shell Metachar Regex Missing Backslash | `src/core/sanitizer.ts` |
| CORE-020 | 2 | UncaughtException Handler Calls Async Operations | `src/core/` |
| CORE-021 | 2 | Singleton Patterns Use Unprotected Static State | `src/core/` |
| TOOL-027 | 3 | Inconsistent dry-run Defaults Across Tools | `src/tools/` (multiple) |
| TOOL-028 | 3 | Missing dry-run Support in Some Tools | `src/tools/` (multiple) |
| TOOL-029 | 3 | Error Message Information Exposure | `src/tools/` (multiple) |
| TOOL-030 | 3 | Weak Pattern Validation in Tool Inputs | `src/tools/` (multiple) |
| TOOL-031 | 3 | Inconsistent Error Handling Patterns | `src/tools/` (multiple) |
| TOOL-032 | 3 | Minor Input Validation Gaps | `src/tools/` (multiple) |
| CICD-004 | 5 | No Changelog Automation | `CHANGELOG.md` |
| CICD-011 | 5 | No License Compliance Check | `package.json` |
| CICD-016 | 5 | Test File Naming Convention Gaps | `tests/` |
| CICD-018 | 5 | No Pre-commit Hooks | Project root |
| CICD-028 | 5 | No Multi-User Sudo Isolation | `src/core/sudo-session.ts` |

### INFO Findings (11)

| ID | Phase | Title | Description |
|---|---|---|---|
| CORE-022 | 2 | Secure Defaults Well-Implemented | `shell: false` enforced at two layers (executor and spawn-safe). |
| CORE-023 | 2 | Password Buffer Lifecycle Generally Well-Managed | Buffers are created, used, and zeroed in most happy-path scenarios. |
| CORE-024 | 2 | Binary Integrity Verification Strong | Allowlist with path resolution provides defense-in-depth. |
| TOOL-033 | 3 | Consistent Sanitization in Some Modules | Several tool modules apply consistent input sanitization. |
| TOOL-034 | 3 | Good dry-run Adoption | Majority of system-modifying tools support dry-run mode. |
| TOOL-035 | 3 | Changelog Usage for Audit Trail | Changes are logged to the changelog for accountability. |
| TOOL-036 | 3 | Safety Checks Present | Many tools verify preconditions before executing. |
| TOOL-037 | 3 | Positive Code Quality Patterns | Consistent error handling and TypeScript strict mode. |
| CICD-012 | 5 | Minimal Dependency Footprint | Only 2 runtime dependencies — excellent attack surface reduction. |
| CICD-019 | 5 | TypeScript Strict Mode Enabled | Catches many common errors at compile time. |
| CICD-025 | 5 | CI Runs on Multiple Node Versions | Matrix testing across Node 18, 20, 22 ensures compatibility. |

---

## 8. Test Coverage Assessment

### Current Coverage Metrics

| Metric | Actual | Threshold | Status |
|---|---|---|---|
| Statements | 28.2% | 60% | ❌ FAIL |
| Branches | 27.85% | 50% | ❌ FAIL |
| Functions | 26.33% | 60% | ❌ FAIL |
| Lines | 29.0% | 60% | ❌ FAIL |

### Test Infrastructure

- **Framework:** Vitest
- **Test Files:** 11 (all in `tests/core/`)
- **Total Tests:** 352 (all passing)
- **Tool Module Tests:** 0

### Core Module Coverage Gaps

| Module | Coverage | Risk Level |
|---|---|---|
| `policy-engine.ts` | 0% | 🔴 CRITICAL — executes arbitrary commands |
| `tool-wrapper.ts` | 0% | 🔴 CRITICAL — pre-flight bypass vector |
| `tool-registry.ts` | 0% | HIGH — tool dispatch layer |
| `preflight.ts` | 0% | HIGH — dependency validation |
| `privilege-manager.ts` | 0% | HIGH — privilege escalation surface |
| `auto-installer.ts` | 0% | HIGH — installs arbitrary packages |
| `distro.ts` | 0% | MEDIUM |
| `distro-adapter.ts` | 0% | MEDIUM |
| `installer.ts` | 0% | MEDIUM |
| `parsers.ts` | 0% | MEDIUM |
| `dependency-validator.ts` | 0% | MEDIUM |
| `tool-dependencies.ts` | 0% | LOW |
| `index.ts` | 0% | LOW |
| `sudo-guard.ts` | 10.95% | HIGH — credential handling |

### 10 Critical Untested Vulnerabilities

1. Policy engine command execution paths (CORE-002)
2. Tool wrapper pre-flight bypass (CORE-004)
3. Auto-installer package execution (CORE-008)
4. Privilege escalation via privilege-manager
5. Shell injection in 21+ tool module call sites (TOOL-001, TOOL-002)
6. Path traversal in quarantine management (TOOL-006)
7. Firewall command injection (TOOL-003)
8. Scheduled audit command execution (TOOL-004)
9. SSH configuration injection (TOOL-012)
10. All 21 tool modules have zero test coverage

---

## 9. Positive Security Controls

Despite the significant findings, the project demonstrates strong security awareness in several areas:

### ✅ Defense-in-Depth Architecture

- **Dual-layer `shell: false` enforcement** — both `executor.ts` and `spawn-safe.ts` set `shell: false`, preventing accidental shell interpretation at two separate code layers.
- **Command allowlist with path resolution** — 115 binaries are explicitly allowlisted with full path resolution at startup, providing a strong default security boundary.
- **Secure-fs module** — dedicated module for audited file operations with backup and rollback support.

### ✅ Credential Handling

- **Buffer-based password lifecycle** — passwords are generally handled as Buffers rather than strings, enabling memory zeroing after use.
- **Sudo session management** — dedicated session lifecycle with credential timeout and cleanup.

### ✅ Operational Safety

- **Dry-run support** — majority of system-modifying tools support dry-run mode for previewing changes.
- **Changelog/audit trail** — system changes are logged for accountability and forensic review.
- **Rollback capability** — backup manager enables reverting changes when operations fail.
- **Binary integrity checks** — path resolution verifies that executables exist and are accessible.

### ✅ Minimal Attack Surface

- **Only 2 runtime dependencies** — `@modelcontextprotocol/sdk` and `zod`. This dramatically reduces supply chain risk compared to typical Node.js projects.
- **TypeScript strict mode** — catches type-related errors at compile time.
- **Comprehensive documentation** — 10 documentation files covering architecture, standards, safeguards, and tool reference.

---

## 10. Prioritized Remediation Roadmap

### 🔴 Phase 1: IMMEDIATE — Critical Shell Injection & Command Bypass

**Target: Before any production/external use**

| Priority | Finding(s) | Action |
|---|---|---|
| P0 | CORE-001, TOOL-001, TOOL-002, TOOL-003 | Remove `sh` and `bash` from command allowlist. Refactor all 21+ shell invocation sites to use direct binary execution with argument arrays. |
| P0 | CORE-004 | Remove `bypassAllowlist` option from `spawn-safe.ts`. Add needed binaries to the allowlist instead. |
| P0 | CORE-002 | Add Zod schema validation for policy engine JSON files. Restrict executable commands to allowlisted set. |
| P0 | CORE-003 | Store rollback state as structured data. Validate rollback parameters before execution. |
| P0 | TOOL-004 | Restrict `scheduled_audit` to predefined audit commands only. |
| P0 | TOOL-005 | Route `defense_workflow` commands through `spawn-safe` with full safeguard enforcement. |
| P0 | CICD-020 | Fix `printf` format string injection in `mcp-call.sh`. |
| P0 | CICD-023 | Regenerate `package-lock.json` to match `package.json` version. |
| P0 | CICD-006 | Add `npm audit --audit-level=high` to CI pipeline. |

### 🟠 Phase 2: SHORT-TERM — High Severity Remediation

**Target: Within the next release cycle**

| Priority | Finding(s) | Action |
|---|---|---|
| P1 | CORE-008 | Implement strict package allowlist for auto-installer. |
| P1 | CORE-009 | Use `re2` or implement regex complexity limits for policy rules. |
| P1 | TOOL-006, TOOL-007 | Add path traversal validation to malware quarantine and permission hardening. |
| P1 | TOOL-008 | Validate nftables table names against strict pattern. |
| P1 | TOOL-009, TOOL-010, TOOL-011 | Replace all `writeFileSync` calls with `secure-fs` module. |
| P1 | TOOL-012 | Eliminate shell commands for SSH config; use direct file manipulation. |
| P1 | TOOL-013, TOOL-014 | Default all system-modifying tools to `dry_run: true`. |
| P1 | CICD-001 | Disable source maps in production builds. |
| P1 | CICD-005 | Pin all GitHub Actions to commit SHAs. |
| P1 | CICD-007 | Add CodeQL or Semgrep SAST to CI. |
| P1 | CICD-008 | Enforce coverage thresholds in CI. |
| P1 | CICD-013 | Remove `/etc` from default `allowedDirs`. |
| P1 | CORE-005 | Minimize password string exposure; ensure Buffer-only credential paths. |
| P1 | CORE-006 | Add ownership/permissions/integrity verification for SUDO_ASKPASS scripts. |
| P1 | CORE-007 | Re-verify binary paths at execution time or cache with inode checks. |
| P1 | CORE-010, CICD-026 | Remove hardcoded `/home/robert/` path; use `os.homedir()`. |
| P1 | CICD-021 | Route `run-assessment.mjs` child processes through `spawn-safe`. |

### 🟡 Phase 3: MEDIUM-TERM — Hardening & Coverage

**Target: Within 2-3 release cycles**

| Priority | Finding(s) | Action |
|---|---|---|
| P2 | Phase 4 (all) | Raise test coverage to 60%+ with focus on: `policy-engine.ts`, `tool-wrapper.ts`, `privilege-manager.ts`, `auto-installer.ts`, `sudo-guard.ts`. |
| P2 | Phase 4 (all) | Create test suites for at least the 10 highest-risk tool modules. |
| P2 | CORE-011 through CORE-017 | Address all MEDIUM core findings: Buffer zeroing on error, config validation, secure mkdirSync, path validation, askpass verification. |
| P2 | TOOL-015 through TOOL-026 | Address all MEDIUM tool findings: path traversal fixes, BPF validation, privilege checks, `writeFileSync` replacements. |
| P2 | CICD-002 through CICD-027 (MEDIUM) | Address CI/CD MEDIUM findings: multi-OS testing, security linting, documentation updates. |

### 🟢 Phase 4: LONG-TERM — Operational Excellence

**Target: GA release readiness**

| Priority | Finding(s) | Action |
|---|---|---|
| P3 | CICD-024 | Implement request rate limiting for tool invocations. |
| P3 | CICD-027 | Implement structured logging (JSON format) with security event classification. |
| P3 | CICD-028 | Add multi-user sudo isolation for concurrent sessions. |
| P3 | CICD-022 | Pin all dependency versions (remove caret ranges) for GA release. |
| P3 | LOW findings | Address all remaining LOW findings: consistent dry-run defaults, error message sanitization, pre-commit hooks, regex fixes. |
| P3 | — | Implement encrypted state storage for sensitive configuration and rollback data. |
| P3 | — | Add atomic file write operations for concurrent safety. |
| P3 | — | Conduct external penetration test focused on MCP protocol attack surface. |
| P3 | — | Achieve 80%+ test coverage across all modules before GA release. |

---

## 11. Appendix: Files Reviewed

### Core Modules (24 files)

| File | Phase(s) Reviewed |
|---|---|
| `src/core/auto-installer.ts` | 2 |
| `src/core/backup-manager.ts` | 2 |
| `src/core/changelog.ts` | 2 |
| `src/core/command-allowlist.ts` | 2 |
| `src/core/config.ts` | 2, 5 |
| `src/core/dependency-validator.ts` | 2 |
| `src/core/distro-adapter.ts` | 2 |
| `src/core/distro.ts` | 2 |
| `src/core/executor.ts` | 2 |
| `src/core/installer.ts` | 2 |
| `src/core/parsers.ts` | 2 |
| `src/core/policy-engine.ts` | 2 |
| `src/core/preflight.ts` | 2 |
| `src/core/privilege-manager.ts` | 2 |
| `src/core/rollback.ts` | 2 |
| `src/core/safeguards.ts` | 2, 5 |
| `src/core/sanitizer.ts` | 2 |
| `src/core/secure-fs.ts` | 2 |
| `src/core/spawn-safe.ts` | 2 |
| `src/core/sudo-guard.ts` | 2 |
| `src/core/sudo-session.ts` | 2 |
| `src/core/tool-dependencies.ts` | 2 |
| `src/core/tool-registry.ts` | 2 |
| `src/core/tool-wrapper.ts` | 2 |

### Tool Modules (21 files)

| File | Phase(s) Reviewed |
|---|---|
| `src/tools/access-control.ts` | 3 |
| `src/tools/app-hardening.ts` | 3 |
| `src/tools/backup.ts` | 3 |
| `src/tools/compliance.ts` | 3 |
| `src/tools/container-security.ts` | 3 |
| `src/tools/drift-detection.ts` | 3 |
| `src/tools/ebpf-security.ts` | 3 |
| `src/tools/encryption.ts` | 3 |
| `src/tools/firewall.ts` | 3 |
| `src/tools/hardening.ts` | 3 |
| `src/tools/ids.ts` | 3 |
| `src/tools/incident-response.ts` | 3 |
| `src/tools/logging.ts` | 3 |
| `src/tools/malware.ts` | 3 |
| `src/tools/meta.ts` | 3 |
| `src/tools/network-defense.ts` | 3 |
| `src/tools/patch-management.ts` | 3 |
| `src/tools/secrets.ts` | 3 |
| `src/tools/sudo-management.ts` | 3 |
| `src/tools/supply-chain-security.ts` | 3 |
| `src/tools/zero-trust-network.ts` | 3 |

### Test Files (11 files)

| File | Phase(s) Reviewed |
|---|---|
| `tests/core/backup-manager.test.ts` | 4 |
| `tests/core/changelog.test.ts` | 4 |
| `tests/core/command-allowlist.test.ts` | 4 |
| `tests/core/config.test.ts` | 4 |
| `tests/core/executor.test.ts` | 4 |
| `tests/core/rollback.test.ts` | 4 |
| `tests/core/safeguards.test.ts` | 4 |
| `tests/core/sanitizer.test.ts` | 4 |
| `tests/core/secure-fs.test.ts` | 4 |
| `tests/core/spawn-safe.test.ts` | 4 |
| `tests/core/sudo-session.test.ts` | 4 |

### Configuration & CI Files

| File | Phase(s) Reviewed |
|---|---|
| `package.json` | 1, 5 |
| `package-lock.json` | 1, 5 |
| `tsconfig.json` | 5 |
| `vitest.config.ts` | 4, 5 |
| `.github/workflows/ci.yml` | 5 |
| `mcp-call.sh` | 5 |
| `run-assessment.mjs` | 5 |
| `src/index.ts` | 1 |

### Documentation Files (10 files)

| File | Phase(s) Reviewed |
|---|---|
| `README.md` | 1 |
| `ARCHITECTURE.md` | 1, 5 |
| `CHANGELOG.md` | 1 |
| `HARDENING-ASSESSMENT-REPORT.md` | 1 |
| `LICENSE` | 1 |
| `PREFLIGHT-ARCHITECTURE.md` | 1 |
| `REMEDIATION-PLAN.md` | 1 |
| `SAFEGUARDS.md` | 1 |
| `STANDARDS.md` | 1 |
| `TOOLS-REFERENCE.md` | 1 |
| `kali-defense-mcp-server-spec.md` | 1 |

---

*Report generated: 2026-03-07 | Audit methodology: 6-phase comprehensive security review | Total files reviewed: 67+ | Total findings: 89*
