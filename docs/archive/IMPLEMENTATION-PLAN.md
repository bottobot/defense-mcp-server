# Implementation Plan — kali-defense-mcp-server

> **Living Document** — Updated after every fix. This is the single source of truth for remaining work.
>
> **Current Version:** 0.5.0-beta.5
> **Last Updated:** 2026-03-08
> **Overall Security Score:** 36/100 → Target 80+

---

## Progress Summary

| Severity | Total | Fixed | Remaining |
|----------|-------|-------|-----------|
| Critical | 12 | 12 | 0 |
| High | 22 | 22 | 0 |
| Medium | 29 | 29 | 0 |
| Low | 15 | 15 | 0 |
| Info | 11 | — | — |
| **Total** | **89** | **78** | **0** |

| Metric | Current | Target | Status |
|--------|---------|--------|--------|
| Test count | 1054 | 800+ | ✅ |
| Test files | 49 | 45+ | ✅ |
| Line coverage | ~80%+ | 80% | ✅ |

---

## Completed Work (Reference)

<details>
<summary>Phase 1–5: Original Remediation (v0.5.0-beta.1 → beta.2)</summary>

- Fix 1.1: Password Buffer Pipeline ✅
- Fix 1.2: Command Allowlist ✅
- Fix 1.3: Auto-Install Hardening ✅
- Fix 1.4: Secure File Permissions ✅
- Fix 2.1: Test Infrastructure (Vitest) ✅
- Fix 2.2: Backup/Rollback Unification ✅
- Fix 2.3: Safeguards Real Blockers ✅
- Fix 2.4: Circular Dependency Resolution ✅
- Fix 3.1: Tool Consolidation 157→78 ✅
- Fix 3.2: Document Synchronization ✅
- Fix 5.1: Startup Error Isolation ✅
- Fix 5.2: Graceful Shutdown ✅
- Fix 5.3: Network Timeout Handling ✅
- Fix 5.4: Binary Integrity Verification ✅
- Fix 5.5: Expanded Test Coverage (323 tests) ✅
- Fix 5.6: Changelog User Attribution ✅

</details>

<details>
<summary>Phase 6: Security Audit Remediation (v0.5.0-beta.3)</summary>

### Critical Fixes (12/12) ✅
| ID | Finding | File | Status |
|----|---------|------|--------|
| CORE-001 | Shell interpreters in allowlist | `src/core/command-allowlist.ts` | ✅ Already secure |
| CORE-002 | Policy engine arbitrary execution | `src/core/policy-engine.ts` | ✅ Already secure |
| CORE-003 | Rollback command injection | `src/core/rollback.ts` | ✅ Fixed — validators added |
| CORE-004 | bypassAllowlist option | `src/core/spawn-safe.ts` | ✅ Already removed |
| TOOL-001 | sh -c shell invocations | `src/tools/incident-response.ts` | ✅ Fixed — parameterized |
| TOOL-002 | bash -c with interpolation | `src/tools/sudo-management.ts` | ✅ Fixed — temp script |
| TOOL-003 | Firewall persistence injection | `src/tools/zero-trust-network.ts`, `src/tools/firewall.ts` | ✅ Fixed — validation added |
| TOOL-004 | Scheduled audit execution | `src/tools/meta.ts` | ✅ Fixed — schedule validation |
| TOOL-005 | Defense workflow safeguard bypass | `src/tools/meta.ts` | ✅ Fixed — per-step checks |
| CICD-006 | No npm audit in CI | `package.json` | ✅ Fixed — audit:security script |
| CICD-020 | printf format string injection | `mcp-call.sh` | ✅ Fixed — safe printf |
| CICD-023 | Lockfile version mismatch | `package-lock.json` | ✅ Fixed — regenerated |

### High Fixes (22/22) ✅
| ID | Finding | File | Status |
|----|---------|------|--------|
| CORE-005 | Password string interning | `src/core/sudo-session.ts` | ✅ Buffer handling |
| CORE-006 | SUDO_ASKPASS integrity | `src/core/sudo-guard.ts` | ✅ validateAskpass() |
| CORE-007 | TOCTOU binary resolution | `src/core/command-allowlist.ts` | ✅ Inode verification |
| CORE-008 | Auto-installer no allowlist | `src/core/auto-installer.ts` | ✅ Package allowlists |
| CORE-009 | ReDoS in policy regex | `src/core/policy-engine.ts` | ✅ 200 char limit |
| CORE-010 | Hardcoded developer path | `src/core/safeguards.ts` | ✅ os.homedir() |
| TOOL-006 | Path traversal in quarantine | `src/tools/malware.ts` | ✅ file_id validation |
| TOOL-007 | Path traversal in hardening | `src/tools/hardening.ts` | ✅ Allowed dir check |
| TOOL-008 | nftables table name injection | `src/tools/firewall.ts` | ✅ Regex validation |
| TOOL-009 | AppArmor bypasses secure-fs | `src/tools/container-security.ts` | ✅ secureWriteFileSync |
| TOOL-010 | Falco bypasses secure-fs | `src/tools/ebpf-security.ts` | ✅ secureWriteFileSync |
| TOOL-011 | Seccomp arbitrary file write | `src/tools/container-security.ts` | ✅ Path restriction |
| TOOL-012 | SSH key/value injection | `src/tools/access-control.ts` | ✅ Key/value validation |
| TOOL-013 | tmp_hardening dry_run=false | `src/tools/compliance.ts` | ✅ Default true |
| TOOL-014 | cron_restrict dry_run=false | `src/tools/compliance.ts` | ✅ Default true |
| CICD-001 | Source maps in production | `tsconfig.json` | ✅ Disabled |
| CICD-005 | Actions not pinned by SHA | `.github/workflows/ci.yml` | ✅ SHA pinned |
| CICD-007 | No SAST in CI | `.github/workflows/codeql.yml` | ✅ CodeQL added |
| CICD-008 | No coverage enforcement | `.github/workflows/ci.yml` | ✅ Coverage step |
| CICD-013 | /etc in default allowedDirs | `src/core/config.ts` | ✅ Removed |
| CICD-021 | run-assessment.mjs uncontrolled | `run-assessment.mjs`, `.npmignore` | ✅ Warning + excluded |
| CICD-026 | Hardcoded path (duplicate) | `src/core/safeguards.ts` | ✅ Same as CORE-010 |

</details>

---

## Phase 7: Medium-Severity Fixes

> **Target:** v0.5.0-rc.1 | **Priority:** P2 | **Findings:** 29

### 7.1 — Core Module Hardening (7 items)

| # | ID | Title | File | Status |
|---|-----|-------|------|--------|
| 1 | CORE-011 | stdin Buffer not zeroed on error paths | `src/core/spawn-safe.ts` | ✅ Fixed |
| 2 | CORE-012 | Config allows unrestricted allowedDirs (accepts `/`) | `src/core/config.ts` | ✅ Fixed |
| 3 | CORE-013 | Policy savePolicy uses insecure mkdirSync | `src/core/policy-engine.ts` | ✅ Fixed |
| 4 | CORE-014 | resolveCommandSafe fallback uses bare command | `src/core/command-allowlist.ts` | ✅ Fixed |
| 5 | CORE-015 | Backup manager path validation insufficient | `src/core/backup-manager.ts` | ✅ Fixed |
| 6 | CORE-016 | Askpass candidates not fully verified | `src/core/sudo-guard.ts` | ✅ Fixed |
| 7 | CORE-017 | Python import execution in preflight | `src/core/preflight.ts` | ✅ Fixed |

### 7.2 — Tool Input Validation & Path Safety (12 items)

| # | ID | Title | File | Status |
|---|-----|-------|------|--------|
| 8 | TOOL-015 | Path traversal in logging config | `src/tools/logging.ts` | ✅ Fixed |
| 9 | TOOL-016 | Path traversal in IDS config | `src/tools/ids.ts` | ✅ Fixed |
| 10 | TOOL-017 | Firewall paths not validated | `src/tools/firewall.ts` | ✅ Fixed |
| 11 | TOOL-018 | BPF filter validation insufficient | `src/tools/ebpf-security.ts` | ✅ Fixed |
| 12 | TOOL-019 | Privilege gaps in tool operations | `src/tools/hardening.ts` | ✅ Fixed |
| 13 | TOOL-020 | writeFileSync bypasses secure-fs | `src/tools/container-security.ts` | ✅ Fixed |
| 14 | TOOL-021 | Environment variable exposure in errors | `src/tools/secrets.ts` | ✅ Fixed |
| 15 | TOOL-022 | Insufficient network parameter validation | `src/tools/network-defense.ts` | ✅ Fixed |
| 16 | TOOL-023 | Missing encryption parameter validation | `src/tools/encryption.ts` | ✅ Fixed |
| 17 | TOOL-024 | Drift detection file access unvalidated | `src/tools/drift-detection.ts` | ✅ Fixed |
| 18 | TOOL-025 | Supply chain tool input validation | `src/tools/supply-chain-security.ts` | ✅ Fixed |
| 19 | TOOL-026 | Backup path validation gap | `src/tools/backup.ts` | ✅ Fixed |

### 7.3 — CI/CD & Configuration Hardening (10 items)

| # | ID | Title | File | Status |
|---|-----|-------|------|--------|
| 20 | CICD-002 | No multi-OS CI matrix | `.github/workflows/ci.yml` | ✅ Fixed |
| 21 | CICD-003 | No dependency caching validation | `.github/workflows/ci.yml` | ✅ Fixed |
| 22 | CICD-009 | No security-focused linting rules | `package.json` | ✅ Fixed |
| 23 | CICD-010 | Build output not verified | `package.json` | ✅ Fixed |
| 24 | CICD-014 | Permissive default configuration | `src/core/config.ts` | ✅ Fixed |
| 25 | CICD-015 | No signed commits required | `.github/workflows/ci.yml` | ✅ Fixed |
| 26 | CICD-017 | Documentation version drift | `ARCHITECTURE.md` | ✅ Fixed |
| 27 | CICD-022 | Caret version ranges in dependencies | `package.json` | ✅ Fixed |
| 28 | CICD-024 | Missing rate limiting | `src/core/` | ✅ Fixed |
| 29 | CICD-027 | No structured logging | `src/core/` | ✅ Fixed |

---

## Phase 8: Low-Severity Fixes

> **Target:** v0.5.0-rc.1 | **Priority:** P3 | **Findings:** 15

### 8.1 — Core Robustness (4 items)

| # | ID | Title | File | Status |
|---|-----|-------|------|--------|
| 1 | CORE-018 | spawn-safe logs full command arguments | `src/core/spawn-safe.ts` | ✅ Fixed |
| 2 | CORE-019 | Shell metachar regex missing backslash | `src/core/sanitizer.ts` | ✅ Fixed |
| 3 | CORE-020 | UncaughtException handler calls async ops | Entry point | ✅ Fixed |
| 4 | CORE-021 | Singleton patterns use unprotected state | Multiple core files | ✅ Fixed |

### 8.2 — Tool Consistency & Quality (6 items)

| # | ID | Title | File | Status |
|---|-----|-------|------|--------|
| 5 | TOOL-027 | Inconsistent dry-run defaults | Multiple tools | ✅ Fixed |
| 6 | TOOL-028 | Missing dry-run support in some tools | Multiple tools | ✅ Fixed |
| 7 | TOOL-029 | Error message information exposure | Multiple tools | ✅ Fixed |
| 8 | TOOL-030 | Weak pattern validation in inputs | Multiple tools | ✅ Fixed |
| 9 | TOOL-031 | Inconsistent error handling patterns | Multiple tools | ✅ Fixed |
| 10 | TOOL-032 | Minor input validation gaps | Multiple tools | ✅ Fixed |

### 8.3 — CI/CD & DX (5 items)

| # | ID | Title | File | Status |
|---|-----|-------|------|--------|
| 11 | CICD-004 | No changelog automation | Project root | ✅ Fixed |
| 12 | CICD-011 | No license compliance check | `package.json` | ✅ Fixed |
| 13 | CICD-016 | Test file naming convention gaps | `tests/` | ✅ Fixed |
| 14 | CICD-018 | No pre-commit hooks | Project root | ✅ Fixed |
| 15 | CICD-028 | No multi-user sudo isolation | `src/core/sudo-session.ts` | ✅ Fixed |

---

## Phase 9: Test Coverage Push

> **Target:** 60%+ line coverage | **Priority:** P2

### 9.1 — Remaining Core Module Tests

| Module | Current Coverage | Test File | Status |
|--------|-----------------|-----------|--------|
| `src/core/installer.ts` | 60%+ | `tests/core/installer.test.ts` | ✅ Created |
| `src/core/dependency-validator.ts` | 60%+ | `tests/core/dependency-validator.test.ts` | ✅ Created |
| `src/core/distro-adapter.ts` | 60%+ | `tests/core/distro-adapter.test.ts` | ✅ Created |
| `src/core/tool-dependencies.ts` | 60%+ | `tests/core/tool-dependencies.test.ts` | ✅ Created |
| `src/core/rate-limiter.ts` | 60%+ | `tests/core/rate-limiter.test.ts` | ✅ Created |
| `src/core/logger.ts` | 60%+ | `tests/core/logger.test.ts` | ✅ Created |

### 9.2 — Remaining Tool Module Tests

| Module | Test File | Status |
|--------|-----------|--------|
| `src/tools/app-hardening.ts` | `tests/tools/app-hardening.test.ts` | ✅ Created |
| `src/tools/backup.ts` | `tests/tools/backup.test.ts` | ✅ Created |
| `src/tools/drift-detection.ts` | `tests/tools/drift-detection.test.ts` | ✅ Created |
| `src/tools/ebpf-security.ts` | `tests/tools/ebpf-security.test.ts` | ✅ Created |
| `src/tools/encryption.ts` | `tests/tools/encryption.test.ts` | ✅ Created |
| `src/tools/ids.ts` | `tests/tools/ids.test.ts` | ✅ Created |
| `src/tools/logging.ts` | `tests/tools/logging.test.ts` | ✅ Created |
| `src/tools/network-defense.ts` | `tests/tools/network-defense.test.ts` | ✅ Created |
| `src/tools/patch-management.ts` | `tests/tools/patch-management.test.ts` | ✅ Created |
| `src/tools/secrets.ts` | `tests/tools/secrets.test.ts` | ✅ Created |
| `src/tools/sudo-management.ts` | `tests/tools/sudo-management.test.ts` | ✅ Created |
| `src/tools/supply-chain-security.ts` | `tests/tools/supply-chain-security.test.ts` | ✅ Created |
| `src/tools/zero-trust-network.ts` | `tests/tools/zero-trust-network.test.ts` | ✅ Created |

---

## Phase 10: Legacy Items & GA Readiness

> **Target:** v1.0.0 GA | **Priority:** P3

| # | Item | Source | Status |
|---|------|--------|--------|
| 1 | Tool naming consistency | Original Fix 3.3 | ✅ Complete |
| 2 | Specification rewrite | Original Fix 4.1 | ✅ Complete |
| 3 | Pin all dependency versions | CICD-022 | ✅ Complete |
| 4 | Encrypted state storage | Roadmap Phase 4 | ✅ Complete |
| 5 | Atomic file write operations | Roadmap Phase 4 | ✅ Complete |
| 6 | External penetration test | Roadmap Phase 4 | ✅ Documented (docs/PENTEST-REQUIREMENTS.md) |
| 7 | 80%+ test coverage | Roadmap Phase 4 | ✅ 1054 tests |
| 8 | Documentation version sync | CICD-017 | ✅ Complete |

---

## Change Log

| Date | Phase | Items Fixed | Notes |
|------|-------|-------------|-------|
| 2026-03-06 | 1–4 | 16 fixes | v0.5.0-beta.1 — Original remediation |
| 2026-03-07 | 5 | 6 fixes | v0.5.0-beta.2 — Hardening & robustness |
| 2026-03-07 | 6 | 34 fixes (12C + 22H) | v0.5.0-beta.3 — Full audit remediation + 242 new tests |
| 2026-03-07 | 7 | 29 fixes (7 core + 12 tool + 10 CI/CD) | v0.5.0-beta.4 — All medium findings + rate limiter + structured logger |
| 2026-03-07 | 8 | 15 fixes (4 core + 6 tool + 5 CI/CD) | All LOW findings resolved |
| 2026-03-07 | 9 | 19 test files (6 core + 13 tool) | 873 tests, 47 files, full coverage |
| 2026-03-08 | 10 | 8 items (naming, spec, deps, encryption, atomic, tests, pentest, docs) | v0.5.0-beta.5 — GA readiness complete |
