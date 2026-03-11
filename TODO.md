# Defense MCP Server — Developer TODO

> **Project rename complete:** This codebase has been renamed from `kali-defense-mcp-server` to **Defense MCP Server** (`defense-mcp-server`). The npm package name, server metadata, and all documentation have been updated.

---

## Table of Contents

- [🔴 Section 1: High Priority Fixes](#-section-1-high-priority-fixes)
  - [Fix 1: Stale `package.json` metadata](#fix-1-stale-packagejson-metadata)
  - [Fix 2: Audit `toolName` in all `executeCommand()` calls](#fix-2-audit-toolname-in-all-executecommand-calls)
  - [Fix 3: Remove spurious runtime dependency](#fix-3-remove-spurious-runtime-dependency)
- [🟡 Section 2: Medium Priority — New Capabilities](#-section-2-medium-priority--new-capabilities)
  - [Feature 1: Security Posture Scoring & Dashboard](#feature-1-security-posture-scoring--dashboard)
  - [Feature 2: CVE Intelligence Tools](#feature-2-cve-intelligence-tools)
  - [Feature 3: Binary Memory Protection Audit](#feature-3-binary-memory-protection-audit-merge-into-hardeningts)
  - [Feature 4: Regulatory Compliance Labels](#feature-4-regulatory-compliance-labels)
- [🟢 Section 3: Lower Priority — Architectural Improvements](#-section-3-lower-priority--architectural-improvements)
  - [Improvement 1: Secure Scheduled Audit Mechanism](#improvement-1-secure-scheduled-audit-mechanism)
  - [Improvement 2: Test Coverage Gaps](#improvement-2-test-coverage-gaps)
- [✅ Section 4: Completed / Already Done](#-section-4-completed--already-done)

---

## 🔴 Section 1: High Priority Fixes

### Fix 1: Stale `package.json` metadata

**File:** [`package.json`](package.json)

The `repository`, `bugs`, and `homepage` fields in [`package.json`](package.json) still point to the old `bottobot` GitHub repository. These must be updated before any public release or npm publish, as they direct users and tooling (e.g., `npm bugs`, `npm repo`) to the wrong location.

**Current values (to be replaced):**

```json
{
  "repository": {
    "type": "git",
    "url": "git+https://github.com/YOUR_GITHUB_USERNAME/defense-mcp-server.git"
  },
  "bugs": {
    "url": "https://github.com/YOUR_GITHUB_USERNAME/defense-mcp-server/issues"
  },
  "homepage": "https://github.com/YOUR_GITHUB_USERNAME/defense-mcp-server#readme"
}
```

**Replace with:**

```json
{
  "repository": {
    "type": "git",
    "url": "git+https://github.com/YOUR_GITHUB_USERNAME/defense-mcp-server.git"
  },
  "bugs": {
    "url": "https://github.com/YOUR_GITHUB_USERNAME/defense-mcp-server/issues"
  },
  "homepage": "https://github.com/YOUR_GITHUB_USERNAME/defense-mcp-server#readme"
}
```

Replace `YOUR_GITHUB_USERNAME` with the actual GitHub username or organization that owns the new repository.

---

### Fix 2: Audit `toolName` in all `executeCommand()` calls

**File to check:** [`src/core/executor.ts`](src/core/executor.ts)

Inspect [`src/core/executor.ts`](src/core/executor.ts) to confirm whether `toolName` is a required field in the `ExecuteCommandOptions` interface. If it is required for rate-limiter keying (which is the expected design — the rate limiter in [`src/core/rate-limiter.ts`](src/core/rate-limiter.ts) keys limits per tool), then **any tool module that calls `executeCommand()` without supplying `toolName` is silently bypassing per-tool rate limiting**. All such calls fall through to the global rate limit bucket only, making per-tool throttling ineffective.

**Correct pattern** (as used in [`src/tools/hardening.ts`](src/tools/hardening.ts)):

```typescript
await executeCommand({ 
  command: "sysctl", 
  args: ["-n", key], 
  toolName: "tool_name_here",   // required for rate-limiter keying
  timeout: getToolTimeout("tool_name_here") 
});
```

**Audit command** — run this to find every `executeCommand` call that is missing `toolName`:

```bash
grep -rn "executeCommand({" src/tools/ | grep -v "toolName"
```

Review every line in the output and add the appropriate `toolName` string. The tool name should match the string used when the tool is registered on the MCP server (i.e., the first argument to `server.tool()`). Also supply `timeout: getToolTimeout("tool_name_here")` so timeouts are consistent with configuration.

---

### Fix 3: Remove spurious runtime dependency

**File:** [`package.json`](package.json)

[`package.json`](package.json) previously listed `"kali-defense-mcp-server": "^0.5.2"` in the `dependencies` (runtime) section. This was the **old upstream package** — the package this project forked from — and has since been removed. Shipping a dependency on the old package would cause:

- Unnecessary package bloat
- A confusing circular-identity situation at runtime
- Potential for version conflicts

**Before removing**, verify that no source file actually imports from it:

```bash
grep -rn "from 'defense-mcp-server'" src/
```

If that grep returns no results, it is safe to remove:

```bash
npm uninstall defense-mcp-server
```

If any `src/` file does import from it, that import must be refactored to use the local equivalent module before removing the dependency.

---

## 🟡 Section 2: Medium Priority — New Capabilities

### Feature 1: Security Posture Scoring & Dashboard

**New file:** [`src/tools/security-posture.ts`](src/tools/security-posture.ts)  
**Registration:** [`src/index.ts`](src/index.ts)  
**Test file:** [`tests/tools/security-posture.test.ts`](tests/tools/security-posture.test.ts)

#### What this adds

A weighted 0–100 security posture score computed across five domains (authentication, network, kernel, services, filesystem). Each domain check runs real system commands, assigns a domain score, and the weighted average becomes the overall score. Scores are persisted to `~/.kali-defense/posture/history.json` so trend analysis is possible over time. A dashboard tool aggregates the latest scores into a human-readable summary.

#### Three tools to implement

| Tool name | Description |
|---|---|
| `security_posture_score` | Runs all domain checks and returns the current score with per-domain breakdown |
| `security_posture_trend` | Reads `history.json` and returns score progression over the last N entries |
| `security_posture_dashboard` | Renders a combined human-readable dashboard with score + top recommendations |

#### Import block

```typescript
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeCommand } from "../core/executor.js";
import { getConfig, getToolTimeout } from "../core/config.js";
import { createTextContent, createErrorContent, formatToolOutput } from "../core/parsers.js";
import { logChange, createChangeEntry } from "../core/changelog.js";
import { SafeguardRegistry } from "../core/safeguards.js";
import { secureWriteFileSync } from "../core/secure-fs.js";
import { existsSync, readFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

const POSTURE_DIR = join(homedir(), ".kali-defense", "posture");
const HISTORY_FILE = join(POSTURE_DIR, "history.json");
const MAX_HISTORY = 1000;
```

> **Path note:** State is written to `~/.kali-defense/posture/history.json`, which is consistent with the rest of Server B's state directory convention. Do **not** use `~/.kali-mcp-posture/` (that was Server A's path and has been retired).

#### Export signature

```typescript
export function registerSecurityPostureTools(server: McpServer): void {
  // Tool: security_posture_score
  // Tool: security_posture_trend  
  // Tool: security_posture_dashboard
}
```

#### Secure file writes

All writes to `history.json` must use [`secureWriteFileSync`](src/core/secure-fs.ts) from `../core/secure-fs.js` — **never** bare `writeFileSync`. This ensures atomic writes with proper temp-file + rename semantics and enforces mode `0o600`.

```typescript
// ✅ Correct
secureWriteFileSync(HISTORY_FILE, JSON.stringify(history, null, 2));

// ❌ Wrong — do not do this
import { writeFileSync } from "node:fs";
writeFileSync(HISTORY_FILE, JSON.stringify(history, null, 2));
```

#### Passing `toolName` in all `executeCommand` calls

Every `executeCommand` call inside this module must include `toolName` and `timeout`:

```typescript
await executeCommand({
  command: "sysctl",
  args: ["-n", "kernel.randomize_va_space"],
  toolName: "security_posture_score",
  timeout: getToolTimeout("security_posture_score"),
});
```

#### Registration in `src/index.ts`

```typescript
import { registerSecurityPostureTools } from "./tools/security-posture.js";
// ...inside main():
safeRegister("security-posture", registerSecurityPostureTools);
```

#### Test file

Create [`tests/tools/security-posture.test.ts`](tests/tools/security-posture.test.ts) following the same structure as existing tool tests (e.g., [`tests/tools/hardening.test.ts`](tests/tools/hardening.test.ts)). Mock `executeCommand`, `secureWriteFileSync`, and `readFileSync` to keep tests hermetic.

---

### Feature 2: CVE Intelligence Tools

**New core module:** [`src/core/network-client.ts`](src/core/network-client.ts)  
**New tool file:** [`src/tools/vulnerability-intel.ts`](src/tools/vulnerability-intel.ts)  
**Test files:** [`tests/core/network-client.test.ts`](tests/core/network-client.test.ts), [`tests/tools/vulnerability-intel.test.ts`](tests/tools/vulnerability-intel.test.ts)

#### What this adds

- `vuln_lookup_cve` — looks up a specific CVE ID via the NVD REST API and returns severity, description, and affected packages
- `vuln_scan_packages` — runs the distro-appropriate package vulnerability scanner (`debsecan`, `apt-get upgrade -s`, or `dnf updateinfo --security`) and returns a list of vulnerable packages
- `vuln_patch_urgency` — for a named package, fetches current installed version, latest available version, and patches the changelog for security-relevant entries, returning a patch urgency rating

#### Critical architectural requirement: use the network-client module

**Do not** write inline `https.get()` calls inside tool handlers. Instead, first create the controlled network client module at [`src/core/network-client.ts`](src/core/network-client.ts). This centralizes timeout enforcement, error normalization, HTTP status handling, and future rate limiting for all outbound network calls.

**`src/core/network-client.ts`:**

```typescript
import * as https from "node:https";

interface HttpsGetOptions {
  timeout?: number;
  headers?: Record<string, string>;
}

/**
 * Controlled outbound HTTPS GET. All network calls from tools should use this.
 * Centralizes timeout enforcement, error normalization, and future rate limiting.
 */
export function httpsGet(url: string, options: HttpsGetOptions = {}): Promise<string> {
  const { timeout = 15000, headers = {} } = options;
  return new Promise((resolve, reject) => {
    const req = https.get(url, { timeout, headers }, (res) => {
      if (res.statusCode === 403) {
        reject(new Error(`HTTP 403 from ${url} — rate limited or access denied`));
        return;
      }
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode} from ${url}`));
        return;
      }
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => chunks.push(chunk));
      res.on("end", () => resolve(Buffer.concat(chunks).toString("utf-8")));
      res.on("error", reject);
    });
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error(`Request to ${url} timed out`)); });
  });
}
```

**Import in tool files:**

```typescript
import { httpsGet } from "../core/network-client.js";
```

#### Three tools to implement in `src/tools/vulnerability-intel.ts`

| Tool name | Command / API | Notes |
|---|---|---|
| `vuln_lookup_cve` | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<id>` | Validate CVE ID format (`CVE-YYYY-NNNNN`) before the request |
| `vuln_scan_packages` | `debsecan` / `apt-get upgrade -s` / `dnf updateinfo --security` | Use [`src/core/distro-adapter.ts`](src/core/distro-adapter.ts) to select the right command |
| `vuln_patch_urgency` | `dpkg-query -l <pkg>` + `apt-cache policy <pkg>` + grep changelog | Returns `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` urgency rating |

All three tools must pass `toolName` to `executeCommand` and respect the command allowlist in [`src/core/command-allowlist.ts`](src/core/command-allowlist.ts). If `debsecan`, `dpkg-query`, `apt-cache`, `dnf` are not already on the allowlist, add them there first.

---

### Feature 3: Binary Memory Protection Audit (merge into existing `hardening.ts`)

**File to modify:** [`src/tools/hardening.ts`](src/tools/hardening.ts) — **do not create a new module**

This functionality belongs inside the existing `harden_memory` tool as new `action` values, not as a separate tool file. Adding it to the existing tool keeps related hardening logic co-located and avoids proliferating tool namespaces.

#### New actions to add to `harden_memory`

| Action | Description |
|---|---|
| `audit_binaries` | Runs `readelf -h -Wl -Wd <binary>` on a supplied path (or a default set of system binaries) and reports PIE, RELRO, and NX status for each |
| `report_cpu_mitigations` | Reads `/proc/cmdline`, `/proc/cpuinfo` (flags field), and a set of security-relevant `sysctl` keys to report which CPU mitigations are active (Spectre v1/v2, Meltdown, MDS, etc.) |

#### `readelf` parsing logic skeleton

```typescript
// Check PIE: ELF Type should be "DYN" not "EXEC"
const isPIE = readelfOutput.includes("Type:") && readelfOutput.includes("DYN");

// Check RELRO: needs both GNU_RELRO and BIND_NOW
const hasRelro = readelfOutput.includes("GNU_RELRO");
const isFullRelro = readelfOutput.includes("BIND_NOW");

// Check NX: GNU_STACK should NOT have RWE flag
const hasNX = readelfOutput.includes("GNU_STACK") && !readelfOutput.includes("RWE");
```

Map these to a result object per binary:

```typescript
interface BinaryProtections {
  path: string;
  pie: boolean;           // Position-Independent Executable
  relro: "none" | "partial" | "full";
  nx: boolean;            // Non-Executable stack
}
```

#### Allowlist note

`readelf` is already on the allowlist in [`src/core/command-allowlist.ts`](src/core/command-allowlist.ts) — no changes to the allowlist are needed for the `audit_binaries` action. For `report_cpu_mitigations`, reading `/proc/cmdline` and `/proc/cpuinfo` can be done with `readFileSync` directly (no subprocess needed), and the `sysctl` calls are already allowlisted.

---

### Feature 4: Regulatory Compliance Labels

**File to modify:** [`src/tools/compliance.ts`](src/tools/compliance.ts)

#### What this adds

Each compliance check gains a structured check ID tied to a specific regulatory framework, enabling reports to cite specific control references (e.g., "PCI-DSS v4 Requirement 1.1"). This makes audit reports usable by compliance officers, not just engineers.

#### Check ID data structures

Add these interfaces to [`src/tools/compliance.ts`](src/tools/compliance.ts):

```typescript
interface ComplianceCheck {
  id: string;         // e.g. "PCI-1.1", "HIPAA-164.312a"
  framework: string;  // e.g. "pci-dss-v4"
  description: string;
  command: string;
  args: string[];
  passCondition: (output: string) => boolean;
}

type ComplianceRating = "COMPLIANT" | "PARTIALLY_COMPLIANT" | "NON_COMPLIANT";
```

#### Check IDs to implement

**Common checks (apply to all frameworks):**

| ID | Name | Command / Source |
|---|---|---|
| `AUTH-001` | No empty passwords | `grep -E '^[^:]+::' /etc/shadow` (empty = fail) |
| `NET-001` | IP forwarding disabled | `sysctl net.ipv4.ip_forward` (0 = pass) |
| `NET-002` | SYN cookies enabled | `sysctl net.ipv4.tcp_syncookies` (1 = pass) |
| `KERN-001` | ASLR enabled | `sysctl kernel.randomize_va_space` (2 = pass) |
| `KERN-002` | dmesg restricted | `sysctl kernel.dmesg_restrict` (1 = pass) |
| `FS-001` | `/etc/passwd` permissions | `stat -c '%a' /etc/passwd` (644 = pass) |
| `FS-002` | `/etc/shadow` permissions | `stat -c '%a' /etc/shadow` (640 or 000 = pass) |
| `SVC-001` | Telnet not active | `ss -tlnp` (no `:23` = pass) |
| `SSH-001` | SSH PermitRootLogin disabled | `sshd -T` grep `permitrootlogin no` |

**PCI-DSS v4:**

| ID | Name | Details |
|---|---|---|
| `PCI-1.1` | Firewall rules present | `iptables -L` or `nft list ruleset` — non-empty = pass |
| `PCI-8.2` | Password minimum length ≥ 12 | `grep minlen /etc/security/pwquality.conf` — value ≥ 12 = pass |

**HIPAA:**

| ID | Name | Details |
|---|---|---|
| `HIPAA-164.312a` | Audit logging active | `systemctl is-active auditd` = `active` |

**SOC 2:**

| ID | Name | Details |
|---|---|---|
| `SOC2-CC6.1` | Audit logging active | `systemctl is-active auditd` = `active` |

**ISO 27001:**

| ID | Name | Details |
|---|---|---|
| `ISO-A.12.4.1` | System logging active | `systemctl is-active rsyslog` or `systemd-journald` active |

**GDPR:**

| ID | Name | Details |
|---|---|---|
| `GDPR-Art32` | Encryption tooling present | `which openssl` returns a path |

#### ⚠️ Critical: ESM import rule

**Do not** use `require()` inside functions. All imports must be top-level ESM `import` statements:

```typescript
// ✅ Correct — top-level ESM import
import { statSync } from "node:fs";

// ❌ Wrong — never do this in ESM modules
function checkFile() {
  const { statSync } = require("fs"); // This will throw in ESM context
}
```

---

## 🟢 Section 3: Lower Priority — Architectural Improvements

### Improvement 1: Secure Scheduled Audit Mechanism

**Context:** Server A (the upstream) had a scheduled audit feature that accepted user-supplied shell command strings and embedded them directly into systemd `ExecStart=/bin/bash -c '...'` lines. This is a **critical command injection vulnerability** — any user who can call that MCP tool can execute arbitrary shell commands as the service user. This feature was intentionally removed in Server B and must **not** be re-added in its original form.

#### Safe design for scheduled audits

If scheduled auditing is re-introduced, it must follow these constraints:

1. **Accept only a `toolName` parameter**, validated against a fixed allowlist of registered MCP tool names (e.g., the keys from the tool registry). Never accept free-form shell strings from users.

2. **The systemd service must call the MCP server itself** (or a dedicated, compiled audit runner binary) with the tool name as a flag — never use `ExecStart=/bin/bash -c '...'` with user-supplied content.

3. **All service file writes** must go through [`secureWriteFileSync`](src/core/secure-fs.ts) — never `writeFileSync` or shell redirection.

4. **Never use `/bin/bash -c`** in the service template. Allowlisted binaries only, invoked via [`src/core/spawn-safe.ts`](src/core/spawn-safe.ts).

**Safe systemd unit template pattern:**

```
[Service]
ExecStart=/usr/local/bin/defense-mcp-audit --tool=<validated_tool_name>
User=defense-mcp
NoNewPrivileges=true
```

Where `<validated_tool_name>` is substituted only after validation against the registered tool list — it is never passed through a shell interpreter.

---

### Improvement 2: Test Coverage Gaps

**Test directory:** [`tests/tools/`](tests/tools/)

All 31 existing tool modules have corresponding test files in [`tests/tools/`](tests/tools/). Any newly added tool modules (see Section 2: Features 1 and 2) must have corresponding test files created at the same time as the implementation — not after.

#### Files needed for new features

| New module | Required test file |
|---|---|
| [`src/tools/security-posture.ts`](src/tools/security-posture.ts) | [`tests/tools/security-posture.test.ts`](tests/tools/security-posture.test.ts) |
| [`src/tools/vulnerability-intel.ts`](src/tools/vulnerability-intel.ts) | [`tests/tools/vulnerability-intel.test.ts`](tests/tools/vulnerability-intel.test.ts) |
| [`src/core/network-client.ts`](src/core/network-client.ts) | [`tests/core/network-client.test.ts`](tests/core/network-client.test.ts) |

#### Test file template pattern

Follow the structure of existing tests such as [`tests/tools/hardening.test.ts`](tests/tools/hardening.test.ts):

```typescript
import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock core dependencies before importing the module under test
vi.mock("../../src/core/executor.js", () => ({
  executeCommand: vi.fn(),
}));
vi.mock("../../src/core/secure-fs.js", () => ({
  secureWriteFileSync: vi.fn(),
}));

import { registerSecurityPostureTools } from "../../src/tools/security-posture.js";
import { executeCommand } from "../../src/core/executor.js";

describe("security-posture tools", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("security_posture_score", () => {
    it("returns a score between 0 and 100", async () => {
      // Arrange
      vi.mocked(executeCommand).mockResolvedValue({ stdout: "2\n", stderr: "", exitCode: 0 });
      // Act + Assert
      // ...
    });
  });
});
```

Key rules for test files:
- Mock `executeCommand` — never let tests spawn real subprocesses
- Mock `secureWriteFileSync` — never write real files in tests
- Mock `httpsGet` (for vulnerability-intel) — never make real network requests in tests
- Each tool must have at least one success-path test and one error-path test
- Tests must be runnable with `npm test` (vitest) without any system dependencies

---

## ✅ Section 4: Completed / Already Done

The following capabilities are fully implemented in Server B. Do **not** re-add or re-implement these — they were intentionally designed and tested. If you see a PR or suggestion to add something that sounds like one of these, check this list first.

| Component | File(s) | Notes |
|---|---|---|
| **Command allowlist** | [`src/core/command-allowlist.ts`](src/core/command-allowlist.ts) | 153 entries, resolved to absolute paths at startup; all `executeCommand` calls are validated against this list |
| **Per-tool rate limiter** | [`src/core/rate-limiter.ts`](src/core/rate-limiter.ts) | 30 calls/tool/minute, 100 calls/global/minute; keyed by `toolName` — see Fix 2 above |
| **Encrypted state** | [`src/core/encrypted-state.ts`](src/core/encrypted-state.ts) | AES-GCM encrypted persistence for sensitive state |
| **Secure filesystem writes** | [`src/core/secure-fs.ts`](src/core/secure-fs.ts) | Atomic temp-file + rename writes, enforces `0o600` mode — use this everywhere |
| **Safe subprocess spawning** | [`src/core/spawn-safe.ts`](src/core/spawn-safe.ts) | No shell interpolation; args passed as array; used by executor |
| **Full test suite** | [`tests/`](tests/) | 74+ tests across core and tool modules; run with `npm test` |
| **Graceful shutdown** | [`src/index.ts`](src/index.ts) | SIGTERM and SIGINT handlers ensure clean exit |
| **Error-isolated module registration** | [`src/index.ts`](src/index.ts) | `safeRegister()` wraps each tool module so one failing module does not crash the server |
| **Parallel startup** | [`src/index.ts`](src/index.ts) | `Promise.allSettled()` used for concurrent initialization |
| **Secrets scanning** | [`src/tools/secrets.ts`](src/tools/secrets.ts) | Supersedes old `secrets-scanner.ts`; already includes git history scanning and error sanitization (no raw secret values in error messages) |
| **Container security** | [`src/tools/container-security.ts`](src/tools/container-security.ts) | Supersedes old `container-advanced.ts`; covers privileged container detection, seccomp, AppArmor profiles |

---

*Last updated: 2026-03-11. Maintainer: Defense MCP Server project.*
