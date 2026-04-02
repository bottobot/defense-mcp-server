# Implementation Plan: 15 Security Enhancements

> Generated 2026-03-30 | defense-mcp-server v0.9.0 | MCP SDK v1.27.1 | Zod v3.25.76

---

## Table of Contents

- [Overview](#overview)
- [Phase 1: Core Infrastructure](#phase-1-core-infrastructure-items-6-7-8-15)
- [Phase 2: New Tool Actions (High Priority)](#phase-2-new-tool-actions-high-priority-items-1-5)
- [Phase 3: New Tool Actions (Medium Priority)](#phase-3-new-tool-actions-medium-priority-items-9-14)
- [Cross-Cutting Changes](#cross-cutting-changes)
- [Implementation Sequence](#implementation-sequence)
- [Risk Matrix](#risk-matrix)

---

## Overview

15 enhancements identified from competitive analysis of security MCP servers (Puliczek/awesome-mcp-security, FuzzingLabs/mcp-security-hub, cyproxio/mcp-for-security, Wazuh MCP servers, pfSense MCP, and others).

### Current Architecture (Key Patterns)

```
Tool Registration:  server.tool(name, description, zodSchema, handler)
Execution:          executeCommand({ toolName, command, args }) | spawnSafe(cmd, args)
Results:            createTextContent(text) | formatToolOutput(json) | createErrorContent(msg)
Config:             env vars -> getConfig() with 5s cache
Safety:             command-allowlist.ts -> sanitizer.ts -> spawn(shell:false)
Pre-flight:         tool-wrapper.ts Proxy -> PreflightEngine -> dependency check -> privilege check
Testing:            vitest + vi.mock() + createMockServer() helper
```

The SDK v1.27.1 `server.tool()` supports a 5-arg overload for annotations:
```typescript
server.tool(name, description, paramsSchema, annotations: ToolAnnotations, handler)
// ToolAnnotations: { title?, readOnlyHint?, destructiveHint?, idempotentHint?, openWorldHint? }
```

---

## Phase 1: Core Infrastructure (Items 6, 7, 8, 15)

### Item 7: MCP Tool Annotations

**Priority:** HIGH | **Effort:** Low | **Risk:** Low | **Depends on:** Nothing

Adds `readOnlyHint`/`destructiveHint` metadata to all 31 tools. Required for Anthropic Connectors directory submission.

#### New File: `src/core/tool-annotations.ts`

```typescript
import type { ToolAnnotations } from "@modelcontextprotocol/sdk/types.js";

export const TOOL_ANNOTATIONS: Record<string, ToolAnnotations> = {
  // ── Read-only tools (all actions are non-modifying) ──────────
  secrets:          { readOnlyHint: true,  destructiveHint: false, idempotentHint: true,  openWorldHint: false },
  cloud_security:   { readOnlyHint: true,  destructiveHint: false, idempotentHint: true,  openWorldHint: true  },
  process_security: { readOnlyHint: true,  destructiveHint: false, idempotentHint: true,  openWorldHint: false },
  api_security:     { readOnlyHint: true,  destructiveHint: false, idempotentHint: true,  openWorldHint: true  },

  // ── Destructive tools (have at least one state-modifying action) ──
  firewall:           { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  harden_kernel:      { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  harden_host:        { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  access_control:     { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  compliance:         { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  integrity:          { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  log_management:     { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  malware:            { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  container_docker:   { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  container_isolation:{ readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  ebpf:               { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  crypto:             { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  network_defense:    { readOnlyHint: false, destructiveHint: false, idempotentHint: true,  openWorldHint: false },
  patch:              { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  incident_response:  { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  defense_mgmt:       { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  sudo_session:       { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  backup:             { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  supply_chain:       { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  zero_trust:         { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  honeypot_manage:    { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  dns_security:       { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  threat_intel:       { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  vuln_manage:        { readOnlyHint: false, destructiveHint: false, idempotentHint: true,  openWorldHint: true  },
  waf_manage:         { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  wireless_security:  { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  app_harden:         { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
};

export function getToolAnnotations(toolName: string): ToolAnnotations | undefined {
  return TOOL_ANNOTATIONS[toolName];
}

export function isReadOnlyTool(toolName: string): boolean {
  return TOOL_ANNOTATIONS[toolName]?.readOnlyHint === true;
}
```

#### Modify: `src/core/tool-wrapper.ts`

Auto-inject annotations in the proxy so **zero changes** to 29 tool files are needed. In `createWrappedToolMethod`, after building `wrappedArgs`:

```typescript
import { getToolAnnotations } from "./tool-annotations.js";

// Inside the wrapped method, after const toolName = args[0]:
const annotations = getToolAnnotations(toolName);
if (annotations) {
  // Insert annotations before the handler (last arg)
  wrappedArgs.splice(wrappedArgs.length - 1, 0, annotations);
}
```

The SDK's `tool()` method distinguishes annotations from Zod schemas via `isZodRawShapeCompat()` — a plain object like `{readOnlyHint: true}` will not pass that check, so it will be correctly identified as annotations.

#### Tests: `tests/core/tool-annotations.test.ts`
- All 31 tools have annotation entries
- Read-only classification is correct
- `getToolAnnotations("unknown")` returns undefined
- Proxy correctly passes annotations to SDK

---

### Item 8: Read-Only Mode / Tool Allowlisting

**Priority:** HIGH | **Effort:** Low | **Risk:** Low | **Depends on:** Item 7

#### Modify: `src/core/config.ts`

Add to `DefenseConfig` interface:
```typescript
/** DEFENSE_MCP_READ_ONLY=true restricts to audit-only tools. Default: false */
readOnly: boolean;
/** DEFENSE_MCP_ALLOWED_TOOLS=firewall,compliance — comma-separated. Default: "" (all) */
allowedTools: string[];
```

In `buildConfigFromEnv()`:
```typescript
readOnly: process.env.DEFENSE_MCP_READ_ONLY === "true",
allowedTools: (process.env.DEFENSE_MCP_ALLOWED_TOOLS ?? "")
  .split(",").map(s => s.trim()).filter(Boolean),
```

#### Modify: `src/core/tool-wrapper.ts`

In `createWrappedToolMethod`, before forwarding to `originalTool()`:
```typescript
const config = getConfig();

if (config.allowedTools.length > 0 && !config.allowedTools.includes(toolName)) {
  console.error(`[tool-filter] Skipping '${toolName}' — not in DEFENSE_MCP_ALLOWED_TOOLS`);
  return undefined;
}

if (config.readOnly && !isReadOnlyTool(toolName)) {
  console.error(`[tool-filter] Skipping destructive tool '${toolName}' — read-only mode`);
  return undefined;
}
```

Filtering at registration time (startup) means filtered tools never appear in the MCP client's tool list.

#### Modify: `src/index.ts`

Add startup logging after `safeRegister()` calls:
```typescript
if (config.readOnly) console.error("[startup] READ-ONLY mode — only audit tools registered");
if (config.allowedTools.length > 0) console.error(`[startup] Allowed tools: ${config.allowedTools.join(", ")}`);
```

#### Tests
- `DEFENSE_MCP_READ_ONLY=true` skips destructive tools, keeps read-only
- `DEFENSE_MCP_ALLOWED_TOOLS=firewall` only registers firewall
- Empty allowlist = all tools (default)

---

### Item 6: Output Sanitization (Credential Redaction)

**Priority:** HIGH | **Effort:** Low | **Risk:** Low | **Depends on:** Nothing

#### New File: `src/core/output-redactor.ts`

```typescript
const REDACTION_PATTERNS: Array<{ pattern: RegExp; replacement: string; label: string }> = [
  // Private key blocks
  { pattern: /-----BEGIN\s[\w\s]*PRIVATE KEY-----[\s\S]*?-----END\s[\w\s]*PRIVATE KEY-----/g,
    replacement: "[REDACTED: private key]", label: "private-key" },

  // AWS access keys (AKIA...)
  { pattern: /\bAKIA[0-9A-Z]{16}\b/g,
    replacement: "[REDACTED: AWS key]", label: "aws-key" },

  // AWS secret key patterns
  { pattern: /(?:aws_secret_access_key|secret[_-]?access[_-]?key)\s*[=:]\s*[A-Za-z0-9/+=]{40}/gi,
    replacement: "[REDACTED: AWS secret]", label: "aws-secret" },

  // Password patterns
  { pattern: /(?:password|passwd|pass|pwd)\s*[=:]\s*\S+/gi,
    replacement: "[REDACTED: password]", label: "password" },

  // Auth headers
  { pattern: /(?:Authorization|Bearer|Basic)\s*[:=]\s*\S+/gi,
    replacement: "[REDACTED: auth token]", label: "auth-header" },

  // API keys/tokens
  { pattern: /(?:api[_-]?key|api[_-]?token|access[_-]?token|auth[_-]?token|secret[_-]?key)\s*[=:]\s*\S+/gi,
    replacement: "[REDACTED: api key]", label: "api-key" },

  // Connection strings with credentials
  { pattern: /(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp|mssql):\/\/[^:]+:[^@]+@/gi,
    replacement: "[REDACTED: connection string]://", label: "connection-string" },

  // /etc/shadow hashes
  { pattern: /^([^:]+):\$[0-9a-z]+\$[^:]+:/gm,
    replacement: "$1:[REDACTED: hash]:", label: "shadow-hash" },
];

export interface RedactionResult {
  text: string;
  redactionCount: number;
  matchedPatterns: string[];
}

export function redactOutput(text: string): RedactionResult {
  if (!text) return { text, redactionCount: 0, matchedPatterns: [] };
  let result = text;
  let redactionCount = 0;
  const matchedPatterns: string[] = [];

  for (const { pattern, replacement, label } of REDACTION_PATTERNS) {
    pattern.lastIndex = 0;
    const matches = result.match(pattern);
    if (matches?.length) {
      redactionCount += matches.length;
      matchedPatterns.push(label);
      result = result.replace(pattern, replacement);
    }
  }
  return { text: result, redactionCount, matchedPatterns };
}
```

#### Modify: `src/core/executor.ts`

In `child.on("close")`, after `Buffer.concat` produces stdout/stderr strings, before `resolve()`:

```typescript
import { redactOutput } from "./output-redactor.js";

// Apply output redaction
if (getConfig().redactOutput) {
  const stdoutR = redactOutput(stdout);
  const stderrR = redactOutput(stderr);
  stdout = stdoutR.text;
  stderr = stderrR.text;
  if (stdoutR.redactionCount + stderrR.redactionCount > 0) {
    console.error(`[output-redactor] Redacted ${stdoutR.redactionCount + stderrR.redactionCount} sensitive pattern(s) from '${options.toolName}'`);
  }
}
```

#### Modify: `src/core/config.ts`

Add: `redactOutput: boolean` to `DefenseConfig` (default: `true`).

```typescript
redactOutput: process.env.DEFENSE_MCP_REDACT_OUTPUT !== "false",
```

#### Tests: `tests/core/output-redactor.test.ts`
- Private key redaction
- AWS key redaction
- Password pattern redaction
- Connection string redaction
- Shadow hash redaction
- No false positives on clean text
- Performance: 1MB input < 100ms

---

### Item 15: MCP Self-Security Audit

**Priority:** LOW | **Effort:** Low | **Risk:** Low | **Depends on:** Items 6, 7, 8

#### Modify: `src/tools/meta.ts`

Add `"self_audit"` to the action enum. Add `verbose: z.boolean().optional().default(false)` parameter.

Implement `performSelfAudit(verbose: boolean)` helper that checks:

1. **State directory permissions** — `verifySecurePermissions()` on `~/.defense-mcp` tree
2. **Changelog integrity** — `verifyChangelog()` for hash-chain validity
3. **Allowlist status** — `isAllowlisted()` for critical binaries
4. **Binary integrity** — `verifyAllBinaries()` results
5. **Config security** — dryRun, requireConfirmation, backupEnabled, readOnly, redactOutput
6. **Rate limiter status** — `RateLimiter.instance()` configuration
7. **Overall score** — count of passed vs warned checks

Output format:
```
=== Defense MCP Self-Security Audit ===
1. State Directory: OK (0700)
2. Changelog: VALID (47 entries, chain intact)
3. Allowlist: 12/14 binaries verified
4. Binary Integrity: 10 verified, 1 warning
5. Config: [OK] dryRun=true [WARN] readOnly=false
6. Rate Limiter: 30/tool, 100/global, 60s window
Overall: 9/10 (1 warning)
```

#### Tests: Extend `tests/tools/meta.test.ts`

---

## Phase 2: New Tool Actions — High Priority (Items 1-5)

### Item 1: OWASP HTTP Security Header Auditing

**Priority:** HIGH | **Effort:** Low | **Target:** `api_security` → `header_audit`

#### Constants

```typescript
const OWASP_SECURITY_HEADERS = [
  { name: "Content-Security-Policy", desc: "Prevents XSS and injection attacks",
    nginx: "add_header Content-Security-Policy \"default-src 'self'\";",
    apache: "Header set Content-Security-Policy \"default-src 'self'\"" },
  { name: "Strict-Transport-Security", desc: "Forces HTTPS",
    nginx: "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\";",
    apache: "Header set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"" },
  { name: "X-Frame-Options", desc: "Prevents clickjacking",
    nginx: "add_header X-Frame-Options \"DENY\";", apache: "Header set X-Frame-Options \"DENY\"" },
  { name: "X-Content-Type-Options", desc: "Prevents MIME sniffing",
    nginx: "add_header X-Content-Type-Options \"nosniff\";", apache: "Header set X-Content-Type-Options \"nosniff\"" },
  { name: "Permissions-Policy", desc: "Controls browser features" },
  { name: "Cross-Origin-Embedder-Policy", desc: "Controls cross-origin embedding" },
  { name: "Cross-Origin-Opener-Policy", desc: "Isolates browsing context" },
  { name: "Cross-Origin-Resource-Policy", desc: "Controls cross-origin resource loading" },
  { name: "Referrer-Policy", desc: "Controls referrer information" },
  { name: "Clear-Site-Data", desc: "Clears browsing data on logout" },
  { name: "Cache-Control", desc: "Controls caching behavior" },
  { name: "X-Permitted-Cross-Domain-Policies", desc: "Restricts Adobe cross-domain policies" },
];

const INFO_LEAKING_HEADERS = [
  "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
  "X-Runtime", "X-Version", "X-Generator", "X-Varnish", "Via",
  "X-Backend-Server", "X-Server-ID",
];
// Plus prefix matches: X-Drupal-*, X-Envoy-*, X-Kubernetes-*, X-LiteSpeed-*, X-Nextjs-*
```

#### Handler

```typescript
async function auditHeaders(target: string, includeRecs: boolean): Promise<HeaderAuditResult>
```

Uses existing `runCommand("curl", ["-sI", "-m", "10", target])`. Parse headers, check presence against both lists, compute score (present/12 * 100).

#### Schema Changes
- Add `"header_audit"` to action enum
- Add `include_recommendations: z.boolean().optional().default(true)`

#### Allowlist: No changes (curl already allowed)

---

### Item 2: Post-Hardening Self-Assessment

**Priority:** HIGH | **Effort:** Medium | **Target:** `vuln_manage` → `self_assess`

#### Handler

```typescript
async function selfAssessWithNuclei(ports: number[], templates: string): Promise<SelfAssessResult>
async function selfAssessBuiltIn(ports: number[]): Promise<SelfAssessResult>
```

**With nuclei:** `nuclei -u http://127.0.0.1:<port> -t misconfigurations/ -json -silent`
**Fallback:** curl-based checks against `SELF_ASSESS_CHECKS` constant (exposed paths, default pages, common misconfigs).

#### Schema Changes
- Add `"self_assess"` to action enum
- Add `ports: z.string().optional()`, `templates: z.enum(["misconfig","defaults","exposures","all"]).optional().default("all")`

#### Allowlist: Add `nuclei` to ALLOWLIST_DEFINITIONS
#### Tool-deps: Add `"nuclei"` to vuln_manage optionalBinaries

---

### Item 3: IaC Security Scanning

**Priority:** MEDIUM | **Effort:** Medium | **Target:** `supply_chain` → `iac_scan`

#### Handler

```typescript
async function iacScanWithTrivy(path: string): Promise<IacScanResult>
async function iacScanBuiltIn(path: string, type: string): Promise<IacScanResult>
function detectIacType(path: string): string
```

**With trivy:** `trivy config --format json <path>`
**Fallback:** regex checks from `IAC_CHECKS` constant:
- Dockerfile: USER root, ADD instead of COPY, no HEALTHCHECK
- docker-compose: privileged:true, host networking, sensitive volume mounts
- Terraform: missing encryption, public access, permissive security groups
- K8s: privileged containers, hostNetwork, no resource limits

#### Schema Changes
- Add `"iac_scan"` to action enum
- Add `iac_type: z.enum(["dockerfile","compose","terraform","kubernetes","auto"]).optional().default("auto")`

#### Tool-deps: Add `"trivy"` to supply_chain optionalBinaries

---

### Item 4: Password Strength Validation

**Priority:** HIGH | **Effort:** Medium | **Target:** `access_control` → `password_strength_test`

#### Handler

```typescript
async function testPasswordStrength(
  users?: string[], wordlist?: string, timeoutSec?: number
): Promise<PasswordStrengthResult>
```

1. Read `/etc/shadow` via `executeCommand({ command: "sudo", args: ["cat", "/etc/shadow"] })`
2. Parse hash prefixes: `$1$`=MD5(weak), `$5$`=SHA-256(ok), `$6$`=SHA-512(good), `$y$`=yescrypt(best)
3. Check: empty passwords, locked accounts, password age, expiry enforcement
4. If john available: crack attempt with timeout, report cracked/not-cracked per user
5. **NEVER return actual hashes or recovered passwords to the LLM**

#### Schema Changes
- Add `"password_strength_test"` to action enum
- Add `users: z.array(z.string()).optional()`, `wordlist: z.string().optional()`, `timeout_seconds: z.number().optional().default(60)`

#### Allowlist: Add `john` to ALLOWLIST_DEFINITIONS
#### Tool-deps: Add `"john"` to access_control optionalBinaries

---

### Item 5: Exploit Availability Enrichment

**Priority:** HIGH | **Effort:** Medium | **Target:** `vuln_manage` → `exploit_check`

#### Handler

```typescript
function validateCveId(id: string): string  // regex: /^CVE-\d{4}-\d{4,}$/
async function checkSearchsploit(cveId: string): Promise<SearchsploitResult>
async function checkEpss(cveId: string): Promise<EpssResult>
async function checkKev(cveId: string): Promise<KevResult>
```

- **searchsploit:** `searchsploit --cve <CVE-ID> --json` (already optional binary)
- **EPSS:** `curl -s https://api.first.org/data/v1/epss?cve=<CVE-ID>` → exploitation probability
- **KEV:** Fetch CISA KEV JSON, cache in `~/.defense-mcp/kev-cache.json` with 24h TTL via `secureWriteFileSync`

Returns: `exploit_available`, `epss_score` (0-1), `kev_listed`, `exploit_refs[]`, `risk_summary`.

#### Schema Changes
- Add `"exploit_check"` to action enum
- Add `cve_id: z.string().optional()`, `check_epss: z.boolean().optional().default(true)`, `check_kev: z.boolean().optional().default(true)`

#### Allowlist/Tool-deps: No changes (searchsploit, curl already allowed)

---

## Phase 3: New Tool Actions — Medium Priority (Items 9-14)

### Item 9: Service Technology Fingerprinting

**Target:** `app_harden` → `fingerprint` | **Effort:** Medium

- Use `ss -tulnp` to identify listening services
- For HTTP services: `curl -sI http://127.0.0.1:<port>` to extract Server/X-Powered-By headers
- For all services: `<binary> --version` to detect version
- Cross-reference against known CVE ranges
- **Params:** `port: z.number().optional()`, `service: z.string().optional()`

### Item 10: SIEM Forwarding Verification

**Target:** `log_management` → `siem_verify` | **Effort:** Medium

- Send test message via `logger -t defense-mcp-test "VERIFY_<uuid>"`
- Check rsyslog status via `systemctl is-active rsyslog` + config validation via `rsyslogd -N1`
- Check filebeat status + config parsing
- Verify TLS certs on forwarding connections via `openssl s_client`
- **Params:** Reuse existing `siem_host`, `protocol` params; add `verify_receipt: z.boolean().optional().default(false)`

### Item 11: Regulatory Compliance Knowledge Base

**Target:** `compliance` → `regulation_query` | **Effort:** Medium

- Embedded TypeScript constant with key regulatory requirements:
  - GDPR (Art.32 security, Art.33 breach notification)
  - HIPAA Security Rule controls
  - PCI-DSS v4.0 requirements
  - SOC2 Trust Service Criteria
  - NIST 800-53 control families
  - CIS Controls v8 safeguards
- Each requirement maps to specific defense-mcp-server tool actions
- Keyword search across requirements
- **Params:** `regulation: z.enum(["gdpr","hipaa","pci_dss","soc2","nist_800_53","cis_controls"]).optional()`, `query: z.string().optional()`, `control_id: z.string().optional()`
- **No command execution** — pure data lookup
- Consider placing KB in separate file `src/core/regulatory-kb.ts` to avoid bloating compliance.ts

### Item 12: Static Code Analysis (SAST)

**Target:** `supply_chain` → `code_scan` | **Effort:** Medium

- If semgrep available: `semgrep scan --config auto --json <path>`
- Fallback: grep-based checks for hardcoded creds, SQL injection, command injection, insecure randomness
- **Params:** `language: z.string().optional()`, `rules: z.enum(["auto","security","owasp"]).optional().default("auto")`
- **Allowlist:** Add `semgrep`
- **Tool-deps:** Add `"semgrep"` to supply_chain optionalBinaries

### Item 13: Active Directory Integration Security

**Target:** `access_control` → `ad_audit` | **Effort:** Medium

- Auto-detect AD integration (SSSD, Winbind, Realmd)
- Audit: keytab permissions, LDAP binding security, SSSD config, NTLM fallback
- Non-joined systems return informational "No AD integration detected"
- **Params:** None (auto-detect)
- **Allowlist:** Add `wbinfo`, `realm`, `klist`
- **Tool-deps:** Add to access_control optionalBinaries

### Item 14: HTTP Request Smuggling Detection

**Target:** `waf_manage` → `smuggling_test` | **Effort:** Medium

- CL.TE, TE.CL, TE.TE tests via crafted curl requests
- **SAFETY:** Target MUST resolve to localhost (strict validation: 127.0.0.1, ::1, localhost only)
- Uses curl with carefully constructed args (not string concatenation — guaranteed by spawnSafe shell:false)
- **Params:** `target: z.string().optional().default("127.0.0.1")`, `port: z.number().optional().default(80)`

---

## Cross-Cutting Changes

### `src/core/command-allowlist.ts` — New Entries

| Binary | Items | Candidates |
|--------|-------|-----------|
| `nuclei` | 2 | `/usr/bin/nuclei`, `/usr/local/bin/nuclei` |
| `john` | 4 | `/usr/bin/john`, `/usr/sbin/john`, `/usr/local/bin/john` |
| `semgrep` | 12 | `/usr/bin/semgrep`, `/usr/local/bin/semgrep` |
| `wbinfo` | 13 | `/usr/bin/wbinfo`, `/usr/sbin/wbinfo` |
| `realm` | 13 | `/usr/bin/realm`, `/usr/sbin/realm` |
| `klist` | 13 | `/usr/bin/klist`, `/usr/local/bin/klist` |

### `src/core/tool-dependencies.ts` — Modified Entries

| Tool | New optionalBinaries |
|------|---------------------|
| `vuln_manage` | `"nuclei"` |
| `supply_chain` | `"trivy"`, `"semgrep"` |
| `access_control` | `"john"`, `"wbinfo"`, `"realm"`, `"klist"` |
| `waf_manage` | `"curl"` |
| `app_harden` | `"curl"` |

### `src/core/config.ts` — New Config Fields

| Field | Env Var | Default | Item |
|-------|---------|---------|------|
| `readOnly` | `DEFENSE_MCP_READ_ONLY` | `false` | 8 |
| `allowedTools` | `DEFENSE_MCP_ALLOWED_TOOLS` | `""` | 8 |
| `redactOutput` | `DEFENSE_MCP_REDACT_OUTPUT` | `true` | 6 |

### New Files

| File | Item | Purpose |
|------|------|---------|
| `src/core/tool-annotations.ts` | 7 | Centralized annotation map for all 31 tools |
| `src/core/output-redactor.ts` | 6 | Credential redaction from command output |
| `src/core/regulatory-kb.ts` | 11 | Regulatory compliance knowledge base constant |
| `tests/core/tool-annotations.test.ts` | 7 | Annotation tests |
| `tests/core/output-redactor.test.ts` | 6 | Redaction tests |

---

## Implementation Sequence

```
WEEK 1: Core Infrastructure (independent foundation)
├── Item 7: Tool Annotations          [1 day]  — no deps
├── Item 6: Output Sanitization       [1 day]  — no deps
├── Item 8: Read-Only Mode            [1 day]  — depends on Item 7
└── Item 15: Self-Audit               [0.5 day] — depends on Items 6,7,8

WEEK 2: High-Priority Actions (highest hardening impact)
├── Item 1: Header Audit              [0.5 day] — no deps
├── Item 5: Exploit Enrichment        [1 day]  — no deps
├── Item 4: Password Strength         [1 day]  — no deps
├── Item 3: IaC Scanning              [1 day]  — no deps
└── Item 2: Self-Assessment           [1.5 day] — benefits from Item 1

WEEK 3: Medium-Priority Actions
├── Item 11: Regulation Query         [1 day]  — pure data, lowest risk
├── Item 9:  Service Fingerprint      [1 day]  — builds on existing detectRunningApps()
├── Item 13: AD Audit                 [1 day]  — read-only, 3 new allowlist entries
├── Item 10: SIEM Verify              [1 day]  — reuses existing SIEM patterns
├── Item 12: Code Scan                [1 day]  — semgrep + grep fallback
└── Item 14: Smuggling Test           [1 day]  — most security-sensitive
```

---

## Risk Matrix

| Item | Risk | Mitigation |
|------|------|-----------|
| 7: Annotations | LOW — SDK already supports 5-arg tool() | Test proxy pass-through |
| 8: Read-Only Mode | LOW — registration-time filtering | Test that filtered tools don't appear |
| 6: Output Redaction | LOW — over-redacting is safe | Log redactions; make toggleable |
| 15: Self-Audit | LOW — read-only checks | Handle missing files gracefully |
| 1: Header Audit | LOW — curl to localhost | Validate target |
| 2: Self-Assess | MEDIUM — nuclei fallback complexity | Keep built-in checks simple |
| 3: IaC Scan | LOW — trivy fallback with regex | Cap directory scan depth |
| 4: Password Strength | MEDIUM — reads /etc/shadow | NEVER return hashes; secure temp files |
| 5: Exploit Check | LOW — external API calls | Cache KEV; timeout on EPSS |
| 9: Fingerprint | LOW — version parsing varies | Return "unknown" gracefully |
| 10: SIEM Verify | LOW — extends existing patterns | Don't wait for end-to-end delivery |
| 11: Regulation KB | LOW — pure data | Keep KB size manageable |
| 12: Code Scan | MEDIUM — path validation critical | Restrict to allowedDirs |
| 13: AD Audit | LOW — read-only, optional | Return info when not AD-joined |
| 14: Smuggling Test | MEDIUM — crafted HTTP requests | Strict localhost-only validation |

---

## Summary

| Phase | Items | New Actions | New Files | Modified Files |
|-------|-------|-------------|-----------|----------------|
| 1: Core | 6,7,8,15 | 1 (self_audit) | 2 | 4 (config, executor, tool-wrapper, meta) |
| 2: High | 1,2,3,4,5 | 5 | 0 | 5 tools + 2 core |
| 3: Medium | 9,10,11,12,13,14 | 6 | 1 (regulatory-kb) | 6 tools + 2 core |
| **Total** | **15** | **12 new actions** | **3** | **~15** |

Final action count after implementation: **253 + 12 = 265 actions** across 31 tools.
