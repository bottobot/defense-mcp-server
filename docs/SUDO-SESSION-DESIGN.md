# Secure Interactive Sudo Session Design

**Version:** 1.0  
**Status:** Implemented
**Author:** Defense MCP Architect  
**Date:** 2026-03-12  
**Replaces:** `mcpuser ALL=(ALL) NOPASSWD: ALL` — CRIT-001

---

## Table of Contents

1. [Context and Problem Statement](#1-context-and-problem-statement)
2. [Architecture Overview](#2-architecture-overview)
3. [Component Specifications](#3-component-specifications)
4. [MCP Tool API](#4-mcp-tool-api)
5. [Sudoers Hardening Plan](#5-sudoers-hardening-plan)
6. [Docker Changes](#6-docker-changes)
7. [Security Analysis and Threat Model](#7-security-analysis-and-threat-model)
8. [Implementation Checklist](#8-implementation-checklist)

---

## 1. Context and Problem Statement

### 1.1 The Critical Finding

The Dockerfile currently configures a blanket passwordless sudo grant:

```dockerfile
# Dockerfile line 50 — CRITICAL SECURITY FINDING
echo "mcpuser ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/mcpuser
```

This means any process running as `mcpuser` — including the MCP server and any tool it wraps — can execute **any command as root without any authentication**. A single command-injection vulnerability in any of the 94 wrapped security tools immediately yields full root compromise of the host (when running `--privileged`) or the container's root namespace.

### 1.2 What Already Exists

Reading the codebase reveals that the **in-process credential management infrastructure is already largely implemented** and well-designed:

| Component | File | Status |
|-----------|------|--------|
| In-memory password buffer with TTL | `src/core/sudo-session.ts` | ✅ Implemented |
| Permission error detection + elevation prompt | `src/core/sudo-guard.ts` | ✅ Implemented |
| Transparent credential injection via `sudo -S` | `src/core/executor.ts` | ✅ Implemented |
| `sudo_elevate` / `sudo_drop` / `sudo_status` MCP tools | `src/tools/sudo-management.ts` | ✅ Implemented |
| Rate limiter infrastructure | `src/core/rate-limiter.ts` | ✅ Exists |
| AES-256-GCM encrypted state store | `src/core/encrypted-state.ts` | ✅ Implemented |

**What is NOT implemented:**

1. The `NOPASSWD: ALL` sudoers line is still present — the credential system is built on top of a NOPASSWD grant, meaning `sudo` never validates the password even when `SudoSession.elevate()` calls `sudo -S -k -v`. The "authentication" is theater.
2. No rate limiting is wired into `sudo_elevate` for failed authentication attempts.
3. No audit trail is emitted to the structured logger for elevation events.
4. The `mcpuser` account has no real password — there is nothing to authenticate against.
5. No Docker entrypoint mechanism exists to set a real password at container startup.

### 1.3 Scope of This Design

This document designs:
- **Sudoers replacement**: Remove `NOPASSWD: ALL`; install a scoped allowlist of specific commands that mcpuser may run with sudo (password required)
- **Docker entrypoint**: Mechanism to set the mcpuser password at container startup from a Docker secret or env var, so `sudo -S -k -v` actually validates credentials
- **Rate limiting**: Wire the existing `RateLimiter` into `sudo_elevate` to cap failed auth attempts
- **Audit trail**: Emit structured log events for all elevation/drop/expiry events
- **MCP tool enhancements**: Minor additions to existing tools

---

## 2. Architecture Overview

### 2.1 Component Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│  MCP Client (Claude / Roo)                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────────────┐  │
│  │ Tool Request │  │ sudo_elevate │  │ Tool Response Read  │  │
│  │ (any tool)   │  │ {password}   │  │  + Elevation Prompt │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬──────────┘  │
└─────────┼─────────────────┼─────────────────────┼─────────────┘
          │ JSON-RPC/stdio  │ JSON-RPC/stdio       │
┌─────────▼─────────────────▼─────────────────────▼─────────────┐
│  Defense MCP Server (mcpuser, non-root)                        │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  tool-wrapper.ts  (pre-flight + post-execution guard)    │  │
│  │  ┌────────────────┐   ┌──────────────────────────────┐  │  │
│  │  │ SudoGuard      │   │ PrivilegeManager             │  │  │
│  │  │ .isPermission  │   │ .checkForTool(manifest)      │  │  │
│  │  │  Error()       │   │ → PrivilegeIssue[]           │  │  │
│  │  │ .createElev-   │   └──────────────────────────────┘  │  │
│  │  │  ationPrompt() │                                      │  │
│  │  └────────────────┘                                      │  │
│  └──────────────────────────────────────────────────────────┘  │
│                           │                                     │
│  ┌────────────────────────▼──────────────────────────────────┐ │
│  │  executor.ts                                              │ │
│  │  prepareSudoOptions()                                     │ │
│  │   Strategy 1: SudoSession.getPassword() → sudo -S stdin  │ │
│  │   Strategy 2: findAskpassHelper()       → sudo -A        │ │
│  │   Strategy 3: No session               → fail + prompt   │ │
│  └────────────────────────┬──────────────────────────────────┘ │
│                           │                                     │
│  ┌────────────────────────▼──────────────────────────────────┐ │
│  │  SudoSession (singleton)                                  │ │
│  │  ┌─────────────────────────────────────────────────────┐ │ │
│  │  │  passwordBuf: Buffer | null  ← zeroable, in-memory  │ │ │
│  │  │  expiresAt: number | null    ← TTL epoch ms         │ │ │
│  │  │  expiryTimer: Timeout        ← auto-drop on expiry  │ │ │
│  │  │  authAttempts: RateLimiter   ← NEW: rate limiting   │ │ │
│  │  └─────────────────────────────────────────────────────┘ │ │
│  │                                                            │ │
│  │  elevate(password)                                         │ │
│  │    → RateLimiter.check()           (NEW)                  │ │
│  │    → runSimple("sudo -S -k -v -p ''")  ← validates creds  │ │
│  │    → storePassword(buf, ttl)                              │ │
│  │    → logger.audit("elevation_granted")  (NEW)             │ │
│  └────────────────────────┬──────────────────────────────────┘ │
│                           │ sudo -S (password via stdin)        │
└───────────────────────────┼─────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│  OS Kernel / sudo binary                                        │
│                                                                 │
│  /etc/sudoers.d/mcpuser  ← SCOPED ALLOWLIST (no NOPASSWD)      │
│                                                                 │
│  Validates: is this mcpuser?                                    │
│             is this command in the allowlist?                   │
│             is the password correct?  ← NOW ACTUALLY CHECKED   │
│                                                                 │
│  Target binaries: iptables, sysctl, systemctl, auditctl, ...   │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Data Flow: First Elevation Request

```
Sequence: First tool call requiring sudo with no active session

1. MCP Client → tool_call("firewall_iptables", {action:"list"})
2. tool-wrapper.ts pre-flight:
   a. PrivilegeManager.checkForTool(manifest{sudo:"always"})
   b. SudoSession.isElevated() → false
   c. testPasswordlessSudo() → false  (NOPASSWD removed)
   d. isAskpassAvailable() → false    (headless Docker)
   e. → issues: [{type:"sudo-required"}]
3. SudoGuard.createElevationPrompt("firewall_iptables")
   → MCP response: {isError:true, _meta:{haltWorkflow:true, elevationTool:"sudo_elevate"}}
4. MCP Client displays elevation prompt to human operator
5. Human operator provides password
6. MCP Client → tool_call("sudo_elevate", {password:"...", timeout_minutes:15})
7. SudoSession.elevate(password):
   a. RateLimiter.check(clientId) → OK              (NEW)
   b. runSimple("sudo -S -k -v -p ''", passwordBuf)
   c. sudo validates: is mcpuser in sudoers? YES
                      is password correct? YES (ACTUALLY CHECKED NOW)
   d. storePassword(passwordBuf, 15min TTL)
   e. set expiryTimer → drop() after 15min
   f. logger.audit("elevation_granted", {user, ttlMs})  (NEW)
   g. → {success: true}
8. sudo_elevate response: "🔓 Elevated as 'mcpuser', expires in 15 min"
9. MCP Client → tool_call("firewall_iptables", {action:"list"})  (retry)
10. executor.ts prepareSudoOptions():
    a. session.getPassword() → Buffer copy of password
    b. prepend ["-S", "-p", ""]
    c. stdin = Buffer.concat([passwordBuf, "\n"])
    d. zero passwordBuf after concat
11. spawn("/usr/sbin/sudo", ["-S", "-p", "", "/usr/sbin/iptables", "-L"])
    stdin → password bytes
    sudo validates against PAM → OK (command in allowlist)
12. iptables output → MCP response
```

### 2.3 Data Flow: Cached Elevation (Subsequent Call)

```
Sequence: Second tool call within TTL window

1. MCP Client → tool_call("harden_sysctl", {action:"set", key:"..."})
2. tool-wrapper.ts pre-flight:
   a. SudoSession.isElevated() → true  (session active)
   b. Preflight passes
3. executor.ts prepareSudoOptions():
   a. session.getPassword() → Buffer copy (TTL not expired)
   b. stdin injection → sudo -S
4. sudo validates password → OK (command in allowlist)
5. sysctl output → MCP response
   [No re-prompting. Transparent to operator.]
```

### 2.4 Data Flow: TTL Expiry

```
Sequence: TTL expires mid-session

1. (After 15 minutes) SudoSession.expiryTimer fires:
   a. passwordBuf.fill(0)  ← zero the buffer
   b. passwordBuf = null
   c. runSimple("sudo -k")  ← invalidate OS sudo cache
   d. logger.audit("session_expired", {user})  (NEW)
2. MCP Client → tool_call("any_sudo_tool", ...)
3. tool-wrapper.ts: SudoSession.isElevated() → false
4. SudoGuard.createElevationPrompt() → re-prompt
```

---

## 3. Component Specifications

### 3.1 SudoSession Enhancements (`src/core/sudo-session.ts`)

**Current state**: Fully functional except for the hollow authentication (NOPASSWD means `sudo -S -k -v` always passes).

**Required changes:**

#### 3.1.1 Rate Limiting on `elevate()`

Import and use the existing `RateLimiter` to cap failed authentication attempts:

```typescript
// Add to SudoSession class
private authRateLimiter: RateLimiter;

// In constructor:
this.authRateLimiter = new RateLimiter({
  maxAttempts: 5,          // 5 failed attempts
  windowMs: 5 * 60 * 1000, // within 5 minutes
  lockoutMs: 15 * 60 * 1000 // 15-minute lockout
});
```

In `elevate()`, before calling `runSimple("sudo -S -k -v")`:

```typescript
// Rate limit by a stable client identifier
const clientId = this.sessionUserId?.toString() ?? "default";
const rateLimitCheck = this.authRateLimiter.check(clientId);
if (!rateLimitCheck.allowed) {
  return {
    success: false,
    error: `Too many failed authentication attempts. ` +
           `Locked out for ${Math.ceil(rateLimitCheck.retryAfterMs! / 1000)} seconds.`
  };
}
```

After a failed authentication, record the attempt:
```typescript
if (result.exitCode !== 0) {
  this.authRateLimiter.record(clientId);
}
```

On success, reset the counter:
```typescript
if (result.exitCode === 0) {
  this.authRateLimiter.reset(clientId);
}
```

#### 3.1.2 Structured Audit Trail

Emit to the existing `logger` (which writes to stderr, captured by the MCP host) for all state transitions:

| Event | Log Level | Fields |
|-------|-----------|--------|
| `elevation_granted` | AUDIT | `{user, uid, ttlMs, expiresAt}` |
| `elevation_failed` | WARN | `{user, reason, attemptCount}` |
| `session_expired` | AUDIT | `{user, ttlMs}` |
| `session_dropped` | AUDIT | `{user, remainingMs}` |
| `session_extended` | AUDIT | `{user, newExpiresAt}` |
| `rate_limit_triggered` | WARN | `{uid, lockoutMs}` |

Example emission:
```typescript
logger.audit("sudo-session", "elevation_granted", "Privileges elevated", {
  user: currentUser,
  uid: this.sessionUserId,
  ttlMs: ms,
  expiresAt: new Date(this.expiresAt!).toISOString(),
  // NOTE: password is NEVER included
});
```

#### 3.1.3 Session Isolation Guard

The existing `sessionUserId` field (`CICD-028`) already records the OS UID. Enhance `getPassword()` to refuse credential reuse if the calling process UID changes mid-session (defense against UID-switching attacks):

```typescript
getPassword(): Buffer | null {
  const currentUid = process.getuid?.() ?? -1;
  if (this.sessionUserId !== null && currentUid !== this.sessionUserId) {
    logger.warn("sudo-session", "getPassword",
      "Session UID mismatch — dropping credentials", {
        sessionUid: this.sessionUserId, currentUid
      });
    this.drop();
    return null;
  }
  // ... existing logic
}
```

### 3.2 SudoGuard (`src/core/sudo-guard.ts`)

No structural changes required. The existing `createElevationPrompt()` and `isPermissionError()` are correct.

**Minor enhancement**: Add a `SUDO_NOPASSWD_DETECTED` check. When `NOPASSWD: ALL` is still present, log a critical warning during server startup:

```typescript
// Add static startup check:
static async checkSudoersConfiguration(): Promise<void> {
  // Run: sudo -n true 2>&1
  // If it succeeds without a password AND there's no session,
  // warn that NOPASSWD is still active (authentication is hollow)
  const result = await runSimple("sudo", ["-n", "true"], undefined, 3000);
  if (result.exitCode === 0 && !SudoSession.getInstance().isElevated()) {
    logger.warn("sudo-guard", "startup",
      "SECURITY WARNING: Passwordless sudo detected. " +
      "Authentication via sudo_elevate is non-functional. " +
      "Remove NOPASSWD from /etc/sudoers.d/mcpuser and set a real password.",
      { severity: "CRITICAL" }
    );
  }
}
```

### 3.3 Executor (`src/core/executor.ts`)

No changes required. The `prepareSudoOptions()` Strategy 1 (stdin piping via `-S`) works correctly once the OS actually validates the password.

**Verification**: Once NOPASSWD is removed, the following behavior should be confirmed:
- `sudo -S -k -v -p ''` fails with wrong password → `elevate()` returns `{success: false}`
- `sudo -S -k -v -p ''` succeeds with correct password → session established
- All subsequent `sudo` commands receive the cached password via stdin

### 3.4 PrivilegeManager (`src/core/privilege-manager.ts`)

The `testPasswordlessSudo()` method (used in pre-flight) calls `sudo -n true`. Once NOPASSWD is removed, this will correctly return `false`, ensuring tools with `sudo: "always"` trigger the elevation flow rather than proceeding silently.

**No code changes required.** Behavior changes automatically when NOPASSWD is removed from sudoers.

### 3.5 Rate Limiter Integration (`src/core/rate-limiter.ts`)

The existing `RateLimiter` needs to be reviewed to confirm it supports:
- Per-identifier sliding window or fixed window counting
- Configurable lockout period (not just window)
- `reset()` method for clearing on successful auth

If `reset()` is not present, add it. The interface needed by SudoSession:

```typescript
interface RateLimitCheck {
  allowed: boolean;
  remaining: number;      // attempts remaining in window
  retryAfterMs?: number;  // if locked out, ms until unlock
}

interface IRateLimiter {
  check(id: string): RateLimitCheck;
  record(id: string): void;   // record a failure
  reset(id: string): void;    // clear on success
}
```

### 3.6 Docker Entrypoint (`docker-entrypoint.sh`)

A new shell script that runs as root at container startup, sets the mcpuser password, then drops privileges:

**Full spec in Section 6.**

---

## 4. MCP Tool API

### 4.1 Existing Tools (No Rename Required)

The existing MCP tool names in `src/tools/sudo-management.ts` already match the design intent. The proposed `sudo_authenticate` maps 1:1 to the existing `sudo_elevate`.

| Proposed Name | Existing Tool | Verdict |
|---------------|--------------|---------|
| `sudo_authenticate` | `sudo_elevate` | Keep `sudo_elevate` — name is clear |
| `sudo_status` | `sudo_status` | ✅ No change |
| `sudo_revoke` | `sudo_drop` | Keep `sudo_drop` — name matches behavior |
| _(new)_ | `sudo_extend` | Already exists |
| _(new)_ | `preflight_batch_check` | Already exists |

### 4.2 `sudo_elevate` — Enhanced Specification

**Tool name:** `sudo_elevate`  
**Current location:** `src/tools/sudo-management.ts:36`

**Current parameters:**
```typescript
{
  password: z.string().min(1),
  timeout_minutes: z.number().min(1).max(480).default(15)
}
```

**Proposed enhancements to the handler:**

1. **Rate limiting check** (delegates to `SudoSession.elevate()` which now rate-limits internally)
2. **Audit log** on grant and failure
3. **Clearer error messages** distinguishing wrong password vs. account not in sudoers vs. rate limited

**Enhanced response for rate limit:**
```
❌ Authentication rate limit exceeded.
Too many failed attempts detected within the last 5 minutes.
Please wait N minutes before trying again.

For security, this lockout cannot be bypassed.
Contact your system administrator if this is unexpected.
```

**Enhanced response for wrong password (after NOPASSWD removal):**
```
❌ Authentication failed: Incorrect password.
Attempts remaining: 3 (before lockout)

Please verify your sudo password is correct.
The password for 'mcpuser' is set at container startup
via MCPUSER_PASSWORD or the Docker secret 'mcpuser-password'.
```

### 4.3 `sudo_status` — Enhanced Specification

Add the following fields to the status output:

```
🔓 Sudo Session Active
════════════════════════════════════════
  User: mcpuser
  Expires: 2026-03-12T05:15:00.000Z
  Remaining: 14m 22s
  Auth method: password (sudo -S)
  Session UID: 1001
  Rate limit: 5/5 attempts remaining

⚠️ Session expiring soon! Use sudo_extend to continue.
```

### 4.4 `sudo_drop` — No Changes Required

Current implementation correctly:
- Zeroes the password buffer
- Clears session metadata
- Calls `sudo -k` to invalidate the OS-level sudo credential cache

### 4.5 `sudo_extend` — No Changes Required

### 4.6 `preflight_batch_check` — No Changes Required

### 4.7 New Tool: `sudo_elevate_gui` in Headless Docker

**Finding**: `sudo_elevate_gui` uses `zenity`/`kdialog`/`ssh-askpass` — none of which are available in the headless Docker container. The GUI flow cannot work in this environment.

**Recommendation**: When `sudo_elevate_gui` is called and no `DISPLAY`/`WAYLAND_DISPLAY` is set, return a clear error:

```
❌ GUI elevation is not available in headless environments.

The Defense MCP Server is running in a Docker container without
a display server. Use sudo_elevate instead:

  Tool: sudo_elevate
  Parameter: password = <your sudo password>

The mcpuser password is set at container startup via:
  - Docker secret: mcpuser-password
  - Environment variable: MCPUSER_PASSWORD (less secure)
```

---

## 5. Sudoers Hardening Plan

### 5.1 Removal of Dangerous Grant

**File to remove/replace:** `/etc/sudoers.d/mcpuser`

**Current content (DANGEROUS — remove):**
```
mcpuser ALL=(ALL) NOPASSWD: ALL
```

**Replace with scoped allowlist (see 5.2).**

### 5.2 Scoped Sudoers Allowlist

The allowlist is derived from auditing every tool module in `src/tools/` and the commands they spawn via `executor.ts`. Only commands that legitimately require root are included.

**File:** `/etc/sudoers.d/mcpuser` (mode `0440`, owned `root:root`)

```sudoers
# Defense MCP Server — scoped sudo allowlist
# Generated by: docs/SUDO-SESSION-DESIGN.md
# Replaces: mcpuser ALL=(ALL) NOPASSWD: ALL
#
# SECURITY: All entries require password authentication.
# The MCP server's SudoSession module caches credentials
# in a zeroable memory buffer for the session TTL.
#
# Format: mcpuser ALL=(root) PASSWD: /absolute/path [args]
# The PASSWD: tag is the default but stated explicitly for clarity.

Defaults:mcpuser !requiretty
Defaults:mcpuser passwd_tries=1
Defaults:mcpuser badpass_message=""

# ── Credential validation ────────────────────────────────────────────────────
# Used by SudoSession.elevate() to validate credentials:
mcpuser ALL=(root) /usr/bin/sudo -S -k -v -p ""
# Note: sudo calling sudo is unusual but required for validation-without-command

# ── Firewall ─────────────────────────────────────────────────────────────────
mcpuser ALL=(root) /usr/sbin/iptables *
mcpuser ALL=(root) /usr/sbin/ip6tables *
mcpuser ALL=(root) /usr/sbin/iptables-save
mcpuser ALL=(root) /usr/sbin/iptables-restore *
mcpuser ALL=(root) /usr/sbin/ip6tables-save
mcpuser ALL=(root) /usr/sbin/ip6tables-restore *
mcpuser ALL=(root) /usr/sbin/nft *
mcpuser ALL=(root) /usr/sbin/ufw *
mcpuser ALL=(root) /usr/bin/ufw *

# ── Kernel parameters ────────────────────────────────────────────────────────
mcpuser ALL=(root) /usr/sbin/sysctl *

# ── Service management ───────────────────────────────────────────────────────
mcpuser ALL=(root) /usr/bin/systemctl *
mcpuser ALL=(root) /bin/systemctl *

# ── Audit subsystem ──────────────────────────────────────────────────────────
mcpuser ALL=(root) /usr/sbin/auditctl *
mcpuser ALL=(root) /usr/sbin/ausearch *
mcpuser ALL=(root) /usr/sbin/aureport *
mcpuser ALL=(root) /usr/sbin/auditd
mcpuser ALL=(root) /usr/sbin/service auditd *
mcpuser ALL=(root) /sbin/auditctl *

# ── Intrusion detection ──────────────────────────────────────────────────────
mcpuser ALL=(root) /usr/bin/rkhunter *
mcpuser ALL=(root) /usr/sbin/chkrootkit *
mcpuser ALL=(root) /usr/bin/chkrootkit *

# ── File integrity (AIDE) ─────────────────────────────────────────────────────
mcpuser ALL=(root) /usr/bin/aide *
mcpuser ALL=(root) /usr/sbin/aide *

# ── Malware scanning ─────────────────────────────────────────────────────────
mcpuser ALL=(root) /usr/bin/clamscan *
mcpuser ALL=(root) /usr/bin/freshclam
mcpuser ALL=(root) /usr/sbin/clamd *

# ── Security assessment ──────────────────────────────────────────────────────
mcpuser ALL=(root) /usr/bin/lynis *

# ── Network tools ────────────────────────────────────────────────────────────
mcpuser ALL=(root) /usr/bin/nmap *
mcpuser ALL=(root) /usr/bin/tcpdump *

# ── File permission management ────────────────────────────────────────────────
mcpuser ALL=(root) /usr/bin/chmod *
mcpuser ALL=(root) /bin/chmod *
mcpuser ALL=(root) /usr/bin/chown *
mcpuser ALL=(root) /bin/chown *

# ── User account management ───────────────────────────────────────────────────
mcpuser ALL=(root) /usr/sbin/useradd *
mcpuser ALL=(root) /usr/sbin/usermod *
mcpuser ALL=(root) /usr/sbin/userdel *
mcpuser ALL=(root) /usr/bin/passwd *
mcpuser ALL=(root) /usr/sbin/chpasswd

# ── Package management (for auto-installer) ───────────────────────────────────
mcpuser ALL=(root) /usr/bin/apt-get *
mcpuser ALL=(root) /usr/bin/apt *
mcpuser ALL=(root) /usr/bin/dpkg *
mcpuser ALL=(root) /usr/bin/dpkg-reconfigure *

# ── Package integrity ─────────────────────────────────────────────────────────
mcpuser ALL=(root) /usr/bin/debsums *

# ── Fail2ban ──────────────────────────────────────────────────────────────────
mcpuser ALL=(root) /usr/bin/fail2ban-client *

# ── Kernel module management ──────────────────────────────────────────────────
mcpuser ALL=(root) /usr/sbin/modprobe *
mcpuser ALL=(root) /sbin/modprobe *
mcpuser ALL=(root) /usr/sbin/rmmod *
mcpuser ALL=(root) /sbin/rmmod *
mcpuser ALL=(root) /usr/sbin/modinfo *

# ── Capabilities ──────────────────────────────────────────────────────────────
mcpuser ALL=(root) /usr/sbin/setcap *

# ── AppArmor / SELinux ────────────────────────────────────────────────────────
mcpuser ALL=(root) /usr/sbin/aa-enforce *
mcpuser ALL=(root) /usr/sbin/aa-complain *
mcpuser ALL=(root) /usr/sbin/aa-disable *
mcpuser ALL=(root) /usr/sbin/apparmor_parser *
mcpuser ALL=(root) /usr/sbin/setenforce *
mcpuser ALL=(root) /usr/sbin/getsebool *
mcpuser ALL=(root) /usr/sbin/setsebool *

# ── Disk / cryptography ───────────────────────────────────────────────────────
mcpuser ALL=(root) /usr/sbin/cryptsetup *
mcpuser ALL=(root) /sbin/cryptsetup *

# ── WireGuard / VPN ───────────────────────────────────────────────────────────
mcpuser ALL=(root) /usr/bin/wg *
mcpuser ALL=(root) /usr/bin/wg-quick *
mcpuser ALL=(root) /usr/sbin/ip *
mcpuser ALL=(root) /sbin/ip *

# ── USB device control ────────────────────────────────────────────────────────
mcpuser ALL=(root) /usr/sbin/udev *
mcpuser ALL=(root) /sbin/udevadm *
mcpuser ALL=(root) /usr/sbin/usbguard *

# ── System identification ─────────────────────────────────────────────────────
# Required by SudoSession.elevate() to identify the current user after elevation
mcpuser ALL=(root) /usr/bin/whoami

# ── GRUB / bootloader ────────────────────────────────────────────────────────
mcpuser ALL=(root) /usr/sbin/update-grub
mcpuser ALL=(root) /usr/sbin/grub-mkconfig *
mcpuser ALL=(root) /usr/bin/grub-mkconfig *

# ── Docker socket access (for container tools) ────────────────────────────────
mcpuser ALL=(root) /usr/bin/docker *

# ── Forensics and incident response ──────────────────────────────────────────
mcpuser ALL=(root) /usr/bin/find *
mcpuser ALL=(root) /bin/dd *
mcpuser ALL=(root) /usr/sbin/losetup *
mcpuser ALL=(root) /sbin/losetup *

# ── Process management ────────────────────────────────────────────────────────
mcpuser ALL=(root) /bin/kill *
mcpuser ALL=(root) /usr/bin/kill *

# ── Log rotation / management ─────────────────────────────────────────────────
mcpuser ALL=(root) /usr/sbin/logrotate *

# ── Unattended upgrades ───────────────────────────────────────────────────────
mcpuser ALL=(root) /usr/bin/unattended-upgrades *
mcpuser ALL=(root) /usr/bin/unattended-upgrade *

# ── TLS / certificate management ─────────────────────────────────────────────
mcpuser ALL=(root) /usr/bin/certbot *
mcpuser ALL=(root) /usr/bin/openssl *
```

### 5.3 Sudo Configuration Hardening Options

In addition to the allowlist, apply these sudo `Defaults` settings at the top of the file:

```sudoers
# Global sudo hardening (in /etc/sudoers.d/99-defense-hardening)
Defaults        log_output
Defaults        logfile=/var/log/sudo.log
Defaults        log_year
Defaults        passwd_timeout=30
Defaults        timestamp_timeout=0   # disable OS-level credential caching
                                      # (SudoSession handles its own TTL)
Defaults        !authenticate         # REMOVED — this is the dangerous line
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
```

> **Critical note on `timestamp_timeout=0`**: Setting this to 0 means sudo **always** requires a password, even after a recent successful authentication. This is intentional — we want sudo to always receive the password via stdin from `SudoSession`, not rely on the OS sudo timestamp cache (which could be stolen or manipulated).

### 5.4 Validation: sudoers Syntax Check

Before deploying, always validate with `visudo -c -f /etc/sudoers.d/mcpuser`. A Dockerfile `RUN` instruction should do this:

```dockerfile
RUN visudo -c -f /etc/sudoers.d/mcpuser && \
    echo "sudoers validation passed"
```

### 5.5 Commands Explicitly NOT Granted

The following commands are commonly misused and must **not** appear in the allowlist:

| Command | Reason Excluded |
|---------|----------------|
| `bash`, `sh`, `zsh` | Shell escape → arbitrary code execution |
| `su` | Bypasses sudo logging and allowlist |
| `env` | Environment manipulation → bypass restrictions |
| `less`, `more`, `vi`, `nano` | Shell escape via `!command` |
| `tee` | Write to arbitrary files as root |
| `cat` | Read arbitrary sensitive files as root |
| `cp`, `mv` | Overwrite system files as root |
| `rm` | Delete system files / wipe evidence |
| `python3`, `node`, `perl` | Arbitrary code execution as root |
| `curl`, `wget` | Exfiltration + arbitrary code download/exec |
| `nc`, `netcat`, `ncat` | Network backdoor potential |
| `strace`, `ltrace` | Credential extraction from other processes |
| `gdb` | Arbitrary memory read/write |
| `mount`, `umount` | Filesystem manipulation |
| `chroot` | Container escape vector |

---

## 6. Docker Changes

### 6.1 Problem: mcpuser Has No Password

In the current Dockerfile, `useradd` creates `mcpuser` without a password:
```dockerfile
useradd --uid 1001 --gid mcpuser --shell /bin/bash --create-home mcpuser
```

The account has a locked password (`!` in `/etc/shadow`). `sudo -S -k -v` with any password will fail (exit 1) because the PAM stack rejects locked accounts by default.

Once NOPASSWD is removed, we need `mcpuser` to have a real password that `sudo` can validate via PAM.

### 6.2 Solution: Runtime Password Injection via Entrypoint

The password must **not** be baked into the Docker image (it would be visible in `docker inspect`, image layers, and any registry push). Instead, inject it at container startup via:

**Option A (Recommended): Docker Secret**
```bash
docker run --secret mcpuser-password defense-mcp-server
```
The secret is mounted at `/run/secrets/mcpuser-password` (mode `0400`, owner `root`).

**Option B (Acceptable): Environment Variable**
```bash
docker run -e MCPUSER_PASSWORD='...' defense-mcp-server
```
Less secure (visible in `docker inspect`, `/proc/<pid>/environ`) but acceptable for development/CI.

### 6.3 New: `docker-entrypoint.sh`

Create `docker-entrypoint.sh` in the repository root:

```bash
#!/bin/bash
# docker-entrypoint.sh
# Runs as root at container startup.
# Sets mcpuser password from Docker secret or env var, then drops to mcpuser.
#
# Security properties:
# - Password is read from /run/secrets/mcpuser-password (preferred) or MCPUSER_PASSWORD env
# - Password is passed to chpasswd via stdin (not command-line arguments)
# - MCPUSER_PASSWORD env var is unset after use to prevent exposure in /proc
# - If no password source is available, falls back to a random password and warns
#   (tools requiring sudo will fail until sudo_elevate is called with the correct credentials)

set -euo pipefail

# ── 1. Determine password source ─────────────────────────────────────────────
MCPUSER_PW=""

if [ -f /run/secrets/mcpuser-password ]; then
    # Docker secret — preferred, most secure
    MCPUSER_PW=$(cat /run/secrets/mcpuser-password)
    echo "[entrypoint] Using Docker secret for mcpuser password" >&2

elif [ -n "${MCPUSER_PASSWORD:-}" ]; then
    # Environment variable — acceptable for dev/CI
    MCPUSER_PW="$MCPUSER_PASSWORD"
    echo "[entrypoint] Using MCPUSER_PASSWORD environment variable" >&2
    echo "[entrypoint] WARNING: env-var password is visible in 'docker inspect'" >&2
    echo "[entrypoint] WARNING: Use Docker secrets in production" >&2

else
    # No password source — generate random password (sudo will always fail)
    # The server still starts; tools without sudo work fine
    MCPUSER_PW=$(tr -dc 'A-Za-z0-9!@#$%^&*' < /dev/urandom | head -c 32)
    echo "[entrypoint] WARNING: No password source found (no secret, no MCPUSER_PASSWORD)" >&2
    echo "[entrypoint] WARNING: mcpuser has a random password. sudo_elevate will always fail." >&2
    echo "[entrypoint] WARNING: Pass password via: docker run --secret mcpuser-password" >&2
fi

# ── 2. Set the mcpuser password ───────────────────────────────────────────────
if [ -n "$MCPUSER_PW" ]; then
    echo "mcpuser:${MCPUSER_PW}" | chpasswd
    echo "[entrypoint] mcpuser password set successfully" >&2
fi

# ── 3. Zero the password from this process's memory (best-effort) ─────────────
unset MCPUSER_PASSWORD
unset MCPUSER_PW

# ── 4. Drop to mcpuser and exec the MCP server ───────────────────────────────
# Use exec to replace this root shell with the Node.js process
# su-exec is preferred (single binary, no shell escape surface)
# Fall back to gosu if su-exec is not available
if command -v su-exec >/dev/null 2>&1; then
    exec su-exec mcpuser node /app/build/index.js "$@"
elif command -v gosu >/dev/null 2>&1; then
    exec gosu mcpuser node /app/build/index.js "$@"
else
    # Fallback: setpriv (part of util-linux, available in Debian)
    exec setpriv --reuid=1001 --regid=1001 --init-groups node /app/build/index.js "$@"
fi
```

### 6.4 Dockerfile Changes

```dockerfile
# Defense MCP Server — Docker Image
FROM node:22-slim

LABEL org.opencontainers.image.title="defense-mcp-server"
LABEL org.opencontainers.image.description="Defensive security MCP server — 94 tools for system hardening"
LABEL org.opencontainers.image.version="0.7.0"
LABEL org.opencontainers.image.licenses="MIT"

# Install Linux security tools + su-exec for safe privilege drop
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core utilities
    sudo \
    procps \
    iproute2 \
    net-tools \
    iputils-ping \
    # Privilege drop helper
    # NOTE: su-exec is preferred. If unavailable, gosu is a fallback.
    # Install via: curl + verify signature, or build from source
    # For now, use setpriv (already in util-linux which is standard):
    util-linux \
    # Firewall
    iptables \
    nftables \
    ufw \
    # Intrusion detection
    rkhunter \
    chkrootkit \
    aide \
    # Malware scanning
    clamav \
    clamav-daemon \
    # Audit
    auditd \
    audispd-plugins \
    lynis \
    # System hardening
    fail2ban \
    # SSH
    openssh-client \
    # Network tools
    nmap \
    tcpdump \
    # File tools
    debsums \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for the server process
# NOTE: No NOPASSWD sudo — real password set at runtime via entrypoint
RUN groupadd --gid 1001 mcpuser && \
    useradd --uid 1001 --gid mcpuser --shell /bin/bash --create-home mcpuser

# Install scoped sudoers allowlist (password required for all commands)
COPY etc/sudoers.d/mcpuser /etc/sudoers.d/mcpuser
RUN chmod 0440 /etc/sudoers.d/mcpuser && \
    chown root:root /etc/sudoers.d/mcpuser && \
    visudo -c -f /etc/sudoers.d/mcpuser

# Disable OS-level sudo credential caching
# (SudoSession manages its own in-memory TTL)
RUN echo 'Defaults timestamp_timeout=0' > /etc/sudoers.d/99-timestamp-zero && \
    echo 'Defaults log_output'         >> /etc/sudoers.d/99-timestamp-zero && \
    chmod 0440 /etc/sudoers.d/99-timestamp-zero

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts

COPY build/ ./build/
COPY README.md CHANGELOG.md LICENSE ./
COPY docs/TOOLS-REFERENCE.md docs/SAFEGUARDS.md ./docs/

RUN chown -R mcpuser:mcpuser /app

# Copy and configure entrypoint (runs as root to set password, then drops)
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh && \
    chown root:root /usr/local/bin/docker-entrypoint.sh

# NOTE: Do NOT set USER mcpuser here — entrypoint runs as root to set password
# The entrypoint uses su-exec/setpriv to drop to mcpuser

ENV NODE_ENV=production
ENV DEFENSE_MCP_DRY_RUN=false
ENV DEFENSE_MCP_AUTO_INSTALL=false
ENV DEFENSE_MCP_PREFLIGHT=true

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD node -e "require('./build/index.js')" 2>/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
```

### 6.5 Running the Container

**With Docker Secrets (Recommended for Production):**
```bash
# Create the secret
echo "MySecurePassword123!" | docker secret create mcpuser-password -

# Docker Swarm deployment
docker service create \
  --name defense-mcp \
  --secret mcpuser-password \
  defense-mcp-server

# docker-compose with secrets
# docker-compose.yml:
services:
  defense-mcp:
    image: defense-mcp-server
    secrets:
      - mcpuser-password
secrets:
  mcpuser-password:
    external: true
```

**With Environment Variable (Development/CI):**
```bash
docker run \
  -e MCPUSER_PASSWORD='MySecurePassword123!' \
  defense-mcp-server
```

**MCP client config (Claude Desktop / Roo) — no password in config:**
```json
{
  "mcpServers": {
    "defense-mcp": {
      "command": "docker",
      "args": ["run", "--rm", "-i",
               "--secret", "mcpuser-password",
               "defense-mcp-server"]
    }
  }
}
```

### 6.6 Directory Structure for New Files

```
defense-mcp-server/
├── docker-entrypoint.sh          ← NEW: runtime password injection
├── etc/
│   └── sudoers.d/
│       └── mcpuser               ← NEW: scoped allowlist (replaces NOPASSWD)
├── Dockerfile                    ← MODIFIED: entrypoint, no NOPASSWD, USER dropped
```

---

## 7. Security Analysis and Threat Model

### 7.1 Attack Surface Comparison

#### Current State (NOPASSWD: ALL)

```
Attack Surface Matrix — BEFORE

Threat Vector                          | Exploitability | Impact
--------------------------------------|----------------|--------
Command injection in any wrapped tool  | HIGH           | CRITICAL (root)
Path traversal in file-handling tools  | MEDIUM         | CRITICAL (root)
Argument injection in network tools    | MEDIUM         | HIGH (root)
Rogue MCP client connecting to server  | LOW            | CRITICAL (root)
Compromised MCP host process           | HIGH           | CRITICAL (root)
Password sniffing / credential theft   | N/A            | N/A (no password)
Lateral movement from tool output      | MEDIUM         | CRITICAL (root)
Container escape (if --privileged)     | MEDIUM         | HOST COMPROMISE
```

**Effective privilege level of any exploit**: `root` (immediate, no additional steps)

#### Target State (Scoped Allowlist + Password Auth)

```
Attack Surface Matrix — AFTER

Threat Vector                          | Exploitability | Impact         | Notes
--------------------------------------|----------------|-----------------|--------
Command injection in any wrapped tool  | MEDIUM         | HIGH (not root) | Sudo required + allowlisted
Path traversal in file-handling tools  | MEDIUM         | MEDIUM          | mcpuser access only
Argument injection in network tools    | MEDIUM         | MEDIUM          | Command in allowlist, args validated
Rogue MCP client connecting to server  | LOW            | MEDIUM          | Must also know sudo password
Compromised MCP host process           | HIGH           | MEDIUM          | Host sees password in env (if env method)
Password in environment variable       | MEDIUM         | HIGH            | Use Docker secrets to mitigate
Credential brute force via sudo_elevate| LOW            | LOW             | 5-attempt rate limit
Sudo session hijacking                 | LOW            | HIGH            | sessionUserId guard
Buffer not zeroed on crash             | LOW            | MEDIUM          | Signal handlers + process.once
Docker secret exposure                 | LOW            | HIGH            | secret limited to container lifetime
```

**Effective privilege level of arbitrary code execution as mcpuser**: Limited to allowlisted sudo commands only. Attacker cannot run `bash`, `python`, `curl`, etc. as root.

### 7.2 Residual Risks and Mitigations

#### Risk 1: Wide Argument Wildcards in Sudoers

The allowlist uses `*` wildcards for arguments (e.g., `iptables *`). This means an attacker with code execution as mcpuser could run `sudo iptables -F` (flush all firewall rules) — destructive but not a privilege escalation beyond what iptables already allows.

**Mitigation**: Accept this risk for operational flexibility. The defense-in-depth model assumes mcpuser is trusted for defensive operations. Privilege escalation beyond what the allowlist commands can do is blocked.

#### Risk 2: `sudo -S -k -v -p ""` in Allowlist

This sudo-calls-sudo pattern is required for `SudoSession.elevate()`. The risk: an attacker could use it to validate arbitrary passwords against the OS PAM stack (oracle attack).

**Mitigation**: Rate limiting in `SudoSession` caps attempts to 5 per 5-minute window. The lockout (15 minutes) prevents sustained brute force.

#### Risk 3: Password in Environment Variable

Using `-e MCPUSER_PASSWORD=...` exposes the password in `docker inspect` output and `/proc/1/environ` inside the container.

**Mitigation**: 
- Strongly recommend Docker secrets for production
- Entrypoint unsets `MCPUSER_PASSWORD` after use
- Document the risk prominently

#### Risk 4: Password Cached in Node.js Buffer

Even though the buffer is zeroed on TTL expiry and drop, Node.js `Buffer` allocations may be present in multiple V8 heap snapshots or core dumps.

**Mitigation**:
- Core dumps are disabled in the container (`ulimit -c 0` in entrypoint)
- The buffer is zeroed via `.fill(0)` on expiry, drop, and in all failure paths
- This is the best achievable in Node.js without OS-level memory pinning

#### Risk 5: SUDO_ASKPASS Injection

If `SUDO_ASKPASS` environment variable is set to a malicious binary, `executor.ts` would use it. The existing `SudoGuard.validateAskpassPath()` mitigates this with ownership + permission checks.

**Mitigation**: Already implemented. No additional action required.

#### Risk 6: Entrypoint Script Injection

The `docker-entrypoint.sh` reads the password and passes it to `chpasswd` via stdin. If the secret file or env var contains shell metacharacters, the `echo "mcpuser:${MCPUSER_PW}" | chpasswd` pattern in the entrypoint could be unsafe.

**Mitigation**: Use `printf '%s\n' "mcpuser:${MCPUSER_PW}"` instead of `echo`. Alternatively, write to a temp file and pipe — but the current heredoc approach with `chpasswd` is safe since the password goes via stdin, not a shell command string.

### 7.3 Trust Model

```
Trust Boundaries

Level 0 (Most Trusted):
  - Docker host system
  - Docker daemon
  - Operator running the docker run command

Level 1 (Trusted):
  - MCP client (Claude Desktop / Roo)
  - The human operator interacting with the MCP client

Level 2 (Conditionally Trusted — after sudo_elevate):
  - The Node.js MCP server process (mcpuser)
  - The SudoSession credential cache
  - Allowlisted sudo commands

Level 3 (Untrusted — defense against this level is the goal):
  - Attacker with arbitrary code execution as mcpuser
  - Compromised tool output (command injection attempts)
  - Rogue data in scanned files / network packets

Security invariant: An attacker at Level 3 cannot escalate to Level 0/1
  using the scoped sudoers allowlist, even with the cached password,
  because the allowlist explicitly excludes shell escapes and interpreters.
```

### 7.4 Compliance Mapping

| Requirement | CIS Benchmark | Current | Target |
|-------------|--------------|---------|--------|
| No passwordless sudo | CIS 5.3.7 | ❌ FAIL | ✅ PASS |
| sudo logging enabled | CIS 5.3.4 | ❌ FAIL | ✅ PASS |
| sudo requires re-auth | CIS 5.3.5 | ❌ FAIL | ✅ PASS |
| Specific commands only | CIS 5.3.6 | ❌ FAIL | ✅ PASS |
| No NOPASSWD | CIS 5.3.7 | ❌ FAIL | ✅ PASS |

---

## 8. Implementation Checklist

The following items are ordered by dependency — each item can only be implemented after all items above it are complete.

### Phase 1: Sudoers and Docker (Required First — Establishes Real Auth)

- [ ] **Create `etc/sudoers.d/mcpuser`** — scoped allowlist from Section 5.2
  - File: `etc/sudoers.d/mcpuser` (checked into repo, copied to image)
  - Must pass `visudo -c -f` check in Dockerfile

- [ ] **Create `docker-entrypoint.sh`** — runtime password injection
  - File: `docker-entrypoint.sh`
  - Reads from `/run/secrets/mcpuser-password` or `MCPUSER_PASSWORD`
  - Sets password via `chpasswd`, unsets env var, drops to mcpuser via `setpriv`/`su-exec`
  - Must handle: secret present, env var present, neither present (random password + warn)

- [ ] **Modify `Dockerfile`**
  - Remove: `echo "mcpuser ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/mcpuser`
  - Add: `COPY etc/sudoers.d/mcpuser /etc/sudoers.d/mcpuser`
  - Add: `RUN chmod 0440 ... && visudo -c -f ...`
  - Add: `RUN echo 'Defaults timestamp_timeout=0' > /etc/sudoers.d/99-timestamp-zero`
  - Add: `COPY docker-entrypoint.sh /usr/local/bin/`
  - Remove: `USER mcpuser` (entrypoint handles privilege drop)
  - Change: `ENTRYPOINT` to `["/usr/local/bin/docker-entrypoint.sh"]`
  - Add: `util-linux` to apt-get install (for `setpriv`)

### Phase 2: Rate Limiting (Prevents Brute Force)

- [ ] **Review `src/core/rate-limiter.ts`**
  - Confirm it supports: `check(id)`, `record(id)`, `reset(id)` interface
  - If `reset()` is missing, add it

- [ ] **Modify `src/core/sudo-session.ts`** — wire in rate limiter
  - Import `RateLimiter` from `./rate-limiter.js`
  - Add `authRateLimiter` field to `SudoSession`
  - In `elevate()`: check rate limit before calling `runSimple("sudo -S -k -v")`
  - In `elevate()`: record failure on wrong password; reset on success
  - Return structured error for rate-limit exceeded with `retryAfterMs`

### Phase 3: Audit Trail (Observability and Forensics)

- [ ] **Modify `src/core/sudo-session.ts`** — add audit log emissions
  - Import `logger` from `./logger.js`
  - Add `logger.audit(...)` calls for: `elevation_granted`, `elevation_failed`, `session_expired`, `session_dropped`, `session_extended`, `rate_limit_triggered`
  - Fields: user, uid, ttlMs, expiresAt — **never the password**

- [ ] **Modify `src/core/sudo-guard.ts`** — add startup NOPASSWD detection
  - Add `SudoGuard.checkSudoersConfiguration()` static method
  - Call from `src/index.ts` during server initialization
  - Log CRITICAL warning if NOPASSWD is still detected

### Phase 4: Tool Enhancements (UX and Headless Docker)

- [ ] **Modify `src/tools/sudo-management.ts`** — `sudo_elevate` handler
  - Improve error message for rate-limited response
  - Improve error message for wrong password (after NOPASSWD removal, fails are real)
  - Add auth method to `sudo_status` output

- [ ] **Modify `src/tools/sudo-management.ts`** — `sudo_elevate_gui` handler
  - Detect headless environment (`!process.env.DISPLAY && !process.env.WAYLAND_DISPLAY`)
  - Return clear error directing user to `sudo_elevate` instead

- [ ] **Modify `src/core/sudo-session.ts`** — UID guard in `getPassword()`
  - Add `sessionUserId` vs `process.getuid()` check before returning password copy
  - Drop session and log warning if UID mismatch detected

### Phase 5: Test Updates

- [ ] **Update `tests/core/sudo-session.test.ts`**
  - Add tests for rate limiting behavior (5 failures → lockout)
  - Add tests for UID mismatch guard in `getPassword()`
  - Add tests for audit log emissions (mock logger)
  - Remove/update tests that assume NOPASSWD (they mocked sudo anyway)

- [ ] **Update `tests/tools/sudo-management.test.ts`**
  - Add test for rate-limited `sudo_elevate` response format
  - Add test for `sudo_elevate_gui` headless detection

- [ ] **Create `tests/integration/sudo-auth.test.ts`** (optional, CI only)
  - Integration test that runs the actual Docker container
  - Verifies NOPASSWD is gone: `sudo -n true` must fail
  - Verifies `sudo_elevate` with wrong password fails
  - Verifies `sudo_elevate` with correct password (from Docker secret) succeeds

### Phase 6: Documentation Updates

- [ ] **Update `README.md`** — document password setup
  - Add "Authentication Setup" section
  - Document Docker secret approach
  - Document env var approach (with security caveat)
  - Explain why `sudo_elevate` is needed (NOPASSWD removed)

- [ ] **Update `docs/SAFEGUARDS.md`** — update NOPASSWD finding to RESOLVED

- [ ] **Update `docs/ARCHITECTURE.md`** — add credential flow diagram

---

## Appendix A: Verification Checklist After Deployment

Run these checks inside the container to verify the hardening is complete:

```bash
# 1. Verify NOPASSWD is gone
sudo -n true 2>&1
# Expected: "sudo: a password is required" (exit 1)

# 2. Verify password auth works
echo "mcpuser:correctpassword" | sudo -S true 2>/dev/null
# Expected: exit 0 with correct password

# 3. Verify blocked command (shell)
echo "mcpuser:correctpassword" | sudo -S bash -c "id" 2>&1
# Expected: "Sorry, user mcpuser is not allowed to execute '/bin/bash'"

# 4. Verify blocked command (python)
echo "mcpuser:correctpassword" | sudo -S python3 -c "import os; os.system('id')" 2>&1
# Expected: sudo error about not being in sudoers for this command

# 5. Verify allowed command (iptables)
echo "mcpuser:correctpassword" | sudo -S iptables -L 2>&1
# Expected: iptables chain listing (no sudo error)

# 6. Verify timestamp_timeout=0 (sudo always prompts)
echo "mcpuser:correctpassword" | sudo -S true
sudo -n true 2>&1
# Expected: "a password is required" (no cached ticket)

# 7. Verify rate limiting (requires MCP tool call)
# Call sudo_elevate 6 times with wrong password
# 6th call should return rate-limit error
```

---

## Appendix B: Threat Model Summary Table

| Threat | Attack Path | Before | After | Residual Risk |
|--------|------------|--------|-------|---------------|
| Command injection → root shell | Inject `; bash` into tool arg | CRITICAL | LOW | Bash not in allowlist |
| Code exec as mcpuser → root | Run any command as root | CRITICAL | LOW | Allowlist restricts commands |
| Password brute force | Call sudo_elevate repeatedly | N/A (no password) | LOW | 5-attempt rate limit |
| Credential theft from memory | Process dump / ptrace | MEDIUM | LOW | Buffer zeroed, UID guard |
| Container escape via root | Run privileged ops | CRITICAL | MEDIUM | --privileged still risky |
| Hollow authentication bypass | NOPASSWD still present | CRITICAL | NONE | NOPASSWD removed |
| Docker secret compromise | Access /run/secrets | LOW | MEDIUM | Secret scoped to container |
| Env var credential exposure | docker inspect | N/A | MEDIUM | Use secrets not env vars |
| Session fixation | Reuse old session | LOW | LOW | UID guard + TTL |

**Net security improvement**: 7 out of 8 threat vectors significantly reduced or eliminated.
