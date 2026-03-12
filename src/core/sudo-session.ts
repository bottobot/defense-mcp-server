/**
 * SudoSession — singleton that manages elevated privilege credentials.
 *
 * The MCP server runs non-interactively via stdio transport, so `sudo`
 * cannot prompt for a password through a TTY. This module stores the
 * user's password in a zeroable Buffer and transparently provides it
 * to `sudo -S` via stdin piping in the executor.
 *
 * Security features:
 *   - Password stored in a Buffer and remains as Buffer through the entire
 *     stdin pipeline (never converted to a V8 string, can be zeroed)
 *   - Auto-expires after a configurable timeout (default 15 minutes)
 *   - Explicit `drop()` zeroes the buffer immediately
 *   - Process exit handler zeroes the buffer on shutdown
 *   - Validates credentials before storing (test with `sudo -S -k -v`)
 *   - Never logs or exposes the password in any output
 *   - Rate limits failed authentication attempts (5 per 5 minutes)
 *   - Session UID guard: drops session if OS UID changes mid-session
 *   - Emits structured audit events for all state transitions
 *
 * Child process spawning goes through spawn-safe.ts which enforces the
 * command allowlist and shell: false without creating circular dependencies.
 */

import { spawnSafe } from "./spawn-safe.js";
import { RateLimiter } from "./rate-limiter.js";
import { logger } from "./logger.js";

// ── Types ────────────────────────────────────────────────────────────────────

export interface SudoSessionStatus {
  elevated: boolean;
  username: string | null;
  expiresAt: string | null;
  remainingSeconds: number | null;
  /** Rate-limit info (safe to surface to MCP callers). */
  rateLimit: {
    limited: boolean;
    attemptsRemaining: number;
    resetAt?: string; // ISO 8601 — only present when limited
  };
}

/** Structured result from {@link SudoSession.elevate}. */
export interface ElevateResult {
  success: boolean;
  error?: string;
  /** Present when the elevation was blocked by rate limiting. */
  rateLimited?: boolean;
  /** Present when rate-limited: ms until the lockout window resets. */
  retryAfterMs?: number;
}

// ── Constants ────────────────────────────────────────────────────────────────

/** Rate limiter key used for all sudo elevation attempts. */
const AUTH_RL_KEY = "sudo_elevate";

/**
 * Number of failed attempts allowed within the rate-limit window before
 * the account is temporarily locked out.
 */
const AUTH_RL_MAX_ATTEMPTS = 5;

/**
 * Sliding-window size in milliseconds for the auth rate limiter (5 minutes).
 * After this window passes with no new failures, the counter resets.
 */
const AUTH_RL_WINDOW_MS = 5 * 60 * 1000; // 5 minutes

// ── Internal helper: run a command via spawn-safe ────────────────────────────

interface SimpleResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

function runSimple(
  command: string,
  args: string[],
  stdin?: string | Buffer,
  timeoutMs = 10000
): Promise<SimpleResult> {
  return new Promise((resolve) => {
    const controller = new AbortController();

    let child;
    try {
      child = spawnSafe(command, args, {
        signal: controller.signal,
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch {
      resolve({ stdout: "", stderr: `spawn failed for: ${command}`, exitCode: 1 });
      return;
    }

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];

    const timer = setTimeout(() => controller.abort(), timeoutMs);

    child.stdout?.on("data", (c: Buffer) => stdoutChunks.push(c));
    child.stderr?.on("data", (c: Buffer) => stderrChunks.push(c));

    if (stdin && child.stdin) {
      // Write as Buffer to avoid creating immutable V8 strings from passwords
      child.stdin.write(Buffer.isBuffer(stdin) ? stdin : Buffer.from(stdin, "utf-8"));
      child.stdin.end();
    }

    child.on("close", (code: number | null) => {
      clearTimeout(timer);
      resolve({
        stdout: Buffer.concat(stdoutChunks).toString("utf-8"),
        stderr: Buffer.concat(stderrChunks).toString("utf-8"),
        exitCode: code ?? 1,
      });
    });

    child.on("error", () => {
      clearTimeout(timer);
      resolve({
        stdout: Buffer.concat(stdoutChunks).toString("utf-8"),
        stderr: Buffer.concat(stderrChunks).toString("utf-8"),
        exitCode: 1,
      });
    });
  });
}

// ── SudoSession singleton ────────────────────────────────────────────────────

// SECURITY (CORE-021): Module-scoped singleton variable prevents external
// mutation via (SudoSession as any).instance — inaccessible outside module.
let _sudoSessionInstance: SudoSession | null = null;

export class SudoSession {
  /** Password stored in a Buffer so we can zero it (not interned by V8). */
  private passwordBuf: Buffer | null = null;

  /** Username that authenticated. */
  private username: string | null = null;

  /**
   * SECURITY (CICD-028): OS-level user ID that created this session.
   * Used for session isolation tracking. Defaults to process.getuid().
   *
   * NOTE: Concurrent multi-user sessions are NOT currently supported.
   * This server should not be used in multi-tenant environments where
   * multiple users share the same process. Each user should run their
   * own server instance.
   */
  private sessionUserId: number | null = null;

  /** Timestamp (epoch ms) when the session expires. */
  private expiresAt: number | null = null;

  /** Epoch ms when the current session was established (for drop duration calc). */
  private elevatedAt: number | null = null;

  /** Handle for the auto-expiry timer. */
  private expiryTimer: ReturnType<typeof setTimeout> | null = null;

  /** Default session timeout in milliseconds (15 min). */
  private defaultTimeoutMs = 15 * 60 * 1000;

  /**
   * Per-session rate limiter for authentication attempts.
   * Configured with a sliding 5-minute window and 5-attempt cap.
   * Uses per-key tracking via `peek()` / `record()` / `resetKey()`.
   */
  private authRateLimiter: RateLimiter;

  private constructor() {
    // Dedicated rate limiter for auth — separate from the global tool limiter.
    // maxPerTool=5, maxGlobal=0 (disabled), windowMs=5min (in seconds for ctor)
    this.authRateLimiter = new RateLimiter(
      AUTH_RL_MAX_ATTEMPTS, // maxPerTool: cap per key
      0,                    // maxGlobal: disabled (no global cap for auth)
      AUTH_RL_WINDOW_MS / 1000 // windowMs: constructor takes seconds
    );

    // Zero the password on process exit/crash
    const cleanup = () => this.drop();
    process.once("exit", cleanup);
    process.once("SIGINT", cleanup);
    process.once("SIGTERM", cleanup);
    process.once("uncaughtException", cleanup);
  }

  /** Get the singleton instance. */
  static getInstance(): SudoSession {
    if (!_sudoSessionInstance) {
      _sudoSessionInstance = new SudoSession();
    }
    return _sudoSessionInstance;
  }

  /**
   * Reset the singleton instance (for testing only).
   * @internal
   */
  static resetInstance(): void {
    _sudoSessionInstance = null;
  }

  /**
   * Set the session timeout in milliseconds.
   * Only affects future `elevate()` calls.
   */
  setDefaultTimeout(ms: number): void {
    if (ms > 0) {
      this.defaultTimeoutMs = ms;
    }
  }

  /**
   * Attempt to elevate privileges by validating the given password.
   *
   * Runs `sudo -S -k -v` with the password piped on stdin.
   * `-k` invalidates cached credentials so we always test our password.
   * `-v` validates without running a command.
   * `-S` reads password from stdin.
   * `-p ""` suppresses the password prompt text.
   *
   * Phase 2: Checks the auth rate limiter before attempting. Records failures.
   * Resets the counter on success.
   *
   * Phase 3: Emits structured audit events for all outcomes.
   *
   * @returns Structured result indicating success, failure, or rate-limit block.
   */
  async elevate(password: string | Buffer, timeoutMs?: number): Promise<ElevateResult> {
    // SECURITY (CORE-005): JavaScript strings are immutable and interned by V8,
    // making them impossible to reliably zero from memory. Convert password to
    // Buffer immediately to minimize credential lifetime as a V8 string.
    const passwordBuf = Buffer.isBuffer(password)
      ? Buffer.from(password)  // defensive copy so caller's buffer isn't affected
      : Buffer.from(password, "utf-8");

    // Determine who we are first
    const whoami = await runSimple("whoami", []);
    const currentUser = whoami.stdout.trim() || "unknown";
    const currentUid = process.getuid?.() ?? -1;

    // AUDIT: elevation requested
    logger.security("sudo-session", "elevation_requested", "Sudo elevation requested", {
      user: currentUser,
      uid: currentUid,
    });

    // ── Phase 2: Rate limit check ─────────────────────────────────────────
    const rlState = this.authRateLimiter.peek(AUTH_RL_KEY);
    if (!rlState.allowed) {
      const retryAfterMs = rlState.retryAfterMs ?? AUTH_RL_WINDOW_MS;
      const retryAfterSec = Math.ceil(retryAfterMs / 1000);

      // AUDIT: rate limit triggered
      logger.security("sudo-session", "rate_limit_triggered",
        "Authentication rate limit reached — elevation blocked", {
          user: currentUser,
          uid: currentUid,
          attemptsInWindow: AUTH_RL_MAX_ATTEMPTS,
          retryAfterMs,
          lockoutUntil: new Date(Date.now() + retryAfterMs).toISOString(),
        });

      // Zero the password buffer before returning
      passwordBuf.fill(0);

      return {
        success: false,
        rateLimited: true,
        retryAfterMs,
        error:
          `Too many failed authentication attempts. ` +
          `Locked out for ${retryAfterSec} seconds (${Math.ceil(retryAfterSec / 60)} min). ` +
          `Rate limit: ${AUTH_RL_MAX_ATTEMPTS} attempts per ${AUTH_RL_WINDOW_MS / 60000} minutes.`,
      };
    }

    // If already running as root, no password needed
    if (currentUser === "root") {
      this.username = "root";
      this.expiresAt = null;
      this.elevatedAt = Date.now();
      this.sessionUserId = currentUid >= 0 ? currentUid : null;
      // Store an empty buffer — the executor will skip stdin piping for root
      this.passwordBuf = Buffer.alloc(0);
      // Zero the local buffer — not needed for root
      passwordBuf.fill(0);

      // AUDIT: elevation granted (root — no TTL)
      logger.security("sudo-session", "elevation_granted",
        "Privileges elevated (running as root — no authentication required)", {
          user: "root",
          uid: currentUid,
          ttlMs: null,
          expiresAt: null,
        });

      // Reset any prior rate limit state
      this.authRateLimiter.resetKey(AUTH_RL_KEY);
      return { success: true };
    }

    // Validate the password with sudo -S -k -v
    const validationBuf = Buffer.concat([passwordBuf, Buffer.from("\n")]);
    const result = await runSimple(
      "sudo",
      ["-S", "-k", "-v", "-p", ""],
      validationBuf,
      10000
    );
    // Zero the validation buffer immediately after use
    validationBuf.fill(0);

    if (result.exitCode === 0) {
      // ── Successful elevation ───────────────────────────────────────────
      // Password is valid — store it (storePassword makes its own defensive copy)
      this.storePassword(passwordBuf, timeoutMs);
      // Zero our local copy since storePassword made its own
      passwordBuf.fill(0);
      this.username = currentUser;
      // SECURITY (CICD-028): Track the OS-level user ID for session isolation
      this.sessionUserId = currentUid >= 0 ? currentUid : null;
      this.elevatedAt = Date.now();

      // Reset rate limit counter on successful auth
      this.authRateLimiter.resetKey(AUTH_RL_KEY);

      const ttlMs = timeoutMs ?? this.defaultTimeoutMs;
      const expiresAt = this.expiresAt;

      // AUDIT: elevation granted
      logger.security("sudo-session", "elevation_granted",
        `Privileges elevated for user '${currentUser}'`, {
          user: currentUser,
          uid: this.sessionUserId,
          ttlMs,
          expiresAt: expiresAt !== null ? new Date(expiresAt).toISOString() : null,
          // NOTE: password is NEVER included in log output
        });

      return { success: true };
    }

    // ── Failed elevation ───────────────────────────────────────────────────
    // Zero password buffer on all failure paths
    passwordBuf.fill(0);

    // Record the failure for rate limiting
    this.authRateLimiter.record(AUTH_RL_KEY);

    // Peek updated state to include remaining attempts in error message
    const rlAfter = this.authRateLimiter.peek(AUTH_RL_KEY);
    const attemptsRemaining = rlAfter.remaining;

    // Check for common failure reasons
    const stderr = result.stderr.toLowerCase();
    let reason: string;
    let errorMsg: string;

    if (stderr.includes("not in the sudoers file")) {
      reason = "not_in_sudoers";
      errorMsg = `User '${currentUser}' is not in the sudoers file. Cannot elevate privileges.`;
    } else if (stderr.includes("incorrect password") || stderr.includes("sorry")) {
      reason = "authentication_failed";
      errorMsg =
        `Incorrect password. ` +
        (attemptsRemaining > 0
          ? `Attempts remaining before lockout: ${attemptsRemaining}.`
          : `Rate limit reached. Elevation is locked out for the next ${AUTH_RL_WINDOW_MS / 60000} minutes.`);
    } else {
      reason = "sudo_error";
      errorMsg = `sudo validation failed (exit ${result.exitCode}): ${result.stderr.substring(0, 200)}`;
    }

    // AUDIT: elevation failed
    logger.security("sudo-session", "elevation_failed",
      `Elevation failed for user '${currentUser}': ${reason}`, {
        user: currentUser,
        uid: currentUid,
        reason,
        attemptsRemaining,
        // NOTE: password is NEVER logged
      });

    return { success: false, error: errorMsg };
  }

  /**
   * Returns a **copy** of the password Buffer for piping to sudo -S,
   * or null if not elevated.
   *
   * SECURITY (CICD-028): Validates that the calling process UID matches the
   * UID that established the session. If the UID has changed (e.g., due to
   * a UID-switching attack), the session is dropped and null is returned.
   *
   * The caller MUST zero the returned Buffer with `.fill(0)` after use.
   * A copy is returned so the original can be zeroed independently via `drop()`.
   */
  getPassword(): Buffer | null {
    // SECURITY (CICD-028): Session isolation — refuse to provide credentials
    // if the OS UID no longer matches the UID that established the session.
    const currentUid = process.getuid?.() ?? -1;
    if (this.sessionUserId !== null && currentUid !== this.sessionUserId) {
      logger.warn("sudo-session", "uid_mismatch",
        "Session UID mismatch — dropping credentials as a precaution", {
          sessionUid: this.sessionUserId,
          currentUid,
        });
      this.drop();
      return null;
    }

    if (!this.passwordBuf || this.passwordBuf.length === 0) {
      return null;
    }
    if (this.isExpired()) {
      this.drop();
      return null;
    }
    // Return a COPY so original can be zeroed independently
    const copy = Buffer.alloc(this.passwordBuf.length);
    this.passwordBuf.copy(copy);
    return copy;
  }

  /** Check whether we have an active elevated session. */
  isElevated(): boolean {
    if (!this.passwordBuf) return false;
    if (this.username === "root") return true; // root never expires
    if (this.isExpired()) {
      this.drop();
      return false;
    }
    return true;
  }

  /** Get current session status (safe to expose via MCP). */
  getStatus(): SudoSessionStatus {
    const rlState = this.authRateLimiter.peek(AUTH_RL_KEY);

    if (!this.isElevated()) {
      return {
        elevated: false,
        username: null,
        expiresAt: null,
        remainingSeconds: null,
        rateLimit: {
          limited: !rlState.allowed,
          attemptsRemaining: rlState.remaining === Infinity ? AUTH_RL_MAX_ATTEMPTS : rlState.remaining,
          ...(rlState.retryAfterMs !== undefined
            ? { resetAt: new Date(Date.now() + rlState.retryAfterMs).toISOString() }
            : {}),
        },
      };
    }

    const remaining = this.expiresAt
      ? Math.max(0, Math.round((this.expiresAt - Date.now()) / 1000))
      : null;

    return {
      elevated: true,
      username: this.username,
      expiresAt: this.expiresAt ? new Date(this.expiresAt).toISOString() : null,
      remainingSeconds: remaining,
      rateLimit: {
        limited: false,
        attemptsRemaining: rlState.remaining === Infinity ? AUTH_RL_MAX_ATTEMPTS : rlState.remaining,
      },
    };
  }

  /**
   * Get the current rate-limit status for the auth key.
   * Safe to surface to MCP callers (contains no credentials).
   */
  getRateLimitStatus(): {
    limited: boolean;
    attemptsRemaining: number;
    resetAt?: string;
  } {
    const rlState = this.authRateLimiter.peek(AUTH_RL_KEY);
    return {
      limited: !rlState.allowed,
      attemptsRemaining: rlState.remaining === Infinity ? AUTH_RL_MAX_ATTEMPTS : rlState.remaining,
      ...(rlState.retryAfterMs !== undefined
        ? { resetAt: new Date(Date.now() + rlState.retryAfterMs).toISOString() }
        : {}),
    };
  }

  /**
   * Drop elevated privileges immediately.
   * Zeroes the password buffer and clears all session state.
   */
  drop(): void {
    const user = this.username;
    const uid = this.sessionUserId;
    const elevatedAt = this.elevatedAt;
    const durationMs = elevatedAt !== null ? Date.now() - elevatedAt : null;

    if (this.passwordBuf) {
      // Zero the buffer contents
      this.passwordBuf.fill(0);
      this.passwordBuf = null;
    }
    this.username = null;
    this.expiresAt = null;
    this.elevatedAt = null;
    this.sessionUserId = null;

    if (this.expiryTimer) {
      clearTimeout(this.expiryTimer);
      this.expiryTimer = null;
    }

    // Also invalidate the system sudo cache (fire and forget)
    try {
      runSimple("sudo", ["-k"], undefined, 3000).catch(() => {});
    } catch {
      // Best effort
    }

    // AUDIT: session dropped (only if there was an active session to drop)
    if (user !== null) {
      logger.security("sudo-session", "session_dropped",
        `Privileges dropped for user '${user}'`, {
          user,
          uid,
          durationMs,
        });
    }
  }

  /**
   * Extend the session timeout by the given milliseconds (or the default).
   */
  extend(extraMs?: number): boolean {
    if (!this.isElevated()) return false;
    if (this.username === "root") return true; // root sessions don't expire

    const ms = extraMs ?? this.defaultTimeoutMs;
    this.expiresAt = Date.now() + ms;

    // Reset the timer
    if (this.expiryTimer) {
      clearTimeout(this.expiryTimer);
    }
    this.expiryTimer = setTimeout(() => {
      this._onSessionExpired();
    }, ms);
    // Prevent the timer from keeping the process alive
    if (this.expiryTimer && typeof this.expiryTimer === "object" && "unref" in this.expiryTimer) {
      this.expiryTimer.unref();
    }

    // AUDIT: session extended
    logger.security("sudo-session", "session_extended",
      `Session extended for user '${this.username}'`, {
        user: this.username,
        uid: this.sessionUserId,
        newExpiresAt: new Date(this.expiresAt).toISOString(),
        extensionMs: ms,
      });

    return true;
  }

  // ── Private helpers ──────────────────────────────────────────────────────

  /** Called when the TTL timer fires. Emits audit event then drops. */
  private _onSessionExpired(): void {
    const user = this.username;
    const uid = this.sessionUserId;
    const elevatedAt = this.elevatedAt;
    const durationMs = elevatedAt !== null ? Date.now() - elevatedAt : null;

    // AUDIT: session expired (before drop clears the fields)
    logger.security("sudo-session", "session_expired",
      `Session TTL expired for user '${user}'`, {
        user,
        uid,
        durationMs,
      });

    this.drop();
  }

  private storePassword(password: string | Buffer, timeoutMs?: number): void {
    // Zero any existing buffer
    if (this.passwordBuf) {
      this.passwordBuf.fill(0);
    }

    // Store in a new buffer (accept both string and Buffer to avoid V8 string interning)
    this.passwordBuf = Buffer.isBuffer(password)
      ? Buffer.from(password)  // defensive copy
      : Buffer.from(password, "utf-8");

    // Set expiry
    const ms = timeoutMs ?? this.defaultTimeoutMs;
    this.expiresAt = Date.now() + ms;

    // Auto-drop on expiry
    if (this.expiryTimer) {
      clearTimeout(this.expiryTimer);
    }
    this.expiryTimer = setTimeout(() => {
      this._onSessionExpired();
    }, ms);

    // Don't let the timer keep the process alive
    if (this.expiryTimer && typeof this.expiryTimer === "object" && "unref" in this.expiryTimer) {
      this.expiryTimer.unref();
    }
  }

  private isExpired(): boolean {
    if (this.expiresAt === null) return false; // root sessions don't expire
    return Date.now() >= this.expiresAt;
  }
}
