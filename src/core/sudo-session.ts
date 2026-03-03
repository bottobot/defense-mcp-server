/**
 * SudoSession — singleton that manages elevated privilege credentials.
 *
 * The MCP server runs non-interactively via stdio transport, so `sudo`
 * cannot prompt for a password through a TTY. This module stores the
 * user's password in a zeroable Buffer and transparently provides it
 * to `sudo -S` via stdin piping in the executor.
 *
 * Security features:
 *   - Password stored in a Buffer (can be zeroed, not interned by V8)
 *   - Auto-expires after a configurable timeout (default 15 minutes)
 *   - Explicit `drop()` zeroes the buffer immediately
 *   - Process exit handler zeroes the buffer on shutdown
 *   - Validates credentials before storing (test with `sudo -S -v`)
 *   - Never logs or exposes the password in any output
 *
 * NOTE: This module uses `spawn` directly (not the executor) to avoid
 * a circular dependency, since the executor imports SudoSession.
 */

import { spawn } from "node:child_process";

// ── Types ────────────────────────────────────────────────────────────────────

export interface SudoSessionStatus {
  elevated: boolean;
  username: string | null;
  expiresAt: string | null;
  remainingSeconds: number | null;
}

// ── Internal helper: run a command without the executor ──────────────────────

interface SimpleResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

function runSimple(
  command: string,
  args: string[],
  stdin?: string,
  timeoutMs = 10000
): Promise<SimpleResult> {
  return new Promise((resolve) => {
    const controller = new AbortController();
    let child;
    try {
      child = spawn(command, args, {
        shell: false,
        signal: controller.signal,
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch {
      resolve({ stdout: "", stderr: "spawn failed", exitCode: 1 });
      return;
    }

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];

    const timer = setTimeout(() => controller.abort(), timeoutMs);

    child.stdout?.on("data", (c: Buffer) => stdoutChunks.push(c));
    child.stderr?.on("data", (c: Buffer) => stderrChunks.push(c));

    if (stdin && child.stdin) {
      child.stdin.write(stdin);
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

export class SudoSession {
  private static instance: SudoSession | null = null;

  /** Password stored in a Buffer so we can zero it (not interned by V8). */
  private passwordBuf: Buffer | null = null;

  /** Username that authenticated. */
  private username: string | null = null;

  /** Timestamp (epoch ms) when the session expires. */
  private expiresAt: number | null = null;

  /** Handle for the auto-expiry timer. */
  private expiryTimer: ReturnType<typeof setTimeout> | null = null;

  /** Default session timeout in milliseconds (15 min). */
  private defaultTimeoutMs = 15 * 60 * 1000;

  private constructor() {
    // Zero the password on process exit/crash
    const cleanup = () => this.drop();
    process.once("exit", cleanup);
    process.once("SIGINT", cleanup);
    process.once("SIGTERM", cleanup);
    process.once("uncaughtException", cleanup);
  }

  /** Get the singleton instance. */
  static getInstance(): SudoSession {
    if (!SudoSession.instance) {
      SudoSession.instance = new SudoSession();
    }
    return SudoSession.instance;
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
   * @returns result indicating success or failure with error message.
   */
  async elevate(password: string, timeoutMs?: number): Promise<{ success: boolean; error?: string }> {
    // Determine who we are first
    const whoami = await runSimple("whoami", []);
    const currentUser = whoami.stdout.trim() || "unknown";

    // If already running as root, no password needed
    if (currentUser === "root") {
      this.username = "root";
      this.expiresAt = null;
      // Store an empty buffer — the executor will skip stdin piping for root
      this.passwordBuf = Buffer.alloc(0);
      return { success: true };
    }

    // Validate the password with sudo -S -k -v
    const result = await runSimple(
      "sudo",
      ["-S", "-k", "-v", "-p", ""],
      password + "\n",
      10000
    );

    if (result.exitCode === 0) {
      // Password is valid — store it
      this.storePassword(password, timeoutMs);
      this.username = currentUser;
      console.error(`[sudo-session] Elevated privileges for user '${currentUser}'`);
      return { success: true };
    }

    // Check for common failure reasons
    const stderr = result.stderr.toLowerCase();
    if (stderr.includes("not in the sudoers file")) {
      return {
        success: false,
        error: `User '${currentUser}' is not in the sudoers file. Cannot elevate privileges.`,
      };
    }
    if (stderr.includes("incorrect password") || stderr.includes("sorry")) {
      return {
        success: false,
        error: "Incorrect password. Please try again.",
      };
    }

    return {
      success: false,
      error: `sudo validation failed (exit ${result.exitCode}): ${result.stderr.substring(0, 200)}`,
    };
  }

  /**
   * Returns the password for piping to sudo -S, or null if not elevated.
   * The returned string should be used immediately and not stored.
   */
  getPassword(): string | null {
    if (!this.passwordBuf || this.passwordBuf.length === 0) {
      return null;
    }
    if (this.isExpired()) {
      this.drop();
      return null;
    }
    return this.passwordBuf.toString("utf-8");
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
    if (!this.isElevated()) {
      return {
        elevated: false,
        username: null,
        expiresAt: null,
        remainingSeconds: null,
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
    };
  }

  /**
   * Drop elevated privileges immediately.
   * Zeroes the password buffer and clears all session state.
   */
  drop(): void {
    if (this.passwordBuf) {
      // Zero the buffer contents
      this.passwordBuf.fill(0);
      this.passwordBuf = null;
    }
    this.username = null;
    this.expiresAt = null;

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

    console.error("[sudo-session] Privileges dropped, password zeroed");
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
    this.expiryTimer = setTimeout(() => this.drop(), ms);
    // Prevent the timer from keeping the process alive
    if (this.expiryTimer && typeof this.expiryTimer === "object" && "unref" in this.expiryTimer) {
      this.expiryTimer.unref();
    }

    console.error(
      `[sudo-session] Session extended, expires at ${new Date(this.expiresAt).toISOString()}`
    );
    return true;
  }

  // ── Private helpers ──────────────────────────────────────────────────────

  private storePassword(password: string, timeoutMs?: number): void {
    // Zero any existing buffer
    if (this.passwordBuf) {
      this.passwordBuf.fill(0);
    }

    // Store in a new buffer
    this.passwordBuf = Buffer.from(password, "utf-8");

    // Set expiry
    const ms = timeoutMs ?? this.defaultTimeoutMs;
    this.expiresAt = Date.now() + ms;

    // Auto-drop on expiry
    if (this.expiryTimer) {
      clearTimeout(this.expiryTimer);
    }
    this.expiryTimer = setTimeout(() => {
      console.error("[sudo-session] Session expired, dropping privileges");
      this.drop();
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
