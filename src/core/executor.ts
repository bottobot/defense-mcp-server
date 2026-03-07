import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { getConfig, getToolTimeout } from "./config.js";
import { SudoSession } from "./sudo-session.js";
import { SudoGuard } from "./sudo-guard.js";
import { resolveCommand, resolveSudoCommand } from "./command-allowlist.js";

// ── Askpass helper detection ─────────────────────────────────────────────────

/**
 * Ordered list of known graphical sudo/SSH askpass helpers.
 * The first one found on the system will be used as the SUDO_ASKPASS program.
 */
const ASKPASS_CANDIDATES = [
  "/usr/bin/ssh-askpass",     // Generic (often symlinked to ksshaskpass/gnome)
  "/usr/bin/ksshaskpass",     // KDE Plasma
  "/usr/lib/ssh/x11-ssh-askpass", // X11 classic
  "/usr/libexec/openssh/gnome-ssh-askpass", // GNOME
  "/usr/bin/lxqt-sudo",      // LXQt
];

/** Cached result of askpass detection (null = not yet checked, undefined = not found) */
let cachedAskpass: string | undefined | null = null;

/**
 * Find the first available graphical askpass helper on the system.
 * Returns the absolute path or `undefined` if none found.
 * Result is cached for the process lifetime.
 */
function findAskpassHelper(): string | undefined {
  if (cachedAskpass !== null) return cachedAskpass;

  // Check environment variable first — user may have set it explicitly
  const envAskpass = process.env.SUDO_ASKPASS;
  if (envAskpass && existsSync(envAskpass)) {
    cachedAskpass = envAskpass;
    return cachedAskpass;
  }

  // Must have a display server to show a GUI dialog
  const hasDisplay = !!(process.env.DISPLAY || process.env.WAYLAND_DISPLAY);
  if (!hasDisplay) {
    cachedAskpass = undefined;
    return undefined;
  }

  for (const candidate of ASKPASS_CANDIDATES) {
    if (existsSync(candidate)) {
      cachedAskpass = candidate;
      console.error(`[executor] Found askpass helper: ${candidate}`);
      return cachedAskpass;
    }
  }

  cachedAskpass = undefined;
  return undefined;
}

/**
 * Options for executing a command.
 */
export interface ExecuteOptions {
  /** The command binary to execute */
  command: string;
  /** Arguments to pass to the command */
  args: string[];
  /** Timeout in milliseconds (overrides default) */
  timeout?: number;
  /** Working directory for the command */
  cwd?: string;
  /** Additional environment variables */
  env?: Record<string, string>;
  /** Data to pipe to stdin (Buffer preferred for sensitive data like passwords) */
  stdin?: string | Buffer;
  /** Maximum output buffer size in bytes */
  maxBuffer?: number;
  /** Tool name for timeout lookup */
  toolName?: string;
  /** Skip automatic sudo credential injection (used internally) */
  skipSudoInjection?: boolean;
}

/**
 * Result of a command execution.
 */
export interface CommandResult {
  /** Standard output content */
  stdout: string;
  /** Standard error content */
  stderr: string;
  /** Process exit code (124 on timeout) */
  exitCode: number;
  /** Whether the command was killed due to timeout */
  timedOut: boolean;
  /** Wall-clock duration in milliseconds */
  duration: number;
  /**
   * Whether the command failed due to insufficient privileges.
   * Detected by analyzing stderr/stdout against known permission error patterns.
   * When `true`, the caller should prompt the user to call `sudo_elevate`.
   */
  permissionDenied: boolean;
}

/**
 * Prepares sudo command options by injecting credentials so that sudo
 * works in non-interactive (no-TTY) environments like MCP servers.
 *
 * **Strategy (in priority order):**
 * 1. If a {@link SudoSession} is active with a cached password, inject
 *    `-S -p ""` and pipe the password via stdin (fastest, no UI).
 * 2. If no session but a graphical askpass helper is available (e.g.
 *    `ssh-askpass`, `ksshaskpass`), inject `-A` and set `SUDO_ASKPASS`
 *    env var. This pops a **secure native GUI dialog** for the password
 *    — the password never enters the chat or any log.
 * 3. If neither is available, let sudo run as-is (will fail without TTY,
 *    but the error will be caught and an elevation prompt returned).
 *
 * This is transparent to callers — tool code continues to use
 * `command: "sudo", args: ["iptables", ...]`.
 */
function prepareSudoOptions(options: ExecuteOptions): ExecuteOptions {
  // Only transform calls where the command is "sudo"
  if (options.command !== "sudo") return options;

  // Skip if the caller explicitly opted out (e.g. sudo-session.ts itself)
  if (options.skipSudoInjection) return options;

  // Skip if the caller already supplied `-S` or `-A` (manual control)
  if (options.args.includes("-S") || options.args.includes("-A")) return options;

  const session = SudoSession.getInstance();
  const passwordBuf = session.getPassword(); // Returns Buffer | null (a copy)

  if (passwordBuf) {
    // ── Strategy 1: SudoSession has a cached password → pipe via stdin ──
    const newArgs = ["-S", "-p", "", ...options.args];
    const newline = Buffer.from("\n");
    const stdinPayload = options.stdin
      ? Buffer.concat([
          passwordBuf,
          newline,
          Buffer.isBuffer(options.stdin) ? options.stdin : Buffer.from(options.stdin),
        ])
      : Buffer.concat([passwordBuf, newline]);
    // Zero the password copy immediately after concatenation
    passwordBuf.fill(0);

    return {
      ...options,
      args: newArgs,
      stdin: stdinPayload,
    };
  }

  // ── Strategy 2: No cached password → try graphical askpass helper ──
  const askpassPath = findAskpassHelper();
  if (askpassPath) {
    console.error(
      `[executor] No sudo session — falling back to askpass GUI: ${askpassPath}`,
    );
    const newArgs = ["-A", ...options.args];
    return {
      ...options,
      args: newArgs,
      env: {
        ...options.env,
        SUDO_ASKPASS: askpassPath,
        // Ensure DISPLAY is forwarded for GUI dialog
        ...(process.env.DISPLAY ? { DISPLAY: process.env.DISPLAY } : {}),
        ...(process.env.WAYLAND_DISPLAY
          ? { WAYLAND_DISPLAY: process.env.WAYLAND_DISPLAY }
          : {}),
      },
    };
  }

  // ── Strategy 3: No session, no askpass → let sudo fail naturally ──
  // The error will be caught by SudoGuard and an elevation prompt returned.
  return options;
}

/**
 * Executes a command safely using spawn with shell: false.
 *
 * - Transparently injects sudo credentials from SudoSession when available
 * - Uses AbortController for timeout enforcement
 * - Caps stdout/stderr buffers to maxBuffer
 * - Tracks execution duration
 * - Handles stdin piping
 * - Catches spawn errors gracefully
 */
export async function executeCommand(
  options: ExecuteOptions
): Promise<CommandResult> {
  const config = getConfig();
  const timeout =
    options.timeout ??
    (options.toolName
      ? getToolTimeout(options.toolName, config)
      : config.commandTimeout);
  const maxBuffer = options.maxBuffer ?? config.maxBuffer;

  // ── Command allowlist validation ─────────────────────────────────────
  // Resolve bare command names to absolute paths and reject anything
  // not in the allowlist. For sudo, also validate the target binary.
  try {
    if (options.command === "sudo") {
      const { sudoPath, targetIndex, targetPath } = resolveSudoCommand(options.args);
      options = {
        ...options,
        command: sudoPath,
        args: targetIndex >= 0
          ? [
              ...options.args.slice(0, targetIndex),
              targetPath,
              ...options.args.slice(targetIndex + 1),
            ]
          : options.args,
      };
    } else {
      options = {
        ...options,
        command: resolveCommand(options.command),
      };
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      stdout: "",
      stderr: `Allowlist validation failed: ${message}`,
      exitCode: 1,
      timedOut: false,
      duration: 0,
      permissionDenied: false,
    };
  }

  // ── Transparent sudo credential injection ────────────────────────────
  const effectiveOptions = prepareSudoOptions(options);

  return new Promise<CommandResult>((resolve) => {
    const startTime = Date.now();
    let timedOut = false;

    const controller = new AbortController();
    const { signal } = controller;

    let spawnEnv: NodeJS.ProcessEnv | undefined;
    if (effectiveOptions.env) {
      spawnEnv = { ...process.env, ...effectiveOptions.env };
    }

    let child;
    try {
      child = spawn(effectiveOptions.command, effectiveOptions.args, {
        shell: false,
        cwd: effectiveOptions.cwd,
        env: spawnEnv,
        signal,
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch (err: unknown) {
      const duration = Date.now() - startTime;
      const message = err instanceof Error ? err.message : String(err);
      const stderrMsg = `Spawn error: ${message}`;
      resolve({
        stdout: "",
        stderr: stderrMsg,
        exitCode: 1,
        timedOut: false,
        duration,
        permissionDenied: SudoGuard.isPermissionError(stderrMsg, 1),
      });
      return;
    }

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    let stdoutLen = 0;
    let stderrLen = 0;
    let stdoutCapped = false;
    let stderrCapped = false;

    const timeoutId = setTimeout(() => {
      timedOut = true;
      // Graceful SIGTERM first
      try { child.kill("SIGTERM"); } catch { /* ignore */ }
      // Escalate to SIGKILL after 5 seconds if still running
      setTimeout(() => {
        try { if (!child.killed) child.kill("SIGKILL"); } catch { /* ignore */ }
      }, 5000);
    }, timeout);

    child.stdout?.on("data", (chunk: Buffer) => {
      if (stdoutCapped) return;
      stdoutLen += chunk.length;
      if (stdoutLen > maxBuffer) {
        stdoutCapped = true;
        const remaining = maxBuffer - (stdoutLen - chunk.length);
        if (remaining > 0) {
          stdoutChunks.push(chunk.subarray(0, remaining));
        }
      } else {
        stdoutChunks.push(chunk);
      }
    });

    child.stderr?.on("data", (chunk: Buffer) => {
      if (stderrCapped) return;
      stderrLen += chunk.length;
      if (stderrLen > maxBuffer) {
        stderrCapped = true;
        const remaining = maxBuffer - (stderrLen - chunk.length);
        if (remaining > 0) {
          stderrChunks.push(chunk.subarray(0, remaining));
        }
      } else {
        stderrChunks.push(chunk);
      }
    });

    if (effectiveOptions.stdin && child.stdin) {
      const stdinBuf = Buffer.isBuffer(effectiveOptions.stdin)
        ? effectiveOptions.stdin
        : Buffer.from(effectiveOptions.stdin);
      child.stdin.write(stdinBuf);
      child.stdin.end();
      // Zero the buffer after writing (may contain sudo password)
      stdinBuf.fill(0);
    }

    child.on("close", (code: number | null) => {
      clearTimeout(timeoutId);
      const duration = Date.now() - startTime;
      const exitCode = timedOut ? 124 : (code ?? 1);

      let stdout = Buffer.concat(stdoutChunks).toString("utf-8");
      let stderr = Buffer.concat(stderrChunks).toString("utf-8");

      if (stdoutCapped) {
        stdout += "\n[OUTPUT TRUNCATED - exceeded max buffer]";
      }
      if (stderrCapped) {
        stderr += "\n[STDERR TRUNCATED - exceeded max buffer]";
      }

      if (timedOut) {
        const timeoutSec = Math.round(timeout / 1000);
        stderr += `\nCommand timed out after ${timeoutSec} seconds. ` +
          `The target may be unreachable or the operation is taking too long. ` +
          `Consider increasing KALI_DEFENSE_COMMAND_TIMEOUT (current: ${timeoutSec}s).`;
      }

      // Detect permission errors from combined output
      const combinedOutput = stdout + "\n" + stderr;
      const permissionDenied =
        !timedOut &&
        exitCode !== 0 &&
        SudoGuard.isPermissionError(combinedOutput, exitCode);

      resolve({
        stdout,
        stderr,
        exitCode,
        timedOut,
        duration,
        permissionDenied,
      });
    });

    child.on("error", (err: Error) => {
      clearTimeout(timeoutId);
      const duration = Date.now() - startTime;

      // If it was an abort error from our timeout, handle as timeout
      if (timedOut) {
        const timeoutSec = Math.round(timeout / 1000);
        const timeoutMsg = `\nCommand timed out after ${timeoutSec} seconds. ` +
          `The target may be unreachable or the operation is taking too long. ` +
          `Consider increasing KALI_DEFENSE_COMMAND_TIMEOUT (current: ${timeoutSec}s).`;
        resolve({
          stdout: Buffer.concat(stdoutChunks).toString("utf-8"),
          stderr: Buffer.concat(stderrChunks).toString("utf-8") + timeoutMsg,
          exitCode: 124,
          timedOut: true,
          duration,
          permissionDenied: false,
        });
        return;
      }

      const stderrMsg = `Process error: ${err.message}`;
      resolve({
        stdout: Buffer.concat(stdoutChunks).toString("utf-8"),
        stderr: stderrMsg,
        exitCode: 1,
        timedOut: false,
        duration,
        permissionDenied: SudoGuard.isPermissionError(stderrMsg, 1),
      });
    });
  });
}
