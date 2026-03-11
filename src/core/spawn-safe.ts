/**
 * Low-level safe process spawning for defense-mcp-server.
 *
 * This module provides the foundational child process creation layer.
 * It has NO dependencies on executor.ts, sudo-session.ts, or any module
 * that could create circular imports.
 *
 * Dependencies: node:child_process, ./command-allowlist.js
 *
 * All child process creation outside of executor.ts should go through
 * this module to ensure:
 * 1. Command allowlist enforcement
 * 2. shell: false always
 * 3. Audit logging to stderr
 */

import {
  spawn as nodeSpawn,
  execFileSync as nodeExecFileSync,
  type SpawnOptions,
  type ExecFileSyncOptions,
  type ChildProcess,
} from "node:child_process";
import { resolveCommand } from "./command-allowlist.js";

// ── Types ────────────────────────────────────────────────────────────────────

export interface SpawnSafeOptions extends SpawnOptions {}

export interface ExecFileSafeOptions extends ExecFileSyncOptions {}

// ── Argument Redaction ───────────────────────────────────────────────────────

/**
 * SECURITY (CORE-018): Patterns whose NEXT argument should be redacted in logs.
 * Matches flags like --password, --token, --key, --secret (with = or space-separated values).
 */
const SENSITIVE_FLAG_RE = /^--?(password|token|key|secret|passphrase|credential|auth)$/i;

/**
 * Redact sensitive arguments from a command's argument array for safe logging.
 *
 * Rules:
 * 1. If the command is "sudo", redact any argument immediately after `-S` (stdin password flag)
 * 2. If any argument matches sensitive flag patterns (--password, --token, --key, --secret),
 *    the NEXT argument is replaced with `[REDACTED]`
 * 3. If a sensitive flag uses `=` syntax (e.g. `--password=foo`), the value portion is redacted
 *
 * @param command - The command being executed
 * @param args - The original arguments array
 * @returns A new array safe for logging (original is not mutated)
 */
export function redactArgs(command: string, args: readonly string[]): string[] {
  const redacted = [...args];
  const isSudo = command === "sudo" || command.endsWith("/sudo");

  for (let i = 0; i < redacted.length; i++) {
    const arg = redacted[i];

    // Rule 1: For sudo, redact the argument after -S (stdin password)
    if (isSudo && arg === "-S" && i + 1 < redacted.length) {
      // Don't redact known sudo flags that follow -S
      const next = redacted[i + 1];
      if (next && !next.startsWith("-")) {
        redacted[i + 1] = "[REDACTED]";
      }
    }

    // Rule 2: Redact argument after sensitive flags
    if (SENSITIVE_FLAG_RE.test(arg) && i + 1 < redacted.length) {
      redacted[i + 1] = "[REDACTED]";
    }

    // Rule 3: Redact value in --flag=value style for sensitive flags
    const eqIdx = arg.indexOf("=");
    if (eqIdx > 0) {
      const flagPart = arg.substring(0, eqIdx);
      if (SENSITIVE_FLAG_RE.test(flagPart)) {
        redacted[i] = `${flagPart}=[REDACTED]`;
      }
    }
  }

  return redacted;
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Spawn a child process safely with allowlist enforcement and shell: false.
 * Returns a ChildProcess (async — listen on events for output).
 *
 * @param command - Bare binary name (e.g. "sudo") or absolute path
 * @param args - Arguments to pass to the command
 * @param options - SpawnOptions (shell is always forced to false)
 * @throws {Error} If the command is not in the allowlist
 */
export function spawnSafe(
  command: string,
  args: string[],
  options?: SpawnSafeOptions,
): ChildProcess {
  const resolvedCommand = resolveCommandSafe(command);

  const safeOptions: SpawnOptions = {
    ...options,
    shell: false, // ALWAYS false — non-negotiable
  };

  console.error(`[spawn-safe] ${resolvedCommand} ${redactArgs(command, args).join(" ")}`);
  return nodeSpawn(resolvedCommand, args, safeOptions);
}

/**
 * Execute a file synchronously with allowlist enforcement and shell: false.
 *
 * @param command - Bare binary name (e.g. "iptables") or absolute path
 * @param args - Arguments to pass to the command
 * @param options - ExecFileSyncOptions (shell is always forced to false)
 * @returns stdout as Buffer (no encoding) or string (with encoding option)
 * @throws {Error} If the command is not in the allowlist or the process exits non-zero
 */
export function execFileSafe(
  command: string,
  args: string[],
  options?: ExecFileSafeOptions,
): Buffer | string {
  const resolvedCommand = resolveCommandSafe(command);

  // SECURITY (CORE-011): Capture reference to any stdin input buffer for cleanup
  const inputBuffer = options?.input && Buffer.isBuffer(options.input) ? options.input : null;

  const safeOptions: ExecFileSyncOptions = {
    ...options,
    shell: false, // ALWAYS false
    timeout: options?.timeout ?? 120_000, // 120 second default for sync operations
  };

  console.error(`[spawn-safe] ${resolvedCommand} ${redactArgs(command, args).join(" ")}`);
  try {
    return nodeExecFileSync(resolvedCommand, args, safeOptions);
  } catch (err: unknown) {
    // Provide user-friendly timeout message
    if (err instanceof Error && "killed" in err && (err as NodeJS.ErrnoException).code === "ETIMEDOUT") {
      const timeoutSec = Math.round((safeOptions.timeout as number) / 1000);
      throw new Error(
        `Command timed out after ${timeoutSec} seconds. ` +
        `The target may be unreachable or the operation is taking too long. ` +
        `Consider increasing KALI_DEFENSE_COMMAND_TIMEOUT (current: ${timeoutSec}s).`
      );
    }
    throw err;
  } finally {
    // SECURITY (CORE-011): Zero any stdin buffer that may contain sensitive data
    // (e.g., passwords piped to commands). Guaranteed cleanup on all paths.
    if (inputBuffer) {
      inputBuffer.fill(0);
    }
  }
}

// ── Internal helper ──────────────────────────────────────────────────────────

/**
 * Resolve a command through the allowlist, or throw.
 *
 * Every command MUST pass through the allowlist — there is no bypass mechanism.
 *
 * If `resolveCommand()` throws (e.g. allowlist not yet initialized at startup),
 * falls back to checking `isAllowlisted()` which works even before
 * `initializeAllowlist()` has been called.
 */
function resolveCommandSafe(command: string): string {
  try {
    return resolveCommand(command);
  } catch {
    // SECURITY (CORE-014): Do NOT fall back to bare command name when resolution fails.
    // Using bare names allows PATH manipulation attacks. If resolveCommand() failed,
    // the binary either isn't on the system or the allowlist isn't initialized.
    // In either case, refuse to proceed.
    console.error(`[spawn-safe] Command resolution failed for "${command}" — refusing bare-name fallback`);
    throw new Error(`[spawn-safe] Command not in allowlist or not found on system: "${command}"`);
  }
}
