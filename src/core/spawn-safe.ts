/**
 * Low-level safe process spawning for kali-defense-mcp-server.
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
import { resolveCommand, isAllowlisted } from "./command-allowlist.js";

// ── Types ────────────────────────────────────────────────────────────────────

export interface SpawnSafeOptions extends SpawnOptions {
  /** If true, skip allowlist check (use with extreme caution) */
  bypassAllowlist?: boolean;
}

export interface ExecFileSafeOptions extends ExecFileSyncOptions {
  /** If true, skip allowlist check */
  bypassAllowlist?: boolean;
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Spawn a child process safely with allowlist enforcement and shell: false.
 * Returns a ChildProcess (async — listen on events for output).
 *
 * @param command - Bare binary name (e.g. "sudo") or absolute path
 * @param args - Arguments to pass to the command
 * @param options - SpawnOptions plus optional `bypassAllowlist`
 * @throws {Error} If the command is not in the allowlist
 */
export function spawnSafe(
  command: string,
  args: string[],
  options?: SpawnSafeOptions,
): ChildProcess {
  const resolvedCommand = resolveCommandSafe(command, options?.bypassAllowlist);

  const safeOptions: SpawnOptions = {
    ...options,
    shell: false, // ALWAYS false — non-negotiable
  };

  // Remove our custom property before passing to Node
  delete (safeOptions as Record<string, unknown>).bypassAllowlist;

  console.error(`[spawn-safe] ${resolvedCommand} ${args.join(" ")}`);
  return nodeSpawn(resolvedCommand, args, safeOptions);
}

/**
 * Execute a file synchronously with allowlist enforcement and shell: false.
 *
 * @param command - Bare binary name (e.g. "iptables") or absolute path
 * @param args - Arguments to pass to the command
 * @param options - ExecFileSyncOptions plus optional `bypassAllowlist`
 * @returns stdout as Buffer (no encoding) or string (with encoding option)
 * @throws {Error} If the command is not in the allowlist or the process exits non-zero
 */
export function execFileSafe(
  command: string,
  args: string[],
  options?: ExecFileSafeOptions,
): Buffer | string {
  const resolvedCommand = resolveCommandSafe(command, options?.bypassAllowlist);

  const safeOptions: ExecFileSyncOptions = {
    ...options,
    shell: false, // ALWAYS false
    timeout: options?.timeout ?? 120_000, // 120 second default for sync operations
  };

  delete (safeOptions as Record<string, unknown>).bypassAllowlist;

  console.error(`[spawn-safe] ${resolvedCommand} ${args.join(" ")}`);
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
  }
}

// ── Internal helper ──────────────────────────────────────────────────────────

/**
 * Resolve a command through the allowlist, or throw.
 *
 * If `resolveCommand()` throws (e.g. allowlist not yet initialized at startup),
 * falls back to checking `isAllowlisted()` which works even before
 * `initializeAllowlist()` has been called.
 */
function resolveCommandSafe(
  command: string,
  bypassAllowlist?: boolean,
): string {
  if (bypassAllowlist) {
    return command;
  }

  try {
    return resolveCommand(command);
  } catch {
    // If allowlist not initialized yet (early startup), check if it's a known binary
    if (isAllowlisted(command)) {
      return command; // Use bare name — allowlist knows it but hasn't resolved paths yet
    }
    throw new Error(`[spawn-safe] Command not in allowlist: "${command}"`);
  }
}
