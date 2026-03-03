import { spawn } from "node:child_process";
import { getConfig, getToolTimeout } from "./config.js";
import { SudoSession } from "./sudo-session.js";

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
  /** Data to pipe to stdin */
  stdin?: string;
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
}

/**
 * Prepares sudo command options by injecting `-S -p ""` flags and
 * piping the stored password via stdin when a SudoSession is active.
 *
 * This is transparent to callers — tool code continues to use
 * `command: "sudo", args: ["iptables", ...]` and the password is
 * automatically injected if the session is elevated.
 */
function prepareSudoOptions(options: ExecuteOptions): ExecuteOptions {
  // Only transform calls where the command is "sudo"
  if (options.command !== "sudo") return options;

  // Skip if the caller explicitly opted out (e.g. sudo-session.ts itself)
  if (options.skipSudoInjection) return options;

  // Skip if the caller already supplied `-S` (manual control)
  if (options.args.includes("-S")) return options;

  const session = SudoSession.getInstance();
  const password = session.getPassword();

  if (!password) {
    // No active session — let sudo run normally (will likely fail without TTY)
    return options;
  }

  // Inject -S (read from stdin) and -p "" (suppress prompt) before the
  // existing arguments.  We also prepend --stdin so there is no ambiguity.
  const newArgs = ["-S", "-p", "", ...options.args];

  // Combine password with any existing stdin the caller provided
  const stdinPayload = options.stdin
    ? password + "\n" + options.stdin
    : password + "\n";

  return {
    ...options,
    args: newArgs,
    stdin: stdinPayload,
  };
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
      : config.defaultTimeout);
  const maxBuffer = options.maxBuffer ?? config.maxBuffer;

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
      resolve({
        stdout: "",
        stderr: `Spawn error: ${message}`,
        exitCode: 1,
        timedOut: false,
        duration,
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
      controller.abort();
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
      child.stdin.write(effectiveOptions.stdin);
      child.stdin.end();
    }

    child.on("close", (code: number | null) => {
      clearTimeout(timeoutId);
      const duration = Date.now() - startTime;

      let stdout = Buffer.concat(stdoutChunks).toString("utf-8");
      let stderr = Buffer.concat(stderrChunks).toString("utf-8");

      if (stdoutCapped) {
        stdout += "\n[OUTPUT TRUNCATED - exceeded max buffer]";
      }
      if (stderrCapped) {
        stderr += "\n[STDERR TRUNCATED - exceeded max buffer]";
      }

      resolve({
        stdout,
        stderr,
        exitCode: timedOut ? 124 : (code ?? 1),
        timedOut,
        duration,
      });
    });

    child.on("error", (err: Error) => {
      clearTimeout(timeoutId);
      const duration = Date.now() - startTime;

      // If it was an abort error from our timeout, handle as timeout
      if (timedOut) {
        resolve({
          stdout: Buffer.concat(stdoutChunks).toString("utf-8"),
          stderr: Buffer.concat(stderrChunks).toString("utf-8"),
          exitCode: 124,
          timedOut: true,
          duration,
        });
        return;
      }

      resolve({
        stdout: Buffer.concat(stdoutChunks).toString("utf-8"),
        stderr: `Process error: ${err.message}`,
        exitCode: 1,
        timedOut: false,
        duration,
      });
    });
  });
}
