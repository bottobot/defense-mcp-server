import { spawn } from "node:child_process";
import { getConfig, getToolTimeout } from "./config.js";

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
 * Executes a command safely using spawn with shell: false.
 *
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

  return new Promise<CommandResult>((resolve) => {
    const startTime = Date.now();
    let timedOut = false;

    const controller = new AbortController();
    const { signal } = controller;

    let spawnEnv: NodeJS.ProcessEnv | undefined;
    if (options.env) {
      spawnEnv = { ...process.env, ...options.env };
    }

    let child;
    try {
      child = spawn(options.command, options.args, {
        shell: false,
        cwd: options.cwd,
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

    if (options.stdin && child.stdin) {
      child.stdin.write(options.stdin);
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
