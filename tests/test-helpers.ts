/**
 * Shared test utilities for defense-mcp-server tool tests.
 *
 * Eliminates boilerplate duplication across test files by providing
 * common helpers for mock servers, child processes, and command results.
 */

import { vi } from "vitest";
import { EventEmitter } from "node:events";

// ── Types ────────────────────────────────────────────────────────────────────

/** Standard tool handler signature used across all tool tests. */
export type ToolHandler = (
  params: Record<string, unknown>,
) => Promise<{
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}>;

/** Tool entry stored in the mock server's tools map. */
export interface ToolEntry {
  schema: Record<string, unknown>;
  handler: ToolHandler;
}

/** Standard CommandResult shape returned by executeCommand. */
export interface MockCommandResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  duration: number;
  permissionDenied: boolean;
}

// ── Mock Server ──────────────────────────────────────────────────────────────

/**
 * Create a mock MCP server that captures tool registrations.
 * Works with any registerXxxTools function.
 *
 * Usage:
 *   const { server, tools } = createMockServer();
 *   registerFirewallTools(server);
 *   const handler = tools.get("firewall")!.handler;
 */
export function createMockServer() {
  const tools = new Map<string, ToolEntry>();
  const server = {
    tool: vi.fn(
      (
        name: string,
        _desc: string,
        schema: Record<string, unknown>,
        handler: ToolHandler,
      ) => {
        tools.set(name, { schema, handler });
      },
    ),
  };
  // Cast to `any` so it satisfies any registerXxxTools(server) signature
  return { server: server as any, tools };
}

// ── Mock Child Process ───────────────────────────────────────────────────────

/**
 * Create a mock ChildProcess that emits stdout/stderr and close code.
 * Used for tools that call spawnSafe().
 */
export function createMockChildProcess(
  stdout: string,
  stderr: string,
  exitCode: number,
) {
  const cp = new EventEmitter() as EventEmitter & {
    stdout: EventEmitter;
    stderr: EventEmitter;
    kill: ReturnType<typeof vi.fn>;
  };
  cp.stdout = new EventEmitter();
  cp.stderr = new EventEmitter();
  cp.kill = vi.fn();

  process.nextTick(() => {
    if (stdout) cp.stdout.emit("data", Buffer.from(stdout));
    if (stderr) cp.stderr.emit("data", Buffer.from(stderr));
    cp.emit("close", exitCode);
  });

  return cp;
}

// ── Mock Command Results ─────────────────────────────────────────────────────

/** A successful command result with empty output. */
export const CMD_OK: MockCommandResult = {
  exitCode: 0,
  stdout: "",
  stderr: "",
  timedOut: false,
  duration: 10,
  permissionDenied: false,
};

/** Create a successful command result with custom stdout. */
export function cmdSuccess(stdout: string, stderr = ""): MockCommandResult {
  return { ...CMD_OK, stdout, stderr };
}

/** Create a failed command result. */
export function cmdFail(stderr = "", exitCode = 1, stdout = ""): MockCommandResult {
  return { ...CMD_OK, exitCode, stdout, stderr };
}

/** Create a timed-out command result. */
export function cmdTimeout(): MockCommandResult {
  return { ...CMD_OK, exitCode: 124, timedOut: true, stderr: "Command timed out" };
}

/** Create a permission-denied command result. */
export function cmdPermDenied(): MockCommandResult {
  return { ...CMD_OK, exitCode: 1, permissionDenied: true, stderr: "Permission denied" };
}

// ── Standard Mock Factories ──────────────────────────────────────────────────

/** Standard parsers mock object for vi.mock(). */
export function parsersMock() {
  return {
    createTextContent: vi.fn((text: string) => ({ type: "text", text })),
    createErrorContent: vi.fn((text: string) => ({ type: "text", text: `Error: ${text}` })),
    formatToolOutput: vi.fn((obj: unknown) => ({ type: "text", text: JSON.stringify(obj) })),
    parseAuditdOutput: vi.fn().mockReturnValue([]),
    parseFail2banOutput: vi.fn().mockReturnValue({}),
  };
}

/** Standard config mock object for vi.mock(). */
export function configMock(overrides: Record<string, unknown> = {}) {
  return {
    getConfig: vi.fn().mockReturnValue({ dryRun: false, networkTimeout: 10000, ...overrides }),
    getToolTimeout: vi.fn().mockReturnValue(30000),
  };
}

/** Standard changelog mock object for vi.mock(). */
export function changelogMock() {
  return {
    logChange: vi.fn(),
    createChangeEntry: vi.fn().mockReturnValue({}),
    backupFile: vi.fn().mockReturnValue("/tmp/backup"),
  };
}

/** Standard sanitizer mock object for vi.mock(). */
export function sanitizerMock() {
  return {
    sanitizeArgs: vi.fn((a: string[]) => a),
    validateFilePath: vi.fn((p: string) => p),
    validateAuditdKey: vi.fn((k: string) => k),
    validateTarget: vi.fn((t: string) => t),
    validateInterface: vi.fn((i: string) => i),
    validateToolPath: vi.fn((p: string) => {
      if (p.includes("..")) throw new Error("Path contains forbidden directory traversal (..)");
      return p;
    }),
  };
}

/** Standard safeguards mock object for vi.mock(). */
export function safeguardsMock() {
  return {
    SafeguardRegistry: {
      getInstance: vi.fn().mockReturnValue({
        checkSafety: vi.fn().mockResolvedValue({ safe: true, warnings: [], blockers: [], impactedApps: [] }),
      }),
    },
  };
}

/** Standard executor mock object for vi.mock(). */
export function executorMock() {
  return {
    executeCommand: vi.fn().mockResolvedValue(CMD_OK),
  };
}

/** Standard secure-fs mock object for vi.mock(). */
export function secureFsMock() {
  return {
    secureWriteFileSync: vi.fn(),
    secureCopyFileSync: vi.fn(),
  };
}
