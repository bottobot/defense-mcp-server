/**
 * Tests for src/tools/backup.ts
 *
 * Covers: tool registration, TOOL-026 backup path validation, schema validation,
 * dry_run defaults, restore path validation, and action routing.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/core/executor.js", () => ({
  executeCommand: vi.fn().mockResolvedValue({ exitCode: 0, stdout: "", stderr: "", timedOut: false, duration: 10, permissionDenied: false }),
}));

const cmdOk = { exitCode: 0, stdout: "", stderr: "", timedOut: false, duration: 10, permissionDenied: false };
vi.mock("../../src/core/config.js", () => ({
  getConfig: vi.fn().mockReturnValue({ dryRun: true, backupDir: "/tmp/kali-backups" }),
  getToolTimeout: vi.fn().mockReturnValue(30000),
}));
vi.mock("../../src/core/parsers.js", () => ({
  createTextContent: vi.fn((text: string) => ({ type: "text", text })),
  createErrorContent: vi.fn((text: string) => ({ type: "text", text: `Error: ${text}` })),
  formatToolOutput: vi.fn((obj: unknown) => ({ type: "text", text: JSON.stringify(obj) })),
}));
vi.mock("../../src/core/changelog.js", () => ({
  logChange: vi.fn(),
  createChangeEntry: vi.fn().mockReturnValue({}),
  backupFile: vi.fn().mockReturnValue("/tmp/backup/file.bak"),
  restoreFile: vi.fn(),
}));
vi.mock("../../src/core/sanitizer.js", () => ({
  validateFilePath: vi.fn((p: string) => p),
  validateToolPath: vi.fn((p: string) => p),
}));
vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return { ...actual, existsSync: vi.fn().mockReturnValue(false), readFileSync: vi.fn().mockReturnValue("") };
});

import { registerBackupTools } from "../../src/tools/backup.js";

type ToolHandler = (params: Record<string, unknown>) => Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }>;

function createMockServer() {
  const tools = new Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>();
  const server = {
    tool: vi.fn((name: string, _desc: string, schema: Record<string, unknown>, handler: ToolHandler) => {
      tools.set(name, { schema, handler });
    }),
  };
  return { server: server as unknown as Parameters<typeof registerBackupTools>[0], tools };
}

describe("backup tools", () => {
  let tools: Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>;

  beforeEach(() => {
    vi.clearAllMocks();
    const mock = createMockServer();
    registerBackupTools(mock.server);
    tools = mock.tools;
  });

  it("should register the backup tool", () => {
    expect(tools.has("backup")).toBe(true);
  });

  it("should preview config backup in dry_run mode", async () => {
    const handler = tools.get("backup")!.handler;
    const result = await handler({ action: "config", dry_run: true });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("DRY-RUN");
  });

  it("should require backup_path for restore action", async () => {
    const handler = tools.get("backup")!.handler;
    const result = await handler({ action: "restore" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("backup_path is required");
  });

  it("should require original_path for restore action", async () => {
    const handler = tools.get("backup")!.handler;
    const result = await handler({ action: "restore", backup_path: "/tmp/backup.bak" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("original_path is required");
  });

  it("should reject backup path with traversal in state action (TOOL-026)", async () => {
    const handler = tools.get("backup")!.handler;
    const result = await handler({ action: "state", output_dir: "/tmp/../../../etc/shadow", dry_run: true });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("traversal");
  });

  it("should preview state snapshot in dry_run mode", async () => {
    const handler = tools.get("backup")!.handler;
    const result = await handler({
      action: "state",
      output_dir: "/tmp/snapshot",
      include_packages: true,
      include_services: false,
      include_network: false,
      include_firewall: false,
      include_users: false,
      dry_run: true,
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("DRY-RUN");
  });

  it("should handle list action", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk, stdout: "" });
    const handler = tools.get("backup")!.handler;
    const result = await handler({ action: "list", sort_by: "date", limit: 10 });
    // Should not be an error (may produce empty list)
    expect(result.content).toBeDefined();
  });

  it("should handle unknown action", async () => {
    const handler = tools.get("backup")!.handler;
    const result = await handler({ action: "unknown_action" as string });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Unknown action");
  });
});
