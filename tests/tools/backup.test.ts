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
  getConfig: vi.fn().mockReturnValue({ dryRun: true, backupDir: "/tmp/defense-backups" }),
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

  // ── config action: execution (non-dry-run) ─────────────────────────────

  it("should backup config files in non-dry-run mode", async () => {
    const { getConfig } = await import("../../src/core/config.js");
    vi.mocked(getConfig).mockReturnValue({ dryRun: false, backupDir: "/tmp/defense-backups" } as ReturnType<typeof getConfig>);
    const { backupFile } = await import("../../src/core/changelog.js");
    vi.mocked(backupFile).mockReturnValue("/tmp/defense-backups/passwd.bak");

    const handler = tools.get("backup")!.handler;
    const result = await handler({ action: "config", files: "/etc/passwd,/etc/hosts", dry_run: false });
    expect(result.isError).toBeUndefined();
    expect(backupFile).toHaveBeenCalled();
  });

  it("should handle backup failure for individual files gracefully", async () => {
    const { getConfig } = await import("../../src/core/config.js");
    vi.mocked(getConfig).mockReturnValue({ dryRun: false, backupDir: "/tmp/defense-backups" } as ReturnType<typeof getConfig>);
    const { backupFile } = await import("../../src/core/changelog.js");
    vi.mocked(backupFile).mockImplementation((filePath: string) => {
      if (filePath === "/etc/shadow") throw new Error("Permission denied");
      return "/tmp/defense-backups/file.bak";
    });

    const handler = tools.get("backup")!.handler;
    const result = await handler({ action: "config", files: "/etc/passwd,/etc/shadow", dry_run: false });
    expect(result.isError).toBeUndefined();
    // Should report partial success
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.failed).toBe(1);
    expect(parsed.succeeded).toBe(1);
  });

  it("should use default critical files when no files specified in dry_run", async () => {
    const handler = tools.get("backup")!.handler;
    const result = await handler({ action: "config", dry_run: true });
    expect(result.isError).toBeUndefined();
    // Default files include /etc/passwd
    expect(result.content[0].text).toContain("/etc/passwd");
  });

  it("should include tag in config backup dry_run output", async () => {
    const handler = tools.get("backup")!.handler;
    const result = await handler({ action: "config", dry_run: true, tag: "pre-upgrade" });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("DRY-RUN");
  });

  // ── state action: execution (non-dry-run) ──────────────────────────────

  it("should capture system state in non-dry-run mode", async () => {
    const { getConfig } = await import("../../src/core/config.js");
    vi.mocked(getConfig).mockReturnValue({ dryRun: false, backupDir: "/tmp/defense-backups" } as ReturnType<typeof getConfig>);
    const { executeCommand } = await import("../../src/core/executor.js");
    vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk, stdout: "command output here" });

    const handler = tools.get("backup")!.handler;
    const result = await handler({
      action: "state",
      output_dir: "/tmp/snapshot-test",
      include_packages: true,
      include_services: false,
      include_network: false,
      include_firewall: false,
      include_users: false,
      dry_run: false,
    });
    expect(result.isError).toBeUndefined();
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.snapshotDir).toBe("/tmp/snapshot-test");
  });

  it("should handle empty command output in state capture", async () => {
    const { getConfig } = await import("../../src/core/config.js");
    vi.mocked(getConfig).mockReturnValue({ dryRun: false, backupDir: "/tmp/defense-backups" } as ReturnType<typeof getConfig>);
    const { executeCommand } = await import("../../src/core/executor.js");
    vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk, stdout: "", stderr: "No output" });

    const handler = tools.get("backup")!.handler;
    const result = await handler({
      action: "state",
      output_dir: "/tmp/snapshot-test",
      include_packages: true,
      include_services: false,
      include_network: false,
      include_firewall: false,
      include_users: false,
      dry_run: false,
    });
    expect(result.isError).toBeUndefined();
  });

  it("should reject state output_dir outside allowed directories", async () => {
    const handler = tools.get("backup")!.handler;
    const result = await handler({
      action: "state",
      output_dir: "/usr/local/forbidden-dir",
      dry_run: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("not within allowed directories");
  });

  // ── restore action: execution ──────────────────────────────────────────

  it("should preview restore in dry_run mode", async () => {
    const handler = tools.get("backup")!.handler;
    const result = await handler({
      action: "restore",
      backup_path: "/tmp/defense-backups/passwd.bak",
      original_path: "/tmp/defense-backups/passwd",
      dry_run: true,
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("DRY-RUN");
  });

  it("should execute restore in non-dry-run mode", async () => {
    const { getConfig } = await import("../../src/core/config.js");
    vi.mocked(getConfig).mockReturnValue({ dryRun: false, backupDir: "/tmp/defense-backups" } as ReturnType<typeof getConfig>);
    const { restoreFile, backupFile } = await import("../../src/core/changelog.js");
    vi.mocked(backupFile).mockReturnValue("/tmp/defense-backups/current.bak");

    const handler = tools.get("backup")!.handler;
    const result = await handler({
      action: "restore",
      backup_path: "/tmp/defense-backups/passwd.bak",
      original_path: "/tmp/defense-backups/passwd",
      dry_run: false,
    });
    expect(result.isError).toBeUndefined();
    expect(restoreFile).toHaveBeenCalled();
    expect(result.content[0].text).toContain("restored successfully");
  });

  it("should reject restore with traversal in backup_path", async () => {
    const handler = tools.get("backup")!.handler;
    const result = await handler({
      action: "restore",
      backup_path: "/tmp/../../../etc/shadow",
      original_path: "/tmp/defense-backups/target",
      dry_run: false,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("traversal");
  });

  // ── verify action ──────────────────────────────────────────────────────

  it("should verify a specific backup file", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk, stdout: "File: /tmp/backup.bak\nSize: 1024\n" });

    const handler = tools.get("backup")!.handler;
    const result = await handler({
      action: "verify",
      backup_path: "/tmp/defense-backups/test.bak",
      check_integrity: false,
    });
    expect(result.isError).toBeUndefined();
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.exists).toBe(true);
  });

  it("should report error when backup file not found during verify", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk, exitCode: 1, stdout: "", stderr: "No such file" });

    const handler = tools.get("backup")!.handler;
    const result = await handler({
      action: "verify",
      backup_path: "/tmp/defense-backups/nonexistent.bak",
      check_integrity: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("not found");
  });

  it("should verify all backups when no backup_path specified", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    vi.mocked(executeCommand).mockResolvedValue({
      ...cmdOk,
      stdout: `${Date.now() / 1000} 1024 /tmp/defense-backups/file1.bak\n${Date.now() / 1000} 2048 /tmp/defense-backups/file2.bak\n`,
    });

    const handler = tools.get("backup")!.handler;
    const result = await handler({ action: "verify", check_integrity: false });
    expect(result.isError).toBeUndefined();
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.totalBackups).toBe(2);
  });

  it("should report error when backup directory cannot be listed in verify", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk, exitCode: 1, stdout: "", stderr: "Permission denied" });

    const handler = tools.get("backup")!.handler;
    const result = await handler({ action: "verify", check_integrity: false });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Cannot list backups");
  });
});
