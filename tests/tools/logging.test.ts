/**
 * Tests for src/tools/logging.ts
 *
 * Covers: TOOL-015 log path validation, tool registration (log_management),
 * action routing, dry_run defaults, and auditd key validation.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/core/executor.js", () => ({
  executeCommand: vi.fn().mockResolvedValue({ exitCode: 0, stdout: "", stderr: "", timedOut: false, duration: 10, permissionDenied: false }),
}));

const cmdOk = { exitCode: 0, stdout: "", stderr: "", timedOut: false, duration: 10, permissionDenied: false };
vi.mock("../../src/core/config.js", () => ({
  getConfig: vi.fn().mockReturnValue({ dryRun: true }),
  getToolTimeout: vi.fn().mockReturnValue(30000),
}));
vi.mock("../../src/core/parsers.js", () => ({
  createTextContent: vi.fn((text: string) => ({ type: "text", text })),
  createErrorContent: vi.fn((text: string) => ({ type: "text", text: `Error: ${text}` })),
  parseAuditdOutput: vi.fn().mockReturnValue([]),
  parseFail2banOutput: vi.fn().mockReturnValue({}),
  formatToolOutput: vi.fn((obj: unknown) => ({ type: "text", text: JSON.stringify(obj) })),
}));
vi.mock("../../src/core/changelog.js", () => ({
  logChange: vi.fn(),
  createChangeEntry: vi.fn().mockReturnValue({}),
  backupFile: vi.fn().mockReturnValue("/tmp/backup"),
}));
vi.mock("../../src/core/sanitizer.js", () => ({
  sanitizeArgs: vi.fn((a: string[]) => a),
  validateFilePath: vi.fn((p: string) => p),
  validateAuditdKey: vi.fn((k: string) => k),
  validateTarget: vi.fn((t: string) => t),
  validateToolPath: vi.fn((p: string, _dirs: string[], _label: string) => {
    if (p.includes("..")) throw new Error("Path contains forbidden directory traversal (..)");
    return p;
  }),
}));
vi.mock("../../src/core/distro-adapter.js", () => ({
  getDistroAdapter: vi.fn().mockResolvedValue({
    paths: { syslog: "/var/log/syslog" },
  }),
}));
vi.mock("../../src/core/spawn-safe.js", () => ({
  spawnSafe: vi.fn(),
}));
vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return { ...actual, existsSync: vi.fn().mockReturnValue(true) };
});

import { registerLoggingTools } from "../../src/tools/logging.js";

type ToolHandler = (params: Record<string, unknown>) => Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }>;

function createMockServer() {
  const tools = new Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>();
  const server = {
    tool: vi.fn((name: string, _desc: string, schema: Record<string, unknown>, handler: ToolHandler) => {
      tools.set(name, { schema, handler });
    }),
  };
  return { server: server as unknown as Parameters<typeof registerLoggingTools>[0], tools };
}

describe("logging tools", () => {
  let tools: Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>;

  beforeEach(() => {
    vi.clearAllMocks();
    const mock = createMockServer();
    registerLoggingTools(mock.server);
    tools = mock.tools;
  });

  it("should register 1 log_management tool", () => {
    expect(tools.has("log_management")).toBe(true);
  });

  // ── auditd_rules ──────────────────────────────────────────────────────

  it("should require rules_action for auditd_rules action", async () => {
    const handler = tools.get("log_management")!.handler;
    const result = await handler({ action: "auditd_rules" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("rules_action is required");
  });

  it("should require rule string for add action", async () => {
    const handler = tools.get("log_management")!.handler;
    const result = await handler({ action: "auditd_rules", rules_action: "add" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("rule string is required");
  });

  it("should preview rule add in dry_run mode", async () => {
    const handler = tools.get("log_management")!.handler;
    const result = await handler({
      action: "auditd_rules",
      rules_action: "add",
      rule: "-w /etc/passwd -p wa -k identity",
      dry_run: true,
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("DRY-RUN");
  });

  // ── fail2ban actions ──────────────────────────────────────────────────

  it("should require jail for fail2ban_ban action", async () => {
    const handler = tools.get("log_management")!.handler;
    const result = await handler({ action: "fail2ban_ban" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Jail name is required");
  });

  it("should require ip for fail2ban_ban action", async () => {
    const handler = tools.get("log_management")!.handler;
    const result = await handler({ action: "fail2ban_ban", jail: "sshd" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("IP address is required");
  });

  it("should preview fail2ban_ban in dry_run mode", async () => {
    const handler = tools.get("log_management")!.handler;
    const result = await handler({
      action: "fail2ban_ban",
      jail: "sshd",
      ip: "192.168.1.100",
      dry_run: true,
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("DRY-RUN");
  });

  // ── syslog_analyze ────────────────────────────────────────────────────

  it("should reject log_file path with traversal (TOOL-015)", async () => {
    const handler = tools.get("log_management")!.handler;
    const result = await handler({
      action: "syslog_analyze",
      log_file: "/var/log/../../../etc/shadow",
      pattern: "all",
      lines: 100,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("traversal");
  });

  it("should handle rotation_audit action", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk, stdout: "weekly\nrotate 4\ncompress\n" });
    const handler = tools.get("log_management")!.handler;
    const result = await handler({ action: "rotation_audit" });
    expect(result.isError).toBeUndefined();
  });

  // ── rotation_configure ───────────────────────────────────────────────

  it("should require logrotate_path for rotation_configure", async () => {
    const handler = tools.get("log_management")!.handler;
    const result = await handler({ action: "rotation_configure" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("logrotate_path is required");
  });

  it("should require logrotate_name for rotation_configure", async () => {
    const handler = tools.get("log_management")!.handler;
    const result = await handler({ action: "rotation_configure", logrotate_path: "/var/log/myapp.log" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("logrotate_name is required");
  });

  it("should reject logrotate_name with path traversal", async () => {
    const handler = tools.get("log_management")!.handler;
    const result = await handler({
      action: "rotation_configure",
      logrotate_path: "/var/log/myapp.log",
      logrotate_name: "../etc/evil",
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Invalid logrotate_name");
  });

  it("should reject unsafe extra_directives", async () => {
    const handler = tools.get("log_management")!.handler;
    const result = await handler({
      action: "rotation_configure",
      logrotate_path: "/var/log/myapp.log",
      logrotate_name: "myapp",
      extra_directives: ["rm -rf /"],
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Unsafe logrotate directive");
  });

  it("should preview rotation_configure in dry_run mode", async () => {
    const handler = tools.get("log_management")!.handler;
    const result = await handler({
      action: "rotation_configure",
      logrotate_path: "/var/log/myapp.log",
      logrotate_name: "myapp",
      rotate_count: 5,
      rotate_frequency: "daily",
      compress_logs: true,
      extra_directives: ["missingok", "notifempty"],
      dry_run: true,
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("DRY-RUN");
    expect(result.content[0].text).toContain("/var/log/myapp.log");
    expect(result.content[0].text).toContain("daily");
    expect(result.content[0].text).toContain("rotate 5");
    expect(result.content[0].text).toContain("compress");
    expect(result.content[0].text).toContain("missingok");
    expect(result.content[0].text).toContain("notifempty");
  });

  it("should write logrotate config when not dry_run", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk });
    const handler = tools.get("log_management")!.handler;
    const result = await handler({
      action: "rotation_configure",
      logrotate_path: "/var/log/myapp.log",
      logrotate_name: "myapp",
      rotate_count: 7,
      rotate_frequency: "weekly",
      compress_logs: true,
      dry_run: false,
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("Logrotate configuration written to /etc/logrotate.d/myapp");
    expect(vi.mocked(executeCommand)).toHaveBeenCalledWith(
      expect.objectContaining({
        command: "sudo",
        args: ["tee", "/etc/logrotate.d/myapp"],
      }),
    );
  });
});
