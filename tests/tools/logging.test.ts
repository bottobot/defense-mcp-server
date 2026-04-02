/**
 * Tests for src/tools/logging.ts
 *
 * Covers: TOOL-015 log path validation, tool registration (log_management),
 * action routing, dry_run defaults, and auditd key validation.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { EventEmitter } from "node:events";

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

  // ── auditd_search ─────────────────────────────────────────────────────

  describe("auditd_search", () => {
    it("should run ausearch with key filter", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValue({
        ...cmdOk,
        stdout: "type=SYSCALL msg=audit(1234): arch=c000003e syscall=257\n",
      });
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "auditd_search", key: "identity" });
      expect(result.isError).toBeUndefined();
      expect(vi.mocked(executeCommand)).toHaveBeenCalledWith(
        expect.objectContaining({
          command: "sudo",
          args: expect.arrayContaining(["ausearch", "-k", "identity", "--interpret"]),
        }),
      );
    });

    it("should run ausearch with syscall filter", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk, stdout: "audit record\n" });
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "auditd_search", syscall: "open" });
      expect(result.isError).toBeUndefined();
      expect(vi.mocked(executeCommand)).toHaveBeenCalledWith(
        expect.objectContaining({
          args: expect.arrayContaining(["-sc", "open"]),
        }),
      );
    });

    it("should run ausearch with uid filter", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk, stdout: "audit record\n" });
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "auditd_search", uid: "1000" });
      expect(result.isError).toBeUndefined();
      expect(vi.mocked(executeCommand)).toHaveBeenCalledWith(
        expect.objectContaining({
          args: expect.arrayContaining(["-ui", "1000"]),
        }),
      );
    });

    it("should run ausearch with start/end time filters", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk, stdout: "audit\n" });
      const handler = tools.get("log_management")!.handler;
      const result = await handler({
        action: "auditd_search",
        key: "identity",
        start: "today",
        end: "now",
      });
      expect(result.isError).toBeUndefined();
      expect(vi.mocked(executeCommand)).toHaveBeenCalledWith(
        expect.objectContaining({
          args: expect.arrayContaining(["--start", "today", "--end", "now"]),
        }),
      );
    });

    it("should run ausearch with success filter", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk, stdout: "audit\n" });
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "auditd_search", key: "identity", success: "yes" });
      expect(result.isError).toBeUndefined();
      expect(vi.mocked(executeCommand)).toHaveBeenCalledWith(
        expect.objectContaining({
          args: expect.arrayContaining(["--success", "yes"]),
        }),
      );
    });

    it("should handle no matches from ausearch", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValue({
        ...cmdOk,
        exitCode: 1,
        stderr: "no matches",
        stdout: "",
      });
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "auditd_search", key: "nonexistent" });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("No matching audit records");
    });

    it("should return error on ausearch failure", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValue({
        ...cmdOk,
        exitCode: 2,
        stderr: "ausearch error: permission denied",
      });
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "auditd_search", key: "identity" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("ausearch failed");
    });

    it("should catch thrown errors in auditd_search", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockRejectedValue(new Error("connection lost"));
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "auditd_search", key: "identity" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("connection lost");
    });
  });

  // ── auditd_report ─────────────────────────────────────────────────────

  describe("auditd_report", () => {
    it("should run aureport with default summary type", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValue({
        ...cmdOk,
        stdout: "Summary Report\n=====\nEvents: 100\n",
      });
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "auditd_report" });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("Audit Report");
      expect(vi.mocked(executeCommand)).toHaveBeenCalledWith(
        expect.objectContaining({
          command: "sudo",
          args: expect.arrayContaining(["aureport", "--summary"]),
        }),
      );
    });

    it("should run aureport with auth report type", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValue({
        ...cmdOk,
        stdout: "Authentication Report\n",
      });
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "auditd_report", report_type: "auth" });
      expect(result.isError).toBeUndefined();
      expect(vi.mocked(executeCommand)).toHaveBeenCalledWith(
        expect.objectContaining({
          args: expect.arrayContaining(["aureport", "--auth"]),
        }),
      );
    });

    it("should run aureport with start time filter", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk, stdout: "report\n" });
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "auditd_report", start: "today" });
      expect(result.isError).toBeUndefined();
      expect(vi.mocked(executeCommand)).toHaveBeenCalledWith(
        expect.objectContaining({
          args: expect.arrayContaining(["--start", "today"]),
        }),
      );
    });

    it("should return error on aureport failure", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValue({
        ...cmdOk,
        exitCode: 1,
        stderr: "aureport: no audit logs",
      });
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "auditd_report" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("aureport failed");
    });

    it("should catch thrown errors in auditd_report", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockRejectedValue(new Error("audit daemon down"));
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "auditd_report" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("audit daemon down");
    });
  });

  // ── auditd_cis_rules ──────────────────────────────────────────────────

  describe("auditd_cis_rules", () => {
    it("should check CIS rules and report compliance", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValue({
        ...cmdOk,
        stdout: "-w /etc/passwd -p wa -k identity\n-w /etc/shadow -p wa -k identity\n",
      });
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "auditd_cis_rules", cis_action: "check" });
      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.summary).toBeDefined();
      expect(parsed.summary.totalRequired).toBeGreaterThan(0);
      expect(parsed.results).toBeInstanceOf(Array);
    });

    it("should generate CIS rules text", async () => {
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "auditd_cis_rules", cis_action: "generate" });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("CIS Benchmark");
      expect(result.content[0].text).toContain("-w /etc/passwd");
      expect(result.content[0].text).toContain("-e 2");
    });

    it("should catch errors in auditd_cis_rules", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockRejectedValue(new Error("auditctl not found"));
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "auditd_cis_rules", cis_action: "check" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("auditctl not found");
    });
  });

  // ── journalctl_query ──────────────────────────────────────────────────

  describe("journalctl_query", () => {
    it("should run journalctl with default options", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValue({
        ...cmdOk,
        stdout: "Apr 01 12:00:00 host sshd[1234]: Accepted publickey\n",
      });
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "journalctl_query" });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("Accepted publickey");
      expect(vi.mocked(executeCommand)).toHaveBeenCalledWith(
        expect.objectContaining({
          command: "journalctl",
          args: expect.arrayContaining(["-n", "100", "-o", "short", "--no-pager"]),
        }),
      );
    });

    it("should run journalctl with unit filter", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk, stdout: "sshd logs\n" });
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "journalctl_query", unit: "sshd" });
      expect(result.isError).toBeUndefined();
      expect(vi.mocked(executeCommand)).toHaveBeenCalledWith(
        expect.objectContaining({
          args: expect.arrayContaining(["--unit", "sshd"]),
        }),
      );
    });

    it("should run journalctl with priority filter", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk, stdout: "error logs\n" });
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "journalctl_query", priority: "err" });
      expect(result.isError).toBeUndefined();
      expect(vi.mocked(executeCommand)).toHaveBeenCalledWith(
        expect.objectContaining({
          args: expect.arrayContaining(["-p", "err"]),
        }),
      );
    });

    it("should run journalctl with since/until/grep filters", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk, stdout: "filtered logs\n" });
      const handler = tools.get("log_management")!.handler;
      const result = await handler({
        action: "journalctl_query",
        since: "1 hour ago",
        until: "now",
        grep: "error",
      });
      expect(result.isError).toBeUndefined();
      expect(vi.mocked(executeCommand)).toHaveBeenCalledWith(
        expect.objectContaining({
          args: expect.arrayContaining(["--since", "1 hour ago", "--until", "now", "-g", "error"]),
        }),
      );
    });

    it("should return error on journalctl failure", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValue({
        ...cmdOk,
        exitCode: 1,
        stderr: "Failed to get journal: Access denied",
      });
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "journalctl_query" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("journalctl query failed");
    });

    it("should catch thrown errors in journalctl_query", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockRejectedValue(new Error("systemd unavailable"));
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "journalctl_query" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("systemd unavailable");
    });
  });

  // ── fail2ban_status ───────────────────────────────────────────────────

  describe("fail2ban_status", () => {
    it("should run fail2ban-client status without jail", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValue({
        ...cmdOk,
        stdout: "Status\n|- Number of jail: 1\n`- Jail list: sshd\n",
      });
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "fail2ban_status" });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("Jail list");
    });

    it("should run fail2ban-client status with specific jail", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValue({
        ...cmdOk,
        stdout: "Status for the jail: sshd\n|- Filter\n`- Actions\n",
      });
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "fail2ban_status", jail: "sshd" });
      expect(result.isError).toBeUndefined();
      expect(vi.mocked(executeCommand)).toHaveBeenCalledWith(
        expect.objectContaining({
          args: expect.arrayContaining(["fail2ban-client", "status", "sshd"]),
        }),
      );
    });

    it("should return error on fail2ban-client status failure", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValue({
        ...cmdOk,
        exitCode: 255,
        stderr: "ERROR Failed to access socket path",
      });
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "fail2ban_status" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("fail2ban status failed");
    });

    it("should catch thrown errors in fail2ban_status", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockRejectedValue(new Error("socket error"));
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "fail2ban_status" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("socket error");
    });
  });

  // ── fail2ban_unban ────────────────────────────────────────────────────

  describe("fail2ban_unban", () => {
    it("should require jail for fail2ban_unban", async () => {
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "fail2ban_unban" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Jail name is required");
    });

    it("should require ip for fail2ban_unban", async () => {
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "fail2ban_unban", jail: "sshd" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("IP address is required");
    });

    it("should preview fail2ban_unban in dry_run mode", async () => {
      const handler = tools.get("log_management")!.handler;
      const result = await handler({
        action: "fail2ban_unban",
        jail: "sshd",
        ip: "10.0.0.5",
        dry_run: true,
      });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("DRY-RUN");
      expect(result.content[0].text).toContain("unbanip");
    });

    it("should execute fail2ban_unban when not dry_run", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const { getConfig } = await import("../../src/core/config.js");
      vi.mocked(getConfig).mockReturnValue({ dryRun: false } as ReturnType<typeof getConfig>);
      vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk, stdout: "1" });
      const handler = tools.get("log_management")!.handler;
      const result = await handler({
        action: "fail2ban_unban",
        jail: "sshd",
        ip: "10.0.0.5",
        dry_run: false,
      });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("unbanned");
      expect(vi.mocked(executeCommand)).toHaveBeenCalledWith(
        expect.objectContaining({
          args: expect.arrayContaining(["fail2ban-client", "set", "sshd", "unbanip", "10.0.0.5"]),
        }),
      );
    });

    it("should return error when fail2ban_unban command fails", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const { getConfig } = await import("../../src/core/config.js");
      vi.mocked(getConfig).mockReturnValue({ dryRun: false } as ReturnType<typeof getConfig>);
      vi.mocked(executeCommand).mockResolvedValue({
        ...cmdOk,
        exitCode: 1,
        stderr: "IP not found in jail",
      });
      const handler = tools.get("log_management")!.handler;
      const result = await handler({
        action: "fail2ban_unban",
        jail: "sshd",
        ip: "10.0.0.5",
        dry_run: false,
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("fail2ban unban failed");
    });
  });

  // ── fail2ban_reload ───────────────────────────────────────────────────

  describe("fail2ban_reload", () => {
    it("should preview fail2ban_reload in dry_run mode", async () => {
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "fail2ban_reload", dry_run: true });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("DRY-RUN");
      expect(result.content[0].text).toContain("fail2ban-client reload");
    });

    it("should execute fail2ban_reload when not dry_run", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const { getConfig } = await import("../../src/core/config.js");
      vi.mocked(getConfig).mockReturnValue({ dryRun: false } as ReturnType<typeof getConfig>);
      vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk });
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "fail2ban_reload", dry_run: false });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("reloaded successfully");
    });

    it("should return error when fail2ban_reload command fails", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const { getConfig } = await import("../../src/core/config.js");
      vi.mocked(getConfig).mockReturnValue({ dryRun: false } as ReturnType<typeof getConfig>);
      vi.mocked(executeCommand).mockResolvedValue({
        ...cmdOk,
        exitCode: 1,
        stderr: "ERROR  Failed to access socket path",
      });
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "fail2ban_reload", dry_run: false });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("fail2ban reload failed");
    });

    it("should catch thrown errors in fail2ban_reload", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const { getConfig } = await import("../../src/core/config.js");
      vi.mocked(getConfig).mockReturnValue({ dryRun: false } as ReturnType<typeof getConfig>);
      vi.mocked(executeCommand).mockRejectedValue(new Error("daemon crashed"));
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "fail2ban_reload", dry_run: false });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("daemon crashed");
    });
  });

  // ── fail2ban_audit ────────────────────────────────────────────────────

  describe("fail2ban_audit", () => {
    it("should report fail2ban not installed when status fails", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValue({
        ...cmdOk,
        exitCode: 1,
        stderr: "fail2ban-client: command not found",
      });
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "fail2ban_audit" });
      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.installed).toBe(false);
    });

    it("should audit fail2ban jails and settings", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand)
        .mockResolvedValueOnce({
          ...cmdOk,
          stdout: "Status\n|- Number of jail: 1\n`- Jail list:\tsshd\n",
        })
        .mockResolvedValueOnce({ ...cmdOk, stdout: "600\n" })
        .mockResolvedValueOnce({ ...cmdOk, stdout: "5\n" })
        .mockResolvedValueOnce({ ...cmdOk, stdout: "600\n" });
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "fail2ban_audit" });
      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.installed).toBe(true);
      expect(parsed.activeJails).toBe(1);
      expect(parsed.jails).toContain("sshd");
      expect(parsed.findings.length).toBe(3);
    });

    it("should flag low bantime as WARN", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand)
        .mockResolvedValueOnce({
          ...cmdOk,
          stdout: "Status\n|- Number of jail: 1\n`- Jail list:\tsshd\n",
        })
        .mockResolvedValueOnce({ ...cmdOk, stdout: "60\n" })
        .mockResolvedValueOnce({ ...cmdOk, stdout: "3\n" })
        .mockResolvedValueOnce({ ...cmdOk, stdout: "300\n" });
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "fail2ban_audit" });
      const parsed = JSON.parse(result.content[0].text);
      const bantimeFinding = parsed.findings.find((f: { setting: string }) => f.setting === "bantime");
      expect(bantimeFinding.status).toBe("WARN");
    });

    it("should report missing recommended jails", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand)
        .mockResolvedValueOnce({
          ...cmdOk,
          stdout: "Status\n|- Number of jail: 1\n`- Jail list:\tsshd\n",
        })
        .mockResolvedValueOnce({ ...cmdOk, stdout: "600\n" })
        .mockResolvedValueOnce({ ...cmdOk, stdout: "5\n" })
        .mockResolvedValueOnce({ ...cmdOk, stdout: "600\n" });
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "fail2ban_audit" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.missingRecommended).toContain("apache-auth");
      expect(parsed.missingRecommended).toContain("nginx-http-auth");
    });

    it("should catch thrown errors in fail2ban_audit", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockRejectedValue(new Error("unexpected error"));
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "fail2ban_audit" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("unexpected error");
    });
  });

  // ── SIEM helper: create a mock child process for spawnSafe ──────────

  function createSiemCP(stdout: string, stderr: string, exitCode: number) {
    const cp = new EventEmitter() as EventEmitter & { stdout: EventEmitter; stderr: EventEmitter; kill: ReturnType<typeof vi.fn> };
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

  // ── siem_syslog_forward ───────────────────────────────────────────────

  describe("siem_syslog_forward", () => {
    it("should return syslog forwarding status with rsyslog detected", async () => {
      const { spawnSafe } = await import("../../src/core/spawn-safe.js");
      const responses = [
        { stdout: "ii  rsyslog  8.2102.0-2  amd64  reliable syslog\n", stderr: "", exitCode: 0 },
        { stdout: "", stderr: "", exitCode: 1 },
        { stdout: "*.* @@siem.example.com:514\n", stderr: "", exitCode: 0 },
        { stdout: "", stderr: "", exitCode: 1 },
        { stdout: "", stderr: "", exitCode: 1 },
      ];
      let callIdx = 0;
      vi.mocked(spawnSafe).mockImplementation(() => {
        const r = responses[callIdx] ?? { stdout: "", stderr: "", exitCode: 1 };
        callIdx++;
        return createSiemCP(r.stdout, r.stderr, r.exitCode) as any;
      });

      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "siem_syslog_forward" });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("Syslog Daemon: rsyslog");
    });

    it("should report no daemon found when neither rsyslog nor syslog-ng installed", async () => {
      const { spawnSafe } = await import("../../src/core/spawn-safe.js");
      vi.mocked(spawnSafe).mockImplementation(() => createSiemCP("", "", 1) as any);

      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "siem_syslog_forward" });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("Daemon Installed: no");
    });

    it("should handle spawnSafe errors gracefully in siem_syslog_forward", async () => {
      const { spawnSafe } = await import("../../src/core/spawn-safe.js");
      vi.mocked(spawnSafe).mockImplementation(() => { throw new Error("spawn failed"); });
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "siem_syslog_forward" });
      // runCommand catches spawn errors internally
      expect(result.isError).toBeUndefined();
    });
  });

  // ── siem_filebeat ─────────────────────────────────────────────────────

  describe("siem_filebeat", () => {
    it("should report filebeat not installed", async () => {
      const { spawnSafe } = await import("../../src/core/spawn-safe.js");
      vi.mocked(spawnSafe).mockImplementation(() => createSiemCP("", "", 1) as any);

      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "siem_filebeat" });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("not installed");
    });

    it("should report filebeat installed and running", async () => {
      const { spawnSafe } = await import("../../src/core/spawn-safe.js");
      const responses = [
        { stdout: "/usr/bin/filebeat", stderr: "", exitCode: 0 },
        { stdout: "filebeat version 8.12.0", stderr: "", exitCode: 0 },
        { stdout: "output.logstash:\n  hosts: [\"siem:5044\"]", stderr: "", exitCode: 0 },
        { stdout: "Enabled:\nsystem\nDisabled:\napache\nnginx", stderr: "", exitCode: 0 },
        { stdout: "active (running)", stderr: "", exitCode: 0 },
      ];
      let callIdx = 0;
      vi.mocked(spawnSafe).mockImplementation(() => {
        const r = responses[callIdx] ?? { stdout: "", stderr: "", exitCode: 1 };
        callIdx++;
        return createSiemCP(r.stdout, r.stderr, r.exitCode) as any;
      });

      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "siem_filebeat" });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("Installed: yes");
      expect(result.content[0].text).toContain("filebeat version 8.12.0");
    });
  });

  // ── siem_audit_forwarding ─────────────────────────────────────────────

  describe("siem_audit_forwarding", () => {
    it("should audit forwarding and report non-compliance when nothing forwarded", async () => {
      const { spawnSafe } = await import("../../src/core/spawn-safe.js");
      const responses = [
        { stdout: "# no forwarding rules\n", stderr: "", exitCode: 0 },
        { stdout: "inactive (dead)", stderr: "", exitCode: 3 },
        { stdout: "sharedscripts\npostrotate\n", stderr: "", exitCode: 0 },
      ];
      let callIdx = 0;
      vi.mocked(spawnSafe).mockImplementation(() => {
        const r = responses[callIdx] ?? { stdout: "", stderr: "", exitCode: 1 };
        callIdx++;
        return createSiemCP(r.stdout, r.stderr, r.exitCode) as any;
      });

      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "siem_audit_forwarding" });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("CIS Compliant");
    });
  });

  // ── siem_test_connectivity ────────────────────────────────────────────

  describe("siem_test_connectivity", () => {
    it("should require siem_host parameter", async () => {
      const handler = tools.get("log_management")!.handler;
      const result = await handler({ action: "siem_test_connectivity" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("siem_host");
    });

    it("should reject invalid siem_host format", async () => {
      const handler = tools.get("log_management")!.handler;
      const result = await handler({
        action: "siem_test_connectivity",
        siem_host: "!invalid host!",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Invalid siem_host");
    });

    it("should test connectivity to valid SIEM host", async () => {
      const { spawnSafe } = await import("../../src/core/spawn-safe.js");
      const responses = [
        { stdout: ";; ANSWER SECTION:\nsiem.example.com. 300 IN A 10.0.0.1\n", stderr: "", exitCode: 0 },
        { stdout: "", stderr: "", exitCode: 0 },
        { stdout: "Chain INPUT\n", stderr: "", exitCode: 0 },
        { stdout: "", stderr: "", exitCode: 0 },
      ];
      let callIdx = 0;
      vi.mocked(spawnSafe).mockImplementation(() => {
        const r = responses[callIdx] ?? { stdout: "", stderr: "", exitCode: 1 };
        callIdx++;
        return createSiemCP(r.stdout, r.stderr, r.exitCode) as any;
      });

      const handler = tools.get("log_management")!.handler;
      const result = await handler({
        action: "siem_test_connectivity",
        siem_host: "siem.example.com",
        siem_port: 514,
      });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("siem.example.com");
      expect(result.content[0].text).toContain("DNS Resolution");
    });

    it("should handle DNS failure gracefully", async () => {
      const { spawnSafe } = await import("../../src/core/spawn-safe.js");
      const responses = [
        { stdout: "", stderr: "dig: command not found", exitCode: 127 },
        { stdout: "", stderr: "nc: connect failed", exitCode: 1 },
        { stdout: "", stderr: "iptables: Permission denied", exitCode: 1 },
        { stdout: "", stderr: "logger: not found", exitCode: 1 },
      ];
      let callIdx = 0;
      vi.mocked(spawnSafe).mockImplementation(() => {
        const r = responses[callIdx] ?? { stdout: "", stderr: "", exitCode: 1 };
        callIdx++;
        return createSiemCP(r.stdout, r.stderr, r.exitCode) as any;
      });

      const handler = tools.get("log_management")!.handler;
      const result = await handler({
        action: "siem_test_connectivity",
        siem_host: "10.0.0.1",
      });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("Connectivity Test");
    });
  });

  // ── unknown action ────────────────────────────────────────────────────

  it("should return error for unknown action", async () => {
    const handler = tools.get("log_management")!.handler;
    const result = await handler({ action: "nonexistent_action" as any });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Unknown action");
  });
});
