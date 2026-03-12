/**
 * Tests for src/tools/reporting.ts
 *
 * reporting.ts is now a re-export stub (registerReportingTools → registerMetaTools).
 * The registered tool is defense_mgmt with actions:
 *   report_generate, report_list, report_formats
 *
 * Tests input validation, error handling, and output format correctness.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Mock all external dependencies ─────────────────────────────────────────

vi.mock("../../src/core/executor.js", () => ({
  executeCommand: vi.fn().mockResolvedValue({ exitCode: 0, stdout: "", stderr: "" }),
}));
vi.mock("../../src/core/command-allowlist.js", () => ({
  resolveCommand: vi.fn((cmd: string) => `/usr/bin/${cmd}`),
  isAllowlisted: vi.fn().mockReturnValue(true),
}));
vi.mock("../../src/core/config.js", () => ({
  getConfig: vi.fn().mockReturnValue({ dryRun: true }),
  getToolTimeout: vi.fn().mockReturnValue(30000),
}));
vi.mock("../../src/core/spawn-safe.js", () => ({
  spawnSafe: vi.fn(),
}));

vi.mock("../../src/core/secure-fs.js", () => ({
  secureWriteFileSync: vi.fn(),
}));

vi.mock("../../src/core/parsers.js", () => ({
  createTextContent: vi.fn((text: string) => ({ type: "text", text })),
  createErrorContent: vi.fn((text: string) => ({ type: "text", text: `Error: ${text}` })),
  formatToolOutput: vi.fn((obj: unknown) => ({ type: "text", text: JSON.stringify(obj) })),
}));

vi.mock("../../src/core/changelog.js", () => ({
  logChange: vi.fn(),
  createChangeEntry: vi.fn().mockReturnValue({}),
  getChangelog: vi.fn().mockReturnValue([]),
}));

vi.mock("../../src/core/installer.js", () => ({
  checkAllTools: vi.fn().mockResolvedValue([]),
  installMissing: vi.fn().mockResolvedValue([]),
}));

vi.mock("../../src/core/safeguards.js", () => ({
  SafeguardRegistry: {
    getInstance: vi.fn().mockReturnValue({
      checkSafety: vi.fn().mockResolvedValue({ safe: true, warnings: [], blockers: [], impactedApps: [] }),
    }),
  },
}));

vi.mock("node:fs", () => ({
  existsSync: vi.fn().mockReturnValue(false),
  readdirSync: vi.fn().mockReturnValue([]),
  statSync: vi.fn().mockReturnValue({
    size: 1024,
    mtime: new Date("2025-01-01T00:00:00Z"),
  }),
  readFileSync: vi.fn().mockReturnValue("[]"),
  writeFileSync: vi.fn(),
  mkdirSync: vi.fn(),
}));

vi.mock("node:os", () => ({
  homedir: vi.fn().mockReturnValue("/tmp/test-home"),
}));

vi.mock("node:path", async () => {
  const actual = await vi.importActual("node:path");
  return actual;
});

import { registerReportingTools } from "../../src/tools/reporting.js";
import { spawnSafe } from "../../src/core/spawn-safe.js";
import { secureWriteFileSync } from "../../src/core/secure-fs.js";
import { existsSync, readdirSync } from "node:fs";
import { EventEmitter } from "node:events";

const mockSpawnSafe = vi.mocked(spawnSafe);
const mockSecureWriteFileSync = vi.mocked(secureWriteFileSync);

// ── Helpers ────────────────────────────────────────────────────────────────

type ToolHandler = (
  params: Record<string, unknown>,
) => Promise<{
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}>;

function createMockServer() {
  const tools = new Map<
    string,
    { schema: Record<string, unknown>; handler: ToolHandler }
  >();
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
  return {
    server: server as unknown as Parameters<typeof registerReportingTools>[0],
    tools,
  };
}

/**
 * Create a mock ChildProcess that emits provided stdout/stderr and close code.
 */
function createMockChildProcess(
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

  // Emit data on next tick so listeners can be set up
  process.nextTick(() => {
    if (stdout) cp.stdout.emit("data", Buffer.from(stdout));
    if (stderr) cp.stderr.emit("data", Buffer.from(stderr));
    cp.emit("close", exitCode);
  });

  return cp;
}

/**
 * Set up mockSpawnSafe to return mock ChildProcess for each command pattern.
 */
function setupDefaultSpawnMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    const fullCmd = `${command} ${args.join(" ")}`;

    // uname -a
    if (command === "uname" || (command === "sudo" && args.includes("uname"))) {
      return createMockChildProcess(
        "Linux testhost 6.1.0-kali9-amd64 #1 SMP x86_64 GNU/Linux",
        "",
        0,
      ) as any;
    }

    // hostname
    if (command === "hostname") {
      return createMockChildProcess("testhost", "", 0) as any;
    }

    // uptime
    if (command === "uptime") {
      return createMockChildProcess(
        " 10:30:00 up 5 days, 3:45, 2 users, load average: 0.15, 0.10, 0.05",
        "",
        0,
      ) as any;
    }

    // iptables
    if (fullCmd.includes("iptables")) {
      return createMockChildProcess(
        "Chain INPUT (policy ACCEPT)\nnum  target  prot opt source  destination\n1  DROP  tcp  --  0.0.0.0/0  0.0.0.0/0  tcp dpt:23",
        "",
        0,
      ) as any;
    }

    // systemctl list-units
    if (fullCmd.includes("list-units")) {
      return createMockChildProcess(
        "ssh.service loaded active running OpenSSH server\ncron.service loaded active running Regular background program processing daemon",
        "",
        0,
      ) as any;
    }

    // ss -tulnp
    if (fullCmd.includes("-tulnp")) {
      return createMockChildProcess(
        "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*",
        "",
        0,
      ) as any;
    }

    // journalctl
    if (command === "journalctl" || fullCmd.includes("journalctl")) {
      return createMockChildProcess(
        "Jan 01 10:00:00 testhost sshd[1234]: Accepted publickey for user1",
        "",
        0,
      ) as any;
    }

    // grep (for auth.log fallback)
    if (fullCmd.includes("grep") && fullCmd.includes("auth.log")) {
      return createMockChildProcess("", "", 1) as any;
    }

    // lynis
    if (fullCmd.includes("lynis")) {
      return createMockChildProcess(
        "Lynis audit system\nHardening index : 72\nWarning: test warning\nSuggestion: test suggestion",
        "",
        0,
      ) as any;
    }

    // aide
    if (fullCmd.includes("aide")) {
      return createMockChildProcess("", "", -1) as any;
    }

    // fail2ban-client
    if (fullCmd.includes("fail2ban")) {
      return createMockChildProcess("", "", -1) as any;
    }

    // Default: return success with empty output
    return createMockChildProcess("", "", 0) as any;
  });
}

// ── Tests ──────────────────────────────────────────────────────────────────

describe("reporting tools", () => {
  let tools: Map<
    string,
    { schema: Record<string, unknown>; handler: ToolHandler }
  >;

  beforeEach(() => {
    vi.clearAllMocks();
    const mock = createMockServer();
    registerReportingTools(mock.server);
    tools = mock.tools;
    setupDefaultSpawnMocks();
  });

  // ── Registration ────────────────────────────────────────────────────────

  it("should register the defense_mgmt tool (via re-export stub)", () => {
    expect(tools.has("defense_mgmt")).toBe(true);
  });

  it("should register with server.tool called once", () => {
    const mock = createMockServer();
    registerReportingTools(mock.server);
    expect(mock.server.tool).toHaveBeenCalledTimes(1);
    expect(mock.server.tool).toHaveBeenCalledWith(
      "defense_mgmt",
      expect.any(String),
      expect.any(Object),
      expect.any(Function),
    );
  });

  // ── report_formats action ────────────────────────────────────────────────

  it("should return supported formats for report_formats action", async () => {
    const handler = tools.get("defense_mgmt")!.handler;
    const result = await handler({ action: "report_formats" });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("markdown");
    expect(result.content[0].text).toContain("html");
    expect(result.content[0].text).toContain("json");
    expect(result.content[0].text).toContain("csv");
  });

  it("should return report types in report_formats action", async () => {
    const handler = tools.get("defense_mgmt")!.handler;
    const result = await handler({ action: "report_formats" });
    expect(result.content[0].text).toContain("executive_summary");
    expect(result.content[0].text).toContain("technical_detail");
    expect(result.content[0].text).toContain("compliance_evidence");
    expect(result.content[0].text).toContain("vulnerability_report");
    expect(result.content[0].text).toContain("hardening_status");
  });

  it("should return available sections in report_formats action", async () => {
    const handler = tools.get("defense_mgmt")!.handler;
    const result = await handler({ action: "report_formats" });
    expect(result.content[0].text).toContain("system_overview");
    expect(result.content[0].text).toContain("firewall_status");
    expect(result.content[0].text).toContain("recommendations");
  });

  // ── report_list action ───────────────────────────────────────────────────

  it("should handle report_list when directory does not exist", async () => {
    vi.mocked(existsSync).mockReturnValue(false);
    const handler = tools.get("defense_mgmt")!.handler;
    const result = await handler({ action: "report_list" });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("does not exist");
  });

  it("should list reports when directory exists", async () => {
    vi.mocked(existsSync).mockReturnValue(true);
    vi.mocked(readdirSync).mockReturnValue([
      "report-2025-01-01.md" as unknown as ReturnType<typeof readdirSync>[0],
      "report-2025-01-02.json" as unknown as ReturnType<typeof readdirSync>[0],
      "random.txt" as unknown as ReturnType<typeof readdirSync>[0],
    ]);

    const handler = tools.get("defense_mgmt")!.handler;
    const result = await handler({ action: "report_list" });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("report-2025-01-01.md");
    expect(result.content[0].text).toContain("report-2025-01-02.json");
    expect(result.content[0].text).not.toContain("random.txt");
  });

  it("should show totalReports count", async () => {
    vi.mocked(existsSync).mockReturnValue(true);
    vi.mocked(readdirSync).mockReturnValue([
      "report-a.md" as unknown as ReturnType<typeof readdirSync>[0],
      "report-b.html" as unknown as ReturnType<typeof readdirSync>[0],
      "report-c.csv" as unknown as ReturnType<typeof readdirSync>[0],
    ]);

    const handler = tools.get("defense_mgmt")!.handler;
    const result = await handler({ action: "report_list" });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.totalReports).toBe(3);
  });

  // ── report_generate action — markdown format ─────────────────────────────

  it("should generate a markdown report with all sections", async () => {
    const handler = tools.get("defense_mgmt")!.handler;
    const result = await handler({
      action: "report_generate",
      format: "markdown",
      report_type: "technical_detail",
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("# Security Report");
    expect(result.content[0].text).toContain("System Overview");
    expect(result.content[0].text).toContain("Firewall Status");
    expect(result.content[0].text).toContain("Recommendations");
  });

  it("should include system info in markdown report", async () => {
    const handler = tools.get("defense_mgmt")!.handler;
    const result = await handler({
      action: "report_generate",
      format: "markdown",
    });
    expect(result.content[0].text).toContain("Linux testhost");
  });

  // ── report_generate action — html format ────────────────────────────────

  it("should generate an HTML report", async () => {
    const handler = tools.get("defense_mgmt")!.handler;
    const result = await handler({
      action: "report_generate",
      format: "html",
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("<!DOCTYPE html>");
    expect(result.content[0].text).toContain("<h1>");
    expect(result.content[0].text).toContain("</html>");
  });

  // ── report_generate action — json format ────────────────────────────────

  it("should generate a JSON report", async () => {
    const handler = tools.get("defense_mgmt")!.handler;
    const result = await handler({
      action: "report_generate",
      format: "json",
    });
    expect(result.isError).toBeUndefined();
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.reportType).toBe("technical_detail");
    expect(parsed.format).toBe("json");
    expect(parsed.report).toBeDefined();
    expect(parsed.report.sections).toBeInstanceOf(Array);
  });

  // ── report_generate action — csv format ─────────────────────────────────

  it("should generate a CSV report", async () => {
    const handler = tools.get("defense_mgmt")!.handler;
    const result = await handler({
      action: "report_generate",
      format: "csv",
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("Section,Status,Summary");
    expect(result.content[0].text).toContain("System Overview");
  });

  // ── report_generate with include_sections filter ─────────────────────────

  it("should only include specified sections", async () => {
    const handler = tools.get("defense_mgmt")!.handler;
    const result = await handler({
      action: "report_generate",
      format: "markdown",
      include_sections: ["system_overview", "firewall_status"],
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("System Overview");
    expect(result.content[0].text).toContain("Firewall Status");
    expect(result.content[0].text).not.toContain("Service Audit");
    expect(result.content[0].text).not.toContain("Active Connections");
  });

  // ── report_generate with output_path (file write) ───────────────────────

  it("should write report to file when output_path is provided", async () => {
    const handler = tools.get("defense_mgmt")!.handler;
    const result = await handler({
      action: "report_generate",
      format: "markdown",
      output_path: "/tmp/test-report.md",
    });
    expect(result.isError).toBeUndefined();
    expect(mockSecureWriteFileSync).toHaveBeenCalledWith(
      "/tmp/test-report.md",
      expect.any(String),
      "utf-8",
    );
  });

  it("should handle file write errors gracefully", async () => {
    mockSecureWriteFileSync.mockImplementation(() => {
      throw new Error("Permission denied");
    });

    const handler = tools.get("defense_mgmt")!.handler;
    const result = await handler({
      action: "report_generate",
      format: "markdown",
      output_path: "/root/protected-report.md",
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Permission denied");
  });

  // ── report_generate with since parameter ────────────────────────────────

  it("should pass since parameter to login gathering", async () => {
    const handler = tools.get("defense_mgmt")!.handler;
    const result = await handler({
      action: "report_generate",
      format: "markdown",
      since: "2025-01-01",
      include_sections: ["recent_logins"],
    });
    expect(result.isError).toBeUndefined();
    expect(mockSpawnSafe).toHaveBeenCalledWith(
      "journalctl",
      expect.arrayContaining(["--since", "2025-01-01"]),
    );
  });

  // ── Error handling ───────────────────────────────────────────────────────

  it("should handle command failures gracefully within sections", async () => {
    mockSpawnSafe.mockImplementation((_command: string, _args: string[]) => {
      return createMockChildProcess("", "command not found", 127) as any;
    });

    const handler = tools.get("defense_mgmt")!.handler;
    const result = await handler({
      action: "report_generate",
      format: "markdown",
      include_sections: ["system_overview", "firewall_status"],
    });
    expect(result.isError).toBeUndefined();
    expect(result.content).toBeDefined();
  });

  it("should handle spawnSafe throwing for report_generate", async () => {
    mockSpawnSafe.mockImplementation((_command?: string, _args?: string[]) => {
      throw new Error("Binary not in allowlist");
    });

    const handler = tools.get("defense_mgmt")!.handler;
    const result = await handler({
      action: "report_generate",
      format: "json",
      include_sections: ["system_overview"],
    });
    expect(result.isError).toBeUndefined();
  });

  // ── Report type variations ───────────────────────────────────────────────

  it("should accept executive_summary report type", async () => {
    const handler = tools.get("defense_mgmt")!.handler;
    const result = await handler({
      action: "report_generate",
      format: "markdown",
      report_type: "executive_summary",
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("Executive Summary");
  });

  it("should accept hardening_status report type", async () => {
    const handler = tools.get("defense_mgmt")!.handler;
    const result = await handler({
      action: "report_generate",
      format: "json",
      report_type: "hardening_status",
    });
    expect(result.isError).toBeUndefined();
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.reportType).toBe("hardening_status");
  });

  // ── Recommendations generation ───────────────────────────────────────────

  it("should generate recommendations based on gathered data", async () => {
    const handler = tools.get("defense_mgmt")!.handler;
    const result = await handler({
      action: "report_generate",
      format: "markdown",
      include_sections: ["firewall_status", "service_audit", "recommendations"],
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("Recommendations");
  });

  it("should recommend firewall review when only ACCEPT rules found", async () => {
    mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
      const fullCmd = `${command} ${args.join(" ")}`;
      if (fullCmd.includes("iptables")) {
        return createMockChildProcess(
          "Chain INPUT (policy ACCEPT)\nnum target prot\n1 ACCEPT tcp",
          "",
          0,
        ) as any;
      }
      return createMockChildProcess("", "", 0) as any;
    });

    const handler = tools.get("defense_mgmt")!.handler;
    const result = await handler({
      action: "report_generate",
      format: "markdown",
      include_sections: ["firewall_status", "recommendations"],
    });
    expect(result.content[0].text).toContain("DROP policy");
  });

  // ── Summary metadata ─────────────────────────────────────────────────────

  it("should include summary metadata for non-json formats", async () => {
    const handler = tools.get("defense_mgmt")!.handler;
    const result = await handler({
      action: "report_generate",
      format: "markdown",
    });
    expect(result.content.length).toBeGreaterThanOrEqual(2);
    const summary = JSON.parse(result.content[1].text);
    expect(summary.reportType).toBe("technical_detail");
    expect(summary.format).toBe("markdown");
    expect(summary.timestamp).toBeDefined();
    expect(summary.sectionsIncluded).toBeInstanceOf(Array);
  });
});
