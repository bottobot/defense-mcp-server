/**
 * Tests for src/tools/logging.ts SIEM actions (via re-export from siem-integration.ts)
 *
 * Covers: log_management tool with SIEM actions siem_syslog_forward,
 * siem_filebeat, siem_audit_forwarding, siem_test_connectivity.
 * Tests rsyslog vs syslog-ng detection, forwarding rule parsing,
 * Filebeat config parsing, forwarding audit completeness,
 * connectivity checks (success, failure, TLS), JSON/text output,
 * and error handling.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Mock all external dependencies ─────────────────────────────────────────

vi.mock("../../src/core/spawn-safe.js", () => ({
  spawnSafe: vi.fn(),
}));

vi.mock("../../src/core/parsers.js", () => ({
  createTextContent: vi.fn((text: string) => ({ type: "text", text })),
  createErrorContent: vi.fn((text: string) => ({ type: "text", text: `Error: ${text}` })),
  formatToolOutput: vi.fn((obj: unknown) => ({ type: "text", text: JSON.stringify(obj) })),
}));

vi.mock("../../src/core/executor.js", () => ({
  executeCommand: vi.fn().mockResolvedValue({ exitCode: 0, stdout: "", stderr: "", timedOut: false, duration: 10, permissionDenied: false }),
}));

vi.mock("../../src/core/config.js", () => ({
  getConfig: vi.fn().mockReturnValue({ dryRun: false }),
  getToolTimeout: vi.fn().mockReturnValue(30000),
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
  validateToolPath: vi.fn((p: string) => p),
}));

vi.mock("../../src/core/distro-adapter.js", () => ({
  getDistroAdapter: vi.fn().mockResolvedValue({
    paths: { syslog: "/var/log/syslog" },
  }),
}));

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return { ...actual, existsSync: vi.fn().mockReturnValue(true) };
});

import {
  registerSiemIntegrationTools,
  validateSiemHost,
} from "../../src/tools/siem-integration.js";
import { spawnSafe } from "../../src/core/spawn-safe.js";
import { EventEmitter } from "node:events";
import type { ChildProcess } from "node:child_process";

const mockSpawnSafe = vi.mocked(spawnSafe);

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
    server: server as unknown as Parameters<typeof registerSiemIntegrationTools>[0],
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
): ChildProcess {
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

  return cp as unknown as ChildProcess;
}

// ── Mock setups ────────────────────────────────────────────────────────────

/**
 * Default mocks: rsyslog installed, no forwarding rules, no filebeat.
 */
function setupDefaultMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    // dpkg -l rsyslog — installed
    if (command === "dpkg" && args[0] === "-l" && args[1] === "rsyslog") {
      return createMockChildProcess("ii  rsyslog  8.2001.0  amd64  reliable syslogd\n", "", 0);
    }
    // dpkg -l syslog-ng — not installed
    if (command === "dpkg" && args[0] === "-l" && args[1] === "syslog-ng") {
      return createMockChildProcess("", "no packages found", 1);
    }
    // dpkg -l rsyslog-gnutls — not installed
    if (command === "dpkg" && args[0] === "-l" && args[1] === "rsyslog-gnutls") {
      return createMockChildProcess("", "no packages found", 1);
    }
    // dpkg -l filebeat — not installed
    if (command === "dpkg" && args[0] === "-l" && args[1] === "filebeat") {
      return createMockChildProcess("", "no packages found", 1);
    }
    // cat /etc/rsyslog.conf — basic config, no forwarding
    if (command === "cat" && args[0] === "/etc/rsyslog.conf") {
      return createMockChildProcess(
        "# /etc/rsyslog.conf\n" +
        "module(load=\"imuxsock\")\n" +
        "module(load=\"imklog\")\n" +
        "*.* /var/log/syslog\n" +
        "auth,authpriv.* /var/log/auth.log\n",
        "",
        0,
      );
    }
    // cat /etc/rsyslog.d/ — fails (it's a directory)
    if (command === "cat" && args[0] === "/etc/rsyslog.d/") {
      return createMockChildProcess("", "Is a directory", 1);
    }
    // which filebeat — not found
    if (command === "which" && args[0] === "filebeat") {
      return createMockChildProcess("", "", 1);
    }
    // systemctl status filebeat — not found
    if (command === "systemctl" && args[1] === "filebeat") {
      return createMockChildProcess("Unit filebeat.service not found", "", 4);
    }
    // cat /etc/logrotate.d/rsyslog
    if (command === "cat" && args[0] === "/etc/logrotate.d/rsyslog") {
      return createMockChildProcess(
        "/var/log/syslog\n{\n  rotate 7\n  daily\n  sharedscripts\n  postrotate\n    /usr/lib/rsyslog/rsyslog-rotate\n  endscript\n}\n",
        "",
        0,
      );
    }
    // Default
    return createMockChildProcess("", "", 1);
  });
}

/**
 * Mock: rsyslog installed with existing forwarding rules.
 */
function setupRsyslogWithForwardingMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    if (command === "dpkg" && args[0] === "-l" && args[1] === "rsyslog") {
      return createMockChildProcess("ii  rsyslog  8.2001.0  amd64  reliable syslogd\n", "", 0);
    }
    if (command === "dpkg" && args[0] === "-l" && args[1] === "syslog-ng") {
      return createMockChildProcess("", "no packages found", 1);
    }
    if (command === "dpkg" && args[0] === "-l" && args[1] === "rsyslog-gnutls") {
      return createMockChildProcess("ii  rsyslog-gnutls  8.2001.0  amd64  TLS support\n", "", 0);
    }
    if (command === "dpkg" && args[0] === "-l" && args[1] === "filebeat") {
      return createMockChildProcess("", "no packages found", 1);
    }
    if (command === "cat" && args[0] === "/etc/rsyslog.conf") {
      return createMockChildProcess(
        "# /etc/rsyslog.conf\n" +
        "module(load=\"imuxsock\")\n" +
        "module(load=\"imklog\")\n" +
        "module(load=\"imtcp\")\n" +
        "*.* /var/log/syslog\n" +
        "auth,authpriv.* /var/log/auth.log\n" +
        "*.* @@siem.example.com:514\n" +
        "auth.* @@siem.example.com:514\n",
        "",
        0,
      );
    }
    if (command === "cat" && args[0] === "/etc/rsyslog.d/") {
      return createMockChildProcess("", "Is a directory", 1);
    }
    if (command === "which" && args[0] === "filebeat") {
      return createMockChildProcess("", "", 1);
    }
    if (command === "systemctl" && args[1] === "filebeat") {
      return createMockChildProcess("Unit filebeat.service not found", "", 4);
    }
    if (command === "cat" && args[0] === "/etc/logrotate.d/rsyslog") {
      return createMockChildProcess(
        "/var/log/syslog\n{\n  rotate 7\n  daily\n  sharedscripts\n  postrotate\n    /usr/lib/rsyslog/rsyslog-rotate\n  endscript\n}\n",
        "",
        0,
      );
    }
    return createMockChildProcess("", "", 1);
  });
}

/**
 * Mock: syslog-ng installed instead of rsyslog.
 */
function setupSyslogNgMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    if (command === "dpkg" && args[0] === "-l" && args[1] === "rsyslog") {
      return createMockChildProcess("", "no packages found", 1);
    }
    if (command === "dpkg" && args[0] === "-l" && args[1] === "syslog-ng") {
      return createMockChildProcess("ii  syslog-ng  3.28  amd64  enhanced syslogd\n", "", 0);
    }
    if (command === "dpkg" && args[0] === "-l" && args[1] === "rsyslog-gnutls") {
      return createMockChildProcess("", "no packages found", 1);
    }
    if (command === "cat" && args[0] === "/etc/rsyslog.conf") {
      return createMockChildProcess("", "No such file or directory", 1);
    }
    if (command === "cat" && args[0] === "/etc/rsyslog.d/") {
      return createMockChildProcess("", "Is a directory", 1);
    }
    return createMockChildProcess("", "", 1);
  });
}

/**
 * Mock: no syslog daemon installed.
 */
function setupNoSyslogMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    if (command === "dpkg" && args[0] === "-l" && args[1] === "rsyslog") {
      return createMockChildProcess("", "no packages found", 1);
    }
    if (command === "dpkg" && args[0] === "-l" && args[1] === "syslog-ng") {
      return createMockChildProcess("", "no packages found", 1);
    }
    return createMockChildProcess("", "", 1);
  });
}

/**
 * Mock: filebeat installed and running.
 */
function setupFilebeatMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    if (command === "which" && args[0] === "filebeat") {
      return createMockChildProcess("/usr/bin/filebeat", "", 0);
    }
    if (command === "dpkg" && args[0] === "-l" && args[1] === "filebeat") {
      return createMockChildProcess("ii  filebeat  8.10.0  amd64  lightweight shipper\n", "", 0);
    }
    if (command === "filebeat" && args[0] === "version") {
      return createMockChildProcess("filebeat version 8.10.0 (amd64)", "", 0);
    }
    if (command === "cat" && args[0] === "/etc/filebeat/filebeat.yml") {
      return createMockChildProcess(
        "filebeat.inputs:\n" +
        "- type: log\n" +
        "  paths:\n" +
        "    - /var/log/*.log\n" +
        "output.logstash:\n" +
        "  hosts: [\"siem.example.com:5044\"]\n",
        "",
        0,
      );
    }
    if (command === "filebeat" && args[0] === "modules" && args[1] === "list") {
      return createMockChildProcess(
        "Enabled:\nsystem\nauditd\n\nDisabled:\napache\nnginx\nmysql\n",
        "",
        0,
      );
    }
    if (command === "systemctl" && args[1] === "filebeat") {
      return createMockChildProcess(
        "● filebeat.service - Filebeat sends log files to Logstash\n   Active: active (running) since Mon 2025-01-01\n",
        "",
        0,
      );
    }
    // For audit_forwarding tests, provide rsyslog too
    if (command === "dpkg" && args[0] === "-l" && args[1] === "rsyslog") {
      return createMockChildProcess("ii  rsyslog  8.2001.0  amd64  reliable syslogd\n", "", 0);
    }
    if (command === "cat" && args[0] === "/etc/rsyslog.conf") {
      return createMockChildProcess(
        "# /etc/rsyslog.conf\n*.* /var/log/syslog\n",
        "",
        0,
      );
    }
    if (command === "cat" && args[0] === "/etc/logrotate.d/rsyslog") {
      return createMockChildProcess(
        "/var/log/syslog\n{\n  rotate 7\n  daily\n  sharedscripts\n  postrotate\n    /usr/lib/rsyslog/rsyslog-rotate\n  endscript\n}\n",
        "",
        0,
      );
    }
    return createMockChildProcess("", "", 1);
  });
}

/**
 * Mock: filebeat not installed.
 */
function setupNoFilebeatMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    if (command === "which" && args[0] === "filebeat") {
      return createMockChildProcess("", "filebeat not found", 1);
    }
    if (command === "dpkg" && args[0] === "-l" && args[1] === "filebeat") {
      return createMockChildProcess("", "no packages found", 1);
    }
    return createMockChildProcess("", "", 1);
  });
}

/**
 * Mock: SIEM connectivity success.
 */
function setupConnectivitySuccessMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    if (command === "dig") {
      return createMockChildProcess(
        ";; ANSWER SECTION:\nsiem.example.com.  300  IN  A  10.0.0.1\n",
        "",
        0,
      );
    }
    if (command === "nc") {
      return createMockChildProcess("", "", 0);
    }
    if (command === "iptables") {
      return createMockChildProcess(
        "Chain INPUT (policy ACCEPT)\ntarget prot opt source destination\n",
        "",
        0,
      );
    }
    if (command === "logger") {
      return createMockChildProcess("", "", 0);
    }
    if (command === "openssl") {
      return createMockChildProcess("Verification: OK\n", "", 0);
    }
    return createMockChildProcess("", "", 0);
  });
}

/**
 * Mock: SIEM connectivity failure.
 */
function setupConnectivityFailureMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    if (command === "dig") {
      return createMockChildProcess(";; AUTHORITY SECTION:\n", "", 0);
    }
    if (command === "nc") {
      return createMockChildProcess("", "Connection refused", 1);
    }
    if (command === "iptables") {
      return createMockChildProcess(
        "Chain INPUT (policy ACCEPT)\ntarget prot opt source destination\nDROP tcp -- 0.0.0.0/0 0.0.0.0/0 tcp dpt:514\n",
        "",
        0,
      );
    }
    if (command === "logger") {
      return createMockChildProcess("", "Connection refused", 1);
    }
    if (command === "openssl") {
      return createMockChildProcess("", "Connection refused", 1);
    }
    return createMockChildProcess("", "", 1);
  });
}

/**
 * Mock: TLS connectivity test.
 */
function setupTlsConnectivityMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    if (command === "dig") {
      return createMockChildProcess(
        ";; ANSWER SECTION:\nsiem.example.com.  300  IN  A  10.0.0.1\n",
        "",
        0,
      );
    }
    if (command === "nc") {
      return createMockChildProcess("", "", 0);
    }
    if (command === "openssl" && args[0] === "s_client") {
      return createMockChildProcess("Verification: OK\nSubject: CN=siem.example.com\n", "", 0);
    }
    if (command === "iptables") {
      return createMockChildProcess(
        "Chain INPUT (policy ACCEPT)\ntarget prot opt source destination\n",
        "",
        0,
      );
    }
    if (command === "logger") {
      return createMockChildProcess("", "", 0);
    }
    return createMockChildProcess("", "", 0);
  });
}

// ── Tests ──────────────────────────────────────────────────────────────────

describe("siem-integration tools", () => {
  let tools: Map<
    string,
    { schema: Record<string, unknown>; handler: ToolHandler }
  >;

  beforeEach(() => {
    vi.clearAllMocks();
    const mock = createMockServer();
    registerSiemIntegrationTools(mock.server);
    tools = mock.tools;
    setupDefaultMocks();
  });

  // ── Registration ────────────────────────────────────────────────────────

  it("should register the log_management tool", () => {
    expect(tools.has("siem_log_management")).toBe(true);
  });

  it("should register with server.tool called once", () => {
    const mock = createMockServer();
    registerSiemIntegrationTools(mock.server);
    expect(mock.server.tool).toHaveBeenCalledTimes(1);
    expect(mock.server.tool).toHaveBeenCalledWith(
      "siem_log_management",
      expect.any(String),
      expect.any(Object),
      expect.any(Function),
    );
  });

  // ── Unknown action ──────────────────────────────────────────────────────

  it("should report error for unknown action", async () => {
    const handler = tools.get("siem_log_management")!.handler;
    const result = await handler({ action: "nonexistent" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Unknown action");
  });

  // ── Pure function tests ─────────────────────────────────────────────────

  describe("validateSiemHost", () => {
    it("should accept valid hostnames", () => {
      expect(validateSiemHost("siem.example.com")).toBe(true);
      expect(validateSiemHost("my-siem-server")).toBe(true);
      expect(validateSiemHost("siem01.corp.local")).toBe(true);
    });

    it("should accept valid IP addresses", () => {
      expect(validateSiemHost("192.168.1.100")).toBe(true);
      expect(validateSiemHost("10.0.0.1")).toBe(true);
    });

    it("should reject empty strings", () => {
      expect(validateSiemHost("")).toBe(false);
      expect(validateSiemHost("   ")).toBe(false);
    });

    it("should reject invalid hostnames", () => {
      expect(validateSiemHost("-invalid")).toBe(false);
      expect(validateSiemHost("ab")).toBe(true); // two chars is fine
    });
  });

  // ── siem_syslog_forward ─────────────────────────────────────────────────

  describe("siem_syslog_forward", () => {
    it("should detect rsyslog as installed", async () => {
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({ action: "siem_syslog_forward", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.syslogDaemon).toBe("rsyslog");
      expect(parsed.daemonInstalled).toBe(true);
    });

    it("should detect syslog-ng as installed", async () => {
      setupSyslogNgMocks();
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({ action: "siem_syslog_forward", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.syslogDaemon).toBe("syslog-ng");
      expect(parsed.daemonInstalled).toBe(true);
    });

    it("should handle no syslog daemon installed", async () => {
      setupNoSyslogMocks();
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({ action: "siem_syslog_forward", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.syslogDaemon).toBe("none");
      expect(parsed.daemonInstalled).toBe(false);
      expect(parsed.recommendations.some((r: string) => r.includes("No syslog daemon found"))).toBe(true);
    });

    it("should detect existing forwarding rules", async () => {
      setupRsyslogWithForwardingMocks();
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({ action: "siem_syslog_forward", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.existingForwardingRules.length).toBeGreaterThan(0);
      expect(parsed.existingForwardingRules.some((r: string) => r.includes("@@siem.example.com"))).toBe(true);
    });

    it("should report no forwarding rules when none exist", async () => {
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({ action: "siem_syslog_forward", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.existingForwardingRules.length).toBe(0);
      expect(parsed.recommendations.some((r: string) => r.includes("No remote forwarding rules found"))).toBe(true);
    });

    it("should detect loaded rsyslog modules", async () => {
      setupRsyslogWithForwardingMocks();
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({ action: "siem_syslog_forward", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.rsyslogModules.imtcp).toBe(true);
    });

    it("should detect TLS support", async () => {
      setupRsyslogWithForwardingMocks();
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({ action: "siem_syslog_forward", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.tlsSupport).toBe(true);
    });

    it("should generate recommended config when siem_host provided", async () => {
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({
        action: "siem_syslog_forward",
        siem_host: "siem.example.com",
        siem_port: 514,
        protocol: "tcp",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.recommendedConfig).toContain("@@siem.example.com:514");
    });

    it("should generate UDP forwarding config", async () => {
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({
        action: "siem_syslog_forward",
        siem_host: "siem.example.com",
        protocol: "udp",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.recommendedConfig).toContain("@siem.example.com:");
      expect(parsed.recommendedConfig).not.toContain("@@siem.example.com:");
    });

    it("should generate TLS forwarding config", async () => {
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({
        action: "siem_syslog_forward",
        siem_host: "siem.example.com",
        protocol: "tls",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.recommendedConfig).toContain("gtls");
      expect(parsed.recommendedConfig).toContain("@@siem.example.com:");
    });

    it("should warn about TLS when rsyslog-gnutls not installed", async () => {
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({
        action: "siem_syslog_forward",
        siem_host: "siem.example.com",
        protocol: "tls",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.recommendations.some((r: string) => r.includes("rsyslog-gnutls not installed"))).toBe(true);
    });

    it("should generate config with specific log sources", async () => {
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({
        action: "siem_syslog_forward",
        siem_host: "siem.example.com",
        log_sources: ["auth", "kern"],
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.recommendedConfig).toContain("auth.*");
      expect(parsed.recommendedConfig).toContain("kern.*");
    });

    it("should return text format by default", async () => {
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({ action: "siem_syslog_forward" });
      expect(result.content[0].text).toContain("Syslog Forwarding Configuration");
      expect(result.content[0].text).toContain("Syslog Daemon");
    });
  });

  // ── siem_filebeat ───────────────────────────────────────────────────────

  describe("siem_filebeat", () => {
    it("should detect filebeat when installed", async () => {
      setupFilebeatMocks();
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({ action: "siem_filebeat", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.installed).toBe(true);
      expect(parsed.version).toContain("8.10.0");
    });

    it("should handle filebeat not installed", async () => {
      setupNoFilebeatMocks();
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({ action: "siem_filebeat", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.installed).toBe(false);
      expect(parsed.recommendations.some((r: string) => r.includes("not installed"))).toBe(true);
    });

    it("should list enabled filebeat modules", async () => {
      setupFilebeatMocks();
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({ action: "siem_filebeat", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.enabledModules).toContain("system");
      expect(parsed.enabledModules).toContain("auditd");
    });

    it("should list disabled filebeat modules", async () => {
      setupFilebeatMocks();
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({ action: "siem_filebeat", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.disabledModules).toContain("apache");
      expect(parsed.disabledModules).toContain("nginx");
    });

    it("should check filebeat service status", async () => {
      setupFilebeatMocks();
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({ action: "siem_filebeat", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.serviceRunning).toBe(true);
    });

    it("should generate recommended config with siem_host", async () => {
      setupFilebeatMocks();
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({
        action: "siem_filebeat",
        siem_host: "logstash.example.com",
        siem_port: 5044,
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.recommendedConfig).toContain("logstash.example.com:5044");
      expect(parsed.recommendedConfig).toContain("output.logstash");
    });

    it("should recommend enabling modules when none enabled", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "which" && args[0] === "filebeat") {
          return createMockChildProcess("/usr/bin/filebeat", "", 0);
        }
        if (command === "filebeat" && args[0] === "version") {
          return createMockChildProcess("filebeat version 8.10.0", "", 0);
        }
        if (command === "cat" && args[0] === "/etc/filebeat/filebeat.yml") {
          return createMockChildProcess("filebeat.inputs:\n", "", 0);
        }
        if (command === "filebeat" && args[0] === "modules") {
          return createMockChildProcess("Enabled:\n\nDisabled:\nsystem\napache\n", "", 0);
        }
        if (command === "systemctl" && args[1] === "filebeat") {
          return createMockChildProcess("Active: inactive (dead)\n", "", 3);
        }
        return createMockChildProcess("", "", 1);
      });

      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({ action: "siem_filebeat", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.recommendations.some((r: string) => r.includes("No Filebeat modules enabled"))).toBe(true);
    });

    it("should recommend starting service when not running", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "which" && args[0] === "filebeat") {
          return createMockChildProcess("/usr/bin/filebeat", "", 0);
        }
        if (command === "filebeat" && args[0] === "version") {
          return createMockChildProcess("filebeat version 8.10.0", "", 0);
        }
        if (command === "cat" && args[0] === "/etc/filebeat/filebeat.yml") {
          return createMockChildProcess("filebeat.inputs:\n", "", 0);
        }
        if (command === "filebeat" && args[0] === "modules") {
          return createMockChildProcess("Enabled:\nsystem\n\nDisabled:\n", "", 0);
        }
        if (command === "systemctl" && args[1] === "filebeat") {
          return createMockChildProcess("Active: inactive (dead)\n", "", 3);
        }
        return createMockChildProcess("", "", 1);
      });

      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({ action: "siem_filebeat", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.serviceRunning).toBe(false);
      expect(parsed.recommendations.some((r: string) => r.includes("not running"))).toBe(true);
    });

    it("should return text format with filebeat info", async () => {
      setupFilebeatMocks();
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({ action: "siem_filebeat" });
      expect(result.content[0].text).toContain("Filebeat Configuration");
      expect(result.content[0].text).toContain("Installed: yes");
    });
  });

  // ── siem_audit_forwarding ───────────────────────────────────────────────

  describe("siem_audit_forwarding", () => {
    it("should detect no forwarding configured", async () => {
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({ action: "siem_audit_forwarding", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.rsyslogForwarding).toBe(false);
      expect(parsed.filebeatRunning).toBe(false);
      expect(parsed.cisCompliant).toBe(false);
    });

    it("should detect rsyslog forwarding as configured", async () => {
      setupRsyslogWithForwardingMocks();
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({ action: "siem_audit_forwarding", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.rsyslogForwarding).toBe(true);
      expect(parsed.rsyslogRules.length).toBeGreaterThan(0);
      expect(parsed.cisCompliant).toBe(true);
    });

    it("should detect filebeat as running forwarding", async () => {
      setupFilebeatMocks();
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({ action: "siem_audit_forwarding", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.filebeatRunning).toBe(true);
      expect(parsed.cisCompliant).toBe(true);
    });

    it("should check critical log source coverage", async () => {
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({ action: "siem_audit_forwarding", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.criticalSourcesCovered.length).toBe(4); // auth, syslog, kern, audit
      const sources = parsed.criticalSourcesCovered.map((s: { source: string }) => s.source);
      expect(sources).toContain("auth");
      expect(sources).toContain("syslog");
      expect(sources).toContain("kern");
      expect(sources).toContain("audit");
    });

    it("should report missing sources when no forwarding", async () => {
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({ action: "siem_audit_forwarding", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.missingSourcesCount).toBe(4);
      expect(parsed.recommendations.some((r: string) => r.includes("Missing forwarding"))).toBe(true);
    });

    it("should report all sources covered with wildcard forwarding", async () => {
      setupRsyslogWithForwardingMocks();
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({ action: "siem_audit_forwarding", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.missingSourcesCount).toBe(0);
    });

    it("should check log rotation configuration", async () => {
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({ action: "siem_audit_forwarding", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.logRotationInterferes).toBe(false);
    });

    it("should detect log rotation interference", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "cat" && args[0] === "/etc/rsyslog.conf") {
          return createMockChildProcess("*.* /var/log/syslog\n", "", 0);
        }
        if (command === "systemctl" && args[1] === "filebeat") {
          return createMockChildProcess("Unit filebeat.service not found", "", 4);
        }
        if (command === "cat" && args[0] === "/etc/logrotate.d/rsyslog") {
          return createMockChildProcess(
            "/var/log/syslog\n{\n  rotate 7\n  daily\n}\n",
            "",
            0,
          );
        }
        return createMockChildProcess("", "", 1);
      });

      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({ action: "siem_audit_forwarding", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.logRotationInterferes).toBe(true);
    });

    it("should include CIS benchmark reference", async () => {
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({ action: "siem_audit_forwarding", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.cisBenchmark).toContain("CIS Benchmark");
      expect(parsed.cisBenchmark).toContain("4.2.1");
    });

    it("should check custom log sources", async () => {
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({
        action: "siem_audit_forwarding",
        log_sources: ["auth", "kern"],
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.criticalSourcesCovered.length).toBe(2);
    });

    it("should report CRITICAL recommendation when no forwarding", async () => {
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({ action: "siem_audit_forwarding", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.recommendations.some((r: string) => r.includes("CRITICAL"))).toBe(true);
    });

    it("should return text format with audit summary", async () => {
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({ action: "siem_audit_forwarding" });
      expect(result.content[0].text).toContain("Log Forwarding Audit");
      expect(result.content[0].text).toContain("CIS Reference");
    });
  });

  // ── siem_test_connectivity ──────────────────────────────────────────────

  describe("siem_test_connectivity", () => {
    it("should require siem_host parameter", async () => {
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({ action: "siem_test_connectivity" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("requires siem_host");
    });

    it("should validate siem_host format", async () => {
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({ action: "siem_test_connectivity", siem_host: "-invalid!" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Invalid siem_host");
    });

    it("should test successful connectivity", async () => {
      setupConnectivitySuccessMocks();
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({
        action: "siem_test_connectivity",
        siem_host: "siem.example.com",
        siem_port: 514,
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.tcpConnectivity).toBe(true);
      expect(parsed.dnsResolution).toBe(true);
      expect(parsed.testMessageSent).toBe(true);
    });

    it("should test failed connectivity", async () => {
      setupConnectivityFailureMocks();
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({
        action: "siem_test_connectivity",
        siem_host: "unreachable.example.com",
        siem_port: 514,
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.tcpConnectivity).toBe(false);
      expect(parsed.dnsResolution).toBe(false);
      expect(parsed.recommendations.length).toBeGreaterThan(0);
    });

    it("should detect firewall blocking", async () => {
      setupConnectivityFailureMocks();
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({
        action: "siem_test_connectivity",
        siem_host: "siem.example.com",
        siem_port: 514,
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.firewallBlocked).toBe(true);
      expect(parsed.recommendations.some((r: string) => r.includes("Firewall rule blocking"))).toBe(true);
    });

    it("should test TLS connectivity", async () => {
      setupTlsConnectivityMocks();
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({
        action: "siem_test_connectivity",
        siem_host: "siem.example.com",
        siem_port: 6514,
        protocol: "tls",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.tlsVerification).toBe(true);
      expect(parsed.tcpConnectivity).toBe(true);
      expect(parsed.protocol).toBe("tls");
    });

    it("should handle TLS failure", async () => {
      setupConnectivityFailureMocks();
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({
        action: "siem_test_connectivity",
        siem_host: "siem.example.com",
        siem_port: 6514,
        protocol: "tls",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.tlsVerification).toBe(false);
      expect(parsed.recommendations.some((r: string) => r.includes("TLS"))).toBe(true);
    });

    it("should use default port 514 when not specified", async () => {
      setupConnectivitySuccessMocks();
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({
        action: "siem_test_connectivity",
        siem_host: "siem.example.com",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.siemPort).toBe(514);
    });

    it("should send test syslog message on success", async () => {
      setupConnectivitySuccessMocks();
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({
        action: "siem_test_connectivity",
        siem_host: "siem.example.com",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.testMessageSent).toBe(true);
      expect(parsed.testMessageResult).toContain("successfully");
    });

    it("should handle logger not available", async () => {
      mockSpawnSafe.mockImplementation((command: string) => {
        if (command === "dig") {
          return createMockChildProcess(";; ANSWER SECTION:\nhost 300 IN A 10.0.0.1\n", "", 0);
        }
        if (command === "nc") {
          return createMockChildProcess("", "", 0);
        }
        if (command === "iptables") {
          return createMockChildProcess("Chain INPUT (policy ACCEPT)\n", "", 0);
        }
        if (command === "logger") {
          return createMockChildProcess("", "logger: not found", 127);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({
        action: "siem_test_connectivity",
        siem_host: "siem.example.com",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.testMessageSent).toBe(false);
    });

    it("should return text format with connectivity summary", async () => {
      setupConnectivitySuccessMocks();
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({
        action: "siem_test_connectivity",
        siem_host: "siem.example.com",
      });
      expect(result.content[0].text).toContain("Connectivity Test");
      expect(result.content[0].text).toContain("siem.example.com");
    });

    it("should recommend checking SIEM when unreachable", async () => {
      setupConnectivityFailureMocks();
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({
        action: "siem_test_connectivity",
        siem_host: "siem.example.com",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.recommendations.some((r: string) =>
        r.includes("CRITICAL") || r.includes("unreachable") || r.includes("Cannot reach"),
      )).toBe(true);
    });
  });

  // ── Output format tests ─────────────────────────────────────────────────

  describe("output formats", () => {
    it("should return JSON for siem_syslog_forward", async () => {
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({ action: "siem_syslog_forward", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("siem_syslog_forward");
    });

    it("should return JSON for siem_filebeat", async () => {
      setupFilebeatMocks();
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({ action: "siem_filebeat", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("siem_filebeat");
    });

    it("should return JSON for siem_audit_forwarding", async () => {
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({ action: "siem_audit_forwarding", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("siem_audit_forwarding");
    });

    it("should return JSON for siem_test_connectivity", async () => {
      setupConnectivitySuccessMocks();
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({
        action: "siem_test_connectivity",
        siem_host: "siem.example.com",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("siem_test_connectivity");
    });

    it("should default to text format", async () => {
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({ action: "siem_syslog_forward" });
      expect(result.content[0].text).toContain("SIEM Integration");
    });
  });

  // ── Error handling ──────────────────────────────────────────────────────

  describe("error handling", () => {
    it("should handle spawnSafe throwing errors", async () => {
      mockSpawnSafe.mockImplementation(() => {
        throw new Error("spawn failed");
      });

      const handler = tools.get("siem_log_management")!.handler;
      // siem_syslog_forward catches errors internally in runCommand
      const result = await handler({ action: "siem_syslog_forward", output_format: "json" });
      expect(result.content).toBeDefined();
    });

    it("should handle command failures in all SIEM actions", async () => {
      mockSpawnSafe.mockImplementation(() => {
        return createMockChildProcess("", "command failed", 1);
      });

      const handler = tools.get("siem_log_management")!.handler;

      // Actions that don't require siem_host should handle failures gracefully
      for (const action of ["siem_syslog_forward", "siem_filebeat", "siem_audit_forwarding"]) {
        const result = await handler({ action, output_format: "json" });
        expect(result.content).toBeDefined();
        expect(result.isError).toBeUndefined(); // Graceful, not error
      }
    });

    it("should handle missing tools gracefully", async () => {
      mockSpawnSafe.mockImplementation(() => {
        throw new Error("Command not in allowlist");
      });

      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({ action: "siem_syslog_forward", output_format: "json" });
      // runCommand catches the error and returns it as CommandResult
      expect(result.content).toBeDefined();
    });

    it("should handle unreachable host in connectivity test", async () => {
      setupConnectivityFailureMocks();
      const handler = tools.get("siem_log_management")!.handler;
      const result = await handler({
        action: "siem_test_connectivity",
        siem_host: "unreachable.host",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.tcpConnectivity).toBe(false);
      expect(parsed.recommendations.length).toBeGreaterThan(0);
    });
  });
});
