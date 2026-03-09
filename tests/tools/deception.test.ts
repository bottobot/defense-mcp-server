/**
 * Tests for src/tools/deception.ts
 *
 * Covers: honeypot_manage tool with actions deploy_canary, deploy_honeyport,
 * check_triggers, remove, list.
 * Tests canary deployment (file, credential, directory, ssh_key), honeyport
 * setup, trigger checking (triggered vs not), canary removal, registry
 * management, JSON/text output, and error handling.
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

vi.mock("../../src/core/secure-fs.js", () => ({
  secureWriteFileSync: vi.fn(),
}));

vi.mock("node:fs", () => ({
  existsSync: vi.fn(() => false),
  readFileSync: vi.fn(() => ""),
  unlinkSync: vi.fn(),
  rmSync: vi.fn(),
}));

import { registerDeceptionTools } from "../../src/tools/deception.js";
import { spawnSafe } from "../../src/core/spawn-safe.js";
import { secureWriteFileSync } from "../../src/core/secure-fs.js";
import { existsSync, readFileSync, unlinkSync, rmSync } from "node:fs";
import { EventEmitter } from "node:events";

const mockSpawnSafe = vi.mocked(spawnSafe);
const mockSecureWriteFileSync = vi.mocked(secureWriteFileSync);
const mockExistsSync = vi.mocked(existsSync);
const mockReadFileSync = vi.mocked(readFileSync);
const mockUnlinkSync = vi.mocked(unlinkSync);
const mockRmSync = vi.mocked(rmSync);

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
    server: server as unknown as Parameters<typeof registerDeceptionTools>[0],
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
 * Set up default spawnSafe mocks — basic command responses.
 */
function setupDefaultMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    // inotifywait — simulate background launch
    if (command === "inotifywait") {
      return createMockChildProcess("", "", 0);
    }
    // stat — return access time
    if (command === "stat") {
      return createMockChildProcess("1700000000", "", 0);
    }
    // ncat — simulate listener start
    if (command === "ncat") {
      return createMockChildProcess("", "", 0);
    }
    // sh -c lsof — return PID
    if (command === "sh" && args[0] === "-c" && args[1]?.includes("lsof")) {
      return createMockChildProcess("12345", "", 0);
    }
    // iptables — success
    if (command === "iptables") {
      return createMockChildProcess("", "", 0);
    }
    // grep syslog — no entries
    if (command === "grep") {
      return createMockChildProcess("", "", 1);
    }
    // kill — success
    if (command === "kill") {
      return createMockChildProcess("", "", 0);
    }
    // Default: return failure
    return createMockChildProcess("", "", 1);
  });
}

/**
 * Build a mock registry JSON string.
 */
function buildRegistryJson(canaries: Array<Record<string, unknown>> = []): string {
  return JSON.stringify({
    canaries,
    lastUpdated: new Date().toISOString(),
  });
}

// ── Tests ──────────────────────────────────────────────────────────────────

describe("deception tools", () => {
  let tools: Map<
    string,
    { schema: Record<string, unknown>; handler: ToolHandler }
  >;

  beforeEach(() => {
    vi.clearAllMocks();
    mockSecureWriteFileSync.mockImplementation(() => {});
    mockUnlinkSync.mockImplementation(() => {});
    mockRmSync.mockImplementation(() => {});
    const mock = createMockServer();
    registerDeceptionTools(mock.server);
    tools = mock.tools;
    setupDefaultMocks();
    mockExistsSync.mockReturnValue(false);
    mockReadFileSync.mockReturnValue("");
  });

  // ── Registration ────────────────────────────────────────────────────────

  it("should register the honeypot_manage tool", () => {
    expect(tools.has("honeypot_manage")).toBe(true);
  });

  it("should register with server.tool called once", () => {
    const mock = createMockServer();
    registerDeceptionTools(mock.server);
    expect(mock.server.tool).toHaveBeenCalledTimes(1);
    expect(mock.server.tool).toHaveBeenCalledWith(
      "honeypot_manage",
      expect.any(String),
      expect.any(Object),
      expect.any(Function),
    );
  });

  // ── Unknown action ──────────────────────────────────────────────────────

  it("should report error for unknown action", async () => {
    const handler = tools.get("honeypot_manage")!.handler;
    const result = await handler({ action: "nonexistent" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Unknown action");
  });

  // ── deploy_canary ───────────────────────────────────────────────────────

  describe("deploy_canary", () => {
    it("should require canary_type parameter", async () => {
      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({ action: "deploy_canary", canary_path: "/tmp/test" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("canary_type");
    });

    it("should require canary_path parameter", async () => {
      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({ action: "deploy_canary", canary_type: "file" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("canary_path");
    });

    it("should deploy a file canary", async () => {
      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "deploy_canary",
        canary_type: "file",
        canary_path: "/tmp/honeypot/passwords.txt",
        output_format: "json",
      });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("deploy_canary");
      expect(parsed.type).toBe("file");
      expect(parsed.canaryId).toMatch(/^canary-/);
      expect(parsed.path).toBe("/tmp/honeypot/passwords.txt");

      // Should have called secureWriteFileSync for the canary file and registry
      expect(mockSecureWriteFileSync).toHaveBeenCalled();
    });

    it("should deploy a credential canary", async () => {
      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "deploy_canary",
        canary_type: "credential",
        canary_path: "/home/user/.aws/credentials",
        output_format: "json",
      });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("deploy_canary");
      expect(parsed.type).toBe("credential");
      expect(parsed.canaryId).toMatch(/^canary-/);

      // Should write the fake credential file
      expect(mockSecureWriteFileSync).toHaveBeenCalled();
      const firstWriteCall = mockSecureWriteFileSync.mock.calls[0];
      expect(firstWriteCall[0]).toBe("/home/user/.aws/credentials");
      // Content should contain fake AWS-like credentials
      expect(String(firstWriteCall[1])).toContain("aws_access_key_id");
    });

    it("should deploy a directory canary with multiple files", async () => {
      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "deploy_canary",
        canary_type: "directory",
        canary_path: "/tmp/secrets/",
        output_format: "json",
      });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("deploy_canary");
      expect(parsed.type).toBe("directory");

      // Should have written multiple files (passwords.txt, id_rsa, .env.backup) + registry
      // At least 4 secureWriteFileSync calls: 3 files + 1 registry
      expect(mockSecureWriteFileSync.mock.calls.length).toBeGreaterThanOrEqual(4);
    });

    it("should deploy an ssh_key canary", async () => {
      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "deploy_canary",
        canary_type: "ssh_key",
        canary_path: "/home/user/.ssh/id_rsa",
        output_format: "json",
      });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("deploy_canary");
      expect(parsed.type).toBe("ssh_key");

      // Should write the fake SSH key file
      const firstWriteCall = mockSecureWriteFileSync.mock.calls[0];
      expect(firstWriteCall[0]).toBe("/home/user/.ssh/id_rsa");
      expect(String(firstWriteCall[1])).toContain("OPENSSH PRIVATE KEY");
    });

    it("should set up inotifywait monitoring", async () => {
      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "deploy_canary",
        canary_type: "file",
        canary_path: "/tmp/test.txt",
        output_format: "json",
      });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.monitoringSetup).toBe(true);
      expect(parsed.monitoringDetails).toContain("inotifywait");

      // Verify inotifywait was called
      const inotifyCalls = mockSpawnSafe.mock.calls.filter(
        (call) => call[0] === "inotifywait",
      );
      expect(inotifyCalls.length).toBe(1);
    });

    it("should handle inotifywait failure gracefully", async () => {
      mockSpawnSafe.mockImplementation((command: string, _args: string[]) => {
        if (command === "inotifywait") {
          return createMockChildProcess("", "command not found", 127);
        }
        if (command === "stat") {
          return createMockChildProcess("1700000000", "", 0);
        }
        return createMockChildProcess("", "", 1);
      });

      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "deploy_canary",
        canary_type: "file",
        canary_path: "/tmp/test.txt",
        output_format: "json",
      });

      const parsed = JSON.parse(result.content[0].text);
      // Still succeeds overall
      expect(parsed.canaryId).toMatch(/^canary-/);
      expect(parsed.monitoringSetup).toBe(false);
      expect(parsed.monitoringDetails).toContain("failed");
    });

    it("should generate unique canary IDs", async () => {
      const handler = tools.get("honeypot_manage")!.handler;
      const result1 = await handler({
        action: "deploy_canary",
        canary_type: "file",
        canary_path: "/tmp/test1.txt",
        output_format: "json",
      });
      const result2 = await handler({
        action: "deploy_canary",
        canary_type: "file",
        canary_path: "/tmp/test2.txt",
        output_format: "json",
      });

      const parsed1 = JSON.parse(result1.content[0].text);
      const parsed2 = JSON.parse(result2.content[0].text);
      expect(parsed1.canaryId).not.toBe(parsed2.canaryId);
    });

    it("should write to registry on deployment", async () => {
      const handler = tools.get("honeypot_manage")!.handler;
      await handler({
        action: "deploy_canary",
        canary_type: "file",
        canary_path: "/tmp/test.txt",
        output_format: "json",
      });

      // secureWriteFileSync should be called for the registry
      const registryWrites = mockSecureWriteFileSync.mock.calls.filter(
        (call) => String(call[0]).includes("registry.json"),
      );
      expect(registryWrites.length).toBe(1);

      // Parse the written registry data
      const registryData = JSON.parse(String(registryWrites[0][1]));
      expect(registryData.canaries.length).toBe(1);
      expect(registryData.canaries[0].type).toBe("file");
      expect(registryData.canaries[0].status).toBe("active");
    });

    it("should return text format by default", async () => {
      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "deploy_canary",
        canary_type: "file",
        canary_path: "/tmp/test.txt",
      });
      expect(result.content[0].text).toContain("Deploy Canary");
      expect(result.content[0].text).toContain("Canary ID:");
      expect(result.content[0].text).toContain("Type: file");
    });

    it("should append default filename for directory path ending with /", async () => {
      const handler = tools.get("honeypot_manage")!.handler;
      await handler({
        action: "deploy_canary",
        canary_type: "file",
        canary_path: "/tmp/honeypot/",
        output_format: "json",
      });

      // The file write should append passwords.txt
      const fileWrites = mockSecureWriteFileSync.mock.calls.filter(
        (call) => !String(call[0]).includes("registry.json"),
      );
      expect(fileWrites.length).toBeGreaterThan(0);
      expect(String(fileWrites[0][0])).toBe("/tmp/honeypot/passwords.txt");
    });

    it("should append default filename for credential canary path ending with /", async () => {
      const handler = tools.get("honeypot_manage")!.handler;
      await handler({
        action: "deploy_canary",
        canary_type: "credential",
        canary_path: "/home/user/",
        output_format: "json",
      });

      const fileWrites = mockSecureWriteFileSync.mock.calls.filter(
        (call) => !String(call[0]).includes("registry.json"),
      );
      expect(String(fileWrites[0][0])).toBe("/home/user/.aws/credentials");
    });

    it("should handle errors during deployment", async () => {
      mockSecureWriteFileSync.mockImplementation(() => {
        throw new Error("Permission denied");
      });

      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "deploy_canary",
        canary_type: "file",
        canary_path: "/root/test.txt",
        output_format: "json",
      });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("deploy_canary failed");
    });
  });

  // ── deploy_honeyport ────────────────────────────────────────────────────

  describe("deploy_honeyport", () => {
    it("should require port parameter", async () => {
      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({ action: "deploy_honeyport" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("port");
    });

    it("should deploy a honeyport listener", async () => {
      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "deploy_honeyport",
        port: 4444,
        output_format: "json",
      });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("deploy_honeyport");
      expect(parsed.port).toBe(4444);
      expect(parsed.canaryId).toMatch(/^canary-/);
      expect(parsed.logPath).toContain("honeyport-4444.log");
    });

    it("should start ncat listener", async () => {
      const handler = tools.get("honeypot_manage")!.handler;
      await handler({
        action: "deploy_honeyport",
        port: 5555,
        output_format: "json",
      });

      // Verify ncat was called with the right args
      const ncatCalls = mockSpawnSafe.mock.calls.filter(
        (call) => call[0] === "ncat",
      );
      expect(ncatCalls.length).toBe(1);
      expect(ncatCalls[0][1]).toContain("-l");
      expect(ncatCalls[0][1]).toContain("-k");
    });

    it("should resolve listener PID", async () => {
      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "deploy_honeyport",
        port: 6666,
        output_format: "json",
      });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.listenerPid).toBe(12345);
    });

    it("should add iptables LOG rule", async () => {
      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "deploy_honeyport",
        port: 7777,
        output_format: "json",
      });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.iptablesRuleAdded).toBe(true);

      // Verify iptables was called
      const iptablesCalls = mockSpawnSafe.mock.calls.filter(
        (call) => call[0] === "iptables",
      );
      expect(iptablesCalls.length).toBe(1);
      expect(iptablesCalls[0][1]).toContain("-A");
      expect(iptablesCalls[0][1]).toContain("INPUT");
      expect(iptablesCalls[0][1]).toContain("--dport");
      expect(iptablesCalls[0][1]).toContain("7777");
      expect(iptablesCalls[0][1]).toContain("LOG");
    });

    it("should register honeyport in registry", async () => {
      const handler = tools.get("honeypot_manage")!.handler;
      await handler({
        action: "deploy_honeyport",
        port: 8888,
        output_format: "json",
      });

      const registryWrites = mockSecureWriteFileSync.mock.calls.filter(
        (call) => String(call[0]).includes("registry.json"),
      );
      expect(registryWrites.length).toBe(1);
      const registryData = JSON.parse(String(registryWrites[0][1]));
      expect(registryData.canaries.length).toBe(1);
      expect(registryData.canaries[0].type).toBe("honeyport");
      expect(registryData.canaries[0].port).toBe(8888);
      expect(registryData.canaries[0].pid).toBe(12345);
    });

    it("should return text format", async () => {
      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "deploy_honeyport",
        port: 9999,
      });
      expect(result.content[0].text).toContain("Deploy Honeyport");
      expect(result.content[0].text).toContain("Port: 9999");
      expect(result.content[0].text).toContain("Listener PID:");
    });

    it("should handle iptables failure gracefully", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "iptables") {
          return createMockChildProcess("", "permission denied", 1);
        }
        if (command === "ncat") {
          return createMockChildProcess("", "", 0);
        }
        if (command === "sh" && args[0] === "-c" && args[1]?.includes("lsof")) {
          return createMockChildProcess("12345", "", 0);
        }
        return createMockChildProcess("", "", 1);
      });

      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "deploy_honeyport",
        port: 4444,
        output_format: "json",
      });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.iptablesRuleAdded).toBe(false);
      // Still succeeds overall
      expect(parsed.canaryId).toMatch(/^canary-/);
    });
  });

  // ── check_triggers ──────────────────────────────────────────────────────

  describe("check_triggers", () => {
    it("should report no triggers when registry is empty", async () => {
      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "check_triggers",
        output_format: "json",
      });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.triggeredCount).toBe(0);
      expect(parsed.totalCanaries).toBe(0);
      expect(parsed.triggered.length).toBe(0);
    });

    it("should detect triggered file canary (access time changed)", async () => {
      // Mock registry with a file canary
      const registryData = buildRegistryJson([
        {
          id: "canary-1234-abc",
          type: "file",
          path: "/tmp/honeypot/passwords.txt",
          deployedAt: "2025-01-01T00:00:00.000Z",
          status: "active",
          description: "Canary file deployed",
          accessTimeAtDeploy: "1700000000",
        },
      ]);

      mockExistsSync.mockImplementation((path: unknown) => {
        if (String(path).includes("registry.json")) return true;
        return false;
      });
      mockReadFileSync.mockImplementation((path: unknown) => {
        if (String(path).includes("registry.json")) return registryData;
        return "";
      });

      // stat returns different access time (file was accessed)
      mockSpawnSafe.mockImplementation((command: string) => {
        if (command === "stat") {
          return createMockChildProcess("1700099999", "", 0);
        }
        if (command === "grep") {
          return createMockChildProcess("", "", 1);
        }
        return createMockChildProcess("", "", 1);
      });

      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "check_triggers",
        output_format: "json",
      });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.triggeredCount).toBe(1);
      expect(parsed.triggered.length).toBe(1);
      expect(parsed.triggered[0].id).toBe("canary-1234-abc");
      expect(parsed.triggered[0].triggered).toBe(true);
      expect(parsed.triggered[0].severity).toBe("HIGH");
      expect(parsed.triggered[0].accessDetails.length).toBeGreaterThan(0);
    });

    it("should detect not-triggered file canary (access time unchanged)", async () => {
      const registryData = buildRegistryJson([
        {
          id: "canary-5678-def",
          type: "file",
          path: "/tmp/honeypot/test.txt",
          deployedAt: "2025-01-01T00:00:00.000Z",
          status: "active",
          description: "Canary file deployed",
          accessTimeAtDeploy: "1700000000",
        },
      ]);

      mockExistsSync.mockImplementation((path: unknown) => {
        if (String(path).includes("registry.json")) return true;
        return false;
      });
      mockReadFileSync.mockImplementation((path: unknown) => {
        if (String(path).includes("registry.json")) return registryData;
        return "";
      });

      // stat returns same access time (file NOT accessed)
      mockSpawnSafe.mockImplementation((command: string) => {
        if (command === "stat") {
          return createMockChildProcess("1700000000", "", 0);
        }
        if (command === "grep") {
          return createMockChildProcess("", "", 1);
        }
        return createMockChildProcess("", "", 1);
      });

      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "check_triggers",
        output_format: "json",
      });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.triggeredCount).toBe(0);
      expect(parsed.notTriggered).toContain("canary-5678-def");
    });

    it("should detect triggered honeyport (log has entries)", async () => {
      const registryData = buildRegistryJson([
        {
          id: "canary-hp-9999",
          type: "honeyport",
          port: 9999,
          pid: 12345,
          deployedAt: "2025-01-01T00:00:00.000Z",
          status: "active",
          description: "Honeyport listener on port 9999",
        },
      ]);

      mockExistsSync.mockImplementation((path: unknown) => {
        const p = String(path);
        if (p.includes("registry.json")) return true;
        if (p.includes("honeyport-9999.log")) return true;
        return false;
      });
      mockReadFileSync.mockImplementation((path: unknown) => {
        const p = String(path);
        if (p.includes("registry.json")) return registryData;
        if (p.includes("honeyport-9999.log")) {
          return "2025-01-02 10:00:00 connection from 192.168.1.50:54321\n2025-01-02 10:05:00 connection from 10.0.0.5:12345\n";
        }
        return "";
      });

      mockSpawnSafe.mockImplementation((command: string) => {
        if (command === "grep") {
          return createMockChildProcess("", "", 1);
        }
        return createMockChildProcess("", "", 1);
      });

      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "check_triggers",
        output_format: "json",
      });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.triggeredCount).toBe(1);
      expect(parsed.triggered[0].id).toBe("canary-hp-9999");
      expect(parsed.triggered[0].severity).toBe("CRITICAL");
      expect(parsed.triggered[0].accessDetails.some(
        (d: string) => d.includes("Connection log entries"),
      )).toBe(true);
    });

    it("should detect not-triggered honeyport (empty log)", async () => {
      const registryData = buildRegistryJson([
        {
          id: "canary-hp-7777",
          type: "honeyport",
          port: 7777,
          pid: 11111,
          deployedAt: "2025-01-01T00:00:00.000Z",
          status: "active",
          description: "Honeyport listener on port 7777",
        },
      ]);

      mockExistsSync.mockImplementation((path: unknown) => {
        const p = String(path);
        if (p.includes("registry.json")) return true;
        // Log file either doesn't exist or is empty
        return false;
      });
      mockReadFileSync.mockImplementation((path: unknown) => {
        if (String(path).includes("registry.json")) return registryData;
        return "";
      });

      mockSpawnSafe.mockImplementation((command: string) => {
        if (command === "grep") {
          return createMockChildProcess("", "", 1);
        }
        return createMockChildProcess("", "", 1);
      });

      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "check_triggers",
        output_format: "json",
      });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.triggeredCount).toBe(0);
      expect(parsed.notTriggered).toContain("canary-hp-7777");
    });

    it("should detect triggered canary via inotify log", async () => {
      const registryData = buildRegistryJson([
        {
          id: "canary-inotify-test",
          type: "credential",
          path: "/home/user/.aws/credentials",
          deployedAt: "2025-01-01T00:00:00.000Z",
          status: "active",
          description: "Canary credential file",
          accessTimeAtDeploy: "1700000000",
        },
      ]);

      mockExistsSync.mockImplementation((path: unknown) => {
        const p = String(path);
        if (p.includes("registry.json")) return true;
        if (p.includes("canary-canary-inotify-test.log")) return true;
        return false;
      });
      mockReadFileSync.mockImplementation((path: unknown) => {
        const p = String(path);
        if (p.includes("registry.json")) return registryData;
        if (p.includes("canary-canary-inotify-test.log")) {
          return "2025-01-02T10:30:00 /home/user/.aws/credentials OPEN\n";
        }
        return "";
      });

      // stat returns same access time (inotify detects it)
      mockSpawnSafe.mockImplementation((command: string) => {
        if (command === "stat") {
          return createMockChildProcess("1700000000", "", 0);
        }
        if (command === "grep") {
          return createMockChildProcess("", "", 1);
        }
        return createMockChildProcess("", "", 1);
      });

      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "check_triggers",
        output_format: "json",
      });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.triggeredCount).toBe(1);
      expect(parsed.triggered[0].severity).toBe("CRITICAL");
      expect(parsed.triggered[0].accessDetails.some(
        (d: string) => d.includes("inotify events"),
      )).toBe(true);
    });

    it("should check syslog for honeyport entries", async () => {
      const registryData = buildRegistryJson([]);

      mockExistsSync.mockImplementation((path: unknown) => {
        if (String(path).includes("registry.json")) return true;
        return false;
      });
      mockReadFileSync.mockImplementation((path: unknown) => {
        if (String(path).includes("registry.json")) return registryData;
        return "";
      });

      mockSpawnSafe.mockImplementation((command: string) => {
        if (command === "grep") {
          return createMockChildProcess(
            "Jan 2 10:00:00 host kernel: HONEYPORT:9999: IN=eth0 SRC=192.168.1.50\n",
            "",
            0,
          );
        }
        return createMockChildProcess("", "", 1);
      });

      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "check_triggers",
        output_format: "json",
      });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.syslogEntries.length).toBe(1);
      expect(parsed.syslogEntries[0]).toContain("HONEYPORT");
    });

    it("should skip removed canaries", async () => {
      const registryData = buildRegistryJson([
        {
          id: "canary-removed-1",
          type: "file",
          path: "/tmp/removed.txt",
          deployedAt: "2025-01-01T00:00:00.000Z",
          status: "removed",
          description: "Removed canary",
          accessTimeAtDeploy: "1700000000",
        },
      ]);

      mockExistsSync.mockImplementation((path: unknown) => {
        if (String(path).includes("registry.json")) return true;
        return false;
      });
      mockReadFileSync.mockImplementation((path: unknown) => {
        if (String(path).includes("registry.json")) return registryData;
        return "";
      });

      mockSpawnSafe.mockImplementation((command: string) => {
        if (command === "grep") {
          return createMockChildProcess("", "", 1);
        }
        return createMockChildProcess("", "", 1);
      });

      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "check_triggers",
        output_format: "json",
      });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.triggeredCount).toBe(0);
      expect(parsed.notTriggered.length).toBe(0);
    });

    it("should return text format with trigger details", async () => {
      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({ action: "check_triggers" });
      expect(result.content[0].text).toContain("Check Triggers");
      expect(result.content[0].text).toContain("Total Canaries:");
      expect(result.content[0].text).toContain("Triggered:");
    });

    it("should update registry with triggered status", async () => {
      const registryData = buildRegistryJson([
        {
          id: "canary-trigger-update",
          type: "file",
          path: "/tmp/trigger.txt",
          deployedAt: "2025-01-01T00:00:00.000Z",
          status: "active",
          description: "Test canary",
          accessTimeAtDeploy: "1700000000",
        },
      ]);

      mockExistsSync.mockImplementation((path: unknown) => {
        if (String(path).includes("registry.json")) return true;
        return false;
      });
      mockReadFileSync.mockImplementation((path: unknown) => {
        if (String(path).includes("registry.json")) return registryData;
        return "";
      });

      mockSpawnSafe.mockImplementation((command: string) => {
        if (command === "stat") {
          return createMockChildProcess("1700099999", "", 0); // Different time = triggered
        }
        if (command === "grep") {
          return createMockChildProcess("", "", 1);
        }
        return createMockChildProcess("", "", 1);
      });

      const handler = tools.get("honeypot_manage")!.handler;
      await handler({ action: "check_triggers", output_format: "json" });

      // Check that registry was written with updated status
      const registryWrites = mockSecureWriteFileSync.mock.calls.filter(
        (call) => String(call[0]).includes("registry.json"),
      );
      expect(registryWrites.length).toBe(1);
      const updatedRegistry = JSON.parse(String(registryWrites[0][1]));
      expect(updatedRegistry.canaries[0].status).toBe("triggered");
    });
  });

  // ── remove ──────────────────────────────────────────────────────────────

  describe("remove", () => {
    it("should require canary_id parameter", async () => {
      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({ action: "remove" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("canary_id");
    });

    it("should report not found for unknown canary ID", async () => {
      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "remove",
        canary_id: "nonexistent-id",
        output_format: "json",
      });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.found).toBe(false);
      expect(parsed.description).toContain("not found");
    });

    it("should remove a file canary", async () => {
      const registryData = buildRegistryJson([
        {
          id: "canary-remove-file",
          type: "file",
          path: "/tmp/honeypot/passwords.txt",
          deployedAt: "2025-01-01T00:00:00.000Z",
          status: "active",
          description: "Canary file",
          accessTimeAtDeploy: "1700000000",
        },
      ]);

      mockExistsSync.mockImplementation((path: unknown) => {
        const p = String(path);
        if (p.includes("registry.json")) return true;
        if (p.includes("canary-canary-remove-file.log")) return true;
        return false;
      });
      mockReadFileSync.mockImplementation((path: unknown) => {
        if (String(path).includes("registry.json")) return registryData;
        return "";
      });

      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "remove",
        canary_id: "canary-remove-file",
        output_format: "json",
      });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.found).toBe(true);
      expect(parsed.fileRemoved).toBe(true);
      expect(parsed.description).toContain("removed");

      // Verify unlinkSync was called for the canary file
      expect(mockUnlinkSync).toHaveBeenCalledWith("/tmp/honeypot/passwords.txt");
    });

    it("should remove a directory canary", async () => {
      const registryData = buildRegistryJson([
        {
          id: "canary-remove-dir",
          type: "directory",
          path: "/tmp/secrets",
          deployedAt: "2025-01-01T00:00:00.000Z",
          status: "active",
          description: "Canary directory",
        },
      ]);

      mockExistsSync.mockImplementation((path: unknown) => {
        if (String(path).includes("registry.json")) return true;
        return false;
      });
      mockReadFileSync.mockImplementation((path: unknown) => {
        if (String(path).includes("registry.json")) return registryData;
        return "";
      });

      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "remove",
        canary_id: "canary-remove-dir",
        output_format: "json",
      });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.found).toBe(true);
      expect(parsed.fileRemoved).toBe(true);

      // Verify rmSync was called for directory removal
      expect(mockRmSync).toHaveBeenCalledWith("/tmp/secrets", { recursive: true, force: true });
    });

    it("should kill honeyport listener and remove iptables rule", async () => {
      const registryData = buildRegistryJson([
        {
          id: "canary-remove-hp",
          type: "honeyport",
          port: 4444,
          pid: 99999,
          deployedAt: "2025-01-01T00:00:00.000Z",
          status: "active",
          description: "Honeyport",
        },
      ]);

      mockExistsSync.mockImplementation((path: unknown) => {
        if (String(path).includes("registry.json")) return true;
        return false;
      });
      mockReadFileSync.mockImplementation((path: unknown) => {
        if (String(path).includes("registry.json")) return registryData;
        return "";
      });

      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "remove",
        canary_id: "canary-remove-hp",
        output_format: "json",
      });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.found).toBe(true);
      expect(parsed.listenerKilled).toBe(true);
      expect(parsed.iptablesRemoved).toBe(true);

      // Verify kill was called
      const killCalls = mockSpawnSafe.mock.calls.filter(
        (call) => call[0] === "kill",
      );
      expect(killCalls.length).toBe(1);
      expect(killCalls[0][1]).toContain("99999");

      // Verify iptables -D was called
      const iptablesCalls = mockSpawnSafe.mock.calls.filter(
        (call) => call[0] === "iptables",
      );
      expect(iptablesCalls.length).toBe(1);
      expect(iptablesCalls[0][1]).toContain("-D");
    });

    it("should update registry with removed status", async () => {
      const registryData = buildRegistryJson([
        {
          id: "canary-remove-status",
          type: "file",
          path: "/tmp/test.txt",
          deployedAt: "2025-01-01T00:00:00.000Z",
          status: "active",
          description: "Test canary",
        },
      ]);

      mockExistsSync.mockImplementation((path: unknown) => {
        if (String(path).includes("registry.json")) return true;
        return false;
      });
      mockReadFileSync.mockImplementation((path: unknown) => {
        if (String(path).includes("registry.json")) return registryData;
        return "";
      });

      const handler = tools.get("honeypot_manage")!.handler;
      await handler({
        action: "remove",
        canary_id: "canary-remove-status",
        output_format: "json",
      });

      const registryWrites = mockSecureWriteFileSync.mock.calls.filter(
        (call) => String(call[0]).includes("registry.json"),
      );
      expect(registryWrites.length).toBe(1);
      const updatedRegistry = JSON.parse(String(registryWrites[0][1]));
      expect(updatedRegistry.canaries[0].status).toBe("removed");
    });

    it("should return text format for removal", async () => {
      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "remove",
        canary_id: "nonexistent",
      });
      expect(result.content[0].text).toContain("Remove Canary");
    });

    it("should handle file removal failure gracefully", async () => {
      const registryData = buildRegistryJson([
        {
          id: "canary-remove-fail",
          type: "file",
          path: "/tmp/gone.txt",
          deployedAt: "2025-01-01T00:00:00.000Z",
          status: "active",
          description: "Test canary",
        },
      ]);

      mockExistsSync.mockImplementation((path: unknown) => {
        if (String(path).includes("registry.json")) return true;
        return false;
      });
      mockReadFileSync.mockImplementation((path: unknown) => {
        if (String(path).includes("registry.json")) return registryData;
        return "";
      });
      mockUnlinkSync.mockImplementation(() => {
        throw new Error("No such file");
      });

      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "remove",
        canary_id: "canary-remove-fail",
        output_format: "json",
      });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.found).toBe(true);
      expect(parsed.fileRemoved).toBe(false);
      // Should still succeed overall
      expect(result.isError).toBeUndefined();
    });
  });

  // ── list ────────────────────────────────────────────────────────────────

  describe("list", () => {
    it("should list empty registry", async () => {
      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "list",
        output_format: "json",
      });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("list");
      expect(parsed.totalCanaries).toBe(0);
      expect(parsed.active).toBe(0);
      expect(parsed.triggered).toBe(0);
      expect(parsed.removed).toBe(0);
      expect(parsed.canaries).toEqual([]);
    });

    it("should list canaries with correct status counts", async () => {
      const registryData = buildRegistryJson([
        {
          id: "canary-1",
          type: "file",
          path: "/tmp/c1.txt",
          deployedAt: "2025-01-01T00:00:00.000Z",
          status: "active",
          description: "Active canary",
        },
        {
          id: "canary-2",
          type: "honeyport",
          port: 4444,
          deployedAt: "2025-01-02T00:00:00.000Z",
          status: "triggered",
          description: "Triggered honeyport",
        },
        {
          id: "canary-3",
          type: "credential",
          path: "/tmp/creds",
          deployedAt: "2025-01-03T00:00:00.000Z",
          status: "removed",
          description: "Removed credential",
        },
      ]);

      mockExistsSync.mockImplementation((path: unknown) => {
        if (String(path).includes("registry.json")) return true;
        return false;
      });
      mockReadFileSync.mockImplementation((path: unknown) => {
        if (String(path).includes("registry.json")) return registryData;
        return "";
      });

      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "list",
        output_format: "json",
      });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.totalCanaries).toBe(3);
      expect(parsed.active).toBe(1);
      expect(parsed.triggered).toBe(1);
      expect(parsed.removed).toBe(1);
      expect(parsed.canaries.length).toBe(3);
    });

    it("should return text format with canary details", async () => {
      const registryData = buildRegistryJson([
        {
          id: "canary-text-test",
          type: "file",
          path: "/tmp/test.txt",
          deployedAt: "2025-01-01T00:00:00.000Z",
          status: "active",
          description: "Test canary",
        },
      ]);

      mockExistsSync.mockImplementation((path: unknown) => {
        if (String(path).includes("registry.json")) return true;
        return false;
      });
      mockReadFileSync.mockImplementation((path: unknown) => {
        if (String(path).includes("registry.json")) return registryData;
        return "";
      });

      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({ action: "list" });

      expect(result.content[0].text).toContain("Canary Registry");
      expect(result.content[0].text).toContain("Total:");
      expect(result.content[0].text).toContain("Active:");
      expect(result.content[0].text).toContain("canary-text-test");
      expect(result.content[0].text).toContain("ACTIVE");
    });

    it("should show no canaries message when empty", async () => {
      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({ action: "list" });
      expect(result.content[0].text).toContain("No canaries deployed");
    });
  });

  // ── Output format tests ─────────────────────────────────────────────────

  describe("output formats", () => {
    it("should return JSON for deploy_canary", async () => {
      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "deploy_canary",
        canary_type: "file",
        canary_path: "/tmp/test.txt",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("deploy_canary");
    });

    it("should return JSON for deploy_honeyport", async () => {
      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "deploy_honeyport",
        port: 4444,
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("deploy_honeyport");
    });

    it("should return JSON for check_triggers", async () => {
      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "check_triggers",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("check_triggers");
    });

    it("should return JSON for remove", async () => {
      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "remove",
        canary_id: "nonexistent",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("remove");
    });

    it("should return JSON for list", async () => {
      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "list",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("list");
    });

    it("should default to text format", async () => {
      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({ action: "list" });
      expect(result.content[0].text).toContain("Honeypot");
    });
  });

  // ── Error handling ──────────────────────────────────────────────────────

  describe("error handling", () => {
    it("should handle spawnSafe throwing errors in deploy_canary", async () => {
      mockSpawnSafe.mockImplementation(() => {
        throw new Error("spawn failed");
      });
      mockSecureWriteFileSync.mockImplementation(() => {
        // Allow file writes to succeed
      });

      const handler = tools.get("honeypot_manage")!.handler;
      // deploy_canary catches errors in runCommand internally
      const result = await handler({
        action: "deploy_canary",
        canary_type: "file",
        canary_path: "/tmp/test.txt",
        output_format: "json",
      });
      expect(result.content).toBeDefined();
    });

    it("should handle command failures in check_triggers gracefully", async () => {
      const registryData = buildRegistryJson([
        {
          id: "canary-err-test",
          type: "file",
          path: "/tmp/test.txt",
          deployedAt: "2025-01-01T00:00:00.000Z",
          status: "active",
          description: "Test",
          accessTimeAtDeploy: "1700000000",
        },
      ]);

      mockExistsSync.mockImplementation((path: unknown) => {
        if (String(path).includes("registry.json")) return true;
        return false;
      });
      mockReadFileSync.mockImplementation((path: unknown) => {
        if (String(path).includes("registry.json")) return registryData;
        return "";
      });

      mockSpawnSafe.mockImplementation(() => {
        return createMockChildProcess("", "command failed", 1);
      });

      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "check_triggers",
        output_format: "json",
      });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle secureWriteFileSync failure in deploy_honeyport", async () => {
      // Allow spawnSafe to work but fail on registry write
      let callCount = 0;
      mockSecureWriteFileSync.mockImplementation(() => {
        callCount++;
        // Throw only for the registry write (not other potential writes)
        throw new Error("Disk full");
      });

      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "deploy_honeyport",
        port: 4444,
        output_format: "json",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("deploy_honeyport failed");
    });

    it("should handle registry read failure gracefully", async () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFileSync.mockImplementation(() => {
        throw new Error("Read error");
      });

      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "list",
        output_format: "json",
      });

      // Should return empty registry, not error
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.totalCanaries).toBe(0);
    });

    it("should handle invalid JSON in registry file", async () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFileSync.mockReturnValue("not valid json{{{");

      const handler = tools.get("honeypot_manage")!.handler;
      const result = await handler({
        action: "list",
        output_format: "json",
      });

      // Should return empty registry
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.totalCanaries).toBe(0);
    });
  });
});
