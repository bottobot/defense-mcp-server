/**
 * Tests for src/core/tool-wrapper.ts
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Mock all external dependencies ───────────────────────────────────────────

const mockRunPreflight = vi.fn(async () => ({
  toolName: "test_tool",
  passed: true,
  timestamp: Date.now(),
  duration: 5,
  dependencies: { checked: [], missing: [], installed: [], warnings: [] },
  privileges: { satisfied: true, issues: [], recommendations: [] },
  summary: "✅ Pre-flight passed",
  errors: [],
  warnings: [],
}));

const mockFormatSummary = vi.fn(() => "summary text");
const mockFormatStatusMessage = vi.fn(() => "[pre-flight ✓] All checks passed (0 deps)");
const mockClearCache = vi.fn();

vi.mock("../../src/core/preflight.js", () => ({
  PreflightEngine: {
    instance: vi.fn(() => ({
      runPreflight: mockRunPreflight,
      formatSummary: mockFormatSummary,
      formatStatusMessage: mockFormatStatusMessage,
      clearCache: mockClearCache,
    })),
  },
}));

const mockRegistryManifests = new Map<string, any>();
vi.mock("../../src/core/tool-registry.js", () => ({
  ToolRegistry: {
    instance: vi.fn(() => ({
      getManifest: vi.fn((name: string) => mockRegistryManifests.get(name)),
    })),
  },
}));

vi.mock("../../src/core/privilege-manager.js", () => ({
  PrivilegeManager: {
    instance: vi.fn(() => ({
      clearCache: vi.fn(),
    })),
  },
}));

vi.mock("../../src/core/sudo-guard.js", () => ({
  SudoGuard: {
    isResponsePermissionError: vi.fn(() => false),
    extractResponseText: vi.fn(() => undefined),
    createElevationPrompt: vi.fn((toolName: string, reason?: string) => ({
      content: [{ type: "text", text: "🛑 ELEVATION REQUIRED" }],
      isError: true,
      _meta: {
        elevationRequired: true,
        haltWorkflow: true,
        failedTool: toolName,
        reason: reason ?? "Requires elevation",
        elevationTool: "sudo_elevate",
      },
    })),
  },
}));

import {
  createPreflightServer,
  invalidatePreflightCaches,
} from "../../src/core/tool-wrapper.js";
import { SudoGuard } from "../../src/core/sudo-guard.js";

// ── Fake McpServer ───────────────────────────────────────────────────────────

function createFakeMcpServer() {
  const registeredTools: Record<string, Function> = {};
  return {
    tool: vi.fn((...args: unknown[]) => {
      const name = args[0] as string;
      const handler = args[args.length - 1] as Function;
      registeredTools[name] = handler;
    }),
    _registeredTools: registeredTools,
    connect: vi.fn(),
    resource: vi.fn(),
  };
}

describe("createPreflightServer", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockRegistryManifests.clear();
    mockRunPreflight.mockResolvedValue({
      toolName: "test_tool",
      passed: true,
      timestamp: Date.now(),
      duration: 5,
      dependencies: { checked: [], missing: [], installed: [], warnings: [] },
      privileges: { satisfied: true, issues: [], recommendations: [] },
      summary: "✅ Pre-flight passed",
      errors: [],
      warnings: [],
    } as any);
  });

  // ── Proxy creation ─────────────────────────────────────────────────────────

  it("returns the raw server when disabled", () => {
    const server = createFakeMcpServer();
    const proxy = createPreflightServer(server as any, { enabled: false });
    expect(proxy).toBe(server);
  });

  it("returns a proxy when enabled", () => {
    const server = createFakeMcpServer();
    const proxy = createPreflightServer(server as any, { enabled: true });
    expect(proxy).not.toBe(server);
  });

  it("passes through non-tool properties unchanged", () => {
    const server = createFakeMcpServer();
    const proxy = createPreflightServer(server as any, { enabled: true });
    expect((proxy as any).connect).toBe(server.connect);
    expect((proxy as any).resource).toBe(server.resource);
  });

  // ── Bypass tools ───────────────────────────────────────────────────────────

  it("bypasses pre-flight for sudo_session tool", () => {
    const server = createFakeMcpServer();
    const proxy = createPreflightServer(server as any, { enabled: true });

    const handler = vi.fn(async () => ({ content: [{ type: "text", text: "OK" }] }));
    (proxy as any).tool("sudo_session", {}, handler);

    // The original server.tool should have been called with the ORIGINAL handler
    // (not wrapped) because sudo_session is in the bypass set
    expect(server.tool).toHaveBeenCalledWith("sudo_session", {}, handler);
  });

  it("bypasses pre-flight for custom additional bypass tools", () => {
    const server = createFakeMcpServer();
    const proxy = createPreflightServer(server as any, {
      enabled: true,
      additionalBypass: ["my_custom_tool"],
    });

    const handler = vi.fn();
    (proxy as any).tool("my_custom_tool", {}, handler);
    expect(server.tool).toHaveBeenCalledWith("my_custom_tool", {}, handler);
  });

  // ── Pre-flight wrapping ────────────────────────────────────────────────────

  it("wraps non-bypass tool handlers with pre-flight", () => {
    const server = createFakeMcpServer();
    const proxy = createPreflightServer(server as any, { enabled: true });

    const originalHandler = vi.fn(async () => ({
      content: [{ type: "text", text: "Tool output" }],
    }));

    (proxy as any).tool("firewall_iptables", {}, originalHandler);

    // server.tool should have been called, but with a DIFFERENT handler
    expect(server.tool).toHaveBeenCalled();
    const registeredArgs = (server.tool as any).mock.calls[0];
    const wrappedHandler = registeredArgs[registeredArgs.length - 1];
    expect(wrappedHandler).not.toBe(originalHandler);
  });

  it("calls original handler when pre-flight passes", async () => {
    const server = createFakeMcpServer();
    const proxy = createPreflightServer(server as any, { enabled: true });

    const originalHandler = vi.fn(async () => ({
      content: [{ type: "text", text: "Tool output" }],
    }));

    (proxy as any).tool("test_tool", {}, originalHandler);

    // Extract the wrapped handler and call it
    const registeredArgs = (server.tool as any).mock.calls[0];
    const wrappedHandler = registeredArgs[registeredArgs.length - 1];
    const result = await wrappedHandler({ action: "list" });

    expect(originalHandler).toHaveBeenCalled();
    expect(result).toEqual({
      content: [{ type: "text", text: "Tool output" }],
    });
  });

  it("returns error when pre-flight fails (non-sudo)", async () => {
    mockRunPreflight.mockResolvedValueOnce({
      toolName: "test_tool",
      passed: false,
      timestamp: Date.now(),
      duration: 5,
      dependencies: {
        checked: [],
        missing: [{ name: "nmap", type: "binary", required: true, found: false }],
        installed: [],
        warnings: [],
      },
      privileges: { satisfied: true, issues: [], recommendations: [] },
      summary: "❌ Pre-flight FAILED",
      errors: ["Missing required binary: nmap"],
      warnings: [],
    } as any);

    const server = createFakeMcpServer();
    const proxy = createPreflightServer(server as any, { enabled: true });

    const originalHandler = vi.fn();
    (proxy as any).tool("test_tool", {}, originalHandler);

    const registeredArgs = (server.tool as any).mock.calls[0];
    const wrappedHandler = registeredArgs[registeredArgs.length - 1];
    const result = await wrappedHandler();

    expect(originalHandler).not.toHaveBeenCalled();
    expect(result.isError).toBe(true);
  });

  it("returns elevation prompt when pre-flight fails with sudo issue", async () => {
    mockRunPreflight.mockResolvedValueOnce({
      toolName: "log_auditd",
      passed: false,
      timestamp: Date.now(),
      duration: 5,
      dependencies: { checked: [], missing: [], installed: [], warnings: [] },
      privileges: {
        satisfied: false,
        issues: [
          {
            type: "sudo-required",
            description: "Sudo required",
            operation: "log_auditd",
            resolution: "Call sudo_elevate",
          },
        ],
        recommendations: [],
      },
      summary: "❌ Pre-flight FAILED",
      errors: ["Sudo required"],
      warnings: [],
    } as any);

    const server = createFakeMcpServer();
    const proxy = createPreflightServer(server as any, { enabled: true });

    const originalHandler = vi.fn();
    (proxy as any).tool("log_auditd", {}, originalHandler);

    const registeredArgs = (server.tool as any).mock.calls[0];
    const wrappedHandler = registeredArgs[registeredArgs.length - 1];
    const result = await wrappedHandler();

    expect(originalHandler).not.toHaveBeenCalled();
    expect(result._meta.elevationRequired).toBe(true);
    expect(result._meta.failedTool).toBe("log_auditd");
  });

  // ── Runtime permission error detection ─────────────────────────────────────

  it("detects runtime permission errors and returns elevation prompt", async () => {
    vi.mocked(SudoGuard.isResponsePermissionError).mockReturnValueOnce(true);
    vi.mocked(SudoGuard.extractResponseText).mockReturnValueOnce("permission denied");

    const server = createFakeMcpServer();
    const proxy = createPreflightServer(server as any, { enabled: true });

    const originalHandler = vi.fn(async () => ({
      content: [{ type: "text", text: "Error: permission denied" }],
      isError: true,
    }));

    (proxy as any).tool("firewall_iptables", {}, originalHandler);

    const registeredArgs = (server.tool as any).mock.calls[0];
    const wrappedHandler = registeredArgs[registeredArgs.length - 1];
    const result = await wrappedHandler();

    expect(result._meta.elevationRequired).toBe(true);
  });

  // ── Error safety ───────────────────────────────────────────────────────────

  it("falls through to original handler when pre-flight throws", async () => {
    mockRunPreflight.mockRejectedValueOnce(new Error("Pre-flight crashed"));

    const server = createFakeMcpServer();
    const proxy = createPreflightServer(server as any, { enabled: true });

    const originalHandler = vi.fn(async () => ({
      content: [{ type: "text", text: "Tool output despite preflight error" }],
    }));

    (proxy as any).tool("test_tool", {}, originalHandler);

    const registeredArgs = (server.tool as any).mock.calls[0];
    const wrappedHandler = registeredArgs[registeredArgs.length - 1];
    const result = await wrappedHandler();

    expect(originalHandler).toHaveBeenCalled();
    expect(result.content[0].text).toContain("Tool output despite preflight error");
  });

  // ── Short args passthrough ─────────────────────────────────────────────────

  it("passes through when tool() called with less than 2 args", () => {
    const server = createFakeMcpServer();
    const proxy = createPreflightServer(server as any, { enabled: true });

    // Call with just 1 arg (should passthrough)
    (proxy as any).tool("single_arg");
    expect(server.tool).toHaveBeenCalledWith("single_arg");
  });
});

describe("invalidatePreflightCaches", () => {
  it("calls clearCache on PreflightEngine and PrivilegeManager", () => {
    invalidatePreflightCaches();
    expect(mockClearCache).toHaveBeenCalled();
  });
});
