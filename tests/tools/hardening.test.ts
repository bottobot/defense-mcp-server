/**
 * Tests for src/tools/hardening.ts
 *
 * Covers: TOOL-007 (path traversal validation),
 * validatePathWithinAllowed with valid and malicious paths,
 * and rejection of .. sequences.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Mock all external dependencies ─────────────────────────────────────────

vi.mock("../../src/core/executor.js", () => ({
  executeCommand: vi.fn().mockResolvedValue({ exitCode: 0, stdout: "644 root root /etc/passwd", stderr: "" }),
}));
vi.mock("../../src/core/config.js", () => ({
  getConfig: vi.fn().mockReturnValue({ dryRun: true }),
  getToolTimeout: vi.fn().mockReturnValue(30000),
}));
vi.mock("../../src/core/parsers.js", () => ({
  createTextContent: vi.fn((text: string) => ({ type: "text", text })),
  createErrorContent: vi.fn((text: string) => ({ type: "text", text: `Error: ${text}` })),
  parseSysctlOutput: vi.fn().mockReturnValue([]),
  parseSystemctlOutput: vi.fn().mockReturnValue([]),
  formatToolOutput: vi.fn((obj: unknown) => ({ type: "text", text: JSON.stringify(obj) })),
}));
vi.mock("../../src/core/changelog.js", () => ({
  logChange: vi.fn(),
  createChangeEntry: vi.fn().mockReturnValue({}),
  backupFile: vi.fn().mockReturnValue("/tmp/backup"),
}));
vi.mock("../../src/core/sanitizer.js", () => ({
  validateServiceName: vi.fn((s: string) => s),
  validateFilePath: vi.fn((p: string) => p),
  sanitizeArgs: vi.fn((a: string[]) => a),
  validateSysctlKey: vi.fn((k: string) => k),
}));
vi.mock("../../src/core/safeguards.js", () => ({
  SafeguardRegistry: {
    getInstance: vi.fn().mockReturnValue({
      checkSafety: vi.fn().mockResolvedValue({ safe: true, warnings: [], blockers: [], impactedApps: [] }),
    }),
  },
}));
vi.mock("node:fs", () => ({
  readFileSync: vi.fn().mockReturnValue(""),
  existsSync: vi.fn().mockReturnValue(true),
}));

import { registerHardeningTools } from "../../src/tools/hardening.js";

// ── Helper ─────────────────────────────────────────────────────────────────

type ToolHandler = (params: Record<string, unknown>) => Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }>;

function createMockServer() {
  const tools = new Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>();
  const server = {
    tool: vi.fn((name: string, _desc: string, schema: Record<string, unknown>, handler: ToolHandler) => {
      tools.set(name, { schema, handler });
    }),
  };
  return { server: server as unknown as Parameters<typeof registerHardeningTools>[0], tools };
}

describe("hardening tools", () => {
  let tools: Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>;

  beforeEach(() => {
    vi.clearAllMocks();
    const mock = createMockServer();
    registerHardeningTools(mock.server);
    tools = mock.tools;
  });

  // ── Registration ──────────────────────────────────────────────────────

  it("should register hardening tools", () => {
    expect(tools.has("harden_sysctl")).toBe(true);
    expect(tools.has("harden_service")).toBe(true);
    expect(tools.has("harden_permissions")).toBe(true);
    expect(tools.has("harden_systemd")).toBe(true);
    expect(tools.has("harden_kernel")).toBe(true);
    expect(tools.has("harden_bootloader")).toBe(true);
  });

  // ── TOOL-007: Path traversal validation ──────────────────────────────

  it("should reject path containing .. sequences (TOOL-007)", async () => {
    const handler = tools.get("harden_permissions")!.handler;
    const result = await handler({
      action: "check",
      path: "/etc/../root/.ssh/authorized_keys",
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Path traversal");
  });

  it("should reject path with encoded .. traversal (TOOL-007)", async () => {
    const handler = tools.get("harden_permissions")!.handler;
    const result = await handler({
      action: "fix",
      path: "/tmp/../../etc/shadow",
      mode: "600",
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Path traversal");
  });

  it("should reject path outside allowed directories (TOOL-007)", async () => {
    const handler = tools.get("harden_permissions")!.handler;
    const result = await handler({
      action: "check",
      path: "/proc/self/environ",
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("outside allowed directories");
  });

  it("should accept path within /etc (TOOL-007)", async () => {
    const handler = tools.get("harden_permissions")!.handler;
    const result = await handler({
      action: "check",
      path: "/etc/ssh/sshd_config",
    });
    expect(result.isError).toBeUndefined();
  });

  it("should accept path within /var (TOOL-007)", async () => {
    const handler = tools.get("harden_permissions")!.handler;
    const result = await handler({
      action: "check",
      path: "/var/log/auth.log",
    });
    expect(result.isError).toBeUndefined();
  });

  // ── Required params ──────────────────────────────────────────────────

  it("should require path for check action", async () => {
    const handler = tools.get("harden_permissions")!.handler;
    const result = await handler({ action: "check" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("path");
  });

  it("should require path for fix action", async () => {
    const handler = tools.get("harden_permissions")!.handler;
    const result = await handler({ action: "fix" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("path");
  });

  it("should require mode/owner/group for fix action", async () => {
    const handler = tools.get("harden_permissions")!.handler;
    const result = await handler({
      action: "fix",
      path: "/etc/passwd",
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("mode");
  });

  // ── harden_sysctl tests ──────────────────────────────────────────────

  describe("harden_sysctl", () => {
    it("should handle sysctl get with key", async () => {
      const handler = tools.get("harden_sysctl")!.handler;
      const result = await handler({
        action: "get",
        key: "net.ipv4.ip_forward",
      });
      expect(result.content).toBeDefined();
    });

    it("should handle sysctl get all", async () => {
      const handler = tools.get("harden_sysctl")!.handler;
      const result = await handler({
        action: "get",
        all: true,
      });
      expect(result.content).toBeDefined();
    });

    it("should handle sysctl get with pattern", async () => {
      const handler = tools.get("harden_sysctl")!.handler;
      const result = await handler({
        action: "get",
        pattern: "ipv4",
      });
      expect(result.content).toBeDefined();
    });

    it("should require key or all/pattern for get", async () => {
      const handler = tools.get("harden_sysctl")!.handler;
      const result = await handler({ action: "get" });
      expect(result.isError).toBe(true);
    });

    it("should require key for set action", async () => {
      const handler = tools.get("harden_sysctl")!.handler;
      const result = await handler({ action: "set", value: "0", dry_run: true });
      expect(result.isError).toBe(true);
    });

    it("should require value for set action", async () => {
      const handler = tools.get("harden_sysctl")!.handler;
      const result = await handler({ action: "set", key: "net.ipv4.ip_forward", dry_run: true });
      expect(result.isError).toBe(true);
    });

    it("should handle sysctl audit action", async () => {
      const handler = tools.get("harden_sysctl")!.handler;
      const result = await handler({ action: "audit", category: "all" });
      expect(result.content).toBeDefined();
    });
  });

  // ── harden_service tests ─────────────────────────────────────────────

  describe("harden_service", () => {
    it("should require service for manage action", async () => {
      const handler = tools.get("harden_service")!.handler;
      const result = await handler({ action: "manage", service_action: "status" });
      expect(result.isError).toBe(true);
    });

    it("should require service_action for manage action", async () => {
      const handler = tools.get("harden_service")!.handler;
      const result = await handler({ action: "manage", service: "ssh.service" });
      expect(result.isError).toBe(true);
    });

    it("should handle service audit action", async () => {
      const handler = tools.get("harden_service")!.handler;
      const result = await handler({ action: "audit" });
      expect(result.content).toBeDefined();
    });
  });

  // ── harden_permissions audit ─────────────────────────────────────────

  describe("harden_permissions audit", () => {
    it("should handle audit action with default scope", async () => {
      const handler = tools.get("harden_permissions")!.handler;
      const result = await handler({ action: "audit", scope: "all" });
      expect(result.content).toBeDefined();
    });

    it("should handle audit action with specific scope", async () => {
      const handler = tools.get("harden_permissions")!.handler;
      const result = await handler({ action: "audit", scope: "ssh" });
      expect(result.content).toBeDefined();
    });
  });

  // ── harden_kernel tests ──────────────────────────────────────────────

  describe("harden_kernel", () => {
    it("should handle kernel audit action", async () => {
      const handler = tools.get("harden_kernel")!.handler;
      const result = await handler({ action: "audit", check_type: "all" });
      expect(result.content).toBeDefined();
    });

    it("should handle modules action", async () => {
      const handler = tools.get("harden_kernel")!.handler;
      const result = await handler({ action: "modules" });
      expect(result.content).toBeDefined();
    });

    it("should handle coredump action in dry_run", async () => {
      const handler = tools.get("harden_kernel")!.handler;
      const result = await handler({ action: "coredump", dry_run: true });
      expect(result.content).toBeDefined();
    });
  });

  // ── harden_bootloader tests ──────────────────────────────────────────

  describe("harden_bootloader", () => {
    it("should handle bootloader audit action", async () => {
      const handler = tools.get("harden_bootloader")!.handler;
      const result = await handler({ action: "audit" });
      expect(result.content).toBeDefined();
    });

    it("should require configure_action for configure", async () => {
      const handler = tools.get("harden_bootloader")!.handler;
      const result = await handler({ action: "configure", dry_run: true });
      expect(result.isError).toBe(true);
    });
  });
});
