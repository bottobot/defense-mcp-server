/**
 * Tests for src/tools/app-hardening.ts
 *
 * Covers: tool registration, action routing (audit/recommend/firewall/systemd),
 * schema validation, dry_run defaults, and known app profile lookups.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Mock all external dependencies before imports ──────────────────────────

vi.mock("../../src/core/executor.js", () => ({
  executeCommand: vi.fn().mockResolvedValue({ exitCode: 0, stdout: "", stderr: "", timedOut: false, duration: 10, permissionDenied: false }),
}));
vi.mock("../../src/core/config.js", () => ({
  getConfig: vi.fn().mockReturnValue({ dryRun: true }),
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
}));

import { registerAppHardeningTools } from "../../src/tools/app-hardening.js";
import { executeCommand } from "../../src/core/executor.js";

// ── Helper ─────────────────────────────────────────────────────────────────

type ToolHandler = (params: Record<string, unknown>) => Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }>;

function createMockServer() {
  const tools = new Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>();
  const server = {
    tool: vi.fn((name: string, _desc: string, schema: Record<string, unknown>, handler: ToolHandler) => {
      tools.set(name, { schema, handler });
    }),
  };
  return { server: server as unknown as Parameters<typeof registerAppHardeningTools>[0], tools };
}

describe("app-hardening tools", () => {
  let tools: Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>;

  beforeEach(() => {
    vi.clearAllMocks();
    const mock = createMockServer();
    registerAppHardeningTools(mock.server);
    tools = mock.tools;
  });

  // ── Registration ──────────────────────────────────────────────────────

  it("should register the app_harden tool", () => {
    expect(tools.has("app_harden")).toBe(true);
  });

  // ── Action: recommend ─────────────────────────────────────────────────

  it("should require app_name for recommend action", async () => {
    const handler = tools.get("app_harden")!.handler;
    const result = await handler({ action: "recommend" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("app_name is required");
  });

  it("should return error for unknown app in recommend", async () => {
    const handler = tools.get("app_harden")!.handler;
    const result = await handler({ action: "recommend", app_name: "nonexistent_app_xyz" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Unknown application");
  });

  it("should return hardening guide for known app (nginx)", async () => {
    const handler = tools.get("app_harden")!.handler;
    const result = await handler({ action: "recommend", app_name: "nginx" });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("Nginx");
  });

  // ── Action: firewall ──────────────────────────────────────────────────

  it("should require app_name for firewall action", async () => {
    const handler = tools.get("app_harden")!.handler;
    const result = await handler({ action: "firewall" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("app_name is required");
  });

  it("should return error for unknown app in firewall action", async () => {
    const handler = tools.get("app_harden")!.handler;
    const result = await handler({ action: "firewall", app_name: "fakething" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Unknown application");
  });

  it("should preview firewall rules in dry_run mode", async () => {
    const handler = tools.get("app_harden")!.handler;
    const result = await handler({
      action: "firewall",
      app_name: "redis",
      lan_cidr: "192.168.1.0/24",
      dry_run: true,
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("DRY RUN");
  });

  // ── Action: systemd ───────────────────────────────────────────────────

  it("should require app_name for systemd action", async () => {
    const handler = tools.get("app_harden")!.handler;
    const result = await handler({ action: "systemd" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("app_name is required");
  });

  it("should preview systemd hardening in dry_run mode", async () => {
    const handler = tools.get("app_harden")!.handler;
    vi.mocked(executeCommand).mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "", timedOut: false, duration: 10, permissionDenied: false });
    const result = await handler({
      action: "systemd",
      app_name: "sshd",
      dry_run: true,
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("DRY RUN");
  });

  // ── Action: audit ─────────────────────────────────────────────────────

  it("should handle audit action when no apps are detected", async () => {
    vi.mocked(executeCommand).mockResolvedValue({ exitCode: 0, stdout: "  PID USER COMM\n", stderr: "", timedOut: false, duration: 10, permissionDenied: false });
    const handler = tools.get("app_harden")!.handler;
    const result = await handler({ action: "audit" });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("No known applications detected");
  });
});
