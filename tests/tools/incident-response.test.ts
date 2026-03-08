/**
 * Tests for src/tools/incident-response.ts
 *
 * Covers: TOOL-001 (parameterized commands),
 * step structure is { command, args } not shell strings,
 * and schema validation.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Mock all external dependencies ─────────────────────────────────────────

const { mockExecuteCommand } = vi.hoisted(() => ({
  mockExecuteCommand: vi.fn().mockResolvedValue({ exitCode: 0, stdout: "", stderr: "" }),
}));

vi.mock("../../src/core/executor.js", () => ({
  executeCommand: mockExecuteCommand,
}));
vi.mock("../../src/core/config.js", () => ({
  getConfig: vi.fn().mockReturnValue({ dryRun: true }),
}));
vi.mock("../../src/core/parsers.js", () => ({
  createTextContent: vi.fn((text: string) => ({ type: "text", text })),
  createErrorContent: vi.fn((text: string) => ({ type: "text", text: `Error: ${text}` })),
}));

import { registerIncidentResponseTools } from "../../src/tools/incident-response.js";

// ── Helper ─────────────────────────────────────────────────────────────────

type ToolHandler = (params: Record<string, unknown>) => Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }>;

function createMockServer() {
  const tools = new Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>();
  const server = {
    tool: vi.fn((name: string, _desc: string, schema: Record<string, unknown>, handler: ToolHandler) => {
      tools.set(name, { schema, handler });
    }),
  };
  return { server: server as unknown as Parameters<typeof registerIncidentResponseTools>[0], tools };
}

describe("incident-response tools", () => {
  let tools: Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>;

  beforeEach(() => {
    vi.clearAllMocks();
    const mock = createMockServer();
    registerIncidentResponseTools(mock.server);
    tools = mock.tools;
  });

  // ── Registration ──────────────────────────────────────────────────────

  it("should register the incident_response tool", () => {
    expect(tools.has("incident_response")).toBe(true);
  });

  // ── TOOL-001: Parameterized commands ─────────────────────────────────

  it("should use parameterized commands for collection steps (TOOL-001)", async () => {
    const handler = tools.get("incident_response")!.handler;
    await handler({
      action: "collect",
      output_dir: "/tmp/ir-collection",
      dry_run: false,
    });

    // executeCommand should have been called with { command, args } pattern
    // not with shell strings like "ps auxwww > file"
    const calls = mockExecuteCommand.mock.calls;
    // First call is mkdir -p, then collection steps follow
    expect(calls.length).toBeGreaterThan(1);

    // Check that collection steps use command + args pattern
    for (const call of calls) {
      const opts = call[0];
      expect(typeof opts.command).toBe("string");
      expect(Array.isArray(opts.args)).toBe(true);
      // Verify no shell string injection — command should be a single binary name
      expect(opts.command).not.toContain(" ");
      expect(opts.command).not.toContain(";");
      expect(opts.command).not.toContain("|");
    }
  });

  it("should use { command, args } structure not shell strings (TOOL-001)", async () => {
    const handler = tools.get("incident_response")!.handler;
    await handler({
      action: "collect",
      output_dir: "/tmp/ir-test",
      dry_run: false,
    });

    // Verify that steps like "ps auxwww" are passed as { command: "ps", args: ["auxwww"] }
    const psCall = mockExecuteCommand.mock.calls.find(
      (call) => call[0].command === "ps"
    );
    expect(psCall).toBeDefined();
    expect(psCall![0].args).toContain("auxwww");
  });

  // ── Dry-run mode ─────────────────────────────────────────────────────

  it("should produce dry-run output for collect action", async () => {
    const handler = tools.get("incident_response")!.handler;
    const result = await handler({
      action: "collect",
      output_dir: "/tmp/ir-collection",
      dry_run: true,
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("DRY-RUN");
    expect(result.content[0].text).toContain("Volatile Data Collection Plan");
  });

  it("should list all collection steps in dry-run output", async () => {
    const handler = tools.get("incident_response")!.handler;
    const result = await handler({
      action: "collect",
      output_dir: "/tmp/ir-collection",
      dry_run: true,
    });
    // Should list processes, network connections, etc.
    expect(result.content[0].text).toContain("processes");
    expect(result.content[0].text).toContain("Network connections");
  });

  // ── IOC scan ─────────────────────────────────────────────────────────

  it("should run IOC scan without errors", async () => {
    const handler = tools.get("incident_response")!.handler;
    const result = await handler({
      action: "ioc_scan",
      check_type: "all",
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("IOC");
  });

  // ── Timeline ─────────────────────────────────────────────────────────

  it("should run timeline without errors", async () => {
    const handler = tools.get("incident_response")!.handler;
    const result = await handler({
      action: "timeline",
      path: "/",
      hours: 24,
      exclude_paths: "/proc,/sys,/dev,/run",
      file_types: "all",
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("Timeline");
  });
});
