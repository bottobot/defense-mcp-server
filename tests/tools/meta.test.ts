/**
 * Tests for src/tools/meta.ts
 *
 * Covers: TOOL-004 (schedule validation for defense_scheduled_audit),
 * TOOL-005 (defense_workflow safeguard checks), and schema validation.
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
  getConfig: vi.fn().mockReturnValue({ dryRun: true, policyDir: "/tmp/policies" }),
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
  readFileSync: vi.fn().mockReturnValue("[]"),
  writeFileSync: vi.fn(),
  mkdirSync: vi.fn(),
  readdirSync: vi.fn().mockReturnValue([]),
}));
vi.mock("node:path", async () => {
  const actual = await vi.importActual("node:path");
  return actual;
});
vi.mock("node:os", () => ({
  homedir: vi.fn().mockReturnValue("/tmp/test-home"),
}));

import { registerMetaTools } from "../../src/tools/meta.js";

// ── Helper ─────────────────────────────────────────────────────────────────

type ToolHandler = (params: Record<string, unknown>) => Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }>;

function createMockServer() {
  const tools = new Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>();
  const server = {
    tool: vi.fn((name: string, _desc: string, schema: Record<string, unknown>, handler: ToolHandler) => {
      tools.set(name, { schema, handler });
    }),
  };
  return { server: server as unknown as Parameters<typeof registerMetaTools>[0], tools };
}

describe("meta tools", () => {
  let tools: Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>;

  beforeEach(() => {
    vi.clearAllMocks();
    const mock = createMockServer();
    registerMetaTools(mock.server);
    tools = mock.tools;
  });

  // ── Registration ──────────────────────────────────────────────────────

  it("should register all meta tools", () => {
    expect(tools.has("defense_check_tools")).toBe(true);
    expect(tools.has("defense_workflow")).toBe(true);
    expect(tools.has("defense_change_history")).toBe(true);
    expect(tools.has("defense_security_posture")).toBe(true);
    expect(tools.has("defense_scheduled_audit")).toBe(true);
  });

  // ── TOOL-004: Schedule validation ────────────────────────────────────

  it("should reject schedule with shell metacharacters (TOOL-004)", async () => {
    const handler = tools.get("defense_scheduled_audit")!.handler;
    const result = await handler({
      action: "create",
      name: "test-audit",
      command: "lynis audit system",
      schedule: "0 2 * * *; rm -rf /",
      useSystemd: false,
      dryRun: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("forbidden characters");
  });

  it("should reject cron schedule with wrong number of fields (TOOL-004)", async () => {
    const handler = tools.get("defense_scheduled_audit")!.handler;
    const result = await handler({
      action: "create",
      name: "test-audit",
      command: "lynis audit system",
      schedule: "0 2 *",
      useSystemd: false,
      dryRun: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Expected 5 fields");
  });

  it("should accept valid cron schedule (TOOL-004)", async () => {
    const handler = tools.get("defense_scheduled_audit")!.handler;
    const result = await handler({
      action: "create",
      name: "test-audit",
      command: "lynis audit system",
      schedule: "0 2 * * *",
      useSystemd: false,
      dryRun: true,
    });
    expect(result.isError).toBeUndefined();
  });

  it("should reject schedule with backticks (TOOL-004)", async () => {
    const handler = tools.get("defense_scheduled_audit")!.handler;
    const result = await handler({
      action: "create",
      name: "test-audit",
      command: "lynis audit system",
      schedule: "`rm -rf /` * * * *",
      useSystemd: true,
      dryRun: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("forbidden characters");
  });

  // ── Audit name validation ────────────────────────────────────────────

  it("should reject audit name with invalid characters", async () => {
    const handler = tools.get("defense_scheduled_audit")!.handler;
    const result = await handler({
      action: "create",
      name: "test audit!",
      command: "lynis audit system",
      schedule: "0 2 * * *",
      useSystemd: true,
      dryRun: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Invalid audit name");
  });

  // ── TOOL-005: defense_workflow safeguard checks ──────────────────────

  it("should require workflow for run action (TOOL-005)", async () => {
    const handler = tools.get("defense_workflow")!.handler;
    const result = await handler({
      action: "run",
      dry_run: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("workflow is required");
  });

  it("should produce dry-run output for workflow run (TOOL-005)", async () => {
    const handler = tools.get("defense_workflow")!.handler;
    const result = await handler({
      action: "run",
      workflow: "quick_harden",
      dry_run: true,
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("DRY RUN");
  });

  // ── Required params ──────────────────────────────────────────────────

  it("should require name for defense_scheduled_audit create", async () => {
    const handler = tools.get("defense_scheduled_audit")!.handler;
    const result = await handler({
      action: "create",
      command: "lynis audit system",
      schedule: "0 2 * * *",
      dryRun: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("name is required");
  });

  it("should require objective for workflow suggest", async () => {
    const handler = tools.get("defense_workflow")!.handler;
    const result = await handler({
      action: "suggest",
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("objective is required");
  });
});
