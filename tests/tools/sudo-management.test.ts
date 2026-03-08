/**
 * Tests for src/tools/sudo-management.ts
 *
 * Covers: tool registration, sudo_elevate, sudo_status, sudo_drop,
 * sudo_extend, preflight_batch_check, and sudo_elevate_gui.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/core/spawn-safe.js", () => ({
  spawnSafe: vi.fn().mockReturnValue({
    on: vi.fn(),
    unref: vi.fn(),
    stdout: { on: vi.fn() },
    stderr: { on: vi.fn() },
  }),
}));
vi.mock("../../src/core/sudo-session.js", () => {
  const mockSession = {
    isElevated: vi.fn().mockReturnValue(false),
    getStatus: vi.fn().mockReturnValue({ elevated: false, username: "", expiresAt: null, remainingSeconds: null }),
    elevate: vi.fn().mockResolvedValue({ success: true }),
    drop: vi.fn(),
    extend: vi.fn().mockReturnValue(true),
    setDefaultTimeout: vi.fn(),
  };
  return {
    SudoSession: {
      getInstance: vi.fn().mockReturnValue(mockSession),
    },
  };
});
vi.mock("../../src/core/config.js", () => ({
  getConfig: vi.fn().mockReturnValue({ dryRun: true, sudoSessionTimeout: undefined }),
}));
vi.mock("../../src/core/parsers.js", () => ({
  createTextContent: vi.fn((text: string) => ({ type: "text", text })),
  createErrorContent: vi.fn((text: string) => ({ type: "text", text: `Error: ${text}` })),
}));
vi.mock("../../src/core/tool-wrapper.js", () => ({
  invalidatePreflightCaches: vi.fn(),
}));
vi.mock("../../src/core/preflight.js", () => ({
  PreflightEngine: {
    instance: vi.fn().mockReturnValue({
      runPreflight: vi.fn().mockResolvedValue({
        passed: true,
        dependencies: { missing: [] },
        privileges: { issues: [] },
        errors: [],
      }),
    }),
  },
}));
vi.mock("../../src/core/tool-registry.js", () => ({
  ToolRegistry: {
    instance: vi.fn().mockReturnValue({
      getManifest: vi.fn().mockReturnValue({ sudo: "never", sudoReason: "" }),
    }),
  },
}));
vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return { ...actual, existsSync: vi.fn().mockReturnValue(false), statSync: vi.fn(), readFileSync: vi.fn(), writeFileSync: vi.fn(), unlinkSync: vi.fn() };
});

import { registerSudoManagementTools } from "../../src/tools/sudo-management.js";
import { SudoSession } from "../../src/core/sudo-session.js";

type ToolHandler = (params: Record<string, unknown>) => Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean; _meta?: Record<string, unknown> }>;

function createMockServer() {
  const tools = new Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>();
  const server = {
    tool: vi.fn((name: string, _desc: string, schema: Record<string, unknown>, handler: ToolHandler) => {
      tools.set(name, { schema, handler });
    }),
  };
  return { server: server as unknown as Parameters<typeof registerSudoManagementTools>[0], tools };
}

describe("sudo-management tools", () => {
  let tools: Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>;

  beforeEach(() => {
    vi.clearAllMocks();
    const mock = createMockServer();
    registerSudoManagementTools(mock.server);
    tools = mock.tools;
  });

  it("should register all 6 sudo management tools", () => {
    expect(tools.has("sudo_elevate")).toBe(true);
    expect(tools.has("sudo_elevate_gui")).toBe(true);
    expect(tools.has("sudo_status")).toBe(true);
    expect(tools.has("sudo_drop")).toBe(true);
    expect(tools.has("sudo_extend")).toBe(true);
    expect(tools.has("preflight_batch_check")).toBe(true);
  });

  // ── sudo_elevate ──────────────────────────────────────────────────────

  it("should elevate successfully with valid password", async () => {
    const session = SudoSession.getInstance();
    vi.mocked(session.elevate).mockResolvedValue({ success: true });
    vi.mocked(session.getStatus).mockReturnValue({ elevated: true, username: "testuser", expiresAt: "2025-01-01T00:00:00Z", remainingSeconds: 900 });

    const handler = tools.get("sudo_elevate")!.handler;
    const result = await handler({ password: "testpass", timeout_minutes: 15 });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("elevated successfully");
  });

  it("should report error when elevation fails", async () => {
    const session = SudoSession.getInstance();
    vi.mocked(session.elevate).mockResolvedValue({ success: false, error: "wrong password" });

    const handler = tools.get("sudo_elevate")!.handler;
    const result = await handler({ password: "badpass", timeout_minutes: 15 });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Elevation failed");
  });

  it("should report already elevated if session is active", async () => {
    const session = SudoSession.getInstance();
    vi.mocked(session.isElevated).mockReturnValue(true);
    vi.mocked(session.getStatus).mockReturnValue({ elevated: true, username: "testuser", expiresAt: "2025-01-01T00:00:00Z", remainingSeconds: 900 });

    const handler = tools.get("sudo_elevate")!.handler;
    const result = await handler({ password: "testpass", timeout_minutes: 15 });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("Already elevated");
  });

  // ── sudo_status ───────────────────────────────────────────────────────

  it("should report not elevated when no session", async () => {
    const session = SudoSession.getInstance();
    vi.mocked(session.getStatus).mockReturnValue({ elevated: false, username: "", expiresAt: null, remainingSeconds: null });

    const handler = tools.get("sudo_status")!.handler;
    const result = await handler({});
    expect(result.content[0].text).toContain("Not elevated");
  });

  // ── sudo_drop ─────────────────────────────────────────────────────────

  it("should drop session when elevated", async () => {
    const session = SudoSession.getInstance();
    vi.mocked(session.isElevated).mockReturnValue(true);
    vi.mocked(session.getStatus).mockReturnValue({ elevated: true, username: "testuser", expiresAt: "2025-01-01T00:00:00Z", remainingSeconds: 900 });

    const handler = tools.get("sudo_drop")!.handler;
    const result = await handler({});
    expect(result.content[0].text).toContain("Privileges dropped");
    expect(session.drop).toHaveBeenCalled();
  });

  // ── sudo_extend ───────────────────────────────────────────────────────

  it("should fail to extend when not elevated", async () => {
    const session = SudoSession.getInstance();
    vi.mocked(session.isElevated).mockReturnValue(false);

    const handler = tools.get("sudo_extend")!.handler;
    const result = await handler({ minutes: 15 });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("No active sudo session");
  });

  // ── preflight_batch_check ─────────────────────────────────────────────

  it("should report tools as ready when preflight passes", async () => {
    const handler = tools.get("preflight_batch_check")!.handler;
    const result = await handler({ tools: ["sudo_status"] });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("Ready");
  });
});
