/**
 * Tests for src/tools/sudo-management.ts
 *
 * Covers: tool registration, sudo_session with actions:
 * elevate, elevate_gui, status, drop, extend, preflight_check.
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
  const defaultRateLimit = { limited: false, attemptsRemaining: 5 };
  const mockSession = {
    isElevated: vi.fn().mockReturnValue(false),
    getStatus: vi.fn().mockReturnValue({
      elevated: false,
      username: "",
      expiresAt: null,
      remainingSeconds: null,
      rateLimit: defaultRateLimit,
    }),
    elevate: vi.fn().mockResolvedValue({ success: true }),
    drop: vi.fn(),
    extend: vi.fn().mockReturnValue(true),
    setDefaultTimeout: vi.fn(),
    getRateLimitStatus: vi.fn().mockReturnValue(defaultRateLimit),
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

  it("should register exactly 1 tool: sudo_session", () => {
    expect(tools.size).toBe(1);
    expect(tools.has("sudo_session")).toBe(true);
  });

  // ── elevate action ────────────────────────────────────────────────────

  it("should elevate successfully with valid password", async () => {
    const session = SudoSession.getInstance();
    vi.mocked(session.elevate).mockResolvedValue({ success: true });
    vi.mocked(session.getStatus).mockReturnValue({
      elevated: true,
      username: "testuser",
      expiresAt: "2025-01-01T00:00:00Z",
      remainingSeconds: 900,
      rateLimit: { limited: false, attemptsRemaining: 5 },
    });

    const handler = tools.get("sudo_session")!.handler;
    const result = await handler({ action: "elevate", password: "testpass", timeout_minutes: 15 });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("elevated successfully");
  });

  it("should report error when elevation fails", async () => {
    const session = SudoSession.getInstance();
    vi.mocked(session.elevate).mockResolvedValue({ success: false, error: "wrong password" });
    // getRateLimitStatus is called after a failed attempt — return 4 remaining
    vi.mocked(session.getRateLimitStatus).mockReturnValue({ limited: false, attemptsRemaining: 4 });

    const handler = tools.get("sudo_session")!.handler;
    const result = await handler({ action: "elevate", password: "badpass", timeout_minutes: 15 });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Authentication failed");
  });

  it("should report already elevated if session is active", async () => {
    const session = SudoSession.getInstance();
    vi.mocked(session.isElevated).mockReturnValue(true);
    vi.mocked(session.getStatus).mockReturnValue({
      elevated: true,
      username: "testuser",
      expiresAt: "2025-01-01T00:00:00Z",
      remainingSeconds: 900,
      rateLimit: { limited: false, attemptsRemaining: 5 },
    });

    const handler = tools.get("sudo_session")!.handler;
    const result = await handler({ action: "elevate", password: "testpass", timeout_minutes: 15 });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("Already elevated");
  });

  it("should require password for elevate action", async () => {
    const handler = tools.get("sudo_session")!.handler;
    const result = await handler({ action: "elevate", timeout_minutes: 15 });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("password parameter is required");
  });

  // ── status action ─────────────────────────────────────────────────────

  it("should report not elevated when no session", async () => {
    const session = SudoSession.getInstance();
    vi.mocked(session.getStatus).mockReturnValue({
      elevated: false,
      username: "",
      expiresAt: null,
      remainingSeconds: null,
      rateLimit: { limited: false, attemptsRemaining: 5 },
    });

    const handler = tools.get("sudo_session")!.handler;
    const result = await handler({ action: "status" });
    expect(result.content[0].text).toContain("Not elevated");
  });

  // ── drop action ───────────────────────────────────────────────────────

  it("should drop session when elevated", async () => {
    const session = SudoSession.getInstance();
    vi.mocked(session.isElevated).mockReturnValue(true);
    vi.mocked(session.getStatus).mockReturnValue({
      elevated: true,
      username: "testuser",
      expiresAt: "2025-01-01T00:00:00Z",
      remainingSeconds: 900,
      rateLimit: { limited: false, attemptsRemaining: 5 },
    });

    const handler = tools.get("sudo_session")!.handler;
    const result = await handler({ action: "drop" });
    expect(result.content[0].text).toContain("Privileges dropped");
    expect(session.drop).toHaveBeenCalled();
  });

  // ── extend action ─────────────────────────────────────────────────────

  it("should fail to extend when not elevated", async () => {
    const session = SudoSession.getInstance();
    vi.mocked(session.isElevated).mockReturnValue(false);

    const handler = tools.get("sudo_session")!.handler;
    const result = await handler({ action: "extend", minutes: 15 });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("No active sudo session");
  });

  // ── preflight_check action ────────────────────────────────────────────

  it("should report tools as ready when preflight passes", async () => {
    const handler = tools.get("sudo_session")!.handler;
    const result = await handler({ action: "preflight_check", tools: ["sudo_session"] });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("Ready");
  });

  it("should require tools array for preflight_check action", async () => {
    const handler = tools.get("sudo_session")!.handler;
    const result = await handler({ action: "preflight_check" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("tools array is required");
  });
});
