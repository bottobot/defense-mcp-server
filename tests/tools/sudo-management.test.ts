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

  // ── elevate_gui action ─────────────────────────────────────────────────

  it("should report already elevated for elevate_gui when session active", async () => {
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
    const result = await handler({ action: "elevate_gui", timeout_minutes: 15 });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("Already elevated");
  });

  it("should block elevate_gui when rate limited", async () => {
    const session = SudoSession.getInstance();
    vi.mocked(session.isElevated).mockReturnValue(false);
    vi.mocked(session.getRateLimitStatus).mockReturnValue({
      limited: true,
      attemptsRemaining: 0,
      resetAt: Date.now() + 60000,
    });

    const handler = tools.get("sudo_session")!.handler;
    const result = await handler({ action: "elevate_gui", timeout_minutes: 15 });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("rate limit");
  });

  it("should fail elevate_gui when no graphical session detected", async () => {
    const session = SudoSession.getInstance();
    vi.mocked(session.isElevated).mockReturnValue(false);
    vi.mocked(session.getRateLimitStatus).mockReturnValue({ limited: false, attemptsRemaining: 5 });

    // In test environment there is no DISPLAY or WAYLAND_DISPLAY
    const originalDisplay = process.env.DISPLAY;
    const originalWayland = process.env.WAYLAND_DISPLAY;
    delete process.env.DISPLAY;
    delete process.env.WAYLAND_DISPLAY;

    const handler = tools.get("sudo_session")!.handler;
    const result = await handler({ action: "elevate_gui", timeout_minutes: 15 });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("no graphical session");

    // Restore env
    if (originalDisplay !== undefined) process.env.DISPLAY = originalDisplay;
    if (originalWayland !== undefined) process.env.WAYLAND_DISPLAY = originalWayland;
  });

  // ── status action (elevated path) ──────────────────────────────────────

  it("should report active session details when elevated", async () => {
    const session = SudoSession.getInstance();
    vi.mocked(session.getStatus).mockReturnValue({
      elevated: true,
      username: "admin",
      expiresAt: "2025-06-01T12:00:00Z",
      remainingSeconds: 600,
      rateLimit: { limited: false, attemptsRemaining: 5 },
    });

    const handler = tools.get("sudo_session")!.handler;
    const result = await handler({ action: "status" });
    expect(result.content[0].text).toContain("Sudo Session Active");
    expect(result.content[0].text).toContain("admin");
  });

  it("should warn when session is expiring soon in status", async () => {
    const session = SudoSession.getInstance();
    vi.mocked(session.getStatus).mockReturnValue({
      elevated: true,
      username: "admin",
      expiresAt: "2025-06-01T12:00:00Z",
      remainingSeconds: 60,
      rateLimit: { limited: false, attemptsRemaining: 5 },
    });

    const handler = tools.get("sudo_session")!.handler;
    const result = await handler({ action: "status" });
    expect(result.content[0].text).toContain("expiring soon");
  });

  it("should show rate limit active in status when not elevated and locked out", async () => {
    const session = SudoSession.getInstance();
    vi.mocked(session.getStatus).mockReturnValue({
      elevated: false,
      username: "",
      expiresAt: null,
      remainingSeconds: null,
      rateLimit: { limited: true, attemptsRemaining: 0, resetAt: Date.now() + 120000 },
    });

    const handler = tools.get("sudo_session")!.handler;
    const result = await handler({ action: "status" });
    expect(result.content[0].text).toContain("Not elevated");
    expect(result.content[0].text).toContain("Rate limit ACTIVE");
  });

  // ── drop action (not elevated path) ────────────────────────────────────

  it("should report no session to drop when not elevated", async () => {
    const session = SudoSession.getInstance();
    vi.mocked(session.isElevated).mockReturnValue(false);

    const handler = tools.get("sudo_session")!.handler;
    const result = await handler({ action: "drop" });
    expect(result.content[0].text).toContain("No active sudo session to drop");
  });

  // ── extend action (success path) ───────────────────────────────────────

  it("should extend session successfully when elevated", async () => {
    const session = SudoSession.getInstance();
    vi.mocked(session.isElevated).mockReturnValue(true);
    vi.mocked(session.extend).mockReturnValue(true);
    vi.mocked(session.getStatus).mockReturnValue({
      elevated: true,
      username: "admin",
      expiresAt: "2025-06-01T12:30:00Z",
      remainingSeconds: 1800,
      rateLimit: { limited: false, attemptsRemaining: 5 },
    });

    const handler = tools.get("sudo_session")!.handler;
    const result = await handler({ action: "extend", minutes: 30 });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("Session extended by 30 minutes");
    expect(result.content[0].text).toContain("admin");
  });

  it("should report error when extend fails (session expired)", async () => {
    const session = SudoSession.getInstance();
    vi.mocked(session.isElevated).mockReturnValue(true);
    vi.mocked(session.extend).mockReturnValue(false);

    const handler = tools.get("sudo_session")!.handler;
    const result = await handler({ action: "extend", minutes: 15 });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Failed to extend");
  });

  // ── elevate rate limit check ───────────────────────────────────────────

  it("should block elevation when rate limited (pre-flight check)", async () => {
    const session = SudoSession.getInstance();
    vi.mocked(session.isElevated).mockReturnValue(false);
    vi.mocked(session.getRateLimitStatus).mockReturnValue({
      limited: true,
      attemptsRemaining: 0,
      resetAt: Date.now() + 300000,
    });

    const handler = tools.get("sudo_session")!.handler;
    const result = await handler({ action: "elevate", password: "test", timeout_minutes: 15 });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("rate limit");
  });

  it("should report rate limited after failed elevation with rateLimited flag", async () => {
    const session = SudoSession.getInstance();
    vi.mocked(session.isElevated).mockReturnValue(false);
    vi.mocked(session.getRateLimitStatus).mockReturnValue({ limited: false, attemptsRemaining: 1 });
    vi.mocked(session.elevate).mockResolvedValue({ success: false, error: "bad password", rateLimited: true });

    const handler = tools.get("sudo_session")!.handler;
    const result = await handler({ action: "elevate", password: "badpass", timeout_minutes: 15 });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("rate limit");
  });

  // ── preflight_check with unknown tool ──────────────────────────────────

  it("should report unknown tool in preflight_check as other issue", async () => {
    const { ToolRegistry } = await import("../../src/core/tool-registry.js");
    const registry = ToolRegistry.instance();
    vi.mocked(registry.getManifest).mockReturnValue(null as unknown as ReturnType<typeof registry.getManifest>);

    const handler = tools.get("sudo_session")!.handler;
    const result = await handler({ action: "preflight_check", tools: ["nonexistent_tool"] });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("Other issues: 1");
  });

  it("should report tools needing sudo in preflight_check", async () => {
    const { ToolRegistry } = await import("../../src/core/tool-registry.js");
    const { PreflightEngine } = await import("../../src/core/preflight.js");
    const registry = ToolRegistry.instance();
    const engine = PreflightEngine.instance();

    vi.mocked(registry.getManifest).mockReturnValue({ sudo: "always", sudoReason: "Needs root access" } as ReturnType<typeof registry.getManifest>);
    vi.mocked(engine.runPreflight).mockResolvedValue({
      passed: false,
      dependencies: { missing: [] },
      privileges: { issues: [{ type: "sudo-required", message: "sudo needed" }] },
      errors: [],
    } as unknown as Awaited<ReturnType<typeof engine.runPreflight>>);

    const session = SudoSession.getInstance();
    vi.mocked(session.isElevated).mockReturnValue(false);

    const handler = tools.get("sudo_session")!.handler;
    const result = await handler({ action: "preflight_check", tools: ["firewall"] });
    expect(result.content[0].text).toContain("SUDO ELEVATION REQUIRED");
  });

  // ── unknown action ─────────────────────────────────────────────────────

  it("should return error for unknown action", async () => {
    const handler = tools.get("sudo_session")!.handler;
    const result = await handler({ action: "unknown_action" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Unknown action");
  });
});
