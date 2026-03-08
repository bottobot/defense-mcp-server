/**
 * Tests for src/tools/access-control.ts
 *
 * Covers: TOOL-012 (SSH config key validation, value validation),
 * shell metacharacter rejection, and valid vs invalid SSH directives.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Mock all external dependencies ─────────────────────────────────────────

vi.mock("../../src/core/executor.js", () => ({
  executeCommand: vi.fn().mockResolvedValue({ exitCode: 0, stdout: "", stderr: "" }),
}));
vi.mock("../../src/core/config.js", () => ({
  getConfig: vi.fn().mockReturnValue({ dryRun: true }),
  getToolTimeout: vi.fn().mockReturnValue(30000),
}));
vi.mock("../../src/core/distro-adapter.js", () => ({
  getDistroAdapter: vi.fn().mockResolvedValue({
    paths: {
      pamAuth: "/etc/pam.d/common-auth",
      pamPassword: "/etc/pam.d/common-password",
      pamAllConfigs: ["/etc/pam.d/common-auth", "/etc/pam.d/common-password"],
    },
  }),
}));
vi.mock("../../src/core/parsers.js", () => ({
  createTextContent: vi.fn((text: string) => ({ type: "text", text })),
  createErrorContent: vi.fn((text: string) => ({ type: "text", text: `Error: ${text}` })),
  formatToolOutput: vi.fn((obj: unknown) => ({ type: "text", text: JSON.stringify(obj) })),
}));
vi.mock("../../src/core/changelog.js", () => ({
  logChange: vi.fn(),
  createChangeEntry: vi.fn().mockReturnValue({}),
  backupFile: vi.fn().mockReturnValue("/tmp/backup"),
}));
vi.mock("../../src/core/sanitizer.js", () => ({
  sanitizeArgs: vi.fn((a: string[]) => a),
}));

import { registerAccessControlTools } from "../../src/tools/access-control.js";

// ── Helper ─────────────────────────────────────────────────────────────────

type ToolHandler = (params: Record<string, unknown>) => Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }>;

function createMockServer() {
  const tools = new Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>();
  const server = {
    tool: vi.fn((name: string, _desc: string, schema: Record<string, unknown>, handler: ToolHandler) => {
      tools.set(name, { schema, handler });
    }),
  };
  return { server: server as unknown as Parameters<typeof registerAccessControlTools>[0], tools };
}

describe("access-control tools", () => {
  let tools: Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>;

  beforeEach(() => {
    vi.clearAllMocks();
    const mock = createMockServer();
    registerAccessControlTools(mock.server);
    tools = mock.tools;
  });

  // ── Registration ──────────────────────────────────────────────────────

  it("should register all access control tools", () => {
    expect(tools.has("access_ssh")).toBe(true);
    expect(tools.has("access_pam")).toBe(true);
    expect(tools.has("access_sudo_audit")).toBe(true);
    expect(tools.has("access_user_audit")).toBe(true);
    expect(tools.has("access_password_policy")).toBe(true);
    expect(tools.has("access_restrict_shell")).toBe(true);
  });

  // ── TOOL-012: SSH config key validation ──────────────────────────────

  it("should reject invalid SSH config key (TOOL-012)", async () => {
    const handler = tools.get("access_ssh")!.handler;
    const result = await handler({
      action: "harden",
      settings: "InvalidDirective=yes",
      dry_run: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Invalid SSH configuration directive");
  });

  it("should accept valid SSH config key PermitRootLogin (TOOL-012)", async () => {
    const handler = tools.get("access_ssh")!.handler;
    const result = await handler({
      action: "harden",
      settings: "PermitRootLogin=no",
      dry_run: true,
    });
    expect(result.isError).toBeUndefined();
  });

  it("should accept valid SSH config key MaxAuthTries (TOOL-012)", async () => {
    const handler = tools.get("access_ssh")!.handler;
    const result = await handler({
      action: "harden",
      settings: "MaxAuthTries=4",
      dry_run: true,
    });
    expect(result.isError).toBeUndefined();
  });

  // ── TOOL-012: SSH config value validation (shell metacharacter rejection) ──

  it("should reject SSH config value with semicolons (TOOL-012)", async () => {
    const handler = tools.get("access_ssh")!.handler;
    const result = await handler({
      action: "harden",
      settings: "PermitRootLogin=no;rm -rf /",
      dry_run: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("shell metacharacters");
  });

  it("should reject SSH config value with backticks (TOOL-012)", async () => {
    const handler = tools.get("access_ssh")!.handler;
    const result = await handler({
      action: "harden",
      settings: "Banner=`cat /etc/shadow`",
      dry_run: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("shell metacharacters");
  });

  it("should reject SSH config value with pipe (TOOL-012)", async () => {
    const handler = tools.get("access_ssh")!.handler;
    const result = await handler({
      action: "harden",
      settings: "PermitRootLogin=no|echo pwned",
      dry_run: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("shell metacharacters");
  });

  // ── Settings validation ──────────────────────────────────────────────

  it("should require settings or apply_recommended for harden", async () => {
    const handler = tools.get("access_ssh")!.handler;
    const result = await handler({
      action: "harden",
      dry_run: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("No settings");
  });

  it("should accept apply_recommended=true for harden", async () => {
    const handler = tools.get("access_ssh")!.handler;
    const result = await handler({
      action: "harden",
      apply_recommended: true,
      dry_run: true,
    });
    expect(result.isError).toBeUndefined();
  });
});
