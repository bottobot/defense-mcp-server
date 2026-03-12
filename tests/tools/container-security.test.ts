/**
 * Tests for src/tools/container-security.ts
 *
 * Covers: TOOL-011 (seccomp profile path restriction),
 * secure-fs usage, dry_run defaults, and schema validation.
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
vi.mock("../../src/core/parsers.js", () => ({
  createTextContent: vi.fn((text: string) => ({ type: "text", text })),
  createErrorContent: vi.fn((text: string) => ({ type: "text", text: `Error: ${text}` })),
  formatToolOutput: vi.fn((obj: unknown) => ({ type: "text", text: JSON.stringify(obj) })),
  parseJsonSafe: vi.fn((s: string) => { try { return JSON.parse(s); } catch { return null; } }),
}));
vi.mock("../../src/core/changelog.js", () => ({
  logChange: vi.fn(),
  createChangeEntry: vi.fn().mockReturnValue({}),
  backupFile: vi.fn().mockReturnValue("/tmp/backup"),
}));
vi.mock("../../src/core/sanitizer.js", () => ({
  sanitizeArgs: vi.fn((a: string[]) => a),
}));
vi.mock("../../src/core/safeguards.js", () => ({
  SafeguardRegistry: {
    getInstance: vi.fn().mockReturnValue({
      checkSafety: vi.fn().mockResolvedValue({ safe: true, warnings: [], blockers: [], impactedApps: [] }),
    }),
  },
}));

const { mockSecureWriteFileSync } = vi.hoisted(() => ({
  mockSecureWriteFileSync: vi.fn(),
}));
vi.mock("../../src/core/secure-fs.js", () => ({
  secureWriteFileSync: mockSecureWriteFileSync,
}));

vi.mock("node:fs", () => ({
  existsSync: vi.fn().mockReturnValue(false),
  mkdirSync: vi.fn(),
}));

import { registerContainerSecurityTools } from "../../src/tools/container-security.js";

// ── Helper ─────────────────────────────────────────────────────────────────

type ToolHandler = (params: Record<string, unknown>) => Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }>;

function createMockServer() {
  const tools = new Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>();
  const server = {
    tool: vi.fn((name: string, _desc: string, schema: Record<string, unknown>, handler: ToolHandler) => {
      tools.set(name, { schema, handler });
    }),
  };
  return { server: server as unknown as Parameters<typeof registerContainerSecurityTools>[0], tools };
}

describe("container-security tools", () => {
  let tools: Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>;

  beforeEach(() => {
    vi.clearAllMocks();
    const mock = createMockServer();
    registerContainerSecurityTools(mock.server);
    tools = mock.tools;
  });

  // ── Registration ──────────────────────────────────────────────────────

  it("should register 2 container security tools", () => {
    expect(tools.has("container_docker")).toBe(true);
    expect(tools.has("container_isolation")).toBe(true);
    expect(tools.size).toBe(2);
  });

  // ── TOOL-011: Seccomp profile path restriction ───────────────────────

  it("should restrict seccomp profile output to safe directory (TOOL-011)", async () => {
    const handler = tools.get("container_isolation")!.handler;
    const result = await handler({
      action: "seccomp_profile",
      allowedSyscalls: ["read", "write", "exit"],
      defaultAction: "SCMP_ACT_ERRNO",
      outputPath: "/etc/evil/profile.json",
      dryRun: false,
    });
    // Should succeed but redirect to safe directory
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("restricted to safe directory");
  });

  it("should use secureWriteFileSync for seccomp profile writing (TOOL-011)", async () => {
    const handler = tools.get("container_isolation")!.handler;
    await handler({
      action: "seccomp_profile",
      allowedSyscalls: ["read", "write"],
      defaultAction: "SCMP_ACT_ERRNO",
      outputPath: "/tmp/kali-defense/seccomp/test.json",
      dryRun: false,
    });
    // secureWriteFileSync should have been called
    expect(mockSecureWriteFileSync).toHaveBeenCalled();
  });

  it("should produce dry-run output for seccomp profile when dryRun is true", async () => {
    const handler = tools.get("container_isolation")!.handler;
    const result = await handler({
      action: "seccomp_profile",
      allowedSyscalls: ["read", "write", "exit"],
      defaultAction: "SCMP_ACT_ERRNO",
      dryRun: true,
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("dryRun");
    // secureWriteFileSync should NOT have been called in dry-run
    expect(mockSecureWriteFileSync).not.toHaveBeenCalled();
  });

  // ── Required params ──────────────────────────────────────────────────

  it("should require allowedSyscalls for seccomp_profile", async () => {
    const handler = tools.get("container_isolation")!.handler;
    const result = await handler({
      action: "seccomp_profile",
      defaultAction: "SCMP_ACT_ERRNO",
      dryRun: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("allowedSyscalls");
  });

  it("should require username for rootless_setup action", async () => {
    const handler = tools.get("container_isolation")!.handler;
    const result = await handler({
      action: "rootless_setup",
      dryRun: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("username");
  });

  // ── AppArmor ─────────────────────────────────────────────────────────

  it("should require profile name for apparmor_enforce action", async () => {
    const handler = tools.get("container_isolation")!.handler;
    const result = await handler({ action: "apparmor_enforce" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("profile name is required");
  });

  it("should require profileName for apparmor_apply_container action", async () => {
    const handler = tools.get("container_isolation")!.handler;
    const result = await handler({ action: "apparmor_apply_container" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("profileName");
  });

  // ── Docker daemon ────────────────────────────────────────────────────

  it("should require daemon_action for docker daemon", async () => {
    const handler = tools.get("container_docker")!.handler;
    const result = await handler({ action: "daemon" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("daemon_action");
  });

  // ── image_scan ───────────────────────────────────────────────────────

  it("should require image for image_scan action", async () => {
    const handler = tools.get("container_docker")!.handler;
    const result = await handler({ action: "image_scan" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("image is required");
  });
});
