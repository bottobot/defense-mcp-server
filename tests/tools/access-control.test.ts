/**
 * Tests for src/tools/access-control.ts
 *
 * Covers: TOOL-012 (SSH config key validation, value validation),
 * shell metacharacter rejection, valid vs invalid SSH directives,
 * and pam_configure faillock flow using pam-utils.
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

// Mock pam-utils I/O functions (but NOT the pure functions — they work correctly)
// vi.hoisted ensures the variable is available in the hoisted vi.mock factory
const { MOCK_COMMON_AUTH } = vi.hoisted(() => ({
  MOCK_COMMON_AUTH: `#
# /etc/pam.d/common-auth
#
# here are the per-package modules (the "Primary" block)
auth\t[success=1 default=ignore]\tpam_unix.so nullok
# here's the fallback if no module succeeds
auth\trequisite\t\t\tpam_deny.so
auth\trequired\t\t\tpam_permit.so
# end of pam-auth-update config`,
}));

vi.mock("../../src/core/pam-utils.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/core/pam-utils.js")>();
  return {
    ...actual,
    // Mock I/O functions only
    readPamFile: vi.fn().mockResolvedValue(MOCK_COMMON_AUTH),
    writePamFile: vi.fn().mockResolvedValue(undefined),
    backupPamFile: vi.fn().mockResolvedValue({
      id: "test-backup-id",
      originalPath: "/etc/pam.d/common-auth",
      backupPath: "/tmp/test-backup",
      timestamp: new Date().toISOString(),
    }),
    restorePamFile: vi.fn().mockResolvedValue(undefined),
  };
});

import { registerAccessControlTools } from "../../src/tools/access-control.js";
import {
  readPamFile,
  writePamFile,
  backupPamFile,
  restorePamFile,
  parsePamConfig,
  serializePamConfig,
  validatePamConfig,
} from "../../src/core/pam-utils.js";
import type { PamRule } from "../../src/core/pam-utils.js";

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

  it("should register exactly 1 consolidated access_control tool", () => {
    expect(tools.size).toBe(1);
    expect(tools.has("access_control")).toBe(true);
  });

  // ── TOOL-012: SSH config key validation ──────────────────────────────

  it("should reject invalid SSH config key (TOOL-012)", async () => {
    const handler = tools.get("access_control")!.handler;
    const result = await handler({
      action: "ssh_harden",
      settings: "InvalidDirective=yes",
      dry_run: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Invalid SSH configuration directive");
  });

  it("should accept valid SSH config key PermitRootLogin (TOOL-012)", async () => {
    const handler = tools.get("access_control")!.handler;
    const result = await handler({
      action: "ssh_harden",
      settings: "PermitRootLogin=no",
      dry_run: true,
    });
    expect(result.isError).toBeUndefined();
  });

  it("should accept valid SSH config key MaxAuthTries (TOOL-012)", async () => {
    const handler = tools.get("access_control")!.handler;
    const result = await handler({
      action: "ssh_harden",
      settings: "MaxAuthTries=4",
      dry_run: true,
    });
    expect(result.isError).toBeUndefined();
  });

  // ── TOOL-012: SSH config value validation (shell metacharacter rejection) ──

  it("should reject SSH config value with semicolons (TOOL-012)", async () => {
    const handler = tools.get("access_control")!.handler;
    const result = await handler({
      action: "ssh_harden",
      settings: "PermitRootLogin=no;rm -rf /",
      dry_run: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("shell metacharacters");
  });

  it("should reject SSH config value with backticks (TOOL-012)", async () => {
    const handler = tools.get("access_control")!.handler;
    const result = await handler({
      action: "ssh_harden",
      settings: "Banner=`cat /etc/shadow`",
      dry_run: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("shell metacharacters");
  });

  it("should reject SSH config value with pipe (TOOL-012)", async () => {
    const handler = tools.get("access_control")!.handler;
    const result = await handler({
      action: "ssh_harden",
      settings: "PermitRootLogin=no|echo pwned",
      dry_run: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("shell metacharacters");
  });

  // ── Settings validation ──────────────────────────────────────────────

  it("should require settings or apply_recommended for ssh_harden", async () => {
    const handler = tools.get("access_control")!.handler;
    const result = await handler({
      action: "ssh_harden",
      dry_run: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("No settings");
  });

  it("should accept apply_recommended=true for ssh_harden", async () => {
    const handler = tools.get("access_control")!.handler;
    const result = await handler({
      action: "ssh_harden",
      apply_recommended: true,
      dry_run: true,
    });
    expect(result.isError).toBeUndefined();
  });

  // ── pam_configure ─────────────────────────────────────────────────────

  describe("pam_configure action", () => {
    it("should require module parameter", async () => {
      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "pam_configure",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("module");
    });

    it("should produce dry-run output for faillock without writing", async () => {
      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "pam_configure",
        module: "faillock",
        dry_run: true,
      });

      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("DRY-RUN");
      expect(result.content[0].text).toContain("pam_faillock");
      // In dry-run mode, should NOT call the I/O functions
      expect(readPamFile).not.toHaveBeenCalled();
      expect(writePamFile).not.toHaveBeenCalled();
      expect(backupPamFile).not.toHaveBeenCalled();
    });

    it("should use pam-utils flow (not sed) for faillock configuration", async () => {
      const { getConfig } = await import("../../src/core/config.js");
      // Override dryRun to false for this test to exercise the real path
      vi.mocked(getConfig).mockReturnValue({ dryRun: false } as ReturnType<typeof getConfig>);

      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "pam_configure",
        module: "faillock",
        dry_run: false,
      });

      // Should have called the pam-utils I/O functions
      expect(backupPamFile).toHaveBeenCalledWith("/etc/pam.d/common-auth");
      expect(readPamFile).toHaveBeenCalledWith("/etc/pam.d/common-auth");
      expect(writePamFile).toHaveBeenCalled();

      // writePamFile should have been called with content that contains faillock rules
      const writeCall = vi.mocked(writePamFile).mock.calls[0];
      expect(writeCall[0]).toBe("/etc/pam.d/common-auth");
      const writtenContent = writeCall[1];

      // Parse the written content and verify it's valid
      const lines = parsePamConfig(writtenContent);
      const validation = validatePamConfig(lines);
      expect(validation.valid).toBe(true);

      // Verify faillock rules are present and correctly ordered
      const rules = lines.filter((l) => l.kind === "rule") as Array<{
        kind: "rule"; pamType: string; control: string; module: string; args: string[]; rawLine: string;
      }>;
      const faillockRules = rules.filter((r) => r.module === "pam_faillock.so");
      expect(faillockRules.length).toBe(2);

      // preauth before pam_unix.so, authfail after
      const preauthIdx = rules.findIndex(
        (r) => r.module === "pam_faillock.so" && r.args.includes("preauth"),
      );
      const unixIdx = rules.findIndex((r) => r.module === "pam_unix.so");
      const authfailIdx = rules.findIndex(
        (r) => r.module === "pam_faillock.so" && r.args.includes("authfail"),
      );

      expect(preauthIdx).toBeLessThan(unixIdx);
      expect(authfailIdx).toBeGreaterThan(unixIdx);

      // Verify jump counts were adjusted correctly
      const unixRule = rules.find((r) => r.module === "pam_unix.so") as PamRule;
      expect(unixRule).toBeDefined();
      expect(unixRule.control).toBe("[success=2 default=ignore]");

      // Verify no concatenated fields in written content (REGRESSION)
      for (const line of writtenContent.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#")) continue;
        expect(trimmed).not.toMatch(/^auth(required|requisite|sufficient|optional)/);
        expect(trimmed).not.toMatch(/required(pam_|\/)/);
        expect(trimmed).not.toMatch(/requisite(pam_|\/)/);
      }

      // Should NOT have called executeCommand with sed for PAM modification
      const { executeCommand } = await import("../../src/core/executor.js");
      const sedCalls = vi.mocked(executeCommand).mock.calls.filter(
        (call) => {
          const args = call[0] as { args?: string[] };
          return args.args && args.args.some((a: string) => typeof a === "string" && a.includes("sed"));
        },
      );
      expect(sedCalls.length).toBe(0);
    });

    it("should call restorePamFile on write failure for faillock", async () => {
      const { getConfig } = await import("../../src/core/config.js");
      vi.mocked(getConfig).mockReturnValue({ dryRun: false } as ReturnType<typeof getConfig>);

      // Make writePamFile fail
      vi.mocked(writePamFile).mockRejectedValueOnce(new Error("Write failed"));

      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "pam_configure",
        module: "faillock",
        dry_run: false,
      });

      // Should have attempted to restore from backup
      expect(restorePamFile).toHaveBeenCalled();
      // Should report the error
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Write failed");
    });

    it("should produce dry-run output for pwquality", async () => {
      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "pam_configure",
        module: "pwquality",
        dry_run: true,
      });

      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("DRY-RUN");
      expect(result.content[0].text).toContain("pwquality");
    });

    it("should apply custom faillock settings", async () => {
      const { getConfig } = await import("../../src/core/config.js");
      vi.mocked(getConfig).mockReturnValue({ dryRun: false } as ReturnType<typeof getConfig>);

      const handler = tools.get("access_control")!.handler;
      await handler({
        action: "pam_configure",
        module: "faillock",
        pam_settings: {
          deny: 3,
          unlock_time: 600,
          fail_interval: 600,
        },
        dry_run: false,
      });

      // Verify the written content contains custom settings
      const writeCall = vi.mocked(writePamFile).mock.calls[0];
      const writtenContent = writeCall[1];
      expect(writtenContent).toContain("deny=3");
      expect(writtenContent).toContain("unlock_time=600");
      expect(writtenContent).toContain("fail_interval=600");
    });
  });
});
