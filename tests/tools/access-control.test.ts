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
      await handler({
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

    // ── PAM Sanity Check Integration Tests ──────────────────────────────

    describe("pam_configure sanity checks", () => {
      it("should block faillock with deny=1 (critical finding)", async () => {
        const handler = tools.get("access_control")!.handler;
        const result = await handler({
          action: "pam_configure",
          module: "faillock",
          pam_settings: { deny: 1, unlock_time: 0 },
          dry_run: false,
        });
        expect(result.isError).toBe(true);
        expect(result.content[0].text).toContain("sanity check FAILED");
        expect(result.content[0].text).toContain("force=true");
        // Should NOT have called any I/O functions (blocked before backup)
        expect(backupPamFile).not.toHaveBeenCalled();
        expect(readPamFile).not.toHaveBeenCalled();
        expect(writePamFile).not.toHaveBeenCalled();
      });

      it("should block faillock with deny=2 (critical finding)", async () => {
        const handler = tools.get("access_control")!.handler;
        const result = await handler({
          action: "pam_configure",
          module: "faillock",
          pam_settings: { deny: 2 },
          dry_run: false,
        });
        expect(result.isError).toBe(true);
        expect(result.content[0].text).toContain("sanity check FAILED");
      });

      it("should block faillock with unlock_time=0 (permanent lock)", async () => {
        const handler = tools.get("access_control")!.handler;
        const result = await handler({
          action: "pam_configure",
          module: "faillock",
          pam_settings: { unlock_time: 0 },
          dry_run: false,
        });
        expect(result.isError).toBe(true);
        expect(result.content[0].text).toContain("sanity check FAILED");
        expect(result.content[0].text).toContain("Permanent lock");
      });

      it("should allow faillock with deny=1 when force=true", async () => {
        const { getConfig } = await import("../../src/core/config.js");
        vi.mocked(getConfig).mockReturnValue({ dryRun: false } as ReturnType<typeof getConfig>);

        const handler = tools.get("access_control")!.handler;
        const result = await handler({
          action: "pam_configure",
          module: "faillock",
          pam_settings: { deny: 1, unlock_time: 900 },
          force: true,
          dry_run: false,
        });
        // Should proceed (not blocked by sanity check)
        expect(result.isError).toBeUndefined();
        // Should have called I/O functions (force overrides sanity block)
        expect(backupPamFile).toHaveBeenCalled();
        expect(writePamFile).toHaveBeenCalled();
        // Response should include sanity warnings
        expect(result.content[0].text).toContain("Sanity warnings");
      });

      it("should include sanity warnings in dry-run output for faillock", async () => {
        const handler = tools.get("access_control")!.handler;
        const result = await handler({
          action: "pam_configure",
          module: "faillock",
          pam_settings: { deny: 5, unlock_time: 3600 },
          dry_run: true,
        });
        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("DRY-RUN");
        expect(result.content[0].text).toContain("Sanity warnings");
        expect(result.content[0].text).toContain("unlock_time");
      });

      it("should succeed without warnings for sane faillock defaults", async () => {
        const handler = tools.get("access_control")!.handler;
        const result = await handler({
          action: "pam_configure",
          module: "faillock",
          pam_settings: { deny: 5, unlock_time: 900, fail_interval: 900 },
          dry_run: true,
        });
        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).not.toContain("Sanity warnings");
      });

      it("should block faillock in dry-run mode too when critical", async () => {
        const handler = tools.get("access_control")!.handler;
        const result = await handler({
          action: "pam_configure",
          module: "faillock",
          pam_settings: { deny: 1 },
          dry_run: true,
        });
        // Critical findings should block even in dry-run
        expect(result.isError).toBe(true);
        expect(result.content[0].text).toContain("sanity check FAILED");
      });

      it("should block pwquality with minlen=100 (critical finding)", async () => {
        const handler = tools.get("access_control")!.handler;
        const result = await handler({
          action: "pam_configure",
          module: "pwquality",
          pam_settings: { minlen: 100 },
          dry_run: true,
        });
        expect(result.isError).toBe(true);
        expect(result.content[0].text).toContain("sanity check FAILED");
        expect(result.content[0].text).toContain("minlen");
      });

      it("should include sanity warnings in dry-run output for pwquality", async () => {
        const handler = tools.get("access_control")!.handler;
        const result = await handler({
          action: "pam_configure",
          module: "pwquality",
          pam_settings: { minlen: 25 },
          dry_run: true,
        });
        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("DRY-RUN");
        expect(result.content[0].text).toContain("Sanity warnings");
      });

      it("should succeed without warnings for sane pwquality defaults", async () => {
        const handler = tools.get("access_control")!.handler;
        const result = await handler({
          action: "pam_configure",
          module: "pwquality",
          dry_run: true,
        });
        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).not.toContain("Sanity warnings");
      });

      it("should include warnings in success response for faillock", async () => {
        const { getConfig } = await import("../../src/core/config.js");
        vi.mocked(getConfig).mockReturnValue({ dryRun: false } as ReturnType<typeof getConfig>);

        const handler = tools.get("access_control")!.handler;
        const result = await handler({
          action: "pam_configure",
          module: "faillock",
          pam_settings: { deny: 5, unlock_time: 3600 },
          dry_run: false,
        });
        expect(result.isError).toBeUndefined();
        // unlock_time=3600 is a warning (> 1800) but not critical
        expect(result.content[0].text).toContain("Sanity warnings");
        expect(result.content[0].text).toContain("unlock_time");
      });
    });
  });
  // ── ssh_audit service state detection ─────────────────────────────────

  describe("ssh_audit service state detection", () => {
    const MOCK_SSHD_CONFIG = `# SSH config
PermitRootLogin yes
PasswordAuthentication yes
X11Forwarding yes
MaxAuthTries 6
Protocol 2
PermitEmptyPasswords no
`;

    async function mockExecuteForSshState(opts: {
      sshdBinaryExists: boolean;
      serviceActive: boolean;
      configReadable: boolean;
      configContent?: string;
    }) {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockImplementation(async (params: Record<string, unknown>) => {
        const command = params.command as string;
        const args = params.args as string[];

        // which sshd
        if (command === "which" && args?.[0] === "sshd") {
          return {
            exitCode: opts.sshdBinaryExists ? 0 : 1,
            stdout: opts.sshdBinaryExists ? "/usr/sbin/sshd" : "",
            stderr: opts.sshdBinaryExists ? "" : "which: no sshd in PATH",
          };
        }

        // systemctl is-active ssh sshd
        if (command === "systemctl" && args?.[0] === "is-active") {
          return {
            exitCode: opts.serviceActive ? 0 : 3,
            stdout: opts.serviceActive ? "active" : "inactive",
            stderr: "",
          };
        }

        // sudo cat /etc/ssh/sshd_config
        if (command === "sudo" && args?.[0] === "cat" && (args?.[1] ?? "").includes("sshd_config")) {
          return {
            exitCode: opts.configReadable ? 0 : 1,
            stdout: opts.configReadable ? (opts.configContent ?? MOCK_SSHD_CONFIG) : "",
            stderr: opts.configReadable ? "" : "No such file or directory",
          };
        }

        // Default fallback
        return { exitCode: 0, stdout: "", stderr: "" };
      });
    }

    it("should audit normally when sshd is active (original severities)", async () => {
      await mockExecuteForSshState({
        sshdBinaryExists: true,
        serviceActive: true,
        configReadable: true,
      });

      const handler = tools.get("access_control")!.handler;
      const result = await handler({ action: "ssh_audit" });

      expect(result.isError).toBeUndefined();
      const output = JSON.parse(result.content[0].text);
      expect(output.serviceState).toBe("active");
      expect(output.serviceStatus).toContain("ACTIVE");

      // Findings should have original severities (not downgraded)
      const permitRoot = output.findings.find((f: Record<string, unknown>) => f.setting === "PermitRootLogin");
      expect(permitRoot).toBeDefined();
      expect(permitRoot.severity).toBe("critical");
      expect(permitRoot.description).not.toContain("[RESIDUAL CONFIG]");
      expect(permitRoot.description).not.toContain("[SERVICE STOPPED]");
    });

    it("should downgrade severities when sshd is installed but inactive", async () => {
      await mockExecuteForSshState({
        sshdBinaryExists: true,
        serviceActive: false,
        configReadable: true,
      });

      const handler = tools.get("access_control")!.handler;
      const result = await handler({ action: "ssh_audit" });

      expect(result.isError).toBeUndefined();
      const output = JSON.parse(result.content[0].text);
      expect(output.serviceState).toBe("installed_inactive");
      expect(output.serviceStatus).toContain("INACTIVE");
      expect(output.note).toContain("not currently running");

      // critical → high, high → medium
      const permitRoot = output.findings.find((f: Record<string, unknown>) => f.setting === "PermitRootLogin");
      expect(permitRoot.severity).toBe("high"); // downgraded from critical
      expect(permitRoot.description).toContain("[SERVICE STOPPED]");

      const passwordAuth = output.findings.find((f: Record<string, unknown>) => f.setting === "PasswordAuthentication");
      expect(passwordAuth.severity).toBe("medium"); // downgraded from high
      expect(passwordAuth.description).toContain("[SERVICE STOPPED]");
    });

    it("should set all findings to INFO when sshd removed but config remains (residual)", async () => {
      await mockExecuteForSshState({
        sshdBinaryExists: false,
        serviceActive: false,
        configReadable: true,
      });

      const handler = tools.get("access_control")!.handler;
      const result = await handler({ action: "ssh_audit" });

      expect(result.isError).toBeUndefined();
      const output = JSON.parse(result.content[0].text);
      expect(output.serviceState).toBe("removed_residual");
      expect(output.serviceStatus).toContain("NOT INSTALLED");
      expect(output.serviceStatus).toContain("residual");
      expect(output.note).toContain("dpkg --purge");

      // ALL findings should be info severity with [RESIDUAL CONFIG] prefix
      for (const finding of output.findings) {
        expect(finding.severity).toBe("info");
        expect(finding.description).toContain("[RESIDUAL CONFIG]");
      }
    });

    it("should skip audit entirely when SSH is not installed", async () => {
      await mockExecuteForSshState({
        sshdBinaryExists: false,
        serviceActive: false,
        configReadable: false,
      });

      const handler = tools.get("access_control")!.handler;
      const result = await handler({ action: "ssh_audit" });

      expect(result.isError).toBeUndefined();
      const output = JSON.parse(result.content[0].text);
      expect(output.serviceState).toBe("not_installed");
      expect(output.serviceStatus).toBe("NOT INSTALLED");
      expect(output.note).toContain("not installed");
      expect(output.findings).toHaveLength(0);
      expect(output.summary.total).toBe(0);
    });
  });

  // ── sudoers_manage ──────────────────────────────────────────────────

  describe("sudoers_manage", () => {
    it("should require sudoers_action", async () => {
      const handler = tools.get("access_control")!.handler;
      const result = await handler({ action: "sudoers_manage" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("sudoers_action");
    });

    it("should reject filename with path traversal (write)", async () => {
      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "sudoers_manage",
        sudoers_action: "write",
        sudoers_filename: "../etc/evil",
        sudoers_content: "user ALL=(ALL) ALL",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Invalid sudoers filename");
    });

    it("should reject filename with path traversal (remove)", async () => {
      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "sudoers_manage",
        sudoers_action: "remove",
        sudoers_filename: "../../shadow",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Invalid sudoers filename");
    });

    it("should refuse to overwrite README (write)", async () => {
      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "sudoers_manage",
        sudoers_action: "write",
        sudoers_filename: "README",
        sudoers_content: "user ALL=(ALL) ALL",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("README");
    });

    it("should refuse to remove README", async () => {
      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "sudoers_manage",
        sudoers_action: "remove",
        sudoers_filename: "README",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("README");
    });

    it("should reject NOPASSWD: ALL content", async () => {
      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "sudoers_manage",
        sudoers_action: "write",
        sudoers_filename: "myuser",
        sudoers_content: "myuser ALL=(ALL) NOPASSWD: ALL",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("NOPASSWD: ALL");
    });

    it("should require filename for write", async () => {
      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "sudoers_manage",
        sudoers_action: "write",
        sudoers_content: "user ALL=(ALL) ALL",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("sudoers_filename");
    });

    it("should require content for write", async () => {
      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "sudoers_manage",
        sudoers_action: "write",
        sudoers_filename: "myuser",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("sudoers_content");
    });

    it("should preview write in dry_run mode", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValue({ exitCode: 0, stdout: "parsed OK", stderr: "" });
      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "sudoers_manage",
        sudoers_action: "write",
        sudoers_filename: "deploy",
        sudoers_content: "deploy ALL=(ALL) /usr/bin/systemctl restart myapp",
        dry_run: true,
      });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("DRY-RUN");
      expect(result.content[0].text).toContain("deploy");
    });

    it("should run visudo -c for validate sub-action", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValue({
        exitCode: 0,
        stdout: "/etc/sudoers: parsed OK\n/etc/sudoers.d/myuser: parsed OK",
        stderr: "",
      });
      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "sudoers_manage",
        sudoers_action: "validate",
      });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("parsed OK");
    });
  });

  // ── password_policy_set target_user ─────────────────────────────────

  describe("password_policy_set target_user", () => {
    it("should reject invalid username", async () => {
      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "password_policy_set",
        target_user: "root; rm -rf /",
        max_days: 90,
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Invalid username");
    });

    it("should require at least one chage parameter", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValue({ exitCode: 0, stdout: "uid=1000(testuser)", stderr: "" });
      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "password_policy_set",
        target_user: "testuser",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("No applicable chage parameters");
    });

    it("should preview chage in dry_run mode", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValue({ exitCode: 0, stdout: "uid=1000(testuser)", stderr: "" });
      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "password_policy_set",
        target_user: "testuser",
        max_days: 90,
        warn_days: 14,
        dry_run: true,
      });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("DRY-RUN");
      expect(result.content[0].text).toContain("testuser");
      expect(result.content[0].text).toContain("chage");
    });

    it("should return error when target_user does not exist", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockImplementation(async (params: Record<string, unknown>) => {
        const command = params.command as string;
        if (command === "id") {
          return { exitCode: 1, stdout: "", stderr: "id: 'nosuchuser': no such user" };
        }
        return { exitCode: 0, stdout: "", stderr: "" };
      });
      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "password_policy_set",
        target_user: "nosuchuser",
        max_days: 90,
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("does not exist");
    });

    it("should apply chage successfully for target_user (non-dry-run)", async () => {
      const { getConfig } = await import("../../src/core/config.js");
      vi.mocked(getConfig).mockReturnValue({ dryRun: false } as ReturnType<typeof getConfig>);
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockImplementation(async (params: Record<string, unknown>) => {
        const command = params.command as string;
        const args = params.args as string[];
        if (command === "id") {
          return { exitCode: 0, stdout: "uid=1000(deploy)", stderr: "" };
        }
        if (command === "sudo" && args?.[0] === "chage" && args?.[1] === "-l") {
          return { exitCode: 0, stdout: "Last password change\t\t\t: Jan 01, 2026\nMaximum number of days between password change\t\t: 99999", stderr: "" };
        }
        if (command === "sudo" && args?.[0] === "chage" && args?.[1] === "-M") {
          return { exitCode: 0, stdout: "", stderr: "" };
        }
        return { exitCode: 0, stdout: "", stderr: "" };
      });
      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "password_policy_set",
        target_user: "deploy",
        max_days: 90,
        dry_run: false,
      });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("deploy");
    });
  });

  // ── ssh_harden (non-dry-run path) ──────────────────────────────────

  describe("ssh_harden non-dry-run", () => {
    it("should apply settings and validate config (success path)", async () => {
      const { getConfig } = await import("../../src/core/config.js");
      vi.mocked(getConfig).mockReturnValue({ dryRun: false } as ReturnType<typeof getConfig>);
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockImplementation(async (params: Record<string, unknown>) => {
        const command = params.command as string;
        const args = params.args as string[];
        // sshd -t validation pass
        if (command === "sudo" && args?.[0] === "sshd" && args?.[1] === "-t") {
          return { exitCode: 0, stdout: "", stderr: "" };
        }
        return { exitCode: 0, stdout: "", stderr: "" };
      });
      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "ssh_harden",
        settings: "PermitRootLogin=no",
        dry_run: false,
      });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("SSH hardening applied");
      expect(result.content[0].text).toContain("PermitRootLogin");
    });

    it("should report error when sshd -t validation fails", async () => {
      const { getConfig } = await import("../../src/core/config.js");
      vi.mocked(getConfig).mockReturnValue({ dryRun: false } as ReturnType<typeof getConfig>);
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockImplementation(async (params: Record<string, unknown>) => {
        const command = params.command as string;
        const args = params.args as string[];
        if (command === "sudo" && args?.[0] === "sshd" && args?.[1] === "-t") {
          return { exitCode: 1, stdout: "", stderr: "/etc/ssh/sshd_config: line 42: Bad configuration option" };
        }
        return { exitCode: 0, stdout: "", stderr: "" };
      });
      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "ssh_harden",
        settings: "PermitRootLogin=no",
        dry_run: false,
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("config validation failed");
    });

    it("should restart sshd when restart_sshd=true", async () => {
      const { getConfig } = await import("../../src/core/config.js");
      vi.mocked(getConfig).mockReturnValue({ dryRun: false } as ReturnType<typeof getConfig>);
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValue({ exitCode: 0, stdout: "", stderr: "" });
      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "ssh_harden",
        settings: "PermitRootLogin=no",
        restart_sshd: true,
        dry_run: false,
      });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("sshd restarted successfully");
    });

    it("should mention sshd restart in dry_run when restart_sshd=true", async () => {
      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "ssh_harden",
        settings: "PermitRootLogin=no",
        restart_sshd: true,
        dry_run: true,
      });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("restart sshd");
    });

    it("should apply all recommended settings when apply_recommended=true (non-dry-run)", async () => {
      const { getConfig } = await import("../../src/core/config.js");
      vi.mocked(getConfig).mockReturnValue({ dryRun: false } as ReturnType<typeof getConfig>);
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValue({ exitCode: 0, stdout: "", stderr: "" });
      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "ssh_harden",
        apply_recommended: true,
        dry_run: false,
      });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("SSH hardening applied");
    });
  });

  // ── ssh_cipher_audit ───────────────────────────────────────────────

  describe("ssh_cipher_audit", () => {
    it("should report PASS when only strong ciphers are configured", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockImplementation(async (params: Record<string, unknown>) => {
        const command = params.command as string;
        const args = params.args as string[];
        // cat sshd_config
        if (command === "cat" && args?.[0]?.toString().includes("sshd_config")) {
          return {
            exitCode: 0,
            stdout: `Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512`,
            stderr: "",
          };
        }
        // sshd -T runtime config (fail so file config is used)
        if (command === "sudo" && args?.[0] === "sshd" && args?.[1] === "-T") {
          return { exitCode: 1, stdout: "", stderr: "" };
        }
        // ls /etc/ssh/
        if (command === "ls") {
          return { exitCode: 0, stdout: "ssh_host_ed25519_key\nssh_host_rsa_key", stderr: "" };
        }
        return { exitCode: 0, stdout: "", stderr: "" };
      });
      const handler = tools.get("access_control")!.handler;
      const result = await handler({ action: "ssh_cipher_audit" });
      expect(result.isError).toBeUndefined();
      const output = JSON.parse(result.content[0].text);
      expect(output.summary.fail).toBe(0);
    });

    it("should report FAIL when weak ciphers are present", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockImplementation(async (params: Record<string, unknown>) => {
        const command = params.command as string;
        const args = params.args as string[];
        if (command === "cat" && args?.[0]?.toString().includes("sshd_config")) {
          return {
            exitCode: 0,
            stdout: `Ciphers 3des-cbc,aes256-ctr
MACs hmac-md5,hmac-sha2-256
KexAlgorithms diffie-hellman-group1-sha1,curve25519-sha256
HostKeyAlgorithms ssh-dss,ssh-ed25519`,
            stderr: "",
          };
        }
        if (command === "sudo" && args?.[0] === "sshd") {
          return { exitCode: 1, stdout: "", stderr: "" };
        }
        if (command === "ls") {
          return { exitCode: 0, stdout: "ssh_host_dsa_key\nssh_host_ed25519_key", stderr: "" };
        }
        return { exitCode: 0, stdout: "", stderr: "" };
      });
      const handler = tools.get("access_control")!.handler;
      const result = await handler({ action: "ssh_cipher_audit" });
      expect(result.isError).toBeUndefined();
      const output = JSON.parse(result.content[0].text);
      expect(output.summary.fail).toBeGreaterThan(0);
      expect(output.recommendation).toContain("CRITICAL");
      // DSA host key should be flagged
      const dsaKey = output.hostKeyAudit.find((k: Record<string, unknown>) => k.key === "DSA");
      expect(dsaKey.status).toBe("FAIL");
    });

    it("should report WARN when no algorithms are explicitly configured", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockImplementation(async (params: Record<string, unknown>) => {
        const command = params.command as string;
        const args = params.args as string[];
        if (command === "cat" && args?.[0]?.toString().includes("sshd_config")) {
          return { exitCode: 0, stdout: "# No explicit algorithm config\nPermitRootLogin no", stderr: "" };
        }
        if (command === "sudo" && args?.[0] === "sshd") {
          return { exitCode: 1, stdout: "", stderr: "" };
        }
        if (command === "ls") {
          return { exitCode: 0, stdout: "ssh_host_ed25519_key", stderr: "" };
        }
        return { exitCode: 0, stdout: "", stderr: "" };
      });
      const handler = tools.get("access_control")!.handler;
      const result = await handler({ action: "ssh_cipher_audit" });
      expect(result.isError).toBeUndefined();
      const output = JSON.parse(result.content[0].text);
      expect(output.summary.warn).toBeGreaterThan(0);
      expect(output.recommendation).toContain("WARNING");
    });
  });

  // ── pam_audit ──────────────────────────────────────────────────────

  describe("pam_audit", () => {
    it("should require service or check_all", async () => {
      const handler = tools.get("access_control")!.handler;
      const result = await handler({ action: "pam_audit" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("service");
    });

    it("should audit a specific PAM service", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockImplementation(async (params: Record<string, unknown>) => {
        const args = params.args as string[];
        if (args?.[0] === "cat" && args?.[1] === "/etc/pam.d/sshd") {
          return {
            exitCode: 0,
            stdout: `auth\trequired\tpam_unix.so nullok
auth\trequired\tpam_deny.so
account\trequired\tpam_unix.so`,
            stderr: "",
          };
        }
        return { exitCode: 0, stdout: "", stderr: "" };
      });
      const handler = tools.get("access_control")!.handler;
      const result = await handler({ action: "pam_audit", service: "sshd" });
      expect(result.isError).toBeUndefined();
      const output = JSON.parse(result.content[0].text);
      expect(output.filesChecked).toContain("/etc/pam.d/sshd");
      // Should detect missing lockout in sshd
      const lockoutFinding = output.findings.find((f: Record<string, unknown>) => f.type === "LOCKOUT_POLICY");
      expect(lockoutFinding).toBeDefined();
      expect(lockoutFinding.severity).toBe("high");
    });

    it("should audit all common PAM files with check_all", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockImplementation(async (params: Record<string, unknown>) => {
        const args = params.args as string[];
        if (args?.[0] === "cat" && args?.[1]?.toString().includes("common-auth")) {
          return {
            exitCode: 0,
            stdout: `auth\t[success=1 default=ignore]\tpam_unix.so nullok
auth\trequisite\tpam_deny.so`,
            stderr: "",
          };
        }
        if (args?.[0] === "cat" && args?.[1]?.toString().includes("common-password")) {
          return {
            exitCode: 0,
            stdout: `password\trequisite\tpam_pwquality.so retry=3
password\t[success=1 default=ignore]\tpam_unix.so sha512`,
            stderr: "",
          };
        }
        return { exitCode: 0, stdout: "", stderr: "" };
      });
      const handler = tools.get("access_control")!.handler;
      const result = await handler({ action: "pam_audit", check_all: true });
      expect(result.isError).toBeUndefined();
      const output = JSON.parse(result.content[0].text);
      expect(output.filesChecked.length).toBeGreaterThanOrEqual(2);
    });

    it("should detect MD5 hashing as critical", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockImplementation(async (params: Record<string, unknown>) => {
        const args = params.args as string[];
        if (args?.[0] === "cat" && args?.[1] === "/etc/pam.d/login") {
          return {
            exitCode: 0,
            stdout: `password\t[success=1 default=ignore]\tpam_unix.so md5`,
            stderr: "",
          };
        }
        return { exitCode: 0, stdout: "", stderr: "" };
      });
      const handler = tools.get("access_control")!.handler;
      const result = await handler({ action: "pam_audit", service: "login" });
      expect(result.isError).toBeUndefined();
      const output = JSON.parse(result.content[0].text);
      const md5Finding = output.findings.find(
        (f: Record<string, unknown>) => f.type === "HASH_ALGORITHM" && (f.detail as string).includes("MD5")
      );
      expect(md5Finding).toBeDefined();
      expect(md5Finding.severity).toBe("critical");
    });

    it("should handle unreadable PAM files gracefully", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockImplementation(async (params: Record<string, unknown>) => {
        const args = params.args as string[];
        if (args?.[0] === "cat" && args?.[1] === "/etc/pam.d/sudo") {
          return { exitCode: 1, stdout: "", stderr: "Permission denied" };
        }
        return { exitCode: 0, stdout: "", stderr: "" };
      });
      const handler = tools.get("access_control")!.handler;
      const result = await handler({ action: "pam_audit", service: "sudo" });
      expect(result.isError).toBeUndefined();
      const output = JSON.parse(result.content[0].text);
      expect(output.unreadableFiles).toBe(1);
      const unreadable = output.findings.find((f: Record<string, unknown>) => f.type === "FILE_UNREADABLE");
      expect(unreadable).toBeDefined();
    });

    it("should detect SHA-512 hashing as info (good)", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockImplementation(async (params: Record<string, unknown>) => {
        const args = params.args as string[];
        if (args?.[0] === "cat") {
          return {
            exitCode: 0,
            stdout: `auth\trequired\tpam_unix.so sha512
auth\trequired\tpam_faillock.so`,
            stderr: "",
          };
        }
        return { exitCode: 0, stdout: "", stderr: "" };
      });
      const handler = tools.get("access_control")!.handler;
      const result = await handler({ action: "pam_audit", service: "sshd" });
      const output = JSON.parse(result.content[0].text);
      const sha512Finding = output.findings.find(
        (f: Record<string, unknown>) => f.type === "HASH_ALGORITHM" && (f.detail as string).includes("SHA-512")
      );
      expect(sha512Finding).toBeDefined();
      expect(sha512Finding.severity).toBe("info");
    });
  });

  // ── sudo_audit ─────────────────────────────────────────────────────

  describe("sudo_audit", () => {
    it("should detect NOPASSWD entries", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockImplementation(async (params: Record<string, unknown>) => {
        const command = params.command as string;
        const args = params.args as string[];
        if (command === "sudo" && args?.[0] === "cat" && args?.[1] === "/etc/sudoers") {
          return {
            exitCode: 0,
            stdout: `Defaults env_reset
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
root\tALL=(ALL:ALL) ALL
deploy\tALL=(ALL) NOPASSWD: /usr/bin/systemctl restart myapp`,
            stderr: "",
          };
        }
        if (command === "sudo" && args?.[0] === "ls") {
          return { exitCode: 0, stdout: "", stderr: "" };
        }
        if (command === "getent") {
          return { exitCode: 0, stdout: "sudo:x:27:admin", stderr: "" };
        }
        return { exitCode: 0, stdout: "", stderr: "" };
      });
      const handler = tools.get("access_control")!.handler;
      const result = await handler({ action: "sudo_audit", check_nopasswd: true, check_insecure: true });
      expect(result.isError).toBeUndefined();
      const output = JSON.parse(result.content[0].text);
      const nopasswd = output.findings.find((f: Record<string, unknown>) => f.type === "NOPASSWD");
      expect(nopasswd).toBeDefined();
      expect(nopasswd.severity).toBe("high");
    });

    it("should detect !authenticate as critical", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockImplementation(async (params: Record<string, unknown>) => {
        const command = params.command as string;
        const args = params.args as string[];
        if (command === "sudo" && args?.[0] === "cat" && args?.[1] === "/etc/sudoers") {
          return {
            exitCode: 0,
            stdout: `Defaults env_reset
Defaults !authenticate`,
            stderr: "",
          };
        }
        if (command === "sudo" && args?.[0] === "ls") {
          return { exitCode: 0, stdout: "", stderr: "" };
        }
        if (command === "getent") {
          return { exitCode: 0, stdout: "sudo:x:27:", stderr: "" };
        }
        return { exitCode: 0, stdout: "", stderr: "" };
      });
      const handler = tools.get("access_control")!.handler;
      const result = await handler({ action: "sudo_audit", check_nopasswd: true, check_insecure: true });
      const output = JSON.parse(result.content[0].text);
      const noAuth = output.findings.find((f: Record<string, unknown>) => f.type === "NO_AUTHENTICATE");
      expect(noAuth).toBeDefined();
      expect(noAuth.severity).toBe("critical");
    });

    it("should detect broad privilege for non-root users", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockImplementation(async (params: Record<string, unknown>) => {
        const command = params.command as string;
        const args = params.args as string[];
        if (command === "sudo" && args?.[0] === "cat" && args?.[1] === "/etc/sudoers") {
          return {
            exitCode: 0,
            stdout: `Defaults env_reset
Defaults secure_path="/usr/sbin:/usr/bin"
root\tALL=(ALL:ALL) ALL
admin\tALL=(ALL) ALL`,
            stderr: "",
          };
        }
        if (command === "sudo" && args?.[0] === "ls") {
          return { exitCode: 0, stdout: "", stderr: "" };
        }
        if (command === "getent") {
          return { exitCode: 0, stdout: "sudo:x:27:admin", stderr: "" };
        }
        return { exitCode: 0, stdout: "", stderr: "" };
      });
      const handler = tools.get("access_control")!.handler;
      const result = await handler({ action: "sudo_audit", check_nopasswd: true, check_insecure: true });
      const output = JSON.parse(result.content[0].text);
      const broad = output.findings.find((f: Record<string, unknown>) => f.type === "BROAD_PRIVILEGE");
      expect(broad).toBeDefined();
      expect(broad.severity).toBe("high");
    });

    it("should detect missing secure defaults", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockImplementation(async (params: Record<string, unknown>) => {
        const command = params.command as string;
        const args = params.args as string[];
        if (command === "sudo" && args?.[0] === "cat" && args?.[1] === "/etc/sudoers") {
          return {
            exitCode: 0,
            stdout: `# Minimal sudoers
root\tALL=(ALL:ALL) ALL`,
            stderr: "",
          };
        }
        if (command === "sudo" && args?.[0] === "ls") {
          return { exitCode: 0, stdout: "", stderr: "" };
        }
        if (command === "getent") {
          return { exitCode: 0, stdout: "sudo:x:27:", stderr: "" };
        }
        return { exitCode: 0, stdout: "", stderr: "" };
      });
      const handler = tools.get("access_control")!.handler;
      const result = await handler({ action: "sudo_audit", check_nopasswd: true, check_insecure: true });
      const output = JSON.parse(result.content[0].text);
      const missingDefaults = output.findings.filter((f: Record<string, unknown>) => f.type === "MISSING_DEFAULT");
      expect(missingDefaults.length).toBeGreaterThanOrEqual(2); // env_reset and secure_path at minimum
    });

    it("should return error when /etc/sudoers is unreadable", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockImplementation(async (params: Record<string, unknown>) => {
        const command = params.command as string;
        const args = params.args as string[];
        if (command === "sudo" && args?.[0] === "cat" && args?.[1] === "/etc/sudoers") {
          return { exitCode: 1, stdout: "", stderr: "Permission denied" };
        }
        return { exitCode: 0, stdout: "", stderr: "" };
      });
      const handler = tools.get("access_control")!.handler;
      const result = await handler({ action: "sudo_audit", check_nopasswd: true, check_insecure: true });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Cannot read /etc/sudoers");
    });

    it("should include drop-in files in audit", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockImplementation(async (params: Record<string, unknown>) => {
        const command = params.command as string;
        const args = params.args as string[];
        if (command === "sudo" && args?.[0] === "cat" && args?.[1] === "/etc/sudoers") {
          return { exitCode: 0, stdout: "Defaults env_reset\nDefaults secure_path=\"/usr/sbin:/usr/bin\"", stderr: "" };
        }
        if (command === "sudo" && args?.[0] === "ls") {
          return { exitCode: 0, stdout: "deploy\nciadmin", stderr: "" };
        }
        if (command === "sudo" && args?.[0] === "cat" && args?.[1]?.toString().includes("sudoers.d/deploy")) {
          return { exitCode: 0, stdout: "deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl", stderr: "" };
        }
        if (command === "sudo" && args?.[0] === "cat" && args?.[1]?.toString().includes("sudoers.d/ciadmin")) {
          return { exitCode: 0, stdout: "ciadmin ALL=(ALL) ALL", stderr: "" };
        }
        if (command === "getent") {
          return { exitCode: 0, stdout: "sudo:x:27:", stderr: "" };
        }
        return { exitCode: 0, stdout: "", stderr: "" };
      });
      const handler = tools.get("access_control")!.handler;
      const result = await handler({ action: "sudo_audit", check_nopasswd: true, check_insecure: true });
      const output = JSON.parse(result.content[0].text);
      expect(output.dropInFiles).toContain("deploy");
      expect(output.dropInFiles).toContain("ciadmin");
      expect(output.findings.length).toBeGreaterThan(0);
    });
  });

  // ── user_audit ─────────────────────────────────────────────────────

  describe("user_audit", () => {
    const MOCK_PASSWD = [
      "root:x:0:0:root:/root:/bin/bash",
      "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
      "bin:x:2:2:bin:/bin:/usr/sbin/nologin",
      "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
      "syslog:x:104:110::/home/syslog:/bin/bash",
      "admin:x:1000:1000:Admin User:/home/admin:/bin/bash",
      "deploy:x:1001:1001:Deploy User:/home/deploy:/bin/bash",
      "stale:x:1002:1002:Stale User:/home/stale:/bin/bash",
    ].join("\n");

    const MOCK_SHADOW = [
      "root:$6$salt$hash:19000:0:99999:7:::",
      "daemon:*:19000:0:99999:7:::",
      "bin:*:19000:0:99999:7:::",
      "www-data:*:19000:0:99999:7:::",
      "syslog:!!:19000:0:99999:7:::",
      "admin:$6$salt$hash:19000:0:99999:7:::",
      "deploy::19000:0:99999:7:::",
      "stale:!$6$salt$hash:19000:0:99999:7:::",
    ].join("\n");

    const MOCK_LASTLOG = [
      "Username         Port     From             Latest",
      "root                                       **Never logged in**",
      "admin            pts/0    192.168.1.5      Mon Jan  5 10:00:00 +0000 2026",
      "deploy                                     **Never logged in**",
      "stale                                      **Never logged in**",
      "syslog                                     **Never logged in**",
    ].join("\n");

    async function mockExecuteForUserAudit() {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockImplementation(async (params: Record<string, unknown>) => {
        const command = params.command as string;
        const args = params.args as string[];
        if (command === "cat" && args?.[0] === "/etc/passwd") {
          return { exitCode: 0, stdout: MOCK_PASSWD, stderr: "" };
        }
        if (command === "sudo" && args?.[0] === "cat" && args?.[1] === "/etc/shadow") {
          return { exitCode: 0, stdout: MOCK_SHADOW, stderr: "" };
        }
        if (command === "lastlog") {
          return { exitCode: 0, stdout: MOCK_LASTLOG, stderr: "" };
        }
        return { exitCode: 0, stdout: "", stderr: "" };
      });
    }

    it("should audit all user categories by default", async () => {
      await mockExecuteForUserAudit();
      const handler = tools.get("access_control")!.handler;
      const result = await handler({ action: "user_audit", check_type: "all" });
      expect(result.isError).toBeUndefined();
      const output = JSON.parse(result.content[0].text);
      expect(output.checkType).toBe("all");
      expect(output.totalUsers).toBe(8);
      expect(output.categories.privileged).toBeDefined();
      expect(output.categories.inactive).toBeDefined();
      expect(output.categories.no_password).toBeDefined();
      expect(output.categories.shell).toBeDefined();
      expect(output.categories.locked).toBeDefined();
    });

    it("should find privileged users (uid=0)", async () => {
      await mockExecuteForUserAudit();
      const handler = tools.get("access_control")!.handler;
      const result = await handler({ action: "user_audit", check_type: "privileged" });
      const output = JSON.parse(result.content[0].text);
      expect(output.categories.privileged.length).toBe(1);
      expect(output.categories.privileged[0].username).toBe("root");
    });

    it("should detect system users with login shells", async () => {
      await mockExecuteForUserAudit();
      const handler = tools.get("access_control")!.handler;
      const result = await handler({ action: "user_audit", check_type: "shell" });
      const output = JSON.parse(result.content[0].text);
      // syslog (uid=104) has /bin/bash
      const syslogEntry = output.categories.shell.find((u: Record<string, unknown>) => u.username === "syslog");
      expect(syslogEntry).toBeDefined();
      expect(syslogEntry.warning).toContain("interactive login shell");
    });

    it("should detect users with empty or no password", async () => {
      await mockExecuteForUserAudit();
      const handler = tools.get("access_control")!.handler;
      const result = await handler({ action: "user_audit", check_type: "no_password" });
      const output = JSON.parse(result.content[0].text);
      // deploy has empty password hash; daemon/bin/www-data have "*"; syslog has "!!"
      expect(output.categories.no_password.length).toBeGreaterThan(0);
    });

    it("should detect locked accounts", async () => {
      await mockExecuteForUserAudit();
      const handler = tools.get("access_control")!.handler;
      const result = await handler({ action: "user_audit", check_type: "locked" });
      const output = JSON.parse(result.content[0].text);
      // stale has "!" prefix, daemon/bin/www-data have "*"
      expect(output.categories.locked.length).toBeGreaterThan(0);
    });
  });

  // ── password_policy_audit ──────────────────────────────────────────

  describe("password_policy_audit", () => {
    it("should audit login.defs and PAM password settings", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockImplementation(async (params: Record<string, unknown>) => {
        const command = params.command as string;
        const args = params.args as string[];
        if (command === "cat" && args?.[0] === "/etc/login.defs") {
          return {
            exitCode: 0,
            stdout: `PASS_MAX_DAYS\t99999
PASS_MIN_DAYS\t0
PASS_WARN_AGE\t7
ENCRYPT_METHOD SHA512`,
            stderr: "",
          };
        }
        if (command === "cat" && args?.[0]?.toString().includes("common-password")) {
          return {
            exitCode: 0,
            stdout: `password\trequisite\tpam_pwquality.so retry=3
password\t[success=1 default=ignore]\tpam_unix.so sha512`,
            stderr: "",
          };
        }
        if (command === "cat" && args?.[0] === "/etc/default/useradd") {
          return { exitCode: 0, stdout: "INACTIVE=-1", stderr: "" };
        }
        return { exitCode: 0, stdout: "", stderr: "" };
      });
      const handler = tools.get("access_control")!.handler;
      const result = await handler({ action: "password_policy_audit" });
      expect(result.isError).toBeUndefined();
      const output = JSON.parse(result.content[0].text);
      expect(output.loginDefs["PASS_MAX_DAYS"]).toBe("99999");
      expect(output.loginDefs["ENCRYPT_METHOD"]).toBe("SHA512");
      // PASS_MAX_DAYS > 365 should be a recommendation
      const maxDaysRec = output.recommendations.find((r: string) => r.includes("PASS_MAX_DAYS"));
      expect(maxDaysRec).toBeDefined();
      // INACTIVE=-1 should be a recommendation
      const inactiveRec = output.recommendations.find((r: string) => r.includes("INACTIVE"));
      expect(inactiveRec).toBeDefined();
      // pam_pwquality should be detected
      const pwqMod = output.pamModules.find((m: Record<string, unknown>) => m.module === "pam_pwquality");
      expect(pwqMod.present).toBe(true);
    });

    it("should recommend PASS_MIN_DAYS >= 1 when set to 0", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockImplementation(async (params: Record<string, unknown>) => {
        const command = params.command as string;
        const args = params.args as string[];
        if (command === "cat" && args?.[0] === "/etc/login.defs") {
          return { exitCode: 0, stdout: "PASS_MAX_DAYS\t90\nPASS_MIN_DAYS\t0\nPASS_WARN_AGE\t7\nENCRYPT_METHOD SHA512", stderr: "" };
        }
        if (command === "cat" && args?.[0]?.toString().includes("common-password")) {
          return { exitCode: 0, stdout: "password\trequisite\tpam_pwquality.so", stderr: "" };
        }
        if (command === "cat" && args?.[0] === "/etc/default/useradd") {
          return { exitCode: 0, stdout: "INACTIVE=30", stderr: "" };
        }
        return { exitCode: 0, stdout: "", stderr: "" };
      });
      const handler = tools.get("access_control")!.handler;
      const result = await handler({ action: "password_policy_audit" });
      const output = JSON.parse(result.content[0].text);
      const minDaysRec = output.recommendations.find((r: string) => r.includes("PASS_MIN_DAYS"));
      expect(minDaysRec).toBeDefined();
    });

    it("should recommend pam_pwquality when not configured", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockImplementation(async (params: Record<string, unknown>) => {
        const command = params.command as string;
        const args = params.args as string[];
        if (command === "cat" && args?.[0] === "/etc/login.defs") {
          return { exitCode: 0, stdout: "PASS_MAX_DAYS\t90\nPASS_MIN_DAYS\t1\nPASS_WARN_AGE\t14\nENCRYPT_METHOD SHA512", stderr: "" };
        }
        if (command === "cat" && args?.[0]?.toString().includes("common-password")) {
          return { exitCode: 0, stdout: "password\t[success=1 default=ignore]\tpam_unix.so sha512", stderr: "" };
        }
        if (command === "cat" && args?.[0] === "/etc/default/useradd") {
          return { exitCode: 0, stdout: "INACTIVE=30", stderr: "" };
        }
        return { exitCode: 0, stdout: "", stderr: "" };
      });
      const handler = tools.get("access_control")!.handler;
      const result = await handler({ action: "password_policy_audit" });
      const output = JSON.parse(result.content[0].text);
      const pwqRec = output.recommendations.find((r: string) => r.includes("pam_pwquality"));
      expect(pwqRec).toBeDefined();
    });
  });

  // ── password_policy_set (system-wide) ──────────────────────────────

  describe("password_policy_set system-wide", () => {
    it("should require at least one policy parameter", async () => {
      const handler = tools.get("access_control")!.handler;
      const result = await handler({ action: "password_policy_set" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("No password policy values");
    });

    it("should preview changes in dry_run mode", async () => {
      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "password_policy_set",
        max_days: 365,
        min_days: 1,
        warn_days: 14,
        dry_run: true,
      });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("DRY-RUN");
      expect(result.content[0].text).toContain("PASS_MAX_DAYS");
      expect(result.content[0].text).toContain("PASS_MIN_DAYS");
      expect(result.content[0].text).toContain("PASS_WARN_AGE");
    });

    it("should include INACTIVE in dry_run when inactive_days set", async () => {
      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "password_policy_set",
        inactive_days: 30,
        dry_run: true,
      });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("INACTIVE");
    });

    it("should apply system-wide settings (non-dry-run)", async () => {
      const { getConfig } = await import("../../src/core/config.js");
      vi.mocked(getConfig).mockReturnValue({ dryRun: false } as ReturnType<typeof getConfig>);
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValue({ exitCode: 0, stdout: "", stderr: "" });
      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "password_policy_set",
        max_days: 365,
        encrypt_method: "SHA512",
        dry_run: false,
      });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("Password policy updated");
      expect(result.content[0].text).toContain("PASS_MAX_DAYS");
      expect(result.content[0].text).toContain("ENCRYPT_METHOD");
    });

    it("should handle inactive_days in non-dry-run mode", async () => {
      const { getConfig } = await import("../../src/core/config.js");
      vi.mocked(getConfig).mockReturnValue({ dryRun: false } as ReturnType<typeof getConfig>);
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockImplementation(async (params: Record<string, unknown>) => {
        const command = params.command as string;
        const args = params.args as string[];
        // grep for INACTIVE returns found
        if (command === "grep" && args?.[1] === "/etc/default/useradd") {
          return { exitCode: 0, stdout: "INACTIVE=30", stderr: "" };
        }
        return { exitCode: 0, stdout: "", stderr: "" };
      });
      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "password_policy_set",
        inactive_days: 30,
        dry_run: false,
      });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("INACTIVE");
    });
  });

  // ── restrict_shell ─────────────────────────────────────────────────

  describe("restrict_shell", () => {
    it("should require username", async () => {
      const handler = tools.get("access_control")!.handler;
      const result = await handler({ action: "restrict_shell" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("username");
    });

    it("should reject invalid username", async () => {
      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "restrict_shell",
        username: "bad user!",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Invalid username");
    });

    it("should reject invalid shell path", async () => {
      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "restrict_shell",
        username: "deploy",
        shell: "not-a-path",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Invalid shell path");
    });

    it("should refuse to change shell for root", async () => {
      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "restrict_shell",
        username: "root",
        shell: "/usr/sbin/nologin",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("root");
      expect(result.content[0].text).toContain("safety restriction");
    });

    it("should refuse to change shell for current user", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockImplementation(async (params: Record<string, unknown>) => {
        const command = params.command as string;
        if (command === "whoami") {
          return { exitCode: 0, stdout: "deploy", stderr: "" };
        }
        return { exitCode: 0, stdout: "", stderr: "" };
      });
      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "restrict_shell",
        username: "deploy",
        shell: "/usr/sbin/nologin",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("current user");
    });

    it("should return error when user does not exist", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockImplementation(async (params: Record<string, unknown>) => {
        const command = params.command as string;
        if (command === "whoami") {
          return { exitCode: 0, stdout: "admin", stderr: "" };
        }
        if (command === "id") {
          return { exitCode: 1, stdout: "", stderr: "id: 'nosuchuser': no such user" };
        }
        return { exitCode: 0, stdout: "", stderr: "" };
      });
      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "restrict_shell",
        username: "nosuchuser",
        shell: "/usr/sbin/nologin",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("does not exist");
    });

    it("should preview shell change in dry_run mode", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockImplementation(async (params: Record<string, unknown>) => {
        const command = params.command as string;
        if (command === "whoami") {
          return { exitCode: 0, stdout: "admin", stderr: "" };
        }
        if (command === "id") {
          return { exitCode: 0, stdout: "uid=1001(deploy)", stderr: "" };
        }
        if (command === "getent") {
          return { exitCode: 0, stdout: "deploy:x:1001:1001::/home/deploy:/bin/bash", stderr: "" };
        }
        return { exitCode: 0, stdout: "", stderr: "" };
      });
      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "restrict_shell",
        username: "deploy",
        shell: "/usr/sbin/nologin",
        dry_run: true,
      });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("DRY-RUN");
      expect(result.content[0].text).toContain("/bin/bash");
      expect(result.content[0].text).toContain("/usr/sbin/nologin");
    });

    it("should apply shell change successfully (non-dry-run)", async () => {
      const { getConfig } = await import("../../src/core/config.js");
      vi.mocked(getConfig).mockReturnValue({ dryRun: false } as ReturnType<typeof getConfig>);
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockImplementation(async (params: Record<string, unknown>) => {
        const command = params.command as string;
        const args = params.args as string[];
        if (command === "whoami") {
          return { exitCode: 0, stdout: "admin", stderr: "" };
        }
        if (command === "id") {
          return { exitCode: 0, stdout: "uid=1001(deploy)", stderr: "" };
        }
        if (command === "getent") {
          return { exitCode: 0, stdout: "deploy:x:1001:1001::/home/deploy:/bin/bash", stderr: "" };
        }
        if (command === "sudo" && args?.[0] === "usermod") {
          return { exitCode: 0, stdout: "", stderr: "" };
        }
        return { exitCode: 0, stdout: "", stderr: "" };
      });
      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "restrict_shell",
        username: "deploy",
        shell: "/usr/sbin/nologin",
        dry_run: false,
      });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("Shell restricted");
      expect(result.content[0].text).toContain("Rollback");
    });

    it("should report error when usermod fails", async () => {
      const { getConfig } = await import("../../src/core/config.js");
      vi.mocked(getConfig).mockReturnValue({ dryRun: false } as ReturnType<typeof getConfig>);
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockImplementation(async (params: Record<string, unknown>) => {
        const command = params.command as string;
        const args = params.args as string[];
        if (command === "whoami") {
          return { exitCode: 0, stdout: "admin", stderr: "" };
        }
        if (command === "id") {
          return { exitCode: 0, stdout: "uid=1001(deploy)", stderr: "" };
        }
        if (command === "getent") {
          return { exitCode: 0, stdout: "deploy:x:1001:1001::/home/deploy:/bin/bash", stderr: "" };
        }
        if (command === "sudo" && args?.[0] === "usermod") {
          return { exitCode: 1, stdout: "", stderr: "usermod: user 'deploy' does not exist" };
        }
        return { exitCode: 0, stdout: "", stderr: "" };
      });
      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "restrict_shell",
        username: "deploy",
        shell: "/usr/sbin/nologin",
        dry_run: false,
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Failed to change shell");
    });

    it("should accept a custom shell path", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockImplementation(async (params: Record<string, unknown>) => {
        const command = params.command as string;
        if (command === "whoami") {
          return { exitCode: 0, stdout: "admin", stderr: "" };
        }
        if (command === "id") {
          return { exitCode: 0, stdout: "uid=1001(deploy)", stderr: "" };
        }
        if (command === "getent") {
          return { exitCode: 0, stdout: "deploy:x:1001:1001::/home/deploy:/bin/bash", stderr: "" };
        }
        return { exitCode: 0, stdout: "", stderr: "" };
      });
      const handler = tools.get("access_control")!.handler;
      const result = await handler({
        action: "restrict_shell",
        username: "deploy",
        shell: "/bin/false",
        dry_run: true,
      });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("/bin/false");
    });
  });

});
