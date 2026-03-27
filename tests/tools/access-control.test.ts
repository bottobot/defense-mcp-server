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
  });

});
