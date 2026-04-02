/**
 * Tests for src/tools/patch-management.ts
 *
 * Covers: tool registration, vulnerability_intel action routing,
 * CVE ID validation, dry_run defaults, and distro-aware patching.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/core/executor.js", () => ({
  executeCommand: vi.fn().mockResolvedValue({ exitCode: 0, stdout: "", stderr: "", timedOut: false, duration: 10, permissionDenied: false }),
}));
vi.mock("../../src/core/config.js", () => ({
  getConfig: vi.fn().mockReturnValue({ dryRun: true, networkTimeout: 10000 }),
  getToolTimeout: vi.fn().mockReturnValue(30000),
}));
vi.mock("../../src/core/parsers.js", () => ({
  createTextContent: vi.fn((text: string) => ({ type: "text", text })),
  createErrorContent: vi.fn((text: string) => ({ type: "text", text: `Error: ${text}` })),
  formatToolOutput: vi.fn((obj: unknown) => ({ type: "text", text: JSON.stringify(obj) })),
}));
vi.mock("../../src/core/distro-adapter.js", () => ({
  getDistroAdapter: vi.fn().mockResolvedValue({
    isDebian: true,
    isRhel: false,
    isSuse: false,
    isArch: false,
    isAlpine: false,
    summary: "Debian 12",
    pkg: { updateCmd: () => ["apt-get", "update"] },
    pkgQuery: {
      listUpgradableCmd: ["apt", "list", "--upgradable"],
      showHeldCmd: ["dpkg", "--get-selections"],
      autoRemoveCmd: ["apt-get", "--dry-run", "autoremove"],
      listKernelsCmd: ["dpkg", "--list", "linux-image-*"],
    },
    autoUpdate: {
      supported: true,
      packageName: "unattended-upgrades",
      checkInstalledCmd: ["dpkg", "-s", "unattended-upgrades"],
      serviceName: "unattended-upgrades",
      configFiles: ["/etc/apt/apt.conf.d/20auto-upgrades"],
      installHint: "sudo apt install unattended-upgrades",
    },
    integrity: {
      supported: true,
      toolName: "debsums",
      checkCmd: ["debsums", "-s"],
      checkPackageCmd: (pkg: string) => ["debsums", pkg],
      installHint: "sudo apt install debsums",
    },
  }),
}));
vi.mock("../../src/core/distro.js", () => ({
  detectDistro: vi.fn().mockResolvedValue({ id: "debian", family: "debian", name: "Debian", packageManager: "apt" }),
}));
vi.mock("node:https", () => ({
  get: vi.fn(),
}));

import { registerPatchManagementTools } from "../../src/tools/patch-management.js";

type ToolHandler = (params: Record<string, unknown>) => Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }>;

function createMockServer() {
  const tools = new Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>();
  const server = {
    tool: vi.fn((name: string, _desc: string, schema: Record<string, unknown>, handler: ToolHandler) => {
      tools.set(name, { schema, handler });
    }),
  };
  return { server: server as unknown as Parameters<typeof registerPatchManagementTools>[0], tools };
}

describe("patch-management tools", () => {
  let tools: Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>;

  beforeEach(() => {
    vi.clearAllMocks();
    const mock = createMockServer();
    registerPatchManagementTools(mock.server);
    tools = mock.tools;
  });

  it("should register 1 patch tool", () => {
    expect(tools.has("patch")).toBe(true);
    expect(tools.size).toBe(1);
  });

  // ── vuln_lookup ───────────────────────────────────────────────────────

  it("should require cveId for vuln_lookup action", async () => {
    const handler = tools.get("patch")!.handler;
    const result = await handler({ action: "vuln_lookup", dryRun: true });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("cveId is required");
  });

  it("should reject malformed CVE ID", async () => {
    const handler = tools.get("patch")!.handler;
    const result = await handler({ action: "vuln_lookup", cveId: "not-a-cve", dryRun: true });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("CVE-YYYY-NNNN");
  });

  it("should accept valid CVE ID in dry_run mode", async () => {
    const handler = tools.get("patch")!.handler;
    const result = await handler({ action: "vuln_lookup", cveId: "CVE-2024-1234", dryRun: true });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("dryRun");
  });

  it("should preview vuln_scan action in dry_run mode", async () => {
    const handler = tools.get("patch")!.handler;
    const result = await handler({ action: "vuln_scan", maxPackages: 10, dryRun: true });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("dryRun");
  });

  it("should require packageName for vuln_urgency action", async () => {
    const handler = tools.get("patch")!.handler;
    const result = await handler({ action: "vuln_urgency", dryRun: true });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("packageName is required");
  });

  it("should preview vuln_urgency action in dry_run mode", async () => {
    const handler = tools.get("patch")!.handler;
    const result = await handler({ action: "vuln_urgency", packageName: "openssl", dryRun: true });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("dryRun");
  });

  it("should handle unknown action", async () => {
    const handler = tools.get("patch")!.handler;
    const result = await handler({ action: "unknown" as string });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Unknown action");
  });

  // ── update_audit ────────────────────────────────────────────────────

  describe("update_audit", () => {
    it("should return upgradable packages for Debian", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const handler = tools.get("patch")!.handler;

      vi.mocked(executeCommand)
        // apt-get update
        .mockResolvedValueOnce({ exitCode: 0, stdout: "Hit:1 http://deb.debian.org/debian bookworm InRelease\n", stderr: "", timedOut: false, duration: 100, permissionDenied: false })
        // apt list --upgradable
        .mockResolvedValueOnce({ exitCode: 0, stdout: "openssl/bookworm-security 3.0.14-1~deb12u1 amd64 [upgradable from: 3.0.11-1~deb12u2]\ncurl/bookworm 8.5.0-1 amd64 [upgradable from: 7.88.1-10]\n", stderr: "", timedOut: false, duration: 50, permissionDenied: false })
        // dpkg --get-selections (held)
        .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "", timedOut: false, duration: 10, permissionDenied: false })
        // apt-get --dry-run autoremove
        .mockResolvedValueOnce({ exitCode: 0, stdout: "0 upgraded, 0 newly installed, 3 to remove and 0 not upgraded.\n", stderr: "", timedOut: false, duration: 10, permissionDenied: false })
        // uname -r
        .mockResolvedValueOnce({ exitCode: 0, stdout: "6.1.0-18-amd64\n", stderr: "", timedOut: false, duration: 5, permissionDenied: false });

      const result = await handler({ action: "update_audit", security_only: false, dryRun: true });
      const output = JSON.parse(result.content[0].text);

      expect(output.summary.totalUpgradable).toBe(2);
      expect(output.summary.securityUpdates).toBe(1);
      expect(output.summary.currentKernel).toBe("6.1.0-18-amd64");
      expect(output.summary.autoRemoveCandidates).toBe(3);
      expect(output.summary.status).toBe("SECURITY_UPDATES_PENDING");
      expect(output.packages).toHaveLength(2);
      expect(output.packages[0].name).toBe("openssl");
      expect(output.packages[0].security).toBe(true);
      expect(output.packages[1].name).toBe("curl");
      expect(output.packages[1].security).toBe(false);
    });

    it("should filter to security-only when requested", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const handler = tools.get("patch")!.handler;

      vi.mocked(executeCommand)
        .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "", timedOut: false, duration: 100, permissionDenied: false })
        .mockResolvedValueOnce({ exitCode: 0, stdout: "openssl/bookworm-security 3.0.14-1~deb12u1 amd64 [upgradable from: 3.0.11-1~deb12u2]\ncurl/bookworm 8.5.0-1 amd64 [upgradable from: 7.88.1-10]\n", stderr: "", timedOut: false, duration: 50, permissionDenied: false })
        .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "", timedOut: false, duration: 10, permissionDenied: false })
        .mockResolvedValueOnce({ exitCode: 0, stdout: "0 to remove\n", stderr: "", timedOut: false, duration: 10, permissionDenied: false })
        .mockResolvedValueOnce({ exitCode: 0, stdout: "6.1.0-18-amd64\n", stderr: "", timedOut: false, duration: 5, permissionDenied: false });

      const result = await handler({ action: "update_audit", security_only: true, dryRun: true });
      const output = JSON.parse(result.content[0].text);

      expect(output.packages).toHaveLength(1);
      expect(output.packages[0].name).toBe("openssl");
    });

    it("should report UP_TO_DATE when no packages are upgradable", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const handler = tools.get("patch")!.handler;

      vi.mocked(executeCommand)
        .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "", timedOut: false, duration: 100, permissionDenied: false })
        .mockResolvedValueOnce({ exitCode: 0, stdout: "Listing... Done\n", stderr: "", timedOut: false, duration: 50, permissionDenied: false })
        .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "", timedOut: false, duration: 10, permissionDenied: false })
        .mockResolvedValueOnce({ exitCode: 0, stdout: "0 to remove\n", stderr: "", timedOut: false, duration: 10, permissionDenied: false })
        .mockResolvedValueOnce({ exitCode: 0, stdout: "6.1.0-18-amd64\n", stderr: "", timedOut: false, duration: 5, permissionDenied: false });

      const result = await handler({ action: "update_audit", security_only: false, dryRun: true });
      const output = JSON.parse(result.content[0].text);

      expect(output.summary.totalUpgradable).toBe(0);
      expect(output.summary.status).toBe("UP_TO_DATE");
    });

    it("should report held-back packages", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const handler = tools.get("patch")!.handler;

      vi.mocked(executeCommand)
        .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "", timedOut: false, duration: 100, permissionDenied: false })
        .mockResolvedValueOnce({ exitCode: 0, stdout: "Listing... Done\n", stderr: "", timedOut: false, duration: 50, permissionDenied: false })
        .mockResolvedValueOnce({ exitCode: 0, stdout: "linux-image-amd64\thold\n", stderr: "", timedOut: false, duration: 10, permissionDenied: false })
        .mockResolvedValueOnce({ exitCode: 0, stdout: "0 to remove\n", stderr: "", timedOut: false, duration: 10, permissionDenied: false })
        .mockResolvedValueOnce({ exitCode: 0, stdout: "6.1.0-18-amd64\n", stderr: "", timedOut: false, duration: 5, permissionDenied: false });

      const result = await handler({ action: "update_audit", security_only: false, dryRun: true });
      const output = JSON.parse(result.content[0].text);

      expect(output.summary.heldBack).toContain("linux-image-amd64\thold");
    });

    it("should handle executeCommand failure gracefully", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const handler = tools.get("patch")!.handler;

      vi.mocked(executeCommand).mockRejectedValueOnce(new Error("Permission denied"));

      const result = await handler({ action: "update_audit", security_only: false, dryRun: true });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Permission denied");
    });
  });

  // ── unattended_audit ────────────────────────────────────────────────

  describe("unattended_audit", () => {
    it("should report installed and enabled unattended-upgrades on Debian", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const handler = tools.get("patch")!.handler;

      vi.mocked(executeCommand)
        // dpkg -s unattended-upgrades (installed check)
        .mockResolvedValueOnce({ exitCode: 0, stdout: "Status: ii installed\n", stderr: "", timedOut: false, duration: 10, permissionDenied: false })
        // systemctl is-enabled
        .mockResolvedValueOnce({ exitCode: 0, stdout: "enabled\n", stderr: "", timedOut: false, duration: 10, permissionDenied: false })
        // cat /etc/apt/apt.conf.d/20auto-upgrades
        .mockResolvedValueOnce({ exitCode: 0, stdout: 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n', stderr: "", timedOut: false, duration: 5, permissionDenied: false });

      const result = await handler({ action: "unattended_audit", dryRun: true });
      const output = JSON.parse(result.content[0].text);

      expect(output.summary.pass).toBeGreaterThanOrEqual(3);
      expect(output.summary.fail).toBe(0);
      expect(output.recommendation).toContain("properly configured");
    });

    it("should report not installed unattended-upgrades", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const handler = tools.get("patch")!.handler;

      vi.mocked(executeCommand)
        // dpkg -s returns no "ii"
        .mockResolvedValueOnce({ exitCode: 1, stdout: "dpkg-query: package 'unattended-upgrades' is not installed\n", stderr: "", timedOut: false, duration: 10, permissionDenied: false });

      const result = await handler({ action: "unattended_audit", dryRun: true });
      const output = JSON.parse(result.content[0].text);

      expect(output.findings[0].status).toBe("FAIL");
      expect(output.recommendation).toContain("CRITICAL");
    });

    it("should handle unsupported distro for auto-updates", async () => {
      const { getDistroAdapter } = await import("../../src/core/distro-adapter.js");
      const handler = tools.get("patch")!.handler;

      vi.mocked(getDistroAdapter).mockResolvedValueOnce({
        isDebian: false, isRhel: false, isSuse: false, isArch: true, isAlpine: false,
        summary: "Arch Linux",
        distro: { name: "Arch Linux", id: "arch", family: "arch", packageManager: "pacman" },
        autoUpdate: {
          supported: false,
          packageName: "",
          checkInstalledCmd: [],
          serviceName: "",
          configFiles: [],
          installHint: "Consider using a cron job with pacman -Syu",
        },
      } as any);

      const result = await handler({ action: "unattended_audit", dryRun: true });
      const output = JSON.parse(result.content[0].text);

      expect(output.supported).toBe(false);
      expect(output.message).toContain("not natively supported");
    });

    it("should report disabled service", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const handler = tools.get("patch")!.handler;

      vi.mocked(executeCommand)
        .mockResolvedValueOnce({ exitCode: 0, stdout: "Status: ii installed\n", stderr: "", timedOut: false, duration: 10, permissionDenied: false })
        // systemctl is-enabled returns disabled
        .mockResolvedValueOnce({ exitCode: 0, stdout: "disabled\n", stderr: "", timedOut: false, duration: 10, permissionDenied: false })
        // config file
        .mockResolvedValueOnce({ exitCode: 0, stdout: 'APT::Periodic::Update-Package-Lists "0";\nAPT::Periodic::Unattended-Upgrade "0";\n', stderr: "", timedOut: false, duration: 5, permissionDenied: false });

      const result = await handler({ action: "unattended_audit", dryRun: true });
      const output = JSON.parse(result.content[0].text);

      const serviceFinding = output.findings.find((f: any) => f.check === "service_enabled");
      expect(serviceFinding.status).toBe("FAIL");
      expect(output.summary.fail).toBeGreaterThan(0);
      expect(output.recommendation).toContain("WARNING");
    });

    it("should handle missing config file", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const handler = tools.get("patch")!.handler;

      vi.mocked(executeCommand)
        .mockResolvedValueOnce({ exitCode: 0, stdout: "Status: ii installed\n", stderr: "", timedOut: false, duration: 10, permissionDenied: false })
        .mockResolvedValueOnce({ exitCode: 0, stdout: "enabled\n", stderr: "", timedOut: false, duration: 10, permissionDenied: false })
        // config file not found
        .mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "No such file or directory", timedOut: false, duration: 5, permissionDenied: false });

      const result = await handler({ action: "unattended_audit", dryRun: true });
      const output = JSON.parse(result.content[0].text);

      const configFinding = output.findings.find((f: any) => f.check === "config_file");
      expect(configFinding.status).toBe("FAIL");
      expect(configFinding.value).toBe("missing");
    });
  });

  // ── integrity_check ─────────────────────────────────────────────────

  describe("integrity_check", () => {
    it("should detect modified files on Debian", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const handler = tools.get("patch")!.handler;

      vi.mocked(executeCommand).mockResolvedValueOnce({
        exitCode: 0,
        stdout: "/usr/bin/test CHANGED\n/etc/passwd CHANGED\n/usr/lib/foo OK\n",
        stderr: "",
        timedOut: false, duration: 500, permissionDenied: false,
      });

      const result = await handler({ action: "integrity_check", changed_only: true, dryRun: true });
      const output = JSON.parse(result.content[0].text);

      expect(output.summary.changed).toBe(2);
      expect(output.summary.status).toBe("WARN");
      expect(output.changedFiles).toHaveLength(2);
      expect(output.note).toContain("Modified files detected");
    });

    it("should report clean integrity check", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const handler = tools.get("patch")!.handler;

      vi.mocked(executeCommand).mockResolvedValueOnce({
        exitCode: 0,
        stdout: "/usr/bin/test OK\n/usr/lib/foo OK\n",
        stderr: "",
        timedOut: false, duration: 500, permissionDenied: false,
      });

      const result = await handler({ action: "integrity_check", changed_only: true, dryRun: true });
      const output = JSON.parse(result.content[0].text);

      expect(output.summary.changed).toBe(0);
      expect(output.summary.status).toBe("PASS");
      expect(output.note).toContain("match their package checksums");
    });

    it("should handle unsupported distro for integrity check", async () => {
      const { getDistroAdapter } = await import("../../src/core/distro-adapter.js");
      const handler = tools.get("patch")!.handler;

      vi.mocked(getDistroAdapter).mockResolvedValueOnce({
        isDebian: false, isRhel: false, isSuse: false, isArch: false, isAlpine: true,
        summary: "Alpine 3.19",
        integrity: {
          supported: false,
          toolName: "",
          checkCmd: [],
          checkPackageCmd: () => [],
          installHint: "apk audit is limited",
        },
      } as any);

      const result = await handler({ action: "integrity_check", changed_only: true, dryRun: true });
      const output = JSON.parse(result.content[0].text);

      expect(output.error).toContain("not supported");
    });

    it("should check specific package when package_name is provided", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const handler = tools.get("patch")!.handler;

      vi.mocked(executeCommand).mockResolvedValueOnce({
        exitCode: 0,
        stdout: "/usr/bin/openssl OK\n",
        stderr: "",
        timedOut: false, duration: 100, permissionDenied: false,
      });

      const result = await handler({ action: "integrity_check", package_name: "openssl", changed_only: true, dryRun: true });
      const output = JSON.parse(result.content[0].text);

      expect(output.summary.status).toBe("PASS");
      // Verify executeCommand was called with the package-specific command
      expect(vi.mocked(executeCommand)).toHaveBeenCalledWith(
        expect.objectContaining({ args: ["debsums", "openssl"] })
      );
    });

    it("should handle tool not found error", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const handler = tools.get("patch")!.handler;

      vi.mocked(executeCommand).mockRejectedValueOnce(new Error("debsums: not found"));

      const result = await handler({ action: "integrity_check", changed_only: true, dryRun: true });
      const output = JSON.parse(result.content[0].text);

      expect(output.error).toContain("not available");
      expect(output.recommendation).toBeDefined();
    });
  });

  // ── kernel_audit ────────────────────────────────────────────────────

  describe("kernel_audit", () => {
    it("should report kernel info with CPU vulnerabilities on Debian", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const handler = tools.get("patch")!.handler;

      vi.mocked(executeCommand)
        // uname -r
        .mockResolvedValueOnce({ exitCode: 0, stdout: "6.1.0-18-amd64\n", stderr: "", timedOut: false, duration: 5, permissionDenied: false })
        // dpkg --list linux-image-*
        .mockResolvedValueOnce({ exitCode: 0, stdout: "ii  linux-image-6.1.0-17-amd64 6.1.69-1 amd64 Linux 6.1\nii  linux-image-6.1.0-18-amd64 6.1.76-1 amd64 Linux 6.1\n", stderr: "", timedOut: false, duration: 10, permissionDenied: false })
        // ls /sys/devices/system/cpu/vulnerabilities/
        .mockResolvedValueOnce({ exitCode: 0, stdout: "spectre_v1\nspectre_v2\nmeltdown\n", stderr: "", timedOut: false, duration: 5, permissionDenied: false })
        // cat spectre_v1
        .mockResolvedValueOnce({ exitCode: 0, stdout: "Mitigation: usercopy/swapgs barriers\n", stderr: "", timedOut: false, duration: 5, permissionDenied: false })
        // cat spectre_v2
        .mockResolvedValueOnce({ exitCode: 0, stdout: "Mitigation: Retpolines\n", stderr: "", timedOut: false, duration: 5, permissionDenied: false })
        // cat meltdown
        .mockResolvedValueOnce({ exitCode: 0, stdout: "Not affected\n", stderr: "", timedOut: false, duration: 5, permissionDenied: false })
        // uptime -s
        .mockResolvedValueOnce({ exitCode: 0, stdout: "2024-01-15 10:30:00\n", stderr: "", timedOut: false, duration: 5, permissionDenied: false })
        // canonical-livepatch status
        .mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "not installed", timedOut: false, duration: 5, permissionDenied: false });

      const result = await handler({ action: "kernel_audit", dryRun: true });
      const output = JSON.parse(result.content[0].text);

      expect(output.currentKernel).toBe("6.1.0-18-amd64");
      expect(output.installedKernels).toHaveLength(2);
      expect(output.cpuVulnerabilities.total).toBe(3);
      expect(output.cpuVulnerabilities.mitigated).toBe(3);
      expect(output.cpuVulnerabilities.unmitigated).toBe(0);
      expect(output.livepatch.available).toBe(false);
      expect(output.bootTime).toBe("2024-01-15 10:30:00");
    });

    it("should flag unmitigated CPU vulnerabilities", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const handler = tools.get("patch")!.handler;

      vi.mocked(executeCommand)
        .mockResolvedValueOnce({ exitCode: 0, stdout: "6.1.0-18-amd64\n", stderr: "", timedOut: false, duration: 5, permissionDenied: false })
        .mockResolvedValueOnce({ exitCode: 0, stdout: "ii  linux-image-6.1.0-18-amd64 6.1.76-1 amd64 Linux 6.1\n", stderr: "", timedOut: false, duration: 10, permissionDenied: false })
        // vulnerabilities dir
        .mockResolvedValueOnce({ exitCode: 0, stdout: "spectre_v1\n", stderr: "", timedOut: false, duration: 5, permissionDenied: false })
        // spectre_v1 - Vulnerable
        .mockResolvedValueOnce({ exitCode: 0, stdout: "Vulnerable\n", stderr: "", timedOut: false, duration: 5, permissionDenied: false })
        .mockResolvedValueOnce({ exitCode: 0, stdout: "2024-01-15 10:30:00\n", stderr: "", timedOut: false, duration: 5, permissionDenied: false })
        .mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "", timedOut: false, duration: 5, permissionDenied: false });

      const result = await handler({ action: "kernel_audit", dryRun: true });
      const output = JSON.parse(result.content[0].text);

      expect(output.cpuVulnerabilities.unmitigated).toBe(1);
      expect(output.recommendations).toContainEqual(expect.stringContaining("CPU vulnerabilities not fully mitigated"));
    });

    it("should recommend cleanup when many old kernels are installed", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const handler = tools.get("patch")!.handler;

      vi.mocked(executeCommand)
        .mockResolvedValueOnce({ exitCode: 0, stdout: "6.1.0-20-amd64\n", stderr: "", timedOut: false, duration: 5, permissionDenied: false })
        // 4 kernels installed
        .mockResolvedValueOnce({ exitCode: 0, stdout: "ii  linux-image-6.1.0-17-amd64 6.1.69-1 amd64 Linux\nii  linux-image-6.1.0-18-amd64 6.1.76-1 amd64 Linux\nii  linux-image-6.1.0-19-amd64 6.1.80-1 amd64 Linux\nii  linux-image-6.1.0-20-amd64 6.1.85-1 amd64 Linux\n", stderr: "", timedOut: false, duration: 10, permissionDenied: false })
        // no vulnerabilities dir
        .mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "No such file", timedOut: false, duration: 5, permissionDenied: false })
        .mockResolvedValueOnce({ exitCode: 0, stdout: "2024-03-01 08:00:00\n", stderr: "", timedOut: false, duration: 5, permissionDenied: false })
        .mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "", timedOut: false, duration: 5, permissionDenied: false });

      const result = await handler({ action: "kernel_audit", dryRun: true });
      const output = JSON.parse(result.content[0].text);

      expect(output.installedKernels).toHaveLength(4);
      expect(output.recommendations).toContainEqual(expect.stringContaining("old kernels"));
    });

    it("should handle kernel_audit error gracefully", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const handler = tools.get("patch")!.handler;

      vi.mocked(executeCommand).mockRejectedValueOnce(new Error("uname failed"));

      const result = await handler({ action: "kernel_audit", dryRun: true });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("uname failed");
    });
  });

  // ── vuln_lookup (non-dry-run) ───────────────────────────────────────

  describe("vuln_lookup (non-dry-run)", () => {
    it("should fetch CVE data from NVD API", async () => {
      const { getConfig } = await import("../../src/core/config.js");
      const https = await import("node:https");
      const handler = tools.get("patch")!.handler;

      vi.mocked(getConfig).mockReturnValue({ dryRun: false, networkTimeout: 10000 } as any);

      const mockResponse = {
        statusCode: 200,
        on: vi.fn((event: string, cb: Function) => {
          if (event === "data") {
            const body = JSON.stringify({
              vulnerabilities: [{
                cve: {
                  id: "CVE-2024-1234",
                  descriptions: [{ lang: "en", value: "Test vulnerability description" }],
                  published: "2024-01-01T00:00:00Z",
                  lastModified: "2024-01-02T00:00:00Z",
                  metrics: {
                    cvssMetricV31: [{ cvssData: { baseScore: 7.5, baseSeverity: "HIGH", vectorString: "CVSS:3.1/AV:N" } }],
                  },
                  references: [{ url: "https://example.com/advisory" }],
                },
              }],
            });
            cb(Buffer.from(body));
          }
          if (event === "end") {
            cb();
          }
          return mockResponse;
        }),
      };

      const mockReq = {
        on: vi.fn().mockReturnThis(),
        destroy: vi.fn(),
      };

      vi.mocked(https.get).mockImplementation((_url: any, _opts: any, cb: any) => {
        cb(mockResponse);
        return mockReq as any;
      });

      const result = await handler({ action: "vuln_lookup", cveId: "CVE-2024-1234", dryRun: false });
      const output = JSON.parse(result.content[0].text);

      expect(output.cveId).toBe("CVE-2024-1234");
      expect(output.description).toBe("Test vulnerability description");
      expect(output.cvssV31.score).toBe(7.5);
      expect(output.cvssV31.severity).toBe("HIGH");
      expect(output.references).toContain("https://example.com/advisory");
    });

    it("should handle CVE not found", async () => {
      const { getConfig } = await import("../../src/core/config.js");
      const https = await import("node:https");
      const handler = tools.get("patch")!.handler;

      vi.mocked(getConfig).mockReturnValue({ dryRun: false, networkTimeout: 10000 } as any);

      const mockResponse = {
        statusCode: 200,
        on: vi.fn((event: string, cb: Function) => {
          if (event === "data") cb(Buffer.from(JSON.stringify({ vulnerabilities: [] })));
          if (event === "end") cb();
          return mockResponse;
        }),
      };
      const mockReq = { on: vi.fn().mockReturnThis(), destroy: vi.fn() };

      vi.mocked(https.get).mockImplementation((_url: any, _opts: any, cb: any) => {
        cb(mockResponse);
        return mockReq as any;
      });

      const result = await handler({ action: "vuln_lookup", cveId: "CVE-2024-9999", dryRun: false });
      const output = JSON.parse(result.content[0].text);

      expect(output.found).toBe(false);
    });

    it("should handle NVD API rate limit (HTTP 403)", async () => {
      const { getConfig } = await import("../../src/core/config.js");
      const https = await import("node:https");
      const handler = tools.get("patch")!.handler;

      vi.mocked(getConfig).mockReturnValue({ dryRun: false, networkTimeout: 10000 } as any);

      const mockResponse = {
        statusCode: 403,
        on: vi.fn().mockReturnThis(),
      };
      const mockReq = { on: vi.fn().mockReturnThis(), destroy: vi.fn() };

      vi.mocked(https.get).mockImplementation((_url: any, _opts: any, cb: any) => {
        cb(mockResponse);
        return mockReq as any;
      });

      const result = await handler({ action: "vuln_lookup", cveId: "CVE-2024-1234", dryRun: false });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("rate limit");
    });
  });

  // ── vuln_scan (non-dry-run) ─────────────────────────────────────────

  describe("vuln_scan (non-dry-run)", () => {
    it("should scan for vulnerable packages on Debian using apt-get", async () => {
      const { getConfig } = await import("../../src/core/config.js");
      const { executeCommand } = await import("../../src/core/executor.js");
      const handler = tools.get("patch")!.handler;

      vi.mocked(getConfig).mockReturnValue({ dryRun: false, networkTimeout: 10000 } as any);

      vi.mocked(executeCommand)
        // which debsecan -> not found
        .mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "", timedOut: false, duration: 5, permissionDenied: false })
        // apt-get upgrade -s
        .mockResolvedValueOnce({
          exitCode: 0,
          stdout: "Inst openssl [3.0.11-1~deb12u2] (3.0.14-1~deb12u1 Debian:12.5/stable [amd64])\nInst curl [7.88.1-10] (8.5.0-1 Debian:12.5/stable [amd64])\nConf openssl (3.0.14-1~deb12u1)\nConf curl (8.5.0-1)\n",
          stderr: "", timedOut: false, duration: 100, permissionDenied: false,
        });

      const result = await handler({ action: "vuln_scan", maxPackages: 50, dryRun: false });
      const output = JSON.parse(result.content[0].text);

      expect(output.tool).toBe("apt-get upgrade -s");
      expect(output.upgradablePackages).toBe(2);
      expect(output.packages[0].package).toBe("openssl");
      expect(output.packages[0].current).toBe("3.0.11-1~deb12u2");
      expect(output.packages[0].available).toBe("3.0.14-1~deb12u1");
    });

    it("should use debsecan when available", async () => {
      const { getConfig } = await import("../../src/core/config.js");
      const { executeCommand } = await import("../../src/core/executor.js");
      const handler = tools.get("patch")!.handler;

      vi.mocked(getConfig).mockReturnValue({ dryRun: false, networkTimeout: 10000 } as any);

      vi.mocked(executeCommand)
        // which debsecan -> found
        .mockResolvedValueOnce({ exitCode: 0, stdout: "/usr/bin/debsecan\n", stderr: "", timedOut: false, duration: 5, permissionDenied: false })
        // debsecan --format detail
        .mockResolvedValueOnce({
          exitCode: 0,
          stdout: "CVE-2024-1234 openssl -- buffer overflow\nCVE-2024-5678 curl -- redirect issue\n",
          stderr: "", timedOut: false, duration: 200, permissionDenied: false,
        });

      const result = await handler({ action: "vuln_scan", maxPackages: 50, dryRun: false });
      const output = JSON.parse(result.content[0].text);

      expect(output.tool).toBe("debsecan");
      expect(output.totalFindings).toBe(2);
    });

    it("should handle vuln_scan error", async () => {
      const { getConfig } = await import("../../src/core/config.js");
      const { executeCommand } = await import("../../src/core/executor.js");
      const { detectDistro } = await import("../../src/core/distro.js");
      const handler = tools.get("patch")!.handler;

      vi.mocked(getConfig).mockReturnValue({ dryRun: false, networkTimeout: 10000 } as any);
      vi.mocked(detectDistro).mockRejectedValueOnce(new Error("Cannot detect distro"));

      const result = await handler({ action: "vuln_scan", maxPackages: 50, dryRun: false });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Package CVE scan failed");
    });
  });

  // ── vuln_urgency (non-dry-run) ──────────────────────────────────────

  describe("vuln_urgency (non-dry-run)", () => {
    it("should report package urgency info for installed Debian package", async () => {
      const { getConfig } = await import("../../src/core/config.js");
      const { executeCommand } = await import("../../src/core/executor.js");
      const handler = tools.get("patch")!.handler;

      vi.mocked(getConfig).mockReturnValue({ dryRun: false, networkTimeout: 10000 } as any);

      vi.mocked(executeCommand)
        // dpkg-query -W
        .mockResolvedValueOnce({ exitCode: 0, stdout: "3.0.11-1~deb12u2", stderr: "", timedOut: false, duration: 10, permissionDenied: false })
        // apt-cache policy
        .mockResolvedValueOnce({ exitCode: 0, stdout: "openssl:\n  Installed: 3.0.11-1~deb12u2\n  Candidate: 3.0.14-1~deb12u1\n  Version table:\n", stderr: "", timedOut: false, duration: 10, permissionDenied: false })
        // apt-get changelog
        .mockResolvedValueOnce({ exitCode: 0, stdout: "openssl (3.0.14-1~deb12u1) bookworm-security; urgency=high\n  * Fix CVE-2024-1234: buffer overflow\n  * security update\nopenssl (3.0.11-1) bookworm; urgency=medium\n  * Regular update\n", stderr: "", timedOut: false, duration: 100, permissionDenied: false });

      const result = await handler({ action: "vuln_urgency", packageName: "openssl", dryRun: false });
      const output = JSON.parse(result.content[0].text);

      expect(output.package).toBe("openssl");
      expect(output.installedVersion).toBe("3.0.11-1~deb12u2");
      expect(output.candidateVersion).toBe("3.0.14-1~deb12u1");
      expect(output.updateAvailable).toBe(true);
      expect(output.securityEntries).toBeDefined();
      expect(output.securityEntries.length).toBeGreaterThan(0);
    });

    it("should handle not-installed package", async () => {
      const { getConfig } = await import("../../src/core/config.js");
      const { executeCommand } = await import("../../src/core/executor.js");
      const handler = tools.get("patch")!.handler;

      vi.mocked(getConfig).mockReturnValue({ dryRun: false, networkTimeout: 10000 } as any);

      vi.mocked(executeCommand)
        // dpkg-query returns error
        .mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "not installed", timedOut: false, duration: 10, permissionDenied: false })
        // apt-cache policy
        .mockResolvedValueOnce({ exitCode: 0, stdout: "fakepackage:\n  Installed: (none)\n  Candidate: 1.0.0\n", stderr: "", timedOut: false, duration: 10, permissionDenied: false })
        // apt-get changelog
        .mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "", timedOut: false, duration: 10, permissionDenied: false });

      const result = await handler({ action: "vuln_urgency", packageName: "fakepackage", dryRun: false });
      const output = JSON.parse(result.content[0].text);

      expect(output.installedVersion).toBe("not installed");
    });

    it("should handle vuln_urgency error", async () => {
      const { getConfig } = await import("../../src/core/config.js");
      const { detectDistro } = await import("../../src/core/distro.js");
      const handler = tools.get("patch")!.handler;

      vi.mocked(getConfig).mockReturnValue({ dryRun: false, networkTimeout: 10000 } as any);
      vi.mocked(detectDistro).mockRejectedValueOnce(new Error("distro detection failed"));

      const result = await handler({ action: "vuln_urgency", packageName: "openssl", dryRun: false });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Patch urgency check failed");
    });
  });
});
