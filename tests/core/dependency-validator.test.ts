import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock executor
vi.mock("../../src/core/executor.js", () => ({
  executeCommand: vi.fn(),
}));

// Mock config
vi.mock("../../src/core/config.js", () => ({
  getConfig: vi.fn(),
}));

// Mock installer
vi.mock("../../src/core/installer.js", () => ({
  checkTool: vi.fn(),
  installTool: vi.fn(),
  DEFENSIVE_TOOLS: [
    {
      name: "Lynis",
      binary: "lynis",
      packages: { debian: "lynis", fallback: "lynis" },
      category: "hardening",
      required: true,
    },
  ],
}));

// Mock distro (needed by validateAllDependencies dynamic import)
vi.mock("../../src/core/distro.js", () => ({
  detectDistro: vi.fn().mockResolvedValue({
    id: "debian",
    name: "Debian",
    version: "12",
    osFamily: "linux",
    specificDistro: "debian",
    family: "debian",
    packageManager: "apt",
    initSystem: "systemd",
    hasFirewalld: false,
    hasUfw: true,
    hasSelinux: false,
    hasApparmor: true,
  }),
  getPackageManager: vi.fn().mockReturnValue({
    updateCmd: () => ["apt-get", "update"],
    installCmd: (pkg: string) => ["apt-get", "install", "-y", pkg],
    removeCmd: (pkg: string) => ["apt-get", "remove", "-y", pkg],
    searchCmd: (term: string) => ["apt-cache", "search", term],
    listInstalledCmd: () => ["dpkg", "--list"],
  }),
}));

import { executeCommand } from "../../src/core/executor.js";
import { getConfig } from "../../src/core/config.js";
import { checkTool, installTool } from "../../src/core/installer.js";
import {
  clearDependencyCache,
  ensureDependencies,
  isBinaryInstalled,
  formatValidationReport,
  type ValidationReport,
  type EnsureResult,
} from "../../src/core/dependency-validator.js";

const mockCheckTool = vi.mocked(checkTool);
const mockInstallTool = vi.mocked(installTool);
const mockGetConfig = vi.mocked(getConfig);
const mockExecute = vi.mocked(executeCommand);

/** Helper to build a full CommandResult. */
function cmdResult(overrides: Partial<{
  stdout: string;
  stderr: string;
  exitCode: number;
  timedOut: boolean;
  duration: number;
  permissionDenied: boolean;
}> = {}) {
  return {
    stdout: overrides.stdout ?? "",
    stderr: overrides.stderr ?? "",
    exitCode: overrides.exitCode ?? 0,
    timedOut: overrides.timedOut ?? false,
    duration: overrides.duration ?? 10,
    permissionDenied: overrides.permissionDenied ?? false,
  };
}

describe("dependency-validator", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    clearDependencyCache();
    vi.spyOn(console, "error").mockImplementation(() => {});
    mockGetConfig.mockReturnValue({
      autoInstall: false,
      dryRun: false,
    } as ReturnType<typeof getConfig>);
  });

  // ── clearDependencyCache ────────────────────────────────────────────────

  describe("clearDependencyCache", () => {
    it("should clear cached binary status", async () => {
      // First call: binary not found
      mockCheckTool.mockResolvedValueOnce({ installed: false });
      const first = await isBinaryInstalled("lynis");
      expect(first).toBe(false);

      // Clear cache
      clearDependencyCache();

      // Second call: binary found (cache invalidated, so new check)
      mockCheckTool.mockResolvedValueOnce({ installed: true, path: "/usr/bin/lynis" });
      const second = await isBinaryInstalled("lynis");
      expect(second).toBe(true);
    });
  });

  // ── isBinaryInstalled ──────────────────────────────────────────────────

  describe("isBinaryInstalled", () => {
    it("should return true when binary is available", async () => {
      mockCheckTool.mockResolvedValueOnce({ installed: true, path: "/usr/bin/lynis" });
      const result = await isBinaryInstalled("lynis");
      expect(result).toBe(true);
    });

    it("should return false when binary is not available", async () => {
      mockCheckTool.mockResolvedValueOnce({ installed: false });
      const result = await isBinaryInstalled("nonexistent");
      expect(result).toBe(false);
    });

    it("should use cache on subsequent calls within TTL", async () => {
      mockCheckTool.mockResolvedValueOnce({ installed: true, path: "/usr/bin/lynis" });
      await isBinaryInstalled("lynis");

      // Second call should use cache, not call checkTool again
      const result = await isBinaryInstalled("lynis");
      expect(result).toBe(true);
      expect(mockCheckTool).toHaveBeenCalledTimes(1);
    });

    it("should return true for trivial binaries without checking", async () => {
      // 'cat', 'grep', etc. are trivial binaries always present
      const result = await isBinaryInstalled("cat");
      expect(result).toBe(true);
      expect(mockCheckTool).not.toHaveBeenCalled();
    });
  });

  // ── ensureDependencies ─────────────────────────────────────────────────

  describe("ensureDependencies", () => {
    it("should return satisfied for unknown tool names", async () => {
      const result = await ensureDependencies("totally_unknown_tool");
      expect(result.satisfied).toBe(true);
      expect(result.missingRequired).toEqual([]);
      expect(result.missingOptional).toEqual([]);
    });

    it("should return satisfied when all required binaries are available", async () => {
      // firewall_iptables requires "iptables", optional "ip6tables"
      // Provide mock results for both required and optional binary checks
      mockCheckTool.mockResolvedValue({ installed: true, path: "/usr/sbin/iptables" });

      const result = await ensureDependencies("firewall_iptables");
      expect(result.satisfied).toBe(true);
      expect(result.missingRequired).toEqual([]);
    });

    it("should report missing required binaries", async () => {
      // firewall_iptables requires "iptables", optional "ip6tables"
      // All calls return not installed
      mockCheckTool.mockResolvedValue({ installed: false });

      const result = await ensureDependencies("firewall_iptables");
      expect(result.satisfied).toBe(false);
      expect(result.missingRequired).toContain("iptables");
    });

    it("should auto-install missing binaries when autoInstall is enabled", async () => {
      mockGetConfig.mockReturnValue({
        autoInstall: true,
        dryRun: false,
      } as ReturnType<typeof getConfig>);

      // All checkTool calls: not installed initially
      mockCheckTool.mockResolvedValueOnce({ installed: false }); // iptables required check
      // installTool succeeds
      mockInstallTool.mockResolvedValueOnce({
        tool: { name: "iptables", binary: "iptables", packages: {}, category: "firewall", required: true },
        success: true,
        message: "Installed",
      });
      // Re-check after install: now installed
      mockCheckTool.mockResolvedValueOnce({ installed: true, path: "/usr/sbin/iptables" });
      // ip6tables optional check: not installed (but doesn't fail the overall check)
      mockCheckTool.mockResolvedValueOnce({ installed: false });
      // auto-install attempt for ip6tables
      mockInstallTool.mockResolvedValueOnce({
        tool: { name: "ip6tables", binary: "ip6tables", packages: {}, category: "firewall", required: false },
        success: false,
        message: "Not found",
      });

      const result = await ensureDependencies("firewall_iptables");
      expect(result.satisfied).toBe(true);
      expect(result.autoInstalled).toContain("iptables");
    });

    it("should report install errors when auto-install fails", async () => {
      mockGetConfig.mockReturnValue({
        autoInstall: true,
        dryRun: false,
      } as ReturnType<typeof getConfig>);

      // iptables required: not installed
      mockCheckTool.mockResolvedValueOnce({ installed: false });
      mockInstallTool.mockResolvedValueOnce({
        tool: { name: "iptables", binary: "iptables", packages: {}, category: "firewall", required: true },
        success: false,
        message: "Package not found",
      });
      // ip6tables optional: not installed
      mockCheckTool.mockResolvedValueOnce({ installed: false });
      mockInstallTool.mockResolvedValueOnce({
        tool: { name: "ip6tables", binary: "ip6tables", packages: {}, category: "firewall", required: false },
        success: false,
        message: "Not found",
      });

      const result = await ensureDependencies("firewall_iptables");
      expect(result.satisfied).toBe(false);
      expect(result.missingRequired).toContain("iptables");
      expect(result.installErrors.length).toBeGreaterThan(0);
    });
  });

  // ── formatValidationReport ─────────────────────────────────────────────

  describe("formatValidationReport", () => {
    it("should produce a formatted string with summary info", () => {
      const report: ValidationReport = {
        totalChecked: 10,
        available: ["lynis", "aide"],
        missing: ["snort"],
        installed: [],
        installFailed: [],
        criticalMissing: [],
        durationMs: 150,
        autoInstallEnabled: false,
      };

      const output = formatValidationReport(report);
      expect(output).toContain("10");
      expect(output).toContain("snort");
      expect(output).toContain("DISABLED");
      expect(output).toContain("150ms");
    });

    it("should highlight critical missing tools", () => {
      const report: ValidationReport = {
        totalChecked: 5,
        available: [],
        missing: ["lynis"],
        installed: [],
        installFailed: [],
        criticalMissing: [
          { toolName: "compliance_lynis_audit", missingBinaries: ["lynis"] },
        ],
        durationMs: 100,
        autoInstallEnabled: false,
      };

      const output = formatValidationReport(report);
      expect(output).toContain("CRITICAL");
      expect(output).toContain("compliance_lynis_audit");
    });

    it("should show auto-installed binaries when present", () => {
      const report: ValidationReport = {
        totalChecked: 3,
        available: ["lynis"],
        missing: [],
        installed: ["lynis"],
        installFailed: [],
        criticalMissing: [],
        durationMs: 500,
        autoInstallEnabled: true,
      };

      const output = formatValidationReport(report);
      expect(output).toContain("lynis");
      expect(output).toContain("ENABLED");
    });
  });
});
