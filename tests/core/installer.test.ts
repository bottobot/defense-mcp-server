import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock executor before importing installer
vi.mock("../../src/core/executor.js", () => ({
  executeCommand: vi.fn(),
}));

// Mock distro before importing installer
vi.mock("../../src/core/distro.js", () => ({
  detectDistro: vi.fn(),
  getInstallCommand: vi.fn(),
  getUpdateCommand: vi.fn(),
}));

// Mock config before importing installer
vi.mock("../../src/core/config.js", () => ({
  getConfig: vi.fn(),
}));

// Mock command-allowlist to control resolveCommand behavior (new impl uses this instead of `which`)
vi.mock("../../src/core/command-allowlist.js", () => ({
  resolveCommand: vi.fn(),
}));

// Mock node:fs to control existsSync fallback in checkTool
vi.mock("node:fs", () => ({
  existsSync: vi.fn(),
}));

import { executeCommand } from "../../src/core/executor.js";
import { detectDistro, getInstallCommand, getUpdateCommand } from "../../src/core/distro.js";
import { getConfig } from "../../src/core/config.js";
import { resolveCommand } from "../../src/core/command-allowlist.js";
import { existsSync } from "node:fs";
import {
  checkTool,
  checkAllTools,
  installTool,
  installMissing,
  DEFENSIVE_TOOLS,
  type ToolRequirement,
} from "../../src/core/installer.js";

const mockExecute = vi.mocked(executeCommand);
const mockDetectDistro = vi.mocked(detectDistro);
const mockGetInstallCommand = vi.mocked(getInstallCommand);
const mockGetUpdateCommand = vi.mocked(getUpdateCommand);
const mockGetConfig = vi.mocked(getConfig);
const mockResolveCommand = vi.mocked(resolveCommand);
const mockExistsSync = vi.mocked(existsSync);

/** Helper to build a full CommandResult with defaults. */
function cmdResult(overrides: {
  stdout?: string;
  stderr?: string;
  exitCode?: number;
  timedOut?: boolean;
  duration?: number;
  permissionDenied?: boolean;
}) {
  return {
    stdout: overrides.stdout ?? "",
    stderr: overrides.stderr ?? "",
    exitCode: overrides.exitCode ?? 0,
    timedOut: overrides.timedOut ?? false,
    duration: overrides.duration ?? 10,
    permissionDenied: overrides.permissionDenied ?? false,
  };
}

/** Helper to build a DistroInfo object. */
function makeDistro(family: string, pkgMgr: string) {
  return {
    id: family,
    name: family.charAt(0).toUpperCase() + family.slice(1),
    version: "12",
    osFamily: "linux" as const,
    specificDistro: family as "debian",
    family: family as "debian",
    packageManager: pkgMgr as "apt",
    initSystem: "systemd" as const,
    hasFirewalld: false,
    hasUfw: family === "debian",
    hasSelinux: false,
    hasApparmor: family === "debian",
  };
}

describe("installer", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.spyOn(console, "error").mockImplementation(() => {});
    // Default: binary not found — resolveCommand throws and existsSync returns false.
    // Individual tests override these for the "installed" scenario.
    mockResolveCommand.mockImplementation(() => {
      throw new Error("Command not in allowlist or not found on this system");
    });
    mockExistsSync.mockReturnValue(false);
  });

  // ── DEFENSIVE_TOOLS registry ────────────────────────────────────────────

  describe("DEFENSIVE_TOOLS", () => {
    it("should contain a non-empty array of tool definitions", () => {
      expect(DEFENSIVE_TOOLS).toBeDefined();
      expect(DEFENSIVE_TOOLS.length).toBeGreaterThan(0);
    });

    it("should have every entry with a valid binary field", () => {
      for (const tool of DEFENSIVE_TOOLS) {
        expect(tool.binary).toBeTruthy();
        expect(typeof tool.binary).toBe("string");
      }
    });

    it("should include required tools across core categories", () => {
      const requiredTools = DEFENSIVE_TOOLS.filter((t) => t.required);
      expect(requiredTools.length).toBeGreaterThan(0);
      const categories = new Set(requiredTools.map((t) => t.category));
      expect(categories.has("hardening")).toBe(true);
      expect(categories.has("firewall")).toBe(true);
      expect(categories.has("network")).toBe(true);
    });
  });

  // ── checkTool ───────────────────────────────────────────────────────────

  describe("checkTool", () => {
    it("should return installed=false when binary is not found", async () => {
      // resolveCommand throws (default) and existsSync returns false (default)
      // → binaryPath remains undefined → installed: false
      const result = await checkTool("nonexistent");
      expect(result.installed).toBe(false);
      expect(result.version).toBeUndefined();
      expect(result.path).toBeUndefined();
    });

    it("should return installed=true with version from --version", async () => {
      // resolveCommand returns the resolved path for "lynis"
      mockResolveCommand.mockReturnValueOnce("/usr/bin/lynis");
      // --version succeeds
      mockExecute.mockResolvedValueOnce(cmdResult({ stdout: "Lynis 3.0.8\nMore info\n" }));

      const result = await checkTool("lynis");
      expect(result.installed).toBe(true);
      expect(result.version).toBe("Lynis 3.0.8");
      expect(result.path).toBe("/usr/bin/lynis");
    });

    it("should fallback to -V when --version fails", async () => {
      // resolveCommand returns the resolved path for "iptables"
      mockResolveCommand.mockReturnValueOnce("/usr/sbin/iptables");
      // --version fails
      mockExecute.mockResolvedValueOnce(cmdResult({ exitCode: 1 }));
      // -V succeeds
      mockExecute.mockResolvedValueOnce(cmdResult({ stdout: "iptables v1.8.9\n" }));

      const result = await checkTool("iptables");
      expect(result.installed).toBe(true);
      expect(result.version).toBe("iptables v1.8.9");
    });

    it("should return installed=true without version if all version checks fail", async () => {
      // resolveCommand returns the resolved path for "tool"
      mockResolveCommand.mockReturnValueOnce("/usr/bin/tool");
      // --version fails
      mockExecute.mockResolvedValueOnce(cmdResult({ exitCode: 1 }));
      // -V also fails
      mockExecute.mockResolvedValueOnce(cmdResult({ exitCode: 1 }));

      const result = await checkTool("tool");
      expect(result.installed).toBe(true);
      expect(result.version).toBeUndefined();
      expect(result.path).toBe("/usr/bin/tool");
    });
  });

  // ── checkAllTools ───────────────────────────────────────────────────────

  describe("checkAllTools", () => {
    it("should filter by category when provided", async () => {
      const encryptionTools = DEFENSIVE_TOOLS.filter((t) => t.category === "encryption");
      // resolveCommand throws (default) and existsSync returns false (default)
      // → all encryption tools appear not installed → no executeCommand calls needed

      const results = await checkAllTools("encryption");
      expect(results.length).toBe(encryptionTools.length);
      for (const r of results) {
        expect(r.tool.category).toBe("encryption");
      }
    });
  });

  // ── installTool ─────────────────────────────────────────────────────────

  describe("installTool", () => {
    const testTool: ToolRequirement = {
      name: "TestTool",
      binary: "testtool",
      packages: { debian: "testtool-pkg", fallback: "testtool" },
      category: "hardening",
      required: true,
    };

    it("should return failure when package manager is unknown", async () => {
      mockDetectDistro.mockResolvedValueOnce(makeDistro("unknown", "unknown"));

      const result = await installTool(testTool);
      expect(result.success).toBe(false);
      expect(result.message).toContain("unknown package manager");
    });

    it("should successfully install a package on debian", async () => {
      mockDetectDistro.mockResolvedValueOnce(makeDistro("debian", "apt"));
      mockGetUpdateCommand.mockReturnValueOnce(["apt-get", "update"]);
      mockGetInstallCommand.mockReturnValueOnce(["apt-get", "install", "-y", "testtool-pkg"]);
      mockExecute.mockResolvedValueOnce(cmdResult({})); // update
      mockExecute.mockResolvedValueOnce(cmdResult({ stdout: "Installed." })); // install

      const result = await installTool(testTool);
      expect(result.success).toBe(true);
      expect(result.message).toContain("Successfully installed");
    });

    it("should return failure when installation command fails", async () => {
      mockDetectDistro.mockResolvedValueOnce(makeDistro("debian", "apt"));
      mockGetUpdateCommand.mockReturnValueOnce(["apt-get", "update"]);
      mockGetInstallCommand.mockReturnValueOnce(["apt-get", "install", "-y", "testtool-pkg"]);
      mockExecute.mockResolvedValueOnce(cmdResult({})); // update ok
      mockExecute.mockResolvedValueOnce(cmdResult({ exitCode: 100, stderr: "E: Package not found" }));

      const result = await installTool(testTool);
      expect(result.success).toBe(false);
      expect(result.message).toContain("Failed to install");
      expect(result.message).toContain("E: Package not found");
    });

    it("should use fallback package when family-specific is missing", async () => {
      const toolNoDebian: ToolRequirement = {
        name: "FallbackTool",
        binary: "fallbacktool",
        packages: { fallback: "fallback-pkg" },
        category: "hardening",
        required: false,
      };

      mockDetectDistro.mockResolvedValueOnce(makeDistro("debian", "apt"));
      mockGetUpdateCommand.mockReturnValueOnce(["apt-get", "update"]);
      mockGetInstallCommand.mockReturnValueOnce(["apt-get", "install", "-y", "fallback-pkg"]);
      mockExecute.mockResolvedValueOnce(cmdResult({}));
      mockExecute.mockResolvedValueOnce(cmdResult({}));

      const result = await installTool(toolNoDebian);
      expect(result.success).toBe(true);
      expect(mockGetInstallCommand).toHaveBeenCalledWith("apt", "fallback-pkg");
    });

    it("should return failure when no package name is configured", async () => {
      const toolNoPkg: ToolRequirement = {
        name: "NoPkg",
        binary: "nopkg",
        packages: {},
        category: "hardening",
        required: false,
      };

      mockDetectDistro.mockResolvedValueOnce(makeDistro("debian", "apt"));

      const result = await installTool(toolNoPkg);
      expect(result.success).toBe(false);
      expect(result.message).toContain("No package name configured");
    });
  });

  // ── installMissing ──────────────────────────────────────────────────────

  describe("installMissing", () => {
    it("should return empty array when all tools are installed", async () => {
      mockGetConfig.mockReturnValue({ dryRun: false, autoInstall: false } as ReturnType<typeof getConfig>);

      // Mock resolveCommand to return a path for every tool, and --version to succeed.
      // This makes checkTool() report installed=true for all DEFENSIVE_TOOLS.
      for (const t of DEFENSIVE_TOOLS) {
        mockResolveCommand.mockReturnValueOnce(`/usr/bin/${t.binary}`);
        mockExecute.mockResolvedValueOnce(cmdResult({ stdout: "1.0\n" }));
      }

      const results = await installMissing();
      expect(results).toEqual([]);
    });

    it("should report dry-run results when dryRun is true", async () => {
      mockGetConfig.mockReturnValue({ dryRun: true, autoInstall: false } as ReturnType<typeof getConfig>);

      // resolveCommand throws (default) and existsSync returns false (default)
      // → all container tools appear not installed → installMissing returns [DRY RUN] entries
      const containerTools = DEFENSIVE_TOOLS.filter((t) => t.category === "container");

      const results = await installMissing("container");
      expect(results.length).toBe(containerTools.length);
      for (const r of results) {
        expect(r.message).toContain("[DRY RUN]");
        expect(r.success).toBe(false);
      }
    });
  });
});
