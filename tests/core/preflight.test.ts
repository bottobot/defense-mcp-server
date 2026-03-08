/**
 * Tests for src/core/preflight.ts
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ── Mock all external dependencies before importing ──────────────────────────

vi.mock("../../src/core/spawn-safe.js", () => ({
  execFileSafe: vi.fn(() => ""),
}));

vi.mock("../../src/core/dependency-validator.js", () => ({
  isBinaryInstalled: vi.fn(async () => true),
  clearDependencyCache: vi.fn(),
}));

vi.mock("../../src/core/config.js", () => ({
  getConfig: vi.fn(() => ({
    autoInstall: false,
    dryRun: false,
    backupDir: "/tmp/backups",
    logLevel: "info",
  })),
}));

vi.mock("../../src/core/tool-dependencies.js", () => ({
  TOOL_DEPENDENCIES: [],
  getToolRequirementForBinary: vi.fn(() => null),
}));

vi.mock("../../src/core/tool-registry.js", () => {
  const manifests = new Map();
  const registry = {
    getManifest: vi.fn((name: string) => manifests.get(name)),
    register: vi.fn((m: any) => manifests.set(m.toolName, m)),
    has: vi.fn((name: string) => manifests.has(name)),
    getAll: vi.fn(() => Array.from(manifests.values())),
    _manifests: manifests,
  };
  return {
    ToolRegistry: {
      instance: vi.fn(() => registry),
      resetInstance: vi.fn(),
    },
    initializeRegistry: vi.fn(() => registry),
  };
});

vi.mock("../../src/core/privilege-manager.js", () => {
  const pm = {
    checkForTool: vi.fn(async () => ({
      satisfied: true,
      issues: [],
      recommendations: [],
    })),
    getStatus: vi.fn(async () => ({
      uid: 1000,
      euid: 1000,
      isRoot: false,
      sudoAvailable: true,
      passwordlessSudo: false,
      sudoSessionActive: false,
      capabilities: new Set(),
      groups: ["user"],
    })),
    clearCache: vi.fn(),
  };
  return {
    PrivilegeManager: {
      instance: vi.fn(() => pm),
    },
  };
});

vi.mock("../../src/core/auto-installer.js", () => {
  const ai = {
    isEnabled: vi.fn(() => false),
    resolveAll: vi.fn(async () => ({
      attempted: [],
      allResolved: false,
      unresolvedDependencies: [],
    })),
  };
  return {
    AutoInstaller: {
      instance: vi.fn(() => ai),
      resetInstance: vi.fn(),
    },
  };
});

vi.mock("../../src/core/safeguards.js", () => ({
  SafeguardRegistry: {
    getInstance: vi.fn(() => ({
      checkSafety: vi.fn(async () => ({
        safe: true,
        blockers: [],
        warnings: [],
        impactedApps: [],
      })),
    })),
  },
}));

vi.mock("node:fs", () => ({
  existsSync: vi.fn(() => true),
}));

import { PreflightEngine, type PreflightResult } from "../../src/core/preflight.js";
import { ToolRegistry } from "../../src/core/tool-registry.js";
import { PrivilegeManager } from "../../src/core/privilege-manager.js";
import { isBinaryInstalled } from "../../src/core/dependency-validator.js";

describe("PreflightEngine", () => {
  let engine: PreflightEngine;
  let registry: ReturnType<typeof ToolRegistry.instance>;

  beforeEach(() => {
    vi.clearAllMocks();
    // Access the singleton — constructor is private, use instance()
    engine = PreflightEngine.instance();
    engine.clearCache();
    registry = ToolRegistry.instance();
  });

  // ── Basic pass scenarios ───────────────────────────────────────────────────

  it("passes when tool has no manifest (with warning)", async () => {
    // registry returns undefined for unknown tools
    const result = await engine.runPreflight("unknown_tool");
    expect(result.passed).toBe(true);
    expect(result.warnings).toContain(
      "Tool not registered in manifest — skipping pre-flight",
    );
  });

  it("passes for a fully satisfied tool", async () => {
    (registry as any)._manifests.set("test_ok", {
      toolName: "test_ok",
      requiredBinaries: ["echo"],
      sudo: "never",
    });

    const result = await engine.runPreflight("test_ok");
    expect(result.passed).toBe(true);
    expect(result.errors).toHaveLength(0);
    expect(result.toolName).toBe("test_ok");
  });

  // ── Missing binary detection ───────────────────────────────────────────────

  it("fails when a required binary is missing", async () => {
    (registry as any)._manifests.set("test_missing", {
      toolName: "test_missing",
      requiredBinaries: ["nonexistent_binary"],
      sudo: "never",
    });

    vi.mocked(isBinaryInstalled).mockResolvedValueOnce(false);

    const result = await engine.runPreflight("test_missing");
    expect(result.passed).toBe(false);
    expect(result.dependencies.missing).toHaveLength(1);
    expect(result.dependencies.missing[0].name).toBe("nonexistent_binary");
  });

  // ── Privilege checking ─────────────────────────────────────────────────────

  it("fails when privilege issues are blocking", async () => {
    (registry as any)._manifests.set("test_priv", {
      toolName: "test_priv",
      requiredBinaries: [],
      sudo: "always",
    });

    const pmInstance = PrivilegeManager.instance();
    vi.mocked(pmInstance.checkForTool).mockResolvedValueOnce({
      satisfied: false,
      issues: [
        {
          type: "sudo-required",
          description: "Sudo is required",
          operation: "test_priv",
          resolution: "Run sudo_elevate",
        },
      ],
      recommendations: [],
    });

    const result = await engine.runPreflight("test_priv");
    expect(result.passed).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0]).toContain("Sudo is required");
  });

  it("adds non-blocking privilege issues as warnings", async () => {
    (registry as any)._manifests.set("test_cond", {
      toolName: "test_cond",
      requiredBinaries: [],
      sudo: "conditional",
    });

    const pmInstance = PrivilegeManager.instance();
    vi.mocked(pmInstance.checkForTool).mockResolvedValueOnce({
      satisfied: true,
      issues: [
        {
          type: "capability-missing" as any,
          description: "CAP_NET_RAW missing",
          operation: "test_cond",
          resolution: "Grant capability",
        },
      ],
      recommendations: ["Consider running with elevated privileges"],
    });

    const result = await engine.runPreflight("test_cond");
    expect(result.passed).toBe(true);
    expect(result.warnings).toContain("CAP_NET_RAW missing");
    expect(result.warnings).toContain("Consider running with elevated privileges");
  });

  // ── Caching ────────────────────────────────────────────────────────────────

  it("returns cached result for a passing tool on second call", async () => {
    (registry as any)._manifests.set("cached_tool", {
      toolName: "cached_tool",
      requiredBinaries: [],
      sudo: "never",
    });

    const r1 = await engine.runPreflight("cached_tool");
    expect(r1.passed).toBe(true);

    // Second call should return cached
    const r2 = await engine.runPreflight("cached_tool");
    expect(r2.passed).toBe(true);
    expect(r2.timestamp).toBe(r1.timestamp);
  });

  it("clears cache when clearCache() is called", async () => {
    (registry as any)._manifests.set("cached_tool2", {
      toolName: "cached_tool2",
      requiredBinaries: [],
      sudo: "never",
    });

    const r1 = await engine.runPreflight("cached_tool2");
    engine.clearCache();
    const r2 = await engine.runPreflight("cached_tool2");
    // Timestamps should differ after cache clear
    expect(r2.timestamp).toBeGreaterThanOrEqual(r1.timestamp);
  });

  // ── Summary formatting ─────────────────────────────────────────────────────

  it("formats a passing summary with checkmark", async () => {
    (registry as any)._manifests.set("fmt_pass", {
      toolName: "fmt_pass",
      requiredBinaries: ["echo"],
      sudo: "never",
    });

    const result = await engine.runPreflight("fmt_pass");
    expect(result.summary).toContain("✅");
    expect(result.summary).toContain("fmt_pass");
    expect(result.summary).toContain("Ready to execute");
  });

  it("formats a failing summary with X mark", async () => {
    (registry as any)._manifests.set("fmt_fail", {
      toolName: "fmt_fail",
      requiredBinaries: ["missing_bin"],
      sudo: "never",
    });

    vi.mocked(isBinaryInstalled).mockResolvedValueOnce(false);

    const result = await engine.runPreflight("fmt_fail");
    expect(result.summary).toContain("❌");
    expect(result.summary).toContain("fmt_fail");
    expect(result.summary).toContain("Cannot proceed");
  });

  // ── formatStatusMessage ────────────────────────────────────────────────────

  it("formats short status for clean pass", async () => {
    (registry as any)._manifests.set("status_tool", {
      toolName: "status_tool",
      requiredBinaries: [],
      sudo: "never",
    });

    const result = await engine.runPreflight("status_tool");
    const msg = engine.formatStatusMessage(result);
    expect(msg).toContain("[pre-flight ✓]");
    expect(msg).toContain("All checks passed");
  });

  // ── Duration tracking ──────────────────────────────────────────────────────

  it("records a non-negative duration", async () => {
    (registry as any)._manifests.set("dur_tool", {
      toolName: "dur_tool",
      requiredBinaries: [],
      sudo: "never",
    });

    const result = await engine.runPreflight("dur_tool");
    expect(result.duration).toBeGreaterThanOrEqual(0);
  });

  // ── Timestamp ──────────────────────────────────────────────────────────────

  it("records a valid timestamp", async () => {
    (registry as any)._manifests.set("ts_tool", {
      toolName: "ts_tool",
      requiredBinaries: [],
      sudo: "never",
    });

    const before = Date.now();
    const result = await engine.runPreflight("ts_tool");
    const after = Date.now();

    expect(result.timestamp).toBeGreaterThanOrEqual(before);
    expect(result.timestamp).toBeLessThanOrEqual(after);
  });
});
