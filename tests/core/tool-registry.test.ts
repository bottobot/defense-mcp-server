/**
 * Tests for src/core/tool-registry.ts
 */
import { describe, it, expect, beforeEach } from "vitest";
import {
  ToolRegistry,
  type ToolManifest,
  migrateFromLegacy,
  initializeRegistry,
  resetRegistryInitialization,
  DEFAULT_MANIFESTS,
} from "../../src/core/tool-registry.js";

// ── Helper to create a test manifest ─────────────────────────────────────────

function makeManifest(overrides: Partial<ToolManifest> = {}): ToolManifest {
  return {
    toolName: overrides.toolName ?? "test_tool",
    requiredBinaries: overrides.requiredBinaries ?? ["echo"],
    sudo: overrides.sudo ?? "never",
    ...overrides,
  };
}

describe("ToolRegistry", () => {
  beforeEach(() => {
    // Reset singleton between tests
    ToolRegistry.resetInstance();
    resetRegistryInitialization();
  });

  // ── Singleton ──────────────────────────────────────────────────────────────

  it("returns the same singleton instance on repeated calls", () => {
    const a = ToolRegistry.instance();
    const b = ToolRegistry.instance();
    expect(a).toBe(b);
  });

  it("creates a new instance after resetInstance()", () => {
    const a = ToolRegistry.instance();
    ToolRegistry.resetInstance();
    const b = ToolRegistry.instance();
    expect(a).not.toBe(b);
  });

  // ── register / getManifest / has ───────────────────────────────────────────

  it("registers and retrieves a tool manifest", () => {
    const reg = ToolRegistry.instance();
    const manifest = makeManifest({ toolName: "firewall_iptables" });
    reg.register(manifest);

    expect(reg.has("firewall_iptables")).toBe(true);
    expect(reg.getManifest("firewall_iptables")).toEqual(manifest);
  });

  it("returns undefined for an unregistered tool", () => {
    const reg = ToolRegistry.instance();
    expect(reg.getManifest("nonexistent")).toBeUndefined();
    expect(reg.has("nonexistent")).toBe(false);
  });

  it("overwrites a manifest on re-registration", () => {
    const reg = ToolRegistry.instance();
    reg.register(makeManifest({ toolName: "t1", sudo: "never" }));
    reg.register(makeManifest({ toolName: "t1", sudo: "always" }));

    expect(reg.getManifest("t1")?.sudo).toBe("always");
  });

  // ── registerAll ────────────────────────────────────────────────────────────

  it("bulk registers an array of manifests", () => {
    const reg = ToolRegistry.instance();
    const manifests = [
      makeManifest({ toolName: "a" }),
      makeManifest({ toolName: "b" }),
      makeManifest({ toolName: "c" }),
    ];
    reg.registerAll(manifests);

    expect(reg.has("a")).toBe(true);
    expect(reg.has("b")).toBe(true);
    expect(reg.has("c")).toBe(true);
  });

  // ── getToolsRequiring ──────────────────────────────────────────────────────

  it("finds tools that require a specific binary", () => {
    const reg = ToolRegistry.instance();
    reg.register(makeManifest({ toolName: "t1", requiredBinaries: ["iptables", "ip6tables"] }));
    reg.register(makeManifest({ toolName: "t2", requiredBinaries: ["iptables"] }));
    reg.register(makeManifest({ toolName: "t3", requiredBinaries: ["nft"] }));

    const tools = reg.getToolsRequiring("iptables");
    expect(tools).toContain("t1");
    expect(tools).toContain("t2");
    expect(tools).not.toContain("t3");
  });

  it("returns empty array when no tools require the binary", () => {
    const reg = ToolRegistry.instance();
    reg.register(makeManifest({ toolName: "t1", requiredBinaries: ["nft"] }));
    expect(reg.getToolsRequiring("nonexistent")).toEqual([]);
  });

  // ── getToolsByCategory ─────────────────────────────────────────────────────

  it("returns tools filtered by category", () => {
    const reg = ToolRegistry.instance();
    reg.register(makeManifest({ toolName: "fw1", category: "firewall" }));
    reg.register(makeManifest({ toolName: "fw2", category: "firewall" }));
    reg.register(makeManifest({ toolName: "log1", category: "logging" }));

    const fwTools = reg.getToolsByCategory("firewall");
    expect(fwTools).toHaveLength(2);
    expect(fwTools.map((t) => t.toolName)).toEqual(["fw1", "fw2"]);
  });

  // ── getAllRequiredBinaries ──────────────────────────────────────────────────

  it("collects all unique required binaries across tools", () => {
    const reg = ToolRegistry.instance();
    reg.register(makeManifest({ toolName: "t1", requiredBinaries: ["a", "b"] }));
    reg.register(makeManifest({ toolName: "t2", requiredBinaries: ["b", "c"] }));

    const bins = reg.getAllRequiredBinaries();
    expect(bins).toEqual(new Set(["a", "b", "c"]));
  });

  // ── getToolsNeedingSudo ────────────────────────────────────────────────────

  it("returns tools with sudo 'always' or 'conditional'", () => {
    const reg = ToolRegistry.instance();
    reg.register(makeManifest({ toolName: "s1", sudo: "always" }));
    reg.register(makeManifest({ toolName: "s2", sudo: "conditional" }));
    reg.register(makeManifest({ toolName: "s3", sudo: "never" }));

    const sudoTools = reg.getToolsNeedingSudo();
    const names = sudoTools.map((t) => t.toolName);
    expect(names).toContain("s1");
    expect(names).toContain("s2");
    expect(names).not.toContain("s3");
  });

  // ── getAll ─────────────────────────────────────────────────────────────────

  it("returns all registered manifests", () => {
    const reg = ToolRegistry.instance();
    reg.register(makeManifest({ toolName: "a" }));
    reg.register(makeManifest({ toolName: "b" }));

    const all = reg.getAll();
    expect(all).toHaveLength(2);
  });

  // ── migrateFromLegacy ──────────────────────────────────────────────────────

  it("migrates legacy tool dependencies into the registry", () => {
    const reg = ToolRegistry.instance();
    migrateFromLegacy(reg);

    // The legacy data should populate the registry with at least some tools
    const all = reg.getAll();
    expect(all.length).toBeGreaterThan(0);
    // All migrated entries should have sudo: 'never' as default
    for (const m of all) {
      expect(m.sudo).toBe("never");
    }
  });

  // ── initializeRegistry ─────────────────────────────────────────────────────

  it("initializes the registry with legacy + overlay data", () => {
    const reg = initializeRegistry();
    expect(reg).toBe(ToolRegistry.instance());

    // Should have entries from DEFAULT_MANIFESTS overlayed
    const fw = reg.getManifest("firewall_iptables");
    if (fw) {
      expect(fw.sudo).toBe("conditional");
    }
  });

  it("is idempotent — second call returns immediately", () => {
    const reg1 = initializeRegistry();
    const reg2 = initializeRegistry();
    expect(reg1).toBe(reg2);
  });

  // ── DEFAULT_MANIFESTS ──────────────────────────────────────────────────────

  it("DEFAULT_MANIFESTS contains entries with inferred categories", () => {
    expect(DEFAULT_MANIFESTS.length).toBeGreaterThan(0);
    for (const m of DEFAULT_MANIFESTS) {
      expect(m.toolName).toBeTruthy();
      expect(["never", "always", "conditional"]).toContain(m.sudo);
      // category should have been inferred
      expect(m.category).toBeTruthy();
    }
  });

  it("DEFAULT_MANIFESTS infers correct categories from tool name prefixes", () => {
    const find = (name: string) =>
      DEFAULT_MANIFESTS.find((m) => m.toolName === name);

    expect(find("firewall_iptables")?.category).toBe("firewall");
    expect(find("harden_sysctl")?.category).toBe("hardening");
    expect(find("log_auditd")?.category).toBe("logging");
    expect(find("malware_clamav")?.category).toBe("malware");
    expect(find("container_docker")?.category).toBe("container");
    expect(find("secrets_scan")?.category).toBe("secrets");
  });
});
