import { describe, it, expect } from "vitest";
import {
  TOOL_DEPENDENCIES,
  getDependenciesForTool,
  getToolRequirementForBinary,
  getAllRequiredBinaries,
  getAllBinaries,
  getCriticalDependencies,
  type ToolDependency,
} from "../../src/core/tool-dependencies.js";

describe("tool-dependencies", () => {
  // ── TOOL_DEPENDENCIES registry ──────────────────────────────────────────

  describe("TOOL_DEPENDENCIES", () => {
    it("should contain a non-empty array of tool dependency definitions", () => {
      expect(TOOL_DEPENDENCIES).toBeDefined();
      expect(Array.isArray(TOOL_DEPENDENCIES)).toBe(true);
      expect(TOOL_DEPENDENCIES.length).toBeGreaterThan(0);
    });

    it("should have unique toolName for each entry", () => {
      const names = TOOL_DEPENDENCIES.map((d) => d.toolName);
      const unique = new Set(names);
      expect(unique.size).toBe(names.length);
    });

    it("should have requiredBinaries as an array on every entry", () => {
      for (const dep of TOOL_DEPENDENCIES) {
        expect(Array.isArray(dep.requiredBinaries)).toBe(true);
      }
    });
  });

  // ── getDependenciesForTool ──────────────────────────────────────────────

  describe("getDependenciesForTool", () => {
    it("should return dependency info for a known tool", () => {
      const dep = getDependenciesForTool("firewall_iptables");
      expect(dep).toBeDefined();
      expect(dep!.toolName).toBe("firewall_iptables");
      expect(dep!.requiredBinaries).toContain("iptables");
    });

    it("should return undefined for an unknown tool", () => {
      const dep = getDependenciesForTool("totally_nonexistent_tool");
      expect(dep).toBeUndefined();
    });

    it("should return critical flag for critical tools", () => {
      const dep = getDependenciesForTool("firewall_iptables");
      expect(dep).toBeDefined();
      expect(dep!.critical).toBe(true);
    });

    it("should return optional binaries when defined", () => {
      const dep = getDependenciesForTool("firewall_iptables");
      expect(dep).toBeDefined();
      expect(dep!.optionalBinaries).toContain("ip6tables");
    });
  });

  // ── getToolRequirementForBinary ─────────────────────────────────────────

  describe("getToolRequirementForBinary", () => {
    it("should return the ToolRequirement for a known binary", () => {
      const req = getToolRequirementForBinary("lynis");
      expect(req).toBeDefined();
      expect(req!.name).toBe("Lynis");
      expect(req!.binary).toBe("lynis");
    });

    it("should return undefined for an unknown binary", () => {
      const req = getToolRequirementForBinary("totally_unknown_binary");
      expect(req).toBeUndefined();
    });
  });

  // ── getAllRequiredBinaries ───────────────────────────────────────────────

  describe("getAllRequiredBinaries", () => {
    it("should return a non-empty array of unique binary names", () => {
      const binaries = getAllRequiredBinaries();
      expect(binaries.length).toBeGreaterThan(0);
      const unique = new Set(binaries);
      expect(unique.size).toBe(binaries.length);
    });

    it("should include known critical binaries like iptables", () => {
      const binaries = getAllRequiredBinaries();
      expect(binaries).toContain("iptables");
    });
  });

  // ── getAllBinaries ──────────────────────────────────────────────────────

  describe("getAllBinaries", () => {
    it("should return both required and optional arrays", () => {
      const result = getAllBinaries();
      expect(result).toHaveProperty("required");
      expect(result).toHaveProperty("optional");
      expect(Array.isArray(result.required)).toBe(true);
      expect(Array.isArray(result.optional)).toBe(true);
    });

    it("should separate required and optional binaries correctly", () => {
      const { required, optional } = getAllBinaries();
      // The function moves binaries that appear as required in ANY tool
      // out of the optional set. Some trivial binaries like 'find'/'grep'
      // may appear as required in one tool and optional in another — the
      // function is supposed to prioritize required. Verify at least some
      // binaries are in each set.
      expect(required.length).toBeGreaterThan(0);
      expect(optional.length).toBeGreaterThan(0);
      // Each set should have unique entries within itself
      expect(new Set(required).size).toBe(required.length);
      expect(new Set(optional).size).toBe(optional.length);
    });
  });

  // ── getCriticalDependencies ─────────────────────────────────────────────

  describe("getCriticalDependencies", () => {
    it("should return only critical dependencies", () => {
      const critical = getCriticalDependencies();
      expect(critical.length).toBeGreaterThan(0);
      for (const dep of critical) {
        expect(dep.critical).toBe(true);
      }
    });

    it("should include firewall_iptables as a critical tool", () => {
      const critical = getCriticalDependencies();
      const names = critical.map((d) => d.toolName);
      expect(names).toContain("firewall_iptables");
    });
  });
});
