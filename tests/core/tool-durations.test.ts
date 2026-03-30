/**
 * Tests for tool duration estimation database.
 */

import { describe, it, expect } from "vitest";
import {
  getDurationEstimate,
  getRecommendedTimeout,
  formatDurationEstimate,
  formatElapsed,
  isLongRunning,
  getProgressCapableActions,
  getComplexityMultiplier,
  DURATION_DATABASE,
} from "../../src/core/tool-durations.js";

describe("tool-durations", () => {
  describe("getDurationEstimate", () => {
    it("returns estimate for known tool action", () => {
      const est = getDurationEstimate("malware", "clamav_scan");
      expect(est).toBeDefined();
      expect(est!.description).toContain("ClamAV");
      expect(est!.complexity).toBe("high");
      expect(est!.recommendedTimeoutMs).toBeGreaterThan(60_000);
    });

    it("returns estimate for rootkit scanner", () => {
      const est = getDurationEstimate("integrity", "rootkit_rkhunter");
      expect(est).toBeDefined();
      expect(est!.complexity).toBe("critical");
      expect(est!.recommendedTimeoutMs).toBeGreaterThanOrEqual(900_000);
    });

    it("returns undefined for unknown tool", () => {
      const est = getDurationEstimate("nonexistent", "fake_action");
      expect(est).toBeUndefined();
    });

    it("returns estimate for lynis audit", () => {
      const est = getDurationEstimate("compliance", "lynis_audit");
      expect(est).toBeDefined();
      expect(est!.complexity).toBe("high");
      expect(est!.supportsProgress).toBe(true);
    });

    it("returns estimate for quick tool", () => {
      const est = getDurationEstimate("firewall", "iptables_list");
      expect(est).toBeDefined();
      expect(est!.complexity).toBe("low");
      expect(est!.maxSeconds).toBeLessThanOrEqual(30);
    });
  });

  describe("getRecommendedTimeout", () => {
    it("returns recommended timeout for clamav_scan", () => {
      const timeout = getRecommendedTimeout("malware", "clamav_scan");
      expect(timeout).toBe(900_000); // 15 minutes
    });

    it("returns recommended timeout for rkhunter", () => {
      const timeout = getRecommendedTimeout("integrity", "rootkit_rkhunter");
      expect(timeout).toBe(1_200_000); // 20 minutes
    });

    it("returns fallback for unknown action", () => {
      const timeout = getRecommendedTimeout("unknown", "unknown", 42_000);
      expect(timeout).toBe(42_000);
    });

    it("returns base timeout when no fallback given for unknown", () => {
      const timeout = getRecommendedTimeout("unknown", "unknown");
      expect(timeout).toBe(60_000);
    });
  });

  describe("formatDurationEstimate", () => {
    it("formats short durations in seconds", () => {
      const result = formatDurationEstimate({
        description: "test",
        minSeconds: 5,
        maxSeconds: 15,
        complexity: "low",
        recommendedTimeoutMs: 60_000,
        durationFactors: [],
        supportsProgress: false,
      });
      expect(result).toBe("5-15s");
    });

    it("formats medium durations in minutes", () => {
      const result = formatDurationEstimate({
        description: "test",
        minSeconds: 120,
        maxSeconds: 300,
        complexity: "high",
        recommendedTimeoutMs: 600_000,
        durationFactors: [],
        supportsProgress: true,
      });
      expect(result).toBe("2-5 min");
    });

    it("formats mixed second/minute durations", () => {
      const result = formatDurationEstimate({
        description: "test",
        minSeconds: 30,
        maxSeconds: 120,
        complexity: "medium",
        recommendedTimeoutMs: 300_000,
        durationFactors: [],
        supportsProgress: false,
      });
      expect(result).toBe("30s-2 min");
    });

    it("formats equal min/max durations", () => {
      const result = formatDurationEstimate({
        description: "test",
        minSeconds: 10,
        maxSeconds: 10,
        complexity: "low",
        recommendedTimeoutMs: 60_000,
        durationFactors: [],
        supportsProgress: false,
      });
      expect(result).toBe("~10s");
    });
  });

  describe("formatElapsed", () => {
    it("formats milliseconds", () => {
      expect(formatElapsed(500)).toBe("500ms");
    });

    it("formats seconds", () => {
      expect(formatElapsed(5_000)).toBe("5.0s");
    });

    it("formats minutes and seconds", () => {
      expect(formatElapsed(135_000)).toBe("2m 15s");
    });

    it("formats hours and minutes", () => {
      expect(formatElapsed(3_900_000)).toBe("1h 5m");
    });

    it("formats exact minutes", () => {
      expect(formatElapsed(120_000)).toBe("2m");
    });

    it("formats exact hours", () => {
      expect(formatElapsed(3_600_000)).toBe("1h");
    });
  });

  describe("isLongRunning", () => {
    it("returns true for ClamAV scan", () => {
      expect(isLongRunning("malware", "clamav_scan")).toBe(true);
    });

    it("returns true for rkhunter", () => {
      expect(isLongRunning("integrity", "rootkit_rkhunter")).toBe(true);
    });

    it("returns false for iptables list", () => {
      expect(isLongRunning("firewall", "iptables_list")).toBe(false);
    });

    it("returns false for unknown tool", () => {
      expect(isLongRunning("nonexistent", "fake")).toBe(false);
    });
  });

  describe("getProgressCapableActions", () => {
    it("includes long-running tools", () => {
      const actions = getProgressCapableActions();
      expect(actions).toContain("malware:clamav_scan");
      expect(actions).toContain("integrity:rootkit_rkhunter");
      expect(actions).toContain("compliance:lynis_audit");
    });

    it("excludes quick tools", () => {
      const actions = getProgressCapableActions();
      expect(actions).not.toContain("firewall:iptables_list");
      expect(actions).not.toContain("access_control:ssh_audit");
    });
  });

  describe("getComplexityMultiplier", () => {
    it("returns 1 for low", () => {
      expect(getComplexityMultiplier("low")).toBe(1);
    });

    it("returns 15 for critical", () => {
      expect(getComplexityMultiplier("critical")).toBe(15);
    });
  });

  describe("DURATION_DATABASE", () => {
    it("has recommended timeout > maxSeconds for all entries", () => {
      for (const [key, est] of Object.entries(DURATION_DATABASE)) {
        const maxMs = est.maxSeconds * 1000;
        expect(est.recommendedTimeoutMs).toBeGreaterThanOrEqual(
          maxMs,
        );
      }
    });

    it("has minSeconds <= maxSeconds for all entries", () => {
      for (const [key, est] of Object.entries(DURATION_DATABASE)) {
        expect(est.minSeconds).toBeLessThanOrEqual(est.maxSeconds);
      }
    });

    it("has non-empty descriptions for all entries", () => {
      for (const [key, est] of Object.entries(DURATION_DATABASE)) {
        expect(est.description.length).toBeGreaterThan(0);
      }
    });
  });
});
