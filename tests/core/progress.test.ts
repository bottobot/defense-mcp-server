/**
 * Tests for progress tracking and duration display.
 */

import { describe, it, expect } from "vitest";
import {
  renderProgressBar,
  generateDurationBanner,
  generateTimingSummary,
  startTiming,
  getElapsed,
  finishTiming,
  generatePhaseBanner,
} from "../../src/core/progress.js";

describe("progress", () => {
  describe("renderProgressBar", () => {
    it("renders 0% progress", () => {
      const bar = renderProgressBar(0);
      expect(bar).toBe("[░░░░░░░░░░░░░░░░░░░░] 0%");
    });

    it("renders 50% progress", () => {
      const bar = renderProgressBar(50);
      expect(bar).toBe("[██████████░░░░░░░░░░] 50%");
    });

    it("renders 100% progress", () => {
      const bar = renderProgressBar(100);
      expect(bar).toBe("[████████████████████] 100%");
    });

    it("clamps values above 100", () => {
      const bar = renderProgressBar(150);
      expect(bar).toBe("[████████████████████] 100%");
    });

    it("clamps values below 0", () => {
      const bar = renderProgressBar(-10);
      expect(bar).toBe("[░░░░░░░░░░░░░░░░░░░░] 0%");
    });

    it("supports custom width", () => {
      const bar = renderProgressBar(50, { width: 10 });
      expect(bar).toBe("[█████░░░░░] 50%");
    });

    it("supports custom characters", () => {
      const bar = renderProgressBar(50, { fillChar: "#", emptyChar: "-", width: 10 });
      expect(bar).toBe("[#####-----] 50%");
    });
  });

  describe("generateDurationBanner", () => {
    it("generates banner for known long-running tool", () => {
      const banner = generateDurationBanner("malware", "clamav_scan", 900_000);
      expect(banner).toContain("ClamAV");
      expect(banner).toContain("Duration estimate");
      expect(banner).toContain("Complexity");
      expect(banner).toContain("Timeout");
      expect(banner).toContain("Progress tracking");
    });

    it("generates compact banner for quick tool", () => {
      const banner = generateDurationBanner("firewall", "iptables_list", 60_000);
      expect(banner).toContain("Est:");
      expect(banner).toContain("LOW");
      // Should NOT contain the box-drawing characters of the detailed banner
      expect(banner).not.toContain("┌");
    });

    it("generates minimal banner for unknown tool", () => {
      const banner = generateDurationBanner("unknown", "unknown", 60_000);
      expect(banner).toContain("Timeout");
    });

    it("generates banner for rkhunter", () => {
      const banner = generateDurationBanner("integrity", "rootkit_rkhunter", 1_200_000);
      expect(banner).toContain("Rootkit Hunter");
      expect(banner).toContain("CRITICAL");
    });
  });

  describe("generateTimingSummary", () => {
    it("shows faster than expected for quick execution", () => {
      // clamav_scan minSeconds is 120 → 120000ms
      const summary = generateTimingSummary("malware", "clamav_scan", 50_000);
      expect(summary).toContain("Faster than expected");
    });

    it("shows within estimate for normal execution", () => {
      // clamav_scan: 120-600s → 120000-600000ms
      const summary = generateTimingSummary("malware", "clamav_scan", 300_000);
      expect(summary).toContain("Within estimate");
    });

    it("shows slower than expected for long execution", () => {
      // clamav_scan maxSeconds is 600 → 600000ms
      const summary = generateTimingSummary("malware", "clamav_scan", 700_000);
      expect(summary).toContain("Slower than expected");
    });

    it("handles unknown tool gracefully", () => {
      const summary = generateTimingSummary("unknown", "unknown", 5_000);
      expect(summary).toContain("Completed in");
    });
  });

  describe("startTiming / getElapsed / finishTiming", () => {
    it("creates timing context", () => {
      const ctx = startTiming("malware", "clamav_scan");
      expect(ctx.toolName).toBe("malware");
      expect(ctx.action).toBe("clamav_scan");
      expect(ctx.startTime).toBeGreaterThan(0);
      expect(ctx.estimate).toBeDefined();
    });

    it("tracks elapsed time", async () => {
      const ctx = startTiming("malware", "clamav_scan");
      // Small delay
      await new Promise((r) => setTimeout(r, 10));
      const elapsed = getElapsed(ctx);
      expect(elapsed).toBeGreaterThanOrEqual(5);
    });

    it("finishes timing with summary", () => {
      const ctx = startTiming("malware", "clamav_scan");
      // Force a known startTime for predictable output
      ctx.startTime = Date.now() - 5000;
      const summary = finishTiming(ctx);
      expect(summary).toContain("Completed in");
      expect(summary).toContain("5.0s");
    });
  });

  describe("generatePhaseBanner", () => {
    it("generates phase banner with tools", () => {
      const banner = generatePhaseBanner("MALWARE & INTEGRITY", 11, [
        { toolName: "malware", action: "clamav_scan", label: "ClamAV Scan" },
        { toolName: "integrity", action: "rootkit_rkhunter", label: "rkhunter" },
      ]);
      expect(banner).toContain("PHASE 11");
      expect(banner).toContain("MALWARE & INTEGRITY");
      expect(banner).toContain("ClamAV Scan");
      expect(banner).toContain("rkhunter");
      expect(banner).toContain("TOTAL ESTIMATE");
      expect(banner).toContain("Long-running phase");
    });

    it("handles empty tools list", () => {
      const banner = generatePhaseBanner("EMPTY", 0, []);
      expect(banner).toContain("PHASE 0");
      expect(banner).toContain("EMPTY");
    });

    it("handles unknown tools gracefully", () => {
      const banner = generatePhaseBanner("TEST", 1, [
        { toolName: "unknown", action: "unknown", label: "Unknown Tool" },
      ]);
      expect(banner).toContain("Unknown Tool");
      expect(banner).toContain("unknown");
    });
  });
});
