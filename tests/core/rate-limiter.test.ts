import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { RateLimiter } from "../../src/core/rate-limiter.js";

describe("rate-limiter", () => {
  let limiter: RateLimiter;

  beforeEach(() => {
    RateLimiter.resetInstance();
  });

  afterEach(() => {
    RateLimiter.resetInstance();
  });

  // ── Constructor / configuration ─────────────────────────────────────────

  describe("constructor", () => {
    it("should use provided limits when given", () => {
      limiter = new RateLimiter(10, 50, 30);
      expect(limiter.maxPerTool).toBe(10);
      expect(limiter.maxGlobal).toBe(50);
      expect(limiter.windowMs).toBe(30_000);
    });

    it("should use defaults when no arguments provided", () => {
      limiter = new RateLimiter();
      expect(limiter.maxPerTool).toBe(30);
      expect(limiter.maxGlobal).toBe(100);
      expect(limiter.windowMs).toBe(60_000);
    });

    it("should read limits from environment variables", () => {
      const envBackup = {
        perTool: process.env.DEFENSE_MCP_RATE_LIMIT_PER_TOOL,
        global: process.env.DEFENSE_MCP_RATE_LIMIT_GLOBAL,
        window: process.env.DEFENSE_MCP_RATE_LIMIT_WINDOW,
      };
      try {
        process.env.DEFENSE_MCP_RATE_LIMIT_PER_TOOL = "5";
        process.env.DEFENSE_MCP_RATE_LIMIT_GLOBAL = "20";
        process.env.DEFENSE_MCP_RATE_LIMIT_WINDOW = "120";

        limiter = new RateLimiter();
        expect(limiter.maxPerTool).toBe(5);
        expect(limiter.maxGlobal).toBe(20);
        expect(limiter.windowMs).toBe(120_000);
      } finally {
        process.env.DEFENSE_MCP_RATE_LIMIT_PER_TOOL = envBackup.perTool;
        process.env.DEFENSE_MCP_RATE_LIMIT_GLOBAL = envBackup.global;
        process.env.DEFENSE_MCP_RATE_LIMIT_WINDOW = envBackup.window;
      }
    });

    it("should fall back to defaults for invalid env var values", () => {
      const envBackup = process.env.DEFENSE_MCP_RATE_LIMIT_PER_TOOL;
      try {
        process.env.DEFENSE_MCP_RATE_LIMIT_PER_TOOL = "not_a_number";
        limiter = new RateLimiter();
        expect(limiter.maxPerTool).toBe(30); // default
      } finally {
        process.env.DEFENSE_MCP_RATE_LIMIT_PER_TOOL = envBackup;
      }
    });

    it("should fall back to defaults for negative env var values", () => {
      const envBackup = process.env.DEFENSE_MCP_RATE_LIMIT_PER_TOOL;
      try {
        process.env.DEFENSE_MCP_RATE_LIMIT_PER_TOOL = "-5";
        limiter = new RateLimiter();
        expect(limiter.maxPerTool).toBe(30); // default
      } finally {
        process.env.DEFENSE_MCP_RATE_LIMIT_PER_TOOL = envBackup;
      }
    });
  });

  // ── Singleton ───────────────────────────────────────────────────────────

  describe("singleton", () => {
    it("should return the same instance on repeated calls", () => {
      const a = RateLimiter.instance();
      const b = RateLimiter.instance();
      expect(a).toBe(b);
    });

    it("should return a new instance after resetInstance", () => {
      const a = RateLimiter.instance();
      RateLimiter.resetInstance();
      const b = RateLimiter.instance();
      expect(a).not.toBe(b);
    });
  });

  // ── Per-tool rate limiting ──────────────────────────────────────────────

  describe("per-tool rate limiting", () => {
    it("should allow invocations within the per-tool limit", () => {
      limiter = new RateLimiter(3, 100, 60);

      const r1 = limiter.check("firewall_iptables");
      expect(r1.allowed).toBe(true);
      expect(r1.remainingPerTool).toBe(2);

      const r2 = limiter.check("firewall_iptables");
      expect(r2.allowed).toBe(true);
      expect(r2.remainingPerTool).toBe(1);

      const r3 = limiter.check("firewall_iptables");
      expect(r3.allowed).toBe(true);
      expect(r3.remainingPerTool).toBe(0);
    });

    it("should reject invocations that exceed the per-tool limit", () => {
      limiter = new RateLimiter(2, 100, 60);

      limiter.check("firewall_iptables");
      limiter.check("firewall_iptables");

      const rejected = limiter.check("firewall_iptables");
      expect(rejected.allowed).toBe(false);
      expect(rejected.reason).toContain("Per-tool rate limit exceeded");
      expect(rejected.reason).toContain("firewall_iptables");
      expect(rejected.remainingPerTool).toBe(0);
    });

    it("should track different tools independently", () => {
      limiter = new RateLimiter(1, 100, 60);

      const r1 = limiter.check("firewall_iptables");
      expect(r1.allowed).toBe(true);

      // Different tool should still be allowed
      const r2 = limiter.check("harden_sysctl");
      expect(r2.allowed).toBe(true);

      // Same tool should now be rejected
      const r3 = limiter.check("firewall_iptables");
      expect(r3.allowed).toBe(false);
    });
  });

  // ── Global rate limiting ────────────────────────────────────────────────

  describe("global rate limiting", () => {
    it("should reject when global limit is reached across tools", () => {
      limiter = new RateLimiter(10, 3, 60);

      limiter.check("tool_a");
      limiter.check("tool_b");
      limiter.check("tool_c");

      const rejected = limiter.check("tool_d");
      expect(rejected.allowed).toBe(false);
      expect(rejected.reason).toContain("Global rate limit exceeded");
      expect(rejected.remainingGlobal).toBe(0);
    });

    it("should report remaining global invocations correctly", () => {
      limiter = new RateLimiter(100, 5, 60);

      const r1 = limiter.check("tool_a");
      expect(r1.remainingGlobal).toBe(4);

      limiter.check("tool_b");
      limiter.check("tool_c");

      const r4 = limiter.check("tool_d");
      expect(r4.remainingGlobal).toBe(1);
    });
  });

  // ── Window expiry / sliding window ─────────────────────────────────────

  describe("sliding window", () => {
    it("should allow invocations after window expires", () => {
      // Use a very short window (1 second = 1000ms)
      limiter = new RateLimiter(1, 100, 1);

      const r1 = limiter.check("firewall_iptables");
      expect(r1.allowed).toBe(true);

      // Should be rejected immediately
      const r2 = limiter.check("firewall_iptables");
      expect(r2.allowed).toBe(false);

      // Manually age out the timestamps by manipulating internals
      // Access private field via any cast for testing
      const toolBuckets = (limiter as unknown as { toolBuckets: Map<string, { timestamps: number[] }> }).toolBuckets;
      const globalBucket = (limiter as unknown as { globalBucket: { timestamps: number[] } }).globalBucket;
      const oldTime = Date.now() - 2000; // 2 seconds ago
      const bucket = toolBuckets.get("firewall_iptables");
      if (bucket) bucket.timestamps = [oldTime];
      globalBucket.timestamps = [oldTime];

      // Now should be allowed again
      const r3 = limiter.check("firewall_iptables");
      expect(r3.allowed).toBe(true);
    });
  });

  // ── Disabled limits (0 = disabled) ──────────────────────────────────────

  describe("disabled limits", () => {
    it("should allow unlimited per-tool invocations when maxPerTool is 0", () => {
      limiter = new RateLimiter(0, 100, 60);

      for (let i = 0; i < 50; i++) {
        const result = limiter.check("firewall_iptables");
        expect(result.allowed).toBe(true);
      }
    });

    it("should allow unlimited global invocations when maxGlobal is 0", () => {
      limiter = new RateLimiter(100, 0, 60);

      for (let i = 0; i < 50; i++) {
        const result = limiter.check(`tool_${i}`);
        expect(result.allowed).toBe(true);
      }
    });

    it("should report Infinity for remaining when limit is disabled", () => {
      limiter = new RateLimiter(0, 0, 60);

      const result = limiter.check("firewall_iptables");
      expect(result.allowed).toBe(true);
      expect(result.remainingPerTool).toBe(Infinity);
      expect(result.remainingGlobal).toBe(Infinity);
    });
  });

  // ── reset ───────────────────────────────────────────────────────────────

  describe("reset", () => {
    it("should clear all rate limit state", () => {
      limiter = new RateLimiter(1, 100, 60);

      limiter.check("firewall_iptables");
      const rejected = limiter.check("firewall_iptables");
      expect(rejected.allowed).toBe(false);

      limiter.reset();

      const afterReset = limiter.check("firewall_iptables");
      expect(afterReset.allowed).toBe(true);
    });
  });
});
