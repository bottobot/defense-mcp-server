/**
 * rate-limiter.ts — Token-bucket rate limiter for MCP tool invocations.
 *
 * Provides per-tool and global rate limiting to prevent abuse and resource
 * exhaustion. Limits are configurable via environment variables.
 *
 * @module rate-limiter
 * @see CICD-024
 */

// ── Types ────────────────────────────────────────────────────────────────────

/** Tracks invocation timestamps for a single bucket (tool or global). */
interface Bucket {
  /** Timestamps (ms) of invocations within the current window */
  timestamps: number[];
}

/** Result of a rate limit check. */
export interface RateLimitResult {
  /** Whether the invocation is allowed */
  allowed: boolean;
  /** If rejected, the reason message */
  reason?: string;
  /** Remaining invocations in the current window (per-tool) */
  remainingPerTool: number;
  /** Remaining invocations in the current window (global) */
  remainingGlobal: number;
}

// ── Rate Limiter Class ───────────────────────────────────────────────────────

/**
 * Simple sliding-window rate limiter for tool invocations.
 *
 * Tracks invocations per tool and globally using timestamp arrays.
 * Old entries outside the time window are pruned on each check.
 *
 * Configuration via environment variables:
 * - `KALI_DEFENSE_RATE_LIMIT_PER_TOOL` — Max invocations per tool per window (default: 30)
 * - `KALI_DEFENSE_RATE_LIMIT_GLOBAL`   — Max total invocations per window (default: 100)
 * - `KALI_DEFENSE_RATE_LIMIT_WINDOW`   — Window size in seconds (default: 60)
 *
 * Set any limit to `0` to disable that particular limit.
 */
export class RateLimiter {
  /** Per-tool invocation buckets */
  private toolBuckets: Map<string, Bucket> = new Map();
  /** Global invocation bucket */
  private globalBucket: Bucket = { timestamps: [] };

  /** Max invocations per tool per window */
  readonly maxPerTool: number;
  /** Max total invocations per window */
  readonly maxGlobal: number;
  /** Window size in milliseconds */
  readonly windowMs: number;

  private static _instance: RateLimiter | null = null;

  constructor(maxPerTool?: number, maxGlobal?: number, windowMs?: number) {
    this.maxPerTool = maxPerTool ?? this.parseEnvInt("KALI_DEFENSE_RATE_LIMIT_PER_TOOL", 30);
    this.maxGlobal = maxGlobal ?? this.parseEnvInt("KALI_DEFENSE_RATE_LIMIT_GLOBAL", 100);
    this.windowMs = (windowMs ?? this.parseEnvInt("KALI_DEFENSE_RATE_LIMIT_WINDOW", 60)) * 1000;
  }

  /** Get or create the singleton instance. */
  static instance(): RateLimiter {
    if (!RateLimiter._instance) {
      RateLimiter._instance = new RateLimiter();
    }
    return RateLimiter._instance;
  }

  /** Reset the singleton (for testing). */
  static resetInstance(): void {
    RateLimiter._instance = null;
  }

  /**
   * Check whether an invocation of `toolName` is allowed, and if so,
   * record it. Returns a {@link RateLimitResult} indicating whether the
   * call is permitted.
   *
   * @param toolName - The MCP tool name being invoked
   * @returns Rate limit check result
   */
  check(toolName: string): RateLimitResult {
    const now = Date.now();

    // Prune expired entries
    this.pruneGlobal(now);
    this.pruneTool(toolName, now);

    const toolBucket = this.getToolBucket(toolName);
    const globalCount = this.globalBucket.timestamps.length;
    const toolCount = toolBucket.timestamps.length;

    // Check global limit (0 = disabled)
    if (this.maxGlobal > 0 && globalCount >= this.maxGlobal) {
      return {
        allowed: false,
        reason:
          `Global rate limit exceeded: ${globalCount}/${this.maxGlobal} invocations ` +
          `in the last ${this.windowMs / 1000}s. Please wait before retrying.`,
        remainingPerTool: Math.max(0, this.maxPerTool - toolCount),
        remainingGlobal: 0,
      };
    }

    // Check per-tool limit (0 = disabled)
    if (this.maxPerTool > 0 && toolCount >= this.maxPerTool) {
      return {
        allowed: false,
        reason:
          `Per-tool rate limit exceeded for '${toolName}': ${toolCount}/${this.maxPerTool} ` +
          `invocations in the last ${this.windowMs / 1000}s. Please wait before retrying.`,
        remainingPerTool: 0,
        remainingGlobal: Math.max(0, this.maxGlobal - globalCount),
      };
    }

    // Allowed — record the invocation
    toolBucket.timestamps.push(now);
    this.globalBucket.timestamps.push(now);

    return {
      allowed: true,
      remainingPerTool: this.maxPerTool > 0 ? this.maxPerTool - toolCount - 1 : Infinity,
      remainingGlobal: this.maxGlobal > 0 ? this.maxGlobal - globalCount - 1 : Infinity,
    };
  }

  /** Clear all rate limit state (for testing). */
  reset(): void {
    this.toolBuckets.clear();
    this.globalBucket = { timestamps: [] };
  }

  // ── Internal helpers ─────────────────────────────────────────────────────

  private getToolBucket(toolName: string): Bucket {
    let bucket = this.toolBuckets.get(toolName);
    if (!bucket) {
      bucket = { timestamps: [] };
      this.toolBuckets.set(toolName, bucket);
    }
    return bucket;
  }

  private pruneGlobal(now: number): void {
    const cutoff = now - this.windowMs;
    this.globalBucket.timestamps = this.globalBucket.timestamps.filter(
      (t) => t > cutoff,
    );
  }

  private pruneTool(toolName: string, now: number): void {
    const bucket = this.toolBuckets.get(toolName);
    if (bucket) {
      const cutoff = now - this.windowMs;
      bucket.timestamps = bucket.timestamps.filter((t) => t > cutoff);
    }
  }

  private parseEnvInt(envVar: string, defaultValue: number): number {
    const raw = process.env[envVar];
    if (raw === undefined) return defaultValue;
    const parsed = parseInt(raw, 10);
    return isNaN(parsed) || parsed < 0 ? defaultValue : parsed;
  }
}
