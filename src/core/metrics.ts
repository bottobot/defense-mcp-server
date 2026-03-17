/**
 * metrics.ts — In-process metrics collection for observability.
 *
 * Collects tool invocation counts, error rates, and latency histograms
 * in memory. Exposes a `getMetrics()` function that returns a snapshot
 * for reporting via the `defense_mgmt` tool or external monitoring.
 *
 * **Design**: No external dependencies. Metrics are collected in a
 * simple Map structure and can be serialized to JSON. A future
 * Prometheus-compatible endpoint can be added without changing the
 * collection API.
 *
 * Environment:
 *   DEFENSE_MCP_METRICS=true   Enable metrics collection (default: true)
 *
 * @module metrics
 */

// ── Types ────────────────────────────────────────────────────────────────────

/** Metrics snapshot for a single tool. */
export interface ToolMetrics {
  /** Tool name (e.g., "firewall", "harden_host") */
  toolName: string;
  /** Total invocations */
  invocations: number;
  /** Total errors (non-zero exit codes) */
  errors: number;
  /** Total rate-limiter rejections */
  rateLimitHits: number;
  /** Minimum latency in ms */
  minLatencyMs: number;
  /** Maximum latency in ms */
  maxLatencyMs: number;
  /** Sum of all latencies (for computing average) */
  totalLatencyMs: number;
  /** Last invocation timestamp (ISO 8601) */
  lastInvoked: string | null;
}

/** Complete metrics snapshot. */
export interface MetricsSnapshot {
  /** ISO 8601 timestamp when this snapshot was taken */
  timestamp: string;
  /** Server uptime in seconds */
  uptimeSeconds: number;
  /** Total tool invocations across all tools */
  totalInvocations: number;
  /** Total errors across all tools */
  totalErrors: number;
  /** Per-tool metrics */
  tools: ToolMetrics[];
}

// ── Metrics Collector ────────────────────────────────────────────────────────

const enabled = process.env.DEFENSE_MCP_METRICS !== "false";
const startTime = Date.now();
const toolMetrics = new Map<string, ToolMetrics>();

/** Get or create a metrics entry for a tool. */
function getOrCreate(toolName: string): ToolMetrics {
  let entry = toolMetrics.get(toolName);
  if (!entry) {
    entry = {
      toolName,
      invocations: 0,
      errors: 0,
      rateLimitHits: 0,
      minLatencyMs: Infinity,
      maxLatencyMs: 0,
      totalLatencyMs: 0,
      lastInvoked: null,
    };
    toolMetrics.set(toolName, entry);
  }
  return entry;
}

/**
 * Record a tool invocation.
 *
 * @param toolName   - The tool that was invoked
 * @param durationMs - Wall-clock duration of the invocation in milliseconds
 * @param isError    - Whether the invocation resulted in an error
 */
export function recordInvocation(
  toolName: string,
  durationMs: number,
  isError: boolean,
): void {
  if (!enabled) return;

  const entry = getOrCreate(toolName);
  entry.invocations++;
  entry.totalLatencyMs += durationMs;
  entry.lastInvoked = new Date().toISOString();

  if (durationMs < entry.minLatencyMs) entry.minLatencyMs = durationMs;
  if (durationMs > entry.maxLatencyMs) entry.maxLatencyMs = durationMs;

  if (isError) entry.errors++;
}

/**
 * Record a rate-limiter rejection for a tool.
 *
 * @param toolName - The tool that was rate-limited
 */
export function recordRateLimitHit(toolName: string): void {
  if (!enabled) return;
  getOrCreate(toolName).rateLimitHits++;
}

/**
 * Get a complete metrics snapshot.
 *
 * @returns MetricsSnapshot with per-tool breakdown
 */
export function getMetrics(): MetricsSnapshot {
  const tools = Array.from(toolMetrics.values()).map((t) => ({
    ...t,
    // Replace Infinity with 0 for tools that haven't been invoked
    minLatencyMs: t.minLatencyMs === Infinity ? 0 : t.minLatencyMs,
  }));

  const totalInvocations = tools.reduce((sum, t) => sum + t.invocations, 0);
  const totalErrors = tools.reduce((sum, t) => sum + t.errors, 0);

  return {
    timestamp: new Date().toISOString(),
    uptimeSeconds: Math.floor((Date.now() - startTime) / 1000),
    totalInvocations,
    totalErrors,
    tools,
  };
}

/**
 * Reset all metrics. Primarily used in tests.
 */
export function resetMetrics(): void {
  toolMetrics.clear();
}
