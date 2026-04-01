/**
 * Progress tracking and duration display for Defense MCP Server.
 *
 * Provides utilities to:
 * 1. Generate pre-execution duration banners for tool output
 * 2. Format progress bars for long-running operations
 * 3. Generate post-execution timing summaries
 *
 * Since MCP tools communicate via text responses (not streaming),
 * progress is conveyed through:
 * - Pre-execution banners with duration estimates
 * - Post-execution timing summaries with actual vs estimated duration
 *
 * @module progress
 */

import {
  getDurationEstimate,
  formatDurationEstimate,
  formatElapsed,
  isLongRunning,
  type DurationEstimate,
  type Complexity,
} from "./tool-durations.js";

// ── Types ────────────────────────────────────────────────────────────────────

/** Progress bar style configuration */
export interface ProgressBarOptions {
  /** Total width of the bar in characters (default: 20) */
  width?: number;
  /** Character for filled portion (default: "█") */
  fillChar?: string;
  /** Character for empty portion (default: "░") */
  emptyChar?: string;
}

/** Timing context for a tool execution */
export interface TimingContext {
  /** Tool name */
  toolName: string;
  /** Action being performed */
  action: string;
  /** Start timestamp in ms */
  startTime: number;
  /** Duration estimate (if available) */
  estimate?: DurationEstimate;
}

// ── Progress Bar Rendering ───────────────────────────────────────────────────

const DEFAULT_BAR_WIDTH = 20;
const FILL_CHAR = "█";
const EMPTY_CHAR = "░";

/**
 * Render a text-based progress bar.
 *
 * @param percent - Completion percentage (0-100)
 * @param options - Optional style configuration
 * @returns Formatted progress bar string like "[████████░░░░░░░░░░░░] 40%"
 */
export function renderProgressBar(
  percent: number,
  options?: ProgressBarOptions
): string {
  const width = options?.width ?? DEFAULT_BAR_WIDTH;
  const fill = options?.fillChar ?? FILL_CHAR;
  const empty = options?.emptyChar ?? EMPTY_CHAR;

  const clamped = Math.max(0, Math.min(100, percent));
  const filled = Math.round((clamped / 100) * width);
  const remaining = width - filled;

  return `[${fill.repeat(filled)}${empty.repeat(remaining)}] ${Math.round(clamped)}%`;
}

// ── Complexity Badges ────────────────────────────────────────────────────────

const COMPLEXITY_BADGES: Record<Complexity, string> = {
  low: "LOW",
  medium: "MEDIUM",
  high: "HIGH",
  critical: "WARNING: CRITICAL",
};

// ── Pre-Execution Banner ─────────────────────────────────────────────────────

/**
 * Generate a pre-execution duration banner for tool output.
 *
 * For quick tools (< 30s), returns a compact one-liner.
 * For long-running tools (> 30s), returns a detailed multi-line banner
 * with duration estimate, complexity, and timeout information.
 *
 * @param toolName - Tool name (e.g., "malware")
 * @param action - Action being performed (e.g., "clamav_scan")
 * @param timeoutMs - Configured timeout in milliseconds
 * @returns Formatted banner string to prepend to tool output
 */
export function generateDurationBanner(
  toolName: string,
  action: string,
  timeoutMs: number
): string {
  const estimate = getDurationEstimate(toolName, action);

  if (!estimate) {
    // No estimate available — return minimal info
    return `Timeout: ${formatElapsed(timeoutMs)}\n`;
  }

  const durationStr = formatDurationEstimate(estimate);
  const complexityBadge = COMPLEXITY_BADGES[estimate.complexity];
  const longRunning = isLongRunning(toolName, action);

  if (!longRunning) {
    // Quick tool — compact one-liner
    return `Est: ${durationStr} | ${complexityBadge}\n`;
  }

  // Long-running tool — detailed banner
  const lines: string[] = [];
  lines.push("┌─────────────────────────────────────────────────────────┐");
  lines.push(`│ ${estimate.description.padEnd(54)}│`);
  lines.push("├─────────────────────────────────────────────────────────┤");
  lines.push(`│ Duration estimate: ${durationStr.padEnd(36)}│`);
  lines.push(`│ Complexity: ${complexityBadge.padEnd(42)}│`);
  lines.push(`│ Timeout: ${formatElapsed(timeoutMs).padEnd(45)}│`);

  if (estimate.supportsProgress) {
    lines.push(`│ Progress tracking: enabled${" ".repeat(28)}│`);
  }

  if (estimate.durationFactors.length > 0) {
    lines.push(`│ Factors: ${estimate.durationFactors.slice(0, 2).join(", ").padEnd(45)}│`);
  }

  lines.push("└─────────────────────────────────────────────────────────┘");

  return lines.join("\n") + "\n\n";
}

// ── Post-Execution Summary ───────────────────────────────────────────────────

/**
 * Generate a post-execution timing summary.
 *
 * Compares actual duration to estimated duration and provides feedback
 * on whether the tool ran faster/slower than expected.
 *
 * @param toolName - Tool name
 * @param action - Action performed
 * @param actualMs - Actual execution time in milliseconds
 * @returns Formatted timing summary string
 */
export function generateTimingSummary(
  toolName: string,
  action: string,
  actualMs: number
): string {
  const estimate = getDurationEstimate(toolName, action);
  const actualStr = formatElapsed(actualMs);

  if (!estimate) {
    return `\nCompleted in ${actualStr}`;
  }

  const minMs = estimate.minSeconds * 1000;
  const maxMs = estimate.maxSeconds * 1000;
  const estimatedStr = formatDurationEstimate(estimate);

  let indicator: string;
  if (actualMs < minMs) {
    indicator = "Faster than expected";
  } else if (actualMs > maxMs) {
    indicator = "Slower than expected";
  } else {
    indicator = "PASS: Within estimate";
  }

  return `\nCompleted in ${actualStr} (est: ${estimatedStr}) — ${indicator}`;
}

// ── Timing Context Helpers ───────────────────────────────────────────────────

/**
 * Create a timing context for tracking tool execution duration.
 */
export function startTiming(toolName: string, action: string): TimingContext {
  return {
    toolName,
    action,
    startTime: Date.now(),
    estimate: getDurationEstimate(toolName, action),
  };
}

/**
 * Get elapsed time in milliseconds from a timing context.
 */
export function getElapsed(ctx: TimingContext): number {
  return Date.now() - ctx.startTime;
}

/**
 * Complete timing and return summary string.
 */
export function finishTiming(ctx: TimingContext): string {
  const elapsed = getElapsed(ctx);
  return generateTimingSummary(ctx.toolName, ctx.action, elapsed);
}

// ── Phase Banner (for multi-step audit workflows) ────────────────────────────

/** Tool info for a phase */
export interface PhaseToolInfo {
  toolName: string;
  action: string;
  /** Optional human-readable label override */
  label?: string;
}

/**
 * Generate a phase summary banner showing all tools in a phase
 * with their estimated durations.
 *
 * @param phaseName - Phase name/title (e.g., "MALWARE & INTEGRITY")
 * @param phaseNumber - Phase number (e.g., 11)
 * @param tools - List of tools to be executed in this phase
 * @returns Formatted phase banner string
 */
export function generatePhaseBanner(
  phaseName: string,
  phaseNumber: number,
  tools: PhaseToolInfo[]
): string {
  const lines: string[] = [];
  lines.push("╔════════════════════════════════════════════════════════════╗");
  lines.push(`║  PHASE ${phaseNumber}: ${phaseName.padEnd(48)}║`);
  lines.push("╠════════════════════════════════════════════════════════════╣");
  lines.push("║                                                            ║");

  let totalMinSec = 0;
  let totalMaxSec = 0;
  let hasLongRunning = false;

  for (const tool of tools) {
    const estimate = getDurationEstimate(tool.toolName, tool.action);
    const label = tool.label ?? `${tool.toolName}:${tool.action}`;

    if (estimate) {
      const durationStr = formatDurationEstimate(estimate);
      const badge = COMPLEXITY_BADGES[estimate.complexity];
      lines.push(`║  ├─ ${label.padEnd(28)} ${durationStr.padEnd(14)} ${badge.padEnd(10)}║`);
      totalMinSec += estimate.minSeconds;
      totalMaxSec += estimate.maxSeconds;
      if (estimate.maxSeconds > 30) hasLongRunning = true;
    } else {
      lines.push(`║  ├─ ${label.padEnd(28)} ~unknown${" ".repeat(23)}║`);
    }
  }

  lines.push("║                                                            ║");

  if (totalMinSec > 0) {
    const totalMinMin = Math.ceil(totalMinSec / 60);
    const totalMaxMin = Math.ceil(totalMaxSec / 60);
    const avgMin = Math.ceil((totalMinMin + totalMaxMin) / 2);
    lines.push(`║  TOTAL ESTIMATE: ${totalMinMin}-${totalMaxMin} min (avg: ~${avgMin} min)${" ".repeat(Math.max(0, 20 - String(totalMaxMin).length - String(avgMin).length))}║`);
  }

  if (hasLongRunning) {
    lines.push("║  WARNING: Long-running phase — progress updates included         ║");
  }

  lines.push("║  OK All tools will run to completion (no timeouts)          ║");
  lines.push("║                                                            ║");
  lines.push("╚════════════════════════════════════════════════════════════╝");

  return lines.join("\n");
}
