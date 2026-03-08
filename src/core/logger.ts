/**
 * logger.ts — Structured logging module for security event correlation.
 *
 * Outputs JSON-formatted log entries with consistent fields for easy parsing
 * by log aggregation systems (ELK, Splunk, Loki, etc.).
 *
 * Supports standard log levels plus a `security` level for security-relevant
 * events (authentication, privilege escalation, policy violations).
 *
 * @module logger
 * @see CICD-027
 */

// ── Types ────────────────────────────────────────────────────────────────────

/** Supported log levels, ordered by severity (lowest to highest). */
export type LogLevel = "debug" | "info" | "warn" | "error" | "security";

/** Numeric severity for each log level (used for filtering). */
const LOG_LEVEL_SEVERITY: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
  /** Security events always log regardless of level (severity 999). */
  security: 999,
};

/** A structured log entry written as JSON to stderr. */
export interface LogEntry {
  /** ISO 8601 UTC timestamp */
  timestamp: string;
  /** Log severity level */
  level: LogLevel;
  /** Module or subsystem that produced the log (e.g., "preflight", "executor") */
  component: string;
  /** Action being performed (e.g., "tool_invoked", "sudo_elevated") */
  action: string;
  /** Human-readable message */
  message: string;
  /** Optional structured details (tool params, error info, metrics, etc.) */
  details?: Record<string, unknown>;
}

// ── Logger Class ─────────────────────────────────────────────────────────────

/**
 * Structured logger that outputs JSON to stderr.
 *
 * Uses stderr so log output doesn't interfere with MCP protocol messages
 * on stdout (StdioServerTransport).
 *
 * Usage:
 * ```typescript
 * import { logger } from './logger.js';
 *
 * logger.info('preflight', 'cache_hit', 'Pre-flight cache hit for tool', { toolName: 'firewall_iptables' });
 * logger.security('sudo-guard', 'elevation_requested', 'Sudo elevation requested', { tool: 'harden_sysctl' });
 * ```
 */
export class Logger {
  private minLevel: LogLevel;

  constructor(minLevel?: LogLevel) {
    this.minLevel = minLevel ?? this.parseEnvLevel();
  }

  /**
   * Read the minimum log level from `KALI_DEFENSE_LOG_LEVEL` env var.
   * Falls back to `"info"` if unset or invalid.
   */
  private parseEnvLevel(): LogLevel {
    const raw = process.env.KALI_DEFENSE_LOG_LEVEL?.toLowerCase();
    if (raw && raw in LOG_LEVEL_SEVERITY) {
      return raw as LogLevel;
    }
    return "info";
  }

  /** Check whether a message at `level` should be emitted. */
  private shouldLog(level: LogLevel): boolean {
    return LOG_LEVEL_SEVERITY[level] >= LOG_LEVEL_SEVERITY[this.minLevel];
  }

  /**
   * Emit a structured log entry as a single JSON line to stderr.
   *
   * @param level     - Severity level
   * @param component - Subsystem name (e.g., "executor", "preflight")
   * @param action    - Action identifier (e.g., "command_executed", "cache_miss")
   * @param message   - Human-readable description
   * @param details   - Optional structured metadata
   */
  log(
    level: LogLevel,
    component: string,
    action: string,
    message: string,
    details?: Record<string, unknown>,
  ): void {
    if (!this.shouldLog(level)) return;

    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      component,
      action,
      message,
      ...(details !== undefined ? { details } : {}),
    };

    // Single-line JSON to stderr — safe for MCP stdio transport
    process.stderr.write(JSON.stringify(entry) + "\n");
  }

  /** Log a debug-level message. */
  debug(
    component: string,
    action: string,
    message: string,
    details?: Record<string, unknown>,
  ): void {
    this.log("debug", component, action, message, details);
  }

  /** Log an info-level message. */
  info(
    component: string,
    action: string,
    message: string,
    details?: Record<string, unknown>,
  ): void {
    this.log("info", component, action, message, details);
  }

  /** Log a warning-level message. */
  warn(
    component: string,
    action: string,
    message: string,
    details?: Record<string, unknown>,
  ): void {
    this.log("warn", component, action, message, details);
  }

  /** Log an error-level message. */
  error(
    component: string,
    action: string,
    message: string,
    details?: Record<string, unknown>,
  ): void {
    this.log("error", component, action, message, details);
  }

  /**
   * Log a security-relevant event.
   *
   * Security events are **always** emitted regardless of the configured
   * minimum log level. Use for:
   * - Authentication / privilege escalation events
   * - Policy violations
   * - Rate limit breaches
   * - Suspicious input patterns
   * - Configuration changes with security impact
   */
  security(
    component: string,
    action: string,
    message: string,
    details?: Record<string, unknown>,
  ): void {
    this.log("security", component, action, message, details);
  }

  /**
   * Update the minimum log level at runtime.
   * Useful for tests or dynamic configuration changes.
   */
  setLevel(level: LogLevel): void {
    this.minLevel = level;
  }

  /** Get the current minimum log level. */
  getLevel(): LogLevel {
    return this.minLevel;
  }
}

// ── Singleton Export ─────────────────────────────────────────────────────────

/**
 * Default singleton logger instance.
 *
 * Import and use directly:
 * ```typescript
 * import { logger } from '../core/logger.js';
 * logger.info('my-module', 'action', 'Something happened');
 * ```
 */
export const logger = new Logger();
