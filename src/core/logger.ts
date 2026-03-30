/**
 * logger.ts — Structured logging module for security event correlation.
 *
 * Outputs JSON-formatted log entries with consistent fields for easy parsing
 * by log aggregation systems (ELK, Splunk, Loki, etc.).
 *
 * Supports standard log levels plus a `security` level for security-relevant
 * events (authentication, privilege escalation, policy violations).
 *
 * Optional file-based logging with size-based rotation via:
 *   DEFENSE_MCP_LOG_FILE=/path/to/logfile.json
 *   DEFENSE_MCP_LOG_MAX_SIZE=10485760  (10 MB default)
 *   DEFENSE_MCP_LOG_MAX_FILES=5        (keep 5 rotated files)
 *
 * @module logger
 * @see CICD-027
 */

import { appendFileSync, statSync, renameSync, existsSync, unlinkSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

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

// ── Log Rotation ─────────────────────────────────────────────────────────────

/** Default max log file size: 10 MB */
const DEFAULT_MAX_SIZE = 10 * 1024 * 1024;
/** Default number of rotated files to keep */
const DEFAULT_MAX_FILES = 5;

/**
 * Rotate a log file using numbered suffixes: log.json → log.json.1 → log.json.2 etc.
 * Oldest files beyond maxFiles are deleted.
 *
 * @param filePath - The active log file path
 * @param maxFiles - Maximum number of rotated files to keep
 */
function rotateLogFile(filePath: string, maxFiles: number): void {
  try {
    // Delete the oldest file if it would exceed maxFiles
    const oldest = `${filePath}.${maxFiles}`;
    if (existsSync(oldest)) {
      unlinkSync(oldest);
    }

    // Shift existing rotated files: .4 → .5, .3 → .4, etc.
    for (let i = maxFiles - 1; i >= 1; i--) {
      const src = `${filePath}.${i}`;
      const dst = `${filePath}.${i + 1}`;
      if (existsSync(src)) {
        renameSync(src, dst);
      }
    }

    // Move the current log file to .1
    if (existsSync(filePath)) {
      renameSync(filePath, `${filePath}.1`);
    }
  } catch {
    // Best-effort rotation — don't crash the server if rotation fails
    process.stderr.write(`[logger] WARNING: Log rotation failed for ${filePath}\n`);
  }
}

// ── Logger Class ─────────────────────────────────────────────────────────────

/**
 * Structured logger that outputs JSON to stderr.
 *
 * Uses stderr so log output doesn't interfere with MCP protocol messages
 * on stdout (StdioServerTransport).
 *
 * Optionally writes to a file with automatic size-based rotation when
 * DEFENSE_MCP_LOG_FILE is set.
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
  private logFile: string | null;
  private maxFileSize: number;
  private maxFiles: number;

  constructor(minLevel?: LogLevel) {
    this.minLevel = minLevel ?? this.parseEnvLevel();
    this.logFile = process.env.DEFENSE_MCP_LOG_FILE || null;
    this.maxFileSize = parseInt(process.env.DEFENSE_MCP_LOG_MAX_SIZE || "", 10) || DEFAULT_MAX_SIZE;
    this.maxFiles = parseInt(process.env.DEFENSE_MCP_LOG_MAX_FILES || "", 10) || DEFAULT_MAX_FILES;

    // Ensure log directory exists if file logging is enabled
    if (this.logFile) {
      try {
        const dir = dirname(this.logFile);
        mkdirSync(dir, { recursive: true });
      } catch {
        // Fall back to stderr-only if directory creation fails
        process.stderr.write(`[logger] WARNING: Cannot create log directory for ${this.logFile}, falling back to stderr-only\n`);
        this.logFile = null;
      }
    }
  }

  /**
   * Read the minimum log level from `DEFENSE_MCP_LOG_LEVEL` env var.
   * Falls back to `"info"` if unset or invalid.
   */
  private parseEnvLevel(): LogLevel {
    const raw = process.env.DEFENSE_MCP_LOG_LEVEL?.toLowerCase();
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
   * Write a log line to the file, with size-based rotation.
   * This is best-effort — file write failures don't throw.
   */
  private writeToFile(line: string): void {
    if (!this.logFile) return;

    try {
      // Attempt rotation first, then append — both are best-effort.
      // The append itself is atomic enough for structured log lines.
      try {
        const stats = statSync(this.logFile);
        if (stats.size >= this.maxFileSize) {
          rotateLogFile(this.logFile, this.maxFiles);
        }
      } catch {
        // File may not exist yet — appendFileSync will create it
      }

      appendFileSync(this.logFile, line, { encoding: "utf-8", mode: 0o600 });
    } catch {
      // Best-effort — don't crash the server on write failure
    }
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
    const line = JSON.stringify(entry) + "\n";
    process.stderr.write(line);

    // Also write to file if configured (with rotation)
    this.writeToFile(line);
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
