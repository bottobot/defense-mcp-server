/**
 * SudoGuard — Central module for detecting permission failures and generating
 * structured elevation prompts that instruct the AI client to ask the user
 * for their sudo password.
 *
 * This module ensures that no MCP tool ever silently fails due to missing
 * sudo privileges. Instead, failures are intercepted and converted into
 * clear, actionable elevation prompts.
 *
 * ## Three Interception Layers
 *
 * 1. **Pre-flight** (tool-wrapper.ts): Tools with `sudo: "always"` are blocked
 *    before execution if no session is active. SudoGuard generates the prompt.
 *
 * 2. **Executor** (executor.ts): After command execution, the `permissionDenied`
 *    flag on {@link CommandResult} is set when stderr/exit code match known
 *    permission-denied patterns.
 *
 * 3. **Post-execution** (tool-wrapper.ts): If a tool handler's response
 *    indicates a permission error (detected via output text analysis),
 *    SudoGuard wraps it with an elevation prompt.
 *
 * ## Usage
 *
 * ```typescript
 * import { SudoGuard } from './sudo-guard.js';
 *
 * // Check if command output indicates permission denied
 * if (SudoGuard.isPermissionError(result.stderr, result.exitCode)) {
 *   return SudoGuard.createElevationPrompt('firewall_iptables_add');
 * }
 * ```
 *
 * @module sudo-guard
 */

import { SudoSession } from "./sudo-session.js";

// ── Permission Error Detection ───────────────────────────────────────────────

/**
 * Patterns in stderr/stdout that indicate a permission/privilege failure.
 * These are matched case-insensitively against combined output.
 *
 * Covers sudo, polkit, systemd, Docker, iptables, and general POSIX errors.
 */
const PERMISSION_ERROR_PATTERNS: RegExp[] = [
  // sudo-specific
  /sudo[:\s].*password/i,
  /sudo[:\s].*required/i,
  /a password is required/i,
  /sorry,?\s+try again/i,
  /\bsudo\b.*\bnot allowed\b/i,
  /no password.*and.*not.*(sudoers|allowed)/i,

  // General POSIX permission errors
  /permission denied/i,
  /operation not permitted/i,
  /EACCES/,
  /EPERM/,
  /access denied/i,

  // Specific binary errors
  /must be run as root/i,
  /must be root/i,
  /requires? root/i,
  /requires? superuser/i,
  /run.*as.*root/i,
  /need to be root/i,
  /insufficient privileges?/i,
  /not enough privileges?/i,
  /only root can/i,
  /you must be root/i,

  // iptables / nftables
  /can't initialize iptables/i,
  /iptables.*Permission denied/i,
  /nft.*Operation not permitted/i,

  // systemd / service management
  /polkit.*authorization/i,
  /interactive authentication required/i,
  /access denied by.*policy/i,
  /not privileged/i,

  // Docker
  /docker.*permission denied/i,
  /connect: permission denied/i,
  /dial.*permission denied/i,

  // Package management
  /are you root\?/i,
  /unable to lock/i,
  /could not get lock/i,

  // auditd
  /audit.*permission/i,

  // File system
  /cannot open.*permission denied/i,
  /cannot write.*permission denied/i,
  /read-only file system/i,
];

/**
 * Exit codes that commonly indicate permission failures.
 * Note: exit code alone is not sufficient — must be combined with pattern
 * matching for reliable detection.
 */
const PERMISSION_EXIT_CODES = new Set<number>([
  1,   // General error (common for sudo failures)
  126, // Command invoked cannot execute (permission issue)
  4,   // iptables: resource problem (often permission)
  77,  // BSD/systemd: noperm
]);

// ── Types ────────────────────────────────────────────────────────────────────

/**
 * Structured MCP response content for an elevation prompt.
 * Returned when a tool cannot proceed without sudo privileges.
 */
export interface ElevationPromptResponse {
  content: Array<{ type: "text"; text: string }>;
  isError: true;
  _meta: {
    /** Machine-readable tag for client-side detection */
    elevationRequired: true;
    /** The tool that failed */
    failedTool: string;
    /** Why elevation is needed */
    reason: string;
    /** The tool to call for elevation */
    elevationTool: "sudo_elevate";
  };
}

// ── SudoGuard ────────────────────────────────────────────────────────────────

/**
 * Static utility class for permission error detection and elevation prompt
 * generation. All methods are stateless and can be called directly.
 */
export class SudoGuard {
  /**
   * Check whether command output (stderr and/or stdout) indicates a
   * permission/privilege failure.
   *
   * Uses a combination of pattern matching against known error messages
   * and exit code analysis. Pattern matching alone is authoritative —
   * exit codes are used as supporting evidence only.
   *
   * @param output  Combined stderr + stdout text to analyze
   * @param exitCode  The process exit code (optional, for confidence)
   * @returns `true` if the output indicates a permission error
   */
  static isPermissionError(output: string, exitCode?: number): boolean {
    if (!output || output.length === 0) {
      return false;
    }

    // Check patterns against combined output
    for (const pattern of PERMISSION_ERROR_PATTERNS) {
      if (pattern.test(output)) {
        return true;
      }
    }

    // Exit code alone is not sufficient (too many false positives),
    // but exit code 126 is very specific to permission issues
    if (exitCode === 126) {
      return true;
    }

    return false;
  }

  /**
   * Create a structured MCP elevation prompt response.
   *
   * The response includes:
   * - A clear human-readable message explaining what happened
   * - Instructions to call `sudo_elevate` with the user's password
   * - Machine-readable `_meta` for client-side automation
   *
   * @param toolName  The tool that requires elevation
   * @param reason    Optional specific reason (from manifest or error output)
   * @param originalError  The original error message to include for context
   */
  static createElevationPrompt(
    toolName: string,
    reason?: string,
    originalError?: string,
  ): ElevationPromptResponse {
    const session = SudoSession.getInstance();
    const status = session.getStatus();

    const reasonText = reason ?? "This tool requires elevated (root) privileges to function.";

    // Build the prompt message
    const lines: string[] = [];
    lines.push("🔒 ELEVATED PRIVILEGES REQUIRED");
    lines.push("═".repeat(50));
    lines.push("");
    lines.push(`Tool: ${toolName}`);
    lines.push(`Reason: ${reasonText}`);
    lines.push("");

    if (status.elevated && status.remainingSeconds !== null && status.remainingSeconds <= 0) {
      // Session expired
      lines.push("⚠️  Your sudo session has expired.");
      lines.push("");
    }

    lines.push("ACTION REQUIRED:");
    lines.push("─".repeat(50));
    lines.push("");
    lines.push("Please provide your sudo password by calling:");
    lines.push("");
    lines.push("  Tool: sudo_elevate");
    lines.push("  Parameter: password = <your sudo password>");
    lines.push("");
    lines.push("Once elevated, all privileged tools (including this one)");
    lines.push("will work automatically for the session duration.");
    lines.push("");
    lines.push("The password is:");
    lines.push("  • Stored securely in a zeroable memory buffer");
    lines.push("  • Never logged or exposed in any output");
    lines.push("  • Auto-expires after the configured timeout (default: 15 min)");
    lines.push("  • Can be dropped at any time with sudo_drop");

    if (originalError) {
      lines.push("");
      lines.push("─".repeat(50));
      lines.push("Original error:");
      lines.push(originalError.substring(0, 500));
    }

    return {
      content: [
        {
          type: "text" as const,
          text: lines.join("\n"),
        },
      ],
      isError: true,
      _meta: {
        elevationRequired: true,
        failedTool: toolName,
        reason: reasonText,
        elevationTool: "sudo_elevate",
      },
    };
  }

  /**
   * Check if a tool handler's MCP response content indicates a permission
   * error that occurred at runtime (after pre-flight passed).
   *
   * This catches `conditional` sudo tools and tools where the pre-flight
   * check passed but the actual command still failed due to permissions.
   *
   * Examines the `content` array of the tool's response for text content
   * matching permission error patterns.
   */
  static isResponsePermissionError(
    response: Record<string, unknown> | undefined,
  ): boolean {
    if (!response) return false;

    // Only check error responses
    if (!response.isError) return false;

    const content = response.content;
    if (!Array.isArray(content)) return false;

    for (const item of content) {
      if (
        typeof item === "object" &&
        item !== null &&
        "type" in item &&
        (item as Record<string, unknown>).type === "text" &&
        "text" in item &&
        typeof (item as Record<string, unknown>).text === "string"
      ) {
        const text = (item as Record<string, unknown>).text as string;
        if (SudoGuard.isPermissionError(text)) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Extract the first text content string from an MCP response.
   * Used to pass original error context to the elevation prompt.
   */
  static extractResponseText(
    response: Record<string, unknown> | undefined,
  ): string | undefined {
    if (!response) return undefined;
    const content = response.content;
    if (!Array.isArray(content)) return undefined;

    for (const item of content) {
      if (
        typeof item === "object" &&
        item !== null &&
        "type" in item &&
        (item as Record<string, unknown>).type === "text" &&
        "text" in item
      ) {
        return (item as Record<string, unknown>).text as string;
      }
    }

    return undefined;
  }

  /**
   * Check if the current process has an active sudo session that can
   * be used for privileged operations.
   */
  static hasActiveSession(): boolean {
    return SudoSession.getInstance().isElevated();
  }
}
