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
import { statSync, lstatSync, readFileSync } from "node:fs";
import { logger } from "./logger.js";

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
    /**
     * Machine-readable flag that instructs the AI client to STOP its
     * current workflow and ask the user for credentials before proceeding.
     * The AI MUST NOT silently skip the tool or continue without elevation.
     */
    haltWorkflow: true;
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
   * Check whether passwordless sudo (`NOPASSWD: ALL`) is still active.
   *
   * Reads `/etc/sudoers` and `/etc/sudoers.d/mcpuser` (non-root readable
   * paths only) and searches for the `NOPASSWD:.*ALL` pattern. If found,
   * logs a CRITICAL security warning — the credential validation in
   * `SudoSession.elevate()` is hollow while this grant exists.
   *
   * This check is intended to be called during server startup so operators
   * are alerted immediately if the Docker image was not rebuilt correctly.
   *
   * @returns `{ nopasswdDetected: boolean, location?: string }`
   */
  static checkNopasswdConfiguration(): { nopasswdDetected: boolean; location?: string } {
    const candidatePaths = [
      "/etc/sudoers",
      "/etc/sudoers.d/mcpuser",
      "/etc/sudoers.d/",
    ];

    const nopasswdPattern = /NOPASSWD\s*:\s*ALL/i;

    for (const filePath of candidatePaths) {
      try {
        const content = readFileSync(filePath, "utf-8");
        if (nopasswdPattern.test(content)) {
          logger.security(
            "sudo-guard",
            "nopasswd_detected",
            "SECURITY CRITICAL: NOPASSWD:ALL detected in sudoers configuration. " +
            "Authentication via sudo_elevate is NON-FUNCTIONAL — any password will be accepted. " +
            "Remove NOPASSWD from the sudoers file and set a real password for the user. " +
            "See docs/SUDO-SESSION-DESIGN.md for remediation steps.",
            {
              severity: "CRITICAL",
              location: filePath,
              remediation:
                "Update the sudoers configuration to use a scoped allowlist " +
                "with no NOPASSWD. See docs/SUDO-SESSION-DESIGN.md for details.",
            }
          );
          return { nopasswdDetected: true, location: filePath };
        }
      } catch {
        // File may not exist or may not be readable — that's fine
      }
    }

    logger.info(
      "sudo-guard",
      "nopasswd_check_passed",
      "Sudoers NOPASSWD:ALL check passed — passwordless sudo not detected"
    );
    return { nopasswdDetected: false };
  }

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

    // Build the prompt message for AI clients.
    const lines: string[] = [];
    lines.push("🔒 Sudo session required");
    lines.push("─".repeat(50));
    lines.push("");
    lines.push(`Tool: ${toolName}`);
    lines.push(`Reason: ${reasonText}`);
    lines.push("");

    if (status.elevated && status.remainingSeconds !== null && status.remainingSeconds <= 0) {
      lines.push("⚠️  Your sudo session has expired.");
      lines.push("");
      lines.push("ACTION: Call sudo_session with action=elevate_gui to re-authenticate,");
      lines.push("or action=extend to extend an active session.");
    } else {
      lines.push("ACTION: Call sudo_session with action=elevate_gui to authenticate.");
      lines.push("Once elevated, ALL privileged tools will work automatically");
      lines.push("for the session duration.");
    }
    lines.push("");
    lines.push("Security: Password is entered via a secure GUI dialog (zenity),");
    lines.push("stored in a zeroable memory buffer, and never visible to the AI.");

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
        haltWorkflow: true,
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

  /**
   * SECURITY (CORE-006): Validate the SUDO_ASKPASS environment variable.
   *
   * Before trusting the SUDO_ASKPASS path, verify:
   * 1. The file exists and is a regular file (not a symlink)
   * 2. Ownership is root or the current user
   * 3. Permissions are restrictive (0o700 or 0o500 — no world/group access)
   *
   * @returns `{ valid: true }` if safe, or `{ valid: false, reason: string }` if not
   */
  static validateAskpass(): { valid: boolean; reason?: string } {
    const askpassPath = process.env.SUDO_ASKPASS;

    if (!askpassPath) {
      return { valid: true }; // Not set — nothing to validate
    }

    return SudoGuard.validateAskpassPath(askpassPath);
  }

  /**
   * SECURITY (CORE-016): Validate an askpass helper path.
   *
   * Before trusting any askpass candidate, verify:
   * 1. The file exists and is a regular file (not a symlink)
   * 2. Ownership is root or the current user
   * 3. Permissions are restrictive (no group/world access)
   *
   * @param askpassPath Absolute path to the askpass candidate
   * @returns `{ valid: true }` if safe, or `{ valid: false, reason: string }` if not
   */
  static validateAskpassPath(askpassPath: string): { valid: boolean; reason?: string } {
    try {
      // 1. Check with lstat (does NOT follow symlinks)
      const lstats = lstatSync(askpassPath);

      if (lstats.isSymbolicLink()) {
        return {
          valid: false,
          reason: `Askpass path '${askpassPath}' is a symlink. Refusing to trust it.`,
        };
      }

      if (!lstats.isFile()) {
        return {
          valid: false,
          reason: `Askpass path '${askpassPath}' is not a regular file.`,
        };
      }

      // 2. Verify ownership: must be root (uid 0) or the current user
      const currentUid = process.getuid?.() ?? -1;
      if (lstats.uid !== 0 && lstats.uid !== currentUid) {
        return {
          valid: false,
          reason: `Askpass '${askpassPath}' is owned by uid ${lstats.uid}, expected root (0) or current user (${currentUid}).`,
        };
      }

      // 3. Verify permissions: no group or world access (must be 0o700 or 0o500)
      // Extract the permission bits (lower 9 bits of mode)
      const perms = lstats.mode & 0o777;
      const groupWorldBits = perms & 0o077;
      if (groupWorldBits !== 0) {
        return {
          valid: false,
          reason: `Askpass '${askpassPath}' has overly permissive mode 0o${perms.toString(8)}. ` +
            `Expected no group/world access (e.g., 0700 or 0500).`,
        };
      }

      return { valid: true };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        valid: false,
        reason: `Failed to verify askpass '${askpassPath}': ${msg}`,
      };
    }
  }
}
