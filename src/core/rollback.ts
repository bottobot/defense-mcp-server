/**
 * RollbackManager — singleton that tracks system changes and provides
 * rollback capability for file, sysctl, service, and firewall modifications.
 */

import { existsSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { homedir } from "node:os";
import { secureWriteFileSync, secureMkdirSync, secureCopyFileSync } from "./secure-fs.js";
import { randomUUID } from "node:crypto";
import { executeCommand } from "./executor.js";
import { isAllowlisted } from "./command-allowlist.js";

// ── Validation Constants ─────────────────────────────────────────────────────

/** Control characters regex — matches dangerous non-printable characters */
const CONTROL_CHAR_RE = /[\x00-\x08\x0e-\x1f\x7f]/;

/**
 * Safe pattern for service names (systemd unit names).
 * Allows alphanumeric, @, dots, underscores, hyphens, colons.
 */
const SAFE_SERVICE_NAME_RE = /^[a-zA-Z0-9@._:-]+$/;

/**
 * Allowed commands for firewall rollback.
 * Only specific firewall binaries are permitted — never shell interpreters.
 * This is defense-in-depth on top of the general command allowlist.
 */
const ALLOWED_FIREWALL_COMMANDS = new Set([
  "iptables", "ip6tables", "iptables-restore", "ip6tables-restore",
  "iptables-save", "ip6tables-save", "nft", "ufw", "netfilter-persistent",
]);

/**
 * Validate a rollback argument for injection safety.
 * Rejects null bytes, control characters, and excessively long values.
 *
 * @param arg The argument string to validate
 * @param index The argument index (for error messages)
 * @param label Human-readable label (e.g., "Firewall rollback")
 * @throws {Error} If validation fails
 */
function validateRollbackArg(arg: string, index: number, label: string): void {
  if (typeof arg !== "string") {
    throw new Error(`[rollback] ${label} argument at index ${index} is not a string`);
  }
  if (arg.length > 512) {
    throw new Error(
      `[rollback] ${label} argument at index ${index} is too long (${arg.length} chars, max 512)`
    );
  }
  if (arg.includes("\0")) {
    throw new Error(`[rollback] ${label} argument at index ${index} contains null bytes`);
  }
  if (CONTROL_CHAR_RE.test(arg)) {
    throw new Error(
      `[rollback] ${label} argument at index ${index} contains control characters`
    );
  }
}

/**
 * Validate that a command is a recognized firewall tool.
 * Extracts the bare binary name from an absolute path if needed.
 *
 * @param command The command (bare name or absolute path)
 * @throws {Error} If the command is not a recognized firewall tool
 */
function validateFirewallCommand(command: string): void {
  const bareCommand = command.startsWith("/")
    ? (command.split("/").pop() ?? command)
    : command;
  if (!ALLOWED_FIREWALL_COMMANDS.has(bareCommand)) {
    throw new Error(
      `[rollback] '${command}' is not a recognized firewall command for rollback`
    );
  }
}

// ── Types ────────────────────────────────────────────────────────────────────

export type ChangeType = "file" | "sysctl" | "service" | "firewall";

/**
 * Structured rollback command — stores the command and args as separate fields
 * to avoid reconstructing them from a string (which is an injection risk).
 */
export interface RollbackCommand {
  command: string;
  args: string[];
}

export interface ChangeRecord {
  id: string;
  operationId: string;
  sessionId: string;
  type: ChangeType;
  target: string;
  originalValue: string;
  timestamp: string;
  rolledBack: boolean;
  /** Optional reference to a changelog entry ID for cross-referencing */
  changelogRef?: string;
  /**
   * Structured rollback command for firewall-type changes.
   * Preferred over parsing originalValue via string splitting.
   * When present, this is used instead of originalValue for rollback execution.
   */
  rollbackCommand?: RollbackCommand;
}

/**
 * Versioned rollback state file format.
 * Old files stored a bare array; new files use this envelope.
 */
export interface RollbackState {
  version: 1;
  changes: ChangeRecord[];
}

// ── RollbackManager ──────────────────────────────────────────────────────────

export class RollbackManager {
  private static instance: RollbackManager | null = null;
  private readonly storePath: string;
  private readonly sessionId: string;
  private changes: ChangeRecord[] = [];

  private constructor() {
    this.sessionId = randomUUID();
    const storeDir = join(homedir(), ".defense-mcp");
    this.storePath = join(storeDir, "rollback-state.json");

    // Load existing state (with migration from old bare-array format)
    try {
      if (existsSync(this.storePath)) {
        const raw = readFileSync(this.storePath, "utf-8");
        const parsed = JSON.parse(raw);
        // Handle old format (bare array)
        if (Array.isArray(parsed)) {
          this.changes = parsed;
        }
        // Handle versioned format
        else if (parsed && typeof parsed === "object" && Array.isArray(parsed.changes)) {
          this.changes = parsed.changes;
        }
      }
    } catch {
      this.changes = [];
    }
  }

  /** Get the singleton instance. */
  static getInstance(): RollbackManager {
    if (!RollbackManager.instance) {
      RollbackManager.instance = new RollbackManager();
    }
    return RollbackManager.instance;
  }

  /** Persist state to disk in versioned format. */
  private save(): void {
    try {
      const state: RollbackState = {
        version: 1,
        changes: this.changes,
      };
      secureWriteFileSync(this.storePath, JSON.stringify(state, null, 2), "utf-8");
    } catch (err) {
      console.error(`[rollback] Failed to save state: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  /**
   * Track a change for later rollback.
   * @param changelogRef Optional reference to a changelog entry ID
   * @param rollbackCmd Optional structured rollback command (preferred for firewall changes)
   */
  trackChange(
    operationId: string,
    type: ChangeType,
    target: string,
    originalValue: string,
    changelogRef?: string,
    rollbackCmd?: RollbackCommand
  ): void {
    const record: ChangeRecord = {
      id: randomUUID(),
      operationId,
      sessionId: this.sessionId,
      type,
      target,
      originalValue,
      timestamp: new Date().toISOString(),
      rolledBack: false,
      ...(changelogRef !== undefined ? { changelogRef } : {}),
      ...(rollbackCmd !== undefined ? { rollbackCommand: rollbackCmd } : {}),
    };

    this.changes.push(record);
    this.save();
    console.error(`[rollback] Tracked ${type} change on ${target} (op: ${operationId})`);
  }

  /**
   * Rollback a single operation by its operation ID.
   */
  async rollback(operationId: string): Promise<void> {
    const records = this.changes.filter(
      (c) => c.operationId === operationId && !c.rolledBack
    );

    if (records.length === 0) {
      throw new Error(`No pending changes found for operation: ${operationId}`);
    }

    // Rollback in reverse order
    for (const record of records.reverse()) {
      await this.rollbackRecord(record);
    }

    this.save();
  }

  /**
   * Rollback all changes from the current session.
   */
  async rollbackSession(sessionId: string): Promise<void> {
    const records = this.changes.filter(
      (c) => c.sessionId === sessionId && !c.rolledBack
    );

    if (records.length === 0) {
      throw new Error(`No pending changes found for session: ${sessionId}`);
    }

    for (const record of records.reverse()) {
      await this.rollbackRecord(record);
    }

    this.save();
  }

  /**
   * List all tracked changes.
   */
  listChanges(): ChangeRecord[] {
    return [...this.changes].sort(
      (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );
  }

  /** Get the current session ID. */
  getSessionId(): string {
    return this.sessionId;
  }

  /** Rollback a single change record. */
  private async rollbackRecord(record: ChangeRecord): Promise<void> {
    try {
      switch (record.type) {
        case "file": {
          // originalValue is the backup path
          if (existsSync(record.originalValue)) {
            secureMkdirSync(dirname(record.target));
            secureCopyFileSync(record.originalValue, record.target);
          } else {
            console.error(`[rollback] Backup file missing: ${record.originalValue}`);
          }
          break;
        }

        case "sysctl": {
          // Validate that sysctl is in the allowlist before executing
          if (!isAllowlisted("sysctl")) {
            throw new Error("[rollback] sysctl is not in the command allowlist — refusing to execute");
          }
          // Validate sysctl key: must be dotted identifiers (e.g. net.ipv4.ip_forward)
          if (!/^[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+)+$/.test(record.target)) {
            throw new Error(`[rollback] Invalid sysctl key: ${record.target}`);
          }
          // Validate sysctl value: must not contain shell metacharacters
          if (/[;&|`$(){}[\]\\<>!#~]/.test(record.originalValue)) {
            throw new Error(`[rollback] Invalid sysctl value (contains shell metacharacters): ${record.originalValue}`);
          }
          await executeCommand({
            toolName: "_internal",
            command: "sysctl",
            args: ["-w", `${record.target}=${record.originalValue}`],
            timeout: 10000,
          });
          break;
        }

        case "service": {
          // Validate service name against safe pattern
          if (!SAFE_SERVICE_NAME_RE.test(record.target)) {
            throw new Error(`[rollback] Invalid service name: ${record.target}`);
          }
          // originalValue is the previous state (e.g., "active", "inactive")
          const action = record.originalValue === "active" ? "start" : "stop";
          await executeCommand({
            toolName: "_internal",
            command: "systemctl",
            args: [action, record.target],
            timeout: 30000,
          });
          break;
        }

        case "firewall": {
          // Prefer structured rollbackCommand if available (CORE-003 remediation)
          if (record.rollbackCommand) {
            const { command, args } = record.rollbackCommand;
            // Validate command is in the general allowlist
            if (!isAllowlisted(command)) {
              throw new Error(
                `[rollback] Firewall rollback command '${command}' is not in the command allowlist — refusing to execute`
              );
            }
            // Defense-in-depth: only allow known firewall commands
            validateFirewallCommand(command);
            // Validate each argument for injection safety
            for (let i = 0; i < args.length; i++) {
              validateRollbackArg(args[i], i, "Firewall rollback");
            }
            await executeCommand({
              toolName: "_internal",
              command,
              args,
              timeout: 10000,
            });
          } else {
            // Legacy fallback: reconstruct from originalValue string splitting
            // Validate the command against the allowlist before executing
            const parts = record.originalValue.split(/\s+/).filter(Boolean);
            if (parts.length < 2) {
              throw new Error(`[rollback] Firewall rollback command too short: '${record.originalValue}'`);
            }
            const command = parts[0];
            if (!isAllowlisted(command)) {
              throw new Error(
                `[rollback] Firewall rollback command '${command}' is not in the command allowlist — refusing to execute`
              );
            }
            // Defense-in-depth: only allow known firewall commands
            validateFirewallCommand(command);
            // Validate each argument for injection safety
            const args = parts.slice(1);
            for (let i = 0; i < args.length; i++) {
              validateRollbackArg(args[i], i, "Firewall rollback (legacy)");
            }
            await executeCommand({
              toolName: "_internal",
              command,
              args,
              timeout: 10000,
            });
          }
          break;
        }
      }

      record.rolledBack = true;
      console.error(`[rollback] Rolled back ${record.type} change on ${record.target}`);
    } catch (err) {
      console.error(`[rollback] Failed to rollback ${record.type} on ${record.target}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
}
