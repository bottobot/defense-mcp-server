/**
 * RollbackManager — singleton that tracks system changes and provides
 * rollback capability for file, sysctl, service, and firewall modifications.
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync, copyFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { homedir } from "node:os";
import { randomUUID } from "node:crypto";
import { executeCommand } from "./executor.js";

// ── Types ────────────────────────────────────────────────────────────────────

export type ChangeType = "file" | "sysctl" | "service" | "firewall";

export interface ChangeRecord {
  id: string;
  operationId: string;
  sessionId: string;
  type: ChangeType;
  target: string;
  originalValue: string;
  timestamp: string;
  rolledBack: boolean;
}

// ── RollbackManager ──────────────────────────────────────────────────────────

export class RollbackManager {
  private static instance: RollbackManager | null = null;
  private readonly storePath: string;
  private readonly sessionId: string;
  private changes: ChangeRecord[] = [];

  private constructor() {
    this.sessionId = randomUUID();
    const storeDir = join(homedir(), ".kali-defense");
    this.storePath = join(storeDir, "rollback-state.json");

    // Load existing state
    try {
      if (existsSync(this.storePath)) {
        const raw = readFileSync(this.storePath, "utf-8");
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) {
          this.changes = parsed;
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

  /** Persist state to disk. */
  private save(): void {
    try {
      const dir = dirname(this.storePath);
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
      }
      writeFileSync(this.storePath, JSON.stringify(this.changes, null, 2), "utf-8");
    } catch (err) {
      console.error(`[rollback] Failed to save state: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  /**
   * Track a change for later rollback.
   */
  trackChange(
    operationId: string,
    type: ChangeType,
    target: string,
    originalValue: string
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
            const targetDir = dirname(record.target);
            if (!existsSync(targetDir)) {
              mkdirSync(targetDir, { recursive: true });
            }
            copyFileSync(record.originalValue, record.target);
          } else {
            console.error(`[rollback] Backup file missing: ${record.originalValue}`);
          }
          break;
        }

        case "sysctl": {
          await executeCommand({
            command: "sysctl",
            args: ["-w", `${record.target}=${record.originalValue}`],
            timeout: 10000,
          });
          break;
        }

        case "service": {
          // originalValue is the previous state (e.g., "active", "inactive")
          const action = record.originalValue === "active" ? "start" : "stop";
          await executeCommand({
            command: "systemctl",
            args: [action, record.target],
            timeout: 30000,
          });
          break;
        }

        case "firewall": {
          // originalValue is the rollback command (e.g., "iptables -D INPUT ...")
          const parts = record.originalValue.split(/\s+/);
          if (parts.length >= 2) {
            await executeCommand({
              command: parts[0],
              args: parts.slice(1),
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
