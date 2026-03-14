import { readFileSync } from "node:fs";
import { dirname, join, basename } from "node:path";
import { userInfo } from "node:os";
import { secureWriteFileSync, secureMkdirSync, secureCopyFileSync } from "./secure-fs.js";
import { randomUUID } from "node:crypto";
import { getConfig } from "./config.js";
import { BackupManager } from "./backup-manager.js";

/**
 * A single changelog entry recording a defensive action taken.
 */
export interface ChangeEntry {
  /** Unique identifier (UUID v4) */
  id: string;
  /** ISO 8601 timestamp */
  timestamp: string;
  /** Tool that performed the action */
  tool: string;
  /** Description of the action */
  action: string;
  /** Target of the action (file, service, etc.) */
  target: string;
  /** State before the change */
  before?: string;
  /** State after the change */
  after?: string;
  /** Path to backup file if one was created */
  backupPath?: string;
  /** Whether this was a dry-run (no actual changes) */
  dryRun: boolean;
  /** Whether the action succeeded */
  success: boolean;
  /** Error message if the action failed */
  error?: string;
  /** Command to undo this change */
  rollbackCommand?: string;
  /** OS username who made the change (auto-populated) */
  user?: string;
  /** MCP session identifier (if available) */
  sessionId?: string;
}

/**
 * Versioned changelog state file format.
 * Old files stored a bare array; new files use this envelope.
 */
export interface ChangelogState {
  version: 1;
  entries: ChangeEntry[];
}

/**
 * Creates a new ChangeEntry with auto-generated id and timestamp.
 */
export function createChangeEntry(
  partial: Omit<ChangeEntry, "id" | "timestamp" | "user">
): ChangeEntry {
  return {
    id: randomUUID(),
    timestamp: new Date().toISOString(),
    user: (() => { try { return userInfo().username; } catch { return undefined; } })(),
    ...partial,
  };
}

/** Maximum number of changelog entries to retain. Older entries beyond this
 *  limit are discarded during writes to prevent unbounded file growth. */
const MAX_CHANGELOG_ENTRIES = 10_000;

/**
 * Load changelog state from disk, migrating old bare-array format if needed.
 */
function loadChangelogState(changelogPath: string): ChangelogState {
  try {
    const raw = readFileSync(changelogPath, "utf-8");
    const parsed = JSON.parse(raw);
    // Handle old format (bare array)
    if (Array.isArray(parsed)) {
      return { version: 1, entries: parsed };
    }
    // Handle versioned format
    if (parsed && typeof parsed === "object" && Array.isArray(parsed.entries)) {
      return { version: 1, entries: parsed.entries };
    }
  } catch {
    // File doesn't exist or is invalid - start fresh
  }
  return { version: 1, entries: [] };
}

/**
 * Appends a change entry to the changelog JSON file.
 * Creates the file and parent directories if they don't exist.
 * Rotates old entries when the file exceeds MAX_CHANGELOG_ENTRIES.
 * Fails silently (logs to stderr) to avoid disrupting tool execution.
 */
export function logChange(entry: ChangeEntry): void {
  try {
    const config = getConfig();
    const changelogPath = config.changelogPath;
    const dir = dirname(changelogPath);

    // Ensure directory exists
    secureMkdirSync(dir);

    // Read existing entries (with migration)
    const state = loadChangelogState(changelogPath);

    // Append new entry
    state.entries.push(entry);

    // Rotate: keep only the most recent entries to prevent unbounded growth
    if (state.entries.length > MAX_CHANGELOG_ENTRIES) {
      state.entries = state.entries.slice(-MAX_CHANGELOG_ENTRIES);
    }

    // Write back in versioned format
    secureWriteFileSync(changelogPath, JSON.stringify(state, null, 2), "utf-8");
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`[changelog] Failed to log change: ${message}`);
  }
}

/**
 * Reads changelog entries, newest first.
 * Returns empty array on any error.
 *
 * @param limit Maximum number of entries to return (default: all)
 */
export function getChangelog(limit?: number): ChangeEntry[] {
  try {
    const config = getConfig();
    const state = loadChangelogState(config.changelogPath);

    // Sort newest first
    const sorted = state.entries.sort(
      (a, b) =>
        new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );

    if (limit !== undefined && limit > 0) {
      return sorted.slice(0, limit);
    }

    return sorted;
  } catch {
    return [];
  }
}

/**
 * Creates a backup copy of a file using the unified BackupManager.
 * The backup is tracked in the manifest at ~/.defense-mcp/backups/manifest.json.
 *
 * @param filePath Absolute path to the file to back up
 * @returns Path to the backup file
 */
export function backupFile(filePath: string): string {
  const config = getConfig();
  const manager = new BackupManager(config.backupDir);
  const entry = manager.backupSync(filePath);
  return entry.backupPath;
}

/**
 * Restores a file from a backup.
 *
 * @param backupPath Path to the backup file
 * @param originalPath Path to restore the file to
 */
export function restoreFile(backupPath: string, originalPath: string): void {
  // Ensure target directory exists
  const targetDir = dirname(originalPath);
  secureMkdirSync(targetDir);

  secureCopyFileSync(backupPath, originalPath);

  console.error(
    `[changelog] Restored ${backupPath} → ${originalPath}`
  );
}
