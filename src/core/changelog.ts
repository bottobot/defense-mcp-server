import { readFileSync, writeFileSync, mkdirSync, copyFileSync } from "node:fs";
import { dirname, join, basename } from "node:path";
import { randomUUID } from "node:crypto";
import { getConfig } from "./config.js";

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
}

/**
 * Creates a new ChangeEntry with auto-generated id and timestamp.
 */
export function createChangeEntry(
  partial: Omit<ChangeEntry, "id" | "timestamp">
): ChangeEntry {
  return {
    id: randomUUID(),
    timestamp: new Date().toISOString(),
    ...partial,
  };
}

/** Maximum number of changelog entries to retain. Older entries beyond this
 *  limit are discarded during writes to prevent unbounded file growth. */
const MAX_CHANGELOG_ENTRIES = 10_000;

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
    mkdirSync(dir, { recursive: true });

    // Read existing entries
    let entries: ChangeEntry[] = [];
    try {
      const raw = readFileSync(changelogPath, "utf-8");
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        entries = parsed;
      }
    } catch {
      // File doesn't exist or is invalid - start fresh
    }

    // Append new entry
    entries.push(entry);

    // Rotate: keep only the most recent entries to prevent unbounded growth
    if (entries.length > MAX_CHANGELOG_ENTRIES) {
      entries = entries.slice(-MAX_CHANGELOG_ENTRIES);
    }

    // Write back
    writeFileSync(changelogPath, JSON.stringify(entries, null, 2), "utf-8");
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
    const raw = readFileSync(config.changelogPath, "utf-8");
    const parsed = JSON.parse(raw);

    if (!Array.isArray(parsed)) return [];

    // Sort newest first
    const sorted = (parsed as ChangeEntry[]).sort(
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
 * Creates a backup copy of a file in the configured backup directory.
 * The backup filename includes a timestamp prefix for uniqueness.
 *
 * @param filePath Absolute path to the file to back up
 * @returns Path to the backup file
 */
export function backupFile(filePath: string): string {
  const config = getConfig();
  const backupDir = config.backupDir;

  // Ensure backup directory exists
  mkdirSync(backupDir, { recursive: true });

  // Create timestamped backup filename
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const originalName = basename(filePath);
  const backupName = `${timestamp}_${originalName}`;
  const backupPath = join(backupDir, backupName);

  copyFileSync(filePath, backupPath);

  console.error(`[changelog] Backed up ${filePath} → ${backupPath}`);
  return backupPath;
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
  mkdirSync(targetDir, { recursive: true });

  copyFileSync(backupPath, originalPath);

  console.error(
    `[changelog] Restored ${backupPath} → ${originalPath}`
  );
}
