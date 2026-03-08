/**
 * BackupManager — manages file backups with manifest tracking.
 *
 * Backups are stored under ~/.kali-defense/backups/ with timestamped filenames.
 * A manifest.json tracks all backups for listing and restore operations.
 */

import {
  existsSync,
  readFileSync,
  unlinkSync,
  readdirSync,
  statSync,
  lstatSync,
} from "node:fs";
import { join, basename, dirname, resolve as pathResolve } from "node:path";
import { secureWriteFileSync, secureMkdirSync, secureCopyFileSync } from "./secure-fs.js";
import { homedir } from "node:os";
import { randomUUID } from "node:crypto";
import { z } from "zod";

// ── Types ────────────────────────────────────────────────────────────────────

export interface BackupEntry {
  id: string;
  originalPath: string;
  backupPath: string;
  timestamp: string;
  sizeBytes: number;
}

export interface BackupManifest {
  version: 1;
  backups: BackupEntry[];
}

// ── Zod validators ───────────────────────────────────────────────────────────

const FilePathSchema = z.string().min(1).max(4096);
const BackupIdSchema = z.string().uuid();
const DaysOldSchema = z.number().int().min(1).max(3650);

// ── SECURITY (CORE-015): Path validation helper ──────────────────────────────

/**
 * Validate that a backup path is safe:
 * 1. No `..` traversal sequences
 * 2. Normalized via path.resolve()
 * 3. Resolved path is within the backup base directory
 * 4. Not a symlink (prevent symlink attacks)
 *
 * @param filePath The path to validate
 * @param baseDir The backup base directory that paths must stay within
 * @throws {Error} If the path fails validation
 */
export function validateBackupPath(filePath: string, baseDir: string): void {
  // 1. Reject paths containing '..' traversal sequences
  if (filePath.includes("..")) {
    throw new Error(
      `SECURITY: Backup path contains '..' traversal sequence: ${filePath}`
    );
  }

  // 2. Normalize with path.resolve()
  const resolved = pathResolve(filePath);
  const resolvedBase = pathResolve(baseDir);

  // 3. Verify the resolved path is within the backup base directory
  if (!resolved.startsWith(resolvedBase + "/") && resolved !== resolvedBase) {
    throw new Error(
      `SECURITY: Backup path '${resolved}' escapes base directory '${resolvedBase}'`
    );
  }

  // 4. Reject symlinks (if the path exists)
  if (existsSync(filePath)) {
    try {
      const lstats = lstatSync(filePath);
      if (lstats.isSymbolicLink()) {
        throw new Error(
          `SECURITY: Backup path '${filePath}' is a symlink. Refusing to use.`
        );
      }
    } catch (err: unknown) {
      if (err instanceof Error && err.message.startsWith("SECURITY:")) {
        throw err;
      }
      // lstat failure on existing path is suspicious but non-fatal for validation
    }
  }
}

// ── BackupManager ────────────────────────────────────────────────────────────

export class BackupManager {
  private readonly backupDir: string;
  private readonly manifestPath: string;

  constructor(backupDir?: string) {
    this.backupDir = backupDir ?? join(homedir(), ".kali-defense", "backups");
    this.manifestPath = join(this.backupDir, "manifest.json");
  }

  /** Ensure backup directory exists. */
  private ensureDir(): void {
    secureMkdirSync(this.backupDir);
  }

  /** Read manifest from disk with migration from old format. */
  private readManifest(): BackupManifest {
    try {
      if (existsSync(this.manifestPath)) {
        const raw = readFileSync(this.manifestPath, "utf-8");
        const parsed = JSON.parse(raw);
        if (parsed && Array.isArray(parsed.backups)) {
          // Migrate: ensure version field is present (old format may lack it)
          return { version: 1, backups: parsed.backups };
        }
      }
    } catch {
      // Corrupt or missing manifest — start fresh
    }
    return { version: 1, backups: [] };
  }

  /** Write manifest to disk. */
  private writeManifest(manifest: BackupManifest): void {
    this.ensureDir();
    secureWriteFileSync(this.manifestPath, JSON.stringify(manifest, null, 2), "utf-8");
  }

  /**
   * Create a backup of a file (synchronous).
   * @returns The BackupEntry with id and backupPath.
   */
  backupSync(filePath: string): BackupEntry {
    const validated = FilePathSchema.parse(filePath);
    this.ensureDir();

    if (!existsSync(validated)) {
      throw new Error(`Source file does not exist: ${validated}`);
    }

    const id = randomUUID();
    const now = new Date();
    const ts = now.toISOString().replace(/[:.]/g, "-");
    const name = basename(validated);
    const backupName = `${ts}_${name}`;
    const backupPath = join(this.backupDir, backupName);

    // SECURITY (CORE-015): Validate the backup destination path
    validateBackupPath(backupPath, this.backupDir);

    secureCopyFileSync(validated, backupPath);

    const stat = statSync(backupPath);
    const entry: BackupEntry = {
      id,
      originalPath: validated,
      backupPath,
      timestamp: now.toISOString(),
      sizeBytes: stat.size,
    };

    const manifest = this.readManifest();
    manifest.backups.push(entry);
    this.writeManifest(manifest);

    console.error(`[backup-manager] Backed up ${validated} → ${backupPath} (id: ${id})`);
    return entry;
  }

  /**
   * Create a backup of a file.
   * @returns The backup ID.
   */
  async backup(filePath: string): Promise<string> {
    const entry = this.backupSync(filePath);
    return entry.id;
  }

  /**
   * Restore a file from backup by ID.
   */
  async restore(backupId: string): Promise<void> {
    const validated = BackupIdSchema.parse(backupId);
    const manifest = this.readManifest();
    const entry = manifest.backups.find((b) => b.id === validated);

    if (!entry) {
      throw new Error(`Backup not found: ${validated}`);
    }

    if (!existsSync(entry.backupPath)) {
      throw new Error(`Backup file missing on disk: ${entry.backupPath}`);
    }

    // SECURITY (CORE-015): Validate the backup source path before restore
    validateBackupPath(entry.backupPath, this.backupDir);

    secureMkdirSync(dirname(entry.originalPath));
    secureCopyFileSync(entry.backupPath, entry.originalPath);
    console.error(`[backup-manager] Restored ${entry.backupPath} → ${entry.originalPath}`);
  }

  /**
   * List all backup entries.
   */
  async listBackups(): Promise<BackupEntry[]> {
    const manifest = this.readManifest();
    return manifest.backups.sort(
      (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );
  }

  /**
   * Remove backups older than the specified number of days.
   */
  async pruneOldBackups(daysOld: number): Promise<void> {
    const days = DaysOldSchema.parse(daysOld);
    const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
    const manifest = this.readManifest();

    const keep: BackupEntry[] = [];
    const remove: BackupEntry[] = [];

    for (const entry of manifest.backups) {
      if (new Date(entry.timestamp).getTime() < cutoff) {
        remove.push(entry);
      } else {
        keep.push(entry);
      }
    }

    for (const entry of remove) {
      try {
        if (existsSync(entry.backupPath)) {
          unlinkSync(entry.backupPath);
        }
      } catch (err) {
        console.error(`[backup-manager] Failed to delete ${entry.backupPath}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    manifest.backups = keep;
    this.writeManifest(manifest);

    console.error(`[backup-manager] Pruned ${remove.length} backup(s) older than ${days} day(s)`);
  }
}
