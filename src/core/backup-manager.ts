/**
 * BackupManager — manages file backups with manifest tracking.
 *
 * Backups are stored under ~/.kali-mcp-backups/ with timestamped filenames.
 * A manifest.json tracks all backups for listing and restore operations.
 */

import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  unlinkSync,
  readdirSync,
  statSync,
} from "node:fs";
import { join, basename, dirname } from "node:path";
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

interface BackupManifest {
  backups: BackupEntry[];
}

// ── Zod validators ───────────────────────────────────────────────────────────

const FilePathSchema = z.string().min(1).max(4096);
const BackupIdSchema = z.string().uuid();
const DaysOldSchema = z.number().int().min(1).max(3650);

// ── BackupManager ────────────────────────────────────────────────────────────

export class BackupManager {
  private readonly backupDir: string;
  private readonly manifestPath: string;

  constructor(backupDir?: string) {
    this.backupDir = backupDir ?? join(homedir(), ".kali-mcp-backups");
    this.manifestPath = join(this.backupDir, "manifest.json");
  }

  /** Ensure backup directory exists. */
  private ensureDir(): void {
    if (!existsSync(this.backupDir)) {
      mkdirSync(this.backupDir, { recursive: true });
    }
  }

  /** Read manifest from disk. */
  private readManifest(): BackupManifest {
    try {
      if (existsSync(this.manifestPath)) {
        const raw = readFileSync(this.manifestPath, "utf-8");
        const parsed = JSON.parse(raw);
        if (parsed && Array.isArray(parsed.backups)) {
          return parsed as BackupManifest;
        }
      }
    } catch {
      // Corrupt or missing manifest — start fresh
    }
    return { backups: [] };
  }

  /** Write manifest to disk. */
  private writeManifest(manifest: BackupManifest): void {
    this.ensureDir();
    writeFileSync(this.manifestPath, JSON.stringify(manifest, null, 2), "utf-8");
  }

  /**
   * Create a backup of a file.
   * @returns The backup ID.
   */
  async backup(filePath: string): Promise<string> {
    const validated = FilePathSchema.parse(filePath);
    this.ensureDir();

    if (!existsSync(validated)) {
      throw new Error(`Source file does not exist: ${validated}`);
    }

    const id = randomUUID();
    const now = new Date();
    const ts = now.toISOString().replace(/[:.]/g, "-").replace("T", "_").slice(0, 19);
    const name = basename(validated);
    const backupName = `${ts}_${name}`;
    const backupPath = join(this.backupDir, backupName);

    copyFileSync(validated, backupPath);

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
    return id;
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

    const targetDir = dirname(entry.originalPath);
    if (!existsSync(targetDir)) {
      mkdirSync(targetDir, { recursive: true });
    }

    copyFileSync(entry.backupPath, entry.originalPath);
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
