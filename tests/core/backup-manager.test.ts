import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
    mkdtempSync,
    rmSync,
    readFileSync,
    writeFileSync,
    existsSync,
    statSync,
    symlinkSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
    BackupManager,
    validateBackupPath,
    type BackupEntry,
    type BackupManifest,
} from "../../src/core/backup-manager.js";

describe("backup-manager", () => {
    let tempDir: string;
    let backupDir: string;
    let sourceDir: string;

    beforeEach(() => {
        tempDir = mkdtempSync(join(tmpdir(), "kali-backup-test-"));
        backupDir = join(tempDir, "backups");
        sourceDir = join(tempDir, "source");

        // Create the source directory for test files
        const { mkdirSync } = require("node:fs");
        mkdirSync(sourceDir, { recursive: true });
    });

    afterEach(() => {
        rmSync(tempDir, { recursive: true, force: true });
    });

    /** Helper to read the manifest from disk */
    function readManifest(): BackupManifest {
        const manifestPath = join(backupDir, "manifest.json");
        const raw = readFileSync(manifestPath, "utf-8");
        return JSON.parse(raw) as BackupManifest;
    }

    // ── Constructor ──────────────────────────────────────────────────────

    describe("constructor", () => {
        it("should create a BackupManager with custom directory", () => {
            const manager = new BackupManager(backupDir);
            expect(manager).toBeDefined();
        });

        it("should use default directory when none specified", () => {
            const manager = new BackupManager();
            expect(manager).toBeDefined();
        });
    });

    // ── backupSync ───────────────────────────────────────────────────────

    describe("backupSync", () => {
        it("should create a backup copy of a file", () => {
            const srcPath = join(sourceDir, "test.conf");
            writeFileSync(srcPath, "test content");

            const manager = new BackupManager(backupDir);
            const entry = manager.backupSync(srcPath);

            expect(entry).toBeDefined();
            expect(entry.id).toBeTruthy();
            expect(existsSync(entry.backupPath)).toBe(true);

            const backupContent = readFileSync(entry.backupPath, "utf-8");
            expect(backupContent).toBe("test content");
        });

        it("should return a BackupEntry with all required fields", () => {
            const srcPath = join(sourceDir, "fields.conf");
            writeFileSync(srcPath, "content");

            const manager = new BackupManager(backupDir);
            const entry = manager.backupSync(srcPath);

            expect(entry.id).toMatch(
                /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
            );
            expect(entry.originalPath).toBe(srcPath);
            expect(entry.backupPath).toBeTruthy();
            expect(entry.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
            expect(entry.sizeBytes).toBeGreaterThan(0);
        });

        it("should create backup directory if it does not exist", () => {
            const srcPath = join(sourceDir, "autodir.conf");
            writeFileSync(srcPath, "data");

            expect(existsSync(backupDir)).toBe(false);

            const manager = new BackupManager(backupDir);
            manager.backupSync(srcPath);

            expect(existsSync(backupDir)).toBe(true);
        });

        it("should include timestamp in backup filename", () => {
            const srcPath = join(sourceDir, "timestamped.conf");
            writeFileSync(srcPath, "data");

            const manager = new BackupManager(backupDir);
            const entry = manager.backupSync(srcPath);

            const filename = entry.backupPath.split("/").pop()!;
            // Format: YYYY-MM-DDTHH-MM-SS-sssZ_timestamped.conf
            expect(filename).toMatch(/^\d{4}-\d{2}-\d{2}T.*_timestamped\.conf$/);
        });

        it("should write backup file with secure permissions (0o600)", () => {
            const srcPath = join(sourceDir, "secure.conf");
            writeFileSync(srcPath, "sensitive data");

            const manager = new BackupManager(backupDir);
            const entry = manager.backupSync(srcPath);

            const stats = statSync(entry.backupPath);
            expect(stats.mode & 0o777).toBe(0o600);
        });

        it("should throw when source file does not exist", () => {
            const manager = new BackupManager(backupDir);
            expect(() =>
                manager.backupSync("/nonexistent/path/file.conf")
            ).toThrow(/does not exist/i);
        });

        it("should throw on empty file path", () => {
            const manager = new BackupManager(backupDir);
            expect(() => manager.backupSync("")).toThrow();
        });

        it("should handle binary file content correctly", () => {
            const srcPath = join(sourceDir, "binary.dat");
            const binaryData = Buffer.from([0x00, 0x01, 0xff, 0xfe, 0x42, 0x43]);
            writeFileSync(srcPath, binaryData);

            const manager = new BackupManager(backupDir);
            const entry = manager.backupSync(srcPath);

            const backupData = readFileSync(entry.backupPath);
            expect(Buffer.compare(backupData, binaryData)).toBe(0);
        });
    });

    // ── backup (async) ───────────────────────────────────────────────────

    describe("backup", () => {
        it("should return a backup ID string", async () => {
            const srcPath = join(sourceDir, "async.conf");
            writeFileSync(srcPath, "async content");

            const manager = new BackupManager(backupDir);
            const id = await manager.backup(srcPath);

            expect(typeof id).toBe("string");
            expect(id).toMatch(
                /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
            );
        });
    });

    // ── Manifest ─────────────────────────────────────────────────────────

    describe("manifest", () => {
        it("should update manifest on each backup", () => {
            const manager = new BackupManager(backupDir);

            const src1 = join(sourceDir, "file1.conf");
            const src2 = join(sourceDir, "file2.conf");
            writeFileSync(src1, "content1");
            writeFileSync(src2, "content2");

            manager.backupSync(src1);
            manager.backupSync(src2);

            const manifest = readManifest();
            expect(manifest.version).toBe(1);
            expect(manifest.backups.length).toBe(2);
        });

        it("should store versioned manifest format", () => {
            const srcPath = join(sourceDir, "versioned.conf");
            writeFileSync(srcPath, "data");

            const manager = new BackupManager(backupDir);
            manager.backupSync(srcPath);

            const manifest = readManifest();
            expect(manifest.version).toBe(1);
            expect(Array.isArray(manifest.backups)).toBe(true);
        });

        it("should write manifest with secure permissions (0o600)", () => {
            const srcPath = join(sourceDir, "perms.conf");
            writeFileSync(srcPath, "data");

            const manager = new BackupManager(backupDir);
            manager.backupSync(srcPath);

            const manifestPath = join(backupDir, "manifest.json");
            const stats = statSync(manifestPath);
            expect(stats.mode & 0o777).toBe(0o600);
        });

        it("should record originalPath in manifest entry", () => {
            const srcPath = join(sourceDir, "original.conf");
            writeFileSync(srcPath, "original");

            const manager = new BackupManager(backupDir);
            manager.backupSync(srcPath);

            const manifest = readManifest();
            expect(manifest.backups[0].originalPath).toBe(srcPath);
        });

        it("should record sizeBytes in manifest entry", () => {
            const content = "hello world — 123 bytes of content";
            const srcPath = join(sourceDir, "sized.conf");
            writeFileSync(srcPath, content);

            const manager = new BackupManager(backupDir);
            manager.backupSync(srcPath);

            const manifest = readManifest();
            expect(manifest.backups[0].sizeBytes).toBe(Buffer.byteLength(content));
        });
    });

    // ── listBackups ──────────────────────────────────────────────────────

    describe("listBackups", () => {
        it("should return empty array when no backups exist", async () => {
            const manager = new BackupManager(backupDir);
            const list = await manager.listBackups();
            expect(list).toEqual([]);
        });

        it("should return all backup entries", async () => {
            const manager = new BackupManager(backupDir);

            const src1 = join(sourceDir, "list1.conf");
            const src2 = join(sourceDir, "list2.conf");
            writeFileSync(src1, "content1");
            writeFileSync(src2, "content2");

            manager.backupSync(src1);
            manager.backupSync(src2);

            const list = await manager.listBackups();
            expect(list.length).toBe(2);
        });

        it("should return entries sorted newest first", async () => {
            const manager = new BackupManager(backupDir);

            const src1 = join(sourceDir, "sort1.conf");
            writeFileSync(src1, "data1");
            manager.backupSync(src1);

            // Small delay to ensure different timestamps
            await new Promise((resolve) => setTimeout(resolve, 50));

            const src2 = join(sourceDir, "sort2.conf");
            writeFileSync(src2, "data2");
            manager.backupSync(src2);

            const list = await manager.listBackups();
            expect(list.length).toBe(2);
            // Newest first
            const t0 = new Date(list[0].timestamp).getTime();
            const t1 = new Date(list[1].timestamp).getTime();
            expect(t0).toBeGreaterThanOrEqual(t1);
        });
    });

    // ── restore ──────────────────────────────────────────────────────────

    describe("restore", () => {
        it("should restore a backed-up file", async () => {
            const srcPath = join(sourceDir, "restorable.conf");
            writeFileSync(srcPath, "original content");

            const manager = new BackupManager(backupDir);
            const id = await manager.backup(srcPath);

            // Overwrite the original
            writeFileSync(srcPath, "modified content");
            expect(readFileSync(srcPath, "utf-8")).toBe("modified content");

            // Restore
            await manager.restore(id);
            expect(readFileSync(srcPath, "utf-8")).toBe("original content");
        });

        it("should throw for non-existent backup ID", async () => {
            const manager = new BackupManager(backupDir);
            await expect(
                manager.restore("00000000-0000-0000-0000-000000000000")
            ).rejects.toThrow(/not found/i);
        });

        it("should throw for invalid backup ID format", async () => {
            const manager = new BackupManager(backupDir);
            await expect(manager.restore("not-a-uuid")).rejects.toThrow();
        });

        it("should create parent directories during restore", async () => {
            const srcPath = join(sourceDir, "deep", "nested", "restore.conf");
            const { mkdirSync } = require("node:fs");
            mkdirSync(join(sourceDir, "deep", "nested"), { recursive: true });
            writeFileSync(srcPath, "deep content");

            const manager = new BackupManager(backupDir);
            const id = await manager.backup(srcPath);

            // Remove the original and its parent directory
            rmSync(join(sourceDir, "deep"), { recursive: true, force: true });
            expect(existsSync(srcPath)).toBe(false);

            // Restore should recreate directories
            await manager.restore(id);
            expect(readFileSync(srcPath, "utf-8")).toBe("deep content");
        });
    });

    // ── pruneOldBackups ──────────────────────────────────────────────────

    describe("pruneOldBackups", () => {
        it("should remove backups older than specified days", async () => {
            const manager = new BackupManager(backupDir);

            const srcPath = join(sourceDir, "prune.conf");
            writeFileSync(srcPath, "prune me");
            manager.backupSync(srcPath);

            // Manually adjust manifest timestamp to be old
            const manifestPath = join(backupDir, "manifest.json");
            const manifest = JSON.parse(readFileSync(manifestPath, "utf-8"));
            manifest.backups[0].timestamp = "2020-01-01T00:00:00.000Z";
            writeFileSync(manifestPath, JSON.stringify(manifest));

            await manager.pruneOldBackups(1);

            const list = await manager.listBackups();
            expect(list.length).toBe(0);
        });

        it("should keep recent backups", async () => {
            const manager = new BackupManager(backupDir);

            const srcPath = join(sourceDir, "keep.conf");
            writeFileSync(srcPath, "keep me");
            manager.backupSync(srcPath);

            // Don't change timestamp — it's fresh
            await manager.pruneOldBackups(1);

            const list = await manager.listBackups();
            expect(list.length).toBe(1);
        });

        it("should validate days parameter", async () => {
            const manager = new BackupManager(backupDir);
            await expect(manager.pruneOldBackups(0)).rejects.toThrow();
            await expect(manager.pruneOldBackups(-1)).rejects.toThrow();
        });

        it("should delete backup files from disk during prune", async () => {
            const manager = new BackupManager(backupDir);

            const srcPath = join(sourceDir, "delete-disk.conf");
            writeFileSync(srcPath, "delete me from disk");
            const entry = manager.backupSync(srcPath);

            expect(existsSync(entry.backupPath)).toBe(true);

            // Make it old
            const manifestPath = join(backupDir, "manifest.json");
            const manifest = JSON.parse(readFileSync(manifestPath, "utf-8"));
            manifest.backups[0].timestamp = "2020-01-01T00:00:00.000Z";
            writeFileSync(manifestPath, JSON.stringify(manifest));

            await manager.pruneOldBackups(1);

            // File should be deleted from disk
            expect(existsSync(entry.backupPath)).toBe(false);
        });
    });

    // ── CORE-015: validateBackupPath ──────────────────────────────────────

    describe("validateBackupPath (CORE-015)", () => {
        it("should reject paths containing '..' traversal", () => {
            expect(() =>
                validateBackupPath("../etc/shadow", backupDir)
            ).toThrow("SECURITY");
            expect(() =>
                validateBackupPath(`${backupDir}/../etc/shadow`, backupDir)
            ).toThrow("SECURITY");
        });

        it("should reject paths outside base directory", () => {
            expect(() =>
                validateBackupPath("/tmp/outside", backupDir)
            ).toThrow("SECURITY");
        });

        it("should accept paths within base directory", () => {
            const { mkdirSync } = require("node:fs");
            mkdirSync(backupDir, { recursive: true });
            const validPath = join(backupDir, "valid-backup.dat");
            writeFileSync(validPath, "data");

            expect(() => validateBackupPath(validPath, backupDir)).not.toThrow();
        });

        it("should reject symlinks (CORE-015)", () => {
            const { mkdirSync } = require("node:fs");
            mkdirSync(backupDir, { recursive: true });

            const realFile = join(sourceDir, "real.txt");
            writeFileSync(realFile, "real content");

            const symlinkPath = join(backupDir, "symlink-backup");
            symlinkSync(realFile, symlinkPath);

            expect(() => validateBackupPath(symlinkPath, backupDir)).toThrow("SECURITY");
        });

        it("should accept base directory itself", () => {
            const { mkdirSync } = require("node:fs");
            mkdirSync(backupDir, { recursive: true });

            expect(() => validateBackupPath(backupDir, backupDir)).not.toThrow();
        });
    });

    // ── Multiple backups of same file ────────────────────────────────────

    describe("multiple backups", () => {
        it("should create multiple backups of the same file", async () => {
            const manager = new BackupManager(backupDir);
            const srcPath = join(sourceDir, "multi.conf");
            writeFileSync(srcPath, "version1");
            const entry1 = manager.backupSync(srcPath);

            // Small delay to ensure different timestamps in backup filenames
            await new Promise((resolve) => setTimeout(resolve, 50));

            writeFileSync(srcPath, "version2");
            const entry2 = manager.backupSync(srcPath);

            expect(entry1.id).not.toBe(entry2.id);
            // Backup paths may be the same if within same millisecond
            // but IDs must differ
            const manifest = readManifest();
            expect(manifest.backups.length).toBe(2);
        });
    });

    // ── Corrupt manifest recovery ────────────────────────────────────────

    describe("corrupt manifest recovery", () => {
        it("should handle corrupt manifest JSON gracefully", () => {
            const { mkdirSync } = require("node:fs");
            mkdirSync(backupDir, { recursive: true });
            const manifestPath = join(backupDir, "manifest.json");
            writeFileSync(manifestPath, "{invalid json");

            const manager = new BackupManager(backupDir);
            const srcPath = join(sourceDir, "recovery.conf");
            writeFileSync(srcPath, "data");

            // Should not throw — starts fresh
            expect(() => manager.backupSync(srcPath)).not.toThrow();
        });
    });
});
