import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync, readFileSync, writeFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
    logChange,
    getChangelog,
    createChangeEntry,
    backupFile,
    type ChangeEntry,
    type ChangelogState,
} from "../../src/core/changelog.js";

describe("changelog", () => {
    let tempDir: string;
    let changelogPath: string;
    let backupDir: string;

    // Save original env values
    const origChangelogPath = process.env.KALI_DEFENSE_CHANGELOG_PATH;
    const origBackupDir = process.env.KALI_DEFENSE_BACKUP_DIR;

    beforeEach(() => {
        tempDir = mkdtempSync(join(tmpdir(), "kali-defense-changelog-test-"));
        changelogPath = join(tempDir, "changelog.json");
        backupDir = join(tempDir, "backups");

        // Redirect config to use temp paths
        process.env.KALI_DEFENSE_CHANGELOG_PATH = changelogPath;
        process.env.KALI_DEFENSE_BACKUP_DIR = backupDir;
    });

    afterEach(() => {
        rmSync(tempDir, { recursive: true, force: true });

        // Restore original env values
        if (origChangelogPath === undefined) {
            delete process.env.KALI_DEFENSE_CHANGELOG_PATH;
        } else {
            process.env.KALI_DEFENSE_CHANGELOG_PATH = origChangelogPath;
        }
        if (origBackupDir === undefined) {
            delete process.env.KALI_DEFENSE_BACKUP_DIR;
        } else {
            process.env.KALI_DEFENSE_BACKUP_DIR = origBackupDir;
        }
    });

    /** Helper to read the versioned changelog state from disk. */
    function readState(): ChangelogState {
        const raw = readFileSync(changelogPath, "utf-8");
        return JSON.parse(raw) as ChangelogState;
    }

    // ── createChangeEntry ─────────────────────────────────────────────────

    describe("createChangeEntry", () => {
        it("should generate a UUID id", () => {
            const entry = createChangeEntry({
                tool: "test-tool",
                action: "test action",
                target: "/etc/test",
                dryRun: false,
                success: true,
            });
            // UUID v4 format: 8-4-4-4-12 hex chars
            expect(entry.id).toMatch(
                /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
            );
        });

        it("should generate an ISO 8601 timestamp", () => {
            const entry = createChangeEntry({
                tool: "test-tool",
                action: "test action",
                target: "/etc/test",
                dryRun: false,
                success: true,
            });
            // Should parse as a valid date
            const date = new Date(entry.timestamp);
            expect(date.getTime()).not.toBeNaN();
            // Should be an ISO string
            expect(entry.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
        });

        it("should include all provided fields", () => {
            const entry = createChangeEntry({
                tool: "firewall_ufw_rule",
                action: "Added UFW rule",
                target: "port 22",
                before: "no rule",
                after: "allow 22/tcp",
                dryRun: false,
                success: true,
                rollbackCommand: "ufw delete allow 22/tcp",
            });
            expect(entry.tool).toBe("firewall_ufw_rule");
            expect(entry.action).toBe("Added UFW rule");
            expect(entry.target).toBe("port 22");
            expect(entry.before).toBe("no rule");
            expect(entry.after).toBe("allow 22/tcp");
            expect(entry.dryRun).toBe(false);
            expect(entry.success).toBe(true);
            expect(entry.rollbackCommand).toBe("ufw delete allow 22/tcp");
        });

        it("should auto-populate user field with OS username", () => {
            const entry = createChangeEntry({
                tool: "test-tool",
                action: "user attr test",
                target: "/etc/test",
                dryRun: false,
                success: true,
            });
            // user field should be a non-empty string matching current OS user
            expect(entry.user).toBeDefined();
            expect(typeof entry.user).toBe("string");
            expect(entry.user!.length).toBeGreaterThan(0);

            // Verify it matches the actual OS username
            const { userInfo } = require("node:os");
            expect(entry.user).toBe(userInfo().username);
        });

        it("should include user field in logged entries", () => {
            const entry = createChangeEntry({
                tool: "test-tool",
                action: "persist user test",
                target: "/etc/test",
                dryRun: false,
                success: true,
            });
            logChange(entry);

            const state = readState();
            expect(state.entries[0].user).toBeDefined();
            expect(typeof state.entries[0].user).toBe("string");
            expect(state.entries[0].user!.length).toBeGreaterThan(0);
        });

        it("should accept optional sessionId field", () => {
            const entry = createChangeEntry({
                tool: "test-tool",
                action: "session test",
                target: "/etc/test",
                dryRun: false,
                success: true,
                sessionId: "mcp-session-abc-123",
            });
            expect(entry.sessionId).toBe("mcp-session-abc-123");

            logChange(entry);
            const state = readState();
            expect(state.entries[0].sessionId).toBe("mcp-session-abc-123");
        });
    });

    // ── logChange ─────────────────────────────────────────────────────────

    describe("logChange", () => {
        it("should create a changelog file if none exists", () => {
            const entry = createChangeEntry({
                tool: "test",
                action: "test action",
                target: "/test",
                dryRun: false,
                success: true,
            });
            logChange(entry);

            const state = readState();
            expect(state.version).toBe(1);
            expect(Array.isArray(state.entries)).toBe(true);
            expect(state.entries.length).toBe(1);
            expect(state.entries[0].tool).toBe("test");
        });

        it("should append entries correctly", () => {
            const entry1 = createChangeEntry({
                tool: "tool1",
                action: "action1",
                target: "/target1",
                dryRun: false,
                success: true,
            });
            const entry2 = createChangeEntry({
                tool: "tool2",
                action: "action2",
                target: "/target2",
                dryRun: true,
                success: true,
            });

            logChange(entry1);
            logChange(entry2);

            const state = readState();
            expect(state.entries.length).toBe(2);
            expect(state.entries[0].tool).toBe("tool1");
            expect(state.entries[1].tool).toBe("tool2");
        });

        it("should write file with secure permissions (0o600)", () => {
            const entry = createChangeEntry({
                tool: "test",
                action: "test",
                target: "/test",
                dryRun: false,
                success: true,
            });
            logChange(entry);

            const stats = statSync(changelogPath);
            expect(stats.mode & 0o777).toBe(0o600);
        });

        it("should handle corrupt existing file gracefully", () => {
            // Write invalid JSON to changelog
            writeFileSync(changelogPath, "not-valid-json{{{");

            const entry = createChangeEntry({
                tool: "test",
                action: "test",
                target: "/test",
                dryRun: false,
                success: true,
            });

            // Should not throw
            expect(() => logChange(entry)).not.toThrow();

            // Should have overwritten with valid data
            const state = readState();
            expect(state.entries.length).toBe(1);
        });

        it("should migrate old bare-array format", () => {
            // Write old-format bare array
            const oldEntry: ChangeEntry = {
                id: "old-id",
                timestamp: "2024-01-01T00:00:00.000Z",
                tool: "old-tool",
                action: "old action",
                target: "/old",
                dryRun: false,
                success: true,
            };
            writeFileSync(changelogPath, JSON.stringify([oldEntry]));

            const newEntry = createChangeEntry({
                tool: "new-tool",
                action: "new action",
                target: "/new",
                dryRun: false,
                success: true,
            });
            logChange(newEntry);

            // Should now be in versioned format with both entries
            const state = readState();
            expect(state.version).toBe(1);
            expect(state.entries.length).toBe(2);
            expect(state.entries[0].tool).toBe("old-tool");
            expect(state.entries[1].tool).toBe("new-tool");
        });

        it("should record dryRun flag correctly", () => {
            const entry = createChangeEntry({
                tool: "test",
                action: "dry run test",
                target: "/test",
                dryRun: true,
                success: true,
            });
            logChange(entry);

            const state = readState();
            expect(state.entries[0].dryRun).toBe(true);
        });

        it("should record error field on failed actions", () => {
            const entry = createChangeEntry({
                tool: "test",
                action: "failed action",
                target: "/test",
                dryRun: false,
                success: false,
                error: "Permission denied",
            });
            logChange(entry);

            const state = readState();
            expect(state.entries[0].success).toBe(false);
            expect(state.entries[0].error).toBe("Permission denied");
        });
    });

    // ── getChangelog ──────────────────────────────────────────────────────

    describe("getChangelog", () => {
        it("should return empty array when no changelog exists", () => {
            const entries = getChangelog();
            expect(entries).toEqual([]);
        });

        it("should return entries from changelog file", () => {
            const entry1 = createChangeEntry({
                tool: "tool1",
                action: "action1",
                target: "/target1",
                dryRun: false,
                success: true,
            });
            const entry2 = createChangeEntry({
                tool: "tool2",
                action: "action2",
                target: "/target2",
                dryRun: false,
                success: true,
            });
            logChange(entry1);
            logChange(entry2);

            const entries = getChangelog();
            expect(entries.length).toBe(2);
        });

        it("should return entries sorted newest first", () => {
            // Create entries with known timestamps
            const oldEntry: ChangeEntry = {
                id: "old-id",
                timestamp: "2024-01-01T00:00:00.000Z",
                tool: "old",
                action: "old action",
                target: "/old",
                dryRun: false,
                success: true,
            };
            const newEntry: ChangeEntry = {
                id: "new-id",
                timestamp: "2025-06-15T12:00:00.000Z",
                tool: "new",
                action: "new action",
                target: "/new",
                dryRun: false,
                success: true,
            };

            logChange(oldEntry);
            logChange(newEntry);

            const entries = getChangelog();
            expect(entries[0].tool).toBe("new");
            expect(entries[1].tool).toBe("old");
        });

        it("should respect the limit parameter", () => {
            for (let i = 0; i < 5; i++) {
                logChange(
                    createChangeEntry({
                        tool: `tool${i}`,
                        action: `action${i}`,
                        target: `/target${i}`,
                        dryRun: false,
                        success: true,
                    })
                );
            }

            const limited = getChangelog(2);
            expect(limited.length).toBe(2);
        });

        it("should return empty array for corrupt file", () => {
            writeFileSync(changelogPath, "{{broken json");
            const entries = getChangelog();
            expect(entries).toEqual([]);
        });

        it("should read old bare-array format files", () => {
            // Write old-format bare array directly
            const oldEntries: ChangeEntry[] = [
                {
                    id: "id-1",
                    timestamp: "2024-01-01T00:00:00.000Z",
                    tool: "old-tool",
                    action: "old action",
                    target: "/old",
                    dryRun: false,
                    success: true,
                },
            ];
            writeFileSync(changelogPath, JSON.stringify(oldEntries));

            const entries = getChangelog();
            expect(entries.length).toBe(1);
            expect(entries[0].tool).toBe("old-tool");
        });
    });

    // ── backupFile ────────────────────────────────────────────────────────

    describe("backupFile", () => {
        it("should create a backup copy of a file", () => {
            const srcPath = join(tempDir, "original.conf");
            writeFileSync(srcPath, "original content");

            const backupPath = backupFile(srcPath);

            expect(backupPath).toContain("original.conf");
            const content = readFileSync(backupPath, "utf-8");
            expect(content).toBe("original content");
        });

        it("should create backup with secure permissions (0o600)", () => {
            const srcPath = join(tempDir, "secure-backup.conf");
            writeFileSync(srcPath, "data");

            const backupPath = backupFile(srcPath);

            const stats = statSync(backupPath);
            expect(stats.mode & 0o777).toBe(0o600);
        });

        it("should create backup directory if it doesn't exist", () => {
            const srcPath = join(tempDir, "new-backup.conf");
            writeFileSync(srcPath, "data");

            // backupDir doesn't exist yet; backupFile should create it
            const backupPath = backupFile(srcPath);
            expect(backupPath).toBeTruthy();

            const dirStats = statSync(backupDir);
            expect(dirStats.isDirectory()).toBe(true);
        });

        it("should include timestamp in backup filename", () => {
            const srcPath = join(tempDir, "timestamped.conf");
            writeFileSync(srcPath, "data");

            const backupPath = backupFile(srcPath);

            // Should contain ISO-like timestamp pattern
            const filename = backupPath.split("/").pop()!;
            expect(filename).toMatch(/^\d{4}-\d{2}-\d{2}T.*_timestamped\.conf$/);
        });

        it("should track backup in manifest.json", () => {
            const srcPath = join(tempDir, "tracked.conf");
            writeFileSync(srcPath, "tracked content");

            backupFile(srcPath);

            // Manifest should exist and contain the backup entry
            const manifestPath = join(backupDir, "manifest.json");
            const manifest = JSON.parse(readFileSync(manifestPath, "utf-8"));
            expect(manifest.version).toBe(1);
            expect(manifest.backups.length).toBe(1);
            expect(manifest.backups[0].originalPath).toBe(srcPath);
        });
    });
});
