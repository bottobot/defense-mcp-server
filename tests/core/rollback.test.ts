import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync, readFileSync, writeFileSync, existsSync, statSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

/**
 * RollbackManager is a singleton that reads from ~/.kali-defense/rollback-state.json.
 * To test it in isolation we dynamically import a fresh module for each test,
 * pointing HOME at a temp directory so it picks up an isolated state file.
 */

describe("rollback", () => {
    let tempDir: string;
    let kaliDir: string;
    let statePath: string;

    const origHome = process.env.HOME;

    beforeEach(() => {
        tempDir = mkdtempSync(join(tmpdir(), "kali-rollback-test-"));
        kaliDir = join(tempDir, ".kali-defense");
        statePath = join(kaliDir, "rollback-state.json");

        // Point HOME to the temp directory so RollbackManager uses our isolated dir
        process.env.HOME = tempDir;
    });

    afterEach(() => {
        rmSync(tempDir, { recursive: true, force: true });
        if (origHome === undefined) {
            delete process.env.HOME;
        } else {
            process.env.HOME = origHome;
        }
    });

    /**
     * Helper: create a fresh RollbackManager by resetting the singleton.
     * We import it dynamically and clear the module's singleton state.
     */
    async function createFreshManager() {
        // We need to work around the singleton pattern.
        // Import the module, then use reflection to reset the singleton.
        const mod = await import("../../src/core/rollback.js");
        const RollbackManager = mod.RollbackManager;

        // Reset singleton via reflection
        (RollbackManager as unknown as Record<string, unknown>)["instance"] = null;

        return RollbackManager.getInstance();
    }

    // ── Constructor / initialization ──────────────────────────────────────

    describe("initialization", () => {
        it("should create a RollbackManager instance", async () => {
            const manager = await createFreshManager();
            expect(manager).toBeDefined();
        });

        it("should have a session ID (UUID format)", async () => {
            const manager = await createFreshManager();
            const sessionId = manager.getSessionId();
            expect(sessionId).toMatch(
                /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
            );
        });

        it("should start with empty changes when no state file exists", async () => {
            const manager = await createFreshManager();
            const changes = manager.listChanges();
            expect(changes).toEqual([]);
        });

        it("should generate unique session IDs on each instance reset", async () => {
            const m1 = await createFreshManager();
            const s1 = m1.getSessionId();

            const m2 = await createFreshManager();
            const s2 = m2.getSessionId();

            expect(s1).not.toBe(s2);
        });
    });

    // ── trackChange ──────────────────────────────────────────────────────

    describe("trackChange", () => {
        it("should add a change record", async () => {
            const manager = await createFreshManager();
            manager.trackChange("op-1", "sysctl", "net.ipv4.ip_forward", "0");

            const changes = manager.listChanges();
            expect(changes.length).toBe(1);
            expect(changes[0].operationId).toBe("op-1");
            expect(changes[0].type).toBe("sysctl");
            expect(changes[0].target).toBe("net.ipv4.ip_forward");
            expect(changes[0].originalValue).toBe("0");
        });

        it("should generate a UUID for each change record", async () => {
            const manager = await createFreshManager();
            manager.trackChange("op-1", "file", "/etc/test", "backup-path");

            const changes = manager.listChanges();
            expect(changes[0].id).toMatch(
                /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
            );
        });

        it("should record the session ID on each change", async () => {
            const manager = await createFreshManager();
            const sessionId = manager.getSessionId();
            manager.trackChange("op-1", "firewall", "INPUT", "iptables -D INPUT 1");

            const changes = manager.listChanges();
            expect(changes[0].sessionId).toBe(sessionId);
        });

        it("should set rolledBack to false for new changes", async () => {
            const manager = await createFreshManager();
            manager.trackChange("op-1", "service", "ssh.service", "active");

            const changes = manager.listChanges();
            expect(changes[0].rolledBack).toBe(false);
        });

        it("should record an ISO timestamp", async () => {
            const manager = await createFreshManager();
            manager.trackChange("op-1", "sysctl", "kernel.sysrq", "1");

            const changes = manager.listChanges();
            const date = new Date(changes[0].timestamp);
            expect(date.getTime()).not.toBeNaN();
            expect(changes[0].timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
        });

        it("should accept an optional changelogRef", async () => {
            const manager = await createFreshManager();
            manager.trackChange("op-1", "file", "/etc/test", "backup-path", "changelog-id-123");

            const changes = manager.listChanges();
            expect(changes[0].changelogRef).toBe("changelog-id-123");
        });

        it("should track multiple changes", async () => {
            const manager = await createFreshManager();
            manager.trackChange("op-1", "sysctl", "net.ipv4.ip_forward", "0");
            manager.trackChange("op-1", "sysctl", "net.ipv4.conf.all.rp_filter", "1");
            manager.trackChange("op-2", "file", "/etc/ssh/sshd_config", "/backup/sshd_config");

            const changes = manager.listChanges();
            expect(changes.length).toBe(3);
        });
    });

    // ── Persistence / save ───────────────────────────────────────────────

    describe("persistence", () => {
        it("should save state to disk on trackChange", async () => {
            const manager = await createFreshManager();
            manager.trackChange("op-1", "sysctl", "net.ipv4.ip_forward", "0");

            // The state file should exist
            expect(existsSync(statePath)).toBe(true);
        });

        it("should write versioned state format", async () => {
            const manager = await createFreshManager();
            manager.trackChange("op-1", "file", "/etc/test", "backup-path");

            const raw = readFileSync(statePath, "utf-8");
            const state = JSON.parse(raw);
            expect(state.version).toBe(1);
            expect(Array.isArray(state.changes)).toBe(true);
            expect(state.changes.length).toBe(1);
        });

        it("should write state file with secure permissions (0o600)", async () => {
            const manager = await createFreshManager();
            manager.trackChange("op-1", "sysctl", "test.key", "old-value");

            const stats = statSync(statePath);
            expect(stats.mode & 0o777).toBe(0o600);
        });

        it("should persist and reload changes across instances", async () => {
            // Track changes with first manager
            const m1 = await createFreshManager();
            m1.trackChange("op-1", "sysctl", "net.ipv4.ip_forward", "0");
            m1.trackChange("op-2", "file", "/etc/test", "backup-path");

            // Create a new manager (simulating server restart)
            const m2 = await createFreshManager();
            const changes = m2.listChanges();
            expect(changes.length).toBe(2);
        });
    });

    // ── Migration from old format ────────────────────────────────────────

    describe("migration", () => {
        it("should migrate old bare-array format", async () => {
            const { secureMkdirSync, secureWriteFileSync } = await import("../../src/core/secure-fs.js");
            secureMkdirSync(kaliDir);

            // Write old format (bare array, no version envelope)
            const oldData = [
                {
                    id: "old-id-1",
                    operationId: "old-op",
                    sessionId: "old-session",
                    type: "sysctl",
                    target: "net.ipv4.ip_forward",
                    originalValue: "0",
                    timestamp: "2024-01-01T00:00:00.000Z",
                    rolledBack: false,
                },
            ];
            secureWriteFileSync(statePath, JSON.stringify(oldData), "utf-8");

            const manager = await createFreshManager();
            const changes = manager.listChanges();
            expect(changes.length).toBe(1);
            expect(changes[0].operationId).toBe("old-op");
        });

        it("should handle corrupt state file gracefully", async () => {
            const { secureMkdirSync, secureWriteFileSync } = await import("../../src/core/secure-fs.js");
            secureMkdirSync(kaliDir);

            // Write corrupt data
            secureWriteFileSync(statePath, "not valid json {{", "utf-8");

            const manager = await createFreshManager();
            const changes = manager.listChanges();
            expect(changes).toEqual([]);
        });
    });

    // ── listChanges sorting ──────────────────────────────────────────────

    describe("listChanges", () => {
        it("should return changes sorted newest first", async () => {
            const { secureMkdirSync, secureWriteFileSync } = await import("../../src/core/secure-fs.js");
            secureMkdirSync(kaliDir);

            // Pre-seed state with known timestamps
            const state = {
                version: 1,
                changes: [
                    {
                        id: "id-1",
                        operationId: "op-1",
                        sessionId: "s1",
                        type: "sysctl",
                        target: "key1",
                        originalValue: "v1",
                        timestamp: "2024-01-01T00:00:00.000Z",
                        rolledBack: false,
                    },
                    {
                        id: "id-2",
                        operationId: "op-2",
                        sessionId: "s1",
                        type: "file",
                        target: "key2",
                        originalValue: "v2",
                        timestamp: "2025-06-15T12:00:00.000Z",
                        rolledBack: false,
                    },
                ],
            };
            secureWriteFileSync(statePath, JSON.stringify(state), "utf-8");

            const manager = await createFreshManager();
            const changes = manager.listChanges();
            expect(changes[0].id).toBe("id-2"); // Newer
            expect(changes[1].id).toBe("id-1"); // Older
        });

        it("should return a copy (not a reference to internal array)", async () => {
            const manager = await createFreshManager();
            manager.trackChange("op-1", "sysctl", "key", "val");

            const changes1 = manager.listChanges();
            const changes2 = manager.listChanges();
            expect(changes1).not.toBe(changes2); // Different array instances
            expect(changes1).toEqual(changes2);   // Same content
        });
    });

    // ── rollback ─────────────────────────────────────────────────────────

    describe("rollback", () => {
        it("should throw when no changes found for operation", async () => {
            const manager = await createFreshManager();
            await expect(manager.rollback("nonexistent-op")).rejects.toThrow(
                /no pending changes/i
            );
        });

        it("should throw when no changes found for session", async () => {
            const manager = await createFreshManager();
            await expect(manager.rollbackSession("nonexistent-session")).rejects.toThrow(
                /no pending changes/i
            );
        });
    });
});
