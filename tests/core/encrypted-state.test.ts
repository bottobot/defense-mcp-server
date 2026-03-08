import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync, existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { SecureStateStore } from "../../src/core/encrypted-state.js";

describe("SecureStateStore", () => {
    let tempDir: string;

    beforeEach(() => {
        tempDir = mkdtempSync(join(tmpdir(), "kali-defense-state-test-"));
    });

    afterEach(() => {
        rmSync(tempDir, { recursive: true, force: true });
        vi.restoreAllMocks();
    });

    // ── Round-trip ──────────────────────────────────────────────────────────

    describe("save and load round-trip", () => {
        it("should save and load data in unencrypted mode", () => {
            const store = new SecureStateStore(tempDir, "");
            const data = { foo: "bar", count: 42, nested: { a: 1 } };
            store.save("test-state", data);
            const loaded = store.load("test-state");
            expect(loaded).toEqual(data);
        });

        it("should save and load data in encrypted mode", () => {
            const store = new SecureStateStore(tempDir, "my-secret-key-123");
            const data = { sensitive: "value", list: [1, 2, 3] };
            store.save("encrypted-state", data);
            const loaded = store.load("encrypted-state");
            expect(loaded).toEqual(data);
        });

        it("should handle complex nested objects", () => {
            const store = new SecureStateStore(tempDir, "test-key");
            const data = {
                rollback: {
                    timestamp: "2026-01-01T00:00:00Z",
                    files: [
                        { path: "/etc/foo", backup: "/tmp/foo.bak" },
                        { path: "/etc/bar", backup: "/tmp/bar.bak" },
                    ],
                },
                metadata: { version: 1, encrypted: true },
            };
            store.save("complex", data);
            const loaded = store.load("complex");
            expect(loaded).toEqual(data);
        });
    });

    // ── Load non-existent ───────────────────────────────────────────────────

    describe("load non-existent state", () => {
        it("should return null for non-existent state ID", () => {
            const store = new SecureStateStore(tempDir, "key");
            const result = store.load("does-not-exist");
            expect(result).toBeNull();
        });
    });

    // ── Delete ──────────────────────────────────────────────────────────────

    describe("delete", () => {
        it("should remove the state file", () => {
            const store = new SecureStateStore(tempDir, "key");
            store.save("to-delete", { data: true });
            expect(store.load("to-delete")).not.toBeNull();

            store.delete("to-delete");
            expect(store.load("to-delete")).toBeNull();
        });

        it("should not throw when deleting non-existent state", () => {
            const store = new SecureStateStore(tempDir, "key");
            expect(() => store.delete("nonexistent")).not.toThrow();
        });
    });

    // ── Encrypted vs unencrypted ────────────────────────────────────────────

    describe("encryption mode", () => {
        it("should report encrypted=true when key is provided", () => {
            const store = new SecureStateStore(tempDir, "my-key");
            expect(store.encrypted).toBe(true);
        });

        it("should report encrypted=false when no key is provided", () => {
            const store = new SecureStateStore(tempDir, "");
            expect(store.encrypted).toBe(false);
        });

        it("should store encrypted data that is not valid JSON on disk", () => {
            const store = new SecureStateStore(tempDir, "secret");
            store.save("enc-test", { message: "hello" });

            // Read raw file — should not be parseable as JSON
            const filePath = join(tempDir, "enc-test.state");
            const raw = readFileSync(filePath);
            expect(() => JSON.parse(raw.toString("utf-8"))).toThrow();
        });

        it("should store unencrypted data as valid JSON on disk", () => {
            const store = new SecureStateStore(tempDir, "");
            store.save("plain-test", { message: "hello" });

            const filePath = join(tempDir, "plain-test.state");
            const raw = readFileSync(filePath, "utf-8");
            const parsed = JSON.parse(raw);
            expect(parsed).toEqual({ message: "hello" });
        });
    });

    // ── Invalid key / wrong key ─────────────────────────────────────────────

    describe("invalid key handling", () => {
        it("should fail to decrypt with wrong key", () => {
            const store1 = new SecureStateStore(tempDir, "correct-key");
            store1.save("secret", { data: "sensitive" });

            const store2 = new SecureStateStore(tempDir, "wrong-key");
            expect(() => store2.load("secret")).toThrow(/Failed to decrypt|invalid key|corrupted/i);
        });
    });

    // ── File permissions ────────────────────────────────────────────────────

    describe("file permissions", () => {
        it("should set state files to 0o600 permissions", () => {
            const store = new SecureStateStore(tempDir, "key");
            store.save("perms-test", { data: true });

            const filePath = join(tempDir, "perms-test.state");
            const stats = statSync(filePath);
            expect(stats.mode & 0o777).toBe(0o600);
        });
    });

    // ── Corrupted data ──────────────────────────────────────────────────────

    describe("corrupted data handling", () => {
        it("should throw on corrupted encrypted data", () => {
            const store = new SecureStateStore(tempDir, "key");
            store.save("corrupt-test", { data: true });

            // Corrupt the file by overwriting with garbage
            const filePath = join(tempDir, "corrupt-test.state");
            const { writeFileSync } = require("node:fs");
            writeFileSync(filePath, Buffer.from("this is not encrypted data at all - garbage bytes"));

            expect(() => store.load("corrupt-test")).toThrow(/corrupted|decrypt|too short/i);
        });

        it("should throw on truncated encrypted data", () => {
            const store = new SecureStateStore(tempDir, "key");
            store.save("truncated-test", { data: true });

            // Truncate the file to just a few bytes
            const filePath = join(tempDir, "truncated-test.state");
            const { writeFileSync } = require("node:fs");
            writeFileSync(filePath, Buffer.from([0x01, 0x02, 0x03]));

            expect(() => store.load("truncated-test")).toThrow(/too short|corrupted/i);
        });
    });

    // ── Path sanitization ───────────────────────────────────────────────────

    describe("ID sanitization", () => {
        it("should sanitize state IDs to prevent path traversal", () => {
            const store = new SecureStateStore(tempDir, "");
            store.save("../../etc/passwd", { malicious: true });

            // Should not write outside the state directory
            expect(existsSync(join(tempDir, "______etc_passwd.state"))).toBe(true);
            expect(existsSync("/etc/passwd.state")).toBe(false);
        });
    });

    // ── Warning log on unencrypted mode ─────────────────────────────────────

    describe("unencrypted fallback warning", () => {
        it("should log a warning when no key is configured", () => {
            const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

            // Creating with empty key should trigger warning
            new SecureStateStore(tempDir, "");

            // Check that a warning was logged to stderr
            const calls = stderrSpy.mock.calls.map((c) => String(c[0]));
            const hasWarning = calls.some(
                (msg) => msg.includes("warn") && msg.includes("unencrypted"),
            );
            expect(hasWarning).toBe(true);
        });
    });
});
