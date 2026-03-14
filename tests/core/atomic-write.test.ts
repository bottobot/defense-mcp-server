import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync, statSync, readFileSync, writeFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { atomicWriteFileSync, secureWriteFileSync } from "../../src/core/secure-fs.js";

describe("atomicWriteFileSync", () => {
    let tempDir: string;

    beforeEach(() => {
        tempDir = mkdtempSync(join(tmpdir(), "defense-mcp-atomic-test-"));
    });

    afterEach(() => {
        rmSync(tempDir, { recursive: true, force: true });
        vi.restoreAllMocks();
    });

    // ── Basic creation ──────────────────────────────────────────────────────

    it("should create a file", () => {
        const filePath = join(tempDir, "test.txt");
        atomicWriteFileSync(filePath, "hello world");
        expect(readFileSync(filePath, "utf-8")).toBe("hello world");
    });

    it("should write correct content", () => {
        const filePath = join(tempDir, "data.json");
        const content = JSON.stringify({ key: "value", num: 42 });
        atomicWriteFileSync(filePath, content);
        const read = readFileSync(filePath, "utf-8");
        expect(JSON.parse(read)).toEqual({ key: "value", num: 42 });
    });

    it("should handle Buffer data", () => {
        const filePath = join(tempDir, "binary.bin");
        const buf = Buffer.from([0xDE, 0xAD, 0xBE, 0xEF]);
        atomicWriteFileSync(filePath, buf);
        const read = readFileSync(filePath);
        expect(read).toEqual(buf);
    });

    // ── Temp file cleanup ───────────────────────────────────────────────────

    it("should not leave temp files after successful write", () => {
        const filePath = join(tempDir, "clean.txt");
        atomicWriteFileSync(filePath, "data");

        const files = readdirSync(tempDir);
        const tmpFiles = files.filter((f) => f.includes(".tmp."));
        expect(tmpFiles).toHaveLength(0);
    });

    // ── File permissions ────────────────────────────────────────────────────

    it("should set file permissions to 0o600 by default", () => {
        const filePath = join(tempDir, "perms.txt");
        atomicWriteFileSync(filePath, "secure data");
        const stats = statSync(filePath);
        expect(stats.mode & 0o777).toBe(0o600);
    });

    it("should set custom file permissions when specified", () => {
        const filePath = join(tempDir, "custom-perms.txt");
        atomicWriteFileSync(filePath, "data", { mode: 0o644 });
        const stats = statSync(filePath);
        expect(stats.mode & 0o777).toBe(0o644);
    });

    // ── Overwrite existing file ─────────────────────────────────────────────

    it("should atomically overwrite an existing file", () => {
        const filePath = join(tempDir, "overwrite.txt");
        writeFileSync(filePath, "original content");

        atomicWriteFileSync(filePath, "updated content");
        const read = readFileSync(filePath, "utf-8");
        expect(read).toBe("updated content");
    });

    it("should maintain permissions when overwriting", () => {
        const filePath = join(tempDir, "overwrite-perms.txt");
        atomicWriteFileSync(filePath, "first");
        atomicWriteFileSync(filePath, "second");
        const stats = statSync(filePath);
        expect(stats.mode & 0o777).toBe(0o600);
    });

    // ── Parent directory creation ───────────────────────────────────────────

    it("should create parent directories if they don't exist", () => {
        const filePath = join(tempDir, "nested", "dir", "file.txt");
        atomicWriteFileSync(filePath, "nested data");
        const read = readFileSync(filePath, "utf-8");
        expect(read).toBe("nested data");
    });

    // ── Empty content ───────────────────────────────────────────────────────

    it("should handle empty string content", () => {
        const filePath = join(tempDir, "empty.txt");
        atomicWriteFileSync(filePath, "");
        const read = readFileSync(filePath, "utf-8");
        expect(read).toBe("");
        const stats = statSync(filePath);
        expect(stats.mode & 0o777).toBe(0o600);
    });
});

// ── Integration with secureWriteFileSync ────────────────────────────────────

describe("secureWriteFileSync with atomic option", () => {
    let tempDir: string;

    beforeEach(() => {
        tempDir = mkdtempSync(join(tmpdir(), "defense-mcp-secure-atomic-test-"));
    });

    afterEach(() => {
        rmSync(tempDir, { recursive: true, force: true });
    });

    it("should write atomically when atomic option is true", () => {
        const filePath = join(tempDir, "atomic-secure.txt");
        secureWriteFileSync(filePath, "atomic content", { atomic: true });

        const read = readFileSync(filePath, "utf-8");
        expect(read).toBe("atomic content");
        const stats = statSync(filePath);
        expect(stats.mode & 0o777).toBe(0o600);
    });

    it("should write non-atomically by default", () => {
        const filePath = join(tempDir, "non-atomic.txt");
        secureWriteFileSync(filePath, "normal content");

        const read = readFileSync(filePath, "utf-8");
        expect(read).toBe("normal content");
        const stats = statSync(filePath);
        expect(stats.mode & 0o777).toBe(0o600);
    });

    it("should not leave temp files with atomic write", () => {
        const filePath = join(tempDir, "clean-atomic.txt");
        secureWriteFileSync(filePath, "clean", { atomic: true });

        const files = readdirSync(tempDir);
        const tmpFiles = files.filter((f) => f.includes(".tmp."));
        expect(tmpFiles).toHaveLength(0);
    });

    it("should still accept legacy BufferEncoding parameter", () => {
        const filePath = join(tempDir, "legacy.txt");
        secureWriteFileSync(filePath, "legacy content", "utf-8");

        const read = readFileSync(filePath, "utf-8");
        expect(read).toBe("legacy content");
    });
});
