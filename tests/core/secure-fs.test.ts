import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, rmSync, statSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
    secureWriteFileSync,
    secureMkdirSync,
    secureCopyFileSync,
    verifySecurePermissions,
    hardenFilePermissions,
    hardenDirPermissions,
} from "../../src/core/secure-fs.js";

describe("secure-fs", () => {
    let tempDir: string;

    beforeEach(() => {
        tempDir = mkdtempSync(join(tmpdir(), "defense-mcp-test-"));
    });

    afterEach(() => {
        rmSync(tempDir, { recursive: true, force: true });
    });

    // ── secureWriteFileSync ───────────────────────────────────────────────

    describe("secureWriteFileSync", () => {
        it("should write file with 0o600 permissions", () => {
            const filePath = join(tempDir, "test.json");
            secureWriteFileSync(filePath, '{"test": true}');
            const stats = statSync(filePath);
            expect(stats.mode & 0o777).toBe(0o600);
        });

        it("should write correct content", () => {
            const filePath = join(tempDir, "test.txt");
            secureWriteFileSync(filePath, "hello world");
            const content = readFileSync(filePath, "utf-8");
            expect(content).toBe("hello world");
        });

        it("should create parent directories with 0o700 permissions", () => {
            const filePath = join(tempDir, "subdir", "test.json");
            secureWriteFileSync(filePath, "data");
            const dirStats = statSync(join(tempDir, "subdir"));
            expect(dirStats.mode & 0o777).toBe(0o700);
        });

        it("should create deeply nested directories", () => {
            const filePath = join(tempDir, "a", "b", "c", "test.json");
            secureWriteFileSync(filePath, "deep");
            const content = readFileSync(filePath, "utf-8");
            expect(content).toBe("deep");
        });

        it("should overwrite existing file and maintain permissions", () => {
            const filePath = join(tempDir, "overwrite.txt");
            secureWriteFileSync(filePath, "first");
            secureWriteFileSync(filePath, "second");
            const content = readFileSync(filePath, "utf-8");
            expect(content).toBe("second");
            const stats = statSync(filePath);
            expect(stats.mode & 0o777).toBe(0o600);
        });

        it("should handle Buffer data", () => {
            const filePath = join(tempDir, "buffer.bin");
            const buf = Buffer.from([0x01, 0x02, 0x03]);
            secureWriteFileSync(filePath, buf);
            const content = readFileSync(filePath);
            expect(content).toEqual(buf);
        });

        it("should handle empty string content", () => {
            const filePath = join(tempDir, "empty.txt");
            secureWriteFileSync(filePath, "");
            const content = readFileSync(filePath, "utf-8");
            expect(content).toBe("");
            const stats = statSync(filePath);
            expect(stats.mode & 0o777).toBe(0o600);
        });
    });

    // ── secureMkdirSync ───────────────────────────────────────────────────

    describe("secureMkdirSync", () => {
        it("should create directory with 0o700 permissions", () => {
            const dirPath = join(tempDir, "secure-dir");
            secureMkdirSync(dirPath);
            const stats = statSync(dirPath);
            expect(stats.mode & 0o777).toBe(0o700);
        });

        it("should create nested directories", () => {
            const dirPath = join(tempDir, "a", "b", "c");
            secureMkdirSync(dirPath);
            const stats = statSync(dirPath);
            expect(stats.mode & 0o777).toBe(0o700);
        });

        it("should fix permissions on existing directory", () => {
            const dirPath = join(tempDir, "existing");
            // Create with loose permissions first
            mkdirSync(dirPath, { mode: 0o755 });
            // Now secureMkdirSync should harden it
            secureMkdirSync(dirPath);
            const stats = statSync(dirPath);
            expect(stats.mode & 0o777).toBe(0o700);
        });
    });

    // ── secureCopyFileSync ────────────────────────────────────────────────

    describe("secureCopyFileSync", () => {
        it("should copy file with 0o600 permissions on destination", () => {
            const srcPath = join(tempDir, "source.txt");
            writeFileSync(srcPath, "source content", { mode: 0o644 });

            const destPath = join(tempDir, "dest.txt");
            secureCopyFileSync(srcPath, destPath);

            const content = readFileSync(destPath, "utf-8");
            expect(content).toBe("source content");
            const stats = statSync(destPath);
            expect(stats.mode & 0o777).toBe(0o600);
        });

        it("should create parent directories for destination", () => {
            const srcPath = join(tempDir, "source2.txt");
            writeFileSync(srcPath, "data");

            const destPath = join(tempDir, "subdir2", "dest2.txt");
            secureCopyFileSync(srcPath, destPath);

            const content = readFileSync(destPath, "utf-8");
            expect(content).toBe("data");
        });
    });

    // ── verifySecurePermissions ───────────────────────────────────────────

    describe("verifySecurePermissions", () => {
        it("should return true for 0o600 files", () => {
            const filePath = join(tempDir, "secure.txt");
            writeFileSync(filePath, "secure", { mode: 0o600 });
            chmodSync(filePath, 0o600);
            expect(verifySecurePermissions(filePath)).toBe(true);
        });

        it("should return true for 0o700 files", () => {
            const filePath = join(tempDir, "exec.sh");
            writeFileSync(filePath, "#!/bin/sh", { mode: 0o700 });
            chmodSync(filePath, 0o700);
            expect(verifySecurePermissions(filePath)).toBe(true);
        });

        it("should return false for 0o644 files", () => {
            const filePath = join(tempDir, "open.txt");
            writeFileSync(filePath, "open", { mode: 0o644 });
            chmodSync(filePath, 0o644);
            expect(verifySecurePermissions(filePath)).toBe(false);
        });

        it("should return false for 0o755 files", () => {
            const filePath = join(tempDir, "open-exec.sh");
            writeFileSync(filePath, "#!/bin/sh", { mode: 0o755 });
            chmodSync(filePath, 0o755);
            expect(verifySecurePermissions(filePath)).toBe(false);
        });

        it("should return false for non-existent files", () => {
            expect(verifySecurePermissions(join(tempDir, "nonexistent.txt"))).toBe(false);
        });
    });

    // ── hardenFilePermissions ─────────────────────────────────────────────

    describe("hardenFilePermissions", () => {
        it("should change 0o644 file to 0o600", () => {
            const filePath = join(tempDir, "loose.txt");
            writeFileSync(filePath, "data", { mode: 0o644 });
            chmodSync(filePath, 0o644);
            hardenFilePermissions(filePath);
            const stats = statSync(filePath);
            expect(stats.mode & 0o777).toBe(0o600);
        });

        it("should not throw for non-existent file", () => {
            expect(() =>
                hardenFilePermissions(join(tempDir, "no-such-file.txt"))
            ).not.toThrow();
        });
    });

    // ── hardenDirPermissions ──────────────────────────────────────────────

    describe("hardenDirPermissions", () => {
        it("should change 0o755 directory to 0o700", () => {
            const dirPath = join(tempDir, "loose-dir");
            mkdirSync(dirPath, { mode: 0o755 });
            hardenDirPermissions(dirPath);
            const stats = statSync(dirPath);
            expect(stats.mode & 0o777).toBe(0o700);
        });

        it("should not throw for non-existent directory", () => {
            expect(() =>
                hardenDirPermissions(join(tempDir, "no-such-dir"))
            ).not.toThrow();
        });
    });
});
