import { describe, it, expect, beforeAll } from "vitest";
import { executeCommand, type CommandResult } from "../../src/core/executor.js";
import { initializeAllowlist } from "../../src/core/command-allowlist.js";

describe("executor", () => {
    beforeAll(() => {
        initializeAllowlist();
    });

    // ── Basic execution ───────────────────────────────────────────────────

    describe("executeCommand — basic execution", () => {
        it("should execute a simple allowlisted command", async () => {
            const result = await executeCommand({ command: "cat", args: ["/dev/null"] });
            expect(result.exitCode).toBe(0);
            expect(result.timedOut).toBe(false);
            expect(result.permissionDenied).toBe(false);
        });

        it("should capture stdout correctly via stdin pipe", async () => {
            const result = await executeCommand({
                command: "cat",
                args: [],
                stdin: "hello from stdin\n",
            });
            expect(result.exitCode).toBe(0);
            expect(result.stdout).toContain("hello from stdin");
        });

        it("should handle string stdin data", async () => {
            const result = await executeCommand({
                command: "cat",
                args: [],
                stdin: "string input data\n",
            });
            expect(result.exitCode).toBe(0);
            expect(result.stdout).toContain("string input data");
        });

        it("should handle Buffer stdin data", async () => {
            const result = await executeCommand({
                command: "cat",
                args: [],
                stdin: Buffer.from("buffer input data\n"),
            });
            expect(result.exitCode).toBe(0);
            expect(result.stdout).toContain("buffer input data");
        });

        it("should handle custom environment variables", async () => {
            const result = await executeCommand({
                command: "sh",
                args: ["-c", "echo $TEST_KALI_EXEC_VAR"],
                env: { TEST_KALI_EXEC_VAR: "kali_exec_test_123" },
            });
            expect(result.exitCode).toBe(0);
            expect(result.stdout).toContain("kali_exec_test_123");
        });

        it("should return all CommandResult fields", async () => {
            const result = await executeCommand({ command: "cat", args: ["/dev/null"] });
            expect(result).toHaveProperty("stdout");
            expect(result).toHaveProperty("stderr");
            expect(result).toHaveProperty("exitCode");
            expect(result).toHaveProperty("timedOut");
            expect(result).toHaveProperty("duration");
            expect(result).toHaveProperty("permissionDenied");
            expect(typeof result.stdout).toBe("string");
            expect(typeof result.stderr).toBe("string");
            expect(typeof result.exitCode).toBe("number");
            expect(typeof result.timedOut).toBe("boolean");
            expect(typeof result.duration).toBe("number");
            expect(typeof result.permissionDenied).toBe("boolean");
        });

        it("should track execution duration", async () => {
            const result = await executeCommand({ command: "cat", args: ["/dev/null"] });
            expect(result.duration).toBeGreaterThanOrEqual(0);
            // A simple cat /dev/null should finish in well under 5 seconds
            expect(result.duration).toBeLessThan(5000);
        });
    });

    // ── Allowlist enforcement ─────────────────────────────────────────────

    describe("executeCommand — allowlist enforcement", () => {
        it("should reject non-allowlisted bare commands", async () => {
            const result = await executeCommand({
                command: "nonexistent_evil_binary",
                args: [],
            });
            expect(result.exitCode).toBe(1);
            expect(result.stderr).toContain("Allowlist");
            expect(result.timedOut).toBe(false);
            expect(result.duration).toBe(0);
        });

        it("should reject non-allowlisted absolute paths", async () => {
            const result = await executeCommand({
                command: "/tmp/evil-binary",
                args: [],
            });
            expect(result.exitCode).toBe(1);
            expect(result.stderr).toContain("Allowlist");
        });

        it("should reject path traversal attempts", async () => {
            const result = await executeCommand({
                command: "../../../tmp/evil",
                args: [],
            });
            expect(result.exitCode).toBe(1);
            expect(result.stderr).toContain("Allowlist");
        });
    });

    // ── Error handling ────────────────────────────────────────────────────

    describe("executeCommand — error handling", () => {
        it("should handle command failure with non-zero exit code", async () => {
            const result = await executeCommand({
                command: "cat",
                args: ["/nonexistent/file/that/does/not/exist/anywhere"],
            });
            expect(result.exitCode).not.toBe(0);
            expect(result.stderr).toBeTruthy();
        });

        it("should not set permissionDenied on normal failures", async () => {
            const result = await executeCommand({
                command: "cat",
                args: ["/nonexistent/file"],
            });
            expect(result.exitCode).not.toBe(0);
            expect(result.permissionDenied).toBe(false);
        });

        it("should capture stderr from failed commands", async () => {
            const result = await executeCommand({
                command: "cat",
                args: ["/nonexistent/path/to/nowhere"],
            });
            expect(result.stderr).toBeTruthy();
            expect(result.stderr.length).toBeGreaterThan(0);
        });
    });

    // ── Timeout behavior ──────────────────────────────────────────────────

    describe("executeCommand — timeout", () => {
        it("should kill a command that exceeds timeout", async () => {
            // cat with no stdin and no file will hang forever — perfect for timeout test
            const result = await executeCommand({
                command: "cat",
                args: [],
                timeout: 500,
            });
            expect(result.timedOut).toBe(true);
            expect(result.exitCode).toBe(124);
            expect(result.stderr).toContain("timed out");
        }, 15000);

        it("should include timeout duration in stderr message", async () => {
            const result = await executeCommand({
                command: "cat",
                args: [],
                timeout: 1000,
            });
            expect(result.timedOut).toBe(true);
            expect(result.stderr).toMatch(/timed out after \d+ seconds/i);
        }, 15000);

        it("should not timeout a fast command", async () => {
            const result = await executeCommand({
                command: "cat",
                args: ["/dev/null"],
                timeout: 30000,
            });
            expect(result.timedOut).toBe(false);
            expect(result.exitCode).toBe(0);
        });
    });

    // ── Sudo options ──────────────────────────────────────────────────────

    describe("executeCommand — sudo handling", () => {
        it("should pass through non-sudo commands without sudo injection", async () => {
            const result = await executeCommand({
                command: "cat",
                args: ["/dev/null"],
            });
            expect(result.exitCode).toBe(0);
            // Just verifying no sudo-related errors
            expect(result.stderr).not.toContain("sudo");
        });

        it("should validate sudo target binary against allowlist", async () => {
            // sudo + cat: both are allowlisted
            // Without active sudo session, this may fail but NOT with allowlist error
            const result = await executeCommand({
                command: "sudo",
                args: ["cat", "/dev/null"],
                skipSudoInjection: true,
            });
            if (result.exitCode !== 0) {
                // Should NOT be an allowlist failure — both sudo and cat are allowlisted
                expect(result.stderr).not.toContain("Allowlist validation failed");
            }
        });

        it("should reject sudo with non-allowlisted target", async () => {
            const result = await executeCommand({
                command: "sudo",
                args: ["evil_binary", "--flag"],
                skipSudoInjection: true,
            });
            expect(result.exitCode).toBe(1);
            expect(result.stderr).toContain("Allowlist");
        });
    });
});
