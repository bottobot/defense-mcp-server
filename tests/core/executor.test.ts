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
                command: "env",
                args: [],
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

    // ── Additional: sudo with -S/-A flags already present ──────────────

    describe("executeCommand — sudo flag passthrough", () => {
        it("should not inject sudo flags when -S is already present", async () => {
            const result = await executeCommand({
                command: "sudo",
                args: ["-S", "cat", "/dev/null"],
                skipSudoInjection: true,
                timeout: 2000,
            });
            // Just verify it runs without allowlist errors — it may fail due to no password
            if (result.exitCode !== 0) {
                expect(result.stderr).not.toContain("Allowlist validation failed");
            }
        }, 15000);

        it("should not inject sudo flags when -A is already present", async () => {
            const result = await executeCommand({
                command: "sudo",
                args: ["-A", "cat", "/dev/null"],
                skipSudoInjection: true,
                timeout: 2000,
            });
            if (result.exitCode !== 0) {
                expect(result.stderr).not.toContain("Allowlist validation failed");
            }
        }, 15000);
    });

    // ── Additional: toolName timeout resolution ────────────────────────

    describe("executeCommand — toolName timeout", () => {
        it("should accept toolName for timeout lookup", async () => {
            const result = await executeCommand({
                command: "cat",
                args: ["/dev/null"],
                toolName: "some_tool",
            });
            expect(result.exitCode).toBe(0);
        });

        it("should use custom timeout over toolName when both provided", async () => {
            const result = await executeCommand({
                command: "cat",
                args: ["/dev/null"],
                timeout: 30000,
                toolName: "some_tool",
            });
            expect(result.exitCode).toBe(0);
            expect(result.timedOut).toBe(false);
        });
    });

    // ── Additional: cwd option ─────────────────────────────────────────

    describe("executeCommand — working directory", () => {
        it("should execute command in specified cwd", async () => {
            const result = await executeCommand({
                command: "cat",
                args: ["/dev/null"],
                cwd: "/tmp",
            });
            expect(result.exitCode).toBe(0);
        });
    });

    // ── Additional: output buffer behavior ─────────────────────────────

    describe("executeCommand — output buffer handling", () => {
        it("should capture both stdout and stderr", async () => {
            // ls on nonexistent produces stderr; cat /dev/null produces empty stdout
            const result = await executeCommand({
                command: "ls",
                args: ["/nonexistent_path_for_test"],
            });
            expect(result.exitCode).not.toBe(0);
            expect(result.stderr.length).toBeGreaterThan(0);
        });

        it("should handle very small maxBuffer", async () => {
            const result = await executeCommand({
                command: "cat",
                args: ["/proc/version"],
                maxBuffer: 10,
            });
            // Output should be truncated
            expect(result.exitCode).toBe(0);
            expect(result.stdout).toContain("[OUTPUT TRUNCATED");
        });

        it("should handle large output within default maxBuffer", async () => {
            const result = await executeCommand({
                command: "cat",
                args: ["/proc/meminfo"],
            });
            expect(result.exitCode).toBe(0);
            expect(result.stdout.length).toBeGreaterThan(100);
        });
    });

    // ── Additional: permission denied detection ────────────────────────

    describe("executeCommand — permissionDenied detection", () => {
        it("should detect permission denied on /etc/shadow (non-root)", async () => {
            // Only test if we're not root
            if (process.getuid?.() === 0) return;
            const result = await executeCommand({
                command: "cat",
                args: ["/etc/shadow"],
            });
            expect(result.exitCode).not.toBe(0);
            expect(result.permissionDenied).toBe(true);
        });

        it("should not flag permissionDenied on timeouts", async () => {
            const result = await executeCommand({
                command: "cat",
                args: [],
                timeout: 300,
            });
            expect(result.timedOut).toBe(true);
            expect(result.permissionDenied).toBe(false);
        }, 10000);

        it("should not flag permissionDenied on file-not-found", async () => {
            const result = await executeCommand({
                command: "cat",
                args: ["/nonexistent/file/for/test"],
            });
            expect(result.exitCode).not.toBe(0);
            expect(result.permissionDenied).toBe(false);
        });
    });

    // ── Additional: env option merging ─────────────────────────────────

    describe("executeCommand — environment merging", () => {
        it("should merge env with process.env", async () => {
            const result = await executeCommand({
                command: "env",
                args: [],
                env: { KALI_TEST_VAR_A: "alpha", KALI_TEST_VAR_B: "beta" },
            });
            expect(result.exitCode).toBe(0);
            expect(result.stdout).toContain("KALI_TEST_VAR_A=alpha");
            expect(result.stdout).toContain("KALI_TEST_VAR_B=beta");
        });

        it("should still have PATH from process.env when custom env is set", async () => {
            const result = await executeCommand({
                command: "env",
                args: [],
                env: { KALI_CUSTOM: "yes" },
            });
            expect(result.exitCode).toBe(0);
            expect(result.stdout).toContain("PATH=");
        });
    });

    // ── Additional: multiple successive commands ───────────────────────

    describe("executeCommand — multiple calls", () => {
        it("should handle multiple concurrent commands", async () => {
            const results = await Promise.all([
                executeCommand({ command: "cat", args: ["/dev/null"] }),
                executeCommand({ command: "cat", args: ["/dev/null"] }),
                executeCommand({ command: "cat", args: ["/dev/null"] }),
            ]);
            for (const result of results) {
                expect(result.exitCode).toBe(0);
            }
        });
    });
});
