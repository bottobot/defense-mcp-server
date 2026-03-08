import { describe, it, expect, beforeAll } from "vitest";
import { spawnSafe, execFileSafe, redactArgs } from "../../src/core/spawn-safe.js";
import { initializeAllowlist } from "../../src/core/command-allowlist.js";

describe("spawn-safe", () => {
    beforeAll(() => {
        initializeAllowlist();
    });

    // ── execFileSafe ─────────────────────────────────────────────────────

    describe("execFileSafe", () => {
        it("should execute an allowlisted command synchronously", () => {
            const result = execFileSafe("cat", ["/dev/null"]);
            // Result is Buffer by default (no encoding option)
            expect(Buffer.isBuffer(result)).toBe(true);
        });

        it("should return output as string when encoding is specified", () => {
            const result = execFileSafe("cat", ["/dev/null"], { encoding: "utf-8" });
            expect(typeof result).toBe("string");
        });

        it("should capture stdout from a command", () => {
            // Use cat with stdin to produce known output (no shell needed)
            const result = execFileSafe("cat", ["/proc/version"], {
                encoding: "utf-8",
            });
            expect(typeof result).toBe("string");
            expect((result as string).length).toBeGreaterThan(0);
        });

        it("should reject non-allowlisted commands", () => {
            expect(() => execFileSafe("evil_binary", [])).toThrow(/allowlist/i);
        });

        it("should reject non-allowlisted absolute paths", () => {
            expect(() => execFileSafe("/tmp/evil-script", [])).toThrow(/allowlist/i);
        });

        it("should reject commands even if bypassAllowlist is passed as an option", () => {
            // Verify there is no escape hatch — passing bypassAllowlist as an
            // unknown option must NOT skip allowlist validation.
            expect(() =>
                execFileSafe("not_a_real_binary", [], {
                    bypassAllowlist: true,
                } as any)
            ).toThrow(/allowlist/i);
        });

        it("should always use shell: false (no shell injection)", () => {
            // Attempt shell metacharacters — they should be treated as literal args
            expect(() =>
                execFileSafe("cat", ["/dev/null; echo injected"], { encoding: "utf-8" })
            ).toThrow(); // cat will try to open a file literally named "/dev/null; echo injected"
        });

        it("should throw on command failure (non-zero exit)", () => {
            expect(() =>
                execFileSafe("cat", ["/nonexistent/path/that/cannot/exist"])
            ).toThrow();
        });

        it("should timeout long-running commands", () => {
            // tail -f /dev/null will hang forever — perfect for timeout test
            expect(() =>
                execFileSafe("tail", ["-f", "/dev/null"], { timeout: 500 })
            ).toThrow();
        }, 10000);
    });

    // ── spawnSafe ────────────────────────────────────────────────────────

    describe("spawnSafe", () => {
        it("should return a ChildProcess for allowlisted commands", () => {
            const child = spawnSafe("cat", ["/dev/null"]);
            expect(child).toBeDefined();
            expect(child.pid).toBeDefined();
            // Clean up
            child.kill();
        });

        it("should throw for non-allowlisted commands", () => {
            expect(() => spawnSafe("evil_binary", [])).toThrow(/allowlist/i);
        });

        it("should produce stdout data via events", async () => {
            const child = spawnSafe("cat", ["/proc/version"]);
            const output = await new Promise<string>((resolve, reject) => {
                let data = "";
                child.stdout?.on("data", (chunk: Buffer) => {
                    data += chunk.toString();
                });
                child.on("close", () => resolve(data));
                child.on("error", reject);
            });
            expect(output.length).toBeGreaterThan(0);
        });

        it("should exit with code 0 for successful commands", async () => {
            const child = spawnSafe("cat", ["/dev/null"]);
            const code = await new Promise<number | null>((resolve, reject) => {
                child.on("close", resolve);
                child.on("error", reject);
            });
            expect(code).toBe(0);
        });

        it("should reject commands even if bypassAllowlist is passed as an option", () => {
            // Verify there is no escape hatch — passing bypassAllowlist as an
            // unknown option must NOT skip allowlist validation.
            expect(() =>
                spawnSafe("not_a_real_binary", [], {
                    bypassAllowlist: true,
                } as any)
            ).toThrow(/allowlist/i);
        });

        it("should report non-zero exit for failed commands", async () => {
            const child = spawnSafe("cat", ["/nonexistent/file/path"]);
            const code = await new Promise<number | null>((resolve, reject) => {
                child.on("close", resolve);
                child.on("error", reject);
            });
            expect(code).not.toBe(0);
        });
    });

    // ── Type interface checks ────────────────────────────────────────────

    describe("SpawnSafeOptions / ExecFileSafeOptions", () => {
        it("should accept cwd option in execFileSafe", () => {
            const result = execFileSafe("cat", ["/dev/null"], {
                cwd: "/tmp",
                encoding: "utf-8",
            });
            expect(typeof result).toBe("string");
        });

        it("should accept env option in execFileSafe", () => {
            const result = execFileSafe("env", [], {
                env: { ...process.env, SPAWN_TEST_VAR: "spawn_env_test" },
                encoding: "utf-8",
            });
            expect(result).toContain("spawn_env_test");
        });

        it("should accept cwd option in spawnSafe", async () => {
            const child = spawnSafe("cat", ["/dev/null"], { cwd: "/tmp" });
            const code = await new Promise<number | null>((resolve, reject) => {
                child.on("close", resolve);
                child.on("error", reject);
            });
            expect(code).toBe(0);
        });
    });

    // ── redactArgs ───────────────────────────────────────────────────────

    describe("redactArgs", () => {
        it("should not modify args without sensitive flags", () => {
            const result = redactArgs("cat", ["/etc/hosts", "--verbose"]);
            expect(result).toEqual(["/etc/hosts", "--verbose"]);
        });

        it("should redact argument after --password flag", () => {
            const result = redactArgs("some-tool", ["--password", "secret123"]);
            expect(result[0]).toBe("--password");
            expect(result[1]).toBe("[REDACTED]");
        });

        it("should redact argument after --token flag", () => {
            const result = redactArgs("some-tool", ["--token", "abc-def-ghi"]);
            expect(result[1]).toBe("[REDACTED]");
        });

        it("should redact argument after --key flag", () => {
            const result = redactArgs("some-tool", ["--key", "my-api-key"]);
            expect(result[1]).toBe("[REDACTED]");
        });

        it("should redact argument after --secret flag", () => {
            const result = redactArgs("some-tool", ["--secret", "top-secret"]);
            expect(result[1]).toBe("[REDACTED]");
        });

        it("should redact --password=value style", () => {
            const result = redactArgs("some-tool", ["--password=secret123"]);
            expect(result[0]).toBe("--password=[REDACTED]");
        });

        it("should redact --token=value style", () => {
            const result = redactArgs("some-tool", ["--token=abc123"]);
            expect(result[0]).toBe("--token=[REDACTED]");
        });

        it("should not mutate the original array", () => {
            const original = ["--password", "secret"];
            const result = redactArgs("tool", original);
            expect(original[1]).toBe("secret");
            expect(result[1]).toBe("[REDACTED]");
        });

        it("should handle sudo -S flag (redact next non-flag arg)", () => {
            const result = redactArgs("sudo", ["-S", "password-here", "cat", "/etc/shadow"]);
            expect(result[1]).toBe("[REDACTED]");
            expect(result[2]).toBe("cat");
        });

        it("should not redact sudo -S when followed by a flag", () => {
            const result = redactArgs("sudo", ["-S", "-n", "cat"]);
            expect(result[1]).toBe("-n"); // Not redacted because it starts with -
        });

        it("should handle empty args array", () => {
            const result = redactArgs("tool", []);
            expect(result).toEqual([]);
        });
    });

    // ── execFileSafe stdin buffer cleanup ────────────────────────────────

    describe("execFileSafe stdin buffer cleanup", () => {
        it("should zero input buffer after execution", () => {
            const inputBuf = Buffer.from("sensitive-data");
            try {
                execFileSafe("cat", [], { input: inputBuf });
            } catch {
                // cat with no args + stdin may produce output or error
            }
            // Buffer should be zeroed after execution (CORE-011)
            expect(inputBuf.every((b) => b === 0)).toBe(true);
        });

        it("should zero input buffer even on execution failure", () => {
            const inputBuf = Buffer.from("sensitive-data");
            try {
                execFileSafe("cat", ["/nonexistent-file-path"], { input: inputBuf });
            } catch {
                // Expected to throw
            }
            expect(inputBuf.every((b) => b === 0)).toBe(true);
        });
    });
});
