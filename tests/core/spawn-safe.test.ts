import { describe, it, expect, beforeAll } from "vitest";
import { spawnSafe, execFileSafe } from "../../src/core/spawn-safe.js";
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
            // Use grep with a fixed string against /dev/null to get empty output, or use cat
            const result = execFileSafe("sh", ["-c", "echo hello_spawn_safe"], {
                encoding: "utf-8",
            });
            expect(result).toContain("hello_spawn_safe");
        });

        it("should reject non-allowlisted commands", () => {
            expect(() => execFileSafe("evil_binary", [])).toThrow(/allowlist/i);
        });

        it("should reject non-allowlisted absolute paths", () => {
            expect(() => execFileSafe("/tmp/evil-script", [])).toThrow(/allowlist/i);
        });

        it("should allow bypassing the allowlist when bypassAllowlist is true", () => {
            // /usr/bin/cat should work with bypass — it's a real binary
            const result = execFileSafe("/usr/bin/cat", ["/dev/null"], {
                bypassAllowlist: true,
            });
            expect(Buffer.isBuffer(result) || typeof result === "string").toBe(true);
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
            // sh -c "sleep 60" with a 500ms timeout should throw
            expect(() =>
                execFileSafe("sh", ["-c", "sleep 60"], { timeout: 500 })
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
            const child = spawnSafe("sh", ["-c", "echo spawn_output_test"]);
            const output = await new Promise<string>((resolve, reject) => {
                let data = "";
                child.stdout?.on("data", (chunk: Buffer) => {
                    data += chunk.toString();
                });
                child.on("close", () => resolve(data));
                child.on("error", reject);
            });
            expect(output).toContain("spawn_output_test");
        });

        it("should exit with code 0 for successful commands", async () => {
            const child = spawnSafe("cat", ["/dev/null"]);
            const code = await new Promise<number | null>((resolve, reject) => {
                child.on("close", resolve);
                child.on("error", reject);
            });
            expect(code).toBe(0);
        });

        it("should allow bypassing allowlist", () => {
            const child = spawnSafe("/usr/bin/cat", ["/dev/null"], {
                bypassAllowlist: true,
            });
            expect(child).toBeDefined();
            child.kill();
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
            const result = execFileSafe("sh", ["-c", "echo $SPAWN_TEST_VAR"], {
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
});
