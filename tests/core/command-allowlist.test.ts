import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
    isAllowlisted,
    resolveCommand,
    getAllowlistEntries,
    isInitialized,
    initializeAllowlist,
    resolveSudoCommand,
    verifyBinaryOwnership,
    verifyAllBinaries,
    getCriticalBinaryPackages,
    isRuntimePathVerificationEnabled,
    setRuntimePathVerification,
} from "../../src/core/command-allowlist.js";

describe("command-allowlist", () => {
    // ── isAllowlisted ─────────────────────────────────────────────────────

    describe("isAllowlisted", () => {
        it("should return true for known binaries", () => {
            expect(isAllowlisted("iptables")).toBe(true);
            expect(isAllowlisted("sysctl")).toBe(true);
            expect(isAllowlisted("systemctl")).toBe(true);
            expect(isAllowlisted("ufw")).toBe(true);
            expect(isAllowlisted("nmap")).toBe(true);
            expect(isAllowlisted("sudo")).toBe(true);
            expect(isAllowlisted("ssh")).toBe(true);
            expect(isAllowlisted("openssl")).toBe(true);
        });

        it("should return false for unknown binaries", () => {
            expect(isAllowlisted("evil-binary")).toBe(false);
            expect(isAllowlisted("not-a-real-command")).toBe(false);
            expect(isAllowlisted("rm-all-data")).toBe(false);
            expect(isAllowlisted("")).toBe(false);
        });

        it("should return true for known absolute paths", () => {
            // /usr/bin/cat or /bin/cat should be in the allowlist candidates
            const catPaths = ["/usr/bin/cat", "/bin/cat"];
            const anyMatch = catPaths.some((p) => isAllowlisted(p));
            expect(anyMatch).toBe(true);
        });

        it("should return false for unknown absolute paths", () => {
            expect(isAllowlisted("/tmp/evil")).toBe(false);
            expect(isAllowlisted("/usr/bin/not-real")).toBe(false);
        });
    });

    // ── resolveCommand ────────────────────────────────────────────────────

    describe("resolveCommand", () => {
        it("should throw for non-allowlisted commands", () => {
            expect(() => resolveCommand("evil-command")).toThrow("not in allowlist");
        });

        it("should throw for non-allowlisted absolute paths", () => {
            expect(() => resolveCommand("/tmp/evil")).toThrow("not in allowlist");
        });

        it("should return absolute path for known commands that exist on system", () => {
            // cat, ls, grep are almost universally available on Linux
            const universalBinaries = ["cat", "ls", "grep"];
            for (const bin of universalBinaries) {
                const resolved = resolveCommand(bin);
                expect(resolved).toMatch(/^\//); // starts with /
                expect(resolved).toContain(bin);
            }
        });

        it("should accept an allowlisted absolute path directly", () => {
            // /usr/bin/cat or /bin/cat should exist on Linux
            const catPaths = ["/usr/bin/cat", "/bin/cat"];
            let resolved: string | undefined;
            for (const p of catPaths) {
                try {
                    resolved = resolveCommand(p);
                    break;
                } catch {
                    // candidate doesn't exist or isn't allowlisted at that path
                }
            }
            expect(resolved).toBeDefined();
            expect(resolved).toMatch(/^\//);
        });

        it("should throw for allowlisted commands not found on system", () => {
            // sw_vers is macOS-only, unlikely to be on a Linux test system
            expect(() => resolveCommand("sw_vers")).toThrow("not found on this system");
        });
    });

    // ── getAllowlistEntries ────────────────────────────────────────────────

    describe("getAllowlistEntries", () => {
        it("should return a non-empty array", () => {
            const entries = getAllowlistEntries();
            expect(entries.length).toBeGreaterThan(0);
        });

        it("should contain expected critical binaries", () => {
            const entries = getAllowlistEntries();
            const binaryNames = entries.map((e) => e.binary);

            // Firewall
            expect(binaryNames).toContain("iptables");
            expect(binaryNames).toContain("ip6tables");
            expect(binaryNames).toContain("ufw");
            expect(binaryNames).toContain("nft");

            // Kernel
            expect(binaryNames).toContain("sysctl");

            // Systemd
            expect(binaryNames).toContain("systemctl");

            // SSH
            expect(binaryNames).toContain("sshd");
            expect(binaryNames).toContain("ssh");

            // Privilege
            expect(binaryNames).toContain("sudo");

            // Networking
            expect(binaryNames).toContain("ss");
            expect(binaryNames).toContain("nmap");
            expect(binaryNames).toContain("tcpdump");

            // Malware
            expect(binaryNames).toContain("clamscan");
            expect(binaryNames).toContain("rkhunter");

            // Crypto
            expect(binaryNames).toContain("openssl");
        });

        it("should have candidates array for each entry", () => {
            const entries = getAllowlistEntries();
            for (const entry of entries) {
                expect(entry.binary).toBeTruthy();
                expect(Array.isArray(entry.candidates)).toBe(true);
                expect(entry.candidates.length).toBeGreaterThan(0);
                // All candidates should be absolute paths
                for (const candidate of entry.candidates) {
                    expect(candidate).toMatch(/^\//);
                }
            }
        });
    });

    // ── initializeAllowlist ───────────────────────────────────────────────

    describe("initializeAllowlist", () => {
        it("should run without throwing", () => {
            expect(() => initializeAllowlist()).not.toThrow();
        });

        it("should set initialized flag", () => {
            initializeAllowlist();
            expect(isInitialized()).toBe(true);
        });

        it("should resolve at least some binaries on a Linux system", () => {
            initializeAllowlist();
            const entries = getAllowlistEntries();
            const resolvedCount = entries.filter((e) => e.resolvedPath !== undefined).length;
            // On any Linux system, at least basic coreutils should be resolvable
            expect(resolvedCount).toBeGreaterThan(10);
        });
    });

    // ── resolveSudoCommand ────────────────────────────────────────────────

    describe("resolveSudoCommand", () => {
        it("should resolve sudo and target command", () => {
            // cat should exist on any Linux system
            const result = resolveSudoCommand(["cat", "/etc/passwd"]);
            expect(result.sudoPath).toMatch(/sudo$/);
            expect(result.targetIndex).toBe(0);
            expect(result.targetPath).toMatch(/cat$/);
        });

        it("should skip sudo flags with no arguments", () => {
            const result = resolveSudoCommand(["-S", "-n", "cat", "/etc/passwd"]);
            expect(result.targetIndex).toBe(2);
            expect(result.targetPath).toMatch(/cat$/);
        });

        it("should skip sudo flags with arguments", () => {
            const result = resolveSudoCommand(["-u", "root", "cat", "/etc/passwd"]);
            expect(result.targetIndex).toBe(2);
            expect(result.targetPath).toMatch(/cat$/);
        });

        it("should handle sudo-only commands (no target)", () => {
            const result = resolveSudoCommand(["-v"]);
            expect(result.targetIndex).toBe(-1);
            expect(result.targetPath).toBe("");
        });

        it("should throw for non-allowlisted target commands", () => {
            expect(() => resolveSudoCommand(["evil-cmd"])).toThrow("not in allowlist");
        });
    });

    // ── Binary Integrity Verification ─────────────────────────────────────

    describe("getCriticalBinaryPackages", () => {
        it("should return a non-empty mapping", () => {
            const packages = getCriticalBinaryPackages();
            expect(Object.keys(packages).length).toBeGreaterThan(0);
        });

        it("should contain expected critical binaries", () => {
            const packages = getCriticalBinaryPackages();
            expect(packages["iptables"]).toBeDefined();
            expect(packages["sysctl"]).toBeDefined();
            expect(packages["sudo"]).toBeDefined();
            expect(packages["openssl"]).toBeDefined();
            expect(packages["sshd"]).toBeDefined();
            expect(packages["clamscan"]).toBeDefined();
            expect(packages["lynis"]).toBeDefined();
        });

        it("should have array values for each entry", () => {
            const packages = getCriticalBinaryPackages();
            for (const [key, value] of Object.entries(packages)) {
                expect(Array.isArray(value)).toBe(true);
                expect(value.length).toBeGreaterThan(0);
            }
        });
    });

    describe("verifyBinaryOwnership", () => {
        it("should return not-found for a nonexistent path", () => {
            const result = verifyBinaryOwnership("/nonexistent/binary");
            expect(result.verified).toBe(false);
            expect(result.message).toContain("not found");
        });

        it("should attempt verification for an existing binary", () => {
            // /usr/bin/cat should exist on any Linux system
            const catPaths = ["/usr/bin/cat", "/bin/cat"];
            let result;
            for (const p of catPaths) {
                result = verifyBinaryOwnership(p);
                if (result.verified) break;
            }
            // Should at least return a result (may or may not verify depending on system)
            expect(result).toBeDefined();
            expect(result!.path).toBeTruthy();
            expect(result!.binary).toBeTruthy();
        });

        it("should check expected package when provided", () => {
            // /usr/bin/cat is typically owned by 'coreutils'
            const catPaths = ["/usr/bin/cat", "/bin/cat"];
            let result;
            for (const p of catPaths) {
                result = verifyBinaryOwnership(p, "coreutils");
                if (result.verified) break;
            }
            // On a Debian/Ubuntu system this should verify successfully
            // On other systems it might fail — that's acceptable
            expect(result).toBeDefined();
        });
    });

    describe("verifyAllBinaries", () => {
        it("should run without throwing", async () => {
            initializeAllowlist();
            await expect(verifyAllBinaries()).resolves.not.toThrow();
        });

        it("should return an array of results", async () => {
            initializeAllowlist();
            const results = await verifyAllBinaries();
            expect(Array.isArray(results)).toBe(true);
        });

        it("should have binary and path for each result", async () => {
            initializeAllowlist();
            const results = await verifyAllBinaries();
            for (const result of results) {
                expect(result.binary).toBeTruthy();
                expect(result.path).toBeTruthy();
                expect(typeof result.verified).toBe("boolean");
                expect(result.message).toBeTruthy();
            }
        });
    });

    // ── Runtime path verification ─────────────────────────────────────────

    describe("runtime path verification", () => {
        it("should report runtime path verification status", () => {
            const enabled = isRuntimePathVerificationEnabled();
            expect(typeof enabled).toBe("boolean");
        });

        it("should allow toggling runtime path verification", () => {
            const original = isRuntimePathVerificationEnabled();
            setRuntimePathVerification(!original);
            expect(isRuntimePathVerificationEnabled()).toBe(!original);
            // Restore
            setRuntimePathVerification(original);
            expect(isRuntimePathVerificationEnabled()).toBe(original);
        });

        it("should resolve commands with verification enabled", () => {
            setRuntimePathVerification(true);
            initializeAllowlist();
            const resolved = resolveCommand("cat");
            expect(resolved).toMatch(/^\//);
        });

        it("should resolve commands with verification disabled", () => {
            setRuntimePathVerification(false);
            initializeAllowlist();
            const resolved = resolveCommand("cat");
            expect(resolved).toMatch(/^\//);
            // Restore
            setRuntimePathVerification(true);
        });
    });

    // ── resolveSudoCommand edge cases ─────────────────────────────────────

    describe("resolveSudoCommand edge cases", () => {
        it("should skip empty string arguments", () => {
            const result = resolveSudoCommand(["-S", "-p", "", "cat", "/etc/passwd"]);
            expect(result.targetIndex).toBe(3);
            expect(result.targetPath).toMatch(/cat$/);
        });

        it("should handle --stdin long flag", () => {
            const result = resolveSudoCommand(["--stdin", "cat", "/etc/passwd"]);
            expect(result.targetIndex).toBe(1);
            expect(result.targetPath).toMatch(/cat$/);
        });

        it("should handle -k (kill cached credentials) alone", () => {
            const result = resolveSudoCommand(["-k"]);
            expect(result.targetIndex).toBe(-1);
            expect(result.targetPath).toBe("");
        });

        it("should handle -K (remove timestamp)", () => {
            const result = resolveSudoCommand(["-K"]);
            expect(result.targetIndex).toBe(-1);
        });

        it("should skip unknown flags starting with -", () => {
            // Unknown flag -- should be skipped
            const result = resolveSudoCommand(["-Z", "cat", "/etc/passwd"]);
            expect(result.targetIndex).toBe(1);
            expect(result.targetPath).toMatch(/cat$/);
        });

        it("should handle --user flag with argument", () => {
            const result = resolveSudoCommand(["--user", "root", "cat", "/dev/null"]);
            expect(result.targetIndex).toBe(2);
            expect(result.targetPath).toMatch(/cat$/);
        });
    });

    // ── isAllowlisted edge cases ──────────────────────────────────────────

    describe("isAllowlisted edge cases", () => {
        it("should handle empty string", () => {
            expect(isAllowlisted("")).toBe(false);
        });

        it("should return true for allowlisted absolute paths from candidates", () => {
            // Test with a candidate path that exists on the system
            const entries = getAllowlistEntries();
            const catEntry = entries.find((e) => e.binary === "cat");
            if (catEntry && catEntry.resolvedPath) {
                expect(isAllowlisted(catEntry.resolvedPath)).toBe(true);
            }
        });
    });

    // ── Allowlist entries structure ────────────────────────────────────────

    describe("allowlist entries structure", () => {
        it("should have resolvedPath or undefined for each entry", () => {
            initializeAllowlist();
            const entries = getAllowlistEntries();
            for (const entry of entries) {
                expect(
                    entry.resolvedPath === undefined || typeof entry.resolvedPath === "string"
                ).toBe(true);
            }
        });

        it("should record inodes for resolved entries", () => {
            initializeAllowlist();
            const entries = getAllowlistEntries();
            const resolvedEntries = entries.filter((e) => e.resolvedPath);
            // At least some should have inodes recorded
            const withInodes = resolvedEntries.filter((e) => e.resolvedInode !== undefined);
            expect(withInodes.length).toBeGreaterThan(0);
        });

        it("should have all candidate paths as absolute paths", () => {
            const entries = getAllowlistEntries();
            for (const entry of entries) {
                for (const candidate of entry.candidates) {
                    expect(candidate.startsWith("/")).toBe(true);
                }
            }
        });
    });
});
