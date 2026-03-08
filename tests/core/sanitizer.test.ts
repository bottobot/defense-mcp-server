import { describe, it, expect } from "vitest";
import {
    sanitizeArgs,
    validateTarget,
    validatePort,
    validatePortRange,
    validateFilePath,
    validateServiceName,
    validateSysctlKey,
    validateConfigKey,
    validatePackageName,
    validateIptablesChain,
    validateInterface,
    validateUsername,
    validateYaraRule,
    validateCertPath,
    validateFirewallZone,
    validateAuditdKey,
    validateToolPath,
    sanitizeToolError,
} from "../../src/core/sanitizer.js";
import type { DefenseConfig } from "../../src/core/config.js";

// Helper to create a config that allows /tmp paths
function tmpConfig(): DefenseConfig {
    return {
        defaultTimeout: 120_000,
        maxBuffer: 10 * 1024 * 1024,
        allowedDirs: ["/tmp", "/home", "/var/log", "/etc"],
        logLevel: "info",
        dryRun: false,
        changelogPath: "/tmp/test-changelog.json",
        backupDir: "/tmp/test-backups",
        backupEnabled: true,
        autoInstall: false,
        protectedPaths: ["/boot", "/usr/lib/systemd", "/usr/bin", "/usr/sbin"],
        requireConfirmation: true,
        quarantineDir: "/tmp/test-quarantine",
        policyDir: "/tmp/test-policies",
        toolTimeouts: {},
        sudoSessionTimeout: 15 * 60 * 1000,
        commandTimeout: 120_000,
        networkTimeout: 30_000,
    };
}

describe("sanitizer", () => {
    // ── sanitizeArgs ──────────────────────────────────────────────────────

    describe("sanitizeArgs", () => {
        it("should reject shell metacharacter semicolon", () => {
            expect(() => sanitizeArgs(["foo;bar"])).toThrow("forbidden shell metacharacters");
        });

        it("should reject shell metacharacter pipe", () => {
            expect(() => sanitizeArgs(["foo|bar"])).toThrow("forbidden shell metacharacters");
        });

        it("should reject shell metacharacter ampersand", () => {
            expect(() => sanitizeArgs(["foo&bar"])).toThrow("forbidden shell metacharacters");
        });

        it("should reject shell metacharacter backtick", () => {
            expect(() => sanitizeArgs(["foo`bar"])).toThrow("forbidden shell metacharacters");
        });

        it("should reject shell metacharacter dollar-paren $(...)", () => {
            expect(() => sanitizeArgs(["$(whoami)"])).toThrow("forbidden shell metacharacters");
        });

        it("should reject shell metacharacter curly braces", () => {
            expect(() => sanitizeArgs(["{a,b}"])).toThrow("forbidden shell metacharacters");
        });

        it("should reject shell metacharacter angle brackets", () => {
            expect(() => sanitizeArgs(["foo>bar"])).toThrow("forbidden shell metacharacters");
            expect(() => sanitizeArgs(["foo<bar"])).toThrow("forbidden shell metacharacters");
        });

        it("should reject newlines", () => {
            expect(() => sanitizeArgs(["foo\nbar"])).toThrow("forbidden shell metacharacters");
            expect(() => sanitizeArgs(["foo\rbar"])).toThrow("forbidden shell metacharacters");
        });

        it("should reject control characters (null byte)", () => {
            expect(() => sanitizeArgs(["foo\x00bar"])).toThrow("control characters");
        });

        it("should reject control characters (other)", () => {
            expect(() => sanitizeArgs(["foo\x01bar"])).toThrow("control characters");
            expect(() => sanitizeArgs(["foo\x7fbar"])).toThrow("control characters");
        });

        it("should accept clean arguments", () => {
            const args = ["192.168.1.1", "eth0", "22", "--verbose", "myfile.txt"];
            expect(sanitizeArgs(args)).toEqual(args);
        });

        it("should accept empty array", () => {
            expect(sanitizeArgs([])).toEqual([]);
        });

        it("should accept single empty string argument", () => {
            // Empty strings don't contain metacharacters
            expect(sanitizeArgs([""])).toEqual([""]);
        });

        it("should reject non-array input", () => {
            expect(() => sanitizeArgs("not-an-array" as unknown as string[])).toThrow(
                "Arguments must be an array"
            );
        });

        it("should reject non-string elements", () => {
            expect(() => sanitizeArgs([123 as unknown as string])).toThrow(
                "not a string"
            );
        });

        it("should accept arguments with hyphens and dots", () => {
            expect(sanitizeArgs(["--timeout=30", "my.file.txt", "-v"])).toEqual([
                "--timeout=30",
                "my.file.txt",
                "-v",
            ]);
        });

        it("should accept unicode characters that are not control chars", () => {
            // Unicode letters should pass through (no shell metacharacters)
            expect(sanitizeArgs(["café"])).toEqual(["café"]);
        });
    });

    // ── validateTarget ────────────────────────────────────────────────────

    describe("validateTarget", () => {
        it("should accept valid IPv4 address", () => {
            expect(validateTarget("192.168.1.1")).toBe("192.168.1.1");
        });

        it("should accept IPv4 with CIDR", () => {
            expect(validateTarget("10.0.0.0/8")).toBe("10.0.0.0/8");
        });

        it("should accept valid IPv6 address", () => {
            expect(validateTarget("::1")).toBe("::1");
            expect(validateTarget("fe80::1")).toBe("fe80::1");
        });

        it("should accept valid hostname", () => {
            expect(validateTarget("example.com")).toBe("example.com");
            expect(validateTarget("my-host")).toBe("my-host");
        });

        it("should reject empty string", () => {
            expect(() => validateTarget("")).toThrow("non-empty string");
        });

        it("should reject shell metacharacters in target", () => {
            expect(() => validateTarget("192.168.1.1;rm -rf /")).toThrow(
                "forbidden shell metacharacters"
            );
        });

        it("should reject control characters", () => {
            expect(() => validateTarget("host\x00name")).toThrow("control characters");
        });

        it("should reject invalid IPv4 octets", () => {
            expect(() => validateTarget("999.999.999.999")).toThrow("Invalid IPv4");
        });

        it("should reject invalid CIDR prefix", () => {
            expect(() => validateTarget("10.0.0.0/33")).toThrow("Invalid CIDR");
        });

        it("should trim whitespace", () => {
            expect(validateTarget("  192.168.1.1  ")).toBe("192.168.1.1");
        });

        it("should accept localhost", () => {
            expect(validateTarget("localhost")).toBe("localhost");
        });
    });

    // ── validatePort ──────────────────────────────────────────────────────

    describe("validatePort", () => {
        it("should accept valid port number", () => {
            expect(validatePort(80)).toBe(80);
            expect(validatePort(443)).toBe(443);
        });

        it("should accept string port number", () => {
            expect(validatePort("22")).toBe(22);
        });

        it("should accept boundary values", () => {
            expect(validatePort(1)).toBe(1);
            expect(validatePort(65535)).toBe(65535);
        });

        it("should reject port 0", () => {
            expect(() => validatePort(0)).toThrow("Invalid port");
        });

        it("should reject port above 65535", () => {
            expect(() => validatePort(65536)).toThrow("Invalid port");
        });

        it("should reject negative port", () => {
            expect(() => validatePort(-1)).toThrow("Invalid port");
        });

        it("should reject NaN", () => {
            expect(() => validatePort("abc")).toThrow("Invalid port");
        });

        it("should reject float", () => {
            expect(() => validatePort(80.5)).toThrow("Invalid port");
        });
    });

    // ── validatePortRange ─────────────────────────────────────────────────

    describe("validatePortRange", () => {
        it("should accept single port", () => {
            expect(validatePortRange("80")).toBe("80");
        });

        it("should accept port range", () => {
            expect(validatePortRange("1-1024")).toBe("1-1024");
        });

        it("should accept comma-separated ports", () => {
            expect(validatePortRange("80,443")).toBe("80,443");
        });

        it("should accept mixed ports and ranges", () => {
            expect(validatePortRange("80,443,8000-9000")).toBe("80,443,8000-9000");
        });

        it("should reject empty string", () => {
            expect(() => validatePortRange("")).toThrow("non-empty string");
        });

        it("should reject shell metacharacters", () => {
            expect(() => validatePortRange("80;rm")).toThrow("forbidden shell metacharacters");
        });

        it("should reject invalid range (start > end)", () => {
            expect(() => validatePortRange("9000-8000")).toThrow("start > end");
        });

        it("should reject port out of range", () => {
            expect(() => validatePortRange("0")).toThrow("Port out of range");
            expect(() => validatePortRange("70000")).toThrow("Port out of range");
        });
    });

    // ── validateFilePath ──────────────────────────────────────────────────

    describe("validateFilePath", () => {
        const cfg = tmpConfig();

        it("should accept path within allowed directories", () => {
            const result = validateFilePath("/tmp/test.txt", cfg);
            expect(result).toBe("/tmp/test.txt");
        });

        it("should reject null bytes", () => {
            expect(() => validateFilePath("/tmp/test\0.txt", cfg)).toThrow("null bytes");
        });

        it("should reject path traversal with ..", () => {
            expect(() => validateFilePath("/tmp/../etc/shadow", cfg)).toThrow(
                "directory traversal"
            );
        });

        it("should reject shell metacharacters in path", () => {
            expect(() => validateFilePath("/tmp/test;rm -rf /", cfg)).toThrow(
                "forbidden shell metacharacters"
            );
        });

        it("should reject control characters in path", () => {
            expect(() => validateFilePath("/tmp/test\x01file", cfg)).toThrow(
                "control characters"
            );
        });

        it("should reject empty path", () => {
            expect(() => validateFilePath("", cfg)).toThrow("non-empty string");
        });

        it("should reject paths outside allowed directories", () => {
            expect(() => validateFilePath("/opt/secret", cfg)).toThrow(
                "not within allowed directories"
            );
        });

        it("should reject protected paths", () => {
            // /boot must be in allowedDirs so it passes the first check,
            // then gets caught by the protectedPaths check
            const cfgWithBoot = {
                ...cfg,
                allowedDirs: [...cfg.allowedDirs, "/boot"],
            };
            expect(() => validateFilePath("/boot/grub/grub.cfg", cfgWithBoot)).toThrow(
                "protected location"
            );
        });

        it("should accept path in /etc (allowed dir)", () => {
            const result = validateFilePath("/etc/ssh/sshd_config", cfg);
            expect(result).toBe("/etc/ssh/sshd_config");
        });
    });

    // ── validateServiceName ───────────────────────────────────────────────

    describe("validateServiceName", () => {
        it("should accept valid service names", () => {
            expect(validateServiceName("ssh.service")).toBe("ssh.service");
            expect(validateServiceName("sshd")).toBe("sshd");
            expect(validateServiceName("bluetooth.service")).toBe("bluetooth.service");
            expect(validateServiceName("user@1000.service")).toBe("user@1000.service");
        });

        it("should reject empty string", () => {
            expect(() => validateServiceName("")).toThrow("non-empty string");
        });

        it("should reject shell metacharacters", () => {
            expect(() => validateServiceName("ssh;evil")).toThrow("Invalid service name");
        });

        it("should reject spaces", () => {
            expect(() => validateServiceName("my service")).toThrow("Invalid service name");
        });

        it("should trim whitespace", () => {
            expect(validateServiceName("  sshd  ")).toBe("sshd");
        });
    });

    // ── validateSysctlKey ─────────────────────────────────────────────────

    describe("validateSysctlKey", () => {
        it("should accept valid sysctl keys", () => {
            expect(validateSysctlKey("net.ipv4.ip_forward")).toBe("net.ipv4.ip_forward");
            expect(validateSysctlKey("kernel.randomize_va_space")).toBe(
                "kernel.randomize_va_space"
            );
        });

        it("should reject single word (no dots)", () => {
            expect(() => validateSysctlKey("kernel")).toThrow("Invalid sysctl key");
        });

        it("should reject empty string", () => {
            expect(() => validateSysctlKey("")).toThrow("non-empty string");
        });

        it("should reject shell metacharacters", () => {
            expect(() => validateSysctlKey("net;evil.key")).toThrow("Invalid sysctl key");
        });
    });

    // ── validateConfigKey ─────────────────────────────────────────────────

    describe("validateConfigKey", () => {
        it("should accept valid config keys", () => {
            expect(validateConfigKey("PermitRootLogin")).toBe("PermitRootLogin");
            expect(validateConfigKey("max-auth-tries")).toBe("max-auth-tries");
            expect(validateConfigKey("net.ipv4.forward")).toBe("net.ipv4.forward");
        });

        it("should reject empty string", () => {
            expect(() => validateConfigKey("")).toThrow("non-empty string");
        });

        it("should reject spaces", () => {
            expect(() => validateConfigKey("my key")).toThrow("Invalid config key");
        });
    });

    // ── validatePackageName ───────────────────────────────────────────────

    describe("validatePackageName", () => {
        it("should accept valid package names", () => {
            expect(validatePackageName("nginx")).toBe("nginx");
            expect(validatePackageName("libssl1.1")).toBe("libssl1.1");
            expect(validatePackageName("g++")).toBe("g++");
            expect(validatePackageName("python3.10")).toBe("python3.10");
        });

        it("should reject empty string", () => {
            expect(() => validatePackageName("")).toThrow("non-empty string");
        });

        it("should reject shell metacharacters", () => {
            expect(() => validatePackageName("pkg;evil")).toThrow("Invalid package name");
        });
    });

    // ── validateIptablesChain ─────────────────────────────────────────────

    describe("validateIptablesChain", () => {
        it("should accept built-in chains", () => {
            expect(validateIptablesChain("INPUT")).toBe("INPUT");
            expect(validateIptablesChain("OUTPUT")).toBe("OUTPUT");
            expect(validateIptablesChain("FORWARD")).toBe("FORWARD");
        });

        it("should accept custom chains", () => {
            expect(validateIptablesChain("syn_flood")).toBe("syn_flood");
            expect(validateIptablesChain("MY-CHAIN")).toBe("MY-CHAIN");
        });

        it("should reject empty string", () => {
            expect(() => validateIptablesChain("")).toThrow("non-empty string");
        });

        it("should reject chains starting with numbers", () => {
            expect(() => validateIptablesChain("123chain")).toThrow("Invalid iptables chain");
        });

        it("should reject chains that are too long (>29 chars)", () => {
            expect(() => validateIptablesChain("a".repeat(30))).toThrow(
                "Invalid iptables chain"
            );
        });
    });

    // ── validateInterface ─────────────────────────────────────────────────

    describe("validateInterface", () => {
        it("should accept valid interface names", () => {
            expect(validateInterface("eth0")).toBe("eth0");
            expect(validateInterface("wlan0")).toBe("wlan0");
            expect(validateInterface("lo")).toBe("lo");
            expect(validateInterface("any")).toBe("any");
        });

        it("should reject empty string", () => {
            expect(() => validateInterface("")).toThrow("non-empty string");
        });

        it("should reject names longer than 16 chars", () => {
            expect(() => validateInterface("a".repeat(17))).toThrow("too long");
        });

        it("should reject shell metacharacters", () => {
            expect(() => validateInterface("eth0;evil")).toThrow("Invalid interface name");
        });
    });

    // ── validateUsername ───────────────────────────────────────────────────

    describe("validateUsername", () => {
        it("should accept valid usernames", () => {
            expect(validateUsername("root")).toBe("root");
            expect(validateUsername("www-data")).toBe("www-data");
            expect(validateUsername("user.name")).toBe("user.name");
        });

        it("should reject empty string", () => {
            expect(() => validateUsername("")).toThrow("non-empty string");
        });

        it("should reject names longer than 32 chars", () => {
            expect(() => validateUsername("a".repeat(33))).toThrow("too long");
        });

        it("should reject shell metacharacters", () => {
            expect(() => validateUsername("root;evil")).toThrow("Invalid username");
        });
    });

    // ── validateYaraRule ──────────────────────────────────────────────────

    describe("validateYaraRule", () => {
        it("should accept .yar files", () => {
            expect(validateYaraRule("/rules/test.yar")).toBe("/rules/test.yar");
        });

        it("should accept .yara files", () => {
            expect(validateYaraRule("/rules/test.yara")).toBe("/rules/test.yara");
        });

        it("should reject non-yara extensions", () => {
            expect(() => validateYaraRule("/rules/test.txt")).toThrow("Must end in .yar");
        });

        it("should reject path traversal", () => {
            expect(() => validateYaraRule("../etc/test.yar")).toThrow("directory traversal");
        });

        it("should reject empty string", () => {
            expect(() => validateYaraRule("")).toThrow("non-empty string");
        });
    });

    // ── validateCertPath ──────────────────────────────────────────────────

    describe("validateCertPath", () => {
        it("should accept .pem files", () => {
            expect(validateCertPath("/certs/ca.pem")).toBe("/certs/ca.pem");
        });

        it("should accept .crt files", () => {
            expect(validateCertPath("/certs/server.crt")).toBe("/certs/server.crt");
        });

        it("should accept .key files", () => {
            expect(validateCertPath("/certs/server.key")).toBe("/certs/server.key");
        });

        it("should accept .p12 and .pfx files", () => {
            expect(validateCertPath("/certs/cert.p12")).toBe("/certs/cert.p12");
            expect(validateCertPath("/certs/cert.pfx")).toBe("/certs/cert.pfx");
        });

        it("should reject non-cert extensions", () => {
            expect(() => validateCertPath("/certs/cert.txt")).toThrow("Invalid certificate file");
        });

        it("should reject path traversal", () => {
            expect(() => validateCertPath("../etc/cert.pem")).toThrow("directory traversal");
        });

        it("should reject empty string", () => {
            expect(() => validateCertPath("")).toThrow("non-empty string");
        });
    });

    // ── validateFirewallZone ──────────────────────────────────────────────

    describe("validateFirewallZone", () => {
        it("should accept valid zone names", () => {
            expect(validateFirewallZone("public")).toBe("public");
            expect(validateFirewallZone("trusted")).toBe("trusted");
            expect(validateFirewallZone("dmz")).toBe("dmz");
            expect(validateFirewallZone("my-zone_1")).toBe("my-zone_1");
        });

        it("should reject empty string", () => {
            expect(() => validateFirewallZone("")).toThrow("non-empty string");
        });

        it("should reject spaces", () => {
            expect(() => validateFirewallZone("my zone")).toThrow("Invalid firewall zone");
        });
    });

    // ── validateAuditdKey ─────────────────────────────────────────────────

    describe("validateAuditdKey", () => {
        it("should accept valid auditd keys", () => {
            expect(validateAuditdKey("identity")).toBe("identity");
            expect(validateAuditdKey("time-change")).toBe("time-change");
            expect(validateAuditdKey("my_audit_key")).toBe("my_audit_key");
        });

        it("should reject empty string", () => {
            expect(() => validateAuditdKey("")).toThrow("non-empty string");
        });

        it("should reject dots", () => {
            expect(() => validateAuditdKey("my.key")).toThrow("Invalid auditd key");
        });
    });

    // ── validateToolPath ──────────────────────────────────────────────────

    describe("validateToolPath", () => {
        it("should accept path within allowed directories", () => {
            const result = validateToolPath("/var/log/syslog", ["/var/log", "/tmp"]);
            expect(result).toContain("/var/log/syslog");
        });

        it("should reject path outside allowed directories", () => {
            expect(() => validateToolPath("/etc/shadow", ["/var/log", "/tmp"])).toThrow(
                "not within allowed directories"
            );
        });

        it("should reject null bytes", () => {
            expect(() => validateToolPath("/tmp/test\0.txt", ["/tmp"])).toThrow("null bytes");
        });

        it("should reject path traversal with ..", () => {
            expect(() => validateToolPath("/tmp/../etc/shadow", ["/tmp"])).toThrow(
                "directory traversal"
            );
        });

        it("should reject shell metacharacters", () => {
            expect(() => validateToolPath("/tmp/test;rm -rf /", ["/tmp"])).toThrow(
                "forbidden shell metacharacters"
            );
        });

        it("should reject control characters", () => {
            expect(() => validateToolPath("/tmp/test\x01file", ["/tmp"])).toThrow(
                "control characters"
            );
        });

        it("should reject empty path", () => {
            expect(() => validateToolPath("", ["/tmp"])).toThrow("non-empty string");
        });

        it("should use custom label in error messages", () => {
            expect(() => validateToolPath("", ["/tmp"], "Config path")).toThrow("Config path");
        });

        it("should accept path matching allowed dir exactly", () => {
            const result = validateToolPath("/tmp", ["/tmp"]);
            expect(result).toContain("/tmp");
        });

        it("should accept nested paths within allowed dirs", () => {
            const result = validateToolPath("/tmp/deep/nested/file.txt", ["/tmp"]);
            expect(result).toContain("/tmp/deep/nested/file.txt");
        });
    });

    // ── sanitizeToolError ─────────────────────────────────────────────────

    describe("sanitizeToolError", () => {
        it("should handle Error objects", () => {
            const result = sanitizeToolError(new Error("something went wrong"));
            expect(result).toBe("something went wrong");
        });

        it("should handle string errors", () => {
            const result = sanitizeToolError("string error message");
            expect(result).toBe("string error message");
        });

        it("should handle non-string/non-Error values", () => {
            const result = sanitizeToolError(42);
            expect(result).toBe("42");
        });

        it("should strip absolute paths from error messages", () => {
            const result = sanitizeToolError(new Error("File not found: /home/user/secret.txt"));
            expect(result).not.toContain("/home/user/secret.txt");
            expect(result).toContain("[path]");
        });

        it("should strip stack traces from error messages", () => {
            const result = sanitizeToolError(new Error("Error occurred\n    at Function.foo (/path/to/file.js:10:5)\n    at bar (/path/to/other.js:20:10)"));
            expect(result).not.toContain("at Function.foo");
        });

        it("should truncate overly long messages", () => {
            const longMsg = "x".repeat(600);
            const result = sanitizeToolError(longMsg);
            expect(result.length).toBeLessThanOrEqual(500);
            expect(result).toContain("...");
        });

        it("should handle null/undefined", () => {
            const result1 = sanitizeToolError(null);
            expect(typeof result1).toBe("string");
            const result2 = sanitizeToolError(undefined);
            expect(typeof result2).toBe("string");
        });

        it("should strip /tmp paths from messages", () => {
            const result = sanitizeToolError("Cannot read /tmp/some-temp-file.txt");
            expect(result).toContain("[path]");
        });

        it("should preserve short messages without paths", () => {
            const result = sanitizeToolError("Invalid argument");
            expect(result).toBe("Invalid argument");
        });
    });
});
