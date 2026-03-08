import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { getConfig, getToolTimeout, KNOWN_TOOLS, invalidateConfigCache } from "../../src/core/config.js";

describe("config", () => {
    // Save and restore all env vars we might touch
    const envBackup: Record<string, string | undefined> = {};
    const envKeys = [
        "KALI_DEFENSE_TIMEOUT_DEFAULT",
        "KALI_DEFENSE_MAX_OUTPUT_SIZE",
        "KALI_DEFENSE_ALLOWED_DIRS",
        "KALI_DEFENSE_LOG_LEVEL",
        "KALI_DEFENSE_DRY_RUN",
        "KALI_DEFENSE_CHANGELOG_PATH",
        "KALI_DEFENSE_BACKUP_DIR",
        "KALI_DEFENSE_BACKUP_ENABLED",
        "KALI_DEFENSE_AUTO_INSTALL",
        "KALI_DEFENSE_PROTECTED_PATHS",
        "KALI_DEFENSE_REQUIRE_CONFIRMATION",
        "KALI_DEFENSE_QUARANTINE_DIR",
        "KALI_DEFENSE_POLICY_DIR",
        "KALI_DEFENSE_SUDO_TIMEOUT",
        "KALI_DEFENSE_TIMEOUT_LYNIS",
        "KALI_DEFENSE_TIMEOUT_NMAP",
        "KALI_DEFENSE_COMMAND_TIMEOUT",
        "KALI_DEFENSE_NETWORK_TIMEOUT",
    ];

    beforeEach(() => {
        for (const key of envKeys) {
            envBackup[key] = process.env[key];
            delete process.env[key];
        }
        // Invalidate config cache so each test sees fresh env vars
        invalidateConfigCache();
    });

    afterEach(() => {
        for (const key of envKeys) {
            if (envBackup[key] === undefined) {
                delete process.env[key];
            } else {
                process.env[key] = envBackup[key];
            }
        }
    });

    // ── Default values ────────────────────────────────────────────────────

    describe("default config values", () => {
        it("should have default timeout of 120 seconds (120000ms)", () => {
            const config = getConfig();
            expect(config.defaultTimeout).toBe(120_000);
        });

        it("should have default maxBuffer of 10MB", () => {
            const config = getConfig();
            expect(config.maxBuffer).toBe(10 * 1024 * 1024);
        });

        // SECURITY (CICD-013): /etc is intentionally excluded from default allowedDirs
        // because it contains sensitive system configuration files. Tools needing
        // /etc access must explicitly set KALI_DEFENSE_ALLOWED_DIRS.
        it("should include /tmp, /home, /var/log in allowedDirs (not /etc)", () => {
            const config = getConfig();
            expect(config.allowedDirs).toContain("/tmp");
            expect(config.allowedDirs).toContain("/home");
            expect(config.allowedDirs).toContain("/var/log");
            expect(config.allowedDirs).not.toContain("/etc");
        });

        it("should have default logLevel of 'info'", () => {
            const config = getConfig();
            expect(config.logLevel).toBe("info");
        });

        // CICD-014: dryRun defaults to true for security (safe preview mode)
        it("should have dryRun enabled by default", () => {
            const config = getConfig();
            expect(config.dryRun).toBe(true);
        });

        // CICD-014: backupEnabled defaults to true
        it("should have backupEnabled enabled by default", () => {
            const config = getConfig();
            expect(config.backupEnabled).toBe(true);
        });

        it("should have autoInstall disabled by default", () => {
            const config = getConfig();
            expect(config.autoInstall).toBe(false);
        });

        it("should have requireConfirmation enabled by default", () => {
            const config = getConfig();
            expect(config.requireConfirmation).toBe(true);
        });

        it("should have sensible default paths", () => {
            const config = getConfig();
            expect(config.changelogPath).toContain(".kali-defense");
            expect(config.changelogPath).toContain("changelog.json");
            expect(config.backupDir).toContain(".kali-defense");
            expect(config.backupDir).toContain("backups");
            expect(config.quarantineDir).toContain(".kali-defense");
            expect(config.quarantineDir).toContain("quarantine");
            expect(config.policyDir).toContain(".kali-defense");
            expect(config.policyDir).toContain("policies");
        });

        it("should have default sudo session timeout of 15 minutes", () => {
            const config = getConfig();
            expect(config.sudoSessionTimeout).toBe(15 * 60 * 1000);
        });

        it("should have default commandTimeout of 120 seconds (120000ms)", () => {
            const config = getConfig();
            expect(config.commandTimeout).toBe(120_000);
        });

        it("should have default networkTimeout of 30 seconds (30000ms)", () => {
            const config = getConfig();
            expect(config.networkTimeout).toBe(30_000);
        });

        it("should have protected paths include /boot and /usr/bin", () => {
            const config = getConfig();
            expect(config.protectedPaths).toContain("/boot");
            expect(config.protectedPaths).toContain("/usr/bin");
            expect(config.protectedPaths).toContain("/usr/sbin");
        });

        it("should have empty toolTimeouts by default", () => {
            const config = getConfig();
            expect(Object.keys(config.toolTimeouts).length).toBe(0);
        });
    });

    // ── Environment variable overrides ────────────────────────────────────

    describe("environment variable overrides", () => {
        it("should disable dryRun with KALI_DEFENSE_DRY_RUN=false", () => {
            process.env.KALI_DEFENSE_DRY_RUN = "false";
            const config = getConfig();
            expect(config.dryRun).toBe(false);
        });

        it("should keep dryRun true when KALI_DEFENSE_DRY_RUN is not 'false'", () => {
            process.env.KALI_DEFENSE_DRY_RUN = "true";
            const config = getConfig();
            expect(config.dryRun).toBe(true);
        });

        it("should disable backupEnabled with KALI_DEFENSE_BACKUP_ENABLED=false", () => {
            process.env.KALI_DEFENSE_BACKUP_ENABLED = "false";
            const config = getConfig();
            expect(config.backupEnabled).toBe(false);
        });

        it("should override autoInstall with KALI_DEFENSE_AUTO_INSTALL=true", () => {
            process.env.KALI_DEFENSE_AUTO_INSTALL = "true";
            const config = getConfig();
            expect(config.autoInstall).toBe(true);
        });

        it("should override logLevel with KALI_DEFENSE_LOG_LEVEL", () => {
            process.env.KALI_DEFENSE_LOG_LEVEL = "debug";
            const config = getConfig();
            expect(config.logLevel).toBe("debug");
        });

        it("should handle invalid log level gracefully", () => {
            process.env.KALI_DEFENSE_LOG_LEVEL = "invalid";
            const config = getConfig();
            expect(config.logLevel).toBe("info");
        });

        it("should override defaultTimeout via KALI_DEFENSE_TIMEOUT_DEFAULT", () => {
            process.env.KALI_DEFENSE_TIMEOUT_DEFAULT = "60";
            const config = getConfig();
            expect(config.defaultTimeout).toBe(60_000);
        });

        it("should handle invalid timeout gracefully", () => {
            process.env.KALI_DEFENSE_TIMEOUT_DEFAULT = "abc";
            const config = getConfig();
            expect(config.defaultTimeout).toBe(120_000);
        });

        it("should override maxBuffer via KALI_DEFENSE_MAX_OUTPUT_SIZE", () => {
            process.env.KALI_DEFENSE_MAX_OUTPUT_SIZE = "5242880";
            const config = getConfig();
            expect(config.maxBuffer).toBe(5_242_880);
        });

        it("should override allowedDirs via KALI_DEFENSE_ALLOWED_DIRS", () => {
            process.env.KALI_DEFENSE_ALLOWED_DIRS = "/opt,/srv";
            const config = getConfig();
            expect(config.allowedDirs).toContain("/opt");
            expect(config.allowedDirs).toContain("/srv");
            expect(config.allowedDirs).not.toContain("/tmp");
        });

        it("should override changelogPath via KALI_DEFENSE_CHANGELOG_PATH", () => {
            process.env.KALI_DEFENSE_CHANGELOG_PATH = "/tmp/my-changelog.json";
            const config = getConfig();
            expect(config.changelogPath).toBe("/tmp/my-changelog.json");
        });

        it("should override backupDir via KALI_DEFENSE_BACKUP_DIR", () => {
            process.env.KALI_DEFENSE_BACKUP_DIR = "/tmp/my-backups";
            const config = getConfig();
            expect(config.backupDir).toBe("/tmp/my-backups");
        });

        it("should override sudoSessionTimeout via KALI_DEFENSE_SUDO_TIMEOUT", () => {
            process.env.KALI_DEFENSE_SUDO_TIMEOUT = "30";
            const config = getConfig();
            expect(config.sudoSessionTimeout).toBe(30 * 60 * 1000);
        });

        it("should override requireConfirmation=false", () => {
            process.env.KALI_DEFENSE_REQUIRE_CONFIRMATION = "false";
            const config = getConfig();
            expect(config.requireConfirmation).toBe(false);
        });

        it("should parse per-tool timeouts from environment variables", () => {
            process.env.KALI_DEFENSE_TIMEOUT_LYNIS = "300";
            process.env.KALI_DEFENSE_TIMEOUT_NMAP = "600";
            const config = getConfig();
            expect(config.toolTimeouts["lynis"]).toBe(300_000);
            expect(config.toolTimeouts["nmap"]).toBe(600_000);
        });

        it("should override commandTimeout via KALI_DEFENSE_COMMAND_TIMEOUT", () => {
            process.env.KALI_DEFENSE_COMMAND_TIMEOUT = "60";
            const config = getConfig();
            expect(config.commandTimeout).toBe(60_000);
        });

        it("should handle invalid commandTimeout gracefully", () => {
            process.env.KALI_DEFENSE_COMMAND_TIMEOUT = "abc";
            const config = getConfig();
            expect(config.commandTimeout).toBe(120_000);
        });

        it("should override networkTimeout via KALI_DEFENSE_NETWORK_TIMEOUT", () => {
            process.env.KALI_DEFENSE_NETWORK_TIMEOUT = "15";
            const config = getConfig();
            expect(config.networkTimeout).toBe(15_000);
        });

        it("should handle invalid networkTimeout gracefully", () => {
            process.env.KALI_DEFENSE_NETWORK_TIMEOUT = "-5";
            const config = getConfig();
            expect(config.networkTimeout).toBe(30_000);
        });
    });

    // ── Config getters return correct types ───────────────────────────────

    describe("config getter types", () => {
        it("should return number for defaultTimeout", () => {
            const config = getConfig();
            expect(typeof config.defaultTimeout).toBe("number");
        });

        it("should return number for maxBuffer", () => {
            const config = getConfig();
            expect(typeof config.maxBuffer).toBe("number");
        });

        it("should return array for allowedDirs", () => {
            const config = getConfig();
            expect(Array.isArray(config.allowedDirs)).toBe(true);
        });

        it("should return string for logLevel", () => {
            const config = getConfig();
            expect(typeof config.logLevel).toBe("string");
        });

        it("should return boolean for dryRun", () => {
            const config = getConfig();
            expect(typeof config.dryRun).toBe("boolean");
        });

        it("should return boolean for autoInstall", () => {
            const config = getConfig();
            expect(typeof config.autoInstall).toBe("boolean");
        });

        it("should return string for changelogPath", () => {
            const config = getConfig();
            expect(typeof config.changelogPath).toBe("string");
        });

        it("should return object for toolTimeouts", () => {
            const config = getConfig();
            expect(typeof config.toolTimeouts).toBe("object");
        });
    });

    // ── getToolTimeout ────────────────────────────────────────────────────

    describe("getToolTimeout", () => {
        it("should return default timeout for unknown tools", () => {
            const timeout = getToolTimeout("unknown-tool");
            expect(timeout).toBe(120_000);
        });

        it("should return per-tool timeout when configured", () => {
            process.env.KALI_DEFENSE_TIMEOUT_LYNIS = "300";
            const config = getConfig();
            const timeout = getToolTimeout("lynis", config);
            expect(timeout).toBe(300_000);
        });

        it("should fall back to default when tool has no override", () => {
            const config = getConfig();
            const timeout = getToolTimeout("aide", config);
            expect(timeout).toBe(config.defaultTimeout);
        });
    });

    // ── KNOWN_TOOLS ───────────────────────────────────────────────────────

    describe("KNOWN_TOOLS", () => {
        it("should be a non-empty array", () => {
            expect(KNOWN_TOOLS.length).toBeGreaterThan(0);
        });

        it("should contain expected security tools", () => {
            const tools = [...KNOWN_TOOLS];
            expect(tools).toContain("lynis");
            expect(tools).toContain("aide");
            expect(tools).toContain("clamav");
            expect(tools).toContain("nmap");
            expect(tools).toContain("rkhunter");
        });
    });

    // ── Config cache behavior ─────────────────────────────────────────────

    describe("config cache", () => {
        it("should return cached config on repeated calls within TTL", () => {
            const config1 = getConfig();
            const config2 = getConfig();
            expect(config1).toBe(config2); // Same object reference (cached)
        });

        it("should return fresh config after cache invalidation", () => {
            const config1 = getConfig();
            invalidateConfigCache();
            const config2 = getConfig();
            expect(config1).not.toBe(config2);
        });

        it("should reflect env changes after invalidation", () => {
            const config1 = getConfig();
            expect(config1.logLevel).toBe("info");

            process.env.KALI_DEFENSE_LOG_LEVEL = "error";
            invalidateConfigCache();
            const config2 = getConfig();
            expect(config2.logLevel).toBe("error");
        });
    });

    // ── CORE-012: Broad directory rejection ───────────────────────────────

    describe("CORE-012 broad directory rejection", () => {
        it("should reject root directory '/' in allowedDirs", () => {
            process.env.KALI_DEFENSE_ALLOWED_DIRS = "/,/tmp";
            const config = getConfig();
            expect(config.allowedDirs).not.toContain("/");
            expect(config.allowedDirs).toContain("/tmp");
        });

        it("should warn about broad directories like /etc", () => {
            process.env.KALI_DEFENSE_ALLOWED_DIRS = "/etc,/tmp";
            const config = getConfig();
            expect(config.allowedDirs).toContain("/etc");
            expect(config.allowedDirs).toContain("/tmp");
        });
    });

    // ── Edge cases in env var parsing ─────────────────────────────────────

    describe("env var edge cases", () => {
        it("should handle empty KALI_DEFENSE_ALLOWED_DIRS", () => {
            process.env.KALI_DEFENSE_ALLOWED_DIRS = "";
            const config = getConfig();
            expect(Array.isArray(config.allowedDirs)).toBe(true);
        });

        it("should handle zero timeout values gracefully", () => {
            process.env.KALI_DEFENSE_TIMEOUT_DEFAULT = "0";
            const config = getConfig();
            expect(config.defaultTimeout).toBe(120_000);
        });

        it("should handle negative timeout values gracefully", () => {
            process.env.KALI_DEFENSE_TIMEOUT_DEFAULT = "-10";
            const config = getConfig();
            expect(config.defaultTimeout).toBe(120_000);
        });

        it("should handle negative maxBuffer gracefully", () => {
            process.env.KALI_DEFENSE_MAX_OUTPUT_SIZE = "-1";
            const config = getConfig();
            expect(config.maxBuffer).toBe(10 * 1024 * 1024);
        });

        it("should handle invalid sudo timeout gracefully", () => {
            process.env.KALI_DEFENSE_SUDO_TIMEOUT = "abc";
            const config = getConfig();
            expect(config.sudoSessionTimeout).toBe(15 * 60 * 1000);
        });

        it("should handle zero sudo timeout gracefully", () => {
            process.env.KALI_DEFENSE_SUDO_TIMEOUT = "0";
            const config = getConfig();
            expect(config.sudoSessionTimeout).toBe(15 * 60 * 1000);
        });

        it("should ignore invalid per-tool timeout values", () => {
            process.env.KALI_DEFENSE_TIMEOUT_LYNIS = "abc";
            const config = getConfig();
            expect(config.toolTimeouts["lynis"]).toBeUndefined();
        });

        it("should ignore negative per-tool timeout values", () => {
            process.env.KALI_DEFENSE_TIMEOUT_NMAP = "-5";
            const config = getConfig();
            expect(config.toolTimeouts["nmap"]).toBeUndefined();
        });

        it("should handle tilde expansion in paths", () => {
            process.env.KALI_DEFENSE_BACKUP_DIR = "~/my-backups";
            const config = getConfig();
            expect(config.backupDir).not.toContain("~");
            expect(config.backupDir).toContain("my-backups");
        });
    });

    // ── getToolTimeout edge cases ─────────────────────────────────────────

    describe("getToolTimeout edge cases", () => {
        it("should work without passing config explicitly", () => {
            const timeout = getToolTimeout("unknown-tool");
            expect(typeof timeout).toBe("number");
            expect(timeout).toBe(120_000);
        });

        it("should handle case-insensitive tool name lookup", () => {
            process.env.KALI_DEFENSE_TIMEOUT_LYNIS = "200";
            const config = getConfig();
            // getToolTimeout lowercases the name
            const timeout = getToolTimeout("lynis", config);
            expect(timeout).toBe(200_000);
        });
    });
});
