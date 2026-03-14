import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Logger, type LogLevel, type LogEntry } from "../../src/core/logger.js";

describe("logger", () => {
  let stderrSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  });

  afterEach(() => {
    stderrSpy.mockRestore();
  });

  // ── JSON output format ──────────────────────────────────────────────────

  describe("structured JSON output", () => {
    it("should emit a valid JSON line to stderr", () => {
      const logger = new Logger("debug");
      logger.info("test-component", "test_action", "Hello world");

      expect(stderrSpy).toHaveBeenCalledTimes(1);
      const output = stderrSpy.mock.calls[0][0] as string;
      const parsed = JSON.parse(output.trim()) as LogEntry;
      expect(parsed.level).toBe("info");
      expect(parsed.component).toBe("test-component");
      expect(parsed.action).toBe("test_action");
      expect(parsed.message).toBe("Hello world");
    });

    it("should include an ISO 8601 timestamp", () => {
      const logger = new Logger("debug");
      logger.info("comp", "act", "msg");

      const output = stderrSpy.mock.calls[0][0] as string;
      const parsed = JSON.parse(output.trim()) as LogEntry;
      expect(parsed.timestamp).toBeDefined();
      // Validate ISO 8601 format
      expect(new Date(parsed.timestamp).toISOString()).toBe(parsed.timestamp);
    });

    it("should include details when provided", () => {
      const logger = new Logger("debug");
      logger.info("comp", "act", "msg", { toolName: "firewall_iptables", count: 42 });

      const output = stderrSpy.mock.calls[0][0] as string;
      const parsed = JSON.parse(output.trim()) as LogEntry;
      expect(parsed.details).toBeDefined();
      expect(parsed.details!.toolName).toBe("firewall_iptables");
      expect(parsed.details!.count).toBe(42);
    });

    it("should NOT include details key when not provided", () => {
      const logger = new Logger("debug");
      logger.info("comp", "act", "msg");

      const output = stderrSpy.mock.calls[0][0] as string;
      const parsed = JSON.parse(output.trim());
      expect("details" in parsed).toBe(false);
    });
  });

  // ── Log level methods ───────────────────────────────────────────────────

  describe("log level methods", () => {
    it("should emit debug-level messages via debug()", () => {
      const logger = new Logger("debug");
      logger.debug("comp", "act", "debug message");

      const parsed = JSON.parse((stderrSpy.mock.calls[0][0] as string).trim());
      expect(parsed.level).toBe("debug");
    });

    it("should emit info-level messages via info()", () => {
      const logger = new Logger("debug");
      logger.info("comp", "act", "info message");

      const parsed = JSON.parse((stderrSpy.mock.calls[0][0] as string).trim());
      expect(parsed.level).toBe("info");
    });

    it("should emit warn-level messages via warn()", () => {
      const logger = new Logger("debug");
      logger.warn("comp", "act", "warn message");

      const parsed = JSON.parse((stderrSpy.mock.calls[0][0] as string).trim());
      expect(parsed.level).toBe("warn");
    });

    it("should emit error-level messages via error()", () => {
      const logger = new Logger("debug");
      logger.error("comp", "act", "error message");

      const parsed = JSON.parse((stderrSpy.mock.calls[0][0] as string).trim());
      expect(parsed.level).toBe("error");
    });

    it("should emit security-level messages via security()", () => {
      const logger = new Logger("debug");
      logger.security("sudo-guard", "elevation_requested", "Sudo elevation requested", {
        tool: "harden_sysctl",
      });

      const parsed = JSON.parse((stderrSpy.mock.calls[0][0] as string).trim());
      expect(parsed.level).toBe("security");
      expect(parsed.component).toBe("sudo-guard");
      expect(parsed.details!.tool).toBe("harden_sysctl");
    });
  });

  // ── Log level filtering ─────────────────────────────────────────────────

  describe("log level filtering", () => {
    it("should suppress debug messages when level is info", () => {
      const logger = new Logger("info");
      logger.debug("comp", "act", "should be suppressed");

      expect(stderrSpy).not.toHaveBeenCalled();
    });

    it("should suppress info messages when level is warn", () => {
      const logger = new Logger("warn");
      logger.info("comp", "act", "should be suppressed");
      logger.debug("comp", "act", "should be suppressed too");

      expect(stderrSpy).not.toHaveBeenCalled();
    });

    it("should allow warn messages when level is warn", () => {
      const logger = new Logger("warn");
      logger.warn("comp", "act", "should appear");

      expect(stderrSpy).toHaveBeenCalledTimes(1);
    });

    it("should suppress warn and info when level is error", () => {
      const logger = new Logger("error");
      logger.debug("comp", "act", "no");
      logger.info("comp", "act", "no");
      logger.warn("comp", "act", "no");

      expect(stderrSpy).not.toHaveBeenCalled();

      logger.error("comp", "act", "yes");
      expect(stderrSpy).toHaveBeenCalledTimes(1);
    });

    it("should always emit security messages regardless of level", () => {
      const logger = new Logger("error");
      logger.security("comp", "act", "security event");

      expect(stderrSpy).toHaveBeenCalledTimes(1);
      const parsed = JSON.parse((stderrSpy.mock.calls[0][0] as string).trim());
      expect(parsed.level).toBe("security");
    });
  });

  // ── setLevel / getLevel ─────────────────────────────────────────────────

  describe("setLevel / getLevel", () => {
    it("should return the current level via getLevel()", () => {
      const logger = new Logger("warn");
      expect(logger.getLevel()).toBe("warn");
    });

    it("should dynamically change filtering via setLevel()", () => {
      const logger = new Logger("error");

      logger.info("comp", "act", "suppressed");
      expect(stderrSpy).not.toHaveBeenCalled();

      logger.setLevel("debug");
      expect(logger.getLevel()).toBe("debug");

      logger.info("comp", "act", "now visible");
      expect(stderrSpy).toHaveBeenCalledTimes(1);
    });
  });

  // ── Environment variable configuration ─────────────────────────────────

  describe("environment variable configuration", () => {
    it("should read DEFENSE_MCP_LOG_LEVEL from environment", () => {
      const backup = process.env.DEFENSE_MCP_LOG_LEVEL;
      try {
        process.env.DEFENSE_MCP_LOG_LEVEL = "warn";
        const logger = new Logger();
        expect(logger.getLevel()).toBe("warn");
      } finally {
        if (backup === undefined) {
          delete process.env.DEFENSE_MCP_LOG_LEVEL;
        } else {
          process.env.DEFENSE_MCP_LOG_LEVEL = backup;
        }
      }
    });

    it("should default to info for invalid env values", () => {
      const backup = process.env.DEFENSE_MCP_LOG_LEVEL;
      try {
        process.env.DEFENSE_MCP_LOG_LEVEL = "invalid_level";
        const logger = new Logger();
        expect(logger.getLevel()).toBe("info");
      } finally {
        if (backup === undefined) {
          delete process.env.DEFENSE_MCP_LOG_LEVEL;
        } else {
          process.env.DEFENSE_MCP_LOG_LEVEL = backup;
        }
      }
    });
  });
});
