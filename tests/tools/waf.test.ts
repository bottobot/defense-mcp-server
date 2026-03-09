/**
 * Tests for src/tools/waf.ts
 *
 * Covers: waf_manage tool with actions modsec_audit, modsec_rules,
 * rate_limit_config, owasp_crs_deploy, blocked_requests.
 * Tests input validation, error handling, config parsing, and output formats.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Mock all external dependencies before imports ──────────────────────────

vi.mock("../../src/core/spawn-safe.js", () => ({
  spawnSafe: vi.fn(),
}));

vi.mock("../../src/core/parsers.js", () => ({
  createTextContent: vi.fn((text: string) => ({ type: "text", text })),
  createErrorContent: vi.fn((text: string) => ({ type: "text", text: `Error: ${text}` })),
  formatToolOutput: vi.fn((obj: unknown) => ({ type: "text", text: JSON.stringify(obj) })),
}));

import { registerWafTools } from "../../src/tools/waf.js";
import { spawnSafe } from "../../src/core/spawn-safe.js";
import { EventEmitter } from "node:events";

const mockSpawnSafe = vi.mocked(spawnSafe);

// ── Helpers ────────────────────────────────────────────────────────────────

type ToolHandler = (
  params: Record<string, unknown>,
) => Promise<{
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}>;

function createMockServer() {
  const tools = new Map<
    string,
    { schema: Record<string, unknown>; handler: ToolHandler }
  >();
  const server = {
    tool: vi.fn(
      (
        name: string,
        _desc: string,
        schema: Record<string, unknown>,
        handler: ToolHandler,
      ) => {
        tools.set(name, { schema, handler });
      },
    ),
  };
  return {
    server: server as unknown as Parameters<typeof registerWafTools>[0],
    tools,
  };
}

/**
 * Create a mock ChildProcess that emits provided stdout/stderr and close code.
 */
function createMockChildProcess(
  stdout: string,
  stderr: string,
  exitCode: number,
) {
  const cp = new EventEmitter() as EventEmitter & {
    stdout: EventEmitter;
    stderr: EventEmitter;
    kill: ReturnType<typeof vi.fn>;
  };
  cp.stdout = new EventEmitter();
  cp.stderr = new EventEmitter();
  cp.kill = vi.fn();

  // Emit data on next tick so listeners can be set up
  process.nextTick(() => {
    if (stdout) cp.stdout.emit("data", Buffer.from(stdout));
    if (stderr) cp.stderr.emit("data", Buffer.from(stderr));
    cp.emit("close", exitCode);
  });

  return cp;
}

/**
 * Set up default spawn mocks with reasonable responses.
 */
function setupDefaultSpawnMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    const fullCmd = `${command} ${args.join(" ")}`;

    // dpkg -l checks for ModSecurity packages
    if (command === "dpkg" && args[0] === "-l") {
      if (args[1] === "libapache2-mod-security2" || args[1] === "libnginx-mod-security") {
        return createMockChildProcess("ii  libapache2-mod-security2", "", 0);
      }
    }

    // which modsecurity-check
    if (command === "which" && args[0] === "modsecurity-check") {
      return createMockChildProcess("/usr/bin/modsecurity-check", "", 0);
    }

    // test -f (file existence checks)
    if (command === "test" && args[0] === "-f") {
      return createMockChildProcess("", "", 0);
    }

    // test -d (directory existence checks)
    if (command === "test" && args[0] === "-d") {
      return createMockChildProcess("", "", 0);
    }

    // sudo cat (config file reads)
    if (command === "sudo" && args[0] === "cat") {
      const path = args[1];

      // ModSecurity config
      if (path && path.includes("modsecurity.conf")) {
        return createMockChildProcess(
          "SecRuleEngine On\nSecAuditEngine RelevantOnly\nSecAuditLog /var/log/modsecurity/modsec_audit.log\nSecRequestBodyAccess On\nSecResponseBodyAccess Off\nSecRule REQUEST_HEADERS:Content-Type \"text/xml\" \"id:200001\"\n",
          "",
          0,
        );
      }

      // nginx.conf
      if (path === "/etc/nginx/nginx.conf") {
        return createMockChildProcess(
          "http {\n  limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;\n  server {\n    limit_req zone=api burst=20 nodelay;\n  }\n}\n",
          "",
          0,
        );
      }

      // apache2.conf
      if (path === "/etc/apache2/apache2.conf") {
        return createMockChildProcess("ServerRoot \"/etc/apache2\"\n", "", 0);
      }

      // CRS setup conf
      if (path && path.includes("crs-setup.conf")) {
        return createMockChildProcess(
          "SecAction \"id:900000,phase:1,pass,t:none,nolog,setvar:'tx.paranoia_level=2'\"\n",
          "",
          0,
        );
      }

      // evasive.conf
      if (path && path.includes("evasive.conf")) {
        return createMockChildProcess(
          "<IfModule mod_evasive20.c>\n  DOSPageCount 10\n  DOSSiteCount 50\n  DOSBlockingPeriod 60\n</IfModule>\n",
          "",
          0,
        );
      }

      // Default cat
      return createMockChildProcess("", "", 0);
    }

    // sudo ls (directory listings)
    if (command === "sudo" && args[0] === "ls") {
      const path = args[args.length - 1];
      if (path && path.includes("rules")) {
        return createMockChildProcess(
          "total 128\n-rw-r--r-- 1 root root 5000 Jan 01 00:00 REQUEST-901-INITIALIZATION.conf\n-rw-r--r-- 1 root root 3000 Jan 01 00:00 REQUEST-941-APPLICATION-ATTACK-XSS.conf\n-rw-r--r-- 1 root root 4000 Jan 01 00:00 REQUEST-942-APPLICATION-ATTACK-SQLI.conf\n",
          "",
          0,
        );
      }
      if (path && path.includes("sites-enabled")) {
        return createMockChildProcess("default\n", "", 0);
      }
      return createMockChildProcess("", "", 0);
    }

    // sudo grep (log analysis)
    if (command === "sudo" && args[0] === "grep") {
      const grepArgs = args.slice(1);
      const grepPattern = grepArgs.find((a) => !a.startsWith("-")) || "";

      // IP extraction
      if (grepArgs.includes("-oP") && grepPattern.includes("\\d+")) {
        return createMockChildProcess(
          "192.168.1.100\n192.168.1.100\n192.168.1.100\n10.0.0.50\n10.0.0.50\n172.16.0.1\n",
          "",
          0,
        );
      }

      // Rule ID extraction
      if (grepArgs.includes("-oP") && grepPattern.includes("id")) {
        return createMockChildProcess(
          'id "941100"\nid "941100"\nid "941100"\nid "942100"\nid "942100"\nid "920350"\n',
          "",
          0,
        );
      }

      // Category counts (-c flag)
      if (grepArgs.includes("-ciP")) {
        if (grepPattern.includes("sql")) return createMockChildProcess("15", "", 0);
        if (grepPattern.includes("xss")) return createMockChildProcess("8", "", 0);
        if (grepPattern.includes("scanner")) return createMockChildProcess("3", "", 0);
        return createMockChildProcess("0", "", 0);
      }

      return createMockChildProcess("", "", 1);
    }

    // sudo tail (log tail)
    if (command === "sudo" && args[0] === "tail") {
      return createMockChildProcess(
        "[2025-01-01 10:00:00] Blocked request from 192.168.1.100 (rule 941100)\n[2025-01-01 10:05:00] Blocked request from 10.0.0.50 (rule 942100)\n",
        "",
        0,
      );
    }

    // sudo sed (rule management)
    if (command === "sudo" && args[0] === "sed") {
      return createMockChildProcess("", "", 0);
    }

    // sudo sh -c (append to config)
    if (command === "sudo" && args[0] === "sh") {
      return createMockChildProcess("", "", 0);
    }

    // stat
    if (command === "stat") {
      return createMockChildProcess("1048576", "", 0);
    }

    // head (version file)
    if (command === "head") {
      return createMockChildProcess("Version 3.3.5\nChanges:\n", "", 0);
    }

    // cat VERSION
    if (command === "cat" && args[0] && args[0].includes("VERSION")) {
      return createMockChildProcess("3.3.5", "", 0);
    }

    // ls (rules directory listing)
    if (command === "ls") {
      return createMockChildProcess(
        "REQUEST-901-INITIALIZATION.conf\nREQUEST-941-APPLICATION-ATTACK-XSS.conf\nREQUEST-942-APPLICATION-ATTACK-SQLI.conf\n",
        "",
        0,
      );
    }

    // apache2ctl -M
    if (command === "apache2ctl") {
      return createMockChildProcess(
        " ratelimit_module (shared)\n evasive20_module (shared)\n security2_module (shared)\n",
        "",
        0,
      );
    }

    // Default: return success with empty output
    return createMockChildProcess("", "", 0);
  });
}

/**
 * Set up spawn mocks for a system without ModSecurity installed.
 */
function setupNoModSecurityMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    // dpkg -l always fails (not installed)
    if (command === "dpkg") {
      return createMockChildProcess("", "no packages found", 1);
    }

    // which fails
    if (command === "which") {
      return createMockChildProcess("", "", 1);
    }

    // test -f fails (no config files)
    if (command === "test" && args[0] === "-f") {
      return createMockChildProcess("", "", 1);
    }

    // test -d fails (no directories)
    if (command === "test" && args[0] === "-d") {
      return createMockChildProcess("", "", 1);
    }

    // sudo cat fails (no config)
    if (command === "sudo" && args[0] === "cat") {
      return createMockChildProcess("", "No such file or directory", 1);
    }

    // sudo ls fails
    if (command === "sudo" && args[0] === "ls") {
      return createMockChildProcess("", "No such file or directory", 1);
    }

    return createMockChildProcess("", "", 1);
  });
}

// ── Tests ──────────────────────────────────────────────────────────────────

describe("waf tools", () => {
  let tools: Map<
    string,
    { schema: Record<string, unknown>; handler: ToolHandler }
  >;

  beforeEach(() => {
    vi.clearAllMocks();
    const mock = createMockServer();
    registerWafTools(mock.server);
    tools = mock.tools;
    setupDefaultSpawnMocks();
  });

  // ── Registration ────────────────────────────────────────────────────────

  it("should register the waf_manage tool", () => {
    expect(tools.has("waf_manage")).toBe(true);
  });

  it("should register with server.tool called once", () => {
    const mock = createMockServer();
    registerWafTools(mock.server);
    expect(mock.server.tool).toHaveBeenCalledTimes(1);
    expect(mock.server.tool).toHaveBeenCalledWith(
      "waf_manage",
      expect.any(String),
      expect.any(Object),
      expect.any(Function),
    );
  });

  // ── Unknown action ──────────────────────────────────────────────────────

  it("should return error for unknown action", async () => {
    const handler = tools.get("waf_manage")!.handler;
    const result = await handler({ action: "nonexistent" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Unknown action");
  });

  // ═══════════════════════════════════════════════════════════════════════
  // modsec_audit
  // ═══════════════════════════════════════════════════════════════════════

  describe("modsec_audit action", () => {
    it("should audit ModSecurity configuration for nginx", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "modsec_audit", web_server: "nginx" });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("ModSecurity WAF Audit");
      expect(result.content[0].text).toContain("nginx");
    });

    it("should report ModSecurity as installed when dpkg finds it", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "modsec_audit" });
      expect(result.content[0].text).toContain("ModSecurity is installed");
    });

    it("should detect SecRuleEngine On status", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "modsec_audit" });
      expect(result.content[0].text).toContain("SecRuleEngine: On");
    });

    it("should detect SecRuleEngine DetectionOnly", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "dpkg") return createMockChildProcess("ii  libapache2-mod-security2", "", 0);
        if (command === "which") return createMockChildProcess("/usr/bin/modsecurity-check", "", 0);
        if (command === "test") return createMockChildProcess("", "", 0);
        if (command === "sudo" && args[0] === "cat") {
          return createMockChildProcess(
            "SecRuleEngine DetectionOnly\nSecAuditLog /var/log/modsec.log\n",
            "",
            0,
          );
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "modsec_audit" });
      expect(result.content[0].text).toContain("DetectionOnly");
    });

    it("should detect SecRuleEngine Off", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "dpkg") return createMockChildProcess("ii  package", "", 0);
        if (command === "which") return createMockChildProcess("", "", 1);
        if (command === "test") return createMockChildProcess("", "", 0);
        if (command === "sudo" && args[0] === "cat") {
          return createMockChildProcess("SecRuleEngine Off\n", "", 0);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "modsec_audit" });
      expect(result.content[0].text).toContain("SecRuleEngine: Off");
      expect(result.content[0].text).toContain("WAF disabled");
    });

    it("should report when ModSecurity is not installed", async () => {
      setupNoModSecurityMocks();
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "modsec_audit" });
      expect(result.content[0].text).toContain("NOT installed");
    });

    it("should suggest apt install for nginx when not installed", async () => {
      setupNoModSecurityMocks();
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "modsec_audit", web_server: "nginx" });
      expect(result.content[0].text).toContain("libnginx-mod-security");
    });

    it("should suggest apt install for apache when not installed", async () => {
      setupNoModSecurityMocks();
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "modsec_audit", web_server: "apache" });
      expect(result.content[0].text).toContain("libapache2-mod-security2");
    });

    it("should check for common misconfigurations", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "modsec_audit" });
      expect(result.content[0].text).toContain("Misconfiguration Checks");
    });

    it("should detect audit log path", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "modsec_audit" });
      expect(result.content[0].text).toContain("Audit Log:");
    });

    it("should output JSON format when requested", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "modsec_audit", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.installed).toBe(true);
      expect(parsed.engine_mode).toBe("On");
    });

    it("should audit apache config paths", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "modsec_audit", web_server: "apache" });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("ModSecurity WAF Audit");
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // modsec_rules
  // ═══════════════════════════════════════════════════════════════════════

  describe("modsec_rules action", () => {
    it("should list rule files", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "modsec_rules", rule_action: "list" });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("Rules Management");
      expect(result.content[0].text).toContain(".conf");
    });

    it("should list rule files from standard directories", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "modsec_rules", rule_action: "list" });
      expect(result.content[0].text).toContain("REQUEST-941-APPLICATION-ATTACK-XSS.conf");
    });

    it("should require rule_id for enable action", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "modsec_rules", rule_action: "enable" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("rule_id is required");
    });

    it("should require rule_id for disable action", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "modsec_rules", rule_action: "disable" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("rule_id is required");
    });

    it("should disable a rule by adding SecRuleRemoveById", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({
        action: "modsec_rules",
        rule_action: "disable",
        rule_id: "941100",
      });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("941100");
      // Should mention reload
      expect(result.content[0].text).toContain("reload");
    });

    it("should enable a rule by removing SecRuleRemoveById", async () => {
      // Mock config that already has the rule disabled
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "sudo" && args[0] === "cat") {
          return createMockChildProcess(
            "SecRuleEngine On\nSecRuleRemoveById 941100\n",
            "",
            0,
          );
        }
        if (command === "sudo" && args[0] === "sed") {
          return createMockChildProcess("", "", 0);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({
        action: "modsec_rules",
        rule_action: "enable",
        rule_id: "941100",
      });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("enabled");
    });

    it("should report already disabled when rule has existing removal", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "sudo" && args[0] === "cat") {
          return createMockChildProcess(
            "SecRuleEngine On\nSecRuleRemoveById 941100\n",
            "",
            0,
          );
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({
        action: "modsec_rules",
        rule_action: "disable",
        rule_id: "941100",
      });
      expect(result.content[0].text).toContain("already disabled");
    });

    it("should report already enabled when no removal directive exists", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({
        action: "modsec_rules",
        rule_action: "enable",
        rule_id: "999999",
      });
      expect(result.content[0].text).toContain("already enabled");
    });

    it("should report error when no config file found for rules", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "sudo" && args[0] === "cat") {
          return createMockChildProcess("", "No such file", 1);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({
        action: "modsec_rules",
        rule_action: "enable",
        rule_id: "941100",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("No ModSecurity configuration");
    });

    it("should output JSON for list action", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({
        action: "modsec_rules",
        rule_action: "list",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.rule_files).toBeDefined();
      expect(Array.isArray(parsed.rule_files)).toBe(true);
    });

    it("should handle no rule files found", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "sudo" && args[0] === "ls") {
          return createMockChildProcess("", "No such file or directory", 1);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "modsec_rules", rule_action: "list" });
      expect(result.content[0].text).toContain("No rule files found");
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // rate_limit_config
  // ═══════════════════════════════════════════════════════════════════════

  describe("rate_limit_config action", () => {
    it("should show nginx rate limiting configuration", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "rate_limit_config", web_server: "nginx" });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("Rate Limiting Configuration");
      expect(result.content[0].text).toContain("nginx");
    });

    it("should detect existing nginx limit_req_zone directives", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "rate_limit_config", web_server: "nginx" });
      expect(result.content[0].text).toContain("limit_req_zone");
    });

    it("should detect existing nginx limit_req directives", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "rate_limit_config", web_server: "nginx" });
      expect(result.content[0].text).toContain("limit_req");
    });

    it("should suggest custom rate when rate_limit is provided", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({
        action: "rate_limit_config",
        web_server: "nginx",
        rate_limit: 25,
      });
      expect(result.content[0].text).toContain("25r/s");
    });

    it("should use default rate of 10 when rate_limit is not provided", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "rate_limit_config", web_server: "nginx" });
      expect(result.content[0].text).toContain("10r/s");
    });

    it("should use custom zone name when rate_limit_zone is provided", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({
        action: "rate_limit_config",
        web_server: "nginx",
        rate_limit_zone: "myzone",
      });
      expect(result.content[0].text).toContain("myzone");
    });

    it("should show apache rate limiting with mod_evasive", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "rate_limit_config", web_server: "apache" });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("Apache");
      expect(result.content[0].text).toContain("mod_ratelimit");
    });

    it("should detect loaded apache modules", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "rate_limit_config", web_server: "apache" });
      expect(result.content[0].text).toContain("loaded");
    });

    it("should suggest mod_evasive install when not loaded", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "apache2ctl") {
          return createMockChildProcess("core_module (static)\n", "", 0);
        }
        if (command === "sudo" && args[0] === "cat") {
          return createMockChildProcess("", "", 1);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "rate_limit_config", web_server: "apache" });
      expect(result.content[0].text).toContain("libapache2-mod-evasive");
    });

    it("should output JSON format for nginx", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({
        action: "rate_limit_config",
        web_server: "nginx",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.web_server).toBe("nginx");
      expect(parsed.suggested_rate).toBeDefined();
    });

    it("should output JSON format for apache", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({
        action: "rate_limit_config",
        web_server: "apache",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.web_server).toBe("apache");
      expect(parsed.mod_ratelimit).toBeDefined();
      expect(parsed.mod_evasive).toBeDefined();
    });

    it("should handle missing nginx config gracefully", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "sudo" && args[0] === "cat") {
          return createMockChildProcess("", "No such file", 1);
        }
        if (command === "sudo" && args[0] === "ls") {
          return createMockChildProcess("", "", 1);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "rate_limit_config", web_server: "nginx" });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("Could not read");
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // owasp_crs_deploy
  // ═══════════════════════════════════════════════════════════════════════

  describe("owasp_crs_deploy action", () => {
    it("should check OWASP CRS installation status", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "owasp_crs_deploy" });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("OWASP Core Rule Set");
    });

    it("should detect CRS is installed when directory exists", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "owasp_crs_deploy" });
      expect(result.content[0].text).toContain("CRS found at");
    });

    it("should report CRS version", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "owasp_crs_deploy" });
      expect(result.content[0].text).toContain("3.3.5");
    });

    it("should report paranoia level", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "owasp_crs_deploy" });
      expect(result.content[0].text).toContain("Paranoia Level");
    });

    it("should check CRS integration with ModSecurity", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "owasp_crs_deploy" });
      expect(result.content[0].text).toContain("Integration Check");
    });

    it("should list active rule categories", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "owasp_crs_deploy" });
      expect(result.content[0].text).toContain("Rule Categories");
    });

    it("should provide installation instructions when CRS not found", async () => {
      setupNoModSecurityMocks();
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "owasp_crs_deploy" });
      expect(result.content[0].text).toContain("NOT installed");
      expect(result.content[0].text).toContain("apt install");
      expect(result.content[0].text).toContain("modsecurity-crs");
    });

    it("should provide git clone instructions when CRS not found", async () => {
      setupNoModSecurityMocks();
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "owasp_crs_deploy" });
      expect(result.content[0].text).toContain("git clone");
      expect(result.content[0].text).toContain("coreruleset");
    });

    it("should output JSON format", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "owasp_crs_deploy", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.installed).toBe(true);
      expect(parsed.version).toBe("3.3.5");
    });

    it("should output JSON when CRS not installed", async () => {
      setupNoModSecurityMocks();
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "owasp_crs_deploy", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.installed).toBe(false);
      expect(parsed.crs_path).toBeNull();
    });

    it("should warn when CRS not integrated with ModSecurity", async () => {
      // CRS directory exists but no Include directives found
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "test" && args[0] === "-d") {
          // Only first OWASP path matches
          if (args[1] === "/usr/share/modsecurity-crs") {
            return createMockChildProcess("", "", 0);
          }
          return createMockChildProcess("", "", 1);
        }
        if (command === "cat" && args[0] && args[0].includes("VERSION")) {
          return createMockChildProcess("4.0.0", "", 0);
        }
        if (command === "head") {
          return createMockChildProcess("", "", 1);
        }
        if (command === "sudo" && args[0] === "cat") {
          // Config files without CRS include
          return createMockChildProcess("SecRuleEngine On\n", "", 0);
        }
        if (command === "ls") {
          return createMockChildProcess("RULE-FILE.conf\n", "", 0);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "owasp_crs_deploy" });
      expect(result.content[0].text).toContain("NOT found in ModSecurity");
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // blocked_requests
  // ═══════════════════════════════════════════════════════════════════════

  describe("blocked_requests action", () => {
    it("should analyze WAF log file", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "blocked_requests" });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("Blocked Requests Analysis");
    });

    it("should show top blocked IPs", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "blocked_requests" });
      expect(result.content[0].text).toContain("Top Blocked IPs");
      expect(result.content[0].text).toContain("192.168.1.100");
    });

    it("should show top triggered rules", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "blocked_requests" });
      expect(result.content[0].text).toContain("Top Triggered Rules");
      expect(result.content[0].text).toContain("941100");
    });

    it("should show attack categories", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "blocked_requests" });
      expect(result.content[0].text).toContain("Attack Categories");
      expect(result.content[0].text).toContain("SQL Injection");
    });

    it("should identify false positive candidates", async () => {
      // Make a rule trigger > 100 times
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "test") return createMockChildProcess("", "", 0);
        if (command === "stat") return createMockChildProcess("2048000", "", 0);

        if (command === "sudo" && args[0] === "grep") {
          const grepArgs = args.slice(1);
          const grepPattern = grepArgs.find((a) => !a.startsWith("-")) || "";

          // Rule ID extraction — one rule triggered 150 times (check before IP since both contain \d+)
          if (grepArgs.includes("-oP") && grepPattern.includes("id")) {
            const lines = Array(150).fill('id "941100"').join("\n") + '\nid "942100"\n';
            return createMockChildProcess(lines, "", 0);
          }

          // IP extraction
          if (grepArgs.includes("-oP") && grepPattern.includes("\\d+")) {
            return createMockChildProcess("192.168.1.1\n", "", 0);
          }

          // Category counts
          if (grepArgs.includes("-ciP")) {
            return createMockChildProcess("0", "", 0);
          }
        }

        if (command === "sudo" && args[0] === "tail") {
          return createMockChildProcess("Recent log entry\n", "", 0);
        }

        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "blocked_requests" });
      expect(result.content[0].text).toContain("False Positive");
      expect(result.content[0].text).toContain("941100");
    });

    it("should use custom log_path when provided", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({
        action: "blocked_requests",
        log_path: "/custom/path/modsec.log",
      });
      expect(result.content[0].text).toContain("/custom/path/modsec.log");
    });

    it("should report when no log file found", async () => {
      setupNoModSecurityMocks();
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "blocked_requests" });
      expect(result.content[0].text).toContain("No ModSecurity audit log found");
    });

    it("should show recent activity", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "blocked_requests" });
      expect(result.content[0].text).toContain("Recent Activity");
    });

    it("should output JSON format", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "blocked_requests", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.log_found).toBe(true);
      expect(parsed.top_blocked_ips).toBeDefined();
      expect(parsed.top_triggered_rules).toBeDefined();
      expect(parsed.attack_categories).toBeDefined();
    });

    it("should output JSON when log not found", async () => {
      setupNoModSecurityMocks();
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "blocked_requests", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.log_found).toBe(false);
    });

    it("should report log file size", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "blocked_requests" });
      expect(result.content[0].text).toContain("MB");
    });

    it("should handle empty log gracefully", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "test") return createMockChildProcess("", "", 0);
        if (command === "stat") return createMockChildProcess("0", "", 0);
        if (command === "sudo" && args[0] === "grep") {
          return createMockChildProcess("", "", 1);
        }
        if (command === "sudo" && args[0] === "tail") {
          return createMockChildProcess("", "", 0);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "blocked_requests" });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("No blocked IPs found");
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // Error handling
  // ═══════════════════════════════════════════════════════════════════════

  describe("error handling", () => {
    it("should handle spawnSafe throwing for modsec_audit", async () => {
      mockSpawnSafe.mockImplementation(() => {
        throw new Error("Binary not in allowlist");
      });

      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "modsec_audit" });
      // runCommand catches the error internally; audit should still complete
      expect(result.content).toBeDefined();
    });

    it("should handle spawnSafe throwing for blocked_requests", async () => {
      mockSpawnSafe.mockImplementation(() => {
        throw new Error("Binary not in allowlist");
      });

      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "blocked_requests" });
      // Should handle gracefully — no log found
      expect(result.content).toBeDefined();
    });

    it("should handle spawnSafe throwing for rate_limit_config", async () => {
      mockSpawnSafe.mockImplementation(() => {
        throw new Error("Binary not in allowlist");
      });

      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "rate_limit_config" });
      expect(result.content).toBeDefined();
    });

    it("should handle spawnSafe throwing for owasp_crs_deploy", async () => {
      mockSpawnSafe.mockImplementation(() => {
        throw new Error("Binary not in allowlist");
      });

      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "owasp_crs_deploy" });
      expect(result.content).toBeDefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // Output format variations
  // ═══════════════════════════════════════════════════════════════════════

  describe("output format", () => {
    it("should default to text output", async () => {
      const handler = tools.get("waf_manage")!.handler;
      const result = await handler({ action: "modsec_audit" });
      // Text format uses createTextContent, not formatToolOutput
      expect(result.content[0].text).not.toMatch(/^\{/);
    });

    it("should return JSON for all actions when output_format=json", async () => {
      const handler = tools.get("waf_manage")!.handler;

      for (const action of ["modsec_audit", "modsec_rules", "rate_limit_config", "owasp_crs_deploy", "blocked_requests"]) {
        const params: Record<string, unknown> = { action, output_format: "json" };
        if (action === "modsec_rules") params.rule_action = "list";
        const result = await handler(params);
        // JSON output should be parseable
        expect(() => JSON.parse(result.content[0].text)).not.toThrow();
      }
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // Web server path differences
  // ═══════════════════════════════════════════════════════════════════════

  describe("nginx vs apache paths", () => {
    it("should use nginx config paths by default", async () => {
      const handler = tools.get("waf_manage")!.handler;
      await handler({ action: "modsec_audit" });
      // Verify cat was called with modsecurity.conf path
      expect(mockSpawnSafe).toHaveBeenCalledWith(
        "sudo",
        expect.arrayContaining(["cat"]),
      );
    });

    it("should use apache config paths when web_server=apache", async () => {
      const handler = tools.get("waf_manage")!.handler;
      await handler({ action: "modsec_audit", web_server: "apache" });
      // Should have attempted reading apache config paths
      expect(mockSpawnSafe).toHaveBeenCalled();
    });

    it("should check apache modules for rate limiting", async () => {
      const handler = tools.get("waf_manage")!.handler;
      await handler({ action: "rate_limit_config", web_server: "apache" });
      expect(mockSpawnSafe).toHaveBeenCalledWith(
        "apache2ctl",
        ["-M"],
      );
    });

    it("should read nginx.conf for rate limiting", async () => {
      const handler = tools.get("waf_manage")!.handler;
      await handler({ action: "rate_limit_config", web_server: "nginx" });
      expect(mockSpawnSafe).toHaveBeenCalledWith(
        "sudo",
        expect.arrayContaining(["cat", "/etc/nginx/nginx.conf"]),
      );
    });
  });
});
