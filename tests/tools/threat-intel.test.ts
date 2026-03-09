/**
 * Tests for src/tools/threat-intel.ts
 *
 * Covers: threat_intel tool with actions check_ip, check_hash, check_domain,
 * update_feeds, blocklist_apply.
 * Tests input validation, error handling, hash type detection,
 * IP validation, feed searching, and blocklist application.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Mock all external dependencies ─────────────────────────────────────────

vi.mock("../../src/core/spawn-safe.js", () => ({
  spawnSafe: vi.fn(),
}));

vi.mock("../../src/core/parsers.js", () => ({
  createTextContent: vi.fn((text: string) => ({ type: "text", text })),
  createErrorContent: vi.fn((text: string) => ({ type: "text", text: `Error: ${text}` })),
  formatToolOutput: vi.fn((obj: unknown) => ({ type: "text", text: JSON.stringify(obj) })),
}));

vi.mock("node:fs", () => ({
  existsSync: vi.fn(() => false),
  readFileSync: vi.fn(() => ""),
  readdirSync: vi.fn(() => []),
  statSync: vi.fn(() => ({
    isFile: () => true,
    size: 100,
    mtime: new Date("2025-01-01T00:00:00Z"),
  })),
}));

import {
  registerThreatIntelTools,
  isValidIPv4,
  detectHashType,
} from "../../src/tools/threat-intel.js";
import { spawnSafe } from "../../src/core/spawn-safe.js";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { EventEmitter } from "node:events";

const mockSpawnSafe = vi.mocked(spawnSafe);
const mockExistsSync = vi.mocked(existsSync);
const mockReadFileSync = vi.mocked(readFileSync);
const mockReaddirSync = vi.mocked(readdirSync);
const mockStatSync = vi.mocked(statSync);

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
    server: server as unknown as Parameters<typeof registerThreatIntelTools>[0],
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
 * Set up default spawnSafe mocks for threat intel commands.
 */
function setupDefaultSpawnMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    // fail2ban-client status
    if (command === "fail2ban-client" && args[0] === "status" && args.length === 1) {
      return createMockChildProcess(
        "Status\n|- Number of jail:\t2\n`- Jail list:\tsshd, recidive\n",
        "",
        0,
      );
    }

    // fail2ban-client status <jail>
    if (command === "fail2ban-client" && args[0] === "status" && args.length === 2) {
      return createMockChildProcess(
        `Status for the jail: ${args[1]}\n|- Filter\n|  |- Currently failed: 0\n|- Actions\n   |- Currently banned: 1\n   |- Banned IP list: 10.0.0.99\n`,
        "",
        0,
      );
    }

    // fail2ban-client set ... banip ...
    if (command === "fail2ban-client" && args.includes("banip")) {
      return createMockChildProcess("1", "", 0);
    }

    // iptables -L -n
    if (command === "iptables" && args.includes("-L") && args.includes("-n")) {
      return createMockChildProcess(
        "Chain INPUT (policy ACCEPT)\ntarget     prot opt source               destination\nDROP       all  --  192.168.1.100        0.0.0.0/0\n",
        "",
        0,
      );
    }

    // iptables -L INPUT -n
    if (command === "iptables" && args.includes("INPUT")) {
      return createMockChildProcess(
        "Chain INPUT (policy ACCEPT)\ntarget     prot opt source               destination\nDROP       all  --  192.168.1.100        0.0.0.0/0\n",
        "",
        0,
      );
    }

    // iptables -A INPUT -s ... -j DROP
    if (command === "iptables" && args.includes("-A")) {
      return createMockChildProcess("", "", 0);
    }

    // whois
    if (command === "whois") {
      return createMockChildProcess(
        "country:        US\nOrgName:        Example Org\nnetname:        EXAMPLE-NET\n",
        "",
        0,
      );
    }

    // dig +short
    if (command === "dig" && args.includes("+short")) {
      return createMockChildProcess("93.184.216.34\n", "", 0);
    }

    // cat /etc/hosts
    if (command === "cat" && args.includes("/etc/hosts")) {
      return createMockChildProcess(
        "127.0.0.1 localhost\n::1 localhost\n0.0.0.0 blocked.example.com\n",
        "",
        0,
      );
    }

    // cat (blocklist file)
    if (command === "cat") {
      return createMockChildProcess(
        "10.0.0.1\n10.0.0.2\n10.0.0.3\n# comment\n",
        "",
        0,
      );
    }

    // grep (ClamAV)
    if (command === "grep") {
      return createMockChildProcess("", "", 1);
    }

    // curl
    if (command === "curl") {
      return createMockChildProcess("", "", 0);
    }

    // wget
    if (command === "wget") {
      return createMockChildProcess("", "", 0);
    }

    // mkdir
    if (command === "mkdir") {
      return createMockChildProcess("", "", 0);
    }

    // sudo tee
    if (command === "sudo" && args.includes("tee")) {
      return createMockChildProcess("", "", 0);
    }

    // Default: return success with empty output
    return createMockChildProcess("", "", 0);
  });
}

// ── Tests ──────────────────────────────────────────────────────────────────

describe("threat-intel tools", () => {
  let tools: Map<
    string,
    { schema: Record<string, unknown>; handler: ToolHandler }
  >;

  beforeEach(() => {
    vi.clearAllMocks();
    const mock = createMockServer();
    registerThreatIntelTools(mock.server);
    tools = mock.tools;
    setupDefaultSpawnMocks();

    // Default: feed directories don't exist
    mockExistsSync.mockReturnValue(false);
  });

  // ── Registration ────────────────────────────────────────────────────────

  it("should register the threat_intel tool", () => {
    expect(tools.has("threat_intel")).toBe(true);
  });

  it("should register with server.tool called once", () => {
    const mock = createMockServer();
    registerThreatIntelTools(mock.server);
    expect(mock.server.tool).toHaveBeenCalledTimes(1);
    expect(mock.server.tool).toHaveBeenCalledWith(
      "threat_intel",
      expect.any(String),
      expect.any(Object),
      expect.any(Function),
    );
  });

  // ── Unknown action ──────────────────────────────────────────────────────

  it("should report error for unknown action", async () => {
    const handler = tools.get("threat_intel")!.handler;
    const result = await handler({ action: "nonexistent" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Unknown action");
  });

  // ── Pure function tests ─────────────────────────────────────────────────

  describe("isValidIPv4", () => {
    it("should accept valid IPv4 addresses", () => {
      expect(isValidIPv4("192.168.1.1")).toBe(true);
      expect(isValidIPv4("10.0.0.1")).toBe(true);
      expect(isValidIPv4("0.0.0.0")).toBe(true);
      expect(isValidIPv4("255.255.255.255")).toBe(true);
    });

    it("should reject invalid IPv4 addresses", () => {
      expect(isValidIPv4("256.0.0.1")).toBe(false);
      expect(isValidIPv4("abc.def.ghi.jkl")).toBe(false);
      expect(isValidIPv4("192.168.1")).toBe(false);
      expect(isValidIPv4("")).toBe(false);
      expect(isValidIPv4("192.168.1.1.1")).toBe(false);
    });

    it("should reject octet values > 255", () => {
      expect(isValidIPv4("999.999.999.999")).toBe(false);
      expect(isValidIPv4("192.168.1.256")).toBe(false);
    });
  });

  describe("detectHashType", () => {
    it("should detect MD5 (32 chars)", () => {
      expect(detectHashType("d41d8cd98f00b204e9800998ecf8427e")).toBe("MD5");
    });

    it("should detect SHA1 (40 chars)", () => {
      expect(detectHashType("da39a3ee5e6b4b0d3255bfef95601890afd80709")).toBe("SHA1");
    });

    it("should detect SHA256 (64 chars)", () => {
      expect(detectHashType("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")).toBe("SHA256");
    });

    it("should return unknown for invalid length", () => {
      expect(detectHashType("abc123")).toBe("unknown");
      expect(detectHashType("")).toBe("unknown");
    });

    it("should return unknown for non-hex characters", () => {
      expect(detectHashType("g41d8cd98f00b204e9800998ecf8427e")).toBe("unknown");
      expect(detectHashType("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ")).toBe("unknown");
    });

    it("should be case-insensitive", () => {
      expect(detectHashType("D41D8CD98F00B204E9800998ECF8427E")).toBe("MD5");
    });
  });

  // ── check_ip ────────────────────────────────────────────────────────────

  describe("check_ip", () => {
    it("should require indicator parameter", async () => {
      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({ action: "check_ip" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("indicator");
    });

    it("should reject invalid IP format", async () => {
      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({ action: "check_ip", indicator: "not-an-ip" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Invalid IP address");
    });

    it("should check IP against feeds and security tools", async () => {
      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({ action: "check_ip", indicator: "10.0.0.1" });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("10.0.0.1");
    });

    it("should detect IP in iptables DROP rules", async () => {
      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "check_ip",
        indicator: "192.168.1.100",
        output_format: "json",
      });
      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.inIptables).toBe(true);
      expect(parsed.alreadyBlocked).toBe(true);
    });

    it("should detect IP in fail2ban banned list", async () => {
      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "check_ip",
        indicator: "10.0.0.99",
        output_format: "json",
      });
      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.inFail2ban).toBe(true);
      expect(parsed.alreadyBlocked).toBe(true);
    });

    it("should check IP against local feed files", async () => {
      // Set up feed directory with a matching feed
      mockExistsSync.mockImplementation((path: unknown) => {
        return path === "/var/lib/kali-defense/threat-feeds";
      });
      mockReaddirSync.mockImplementation(() => ["abuse-ips.txt"] as unknown as ReturnType<typeof readdirSync>);
      mockStatSync.mockImplementation(() => ({
        isFile: () => true,
        size: 200,
        mtime: new Date(),
      }) as unknown as ReturnType<typeof statSync>);
      mockReadFileSync.mockImplementation(() => "10.0.0.50\n10.0.0.51\n# comment\n");

      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "check_ip",
        indicator: "10.0.0.50",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.feedMatches).toContain("abuse-ips.txt");
      expect(parsed.matchFound).toBe(true);
      expect(parsed.reputationScore).toBeGreaterThan(0);
    });

    it("should return whois info when available", async () => {
      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "check_ip",
        indicator: "10.0.0.1",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.whoisInfo).toContain("US");
    });

    it("should return text format by default", async () => {
      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({ action: "check_ip", indicator: "10.0.0.1" });
      expect(result.content[0].text).toContain("Threat Intel");
      expect(result.content[0].text).toContain("Reputation Score");
    });

    it("should return JSON format when requested", async () => {
      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "check_ip",
        indicator: "10.0.0.1",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("check_ip");
      expect(parsed.indicator).toBe("10.0.0.1");
    });

    it("should handle fail2ban not available", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "fail2ban-client") {
          return createMockChildProcess("", "command not found", 127);
        }
        if (command === "iptables") {
          return createMockChildProcess("", "", 0);
        }
        if (command === "whois") {
          return createMockChildProcess("", "", 1);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "check_ip",
        indicator: "10.0.0.1",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.inFail2ban).toBe(false);
    });
  });

  // ── check_hash ──────────────────────────────────────────────────────────

  describe("check_hash", () => {
    it("should require indicator parameter", async () => {
      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({ action: "check_hash" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("indicator");
    });

    it("should reject invalid hash format", async () => {
      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({ action: "check_hash", indicator: "not-a-hash" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Unable to detect hash type");
    });

    it("should auto-detect MD5 hash type", async () => {
      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "check_hash",
        indicator: "d41d8cd98f00b204e9800998ecf8427e",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.hashType).toBe("MD5");
    });

    it("should auto-detect SHA1 hash type", async () => {
      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "check_hash",
        indicator: "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.hashType).toBe("SHA1");
    });

    it("should auto-detect SHA256 hash type", async () => {
      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "check_hash",
        indicator: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.hashType).toBe("SHA256");
    });

    it("should check hash against local feed files", async () => {
      const testHash = "d41d8cd98f00b204e9800998ecf8427e";

      mockExistsSync.mockImplementation((path: unknown) => {
        return path === "/var/lib/kali-defense/threat-feeds/hashes";
      });
      mockReaddirSync.mockImplementation(() => ["malware-hashes.txt"] as unknown as ReturnType<typeof readdirSync>);
      mockStatSync.mockImplementation(() => ({
        isFile: () => true,
        size: 500,
        mtime: new Date(),
      }) as unknown as ReturnType<typeof statSync>);
      mockReadFileSync.mockImplementation(() =>
        `${testHash}:Trojan.GenericKD\naaaabbbbccccddddeeeeffffaaaabbbb\n`,
      );

      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "check_hash",
        indicator: testHash,
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.feedMatches).toContain("malware-hashes.txt");
      expect(parsed.matchFound).toBe(true);
      expect(parsed.malwareName).toBe("Trojan.GenericKD");
    });

    it("should check ClamAV databases when available", async () => {
      mockExistsSync.mockImplementation((path: unknown) => {
        return path === "/var/lib/clamav";
      });

      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "grep" && args.includes("/var/lib/clamav")) {
          return createMockChildProcess("/var/lib/clamav/main.cld\n", "", 0);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "check_hash",
        indicator: "d41d8cd98f00b204e9800998ecf8427e",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.clamavMatch).toBe("/var/lib/clamav/main.cld");
      expect(parsed.matchFound).toBe(true);
    });

    it("should return text format by default", async () => {
      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "check_hash",
        indicator: "d41d8cd98f00b204e9800998ecf8427e",
      });
      expect(result.content[0].text).toContain("Hash Type: MD5");
    });

    it("should handle missing feed directories gracefully", async () => {
      mockExistsSync.mockReturnValue(false);

      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "check_hash",
        indicator: "d41d8cd98f00b204e9800998ecf8427e",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.feedsChecked).toBe(0);
      expect(parsed.matchFound).toBe(false);
    });
  });

  // ── check_domain ────────────────────────────────────────────────────────

  describe("check_domain", () => {
    it("should require indicator parameter", async () => {
      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({ action: "check_domain" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("indicator");
    });

    it("should check domain against local blocklists", async () => {
      mockExistsSync.mockImplementation((path: unknown) => {
        return path === "/var/lib/kali-defense/threat-feeds/domains";
      });
      mockReaddirSync.mockImplementation(() => ["phishing-domains.txt"] as unknown as ReturnType<typeof readdirSync>);
      mockStatSync.mockImplementation(() => ({
        isFile: () => true,
        size: 300,
        mtime: new Date(),
      }) as unknown as ReturnType<typeof statSync>);
      mockReadFileSync.mockImplementation(() => "evil.example.com\nphish.example.com\n");

      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "check_domain",
        indicator: "evil.example.com",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.feedMatches).toContain("phishing-domains.txt");
      expect(parsed.matchFound).toBe(true);
    });

    it("should check /etc/hosts for existing blocks", async () => {
      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "check_domain",
        indicator: "blocked.example.com",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.inHostsFile).toBe(true);
      expect(parsed.isBlocked).toBe(true);
    });

    it("should detect sinkholed domains via dig", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "dig" && args.includes("+short")) {
          return createMockChildProcess("0.0.0.0\n", "", 0);
        }
        if (command === "cat" && args.includes("/etc/hosts")) {
          return createMockChildProcess("127.0.0.1 localhost\n", "", 0);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "check_domain",
        indicator: "sinkholed.example.com",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.isSinkholed).toBe(true);
      expect(parsed.isBlocked).toBe(true);
    });

    it("should return resolved IPs", async () => {
      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "check_domain",
        indicator: "example.com",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.resolvedIPs.length).toBeGreaterThan(0);
      expect(parsed.resolvedIPs).toContain("93.184.216.34");
    });

    it("should normalize trailing dots in domain", async () => {
      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "check_domain",
        indicator: "example.com.",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.indicator).toBe("example.com");
    });

    it("should return text format by default", async () => {
      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "check_domain",
        indicator: "example.com",
      });
      expect(result.content[0].text).toContain("Domain Check");
    });

    it("should handle missing feed directories gracefully", async () => {
      mockExistsSync.mockReturnValue(false);

      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "check_domain",
        indicator: "example.com",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.feedsChecked).toBe(0);
    });
  });

  // ── update_feeds ────────────────────────────────────────────────────────

  describe("update_feeds", () => {
    it("should list available feeds when no URL provided", async () => {
      mockExistsSync.mockImplementation((path: unknown) => {
        return path === "/var/lib/kali-defense/threat-feeds";
      });
      mockReaddirSync.mockImplementation(() => ["abuse-ips.txt", "tor-exit-nodes.txt"] as unknown as ReturnType<typeof readdirSync>);
      mockStatSync.mockImplementation(() => ({
        isFile: () => true,
        size: 1024,
        mtime: new Date("2025-06-15T00:00:00Z"),
      }) as unknown as ReturnType<typeof statSync>);
      mockReadFileSync.mockImplementation(() => "10.0.0.1\n10.0.0.2\n# comment\n");

      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "update_feeds",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.mode).toBe("list");
      expect(parsed.ipFeeds.length).toBe(2);
      expect(parsed.ipFeeds[0].name).toBe("abuse-ips.txt");
      expect(parsed.ipFeeds[0].indicatorCount).toBe(2);
    });

    it("should show feed stats with text format", async () => {
      mockExistsSync.mockReturnValue(false);

      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({ action: "update_feeds" });
      expect(result.content[0].text).toContain("Available Feeds");
    });

    it("should require feed_name when URL provided", async () => {
      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "update_feeds",
        feed_url: "https://example.com/feed.txt",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("feed_name");
    });

    it("should download feed via curl", async () => {
      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "update_feeds",
        feed_name: "new-feed.txt",
        feed_url: "https://example.com/feed.txt",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.mode).toBe("download");
      expect(parsed.feedName).toBe("new-feed.txt");
      expect(parsed.downloadSuccess).toBe(true);
    });

    it("should fall back to wget when curl fails", async () => {
      let wgetCalled = false;
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "curl") {
          return createMockChildProcess("", "curl: command not found", 127);
        }
        if (command === "wget") {
          wgetCalled = true;
          return createMockChildProcess("", "", 0);
        }
        if (command === "mkdir") {
          return createMockChildProcess("", "", 0);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "update_feeds",
        feed_name: "new-feed.txt",
        feed_url: "https://example.com/feed.txt",
        output_format: "json",
      });
      expect(wgetCalled).toBe(true);
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.downloadSuccess).toBe(true);
    });

    it("should report error when both curl and wget fail", async () => {
      mockSpawnSafe.mockImplementation((command: string) => {
        if (command === "curl") {
          return createMockChildProcess("", "curl failed", 1);
        }
        if (command === "wget") {
          return createMockChildProcess("", "wget failed", 1);
        }
        if (command === "mkdir") {
          return createMockChildProcess("", "", 0);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "update_feeds",
        feed_name: "bad-feed.txt",
        feed_url: "https://example.com/bad-feed.txt",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Failed to download");
    });

    it("should handle empty feed directories", async () => {
      mockExistsSync.mockReturnValue(false);

      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "update_feeds",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.totalFeeds).toBe(0);
    });
  });

  // ── blocklist_apply ─────────────────────────────────────────────────────

  describe("blocklist_apply", () => {
    it("should require blocklist_path parameter", async () => {
      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({ action: "blocklist_apply" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("blocklist_path");
    });

    it("should handle empty blocklist file", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "cat") {
          return createMockChildProcess("# only comments\n# no entries\n", "", 0);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "blocklist_apply",
        blocklist_path: "/tmp/empty.txt",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("empty");
    });

    it("should handle blocklist file read failure", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "cat") {
          return createMockChildProcess("", "No such file", 1);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "blocklist_apply",
        blocklist_path: "/tmp/nonexistent.txt",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Failed to read blocklist");
    });

    // ── iptables target ───────────────────────────────────────────────

    it("should apply blocklist to iptables", async () => {
      let iptablesAddCalls = 0;
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "cat") {
          return createMockChildProcess("10.0.0.1\n10.0.0.2\n", "", 0);
        }
        if (command === "iptables" && args.includes("-L")) {
          return createMockChildProcess(
            "Chain INPUT (policy ACCEPT)\ntarget prot opt source destination\n",
            "",
            0,
          );
        }
        if (command === "iptables" && args.includes("-A")) {
          iptablesAddCalls++;
          return createMockChildProcess("", "", 0);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "blocklist_apply",
        blocklist_path: "/tmp/blocklist.txt",
        apply_to: "iptables",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.target).toBe("iptables");
      expect(parsed.applied).toBe(2);
      expect(iptablesAddCalls).toBe(2);
    });

    it("should skip duplicate iptables rules", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "cat") {
          return createMockChildProcess("192.168.1.100\n10.0.0.1\n", "", 0);
        }
        if (command === "iptables" && args.includes("-L")) {
          return createMockChildProcess(
            "Chain INPUT\nDROP all -- 192.168.1.100 0.0.0.0/0\n",
            "",
            0,
          );
        }
        if (command === "iptables" && args.includes("-A")) {
          return createMockChildProcess("", "", 0);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "blocklist_apply",
        blocklist_path: "/tmp/blocklist.txt",
        apply_to: "iptables",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.skipped).toBe(1); // 192.168.1.100 already exists
      expect(parsed.applied).toBe(1); // 10.0.0.1 is new
    });

    it("should skip invalid IPs with iptables", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "cat") {
          return createMockChildProcess("not-an-ip\n10.0.0.1\n", "", 0);
        }
        if (command === "iptables" && args.includes("-L")) {
          return createMockChildProcess("Chain INPUT\n", "", 0);
        }
        if (command === "iptables" && args.includes("-A")) {
          return createMockChildProcess("", "", 0);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "blocklist_apply",
        blocklist_path: "/tmp/blocklist.txt",
        apply_to: "iptables",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.skipped).toBe(1); // invalid IP
      expect(parsed.applied).toBe(1); // valid IP
      expect(parsed.errors.length).toBe(1);
    });

    // ── fail2ban target ───────────────────────────────────────────────

    it("should apply blocklist to fail2ban", async () => {
      let banCalls = 0;
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "cat") {
          return createMockChildProcess("10.0.0.1\n10.0.0.2\n", "", 0);
        }
        if (command === "fail2ban-client" && args.includes("banip")) {
          banCalls++;
          return createMockChildProcess("1", "", 0);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "blocklist_apply",
        blocklist_path: "/tmp/blocklist.txt",
        apply_to: "fail2ban",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.target).toBe("fail2ban");
      expect(parsed.applied).toBe(2);
      expect(banCalls).toBe(2);
    });

    it("should skip already banned IPs in fail2ban", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "cat") {
          return createMockChildProcess("10.0.0.1\n", "", 0);
        }
        if (command === "fail2ban-client" && args.includes("banip")) {
          return createMockChildProcess("", "already banned", 1);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "blocklist_apply",
        blocklist_path: "/tmp/blocklist.txt",
        apply_to: "fail2ban",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.skipped).toBe(1);
    });

    // ── hosts target ──────────────────────────────────────────────────

    it("should apply blocklist to /etc/hosts", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "cat" && args.includes("/etc/hosts")) {
          return createMockChildProcess("127.0.0.1 localhost\n", "", 0);
        }
        if (command === "cat") {
          return createMockChildProcess("evil.com\nbad.org\n", "", 0);
        }
        if (command === "sudo" && args.includes("tee")) {
          return createMockChildProcess("", "", 0);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "blocklist_apply",
        blocklist_path: "/tmp/domains.txt",
        apply_to: "hosts",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.target).toBe("hosts");
      expect(parsed.applied).toBe(2);
    });

    it("should skip already blocked domains in /etc/hosts", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "cat" && args.includes("/etc/hosts")) {
          return createMockChildProcess(
            "127.0.0.1 localhost\n0.0.0.0 evil.com\n",
            "",
            0,
          );
        }
        if (command === "cat") {
          return createMockChildProcess("evil.com\nnew-evil.org\n", "", 0);
        }
        if (command === "sudo" && args.includes("tee")) {
          return createMockChildProcess("", "", 0);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "blocklist_apply",
        blocklist_path: "/tmp/domains.txt",
        apply_to: "hosts",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.skipped).toBe(1); // evil.com already blocked
      expect(parsed.applied).toBe(1); // new-evil.org is new
    });

    // ── batch size limiting ───────────────────────────────────────────

    it("should limit batch size to 1000 entries", async () => {
      // Generate 1500 IPs
      const ips = Array.from({ length: 1500 }, (_, i) => {
        const a = Math.floor(i / 256);
        const b = i % 256;
        return `10.${a}.${b}.1`;
      }).join("\n");

      let addCalls = 0;
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "cat" && !args.includes("/etc/hosts")) {
          return createMockChildProcess(ips, "", 0);
        }
        if (command === "iptables" && args.includes("-L")) {
          return createMockChildProcess("Chain INPUT\n", "", 0);
        }
        if (command === "iptables" && args.includes("-A")) {
          addCalls++;
          return createMockChildProcess("", "", 0);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "blocklist_apply",
        blocklist_path: "/tmp/big-blocklist.txt",
        apply_to: "iptables",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.truncated).toBe(true);
      expect(parsed.totalEntries).toBe(1500);
      expect(addCalls).toBeLessThanOrEqual(1000);
      expect(parsed.maxBatchSize).toBe(1000);
    });

    it("should deduplicate entries", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "cat" && !args.includes("/etc/hosts")) {
          return createMockChildProcess("10.0.0.1\n10.0.0.1\n10.0.0.1\n", "", 0);
        }
        if (command === "iptables" && args.includes("-L")) {
          return createMockChildProcess("Chain INPUT\n", "", 0);
        }
        if (command === "iptables" && args.includes("-A")) {
          return createMockChildProcess("", "", 0);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "blocklist_apply",
        blocklist_path: "/tmp/dups.txt",
        apply_to: "iptables",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.applied).toBe(1); // deduped to 1
    });

    // ── output format ─────────────────────────────────────────────────

    it("should return text format for blocklist_apply", async () => {
      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "blocklist_apply",
        blocklist_path: "/tmp/blocklist.txt",
        apply_to: "iptables",
      });
      expect(result.content[0].text).toContain("Blocklist Applied");
    });

    it("should default apply_to to iptables", async () => {
      const handler = tools.get("threat_intel")!.handler;
      const result = await handler({
        action: "blocklist_apply",
        blocklist_path: "/tmp/blocklist.txt",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.target).toBe("iptables");
    });
  });
});
