/**
 * Tests for src/tools/dns-security.ts
 *
 * Covers: dns_security tool with actions audit_resolv, check_dnssec,
 * detect_tunneling, block_domains, query_log_audit.
 * Tests input validation, error handling, entropy calculation,
 * DNSSEC parsing, and blocklist management.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Mock all external dependencies ─────────────────────────────────────────

vi.mock("../../src/core/spawn-safe.js", () => ({
  spawnSafe: vi.fn(),
}));

vi.mock("../../src/core/secure-fs.js", () => ({
  secureWriteFileSync: vi.fn(),
  secureCopyFileSync: vi.fn(),
}));

vi.mock("../../src/core/parsers.js", () => ({
  createTextContent: vi.fn((text: string) => ({ type: "text", text })),
  createErrorContent: vi.fn((text: string) => ({ type: "text", text: `Error: ${text}` })),
  formatToolOutput: vi.fn((obj: unknown) => ({ type: "text", text: JSON.stringify(obj) })),
}));

vi.mock("../../src/core/sanitizer.js", () => ({
  validateInterface: vi.fn((i: string) => {
    if (i.includes(";") || i.includes("&")) throw new Error("Invalid interface name");
    return i;
  }),
}));

import {
  registerDnsSecurityTools,
  calculateShannonEntropy,
  parseDnssecOutput,
  analyzeDnsQueries,
  analyzeQueryLog,
  auditResolvConf,
} from "../../src/tools/dns-security.js";
import { spawnSafe } from "../../src/core/spawn-safe.js";
import { secureWriteFileSync, secureCopyFileSync } from "../../src/core/secure-fs.js";
import { EventEmitter } from "node:events";

const mockSpawnSafe = vi.mocked(spawnSafe);
const mockSecureWriteFileSync = vi.mocked(secureWriteFileSync);
const mockSecureCopyFileSync = vi.mocked(secureCopyFileSync);

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
    server: server as unknown as Parameters<typeof registerDnsSecurityTools>[0],
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
 * Set up default spawnSafe mocks for DNS security commands.
 */
function setupDefaultSpawnMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    const fullCmd = `${command} ${args.join(" ")}`;

    // cat /etc/resolv.conf
    if (command === "cat" && args.includes("/etc/resolv.conf")) {
      return createMockChildProcess(
        "nameserver 8.8.8.8\nnameserver 1.1.1.1\nsearch example.com\noptions edns0\n",
        "",
        0,
      );
    }

    // systemd-resolve --status
    if (command === "systemd-resolve" || (command === "resolvectl" && args.includes("status"))) {
      return createMockChildProcess(
        "Global\n  DNSSEC: no\n  DNSOverTLS: no\n  DNS Servers: 8.8.8.8\n",
        "",
        0,
      );
    }

    // dig +dnssec
    if (command === "dig" && args.includes("+dnssec")) {
      return createMockChildProcess(
        ";; flags: qr rd ra ad; QUERY: 1, ANSWER: 2\n;; ANSWER SECTION:\nexample.com. 300 IN A 93.184.216.34\nexample.com. 300 IN RRSIG A 13 2 300 20250101 20240101 12345 example.com. abc123==\n",
        "",
        0,
      );
    }

    // dig +short DS
    if (command === "dig" && args.includes("DS")) {
      return createMockChildProcess(
        "12345 13 2 AABB...\n",
        "",
        0,
      );
    }

    // sudo tcpdump (DNS capture)
    if (command === "sudo" && args.includes("tcpdump")) {
      return createMockChildProcess(
        "12:00:00.000 IP 192.168.1.1.12345 > 8.8.8.8.53: 1234+ A? example.com. (30)\n12:00:01.000 IP 192.168.1.1.12346 > 8.8.8.8.53: 1235+ A? normal.org. (28)\n",
        "",
        0,
      );
    }

    // sudo cat /etc/hosts
    if (command === "sudo" && args.includes("cat") && args.includes("/etc/hosts")) {
      return createMockChildProcess(
        "127.0.0.1 localhost\n::1 localhost\n0.0.0.0 blocked.example.com\n",
        "",
        0,
      );
    }

    // sudo cp (backup)
    if (command === "sudo" && args.includes("cp")) {
      return createMockChildProcess("", "", 0);
    }

    // cat (blocklist file)
    if (command === "cat") {
      return createMockChildProcess(
        "malware.example.com\nphishing.example.com\n",
        "",
        0,
      );
    }

    // journalctl (DNS logs)
    if (command === "journalctl") {
      return createMockChildProcess(
        "Jan 01 10:00:00 host systemd-resolved[123]: query[A] example.com\nJan 01 10:00:01 host systemd-resolved[123]: query[A] safe.org\nJan 01 11:00:00 host systemd-resolved[123]: NXDOMAIN example.xyz\n",
        "",
        0,
      );
    }

    // sudo grep (log files)
    if (command === "sudo" && args.includes("grep")) {
      return createMockChildProcess("", "", 1);
    }

    // Default: return success with empty output
    return createMockChildProcess("", "", 0);
  });
}

// ── Tests ──────────────────────────────────────────────────────────────────

describe("dns-security tools", () => {
  let tools: Map<
    string,
    { schema: Record<string, unknown>; handler: ToolHandler }
  >;

  beforeEach(() => {
    vi.clearAllMocks();
    const mock = createMockServer();
    registerDnsSecurityTools(mock.server);
    tools = mock.tools;
    setupDefaultSpawnMocks();
  });

  // ── Registration ────────────────────────────────────────────────────────

  it("should register the dns_security tool", () => {
    expect(tools.has("dns_security")).toBe(true);
  });

  it("should register with server.tool called once", () => {
    const mock = createMockServer();
    registerDnsSecurityTools(mock.server);
    expect(mock.server.tool).toHaveBeenCalledTimes(1);
    expect(mock.server.tool).toHaveBeenCalledWith(
      "dns_security",
      expect.any(String),
      expect.any(Object),
      expect.any(Function),
    );
  });

  // ── Unknown action ──────────────────────────────────────────────────────

  it("should report error for unknown action", async () => {
    const handler = tools.get("dns_security")!.handler;
    const result = await handler({ action: "nonexistent" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Unknown action");
  });

  // ── audit_resolv ────────────────────────────────────────────────────────

  describe("audit_resolv", () => {
    it("should audit resolv.conf and return findings", async () => {
      const handler = tools.get("dns_security")!.handler;
      const result = await handler({ action: "audit_resolv" });
      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("audit_resolv");
      expect(parsed.nameservers).toBeDefined();
      expect(parsed.findings).toBeDefined();
      expect(parsed.recommendations).toBeDefined();
    });

    it("should identify public DNS resolvers", async () => {
      const handler = tools.get("dns_security")!.handler;
      const result = await handler({ action: "audit_resolv" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.nameservers.length).toBe(2);
      expect(parsed.nameservers[0].type).toBe("public");
      expect(parsed.nameservers[0].provider).toContain("Google");
    });

    it("should recommend DoT and DNSSEC when not enabled", async () => {
      const handler = tools.get("dns_security")!.handler;
      const result = await handler({ action: "audit_resolv" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.recommendations.some((r: string) => r.includes("DNS over TLS"))).toBe(true);
      expect(parsed.recommendations.some((r: string) => r.includes("DNSSEC"))).toBe(true);
    });

    it("should handle command failure gracefully", async () => {
      mockSpawnSafe.mockImplementation(() => {
        throw new Error("Binary not in allowlist");
      });

      const handler = tools.get("dns_security")!.handler;
      const result = await handler({ action: "audit_resolv" });
      // runCommand catches the error, so audit still completes with empty content
      expect(result.isError).toBeUndefined();
    });

    it("should fall back to resolvectl when systemd-resolve fails", async () => {
      let callCount = 0;
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "systemd-resolve") {
          return createMockChildProcess("", "command not found", 127);
        }
        if (command === "resolvectl" && args.includes("status")) {
          callCount++;
          return createMockChildProcess(
            "Global\n  DNSSEC: yes\n  DNSOverTLS: yes\n",
            "",
            0,
          );
        }
        if (command === "cat") {
          return createMockChildProcess("nameserver 8.8.8.8\n", "", 0);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("dns_security")!.handler;
      const result = await handler({ action: "audit_resolv" });
      expect(result.isError).toBeUndefined();
      expect(callCount).toBe(1);
    });
  });

  // ── check_dnssec ────────────────────────────────────────────────────────

  describe("check_dnssec", () => {
    it("should require domain parameter", async () => {
      const handler = tools.get("dns_security")!.handler;
      const result = await handler({ action: "check_dnssec" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("domain");
    });

    it("should check DNSSEC for a domain", async () => {
      const handler = tools.get("dns_security")!.handler;
      const result = await handler({ action: "check_dnssec", domain: "example.com" });
      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("check_dnssec");
      expect(parsed.domain).toBe("example.com");
      expect(parsed.dnssecEnabled).toBeDefined();
      expect(parsed.hasRRSIG).toBeDefined();
      expect(parsed.adFlag).toBeDefined();
    });

    it("should detect AD flag and RRSIG in dig output", async () => {
      const handler = tools.get("dns_security")!.handler;
      const result = await handler({ action: "check_dnssec", domain: "example.com" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.adFlag).toBe(true);
      expect(parsed.hasRRSIG).toBe(true);
      expect(parsed.chainOfTrustValid).toBe(true);
    });

    it("should handle dig failure", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "dig") {
          return createMockChildProcess("", "dig: command not found", 127);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("dns_security")!.handler;
      const result = await handler({ action: "check_dnssec", domain: "example.com" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("dig command failed");
    });

    it("should detect missing DNSSEC", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "dig" && args.includes("+dnssec")) {
          return createMockChildProcess(
            ";; flags: qr rd ra; QUERY: 1, ANSWER: 1\n;; ANSWER SECTION:\nno-dnssec.com. 300 IN A 1.2.3.4\n",
            "",
            0,
          );
        }
        if (command === "dig" && args.includes("DS")) {
          return createMockChildProcess("", "", 0);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("dns_security")!.handler;
      const result = await handler({ action: "check_dnssec", domain: "no-dnssec.com" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.dnssecEnabled).toBe(false);
      expect(parsed.hasRRSIG).toBe(false);
      expect(parsed.adFlag).toBe(false);
    });
  });

  // ── detect_tunneling ────────────────────────────────────────────────────

  describe("detect_tunneling", () => {
    it("should capture and analyze DNS traffic", async () => {
      const handler = tools.get("dns_security")!.handler;
      const result = await handler({
        action: "detect_tunneling",
        interface: "any",
        duration: 10,
      });
      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("detect_tunneling");
      expect(parsed.totalQueries).toBeDefined();
      expect(parsed.findings).toBeDefined();
    });

    it("should cap duration at 120 seconds", async () => {
      const handler = tools.get("dns_security")!.handler;
      const result = await handler({
        action: "detect_tunneling",
        interface: "any",
        duration: 999,
      });
      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.duration).toBe(120);
    });

    it("should detect high entropy domains", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "sudo" && args.includes("tcpdump")) {
          return createMockChildProcess(
            "12:00:00.000 IP 10.0.0.1.5555 > 8.8.8.8.53: 1+ A? aXk2mN9pQrStUvWx.evil.com. (50)\n12:00:01.000 IP 10.0.0.1.5556 > 8.8.8.8.53: 2+ TXT? bY3lO0qRsT5uV6wXyZ1aB2cD3eF4gH5iJ.evil.com. (80)\n",
            "",
            0,
          );
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("dns_security")!.handler;
      const result = await handler({
        action: "detect_tunneling",
        threshold: 3.0,
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.suspiciousQueries.length).toBeGreaterThan(0);
    });

    it("should validate interface", async () => {
      const { validateInterface } = await import("../../src/core/sanitizer.js");
      vi.mocked(validateInterface).mockImplementation(() => {
        throw new Error("Invalid interface name");
      });

      const handler = tools.get("dns_security")!.handler;
      const result = await handler({
        action: "detect_tunneling",
        interface: "eth0;rm -rf /",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Invalid interface");
    });

    it("should handle tcpdump failure", async () => {
      mockSpawnSafe.mockImplementation((command: string) => {
        if (command === "sudo") {
          return createMockChildProcess("", "permission denied", 1);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("dns_security")!.handler;
      const result = await handler({ action: "detect_tunneling" });
      // Still returns results (empty capture), not an error
      expect(result.isError).toBeUndefined();
    });
  });

  // ── block_domains ───────────────────────────────────────────────────────

  describe("block_domains", () => {
    it("should require domains_to_block or blocklist_path", async () => {
      const handler = tools.get("dns_security")!.handler;
      const result = await handler({ action: "block_domains" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("domains_to_block");
    });

    it("should add domains to /etc/hosts", async () => {
      const handler = tools.get("dns_security")!.handler;
      const result = await handler({
        action: "block_domains",
        domains_to_block: ["malware.example.com", "phish.example.com"],
      });
      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("block_domains");
      expect(parsed.domainsAdded).toBeGreaterThan(0);
    });

    it("should skip already blocked domains", async () => {
      const handler = tools.get("dns_security")!.handler;
      const result = await handler({
        action: "block_domains",
        domains_to_block: ["blocked.example.com"],
      });
      const parsed = JSON.parse(result.content[0].text);
      // blocked.example.com is already in mock /etc/hosts
      expect(parsed.alreadyBlocked).toBeGreaterThanOrEqual(1);
    });

    it("should backup /etc/hosts before modifying", async () => {
      const handler = tools.get("dns_security")!.handler;
      await handler({
        action: "block_domains",
        domains_to_block: ["new-malware.example.com"],
      });
      // secureCopyFileSync should have been called for backup
      expect(mockSecureCopyFileSync).toHaveBeenCalledWith(
        "/etc/hosts",
        expect.stringContaining("/etc/hosts.bak."),
      );
    });

    it("should import domains from blocklist file", async () => {
      const handler = tools.get("dns_security")!.handler;
      const result = await handler({
        action: "block_domains",
        blocklist_path: "/tmp/blocklist.txt",
      });
      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.domainsAdded).toBeGreaterThan(0);
    });

    it("should handle blocklist file read failure", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "cat" && args.includes("/tmp/missing.txt")) {
          return createMockChildProcess("", "No such file", 1);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("dns_security")!.handler;
      const result = await handler({
        action: "block_domains",
        blocklist_path: "/tmp/missing.txt",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Failed to read blocklist");
    });

    it("should deduplicate domains", async () => {
      const handler = tools.get("dns_security")!.handler;
      const result = await handler({
        action: "block_domains",
        domains_to_block: ["dup.example.com", "dup.example.com", "dup.example.com"],
      });
      const parsed = JSON.parse(result.content[0].text);
      // Should only add once despite 3 entries
      expect(parsed.domainsAdded).toBeLessThanOrEqual(1);
    });

    it("should fall back to sudo cp when secureCopyFileSync fails", async () => {
      mockSecureCopyFileSync.mockImplementation(() => {
        throw new Error("Permission denied");
      });

      const handler = tools.get("dns_security")!.handler;
      const result = await handler({
        action: "block_domains",
        domains_to_block: ["fallback-test.example.com"],
      });
      // Should still work — falls back to sudo cp
      expect(result.isError).toBeUndefined();
    });
  });

  // ── query_log_audit ─────────────────────────────────────────────────────

  describe("query_log_audit", () => {
    it("should analyze DNS query logs from journalctl", async () => {
      const handler = tools.get("dns_security")!.handler;
      const result = await handler({ action: "query_log_audit" });
      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("query_log_audit");
      expect(parsed.totalEntries).toBeDefined();
      expect(parsed.findings).toBeDefined();
    });

    it("should read from specified log path", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "sudo" && args.includes("cat") && args.includes("/var/log/dnsmasq.log")) {
          return createMockChildProcess(
            "Jan 01 10:00:00 host dnsmasq[123]: query[A] example.com from 192.168.1.1\nJan 01 10:00:01 host dnsmasq[123]: query[A] test.org from 192.168.1.1\n",
            "",
            0,
          );
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("dns_security")!.handler;
      const result = await handler({
        action: "query_log_audit",
        log_path: "/var/log/dnsmasq.log",
      });
      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.logSource).toBe("/var/log/dnsmasq.log");
    });

    it("should handle missing log gracefully", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "sudo" && args.includes("cat")) {
          return createMockChildProcess("", "No such file", 1);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("dns_security")!.handler;
      const result = await handler({
        action: "query_log_audit",
        log_path: "/nonexistent/log",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Failed to read log file");
    });

    it("should report when no logs are found", async () => {
      mockSpawnSafe.mockImplementation(() => {
        return createMockChildProcess("", "", 1);
      });

      const handler = tools.get("dns_security")!.handler;
      const result = await handler({ action: "query_log_audit" });
      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.message).toContain("No DNS query logs found");
    });

    it("should detect suspicious TLDs", async () => {
      mockSpawnSafe.mockImplementation((command: string) => {
        if (command === "journalctl") {
          return createMockChildProcess(
            "10:00:00 host resolved: query[A] evil.xyz\n10:00:01 host resolved: query[A] bad.top\n10:00:02 host resolved: query[A] phish.buzz\n",
            "",
            0,
          );
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("dns_security")!.handler;
      const result = await handler({ action: "query_log_audit" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.suspiciousTldQueries.length).toBeGreaterThan(0);
    });
  });

  // ── Pure function tests ─────────────────────────────────────────────────

  describe("calculateShannonEntropy", () => {
    it("should return 0 for empty string", () => {
      expect(calculateShannonEntropy("")).toBe(0);
    });

    it("should return 0 for single character", () => {
      expect(calculateShannonEntropy("a")).toBe(0);
    });

    it("should return 0 for repeated characters", () => {
      expect(calculateShannonEntropy("aaaa")).toBe(0);
    });

    it("should return 1.0 for two equally distributed characters", () => {
      const entropy = calculateShannonEntropy("ab");
      expect(entropy).toBeCloseTo(1.0, 5);
    });

    it("should return higher entropy for random-looking strings", () => {
      const normalDomain = "www.example.com";
      const randomDomain = "aXk2mN9pQrStUvWx";
      expect(calculateShannonEntropy(randomDomain)).toBeGreaterThan(
        calculateShannonEntropy(normalDomain),
      );
    });

    it("should return max entropy for all unique characters", () => {
      const str = "abcdefgh";
      const entropy = calculateShannonEntropy(str);
      // log2(8) = 3.0
      expect(entropy).toBeCloseTo(3.0, 5);
    });

    it("should handle typical DNS tunneling strings", () => {
      // DGA-like domain labels have high entropy (>3.5)
      const dgaDomain = "x7k2p9m4q1r6s3t8u5v0w";
      const entropy = calculateShannonEntropy(dgaDomain);
      expect(entropy).toBeGreaterThan(3.0);
    });

    it("should handle normal domain labels with lower entropy", () => {
      const normalLabel = "google";
      const entropy = calculateShannonEntropy(normalLabel);
      expect(entropy).toBeLessThan(3.0);
    });
  });

  describe("parseDnssecOutput", () => {
    it("should detect AD flag in dig output", () => {
      const output = ";; flags: qr rd ra ad; QUERY: 1\n;; ANSWER SECTION:\nexample.com. 300 IN RRSIG A 13 2 300 2025 2024 123 example.com. abc==\n";
      const result = parseDnssecOutput("example.com", output);
      expect(result.adFlag).toBe(true);
      expect(result.hasRRSIG).toBe(true);
      expect(result.chainValid).toBe(true);
    });

    it("should detect missing RRSIG", () => {
      const output = ";; flags: qr rd ra; QUERY: 1\n;; ANSWER SECTION:\nexample.com. 300 IN A 1.2.3.4\n";
      const result = parseDnssecOutput("example.com", output);
      expect(result.hasRRSIG).toBe(false);
      expect(result.dnssecEnabled).toBe(false);
      expect(result.issues).toContain("No RRSIG records found — domain may not be DNSSEC-signed");
    });

    it("should detect RRSIG without AD flag (broken chain)", () => {
      const output = ";; flags: qr rd ra; QUERY: 1\nexample.com. 300 IN RRSIG A 13 2 300 2025 2024 123 example.com. abc==\n";
      const result = parseDnssecOutput("example.com", output);
      expect(result.hasRRSIG).toBe(true);
      expect(result.adFlag).toBe(false);
      expect(result.chainValid).toBe(false);
      expect(result.issues.some((i) => i.includes("chain of trust"))).toBe(true);
    });

    it("should detect DNSKEY records", () => {
      const output = ";; flags: qr rd ra ad;\nexample.com. 300 IN DNSKEY 257 3 13 abc123==\n";
      const result = parseDnssecOutput("example.com", output);
      expect(result.hasDNSKEY).toBe(true);
    });

    it("should detect SERVFAIL", () => {
      const output = ";; Got answer:\n;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL\n";
      const result = parseDnssecOutput("example.com", output);
      expect(result.issues.some((i) => i.includes("SERVFAIL"))).toBe(true);
    });

    it("should handle empty output", () => {
      const result = parseDnssecOutput("example.com", "");
      expect(result.dnssecEnabled).toBe(false);
      expect(result.hasRRSIG).toBe(false);
      expect(result.adFlag).toBe(false);
    });
  });

  describe("analyzeDnsQueries", () => {
    it("should count total queries", () => {
      const captured = "12:00:00 IP 10.0.0.1.5555 > 8.8.8.8.53: 1+ A? example.com. (30)\n12:00:01 IP 10.0.0.1.5556 > 8.8.8.8.53: 2+ A? test.org. (28)\n";
      const result = analyzeDnsQueries(captured, 3.5);
      expect(result.totalQueries).toBe(2);
    });

    it("should detect high entropy subdomains", () => {
      const captured = "12:00:00 IP 10.0.0.1.5555 > 8.8.8.8.53: 1+ A? aXk2mN9pQrStUvWxYz1234567890.evil.com. (60)\n";
      const result = analyzeDnsQueries(captured, 3.0);
      expect(result.suspicious.length).toBeGreaterThan(0);
      expect(result.suspicious[0].reason).toContain("entropy");
    });

    it("should count TXT queries", () => {
      const captured = "12:00:00 IP 10.0.0.1.5555 > 8.8.8.8.53: 1+ TXT? data.evil.com. (40)\n";
      const result = analyzeDnsQueries(captured, 3.5);
      expect(result.txtQueries).toBe(1);
    });

    it("should count NULL queries", () => {
      const captured = "12:00:00 IP 10.0.0.1.5555 > 8.8.8.8.53: 1+ NULL? tunnel.evil.com. (40)\n";
      const result = analyzeDnsQueries(captured, 3.5);
      expect(result.nullQueries).toBe(1);
    });

    it("should track domain frequency distribution", () => {
      const captured = [
        "12:00:00 IP 10.0.0.1.1 > 8.8.8.8.53: 1+ A? sub1.evil.com. (30)",
        "12:00:01 IP 10.0.0.1.2 > 8.8.8.8.53: 2+ A? sub2.evil.com. (30)",
        "12:00:02 IP 10.0.0.1.3 > 8.8.8.8.53: 3+ A? sub3.evil.com. (30)",
        "12:00:03 IP 10.0.0.1.4 > 8.8.8.8.53: 4+ A? other.safe.org. (30)",
      ].join("\n");
      const result = analyzeDnsQueries(captured, 3.5);
      expect(result.domainCounts["evil.com"]).toBe(3);
      expect(result.domainCounts["safe.org"]).toBe(1);
    });

    it("should handle empty capture output", () => {
      const result = analyzeDnsQueries("", 3.5);
      expect(result.totalQueries).toBe(0);
      expect(result.suspicious.length).toBe(0);
    });
  });

  describe("analyzeQueryLog", () => {
    it("should count total entries", () => {
      const log = "10:00:00 host dnsmasq[1]: query[A] example.com from 10.0.0.1\n10:00:01 host dnsmasq[1]: query[A] test.org from 10.0.0.1\n";
      const result = analyzeQueryLog(log);
      expect(result.totalEntries).toBe(2);
    });

    it("should extract top domains", () => {
      const log = [
        "10:00:00 host dnsmasq[1]: query[A] example.com from 10.0.0.1",
        "10:00:01 host dnsmasq[1]: query[A] example.com from 10.0.0.1",
        "10:00:02 host dnsmasq[1]: query[A] example.com from 10.0.0.1",
        "10:00:03 host dnsmasq[1]: query[A] test.org from 10.0.0.1",
      ].join("\n");
      const result = analyzeQueryLog(log);
      expect(result.topDomains[0].domain).toBe("example.com");
      expect(result.topDomains[0].count).toBe(3);
    });

    it("should detect suspicious TLDs", () => {
      const log = "10:00:00 host resolved: query[A] evil.xyz from 10.0.0.1\n10:00:01 host resolved: query[A] bad.top from 10.0.0.1\n";
      const result = analyzeQueryLog(log);
      expect(result.suspiciousTldQueries.length).toBeGreaterThan(0);
    });

    it("should count NXDOMAIN responses", () => {
      const log = "10:00:00 host: NXDOMAIN for random123.com\n10:00:01 host: NXDOMAIN for random456.com\n10:00:02 host: query[A] good.com\n";
      const result = analyzeQueryLog(log);
      expect(result.nxdomainCount).toBe(2);
    });

    it("should calculate NXDOMAIN rate", () => {
      const log = "10:00:00 host: NXDOMAIN for a.com\n10:00:01 host: NXDOMAIN for b.com\n10:00:02 host: query ok\n10:00:03 host: query ok\n";
      const result = analyzeQueryLog(log);
      expect(result.nxdomainRate).toBeCloseTo(0.5, 1);
    });

    it("should flag high NXDOMAIN rate", () => {
      const lines = [];
      for (let i = 0; i < 10; i++) {
        lines.push(`10:00:0${i} host: NXDOMAIN for random${i}.com`);
      }
      lines.push("10:01:00 host: query[A] good.com from 10.0.0.1");
      const result = analyzeQueryLog(lines.join("\n"));
      expect(result.findings.some((f) => f.includes("NXDOMAIN"))).toBe(true);
    });

    it("should build query timeline", () => {
      const log = "10:00:00 host: query ok\n10:00:01 host: query ok\n11:00:00 host: query ok\n";
      const result = analyzeQueryLog(log);
      expect(result.queryTimeline["10:00"]).toBe(2);
      expect(result.queryTimeline["11:00"]).toBe(1);
    });

    it("should handle empty log", () => {
      const result = analyzeQueryLog("");
      expect(result.totalEntries).toBe(0);
      expect(result.topDomains.length).toBe(0);
      expect(result.nxdomainRate).toBe(0);
    });
  });

  describe("auditResolvConf", () => {
    it("should parse nameservers", () => {
      const result = auditResolvConf("nameserver 8.8.8.8\nnameserver 1.1.1.1\n", "");
      expect(result.nameservers.length).toBe(2);
      expect(result.nameservers[0].ip).toBe("8.8.8.8");
      expect(result.nameservers[0].type).toBe("public");
    });

    it("should identify internal resolvers", () => {
      const result = auditResolvConf("nameserver 192.168.1.1\n", "");
      expect(result.nameservers[0].type).toBe("internal");
    });

    it("should identify loopback resolvers", () => {
      const result = auditResolvConf("nameserver 127.0.0.1\n", "");
      expect(result.nameservers[0].type).toBe("loopback");
    });

    it("should parse search domains", () => {
      const result = auditResolvConf("search example.com corp.local\n", "");
      expect(result.searchDomains).toEqual(["example.com", "corp.local"]);
    });

    it("should parse options", () => {
      const result = auditResolvConf("options edns0 trust-ad\n", "");
      expect(result.options).toEqual(["edns0", "trust-ad"]);
    });

    it("should warn on single nameserver", () => {
      const result = auditResolvConf("nameserver 8.8.8.8\n", "");
      expect(result.findings.some((f) => f.status === "WARN")).toBe(true);
    });

    it("should fail on no nameservers", () => {
      const result = auditResolvConf("# empty\n", "");
      expect(result.findings.some((f) => f.status === "FAIL" && f.check === "nameserver_count")).toBe(true);
    });

    it("should pass on multiple nameservers", () => {
      const result = auditResolvConf("nameserver 8.8.8.8\nnameserver 1.1.1.1\n", "");
      expect(result.findings.some((f) => f.status === "PASS" && f.check === "nameserver_count")).toBe(true);
    });

    it("should detect DNS over TLS enabled", () => {
      const result = auditResolvConf("nameserver 8.8.8.8\n", "DNSOverTLS: yes\nDNSSEC: yes\n");
      expect(result.findings.some((f) => f.check === "dns_over_tls" && f.status === "PASS")).toBe(true);
    });

    it("should detect DNS over TLS disabled", () => {
      const result = auditResolvConf("nameserver 8.8.8.8\n", "DNSOverTLS: no\n");
      expect(result.findings.some((f) => f.check === "dns_over_tls" && f.status === "FAIL")).toBe(true);
    });

    it("should detect DNSSEC enabled", () => {
      const result = auditResolvConf("nameserver 8.8.8.8\n", "DNSSEC: yes\n");
      expect(result.findings.some((f) => f.check === "dnssec_validation" && f.status === "PASS")).toBe(true);
    });

    it("should detect DNSSEC disabled", () => {
      const result = auditResolvConf("nameserver 8.8.8.8\n", "DNSSEC: no\n");
      expect(result.findings.some((f) => f.check === "dnssec_validation" && f.status === "FAIL")).toBe(true);
    });

    it("should skip comments", () => {
      const result = auditResolvConf("# comment\nnameserver 8.8.8.8\n", "");
      expect(result.nameservers.length).toBe(1);
    });
  });
});
