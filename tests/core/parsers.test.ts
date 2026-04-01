/**
 * Tests for src/core/parsers.ts
 */
import { describe, it, expect } from "vitest";
import {
  parseKeyValue,
  parseTable,
  parseJsonSafe,
  formatToolOutput,
  createTextContent,
  createErrorContent,
  parseIptablesOutput,
  parseNftOutput,
  parseSysctlOutput,
  parseAuditdOutput,
  parseLynisOutput,
  parseOscapOutput,
  parseClamavOutput,
  extractClamavSummary,
  parseSsOutput,
  parseFail2banOutput,
  parseSystemctlOutput,
  MAX_OUTPUT_SIZE,
  truncateWithMetadata,
  DEFAULT_MAX_ITEMS,
} from "../../src/core/parsers.js";

// ── Generic parsers ──────────────────────────────────────────────────────────

describe("parseKeyValue", () => {
  it("parses key:value pairs separated by colon", () => {
    const result = parseKeyValue("Name: John\nAge: 30\nCity: NYC");
    expect(result).toEqual({ Name: "John", Age: "30", City: "NYC" });
  });

  it("skips lines without separator", () => {
    const result = parseKeyValue("Name: John\nno-separator-here\nAge: 30");
    expect(result).toEqual({ Name: "John", Age: "30" });
  });

  it("handles custom separator", () => {
    const result = parseKeyValue("x = 1\ny = 2", "=");
    expect(result).toEqual({ x: "1", y: "2" });
  });

  it("returns empty object for empty input", () => {
    expect(parseKeyValue("")).toEqual({});
  });

  it("handles values containing the separator", () => {
    const result = parseKeyValue("URL: http://example.com:8080");
    expect(result["URL"]).toBe("http://example.com:8080");
  });

  it("trims keys and values", () => {
    const result = parseKeyValue("  key  :  value  ");
    expect(result["key"]).toBe("value");
  });
});

describe("parseTable", () => {
  it("parses whitespace-delimited table with headers", () => {
    const input = "NAME    AGE    CITY\nJohn    30     NYC\nJane    25     LA";
    const rows = parseTable(input);
    expect(rows).toHaveLength(2);
    expect(rows[0]).toEqual({ name: "John", age: "30", city: "NYC" });
    expect(rows[1]).toEqual({ name: "Jane", age: "25", city: "LA" });
  });

  it("returns empty array for input with only headers", () => {
    expect(parseTable("HEADER1 HEADER2")).toEqual([]);
  });

  it("returns empty array for empty input", () => {
    expect(parseTable("")).toEqual([]);
  });

  it("last column captures remaining text (values with spaces)", () => {
    const input = "PID  CMD\n1234 /usr/bin/node server.js";
    const rows = parseTable(input);
    expect(rows[0]["cmd"]).toBe("/usr/bin/node server.js");
  });
});

describe("parseJsonSafe", () => {
  it("parses valid JSON", () => {
    expect(parseJsonSafe('{"key": "value"}')).toEqual({ key: "value" });
  });

  it("returns null for invalid JSON", () => {
    expect(parseJsonSafe("not json")).toBeNull();
  });

  it("parses JSON arrays", () => {
    expect(parseJsonSafe("[1, 2, 3]")).toEqual([1, 2, 3]);
  });

  it("returns null for empty string", () => {
    expect(parseJsonSafe("")).toBeNull();
  });
});

describe("formatToolOutput", () => {
  it("formats strings as-is", () => {
    const result = formatToolOutput("hello");
    expect(result).toEqual({ type: "text", text: "hello" });
  });

  it("formats objects as JSON with indentation", () => {
    const result = formatToolOutput({ key: "value" });
    expect(result.type).toBe("text");
    expect(result.text).toContain('"key"');
    expect(result.text).toContain('"value"');
  });

  it("does not globally truncate large output (tools control their own size)", () => {
    const hugeString = "x".repeat(MAX_OUTPUT_SIZE + 1000);
    const result = formatToolOutput(hugeString);
    // Global truncation was removed — output passes through unmodified
    expect(result.text).toBe(hugeString);
    expect(result.text).not.toContain("[OUTPUT TRUNCATED:");
  });

  it("does not truncate large JSON output (tools use truncateWithMetadata instead)", () => {
    const bigData = { items: Array.from({ length: 5000 }, (_, i) => ({ id: i, name: "x".repeat(50) })) };
    const result = formatToolOutput(bigData);
    // Full JSON is preserved — no mid-JSON truncation
    expect(result.text).toBe(JSON.stringify(bigData));
    expect(result.text).not.toContain("[OUTPUT TRUNCATED:");
  });

  it("does not truncate output under MAX_OUTPUT_SIZE", () => {
    const normalData = { key: "value", nested: { a: 1, b: 2 } };
    const result = formatToolOutput(normalData);
    expect(result.text).not.toContain("[OUTPUT TRUNCATED:");
    expect(result.text).toBe(JSON.stringify(normalData));
  });
});

describe("truncateWithMetadata", () => {
  it("returns all items when under limit", () => {
    const items = [1, 2, 3, 4, 5];
    const { items: result, meta } = truncateWithMetadata(items, 10);
    expect(result).toEqual([1, 2, 3, 4, 5]);
    expect(meta).toEqual({ truncated: false, total_count: 5, showing: 5 });
  });

  it("truncates items exceeding limit and includes metadata", () => {
    const items = Array.from({ length: 2000 }, (_, i) => `item-${i}`);
    const { items: result, meta } = truncateWithMetadata(items, 500);
    expect(result).toHaveLength(500);
    expect(result[0]).toBe("item-0");
    expect(result[499]).toBe("item-499");
    expect(meta).toEqual({ truncated: true, total_count: 2000, showing: 500 });
  });

  it("handles exact limit boundary (not truncated)", () => {
    const items = [1, 2, 3];
    const { items: result, meta } = truncateWithMetadata(items, 3);
    expect(result).toEqual([1, 2, 3]);
    expect(meta.truncated).toBe(false);
  });

  it("handles empty array", () => {
    const { items: result, meta } = truncateWithMetadata([], 100);
    expect(result).toEqual([]);
    expect(meta).toEqual({ truncated: false, total_count: 0, showing: 0 });
  });

  it("uses DEFAULT_MAX_ITEMS when no limit specified", () => {
    const items = Array.from({ length: DEFAULT_MAX_ITEMS + 100 }, (_, i) => i);
    const { items: result, meta } = truncateWithMetadata(items);
    expect(result).toHaveLength(DEFAULT_MAX_ITEMS);
    expect(meta.truncated).toBe(true);
    expect(meta.total_count).toBe(DEFAULT_MAX_ITEMS + 100);
    expect(meta.showing).toBe(DEFAULT_MAX_ITEMS);
  });

  it("preserves object references in truncated arrays", () => {
    const obj1 = { id: 1, name: "test" };
    const obj2 = { id: 2, name: "test2" };
    const items = [obj1, obj2, { id: 3 }];
    const { items: result } = truncateWithMetadata(items, 2);
    expect(result[0]).toBe(obj1);
    expect(result[1]).toBe(obj2);
  });
});

describe("createTextContent", () => {
  it("creates MCP text content object", () => {
    expect(createTextContent("hello")).toEqual({ type: "text", text: "hello" });
  });
});

describe("createErrorContent", () => {
  it("creates MCP text content with Error prefix", () => {
    const result = createErrorContent("something went wrong");
    expect(result).toEqual({ type: "text", text: "Error: something went wrong" });
  });
});

// ── Firewall parsers ─────────────────────────────────────────────────────────

describe("parseIptablesOutput", () => {
  const sampleOutput = `Chain INPUT (policy ACCEPT 100 packets, 5000 bytes)
 pkts bytes target     prot opt in     out     source               destination
  50  3000 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22
  25  1500 DROP       tcp  --  *      *       10.0.0.0/8           0.0.0.0/0            tcp dpt:80

Chain FORWARD (policy DROP 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination

Chain OUTPUT (policy ACCEPT 200 packets, 10000 bytes)
 pkts bytes target     prot opt in     out     source               destination`;

  it("parses iptables rules with chain context", () => {
    const rules = parseIptablesOutput(sampleOutput);
    expect(rules.length).toBeGreaterThanOrEqual(2);
    expect(rules[0].chain).toBe("INPUT");
    expect(rules[0].target).toBe("ACCEPT");
    expect(rules[0].protocol).toBe("tcp");
    expect(rules[0].source).toBe("0.0.0.0/0");
  });

  it("detects chain policy", () => {
    const rules = parseIptablesOutput(sampleOutput);
    expect(rules[0].policy).toBe("ACCEPT");
  });

  it("returns empty array for empty input", () => {
    expect(parseIptablesOutput("")).toEqual([]);
  });
});

describe("parseNftOutput", () => {
  it("parses nft ruleset into table sections", () => {
    const input = `table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
  }
}`;
    const result = parseNftOutput(input);
    expect(result["inet filter"]).toBeDefined();
    expect(result["inet filter"].length).toBeGreaterThan(0);
  });

  it("returns empty object for empty input", () => {
    expect(parseNftOutput("")).toEqual({});
  });
});

// ── System parsers ───────────────────────────────────────────────────────────

describe("parseSysctlOutput", () => {
  it("parses sysctl key=value entries", () => {
    const input = "net.ipv4.ip_forward = 0\nkernel.randomize_va_space = 2";
    const entries = parseSysctlOutput(input);
    expect(entries).toHaveLength(2);
    expect(entries[0]).toEqual({ key: "net.ipv4.ip_forward", value: "0" });
    expect(entries[1]).toEqual({ key: "kernel.randomize_va_space", value: "2" });
  });

  it("returns empty array for empty input", () => {
    expect(parseSysctlOutput("")).toEqual([]);
  });

  it("skips lines without = separator", () => {
    const entries = parseSysctlOutput("some_comment\nkey = value");
    expect(entries).toHaveLength(1);
  });
});

// ── Audit parsers ────────────────────────────────────────────────────────────

describe("parseAuditdOutput", () => {
  it("parses audit log entries", () => {
    const input =
      'type=SYSCALL msg=audit(1234567890.123:456): arch=c000003e syscall=59 success=yes exit=0 a0=55f7c pid=1234';
    const entries = parseAuditdOutput(input);
    expect(entries).toHaveLength(1);
    expect(entries[0].type).toBe("SYSCALL");
    expect(entries[0].timestamp).toBe("1234567890.123:456");
    expect(entries[0].fields["arch"]).toBe("c000003e");
  });

  it("returns empty array for empty input", () => {
    expect(parseAuditdOutput("")).toEqual([]);
  });

  it("skips separator and time lines", () => {
    const input = "----\ntime->Mon Mar 7 2026\n";
    expect(parseAuditdOutput(input)).toEqual([]);
  });
});

// ── Assessment parsers ───────────────────────────────────────────────────────

describe("parseLynisOutput", () => {
  it("parses warnings, suggestions, and findings", () => {
    const input = `
  Warning: [AUTH-9328] Default umask in /etc/login.defs is too permissive
  Suggestion: [FILE-6310] Consider restricting file permissions
  * Finding [BOOT-5122] No password set for GRUB
`;
    const findings = parseLynisOutput(input);
    expect(findings).toHaveLength(3);
    expect(findings[0].severity).toBe("warning");
    expect(findings[0].testId).toBe("AUTH-9328");
    expect(findings[1].severity).toBe("suggestion");
    expect(findings[2].severity).toBe("finding");
  });

  it("returns empty array for clean output", () => {
    expect(parseLynisOutput("Everything looks good")).toEqual([]);
  });
});

describe("parseOscapOutput", () => {
  it("parses OpenSCAP rule results", () => {
    const input = `Title   : Ensure SSH root login is disabled
Rule    : xccdf_rule_sshd_disable_root
Result  : fail
Severity: high`;
    const results = parseOscapOutput(input);
    expect(results).toHaveLength(1);
    expect(results[0].ruleId).toBe("xccdf_rule_sshd_disable_root");
    expect(results[0].result).toBe("fail");
    expect(results[0].severity).toBe("high");
    expect(results[0].title).toBe("Ensure SSH root login is disabled");
  });

  it("returns empty array for empty input", () => {
    expect(parseOscapOutput("")).toEqual([]);
  });
});

// ── Malware parsers ──────────────────────────────────────────────────────────

describe("parseClamavOutput", () => {
  it("parses OK results", () => {
    const results = parseClamavOutput("/home/user/file.txt: OK");
    expect(results).toHaveLength(1);
    expect(results[0].status).toBe("OK");
    expect(results[0].file).toBe("/home/user/file.txt");
  });

  it("parses FOUND results with virus name", () => {
    const results = parseClamavOutput("/tmp/malware.exe: Eicar-Signature FOUND");
    expect(results).toHaveLength(1);
    expect(results[0].status).toBe("FOUND");
    expect(results[0].virus).toBe("Eicar-Signature");
  });

  it("parses ERROR results", () => {
    const results = parseClamavOutput("/dev/null: Empty file ERROR");
    expect(results).toHaveLength(1);
    expect(results[0].status).toBe("ERROR");
  });

  it("returns empty array for empty input", () => {
    expect(parseClamavOutput("")).toEqual([]);
  });
});

describe("extractClamavSummary", () => {
  it("extracts ClamAV built-in summary section", () => {
    const stdout = `/home/user/file1.txt: OK
/home/user/file2.txt: OK
/tmp/malware.exe: Eicar-Signature FOUND

----------- SCAN SUMMARY -----------
Known viruses: 8000000
Engine version: 1.0.0
Scanned directories: 5
Scanned files: 3
Infected files: 1
Data scanned: 0.50 MB
Time: 2.500 sec (0 m 2 s)`;
    const summary = extractClamavSummary(stdout);
    expect(summary).toContain("SCAN SUMMARY");
    expect(summary).toContain("Infected files: 1");
    expect(summary).toContain("Scanned files: 3");
    expect(summary).not.toContain("/home/user/file1.txt");
  });

  it("returns fallback summary when no summary marker found", () => {
    const stdout = `/home/user/file1.txt: OK
/home/user/file2.txt: OK
/tmp/malware.exe: Eicar-Signature FOUND`;
    const summary = extractClamavSummary(stdout);
    expect(summary).toContain("Scanned files:");
    expect(summary).toContain("Infected: 1");
  });

  it("handles empty input", () => {
    const summary = extractClamavSummary("");
    expect(summary).toContain("Scanned files: 0");
    expect(summary).toContain("Infected: 0");
  });

  it("truncates summary to 500 chars max", () => {
    // Create a very long fake summary section
    const longSummary = "----------- SCAN SUMMARY -----------\n" + "A".repeat(600);
    const summary = extractClamavSummary(longSummary);
    expect(summary.length).toBeLessThanOrEqual(500);
  });
});

// ── Network parsers ──────────────────────────────────────────────────────────

describe("parseSsOutput", () => {
  it("parses ss -tulnp output", () => {
    const input = `Netid  State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process
tcp    LISTEN  0       128     0.0.0.0:22         0.0.0.0:*          users:(("sshd",pid=1234,fd=3))
tcp    LISTEN  0       128     0.0.0.0:80         0.0.0.0:*          users:(("nginx",pid=5678,fd=6))`;
    const entries = parseSsOutput(input);
    expect(entries).toHaveLength(2);
    expect(entries[0].state).toBe("LISTEN");
    expect(entries[0].local).toBe("0.0.0.0:22");
  });

  it("returns empty array for header-only input", () => {
    const input = "Netid  State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port";
    expect(parseSsOutput(input)).toEqual([]);
  });
});

// ── Service parsers ──────────────────────────────────────────────────────────

describe("parseSystemctlOutput", () => {
  it("parses systemctl list-units output", () => {
    const input = `  UNIT                   LOAD   ACTIVE SUB     DESCRIPTION
  ssh.service            loaded active running OpenBSD Secure Shell server
● nginx.service          loaded failed failed  A high performance web server`;
    const units = parseSystemctlOutput(input);
    expect(units).toHaveLength(2);
    expect(units[0].unit).toBe("ssh.service");
    expect(units[0].active).toBe("active");
    expect(units[1].unit).toBe("nginx.service");
    expect(units[1].active).toBe("failed");
  });

  it("returns empty array for empty input", () => {
    expect(parseSystemctlOutput("")).toEqual([]);
  });

  it("skips header and legend lines", () => {
    const input = "UNIT LOAD ACTIVE SUB DESCRIPTION\nTo show all installed\nLEGEND: ...";
    expect(parseSystemctlOutput(input)).toEqual([]);
  });
});

describe("parseFail2banOutput", () => {
  it("parses fail2ban jail status", () => {
    const input = `Status for the jail: sshd
|- Currently failed: 3
|- Total failed: 10
|- Currently banned: 1
\`- Total banned: 5`;
    const jails = parseFail2banOutput(input);
    // The parser expects a specific format with banned IPs
    // but should at least capture the jail name and push remaining
    expect(jails.length).toBeGreaterThanOrEqual(1);
    expect(jails[0].name).toBe("sshd");
    expect(jails[0].currentlyFailed).toBe(3);
  });

  it("returns empty array for empty input", () => {
    expect(parseFail2banOutput("")).toEqual([]);
  });
});
