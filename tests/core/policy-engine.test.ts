import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  validateRuleCheck,
  safeRegexTest,
  loadPolicy,
  savePolicy,
  evaluateRule,
  BUILTIN_RULE_TEMPLATES,
  type PolicyRule,
  type PolicySet,
} from "../../src/core/policy-engine.js";

// ── Mocks ────────────────────────────────────────────────────────────────────

// Mock the command allowlist — accept common security binaries
vi.mock("../../src/core/command-allowlist.js", () => {
  const ALLOWED = new Set([
    "sysctl",
    "grep",
    "sed",
    "find",
    "stat",
    "systemctl",
    "findmnt",
    "which",
    "aa-enabled",
    "docker",
    "cat",
    "ls",
    "iptables",
    "ufw",
    "auditctl",
    "fail2ban-client",
    "aide",
    "lynis",
    "nmap",
    "openssl",
  ]);
  return {
    isAllowlisted: (cmd: string) => ALLOWED.has(cmd),
    resolveCommand: (cmd: string) => {
      if (!ALLOWED.has(cmd)) throw new Error(`Not allowlisted: ${cmd}`);
      return `/usr/bin/${cmd}`;
    },
  };
});

// Mock executor
vi.mock("../../src/core/executor.js", () => ({
  executeCommand: vi.fn(),
}));

// Mock secure-fs
vi.mock("../../src/core/secure-fs.js", () => ({
  secureWriteFileSync: vi.fn(),
  secureMkdirSync: vi.fn(),
}));

// Mock config
vi.mock("../../src/core/config.js", () => ({
  getConfig: () => ({
    policyDir: "/tmp/test-policies",
  }),
}));

// Mock fs — only readFileSync and readdirSync are used by policy-engine
vi.mock("node:fs", async () => {
  const actual =
    await vi.importActual<typeof import("node:fs")>("node:fs");
  return {
    ...actual,
    readFileSync: vi.fn(),
    readdirSync: vi.fn(() => []),
  };
});

import { executeCommand } from "../../src/core/executor.js";
import { secureWriteFileSync } from "../../src/core/secure-fs.js";
import { readFileSync } from "node:fs";

const mockedExec = vi.mocked(executeCommand);
const mockedWriteFile = vi.mocked(secureWriteFileSync);
const mockedReadFile = vi.mocked(readFileSync);

// ── Helpers ──────────────────────────────────────────────────────────────────

function makeRule(overrides: Partial<PolicyRule> = {}): PolicyRule {
  return {
    id: "TEST-001",
    title: "Test rule",
    description: "A test rule",
    severity: "medium",
    category: "test",
    check: ["sysctl", "-n", "net.ipv4.ip_forward"],
    expectedOutput: "^0$",
    ...overrides,
  };
}

function makeCommandResult(overrides: Record<string, unknown> = {}) {
  return {
    stdout: "",
    stderr: "",
    exitCode: 0,
    timedOut: false,
    duration: 10,
    permissionDenied: false,
    ...overrides,
  };
}

function makePolicyJson(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    name: "Test Policy",
    version: "1.0.0",
    description: "A test policy",
    rules: [
      {
        id: "TEST-001",
        title: "Test rule",
        description: "A test rule",
        severity: "medium",
        category: "test",
        check: ["sysctl", "-n", "net.ipv4.ip_forward"],
        expectedOutput: "^0$",
      },
    ],
    ...overrides,
  });
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe("policy-engine", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // ── validateRuleCheck ────────────────────────────────────────────────────

  describe("validateRuleCheck", () => {
    it("should accept a valid allowlisted command", () => {
      expect(() => validateRuleCheck(["sysctl", "-n", "net.ipv4.ip_forward"])).not.toThrow();
    });

    it("should accept grep with regex arguments containing shell metacharacters", () => {
      // Shell metacharacters in args are harmless because execFile doesn't use a shell
      expect(() =>
        validateRuleCheck(["grep", "-E", "pam_faillock", "/etc/pam.d/common-auth"])
      ).not.toThrow();
    });

    it("should reject empty array", () => {
      expect(() => validateRuleCheck([])).toThrow("non-empty array");
    });

    it("should reject non-array input", () => {
      expect(() => validateRuleCheck(null as unknown as string[])).toThrow("non-empty array");
    });

    it("should reject sh as command", () => {
      expect(() => validateRuleCheck(["sh", "-c", "echo hello"])).toThrow(
        "Shell interpreter 'sh' is not allowed"
      );
    });

    it("should reject bash as command", () => {
      expect(() => validateRuleCheck(["bash", "-c", "echo hello"])).toThrow(
        "Shell interpreter 'bash' is not allowed"
      );
    });

    it("should reject zsh as command", () => {
      expect(() => validateRuleCheck(["zsh", "-c", "echo hello"])).toThrow(
        "Shell interpreter 'zsh' is not allowed"
      );
    });

    it("should reject dash as command", () => {
      expect(() => validateRuleCheck(["dash", "-c", "echo hello"])).toThrow(
        "Shell interpreter 'dash' is not allowed"
      );
    });

    it("should reject fish as command", () => {
      expect(() => validateRuleCheck(["fish", "-c", "echo hello"])).toThrow(
        "Shell interpreter 'fish' is not allowed"
      );
    });

    it("should reject ksh as command", () => {
      expect(() => validateRuleCheck(["ksh", "-c", "echo hello"])).toThrow(
        "Shell interpreter 'ksh' is not allowed"
      );
    });

    it("should reject absolute path to sh", () => {
      expect(() => validateRuleCheck(["/bin/sh", "-c", "echo hello"])).toThrow(
        "Shell interpreter '/bin/sh' is not allowed"
      );
    });

    it("should reject /usr/bin/bash", () => {
      expect(() => validateRuleCheck(["/usr/bin/bash", "-c", "echo hello"])).toThrow(
        "Shell interpreter '/usr/bin/bash' is not allowed"
      );
    });

    it("should reject command not in allowlist", () => {
      expect(() => validateRuleCheck(["nc", "-l", "-p", "4444"])).toThrow(
        "not in the security allowlist"
      );
    });

    it("should reject arguments containing null bytes", () => {
      expect(() => validateRuleCheck(["sysctl", "-n\0injected"])).toThrow(
        "null bytes"
      );
    });

    it("should reject arguments containing control characters", () => {
      expect(() => validateRuleCheck(["sysctl", "\x01evil"])).toThrow(
        "control characters"
      );
    });

    it("should use the label parameter in error messages", () => {
      expect(() => validateRuleCheck([], "remediation")).toThrow(
        "remediation must be a non-empty array"
      );
    });

    it("should reject non-string arguments", () => {
      expect(() =>
        validateRuleCheck(["sysctl", 123 as unknown as string])
      ).toThrow("not a string");
    });
  });

  // ── safeRegexTest ────────────────────────────────────────────────────────

  describe("safeRegexTest", () => {
    it("should match a simple pattern", () => {
      expect(safeRegexTest("^0$", "0")).toBe(true);
    });

    it("should not match when pattern doesn't fit", () => {
      expect(safeRegexTest("^0$", "1")).toBe(false);
    });

    it("should support multiline matching", () => {
      expect(safeRegexTest("^active$", "active\nother")).toBe(true);
    });

    it("should reject nested quantifier (a+)+", () => {
      expect(() => safeRegexTest("(a+)+", "aaa")).toThrow("ReDoS");
    });

    it("should reject nested quantifier (a*)*", () => {
      expect(() => safeRegexTest("(a*)*", "aaa")).toThrow("ReDoS");
    });

    it("should reject repeated quantifiers ++", () => {
      expect(() => safeRegexTest("a++", "aaa")).toThrow("ReDoS");
    });

    it("should reject repeated quantifiers **", () => {
      expect(() => safeRegexTest("a**", "aaa")).toThrow("ReDoS");
    });

    it("should reject patterns that are too long", () => {
      const longPattern = "a".repeat(1025);
      expect(() => safeRegexTest(longPattern, "aaa")).toThrow("too long");
    });

    it("should throw on invalid regex syntax", () => {
      expect(() => safeRegexTest("[invalid", "test")).toThrow("Invalid regex");
    });

    it("should handle legitimate complex patterns", () => {
      // This is a real pattern from the policy templates
      expect(
        safeRegexTest(
          "PASS_MAX_DAYS\\s+([1-9]|[1-9][0-9]|[12][0-9]{2}|3[0-5][0-9]|36[0-5])$",
          "PASS_MAX_DAYS\t365"
        )
      ).toBe(true);
    });

    it("should handle escape sequences in patterns", () => {
      expect(
        safeRegexTest("PermitRootLogin\\s+no", "PermitRootLogin no")
      ).toBe(true);
    });
  });

  // ── loadPolicy ───────────────────────────────────────────────────────────

  describe("loadPolicy", () => {
    it("should load and validate a well-formed policy", () => {
      mockedReadFile.mockReturnValue(makePolicyJson());
      const result = loadPolicy("/tmp/test.json");
      expect(result.name).toBe("Test Policy");
      expect(result.rules).toHaveLength(1);
      expect(result.rules[0].id).toBe("TEST-001");
    });

    it("should reject policy with missing name", () => {
      mockedReadFile.mockReturnValue(
        JSON.stringify({ rules: [{ id: "X", check: ["sysctl"] }] })
      );
      expect(() => loadPolicy("/tmp/bad.json")).toThrow("Invalid policy file");
    });

    it("should reject policy with empty rules array", () => {
      mockedReadFile.mockReturnValue(
        JSON.stringify({ name: "Empty", rules: [] })
      );
      expect(() => loadPolicy("/tmp/bad.json")).toThrow("Invalid policy file");
    });

    it("should reject policy with no rules field", () => {
      mockedReadFile.mockReturnValue(JSON.stringify({ name: "No rules" }));
      expect(() => loadPolicy("/tmp/bad.json")).toThrow("Invalid policy file");
    });

    it("should reject rule with empty check array", () => {
      mockedReadFile.mockReturnValue(
        makePolicyJson({
          rules: [
            {
              id: "BAD",
              title: "Bad",
              description: "Bad rule",
              severity: "low",
              category: "test",
              check: [],
            },
          ],
        })
      );
      expect(() => loadPolicy("/tmp/bad.json")).toThrow("Invalid policy file");
    });

    it("should reject rule with sh -c in check", () => {
      mockedReadFile.mockReturnValue(
        makePolicyJson({
          rules: [
            {
              id: "SHELL-001",
              title: "Shell rule",
              description: "Uses shell",
              severity: "low",
              category: "test",
              check: ["sh", "-c", "echo hello"],
            },
          ],
        })
      );
      expect(() => loadPolicy("/tmp/bad.json")).toThrow(
        "Shell interpreter 'sh' is not allowed"
      );
    });

    it("should reject rule with non-allowlisted command in check", () => {
      mockedReadFile.mockReturnValue(
        makePolicyJson({
          rules: [
            {
              id: "NC-001",
              title: "Netcat rule",
              description: "Uses nc",
              severity: "low",
              category: "test",
              check: ["nc", "-l", "4444"],
            },
          ],
        })
      );
      expect(() => loadPolicy("/tmp/bad.json")).toThrow(
        "not in the security allowlist"
      );
    });

    it("should reject rule with sh -c in remediation", () => {
      mockedReadFile.mockReturnValue(
        makePolicyJson({
          rules: [
            {
              id: "REM-001",
              title: "Remediation rule",
              description: "Has shell remediation",
              severity: "low",
              category: "test",
              check: ["sysctl", "-n", "net.ipv4.ip_forward"],
              remediation: ["bash", "-c", "echo fix"],
            },
          ],
        })
      );
      expect(() => loadPolicy("/tmp/bad.json")).toThrow(
        "Shell interpreter 'bash' is not allowed"
      );
    });

    it("should reject rule with excessively long id", () => {
      mockedReadFile.mockReturnValue(
        makePolicyJson({
          rules: [
            {
              id: "A".repeat(200),
              check: ["sysctl", "-n", "net.ipv4.ip_forward"],
            },
          ],
        })
      );
      expect(() => loadPolicy("/tmp/bad.json")).toThrow("Invalid policy file");
    });

    it("should accept policy with default fields filled in", () => {
      // Minimal valid policy — schema defaults fill in missing optional fields
      mockedReadFile.mockReturnValue(
        JSON.stringify({
          name: "Minimal",
          rules: [
            {
              id: "MIN-001",
              check: ["sysctl", "-n", "net.ipv4.ip_forward"],
            },
          ],
        })
      );
      const result = loadPolicy("/tmp/minimal.json");
      expect(result.name).toBe("Minimal");
      expect(result.version).toBe("1.0.0");
      expect(result.rules[0].severity).toBe("medium");
      expect(result.rules[0].category).toBe("general");
    });

    it("should reject too many rules", () => {
      const rules = Array.from({ length: 201 }, (_, i) => ({
        id: `RULE-${i}`,
        check: ["sysctl", "-n", "net.ipv4.ip_forward"],
      }));
      mockedReadFile.mockReturnValue(
        JSON.stringify({ name: "TooMany", rules })
      );
      expect(() => loadPolicy("/tmp/bad.json")).toThrow("Invalid policy file");
    });

    it("should reject invalid JSON", () => {
      mockedReadFile.mockReturnValue("not valid json {{{");
      expect(() => loadPolicy("/tmp/bad.json")).toThrow();
    });
  });

  // ── savePolicy ───────────────────────────────────────────────────────────

  describe("savePolicy", () => {
    it("should use secureWriteFileSync instead of plain writeFileSync", () => {
      const policy: PolicySet = {
        name: "Test",
        version: "1.0.0",
        description: "Test",
        rules: [],
      };
      savePolicy("/tmp/test-policy.json", policy);
      expect(mockedWriteFile).toHaveBeenCalledWith(
        "/tmp/test-policy.json",
        expect.any(String),
        "utf-8"
      );
    });

    it("should write properly formatted JSON", () => {
      const policy: PolicySet = {
        name: "Test",
        version: "1.0.0",
        description: "Test",
        rules: [],
      };
      savePolicy("/tmp/test.json", policy);
      const writtenContent = mockedWriteFile.mock.calls[0][1] as string;
      expect(JSON.parse(writtenContent)).toEqual(policy);
      // 2-space indentation
      expect(writtenContent).toContain("  ");
    });
  });

  // ── evaluateRule ─────────────────────────────────────────────────────────

  describe("evaluateRule", () => {
    it("should validate the check command before executing", async () => {
      const rule = makeRule({ check: ["sh", "-c", "echo hello"] });
      const result = await evaluateRule(rule);
      expect(result.passed).toBe(false);
      expect(result.message).toContain("Shell interpreter");
      // Should NOT have called executeCommand
      expect(mockedExec).not.toHaveBeenCalled();
    });

    it("should reject non-allowlisted commands", async () => {
      const rule = makeRule({ check: ["nc", "-l", "4444"] });
      const result = await evaluateRule(rule);
      expect(result.passed).toBe(false);
      expect(result.message).toContain("not in the security allowlist");
      expect(mockedExec).not.toHaveBeenCalled();
    });

    it("should execute valid commands and check output", async () => {
      mockedExec.mockResolvedValue(makeCommandResult({
        stdout: "0\n",
      }));
      const rule = makeRule();
      const result = await evaluateRule(rule);
      expect(result.passed).toBe(true);
      expect(result.actual).toBe("0");
      expect(mockedExec).toHaveBeenCalledWith({
        command: "sysctl",
        args: ["-n", "net.ipv4.ip_forward"],
        timeout: 30_000,
      });
    });

    it("should fail when output doesn't match expected pattern", async () => {
      mockedExec.mockResolvedValue(makeCommandResult({
        stdout: "1\n",
      }));
      const rule = makeRule({ expectedOutput: "^0$" });
      const result = await evaluateRule(rule);
      expect(result.passed).toBe(false);
      expect(result.message).toContain("not found in output");
    });

    it("should pass on exit code 0 when no expectedOutput", async () => {
      mockedExec.mockResolvedValue(makeCommandResult({
        stdout: "anything\n",
      }));
      const rule = makeRule({ expectedOutput: undefined });
      const result = await evaluateRule(rule);
      expect(result.passed).toBe(true);
      expect(result.message).toContain("exit code 0");
    });

    it("should fail on non-zero exit code when no expectedOutput", async () => {
      mockedExec.mockResolvedValue(makeCommandResult({
        stdout: "",
        stderr: "not found\n",
        exitCode: 1,
      }));
      const rule = makeRule({ expectedOutput: undefined });
      const result = await evaluateRule(rule);
      expect(result.passed).toBe(false);
      expect(result.message).toContain("exit code 1");
    });

    it("should handle empty check array gracefully", async () => {
      const rule = makeRule({ check: [] });
      const result = await evaluateRule(rule);
      expect(result.passed).toBe(false);
      expect(result.message).toContain("no check command");
    });

    it("should handle execution errors gracefully", async () => {
      mockedExec.mockRejectedValue(new Error("Command timed out"));
      const rule = makeRule();
      const result = await evaluateRule(rule);
      expect(result.passed).toBe(false);
      expect(result.message).toContain("Command timed out");
    });

    it("should reject ReDoS patterns in expectedOutput", async () => {
      mockedExec.mockResolvedValue(makeCommandResult({
        stdout: "aaa\n",
      }));
      const rule = makeRule({ expectedOutput: "(a+)+" });
      const result = await evaluateRule(rule);
      expect(result.passed).toBe(false);
      expect(result.message).toContain("ReDoS");
    });

    it("should fall back to substring match for simple invalid regex", async () => {
      mockedExec.mockResolvedValue(makeCommandResult({
        stdout: "hello [world\n",
      }));
      const rule = makeRule({ expectedOutput: "[world" });
      const result = await evaluateRule(rule);
      // "[world" is invalid regex but substring match should find it
      expect(result.passed).toBe(true);
    });
  });

  // ── BUILTIN_RULE_TEMPLATES ───────────────────────────────────────────────

  describe("BUILTIN_RULE_TEMPLATES", () => {
    it("should contain no sh -c patterns in check arrays", () => {
      for (const rule of BUILTIN_RULE_TEMPLATES) {
        expect(rule.check[0]).not.toBe("sh");
        expect(rule.check[0]).not.toBe("bash");
        expect(rule.check[0]).not.toBe("/bin/sh");
        expect(rule.check[0]).not.toBe("/bin/bash");
      }
    });

    it("should contain no sh -c patterns in remediation arrays", () => {
      for (const rule of BUILTIN_RULE_TEMPLATES) {
        if (rule.remediation) {
          expect(rule.remediation[0]).not.toBe("sh");
          expect(rule.remediation[0]).not.toBe("bash");
          expect(rule.remediation[0]).not.toBe("/bin/sh");
          expect(rule.remediation[0]).not.toBe("/bin/bash");
        }
      }
    });

    it("should have all check commands in the allowlist", () => {
      for (const rule of BUILTIN_RULE_TEMPLATES) {
        expect(() =>
          validateRuleCheck(rule.check, `builtin ${rule.id} check`)
        ).not.toThrow();
      }
    });

    it("should have all remediation commands in the allowlist", () => {
      for (const rule of BUILTIN_RULE_TEMPLATES) {
        if (rule.remediation) {
          expect(() =>
            validateRuleCheck(
              rule.remediation!,
              `builtin ${rule.id} remediation`
            )
          ).not.toThrow();
        }
      }
    });

    it("should have unique IDs", () => {
      const ids = BUILTIN_RULE_TEMPLATES.map((r) => r.id);
      const unique = new Set(ids);
      expect(unique.size).toBe(ids.length);
    });

    it("should have valid severity levels", () => {
      const validSeverities = ["critical", "high", "medium", "low", "info"];
      for (const rule of BUILTIN_RULE_TEMPLATES) {
        expect(validSeverities).toContain(rule.severity);
      }
    });

    it("should have at least 10 rules", () => {
      expect(BUILTIN_RULE_TEMPLATES.length).toBeGreaterThanOrEqual(10);
    });
  });
});
