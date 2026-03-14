/**
 * Tests for src/core/pam-utils.ts
 *
 * Comprehensive tests for the PAM configuration parser, serializer,
 * validator, and manipulation helpers. These replaced the fragile sed-based
 * PAM manipulation that caused the critical lockout bug.
 *
 * Pure functions (parser, serializer, validator, helpers) are tested
 * WITHOUT mocks. I/O functions use mocked executeCommand.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

import {
  parsePamConfig,
  serializePamConfig,
  validatePamConfig,
  validatePamConfigContent,
  createPamRule,
  removeModuleRules,
  insertBeforeModule,
  insertAfterModule,
  findModuleRules,
  adjustJumpCounts,
  PamValidationError,
  PamWriteError,
  type PamRule,
  type PamComment,
  type PamBlank,
  type PamInclude,
  type PamLine,
} from "../../src/core/pam-utils.js";

// ── Test Fixtures ───────────────────────────────────────────────────────────

/** Standard Debian common-auth PAM config */
const DEBIAN_COMMON_AUTH = `#
# /etc/pam.d/common-auth - authentication settings common to all services
#
# This file is included from other service-specific PAM config files,
# and should contain a list of the authentication modules that define
# the central authentication scheme for use on the system
# (e.g., /etc/shadow, LDAP, Kerberos, etc.).  The default is to use the
# traditional Unix authentication mechanisms.
#

# here are the per-package modules (the "Primary" block)
auth\t[success=1 default=ignore]\tpam_unix.so nullok
# here's the fallback if no module succeeds
auth\trequisite\t\t\tpam_deny.so
# prime the stack with a positive return value if there isn't one already;
# this avoids us returning an error just because nothing sets a success code
# since the modules above will each just jump around
auth\trequired\t\t\tpam_permit.so
# and here are more per-package modules (the "Additional" block)
# end of pam-auth-update config`;

/** Minimal valid PAM config */
const MINIMAL_PAM = `auth required pam_unix.so
auth requisite pam_deny.so`;

/** PAM config with @include directives */
const PAM_WITH_INCLUDES = `# PAM config with includes
@include common-auth
auth required pam_unix.so
@include common-account`;

/** PAM config with tab-separated and multi-space-separated fields */
const PAM_MIXED_WHITESPACE = `auth\trequired\tpam_unix.so nullok
auth    requisite    pam_deny.so
auth\t\trequired\t\tpam_permit.so`;

// ── Parser Tests ────────────────────────────────────────────────────────────

describe("parsePamConfig", () => {
  it("parses a standard Debian common-auth file correctly", () => {
    const lines = parsePamConfig(DEBIAN_COMMON_AUTH);

    // Count line types
    const rules = lines.filter((l) => l.kind === "rule");
    const comments = lines.filter((l) => l.kind === "comment");
    const blanks = lines.filter((l) => l.kind === "blank");

    expect(rules.length).toBe(3);
    expect(comments.length).toBeGreaterThanOrEqual(10);
    expect(blanks.length).toBeGreaterThanOrEqual(1);

    // Verify the three rules
    const ruleList = rules as PamRule[];
    expect(ruleList[0].pamType).toBe("auth");
    expect(ruleList[0].control).toBe("[success=1 default=ignore]");
    expect(ruleList[0].module).toBe("pam_unix.so");
    expect(ruleList[0].args).toEqual(["nullok"]);

    expect(ruleList[1].pamType).toBe("auth");
    expect(ruleList[1].control).toBe("requisite");
    expect(ruleList[1].module).toBe("pam_deny.so");
    expect(ruleList[1].args).toEqual([]);

    expect(ruleList[2].pamType).toBe("auth");
    expect(ruleList[2].control).toBe("required");
    expect(ruleList[2].module).toBe("pam_permit.so");
    expect(ruleList[2].args).toEqual([]);
  });

  it("parses @include directives", () => {
    const lines = parsePamConfig(PAM_WITH_INCLUDES);
    const includes = lines.filter((l) => l.kind === "include") as PamInclude[];

    expect(includes.length).toBe(2);
    expect(includes[0].target).toBe("common-auth");
    expect(includes[1].target).toBe("common-account");
  });

  it("handles bracket-style controls like [success=1 default=ignore]", () => {
    const content = "auth\t[success=1 default=ignore]\tpam_unix.so nullok";
    const lines = parsePamConfig(content);
    const rules = lines.filter((l) => l.kind === "rule") as PamRule[];

    expect(rules.length).toBe(1);
    expect(rules[0].control).toBe("[success=1 default=ignore]");
    expect(rules[0].module).toBe("pam_unix.so");
    expect(rules[0].args).toEqual(["nullok"]);
  });

  it("handles tab-separated and multi-space-separated fields", () => {
    const lines = parsePamConfig(PAM_MIXED_WHITESPACE);
    const rules = lines.filter((l) => l.kind === "rule") as PamRule[];

    expect(rules.length).toBe(3);
    // All should parse correctly regardless of whitespace
    expect(rules[0].pamType).toBe("auth");
    expect(rules[0].control).toBe("required");
    expect(rules[0].module).toBe("pam_unix.so");
    expect(rules[0].args).toEqual(["nullok"]);

    expect(rules[1].pamType).toBe("auth");
    expect(rules[1].control).toBe("requisite");
    expect(rules[1].module).toBe("pam_deny.so");

    expect(rules[2].pamType).toBe("auth");
    expect(rules[2].control).toBe("required");
    expect(rules[2].module).toBe("pam_permit.so");
  });

  it("preserves comment and blank line structure (lossless)", () => {
    const content = `# Comment one
# Comment two

auth required pam_unix.so

# Trailing comment`;
    const lines = parsePamConfig(content);

    expect(lines[0]).toEqual({ kind: "comment", text: "# Comment one" });
    expect(lines[1]).toEqual({ kind: "comment", text: "# Comment two" });
    expect(lines[2]).toEqual({ kind: "blank" });
    expect(lines[3].kind).toBe("rule");
    expect(lines[4]).toEqual({ kind: "blank" });
    expect(lines[5]).toEqual({ kind: "comment", text: "# Trailing comment" });
  });

  it("handles malformed/unparseable lines as comments (doesn't crash)", () => {
    // A line with only one token can't be parsed as a PAM rule (needs at least 3: type control module)
    const content = `auth required pam_unix.so
singletoken
auth requisite pam_deny.so`;

    // Suppress console.error from the parser warning
    const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const lines = parsePamConfig(content);
    consoleSpy.mockRestore();

    expect(lines.length).toBe(3);
    expect(lines[0].kind).toBe("rule");
    // Garbage line preserved as comment
    expect(lines[1].kind).toBe("comment");
    expect((lines[1] as PamComment).text).toBe("singletoken");
    expect(lines[2].kind).toBe("rule");
  });

  it("parses rules with multiple arguments", () => {
    const content = "auth required pam_unix.so nullok try_first_pass sha512";
    const lines = parsePamConfig(content);
    const rules = lines.filter((l) => l.kind === "rule") as PamRule[];

    expect(rules.length).toBe(1);
    expect(rules[0].args).toEqual(["nullok", "try_first_pass", "sha512"]);
  });

  it("parses rules with complex bracket controls and multiple args", () => {
    const content = "auth [success=2 default=ignore] pam_unix.so nullok try_first_pass";
    const lines = parsePamConfig(content);
    const rules = lines.filter((l) => l.kind === "rule") as PamRule[];

    expect(rules.length).toBe(1);
    expect(rules[0].control).toBe("[success=2 default=ignore]");
    expect(rules[0].module).toBe("pam_unix.so");
    expect(rules[0].args).toEqual(["nullok", "try_first_pass"]);
  });

  it("parses rules with - prefix on pamType", () => {
    const content = "-auth optional pam_faillock.so preauth silent";
    const lines = parsePamConfig(content);
    const rules = lines.filter((l) => l.kind === "rule") as PamRule[];

    expect(rules.length).toBe(1);
    expect(rules[0].pamType).toBe("-auth");
    expect(rules[0].control).toBe("optional");
    expect(rules[0].module).toBe("pam_faillock.so");
    expect(rules[0].args).toEqual(["preauth", "silent"]);
  });

  it("handles empty input", () => {
    const lines = parsePamConfig("");
    // Empty input produces one blank line (from the empty string split)
    expect(lines.length).toBe(1);
    expect(lines[0].kind).toBe("blank");
  });

  it("preserves rawLine on parsed rules", () => {
    const rawInput = "auth\t[success=1 default=ignore]\tpam_unix.so nullok";
    const lines = parsePamConfig(rawInput);
    const rules = lines.filter((l) => l.kind === "rule") as PamRule[];

    expect(rules[0].rawLine).toBe(rawInput);
  });
});

// ── Serializer Tests ────────────────────────────────────────────────────────

describe("serializePamConfig", () => {
  it("produces properly formatted output with consistent separators", () => {
    const lines: PamLine[] = [
      createPamRule("auth", "required", "pam_unix.so", ["nullok"]),
      createPamRule("auth", "requisite", "pam_deny.so", []),
    ];

    const output = serializePamConfig(lines);
    const outputLines = output.trimEnd().split("\n");

    expect(outputLines[0]).toBe("auth    required    pam_unix.so nullok");
    expect(outputLines[1]).toBe("auth    requisite    pam_deny.so");
  });

  it("preserves comments and blank lines exactly", () => {
    const lines: PamLine[] = [
      { kind: "comment", text: "# This is a comment" },
      { kind: "blank" },
      createPamRule("auth", "required", "pam_unix.so", []),
      { kind: "comment", text: "# Another comment" },
    ];

    const output = serializePamConfig(lines);
    const outputLines = output.trimEnd().split("\n");

    expect(outputLines[0]).toBe("# This is a comment");
    expect(outputLines[1]).toBe("");
    expect(outputLines[2]).toBe("auth    required    pam_unix.so");
    expect(outputLines[3]).toBe("# Another comment");
  });

  it("produces output ending with newline", () => {
    const lines: PamLine[] = [
      createPamRule("auth", "required", "pam_unix.so", []),
    ];

    const output = serializePamConfig(lines);
    expect(output.endsWith("\n")).toBe(true);
  });

  it("round-trip: parse → serialize → parse produces identical structures", () => {
    const original = parsePamConfig(DEBIAN_COMMON_AUTH);
    const serialized = serializePamConfig(original);
    const reparsed = parsePamConfig(serialized);

    // Compare structural equivalence (ignoring rawLine which may differ after serialize)
    expect(reparsed.length).toBe(original.length);

    for (let i = 0; i < original.length; i++) {
      expect(reparsed[i].kind).toBe(original[i].kind);
      if (original[i].kind === "rule" && reparsed[i].kind === "rule") {
        const origRule = original[i] as PamRule;
        const reParsedRule = reparsed[i] as PamRule;
        expect(reParsedRule.pamType).toBe(origRule.pamType);
        expect(reParsedRule.control).toBe(origRule.control);
        expect(reParsedRule.module).toBe(origRule.module);
        expect(reParsedRule.args).toEqual(origRule.args);
      }
      if (original[i].kind === "comment" && reparsed[i].kind === "comment") {
        expect((reparsed[i] as PamComment).text).toBe((original[i] as PamComment).text);
      }
      if (original[i].kind === "include" && reparsed[i].kind === "include") {
        expect((reparsed[i] as PamInclude).target).toBe((original[i] as PamInclude).target);
      }
    }
  });

  it("CRITICAL REGRESSION: output lines NEVER contain concatenated fields", () => {
    // This is the original bug: sed commands produced lines like
    // "authrequiredpam_deny.so" with no whitespace between fields
    const lines: PamLine[] = [
      createPamRule("auth", "required", "pam_deny.so", []),
      createPamRule("auth", "[success=1 default=ignore]", "pam_unix.so", ["nullok"]),
      createPamRule("auth", "requisite", "pam_deny.so", []),
      createPamRule("auth", "required", "pam_permit.so", []),
    ];

    const output = serializePamConfig(lines);

    // Check that no line contains concatenated fields
    for (const line of output.split("\n")) {
      if (line.trim() === "" || line.trim().startsWith("#")) continue;

      // The original bug: "authrequiredpam_deny.so"
      expect(line).not.toMatch(/^auth(required|requisite|sufficient|optional)/);
      expect(line).not.toMatch(/^account(required|requisite|sufficient|optional)/);
      expect(line).not.toMatch(/^password(required|requisite|sufficient|optional)/);
      expect(line).not.toMatch(/^session(required|requisite|sufficient|optional)/);
      expect(line).not.toMatch(/required(pam_|\/)/);
      expect(line).not.toMatch(/requisite(pam_|\/)/);

      // Each rule line must have at least 3 whitespace-separated fields
      if (line.trim().length > 0) {
        const fields = line.trim().split(/\s+/);
        expect(fields.length).toBeGreaterThanOrEqual(3);
      }
    }
  });

  it("serializes include directives preserving raw line", () => {
    const lines: PamLine[] = [
      { kind: "include", target: "common-auth", rawLine: "@include common-auth" },
    ];

    const output = serializePamConfig(lines);
    expect(output.trimEnd()).toBe("@include common-auth");
  });
});

// ── Validator Tests ─────────────────────────────────────────────────────────

describe("validatePamConfig", () => {
  it("accepts a valid Debian common-auth config", () => {
    const lines = parsePamConfig(DEBIAN_COMMON_AUTH);
    const result = validatePamConfig(lines);

    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it("rejects config with no pam_unix.so rule", () => {
    const content = `auth required pam_deny.so
auth required pam_permit.so`;
    const lines = parsePamConfig(content);
    const result = validatePamConfig(lines);

    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("pam_unix.so"))).toBe(true);
  });

  it("rejects config with invalid pamType", () => {
    const lines: PamLine[] = [
      {
        kind: "rule",
        pamType: "invalid_type",
        control: "required",
        module: "pam_unix.so",
        args: [],
        rawLine: "invalid_type required pam_unix.so",
      },
    ];
    const result = validatePamConfig(lines);

    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("Invalid PAM type"))).toBe(true);
  });

  it("rejects config with empty module name", () => {
    const lines: PamLine[] = [
      {
        kind: "rule",
        pamType: "auth",
        control: "required",
        module: "",
        args: [],
        rawLine: "auth required ",
      },
    ];
    const result = validatePamConfig(lines);

    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("does not end with .so"))).toBe(true);
  });

  it("rejects config with module not ending in .so", () => {
    const lines: PamLine[] = [
      {
        kind: "rule",
        pamType: "auth",
        control: "required",
        module: "pam_unix",
        args: [],
        rawLine: "auth required pam_unix",
      },
    ];
    const result = validatePamConfig(lines);

    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("does not end with .so"))).toBe(true);
    // Also no pam_unix.so
    expect(result.errors.some((e) => e.includes("pam_unix.so"))).toBe(true);
  });

  it("detects concatenated fields — the original corruption pattern", () => {
    // Simulate what the old sed bug produced
    const lines: PamLine[] = [
      {
        kind: "rule",
        pamType: "authrequired",
        control: "pam_deny.so",
        module: "something.so",
        args: [],
        rawLine: "authrequiredpam_deny.so",
      },
    ];
    const result = validatePamConfig(lines);

    expect(result.valid).toBe(false);
    // Should detect concatenated fields AND invalid pamType
    expect(result.errors.length).toBeGreaterThanOrEqual(1);
  });

  it("accepts rules with - prefix on pamType", () => {
    const lines: PamLine[] = [
      createPamRule("-auth", "optional", "pam_unix.so", []),
    ];
    const result = validatePamConfig(lines);

    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it("accepts rules with bracket-style controls", () => {
    const lines = parsePamConfig(DEBIAN_COMMON_AUTH);
    const result = validatePamConfig(lines);

    expect(result.valid).toBe(true);
  });

  it("skips comment and blank lines during validation", () => {
    const lines: PamLine[] = [
      { kind: "comment", text: "# this is fine" },
      { kind: "blank" },
      createPamRule("auth", "required", "pam_unix.so", []),
    ];
    const result = validatePamConfig(lines);

    expect(result.valid).toBe(true);
  });
});

describe("validatePamConfigContent", () => {
  it("validates raw string content (convenience wrapper)", () => {
    const result = validatePamConfigContent(DEBIAN_COMMON_AUTH);
    expect(result.valid).toBe(true);
  });

  it("rejects invalid raw content", () => {
    const result = validatePamConfigContent("auth required pam_deny.so\n");
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("pam_unix.so"))).toBe(true);
  });
});

// ── Manipulation Helper Tests ───────────────────────────────────────────────

describe("createPamRule", () => {
  it("creates a properly formatted PamRule", () => {
    const rule = createPamRule("auth", "required", "pam_faillock.so", [
      "preauth", "silent", "deny=5",
    ]);

    expect(rule.kind).toBe("rule");
    expect(rule.pamType).toBe("auth");
    expect(rule.control).toBe("required");
    expect(rule.module).toBe("pam_faillock.so");
    expect(rule.args).toEqual(["preauth", "silent", "deny=5"]);
    expect(rule.rawLine).toBe("auth    required    pam_faillock.so preauth silent deny=5");
  });

  it("creates a rule with no arguments", () => {
    const rule = createPamRule("auth", "requisite", "pam_deny.so", []);

    expect(rule.args).toEqual([]);
    expect(rule.rawLine).toBe("auth    requisite    pam_deny.so");
  });

  it("creates a rule with bracket-style control", () => {
    const rule = createPamRule("auth", "[default=die]", "pam_faillock.so", ["authfail"]);

    expect(rule.control).toBe("[default=die]");
    expect(rule.rawLine).toBe("auth    [default=die]    pam_faillock.so authfail");
  });
});

describe("removeModuleRules", () => {
  it("removes all rules for a given module, preserves others", () => {
    const lines = parsePamConfig(DEBIAN_COMMON_AUTH);
    const before = lines.filter((l) => l.kind === "rule").length;

    const filtered = removeModuleRules(lines, "pam_deny.so");
    const rulesAfter = filtered.filter((l) => l.kind === "rule") as PamRule[];

    // Should have removed exactly the pam_deny.so rule
    expect(rulesAfter.length).toBe(before - 1);
    expect(rulesAfter.every((r) => r.module !== "pam_deny.so")).toBe(true);
  });

  it("preserves comments and blank lines", () => {
    const lines = parsePamConfig(DEBIAN_COMMON_AUTH);
    const commentsBefore = lines.filter((l) => l.kind === "comment").length;
    const blanksBefore = lines.filter((l) => l.kind === "blank").length;

    const filtered = removeModuleRules(lines, "pam_deny.so");
    const commentsAfter = filtered.filter((l) => l.kind === "comment").length;
    const blanksAfter = filtered.filter((l) => l.kind === "blank").length;

    expect(commentsAfter).toBe(commentsBefore);
    expect(blanksAfter).toBe(blanksBefore);
  });

  it("returns unchanged array when module not found", () => {
    const lines = parsePamConfig(DEBIAN_COMMON_AUTH);
    const filtered = removeModuleRules(lines, "pam_nonexistent.so");

    expect(filtered.length).toBe(lines.length);
  });

  it("does not modify the original array", () => {
    const lines = parsePamConfig(DEBIAN_COMMON_AUTH);
    const originalLength = lines.length;

    removeModuleRules(lines, "pam_deny.so");

    expect(lines.length).toBe(originalLength);
  });
});

describe("insertBeforeModule", () => {
  it("inserts a rule before the first occurrence of target module", () => {
    const lines = parsePamConfig(MINIMAL_PAM);
    const newRule = createPamRule("auth", "required", "pam_faillock.so", ["preauth"]);

    const result = insertBeforeModule(lines, "pam_unix.so", newRule);
    const rules = result.filter((l) => l.kind === "rule") as PamRule[];

    // New rule should be before pam_unix.so
    const faillockIdx = rules.findIndex((r) => r.module === "pam_faillock.so");
    const unixIdx = rules.findIndex((r) => r.module === "pam_unix.so");

    expect(faillockIdx).toBeLessThan(unixIdx);
    expect(faillockIdx).toBe(0);
  });

  it("appends at end if target module not found", () => {
    const lines = parsePamConfig(MINIMAL_PAM);
    const newRule = createPamRule("auth", "required", "pam_faillock.so", ["preauth"]);

    const result = insertBeforeModule(lines, "pam_nonexistent.so", newRule);
    const lastLine = result[result.length - 1];

    expect(lastLine.kind).toBe("rule");
    expect((lastLine as PamRule).module).toBe("pam_faillock.so");
  });

  it("does not modify the original array", () => {
    const lines = parsePamConfig(MINIMAL_PAM);
    const originalLength = lines.length;
    const newRule = createPamRule("auth", "required", "pam_faillock.so", ["preauth"]);

    insertBeforeModule(lines, "pam_unix.so", newRule);

    expect(lines.length).toBe(originalLength);
  });
});

describe("insertAfterModule", () => {
  it("inserts a rule after the first occurrence of target module", () => {
    const lines = parsePamConfig(MINIMAL_PAM);
    const newRule = createPamRule("auth", "[default=die]", "pam_faillock.so", ["authfail"]);

    const result = insertAfterModule(lines, "pam_unix.so", newRule);
    const rules = result.filter((l) => l.kind === "rule") as PamRule[];

    const unixIdx = rules.findIndex((r) => r.module === "pam_unix.so");
    const faillockIdx = rules.findIndex((r) => r.module === "pam_faillock.so");

    expect(faillockIdx).toBe(unixIdx + 1);
  });

  it("appends at end if target module not found", () => {
    const lines = parsePamConfig(MINIMAL_PAM);
    const newRule = createPamRule("auth", "[default=die]", "pam_faillock.so", ["authfail"]);

    const result = insertAfterModule(lines, "pam_nonexistent.so", newRule);
    const lastLine = result[result.length - 1];

    expect(lastLine.kind).toBe("rule");
    expect((lastLine as PamRule).module).toBe("pam_faillock.so");
  });
});

describe("findModuleRules", () => {
  it("finds all rules for a specific module", () => {
    const lines = parsePamConfig(DEBIAN_COMMON_AUTH);
    const found = findModuleRules(lines, "pam_unix.so");

    expect(found.length).toBe(1);
    expect(found[0].module).toBe("pam_unix.so");
    expect(found[0].args).toEqual(["nullok"]);
  });

  it("returns empty array when module not found", () => {
    const lines = parsePamConfig(DEBIAN_COMMON_AUTH);
    const found = findModuleRules(lines, "pam_nonexistent.so");

    expect(found).toEqual([]);
  });
});

describe("manipulation followed by serialization produces valid PAM config", () => {
  it("insert before pam_unix.so + adjust jumps + serialize produces valid output", () => {
    let lines = parsePamConfig(DEBIAN_COMMON_AUTH);

    const preRule = createPamRule("auth", "required", "pam_faillock.so", [
      "preauth", "silent", "deny=5",
    ]);
    lines = insertBeforeModule(lines, "pam_unix.so", preRule);
    // preauth is inserted BEFORE pam_unix.so, so the rules between pam_unix.so
    // and pam_deny.so haven't changed — no jump count adjustment needed here
    // since nothing was inserted AFTER pam_unix.so but BEFORE pam_deny.so.
    // However, we call adjustJumpCounts for safety.
    lines = adjustJumpCounts(lines);

    const output = serializePamConfig(lines);
    const validation = validatePamConfigContent(output);

    expect(validation.valid).toBe(true);
  });

  it("remove + insert + serialize produces valid output", () => {
    let lines = parsePamConfig(DEBIAN_COMMON_AUTH);

    // Remove and re-insert pam_deny.so in the same position
    lines = removeModuleRules(lines, "pam_deny.so");
    const denyRule = createPamRule("auth", "requisite", "pam_deny.so", []);
    lines = insertAfterModule(lines, "pam_unix.so", denyRule);
    lines = adjustJumpCounts(lines);

    const output = serializePamConfig(lines);
    const validation = validatePamConfigContent(output);

    expect(validation.valid).toBe(true);
  });
});

// ── Integration: Faillock Configuration Flow ────────────────────────────────

describe("Integration: Faillock Configuration Flow", () => {
  it("full faillock flow: standard common-auth → add faillock → adjust jumps → validate → correct ordering", () => {
    // 1. Start with standard Debian common-auth
    let lines = parsePamConfig(DEBIAN_COMMON_AUTH);

    // 2. Remove any existing faillock rules
    lines = removeModuleRules(lines, "pam_faillock.so");

    // 3. Create new faillock rules with specific settings
    const failArgs = ["deny=5", "unlock_time=900", "fail_interval=900"];
    const preRule = createPamRule("auth", "required", "pam_faillock.so", [
      "preauth", "silent", ...failArgs,
    ]);
    const authFailRule = createPamRule("auth", "[default=die]", "pam_faillock.so", [
      "authfail", ...failArgs,
    ]);

    // 4. Insert before/after pam_unix.so
    lines = insertBeforeModule(lines, "pam_unix.so", preRule);
    lines = insertAfterModule(lines, "pam_unix.so", authFailRule);

    // 4b. CRITICAL: Adjust jump counts after all insertions
    lines = adjustJumpCounts(lines);

    // 5. Serialize
    const output = serializePamConfig(lines);

    // 6. Validate
    const validation = validatePamConfigContent(output);
    expect(validation.valid).toBe(true);

    // 7. Verify correct PAM ordering
    const reParsed = parsePamConfig(output);
    const rules = reParsed.filter((l) => l.kind === "rule") as PamRule[];

    // preauth should be BEFORE pam_unix.so
    const preauthIdx = rules.findIndex(
      (r) => r.module === "pam_faillock.so" && r.args.includes("preauth"),
    );
    const unixIdx = rules.findIndex((r) => r.module === "pam_unix.so");
    const authfailIdx = rules.findIndex(
      (r) => r.module === "pam_faillock.so" && r.args.includes("authfail"),
    );

    expect(preauthIdx).toBeLessThan(unixIdx);
    expect(authfailIdx).toBeGreaterThan(unixIdx);

    // Verify the preauth rule has correct control and args
    expect(rules[preauthIdx].control).toBe("required");
    expect(rules[preauthIdx].args).toContain("preauth");
    expect(rules[preauthIdx].args).toContain("silent");
    expect(rules[preauthIdx].args).toContain("deny=5");

    // Verify the authfail rule has correct control
    expect(rules[authfailIdx].control).toBe("[default=die]");
    expect(rules[authfailIdx].args).toContain("authfail");
    expect(rules[authfailIdx].args).toContain("deny=5");

    // Verify the jump count was adjusted correctly
    expect(rules[unixIdx].control).toBe("[success=2 default=ignore]");
  });

  it("idempotent: running faillock configuration twice produces the same result", () => {
    function applyFaillock(content: string): string {
      let lines = parsePamConfig(content);
      lines = removeModuleRules(lines, "pam_faillock.so");

      const failArgs = ["deny=5", "unlock_time=900", "fail_interval=900"];
      const preRule = createPamRule("auth", "required", "pam_faillock.so", [
        "preauth", "silent", ...failArgs,
      ]);
      const authFailRule = createPamRule("auth", "[default=die]", "pam_faillock.so", [
        "authfail", ...failArgs,
      ]);

      lines = insertBeforeModule(lines, "pam_unix.so", preRule);
      lines = insertAfterModule(lines, "pam_unix.so", authFailRule);
      lines = adjustJumpCounts(lines);

      return serializePamConfig(lines);
    }

    const firstPass = applyFaillock(DEBIAN_COMMON_AUTH);
    const secondPass = applyFaillock(firstPass);

    // Both passes should produce identical output
    expect(secondPass).toBe(firstPass);

    // And it should be valid
    const validation = validatePamConfigContent(secondPass);
    expect(validation.valid).toBe(true);

    // Verify no duplicate faillock rules
    const lines = parsePamConfig(secondPass);
    const faillockRules = findModuleRules(lines, "pam_faillock.so");
    expect(faillockRules.length).toBe(2); // preauth + authfail, no duplicates
  });

  it("round-trip safety: the full flow never produces corrupted whitespace", () => {
    // Apply faillock
    let lines = parsePamConfig(DEBIAN_COMMON_AUTH);
    lines = removeModuleRules(lines, "pam_faillock.so");

    const preRule = createPamRule("auth", "required", "pam_faillock.so", [
      "preauth", "silent", "deny=5",
    ]);
    const authFailRule = createPamRule("auth", "[default=die]", "pam_faillock.so", [
      "authfail", "deny=5",
    ]);

    lines = insertBeforeModule(lines, "pam_unix.so", preRule);
    lines = insertAfterModule(lines, "pam_unix.so", authFailRule);
    lines = adjustJumpCounts(lines);

    const output = serializePamConfig(lines);

    // Verify NO concatenated fields in any line
    for (const line of output.split("\n")) {
      const trimmed = line.trim();
      if (trimmed === "" || trimmed.startsWith("#")) continue;

      // Check for the original bug pattern
      for (const pattern of [
        /^auth(required|requisite|sufficient|optional)/,
        /^account(required|requisite|sufficient|optional)/,
        /^password(required|requisite|sufficient|optional)/,
        /^session(required|requisite|sufficient|optional)/,
        /required(pam_|\/)/,
        /requisite(pam_|\/)/,
        /sufficient(pam_|\/)/,
        /optional(pam_|\/)/,
      ]) {
        expect(trimmed).not.toMatch(pattern);
      }

      // Every non-comment, non-blank line should have whitespace between fields
      if (trimmed.startsWith("@include")) continue;
      const fields = trimmed.split(/\s+/);
      expect(fields.length).toBeGreaterThanOrEqual(3);
    }
  });
});

// ── adjustJumpCounts Tests ──────────────────────────────────────────────────

describe("adjustJumpCounts", () => {
  it("updates [success=1] to [success=2] when a rule is inserted between pam_unix.so and pam_deny.so", () => {
    // Standard Debian common-auth has success=1 which skips pam_deny.so
    // After inserting faillock authfail between pam_unix.so and pam_deny.so,
    // we need success=2 to skip both authfail and pam_deny.so
    const lines: PamLine[] = [
      createPamRule("auth", "required", "pam_faillock.so", ["preauth", "silent"]),
      createPamRule("auth", "[success=1 default=ignore]", "pam_unix.so", ["nullok"]),
      createPamRule("auth", "[default=die]", "pam_faillock.so", ["authfail"]),
      createPamRule("auth", "requisite", "pam_deny.so", []),
      createPamRule("auth", "required", "pam_permit.so", []),
    ];

    const adjusted = adjustJumpCounts(lines);
    const unixRule = (adjusted.filter((l) => l.kind === "rule") as PamRule[])
      .find((r) => r.module === "pam_unix.so");

    expect(unixRule).toBeDefined();
    expect(unixRule!.control).toBe("[success=2 default=ignore]");
  });

  it("leaves [success=1] unchanged when no extra rules exist between pam_unix.so and pam_deny.so", () => {
    // Standard config — no insertions, success=1 is correct
    const lines: PamLine[] = [
      createPamRule("auth", "[success=1 default=ignore]", "pam_unix.so", ["nullok"]),
      createPamRule("auth", "requisite", "pam_deny.so", []),
      createPamRule("auth", "required", "pam_permit.so", []),
    ];

    const adjusted = adjustJumpCounts(lines);
    const unixRule = (adjusted.filter((l) => l.kind === "rule") as PamRule[])
      .find((r) => r.module === "pam_unix.so");

    expect(unixRule!.control).toBe("[success=1 default=ignore]");
  });

  it("correctly handles comments between rules (only counts PamRule entries)", () => {
    const lines: PamLine[] = [
      createPamRule("auth", "[success=1 default=ignore]", "pam_unix.so", ["nullok"]),
      { kind: "comment", text: "# this is a comment between rules" },
      createPamRule("auth", "[default=die]", "pam_faillock.so", ["authfail"]),
      createPamRule("auth", "requisite", "pam_deny.so", []),
      createPamRule("auth", "required", "pam_permit.so", []),
    ];

    const adjusted = adjustJumpCounts(lines);
    const unixRule = (adjusted.filter((l) => l.kind === "rule") as PamRule[])
      .find((r) => r.module === "pam_unix.so");

    // Should be success=2: skip authfail + pam_deny.so
    expect(unixRule!.control).toBe("[success=2 default=ignore]");
  });

  it("does not modify rules without [success=N] controls", () => {
    const lines: PamLine[] = [
      createPamRule("auth", "required", "pam_faillock.so", ["preauth"]),
      createPamRule("auth", "[success=1 default=ignore]", "pam_unix.so", ["nullok"]),
      createPamRule("auth", "requisite", "pam_deny.so", []),
      createPamRule("auth", "required", "pam_permit.so", []),
    ];

    const adjusted = adjustJumpCounts(lines);
    const faillock = (adjusted.filter((l) => l.kind === "rule") as PamRule[])
      .find((r) => r.module === "pam_faillock.so");

    expect(faillock!.control).toBe("required");
  });

  it("handles the full faillock flow with jump count adjustment", () => {
    // Start with standard Debian common-auth
    let lines = parsePamConfig(DEBIAN_COMMON_AUTH);

    // Remove existing faillock rules
    lines = removeModuleRules(lines, "pam_faillock.so");

    // Create and insert faillock rules
    const failArgs = ["deny=5", "unlock_time=900", "fail_interval=900"];
    const preRule = createPamRule("auth", "required", "pam_faillock.so", [
      "preauth", "silent", ...failArgs,
    ]);
    const authFailRule = createPamRule("auth", "[default=die]", "pam_faillock.so", [
      "authfail", ...failArgs,
    ]);

    lines = insertBeforeModule(lines, "pam_unix.so", preRule);
    lines = insertAfterModule(lines, "pam_unix.so", authFailRule);

    // CRITICAL: Adjust jump counts after all insertions
    lines = adjustJumpCounts(lines);

    // Verify the final config has the correct [success=N] value
    const rules = lines.filter((l) => l.kind === "rule") as PamRule[];
    const unixRule = rules.find((r) => r.module === "pam_unix.so");
    expect(unixRule).toBeDefined();

    // After inserting authfail between pam_unix.so and pam_deny.so,
    // success should jump over authfail + pam_deny.so = success=2
    expect(unixRule!.control).toBe("[success=2 default=ignore]");

    // Also verify the config is valid after adjustment
    const output = serializePamConfig(lines);
    const validation = validatePamConfigContent(output);
    expect(validation.valid).toBe(true);
  });

  it("updates rawLine when control is changed", () => {
    const lines: PamLine[] = [
      createPamRule("auth", "[success=1 default=ignore]", "pam_unix.so", ["nullok"]),
      createPamRule("auth", "[default=die]", "pam_faillock.so", ["authfail"]),
      createPamRule("auth", "requisite", "pam_deny.so", []),
      createPamRule("auth", "required", "pam_permit.so", []),
    ];

    const adjusted = adjustJumpCounts(lines);
    const unixRule = (adjusted.filter((l) => l.kind === "rule") as PamRule[])
      .find((r) => r.module === "pam_unix.so");

    expect(unixRule!.rawLine).toContain("[success=2 default=ignore]");
    expect(unixRule!.rawLine).toContain("pam_unix.so");
    expect(unixRule!.rawLine).toContain("nullok");
  });
});

// ── validatePamConfig jump count validation Tests ───────────────────────────

describe("validatePamConfig jump count validation", () => {
  it("catches incorrect jump count that would land on pam_deny.so", () => {
    // [success=1] but 2 rules before pam_deny.so — success would land on pam_deny.so
    const lines: PamLine[] = [
      createPamRule("auth", "[success=1 default=ignore]", "pam_unix.so", ["nullok"]),
      createPamRule("auth", "[default=die]", "pam_faillock.so", ["authfail"]),
      createPamRule("auth", "requisite", "pam_deny.so", []),
      createPamRule("auth", "required", "pam_permit.so", []),
    ];

    const result = validatePamConfig(lines);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("success=1") && e.includes("pam_deny.so"))).toBe(true);
  });

  it("accepts correct jump count that skips past pam_deny.so", () => {
    // [success=2] with 1 rule between pam_unix.so and pam_deny.so — correct
    const lines: PamLine[] = [
      createPamRule("auth", "[success=2 default=ignore]", "pam_unix.so", ["nullok"]),
      createPamRule("auth", "[default=die]", "pam_faillock.so", ["authfail"]),
      createPamRule("auth", "requisite", "pam_deny.so", []),
      createPamRule("auth", "required", "pam_permit.so", []),
    ];

    const result = validatePamConfig(lines);
    expect(result.valid).toBe(true);
  });

  it("catches jump count that goes beyond the end of the rule list", () => {
    const lines: PamLine[] = [
      createPamRule("auth", "[success=10 default=ignore]", "pam_unix.so", ["nullok"]),
      createPamRule("auth", "requisite", "pam_deny.so", []),
      createPamRule("auth", "required", "pam_permit.so", []),
    ];

    const result = validatePamConfig(lines);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("jumps beyond"))).toBe(true);
  });

  it("accepts standard Debian common-auth (success=1 is correct)", () => {
    const lines = parsePamConfig(DEBIAN_COMMON_AUTH);
    const result = validatePamConfig(lines);
    expect(result.valid).toBe(true);
  });
});

// ── pamType filter Tests ────────────────────────────────────────────────────

describe("insertBeforeModule with pamType filter", () => {
  it("matches only the correct pamType when filter is provided", () => {
    const lines: PamLine[] = [
      createPamRule("account", "required", "pam_unix.so", []),
      createPamRule("auth", "[success=1 default=ignore]", "pam_unix.so", ["nullok"]),
      createPamRule("auth", "requisite", "pam_deny.so", []),
    ];

    const newRule = createPamRule("auth", "required", "pam_faillock.so", ["preauth"]);
    const result = insertBeforeModule(lines, "pam_unix.so", newRule, { pamType: "auth" });
    const rules = result.filter((l) => l.kind === "rule") as PamRule[];

    // Should insert before the auth pam_unix.so, not the account one
    const faillockIdx = rules.findIndex((r) => r.module === "pam_faillock.so");
    const accountUnixIdx = rules.findIndex((r) => r.module === "pam_unix.so" && r.pamType === "account");
    const authUnixIdx = rules.findIndex((r) => r.module === "pam_unix.so" && r.pamType === "auth");

    expect(faillockIdx).toBeGreaterThan(accountUnixIdx);
    expect(faillockIdx).toBeLessThan(authUnixIdx);
  });

  it("still works without pamType filter (backward compatible)", () => {
    const lines: PamLine[] = [
      createPamRule("account", "required", "pam_unix.so", []),
      createPamRule("auth", "[success=1 default=ignore]", "pam_unix.so", ["nullok"]),
    ];

    const newRule = createPamRule("auth", "required", "pam_faillock.so", ["preauth"]);
    const result = insertBeforeModule(lines, "pam_unix.so", newRule);
    const rules = result.filter((l) => l.kind === "rule") as PamRule[];

    // Without filter, inserts before first pam_unix.so (the account one)
    expect(rules[0].module).toBe("pam_faillock.so");
  });
});

describe("insertAfterModule with pamType filter", () => {
  it("matches only the correct pamType when filter is provided", () => {
    const lines: PamLine[] = [
      createPamRule("account", "required", "pam_unix.so", []),
      createPamRule("auth", "[success=1 default=ignore]", "pam_unix.so", ["nullok"]),
      createPamRule("auth", "requisite", "pam_deny.so", []),
    ];

    const newRule = createPamRule("auth", "[default=die]", "pam_faillock.so", ["authfail"]);
    const result = insertAfterModule(lines, "pam_unix.so", newRule, { pamType: "auth" });
    const rules = result.filter((l) => l.kind === "rule") as PamRule[];

    // Should insert after the auth pam_unix.so
    const authUnixIdx = rules.findIndex((r) => r.module === "pam_unix.so" && r.pamType === "auth");
    const faillockIdx = rules.findIndex((r) => r.module === "pam_faillock.so");

    expect(faillockIdx).toBe(authUnixIdx + 1);
  });
});

// ── Error Class Tests ───────────────────────────────────────────────────────

describe("PamValidationError", () => {
  it("includes errors array and file path in message", () => {
    const error = new PamValidationError(
      ["Error 1", "Error 2"],
      "/etc/pam.d/common-auth",
    );

    expect(error.name).toBe("PamValidationError");
    expect(error.errors).toEqual(["Error 1", "Error 2"]);
    expect(error.filePath).toBe("/etc/pam.d/common-auth");
    expect(error.message).toContain("Error 1");
    expect(error.message).toContain("Error 2");
    expect(error.message).toContain("/etc/pam.d/common-auth");
  });

  it("handles missing filePath", () => {
    const error = new PamValidationError(["Error 1"]);
    expect(error.message).toContain("Error 1");
    expect(error.filePath).toBeUndefined();
  });
});

describe("PamWriteError", () => {
  it("includes file path and optional backup ID", () => {
    const error = new PamWriteError(
      "Write failed",
      "/etc/pam.d/common-auth",
      "backup-123",
    );

    expect(error.name).toBe("PamWriteError");
    expect(error.filePath).toBe("/etc/pam.d/common-auth");
    expect(error.backupId).toBe("backup-123");
    expect(error.message).toBe("Write failed");
  });
});
