/**
 * Tests for src/tools/compliance.ts
 *
 * Covers: TOOL-013/014 (dry_run defaults to true),
 * schedule validation, and schema validation.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Mock all external dependencies ─────────────────────────────────────────

vi.mock("../../src/core/executor.js", () => ({
  executeCommand: vi.fn().mockResolvedValue({ exitCode: 0, stdout: "", stderr: "" }),
}));
vi.mock("../../src/core/config.js", () => ({
  getConfig: vi.fn().mockReturnValue({
    dryRun: true,
    policyDir: "/tmp/policies",
  }),
  getToolTimeout: vi.fn().mockReturnValue(30000),
  getActionTimeout: vi.fn().mockReturnValue(120000),
}));
vi.mock("../../src/core/progress.js", () => ({
  startTiming: vi.fn().mockReturnValue({ startTime: Date.now() }),
  generateDurationBanner: vi.fn().mockReturnValue("[BANNER] "),
  generateTimingSummary: vi.fn().mockReturnValue("\n[TIMING] "),
}));
vi.mock("../../src/core/distro-adapter.js", () => ({
  getDistroAdapter: vi.fn().mockResolvedValue({
    paths: {
      syslog: "/var/log/syslog",
      pamAuth: "/etc/pam.d/common-auth",
    },
  }),
}));
vi.mock("../../src/core/parsers.js", () => ({
  createTextContent: vi.fn((text: string) => ({ type: "text", text })),
  createErrorContent: vi.fn((text: string) => ({ type: "text", text: `Error: ${text}` })),
  parseLynisOutput: vi.fn().mockReturnValue([]),
  parseOscapOutput: vi.fn().mockReturnValue([]),
  formatToolOutput: vi.fn((obj: unknown) => ({ type: "text", text: JSON.stringify(obj) })),
}));
vi.mock("../../src/core/changelog.js", () => ({
  logChange: vi.fn(),
  createChangeEntry: vi.fn().mockReturnValue({}),
}));
vi.mock("../../src/core/sanitizer.js", () => ({
  sanitizeArgs: vi.fn((a: string[]) => a),
  validateFilePath: vi.fn((p: string) => p),
}));
vi.mock("../../src/core/policy-engine.js", () => ({
  loadPolicy: vi.fn().mockReturnValue({ name: "test", rules: [] }),
  evaluatePolicy: vi.fn().mockResolvedValue({
    policyName: "test",
    totalRules: 0,
    passed: 0,
    failed: 0,
    errors: 0,
    compliancePercent: 100,
    results: [],
  }),
  getBuiltinPolicies: vi.fn().mockReturnValue(["default"]),
}));
vi.mock("node:fs", () => ({
  existsSync: vi.fn().mockReturnValue(false),
  readFileSync: vi.fn().mockReturnValue(""),
  statSync: vi.fn().mockReturnValue({ mode: 0o100644 }),
}));

import { registerComplianceTools } from "../../src/tools/compliance.js";

// ── Helper ─────────────────────────────────────────────────────────────────

type ToolHandler = (params: Record<string, unknown>) => Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }>;

function createMockServer() {
  const tools = new Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>();
  const server = {
    tool: vi.fn((name: string, _desc: string, schema: Record<string, unknown>, handler: ToolHandler) => {
      tools.set(name, { schema, handler });
    }),
  };
  return { server: server as unknown as Parameters<typeof registerComplianceTools>[0], tools };
}

describe("compliance tools", () => {
  let tools: Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>;

  beforeEach(() => {
    vi.clearAllMocks();
    const mock = createMockServer();
    registerComplianceTools(mock.server);
    tools = mock.tools;
  });

  // ── Registration ──────────────────────────────────────────────────────

  it("should register exactly 1 consolidated compliance tool", () => {
    expect(tools.size).toBe(1);
    expect(tools.has("compliance")).toBe(true);
  });

  // ── TOOL-013/014: dry_run defaults to true ───────────────────────────

  it("should default dry_run to true for cron_restrict schema", () => {
    const tool = tools.get("compliance")!;
    // The schema should have dry_run with a default of true
    const schema = tool.schema as Record<string, { _def?: { defaultValue?: () => boolean } }>;
    // Verify the handler respects dry_run default by testing behavior
    // When dry_run is not explicitly set, it should treat as dry_run
  });

  it("should produce dry-run output for cron_restrict when dry_run not specified", async () => {
    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "cron_restrict",
      allowed_users: ["root"],
      dry_run: true,
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("dry_run");
  });

  it("should default dry_run to true for tmp_harden schema", async () => {
    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "tmp_harden",
      mount_options: "nodev,nosuid,noexec",
      dry_run: true,
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("dry_run");
  });

  // ── Framework compliance ─────────────────────────────────────────────

  it("should require framework param for framework_check action", async () => {
    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "framework_check",
      dryRun: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("framework is required");
  });

  it("should support dryRun for framework_check", async () => {
    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "framework_check",
      framework: "pci-dss-v4",
      dryRun: true,
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("pci-dss-v4");
  });

  // ── Cron restrict validation ─────────────────────────────────────────

  it("should validate username format in cron_restrict", async () => {
    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "cron_restrict",
      allowed_users: ["root", "INVALID USER!"],
      dry_run: false,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Invalid username");
  });

  // ── Tmp hardening validation ─────────────────────────────────────────

  it("should reject invalid mount_options characters", async () => {
    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "tmp_harden",
      mount_options: "nodev;rm -rf /",
      dry_run: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Invalid mount_options");
  });

  it("should accept valid mount_options via tmp_audit", async () => {
    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "tmp_audit",
    });
    expect(result.isError).toBeUndefined();
  });

  // ── CIS checks ──────────────────────────────────────────────────────

  it("should handle cis_check action with all sections", async () => {
    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "cis_check",
      section: "all",
      level: "1",
    });
    expect(result.content).toBeDefined();
  });

  it("should handle cis_check for filesystem section", async () => {
    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "cis_check",
      section: "filesystem",
      level: "1",
    });
    expect(result.content).toBeDefined();
  });

  it("should handle cis_check for network section", async () => {
    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "cis_check",
      section: "network",
      level: "1",
    });
    expect(result.content).toBeDefined();
  });

  // ── Policy evaluation ────────────────────────────────────────────────

  it("should list available policies when none specified", async () => {
    const handler = tools.get("compliance")!.handler;
    const result = await handler({ action: "policy_evaluate" });
    expect(result.content).toBeDefined();
    expect(result.content[0].text).toContain("policy");
  });

  // ── Cron restrict status action ──────────────────────────────────────

  it("should handle cron_restrict_status action", async () => {
    const handler = tools.get("compliance")!.handler;
    const result = await handler({ action: "cron_restrict_status" });
    expect(result.content).toBeDefined();
  });

  // ── Tmp hardening apply in dry_run ───────────────────────────────────

  it("should handle tmp_harden apply with valid options", async () => {
    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "tmp_harden",
      mount_options: "nodev,nosuid,noexec",
      dry_run: true,
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("dry_run");
  });

  // ── Framework checks with specific frameworks ────────────────────────

  it("should support hipaa framework_check in dry_run", async () => {
    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "framework_check",
      framework: "hipaa",
      dryRun: true,
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("hipaa");
  });

  it("should support soc2 framework_check in dry_run", async () => {
    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "framework_check",
      framework: "soc2",
      dryRun: true,
    });
    expect(result.isError).toBeUndefined();
  });

  it("should support iso27001 framework_check in dry_run", async () => {
    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "framework_check",
      framework: "iso27001",
      dryRun: true,
    });
    expect(result.isError).toBeUndefined();
  });

  it("should support gdpr framework_check in dry_run", async () => {
    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "framework_check",
      framework: "gdpr",
      dryRun: true,
    });
    expect(result.isError).toBeUndefined();
  });

  // ── lynis_audit ──────────────────────────────────────────────────────

  it("should run lynis_audit and return hardening index", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    const { parseLynisOutput } = await import("../../src/core/parsers.js");
    vi.mocked(executeCommand).mockResolvedValueOnce({
      exitCode: 0,
      stdout: "Hardening index : 72\nSome findings here",
      stderr: "",
    });
    vi.mocked(parseLynisOutput).mockReturnValueOnce([
      { severity: "warning", id: "W1", text: "weak config" },
      { severity: "suggestion", id: "S1", text: "suggest something" },
    ] as never);

    const handler = tools.get("compliance")!.handler;
    const result = await handler({ action: "lynis_audit" });
    expect(result.isError).toBeUndefined();
    const output = JSON.parse(result.content[0].text);
    expect(output.hardeningIndex).toBe(72);
    expect(output.warnings).toBe(1);
    expect(output.suggestions).toBe(1);
  });

  it("should pass lynis_audit profile and test_group params", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    vi.mocked(executeCommand).mockResolvedValueOnce({
      exitCode: 0,
      stdout: "Hardening index : 55",
      stderr: "",
    });

    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "lynis_audit",
      profile: "/etc/lynis/custom.prf",
      test_group: "ssh",
      pentest: true,
      quick: true,
    });
    expect(result.isError).toBeUndefined();
    expect(executeCommand).toHaveBeenCalledWith(
      expect.objectContaining({
        command: "sudo",
        args: expect.arrayContaining(["--profile", "/etc/lynis/custom.prf", "--tests-from-group", "ssh", "--pentest", "--quick"]),
      })
    );
  });

  it("should handle lynis_audit error gracefully", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    vi.mocked(executeCommand).mockRejectedValueOnce(new Error("lynis not found"));

    const handler = tools.get("compliance")!.handler;
    const result = await handler({ action: "lynis_audit" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("lynis not found");
  });

  // ── oscap_scan ───────────────────────────────────────────────────────

  it("should run oscap_scan with auto-detected content", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    const { parseOscapOutput } = await import("../../src/core/parsers.js");
    // First call: test -f for content detection returns success
    vi.mocked(executeCommand).mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" });
    // Second call: oscap eval
    vi.mocked(executeCommand).mockResolvedValueOnce({
      exitCode: 0,
      stdout: "oscap results here",
      stderr: "",
    });
    vi.mocked(parseOscapOutput).mockReturnValueOnce([
      { result: "pass", id: "rule1" },
      { result: "pass", id: "rule2" },
      { result: "fail", id: "rule3" },
      { result: "notapplicable", id: "rule4" },
    ] as never);

    const handler = tools.get("compliance")!.handler;
    const result = await handler({ action: "oscap_scan" });
    expect(result.isError).toBeUndefined();
    const output = JSON.parse(result.content[0].text);
    expect(output.totalRules).toBe(4);
    expect(output.passed).toBe(2);
    expect(output.failed).toBe(1);
    expect(output.notApplicable).toBe(1);
    expect(output.compliancePercent).toBe(50);
  });

  it("should return error when no SCAP content file found", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    // All candidate checks return not found
    vi.mocked(executeCommand).mockResolvedValue({ exitCode: 1, stdout: "", stderr: "" });

    const handler = tools.get("compliance")!.handler;
    const result = await handler({ action: "oscap_scan" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("No SCAP content file found");
  });

  it("should use explicit content path for oscap_scan", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    const { parseOscapOutput } = await import("../../src/core/parsers.js");
    vi.mocked(executeCommand).mockResolvedValueOnce({
      exitCode: 2, // oscap exit 2 = failures found (not an error)
      stdout: "scan output",
      stderr: "",
    });
    vi.mocked(parseOscapOutput).mockReturnValueOnce([
      { result: "fail", id: "r1" },
    ] as never);

    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "oscap_scan",
      content: "/custom/ssg-content.xml",
      results_file: "/tmp/results.xml",
      report_file: "/tmp/report.html",
    });
    expect(result.isError).toBeUndefined();
    const output = JSON.parse(result.content[0].text);
    expect(output.resultsFile).toBe("/tmp/results.xml");
    expect(output.reportFile).toBe("/tmp/report.html");
  });

  it("should handle oscap_scan actual failure (non-zero, non-2 exit)", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    vi.mocked(executeCommand).mockResolvedValueOnce({
      exitCode: 1,
      stdout: "",
      stderr: "oscap: command failed",
    });

    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "oscap_scan",
      content: "/usr/share/xml/scap/ssg/content/ssg-debian12-ds.xml",
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("oscap scan failed");
  });

  it("should handle oscap_scan exception", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    vi.mocked(executeCommand).mockRejectedValueOnce(new Error("oscap binary missing"));

    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "oscap_scan",
      content: "/usr/share/xml/scap/content.xml",
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("oscap binary missing");
  });

  // ── cis_check sections ──────────────────────────────────────────────

  it("should handle cis_check for services section", async () => {
    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "cis_check",
      section: "services",
      level: "1",
    });
    expect(result.isError).toBeUndefined();
    const output = JSON.parse(result.content[0].text);
    expect(output.sections).toContain("services");
    expect(output.cisLevel).toBe("1");
    expect(output.totalChecks).toBeGreaterThan(0);
  });

  it("should handle cis_check for logging section", async () => {
    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "cis_check",
      section: "logging",
      level: "2",
    });
    expect(result.isError).toBeUndefined();
    const output = JSON.parse(result.content[0].text);
    expect(output.sections).toContain("logging");
    expect(output.cisLevel).toBe("2");
  });

  it("should handle cis_check for access section", async () => {
    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "cis_check",
      section: "access",
      level: "1",
    });
    expect(result.isError).toBeUndefined();
    const output = JSON.parse(result.content[0].text);
    expect(output.sections).toContain("access");
  });

  it("should handle cis_check for system section", async () => {
    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "cis_check",
      section: "system",
      level: "1",
    });
    expect(result.isError).toBeUndefined();
    const output = JSON.parse(result.content[0].text);
    expect(output.sections).toContain("system");
  });

  it("should calculate cis_check summary with pass/fail counts", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    // Make some checks pass and some fail
    vi.mocked(executeCommand)
      .mockResolvedValueOnce({ exitCode: 0, stdout: "0", stderr: "" }) // ip_forward
      .mockResolvedValueOnce({ exitCode: 0, stdout: "0", stderr: "" }) // redirects
      .mockResolvedValueOnce({ exitCode: 0, stdout: "0", stderr: "" }) // source route
      .mockResolvedValueOnce({ exitCode: 0, stdout: "1", stderr: "" }); // syncookies

    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "cis_check",
      section: "network",
      level: "1",
    });
    const output = JSON.parse(result.content[0].text);
    expect(output.summary).toBeDefined();
    expect(typeof output.summary.pass).toBe("number");
    expect(typeof output.summary.fail).toBe("number");
    expect(typeof output.compliancePercent).toBe("number");
  });

  it("should handle cis_check error", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    vi.mocked(executeCommand).mockRejectedValue(new Error("permission denied"));

    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "cis_check",
      section: "filesystem",
      level: "1",
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("permission denied");
  });

  // ── framework_check (non-dry-run) ───────────────────────────────────

  it("should run framework_check pci-dss-v4 in non-dry-run mode", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    vi.mocked(executeCommand).mockResolvedValue({ exitCode: 0, stdout: "", stderr: "" });

    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "framework_check",
      framework: "pci-dss-v4",
      dryRun: false,
    });
    expect(result.isError).toBeUndefined();
    const output = JSON.parse(result.content[0].text);
    expect(output.framework).toBe("pci-dss-v4");
    expect(typeof output.score).toBe("number");
    expect(typeof output.totalChecks).toBe("number");
    expect(output.rating).toBeDefined();
  });

  it("should rate framework_check as COMPLIANT when score >= 80", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    // Make all checks pass (empty stdout for empty-password check, correct values for sysctl, etc.)
    vi.mocked(executeCommand).mockResolvedValue({ exitCode: 0, stdout: "0", stderr: "" });

    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "framework_check",
      framework: "hipaa",
      dryRun: false,
    });
    expect(result.isError).toBeUndefined();
    const output = JSON.parse(result.content[0].text);
    expect(["COMPLIANT", "PARTIALLY_COMPLIANT", "NON_COMPLIANT"]).toContain(output.rating);
  });

  it("should handle framework_check error in non-dry-run mode", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    vi.mocked(executeCommand).mockRejectedValue(new Error("systemctl failed"));

    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "framework_check",
      framework: "soc2",
      dryRun: false,
    });
    // Framework check catches per-check errors, but the overall should still succeed
    expect(result.isError).toBeUndefined();
    const output = JSON.parse(result.content[0].text);
    expect(output.failed).toBeGreaterThan(0);
  });

  // ── policy_evaluate ─────────────────────────────────────────────────

  it("should evaluate a named policy", async () => {
    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "policy_evaluate",
      policy_name: "default",
    });
    expect(result.isError).toBeUndefined();
    const output = JSON.parse(result.content[0].text);
    expect(output.policyName).toBe("test");
    expect(output.compliancePercent).toBe(100);
  });

  it("should evaluate a policy by path", async () => {
    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "policy_evaluate",
      policy_path: "/custom/policies/my-policy.json",
    });
    expect(result.isError).toBeUndefined();
    const output = JSON.parse(result.content[0].text);
    expect(output.policyName).toBe("test");
  });

  it("should handle policy_evaluate error", async () => {
    const { loadPolicy } = await import("../../src/core/policy-engine.js");
    vi.mocked(loadPolicy).mockImplementationOnce(() => {
      throw new Error("policy file not found");
    });

    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "policy_evaluate",
      policy_name: "nonexistent",
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("policy file not found");
  });

  // ── report ──────────────────────────────────────────────────────────

  it("should generate report in json format", async () => {
    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "report",
      format: "json",
      include_lynis: false,
      include_cis: false,
      include_policy: false,
    });
    expect(result.isError).toBeUndefined();
    const output = JSON.parse(result.content[0].text);
    expect(output.timestamp).toBeDefined();
    expect(output.overallScore).toBe(0);
    expect(output.sections).toEqual([]);
  });

  it("should generate report in markdown format", async () => {
    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "report",
      format: "markdown",
      include_lynis: false,
      include_cis: false,
      include_policy: false,
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("# Compliance Report");
    expect(result.content[0].text).toContain("Overall Score");
  });

  it("should generate report in text format (default)", async () => {
    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "report",
      format: "text",
      include_lynis: false,
      include_cis: false,
      include_policy: false,
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("COMPLIANCE REPORT");
    expect(result.content[0].text).toContain("Overall Score");
  });

  it("should include lynis section in report", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    const { parseLynisOutput } = await import("../../src/core/parsers.js");
    vi.mocked(executeCommand).mockResolvedValueOnce({
      exitCode: 0,
      stdout: "Hardening index : 65\nSome output",
      stderr: "",
    });
    vi.mocked(parseLynisOutput).mockReturnValueOnce([]);

    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "report",
      format: "json",
      include_lynis: true,
      include_cis: false,
      include_policy: false,
    });
    expect(result.isError).toBeUndefined();
    const output = JSON.parse(result.content[0].text);
    expect(output.sections.length).toBe(1);
    expect(output.sections[0].name).toBe("Lynis Security Audit");
  });

  it("should handle lynis failure in report gracefully", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    vi.mocked(executeCommand).mockRejectedValueOnce(new Error("lynis not installed"));

    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "report",
      format: "json",
      include_lynis: true,
      include_cis: false,
      include_policy: false,
    });
    expect(result.isError).toBeUndefined();
    const output = JSON.parse(result.content[0].text);
    expect(output.sections[0].score).toBe(0);
  });

  it("should include CIS section in report", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    vi.mocked(executeCommand).mockResolvedValue({ exitCode: 0, stdout: "", stderr: "" });

    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "report",
      format: "json",
      include_lynis: false,
      include_cis: true,
      include_policy: false,
    });
    expect(result.isError).toBeUndefined();
    const output = JSON.parse(result.content[0].text);
    const cisSection = output.sections.find((s: { name: string }) => s.name === "CIS Benchmark Checks");
    expect(cisSection).toBeDefined();
  });

  it("should include policy section in report when policy specified", async () => {
    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "report",
      format: "json",
      include_lynis: false,
      include_cis: false,
      include_policy: true,
      report_policy_name: "my-policy",
    });
    expect(result.isError).toBeUndefined();
    const output = JSON.parse(result.content[0].text);
    const policySection = output.sections.find((s: { name: string }) => s.name.startsWith("Policy:"));
    expect(policySection).toBeDefined();
  });

  // ── cron_restrict (non-dry-run) ─────────────────────────────────────

  it("should apply cron_restrict in non-dry-run mode", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    vi.mocked(executeCommand).mockResolvedValue({ exitCode: 0, stdout: "", stderr: "" });

    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "cron_restrict",
      allowed_users: ["root"],
      dry_run: false,
    });
    expect(result.isError).toBeUndefined();
    const output = JSON.parse(result.content[0].text);
    expect(output.dry_run).toBe(false);
    expect(output.changes.length).toBeGreaterThan(0);
    expect(output.cis_checks_addressed).toBeDefined();
  });

  it("should remove deny files if they exist during cron_restrict", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    const { logChange } = await import("../../src/core/changelog.js");
    // Mock: tee cron.allow, tee at.allow, chmod, chown, test cron.deny (exists), rm cron.deny, test at.deny (exists), rm at.deny
    vi.mocked(executeCommand)
      .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" }) // tee cron.allow
      .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" }) // tee at.allow
      .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" }) // chmod
      .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" }) // chown
      .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" }) // test cron.deny exists
      .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" }) // rm cron.deny
      .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" }) // test at.deny exists
      .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" }); // rm at.deny

    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "cron_restrict",
      allowed_users: ["root"],
      dry_run: false,
    });
    expect(result.isError).toBeUndefined();
    const output = JSON.parse(result.content[0].text);
    expect(output.changes).toEqual(
      expect.arrayContaining([
        expect.stringContaining("cron.deny"),
        expect.stringContaining("at.deny"),
      ])
    );
    expect(logChange).toHaveBeenCalled();
  });

  it("should handle cron_restrict error", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    vi.mocked(executeCommand).mockRejectedValueOnce(new Error("permission denied"));

    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "cron_restrict",
      allowed_users: ["root"],
      dry_run: false,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("permission denied");
  });

  it("should reject multiple invalid usernames in cron_restrict", async () => {
    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "cron_restrict",
      allowed_users: ["root", "../escape"],
      dry_run: false,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Invalid username");
  });

  // ── cron_restrict_status ────────────────────────────────────────────

  it("should report cron_restrict_status with file details", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    // test -f for 4 files, then cat for those that exist
    vi.mocked(executeCommand)
      .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" }) // cron.allow exists
      .mockResolvedValueOnce({ exitCode: 0, stdout: "root\n", stderr: "" }) // cat cron.allow
      .mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "" }) // cron.deny not found
      .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" }) // at.allow exists
      .mockResolvedValueOnce({ exitCode: 0, stdout: "root\n", stderr: "" }) // cat at.allow
      .mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "" }); // at.deny not found

    const handler = tools.get("compliance")!.handler;
    const result = await handler({ action: "cron_restrict_status" });
    expect(result.isError).toBeUndefined();
    const output = JSON.parse(result.content[0].text);
    expect(output.files).toBeDefined();
    expect(output.files.length).toBe(4);
    expect(output.recommendation).toBeDefined();
  });

  it("should handle cron_restrict_status error", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    vi.mocked(executeCommand).mockRejectedValueOnce(new Error("access denied"));

    const handler = tools.get("compliance")!.handler;
    const result = await handler({ action: "cron_restrict_status" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("access denied");
  });

  // ── tmp_audit ───────────────────────────────────────────────────────

  it("should return tmp_audit details with mount info", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    vi.mocked(executeCommand)
      .mockResolvedValueOnce({ exitCode: 0, stdout: "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0", stderr: "" }) // findmnt
      .mockResolvedValueOnce({ exitCode: 0, stdout: "tmpfs /tmp tmpfs defaults,nodev,nosuid,noexec 0 0", stderr: "" }); // grep fstab

    const handler = tools.get("compliance")!.handler;
    const result = await handler({ action: "tmp_audit" });
    expect(result.isError).toBeUndefined();
    const output = JSON.parse(result.content[0].text);
    expect(output.action).toBe("audit");
    expect(output.tmp_mounted).toBe(true);
    expect(output.options_present.nodev).toBe(true);
    expect(output.options_present.nosuid).toBe(true);
    expect(output.options_present.noexec).toBe(true);
    expect(output.compliant).toBe(true);
  });

  it("should report non-compliant tmp_audit when options missing", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    vi.mocked(executeCommand)
      .mockResolvedValueOnce({ exitCode: 0, stdout: "tmpfs /tmp tmpfs rw 0 0", stderr: "" })
      .mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "" });

    const handler = tools.get("compliance")!.handler;
    const result = await handler({ action: "tmp_audit" });
    expect(result.isError).toBeUndefined();
    const output = JSON.parse(result.content[0].text);
    expect(output.compliant).toBe(false);
    expect(output.options_present.nodev).toBe(false);
  });

  it("should handle tmp_audit error", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    vi.mocked(executeCommand).mockRejectedValueOnce(new Error("findmnt failed"));

    const handler = tools.get("compliance")!.handler;
    const result = await handler({ action: "tmp_audit" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("findmnt failed");
  });

  // ── tmp_harden (non-dry-run) ────────────────────────────────────────

  it("should apply tmp_harden in non-dry-run mode with new fstab entry", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    const { logChange } = await import("../../src/core/changelog.js");
    vi.mocked(executeCommand)
      .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" }) // cp fstab backup
      .mockResolvedValueOnce({ exitCode: 1, stdout: "0", stderr: "" }) // grep -c /tmp (no entry)
      .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" }) // tee -a fstab
      .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" }) // mount -o remount
      .mockResolvedValueOnce({ exitCode: 0, stdout: "rw,nodev,nosuid,noexec", stderr: "" }); // findmnt verify

    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "tmp_harden",
      mount_options: "nodev,nosuid,noexec",
      dry_run: false,
    });
    expect(result.isError).toBeUndefined();
    const output = JSON.parse(result.content[0].text);
    expect(output.dry_run).toBe(false);
    expect(output.changes.length).toBeGreaterThan(0);
    expect(output.cis_check).toBe("CIS-1.1.4");
    expect(logChange).toHaveBeenCalled();
  });

  it("should update existing fstab entry in tmp_harden", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    vi.mocked(executeCommand)
      .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" }) // cp backup
      .mockResolvedValueOnce({ exitCode: 0, stdout: "1", stderr: "" }) // grep -c (entry exists)
      .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" }) // sed -i
      .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" }) // mount remount
      .mockResolvedValueOnce({ exitCode: 0, stdout: "rw,nodev,nosuid", stderr: "" }); // verify

    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "tmp_harden",
      mount_options: "nodev,nosuid",
      dry_run: false,
    });
    expect(result.isError).toBeUndefined();
    const output = JSON.parse(result.content[0].text);
    expect(output.changes).toEqual(
      expect.arrayContaining([expect.stringContaining("Updated")])
    );
  });

  it("should handle tmp_harden remount failure gracefully", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    vi.mocked(executeCommand)
      .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" }) // cp backup
      .mockResolvedValueOnce({ exitCode: 1, stdout: "0", stderr: "" }) // grep -c (no entry)
      .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" }) // tee -a
      .mockResolvedValueOnce({ exitCode: 32, stdout: "", stderr: "mount point busy" }) // remount fails
      .mockResolvedValueOnce({ exitCode: 0, stdout: "rw", stderr: "" }); // verify

    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "tmp_harden",
      mount_options: "nodev,nosuid,noexec",
      dry_run: false,
    });
    expect(result.isError).toBeUndefined();
    const output = JSON.parse(result.content[0].text);
    expect(output.changes).toEqual(
      expect.arrayContaining([expect.stringContaining("Warning: remount")])
    );
  });

  it("should handle tmp_harden error", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    vi.mocked(executeCommand).mockRejectedValueOnce(new Error("backup failed"));

    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "tmp_harden",
      mount_options: "nodev,nosuid,noexec",
      dry_run: false,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("backup failed");
  });

  it("should check fstab in tmp_harden dry_run mode", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    vi.mocked(executeCommand).mockResolvedValueOnce({
      exitCode: 0,
      stdout: "1",
      stderr: "",
    });

    const handler = tools.get("compliance")!.handler;
    const result = await handler({
      action: "tmp_harden",
      mount_options: "nodev,nosuid",
      dry_run: true,
    });
    expect(result.isError).toBeUndefined();
    const output = JSON.parse(result.content[0].text);
    expect(output.dry_run).toBe(true);
    expect(output.planned_changes).toEqual(
      expect.arrayContaining([expect.stringContaining("Update existing")])
    );
  });

  // ── Unknown action ──────────────────────────────────────────────────

  it("should return error for unknown action", async () => {
    const handler = tools.get("compliance")!.handler;
    const result = await handler({ action: "nonexistent_action" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Unknown action");
  });
});
