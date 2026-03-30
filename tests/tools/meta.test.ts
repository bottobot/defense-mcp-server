/**
 * Tests for src/tools/meta.ts
 *
 * Covers: TOOL-004 (schedule validation for defense_mgmt scheduled_create),
 * TOOL-005 (defense_mgmt workflow_run safeguard checks), schema validation,
 * and remediate_* actions (plan, apply, rollback, status).
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { EventEmitter } from "node:events";

// ── Mock all external dependencies ─────────────────────────────────────────

vi.mock("../../src/core/executor.js", () => ({
  executeCommand: vi.fn().mockResolvedValue({ exitCode: 0, stdout: "", stderr: "" }),
}));
vi.mock("../../src/core/command-allowlist.js", () => ({
  resolveCommand: vi.fn((cmd: string) => `/usr/bin/${cmd}`),
  isAllowlisted: vi.fn().mockReturnValue(true),
}));
vi.mock("../../src/core/config.js", () => ({
  getConfig: vi.fn().mockReturnValue({ dryRun: true, policyDir: "/tmp/policies" }),
  getToolTimeout: vi.fn().mockReturnValue(30000),
}));
vi.mock("../../src/core/parsers.js", () => ({
  createTextContent: vi.fn((text: string) => ({ type: "text", text })),
  createErrorContent: vi.fn((text: string) => ({ type: "text", text: `Error: ${text}` })),
  formatToolOutput: vi.fn((obj: unknown) => ({ type: "text", text: JSON.stringify(obj) })),
}));
vi.mock("../../src/core/changelog.js", () => ({
  logChange: vi.fn(),
  createChangeEntry: vi.fn().mockReturnValue({}),
  getChangelog: vi.fn().mockReturnValue([]),
}));
vi.mock("../../src/core/installer.js", () => ({
  checkAllTools: vi.fn().mockResolvedValue([]),
  installMissing: vi.fn().mockResolvedValue([]),
  getInstallHint: vi.fn().mockResolvedValue("sudo apt install -y example-pkg"),
  getAlternativesMap: vi.fn().mockReturnValue(new Map()),
}));
vi.mock("../../src/core/safeguards.js", () => ({
  SafeguardRegistry: {
    getInstance: vi.fn().mockReturnValue({
      checkSafety: vi.fn().mockResolvedValue({ safe: true, warnings: [], blockers: [], impactedApps: [] }),
    }),
  },
}));
vi.mock("../../src/core/spawn-safe.js", () => ({
  spawnSafe: vi.fn(),
}));
vi.mock("../../src/core/third-party-installer.js", () => ({
  listThirdPartyTools: vi.fn().mockResolvedValue([]),
  installThirdPartyTool: vi.fn().mockResolvedValue({ binary: "trivy", success: true, message: "Trivy v0.58.1 installed" }),
  getVerifiedInstallInstructions: vi.fn().mockReturnValue("## Trivy v0.58.1 — Verified APT Installation\n\n```bash\nsudo apt-get install trivy\n```"),
  isThirdPartyInstallEnabled: vi.fn().mockReturnValue(false),
}));
vi.mock("../../src/core/third-party-manifest.js", () => ({
  THIRD_PARTY_MANIFEST: [
    { binary: "falco", name: "Falco", version: "0.39.2", installMethod: "apt-repo", verification: "gpg-apt-repo" },
    { binary: "trivy", name: "Trivy", version: "0.58.1", installMethod: "apt-repo", verification: "gpg-apt-repo" },
    { binary: "grype", name: "Grype", version: "0.86.1", installMethod: "github-release", verification: "sha256" },
  ],
}));
vi.mock("../../src/core/secure-fs.js", () => ({
  secureWriteFileSync: vi.fn(),
}));
vi.mock("node:fs", () => ({
  existsSync: vi.fn().mockReturnValue(false),
  readFileSync: vi.fn().mockReturnValue("[]"),
  writeFileSync: vi.fn(),
  mkdirSync: vi.fn(),
  readdirSync: vi.fn().mockReturnValue([]),
  statSync: vi.fn().mockReturnValue({ size: 1024, mtime: new Date("2025-01-01T00:00:00Z") }),
}));
vi.mock("node:path", async () => {
  const actual = await vi.importActual("node:path");
  return actual;
});
vi.mock("node:os", () => ({
  homedir: vi.fn().mockReturnValue("/tmp/test-home"),
}));

import { registerMetaTools } from "../../src/tools/meta.js";
import { spawnSafe } from "../../src/core/spawn-safe.js";
import { secureWriteFileSync } from "../../src/core/secure-fs.js";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { checkAllTools, getAlternativesMap } from "../../src/core/installer.js";
import {
  listThirdPartyTools,
  installThirdPartyTool,
  isThirdPartyInstallEnabled,
} from "../../src/core/third-party-installer.js";

const mockSpawnSafe = vi.mocked(spawnSafe);
const mockSecureWriteFileSync = vi.mocked(secureWriteFileSync);
const mockExistsSync = vi.mocked(existsSync);
const mockReadFileSync = vi.mocked(readFileSync);
const mockReaddirSync = vi.mocked(readdirSync);
const mockCheckAllTools = vi.mocked(checkAllTools);
const mockGetAlternativesMap = vi.mocked(getAlternativesMap);
const mockListThirdPartyTools = vi.mocked(listThirdPartyTools);
const mockInstallThirdPartyTool = vi.mocked(installThirdPartyTool);
const mockIsThirdPartyInstallEnabled = vi.mocked(isThirdPartyInstallEnabled);

// ── Helper ─────────────────────────────────────────────────────────────────

type ToolHandler = (params: Record<string, unknown>) => Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }>;

function createMockServer() {
  const tools = new Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>();
  const server = {
    tool: vi.fn((name: string, _desc: string, schema: Record<string, unknown>, handler: ToolHandler) => {
      tools.set(name, { schema, handler });
    }),
  };
  return { server: server as unknown as Parameters<typeof registerMetaTools>[0], tools };
}

describe("meta tools", () => {
  let tools: Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>;

  beforeEach(() => {
    vi.clearAllMocks();
    const mock = createMockServer();
    registerMetaTools(mock.server);
    tools = mock.tools;
  });

  // ── Registration ──────────────────────────────────────────────────────

  it("should register exactly 1 tool: defense_mgmt", () => {
    expect(tools.size).toBe(1);
    expect(tools.has("defense_mgmt")).toBe(true);
  });

  // ── TOOL-004: Schedule validation ────────────────────────────────────

  it("should reject schedule with shell metacharacters (TOOL-004)", async () => {
    const handler = tools.get("defense_mgmt")!.handler;
    const result = await handler({
      action: "scheduled_create",
      name: "test-audit",
      command: "lynis audit system",
      schedule: "0 2 * * *; rm -rf /",
      useSystemd: false,
      dry_run: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("forbidden characters");
  });

  it("should reject cron schedule with wrong number of fields (TOOL-004)", async () => {
    const handler = tools.get("defense_mgmt")!.handler;
    const result = await handler({
      action: "scheduled_create",
      name: "test-audit",
      command: "lynis audit system",
      schedule: "0 2 *",
      useSystemd: false,
      dry_run: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Expected 5 fields");
  });

  it("should accept valid cron schedule (TOOL-004)", async () => {
    const handler = tools.get("defense_mgmt")!.handler;
    const result = await handler({
      action: "scheduled_create",
      name: "test-audit",
      command: "lynis audit system",
      schedule: "0 2 * * *",
      useSystemd: false,
      dry_run: true,
    });
    expect(result.isError).toBeUndefined();
  });

  it("should reject schedule with backticks (TOOL-004)", async () => {
    const handler = tools.get("defense_mgmt")!.handler;
    const result = await handler({
      action: "scheduled_create",
      name: "test-audit",
      command: "lynis audit system",
      schedule: "`rm -rf /` * * * *",
      useSystemd: true,
      dry_run: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("forbidden characters");
  });

  // ── Audit name validation ────────────────────────────────────────────

  it("should reject audit name with invalid characters", async () => {
    const handler = tools.get("defense_mgmt")!.handler;
    const result = await handler({
      action: "scheduled_create",
      name: "test audit!",
      command: "lynis audit system",
      schedule: "0 2 * * *",
      useSystemd: true,
      dry_run: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Invalid audit name");
  });

  // ── TOOL-005: workflow_run safeguard checks ──────────────────────────

  it("should require workflow for workflow_run action (TOOL-005)", async () => {
    const handler = tools.get("defense_mgmt")!.handler;
    const result = await handler({
      action: "workflow_run",
      dry_run: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("workflow is required");
  });

  it("should produce dry-run output for workflow_run (TOOL-005)", async () => {
    const handler = tools.get("defense_mgmt")!.handler;
    const result = await handler({
      action: "workflow_run",
      workflow: "quick_harden",
      dry_run: true,
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("DRY RUN");
  });

  // ── Required params ──────────────────────────────────────────────────

  it("should require name for scheduled_create action", async () => {
    const handler = tools.get("defense_mgmt")!.handler;
    const result = await handler({
      action: "scheduled_create",
      command: "lynis audit system",
      schedule: "0 2 * * *",
      dry_run: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("name is required");
  });

  it("should require objective for workflow_suggest", async () => {
    const handler = tools.get("defense_mgmt")!.handler;
    const result = await handler({
      action: "workflow_suggest",
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("objective is required");
  });

  // ── auto_remediate ──────────────────────────────────────────────────────

  /**
   * Helper: create a mock ChildProcess from EventEmitter that emits
   * stdout/stderr and a close code on nextTick.
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

    process.nextTick(() => {
      if (stdout) cp.stdout.emit("data", Buffer.from(stdout));
      if (stderr) cp.stderr.emit("data", Buffer.from(stderr));
      cp.emit("close", exitCode);
    });

    return cp;
  }

  /**
   * Helper: set up spawnSafe to return mock ChildProcess based on command.
   */
  function setupRemediateSpawnMocks(overrides?: Record<string, { stdout: string; stderr: string; exitCode: number }>) {
    const defaults: Record<string, { stdout: string; stderr: string; exitCode: number }> = {
      "sysctl -a": {
        stdout: [
          "kernel.randomize_va_space = 0",
          "net.ipv4.ip_forward = 1",
          "net.ipv4.tcp_syncookies = 0",
          "net.ipv4.conf.all.rp_filter = 0",
          "net.ipv4.conf.all.accept_redirects = 1",
          "net.ipv4.conf.all.accept_source_route = 1",
        ].join("\n"),
        stderr: "",
        exitCode: 0,
      },
      "grep -E": {
        stdout: "PermitRootLogin yes\nPermitEmptyPasswords yes\n",
        stderr: "",
        exitCode: 0,
      },
      "iptables -L -n": {
        stdout: "Chain INPUT (policy ACCEPT)\nChain FORWARD (policy ACCEPT)\nChain OUTPUT (policy ACCEPT)\n",
        stderr: "",
        exitCode: 0,
      },
      "lynis audit": {
        stdout: "Hardening index : 62\nWarning: some warning\nSuggestion: some suggestion\n",
        stderr: "",
        exitCode: 0,
      },
      "sysctl -n": {
        stdout: "0",
        stderr: "",
        exitCode: 0,
      },
      "sysctl -w": {
        stdout: "kernel.randomize_va_space = 2",
        stderr: "",
        exitCode: 0,
      },
    };

    const merged = { ...defaults, ...overrides };

    mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
      const fullCmd = `${command} ${args.join(" ")}`;

      for (const [pattern, result] of Object.entries(merged)) {
        if (fullCmd.includes(pattern) || command === pattern) {
          return createMockChildProcess(result.stdout, result.stderr, result.exitCode) as any;
        }
      }

      // Default: success with empty output
      return createMockChildProcess("", "", 0) as any;
    });
  }

  describe("remediate actions", () => {
    it("defense_mgmt should be registered", () => {
      expect(tools.has("defense_mgmt")).toBe(true);
    });

    // ── remediate_plan action ──────────────────────────────────────────────

    describe("remediate_plan action", () => {
      it("should generate findings from multiple sources", async () => {
        setupRemediateSpawnMocks();
        const handler = tools.get("defense_mgmt")!.handler;
        const result = await handler({
          action: "remediate_plan",
          source: "all",
          severity_filter: "low",
          output_format: "text",
        });
        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("Auto-Remediation Plan");
        expect(result.content[0].text).toContain("HARD-001");
      });

      it("should filter by severity", async () => {
        setupRemediateSpawnMocks();
        const handler = tools.get("defense_mgmt")!.handler;
        const result = await handler({
          action: "remediate_plan",
          source: "all",
          severity_filter: "critical",
          output_format: "text",
        });
        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("ACCESS-001");
        expect(result.content[0].text).not.toContain("HARD-003");
      });

      it("should filter by source", async () => {
        setupRemediateSpawnMocks();
        const handler = tools.get("defense_mgmt")!.handler;
        const result = await handler({
          action: "remediate_plan",
          source: "hardening",
          severity_filter: "low",
          output_format: "text",
        });
        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("HARD-001");
        expect(result.content[0].text).not.toContain("ACCESS-001");
        expect(result.content[0].text).not.toContain("FW-001");
      });

      it("should return sorted output (severity then risk)", async () => {
        setupRemediateSpawnMocks();
        const handler = tools.get("defense_mgmt")!.handler;
        const result = await handler({
          action: "remediate_plan",
          source: "all",
          severity_filter: "low",
          output_format: "json",
        });
        expect(result.isError).toBeUndefined();
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.findings.length).toBeGreaterThan(0);
        const firstSev = parsed.findings[0].severity;
        expect(["critical", "high"]).toContain(firstSev);
      });

      it("should show no findings when system is clean", async () => {
        setupRemediateSpawnMocks({
          "sysctl -a": {
            stdout: [
              "kernel.randomize_va_space = 2",
              "net.ipv4.ip_forward = 0",
              "net.ipv4.tcp_syncookies = 1",
              "net.ipv4.conf.all.rp_filter = 1",
              "net.ipv4.conf.all.accept_redirects = 0",
              "net.ipv4.conf.all.accept_source_route = 0",
            ].join("\n"),
            stderr: "",
            exitCode: 0,
          },
          "grep -E": { stdout: "PermitRootLogin no\n", stderr: "", exitCode: 0 },
          "iptables -L -n": { stdout: "Chain INPUT (policy DROP)\nChain FORWARD (policy DROP)\n", stderr: "", exitCode: 0 },
          "lynis audit": { stdout: "", stderr: "", exitCode: 0 },
        });
        const handler = tools.get("defense_mgmt")!.handler;
        const result = await handler({
          action: "remediate_plan",
          source: "all",
          severity_filter: "medium",
          output_format: "text",
        });
        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("No findings");
      });

      it("should return JSON output when format is json", async () => {
        setupRemediateSpawnMocks();
        const handler = tools.get("defense_mgmt")!.handler;
        const result = await handler({
          action: "remediate_plan",
          source: "hardening",
          severity_filter: "medium",
          output_format: "json",
        });
        expect(result.isError).toBeUndefined();
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.action).toBe("plan");
        expect(parsed.source).toBe("hardening");
        expect(Array.isArray(parsed.findings)).toBe(true);
      });
    });

    // ── remediate_apply action ─────────────────────────────────────────────

    describe("remediate_apply action", () => {
      it("should show plan but not execute when dry_run=true", async () => {
        setupRemediateSpawnMocks();
        const handler = tools.get("defense_mgmt")!.handler;
        const result = await handler({
          action: "remediate_apply",
          source: "hardening",
          severity_filter: "medium",
          dry_run: true,
          output_format: "text",
        });
        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("DRY RUN");
        expect(result.content[0].text).toContain("Would execute");
        expect(mockSecureWriteFileSync).not.toHaveBeenCalled();
      });

      it("should return dry_run JSON output", async () => {
        setupRemediateSpawnMocks();
        const handler = tools.get("defense_mgmt")!.handler;
        const result = await handler({
          action: "remediate_apply",
          source: "hardening",
          severity_filter: "medium",
          dry_run: true,
          output_format: "json",
        });
        expect(result.isError).toBeUndefined();
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.dry_run).toBe(true);
        expect(Array.isArray(parsed.would_execute)).toBe(true);
        expect(Array.isArray(parsed.would_skip)).toBe(true);
      });

      it("should execute safe remediations and skip risky ones when dry_run=false", async () => {
        setupRemediateSpawnMocks();
        const handler = tools.get("defense_mgmt")!.handler;
        const result = await handler({
          action: "remediate_apply",
          source: "all",
          severity_filter: "low",
          dry_run: false,
          output_format: "text",
        });
        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("LIVE EXECUTION");
        expect(result.content[0].text).toContain("Session ID:");
        expect(result.content[0].text).toContain("SKIPPED");
        expect(mockSecureWriteFileSync).toHaveBeenCalled();
      });

      it("should create session file with correct structure when dry_run=false", async () => {
        setupRemediateSpawnMocks();
        const handler = tools.get("defense_mgmt")!.handler;
        await handler({
          action: "remediate_apply",
          source: "hardening",
          severity_filter: "high",
          dry_run: false,
          output_format: "text",
        });
        expect(mockSecureWriteFileSync).toHaveBeenCalled();
        const callArgs = mockSecureWriteFileSync.mock.calls[0];
        expect(callArgs[0]).toContain("remediation-sessions");
        expect(callArgs[0]).toContain(".json");
        const sessionData = JSON.parse(callArgs[1] as string);
        expect(sessionData.session_id).toBeDefined();
        expect(sessionData.created_at).toBeDefined();
        expect(Array.isArray(sessionData.actions)).toBe(true);
        expect(sessionData.summary).toBeDefined();
      });

      it("should return no findings message when system is clean", async () => {
        setupRemediateSpawnMocks({
          "sysctl -a": { stdout: "kernel.randomize_va_space = 2\nnet.ipv4.ip_forward = 0\n", stderr: "", exitCode: 0 },
          "grep -E": { stdout: "PermitRootLogin no\n", stderr: "", exitCode: 0 },
          "iptables -L -n": { stdout: "Chain INPUT (policy DROP)\n", stderr: "", exitCode: 0 },
          "lynis audit": { stdout: "", stderr: "", exitCode: 0 },
        });
        const handler = tools.get("defense_mgmt")!.handler;
        const result = await handler({
          action: "remediate_apply",
          source: "all",
          severity_filter: "medium",
          dry_run: false,
          output_format: "text",
        });
        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("Nothing to remediate");
      });
    });

    // ── remediate_rollback action ──────────────────────────────────────────

    describe("remediate_rollback action", () => {
      it("should require session_id", async () => {
        const handler = tools.get("defense_mgmt")!.handler;
        const result = await handler({
          action: "remediate_rollback",
          output_format: "text",
        });
        expect(result.isError).toBe(true);
        expect(result.content[0].text).toContain("session_id is required");
      });

      it("should error when session not found", async () => {
        mockExistsSync.mockReturnValue(false);
        const handler = tools.get("defense_mgmt")!.handler;
        const result = await handler({
          action: "remediate_rollback",
          session_id: "rem-nonexistent",
          output_format: "text",
        });
        expect(result.isError).toBe(true);
        expect(result.content[0].text).toContain("Session not found");
      });

      it("should read session and execute rollback in reverse order", async () => {
        const sessionData = {
          session_id: "rem-123456-abc",
          created_at: "2025-01-01T00:00:00Z",
          status: "completed",
          actions: [
            { finding_id: "HARD-001", description: "ASLR not fully enabled", remediation_command: "sysctl", remediation_args: ["-w", "kernel.randomize_va_space=2"], rollback_command: "sysctl", rollback_args: ["-w", "kernel.randomize_va_space=0"], before_state: "0", after_state: "2", status: "success", timestamp: "2025-01-01T00:00:01Z" },
            { finding_id: "HARD-003", description: "SYN cookies not enabled", remediation_command: "sysctl", remediation_args: ["-w", "net.ipv4.tcp_syncookies=1"], rollback_command: "sysctl", rollback_args: ["-w", "net.ipv4.tcp_syncookies=0"], before_state: "0", after_state: "1", status: "success", timestamp: "2025-01-01T00:00:02Z" },
          ],
          summary: { total: 2, successful: 2, failed: 0, skipped: 0, rolled_back: 0 },
        };

        mockExistsSync.mockReturnValue(true);
        mockReadFileSync.mockReturnValue(JSON.stringify(sessionData));
        setupRemediateSpawnMocks();

        const handler = tools.get("defense_mgmt")!.handler;
        const result = await handler({
          action: "remediate_rollback",
          session_id: "rem-123456-abc",
          output_format: "text",
        });
        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("Rollback Session");
        expect(result.content[0].text).toContain("Rolled back");
        expect(mockSecureWriteFileSync).toHaveBeenCalled();
      });

      it("should return JSON for rollback", async () => {
        const sessionData = {
          session_id: "rem-123456-abc",
          created_at: "2025-01-01T00:00:00Z",
          status: "completed",
          actions: [
            { finding_id: "HARD-001", description: "ASLR not fully enabled", remediation_command: "sysctl", remediation_args: ["-w", "kernel.randomize_va_space=2"], rollback_command: "sysctl", rollback_args: ["-w", "kernel.randomize_va_space=0"], before_state: "0", after_state: "2", status: "success", timestamp: "2025-01-01T00:00:01Z" },
          ],
          summary: { total: 1, successful: 1, failed: 0, skipped: 0, rolled_back: 0 },
        };

        mockExistsSync.mockReturnValue(true);
        mockReadFileSync.mockReturnValue(JSON.stringify(sessionData));
        setupRemediateSpawnMocks();

        const handler = tools.get("defense_mgmt")!.handler;
        const result = await handler({
          action: "remediate_rollback",
          session_id: "rem-123456-abc",
          output_format: "json",
        });
        expect(result.isError).toBeUndefined();
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.session_id).toBe("rem-123456-abc");
        expect(parsed.actions_rolled_back).toBe(1);
      });
    });

    // ── remediate_status action ────────────────────────────────────────────

    describe("remediate_status action", () => {
      it("should show specific session details", async () => {
        const sessionData = {
          session_id: "rem-123456-abc",
          created_at: "2025-01-01T00:00:00Z",
          status: "completed",
          actions: [
            { finding_id: "HARD-001", description: "ASLR not fully enabled", remediation_command: "sysctl", remediation_args: ["-w", "kernel.randomize_va_space=2"], rollback_command: "sysctl", rollback_args: ["-w", "kernel.randomize_va_space=0"], before_state: "0", after_state: "2", status: "success", timestamp: "2025-01-01T00:00:01Z" },
          ],
          summary: { total: 1, successful: 1, failed: 0, skipped: 0, rolled_back: 0 },
        };

        mockExistsSync.mockReturnValue(true);
        mockReadFileSync.mockReturnValue(JSON.stringify(sessionData));

        const handler = tools.get("defense_mgmt")!.handler;
        const result = await handler({
          action: "remediate_status",
          session_id: "rem-123456-abc",
          output_format: "text",
        });
        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("Session Detail");
        expect(result.content[0].text).toContain("rem-123456-abc");
        expect(result.content[0].text).toContain("completed");
      });

      it("should error when specific session not found", async () => {
        mockExistsSync.mockReturnValue(false);
        const handler = tools.get("defense_mgmt")!.handler;
        const result = await handler({
          action: "remediate_status",
          session_id: "rem-nonexistent",
          output_format: "text",
        });
        expect(result.isError).toBe(true);
        expect(result.content[0].text).toContain("Session not found");
      });

      it("should list all sessions when no session_id", async () => {
        mockExistsSync.mockReturnValue(true);
        mockReaddirSync.mockReturnValue(["rem-111.json", "rem-222.json"] as any);
        mockReadFileSync.mockImplementation((path: any) => {
          if (String(path).includes("rem-111")) {
            return JSON.stringify({ session_id: "rem-111", created_at: "2025-01-01T00:00:00Z", status: "completed", actions: [], summary: { total: 2, successful: 2, failed: 0, skipped: 0, rolled_back: 0 } });
          }
          return JSON.stringify({ session_id: "rem-222", created_at: "2025-01-02T00:00:00Z", status: "partial", actions: [], summary: { total: 3, successful: 1, failed: 1, skipped: 1, rolled_back: 0 } });
        });

        const handler = tools.get("defense_mgmt")!.handler;
        const result = await handler({
          action: "remediate_status",
          output_format: "text",
        });
        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("Remediation Sessions");
        expect(result.content[0].text).toContain("rem-111");
        expect(result.content[0].text).toContain("rem-222");
      });

      it("should show no sessions found when directory missing", async () => {
        mockExistsSync.mockReturnValue(false);
        const handler = tools.get("defense_mgmt")!.handler;
        const result = await handler({
          action: "remediate_status",
          output_format: "text",
        });
        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("No remediation sessions found");
      });

      it("should show no sessions found when directory is empty", async () => {
        mockExistsSync.mockReturnValue(true);
        mockReaddirSync.mockReturnValue([]);
        const handler = tools.get("defense_mgmt")!.handler;
        const result = await handler({
          action: "remediate_status",
          output_format: "text",
        });
        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("No remediation sessions found");
      });

      it("should return JSON session list", async () => {
        mockExistsSync.mockReturnValue(true);
        mockReaddirSync.mockReturnValue(["rem-111.json"] as any);
        mockReadFileSync.mockReturnValue(JSON.stringify({ session_id: "rem-111", created_at: "2025-01-01T00:00:00Z", status: "completed", actions: [], summary: { total: 1, successful: 1, failed: 0, skipped: 0, rolled_back: 0 } }));

        const handler = tools.get("defense_mgmt")!.handler;
        const result = await handler({
          action: "remediate_status",
          output_format: "json",
        });
        expect(result.isError).toBeUndefined();
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.total_sessions).toBe(1);
        expect(parsed.sessions[0].session_id).toBe("rem-111");
      });
    });

    // ── Error handling ─────────────────────────────────────────────────────

    describe("error handling", () => {
      it("should handle command failures gracefully in remediate_plan", async () => {
        setupRemediateSpawnMocks({
          "sysctl -a": { stdout: "", stderr: "permission denied", exitCode: 1 },
          "grep -E": { stdout: "", stderr: "no such file", exitCode: 2 },
          "iptables -L -n": { stdout: "", stderr: "permission denied", exitCode: 1 },
          "lynis audit": { stdout: "", stderr: "not found", exitCode: 127 },
        });
        const handler = tools.get("defense_mgmt")!.handler;
        const result = await handler({
          action: "remediate_plan",
          source: "all",
          severity_filter: "medium",
          output_format: "text",
        });
        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("No findings");
      });

      it("should handle missing session directory in remediate_status", async () => {
        mockExistsSync.mockReturnValue(false);
        const handler = tools.get("defense_mgmt")!.handler;
        const result = await handler({
          action: "remediate_status",
          output_format: "json",
        });
        expect(result.isError).toBeUndefined();
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.sessions).toEqual([]);
      });
    });
  });

  // ── Audit Gate (check_tools gate=true) ────────────────────────────────

  describe("check_tools gate mode", () => {
    const makeTool = (name: string, binary: string, required: boolean, installed: boolean, alternativeFor?: string) => ({
      tool: { name, binary, packages: { debian: name.toLowerCase() }, category: "assessment" as const, required, alternativeFor },
      installed,
      version: installed ? "1.0.0" : undefined,
      path: installed ? `/usr/bin/${binary}` : undefined,
    });

    it("should return gateResult=passed when all tools installed", async () => {
      mockCheckAllTools.mockResolvedValue([
        makeTool("Lynis", "lynis", true, true),
        makeTool("ClamAV", "clamscan", true, true),
      ]);
      const handler = tools.get("defense_mgmt")!.handler;
      const result = await handler({ action: "check_tools", gate: true }) as Record<string, unknown>;
      expect(result.isError).toBeUndefined();
      expect(result.content).toBeDefined();
      expect((result._meta as Record<string, unknown>).gateResult).toBe("passed");
      expect((result._meta as Record<string, unknown>).haltWorkflow).toBe(false);
    });

    it("should return isError + haltWorkflow when required tools missing", async () => {
      mockCheckAllTools.mockResolvedValue([
        makeTool("Lynis", "lynis", true, true),
        makeTool("ClamAV", "clamscan", true, false),
      ]);
      mockGetAlternativesMap.mockReturnValue(new Map());
      const handler = tools.get("defense_mgmt")!.handler;
      const result = await handler({ action: "check_tools", gate: true }) as Record<string, unknown>;
      expect(result.isError).toBe(true);
      expect((result._meta as Record<string, unknown>).haltWorkflow).toBe(true);
      expect((result._meta as Record<string, unknown>).gateResult).toBe("blocked");
      expect((result._meta as Record<string, unknown>).requiredMissingCount).toBe(1);
    });

    it("should return passed_with_warnings when only optional tools missing", async () => {
      mockCheckAllTools.mockResolvedValue([
        makeTool("Lynis", "lynis", true, true),
        makeTool("htop", "htop", false, false),
      ]);
      mockGetAlternativesMap.mockReturnValue(new Map());
      const handler = tools.get("defense_mgmt")!.handler;
      const result = await handler({ action: "check_tools", gate: true }) as Record<string, unknown>;
      expect(result.isError).toBeUndefined();
      expect((result._meta as Record<string, unknown>).gateResult).toBe("passed_with_warnings");
      expect((result._meta as Record<string, unknown>).haltWorkflow).toBe(false);
      expect((result._meta as Record<string, unknown>).optionalMissingCount).toBe(1);
    });

    it("should NOT return isError when gate=false (backwards compatible)", async () => {
      mockCheckAllTools.mockResolvedValue([
        makeTool("ClamAV", "clamscan", true, false),
      ]);
      const handler = tools.get("defense_mgmt")!.handler;
      const result = await handler({ action: "check_tools", gate: false }) as Record<string, unknown>;
      expect(result.isError).toBeUndefined();
      expect(result._meta).toBeUndefined();
    });

    it("should pass gate when required tool missing but alternative installed", async () => {
      mockCheckAllTools.mockResolvedValue([
        makeTool("iptables", "iptables", true, false),
        makeTool("nftables", "nft", false, true, "iptables"),
      ]);
      mockGetAlternativesMap.mockReturnValue(
        new Map([["iptables", [{ name: "nftables", binary: "nft", packages: { debian: "nftables" }, category: "firewall" as const, required: false, alternativeFor: "iptables" }]]])
      );
      const handler = tools.get("defense_mgmt")!.handler;
      const result = await handler({ action: "check_tools", gate: true }) as Record<string, unknown>;
      expect(result.isError).toBeUndefined();
      expect((result._meta as Record<string, unknown>).haltWorkflow).toBe(false);
    });

    it("should include install hints in blocked gate output", async () => {
      mockCheckAllTools.mockResolvedValue([
        makeTool("ClamAV", "clamscan", true, false),
      ]);
      mockGetAlternativesMap.mockReturnValue(new Map());
      const handler = tools.get("defense_mgmt")!.handler;
      const result = await handler({ action: "check_tools", gate: true });
      expect(result.content[0].text).toContain("AUDIT GATE: BLOCKED");
      expect(result.content[0].text).toContain("Install:");
    });
  });

  // ── check_optional_deps ─────────────────────────────────────────────────

  describe("check_optional_deps action", () => {
    it("should return formatted status of all third-party tools", async () => {
      mockListThirdPartyTools.mockResolvedValue([
        { binary: "falco", name: "Falco", installed: true, currentVersion: "0.39.2", manifestVersion: "0.39.2", needsUpdate: false },
        { binary: "trivy", name: "Trivy", installed: false, manifestVersion: "0.58.1", needsUpdate: false },
        { binary: "grype", name: "Grype", installed: false, manifestVersion: "0.86.1", needsUpdate: false },
      ]);

      const handler = tools.get("defense_mgmt")!.handler;
      const result = await handler({ action: "check_optional_deps" });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("Optional Third-Party Tool Status");
      expect(result.content[0].text).toContain("falco");
      expect(result.content[0].text).toContain("trivy");
      expect(result.content[0].text).toContain("grype");
      expect(result.content[0].text).toContain("Installed: 1");
      expect(result.content[0].text).toContain("Missing: 2");
    });

    it("should show install hints for missing tools", async () => {
      mockListThirdPartyTools.mockResolvedValue([
        { binary: "trivy", name: "Trivy", installed: false, manifestVersion: "0.58.1", needsUpdate: false },
      ]);

      const handler = tools.get("defense_mgmt")!.handler;
      const result = await handler({ action: "check_optional_deps" });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("Install Hints");
      expect(result.content[0].text).toContain("install_optional_deps");
    });

    it("should show all installed when nothing is missing", async () => {
      mockListThirdPartyTools.mockResolvedValue([
        { binary: "falco", name: "Falco", installed: true, currentVersion: "0.39.2", manifestVersion: "0.39.2", needsUpdate: false },
      ]);

      const handler = tools.get("defense_mgmt")!.handler;
      const result = await handler({ action: "check_optional_deps" });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("Installed: 1");
      expect(result.content[0].text).toContain("Missing: 0");
      expect(result.content[0].text).not.toContain("Install Hints");
    });
  });

  // ── install_optional_deps ───────────────────────────────────────────────

  describe("install_optional_deps action", () => {
    it("should return instructions when DEFENSE_MCP_THIRD_PARTY_INSTALL is not set", async () => {
      mockIsThirdPartyInstallEnabled.mockReturnValue(false);
      mockListThirdPartyTools.mockResolvedValue([
        { binary: "trivy", name: "Trivy", installed: false, manifestVersion: "0.58.1", needsUpdate: false },
      ]);

      const handler = tools.get("defense_mgmt")!.handler;
      const result = await handler({
        action: "install_optional_deps",
        dry_run: false,
      });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("Third-Party Installation Not Enabled");
      expect(result.content[0].text).toContain("DEFENSE_MCP_THIRD_PARTY_INSTALL=true");
      expect(result.content[0].text).toContain("Missing Optional Tools");
      expect(mockInstallThirdPartyTool).not.toHaveBeenCalled();
    });

    it("should return dry-run plan when dry_run=true", async () => {
      mockIsThirdPartyInstallEnabled.mockReturnValue(true);
      mockListThirdPartyTools.mockResolvedValue([
        { binary: "falco", name: "Falco", installed: true, currentVersion: "0.39.2", manifestVersion: "0.39.2", needsUpdate: false },
        { binary: "trivy", name: "Trivy", installed: false, manifestVersion: "0.58.1", needsUpdate: false },
        { binary: "grype", name: "Grype", installed: false, manifestVersion: "0.86.1", needsUpdate: false },
      ]);

      const handler = tools.get("defense_mgmt")!.handler;
      const result = await handler({
        action: "install_optional_deps",
        dry_run: true,
      });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("DRY RUN");
      expect(result.content[0].text).toContain("trivy");
      expect(result.content[0].text).toContain("grype");
      expect(result.content[0].text).toContain("Tools to install: 2");
      expect(mockInstallThirdPartyTool).not.toHaveBeenCalled();
    });

    it("should call installThirdPartyTool when dry_run=false and env var set", async () => {
      mockIsThirdPartyInstallEnabled.mockReturnValue(true);
      mockListThirdPartyTools.mockResolvedValue([
        { binary: "trivy", name: "Trivy", installed: false, manifestVersion: "0.58.1", needsUpdate: false },
      ]);
      mockInstallThirdPartyTool.mockResolvedValue({
        binary: "trivy",
        success: true,
        message: "Trivy v0.58.1 installed to /usr/local/bin/trivy (SHA256 verified)",
      });

      const handler = tools.get("defense_mgmt")!.handler;
      const result = await handler({
        action: "install_optional_deps",
        dry_run: false,
        force: true,
      });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("LIVE");
      expect(result.content[0].text).toContain("Success: 1");
      expect(mockInstallThirdPartyTool).toHaveBeenCalledWith("trivy", { force: true });
    });

    it("should handle installation failures gracefully", async () => {
      mockIsThirdPartyInstallEnabled.mockReturnValue(true);
      mockListThirdPartyTools.mockResolvedValue([
        { binary: "trivy", name: "Trivy", installed: false, manifestVersion: "0.58.1", needsUpdate: false },
      ]);
      mockInstallThirdPartyTool.mockResolvedValue({
        binary: "trivy",
        success: false,
        message: "SHA256 MISMATCH for Trivy!",
      });

      const handler = tools.get("defense_mgmt")!.handler;
      const result = await handler({
        action: "install_optional_deps",
        dry_run: false,
      });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("Failed: 1");
      expect(result.content[0].text).toContain("SHA256 MISMATCH");
    });

    it("should install only specified tool_name", async () => {
      mockIsThirdPartyInstallEnabled.mockReturnValue(true);
      mockListThirdPartyTools.mockResolvedValue([
        { binary: "falco", name: "Falco", installed: false, manifestVersion: "0.39.2", needsUpdate: false },
        { binary: "trivy", name: "Trivy", installed: false, manifestVersion: "0.58.1", needsUpdate: false },
      ]);
      mockInstallThirdPartyTool.mockResolvedValue({
        binary: "trivy",
        success: true,
        message: "Trivy v0.58.1 installed",
      });

      const handler = tools.get("defense_mgmt")!.handler;
      const result = await handler({
        action: "install_optional_deps",
        dry_run: false,
        tool_name: "trivy",
      });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("Success: 1");
      expect(mockInstallThirdPartyTool).toHaveBeenCalledTimes(1);
      expect(mockInstallThirdPartyTool).toHaveBeenCalledWith("trivy", { force: false });
    });

    it("should skip already-installed tools when force=false", async () => {
      mockIsThirdPartyInstallEnabled.mockReturnValue(true);
      mockListThirdPartyTools.mockResolvedValue([
        { binary: "falco", name: "Falco", installed: true, currentVersion: "0.39.2", manifestVersion: "0.39.2", needsUpdate: false },
      ]);

      const handler = tools.get("defense_mgmt")!.handler;
      const result = await handler({
        action: "install_optional_deps",
        dry_run: false,
        force: false,
      });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("Skipped: 1");
      expect(result.content[0].text).toContain("already installed");
      expect(mockInstallThirdPartyTool).not.toHaveBeenCalled();
    });

    it("should include confirmation notice when force=false and dry_run=false", async () => {
      mockIsThirdPartyInstallEnabled.mockReturnValue(true);
      mockListThirdPartyTools.mockResolvedValue([
        { binary: "trivy", name: "Trivy", installed: false, manifestVersion: "0.58.1", needsUpdate: false },
      ]);
      mockInstallThirdPartyTool.mockResolvedValue({
        binary: "trivy",
        success: true,
        message: "Trivy v0.58.1 installed",
      });

      const handler = tools.get("defense_mgmt")!.handler;
      const result = await handler({
        action: "install_optional_deps",
        dry_run: false,
        force: false,
      });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("caller is responsible for confirming intent");
    });
  });
});
