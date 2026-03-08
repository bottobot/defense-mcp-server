/**
 * Tests for src/tools/ebpf-security.ts
 *
 * Covers: TOOL-018 BPF filter validation (exported validateBpfFilter),
 * tool registration, dry_run defaults, Falco action routing.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/core/executor.js", () => ({
  executeCommand: vi.fn().mockResolvedValue({ exitCode: 0, stdout: "", stderr: "", timedOut: false, duration: 10, permissionDenied: false }),
}));

const cmdOk = { exitCode: 0, stdout: "", stderr: "", timedOut: false, duration: 10, permissionDenied: false };
vi.mock("../../src/core/parsers.js", () => ({
  createTextContent: vi.fn((text: string) => ({ type: "text", text })),
  createErrorContent: vi.fn((text: string) => ({ type: "text", text: `Error: ${text}` })),
  formatToolOutput: vi.fn((obj: unknown) => ({ type: "text", text: JSON.stringify(obj) })),
}));
vi.mock("../../src/core/changelog.js", () => ({
  logChange: vi.fn(),
  createChangeEntry: vi.fn().mockReturnValue({}),
}));
vi.mock("../../src/core/safeguards.js", () => ({
  SafeguardRegistry: {
    getInstance: vi.fn().mockReturnValue({
      checkSafety: vi.fn().mockResolvedValue({ safe: true, warnings: [] }),
    }),
  },
}));
vi.mock("../../src/core/secure-fs.js", () => ({
  secureWriteFileSync: vi.fn(),
}));
vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return {
    ...actual,
    existsSync: vi.fn().mockReturnValue(false),
    readFileSync: vi.fn().mockReturnValue(""),
    mkdirSync: vi.fn(),
  };
});

import { validateBpfFilter, registerEbpfSecurityTools } from "../../src/tools/ebpf-security.js";

type ToolHandler = (params: Record<string, unknown>) => Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }>;

function createMockServer() {
  const tools = new Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>();
  const server = {
    tool: vi.fn((name: string, _desc: string, schema: Record<string, unknown>, handler: ToolHandler) => {
      tools.set(name, { schema, handler });
    }),
  };
  return { server: server as unknown as Parameters<typeof registerEbpfSecurityTools>[0], tools };
}

describe("ebpf-security tools", () => {
  // ── validateBpfFilter (TOOL-018) ──────────────────────────────────────

  describe("validateBpfFilter", () => {
    it("should accept a valid BPF filter", () => {
      expect(validateBpfFilter("port 80")).toBe("port 80");
    });

    it("should accept BPF filter with common operators", () => {
      expect(validateBpfFilter("host 192.168.1.1 and port 443")).toBe("host 192.168.1.1 and port 443");
    });

    it("should reject empty string", () => {
      expect(() => validateBpfFilter("")).toThrow("non-empty string");
    });

    it("should reject shell metacharacters (semicolon)", () => {
      expect(() => validateBpfFilter("port 80; rm -rf /")).toThrow("forbidden shell metacharacters");
    });

    it("should reject shell metacharacters (pipe)", () => {
      expect(() => validateBpfFilter("port 80 | cat /etc/passwd")).toThrow("forbidden shell metacharacters");
    });

    it("should reject shell metacharacters (backtick)", () => {
      expect(() => validateBpfFilter("`whoami`")).toThrow("forbidden shell metacharacters");
    });

    it("should reject shell metacharacters ($())", () => {
      expect(() => validateBpfFilter("$(id)")).toThrow("forbidden shell metacharacters");
    });

    it("should reject excessively long filters", () => {
      const longFilter = "a".repeat(501);
      expect(() => validateBpfFilter(longFilter)).toThrow("too long");
    });

    it("should trim whitespace", () => {
      expect(validateBpfFilter("  port 80  ")).toBe("port 80");
    });
  });

  // ── Tool registration ─────────────────────────────────────────────────

  describe("tool registration", () => {
    let tools: Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>;

    beforeEach(() => {
      vi.clearAllMocks();
      const mock = createMockServer();
      registerEbpfSecurityTools(mock.server);
      tools = mock.tools;
    });

    it("should register list_ebpf_programs and falco tools", () => {
      expect(tools.has("ebpf_list_programs")).toBe(true);
      expect(tools.has("ebpf_falco")).toBe(true);
    });

    it("should handle falco status action when not installed", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValueOnce({ ...cmdOk, exitCode: 1, stdout: "" });
      const handler = tools.get("ebpf_falco")!.handler;
      const result = await handler({ action: "status" });
      expect(result.content[0].text).toContain("installed");
    });

    it("should require ruleName for deploy_rules action", async () => {
      const handler = tools.get("ebpf_falco")!.handler;
      const result = await handler({ action: "deploy_rules", dryRun: true });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("ruleName is required");
    });

    it("should require ruleContent for deploy_rules action", async () => {
      const handler = tools.get("ebpf_falco")!.handler;
      const result = await handler({ action: "deploy_rules", ruleName: "test", dryRun: true });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("ruleContent is required");
    });

    it("should preview deploy_rules in dry_run mode", async () => {
      const handler = tools.get("ebpf_falco")!.handler;
      const result = await handler({
        action: "deploy_rules",
        ruleName: "test-rule",
        ruleContent: "- rule: test\n  desc: test rule",
        dryRun: true,
      });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("dryRun");
    });
  });
});
