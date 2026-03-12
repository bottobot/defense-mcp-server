/**
 * Tests for src/tools/secrets.ts
 *
 * Covers: TOOL-021 error message sanitization, tool registration,
 * secrets scanning types, env audit, SSH key sprawl, and git history scan.
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

import { registerSecretsTools } from "../../src/tools/secrets.js";
import { executeCommand } from "../../src/core/executor.js";

type ToolHandler = (params: Record<string, unknown>) => Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }>;

function createMockServer() {
  const tools = new Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>();
  const server = {
    tool: vi.fn((name: string, _desc: string, schema: Record<string, unknown>, handler: ToolHandler) => {
      tools.set(name, { schema, handler });
    }),
  };
  return { server: server as unknown as Parameters<typeof registerSecretsTools>[0], tools };
}

describe("secrets tools", () => {
  let tools: Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>;

  beforeEach(() => {
    vi.clearAllMocks();
    const mock = createMockServer();
    registerSecretsTools(mock.server);
    tools = mock.tools;
  });

  it("should register 1 secrets tool", () => {
    expect(tools.has("secrets")).toBe(true);
    expect(tools.size).toBe(1);
  });

  // ── scan ──────────────────────────────────────────────────────────────

  it("should scan for all secret types by default", async () => {
    vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk, stdout: "", exitCode: 1 });
    const handler = tools.get("secrets")!.handler;
    const result = await handler({ action: "scan", path: "/home", scan_type: "all", max_depth: 3 });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("Secrets Scan Report");
  });

  it("should scan only for api_keys when specified", async () => {
    vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk, stdout: "", exitCode: 1 });
    const handler = tools.get("secrets")!.handler;
    const result = await handler({ action: "scan", path: "/home", scan_type: "api_keys", max_depth: 3 });
    expect(result.isError).toBeUndefined();
  });

  it("should report no findings when grep returns nothing", async () => {
    vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk, stdout: "", exitCode: 1 });
    const handler = tools.get("secrets")!.handler;
    const result = await handler({ action: "scan", path: "/home", scan_type: "all", max_depth: 3 });
    expect(result.content[0].text).toContain("No hardcoded secrets detected");
  });

  // ── env_audit ─────────────────────────────────────────────────────────

  it("should audit environment variables", async () => {
    vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk, stdout: "HOME=/home/user\nPATH=/usr/bin\n" });
    const handler = tools.get("secrets")!.handler;
    const result = await handler({ action: "env_audit", check_env: true, check_files: false });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("SENSITIVE ENVIRONMENT VARIABLES");
  });

  // ── ssh_key_sprawl ────────────────────────────────────────────────────

  it("should scan for SSH private keys", async () => {
    vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk, stdout: "" });
    const handler = tools.get("secrets")!.handler;
    const result = await handler({ action: "ssh_key_sprawl", search_path: "/home", check_authorized_keys: false });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("SSH Key Sprawl Report");
  });

  // ── git_history_scan ──────────────────────────────────────────────────

  it("should require repoPath for git_history_scan", async () => {
    const handler = tools.get("secrets")!.handler;
    const result = await handler({ action: "git_history_scan", dryRun: true });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("repoPath is required");
  });

  it("should preview git history scan in dry_run mode", async () => {
    const handler = tools.get("secrets")!.handler;
    const result = await handler({ action: "git_history_scan", repoPath: "/home/user/project", dryRun: true });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("dryRun");
  });

  it("should report error when no scanning tools available", async () => {
    vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk, exitCode: 1, stdout: "" });
    const handler = tools.get("secrets")!.handler;
    const result = await handler({ action: "git_history_scan", repoPath: "/home/user/project", dryRun: false });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("truffleHog");
  });
});
