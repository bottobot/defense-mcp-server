/**
 * Tests for src/tools/supply-chain-security.ts
 *
 * Covers: TOOL-025 package name validation, registry URL validation,
 * key path traversal rejection, tool registration, and dry_run defaults.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/core/executor.js", () => ({
  executeCommand: vi.fn().mockResolvedValue({ exitCode: 0, stdout: "", stderr: "", timedOut: false, duration: 10, permissionDenied: false }),
}));

const cmdOk = { exitCode: 0, stdout: "", stderr: "", timedOut: false, duration: 10, permissionDenied: false };
vi.mock("../../src/core/config.js", () => ({
  getConfig: vi.fn().mockReturnValue({ dryRun: true }),
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
}));
vi.mock("../../src/core/sanitizer.js", () => ({
  validateFilePath: vi.fn((p: string) => p),
}));
vi.mock("../../src/core/distro.js", () => ({
  detectDistro: vi.fn().mockResolvedValue({ id: "debian", family: "debian", name: "Debian", packageManager: "apt" }),
}));
vi.mock("../../src/core/safeguards.js", () => ({
  SafeguardRegistry: {
    getInstance: vi.fn().mockReturnValue({
      checkSafety: vi.fn().mockResolvedValue({ safe: true, warnings: [] }),
    }),
  },
}));

import { registerSupplyChainSecurityTools } from "../../src/tools/supply-chain-security.js";

type ToolHandler = (params: Record<string, unknown>) => Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }>;

function createMockServer() {
  const tools = new Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>();
  const server = {
    tool: vi.fn((name: string, _desc: string, schema: Record<string, unknown>, handler: ToolHandler) => {
      tools.set(name, { schema, handler });
    }),
  };
  return { server: server as unknown as Parameters<typeof registerSupplyChainSecurityTools>[0], tools };
}

describe("supply-chain-security tools", () => {
  let tools: Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>;

  beforeEach(() => {
    vi.clearAllMocks();
    const mock = createMockServer();
    registerSupplyChainSecurityTools(mock.server);
    tools = mock.tools;
  });

  it("should register the supply_chain tool", () => {
    expect(tools.has("supply_chain")).toBe(true);
  });

  // ── sbom action ───────────────────────────────────────────────────────

  it("should fallback to dpkg when no SBOM tool is installed", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    // which syft → not found, which cdxgen → not found, dpkg-query → success
    vi.mocked(executeCommand)
      .mockResolvedValueOnce({ ...cmdOk, exitCode: 1 }) // which syft
      .mockResolvedValueOnce({ ...cmdOk, exitCode: 1 }) // which cdxgen
      .mockResolvedValueOnce({ ...cmdOk, stdout: "openssl\t3.0.11\tamd64\n" }); // dpkg-query

    const handler = tools.get("supply_chain")!.handler;
    const result = await handler({ action: "sbom", path: ".", format: "cyclonedx-json" });
    expect(result.isError).toBeUndefined();
  });

  // ── sign action ───────────────────────────────────────────────────────

  it("should require artifact for sign action", async () => {
    const handler = tools.get("supply_chain")!.handler;
    const result = await handler({ action: "sign", dryRun: true });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("artifact is required");
  });

  it("should reject key path with traversal (TOOL-025)", async () => {
    const handler = tools.get("supply_chain")!.handler;
    const result = await handler({
      action: "sign",
      artifact: "myimage:latest",
      keyPath: "/tmp/../../../etc/shadow",
      dryRun: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("traversal");
  });

  it("should preview sign in dry_run mode", async () => {
    const handler = tools.get("supply_chain")!.handler;
    const result = await handler({
      action: "sign",
      artifact: "myimage:latest",
      dryRun: true,
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("dryRun");
  });

  // ── verify_slsa action ────────────────────────────────────────────────

  it("should require artifact for verify_slsa action", async () => {
    const handler = tools.get("supply_chain")!.handler;
    const result = await handler({ action: "verify_slsa" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("artifact is required");
  });

  it("should reject non-HTTPS source URL (TOOL-025)", async () => {
    const handler = tools.get("supply_chain")!.handler;
    const result = await handler({
      action: "verify_slsa",
      artifact: "myimage:latest",
      source: "http://github.com/myrepo",
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("HTTPS");
  });

  it("should handle unknown action", async () => {
    const handler = tools.get("supply_chain")!.handler;
    const result = await handler({ action: "unknown" as string });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Unknown action");
  });
});
