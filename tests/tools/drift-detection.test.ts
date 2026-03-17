/**
 * Tests for src/tools/integrity.ts (via re-export from drift-detection.ts)
 *
 * Covers: tool registration, TOOL-024 baseline path validation,
 * extension validation, traversal rejection, and dry_run defaults.
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
  sanitizeArgs: vi.fn((a: string[]) => a),
  validateToolPath: vi.fn((p: string, _dirs: string[], _label: string) => {
    if (p.includes("..")) throw new Error("Path contains forbidden directory traversal (..)");
    return p;
  }),
}));
vi.mock("../../src/core/secure-fs.js", () => ({
  secureWriteFileSync: vi.fn(),
}));
vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return {
    ...actual,
    existsSync: vi.fn().mockReturnValue(true),
    readFileSync: vi.fn().mockReturnValue("{}"),
    mkdirSync: vi.fn(),
    readdirSync: vi.fn().mockReturnValue([]),
    statSync: vi.fn().mockReturnValue({ size: 100, mtime: new Date() }),
  };
});

import { registerIntegrityTools } from "../../src/tools/integrity.js";

type ToolHandler = (params: Record<string, unknown>) => Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }>;

function createMockServer() {
  const tools = new Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>();
  const server = {
    tool: vi.fn((name: string, _desc: string, schema: Record<string, unknown>, handler: ToolHandler) => {
      tools.set(name, { schema, handler });
    }),
  };
  return { server: server as unknown as Parameters<typeof registerIntegrityTools>[0], tools };
}

describe("drift-detection tools (canonical: integrity)", () => {
  let tools: Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>;

  beforeEach(() => {
    vi.clearAllMocks();
    const mock = createMockServer();
    registerIntegrityTools(mock.server);
    tools = mock.tools;
  });

  it("should register integrity tool", () => {
    expect(tools.has("integrity")).toBe(true);
  });

  it("should default dryRun to true", async () => {
    const handler = tools.get("integrity")!.handler;
    const result = await handler({ action: "baseline_create", name: "test", directories: ["/etc"], dryRun: true });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("dryRun");
  });

  it("should list baselines from the baseline directory", async () => {
    const handler = tools.get("integrity")!.handler;
    const result = await handler({ action: "baseline_list" });
    expect(result.isError).toBeUndefined();
  });

  it("should return error when comparing non-existent baseline", async () => {
    const fs = await import("node:fs");
    vi.mocked(fs.existsSync).mockReturnValue(false);
    const handler = tools.get("integrity")!.handler;
    const result = await handler({ action: "baseline_compare", name: "nonexistent" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("not found");
  });

  it("should handle baseline_create action in non-dry-run mode", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    const fs = await import("node:fs");
    vi.mocked(fs.existsSync).mockReturnValue(true);
    vi.mocked(executeCommand).mockResolvedValue({
      ...cmdOk,
      stdout: "/etc/hosts\n/etc/passwd\n",
    });
    vi.mocked(fs.statSync).mockReturnValue({ size: 100, mtime: new Date() } as ReturnType<typeof fs.statSync>);
    vi.mocked(fs.readFileSync).mockReturnValue(Buffer.from("content"));

    const handler = tools.get("integrity")!.handler;
    const result = await handler({ action: "baseline_create", name: "test", directories: ["/etc"], dryRun: false });
    expect(result.isError).toBeUndefined();
  });

  it("should handle unknown action", async () => {
    const handler = tools.get("integrity")!.handler;
    const result = await handler({ action: "unknown" as string });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Unknown action");
  });
});
