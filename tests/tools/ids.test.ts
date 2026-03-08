/**
 * Tests for src/tools/ids.ts
 *
 * Covers: TOOL-016 path validation for IDS config/baseline paths,
 * tool registration, action routing, dry_run defaults.
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

import { registerIdsTools } from "../../src/tools/ids.js";

type ToolHandler = (params: Record<string, unknown>) => Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }>;

function createMockServer() {
  const tools = new Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>();
  const server = {
    tool: vi.fn((name: string, _desc: string, schema: Record<string, unknown>, handler: ToolHandler) => {
      tools.set(name, { schema, handler });
    }),
  };
  return { server: server as unknown as Parameters<typeof registerIdsTools>[0], tools };
}

describe("ids tools", () => {
  let tools: Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>;

  beforeEach(() => {
    vi.clearAllMocks();
    const mock = createMockServer();
    registerIdsTools(mock.server);
    tools = mock.tools;
  });

  it("should register all 3 IDS tools", () => {
    expect(tools.has("ids_aide_manage")).toBe(true);
    expect(tools.has("ids_rootkit_scan")).toBe(true);
    expect(tools.has("ids_file_integrity_check")).toBe(true);
  });

  // ── ids_aide_manage ───────────────────────────────────────────────────

  it("should preview AIDE init in dry_run mode", async () => {
    const handler = tools.get("ids_aide_manage")!.handler;
    const result = await handler({ action: "init", dry_run: true });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("DRY-RUN");
  });

  it("should reject AIDE config path with traversal (TOOL-016)", async () => {
    const handler = tools.get("ids_aide_manage")!.handler;
    const result = await handler({ action: "check", config: "/etc/../../../tmp/evil", dry_run: true });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("traversal");
  });

  // ── ids_rootkit_scan ──────────────────────────────────────────────────

  it("should handle rkhunter action", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk, stdout: "System checks summary\nAll checks OK" });
    const handler = tools.get("ids_rootkit_scan")!.handler;
    const result = await handler({ action: "rkhunter", update_first: false, skip_keypress: true, report_warnings_only: false });
    expect(result.isError).toBeUndefined();
  });

  it("should handle chkrootkit action", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk, stdout: "ROOTDIR is `/'\nnot infected\nnot infected" });
    const handler = tools.get("ids_rootkit_scan")!.handler;
    const result = await handler({ action: "chkrootkit", quiet: false, expert: false });
    expect(result.isError).toBeUndefined();
  });

  // ── ids_file_integrity_check ──────────────────────────────────────────

  it("should reject file paths with traversal (TOOL-016)", async () => {
    const handler = tools.get("ids_file_integrity_check")!.handler;
    const result = await handler({ paths: "/etc/../../../tmp/evil", create_baseline: false });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("traversal");
  });

  it("should handle empty paths input", async () => {
    const handler = tools.get("ids_file_integrity_check")!.handler;
    const result = await handler({ paths: "", create_baseline: false });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("No file paths");
  });

  it("should validate baseline_path for traversal (TOOL-016)", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk, stdout: "abc123  /etc/hosts" });
    const handler = tools.get("ids_file_integrity_check")!.handler;
    const result = await handler({ paths: "/etc/hosts", baseline_path: "/tmp/../../../etc/shadow", create_baseline: false });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("traversal");
  });
});
