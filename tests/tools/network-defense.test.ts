/**
 * Tests for src/tools/network-defense.ts
 *
 * Covers: TOOL-022 network parameter validation (IP, CIDR, port, protocol),
 * BPF filter validation, capture path validation, tool registration, and action routing.
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
  parseSsOutput: vi.fn().mockReturnValue([]),
  formatToolOutput: vi.fn((obj: unknown) => ({ type: "text", text: JSON.stringify(obj) })),
}));
vi.mock("../../src/core/changelog.js", () => ({
  logChange: vi.fn(),
  createChangeEntry: vi.fn().mockReturnValue({}),
}));
vi.mock("../../src/core/sanitizer.js", () => ({
  validateInterface: vi.fn((i: string) => i),
  sanitizeArgs: vi.fn((a: string[]) => a),
  validateTarget: vi.fn((t: string) => t),
  validateToolPath: vi.fn((p: string, _dirs: string[], _label: string) => {
    if (p.includes("..")) throw new Error("Path contains forbidden directory traversal (..)");
    return p;
  }),
}));
vi.mock("../../src/tools/ebpf-security.js", () => ({
  validateBpfFilter: vi.fn((f: string) => {
    if (f.includes(";")) throw new Error("BPF filter contains forbidden shell metacharacters");
    return f;
  }),
}));

import { registerNetworkDefenseTools } from "../../src/tools/network-defense.js";
import { executeCommand } from "../../src/core/executor.js";

type ToolHandler = (params: Record<string, unknown>) => Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }>;

function createMockServer() {
  const tools = new Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>();
  const server = {
    tool: vi.fn((name: string, _desc: string, schema: Record<string, unknown>, handler: ToolHandler) => {
      tools.set(name, { schema, handler });
    }),
  };
  return { server: server as unknown as Parameters<typeof registerNetworkDefenseTools>[0], tools };
}

describe("network-defense tools", () => {
  let tools: Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>;

  beforeEach(() => {
    vi.clearAllMocks();
    const mock = createMockServer();
    registerNetworkDefenseTools(mock.server);
    tools = mock.tools;
  });

  it("should register all 3 network defense tools", () => {
    expect(tools.has("netdef_connections")).toBe(true);
    expect(tools.has("netdef_capture")).toBe(true);
    expect(tools.has("netdef_security_audit")).toBe(true);
  });

  // ── netdef_connections ────────────────────────────────────────────────

  it("should handle list action", async () => {
    const handler = tools.get("netdef_connections")!.handler;
    const result = await handler({ action: "list", protocol: "all", listening: false, process: true });
    expect(result.isError).toBeUndefined();
  });

  it("should handle audit action", async () => {
    vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk, stdout: "Netid  State  Recv-Q Send-Q Local Address:Port\n" });
    const handler = tools.get("netdef_connections")!.handler;
    const result = await handler({ action: "audit", include_loopback: false });
    expect(result.isError).toBeUndefined();
  });

  // ── netdef_capture ────────────────────────────────────────────────────

  it("should preview custom capture in dry_run mode", async () => {
    const handler = tools.get("netdef_capture")!.handler;
    const result = await handler({
      action: "custom",
      interface: "any",
      count: 10,
      duration: 5,
      dry_run: true,
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("DRY-RUN");
  });

  it("should reject BPF filter with shell metacharacters (TOOL-022/018)", async () => {
    const handler = tools.get("netdef_capture")!.handler;
    const result = await handler({
      action: "custom",
      interface: "any",
      count: 10,
      duration: 5,
      filter: "port 80; rm -rf /",
      dry_run: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("metacharacters");
  });

  it("should reject output_file path with traversal (TOOL-022)", async () => {
    const handler = tools.get("netdef_capture")!.handler;
    const result = await handler({
      action: "custom",
      interface: "any",
      count: 10,
      duration: 5,
      output_file: "/tmp/../../../etc/capture.pcap",
      dry_run: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("traversal");
  });

  // ── netdef_security_audit ─────────────────────────────────────────────

  it("should handle scan_detect action", async () => {
    vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk, stdout: "" });
    const handler = tools.get("netdef_security_audit")!.handler;
    const result = await handler({ action: "scan_detect", threshold: 10, timeframe: 60 });
    expect(result.isError).toBeUndefined();
  });

  it("should handle self_scan action", async () => {
    vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk, stdout: "Nmap scan report" });
    const handler = tools.get("netdef_security_audit")!.handler;
    const result = await handler({ action: "self_scan", target: "localhost", scan_type: "quick" });
    expect(result.isError).toBeUndefined();
  });
});
