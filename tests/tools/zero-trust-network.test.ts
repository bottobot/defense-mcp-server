/**
 * Tests for src/tools/zero-trust-network.ts
 *
 * Covers: TOOL-003 input validation (service name, interface name, port validation),
 * tool registration, action routing, dry_run defaults, and microsegmentation.
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
  backupFile: vi.fn().mockReturnValue("/tmp/backup"),
}));
vi.mock("../../src/core/safeguards.js", () => ({
  SafeguardRegistry: {
    getInstance: vi.fn().mockReturnValue({
      checkSafety: vi.fn().mockResolvedValue({ safe: true, warnings: [] }),
    }),
  },
}));
vi.mock("../../src/core/sanitizer.js", () => ({
  validateFilePath: vi.fn((p: string) => p),
  validateTarget: vi.fn((t: string) => t),
  validatePort: vi.fn((p: number) => {
    if (p < 1 || p > 65535) throw new Error(`Port must be 1-65535, got: ${p}`);
    return p;
  }),
}));
vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return { ...actual, existsSync: vi.fn().mockReturnValue(false), readFileSync: vi.fn().mockReturnValue("") };
});

import { registerZeroTrustNetworkTools } from "../../src/tools/zero-trust-network.js";

type ToolHandler = (params: Record<string, unknown>) => Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }>;

function createMockServer() {
  const tools = new Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>();
  const server = {
    tool: vi.fn((name: string, _desc: string, schema: Record<string, unknown>, handler: ToolHandler) => {
      tools.set(name, { schema, handler });
    }),
  };
  return { server: server as unknown as Parameters<typeof registerZeroTrustNetworkTools>[0], tools };
}

describe("zero-trust-network tools", () => {
  let tools: Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>;

  beforeEach(() => {
    vi.clearAllMocks();
    const mock = createMockServer();
    registerZeroTrustNetworkTools(mock.server);
    tools = mock.tools;
  });

  it("should register the zero_trust tool", () => {
    expect(tools.has("zero_trust")).toBe(true);
  });

  // ── wireguard action ──────────────────────────────────────────────────

  it("should require address for wireguard action", async () => {
    const handler = tools.get("zero_trust")!.handler;
    const result = await handler({ action: "wireguard", interfaceName: "wg0", listenPort: 51820, dryRun: true });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("address is required");
  });

  it("should preview wireguard setup in dry_run mode", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    vi.mocked(executeCommand)
      .mockResolvedValueOnce({ ...cmdOk, stdout: "privatekey123" }) // wg genkey
      .mockResolvedValueOnce({ ...cmdOk, stdout: "publickey456" });  // wg pubkey

    const handler = tools.get("zero_trust")!.handler;
    const result = await handler({
      action: "wireguard",
      interfaceName: "wg0",
      listenPort: 51820,
      address: "10.0.0.1/24",
      dryRun: true,
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("dryRun");
  });

  // ── wg_peers action ───────────────────────────────────────────────────

  it("should require peer_action for wg_peers", async () => {
    const handler = tools.get("zero_trust")!.handler;
    const result = await handler({ action: "wg_peers", interfaceName: "wg0", dryRun: true });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("peer_action is required");
  });

  it("should require publicKey for add peer action", async () => {
    const handler = tools.get("zero_trust")!.handler;
    const result = await handler({ action: "wg_peers", peer_action: "add", interfaceName: "wg0", dryRun: true });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("publicKey is required");
  });

  it("should require allowedIps for add peer action", async () => {
    const handler = tools.get("zero_trust")!.handler;
    const result = await handler({
      action: "wg_peers",
      peer_action: "add",
      interfaceName: "wg0",
      publicKey: "abc123",
      dryRun: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("allowedIps is required");
  });

  // ── mtls action ───────────────────────────────────────────────────────

  it("should require outputDir for mtls action", async () => {
    const handler = tools.get("zero_trust")!.handler;
    const result = await handler({ action: "mtls", dryRun: true });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("outputDir is required");
  });

  it("should preview mtls cert generation in dry_run mode", async () => {
    const handler = tools.get("zero_trust")!.handler;
    const result = await handler({
      action: "mtls",
      outputDir: "/tmp/certs",
      commonName: "test-ca",
      serverCN: "server.test",
      clientCN: "client.test",
      validDays: 365,
      dryRun: true,
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("dryRun");
  });

  // ── microsegment action ───────────────────────────────────────────────

  it("should require service for microsegment action", async () => {
    const handler = tools.get("zero_trust")!.handler;
    const result = await handler({ action: "microsegment", dryRun: true });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("service is required");
  });

  it("should require allowPorts for microsegment action", async () => {
    const handler = tools.get("zero_trust")!.handler;
    const result = await handler({ action: "microsegment", service: "nginx", dryRun: true });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("allowPorts is required");
  });

  it("should reject invalid service name with spaces (TOOL-003)", async () => {
    const handler = tools.get("zero_trust")!.handler;
    const result = await handler({
      action: "microsegment",
      service: "my service; drop",
      allowPorts: [80],
      allowSources: [],
      denyAll: true,
      dryRun: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Invalid service name");
  });

  it("should preview microsegmentation rules in dry_run mode", async () => {
    const handler = tools.get("zero_trust")!.handler;
    const result = await handler({
      action: "microsegment",
      service: "nginx",
      allowPorts: [80, 443],
      allowSources: [],
      denyAll: true,
      dryRun: true,
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("dryRun");
  });

  it("should handle unknown action", async () => {
    const handler = tools.get("zero_trust")!.handler;
    const result = await handler({ action: "unknown" as string });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Unknown action");
  });
});
