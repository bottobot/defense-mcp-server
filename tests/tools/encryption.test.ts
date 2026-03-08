/**
 * Tests for src/tools/encryption.ts
 *
 * Covers: TOOL-023 algorithm validation, key path validation, path traversal
 * rejection, tool registration, and action routing.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/core/executor.js", () => ({
  executeCommand: vi.fn().mockResolvedValue({ exitCode: 0, stdout: "", stderr: "", timedOut: false, duration: 10, permissionDenied: false }),
}));
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
  backupFile: vi.fn().mockReturnValue("/tmp/backup"),
}));
vi.mock("../../src/core/sanitizer.js", () => ({
  validateTarget: vi.fn((t: string) => t),
  validateFilePath: vi.fn((p: string) => p),
  validateCertPath: vi.fn((p: string) => p),
  sanitizeArgs: vi.fn((a: string[]) => a),
  validateToolPath: vi.fn((p: string, _dirs: string[], _label: string) => {
    if (p.includes("..")) throw new Error("Path contains forbidden directory traversal (..)");
    return p;
  }),
}));

import { registerEncryptionTools } from "../../src/tools/encryption.js";

type ToolHandler = (params: Record<string, unknown>) => Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }>;

function createMockServer() {
  const tools = new Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>();
  const server = {
    tool: vi.fn((name: string, _desc: string, schema: Record<string, unknown>, handler: ToolHandler) => {
      tools.set(name, { schema, handler });
    }),
  };
  return { server: server as unknown as Parameters<typeof registerEncryptionTools>[0], tools };
}

describe("encryption tools", () => {
  let tools: Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>;

  beforeEach(() => {
    vi.clearAllMocks();
    const mock = createMockServer();
    registerEncryptionTools(mock.server);
    tools = mock.tools;
  });

  it("should register all 4 encryption tools", () => {
    expect(tools.has("crypto_tls")).toBe(true);
    expect(tools.has("crypto_gpg_keys")).toBe(true);
    expect(tools.has("crypto_luks_manage")).toBe(true);
    expect(tools.has("crypto_file_hash")).toBe(true);
  });

  // ── crypto_tls ────────────────────────────────────────────────────────

  it("should require host for remote_audit action", async () => {
    const handler = tools.get("crypto_tls")!.handler;
    const result = await handler({ action: "remote_audit", port: 443, check_ciphers: true, check_protocols: true, check_certificate: true });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("host is required");
  });

  it("should require cert_path or host for cert_expiry", async () => {
    const handler = tools.get("crypto_tls")!.handler;
    const result = await handler({ action: "cert_expiry", port: 443, warn_days: 30 });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Must specify");
  });

  // ── crypto_gpg_keys ───────────────────────────────────────────────────

  it("should require key_id for GPG export action", async () => {
    const handler = tools.get("crypto_gpg_keys")!.handler;
    const result = await handler({ action: "export" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("key_id is required");
  });

  it("should require file_path for GPG import action", async () => {
    const handler = tools.get("crypto_gpg_keys")!.handler;
    const result = await handler({ action: "import" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("file_path is required");
  });

  it("should reject GPG import path with traversal (TOOL-023)", async () => {
    const handler = tools.get("crypto_gpg_keys")!.handler;
    const result = await handler({ action: "import", file_path: "/tmp/../../../etc/shadow" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("traversal");
  });

  // ── crypto_luks_manage ────────────────────────────────────────────────

  it("should require name for LUKS status action", async () => {
    const handler = tools.get("crypto_luks_manage")!.handler;
    const result = await handler({ action: "status" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("name");
  });

  it("should require device for LUKS dump action", async () => {
    const handler = tools.get("crypto_luks_manage")!.handler;
    const result = await handler({ action: "dump" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("device");
  });

  it("should reject LUKS device path with traversal", async () => {
    const handler = tools.get("crypto_luks_manage")!.handler;
    const result = await handler({ action: "dump", device: "/dev/../etc/shadow" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("traversal");
  });

  // ── crypto_file_hash ──────────────────────────────────────────────────

  it("should reject file hash path with traversal", async () => {
    const handler = tools.get("crypto_file_hash")!.handler;
    const result = await handler({ path: "/etc/../../../etc/shadow", algorithm: "sha256", recursive: false });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("traversal");
  });
});
