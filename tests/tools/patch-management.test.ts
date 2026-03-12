/**
 * Tests for src/tools/patch-management.ts
 *
 * Covers: tool registration, vulnerability_intel action routing,
 * CVE ID validation, dry_run defaults, and distro-aware patching.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/core/executor.js", () => ({
  executeCommand: vi.fn().mockResolvedValue({ exitCode: 0, stdout: "", stderr: "", timedOut: false, duration: 10, permissionDenied: false }),
}));
vi.mock("../../src/core/config.js", () => ({
  getConfig: vi.fn().mockReturnValue({ dryRun: true, networkTimeout: 10000 }),
  getToolTimeout: vi.fn().mockReturnValue(30000),
}));
vi.mock("../../src/core/parsers.js", () => ({
  createTextContent: vi.fn((text: string) => ({ type: "text", text })),
  createErrorContent: vi.fn((text: string) => ({ type: "text", text: `Error: ${text}` })),
  formatToolOutput: vi.fn((obj: unknown) => ({ type: "text", text: JSON.stringify(obj) })),
}));
vi.mock("../../src/core/distro-adapter.js", () => ({
  getDistroAdapter: vi.fn().mockResolvedValue({
    isDebian: true,
    isRhel: false,
    isSuse: false,
    isArch: false,
    isAlpine: false,
    summary: "Debian 12",
    pkg: { updateCmd: () => ["apt-get", "update"] },
    pkgQuery: {
      listUpgradableCmd: ["apt", "list", "--upgradable"],
      showHeldCmd: ["dpkg", "--get-selections"],
      autoRemoveCmd: ["apt-get", "--dry-run", "autoremove"],
      listKernelsCmd: ["dpkg", "--list", "linux-image-*"],
    },
    autoUpdate: {
      supported: true,
      packageName: "unattended-upgrades",
      checkInstalledCmd: ["dpkg", "-s", "unattended-upgrades"],
      serviceName: "unattended-upgrades",
      configFiles: ["/etc/apt/apt.conf.d/20auto-upgrades"],
      installHint: "sudo apt install unattended-upgrades",
    },
    integrity: {
      supported: true,
      toolName: "debsums",
      checkCmd: ["debsums", "-s"],
      checkPackageCmd: (pkg: string) => ["debsums", pkg],
      installHint: "sudo apt install debsums",
    },
  }),
}));
vi.mock("../../src/core/distro.js", () => ({
  detectDistro: vi.fn().mockResolvedValue({ id: "debian", family: "debian", name: "Debian", packageManager: "apt" }),
}));
vi.mock("node:https", () => ({
  get: vi.fn(),
}));

import { registerPatchManagementTools } from "../../src/tools/patch-management.js";

type ToolHandler = (params: Record<string, unknown>) => Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }>;

function createMockServer() {
  const tools = new Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>();
  const server = {
    tool: vi.fn((name: string, _desc: string, schema: Record<string, unknown>, handler: ToolHandler) => {
      tools.set(name, { schema, handler });
    }),
  };
  return { server: server as unknown as Parameters<typeof registerPatchManagementTools>[0], tools };
}

describe("patch-management tools", () => {
  let tools: Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>;

  beforeEach(() => {
    vi.clearAllMocks();
    const mock = createMockServer();
    registerPatchManagementTools(mock.server);
    tools = mock.tools;
  });

  it("should register 1 patch tool", () => {
    expect(tools.has("patch")).toBe(true);
    expect(tools.size).toBe(1);
  });

  // ── vuln_lookup ───────────────────────────────────────────────────────

  it("should require cveId for vuln_lookup action", async () => {
    const handler = tools.get("patch")!.handler;
    const result = await handler({ action: "vuln_lookup", dryRun: true });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("cveId is required");
  });

  it("should reject malformed CVE ID", async () => {
    const handler = tools.get("patch")!.handler;
    const result = await handler({ action: "vuln_lookup", cveId: "not-a-cve", dryRun: true });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("CVE-YYYY-NNNN");
  });

  it("should accept valid CVE ID in dry_run mode", async () => {
    const handler = tools.get("patch")!.handler;
    const result = await handler({ action: "vuln_lookup", cveId: "CVE-2024-1234", dryRun: true });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("dryRun");
  });

  it("should preview vuln_scan action in dry_run mode", async () => {
    const handler = tools.get("patch")!.handler;
    const result = await handler({ action: "vuln_scan", maxPackages: 10, dryRun: true });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("dryRun");
  });

  it("should require packageName for vuln_urgency action", async () => {
    const handler = tools.get("patch")!.handler;
    const result = await handler({ action: "vuln_urgency", dryRun: true });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("packageName is required");
  });

  it("should preview vuln_urgency action in dry_run mode", async () => {
    const handler = tools.get("patch")!.handler;
    const result = await handler({ action: "vuln_urgency", packageName: "openssl", dryRun: true });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("dryRun");
  });

  it("should handle unknown action", async () => {
    const handler = tools.get("patch")!.handler;
    const result = await handler({ action: "unknown" as string });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Unknown action");
  });
});
