/**
 * Tests for src/tools/firewall.ts
 *
 * Covers: TOOL-003 (port validation), TOOL-008 (nftables table name validation),
 * match module validation, schema validation, and tool registration.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Mock all external dependencies before imports ──────────────────────────

vi.mock("../../src/core/executor.js", () => ({
  executeCommand: vi.fn().mockResolvedValue({ exitCode: 0, stdout: "", stderr: "" }),
}));
vi.mock("../../src/core/config.js", () => ({
  getConfig: vi.fn().mockReturnValue({ dryRun: true, quarantineDir: "/tmp/quarantine" }),
  getToolTimeout: vi.fn().mockReturnValue(30000),
}));
vi.mock("../../src/core/distro-adapter.js", () => ({
  getDistroAdapter: vi.fn().mockResolvedValue({
    fwPersistence: {
      packageName: "iptables-persistent",
      installCmd: ["apt-get", "install", "-y", "iptables-persistent"],
      enableCmd: ["systemctl", "enable", "netfilter-persistent"],
      checkInstalledCmd: ["dpkg", "-s", "iptables-persistent"],
      serviceName: "netfilter-persistent",
      uninstallHint: "sudo apt remove iptables-persistent",
    },
    isDebian: true,
    paths: { firewallPersistenceConfig: "/etc/iptables/rules.v4" },
    summary: "Debian 12",
  }),
}));
vi.mock("../../src/core/parsers.js", () => ({
  createTextContent: vi.fn((text: string) => ({ type: "text", text })),
  createErrorContent: vi.fn((text: string) => ({ type: "text", text: `Error: ${text}` })),
  parseIptablesOutput: vi.fn().mockReturnValue([]),
  formatToolOutput: vi.fn((obj: unknown) => ({ type: "text", text: JSON.stringify(obj) })),
}));
vi.mock("../../src/core/changelog.js", () => ({
  logChange: vi.fn(),
  createChangeEntry: vi.fn().mockReturnValue({}),
  backupFile: vi.fn().mockReturnValue("/tmp/backup"),
}));
vi.mock("../../src/core/sanitizer.js", () => ({
  validateIptablesChain: vi.fn((c: string) => c),
  validateFilePath: vi.fn((p: string) => p),
  validateTarget: vi.fn((t: string) => t),
  validatePortRange: vi.fn((p: string) => p),
  sanitizeArgs: vi.fn((a: string[]) => a),
}));

import { registerFirewallTools } from "../../src/tools/firewall.js";

// ── Helper to capture registered tools ─────────────────────────────────────

type ToolHandler = (params: Record<string, unknown>) => Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }>;

function createMockServer() {
  const tools = new Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>();
  const server = {
    tool: vi.fn((name: string, _desc: string, schema: Record<string, unknown>, handler: ToolHandler) => {
      tools.set(name, { schema, handler });
    }),
  };
  return { server: server as unknown as Parameters<typeof registerFirewallTools>[0], tools };
}

describe("firewall tools", () => {
  let tools: Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>;

  beforeEach(() => {
    vi.clearAllMocks();
    const mock = createMockServer();
    registerFirewallTools(mock.server);
    tools = mock.tools;
  });

  // ── Registration ──────────────────────────────────────────────────────

  it("should register a single firewall tool", () => {
    expect(tools.has("firewall")).toBe(true);
  });

  // ── TOOL-003: Port validation ────────────────────────────────────────

  it("should reject port specification with invalid characters (TOOL-003)", async () => {
    const handler = tools.get("firewall")!.handler;
    const result = await handler({
      action: "iptables_add",
      chain: "INPUT",
      protocol: "tcp",
      port: "80;rm -rf /",
      table: "filter",
      dry_run: true,
      target_action: "DROP",
    });
    expect(result.isError).toBe(true);
  });

  it("should reject port number out of range (TOOL-003)", async () => {
    const handler = tools.get("firewall")!.handler;
    const result = await handler({
      action: "iptables_add",
      chain: "INPUT",
      protocol: "tcp",
      port: "99999",
      table: "filter",
      dry_run: true,
      target_action: "DROP",
    });
    expect(result.isError).toBe(true);
  });

  it("should accept valid port range (TOOL-003)", async () => {
    const handler = tools.get("firewall")!.handler;
    const result = await handler({
      action: "iptables_add",
      chain: "INPUT",
      protocol: "tcp",
      port: "8080:8090",
      table: "filter",
      dry_run: true,
      target_action: "DROP",
    });
    expect(result.isError).toBeUndefined();
  });

  // ── TOOL-008: nftables table name validation ─────────────────────────

  it("should reject nftables table name with spaces (TOOL-008)", async () => {
    const handler = tools.get("firewall")!.handler;
    const result = await handler({
      action: "nftables_list",
      table: "my table; drop",
      family: "ip",
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Invalid nftables table name");
  });

  it("should reject nftables table name starting with number (TOOL-008)", async () => {
    const handler = tools.get("firewall")!.handler;
    const result = await handler({
      action: "nftables_list",
      table: "123table",
      family: "ip",
    });
    expect(result.isError).toBe(true);
  });

  it("should accept valid nftables table name (TOOL-008)", async () => {
    const handler = tools.get("firewall")!.handler;
    const result = await handler({
      action: "nftables_list",
      table: "myfilter",
      family: "ip",
    });
    // Should not error on the table name validation
    expect(result.isError).toBeUndefined();
  });

  // ── Match module validation ──────────────────────────────────────────

  it("should reject unknown match module", async () => {
    const handler = tools.get("firewall")!.handler;
    const result = await handler({
      action: "iptables_add",
      chain: "INPUT",
      protocol: "tcp",
      match_module: "malicious_module",
      table: "filter",
      dry_run: true,
      target_action: "DROP",
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Unknown match module");
  });

  it("should accept allowed match module 'limit'", async () => {
    const handler = tools.get("firewall")!.handler;
    const result = await handler({
      action: "iptables_add",
      chain: "INPUT",
      protocol: "tcp",
      match_module: "limit",
      match_options: "--limit 5/min",
      table: "filter",
      dry_run: true,
      target_action: "DROP",
    });
    expect(result.isError).toBeUndefined();
  });

  // ── Chain and protocol validation ────────────────────────────────────

  it("should require chain for add action", async () => {
    const handler = tools.get("firewall")!.handler;
    const result = await handler({
      action: "iptables_add",
      table: "filter",
      dry_run: true,
      target_action: "DROP",
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("chain");
  });

  it("should require protocol when port is specified", async () => {
    const handler = tools.get("firewall")!.handler;
    const result = await handler({
      action: "iptables_add",
      chain: "INPUT",
      port: "80",
      table: "filter",
      dry_run: true,
      target_action: "DROP",
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Protocol");
  });

  // ── Custom chain name validation ─────────────────────────────────────

  it("should reject invalid custom chain name", async () => {
    const handler = tools.get("firewall")!.handler;
    const result = await handler({
      action: "iptables_create_chain",
      chain_name: "invalid chain!",
      table: "filter",
      dry_run: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Invalid chain name");
  });

  it("should accept valid custom chain name", async () => {
    const handler = tools.get("firewall")!.handler;
    const result = await handler({
      action: "iptables_create_chain",
      chain_name: "MY_CHAIN",
      table: "filter",
      dry_run: true,
    });
    expect(result.isError).toBeUndefined();
  });

  // ── iptables list action ─────────────────────────────────────────────

  it("should handle list action", async () => {
    const handler = tools.get("firewall")!.handler;
    const result = await handler({
      action: "iptables_list",
      table: "filter",
    });
    expect(result.content).toBeDefined();
    expect(result.content.length).toBeGreaterThan(0);
  });

  it("should handle list action with verbose and chain", async () => {
    const handler = tools.get("firewall")!.handler;
    const result = await handler({
      action: "iptables_list",
      table: "filter",
      chain: "INPUT",
      verbose: true,
    });
    expect(result.content).toBeDefined();
  });

  // ── iptables delete action ───────────────────────────────────────────

  it("should require chain for delete action", async () => {
    const handler = tools.get("firewall")!.handler;
    const result = await handler({
      action: "iptables_delete",
      table: "filter",
      dry_run: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("chain");
  });

  it("should require rule_number for delete action", async () => {
    const handler = tools.get("firewall")!.handler;
    const result = await handler({
      action: "iptables_delete",
      table: "filter",
      chain: "INPUT",
      dry_run: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("rule_number");
  });

  it("should handle delete action in dry_run", async () => {
    const handler = tools.get("firewall")!.handler;
    const result = await handler({
      action: "iptables_delete",
      table: "filter",
      chain: "INPUT",
      rule_number: 1,
      dry_run: true,
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("DRY-RUN");
  });

  // ── iptables set_policy action ───────────────────────────────────────

  it("should require chain for set_policy action", async () => {
    const handler = tools.get("firewall")!.handler;
    const result = await handler({
      action: "iptables_set_policy",
      table: "filter",
      policy: "DROP",
      dry_run: true,
    });
    expect(result.isError).toBe(true);
  });

  it("should require policy for set_policy action", async () => {
    const handler = tools.get("firewall")!.handler;
    const result = await handler({
      action: "iptables_set_policy",
      table: "filter",
      chain: "INPUT",
      dry_run: true,
    });
    expect(result.isError).toBe(true);
  });

  it("should reject non-built-in chains for set_policy", async () => {
    const handler = tools.get("firewall")!.handler;
    const result = await handler({
      action: "iptables_set_policy",
      table: "filter",
      chain: "MY_CUSTOM",
      policy: "DROP",
      dry_run: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("INPUT, FORWARD, or OUTPUT");
  });

  // ── iptables create_chain missing chain_name ─────────────────────────

  it("should require chain_name for create_chain action", async () => {
    const handler = tools.get("firewall")!.handler;
    const result = await handler({
      action: "iptables_create_chain",
      table: "filter",
      dry_run: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("chain_name");
  });

  // ── UFW tool tests ───────────────────────────────────────────────────

  it("should handle UFW status action", async () => {
    const handler = tools.get("firewall")!.handler;
    const result = await handler({ action: "ufw_status" });
    expect(result.content).toBeDefined();
  });

  it("should require rule_action for UFW add", async () => {
    const handler = tools.get("firewall")!.handler;
    const result = await handler({ action: "ufw_add", dry_run: true });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("rule_action");
  });

  it("should handle UFW add in dry_run", async () => {
    const handler = tools.get("firewall")!.handler;
    const result = await handler({
      action: "ufw_add",
      rule_action: "allow",
      direction: "in",
      port: "22",
      protocol: "tcp",
      dry_run: true,
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("DRY-RUN");
  });

  // ── match_options/tcp_flags validation ───────────────────────────────

  it("should reject match_options with special characters", async () => {
    const handler = tools.get("firewall")!.handler;
    const result = await handler({
      action: "iptables_add",
      chain: "INPUT",
      protocol: "tcp",
      match_module: "limit",
      match_options: "--limit 5/min; rm -rf /",
      table: "filter",
      dry_run: true,
      target_action: "DROP",
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("invalid characters");
  });

  it("should accept --syn tcp flag", async () => {
    const handler = tools.get("firewall")!.handler;
    const result = await handler({
      action: "iptables_add",
      chain: "INPUT",
      protocol: "tcp",
      tcp_flags: "--syn",
      table: "filter",
      dry_run: true,
      target_action: "DROP",
    });
    expect(result.isError).toBeUndefined();
  });

  it("should reject invalid tcp_flags", async () => {
    const handler = tools.get("firewall")!.handler;
    const result = await handler({
      action: "iptables_add",
      chain: "INPUT",
      protocol: "tcp",
      tcp_flags: "--invalid-flag",
      table: "filter",
      dry_run: true,
      target_action: "DROP",
    });
    expect(result.isError).toBe(true);
  });

});
