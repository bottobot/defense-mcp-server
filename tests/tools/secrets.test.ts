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

  // ── scan: findings present ───────────────────────────────────────────

  it("should report api_key findings when grep returns files", async () => {
    vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk, stdout: "/home/user/app.js\n/home/user/config.yaml\n" });
    const handler = tools.get("secrets")!.handler;
    const result = await handler({ action: "scan", path: "/home", scan_type: "api_keys", max_depth: 3 });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("API_KEYS");
  });

  it("should scan for passwords only when specified", async () => {
    vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk, stdout: "/home/user/config.ini\n" });
    const handler = tools.get("secrets")!.handler;
    const result = await handler({ action: "scan", path: "/home", scan_type: "passwords", max_depth: 3 });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("PASSWORDS");
  });

  it("should scan for tokens only when specified", async () => {
    vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk, stdout: "/home/user/token.env\n" });
    const handler = tools.get("secrets")!.handler;
    const result = await handler({ action: "scan", path: "/home", scan_type: "tokens", max_depth: 3 });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("TOKENS");
  });

  it("should scan for private_keys and show permission info", async () => {
    let callCount = 0;
    vi.mocked(executeCommand).mockImplementation(async () => {
      callCount++;
      if (callCount === 1) {
        // find returns key files
        return { ...cmdOk, stdout: "/home/user/.ssh/id_rsa\n" };
      }
      // stat returns permissions
      return { ...cmdOk, stdout: "600 user:user /home/user/.ssh/id_rsa" };
    });
    const handler = tools.get("secrets")!.handler;
    const result = await handler({ action: "scan", path: "/home", scan_type: "private_keys", max_depth: 3 });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("PRIVATE_KEYS");
  });

  it("should handle scan errors gracefully", async () => {
    vi.mocked(executeCommand).mockRejectedValue(new Error("Permission denied"));
    const handler = tools.get("secrets")!.handler;
    const result = await handler({ action: "scan", path: "/root", scan_type: "all", max_depth: 3 });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Permission denied");
  });

  // ── env_audit: file exposure check ─────────────────────────────────────

  it("should check .env file exposure when check_files is true", async () => {
    let callCount = 0;
    vi.mocked(executeCommand).mockImplementation(async () => {
      callCount++;
      if (callCount === 1) {
        // env output
        return { ...cmdOk, stdout: "HOME=/home/user\n" };
      }
      if (callCount === 2) {
        // find .env files
        return { ...cmdOk, stdout: "/home/user/project/.env\n" };
      }
      if (callCount === 3) {
        // stat on .env file
        return { ...cmdOk, stdout: "644 user:user /home/user/project/.env" };
      }
      if (callCount === 4) {
        // ls -la /proc/1/environ
        return { ...cmdOk, exitCode: 1, stdout: "" };
      }
      // find /proc readable environ
      return { ...cmdOk, stdout: "" };
    });
    const handler = tools.get("secrets")!.handler;
    const result = await handler({ action: "env_audit", check_env: true, check_files: true });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain(".ENV FILE EXPOSURE");
  });

  it("should detect sensitive env variables and redact values", async () => {
    vi.mocked(executeCommand).mockResolvedValue({
      ...cmdOk,
      stdout: "HOME=/home/user\nAPI_KEY=supersecret123\nDB_PASSWORD=hunter2\nPATH=/usr/bin\n",
    });
    const handler = tools.get("secrets")!.handler;
    const result = await handler({ action: "env_audit", check_env: true, check_files: false });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("REDACTED");
  });

  it("should handle env_audit errors gracefully", async () => {
    vi.mocked(executeCommand).mockRejectedValue(new Error("env command failed"));
    const handler = tools.get("secrets")!.handler;
    const result = await handler({ action: "env_audit", check_env: true, check_files: false });
    expect(result.isError).toBe(true);
  });

  // ── ssh_key_sprawl: with key files ─────────────────────────────────────

  it("should report SSH keys found with permissions and age", async () => {
    let callCount = 0;
    vi.mocked(executeCommand).mockImplementation(async () => {
      callCount++;
      if (callCount === 1) {
        // find SSH keys
        return { ...cmdOk, stdout: "/home/user/.ssh/id_rsa\n" };
      }
      if (callCount === 2) {
        // stat on key file (perms owner mtime)
        const mtime = Math.floor((Date.now() - 100 * 86400 * 1000) / 1000); // 100 days ago
        return { ...cmdOk, stdout: `600 user:user ${mtime}` };
      }
      if (callCount === 3) {
        // ssh-keygen -l -f
        return { ...cmdOk, stdout: "4096 SHA256:abcdef user@host (RSA)" };
      }
      // summary find
      return { ...cmdOk, stdout: "" };
    });
    const handler = tools.get("secrets")!.handler;
    const result = await handler({ action: "ssh_key_sprawl", search_path: "/home", check_authorized_keys: false });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("SSH PRIVATE KEYS");
    expect(result.content[0].text).toContain("id_rsa");
  });

  it("should report authorized_keys when check_authorized_keys is true", async () => {
    let callCount = 0;
    vi.mocked(executeCommand).mockImplementation(async () => {
      callCount++;
      if (callCount === 1) {
        // find SSH private keys (none)
        return { ...cmdOk, stdout: "" };
      }
      if (callCount === 2) {
        // find authorized_keys
        return { ...cmdOk, stdout: "/home/user/.ssh/authorized_keys\n" };
      }
      if (callCount === 3) {
        // stat
        return { ...cmdOk, stdout: "600 user:user" };
      }
      if (callCount === 4) {
        // grep -c non-comment lines
        return { ...cmdOk, stdout: "3" };
      }
      if (callCount === 5) {
        // grep -c command= lines
        return { ...cmdOk, stdout: "1" };
      }
      // summary find for authorized_keys count
      return { ...cmdOk, stdout: "/home/user/.ssh/authorized_keys\n" };
    });
    const handler = tools.get("secrets")!.handler;
    const result = await handler({ action: "ssh_key_sprawl", search_path: "/home", check_authorized_keys: true });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("AUTHORIZED_KEYS");
  });

  it("should handle ssh_key_sprawl errors gracefully", async () => {
    vi.mocked(executeCommand).mockRejectedValue(new Error("find failed"));
    const handler = tools.get("secrets")!.handler;
    const result = await handler({ action: "ssh_key_sprawl", search_path: "/home", check_authorized_keys: false });
    expect(result.isError).toBe(true);
  });

  // ── git_history_scan: with trufflehog ──────────────────────────────────

  it("should use trufflehog when available", async () => {
    let callCount = 0;
    vi.mocked(executeCommand).mockImplementation(async () => {
      callCount++;
      if (callCount === 1) {
        // which trufflehog
        return { ...cmdOk, exitCode: 0, stdout: "/usr/bin/trufflehog" };
      }
      // trufflehog scan output (JSON lines)
      return { ...cmdOk, stdout: '{"SourceMetadata":{"file":"test.py"},"Raw":"ghp_abc123"}\n' };
    });
    const handler = tools.get("secrets")!.handler;
    const result = await handler({ action: "git_history_scan", repoPath: "/home/user/project", dryRun: false });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("trufflehog");
  });

  it("should fall back to gitleaks when trufflehog is not available", async () => {
    let callCount = 0;
    vi.mocked(executeCommand).mockImplementation(async () => {
      callCount++;
      if (callCount === 1) {
        // which trufflehog - not found
        return { ...cmdOk, exitCode: 1, stdout: "" };
      }
      if (callCount === 2) {
        // which gitleaks - found
        return { ...cmdOk, exitCode: 0, stdout: "/usr/bin/gitleaks" };
      }
      // gitleaks output
      return { ...cmdOk, stdout: "[]" };
    });
    const handler = tools.get("secrets")!.handler;
    const result = await handler({ action: "git_history_scan", repoPath: "/home/user/project", dryRun: false });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("gitleaks");
  });

  it("should handle git_history_scan execution errors", async () => {
    vi.mocked(executeCommand).mockRejectedValue(new Error("git error"));
    const handler = tools.get("secrets")!.handler;
    const result = await handler({ action: "git_history_scan", repoPath: "/home/user/project", dryRun: false });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Git history scan failed");
  });

  // ── unknown action ─────────────────────────────────────────────────────

  it("should return error for unknown action", async () => {
    const handler = tools.get("secrets")!.handler;
    const result = await handler({ action: "unknown_action" as string });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Unknown action");
  });
});
