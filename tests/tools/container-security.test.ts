/**
 * Tests for src/tools/container-security.ts
 *
 * Covers: TOOL-011 (seccomp profile path restriction),
 * secure-fs usage, dry_run defaults, and schema validation.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Mock all external dependencies ─────────────────────────────────────────

vi.mock("../../src/core/executor.js", () => ({
  executeCommand: vi.fn().mockResolvedValue({ exitCode: 0, stdout: "", stderr: "" }),
}));
vi.mock("../../src/core/config.js", () => ({
  getConfig: vi.fn().mockReturnValue({ dryRun: true }),
  getToolTimeout: vi.fn().mockReturnValue(30000),
}));
vi.mock("../../src/core/parsers.js", () => ({
  createTextContent: vi.fn((text: string) => ({ type: "text", text })),
  createErrorContent: vi.fn((text: string) => ({ type: "text", text: `Error: ${text}` })),
  formatToolOutput: vi.fn((obj: unknown) => ({ type: "text", text: JSON.stringify(obj) })),
  parseJsonSafe: vi.fn((s: string) => { try { return JSON.parse(s); } catch { return null; } }),
}));
vi.mock("../../src/core/changelog.js", () => ({
  logChange: vi.fn(),
  createChangeEntry: vi.fn().mockReturnValue({}),
  backupFile: vi.fn().mockReturnValue("/tmp/backup"),
}));
vi.mock("../../src/core/sanitizer.js", () => ({
  sanitizeArgs: vi.fn((a: string[]) => a),
}));
vi.mock("../../src/core/safeguards.js", () => ({
  SafeguardRegistry: {
    getInstance: vi.fn().mockReturnValue({
      checkSafety: vi.fn().mockResolvedValue({ safe: true, warnings: [], blockers: [], impactedApps: [] }),
    }),
  },
}));

const { mockSecureWriteFileSync } = vi.hoisted(() => ({
  mockSecureWriteFileSync: vi.fn(),
}));
vi.mock("../../src/core/secure-fs.js", () => ({
  secureWriteFileSync: mockSecureWriteFileSync,
}));

vi.mock("node:fs", () => ({
  existsSync: vi.fn().mockReturnValue(false),
  mkdirSync: vi.fn(),
}));

import { registerContainerSecurityTools, DESKTOP_BREAKING_PROFILES } from "../../src/tools/container-security.js";

// ── Helper ─────────────────────────────────────────────────────────────────

type ToolHandler = (params: Record<string, unknown>) => Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }>;

function createMockServer() {
  const tools = new Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>();
  const server = {
    tool: vi.fn((name: string, _desc: string, schema: Record<string, unknown>, handler: ToolHandler) => {
      tools.set(name, { schema, handler });
    }),
  };
  return { server: server as unknown as Parameters<typeof registerContainerSecurityTools>[0], tools };
}

describe("container-security tools", () => {
  let tools: Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>;

  beforeEach(() => {
    vi.clearAllMocks();
    const mock = createMockServer();
    registerContainerSecurityTools(mock.server);
    tools = mock.tools;
  });

  // ── Registration ──────────────────────────────────────────────────────

  it("should register 2 container security tools", () => {
    expect(tools.has("container_docker")).toBe(true);
    expect(tools.has("container_isolation")).toBe(true);
    expect(tools.size).toBe(2);
  });

  // ── TOOL-011: Seccomp profile path restriction ───────────────────────

  it("should restrict seccomp profile output to safe directory (TOOL-011)", async () => {
    const handler = tools.get("container_isolation")!.handler;
    const result = await handler({
      action: "seccomp_profile",
      allowedSyscalls: ["read", "write", "exit"],
      defaultAction: "SCMP_ACT_ERRNO",
      outputPath: "/etc/evil/profile.json",
      dryRun: false,
    });
    // Should succeed but redirect to safe directory
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("restricted to safe directory");
  });

  it("should use secureWriteFileSync for seccomp profile writing (TOOL-011)", async () => {
    const handler = tools.get("container_isolation")!.handler;
    await handler({
      action: "seccomp_profile",
      allowedSyscalls: ["read", "write"],
      defaultAction: "SCMP_ACT_ERRNO",
      outputPath: "/tmp/defense-mcp/seccomp/test.json",
      dryRun: false,
    });
    // secureWriteFileSync should have been called
    expect(mockSecureWriteFileSync).toHaveBeenCalled();
  });

  it("should produce dry-run output for seccomp profile when dryRun is true", async () => {
    const handler = tools.get("container_isolation")!.handler;
    const result = await handler({
      action: "seccomp_profile",
      allowedSyscalls: ["read", "write", "exit"],
      defaultAction: "SCMP_ACT_ERRNO",
      dryRun: true,
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("dryRun");
    // secureWriteFileSync should NOT have been called in dry-run
    expect(mockSecureWriteFileSync).not.toHaveBeenCalled();
  });

  // ── Required params ──────────────────────────────────────────────────

  it("should require allowedSyscalls for seccomp_profile", async () => {
    const handler = tools.get("container_isolation")!.handler;
    const result = await handler({
      action: "seccomp_profile",
      defaultAction: "SCMP_ACT_ERRNO",
      dryRun: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("allowedSyscalls");
  });

  it("should require username for rootless_setup action", async () => {
    const handler = tools.get("container_isolation")!.handler;
    const result = await handler({
      action: "rootless_setup",
      dryRun: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("username");
  });

  // ── AppArmor ─────────────────────────────────────────────────────────

  it("should require profile name for apparmor_enforce action", async () => {
    const handler = tools.get("container_isolation")!.handler;
    const result = await handler({ action: "apparmor_enforce" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("profile name is required");
  });

  it("should require profileName for apparmor_apply_container action", async () => {
    const handler = tools.get("container_isolation")!.handler;
    const result = await handler({ action: "apparmor_apply_container" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("profileName");
  });

  // ── Docker daemon ────────────────────────────────────────────────────

  it("should require daemon_action for docker daemon", async () => {
    const handler = tools.get("container_docker")!.handler;
    const result = await handler({ action: "daemon" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("daemon_action");
  });

  // ── image_scan ───────────────────────────────────────────────────────

  it("should require image for image_scan action", async () => {
    const handler = tools.get("container_docker")!.handler;
    const result = await handler({ action: "image_scan" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("image is required");
  });

  // ── DESKTOP_BREAKING_PROFILES ────────────────────────────────────────

  it("should have DESKTOP_BREAKING_PROFILES set with known dangerous profiles", () => {
    expect(DESKTOP_BREAKING_PROFILES).toBeDefined();
    expect(DESKTOP_BREAKING_PROFILES.has("flatpak")).toBe(true);
    expect(DESKTOP_BREAKING_PROFILES.has("chromium")).toBe(true);
    expect(DESKTOP_BREAKING_PROFILES.has("unprivileged_userns")).toBe(true);
    expect(DESKTOP_BREAKING_PROFILES.has("firefox")).toBe(true);
    expect(DESKTOP_BREAKING_PROFILES.has("code")).toBe(true);
  });

  // ── AppArmor Install Safety ──────────────────────────────────────────

  it("apparmor_install dry-run should warn about desktop-breaking profiles", async () => {
    const handler = tools.get("container_isolation")!.handler;
    const result = await handler({ action: "apparmor_install", dry_run: true });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("COMPLAIN mode");
    expect(result.content[0].text).toContain("desktop applications");
  });

  // ── AppArmor Enforce Safety ──────────────────────────────────────────

  it("apparmor_enforce dry-run should warn when enforcing desktop-breaking profile", async () => {
    const handler = tools.get("container_isolation")!.handler;
    const result = await handler({ action: "apparmor_enforce", profile: "flatpak", dry_run: true });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("WARNING");
    expect(result.content[0].text).toContain("desktop applications");
  });

  it("apparmor_enforce dry-run should NOT warn for non-desktop profiles", async () => {
    const handler = tools.get("container_isolation")!.handler;
    const result = await handler({ action: "apparmor_enforce", profile: "my_custom_profile", dry_run: true });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).not.toContain("WARNING");
    expect(result.content[0].text).not.toContain("desktop applications");
  });

  it("apparmor_enforce dry-run should warn for profile path containing desktop profile name", async () => {
    const handler = tools.get("container_isolation")!.handler;
    const result = await handler({ action: "apparmor_enforce", profile: "/etc/apparmor.d/chromium", dry_run: true });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("WARNING");
  });

  it("apparmor_complain should provide rollback command to enforce", async () => {
    const { executeCommand } = await import("../../src/core/executor.js");
    vi.mocked(executeCommand).mockResolvedValueOnce({ exitCode: 0, stdout: "Setting profile to complain mode", stderr: "" });
    const { createChangeEntry } = await import("../../src/core/changelog.js");
    const handler = tools.get("container_isolation")!.handler;
    await handler({ action: "apparmor_complain", profile: "test_profile", dry_run: false });
    // Should NOT have a rollback command for complain (it's safe)
    expect(vi.mocked(createChangeEntry)).toHaveBeenCalled();
  });

  // ══════════════════════════════════════════════════════════════════════
  // container_docker — audit action
  // ══════════════════════════════════════════════════════════════════════

  describe("container_docker / audit", () => {
    it("should return early when docker is not installed", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "not found" });
      const handler = tools.get("container_docker")!.handler;
      const result = await handler({ action: "audit", check_type: "all" });
      expect(result.content[0].text).toContain("Docker is not installed");
    });

    it("should audit daemon configuration and report findings", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const dockerInfo = JSON.stringify({
        ServerVersion: "24.0.7",
        Driver: "overlay2",
        LoggingDriver: "json-file",
        LiveRestoreEnabled: false,
        SecurityOptions: ["name=seccomp,profile=default"],
      });
      vi.mocked(executeCommand)
        .mockResolvedValueOnce({ exitCode: 0, stdout: "/usr/bin/docker", stderr: "" }) // which docker
        .mockResolvedValueOnce({ exitCode: 0, stdout: dockerInfo, stderr: "" }) // docker info
        .mockResolvedValueOnce({ exitCode: 0, stdout: '{"icc": true}', stderr: "" }) // cat daemon.json
        .mockResolvedValueOnce({ exitCode: 0, stdout: "srw-rw---- 1 root docker", stderr: "" }) // ls docker.sock
        .mockResolvedValueOnce({ exitCode: 0, stdout: "nginx:latest | 100MB | 2 days ago | abc123", stderr: "" }) // docker images
        .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" }) // docker ps (no containers)
        .mockResolvedValueOnce({ exitCode: 0, stdout: "bridge | bridge | local", stderr: "" }); // docker network ls
      const handler = tools.get("container_docker")!.handler;
      const result = await handler({ action: "audit", check_type: "all" });
      expect(result.content[0].text).toContain("Docker Security Audit");
      expect(result.content[0].text).toContain("Server Version: 24.0.7");
      expect(result.content[0].text).toContain("User namespaces not enabled");
      expect(result.content[0].text).toContain("Live restore is not enabled");
    });

    it("should detect world-writable docker socket", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand)
        .mockResolvedValueOnce({ exitCode: 0, stdout: "/usr/bin/docker", stderr: "" })
        .mockResolvedValueOnce({ exitCode: 0, stdout: "{}", stderr: "" }) // docker info
        .mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "no such file" }) // no daemon.json
        .mockResolvedValueOnce({ exitCode: 0, stdout: "srw-rw-rw- 1 root docker", stderr: "" }); // world-writable
      const handler = tools.get("container_docker")!.handler;
      const result = await handler({ action: "audit", check_type: "daemon" });
      expect(result.content[0].text).toContain("Docker socket is world-writable");
    });

    it("should detect images using latest tag", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand)
        .mockResolvedValueOnce({ exitCode: 0, stdout: "/usr/bin/docker", stderr: "" })
        .mockResolvedValueOnce({ exitCode: 0, stdout: "nginx:latest | 100MB | 2 days ago | abc123\nalpine:3.18 | 5MB | 1 week | def456", stderr: "" });
      const handler = tools.get("container_docker")!.handler;
      const result = await handler({ action: "audit", check_type: "images" });
      expect(result.content[0].text).toContain("Total images: 2");
      expect(result.content[0].text).toContain("using 'latest' tag");
    });

    it("should detect privileged containers and docker socket mounts", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand)
        .mockResolvedValueOnce({ exitCode: 0, stdout: "/usr/bin/docker", stderr: "" })
        .mockResolvedValueOnce({ exitCode: 0, stdout: "abc123|mycontainer|nginx:latest|Up 2 hours|80/tcp", stderr: "" }) // docker ps
        .mockResolvedValueOnce({ exitCode: 0, stdout: "true|host|host|false", stderr: "" }) // docker inspect (privileged, host net, host pid)
        .mockResolvedValueOnce({ exitCode: 0, stdout: JSON.stringify([{ Source: "/var/run/docker.sock", Destination: "/var/run/docker.sock", RW: true }]), stderr: "" }); // mounts
      const handler = tools.get("container_docker")!.handler;
      const result = await handler({ action: "audit", check_type: "containers" });
      expect(result.content[0].text).toContain("privileged mode");
      expect(result.content[0].text).toContain("host networking");
      expect(result.content[0].text).toContain("host PID namespace");
      expect(result.content[0].text).toContain("Docker socket mounted");
    });

    it("should detect root filesystem mount in containers", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand)
        .mockResolvedValueOnce({ exitCode: 0, stdout: "/usr/bin/docker", stderr: "" })
        .mockResolvedValueOnce({ exitCode: 0, stdout: "abc123|badcontainer|alpine|Up|", stderr: "" })
        .mockResolvedValueOnce({ exitCode: 0, stdout: "false|bridge||false", stderr: "" })
        .mockResolvedValueOnce({ exitCode: 0, stdout: JSON.stringify([{ Source: "/", Destination: "/host", RW: true }]), stderr: "" });
      const handler = tools.get("container_docker")!.handler;
      const result = await handler({ action: "audit", check_type: "containers" });
      expect(result.content[0].text).toContain("Root filesystem '/' mounted");
    });

    it("should handle audit errors gracefully", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockRejectedValueOnce(new Error("connection refused"));
      const handler = tools.get("container_docker")!.handler;
      const result = await handler({ action: "audit", check_type: "all" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("connection refused");
    });
  });

  // ══════════════════════════════════════════════════════════════════════
  // container_docker — bench action
  // ══════════════════════════════════════════════════════════════════════

  describe("container_docker / bench", () => {
    it("should return early when docker is not installed", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "" });
      const handler = tools.get("container_docker")!.handler;
      const result = await handler({ action: "bench" });
      expect(result.content[0].text).toContain("Docker is not installed");
    });

    it("should run docker bench and parse results", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const benchOutput = [
        "[INFO] 1 - Host Configuration",
        "[PASS] 1.1 - Ensure a separate partition for containers",
        "[WARN] 1.2 - Ensure only trusted users control Docker",
        "[NOTE] 1.3 - Some note here",
        "[INFO] 2 - Docker daemon configuration",
        "[PASS] 2.1 - Restrict network traffic",
      ].join("\n");
      vi.mocked(executeCommand)
        .mockResolvedValueOnce({ exitCode: 0, stdout: "/usr/bin/docker", stderr: "" })
        .mockResolvedValueOnce({ exitCode: 0, stdout: benchOutput, stderr: "" });
      const handler = tools.get("container_docker")!.handler;
      const result = await handler({ action: "bench", log_level: "WARN" });
      expect(result.content[0].text).toContain("Docker Bench for Security");
      expect(result.content[0].text).toContain("[PASS]: 2");
      expect(result.content[0].text).toContain("[WARN]: 1");
    });

    it("should handle bench failure with no output", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand)
        .mockResolvedValueOnce({ exitCode: 0, stdout: "/usr/bin/docker", stderr: "" })
        .mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "" });
      const handler = tools.get("container_docker")!.handler;
      const result = await handler({ action: "bench" });
      expect(result.content[0].text).toContain("Docker Bench could not run");
    });

    it("should pass check sections to bench command", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand)
        .mockResolvedValueOnce({ exitCode: 0, stdout: "/usr/bin/docker", stderr: "" })
        .mockResolvedValueOnce({ exitCode: 0, stdout: "[PASS] 1.1 - Check", stderr: "" });
      const handler = tools.get("container_docker")!.handler;
      await handler({ action: "bench", checks: "1,2" });
      expect(vi.mocked(executeCommand)).toHaveBeenCalledWith(
        expect.objectContaining({ args: expect.arrayContaining(["-c", "1,2"]) })
      );
    });
  });

  // ══════════════════════════════════════════════════════════════════════
  // container_docker — seccomp action
  // ══════════════════════════════════════════════════════════════════════

  describe("container_docker / seccomp", () => {
    it("should return error when docker is not available", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "not running" });
      const handler = tools.get("container_docker")!.handler;
      const result = await handler({ action: "seccomp" });
      expect(result.content[0].text).toContain("Docker is not available");
    });

    it("should detect unconfined seccomp containers", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand)
        .mockResolvedValueOnce({ exitCode: 0, stdout: "abc123 myapp nginx", stderr: "" })
        .mockResolvedValueOnce({ exitCode: 0, stdout: "[seccomp=unconfined]", stderr: "" });
      const handler = tools.get("container_docker")!.handler;
      const result = await handler({ action: "seccomp" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.summary.fail).toBe(1);
      expect(parsed.containers[0].status).toBe("FAIL");
      expect(parsed.containers[0].note).toContain("HIGH RISK");
    });

    it("should report containers with default seccomp", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand)
        .mockResolvedValueOnce({ exitCode: 0, stdout: "abc123 myapp nginx", stderr: "" })
        .mockResolvedValueOnce({ exitCode: 0, stdout: "[]", stderr: "" });
      const handler = tools.get("container_docker")!.handler;
      const result = await handler({ action: "seccomp" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.summary.warn).toBe(1);
      expect(parsed.containers[0].note).toContain("Docker default seccomp");
    });
  });

  // ══════════════════════════════════════════════════════════════════════
  // container_docker — daemon action
  // ══════════════════════════════════════════════════════════════════════

  describe("container_docker / daemon", () => {
    it("should audit daemon config and report missing settings", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValueOnce({ exitCode: 0, stdout: '{"live-restore": true}', stderr: "" });
      const handler = tools.get("container_docker")!.handler;
      const result = await handler({ action: "daemon", daemon_action: "audit" });
      expect(result.content[0].text).toContain("Missing");
      expect(result.content[0].text).toContain("userns-remap");
      expect(result.content[0].text).toContain("Present");
      expect(result.content[0].text).toContain("live-restore");
    });

    it("should report when no daemon.json exists during audit", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "no such file" });
      const handler = tools.get("container_docker")!.handler;
      const result = await handler({ action: "daemon", daemon_action: "audit" });
      expect(result.content[0].text).toContain("No /etc/docker/daemon.json found");
    });

    it("should require settings for daemon apply", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "" });
      const handler = tools.get("container_docker")!.handler;
      const result = await handler({ action: "daemon", daemon_action: "apply" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("settings parameter is required");
    });

    it("should dry-run apply daemon settings", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "" }); // no existing config
      const handler = tools.get("container_docker")!.handler;
      const result = await handler({
        action: "daemon",
        daemon_action: "apply",
        settings: { userns_remap: true, no_new_privileges: true, icc: false },
        dry_run: true,
      });
      expect(result.content[0].text).toContain("DRY RUN");
      expect(result.content[0].text).toContain("userns-remap");
    });

    it("should report no changes when settings are empty", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValueOnce({ exitCode: 0, stdout: '{}', stderr: "" });
      const handler = tools.get("container_docker")!.handler;
      const result = await handler({
        action: "daemon",
        daemon_action: "apply",
        settings: {},
        dry_run: true,
      });
      expect(result.content[0].text).toContain("No changes to apply");
    });
  });

  // ══════════════════════════════════════════════════════════════════════
  // container_docker — image_scan action
  // ══════════════════════════════════════════════════════════════════════

  describe("container_docker / image_scan", () => {
    it("should scan with trivy when available", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValueOnce({ exitCode: 0, stdout: '{"Results":[]}', stderr: "" });
      const handler = tools.get("container_docker")!.handler;
      const result = await handler({ action: "image_scan", image: "nginx:latest" });
      expect(result.content[0].text).toContain("Trivy scan results");
      expect(result.content[0].text).toContain("nginx:latest");
    });

    it("should fall back to grype when trivy is not available", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand)
        .mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "not found" }) // trivy fails
        .mockResolvedValueOnce({ exitCode: 0, stdout: '{"matches":[]}', stderr: "" }); // grype succeeds
      const handler = tools.get("container_docker")!.handler;
      const result = await handler({ action: "image_scan", image: "alpine:3.18" });
      expect(result.content[0].text).toContain("Grype scan results");
    });

    it("should report when neither scanner is available", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand)
        .mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "" })
        .mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "" });
      const handler = tools.get("container_docker")!.handler;
      const result = await handler({ action: "image_scan", image: "nginx:latest" });
      expect(result.content[0].text).toContain("Neither Trivy nor Grype");
    });
  });

  // ══════════════════════════════════════════════════════════════════════
  // container_docker — unknown action
  // ══════════════════════════════════════════════════════════════════════

  it("container_docker should handle unknown action", async () => {
    const handler = tools.get("container_docker")!.handler;
    const result = await handler({ action: "nonexistent" as string });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Unknown action");
  });

  // ══════════════════════════════════════════════════════════════════════
  // container_isolation — apparmor_status
  // ══════════════════════════════════════════════════════════════════════

  describe("container_isolation / apparmor_status", () => {
    it("should report AppArmor enabled when aa-enabled says Yes", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand)
        .mockResolvedValueOnce({ exitCode: 0, stdout: "Yes", stderr: "" }) // aa-enabled
        .mockResolvedValueOnce({ exitCode: 0, stdout: "Y", stderr: "" }) // kernel module
        .mockResolvedValueOnce({ exitCode: 0, stdout: "active", stderr: "" }) // systemctl
        .mockResolvedValueOnce({ exitCode: 0, stdout: "Status: install ok installed", stderr: "" }) // apparmor-profiles
        .mockResolvedValueOnce({ exitCode: 0, stdout: "Status: install ok installed", stderr: "" }) // apparmor-profiles-extra
        .mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "" }); // apparmor-utils not installed
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({ action: "apparmor_status" });
      expect(result.content[0].text).toContain("AppArmor enabled: Yes");
      expect(result.content[0].text).toContain("Kernel module: Loaded");
      expect(result.content[0].text).toContain("apparmor-profiles: Installed");
      expect(result.content[0].text).toContain("apparmor-utils: Not installed");
    });

    it("should report AppArmor disabled when not enabled", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand)
        .mockResolvedValueOnce({ exitCode: 1, stdout: "No", stderr: "" }) // aa-enabled
        .mockResolvedValueOnce({ exitCode: 0, stdout: "N", stderr: "" }) // kernel module not loaded
        .mockResolvedValueOnce({ exitCode: 1, stdout: "inactive", stderr: "" }) // systemctl
        .mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "" })
        .mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "" })
        .mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "" });
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({ action: "apparmor_status" });
      expect(result.content[0].text).toContain("AppArmor enabled: No");
    });
  });

  // ══════════════════════════════════════════════════════════════════════
  // container_isolation — apparmor_list
  // ══════════════════════════════════════════════════════════════════════

  describe("container_isolation / apparmor_list", () => {
    it("should parse and display profiles by mode", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const aaOutput = [
        "37 profiles are loaded.",
        "35 profiles are in enforce mode.",
        "   /usr/sbin/nginx",
        "   /usr/bin/man",
        "2 profiles are in complain mode.",
        "   /usr/sbin/tcpdump",
        "0 processes have profiles defined.",
      ].join("\n");
      vi.mocked(executeCommand).mockResolvedValueOnce({ exitCode: 0, stdout: aaOutput, stderr: "" });
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({ action: "apparmor_list" });
      expect(result.content[0].text).toContain("Enforce Mode");
      expect(result.content[0].text).toContain("/usr/sbin/nginx");
      expect(result.content[0].text).toContain("Complain Mode");
      expect(result.content[0].text).toContain("/usr/sbin/tcpdump");
    });

    it("should fall back to apparmor_status when aa-status fails", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand)
        .mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "not found" }) // aa-status fails
        .mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "also not found" }); // apparmor_status fails
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({ action: "apparmor_list" });
      expect(result.content[0].text).toContain("Cannot list AppArmor profiles");
    });
  });

  // ══════════════════════════════════════════════════════════════════════
  // container_isolation — apparmor_disable
  // ══════════════════════════════════════════════════════════════════════

  describe("container_isolation / apparmor_disable", () => {
    it("should require profile name", async () => {
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({ action: "apparmor_disable" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("profile name is required");
    });

    it("should disable a profile and log change with rollback", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const { createChangeEntry } = await import("../../src/core/changelog.js");
      vi.mocked(executeCommand).mockResolvedValueOnce({ exitCode: 0, stdout: "Disabled profile", stderr: "" });
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({ action: "apparmor_disable", profile: "test_profile", dry_run: false });
      expect(result.content[0].text).toContain("disable mode");
      expect(vi.mocked(createChangeEntry)).toHaveBeenCalledWith(
        expect.objectContaining({ rollbackCommand: "sudo aa-enforce test_profile" })
      );
    });

    it("should return error when disable command fails", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "permission denied" });
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({ action: "apparmor_disable", profile: "test_profile", dry_run: false });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("permission denied");
    });
  });

  // ══════════════════════════════════════════════════════════════════════
  // container_isolation — apparmor_install (live)
  // ══════════════════════════════════════════════════════════════════════

  describe("container_isolation / apparmor_install live", () => {
    it("should install packages and set desktop profiles to complain", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand)
        .mockResolvedValueOnce({ exitCode: 0, stdout: "installed", stderr: "" }) // apt-get install
        // For each DESKTOP_BREAKING_PROFILES entry that exists: test -f, then aa-complain
        .mockImplementation(async (opts: { command: string; args: string[] }) => {
          if (opts.command === "test") return { exitCode: 0, stdout: "", stderr: "" };
          if (opts.command === "sudo" && opts.args[0] === "aa-complain") return { exitCode: 0, stdout: "Set complain", stderr: "" };
          return { exitCode: 0, stdout: "", stderr: "" };
        });
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({ action: "apparmor_install", dry_run: false });
      expect(result.content[0].text).toContain("Successfully installed");
      expect(result.content[0].text).toContain("complain mode");
    });

    it("should return error when install fails", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "E: Unable to locate package" });
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({ action: "apparmor_install", dry_run: false });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Failed to install");
    });
  });

  // ══════════════════════════════════════════════════════════════════════
  // container_isolation — apparmor_apply_container
  // ══════════════════════════════════════════════════════════════════════

  describe("container_isolation / apparmor_apply_container", () => {
    it("should generate and apply a profile in live mode", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValueOnce({ exitCode: 0, stdout: "Profile loaded", stderr: "" });
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({
        action: "apparmor_apply_container",
        profileName: "my_nginx",
        containerName: "web",
        allowNetwork: true,
        allowWrite: ["/var/log/nginx"],
        dry_run: false,
        dryRun: false,
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.success).toBe(true);
      expect(mockSecureWriteFileSync).toHaveBeenCalledWith(
        "/etc/apparmor.d/my_nginx",
        expect.stringContaining("network,"),
        "utf-8"
      );
    });

    it("should generate a deny-network profile when allowNetwork is false", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValueOnce({ exitCode: 0, stdout: "loaded", stderr: "" });
      const handler = tools.get("container_isolation")!.handler;
      await handler({
        action: "apparmor_apply_container",
        profileName: "isolated_app",
        allowNetwork: false,
        dry_run: false,
        dryRun: false,
      });
      expect(mockSecureWriteFileSync).toHaveBeenCalledWith(
        "/etc/apparmor.d/isolated_app",
        expect.stringContaining("deny network,"),
        "utf-8"
      );
    });

    it("should produce dry-run output with profile content", async () => {
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({
        action: "apparmor_apply_container",
        profileName: "test_profile",
        dry_run: true,
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.dryRun).toBe(true);
      expect(parsed.profileName).toBe("test_profile");
      expect(parsed.profile).toContain("profile test_profile");
    });
  });

  // ══════════════════════════════════════════════════════════════════════
  // container_isolation — selinux_status
  // ══════════════════════════════════════════════════════════════════════

  describe("container_isolation / selinux_status", () => {
    it("should display sestatus output", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValueOnce({
        exitCode: 0,
        stdout: "SELinux status:                 enabled\nCurrent mode:                   enforcing",
        stderr: "",
      });
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({ action: "selinux_status" });
      expect(result.content[0].text).toContain("SELinux status:");
      expect(result.content[0].text).toContain("enforcing");
    });

    it("should warn when SELinux is not installed", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "sestatus: command not found" });
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({ action: "selinux_status" });
      expect(result.content[0].text).toContain("SELinux may not be installed");
    });
  });

  // ══════════════════════════════════════════════════════════════════════
  // container_isolation — selinux_getenforce
  // ══════════════════════════════════════════════════════════════════════

  describe("container_isolation / selinux_getenforce", () => {
    it("should display current SELinux mode", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValueOnce({ exitCode: 0, stdout: "Enforcing", stderr: "" });
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({ action: "selinux_getenforce" });
      expect(result.content[0].text).toContain("Current SELinux mode: Enforcing");
    });

    it("should warn when getenforce is not available", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "" });
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({ action: "selinux_getenforce" });
      expect(result.content[0].text).toContain("getenforce not available");
    });
  });

  // ══════════════════════════════════════════════════════════════════════
  // container_isolation — selinux_setenforce
  // ══════════════════════════════════════════════════════════════════════

  describe("container_isolation / selinux_setenforce", () => {
    it("should require mode parameter", async () => {
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({ action: "selinux_setenforce" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("mode is required");
    });

    it("should warn that disabled cannot be set at runtime", async () => {
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({ action: "selinux_setenforce", mode: "disabled" });
      expect(result.content[0].text).toContain("Cannot disable SELinux at runtime");
    });

    it("should dry-run setenforce", async () => {
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({ action: "selinux_setenforce", mode: "enforcing", dry_run: true });
      expect(result.content[0].text).toContain("DRY RUN");
      expect(result.content[0].text).toContain("enforcing");
    });

    it("should set SELinux to permissive in live mode", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" });
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({ action: "selinux_setenforce", mode: "permissive", dry_run: false });
      expect(result.content[0].text).toContain("SELinux mode set to permissive");
      expect(vi.mocked(executeCommand)).toHaveBeenCalledWith(
        expect.objectContaining({ args: ["setenforce", "0"] })
      );
    });

    it("should return error when setenforce fails", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "Permission denied" });
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({ action: "selinux_setenforce", mode: "enforcing", dry_run: false });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Permission denied");
    });
  });

  // ══════════════════════════════════════════════════════════════════════
  // container_isolation — selinux_booleans
  // ══════════════════════════════════════════════════════════════════════

  describe("container_isolation / selinux_booleans", () => {
    it("should list all booleans when no name given", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValueOnce({ exitCode: 0, stdout: "httpd_can_network_connect --> on\ncontainer_connect_any --> off", stderr: "" });
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({ action: "selinux_booleans" });
      expect(result.content[0].text).toContain("httpd_can_network_connect");
    });

    it("should get a specific boolean value", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValueOnce({ exitCode: 0, stdout: "httpd_can_network_connect --> on", stderr: "" });
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({ action: "selinux_booleans", boolean_name: "httpd_can_network_connect" });
      expect(result.content[0].text).toContain("httpd_can_network_connect --> on");
    });

    it("should set a boolean in dry-run mode", async () => {
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({ action: "selinux_booleans", boolean_name: "httpd_can_network_connect", boolean_value: "off", dry_run: true });
      expect(result.content[0].text).toContain("DRY RUN");
      expect(result.content[0].text).toContain("httpd_can_network_connect");
    });

    it("should set a boolean in live mode", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" });
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({ action: "selinux_booleans", boolean_name: "httpd_can_network_connect", boolean_value: "on", dry_run: false });
      expect(result.content[0].text).toContain("set to on");
    });

    it("should return error when setting boolean fails", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "Could not change" });
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({ action: "selinux_booleans", boolean_name: "invalid_bool", boolean_value: "on", dry_run: false });
      expect(result.isError).toBe(true);
    });
  });

  // ══════════════════════════════════════════════════════════════════════
  // container_isolation — selinux_audit
  // ══════════════════════════════════════════════════════════════════════

  describe("container_isolation / selinux_audit", () => {
    it("should report no recent denials", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "<no matches>" });
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({ action: "selinux_audit" });
      expect(result.content[0].text).toContain("No recent SELinux AVC denials");
    });

    it("should display recent AVC denials", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValueOnce({
        exitCode: 0,
        stdout: "type=AVC msg=audit(1234): avc: denied { read } for comm=\"httpd\"",
        stderr: "",
      });
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({ action: "selinux_audit" });
      expect(result.content[0].text).toContain("Recent SELinux AVC Denials");
      expect(result.content[0].text).toContain("httpd");
    });

    it("should warn when audit logs cannot be searched", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "permission denied" });
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({ action: "selinux_audit" });
      expect(result.content[0].text).toContain("Could not search audit logs");
    });
  });

  // ══════════════════════════════════════════════════════════════════════
  // container_isolation — namespace_check
  // ══════════════════════════════════════════════════════════════════════

  describe("container_isolation / namespace_check", () => {
    it("should inspect namespaces for a specific PID", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValueOnce({
        exitCode: 0,
        stdout: "lrwxrwxrwx 1 root root 0 user -> user:[4026531837]\nlrwxrwxrwx 1 root root 0 net -> net:[4026531840]",
        stderr: "",
      });
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({ action: "namespace_check", pid: 1234 });
      expect(result.content[0].text).toContain("Process PID: 1234");
      expect(result.content[0].text).toContain("Namespace symlinks");
    });

    it("should return error for invalid PID", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "No such file or directory" });
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({ action: "namespace_check", pid: 999999 });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Cannot read namespaces");
    });

    it("should check user namespaces when check_type is user", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValueOnce({ exitCode: 0, stdout: "28633", stderr: "" });
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({ action: "namespace_check", check_type: "user" });
      expect(result.content[0].text).toContain("User Namespaces");
      expect(result.content[0].text).toContain("max_user_namespaces: 28633");
      expect(result.content[0].text).toContain("User namespaces are enabled");
    });

    it("should warn when user namespaces are disabled", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValueOnce({ exitCode: 0, stdout: "0", stderr: "" });
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({ action: "namespace_check", check_type: "user" });
      expect(result.content[0].text).toContain("User namespaces are disabled");
    });

    it("should check network namespaces", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValueOnce({ exitCode: 0, stdout: "ns1 (id: 0)\nns2 (id: 1)", stderr: "" });
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({ action: "namespace_check", check_type: "network" });
      expect(result.content[0].text).toContain("Network Namespaces");
      expect(result.content[0].text).toContain("Named network namespaces: 2");
    });

    it("should check mount namespaces", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand).mockResolvedValueOnce({ exitCode: 0, stdout: "line1\nline2\nline3", stderr: "" });
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({ action: "namespace_check", check_type: "mount" });
      expect(result.content[0].text).toContain("Mount Namespace Info");
      expect(result.content[0].text).toContain("3 mount points");
    });
  });

  // ══════════════════════════════════════════════════════════════════════
  // container_isolation — rootless_setup
  // ══════════════════════════════════════════════════════════════════════

  describe("container_isolation / rootless_setup", () => {
    it("should dry-run rootless setup and show current state", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand)
        .mockResolvedValueOnce({ exitCode: 0, stdout: "/usr/bin/newuidmap", stderr: "" }) // which newuidmap
        .mockResolvedValueOnce({ exitCode: 0, stdout: "/usr/bin/newgidmap", stderr: "" }) // which newgidmap
        .mockResolvedValueOnce({ exitCode: 0, stdout: "1", stderr: "" }) // sysctl userns
        .mockResolvedValueOnce({ exitCode: 0, stdout: "testuser:100000:65536", stderr: "" }); // grep subuid
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({ action: "rootless_setup", username: "testuser", dryRun: true });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.dryRun).toBe(true);
      expect(parsed.username).toBe("testuser");
      expect(parsed.currentState.newuidmap).toBe(true);
      expect(parsed.currentState.subuidConfigured).toBe(true);
    });

    it("should configure subuid and enable user namespaces in live mode", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      vi.mocked(executeCommand)
        .mockResolvedValueOnce({ exitCode: 0, stdout: "/usr/bin/newuidmap", stderr: "" })
        .mockResolvedValueOnce({ exitCode: 0, stdout: "/usr/bin/newgidmap", stderr: "" })
        .mockResolvedValueOnce({ exitCode: 1, stdout: "0", stderr: "" }) // userns not enabled
        .mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "" }) // subuid not configured
        .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "" }) // usermod
        .mockResolvedValueOnce({ exitCode: 0, stdout: "kernel.unprivileged_userns_clone = 1", stderr: "" }); // sysctl -w
      const handler = tools.get("container_isolation")!.handler;
      const result = await handler({ action: "rootless_setup", username: "newuser", dryRun: false });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.results).toHaveLength(2);
      expect(parsed.results[0].step).toContain("subuid");
      expect(parsed.results[1].step).toContain("user namespaces");
    });
  });

  // ══════════════════════════════════════════════════════════════════════
  // container_isolation — unknown action
  // ══════════════════════════════════════════════════════════════════════

  it("container_isolation should handle unknown action", async () => {
    const handler = tools.get("container_isolation")!.handler;
    const result = await handler({ action: "nonexistent" as string });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Unknown action");
  });
});
