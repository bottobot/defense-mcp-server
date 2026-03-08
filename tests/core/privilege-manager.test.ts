/**
 * Tests for src/core/privilege-manager.ts
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Mock all external dependencies ───────────────────────────────────────────

vi.mock("../../src/core/spawn-safe.js", () => ({
  execFileSafe: vi.fn(() => ""),
}));

vi.mock("../../src/core/sudo-session.js", () => ({
  SudoSession: {
    getInstance: vi.fn(() => ({
      isElevated: vi.fn(() => false),
    })),
  },
}));

vi.mock("node:fs", () => ({
  readFileSync: vi.fn(() => "CapEff:\t0000000000000000\n"),
  existsSync: vi.fn(() => false),
}));

import {
  PrivilegeManager,
  type PrivilegeStatus,
  type PrivilegeCheckResult,
} from "../../src/core/privilege-manager.js";
import { execFileSafe } from "../../src/core/spawn-safe.js";
import { readFileSync, existsSync } from "node:fs";
import { SudoSession } from "../../src/core/sudo-session.js";
import type { ToolManifest } from "../../src/core/tool-registry.js";

describe("PrivilegeManager", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Reset singleton by accessing private field
    (PrivilegeManager as any)._instance = null;
  });

  // ── Singleton ──────────────────────────────────────────────────────────────

  it("returns the same singleton on repeated calls", () => {
    const a = PrivilegeManager.instance();
    const b = PrivilegeManager.instance();
    expect(a).toBe(b);
  });

  // ── getStatus ──────────────────────────────────────────────────────────────

  it("returns a PrivilegeStatus with expected fields", async () => {
    // Mock `which sudo` → found, `sudo -n true` → fails, `id -Gn` → groups
    vi.mocked(execFileSafe).mockImplementation((cmd: string, args?: readonly string[]) => {
      if (cmd === "which" && args?.[0] === "sudo") return "/usr/bin/sudo\n";
      if (cmd === "id") return "user adm sudo\n";
      throw new Error("command failed");
    });

    const pm = PrivilegeManager.instance();
    const status = await pm.getStatus();

    expect(status).toHaveProperty("uid");
    expect(status).toHaveProperty("euid");
    expect(status).toHaveProperty("isRoot");
    expect(status).toHaveProperty("sudoAvailable");
    expect(status).toHaveProperty("passwordlessSudo");
    expect(status).toHaveProperty("sudoSessionActive");
    expect(status).toHaveProperty("capabilities");
    expect(status).toHaveProperty("groups");
    expect(status.isRoot).toBe(false);
    expect(status.groups).toContain("user");
  });

  it("caches status for repeated calls", async () => {
    vi.mocked(execFileSafe).mockImplementation((cmd: string, args?: readonly string[]) => {
      if (cmd === "which") return "/usr/bin/sudo\n";
      if (cmd === "id") return "user\n";
      throw new Error("fail");
    });

    const pm = PrivilegeManager.instance();
    const s1 = await pm.getStatus();
    const s2 = await pm.getStatus();
    expect(s1).toBe(s2); // same object reference = cached
  });

  it("refreshes cache after clearCache()", async () => {
    vi.mocked(execFileSafe).mockImplementation((cmd: string, args?: readonly string[]) => {
      if (cmd === "which") return "/usr/bin/sudo\n";
      if (cmd === "id") return "user\n";
      throw new Error("fail");
    });

    const pm = PrivilegeManager.instance();
    const s1 = await pm.getStatus();
    pm.clearCache();
    const s2 = await pm.getStatus();
    expect(s1).not.toBe(s2); // different objects = cache was cleared
  });

  // ── checkForTool ───────────────────────────────────────────────────────────

  it("returns satisfied for sudo: 'never' tools", async () => {
    const pm = PrivilegeManager.instance();
    const manifest: ToolManifest = {
      toolName: "test_tool",
      requiredBinaries: [],
      sudo: "never",
    };

    const result = await pm.checkForTool(manifest);
    expect(result.satisfied).toBe(true);
    expect(result.issues).toHaveLength(0);
  });

  it("returns issues for sudo: 'always' when no session or root", async () => {
    vi.mocked(execFileSafe).mockImplementation((cmd: string, args?: readonly string[]) => {
      if (cmd === "which" && args?.[0] === "sudo") return "/usr/bin/sudo\n";
      if (cmd === "id") return "user\n";
      throw new Error("fail");
    });

    const pm = PrivilegeManager.instance();
    const manifest: ToolManifest = {
      toolName: "log_auditd",
      requiredBinaries: [],
      sudo: "always",
      sudoReason: "Auditd requires root for rule management",
    };

    const result = await pm.checkForTool(manifest);
    expect(result.satisfied).toBe(false);
    expect(result.issues.length).toBeGreaterThan(0);
    expect(result.issues[0].type).toBe("sudo-required");
    expect(result.recommendations.length).toBeGreaterThan(0);
  });

  it("returns sudo-unavailable when sudo binary is missing", async () => {
    // sudo not found
    vi.mocked(execFileSafe).mockImplementation((cmd: string) => {
      if (cmd === "id") return "user\n";
      throw new Error("not found");
    });

    const pm = PrivilegeManager.instance();
    const manifest: ToolManifest = {
      toolName: "test_tool",
      requiredBinaries: [],
      sudo: "always",
    };

    const result = await pm.checkForTool(manifest);
    expect(result.satisfied).toBe(false);
    expect(result.issues[0].type).toBe("sudo-unavailable");
  });

  it("returns recommendations for sudo: 'conditional' tools", async () => {
    vi.mocked(execFileSafe).mockImplementation((cmd: string, args?: readonly string[]) => {
      if (cmd === "which" && args?.[0] === "sudo") return "/usr/bin/sudo\n";
      if (cmd === "id") return "user\n";
      throw new Error("fail");
    });

    const pm = PrivilegeManager.instance();
    const manifest: ToolManifest = {
      toolName: "firewall_iptables",
      requiredBinaries: [],
      sudo: "conditional",
    };

    const result = await pm.checkForTool(manifest);
    // conditional tools don't block but add recommendations
    expect(result.satisfied).toBe(true);
    expect(result.recommendations.length).toBeGreaterThan(0);
  });

  // ── Capability checking ────────────────────────────────────────────────────

  it("parses capabilities from /proc/self/status", async () => {
    // CapEff with CAP_NET_RAW (bit 13) set = 0x0000000000002000
    vi.mocked(readFileSync).mockReturnValue(
      "Name:\tnode\nCapEff:\t0000000000002000\n",
    );

    const pm = PrivilegeManager.instance();
    const caps = await pm.getCurrentCapabilities();
    expect(caps.has("CAP_NET_RAW")).toBe(true);
    expect(caps.has("CAP_SYS_ADMIN")).toBe(false);
  });

  it("returns empty set when /proc/self/status is unavailable", async () => {
    vi.mocked(readFileSync).mockImplementation(() => {
      throw new Error("ENOENT");
    });

    const pm = PrivilegeManager.instance();
    const caps = await pm.getCurrentCapabilities();
    expect(caps.size).toBe(0);
  });

  it("detects capability-missing for tools requiring specific caps", async () => {
    vi.mocked(readFileSync).mockReturnValue("CapEff:\t0000000000000000\n");
    vi.mocked(execFileSafe).mockImplementation((cmd: string, args?: readonly string[]) => {
      if (cmd === "which" && args?.[0] === "sudo") return "/usr/bin/sudo\n";
      if (cmd === "id") return "user\n";
      throw new Error("fail");
    });

    const pm = PrivilegeManager.instance();
    const manifest: ToolManifest = {
      toolName: "netdef_capture",
      requiredBinaries: [],
      sudo: "always",
      capabilities: ["CAP_NET_RAW"],
    };

    const result = await pm.checkForTool(manifest);
    const capIssues = result.issues.filter((i) => i.type === "capability-missing");
    expect(capIssues.length).toBeGreaterThan(0);
    expect(capIssues[0].description).toContain("CAP_NET_RAW");
  });

  // ── hasCapability ──────────────────────────────────────────────────────────

  it("returns true when capability is present", async () => {
    // All caps set = full root
    vi.mocked(readFileSync).mockReturnValue("CapEff:\t000001ffffffffff\n");

    const pm = PrivilegeManager.instance();
    expect(await pm.hasCapability("CAP_SYS_ADMIN")).toBe(true);
    expect(await pm.hasCapability("CAP_NET_RAW")).toBe(true);
  });

  it("returns false when capability is absent", async () => {
    vi.mocked(readFileSync).mockReturnValue("CapEff:\t0000000000000000\n");

    const pm = PrivilegeManager.instance();
    expect(await pm.hasCapability("CAP_SYS_ADMIN")).toBe(false);
  });

  // ── testPasswordlessSudo ───────────────────────────────────────────────────

  it("detects passwordless sudo when sudo -n true succeeds", async () => {
    vi.mocked(execFileSafe).mockImplementation((cmd: string, args?: readonly string[]) => {
      if (cmd === "sudo" && args?.[0] === "-n") return "";
      return "";
    });

    const pm = PrivilegeManager.instance();
    expect(await pm.testPasswordlessSudo()).toBe(true);
  });

  it("returns false when sudo -n true fails", async () => {
    vi.mocked(execFileSafe).mockImplementation((cmd: string, args?: readonly string[]) => {
      if (cmd === "sudo") throw new Error("password required");
      return "";
    });

    const pm = PrivilegeManager.instance();
    expect(await pm.testPasswordlessSudo()).toBe(false);
  });
});
