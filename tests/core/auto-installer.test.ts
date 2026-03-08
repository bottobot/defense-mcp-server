/**
 * Tests for src/core/auto-installer.ts
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Mock all external dependencies ───────────────────────────────────────────

vi.mock("../../src/core/spawn-safe.js", () => ({
  execFileSafe: vi.fn(() => ""),
}));

vi.mock("../../src/core/config.js", () => ({
  getConfig: vi.fn(() => ({
    autoInstall: false,
    dryRun: false,
    backupDir: "/tmp/backups",
    logLevel: "info",
  })),
}));

vi.mock("../../src/core/distro.js", () => ({
  detectDistro: vi.fn(async () => ({
    id: "kali",
    name: "Kali GNU/Linux",
    version: "2024.1",
    osFamily: "linux",
    specificDistro: "kali",
    family: "debian",
    packageManager: "apt",
    initSystem: "systemd",
    hasFirewalld: false,
    hasUfw: true,
    hasSelinux: false,
    hasApparmor: true,
  })),
}));

vi.mock("../../src/core/installer.js", () => ({
  DEFENSIVE_TOOLS: [
    {
      binary: "iptables",
      packages: { debian: "iptables", rhel: "iptables", fallback: "iptables" },
    },
    {
      binary: "nft",
      packages: { debian: "nftables", rhel: "nftables", fallback: "nftables" },
    },
  ],
}));

vi.mock("../../src/core/sudo-session.js", () => ({
  SudoSession: {
    getInstance: vi.fn(() => ({
      getPassword: vi.fn(() => null),
      isElevated: vi.fn(() => false),
    })),
  },
}));

vi.mock("../../src/core/command-allowlist.js", () => ({
  resolveCommand: vi.fn((cmd: string) => `/usr/bin/${cmd}`),
}));

vi.mock("../../src/core/changelog.js", () => ({
  logChange: vi.fn(),
  createChangeEntry: vi.fn(() => ({})),
}));

import { AutoInstaller, validatePackageName } from "../../src/core/auto-installer.js";
import { getConfig } from "../../src/core/config.js";
import { execFileSafe } from "../../src/core/spawn-safe.js";
import type { ToolManifest } from "../../src/core/tool-registry.js";

describe("AutoInstaller", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    // Re-apply default mock so getConfig returns autoInstall: false
    vi.mocked(getConfig).mockReturnValue({
      autoInstall: false,
      dryRun: false,
      backupDir: "/tmp/backups",
      logLevel: "info",
    } as any);
    AutoInstaller.resetInstance();
  });

  // ── Singleton ──────────────────────────────────────────────────────────────

  it("returns the same singleton instance on repeated calls", () => {
    const a = AutoInstaller.instance();
    const b = AutoInstaller.instance();
    expect(a).toBe(b);
  });

  it("creates a new instance after resetInstance()", () => {
    const a = AutoInstaller.instance();
    AutoInstaller.resetInstance();
    const b = AutoInstaller.instance();
    expect(a).not.toBe(b);
  });

  // ── isEnabled ──────────────────────────────────────────────────────────────

  it("reports disabled when config.autoInstall is false", () => {
    const installer = AutoInstaller.instance();
    expect(installer.isEnabled()).toBe(false);
  });

  it("reports enabled when config.autoInstall is true", () => {
    vi.mocked(getConfig).mockReturnValue({
      autoInstall: true,
      dryRun: false,
      backupDir: "/tmp/backups",
      logLevel: "info",
    } as any);

    AutoInstaller.resetInstance();
    const installer = AutoInstaller.instance();
    expect(installer.isEnabled()).toBe(true);
  });

  // ── resolveAll — disabled mode ─────────────────────────────────────────────

  it("skips all dependencies when auto-install is disabled", async () => {
    const installer = AutoInstaller.instance();
    const manifest: ToolManifest = {
      toolName: "test_tool",
      requiredBinaries: ["iptables"],
      sudo: "never",
    };

    const result = await installer.resolveAll(manifest, ["iptables"], ["yara-python"], ["cdxgen"]);

    expect(result.allResolved).toBe(false);
    expect(result.attempted).toHaveLength(3);
    for (const a of result.attempted) {
      expect(a.method).toBe("skipped");
      expect(a.success).toBe(false);
      expect(a.message).toContain("Auto-install is disabled");
    }
  });

  // ── resolveAll — enabled mode ──────────────────────────────────────────────

  it("attempts binary installation when enabled", async () => {
    vi.mocked(getConfig).mockReturnValue({ autoInstall: true } as any);
    AutoInstaller.resetInstance();
    const installer = AutoInstaller.instance();

    // Mock: 'which' for binaryAvailable check -> first call fails (install), second succeeds (verify)
    const execMock = vi.mocked(execFileSafe);
    // The installBinary flow calls execFileSafe multiple times
    // We let them all succeed by default (the mock returns "")
    
    const manifest: ToolManifest = {
      toolName: "test_tool",
      requiredBinaries: ["iptables"],
      sudo: "never",
    };

    const result = await installer.resolveAll(manifest, ["iptables"]);
    expect(result.attempted).toHaveLength(1);
    expect(result.attempted[0].dependency).toBe("iptables");
    expect(result.attempted[0].type).toBe("binary");
  });

  // ── Package allowlist enforcement (CORE-008) ───────────────────────────────

  it("rejects pip packages not in ALLOWED_PIP_PACKAGES", async () => {
    vi.mocked(getConfig).mockReturnValue({ autoInstall: true } as any);
    AutoInstaller.resetInstance();
    const installer = AutoInstaller.instance();

    // Mock pip3 availability
    vi.mocked(execFileSafe).mockImplementation((cmd: string) => {
      if (cmd === "which") return "/usr/bin/pip3";
      return "";
    });

    const manifest: ToolManifest = {
      toolName: "test_tool",
      requiredBinaries: [],
      sudo: "never",
    };

    const result = await installer.resolveAll(
      manifest,
      [],
      ["malicious-package"], // not in allowlist
    );

    expect(result.attempted).toHaveLength(1);
    expect(result.attempted[0].success).toBe(false);
    expect(result.attempted[0].message).toContain("not in the allowed packages list");
  });

  it("rejects npm packages not in ALLOWED_NPM_PACKAGES", async () => {
    vi.mocked(getConfig).mockReturnValue({ autoInstall: true } as any);
    AutoInstaller.resetInstance();
    const installer = AutoInstaller.instance();

    // Mock npm availability
    vi.mocked(execFileSafe).mockImplementation((cmd: string) => {
      if (cmd === "which") return "/usr/bin/npm";
      return "";
    });

    const manifest: ToolManifest = {
      toolName: "test_tool",
      requiredBinaries: [],
      sudo: "never",
    };

    const result = await installer.resolveAll(
      manifest,
      [],
      undefined,
      ["evil-npm-pkg"], // not in allowlist
    );

    expect(result.attempted).toHaveLength(1);
    expect(result.attempted[0].success).toBe(false);
    expect(result.attempted[0].message).toContain("not in the allowed packages list");
  });

  // ── Binary not in DEFENSIVE_TOOLS ──────────────────────────────────────────

  it("refuses to install binaries not in DEFENSIVE_TOOLS", async () => {
    vi.mocked(getConfig).mockReturnValue({ autoInstall: true } as any);
    AutoInstaller.resetInstance();
    const installer = AutoInstaller.instance();

    const manifest: ToolManifest = {
      toolName: "test_tool",
      requiredBinaries: ["unknown_binary"],
      sudo: "never",
    };

    const result = await installer.resolveAll(manifest, ["unknown_binary"]);
    expect(result.attempted).toHaveLength(1);
    expect(result.attempted[0].success).toBe(false);
    expect(result.attempted[0].message).toContain("not in the approved DEFENSIVE_TOOLS list");
  });
});

// ── validatePackageName ──────────────────────────────────────────────────────

describe("validatePackageName", () => {
  it("accepts valid package names", () => {
    expect(validatePackageName("iptables")).toBe(true);
    expect(validatePackageName("lib0pcap-dev")).toBe(true);
    expect(validatePackageName("nftables")).toBe(true);
    expect(validatePackageName("python3.11")).toBe(true);
    expect(validatePackageName("gcc-12")).toBe(true);
  });

  it("rejects names starting with non-alphanumeric", () => {
    expect(validatePackageName("-bad")).toBe(false);
    expect(validatePackageName(".bad")).toBe(false);
    expect(validatePackageName("")).toBe(false);
  });

  it("rejects names with shell metacharacters", () => {
    expect(validatePackageName("pkg; rm -rf /")).toBe(false);
    expect(validatePackageName("pkg$(evil)")).toBe(false);
    expect(validatePackageName("pkg`evil`")).toBe(false);
    expect(validatePackageName("pkg|pipe")).toBe(false);
  });

  it("rejects names with path separators", () => {
    expect(validatePackageName("../../../etc/passwd")).toBe(false);
    expect(validatePackageName("pkg/subpkg")).toBe(false);
  });

  it("rejects names longer than 128 characters", () => {
    const longName = "a" + "b".repeat(128);
    expect(validatePackageName(longName)).toBe(false);
  });

  it("accepts names with colons (arch qualifiers)", () => {
    expect(validatePackageName("libssl-dev:amd64")).toBe(true);
  });
});
