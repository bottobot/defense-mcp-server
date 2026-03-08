/**
 * Tests for src/core/distro.ts
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Mock executor ────────────────────────────────────────────────────────────

vi.mock("../../src/core/executor.js", () => ({
  executeCommand: vi.fn(async (opts: { command: string; args: string[] }) => {
    if (opts.command === "which") {
      // Default: most binaries not found
      return { exitCode: 1, stdout: "", stderr: "not found" };
    }
    return { exitCode: 1, stdout: "", stderr: "" };
  }),
}));

vi.mock("node:fs", () => ({
  readFileSync: vi.fn(() => ""),
  existsSync: vi.fn(() => false),
}));

vi.mock("node:fs/promises", () => ({
  readFile: vi.fn(async () => {
    throw new Error("ENOENT");
  }),
}));

import {
  getPackageManager,
  getServiceManager,
  getInstallCommand,
  getUpdateCommand,
  type PackageManagerName,
  type InitSystem,
} from "../../src/core/distro.js";

describe("getPackageManager", () => {
  // ── apt ────────────────────────────────────────────────────────────────────

  it("returns apt commands for 'apt'", () => {
    const pm = getPackageManager("apt");
    expect(pm.installCmd("nginx")).toEqual(["apt-get", "install", "-y", "nginx"]);
    expect(pm.removeCmd("nginx")).toEqual(["apt-get", "remove", "-y", "nginx"]);
    expect(pm.updateCmd()).toEqual(["apt-get", "update"]);
    expect(pm.searchCmd("nginx")).toEqual(["apt-cache", "search", "nginx"]);
    expect(pm.listInstalledCmd()).toEqual(["dpkg", "--get-selections"]);
  });

  // ── dnf ────────────────────────────────────────────────────────────────────

  it("returns dnf commands for 'dnf'", () => {
    const pm = getPackageManager("dnf");
    expect(pm.installCmd("nginx")).toEqual(["dnf", "install", "-y", "nginx"]);
    expect(pm.removeCmd("nginx")).toEqual(["dnf", "remove", "-y", "nginx"]);
  });

  // ── yum ────────────────────────────────────────────────────────────────────

  it("returns yum commands for 'yum'", () => {
    const pm = getPackageManager("yum");
    expect(pm.installCmd("nginx")).toEqual(["yum", "install", "-y", "nginx"]);
  });

  // ── pacman ─────────────────────────────────────────────────────────────────

  it("returns pacman commands for 'pacman'", () => {
    const pm = getPackageManager("pacman");
    expect(pm.installCmd("nginx")).toEqual(["pacman", "-S", "--noconfirm", "nginx"]);
    expect(pm.removeCmd("nginx")).toEqual(["pacman", "-R", "--noconfirm", "nginx"]);
  });

  // ── brew ───────────────────────────────────────────────────────────────────

  it("returns brew commands for 'brew'", () => {
    const pm = getPackageManager("brew");
    expect(pm.installCmd("nginx")).toEqual(["brew", "install", "nginx"]);
  });

  // ── apk ────────────────────────────────────────────────────────────────────

  it("returns apk commands for 'apk'", () => {
    const pm = getPackageManager("apk");
    expect(pm.installCmd("nginx")).toEqual(["apk", "add", "nginx"]);
    expect(pm.removeCmd("nginx")).toEqual(["apk", "del", "nginx"]);
  });

  // ── zypper ─────────────────────────────────────────────────────────────────

  it("returns zypper commands for 'zypper'", () => {
    const pm = getPackageManager("zypper");
    expect(pm.installCmd("nginx")).toEqual(["zypper", "install", "-y", "nginx"]);
  });

  // ── distro name mapping ────────────────────────────────────────────────────

  it("resolves distro names to package managers", () => {
    expect(getPackageManager("debian").installCmd("x")).toEqual(["apt-get", "install", "-y", "x"]);
    expect(getPackageManager("ubuntu").installCmd("x")).toEqual(["apt-get", "install", "-y", "x"]);
    expect(getPackageManager("kali").installCmd("x")).toEqual(["apt-get", "install", "-y", "x"]);
    expect(getPackageManager("fedora").installCmd("x")).toEqual(["dnf", "install", "-y", "x"]);
    expect(getPackageManager("arch").installCmd("x")).toEqual(["pacman", "-S", "--noconfirm", "x"]);
    expect(getPackageManager("alpine").installCmd("x")).toEqual(["apk", "add", "x"]);
    expect(getPackageManager("macos").installCmd("x")).toEqual(["brew", "install", "x"]);
  });

  // ── unknown ────────────────────────────────────────────────────────────────

  it("returns echo fallback for unknown package manager", () => {
    const pm = getPackageManager("unknown");
    const cmd = pm.installCmd("test");
    expect(cmd[0]).toBe("echo");
  });

  it("returns echo fallback when no input provided", () => {
    const pm = getPackageManager();
    const cmd = pm.installCmd("test");
    expect(cmd[0]).toBe("echo");
  });
});

describe("getServiceManager", () => {
  it("returns systemd commands for 'systemd'", () => {
    const sm = getServiceManager("systemd");
    expect(sm.startCmd("nginx")).toEqual(["systemctl", "start", "nginx"]);
    expect(sm.stopCmd("nginx")).toEqual(["systemctl", "stop", "nginx"]);
    expect(sm.enableCmd("nginx")).toEqual(["systemctl", "enable", "nginx"]);
    expect(sm.disableCmd("nginx")).toEqual(["systemctl", "disable", "nginx"]);
    expect(sm.statusCmd("nginx")).toEqual(["systemctl", "status", "nginx"]);
    expect(sm.listServicesCmd()).toEqual(["systemctl", "list-units", "--type=service", "--all"]);
  });

  it("returns launchd commands for 'launchd'", () => {
    const sm = getServiceManager("launchd");
    expect(sm.startCmd("com.apple.svc")).toEqual(["launchctl", "start", "com.apple.svc"]);
    expect(sm.stopCmd("com.apple.svc")).toEqual(["launchctl", "stop", "com.apple.svc"]);
  });

  it("returns openrc commands for 'openrc'", () => {
    const sm = getServiceManager("openrc");
    expect(sm.startCmd("nginx")).toEqual(["rc-service", "nginx", "start"]);
    expect(sm.enableCmd("nginx")).toEqual(["rc-update", "add", "nginx", "default"]);
  });

  it("returns sysvinit fallback for unknown init system", () => {
    const sm = getServiceManager("unknown");
    expect(sm.startCmd("nginx")).toEqual(["service", "nginx", "start"]);
    expect(sm.enableCmd("nginx")).toEqual(["update-rc.d", "nginx", "enable"]);
  });
});

describe("legacy helpers", () => {
  it("getInstallCommand returns correct command", () => {
    expect(getInstallCommand("apt", "nginx")).toEqual(["apt-get", "install", "-y", "nginx"]);
    expect(getInstallCommand("dnf", "nginx")).toEqual(["dnf", "install", "-y", "nginx"]);
  });

  it("getUpdateCommand returns correct command", () => {
    expect(getUpdateCommand("apt")).toEqual(["apt-get", "update"]);
    expect(getUpdateCommand("pacman")).toEqual(["pacman", "-Sy"]);
  });
});
