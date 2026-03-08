import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock distro module
vi.mock("../../src/core/distro.js", () => ({
  detectDistro: vi.fn(),
  getPackageManager: vi.fn(),
  getServiceManager: vi.fn(),
  getFirewallBackend: vi.fn(),
}));

import {
  detectDistro,
  getPackageManager,
  getServiceManager,
  getFirewallBackend,
} from "../../src/core/distro.js";
import { DistroAdapter } from "../../src/core/distro-adapter.js";
import type { DistroInfo, PackageManagerCommands, ServiceManagerCommands, FirewallBackendCommands } from "../../src/core/distro.js";

const mockDetectDistro = vi.mocked(detectDistro);

/** Helper to build a DistroInfo object. */
function makeDistro(family: string, pkgMgr: string, initSystem = "systemd"): DistroInfo {
  return {
    id: family,
    name: family.charAt(0).toUpperCase() + family.slice(1),
    version: "12",
    osFamily: "linux",
    specificDistro: family as DistroInfo["specificDistro"],
    family: family as DistroInfo["family"],
    packageManager: pkgMgr as DistroInfo["packageManager"],
    initSystem: initSystem as DistroInfo["initSystem"],
    hasFirewalld: false,
    hasUfw: family === "debian",
    hasSelinux: family === "rhel",
    hasApparmor: family === "debian",
  };
}

/** Helper to build mock package manager commands. */
function makePkgMgr(): PackageManagerCommands {
  return {
    installCmd: (pkg: string) => ["apt-get", "install", "-y", pkg],
    removeCmd: (pkg: string) => ["apt-get", "remove", "-y", pkg],
    updateCmd: () => ["apt-get", "update"],
    searchCmd: (term: string) => ["apt-cache", "search", term],
    listInstalledCmd: () => ["dpkg", "--list"],
  };
}

/** Helper to build mock service manager commands. */
function makeSvcMgr(): ServiceManagerCommands {
  return {
    startCmd: (svc: string) => ["systemctl", "start", svc],
    stopCmd: (svc: string) => ["systemctl", "stop", svc],
    enableCmd: (svc: string) => ["systemctl", "enable", svc],
    disableCmd: (svc: string) => ["systemctl", "disable", svc],
    statusCmd: (svc: string) => ["systemctl", "status", svc],
    listServicesCmd: () => ["systemctl", "list-units", "--type=service"],
  };
}

/** Helper to build mock firewall backend commands. */
function makeFwBackend(): FirewallBackendCommands {
  return {
    name: "iptables",
    allowCmd: (port: number, proto?: string) => ["iptables", "-A", "INPUT", "-p", proto ?? "tcp", "--dport", String(port), "-j", "ACCEPT"],
    denyCmd: (port: number, proto?: string) => ["iptables", "-A", "INPUT", "-p", proto ?? "tcp", "--dport", String(port), "-j", "DROP"],
    listCmd: () => ["iptables", "-L", "-n", "-v"],
    flushCmd: () => ["iptables", "-F"],
  };
}

describe("distro-adapter", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  // ── DistroAdapter construction ──────────────────────────────────────────

  describe("DistroAdapter", () => {
    it("should construct with correct distro info", () => {
      const distro = makeDistro("debian", "apt");
      const adapter = new DistroAdapter(distro, makePkgMgr(), makeSvcMgr(), makeFwBackend());

      expect(adapter.distro.family).toBe("debian");
      expect(adapter.distro.packageManager).toBe("apt");
      expect(adapter.isDebian).toBe(true);
      expect(adapter.isRhel).toBe(false);
    });

    it("should build correct paths for debian family", () => {
      const distro = makeDistro("debian", "apt");
      const adapter = new DistroAdapter(distro, makePkgMgr(), makeSvcMgr(), makeFwBackend());

      expect(adapter.paths.syslog).toBe("/var/log/syslog");
      expect(adapter.paths.authLog).toBe("/var/log/auth.log");
      expect(adapter.paths.pamAuth).toBe("/etc/pam.d/common-auth");
      expect(adapter.paths.pamPassword).toBe("/etc/pam.d/common-password");
    });

    it("should build correct paths for rhel family", () => {
      const distro = makeDistro("rhel", "dnf");
      const adapter = new DistroAdapter(distro, makePkgMgr(), makeSvcMgr(), makeFwBackend());

      expect(adapter.paths.syslog).toBe("/var/log/messages");
      expect(adapter.paths.authLog).toBe("/var/log/secure");
      expect(adapter.paths.pamAuth).toBe("/etc/pam.d/system-auth");
      expect(adapter.paths.pamPassword).toBe("/etc/pam.d/password-auth");
    });

    it("should build integrity config for debian (debsums)", () => {
      const distro = makeDistro("debian", "apt");
      const adapter = new DistroAdapter(distro, makePkgMgr(), makeSvcMgr(), makeFwBackend());

      expect(adapter.integrity.supported).toBe(true);
      expect(adapter.integrity.toolName).toBe("debsums");
      expect(adapter.integrity.checkCmd).toContain("debsums");
    });

    it("should build integrity config for rhel (rpm)", () => {
      const distro = makeDistro("rhel", "dnf");
      const adapter = new DistroAdapter(distro, makePkgMgr(), makeSvcMgr(), makeFwBackend());

      expect(adapter.integrity.supported).toBe(true);
      expect(adapter.integrity.toolName).toBe("rpm");
      expect(adapter.integrity.checkCmd).toContain("rpm");
    });

    it("should report correct family booleans", () => {
      const arch = makeDistro("arch", "pacman");
      const archAdapter = new DistroAdapter(arch, makePkgMgr(), makeSvcMgr(), makeFwBackend());
      expect(archAdapter.isArch).toBe(true);
      expect(archAdapter.isDebian).toBe(false);

      const alpine = makeDistro("alpine", "apk");
      const alpineAdapter = new DistroAdapter(alpine, makePkgMgr(), makeSvcMgr(), makeFwBackend());
      expect(alpineAdapter.isAlpine).toBe(true);
      expect(alpineAdapter.isRhel).toBe(false);

      const suse = makeDistro("suse", "zypper");
      const suseAdapter = new DistroAdapter(suse, makePkgMgr(), makeSvcMgr(), makeFwBackend());
      expect(suseAdapter.isSuse).toBe(true);
    });

    it("should produce a summary string with relevant info", () => {
      const distro = makeDistro("debian", "apt");
      const adapter = new DistroAdapter(distro, makePkgMgr(), makeSvcMgr(), makeFwBackend());

      const summary = adapter.summary;
      expect(summary).toContain("debian");
      expect(summary).toContain("apt");
      expect(summary).toContain("systemd");
      expect(summary).toContain("iptables");
    });

    it("should return install/remove commands via installPkg/removePkg", () => {
      const distro = makeDistro("debian", "apt");
      const adapter = new DistroAdapter(distro, makePkgMgr(), makeSvcMgr(), makeFwBackend());

      const install = adapter.installPkg("nginx");
      expect(install.command).toBe("sudo");
      expect(install.args).toContain("nginx");

      const remove = adapter.removePkg("nginx");
      expect(remove.command).toBe("sudo");
      expect(remove.args).toContain("nginx");
    });

    it("should build auto-update config for debian with unattended-upgrades", () => {
      const distro = makeDistro("debian", "apt");
      const adapter = new DistroAdapter(distro, makePkgMgr(), makeSvcMgr(), makeFwBackend());

      expect(adapter.autoUpdate.supported).toBe(true);
      expect(adapter.autoUpdate.packageName).toBe("unattended-upgrades");
      expect(adapter.autoUpdate.serviceName).toBe("unattended-upgrades");
    });

    it("should build auto-update config for arch as unsupported", () => {
      const distro = makeDistro("arch", "pacman");
      const adapter = new DistroAdapter(distro, makePkgMgr(), makeSvcMgr(), makeFwBackend());

      expect(adapter.autoUpdate.supported).toBe(false);
    });

    it("should build correct package query commands for debian", () => {
      const distro = makeDistro("debian", "apt");
      const adapter = new DistroAdapter(distro, makePkgMgr(), makeSvcMgr(), makeFwBackend());

      expect(adapter.pkgQuery.listInstalledCmd[0]).toBe("dpkg");
      expect(adapter.pkgQuery.listUpgradableCmd[0]).toBe("apt");
    });

    it("should build firewall persistence config for debian", () => {
      const distro = makeDistro("debian", "apt");
      const adapter = new DistroAdapter(distro, makePkgMgr(), makeSvcMgr(), makeFwBackend());

      expect(adapter.fwPersistence.packageName).toBe("iptables-persistent");
      expect(adapter.fwPersistence.serviceName).toBe("netfilter-persistent");
    });
  });
});
