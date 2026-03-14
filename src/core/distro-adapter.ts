/**
 * DistroAdapter — unified cross-distribution API for the Defense MCP Server.
 *
 * This module provides a single, cached adapter instance that abstracts away
 * distribution-specific differences in:
 *   - Package management (apt / dnf / yum / zypper / pacman / apk)
 *   - Service management (systemd / openrc / sysvinit / launchd)
 *   - Firewall backends (iptables / nftables / ufw / firewalld)
 *   - File system paths (logs, PAM configs, syslog, package tools)
 *   - Package integrity checking (debsums / rpm -V)
 *   - Automatic updates configuration
 *
 * Supported distributions:
 *   Debian, Ubuntu, Kali, Linux Mint, Pop!_OS  →  debian family
 *   RHEL, CentOS, Fedora, Rocky, AlmaLinux     →  rhel family
 *   openSUSE, SLES                              →  suse family
 *   Arch, Manjaro                               →  arch family
 *   Alpine                                      →  alpine family
 *
 * Usage:
 *   import { getDistroAdapter } from "../core/distro-adapter.js";
 *   const da = await getDistroAdapter();
 *   const cmd = da.pkg.installCmd("nginx");  // distro-correct install
 *   const logPath = da.paths.syslog;          // "/var/log/syslog" or "/var/log/messages"
 */

import {
  detectDistro,
  getPackageManager,
  getServiceManager,
  getFirewallBackend,
  type DistroInfo,
  type DistroFamily,
  type PackageManagerName,
  type PackageManagerCommands,
  type ServiceManagerCommands,
  type FirewallBackendCommands,
  type InitSystem,
} from "./distro.js";

// ── Path Maps ────────────────────────────────────────────────────────────────

/** System paths that vary across distributions. */
export interface DistroPaths {
  /** Primary syslog file */
  syslog: string;
  /** Authentication log */
  authLog: string;
  /** PAM common-auth or system-auth equivalent */
  pamAuth: string;
  /** PAM common-password or password-auth equivalent */
  pamPassword: string;
  /** PAM common-session equivalent */
  pamSession: string;
  /** PAM common-account equivalent */
  pamAccount: string;
  /** All PAM config files to audit */
  pamAllConfigs: string[];
  /** Auto-update config dir (apt.conf.d, dnf automatic, etc.) */
  autoUpdateConfig: string;
  /** Auto-update package name */
  autoUpdatePackage: string;
  /** Auto-update service name */
  autoUpdateService: string;
  /** Firewall persistence config path */
  firewallPersistenceConfig: string;
  /** Package manager lock file */
  packageLockFile: string;
  /** Network interface config dir */
  networkConfigDir: string;
  /** Kernel modules blacklist config */
  modprobeDir: string;
  /** GRUB config file */
  grubConfig: string;
  /** GRUB defaults file */
  grubDefaults: string;
  /** GRUB update command */
  grubUpdateCmd: string[];
}

/** Package integrity check configuration. */
export interface IntegrityCheckConfig {
  /** Whether integrity checking is supported */
  supported: boolean;
  /** The command to check package integrity */
  checkCmd: string[];
  /** The command to check a specific package */
  checkPackageCmd: (pkg: string) => string[];
  /** Name of the integrity tool */
  toolName: string;
  /** How to install the integrity tool */
  installHint: string;
}

/** Auto-update audit configuration. */
export interface AutoUpdateConfig {
  /** Whether auto-updates are supported on this distro */
  supported: boolean;
  /** Package name for auto-updates */
  packageName: string;
  /** How to check if auto-update is installed */
  checkInstalledCmd: string[];
  /** Service name to check */
  serviceName: string;
  /** Config files to audit */
  configFiles: string[];
  /** How to install auto-updates */
  installHint: string;
}

/** Package listing/querying commands. */
export interface PackageQueryCommands {
  /** List all installed packages */
  listInstalledCmd: string[];
  /** Query a specific package (returns version info) */
  queryPackageCmd: (pkg: string) => string[];
  /** List available upgrades */
  listUpgradableCmd: string[];
  /** Show held/locked packages */
  showHeldCmd: string[];
  /** Simulate upgrade (dry-run) */
  simulateUpgradeCmd: string[];
  /** Show package changelog */
  changelogCmd: (pkg: string) => string[];
  /** Show package policy/info */
  policyCmd: (pkg: string) => string[];
  /** Check if a specific package is installed */
  isInstalledCmd: (pkg: string) => string[];
  /** List installed kernel packages */
  listKernelsCmd: string[];
  /** Check for auto-removable packages */
  autoRemoveCmd: string[];
}

/** Firewall persistence commands. */
export interface FirewallPersistenceConfig {
  /** Package name for firewall persistence */
  packageName: string;
  /** How to check if persistence is installed */
  checkInstalledCmd: string[];
  /** Install command (already includes sudo) */
  installCmd: string[];
  /** Service name for persistence */
  serviceName: string;
  /** Enable persistence service */
  enableCmd: string[];
  /** Save rules command */
  saveCmd: string[];
  /** Rollback/uninstall hint */
  uninstallHint: string;
}

// ── DistroAdapter ────────────────────────────────────────────────────────────

export class DistroAdapter {
  readonly distro: DistroInfo;
  readonly pkg: PackageManagerCommands;
  readonly svc: ServiceManagerCommands;
  readonly fw: FirewallBackendCommands;
  readonly paths: DistroPaths;
  readonly integrity: IntegrityCheckConfig;
  readonly autoUpdate: AutoUpdateConfig;
  readonly pkgQuery: PackageQueryCommands;
  readonly fwPersistence: FirewallPersistenceConfig;

  constructor(
    distro: DistroInfo,
    pkg: PackageManagerCommands,
    svc: ServiceManagerCommands,
    fw: FirewallBackendCommands,
  ) {
    this.distro = distro;
    this.pkg = pkg;
    this.svc = svc;
    this.fw = fw;
    this.paths = buildPaths(distro);
    this.integrity = buildIntegrityConfig(distro);
    this.autoUpdate = buildAutoUpdateConfig(distro);
    this.pkgQuery = buildPackageQueryCommands(distro);
    this.fwPersistence = buildFirewallPersistenceConfig(distro);
  }

  /** Human-readable summary of the detected environment. */
  get summary(): string {
    return (
      `${this.distro.name} (${this.distro.family}) | ` +
      `pkg=${this.distro.packageManager} | init=${this.distro.initSystem} | ` +
      `fw=${this.fw.name}`
    );
  }

  /** Whether the distro family is Debian-based. */
  get isDebian(): boolean { return this.distro.family === "debian"; }

  /** Whether the distro family is RHEL-based. */
  get isRhel(): boolean { return this.distro.family === "rhel"; }

  /** Whether the distro family is SUSE-based. */
  get isSuse(): boolean { return this.distro.family === "suse"; }

  /** Whether the distro family is Arch-based. */
  get isArch(): boolean { return this.distro.family === "arch"; }

  /** Whether the distro family is Alpine. */
  get isAlpine(): boolean { return this.distro.family === "alpine"; }

  /** Install a package using the distro's package manager (returns command array). */
  installPkg(pkg: string): { command: string; args: string[] } {
    const cmd = this.pkg.installCmd(pkg);
    return { command: "sudo", args: cmd };
  }

  /** Remove a package using the distro's package manager (returns command array). */
  removePkg(pkg: string): { command: string; args: string[] } {
    const cmd = this.pkg.removeCmd(pkg);
    return { command: "sudo", args: cmd };
  }
}

// ── Path builders ────────────────────────────────────────────────────────────

function buildPaths(distro: DistroInfo): DistroPaths {
  const family = distro.family;

  // Syslog location
  const syslog = (() => {
    switch (family) {
      case "debian": return "/var/log/syslog";
      case "rhel": return "/var/log/messages";
      case "suse": return "/var/log/messages";
      case "arch": return "/var/log/messages.log"; // usually journald only
      case "alpine": return "/var/log/messages";
      default: return "/var/log/syslog";
    }
  })();

  // Auth log location
  const authLog = (() => {
    switch (family) {
      case "debian": return "/var/log/auth.log";
      case "rhel": return "/var/log/secure";
      case "suse": return "/var/log/secure";
      case "arch": return "/var/log/auth.log"; // usually journald
      case "alpine": return "/var/log/auth.log";
      default: return "/var/log/auth.log";
    }
  })();

  // PAM paths — Debian uses common-*, RHEL/SUSE use system-auth/password-auth
  const isDebianPam = family === "debian" || family === "alpine";
  const pamAuth = isDebianPam ? "/etc/pam.d/common-auth" : "/etc/pam.d/system-auth";
  const pamPassword = isDebianPam ? "/etc/pam.d/common-password" : "/etc/pam.d/password-auth";
  const pamSession = isDebianPam ? "/etc/pam.d/common-session" : "/etc/pam.d/system-auth";
  const pamAccount = isDebianPam ? "/etc/pam.d/common-account" : "/etc/pam.d/system-auth";

  const pamAllConfigs = isDebianPam
    ? ["/etc/pam.d/common-auth", "/etc/pam.d/common-password", "/etc/pam.d/common-session", "/etc/pam.d/common-account"]
    : ["/etc/pam.d/system-auth", "/etc/pam.d/password-auth"];

  // Auto-update config
  const autoUpdateConfig = (() => {
    switch (family) {
      case "debian": return "/etc/apt/apt.conf.d";
      case "rhel": return "/etc/dnf/automatic.conf";
      case "suse": return "/etc/zypp/zypp.conf";
      case "arch": return "/etc/pacman.conf"; // no native auto-update
      case "alpine": return "/etc/apk"; // no native auto-update
      default: return "/etc";
    }
  })();

  const autoUpdatePackage = (() => {
    switch (family) {
      case "debian": return "unattended-upgrades";
      case "rhel": return "dnf-automatic";
      case "suse": return "zypper"; // uses cron/systemd
      default: return "";
    }
  })();

  const autoUpdateService = (() => {
    switch (family) {
      case "debian": return "unattended-upgrades";
      case "rhel": return "dnf-automatic.timer";
      case "suse": return "zypper";
      default: return "";
    }
  })();

  // Firewall persistence
  const firewallPersistenceConfig = (() => {
    switch (family) {
      case "debian": return "/etc/iptables/rules.v4";
      case "rhel": return "/etc/sysconfig/iptables";
      case "suse": return "/etc/sysconfig/iptables";
      case "arch": return "/etc/iptables/iptables.rules";
      case "alpine": return "/etc/iptables/rules-save";
      default: return "/etc/iptables/rules.v4";
    }
  })();

  // Package lock file
  const packageLockFile = (() => {
    switch (distro.packageManager) {
      case "apt": return "/var/lib/dpkg/lock-frontend";
      case "dnf": case "yum": return "/var/run/yum.pid";
      case "zypper": return "/var/run/zypp.pid";
      case "pacman": return "/var/lib/pacman/db.lck";
      case "apk": return "/lib/apk/db/lock";
      default: return "";
    }
  })();

  // Network config
  const networkConfigDir = (() => {
    switch (family) {
      case "debian": return "/etc/network";
      case "rhel": return "/etc/sysconfig/network-scripts";
      case "suse": return "/etc/sysconfig/network";
      case "arch": return "/etc/systemd/network";
      case "alpine": return "/etc/network";
      default: return "/etc/network";
    }
  })();

  // GRUB config paths
  const grubConfig = (() => {
    switch (family) {
      case "debian": return "/boot/grub/grub.cfg";
      case "rhel": return "/boot/grub2/grub.cfg";
      case "suse": return "/boot/grub2/grub.cfg";
      case "arch": return "/boot/grub/grub.cfg";
      default: return "/boot/grub/grub.cfg";
    }
  })();

  const grubDefaults = "/etc/default/grub"; // same everywhere

  const grubUpdateCmd = (() => {
    switch (family) {
      case "debian": return ["update-grub"];
      case "rhel": return ["grub2-mkconfig", "-o", "/boot/grub2/grub.cfg"];
      case "suse": return ["grub2-mkconfig", "-o", "/boot/grub2/grub.cfg"];
      case "arch": return ["grub-mkconfig", "-o", "/boot/grub/grub.cfg"];
      default: return ["update-grub"];
    }
  })();

  return {
    syslog, authLog,
    pamAuth, pamPassword, pamSession, pamAccount, pamAllConfigs,
    autoUpdateConfig, autoUpdatePackage, autoUpdateService,
    firewallPersistenceConfig, packageLockFile,
    networkConfigDir,
    modprobeDir: "/etc/modprobe.d", // universal
    grubConfig, grubDefaults, grubUpdateCmd,
  };
}

// ── Integrity check ──────────────────────────────────────────────────────────

function buildIntegrityConfig(distro: DistroInfo): IntegrityCheckConfig {
  switch (distro.family) {
    case "debian":
      return {
        supported: true,
        checkCmd: ["debsums", "-s"],
        checkPackageCmd: (pkg) => ["debsums", "-s", pkg],
        toolName: "debsums",
        installHint: `sudo ${distro.packageManager} install debsums`,
      };
    case "rhel":
    case "suse":
      return {
        supported: true,
        checkCmd: ["rpm", "-Va"],
        checkPackageCmd: (pkg) => ["rpm", "-V", pkg],
        toolName: "rpm",
        installHint: "rpm is pre-installed on RPM-based systems",
      };
    case "arch":
      return {
        supported: true,
        checkCmd: ["pacman", "-Qk"],
        checkPackageCmd: (pkg) => ["pacman", "-Qk", pkg],
        toolName: "pacman",
        installHint: "pacman is the native Arch package manager",
      };
    case "alpine":
      return {
        supported: true,
        checkCmd: ["apk", "verify"],
        checkPackageCmd: (pkg) => ["apk", "verify", pkg],
        toolName: "apk",
        installHint: "apk is the native Alpine package manager",
      };
    default:
      return {
        supported: false,
        checkCmd: ["echo", "Package integrity checking not supported on this distro"],
        checkPackageCmd: () => ["echo", "Not supported"],
        toolName: "unknown",
        installHint: "No package integrity tool available",
      };
  }
}

// ── Auto-update config ───────────────────────────────────────────────────────

function buildAutoUpdateConfig(distro: DistroInfo): AutoUpdateConfig {
  switch (distro.family) {
    case "debian":
      return {
        supported: true,
        packageName: "unattended-upgrades",
        checkInstalledCmd: ["dpkg", "-l", "unattended-upgrades"],
        serviceName: "unattended-upgrades",
        configFiles: [
          "/etc/apt/apt.conf.d/20auto-upgrades",
          "/etc/apt/apt.conf.d/50unattended-upgrades",
        ],
        installHint: "sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades",
      };
    case "rhel":
      return {
        supported: true,
        packageName: "dnf-automatic",
        checkInstalledCmd: ["rpm", "-q", "dnf-automatic"],
        serviceName: "dnf-automatic.timer",
        configFiles: ["/etc/dnf/automatic.conf"],
        installHint: "sudo dnf install dnf-automatic && sudo systemctl enable --now dnf-automatic.timer",
      };
    case "suse":
      return {
        supported: true,
        packageName: "yast2-online-update-configuration",
        checkInstalledCmd: ["rpm", "-q", "yast2-online-update-configuration"],
        serviceName: "yast-online-update.timer",
        configFiles: ["/etc/zypp/zypp.conf"],
        installHint: "sudo zypper install yast2-online-update-configuration",
      };
    case "arch":
      return {
        supported: false,
        packageName: "",
        checkInstalledCmd: ["echo", "No native auto-update on Arch"],
        serviceName: "",
        configFiles: [],
        installHint: "Arch Linux does not support unattended upgrades natively. Consider a custom systemd timer with `pacman -Syu --noconfirm`.",
      };
    case "alpine":
      return {
        supported: false,
        packageName: "",
        checkInstalledCmd: ["echo", "No native auto-update on Alpine"],
        serviceName: "",
        configFiles: [],
        installHint: "Alpine does not support unattended upgrades natively. Consider a cron job with `apk upgrade`.",
      };
    default:
      return {
        supported: false,
        packageName: "",
        checkInstalledCmd: ["echo", "Unknown distro"],
        serviceName: "",
        configFiles: [],
        installHint: "Unknown distribution",
      };
  }
}

// ── Package query commands ───────────────────────────────────────────────────

function buildPackageQueryCommands(distro: DistroInfo): PackageQueryCommands {
  switch (distro.family) {
    case "debian":
      return {
        listInstalledCmd: ["dpkg", "--get-selections"],
        queryPackageCmd: (pkg) => ["dpkg-query", "-W", "-f", "${Package}\t${Version}\t${Architecture}\n", pkg],
        listUpgradableCmd: ["apt", "list", "--upgradable"],
        showHeldCmd: ["apt-mark", "showhold"],
        simulateUpgradeCmd: ["apt-get", "upgrade", "-s"],
        changelogCmd: (pkg) => ["apt-get", "changelog", pkg],
        policyCmd: (pkg) => ["apt-cache", "policy", pkg],
        isInstalledCmd: (pkg) => ["dpkg", "-l", pkg],
        listKernelsCmd: ["dpkg", "--list", "linux-image-*"],
        autoRemoveCmd: ["apt", "--dry-run", "autoremove"],
      };
    case "rhel":
      return {
        listInstalledCmd: ["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"],
        queryPackageCmd: (pkg) => ["rpm", "-q", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n", pkg],
        listUpgradableCmd: [distro.packageManager === "dnf" ? "dnf" : "yum", "check-update"],
        showHeldCmd: [distro.packageManager === "dnf" ? "dnf" : "yum", "versionlock", "list"],
        simulateUpgradeCmd: [distro.packageManager === "dnf" ? "dnf" : "yum", "update", "--assumeno"],
        changelogCmd: (pkg) => [distro.packageManager === "dnf" ? "dnf" : "yum", "changelog", pkg],
        policyCmd: (pkg) => [distro.packageManager === "dnf" ? "dnf" : "yum", "info", pkg],
        isInstalledCmd: (pkg) => ["rpm", "-q", pkg],
        listKernelsCmd: ["rpm", "-qa", "kernel-*"],
        autoRemoveCmd: [distro.packageManager === "dnf" ? "dnf" : "yum", "autoremove", "--assumeno"],
      };
    case "suse":
      return {
        listInstalledCmd: ["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"],
        queryPackageCmd: (pkg) => ["rpm", "-q", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n", pkg],
        listUpgradableCmd: ["zypper", "list-updates"],
        showHeldCmd: ["zypper", "locks"],
        simulateUpgradeCmd: ["zypper", "--dry-run", "update"],
        changelogCmd: (pkg) => ["rpm", "-q", "--changelog", pkg],
        policyCmd: (pkg) => ["zypper", "info", pkg],
        isInstalledCmd: (pkg) => ["rpm", "-q", pkg],
        listKernelsCmd: ["rpm", "-qa", "kernel-*"],
        autoRemoveCmd: ["zypper", "--dry-run", "remove", "--clean-deps"],
      };
    case "arch":
      return {
        listInstalledCmd: ["pacman", "-Q"],
        queryPackageCmd: (pkg) => ["pacman", "-Qi", pkg],
        listUpgradableCmd: ["pacman", "-Qu"],
        showHeldCmd: ["grep", "IgnorePkg", "/etc/pacman.conf"],
        simulateUpgradeCmd: ["pacman", "-Syu", "--print"],
        changelogCmd: (pkg) => ["pacman", "-Qc", pkg],
        policyCmd: (pkg) => ["pacman", "-Si", pkg],
        isInstalledCmd: (pkg) => ["pacman", "-Q", pkg],
        listKernelsCmd: ["pacman", "-Q", "linux"],
        autoRemoveCmd: ["pacman", "-Qdtq"],
      };
    case "alpine":
      return {
        listInstalledCmd: ["apk", "info", "-v"],
        queryPackageCmd: (pkg) => ["apk", "info", pkg],
        listUpgradableCmd: ["apk", "version", "-l", "<"],
        showHeldCmd: ["apk", "list", "--locked"],
        simulateUpgradeCmd: ["apk", "upgrade", "--simulate"],
        changelogCmd: (pkg) => ["apk", "info", "-d", pkg],
        policyCmd: (pkg) => ["apk", "policy", pkg],
        isInstalledCmd: (pkg) => ["apk", "info", "-e", pkg],
        listKernelsCmd: ["apk", "info", "linux-*"],
        autoRemoveCmd: ["echo", "Not applicable on Alpine"],
      };
    default:
      return {
        listInstalledCmd: ["echo", "Unknown package manager"],
        queryPackageCmd: () => ["echo", "Unknown"],
        listUpgradableCmd: ["echo", "Unknown"],
        showHeldCmd: ["echo", "Unknown"],
        simulateUpgradeCmd: ["echo", "Unknown"],
        changelogCmd: () => ["echo", "Unknown"],
        policyCmd: () => ["echo", "Unknown"],
        isInstalledCmd: () => ["echo", "Unknown"],
        listKernelsCmd: ["echo", "Unknown"],
        autoRemoveCmd: ["echo", "Unknown"],
      };
  }
}

// ── Firewall persistence config ──────────────────────────────────────────────

function buildFirewallPersistenceConfig(distro: DistroInfo): FirewallPersistenceConfig {
  switch (distro.family) {
    case "debian":
      return {
        packageName: "iptables-persistent",
        checkInstalledCmd: ["dpkg", "-l", "iptables-persistent"],
        installCmd: ["apt-get", "install", "-y", "iptables-persistent"],
        serviceName: "netfilter-persistent",
        enableCmd: ["systemctl", "enable", "netfilter-persistent"],
        saveCmd: ["netfilter-persistent", "save"],
        uninstallHint: "sudo apt-get remove -y iptables-persistent",
      };
    case "rhel":
      return {
        packageName: "iptables-services",
        checkInstalledCmd: ["rpm", "-q", "iptables-services"],
        installCmd: [distro.packageManager === "dnf" ? "dnf" : "yum", "install", "-y", "iptables-services"],
        serviceName: "iptables",
        enableCmd: ["systemctl", "enable", "iptables"],
        saveCmd: ["service", "iptables", "save"],
        uninstallHint: `sudo ${distro.packageManager} remove -y iptables-services`,
      };
    case "suse":
      return {
        packageName: "iptables",
        checkInstalledCmd: ["rpm", "-q", "iptables"],
        installCmd: ["zypper", "install", "-y", "iptables"],
        serviceName: "iptables",
        enableCmd: ["systemctl", "enable", "iptables"],
        saveCmd: ["iptables-save"],
        uninstallHint: "sudo zypper remove -y iptables",
      };
    case "arch":
      return {
        packageName: "iptables",
        checkInstalledCmd: ["pacman", "-Q", "iptables"],
        installCmd: ["pacman", "-S", "--noconfirm", "iptables"],
        serviceName: "iptables",
        enableCmd: ["systemctl", "enable", "iptables"],
        saveCmd: ["iptables-save"],
        uninstallHint: "sudo pacman -R iptables",
      };
    case "alpine":
      return {
        packageName: "iptables",
        checkInstalledCmd: ["apk", "info", "-e", "iptables"],
        installCmd: ["apk", "add", "iptables"],
        serviceName: "iptables",
        enableCmd: ["rc-update", "add", "iptables", "default"],
        saveCmd: ["/etc/init.d/iptables", "save"],
        uninstallHint: "sudo apk del iptables",
      };
    default:
      return {
        packageName: "iptables-persistent",
        checkInstalledCmd: ["echo", "Unknown"],
        installCmd: ["echo", "Cannot install on unknown distro"],
        serviceName: "",
        enableCmd: ["echo", "Unknown"],
        saveCmd: ["iptables-save"],
        uninstallHint: "",
      };
  }
}

// ── Singleton cache ──────────────────────────────────────────────────────────

let cachedAdapter: DistroAdapter | null = null;

/**
 * Returns the singleton DistroAdapter.
 * On first call it detects the distribution and builds all adapters.
 * Subsequent calls return the cached instance.
 */
export async function getDistroAdapter(): Promise<DistroAdapter> {
  if (cachedAdapter) return cachedAdapter;

  const distro = await detectDistro();
  const pkg = getPackageManager(distro.packageManager);
  const svc = getServiceManager(distro.initSystem);
  const fw = await getFirewallBackend();

  cachedAdapter = new DistroAdapter(distro, pkg, svc, fw);

  console.error(`[distro-adapter] Initialized: ${cachedAdapter.summary}`);

  return cachedAdapter;
}

/**
 * Returns the cached adapter if already initialized, or null.
 * Use when you can't await (synchronous contexts).
 */
export function getDistroAdapterSync(): DistroAdapter | null {
  return cachedAdapter;
}
