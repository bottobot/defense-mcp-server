import { readFileSync, existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { executeCommand } from "./executor.js";

// ── OS Family ────────────────────────────────────────────────────────────────

/**
 * Top-level operating system family.
 * 'wsl' is reported when running inside Windows Subsystem for Linux.
 */
export type OsFamily = "linux" | "darwin" | "wsl";

// ── Distro Family ────────────────────────────────────────────────────────────

/** Linux distribution family identifiers. */
export type DistroFamily =
  | "debian"
  | "rhel"
  | "arch"
  | "alpine"
  | "suse"
  | "unknown";

// ── Specific Distro ──────────────────────────────────────────────────────────

export type SpecificDistro =
  | "debian" | "ubuntu" | "kali" | "fedora" | "rhel" | "centos"
  | "arch" | "alpine" | "opensuse" | "macos" | "unknown";

// ── Package Manager ──────────────────────────────────────────────────────────

/** Package manager identifiers (extended with brew). */
export type PackageManagerName =
  | "apt" | "dnf" | "yum" | "pacman" | "brew" | "apk" | "zypper" | "unknown";

/** @deprecated Use PackageManagerName. Kept for backwards compatibility. */
export type PackageManager = PackageManagerName;

// ── Init System ──────────────────────────────────────────────────────────────

export type InitSystem = "systemd" | "openrc" | "launchd" | "sysvinit" | "unknown";

// ── PackageManager interface ─────────────────────────────────────────────────

export interface PackageManagerCommands {
  installCmd(pkg: string): string[];
  removeCmd(pkg: string): string[];
  updateCmd(): string[];
  searchCmd(term: string): string[];
  listInstalledCmd(): string[];
}

// ── ServiceManager interface ─────────────────────────────────────────────────

export interface ServiceManagerCommands {
  startCmd(svc: string): string[];
  stopCmd(svc: string): string[];
  enableCmd(svc: string): string[];
  disableCmd(svc: string): string[];
  statusCmd(svc: string): string[];
  listServicesCmd(): string[];
}

// ── Firewall Backend ─────────────────────────────────────────────────────────

export type FirewallBackendName =
  | "iptables" | "nftables" | "ufw" | "firewalld" | "pf" | "unknown";

export interface FirewallBackendCommands {
  readonly name: FirewallBackendName;
  allowCmd(port: number, proto?: string): string[];
  denyCmd(port: number, proto?: string): string[];
  listCmd(): string[];
  flushCmd(): string[];
}

// ── DistroInfo ───────────────────────────────────────────────────────────────

export interface DistroInfo {
  id: string;
  name: string;
  version: string;
  osFamily: OsFamily;
  specificDistro: SpecificDistro;
  family: DistroFamily;
  packageManager: PackageManagerName;
  initSystem: InitSystem;
  hasFirewalld: boolean;
  hasUfw: boolean;
  hasSelinux: boolean;
  hasApparmor: boolean;
}

// ── Cache ────────────────────────────────────────────────────────────────────

let cachedDistro: DistroInfo | null = null;

// ── Internal helpers ─────────────────────────────────────────────────────────

function parseOsRelease(content: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const line of content.split("\n")) {
    const idx = line.indexOf("=");
    if (idx === -1) continue;
    const key = line.substring(0, idx).trim();
    let value = line.substring(idx + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    result[key] = value;
  }
  return result;
}

async function binaryExists(name: string): Promise<boolean> {
  const result = await executeCommand({ command: "which", args: [name], timeout: 5000 });
  return result.exitCode === 0;
}

async function detectWsl(): Promise<boolean> {
  try {
    const content = await readFile("/proc/version", "utf-8");
    return content.toLowerCase().includes("microsoft");
  } catch {
    return false;
  }
}

function idToSpecificDistro(id: string): SpecificDistro {
  const lower = id.toLowerCase().trim();
  if (lower === "debian") return "debian";
  if (lower === "ubuntu") return "ubuntu";
  if (lower === "kali") return "kali";
  if (lower === "fedora") return "fedora";
  if (lower === "rhel" || lower === "redhat") return "rhel";
  if (lower.startsWith("centos")) return "centos";
  if (lower === "arch" || lower === "archlinux") return "arch";
  if (lower.startsWith("alpine")) return "alpine";
  if (lower.includes("suse") || lower === "sles") return "opensuse";
  if (lower === "macos") return "macos";
  return "unknown";
}

function idToFamily(id: string): DistroFamily {
  const lower = id.toLowerCase();
  const debianIds = ["debian", "ubuntu", "kali", "linuxmint", "pop", "elementary", "zorin", "mx", "antiX", "parrot", "raspbian"];
  if (debianIds.some((d) => lower.includes(d))) return "debian";
  const rhelIds = ["rhel", "centos", "fedora", "rocky", "almalinux", "oracle", "amazon", "redhat"];
  if (rhelIds.some((d) => lower.includes(d))) return "rhel";
  if (lower.includes("arch") || lower.includes("manjaro")) return "arch";
  if (lower.includes("alpine")) return "alpine";
  if (lower.includes("suse") || lower.includes("sles")) return "suse";
  return "unknown";
}

function familyToPackageManager(family: DistroFamily): PackageManagerName {
  switch (family) {
    case "debian": return "apt";
    case "rhel": return "dnf";
    case "arch": return "pacman";
    case "alpine": return "apk";
    case "suse": return "zypper";
    default: return "unknown";
  }
}

// ── detectDistro ─────────────────────────────────────────────────────────────

export async function detectDistro(): Promise<DistroInfo> {
  if (cachedDistro) return cachedDistro;

  let id = "unknown";
  let name = "Unknown Linux";
  let version = "unknown";
  let osFamily: OsFamily = "linux";

  // macOS detection
  if (process.platform === "darwin") {
    osFamily = "darwin";
    try {
      const productResult = await executeCommand({ command: "sw_vers", args: ["-productName"], timeout: 5000 });
      const versionResult = await executeCommand({ command: "sw_vers", args: ["-productVersion"], timeout: 5000 });
      if (productResult.exitCode === 0) {
        id = "macos";
        name = productResult.stdout.trim();
        version = versionResult.exitCode === 0 ? versionResult.stdout.trim() : "unknown";
      }
    } catch {
      id = "macos";
      name = "macOS";
    }
  } else {
    // WSL detection
    const isWsl = await detectWsl();
    if (isWsl) osFamily = "wsl";
  }

  // /etc/os-release
  if (id === "unknown") {
    try {
      if (existsSync("/etc/os-release")) {
        const content = readFileSync("/etc/os-release", "utf-8");
        const fields = parseOsRelease(content);
        id = fields.ID ?? id;
        name = fields.PRETTY_NAME ?? fields.NAME ?? name;
        version = fields.VERSION_ID ?? fields.VERSION ?? version;
      }
    } catch { /* fallback */ }
  }

  // lsb_release
  if (id === "unknown") {
    try {
      const result = await executeCommand({ command: "lsb_release", args: ["-a"], timeout: 5000 });
      if (result.exitCode === 0) {
        for (const line of result.stdout.split("\n")) {
          if (line.startsWith("Distributor ID:")) id = line.split(":")[1]?.trim().toLowerCase() ?? id;
          else if (line.startsWith("Description:")) name = line.split(":")[1]?.trim() ?? name;
          else if (line.startsWith("Release:")) version = line.split(":")[1]?.trim() ?? version;
        }
      }
    } catch { /* fallback */ }
  }

  // Distro-specific files
  if (id === "unknown") {
    const distroFiles: [string, string][] = [
      ["/etc/debian_version", "debian"],
      ["/etc/redhat-release", "rhel"],
      ["/etc/arch-release", "arch"],
      ["/etc/alpine-release", "alpine"],
      ["/etc/SuSE-release", "suse"],
    ];
    for (const [filePath, distroId] of distroFiles) {
      try {
        if (existsSync(filePath)) {
          id = distroId;
          version = readFileSync(filePath, "utf-8").trim().split("\n")[0];
          break;
        }
      } catch { /* try next */ }
    }
  }

  const specificDistro = osFamily === "darwin" ? "macos" : idToSpecificDistro(id);
  const family = idToFamily(id);
  let packageManager: PackageManagerName = osFamily === "darwin" ? "brew" : familyToPackageManager(family);

  if (family === "rhel") {
    const hasDnf = await binaryExists("dnf");
    packageManager = hasDnf ? "dnf" : "yum";
  }

  let initSystem: InitSystem = "unknown";
  if (osFamily === "darwin") {
    initSystem = "launchd";
  } else if (existsSync("/run/systemd/system")) {
    initSystem = "systemd";
  } else if (existsSync("/sbin/openrc-run")) {
    initSystem = "openrc";
  } else if (existsSync("/etc/init.d")) {
    initSystem = "sysvinit";
  }

  const [hasFirewalld, hasUfw, hasSelinux, hasApparmor] = await Promise.all([
    binaryExists("firewall-cmd"),
    binaryExists("ufw"),
    binaryExists("getenforce"),
    binaryExists("apparmor_status"),
  ]);

  cachedDistro = {
    id, name, version,
    osFamily, specificDistro, family,
    packageManager, initSystem,
    hasFirewalld, hasUfw, hasSelinux, hasApparmor,
  };

  console.error(
    `[distro] Detected: ${name} (${id}) osFamily=${osFamily} family=${family} pkg=${packageManager} init=${initSystem}`
  );

  return cachedDistro;
}

// ── PackageManager factory ───────────────────────────────────────────────────

export function getPackageManager(nameOrDistro?: string): PackageManagerCommands {
  const mgr = resolvePackageManagerName(nameOrDistro);
  switch (mgr) {
    case "apt": return {
      installCmd: (pkg) => ["apt-get", "install", "-y", pkg],
      removeCmd: (pkg) => ["apt-get", "remove", "-y", pkg],
      updateCmd: () => ["apt-get", "update"],
      searchCmd: (term) => ["apt-cache", "search", term],
      listInstalledCmd: () => ["dpkg", "--get-selections"],
    };
    case "dnf": return {
      installCmd: (pkg) => ["dnf", "install", "-y", pkg],
      removeCmd: (pkg) => ["dnf", "remove", "-y", pkg],
      updateCmd: () => ["dnf", "check-update"],
      searchCmd: (term) => ["dnf", "search", term],
      listInstalledCmd: () => ["dnf", "list", "installed"],
    };
    case "yum": return {
      installCmd: (pkg) => ["yum", "install", "-y", pkg],
      removeCmd: (pkg) => ["yum", "remove", "-y", pkg],
      updateCmd: () => ["yum", "check-update"],
      searchCmd: (term) => ["yum", "search", term],
      listInstalledCmd: () => ["yum", "list", "installed"],
    };
    case "pacman": return {
      installCmd: (pkg) => ["pacman", "-S", "--noconfirm", pkg],
      removeCmd: (pkg) => ["pacman", "-R", "--noconfirm", pkg],
      updateCmd: () => ["pacman", "-Sy"],
      searchCmd: (term) => ["pacman", "-Ss", term],
      listInstalledCmd: () => ["pacman", "-Q"],
    };
    case "brew": return {
      installCmd: (pkg) => ["brew", "install", pkg],
      removeCmd: (pkg) => ["brew", "uninstall", pkg],
      updateCmd: () => ["brew", "update"],
      searchCmd: (term) => ["brew", "search", term],
      listInstalledCmd: () => ["brew", "list"],
    };
    case "apk": return {
      installCmd: (pkg) => ["apk", "add", pkg],
      removeCmd: (pkg) => ["apk", "del", pkg],
      updateCmd: () => ["apk", "update"],
      searchCmd: (term) => ["apk", "search", term],
      listInstalledCmd: () => ["apk", "info"],
    };
    case "zypper": return {
      installCmd: (pkg) => ["zypper", "install", "-y", pkg],
      removeCmd: (pkg) => ["zypper", "remove", "-y", pkg],
      updateCmd: () => ["zypper", "refresh"],
      searchCmd: (term) => ["zypper", "search", term],
      listInstalledCmd: () => ["zypper", "packages", "--installed-only"],
    };
    default: return {
      installCmd: (pkg) => ["echo", `[unknown-pkg-mgr] install ${pkg}`],
      removeCmd: (pkg) => ["echo", `[unknown-pkg-mgr] remove ${pkg}`],
      updateCmd: () => ["echo", "[unknown-pkg-mgr] update"],
      searchCmd: (term) => ["echo", `[unknown-pkg-mgr] search ${term}`],
      listInstalledCmd: () => ["echo", "[unknown-pkg-mgr] list-installed"],
    };
  }
}

function resolvePackageManagerName(input?: string): PackageManagerName {
  if (!input) return "unknown";
  const lower = input.toLowerCase().trim();
  const directNames: PackageManagerName[] = ["apt", "dnf", "yum", "pacman", "brew", "apk", "zypper"];
  if (directNames.includes(lower as PackageManagerName)) return lower as PackageManagerName;
  switch (lower) {
    case "debian": case "ubuntu": case "kali": return "apt";
    case "fedora": case "rhel": case "centos": return "dnf";
    case "arch": return "pacman";
    case "alpine": return "apk";
    case "opensuse": return "zypper";
    case "macos": return "brew";
    default: return "unknown";
  }
}

// ── ServiceManager factory ───────────────────────────────────────────────────

function detectInitSystemSync(): InitSystem {
  if (process.platform === "darwin") return "launchd";
  if (existsSync("/run/systemd/system")) return "systemd";
  if (existsSync("/sbin/openrc-run")) return "openrc";
  if (existsSync("/etc/init.d")) return "sysvinit";
  return "unknown";
}

export function getServiceManager(initSystem?: InitSystem): ServiceManagerCommands {
  const system = initSystem ?? detectInitSystemSync();
  switch (system) {
    case "systemd": return {
      startCmd: (svc) => ["systemctl", "start", svc],
      stopCmd: (svc) => ["systemctl", "stop", svc],
      enableCmd: (svc) => ["systemctl", "enable", svc],
      disableCmd: (svc) => ["systemctl", "disable", svc],
      statusCmd: (svc) => ["systemctl", "status", svc],
      listServicesCmd: () => ["systemctl", "list-units", "--type=service", "--all"],
    };
    case "launchd": return {
      startCmd: (svc) => ["launchctl", "start", svc],
      stopCmd: (svc) => ["launchctl", "stop", svc],
      enableCmd: (svc) => ["launchctl", "load", "-w", svc],
      disableCmd: (svc) => ["launchctl", "unload", "-w", svc],
      statusCmd: (svc) => ["launchctl", "list", svc],
      listServicesCmd: () => ["launchctl", "list"],
    };
    case "openrc": return {
      startCmd: (svc) => ["rc-service", svc, "start"],
      stopCmd: (svc) => ["rc-service", svc, "stop"],
      enableCmd: (svc) => ["rc-update", "add", svc, "default"],
      disableCmd: (svc) => ["rc-update", "del", svc, "default"],
      statusCmd: (svc) => ["rc-service", svc, "status"],
      listServicesCmd: () => ["rc-status", "--all"],
    };
    default: return {
      startCmd: (svc) => ["service", svc, "start"],
      stopCmd: (svc) => ["service", svc, "stop"],
      enableCmd: (svc) => ["update-rc.d", svc, "enable"],
      disableCmd: (svc) => ["update-rc.d", svc, "disable"],
      statusCmd: (svc) => ["service", svc, "status"],
      listServicesCmd: () => ["service", "--status-all"],
    };
  }
}

// ── Firewall Backend factory ─────────────────────────────────────────────────

function buildFirewallBackend(fbName: FirewallBackendName): FirewallBackendCommands {
  switch (fbName) {
    case "ufw": return {
      name: fbName,
      allowCmd: (port, proto = "tcp") => ["ufw", "allow", `${port}/${proto}`],
      denyCmd: (port, proto = "tcp") => ["ufw", "deny", `${port}/${proto}`],
      listCmd: () => ["ufw", "status", "verbose"],
      flushCmd: () => ["ufw", "reset"],
    };
    case "firewalld": return {
      name: fbName,
      allowCmd: (port, proto = "tcp") => ["firewall-cmd", "--permanent", `--add-port=${port}/${proto}`],
      denyCmd: (port, proto = "tcp") => ["firewall-cmd", "--permanent", `--remove-port=${port}/${proto}`],
      listCmd: () => ["firewall-cmd", "--list-all"],
      flushCmd: () => ["firewall-cmd", "--complete-reload"],
    };
    case "nftables": return {
      name: fbName,
      allowCmd: (port, proto = "tcp") => ["nft", "add", "rule", "inet", "filter", "input", proto, "dport", String(port), "accept"],
      denyCmd: (port, proto = "tcp") => ["nft", "add", "rule", "inet", "filter", "input", proto, "dport", String(port), "drop"],
      listCmd: () => ["nft", "list", "ruleset"],
      flushCmd: () => ["nft", "flush", "ruleset"],
    };
    case "iptables": return {
      name: fbName,
      allowCmd: (port, proto = "tcp") => ["iptables", "-A", "INPUT", "-p", proto, "--dport", String(port), "-j", "ACCEPT"],
      denyCmd: (port, proto = "tcp") => ["iptables", "-A", "INPUT", "-p", proto, "--dport", String(port), "-j", "DROP"],
      listCmd: () => ["iptables", "-L", "-n", "-v"],
      flushCmd: () => ["iptables", "-F"],
    };
    case "pf": return {
      name: fbName,
      allowCmd: (port, proto = "tcp") => ["pfctl", "-e", "-f", "-"],
      denyCmd: (port, proto = "tcp") => ["pfctl", "-e", "-f", "-"],
      listCmd: () => ["pfctl", "-sr"],
      flushCmd: () => ["pfctl", "-F", "all"],
    };
    default: return {
      name: "unknown",
      allowCmd: () => ["echo", "[unknown-firewall] allow"],
      denyCmd: () => ["echo", "[unknown-firewall] deny"],
      listCmd: () => ["echo", "[unknown-firewall] list"],
      flushCmd: () => ["echo", "[unknown-firewall] flush"],
    };
  }
}

export async function getFirewallBackend(): Promise<FirewallBackendCommands> {
  const [hasUfwBin, hasFirewalldBin, hasNft, hasIptables, hasPf] = await Promise.all([
    binaryExists("ufw"),
    binaryExists("firewall-cmd"),
    binaryExists("nft"),
    binaryExists("iptables"),
    binaryExists("pfctl"),
  ]);
  if (hasUfwBin) return buildFirewallBackend("ufw");
  if (hasFirewalldBin) return buildFirewallBackend("firewalld");
  if (hasNft) return buildFirewallBackend("nftables");
  if (hasIptables) return buildFirewallBackend("iptables");
  if (hasPf) return buildFirewallBackend("pf");
  return buildFirewallBackend("unknown");
}

// ── Capability detection ─────────────────────────────────────────────────────

async function safeCap(fn: () => Promise<boolean>): Promise<boolean> {
  try { return await fn(); } catch { return false; }
}

async function fileReadable(path: string): Promise<boolean> {
  try { await readFile(path, "utf-8"); return true; } catch { return false; }
}

export async function canUseAppArmor(): Promise<boolean> {
  return safeCap(async () => (await binaryExists("apparmor_status")) || (await fileReadable("/sys/kernel/security/apparmor")));
}

export async function canUseSELinux(): Promise<boolean> {
  return safeCap(async () => (await binaryExists("getenforce")) || (await fileReadable("/sys/fs/selinux")));
}

export async function canUseAuditd(): Promise<boolean> {
  return safeCap(() => binaryExists("auditctl"));
}

export async function canUseSystemd(): Promise<boolean> {
  return safeCap(async () => existsSync("/run/systemd/system"));
}

export async function canUseIPTables(): Promise<boolean> {
  return safeCap(() => binaryExists("iptables"));
}

export async function canUseNFTables(): Promise<boolean> {
  return safeCap(() => binaryExists("nft"));
}

export async function canUseBPF(): Promise<boolean> {
  return safeCap(async () => (await binaryExists("bpftool")) || existsSync("/sys/fs/bpf"));
}

export async function hasTPM(): Promise<boolean> {
  return safeCap(async () => existsSync("/dev/tpm0") || existsSync("/dev/tpmrm0"));
}

export async function hasSecureBoot(): Promise<boolean> {
  return safeCap(async () => {
    const r = await executeCommand({ command: "mokutil", args: ["--sb-state"], timeout: 5000 });
    return r.exitCode === 0 && r.stdout.toLowerCase().includes("secureboot enabled");
  });
}

// ── Legacy helpers (backwards compatibility) ─────────────────────────────────

/** @deprecated Prefer getPackageManager(pkgManager).installCmd(pkg) */
export function getInstallCommand(pkgManager: PackageManagerName, pkg: string): string[] {
  return getPackageManager(pkgManager).installCmd(pkg);
}

/** @deprecated Prefer getPackageManager(pkgManager).updateCmd() */
export function getUpdateCommand(pkgManager: PackageManagerName): string[] {
  return getPackageManager(pkgManager).updateCmd();
}
