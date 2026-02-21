import { executeCommand } from "./executor.js";
import {
  detectDistro,
  getInstallCommand,
  getUpdateCommand,
  type PackageManager,
} from "./distro.js";
import { getConfig } from "./config.js";

/**
 * Category of a defensive tool.
 */
export type ToolCategory =
  | "hardening"
  | "firewall"
  | "monitoring"
  | "assessment"
  | "network"
  | "access"
  | "access-control"
  | "encryption"
  | "container"
  | "malware"
  | "forensics"
  | "integrity"
  | "compliance"
  | "logging";

/**
 * Package names per distribution family.
 */
export interface PackageNames {
  debian?: string;
  rhel?: string;
  arch?: string;
  alpine?: string;
  suse?: string;
  fallback?: string;
}

/**
 * Requirements for a defensive tool.
 */
export interface ToolRequirement {
  /** Human-readable tool name */
  name: string;
  /** Binary name to check for availability */
  binary: string;
  /** Package names per distribution */
  packages: PackageNames;
  /** Category of the tool */
  category: ToolCategory;
  /** Whether the tool is required (vs optional) */
  required: boolean;
  /** If this tool is an alternative for another */
  alternativeFor?: string;
}

/**
 * Result of checking a tool's availability.
 */
export interface ToolCheckResult {
  /** Tool requirement info */
  tool: ToolRequirement;
  /** Whether the tool is installed */
  installed: boolean;
  /** Detected version string (if available) */
  version?: string;
  /** Path to the binary (if found) */
  path?: string;
}

/**
 * Result of installing a tool.
 */
export interface InstallResult {
  /** Tool requirement info */
  tool: ToolRequirement;
  /** Whether installation succeeded */
  success: boolean;
  /** Output/error message */
  message: string;
}

/**
 * Comprehensive list of defensive security tools across categories.
 */
export const DEFENSIVE_TOOLS: ToolRequirement[] = [
  // ─── Hardening ────────────────────────────────────────────
  {
    name: "Lynis",
    binary: "lynis",
    packages: {
      debian: "lynis",
      rhel: "lynis",
      arch: "lynis",
      alpine: "lynis",
      suse: "lynis",
      fallback: "lynis",
    },
    category: "hardening",
    required: true,
  },
  {
    name: "AIDE",
    binary: "aide",
    packages: {
      debian: "aide",
      rhel: "aide",
      arch: "aide",
      alpine: "aide",
      suse: "aide",
      fallback: "aide",
    },
    category: "hardening",
    required: true,
  },
  {
    name: "Auditd",
    binary: "auditctl",
    packages: {
      debian: "auditd",
      rhel: "audit",
      arch: "audit",
      alpine: "audit",
      suse: "audit",
      fallback: "auditd",
    },
    category: "hardening",
    required: true,
  },
  {
    name: "Sysstat",
    binary: "sar",
    packages: {
      debian: "sysstat",
      rhel: "sysstat",
      arch: "sysstat",
      alpine: "sysstat",
      suse: "sysstat",
      fallback: "sysstat",
    },
    category: "hardening",
    required: false,
  },

  // ─── Firewall ─────────────────────────────────────────────
  {
    name: "iptables",
    binary: "iptables",
    packages: {
      debian: "iptables",
      rhel: "iptables",
      arch: "iptables",
      alpine: "iptables",
      suse: "iptables",
      fallback: "iptables",
    },
    category: "firewall",
    required: true,
  },
  {
    name: "nftables",
    binary: "nft",
    packages: {
      debian: "nftables",
      rhel: "nftables",
      arch: "nftables",
      alpine: "nftables",
      suse: "nftables",
      fallback: "nftables",
    },
    category: "firewall",
    required: false,
    alternativeFor: "iptables",
  },
  {
    name: "UFW",
    binary: "ufw",
    packages: {
      debian: "ufw",
      rhel: "ufw",
      arch: "ufw",
      alpine: "ufw",
      suse: "ufw",
      fallback: "ufw",
    },
    category: "firewall",
    required: false,
  },
  {
    name: "Fail2ban",
    binary: "fail2ban-client",
    packages: {
      debian: "fail2ban",
      rhel: "fail2ban",
      arch: "fail2ban",
      alpine: "fail2ban",
      suse: "fail2ban",
      fallback: "fail2ban",
    },
    category: "firewall",
    required: true,
  },

  // ─── Monitoring ───────────────────────────────────────────
  {
    name: "htop",
    binary: "htop",
    packages: {
      debian: "htop",
      rhel: "htop",
      arch: "htop",
      alpine: "htop",
      suse: "htop",
      fallback: "htop",
    },
    category: "monitoring",
    required: false,
  },
  {
    name: "lsof",
    binary: "lsof",
    packages: {
      debian: "lsof",
      rhel: "lsof",
      arch: "lsof",
      alpine: "lsof",
      suse: "lsof",
      fallback: "lsof",
    },
    category: "monitoring",
    required: true,
  },
  {
    name: "strace",
    binary: "strace",
    packages: {
      debian: "strace",
      rhel: "strace",
      arch: "strace",
      alpine: "strace",
      suse: "strace",
      fallback: "strace",
    },
    category: "monitoring",
    required: false,
  },
  {
    name: "inotify-tools",
    binary: "inotifywait",
    packages: {
      debian: "inotify-tools",
      rhel: "inotify-tools",
      arch: "inotify-tools",
      alpine: "inotify-tools",
      suse: "inotify-tools",
      fallback: "inotify-tools",
    },
    category: "monitoring",
    required: false,
  },
  {
    name: "Snort",
    binary: "snort",
    packages: {
      debian: "snort",
      rhel: "snort",
      arch: "snort",
      alpine: "snort",
      suse: "snort",
      fallback: "snort",
    },
    category: "monitoring",
    required: false,
  },
  {
    name: "Suricata",
    binary: "suricata",
    packages: {
      debian: "suricata",
      rhel: "suricata",
      arch: "suricata",
      alpine: "suricata",
      suse: "suricata",
      fallback: "suricata",
    },
    category: "monitoring",
    required: false,
    alternativeFor: "snort",
  },

  // ─── Assessment ───────────────────────────────────────────
  {
    name: "ClamAV",
    binary: "clamscan",
    packages: {
      debian: "clamav",
      rhel: "clamav",
      arch: "clamav",
      alpine: "clamav",
      suse: "clamav",
      fallback: "clamav",
    },
    category: "assessment",
    required: true,
  },
  {
    name: "rkhunter",
    binary: "rkhunter",
    packages: {
      debian: "rkhunter",
      rhel: "rkhunter",
      arch: "rkhunter",
      alpine: "rkhunter",
      suse: "rkhunter",
      fallback: "rkhunter",
    },
    category: "assessment",
    required: true,
  },
  {
    name: "chkrootkit",
    binary: "chkrootkit",
    packages: {
      debian: "chkrootkit",
      rhel: "chkrootkit",
      arch: "chkrootkit",
      alpine: "chkrootkit",
      suse: "chkrootkit",
      fallback: "chkrootkit",
    },
    category: "assessment",
    required: false,
    alternativeFor: "rkhunter",
  },
  {
    name: "OpenSCAP",
    binary: "oscap",
    packages: {
      debian: "libopenscap8",
      rhel: "openscap-scanner",
      arch: "openscap",
      alpine: "openscap",
      suse: "openscap-utils",
      fallback: "openscap-scanner",
    },
    category: "assessment",
    required: false,
  },
  {
    name: "YARA",
    binary: "yara",
    packages: {
      debian: "yara",
      rhel: "yara",
      arch: "yara",
      alpine: "yara",
      suse: "yara",
      fallback: "yara",
    },
    category: "assessment",
    required: false,
  },

  // ─── Network ──────────────────────────────────────────────
  {
    name: "Nmap",
    binary: "nmap",
    packages: {
      debian: "nmap",
      rhel: "nmap",
      arch: "nmap",
      alpine: "nmap",
      suse: "nmap",
      fallback: "nmap",
    },
    category: "network",
    required: true,
  },
  {
    name: "tcpdump",
    binary: "tcpdump",
    packages: {
      debian: "tcpdump",
      rhel: "tcpdump",
      arch: "tcpdump",
      alpine: "tcpdump",
      suse: "tcpdump",
      fallback: "tcpdump",
    },
    category: "network",
    required: true,
  },
  {
    name: "ss",
    binary: "ss",
    packages: {
      debian: "iproute2",
      rhel: "iproute",
      arch: "iproute2",
      alpine: "iproute2",
      suse: "iproute2",
      fallback: "iproute2",
    },
    category: "network",
    required: true,
  },
  {
    name: "curl",
    binary: "curl",
    packages: {
      debian: "curl",
      rhel: "curl",
      arch: "curl",
      alpine: "curl",
      suse: "curl",
      fallback: "curl",
    },
    category: "network",
    required: true,
  },

  // ─── Access Control ───────────────────────────────────────
  {
    name: "sudo",
    binary: "sudo",
    packages: {
      debian: "sudo",
      rhel: "sudo",
      arch: "sudo",
      alpine: "sudo",
      suse: "sudo",
      fallback: "sudo",
    },
    category: "access",
    required: true,
  },
  {
    name: "AppArmor",
    binary: "apparmor_status",
    packages: {
      debian: "apparmor",
      rhel: "apparmor",
      arch: "apparmor",
      alpine: "apparmor",
      suse: "apparmor",
      fallback: "apparmor",
    },
    category: "access",
    required: false,
  },
  {
    name: "SELinux utilities",
    binary: "getenforce",
    packages: {
      debian: "selinux-utils",
      rhel: "libselinux-utils",
      arch: "selinux-utils",
      alpine: "selinux-utils",
      suse: "selinux-tools",
      fallback: "selinux-utils",
    },
    category: "access",
    required: false,
    alternativeFor: "apparmor",
  },

  // ─── Encryption ───────────────────────────────────────────
  {
    name: "OpenSSL",
    binary: "openssl",
    packages: {
      debian: "openssl",
      rhel: "openssl",
      arch: "openssl",
      alpine: "openssl",
      suse: "openssl",
      fallback: "openssl",
    },
    category: "encryption",
    required: true,
  },
  {
    name: "GnuPG",
    binary: "gpg",
    packages: {
      debian: "gnupg",
      rhel: "gnupg2",
      arch: "gnupg",
      alpine: "gnupg",
      suse: "gpg2",
      fallback: "gnupg",
    },
    category: "encryption",
    required: false,
  },
  {
    name: "cryptsetup",
    binary: "cryptsetup",
    packages: {
      debian: "cryptsetup",
      rhel: "cryptsetup",
      arch: "cryptsetup",
      alpine: "cryptsetup",
      suse: "cryptsetup",
      fallback: "cryptsetup",
    },
    category: "encryption",
    required: false,
  },

  // ─── Integrity ────────────────────────────────────────────
  {
    name: "debsums",
    binary: "debsums",
    packages: {
      debian: "debsums",
      rhel: "debsums",
      arch: "debsums",
      alpine: "debsums",
      suse: "debsums",
      fallback: "debsums",
    },
    category: "integrity",
    required: false,
  },

  // ─── Access Control ───────────────────────────────────────
  {
    name: "libpam-pwquality",
    binary: "pam_pwquality",
    packages: {
      debian: "libpam-pwquality",
      rhel: "libpam-pwquality",
      arch: "libpam-pwquality",
      alpine: "libpam-pwquality",
      suse: "libpam-pwquality",
      fallback: "libpam-pwquality",
    },
    category: "access-control",
    required: false,
  },

  // ─── Compliance ───────────────────────────────────────────
  {
    name: "chrony",
    binary: "chronyd",
    packages: {
      debian: "chrony",
      rhel: "chrony",
      arch: "chrony",
      alpine: "chrony",
      suse: "chrony",
      fallback: "chrony",
    },
    category: "compliance",
    required: false,
  },

  // ─── Logging ──────────────────────────────────────────────
  {
    name: "acct",
    binary: "accton",
    packages: {
      debian: "acct",
      rhel: "acct",
      arch: "acct",
      alpine: "acct",
      suse: "acct",
      fallback: "acct",
    },
    category: "logging",
    required: false,
  },

  // ─── Firewall (persistent) ────────────────────────────────
  {
    name: "iptables-persistent",
    binary: "netfilter-persistent",
    packages: {
      debian: "iptables-persistent",
      rhel: "iptables-persistent",
      arch: "iptables-persistent",
      alpine: "iptables-persistent",
      suse: "iptables-persistent",
      fallback: "iptables-persistent",
    },
    category: "firewall",
    required: false,
  },

  // ─── Container ────────────────────────────────────────────
  {
    name: "Docker",
    binary: "docker",
    packages: {
      debian: "docker.io",
      rhel: "docker-ce",
      arch: "docker",
      alpine: "docker",
      suse: "docker",
      fallback: "docker",
    },
    category: "container",
    required: false,
  },
];

/**
 * Checks whether a tool binary is available on the system.
 * Uses `which` to find the binary, then attempts `--version` for version info.
 */
export async function checkTool(
  binary: string
): Promise<{ installed: boolean; version?: string; path?: string }> {
  // Check if binary exists
  const whichResult = await executeCommand({
    command: "which",
    args: [binary],
    timeout: 5000,
  });

  if (whichResult.exitCode !== 0) {
    return { installed: false };
  }

  const binaryPath = whichResult.stdout.trim();

  // Try to get version
  let version: string | undefined;
  const versionResult = await executeCommand({
    command: binary,
    args: ["--version"],
    timeout: 5000,
  });

  if (versionResult.exitCode === 0) {
    // Take first line of version output
    version = versionResult.stdout.trim().split("\n")[0];
  } else {
    // Some tools use -v or -V instead
    const altResult = await executeCommand({
      command: binary,
      args: ["-V"],
      timeout: 5000,
    });
    if (altResult.exitCode === 0) {
      version = altResult.stdout.trim().split("\n")[0];
    }
  }

  return { installed: true, version, path: binaryPath };
}

/**
 * Checks all defensive tools or a specific category.
 *
 * @param category Optional category to filter by
 * @returns Array of check results
 */
export async function checkAllTools(
  category?: ToolCategory
): Promise<ToolCheckResult[]> {
  const tools = category
    ? DEFENSIVE_TOOLS.filter((t) => t.category === category)
    : DEFENSIVE_TOOLS;

  const results: ToolCheckResult[] = [];

  for (const tool of tools) {
    const check = await checkTool(tool.binary);
    results.push({
      tool,
      installed: check.installed,
      version: check.version,
      path: check.path,
    });
  }

  return results;
}

/**
 * Installs a tool using the detected distribution's package manager.
 *
 * @param tool Tool requirement to install
 * @returns Installation result
 */
export async function installTool(
  tool: ToolRequirement
): Promise<InstallResult> {
  const distro = await detectDistro();
  const pkgManager = distro.packageManager;

  if (pkgManager === "unknown") {
    return {
      tool,
      success: false,
      message: "Cannot install: unknown package manager",
    };
  }

  // Determine the package name for this distro
  const pkgName =
    (tool.packages as Record<string, string | undefined>)[distro.family] ??
    tool.packages.fallback;

  if (!pkgName) {
    return {
      tool,
      success: false,
      message: `No package name configured for ${distro.family}`,
    };
  }

  console.error(`[installer] Installing ${tool.name} (${pkgName}) via ${pkgManager}`);

  // Run package manager update first
  const updateCmd = getUpdateCommand(pkgManager);
  await executeCommand({
    command: updateCmd[0],
    args: updateCmd.slice(1),
    timeout: 120_000,
  });

  // Install the package
  const installCmd = getInstallCommand(pkgManager, pkgName);
  const result = await executeCommand({
    command: installCmd[0],
    args: installCmd.slice(1),
    timeout: 300_000,
  });

  if (result.exitCode === 0) {
    return {
      tool,
      success: true,
      message: `Successfully installed ${tool.name} (${pkgName})`,
    };
  }

  return {
    tool,
    success: false,
    message: `Failed to install ${tool.name}: ${result.stderr || result.stdout}`,
  };
}

/**
 * Checks for missing tools and optionally installs them.
 *
 * @param category Optional category filter
 * @param dryRun If true, only report what would be installed
 * @returns Array of install results (or what would be installed)
 */
export async function installMissing(
  category?: ToolCategory,
  dryRun?: boolean
): Promise<InstallResult[]> {
  const config = getConfig();
  const effectiveDryRun = dryRun ?? config.dryRun;

  const checks = await checkAllTools(category);
  const missing = checks.filter((c) => !c.installed);

  if (missing.length === 0) {
    console.error("[installer] All tools are installed");
    return [];
  }

  console.error(
    `[installer] ${missing.length} tools missing: ${missing.map((m) => m.tool.name).join(", ")}`
  );

  const results: InstallResult[] = [];

  for (const check of missing) {
    if (effectiveDryRun) {
      results.push({
        tool: check.tool,
        success: false,
        message: `[DRY RUN] Would install ${check.tool.name}`,
      });
    } else {
      const result = await installTool(check.tool);
      results.push(result);
    }
  }

  return results;
}
