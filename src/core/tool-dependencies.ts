/**
 * Tool-to-dependency mapping for Defense MCP Server.
 *
 * Maps each registered MCP tool name to the system binaries it requires.
 * Used by the dependency validator to ensure all required tools are
 * installed before execution — either at server startup or on-demand.
 *
 * v0.7.0: Final consolidation to 31 tools across 18 modules.
 * Each entry represents a consolidated tool whose dependencies are the
 * UNION of all the individual tools it absorbed. Action-specific binaries
 * are listed as `optionalBinaries` because the tool handles missing ones
 * gracefully based on which `action` the caller selects.
 */

import { DEFENSIVE_TOOLS, type ToolRequirement } from "./installer.js";

// ── Types ────────────────────────────────────────────────────────────────────

/**
 * Dependency specification for an MCP tool.
 */
export interface ToolDependency {
  /** The MCP tool name (e.g. "ids_rootkit_scan") */
  toolName: string;
  /** System binaries required for this tool to function */
  requiredBinaries: string[];
  /** System binaries that are optional (enhance functionality) */
  optionalBinaries?: string[];
  /** Whether this tool is critical (server should warn loudly if deps missing) */
  critical?: boolean;
}

// ── Binary → ToolRequirement lookup ──────────────────────────────────────────

/**
 * Quick lookup from binary name to its ToolRequirement definition.
 * Used to resolve package names for installation.
 */
const binaryToToolReq = new Map<string, ToolRequirement>();
for (const tool of DEFENSIVE_TOOLS) {
  binaryToToolReq.set(tool.binary, tool);
}

/**
 * Returns the ToolRequirement for a given binary name, if known.
 */
export function getToolRequirementForBinary(
  binary: string
): ToolRequirement | undefined {
  return binaryToToolReq.get(binary);
}

// ── Tool Dependency Registry ─────────────────────────────────────────────────

/**
 * Complete mapping of MCP tool names to their system binary dependencies.
 *
 * 31 consolidated tools across 18 modules (v0.7.0).  Each entry specifies:
 * - requiredBinaries: must be present for the tool to work at all
 * - optionalBinaries: enhance functionality but aren't strictly needed
 * - critical: if true, missing deps trigger a startup warning
 */
export const TOOL_DEPENDENCIES: ToolDependency[] = [
  // ── Firewall (1) ──────────────────────────────────────────────────────────
  {
    toolName: "firewall",
    requiredBinaries: ["iptables", "ip6tables", "ufw", "nft"],
    critical: true,
  },

  // ── Hardening (2) ─────────────────────────────────────────────────────────
  {
    toolName: "harden_kernel",
    requiredBinaries: ["sysctl", "grep", "cat", "mokutil"],
    critical: true,
  },
  {
    toolName: "harden_host",
    requiredBinaries: ["systemctl", "systemd-analyze", "chmod", "chown", "stat"],
    critical: true,
  },

  // ── Access Control (1) ────────────────────────────────────────────────────
  {
    toolName: "access_control",
    requiredBinaries: ["ssh", "sshd", "pam-auth-update"],
    critical: true,
  },

  // ── Compliance (1) ────────────────────────────────────────────────────────
  {
    toolName: "compliance",
    requiredBinaries: ["lynis", "oscap", "auditctl"],
    critical: true,
  },

  // ── Integrity (1) — AIDE + rootkit + file integrity + drift detection ──────
  {
    toolName: "integrity",
    requiredBinaries: ["aide", "rkhunter", "chkrootkit", "sha256sum"],
    critical: true,
  },

  // ── Logging (1) ───────────────────────────────────────────────────────────
  {
    toolName: "log_management",
    requiredBinaries: ["auditctl", "ausearch", "aureport", "journalctl", "fail2ban-client", "rsyslog"],
    critical: true,
  },

  // ── Malware (1) ───────────────────────────────────────────────────────────
  {
    toolName: "malware",
    requiredBinaries: ["clamscan", "freshclam", "yara"],
    critical: true,
  },

  // ── Container (2) ─────────────────────────────────────────────────────────
  {
    toolName: "container_docker",
    requiredBinaries: ["docker", "trivy"],
  },
  {
    toolName: "container_isolation",
    requiredBinaries: ["aa-status", "apparmor_parser", "setenforce", "getenforce"],
  },

  // ── eBPF (1) ──────────────────────────────────────────────────────────────
  {
    toolName: "ebpf",
    requiredBinaries: ["bpftool", "falco"],
  },

  // ── Crypto (1) ────────────────────────────────────────────────────────────
  {
    toolName: "crypto",
    requiredBinaries: ["openssl", "gpg", "cryptsetup", "sha256sum"],
    critical: true,
  },

  // ── Network Defense (1) ───────────────────────────────────────────────────
  {
    toolName: "network_defense",
    requiredBinaries: ["ss", "tcpdump", "nmap", "ip"],
    critical: true,
  },

  // ── Patch Management (1) ──────────────────────────────────────────────────
  {
    toolName: "patch",
    requiredBinaries: ["apt-get", "apt", "dpkg", "rpm"],
    optionalBinaries: ["debsums", "livepatch"],
  },

  // ── Secrets (1) ───────────────────────────────────────────────────────────
  {
    toolName: "secrets",
    requiredBinaries: ["grep", "find", "git"],
  },

  // ── Incident Response (1) ─────────────────────────────────────────────────
  {
    toolName: "incident_response",
    requiredBinaries: ["ss", "ps", "netstat", "dd", "tcpdump"],
  },

  // ── Defense Management (1) ────────────────────────────────────────────────
  {
    toolName: "defense_mgmt",
    requiredBinaries: ["lynis"],
    optionalBinaries: ["iptables", "ss", "journalctl", "apt", "sysctl", "systemctl"],
  },

  // ── Sudo Session (1) ──────────────────────────────────────────────────────
  {
    toolName: "sudo_session",
    requiredBinaries: ["sudo"],
  },

  // ── Solo Tools (13) ───────────────────────────────────────────────────────
  {
    toolName: "api_security",
    requiredBinaries: ["curl"],
    optionalBinaries: ["openssl", "ss"],
  },
  {
    toolName: "app_harden",
    requiredBinaries: [],
    optionalBinaries: ["ps", "ss", "systemctl", "iptables"],
  },
  {
    toolName: "backup",
    requiredBinaries: [],
    optionalBinaries: ["cp", "cat", "sha256sum", "ls", "dpkg", "systemctl", "iptables-save", "ss"],
  },
  {
    toolName: "cloud_security",
    requiredBinaries: ["curl"],
    optionalBinaries: ["cat", "stat", "aws", "gsutil", "az", "cloud-init"],
  },
  {
    toolName: "honeypot_manage",
    requiredBinaries: [],
    optionalBinaries: ["ncat", "inotifywait", "iptables", "stat"],
  },
  {
    toolName: "dns_security",
    requiredBinaries: [],
    optionalBinaries: ["dig", "systemd-resolve", "resolvectl", "tcpdump", "cat", "grep"],
  },
  {
    toolName: "process_security",
    requiredBinaries: ["ps"],
    optionalBinaries: ["getpcaps", "capsh", "lsns", "ss"],
  },
  {
    toolName: "supply_chain",
    requiredBinaries: [],
    optionalBinaries: ["syft", "cdxgen", "dpkg", "debsums", "cosign", "slsa-verifier"],
  },
  {
    toolName: "threat_intel",
    requiredBinaries: ["curl"],
    optionalBinaries: ["wget", "fail2ban-client", "iptables", "grep", "whois", "dig"],
  },
  {
    toolName: "vuln_manage",
    requiredBinaries: ["nmap"],
    optionalBinaries: ["nikto", "searchsploit"],
  },
  {
    toolName: "waf_manage",
    requiredBinaries: [],
    optionalBinaries: ["cat", "grep", "sed", "dpkg", "apache2ctl"],
  },
  {
    toolName: "wireless_security",
    requiredBinaries: [],
    optionalBinaries: ["hciconfig", "bluetoothctl", "iw", "nmcli", "rfkill", "lsmod"],
  },
  {
    toolName: "zero_trust",
    requiredBinaries: [],
    optionalBinaries: ["wg", "openssl", "iptables"],
  },
];

// ── Lookup helpers ───────────────────────────────────────────────────────────

/** Map for O(1) lookup by tool name */
const toolDependencyMap = new Map<string, ToolDependency>();
for (const dep of TOOL_DEPENDENCIES) {
  toolDependencyMap.set(dep.toolName, dep);
}

/**
 * Returns the dependency specification for a given MCP tool name.
 */
export function getDependenciesForTool(
  toolName: string
): ToolDependency | undefined {
  return toolDependencyMap.get(toolName);
}

/**
 * Returns all unique required binaries across all tools.
 */
export function getAllRequiredBinaries(): string[] {
  const binaries = new Set<string>();
  for (const dep of TOOL_DEPENDENCIES) {
    for (const bin of dep.requiredBinaries) {
      binaries.add(bin);
    }
  }
  return Array.from(binaries);
}

/**
 * Returns all unique binaries (required + optional) across all tools.
 */
export function getAllBinaries(): { required: string[]; optional: string[] } {
  const required = new Set<string>();
  const optional = new Set<string>();
  for (const dep of TOOL_DEPENDENCIES) {
    for (const bin of dep.requiredBinaries) {
      required.add(bin);
    }
    for (const bin of dep.optionalBinaries ?? []) {
      if (!required.has(bin)) {
        optional.add(bin);
      }
    }
  }
  return {
    required: Array.from(required),
    optional: Array.from(optional),
  };
}

/**
 * Returns all critical tool dependencies (tools that should always work).
 */
export function getCriticalDependencies(): ToolDependency[] {
  return TOOL_DEPENDENCIES.filter((d) => d.critical);
}
