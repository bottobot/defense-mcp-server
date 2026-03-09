/**
 * Tool-to-dependency mapping for Kali Defense MCP Server.
 *
 * Maps each registered MCP tool name to the system binaries it requires.
 * Used by the dependency validator to ensure all required tools are
 * installed before execution — either at server startup or on-demand.
 *
 * After the v0.5.0 tool consolidation (157 → 78 tools), each entry here
 * represents a consolidated tool whose dependencies are the UNION of all
 * the individual tools it absorbed.  Action-specific binaries are listed
 * as `optionalBinaries` because the tool handles missing ones gracefully
 * based on which `action` the caller selects.
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
 * 78 consolidated tools across 21 modules.  Each entry specifies:
 * - requiredBinaries: must be present for the tool to work at all
 * - optionalBinaries: enhance functionality but aren't strictly needed
 * - critical: if true, missing deps trigger a startup warning
 */
export const TOOL_DEPENDENCIES: ToolDependency[] = [
  // ── Firewall Tools (5) ────────────────────────────────────────────────────
  {
    toolName: "firewall_iptables",
    requiredBinaries: ["iptables"],
    optionalBinaries: ["ip6tables"],
    critical: true,
  },
  {
    toolName: "firewall_ufw",
    requiredBinaries: ["ufw"],
  },
  {
    toolName: "firewall_persist",
    requiredBinaries: [],
    optionalBinaries: ["iptables-save", "iptables-restore", "ip6tables-save", "ip6tables-restore", "netfilter-persistent"],
  },
  {
    toolName: "firewall_nftables_list",
    requiredBinaries: ["nft"],
  },
  {
    toolName: "firewall_policy_audit",
    requiredBinaries: ["iptables"],
  },

  // ── Hardening Tools (8) ───────────────────────────────────────────────────
  {
    toolName: "harden_sysctl",
    requiredBinaries: ["sysctl"],
    critical: true,
  },
  {
    toolName: "harden_service",
    requiredBinaries: ["systemctl"],
    critical: true,
  },
  {
    toolName: "harden_permissions",
    requiredBinaries: ["stat"],
    optionalBinaries: ["chmod", "chown", "chgrp"],
  },
  {
    toolName: "harden_systemd",
    requiredBinaries: [],
    optionalBinaries: ["systemd-analyze", "systemctl"],
  },
  {
    toolName: "harden_kernel",
    requiredBinaries: ["cat"],
    optionalBinaries: ["lsmod", "modprobe", "sysctl"],
  },
  {
    toolName: "harden_bootloader",
    requiredBinaries: ["cat"],
    optionalBinaries: ["update-grub"],
  },
  {
    toolName: "harden_misc",
    requiredBinaries: ["cat"],
    optionalBinaries: ["tee"],
  },
  {
    toolName: "harden_memory",
    requiredBinaries: [],
    optionalBinaries: ["readelf", "checksec", "sysctl"],
  },

  // ── IDS Tools (3) ─────────────────────────────────────────────────────────
  {
    toolName: "ids_aide_manage",
    requiredBinaries: ["aide"],
    critical: true,
  },
  {
    toolName: "ids_rootkit_scan",
    requiredBinaries: [],
    optionalBinaries: ["rkhunter", "chkrootkit"],
    critical: true,
  },
  {
    toolName: "ids_file_integrity_check",
    requiredBinaries: ["sha256sum"],
  },

  // ── Logging Tools (4) ─────────────────────────────────────────────────────
  {
    toolName: "log_auditd",
    requiredBinaries: [],
    optionalBinaries: ["auditctl", "ausearch", "aureport"],
    critical: true,
  },
  {
    toolName: "log_journalctl_query",
    requiredBinaries: ["journalctl"],
    critical: true,
  },
  {
    toolName: "log_fail2ban",
    requiredBinaries: ["fail2ban-client"],
  },
  {
    toolName: "log_system",
    requiredBinaries: ["cat"],
    optionalBinaries: ["logrotate"],
  },

  // ── Network Defense Tools (3) ─────────────────────────────────────────────
  {
    toolName: "netdef_connections",
    requiredBinaries: ["ss"],
    critical: true,
  },
  {
    toolName: "netdef_capture",
    requiredBinaries: ["tcpdump"],
  },
  {
    toolName: "netdef_security_audit",
    requiredBinaries: [],
    optionalBinaries: ["cat", "nmap", "sysctl", "ip6tables"],
  },

  // ── Compliance Tools (7) ──────────────────────────────────────────────────
  {
    toolName: "compliance_lynis_audit",
    requiredBinaries: ["lynis"],
    critical: true,
  },
  {
    toolName: "compliance_oscap_scan",
    requiredBinaries: ["oscap"],
  },
  {
    toolName: "compliance_check",
    requiredBinaries: ["cat"],
    optionalBinaries: ["lynis", "oscap"],
  },
  {
    toolName: "compliance_policy_evaluate",
    requiredBinaries: ["cat"],
  },
  {
    toolName: "compliance_report",
    requiredBinaries: [],
    optionalBinaries: ["lynis"],
  },
  {
    toolName: "compliance_cron_restrict",
    requiredBinaries: ["cat"],
  },
  {
    toolName: "compliance_tmp_hardening",
    requiredBinaries: ["mount"],
  },

  // ── Malware Tools (4) ─────────────────────────────────────────────────────
  {
    toolName: "malware_clamav",
    requiredBinaries: [],
    optionalBinaries: ["clamscan", "freshclam"],
    critical: true,
  },
  {
    toolName: "malware_yara_scan",
    requiredBinaries: ["yara"],
  },
  {
    toolName: "malware_file_scan",
    requiredBinaries: [],
    optionalBinaries: ["find", "grep"],
  },
  {
    toolName: "malware_quarantine_manage",
    requiredBinaries: ["cat"],
  },

  // ── Backup Tools (1) ──────────────────────────────────────────────────────
  {
    toolName: "backup",
    requiredBinaries: [],
    optionalBinaries: ["cp", "cat", "sha256sum", "ls", "dpkg", "systemctl", "iptables-save", "ss"],
  },

  // ── Access Control Tools (6) ──────────────────────────────────────────────
  {
    toolName: "access_ssh",
    requiredBinaries: ["cat"],
    optionalBinaries: ["systemctl", "sshd"],
    critical: true,
  },
  {
    toolName: "access_sudo_audit",
    requiredBinaries: ["cat"],
    optionalBinaries: ["visudo"],
  },
  {
    toolName: "access_user_audit",
    requiredBinaries: ["cat"],
  },
  {
    toolName: "access_password_policy",
    requiredBinaries: ["cat"],
  },
  {
    toolName: "access_pam",
    requiredBinaries: ["cat"],
    optionalBinaries: ["pam_pwquality"],
  },
  {
    toolName: "access_restrict_shell",
    requiredBinaries: ["usermod"],
  },

  // ── Encryption Tools (4) ──────────────────────────────────────────────────
  {
    toolName: "crypto_tls",
    requiredBinaries: ["openssl"],
    critical: true,
  },
  {
    toolName: "crypto_gpg_keys",
    requiredBinaries: ["gpg"],
  },
  {
    toolName: "crypto_luks_manage",
    requiredBinaries: ["cryptsetup"],
  },
  {
    toolName: "crypto_file_hash",
    requiredBinaries: ["sha256sum"],
  },

  // ── Container Security Tools (6) ──────────────────────────────────────────
  {
    toolName: "container_docker",
    requiredBinaries: [],
    optionalBinaries: ["docker"],
  },
  {
    toolName: "container_apparmor",
    requiredBinaries: [],
    optionalBinaries: ["apparmor_status", "apparmor_parser"],
  },
  {
    toolName: "container_selinux_manage",
    requiredBinaries: ["getenforce"],
  },
  {
    toolName: "container_namespace_check",
    requiredBinaries: ["cat"],
    optionalBinaries: ["lsns"],
  },
  {
    toolName: "container_image_scan",
    requiredBinaries: [],
    optionalBinaries: ["trivy", "grype"],
  },
  {
    toolName: "container_security_config",
    requiredBinaries: [],
    optionalBinaries: ["newuidmap", "newgidmap"],
  },

  // ── Patch Management Tools (5) ────────────────────────────────────────────
  {
    toolName: "patch_update_audit",
    requiredBinaries: ["apt"],
  },
  {
    toolName: "patch_unattended_audit",
    requiredBinaries: ["cat"],
  },
  {
    toolName: "patch_integrity_check",
    requiredBinaries: [],
    optionalBinaries: ["debsums"],
  },
  {
    toolName: "patch_kernel_audit",
    requiredBinaries: ["uname"],
  },
  {
    toolName: "patch_vulnerability_intel",
    requiredBinaries: [],
    optionalBinaries: ["curl", "apt", "dpkg"],
  },

  // ── Secrets Management Tools (4) ──────────────────────────────────────────
  {
    toolName: "secrets_scan",
    requiredBinaries: ["grep"],
    optionalBinaries: ["trufflehog", "gitleaks"],
  },
  {
    toolName: "secrets_env_audit",
    requiredBinaries: [],
  },
  {
    toolName: "secrets_ssh_key_sprawl",
    requiredBinaries: ["find"],
  },
  {
    toolName: "secrets_git_history_scan",
    requiredBinaries: [],
    optionalBinaries: ["trufflehog", "gitleaks", "git"],
  },

  // ── Incident Response Tools (1) ───────────────────────────────────────────
  {
    toolName: "incident_response",
    requiredBinaries: [],
    optionalBinaries: ["cat", "ps", "ss", "lsof", "ip", "iptables-save", "find", "crontab"],
  },

  // ── Meta Tools (5) ────────────────────────────────────────────────────────
  {
    toolName: "defense_check_tools",
    requiredBinaries: [],
  },
  {
    toolName: "defense_workflow",
    requiredBinaries: [],
  },
  {
    toolName: "defense_change_history",
    requiredBinaries: [],
  },
  {
    toolName: "defense_security_posture",
    requiredBinaries: [],
    optionalBinaries: ["iptables", "ss", "journalctl", "apt", "sysctl", "systemctl"],
  },
  {
    toolName: "defense_scheduled_audit",
    requiredBinaries: [],
    optionalBinaries: ["systemctl", "crontab", "cat"],
  },

  // ── Sudo Management Tools (6) ─────────────────────────────────────────────
  {
    toolName: "sudo_elevate",
    requiredBinaries: [],
  },
  {
    toolName: "sudo_elevate_gui",
    requiredBinaries: [],
  },
  {
    toolName: "sudo_status",
    requiredBinaries: [],
  },
  {
    toolName: "sudo_drop",
    requiredBinaries: [],
  },
  {
    toolName: "sudo_extend",
    requiredBinaries: [],
  },
  {
    toolName: "preflight_batch_check",
    requiredBinaries: [],
  },

  // ── Supply Chain Security Tools (1) ───────────────────────────────────────
  {
    toolName: "supply_chain",
    requiredBinaries: [],
    optionalBinaries: ["syft", "cdxgen", "dpkg", "debsums", "cosign", "slsa-verifier"],
  },

  // ── Drift Detection Tools (1) ─────────────────────────────────────────────
  {
    toolName: "drift_baseline",
    requiredBinaries: [],
    optionalBinaries: ["sha256sum", "sysctl", "systemctl", "cat"],
  },

  // ── Zero Trust Network Tools (1) ──────────────────────────────────────────
  {
    toolName: "zero_trust",
    requiredBinaries: [],
    optionalBinaries: ["wg", "openssl", "iptables"],
  },

  // ── eBPF Security Tools (2) ───────────────────────────────────────────────
  {
    toolName: "ebpf_list_programs",
    requiredBinaries: [],
    optionalBinaries: ["bpftool"],
  },
  {
    toolName: "ebpf_falco",
    requiredBinaries: [],
    optionalBinaries: ["falco", "cat"],
  },

  // ── Application Hardening Tools (1) ───────────────────────────────────────
  {
    toolName: "app_harden",
    requiredBinaries: [],
    optionalBinaries: ["ps", "ss", "systemctl", "iptables"],
  },

  // ── Reporting Tools (1) ───────────────────────────────────────────────────
  {
    toolName: "report_export",
    requiredBinaries: [],
    optionalBinaries: ["lynis", "aide", "fail2ban-client", "iptables", "ss", "pandoc", "wkhtmltopdf"],
  },

  // ── DNS Security Tools (1) ────────────────────────────────────────────────
  {
    toolName: "dns_security",
    requiredBinaries: [],
    optionalBinaries: ["dig", "systemd-resolve", "resolvectl", "tcpdump", "cat", "grep"],
  },

  // ── Vulnerability Management Tools (1) ────────────────────────────────────
  {
    toolName: "vuln_manage",
    requiredBinaries: ["nmap"],
    optionalBinaries: ["nikto", "searchsploit"],
  },

  // ── Forensics Tools (1) ───────────────────────────────────────────────────
  {
    toolName: "ir_forensics",
    requiredBinaries: [],
    optionalBinaries: ["avml", "dd", "sha256sum", "tcpdump", "fdisk"],
  },

  // ── Process Security Tools (1) ────────────────────────────────────────────
  {
    toolName: "process_security",
    requiredBinaries: ["ps"],
    optionalBinaries: ["getpcaps", "capsh", "lsns", "ss"],
  },

  // ── Network Segmentation Tools (1) ────────────────────────────────────────
  {
    toolName: "network_segmentation_audit",
    requiredBinaries: ["ip", "iptables"],
    optionalBinaries: ["traceroute", "nmap", "bridge"],
  },

  // ── WAF Management Tools (1) ──────────────────────────────────────────────
  {
    toolName: "waf_manage",
    requiredBinaries: [],
    optionalBinaries: ["cat", "grep", "sed", "dpkg", "apache2ctl"],
  },

  // ── Threat Intelligence Tools (1) ─────────────────────────────────────────
  {
    toolName: "threat_intel",
    requiredBinaries: ["curl"],
    optionalBinaries: ["wget", "fail2ban-client", "iptables", "grep", "whois", "dig"],
  },

  // ── Auto-Remediation Tools (1) ────────────────────────────────────────────
  {
    toolName: "auto_remediate",
    requiredBinaries: [],
    optionalBinaries: ["sysctl", "iptables", "sed", "grep", "lynis"],
  },

  // ── Cloud Security Tools (1) ──────────────────────────────────────────────
  {
    toolName: "cloud_security",
    requiredBinaries: ["curl"],
    optionalBinaries: ["cat", "stat", "aws", "gsutil", "az", "cloud-init"],
  },

  // ── API Security Tools (1) ────────────────────────────────────────────────
  {
    toolName: "api_security",
    requiredBinaries: ["curl"],
    optionalBinaries: ["openssl", "ss"],
  },

  // ── Deception / Honeypot Tools (1) ────────────────────────────────────────
  {
    toolName: "honeypot_manage",
    requiredBinaries: [],
    optionalBinaries: ["ncat", "inotifywait", "iptables", "stat"],
  },

  // ── Wireless Security Tools (1) ───────────────────────────────────────────
  {
    toolName: "wireless_security",
    requiredBinaries: [],
    optionalBinaries: ["hciconfig", "bluetoothctl", "iw", "nmcli", "rfkill", "lsmod"],
  },

  // ── Certificate Lifecycle Tools (1) ───────────────────────────────────────
  {
    toolName: "certificate_lifecycle",
    requiredBinaries: ["openssl"],
    optionalBinaries: ["certbot", "find", "curl"],
  },

  // ── SIEM Integration Tools (1) ────────────────────────────────────────────
  {
    toolName: "siem_export",
    requiredBinaries: [],
    optionalBinaries: ["cat", "grep", "nc", "openssl", "logger", "filebeat"],
  },

  // ── USB Device Control Tools (1) ──────────────────────────────────────────
  {
    toolName: "usb_device_control",
    requiredBinaries: [],
    optionalBinaries: ["lsusb", "lsblk", "lsmod", "modprobe", "udevadm"],
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
