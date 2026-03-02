/**
 * Tool-to-dependency mapping for Kali Defense MCP Server.
 *
 * Maps each registered MCP tool name to the system binaries it requires.
 * Used by the dependency validator to ensure all required tools are
 * installed before execution — either at server startup or on-demand.
 */

import { DEFENSIVE_TOOLS, type ToolRequirement } from "./installer.js";

// ── Types ────────────────────────────────────────────────────────────────────

/**
 * Dependency specification for an MCP tool.
 */
export interface ToolDependency {
  /** The MCP tool name (e.g. "ids_rkhunter_scan") */
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
 * Organized by tool module for maintainability. Each entry specifies:
 * - requiredBinaries: must be present for the tool to work at all
 * - optionalBinaries: enhance functionality but aren't strictly needed
 * - critical: if true, missing deps trigger a startup warning
 */
export const TOOL_DEPENDENCIES: ToolDependency[] = [
  // ── Firewall Tools ───────────────────────────────────────────────────────
  {
    toolName: "firewall_iptables_list",
    requiredBinaries: ["iptables"],
    critical: true,
  },
  {
    toolName: "firewall_iptables_add",
    requiredBinaries: ["iptables"],
    critical: true,
  },
  {
    toolName: "firewall_iptables_delete",
    requiredBinaries: ["iptables"],
    critical: true,
  },
  {
    toolName: "firewall_ufw_status",
    requiredBinaries: ["ufw"],
  },
  {
    toolName: "firewall_ufw_rule",
    requiredBinaries: ["ufw"],
  },
  {
    toolName: "firewall_save",
    requiredBinaries: ["iptables-save"],
    optionalBinaries: ["ip6tables-save"],
  },
  {
    toolName: "firewall_restore",
    requiredBinaries: ["iptables-restore"],
    optionalBinaries: ["ip6tables-restore"],
  },
  {
    toolName: "firewall_nftables_list",
    requiredBinaries: ["nft"],
  },
  {
    toolName: "firewall_set_policy",
    requiredBinaries: ["iptables"],
    optionalBinaries: ["ip6tables"],
  },
  {
    toolName: "firewall_create_chain",
    requiredBinaries: ["iptables"],
    optionalBinaries: ["ip6tables"],
  },
  {
    toolName: "firewall_persistence",
    requiredBinaries: ["iptables"],
    optionalBinaries: ["netfilter-persistent"],
  },
  {
    toolName: "firewall_policy_audit",
    requiredBinaries: ["iptables"],
  },

  // ── Hardening Tools ──────────────────────────────────────────────────────
  {
    toolName: "harden_sysctl_get",
    requiredBinaries: ["sysctl"],
    critical: true,
  },
  {
    toolName: "harden_sysctl_set",
    requiredBinaries: ["sysctl"],
    critical: true,
  },
  {
    toolName: "harden_sysctl_audit",
    requiredBinaries: ["sysctl"],
    critical: true,
  },
  {
    toolName: "harden_service_manage",
    requiredBinaries: ["systemctl"],
    critical: true,
  },
  {
    toolName: "harden_service_audit",
    requiredBinaries: ["systemctl"],
    critical: true,
  },
  {
    toolName: "harden_file_permissions",
    requiredBinaries: ["stat"],
    optionalBinaries: ["chmod", "chown", "chgrp"],
  },
  {
    toolName: "harden_permissions_audit",
    requiredBinaries: ["stat"],
  },
  {
    toolName: "harden_systemd_audit",
    requiredBinaries: ["systemd-analyze"],
  },
  {
    toolName: "harden_systemd_apply",
    requiredBinaries: ["systemctl"],
  },
  {
    toolName: "harden_kernel_security_audit",
    requiredBinaries: ["cat"],
  },
  {
    toolName: "harden_bootloader_audit",
    requiredBinaries: ["cat"],
  },
  {
    toolName: "harden_bootloader_configure",
    requiredBinaries: ["cat"],
    optionalBinaries: ["update-grub"],
  },
  {
    toolName: "harden_module_audit",
    requiredBinaries: ["lsmod"],
    optionalBinaries: ["modprobe"],
  },
  {
    toolName: "harden_cron_audit",
    requiredBinaries: ["cat"],
  },
  {
    toolName: "harden_umask_audit",
    requiredBinaries: ["cat"],
  },
  {
    toolName: "harden_umask_set",
    requiredBinaries: ["cat"],
  },
  {
    toolName: "harden_banner_audit",
    requiredBinaries: ["cat"],
  },
  {
    toolName: "harden_banner_set",
    requiredBinaries: ["tee"],
  },
  {
    toolName: "harden_coredump_disable",
    requiredBinaries: ["sysctl"],
  },

  // ── IDS Tools ────────────────────────────────────────────────────────────
  {
    toolName: "ids_aide_manage",
    requiredBinaries: ["aide"],
    critical: true,
  },
  {
    toolName: "ids_rkhunter_scan",
    requiredBinaries: ["rkhunter"],
    critical: true,
  },
  {
    toolName: "ids_chkrootkit_scan",
    requiredBinaries: ["chkrootkit"],
  },
  {
    toolName: "ids_file_integrity_check",
    requiredBinaries: ["sha256sum"],
  },
  {
    toolName: "ids_rootkit_summary",
    requiredBinaries: [],
    optionalBinaries: ["rkhunter", "chkrootkit"],
  },

  // ── Logging Tools ────────────────────────────────────────────────────────
  {
    toolName: "log_auditd_rules",
    requiredBinaries: ["auditctl"],
    critical: true,
  },
  {
    toolName: "log_auditd_search",
    requiredBinaries: ["ausearch"],
  },
  {
    toolName: "log_auditd_report",
    requiredBinaries: ["aureport"],
  },
  {
    toolName: "log_journalctl_query",
    requiredBinaries: ["journalctl"],
    critical: true,
  },
  {
    toolName: "log_fail2ban_status",
    requiredBinaries: ["fail2ban-client"],
  },
  {
    toolName: "log_fail2ban_manage",
    requiredBinaries: ["fail2ban-client"],
  },
  {
    toolName: "log_syslog_analyze",
    requiredBinaries: ["cat"],
  },
  {
    toolName: "log_auditd_cis_rules",
    requiredBinaries: ["auditctl"],
  },
  {
    toolName: "log_rotation_audit",
    requiredBinaries: ["cat"],
    optionalBinaries: ["logrotate"],
  },
  {
    toolName: "log_fail2ban_audit",
    requiredBinaries: ["fail2ban-client"],
  },

  // ── Network Defense Tools ────────────────────────────────────────────────
  {
    toolName: "netdef_connections",
    requiredBinaries: ["ss"],
    critical: true,
  },
  {
    toolName: "netdef_port_scan_detect",
    requiredBinaries: ["cat"],
  },
  {
    toolName: "netdef_tcpdump_capture",
    requiredBinaries: ["tcpdump"],
  },
  {
    toolName: "netdef_dns_monitor",
    requiredBinaries: ["tcpdump"],
  },
  {
    toolName: "netdef_arp_monitor",
    requiredBinaries: ["tcpdump"],
  },
  {
    toolName: "netdef_open_ports_audit",
    requiredBinaries: ["ss"],
  },
  {
    toolName: "netdef_ipv6_audit",
    requiredBinaries: ["sysctl"],
    optionalBinaries: ["ip6tables"],
  },
  {
    toolName: "netdef_self_scan",
    requiredBinaries: ["nmap"],
  },

  // ── Compliance Tools ─────────────────────────────────────────────────────
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
    toolName: "compliance_cis_check",
    requiredBinaries: ["cat"],
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

  // ── Malware Tools ────────────────────────────────────────────────────────
  {
    toolName: "malware_clamav_scan",
    requiredBinaries: ["clamscan"],
    critical: true,
  },
  {
    toolName: "malware_clamav_update",
    requiredBinaries: ["freshclam"],
  },
  {
    toolName: "malware_yara_scan",
    requiredBinaries: ["yara"],
  },
  {
    toolName: "malware_suspicious_files",
    requiredBinaries: ["find"],
  },
  {
    toolName: "malware_quarantine_manage",
    requiredBinaries: ["cat"],
  },
  {
    toolName: "malware_webshell_detect",
    requiredBinaries: ["grep"],
  },

  // ── Backup Tools ─────────────────────────────────────────────────────────
  {
    toolName: "backup_config_files",
    requiredBinaries: ["cp"],
  },
  {
    toolName: "backup_system_state",
    requiredBinaries: ["cat"],
    optionalBinaries: ["dpkg", "systemctl", "iptables-save", "ss"],
  },
  {
    toolName: "backup_restore",
    requiredBinaries: ["cp"],
  },
  {
    toolName: "backup_verify",
    requiredBinaries: ["sha256sum"],
  },
  {
    toolName: "backup_list",
    requiredBinaries: ["ls"],
  },

  // ── Access Control Tools ─────────────────────────────────────────────────
  {
    toolName: "access_ssh_audit",
    requiredBinaries: ["cat"],
    critical: true,
  },
  {
    toolName: "access_ssh_harden",
    requiredBinaries: ["cat"],
    optionalBinaries: ["systemctl"],
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
    toolName: "access_pam_audit",
    requiredBinaries: ["cat"],
  },
  {
    toolName: "access_ssh_cipher_audit",
    requiredBinaries: ["cat"],
    optionalBinaries: ["sshd"],
  },
  {
    toolName: "access_pam_configure",
    requiredBinaries: ["cat"],
    optionalBinaries: ["pam_pwquality"],
  },
  {
    toolName: "access_restrict_shell",
    requiredBinaries: ["usermod"],
  },

  // ── Encryption Tools ─────────────────────────────────────────────────────
  {
    toolName: "crypto_tls_audit",
    requiredBinaries: ["openssl"],
    critical: true,
  },
  {
    toolName: "crypto_cert_expiry",
    requiredBinaries: ["openssl"],
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
  {
    toolName: "crypto_tls_config_audit",
    requiredBinaries: ["cat"],
    optionalBinaries: ["openssl"],
  },

  // ── Container Security Tools ─────────────────────────────────────────────
  {
    toolName: "container_docker_audit",
    requiredBinaries: ["docker"],
  },
  {
    toolName: "container_docker_bench",
    requiredBinaries: ["docker"],
  },
  {
    toolName: "container_apparmor_manage",
    requiredBinaries: ["apparmor_status"],
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
    toolName: "container_seccomp_audit",
    requiredBinaries: ["docker"],
  },
  {
    toolName: "container_daemon_configure",
    requiredBinaries: ["cat"],
    optionalBinaries: ["docker"],
  },
  {
    toolName: "container_apparmor_install",
    requiredBinaries: [],
    optionalBinaries: ["apparmor_status"],
  },

  // ── Patch Management Tools ───────────────────────────────────────────────
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

  // ── Secrets Management Tools ─────────────────────────────────────────────
  {
    toolName: "secrets_scan",
    requiredBinaries: ["grep"],
  },
  {
    toolName: "secrets_env_audit",
    requiredBinaries: ["cat"],
  },
  {
    toolName: "secrets_ssh_key_sprawl",
    requiredBinaries: ["find"],
  },

  // ── Incident Response Tools ──────────────────────────────────────────────
  {
    toolName: "ir_volatile_collect",
    requiredBinaries: ["cat"],
    optionalBinaries: ["ps", "ss", "lsof", "ip", "iptables-save"],
  },
  {
    toolName: "ir_ioc_scan",
    requiredBinaries: ["ps"],
    optionalBinaries: ["ss", "find", "crontab"],
  },
  {
    toolName: "ir_timeline_generate",
    requiredBinaries: ["find"],
  },

  // ── Meta Tools ───────────────────────────────────────────────────────────
  {
    toolName: "defense_check_tools",
    requiredBinaries: [],
  },
  {
    toolName: "defense_suggest_workflow",
    requiredBinaries: [],
  },
  {
    toolName: "defense_security_posture",
    requiredBinaries: [],
    optionalBinaries: ["iptables", "ss", "journalctl", "apt"],
  },
  {
    toolName: "defense_change_history",
    requiredBinaries: [],
  },
  {
    toolName: "defense_run_workflow",
    requiredBinaries: [],
  },

  // ── Supply Chain Security Tools ──────────────────────────────────────────
  {
    toolName: "generate_sbom",
    requiredBinaries: [],
    optionalBinaries: ["syft", "cdxgen", "dpkg"],
  },
  {
    toolName: "verify_package_integrity",
    requiredBinaries: [],
    optionalBinaries: ["debsums"],
  },
  {
    toolName: "setup_cosign_signing",
    requiredBinaries: [],
    optionalBinaries: ["cosign"],
  },
  {
    toolName: "check_slsa_attestation",
    requiredBinaries: [],
    optionalBinaries: ["slsa-verifier", "cosign"],
  },

  // ── Memory Protection Tools ──────────────────────────────────────────────
  {
    toolName: "audit_memory_protections",
    requiredBinaries: [],
    optionalBinaries: ["readelf", "checksec"],
  },
  {
    toolName: "enforce_aslr",
    requiredBinaries: ["sysctl"],
  },
  {
    toolName: "report_exploit_mitigations",
    requiredBinaries: ["cat"],
  },

  // ── Drift Detection Tools ────────────────────────────────────────────────
  {
    toolName: "create_baseline",
    requiredBinaries: ["sha256sum"],
    optionalBinaries: ["sysctl", "systemctl"],
  },
  {
    toolName: "compare_to_baseline",
    requiredBinaries: ["sha256sum"],
  },
  {
    toolName: "list_drift_alerts",
    requiredBinaries: ["cat"],
  },

  // ── Vulnerability Intel Tools ────────────────────────────────────────────
  {
    toolName: "lookup_cve",
    requiredBinaries: ["curl"],
  },
  {
    toolName: "scan_packages_cves",
    requiredBinaries: [],
    optionalBinaries: ["apt", "dpkg"],
  },
  {
    toolName: "get_patch_urgency",
    requiredBinaries: [],
    optionalBinaries: ["apt"],
  },

  // ── Security Posture Tools ───────────────────────────────────────────────
  {
    toolName: "calculate_security_score",
    requiredBinaries: [],
    optionalBinaries: ["sysctl", "iptables", "ss", "systemctl"],
  },
  {
    toolName: "get_posture_trend",
    requiredBinaries: ["cat"],
  },
  {
    toolName: "generate_posture_dashboard",
    requiredBinaries: [],
  },

  // ── Secrets Scanner Tools ────────────────────────────────────────────────
  {
    toolName: "scan_for_secrets",
    requiredBinaries: ["grep"],
    optionalBinaries: ["trufflehog", "gitleaks"],
  },
  {
    toolName: "audit_env_vars",
    requiredBinaries: [],
  },
  {
    toolName: "scan_git_history",
    requiredBinaries: [],
    optionalBinaries: ["trufflehog", "gitleaks", "git"],
  },

  // ── Zero Trust Network Tools ─────────────────────────────────────────────
  {
    toolName: "setup_wireguard",
    requiredBinaries: [],
    optionalBinaries: ["wg"],
  },
  {
    toolName: "manage_wg_peers",
    requiredBinaries: [],
    optionalBinaries: ["wg"],
  },
  {
    toolName: "setup_mtls",
    requiredBinaries: ["openssl"],
  },
  {
    toolName: "configure_microsegmentation",
    requiredBinaries: ["iptables"],
  },

  // ── Container Advanced Tools ─────────────────────────────────────────────
  {
    toolName: "generate_seccomp_profile",
    requiredBinaries: [],
  },
  {
    toolName: "apply_apparmor_container",
    requiredBinaries: [],
    optionalBinaries: ["apparmor_parser"],
  },
  {
    toolName: "setup_rootless_containers",
    requiredBinaries: [],
    optionalBinaries: ["newuidmap", "newgidmap"],
  },
  {
    toolName: "scan_image_trivy",
    requiredBinaries: [],
    optionalBinaries: ["trivy"],
  },

  // ── Compliance Extended Tools ────────────────────────────────────────────
  {
    toolName: "run_compliance_check",
    requiredBinaries: [],
    optionalBinaries: ["lynis", "oscap"],
  },

  // ── eBPF Security Tools ──────────────────────────────────────────────────
  {
    toolName: "list_ebpf_programs",
    requiredBinaries: [],
    optionalBinaries: ["bpftool"],
  },
  {
    toolName: "check_falco",
    requiredBinaries: [],
    optionalBinaries: ["falco"],
  },
  {
    toolName: "deploy_falco_rules",
    requiredBinaries: [],
    optionalBinaries: ["falco"],
  },
  {
    toolName: "get_ebpf_events",
    requiredBinaries: ["cat"],
  },

  // ── Automation Workflow Tools ────────────────────────────────────────────
  {
    toolName: "setup_scheduled_audit",
    requiredBinaries: [],
    optionalBinaries: ["systemctl", "crontab"],
  },
  {
    toolName: "list_scheduled_audits",
    requiredBinaries: [],
    optionalBinaries: ["systemctl", "crontab"],
  },
  {
    toolName: "remove_scheduled_audit",
    requiredBinaries: [],
    optionalBinaries: ["systemctl", "crontab"],
  },
  {
    toolName: "get_audit_history",
    requiredBinaries: ["cat"],
  },

  // ── Application Hardening Tools ──────────────────────────────────────────
  {
    toolName: "app_harden_audit",
    requiredBinaries: ["ps"],
    optionalBinaries: ["ss", "systemctl"],
  },
  {
    toolName: "app_harden_recommend",
    requiredBinaries: [],
  },
  {
    toolName: "app_harden_firewall",
    requiredBinaries: [],
    optionalBinaries: ["iptables"],
  },
  {
    toolName: "app_harden_systemd",
    requiredBinaries: [],
    optionalBinaries: ["systemctl"],
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
