/**
 * Enhanced Tool Registry — single source of truth for all MCP tool requirements.
 *
 * Replaces and extends `tool-dependencies.ts` with richer dependency metadata
 * including privilege requirements, Python/npm packages, system libraries,
 * required files, and Linux capabilities.
 *
 * @module tool-registry
 */

import { TOOL_DEPENDENCIES } from "./tool-dependencies.js";

// ── Types ────────────────────────────────────────────────────────────────────

/**
 * Complete requirements manifest for a single MCP tool.
 * Enhanced replacement for the legacy {@link ToolDependency} type.
 */
export interface ToolManifest {
  /** The MCP tool name (e.g., "firewall_iptables_list") */
  toolName: string;

  // ── Binary dependencies ────────────────────────────────────────────────

  /** System binaries required for this tool to function */
  requiredBinaries: string[];
  /** System binaries that enhance functionality but aren't strictly needed */
  optionalBinaries?: string[];

  // ── Python module dependencies ─────────────────────────────────────────

  /** Python modules required (e.g., ["yara-python", "pefile"]) */
  requiredPythonModules?: string[];
  /** Python modules that enhance functionality */
  optionalPythonModules?: string[];

  // ── npm package dependencies ───────────────────────────────────────────

  /** npm packages required (e.g., ["semgrep"]) */
  requiredNpmPackages?: string[];
  /** npm packages that enhance functionality */
  optionalNpmPackages?: string[];

  // ── System libraries (checked via ldconfig or pkg-config) ──────────────

  /** System shared libraries required (e.g., ["libssl", "libpcap"]) */
  requiredLibraries?: string[];

  // ── Required files that must exist ─────────────────────────────────────

  /** Absolute paths that must exist on disk (e.g., ["/etc/audit/auditd.conf"]) */
  requiredFiles?: string[];

  // ── Privilege requirements ─────────────────────────────────────────────

  /** Sudo requirement level for this tool */
  sudo: "never" | "always" | "conditional";
  /** Human-readable explanation of why sudo is needed */
  sudoReason?: string;
  /** Linux capabilities required (e.g., ["CAP_NET_RAW"]) */
  capabilities?: string[];

  // ── Metadata ───────────────────────────────────────────────────────────

  /** Whether this tool is critical for core functionality */
  critical?: boolean;
  /** Tool module category (firewall, logging, compliance, etc.) */
  category?: string;
  /** Additional categorization tags */
  tags?: string[];
}

// ── Registry Class ───────────────────────────────────────────────────────────

/**
 * Map-based registry with O(1) lookup for tool manifests.
 * Singleton pattern — use {@link ToolRegistry.instance} to obtain.
 */
export class ToolRegistry {
  private manifests: Map<string, ToolManifest> = new Map();

  private static _instance: ToolRegistry | null = null;

  /** Get or create the singleton registry instance. */
  static instance(): ToolRegistry {
    if (!ToolRegistry._instance) {
      ToolRegistry._instance = new ToolRegistry();
    }
    return ToolRegistry._instance;
  }

  /**
   * Reset the singleton (primarily for testing).
   * @internal
   */
  static resetInstance(): void {
    ToolRegistry._instance = null;
  }

  /** Register a single tool manifest. Overwrites if already registered. */
  register(manifest: ToolManifest): void {
    this.manifests.set(manifest.toolName, manifest);
  }

  /** Bulk register an array of tool manifests. */
  registerAll(manifests: ToolManifest[]): void {
    for (const m of manifests) {
      this.register(m);
    }
  }

  /** Get manifest for a tool, or `undefined` if unregistered. */
  getManifest(toolName: string): ToolManifest | undefined {
    return this.manifests.get(toolName);
  }

  /** Get all tool names that list `binary` in their `requiredBinaries`. */
  getToolsRequiring(binary: string): string[] {
    const result: string[] = [];
    for (const m of this.manifests.values()) {
      if (m.requiredBinaries.includes(binary)) {
        result.push(m.toolName);
      }
    }
    return result;
  }

  /** Get all manifests whose `category` matches. */
  getToolsByCategory(category: string): ToolManifest[] {
    const result: ToolManifest[] = [];
    for (const m of this.manifests.values()) {
      if (m.category === category) {
        result.push(m);
      }
    }
    return result;
  }

  /** Collect every unique required binary across all registered tools. */
  getAllRequiredBinaries(): Set<string> {
    const bins = new Set<string>();
    for (const m of this.manifests.values()) {
      for (const b of m.requiredBinaries) {
        bins.add(b);
      }
    }
    return bins;
  }

  /** Get all manifests that require sudo (`always` or `conditional`). */
  getToolsNeedingSudo(): ToolManifest[] {
    const result: ToolManifest[] = [];
    for (const m of this.manifests.values()) {
      if (m.sudo === "always" || m.sudo === "conditional") {
        result.push(m);
      }
    }
    return result;
  }

  /** Check whether a tool name is registered. */
  has(toolName: string): boolean {
    return this.manifests.has(toolName);
  }

  /** Return every registered manifest as an array. */
  getAll(): ToolManifest[] {
    return Array.from(this.manifests.values());
  }
}

// ── Category Inference ───────────────────────────────────────────────────────

/** Prefix → category mapping used by {@link inferCategory}. */
const CATEGORY_PREFIX_MAP: [string, string][] = [
  // Exact-match entries (checked first because they're longer/more specific)
  ["generate_sbom", "supply-chain"],
  ["verify_package_integrity", "supply-chain"],
  ["setup_cosign_signing", "supply-chain"],
  ["check_slsa_attestation", "supply-chain"],
  ["audit_memory_protections", "memory-protection"],
  ["enforce_aslr", "memory-protection"],
  ["report_exploit_mitigations", "memory-protection"],
  ["create_baseline", "drift-detection"],
  ["compare_to_baseline", "drift-detection"],
  ["list_drift_alerts", "drift-detection"],
  ["lookup_cve", "vulnerability-intel"],
  ["scan_packages_cves", "vulnerability-intel"],
  ["get_patch_urgency", "vulnerability-intel"],
  ["calculate_security_score", "security-posture"],
  ["get_posture_trend", "security-posture"],
  ["generate_posture_dashboard", "security-posture"],
  ["scan_for_secrets", "secrets-scanner"],
  ["audit_env_vars", "secrets-scanner"],
  ["scan_git_history", "secrets-scanner"],
  ["setup_wireguard", "zero-trust"],
  ["manage_wg_peers", "zero-trust"],
  ["setup_mtls", "zero-trust"],
  ["configure_microsegmentation", "zero-trust"],
  ["generate_seccomp_profile", "container-advanced"],
  ["apply_apparmor_container", "container-advanced"],
  ["setup_rootless_containers", "container-advanced"],
  ["scan_image_trivy", "container-advanced"],
  ["run_compliance_check", "compliance-extended"],
  ["list_ebpf_programs", "ebpf"],
  ["check_falco", "ebpf"],
  ["deploy_falco_rules", "ebpf"],
  ["get_ebpf_events", "ebpf"],
  ["setup_scheduled_audit", "automation"],
  ["list_scheduled_audits", "automation"],
  ["remove_scheduled_audit", "automation"],
  ["get_audit_history", "automation"],

  // Prefix entries (order matters — longest prefix first is guaranteed by
  // the exact entries above; these are all disjoint prefixes)
  ["firewall_", "firewall"],
  ["harden_", "hardening"],
  ["ids_", "ids"],
  ["log_", "logging"],
  ["netdef_", "network"],
  ["compliance_", "compliance"],
  ["malware_", "malware"],
  ["backup_", "backup"],
  ["access_", "access"],
  ["crypto_", "encryption"],
  ["container_", "container"],
  ["patch_", "patch-management"],
  ["secrets_", "secrets"],
  ["ir_", "incident-response"],
  ["defense_", "meta"],
  ["sudo_", "sudo"],
  ["app_harden_", "app-hardening"],
];

/**
 * Infer a human-readable category from the MCP tool name.
 */
function inferCategory(toolName: string): string {
  for (const [prefix, category] of CATEGORY_PREFIX_MAP) {
    if (toolName === prefix || toolName.startsWith(prefix)) {
      return category;
    }
  }
  return "unknown";
}

// ── Legacy Migration ─────────────────────────────────────────────────────────

/**
 * Convert every entry in the legacy `TOOL_DEPENDENCIES` array into a
 * {@link ToolManifest} and register it.  Default `sudo` is `'never'`
 * (overridden later by {@link DEFAULT_MANIFESTS}).
 */
export function migrateFromLegacy(registry: ToolRegistry): void {
  for (const legacy of TOOL_DEPENDENCIES) {
    const manifest: ToolManifest = {
      toolName: legacy.toolName,
      requiredBinaries: [...legacy.requiredBinaries],
      optionalBinaries: legacy.optionalBinaries
        ? [...legacy.optionalBinaries]
        : undefined,
      sudo: "never",
      critical: legacy.critical,
      category: inferCategory(legacy.toolName),
    };
    registry.register(manifest);
  }
}

// ── Default Manifests (Sudo & Privilege Overlays) ────────────────────────────

/**
 * Partial manifest used solely for overlaying sudo/privilege metadata onto
 * legacy-migrated entries.
 */
interface SudoOverlay {
  toolName: string;
  sudo: ToolManifest["sudo"];
  sudoReason?: string;
  capabilities?: string[];
  tags?: string[];
}

/**
 * Static sudo requirement data derived from analysing which tool handlers
 * invoke privileged operations.
 */
const SUDO_OVERLAYS: SudoOverlay[] = [
  // ── Firewall tools (write operations) ── sudo: 'always' ───────────────
  {
    toolName: "firewall_iptables_add",
    sudo: "always",
    sudoReason:
      "Firewall rules require root to modify netfilter tables",
  },
  {
    toolName: "firewall_iptables_delete",
    sudo: "always",
    sudoReason:
      "Firewall rules require root to modify netfilter tables",
  },
  {
    toolName: "firewall_ufw_rule",
    sudo: "always",
    sudoReason:
      "Firewall rules require root to modify netfilter tables",
  },
  {
    toolName: "firewall_save",
    sudo: "always",
    sudoReason:
      "Firewall rules require root to modify netfilter tables",
  },
  {
    toolName: "firewall_restore",
    sudo: "always",
    sudoReason:
      "Firewall rules require root to modify netfilter tables",
  },
  {
    toolName: "firewall_set_policy",
    sudo: "always",
    sudoReason:
      "Firewall rules require root to modify netfilter tables",
  },
  {
    toolName: "firewall_create_chain",
    sudo: "always",
    sudoReason:
      "Firewall rules require root to modify netfilter tables",
  },
  {
    toolName: "firewall_persistence",
    sudo: "always",
    sudoReason:
      "Firewall rules require root to modify netfilter tables",
  },
  {
    toolName: "firewall_nftables_list",
    sudo: "always",
    sudoReason: "nftables requires root to list ruleset",
  },

  // ── Firewall tools (read operations) ── sudo: 'conditional' ───────────
  {
    toolName: "firewall_iptables_list",
    sudo: "conditional",
    sudoReason:
      "Read operations may work without sudo but show limited results",
  },
  {
    toolName: "firewall_ufw_status",
    sudo: "conditional",
    sudoReason:
      "Read operations may work without sudo but show limited results",
  },
  {
    toolName: "firewall_policy_audit",
    sudo: "conditional",
    sudoReason:
      "Read operations may work without sudo but show limited results",
  },

  // ── Auditd tools ── sudo: 'always' ────────────────────────────────────
  {
    toolName: "log_auditd_rules",
    sudo: "always",
    sudoReason: "Auditd requires root for rule management",
  },
  {
    toolName: "log_auditd_search",
    sudo: "always",
    sudoReason: "Auditd requires root for rule management",
  },
  {
    toolName: "log_auditd_report",
    sudo: "always",
    sudoReason: "Auditd requires root for rule management",
  },
  {
    toolName: "log_auditd_cis_rules",
    sudo: "always",
    sudoReason: "Auditd requires root for rule management",
  },

  // ── Other logging tools ────────────────────────────────────────────────
  {
    toolName: "log_fail2ban_manage",
    sudo: "always",
    sudoReason: "Fail2ban management requires root",
  },
  {
    toolName: "log_fail2ban_status",
    sudo: "conditional",
    sudoReason:
      "Read operations may work without sudo but show limited results",
  },
  {
    toolName: "log_journalctl_query",
    sudo: "conditional",
    sudoReason:
      "Read operations may work without sudo but show limited results",
  },
  {
    toolName: "log_syslog_analyze",
    sudo: "conditional",
    sudoReason:
      "Read operations may work without sudo but show limited results",
  },
  {
    toolName: "log_rotation_audit",
    sudo: "conditional",
    sudoReason:
      "Read operations may work without sudo but show limited results",
  },
  {
    toolName: "log_fail2ban_audit",
    sudo: "conditional",
    sudoReason:
      "Read operations may work without sudo but show limited results",
  },

  // ── Access control tools (write) ── sudo: 'always' ────────────────────
  {
    toolName: "access_ssh_harden",
    sudo: "always",
    sudoReason: "Modifying sshd_config requires root",
  },
  {
    toolName: "access_pam_configure",
    sudo: "always",
    sudoReason: "PAM configuration requires root",
  },
  {
    toolName: "access_pam_audit",
    sudo: "always",
    sudoReason: "PAM configuration files are root-readable only",
  },
  {
    toolName: "access_restrict_shell",
    sudo: "always",
    sudoReason: "Changing user shells requires root",
  },
  {
    toolName: "access_password_policy",
    sudo: "always",
    sudoReason: "Password policy changes require root",
  },

  // ── Access control tools (read) ── sudo: 'conditional' ────────────────
  {
    toolName: "access_ssh_audit",
    sudo: "conditional",
    sudoReason:
      "Read operations may work without sudo but show limited results",
  },
  {
    toolName: "access_user_audit",
    sudo: "conditional",
    sudoReason:
      "Read operations may work without sudo but show limited results",
  },
  {
    toolName: "access_sudo_audit",
    sudo: "conditional",
    sudoReason:
      "Read operations may work without sudo but show limited results",
  },
  {
    toolName: "access_ssh_cipher_audit",
    sudo: "conditional",
    sudoReason:
      "Read operations may work without sudo but show limited results",
  },

  // ── Patch management tools ── sudo: 'always' ──────────────────────────
  {
    toolName: "patch_update_audit",
    sudo: "always",
    sudoReason: "Package management requires root",
  },
  {
    toolName: "patch_unattended_audit",
    sudo: "always",
    sudoReason: "Package management requires root",
  },
  {
    toolName: "patch_integrity_check",
    sudo: "always",
    sudoReason: "Package management requires root",
  },
  {
    toolName: "patch_kernel_audit",
    sudo: "always",
    sudoReason: "Package management requires root",
  },

  // ── LUKS encryption ── sudo: 'always' ─────────────────────────────────
  {
    toolName: "crypto_luks_manage",
    sudo: "always",
    sudoReason: "LUKS operations require root",
  },

  // ── Compliance tools ──────────────────────────────────────────────────
  {
    toolName: "compliance_lynis_audit",
    sudo: "always",
    sudoReason: "Lynis requires root for comprehensive audit",
  },
  {
    toolName: "compliance_oscap_scan",
    sudo: "always",
    sudoReason: "OpenSCAP requires root for system scanning",
  },
  {
    toolName: "compliance_cis_check",
    sudo: "conditional",
    sudoReason: "CIS checks may need root for full results",
  },
  {
    toolName: "compliance_cron_restrict",
    sudo: "always",
    sudoReason: "Cron access restriction requires root",
  },
  {
    toolName: "compliance_tmp_hardening",
    sudo: "always",
    sudoReason: "Mount operations require root",
  },

  // ── Hardening tools (write) ── sudo: 'always' ─────────────────────────
  {
    toolName: "harden_sysctl_set",
    sudo: "always",
    sudoReason: "Modifying kernel parameters requires root",
  },
  {
    toolName: "harden_service_manage",
    sudo: "always",
    sudoReason: "Service management requires root",
  },
  {
    toolName: "harden_systemd_apply",
    sudo: "always",
    sudoReason: "Systemd unit modifications require root",
  },
  {
    toolName: "harden_bootloader_configure",
    sudo: "always",
    sudoReason: "Bootloader configuration requires root",
  },
  {
    toolName: "harden_umask_set",
    sudo: "always",
    sudoReason: "System-wide umask changes require root",
  },
  {
    toolName: "harden_banner_set",
    sudo: "always",
    sudoReason: "Writing system banners requires root",
  },
  {
    toolName: "harden_coredump_disable",
    sudo: "always",
    sudoReason: "Core dump configuration requires root",
  },
  {
    toolName: "harden_file_permissions",
    sudo: "always",
    sudoReason: "Changing file permissions/ownership requires root",
  },

  // ── Hardening tools (read/audit) ── sudo: 'conditional' ───────────────
  {
    toolName: "harden_sysctl_get",
    sudo: "conditional",
    sudoReason:
      "Read operations may work without sudo but show limited results",
  },
  {
    toolName: "harden_sysctl_audit",
    sudo: "conditional",
    sudoReason:
      "Read operations may work without sudo but show limited results",
  },
  {
    toolName: "harden_service_audit",
    sudo: "conditional",
    sudoReason:
      "Read operations may work without sudo but show limited results",
  },
  {
    toolName: "harden_permissions_audit",
    sudo: "conditional",
    sudoReason:
      "Read operations may work without sudo but show limited results",
  },
  {
    toolName: "harden_systemd_audit",
    sudo: "conditional",
    sudoReason:
      "Read operations may work without sudo but show limited results",
  },
  {
    toolName: "harden_kernel_security_audit",
    sudo: "conditional",
    sudoReason:
      "Read operations may work without sudo but show limited results",
  },
  {
    toolName: "harden_bootloader_audit",
    sudo: "conditional",
    sudoReason:
      "Read operations may work without sudo but show limited results",
  },
  {
    toolName: "harden_module_audit",
    sudo: "conditional",
    sudoReason:
      "Read operations may work without sudo but show limited results",
  },
  {
    toolName: "harden_cron_audit",
    sudo: "conditional",
    sudoReason:
      "Read operations may work without sudo but show limited results",
  },
  {
    toolName: "harden_umask_audit",
    sudo: "conditional",
    sudoReason:
      "Read operations may work without sudo but show limited results",
  },
  {
    toolName: "harden_banner_audit",
    sudo: "conditional",
    sudoReason:
      "Read operations may work without sudo but show limited results",
  },

  // ── IDS tools ──────────────────────────────────────────────────────────
  {
    toolName: "ids_aide_manage",
    sudo: "always",
    sudoReason: "AIDE database operations require root",
  },
  {
    toolName: "ids_rkhunter_scan",
    sudo: "always",
    sudoReason: "Rootkit scanning requires root",
  },
  {
    toolName: "ids_chkrootkit_scan",
    sudo: "always",
    sudoReason: "Rootkit scanning requires root",
  },

  // ── Network defense tools ──────────────────────────────────────────────
  {
    toolName: "netdef_tcpdump_capture",
    sudo: "always",
    sudoReason: "Packet capture requires root",
    capabilities: ["CAP_NET_RAW"],
  },
  {
    toolName: "netdef_dns_monitor",
    sudo: "always",
    sudoReason: "DNS monitoring requires packet capture privileges",
    capabilities: ["CAP_NET_RAW"],
  },
  {
    toolName: "netdef_arp_monitor",
    sudo: "always",
    sudoReason: "ARP monitoring requires packet capture privileges",
    capabilities: ["CAP_NET_RAW"],
  },
  {
    toolName: "netdef_self_scan",
    sudo: "always",
    sudoReason: "Nmap scanning requires root for SYN scans",
  },
  {
    toolName: "netdef_connections",
    sudo: "conditional",
    sudoReason:
      "Read operations may work without sudo but show limited results",
  },
  {
    toolName: "netdef_open_ports_audit",
    sudo: "conditional",
    sudoReason:
      "Read operations may work without sudo but show limited results",
  },
  {
    toolName: "netdef_ipv6_audit",
    sudo: "conditional",
    sudoReason:
      "Read operations may work without sudo but show limited results",
  },

  // ── Malware tools ──────────────────────────────────────────────────────
  {
    toolName: "malware_clamav_scan",
    sudo: "conditional",
    sudoReason: "May need root to scan restricted directories",
  },
  {
    toolName: "malware_clamav_update",
    sudo: "always",
    sudoReason: "Updating virus definitions requires root",
  },
  {
    toolName: "malware_webshell_detect",
    sudo: "conditional",
    sudoReason: "May need root to scan web server directories",
  },

  // ── Container tools ────────────────────────────────────────────────────
  {
    toolName: "container_docker_audit",
    sudo: "conditional",
    sudoReason:
      "Docker commands may require root or docker group membership",
  },
  {
    toolName: "container_docker_bench",
    sudo: "always",
    sudoReason: "Docker Bench requires root for system checks",
  },
  {
    toolName: "container_apparmor_manage",
    sudo: "always",
    sudoReason: "AppArmor management requires root",
  },
  {
    toolName: "container_selinux_manage",
    sudo: "always",
    sudoReason: "SELinux management requires root",
  },
  {
    toolName: "container_daemon_configure",
    sudo: "always",
    sudoReason: "Docker daemon configuration requires root",
  },
  {
    toolName: "container_apparmor_install",
    sudo: "always",
    sudoReason: "Package installation requires root",
  },

  // ── Incident response tools ────────────────────────────────────────────
  {
    toolName: "ir_volatile_collect",
    sudo: "always",
    sudoReason:
      "Volatile data collection requires root for full system access",
  },
  {
    toolName: "ir_ioc_scan",
    sudo: "conditional",
    sudoReason: "IOC scanning benefits from root access",
  },

  // ── Zero-trust / network tools ─────────────────────────────────────────
  {
    toolName: "setup_wireguard",
    sudo: "always",
    sudoReason: "WireGuard interface configuration requires root",
  },
  {
    toolName: "manage_wg_peers",
    sudo: "always",
    sudoReason: "WireGuard peer management requires root",
  },
  {
    toolName: "configure_microsegmentation",
    sudo: "always",
    sudoReason:
      "Firewall rules require root to modify netfilter tables",
  },

  // ── Memory protection tools ────────────────────────────────────────────
  {
    toolName: "enforce_aslr",
    sudo: "always",
    sudoReason: "Modifying kernel parameters requires root",
  },

  // ── eBPF tools ─────────────────────────────────────────────────────────
  {
    toolName: "list_ebpf_programs",
    sudo: "always",
    sudoReason: "eBPF program listing requires root",
    capabilities: ["CAP_SYS_ADMIN"],
  },
  {
    toolName: "deploy_falco_rules",
    sudo: "always",
    sudoReason: "Falco rule deployment requires root",
  },

  // ── Automation tools ───────────────────────────────────────────────────
  {
    toolName: "setup_scheduled_audit",
    sudo: "always",
    sudoReason: "Creating systemd timers/cron jobs requires root",
  },
  {
    toolName: "remove_scheduled_audit",
    sudo: "always",
    sudoReason: "Removing systemd timers/cron jobs requires root",
  },

  // ── Sudo management tools ── sudo: 'never' (manage sudo themselves) ───
  {
    toolName: "sudo_elevate",
    sudo: "never",
    tags: ["bypass-preflight"],
  },
  {
    toolName: "sudo_status",
    sudo: "never",
    tags: ["bypass-preflight"],
  },
  {
    toolName: "sudo_drop",
    sudo: "never",
    tags: ["bypass-preflight"],
  },
  {
    toolName: "sudo_extend",
    sudo: "never",
    tags: ["bypass-preflight"],
  },
  {
    toolName: "preflight_batch_check",
    sudo: "never",
    sudoReason: "Pre-flight checks run without elevation — they only inspect requirements",
    tags: ["bypass-preflight"],
  },

  // ── IDS tools (remaining) ───────────────────────────────────────────
  {
    toolName: "ids_file_integrity_check",
    sudo: "conditional",
    sudoReason:
      "Baseline creation uses sudo tee; display/compare modes do not",
  },
  {
    toolName: "ids_rootkit_summary",
    sudo: "always",
    sudoReason: "Rootkit scanning requires root (delegates to rkhunter/chkrootkit)",
  },

  // ── Network defense tools (remaining) ───────────────────────────────
  {
    toolName: "netdef_port_scan_detect",
    sudo: "conditional",
    sudoReason:
      "Journalctl and dmesg may need root for full log access",
  },

  // ── Compliance tools (remaining) ────────────────────────────────────
  {
    toolName: "compliance_policy_evaluate",
    sudo: "never",
    sudoReason: "Reads files and evaluates policy without privileged operations",
  },
  {
    toolName: "compliance_report",
    sudo: "conditional",
    sudoReason:
      "May invoke Lynis which requires root for comprehensive audit",
  },

  // ── Malware tools (remaining) ───────────────────────────────────────
  {
    toolName: "malware_yara_scan",
    sudo: "never",
    sudoReason: "YARA scanning runs as current user",
  },
  {
    toolName: "malware_suspicious_files",
    sudo: "never",
    sudoReason: "Uses find command as current user",
  },
  {
    toolName: "malware_quarantine_manage",
    sudo: "never",
    sudoReason: "Manages quarantine files without requiring root",
  },

  // ── Backup tools ────────────────────────────────────────────────────
  {
    toolName: "backup_config_files",
    sudo: "never",
    sudoReason: "Uses Node.js fs for backup operations",
  },
  {
    toolName: "backup_system_state",
    sudo: "conditional",
    sudoReason:
      "Firewall and service snapshots use sudo; package listing does not",
  },
  {
    toolName: "backup_restore",
    sudo: "never",
    sudoReason: "Uses Node.js fs for file restoration",
  },
  {
    toolName: "backup_verify",
    sudo: "never",
    sudoReason: "Reads backup files and computes hashes without root",
  },
  {
    toolName: "backup_list",
    sudo: "never",
    sudoReason: "Lists backup directory contents without root",
  },

  // ── Encryption tools (remaining) ────────────────────────────────────
  {
    toolName: "crypto_tls_audit",
    sudo: "never",
    sudoReason: "OpenSSL client connections do not require root",
  },
  {
    toolName: "crypto_cert_expiry",
    sudo: "never",
    sudoReason: "Certificate inspection does not require root",
  },
  {
    toolName: "crypto_gpg_keys",
    sudo: "never",
    sudoReason: "GPG key operations run as current user",
  },
  {
    toolName: "crypto_file_hash",
    sudo: "never",
    sudoReason: "Hash computation does not require root",
  },
  {
    toolName: "crypto_tls_config_audit",
    sudo: "never",
    sudoReason: "Reads web server and OpenSSL configs without root",
  },

  // ── Container tools (remaining) ─────────────────────────────────────
  {
    toolName: "container_namespace_check",
    sudo: "conditional",
    sudoReason:
      "May fall back to sudo lsns if unprivileged access insufficient",
  },
  {
    toolName: "container_image_scan",
    sudo: "never",
    sudoReason: "Trivy/Grype image scanning does not require root",
  },
  {
    toolName: "container_seccomp_audit",
    sudo: "conditional",
    sudoReason:
      "Docker commands may require root or docker group membership",
  },

  // ── Incident response tools (remaining) ─────────────────────────────
  {
    toolName: "ir_timeline_generate",
    sudo: "never",
    sudoReason: "Filesystem timeline uses find as current user",
  },

  // ── Meta/defense tools (remaining) ──────────────────────────────────
  {
    toolName: "defense_check_tools",
    sudo: "conditional",
    sudoReason:
      "Tool availability checks are unprivileged; install_missing uses sudo",
  },
  {
    toolName: "defense_suggest_workflow",
    sudo: "never",
    sudoReason: "Returns static workflow suggestions without system access",
  },
  {
    toolName: "defense_security_posture",
    sudo: "conditional",
    sudoReason:
      "Some checks (firewall, journalctl) use sudo for full results",
  },
  {
    toolName: "defense_change_history",
    sudo: "never",
    sudoReason: "Reads in-memory changelog without system access",
  },
  {
    toolName: "defense_run_workflow",
    sudo: "conditional",
    sudoReason:
      "Workflow steps may include commands that require root",
  },

  // ── Supply chain security tools ─────────────────────────────────────
  {
    toolName: "generate_sbom",
    sudo: "never",
    sudoReason: "SBOM generation scans packages without root",
  },
  {
    toolName: "verify_package_integrity",
    sudo: "never",
    sudoReason: "Package checksum verification runs as current user",
  },
  {
    toolName: "setup_cosign_signing",
    sudo: "never",
    sudoReason: "Cosign signing operates on user-level artifacts",
  },
  {
    toolName: "check_slsa_attestation",
    sudo: "never",
    sudoReason: "SLSA verification runs as current user",
  },

  // ── Memory protection tools (remaining) ─────────────────────────────
  {
    toolName: "audit_memory_protections",
    sudo: "never",
    sudoReason: "Reads ELF headers with readelf/checksec as current user",
  },
  {
    toolName: "report_exploit_mitigations",
    sudo: "never",
    sudoReason: "Reads kernel parameters from /proc and /sys without root",
  },

  // ── Drift detection tools ───────────────────────────────────────────
  {
    toolName: "create_baseline",
    sudo: "never",
    sudoReason: "Hashes files and captures state without root",
  },
  {
    toolName: "compare_to_baseline",
    sudo: "never",
    sudoReason: "Compares hashes against saved baseline without root",
  },
  {
    toolName: "list_drift_alerts",
    sudo: "never",
    sudoReason: "Lists saved baselines without root",
  },

  // ── Vulnerability intel tools ───────────────────────────────────────
  {
    toolName: "lookup_cve",
    sudo: "never",
    sudoReason: "Queries NVD API over HTTP without root",
  },
  {
    toolName: "scan_packages_cves",
    sudo: "never",
    sudoReason: "Scans installed package list without root",
  },
  {
    toolName: "get_patch_urgency",
    sudo: "never",
    sudoReason: "Checks package update status without root",
  },

  // ── Security posture tools ──────────────────────────────────────────
  {
    toolName: "calculate_security_score",
    sudo: "conditional",
    sudoReason:
      "Some subsystem checks (firewall, sysctl) may benefit from root",
  },
  {
    toolName: "get_posture_trend",
    sudo: "never",
    sudoReason: "Reads historical score data without root",
  },
  {
    toolName: "generate_posture_dashboard",
    sudo: "never",
    sudoReason: "Generates dashboard from cached data without root",
  },

  // ── Secrets scanner tools ───────────────────────────────────────────
  {
    toolName: "scan_for_secrets",
    sudo: "never",
    sudoReason: "Scans files for secret patterns as current user",
  },
  {
    toolName: "audit_env_vars",
    sudo: "never",
    sudoReason: "Inspects environment variables as current user",
  },
  {
    toolName: "scan_git_history",
    sudo: "never",
    sudoReason: "Scans git repository history as current user",
  },

  // ── Zero-trust network tools (remaining) ────────────────────────────
  {
    toolName: "setup_mtls",
    sudo: "never",
    sudoReason: "Generates certificates using openssl as current user",
  },

  // ── Container advanced tools (remaining) ────────────────────────────
  {
    toolName: "generate_seccomp_profile",
    sudo: "never",
    sudoReason: "Generates JSON seccomp profile without root",
  },
  {
    toolName: "apply_apparmor_container",
    sudo: "conditional",
    sudoReason:
      "Loading AppArmor profiles with apparmor_parser requires root",
  },
  {
    toolName: "setup_rootless_containers",
    sudo: "conditional",
    sudoReason:
      "May need root to modify /etc/subuid and /etc/subgid",
  },
  {
    toolName: "scan_image_trivy",
    sudo: "never",
    sudoReason: "Trivy image scanning does not require root",
  },

  // ── Compliance extended tools (remaining) ───────────────────────────
  {
    toolName: "run_compliance_check",
    sudo: "conditional",
    sudoReason:
      "May invoke Lynis or OpenSCAP which require root for full scan",
  },

  // ── eBPF tools (remaining) ──────────────────────────────────────────
  {
    toolName: "check_falco",
    sudo: "never",
    sudoReason: "Checks Falco installation and config without root",
  },
  {
    toolName: "get_ebpf_events",
    sudo: "never",
    sudoReason: "Reads Falco JSON log file without root",
  },

  // ── Automation tools (remaining) ────────────────────────────────────
  {
    toolName: "list_scheduled_audits",
    sudo: "never",
    sudoReason: "Lists systemd timers and cron jobs without root",
  },
  {
    toolName: "get_audit_history",
    sudo: "never",
    sudoReason: "Reads audit job output files without root",
  },

  // ── Secrets management tools ────────────────────────────────────────
  {
    toolName: "secrets_scan",
    sudo: "never",
    sudoReason: "Scans filesystem for secrets using grep/find as current user",
  },
  {
    toolName: "secrets_env_audit",
    sudo: "never",
    sudoReason: "Audits environment variables and .env files as current user",
  },
  {
    toolName: "secrets_ssh_key_sprawl",
    sudo: "never",
    sudoReason: "Finds SSH keys and checks permissions as current user",
  },

  // ── Application hardening tools ─────────────────────────────────────
  {
    toolName: "app_harden_audit",
    sudo: "never",
    sudoReason: "Detects running apps using ps/ss without root",
  },
  {
    toolName: "app_harden_recommend",
    sudo: "never",
    sudoReason: "Returns static hardening recommendations",
  },
  {
    toolName: "app_harden_firewall",
    sudo: "conditional",
    sudoReason:
      "Applying iptables rules requires root; dry-run does not",
  },
  {
    toolName: "app_harden_systemd",
    sudo: "always",
    sudoReason:
      "Creating systemd override files and reloading daemon require root",
  },
];

/**
 * Default enhanced manifests that overlay sudo/privilege requirements
 * on top of the legacy-migrated entries.
 *
 * Each entry is generated from {@link SUDO_OVERLAYS} with just enough
 * structure for the merge step in {@link initializeRegistry} to work.
 * Binary requirements come from the legacy migration — these overlays
 * only contribute privilege metadata and tags.
 */
export const DEFAULT_MANIFESTS: ToolManifest[] = SUDO_OVERLAYS.map(
  (o): ToolManifest => ({
    toolName: o.toolName,
    requiredBinaries: [], // merged from legacy during initialization
    sudo: o.sudo,
    sudoReason: o.sudoReason,
    capabilities: o.capabilities,
    tags: o.tags,
    category: inferCategory(o.toolName),
  }),
);

// ── Initialization ───────────────────────────────────────────────────────────

/**
 * Merge two optional tag arrays, deduplicating values.
 */
function mergeTags(
  a: string[] | undefined,
  b: string[] | undefined,
): string[] | undefined {
  if (!a && !b) return undefined;
  const set = new Set<string>([...(a ?? []), ...(b ?? [])]);
  return Array.from(set);
}

/**
 * Initialize the tool registry by:
 *
 * 1. Creating (or reusing) the singleton
 * 2. Migrating from legacy `TOOL_DEPENDENCIES`
 * 3. Overlaying `DEFAULT_MANIFESTS` — merging privilege metadata while
 *    preserving binary requirements from the legacy data
 * 4. Returning the populated registry
 *
 * Safe to call multiple times; subsequent calls on an already-populated
 * singleton are idempotent because the data is deterministic.
 */
export function initializeRegistry(): ToolRegistry {
  const registry = ToolRegistry.instance();

  // Step 1 — Migrate all legacy tool dependencies (binary requirements)
  migrateFromLegacy(registry);

  // Step 2 — Overlay DEFAULT_MANIFESTS with merge semantics
  for (const overlay of DEFAULT_MANIFESTS) {
    const existing = registry.getManifest(overlay.toolName);

    if (existing) {
      // Merge: keep binary requirements from legacy, overlay sudo + meta
      registry.register({
        ...existing,
        sudo: overlay.sudo,
        sudoReason: overlay.sudoReason ?? existing.sudoReason,
        capabilities: overlay.capabilities ?? existing.capabilities,
        tags: mergeTags(existing.tags, overlay.tags),
        // Prefer the overlay category only when the existing one is missing
        category: existing.category ?? overlay.category,
      });
    } else {
      // No legacy entry (e.g., sudo_elevate) — register overlay as-is
      registry.register(overlay);
    }
  }

  return registry;
}
