/**
 * Enhanced Tool Registry — single source of truth for all MCP tool requirements.
 *
 * Replaces and extends `tool-dependencies.ts` with richer dependency metadata
 * including privilege requirements, Python/npm packages, system libraries,
 * required files, and Linux capabilities.
 *
 * After the v0.5.0 tool consolidation (157 → 78 tools), each entry represents
 * a consolidated action-based tool.
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
  /** The MCP tool name (e.g., "firewall_iptables") */
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
  // Exact-match entries (longer/more specific — checked first)
  ["supply_chain", "supply-chain"],
  ["drift_baseline", "drift-detection"],
  ["zero_trust", "zero-trust"],
  ["memory_protection", "hardening"],
  ["list_ebpf_programs", "ebpf"],
  ["falco", "ebpf"],
  ["scan_git_history", "secrets"],
  ["incident_response", "incident-response"],
  ["vulnerability_intel", "patch-management"],
  ["security_posture", "meta"],
  ["scheduled_audit", "meta"],
  ["app_harden", "app-hardening"],
  ["backup", "backup"],

  // Prefix entries (disjoint prefixes)
  ["firewall_", "firewall"],
  ["harden_", "hardening"],
  ["ids_", "ids"],
  ["log_", "logging"],
  ["netdef_", "network"],
  ["compliance_", "compliance"],
  ["malware_", "malware"],
  ["access_", "access"],
  ["crypto_", "encryption"],
  ["container_", "container"],
  ["patch_", "patch-management"],
  ["secrets_", "secrets"],
  ["defense_", "meta"],
  ["sudo_", "sudo"],
  ["preflight_", "sudo"],
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
 * Static sudo requirement data for all 78 consolidated tools.
 * Each consolidated tool uses action parameters, so sudo is typically
 * "conditional" (depends on which action is selected).
 */
const SUDO_OVERLAYS: SudoOverlay[] = [
  // ── Firewall tools ────────────────────────────────────────────────────
  {
    toolName: "firewall_iptables",
    sudo: "conditional",
    sudoReason: "Read actions may work without sudo; write actions require root to modify netfilter tables",
  },
  {
    toolName: "firewall_ufw",
    sudo: "conditional",
    sudoReason: "Status may work without sudo; add/delete rules require root",
  },
  {
    toolName: "firewall_persist",
    sudo: "always",
    sudoReason: "Saving/restoring firewall rules requires root",
  },
  {
    toolName: "firewall_nftables_list",
    sudo: "always",
    sudoReason: "nftables requires root to list ruleset",
  },
  {
    toolName: "firewall_policy_audit",
    sudo: "conditional",
    sudoReason: "May work without sudo but shows limited results",
  },

  // ── Hardening tools ───────────────────────────────────────────────────
  {
    toolName: "harden_sysctl",
    sudo: "conditional",
    sudoReason: "get/audit actions may work without sudo; set action requires root",
  },
  {
    toolName: "harden_service",
    sudo: "conditional",
    sudoReason: "audit/status may work without sudo; manage actions require root",
  },
  {
    toolName: "harden_permissions",
    sudo: "conditional",
    sudoReason: "check/audit actions may work without sudo; fix action requires root",
  },
  {
    toolName: "harden_systemd",
    sudo: "conditional",
    sudoReason: "audit may work without sudo; apply action requires root for unit overrides",
  },
  {
    toolName: "harden_kernel",
    sudo: "conditional",
    sudoReason: "audit action may work without sudo; modules/coredump actions may require root",
  },
  {
    toolName: "harden_bootloader",
    sudo: "conditional",
    sudoReason: "audit may work without sudo; configure action requires root",
  },
  {
    toolName: "harden_misc",
    sudo: "conditional",
    sudoReason: "audit actions may work without sudo; set actions require root",
  },
  {
    toolName: "memory_protection",
    sudo: "conditional",
    sudoReason: "audit/report actions work without sudo; enforce_aslr requires root",
  },

  // ── IDS tools ─────────────────────────────────────────────────────────
  {
    toolName: "ids_aide_manage",
    sudo: "always",
    sudoReason: "AIDE database operations require root",
  },
  {
    toolName: "ids_rootkit_scan",
    sudo: "always",
    sudoReason: "Rootkit scanning requires root (delegates to rkhunter/chkrootkit)",
  },
  {
    toolName: "ids_file_integrity_check",
    sudo: "conditional",
    sudoReason: "Baseline creation may use sudo tee; display/compare modes do not",
  },

  // ── Logging tools ─────────────────────────────────────────────────────
  {
    toolName: "log_auditd",
    sudo: "always",
    sudoReason: "Auditd requires root for rule management and log searching",
  },
  {
    toolName: "log_journalctl_query",
    sudo: "conditional",
    sudoReason: "May work without sudo but shows limited results",
  },
  {
    toolName: "log_fail2ban",
    sudo: "conditional",
    sudoReason: "status may work without sudo; ban/unban/reload actions require root",
  },
  {
    toolName: "log_system",
    sudo: "conditional",
    sudoReason: "May need sudo to read restricted log files",
  },

  // ── Network defense tools ─────────────────────────────────────────────
  {
    toolName: "netdef_connections",
    sudo: "conditional",
    sudoReason: "May work without sudo but shows limited results",
  },
  {
    toolName: "netdef_capture",
    sudo: "always",
    sudoReason: "Packet capture requires root",
    capabilities: ["CAP_NET_RAW"],
  },
  {
    toolName: "netdef_security_audit",
    sudo: "conditional",
    sudoReason: "scan_detect may need log access; self_scan requires root for SYN scans",
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
    toolName: "compliance_check",
    sudo: "conditional",
    sudoReason: "CIS checks may need root for full results; framework checks vary",
  },
  {
    toolName: "compliance_policy_evaluate",
    sudo: "never",
    sudoReason: "Reads files and evaluates policy without privileged operations",
  },
  {
    toolName: "compliance_report",
    sudo: "conditional",
    sudoReason: "May invoke Lynis which requires root for comprehensive audit",
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

  // ── Malware tools ─────────────────────────────────────────────────────
  {
    toolName: "malware_clamav",
    sudo: "conditional",
    sudoReason: "scan may need root for restricted dirs; update always requires root",
  },
  {
    toolName: "malware_yara_scan",
    sudo: "never",
    sudoReason: "YARA scanning runs as current user",
  },
  {
    toolName: "malware_file_scan",
    sudo: "conditional",
    sudoReason: "suspicious file scan may need root; webshell detection may need root for web dirs",
  },
  {
    toolName: "malware_quarantine_manage",
    sudo: "never",
    sudoReason: "Manages quarantine files without requiring root",
  },

  // ── Backup tools ──────────────────────────────────────────────────────
  {
    toolName: "backup",
    sudo: "conditional",
    sudoReason: "config/restore/verify/list work without sudo; state snapshot may need sudo for firewall/service data",
  },

  // ── Access control tools ──────────────────────────────────────────────
  {
    toolName: "access_ssh",
    sudo: "conditional",
    sudoReason: "audit/cipher_audit may work without sudo; harden action requires root",
  },
  {
    toolName: "access_sudo_audit",
    sudo: "conditional",
    sudoReason: "May work without sudo but shows limited results",
  },
  {
    toolName: "access_user_audit",
    sudo: "conditional",
    sudoReason: "May work without sudo but shows limited results",
  },
  {
    toolName: "access_password_policy",
    sudo: "conditional",
    sudoReason: "audit may work without sudo; set action requires root",
  },
  {
    toolName: "access_pam",
    sudo: "conditional",
    sudoReason: "audit needs root to read PAM files; configure requires root",
  },
  {
    toolName: "access_restrict_shell",
    sudo: "always",
    sudoReason: "Changing user shells requires root",
  },

  // ── Encryption tools ──────────────────────────────────────────────────
  {
    toolName: "crypto_tls",
    sudo: "conditional",
    sudoReason: "remote_audit/cert_expiry work without sudo; config_audit may need root for web server configs",
  },
  {
    toolName: "crypto_gpg_keys",
    sudo: "never",
    sudoReason: "GPG key operations run as current user",
  },
  {
    toolName: "crypto_luks_manage",
    sudo: "always",
    sudoReason: "LUKS operations require root",
  },
  {
    toolName: "crypto_file_hash",
    sudo: "never",
    sudoReason: "Hash computation does not require root",
  },

  // ── Container tools ───────────────────────────────────────────────────
  {
    toolName: "container_docker",
    sudo: "conditional",
    sudoReason: "Docker commands may require root or docker group membership",
  },
  {
    toolName: "container_apparmor",
    sudo: "conditional",
    sudoReason: "status/list may work without sudo; enforce/complain/install require root",
  },
  {
    toolName: "container_selinux_manage",
    sudo: "always",
    sudoReason: "SELinux management requires root",
  },
  {
    toolName: "container_namespace_check",
    sudo: "conditional",
    sudoReason: "May fall back to sudo lsns if unprivileged access insufficient",
  },
  {
    toolName: "container_image_scan",
    sudo: "never",
    sudoReason: "Trivy/Grype image scanning does not require root",
  },
  {
    toolName: "container_security_config",
    sudo: "conditional",
    sudoReason: "seccomp_profile generation does not need root; rootless setup may need root for subuid/subgid",
  },

  // ── Patch management tools ────────────────────────────────────────────
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
  {
    toolName: "vulnerability_intel",
    sudo: "never",
    sudoReason: "CVE lookup and package scanning do not require root",
  },

  // ── Secrets management tools ──────────────────────────────────────────
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
  {
    toolName: "scan_git_history",
    sudo: "never",
    sudoReason: "Scans git repository history as current user",
  },

  // ── Incident response tools ───────────────────────────────────────────
  {
    toolName: "incident_response",
    sudo: "conditional",
    sudoReason: "collect action requires root for full system access; ioc_scan benefits from root; timeline works as user",
  },

  // ── Meta tools ────────────────────────────────────────────────────────
  {
    toolName: "defense_check_tools",
    sudo: "conditional",
    sudoReason: "Tool checks are unprivileged; install_missing uses sudo",
  },
  {
    toolName: "defense_workflow",
    sudo: "conditional",
    sudoReason: "suggest action is unprivileged; run action may include commands that require root",
  },
  {
    toolName: "defense_change_history",
    sudo: "never",
    sudoReason: "Reads in-memory changelog without system access",
  },
  {
    toolName: "security_posture",
    sudo: "conditional",
    sudoReason: "score/dashboard may invoke checks that benefit from root; trend is unprivileged",
  },
  {
    toolName: "scheduled_audit",
    sudo: "conditional",
    sudoReason: "create/remove actions require root for systemd/cron; list/history are unprivileged",
  },

  // ── Sudo management tools ─────────────────────────────────────────────
  {
    toolName: "sudo_elevate",
    sudo: "never",
    tags: ["bypass-preflight"],
  },
  {
    toolName: "sudo_elevate_gui",
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

  // ── Supply chain security tools ───────────────────────────────────────
  {
    toolName: "supply_chain",
    sudo: "conditional",
    sudoReason: "sbom/verify actions work without root; sign action may need credentials",
  },

  // ── Drift detection tools ─────────────────────────────────────────────
  {
    toolName: "drift_baseline",
    sudo: "never",
    sudoReason: "Hashes files and captures state without root",
  },

  // ── Zero-trust network tools ──────────────────────────────────────────
  {
    toolName: "zero_trust",
    sudo: "conditional",
    sudoReason: "wireguard/wg_peers/microsegment require root; mtls cert generation does not",
  },

  // ── eBPF tools ────────────────────────────────────────────────────────
  {
    toolName: "list_ebpf_programs",
    sudo: "always",
    sudoReason: "eBPF program listing requires root",
    capabilities: ["CAP_SYS_ADMIN"],
  },
  {
    toolName: "falco",
    sudo: "conditional",
    sudoReason: "status/events may work without root; deploy_rules requires root",
  },

  // ── Application hardening tools ───────────────────────────────────────
  {
    toolName: "app_harden",
    sudo: "conditional",
    sudoReason: "audit/recommend are unprivileged; firewall/systemd actions require root",
  },
];

/**
 * Default enhanced manifests that overlay sudo/privilege requirements
 * on top of the legacy-migrated entries.
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
      // No legacy entry — register overlay as-is
      registry.register(overlay);
    }
  }

  return registry;
}
