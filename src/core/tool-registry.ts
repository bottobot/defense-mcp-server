/**
 * Enhanced Tool Registry — single source of truth for all MCP tool requirements.
 *
 * Replaces and extends `tool-dependencies.ts` with richer dependency metadata
 * including privilege requirements, Python/npm packages, system libraries,
 * required files, and Linux capabilities.
 *
 * v0.5.0: Tool consolidation (157 → 78 tools), each entry represents a
 * consolidated action-based tool.
 * v0.6.0: Extended to 94 tools across 32 modules with 16 new security tools.
 * v0.7.0: Final consolidation to 31 tools across 18 modules.
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

// SECURITY (CORE-021): Module-scoped singleton variable prevents external
// mutation via (ToolRegistry as any)._instance — inaccessible outside module.
let _registryInstance: ToolRegistry | null = null;

/**
 * Map-based registry with O(1) lookup for tool manifests.
 * Singleton pattern — use {@link ToolRegistry.instance} to obtain.
 */
export class ToolRegistry {
  private manifests: Map<string, ToolManifest> = new Map();

  /** Get or create the singleton registry instance. */
  static instance(): ToolRegistry {
    if (!_registryInstance) {
      _registryInstance = new ToolRegistry();
    }
    return _registryInstance;
  }

  /**
   * Reset the singleton (primarily for testing).
   * @internal
   */
  static resetInstance(): void {
    _registryInstance = null;
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
  // Exact-match entries
  ["supply_chain", "supply-chain"],
  ["incident_response", "incident-response"],
  ["app_harden", "app-hardening"],
  ["backup", "backup"],
  ["defense_mgmt", "meta"],
  ["sudo_session", "sudo"],
  ["integrity", "integrity"],
  ["log_management", "logging"],
  ["network_defense", "network"],
  ["container_docker", "container"],
  ["container_isolation", "container"],

  // Prefix entries
  ["firewall", "firewall"],
  ["harden_", "hardening"],
  ["access_control", "access"],
  ["compliance", "compliance"],
  ["malware", "malware"],
  ["ebpf", "ebpf"],
  ["crypto", "encryption"],
  ["patch", "patch-management"],
  ["secrets", "secrets"],
  // Solo tools
  ["api_security", "api-security"],
  ["cloud_security", "cloud-security"],
  ["honeypot_manage", "deception"],
  ["dns_security", "dns-security"],
  ["process_security", "process-security"],
  ["threat_intel", "threat-intel"],
  ["vuln_manage", "vulnerability-management"],
  ["waf_manage", "waf"],
  ["wireless_security", "wireless-security"],
  ["zero_trust", "zero-trust"],
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
 * Static sudo requirement data for all 31 consolidated tools.
 * Each consolidated tool uses action parameters, so sudo is typically
 * "conditional" (depends on which action is selected).
 */
const SUDO_OVERLAYS: SudoOverlay[] = [
  // ── Firewall ──────────────────────────────────────────────────────────
  {
    toolName: "firewall",
    sudo: "conditional",
    sudoReason: "Read actions may work without sudo; write actions require root to modify netfilter/ufw rules",
  },

  // ── Hardening ─────────────────────────────────────────────────────────
  {
    toolName: "harden_kernel",
    sudo: "conditional",
    sudoReason: "get/audit actions may work without sudo; set/coredump actions require root",
  },
  {
    toolName: "harden_host",
    sudo: "conditional",
    sudoReason: "audit actions may work without sudo; fix/apply/block actions require root",
  },

  // ── Access control ────────────────────────────────────────────────────
  {
    toolName: "access_control",
    sudo: "conditional",
    sudoReason: "audit actions may work without sudo; harden/configure/restrict actions require root",
  },

  // ── Compliance ────────────────────────────────────────────────────────
  {
    toolName: "compliance",
    sudo: "always",
    sudoReason: "Lynis, OpenSCAP, and CIS checks require root for comprehensive audit",
  },

  // ── Integrity (AIDE + rootkit + file + drift) ─────────────────────────
  {
    toolName: "integrity",
    sudo: "always",
    sudoReason: "AIDE, rootkit scanners, and file integrity checks require root",
  },

  // ── Logging ───────────────────────────────────────────────────────────
  {
    toolName: "log_management",
    sudo: "conditional",
    sudoReason: "Auditd management requires root; journal/fail2ban status may work without sudo",
  },

  // ── Malware ───────────────────────────────────────────────────────────
  {
    toolName: "malware",
    sudo: "conditional",
    sudoReason: "ClamAV scan/update and quarantine management may require root",
  },

  // ── Container ─────────────────────────────────────────────────────────
  {
    toolName: "container_docker",
    sudo: "conditional",
    sudoReason: "Docker socket access may require root or docker group membership",
  },
  {
    toolName: "container_isolation",
    sudo: "conditional",
    sudoReason: "AppArmor/SELinux management requires root; namespace checks may not",
  },

  // ── eBPF ──────────────────────────────────────────────────────────────
  {
    toolName: "ebpf",
    sudo: "always",
    sudoReason: "eBPF operations require CAP_SYS_ADMIN or root",
    capabilities: ["CAP_SYS_ADMIN"],
  },

  // ── Crypto ────────────────────────────────────────────────────────────
  {
    toolName: "crypto",
    sudo: "conditional",
    sudoReason: "LUKS operations require root; TLS audit and file hashing may not",
  },

  // ── Network defense ───────────────────────────────────────────────────
  {
    toolName: "network_defense",
    sudo: "conditional",
    sudoReason: "Packet capture requires root; connection listing may work without sudo",
    capabilities: ["CAP_NET_RAW"],
  },

  // ── Patch management ──────────────────────────────────────────────────
  {
    toolName: "patch",
    sudo: "conditional",
    sudoReason: "Package installation requires root; audit actions may work without sudo",
  },

  // ── Secrets ───────────────────────────────────────────────────────────
  {
    toolName: "secrets",
    sudo: "conditional",
    sudoReason: "May need root to scan restricted paths or git repos",
  },

  // ── Incident response ─────────────────────────────────────────────────
  {
    toolName: "incident_response",
    sudo: "always",
    sudoReason: "Forensic collection, memory dumps, and evidence bagging require root",
  },

  // ── Meta / management ─────────────────────────────────────────────────
  {
    toolName: "defense_mgmt",
    sudo: "conditional",
    sudoReason: "Tool checks may need sudo; workflow execution depends on actions performed",
  },

  // ── Sudo session management ───────────────────────────────────────────
  {
    toolName: "sudo_session",
    sudo: "conditional",
    sudoReason: "elevate/elevate_gui require password; status/drop/extend manage existing session",
    tags: ["bypass-preflight"],
  },

  // ── Solo tools ────────────────────────────────────────────────────────
  {
    toolName: "api_security",
    sudo: "conditional",
    sudoReason: "TLS verification may need elevated access; API discovery works without sudo",
  },
  {
    toolName: "app_harden",
    sudo: "conditional",
    sudoReason: "Audit works without sudo; apply/firewall/systemd actions require root",
  },
  {
    toolName: "backup",
    sudo: "conditional",
    sudoReason: "Backup/restore of system files may require root",
  },
  {
    toolName: "cloud_security",
    sudo: "never",
    sudoReason: "Cloud metadata queries do not require local root",
  },
  {
    toolName: "honeypot_manage",
    sudo: "always",
    sudoReason: "Deploying honeyports and canaries requires root to bind privileged ports",
  },
  {
    toolName: "dns_security",
    sudo: "conditional",
    sudoReason: "DNS audit works without sudo; domain blocking requires root",
  },
  {
    toolName: "process_security",
    sudo: "conditional",
    sudoReason: "Process listing works without sudo; capability/cgroup audits may need root",
  },
  {
    toolName: "supply_chain",
    sudo: "conditional",
    sudoReason: "SBOM generation and SLSA verification may need elevated access",
  },
  {
    toolName: "threat_intel",
    sudo: "conditional",
    sudoReason: "Blocklist application requires root; reputation checks do not",
  },
  {
    toolName: "vuln_manage",
    sudo: "conditional",
    sudoReason: "System scanning may require root; web scanning may not",
  },
  {
    toolName: "waf_manage",
    sudo: "conditional",
    sudoReason: "ModSecurity config changes require root; audit may not",
  },
  {
    toolName: "wireless_security",
    sudo: "conditional",
    sudoReason: "WiFi/BT audit may need root to access hardware interfaces",
  },
  {
    toolName: "zero_trust",
    sudo: "always",
    sudoReason: "WireGuard and mTLS setup require root",
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

/** Guard to prevent redundant re-initialization */
let _registryInitialized = false;

/**
 * Initialize the tool registry by:
 *
 * 1. Creating (or reusing) the singleton
 * 2. Migrating from legacy `TOOL_DEPENDENCIES`
 * 3. Overlaying `DEFAULT_MANIFESTS` — merging privilege metadata while
 *    preserving binary requirements from the legacy data
 * 4. Returning the populated registry
 *
 * Safe to call multiple times; subsequent calls return immediately
 * without re-running migration or overlay logic.
 */
export function initializeRegistry(): ToolRegistry {
  const registry = ToolRegistry.instance();

  // Guard: skip re-initialization if already done
  if (_registryInitialized) return registry;
  _registryInitialized = true;

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

/**
 * Reset the initialization guard (for testing purposes).
 * @internal
 */
export function resetRegistryInitialization(): void {
  _registryInitialized = false;
}
