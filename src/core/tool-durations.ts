/**
 * Tool duration estimation database for Defense MCP Server.
 *
 * Provides estimated execution times, complexity levels, and recommended
 * timeouts for every tool action. This ensures:
 * 1. No tool is skipped due to premature timeouts
 * 2. Users see clear duration estimates before execution
 * 3. Timeouts are appropriately sized per action
 *
 * @module tool-durations
 */

// ── Types ────────────────────────────────────────────────────────────────────

/** Complexity level determines default timeout multiplier */
export type Complexity = "low" | "medium" | "high" | "critical";

/** Duration estimate for a specific tool action */
export interface DurationEstimate {
  /** Human-readable description of what this action does */
  description: string;
  /** Estimated minimum duration in seconds */
  minSeconds: number;
  /** Estimated maximum duration in seconds */
  maxSeconds: number;
  /** Complexity level */
  complexity: Complexity;
  /** Recommended timeout in milliseconds (must exceed maxSeconds) */
  recommendedTimeoutMs: number;
  /** What factors affect duration */
  durationFactors: string[];
  /** Whether this action supports progress tracking */
  supportsProgress: boolean;
}

/** Composite key: "toolName:action" */
export type DurationKey = string;

// ── Timeout multipliers by complexity ────────────────────────────────────────

const COMPLEXITY_TIMEOUT_MULTIPLIER: Record<Complexity, number> = {
  low: 1,      // 60s base
  medium: 2,   // 120s
  high: 5,     // 300s
  critical: 15, // 900s
};

/** Base timeout in milliseconds */
const BASE_TIMEOUT_MS = 60_000;

// ── Duration Database ────────────────────────────────────────────────────────

/**
 * Complete duration estimate database for all tool actions.
 * Key format: "toolName:action"
 */
export const DURATION_DATABASE: Record<DurationKey, DurationEstimate> = {
  // ── Defense Management ──────────────────────────────────────────
  "defense_mgmt:check_tools": {
    description: "Check availability of all security tools",
    minSeconds: 5,
    maxSeconds: 15,
    complexity: "low",
    recommendedTimeoutMs: 60_000,
    durationFactors: ["Number of tools to check", "Disk I/O speed"],
    supportsProgress: false,
  },
  "defense_mgmt:check_optional_deps": {
    description: "Check optional third-party tool status",
    minSeconds: 3,
    maxSeconds: 10,
    complexity: "low",
    recommendedTimeoutMs: 60_000,
    durationFactors: ["Number of packages to query"],
    supportsProgress: false,
  },
  "defense_mgmt:posture_score": {
    description: "Calculate overall security posture score",
    minSeconds: 5,
    maxSeconds: 15,
    complexity: "low",
    recommendedTimeoutMs: 60_000,
    durationFactors: ["Number of sysctl checks", "Service enumeration"],
    supportsProgress: false,
  },
  "defense_mgmt:posture_dashboard": {
    description: "Generate security posture dashboard",
    minSeconds: 5,
    maxSeconds: 20,
    complexity: "low",
    recommendedTimeoutMs: 60_000,
    durationFactors: ["Number of checks to aggregate"],
    supportsProgress: false,
  },
  "defense_mgmt:workflow_suggest": {
    description: "Suggest security workflow",
    minSeconds: 1,
    maxSeconds: 5,
    complexity: "low",
    recommendedTimeoutMs: 60_000,
    durationFactors: [],
    supportsProgress: false,
  },
  "defense_mgmt:report_generate": {
    description: "Generate security report",
    minSeconds: 5,
    maxSeconds: 30,
    complexity: "medium",
    recommendedTimeoutMs: 120_000,
    durationFactors: ["Report type", "Data sources included"],
    supportsProgress: false,
  },
  "defense_mgmt:install_optional_deps": {
    description: "Install optional security tools",
    minSeconds: 30,
    maxSeconds: 300,
    complexity: "high",
    recommendedTimeoutMs: 600_000,
    durationFactors: ["Number of tools to install", "Network speed", "Package size"],
    supportsProgress: true,
  },

  // ── Compliance ─────────────────────────────────────────────────
  "compliance:lynis_audit": {
    description: "Run Lynis security audit (271 tests)",
    minSeconds: 120,
    maxSeconds: 300,
    complexity: "high",
    recommendedTimeoutMs: 600_000,
    durationFactors: ["Number of tests", "Service count", "Package count", "Filesystem size"],
    supportsProgress: true,
  },
  "compliance:oscap_scan": {
    description: "Run OpenSCAP compliance scan",
    minSeconds: 180,
    maxSeconds: 480,
    complexity: "high",
    recommendedTimeoutMs: 600_000,
    durationFactors: ["Profile rules count", "System complexity"],
    supportsProgress: true,
  },
  "compliance:cis_check": {
    description: "Run CIS benchmark checks",
    minSeconds: 15,
    maxSeconds: 60,
    complexity: "medium",
    recommendedTimeoutMs: 120_000,
    durationFactors: ["Number of CIS sections", "CIS level"],
    supportsProgress: false,
  },
  "compliance:framework_check": {
    description: "Run compliance framework check",
    minSeconds: 10,
    maxSeconds: 30,
    complexity: "medium",
    recommendedTimeoutMs: 120_000,
    durationFactors: ["Framework type", "Number of controls"],
    supportsProgress: false,
  },
  "compliance:policy_evaluate": {
    description: "Evaluate security policy",
    minSeconds: 5,
    maxSeconds: 15,
    complexity: "low",
    recommendedTimeoutMs: 60_000,
    durationFactors: ["Policy complexity"],
    supportsProgress: false,
  },

  // ── Malware & AV ───────────────────────────────────────────────
  "malware:clamav_scan": {
    description: "ClamAV recursive malware scan with signature matching",
    minSeconds: 120,
    maxSeconds: 600,
    complexity: "high",
    recommendedTimeoutMs: 900_000,
    durationFactors: ["Directory size", "File count", "Max file size", "Virus definition count"],
    supportsProgress: true,
  },
  "malware:clamav_update": {
    description: "Update ClamAV virus definitions",
    minSeconds: 30,
    maxSeconds: 120,
    complexity: "medium",
    recommendedTimeoutMs: 300_000,
    durationFactors: ["Network speed", "Definition size"],
    supportsProgress: true,
  },
  "malware:yara_scan": {
    description: "YARA rules-based file scanning",
    minSeconds: 30,
    maxSeconds: 300,
    complexity: "high",
    recommendedTimeoutMs: 600_000,
    durationFactors: ["Rules count", "Target size", "File count"],
    supportsProgress: true,
  },
  "malware:file_scan_suspicious": {
    description: "Scan for suspicious files (SUID, world-writable, etc.)",
    minSeconds: 10,
    maxSeconds: 60,
    complexity: "medium",
    recommendedTimeoutMs: 120_000,
    durationFactors: ["Search path size", "Max depth", "Check types"],
    supportsProgress: false,
  },
  "malware:file_scan_webshell": {
    description: "Scan for web shell indicators",
    minSeconds: 10,
    maxSeconds: 60,
    complexity: "medium",
    recommendedTimeoutMs: 120_000,
    durationFactors: ["Web directory size", "File count"],
    supportsProgress: false,
  },

  // ── Integrity ──────────────────────────────────────────────────
  "integrity:rootkit_rkhunter": {
    description: "Rootkit Hunter system-wide rootkit scan",
    minSeconds: 180,
    maxSeconds: 900,
    complexity: "critical",
    recommendedTimeoutMs: 1_200_000,
    durationFactors: ["Kernel modules count", "Binary count", "User count", "Network connections"],
    supportsProgress: true,
  },
  "integrity:rootkit_chkrootkit": {
    description: "chkrootkit rootkit scan",
    minSeconds: 60,
    maxSeconds: 300,
    complexity: "high",
    recommendedTimeoutMs: 600_000,
    durationFactors: ["System binary count", "Process count"],
    supportsProgress: true,
  },
  "integrity:rootkit_all": {
    description: "Run all rootkit scanners (rkhunter + chkrootkit)",
    minSeconds: 240,
    maxSeconds: 1200,
    complexity: "critical",
    recommendedTimeoutMs: 1_800_000,
    durationFactors: ["Combined scanner workload"],
    supportsProgress: true,
  },
  "integrity:aide_init": {
    description: "Initialize AIDE file integrity baseline",
    minSeconds: 300,
    maxSeconds: 1800,
    complexity: "critical",
    recommendedTimeoutMs: 2_400_000,
    durationFactors: ["Filesystem size", "File count", "Hashing algorithm"],
    supportsProgress: true,
  },
  "integrity:aide_check": {
    description: "Check AIDE file integrity against baseline",
    minSeconds: 120,
    maxSeconds: 600,
    complexity: "high",
    recommendedTimeoutMs: 900_000,
    durationFactors: ["Monitored file count", "Change volume"],
    supportsProgress: true,
  },
  "integrity:aide_update": {
    description: "Update AIDE baseline database",
    minSeconds: 120,
    maxSeconds: 600,
    complexity: "high",
    recommendedTimeoutMs: 900_000,
    durationFactors: ["Changed file count", "Filesystem size"],
    supportsProgress: true,
  },
  "integrity:file_integrity": {
    description: "SHA-256 file integrity verification",
    minSeconds: 5,
    maxSeconds: 30,
    complexity: "low",
    recommendedTimeoutMs: 60_000,
    durationFactors: ["File count", "File sizes"],
    supportsProgress: false,
  },
  "integrity:baseline_create": {
    description: "Create drift detection baseline",
    minSeconds: 10,
    maxSeconds: 120,
    complexity: "medium",
    recommendedTimeoutMs: 300_000,
    durationFactors: ["Directory count", "File count"],
    supportsProgress: false,
  },

  // ── Firewall ───────────────────────────────────────────────────
  "firewall:iptables_list": {
    description: "List iptables firewall rules",
    minSeconds: 2,
    maxSeconds: 10,
    complexity: "low",
    recommendedTimeoutMs: 60_000,
    durationFactors: ["Rule count"],
    supportsProgress: false,
  },
  "firewall:nftables_list": {
    description: "List nftables ruleset",
    minSeconds: 2,
    maxSeconds: 10,
    complexity: "low",
    recommendedTimeoutMs: 60_000,
    durationFactors: ["Rule count"],
    supportsProgress: false,
  },
  "firewall:policy_audit": {
    description: "Audit firewall policy compliance",
    minSeconds: 5,
    maxSeconds: 20,
    complexity: "low",
    recommendedTimeoutMs: 60_000,
    durationFactors: ["Rule count", "Policy complexity"],
    supportsProgress: false,
  },

  // ── Kernel/Host Hardening ──────────────────────────────────────
  "harden_kernel:sysctl_audit": {
    description: "Audit sysctl kernel parameters (43 settings)",
    minSeconds: 5,
    maxSeconds: 20,
    complexity: "low",
    recommendedTimeoutMs: 60_000,
    durationFactors: ["Settings count"],
    supportsProgress: false,
  },
  "harden_kernel:kernel_audit": {
    description: "Audit kernel security (CPU vulns, LSM, lockdown)",
    minSeconds: 10,
    maxSeconds: 30,
    complexity: "medium",
    recommendedTimeoutMs: 120_000,
    durationFactors: ["CPU vulnerability count", "LSM checks"],
    supportsProgress: false,
  },
  "harden_kernel:bootloader_audit": {
    description: "Audit bootloader security configuration",
    minSeconds: 5,
    maxSeconds: 15,
    complexity: "low",
    recommendedTimeoutMs: 60_000,
    durationFactors: ["Bootloader type"],
    supportsProgress: false,
  },
  "harden_kernel:memory_audit": {
    description: "Audit memory protection settings",
    minSeconds: 5,
    maxSeconds: 20,
    complexity: "low",
    recommendedTimeoutMs: 60_000,
    durationFactors: ["Binary count to check"],
    supportsProgress: false,
  },
  "harden_host:permissions_audit": {
    description: "Audit critical file permissions",
    minSeconds: 5,
    maxSeconds: 20,
    complexity: "low",
    recommendedTimeoutMs: 60_000,
    durationFactors: ["File count to check"],
    supportsProgress: false,
  },
  "harden_host:service_audit": {
    description: "Audit running services for security",
    minSeconds: 5,
    maxSeconds: 30,
    complexity: "low",
    recommendedTimeoutMs: 60_000,
    durationFactors: ["Service count"],
    supportsProgress: false,
  },
  "harden_host:systemd_audit": {
    description: "Audit systemd service sandboxing",
    minSeconds: 10,
    maxSeconds: 30,
    complexity: "medium",
    recommendedTimeoutMs: 120_000,
    durationFactors: ["Service count", "Sandbox analysis depth"],
    supportsProgress: false,
  },

  // ── Access Control ─────────────────────────────────────────────
  "access_control:ssh_audit": {
    description: "Audit SSH server configuration",
    minSeconds: 2,
    maxSeconds: 10,
    complexity: "low",
    recommendedTimeoutMs: 60_000,
    durationFactors: ["Config file size"],
    supportsProgress: false,
  },
  "access_control:pam_audit": {
    description: "Audit PAM configuration files",
    minSeconds: 5,
    maxSeconds: 15,
    complexity: "low",
    recommendedTimeoutMs: 60_000,
    durationFactors: ["PAM file count"],
    supportsProgress: false,
  },
  "access_control:sudo_audit": {
    description: "Audit sudoers configuration",
    minSeconds: 5,
    maxSeconds: 20,
    complexity: "low",
    recommendedTimeoutMs: 60_000,
    durationFactors: ["Sudoers file count", "Rule count"],
    supportsProgress: false,
  },
  "access_control:user_audit": {
    description: "Audit user accounts and privileges",
    minSeconds: 5,
    maxSeconds: 20,
    complexity: "low",
    recommendedTimeoutMs: 60_000,
    durationFactors: ["User count"],
    supportsProgress: false,
  },
  "access_control:password_policy_audit": {
    description: "Audit password policy settings",
    minSeconds: 5,
    maxSeconds: 15,
    complexity: "low",
    recommendedTimeoutMs: 60_000,
    durationFactors: ["Policy files to check"],
    supportsProgress: false,
  },

  // ── Network Defense ────────────────────────────────────────────
  "network_defense:connections_audit": {
    description: "Audit active network connections",
    minSeconds: 5,
    maxSeconds: 15,
    complexity: "low",
    recommendedTimeoutMs: 60_000,
    durationFactors: ["Connection count"],
    supportsProgress: false,
  },
  "network_defense:security_ipv6": {
    description: "Audit IPv6 security configuration",
    minSeconds: 5,
    maxSeconds: 15,
    complexity: "low",
    recommendedTimeoutMs: 60_000,
    durationFactors: ["Interface count"],
    supportsProgress: false,
  },
  "network_defense:security_self_scan": {
    description: "Self-scan for open ports and services",
    minSeconds: 10,
    maxSeconds: 60,
    complexity: "medium",
    recommendedTimeoutMs: 120_000,
    durationFactors: ["Port range", "Service count"],
    supportsProgress: false,
  },
  "network_defense:capture_dns": {
    description: "Capture DNS traffic",
    minSeconds: 10,
    maxSeconds: 120,
    complexity: "medium",
    recommendedTimeoutMs: 300_000,
    durationFactors: ["Capture duration", "Traffic volume"],
    supportsProgress: true,
  },

  // ── Vulnerability Management ───────────────────────────────────
  "vuln_manage:scan_system": {
    description: "Nmap system vulnerability scan",
    minSeconds: 10,
    maxSeconds: 300,
    complexity: "medium",
    recommendedTimeoutMs: 600_000,
    durationFactors: ["Scan type", "Port range", "Target count"],
    supportsProgress: true,
  },
  "vuln_manage:scan_web": {
    description: "Nikto web vulnerability scan",
    minSeconds: 60,
    maxSeconds: 600,
    complexity: "high",
    recommendedTimeoutMs: 900_000,
    durationFactors: ["Target complexity", "Plugin count"],
    supportsProgress: true,
  },

  // ── Cryptography ───────────────────────────────────────────────
  "crypto:cert_inventory": {
    description: "Inventory all SSL/TLS certificates",
    minSeconds: 15,
    maxSeconds: 60,
    complexity: "medium",
    recommendedTimeoutMs: 120_000,
    durationFactors: ["Certificate count", "Search paths"],
    supportsProgress: false,
  },
  "crypto:tls_remote_audit": {
    description: "Audit remote TLS configuration",
    minSeconds: 10,
    maxSeconds: 60,
    complexity: "medium",
    recommendedTimeoutMs: 120_000,
    durationFactors: ["Host responsiveness", "Cipher suite count"],
    supportsProgress: false,
  },

  // ── Logging ────────────────────────────────────────────────────
  "log_management:auditd_rules": {
    description: "List or manage auditd rules",
    minSeconds: 2,
    maxSeconds: 10,
    complexity: "low",
    recommendedTimeoutMs: 60_000,
    durationFactors: ["Rule count"],
    supportsProgress: false,
  },
  "log_management:fail2ban_status": {
    description: "Check fail2ban jail status",
    minSeconds: 2,
    maxSeconds: 10,
    complexity: "low",
    recommendedTimeoutMs: 60_000,
    durationFactors: ["Jail count"],
    supportsProgress: false,
  },
  "log_management:syslog_analyze": {
    description: "Analyze syslog for security events",
    minSeconds: 10,
    maxSeconds: 60,
    complexity: "medium",
    recommendedTimeoutMs: 120_000,
    durationFactors: ["Log size", "Search patterns"],
    supportsProgress: false,
  },

  // ── Patch Management ───────────────────────────────────────────
  "patch:update_audit": {
    description: "Audit pending system updates",
    minSeconds: 5,
    maxSeconds: 30,
    complexity: "low",
    recommendedTimeoutMs: 60_000,
    durationFactors: ["Package count"],
    supportsProgress: false,
  },
  "patch:integrity_check": {
    description: "Verify package file integrity",
    minSeconds: 10,
    maxSeconds: 120,
    complexity: "medium",
    recommendedTimeoutMs: 300_000,
    durationFactors: ["Package count", "File count"],
    supportsProgress: true,
  },
  "patch:vuln_scan": {
    description: "Scan packages for known vulnerabilities",
    minSeconds: 30,
    maxSeconds: 180,
    complexity: "high",
    recommendedTimeoutMs: 300_000,
    durationFactors: ["Package count", "CVE database size"],
    supportsProgress: true,
  },

  // ── Process Security ───────────────────────────────────────────
  "process_security:audit_running": {
    description: "Audit running processes for anomalies",
    minSeconds: 5,
    maxSeconds: 20,
    complexity: "low",
    recommendedTimeoutMs: 60_000,
    durationFactors: ["Process count"],
    supportsProgress: false,
  },
  "process_security:detect_anomalies": {
    description: "Detect process anomalies",
    minSeconds: 10,
    maxSeconds: 30,
    complexity: "medium",
    recommendedTimeoutMs: 120_000,
    durationFactors: ["Process count", "Analysis depth"],
    supportsProgress: false,
  },

  // ── Container/Docker ───────────────────────────────────────────
  "container_docker:audit": {
    description: "Docker security audit",
    minSeconds: 10,
    maxSeconds: 30,
    complexity: "medium",
    recommendedTimeoutMs: 120_000,
    durationFactors: ["Container count", "Image count"],
    supportsProgress: false,
  },
  "container_docker:bench": {
    description: "Docker CIS benchmark",
    minSeconds: 30,
    maxSeconds: 180,
    complexity: "high",
    recommendedTimeoutMs: 300_000,
    durationFactors: ["Check sections", "Container count"],
    supportsProgress: true,
  },
  "container_docker:image_scan": {
    description: "Docker image vulnerability scan",
    minSeconds: 60,
    maxSeconds: 300,
    complexity: "high",
    recommendedTimeoutMs: 600_000,
    durationFactors: ["Image size", "Layer count", "Scanner type"],
    supportsProgress: true,
  },
  "container_isolation:apparmor_status": {
    description: "Check AppArmor status and profiles",
    minSeconds: 3,
    maxSeconds: 10,
    complexity: "low",
    recommendedTimeoutMs: 60_000,
    durationFactors: ["Profile count"],
    supportsProgress: false,
  },

  // ── Secrets ────────────────────────────────────────────────────
  "secrets:scan": {
    description: "Scan filesystem for exposed secrets",
    minSeconds: 15,
    maxSeconds: 120,
    complexity: "medium",
    recommendedTimeoutMs: 300_000,
    durationFactors: ["Search path size", "Max depth", "Scan type"],
    supportsProgress: false,
  },
  "secrets:env_audit": {
    description: "Audit environment variables for secrets",
    minSeconds: 5,
    maxSeconds: 15,
    complexity: "low",
    recommendedTimeoutMs: 60_000,
    durationFactors: ["Environment variable count"],
    supportsProgress: false,
  },
  "secrets:ssh_key_sprawl": {
    description: "Find SSH key sprawl across system",
    minSeconds: 10,
    maxSeconds: 60,
    complexity: "medium",
    recommendedTimeoutMs: 120_000,
    durationFactors: ["Search path size", "User count"],
    supportsProgress: false,
  },
  "secrets:git_history_scan": {
    description: "Scan git history for leaked secrets",
    minSeconds: 30,
    maxSeconds: 300,
    complexity: "high",
    recommendedTimeoutMs: 600_000,
    durationFactors: ["Repository size", "Commit count"],
    supportsProgress: true,
  },

  // ── DNS Security ───────────────────────────────────────────────
  "dns_security:audit_resolv": {
    description: "Audit DNS resolver configuration",
    minSeconds: 3,
    maxSeconds: 10,
    complexity: "low",
    recommendedTimeoutMs: 60_000,
    durationFactors: ["Nameserver count"],
    supportsProgress: false,
  },
  "dns_security:check_dnssec": {
    description: "Check DNSSEC validation",
    minSeconds: 5,
    maxSeconds: 30,
    complexity: "low",
    recommendedTimeoutMs: 60_000,
    durationFactors: ["Domain complexity"],
    supportsProgress: false,
  },
  "dns_security:detect_tunneling": {
    description: "Detect DNS tunneling attempts",
    minSeconds: 30,
    maxSeconds: 120,
    complexity: "medium",
    recommendedTimeoutMs: 300_000,
    durationFactors: ["Capture duration", "Traffic volume"],
    supportsProgress: true,
  },

  // ── Wireless ───────────────────────────────────────────────────
  "wireless_security:wifi_audit": {
    description: "Audit WiFi security configuration",
    minSeconds: 3,
    maxSeconds: 10,
    complexity: "low",
    recommendedTimeoutMs: 60_000,
    durationFactors: ["Interface count", "Saved network count"],
    supportsProgress: false,
  },
  "wireless_security:bt_audit": {
    description: "Audit Bluetooth security",
    minSeconds: 3,
    maxSeconds: 10,
    complexity: "low",
    recommendedTimeoutMs: 60_000,
    durationFactors: ["Bluetooth adapter count"],
    supportsProgress: false,
  },

  // ── App Hardening ──────────────────────────────────────────────
  "app_harden:audit": {
    description: "Audit running application security",
    minSeconds: 5,
    maxSeconds: 20,
    complexity: "low",
    recommendedTimeoutMs: 60_000,
    durationFactors: ["Listening service count"],
    supportsProgress: false,
  },
  "app_harden:recommend": {
    description: "Generate hardening recommendations",
    minSeconds: 5,
    maxSeconds: 15,
    complexity: "low",
    recommendedTimeoutMs: 60_000,
    durationFactors: ["Application type"],
    supportsProgress: false,
  },

  // ── Cloud Security ─────────────────────────────────────────────
  "cloud_security:detect_environment": {
    description: "Detect cloud environment",
    minSeconds: 5,
    maxSeconds: 15,
    complexity: "low",
    recommendedTimeoutMs: 60_000,
    durationFactors: ["Metadata endpoint responsiveness"],
    supportsProgress: false,
  },
  "cloud_security:audit_metadata": {
    description: "Audit cloud metadata security",
    minSeconds: 5,
    maxSeconds: 30,
    complexity: "medium",
    recommendedTimeoutMs: 60_000,
    durationFactors: ["Cloud provider", "Metadata complexity"],
    supportsProgress: false,
  },

  // ── Incident Response ──────────────────────────────────────────
  "incident_response:collect": {
    description: "Collect volatile forensic data",
    minSeconds: 10,
    maxSeconds: 60,
    complexity: "medium",
    recommendedTimeoutMs: 120_000,
    durationFactors: ["Process count", "Connection count"],
    supportsProgress: false,
  },
  "incident_response:ioc_scan": {
    description: "Scan for indicators of compromise",
    minSeconds: 15,
    maxSeconds: 60,
    complexity: "medium",
    recommendedTimeoutMs: 120_000,
    durationFactors: ["IOC check types", "Process count"],
    supportsProgress: false,
  },
  "incident_response:timeline": {
    description: "Build forensic timeline",
    minSeconds: 10,
    maxSeconds: 60,
    complexity: "medium",
    recommendedTimeoutMs: 120_000,
    durationFactors: ["Hours to look back", "File types"],
    supportsProgress: false,
  },
  "incident_response:forensics_memory_dump": {
    description: "Create memory dump for forensics",
    minSeconds: 60,
    maxSeconds: 600,
    complexity: "critical",
    recommendedTimeoutMs: 900_000,
    durationFactors: ["System memory size"],
    supportsProgress: true,
  },
  "incident_response:forensics_network_capture": {
    description: "Capture network traffic for forensics",
    minSeconds: 30,
    maxSeconds: 300,
    complexity: "high",
    recommendedTimeoutMs: 600_000,
    durationFactors: ["Capture duration", "Traffic volume"],
    supportsProgress: true,
  },

  // ── Supply Chain ───────────────────────────────────────────────
  "supply_chain:sbom": {
    description: "Generate Software Bill of Materials",
    minSeconds: 30,
    maxSeconds: 180,
    complexity: "medium",
    recommendedTimeoutMs: 300_000,
    durationFactors: ["Project size", "Dependency count"],
    supportsProgress: true,
  },
};

// ── Lookup Functions ─────────────────────────────────────────────────────────

/**
 * Get the duration estimate for a specific tool action.
 * Returns `undefined` if no estimate exists.
 */
export function getDurationEstimate(
  toolName: string,
  action: string
): DurationEstimate | undefined {
  const key = `${toolName}:${action}`;
  return DURATION_DATABASE[key];
}

/**
 * Get the recommended timeout in milliseconds for a tool action.
 * Falls back to complexity-based calculation if no specific estimate exists,
 * or to the provided default.
 */
export function getRecommendedTimeout(
  toolName: string,
  action: string,
  fallbackMs?: number
): number {
  const estimate = getDurationEstimate(toolName, action);
  if (estimate) {
    return estimate.recommendedTimeoutMs;
  }
  // If no specific estimate, use complexity-based default
  return fallbackMs ?? BASE_TIMEOUT_MS;
}

/**
 * Get the complexity-based timeout multiplier.
 */
export function getComplexityMultiplier(complexity: Complexity): number {
  return COMPLEXITY_TIMEOUT_MULTIPLIER[complexity];
}

/**
 * Format a duration estimate as a human-readable string.
 * Examples: "~5s", "15-30s", "2-5 min", "5-30 min"
 */
export function formatDurationEstimate(estimate: DurationEstimate): string {
  const { minSeconds, maxSeconds } = estimate;

  if (maxSeconds < 60) {
    if (minSeconds === maxSeconds) {
      return `~${minSeconds}s`;
    }
    return `${minSeconds}-${maxSeconds}s`;
  }

  const minMin = Math.floor(minSeconds / 60);
  const maxMin = Math.ceil(maxSeconds / 60);

  if (minSeconds < 60) {
    return `${minSeconds}s-${maxMin} min`;
  }

  if (minMin === maxMin) {
    return `~${minMin} min`;
  }
  return `${minMin}-${maxMin} min`;
}

/**
 * Format a duration in milliseconds as a human-readable elapsed time.
 * Examples: "1.2s", "45.3s", "2m 15s", "1h 5m"
 */
export function formatElapsed(ms: number): string {
  if (ms < 1000) {
    return `${ms}ms`;
  }
  const totalSec = ms / 1000;
  if (totalSec < 60) {
    return `${totalSec.toFixed(1)}s`;
  }
  const min = Math.floor(totalSec / 60);
  const sec = Math.round(totalSec % 60);
  if (min < 60) {
    return sec > 0 ? `${min}m ${sec}s` : `${min}m`;
  }
  const hr = Math.floor(min / 60);
  const remMin = min % 60;
  return remMin > 0 ? `${hr}h ${remMin}m` : `${hr}h`;
}

/**
 * Check if a tool action is considered "long-running" (> 30 seconds estimated).
 */
export function isLongRunning(toolName: string, action: string): boolean {
  const estimate = getDurationEstimate(toolName, action);
  if (!estimate) return false;
  return estimate.maxSeconds > 30;
}

/**
 * Get all actions that support progress tracking.
 */
export function getProgressCapableActions(): DurationKey[] {
  return Object.entries(DURATION_DATABASE)
    .filter(([, est]) => est.supportsProgress)
    .map(([key]) => key);
}
