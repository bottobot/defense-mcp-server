/**
 * Meta/utility tools for Defense MCP Server.
 *
 * Registers 1 tool: defense_mgmt (actions: check_tools, workflow_suggest,
 * workflow_run, change_history, posture_score, posture_trend, posture_dashboard,
 * scheduled_create, scheduled_list, scheduled_remove, scheduled_history,
 * remediate_plan, remediate_apply, remediate_rollback, remediate_status,
 * report_generate, report_list, report_formats,
 * check_optional_deps, install_optional_deps)
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeCommand } from "../core/executor.js";
import { resolveCommand, isAllowlisted } from "../core/command-allowlist.js";
import { getConfig, getToolTimeout } from "../core/config.js";
import {
  createTextContent,
  createErrorContent,
  formatToolOutput,
} from "../core/parsers.js";
import { logChange, createChangeEntry, getChangelog } from "../core/changelog.js";
import {
  checkAllTools,
  installMissing,
  getInstallHint,
  getAlternativesMap,
  type ToolCategory,
  type ToolCheckResult,
} from "../core/installer.js";
import { SafeguardRegistry } from "../core/safeguards.js";
import {
  listThirdPartyTools,
  installThirdPartyTool,
  getVerifiedInstallInstructions,
  isThirdPartyInstallEnabled,
} from "../core/third-party-installer.js";
import { THIRD_PARTY_MANIFEST } from "../core/third-party-manifest.js";
import { existsSync, readFileSync, writeFileSync, mkdirSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { spawnSafe } from "../core/spawn-safe.js";
import { secureWriteFileSync } from "../core/secure-fs.js";
import type { ChildProcess } from "node:child_process";

// Suppress unused import warnings
void getToolTimeout;

// ── Security Posture Helpers ───────────────────────────────────────────────

const POSTURE_DIR = join(homedir(), ".defense-mcp-posture");

function ensurePostureDir(): void {
  if (!existsSync(POSTURE_DIR)) {
    mkdirSync(POSTURE_DIR, { recursive: true });
  }
}

interface DomainScore {
  domain: string;
  score: number;
  maxScore: number;
  checks: { name: string; passed: boolean; detail: string }[];
}

async function checkSysctl(key: string, expected: string): Promise<{ passed: boolean; assessable: boolean; actual: string }> {
  const r = await executeCommand({ toolName: "defense_mgmt", command: "sysctl", args: ["-n", key], timeout: 5000 });
  if (r.exitCode !== 0) {
    return { passed: false, assessable: false, actual: r.stderr.trim() || "command failed" };
  }
  const actual = r.stdout.trim();
  return { passed: actual === expected, assessable: true, actual };
}

// ── Automation Workflow Helpers ─────────────────────────────────────────────

const AUDIT_LOG_DIR = join(homedir(), ".defense-mcp", "audit-logs");

function ensureAuditLogDir(): void {
  if (!existsSync(AUDIT_LOG_DIR)) {
    mkdirSync(AUDIT_LOG_DIR, { recursive: true });
  }
}

// ── Scheduled Audit Command Allowlist (TOOL-004 remediation) ───────────────

/**
 * Strict allowlist of audit commands permitted for scheduled execution.
 * Maps human-readable command strings to their executable binary and arguments.
 * Commands are validated against the command allowlist via resolveCommand().
 * NO arbitrary commands are permitted — only these pre-approved security audits.
 */
const ALLOWED_AUDIT_COMMANDS: Record<string, { command: string; args: string[] }> = {
  "lynis audit system": { command: "lynis", args: ["audit", "system"] },
  "rkhunter --check --skip-keypress": { command: "rkhunter", args: ["--check", "--skip-keypress"] },
  "aide --check": { command: "aide", args: ["--check"] },
  "clamscan -r /home": { command: "clamscan", args: ["-r", "/home"] },
  "chkrootkit": { command: "chkrootkit", args: [] },
  "freshclam": { command: "freshclam", args: [] },
  "tiger": { command: "tiger", args: [] },
};

/** Valid characters for audit job names (used in file paths and systemd unit names) */
const AUDIT_NAME_RE = /^[a-zA-Z0-9_-]+$/;

/**
 * TOOL-004 remediation: Validate schedule format to prevent injection.
 * Allows:
 *   - Cron format: 5 fields of [0-9*,/-] (e.g., "0 2 * * *")
 *   - Systemd calendar format: alphanumeric with *:-/, space, and common calendar specifiers
 */
const CRON_FIELD_RE = /^[0-9*,\/-]+$/;
const SYSTEMD_CALENDAR_RE = /^[a-zA-Z0-9*:,\-\/. ]+$/;
function validateSchedule(schedule: string, isSystemd: boolean): string {
  if (!schedule || typeof schedule !== "string") {
    throw new Error("Schedule must be a non-empty string");
  }
  const trimmed = schedule.trim();
  if (trimmed.length > 256) {
    throw new Error("Schedule string too long (max 256 characters)");
  }
  // Reject shell metacharacters
  if (/[;|&$`(){}<>\n\r\\]/.test(trimmed)) {
    throw new Error(`Schedule contains forbidden characters: ${trimmed}`);
  }

  if (isSystemd) {
    if (!SYSTEMD_CALENDAR_RE.test(trimmed)) {
      throw new Error(`Invalid systemd calendar format: '${trimmed}'. Only alphanumeric, spaces, and *:-/., allowed.`);
    }
  } else {
    // Validate cron: should be 5 space-separated fields
    const fields = trimmed.split(/\s+/);
    if (fields.length !== 5) {
      throw new Error(`Invalid cron schedule: '${trimmed}'. Expected 5 fields (minute hour day month weekday).`);
    }
    for (const field of fields) {
      if (!CRON_FIELD_RE.test(field)) {
        throw new Error(`Invalid cron field: '${field}' in schedule '${trimmed}'.`);
      }
    }
  }
  return trimmed;
}

// ── Workflow definitions ───────────────────────────────────────────────────

interface WorkflowStep {
  tool: string;
  description: string;
  command: string;
  args: string[];
  estimatedSeconds: number;
}

const WORKFLOWS: Record<string, WorkflowStep[]> = {
  quick_harden: [
    {
      tool: "sysctl",
      description: "Audit kernel security parameters",
      command: "sudo",
      args: ["sysctl", "-a"],
      estimatedSeconds: 5,
    },
    {
      tool: "ssh",
      description: "Check SSH configuration",
      command: "cat",
      args: ["/etc/ssh/sshd_config"],
      estimatedSeconds: 2,
    },
    {
      tool: "systemctl",
      description: "Audit running services",
      command: "systemctl",
      args: ["list-units", "--type=service", "--state=running", "--no-pager"],
      estimatedSeconds: 5,
    },
    {
      tool: "ufw/iptables",
      description: "Check firewall status",
      command: "sudo",
      args: ["iptables", "-L", "-n", "--line-numbers"],
      estimatedSeconds: 3,
    },
    {
      tool: "find",
      description: "Audit world-writable files in /etc",
      command: "find",
      args: ["/etc", "-type", "f", "-perm", "-002", "-ls"],
      estimatedSeconds: 10,
    },
  ],
  full_audit: [
    {
      tool: "lynis",
      description: "Run Lynis security audit",
      command: "sudo",
      args: ["lynis", "audit", "system", "--quick", "--no-colors"],
      estimatedSeconds: 120,
    },
    {
      tool: "ssh",
      description: "Audit SSH configuration",
      command: "cat",
      args: ["/etc/ssh/sshd_config"],
      estimatedSeconds: 2,
    },
    {
      tool: "passwd",
      description: "Audit user accounts",
      command: "cat",
      args: ["/etc/passwd"],
      estimatedSeconds: 2,
    },
    {
      tool: "ss",
      description: "Audit listening ports",
      command: "ss",
      args: ["-tulnp"],
      estimatedSeconds: 3,
    },
    {
      tool: "clamscan",
      description: "Quick malware scan of /tmp",
      command: "clamscan",
      args: ["--recursive", "--infected", "/tmp"],
      estimatedSeconds: 60,
    },
  ],
  incident_prep: [
    {
      tool: "tar",
      description: "Backup critical configurations",
      command: "sudo",
      args: [
        "tar",
        "-czf",
        "/tmp/incident-config-backup.tar.gz",
        "/etc/ssh/sshd_config",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
      ],
      estimatedSeconds: 5,
    },
    {
      tool: "ps",
      description: "Snapshot running processes",
      command: "ps",
      args: ["auxf"],
      estimatedSeconds: 2,
    },
    {
      tool: "ss",
      description: "Snapshot network connections",
      command: "ss",
      args: ["-tulnp"],
      estimatedSeconds: 2,
    },
    {
      tool: "auditctl",
      description: "Enable auditd if not running",
      command: "sudo",
      args: ["systemctl", "start", "auditd"],
      estimatedSeconds: 5,
    },
  ],
  backup_all: [
    {
      tool: "tar",
      description: "Backup /etc configuration",
      command: "sudo",
      args: [
        "tar",
        "-czf",
        "/tmp/etc-backup.tar.gz",
        "/etc/",
      ],
      estimatedSeconds: 30,
    },
    {
      tool: "iptables-save",
      description: "Backup firewall rules",
      command: "sudo",
      args: ["iptables-save"],
      estimatedSeconds: 2,
    },
    {
      tool: "dpkg",
      description: "List installed packages",
      command: "dpkg",
      args: ["--get-selections"],
      estimatedSeconds: 5,
    },
  ],
  network_lockdown: [
    {
      tool: "iptables-save",
      description: "Save current firewall state",
      command: "sudo",
      args: ["iptables-save"],
      estimatedSeconds: 2,
    },
    {
      tool: "ss",
      description: "Identify unnecessary listening ports",
      command: "ss",
      args: ["-tulnp"],
      estimatedSeconds: 2,
    },
    {
      tool: "fail2ban",
      description: "Check fail2ban status",
      command: "sudo",
      args: ["fail2ban-client", "status"],
      estimatedSeconds: 3,
    },
    {
      tool: "sysctl",
      description: "Disable IP forwarding",
      command: "sudo",
      args: ["sysctl", "net.ipv4.ip_forward"],
      estimatedSeconds: 2,
    },
  ],
};

// ── Suggested workflows per objective ──────────────────────────────────────

interface SuggestedStep {
  tool: string;
  description: string;
  suggestedParams: string;
  estimatedMinutes: number;
}

const WORKFLOW_SUGGESTIONS: Record<
  string,
  Record<string, SuggestedStep[]>
> = {
  initial_hardening: {
    server: [
      { tool: "hardening_sysctl_audit", description: "Audit kernel security parameters", suggestedParams: "category: 'security'", estimatedMinutes: 1 },
      { tool: "hardening_ssh_audit", description: "Audit and harden SSH configuration", suggestedParams: "action: 'audit'", estimatedMinutes: 1 },
      { tool: "hardening_service_audit", description: "Audit running services, disable unnecessary ones", suggestedParams: "action: 'list'", estimatedMinutes: 2 },
      { tool: "firewall_iptables_list", description: "Review current firewall rules", suggestedParams: "table: 'filter'", estimatedMinutes: 1 },
      { tool: "access_user_audit", description: "Audit user accounts and privileges", suggestedParams: "check_type: 'all'", estimatedMinutes: 1 },
      { tool: "hardening_file_perms", description: "Audit file permissions on critical paths", suggestedParams: "path: '/etc', check_type: 'world_writable'", estimatedMinutes: 3 },
      { tool: "crypto_tls_config_audit", description: "Audit TLS/SSL configuration", suggestedParams: "service: 'all'", estimatedMinutes: 2 },
    ],
    desktop: [
      { tool: "hardening_sysctl_audit", description: "Audit kernel parameters", suggestedParams: "category: 'security'", estimatedMinutes: 1 },
      { tool: "firewall_ufw_status", description: "Check UFW firewall status", suggestedParams: "", estimatedMinutes: 1 },
      { tool: "hardening_service_audit", description: "Disable unnecessary services", suggestedParams: "action: 'list'", estimatedMinutes: 2 },
      { tool: "malware_clamscan", description: "Scan home directory", suggestedParams: "path: '/home', quick: true", estimatedMinutes: 10 },
    ],
    container: [
      { tool: "container_docker_audit", description: "Full Docker security audit", suggestedParams: "check_type: 'all'", estimatedMinutes: 3 },
      { tool: "container_docker_bench", description: "Run CIS Docker Benchmark", suggestedParams: "log_level: 'WARN'", estimatedMinutes: 5 },
      { tool: "container_apparmor_manage", description: "Check AppArmor status", suggestedParams: "action: 'status'", estimatedMinutes: 1 },
      { tool: "container_namespace_check", description: "Verify namespace isolation", suggestedParams: "check_type: 'all'", estimatedMinutes: 1 },
    ],
    cloud: [
      { tool: "hardening_sysctl_audit", description: "Audit kernel parameters", suggestedParams: "category: 'security'", estimatedMinutes: 1 },
      { tool: "hardening_ssh_audit", description: "Harden SSH (critical for cloud instances)", suggestedParams: "action: 'audit'", estimatedMinutes: 1 },
      { tool: "firewall_iptables_list", description: "Verify firewall rules", suggestedParams: "table: 'filter'", estimatedMinutes: 1 },
      { tool: "network_port_audit", description: "Audit exposed ports", suggestedParams: "", estimatedMinutes: 2 },
      { tool: "crypto_tls_config_audit", description: "Audit TLS configuration", suggestedParams: "service: 'all'", estimatedMinutes: 2 },
    ],
  },
  incident_response: {
    server: [
      { tool: "logging_journald_query", description: "Check recent system logs for anomalies", suggestedParams: "priority: 'err', lines: 100", estimatedMinutes: 1 },
      { tool: "network_connections", description: "Check active network connections", suggestedParams: "", estimatedMinutes: 1 },
      { tool: "access_user_audit", description: "Check for unauthorized user accounts", suggestedParams: "check_type: 'all'", estimatedMinutes: 1 },
      { tool: "malware_rkhunter", description: "Scan for rootkits", suggestedParams: "", estimatedMinutes: 5 },
      { tool: "logging_auth_analyze", description: "Analyze authentication logs", suggestedParams: "", estimatedMinutes: 2 },
      { tool: "backup_system_state", description: "Preserve current system state for forensics", suggestedParams: "", estimatedMinutes: 5 },
    ],
    desktop: [
      { tool: "logging_journald_query", description: "Check system logs", suggestedParams: "priority: 'err'", estimatedMinutes: 1 },
      { tool: "malware_clamscan", description: "Full malware scan", suggestedParams: "path: '/'", estimatedMinutes: 30 },
      { tool: "network_connections", description: "Check for suspicious connections", suggestedParams: "", estimatedMinutes: 1 },
    ],
    container: [
      { tool: "container_docker_audit", description: "Audit container security", suggestedParams: "check_type: 'containers'", estimatedMinutes: 2 },
      { tool: "logging_journald_query", description: "Check container logs", suggestedParams: "priority: 'err'", estimatedMinutes: 1 },
    ],
    cloud: [
      { tool: "logging_auth_analyze", description: "Analyze authentication attempts", suggestedParams: "", estimatedMinutes: 2 },
      { tool: "network_connections", description: "Check for anomalous connections", suggestedParams: "", estimatedMinutes: 1 },
      { tool: "access_user_audit", description: "Audit user access", suggestedParams: "check_type: 'all'", estimatedMinutes: 1 },
    ],
  },
  compliance_audit: {
    server: [
      { tool: "compliance_lynis", description: "Run Lynis compliance audit", suggestedParams: "", estimatedMinutes: 5 },
      { tool: "compliance_cis_check", description: "Run CIS benchmark checks", suggestedParams: "", estimatedMinutes: 10 },
      { tool: "hardening_ssh_audit", description: "Audit SSH compliance", suggestedParams: "action: 'audit'", estimatedMinutes: 1 },
      { tool: "crypto_tls_config_audit", description: "Audit crypto compliance", suggestedParams: "service: 'all'", estimatedMinutes: 2 },
    ],
    desktop: [{ tool: "compliance_lynis", description: "Run Lynis audit", suggestedParams: "", estimatedMinutes: 5 }],
    container: [
      { tool: "container_docker_bench", description: "Docker CIS benchmark", suggestedParams: "", estimatedMinutes: 5 },
      { tool: "compliance_lynis", description: "Lynis audit of host", suggestedParams: "", estimatedMinutes: 5 },
    ],
    cloud: [
      { tool: "compliance_lynis", description: "Lynis audit", suggestedParams: "", estimatedMinutes: 5 },
      { tool: "compliance_cis_check", description: "CIS benchmark", suggestedParams: "", estimatedMinutes: 10 },
    ],
  },
  malware_investigation: {
    server: [
      { tool: "malware_clamscan", description: "ClamAV scan", suggestedParams: "path: '/', quick: true", estimatedMinutes: 15 },
      { tool: "malware_rkhunter", description: "Rootkit scan", suggestedParams: "", estimatedMinutes: 5 },
      { tool: "malware_chkrootkit", description: "Secondary rootkit check", suggestedParams: "", estimatedMinutes: 5 },
      { tool: "crypto_file_hash", description: "Hash critical binaries for verification", suggestedParams: "path: '/usr/bin', algorithm: 'sha256', recursive: true", estimatedMinutes: 10 },
    ],
    desktop: [
      { tool: "malware_clamscan", description: "Full ClamAV scan", suggestedParams: "path: '/'", estimatedMinutes: 30 },
      { tool: "malware_rkhunter", description: "Rootkit scan", suggestedParams: "", estimatedMinutes: 5 },
    ],
    container: [{ tool: "container_docker_audit", description: "Audit container images", suggestedParams: "check_type: 'images'", estimatedMinutes: 2 }],
    cloud: [
      { tool: "malware_clamscan", description: "ClamAV scan", suggestedParams: "path: '/'", estimatedMinutes: 15 },
      { tool: "malware_rkhunter", description: "Rootkit scan", suggestedParams: "", estimatedMinutes: 5 },
    ],
  },
  network_monitoring: {
    server: [
      { tool: "network_port_audit", description: "Audit listening ports", suggestedParams: "", estimatedMinutes: 1 },
      { tool: "network_connections", description: "Monitor active connections", suggestedParams: "", estimatedMinutes: 1 },
      { tool: "ids_snort_manage", description: "Check IDS status", suggestedParams: "action: 'status'", estimatedMinutes: 1 },
      { tool: "firewall_iptables_list", description: "Review firewall rules", suggestedParams: "", estimatedMinutes: 1 },
    ],
    desktop: [
      { tool: "network_connections", description: "Check connections", suggestedParams: "", estimatedMinutes: 1 },
      { tool: "firewall_ufw_status", description: "Check UFW", suggestedParams: "", estimatedMinutes: 1 },
    ],
    container: [
      { tool: "container_docker_audit", description: "Audit Docker network", suggestedParams: "check_type: 'network'", estimatedMinutes: 1 },
      { tool: "container_namespace_check", description: "Check network namespace isolation", suggestedParams: "check_type: 'network'", estimatedMinutes: 1 },
    ],
    cloud: [
      { tool: "network_port_audit", description: "Audit exposed ports", suggestedParams: "", estimatedMinutes: 1 },
      { tool: "network_connections", description: "Monitor connections", suggestedParams: "", estimatedMinutes: 1 },
    ],
  },
  full_assessment: {
    server: [
      { tool: "compliance_lynis", description: "Full Lynis audit", suggestedParams: "", estimatedMinutes: 5 },
      { tool: "hardening_sysctl_audit", description: "Kernel audit", suggestedParams: "category: 'all'", estimatedMinutes: 1 },
      { tool: "hardening_ssh_audit", description: "SSH audit", suggestedParams: "action: 'audit'", estimatedMinutes: 1 },
      { tool: "firewall_iptables_list", description: "Firewall audit", suggestedParams: "", estimatedMinutes: 1 },
      { tool: "access_user_audit", description: "User audit", suggestedParams: "check_type: 'all'", estimatedMinutes: 1 },
      { tool: "network_port_audit", description: "Port audit", suggestedParams: "", estimatedMinutes: 1 },
      { tool: "malware_clamscan", description: "Malware scan", suggestedParams: "path: '/', quick: true", estimatedMinutes: 15 },
      { tool: "crypto_tls_config_audit", description: "Crypto audit", suggestedParams: "service: 'all'", estimatedMinutes: 2 },
    ],
    desktop: [
      { tool: "compliance_lynis", description: "Lynis audit", suggestedParams: "", estimatedMinutes: 5 },
      { tool: "firewall_ufw_status", description: "Firewall check", suggestedParams: "", estimatedMinutes: 1 },
      { tool: "malware_clamscan", description: "Malware scan", suggestedParams: "path: '/'", estimatedMinutes: 30 },
    ],
    container: [
      { tool: "container_docker_audit", description: "Docker audit", suggestedParams: "check_type: 'all'", estimatedMinutes: 3 },
      { tool: "container_docker_bench", description: "CIS benchmark", suggestedParams: "", estimatedMinutes: 5 },
      { tool: "container_apparmor_manage", description: "AppArmor status", suggestedParams: "action: 'status'", estimatedMinutes: 1 },
      { tool: "compliance_lynis", description: "Host Lynis audit", suggestedParams: "", estimatedMinutes: 5 },
    ],
    cloud: [
      { tool: "compliance_lynis", description: "Lynis audit", suggestedParams: "", estimatedMinutes: 5 },
      { tool: "hardening_ssh_audit", description: "SSH audit", suggestedParams: "action: 'audit'", estimatedMinutes: 1 },
      { tool: "firewall_iptables_list", description: "Firewall review", suggestedParams: "", estimatedMinutes: 1 },
      { tool: "crypto_tls_config_audit", description: "Crypto audit", suggestedParams: "service: 'all'", estimatedMinutes: 2 },
    ],
  },
};

// ── Auto-Remediate Helpers ─────────────────────────────────────────────────

const REMEDIATION_SESSIONS_DIR = "/var/lib/defense-mcp/remediation-sessions";

const SEVERITY_LEVELS_ORDER = ["critical", "high", "medium", "low"] as const;
type RemSeverity = (typeof SEVERITY_LEVELS_ORDER)[number];
type RemRiskLevel = "safe" | "moderate" | "risky";

interface RemediationFinding {
  finding_id: string;
  description: string;
  severity: RemSeverity;
  remediation_command: string;
  remediation_args: string[];
  rollback_command: string;
  rollback_args: string[];
  risk_level: RemRiskLevel;
  category: string;
}

interface RemSessionAction {
  finding_id: string;
  description: string;
  remediation_command: string;
  remediation_args: string[];
  rollback_command: string;
  rollback_args: string[];
  before_state: string;
  after_state: string;
  status: "success" | "failed" | "skipped" | "rolled_back";
  error?: string;
  timestamp: string;
}

interface RemediationSession {
  session_id: string;
  created_at: string;
  status: "in_progress" | "completed" | "rolled_back" | "partial";
  actions: RemSessionAction[];
  summary: {
    total: number;
    successful: number;
    failed: number;
    skipped: number;
    rolled_back: number;
  };
}

/** Hardcoded set of known, safe remediation mappings */
const KNOWN_REMEDIATIONS: RemediationFinding[] = [
  { finding_id: "HARD-001", description: "ASLR not fully enabled (kernel.randomize_va_space != 2)", severity: "high", remediation_command: "sysctl", remediation_args: ["-w", "kernel.randomize_va_space=2"], rollback_command: "sysctl", rollback_args: ["-w", "kernel.randomize_va_space=0"], risk_level: "safe", category: "hardening" },
  { finding_id: "HARD-002", description: "IP forwarding enabled (net.ipv4.ip_forward = 1)", severity: "medium", remediation_command: "sysctl", remediation_args: ["-w", "net.ipv4.ip_forward=0"], rollback_command: "sysctl", rollback_args: ["-w", "net.ipv4.ip_forward=1"], risk_level: "moderate", category: "hardening" },
  { finding_id: "HARD-003", description: "SYN cookies not enabled (net.ipv4.tcp_syncookies != 1)", severity: "medium", remediation_command: "sysctl", remediation_args: ["-w", "net.ipv4.tcp_syncookies=1"], rollback_command: "sysctl", rollback_args: ["-w", "net.ipv4.tcp_syncookies=0"], risk_level: "safe", category: "hardening" },
  { finding_id: "HARD-004", description: "Reverse path filtering not enabled (net.ipv4.conf.all.rp_filter != 1)", severity: "medium", remediation_command: "sysctl", remediation_args: ["-w", "net.ipv4.conf.all.rp_filter=1"], rollback_command: "sysctl", rollback_args: ["-w", "net.ipv4.conf.all.rp_filter=0"], risk_level: "safe", category: "hardening" },
  { finding_id: "HARD-005", description: "ICMP redirects accepted (net.ipv4.conf.all.accept_redirects != 0)", severity: "medium", remediation_command: "sysctl", remediation_args: ["-w", "net.ipv4.conf.all.accept_redirects=0"], rollback_command: "sysctl", rollback_args: ["-w", "net.ipv4.conf.all.accept_redirects=1"], risk_level: "safe", category: "hardening" },
  { finding_id: "HARD-006", description: "Source routing accepted (net.ipv4.conf.all.accept_source_route != 0)", severity: "high", remediation_command: "sysctl", remediation_args: ["-w", "net.ipv4.conf.all.accept_source_route=0"], rollback_command: "sysctl", rollback_args: ["-w", "net.ipv4.conf.all.accept_source_route=1"], risk_level: "safe", category: "hardening" },
  { finding_id: "ACCESS-001", description: "SSH PermitRootLogin is enabled", severity: "critical", remediation_command: "sed", remediation_args: ["-i", "s/^PermitRootLogin yes/PermitRootLogin no/", "/etc/ssh/sshd_config"], rollback_command: "sed", rollback_args: ["-i", "s/^PermitRootLogin no/PermitRootLogin yes/", "/etc/ssh/sshd_config"], risk_level: "moderate", category: "access_control" },
  { finding_id: "ACCESS-002", description: "SSH PermitEmptyPasswords is enabled", severity: "critical", remediation_command: "sed", remediation_args: ["-i", "s/^PermitEmptyPasswords yes/PermitEmptyPasswords no/", "/etc/ssh/sshd_config"], rollback_command: "sed", rollback_args: ["-i", "s/^PermitEmptyPasswords no/PermitEmptyPasswords yes/", "/etc/ssh/sshd_config"], risk_level: "moderate", category: "access_control" },
  { finding_id: "FW-001", description: "Firewall INPUT chain has default ACCEPT policy", severity: "high", remediation_command: "iptables", remediation_args: ["-P", "INPUT", "DROP"], rollback_command: "iptables", rollback_args: ["-P", "INPUT", "ACCEPT"], risk_level: "risky", category: "firewall" },
  { finding_id: "FW-002", description: "Firewall FORWARD chain has default ACCEPT policy", severity: "high", remediation_command: "iptables", remediation_args: ["-P", "FORWARD", "DROP"], rollback_command: "iptables", rollback_args: ["-P", "FORWARD", "ACCEPT"], risk_level: "risky", category: "firewall" },
];

/** Allowed commands for auto-remediation execution */
const REMEDIATION_ALLOWLIST = new Set(["sysctl", "sed", "iptables"]);

function generateSessionId(): string {
  const ts = Date.now();
  const rand = Math.random().toString(36).substring(2, 8);
  return `rem-${ts}-${rand}`;
}

function severityAtOrAbove(finding: RemSeverity, threshold: RemSeverity): boolean {
  return SEVERITY_LEVELS_ORDER.indexOf(finding) <= SEVERITY_LEVELS_ORDER.indexOf(threshold);
}

function riskSortValue(risk: RemRiskLevel): number {
  switch (risk) {
    case "safe": return 0;
    case "moderate": return 1;
    case "risky": return 2;
    default: return 3;
  }
}

async function runRemediateCmd(
  command: string,
  args: string[],
  timeoutMs = 30_000,
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve) => {
    let child: ReturnType<typeof spawnSafe>;
    try {
      child = spawnSafe(command, args);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      resolve({ stdout: "", stderr: msg, exitCode: -1 });
      return;
    }

    let stdout = "";
    let stderr = "";
    let resolved = false;

    const timer = setTimeout(() => {
      if (!resolved) {
        resolved = true;
        child.kill("SIGTERM");
        resolve({ stdout, stderr: stderr + "\n[TIMEOUT]", exitCode: -1 });
      }
    }, timeoutMs);

    child.stdout?.on("data", (data: Buffer) => { stdout += data.toString(); });
    child.stderr?.on("data", (data: Buffer) => { stderr += data.toString(); });

    child.on("close", (code: number | null) => {
      if (!resolved) {
        resolved = true;
        clearTimeout(timer);
        resolve({ stdout, stderr, exitCode: code ?? -1 });
      }
    });

    child.on("error", (err: Error) => {
      if (!resolved) {
        resolved = true;
        clearTimeout(timer);
        resolve({ stdout, stderr: err.message, exitCode: -1 });
      }
    });
  });
}

async function gatherRemediationFindings(
  source: string,
  severityFilter: RemSeverity,
): Promise<RemediationFinding[]> {
  const findings: RemediationFinding[] = [];
  const shouldInclude = (cat: string): boolean => source === "all" || source === cat;

  if (shouldInclude("hardening")) {
    const sysctlResult = await runRemediateCmd("sysctl", ["-a"]);
    if (sysctlResult.exitCode === 0) {
      const sysctlValues = new Map<string, string>();
      for (const line of sysctlResult.stdout.split("\n")) {
        const match = line.match(/^([^=]+?)\s*=\s*(.+)$/);
        if (match) sysctlValues.set(match[1].trim(), match[2].trim());
      }
      for (const f of KNOWN_REMEDIATIONS.filter(r => r.category === "hardening")) {
        const setArg = f.remediation_args.find(a => a.includes("="));
        if (setArg) {
          const eqIdx = setArg.indexOf("=");
          const key = setArg.substring(0, eqIdx);
          const expected = setArg.substring(eqIdx + 1);
          const actual = sysctlValues.get(key);
          if (actual !== undefined && actual !== expected) findings.push(f);
        }
      }
    }
  }

  if (shouldInclude("access_control")) {
    const sshResult = await runRemediateCmd("grep", ["-E", "^PermitRootLogin|^PermitEmptyPasswords", "/etc/ssh/sshd_config"]);
    if (sshResult.exitCode === 0 || sshResult.stdout.length > 0) {
      if (sshResult.stdout.includes("PermitRootLogin yes")) { const f = KNOWN_REMEDIATIONS.find(r => r.finding_id === "ACCESS-001"); if (f) findings.push(f); }
      if (sshResult.stdout.includes("PermitEmptyPasswords yes")) { const f = KNOWN_REMEDIATIONS.find(r => r.finding_id === "ACCESS-002"); if (f) findings.push(f); }
    }
  }

  if (shouldInclude("firewall")) {
    const fwResult = await runRemediateCmd("iptables", ["-L", "-n"]);
    if (fwResult.exitCode === 0) {
      if (fwResult.stdout.includes("Chain INPUT (policy ACCEPT)")) { const f = KNOWN_REMEDIATIONS.find(r => r.finding_id === "FW-001"); if (f) findings.push(f); }
      if (fwResult.stdout.includes("Chain FORWARD (policy ACCEPT)")) { const f = KNOWN_REMEDIATIONS.find(r => r.finding_id === "FW-002"); if (f) findings.push(f); }
    }
  }

  if (shouldInclude("compliance")) {
    const lynisResult = await runRemediateCmd("lynis", ["audit", "system", "--quick", "--no-colors"], 120_000);
    if (lynisResult.exitCode === 0 || lynisResult.stdout.length > 0) {
      for (const f of KNOWN_REMEDIATIONS) {
        if (findings.some(e => e.finding_id === f.finding_id)) continue;
        const setArg = f.remediation_args.find(a => a.includes("="));
        if (setArg) {
          const key = setArg.substring(0, setArg.indexOf("="));
          if (lynisResult.stdout.includes(key)) findings.push(f);
        }
      }
    }
  }

  const filtered = findings.filter(f => severityAtOrAbove(f.severity, severityFilter));
  filtered.sort((a, b) => {
    const sevDiff = SEVERITY_LEVELS_ORDER.indexOf(a.severity) - SEVERITY_LEVELS_ORDER.indexOf(b.severity);
    if (sevDiff !== 0) return sevDiff;
    return riskSortValue(a.risk_level) - riskSortValue(b.risk_level);
  });
  return filtered;
}

// ── Reporting Helpers (inlined from reporting.ts) ──────────────────────────

const DEFAULT_REPORT_DIR = "/var/lib/defense-mcp/reports";

const SUPPORTED_FORMATS = [
  { format: "markdown", description: "Markdown-formatted report with headers and code blocks", extension: ".md" },
  { format: "html", description: "HTML report suitable for browser viewing", extension: ".html" },
  { format: "json", description: "Structured JSON report for programmatic consumption", extension: ".json" },
  { format: "csv", description: "CSV-formatted summary data for spreadsheet import", extension: ".csv" },
];

const REPORT_TYPES = [
  { type: "executive_summary", description: "High-level security posture overview for leadership" },
  { type: "technical_detail", description: "Detailed technical findings with command output" },
  { type: "compliance_evidence", description: "Evidence collection for compliance audits" },
  { type: "vulnerability_report", description: "Identified vulnerabilities and remediation steps" },
  { type: "hardening_status", description: "Current system hardening status and recommendations" },
];

const ALL_SECTIONS = [
  "system_overview",
  "firewall_status",
  "service_audit",
  "active_connections",
  "recent_logins",
  "compliance_summary",
  "recommendations",
];

interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

async function runReportCommand(
  command: string,
  args: string[],
  timeoutMs = 30_000,
): Promise<CommandResult> {
  return new Promise((resolve) => {
    let child: ChildProcess;
    try {
      child = spawnSafe(command, args);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      resolve({ stdout: "", stderr: msg, exitCode: -1 });
      return;
    }

    let stdout = "";
    let stderr = "";
    let resolved = false;

    const timer = setTimeout(() => {
      if (!resolved) {
        resolved = true;
        child.kill("SIGTERM");
        resolve({ stdout, stderr: stderr + "\n[TIMEOUT]", exitCode: -1 });
      }
    }, timeoutMs);

    child.stdout?.on("data", (data: Buffer) => { stdout += data.toString(); });
    child.stderr?.on("data", (data: Buffer) => { stderr += data.toString(); });

    child.on("close", (code: number | null) => {
      if (!resolved) {
        resolved = true;
        clearTimeout(timer);
        resolve({ stdout, stderr, exitCode: code ?? -1 });
      }
    });

    child.on("error", (err: Error) => {
      if (!resolved) {
        resolved = true;
        clearTimeout(timer);
        resolve({ stdout, stderr: err.message, exitCode: -1 });
      }
    });
  });
}

async function runSudoReportCommand(
  command: string,
  args: string[],
  timeoutMs = 30_000,
): Promise<CommandResult> {
  return runReportCommand("sudo", [command, ...args], timeoutMs);
}

interface ReportSection {
  name: string;
  key: string;
  data: string;
  error?: string;
}

async function gatherSystemOverview(): Promise<ReportSection> {
  const uname = await runReportCommand("uname", ["-a"]);
  const hostname = await runReportCommand("hostname", []);
  const uptime = await runReportCommand("uptime", []);

  let data = "";
  if (uname.exitCode === 0) data += `Kernel: ${uname.stdout.trim()}\n`;
  else data += `Kernel: [error: ${uname.stderr.trim()}]\n`;
  if (hostname.exitCode === 0) data += `Hostname: ${hostname.stdout.trim()}\n`;
  if (uptime.exitCode === 0) data += `Uptime: ${uptime.stdout.trim()}\n`;

  return { name: "System Overview", key: "system_overview", data, error: uname.exitCode !== 0 ? uname.stderr.trim() : undefined };
}

async function gatherFirewallStatus(): Promise<ReportSection> {
  const iptables = await runSudoReportCommand("iptables", ["-L", "-n", "--line-numbers"]);
  const data = iptables.exitCode === 0 ? iptables.stdout.trim() : `[Error gathering firewall rules: ${iptables.stderr.trim()}]`;
  return { name: "Firewall Status", key: "firewall_status", data, error: iptables.exitCode !== 0 ? iptables.stderr.trim() : undefined };
}

async function gatherServiceAudit(): Promise<ReportSection> {
  const services = await runReportCommand("systemctl", ["list-units", "--type=service", "--state=running", "--no-pager", "--no-legend"]);
  const data = services.exitCode === 0 ? services.stdout.trim() : `[Error listing services: ${services.stderr.trim()}]`;
  return { name: "Service Audit", key: "service_audit", data, error: services.exitCode !== 0 ? services.stderr.trim() : undefined };
}

async function gatherActiveConnections(): Promise<ReportSection> {
  const ss = await runReportCommand("ss", ["-tulnp"]);
  const data = ss.exitCode === 0 ? ss.stdout.trim() : `[Error listing connections: ${ss.stderr.trim()}]`;
  return { name: "Active Connections", key: "active_connections", data, error: ss.exitCode !== 0 ? ss.stderr.trim() : undefined };
}

async function gatherRecentLogins(since?: string): Promise<ReportSection> {
  const args = ["_COMM=sshd", "-n", "50", "--no-pager"];
  if (since) args.push("--since", since);
  const logins = await runReportCommand("journalctl", args);

  let data = "";
  if (logins.exitCode === 0 && logins.stdout.trim().length > 0) {
    data = logins.stdout.trim();
  } else {
    const authLog = await runSudoReportCommand("grep", ["-i", "session opened", "/var/log/auth.log"]);
    if (authLog.exitCode === 0) {
      data = authLog.stdout.trim().split("\n").slice(-20).join("\n");
    } else {
      data = "[No login data available]";
    }
  }

  return {
    name: "Recent Logins",
    key: "recent_logins",
    data,
    error: logins.exitCode !== 0 && data === "[No login data available]" ? logins.stderr.trim() : undefined,
  };
}

async function gatherComplianceSummary(): Promise<ReportSection> {
  const lynis = await runSudoReportCommand("lynis", ["audit", "system", "--quick", "--no-colors"], 120_000);

  let data = "";
  if (lynis.exitCode === 0 || lynis.stdout.includes("Hardening index")) {
    const match = lynis.stdout.match(/Hardening index\s*:\s*(\d+)/);
    const index = match ? match[1] : "N/A";
    const warnings = (lynis.stdout.match(/Warning/g) || []).length;
    const suggestions = (lynis.stdout.match(/Suggestion/g) || []).length;
    data = `Hardening Index: ${index}/100\nWarnings: ${warnings}\nSuggestions: ${suggestions}\n`;
  } else {
    const aideStatus = await runSudoReportCommand("aide", ["--check"], 60_000);
    data += aideStatus.exitCode === 0 ? `AIDE Check: PASSED\n${aideStatus.stdout.trim().slice(0, 500)}\n` : `AIDE Check: ${aideStatus.exitCode === -1 ? "Not installed" : "FAILED"}\n`;
    const fail2ban = await runSudoReportCommand("fail2ban-client", ["status"]);
    data += fail2ban.exitCode === 0 ? `\nFail2ban: ${fail2ban.stdout.trim()}\n` : `\nFail2ban: Not available\n`;
  }

  return { name: "Compliance Summary", key: "compliance_summary", data: data || "[No compliance data available]" };
}

function generateReportRecommendations(sections: ReportSection[]): ReportSection {
  const recommendations: string[] = [];

  const firewall = sections.find((s) => s.key === "firewall_status");
  if (firewall?.error) {
    recommendations.push("- Configure and enable firewall (iptables/nftables)");
  } else if (firewall?.data.includes("ACCEPT") && !firewall.data.includes("DROP")) {
    recommendations.push("- Review firewall policy: consider setting default DROP policy");
  }

  const services = sections.find((s) => s.key === "service_audit");
  if (services?.data) {
    for (const svc of ["telnet", "rsh", "rlogin", "tftp"]) {
      if (services.data.toLowerCase().includes(svc)) {
        recommendations.push(`- Disable insecure service: ${svc}`);
      }
    }
  }

  const connections = sections.find((s) => s.key === "active_connections");
  if (connections?.data) {
    const lineCount = connections.data.split("\n").length;
    if (lineCount > 20) recommendations.push(`- Review ${lineCount} active connections for unnecessary exposure`);
  }

  const compliance = sections.find((s) => s.key === "compliance_summary");
  if (compliance?.data.includes("Not installed") || compliance?.data.includes("Not available")) {
    recommendations.push("- Install security audit tools: lynis, aide, fail2ban");
  }

  if (recommendations.length === 0) {
    recommendations.push("- No critical recommendations at this time");
    recommendations.push("- Continue regular security audits");
  }

  return { name: "Recommendations", key: "recommendations", data: recommendations.join("\n") };
}

function escapeHtml(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function formatAsMarkdown(sections: ReportSection[], reportType: string, timestamp: string): string {
  let md = `# Security Report: ${reportType.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())}\n\n`;
  md += `**Generated:** ${timestamp}\n**Report Type:** ${reportType}\n\n---\n\n`;
  for (const section of sections) {
    md += `## ${section.name}\n\n`;
    if (section.error) md += `> ⚠️ Error: ${section.error}\n\n`;
    md += `\`\`\`\n${section.data}\n\`\`\`\n\n`;
  }
  return md;
}

function formatAsHtml(sections: ReportSection[], reportType: string, timestamp: string): string {
  let html = `<!DOCTYPE html>\n<html><head><meta charset="utf-8">\n<title>Security Report: ${escapeHtml(reportType)}</title>\n`;
  html += `<style>body{font-family:sans-serif;max-width:900px;margin:0 auto;padding:20px}`;
  html += `pre{background:#f4f4f4;padding:12px;border-radius:4px;overflow-x:auto}.warning{color:#c00;font-weight:bold}h1{border-bottom:2px solid #333}h2{border-bottom:1px solid #ccc;padding-bottom:4px}</style>\n</head><body>\n`;
  html += `<h1>Security Report: ${escapeHtml(reportType.replace(/_/g, " "))}</h1>\n<p><strong>Generated:</strong> ${escapeHtml(timestamp)}</p>\n`;
  for (const section of sections) {
    html += `<h2>${escapeHtml(section.name)}</h2>\n`;
    if (section.error) html += `<p class="warning">⚠ Error: ${escapeHtml(section.error)}</p>\n`;
    html += `<pre>${escapeHtml(section.data)}</pre>\n`;
  }
  html += `</body></html>`;
  return html;
}

function formatAsJson(sections: ReportSection[], reportType: string, timestamp: string): string {
  return JSON.stringify({ reportType, generatedAt: timestamp, sections: sections.map((s) => ({ name: s.name, key: s.key, data: s.data, error: s.error || null })) }, null, 2);
}

function formatAsCsv(sections: ReportSection[], _reportType: string, _timestamp: string): string {
  const lines = ["Section,Status,Summary"];
  for (const section of sections) {
    const status = section.error ? "ERROR" : "OK";
    const summary = section.data.split("\n")[0].slice(0, 100).replace(/,/g, ";").replace(/"/g, '""');
    lines.push(`"${section.name}","${status}","${summary}"`);
  }
  return lines.join("\n");
}

// ── Registration entry point ───────────────────────────────────────────────

export function registerMetaTools(server: McpServer): void {
  server.tool(
    "defense_mgmt",
    "Defense: tool checks, workflows, change history, posture, scheduled audits, remediation, reports",
    {
      action: z.enum([
        "check_tools",
        "workflow_suggest",
        "workflow_run",
        "change_history",
        "posture_score",
        "posture_trend",
        "posture_dashboard",
        "scheduled_create",
        "scheduled_list",
        "scheduled_remove",
        "scheduled_history",
        "remediate_plan",
        "remediate_apply",
        "remediate_rollback",
        "remediate_status",
        "report_generate",
        "report_list",
        "report_formats",
        "check_optional_deps",
        "install_optional_deps",
      ]).describe("Defense management action"),
      // check_tools params
      category: z.string().optional().describe("Filter by tool category"),
      install_missing: z.boolean().optional().default(false).describe("Attempt to install missing tools"),
      gate: z.boolean().optional().default(false).describe("Audit gate mode: block if required tools missing"),
      // workflow params
      objective: z.enum(["initial_hardening", "incident_response", "compliance_audit", "malware_investigation", "network_monitoring", "full_assessment"]).optional().describe("Security objective"),
      system_type: z.enum(["server", "desktop", "container", "cloud"]).optional().default("server").describe("System type"),
      workflow: z.enum(["quick_harden", "full_audit", "incident_prep", "backup_all", "network_lockdown"]).optional().describe("Workflow to execute"),
      // change_history params
      limit: z.number().optional().default(20).describe("Maximum entries to return"),
      tool: z.string().optional().describe("Filter by tool name"),
      since: z.string().optional().describe("Filter by date, e.g. 'today', '2024-01-01'"),
      // scheduled_audit params
      name: z.string().optional().describe("Audit job name ([a-zA-Z0-9_-] only)"),
      command: z.enum(["lynis audit system", "rkhunter --check --skip-keypress", "aide --check", "clamscan -r /home", "chkrootkit", "freshclam", "tiger"]).optional().describe("Audit command from approved allowlist"),
      schedule: z.string().optional().describe("Cron format or systemd calendar schedule"),
      useSystemd: z.boolean().optional().default(true).describe("Use systemd timer vs cron"),
      lines: z.number().optional().default(100).describe("Number of recent log lines"),
      // auto_remediate params
      source: z.enum(["compliance", "hardening", "access_control", "firewall", "all"]).optional().default("all").describe("Source of findings to remediate"),
      severity_filter: z.enum(["critical", "high", "medium", "low"]).optional().default("medium").describe("Minimum severity to include"),
      session_id: z.string().optional().describe("Remediation session ID"),
      output_format: z.enum(["text", "json"]).optional().default("text").describe("Output format"),
      // optional deps params
      tool_name: z.string().optional().describe("Tool binary name to install (omit for all missing)"),
      force: z.boolean().optional().default(false).describe("Force reinstall even if installed"),
      // report params
      report_type: z.enum(["executive_summary", "technical_detail", "compliance_evidence", "vulnerability_report", "hardening_status"]).optional().default("technical_detail").describe("Report type"),
      format: z.enum(["markdown", "html", "json", "csv"]).optional().default("markdown").describe("Report output format"),
      output_path: z.string().optional().describe("File path to save report"),
      include_sections: z.array(z.string()).optional().describe("Section names to include"),
      // shared
      dry_run: z.boolean().optional().default(true).describe("Preview without executing"),
    },
    async (params) => {
      const { action } = params;

      switch (action) {

        // ── check_tools ────────────────────────────────────────────────────
        case "check_tools": {
          const { category, install_missing, dry_run, gate } = params;
          try {
            const sections: string[] = [];
            sections.push("🔧 Defensive Tool Availability Check");
            sections.push("=".repeat(50));

            const validCategories = ["hardening", "firewall", "monitoring", "assessment", "network", "access", "encryption", "container", "malware", "forensics"];
            const filterCategory = category && validCategories.includes(category) ? (category as ToolCategory) : undefined;

            if (category && !filterCategory) {
              sections.push(`\n⚠️ Unknown category '${category}'. Valid: ${validCategories.join(", ")}`);
              sections.push("Showing all categories.\n");
            }

            const results = await checkAllTools(filterCategory);
            const grouped = new Map<string, ToolCheckResult[]>();
            for (const r of results) {
              const cat = r.tool.category;
              if (!grouped.has(cat)) grouped.set(cat, []);
              grouped.get(cat)!.push(r);
            }

            let installed = 0;
            let missing = 0;

            for (const [cat, tools] of grouped) {
              sections.push(`\n── ${cat.charAt(0).toUpperCase() + cat.slice(1)} ──`);
              for (const t of tools) {
                if (t.installed) {
                  installed++;
                  const version = t.version ? ` (${t.version.substring(0, 60)})` : "";
                  sections.push(`  ✅ ${t.tool.name}${version}`);
                  if (t.path) sections.push(`     Path: ${t.path}`);
                } else {
                  missing++;
                  const req = t.tool.required ? " [REQUIRED]" : " [optional]";
                  sections.push(`  ❌ ${t.tool.name}${req}`);
                }
              }
            }

            sections.push(`\n── Summary ──`);
            sections.push(`  Installed: ${installed} | Missing: ${missing} | Total: ${installed + missing}`);

            if (install_missing && missing > 0) {
              sections.push("\n── Installation ──");
              if (dry_run ?? getConfig().dryRun) {
                const installResults = await installMissing(filterCategory, true);
                for (const r of installResults) sections.push(`  ${r.message}`);
              } else {
                sections.push("  Installing missing tools...\n");
                const installResults = await installMissing(filterCategory, false);
                for (const r of installResults) {
                  const icon = r.success ? "✅" : "❌";
                  sections.push(`  ${icon} ${r.message}`);
                }
                logChange(createChangeEntry({ tool: "defense_mgmt", action: "install_missing", target: filterCategory || "all", after: `Attempted to install ${installResults.length} tools`, dryRun: false, success: installResults.every((r) => r.success) }));
              }
            }

            // ── Gate mode: block audit if required tools are missing ──────
            if (gate) {
              const allMissing = results.filter(r => !r.installed);
              const altMap = getAlternativesMap();

              // A required tool is truly missing only if none of its alternatives are installed
              const requiredMissing = allMissing.filter(r => {
                if (!r.tool.required) return false;
                const alternatives = altMap.get(r.tool.name.toLowerCase()) || [];
                return !alternatives.some(alt =>
                  results.some(res => res.tool.binary === alt.binary && res.installed)
                );
              });
              const optionalMissing = allMissing.filter(r => !r.tool.required);

              if (requiredMissing.length > 0) {
                sections.push("");
                sections.push("🚫 AUDIT GATE: BLOCKED");
                sections.push("=".repeat(50));
                sections.push(`${requiredMissing.length} required tool(s) missing. Audit cannot proceed.\n`);

                sections.push("Required (must fix):");
                for (const r of requiredMissing) {
                  const hint = await getInstallHint(r.tool);
                  sections.push(`  - ${r.tool.name} (${r.tool.binary})`);
                  if (hint) sections.push(`    Install: ${hint}`);
                }

                if (optionalMissing.length > 0) {
                  sections.push("\nOptional (recommended):");
                  for (const r of optionalMissing) {
                    const hint = await getInstallHint(r.tool);
                    sections.push(`  - ${r.tool.name} (${r.tool.binary})`);
                    if (hint) sections.push(`    Install: ${hint}`);
                  }
                }

                sections.push("\nTo install all missing: call defense_mgmt action=check_tools install_missing=true dry_run=false");
                sections.push("Then re-run: defense_mgmt action=check_tools gate=true");

                return {
                  content: [createTextContent(sections.join("\n"))],
                  isError: true,
                  _meta: {
                    haltWorkflow: true,
                    gateResult: "blocked",
                    missingRequired: requiredMissing.map(r => ({ name: r.tool.name, binary: r.tool.binary, category: r.tool.category })),
                    missingOptional: optionalMissing.map(r => ({ name: r.tool.name, binary: r.tool.binary, category: r.tool.category })),
                    requiredMissingCount: requiredMissing.length,
                    optionalMissingCount: optionalMissing.length,
                  },
                };
              }

              if (optionalMissing.length > 0) {
                sections.push("");
                sections.push("✅ AUDIT GATE: PASSED (with warnings)");
                sections.push(`${optionalMissing.length} optional tool(s) missing — audit can proceed but some checks may be skipped.`);
                for (const r of optionalMissing) {
                  const hint = await getInstallHint(r.tool);
                  sections.push(`  - ${r.tool.name} (${r.tool.binary})${hint ? ` — Install: ${hint}` : ""}`);
                }

                return {
                  content: [createTextContent(sections.join("\n"))],
                  _meta: {
                    haltWorkflow: false,
                    gateResult: "passed_with_warnings",
                    missingRequired: [],
                    missingOptional: optionalMissing.map(r => ({ name: r.tool.name, binary: r.tool.binary, category: r.tool.category })),
                    requiredMissingCount: 0,
                    optionalMissingCount: optionalMissing.length,
                  },
                };
              }

              // All tools present
              sections.push("\n✅ AUDIT GATE: PASSED — all tools available.");
              return {
                content: [createTextContent(sections.join("\n"))],
                _meta: {
                  haltWorkflow: false,
                  gateResult: "passed",
                  missingRequired: [],
                  missingOptional: [],
                  requiredMissingCount: 0,
                  optionalMissingCount: 0,
                },
              };
            }

            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── workflow_suggest ───────────────────────────────────────────────
        case "workflow_suggest": {
          const { objective, system_type } = params;
          try {
            if (!objective) return { content: [createErrorContent("objective is required for workflow_suggest action")], isError: true };

            const sections: string[] = [];
            sections.push(`📋 Recommended Workflow: ${objective.replace(/_/g, " ").toUpperCase()}`);
            sections.push(`System type: ${system_type}`);
            sections.push("=".repeat(50));

            const suggestions = WORKFLOW_SUGGESTIONS[objective]?.[system_type!] || [];
            if (suggestions.length === 0) {
              sections.push("\nNo specific workflow available for this combination.");
              return { content: [createTextContent(sections.join("\n"))] };
            }

            let totalMinutes = 0;
            for (let i = 0; i < suggestions.length; i++) {
              const step = suggestions[i];
              totalMinutes += step.estimatedMinutes;
              sections.push(`\n  Step ${i + 1}: ${step.description}`);
              sections.push(`    Tool: ${step.tool}`);
              if (step.suggestedParams) sections.push(`    Suggested params: { ${step.suggestedParams} }`);
              sections.push(`    Estimated time: ~${step.estimatedMinutes} min`);
            }

            sections.push(`\n── Workflow Summary ──`);
            sections.push(`  Total steps: ${suggestions.length}`);
            sections.push(`  Estimated total time: ~${totalMinutes} minutes`);
            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) {
            return { content: [createErrorContent(err instanceof Error ? err.message : String(err))], isError: true };
          }
        }

        // ── workflow_run ───────────────────────────────────────────────────
        case "workflow_run": {
          const { workflow, dry_run } = params;
          try {
            if (!workflow) return { content: [createErrorContent("workflow is required for workflow_run action")], isError: true };

            const sections: string[] = [];
            sections.push(`🚀 Workflow: ${workflow.replace(/_/g, " ").toUpperCase()}`);
            sections.push("=".repeat(50));

            const steps = WORKFLOWS[workflow];
            if (!steps || steps.length === 0) return { content: [createErrorContent(`Unknown workflow: ${workflow}`)], isError: true };

            const invalidSteps: string[] = [];
            for (const step of steps) {
              const cmdToCheck = step.command;
              if (!isAllowlisted(cmdToCheck)) invalidSteps.push(`${step.description}: '${cmdToCheck}' not in command allowlist`);
              if (cmdToCheck === "sudo" && step.args.length > 0) {
                const targetCmd = step.args.find(a => !a.startsWith("-"));
                if (targetCmd && !isAllowlisted(targetCmd)) invalidSteps.push(`${step.description}: sudo target '${targetCmd}' not in command allowlist`);
              }
            }
            if (invalidSteps.length > 0) return { content: [createErrorContent(`Workflow contains commands not in the allowlist:\n${invalidSteps.join("\n")}`)], isError: true };

            const totalEstimate = steps.reduce((sum, s) => sum + s.estimatedSeconds, 0);
            sections.push(`Steps: ${steps.length} | Estimated time: ~${Math.ceil(totalEstimate / 60)} min`);

            const effectiveDryRun = dry_run ?? getConfig().dryRun;
            if (effectiveDryRun) {
              sections.push("\n[DRY RUN] Workflow steps that would be executed:\n");
              for (let i = 0; i < steps.length; i++) {
                const step = steps[i];
                sections.push(`  Step ${i + 1}: ${step.description}`);
                sections.push(`    Tool: ${step.tool}`);
                sections.push(`    Command: ${step.command} ${step.args.join(" ")}`);
                sections.push(`    Est. time: ~${step.estimatedSeconds}s`);
                sections.push("");
              }
              sections.push("To execute, set dry_run: false");
              logChange(createChangeEntry({ tool: "defense_mgmt", action: `${workflow}_dry_run`, target: workflow, after: `Previewed ${steps.length} workflow steps`, dryRun: true, success: true }));
            } else {
              sections.push("\nExecuting workflow...\n");
              let successCount = 0, failCount = 0;

              for (let i = 0; i < steps.length; i++) {
                const step = steps[i];
                sections.push(`── Step ${i + 1}/${steps.length}: ${step.description} ──`);

                const stepSafety = await SafeguardRegistry.getInstance().checkSafety(
                  `defense_mgmt_${workflow}_step_${i + 1}`,
                  { command: step.command, args: step.args, description: step.description }
                );
                if (stepSafety.warnings.length > 0) sections.push(`  ⚠️ Safety warnings: ${stepSafety.warnings.join("; ")}`);
                if (!stepSafety.safe) {
                  sections.push(`  🛑 Step blocked by safeguards: ${stepSafety.blockers.join("; ")}`);
                  sections.push(`  Impacted: ${stepSafety.impactedApps.join(", ")}`);
                  failCount++;
                  logChange(createChangeEntry({ tool: "defense_mgmt", action: `${workflow}_step_${i + 1}`, target: step.description, after: `blocked by safeguards: ${stepSafety.blockers.join("; ")}`, dryRun: false, success: false, error: "Blocked by safeguard checks" }));
                  sections.push("");
                  continue;
                }

                const startTime = Date.now();
                const result = await executeCommand({ command: step.command, args: step.args, toolName: "defense_mgmt", timeout: Math.max(step.estimatedSeconds * 3 * 1000, 30000) });
                const duration = Math.round((Date.now() - startTime) / 1000);

                if (result.exitCode === 0) {
                  successCount++;
                  sections.push(`  ✅ Completed in ${duration}s`);
                  const output = result.stdout.trim();
                  if (output) {
                    const outputLines = output.split("\n");
                    if (outputLines.length > 20) { sections.push(`  Output (${outputLines.length} lines, showing first 20):`); for (const line of outputLines.slice(0, 20)) sections.push(`    ${line}`); sections.push("    ..."); }
                    else { sections.push("  Output:"); for (const line of outputLines) sections.push(`    ${line}`); }
                  }
                } else {
                  failCount++;
                  sections.push(`  ❌ Failed (exit ${result.exitCode}) in ${duration}s`);
                  if (result.stderr) sections.push(`  Error: ${result.stderr.substring(0, 200)}`);
                }
                sections.push("");
                logChange(createChangeEntry({ tool: "defense_mgmt", action: `${workflow}_step_${i + 1}`, target: step.description, after: `exit=${result.exitCode} duration=${duration}s`, dryRun: false, success: result.exitCode === 0, error: result.exitCode !== 0 ? result.stderr.substring(0, 200) : undefined }));
              }

              sections.push("── Workflow Summary ──");
              sections.push(`  Completed: ${successCount}/${steps.length}`);
              sections.push(`  Failed: ${failCount}/${steps.length}`);
              sections.push(failCount === 0 ? "  ✅ All steps completed successfully" : "  ⚠️ Some steps failed");
            }
            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) {
            return { content: [createErrorContent(err instanceof Error ? err.message : String(err))], isError: true };
          }
        }

        // ── change_history ─────────────────────────────────────────────────
        case "change_history": {
          const { limit, tool, since } = params;
          try {
            const sections: string[] = [];
            sections.push("📜 Defense Change History");
            sections.push("=".repeat(50));

            let entries = getChangelog(limit * 5);

            if (tool) entries = entries.filter((e) => e.tool.toLowerCase().includes(tool.toLowerCase()));

            if (since) {
              let sinceDate: Date;
              if (since.toLowerCase() === "today") {
                sinceDate = new Date();
                sinceDate.setHours(0, 0, 0, 0);
              } else {
                sinceDate = new Date(since);
              }
              if (!isNaN(sinceDate.getTime())) entries = entries.filter((e) => new Date(e.timestamp) >= sinceDate);
            }

            entries = entries.slice(0, limit);

            if (entries.length === 0) {
              sections.push("\nNo changes recorded");
              if (tool) sections.push(`  (filtered by tool: ${tool})`);
              if (since) sections.push(`  (filtered by since: ${since})`);
              return { content: [createTextContent(sections.join("\n"))] };
            }

            sections.push(`\nShowing ${entries.length} entries (newest first):`);
            if (tool) sections.push(`  Filter: tool contains '${tool}'`);
            if (since) sections.push(`  Filter: since '${since}'`);

            for (const entry of entries) {
              sections.push("\n  " + "─".repeat(40));
              sections.push(`  ID: ${entry.id}`);
              sections.push(`  Time: ${entry.timestamp}`);
              sections.push(`  Tool: ${entry.tool}`);
              sections.push(`  Action: ${entry.action}`);
              sections.push(`  Target: ${entry.target}`);
              sections.push(`  Dry Run: ${entry.dryRun ? "Yes" : "No"}`);
              sections.push(`  Success: ${entry.success ? "✅" : "❌"}`);
              if (entry.error) sections.push(`  Error: ${entry.error}`);
              if (entry.before) sections.push(`  Before: ${entry.before.substring(0, 100)}`);
              if (entry.after) sections.push(`  After: ${entry.after.substring(0, 100)}`);
              if (entry.backupPath) sections.push(`  Backup: ${entry.backupPath}`);
              if (entry.rollbackCommand) sections.push(`  Rollback: ${entry.rollbackCommand}`);
            }

            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── posture_score ──────────────────────────────────────────────────
        case "posture_score": {
          try {
            const domains: DomainScore[] = [];

            const kernelChecks: { name: string; key: string; expected: string }[] = [
              { name: "ASLR full", key: "kernel.randomize_va_space", expected: "2" },
              { name: "dmesg restricted", key: "kernel.dmesg_restrict", expected: "1" },
              { name: "kptr restricted", key: "kernel.kptr_restrict", expected: "2" },
              { name: "SysRq disabled", key: "kernel.sysrq", expected: "0" },
              { name: "ptrace restricted", key: "kernel.yama.ptrace_scope", expected: "1" },
              { name: "IP forwarding disabled", key: "net.ipv4.ip_forward", expected: "0" },
              { name: "SYN cookies enabled", key: "net.ipv4.tcp_syncookies", expected: "1" },
              { name: "ICMP redirects disabled", key: "net.ipv4.conf.all.accept_redirects", expected: "0" },
              { name: "Source routing disabled", key: "net.ipv4.conf.all.accept_source_route", expected: "0" },
              { name: "Core dumps restricted", key: "fs.suid_dumpable", expected: "0" },
            ];
            const kernelResults = await Promise.all(kernelChecks.map(async (c) => {
              const result = await checkSysctl(c.key, c.expected);
              return { name: c.name, passed: result.passed, assessable: result.assessable, detail: result.assessable ? c.key : `${c.key} (unable to assess)` };
            }));
            const assessableKernelCount = kernelResults.filter((r) => r.assessable).length;
            const kernelPassed = kernelResults.filter((r) => r.passed).length;
            const kernelScore = assessableKernelCount > 0 ? Math.round((kernelPassed / assessableKernelCount) * 100) : -1;
            domains.push({ domain: "kernel-hardening", score: kernelScore, maxScore: 100, checks: kernelResults.map((r) => ({ name: r.name, passed: r.passed, detail: r.detail })) });

            const fwChecks: { name: string; passed: boolean; detail: string }[] = [];

            // Check iptables/nftables rules (with sudo for accurate results)
            const iptResult = await executeCommand({ toolName: "defense_mgmt", command: "sudo", args: ["iptables", "-L", "-n"], timeout: 10000 });
            const hasIptRules = iptResult.exitCode === 0 && iptResult.stdout.split("\n").length > 8;
            fwChecks.push({ name: "iptables rules present", passed: hasIptRules, detail: `${iptResult.exitCode === 0 ? iptResult.stdout.split("\n").length : 0} lines` });

            // Multi-layer firewall detection: UFW → nftables fallback
            let fwDetected = false;
            const ufwResult = await executeCommand({ toolName: "defense_mgmt", command: "sudo", args: ["ufw", "status"], timeout: 5000 });
            if (ufwResult.exitCode === 0) {
              const ufwActive = ufwResult.stdout.includes("active");
              fwChecks.push({ name: "UFW active", passed: ufwActive, detail: ufwResult.stdout.slice(0, 100) });
              fwDetected = ufwActive;
            } else {
              // UFW command failed — check if nftables has active rules (UFW chains or native)
              const nftResult = await executeCommand({ toolName: "defense_mgmt", command: "sudo", args: ["nft", "list", "ruleset"], timeout: 10000 });
              if (nftResult.exitCode === 0) {
                const hasUfwChains = nftResult.stdout.includes("ufw-");
                const hasNftRules = nftResult.stdout.trim().length > 50;
                if (hasUfwChains) {
                  fwChecks.push({ name: "UFW active", passed: true, detail: "Active via nftables backend (ufw chains detected)" });
                  fwDetected = true;
                } else if (hasNftRules) {
                  fwChecks.push({ name: "nftables active", passed: true, detail: "Native nftables ruleset loaded" });
                  fwDetected = true;
                } else {
                  fwChecks.push({ name: "UFW active", passed: false, detail: "No firewall rules detected" });
                }
              } else {
                // Check if binary exists to distinguish "not installed" from "error"
                const whichUfw = await executeCommand({ toolName: "defense_mgmt", command: "which", args: ["ufw"], timeout: 3000 });
                const whichNft = await executeCommand({ toolName: "defense_mgmt", command: "which", args: ["nft"], timeout: 3000 });
                const detail = whichUfw.exitCode === 0 ? "UFW installed but status check failed"
                  : whichNft.exitCode === 0 ? "nftables installed but ruleset check failed"
                  : "No firewall installed";
                fwChecks.push({ name: "firewall detected", passed: false, detail });
              }
            }

            const fwPassed = fwChecks.filter((c) => c.passed).length;
            domains.push({ domain: "firewall", score: Math.round((fwPassed / fwChecks.length) * 100), maxScore: 100, checks: fwChecks });

            const dangerousServices = ["telnet.socket", "rsh.socket", "rlogin.socket", "tftp.socket", "xinetd.service"];
            const svcChecks: { name: string; passed: boolean; detail: string }[] = [];
            for (const svc of dangerousServices) {
              const r = await executeCommand({ toolName: "defense_mgmt", command: "systemctl", args: ["is-active", svc], timeout: 5000 });
              const inactive = r.exitCode !== 0 || r.stdout.trim() !== "active";
              svcChecks.push({ name: `${svc} disabled`, passed: inactive, detail: r.stdout.trim() });
            }
            const svcPassed = svcChecks.filter((c) => c.passed).length;
            domains.push({ domain: "services", score: Math.round((svcPassed / svcChecks.length) * 100), maxScore: 100, checks: svcChecks });

            const userChecks: { name: string; passed: boolean; detail: string }[] = [];
            const rootLogin = await executeCommand({ command: "sudo", args: ["passwd", "-S", "root"], timeout: 5000, toolName: "defense_mgmt" });
            const rootLocked = rootLogin.stdout.includes(" L ") || rootLogin.stdout.includes(" LK ");
            userChecks.push({ name: "Root account locked", passed: rootLocked, detail: rootLogin.stdout.trim().slice(0, 100) });
            const noPasswd = await executeCommand({ command: "sudo", args: ["awk", "-F:", '($2 == "" ) { print $1 }', "/etc/shadow"], timeout: 5000, toolName: "defense_mgmt" });
            const noEmptyPasswd = noPasswd.stdout.trim().length === 0;
            userChecks.push({ name: "No empty passwords", passed: noEmptyPasswd, detail: noPasswd.stdout.trim() || "none" });
            const uidZero = await executeCommand({ toolName: "defense_mgmt", command: "awk", args: ["-F:", '($3 == 0) { print $1 }', "/etc/passwd"], timeout: 5000 });
            const onlyRoot = uidZero.stdout.trim() === "root";
            userChecks.push({ name: "Only root has UID 0", passed: onlyRoot, detail: uidZero.stdout.trim() });
            const userPassed = userChecks.filter((c) => c.passed).length;
            domains.push({ domain: "users", score: Math.round((userPassed / userChecks.length) * 100), maxScore: 100, checks: userChecks });

            const fsChecks: { name: string; passed: boolean; detail: string }[] = [];
            const criticalFiles: [string, string][] = [["/etc/passwd", "644"], ["/etc/shadow", "640"], ["/etc/ssh/sshd_config", "600"]];
            for (const [fp, expected] of criticalFiles) {
              const r = await executeCommand({ toolName: "defense_mgmt", command: "stat", args: ["-c", "%a", fp], timeout: 5000 });
              const actual = r.stdout.trim();
              const ok = r.exitCode === 0 && parseInt(actual, 8) <= parseInt(expected, 8);
              fsChecks.push({ name: `${fp} permissions`, passed: ok, detail: `${actual} (expected \u2264${expected})` });
            }
            const fsPassed = fsChecks.filter((c) => c.passed).length;
            domains.push({ domain: "filesystem", score: Math.round((fsPassed / fsChecks.length) * 100), maxScore: 100, checks: fsChecks });

            const weights: Record<string, number> = { "kernel-hardening": 25, "firewall": 20, "services": 15, "users": 20, "filesystem": 20 };
            let weightedSum = 0, totalWeight = 0;
            for (const d of domains) {
              if (d.score < 0) continue;
              const w = weights[d.domain] ?? 10;
              weightedSum += d.score * w;
              totalWeight += w;
            }
            const overallScore = totalWeight > 0 ? Math.round(weightedSum / totalWeight) : 0;

            ensurePostureDir();
            const historyPath = join(POSTURE_DIR, "history.json");
            let history: { timestamp: string; score: number; domains: Record<string, number> }[] = [];
            try { if (existsSync(historyPath)) history = JSON.parse(readFileSync(historyPath, "utf-8")); } catch { /* start fresh */ }

            const domainScores: Record<string, number> = {};
            for (const d of domains) domainScores[d.domain] = d.score;
            history.push({ timestamp: new Date().toISOString(), score: overallScore, domains: domainScores });
            if (history.length > 1000) history = history.slice(-1000);
            writeFileSync(historyPath, JSON.stringify(history, null, 2), "utf-8");

            return { content: [formatToolOutput({ overallScore, rating: overallScore >= 80 ? "GOOD" : overallScore >= 60 ? "FAIR" : overallScore >= 40 ? "POOR" : "CRITICAL", domains })] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`Security score calculation failed: ${msg}`)], isError: true };
          }
        }

        // ── posture_trend ──────────────────────────────────────────────────
        case "posture_trend": {
          const { limit } = params;
          try {
            ensurePostureDir();
            const historyPath = join(POSTURE_DIR, "history.json");
            if (!existsSync(historyPath)) return { content: [formatToolOutput({ message: "No posture history found. Run defense_mgmt action=posture_score first." })] };

            const history = JSON.parse(readFileSync(historyPath, "utf-8"));
            const recent = history.slice(-limit);
            return { content: [formatToolOutput({ entries: recent.length, trend: recent, latestScore: recent.length > 0 ? recent[recent.length - 1].score : null })] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`Posture trend failed: ${msg}`)], isError: true };
          }
        }

        // ── posture_dashboard ──────────────────────────────────────────────
        case "posture_dashboard": {
          try {
            ensurePostureDir();
            const historyPath = join(POSTURE_DIR, "history.json");
            let latestEntry: { timestamp: string; score: number; domains: Record<string, number> } | null = null;
            try {
              if (existsSync(historyPath)) {
                const history = JSON.parse(readFileSync(historyPath, "utf-8"));
                if (history.length > 0) latestEntry = history[history.length - 1];
              }
            } catch { /* no history */ }

            if (!latestEntry) return { content: [formatToolOutput({ message: "No posture data available. Run defense_mgmt action=posture_score first." })] };

            const recommendations: string[] = [];
            for (const [domain, score] of Object.entries(latestEntry.domains)) {
              if (score < 0) recommendations.push(`INFO: ${domain} could not be assessed`);
              else if (score < 50) recommendations.push(`CRITICAL: ${domain} score is ${score}/100`);
              else if (score < 80) recommendations.push(`MODERATE: ${domain} score is ${score}/100`);
            }
            if (recommendations.length === 0) recommendations.push("All domains scoring above 80.");

            const displayDomainScores: Record<string, number | string> = {};
            for (const [domain, score] of Object.entries(latestEntry.domains)) displayDomainScores[domain] = score < 0 ? "N/A" : score;

            const weights: Record<string, number> = { "kernel-hardening": 25, "firewall": 20, "services": 15, "users": 20, "filesystem": 20 };
            let weightedSum = 0, totalWeight = 0;
            for (const [domain, score] of Object.entries(latestEntry.domains)) {
              if (score < 0) continue;
              const w = weights[domain] ?? 10;
              weightedSum += score * w;
              totalWeight += w;
            }
            const overallScore = totalWeight > 0 ? Math.round(weightedSum / totalWeight) : 0;

            return {
              content: [formatToolOutput({
                dashboard: {
                  timestamp: latestEntry.timestamp,
                  overallScore,
                  rating: overallScore >= 80 ? "GOOD" : overallScore >= 60 ? "FAIR" : overallScore >= 40 ? "POOR" : "CRITICAL",
                  domainScores: displayDomainScores,
                  recommendations,
                  nextSteps: ["Run defense_mgmt action=posture_score for detailed breakdown", "Address CRITICAL domains first", "Re-run periodically"],
                },
              })],
            };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`Dashboard generation failed: ${msg}`)], isError: true };
          }
        }

        // ── scheduled_create ───────────────────────────────────────────────
        case "scheduled_create": {
          const { name, command: auditCommand, schedule, useSystemd, dry_run } = params;
          if (!name) return { content: [createErrorContent("name is required for scheduled_create action")], isError: true };
          if (!auditCommand) return { content: [createErrorContent("command is required for scheduled_create action")], isError: true };
          if (!schedule) return { content: [createErrorContent("schedule is required for scheduled_create action")], isError: true };
          try {
            if (!AUDIT_NAME_RE.test(name)) return { content: [createErrorContent(`Invalid audit name: '${name}'. Only [a-zA-Z0-9_-] allowed.`)], isError: true };

            const validatedSchedule = validateSchedule(schedule, useSystemd);
            const allowedEntry = ALLOWED_AUDIT_COMMANDS[auditCommand];
            if (!allowedEntry) return { content: [createErrorContent(`Command not in scheduled audit allowlist: '${auditCommand}'. Allowed: ${Object.keys(ALLOWED_AUDIT_COMMANDS).join(", ")}`)], isError: true };

            let resolvedBinaryPath: string;
            try { resolvedBinaryPath = resolveCommand(allowedEntry.command); }
            catch { return { content: [createErrorContent(`Audit command binary '${allowedEntry.command}' not found on this system. Install it first.`)], isError: true }; }

            const resolvedCommandLine = [resolvedBinaryPath, ...allowedEntry.args].join(" ");
            const safety = await SafeguardRegistry.getInstance().checkSafety("defense_mgmt_scheduled_audit", { name });
            ensureAuditLogDir();
            const logFile = join(AUDIT_LOG_DIR, `${name}.log`);

            if (useSystemd) {
              const serviceContent = `[Unit]\nDescription=Defense Scheduled Audit: ${name}\n\n[Service]\nType=oneshot\nExecStart=${resolvedCommandLine}\nStandardOutput=append:${logFile}\nStandardError=append:${logFile}\n`;
              const timerContent = `[Unit]\nDescription=Timer for ${name} audit\n\n[Timer]\nOnCalendar=${validatedSchedule}\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n`;
              const servicePath = `/etc/systemd/system/defense-audit-${name}.service`;
              const timerPath = `/etc/systemd/system/defense-audit-${name}.timer`;

              if (dry_run) return { content: [formatToolOutput({ dryRun: true, type: "systemd", servicePath, timerPath, serviceContent, timerContent, warnings: safety.warnings, enableCommand: `systemctl enable --now defense-audit-${name}.timer` })] };

              writeFileSync(servicePath, serviceContent, "utf-8");
              writeFileSync(timerPath, timerContent, "utf-8");
              await executeCommand({ toolName: "defense_mgmt", command: "systemctl", args: ["daemon-reload"], timeout: 10000 });
              const enable = await executeCommand({ toolName: "defense_mgmt", command: "systemctl", args: ["enable", "--now", `defense-audit-${name}.timer`], timeout: 10000 });
              logChange(createChangeEntry({ tool: "defense_mgmt", action: `Create systemd timer for ${name}`, target: timerPath, dryRun: false, success: enable.exitCode === 0, rollbackCommand: `systemctl disable --now defense-audit-${name}.timer && rm ${servicePath} ${timerPath}` }));
              return { content: [formatToolOutput({ success: enable.exitCode === 0, type: "systemd", name, servicePath, timerPath, enabled: enable.exitCode === 0 })] };
            }

            const cronLine = `${validatedSchedule} ${resolvedCommandLine} >> ${logFile} 2>&1 # defense-audit-${name}`;
            if (dry_run) return { content: [formatToolOutput({ dryRun: true, type: "cron", cronLine, warnings: safety.warnings })] };

            const currentCron = await executeCommand({ toolName: "defense_mgmt", command: "crontab", args: ["-l"], timeout: 5000 });
            const existing = currentCron.exitCode === 0 ? currentCron.stdout : "";
            if (existing.includes(`defense-audit-${name}`)) return { content: [createErrorContent(`Cron job 'defense-audit-${name}' already exists. Remove it first.`)], isError: true };

            const newCron = existing.trimEnd() + "\n" + cronLine + "\n";
            const install = await executeCommand({ toolName: "defense_mgmt", command: "crontab", args: ["-"], stdin: newCron, timeout: 5000 });
            logChange(createChangeEntry({ tool: "defense_mgmt", action: `Create cron job for ${name}`, target: "crontab", dryRun: false, success: install.exitCode === 0 }));
            return { content: [formatToolOutput({ success: install.exitCode === 0, type: "cron", name, cronLine })] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`Scheduled audit setup failed: ${msg}`)], isError: true };
          }
        }

        // ── scheduled_list ─────────────────────────────────────────────────
        case "scheduled_list": {
          try {
            const audits: { name: string; type: string; schedule: string; status: string }[] = [];

            const timers = await executeCommand({ toolName: "defense_mgmt", command: "systemctl", args: ["list-timers", "--no-pager", "--plain"], timeout: 10000 });
            if (timers.exitCode === 0) {
              for (const line of timers.stdout.split("\n")) {
                if (line.includes("defense-audit-")) {
                  const match = line.match(/defense-audit-(\S+)/);
                  if (match) audits.push({ name: match[1].replace(".timer", ""), type: "systemd", schedule: line.trim(), status: "active" });
                }
              }
            }

            const cron = await executeCommand({ toolName: "defense_mgmt", command: "crontab", args: ["-l"], timeout: 5000 });
            if (cron.exitCode === 0) {
              for (const line of cron.stdout.split("\n")) {
                if (line.includes("defense-audit-")) {
                  const match = line.match(/# defense-audit-(\S+)/);
                  if (match) audits.push({ name: match[1], type: "cron", schedule: line.split("#")[0].trim(), status: "active" });
                }
              }
            }

            return { content: [formatToolOutput({ totalAudits: audits.length, audits })] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`List audits failed: ${msg}`)], isError: true };
          }
        }

        // ── scheduled_remove ───────────────────────────────────────────────
        case "scheduled_remove": {
          const { name, dry_run } = params;
          try {
            if (!name) return { content: [createErrorContent("name is required for scheduled_remove action")], isError: true };
            const actions: { action: string; success: boolean }[] = [];

            const timerPath = `/etc/systemd/system/defense-audit-${name}.timer`;
            const servicePath = `/etc/systemd/system/defense-audit-${name}.service`;
            const hasTimer = existsSync(timerPath);

            const cron = await executeCommand({ toolName: "defense_mgmt", command: "crontab", args: ["-l"], timeout: 5000 });
            const hasCron = cron.exitCode === 0 && cron.stdout.includes(`defense-audit-${name}`);

            if (!hasTimer && !hasCron) return { content: [createErrorContent(`No scheduled audit found with name: ${name}`)], isError: true };

            if (dry_run) return { content: [formatToolOutput({ dryRun: true, name, hasSystemdTimer: hasTimer, hasCronJob: hasCron, actions: [hasTimer ? `systemctl disable --now defense-audit-${name}.timer && rm ${timerPath} ${servicePath}` : null, hasCron ? `Remove cron line containing defense-audit-${name}` : null].filter(Boolean) })] };

            if (hasTimer) {
              await executeCommand({ toolName: "defense_mgmt", command: "systemctl", args: ["disable", "--now", `defense-audit-${name}.timer`], timeout: 10000 });
              await executeCommand({ toolName: "defense_mgmt", command: "rm", args: ["-f", timerPath, servicePath], timeout: 5000 });
              await executeCommand({ toolName: "defense_mgmt", command: "systemctl", args: ["daemon-reload"], timeout: 10000 });
              actions.push({ action: "Removed systemd timer", success: true });
            }

            if (hasCron) {
              const cronLines = cron.stdout.split("\n").filter((l) => !l.includes(`defense-audit-${name}`));
              await executeCommand({ toolName: "defense_mgmt", command: "crontab", args: ["-"], stdin: cronLines.join("\n") + "\n", timeout: 5000 });
              actions.push({ action: "Removed cron job", success: true });
            }

            logChange(createChangeEntry({ tool: "defense_mgmt", action: `Remove scheduled audit ${name}`, target: name, dryRun: false, success: true }));
            return { content: [formatToolOutput({ name, actions })] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`Remove audit failed: ${msg}`)], isError: true };
          }
        }

        // ── scheduled_history ──────────────────────────────────────────────
        case "scheduled_history": {
          const { name, lines } = params;
          try {
            if (!name) return { content: [createErrorContent("name is required for scheduled_history action")], isError: true };
            ensureAuditLogDir();
            const logFile = join(AUDIT_LOG_DIR, `${name}.log`);
            if (!existsSync(logFile)) return { content: [formatToolOutput({ name, message: `No audit log found at ${logFile}` })] };

            const result = await executeCommand({ toolName: "defense_mgmt", command: "tail", args: ["-n", String(lines), logFile], timeout: 10000 });
            return { content: [formatToolOutput({ name, logFile, lines: result.stdout.trim().split("\n"), totalLines: result.stdout.trim().split("\n").length })] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`Audit history failed: ${msg}`)], isError: true };
          }
        }

        // ── remediate_plan ─────────────────────────────────────────────────
        case "remediate_plan": {
          try {
            const effectiveSource = params.source ?? "all";
            const effectiveSeverity = (params.severity_filter ?? "medium") as RemSeverity;
            const findings = await gatherRemediationFindings(effectiveSource, effectiveSeverity);

            if (params.output_format === "json") {
              return { content: [formatToolOutput({ action: "plan", source: effectiveSource, severity_filter: effectiveSeverity, total_findings: findings.length, findings: findings.map(f => ({ finding_id: f.finding_id, description: f.description, severity: f.severity, remediation_command: `${f.remediation_command} ${f.remediation_args.join(" ")}`, risk_level: f.risk_level, category: f.category })) })] };
            }

            const sections: string[] = [];
            sections.push("🔍 Auto-Remediation Plan");
            sections.push("=".repeat(50));
            sections.push(`Source: ${effectiveSource} | Severity filter: >= ${effectiveSeverity}`);
            sections.push(`Total findings: ${findings.length}`);

            if (findings.length === 0) {
              sections.push("\n✅ No findings match the current filters. System looks good!");
              return { content: [createTextContent(sections.join("\n"))] };
            }

            for (const f of findings) {
              sections.push("");
              sections.push(`  [${f.severity.toUpperCase()}] ${f.finding_id}: ${f.description}`);
              sections.push(`    Category: ${f.category}`);
              sections.push(`    Fix: ${f.remediation_command} ${f.remediation_args.join(" ")}`);
              sections.push(`    Risk: ${f.risk_level}`);
            }

            const safeCount = findings.filter(f => f.risk_level === "safe").length;
            const moderateCount = findings.filter(f => f.risk_level === "moderate").length;
            const riskyCount = findings.filter(f => f.risk_level === "risky").length;
            sections.push("\n── Plan Summary ──");
            sections.push(`  Safe: ${safeCount} | Moderate: ${moderateCount} | Risky: ${riskyCount}`);
            sections.push("  Use action=remediate_apply with dry_run=false to execute safe remediations.");

            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`Remediation plan failed: ${msg}`)], isError: true };
          }
        }

        // ── remediate_apply ────────────────────────────────────────────────
        case "remediate_apply": {
          try {
            const effectiveSource = params.source ?? "all";
            const effectiveSeverity = (params.severity_filter ?? "medium") as RemSeverity;
            const effectiveDryRun = params.dry_run ?? true;
            const findings = await gatherRemediationFindings(effectiveSource, effectiveSeverity);

            if (findings.length === 0) {
              const msg = "No findings match the current filters. Nothing to remediate.";
              if (params.output_format === "json") return { content: [formatToolOutput({ action: "apply", dry_run: effectiveDryRun, message: msg, actions_taken: 0 })] };
              return { content: [createTextContent(`✅ ${msg}`)] };
            }

            if (effectiveDryRun) {
              if (params.output_format === "json") {
                return { content: [formatToolOutput({ action: "apply", dry_run: true, total_findings: findings.length, would_execute: findings.filter(f => f.risk_level === "safe").map(f => ({ finding_id: f.finding_id, description: f.description, command: `${f.remediation_command} ${f.remediation_args.join(" ")}`, risk_level: f.risk_level })), would_skip: findings.filter(f => f.risk_level !== "safe").map(f => ({ finding_id: f.finding_id, description: f.description, risk_level: f.risk_level, reason: `risk_level is ${f.risk_level} (only safe actions auto-executed)` })) })] };
              }

              const sections: string[] = [];
              sections.push("🔒 Auto-Remediation — DRY RUN");
              sections.push("=".repeat(50));
              sections.push("[DRY RUN] No changes will be made.\n");

              const safeFindings = findings.filter(f => f.risk_level === "safe");
              const skippedFindings = findings.filter(f => f.risk_level !== "safe");

              if (safeFindings.length > 0) {
                sections.push("Would execute:");
                for (const f of safeFindings) {
                  sections.push(`  ✅ ${f.finding_id}: ${f.remediation_command} ${f.remediation_args.join(" ")}`);
                  sections.push(`     ${f.description}`);
                }
              }
              if (skippedFindings.length > 0) {
                sections.push("\nWould skip (too risky for auto-execution):");
                for (const f of skippedFindings) sections.push(`  ⏭️  ${f.finding_id}: ${f.description} [${f.risk_level}]`);
              }
              sections.push("\nSet dry_run=false to execute safe remediations.");
              return { content: [createTextContent(sections.join("\n"))] };
            }

            const sessionId = generateSessionId();
            const session: RemediationSession = {
              session_id: sessionId,
              created_at: new Date().toISOString(),
              status: "in_progress",
              actions: [],
              summary: { total: 0, successful: 0, failed: 0, skipped: 0, rolled_back: 0 },
            };

            const sections: string[] = [];
            sections.push("🔧 Auto-Remediation — LIVE EXECUTION");
            sections.push("=".repeat(50));
            sections.push(`Session ID: ${sessionId}\n`);

            for (const f of findings) {
              session.summary.total++;
              if (f.risk_level !== "safe") {
                session.actions.push({ finding_id: f.finding_id, description: f.description, remediation_command: f.remediation_command, remediation_args: f.remediation_args, rollback_command: f.rollback_command, rollback_args: f.rollback_args, before_state: "", after_state: "", status: "skipped", error: `risk_level is ${f.risk_level} (only safe actions auto-executed)`, timestamp: new Date().toISOString() });
                session.summary.skipped++;
                sections.push(`  ⏭️  ${f.finding_id}: SKIPPED (${f.risk_level} risk)`);
                continue;
              }
              if (!REMEDIATION_ALLOWLIST.has(f.remediation_command)) {
                session.actions.push({ finding_id: f.finding_id, description: f.description, remediation_command: f.remediation_command, remediation_args: f.remediation_args, rollback_command: f.rollback_command, rollback_args: f.rollback_args, before_state: "", after_state: "", status: "skipped", error: `Command '${f.remediation_command}' not in remediation allowlist`, timestamp: new Date().toISOString() });
                session.summary.skipped++;
                sections.push(`  ⏭️  ${f.finding_id}: SKIPPED (command not in remediation allowlist)`);
                continue;
              }

              let beforeState = "";
              const setArg = f.remediation_args.find(a => a.includes("="));
              if (setArg && f.remediation_command === "sysctl") {
                const key = setArg.substring(0, setArg.indexOf("="));
                const beforeResult = await runRemediateCmd("sysctl", ["-n", key]);
                beforeState = beforeResult.stdout.trim();
              }

              const result = await runRemediateCmd(f.remediation_command, f.remediation_args);

              let afterState = "";
              if (setArg && f.remediation_command === "sysctl") {
                const key = setArg.substring(0, setArg.indexOf("="));
                const afterResult = await runRemediateCmd("sysctl", ["-n", key]);
                afterState = afterResult.stdout.trim();
              }

              if (result.exitCode === 0) {
                session.actions.push({ finding_id: f.finding_id, description: f.description, remediation_command: f.remediation_command, remediation_args: f.remediation_args, rollback_command: f.rollback_command, rollback_args: f.rollback_args, before_state: beforeState, after_state: afterState, status: "success", timestamp: new Date().toISOString() });
                session.summary.successful++;
                sections.push(`  ✅ ${f.finding_id}: ${f.description}`);
              } else {
                session.actions.push({ finding_id: f.finding_id, description: f.description, remediation_command: f.remediation_command, remediation_args: f.remediation_args, rollback_command: f.rollback_command, rollback_args: f.rollback_args, before_state: beforeState, after_state: afterState, status: "failed", error: result.stderr.substring(0, 200), timestamp: new Date().toISOString() });
                session.summary.failed++;
                sections.push(`  ❌ ${f.finding_id}: FAILED — ${result.stderr.substring(0, 100)}`);
              }
            }

            session.status = session.summary.failed === 0 && session.summary.skipped === 0 ? "completed" : session.summary.successful > 0 ? "partial" : "completed";

            try {
              const sessionPath = join(REMEDIATION_SESSIONS_DIR, `${sessionId}.json`);
              secureWriteFileSync(sessionPath, JSON.stringify(session, null, 2), "utf-8");
              sections.push(`\nSession saved: ${sessionPath}`);
            } catch (writeErr: unknown) {
              sections.push(`\n⚠️ Failed to save session: ${writeErr instanceof Error ? writeErr.message : String(writeErr)}`);
            }

            sections.push("\n── Summary ──");
            sections.push(`  Total: ${session.summary.total} | Success: ${session.summary.successful} | Failed: ${session.summary.failed} | Skipped: ${session.summary.skipped}`);
            sections.push(`  Session ID: ${sessionId} (use with remediate_rollback to undo)`);

            if (params.output_format === "json") return { content: [formatToolOutput(session)] };
            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`Remediation apply failed: ${msg}`)], isError: true };
          }
        }

        // ── remediate_rollback ─────────────────────────────────────────────
        case "remediate_rollback": {
          try {
            const { session_id, output_format } = params;
            if (!session_id) return { content: [createErrorContent("session_id is required for remediate_rollback action")], isError: true };

            const sessionPath = join(REMEDIATION_SESSIONS_DIR, `${session_id}.json`);
            if (!existsSync(sessionPath)) return { content: [createErrorContent(`Session not found: ${session_id}`)], isError: true };

            let session: RemediationSession;
            try { session = JSON.parse(readFileSync(sessionPath, "utf-8")); }
            catch { return { content: [createErrorContent(`Failed to parse session file: ${sessionPath}`)], isError: true }; }

            const sections: string[] = [];
            sections.push("⏪ Rollback Session");
            sections.push("=".repeat(50));
            sections.push(`Session: ${session_id}`);

            const actionsToRollback = session.actions.filter(a => a.status === "success").reverse();
            if (actionsToRollback.length === 0) {
              sections.push("\nNo successful actions to roll back.");
              if (output_format === "json") return { content: [formatToolOutput({ session_id, actions_rolled_back: 0, message: "No successful actions to roll back" })] };
              return { content: [createTextContent(sections.join("\n"))] };
            }

            let rolledBack = 0, errors = 0;
            for (const action of actionsToRollback) {
              const result = await runRemediateCmd(action.rollback_command, action.rollback_args);
              if (result.exitCode === 0) {
                action.status = "rolled_back";
                rolledBack++;
                sections.push(`  ✅ Rolled back: ${action.finding_id} — ${action.description}`);
              } else {
                errors++;
                sections.push(`  ❌ Rollback failed: ${action.finding_id} — ${result.stderr.substring(0, 100)}`);
              }
            }

            session.status = "rolled_back";
            session.summary.rolled_back = rolledBack;
            try { secureWriteFileSync(sessionPath, JSON.stringify(session, null, 2), "utf-8"); } catch { /* best effort */ }

            sections.push(`\n── Rollback Summary ──`);
            sections.push(`  Rolled back: ${rolledBack} | Errors: ${errors}`);

            if (output_format === "json") return { content: [formatToolOutput({ session_id, actions_rolled_back: rolledBack, errors, session })] };
            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`Rollback failed: ${msg}`)], isError: true };
          }
        }

        // ── remediate_status ───────────────────────────────────────────────
        case "remediate_status": {
          try {
            const { session_id, output_format } = params;

            if (session_id) {
              const sessionPath = join(REMEDIATION_SESSIONS_DIR, `${session_id}.json`);
              if (!existsSync(sessionPath)) return { content: [createErrorContent(`Session not found: ${session_id}`)], isError: true };

              let session: RemediationSession;
              try { session = JSON.parse(readFileSync(sessionPath, "utf-8")); }
              catch { return { content: [createErrorContent(`Failed to parse session file: ${sessionPath}`)], isError: true }; }

              if (output_format === "json") return { content: [formatToolOutput(session)] };

              const sections: string[] = [];
              sections.push("📊 Remediation Session Detail");
              sections.push("=".repeat(50));
              sections.push(`Session: ${session.session_id}`);
              sections.push(`Created: ${session.created_at}`);
              sections.push(`Status: ${session.status}`);
              sections.push(`Total: ${session.summary.total} | Success: ${session.summary.successful} | Failed: ${session.summary.failed} | Skipped: ${session.summary.skipped} | Rolled back: ${session.summary.rolled_back}`);

              for (const a of session.actions) {
                sections.push(`\n  ${a.finding_id}: ${a.description}`);
                sections.push(`    Status: ${a.status}`);
                if (a.error) sections.push(`    Error: ${a.error}`);
                if (a.before_state) sections.push(`    Before: ${a.before_state}`);
                if (a.after_state) sections.push(`    After: ${a.after_state}`);
              }

              return { content: [createTextContent(sections.join("\n"))] };
            }

            if (!existsSync(REMEDIATION_SESSIONS_DIR)) {
              const msg = "No remediation sessions found. Run defense_mgmt action=remediate_apply first.";
              if (output_format === "json") return { content: [formatToolOutput({ sessions: [], message: msg })] };
              return { content: [createTextContent(msg)] };
            }

            const files = readdirSync(REMEDIATION_SESSIONS_DIR).filter((f: string) => f.endsWith(".json"));
            if (files.length === 0) {
              const msg = "No remediation sessions found.";
              if (output_format === "json") return { content: [formatToolOutput({ sessions: [], message: msg })] };
              return { content: [createTextContent(msg)] };
            }

            const sessionSummaries: Array<{ session_id: string; created_at: string; status: string; total: number; successful: number; failed: number; rolled_back: number }> = [];
            for (const file of files) {
              try {
                const data = JSON.parse(readFileSync(join(REMEDIATION_SESSIONS_DIR, file), "utf-8")) as RemediationSession;
                sessionSummaries.push({ session_id: data.session_id, created_at: data.created_at, status: data.status, total: data.summary.total, successful: data.summary.successful, failed: data.summary.failed, rolled_back: data.summary.rolled_back });
              } catch { /* skip unparseable files */ }
            }

            if (output_format === "json") return { content: [formatToolOutput({ total_sessions: sessionSummaries.length, sessions: sessionSummaries })] };

            const sections: string[] = [];
            sections.push("📊 Remediation Sessions");
            sections.push("=".repeat(50));
            sections.push(`Total sessions: ${sessionSummaries.length}\n`);
            for (const s of sessionSummaries) {
              sections.push(`  ${s.session_id}`);
              sections.push(`    Created: ${s.created_at} | Status: ${s.status}`);
              sections.push(`    Actions: ${s.total} total, ${s.successful} success, ${s.failed} failed, ${s.rolled_back} rolled back`);
            }
            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`Status check failed: ${msg}`)], isError: true };
          }
        }

        // ── report_generate ────────────────────────────────────────────────
        case "report_generate": {
          const { report_type, format, output_path, include_sections, since } = params;
          try {
            const timestamp = new Date().toISOString();
            const effectiveReportType = report_type ?? "technical_detail";
            const effectiveFormat = format ?? "markdown";
            const sectionsToInclude = include_sections && include_sections.length > 0 ? include_sections : ALL_SECTIONS;

            const sectionPromises: Array<Promise<ReportSection>> = [];
            if (sectionsToInclude.includes("system_overview")) sectionPromises.push(gatherSystemOverview());
            if (sectionsToInclude.includes("firewall_status")) sectionPromises.push(gatherFirewallStatus());
            if (sectionsToInclude.includes("service_audit")) sectionPromises.push(gatherServiceAudit());
            if (sectionsToInclude.includes("active_connections")) sectionPromises.push(gatherActiveConnections());
            if (sectionsToInclude.includes("recent_logins")) sectionPromises.push(gatherRecentLogins(since));
            if (sectionsToInclude.includes("compliance_summary")) sectionPromises.push(gatherComplianceSummary());

            const sections = await Promise.all(sectionPromises);
            if (sectionsToInclude.includes("recommendations")) sections.push(generateReportRecommendations(sections));

            let reportContent: string;
            switch (effectiveFormat) {
              case "html": reportContent = formatAsHtml(sections, effectiveReportType, timestamp); break;
              case "json": reportContent = formatAsJson(sections, effectiveReportType, timestamp); break;
              case "csv": reportContent = formatAsCsv(sections, effectiveReportType, timestamp); break;
              case "markdown": default: reportContent = formatAsMarkdown(sections, effectiveReportType, timestamp); break;
            }

            if (output_path) {
              try { secureWriteFileSync(output_path, reportContent, "utf-8"); }
              catch (writeErr: unknown) {
                const msg = writeErr instanceof Error ? writeErr.message : String(writeErr);
                return { content: [createErrorContent(`Report generated but failed to write to ${output_path}: ${msg}`)], isError: true };
              }
            }

            if (effectiveFormat === "json") {
              return { content: [formatToolOutput({ reportType: effectiveReportType, format: effectiveFormat, timestamp, savedTo: output_path || null, sectionsIncluded: sections.map((s) => s.key), report: JSON.parse(reportContent) })] };
            }

            const summary = { reportType: effectiveReportType, format: effectiveFormat, timestamp, savedTo: output_path || null, sectionsIncluded: sections.map((s) => s.key), sectionsWithErrors: sections.filter((s) => s.error).map((s) => s.key) };
            return { content: [createTextContent(reportContent), formatToolOutput(summary)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`Report generation failed: ${msg}`)], isError: true };
          }
        }

        // ── report_list ────────────────────────────────────────────────────
        case "report_list": {
          try {
            if (!existsSync(DEFAULT_REPORT_DIR)) {
              return { content: [formatToolOutput({ reportDir: DEFAULT_REPORT_DIR, reports: [], message: `Report directory ${DEFAULT_REPORT_DIR} does not exist. Generate a report with output_path to create it.` })] };
            }

            const files = readdirSync(DEFAULT_REPORT_DIR);
            const reports = files.filter((f) => /\.(md|html|json|csv)$/.test(f)).map((f) => {
              const fullPath = `${DEFAULT_REPORT_DIR}/${f}`;
              try {
                const stats = statSync(fullPath);
                return { filename: f, path: fullPath, size: stats.size, modified: stats.mtime.toISOString() };
              } catch {
                return { filename: f, path: fullPath, size: 0, modified: "unknown" };
              }
            });

            return { content: [formatToolOutput({ reportDir: DEFAULT_REPORT_DIR, totalReports: reports.length, reports })] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`Failed to list reports: ${msg}`)], isError: true };
          }
        }

        // ── report_formats ─────────────────────────────────────────────────
        case "report_formats": {
          return { content: [formatToolOutput({ supportedFormats: SUPPORTED_FORMATS, reportTypes: REPORT_TYPES, availableSections: ALL_SECTIONS })] };
        }

        // ── check_optional_deps ─────────────────────────────────────────────
        case "check_optional_deps": {
          try {
            const statuses = await listThirdPartyTools();
            const sections: string[] = [];
            sections.push("📦 Optional Third-Party Tool Status");
            sections.push("=".repeat(50));
            sections.push("");

            // Table header
            sections.push(
              "  " +
              "Binary".padEnd(18) +
              "Installed".padEnd(12) +
              "Current".padEnd(12) +
              "Target".padEnd(12) +
              "Method".padEnd(16) +
              "Verification"
            );
            sections.push("  " + "─".repeat(80));

            let installedCount = 0;
            let missingCount = 0;

            for (const status of statuses) {
              const entry = THIRD_PARTY_MANIFEST.find(e => e.binary === status.binary);
              const installedStr = status.installed ? "✅ yes" : "❌ no";
              const currentVer = status.currentVersion ?? "—";
              const targetVer = status.manifestVersion;
              const method = entry?.installMethod ?? "unknown";
              const verification = entry?.verification ?? "unknown";

              if (status.installed) installedCount++;
              else missingCount++;

              sections.push(
                "  " +
                status.binary.padEnd(18) +
                installedStr.padEnd(12) +
                currentVer.padEnd(12) +
                targetVer.padEnd(12) +
                method.padEnd(16) +
                verification
              );
            }

            sections.push("");
            sections.push(`── Summary ──`);
            sections.push(`  Installed: ${installedCount} | Missing: ${missingCount} | Total: ${statuses.length}`);

            if (missingCount > 0) {
              sections.push("");
              sections.push("── Install Hints for Missing Tools ──");
              for (const status of statuses) {
                if (!status.installed) {
                  const instructions = getVerifiedInstallInstructions(status.binary);
                  const firstLine = instructions.split("\n").find(l => l.startsWith("##")) ?? `Install ${status.binary}`;
                  sections.push(`  • ${status.binary}: ${firstLine}`);
                }
              }
              sections.push("");
              sections.push("  💡 Run: defense_mgmt → install_optional_deps (dry_run=true) to see full install plan");
            }

            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`Optional deps check failed: ${msg}`)], isError: true };
          }
        }

        // ── install_optional_deps ───────────────────────────────────────────
        case "install_optional_deps": {
          try {
            const effectiveDryRun = params.dry_run ?? getConfig().dryRun ?? true;
            const toolName = params.tool_name as string | undefined;
            const forceInstall = (params.force as boolean | undefined) ?? false;

            // Gate 1: Check DEFENSE_MCP_THIRD_PARTY_INSTALL env var
            if (!isThirdPartyInstallEnabled()) {
              const sections: string[] = [];
              sections.push("🔒 Third-Party Installation Not Enabled");
              sections.push("=".repeat(50));
              sections.push("");
              sections.push("SECURITY: Third-party tool installation requires explicit opt-in.");
              sections.push("Set the following environment variable in your MCP server configuration:");
              sections.push("");
              sections.push("  DEFENSE_MCP_THIRD_PARTY_INSTALL=true");
              sections.push("");
              sections.push("This is required because these tools are downloaded from external sources");
              sections.push("and installed with elevated privileges. All downloads are cryptographically");
              sections.push("verified (SHA256/GPG) before installation.");
              sections.push("");

              // Show missing tools with install instructions
              const statuses = await listThirdPartyTools();
              const missing = statuses.filter(s => !s.installed);
              if (missing.length > 0) {
                sections.push("── Missing Optional Tools ──");
                for (const status of missing) {
                  sections.push(`\n  📦 ${status.name} (v${status.manifestVersion})`);
                  const instructions = getVerifiedInstallInstructions(status.binary);
                  // Show first few lines of instructions
                  const instrLines = instructions.split("\n").slice(0, 3);
                  for (const line of instrLines) {
                    sections.push(`     ${line}`);
                  }
                }
              } else {
                sections.push("  ✅ All optional tools are already installed.");
              }

              return { content: [createTextContent(sections.join("\n"))] };
            }

            // Gate 2: Dry-run mode — show plan without executing
            if (effectiveDryRun) {
              const statuses = await listThirdPartyTools();
              const sections: string[] = [];
              sections.push("📋 Third-Party Tool Installation Plan [DRY RUN]");
              sections.push("=".repeat(50));
              sections.push("");

              let planCount = 0;
              for (const status of statuses) {
                // If tool_name specified, only show that tool
                if (toolName && status.binary !== toolName) continue;

                if (!status.installed || forceInstall) {
                  const entry = THIRD_PARTY_MANIFEST.find(e => e.binary === status.binary);
                  planCount++;
                  sections.push(`  ${planCount}. ${status.name} (${status.binary})`);
                  sections.push(`     Version: ${status.manifestVersion}`);
                  sections.push(`     Method:  ${entry?.installMethod ?? "unknown"}`);
                  sections.push(`     Verify:  ${entry?.verification ?? "unknown"}`);
                  if (status.installed && forceInstall) {
                    sections.push(`     Note:    Currently installed (v${status.currentVersion ?? "unknown"}) — force reinstall`);
                  }
                  sections.push("");
                }
              }

              if (planCount === 0) {
                sections.push("  ✅ All optional tools are already installed. Nothing to do.");
                if (toolName) {
                  const found = statuses.find(s => s.binary === toolName);
                  if (!found) {
                    sections.push(`  ⚠️  Tool '${toolName}' is not in the third-party manifest.`);
                  }
                }
              } else {
                sections.push(`── Plan Summary ──`);
                sections.push(`  Tools to install: ${planCount}`);
                sections.push(`  Set dry_run=false to execute installation.`);
              }

              return { content: [createTextContent(sections.join("\n"))] };
            }

            // Gate 3: Live installation (dry_run=false AND DEFENSE_MCP_THIRD_PARTY_INSTALL=true)
            const statuses = await listThirdPartyTools();
            const sections: string[] = [];
            sections.push("🔧 Third-Party Tool Installation [LIVE]");
            sections.push("=".repeat(50));
            sections.push("");

            if (!forceInstall) {
              sections.push("⚠️  Note: The caller is responsible for confirming intent.");
              sections.push("   Use force=true to skip this notice for automation.");
              sections.push("");
            }

            let successCount = 0;
            let failCount = 0;
            let skipCount = 0;

            for (const status of statuses) {
              // If tool_name specified, only install that tool
              if (toolName && status.binary !== toolName) continue;

              if (status.installed && !forceInstall) {
                skipCount++;
                sections.push(`  ⏭️  ${status.name} (${status.binary}) — already installed (v${status.currentVersion ?? "unknown"})`);
                continue;
              }

              sections.push(`  ⏳ Installing ${status.name} v${status.manifestVersion}...`);
              const result = await installThirdPartyTool(status.binary, { force: forceInstall });

              if (result.success) {
                successCount++;
                sections.push(`  ✅ ${result.message}`);
              } else {
                failCount++;
                sections.push(`  ❌ ${result.message}`);
              }
            }

            if (toolName) {
              const found = statuses.find(s => s.binary === toolName);
              if (!found) {
                sections.push(`  ⚠️  Tool '${toolName}' is not in the third-party manifest.`);
                sections.push(`  Available tools: ${statuses.map(s => s.binary).join(", ")}`);
              }
            }

            sections.push("");
            sections.push("── Installation Summary ──");
            sections.push(`  Success: ${successCount} | Failed: ${failCount} | Skipped: ${skipCount}`);

            logChange(createChangeEntry({
              tool: "defense_mgmt",
              action: "install_optional_deps",
              target: toolName ?? "all",
              after: `success=${successCount} failed=${failCount} skipped=${skipCount}`,
              dryRun: false,
              success: failCount === 0,
            }));

            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`Optional deps installation failed: ${msg}`)], isError: true };
          }
        }

        default:
          return { content: [createErrorContent(`Unknown action: ${action}`)], isError: true };
      }
    }
  );
}
