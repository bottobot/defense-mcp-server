/**
 * Meta/utility tools for Kali Defense MCP Server.
 *
 * Registers 5 tools: defense_check_tools, defense_workflow (actions: suggest, run),
 * defense_change_history, security_posture (actions: score, trend, dashboard),
 * scheduled_audit (actions: create, list, remove, history).
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeCommand } from "../core/executor.js";
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
  type ToolCategory,
  type ToolCheckResult,
} from "../core/installer.js";
import { SafeguardRegistry } from "../core/safeguards.js";
import { existsSync, readFileSync, writeFileSync, mkdirSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

// ── Security Posture Helpers ───────────────────────────────────────────────

const POSTURE_DIR = join(homedir(), ".kali-mcp-posture");

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
  const r = await executeCommand({ command: "sysctl", args: ["-n", key], timeout: 5000 });
  if (r.exitCode !== 0) {
    return { passed: false, assessable: false, actual: r.stderr.trim() || "command failed" };
  }
  const actual = r.stdout.trim();
  return { passed: actual === expected, assessable: true, actual };
}

// ── Automation Workflow Helpers ─────────────────────────────────────────────

const AUDIT_LOG_DIR = join(homedir(), ".kali-defense", "audit-logs");

function ensureAuditLogDir(): void {
  if (!existsSync(AUDIT_LOG_DIR)) {
    mkdirSync(AUDIT_LOG_DIR, { recursive: true });
  }
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
      {
        tool: "hardening_sysctl_audit",
        description: "Audit kernel security parameters",
        suggestedParams: "category: 'security'",
        estimatedMinutes: 1,
      },
      {
        tool: "hardening_ssh_audit",
        description: "Audit and harden SSH configuration",
        suggestedParams: "action: 'audit'",
        estimatedMinutes: 1,
      },
      {
        tool: "hardening_service_audit",
        description: "Audit running services, disable unnecessary ones",
        suggestedParams: "action: 'list'",
        estimatedMinutes: 2,
      },
      {
        tool: "firewall_iptables_list",
        description: "Review current firewall rules",
        suggestedParams: "table: 'filter'",
        estimatedMinutes: 1,
      },
      {
        tool: "access_user_audit",
        description: "Audit user accounts and privileges",
        suggestedParams: "check_type: 'all'",
        estimatedMinutes: 1,
      },
      {
        tool: "hardening_file_perms",
        description: "Audit file permissions on critical paths",
        suggestedParams: "path: '/etc', check_type: 'world_writable'",
        estimatedMinutes: 3,
      },
      {
        tool: "crypto_tls_config_audit",
        description: "Audit TLS/SSL configuration",
        suggestedParams: "service: 'all'",
        estimatedMinutes: 2,
      },
    ],
    desktop: [
      {
        tool: "hardening_sysctl_audit",
        description: "Audit kernel parameters",
        suggestedParams: "category: 'security'",
        estimatedMinutes: 1,
      },
      {
        tool: "firewall_ufw_status",
        description: "Check UFW firewall status",
        suggestedParams: "",
        estimatedMinutes: 1,
      },
      {
        tool: "hardening_service_audit",
        description: "Disable unnecessary services",
        suggestedParams: "action: 'list'",
        estimatedMinutes: 2,
      },
      {
        tool: "malware_clamscan",
        description: "Scan home directory",
        suggestedParams: "path: '/home', quick: true",
        estimatedMinutes: 10,
      },
    ],
    container: [
      {
        tool: "container_docker_audit",
        description: "Full Docker security audit",
        suggestedParams: "check_type: 'all'",
        estimatedMinutes: 3,
      },
      {
        tool: "container_docker_bench",
        description: "Run CIS Docker Benchmark",
        suggestedParams: "log_level: 'WARN'",
        estimatedMinutes: 5,
      },
      {
        tool: "container_apparmor_manage",
        description: "Check AppArmor status",
        suggestedParams: "action: 'status'",
        estimatedMinutes: 1,
      },
      {
        tool: "container_namespace_check",
        description: "Verify namespace isolation",
        suggestedParams: "check_type: 'all'",
        estimatedMinutes: 1,
      },
    ],
    cloud: [
      {
        tool: "hardening_sysctl_audit",
        description: "Audit kernel parameters",
        suggestedParams: "category: 'security'",
        estimatedMinutes: 1,
      },
      {
        tool: "hardening_ssh_audit",
        description: "Harden SSH (critical for cloud instances)",
        suggestedParams: "action: 'audit'",
        estimatedMinutes: 1,
      },
      {
        tool: "firewall_iptables_list",
        description: "Verify firewall rules",
        suggestedParams: "table: 'filter'",
        estimatedMinutes: 1,
      },
      {
        tool: "network_port_audit",
        description: "Audit exposed ports",
        suggestedParams: "",
        estimatedMinutes: 2,
      },
      {
        tool: "crypto_tls_config_audit",
        description: "Audit TLS configuration",
        suggestedParams: "service: 'all'",
        estimatedMinutes: 2,
      },
    ],
  },
  incident_response: {
    server: [
      {
        tool: "logging_journald_query",
        description: "Check recent system logs for anomalies",
        suggestedParams: "priority: 'err', lines: 100",
        estimatedMinutes: 1,
      },
      {
        tool: "network_connections",
        description: "Check active network connections",
        suggestedParams: "",
        estimatedMinutes: 1,
      },
      {
        tool: "access_user_audit",
        description: "Check for unauthorized user accounts",
        suggestedParams: "check_type: 'all'",
        estimatedMinutes: 1,
      },
      {
        tool: "malware_rkhunter",
        description: "Scan for rootkits",
        suggestedParams: "",
        estimatedMinutes: 5,
      },
      {
        tool: "logging_auth_analyze",
        description: "Analyze authentication logs",
        suggestedParams: "",
        estimatedMinutes: 2,
      },
      {
        tool: "backup_system_state",
        description: "Preserve current system state for forensics",
        suggestedParams: "",
        estimatedMinutes: 5,
      },
    ],
    desktop: [
      {
        tool: "logging_journald_query",
        description: "Check system logs",
        suggestedParams: "priority: 'err'",
        estimatedMinutes: 1,
      },
      {
        tool: "malware_clamscan",
        description: "Full malware scan",
        suggestedParams: "path: '/'",
        estimatedMinutes: 30,
      },
      {
        tool: "network_connections",
        description: "Check for suspicious connections",
        suggestedParams: "",
        estimatedMinutes: 1,
      },
    ],
    container: [
      {
        tool: "container_docker_audit",
        description: "Audit container security",
        suggestedParams: "check_type: 'containers'",
        estimatedMinutes: 2,
      },
      {
        tool: "logging_journald_query",
        description: "Check container logs",
        suggestedParams: "priority: 'err'",
        estimatedMinutes: 1,
      },
    ],
    cloud: [
      {
        tool: "logging_auth_analyze",
        description: "Analyze authentication attempts",
        suggestedParams: "",
        estimatedMinutes: 2,
      },
      {
        tool: "network_connections",
        description: "Check for anomalous connections",
        suggestedParams: "",
        estimatedMinutes: 1,
      },
      {
        tool: "access_user_audit",
        description: "Audit user access",
        suggestedParams: "check_type: 'all'",
        estimatedMinutes: 1,
      },
    ],
  },
  compliance_audit: {
    server: [
      {
        tool: "compliance_lynis",
        description: "Run Lynis compliance audit",
        suggestedParams: "",
        estimatedMinutes: 5,
      },
      {
        tool: "compliance_cis_check",
        description: "Run CIS benchmark checks",
        suggestedParams: "",
        estimatedMinutes: 10,
      },
      {
        tool: "hardening_ssh_audit",
        description: "Audit SSH compliance",
        suggestedParams: "action: 'audit'",
        estimatedMinutes: 1,
      },
      {
        tool: "crypto_tls_config_audit",
        description: "Audit crypto compliance",
        suggestedParams: "service: 'all'",
        estimatedMinutes: 2,
      },
    ],
    desktop: [
      {
        tool: "compliance_lynis",
        description: "Run Lynis audit",
        suggestedParams: "",
        estimatedMinutes: 5,
      },
    ],
    container: [
      {
        tool: "container_docker_bench",
        description: "Docker CIS benchmark",
        suggestedParams: "",
        estimatedMinutes: 5,
      },
      {
        tool: "compliance_lynis",
        description: "Lynis audit of host",
        suggestedParams: "",
        estimatedMinutes: 5,
      },
    ],
    cloud: [
      {
        tool: "compliance_lynis",
        description: "Lynis audit",
        suggestedParams: "",
        estimatedMinutes: 5,
      },
      {
        tool: "compliance_cis_check",
        description: "CIS benchmark",
        suggestedParams: "",
        estimatedMinutes: 10,
      },
    ],
  },
  malware_investigation: {
    server: [
      {
        tool: "malware_clamscan",
        description: "ClamAV scan",
        suggestedParams: "path: '/', quick: true",
        estimatedMinutes: 15,
      },
      {
        tool: "malware_rkhunter",
        description: "Rootkit scan",
        suggestedParams: "",
        estimatedMinutes: 5,
      },
      {
        tool: "malware_chkrootkit",
        description: "Secondary rootkit check",
        suggestedParams: "",
        estimatedMinutes: 5,
      },
      {
        tool: "crypto_file_hash",
        description: "Hash critical binaries for verification",
        suggestedParams: "path: '/usr/bin', algorithm: 'sha256', recursive: true",
        estimatedMinutes: 10,
      },
    ],
    desktop: [
      {
        tool: "malware_clamscan",
        description: "Full ClamAV scan",
        suggestedParams: "path: '/'",
        estimatedMinutes: 30,
      },
      {
        tool: "malware_rkhunter",
        description: "Rootkit scan",
        suggestedParams: "",
        estimatedMinutes: 5,
      },
    ],
    container: [
      {
        tool: "container_docker_audit",
        description: "Audit container images",
        suggestedParams: "check_type: 'images'",
        estimatedMinutes: 2,
      },
    ],
    cloud: [
      {
        tool: "malware_clamscan",
        description: "ClamAV scan",
        suggestedParams: "path: '/'",
        estimatedMinutes: 15,
      },
      {
        tool: "malware_rkhunter",
        description: "Rootkit scan",
        suggestedParams: "",
        estimatedMinutes: 5,
      },
    ],
  },
  network_monitoring: {
    server: [
      {
        tool: "network_port_audit",
        description: "Audit listening ports",
        suggestedParams: "",
        estimatedMinutes: 1,
      },
      {
        tool: "network_connections",
        description: "Monitor active connections",
        suggestedParams: "",
        estimatedMinutes: 1,
      },
      {
        tool: "ids_snort_manage",
        description: "Check IDS status",
        suggestedParams: "action: 'status'",
        estimatedMinutes: 1,
      },
      {
        tool: "firewall_iptables_list",
        description: "Review firewall rules",
        suggestedParams: "",
        estimatedMinutes: 1,
      },
    ],
    desktop: [
      {
        tool: "network_connections",
        description: "Check connections",
        suggestedParams: "",
        estimatedMinutes: 1,
      },
      {
        tool: "firewall_ufw_status",
        description: "Check UFW",
        suggestedParams: "",
        estimatedMinutes: 1,
      },
    ],
    container: [
      {
        tool: "container_docker_audit",
        description: "Audit Docker network",
        suggestedParams: "check_type: 'network'",
        estimatedMinutes: 1,
      },
      {
        tool: "container_namespace_check",
        description: "Check network namespace isolation",
        suggestedParams: "check_type: 'network'",
        estimatedMinutes: 1,
      },
    ],
    cloud: [
      {
        tool: "network_port_audit",
        description: "Audit exposed ports",
        suggestedParams: "",
        estimatedMinutes: 1,
      },
      {
        tool: "network_connections",
        description: "Monitor connections",
        suggestedParams: "",
        estimatedMinutes: 1,
      },
    ],
  },
  full_assessment: {
    server: [
      {
        tool: "compliance_lynis",
        description: "Full Lynis audit",
        suggestedParams: "",
        estimatedMinutes: 5,
      },
      {
        tool: "hardening_sysctl_audit",
        description: "Kernel audit",
        suggestedParams: "category: 'all'",
        estimatedMinutes: 1,
      },
      {
        tool: "hardening_ssh_audit",
        description: "SSH audit",
        suggestedParams: "action: 'audit'",
        estimatedMinutes: 1,
      },
      {
        tool: "firewall_iptables_list",
        description: "Firewall audit",
        suggestedParams: "",
        estimatedMinutes: 1,
      },
      {
        tool: "access_user_audit",
        description: "User audit",
        suggestedParams: "check_type: 'all'",
        estimatedMinutes: 1,
      },
      {
        tool: "network_port_audit",
        description: "Port audit",
        suggestedParams: "",
        estimatedMinutes: 1,
      },
      {
        tool: "malware_clamscan",
        description: "Malware scan",
        suggestedParams: "path: '/', quick: true",
        estimatedMinutes: 15,
      },
      {
        tool: "crypto_tls_config_audit",
        description: "Crypto audit",
        suggestedParams: "service: 'all'",
        estimatedMinutes: 2,
      },
    ],
    desktop: [
      {
        tool: "compliance_lynis",
        description: "Lynis audit",
        suggestedParams: "",
        estimatedMinutes: 5,
      },
      {
        tool: "firewall_ufw_status",
        description: "Firewall check",
        suggestedParams: "",
        estimatedMinutes: 1,
      },
      {
        tool: "malware_clamscan",
        description: "Malware scan",
        suggestedParams: "path: '/'",
        estimatedMinutes: 30,
      },
    ],
    container: [
      {
        tool: "container_docker_audit",
        description: "Docker audit",
        suggestedParams: "check_type: 'all'",
        estimatedMinutes: 3,
      },
      {
        tool: "container_docker_bench",
        description: "CIS benchmark",
        suggestedParams: "",
        estimatedMinutes: 5,
      },
      {
        tool: "container_apparmor_manage",
        description: "AppArmor status",
        suggestedParams: "action: 'status'",
        estimatedMinutes: 1,
      },
      {
        tool: "compliance_lynis",
        description: "Host Lynis audit",
        suggestedParams: "",
        estimatedMinutes: 5,
      },
    ],
    cloud: [
      {
        tool: "compliance_lynis",
        description: "Lynis audit",
        suggestedParams: "",
        estimatedMinutes: 5,
      },
      {
        tool: "hardening_ssh_audit",
        description: "SSH audit",
        suggestedParams: "action: 'audit'",
        estimatedMinutes: 1,
      },
      {
        tool: "firewall_iptables_list",
        description: "Firewall review",
        suggestedParams: "",
        estimatedMinutes: 1,
      },
      {
        tool: "crypto_tls_config_audit",
        description: "Crypto audit",
        suggestedParams: "service: 'all'",
        estimatedMinutes: 2,
      },
    ],
  },
};

// ── Registration entry point ───────────────────────────────────────────────

export function registerMetaTools(server: McpServer): void {
  // ── 1. defense_check_tools ───────────────────────────────────────────────

  server.tool(
    "defense_check_tools",
    "Check availability and versions of all defensive security tools, optionally install missing ones",
    {
      category: z
        .string()
        .optional()
        .describe(
          "Filter by category: hardening, firewall, monitoring, assessment, network, access, encryption, container"
        ),
      install_missing: z
        .boolean()
        .optional()
        .default(false)
        .describe("Attempt to install missing tools"),
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview installations without executing (defaults to KALI_DEFENSE_DRY_RUN env var)"),
    },
    async ({ category, install_missing, dry_run }) => {
      try {
        const sections: string[] = [];
        sections.push("🔧 Defensive Tool Availability Check");
        sections.push("=".repeat(50));

        const validCategories = [
          "hardening",
          "firewall",
          "monitoring",
          "assessment",
          "network",
          "access",
          "encryption",
          "container",
          "malware",
          "forensics",
        ];

        const filterCategory =
          category && validCategories.includes(category)
            ? (category as ToolCategory)
            : undefined;

        if (category && !filterCategory) {
          sections.push(
            `\n⚠️ Unknown category '${category}'. Valid: ${validCategories.join(", ")}`
          );
          sections.push("Showing all categories.\n");
        }

        const results = await checkAllTools(filterCategory);

        // Group by category
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
              const version = t.version
                ? ` (${t.version.substring(0, 60)})`
                : "";
              sections.push(
                `  ✅ ${t.tool.name}${version}`
              );
              if (t.path) sections.push(`     Path: ${t.path}`);
            } else {
              missing++;
              const req = t.tool.required ? " [REQUIRED]" : " [optional]";
              sections.push(
                `  ❌ ${t.tool.name}${req}`
              );
            }
          }
        }

        sections.push(`\n── Summary ──`);
        sections.push(
          `  Installed: ${installed} | Missing: ${missing} | Total: ${installed + missing}`
        );

        // Install missing tools if requested
        if (install_missing && missing > 0) {
          sections.push("\n── Installation ──");

          if (dry_run ?? getConfig().dryRun) {
            const installResults = await installMissing(
              filterCategory,
              true
            );
            for (const r of installResults) {
              sections.push(`  ${r.message}`);
            }
          } else {
            sections.push("  Installing missing tools...\n");
            const installResults = await installMissing(
              filterCategory,
              false
            );
            for (const r of installResults) {
              const icon = r.success ? "✅" : "❌";
              sections.push(`  ${icon} ${r.message}`);
            }

            logChange(
              createChangeEntry({
                tool: "defense_check_tools",
                action: "install_missing",
                target: filterCategory || "all",
                after: `Attempted to install ${installResults.length} tools`,
                dryRun: false,
                success: installResults.every((r) => r.success),
              })
            );
          }
        }

        return { content: [createTextContent(sections.join("\n"))] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 2. defense_workflow (merged: suggest + run) ─────────────────────────

  server.tool(
    "defense_workflow",
    "Defense workflows: suggest a workflow based on objectives, or run a predefined multi-step workflow.",
    {
      action: z.enum(["suggest", "run"]).describe("Action: suggest=recommend workflow, run=execute predefined workflow"),
      // suggest params
      objective: z.enum(["initial_hardening", "incident_response", "compliance_audit", "malware_investigation", "network_monitoring", "full_assessment"]).optional().describe("Security objective (suggest action)"),
      system_type: z.enum(["server", "desktop", "container", "cloud"]).optional().default("server").describe("System type (suggest action)"),
      // run params
      workflow: z.enum(["quick_harden", "full_audit", "incident_prep", "backup_all", "network_lockdown"]).optional().describe("Workflow to execute (run action)"),
      // shared
      dry_run: z.boolean().optional().describe("Preview without executing (run action)"),
    },
    async (params) => {
      const { action } = params;

      switch (action) {
        case "suggest": {
          const { objective, system_type } = params;
          try {
            if (!objective) return { content: [createErrorContent("objective is required for suggest action")], isError: true };

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

        case "run": {
          const { workflow, dry_run } = params;
          try {
            if (!workflow) return { content: [createErrorContent("workflow is required for run action")], isError: true };

            const sections: string[] = [];
            sections.push(`🚀 Workflow: ${workflow.replace(/_/g, " ").toUpperCase()}`);
            sections.push("=".repeat(50));

            const steps = WORKFLOWS[workflow];
            if (!steps || steps.length === 0) return { content: [createErrorContent(`Unknown workflow: ${workflow}`)], isError: true };

            const totalEstimate = steps.reduce((sum, s) => sum + s.estimatedSeconds, 0);
            sections.push(`Steps: ${steps.length} | Estimated time: ~${Math.ceil(totalEstimate / 60)} min`);

            if (dry_run ?? getConfig().dryRun) {
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
            } else {
              sections.push("\nExecuting workflow...\n");
              let successCount = 0, failCount = 0;

              for (let i = 0; i < steps.length; i++) {
                const step = steps[i];
                sections.push(`── Step ${i + 1}/${steps.length}: ${step.description} ──`);
                const startTime = Date.now();
                const result = await executeCommand({ command: step.command, args: step.args, toolName: `defense_workflow_${workflow}`, timeout: Math.max(step.estimatedSeconds * 3 * 1000, 30000) });
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

                logChange(createChangeEntry({ tool: "defense_workflow", action: `${workflow}_step_${i + 1}`, target: step.description, after: `exit=${result.exitCode} duration=${duration}s`, dryRun: false, success: result.exitCode === 0, error: result.exitCode !== 0 ? result.stderr.substring(0, 200) : undefined }));
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

        default:
          return { content: [createErrorContent(`Unknown action: ${action}`)], isError: true };
      }
    }
  );

  // ── 3. defense_change_history (kept as-is) ──────────────────────────────

  server.tool(
    "defense_change_history",
    "View the audit trail of all defensive changes made by this server",
    {
      limit: z
        .number()
        .optional()
        .default(20)
        .describe("Maximum number of entries to return (default: 20)"),
      tool: z
        .string()
        .optional()
        .describe("Filter by tool name (e.g. 'firewall_ufw_rule')"),
      since: z
        .string()
        .optional()
        .describe("Filter by date, e.g. 'today', '2024-01-01'"),
    },
    async ({ limit, tool, since }) => {
      try {
        const sections: string[] = [];
        sections.push("📜 Defense Change History");
        sections.push("=".repeat(50));

        let entries = getChangelog(limit * 5); // Get more than needed to allow filtering

        // Filter by tool name
        if (tool) {
          entries = entries.filter((e) =>
            e.tool.toLowerCase().includes(tool.toLowerCase())
          );
        }

        // Filter by date
        if (since) {
          let sinceDate: Date;
          if (since.toLowerCase() === "today") {
            sinceDate = new Date();
            sinceDate.setHours(0, 0, 0, 0);
          } else {
            sinceDate = new Date(since);
          }

          if (!isNaN(sinceDate.getTime())) {
            entries = entries.filter(
              (e) => new Date(e.timestamp) >= sinceDate
            );
          }
        }

        // Apply limit after filtering
        entries = entries.slice(0, limit);

        if (entries.length === 0) {
          sections.push("\nNo changes recorded");
          if (tool) sections.push(`  (filtered by tool: ${tool})`);
          if (since) sections.push(`  (filtered by since: ${since})`);
          return { content: [createTextContent(sections.join("\n"))] };
        }

        sections.push(
          `\nShowing ${entries.length} entries (newest first):`
        );
        if (tool) sections.push(`  Filter: tool contains '${tool}'`);
        if (since) sections.push(`  Filter: since '${since}'`);

        for (const entry of entries) {
          sections.push("\n  " + "─".repeat(40));
          sections.push(`  ID: ${entry.id}`);
          sections.push(`  Time: ${entry.timestamp}`);
          sections.push(`  Tool: ${entry.tool}`);
          sections.push(`  Action: ${entry.action}`);
          sections.push(`  Target: ${entry.target}`);
          sections.push(
            `  Dry Run: ${entry.dryRun ? "Yes" : "No"}`
          );
          sections.push(
            `  Success: ${entry.success ? "✅" : "❌"}`
          );
          if (entry.error) sections.push(`  Error: ${entry.error}`);
          if (entry.before)
            sections.push(
              `  Before: ${entry.before.substring(0, 100)}`
            );
          if (entry.after)
            sections.push(
              `  After: ${entry.after.substring(0, 100)}`
            );
          if (entry.backupPath)
            sections.push(`  Backup: ${entry.backupPath}`);
          if (entry.rollbackCommand)
            sections.push(`  Rollback: ${entry.rollbackCommand}`);
        }

        return { content: [createTextContent(sections.join("\n"))] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 4. security_posture (merged: score + trend + dashboard) ─────────────

  server.tool(
    "security_posture",
    "Security posture: calculate security score, view historical trends, or generate a posture dashboard.",
    {
      action: z.enum(["score", "trend", "dashboard"]).describe("Action: score=calculate score, trend=view history, dashboard=generate dashboard"),
      // trend params
      limit: z.number().optional().default(10).describe("Number of historical entries (trend action)"),
      // shared
      dryRun: z.boolean().optional().default(false).describe("Preview only"),
    },
    async (params) => {
      const { action } = params;

      switch (action) {
      case "score": {
        const { dryRun } = params;
      try {
        const domains: DomainScore[] = [];

        // ── Kernel hardening (weight: 20) ──
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
        const kernelResults = await Promise.all(
          kernelChecks.map(async (c) => {
            const result = await checkSysctl(c.key, c.expected);
            return {
              name: c.name,
              passed: result.passed,
              assessable: result.assessable,
              detail: result.assessable ? c.key : `${c.key} (unable to assess)`,
            };
          })
        );
        const assessableKernelCount = kernelResults.filter((r) => r.assessable).length;
        const kernelPassed = kernelResults.filter((r) => r.passed).length;
        const kernelScore = assessableKernelCount > 0
          ? Math.round((kernelPassed / assessableKernelCount) * 100)
          : -1;
        domains.push({
          domain: "kernel-hardening",
          score: kernelScore,
          maxScore: 100,
          checks: kernelResults.map((r) => ({ name: r.name, passed: r.passed, detail: r.detail })),
        });

        // ── Firewall (weight: 15) ──
        const fwChecks: { name: string; passed: boolean; detail: string }[] = [];
        const iptResult = await executeCommand({ command: "iptables", args: ["-L", "-n"], timeout: 10000 });
        const hasRules = iptResult.exitCode === 0 && iptResult.stdout.split("\n").length > 8;
        fwChecks.push({ name: "iptables rules present", passed: hasRules, detail: `${iptResult.stdout.split("\n").length} lines` });

        const ufwResult = await executeCommand({ command: "ufw", args: ["status"], timeout: 5000 });
        const ufwActive = ufwResult.exitCode === 0 && ufwResult.stdout.includes("active");
        fwChecks.push({ name: "UFW active", passed: ufwActive, detail: ufwResult.stdout.slice(0, 100) });

        const fwPassed = fwChecks.filter((c) => c.passed).length;
        domains.push({
          domain: "firewall",
          score: Math.round((fwPassed / fwChecks.length) * 100),
          maxScore: 100,
          checks: fwChecks,
        });

        // ── Services (weight: 15) ──
        const dangerousServices = ["telnet.socket", "rsh.socket", "rlogin.socket", "tftp.socket", "xinetd.service"];
        const svcChecks: { name: string; passed: boolean; detail: string }[] = [];
        for (const svc of dangerousServices) {
          const r = await executeCommand({ command: "systemctl", args: ["is-active", svc], timeout: 5000 });
          const inactive = r.exitCode !== 0 || r.stdout.trim() !== "active";
          svcChecks.push({ name: `${svc} disabled`, passed: inactive, detail: r.stdout.trim() });
        }
        const svcPassed = svcChecks.filter((c) => c.passed).length;
        domains.push({
          domain: "services",
          score: Math.round((svcPassed / svcChecks.length) * 100),
          maxScore: 100,
          checks: svcChecks,
        });

        // ── Users (weight: 15) ──
        const userChecks: { name: string; passed: boolean; detail: string }[] = [];
        const rootLogin = await executeCommand({ command: "passwd", args: ["-S", "root"], timeout: 5000 });
        const rootLocked = rootLogin.stdout.includes(" L ") || rootLogin.stdout.includes(" LK ");
        userChecks.push({ name: "Root account locked", passed: rootLocked, detail: rootLogin.stdout.trim().slice(0, 100) });

        const noPasswd = await executeCommand({ command: "awk", args: ["-F:", '($2 == "" ) { print $1 }', "/etc/shadow"], timeout: 5000 });
        const noEmptyPasswd = noPasswd.stdout.trim().length === 0;
        userChecks.push({ name: "No empty passwords", passed: noEmptyPasswd, detail: noPasswd.stdout.trim() || "none" });

        const uidZero = await executeCommand({ command: "awk", args: ["-F:", '($3 == 0) { print $1 }', "/etc/passwd"], timeout: 5000 });
        const onlyRoot = uidZero.stdout.trim() === "root";
        userChecks.push({ name: "Only root has UID 0", passed: onlyRoot, detail: uidZero.stdout.trim() });

        const userPassed = userChecks.filter((c) => c.passed).length;
        domains.push({
          domain: "users",
          score: Math.round((userPassed / userChecks.length) * 100),
          maxScore: 100,
          checks: userChecks,
        });

        // ── Filesystem (weight: 15) ──
        const fsChecks: { name: string; passed: boolean; detail: string }[] = [];
        const criticalFiles: [string, string][] = [
          ["/etc/passwd", "644"],
          ["/etc/shadow", "640"],
          ["/etc/ssh/sshd_config", "600"],
        ];
        for (const [fp, expected] of criticalFiles) {
          const r = await executeCommand({ command: "stat", args: ["-c", "%a", fp], timeout: 5000 });
          const actual = r.stdout.trim();
          const ok = r.exitCode === 0 && parseInt(actual, 8) <= parseInt(expected, 8);
          fsChecks.push({ name: `${fp} permissions`, passed: ok, detail: `${actual} (expected \u2264${expected})` });
        }
        const fsPassed = fsChecks.filter((c) => c.passed).length;
        domains.push({
          domain: "filesystem",
          score: Math.round((fsPassed / fsChecks.length) * 100),
          maxScore: 100,
          checks: fsChecks,
        });

        // ── Overall score ──
        const weights: Record<string, number> = {
          "kernel-hardening": 25,
          "firewall": 20,
          "services": 15,
          "users": 20,
          "filesystem": 20,
        };

        let weightedSum = 0;
        let totalWeight = 0;
        for (const d of domains) {
          if (d.score < 0) continue;
          const w = weights[d.domain] ?? 10;
          weightedSum += d.score * w;
          totalWeight += w;
        }
        const overallScore = totalWeight > 0 ? Math.round(weightedSum / totalWeight) : 0;

        // Save score history
        ensurePostureDir();
        const historyPath = join(POSTURE_DIR, "history.json");
        let history: { timestamp: string; score: number; domains: Record<string, number> }[] = [];
        try {
          if (existsSync(historyPath)) {
            history = JSON.parse(readFileSync(historyPath, "utf-8"));
          }
        } catch { /* start fresh */ }

        const domainScores: Record<string, number> = {};
        for (const d of domains) domainScores[d.domain] = d.score;

        history.push({ timestamp: new Date().toISOString(), score: overallScore, domains: domainScores });
        if (history.length > 1000) history = history.slice(-1000);
        writeFileSync(historyPath, JSON.stringify(history, null, 2), "utf-8");

        return {
          content: [formatToolOutput({
            overallScore,
            rating: overallScore >= 80 ? "GOOD" : overallScore >= 60 ? "FAIR" : overallScore >= 40 ? "POOR" : "CRITICAL",
            domains,
          })],
        };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(`Security score calculation failed: ${msg}`)], isError: true };
      }
      }

      case "trend": {
        const { limit } = params;
      try {
        ensurePostureDir();
        const historyPath = join(POSTURE_DIR, "history.json");

        if (!existsSync(historyPath)) {
          return { content: [formatToolOutput({ message: "No posture history found. Run security_posture action=score first." })] };
        }

        const history = JSON.parse(readFileSync(historyPath, "utf-8"));
        const recent = history.slice(-limit);

        return {
          content: [formatToolOutput({
            entries: recent.length,
            trend: recent,
            latestScore: recent.length > 0 ? recent[recent.length - 1].score : null,
          })],
        };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(`Posture trend failed: ${msg}`)], isError: true };
      }
      }

      case "dashboard": {
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

        if (!latestEntry) {
          return { content: [formatToolOutput({ message: "No posture data available. Run security_posture action=score first." })] };
        }

        const recommendations: string[] = [];
        for (const [domain, score] of Object.entries(latestEntry.domains)) {
          if (score < 0) recommendations.push(`INFO: ${domain} could not be assessed`);
          else if (score < 50) recommendations.push(`CRITICAL: ${domain} score is ${score}/100`);
          else if (score < 80) recommendations.push(`MODERATE: ${domain} score is ${score}/100`);
        }
        if (recommendations.length === 0) recommendations.push("All domains scoring above 80.");

        const displayDomainScores: Record<string, number | string> = {};
        for (const [domain, score] of Object.entries(latestEntry.domains)) displayDomainScores[domain] = score < 0 ? "N/A" : score;

        let weightedSum = 0;
        let totalWeight = 0;
        const weights: Record<string, number> = { "kernel-hardening": 25, "firewall": 20, "services": 15, "users": 20, "filesystem": 20 };
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
              nextSteps: ["Run security_posture action=score for detailed breakdown", "Address CRITICAL domains first", "Re-run periodically"],
            },
          })],
        };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(`Dashboard generation failed: ${msg}`)], isError: true };
      }
      }

      default:
        return { content: [createErrorContent(`Unknown action: ${action}`)], isError: true };
      }
    }
  );

  // ── 5. scheduled_audit (merged: setup + list + remove + history) ────────

  server.tool(
    "scheduled_audit",
    "Scheduled security audits: create, list, remove, or read audit history.",
    {
      action: z.enum(["create", "list", "remove", "history"]).describe("Action: create, list, remove, history"),
      name: z.string().optional().describe("Audit job name (create/remove/history)"),
      command: z.string().optional().describe("Command to run (create action)"),
      schedule: z.string().optional().describe("Schedule cron format or systemd calendar (create action)"),
      useSystemd: z.boolean().optional().default(true).describe("Use systemd timer vs cron (create action)"),
      lines: z.number().optional().default(100).describe("Number of recent lines (history action)"),
      dryRun: z.boolean().optional().default(true).describe("Preview only"),
    },
    async (params) => {
      const { action } = params;

      switch (action) {
        case "create": {
          const { name, command: auditCommand, schedule, useSystemd, dryRun } = params;
          if (!name) return { content: [createErrorContent("name is required for create action")], isError: true };
          if (!auditCommand) return { content: [createErrorContent("command is required for create action")], isError: true };
          if (!schedule) return { content: [createErrorContent("schedule is required for create action")], isError: true };
          try {
            const safety = await SafeguardRegistry.getInstance().checkSafety("setup_scheduled_audit", { name });
            ensureAuditLogDir();
            const logFile = join(AUDIT_LOG_DIR, `${name}.log`);

            if (useSystemd) {
              const serviceContent = `[Unit]\nDescription=Kali Defense Scheduled Audit: ${name}\n\n[Service]\nType=oneshot\nExecStart=/bin/bash -c '${auditCommand} >> ${logFile} 2>&1'\n`;
              const timerContent = `[Unit]\nDescription=Timer for ${name} audit\n\n[Timer]\nOnCalendar=${schedule}\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n`;
              const servicePath = `/etc/systemd/system/kali-audit-${name}.service`;
              const timerPath = `/etc/systemd/system/kali-audit-${name}.timer`;

              if (dryRun) {
                return { content: [formatToolOutput({ dryRun: true, type: "systemd", servicePath, timerPath, serviceContent, timerContent, warnings: safety.warnings, enableCommand: `systemctl enable --now kali-audit-${name}.timer` })] };
              }

              writeFileSync(servicePath, serviceContent, "utf-8");
              writeFileSync(timerPath, timerContent, "utf-8");
              await executeCommand({ command: "systemctl", args: ["daemon-reload"], timeout: 10000 });
              const enable = await executeCommand({ command: "systemctl", args: ["enable", "--now", `kali-audit-${name}.timer`], timeout: 10000 });

              logChange(createChangeEntry({ tool: "scheduled_audit", action: `Create systemd timer for ${name}`, target: timerPath, dryRun: false, success: enable.exitCode === 0, rollbackCommand: `systemctl disable --now kali-audit-${name}.timer && rm ${servicePath} ${timerPath}` }));
              return { content: [formatToolOutput({ success: enable.exitCode === 0, type: "systemd", name, servicePath, timerPath, enabled: enable.exitCode === 0 })] };
            }

            // Cron approach
            const cronLine = `${schedule} ${auditCommand} >> ${logFile} 2>&1 # kali-audit-${name}`;
            if (dryRun) {
              return { content: [formatToolOutput({ dryRun: true, type: "cron", cronLine, warnings: safety.warnings })] };
            }

            const currentCron = await executeCommand({ command: "crontab", args: ["-l"], timeout: 5000 });
            const existing = currentCron.exitCode === 0 ? currentCron.stdout : "";
            if (existing.includes(`kali-audit-${name}`)) {
              return { content: [createErrorContent(`Cron job 'kali-audit-${name}' already exists. Remove it first.`)], isError: true };
            }

            const newCron = existing.trimEnd() + "\n" + cronLine + "\n";
            const install = await executeCommand({ command: "crontab", args: ["-"], stdin: newCron, timeout: 5000 });
            logChange(createChangeEntry({ tool: "scheduled_audit", action: `Create cron job for ${name}`, target: "crontab", dryRun: false, success: install.exitCode === 0 }));
            return { content: [formatToolOutput({ success: install.exitCode === 0, type: "cron", name, cronLine })] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`Scheduled audit setup failed: ${msg}`)], isError: true };
          }
        }

        case "list": {
          try {
            const audits: { name: string; type: string; schedule: string; status: string }[] = [];

            const timers = await executeCommand({ command: "systemctl", args: ["list-timers", "--no-pager", "--plain"], timeout: 10000 });
            if (timers.exitCode === 0) {
              for (const line of timers.stdout.split("\n")) {
                if (line.includes("kali-audit-")) {
                  const match = line.match(/kali-audit-(\S+)/);
                  if (match) audits.push({ name: match[1].replace(".timer", ""), type: "systemd", schedule: line.trim(), status: "active" });
                }
              }
            }

            const cron = await executeCommand({ command: "crontab", args: ["-l"], timeout: 5000 });
            if (cron.exitCode === 0) {
              for (const line of cron.stdout.split("\n")) {
                if (line.includes("kali-audit-")) {
                  const match = line.match(/# kali-audit-(\S+)/);
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

        case "remove": {
          const { name, dryRun } = params;
          try {
            if (!name) return { content: [createErrorContent("name is required for remove action")], isError: true };
            const actions: { action: string; success: boolean }[] = [];

            const timerPath = `/etc/systemd/system/kali-audit-${name}.timer`;
            const servicePath = `/etc/systemd/system/kali-audit-${name}.service`;
            const hasTimer = existsSync(timerPath);

            const cron = await executeCommand({ command: "crontab", args: ["-l"], timeout: 5000 });
            const hasCron = cron.exitCode === 0 && cron.stdout.includes(`kali-audit-${name}`);

            if (!hasTimer && !hasCron) {
              return { content: [createErrorContent(`No scheduled audit found with name: ${name}`)], isError: true };
            }

            if (dryRun) {
              return { content: [formatToolOutput({ dryRun: true, name, hasSystemdTimer: hasTimer, hasCronJob: hasCron, actions: [hasTimer ? `systemctl disable --now kali-audit-${name}.timer && rm ${timerPath} ${servicePath}` : null, hasCron ? `Remove cron line containing kali-audit-${name}` : null].filter(Boolean) })] };
            }

            if (hasTimer) {
              await executeCommand({ command: "systemctl", args: ["disable", "--now", `kali-audit-${name}.timer`], timeout: 10000 });
              await executeCommand({ command: "rm", args: ["-f", timerPath, servicePath], timeout: 5000 });
              await executeCommand({ command: "systemctl", args: ["daemon-reload"], timeout: 10000 });
              actions.push({ action: "Removed systemd timer", success: true });
            }

            if (hasCron) {
              const lines = cron.stdout.split("\n").filter((l) => !l.includes(`kali-audit-${name}`));
              await executeCommand({ command: "crontab", args: ["-"], stdin: lines.join("\n") + "\n", timeout: 5000 });
              actions.push({ action: "Removed cron job", success: true });
            }

            logChange(createChangeEntry({ tool: "scheduled_audit", action: `Remove scheduled audit ${name}`, target: name, dryRun: false, success: true }));
            return { content: [formatToolOutput({ name, actions })] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`Remove audit failed: ${msg}`)], isError: true };
          }
        }

        case "history": {
          const { name, lines } = params;
          try {
            if (!name) return { content: [createErrorContent("name is required for history action")], isError: true };
            ensureAuditLogDir();
            const logFile = join(AUDIT_LOG_DIR, `${name}.log`);
            if (!existsSync(logFile)) {
              return { content: [formatToolOutput({ name, message: `No audit log found at ${logFile}` })] };
            }

            const result = await executeCommand({ command: "tail", args: ["-n", String(lines), logFile], timeout: 10000 });
            return { content: [formatToolOutput({ name, logFile, lines: result.stdout.trim().split("\n"), totalLines: result.stdout.trim().split("\n").length })] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`Audit history failed: ${msg}`)], isError: true };
          }
        }

        default:
          return { content: [createErrorContent(`Unknown action: ${action}`)], isError: true };
      }
    }
  );
}
