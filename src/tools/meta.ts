/**
 * Meta/utility tools for Kali Defense MCP Server.
 *
 * Registers 5 tools: defense_check_tools, defense_suggest_workflow,
 * defense_security_posture, defense_change_history, defense_run_workflow.
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

  // ── 2. defense_suggest_workflow ──────────────────────────────────────────

  server.tool(
    "defense_suggest_workflow",
    "Suggest a defensive workflow with ordered tool recommendations based on your security objective and system type",
    {
      objective: z
        .enum([
          "initial_hardening",
          "incident_response",
          "compliance_audit",
          "malware_investigation",
          "network_monitoring",
          "full_assessment",
        ])
        .describe("Security objective for the workflow"),
      system_type: z
        .enum(["server", "desktop", "container", "cloud"])
        .optional()
        .default("server")
        .describe("Type of system being secured (default: server)"),
    },
    async ({ objective, system_type }) => {
      try {
        const sections: string[] = [];
        sections.push(
          `📋 Recommended Workflow: ${objective.replace(/_/g, " ").toUpperCase()}`
        );
        sections.push(`System type: ${system_type}`);
        sections.push("=".repeat(50));

        const suggestions =
          WORKFLOW_SUGGESTIONS[objective]?.[system_type] || [];

        if (suggestions.length === 0) {
          sections.push(
            "\nNo specific workflow available for this combination."
          );
          sections.push(
            "Consider using 'full_assessment' objective for a comprehensive approach."
          );
          return { content: [createTextContent(sections.join("\n"))] };
        }

        let totalMinutes = 0;

        for (let i = 0; i < suggestions.length; i++) {
          const step = suggestions[i];
          totalMinutes += step.estimatedMinutes;

          sections.push(
            `\n  Step ${i + 1}: ${step.description}`
          );
          sections.push(`    Tool: ${step.tool}`);
          if (step.suggestedParams) {
            sections.push(
              `    Suggested params: { ${step.suggestedParams} }`
            );
          }
          sections.push(
            `    Estimated time: ~${step.estimatedMinutes} min`
          );
        }

        sections.push(`\n── Workflow Summary ──`);
        sections.push(`  Total steps: ${suggestions.length}`);
        sections.push(
          `  Estimated total time: ~${totalMinutes} minutes`
        );
        sections.push(
          "\nTip: Execute each tool in order. Review results from each step before proceeding to the next."
        );

        return { content: [createTextContent(sections.join("\n"))] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 3. defense_security_posture ─────────────────────────────────────────

  server.tool(
    "defense_security_posture",
    "Get an overall security posture assessment with a scored breakdown across key security areas",
    {
      quick: z
        .boolean()
        .optional()
        .default(true)
        .describe("Quick check (true) vs full assessment (false). Default: true"),
    },
    async ({ quick }) => {
      try {
        const sections: string[] = [];
        sections.push("🛡️ Security Posture Assessment");
        sections.push("=".repeat(50));

        const checks: Array<{
          area: string;
          status: "good" | "warn" | "critical" | "unknown";
          details: string;
        }> = [];

        // 1. Firewall status
        const fwResult = await executeCommand({
          command: "sudo",
          args: ["iptables", "-L", "-n"],
          toolName: "defense_security_posture",
          timeout: 10000,
        });

        if (fwResult.exitCode === 0) {
          const rules = fwResult.stdout
            .split("\n")
            .filter(
              (l) =>
                l.trim() &&
                !l.startsWith("Chain") &&
                !l.startsWith("target")
            );
          if (rules.length > 0) {
            checks.push({
              area: "Firewall",
              status: "good",
              details: `Active with ${rules.length} rules`,
            });
          } else {
            checks.push({
              area: "Firewall",
              status: "warn",
              details: "No firewall rules configured",
            });
          }
        } else {
          // Try UFW
          const ufwResult = await executeCommand({
            command: "sudo",
            args: ["ufw", "status"],
            toolName: "defense_security_posture",
            timeout: 10000,
          });
          if (
            ufwResult.exitCode === 0 &&
            ufwResult.stdout.includes("active")
          ) {
            checks.push({
              area: "Firewall",
              status: "good",
              details: "UFW is active",
            });
          } else {
            checks.push({
              area: "Firewall",
              status: "critical",
              details: "No active firewall detected",
            });
          }
        }

        // 2. SSH configuration
        const sshResult = await executeCommand({
          command: "cat",
          args: ["/etc/ssh/sshd_config"],
          toolName: "defense_security_posture",
          timeout: 5000,
        });

        if (sshResult.exitCode === 0) {
          const sshConfig = sshResult.stdout;
          const issues: string[] = [];

          if (
            sshConfig.match(/PermitRootLogin\s+yes/) ||
            (!sshConfig.match(/PermitRootLogin/) &&
              !sshConfig.match(/PermitRootLogin\s+no/))
          ) {
            issues.push("root login enabled");
          }
          if (
            sshConfig.match(/PasswordAuthentication\s+yes/) ||
            !sshConfig.match(/PasswordAuthentication/)
          ) {
            issues.push("password auth enabled");
          }

          if (issues.length === 0) {
            checks.push({
              area: "SSH Config",
              status: "good",
              details: "Root login disabled, key-based auth",
            });
          } else {
            checks.push({
              area: "SSH Config",
              status: "warn",
              details: `Issues: ${issues.join(", ")}`,
            });
          }
        } else {
          checks.push({
            area: "SSH Config",
            status: "unknown",
            details: "Cannot read SSH configuration",
          });
        }

        // 3. Running services
        const svcResult = await executeCommand({
          command: "systemctl",
          args: [
            "list-units",
            "--type=service",
            "--state=running",
            "--no-pager",
            "--no-legend",
          ],
          toolName: "defense_security_posture",
          timeout: 10000,
        });

        if (svcResult.exitCode === 0) {
          const svcCount = svcResult.stdout
            .trim()
            .split("\n")
            .filter((l) => l.trim()).length;
          checks.push({
            area: "Running Services",
            status: svcCount > 50 ? "warn" : "good",
            details: `${svcCount} services running${svcCount > 50 ? " (consider reducing)" : ""}`,
          });
        }

        // 4. Listening ports
        const portResult = await executeCommand({
          command: "ss",
          args: ["-tulnp"],
          toolName: "defense_security_posture",
          timeout: 10000,
        });

        if (portResult.exitCode === 0) {
          const portLines = portResult.stdout
            .trim()
            .split("\n")
            .filter((l) => l.trim() && !l.startsWith("Netid"));
          const externalPorts = portLines.filter(
            (l) => !l.includes("127.0.0.1") && !l.includes("::1")
          );

          checks.push({
            area: "Listening Ports",
            status: externalPorts.length > 10 ? "warn" : "good",
            details: `${portLines.length} total, ${externalPorts.length} external`,
          });
        }

        // 5. Failed login attempts (last 24h)
        const failedResult = await executeCommand({
          command: "sudo",
          args: [
            "journalctl",
            "-u",
            "ssh",
            "--since",
            "24 hours ago",
            "--no-pager",
            "-q",
          ],
          toolName: "defense_security_posture",
          timeout: 15000,
        });

        if (failedResult.exitCode === 0) {
          const failedCount = (
            failedResult.stdout.match(/Failed password/g) || []
          ).length;
          checks.push({
            area: "Failed Logins (24h)",
            status:
              failedCount > 100
                ? "critical"
                : failedCount > 10
                  ? "warn"
                  : "good",
            details: `${failedCount} failed login attempts`,
          });
        }

        // 6. System updates
        const updateResult = await executeCommand({
          command: "apt",
          args: ["list", "--upgradable"],
          toolName: "defense_security_posture",
          timeout: 30000,
        });

        if (updateResult.exitCode === 0) {
          const upgradable = updateResult.stdout
            .trim()
            .split("\n")
            .filter((l) => l.includes("upgradable")).length;
          checks.push({
            area: "System Updates",
            status:
              upgradable > 20
                ? "warn"
                : upgradable > 0
                  ? "good"
                  : "good",
            details:
              upgradable > 0
                ? `${upgradable} packages upgradable`
                : "System up to date",
          });
        }

        // 7. UID 0 accounts
        const passwdResult = await executeCommand({
          command: "awk",
          args: ["-F:", "$3 == 0 {print $1}", "/etc/passwd"],
          toolName: "defense_security_posture",
          timeout: 5000,
        });

        if (passwdResult.exitCode === 0) {
          const uid0Users = passwdResult.stdout
            .trim()
            .split("\n")
            .filter((l) => l.trim());
          checks.push({
            area: "UID 0 Accounts",
            status: uid0Users.length > 1 ? "critical" : "good",
            details:
              uid0Users.length > 1
                ? `Multiple UID 0 accounts: ${uid0Users.join(", ")}`
                : `Only root has UID 0`,
          });
        }

        // 8. World-writable files (quick check)
        if (!quick) {
          const wwResult = await executeCommand({
            command: "find",
            args: [
              "/etc",
              "-type",
              "f",
              "-perm",
              "-002",
              "-ls",
            ],
            toolName: "defense_security_posture",
            timeout: 30000,
          });

          if (wwResult.exitCode === 0) {
            const wwCount = wwResult.stdout
              .trim()
              .split("\n")
              .filter((l) => l.trim()).length;
            checks.push({
              area: "World-Writable Files (/etc)",
              status: wwCount > 0 ? "warn" : "good",
              details:
                wwCount > 0
                  ? `${wwCount} world-writable files found`
                  : "No world-writable files in /etc",
            });
          }
        }

        // Calculate score
        let score = 0;
        const maxScore = checks.length * 10;

        for (const c of checks) {
          if (c.status === "good") score += 10;
          else if (c.status === "warn") score += 5;
          else if (c.status === "unknown") score += 3;
          // critical = 0
        }

        const percentage = Math.round((score / maxScore) * 100);

        // Display results
        sections.push("\n── Security Checks ──\n");

        const statusIcon: Record<string, string> = {
          good: "✅",
          warn: "⚠️",
          critical: "⛔",
          unknown: "❓",
        };

        for (const c of checks) {
          sections.push(
            `  ${statusIcon[c.status]} ${c.area}: ${c.details}`
          );
        }

        sections.push("\n── Overall Score ──");
        const grade =
          percentage >= 80
            ? "A"
            : percentage >= 60
              ? "B"
              : percentage >= 40
                ? "C"
                : percentage >= 20
                  ? "D"
                  : "F";

        sections.push(
          `  Score: ${score}/${maxScore} (${percentage}%) - Grade: ${grade}`
        );

        if (percentage >= 80) {
          sections.push("  🟢 Good security posture");
        } else if (percentage >= 60) {
          sections.push("  🟡 Moderate security posture - improvements recommended");
        } else if (percentage >= 40) {
          sections.push("  🟠 Weak security posture - action needed");
        } else {
          sections.push("  🔴 Critical security posture - immediate action required");
        }

        return { content: [createTextContent(sections.join("\n"))] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 4. defense_change_history ────────────────────────────────────────────

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

  // ── 5. defense_run_workflow ──────────────────────────────────────────────

  server.tool(
    "defense_run_workflow",
    "Execute a predefined multi-step defensive workflow (quick_harden, full_audit, incident_prep, backup_all, network_lockdown)",
    {
      workflow: z
        .enum([
          "quick_harden",
          "full_audit",
          "incident_prep",
          "backup_all",
          "network_lockdown",
        ])
        .describe("Workflow to execute"),
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview workflow without executing (defaults to KALI_DEFENSE_DRY_RUN env var)"),
    },
    async ({ workflow, dry_run }) => {
      try {
        const sections: string[] = [];
        sections.push(
          `🚀 Workflow: ${workflow.replace(/_/g, " ").toUpperCase()}`
        );
        sections.push("=".repeat(50));

        const steps = WORKFLOWS[workflow];
        if (!steps || steps.length === 0) {
          return {
            content: [
              createErrorContent(
                `Unknown workflow: ${workflow}`
              ),
            ],
            isError: true,
          };
        }

        const totalEstimate = steps.reduce(
          (sum, s) => sum + s.estimatedSeconds,
          0
        );

        sections.push(
          `Steps: ${steps.length} | Estimated time: ~${Math.ceil(totalEstimate / 60)} min`
        );

        if (dry_run ?? getConfig().dryRun) {
          sections.push("\n[DRY RUN] Workflow steps that would be executed:\n");

          for (let i = 0; i < steps.length; i++) {
            const step = steps[i];
            sections.push(
              `  Step ${i + 1}: ${step.description}`
            );
            sections.push(
              `    Tool: ${step.tool}`
            );
            sections.push(
              `    Command: ${step.command} ${step.args.join(" ")}`
            );
            sections.push(
              `    Est. time: ~${step.estimatedSeconds}s`
            );
            sections.push("");
          }

          sections.push(
            "To execute this workflow, set dry_run: false"
          );
        } else {
          sections.push("\nExecuting workflow...\n");

          let successCount = 0;
          let failCount = 0;

          for (let i = 0; i < steps.length; i++) {
            const step = steps[i];
            sections.push(
              `── Step ${i + 1}/${steps.length}: ${step.description} ──`
            );

            const startTime = Date.now();

            const result = await executeCommand({
              command: step.command,
              args: step.args,
              toolName: `defense_run_workflow_${workflow}`,
              timeout: Math.max(
                step.estimatedSeconds * 3 * 1000,
                30000
              ),
            });

            const duration = Math.round(
              (Date.now() - startTime) / 1000
            );

            if (result.exitCode === 0) {
              successCount++;
              sections.push(`  ✅ Completed in ${duration}s`);

              // Include truncated output
              const output = result.stdout.trim();
              if (output) {
                const outputLines = output.split("\n");
                if (outputLines.length > 20) {
                  sections.push(
                    `  Output (${outputLines.length} lines, showing first 20):`
                  );
                  for (const line of outputLines.slice(0, 20)) {
                    sections.push(`    ${line}`);
                  }
                  sections.push("    ...");
                } else {
                  sections.push("  Output:");
                  for (const line of outputLines) {
                    sections.push(`    ${line}`);
                  }
                }
              }
            } else {
              failCount++;
              sections.push(
                `  ❌ Failed (exit ${result.exitCode}) in ${duration}s`
              );
              if (result.stderr) {
                sections.push(
                  `  Error: ${result.stderr.substring(0, 200)}`
                );
              }
            }

            sections.push("");

            logChange(
              createChangeEntry({
                tool: "defense_run_workflow",
                action: `${workflow}_step_${i + 1}`,
                target: step.description,
                after: `exit=${result.exitCode} duration=${duration}s`,
                dryRun: false,
                success: result.exitCode === 0,
                error:
                  result.exitCode !== 0
                    ? result.stderr.substring(0, 200)
                    : undefined,
              })
            );
          }

          sections.push("── Workflow Summary ──");
          sections.push(
            `  Completed: ${successCount}/${steps.length}`
          );
          sections.push(`  Failed: ${failCount}/${steps.length}`);

          if (failCount === 0) {
            sections.push(
              "  ✅ All steps completed successfully"
            );
          } else {
            sections.push(
              "  ⚠️ Some steps failed - review output above"
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
}
