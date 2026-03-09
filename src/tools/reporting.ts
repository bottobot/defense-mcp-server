/**
 * Reporting tools for Kali Defense MCP Server.
 *
 * Registers 1 tool: report_export (actions: generate, list_reports, formats)
 *
 * Generates consolidated security reports by collecting system audit data
 * from multiple sources and formatting into structured output.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { spawnSafe } from "../core/spawn-safe.js";
import { secureWriteFileSync } from "../core/secure-fs.js";
import {
  createTextContent,
  createErrorContent,
  formatToolOutput,
} from "../core/parsers.js";
import type { ChildProcess } from "node:child_process";
import { existsSync, readdirSync, statSync } from "node:fs";

// ── Constants ──────────────────────────────────────────────────────────────────

const DEFAULT_REPORT_DIR = "/var/lib/kali-defense/reports";

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

// ── Commands needed in the allowlist (to be added in a later batch) ────────
// - pandoc (for advanced HTML/PDF conversion)
// - wkhtmltopdf (for PDF generation)

// ── Helpers ────────────────────────────────────────────────────────────────────

interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

/**
 * Run a command via spawnSafe and collect output as a promise.
 * Handles errors gracefully — returns error info instead of throwing.
 */
async function runCommand(
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

    child.stdout?.on("data", (data: Buffer) => {
      stdout += data.toString();
    });
    child.stderr?.on("data", (data: Buffer) => {
      stderr += data.toString();
    });

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

/**
 * Run a command via sudo through spawnSafe.
 */
async function runSudoCommand(
  command: string,
  args: string[],
  timeoutMs = 30_000,
): Promise<CommandResult> {
  return runCommand("sudo", [command, ...args], timeoutMs);
}

// ── Section Generators ─────────────────────────────────────────────────────────

interface ReportSection {
  name: string;
  key: string;
  data: string;
  error?: string;
}

async function gatherSystemOverview(): Promise<ReportSection> {
  const uname = await runCommand("uname", ["-a"]);
  const hostname = await runCommand("hostname", []);
  const uptime = await runCommand("uptime", []);

  let data = "";
  if (uname.exitCode === 0) data += `Kernel: ${uname.stdout.trim()}\n`;
  else data += `Kernel: [error: ${uname.stderr.trim()}]\n`;

  if (hostname.exitCode === 0) data += `Hostname: ${hostname.stdout.trim()}\n`;
  if (uptime.exitCode === 0) data += `Uptime: ${uptime.stdout.trim()}\n`;

  return {
    name: "System Overview",
    key: "system_overview",
    data,
    error: uname.exitCode !== 0 ? uname.stderr.trim() : undefined,
  };
}

async function gatherFirewallStatus(): Promise<ReportSection> {
  const iptables = await runSudoCommand("iptables", ["-L", "-n", "--line-numbers"]);

  let data = "";
  if (iptables.exitCode === 0) {
    data = iptables.stdout.trim();
  } else {
    data = `[Error gathering firewall rules: ${iptables.stderr.trim()}]`;
  }

  return {
    name: "Firewall Status",
    key: "firewall_status",
    data,
    error: iptables.exitCode !== 0 ? iptables.stderr.trim() : undefined,
  };
}

async function gatherServiceAudit(): Promise<ReportSection> {
  const services = await runCommand("systemctl", [
    "list-units", "--type=service", "--state=running", "--no-pager", "--no-legend",
  ]);

  let data = "";
  if (services.exitCode === 0) {
    data = services.stdout.trim();
  } else {
    data = `[Error listing services: ${services.stderr.trim()}]`;
  }

  return {
    name: "Service Audit",
    key: "service_audit",
    data,
    error: services.exitCode !== 0 ? services.stderr.trim() : undefined,
  };
}

async function gatherActiveConnections(): Promise<ReportSection> {
  const ss = await runCommand("ss", ["-tulnp"]);

  let data = "";
  if (ss.exitCode === 0) {
    data = ss.stdout.trim();
  } else {
    data = `[Error listing connections: ${ss.stderr.trim()}]`;
  }

  return {
    name: "Active Connections",
    key: "active_connections",
    data,
    error: ss.exitCode !== 0 ? ss.stderr.trim() : undefined,
  };
}

async function gatherRecentLogins(since?: string): Promise<ReportSection> {
  // Use journalctl to get recent login activity
  const args = ["_COMM=sshd", "-n", "50", "--no-pager"];
  if (since) {
    args.push("--since", since);
  }
  const logins = await runCommand("journalctl", args);

  let data = "";
  if (logins.exitCode === 0 && logins.stdout.trim().length > 0) {
    data = logins.stdout.trim();
  } else {
    // Fallback: try grep on auth.log
    const authLog = await runSudoCommand("grep", ["-i", "session opened", "/var/log/auth.log"]);
    if (authLog.exitCode === 0) {
      const lines = authLog.stdout.trim().split("\n");
      data = lines.slice(-20).join("\n");
    } else {
      data = "[No login data available]";
    }
  }

  return {
    name: "Recent Logins",
    key: "recent_logins",
    data,
    error:
      logins.exitCode !== 0 && data === "[No login data available]"
        ? logins.stderr.trim()
        : undefined,
  };
}

async function gatherComplianceSummary(): Promise<ReportSection> {
  // Try to run a quick lynis audit
  const lynis = await runSudoCommand(
    "lynis",
    ["audit", "system", "--quick", "--no-colors"],
    120_000,
  );

  let data = "";
  if (lynis.exitCode === 0 || lynis.stdout.includes("Hardening index")) {
    // Extract hardening index
    const match = lynis.stdout.match(/Hardening index\s*:\s*(\d+)/);
    const index = match ? match[1] : "N/A";

    // Count warnings and suggestions
    const warnings = (lynis.stdout.match(/Warning/g) || []).length;
    const suggestions = (lynis.stdout.match(/Suggestion/g) || []).length;

    data = `Hardening Index: ${index}/100\n`;
    data += `Warnings: ${warnings}\n`;
    data += `Suggestions: ${suggestions}\n`;
  } else {
    // Lynis not available — provide basic compliance info
    const aideStatus = await runSudoCommand("aide", ["--check"], 60_000);
    if (aideStatus.exitCode === 0) {
      data += `AIDE Check: PASSED\n${aideStatus.stdout.trim().slice(0, 500)}\n`;
    } else {
      data += `AIDE Check: ${aideStatus.exitCode === -1 ? "Not installed" : "FAILED"}\n`;
    }

    const fail2ban = await runSudoCommand("fail2ban-client", ["status"]);
    if (fail2ban.exitCode === 0) {
      data += `\nFail2ban: ${fail2ban.stdout.trim()}\n`;
    } else {
      data += `\nFail2ban: Not available\n`;
    }
  }

  return {
    name: "Compliance Summary",
    key: "compliance_summary",
    data: data || "[No compliance data available]",
  };
}

function generateRecommendations(sections: ReportSection[]): ReportSection {
  const recommendations: string[] = [];

  const firewall = sections.find((s) => s.key === "firewall_status");
  if (firewall?.error) {
    recommendations.push("- Configure and enable firewall (iptables/nftables)");
  } else if (
    firewall?.data.includes("ACCEPT") &&
    !firewall.data.includes("DROP")
  ) {
    recommendations.push(
      "- Review firewall policy: consider setting default DROP policy",
    );
  }

  const services = sections.find((s) => s.key === "service_audit");
  if (services?.data) {
    const dangerous = ["telnet", "rsh", "rlogin", "tftp"];
    for (const svc of dangerous) {
      if (services.data.toLowerCase().includes(svc)) {
        recommendations.push(`- Disable insecure service: ${svc}`);
      }
    }
  }

  const connections = sections.find((s) => s.key === "active_connections");
  if (connections?.data) {
    const lineCount = connections.data.split("\n").length;
    if (lineCount > 20) {
      recommendations.push(
        `- Review ${lineCount} active connections for unnecessary exposure`,
      );
    }
  }

  const compliance = sections.find((s) => s.key === "compliance_summary");
  if (
    compliance?.data.includes("Not installed") ||
    compliance?.data.includes("Not available")
  ) {
    recommendations.push(
      "- Install security audit tools: lynis, aide, fail2ban",
    );
  }

  if (recommendations.length === 0) {
    recommendations.push("- No critical recommendations at this time");
    recommendations.push("- Continue regular security audits");
  }

  return {
    name: "Recommendations",
    key: "recommendations",
    data: recommendations.join("\n"),
  };
}

// ── Format Helpers ─────────────────────────────────────────────────────────────

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function formatAsMarkdown(
  sections: ReportSection[],
  reportType: string,
  timestamp: string,
): string {
  let md = `# Security Report: ${reportType.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())}\n\n`;
  md += `**Generated:** ${timestamp}\n`;
  md += `**Report Type:** ${reportType}\n\n`;
  md += `---\n\n`;

  for (const section of sections) {
    md += `## ${section.name}\n\n`;
    if (section.error) {
      md += `> ⚠️ Error: ${section.error}\n\n`;
    }
    md += `\`\`\`\n${section.data}\n\`\`\`\n\n`;
  }

  return md;
}

function formatAsHtml(
  sections: ReportSection[],
  reportType: string,
  timestamp: string,
): string {
  let html = `<!DOCTYPE html>\n<html><head><meta charset="utf-8">\n`;
  html += `<title>Security Report: ${escapeHtml(reportType)}</title>\n`;
  html += `<style>body{font-family:sans-serif;max-width:900px;margin:0 auto;padding:20px}`;
  html += `pre{background:#f4f4f4;padding:12px;border-radius:4px;overflow-x:auto}`;
  html += `.warning{color:#c00;font-weight:bold}h1{border-bottom:2px solid #333}`;
  html += `h2{border-bottom:1px solid #ccc;padding-bottom:4px}</style>\n`;
  html += `</head><body>\n`;
  html += `<h1>Security Report: ${escapeHtml(reportType.replace(/_/g, " "))}</h1>\n`;
  html += `<p><strong>Generated:</strong> ${escapeHtml(timestamp)}</p>\n`;

  for (const section of sections) {
    html += `<h2>${escapeHtml(section.name)}</h2>\n`;
    if (section.error) {
      html += `<p class="warning">⚠ Error: ${escapeHtml(section.error)}</p>\n`;
    }
    html += `<pre>${escapeHtml(section.data)}</pre>\n`;
  }

  html += `</body></html>`;
  return html;
}

function formatAsJson(
  sections: ReportSection[],
  reportType: string,
  timestamp: string,
): string {
  const report = {
    reportType,
    generatedAt: timestamp,
    sections: sections.map((s) => ({
      name: s.name,
      key: s.key,
      data: s.data,
      error: s.error || null,
    })),
  };
  return JSON.stringify(report, null, 2);
}

function formatAsCsv(
  sections: ReportSection[],
  _reportType: string,
  _timestamp: string,
): string {
  const lines: string[] = [];
  lines.push("Section,Status,Summary");
  for (const section of sections) {
    const status = section.error ? "ERROR" : "OK";
    const summary = section.data
      .split("\n")[0]
      .slice(0, 100)
      .replace(/,/g, ";")
      .replace(/"/g, '""');
    lines.push(`"${section.name}","${status}","${summary}"`);
  }
  return lines.join("\n");
}

// ── Registration entry point ───────────────────────────────────────────────

export function registerReportingTools(server: McpServer): void {
  server.tool(
    "report_export",
    "Generate, list, or query security reports: consolidated system security data in multiple formats.",
    {
      action: z
        .enum(["generate", "list_reports", "formats"])
        .describe(
          "Action: generate=create report, list_reports=list saved reports, formats=show available formats",
        ),
      report_type: z
        .enum([
          "executive_summary",
          "technical_detail",
          "compliance_evidence",
          "vulnerability_report",
          "hardening_status",
        ])
        .optional()
        .default("technical_detail")
        .describe("Type of report to generate (used with generate action)"),
      format: z
        .enum(["markdown", "html", "json", "csv"])
        .optional()
        .default("markdown")
        .describe("Output format for the report"),
      output_path: z
        .string()
        .optional()
        .describe(
          "File path to save the report (uses secure-fs for writing)",
        ),
      include_sections: z
        .array(z.string())
        .optional()
        .describe(
          "Specific section names to include (default: all sections)",
        ),
      since: z
        .string()
        .optional()
        .describe(
          "Only include findings since this date (ISO 8601 or journalctl-compatible)",
        ),
    },
    async (params) => {
      const { action } = params;

      switch (action) {
        case "generate": {
          const {
            report_type,
            format,
            output_path,
            include_sections,
            since,
          } = params;
          try {
            const timestamp = new Date().toISOString();
            const effectiveReportType = report_type ?? "technical_detail";
            const effectiveFormat = format ?? "markdown";
            const sectionsToInclude =
              include_sections && include_sections.length > 0
                ? include_sections
                : ALL_SECTIONS;

            // Gather all requested sections (in parallel where safe)
            const sectionPromises: Array<Promise<ReportSection>> = [];

            if (sectionsToInclude.includes("system_overview")) {
              sectionPromises.push(gatherSystemOverview());
            }
            if (sectionsToInclude.includes("firewall_status")) {
              sectionPromises.push(gatherFirewallStatus());
            }
            if (sectionsToInclude.includes("service_audit")) {
              sectionPromises.push(gatherServiceAudit());
            }
            if (sectionsToInclude.includes("active_connections")) {
              sectionPromises.push(gatherActiveConnections());
            }
            if (sectionsToInclude.includes("recent_logins")) {
              sectionPromises.push(gatherRecentLogins(since));
            }
            if (sectionsToInclude.includes("compliance_summary")) {
              sectionPromises.push(gatherComplianceSummary());
            }

            const sections = await Promise.all(sectionPromises);

            // Generate recommendations based on gathered data
            if (sectionsToInclude.includes("recommendations")) {
              sections.push(generateRecommendations(sections));
            }

            // Format output
            let reportContent: string;
            switch (effectiveFormat) {
              case "html":
                reportContent = formatAsHtml(
                  sections,
                  effectiveReportType,
                  timestamp,
                );
                break;
              case "json":
                reportContent = formatAsJson(
                  sections,
                  effectiveReportType,
                  timestamp,
                );
                break;
              case "csv":
                reportContent = formatAsCsv(
                  sections,
                  effectiveReportType,
                  timestamp,
                );
                break;
              case "markdown":
              default:
                reportContent = formatAsMarkdown(
                  sections,
                  effectiveReportType,
                  timestamp,
                );
                break;
            }

            // Write to file if output_path provided
            if (output_path) {
              try {
                secureWriteFileSync(output_path, reportContent, "utf-8");
              } catch (writeErr: unknown) {
                const msg =
                  writeErr instanceof Error
                    ? writeErr.message
                    : String(writeErr);
                return {
                  content: [
                    createErrorContent(
                      `Report generated but failed to write to ${output_path}: ${msg}`,
                    ),
                  ],
                  isError: true,
                };
              }
            }

            // Return the report
            if (effectiveFormat === "json") {
              return {
                content: [
                  formatToolOutput({
                    reportType: effectiveReportType,
                    format: effectiveFormat,
                    timestamp,
                    savedTo: output_path || null,
                    sectionsIncluded: sections.map((s) => s.key),
                    report: JSON.parse(reportContent),
                  }),
                ],
              };
            }

            const summary = {
              reportType: effectiveReportType,
              format: effectiveFormat,
              timestamp,
              savedTo: output_path || null,
              sectionsIncluded: sections.map((s) => s.key),
              sectionsWithErrors: sections
                .filter((s) => s.error)
                .map((s) => s.key),
            };

            return {
              content: [
                createTextContent(reportContent),
                formatToolOutput(summary),
              ],
            };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return {
              content: [
                createErrorContent(`Report generation failed: ${msg}`),
              ],
              isError: true,
            };
          }
        }

        case "list_reports": {
          try {
            if (!existsSync(DEFAULT_REPORT_DIR)) {
              return {
                content: [
                  formatToolOutput({
                    reportDir: DEFAULT_REPORT_DIR,
                    reports: [],
                    message: `Report directory ${DEFAULT_REPORT_DIR} does not exist. Generate a report with output_path to create it.`,
                  }),
                ],
              };
            }

            const files = readdirSync(DEFAULT_REPORT_DIR);
            const reports = files
              .filter((f) => /\.(md|html|json|csv)$/.test(f))
              .map((f) => {
                const fullPath = `${DEFAULT_REPORT_DIR}/${f}`;
                try {
                  const stats = statSync(fullPath);
                  return {
                    filename: f,
                    path: fullPath,
                    size: stats.size,
                    modified: stats.mtime.toISOString(),
                  };
                } catch {
                  return {
                    filename: f,
                    path: fullPath,
                    size: 0,
                    modified: "unknown",
                  };
                }
              });

            return {
              content: [
                formatToolOutput({
                  reportDir: DEFAULT_REPORT_DIR,
                  totalReports: reports.length,
                  reports,
                }),
              ],
            };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return {
              content: [createErrorContent(`Failed to list reports: ${msg}`)],
              isError: true,
            };
          }
        }

        case "formats": {
          return {
            content: [
              formatToolOutput({
                supportedFormats: SUPPORTED_FORMATS,
                reportTypes: REPORT_TYPES,
                availableSections: ALL_SECTIONS,
              }),
            ],
          };
        }

        default:
          return {
            content: [createErrorContent(`Unknown action: ${action}`)],
            isError: true,
          };
      }
    },
  );
}
