/**
 * eBPF and Falco security tools.
 *
 * Registers 1 tool: ebpf (actions: list_programs, falco_status, falco_deploy_rules, falco_events).
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeCommand } from "../core/executor.js";
import { createErrorContent, formatToolOutput } from "../core/parsers.js";
import { logChange, createChangeEntry } from "../core/changelog.js";
import { SafeguardRegistry } from "../core/safeguards.js";
import { existsSync, readFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { secureWriteFileSync } from "../core/secure-fs.js";

// ── TOOL-018 remediation: BPF filter expression validation ─────────────────

/** Characters allowed in BPF filter expressions */
const BPF_FILTER_ALLOWED_RE = /^[a-zA-Z0-9\s.\/:_\-\[\]!=<>'"]+$/;

/** Shell metacharacters that must be rejected in BPF filters */
const BPF_SHELL_METACHAR_RE = /[;|&`$(){}<>]/;

/** Maximum BPF filter expression length */
const BPF_FILTER_MAX_LENGTH = 500;

/**
 * Validate a BPF filter expression.
 * Rejects shell metacharacters, enforces length limits, and allows only
 * safe characters (alphanumeric, spaces, dots, colons, slashes, hyphens,
 * underscores, brackets, comparison operators, and quotes).
 */
export function validateBpfFilter(filter: string): string {
  if (!filter || typeof filter !== "string") {
    throw new Error("BPF filter must be a non-empty string");
  }

  const trimmed = filter.trim();

  if (trimmed.length > BPF_FILTER_MAX_LENGTH) {
    throw new Error(
      `BPF filter expression too long (${trimmed.length} chars). Maximum is ${BPF_FILTER_MAX_LENGTH} characters.`
    );
  }

  if (BPF_SHELL_METACHAR_RE.test(trimmed)) {
    throw new Error(
      `BPF filter contains forbidden shell metacharacters: '${trimmed}'`
    );
  }

  if (!BPF_FILTER_ALLOWED_RE.test(trimmed)) {
    throw new Error(
      `BPF filter contains invalid characters. Only alphanumeric, spaces, dots, colons, slashes, hyphens, underscores, brackets, comparison operators, and quotes are allowed.`
    );
  }

  return trimmed;
}

export function registerEbpfSecurityTools(server: McpServer): void {

  server.tool(
    "ebpf",
    "eBPF and Falco security: list loaded eBPF programs, check Falco status, deploy Falco rules, or read recent Falco events.",
    {
      action: z.enum(["list_programs", "falco_status", "falco_deploy_rules", "falco_events"]).describe("Action: list_programs=list eBPF programs, falco_status=check Falco, falco_deploy_rules=deploy custom rules, falco_events=read recent events"),
      // list_programs params
      dryRun: z.boolean().optional().default(true).describe("Preview only (list_programs / falco_deploy_rules)"),
      // falco_deploy_rules params
      ruleName: z.string().optional().describe("Rule file name without .yaml extension (falco_deploy_rules action)"),
      ruleContent: z.string().optional().describe("YAML rule content (falco_deploy_rules action)"),
      // falco_events params
      lines: z.number().optional().default(50).describe("Number of recent events to return (falco_events action)"),
      priority: z.enum(["emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"]).optional().describe("Filter by minimum priority (falco_events action)"),
    },
    async (params) => {
      const { action } = params;

      switch (action) {
        // ── list_programs ────────────────────────────────────────────
        case "list_programs": {
          try {
            const results: Record<string, unknown> = {};

            // List BPF filesystem
            if (existsSync("/sys/fs/bpf")) {
              const ls = await executeCommand({
                toolName: "ebpf_security",
                command: "ls",
                args: ["-la", "/sys/fs/bpf"],
                timeout: 5000,
              });
              results.bpfFs = ls.stdout.trim().split("\n");
            } else {
              results.bpfFs = "Not mounted";
            }

            // Try bpftool
            const bpftool = await executeCommand({
              toolName: "ebpf_security",
              command: "bpftool",
              args: ["prog", "list", "--json"],
              timeout: 10000,
            });

            if (bpftool.exitCode === 0) {
              try {
                results.programs = JSON.parse(bpftool.stdout);
              } catch {
                results.programs = bpftool.stdout.split("\n").filter(Boolean);
              }
            } else {
              // Fallback to non-JSON
              const fallback = await executeCommand({
                toolName: "ebpf_security",
                command: "bpftool",
                args: ["prog", "list"],
                timeout: 10000,
              });
              results.programs = fallback.exitCode === 0
                ? fallback.stdout.split("\n").filter(Boolean)
                : "bpftool not available or insufficient permissions";
            }

            // List maps
            const maps = await executeCommand({
              toolName: "ebpf_security",
              command: "bpftool",
              args: ["map", "list", "--json"],
              timeout: 10000,
            });
            if (maps.exitCode === 0) {
              try {
                results.maps = JSON.parse(maps.stdout);
              } catch {
                results.maps = maps.stdout.split("\n").filter(Boolean);
              }
            }

            return { content: [formatToolOutput(results)] };
          } catch (err) {
            return { content: [createErrorContent(`eBPF listing failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true };
          }
        }

        // ── falco_status ─────────────────────────────────────────────
        case "falco_status": {
          try {
            const info: Record<string, unknown> = {};

            // Check if falco is installed
            const which = await executeCommand({ toolName: "ebpf_security", command: "which", args: ["falco"], timeout: 5000 });
            info.installed = which.exitCode === 0;

            if (!info.installed) {
              return {
                content: [formatToolOutput({
                  installed: false,
                  message: "Falco not installed. Install from https://falco.org/docs/install-operate/installation/",
                })],
              };
            }

            // Version
            const version = await executeCommand({ toolName: "ebpf_security", command: "falco", args: ["--version"], timeout: 5000 });
            info.version = version.stdout.trim();

            // Service status
            const status = await executeCommand({
              toolName: "ebpf_security",
              command: "systemctl",
              args: ["status", "falco", "--no-pager"],
              timeout: 10000,
            });
            info.serviceStatus = status.stdout.trim().split("\n").slice(0, 10);
            info.active = status.stdout.includes("active (running)");

            // Check config
            if (existsSync("/etc/falco/falco.yaml")) {
              info.configExists = true;
            }

            // Check custom rules
            if (existsSync("/etc/falco/rules.d")) {
              const ls = await executeCommand({ toolName: "ebpf_security", command: "ls", args: ["/etc/falco/rules.d"], timeout: 5000 });
              info.customRules = ls.stdout.trim().split("\n").filter(Boolean);
            }

            return { content: [formatToolOutput(info)] };
          } catch (err) {
            return { content: [createErrorContent(`Falco check failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true };
          }
        }

        // ── falco_deploy_rules ───────────────────────────────────────
        case "falco_deploy_rules": {
          const { ruleName, ruleContent, dryRun } = params;
          try {
            if (!ruleName) {
              return { content: [createErrorContent("ruleName is required for deploy_rules action")], isError: true };
            }
            if (!ruleContent) {
              return { content: [createErrorContent("ruleContent is required for deploy_rules action")], isError: true };
            }

            const safety = await SafeguardRegistry.getInstance().checkSafety("deploy_falco_rules", { ruleName });

            const rulesDir = "/etc/falco/rules.d";
            const rulePath = `${rulesDir}/${ruleName}.yaml`;

            if (dryRun) {
              return {
                content: [formatToolOutput({
                  dryRun: true,
                  rulePath,
                  ruleContent,
                  warnings: safety.warnings,
                  restartCommand: "systemctl restart falco",
                })],
              };
            }

            if (!existsSync(rulesDir)) {
              mkdirSync(rulesDir, { recursive: true });
            }

            // TOOL-010: Use secure-fs instead of direct writeFileSync for audit trail
            secureWriteFileSync(rulePath, ruleContent, "utf-8");

            // Validate rules
            const validate = await executeCommand({
              toolName: "ebpf_security",
              command: "falco",
              args: ["--validate", rulePath],
              timeout: 15000,
            });

            const entry = createChangeEntry({
              tool: "ebpf",
              action: `Deploy Falco rule ${ruleName}`,
              target: rulePath,
              dryRun: false,
              success: validate.exitCode === 0,
              rollbackCommand: `rm ${rulePath}`,
            });
            logChange(entry);

            return {
              content: [formatToolOutput({
                success: validate.exitCode === 0,
                rulePath,
                validated: validate.exitCode === 0,
                validationOutput: validate.stdout || validate.stderr,
                nextStep: "systemctl restart falco",
              })],
            };
          } catch (err) {
            return { content: [createErrorContent(`Falco rule deployment failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true };
          }
        }

        // ── falco_events ─────────────────────────────────────────────
        case "falco_events": {
          const { lines, priority } = params;
          try {
            const logPaths = [
              "/var/log/falco/falco_events.json",
              "/var/log/falco/events.json",
              "/var/log/falco.log",
            ];

            let logPath: string | null = null;
            for (const p of logPaths) {
              if (existsSync(p)) {
                logPath = p;
                break;
              }
            }

            if (!logPath) {
              // Try journalctl
              const journalResult = await executeCommand({
                toolName: "ebpf_security",
                command: "journalctl",
                args: ["-u", "falco", "--no-pager", "-n", String(lines), "-o", "json"],
                timeout: 10000,
              });

              if (journalResult.exitCode === 0) {
                const events = journalResult.stdout.trim().split("\n").filter(Boolean).map((l) => {
                  try { return JSON.parse(l); } catch { return { raw: l }; }
                });
                return { content: [formatToolOutput({ source: "journalctl", events: events.slice(-lines) })] };
              }

              return { content: [createErrorContent("No Falco log file found and journalctl query failed")], isError: true };
            }

            const result = await executeCommand({
              toolName: "ebpf_security",
              command: "tail",
              args: ["-n", String(lines), logPath],
              timeout: 10000,
            });

            const events = result.stdout.trim().split("\n").filter(Boolean).map((l) => {
              try { return JSON.parse(l); } catch { return { raw: l }; }
            });

            let filtered = events;
            if (priority) {
              const priorities = ["emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"];
              const minIdx = priorities.indexOf(priority);
              filtered = events.filter((e: Record<string, unknown>) => {
                const p = typeof e.priority === "string" ? e.priority.toLowerCase() : "";
                const idx = priorities.indexOf(p);
                return idx >= 0 && idx <= minIdx;
              });
            }

            return {
              content: [formatToolOutput({
                source: logPath,
                totalEvents: filtered.length,
                events: filtered,
              })],
            };
          } catch (err) {
            return { content: [createErrorContent(`eBPF events retrieval failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true };
          }
        }

        default:
          return { content: [createErrorContent(`Unknown action: ${action}`)], isError: true };
      }
    }
  );
}
