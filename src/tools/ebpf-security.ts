/**
 * eBPF and Falco security tools.
 *
 * Registers 2 tools: list_ebpf_programs, falco (actions: status, deploy_rules, events).
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeCommand } from "../core/executor.js";
import { createErrorContent, formatToolOutput } from "../core/parsers.js";
import { logChange, createChangeEntry } from "../core/changelog.js";
import { SafeguardRegistry } from "../core/safeguards.js";
import { existsSync, writeFileSync, readFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

export function registerEbpfSecurityTools(server: McpServer): void {

  // ── list_ebpf_programs (kept as-is) ────────────────────────────────────────

  server.tool(
    "list_ebpf_programs",
    "List loaded eBPF programs and pinned maps.",
    {
      dryRun: z.boolean().optional().default(false).describe("Preview only"),
    },
    async ({ dryRun }) => {
      try {
        const results: Record<string, unknown> = {};

        // List BPF filesystem
        if (existsSync("/sys/fs/bpf")) {
          const ls = await executeCommand({
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
  );

  // ── falco (merged: check_falco + deploy_falco_rules + get_ebpf_events) ────

  server.tool(
    "falco",
    "Falco runtime security: check status, deploy custom rules, or read recent events.",
    {
      action: z.enum(["status", "deploy_rules", "events"]).describe("Action: status=check Falco, deploy_rules=deploy custom rules, events=read recent events"),
      // deploy_rules params
      ruleName: z.string().optional().describe("Rule file name without .yaml extension (deploy_rules action)"),
      ruleContent: z.string().optional().describe("YAML rule content (deploy_rules action)"),
      // events params
      lines: z.number().optional().default(50).describe("Number of recent events to return (events action)"),
      priority: z.enum(["emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"]).optional().describe("Filter by minimum priority (events action)"),
      // shared
      dryRun: z.boolean().optional().default(false).describe("Preview only"),
    },
    async (params) => {
      const { action } = params;

      switch (action) {
        // ── status ──────────────────────────────────────────────────
        case "status": {
          try {
            const info: Record<string, unknown> = {};

            // Check if falco is installed
            const which = await executeCommand({ command: "which", args: ["falco"], timeout: 5000 });
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
            const version = await executeCommand({ command: "falco", args: ["--version"], timeout: 5000 });
            info.version = version.stdout.trim();

            // Service status
            const status = await executeCommand({
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
              const ls = await executeCommand({ command: "ls", args: ["/etc/falco/rules.d"], timeout: 5000 });
              info.customRules = ls.stdout.trim().split("\n").filter(Boolean);
            }

            return { content: [formatToolOutput(info)] };
          } catch (err) {
            return { content: [createErrorContent(`Falco check failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true };
          }
        }

        // ── deploy_rules ────────────────────────────────────────────
        case "deploy_rules": {
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

            writeFileSync(rulePath, ruleContent, "utf-8");

            // Validate rules
            const validate = await executeCommand({
              command: "falco",
              args: ["--validate", rulePath],
              timeout: 15000,
            });

            const entry = createChangeEntry({
              tool: "falco",
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

        // ── events ──────────────────────────────────────────────────
        case "events": {
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
