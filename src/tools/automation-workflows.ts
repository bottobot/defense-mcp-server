/**
 * Automation workflow tools.
 *
 * Tools: setup_scheduled_audit, list_scheduled_audits, remove_scheduled_audit,
 *        get_audit_history
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeCommand } from "../core/executor.js";
import { createErrorContent, formatToolOutput } from "../core/parsers.js";
import { logChange, createChangeEntry } from "../core/changelog.js";
import { SafeguardRegistry } from "../core/safeguards.js";
import { existsSync, writeFileSync, readFileSync, mkdirSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

const AUDIT_LOG_DIR = join(homedir(), ".kali-defense", "audit-logs");

function ensureAuditLogDir(): void {
  if (!existsSync(AUDIT_LOG_DIR)) {
    mkdirSync(AUDIT_LOG_DIR, { recursive: true });
  }
}

export function registerAutomationWorkflowTools(server: McpServer): void {

  // ── setup_scheduled_audit ──────────────────────────────────────────────────

  server.tool(
    "setup_scheduled_audit",
    "Create a scheduled security audit using systemd timer or cron.",
    {
      name: z.string().describe("Audit job name"),
      command: z.string().describe("Command to run"),
      schedule: z.string().describe("Schedule (cron format: '0 2 * * *' or systemd calendar: 'daily')"),
      useSystemd: z.boolean().optional().default(true).describe("Use systemd timer (false for cron)"),
      dryRun: z.boolean().optional().default(true).describe("Preview only"),
    },
    async ({ name, command: auditCommand, schedule, useSystemd, dryRun }) => {
      try {
        const safety = await SafeguardRegistry.getInstance().checkSafety("setup_scheduled_audit", { name });
        ensureAuditLogDir();

        const logFile = join(AUDIT_LOG_DIR, `${name}.log`);

        if (useSystemd) {
          const serviceContent = `[Unit]
Description=Kali Defense Scheduled Audit: ${name}

[Service]
Type=oneshot
ExecStart=/bin/bash -c '${auditCommand} >> ${logFile} 2>&1'
`;

          const timerContent = `[Unit]
Description=Timer for ${name} audit

[Timer]
OnCalendar=${schedule}
Persistent=true

[Install]
WantedBy=timers.target
`;

          const servicePath = `/etc/systemd/system/kali-audit-${name}.service`;
          const timerPath = `/etc/systemd/system/kali-audit-${name}.timer`;

          if (dryRun) {
            return {
              content: [formatToolOutput({
                dryRun: true,
                type: "systemd",
                servicePath,
                timerPath,
                serviceContent,
                timerContent,
                warnings: safety.warnings,
                enableCommand: `systemctl enable --now kali-audit-${name}.timer`,
              })],
            };
          }

          writeFileSync(servicePath, serviceContent, "utf-8");
          writeFileSync(timerPath, timerContent, "utf-8");

          await executeCommand({ command: "systemctl", args: ["daemon-reload"], timeout: 10000 });
          const enable = await executeCommand({
            command: "systemctl",
            args: ["enable", "--now", `kali-audit-${name}.timer`],
            timeout: 10000,
          });

          const entry = createChangeEntry({
            tool: "setup_scheduled_audit",
            action: `Create systemd timer for ${name}`,
            target: timerPath,
            dryRun: false,
            success: enable.exitCode === 0,
            rollbackCommand: `systemctl disable --now kali-audit-${name}.timer && rm ${servicePath} ${timerPath}`,
          });
          logChange(entry);

          return {
            content: [formatToolOutput({
              success: enable.exitCode === 0,
              type: "systemd",
              name,
              servicePath,
              timerPath,
              enabled: enable.exitCode === 0,
            })],
          };
        }

        // Cron approach
        const cronLine = `${schedule} ${auditCommand} >> ${logFile} 2>&1 # kali-audit-${name}`;

        if (dryRun) {
          return {
            content: [formatToolOutput({
              dryRun: true,
              type: "cron",
              cronLine,
              warnings: safety.warnings,
            })],
          };
        }

        // Add to crontab
        const currentCron = await executeCommand({ command: "crontab", args: ["-l"], timeout: 5000 });
        const existing = currentCron.exitCode === 0 ? currentCron.stdout : "";

        if (existing.includes(`kali-audit-${name}`)) {
          return { content: [createErrorContent(`Cron job 'kali-audit-${name}' already exists. Remove it first.`)], isError: true };
        }

        const newCron = existing.trimEnd() + "\n" + cronLine + "\n";
        const install = await executeCommand({
          command: "crontab",
          args: ["-"],
          stdin: newCron,
          timeout: 5000,
        });

        const entry = createChangeEntry({
          tool: "setup_scheduled_audit",
          action: `Create cron job for ${name}`,
          target: "crontab",
          dryRun: false,
          success: install.exitCode === 0,
        });
        logChange(entry);

        return {
          content: [formatToolOutput({
            success: install.exitCode === 0,
            type: "cron",
            name,
            cronLine,
          })],
        };
      } catch (err) {
        return { content: [createErrorContent(`Scheduled audit setup failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true };
      }
    }
  );

  // ── list_scheduled_audits ──────────────────────────────────────────────────

  server.tool(
    "list_scheduled_audits",
    "List all scheduled security audits (systemd timers and cron jobs).",
    {
      dryRun: z.boolean().optional().default(false).describe("Preview only"),
    },
    async ({ dryRun }) => {
      try {
        const audits: { name: string; type: string; schedule: string; status: string }[] = [];

        // Check systemd timers
        const timers = await executeCommand({
          command: "systemctl",
          args: ["list-timers", "--no-pager", "--plain"],
          timeout: 10000,
        });
        if (timers.exitCode === 0) {
          for (const line of timers.stdout.split("\n")) {
            if (line.includes("kali-audit-")) {
              const match = line.match(/kali-audit-(\S+)/);
              if (match) {
                audits.push({
                  name: match[1].replace(".timer", ""),
                  type: "systemd",
                  schedule: line.trim(),
                  status: "active",
                });
              }
            }
          }
        }

        // Check cron
        const cron = await executeCommand({ command: "crontab", args: ["-l"], timeout: 5000 });
        if (cron.exitCode === 0) {
          for (const line of cron.stdout.split("\n")) {
            if (line.includes("kali-audit-")) {
              const match = line.match(/# kali-audit-(\S+)/);
              if (match) {
                audits.push({
                  name: match[1],
                  type: "cron",
                  schedule: line.split("#")[0].trim(),
                  status: "active",
                });
              }
            }
          }
        }

        return {
          content: [formatToolOutput({
            totalAudits: audits.length,
            audits,
          })],
        };
      } catch (err) {
        return { content: [createErrorContent(`List audits failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true };
      }
    }
  );

  // ── remove_scheduled_audit ─────────────────────────────────────────────────

  server.tool(
    "remove_scheduled_audit",
    "Remove a scheduled security audit by name.",
    {
      name: z.string().describe("Audit job name to remove"),
      dryRun: z.boolean().optional().default(true).describe("Preview only"),
    },
    async ({ name, dryRun }) => {
      try {
        const actions: { action: string; success: boolean }[] = [];

        // Check for systemd timer
        const timerPath = `/etc/systemd/system/kali-audit-${name}.timer`;
        const servicePath = `/etc/systemd/system/kali-audit-${name}.service`;
        const hasTimer = existsSync(timerPath);

        // Check cron
        const cron = await executeCommand({ command: "crontab", args: ["-l"], timeout: 5000 });
        const hasCron = cron.exitCode === 0 && cron.stdout.includes(`kali-audit-${name}`);

        if (!hasTimer && !hasCron) {
          return { content: [createErrorContent(`No scheduled audit found with name: ${name}`)], isError: true };
        }

        if (dryRun) {
          return {
            content: [formatToolOutput({
              dryRun: true,
              name,
              hasSystemdTimer: hasTimer,
              hasCronJob: hasCron,
              actions: [
                hasTimer ? `systemctl disable --now kali-audit-${name}.timer && rm ${timerPath} ${servicePath}` : null,
                hasCron ? `Remove cron line containing kali-audit-${name}` : null,
              ].filter(Boolean),
            })],
          };
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

        const entry = createChangeEntry({
          tool: "remove_scheduled_audit",
          action: `Remove scheduled audit ${name}`,
          target: name,
          dryRun: false,
          success: true,
        });
        logChange(entry);

        return { content: [formatToolOutput({ name, actions })] };
      } catch (err) {
        return { content: [createErrorContent(`Remove audit failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true };
      }
    }
  );

  // ── get_audit_history ──────────────────────────────────────────────────────

  server.tool(
    "get_audit_history",
    "Read historical output from scheduled audit jobs.",
    {
      name: z.string().describe("Audit job name"),
      lines: z.number().optional().default(100).describe("Number of recent lines to return"),
      dryRun: z.boolean().optional().default(false).describe("Preview only"),
    },
    async ({ name, lines, dryRun }) => {
      try {
        ensureAuditLogDir();

        const logFile = join(AUDIT_LOG_DIR, `${name}.log`);

        if (!existsSync(logFile)) {
          return { content: [formatToolOutput({ name, message: `No audit log found at ${logFile}` })] };
        }

        const result = await executeCommand({
          command: "tail",
          args: ["-n", String(lines), logFile],
          timeout: 10000,
        });

        return {
          content: [formatToolOutput({
            name,
            logFile,
            lines: result.stdout.trim().split("\n"),
            totalLines: result.stdout.trim().split("\n").length,
          })],
        };
      } catch (err) {
        return { content: [createErrorContent(`Audit history failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true };
      }
    }
  );
}
