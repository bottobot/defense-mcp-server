/**
 * Logging and audit tools for Kali Defense MCP Server.
 *
 * Registers 7 tools: log_auditd_rules, log_auditd_search, log_auditd_report,
 * log_journalctl_query, log_fail2ban_status, log_fail2ban_manage,
 * log_syslog_analyze.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeCommand } from "../core/executor.js";
import { getConfig, getToolTimeout } from "../core/config.js";
import { createTextContent, createErrorContent, parseAuditdOutput, parseFail2banOutput, formatToolOutput } from "../core/parsers.js";
import { logChange, createChangeEntry, backupFile } from "../core/changelog.js";
import { sanitizeArgs, validateFilePath, validateAuditdKey, validateTarget } from "../core/sanitizer.js";
import { getDistroAdapter } from "../core/distro-adapter.js";
import { existsSync } from "node:fs";

// ── Registration entry point ───────────────────────────────────────────────

export function registerLoggingTools(server: McpServer): void {
  // ── 1. log_auditd_rules ──────────────────────────────────────────────

  server.tool(
    "log_auditd_rules",
    "List, add, or delete auditd rules via auditctl",
    {
      action: z.enum(["list", "add", "delete"]).describe("Action to perform on auditd rules"),
      rule: z
        .string()
        .optional()
        .describe("Audit rule, e.g. '-w /etc/passwd -p wa -k identity'"),
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview the command without executing (defaults to KALI_DEFENSE_DRY_RUN env var)"),
    },
    async ({ action, rule, dry_run }) => {
      try {
        if (action === "list") {
          const result = await executeCommand({
            command: "sudo",
            args: ["auditctl", "-l"],
            toolName: "log_auditd_rules",
            timeout: getToolTimeout("auditd"),
          });

          if (result.exitCode !== 0) {
            return {
              content: [createErrorContent(`auditctl list failed (exit ${result.exitCode}): ${result.stderr}`)],
              isError: true,
            };
          }

          return { content: [createTextContent(`Current auditd rules:\n${result.stdout}`)] };
        }

        // add or delete require a rule string
        if (!rule) {
          return {
            content: [createErrorContent(`A rule string is required for '${action}' action`)],
            isError: true,
          };
        }

        // Parse the rule string into args - determine if it's a watch rule (-w) or syscall rule (-a/-d)
        const ruleTokens = rule.trim().split(/\s+/);
        sanitizeArgs(ruleTokens);

        let args: string[];
        if (action === "add") {
          // If the rule starts with -w, use it directly; otherwise prefix with -a
          if (ruleTokens[0] === "-w") {
            args = ["auditctl", ...ruleTokens];
          } else if (ruleTokens[0] === "-a") {
            args = ["auditctl", ...ruleTokens];
          } else {
            args = ["auditctl", "-a", ...ruleTokens];
          }
        } else {
          // delete
          if (ruleTokens[0] === "-w") {
            args = ["auditctl", "-W", ...ruleTokens.slice(1)];
          } else if (ruleTokens[0] === "-a") {
            args = ["auditctl", "-d", ...ruleTokens.slice(1)];
          } else {
            args = ["auditctl", "-d", ...ruleTokens];
          }
        }

        const fullCmd = `sudo ${args.join(" ")}`;

        if (dry_run ?? getConfig().dryRun) {
          const entry = createChangeEntry({
            tool: "log_auditd_rules",
            action: `[DRY-RUN] ${action} auditd rule`,
            target: rule,
            after: fullCmd,
            dryRun: true,
            success: true,
          });
          logChange(entry);

          return {
            content: [createTextContent(`[DRY-RUN] Would execute:\n  ${fullCmd}`)],
          };
        }

        const result = await executeCommand({
          command: "sudo",
          args,
          toolName: "log_auditd_rules",
          timeout: getToolTimeout("auditd"),
        });

        const success = result.exitCode === 0;

        const entry = createChangeEntry({
          tool: "log_auditd_rules",
          action: `${action} auditd rule`,
          target: rule,
          after: fullCmd,
          dryRun: false,
          success,
          error: success ? undefined : result.stderr,
        });
        logChange(entry);

        if (!success) {
          return {
            content: [createErrorContent(`auditctl ${action} failed (exit ${result.exitCode}): ${result.stderr}`)],
            isError: true,
          };
        }

        return {
          content: [createTextContent(`Auditd rule ${action === "add" ? "added" : "deleted"} successfully.\nCommand: ${fullCmd}`)],
        };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 2. log_auditd_search ─────────────────────────────────────────────

  server.tool(
    "log_auditd_search",
    "Search audit logs using ausearch with various filters",
    {
      key: z.string().optional().describe("Audit key to search for"),
      syscall: z.string().optional().describe("System call name to filter"),
      uid: z.string().optional().describe("User ID to filter"),
      start: z.string().optional().describe("Start time, e.g. 'today', '1 hour ago'"),
      end: z.string().optional().describe("End time"),
      success: z.enum(["yes", "no"]).optional().describe("Filter by success/failure"),
      limit: z.number().optional().default(50).describe("Maximum number of lines to return"),
    },
    async ({ key, syscall, uid, start, end, success, limit }) => {
      try {
        const args: string[] = ["ausearch"];

        if (key) {
          validateAuditdKey(key);
          args.push("-k", key);
        }
        if (syscall) {
          sanitizeArgs([syscall]);
          args.push("-sc", syscall);
        }
        if (uid) {
          sanitizeArgs([uid]);
          args.push("-ui", uid);
        }
        if (start) {
          sanitizeArgs([start]);
          args.push("--start", start);
        }
        if (end) {
          sanitizeArgs([end]);
          args.push("--end", end);
        }
        if (success) {
          args.push("--success", success);
        }

        // Add --interpret for human-readable output
        args.push("--interpret");

        sanitizeArgs(args);

        const result = await executeCommand({
          command: "sudo",
          args,
          toolName: "log_auditd_search",
          timeout: getToolTimeout("auditd"),
        });

        // ausearch exits with 1 when no records found
        if (result.exitCode !== 0 && !result.stderr.includes("no matches")) {
          return {
            content: [createErrorContent(`ausearch failed (exit ${result.exitCode}): ${result.stderr}`)],
            isError: true,
          };
        }

        if (result.exitCode !== 0 && result.stderr.includes("no matches")) {
          return { content: [createTextContent("No matching audit records found.")] };
        }

        // Truncate output to limit lines
        const lines = result.stdout.split("\n");
        const truncated = lines.slice(-limit).join("\n");
        const parsed = parseAuditdOutput(result.stdout);

        const output = {
          totalEntries: parsed.length,
          displayedLines: Math.min(lines.length, limit),
          entries: parsed.slice(-limit),
          raw: truncated,
        };

        return { content: [formatToolOutput(output)] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 3. log_auditd_report ─────────────────────────────────────────────

  server.tool(
    "log_auditd_report",
    "Generate audit summary report using aureport",
    {
      report_type: z
        .enum(["summary", "auth", "login", "account", "event", "file", "exec"])
        .optional()
        .default("summary")
        .describe("Type of audit report to generate"),
      start: z.string().optional().describe("Start time for the report, e.g. 'today', '1 week ago'"),
    },
    async ({ report_type, start }) => {
      try {
        const args: string[] = ["aureport"];

        const reportFlags: Record<string, string> = {
          summary: "--summary",
          auth: "--auth",
          login: "--login",
          account: "--account-modifications",
          event: "--event",
          file: "--file",
          exec: "--executable",
        };

        args.push(reportFlags[report_type] ?? "--summary");

        if (start) {
          sanitizeArgs([start]);
          args.push("--start", start);
        }

        sanitizeArgs(args);

        const result = await executeCommand({
          command: "sudo",
          args,
          toolName: "log_auditd_report",
          timeout: getToolTimeout("auditd"),
        });

        if (result.exitCode !== 0) {
          return {
            content: [createErrorContent(`aureport failed (exit ${result.exitCode}): ${result.stderr}`)],
            isError: true,
          };
        }

        return {
          content: [createTextContent(`Audit Report (${report_type}):\n${"=".repeat(50)}\n${result.stdout}`)],
        };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 4. log_journalctl_query ──────────────────────────────────────────

  server.tool(
    "log_journalctl_query",
    "Query systemd journal for log entries with flexible filtering",
    {
      unit: z.string().optional().describe("Systemd unit name to filter"),
      priority: z
        .enum(["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"])
        .optional()
        .describe("Minimum priority level"),
      since: z.string().optional().describe("Start time, e.g. '1 hour ago', 'today', '2024-01-01'"),
      until: z.string().optional().describe("End time"),
      grep: z.string().optional().describe("Pattern to search for in log messages"),
      lines: z.number().optional().default(100).describe("Number of log lines to return"),
      output_format: z
        .enum(["short", "json", "cat", "verbose"])
        .optional()
        .default("short")
        .describe("Output format for journal entries"),
    },
    async ({ unit, priority, since, until, grep, lines, output_format }) => {
      try {
        const args: string[] = ["journalctl"];

        if (unit) {
          sanitizeArgs([unit]);
          args.push("--unit", unit);
        }
        if (priority) {
          args.push("-p", priority);
        }
        if (since) {
          sanitizeArgs([since]);
          args.push("--since", since);
        }
        if (until) {
          sanitizeArgs([until]);
          args.push("--until", until);
        }
        if (grep) {
          sanitizeArgs([grep]);
          args.push("-g", grep);
        }

        args.push("-n", String(lines));
        args.push("-o", output_format);
        args.push("--no-pager");

        sanitizeArgs(args);

        const result = await executeCommand({
          command: "journalctl",
          args: args.slice(1), // Remove 'journalctl' since it's the command
          toolName: "log_journalctl_query",
          timeout: getToolTimeout("auditd"),
        });

        if (result.exitCode !== 0) {
          return {
            content: [createErrorContent(`journalctl query failed (exit ${result.exitCode}): ${result.stderr}`)],
            isError: true,
          };
        }

        return { content: [createTextContent(result.stdout)] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 5. log_fail2ban_status ───────────────────────────────────────────

  server.tool(
    "log_fail2ban_status",
    "Check fail2ban status for all jails or a specific jail",
    {
      jail: z.string().optional().describe("Specific jail name, or omit for overview"),
    },
    async ({ jail }) => {
      try {
        const args: string[] = ["fail2ban-client", "status"];

        if (jail) {
          sanitizeArgs([jail]);
          args.push(jail);
        }

        const result = await executeCommand({
          command: "sudo",
          args,
          toolName: "log_fail2ban_status",
          timeout: getToolTimeout("auditd"),
        });

        if (result.exitCode !== 0) {
          return {
            content: [createErrorContent(`fail2ban status failed (exit ${result.exitCode}): ${result.stderr}`)],
            isError: true,
          };
        }

        if (jail) {
          const parsed = parseFail2banOutput(result.stdout);
          const output = {
            jail: jail,
            parsed: parsed,
            raw: result.stdout,
          };
          return { content: [formatToolOutput(output)] };
        }

        return { content: [createTextContent(result.stdout)] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 6. log_fail2ban_manage ───────────────────────────────────────────

  server.tool(
    "log_fail2ban_manage",
    "Manage fail2ban bans - ban/unban IP addresses or reload configuration",
    {
      action: z.enum(["ban", "unban", "reload"]).describe("Action to perform"),
      jail: z.string().optional().describe("Jail name (required for ban/unban)"),
      ip: z.string().optional().describe("IP address to ban or unban"),
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview the command without executing (defaults to KALI_DEFENSE_DRY_RUN env var)"),
    },
    async ({ action, jail, ip, dry_run }) => {
      try {
        if (action === "reload") {
          const fullCmd = "sudo fail2ban-client reload";

          if (dry_run ?? getConfig().dryRun) {
            const entry = createChangeEntry({
              tool: "log_fail2ban_manage",
              action: "[DRY-RUN] Reload fail2ban",
              target: "fail2ban",
              after: fullCmd,
              dryRun: true,
              success: true,
            });
            logChange(entry);

            return {
              content: [createTextContent(`[DRY-RUN] Would execute:\n  ${fullCmd}`)],
            };
          }

          const result = await executeCommand({
            command: "sudo",
            args: ["fail2ban-client", "reload"],
            toolName: "log_fail2ban_manage",
            timeout: getToolTimeout("auditd"),
          });

          const success = result.exitCode === 0;

          const entry = createChangeEntry({
            tool: "log_fail2ban_manage",
            action: "Reload fail2ban",
            target: "fail2ban",
            after: fullCmd,
            dryRun: false,
            success,
            error: success ? undefined : result.stderr,
          });
          logChange(entry);

          if (!success) {
            return {
              content: [createErrorContent(`fail2ban reload failed (exit ${result.exitCode}): ${result.stderr}`)],
              isError: true,
            };
          }

          return { content: [createTextContent("fail2ban reloaded successfully.")] };
        }

        // ban or unban require jail and ip
        if (!jail) {
          return {
            content: [createErrorContent(`Jail name is required for '${action}' action`)],
            isError: true,
          };
        }
        if (!ip) {
          return {
            content: [createErrorContent(`IP address is required for '${action}' action`)],
            isError: true,
          };
        }

        sanitizeArgs([jail]);
        validateTarget(ip);

        const subcommand = action === "ban" ? "banip" : "unbanip";
        const args = ["fail2ban-client", "set", jail, subcommand, ip];
        const fullCmd = `sudo ${args.join(" ")}`;
        const rollbackCmd = action === "ban"
          ? `sudo fail2ban-client set ${jail} unbanip ${ip}`
          : `sudo fail2ban-client set ${jail} banip ${ip}`;

        if (dry_run ?? getConfig().dryRun) {
          const entry = createChangeEntry({
            tool: "log_fail2ban_manage",
            action: `[DRY-RUN] ${action} IP in fail2ban`,
            target: `${jail}/${ip}`,
            after: fullCmd,
            dryRun: true,
            success: true,
            rollbackCommand: rollbackCmd,
          });
          logChange(entry);

          return {
            content: [createTextContent(`[DRY-RUN] Would execute:\n  ${fullCmd}\n\nRollback command:\n  ${rollbackCmd}`)],
          };
        }

        const result = await executeCommand({
          command: "sudo",
          args,
          toolName: "log_fail2ban_manage",
          timeout: getToolTimeout("auditd"),
        });

        const success = result.exitCode === 0;

        const entry = createChangeEntry({
          tool: "log_fail2ban_manage",
          action: `${action} IP in fail2ban`,
          target: `${jail}/${ip}`,
          after: fullCmd,
          dryRun: false,
          success,
          error: success ? undefined : result.stderr,
          rollbackCommand: rollbackCmd,
        });
        logChange(entry);

        if (!success) {
          return {
            content: [createErrorContent(`fail2ban ${action} failed (exit ${result.exitCode}): ${result.stderr}`)],
            isError: true,
          };
        }

        return {
          content: [createTextContent(`IP ${ip} ${action === "ban" ? "banned" : "unbanned"} in jail ${jail}.\nRollback: ${rollbackCmd}`)],
        };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 7. log_syslog_analyze ────────────────────────────────────────────

  server.tool(
    "log_syslog_analyze",
    "Analyze syslog for security-related events using pattern matching",
    {
      log_file: z
        .string()
        .optional()
        .describe("Path to the log file to analyze (auto-detected per distro if omitted)"),
      pattern: z
        .enum(["auth_failures", "ssh_brute", "privilege_escalation", "service_changes", "all"])
        .optional()
        .default("all")
        .describe("Security event pattern to search for"),
      lines: z.number().optional().default(500).describe("Maximum number of matching lines to return"),
    },
    async ({ log_file, pattern, lines }) => {
      try {
        // Resolve log file path: user-specified > distro adapter > fallbacks
        let effectiveLogFile: string;
        if (log_file) {
          effectiveLogFile = log_file;
        } else {
          const adapterPath = (await getDistroAdapter()).paths.syslog;
          const candidates = [adapterPath];
          if (adapterPath !== "/var/log/messages") candidates.push("/var/log/messages");
          if (adapterPath !== "/var/log/syslog") candidates.push("/var/log/syslog");

          const found = candidates.find((p) => existsSync(p));
          if (!found) {
            return {
              content: [createErrorContent(
                `No syslog file found (tried: ${candidates.join(", ")}). ` +
                `This system may use journald exclusively — use log_journalctl_query instead.`
              )],
              isError: true,
            };
          }
          effectiveLogFile = found;
        }

        // Build grep pattern based on selected type
        const patterns: Record<string, string> = {
          auth_failures: "authentication failure|Failed password|pam_unix.*failed",
          ssh_brute: "Failed password for|Invalid user|Connection closed by.*\\[preauth\\]",
          privilege_escalation: "sudo:|su\\[|su:|pkexec",
          service_changes: "systemd\\[.*Started|systemd\\[.*Stopped|systemd\\[.*Reloading",
        };

        let grepPattern: string;
        if (pattern === "all") {
          grepPattern = Object.values(patterns).join("|");
        } else {
          grepPattern = patterns[pattern] ?? patterns.auth_failures;
        }

        // Use grep -E with -m to limit matches, -c is count
        const args = ["-E", grepPattern, effectiveLogFile, "-m", String(lines)];

        const result = await executeCommand({
          command: "grep",
          args,
          toolName: "log_syslog_analyze",
          timeout: getToolTimeout("auditd"),
        });

        // grep exits with 1 when no matches found
        if (result.exitCode === 1 && result.stdout.trim() === "") {
          return {
            content: [createTextContent(`No matching security events found in ${effectiveLogFile} for pattern '${pattern}'.`)],
          };
        }

        if (result.exitCode !== 0 && result.exitCode !== 1) {
          return {
            content: [createErrorContent(`Log analysis failed (exit ${result.exitCode}): ${result.stderr}`)],
            isError: true,
          };
        }

        const matchedLines = result.stdout.trim().split("\n").filter((l) => l.length > 0);

        const output = {
          logFile: log_file,
          pattern,
          matchCount: matchedLines.length,
          maxLines: lines,
          matches: result.stdout,
        };

        return { content: [formatToolOutput(output)] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── log_auditd_cis_rules ─────────────────────────────────────────────
  server.tool(
    "log_auditd_cis_rules",
    "Check or deploy CIS Benchmark-required auditd rules covering time changes, identity modifications, network config, MAC policy, login/session, file access, and privileged commands.",
    {
      action: z.enum(["check", "generate"]).optional().default("check").describe("check: verify rules exist; generate: output required rules"),
    },
    async (params) => {
      try {
        const CIS_RULES = [
          { rule: "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change", description: "Record time changes (64-bit)" },
          { rule: "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change", description: "Record time changes (32-bit)" },
          { rule: "-w /etc/localtime -p wa -k time-change", description: "Record timezone changes" },
          { rule: "-w /etc/group -p wa -k identity", description: "Record group modifications" },
          { rule: "-w /etc/passwd -p wa -k identity", description: "Record user modifications" },
          { rule: "-w /etc/gshadow -p wa -k identity", description: "Record gshadow changes" },
          { rule: "-w /etc/shadow -p wa -k identity", description: "Record shadow changes" },
          { rule: "-w /etc/security/opasswd -p wa -k identity", description: "Record opasswd changes" },
          { rule: "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale", description: "Record hostname changes" },
          { rule: "-w /etc/issue -p wa -k system-locale", description: "Record issue changes" },
          { rule: "-w /etc/issue.net -p wa -k system-locale", description: "Record issue.net changes" },
          { rule: "-w /etc/hosts -p wa -k system-locale", description: "Record hosts changes" },
          { rule: "-w /etc/apparmor/ -p wa -k MAC-policy", description: "Record AppArmor changes" },
          { rule: "-w /etc/apparmor.d/ -p wa -k MAC-policy", description: "Record AppArmor profile changes" },
          { rule: "-w /var/log/faillog -p wa -k logins", description: "Record failed logins" },
          { rule: "-w /var/log/lastlog -p wa -k logins", description: "Record last logins" },
          { rule: "-w /var/log/tallylog -p wa -k logins", description: "Record tally logins" },
          { rule: "-w /var/run/utmp -p wa -k session", description: "Record utmp session changes" },
          { rule: "-w /var/log/wtmp -p wa -k logins", description: "Record wtmp login changes" },
          { rule: "-w /var/log/btmp -p wa -k logins", description: "Record btmp failed logins" },
          { rule: "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod", description: "Record permission changes" },
          { rule: "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts", description: "Record mount operations" },
          { rule: "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete", description: "Record file deletions" },
          { rule: "-w /etc/sudoers -p wa -k scope", description: "Record sudoers changes" },
          { rule: "-w /etc/sudoers.d/ -p wa -k scope", description: "Record sudoers.d changes" },
          { rule: "-w /var/log/sudo.log -p wa -k actions", description: "Record sudo log changes" },
          { rule: "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules", description: "Record kernel module operations" },
        ];

        if (params.action === "generate") {
          const rulesText = CIS_RULES.map(r => `# ${r.description}\n${r.rule}`).join("\n\n");
          return { content: [createTextContent(`# CIS Benchmark Required Audit Rules\n# Save to /etc/audit/rules.d/99-cis.rules\n# Then run: sudo augenrules --load\n\n${rulesText}\n\n# Make immutable (must be last rule)\n-e 2\n`)] };
        }

        // Check which rules exist
        const currentRules = await executeCommand({ command: "sudo", args: ["auditctl", "-l"], timeout: 10000, toolName: "log_auditd_cis_rules" });
        const existing = currentRules.stdout || "";

        const results = CIS_RULES.map(r => {
          const keyMatch = r.rule.match(/-k\s+(\S+)/);
          const key = keyMatch ? keyMatch[1] : "";
          const found = existing.includes(key) || r.rule.split(" ").every(part => part.startsWith("-") ? existing.includes(part) : true);
          return { description: r.description, rule: r.rule, present: found };
        });

        const present = results.filter(r => r.present).length;
        return { content: [createTextContent(JSON.stringify({ summary: { totalRequired: CIS_RULES.length, present, missing: CIS_RULES.length - present, compliancePercent: Math.round((present / CIS_RULES.length) * 100) }, results }, null, 2))] };
      } catch (error) {
        return { content: [createErrorContent(error instanceof Error ? error.message : String(error))], isError: true };
      }
    },
  );

  // ── log_rotation_audit ────────────────────────────────────────────────
  server.tool(
    "log_rotation_audit",
    "Audit log rotation configuration (logrotate) and journald persistence settings.",
    {},
    async () => {
      try {
        const findings: Array<{check: string, status: string, value: string, description: string}> = [];

        // Check logrotate installed and configured
        const lrResult = await executeCommand({ command: "cat", args: ["/etc/logrotate.conf"], timeout: 5000, toolName: "log_rotation_audit" });
        findings.push({ check: "logrotate_config", status: lrResult.exitCode === 0 ? "PASS" : "FAIL", value: lrResult.exitCode === 0 ? "present" : "missing", description: "logrotate main configuration" });

        if (lrResult.exitCode === 0) {
          const hasCompress = lrResult.stdout.includes("compress");
          findings.push({ check: "logrotate_compress", status: hasCompress ? "PASS" : "WARN", value: hasCompress ? "enabled" : "not set", description: "Log compression enabled" });
          const rotateMatch = lrResult.stdout.match(/rotate\s+(\d+)/);
          if (rotateMatch) {
            findings.push({ check: "logrotate_retention", status: parseInt(rotateMatch[1]) >= 4 ? "PASS" : "WARN", value: `${rotateMatch[1]} rotations`, description: "Log retention count" });
          }
        }

        // Check journald persistence
        const journaldResult = await executeCommand({ command: "cat", args: ["/etc/systemd/journald.conf"], timeout: 5000, toolName: "log_rotation_audit" });
        if (journaldResult.exitCode === 0) {
          const hasPersistent = journaldResult.stdout.includes("Storage=persistent");
          findings.push({ check: "journald_persistent", status: hasPersistent ? "PASS" : "WARN", value: hasPersistent ? "persistent" : "auto/volatile", description: "journald persistent storage (CIS recommends Storage=persistent)" });
          const compressMatch = journaldResult.stdout.match(/Compress=(yes|no)/i);
          findings.push({ check: "journald_compress", status: !compressMatch || compressMatch[1] === "yes" ? "PASS" : "WARN", value: compressMatch ? compressMatch[1] : "default (yes)", description: "journald compression" });
        }

        // Check if /var/log permissions are correct
        const logPerms = await executeCommand({ command: "stat", args: ["-c", "%a %U:%G", "/var/log"], timeout: 5000, toolName: "log_rotation_audit" });
        findings.push({ check: "var_log_permissions", status: logPerms.stdout.trim().startsWith("755") || logPerms.stdout.trim().startsWith("750") ? "PASS" : "WARN", value: logPerms.stdout.trim(), description: "/var/log directory permissions" });

        const passCount = findings.filter(f => f.status === "PASS").length;
        return { content: [createTextContent(JSON.stringify({ summary: { total: findings.length, pass: passCount, fail: findings.filter(f => f.status === "FAIL").length, warn: findings.filter(f => f.status === "WARN").length }, findings }, null, 2))] };
      } catch (error) {
        return { content: [createErrorContent(error instanceof Error ? error.message : String(error))], isError: true };
      }
    },
  );

  // ── log_fail2ban_audit ────────────────────────────────────────────────
  server.tool(
    "log_fail2ban_audit",
    "Audit fail2ban jail configurations for weak settings (short ban times, high maxretry, missing jails).",
    {},
    async () => {
      try {
        // Check if fail2ban is installed and running
        const statusResult = await executeCommand({ command: "sudo", args: ["fail2ban-client", "status"], timeout: 10000, toolName: "log_fail2ban_audit" });
        if (statusResult.exitCode !== 0) {
          return { content: [createTextContent(JSON.stringify({ installed: false, recommendation: "Install fail2ban: sudo apt install fail2ban && sudo systemctl enable fail2ban" }, null, 2))] };
        }

        // Parse jail list
        const jailLine = statusResult.stdout.match(/Jail list:\s*(.*)/);
        const jails = jailLine ? jailLine[1].split(",").map(j => j.trim()).filter(Boolean) : [];

        const findings: Array<{jail: string, setting: string, value: string, status: string, recommendation: string}> = [];

        // Check each jail
        for (const jail of jails) {
          const jailResult = await executeCommand({ command: "sudo", args: ["fail2ban-client", "get", jail, "bantime"], timeout: 5000, toolName: "log_fail2ban_audit" });
          const bantime = parseInt(jailResult.stdout.trim()) || 0;
          findings.push({ jail, setting: "bantime", value: `${bantime}s`, status: bantime >= 600 ? "PASS" : "WARN", recommendation: bantime < 600 ? "Increase bantime to at least 600s (10 min)" : "OK" });

          const maxRetryResult = await executeCommand({ command: "sudo", args: ["fail2ban-client", "get", jail, "maxretry"], timeout: 5000, toolName: "log_fail2ban_audit" });
          const maxRetry = parseInt(maxRetryResult.stdout.trim()) || 0;
          findings.push({ jail, setting: "maxretry", value: String(maxRetry), status: maxRetry <= 5 ? "PASS" : "WARN", recommendation: maxRetry > 5 ? "Reduce maxretry to 5 or less" : "OK" });

          const findtimeResult = await executeCommand({ command: "sudo", args: ["fail2ban-client", "get", jail, "findtime"], timeout: 5000, toolName: "log_fail2ban_audit" });
          const findtime = parseInt(findtimeResult.stdout.trim()) || 0;
          findings.push({ jail, setting: "findtime", value: `${findtime}s`, status: findtime >= 300 ? "PASS" : "WARN", recommendation: findtime < 300 ? "Increase findtime to at least 300s" : "OK" });
        }

        // Check for recommended jails
        const recommendedJails = ["sshd", "apache-auth", "nginx-http-auth", "postfix"];
        const missingJails = recommendedJails.filter(j => !jails.includes(j));

        return { content: [createTextContent(JSON.stringify({ installed: true, activeJails: jails.length, jails, missingRecommended: missingJails, findings, summary: { pass: findings.filter(f => f.status === "PASS").length, warn: findings.filter(f => f.status === "WARN").length } }, null, 2))] };
      } catch (error) {
        return { content: [createErrorContent(error instanceof Error ? error.message : String(error))], isError: true };
      }
    },
  );
}
