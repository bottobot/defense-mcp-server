/**
 * Logging and audit tools for Kali Defense MCP Server.
 *
 * Registers 4 tools:
 *   log_auditd (actions: rules, search, report, cis_rules)
 *   log_journalctl_query (kept as-is)
 *   log_fail2ban (actions: status, ban, unban, reload, audit)
 *   log_system (actions: analyze, rotation_audit)
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
  // ── 1. log_auditd (merged: rules, search, report, cis_rules) ─────────

  server.tool(
    "log_auditd",
    "Auditd management: manage rules, search logs, generate reports, or check CIS benchmark audit rules.",
    {
      action: z.enum(["rules", "search", "report", "cis_rules"]).describe("Action: rules=manage auditd rules, search=search audit logs, report=generate audit report, cis_rules=check/generate CIS rules"),
      // rules params
      rules_action: z.enum(["list", "add", "delete"]).optional().describe("Rule action (rules action)"),
      rule: z.string().optional().describe("Audit rule string (rules add/delete)"),
      // search params
      key: z.string().optional().describe("Audit key to search for (search action)"),
      syscall: z.string().optional().describe("System call name to filter (search action)"),
      uid: z.string().optional().describe("User ID to filter (search action)"),
      start: z.string().optional().describe("Start time e.g. 'today', '1 hour ago' (search/report action)"),
      end: z.string().optional().describe("End time (search action)"),
      success: z.enum(["yes", "no"]).optional().describe("Filter by success/failure (search action)"),
      limit: z.number().optional().default(50).describe("Maximum number of lines to return (search action)"),
      // report params
      report_type: z.enum(["summary", "auth", "login", "account", "event", "file", "exec"]).optional().default("summary").describe("Type of audit report (report action)"),
      // cis_rules params
      cis_action: z.enum(["check", "generate"]).optional().default("check").describe("check or generate CIS rules (cis_rules action)"),
      // shared
      dry_run: z.boolean().optional().describe("Preview the command without executing"),
    },
    async (params) => {
      const { action } = params;

      switch (action) {
        case "rules": {
          const { rules_action, rule, dry_run } = params;
          try {
            if (!rules_action) {
              return { content: [createErrorContent("rules_action is required for rules action (list/add/delete)")], isError: true };
            }

            if (rules_action === "list") {
              const result = await executeCommand({ command: "sudo", args: ["auditctl", "-l"], toolName: "log_auditd", timeout: getToolTimeout("auditd") });
              if (result.exitCode !== 0) return { content: [createErrorContent(`auditctl list failed (exit ${result.exitCode}): ${result.stderr}`)], isError: true };
              return { content: [createTextContent(`Current auditd rules:\n${result.stdout}`)] };
            }

            if (!rule) return { content: [createErrorContent(`A rule string is required for '${rules_action}' action`)], isError: true };

            const ruleTokens = rule.trim().split(/\s+/);
            sanitizeArgs(ruleTokens);

            let args: string[];
            if (rules_action === "add") {
              if (ruleTokens[0] === "-w") args = ["auditctl", ...ruleTokens];
              else if (ruleTokens[0] === "-a") args = ["auditctl", ...ruleTokens];
              else args = ["auditctl", "-a", ...ruleTokens];
            } else {
              if (ruleTokens[0] === "-w") args = ["auditctl", "-W", ...ruleTokens.slice(1)];
              else if (ruleTokens[0] === "-a") args = ["auditctl", "-d", ...ruleTokens.slice(1)];
              else args = ["auditctl", "-d", ...ruleTokens];
            }

            const fullCmd = `sudo ${args.join(" ")}`;

            if (dry_run ?? getConfig().dryRun) {
              logChange(createChangeEntry({ tool: "log_auditd", action: `[DRY-RUN] ${rules_action} auditd rule`, target: rule, after: fullCmd, dryRun: true, success: true }));
              return { content: [createTextContent(`[DRY-RUN] Would execute:\n  ${fullCmd}`)] };
            }

            const result = await executeCommand({ command: "sudo", args, toolName: "log_auditd", timeout: getToolTimeout("auditd") });
            const ok = result.exitCode === 0;
            logChange(createChangeEntry({ tool: "log_auditd", action: `${rules_action} auditd rule`, target: rule, after: fullCmd, dryRun: false, success: ok, error: ok ? undefined : result.stderr }));

            if (!ok) return { content: [createErrorContent(`auditctl ${rules_action} failed (exit ${result.exitCode}): ${result.stderr}`)], isError: true };
            return { content: [createTextContent(`Auditd rule ${rules_action === "add" ? "added" : "deleted"} successfully.\nCommand: ${fullCmd}`)] };
          } catch (err: unknown) {
            return { content: [createErrorContent(err instanceof Error ? err.message : String(err))], isError: true };
          }
        }

        case "search": {
          const { key, syscall, uid, start, end, success, limit: maxLines } = params;
          try {
            const args: string[] = ["ausearch"];
            if (key) { validateAuditdKey(key); args.push("-k", key); }
            if (syscall) { sanitizeArgs([syscall]); args.push("-sc", syscall); }
            if (uid) { sanitizeArgs([uid]); args.push("-ui", uid); }
            if (start) { sanitizeArgs([start]); args.push("--start", start); }
            if (end) { sanitizeArgs([end]); args.push("--end", end); }
            if (success) args.push("--success", success);
            args.push("--interpret");
            sanitizeArgs(args);

            const result = await executeCommand({ command: "sudo", args, toolName: "log_auditd", timeout: getToolTimeout("auditd") });

            if (result.exitCode !== 0 && !result.stderr.includes("no matches")) {
              return { content: [createErrorContent(`ausearch failed (exit ${result.exitCode}): ${result.stderr}`)], isError: true };
            }
            if (result.exitCode !== 0 && result.stderr.includes("no matches")) {
              return { content: [createTextContent("No matching audit records found.")] };
            }

            const lines = result.stdout.split("\n");
            const truncated = lines.slice(-maxLines).join("\n");
            const parsed = parseAuditdOutput(result.stdout);

            return { content: [formatToolOutput({ totalEntries: parsed.length, displayedLines: Math.min(lines.length, maxLines), entries: parsed.slice(-maxLines), raw: truncated })] };
          } catch (err: unknown) {
            return { content: [createErrorContent(err instanceof Error ? err.message : String(err))], isError: true };
          }
        }

        case "report": {
          const { report_type, start } = params;
          try {
            const args: string[] = ["aureport"];
            const reportFlags: Record<string, string> = { summary: "--summary", auth: "--auth", login: "--login", account: "--account-modifications", event: "--event", file: "--file", exec: "--executable" };
            args.push(reportFlags[report_type!] ?? "--summary");
            if (start) { sanitizeArgs([start]); args.push("--start", start); }
            sanitizeArgs(args);

            const result = await executeCommand({ command: "sudo", args, toolName: "log_auditd", timeout: getToolTimeout("auditd") });
            if (result.exitCode !== 0) return { content: [createErrorContent(`aureport failed (exit ${result.exitCode}): ${result.stderr}`)], isError: true };
            return { content: [createTextContent(`Audit Report (${report_type}):\n${"=".repeat(50)}\n${result.stdout}`)] };
          } catch (err: unknown) {
            return { content: [createErrorContent(err instanceof Error ? err.message : String(err))], isError: true };
          }
        }

        case "cis_rules": {
          const { cis_action } = params;
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

            if (cis_action === "generate") {
              const rulesText = CIS_RULES.map(r => `# ${r.description}\n${r.rule}`).join("\n\n");
              return { content: [createTextContent(`# CIS Benchmark Required Audit Rules\n# Save to /etc/audit/rules.d/99-cis.rules\n# Then run: sudo augenrules --load\n\n${rulesText}\n\n# Make immutable (must be last rule)\n-e 2\n`)] };
            }

            const currentRules = await executeCommand({ command: "sudo", args: ["auditctl", "-l"], timeout: 10000, toolName: "log_auditd" });
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
        }

        default:
          return { content: [createErrorContent(`Unknown action: ${action}`)], isError: true };
      }
    }
  );

  // ── 2. log_journalctl_query (kept as-is) ──────────────────────────────

  server.tool(
    "log_journalctl_query",
    "Query systemd journal for log entries with flexible filtering",
    {
      unit: z.string().optional().describe("Systemd unit name to filter"),
      priority: z.enum(["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]).optional().describe("Minimum priority level"),
      since: z.string().optional().describe("Start time, e.g. '1 hour ago', 'today', '2024-01-01'"),
      until: z.string().optional().describe("End time"),
      grep: z.string().optional().describe("Pattern to search for in log messages"),
      lines: z.number().optional().default(100).describe("Number of log lines to return"),
      output_format: z.enum(["short", "json", "cat", "verbose"]).optional().default("short").describe("Output format for journal entries"),
    },
    async ({ unit, priority, since, until, grep, lines, output_format }) => {
      try {
        const args: string[] = ["journalctl"];
        if (unit) { sanitizeArgs([unit]); args.push("--unit", unit); }
        if (priority) args.push("-p", priority);
        if (since) { sanitizeArgs([since]); args.push("--since", since); }
        if (until) { sanitizeArgs([until]); args.push("--until", until); }
        if (grep) { sanitizeArgs([grep]); args.push("-g", grep); }
        args.push("-n", String(lines));
        args.push("-o", output_format);
        args.push("--no-pager");
        sanitizeArgs(args);

        const result = await executeCommand({ command: "journalctl", args: args.slice(1), toolName: "log_journalctl_query", timeout: getToolTimeout("auditd") });
        if (result.exitCode !== 0) return { content: [createErrorContent(`journalctl query failed (exit ${result.exitCode}): ${result.stderr}`)], isError: true };
        return { content: [createTextContent(result.stdout)] };
      } catch (err: unknown) {
        return { content: [createErrorContent(err instanceof Error ? err.message : String(err))], isError: true };
      }
    }
  );

  // ── 3. log_fail2ban (merged: status, ban, unban, reload, audit) ───────

  server.tool(
    "log_fail2ban",
    "Fail2ban management: check status, ban/unban IPs, reload config, or audit jail configurations.",
    {
      action: z.enum(["status", "ban", "unban", "reload", "audit"]).describe("Action: status, ban, unban, reload, audit"),
      // status/ban/unban params
      jail: z.string().optional().describe("Jail name (status: optional, ban/unban: required)"),
      ip: z.string().optional().describe("IP address to ban or unban (ban/unban action)"),
      // shared
      dry_run: z.boolean().optional().describe("Preview without executing"),
    },
    async (params) => {
      const { action } = params;

      switch (action) {
        case "status": {
          const { jail } = params;
          try {
            const args: string[] = ["fail2ban-client", "status"];
            if (jail) { sanitizeArgs([jail]); args.push(jail); }

            const result = await executeCommand({ command: "sudo", args, toolName: "log_fail2ban", timeout: getToolTimeout("auditd") });
            if (result.exitCode !== 0) return { content: [createErrorContent(`fail2ban status failed (exit ${result.exitCode}): ${result.stderr}`)], isError: true };

            if (jail) {
              const parsed = parseFail2banOutput(result.stdout);
              return { content: [formatToolOutput({ jail, parsed, raw: result.stdout })] };
            }
            return { content: [createTextContent(result.stdout)] };
          } catch (err: unknown) {
            return { content: [createErrorContent(err instanceof Error ? err.message : String(err))], isError: true };
          }
        }

        case "ban":
        case "unban": {
          const { jail, ip, dry_run } = params;
          try {
            if (!jail) return { content: [createErrorContent(`Jail name is required for '${action}' action`)], isError: true };
            if (!ip) return { content: [createErrorContent(`IP address is required for '${action}' action`)], isError: true };

            sanitizeArgs([jail]);
            validateTarget(ip);

            const subcommand = action === "ban" ? "banip" : "unbanip";
            const args = ["fail2ban-client", "set", jail, subcommand, ip];
            const fullCmd = `sudo ${args.join(" ")}`;
            const rollbackCmd = action === "ban" ? `sudo fail2ban-client set ${jail} unbanip ${ip}` : `sudo fail2ban-client set ${jail} banip ${ip}`;

            if (dry_run ?? getConfig().dryRun) {
              logChange(createChangeEntry({ tool: "log_fail2ban", action: `[DRY-RUN] ${action} IP in fail2ban`, target: `${jail}/${ip}`, after: fullCmd, dryRun: true, success: true, rollbackCommand: rollbackCmd }));
              return { content: [createTextContent(`[DRY-RUN] Would execute:\n  ${fullCmd}\n\nRollback command:\n  ${rollbackCmd}`)] };
            }

            const result = await executeCommand({ command: "sudo", args, toolName: "log_fail2ban", timeout: getToolTimeout("auditd") });
            const ok = result.exitCode === 0;
            logChange(createChangeEntry({ tool: "log_fail2ban", action: `${action} IP in fail2ban`, target: `${jail}/${ip}`, after: fullCmd, dryRun: false, success: ok, error: ok ? undefined : result.stderr, rollbackCommand: rollbackCmd }));

            if (!ok) return { content: [createErrorContent(`fail2ban ${action} failed (exit ${result.exitCode}): ${result.stderr}`)], isError: true };
            return { content: [createTextContent(`IP ${ip} ${action === "ban" ? "banned" : "unbanned"} in jail ${jail}.\nRollback: ${rollbackCmd}`)] };
          } catch (err: unknown) {
            return { content: [createErrorContent(err instanceof Error ? err.message : String(err))], isError: true };
          }
        }

        case "reload": {
          const { dry_run } = params;
          try {
            const fullCmd = "sudo fail2ban-client reload";

            if (dry_run ?? getConfig().dryRun) {
              logChange(createChangeEntry({ tool: "log_fail2ban", action: "[DRY-RUN] Reload fail2ban", target: "fail2ban", after: fullCmd, dryRun: true, success: true }));
              return { content: [createTextContent(`[DRY-RUN] Would execute:\n  ${fullCmd}`)] };
            }

            const result = await executeCommand({ command: "sudo", args: ["fail2ban-client", "reload"], toolName: "log_fail2ban", timeout: getToolTimeout("auditd") });
            const ok = result.exitCode === 0;
            logChange(createChangeEntry({ tool: "log_fail2ban", action: "Reload fail2ban", target: "fail2ban", after: fullCmd, dryRun: false, success: ok, error: ok ? undefined : result.stderr }));

            if (!ok) return { content: [createErrorContent(`fail2ban reload failed (exit ${result.exitCode}): ${result.stderr}`)], isError: true };
            return { content: [createTextContent("fail2ban reloaded successfully.")] };
          } catch (err: unknown) {
            return { content: [createErrorContent(err instanceof Error ? err.message : String(err))], isError: true };
          }
        }

        case "audit": {
          try {
            const statusResult = await executeCommand({ command: "sudo", args: ["fail2ban-client", "status"], timeout: 10000, toolName: "log_fail2ban" });
            if (statusResult.exitCode !== 0) {
              return { content: [createTextContent(JSON.stringify({ installed: false, recommendation: "Install fail2ban: sudo apt install fail2ban && sudo systemctl enable fail2ban" }, null, 2))] };
            }

            const jailLine = statusResult.stdout.match(/Jail list:\s*(.*)/);
            const jails = jailLine ? jailLine[1].split(",").map(j => j.trim()).filter(Boolean) : [];

            const findings: Array<{jail: string, setting: string, value: string, status: string, recommendation: string}> = [];

            for (const jail of jails) {
              const jailResult = await executeCommand({ command: "sudo", args: ["fail2ban-client", "get", jail, "bantime"], timeout: 5000, toolName: "log_fail2ban" });
              const bantime = parseInt(jailResult.stdout.trim()) || 0;
              findings.push({ jail, setting: "bantime", value: `${bantime}s`, status: bantime >= 600 ? "PASS" : "WARN", recommendation: bantime < 600 ? "Increase bantime to at least 600s (10 min)" : "OK" });

              const maxRetryResult = await executeCommand({ command: "sudo", args: ["fail2ban-client", "get", jail, "maxretry"], timeout: 5000, toolName: "log_fail2ban" });
              const maxRetry = parseInt(maxRetryResult.stdout.trim()) || 0;
              findings.push({ jail, setting: "maxretry", value: String(maxRetry), status: maxRetry <= 5 ? "PASS" : "WARN", recommendation: maxRetry > 5 ? "Reduce maxretry to 5 or less" : "OK" });

              const findtimeResult = await executeCommand({ command: "sudo", args: ["fail2ban-client", "get", jail, "findtime"], timeout: 5000, toolName: "log_fail2ban" });
              const findtime = parseInt(findtimeResult.stdout.trim()) || 0;
              findings.push({ jail, setting: "findtime", value: `${findtime}s`, status: findtime >= 300 ? "PASS" : "WARN", recommendation: findtime < 300 ? "Increase findtime to at least 300s" : "OK" });
            }

            const recommendedJails = ["sshd", "apache-auth", "nginx-http-auth", "postfix"];
            const missingJails = recommendedJails.filter(j => !jails.includes(j));

            return { content: [createTextContent(JSON.stringify({ installed: true, activeJails: jails.length, jails, missingRecommended: missingJails, findings, summary: { pass: findings.filter(f => f.status === "PASS").length, warn: findings.filter(f => f.status === "WARN").length } }, null, 2))] };
          } catch (error) {
            return { content: [createErrorContent(error instanceof Error ? error.message : String(error))], isError: true };
          }
        }

        default:
          return { content: [createErrorContent(`Unknown action: ${action}`)], isError: true };
      }
    }
  );

  // ── 4. log_system (merged: syslog_analyze + rotation_audit) ───────────

  server.tool(
    "log_system",
    "System log analysis: analyze syslog for security events or audit log rotation configuration.",
    {
      action: z.enum(["analyze", "rotation_audit"]).describe("Action: analyze=analyze syslog, rotation_audit=audit logrotate/journald"),
      // analyze params
      log_file: z.string().optional().describe("Path to the log file (analyze action)"),
      pattern: z.enum(["auth_failures", "ssh_brute", "privilege_escalation", "service_changes", "all"]).optional().default("all").describe("Security event pattern (analyze action)"),
      lines: z.number().optional().default(500).describe("Maximum number of matching lines (analyze action)"),
    },
    async (params) => {
      const { action } = params;

      switch (action) {
        case "analyze": {
          const { log_file, pattern, lines: maxLines } = params;
          try {
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
                return { content: [createErrorContent(`No syslog file found (tried: ${candidates.join(", ")}). This system may use journald exclusively — use log_journalctl_query instead.`)], isError: true };
              }
              effectiveLogFile = found;
            }

            const patterns: Record<string, string> = {
              auth_failures: "authentication failure|Failed password|pam_unix.*failed",
              ssh_brute: "Failed password for|Invalid user|Connection closed by.*\\[preauth\\]",
              privilege_escalation: "sudo:|su\\[|su:|pkexec",
              service_changes: "systemd\\[.*Started|systemd\\[.*Stopped|systemd\\[.*Reloading",
            };

            const grepPattern = pattern === "all" ? Object.values(patterns).join("|") : (patterns[pattern!] ?? patterns.auth_failures);
            const args = ["-E", grepPattern, effectiveLogFile, "-m", String(maxLines)];

            const result = await executeCommand({ command: "grep", args, toolName: "log_system", timeout: getToolTimeout("auditd") });

            if (result.exitCode === 1 && result.stdout.trim() === "") {
              return { content: [createTextContent(`No matching security events found in ${effectiveLogFile} for pattern '${pattern}'.`)] };
            }

            if (result.exitCode !== 0 && result.exitCode !== 1) {
              return { content: [createErrorContent(`Log analysis failed (exit ${result.exitCode}): ${result.stderr}`)], isError: true };
            }

            const matchedLines = result.stdout.trim().split("\n").filter((l) => l.length > 0);
            return { content: [formatToolOutput({ logFile: log_file, pattern, matchCount: matchedLines.length, maxLines, matches: result.stdout })] };
          } catch (err: unknown) {
            return { content: [createErrorContent(err instanceof Error ? err.message : String(err))], isError: true };
          }
        }

        case "rotation_audit": {
          try {
            const findings: Array<{check: string, status: string, value: string, description: string}> = [];

            const lrResult = await executeCommand({ command: "cat", args: ["/etc/logrotate.conf"], timeout: 5000, toolName: "log_system" });
            findings.push({ check: "logrotate_config", status: lrResult.exitCode === 0 ? "PASS" : "FAIL", value: lrResult.exitCode === 0 ? "present" : "missing", description: "logrotate main configuration" });

            if (lrResult.exitCode === 0) {
              const hasCompress = lrResult.stdout.includes("compress");
              findings.push({ check: "logrotate_compress", status: hasCompress ? "PASS" : "WARN", value: hasCompress ? "enabled" : "not set", description: "Log compression enabled" });
              const rotateMatch = lrResult.stdout.match(/rotate\s+(\d+)/);
              if (rotateMatch) {
                findings.push({ check: "logrotate_retention", status: parseInt(rotateMatch[1]) >= 4 ? "PASS" : "WARN", value: `${rotateMatch[1]} rotations`, description: "Log retention count" });
              }
            }

            const journaldResult = await executeCommand({ command: "cat", args: ["/etc/systemd/journald.conf"], timeout: 5000, toolName: "log_system" });
            if (journaldResult.exitCode === 0) {
              const hasPersistent = journaldResult.stdout.includes("Storage=persistent");
              findings.push({ check: "journald_persistent", status: hasPersistent ? "PASS" : "WARN", value: hasPersistent ? "persistent" : "auto/volatile", description: "journald persistent storage (CIS recommends Storage=persistent)" });
              const compressMatch = journaldResult.stdout.match(/Compress=(yes|no)/i);
              findings.push({ check: "journald_compress", status: !compressMatch || compressMatch[1] === "yes" ? "PASS" : "WARN", value: compressMatch ? compressMatch[1] : "default (yes)", description: "journald compression" });
            }

            const logPerms = await executeCommand({ command: "stat", args: ["-c", "%a %U:%G", "/var/log"], timeout: 5000, toolName: "log_system" });
            findings.push({ check: "var_log_permissions", status: logPerms.stdout.trim().startsWith("755") || logPerms.stdout.trim().startsWith("750") ? "PASS" : "WARN", value: logPerms.stdout.trim(), description: "/var/log directory permissions" });

            const passCount = findings.filter(f => f.status === "PASS").length;
            return { content: [createTextContent(JSON.stringify({ summary: { total: findings.length, pass: passCount, fail: findings.filter(f => f.status === "FAIL").length, warn: findings.filter(f => f.status === "WARN").length }, findings }, null, 2))] };
          } catch (error) {
            return { content: [createErrorContent(error instanceof Error ? error.message : String(error))], isError: true };
          }
        }

        default:
          return { content: [createErrorContent(`Unknown action: ${action}`)], isError: true };
      }
    }
  );
}
