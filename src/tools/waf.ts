/**
 * WAF (Web Application Firewall) management tools for Defense MCP Server.
 *
 * Registers 1 tool: waf_manage (actions: modsec_audit, modsec_rules,
 * rate_limit_config, owasp_crs_deploy, blocked_requests)
 *
 * Provides ModSecurity WAF auditing, rule management, rate limiting
 * configuration, OWASP CRS deployment checks, and blocked request analysis.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { spawnSafe } from "../core/spawn-safe.js";
import {
  createTextContent,
  createErrorContent,
  formatToolOutput,
} from "../core/parsers.js";
import type { ChildProcess } from "node:child_process";

// ── Constants ──────────────────────────────────────────────────────────────────

const MODSEC_CONF_PATHS: Record<string, string[]> = {
  nginx: [
    "/etc/modsecurity/modsecurity.conf",
    "/etc/nginx/modsecurity.conf",
    "/etc/nginx/modsec/modsecurity.conf",
  ],
  apache: [
    "/etc/modsecurity/modsecurity.conf",
    "/etc/apache2/mods-enabled/security2.conf",
    "/etc/httpd/conf.d/mod_security.conf",
  ],
};

const MODSEC_RULES_DIRS = [
  "/etc/modsecurity/rules",
  "/usr/share/modsecurity-crs/rules",
  "/etc/modsecurity-crs/rules",
];

const MODSEC_AUDIT_LOG_PATHS = [
  "/var/log/modsecurity/modsec_audit.log",
  "/var/log/modsec_audit.log",
  "/var/log/apache2/modsec_audit.log",
  "/var/log/nginx/modsec_audit.log",
];

const OWASP_CRS_PATHS = [
  "/usr/share/modsecurity-crs",
  "/etc/modsecurity-crs",
  "/opt/owasp-crs",
  "/etc/modsecurity/crs",
];

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

// ── Action Implementations ─────────────────────────────────────────────────────

/**
 * Audit ModSecurity WAF configuration.
 */
async function handleModsecAudit(
  webServer: string,
  outputFormat: string,
): Promise<{ content: Array<{ type: "text"; text: string }>; isError?: boolean }> {
  try {
    const sections: string[] = [];
    const jsonData: Record<string, unknown> = {};

    sections.push("🛡️ ModSecurity WAF Audit");
    sections.push("=".repeat(55));
    sections.push(`Web Server: ${webServer}`);

    // Check if ModSecurity is installed
    const dpkgCheck = await runCommand("dpkg", ["-l", "libapache2-mod-security2"]);
    const modsecNginxCheck = await runCommand("dpkg", ["-l", "libnginx-mod-security"]);
    const whichCheck = await runCommand("which", ["modsecurity-check"]);

    const isInstalled =
      dpkgCheck.exitCode === 0 ||
      modsecNginxCheck.exitCode === 0 ||
      whichCheck.exitCode === 0;

    jsonData.installed = isInstalled;
    sections.push(`\n── Installation Status ──`);

    if (!isInstalled) {
      // Check for config file existence as fallback
      const confPaths = MODSEC_CONF_PATHS[webServer] || MODSEC_CONF_PATHS.nginx;
      let configFound = false;
      for (const confPath of confPaths) {
        const testResult = await runCommand("test", ["-f", confPath]);
        if (testResult.exitCode === 0) {
          configFound = true;
          sections.push(`  ⚠️ ModSecurity package not found via dpkg, but config exists: ${confPath}`);
          break;
        }
      }
      if (!configFound) {
        sections.push("  ❌ ModSecurity is NOT installed");
        sections.push("  Install with:");
        if (webServer === "nginx") {
          sections.push("    sudo apt install libnginx-mod-security");
        } else {
          sections.push("    sudo apt install libapache2-mod-security2");
        }
        jsonData.engine_mode = "not_installed";

        if (outputFormat === "json") {
          return { content: [formatToolOutput(jsonData)] };
        }
        return { content: [createTextContent(sections.join("\n"))] };
      }
    } else {
      sections.push("  ✅ ModSecurity is installed");
    }

    // Read ModSecurity configuration
    const confPaths = MODSEC_CONF_PATHS[webServer] || MODSEC_CONF_PATHS.nginx;
    let configContent = "";
    let activeConfPath = "";

    for (const confPath of confPaths) {
      const catResult = await runSudoCommand("cat", [confPath]);
      if (catResult.exitCode === 0 && catResult.stdout.trim().length > 0) {
        configContent = catResult.stdout;
        activeConfPath = confPath;
        break;
      }
    }

    sections.push(`\n── Configuration ──`);
    if (activeConfPath) {
      sections.push(`  Config file: ${activeConfPath}`);
      jsonData.config_path = activeConfPath;

      // Check SecRuleEngine status
      const engineMatch = configContent.match(/^\s*SecRuleEngine\s+(\S+)/m);
      const engineMode = engineMatch ? engineMatch[1] : "unknown";
      jsonData.engine_mode = engineMode;

      if (engineMode === "On") {
        sections.push("  ✅ SecRuleEngine: On (active protection)");
      } else if (engineMode === "DetectionOnly") {
        sections.push("  ⚠️ SecRuleEngine: DetectionOnly (logging only, not blocking)");
      } else if (engineMode === "Off") {
        sections.push("  ❌ SecRuleEngine: Off (WAF disabled!)");
      } else {
        sections.push(`  ❓ SecRuleEngine: ${engineMode}`);
      }

      // Check audit logging
      const auditLogMatch = configContent.match(/^\s*SecAuditLog\s+(\S+)/m);
      const auditLog = auditLogMatch ? auditLogMatch[1] : "not configured";
      jsonData.audit_log = auditLog;
      sections.push(`  Audit Log: ${auditLog}`);

      const auditEngineMatch = configContent.match(/^\s*SecAuditEngine\s+(\S+)/m);
      const auditEngine = auditEngineMatch ? auditEngineMatch[1] : "not set";
      jsonData.audit_engine = auditEngine;
      sections.push(`  Audit Engine: ${auditEngine}`);

      // Count rules
      const ruleCount = (configContent.match(/SecRule\s/g) || []).length;
      jsonData.inline_rule_count = ruleCount;
      sections.push(`  Inline Rules: ${ruleCount}`);

      // Check for common misconfigurations
      sections.push(`\n── Misconfiguration Checks ──`);
      const issues: string[] = [];

      if (engineMode === "Off") {
        issues.push("SecRuleEngine is Off — WAF provides no protection");
      }
      if (auditEngine === "Off" || auditEngine === "not set") {
        issues.push("Audit logging is disabled — no visibility into blocked requests");
      }
      if (!configContent.includes("SecRequestBodyAccess")) {
        issues.push("SecRequestBodyAccess not configured — POST body inspection may be disabled");
      }
      if (!configContent.includes("SecResponseBodyAccess")) {
        issues.push("SecResponseBodyAccess not configured — response inspection may be disabled");
      }
      if (configContent.includes("SecRuleRemoveById")) {
        const removedCount = (configContent.match(/SecRuleRemoveById/g) || []).length;
        issues.push(`${removedCount} rule(s) disabled via SecRuleRemoveById — review for necessity`);
      }

      jsonData.issues = issues;
      if (issues.length === 0) {
        sections.push("  ✅ No common misconfigurations detected");
      } else {
        for (const issue of issues) {
          sections.push(`  ⚠️ ${issue}`);
        }
      }
    } else {
      sections.push("  ❌ No ModSecurity configuration file found");
      sections.push("  Searched paths:");
      for (const p of confPaths) {
        sections.push(`    - ${p}`);
      }
      jsonData.config_path = null;
      jsonData.engine_mode = "no_config";
    }

    if (outputFormat === "json") {
      return { content: [formatToolOutput(jsonData)] };
    }
    return { content: [createTextContent(sections.join("\n"))] };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { content: [createErrorContent(`ModSecurity audit failed: ${msg}`)], isError: true };
  }
}

/**
 * Manage ModSecurity rules.
 */
async function handleModsecRules(
  ruleAction: string,
  ruleId: string | undefined,
  webServer: string,
  outputFormat: string,
): Promise<{ content: Array<{ type: "text"; text: string }>; isError?: boolean }> {
  try {
    const sections: string[] = [];
    const jsonData: Record<string, unknown> = {};

    sections.push("📋 ModSecurity Rules Management");
    sections.push("=".repeat(55));

    switch (ruleAction) {
      case "list": {
        sections.push("\n── Loaded Rule Files ──");
        const allFiles: string[] = [];

        for (const rulesDir of MODSEC_RULES_DIRS) {
          const lsResult = await runSudoCommand("ls", ["-la", rulesDir]);
          if (lsResult.exitCode === 0) {
            sections.push(`\n  Directory: ${rulesDir}`);
            const files = lsResult.stdout
              .split("\n")
              .filter((line) => line.includes(".conf"))
              .map((line) => {
                const parts = line.trim().split(/\s+/);
                return parts[parts.length - 1];
              })
              .filter((f) => f && f.endsWith(".conf"));

            for (const file of files) {
              sections.push(`    📄 ${file}`);
              allFiles.push(`${rulesDir}/${file}`);
            }

            if (files.length === 0) {
              sections.push("    (no .conf rule files found)");
            }
          }
        }

        jsonData.rule_files = allFiles;
        jsonData.total_files = allFiles.length;

        if (allFiles.length === 0) {
          sections.push("\n  ❌ No rule files found in standard directories");
          sections.push("  Searched:");
          for (const d of MODSEC_RULES_DIRS) {
            sections.push(`    - ${d}`);
          }
        } else {
          sections.push(`\n  Total rule files: ${allFiles.length}`);
        }
        break;
      }

      case "enable":
      case "disable": {
        if (!ruleId) {
          return {
            content: [createErrorContent("rule_id is required for enable/disable actions")],
            isError: true,
          };
        }

        sections.push(`\n  Action: ${ruleAction} rule ${ruleId}`);
        jsonData.rule_id = ruleId;
        jsonData.action = ruleAction;

        // Find the active config file
        const confPaths = MODSEC_CONF_PATHS[webServer] || MODSEC_CONF_PATHS.nginx;
        let activeConfPath = "";
        let configContent = "";

        for (const confPath of confPaths) {
          const catResult = await runSudoCommand("cat", [confPath]);
          if (catResult.exitCode === 0 && catResult.stdout.trim().length > 0) {
            configContent = catResult.stdout;
            activeConfPath = confPath;
            break;
          }
        }

        if (!activeConfPath) {
          return {
            content: [createErrorContent("No ModSecurity configuration file found")],
            isError: true,
          };
        }

        const removeDirective = `SecRuleRemoveById ${ruleId}`;
        const hasRemoveDirective = configContent.includes(removeDirective);

        if (ruleAction === "disable") {
          if (hasRemoveDirective) {
            sections.push(`  ℹ️ Rule ${ruleId} is already disabled`);
            jsonData.status = "already_disabled";
          } else {
            // Append SecRuleRemoveById to config
            const appendResult = await runSudoCommand("sh", [
              "-c",
              `echo '${removeDirective}' >> ${activeConfPath}`,
            ]);
            if (appendResult.exitCode === 0) {
              sections.push(`  ✅ Rule ${ruleId} disabled (added ${removeDirective})`);
              sections.push(`  Config: ${activeConfPath}`);
              sections.push(`  ⚠️ Reload ${webServer} to apply: sudo systemctl reload ${webServer}`);
              jsonData.status = "disabled";
            } else {
              sections.push(`  ❌ Failed to disable rule: ${appendResult.stderr}`);
              jsonData.status = "error";
              jsonData.error = appendResult.stderr;
            }
          }
        } else {
          // enable — remove the SecRuleRemoveById directive
          if (!hasRemoveDirective) {
            sections.push(`  ℹ️ Rule ${ruleId} is already enabled (no removal directive found)`);
            jsonData.status = "already_enabled";
          } else {
            const sedResult = await runSudoCommand("sed", [
              "-i",
              `/${removeDirective}/d`,
              activeConfPath,
            ]);
            if (sedResult.exitCode === 0) {
              sections.push(`  ✅ Rule ${ruleId} enabled (removed ${removeDirective})`);
              sections.push(`  Config: ${activeConfPath}`);
              sections.push(`  ⚠️ Reload ${webServer} to apply: sudo systemctl reload ${webServer}`);
              jsonData.status = "enabled";
            } else {
              sections.push(`  ❌ Failed to enable rule: ${sedResult.stderr}`);
              jsonData.status = "error";
              jsonData.error = sedResult.stderr;
            }
          }
        }
        break;
      }

      default:
        return {
          content: [createErrorContent(`Unknown rule_action: ${ruleAction}. Use list, enable, or disable.`)],
          isError: true,
        };
    }

    if (outputFormat === "json") {
      return { content: [formatToolOutput(jsonData)] };
    }
    return { content: [createTextContent(sections.join("\n"))] };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { content: [createErrorContent(`ModSecurity rules management failed: ${msg}`)], isError: true };
  }
}

/**
 * Configure rate limiting at the web server level.
 */
async function handleRateLimitConfig(
  webServer: string,
  rateLimit: number | undefined,
  rateLimitZone: string | undefined,
  outputFormat: string,
): Promise<{ content: Array<{ type: "text"; text: string }>; isError?: boolean }> {
  try {
    const sections: string[] = [];
    const jsonData: Record<string, unknown> = {};

    sections.push("⚡ Rate Limiting Configuration");
    sections.push("=".repeat(55));
    sections.push(`Web Server: ${webServer}`);

    jsonData.web_server = webServer;

    if (webServer === "nginx") {
      // Check current nginx rate limiting configuration
      const nginxConf = await runSudoCommand("cat", ["/etc/nginx/nginx.conf"]);
      const sitesResult = await runSudoCommand("ls", ["/etc/nginx/sites-enabled/"]);

      sections.push("\n── Current Rate Limiting (nginx) ──");

      if (nginxConf.exitCode === 0) {
        const content = nginxConf.stdout;

        // Find limit_req_zone directives
        const zoneMatches = content.match(/limit_req_zone\s+[^;]+;/g) || [];
        const reqMatches = content.match(/limit_req\s+[^;]+;/g) || [];

        jsonData.limit_req_zones = zoneMatches.map((z) => z.trim());
        jsonData.limit_req_directives = reqMatches.map((r) => r.trim());

        if (zoneMatches.length > 0) {
          sections.push("  Rate limit zones defined:");
          for (const zone of zoneMatches) {
            sections.push(`    📊 ${zone.trim()}`);
          }
        } else {
          sections.push("  ❌ No limit_req_zone directives found");
        }

        if (reqMatches.length > 0) {
          sections.push("  Rate limit enforcement:");
          for (const req of reqMatches) {
            sections.push(`    🔒 ${req.trim()}`);
          }
        } else {
          sections.push("  ❌ No limit_req directives found");
        }
      } else {
        sections.push("  ❌ Could not read /etc/nginx/nginx.conf");
        jsonData.error = "Could not read nginx config";
      }

      // Suggest configuration
      sections.push("\n── Recommended Configuration ──");
      const effectiveRate = rateLimit ?? 10;
      const effectiveZone = rateLimitZone ?? "default";

      sections.push("  Add to http {} block in nginx.conf:");
      sections.push(`    limit_req_zone $binary_remote_addr zone=${effectiveZone}:10m rate=${effectiveRate}r/s;`);
      sections.push("  Add to server {} or location {} block:");
      sections.push(`    limit_req zone=${effectiveZone} burst=${effectiveRate * 2} nodelay;`);
      sections.push("    limit_req_status 429;");

      jsonData.suggested_rate = effectiveRate;
      jsonData.suggested_zone = effectiveZone;
    } else {
      // Apache rate limiting
      sections.push("\n── Current Rate Limiting (Apache) ──");

      // Check for mod_ratelimit
      const ratelimitCheck = await runCommand("apache2ctl", ["-M"]);
      let hasRatelimit = false;
      let hasEvasive = false;

      if (ratelimitCheck.exitCode === 0) {
        hasRatelimit = ratelimitCheck.stdout.includes("ratelimit_module");
        hasEvasive = ratelimitCheck.stdout.includes("evasive");
      }

      jsonData.mod_ratelimit = hasRatelimit;
      jsonData.mod_evasive = hasEvasive;

      sections.push(`  mod_ratelimit: ${hasRatelimit ? "✅ loaded" : "❌ not loaded"}`);
      sections.push(`  mod_evasive: ${hasEvasive ? "✅ loaded" : "❌ not loaded"}`);

      if (hasEvasive) {
        const evasiveConf = await runSudoCommand("cat", ["/etc/apache2/mods-enabled/evasive.conf"]);
        if (evasiveConf.exitCode === 0) {
          sections.push("\n  mod_evasive configuration:");
          for (const line of evasiveConf.stdout.split("\n")) {
            const trimmed = line.trim();
            if (trimmed && !trimmed.startsWith("#")) {
              sections.push(`    ${trimmed}`);
            }
          }
        }
      }

      sections.push("\n── Recommended Configuration ──");
      const effectiveRate = rateLimit ?? 10;

      if (!hasEvasive) {
        sections.push("  Install mod_evasive:");
        sections.push("    sudo apt install libapache2-mod-evasive");
        sections.push("    sudo a2enmod evasive");
      }
      sections.push("  Recommended /etc/apache2/mods-enabled/evasive.conf:");
      sections.push("    <IfModule mod_evasive20.c>");
      sections.push(`      DOSPageCount ${effectiveRate}`);
      sections.push(`      DOSSiteCount ${effectiveRate * 5}`);
      sections.push("      DOSPageInterval 1");
      sections.push("      DOSSiteInterval 1");
      sections.push("      DOSBlockingPeriod 60");
      sections.push("    </IfModule>");

      jsonData.suggested_rate = effectiveRate;
    }

    if (outputFormat === "json") {
      return { content: [formatToolOutput(jsonData)] };
    }
    return { content: [createTextContent(sections.join("\n"))] };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { content: [createErrorContent(`Rate limit configuration failed: ${msg}`)], isError: true };
  }
}

/**
 * Check OWASP Core Rule Set deployment status.
 */
async function handleOwaspCrsDeploy(
  webServer: string,
  outputFormat: string,
): Promise<{ content: Array<{ type: "text"; text: string }>; isError?: boolean }> {
  try {
    const sections: string[] = [];
    const jsonData: Record<string, unknown> = {};

    sections.push("🌐 OWASP Core Rule Set (CRS) Status");
    sections.push("=".repeat(55));

    // Check if CRS is installed
    let crsPath = "";
    for (const path of OWASP_CRS_PATHS) {
      const testResult = await runCommand("test", ["-d", path]);
      if (testResult.exitCode === 0) {
        crsPath = path;
        break;
      }
    }

    jsonData.installed = !!crsPath;
    jsonData.crs_path = crsPath || null;

    if (!crsPath) {
      sections.push("\n  ❌ OWASP CRS is NOT installed");
      sections.push("\n── Installation Instructions ──");
      sections.push("  Option 1 — Package manager:");
      sections.push("    sudo apt install modsecurity-crs");
      sections.push("  Option 2 — Git (latest version):");
      sections.push("    sudo git clone https://github.com/coreruleset/coreruleset.git /usr/share/modsecurity-crs");
      sections.push("    sudo cp /usr/share/modsecurity-crs/crs-setup.conf.example /usr/share/modsecurity-crs/crs-setup.conf");
      sections.push("\n  After installation, add to ModSecurity config:");
      sections.push("    Include /usr/share/modsecurity-crs/crs-setup.conf");
      sections.push("    Include /usr/share/modsecurity-crs/rules/*.conf");

      if (outputFormat === "json") {
        return { content: [formatToolOutput(jsonData)] };
      }
      return { content: [createTextContent(sections.join("\n"))] };
    }

    sections.push(`\n  ✅ CRS found at: ${crsPath}`);

    // Check version
    const changelogResult = await runCommand("head", ["-5", `${crsPath}/CHANGES`]);
    const versionFileResult = await runCommand("cat", [`${crsPath}/VERSION`]);

    let version = "unknown";
    if (versionFileResult.exitCode === 0 && versionFileResult.stdout.trim()) {
      version = versionFileResult.stdout.trim();
    } else if (changelogResult.exitCode === 0) {
      const versionMatch = changelogResult.stdout.match(/(\d+\.\d+\.\d+)/);
      if (versionMatch) version = versionMatch[1];
    }

    jsonData.version = version;
    sections.push(`  Version: ${version}`);

    // Check CRS setup file for paranoia level
    const setupConf = await runSudoCommand("cat", [`${crsPath}/crs-setup.conf`]);
    let paranoiaLevel = "1 (default)";
    if (setupConf.exitCode === 0) {
      const plMatch = setupConf.stdout.match(/^\s*SecAction\s.*setvar:'tx\.paranoia_level=(\d+)'/m);
      if (plMatch) {
        paranoiaLevel = plMatch[1];
      }
    }

    jsonData.paranoia_level = paranoiaLevel;
    sections.push(`  Paranoia Level: ${paranoiaLevel}`);

    // Check integration with ModSecurity
    sections.push("\n── Integration Check ──");
    const confPaths = MODSEC_CONF_PATHS[webServer] || MODSEC_CONF_PATHS.nginx;
    let integrated = false;

    for (const confPath of confPaths) {
      const confContent = await runSudoCommand("cat", [confPath]);
      if (confContent.exitCode === 0) {
        if (confContent.stdout.includes("modsecurity-crs") || confContent.stdout.includes("crs-setup")) {
          integrated = true;
          sections.push(`  ✅ CRS Include directives found in ${confPath}`);
          break;
        }
      }
    }

    // Also check for include in main nginx/apache conf
    if (!integrated) {
      const mainConf = webServer === "nginx"
        ? await runSudoCommand("cat", ["/etc/nginx/nginx.conf"])
        : await runSudoCommand("cat", ["/etc/apache2/apache2.conf"]);

      if (mainConf.exitCode === 0 && (mainConf.stdout.includes("modsecurity-crs") || mainConf.stdout.includes("crs-setup"))) {
        integrated = true;
        sections.push("  ✅ CRS Include directives found in main config");
      }
    }

    jsonData.integrated = integrated;
    if (!integrated) {
      sections.push("  ❌ CRS Include directives NOT found in ModSecurity configuration");
      sections.push("  Add these lines to your ModSecurity configuration:");
      sections.push(`    Include ${crsPath}/crs-setup.conf`);
      sections.push(`    Include ${crsPath}/rules/*.conf`);
    }

    // List active rule categories
    sections.push("\n── Active Rule Categories ──");
    const rulesDir = `${crsPath}/rules`;
    const rulesList = await runCommand("ls", [rulesDir]);
    const categories: string[] = [];

    if (rulesList.exitCode === 0) {
      const ruleFiles = rulesList.stdout
        .split("\n")
        .filter((f) => f.endsWith(".conf"))
        .sort();

      for (const file of ruleFiles) {
        categories.push(file);
        sections.push(`    📄 ${file}`);
      }
    }

    jsonData.rule_categories = categories;
    jsonData.total_categories = categories.length;
    sections.push(`\n  Total rule files: ${categories.length}`);

    if (outputFormat === "json") {
      return { content: [formatToolOutput(jsonData)] };
    }
    return { content: [createTextContent(sections.join("\n"))] };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { content: [createErrorContent(`OWASP CRS check failed: ${msg}`)], isError: true };
  }
}

/**
 * Analyze WAF logs for blocked requests.
 */
async function handleBlockedRequests(
  logPath: string | undefined,
  outputFormat: string,
): Promise<{ content: Array<{ type: "text"; text: string }>; isError?: boolean }> {
  try {
    const sections: string[] = [];
    const jsonData: Record<string, unknown> = {};

    sections.push("🚫 WAF Blocked Requests Analysis");
    sections.push("=".repeat(55));

    // Find the log file
    let activeLogPath = logPath;
    if (!activeLogPath) {
      for (const path of MODSEC_AUDIT_LOG_PATHS) {
        const testResult = await runCommand("test", ["-f", path]);
        if (testResult.exitCode === 0) {
          activeLogPath = path;
          break;
        }
      }
    }

    if (!activeLogPath) {
      sections.push("\n  ❌ No ModSecurity audit log found");
      sections.push("  Searched paths:");
      for (const p of MODSEC_AUDIT_LOG_PATHS) {
        sections.push(`    - ${p}`);
      }
      sections.push("\n  Ensure SecAuditLog is configured in modsecurity.conf");
      jsonData.log_found = false;

      if (outputFormat === "json") {
        return { content: [formatToolOutput(jsonData)] };
      }
      return { content: [createTextContent(sections.join("\n"))] };
    }

    jsonData.log_path = activeLogPath;
    jsonData.log_found = true;
    sections.push(`  Log file: ${activeLogPath}`);

    // Get log file size
    const statResult = await runCommand("stat", ["--format=%s", activeLogPath]);
    if (statResult.exitCode === 0) {
      const sizeBytes = parseInt(statResult.stdout.trim(), 10);
      const sizeMB = (sizeBytes / 1024 / 1024).toFixed(2);
      sections.push(`  Log size: ${sizeMB} MB`);
      jsonData.log_size_bytes = sizeBytes;
    }

    // Analyze blocked IPs (top 10)
    sections.push("\n── Top Blocked IPs ──");
    const ipResult = await runSudoCommand("grep", ["-oP", "\\d+\\.\\d+\\.\\d+\\.\\d+", activeLogPath]);
    if (ipResult.exitCode === 0 && ipResult.stdout.trim()) {
      // Count IP occurrences manually
      const ipCounts: Record<string, number> = {};
      for (const ip of ipResult.stdout.trim().split("\n")) {
        const trimmedIp = ip.trim();
        if (trimmedIp) {
          ipCounts[trimmedIp] = (ipCounts[trimmedIp] || 0) + 1;
        }
      }

      const sortedIps = Object.entries(ipCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);

      jsonData.top_blocked_ips = sortedIps.map(([ip, count]) => ({ ip, count }));

      for (const [ip, count] of sortedIps) {
        sections.push(`    ${String(count).padStart(6)} │ ${ip}`);
      }
    } else {
      sections.push("    No blocked IPs found");
      jsonData.top_blocked_ips = [];
    }

    // Analyze triggered rules (top 10)
    sections.push("\n── Top Triggered Rules ──");
    const ruleResult = await runSudoCommand("grep", ["-oP", 'id "\\d+"', activeLogPath]);
    if (ruleResult.exitCode === 0 && ruleResult.stdout.trim()) {
      const ruleCounts: Record<string, number> = {};
      for (const match of ruleResult.stdout.trim().split("\n")) {
        const ruleIdMatch = match.match(/\d+/);
        if (ruleIdMatch) {
          const rid = ruleIdMatch[0];
          ruleCounts[rid] = (ruleCounts[rid] || 0) + 1;
        }
      }

      const sortedRules = Object.entries(ruleCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);

      jsonData.top_triggered_rules = sortedRules.map(([ruleId, count]) => ({ rule_id: ruleId, count }));

      for (const [ruleId, count] of sortedRules) {
        sections.push(`    ${String(count).padStart(6)} │ Rule ${ruleId}`);
      }

      // Identify false positive candidates (rules triggered > 100 times)
      sections.push("\n── Possible False Positives ──");
      const fpCandidates = sortedRules.filter(([, count]) => count > 100);
      jsonData.false_positive_candidates = fpCandidates.map(([ruleId, count]) => ({ rule_id: ruleId, count }));

      if (fpCandidates.length > 0) {
        sections.push("  Rules triggered excessively (may be false positives):");
        for (const [ruleId, count] of fpCandidates) {
          sections.push(`    ⚠️ Rule ${ruleId}: ${count} hits — review for tuning`);
        }
      } else {
        sections.push("  No obvious false positive candidates detected");
      }
    } else {
      sections.push("    No triggered rules found");
      jsonData.top_triggered_rules = [];
      jsonData.false_positive_candidates = [];
    }

    // Attack categories
    sections.push("\n── Attack Categories ──");
    const categories: Record<string, number> = {};
    const categoryPatterns: Record<string, string> = {
      "SQL Injection": "sql|sqli|SQL",
      "XSS": "xss|cross-site scripting",
      "Path Traversal": "traversal|path-traversal|directory",
      "Remote File Inclusion": "rfi|remote file",
      "Local File Inclusion": "lfi|local file",
      "Command Injection": "command injection|cmd|rce",
      "Protocol Violation": "protocol|violation|request-",
      "Scanner Detection": "scanner|nikto|nmap|acunetix",
    };

    for (const [category, pattern] of Object.entries(categoryPatterns)) {
      const grepResult = await runSudoCommand("grep", ["-ciP", pattern, activeLogPath]);
      if (grepResult.exitCode === 0) {
        const count = parseInt(grepResult.stdout.trim(), 10);
        if (count > 0) {
          categories[category] = count;
        }
      }
    }

    jsonData.attack_categories = categories;
    const sortedCategories = Object.entries(categories).sort((a, b) => b[1] - a[1]);

    if (sortedCategories.length > 0) {
      for (const [category, count] of sortedCategories) {
        sections.push(`    ${String(count).padStart(6)} │ ${category}`);
      }
    } else {
      sections.push("    No categorized attacks found");
    }

    // Timeline (recent blocks count by hour — last 24h)
    sections.push("\n── Recent Activity (last 24 lines) ──");
    const tailResult = await runSudoCommand("tail", ["-24", activeLogPath]);
    if (tailResult.exitCode === 0 && tailResult.stdout.trim()) {
      const recentLines = tailResult.stdout.trim().split("\n").slice(0, 10);
      for (const line of recentLines) {
        sections.push(`    ${line.substring(0, 120)}`);
      }
      if (tailResult.stdout.trim().split("\n").length > 10) {
        sections.push("    ...");
      }
    } else {
      sections.push("    No recent entries");
    }

    if (outputFormat === "json") {
      return { content: [formatToolOutput(jsonData)] };
    }
    return { content: [createTextContent(sections.join("\n"))] };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { content: [createErrorContent(`Blocked requests analysis failed: ${msg}`)], isError: true };
  }
}

// ── Registration entry point ───────────────────────────────────────────────

export function registerWafTools(server: McpServer): void {
  server.tool(
    "waf_manage",
    "Web Application Firewall management: audit ModSecurity, manage rules, configure rate limiting, deploy OWASP CRS, analyze blocked requests.",
    {
      action: z
        .enum(["modsec_audit", "modsec_rules", "rate_limit_config", "owasp_crs_deploy", "blocked_requests"])
        .describe(
          "Action: modsec_audit=audit WAF config, modsec_rules=manage rules, rate_limit_config=rate limiting, owasp_crs_deploy=CRS status, blocked_requests=log analysis",
        ),
      web_server: z
        .enum(["nginx", "apache"])
        .optional()
        .default("nginx")
        .describe("Web server type (default: nginx)"),
      rule_id: z
        .string()
        .optional()
        .describe("ModSecurity rule ID (used with modsec_rules action)"),
      rule_action: z
        .enum(["enable", "disable", "list"])
        .optional()
        .default("list")
        .describe("Rule action: enable, disable, or list (used with modsec_rules)"),
      rate_limit: z
        .number()
        .optional()
        .describe("Requests per second for rate limiting (used with rate_limit_config)"),
      rate_limit_zone: z
        .string()
        .optional()
        .describe("Zone name for rate limiting (used with rate_limit_config)"),
      log_path: z
        .string()
        .optional()
        .describe("Path to WAF log file (used with blocked_requests)"),
      output_format: z
        .enum(["text", "json"])
        .optional()
        .default("text")
        .describe("Output format: text or json (default: text)"),
    },
    async (params) => {
      const { action } = params;
      const webServer = params.web_server ?? "nginx";
      const outputFormat = params.output_format ?? "text";

      switch (action) {
        case "modsec_audit":
          return handleModsecAudit(webServer, outputFormat);

        case "modsec_rules": {
          const ruleAction = params.rule_action ?? "list";
          return handleModsecRules(ruleAction, params.rule_id, webServer, outputFormat);
        }

        case "rate_limit_config":
          return handleRateLimitConfig(webServer, params.rate_limit, params.rate_limit_zone, outputFormat);

        case "owasp_crs_deploy":
          return handleOwaspCrsDeploy(webServer, outputFormat);

        case "blocked_requests":
          return handleBlockedRequests(params.log_path, outputFormat);

        default:
          return {
            content: [createErrorContent(`Unknown action: ${action}`)],
            isError: true,
          };
      }
    },
  );
}
