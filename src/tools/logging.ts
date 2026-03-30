/**
 * Log management tools for Defense MCP Server.
 *
 * Consolidates logging.ts (4 tools) and siem-integration.ts (1 tool) into a
 * single tool: `log_management` with 16 actions.
 *
 * Actions:
 *   auditd_rules, auditd_search, auditd_report, auditd_cis_rules
 *   journalctl_query
 *   fail2ban_status, fail2ban_ban, fail2ban_unban, fail2ban_reload, fail2ban_audit
 *   syslog_analyze, rotation_audit, rotation_configure
 *   siem_syslog_forward, siem_filebeat, siem_audit_forwarding, siem_test_connectivity
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeCommand } from "../core/executor.js";
import { getConfig, getToolTimeout } from "../core/config.js";
import {
  createTextContent,
  createErrorContent,
  parseAuditdOutput,
  parseFail2banOutput,
  formatToolOutput,
} from "../core/parsers.js";
import { logChange, createChangeEntry, backupFile } from "../core/changelog.js";
import {
  sanitizeArgs,
  validateFilePath,
  validateAuditdKey,
  validateTarget,
  validateToolPath,
} from "../core/sanitizer.js";
import { getDistroAdapter } from "../core/distro-adapter.js";
import { existsSync } from "node:fs";
import { spawnSafe } from "../core/spawn-safe.js";
import type { ChildProcess } from "node:child_process";

// ── TOOL-015 remediation: allowed directories for log file paths ────────────
const ALLOWED_LOG_DIRS = ["/var/log", "/var/spool", "/tmp", "/var/lib", "/run/log"];

// ── SIEM constants ──────────────────────────────────────────────────────────
/** Critical log sources that should be forwarded per CIS benchmarks */
const CRITICAL_LOG_SOURCES = ["auth", "syslog", "kern", "audit"];

/** Log file paths corresponding to critical sources */
const LOG_SOURCE_FILES: Record<string, string> = {
  auth: "/var/log/auth.log",
  syslog: "/var/log/syslog",
  kern: "/var/log/kern.log",
  audit: "/var/log/audit/audit.log",
};

/** Hostname/IP validation pattern */
const SIEM_HOST_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,253}[a-zA-Z0-9]$/;

// ── SIEM helpers ────────────────────────────────────────────────────────────

interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

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
 * Validate a SIEM host string (hostname or IP address).
 * Returns true if the host looks reasonable.
 */
export function validateSiemHost(host: string): boolean {
  if (!host || host.trim().length === 0) return false;
  const trimmed = host.trim();
  // Allow IP addresses (v4)
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(trimmed)) return true;
  // Allow hostnames
  if (SIEM_HOST_PATTERN.test(trimmed)) return true;
  return false;
}

// ── SIEM action implementations ─────────────────────────────────────────────

interface SyslogForwardResult {
  syslogDaemon: string;
  daemonInstalled: boolean;
  existingForwardingRules: string[];
  rsyslogModules: { imtcp: boolean; imudp: boolean };
  tlsSupport: boolean;
  currentConfig: string;
  recommendedConfig: string;
  recommendations: string[];
}

async function configureSyslogForward(
  siemHost?: string,
  siemPort?: number,
  protocol?: string,
  logSources?: string[],
): Promise<SyslogForwardResult> {
  const result: SyslogForwardResult = {
    syslogDaemon: "unknown",
    daemonInstalled: false,
    existingForwardingRules: [],
    rsyslogModules: { imtcp: false, imudp: false },
    tlsSupport: false,
    currentConfig: "",
    recommendedConfig: "",
    recommendations: [],
  };

  const effectivePort = siemPort ?? 514;
  const effectiveProtocol = protocol ?? "tcp";

  const rsyslogCheck = await runCommand("dpkg", ["-l", "rsyslog"], 10_000);
  const syslogNgCheck = await runCommand("dpkg", ["-l", "syslog-ng"], 10_000);

  if (rsyslogCheck.exitCode === 0 && rsyslogCheck.stdout.includes("ii")) {
    result.syslogDaemon = "rsyslog";
    result.daemonInstalled = true;
  } else if (syslogNgCheck.exitCode === 0 && syslogNgCheck.stdout.includes("ii")) {
    result.syslogDaemon = "syslog-ng";
    result.daemonInstalled = true;
  } else {
    result.syslogDaemon = "none";
    result.daemonInstalled = false;
    result.recommendations.push("No syslog daemon found — install rsyslog: apt-get install rsyslog");
    return result;
  }

  const configResult = await runCommand("cat", ["/etc/rsyslog.conf"], 10_000);
  if (configResult.exitCode === 0) {
    result.currentConfig = configResult.stdout;
    const lines = configResult.stdout.split("\n");
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith("#") || trimmed.length === 0) continue;
      if (/\s@@[^\s]/.test(trimmed) || /\s@[^@\s]/.test(trimmed)) {
        result.existingForwardingRules.push(trimmed);
      }
    }
    result.rsyslogModules.imtcp = configResult.stdout.includes("imtcp");
    result.rsyslogModules.imudp = configResult.stdout.includes("imudp");
  }

  const rsyslogDResult = await runCommand("cat", ["/etc/rsyslog.d/"], 10_000);
  if (rsyslogDResult.exitCode === 0) {
    const lines = rsyslogDResult.stdout.split("\n");
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith("#") || trimmed.length === 0) continue;
      if (/\s@@[^\s]/.test(trimmed) || /\s@[^@\s]/.test(trimmed)) {
        result.existingForwardingRules.push(trimmed);
      }
    }
  }

  const tlsCheck = await runCommand("dpkg", ["-l", "rsyslog-gnutls"], 10_000);
  result.tlsSupport = tlsCheck.exitCode === 0 && tlsCheck.stdout.includes("ii");

  if (siemHost) {
    const forwardPrefix = effectiveProtocol === "udp" ? "@" : "@@";
    const sources = logSources && logSources.length > 0 ? logSources : ["*.*"];
    let config = "# SIEM forwarding configuration\n";
    if (effectiveProtocol === "tls") {
      config += '# TLS configuration\n';
      config += '$DefaultNetstreamDriverCAFile /etc/rsyslog.d/ca.pem\n';
      config += '$DefaultNetstreamDriver gtls\n';
      config += '$ActionSendStreamDriverMode 1\n';
      config += '$ActionSendStreamDriverAuthMode x509/name\n';
      if (!result.tlsSupport) {
        result.recommendations.push("TLS requested but rsyslog-gnutls not installed — install: apt-get install rsyslog-gnutls");
      }
    }
    for (const source of sources) {
      const facility = source === "*.*" ? "*.*" : `${source}.*`;
      config += `${facility} ${forwardPrefix}${siemHost}:${effectivePort}\n`;
    }
    result.recommendedConfig = config;
  }

  if (result.existingForwardingRules.length === 0) {
    result.recommendations.push("No remote forwarding rules found — logs are not being forwarded to a SIEM");
  } else {
    result.recommendations.push(`Found ${result.existingForwardingRules.length} forwarding rule(s) — verify they target the correct SIEM`);
  }

  if (!result.rsyslogModules.imtcp && effectiveProtocol === "tcp") {
    result.recommendations.push("imtcp module not loaded — TCP reception may not work");
  }

  if (!result.tlsSupport) {
    result.recommendations.push("TLS not available — consider installing rsyslog-gnutls for encrypted log forwarding");
  }

  return result;
}

interface FilebeatResult {
  installed: boolean;
  version: string;
  enabledModules: string[];
  disabledModules: string[];
  outputConfig: string;
  serviceStatus: string;
  serviceRunning: boolean;
  configPath: string;
  recommendedConfig: string;
  recommendations: string[];
}

async function configureFilebeat(
  siemHost?: string,
  siemPort?: number,
): Promise<FilebeatResult> {
  const result: FilebeatResult = {
    installed: false,
    version: "unknown",
    enabledModules: [],
    disabledModules: [],
    outputConfig: "",
    serviceStatus: "unknown",
    serviceRunning: false,
    configPath: "/etc/filebeat/filebeat.yml",
    recommendedConfig: "",
    recommendations: [],
  };

  const effectivePort = siemPort ?? 5044;

  const whichResult = await runCommand("which", ["filebeat"], 10_000);
  if (whichResult.exitCode !== 0) {
    const dpkgResult = await runCommand("dpkg", ["-l", "filebeat"], 10_000);
    if (dpkgResult.exitCode !== 0 || !dpkgResult.stdout.includes("ii")) {
      result.installed = false;
      result.recommendations.push("Filebeat is not installed — install from Elastic repository for log shipping");
      return result;
    }
  }

  result.installed = true;

  const versionResult = await runCommand("filebeat", ["version"], 10_000);
  if (versionResult.exitCode === 0) {
    result.version = versionResult.stdout.trim();
  }

  const configResult = await runCommand("cat", ["/etc/filebeat/filebeat.yml"], 10_000);
  if (configResult.exitCode === 0) {
    result.outputConfig = configResult.stdout;
    const lines = configResult.stdout.split("\n");
    let inOutput = false;
    for (const line of lines) {
      if (line.match(/^output\./)) { inOutput = true; }
      if (inOutput && line.trim().length > 0 && !line.startsWith(" ") && !line.startsWith("\t") && !line.match(/^output\./)) {
        inOutput = false;
      }
    }
  }

  const modulesResult = await runCommand("filebeat", ["modules", "list"], 15_000);
  if (modulesResult.exitCode === 0) {
    const lines = modulesResult.stdout.split("\n");
    let inEnabled = false;
    let inDisabled = false;
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed === "Enabled:") { inEnabled = true; inDisabled = false; continue; }
      if (trimmed === "Disabled:") { inEnabled = false; inDisabled = true; continue; }
      if (trimmed.length > 0) {
        if (inEnabled) result.enabledModules.push(trimmed);
        if (inDisabled) result.disabledModules.push(trimmed);
      }
    }
  }

  const serviceResult = await runCommand("systemctl", ["status", "filebeat"], 10_000);
  if (serviceResult.exitCode === 0 || serviceResult.exitCode === 3) {
    result.serviceStatus = serviceResult.stdout.trim();
    result.serviceRunning = serviceResult.stdout.includes("active (running)");
  }

  if (siemHost) {
    result.recommendedConfig =
      "# Filebeat output configuration for Logstash\n" +
      "output.logstash:\n" +
      `  hosts: ["${siemHost}:${effectivePort}"]\n` +
      "  ssl.enabled: true\n" +
      "  ssl.certificate_authorities: ['/etc/filebeat/ca.pem']\n";
  }

  if (!result.serviceRunning) {
    result.recommendations.push("Filebeat service is not running — start with: systemctl start filebeat");
  }
  if (result.enabledModules.length === 0) {
    result.recommendations.push("No Filebeat modules enabled — enable system module: filebeat modules enable system");
  }

  return result;
}

interface ForwardingAuditResult {
  rsyslogForwarding: boolean;
  rsyslogRules: string[];
  filebeatRunning: boolean;
  filebeatStatus: string;
  criticalSourcesCovered: Array<{ source: string; forwarded: boolean; path: string }>;
  missingSourcesCount: number;
  logRotationConfig: string;
  logRotationInterferes: boolean;
  cisBenchmark: string;
  cisCompliant: boolean;
  recommendations: string[];
}

async function auditForwarding(logSources?: string[]): Promise<ForwardingAuditResult> {
  const result: ForwardingAuditResult = {
    rsyslogForwarding: false,
    rsyslogRules: [],
    filebeatRunning: false,
    filebeatStatus: "unknown",
    criticalSourcesCovered: [],
    missingSourcesCount: 0,
    logRotationConfig: "",
    logRotationInterferes: false,
    cisBenchmark: "CIS Benchmark 4.2.1 — Ensure logging is configured to a remote log host",
    cisCompliant: false,
    recommendations: [],
  };

  const sourcesToCheck = logSources && logSources.length > 0 ? logSources : CRITICAL_LOG_SOURCES;

  const rsyslogConfig = await runCommand("cat", ["/etc/rsyslog.conf"], 10_000);
  if (rsyslogConfig.exitCode === 0) {
    const lines = rsyslogConfig.stdout.split("\n");
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith("#") || trimmed.length === 0) continue;
      if (/\s@@[^\s]/.test(trimmed) || /\s@[^@\s]/.test(trimmed)) {
        result.rsyslogRules.push(trimmed);
        result.rsyslogForwarding = true;
      }
      if (trimmed.includes("action(type=\"omfwd\"")) {
        result.rsyslogRules.push(trimmed);
        result.rsyslogForwarding = true;
      }
    }
  }

  const filebeatResult = await runCommand("systemctl", ["status", "filebeat"], 10_000);
  if (filebeatResult.exitCode === 0 || filebeatResult.exitCode === 3) {
    result.filebeatStatus = filebeatResult.stdout.trim();
    result.filebeatRunning = filebeatResult.stdout.includes("active (running)");
  }

  const configContent = rsyslogConfig.exitCode === 0 ? rsyslogConfig.stdout : "";
  for (const source of sourcesToCheck) {
    const logPath = LOG_SOURCE_FILES[source] ?? `/var/log/${source}.log`;
    let forwarded = false;
    if (result.rsyslogForwarding) {
      if (result.rsyslogRules.some((r) => r.includes("*.*"))) { forwarded = true; }
      if (result.rsyslogRules.some((r) => r.includes(`${source}.*`))) { forwarded = true; }
      if (configContent.includes(source) && result.rsyslogForwarding) { forwarded = true; }
    }
    if (result.filebeatRunning) { forwarded = true; }
    result.criticalSourcesCovered.push({ source, forwarded, path: logPath });
    if (!forwarded) { result.missingSourcesCount++; }
  }

  const logrotateResult = await runCommand("cat", ["/etc/logrotate.d/rsyslog"], 10_000);
  if (logrotateResult.exitCode === 0) {
    result.logRotationConfig = logrotateResult.stdout;
    if (!logrotateResult.stdout.includes("sharedscripts") ||
        !logrotateResult.stdout.includes("postrotate")) {
      result.logRotationInterferes = true;
      result.recommendations.push("Log rotation may interfere with forwarding — ensure sharedscripts and postrotate with rsyslog reload are configured");
    }
  }

  result.cisCompliant = result.rsyslogForwarding || result.filebeatRunning;

  if (!result.rsyslogForwarding && !result.filebeatRunning) {
    result.recommendations.push("CRITICAL: No log forwarding configured — logs are not being sent to a remote SIEM");
    result.recommendations.push("Configure rsyslog forwarding or install Filebeat for centralized logging");
  }

  if (result.missingSourcesCount > 0) {
    const missing = result.criticalSourcesCovered
      .filter((s) => !s.forwarded)
      .map((s) => s.source);
    result.recommendations.push(`Missing forwarding for ${result.missingSourcesCount} critical source(s): ${missing.join(", ")}`);
  }

  if (!result.cisCompliant) {
    result.recommendations.push(`Non-compliant with ${result.cisBenchmark}`);
  }

  return result;
}

interface ConnectivityResult {
  siemHost: string;
  siemPort: number;
  protocol: string;
  tcpConnectivity: boolean;
  tcpMessage: string;
  tlsVerification: boolean;
  tlsMessage: string;
  dnsResolution: boolean;
  dnsResult: string;
  firewallStatus: string;
  firewallBlocked: boolean;
  testMessageSent: boolean;
  testMessageResult: string;
  recommendations: string[];
}

async function testConnectivity(
  siemHost: string,
  siemPort?: number,
  protocol?: string,
): Promise<ConnectivityResult> {
  const effectivePort = siemPort ?? 514;
  const effectiveProtocol = protocol ?? "tcp";

  const result: ConnectivityResult = {
    siemHost,
    siemPort: effectivePort,
    protocol: effectiveProtocol,
    tcpConnectivity: false,
    tcpMessage: "not tested",
    tlsVerification: false,
    tlsMessage: "not tested",
    dnsResolution: false,
    dnsResult: "not tested",
    firewallStatus: "not checked",
    firewallBlocked: false,
    testMessageSent: false,
    testMessageResult: "not attempted",
    recommendations: [],
  };

  const digResult = await runCommand("dig", [siemHost], 15_000);
  if (digResult.exitCode === 0 && digResult.stdout.includes("ANSWER SECTION")) {
    result.dnsResolution = true;
    result.dnsResult = "resolved successfully";
  } else if (digResult.exitCode === 0) {
    result.dnsResolution = false;
    result.dnsResult = "DNS query returned no results";
    result.recommendations.push(`DNS resolution failed for ${siemHost} — verify hostname is correct`);
  } else {
    result.dnsResolution = false;
    result.dnsResult = digResult.stderr || "dig command failed";
    result.recommendations.push("dig command not available — install dnsutils for DNS testing");
  }

  const ncResult = await runCommand("nc", ["-z", "-w", "5", siemHost, String(effectivePort)], 15_000);
  if (ncResult.exitCode === 0) {
    result.tcpConnectivity = true;
    result.tcpMessage = `TCP connection to ${siemHost}:${effectivePort} successful`;
  } else {
    result.tcpConnectivity = false;
    result.tcpMessage = `TCP connection to ${siemHost}:${effectivePort} failed`;
    result.recommendations.push(`Cannot reach ${siemHost}:${effectivePort} — check network connectivity and firewall rules`);
  }

  if (effectiveProtocol === "tls") {
    const opensslResult = await runCommand(
      "openssl",
      ["s_client", "-connect", `${siemHost}:${effectivePort}`, "-brief"],
      15_000,
    );
    if (opensslResult.exitCode === 0 && opensslResult.stdout.includes("Verification")) {
      result.tlsVerification = true;
      result.tlsMessage = "TLS handshake successful";
    } else if (opensslResult.exitCode === 0) {
      result.tlsVerification = false;
      result.tlsMessage = opensslResult.stderr || "TLS handshake completed with warnings";
      result.recommendations.push("TLS certificate verification may have issues — check CA certificates");
    } else {
      result.tlsVerification = false;
      result.tlsMessage = opensslResult.stderr || "TLS handshake failed";
      result.recommendations.push("TLS connection failed — verify the SIEM supports TLS on this port");
    }
  }

  const iptablesResult = await runCommand("iptables", ["-L", "-n"], 10_000);
  if (iptablesResult.exitCode === 0) {
    const lines = iptablesResult.stdout.split("\n");
    const portStr = String(effectivePort);
    for (const line of lines) {
      if (line.includes(portStr)) {
        result.firewallStatus = line.trim();
        if (line.includes("DROP") || line.includes("REJECT")) {
          result.firewallBlocked = true;
          result.recommendations.push(`Firewall rule blocking port ${effectivePort} detected — update iptables to allow SIEM traffic`);
        }
      }
    }
    if (result.firewallStatus === "not checked") {
      result.firewallStatus = `No specific rules found for port ${effectivePort}`;
    }
  } else {
    result.firewallStatus = "iptables not accessible (may need root)";
  }

  const loggerResult = await runCommand(
    "logger",
    ["-n", siemHost, "-P", String(effectivePort), "--tcp", "defense-mcp SIEM connectivity test"],
    15_000,
  );
  if (loggerResult.exitCode === 0) {
    result.testMessageSent = true;
    result.testMessageResult = "Test syslog message sent successfully";
  } else {
    result.testMessageSent = false;
    result.testMessageResult = loggerResult.stderr || "Failed to send test message";
    if (loggerResult.stderr?.includes("not found")) {
      result.recommendations.push("logger command not available — install bsdutils for syslog testing");
    }
  }

  if (!result.tcpConnectivity && !result.dnsResolution) {
    result.recommendations.push("CRITICAL: SIEM endpoint is unreachable — verify host, port, and network path");
  } else if (!result.tcpConnectivity) {
    result.recommendations.push("DNS resolves but TCP connection fails — check if SIEM is listening on the specified port");
  }

  return result;
}

// ── Registration entry point ───────────────────────────────────────────────

export function registerLoggingTools(server: McpServer): void {
  server.tool(
    "log_management",
    "Logging: auditd, journalctl, fail2ban, syslog, log rotation, SIEM integration",
    {
      action: z
        .enum([
          "auditd_rules",
          "auditd_search",
          "auditd_report",
          "auditd_cis_rules",
          "journalctl_query",
          "fail2ban_status",
          "fail2ban_ban",
          "fail2ban_unban",
          "fail2ban_reload",
          "fail2ban_audit",
          "syslog_analyze",
          "rotation_audit",
          "rotation_configure",
          "siem_syslog_forward",
          "siem_filebeat",
          "siem_audit_forwarding",
          "siem_test_connectivity",
        ])
        .describe("Log management action"),
      // auditd rules params
      rules_action: z
        .enum(["list", "add", "delete"])
        .optional()
        .describe("Audit rule sub-action"),
      rule: z
        .string()
        .min(1)
        .optional()
        .describe("Audit rule string"),
      // auditd search params
      key: z
        .string()
        .min(1)
        .regex(/^[a-zA-Z0-9._-]+$/)
        .optional()
        .describe("Audit key to search for"),
      syscall: z
        .string()
        .min(1)
        .regex(/^[a-zA-Z0-9_]+$/)
        .optional()
        .describe("System call name to filter"),
      uid: z
        .string()
        .min(1)
        .regex(/^[0-9]+$/)
        .optional()
        .describe("User ID to filter"),
      start: z
        .string()
        .min(1)
        .optional()
        .describe("Start time, e.g. 'today', '1 hour ago'"),
      end: z
        .string()
        .min(1)
        .optional()
        .describe("End time"),
      success: z
        .enum(["yes", "no"])
        .optional()
        .describe("Filter by success/failure"),
      limit: z
        .number()
        .optional()
        .default(50)
        .describe("Maximum lines to return"),
      // auditd report params
      report_type: z
        .enum(["summary", "auth", "login", "account", "event", "file", "exec"])
        .optional()
        .default("summary")
        .describe("Audit report type"),
      // auditd cis_rules params
      cis_action: z
        .enum(["check", "generate"])
        .optional()
        .default("check")
        .describe("Check or generate CIS rules"),
      // shared log params
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview without executing"),
      // journalctl params
      unit: z
        .string()
        .optional()
        .describe("Systemd unit name to filter"),
      priority: z
        .enum(["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"])
        .optional()
        .describe("Minimum priority level"),
      since: z
        .string()
        .optional()
        .describe("Start time, e.g. '1 hour ago', 'today'"),
      until: z
        .string()
        .optional()
        .describe("End time"),
      grep: z
        .string()
        .optional()
        .describe("Pattern to search for in log messages"),
      lines: z
        .number()
        .optional()
        .describe("Number of log lines / max lines to return"),
      output_format: z
        .string()
        .optional()
        .describe("Output format"),
      // fail2ban params
      jail: z
        .string()
        .min(1)
        .regex(/^[a-zA-Z0-9._-]+$/)
        .optional()
        .describe("Fail2ban jail name"),
      ip: z
        .string()
        .min(1)
        .optional()
        .describe("IP address to ban or unban"),
      // syslog_analyze params
      log_file: z
        .string()
        .optional()
        .describe("Path to log file"),
      pattern: z
        .enum(["auth_failures", "ssh_brute", "privilege_escalation", "service_changes", "all"])
        .optional()
        .default("all")
        .describe("Security event pattern to search"),
      // SIEM params
      siem_host: z
        .string()
        .optional()
        .describe("SIEM server hostname or IP address"),
      siem_port: z
        .number()
        .optional()
        .describe("SIEM server port"),
      protocol: z
        .enum(["tcp", "udp", "tls"])
        .optional()
        .default("tcp")
        .describe("Transport protocol"),
      log_sources: z
        .array(z.string())
        .optional()
        .describe("Log sources to forward"),
      // rotation_configure params
      logrotate_path: z
        .string()
        .optional()
        .describe("Log file path to configure rotation for"),
      logrotate_name: z
        .string()
        .optional()
        .describe("Config filename under /etc/logrotate.d/"),
      rotate_count: z
        .number()
        .optional()
        .default(7)
        .describe("Number of rotated files to keep"),
      rotate_frequency: z
        .enum(["daily", "weekly", "monthly"])
        .optional()
        .default("weekly"),
      compress_logs: z
        .boolean()
        .optional()
        .default(true)
        .describe("Compress rotated files"),
      extra_directives: z
        .array(z.string())
        .optional()
        .describe("Additional logrotate directives"),
    },
    async (params) => {
      const { action } = params;

      switch (action) {
        // ── auditd_rules ───────────────────────────────────────────────────
        case "auditd_rules": {
          const { rules_action, rule, dry_run } = params;
          try {
            if (!rules_action) {
              return { content: [createErrorContent("rules_action is required for rules action (list/add/delete)")], isError: true };
            }

            if (rules_action === "list") {
              const result = await executeCommand({ command: "sudo", args: ["auditctl", "-l"], toolName: "log_management", timeout: getToolTimeout("auditd") });
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
              logChange(createChangeEntry({ tool: "log_management", action: `[DRY-RUN] ${rules_action} auditd rule`, target: rule, after: fullCmd, dryRun: true, success: true }));
              return { content: [createTextContent(`[DRY-RUN] Would execute:\n  ${fullCmd}`)] };
            }

            const result = await executeCommand({ command: "sudo", args, toolName: "log_management", timeout: getToolTimeout("auditd") });
            const ok = result.exitCode === 0;
            logChange(createChangeEntry({ tool: "log_management", action: `${rules_action} auditd rule`, target: rule, after: fullCmd, dryRun: false, success: ok, error: ok ? undefined : result.stderr }));

            if (!ok) return { content: [createErrorContent(`auditctl ${rules_action} failed (exit ${result.exitCode}): ${result.stderr}`)], isError: true };
            return { content: [createTextContent(`Auditd rule ${rules_action === "add" ? "added" : "deleted"} successfully.\nCommand: ${fullCmd}`)] };
          } catch (err: unknown) {
            return { content: [createErrorContent(err instanceof Error ? err.message : String(err))], isError: true };
          }
        }

        // ── auditd_search ──────────────────────────────────────────────────
        case "auditd_search": {
          const { key, syscall, uid, start, end, success, limit: maxLines = 50 } = params;
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

            const result = await executeCommand({ command: "sudo", args, toolName: "log_management", timeout: getToolTimeout("auditd") });

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

        // ── auditd_report ──────────────────────────────────────────────────
        case "auditd_report": {
          const { report_type = "summary", start } = params;
          try {
            const args: string[] = ["aureport"];
            const reportFlags: Record<string, string> = { summary: "--summary", auth: "--auth", login: "--login", account: "--account-modifications", event: "--event", file: "--file", exec: "--executable" };
            args.push(reportFlags[report_type!] ?? "--summary");
            if (start) { sanitizeArgs([start]); args.push("--start", start); }
            sanitizeArgs(args);

            const result = await executeCommand({ command: "sudo", args, toolName: "log_management", timeout: getToolTimeout("auditd") });
            if (result.exitCode !== 0) return { content: [createErrorContent(`aureport failed (exit ${result.exitCode}): ${result.stderr}`)], isError: true };
            return { content: [createTextContent(`Audit Report (${report_type}):\n${"=".repeat(50)}\n${result.stdout}`)] };
          } catch (err: unknown) {
            return { content: [createErrorContent(err instanceof Error ? err.message : String(err))], isError: true };
          }
        }

        // ── auditd_cis_rules ───────────────────────────────────────────────
        case "auditd_cis_rules": {
          const { cis_action = "check" } = params;
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

            const currentRules = await executeCommand({ command: "sudo", args: ["auditctl", "-l"], timeout: 10000, toolName: "log_management" });
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

        // ── journalctl_query ───────────────────────────────────────────────
        case "journalctl_query": {
          const { unit, priority, since, until, grep, lines: numLines = 100, output_format } = params;
          const effectiveOutputFormat = (output_format ?? "short") as string;
          try {
            const args: string[] = ["journalctl"];
            if (unit) { sanitizeArgs([unit]); args.push("--unit", unit); }
            if (priority) args.push("-p", priority);
            if (since) { sanitizeArgs([since]); args.push("--since", since); }
            if (until) { sanitizeArgs([until]); args.push("--until", until); }
            if (grep) { sanitizeArgs([grep]); args.push("-g", grep); }
            args.push("-n", String(numLines));
            args.push("-o", effectiveOutputFormat);
            args.push("--no-pager");
            sanitizeArgs(args);

            const result = await executeCommand({ command: "journalctl", args: args.slice(1), toolName: "log_management", timeout: getToolTimeout("auditd") });
            if (result.exitCode !== 0) return { content: [createErrorContent(`journalctl query failed (exit ${result.exitCode}): ${result.stderr}`)], isError: true };
            return { content: [createTextContent(result.stdout)] };
          } catch (err: unknown) {
            return { content: [createErrorContent(err instanceof Error ? err.message : String(err))], isError: true };
          }
        }

        // ── fail2ban_status ────────────────────────────────────────────────
        case "fail2ban_status": {
          const { jail } = params;
          try {
            const args: string[] = ["fail2ban-client", "status"];
            if (jail) { sanitizeArgs([jail]); args.push(jail); }

            const result = await executeCommand({ command: "sudo", args, toolName: "log_management", timeout: getToolTimeout("auditd") });
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

        // ── fail2ban_ban / fail2ban_unban ──────────────────────────────────
        case "fail2ban_ban":
        case "fail2ban_unban": {
          const { jail, ip, dry_run } = params;
          const f2bAction = action === "fail2ban_ban" ? "ban" : "unban";
          try {
            if (!jail) return { content: [createErrorContent(`Jail name is required for '${f2bAction}' action`)], isError: true };
            if (!ip) return { content: [createErrorContent(`IP address is required for '${f2bAction}' action`)], isError: true };

            sanitizeArgs([jail]);
            validateTarget(ip);

            const subcommand = f2bAction === "ban" ? "banip" : "unbanip";
            const args = ["fail2ban-client", "set", jail, subcommand, ip];
            const fullCmd = `sudo ${args.join(" ")}`;
            const rollbackCmd = f2bAction === "ban" ? `sudo fail2ban-client set ${jail} unbanip ${ip}` : `sudo fail2ban-client set ${jail} banip ${ip}`;

            if (dry_run ?? getConfig().dryRun) {
              logChange(createChangeEntry({ tool: "log_management", action: `[DRY-RUN] ${f2bAction} IP in fail2ban`, target: `${jail}/${ip}`, after: fullCmd, dryRun: true, success: true, rollbackCommand: rollbackCmd }));
              return { content: [createTextContent(`[DRY-RUN] Would execute:\n  ${fullCmd}\n\nRollback command:\n  ${rollbackCmd}`)] };
            }

            const result = await executeCommand({ command: "sudo", args, toolName: "log_management", timeout: getToolTimeout("auditd") });
            const ok = result.exitCode === 0;
            logChange(createChangeEntry({ tool: "log_management", action: `${f2bAction} IP in fail2ban`, target: `${jail}/${ip}`, after: fullCmd, dryRun: false, success: ok, error: ok ? undefined : result.stderr, rollbackCommand: rollbackCmd }));

            if (!ok) return { content: [createErrorContent(`fail2ban ${f2bAction} failed (exit ${result.exitCode}): ${result.stderr}`)], isError: true };
            return { content: [createTextContent(`IP ${ip} ${f2bAction === "ban" ? "banned" : "unbanned"} in jail ${jail}.\nRollback: ${rollbackCmd}`)] };
          } catch (err: unknown) {
            return { content: [createErrorContent(err instanceof Error ? err.message : String(err))], isError: true };
          }
        }

        // ── fail2ban_reload ────────────────────────────────────────────────
        case "fail2ban_reload": {
          const { dry_run } = params;
          try {
            const fullCmd = "sudo fail2ban-client reload";

            if (dry_run ?? getConfig().dryRun) {
              logChange(createChangeEntry({ tool: "log_management", action: "[DRY-RUN] Reload fail2ban", target: "fail2ban", after: fullCmd, dryRun: true, success: true }));
              return { content: [createTextContent(`[DRY-RUN] Would execute:\n  ${fullCmd}`)] };
            }

            const result = await executeCommand({ command: "sudo", args: ["fail2ban-client", "reload"], toolName: "log_management", timeout: getToolTimeout("auditd") });
            const ok = result.exitCode === 0;
            logChange(createChangeEntry({ tool: "log_management", action: "Reload fail2ban", target: "fail2ban", after: fullCmd, dryRun: false, success: ok, error: ok ? undefined : result.stderr }));

            if (!ok) return { content: [createErrorContent(`fail2ban reload failed (exit ${result.exitCode}): ${result.stderr}`)], isError: true };
            return { content: [createTextContent("fail2ban reloaded successfully.")] };
          } catch (err: unknown) {
            return { content: [createErrorContent(err instanceof Error ? err.message : String(err))], isError: true };
          }
        }

        // ── fail2ban_audit ─────────────────────────────────────────────────
        case "fail2ban_audit": {
          try {
            const statusResult = await executeCommand({ command: "sudo", args: ["fail2ban-client", "status"], timeout: 10000, toolName: "log_management" });
            if (statusResult.exitCode !== 0) {
              return { content: [createTextContent(JSON.stringify({ installed: false, recommendation: "Install fail2ban: sudo apt install fail2ban && sudo systemctl enable fail2ban" }, null, 2))] };
            }

            const jailLine = statusResult.stdout.match(/Jail list:\s*(.*)/);
            const jails = jailLine ? jailLine[1].split(",").map(j => j.trim()).filter(Boolean) : [];

            const findings: Array<{jail: string, setting: string, value: string, status: string, recommendation: string}> = [];

            for (const jail of jails) {
              const jailResult = await executeCommand({ command: "sudo", args: ["fail2ban-client", "get", jail, "bantime"], timeout: 5000, toolName: "log_management" });
              const bantime = parseInt(jailResult.stdout.trim()) || 0;
              findings.push({ jail, setting: "bantime", value: `${bantime}s`, status: bantime >= 600 ? "PASS" : "WARN", recommendation: bantime < 600 ? "Increase bantime to at least 600s (10 min)" : "OK" });

              const maxRetryResult = await executeCommand({ command: "sudo", args: ["fail2ban-client", "get", jail, "maxretry"], timeout: 5000, toolName: "log_management" });
              const maxRetry = parseInt(maxRetryResult.stdout.trim()) || 0;
              findings.push({ jail, setting: "maxretry", value: String(maxRetry), status: maxRetry <= 5 ? "PASS" : "WARN", recommendation: maxRetry > 5 ? "Reduce maxretry to 5 or less" : "OK" });

              const findtimeResult = await executeCommand({ command: "sudo", args: ["fail2ban-client", "get", jail, "findtime"], timeout: 5000, toolName: "log_management" });
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

        // ── syslog_analyze ─────────────────────────────────────────────────
        case "syslog_analyze": {
          const { log_file, pattern = "all", lines: maxLines = 500 } = params;
          try {
            let effectiveLogFile: string;
            if (log_file) {
              effectiveLogFile = validateToolPath(log_file, ALLOWED_LOG_DIRS, "Log file path");
            } else {
              const adapterPath = (await getDistroAdapter()).paths.syslog;
              const candidates = [adapterPath];
              if (adapterPath !== "/var/log/messages") candidates.push("/var/log/messages");
              if (adapterPath !== "/var/log/syslog") candidates.push("/var/log/syslog");

              const found = candidates.find((p) => existsSync(p));
              if (!found) {
                return { content: [createErrorContent(`No syslog file found (tried: ${candidates.join(", ")}). This system may use journald exclusively — use log_management with action journalctl_query instead.`)], isError: true };
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

            const result = await executeCommand({ command: "grep", args, toolName: "log_management", timeout: getToolTimeout("auditd") });

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

        // ── rotation_audit ─────────────────────────────────────────────────
        case "rotation_audit": {
          try {
            const findings: Array<{check: string, status: string, value: string, description: string}> = [];

            const lrResult = await executeCommand({ command: "cat", args: ["/etc/logrotate.conf"], timeout: 5000, toolName: "log_management" });
            findings.push({ check: "logrotate_config", status: lrResult.exitCode === 0 ? "PASS" : "FAIL", value: lrResult.exitCode === 0 ? "present" : "missing", description: "logrotate main configuration" });

            if (lrResult.exitCode === 0) {
              const hasCompress = lrResult.stdout.includes("compress");
              findings.push({ check: "logrotate_compress", status: hasCompress ? "PASS" : "WARN", value: hasCompress ? "enabled" : "not set", description: "Log compression enabled" });
              const rotateMatch = lrResult.stdout.match(/rotate\s+(\d+)/);
              if (rotateMatch) {
                findings.push({ check: "logrotate_retention", status: parseInt(rotateMatch[1]) >= 4 ? "PASS" : "WARN", value: `${rotateMatch[1]} rotations`, description: "Log retention count" });
              }
            }

            const journaldResult = await executeCommand({ command: "cat", args: ["/etc/systemd/journald.conf"], timeout: 5000, toolName: "log_management" });
            if (journaldResult.exitCode === 0) {
              const hasPersistent = journaldResult.stdout.includes("Storage=persistent");
              findings.push({ check: "journald_persistent", status: hasPersistent ? "PASS" : "WARN", value: hasPersistent ? "persistent" : "auto/volatile", description: "journald persistent storage (CIS recommends Storage=persistent)" });
              const compressMatch = journaldResult.stdout.match(/Compress=(yes|no)/i);
              findings.push({ check: "journald_compress", status: !compressMatch || compressMatch[1] === "yes" ? "PASS" : "WARN", value: compressMatch ? compressMatch[1] : "default (yes)", description: "journald compression" });
            }

            const logPerms = await executeCommand({ command: "stat", args: ["-c", "%a %U:%G", "/var/log"], timeout: 5000, toolName: "log_management" });
            findings.push({ check: "var_log_permissions", status: logPerms.stdout.trim().startsWith("755") || logPerms.stdout.trim().startsWith("750") ? "PASS" : "WARN", value: logPerms.stdout.trim(), description: "/var/log directory permissions" });

            const passCount = findings.filter(f => f.status === "PASS").length;
            return { content: [createTextContent(JSON.stringify({ summary: { total: findings.length, pass: passCount, fail: findings.filter(f => f.status === "FAIL").length, warn: findings.filter(f => f.status === "WARN").length }, findings }, null, 2))] };
          } catch (error) {
            return { content: [createErrorContent(error instanceof Error ? error.message : String(error))], isError: true };
          }
        }

        // ── rotation_configure ─────────────────────────────────────────────
        case "rotation_configure": {
          const {
            logrotate_path,
            logrotate_name,
            rotate_count = 7,
            rotate_frequency = "weekly",
            compress_logs = true,
            extra_directives,
            dry_run,
          } = params;
          try {
            if (!logrotate_path) {
              return { content: [createErrorContent("logrotate_path is required for rotation_configure action")], isError: true };
            }
            if (!logrotate_name) {
              return { content: [createErrorContent("logrotate_name is required for rotation_configure action")], isError: true };
            }

            // Validate logrotate_name: reject path traversal
            if (!/^[a-zA-Z0-9_-]+$/.test(logrotate_name)) {
              return { content: [createErrorContent(`Invalid logrotate_name '${logrotate_name}' — must match /^[a-zA-Z0-9_-]+$/ (no path separators)`)], isError: true };
            }

            // Validate extra_directives against safe list
            const SAFE_DIRECTIVES = [
              "missingok", "notifempty", "delaycompress", "copytruncate",
              "sharedscripts", "dateext", "dateformat", "create",
              "postrotate", "endscript", "prerotate", "firstaction",
              "lastaction", "su",
            ];
            if (extra_directives && extra_directives.length > 0) {
              for (const d of extra_directives) {
                const keyword = d.trim().split(/\s+/)[0];
                if (!SAFE_DIRECTIVES.includes(keyword)) {
                  return { content: [createErrorContent(`Unsafe logrotate directive '${keyword}' — allowed: ${SAFE_DIRECTIVES.join(", ")}`)], isError: true };
                }
              }
            }

            // Build logrotate config string
            const configLines: string[] = [];
            configLines.push(`${logrotate_path} {`);
            configLines.push(`    ${rotate_frequency}`);
            configLines.push(`    rotate ${rotate_count}`);
            if (compress_logs) {
              configLines.push("    compress");
            }
            if (extra_directives && extra_directives.length > 0) {
              for (const d of extra_directives) {
                configLines.push(`    ${d}`);
              }
            }
            configLines.push("}");
            const content = configLines.join("\n") + "\n";

            const configFilePath = `/etc/logrotate.d/${logrotate_name}`;

            if (dry_run ?? getConfig().dryRun) {
              logChange(createChangeEntry({
                tool: "log_management",
                action: "[DRY-RUN] Configure logrotate",
                target: configFilePath,
                after: content,
                dryRun: true,
                success: true,
              }));
              return { content: [createTextContent(`[DRY-RUN] Would write to ${configFilePath}:\n\n${content}`)] };
            }

            // Backup existing file if present
            if (existsSync(configFilePath)) {
              try { backupFile(configFilePath); } catch { /* file may not be readable without sudo */ }
            }

            // Write config via sudo tee
            const writeResult = await executeCommand({
              command: "sudo",
              args: ["tee", configFilePath],
              stdin: content,
              toolName: "log_management",
              timeout: getToolTimeout("auditd"),
            });

            const ok = writeResult.exitCode === 0;
            logChange(createChangeEntry({
              tool: "log_management",
              action: "Configure logrotate",
              target: configFilePath,
              after: content,
              dryRun: false,
              success: ok,
              error: ok ? undefined : writeResult.stderr,
              rollbackCommand: `sudo rm ${configFilePath}`,
            }));

            if (!ok) {
              return { content: [createErrorContent(`Failed to write ${configFilePath} (exit ${writeResult.exitCode}): ${writeResult.stderr}`)], isError: true };
            }

            return { content: [createTextContent(`Logrotate configuration written to ${configFilePath}:\n\n${content}`)] };
          } catch (err: unknown) {
            return { content: [createErrorContent(err instanceof Error ? err.message : String(err))], isError: true };
          }
        }

        // ── siem_syslog_forward ────────────────────────────────────────────
        case "siem_syslog_forward": {
          const outputFormat = params.output_format ?? "text";
          try {
            const syslog = await configureSyslogForward(
              params.siem_host,
              params.siem_port,
              params.protocol,
              params.log_sources,
            );

            const output = {
              action: "siem_syslog_forward",
              syslogDaemon: syslog.syslogDaemon,
              daemonInstalled: syslog.daemonInstalled,
              existingForwardingRules: syslog.existingForwardingRules,
              rsyslogModules: syslog.rsyslogModules,
              tlsSupport: syslog.tlsSupport,
              recommendedConfig: syslog.recommendedConfig,
              recommendations: syslog.recommendations,
            };

            if (outputFormat === "json") {
              return { content: [formatToolOutput(output)] };
            }

            let text = "SIEM Integration — Syslog Forwarding Configuration\n\n";
            text += `Syslog Daemon: ${syslog.syslogDaemon}\n`;
            text += `Daemon Installed: ${syslog.daemonInstalled ? "yes" : "no"}\n`;
            text += `TLS Support: ${syslog.tlsSupport ? "available" : "not available"}\n`;
            text += `Modules — imtcp: ${syslog.rsyslogModules.imtcp ? "loaded" : "not loaded"}, imudp: ${syslog.rsyslogModules.imudp ? "loaded" : "not loaded"}\n`;

            if (syslog.existingForwardingRules.length > 0) {
              text += `\nExisting Forwarding Rules (${syslog.existingForwardingRules.length}):\n`;
              for (const rule of syslog.existingForwardingRules) { text += `  • ${rule}\n`; }
            } else {
              text += "\nExisting Forwarding Rules: none\n";
            }

            if (syslog.recommendedConfig) {
              text += `\nRecommended Configuration:\n${syslog.recommendedConfig}\n`;
            }

            if (syslog.recommendations.length > 0) {
              text += "\nRecommendations:\n";
              for (const rec of syslog.recommendations) { text += `  • ${rec}\n`; }
            }

            return { content: [createTextContent(text)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`siem_syslog_forward failed: ${msg}`)], isError: true };
          }
        }

        // ── siem_filebeat ──────────────────────────────────────────────────
        case "siem_filebeat": {
          const outputFormat = params.output_format ?? "text";
          try {
            const filebeat = await configureFilebeat(params.siem_host, params.siem_port);

            const output = {
              action: "siem_filebeat",
              installed: filebeat.installed,
              version: filebeat.version,
              enabledModules: filebeat.enabledModules,
              disabledModules: filebeat.disabledModules,
              serviceRunning: filebeat.serviceRunning,
              serviceStatus: filebeat.serviceStatus,
              configPath: filebeat.configPath,
              recommendedConfig: filebeat.recommendedConfig,
              recommendations: filebeat.recommendations,
            };

            if (outputFormat === "json") {
              return { content: [formatToolOutput(output)] };
            }

            let text = "SIEM Integration — Filebeat Configuration\n\n";
            text += `Installed: ${filebeat.installed ? "yes" : "no"}\n`;

            if (!filebeat.installed) {
              text += "\nFilebeat is not installed.\n";
            } else {
              text += `Version: ${filebeat.version}\n`;
              text += `Service Running: ${filebeat.serviceRunning ? "yes ✓" : "no ⚠"}\n`;
              text += `Config Path: ${filebeat.configPath}\n`;

              if (filebeat.enabledModules.length > 0) {
                text += `\nEnabled Modules (${filebeat.enabledModules.length}):\n`;
                for (const mod of filebeat.enabledModules) { text += `  • ${mod}\n`; }
              } else {
                text += "\nEnabled Modules: none\n";
              }

              if (filebeat.disabledModules.length > 0) {
                text += `\nDisabled Modules (${filebeat.disabledModules.length}):\n`;
                for (const mod of filebeat.disabledModules.slice(0, 10)) { text += `  • ${mod}\n`; }
                if (filebeat.disabledModules.length > 10) {
                  text += `  ... and ${filebeat.disabledModules.length - 10} more\n`;
                }
              }
            }

            if (filebeat.recommendedConfig) {
              text += `\nRecommended Output Configuration:\n${filebeat.recommendedConfig}\n`;
            }

            if (filebeat.recommendations.length > 0) {
              text += "\nRecommendations:\n";
              for (const rec of filebeat.recommendations) { text += `  • ${rec}\n`; }
            }

            return { content: [createTextContent(text)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`siem_filebeat failed: ${msg}`)], isError: true };
          }
        }

        // ── siem_audit_forwarding ──────────────────────────────────────────
        case "siem_audit_forwarding": {
          const outputFormat = params.output_format ?? "text";
          try {
            const audit = await auditForwarding(params.log_sources);

            const output = {
              action: "siem_audit_forwarding",
              rsyslogForwarding: audit.rsyslogForwarding,
              rsyslogRules: audit.rsyslogRules,
              filebeatRunning: audit.filebeatRunning,
              criticalSourcesCovered: audit.criticalSourcesCovered,
              missingSourcesCount: audit.missingSourcesCount,
              logRotationInterferes: audit.logRotationInterferes,
              cisBenchmark: audit.cisBenchmark,
              cisCompliant: audit.cisCompliant,
              recommendations: audit.recommendations,
            };

            if (outputFormat === "json") {
              return { content: [formatToolOutput(output)] };
            }

            let text = "SIEM Integration — Log Forwarding Audit\n\n";
            text += `CIS Reference: ${audit.cisBenchmark}\n`;
            text += `CIS Compliant: ${audit.cisCompliant ? "YES ✓" : "NO ⚠"}\n\n`;
            text += `Rsyslog Forwarding: ${audit.rsyslogForwarding ? "configured" : "not configured"}\n`;
            text += `Filebeat Running: ${audit.filebeatRunning ? "yes" : "no"}\n`;

            if (audit.rsyslogRules.length > 0) {
              text += `\nRsyslog Forwarding Rules (${audit.rsyslogRules.length}):\n`;
              for (const rule of audit.rsyslogRules) { text += `  • ${rule}\n`; }
            }

            text += `\nCritical Log Source Coverage:\n`;
            for (const source of audit.criticalSourcesCovered) {
              text += `  • ${source.source} (${source.path}): ${source.forwarded ? "forwarded ✓" : "NOT forwarded ⚠"}\n`;
            }

            if (audit.missingSourcesCount > 0) {
              text += `\n⚠ Missing Sources: ${audit.missingSourcesCount}\n`;
            }
            if (audit.logRotationInterferes) {
              text += "\n⚠ Log rotation may interfere with forwarding\n";
            }
            if (audit.recommendations.length > 0) {
              text += "\nRecommendations:\n";
              for (const rec of audit.recommendations) { text += `  • ${rec}\n`; }
            }

            return { content: [createTextContent(text)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`siem_audit_forwarding failed: ${msg}`)], isError: true };
          }
        }

        // ── siem_test_connectivity ─────────────────────────────────────────
        case "siem_test_connectivity": {
          const outputFormat = params.output_format ?? "text";
          try {
            if (!params.siem_host) {
              return { content: [createErrorContent("test_connectivity requires siem_host parameter")], isError: true };
            }
            if (!validateSiemHost(params.siem_host)) {
              return { content: [createErrorContent(`Invalid siem_host format: ${params.siem_host}`)], isError: true };
            }

            const connectivity = await testConnectivity(
              params.siem_host,
              params.siem_port,
              params.protocol,
            );

            const output = {
              action: "siem_test_connectivity",
              siemHost: connectivity.siemHost,
              siemPort: connectivity.siemPort,
              protocol: connectivity.protocol,
              tcpConnectivity: connectivity.tcpConnectivity,
              tcpMessage: connectivity.tcpMessage,
              tlsVerification: connectivity.tlsVerification,
              tlsMessage: connectivity.tlsMessage,
              dnsResolution: connectivity.dnsResolution,
              dnsResult: connectivity.dnsResult,
              firewallStatus: connectivity.firewallStatus,
              firewallBlocked: connectivity.firewallBlocked,
              testMessageSent: connectivity.testMessageSent,
              testMessageResult: connectivity.testMessageResult,
              recommendations: connectivity.recommendations,
            };

            if (outputFormat === "json") {
              return { content: [formatToolOutput(output)] };
            }

            let text = "SIEM Integration — Connectivity Test\n\n";
            text += `Target: ${connectivity.siemHost}:${connectivity.siemPort} (${connectivity.protocol})\n\n`;
            text += `DNS Resolution: ${connectivity.dnsResolution ? "✓ " : "✗ "}${connectivity.dnsResult}\n`;
            text += `TCP Connectivity: ${connectivity.tcpConnectivity ? "✓ " : "✗ "}${connectivity.tcpMessage}\n`;

            if (connectivity.protocol === "tls") {
              text += `TLS Verification: ${connectivity.tlsVerification ? "✓ " : "✗ "}${connectivity.tlsMessage}\n`;
            }

            text += `Firewall: ${connectivity.firewallBlocked ? "⚠ BLOCKED" : connectivity.firewallStatus}\n`;
            text += `Test Message: ${connectivity.testMessageSent ? "✓ " : "✗ "}${connectivity.testMessageResult}\n`;

            if (connectivity.recommendations.length > 0) {
              text += "\nRecommendations:\n";
              for (const rec of connectivity.recommendations) { text += `  • ${rec}\n`; }
            }

            return { content: [createTextContent(text)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`siem_test_connectivity failed: ${msg}`)], isError: true };
          }
        }

        default:
          return { content: [createErrorContent(`Unknown action: ${action}`)], isError: true };
      }
    }
  );
}
