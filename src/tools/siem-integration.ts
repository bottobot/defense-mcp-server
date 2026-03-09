/**
 * SIEM integration tools for Kali Defense MCP Server.
 *
 * Registers 1 tool: siem_export (actions: configure_syslog_forward,
 * configure_filebeat, audit_forwarding, test_connectivity)
 *
 * Provides syslog/rsyslog remote forwarding configuration, Filebeat
 * auditing, comprehensive log forwarding audit with CIS benchmark
 * references, and SIEM endpoint connectivity testing.
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

// ── Host validation ────────────────────────────────────────────────────────────

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

// ── Action implementations ─────────────────────────────────────────────────────

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

  // Check which syslog daemon is installed
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

  // Read current rsyslog config
  const configResult = await runCommand("cat", ["/etc/rsyslog.conf"], 10_000);
  if (configResult.exitCode === 0) {
    result.currentConfig = configResult.stdout;

    // Check for existing remote forwarding rules
    // rsyslog forwarding rules can be:
    //   *.* @@host:port  (TCP)
    //   *.* @host:port   (UDP)
    //   auth.* @@host:port
    const lines = configResult.stdout.split("\n");
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith("#") || trimmed.length === 0) continue;
      // Match lines with @@ (TCP forwarding) or @ (UDP forwarding) after facility
      if (/\s@@[^\s]/.test(trimmed) || /\s@[^@\s]/.test(trimmed)) {
        result.existingForwardingRules.push(trimmed);
      }
    }

    // Check loaded modules
    result.rsyslogModules.imtcp = configResult.stdout.includes("imtcp");
    result.rsyslogModules.imudp = configResult.stdout.includes("imudp");
  }

  // Also check /etc/rsyslog.d/ for forwarding rules
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

  // Check for TLS support (gtls driver)
  const tlsCheck = await runCommand("dpkg", ["-l", "rsyslog-gnutls"], 10_000);
  result.tlsSupport = tlsCheck.exitCode === 0 && tlsCheck.stdout.includes("ii");

  // Generate recommended config if siem_host provided
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

  // Recommendations
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

  // Check if filebeat is installed
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

  // Get version
  const versionResult = await runCommand("filebeat", ["version"], 10_000);
  if (versionResult.exitCode === 0) {
    result.version = versionResult.stdout.trim();
  }

  // Read config
  const configResult = await runCommand("cat", ["/etc/filebeat/filebeat.yml"], 10_000);
  if (configResult.exitCode === 0) {
    result.outputConfig = configResult.stdout;

    // Parse output section
    const lines = configResult.stdout.split("\n");
    let inOutput = false;
    for (const line of lines) {
      if (line.match(/^output\./)) {
        inOutput = true;
      }
      if (inOutput && line.trim().length > 0 && !line.startsWith(" ") && !line.startsWith("\t") && !line.match(/^output\./)) {
        inOutput = false;
      }
    }
  }

  // Check enabled modules
  const modulesResult = await runCommand("filebeat", ["modules", "list"], 15_000);
  if (modulesResult.exitCode === 0) {
    const lines = modulesResult.stdout.split("\n");
    let inEnabled = false;
    let inDisabled = false;

    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed === "Enabled:") {
        inEnabled = true;
        inDisabled = false;
        continue;
      }
      if (trimmed === "Disabled:") {
        inEnabled = false;
        inDisabled = true;
        continue;
      }
      if (trimmed.length > 0) {
        if (inEnabled) result.enabledModules.push(trimmed);
        if (inDisabled) result.disabledModules.push(trimmed);
      }
    }
  }

  // Check service status
  const serviceResult = await runCommand("systemctl", ["status", "filebeat"], 10_000);
  if (serviceResult.exitCode === 0 || serviceResult.exitCode === 3) {
    result.serviceStatus = serviceResult.stdout.trim();
    result.serviceRunning = serviceResult.stdout.includes("active (running)");
  }

  // Generate recommended config if siem_host provided
  if (siemHost) {
    result.recommendedConfig =
      "# Filebeat output configuration for Logstash\n" +
      "output.logstash:\n" +
      `  hosts: ["${siemHost}:${effectivePort}"]\n` +
      "  ssl.enabled: true\n" +
      "  ssl.certificate_authorities: ['/etc/filebeat/ca.pem']\n";
  }

  // Recommendations
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

  // Check rsyslog forwarding rules
  const rsyslogConfig = await runCommand("cat", ["/etc/rsyslog.conf"], 10_000);
  if (rsyslogConfig.exitCode === 0) {
    const lines = rsyslogConfig.stdout.split("\n");
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith("#") || trimmed.length === 0) continue;
      // Match lines with @@ (TCP forwarding) or @ (UDP forwarding) after facility
      if (/\s@@[^\s]/.test(trimmed) || /\s@[^@\s]/.test(trimmed)) {
        result.rsyslogRules.push(trimmed);
        result.rsyslogForwarding = true;
      }
      // Also check for action-based forwarding
      if (trimmed.includes("action(type=\"omfwd\"")) {
        result.rsyslogRules.push(trimmed);
        result.rsyslogForwarding = true;
      }
    }
  }

  // Check filebeat status
  const filebeatResult = await runCommand("systemctl", ["status", "filebeat"], 10_000);
  if (filebeatResult.exitCode === 0 || filebeatResult.exitCode === 3) {
    result.filebeatStatus = filebeatResult.stdout.trim();
    result.filebeatRunning = filebeatResult.stdout.includes("active (running)");
  }

  // Check coverage of critical log sources
  const configContent = rsyslogConfig.exitCode === 0 ? rsyslogConfig.stdout : "";

  for (const source of sourcesToCheck) {
    const logPath = LOG_SOURCE_FILES[source] ?? `/var/log/${source}.log`;
    let forwarded = false;

    // Check if rsyslog has a forwarding rule that covers this source
    if (result.rsyslogForwarding) {
      // Wildcard rule covers everything
      if (result.rsyslogRules.some((r) => r.includes("*.*"))) {
        forwarded = true;
      }
      // Specific facility rule
      if (result.rsyslogRules.some((r) => r.includes(`${source}.*`))) {
        forwarded = true;
      }
      // Check if config mentions this source with forwarding
      if (configContent.includes(source) && result.rsyslogForwarding) {
        forwarded = true;
      }
    }

    // Filebeat covers log sources via modules
    if (result.filebeatRunning) {
      forwarded = true; // Filebeat with system module covers standard logs
    }

    result.criticalSourcesCovered.push({ source, forwarded, path: logPath });
    if (!forwarded) {
      result.missingSourcesCount++;
    }
  }

  // Check log rotation config
  const logrotateResult = await runCommand("cat", ["/etc/logrotate.d/rsyslog"], 10_000);
  if (logrotateResult.exitCode === 0) {
    result.logRotationConfig = logrotateResult.stdout;

    // Check for sharedscripts and postrotate that restarts rsyslog
    if (!logrotateResult.stdout.includes("sharedscripts") ||
        !logrotateResult.stdout.includes("postrotate")) {
      result.logRotationInterferes = true;
      result.recommendations.push("Log rotation may interfere with forwarding — ensure sharedscripts and postrotate with rsyslog reload are configured");
    }
  }

  // CIS compliance check
  result.cisCompliant = result.rsyslogForwarding || result.filebeatRunning;

  // Recommendations
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

  // Test DNS resolution
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

  // Test TCP connectivity
  const ncResult = await runCommand("nc", ["-z", "-w", "5", siemHost, String(effectivePort)], 15_000);
  if (ncResult.exitCode === 0) {
    result.tcpConnectivity = true;
    result.tcpMessage = `TCP connection to ${siemHost}:${effectivePort} successful`;
  } else {
    result.tcpConnectivity = false;
    result.tcpMessage = `TCP connection to ${siemHost}:${effectivePort} failed`;
    result.recommendations.push(`Cannot reach ${siemHost}:${effectivePort} — check network connectivity and firewall rules`);
  }

  // Test TLS if protocol is TLS
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

  // Check firewall rules for the port
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

  // Send test syslog message
  const loggerResult = await runCommand(
    "logger",
    ["-n", siemHost, "-P", String(effectivePort), "--tcp", "kali-defense SIEM connectivity test"],
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

  // Overall connectivity assessment
  if (!result.tcpConnectivity && !result.dnsResolution) {
    result.recommendations.push("CRITICAL: SIEM endpoint is unreachable — verify host, port, and network path");
  } else if (!result.tcpConnectivity) {
    result.recommendations.push("DNS resolves but TCP connection fails — check if SIEM is listening on the specified port");
  }

  return result;
}

// ── Registration entry point ───────────────────────────────────────────────

export function registerSiemIntegrationTools(server: McpServer): void {
  server.tool(
    "siem_export",
    "SIEM integration: configure syslog forwarding, audit Filebeat, comprehensive log forwarding audit with CIS benchmarks, and test SIEM endpoint connectivity.",
    {
      action: z
        .enum(["configure_syslog_forward", "configure_filebeat", "audit_forwarding", "test_connectivity"])
        .describe(
          "Action: configure_syslog_forward=audit/configure rsyslog remote forwarding, configure_filebeat=audit Filebeat configuration, audit_forwarding=comprehensive log forwarding audit, test_connectivity=test SIEM endpoint connectivity",
        ),
      siem_host: z
        .string()
        .optional()
        .describe("SIEM server hostname or IP address"),
      siem_port: z
        .number()
        .optional()
        .describe("SIEM server port (default 514 for syslog, 5044 for filebeat)"),
      protocol: z
        .enum(["tcp", "udp", "tls"])
        .optional()
        .default("tcp")
        .describe("Transport protocol (default tcp)"),
      log_sources: z
        .array(z.string())
        .optional()
        .describe("Log sources to forward (e.g., auth, syslog, kern, audit)"),
      output_format: z
        .enum(["text", "json"])
        .optional()
        .default("text")
        .describe("Output format (default text)"),
    },
    async (params) => {
      const { action } = params;
      const outputFormat = params.output_format ?? "text";

      switch (action) {
        // ── configure_syslog_forward ─────────────────────────────────────
        case "configure_syslog_forward": {
          try {
            const syslog = await configureSyslogForward(
              params.siem_host,
              params.siem_port,
              params.protocol,
              params.log_sources,
            );

            const output = {
              action: "configure_syslog_forward",
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
              for (const rule of syslog.existingForwardingRules) {
                text += `  • ${rule}\n`;
              }
            } else {
              text += "\nExisting Forwarding Rules: none\n";
            }

            if (syslog.recommendedConfig) {
              text += `\nRecommended Configuration:\n${syslog.recommendedConfig}\n`;
            }

            if (syslog.recommendations.length > 0) {
              text += "\nRecommendations:\n";
              for (const rec of syslog.recommendations) {
                text += `  • ${rec}\n`;
              }
            }

            return { content: [createTextContent(text)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`configure_syslog_forward failed: ${msg}`)], isError: true };
          }
        }

        // ── configure_filebeat ───────────────────────────────────────────
        case "configure_filebeat": {
          try {
            const filebeat = await configureFilebeat(
              params.siem_host,
              params.siem_port,
            );

            const output = {
              action: "configure_filebeat",
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
                for (const mod of filebeat.enabledModules) {
                  text += `  • ${mod}\n`;
                }
              } else {
                text += "\nEnabled Modules: none\n";
              }

              if (filebeat.disabledModules.length > 0) {
                text += `\nDisabled Modules (${filebeat.disabledModules.length}):\n`;
                for (const mod of filebeat.disabledModules.slice(0, 10)) {
                  text += `  • ${mod}\n`;
                }
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
              for (const rec of filebeat.recommendations) {
                text += `  • ${rec}\n`;
              }
            }

            return { content: [createTextContent(text)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`configure_filebeat failed: ${msg}`)], isError: true };
          }
        }

        // ── audit_forwarding ─────────────────────────────────────────────
        case "audit_forwarding": {
          try {
            const audit = await auditForwarding(params.log_sources);

            const output = {
              action: "audit_forwarding",
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
              for (const rule of audit.rsyslogRules) {
                text += `  • ${rule}\n`;
              }
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
              for (const rec of audit.recommendations) {
                text += `  • ${rec}\n`;
              }
            }

            return { content: [createTextContent(text)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`audit_forwarding failed: ${msg}`)], isError: true };
          }
        }

        // ── test_connectivity ────────────────────────────────────────────
        case "test_connectivity": {
          try {
            if (!params.siem_host) {
              return {
                content: [createErrorContent("test_connectivity requires siem_host parameter")],
                isError: true,
              };
            }

            if (!validateSiemHost(params.siem_host)) {
              return {
                content: [createErrorContent(`Invalid siem_host format: ${params.siem_host}`)],
                isError: true,
              };
            }

            const connectivity = await testConnectivity(
              params.siem_host,
              params.siem_port,
              params.protocol,
            );

            const output = {
              action: "test_connectivity",
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
              for (const rec of connectivity.recommendations) {
                text += `  • ${rec}\n`;
              }
            }

            return { content: [createTextContent(text)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`test_connectivity failed: ${msg}`)], isError: true };
          }
        }

        default:
          return { content: [createErrorContent(`Unknown action: ${action}`)], isError: true };
      }
    },
  );
}
