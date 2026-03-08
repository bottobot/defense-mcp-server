/**
 * Network defense tools for Kali Defense MCP Server.
 *
 * Registers 3 tools:
 *   netdef_connections (actions: list, audit)
 *   netdef_capture (actions: custom, dns, arp)
 *   netdef_security_audit (actions: scan_detect, ipv6, self_scan)
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeCommand } from "../core/executor.js";
import { getConfig, getToolTimeout } from "../core/config.js";
import {
  createTextContent,
  createErrorContent,
  parseSsOutput,
  formatToolOutput,
} from "../core/parsers.js";
import { logChange, createChangeEntry } from "../core/changelog.js";
import { validateInterface, sanitizeArgs, validateTarget as sanitizerValidateTarget, validateToolPath } from "../core/sanitizer.js";
import { validateBpfFilter } from "./ebpf-security.js";
import * as net from "node:net";

// ── TOOL-022 remediation: strict network parameter validation helpers ───────

/** Allowed protocol names for network operations */
const ALLOWED_PROTOCOLS = new Set(["tcp", "udp", "icmp", "sctp"]);

/** Validate an IP address strictly using net.isIP() */
function validateIPAddress(ip: string, label = "IP address"): string {
  const trimmed = ip.trim();
  // Could be CIDR
  if (trimmed.includes("/")) {
    return validateCIDR(trimmed, label);
  }
  if (net.isIP(trimmed) === 0) {
    throw new Error(`${label} is not a valid IP address: '${trimmed}'`);
  }
  return trimmed;
}

/** Validate a CIDR range (e.g., 192.168.1.0/24) */
function validateCIDR(cidr: string, label = "CIDR range"): string {
  const trimmed = cidr.trim();
  const cidrRe = /^([0-9a-fA-F.:]+)\/(\d{1,3})$/;
  const match = cidrRe.exec(trimmed);
  if (!match) {
    throw new Error(`${label} is not a valid CIDR notation: '${trimmed}'`);
  }
  const ip = match[1];
  const prefix = parseInt(match[2], 10);
  const ipVersion = net.isIP(ip);
  if (ipVersion === 0) {
    throw new Error(`${label} contains invalid IP address: '${ip}'`);
  }
  const maxPrefix = ipVersion === 4 ? 32 : 128;
  if (prefix < 0 || prefix > maxPrefix) {
    throw new Error(`${label} has invalid prefix length: /${prefix} (must be 0-${maxPrefix})`);
  }
  return trimmed;
}

/** Validate port number is in range 1-65535 */
function validatePortNumber(port: number, label = "Port"): number {
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`${label} must be an integer between 1 and 65535, got: ${port}`);
  }
  return port;
}

/** Validate protocol name against whitelist */
function validateProtocol(proto: string, label = "Protocol"): string {
  const lower = proto.trim().toLowerCase();
  if (!ALLOWED_PROTOCOLS.has(lower)) {
    throw new Error(`${label} '${proto}' is not allowed. Allowed: ${[...ALLOWED_PROTOCOLS].join(", ")}`);
  }
  return lower;
}

// ── TOOL-022: Allowed directories for log/output paths ─────────────────────
const ALLOWED_CAPTURE_DIRS = ["/tmp", "/var/log", "/home", "/root", "/opt"];

// ── Known safe ports for audit reference ───────────────────────────────────

const KNOWN_SAFE_PORTS: Record<number, string> = {
  22: "SSH",
  53: "DNS",
  80: "HTTP",
  443: "HTTPS",
  123: "NTP",
  323: "Chrony NTP",
  631: "CUPS (printing)",
  5353: "mDNS",
};

// ── Registration entry point ───────────────────────────────────────────────

export function registerNetworkDefenseTools(server: McpServer): void {
  // ── 1. netdef_connections (merged: connections + open_ports_audit) ─────

  server.tool(
    "netdef_connections",
    "Network connections: list active connections or audit listening ports for suspicious services.",
    {
      action: z.enum(["list", "audit"]).describe("Action: list=list active connections, audit=audit listening ports"),
      // list params
      protocol: z.enum(["tcp", "udp", "all"]).optional().default("all").describe("Protocol filter (list action)"),
      listening: z.boolean().optional().default(false).describe("Show only listening sockets (list action)"),
      process: z.boolean().optional().default(true).describe("Show process information (list action)"),
      // audit params
      include_loopback: z.boolean().optional().default(false).describe("Include services listening only on loopback (audit action)"),
    },
    async (params) => {
      const { action } = params;

      switch (action) {
        case "list": {
          const { protocol, listening, process: showProcess } = params;
          try {
            const args: string[] = [];
            if (protocol === "tcp") args.push("-t");
            else if (protocol === "udp") args.push("-u");
            else args.push("-t", "-u");
            if (listening) args.push("-l");
            args.push("-n");
            if (showProcess) args.push("-p");

            const result = await executeCommand({
              command: "ss", args, toolName: "netdef_connections",
              timeout: getToolTimeout("tcpdump"),
            });

            if (result.exitCode !== 0) {
              return { content: [createErrorContent(`ss command failed (exit ${result.exitCode}): ${result.stderr}`)], isError: true };
            }

            const parsed = parseSsOutput(result.stdout);
            return { content: [formatToolOutput({ protocol, listening, connectionCount: parsed.length, connections: parsed, raw: result.stdout })] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        case "audit": {
          const { include_loopback } = params;
          try {
            const result = await executeCommand({
              command: "ss", args: ["-tulnp"], toolName: "netdef_connections",
              timeout: getToolTimeout("tcpdump"),
            });

            if (result.exitCode !== 0) {
              return { content: [createErrorContent(`ss command failed (exit ${result.exitCode}): ${result.stderr}`)], isError: true };
            }

            const parsed = parseSsOutput(result.stdout);

            interface PortAuditEntry { protocol: string; localAddress: string; port: number; process: string; status: "safe" | "review" | "unknown"; note: string; }
            const auditEntries: PortAuditEntry[] = [];

            for (const entry of parsed) {
              const localParts = entry.local.split(":");
              const portStr = localParts[localParts.length - 1];
              const port = parseInt(portStr, 10);
              if (isNaN(port)) continue;

              const isLoopback = entry.local.startsWith("127.") || entry.local.startsWith("[::1]") || entry.local.startsWith("localhost");
              if (!include_loopback && isLoopback) continue;

              const knownService = KNOWN_SAFE_PORTS[port];
              let status: "safe" | "review" | "unknown";
              let note: string;

              if (knownService) { status = "safe"; note = `Known service: ${knownService}`; }
              else if (port < 1024) { status = "review"; note = "Privileged port - verify this service is expected"; }
              else if (port < 49152) { status = "unknown"; note = "Registered port - verify this service is authorized"; }
              else { status = "unknown"; note = "Ephemeral/dynamic port range"; }

              if (isLoopback) note += " (loopback only)";
              const proto = entry.state.toLowerCase().includes("udp") ? "udp" : "tcp";
              auditEntries.push({ protocol: proto, localAddress: entry.local, port, process: entry.process || "unknown", status, note });
            }

            const safeCount = auditEntries.filter((e) => e.status === "safe").length;
            const reviewCount = auditEntries.filter((e) => e.status === "review").length;
            const unknownCount = auditEntries.filter((e) => e.status === "unknown").length;

            return { content: [formatToolOutput({ totalListeners: auditEntries.length, summary: { safe: safeCount, needsReview: reviewCount, unknown: unknownCount }, listeners: auditEntries, raw: result.stdout })] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        default:
          return { content: [createErrorContent(`Unknown action: ${action}`)], isError: true };
      }
    }
  );

  // ── 2. netdef_capture (merged: tcpdump + dns_monitor + arp_monitor) ────

  server.tool(
    "netdef_capture",
    "Network capture: custom tcpdump capture, DNS query monitoring, or ARP traffic monitoring.",
    {
      action: z.enum(["custom", "dns", "arp"]).describe("Action: custom=tcpdump capture, dns=DNS monitoring, arp=ARP monitoring"),
      interface: z.string().min(1).optional().default("any").describe("Network interface to capture on"),
      count: z.number().optional().default(100).describe("Number of packets to capture"),
      duration: z.number().optional().default(30).describe("Capture duration in seconds"),
      // custom params
      filter: z.string().optional().describe("BPF filter expression (custom action)"),
      output_file: z.string().optional().describe("Path to save pcap file (custom action)"),
      dry_run: z.boolean().optional().describe("Preview the command without executing"),
    },
    async (params) => {
      const { action } = params;

      switch (action) {
        case "custom": {
          const { interface: iface, filter, count, output_file, duration, dry_run } = params;
          try {
            if (iface !== "any") validateInterface(iface);

            const args: string[] = ["-i", iface, "-c", String(count), "-n"];
            if (output_file) {
              // TOOL-022: Validate output file path for traversal
              validateToolPath(output_file, ALLOWED_CAPTURE_DIRS, "Capture output file path");
              args.push("-w", output_file);
            }
            if (filter) {
              // TOOL-018/022: Validate BPF filter expression
              const validatedFilter = validateBpfFilter(filter);
              args.push(...validatedFilter.split(/\s+/));
            }

            const fullCmd = `sudo tcpdump ${args.join(" ")}`;

            if (dry_run ?? getConfig().dryRun) {
              logChange(createChangeEntry({ tool: "netdef_capture", action: "[DRY-RUN] Capture network traffic", target: iface, after: fullCmd, dryRun: true, success: true }));
              return { content: [createTextContent(`[DRY-RUN] Would execute:\n  ${fullCmd}\n\nDuration: ${duration}s, Packets: ${count}`)] };
            }

            const captureTimeout = duration * 1000 + 5000;
            const result = await executeCommand({ command: "sudo", args: ["tcpdump", ...args], toolName: "netdef_capture", timeout: captureTimeout });

            logChange(createChangeEntry({ tool: "netdef_capture", action: "Capture network traffic", target: iface, after: fullCmd, dryRun: false, success: result.exitCode === 0 || result.timedOut }));

            return { content: [formatToolOutput({ interface: iface, filter: filter ?? "none", packetCount: count, duration, timedOut: result.timedOut, outputFile: output_file ?? "none (stdout)", captured: result.stdout, stats: result.stderr })] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        case "dns": {
          const { interface: iface, count, duration } = params;
          try {
            if (iface !== "any") validateInterface(iface);

            const args = ["-i", iface, "-c", String(count), "port", "53", "-n"];
            const captureTimeout = duration * 1000 + 5000;

            const result = await executeCommand({ command: "sudo", args: ["tcpdump", ...args], toolName: "netdef_capture", timeout: captureTimeout });

            const dnsLines = result.stdout.split("\n").filter((l) => l.trim().length > 0);
            const queries: string[] = [];
            const responses: string[] = [];

            for (const line of dnsLines) {
              if (line.includes("A?") || line.includes("AAAA?") || line.includes("PTR?") || line.includes("MX?")) queries.push(line.trim());
              else if (line.includes("A ") || line.includes("CNAME")) responses.push(line.trim());
            }

            return { content: [formatToolOutput({ interface: iface, duration, timedOut: result.timedOut, totalPackets: dnsLines.length, queries: queries.length, responses: responses.length, raw: result.stdout, stats: result.stderr })] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        case "arp": {
          const { interface: iface, count, duration } = params;
          try {
            if (iface !== "any") validateInterface(iface);

            const args = ["-i", iface, "-c", String(count), "arp", "-n"];
            const captureTimeout = duration * 1000 + 5000;

            const result = await executeCommand({ command: "sudo", args: ["tcpdump", ...args], toolName: "netdef_capture", timeout: captureTimeout });

            const arpLines = result.stdout.split("\n").filter((l) => l.trim().length > 0);
            const ipToMac: Record<string, Set<string>> = {};
            const arpRe = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+is-at\s+([0-9a-f:]+)/i;

            for (const line of arpLines) {
              const m = arpRe.exec(line);
              if (m) {
                const ip = m[1]; const mac = m[2];
                if (!ipToMac[ip]) ipToMac[ip] = new Set();
                ipToMac[ip].add(mac);
              }
            }

            const duplicates = Object.entries(ipToMac)
              .filter(([, macs]) => macs.size > 1)
              .map(([ip, macs]) => ({ ip, macAddresses: Array.from(macs), warning: "Multiple MAC addresses detected - possible ARP poisoning!" }));

            return { content: [formatToolOutput({
              interface: iface, duration, timedOut: result.timedOut, totalArpPackets: arpLines.length,
              uniqueIPs: Object.keys(ipToMac).length, arpPoisoningDetected: duplicates.length > 0, duplicateMappings: duplicates,
              ipToMacMap: Object.fromEntries(Object.entries(ipToMac).map(([ip, macs]) => [ip, Array.from(macs)])),
              raw: result.stdout, stats: result.stderr,
            })] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        default:
          return { content: [createErrorContent(`Unknown action: ${action}`)], isError: true };
      }
    }
  );

  // ── 3. netdef_security_audit (merged: port_scan_detect + ipv6 + self_scan) ──

  server.tool(
    "netdef_security_audit",
    "Network security audit: detect port scanning, audit IPv6 configuration, or run nmap self-scan.",
    {
      action: z.enum(["scan_detect", "ipv6", "self_scan"]).describe("Action: scan_detect=detect port scans, ipv6=audit IPv6, self_scan=nmap self-scan"),
      // scan_detect params
      log_file: z.string().optional().describe("Log file to analyze (scan_detect action)"),
      threshold: z.number().optional().default(10).describe("Connection attempts threshold (scan_detect action)"),
      timeframe: z.number().optional().default(60).describe("Seconds to look back (scan_detect action)"),
      // self_scan params
      target: z.enum(["localhost", "external"]).optional().default("localhost").describe("Scan target (self_scan action)"),
      scan_type: z.enum(["quick", "full", "service"]).optional().default("quick").describe("Scan type (self_scan action)"),
    },
    async (params) => {
      const { action } = params;

      switch (action) {
        case "scan_detect": {
          const { log_file, threshold, timeframe } = params;
          try {
            const sinceStr = `${String(timeframe)} seconds ago`;
            sanitizeArgs(["--since", sinceStr, "--no-pager"]);

            const journalArgs = ["--since", sinceStr, "--no-pager", "-g", "SYN|refused connection|connection attempt|UFW BLOCK"];

            const journalResult = await executeCommand({ command: "journalctl", args: journalArgs, toolName: "netdef_security_audit", timeout: getToolTimeout("tcpdump") });

            const dmesgArgs = ["-T", "--level=warn,err"];
            const dmesgResult = await executeCommand({ command: "dmesg", args: dmesgArgs, toolName: "netdef_security_audit", timeout: getToolTimeout("tcpdump") });

            const ipCounts: Record<string, number> = {};
            const ipRe = /SRC=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g;

            const combinedOutput = journalResult.stdout + "\n" + dmesgResult.stdout;
            let match;
            while ((match = ipRe.exec(combinedOutput)) !== null) {
              const ip = match[1];
              ipCounts[ip] = (ipCounts[ip] ?? 0) + 1;
            }

            const flaggedIPs = Object.entries(ipCounts)
              .filter(([, count]) => count >= threshold)
              .sort(([, a], [, b]) => b - a)
              .map(([ip, count]) => ({ ip, attempts: count }));

            return { content: [formatToolOutput({
              timeframe, threshold, totalUniqueSourceIPs: Object.keys(ipCounts).length,
              flaggedIPs, suspectedScan: flaggedIPs.length > 0,
              summary: flaggedIPs.length > 0 ? `${flaggedIPs.length} IP(s) exceeded the threshold of ${threshold} attempts` : "No port scanning activity detected above threshold",
              journalEntries: journalResult.stdout.split("\n").filter((l) => l.trim()).length,
            })] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        case "ipv6": {
          try {
            const findings: Array<{check: string, status: string, value: string, description: string}> = [];

            const ipv6All = await executeCommand({ command: "sysctl", args: ["net.ipv6.conf.all.disable_ipv6"], timeout: 5000, toolName: "netdef_security_audit" });
            const disabled = ipv6All.stdout.includes("= 1");
            findings.push({ check: "ipv6_disabled", status: "INFO", value: disabled ? "disabled" : "enabled", description: "IPv6 status (disable if not needed)" });

            if (!disabled) {
              const addrResult = await executeCommand({ command: "ip", args: ["-6", "addr", "show"], timeout: 5000, toolName: "netdef_security_audit" });
              const hasGlobal = addrResult.stdout.includes("scope global");
              findings.push({ check: "ipv6_global_address", status: hasGlobal ? "INFO" : "PASS", value: hasGlobal ? "has global IPv6 address" : "link-local only", description: "IPv6 global address presence" });

              const ip6tables = await executeCommand({ command: "sudo", args: ["ip6tables", "-L", "-n"], timeout: 10000, toolName: "netdef_security_audit" });
              const inputMatch = ip6tables.stdout.match(/Chain INPUT \(policy (\w+)\)/);
              findings.push({ check: "ipv6_firewall_input", status: inputMatch && (inputMatch[1] === "DROP" || inputMatch[1] === "REJECT") ? "PASS" : "FAIL", value: inputMatch ? inputMatch[1] : "unknown", description: "IPv6 INPUT chain policy (should be DROP if IPv6 enabled)" });

              const sysctlChecks = [
                { key: "net.ipv6.conf.all.accept_ra", expected: "0", desc: "Accept router advertisements" },
                { key: "net.ipv6.conf.all.accept_redirects", expected: "0", desc: "Accept redirects" },
                { key: "net.ipv6.conf.all.accept_source_route", expected: "0", desc: "Accept source route" },
              ];
              for (const sc of sysctlChecks) {
                const val = await executeCommand({ command: "sysctl", args: [sc.key], timeout: 5000, toolName: "netdef_security_audit" });
                const current = val.stdout.split("=").pop()?.trim() || "unknown";
                findings.push({ check: sc.key, status: current === sc.expected ? "PASS" : "FAIL", value: current, description: `${sc.desc} (should be ${sc.expected})` });
              }
            }

            return { content: [createTextContent(JSON.stringify({ summary: { total: findings.length, pass: findings.filter(f => f.status === "PASS").length, fail: findings.filter(f => f.status === "FAIL").length }, ipv6Enabled: !disabled, findings }, null, 2))] };
          } catch (error) {
            return { content: [createErrorContent(error instanceof Error ? error.message : String(error))], isError: true };
          }
        }

        case "self_scan": {
          try {
            let scanTarget = "127.0.0.1";
            if (params.target === "external") {
              const ipResult = await executeCommand({ command: "hostname", args: ["-I"], timeout: 5000, toolName: "netdef_security_audit" });
              scanTarget = ipResult.stdout.trim().split(" ")[0] || "127.0.0.1";
            }

            const args = [scanTarget];
            if (params.scan_type === "quick") args.unshift("-F");
            else if (params.scan_type === "full") args.unshift("-p-");
            else if (params.scan_type === "service") args.unshift("-sV", "-F");
            args.push("--open", "-n");

            const result = await executeCommand({ command: "nmap", args, timeout: 120000, toolName: "netdef_security_audit" });
            return { content: [createTextContent(`Self-Scan Results (target: ${scanTarget}, type: ${params.scan_type}):\n\n${result.stdout}\n${result.stderr ? `\nWarnings:\n${result.stderr}` : ""}`)] };
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
