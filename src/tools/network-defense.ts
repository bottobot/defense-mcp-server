/**
 * Network defense tools for Kali Defense MCP Server.
 *
 * Registers 4 tools:
 *   netdef_connections (actions: list, audit)
 *   netdef_capture (actions: custom, dns, arp)
 *   netdef_security_audit (actions: scan_detect, ipv6, self_scan)
 *   network_segmentation_audit (actions: map_zones, verify_isolation, test_paths, audit_vlans)
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
import { spawnSafe } from "../core/spawn-safe.js";
import type { ChildProcess } from "node:child_process";

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

// ── Segmentation audit command helpers ─────────────────────────────────────

interface SegmentCommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

/**
 * Run a command via spawnSafe for segmentation audit operations.
 * Returns collected stdout/stderr and exit code — never throws.
 */
async function runSegmentCommand(
  command: string,
  args: string[],
  timeoutMs = 30_000,
): Promise<SegmentCommandResult> {
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
    let settled = false;

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
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
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        resolve({ stdout, stderr, exitCode: code ?? -1 });
      }
    });

    child.on("error", (err: Error) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        resolve({ stdout, stderr: err.message, exitCode: -1 });
      }
    });
  });
}

async function runSudoSegmentCommand(
  command: string,
  args: string[],
  timeoutMs = 30_000,
): Promise<SegmentCommandResult> {
  return runSegmentCommand("sudo", [command, ...args], timeoutMs);
}

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

  // ── 4. network_segmentation_audit ────────────────────────────────────────

  server.tool(
    "network_segmentation_audit",
    "Network segmentation audit: map network zones, verify isolation enforcement, test paths between zones, audit VLAN configurations.",
    {
      action: z.enum(["map_zones", "verify_isolation", "test_paths", "audit_vlans"]).describe("Action: map_zones=map network zones, verify_isolation=check segmentation enforcement, test_paths=test connectivity between zones, audit_vlans=audit VLAN configs"),
      source_zone: z.string().optional().describe("Source network zone/subnet in CIDR notation (test_paths action)"),
      dest_zone: z.string().optional().describe("Destination network zone/subnet in CIDR notation (test_paths action)"),
      interface: z.string().optional().describe("Specific network interface to audit"),
      output_format: z.enum(["text", "json"]).optional().default("text").describe("Output format: text or json"),
    },
    async (params) => {
      const { action, output_format } = params;

      switch (action) {
        case "map_zones": {
          try {
            const ifaceFilter = params.interface;

            // Get network interfaces and subnets
            const addrResult = await runSegmentCommand("ip", ["addr", "show"]);

            // Get routing table
            const routeResult = await runSegmentCommand("ip", ["route", "show"]);

            // Get firewall rules
            const fwResult = await runSudoSegmentCommand("iptables", ["-L", "-n", "-v"]);

            // Get FORWARD chain specifically
            const fwdResult = await runSudoSegmentCommand("iptables", ["-L", "FORWARD", "-n", "-v"]);

            // Get bridge interfaces
            const bridgeResult = await runSegmentCommand("bridge", ["link", "show"]);

            // Parse interfaces into zone map
            interface ZoneInfo {
              interface: string;
              subnet: string;
              gateway: string | null;
              firewallRules: string[];
            }

            const zones: ZoneInfo[] = [];
            const ifaceBlocks = addrResult.stdout.split(/(?=^\d+:)/m).filter(b => b.trim());

            for (const block of ifaceBlocks) {
              const ifaceMatch = /^\d+:\s+(\S+?)(?:@\S+)?:/.exec(block);
              if (!ifaceMatch) continue;
              const ifaceName = ifaceMatch[1];
              if (ifaceName === "lo") continue;
              if (ifaceFilter && ifaceName !== ifaceFilter) continue;

              const inetMatches = [...block.matchAll(/inet\s+(\S+)/g)];
              for (const m of inetMatches) {
                const subnet = m[1];

                // Find gateway from route table
                let gateway: string | null = null;
                const routeLines = routeResult.stdout.split("\n");
                for (const line of routeLines) {
                  if (line.includes(ifaceName) && line.includes("via")) {
                    const gwMatch = /via\s+(\S+)/.exec(line);
                    if (gwMatch) { gateway = gwMatch[1]; break; }
                  }
                }

                // Find associated firewall rules
                const firewallRules: string[] = [];
                if (fwResult.exitCode === 0) {
                  const fwLines = fwResult.stdout.split("\n");
                  for (const line of fwLines) {
                    if (line.includes(subnet.split("/")[0]) || line.includes(ifaceName)) {
                      firewallRules.push(line.trim());
                    }
                  }
                }

                zones.push({ interface: ifaceName, subnet, gateway, firewallRules });
              }
            }

            const bridgeInterfaces: string[] = [];
            if (bridgeResult.exitCode === 0 && bridgeResult.stdout.trim()) {
              for (const line of bridgeResult.stdout.split("\n")) {
                if (line.trim()) bridgeInterfaces.push(line.trim());
              }
            }

            const zoneMap = {
              zones,
              totalZones: zones.length,
              forwardChain: fwdResult.exitCode === 0 ? fwdResult.stdout.trim() : "Unable to read FORWARD chain",
              bridgeInterfaces,
            };

            if (output_format === "json") {
              return { content: [formatToolOutput(zoneMap)] };
            }

            let text = `=== Network Zone Map ===\n\nTotal zones detected: ${zones.length}\n\n`;
            for (const zone of zones) {
              text += `Interface: ${zone.interface}\n`;
              text += `  Subnet: ${zone.subnet}\n`;
              text += `  Gateway: ${zone.gateway ?? "none"}\n`;
              text += `  Firewall rules: ${zone.firewallRules.length > 0 ? "\n    " + zone.firewallRules.join("\n    ") : "none"}\n\n`;
            }
            if (fwdResult.exitCode === 0) {
              text += `--- FORWARD Chain ---\n${fwdResult.stdout}\n`;
            }
            if (bridgeInterfaces.length > 0) {
              text += `--- Bridge Interfaces ---\n${bridgeInterfaces.join("\n")}\n`;
            }

            return { content: [createTextContent(text)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        case "verify_isolation": {
          try {
            const violations: string[] = [];
            let score = 100;

            // Check FORWARD chain default policy
            const fwdResult = await runSudoSegmentCommand("iptables", ["-L", "FORWARD", "-n"]);

            let forwardPolicy = "UNKNOWN";
            if (fwdResult.exitCode === 0) {
              const policyMatch = /Chain FORWARD \(policy (\w+)\)/.exec(fwdResult.stdout);
              if (policyMatch) {
                forwardPolicy = policyMatch[1];
                if (forwardPolicy !== "DROP" && forwardPolicy !== "REJECT") {
                  violations.push(`FORWARD chain default policy is ${forwardPolicy} (should be DROP or REJECT)`);
                  score -= 30;
                }
              }

              // Check for overly permissive rules (ACCEPT all from any to any)
              const fwdLines = fwdResult.stdout.split("\n");
              for (const line of fwdLines) {
                if (line.includes("ACCEPT") && line.includes("0.0.0.0/0") &&
                    (line.match(/0\.0\.0\.0\/0/g) || []).length >= 2) {
                  violations.push(`Overly permissive FORWARD rule: ${line.trim()}`);
                  score -= 20;
                }
              }
            } else {
              violations.push("Unable to read FORWARD chain - iptables may not be available");
              score -= 40;
            }

            // Check for NAT/masquerade rules that might bypass segmentation
            const natResult = await runSudoSegmentCommand("iptables", ["-t", "nat", "-L", "-n"]);
            const natBypasses: string[] = [];
            if (natResult.exitCode === 0) {
              const natLines = natResult.stdout.split("\n");
              for (const line of natLines) {
                if (line.includes("MASQUERADE") || line.includes("SNAT")) {
                  natBypasses.push(line.trim());
                }
              }
              if (natBypasses.length > 0) {
                violations.push(`NAT/masquerade rules detected that may bypass segmentation: ${natBypasses.length} rule(s)`);
                score -= 10;
              }
            }

            score = Math.max(0, score);

            const isolation = {
              forwardPolicy,
              violations,
              natBypasses,
              segmentationScore: score,
              segmentationStatus: score >= 80 ? "GOOD" : score >= 50 ? "FAIR" : "POOR",
              violationCount: violations.length,
            };

            if (output_format === "json") {
              return { content: [formatToolOutput(isolation)] };
            }

            let text = `=== Segmentation Isolation Verification ===\n\n`;
            text += `FORWARD Chain Policy: ${forwardPolicy}\n`;
            text += `Segmentation Score: ${score}/100 (${isolation.segmentationStatus})\n`;
            text += `Violations: ${violations.length}\n\n`;
            if (violations.length > 0) {
              text += `--- Violations ---\n`;
              for (const v of violations) {
                text += `  ⚠ ${v}\n`;
              }
            }
            if (natBypasses.length > 0) {
              text += `\n--- NAT/Masquerade Rules ---\n`;
              for (const n of natBypasses) {
                text += `  ${n}\n`;
              }
            }

            return { content: [createTextContent(text)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        case "test_paths": {
          const { source_zone, dest_zone } = params;
          if (!source_zone || !dest_zone) {
            return { content: [createErrorContent("test_paths requires both source_zone and dest_zone parameters (CIDR notation)")], isError: true };
          }

          try {
            validateCIDR(source_zone, "source_zone");
            validateCIDR(dest_zone, "dest_zone");

            const destIP = dest_zone.split("/")[0];

            // Try traceroute first, fall back to tracepath
            let traceResult = await runSegmentCommand("traceroute", ["-n", "-m", "15", destIP], 30_000);
            if (traceResult.exitCode !== 0) {
              traceResult = await runSegmentCommand("tracepath", ["-n", destIP], 30_000);
            }

            // Host discovery in target zone
            const nmapResult = await runSudoSegmentCommand("nmap", ["-sn", dest_zone], 60_000);

            const reachableHosts: string[] = [];
            if (nmapResult.exitCode === 0) {
              const hostRe = /Nmap scan report for (\S+)/g;
              let hm;
              while ((hm = hostRe.exec(nmapResult.stdout)) !== null) {
                reachableHosts.push(hm[1]);
              }
            }

            const pathResult = {
              sourceZone: source_zone,
              destZone: dest_zone,
              traceroute: traceResult.exitCode === 0 ? traceResult.stdout.trim() : `Trace failed: ${traceResult.stderr}`,
              reachableHosts,
              reachableHostCount: reachableHosts.length,
              pathExists: traceResult.exitCode === 0,
            };

            if (output_format === "json") {
              return { content: [formatToolOutput(pathResult)] };
            }

            let text = `=== Path Test: ${source_zone} → ${dest_zone} ===\n\n`;
            text += `--- Traceroute ---\n${traceResult.exitCode === 0 ? traceResult.stdout : `Failed: ${traceResult.stderr}`}\n\n`;
            text += `--- Host Discovery (${dest_zone}) ---\n`;
            text += `Reachable hosts: ${reachableHosts.length}\n`;
            for (const h of reachableHosts) {
              text += `  ${h}\n`;
            }

            return { content: [createTextContent(text)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        case "audit_vlans": {
          try {
            // List VLAN interfaces
            const linkResult = await runSegmentCommand("ip", ["-d", "link", "show"]);

            interface VlanInfo {
              interface: string;
              vlanId: string;
              parentInterface: string;
              flags: string;
            }
            const vlans: VlanInfo[] = [];

            if (linkResult.exitCode === 0) {
              const blocks = linkResult.stdout.split(/(?=^\d+:)/m).filter(b => b.trim());
              for (const block of blocks) {
                if (block.includes("vlan")) {
                  const ifMatch = /^\d+:\s+(\S+?)(?:@(\S+))?:/.exec(block);
                  const vlanIdMatch = /vlan.*?id\s+(\d+)/i.exec(block);
                  if (ifMatch && vlanIdMatch) {
                    vlans.push({
                      interface: ifMatch[1],
                      vlanId: vlanIdMatch[1],
                      parentInterface: ifMatch[2] || "unknown",
                      flags: (block.match(/<([^>]+)>/) || ["", ""])[1],
                    });
                  }
                }
              }
            }

            // Check VLAN tagging config
            let vlanConfig = "";
            const vlanConfigResult = await runSegmentCommand("cat", ["/proc/net/vlan/config"]);
            if (vlanConfigResult.exitCode === 0) {
              vlanConfig = vlanConfigResult.stdout.trim();
            }

            // Check 802.1Q support
            let dot1qSupported = vlanConfigResult.exitCode === 0;
            if (!dot1qSupported) {
              const lsmodResult = await runSegmentCommand("lsmod", []);
              if (lsmodResult.exitCode === 0 && lsmodResult.stdout.includes("8021q")) {
                dot1qSupported = true;
              }
            }

            // Security concerns
            const concerns: string[] = [];
            if (vlans.length === 0) {
              concerns.push("No VLAN interfaces detected - network may lack segmentation");
            }
            if (!dot1qSupported) {
              concerns.push("802.1Q VLAN support not detected");
            }
            // Check for promiscuous interfaces (possible trunk port exposure)
            if (linkResult.exitCode === 0 && linkResult.stdout.includes("PROMISC")) {
              concerns.push("Promiscuous interface detected - possible trunk port exposure");
            }

            const vlanAudit = {
              vlans,
              vlanCount: vlans.length,
              vlanConfig: vlanConfig || "Not available",
              dot1qSupported,
              securityConcerns: concerns,
            };

            if (output_format === "json") {
              return { content: [formatToolOutput(vlanAudit)] };
            }

            let text = `=== VLAN Audit ===\n\n`;
            text += `VLANs detected: ${vlans.length}\n`;
            text += `802.1Q support: ${dot1qSupported ? "yes" : "no"}\n\n`;
            if (vlans.length > 0) {
              text += `--- VLAN Interfaces ---\n`;
              for (const v of vlans) {
                text += `  ${v.interface}: VLAN ID ${v.vlanId} (parent: ${v.parentInterface})\n`;
              }
              text += "\n";
            }
            if (vlanConfig) {
              text += `--- VLAN Config ---\n${vlanConfig}\n\n`;
            }
            if (concerns.length > 0) {
              text += `--- Security Concerns ---\n`;
              for (const c of concerns) {
                text += `  ⚠ ${c}\n`;
              }
            }

            return { content: [createTextContent(text)] };
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
}
