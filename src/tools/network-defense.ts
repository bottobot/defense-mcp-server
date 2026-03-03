/**
 * Network defense tools for Kali Defense MCP Server.
 *
 * Registers 6 tools: netdef_connections, netdef_port_scan_detect,
 * netdef_tcpdump_capture, netdef_dns_monitor, netdef_arp_monitor,
 * netdef_open_ports_audit.
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
import { validateInterface, sanitizeArgs } from "../core/sanitizer.js";

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
  // ── 1. netdef_connections ────────────────────────────────────────────

  server.tool(
    "netdef_connections",
    "List active network connections with optional protocol and state filtering",
    {
      protocol: z
        .enum(["tcp", "udp", "all"])
        .optional()
        .default("all")
        .describe("Protocol filter (tcp, udp, or all)"),
      listening: z
        .boolean()
        .optional()
        .default(false)
        .describe("Show only listening sockets"),
      process: z
        .boolean()
        .optional()
        .default(true)
        .describe("Show process information for each connection"),
    },
    async ({ protocol, listening, process: showProcess }) => {
      try {
        const args: string[] = [];

        // Protocol flags
        if (protocol === "tcp") {
          args.push("-t");
        } else if (protocol === "udp") {
          args.push("-u");
        } else {
          args.push("-t", "-u");
        }

        if (listening) {
          args.push("-l");
        }

        // Always show numeric addresses
        args.push("-n");

        if (showProcess) {
          args.push("-p");
        }

        const result = await executeCommand({
          command: "ss",
          args,
          toolName: "netdef_connections",
          timeout: getToolTimeout("tcpdump"),
        });

        if (result.exitCode !== 0) {
          return {
            content: [createErrorContent(`ss command failed (exit ${result.exitCode}): ${result.stderr}`)],
            isError: true,
          };
        }

        const parsed = parseSsOutput(result.stdout);

        const output = {
          protocol,
          listening,
          connectionCount: parsed.length,
          connections: parsed,
          raw: result.stdout,
        };

        return { content: [formatToolOutput(output)] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 2. netdef_port_scan_detect ──────────────────────────────────────

  server.tool(
    "netdef_port_scan_detect",
    "Check system logs for signs of port scanning activity",
    {
      log_file: z
        .string()
        .optional()
        .describe("Log file to analyze for scan indicators (auto-detected per distro if omitted)"),
      threshold: z
        .number()
        .optional()
        .default(10)
        .describe("Number of connection attempts from same source to flag"),
      timeframe: z
        .number()
        .optional()
        .default(60)
        .describe("How far back to search in seconds (e.g. 60 = last 60 seconds)"),
    },
    async ({ log_file, threshold, timeframe }) => {
      try {
        // Convert numeric timeframe (seconds) to journalctl --since format
        const sinceStr = `${String(timeframe)} seconds ago`;

        // Use journalctl to search for network connection patterns
        // Sanitize user-controlled args separately; the grep pattern
        // contains pipe characters that are safe with spawn(shell:false)
        // but would be rejected by the shell-metacharacter check.
        sanitizeArgs(["--since", sinceStr, "--no-pager"]);

        const journalArgs = [
          "--since", sinceStr,
          "--no-pager",
          "-g", "SYN|refused connection|connection attempt|UFW BLOCK",
        ];

        const journalResult = await executeCommand({
          command: "journalctl",
          args: journalArgs,
          toolName: "netdef_port_scan_detect",
          timeout: getToolTimeout("tcpdump"),
        });

        // Also check for kernel dropped/rejected packets
        const dmesgArgs = ["-T", "--level=warn,err"];
        const dmesgResult = await executeCommand({
          command: "dmesg",
          args: dmesgArgs,
          toolName: "netdef_port_scan_detect",
          timeout: getToolTimeout("tcpdump"),
        });

        // Analyze journalctl output for repeated source IPs
        const ipCounts: Record<string, number> = {};
        const ipRe = /SRC=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g;

        const combinedOutput = journalResult.stdout + "\n" + dmesgResult.stdout;
        let match;
        while ((match = ipRe.exec(combinedOutput)) !== null) {
          const ip = match[1];
          ipCounts[ip] = (ipCounts[ip] ?? 0) + 1;
        }

        // Flag IPs exceeding threshold
        const flaggedIPs = Object.entries(ipCounts)
          .filter(([, count]) => count >= threshold)
          .sort(([, a], [, b]) => b - a)
          .map(([ip, count]) => ({ ip, attempts: count }));

        const output = {
          timeframe,
          threshold,
          totalUniqueSourceIPs: Object.keys(ipCounts).length,
          flaggedIPs,
          suspectedScan: flaggedIPs.length > 0,
          summary: flaggedIPs.length > 0
            ? `${flaggedIPs.length} IP(s) exceeded the threshold of ${threshold} attempts`
            : "No port scanning activity detected above threshold",
          journalEntries: journalResult.stdout.split("\n").filter((l) => l.trim()).length,
        };

        return { content: [formatToolOutput(output)] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 3. netdef_tcpdump_capture ───────────────────────────────────────

  server.tool(
    "netdef_tcpdump_capture",
    "Capture network traffic using tcpdump with BPF filter support",
    {
      interface: z
        .string()
        .optional()
        .default("any")
        .describe("Network interface to capture on (default: any)"),
      filter: z
        .string()
        .optional()
        .describe("BPF filter expression, e.g. 'port 80', 'host 10.0.0.1'"),
      count: z
        .number()
        .optional()
        .default(100)
        .describe("Number of packets to capture"),
      output_file: z
        .string()
        .optional()
        .describe("Path to save pcap file (optional)"),
      duration: z
        .number()
        .optional()
        .default(30)
        .describe("Capture duration in seconds"),
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview the command without executing (defaults to KALI_DEFENSE_DRY_RUN env var)"),
    },
    async ({ interface: iface, filter, count, output_file, duration, dry_run }) => {
      try {
        // Validate interface if not "any"
        if (iface !== "any") {
          validateInterface(iface);
        }

        const args: string[] = ["-i", iface, "-c", String(count), "-n"];

        if (output_file) {
          sanitizeArgs([output_file]);
          args.push("-w", output_file);
        }

        if (filter) {
          sanitizeArgs([filter]);
          args.push(...filter.split(/\s+/));
        }

        const fullCmd = `sudo tcpdump ${args.join(" ")}`;

        if (dry_run ?? getConfig().dryRun) {
          const entry = createChangeEntry({
            tool: "netdef_tcpdump_capture",
            action: "[DRY-RUN] Capture network traffic",
            target: iface,
            after: fullCmd,
            dryRun: true,
            success: true,
          });
          logChange(entry);

          return {
            content: [createTextContent(`[DRY-RUN] Would execute:\n  ${fullCmd}\n\nDuration: ${duration}s, Packets: ${count}`)],
          };
        }

        const captureTimeout = duration * 1000 + 5000;

        const result = await executeCommand({
          command: "sudo",
          args: ["tcpdump", ...args],
          toolName: "netdef_tcpdump_capture",
          timeout: captureTimeout,
        });

        const entry = createChangeEntry({
          tool: "netdef_tcpdump_capture",
          action: "Capture network traffic",
          target: iface,
          after: fullCmd,
          dryRun: false,
          success: result.exitCode === 0 || result.timedOut,
        });
        logChange(entry);

        // tcpdump outputs to stderr for stats
        const output = {
          interface: iface,
          filter: filter ?? "none",
          packetCount: count,
          duration,
          timedOut: result.timedOut,
          outputFile: output_file ?? "none (stdout)",
          captured: result.stdout,
          stats: result.stderr,
        };

        return { content: [formatToolOutput(output)] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 4. netdef_dns_monitor ───────────────────────────────────────────

  server.tool(
    "netdef_dns_monitor",
    "Monitor DNS queries on the network using tcpdump",
    {
      interface: z
        .string()
        .optional()
        .default("any")
        .describe("Network interface to monitor"),
      count: z
        .number()
        .optional()
        .default(50)
        .describe("Number of DNS packets to capture"),
      duration: z
        .number()
        .optional()
        .default(30)
        .describe("Capture duration in seconds"),
    },
    async ({ interface: iface, count, duration }) => {
      try {
        if (iface !== "any") {
          validateInterface(iface);
        }

        const args = ["-i", iface, "-c", String(count), "port", "53", "-n"];
        const captureTimeout = duration * 1000 + 5000;

        const result = await executeCommand({
          command: "sudo",
          args: ["tcpdump", ...args],
          toolName: "netdef_dns_monitor",
          timeout: captureTimeout,
        });

        // Parse DNS queries from tcpdump output
        const dnsLines = result.stdout.split("\n").filter((l) => l.trim().length > 0);
        const queries: string[] = [];
        const responses: string[] = [];

        for (const line of dnsLines) {
          if (line.includes("A?") || line.includes("AAAA?") || line.includes("PTR?") || line.includes("MX?")) {
            queries.push(line.trim());
          } else if (line.includes("A ") || line.includes("CNAME")) {
            responses.push(line.trim());
          }
        }

        const output = {
          interface: iface,
          duration,
          timedOut: result.timedOut,
          totalPackets: dnsLines.length,
          queries: queries.length,
          responses: responses.length,
          raw: result.stdout,
          stats: result.stderr,
        };

        return { content: [formatToolOutput(output)] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 5. netdef_arp_monitor ───────────────────────────────────────────

  server.tool(
    "netdef_arp_monitor",
    "Monitor ARP traffic to detect potential ARP poisoning attacks",
    {
      interface: z
        .string()
        .optional()
        .default("any")
        .describe("Network interface to monitor"),
      count: z
        .number()
        .optional()
        .default(100)
        .describe("Number of ARP packets to capture"),
      duration: z
        .number()
        .optional()
        .default(30)
        .describe("Capture duration in seconds"),
    },
    async ({ interface: iface, count, duration }) => {
      try {
        if (iface !== "any") {
          validateInterface(iface);
        }

        const args = ["-i", iface, "-c", String(count), "arp", "-n"];
        const captureTimeout = duration * 1000 + 5000;

        const result = await executeCommand({
          command: "sudo",
          args: ["tcpdump", ...args],
          toolName: "netdef_arp_monitor",
          timeout: captureTimeout,
        });

        // Parse ARP packets and detect duplicate IP-to-MAC mappings
        const arpLines = result.stdout.split("\n").filter((l) => l.trim().length > 0);
        const ipToMac: Record<string, Set<string>> = {};
        const arpRe = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+is-at\s+([0-9a-f:]+)/i;

        for (const line of arpLines) {
          const m = arpRe.exec(line);
          if (m) {
            const ip = m[1];
            const mac = m[2];
            if (!ipToMac[ip]) {
              ipToMac[ip] = new Set();
            }
            ipToMac[ip].add(mac);
          }
        }

        // Detect IPs with multiple MAC addresses (ARP poisoning indicator)
        const duplicates = Object.entries(ipToMac)
          .filter(([, macs]) => macs.size > 1)
          .map(([ip, macs]) => ({
            ip,
            macAddresses: Array.from(macs),
            warning: "Multiple MAC addresses detected - possible ARP poisoning!",
          }));

        const output = {
          interface: iface,
          duration,
          timedOut: result.timedOut,
          totalArpPackets: arpLines.length,
          uniqueIPs: Object.keys(ipToMac).length,
          arpPoisoningDetected: duplicates.length > 0,
          duplicateMappings: duplicates,
          ipToMacMap: Object.fromEntries(
            Object.entries(ipToMac).map(([ip, macs]) => [ip, Array.from(macs)])
          ),
          raw: result.stdout,
          stats: result.stderr,
        };

        return { content: [formatToolOutput(output)] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 6. netdef_open_ports_audit ──────────────────────────────────────

  server.tool(
    "netdef_open_ports_audit",
    "Audit listening ports and their processes, flagging potentially suspicious services",
    {
      include_loopback: z
        .boolean()
        .optional()
        .default(false)
        .describe("Include services listening only on loopback/localhost"),
    },
    async ({ include_loopback }) => {
      try {
        const result = await executeCommand({
          command: "ss",
          args: ["-tulnp"],
          toolName: "netdef_open_ports_audit",
          timeout: getToolTimeout("tcpdump"),
        });

        if (result.exitCode !== 0) {
          return {
            content: [createErrorContent(`ss command failed (exit ${result.exitCode}): ${result.stderr}`)],
            isError: true,
          };
        }

        const parsed = parseSsOutput(result.stdout);

        // Analyze each listener
        interface PortAuditEntry {
          protocol: string;
          localAddress: string;
          port: number;
          process: string;
          status: "safe" | "review" | "unknown";
          note: string;
        }

        const auditEntries: PortAuditEntry[] = [];

        for (const entry of parsed) {
          // Extract port from local address (e.g., "*:22", "0.0.0.0:80", "[::]:443")
          const localParts = entry.local.split(":");
          const portStr = localParts[localParts.length - 1];
          const port = parseInt(portStr, 10);

          if (isNaN(port)) continue;

          // Check if listening on loopback
          const isLoopback =
            entry.local.startsWith("127.") ||
            entry.local.startsWith("[::1]") ||
            entry.local.startsWith("localhost");

          if (!include_loopback && isLoopback) continue;

          const knownService = KNOWN_SAFE_PORTS[port];
          let status: "safe" | "review" | "unknown";
          let note: string;

          if (knownService) {
            status = "safe";
            note = `Known service: ${knownService}`;
          } else if (port < 1024) {
            status = "review";
            note = "Privileged port - verify this service is expected";
          } else if (port >= 1024 && port < 49152) {
            status = "unknown";
            note = "Registered port - verify this service is authorized";
          } else {
            status = "unknown";
            note = "Ephemeral/dynamic port range";
          }

          if (isLoopback) {
            note += " (loopback only)";
          }

          // Determine protocol from state column patterns
          const proto = entry.state.toLowerCase().includes("udp") ? "udp" : "tcp";

          auditEntries.push({
            protocol: proto,
            localAddress: entry.local,
            port,
            process: entry.process || "unknown",
            status,
            note,
          });
        }

        const safeCount = auditEntries.filter((e) => e.status === "safe").length;
        const reviewCount = auditEntries.filter((e) => e.status === "review").length;
        const unknownCount = auditEntries.filter((e) => e.status === "unknown").length;

        const output = {
          totalListeners: auditEntries.length,
          summary: {
            safe: safeCount,
            needsReview: reviewCount,
            unknown: unknownCount,
          },
          listeners: auditEntries,
          raw: result.stdout,
        };

        return { content: [formatToolOutput(output)] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── netdef_ipv6_audit ─────────────────────────────────────────────────
  server.tool(
    "netdef_ipv6_audit",
    "Audit IPv6 configuration and security. Check if IPv6 is needed, properly firewalled, or should be disabled.",
    {},
    async () => {
      try {
        const findings: Array<{check: string, status: string, value: string, description: string}> = [];

        // Check if IPv6 is enabled
        const ipv6All = await executeCommand({ command: "sysctl", args: ["net.ipv6.conf.all.disable_ipv6"], timeout: 5000, toolName: "netdef_ipv6_audit" });
        const disabled = ipv6All.stdout.includes("= 1");
        findings.push({ check: "ipv6_disabled", status: "INFO", value: disabled ? "disabled" : "enabled", description: "IPv6 status (disable if not needed)" });

        if (!disabled) {
          // Check IPv6 addresses
          const addrResult = await executeCommand({ command: "ip", args: ["-6", "addr", "show"], timeout: 5000, toolName: "netdef_ipv6_audit" });
          const hasGlobal = addrResult.stdout.includes("scope global");
          findings.push({ check: "ipv6_global_address", status: hasGlobal ? "INFO" : "PASS", value: hasGlobal ? "has global IPv6 address" : "link-local only", description: "IPv6 global address presence" });

          // Check IPv6 firewall
          const ip6tables = await executeCommand({ command: "sudo", args: ["ip6tables", "-L", "-n"], timeout: 10000, toolName: "netdef_ipv6_audit" });
          const inputMatch = ip6tables.stdout.match(/Chain INPUT \(policy (\w+)\)/);
          findings.push({ check: "ipv6_firewall_input", status: inputMatch && (inputMatch[1] === "DROP" || inputMatch[1] === "REJECT") ? "PASS" : "FAIL", value: inputMatch ? inputMatch[1] : "unknown", description: "IPv6 INPUT chain policy (should be DROP if IPv6 enabled)" });

          // Check IPv6 sysctl hardening
          const sysctlChecks = [
            { key: "net.ipv6.conf.all.accept_ra", expected: "0", desc: "Accept router advertisements" },
            { key: "net.ipv6.conf.all.accept_redirects", expected: "0", desc: "Accept redirects" },
            { key: "net.ipv6.conf.all.accept_source_route", expected: "0", desc: "Accept source route" },
          ];
          for (const sc of sysctlChecks) {
            const val = await executeCommand({ command: "sysctl", args: [sc.key], timeout: 5000, toolName: "netdef_ipv6_audit" });
            const current = val.stdout.split("=").pop()?.trim() || "unknown";
            findings.push({ check: sc.key, status: current === sc.expected ? "PASS" : "FAIL", value: current, description: `${sc.desc} (should be ${sc.expected})` });
          }
        }

        return { content: [createTextContent(JSON.stringify({ summary: { total: findings.length, pass: findings.filter(f => f.status === "PASS").length, fail: findings.filter(f => f.status === "FAIL").length }, ipv6Enabled: !disabled, findings }, null, 2))] };
      } catch (error) {
        return { content: [createErrorContent(error instanceof Error ? error.message : String(error))], isError: true };
      }
    },
  );

  // ── netdef_self_scan ──────────────────────────────────────────────────
  server.tool(
    "netdef_self_scan",
    "Run an nmap self-scan against localhost or the system's own IP to discover all exposed services and ports from a network perspective.",
    {
      target: z.enum(["localhost", "external"]).optional().default("localhost").describe("localhost or external (scans the machine's primary IP)"),
      scan_type: z.enum(["quick", "full", "service"]).optional().default("quick"),
    },
    async (params) => {
      try {
        let target = "127.0.0.1";
        if (params.target === "external") {
          const ipResult = await executeCommand({ command: "hostname", args: ["-I"], timeout: 5000, toolName: "netdef_self_scan" });
          target = ipResult.stdout.trim().split(" ")[0] || "127.0.0.1";
        }

        const args = [target];
        if (params.scan_type === "quick") { args.unshift("-F"); }
        else if (params.scan_type === "full") { args.unshift("-p-"); }
        else if (params.scan_type === "service") { args.unshift("-sV", "-F"); }
        args.push("--open", "-n");

        const result = await executeCommand({ command: "nmap", args, timeout: 120000, toolName: "netdef_self_scan" });
        return { content: [createTextContent(`Self-Scan Results (target: ${target}, type: ${params.scan_type}):\n\n${result.stdout}\n${result.stderr ? `\nWarnings:\n${result.stderr}` : ""}`)] };
      } catch (error) {
        return { content: [createErrorContent(error instanceof Error ? error.message : String(error))], isError: true };
      }
    },
  );
}
