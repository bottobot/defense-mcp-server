/**
 * Firewall management tools for Defense MCP Server.
 *
 * Registers 1 unified tool: firewall
 * with 14 actions covering iptables, UFW, persistence, nftables, and policy audit.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeCommand } from "../core/executor.js";
import { getConfig, getToolTimeout } from "../core/config.js";
import { getDistroAdapter } from "../core/distro-adapter.js";
import {
  createTextContent,
  createErrorContent,
  parseIptablesOutput,
  formatToolOutput,
} from "../core/parsers.js";
import {
  logChange,
  createChangeEntry,
  backupFile,
} from "../core/changelog.js";
import {
  validateIptablesChain,
  validateTarget,
  sanitizeArgs,
  validateToolPath,
} from "../core/sanitizer.js";

// ── TOOL-017 remediation: allowed directories for firewall rule file paths ──
const ALLOWED_FIREWALL_DIRS = ["/etc/iptables", "/etc/nftables", "/etc/ufw", "/tmp", "/var/lib", "/root", "/home"];

// ── TOOL-003 remediation: strict input validation helpers ──────────────────

/** Validate a port or port range string for iptables --dport: "80", "8080:8090" */
const PORT_SPEC_RE = /^\d{1,5}(:\d{1,5})?$/;
function validatePortSpec(port: string): string {
  if (!PORT_SPEC_RE.test(port)) {
    throw new Error(`Invalid port specification: '${port}'. Must be a number or range (e.g., '80', '8080:8090').`);
  }
  const parts = port.split(":").map(Number);
  for (const p of parts) {
    if (p < 1 || p > 65535) {
      throw new Error(`Port out of range: ${p}. Must be 1-65535.`);
    }
  }
  return port;
}

/** Allowed match module names for iptables -m */
const ALLOWED_MATCH_MODULES = new Set([
  "limit", "conntrack", "state", "recent", "multiport", "tcp", "udp",
  "icmp", "comment", "connlimit", "hashlimit", "iprange", "mark",
  "time", "addrtype", "geoip", "string", "owner", "set", "mac",
]);
function validateMatchModule(mod: string): string {
  if (!ALLOWED_MATCH_MODULES.has(mod)) {
    throw new Error(`Unknown match module: '${mod}'. Allowed: ${[...ALLOWED_MATCH_MODULES].join(", ")}`);
  }
  return mod;
}

// ── Custom chain name regex ────────────────────────────────────────────────

const CHAIN_NAME_REGEX = /^[A-Za-z_][A-Za-z0-9_-]{0,28}$/;

// ── nftables table name regex ──────────────────────────────────────────────
// TOOL-008: Added table name validation
const NFTABLES_TABLE_NAME_RE = /^[a-zA-Z][a-zA-Z0-9_-]{0,63}$/;

// ── Nftables detection helper ─────────────────────────────────────────────
/**
 * Detect whether nftables is the active firewall backend on this system.
 * Returns { active: true, reason } if nftables is managing the firewall,
 * meaning iptables-persistent / UFW should NOT be installed on top of it.
 */
async function detectNftablesActive(): Promise<{ active: boolean; reason: string }> {
  // 1. Check if nftables service is running
  const svcResult = await executeCommand({
    command: "systemctl",
    args: ["is-active", "nftables"],
    toolName: "firewall",
    timeout: 5000,
  });
  const nftServiceActive = svcResult.stdout.trim() === "active";

  // 2. Check if nft binary exists and has a non-trivial ruleset
  const nftResult = await executeCommand({
    command: "sudo",
    args: ["nft", "list", "ruleset"],
    toolName: "firewall",
    timeout: 10000,
  });
  const hasNftRules =
    nftResult.exitCode === 0 &&
    nftResult.stdout.trim().length > 50 &&
    nftResult.stdout.includes("chain ");

  // 3. Check if nftables is enabled at boot
  const enabledResult = await executeCommand({
    command: "systemctl",
    args: ["is-enabled", "nftables"],
    toolName: "firewall",
    timeout: 5000,
  });
  const nftEnabled = enabledResult.stdout.trim() === "enabled";

  if (nftServiceActive && hasNftRules) {
    return { active: true, reason: "nftables service is running with active rules" };
  }
  if (hasNftRules && nftEnabled) {
    return { active: true, reason: "nftables is enabled at boot with active rules" };
  }
  if (hasNftRules) {
    return { active: true, reason: "nftables has active rules loaded" };
  }
  if (nftServiceActive) {
    return { active: true, reason: "nftables service is running" };
  }
  return { active: false, reason: "nftables is not active" };
}

// ── Running services discovery helper ─────────────────────────────────────
/**
 * Discover listening ports and established connections from running programs.
 * Returns a deduplicated list of port/protocol pairs that should be allowed
 * when setting a DROP policy, so existing services aren't killed.
 */
interface ActivePort {
  protocol: "tcp" | "udp";
  port: number;
  process: string;
  direction: "listen" | "established-out" | "established-in";
}

async function discoverActivePorts(): Promise<ActivePort[]> {
  const ports: ActivePort[] = [];
  const seen = new Set<string>();

  // Discover listening TCP/UDP ports
  const listenResult = await executeCommand({
    command: "sudo",
    args: ["ss", "-tlnpH"],
    toolName: "firewall",
    timeout: 10000,
  });
  if (listenResult.exitCode === 0) {
    for (const line of listenResult.stdout.split("\n")) {
      // Format: LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=...))
      const match = line.match(/:(\d+)\s+[\d.*:]+\s+users:\(\("([^"]+)"/);
      if (match) {
        const port = parseInt(match[1], 10);
        const process = match[2];
        const key = `tcp:${port}:listen`;
        if (!seen.has(key) && port >= 1 && port <= 65535) {
          seen.add(key);
          ports.push({ protocol: "tcp", port, process, direction: "listen" });
        }
      }
    }
  }

  const listenUdpResult = await executeCommand({
    command: "sudo",
    args: ["ss", "-ulnpH"],
    toolName: "firewall",
    timeout: 10000,
  });
  if (listenUdpResult.exitCode === 0) {
    for (const line of listenUdpResult.stdout.split("\n")) {
      const match = line.match(/:(\d+)\s+[\d.*:]+\s+users:\(\("([^"]+)"/);
      if (match) {
        const port = parseInt(match[1], 10);
        const process = match[2];
        const key = `udp:${port}:listen`;
        if (!seen.has(key) && port >= 1 && port <= 65535) {
          seen.add(key);
          ports.push({ protocol: "udp", port, process, direction: "listen" });
        }
      }
    }
  }

  // Discover established outbound connections (remote ports programs are talking to)
  const estResult = await executeCommand({
    command: "sudo",
    args: ["ss", "-tnpH", "state", "established"],
    toolName: "firewall",
    timeout: 10000,
  });
  if (estResult.exitCode === 0) {
    for (const line of estResult.stdout.split("\n")) {
      // Format: ESTAB 0 0 192.168.1.5:54321 1.2.3.4:443 users:(("curl",pid=...))
      // We want the remote port (destination) to allow outbound traffic to it
      const match = line.match(
        /\s+[\d.]+:\d+\s+[\d.]+:(\d+)\s+users:\(\("([^"]+)"/
      );
      if (match) {
        const port = parseInt(match[1], 10);
        const process = match[2];
        const key = `tcp:${port}:established-out`;
        if (!seen.has(key) && port >= 1 && port <= 65535) {
          seen.add(key);
          ports.push({ protocol: "tcp", port, process, direction: "established-out" });
        }
      }
    }
  }

  return ports;
}

// ── Registration entry point ───────────────────────────────────────────────

export function registerFirewallTools(server: McpServer): void {
  server.tool(
    "firewall",
    "Firewall: iptables, UFW, nftables, persistence, policy audit",
    {
      action: z
        .enum([
          "iptables_list",
          "iptables_add",
          "iptables_delete",
          "iptables_set_policy",
          "iptables_create_chain",
          "ufw_status",
          "ufw_add",
          "ufw_delete",
          "persist_save",
          "persist_restore",
          "persist_enable",
          "persist_status",
          "nftables_list",
          "policy_audit",
        ])
        .describe("Firewall action"),
      // ── iptables params ──────────────────────────────────────────────
      table: z
        .string()
        .optional()
        .default("filter")
        .describe("Iptables/nftables table name"),
      chain: z
        .string()
        .optional()
        .describe("Target chain (INPUT, OUTPUT, FORWARD, or custom)"),
      dry_run: z
        .boolean()
        .optional()
        .default(true)
        .describe("Preview without applying"),
      ipv6: z
        .boolean()
        .optional()
        .default(false)
        .describe("Also apply to ip6tables"),
      verbose: z
        .boolean()
        .optional()
        .default(false)
        .describe("Show verbose output"),
      protocol: z
        .enum(["tcp", "udp", "icmp", "all", "any"])
        .optional()
        .describe("Protocol to match"),
      source: z
        .string()
        .optional()
        .describe("Source IP/CIDR"),
      destination: z
        .string()
        .optional()
        .describe("Destination IP/CIDR"),
      port: z
        .string()
        .optional()
        .describe("Port or range, e.g. '80', '8080:8090'"),
      target_action: z
        .enum(["ACCEPT", "DROP", "REJECT", "LOG"])
        .optional()
        .default("DROP")
        .describe("Rule target action"),
      position: z
        .number()
        .optional()
        .describe("Rule insert position"),
      match_module: z
        .string()
        .optional()
        .describe("Match module, e.g. 'limit', 'conntrack'"),
      match_options: z
        .string()
        .optional()
        .describe("Match module options"),
      tcp_flags: z
        .string()
        .optional()
        .describe("TCP flags, e.g. '--syn'"),
      custom_chain: z
        .string()
        .optional()
        .describe("Custom chain for -j target, overrides target_action"),
      rule_number: z
        .number()
        .optional()
        .describe("Rule number to delete"),
      policy: z
        .enum(["ACCEPT", "DROP"])
        .optional()
        .describe("Default chain policy"),
      chain_name: z
        .string()
        .optional()
        .describe("Custom chain name to create"),
      // ── UFW params ───────────────────────────────────────────────────
      rule_action: z
        .enum(["allow", "deny", "reject", "limit"])
        .optional()
        .describe("UFW rule action"),
      direction: z
        .enum(["in", "out"])
        .optional()
        .default("in")
        .describe("Traffic direction"),
      from_addr: z
        .string()
        .optional()
        .describe("Source address or 'any'"),
      to_addr: z
        .string()
        .optional()
        .describe("Destination address or 'any'"),
      // ── persist params ───────────────────────────────────────────────
      output_path: z
        .string()
        .optional()
        .default("/etc/iptables/rules.v4")
        .describe("Output file path for saved rules"),
      input_path: z
        .string()
        .optional()
        .describe("Rules file path to restore from"),
      test_only: z
        .boolean()
        .optional()
        .default(true)
        .describe("Validate rules without applying"),
      // ── nftables params ──────────────────────────────────────────────
      family: z
        .enum(["ip", "ip6", "inet", "arp", "bridge", "netdev"])
        .optional()
        .describe("nftables address family"),
    },
    async (params) => {
      const { action } = params;

      switch (action) {
        // ── iptables_list ─────────────────────────────────────────────
        case "iptables_list": {
          const table = params.table ?? "filter";
          try {
            const args = ["-t", table, "-L"];

            if (params.chain) {
              const validatedChain = validateIptablesChain(params.chain);
              args.push(validatedChain);
            }

            args.push("-n", "--line-numbers");

            if (params.verbose) {
              args.push("-v");
            }

            sanitizeArgs(args);

            const result = await executeCommand({
              command: "sudo",
              args: ["iptables", ...args],
              toolName: "firewall",
              timeout: getToolTimeout("firewall"),
            });

            if (result.exitCode !== 0) {
              return {
                content: [
                  createErrorContent(
                    `iptables list failed (exit ${result.exitCode}): ${result.stderr}`
                  ),
                ],
                isError: true,
              };
            }

            const parsed = parseIptablesOutput(result.stdout);

            const output = {
              table,
              chain: params.chain ?? "all",
              rules: parsed,
              ruleCount: parsed.length,
              raw: result.stdout,
            };

            return { content: [formatToolOutput(output)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── iptables_add ──────────────────────────────────────────────
        case "iptables_add": {
          const table = params.table ?? "filter";
          const dry_run = params.dry_run;
          try {
            if (!params.chain) {
              return { content: [createErrorContent("Error: 'chain' is required for add action")], isError: true };
            }

            const validatedChain = validateIptablesChain(params.chain);

            if (params.source) validateTarget(params.source);
            if (params.destination) validateTarget(params.destination);

            // Validate match_options: only allow alphanumeric, commas, slashes, hyphens, spaces, equals signs
            if (params.match_options && !/^[A-Za-z0-9,\/\-\s=]+$/.test(params.match_options)) {
              return {
                content: [
                  createErrorContent(
                    "match_options contains invalid characters. Only alphanumeric, commas, slashes, hyphens, spaces, and equals signs are allowed."
                  ),
                ],
                isError: true,
              };
            }

            // Validate tcp_flags: only allow --syn or --tcp-flags [A-Z,]+ [A-Z,]+
            if (params.tcp_flags) {
              const isSyn = params.tcp_flags === "--syn";
              const isTcpFlags = /^--tcp-flags\s+[A-Z,]+\s+[A-Z,]+$/.test(params.tcp_flags);
              if (!isSyn && !isTcpFlags) {
                return {
                  content: [
                    createErrorContent(
                      "tcp_flags must be '--syn' or '--tcp-flags <mask> <comp>' (e.g., '--tcp-flags SYN,ACK SYN')"
                    ),
                  ],
                  isError: true,
                };
              }
            }

            // Validate custom_chain name
            if (params.custom_chain && !CHAIN_NAME_REGEX.test(params.custom_chain)) {
              return {
                content: [
                  createErrorContent(
                    "custom_chain name is invalid. Must match /^[A-Za-z_][A-Za-z0-9_-]{0,28}$/"
                  ),
                ],
                isError: true,
              };
            }

            const ruleAction = params.target_action ?? "DROP";
            const args = ["-t", table, "-I", validatedChain];

            if (params.position !== undefined) {
              args.push(String(params.position));
            }

            if (params.protocol) {
              args.push("-p", params.protocol);
            }

            if (params.source) {
              args.push("-s", validateTarget(params.source));
            }

            if (params.destination) {
              args.push("-d", validateTarget(params.destination));
            }

            if (params.port) {
              if (!params.protocol || params.protocol === "all") {
                return {
                  content: [
                    createErrorContent(
                      "Protocol (tcp or udp) must be specified when using --dport"
                    ),
                  ],
                  isError: true,
                };
              }
              // TOOL-003: validate port specification before use
              args.push("--dport", validatePortSpec(params.port));
            }

            // Add match module and options
            if (params.match_module) {
              // TOOL-003: validate match module against whitelist
              args.push("-m", validateMatchModule(params.match_module));
              if (params.match_options) {
                const optTokens = params.match_options.trim().split(/\s+/);
                args.push(...optTokens);
              }
            }

            // Add TCP flags
            if (params.tcp_flags) {
              const flagTokens = params.tcp_flags.trim().split(/\s+/);
              args.push(...flagTokens);
            }

            // Determine jump target: custom_chain overrides target_action
            const jumpTarget = params.custom_chain ?? ruleAction;
            args.push("-j", jumpTarget);

            sanitizeArgs(args);

            // Build rollback command (delete rule)
            const deleteArgs = ["-t", table, "-D", validatedChain];
            if (params.protocol) deleteArgs.push("-p", params.protocol);
            if (params.source) deleteArgs.push("-s", params.source);
            if (params.destination) deleteArgs.push("-d", params.destination);
            if (params.port) deleteArgs.push("--dport", params.port);
            if (params.match_module) {
              deleteArgs.push("-m", params.match_module);
              if (params.match_options) {
                deleteArgs.push(...params.match_options.trim().split(/\s+/));
              }
            }
            if (params.tcp_flags) {
              deleteArgs.push(...params.tcp_flags.trim().split(/\s+/));
            }
            deleteArgs.push("-j", jumpTarget);
            const rollbackCmd = `sudo iptables ${deleteArgs.join(" ")}`;

            const fullCmd = `sudo iptables ${args.join(" ")}`;

            if (dry_run ?? getConfig().dryRun) {
              const entry = createChangeEntry({
                tool: "firewall",
                action: `[DRY-RUN] Add iptables rule`,
                target: `${table}/${validatedChain}`,
                after: fullCmd,
                dryRun: true,
                success: true,
                rollbackCommand: rollbackCmd,
              });
              logChange(entry);

              return {
                content: [
                  createTextContent(
                    `[DRY-RUN] Would execute:\n  ${fullCmd}\n\nRollback command:\n  ${rollbackCmd}`
                  ),
                ],
              };
            }

            const result = await executeCommand({
              command: "sudo",
              args: ["iptables", ...args],
              toolName: "firewall",
              timeout: getToolTimeout("firewall"),
            });

            const success = result.exitCode === 0;

            const entry = createChangeEntry({
              tool: "firewall",
              action: `Add iptables rule`,
              target: `${table}/${validatedChain}`,
              after: fullCmd,
              dryRun: false,
              success,
              error: success ? undefined : result.stderr,
              rollbackCommand: rollbackCmd,
            });
            logChange(entry);

            if (!success) {
              return {
                content: [
                  createErrorContent(
                    `iptables add failed (exit ${result.exitCode}): ${result.stderr}`
                  ),
                ],
                isError: true,
              };
            }

            return {
              content: [
                createTextContent(
                  `Rule added successfully.\nCommand: ${fullCmd}\nRollback: ${rollbackCmd}`
                ),
              ],
            };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── iptables_delete ───────────────────────────────────────────
        case "iptables_delete": {
          const table = params.table ?? "filter";
          const dry_run = params.dry_run;
          try {
            if (!params.chain) {
              return { content: [createErrorContent("Error: 'chain' is required for delete action")], isError: true };
            }
            if (params.rule_number === undefined) {
              return { content: [createErrorContent("Error: 'rule_number' is required for delete action")], isError: true };
            }

            const validatedChain = validateIptablesChain(params.chain);
            const args = ["-t", table, "-D", validatedChain, String(params.rule_number)];

            sanitizeArgs(args);

            const fullCmd = `sudo iptables ${args.join(" ")}`;

            if (dry_run ?? getConfig().dryRun) {
              const entry = createChangeEntry({
                tool: "firewall",
                action: `[DRY-RUN] Delete iptables rule #${params.rule_number}`,
                target: `${table}/${validatedChain}`,
                dryRun: true,
                success: true,
              });
              logChange(entry);

              return {
                content: [
                  createTextContent(
                    `[DRY-RUN] Would execute:\n  ${fullCmd}\n\nNote: List rules first with firewall action=iptables_list to confirm rule number.`
                  ),
                ],
              };
            }

            // Get the rule details before deleting (for changelog)
            const listResult = await executeCommand({
              command: "sudo",
              args: ["iptables", "-t", table, "-L", validatedChain, "-n", "--line-numbers", "-v"],
              toolName: "firewall",
            });

            const beforeState = listResult.stdout;

            const result = await executeCommand({
              command: "sudo",
              args: ["iptables", ...args],
              toolName: "firewall",
              timeout: getToolTimeout("firewall"),
            });

            const success = result.exitCode === 0;

            const entry = createChangeEntry({
              tool: "firewall",
              action: `Delete iptables rule #${params.rule_number}`,
              target: `${table}/${validatedChain}`,
              before: beforeState,
              dryRun: false,
              success,
              error: success ? undefined : result.stderr,
            });
            logChange(entry);

            if (!success) {
              return {
                content: [
                  createErrorContent(
                    `iptables delete failed (exit ${result.exitCode}): ${result.stderr}`
                  ),
                ],
                isError: true,
              };
            }

            return {
              content: [
                createTextContent(
                  `Rule #${params.rule_number} deleted from ${validatedChain} in ${table} table.`
                ),
              ],
            };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── iptables_set_policy ───────────────────────────────────────
        case "iptables_set_policy": {
          const dry_run = params.dry_run;
          try {
            if (!params.chain) {
              return { content: [createErrorContent("Error: 'chain' is required for set_policy action (INPUT, FORWARD, or OUTPUT)")], isError: true };
            }
            if (!params.policy) {
              return { content: [createErrorContent("Error: 'policy' is required for set_policy action (ACCEPT or DROP)")], isError: true };
            }

            const chain = params.chain;
            const policy = params.policy;
            const ipv6 = params.ipv6 ?? false;

            // Validate chain is a built-in chain
            if (chain !== "INPUT" && chain !== "FORWARD" && chain !== "OUTPUT") {
              return {
                content: [createErrorContent("Error: chain must be INPUT, FORWARD, or OUTPUT for set_policy action")],
                isError: true,
              };
            }

            const fullCmd = `sudo iptables -P ${chain} ${policy}`;
            const ipv6Cmd = `sudo ip6tables -P ${chain} ${policy}`;
            const injectedRules: string[] = [];

            // ── SAFETY CHECK: Prevent DROP policy without essential allow rules ──
            if (policy === "DROP" && (chain === "INPUT" || chain === "FORWARD" || chain === "OUTPUT")) {
              const safetyRules: Array<{ description: string; checkArgs: string[]; addArgs: string[]; addArgs6?: string[] }> = [];

              if (chain === "INPUT") {
                safetyRules.push(
                  {
                    description: "Allow loopback (lo) traffic",
                    checkArgs: ["-C", "INPUT", "-i", "lo", "-j", "ACCEPT"],
                    addArgs: ["-I", "INPUT", "1", "-i", "lo", "-j", "ACCEPT"],
                    addArgs6: ["-I", "INPUT", "1", "-i", "lo", "-j", "ACCEPT"],
                  },
                  {
                    description: "Allow established/related connections",
                    checkArgs: ["-C", "INPUT", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
                    addArgs: ["-I", "INPUT", "2", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
                    addArgs6: ["-I", "INPUT", "2", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
                  },
                );
              } else if (chain === "FORWARD") {
                safetyRules.push({
                  description: "Allow established/related forwarded connections",
                  checkArgs: ["-C", "FORWARD", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
                  addArgs: ["-I", "FORWARD", "1", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
                  addArgs6: ["-I", "FORWARD", "1", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
                });
              } else if (chain === "OUTPUT") {
                // SAFETY: OUTPUT DROP without egress rules will break ALL outbound
                // traffic including DNS, apt, curl, threat intel feeds, and the MCP
                // server's own network-dependent tools. Auto-inject essential rules.
                safetyRules.push(
                  {
                    description: "Allow loopback (lo) outbound traffic",
                    checkArgs: ["-C", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
                    addArgs: ["-I", "OUTPUT", "1", "-o", "lo", "-j", "ACCEPT"],
                    addArgs6: ["-I", "OUTPUT", "1", "-o", "lo", "-j", "ACCEPT"],
                  },
                  {
                    description: "Allow established/related outbound connections",
                    checkArgs: ["-C", "OUTPUT", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
                    addArgs: ["-I", "OUTPUT", "2", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
                    addArgs6: ["-I", "OUTPUT", "2", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
                  },
                  {
                    description: "Allow DNS queries (UDP 53)",
                    checkArgs: ["-C", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
                    addArgs: ["-I", "OUTPUT", "3", "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
                    addArgs6: ["-I", "OUTPUT", "3", "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
                  },
                  {
                    description: "Allow DNS queries (TCP 53)",
                    checkArgs: ["-C", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "ACCEPT"],
                    addArgs: ["-I", "OUTPUT", "4", "-p", "tcp", "--dport", "53", "-j", "ACCEPT"],
                    addArgs6: ["-I", "OUTPUT", "4", "-p", "tcp", "--dport", "53", "-j", "ACCEPT"],
                  },
                  {
                    description: "Allow HTTPS outbound (TCP 443)",
                    checkArgs: ["-C", "OUTPUT", "-p", "tcp", "--dport", "443", "-j", "ACCEPT"],
                    addArgs: ["-I", "OUTPUT", "5", "-p", "tcp", "--dport", "443", "-j", "ACCEPT"],
                    addArgs6: ["-I", "OUTPUT", "5", "-p", "tcp", "--dport", "443", "-j", "ACCEPT"],
                  },
                  {
                    description: "Allow HTTP outbound (TCP 80, for apt)",
                    checkArgs: ["-C", "OUTPUT", "-p", "tcp", "--dport", "80", "-j", "ACCEPT"],
                    addArgs: ["-I", "OUTPUT", "6", "-p", "tcp", "--dport", "80", "-j", "ACCEPT"],
                    addArgs6: ["-I", "OUTPUT", "6", "-p", "tcp", "--dport", "80", "-j", "ACCEPT"],
                  },
                );
              }

              for (const rule of safetyRules) {
                const checkResult = await executeCommand({
                  command: "sudo",
                  args: ["iptables", ...rule.checkArgs],
                  toolName: "firewall",
                  timeout: getToolTimeout("firewall"),
                });

                if (checkResult.exitCode !== 0) {
                  if (dry_run ?? getConfig().dryRun) {
                    injectedRules.push(`[DRY-RUN] Would add: ${rule.description}`);
                  } else {
                    const addResult = await executeCommand({
                      command: "sudo",
                      args: ["iptables", ...rule.addArgs],
                      toolName: "firewall",
                      timeout: getToolTimeout("firewall"),
                    });
                    if (addResult.exitCode !== 0) {
                      return {
                        content: [
                          createErrorContent(
                            `SAFETY: Failed to add prerequisite rule "${rule.description}" before setting DROP policy. ` +
                            `Aborting to prevent network lockout. Error: ${addResult.stderr}`
                          ),
                        ],
                        isError: true,
                      };
                    }
                    injectedRules.push(`Auto-added: ${rule.description}`);

                    if (ipv6 && rule.addArgs6) {
                      const add6Result = await executeCommand({
                        command: "sudo",
                        args: ["ip6tables", ...rule.addArgs6],
                        toolName: "firewall",
                        timeout: getToolTimeout("firewall"),
                      });
                      if (add6Result.exitCode !== 0) {
                        injectedRules.push(`IPv6: Failed to add "${rule.description}": ${add6Result.stderr}`);
                      } else {
                        injectedRules.push(`Auto-added (IPv6): ${rule.description}`);
                      }
                    }
                  }
                }
              }

              if (injectedRules.length > 0) {
                const safetyEntry = createChangeEntry({
                  tool: "firewall",
                  action: `Safety: auto-injected ${injectedRules.length} prerequisite rules before ${chain} DROP`,
                  target: chain,
                  after: injectedRules.join("; "),
                  dryRun: !!(dry_run ?? getConfig().dryRun),
                  success: true,
                });
                logChange(safetyEntry);
              }

              // ── AUTO-DISCOVER running services and allow their ports ──
              // This prevents killing active programs (qbittorrent, apt, etc.)
              const activePorts = await discoverActivePorts();
              const serviceRules: string[] = [];

              // Deduplicate: skip ports already covered by hardcoded safety rules
              const hardcodedPorts = new Set(["tcp:53", "udp:53", "tcp:80", "tcp:443"]);

              for (const ap of activePorts) {
                const portKey = `${ap.protocol}:${ap.port}`;
                if (hardcodedPorts.has(portKey)) continue;

                if (chain === "INPUT" && ap.direction === "listen") {
                  // Allow inbound to listening ports
                  const checkArgs = ["-C", "INPUT", "-p", ap.protocol, "--dport", String(ap.port), "-j", "ACCEPT"];
                  const addArgs = ["-A", "INPUT", "-p", ap.protocol, "--dport", String(ap.port), "-j", "ACCEPT"];
                  const checkR = await executeCommand({
                    command: "sudo", args: ["iptables", ...checkArgs],
                    toolName: "firewall", timeout: getToolTimeout("firewall"),
                  });
                  if (checkR.exitCode !== 0) {
                    if (dry_run ?? getConfig().dryRun) {
                      serviceRules.push(`[DRY-RUN] Would allow INPUT ${ap.protocol}/${ap.port} (${ap.process})`);
                    } else {
                      const addR = await executeCommand({
                        command: "sudo", args: ["iptables", ...addArgs],
                        toolName: "firewall", timeout: getToolTimeout("firewall"),
                      });
                      if (addR.exitCode === 0) {
                        serviceRules.push(`Auto-allowed INPUT ${ap.protocol}/${ap.port} (${ap.process})`);
                        if (ipv6) {
                          await executeCommand({
                            command: "sudo", args: ["ip6tables", ...addArgs],
                            toolName: "firewall", timeout: getToolTimeout("firewall"),
                          });
                        }
                      }
                    }
                  }
                } else if (chain === "OUTPUT" && (ap.direction === "listen" || ap.direction === "established-out")) {
                  // Allow outbound to remote ports that programs are actively using
                  const dportOrSport = ap.direction === "listen" ? "--sport" : "--dport";
                  const checkArgs = ["-C", "OUTPUT", "-p", ap.protocol, dportOrSport, String(ap.port), "-j", "ACCEPT"];
                  const addArgs = ["-A", "OUTPUT", "-p", ap.protocol, dportOrSport, String(ap.port), "-j", "ACCEPT"];
                  const checkR = await executeCommand({
                    command: "sudo", args: ["iptables", ...checkArgs],
                    toolName: "firewall", timeout: getToolTimeout("firewall"),
                  });
                  if (checkR.exitCode !== 0) {
                    if (dry_run ?? getConfig().dryRun) {
                      serviceRules.push(`[DRY-RUN] Would allow OUTPUT ${ap.protocol}/${dportOrSport.replace("--","")} ${ap.port} (${ap.process})`);
                    } else {
                      const addR = await executeCommand({
                        command: "sudo", args: ["iptables", ...addArgs],
                        toolName: "firewall", timeout: getToolTimeout("firewall"),
                      });
                      if (addR.exitCode === 0) {
                        serviceRules.push(`Auto-allowed OUTPUT ${ap.protocol}/${dportOrSport.replace("--","")} ${ap.port} (${ap.process})`);
                        if (ipv6) {
                          await executeCommand({
                            command: "sudo", args: ["ip6tables", ...addArgs],
                            toolName: "firewall", timeout: getToolTimeout("firewall"),
                          });
                        }
                      }
                    }
                  }
                }
              }

              if (serviceRules.length > 0) {
                injectedRules.push(...serviceRules);
                const serviceEntry = createChangeEntry({
                  tool: "firewall",
                  action: `Safety: auto-allowed ${serviceRules.length} active service ports before ${chain} DROP`,
                  target: chain,
                  after: serviceRules.join("; "),
                  dryRun: !!(dry_run ?? getConfig().dryRun),
                  success: true,
                });
                logChange(serviceEntry);
              }
            }

            if (dry_run ?? getConfig().dryRun) {
              const cmds = [fullCmd];
              if (ipv6) cmds.push(ipv6Cmd);

              // Include discovered service rules in dry-run output
              const injectedSummary = injectedRules.length > 0
                ? `\n\nSafety rules that would be added first:\n  ${injectedRules.join("\n  ")}`
                : "";

              const entry = createChangeEntry({
                tool: "firewall",
                action: `[DRY-RUN] Set ${chain} policy to ${policy}`,
                target: chain,
                after: cmds.join(" && "),
                dryRun: true,
                success: true,
              });
              logChange(entry);

              return {
                content: [
                  createTextContent(
                    `[DRY-RUN] Would execute:\n  ${cmds.join("\n  ")}${injectedSummary}`
                  ),
                ],
              };
            }

            // Get current policy for rollback
            const listResult = await executeCommand({
              command: "sudo",
              args: ["iptables", "-L", chain, "-n"],
              toolName: "firewall",
              timeout: getToolTimeout("firewall"),
            });
            const currentPolicyMatch = listResult.stdout.match(/Chain \w+ \(policy (\w+)\)/);
            const currentPolicy = currentPolicyMatch ? currentPolicyMatch[1] : "ACCEPT";
            const rollbackCmd = `sudo iptables -P ${chain} ${currentPolicy}`;

            const result = await executeCommand({
              command: "sudo",
              args: ["iptables", "-P", chain, policy],
              toolName: "firewall",
              timeout: getToolTimeout("firewall"),
            });

            if (result.exitCode !== 0) {
              const entry = createChangeEntry({
                tool: "firewall",
                action: `Set ${chain} policy to ${policy}`,
                target: chain,
                dryRun: false,
                success: false,
                error: result.stderr,
              });
              logChange(entry);

              return {
                content: [
                  createErrorContent(
                    `iptables set policy failed (exit ${result.exitCode}): ${result.stderr}`
                  ),
                ],
                isError: true,
              };
            }

            const messages = [`IPv4: ${chain} policy set to ${policy}`];

            if (ipv6) {
              const ip6Result = await executeCommand({
                command: "sudo",
                args: ["ip6tables", "-P", chain, policy],
                toolName: "firewall",
                timeout: getToolTimeout("firewall"),
              });

              if (ip6Result.exitCode !== 0) {
                messages.push(`IPv6: FAILED - ${ip6Result.stderr}`);
              } else {
                messages.push(`IPv6: ${chain} policy set to ${policy}`);
              }
            }

            const entry = createChangeEntry({
              tool: "firewall",
              action: `Set ${chain} policy to ${policy}`,
              target: chain,
              before: `policy ${currentPolicy}`,
              after: `policy ${policy}`,
              dryRun: false,
              success: true,
              rollbackCommand: rollbackCmd,
            });
            logChange(entry);

            return {
              content: [
                createTextContent(
                  `Policy updated successfully.\n${messages.join("\n")}\nRollback: ${rollbackCmd}`
                ),
              ],
            };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── iptables_create_chain ─────────────────────────────────────
        case "iptables_create_chain": {
          const dry_run = params.dry_run;
          try {
            if (!params.chain_name) {
              return { content: [createErrorContent("Error: 'chain_name' is required for create_chain action")], isError: true };
            }

            const chain_name = params.chain_name;
            const ipv6 = params.ipv6 ?? false;

            if (!CHAIN_NAME_REGEX.test(chain_name)) {
              return {
                content: [
                  createErrorContent(
                    `Invalid chain name '${chain_name}'. Must match /^[A-Za-z_][A-Za-z0-9_-]{0,28}$/`
                  ),
                ],
                isError: true,
              };
            }

            const fullCmd = `sudo iptables -N ${chain_name}`;
            const ipv6Cmd = `sudo ip6tables -N ${chain_name}`;

            if (dry_run ?? getConfig().dryRun) {
              const cmds = [fullCmd];
              if (ipv6) cmds.push(ipv6Cmd);

              const entry = createChangeEntry({
                tool: "firewall",
                action: `[DRY-RUN] Create custom chain ${chain_name}`,
                target: chain_name,
                after: cmds.join(" && "),
                dryRun: true,
                success: true,
              });
              logChange(entry);

              return {
                content: [
                  createTextContent(
                    `[DRY-RUN] Would execute:\n  ${cmds.join("\n  ")}`
                  ),
                ],
              };
            }

            const result = await executeCommand({
              command: "sudo",
              args: ["iptables", "-N", chain_name],
              toolName: "firewall",
              timeout: getToolTimeout("firewall"),
            });

            if (result.exitCode !== 0) {
              const entry = createChangeEntry({
                tool: "firewall",
                action: `Create custom chain ${chain_name}`,
                target: chain_name,
                dryRun: false,
                success: false,
                error: result.stderr,
              });
              logChange(entry);

              return {
                content: [
                  createErrorContent(
                    `iptables create chain failed (exit ${result.exitCode}): ${result.stderr}`
                  ),
                ],
                isError: true,
              };
            }

            const rollbackCmd = `sudo iptables -X ${chain_name}`;
            const messages = [`IPv4: Chain '${chain_name}' created`];

            if (ipv6) {
              const ip6Result = await executeCommand({
                command: "sudo",
                args: ["ip6tables", "-N", chain_name],
                toolName: "firewall",
                timeout: getToolTimeout("firewall"),
              });

              if (ip6Result.exitCode !== 0) {
                messages.push(`IPv6: FAILED - ${ip6Result.stderr}`);
              } else {
                messages.push(`IPv6: Chain '${chain_name}' created`);
              }
            }

            const entry = createChangeEntry({
              tool: "firewall",
              action: `Create custom chain ${chain_name}`,
              target: chain_name,
              dryRun: false,
              success: true,
              rollbackCommand: rollbackCmd,
            });
            logChange(entry);

            return {
              content: [
                createTextContent(
                  `Chain created successfully.\n${messages.join("\n")}\nRollback: ${rollbackCmd}`
                ),
              ],
            };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── ufw_status ────────────────────────────────────────────────
        case "ufw_status": {
          try {
            // Check if nftables is managing firewall directly (not via UFW backend)
            const nftCheckStatus = await detectNftablesActive();
            if (nftCheckStatus.active) {
              // Check if UFW is even installed
              const ufwCheck = await executeCommand({
                command: "which",
                args: ["ufw"],
                toolName: "firewall",
                timeout: 5000,
              });
              if (ufwCheck.exitCode !== 0) {
                return {
                  content: [
                    createTextContent(
                      `UFW is not installed. This system is using nftables directly (${nftCheckStatus.reason}). ` +
                      `Use firewall action=nftables_list to view current rules. ` +
                      `Installing UFW on a system with active nftables rules is not recommended as it may conflict.`
                    ),
                  ],
                };
              }
            }

            const args = ["ufw", "status"];
            if (params.verbose) {
              args.push("verbose");
            }

            const result = await executeCommand({
              command: "sudo",
              args,
              toolName: "firewall",
              timeout: getToolTimeout("firewall"),
            });

            if (result.exitCode !== 0) {
              return {
                content: [
                  createErrorContent(
                    `ufw status failed (exit ${result.exitCode}): ${result.stderr}`
                  ),
                ],
                isError: true,
              };
            }

            return { content: [createTextContent(result.stdout)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── ufw_add / ufw_delete ──────────────────────────────────────
        case "ufw_add":
        case "ufw_delete": {
          try {
            // Guard: refuse UFW rule changes if nftables is active and UFW is not installed
            const nftCheckUfw = await detectNftablesActive();
            if (nftCheckUfw.active) {
              const ufwInstalled = await executeCommand({
                command: "which",
                args: ["ufw"],
                toolName: "firewall",
                timeout: 5000,
              });
              if (ufwInstalled.exitCode !== 0) {
                return {
                  content: [
                    createErrorContent(
                      `Cannot ${action === "ufw_add" ? "add" : "delete"} UFW rule: UFW is not installed and ` +
                      `this system is using nftables directly (${nftCheckUfw.reason}). ` +
                      `Installing UFW on a system with active nftables rules can conflict and break networking. ` +
                      `Manage firewall rules via nftables instead.`
                    ),
                  ],
                  isError: true,
                };
              }
            }

            if (!params.rule_action) {
              return { content: [createErrorContent("Error: 'rule_action' is required for add/delete actions (allow, deny, reject, limit)")], isError: true };
            }

            const ruleAction = params.rule_action;
            const direction = params.direction ?? "in";
            const deleteRule = action === "ufw_delete";

            if (params.from_addr && params.from_addr !== "any") validateTarget(params.from_addr);
            if (params.to_addr && params.to_addr !== "any") validateTarget(params.to_addr);

            const args = ["ufw"];

            if (deleteRule) {
              args.push("delete");
            }

            args.push(ruleAction, direction);

            if (params.protocol && params.protocol !== "any") {
              args.push("proto", params.protocol);
            }

            if (params.from_addr) {
              args.push("from", params.from_addr);
            }

            if (params.to_addr) {
              args.push("to", params.to_addr);
            }

            if (params.port) {
              args.push("port", params.port);
            }

            sanitizeArgs(args);

            const fullCmd = `sudo ${args.join(" ")}`;

            if (params.dry_run ?? getConfig().dryRun) {
              const entry = createChangeEntry({
                tool: "firewall",
                action: `[DRY-RUN] ${deleteRule ? "Delete" : "Add"} UFW rule`,
                target: `ufw/${ruleAction}/${direction}`,
                after: fullCmd,
                dryRun: true,
                success: true,
              });
              logChange(entry);

              return {
                content: [
                  createTextContent(`[DRY-RUN] Would execute:\n  ${fullCmd}`),
                ],
              };
            }

            // Use --force to avoid interactive prompt
            const execArgs = [...args];
            if (!deleteRule) {
              execArgs.splice(1, 0, "--force");
            }

            const result = await executeCommand({
              command: "sudo",
              args: execArgs,
              toolName: "firewall",
              timeout: getToolTimeout("firewall"),
            });

            const success = result.exitCode === 0;

            // Build rollback: invert the operation
            const rollbackArgs = ["sudo", "ufw"];
            if (!deleteRule) {
              rollbackArgs.push("delete");
            }
            rollbackArgs.push(ruleAction, direction);
            if (params.protocol && params.protocol !== "any") rollbackArgs.push("proto", params.protocol);
            if (params.from_addr) rollbackArgs.push("from", params.from_addr);
            if (params.to_addr) rollbackArgs.push("to", params.to_addr);
            if (params.port) rollbackArgs.push("port", params.port);
            const rollbackCmd = rollbackArgs.join(" ");

            const entry = createChangeEntry({
              tool: "firewall",
              action: `${deleteRule ? "Delete" : "Add"} UFW rule`,
              target: `ufw/${ruleAction}/${direction}`,
              after: fullCmd,
              dryRun: false,
              success,
              error: success ? undefined : result.stderr,
              rollbackCommand: rollbackCmd,
            });
            logChange(entry);

            if (!success) {
              return {
                content: [
                  createErrorContent(
                    `UFW rule failed (exit ${result.exitCode}): ${result.stderr}`
                  ),
                ],
                isError: true,
              };
            }

            return {
              content: [
                createTextContent(
                  `UFW rule ${deleteRule ? "deleted" : "added"} successfully.\nCommand: ${fullCmd}\nRollback: ${rollbackCmd}\n\n${result.stdout}`
                ),
              ],
            };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── persist_save ──────────────────────────────────────────────
        case "persist_save": {
          const dry_run = params.dry_run;
          try {
            const output_path = params.output_path ?? "/etc/iptables/rules.v4";
            // TOOL-017: Validate output path against traversal and allowed dirs
            validateToolPath(output_path, ALLOWED_FIREWALL_DIRS, "Firewall rules output path");
            const ipv6 = params.ipv6 ?? false;
            const saveCmd = ipv6 ? "ip6tables-save" : "iptables-save";
            const fullCmd = `sudo ${saveCmd} > ${output_path}`;

            if (dry_run ?? getConfig().dryRun) {
              const entry = createChangeEntry({
                tool: "firewall",
                action: `[DRY-RUN] Save firewall rules`,
                target: output_path,
                after: fullCmd,
                dryRun: true,
                success: true,
              });
              logChange(entry);

              return {
                content: [
                  createTextContent(
                    `[DRY-RUN] Would execute:\n  ${fullCmd}\n\nThis would save current ${ipv6 ? "ip6tables" : "iptables"} rules to ${output_path}`
                  ),
                ],
              };
            }

            // Backup existing file if it exists
            let backupPath: string | undefined;
            try {
              backupPath = backupFile(output_path);
            } catch {
              // File may not exist yet, that's fine
            }

            // Get current rules
            const result = await executeCommand({
              command: "sudo",
              args: [saveCmd],
              toolName: "firewall",
              timeout: getToolTimeout("firewall"),
            });

            if (result.exitCode !== 0) {
              return {
                content: [
                  createErrorContent(
                    `${saveCmd} failed (exit ${result.exitCode}): ${result.stderr}`
                  ),
                ],
                isError: true,
              };
            }

            // Write rules to file using tee (handles permissions)
            const writeResult = await executeCommand({
              command: "sudo",
              args: ["tee", output_path],
              stdin: result.stdout,
              toolName: "firewall",
              timeout: getToolTimeout("firewall"),
            });

            const success = writeResult.exitCode === 0;

            const entry = createChangeEntry({
              tool: "firewall",
              action: `Save firewall rules`,
              target: output_path,
              after: fullCmd,
              backupPath,
              dryRun: false,
              success,
              error: success ? undefined : writeResult.stderr,
              rollbackCommand: backupPath
                ? `sudo cp ${backupPath} ${output_path}`
                : undefined,
            });
            logChange(entry);

            if (!success) {
              return {
                content: [
                  createErrorContent(
                    `Failed to write rules to ${output_path}: ${writeResult.stderr}`
                  ),
                ],
                isError: true,
              };
            }

            return {
              content: [
                createTextContent(
                  `Firewall rules saved to ${output_path}.${backupPath ? `\nBackup: ${backupPath}` : ""}\nRules:\n${result.stdout}`
                ),
              ],
            };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── persist_restore ───────────────────────────────────────────
        case "persist_restore": {
          const dry_run = params.dry_run;
          try {
            if (!params.input_path) {
              return { content: [createErrorContent("Error: 'input_path' is required for restore action")], isError: true };
            }

            const input_path = params.input_path;
            // TOOL-017: Validate input path against traversal and allowed dirs
            validateToolPath(input_path, ALLOWED_FIREWALL_DIRS, "Firewall rules input path");
            const ipv6 = params.ipv6 ?? false;
            const test_only = params.test_only ?? true;
            const restoreCmd = ipv6 ? "ip6tables-restore" : "iptables-restore";
            const args = [restoreCmd];

            if (test_only) {
              args.push("--test");
            }

            const fullCmd = `sudo ${args.join(" ")} < ${input_path}`;

            if (dry_run ?? getConfig().dryRun) {
              const entry = createChangeEntry({
                tool: "firewall",
                action: `[DRY-RUN] Restore firewall rules`,
                target: input_path,
                after: fullCmd,
                dryRun: true,
                success: true,
              });
              logChange(entry);

              return {
                content: [
                  createTextContent(
                    `[DRY-RUN] Would execute:\n  ${fullCmd}\n\n${test_only ? "This would only validate the rules file." : "This would apply all rules from the file."}`
                  ),
                ],
              };
            }

            // Read the rules file content first
            const catResult = await executeCommand({
              command: "sudo",
              args: ["cat", input_path],
              toolName: "firewall",
            });

            if (catResult.exitCode !== 0) {
              return {
                content: [
                  createErrorContent(
                    `Cannot read rules file ${input_path}: ${catResult.stderr}`
                  ),
                ],
                isError: true,
              };
            }

            // Save current rules before restoring (for rollback)
            let beforeState: string | undefined;
            if (!test_only) {
              const saveCmdStr = ipv6 ? "ip6tables-save" : "iptables-save";
              const saveResult = await executeCommand({
                command: "sudo",
                args: [saveCmdStr],
                toolName: "firewall",
              });
              beforeState = saveResult.stdout;
            }

            const result = await executeCommand({
              command: "sudo",
              args,
              stdin: catResult.stdout,
              toolName: "firewall",
              timeout: getToolTimeout("firewall"),
            });

            const success = result.exitCode === 0;

            const entry = createChangeEntry({
              tool: "firewall",
              action: `${test_only ? "Test" : "Restore"} firewall rules`,
              target: input_path,
              before: beforeState,
              dryRun: false,
              success,
              error: success ? undefined : result.stderr,
            });
            logChange(entry);

            if (!success) {
              return {
                content: [
                  createErrorContent(
                    `${restoreCmd} failed (exit ${result.exitCode}): ${result.stderr}`
                  ),
                ],
                isError: true,
              };
            }

            return {
              content: [
                createTextContent(
                  test_only
                    ? `Rules file ${input_path} validated successfully.`
                    : `Firewall rules restored from ${input_path}.\n${result.stdout}`
                ),
              ],
            };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── persist_enable ────────────────────────────────────────────
        case "persist_enable": {
          const dry_run = params.dry_run;
          try {
            // Guard: refuse to install iptables-persistent if nftables is active
            const nftCheck = await detectNftablesActive();
            if (nftCheck.active) {
              return {
                content: [
                  createErrorContent(
                    `Cannot enable iptables persistence: ${nftCheck.reason}. ` +
                    `Installing iptables-persistent on a system using nftables can conflict ` +
                    `and break networking. Use nftables native persistence instead ` +
                    `(nft rules are typically persisted via /etc/nftables.conf and the nftables systemd service). ` +
                    `To view current nftables rules, use: firewall action=nftables_list`
                  ),
                ],
                isError: true,
              };
            }

            const da = await getDistroAdapter();
            const fwp = da.fwPersistence;

            const installDesc = `sudo ${fwp.installCmd.join(" ")}`;
            const enableDesc = `sudo ${fwp.enableCmd.join(" ")}`;
            const cmds = [installDesc, enableDesc];

            if (dry_run ?? getConfig().dryRun) {
              const entry = createChangeEntry({
                tool: "firewall",
                action: `[DRY-RUN] Enable ${fwp.packageName}`,
                target: fwp.packageName,
                after: cmds.join(" && "),
                dryRun: true,
                success: true,
              });
              logChange(entry);

              return {
                content: [
                  createTextContent(
                    `[DRY-RUN] Would execute:\n  ${cmds.join("\n  ")}`
                  ),
                ],
              };
            }

            // Install the persistence package (distro-aware)
            const installResult = await executeCommand({
              command: "sudo",
              args: fwp.installCmd,
              toolName: "firewall",
              timeout: 120000,
              env: da.isDebian ? { DEBIAN_FRONTEND: "noninteractive" } : undefined,
            });

            let installSuccess = installResult.exitCode === 0;
            if (!installSuccess && da.isDebian) {
              const installResult2 = await executeCommand({
                command: "sudo",
                args: fwp.installCmd,
                env: { DEBIAN_FRONTEND: "noninteractive" },
                toolName: "firewall",
                timeout: 120000,
              });
              installSuccess = installResult2.exitCode === 0;
            }

            if (!installSuccess) {
              const entry = createChangeEntry({
                tool: "firewall",
                action: `Enable ${fwp.packageName}`,
                target: fwp.packageName,
                dryRun: false,
                success: false,
                error: installResult.stderr,
              });
              logChange(entry);

              return {
                content: [
                  createErrorContent(
                    `Failed to install ${fwp.packageName}: ${installResult.stderr}`
                  ),
                ],
                isError: true,
              };
            }

            // Enable the service
            const enableResult = await executeCommand({
              command: "sudo",
              args: fwp.enableCmd,
              toolName: "firewall",
              timeout: 15000,
            });

            const entry = createChangeEntry({
              tool: "firewall",
              action: `Enable ${fwp.packageName}`,
              target: fwp.packageName,
              dryRun: false,
              success: true,
              rollbackCommand: fwp.uninstallHint,
            });
            logChange(entry);

            return {
              content: [
                createTextContent(
                  `${fwp.packageName} installed and ${fwp.serviceName} service enabled.\n` +
                  `Service status: ${enableResult.exitCode === 0 ? "enabled" : "enable may have failed: " + enableResult.stderr}\n` +
                  `Use firewall with action='persist_save' to persist current rules.`
                ),
              ],
            };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── persist_status ────────────────────────────────────────────
        case "persist_status": {
          try {
            const da = await getDistroAdapter();
            const fwp = da.fwPersistence;

            // Check if persistence package is installed (distro-aware)
            const pkgCheckResult = await executeCommand({
              command: fwp.checkInstalledCmd[0],
              args: fwp.checkInstalledCmd.slice(1),
              toolName: "firewall",
              timeout: 5000,
            });

            const installed = da.isDebian
              ? pkgCheckResult.stdout.includes("ii")
              : pkgCheckResult.exitCode === 0;

            // Check if persistence service is enabled
            const svcResult = await executeCommand({
              command: "systemctl",
              args: ["is-enabled", fwp.serviceName],
              toolName: "firewall",
              timeout: 5000,
            });

            const enabled = svcResult.stdout.trim() === "enabled";

            // Check if rules file exists
            const rulesResult = await executeCommand({
              command: "test",
              args: ["-f", da.paths.firewallPersistenceConfig],
              toolName: "firewall",
              timeout: 3000,
            });

            const status = {
              distro: da.summary,
              persistence_package: fwp.packageName,
              package_installed: installed,
              service_enabled: enabled,
              service_name: fwp.serviceName,
              rules_file_exists: rulesResult.exitCode === 0,
              rules_file_path: da.paths.firewallPersistenceConfig,
              recommendation: !installed
                ? `Use firewall with action='persist_enable' to install ${fwp.packageName}`
                : !enabled
                ? `Run: sudo systemctl enable ${fwp.serviceName}`
                : "Persistence is properly configured",
            };

            return {
              content: [createTextContent(JSON.stringify(status))],
            };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── nftables_list ─────────────────────────────────────────────
        case "nftables_list": {
          try {
            const args = ["list", "ruleset"];
            if (params.table && params.family) {
              // TOOL-008: Validate nftables table name
              if (!NFTABLES_TABLE_NAME_RE.test(params.table)) {
                return { content: [createErrorContent(`Invalid nftables table name: '${params.table}'. Must match /^[a-zA-Z][a-zA-Z0-9_-]{0,63}$/ (start with letter, no whitespace or special characters).`)], isError: true };
              }
              args.length = 0;
              args.push("list", "table", params.family, params.table);
            }
            const result = await executeCommand({ command: "sudo", args: ["nft", ...args], timeout: 15000, toolName: "firewall" });
            if (result.exitCode !== 0) {
              if (result.stderr.includes("not found")) {
                return { content: [createErrorContent("nftables (nft) is not installed. Install with: sudo apt install nftables")], isError: true };
              }
              return { content: [createErrorContent(`nft list failed (exit ${result.exitCode}): ${result.stderr}`)], isError: true };
            }
            return { content: [createTextContent(result.stdout || "No nftables rules configured")] };
          } catch (error) {
            return { content: [createErrorContent(error instanceof Error ? error.message : String(error))], isError: true };
          }
        }

        // ── policy_audit ──────────────────────────────────────────────
        case "policy_audit": {
          try {
            const findings: Array<{check: string, status: string, value: string, description: string, recommendation?: string}> = [];

            // Check iptables default policies
            const iptResult = await executeCommand({ command: "sudo", args: ["iptables", "-L", "-n"], timeout: 10000, toolName: "firewall" });
            if (iptResult.exitCode === 0) {
              const output = iptResult.stdout;
              // Check INPUT policy
              const inputMatch = output.match(/Chain INPUT \(policy (\w+)\)/);
              if (inputMatch) {
                const isSecure = inputMatch[1] === "DROP" || inputMatch[1] === "REJECT";
                findings.push({
                  check: "iptables_input_policy",
                  status: isSecure ? "PASS" : "FAIL",
                  value: inputMatch[1],
                  description: "INPUT chain default policy (should be DROP)",
                  recommendation: isSecure
                    ? undefined
                    : "Use firewall action=iptables_set_policy chain=INPUT policy=DROP ipv6=true",
                });
              }
              // Check FORWARD policy
              const fwdMatch = output.match(/Chain FORWARD \(policy (\w+)\)/);
              if (fwdMatch) {
                const isSecure = fwdMatch[1] === "DROP" || fwdMatch[1] === "REJECT";
                findings.push({
                  check: "iptables_forward_policy",
                  status: isSecure ? "PASS" : "FAIL",
                  value: fwdMatch[1],
                  description: "FORWARD chain default policy (should be DROP)",
                  recommendation: isSecure
                    ? undefined
                    : "Use firewall action=iptables_set_policy chain=FORWARD policy=DROP ipv6=true",
                });
              }
              // Check OUTPUT policy
              const outMatch = output.match(/Chain OUTPUT \(policy (\w+)\)/);
              if (outMatch) {
                findings.push({
                  check: "iptables_output_policy",
                  status: "INFO",
                  value: outMatch[1],
                  description: "OUTPUT chain policy (DROP recommended for high security)",
                  recommendation: outMatch[1] !== "DROP"
                    ? "Use firewall action=iptables_set_policy chain=OUTPUT policy=DROP for high-security environments"
                    : undefined,
                });
              }
              // Count rules
              const ruleCount = (output.match(/^[A-Z]+\s/gm) || []).length;
              findings.push({ check: "iptables_rule_count", status: ruleCount > 0 ? "INFO" : "WARN", value: String(ruleCount), description: "Total iptables rules" });
            }

            // Check firewall backend — detect nftables vs UFW vs neither
            const nftAuditCheck = await detectNftablesActive();
            const ufwWhich = await executeCommand({ command: "which", args: ["ufw"], timeout: 5000, toolName: "firewall" });

            if (nftAuditCheck.active) {
              // nftables is the active backend
              findings.push({
                check: "nftables_active",
                status: "PASS",
                value: `active (${nftAuditCheck.reason})`,
                description: "Firewall active via nftables",
              });
              if (ufwWhich.exitCode === 0) {
                // UFW is also installed — check if it's using nftables backend
                const ufwResult = await executeCommand({ command: "sudo", args: ["ufw", "status"], timeout: 10000, toolName: "firewall" });
                if (ufwResult.exitCode === 0 && ufwResult.stdout.includes("Status: active")) {
                  findings.push({ check: "ufw_active", status: "INFO", value: "active (alongside nftables)", description: "UFW is active — likely using nftables backend" });
                }
              } else {
                findings.push({
                  check: "ufw_not_needed",
                  status: "INFO",
                  value: "not installed",
                  description: "UFW is not installed — not needed since nftables is managing the firewall. Do NOT install UFW as it may conflict.",
                });
              }
            } else if (ufwWhich.exitCode === 0) {
              // UFW binary exists — try to get status
              const ufwResult = await executeCommand({ command: "sudo", args: ["ufw", "status"], timeout: 10000, toolName: "firewall" });
              if (ufwResult.exitCode === 0) {
                const active = ufwResult.stdout.includes("Status: active");
                findings.push({ check: "ufw_active", status: active ? "PASS" : "FAIL", value: active ? "active" : "inactive", description: "UFW firewall status" });
              } else {
                // UFW exists but status command failed — check nftables for UFW chains as fallback
                const nftFallback = await executeCommand({ command: "sudo", args: ["nft", "list", "ruleset"], timeout: 10000, toolName: "firewall" });
                const hasUfwChains = nftFallback.exitCode === 0 && nftFallback.stdout.includes("ufw-");
                if (hasUfwChains) {
                  findings.push({ check: "ufw_active", status: "PASS", value: "active (nftables backend)", description: "UFW firewall status (detected via nftables ruleset)" });
                } else {
                  findings.push({ check: "ufw_active", status: "WARN", value: "installed but status check failed", description: "UFW installed but 'ufw status' failed — may need sudo or service restart" });
                }
              }
            } else {
              // Neither nftables nor UFW active
              findings.push({ check: "firewall_missing", status: "FAIL", value: "not installed", description: "No firewall detected (UFW not found, nftables not active)", recommendation: "Install and configure a firewall (nftables recommended for modern systems)" });
            }

            // Check ip6tables
            const ip6Result = await executeCommand({ command: "sudo", args: ["ip6tables", "-L", "-n"], timeout: 10000, toolName: "firewall" });
            if (ip6Result.exitCode === 0) {
              const ip6InputMatch = ip6Result.stdout.match(/Chain INPUT \(policy (\w+)\)/);
              if (ip6InputMatch) {
                const isSecure = ip6InputMatch[1] === "DROP";
                findings.push({
                  check: "ip6tables_input_policy",
                  status: isSecure ? "PASS" : "FAIL",
                  value: ip6InputMatch[1],
                  description: "IPv6 INPUT chain policy (should be DROP)",
                  recommendation: isSecure
                    ? undefined
                    : "Use firewall action=iptables_set_policy chain=INPUT policy=DROP ipv6=true",
                });
              }
            }

            // Check for firewall persistence (distro-aware, nftables-aware)
            const daPolicy = await getDistroAdapter();
            if (nftAuditCheck.active) {
              // nftables persistence is via nftables.conf + systemd service
              const nftConfExists = await executeCommand({ command: "test", args: ["-f", "/etc/nftables.conf"], timeout: 3000, toolName: "firewall" });
              const nftSvcEnabled = await executeCommand({ command: "systemctl", args: ["is-enabled", "nftables"], timeout: 5000, toolName: "firewall" });
              const nftPersistent = nftConfExists.exitCode === 0 && nftSvcEnabled.stdout.trim() === "enabled";
              findings.push({
                check: "firewall_persistence",
                status: nftPersistent ? "PASS" : "WARN",
                value: nftPersistent ? "nftables persistence configured" : "nftables persistence not configured",
                description: "nftables rules persistence (/etc/nftables.conf + systemd service)",
                recommendation: nftPersistent
                  ? undefined
                  : "Ensure /etc/nftables.conf contains your rules and run: sudo systemctl enable nftables",
              });
            } else {
              const fwpPolicy = daPolicy.fwPersistence;
              const persistResult = await executeCommand({ command: fwpPolicy.checkInstalledCmd[0], args: fwpPolicy.checkInstalledCmd.slice(1), timeout: 5000, toolName: "firewall" });
              const persistInstalled = daPolicy.isDebian ? persistResult.stdout.includes("ii") : persistResult.exitCode === 0;
              findings.push({
                check: "firewall_persistence",
                status: persistInstalled ? "PASS" : "WARN",
                value: persistInstalled ? "installed" : "not installed",
                description: `${fwpPolicy.packageName} (rules survive reboot)`,
                recommendation: persistInstalled
                  ? undefined
                  : "Use firewall with action='persist_enable' to install and activate persistence, then action='persist_save' to persist current rules",
              });
            }

            const passCount = findings.filter(f => f.status === "PASS").length;
            const failCount = findings.filter(f => f.status === "FAIL").length;
            return { content: [createTextContent(JSON.stringify({ summary: { total: findings.length, pass: passCount, fail: failCount, warn: findings.filter(f => f.status === "WARN").length }, findings }))] };
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
