/**
 * Firewall management tools for Kali Defense MCP Server.
 *
 * Registers 5 tools: firewall_iptables, firewall_ufw, firewall_persist,
 * firewall_nftables_list, firewall_policy_audit.
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
  validateFilePath,
  validateTarget,
  sanitizeArgs,
} from "../core/sanitizer.js";

// ── Table enum shared across iptables tools ────────────────────────────────

const TABLE_ENUM = z
  .enum(["filter", "nat", "mangle", "raw"])
  .optional()
  .default("filter")
  .describe("Iptables table (default: filter)");

// ── Custom chain name regex ────────────────────────────────────────────────

const CHAIN_NAME_REGEX = /^[A-Za-z_][A-Za-z0-9_-]{0,28}$/;

// ── Registration entry point ───────────────────────────────────────────────

export function registerFirewallTools(server: McpServer): void {
  // ── 1. firewall_iptables (merged: firewall_iptables_list, firewall_iptables_add, firewall_iptables_delete, firewall_set_policy, firewall_create_chain) ──

  server.tool(
    "firewall_iptables",
    "Manage iptables rules and chains. Actions: list=show rules, add=insert rule, delete=remove rule by number, set_policy=set chain default policy, create_chain=create custom chain",
    {
      action: z
        .enum(["list", "add", "delete", "set_policy", "create_chain"])
        .describe("Action: list=show rules, add=insert rule, delete=remove rule by number, set_policy=set chain default, create_chain=create custom chain"),
      // Shared params
      table: TABLE_ENUM,
      chain: z
        .string()
        .optional()
        .describe("Target chain (e.g., INPUT, OUTPUT, FORWARD) — required for list (optional), add, delete"),
      dry_run: z
        .boolean()
        .optional()
        .default(true)
        .describe("Preview changes (for add/delete/set_policy/create_chain)"),
      ipv6: z
        .boolean()
        .optional()
        .default(false)
        .describe("Also apply to ip6tables (for set_policy/create_chain)"),
      // list params
      verbose: z
        .boolean()
        .optional()
        .default(false)
        .describe("Show verbose output with packet/byte counters (for list)"),
      // add params
      protocol: z
        .enum(["tcp", "udp", "icmp", "all"])
        .optional()
        .describe("Protocol to match (for add)"),
      source: z
        .string()
        .optional()
        .describe("Source IP/CIDR to match (for add)"),
      destination: z
        .string()
        .optional()
        .describe("Destination IP/CIDR to match (for add)"),
      port: z
        .string()
        .optional()
        .describe("Destination port or port range, e.g. '80', '8080:8090' (for add)"),
      target_action: z
        .enum(["ACCEPT", "DROP", "REJECT", "LOG"])
        .optional()
        .default("DROP")
        .describe("Rule target action (for add, default: DROP)"),
      position: z
        .number()
        .optional()
        .describe("Position to insert rule (for add)"),
      match_module: z
        .string()
        .optional()
        .describe("Match module to load, e.g. 'limit', 'conntrack' (for add)"),
      match_options: z
        .string()
        .optional()
        .describe("Options for match module (for add)"),
      tcp_flags: z
        .string()
        .optional()
        .describe("TCP flags to match, e.g. '--syn' (for add)"),
      custom_chain: z
        .string()
        .optional()
        .describe("Custom chain for -j target, overrides target_action (for add)"),
      // delete params
      rule_number: z
        .number()
        .optional()
        .describe("Rule number to delete (for delete)"),
      // set_policy params
      policy: z
        .enum(["ACCEPT", "DROP"])
        .optional()
        .describe("Default policy to set (for set_policy)"),
      // create_chain params
      chain_name: z
        .string()
        .optional()
        .describe("Name of custom chain to create (for create_chain)"),
    },
    async (params) => {
      const { action, table, dry_run } = params;

      switch (action) {
        // ── list ──────────────────────────────────────────────────────
        case "list": {
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
              toolName: "firewall_iptables",
              timeout: getToolTimeout("firewall_iptables"),
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

        // ── add ──────────────────────────────────────────────────────
        case "add": {
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
              args.push("-s", params.source);
            }

            if (params.destination) {
              args.push("-d", params.destination);
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
              args.push("--dport", params.port);
            }

            // Add match module and options
            if (params.match_module) {
              args.push("-m", params.match_module);
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
                tool: "firewall_iptables",
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
              toolName: "firewall_iptables",
              timeout: getToolTimeout("firewall_iptables"),
            });

            const success = result.exitCode === 0;

            const entry = createChangeEntry({
              tool: "firewall_iptables",
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

        // ── delete ───────────────────────────────────────────────────
        case "delete": {
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
                tool: "firewall_iptables",
                action: `[DRY-RUN] Delete iptables rule #${params.rule_number}`,
                target: `${table}/${validatedChain}`,
                dryRun: true,
                success: true,
              });
              logChange(entry);

              return {
                content: [
                  createTextContent(
                    `[DRY-RUN] Would execute:\n  ${fullCmd}\n\nNote: List rules first with firewall_iptables action=list to confirm rule number.`
                  ),
                ],
              };
            }

            // Get the rule details before deleting (for changelog)
            const listResult = await executeCommand({
              command: "sudo",
              args: ["iptables", "-t", table, "-L", validatedChain, "-n", "--line-numbers", "-v"],
              toolName: "firewall_iptables",
            });

            const beforeState = listResult.stdout;

            const result = await executeCommand({
              command: "sudo",
              args: ["iptables", ...args],
              toolName: "firewall_iptables",
              timeout: getToolTimeout("firewall_iptables"),
            });

            const success = result.exitCode === 0;

            const entry = createChangeEntry({
              tool: "firewall_iptables",
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

        // ── set_policy ───────────────────────────────────────────────
        case "set_policy": {
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

            // ── SAFETY CHECK: Prevent DROP policy without essential allow rules ──
            if (policy === "DROP" && (chain === "INPUT" || chain === "FORWARD")) {
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
              }

              const injectedRules: string[] = [];

              for (const rule of safetyRules) {
                const checkResult = await executeCommand({
                  command: "sudo",
                  args: ["iptables", ...rule.checkArgs],
                  toolName: "firewall_iptables",
                  timeout: getToolTimeout("firewall_iptables"),
                });

                if (checkResult.exitCode !== 0) {
                  if (dry_run ?? getConfig().dryRun) {
                    injectedRules.push(`[DRY-RUN] Would add: ${rule.description}`);
                  } else {
                    const addResult = await executeCommand({
                      command: "sudo",
                      args: ["iptables", ...rule.addArgs],
                      toolName: "firewall_iptables",
                      timeout: getToolTimeout("firewall_iptables"),
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
                    injectedRules.push(`✅ Auto-added: ${rule.description}`);

                    if (ipv6 && rule.addArgs6) {
                      const add6Result = await executeCommand({
                        command: "sudo",
                        args: ["ip6tables", ...rule.addArgs6],
                        toolName: "firewall_iptables",
                        timeout: getToolTimeout("firewall_iptables"),
                      });
                      if (add6Result.exitCode !== 0) {
                        injectedRules.push(`⚠️ IPv6: Failed to add "${rule.description}": ${add6Result.stderr}`);
                      } else {
                        injectedRules.push(`✅ Auto-added (IPv6): ${rule.description}`);
                      }
                    }
                  }
                }
              }

              if (injectedRules.length > 0) {
                const safetyEntry = createChangeEntry({
                  tool: "firewall_iptables",
                  action: `Safety: auto-injected ${injectedRules.length} prerequisite rules before ${chain} DROP`,
                  target: chain,
                  after: injectedRules.join("; "),
                  dryRun: !!(dry_run ?? getConfig().dryRun),
                  success: true,
                });
                logChange(safetyEntry);
              }
            }

            if (dry_run ?? getConfig().dryRun) {
              const cmds = [fullCmd];
              if (ipv6) cmds.push(ipv6Cmd);

              const entry = createChangeEntry({
                tool: "firewall_iptables",
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
                    `[DRY-RUN] Would execute:\n  ${cmds.join("\n  ")}`
                  ),
                ],
              };
            }

            // Get current policy for rollback
            const listResult = await executeCommand({
              command: "sudo",
              args: ["iptables", "-L", chain, "-n"],
              toolName: "firewall_iptables",
              timeout: getToolTimeout("firewall_iptables"),
            });
            const currentPolicyMatch = listResult.stdout.match(/Chain \w+ \(policy (\w+)\)/);
            const currentPolicy = currentPolicyMatch ? currentPolicyMatch[1] : "ACCEPT";
            const rollbackCmd = `sudo iptables -P ${chain} ${currentPolicy}`;

            const result = await executeCommand({
              command: "sudo",
              args: ["iptables", "-P", chain, policy],
              toolName: "firewall_iptables",
              timeout: getToolTimeout("firewall_iptables"),
            });

            if (result.exitCode !== 0) {
              const entry = createChangeEntry({
                tool: "firewall_iptables",
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
                toolName: "firewall_iptables",
                timeout: getToolTimeout("firewall_iptables"),
              });

              if (ip6Result.exitCode !== 0) {
                messages.push(`IPv6: FAILED - ${ip6Result.stderr}`);
              } else {
                messages.push(`IPv6: ${chain} policy set to ${policy}`);
              }
            }

            const entry = createChangeEntry({
              tool: "firewall_iptables",
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

        // ── create_chain ─────────────────────────────────────────────
        case "create_chain": {
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
                tool: "firewall_iptables",
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
              toolName: "firewall_iptables",
              timeout: getToolTimeout("firewall_iptables"),
            });

            if (result.exitCode !== 0) {
              const entry = createChangeEntry({
                tool: "firewall_iptables",
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
                toolName: "firewall_iptables",
                timeout: getToolTimeout("firewall_iptables"),
              });

              if (ip6Result.exitCode !== 0) {
                messages.push(`IPv6: FAILED - ${ip6Result.stderr}`);
              } else {
                messages.push(`IPv6: Chain '${chain_name}' created`);
              }
            }

            const entry = createChangeEntry({
              tool: "firewall_iptables",
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

        default:
          return { content: [createErrorContent(`Unknown action: ${action}`)], isError: true };
      }
    }
  );

  // ── 2. firewall_ufw (merged: firewall_ufw_status, firewall_ufw_rule) ────

  server.tool(
    "firewall_ufw",
    "Manage UFW (Uncomplicated Firewall). Actions: status=show current status/rules, add=add a rule, delete=delete a rule",
    {
      action: z
        .enum(["status", "add", "delete"])
        .describe("Action: status=show status, add=add rule, delete=delete rule"),
      // status params
      verbose: z
        .boolean()
        .optional()
        .default(false)
        .describe("Show verbose status including logging and default policies (for status)"),
      // add/delete params
      rule_action: z
        .enum(["allow", "deny", "reject", "limit"])
        .optional()
        .describe("Rule action (required for add/delete)"),
      direction: z
        .enum(["in", "out"])
        .optional()
        .default("in")
        .describe("Traffic direction (for add/delete, default: in)"),
      port: z
        .string()
        .optional()
        .describe("Port number or range, e.g. '22', '8000:9000' (for add/delete)"),
      protocol: z
        .enum(["tcp", "udp", "any"])
        .optional()
        .describe("Protocol (for add/delete)"),
      from_addr: z
        .string()
        .optional()
        .describe("Source address or 'any' (for add/delete)"),
      to_addr: z
        .string()
        .optional()
        .describe("Destination address or 'any' (for add/delete)"),
      dry_run: z
        .boolean()
        .optional()
        .default(true)
        .describe("Preview the command without executing (for add/delete)"),
    },
    async (params) => {
      const { action } = params;

      switch (action) {
        // ── status ───────────────────────────────────────────────────
        case "status": {
          try {
            const args = ["ufw", "status"];
            if (params.verbose) {
              args.push("verbose");
            }

            const result = await executeCommand({
              command: "sudo",
              args,
              toolName: "firewall_ufw",
              timeout: getToolTimeout("firewall_ufw"),
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

        // ── add / delete ─────────────────────────────────────────────
        case "add":
        case "delete": {
          try {
            if (!params.rule_action) {
              return { content: [createErrorContent("Error: 'rule_action' is required for add/delete actions (allow, deny, reject, limit)")], isError: true };
            }

            const ruleAction = params.rule_action;
            const direction = params.direction ?? "in";
            const deleteRule = action === "delete";

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
                tool: "firewall_ufw",
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
              toolName: "firewall_ufw",
              timeout: getToolTimeout("firewall_ufw"),
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
              tool: "firewall_ufw",
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

        default:
          return { content: [createErrorContent(`Unknown action: ${action}`)], isError: true };
      }
    }
  );

  // ── 3. firewall_persist (merged: firewall_save, firewall_restore, firewall_persistence) ──

  server.tool(
    "firewall_persist",
    "Manage firewall rule persistence. Actions: save=save iptables rules to file, restore=restore rules from file, enable=install persistence package, status=check persistence status",
    {
      action: z
        .enum(["save", "restore", "enable", "status"])
        .describe("Action: save=save rules to file, restore=restore from file, enable=install persistence, status=check status"),
      // save params
      output_path: z
        .string()
        .optional()
        .default("/etc/iptables/rules.v4")
        .describe("Output file path for save (default: /etc/iptables/rules.v4)"),
      // save/restore params
      ipv6: z
        .boolean()
        .optional()
        .default(false)
        .describe("Use ip6tables instead of iptables (for save/restore)"),
      // restore params
      input_path: z
        .string()
        .optional()
        .describe("Path to rules file to restore from (required for restore)"),
      test_only: z
        .boolean()
        .optional()
        .default(true)
        .describe("Only test/validate rules file without applying (for restore, default: true)"),
      // shared
      dry_run: z
        .boolean()
        .optional()
        .default(true)
        .describe("Preview the command without executing"),
    },
    async (params) => {
      const { action, dry_run } = params;

      switch (action) {
        // ── save ─────────────────────────────────────────────────────
        case "save": {
          try {
            const output_path = params.output_path ?? "/etc/iptables/rules.v4";
            const ipv6 = params.ipv6 ?? false;
            const saveCmd = ipv6 ? "ip6tables-save" : "iptables-save";
            const fullCmd = `sudo ${saveCmd} > ${output_path}`;

            if (dry_run ?? getConfig().dryRun) {
              const entry = createChangeEntry({
                tool: "firewall_persist",
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
              toolName: "firewall_persist",
              timeout: getToolTimeout("firewall_persist"),
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
              toolName: "firewall_persist",
              timeout: getToolTimeout("firewall_persist"),
            });

            const success = writeResult.exitCode === 0;

            const entry = createChangeEntry({
              tool: "firewall_persist",
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

        // ── restore ──────────────────────────────────────────────────
        case "restore": {
          try {
            if (!params.input_path) {
              return { content: [createErrorContent("Error: 'input_path' is required for restore action")], isError: true };
            }

            const input_path = params.input_path;
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
                tool: "firewall_persist",
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
              toolName: "firewall_persist",
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
                toolName: "firewall_persist",
              });
              beforeState = saveResult.stdout;
            }

            const result = await executeCommand({
              command: "sudo",
              args,
              stdin: catResult.stdout,
              toolName: "firewall_persist",
              timeout: getToolTimeout("firewall_persist"),
            });

            const success = result.exitCode === 0;

            const entry = createChangeEntry({
              tool: "firewall_persist",
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

        // ── enable ───────────────────────────────────────────────────
        case "enable": {
          try {
            const da = await getDistroAdapter();
            const fwp = da.fwPersistence;

            const installDesc = `sudo ${fwp.installCmd.join(" ")}`;
            const enableDesc = `sudo ${fwp.enableCmd.join(" ")}`;
            const cmds = [installDesc, enableDesc];

            if (dry_run ?? getConfig().dryRun) {
              const entry = createChangeEntry({
                tool: "firewall_persist",
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
              toolName: "firewall_persist",
              timeout: 120000,
              env: da.isDebian ? { DEBIAN_FRONTEND: "noninteractive" } : undefined,
            });

            let installSuccess = installResult.exitCode === 0;
            if (!installSuccess && da.isDebian) {
              const installResult2 = await executeCommand({
                command: "sudo",
                args: ["bash", "-c", `DEBIAN_FRONTEND=noninteractive ${fwp.installCmd.join(" ")}`],
                toolName: "firewall_persist",
                timeout: 120000,
              });
              installSuccess = installResult2.exitCode === 0;
            }

            if (!installSuccess) {
              const entry = createChangeEntry({
                tool: "firewall_persist",
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
              toolName: "firewall_persist",
              timeout: 15000,
            });

            const entry = createChangeEntry({
              tool: "firewall_persist",
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
                  `Use firewall_persist with action='save' to persist current rules.`
                ),
              ],
            };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── status ───────────────────────────────────────────────────
        case "status": {
          try {
            const da = await getDistroAdapter();
            const fwp = da.fwPersistence;

            // Check if persistence package is installed (distro-aware)
            const pkgCheckResult = await executeCommand({
              command: fwp.checkInstalledCmd[0],
              args: fwp.checkInstalledCmd.slice(1),
              toolName: "firewall_persist",
              timeout: 5000,
            });

            const installed = da.isDebian
              ? pkgCheckResult.stdout.includes("ii")
              : pkgCheckResult.exitCode === 0;

            // Check if persistence service is enabled
            const svcResult = await executeCommand({
              command: "systemctl",
              args: ["is-enabled", fwp.serviceName],
              toolName: "firewall_persist",
              timeout: 5000,
            });

            const enabled = svcResult.stdout.trim() === "enabled";

            // Check if rules file exists
            const rulesResult = await executeCommand({
              command: "test",
              args: ["-f", da.paths.firewallPersistenceConfig],
              toolName: "firewall_persist",
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
                ? `Use firewall_persist with action='enable' to install ${fwp.packageName}`
                : !enabled
                ? `Run: sudo systemctl enable ${fwp.serviceName}`
                : "Persistence is properly configured",
            };

            return {
              content: [createTextContent(JSON.stringify(status, null, 2))],
            };
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

  // ── 4. firewall_nftables_list (kept as-is) ────────────────────────────────
  server.tool(
    "firewall_nftables_list",
    "List nftables ruleset. nftables is the modern replacement for iptables on Linux systems.",
    {
      table: z.string().optional().describe("Specific table name to list"),
      family: z.enum(["ip", "ip6", "inet", "arp", "bridge", "netdev"]).optional().describe("Address family"),
    },
    async (params) => {
      try {
        const args = ["list", "ruleset"];
        if (params.table && params.family) {
          args.length = 0;
          args.push("list", "table", params.family, params.table);
        }
        const result = await executeCommand({ command: "sudo", args: ["nft", ...args], timeout: 15000, toolName: "firewall_nftables_list" });
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
    },
  );

  // ── 5. firewall_policy_audit (kept as-is) ─────────────────────────────────
  server.tool(
    "firewall_policy_audit",
    "Audit firewall configuration for security issues: default chain policies, missing rules, and common misconfigurations.",
    {},
    async () => {
      try {
        const findings: Array<{check: string, status: string, value: string, description: string, recommendation?: string}> = [];

        // Check iptables default policies
        const iptResult = await executeCommand({ command: "sudo", args: ["iptables", "-L", "-n"], timeout: 10000, toolName: "firewall_policy_audit" });
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
                : "Use firewall_iptables action=set_policy chain=INPUT policy=DROP ipv6=true",
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
                : "Use firewall_iptables action=set_policy chain=FORWARD policy=DROP ipv6=true",
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
                ? "Use firewall_iptables action=set_policy chain=OUTPUT policy=DROP for high-security environments"
                : undefined,
            });
          }
          // Count rules
          const ruleCount = (output.match(/^[A-Z]+\s/gm) || []).length;
          findings.push({ check: "iptables_rule_count", status: ruleCount > 0 ? "INFO" : "WARN", value: String(ruleCount), description: "Total iptables rules" });
        }

        // Check UFW status
        const ufwResult = await executeCommand({ command: "sudo", args: ["ufw", "status"], timeout: 10000, toolName: "firewall_policy_audit" });
        if (ufwResult.exitCode === 0) {
          const active = ufwResult.stdout.includes("Status: active");
          findings.push({ check: "ufw_active", status: active ? "PASS" : "FAIL", value: active ? "active" : "inactive", description: "UFW firewall status" });
        } else {
          findings.push({ check: "ufw_installed", status: "FAIL", value: "not installed", description: "UFW firewall availability" });
        }

        // Check ip6tables
        const ip6Result = await executeCommand({ command: "sudo", args: ["ip6tables", "-L", "-n"], timeout: 10000, toolName: "firewall_policy_audit" });
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
                : "Use firewall_iptables action=set_policy chain=INPUT policy=DROP ipv6=true",
            });
          }
        }

        // Check for firewall persistence (distro-aware)
        const daPolicy = await getDistroAdapter();
        const fwpPolicy = daPolicy.fwPersistence;
        const persistResult = await executeCommand({ command: fwpPolicy.checkInstalledCmd[0], args: fwpPolicy.checkInstalledCmd.slice(1), timeout: 5000, toolName: "firewall_policy_audit" });
        const persistInstalled = daPolicy.isDebian ? persistResult.stdout.includes("ii") : persistResult.exitCode === 0;
        findings.push({
          check: "firewall_persistence",
          status: persistInstalled ? "PASS" : "WARN",
          value: persistInstalled ? "installed" : "not installed",
          description: `${fwpPolicy.packageName} (rules survive reboot)`,
          recommendation: persistInstalled
            ? undefined
            : "Use firewall_persist with action='enable' to install and activate persistence, then action='save' to persist current rules",
        });

        const passCount = findings.filter(f => f.status === "PASS").length;
        const failCount = findings.filter(f => f.status === "FAIL").length;
        return { content: [createTextContent(JSON.stringify({ summary: { total: findings.length, pass: passCount, fail: failCount, warn: findings.filter(f => f.status === "WARN").length }, findings }, null, 2))] };
      } catch (error) {
        return { content: [createErrorContent(error instanceof Error ? error.message : String(error))], isError: true };
      }
    },
  );
}
