/**
 * Firewall management tools for Kali Defense MCP Server.
 *
 * Registers 12 tools: firewall_iptables_list, firewall_iptables_add,
 * firewall_iptables_delete, firewall_ufw_status, firewall_ufw_rule,
 * firewall_save, firewall_restore, firewall_nftables_list,
 * firewall_policy_audit, firewall_set_policy, firewall_create_chain,
 * firewall_persistence.
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
  // ── 1. firewall_iptables_list ──────────────────────────────────────────

  server.tool(
    "firewall_iptables_list",
    "List iptables rules for a given table and optional chain",
    {
      table: TABLE_ENUM,
      chain: z
        .string()
        .optional()
        .describe("Specific chain to list (e.g., INPUT, OUTPUT, FORWARD)"),
      verbose: z
        .boolean()
        .optional()
        .default(false)
        .describe("Show verbose output with packet/byte counters"),
    },
    async ({ table, chain, verbose }) => {
      try {
        const args = ["-t", table, "-L"];

        if (chain) {
          const validatedChain = validateIptablesChain(chain);
          args.push(validatedChain);
        }

        args.push("-n", "--line-numbers");

        if (verbose) {
          args.push("-v");
        }

        sanitizeArgs(args);

        const result = await executeCommand({
          command: "sudo",
          args: ["iptables", ...args],
          toolName: "firewall_iptables_list",
          timeout: getToolTimeout("firewall_iptables_list"),
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
          chain: chain ?? "all",
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
  );

  // ── 2. firewall_iptables_add ───────────────────────────────────────────

  server.tool(
    "firewall_iptables_add",
    "Add an iptables rule to a specified chain and table",
    {
      chain: z.string().describe("Target chain (e.g., INPUT, OUTPUT, FORWARD)"),
      table: TABLE_ENUM,
      protocol: z
        .enum(["tcp", "udp", "icmp", "all"])
        .optional()
        .describe("Protocol to match"),
      source: z
        .string()
        .optional()
        .describe("Source IP/CIDR to match"),
      destination: z
        .string()
        .optional()
        .describe("Destination IP/CIDR to match"),
      port: z
        .string()
        .optional()
        .describe("Destination port or port range (e.g., '80', '8080:8090')"),
      action: z
        .enum(["ACCEPT", "DROP", "REJECT", "LOG"])
        .default("DROP")
        .describe("Rule target action (default: DROP)"),
      position: z
        .number()
        .optional()
        .describe("Position to insert the rule (default: top of chain)"),
      match_module: z
        .string()
        .optional()
        .describe("Match module to load (e.g., 'limit', 'conntrack', 'state'). Adds -m <match_module> to the command"),
      match_options: z
        .string()
        .optional()
        .describe("Options for the match module (e.g., '--limit 1/s --limit-burst 3', '--ctstate ESTABLISHED,RELATED'). Appended after -m <match_module>"),
      tcp_flags: z
        .string()
        .optional()
        .describe("TCP flags to match (e.g., '--syn' or '--tcp-flags SYN,ACK SYN'). Added before the action"),
      custom_chain: z
        .string()
        .optional()
        .describe("Custom chain name for -j target instead of action (e.g., 'MY_CHAIN'). Overrides action parameter"),
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview the command without executing (defaults to KALI_DEFENSE_DRY_RUN env var)"),
    },
    async ({ chain, table, protocol, source, destination, port, action, position, match_module, match_options, tcp_flags, custom_chain, dry_run }) => {
      try {
        const validatedChain = validateIptablesChain(chain);

        if (source) validateTarget(source);
        if (destination) validateTarget(destination);

        // Validate match_options: only allow alphanumeric, commas, slashes, hyphens, spaces, equals signs
        if (match_options && !/^[A-Za-z0-9,\/\-\s=]+$/.test(match_options)) {
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
        if (tcp_flags) {
          const isSyn = tcp_flags === "--syn";
          const isTcpFlags = /^--tcp-flags\s+[A-Z,]+\s+[A-Z,]+$/.test(tcp_flags);
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
        if (custom_chain && !CHAIN_NAME_REGEX.test(custom_chain)) {
          return {
            content: [
              createErrorContent(
                "custom_chain name is invalid. Must match /^[A-Za-z_][A-Za-z0-9_-]{0,28}$/"
              ),
            ],
            isError: true,
          };
        }

        const args = ["-t", table, "-I", validatedChain];

        if (position !== undefined) {
          args.push(String(position));
        }

        if (protocol) {
          args.push("-p", protocol);
        }

        if (source) {
          args.push("-s", source);
        }

        if (destination) {
          args.push("-d", destination);
        }

        if (port) {
          if (!protocol || protocol === "all") {
            return {
              content: [
                createErrorContent(
                  "Protocol (tcp or udp) must be specified when using --dport"
                ),
              ],
              isError: true,
            };
          }
          args.push("--dport", port);
        }

        // Add match module and options
        if (match_module) {
          args.push("-m", match_module);
          if (match_options) {
            // Split match_options on whitespace and push each token
            const optTokens = match_options.trim().split(/\s+/);
            args.push(...optTokens);
          }
        }

        // Add TCP flags
        if (tcp_flags) {
          const flagTokens = tcp_flags.trim().split(/\s+/);
          args.push(...flagTokens);
        }

        // Determine jump target: custom_chain overrides action
        const jumpTarget = custom_chain ?? action;
        args.push("-j", jumpTarget);

        sanitizeArgs(args);

        // Build rollback command (delete rule)
        const deleteArgs = ["-t", table, "-D", validatedChain];
        if (protocol) deleteArgs.push("-p", protocol);
        if (source) deleteArgs.push("-s", source);
        if (destination) deleteArgs.push("-d", destination);
        if (port) deleteArgs.push("--dport", port);
        if (match_module) {
          deleteArgs.push("-m", match_module);
          if (match_options) {
            deleteArgs.push(...match_options.trim().split(/\s+/));
          }
        }
        if (tcp_flags) {
          deleteArgs.push(...tcp_flags.trim().split(/\s+/));
        }
        deleteArgs.push("-j", jumpTarget);
        const rollbackCmd = `sudo iptables ${deleteArgs.join(" ")}`;

        const fullCmd = `sudo iptables ${args.join(" ")}`;

        if (dry_run ?? getConfig().dryRun) {
          const entry = createChangeEntry({
            tool: "firewall_iptables_add",
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
          toolName: "firewall_iptables_add",
          timeout: getToolTimeout("firewall_iptables_add"),
        });

        const success = result.exitCode === 0;

        const entry = createChangeEntry({
          tool: "firewall_iptables_add",
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
  );

  // ── 3. firewall_iptables_delete ────────────────────────────────────────

  server.tool(
    "firewall_iptables_delete",
    "Delete an iptables rule by rule number from a specified chain",
    {
      chain: z.string().describe("Target chain (e.g., INPUT, OUTPUT, FORWARD)"),
      table: TABLE_ENUM,
      rule_number: z
        .number()
        .describe("Rule number to delete (use firewall_iptables_list to find)"),
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview the command without executing (defaults to KALI_DEFENSE_DRY_RUN env var)"),
    },
    async ({ chain, table, rule_number, dry_run }) => {
      try {
        const validatedChain = validateIptablesChain(chain);
        const args = ["-t", table, "-D", validatedChain, String(rule_number)];

        sanitizeArgs(args);

        const fullCmd = `sudo iptables ${args.join(" ")}`;

        if (dry_run ?? getConfig().dryRun) {
          const entry = createChangeEntry({
            tool: "firewall_iptables_delete",
            action: `[DRY-RUN] Delete iptables rule #${rule_number}`,
            target: `${table}/${validatedChain}`,
            dryRun: true,
            success: true,
          });
          logChange(entry);

          return {
            content: [
              createTextContent(
                `[DRY-RUN] Would execute:\n  ${fullCmd}\n\nNote: List rules first with firewall_iptables_list to confirm rule number.`
              ),
            ],
          };
        }

        // Get the rule details before deleting (for changelog)
        const listResult = await executeCommand({
          command: "sudo",
          args: ["iptables", "-t", table, "-L", validatedChain, "-n", "--line-numbers", "-v"],
          toolName: "firewall_iptables_delete",
        });

        const beforeState = listResult.stdout;

        const result = await executeCommand({
          command: "sudo",
          args: ["iptables", ...args],
          toolName: "firewall_iptables_delete",
          timeout: getToolTimeout("firewall_iptables_delete"),
        });

        const success = result.exitCode === 0;

        const entry = createChangeEntry({
          tool: "firewall_iptables_delete",
          action: `Delete iptables rule #${rule_number}`,
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
              `Rule #${rule_number} deleted from ${validatedChain} in ${table} table.`
            ),
          ],
        };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 4. firewall_ufw_status ─────────────────────────────────────────────

  server.tool(
    "firewall_ufw_status",
    "Show current UFW (Uncomplicated Firewall) status and rules",
    {
      verbose: z
        .boolean()
        .optional()
        .default(false)
        .describe("Show verbose status including logging and default policies"),
    },
    async ({ verbose }) => {
      try {
        const args = ["ufw", "status"];
        if (verbose) {
          args.push("verbose");
        }

        const result = await executeCommand({
          command: "sudo",
          args,
          toolName: "firewall_ufw_status",
          timeout: getToolTimeout("firewall_ufw_status"),
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
  );

  // ── 5. firewall_ufw_rule ───────────────────────────────────────────────

  server.tool(
    "firewall_ufw_rule",
    "Add or delete a UFW firewall rule",
    {
      action: z
        .enum(["allow", "deny", "reject", "limit"])
        .describe("Rule action (allow, deny, reject, limit)"),
      direction: z
        .enum(["in", "out"])
        .optional()
        .default("in")
        .describe("Traffic direction (default: in)"),
      port: z
        .string()
        .optional()
        .describe("Port number or range (e.g., '22', '8000:9000')"),
      protocol: z
        .enum(["tcp", "udp", "any"])
        .optional()
        .describe("Protocol (tcp, udp, any)"),
      from_addr: z
        .string()
        .optional()
        .describe("Source address or 'any'"),
      to_addr: z
        .string()
        .optional()
        .describe("Destination address or 'any'"),
      delete: z
        .boolean()
        .optional()
        .default(false)
        .describe("Delete the rule instead of adding it"),
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview the command without executing (defaults to KALI_DEFENSE_DRY_RUN env var)"),
    },
    async ({ action, direction, port, protocol, from_addr, to_addr, delete: deleteRule, dry_run }) => {
      try {
        if (from_addr && from_addr !== "any") validateTarget(from_addr);
        if (to_addr && to_addr !== "any") validateTarget(to_addr);

        const args = ["ufw"];

        if (deleteRule) {
          args.push("delete");
        }

        args.push(action, direction);

        if (protocol && protocol !== "any") {
          args.push("proto", protocol);
        }

        if (from_addr) {
          args.push("from", from_addr);
        }

        if (to_addr) {
          args.push("to", to_addr);
        }

        if (port) {
          args.push("port", port);
        }

        sanitizeArgs(args);

        const fullCmd = `sudo ${args.join(" ")}`;

        if (dry_run ?? getConfig().dryRun) {
          const entry = createChangeEntry({
            tool: "firewall_ufw_rule",
            action: `[DRY-RUN] ${deleteRule ? "Delete" : "Add"} UFW rule`,
            target: `ufw/${action}/${direction}`,
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
          // Insert --force after 'ufw' to skip confirmation
          execArgs.splice(1, 0, "--force");
        }

        const result = await executeCommand({
          command: "sudo",
          args: execArgs,
          toolName: "firewall_ufw_rule",
          timeout: getToolTimeout("firewall_ufw_rule"),
        });

        const success = result.exitCode === 0;

        // Build rollback: invert the operation
        const rollbackArgs = ["sudo", "ufw"];
        if (!deleteRule) {
          rollbackArgs.push("delete");
        }
        rollbackArgs.push(action, direction);
        if (protocol && protocol !== "any") rollbackArgs.push("proto", protocol);
        if (from_addr) rollbackArgs.push("from", from_addr);
        if (to_addr) rollbackArgs.push("to", to_addr);
        if (port) rollbackArgs.push("port", port);
        const rollbackCmd = rollbackArgs.join(" ");

        const entry = createChangeEntry({
          tool: "firewall_ufw_rule",
          action: `${deleteRule ? "Delete" : "Add"} UFW rule`,
          target: `ufw/${action}/${direction}`,
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
  );

  // ── 6. firewall_save ───────────────────────────────────────────────────

  server.tool(
    "firewall_save",
    "Save current iptables/ip6tables rules to a file for persistence",
    {
      output_path: z
        .string()
        .optional()
        .default("/etc/iptables/rules.v4")
        .describe("Output file path (default: /etc/iptables/rules.v4)"),
      ipv6: z
        .boolean()
        .optional()
        .default(false)
        .describe("Save ip6tables rules instead of iptables"),
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview the command without executing (defaults to KALI_DEFENSE_DRY_RUN env var)"),
    },
    async ({ output_path, ipv6, dry_run }) => {
      try {
        const saveCmd = ipv6 ? "ip6tables-save" : "iptables-save";
        const fullCmd = `sudo ${saveCmd} > ${output_path}`;

        if (dry_run ?? getConfig().dryRun) {
          const entry = createChangeEntry({
            tool: "firewall_save",
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
          toolName: "firewall_save",
          timeout: getToolTimeout("firewall_save"),
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
          toolName: "firewall_save",
          timeout: getToolTimeout("firewall_save"),
        });

        const success = writeResult.exitCode === 0;

        const entry = createChangeEntry({
          tool: "firewall_save",
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
  );

  // ── 7. firewall_restore ────────────────────────────────────────────────

  server.tool(
    "firewall_restore",
    "Restore iptables/ip6tables rules from a saved file",
    {
      input_path: z
        .string()
        .describe("Path to the rules file to restore from"),
      ipv6: z
        .boolean()
        .optional()
        .default(false)
        .describe("Restore ip6tables rules instead of iptables"),
      test_only: z
        .boolean()
        .optional()
        .default(true)
        .describe("Only test/validate the rules file without applying (default: true)"),
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview the command without executing (defaults to KALI_DEFENSE_DRY_RUN env var)"),
    },
    async ({ input_path, ipv6, test_only, dry_run }) => {
      try {
        const restoreCmd = ipv6 ? "ip6tables-restore" : "iptables-restore";
        const args = [restoreCmd];

        if (test_only) {
          args.push("--test");
        }

        const fullCmd = `sudo ${args.join(" ")} < ${input_path}`;

        if (dry_run ?? getConfig().dryRun) {
          const entry = createChangeEntry({
            tool: "firewall_restore",
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
          toolName: "firewall_restore",
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
          const saveCmd = ipv6 ? "ip6tables-save" : "iptables-save";
          const saveResult = await executeCommand({
            command: "sudo",
            args: [saveCmd],
            toolName: "firewall_restore",
          });
          beforeState = saveResult.stdout;
        }

        const result = await executeCommand({
          command: "sudo",
          args,
          stdin: catResult.stdout,
          toolName: "firewall_restore",
          timeout: getToolTimeout("firewall_restore"),
        });

        const success = result.exitCode === 0;

        const entry = createChangeEntry({
          tool: "firewall_restore",
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
  );

  // ── 8. firewall_nftables_list ────────────────────────────────────────────
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

  // ── 9. firewall_set_policy (GAP-01) ────────────────────────────────────

  server.tool(
    "firewall_set_policy",
    "Set the default policy for an iptables chain (e.g., iptables -P INPUT DROP)",
    {
      chain: z
        .enum(["INPUT", "FORWARD", "OUTPUT"])
        .describe("Built-in chain to set policy for"),
      policy: z
        .enum(["ACCEPT", "DROP"])
        .describe("Default policy to set (ACCEPT or DROP)"),
      ipv6: z
        .boolean()
        .optional()
        .default(false)
        .describe("Also set the policy on ip6tables (default: false)"),
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview the command without executing (defaults to KALI_DEFENSE_DRY_RUN env var)"),
    },
    async ({ chain, policy, ipv6, dry_run }) => {
      try {
        const fullCmd = `sudo iptables -P ${chain} ${policy}`;
        const ipv6Cmd = `sudo ip6tables -P ${chain} ${policy}`;

        if (dry_run ?? getConfig().dryRun) {
          const cmds = [fullCmd];
          if (ipv6) cmds.push(ipv6Cmd);

          const entry = createChangeEntry({
            tool: "firewall_set_policy",
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
          toolName: "firewall_set_policy",
          timeout: getToolTimeout("firewall_set_policy"),
        });
        const currentPolicyMatch = listResult.stdout.match(/Chain \w+ \(policy (\w+)\)/);
        const currentPolicy = currentPolicyMatch ? currentPolicyMatch[1] : "ACCEPT";
        const rollbackCmd = `sudo iptables -P ${chain} ${currentPolicy}`;

        // Execute iptables -P
        const result = await executeCommand({
          command: "sudo",
          args: ["iptables", "-P", chain, policy],
          toolName: "firewall_set_policy",
          timeout: getToolTimeout("firewall_set_policy"),
        });

        if (result.exitCode !== 0) {
          const entry = createChangeEntry({
            tool: "firewall_set_policy",
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

        // Execute ip6tables -P if requested
        if (ipv6) {
          const ip6Result = await executeCommand({
            command: "sudo",
            args: ["ip6tables", "-P", chain, policy],
            toolName: "firewall_set_policy",
            timeout: getToolTimeout("firewall_set_policy"),
          });

          if (ip6Result.exitCode !== 0) {
            messages.push(`IPv6: FAILED - ${ip6Result.stderr}`);
          } else {
            messages.push(`IPv6: ${chain} policy set to ${policy}`);
          }
        }

        const entry = createChangeEntry({
          tool: "firewall_set_policy",
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
  );

  // ── 10. firewall_create_chain (GAP-02) ─────────────────────────────────

  server.tool(
    "firewall_create_chain",
    "Create a custom iptables chain (iptables -N <chain_name>)",
    {
      chain_name: z
        .string()
        .describe("Name of the custom chain to create (alphanumeric, underscore, hyphen; max 29 chars)"),
      ipv6: z
        .boolean()
        .optional()
        .default(false)
        .describe("Also create the chain in ip6tables (default: false)"),
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview the command without executing (defaults to KALI_DEFENSE_DRY_RUN env var)"),
    },
    async ({ chain_name, ipv6, dry_run }) => {
      try {
        // Validate chain name
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
            tool: "firewall_create_chain",
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

        // Execute iptables -N
        const result = await executeCommand({
          command: "sudo",
          args: ["iptables", "-N", chain_name],
          toolName: "firewall_create_chain",
          timeout: getToolTimeout("firewall_create_chain"),
        });

        if (result.exitCode !== 0) {
          const entry = createChangeEntry({
            tool: "firewall_create_chain",
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

        // Execute ip6tables -N if requested
        if (ipv6) {
          const ip6Result = await executeCommand({
            command: "sudo",
            args: ["ip6tables", "-N", chain_name],
            toolName: "firewall_create_chain",
            timeout: getToolTimeout("firewall_create_chain"),
          });

          if (ip6Result.exitCode !== 0) {
            messages.push(`IPv6: FAILED - ${ip6Result.stderr}`);
          } else {
            messages.push(`IPv6: Chain '${chain_name}' created`);
          }
        }

        const entry = createChangeEntry({
          tool: "firewall_create_chain",
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
  );

  // ── 11. firewall_persistence (GAP-07) ──────────────────────────────────

  server.tool(
    "firewall_persistence",
    "Manage iptables-persistent for firewall rule persistence across reboots. Supports installing, saving rules, and checking status.",
    {
      action: z
        .enum(["enable", "save", "status"])
        .describe("Action: 'enable' installs iptables-persistent and enables service, 'save' persists current rules, 'status' checks installation"),
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview the command without executing (defaults to KALI_DEFENSE_DRY_RUN env var)"),
    },
    async ({ action, dry_run }) => {
      try {
        const da = await getDistroAdapter();
        const fwp = da.fwPersistence;

        if (action === "status") {
          // Check if persistence package is installed (distro-aware)
          const pkgCheckResult = await executeCommand({
            command: fwp.checkInstalledCmd[0],
            args: fwp.checkInstalledCmd.slice(1),
            toolName: "firewall_persistence",
            timeout: 5000,
          });

          const installed = da.isDebian
            ? pkgCheckResult.stdout.includes("ii")
            : pkgCheckResult.exitCode === 0;

          // Check if persistence service is enabled
          const svcResult = await executeCommand({
            command: "systemctl",
            args: ["is-enabled", fwp.serviceName],
            toolName: "firewall_persistence",
            timeout: 5000,
          });

          const enabled = svcResult.stdout.trim() === "enabled";

          // Check if rules file exists
          const rulesResult = await executeCommand({
            command: "test",
            args: ["-f", da.paths.firewallPersistenceConfig],
            toolName: "firewall_persistence",
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
              ? `Use firewall_persistence with action='enable' to install ${fwp.packageName}`
              : !enabled
              ? `Run: sudo systemctl enable ${fwp.serviceName}`
              : "Persistence is properly configured",
          };

          return {
            content: [createTextContent(JSON.stringify(status, null, 2))],
          };
        }

        if (action === "enable") {
          const installDesc = `sudo ${fwp.installCmd.join(" ")}`;
          const enableDesc = `sudo ${fwp.enableCmd.join(" ")}`;
          const cmds = [installDesc, enableDesc];

          if (dry_run ?? getConfig().dryRun) {
            const entry = createChangeEntry({
              tool: "firewall_persistence",
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
            toolName: "firewall_persistence",
            timeout: 120000,
            env: da.isDebian ? { DEBIAN_FRONTEND: "noninteractive" } : undefined,
          });

          let installSuccess = installResult.exitCode === 0;
          if (!installSuccess && da.isDebian) {
            // Fallback for Debian: try with bash -c
            const installResult2 = await executeCommand({
              command: "sudo",
              args: ["bash", "-c", `DEBIAN_FRONTEND=noninteractive ${fwp.installCmd.join(" ")}`],
              toolName: "firewall_persistence",
              timeout: 120000,
            });
            installSuccess = installResult2.exitCode === 0;
          }

          if (!installSuccess) {
            const entry = createChangeEntry({
              tool: "firewall_persistence",
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
            toolName: "firewall_persistence",
            timeout: 15000,
          });

          const entry = createChangeEntry({
            tool: "firewall_persistence",
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
                `Use firewall_persistence with action='save' to persist current rules.`
              ),
            ],
          };
        }

        if (action === "save") {
          const fullCmd = `sudo ${fwp.saveCmd.join(" ")}`;

          if (dry_run ?? getConfig().dryRun) {
            const entry = createChangeEntry({
              tool: "firewall_persistence",
              action: `[DRY-RUN] Save persistent firewall rules`,
              target: fwp.serviceName,
              after: fullCmd,
              dryRun: true,
              success: true,
            });
            logChange(entry);

            return {
              content: [
                createTextContent(
                  `[DRY-RUN] Would execute:\n  ${fullCmd}\n\nThis saves firewall rules to ${da.paths.firewallPersistenceConfig}`
                ),
              ],
            };
          }

          const result = await executeCommand({
            command: "sudo",
            args: fwp.saveCmd,
            toolName: "firewall_persistence",
            timeout: 15000,
          });

          const success = result.exitCode === 0;

          const entry = createChangeEntry({
            tool: "firewall_persistence",
            action: `Save persistent firewall rules`,
            target: "netfilter-persistent",
            after: fullCmd,
            dryRun: false,
            success,
            error: success ? undefined : result.stderr,
          });
          logChange(entry);

          if (!success) {
            return {
              content: [
                createErrorContent(
                  `netfilter-persistent save failed (exit ${result.exitCode}): ${result.stderr}\n` +
                  `Is iptables-persistent installed? Use firewall_persistence with action='status' to check.`
                ),
              ],
              isError: true,
            };
          }

          return {
            content: [
              createTextContent(
                `Firewall rules saved persistently (IPv4 + IPv6).\n${result.stdout || "Rules saved to /etc/iptables/rules.v4 and rules.v6"}`
              ),
            ],
          };
        }

        return {
          content: [createErrorContent(`Unknown action: ${action}`)],
          isError: true,
        };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 12. firewall_policy_audit (GAP-16 updated) ─────────────────────────
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
                : "Use firewall_set_policy to set INPUT chain to DROP (e.g., firewall_set_policy chain=INPUT policy=DROP ipv6=true)",
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
                : "Use firewall_set_policy to set FORWARD chain to DROP (e.g., firewall_set_policy chain=FORWARD policy=DROP ipv6=true)",
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
                ? "Use firewall_set_policy to set OUTPUT chain to DROP for high-security environments (e.g., firewall_set_policy chain=OUTPUT policy=DROP)"
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
                : "Use firewall_set_policy with ipv6=true to set IPv6 INPUT policy to DROP (e.g., firewall_set_policy chain=INPUT policy=DROP ipv6=true)",
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
            : "Use firewall_persistence with action='enable' to install and activate persistence, then action='save' to persist current rules",
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
