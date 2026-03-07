/**
 * Intrusion Detection System (IDS) tools for Kali Defense MCP Server.
 *
 * Registers 3 tools: ids_aide_manage, ids_rootkit_scan (actions: rkhunter, chkrootkit, all),
 * ids_file_integrity_check.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeCommand } from "../core/executor.js";
import { getConfig, getToolTimeout } from "../core/config.js";
import {
  createTextContent,
  createErrorContent,
  formatToolOutput,
} from "../core/parsers.js";
import {
  logChange,
  createChangeEntry,
} from "../core/changelog.js";
import { sanitizeArgs } from "../core/sanitizer.js";

// ── Registration entry point ───────────────────────────────────────────────

export function registerIdsTools(server: McpServer): void {
  // ── 1. ids_aide_manage ─────────────────────────────────────────────────

  server.tool(
    "ids_aide_manage",
    "Manage AIDE (Advanced Intrusion Detection Environment) file integrity database",
    {
      action: z
        .enum(["init", "check", "update", "compare"])
        .describe(
          "Action: init (create baseline), check (verify), update (update db), compare (compare dbs)"
        ),
      config: z
        .string()
        .optional()
        .describe("Path to custom AIDE config file"),
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview the command without executing (defaults to KALI_DEFENSE_DRY_RUN env var)"),
    },
    async ({ action, config, dry_run }) => {
      try {
        const args: string[] = [];

        switch (action) {
          case "init":
            args.push("--init");
            break;
          case "check":
            args.push("--check");
            break;
          case "update":
            args.push("--update");
            break;
          case "compare":
            args.push("--compare");
            break;
        }

        if (config) {
          sanitizeArgs([config]);
          args.push("--config", config);
        }

        const fullCmd = `sudo aide ${args.join(" ")}`;

        if (dry_run ?? getConfig().dryRun) {
          let preview = `[DRY-RUN] Would execute:\n  ${fullCmd}`;

          if (action === "init") {
            preview +=
              "\n\nThis will create a new AIDE database. After init, the database at /var/lib/aide/aide.db.new will need to be moved to /var/lib/aide/aide.db.";
          } else if (action === "check") {
            preview +=
              "\n\nThis will check file integrity against the baseline database.";
          } else if (action === "update") {
            preview +=
              "\n\nThis will update the AIDE database with current file states.";
          } else if (action === "compare") {
            preview +=
              "\n\nThis will compare the baseline and new databases.";
          }

          const entry = createChangeEntry({
            tool: "ids_aide_manage",
            action: `[DRY-RUN] AIDE ${action}`,
            target: "aide-database",
            dryRun: true,
            success: true,
          });
          logChange(entry);

          return { content: [createTextContent(preview)] };
        }

        const result = await executeCommand({
          command: "sudo",
          args: ["aide", ...args],
          toolName: "ids_aide_manage",
          timeout: getToolTimeout("aide"),
        });

        // AIDE returns different exit codes:
        // 0 = no changes, 1-7 = changes detected (not necessarily errors)
        const isError = action === "init" && result.exitCode !== 0;

        // For init, move the new database
        let postAction = "";
        if (action === "init" && result.exitCode === 0) {
          const moveResult = await executeCommand({
            command: "sudo",
            args: [
              "mv",
              "/var/lib/aide/aide.db.new",
              "/var/lib/aide/aide.db",
            ],
            toolName: "ids_aide_manage",
          });
          if (moveResult.exitCode === 0) {
            postAction =
              "\n\nDatabase initialized and moved to /var/lib/aide/aide.db";
          } else {
            postAction = `\n\nWarning: Database created but failed to move: ${moveResult.stderr}`;
          }
        }

        const entry = createChangeEntry({
          tool: "ids_aide_manage",
          action: `AIDE ${action}`,
          target: "aide-database",
          dryRun: false,
          success: !isError,
          error: isError ? result.stderr : undefined,
        });
        logChange(entry);

        if (isError) {
          return {
            content: [
              createErrorContent(
                `AIDE ${action} failed (exit ${result.exitCode}): ${result.stderr}`
              ),
            ],
            isError: true,
          };
        }

        // Parse AIDE check output for summary
        let summary = "";
        if (action === "check") {
          const lines = result.stdout.split("\n");
          const summaryLines = lines.filter(
            (l) =>
              l.includes("added") ||
              l.includes("removed") ||
              l.includes("changed") ||
              l.includes("Total")
          );
          if (summaryLines.length > 0) {
            summary = `\n\nSummary:\n${summaryLines.join("\n")}`;
          }
        }

        return {
          content: [
            createTextContent(
              `AIDE ${action} completed (exit code: ${result.exitCode}).${postAction}${summary}\n\n${result.stdout}${result.stderr ? `\n\nStderr:\n${result.stderr}` : ""}`
            ),
          ],
        };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 2. ids_rootkit_scan (merged: rkhunter, chkrootkit, all) ────────────

  server.tool(
    "ids_rootkit_scan",
    "Rootkit detection: run rkhunter, chkrootkit, or combined scan using all available tools.",
    {
      action: z.enum(["rkhunter", "chkrootkit", "all"]).describe("Action: rkhunter=rkhunter scan, chkrootkit=chkrootkit scan, all=combined summary"),
      // rkhunter params
      update_first: z.boolean().optional().default(true).describe("Update rkhunter database before scanning (rkhunter/all action)"),
      skip_keypress: z.boolean().optional().default(true).describe("Skip keypress prompts during scan (rkhunter action)"),
      report_warnings_only: z.boolean().optional().default(false).describe("Only report warnings, not OK results (rkhunter action)"),
      // chkrootkit params
      quiet: z.boolean().optional().default(false).describe("Quiet mode - only show infected findings (chkrootkit action)"),
      expert: z.boolean().optional().default(false).describe("Expert mode - show additional diagnostic info (chkrootkit action)"),
      // all params
      quick: z.boolean().optional().default(true).describe("Quick scan mode - skip database updates (all action)"),
    },
    async (params) => {
      const { action } = params;

      switch (action) {
        // ── rkhunter ────────────────────────────────────────────────
        case "rkhunter": {
          const { update_first, skip_keypress, report_warnings_only } = params;
          try {
            let updateOutput = "";
            if (update_first) {
              const updateResult = await executeCommand({
                command: "sudo",
                args: ["rkhunter", "--update"],
                toolName: "ids_rootkit_scan",
                timeout: getToolTimeout("rkhunter"),
              });
              updateOutput = `Database update (exit ${updateResult.exitCode}):\n${updateResult.stdout}\n\n`;
            }

            const args = ["rkhunter", "--check"];
            if (skip_keypress) args.push("--sk");
            if (report_warnings_only) args.push("--rwo");

            const result = await executeCommand({
              command: "sudo",
              args,
              toolName: "ids_rootkit_scan",
              timeout: getToolTimeout("rkhunter"),
            });

            const warnings: string[] = [];
            const infected: string[] = [];

            for (const line of result.stdout.split("\n")) {
              const trimmed = line.trim();
              if (trimmed.includes("[ Warning ]") || trimmed.includes("WARNING")) {
                warnings.push(trimmed);
              }
              if (trimmed.includes("[ Infected ]") || trimmed.includes("INFECTED")) {
                infected.push(trimmed);
              }
            }

            const output = {
              exitCode: result.exitCode,
              updateOutput: update_first ? updateOutput : undefined,
              warningsCount: warnings.length,
              infectedCount: infected.length,
              warnings,
              infected,
              riskLevel: infected.length > 0 ? "CRITICAL" : warnings.length > 0 ? "WARNING" : "CLEAN",
              raw: result.stdout,
            };

            logChange(createChangeEntry({
              tool: "ids_rootkit_scan",
              action: "Rootkit scan (rkhunter)",
              target: "system",
              after: `Warnings: ${warnings.length}, Infected: ${infected.length}`,
              dryRun: false,
              success: true,
            }));

            return { content: [formatToolOutput(output)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── chkrootkit ──────────────────────────────────────────────
        case "chkrootkit": {
          const { quiet, expert } = params;
          try {
            const args = ["chkrootkit"];
            if (quiet) args.push("-q");
            if (expert) args.push("-x");

            const result = await executeCommand({
              command: "sudo",
              args,
              toolName: "ids_rootkit_scan",
              timeout: getToolTimeout("chkrootkit"),
            });

            const infected: string[] = [];
            const suspicious: string[] = [];
            const notInfected: string[] = [];

            for (const line of result.stdout.split("\n")) {
              const trimmed = line.trim();
              if (!trimmed) continue;
              if (trimmed.includes("INFECTED")) {
                infected.push(trimmed);
              } else if (trimmed.includes("Suspicious") || trimmed.includes("suspicious")) {
                suspicious.push(trimmed);
              } else if (trimmed.includes("not infected") || trimmed.includes("not found") || trimmed.includes("nothing found")) {
                notInfected.push(trimmed);
              }
            }

            const output = {
              exitCode: result.exitCode,
              infectedCount: infected.length,
              suspiciousCount: suspicious.length,
              cleanCount: notInfected.length,
              infected,
              suspicious,
              riskLevel: infected.length > 0 ? "CRITICAL" : suspicious.length > 0 ? "WARNING" : "CLEAN",
              raw: result.stdout,
            };

            logChange(createChangeEntry({
              tool: "ids_rootkit_scan",
              action: "Rootkit scan (chkrootkit)",
              target: "system",
              after: `Infected: ${infected.length}, Suspicious: ${suspicious.length}`,
              dryRun: false,
              success: true,
            }));

            return { content: [formatToolOutput(output)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── all (combined summary) ──────────────────────────────────
        case "all": {
          const { quick } = params;
          try {
            const findings: Array<{
              tool: string;
              available: boolean;
              exitCode: number;
              warnings: string[];
              infected: string[];
              riskLevel: string;
              error?: string;
            }> = [];

            // Check if rkhunter is available
            const rkhunterCheck = await executeCommand({
              command: "which",
              args: ["rkhunter"],
              toolName: "ids_rootkit_scan",
            });

            if (rkhunterCheck.exitCode === 0) {
              const rkhunterArgs = ["rkhunter", "--check", "--sk"];
              if (!quick) {
                await executeCommand({
                  command: "sudo",
                  args: ["rkhunter", "--update"],
                  toolName: "ids_rootkit_scan",
                  timeout: getToolTimeout("rkhunter"),
                });
              }

              const rkhunterResult = await executeCommand({
                command: "sudo",
                args: rkhunterArgs,
                toolName: "ids_rootkit_scan",
                timeout: getToolTimeout("rkhunter"),
              });

              const warnings: string[] = [];
              const infected: string[] = [];

              for (const line of rkhunterResult.stdout.split("\n")) {
                const trimmed = line.trim();
                if (trimmed.includes("[ Warning ]") || trimmed.includes("WARNING")) warnings.push(trimmed);
                if (trimmed.includes("[ Infected ]") || trimmed.includes("INFECTED")) infected.push(trimmed);
              }

              findings.push({
                tool: "rkhunter",
                available: true,
                exitCode: rkhunterResult.exitCode,
                warnings,
                infected,
                riskLevel: infected.length > 0 ? "CRITICAL" : warnings.length > 0 ? "WARNING" : "CLEAN",
              });
            } else {
              findings.push({
                tool: "rkhunter",
                available: false,
                exitCode: -1,
                warnings: [],
                infected: [],
                riskLevel: "UNKNOWN",
                error: "rkhunter not installed. Install with: sudo apt install rkhunter",
              });
            }

            // Check if chkrootkit is available
            const chkrootkitCheck = await executeCommand({
              command: "which",
              args: ["chkrootkit"],
              toolName: "ids_rootkit_scan",
            });

            if (chkrootkitCheck.exitCode === 0) {
              const chkrootkitResult = await executeCommand({
                command: "sudo",
                args: ["chkrootkit", "-q"],
                toolName: "ids_rootkit_scan",
                timeout: getToolTimeout("chkrootkit"),
              });

              const warnings: string[] = [];
              const infected: string[] = [];

              for (const line of chkrootkitResult.stdout.split("\n")) {
                const trimmed = line.trim();
                if (!trimmed) continue;
                if (trimmed.includes("INFECTED")) infected.push(trimmed);
                else if (trimmed.includes("Suspicious") || trimmed.includes("suspicious")) warnings.push(trimmed);
              }

              findings.push({
                tool: "chkrootkit",
                available: true,
                exitCode: chkrootkitResult.exitCode,
                warnings,
                infected,
                riskLevel: infected.length > 0 ? "CRITICAL" : warnings.length > 0 ? "WARNING" : "CLEAN",
              });
            } else {
              findings.push({
                tool: "chkrootkit",
                available: false,
                exitCode: -1,
                warnings: [],
                infected: [],
                riskLevel: "UNKNOWN",
                error: "chkrootkit not installed. Install with: sudo apt install chkrootkit",
              });
            }

            const totalInfected = findings.reduce((sum, f) => sum + f.infected.length, 0);
            const totalWarnings = findings.reduce((sum, f) => sum + f.warnings.length, 0);
            const availableTools = findings.filter((f) => f.available).length;

            let overallRisk = "CLEAN";
            if (totalInfected > 0) overallRisk = "CRITICAL";
            else if (totalWarnings > 0) overallRisk = "WARNING";
            else if (availableTools === 0) overallRisk = "UNKNOWN - No scanning tools available";

            const output = {
              overallRisk,
              summary: { toolsAvailable: availableTools, toolsTotal: findings.length, totalInfected, totalWarnings },
              findings,
              recommendations:
                totalInfected > 0
                  ? ["CRITICAL: Potential rootkit detected. Investigate immediately.", "Boot from clean media and verify system integrity.", "Compare findings against known false positives.", "Consider reimaging the system if infection confirmed."]
                  : totalWarnings > 0
                    ? ["Review warnings and determine if they are false positives.", "Cross-reference with system changes and package updates.", "Run a full scan with verbose output for more details."]
                    : availableTools > 0
                      ? ["System appears clean. Schedule regular scans."]
                      : ["Install rkhunter: sudo apt install rkhunter", "Install chkrootkit: sudo apt install chkrootkit"],
            };

            logChange(createChangeEntry({
              tool: "ids_rootkit_scan",
              action: "Combined rootkit scan",
              target: "system",
              after: `Risk: ${overallRisk}, Infected: ${totalInfected}, Warnings: ${totalWarnings}`,
              dryRun: false,
              success: true,
            }));

            return { content: [formatToolOutput(output)] };
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

  // ── 3. ids_file_integrity_check (kept as-is) ──────────────────────────

  server.tool(
    "ids_file_integrity_check",
    "Quick file integrity check using SHA-256 hashes. Create, verify against, or display file baselines.",
    {
      paths: z
        .union([z.string(), z.array(z.string())])
        .describe("File path(s) to check — accepts a single comma-separated string or an array of paths"),
      baseline_path: z
        .string()
        .optional()
        .describe("Path to baseline hash file for comparison"),
      create_baseline: z
        .boolean()
        .optional()
        .default(false)
        .describe("Create a new baseline hash file from the given paths"),
    },
    async ({ paths, baseline_path, create_baseline }) => {
      try {
        const filePaths = (Array.isArray(paths)
          ? paths
          : paths.split(","))
          .map((p) => p.trim())
          .filter((p) => p.length > 0);

        if (filePaths.length === 0) {
          return {
            content: [createErrorContent("No file paths provided")],
            isError: true,
          };
        }

        sanitizeArgs(filePaths);

        // Compute sha256sum for each file
        const hashResult = await executeCommand({
          command: "sha256sum",
          args: filePaths,
          toolName: "ids_file_integrity_check",
          timeout: getToolTimeout("ids_file_integrity_check"),
        });

        if (hashResult.exitCode !== 0 && !hashResult.stdout) {
          return {
            content: [
              createErrorContent(
                `sha256sum failed (exit ${hashResult.exitCode}): ${hashResult.stderr}`
              ),
            ],
            isError: true,
          };
        }

        // Parse current hashes
        const currentHashes: Array<{ hash: string; file: string }> = [];
        for (const line of hashResult.stdout.split("\n")) {
          const trimmed = line.trim();
          if (!trimmed) continue;
          const parts = trimmed.split(/\s+/);
          if (parts.length >= 2) {
            currentHashes.push({ hash: parts[0], file: parts.slice(1).join(" ") });
          }
        }

        // Create baseline mode
        if (create_baseline) {
          const baselineOutput = baseline_path ?? "/tmp/file-integrity-baseline.sha256";
          sanitizeArgs([baselineOutput]);

          const writeResult = await executeCommand({
            command: "sudo",
            args: ["tee", baselineOutput],
            stdin: hashResult.stdout,
            toolName: "ids_file_integrity_check",
          });

          const success = writeResult.exitCode === 0;

          const entry = createChangeEntry({
            tool: "ids_file_integrity_check",
            action: "Create integrity baseline",
            target: baselineOutput,
            after: `${currentHashes.length} files hashed`,
            dryRun: false,
            success,
            error: success ? undefined : writeResult.stderr,
          });
          logChange(entry);

          if (!success) {
            return {
              content: [
                createErrorContent(
                  `Failed to write baseline: ${writeResult.stderr}`
                ),
              ],
              isError: true,
            };
          }

          return {
            content: [
              formatToolOutput({
                action: "baseline_created",
                baselinePath: baselineOutput,
                fileCount: currentHashes.length,
                hashes: currentHashes,
              }),
            ],
          };
        }

        // Compare against baseline mode
        if (baseline_path) {
          sanitizeArgs([baseline_path]);

          // Read baseline
          const baselineResult = await executeCommand({
            command: "cat",
            args: [baseline_path],
            toolName: "ids_file_integrity_check",
          });

          if (baselineResult.exitCode !== 0) {
            return {
              content: [
                createErrorContent(
                  `Cannot read baseline file ${baseline_path}: ${baselineResult.stderr}`
                ),
              ],
              isError: true,
            };
          }

          // Parse baseline hashes
          const baselineHashes = new Map<string, string>();
          for (const line of baselineResult.stdout.split("\n")) {
            const trimmed = line.trim();
            if (!trimmed) continue;
            const parts = trimmed.split(/\s+/);
            if (parts.length >= 2) {
              baselineHashes.set(parts.slice(1).join(" "), parts[0]);
            }
          }

          // Compare
          const changed: Array<{
            file: string;
            baselineHash: string;
            currentHash: string;
          }> = [];
          const unchanged: string[] = [];
          const newFiles: Array<{ file: string; hash: string }> = [];
          const missingFiles: string[] = [];

          for (const current of currentHashes) {
            const baselineHash = baselineHashes.get(current.file);
            if (baselineHash === undefined) {
              newFiles.push({ file: current.file, hash: current.hash });
            } else if (baselineHash !== current.hash) {
              changed.push({
                file: current.file,
                baselineHash,
                currentHash: current.hash,
              });
            } else {
              unchanged.push(current.file);
            }
            baselineHashes.delete(current.file);
          }

          // Remaining entries in baseline are missing files
          for (const [file] of baselineHashes) {
            missingFiles.push(file);
          }

          const output = {
            action: "comparison",
            baselinePath: baseline_path,
            summary: {
              total: currentHashes.length,
              unchanged: unchanged.length,
              changed: changed.length,
              new: newFiles.length,
              missing: missingFiles.length,
            },
            integrityStatus:
              changed.length > 0 || missingFiles.length > 0
                ? "MODIFIED"
                : "INTACT",
            changed,
            newFiles,
            missingFiles,
            unchanged,
          };

          const entry = createChangeEntry({
            tool: "ids_file_integrity_check",
            action: "File integrity comparison",
            target: baseline_path,
            after: `Changed: ${changed.length}, New: ${newFiles.length}, Missing: ${missingFiles.length}`,
            dryRun: false,
            success: true,
          });
          logChange(entry);

          return { content: [formatToolOutput(output)] };
        }

        // Display mode - just show hashes
        return {
          content: [
            formatToolOutput({
              action: "display",
              fileCount: currentHashes.length,
              hashes: currentHashes,
              errors: hashResult.stderr || undefined,
            }),
          ],
        };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

}
