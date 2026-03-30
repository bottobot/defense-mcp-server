/**
 * Integrity tools for Defense MCP Server.
 *
 * Consolidates IDS (ids.ts) and drift-detection (drift-detection.ts) into a
 * single tool: `integrity` with 11 actions.
 *
 * Actions:
 *   aide_init, aide_check, aide_update, aide_compare  (AIDE database)
 *   rootkit_rkhunter, rootkit_chkrootkit, rootkit_all (rootkit scanning)
 *   file_integrity                                     (SHA-256 file checks)
 *   baseline_create, baseline_compare, baseline_list   (drift detection)
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeCommand } from "../core/executor.js";
import { getConfig, getToolTimeout, getActionTimeout } from "../core/config.js";
import {
  createTextContent,
  createErrorContent,
  formatToolOutput,
} from "../core/parsers.js";
import {
  generateDurationBanner,
  generateTimingSummary,
  startTiming,
} from "../core/progress.js";
import { logChange, createChangeEntry } from "../core/changelog.js";
import { sanitizeArgs, validateToolPath } from "../core/sanitizer.js";
import {
  existsSync,
  readFileSync,
  mkdirSync,
  readdirSync,
  statSync,
} from "node:fs";
import { join, extname, resolve } from "node:path";
import { homedir } from "node:os";
import { createHash } from "node:crypto";
import { secureWriteFileSync } from "../core/secure-fs.js";

// ── TOOL-016 remediation: allowed directories for IDS config/baseline paths ─
const ALLOWED_IDS_DIRS = ["/etc", "/var/lib", "/tmp", "/home", "/opt", "/usr"];

// ── Drift detection constants ──────────────────────────────────────────────
const BASELINE_DIR = join(homedir(), ".defense-mcp-baselines");

/** Allowed directories for drift baseline files */
const ALLOWED_BASELINE_DIRS = [
  BASELINE_DIR,
  "/tmp",
  "/var/lib",
  "/home",
  "/root",
  "/opt",
];

/** Allowed file extensions for baseline files */
const ALLOWED_BASELINE_EXTENSIONS = new Set([".json", ".yaml", ".yml"]);

// ── TOOL-024 remediation: baseline path validation ─────────────────────────

function validateBaselinePath(inputPath: string): string {
  if (!inputPath || typeof inputPath !== "string") {
    throw new Error("Baseline path must be a non-empty string");
  }
  if (inputPath.includes("..")) {
    throw new Error(
      `Baseline path contains forbidden traversal sequence (..): '${inputPath}'`
    );
  }
  const resolved = resolve(inputPath);
  const isAllowed = ALLOWED_BASELINE_DIRS.some(
    (dir) => resolved === dir || resolved.startsWith(dir + "/")
  );
  if (!isAllowed) {
    throw new Error(
      `Baseline path '${resolved}' is not within allowed directories: ${ALLOWED_BASELINE_DIRS.join(", ")}`
    );
  }
  const ext = extname(resolved).toLowerCase();
  if (ext && !ALLOWED_BASELINE_EXTENSIONS.has(ext)) {
    throw new Error(
      `Baseline file has invalid extension '${ext}'. Allowed: ${[...ALLOWED_BASELINE_EXTENSIONS].join(", ")}`
    );
  }
  return resolved;
}

function ensureBaselineDir(): void {
  if (!existsSync(BASELINE_DIR)) {
    mkdirSync(BASELINE_DIR, { recursive: true });
  }
}

interface BaselineEntry {
  path: string;
  hash: string;
  size: number;
  mtime: string;
}

interface BaselineData {
  id: string;
  timestamp: string;
  directories: string[];
  files: BaselineEntry[];
  sysctlState: Record<string, string>;
  services: Record<string, string>;
}

function hashFile(filePath: string): string {
  try {
    const content = readFileSync(filePath);
    return createHash("sha256").update(content).digest("hex");
  } catch {
    return "unreadable";
  }
}

// ── Registration entry point ───────────────────────────────────────────────

export function registerIntegrityTools(server: McpServer): void {
  server.tool(
    "integrity",
    "Integrity: AIDE, rootkit scanning, file hashing, drift baselines",
    {
      action: z
        .enum([
          "aide_init",
          "aide_check",
          "aide_update",
          "aide_compare",
          "rootkit_rkhunter",
          "rootkit_chkrootkit",
          "rootkit_all",
          "file_integrity",
          "baseline_create",
          "baseline_compare",
          "baseline_list",
        ])
        .describe("Integrity monitoring action"),
      // AIDE params
      config: z.string().optional().describe("Custom AIDE config file path"),
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview without executing"),
      // rkhunter params
      update_first: z
        .boolean()
        .optional()
        .default(true)
        .describe("Update rkhunter database before scanning"),
      skip_keypress: z
        .boolean()
        .optional()
        .default(true)
        .describe("Skip keypress prompts"),
      report_warnings_only: z
        .boolean()
        .optional()
        .default(false)
        .describe("Only report warnings"),
      // chkrootkit params
      quiet: z
        .boolean()
        .optional()
        .default(false)
        .describe("Only show infected findings"),
      expert: z
        .boolean()
        .optional()
        .default(false)
        .describe("Show additional diagnostic info"),
      // rootkit_all params
      quick: z
        .boolean()
        .optional()
        .default(true)
        .describe("Quick scan, skip database updates"),
      // file_integrity params
      paths: z
        .union([z.string(), z.array(z.string())])
        .optional()
        .describe("File path(s) to check (string or array)"),
      baseline_path: z
        .string()
        .optional()
        .describe("Baseline hash file for comparison"),
      create_baseline: z
        .boolean()
        .optional()
        .default(false)
        .describe("Create new baseline hash file"),
      // drift baseline params
      name: z
        .string()
        .optional()
        .default("default")
        .describe("Baseline name"),
      directories: z
        .array(z.string())
        .optional()
        .default(["/etc"])
        .describe("Directories to hash"),
      dryRun: z
        .boolean()
        .optional()
        .default(true)
        .describe("Preview only"),
    },
    async (params) => {
      const { action } = params;

      switch (action) {
        // ── aide_init / aide_check / aide_update / aide_compare ────────────
        case "aide_init":
        case "aide_check":
        case "aide_update":
        case "aide_compare": {
          const { config, dry_run } = params;
          const aideAction = action.replace("aide_", "") as
            | "init"
            | "check"
            | "update"
            | "compare";
          try {
            const args: string[] = [];
            switch (aideAction) {
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
              const validatedConfig = validateToolPath(
                config,
                ALLOWED_IDS_DIRS,
                "AIDE config path"
              );
              args.push("--config", validatedConfig);
            }

            const fullCmd = `sudo aide ${args.join(" ")}`;

            if (dry_run ?? getConfig().dryRun) {
              let preview = `[DRY-RUN] Would execute:\n  ${fullCmd}`;
              if (aideAction === "init") {
                preview +=
                  "\n\nThis will create a new AIDE database. After init, the database at /var/lib/aide/aide.db.new will need to be moved to /var/lib/aide/aide.db.";
              } else if (aideAction === "check") {
                preview +=
                  "\n\nThis will check file integrity against the baseline database.";
              } else if (aideAction === "update") {
                preview +=
                  "\n\nThis will update the AIDE database with current file states.";
              } else if (aideAction === "compare") {
                preview +=
                  "\n\nThis will compare the baseline and new databases.";
              }
              const entry = createChangeEntry({
                tool: "integrity",
                action: `[DRY-RUN] AIDE ${aideAction}`,
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
              toolName: "integrity",
              timeout: getToolTimeout("aide"),
            });

            const isError = aideAction === "init" && result.exitCode !== 0;

            let postAction = "";
            if (aideAction === "init" && result.exitCode === 0) {
              const moveResult = await executeCommand({
                command: "sudo",
                args: [
                  "mv",
                  "/var/lib/aide/aide.db.new",
                  "/var/lib/aide/aide.db",
                ],
                toolName: "integrity",
              });
              if (moveResult.exitCode === 0) {
                postAction =
                  "\n\nDatabase initialized and moved to /var/lib/aide/aide.db";
              } else {
                postAction = `\n\nWarning: Database created but failed to move: ${moveResult.stderr}`;
              }
            }

            const entry = createChangeEntry({
              tool: "integrity",
              action: `AIDE ${aideAction}`,
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
                    `AIDE ${aideAction} failed (exit ${result.exitCode}): ${result.stderr}`
                  ),
                ],
                isError: true,
              };
            }

            let summary = "";
            if (aideAction === "check") {
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
                  `AIDE ${aideAction} completed (exit code: ${result.exitCode}).${postAction}${summary}\n\n${result.stdout}${result.stderr ? `\n\nStderr:\n${result.stderr}` : ""}`
                ),
              ],
            };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── rootkit_rkhunter ───────────────────────────────────────────────
        case "rootkit_rkhunter": {
          const { update_first, skip_keypress, report_warnings_only } = params;
          try {
            const actionTimeout = getActionTimeout("integrity", "rootkit_rkhunter");
            const timing = startTiming("integrity", "rootkit_rkhunter");
            const banner = generateDurationBanner("integrity", "rootkit_rkhunter", actionTimeout);

            let updateOutput = "";
            if (update_first) {
              const updateResult = await executeCommand({
                command: "sudo",
                args: ["rkhunter", "--update"],
                toolName: "integrity",
                timeout: actionTimeout,
              });
              updateOutput = `Database update (exit ${updateResult.exitCode}):\n${updateResult.stdout}\n\n`;
            }

            const args = ["rkhunter", "--check"];
            if (skip_keypress) args.push("--sk");
            if (report_warnings_only) args.push("--rwo");

            const result = await executeCommand({
              command: "sudo",
              args,
              toolName: "integrity",
              timeout: actionTimeout,
            });

            const warnings: string[] = [];
            const infected: string[] = [];

            for (const line of result.stdout.split("\n")) {
              const trimmed = line.trim();
              if (
                trimmed.includes("[ Warning ]") ||
                trimmed.includes("WARNING")
              ) {
                warnings.push(trimmed);
              }
              if (
                trimmed.includes("[ Infected ]") ||
                trimmed.includes("INFECTED")
              ) {
                infected.push(trimmed);
              }
            }

            const timingSummary = generateTimingSummary("integrity", "rootkit_rkhunter", Date.now() - timing.startTime);

            const output = {
              exitCode: result.exitCode,
              updateOutput: update_first ? updateOutput : undefined,
              warningsCount: warnings.length,
              infectedCount: infected.length,
              warnings,
              infected,
              riskLevel:
                infected.length > 0
                  ? "CRITICAL"
                  : warnings.length > 0
                    ? "WARNING"
                    : "CLEAN",
              raw: banner + result.stdout + timingSummary,
            };

            logChange(
              createChangeEntry({
                tool: "integrity",
                action: "Rootkit scan (rkhunter)",
                target: "system",
                after: `Warnings: ${warnings.length}, Infected: ${infected.length}`,
                dryRun: false,
                success: true,
              })
            );

            return { content: [formatToolOutput(output)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── rootkit_chkrootkit ─────────────────────────────────────────────
        case "rootkit_chkrootkit": {
          const { quiet, expert } = params;
          try {
            const args = ["chkrootkit"];
            if (quiet) args.push("-q");
            if (expert) args.push("-x");

            const result = await executeCommand({
              command: "sudo",
              args,
              toolName: "integrity",
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
              } else if (
                trimmed.includes("Suspicious") ||
                trimmed.includes("suspicious")
              ) {
                suspicious.push(trimmed);
              } else if (
                trimmed.includes("not infected") ||
                trimmed.includes("not found") ||
                trimmed.includes("nothing found")
              ) {
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
              riskLevel:
                infected.length > 0
                  ? "CRITICAL"
                  : suspicious.length > 0
                    ? "WARNING"
                    : "CLEAN",
              raw: result.stdout,
            };

            logChange(
              createChangeEntry({
                tool: "integrity",
                action: "Rootkit scan (chkrootkit)",
                target: "system",
                after: `Infected: ${infected.length}, Suspicious: ${suspicious.length}`,
                dryRun: false,
                success: true,
              })
            );

            return { content: [formatToolOutput(output)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── rootkit_all (combined summary) ─────────────────────────────────
        case "rootkit_all": {
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

            const rkhunterCheck = await executeCommand({
              command: "which",
              args: ["rkhunter"],
              toolName: "integrity",
            });

            if (rkhunterCheck.exitCode === 0) {
              const rkhunterArgs = ["rkhunter", "--check", "--sk"];
              if (!quick) {
                await executeCommand({
                  command: "sudo",
                  args: ["rkhunter", "--update"],
                  toolName: "integrity",
                  timeout: getToolTimeout("rkhunter"),
                });
              }

              const rkhunterResult = await executeCommand({
                command: "sudo",
                args: rkhunterArgs,
                toolName: "integrity",
                timeout: getToolTimeout("rkhunter"),
              });

              const warnings: string[] = [];
              const infected: string[] = [];

              for (const line of rkhunterResult.stdout.split("\n")) {
                const trimmed = line.trim();
                if (
                  trimmed.includes("[ Warning ]") ||
                  trimmed.includes("WARNING")
                )
                  warnings.push(trimmed);
                if (
                  trimmed.includes("[ Infected ]") ||
                  trimmed.includes("INFECTED")
                )
                  infected.push(trimmed);
              }

              findings.push({
                tool: "rkhunter",
                available: true,
                exitCode: rkhunterResult.exitCode,
                warnings,
                infected,
                riskLevel:
                  infected.length > 0
                    ? "CRITICAL"
                    : warnings.length > 0
                      ? "WARNING"
                      : "CLEAN",
              });
            } else {
              findings.push({
                tool: "rkhunter",
                available: false,
                exitCode: -1,
                warnings: [],
                infected: [],
                riskLevel: "UNKNOWN",
                error:
                  "rkhunter not installed. Install with: sudo apt install rkhunter",
              });
            }

            const chkrootkitCheck = await executeCommand({
              command: "which",
              args: ["chkrootkit"],
              toolName: "integrity",
            });

            if (chkrootkitCheck.exitCode === 0) {
              const chkrootkitResult = await executeCommand({
                command: "sudo",
                args: ["chkrootkit", "-q"],
                toolName: "integrity",
                timeout: getToolTimeout("chkrootkit"),
              });

              const warnings: string[] = [];
              const infected: string[] = [];

              for (const line of chkrootkitResult.stdout.split("\n")) {
                const trimmed = line.trim();
                if (!trimmed) continue;
                if (trimmed.includes("INFECTED")) infected.push(trimmed);
                else if (
                  trimmed.includes("Suspicious") ||
                  trimmed.includes("suspicious")
                )
                  warnings.push(trimmed);
              }

              findings.push({
                tool: "chkrootkit",
                available: true,
                exitCode: chkrootkitResult.exitCode,
                warnings,
                infected,
                riskLevel:
                  infected.length > 0
                    ? "CRITICAL"
                    : warnings.length > 0
                      ? "WARNING"
                      : "CLEAN",
              });
            } else {
              findings.push({
                tool: "chkrootkit",
                available: false,
                exitCode: -1,
                warnings: [],
                infected: [],
                riskLevel: "UNKNOWN",
                error:
                  "chkrootkit not installed. Install with: sudo apt install chkrootkit",
              });
            }

            const totalInfected = findings.reduce(
              (sum, f) => sum + f.infected.length,
              0
            );
            const totalWarnings = findings.reduce(
              (sum, f) => sum + f.warnings.length,
              0
            );
            const availableTools = findings.filter((f) => f.available).length;

            let overallRisk = "CLEAN";
            if (totalInfected > 0) overallRisk = "CRITICAL";
            else if (totalWarnings > 0) overallRisk = "WARNING";
            else if (availableTools === 0)
              overallRisk = "UNKNOWN - No scanning tools available";

            const output = {
              overallRisk,
              summary: {
                toolsAvailable: availableTools,
                toolsTotal: findings.length,
                totalInfected,
                totalWarnings,
              },
              findings,
              recommendations:
                totalInfected > 0
                  ? [
                      "CRITICAL: Potential rootkit detected. Investigate immediately.",
                      "Boot from clean media and verify system integrity.",
                      "Compare findings against known false positives.",
                      "Consider reimaging the system if infection confirmed.",
                    ]
                  : totalWarnings > 0
                    ? [
                        "Review warnings and determine if they are false positives.",
                        "Cross-reference with system changes and package updates.",
                        "Run a full scan with verbose output for more details.",
                      ]
                    : availableTools > 0
                      ? ["System appears clean. Schedule regular scans."]
                      : [
                          "Install rkhunter: sudo apt install rkhunter",
                          "Install chkrootkit: sudo apt install chkrootkit",
                        ],
            };

            logChange(
              createChangeEntry({
                tool: "integrity",
                action: "Combined rootkit scan",
                target: "system",
                after: `Risk: ${overallRisk}, Infected: ${totalInfected}, Warnings: ${totalWarnings}`,
                dryRun: false,
                success: true,
              })
            );

            return { content: [formatToolOutput(output)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── file_integrity ─────────────────────────────────────────────────
        case "file_integrity": {
          const { paths, baseline_path, create_baseline } = params;
          try {
            if (!paths) {
              return {
                content: [createErrorContent("No file paths provided")],
                isError: true,
              };
            }

            const filePaths = (
              Array.isArray(paths) ? paths : paths.split(",")
            )
              .map((p) => p.trim())
              .filter((p) => p.length > 0);

            if (filePaths.length === 0) {
              return {
                content: [createErrorContent("No file paths provided")],
                isError: true,
              };
            }

            // TOOL-016: Validate each file path against traversal
            for (const fp of filePaths) {
              validateToolPath(fp, ALLOWED_IDS_DIRS, "File integrity path");
            }
            sanitizeArgs(filePaths);

            const hashResult = await executeCommand({
              command: "sha256sum",
              args: filePaths,
              toolName: "integrity",
              timeout: getToolTimeout("integrity"),
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

            const currentHashes: Array<{ hash: string; file: string }> = [];
            for (const line of hashResult.stdout.split("\n")) {
              const trimmed = line.trim();
              if (!trimmed) continue;
              const parts = trimmed.split(/\s+/);
              if (parts.length >= 2) {
                currentHashes.push({
                  hash: parts[0],
                  file: parts.slice(1).join(" "),
                });
              }
            }

            // Create baseline mode
            if (create_baseline) {
              const baselineOutput =
                baseline_path ?? join(homedir(), ".defense-mcp", "file-integrity-baseline.sha256");
              // TOOL-016: Validate baseline output path
              validateToolPath(
                baselineOutput,
                ALLOWED_IDS_DIRS,
                "Baseline output path"
              );

              const writeResult = await executeCommand({
                command: "sudo",
                args: ["tee", baselineOutput],
                stdin: hashResult.stdout,
                toolName: "integrity",
              });

              const success = writeResult.exitCode === 0;

              const entry = createChangeEntry({
                tool: "integrity",
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
              // TOOL-016: Validate baseline path for traversal
              validateToolPath(
                baseline_path,
                ALLOWED_IDS_DIRS,
                "Baseline path"
              );

              const baselineResult = await executeCommand({
                command: "cat",
                args: [baseline_path],
                toolName: "integrity",
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

              const baselineHashes = new Map<string, string>();
              for (const line of baselineResult.stdout.split("\n")) {
                const trimmed = line.trim();
                if (!trimmed) continue;
                const parts = trimmed.split(/\s+/);
                if (parts.length >= 2) {
                  baselineHashes.set(parts.slice(1).join(" "), parts[0]);
                }
              }

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
                tool: "integrity",
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

        // ── baseline_create ────────────────────────────────────────────────
        case "baseline_create": {
          const { directories, name, dryRun } = params;
          try {
            ensureBaselineDir();

            if (dryRun) {
              return {
                content: [
                  formatToolOutput({
                    dryRun: true,
                    directories,
                    baselineName: name,
                    storagePath: join(BASELINE_DIR, `${name}.json`),
                  }),
                ],
              };
            }

            const files: BaselineEntry[] = [];
            for (const dir of directories) {
              if (!existsSync(dir)) continue;

              const findResult = await executeCommand({
                toolName: "integrity",
                command: "find",
                args: [
                  dir,
                  "-maxdepth",
                  "3",
                  "-type",
                  "f",
                  "-not",
                  "-path",
                  "*/proc/*",
                  "-not",
                  "-path",
                  "*/sys/*",
                ],
                timeout: 30000,
              });

              if (findResult.stdout.trim()) {
                const paths = findResult.stdout
                  .trim()
                  .split("\n")
                  .filter(Boolean)
                  .slice(0, 5000);
                for (const p of paths) {
                  try {
                    const stat = statSync(p);
                    files.push({
                      path: p,
                      hash: hashFile(p),
                      size: stat.size,
                      mtime: stat.mtime.toISOString(),
                    });
                  } catch {
                    /* skip unreadable */
                  }
                }
              }
            }

            // Capture sysctl state
            const sysctlState: Record<string, string> = {};
            const sysctlResult = await executeCommand({
              toolName: "integrity",
              command: "sysctl",
              args: ["-a"],
              timeout: 10000,
            });
            if (sysctlResult.exitCode === 0 && sysctlResult.stdout.trim()) {
              for (const line of sysctlResult.stdout.split("\n")) {
                const idx = line.indexOf("=");
                if (idx > 0) {
                  sysctlState[line.substring(0, idx).trim()] =
                    line.substring(idx + 1).trim();
                }
              }
            }

            // Fallback: read key sysctl values from /proc/sys/
            if (Object.keys(sysctlState).length === 0) {
              const procSysKeys: [string, string][] = [
                ["net.ipv4.ip_forward", "/proc/sys/net/ipv4/ip_forward"],
                [
                  "net.ipv4.conf.all.accept_redirects",
                  "/proc/sys/net/ipv4/conf/all/accept_redirects",
                ],
                [
                  "net.ipv4.conf.all.send_redirects",
                  "/proc/sys/net/ipv4/conf/all/send_redirects",
                ],
                [
                  "net.ipv4.conf.all.accept_source_route",
                  "/proc/sys/net/ipv4/conf/all/accept_source_route",
                ],
                [
                  "net.ipv4.conf.all.log_martians",
                  "/proc/sys/net/ipv4/conf/all/log_martians",
                ],
                [
                  "net.ipv4.icmp_echo_ignore_broadcasts",
                  "/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts",
                ],
                [
                  "net.ipv4.tcp_syncookies",
                  "/proc/sys/net/ipv4/tcp_syncookies",
                ],
                [
                  "net.ipv6.conf.all.accept_redirects",
                  "/proc/sys/net/ipv6/conf/all/accept_redirects",
                ],
                [
                  "net.ipv6.conf.all.accept_source_route",
                  "/proc/sys/net/ipv6/conf/all/accept_source_route",
                ],
                [
                  "kernel.randomize_va_space",
                  "/proc/sys/kernel/randomize_va_space",
                ],
                [
                  "kernel.dmesg_restrict",
                  "/proc/sys/kernel/dmesg_restrict",
                ],
                ["kernel.kptr_restrict", "/proc/sys/kernel/kptr_restrict"],
                [
                  "kernel.yama.ptrace_scope",
                  "/proc/sys/kernel/yama/ptrace_scope",
                ],
                ["kernel.sysrq", "/proc/sys/kernel/sysrq"],
                [
                  "fs.protected_hardlinks",
                  "/proc/sys/fs/protected_hardlinks",
                ],
                [
                  "fs.protected_symlinks",
                  "/proc/sys/fs/protected_symlinks",
                ],
                ["fs.suid_dumpable", "/proc/sys/fs/suid_dumpable"],
              ];
              for (const [key, procPath] of procSysKeys) {
                try {
                  if (existsSync(procPath)) {
                    const val = readFileSync(procPath, "utf-8").trim();
                    sysctlState[key] = val;
                  }
                } catch {
                  /* skip unreadable */
                }
              }
              if (Object.keys(sysctlState).length > 0) {
                console.error(
                  `[integrity] sysctl binary unavailable; read ${Object.keys(sysctlState).length} keys from /proc/sys/`
                );
              } else {
                console.error(
                  "[integrity] Warning: could not capture any sysctl state (sysctl binary unavailable and /proc/sys/ read failed)"
                );
              }
            }

            // Capture service states
            const services: Record<string, string> = {};
            const svcResult = await executeCommand({
              toolName: "integrity",
              command: "systemctl",
              args: [
                "list-units",
                "--type=service",
                "--no-pager",
                "--plain",
                "--no-legend",
              ],
              timeout: 10000,
            });
            if (svcResult.exitCode === 0) {
              for (const line of svcResult.stdout.split("\n")) {
                const parts = line.trim().split(/\s+/);
                if (parts.length >= 3) {
                  services[parts[0]] = parts[2];
                }
              }
            }

            const baseline: BaselineData = {
              id: name,
              timestamp: new Date().toISOString(),
              directories,
              files,
              sysctlState,
              services,
            };

            const outPath = join(BASELINE_DIR, `${name}.json`);
            // TOOL-024: Validate baseline output path and use secure write
            validateBaselinePath(outPath);
            secureWriteFileSync(outPath, JSON.stringify(baseline, null, 2), "utf-8");

            return {
              content: [
                formatToolOutput({
                  baselineName: name,
                  timestamp: baseline.timestamp,
                  filesHashed: files.length,
                  sysctlKeys: Object.keys(sysctlState).length,
                  servicesTracked: Object.keys(services).length,
                  savedTo: outPath,
                }),
              ],
            };
          } catch (err) {
            return {
              content: [
                createErrorContent(
                  `Baseline creation failed: ${err instanceof Error ? err.message : String(err)}`
                ),
              ],
              isError: true,
            };
          }
        }

        // ── baseline_compare ───────────────────────────────────────────────
        case "baseline_compare": {
          const { name } = params;
          try {
            const baselinePath = join(BASELINE_DIR, `${name}.json`);
            // TOOL-024: Validate baseline path before reading
            validateBaselinePath(baselinePath);
            if (!existsSync(baselinePath)) {
              return {
                content: [
                  createErrorContent(
                    `Baseline '${name}' not found at ${baselinePath}`
                  ),
                ],
                isError: true,
              };
            }

            const baseline: BaselineData = JSON.parse(
              readFileSync(baselinePath, "utf-8")
            );

            const fileChanges: {
              path: string;
              type: string;
              detail: string;
            }[] = [];
            const sysctlChanges: {
              key: string;
              baseline: string;
              current: string;
            }[] = [];
            const serviceChanges: {
              service: string;
              baseline: string;
              current: string;
            }[] = [];

            // Compare files
            for (const entry of baseline.files.slice(0, 2000)) {
              if (!existsSync(entry.path)) {
                fileChanges.push({
                  path: entry.path,
                  type: "deleted",
                  detail: "File no longer exists",
                });
                continue;
              }
              const currentHash = hashFile(entry.path);
              if (currentHash !== entry.hash && currentHash !== "unreadable") {
                fileChanges.push({
                  path: entry.path,
                  type: "modified",
                  detail: `hash changed: ${entry.hash.slice(0, 12)}... → ${currentHash.slice(0, 12)}...`,
                });
              }
            }

            // Compare sysctl
            const sysctlResult = await executeCommand({
              toolName: "integrity",
              command: "sysctl",
              args: ["-a"],
              timeout: 10000,
            });
            if (sysctlResult.exitCode === 0) {
              const currentSysctl: Record<string, string> = {};
              for (const line of sysctlResult.stdout.split("\n")) {
                const idx = line.indexOf("=");
                if (idx > 0) {
                  currentSysctl[line.substring(0, idx).trim()] =
                    line.substring(idx + 1).trim();
                }
              }
              for (const [key, val] of Object.entries(baseline.sysctlState)) {
                const current = currentSysctl[key];
                if (current !== undefined && current !== val) {
                  sysctlChanges.push({ key, baseline: val, current });
                }
              }
            }

            // Compare services
            const svcResult = await executeCommand({
              toolName: "integrity",
              command: "systemctl",
              args: [
                "list-units",
                "--type=service",
                "--no-pager",
                "--plain",
                "--no-legend",
              ],
              timeout: 10000,
            });
            if (svcResult.exitCode === 0) {
              const currentServices: Record<string, string> = {};
              for (const line of svcResult.stdout.split("\n")) {
                const parts = line.trim().split(/\s+/);
                if (parts.length >= 3) {
                  currentServices[parts[0]] = parts[2];
                }
              }
              for (const [svc, state] of Object.entries(baseline.services)) {
                const current = currentServices[svc];
                if (current !== undefined && current !== state) {
                  serviceChanges.push({
                    service: svc,
                    baseline: state,
                    current,
                  });
                }
              }
            }

            const totalDrifts =
              fileChanges.length +
              sysctlChanges.length +
              serviceChanges.length;

            return {
              content: [
                formatToolOutput({
                  baselineName: name,
                  baselineTimestamp: baseline.timestamp,
                  comparedAt: new Date().toISOString(),
                  totalDrifts,
                  fileChanges: fileChanges.slice(0, 50),
                  sysctlChanges: sysctlChanges.slice(0, 50),
                  serviceChanges: serviceChanges.slice(0, 50),
                  status:
                    totalDrifts === 0 ? "NO_DRIFT" : "DRIFT_DETECTED",
                }),
              ],
            };
          } catch (err) {
            return {
              content: [
                createErrorContent(
                  `Baseline comparison failed: ${err instanceof Error ? err.message : String(err)}`
                ),
              ],
              isError: true,
            };
          }
        }

        // ── baseline_list ──────────────────────────────────────────────────
        case "baseline_list": {
          try {
            ensureBaselineDir();

            const files = readdirSync(BASELINE_DIR).filter(
              (f) => f.endsWith(".json") && f !== "manifest.json"
            );

            const baselines = files.map((f) => {
              try {
                const data: BaselineData = JSON.parse(
                  readFileSync(join(BASELINE_DIR, f), "utf-8")
                );
                return {
                  name: data.id,
                  timestamp: data.timestamp,
                  filesTracked: data.files.length,
                  sysctlKeys: Object.keys(data.sysctlState).length,
                  services: Object.keys(data.services).length,
                };
              } catch {
                return {
                  name: f,
                  timestamp: "unknown",
                  filesTracked: 0,
                  sysctlKeys: 0,
                  services: 0,
                };
              }
            });

            return {
              content: [
                formatToolOutput({
                  baselineDir: BASELINE_DIR,
                  totalBaselines: baselines.length,
                  baselines,
                }),
              ],
            };
          } catch (err) {
            return {
              content: [
                createErrorContent(
                  `Drift listing failed: ${err instanceof Error ? err.message : String(err)}`
                ),
              ],
              isError: true,
            };
          }
        }

        default:
          return {
            content: [createErrorContent(`Unknown action: ${action}`)],
            isError: true,
          };
      }
    }
  );
}
