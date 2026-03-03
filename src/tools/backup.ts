/**
 * Backup and restore tools for Kali Defense MCP Server.
 *
 * Registers 5 tools: backup_config_files, backup_system_state,
 * backup_restore, backup_verify, backup_list.
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
  backupFile,
  restoreFile,
} from "../core/changelog.js";
import { validateFilePath } from "../core/sanitizer.js";
import { existsSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { homedir } from "node:os";

// ── Default critical configuration files ─────────────────────────────────

const DEFAULT_CRITICAL_FILES = [
  "/etc/passwd",
  "/etc/shadow",
  "/etc/group",
  "/etc/sudoers",
  "/etc/ssh/sshd_config",
  "/etc/fstab",
  "/etc/hosts",
  "/etc/sysctl.conf",
  "/etc/iptables/rules.v4",
];

// ── Registration entry point ───────────────────────────────────────────────

export function registerBackupTools(server: McpServer): void {
  // ── 1. backup_config_files ─────────────────────────────────────────────

  server.tool(
    "backup_config_files",
    "Backup critical configuration files to the backup directory",
    {
      files: z
        .string()
        .optional()
        .describe(
          "Comma-separated file paths, or omit for default critical files"
        ),
      tag: z
        .string()
        .optional()
        .describe("Tag for this backup set"),
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview the backup without executing (defaults to KALI_DEFENSE_DRY_RUN env var)"),
    },
    async ({ files, tag, dry_run }) => {
      try {
        const fileList = files
          ? files
              .split(",")
              .map((f) => f.trim())
              .filter((f) => f.length > 0)
          : DEFAULT_CRITICAL_FILES;

        if (dry_run ?? getConfig().dryRun) {
          const entry = createChangeEntry({
            tool: "backup_config_files",
            action: `[DRY-RUN] Backup config files${tag ? ` (tag: ${tag})` : ""}`,
            target: fileList.join(", "),
            after: `Would backup ${fileList.length} files`,
            dryRun: true,
            success: true,
          });
          logChange(entry);

          return {
            content: [
              createTextContent(
                `[DRY-RUN] Would backup ${fileList.length} files:\n${fileList.map((f) => `  - ${f}`).join("\n")}`
              ),
            ],
          };
        }

        const results: Array<{
          file: string;
          backupPath?: string;
          error?: string;
        }> = [];

        for (const filePath of fileList) {
          try {
            const bkPath = backupFile(filePath);
            results.push({ file: filePath, backupPath: bkPath });
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            results.push({ file: filePath, error: msg });
          }
        }

        const succeeded = results.filter((r) => r.backupPath);
        const failed = results.filter((r) => r.error);

        const entry = createChangeEntry({
          tool: "backup_config_files",
          action: `Backup config files${tag ? ` (tag: ${tag})` : ""}`,
          target: `${succeeded.length}/${fileList.length} files`,
          after: JSON.stringify(results),
          dryRun: false,
          success: failed.length === 0,
          error:
            failed.length > 0
              ? `${failed.length} file(s) failed to backup`
              : undefined,
        });
        logChange(entry);

        const output = {
          tag: tag ?? null,
          totalFiles: fileList.length,
          succeeded: succeeded.length,
          failed: failed.length,
          results,
        };

        return { content: [formatToolOutput(output)] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 2. backup_system_state ─────────────────────────────────────────────

  server.tool(
    "backup_system_state",
    "Capture a comprehensive system state snapshot (packages, services, network, firewall, users)",
    {
      output_dir: z
        .string()
        .optional()
        .describe(
          "Directory to save snapshot files (defaults to backup dir)"
        ),
      include_packages: z
        .boolean()
        .optional()
        .default(true)
        .describe("Include installed packages list (default: true)"),
      include_services: z
        .boolean()
        .optional()
        .default(true)
        .describe("Include service states (default: true)"),
      include_network: z
        .boolean()
        .optional()
        .default(true)
        .describe("Include network configuration (default: true)"),
      include_firewall: z
        .boolean()
        .optional()
        .default(true)
        .describe("Include firewall rules (default: true)"),
      include_users: z
        .boolean()
        .optional()
        .default(true)
        .describe("Include user/group information (default: true)"),
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview the commands without executing (defaults to KALI_DEFENSE_DRY_RUN env var)"),
    },
    async ({
      output_dir,
      include_packages,
      include_services,
      include_network,
      include_firewall,
      include_users,
      dry_run,
    }) => {
      try {
        const config = getConfig();
        const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
        const snapshotDir = output_dir ?? `${config.backupDir}/snapshot-${timestamp}`;

        const captureSteps: Array<{
          name: string;
          enabled: boolean;
          commands: Array<{ label: string; cmd: string; args: string[] }>;
        }> = [
          {
            name: "packages",
            enabled: include_packages,
            commands: [
              {
                label: "dpkg-selections",
                cmd: "dpkg",
                args: ["--get-selections"],
              },
            ],
          },
          {
            name: "services",
            enabled: include_services,
            commands: [
              {
                label: "systemctl-units",
                cmd: "systemctl",
                args: ["list-unit-files", "--type=service", "--no-pager"],
              },
            ],
          },
          {
            name: "network",
            enabled: include_network,
            commands: [
              { label: "ip-addr", cmd: "ip", args: ["addr", "show"] },
              { label: "ip-route", cmd: "ip", args: ["route", "show"] },
              { label: "ss-listening", cmd: "ss", args: ["-tulnp"] },
            ],
          },
          {
            name: "firewall",
            enabled: include_firewall,
            commands: [
              {
                label: "iptables-save",
                cmd: "sudo",
                args: ["iptables-save"],
              },
              {
                label: "ufw-status",
                cmd: "sudo",
                args: ["ufw", "status", "verbose"],
              },
            ],
          },
          {
            name: "users",
            enabled: include_users,
            commands: [
              { label: "passwd", cmd: "cat", args: ["/etc/passwd"] },
              { label: "group", cmd: "cat", args: ["/etc/group"] },
              { label: "lastlog", cmd: "lastlog", args: [] },
            ],
          },
        ];

        const enabledSteps = captureSteps.filter((s) => s.enabled);
        const allCommands = enabledSteps.flatMap((s) =>
          s.commands.map((c) => `${c.cmd} ${c.args.join(" ")}`)
        );

        if (dry_run ?? getConfig().dryRun) {
          const entry = createChangeEntry({
            tool: "backup_system_state",
            action: "[DRY-RUN] Capture system state snapshot",
            target: snapshotDir,
            after: `Would capture ${enabledSteps.length} categories`,
            dryRun: true,
            success: true,
          });
          logChange(entry);

          return {
            content: [
              createTextContent(
                `[DRY-RUN] Would capture system state to: ${snapshotDir}\n\n` +
                  `Categories: ${enabledSteps.map((s) => s.name).join(", ")}\n\n` +
                  `Commands:\n${allCommands.map((c) => `  ${c}`).join("\n")}`
              ),
            ],
          };
        }

        // Create snapshot directory
        await executeCommand({
          command: "mkdir",
          args: ["-p", snapshotDir],
          toolName: "backup_system_state",
        });

        const results: Record<
          string,
          Array<{ label: string; success: boolean; file?: string; error?: string }>
        > = {};

        for (const step of enabledSteps) {
          results[step.name] = [];

          for (const cmd of step.commands) {
            const outputFile = `${snapshotDir}/${step.name}-${cmd.label}.txt`;

            const result = await executeCommand({
              command: cmd.cmd,
              args: cmd.args,
              toolName: "backup_system_state",
              timeout: getToolTimeout("backup_system_state"),
            });

            if (result.stdout) {
              // Write output to file using tee
              await executeCommand({
                command: "sudo",
                args: ["tee", outputFile],
                stdin: result.stdout,
                toolName: "backup_system_state",
              });

              results[step.name].push({
                label: cmd.label,
                success: true,
                file: outputFile,
              });
            } else {
              results[step.name].push({
                label: cmd.label,
                success: false,
                error: result.stderr || "No output",
              });
            }
          }
        }

        const entry = createChangeEntry({
          tool: "backup_system_state",
          action: "Capture system state snapshot",
          target: snapshotDir,
          after: JSON.stringify(
            Object.fromEntries(
              Object.entries(results).map(([k, v]) => [
                k,
                v.filter((r) => r.success).length + "/" + v.length,
              ])
            )
          ),
          dryRun: false,
          success: true,
        });
        logChange(entry);

        const output = {
          snapshotDir,
          timestamp,
          categories: results,
        };

        return { content: [formatToolOutput(output)] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 3. backup_restore ──────────────────────────────────────────────────

  server.tool(
    "backup_restore",
    "Restore a file from backup to its original location",
    {
      backup_path: z
        .string()
        .describe("Path to the backup file"),
      original_path: z
        .string()
        .describe("Original file path to restore to"),
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview the restore without executing (defaults to KALI_DEFENSE_DRY_RUN env var)"),
    },
    async ({ backup_path, original_path, dry_run }) => {
      try {
        const validatedBackup = validateFilePath(backup_path);
        const validatedOriginal = validateFilePath(original_path);

        const fullCmd = `cp ${validatedBackup} ${validatedOriginal}`;
        const rollbackCmd = `Backup of current file created before restore`;

        if (dry_run ?? getConfig().dryRun) {
          const entry = createChangeEntry({
            tool: "backup_restore",
            action: "[DRY-RUN] Restore file from backup",
            target: validatedOriginal,
            before: validatedOriginal,
            after: `Would restore from ${validatedBackup}`,
            dryRun: true,
            success: true,
          });
          logChange(entry);

          return {
            content: [
              createTextContent(
                `[DRY-RUN] Would execute:\n  ${fullCmd}\n\n` +
                  `Source backup: ${validatedBackup}\n` +
                  `Restore to: ${validatedOriginal}\n\n` +
                  `A backup of the current file will be created before overwriting.`
              ),
            ],
          };
        }

        // Backup the current file before overwriting
        let currentBackupPath: string | undefined;
        try {
          currentBackupPath = backupFile(validatedOriginal);
        } catch {
          // File may not exist yet, that's fine
        }

        restoreFile(validatedBackup, validatedOriginal);

        const entry = createChangeEntry({
          tool: "backup_restore",
          action: "Restore file from backup",
          target: validatedOriginal,
          before: currentBackupPath ?? "none",
          after: `Restored from ${validatedBackup}`,
          backupPath: currentBackupPath,
          dryRun: false,
          success: true,
          rollbackCommand: currentBackupPath
            ? `cp ${currentBackupPath} ${validatedOriginal}`
            : undefined,
        });
        logChange(entry);

        return {
          content: [
            createTextContent(
              `File restored successfully.\n` +
                `Source: ${validatedBackup}\n` +
                `Destination: ${validatedOriginal}\n` +
                (currentBackupPath
                  ? `Previous file backed up to: ${currentBackupPath}`
                  : "No previous file existed.")
            ),
          ],
        };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 4. backup_verify ───────────────────────────────────────────────────

  server.tool(
    "backup_verify",
    "Verify backup file integrity using SHA256 checksums",
    {
      backup_path: z
        .string()
        .optional()
        .describe("Specific backup file to verify, or omit for all backups"),
      check_integrity: z
        .boolean()
        .optional()
        .default(true)
        .describe("Compute and verify SHA256 checksums against manifest (default: true)"),
    },
    async ({ backup_path, check_integrity }) => {
      try {
        const config = getConfig();

        // Load backup manifest for hash comparison if available
        const manifestPath = join(homedir(), ".kali-mcp-backups", "manifest.json");
        let manifestHashes: Map<string, string> | null = null;
        if (check_integrity) {
          try {
            if (existsSync(manifestPath)) {
              const raw = JSON.parse(readFileSync(manifestPath, "utf-8"));
              if (raw && Array.isArray(raw.backups)) {
                manifestHashes = new Map<string, string>();
                for (const entry of raw.backups) {
                  if (entry.backupPath && entry.sha256) {
                    manifestHashes.set(entry.backupPath, entry.sha256);
                  }
                }
              }
            }
          } catch { /* manifest unreadable */ }
        }

        if (backup_path) {
          // Verify a specific backup
          const statResult = await executeCommand({
            command: "stat",
            args: [backup_path],
            toolName: "backup_verify",
            timeout: getToolTimeout("backup_verify"),
          });

          if (statResult.exitCode !== 0) {
            return {
              content: [
                createErrorContent(
                  `Backup file not found: ${backup_path}\n${statResult.stderr}`
                ),
              ],
              isError: true,
            };
          }

          let sha256 = "";
          let integrity = "not_checked";
          if (check_integrity) {
            try {
              const content = readFileSync(backup_path);
              sha256 = createHash("sha256").update(content).digest("hex");
            } catch {
              const hashResult = await executeCommand({
                command: "sha256sum",
                args: [backup_path],
                toolName: "backup_verify",
                timeout: getToolTimeout("backup_verify"),
              });
              sha256 = hashResult.stdout.trim().split(/\s+/)[0] ?? "";
            }

            if (sha256 && manifestHashes) {
              const stored = manifestHashes.get(backup_path);
              if (stored) {
                integrity = stored === sha256 ? "verified" : "corrupted";
              } else {
                integrity = "no_baseline";
              }
            } else if (sha256) {
              integrity = "no_baseline";
            }
          }

          const output = {
            file: backup_path,
            exists: true,
            sha256: sha256 || undefined,
            integrity,
            stat: statResult.stdout,
          };

          return { content: [formatToolOutput(output)] };
        }

        // Verify all backups in backup directory
        const findResult = await executeCommand({
          command: "find",
          args: [config.backupDir, "-type", "f", "-printf", "%T@ %s %p\\n"],
          toolName: "backup_verify",
          timeout: getToolTimeout("backup_verify"),
        });

        if (findResult.exitCode !== 0) {
          return {
            content: [
              createErrorContent(
                `Cannot list backups: ${findResult.stderr}`
              ),
            ],
            isError: true,
          };
        }

        const backupEntries: Array<{
          path: string;
          size: number;
          modified: string;
          ageHours: number;
          sha256?: string;
          integrity?: string;
        }> = [];

        const fileLines = findResult.stdout
          .split("\n")
          .map((l) => l.trim())
          .filter((l) => l.length > 0);

        for (const line of fileLines) {
          const parts = line.split(/\s+/);
          const timestamp = parseFloat(parts[0]) || 0;
          const size = parseInt(parts[1], 10) || 0;
          const filePath = parts.slice(2).join(" ");

          const entry: {
            path: string;
            size: number;
            modified: string;
            ageHours: number;
            sha256?: string;
            integrity?: string;
          } = {
            path: filePath,
            size,
            modified: new Date(timestamp * 1000).toISOString(),
            ageHours: Math.round(
              (Date.now() - timestamp * 1000) / (1000 * 60 * 60)
            ),
          };

          if (check_integrity && filePath && !filePath.endsWith("manifest.json")) {
            try {
              const content = readFileSync(filePath);
              const hash = createHash("sha256").update(content).digest("hex");
              entry.sha256 = hash;

              if (manifestHashes) {
                const stored = manifestHashes.get(filePath);
                if (stored) {
                  entry.integrity = stored === hash ? "verified" : "corrupted";
                } else {
                  entry.integrity = "no_baseline";
                }
              } else {
                entry.integrity = "no_baseline";
              }
            } catch {
              entry.integrity = "unreadable";
            }
          }

          backupEntries.push(entry);
        }

        const verified = backupEntries.filter((b) => b.integrity === "verified").length;
        const corrupted = backupEntries.filter((b) => b.integrity === "corrupted").length;
        const noBaseline = backupEntries.filter((b) => b.integrity === "no_baseline").length;

        const output = {
          backupDir: config.backupDir,
          totalBackups: backupEntries.length,
          integrityChecked: check_integrity,
          summary: check_integrity ? { verified, corrupted, noBaseline } : undefined,
          backups: backupEntries,
        };

        return { content: [formatToolOutput(output)] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 5. backup_list ─────────────────────────────────────────────────────

  server.tool(
    "backup_list",
    "List all backup files with metadata",
    {
      filter: z
        .string()
        .optional()
        .describe("Filter by filename pattern (glob)"),
      sort_by: z
        .enum(["date", "name", "size"])
        .optional()
        .default("date")
        .describe("Sort order (default: date)"),
      limit: z
        .number()
        .optional()
        .default(50)
        .describe("Maximum number of results (default: 50)"),
    },
    async ({ filter, sort_by, limit }) => {
      try {
        const config = getConfig();
        const backupDir = config.backupDir;

        const args = [backupDir, "-type", "f"];

        if (filter) {
          args.push("-name", filter);
        }

        args.push("-printf", "%T@ %s %p\\n");

        const result = await executeCommand({
          command: "find",
          args,
          toolName: "backup_list",
          timeout: getToolTimeout("backup_list"),
        });

        if (result.exitCode !== 0) {
          return {
            content: [
              createErrorContent(
                `Cannot list backups: ${result.stderr}`
              ),
            ],
            isError: true,
          };
        }

        let files = result.stdout
          .split("\n")
          .map((l) => l.trim())
          .filter((l) => l.length > 0)
          .map((line) => {
            const parts = line.split(/\s+/);
            const timestamp = parseFloat(parts[0]) || 0;
            const size = parseInt(parts[1], 10) || 0;
            const filePath = parts.slice(2).join(" ");
            const name = filePath.split("/").pop() ?? filePath;
            return {
              name,
              path: filePath,
              size,
              sizeHuman: formatSize(size),
              modified: new Date(timestamp * 1000).toISOString(),
              timestampEpoch: timestamp,
            };
          });

        // Sort
        switch (sort_by) {
          case "date":
            files.sort((a, b) => b.timestampEpoch - a.timestampEpoch);
            break;
          case "name":
            files.sort((a, b) => a.name.localeCompare(b.name));
            break;
          case "size":
            files.sort((a, b) => b.size - a.size);
            break;
        }

        // Limit
        if (limit > 0) {
          files = files.slice(0, limit);
        }

        const output = {
          backupDir,
          totalFiles: files.length,
          sortedBy: sort_by,
          filter: filter ?? null,
          files,
        };

        return { content: [formatToolOutput(output)] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );
}

// ── Helper ─────────────────────────────────────────────────────────────────

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024)
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}
