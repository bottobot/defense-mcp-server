/**
 * Backup and restore tools for Kali Defense MCP Server.
 *
 * Registers 1 tool: backup (actions: config, state, restore, verify, list).
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
import { validateFilePath, validateToolPath } from "../core/sanitizer.js";
import { existsSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, resolve } from "node:path";
import { homedir } from "node:os";

// ── TOOL-026 remediation: allowed backup directories ───────────────────────
const ALLOWED_BACKUP_DIRS = ["/tmp", "/var/backups", "/home", "/root", "/opt", "/var/lib"];

/**
 * Validate a backup destination path:
 * 1. Reject `..` sequences
 * 2. Resolve and verify within allowed backup directories
 * 3. Validate the destination exists or can be created
 */
function validateBackupPath(inputPath: string): string {
  if (!inputPath || typeof inputPath !== "string") {
    throw new Error("Backup path must be a non-empty string");
  }

  if (inputPath.includes("..")) {
    throw new Error(`Backup path contains forbidden traversal sequence (..): '${inputPath}'`);
  }

  const resolved = resolve(inputPath);

  // Check it's within allowed directories or the config backupDir
  const configBackupDir = getConfig().backupDir;
  const allAllowed = [...ALLOWED_BACKUP_DIRS, configBackupDir];

  const isAllowed = allAllowed.some(
    (dir) => resolved === dir || resolved.startsWith(dir + "/")
  );

  if (!isAllowed) {
    throw new Error(
      `Backup path '${resolved}' is not within allowed directories: ${allAllowed.join(", ")}`
    );
  }

  return resolved;
}

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

// ── Helper ─────────────────────────────────────────────────────────────────

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024)
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

// ── Registration entry point ───────────────────────────────────────────────

export function registerBackupTools(server: McpServer): void {

  server.tool(
    "backup",
    "Backup management: backup config files, capture system state, restore from backup, verify integrity, or list backups.",
    {
      action: z.enum(["config", "state", "restore", "verify", "list"]).describe("Action: config=backup config files, state=system state snapshot, restore=restore from backup, verify=verify integrity, list=list backups"),
      // config params
      files: z.string().optional().describe("Comma-separated file paths, or omit for default critical files (config action)"),
      tag: z.string().optional().describe("Tag for this backup set (config action)"),
      // state params
      output_dir: z.string().optional().describe("Directory to save snapshot files (state action)"),
      include_packages: z.boolean().optional().default(true).describe("Include installed packages list (state action)"),
      include_services: z.boolean().optional().default(true).describe("Include service states (state action)"),
      include_network: z.boolean().optional().default(true).describe("Include network configuration (state action)"),
      include_firewall: z.boolean().optional().default(true).describe("Include firewall rules (state action)"),
      include_users: z.boolean().optional().default(true).describe("Include user/group information (state action)"),
      // restore params
      backup_path: z.string().optional().describe("Path to the backup file (restore/verify action)"),
      original_path: z.string().optional().describe("Original file path to restore to (restore action)"),
      // verify params
      check_integrity: z.boolean().optional().default(true).describe("Compute and verify SHA256 checksums (verify action)"),
      // list params
      filter: z.string().optional().describe("Filter by filename pattern (list action)"),
      sort_by: z.enum(["date", "name", "size"]).optional().default("date").describe("Sort order (list action)"),
      limit: z.number().optional().default(50).describe("Maximum number of results (list action)"),
      // shared
      dry_run: z.boolean().optional().describe("Preview without executing (defaults to KALI_DEFENSE_DRY_RUN env var)"),
    },
    async (params) => {
      const { action } = params;

      switch (action) {
        // ── config ──────────────────────────────────────────────────
        case "config": {
          const { files, tag, dry_run } = params;
          try {
            const fileList = files
              ? files.split(",").map((f) => f.trim()).filter((f) => f.length > 0)
              : DEFAULT_CRITICAL_FILES;

            if (dry_run ?? getConfig().dryRun) {
              logChange(createChangeEntry({
                tool: "backup",
                action: `[DRY-RUN] Backup config files${tag ? ` (tag: ${tag})` : ""}`,
                target: fileList.join(", "),
                after: `Would backup ${fileList.length} files`,
                dryRun: true,
                success: true,
              }));

              return {
                content: [createTextContent(`[DRY-RUN] Would backup ${fileList.length} files:\n${fileList.map((f) => `  - ${f}`).join("\n")}`)],
              };
            }

            const results: Array<{ file: string; backupPath?: string; error?: string }> = [];

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

            logChange(createChangeEntry({
              tool: "backup",
              action: `Backup config files${tag ? ` (tag: ${tag})` : ""}`,
              target: `${succeeded.length}/${fileList.length} files`,
              after: JSON.stringify(results),
              dryRun: false,
              success: failed.length === 0,
              error: failed.length > 0 ? `${failed.length} file(s) failed to backup` : undefined,
            }));

            return { content: [formatToolOutput({ tag: tag ?? null, totalFiles: fileList.length, succeeded: succeeded.length, failed: failed.length, results })] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── state ───────────────────────────────────────────────────
        case "state": {
          const { output_dir, include_packages, include_services, include_network, include_firewall, include_users, dry_run } = params;
          try {
            const config = getConfig();
            const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
            const snapshotDir = output_dir ?? `${config.backupDir}/snapshot-${timestamp}`;
            // TOOL-026: Validate snapshot output directory for traversal
            validateBackupPath(snapshotDir);

            const captureSteps: Array<{ name: string; enabled: boolean; commands: Array<{ label: string; cmd: string; args: string[] }> }> = [
              { name: "packages", enabled: include_packages, commands: [{ label: "dpkg-selections", cmd: "dpkg", args: ["--get-selections"] }] },
              { name: "services", enabled: include_services, commands: [{ label: "systemctl-units", cmd: "systemctl", args: ["list-unit-files", "--type=service", "--no-pager"] }] },
              { name: "network", enabled: include_network, commands: [{ label: "ip-addr", cmd: "ip", args: ["addr", "show"] }, { label: "ip-route", cmd: "ip", args: ["route", "show"] }, { label: "ss-listening", cmd: "ss", args: ["-tulnp"] }] },
              { name: "firewall", enabled: include_firewall, commands: [{ label: "iptables-save", cmd: "sudo", args: ["iptables-save"] }, { label: "ufw-status", cmd: "sudo", args: ["ufw", "status", "verbose"] }] },
              { name: "users", enabled: include_users, commands: [{ label: "passwd", cmd: "cat", args: ["/etc/passwd"] }, { label: "group", cmd: "cat", args: ["/etc/group"] }, { label: "lastlog", cmd: "lastlog", args: [] }] },
            ];

            const enabledSteps = captureSteps.filter((s) => s.enabled);
            const allCommands = enabledSteps.flatMap((s) => s.commands.map((c) => `${c.cmd} ${c.args.join(" ")}`));

            if (dry_run ?? getConfig().dryRun) {
              logChange(createChangeEntry({ tool: "backup", action: "[DRY-RUN] Capture system state snapshot", target: snapshotDir, after: `Would capture ${enabledSteps.length} categories`, dryRun: true, success: true }));

              return {
                content: [createTextContent(`[DRY-RUN] Would capture system state to: ${snapshotDir}\n\nCategories: ${enabledSteps.map((s) => s.name).join(", ")}\n\nCommands:\n${allCommands.map((c) => `  ${c}`).join("\n")}`)],
              };
            }

            await executeCommand({ command: "mkdir", args: ["-p", snapshotDir], toolName: "backup" });

            const results: Record<string, Array<{ label: string; success: boolean; file?: string; error?: string }>> = {};

            for (const step of enabledSteps) {
              results[step.name] = [];
              for (const cmd of step.commands) {
                const outputFile = `${snapshotDir}/${step.name}-${cmd.label}.txt`;
                const result = await executeCommand({ command: cmd.cmd, args: cmd.args, toolName: "backup", timeout: getToolTimeout("backup_system_state") });

                if (result.stdout) {
                  await executeCommand({ command: "sudo", args: ["tee", outputFile], stdin: result.stdout, toolName: "backup" });
                  results[step.name].push({ label: cmd.label, success: true, file: outputFile });
                } else {
                  results[step.name].push({ label: cmd.label, success: false, error: result.stderr || "No output" });
                }
              }
            }

            logChange(createChangeEntry({
              tool: "backup",
              action: "Capture system state snapshot",
              target: snapshotDir,
              after: JSON.stringify(Object.fromEntries(Object.entries(results).map(([k, v]) => [k, v.filter((r) => r.success).length + "/" + v.length]))),
              dryRun: false,
              success: true,
            }));

            return { content: [formatToolOutput({ snapshotDir, timestamp, categories: results })] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── restore ─────────────────────────────────────────────────
        case "restore": {
          const { backup_path, original_path, dry_run } = params;
          try {
            if (!backup_path) return { content: [createErrorContent("backup_path is required for restore action")], isError: true };
            if (!original_path) return { content: [createErrorContent("original_path is required for restore action")], isError: true };

            // TOOL-026: Validate backup paths for traversal
            validateBackupPath(backup_path);
            const validatedBackup = validateFilePath(backup_path);
            validateBackupPath(original_path);
            const validatedOriginal = validateFilePath(original_path);

            const fullCmd = `cp ${validatedBackup} ${validatedOriginal}`;

            if (dry_run ?? getConfig().dryRun) {
              logChange(createChangeEntry({ tool: "backup", action: "[DRY-RUN] Restore file from backup", target: validatedOriginal, before: validatedOriginal, after: `Would restore from ${validatedBackup}`, dryRun: true, success: true }));

              return {
                content: [createTextContent(`[DRY-RUN] Would execute:\n  ${fullCmd}\n\nSource backup: ${validatedBackup}\nRestore to: ${validatedOriginal}\n\nA backup of the current file will be created before overwriting.`)],
              };
            }

            let currentBackupPath: string | undefined;
            try { currentBackupPath = backupFile(validatedOriginal); } catch { /* File may not exist */ }

            restoreFile(validatedBackup, validatedOriginal);

            logChange(createChangeEntry({
              tool: "backup",
              action: "Restore file from backup",
              target: validatedOriginal,
              before: currentBackupPath ?? "none",
              after: `Restored from ${validatedBackup}`,
              backupPath: currentBackupPath,
              dryRun: false,
              success: true,
              rollbackCommand: currentBackupPath ? `cp ${currentBackupPath} ${validatedOriginal}` : undefined,
            }));

            return {
              content: [createTextContent(`File restored successfully.\nSource: ${validatedBackup}\nDestination: ${validatedOriginal}\n${currentBackupPath ? `Previous file backed up to: ${currentBackupPath}` : "No previous file existed."}`)],
            };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── verify ──────────────────────────────────────────────────
        case "verify": {
          const { backup_path, check_integrity } = params;
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
              const statResult = await executeCommand({ command: "stat", args: [backup_path], toolName: "backup", timeout: getToolTimeout("backup_verify") });

              if (statResult.exitCode !== 0) {
                return { content: [createErrorContent(`Backup file not found: ${backup_path}\n${statResult.stderr}`)], isError: true };
              }

              let sha256 = "";
              let integrity = "not_checked";
              if (check_integrity) {
                try {
                  const content = readFileSync(backup_path);
                  sha256 = createHash("sha256").update(content).digest("hex");
                } catch {
                  const hashResult = await executeCommand({ command: "sha256sum", args: [backup_path], toolName: "backup", timeout: getToolTimeout("backup_verify") });
                  sha256 = hashResult.stdout.trim().split(/\s+/)[0] ?? "";
                }

                if (sha256 && manifestHashes) {
                  const stored = manifestHashes.get(backup_path);
                  integrity = stored ? (stored === sha256 ? "verified" : "corrupted") : "no_baseline";
                } else if (sha256) {
                  integrity = "no_baseline";
                }
              }

              return { content: [formatToolOutput({ file: backup_path, exists: true, sha256: sha256 || undefined, integrity, stat: statResult.stdout })] };
            }

            // Verify all backups
            const findResult = await executeCommand({ command: "find", args: [config.backupDir, "-type", "f", "-printf", "%T@ %s %p\\n"], toolName: "backup", timeout: getToolTimeout("backup_verify") });

            if (findResult.exitCode !== 0) {
              return { content: [createErrorContent(`Cannot list backups: ${findResult.stderr}`)], isError: true };
            }

            const backupEntries: Array<{ path: string; size: number; modified: string; ageHours: number; sha256?: string; integrity?: string }> = [];

            const fileLines = findResult.stdout.split("\n").map((l) => l.trim()).filter((l) => l.length > 0);

            for (const line of fileLines) {
              const parts = line.split(/\s+/);
              const timestamp = parseFloat(parts[0]) || 0;
              const size = parseInt(parts[1], 10) || 0;
              const filePath = parts.slice(2).join(" ");

              const entry: { path: string; size: number; modified: string; ageHours: number; sha256?: string; integrity?: string } = {
                path: filePath, size, modified: new Date(timestamp * 1000).toISOString(), ageHours: Math.round((Date.now() - timestamp * 1000) / (1000 * 60 * 60)),
              };

              if (check_integrity && filePath && !filePath.endsWith("manifest.json")) {
                try {
                  const content = readFileSync(filePath);
                  const hash = createHash("sha256").update(content).digest("hex");
                  entry.sha256 = hash;
                  if (manifestHashes) {
                    const stored = manifestHashes.get(filePath);
                    entry.integrity = stored ? (stored === hash ? "verified" : "corrupted") : "no_baseline";
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

            return { content: [formatToolOutput({ backupDir: config.backupDir, totalBackups: backupEntries.length, integrityChecked: check_integrity, summary: check_integrity ? { verified, corrupted, noBaseline } : undefined, backups: backupEntries })] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── list ────────────────────────────────────────────────────
        case "list": {
          const { filter: filterPattern, sort_by, limit: maxLimit } = params;
          try {
            const config = getConfig();
            const backupDir = config.backupDir;

            const args = [backupDir, "-type", "f"];
            if (filterPattern) args.push("-name", filterPattern);
            args.push("-printf", "%T@ %s %p\\n");

            const result = await executeCommand({ command: "find", args, toolName: "backup", timeout: getToolTimeout("backup_list") });

            if (result.exitCode !== 0) {
              return { content: [createErrorContent(`Cannot list backups: ${result.stderr}`)], isError: true };
            }

            let files = result.stdout.split("\n").map((l) => l.trim()).filter((l) => l.length > 0).map((line) => {
              const parts = line.split(/\s+/);
              const timestamp = parseFloat(parts[0]) || 0;
              const size = parseInt(parts[1], 10) || 0;
              const filePath = parts.slice(2).join(" ");
              const name = filePath.split("/").pop() ?? filePath;
              return { name, path: filePath, size, sizeHuman: formatSize(size), modified: new Date(timestamp * 1000).toISOString(), timestampEpoch: timestamp };
            });

            switch (sort_by) {
              case "date": files.sort((a, b) => b.timestampEpoch - a.timestampEpoch); break;
              case "name": files.sort((a, b) => a.name.localeCompare(b.name)); break;
              case "size": files.sort((a, b) => b.size - a.size); break;
            }

            if (maxLimit > 0) files = files.slice(0, maxLimit);

            return { content: [formatToolOutput({ backupDir, totalFiles: files.length, sortedBy: sort_by, filter: filterPattern ?? null, files })] };
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
