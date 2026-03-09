/**
 * Incident response tools for Kali Defense MCP Server.
 *
 * Registers 2 tools:
 *   - incident_response (actions: collect, ioc_scan, timeline)
 *   - ir_forensics (actions: memory_dump, disk_image, network_capture_forensic, evidence_bag, chain_of_custody)
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeCommand } from "../core/executor.js";
import { getConfig } from "../core/config.js";
import {
  createTextContent,
  createErrorContent,
} from "../core/parsers.js";
import { spawnSafe } from "../core/spawn-safe.js";
import { secureWriteFileSync } from "../core/secure-fs.js";
import type { ChildProcess } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";

// ── Suspicious port list for IOC scanning ──────────────────────────────────

const SUSPICIOUS_PORTS = [4444, 5555, 6666, 8888, 9999, 1337, 31337];

const CRYPTO_MINER_NAMES = [
  "xmrig", "minerd", "minergate", "cpuminer", "cgminer",
  "bfgminer", "ethminer", "claymore", "nicehash", "kthreaddi",
];

// ── Forensics constants ────────────────────────────────────────────────────

const DEFAULT_FORENSICS_DIR = "/var/lib/kali-defense/forensics/";

// ── Forensics helper ───────────────────────────────────────────────────────

interface ForensicCommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

/**
 * Run a command via spawnSafe and collect output as a promise.
 * Similar to the helper in reporting.ts — returns error info instead of throwing.
 */
async function runForensicCommand(
  command: string,
  args: string[],
  timeoutMs = 30_000,
): Promise<ForensicCommandResult> {
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
    let resolved = false;

    const timer = setTimeout(() => {
      if (!resolved) {
        resolved = true;
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
      if (!resolved) {
        resolved = true;
        clearTimeout(timer);
        resolve({ stdout, stderr, exitCode: code ?? -1 });
      }
    });

    child.on("error", (err: Error) => {
      if (!resolved) {
        resolved = true;
        clearTimeout(timer);
        resolve({ stdout, stderr: err.message, exitCode: -1 });
      }
    });
  });
}

// ── Registration entry point ───────────────────────────────────────────────

export function registerIncidentResponseTools(server: McpServer): void {
  server.tool(
    "incident_response",
    "Incident response: collect volatile data (RFC 3227), scan for IOCs, or generate filesystem timelines.",
    {
      action: z.enum(["collect", "ioc_scan", "timeline"]).describe("Action: collect=volatile data collection, ioc_scan=scan for indicators of compromise, timeline=filesystem timeline"),
      // collect params
      output_dir: z.string().optional().default("/tmp/ir-collection").describe("Directory to save collected volatile data (collect action)"),
      // ioc_scan params
      check_type: z.enum(["processes", "connections", "persistence", "all"]).optional().default("all").describe("Type of IOC check to perform (ioc_scan action)"),
      // timeline params
      path: z.string().optional().default("/").describe("Root path to search for modified files (timeline action)"),
      hours: z.number().optional().default(24).describe("Look back this many hours for modifications (timeline action)"),
      exclude_paths: z.string().optional().default("/proc,/sys,/dev,/run").describe("Comma-separated paths to exclude from search (timeline action)"),
      file_types: z.enum(["all", "executables", "configs", "scripts"]).optional().default("all").describe("Type of files to include in the timeline (timeline action)"),
      // shared
      dry_run: z.boolean().optional().describe("Preview what would be done without executing (defaults to KALI_DEFENSE_DRY_RUN env var)"),
    },
    async (params) => {
      const { action } = params;

      switch (action) {
        // ── collect ──────────────────────────────────────────────────
        case "collect": {
          const { output_dir, dry_run } = params;
          try {
            const collectionSteps = [
              { name: "01-processes", command: "ps", args: ["auxwww"], desc: "Running processes" },
              { name: "02-network-connections", command: "ss", args: ["-tulnpea"], desc: "Network connections" },
              { name: "03-ip-addresses", command: "ip", args: ["addr", "show"], desc: "IP addresses" },
              { name: "04-routes", command: "ip", args: ["route", "show"], desc: "Routing table" },
              { name: "05-arp-cache", command: "arp", args: ["-an"], desc: "ARP cache" },
              { name: "06-logged-in-users-who", command: "who", args: [], desc: "Logged in users (who)" },
              { name: "07-logged-in-users-w", command: "w", args: [], desc: "Logged in users (w)" },
              { name: "08-recent-logins", command: "last", args: ["-n", "20"], desc: "Recent logins" },
              { name: "09-open-files", command: "lsof", args: ["-n"], desc: "Open files", maxLines: 500 },
              { name: "10-kernel-modules", command: "lsmod", args: [], desc: "Loaded kernel modules" },
              { name: "11-mounts", command: "mount", args: [], desc: "Mounted filesystems" },
              { name: "12-disk-usage", command: "df", args: ["-h"], desc: "Disk usage" },
              { name: "13-environment", command: "env", args: [], desc: "Environment variables" },
              { name: "14-uptime", command: "uptime", args: [], desc: "System uptime" },
              { name: "15-hostname", command: "hostname", args: [], desc: "Hostname" },
              { name: "16-utc-time", command: "date", args: ["-u"], desc: "Current UTC time" },
            ];

            if (dry_run ?? getConfig().dryRun) {
              const lines: string[] = [
                `[DRY-RUN] Volatile Data Collection Plan (RFC 3227)`,
                `Output directory: ${output_dir}/<timestamp>/`,
                ``,
                `The following data would be collected in order of volatility:`,
                ``,
              ];

              for (const step of collectionSteps) {
                lines.push(`  ${step.name}: ${step.desc}`);
                lines.push(`    Command: ${step.command} ${step.args.join(" ")}`);
              }

              lines.push(``);
              lines.push(`Total: ${collectionSteps.length} collection steps`);
              lines.push(`Set dry_run=false to execute collection.`);

              return { content: [createTextContent(lines.join("\n"))] };
            }

            // Create timestamped output directory
            const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
            const collectionDir = `${output_dir}/${timestamp}`;

            const mkdirResult = await executeCommand({
              command: "mkdir",
              args: ["-p", collectionDir],
              toolName: "incident_response",
              timeout: 5000,
            });

            if (mkdirResult.exitCode !== 0) {
              return {
                content: [
                  createErrorContent(
                    `Failed to create output directory ${collectionDir}: ${mkdirResult.stderr}`
                  ),
                ],
                isError: true,
              };
            }

            const lines: string[] = [
              `=== Volatile Data Collection Report (RFC 3227) ===`,
              `Collection Directory: ${collectionDir}`,
              `Started: ${new Date().toISOString()}`,
              ``,
            ];

            let successCount = 0;
            let failCount = 0;

            for (const step of collectionSteps) {
              // Use pre-defined command and args directly — no shell string parsing
              const result = await executeCommand({
                command: step.command,
                args: step.args,
                toolName: "incident_response",
                timeout: 30000,
              });

              // Truncate output if maxLines is set (replaces shell piping to head)
              let stdout = result.stdout;
              if ('maxLines' in step && step.maxLines) {
                const allLines = stdout.split("\n");
                if (allLines.length > step.maxLines) {
                  stdout = allLines.slice(0, step.maxLines).join("\n");
                }
              }

              // Write output to file using tee
              const outputPath = `${collectionDir}/${step.name}.txt`;
              const outputContent = stdout + (result.stderr ? "\n" + result.stderr : "");
              await executeCommand({
                command: "tee",
                args: [outputPath],
                stdin: outputContent,
                toolName: "incident_response",
                timeout: 5000,
              });

              if (result.exitCode === 0) {
                // Get file size
                const sizeResult = await executeCommand({
                  command: "stat",
                  args: ["-c", "%s", `${collectionDir}/${step.name}.txt`],
                  toolName: "incident_response",
                  timeout: 5000,
                });
                const size = sizeResult.stdout.trim();
                lines.push(`  ✓ ${step.name}: ${step.desc} (${size} bytes)`);
                successCount++;
              } else {
                lines.push(`  ✗ ${step.name}: ${step.desc} [FAILED: ${result.stderr.trim()}]`);
                failCount++;
              }
            }

            lines.push(``);
            lines.push(`── Collection Summary ──`);
            lines.push(`Successful: ${successCount}/${collectionSteps.length}`);
            lines.push(`Failed: ${failCount}/${collectionSteps.length}`);
            lines.push(`Output: ${collectionDir}/`);
            lines.push(`Completed: ${new Date().toISOString()}`);

            return { content: [createTextContent(lines.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── ioc_scan ────────────────────────────────────────────────
        case "ioc_scan": {
          const { check_type } = params;
          try {
            const lines: string[] = [
              `=== Indicator of Compromise (IOC) Scan ===`,
              `Check Type: ${check_type}`,
              `Scan Time: ${new Date().toISOString()}`,
              ``,
            ];

            let totalFindings = 0;

            // ── Process IOCs ───────────────────────────────────────────────
            if (check_type === "all" || check_type === "processes") {
              lines.push(`── PROCESS IOCs ──`);

              const psResult = await executeCommand({
                command: "ps",
                args: ["aux"],
                toolName: "incident_response",
                timeout: 15000,
              });

              const psLines = psResult.stdout.split("\n").filter((l) => l.trim());

              const suspiciousPaths = ["/tmp/", "/dev/shm/", "/var/tmp/"];
              const tmpProcesses = psLines.filter((line) =>
                suspiciousPaths.some((p) => line.includes(p))
              );

              if (tmpProcesses.length > 0) {
                lines.push(`  [HIGH] Processes running from suspicious paths:`);
                for (const proc of tmpProcesses) {
                  lines.push(`    ${proc.trim()}`);
                }
                totalFindings += tmpProcesses.length;
              }

              const deletedResult = await executeCommand({
                command: "ls",
                args: ["-la", "/proc/self/exe"],
                toolName: "incident_response",
                timeout: 15000,
              });

              // Use find to locate deleted exe symlinks instead of globbing with shell
              const deletedFindResult = await executeCommand({
                command: "find",
                args: ["/proc", "-maxdepth", "2", "-name", "exe", "-type", "l"],
                toolName: "incident_response",
                timeout: 15000,
              });

              // Filter for "deleted" in TypeScript by checking each symlink
              const exeLinks = deletedFindResult.stdout.split("\n").filter((l) => l.trim());
              const deletedChecks: string[] = [];
              for (const link of exeLinks.slice(0, 50)) {
                const lsResult = await executeCommand({
                  command: "ls",
                  args: ["-la", link],
                  toolName: "incident_response",
                  timeout: 2000,
                });
                if (lsResult.exitCode === 0 && lsResult.stdout.includes("deleted")) {
                  deletedChecks.push(lsResult.stdout.trim());
                }
              }

              const deletedProcs = deletedChecks.slice(0, 20);
              if (deletedProcs.length > 0) {
                lines.push(`  [HIGH] Processes with deleted executables:`);
                for (const proc of deletedProcs) {
                  lines.push(`    ${proc.trim()}`);
                }
                totalFindings += deletedProcs.length;
              }

              const minerProcs = psLines.filter((line) =>
                CRYPTO_MINER_NAMES.some((name) =>
                  line.toLowerCase().includes(name)
                )
              );

              if (minerProcs.length > 0) {
                lines.push(`  [CRITICAL] Potential crypto mining processes:`);
                for (const proc of minerProcs) {
                  lines.push(`    ${proc.trim()}`);
                }
                totalFindings += minerProcs.length;
              }

              if (
                tmpProcesses.length === 0 &&
                deletedProcs.length === 0 &&
                minerProcs.length === 0
              ) {
                lines.push(`  No suspicious processes detected.`);
              }
              lines.push(``);
            }

            // ── Connection IOCs ────────────────────────────────────────────
            if (check_type === "all" || check_type === "connections") {
              lines.push(`── CONNECTION IOCs ──`);

              const ssResult = await executeCommand({
                command: "ss",
                args: ["-tulnpea"],
                toolName: "incident_response",
                timeout: 15000,
              });

              const ssLines = ssResult.stdout.split("\n").filter((l) => l.trim());

              const suspiciousPortConns = ssLines.filter((line) =>
                SUSPICIOUS_PORTS.some(
                  (port) =>
                    line.includes(`:${port} `) || line.includes(`:${port}\t`)
                )
              );

              if (suspiciousPortConns.length > 0) {
                lines.push(`  [HIGH] Connections on suspicious ports (${SUSPICIOUS_PORTS.join(", ")}):`);
                for (const conn of suspiciousPortConns) {
                  lines.push(`    ${conn.trim()}`);
                }
                totalFindings += suspiciousPortConns.length;
              }

              const establishedHighPort = ssLines.filter((line) => {
                if (!line.includes("ESTAB")) return false;
                const peerMatch = line.match(/\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s*$/);
                if (peerMatch) {
                  const port = parseInt(peerMatch[2], 10);
                  return port > 1024 && port < 65535;
                }
                return false;
              });

              if (establishedHighPort.length > 0) {
                lines.push(
                  `  [MEDIUM] ESTABLISHED connections to high ports (review needed):`
                );
                for (const conn of establishedHighPort.slice(0, 20)) {
                  lines.push(`    ${conn.trim()}`);
                }
                if (establishedHighPort.length > 20) {
                  lines.push(
                    `    ... and ${establishedHighPort.length - 20} more`
                  );
                }
                totalFindings += establishedHighPort.length;
              }

              const ipCounts: Record<string, number> = {};
              for (const line of ssLines) {
                const peerMatch = line.match(
                  /\s+(\d+\.\d+\.\d+\.\d+):\d+\s*$/
                );
                if (
                  peerMatch &&
                  !peerMatch[1].startsWith("127.") &&
                  !peerMatch[1].startsWith("0.")
                ) {
                  ipCounts[peerMatch[1]] = (ipCounts[peerMatch[1]] ?? 0) + 1;
                }
              }

              const multiConns = Object.entries(ipCounts)
                .filter(([, count]) => count >= 5)
                .sort(([, a], [, b]) => b - a);

              if (multiConns.length > 0) {
                lines.push(
                  `  [MEDIUM] IPs with multiple connections (≥5):`
                );
                for (const [ip, count] of multiConns) {
                  lines.push(`    ${ip}: ${count} connections`);
                }
                totalFindings += multiConns.length;
              }

              if (
                suspiciousPortConns.length === 0 &&
                establishedHighPort.length === 0 &&
                multiConns.length === 0
              ) {
                lines.push(`  No suspicious connections detected.`);
              }
              lines.push(``);
            }

            // ── Persistence IOCs ───────────────────────────────────────────
            if (check_type === "all" || check_type === "persistence") {
              lines.push(`── PERSISTENCE IOCs ──`);

              lines.push(`  ─ Cron Jobs ─`);
              // Get user crontab
              const crontabResult = await executeCommand({
                command: "crontab",
                args: ["-l"],
                toolName: "incident_response",
                timeout: 10000,
              });

              // Get system crontab
              const cronTabFileResult = await executeCommand({
                command: "cat",
                args: ["/etc/crontab"],
                toolName: "incident_response",
                timeout: 5000,
              });

              // Find cron files in standard directories
              const cronDirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"];
              const cronFileEntries: string[] = [];
              for (const dir of cronDirs) {
                const lsResult = await executeCommand({
                  command: "find",
                  args: [dir, "-maxdepth", "1", "-type", "f"],
                  toolName: "incident_response",
                  timeout: 5000,
                });
                if (lsResult.exitCode === 0 && lsResult.stdout.trim()) {
                  for (const f of lsResult.stdout.trim().split("\n").filter((l) => l.trim())) {
                    const headResult = await executeCommand({
                      command: "head",
                      args: ["-5", f],
                      toolName: "incident_response",
                      timeout: 2000,
                    });
                    cronFileEntries.push(`FILE: ${f}\n${headResult.stdout.trim()}`);
                  }
                }
              }

              // Combine all cron data
              const cronParts: string[] = [];
              if (crontabResult.exitCode === 0 && crontabResult.stdout.trim()) {
                cronParts.push(crontabResult.stdout.trim());
              }
              for (const entry of cronFileEntries) {
                cronParts.push(entry);
              }
              const cronResult = {
                stdout: cronParts.join("\n---\n"),
                exitCode: 0,
              };

              if (cronResult.stdout.trim() && cronResult.stdout.trim() !== "---") {
                const cronEntries = cronResult.stdout
                  .split("---")
                  .filter((s) => s.trim());
                lines.push(`    Found ${cronEntries.length} cron source(s):`);
                for (const entry of cronEntries.slice(0, 10)) {
                  const trimmed = entry.trim().split("\n").slice(0, 3).join("\n      ");
                  lines.push(`      ${trimmed}`);
                }
                const suspiciousCron = cronResult.stdout
                  .split("\n")
                  .filter(
                    (l) =>
                      l.includes("/tmp/") ||
                      l.includes("/dev/shm/") ||
                      l.includes("curl ") ||
                      l.includes("wget ") ||
                      l.includes("base64")
                  );
                if (suspiciousCron.length > 0) {
                  lines.push(`    [HIGH] Suspicious cron entries:`);
                  for (const s of suspiciousCron) {
                    lines.push(`      ${s.trim()}`);
                  }
                  totalFindings += suspiciousCron.length;
                }
              } else {
                lines.push(`    No user cron entries found.`);
              }

              lines.push(`  ─ Systemd Services ─`);
              const systemdResult = await executeCommand({
                command: "find",
                args: [
                  "/etc/systemd/system",
                  "-maxdepth", "1",
                  "-name", "*.service",
                  "-mtime", "-7",
                  "-type", "f",
                ],
                toolName: "incident_response",
                timeout: 15000,
              });

              const recentServices = systemdResult.stdout
                .split("\n")
                .filter((l) => l.trim());
              if (recentServices.length > 0) {
                lines.push(
                  `    [MEDIUM] Recently created service files (last 7 days):`
                );
                for (const svc of recentServices) {
                  lines.push(`      ${svc.trim()}`);
                }
                totalFindings += recentServices.length;
              } else {
                lines.push(
                  `    No recently created systemd services found.`
                );
              }

              lines.push(`  ─ rc.local ─`);
              const rcCatResult = await executeCommand({
                command: "cat",
                args: ["/etc/rc.local"],
                toolName: "incident_response",
                timeout: 10000,
              });

              // Filter out comments, empty lines, and "exit 0" in TypeScript
              const rcContent = rcCatResult.exitCode === 0
                ? rcCatResult.stdout
                    .split("\n")
                    .filter((l) => l.trim() && !l.trim().startsWith("#") && l.trim() !== "exit 0")
                    .join("\n")
                    .trim()
                : "";

              if (rcContent) {
                lines.push(`    [MEDIUM] Non-standard rc.local entries:`);
                for (const entry of rcContent.split("\n")) {
                  lines.push(`      ${entry.trim()}`);
                }
                totalFindings += rcContent.split("\n").length;
              } else {
                lines.push(`    rc.local is clean or not present.`);
              }

              lines.push(`  ─ Shell Profile Checks ─`);
              // Search shell profiles for suspicious patterns
              const profileFiles = ["/root/.bashrc", "/root/.profile"];
              // Find user profile files
              const homeFind = await executeCommand({
                command: "find",
                args: ["/home", "-maxdepth", "2", "(", "-name", ".bashrc", "-o", "-name", ".profile", ")", "-type", "f"],
                toolName: "incident_response",
                timeout: 5000,
              });
              if (homeFind.exitCode === 0 && homeFind.stdout.trim()) {
                profileFiles.push(...homeFind.stdout.trim().split("\n").filter((l) => l.trim()));
              }

              const bashrcResult = await executeCommand({
                command: "grep",
                args: ["-rnH", "curl\\|wget\\|base64\\|/dev/tcp\\|nc -e\\|ncat\\|python.*-c.*import", ...profileFiles],
                toolName: "incident_response",
                timeout: 15000,
              });

              const suspiciousShell = bashrcResult.stdout
                .split("\n")
                .filter((l) => l.trim());
              if (suspiciousShell.length > 0) {
                lines.push(`    [HIGH] Suspicious shell profile entries:`);
                for (const entry of suspiciousShell) {
                  lines.push(`      ${entry.trim()}`);
                }
                totalFindings += suspiciousShell.length;
              } else {
                lines.push(`    No suspicious shell profile entries found.`);
              }

              lines.push(`  ─ SSH Authorized Keys ─`);
              const akResult = await executeCommand({
                command: "find",
                args: [
                  "/home", "/root",
                  "-name", "authorized_keys",
                  "-mtime", "-7",
                  "-type", "f",
                ],
                toolName: "incident_response",
                timeout: 15000,
              });

              const recentAK = akResult.stdout.split("\n").filter((l) => l.trim());
              if (recentAK.length > 0) {
                lines.push(
                  `    [MEDIUM] Recently modified authorized_keys (last 7 days):`
                );
                for (const ak of recentAK) {
                  lines.push(`      ${ak.trim()}`);
                }
                totalFindings += recentAK.length;
              } else {
                lines.push(
                  `    No recently modified authorized_keys files.`
                );
              }
              lines.push(``);
            }

            // ── Summary ────────────────────────────────────────────────────
            lines.push(`── IOC SCAN SUMMARY ──`);
            lines.push(`Total Findings: ${totalFindings}`);
            if (totalFindings === 0) {
              lines.push(`Status: No indicators of compromise detected.`);
            } else if (totalFindings < 5) {
              lines.push(
                `Status: Minor findings — review recommended.`
              );
            } else {
              lines.push(
                `Status: MULTIPLE IOCs DETECTED — immediate investigation recommended!`
              );
            }

            return { content: [createTextContent(lines.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── timeline ────────────────────────────────────────────────
        case "timeline": {
          const { path: searchPath, hours, exclude_paths, file_types } = params;
          try {
            const minutes = hours * 60;

            const excludes = exclude_paths
              .split(",")
              .map((p) => p.trim())
              .filter((p) => p);
            const excludeArgs: string[] = [];
            for (const ex of excludes) {
              excludeArgs.push("-not", "-path", `${ex}/*`);
            }

            let typeArgs: string[] = [];
            switch (file_types) {
              case "executables":
                typeArgs = ["-executable"];
                break;
              case "configs":
                typeArgs = [
                  "(",
                  "-name", "*.conf",
                  "-o", "-name", "*.cfg",
                  "-o", "-name", "*.ini",
                  "-o", "-name", "*.yaml",
                  "-o", "-name", "*.yml",
                  "-o", "-name", "*.json",
                  ")",
                ];
                break;
              case "scripts":
                typeArgs = [
                  "(",
                  "-name", "*.sh",
                  "-o", "-name", "*.py",
                  "-o", "-name", "*.pl",
                  "-o", "-name", "*.rb",
                  ")",
                ];
                break;
              default:
                break;
            }

            const findArgs = [
              searchPath,
              "-mmin", `-${minutes}`,
              "-type", "f",
              ...excludeArgs,
              ...typeArgs,
              "-printf", "%T@ %m %u:%g %p\\n",
            ];

            const result = await executeCommand({
              command: "find",
              args: findArgs,
              toolName: "incident_response",
              timeout: 60000,
            });

            const fileEntries = result.stdout
              .split("\n")
              .filter((l) => l.trim())
              .map((line) => {
                const parts = line.split(" ");
                const epochStr = parts[0];
                const perms = parts[1];
                const owner = parts[2];
                const filePath = parts.slice(3).join(" ");
                const epoch = parseFloat(epochStr);
                const date = new Date(epoch * 1000);
                return {
                  timestamp: date.toISOString(),
                  epoch,
                  permissions: perms,
                  owner,
                  path: filePath,
                };
              })
              .filter((e) => !isNaN(e.epoch))
              .sort((a, b) => b.epoch - a.epoch)
              .slice(0, 200);

            const lines: string[] = [
              `=== Filesystem Timeline ===`,
              `Search Path: ${searchPath}`,
              `Timeframe: Last ${hours} hour(s)`,
              `File Types: ${file_types}`,
              `Excluded: ${exclude_paths}`,
              `Results: ${fileEntries.length} file(s) (max 200)`,
              ``,
              `── TIMELINE (newest first) ──`,
              ``,
            ];

            if (fileEntries.length === 0) {
              lines.push(`No modified files found matching criteria.`);
            } else {
              let lastHour = "";
              for (const entry of fileEntries) {
                const hourKey = entry.timestamp.substring(0, 13);
                if (hourKey !== lastHour) {
                  lines.push(``);
                  lines.push(`  ── ${hourKey}:00Z ──`);
                  lastHour = hourKey;
                }
                lines.push(
                  `  ${entry.timestamp}  ${entry.permissions}  ${entry.owner}  ${entry.path}`
                );
              }
            }

            lines.push(``);
            lines.push(`── STATISTICS ──`);
            lines.push(`Total files found: ${fileEntries.length}`);

            const ownerCounts: Record<string, number> = {};
            for (const entry of fileEntries) {
              ownerCounts[entry.owner] = (ownerCounts[entry.owner] ?? 0) + 1;
            }
            lines.push(`Files by owner:`);
            for (const [owner, count] of Object.entries(ownerCounts).sort(
              ([, a], [, b]) => b - a
            )) {
              lines.push(`  ${owner}: ${count}`);
            }

            const dirCounts: Record<string, number> = {};
            for (const entry of fileEntries) {
              const dir = entry.path.substring(
                0,
                entry.path.lastIndexOf("/")
              );
              dirCounts[dir] = (dirCounts[dir] ?? 0) + 1;
            }
            const topDirs = Object.entries(dirCounts)
              .sort(([, a], [, b]) => b - a)
              .slice(0, 10);
            lines.push(`Top directories with changes:`);
            for (const [dir, count] of topDirs) {
              lines.push(`  ${dir}: ${count}`);
            }

            return { content: [createTextContent(lines.join("\n"))] };
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

  // ── ir_forensics tool ──────────────────────────────────────────────────

  server.tool(
    "ir_forensics",
    "Digital forensics: acquire memory dumps, create forensic disk images, capture network traffic, bag evidence, and manage chain-of-custody logs.",
    {
      action: z
        .enum([
          "memory_dump",
          "disk_image",
          "network_capture_forensic",
          "evidence_bag",
          "chain_of_custody",
        ])
        .describe(
          "Action: memory_dump=acquire RAM, disk_image=forensic disk copy, network_capture_forensic=full packet capture, evidence_bag=bag+hash artifact, chain_of_custody=manage custody log",
        ),
      output_dir: z
        .string()
        .optional()
        .default(DEFAULT_FORENSICS_DIR)
        .describe("Directory to store forensic artifacts"),
      case_id: z
        .string()
        .optional()
        .describe("Case identifier for chain-of-custody tracking"),
      device: z
        .string()
        .optional()
        .describe("Device path for disk imaging (e.g. /dev/sda1)"),
      interface: z
        .string()
        .optional()
        .default("any")
        .describe("Network interface for capture (default: any)"),
      duration: z
        .number()
        .optional()
        .default(60)
        .describe("Capture duration in seconds (default 60, max 300)"),
      evidence_path: z
        .string()
        .optional()
        .describe("Path to evidence file (used with evidence_bag, chain_of_custody)"),
      description: z
        .string()
        .optional()
        .describe("Description of the evidence item"),
      examiner: z
        .string()
        .optional()
        .describe("Name of the forensic examiner"),
      custody_action: z
        .enum(["add", "view", "verify"])
        .optional()
        .default("view")
        .describe("Chain-of-custody sub-action: add, view, or verify"),
    },
    async (params) => {
      const { action } = params;

      switch (action) {
        // ── memory_dump ────────────────────────────────────────────────
        case "memory_dump": {
          const { output_dir } = params;
          try {
            // Create output directory
            const mkdirResult = await runForensicCommand("mkdir", ["-p", output_dir]);
            if (mkdirResult.exitCode !== 0) {
              return {
                content: [createErrorContent(`Failed to create output directory: ${mkdirResult.stderr}`)],
                isError: true,
              };
            }

            const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
            const dumpPath = `${output_dir}/memory-dump-${timestamp}.raw`;

            // Try avml first (preferred)
            const avmlResult = await runForensicCommand("avml", [dumpPath], 120_000);

            let toolUsed: string;
            if (avmlResult.exitCode === 0) {
              toolUsed = "avml";
            } else {
              // Fallback to dd from /proc/kcore
              const ddResult = await runForensicCommand(
                "dd",
                ["if=/proc/kcore", `of=${dumpPath}`, "bs=1M", "status=progress"],
                120_000,
              );
              if (ddResult.exitCode !== 0) {
                return {
                  content: [createErrorContent(`Memory dump failed: avml: ${avmlResult.stderr}; dd: ${ddResult.stderr}`)],
                  isError: true,
                };
              }
              toolUsed = "dd (fallback from /proc/kcore)";
            }

            // Calculate SHA-256 hash
            const hashResult = await runForensicCommand("sha256sum", [dumpPath]);
            const hash = hashResult.exitCode === 0
              ? hashResult.stdout.trim().split(/\s+/)[0]
              : "hash-calculation-failed";

            // Get file size
            const statResult = await runForensicCommand("stat", ["-c", "%s", dumpPath]);
            const size = statResult.exitCode === 0 ? statResult.stdout.trim() : "unknown";

            const lines = [
              `=== Memory Dump Acquisition ===`,
              `Tool Used: ${toolUsed}`,
              `Dump Path: ${dumpPath}`,
              `Size: ${size} bytes`,
              `SHA-256: ${hash}`,
              `Timestamp: ${new Date().toISOString()}`,
            ];

            return { content: [createTextContent(lines.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── disk_image ─────────────────────────────────────────────────
        case "disk_image": {
          const { output_dir, device } = params;
          try {
            if (!device) {
              return {
                content: [createErrorContent("device parameter is required for disk_image action")],
                isError: true,
              };
            }

            // Validate device path
            if (!device.startsWith("/dev/")) {
              return {
                content: [createErrorContent(`Invalid device path: ${device}. Must start with /dev/`)],
                isError: true,
              };
            }

            // Block root device imaging
            if (device === "/dev/sda" || device === "/dev/vda" || device === "/dev/nvme0n1" || device === "/dev/xvda") {
              return {
                content: [createErrorContent(`Refusing to image root device: ${device}. Specify a partition (e.g. /dev/sda1)`)],
                isError: true,
              };
            }

            // Create output directory
            const mkdirResult = await runForensicCommand("mkdir", ["-p", output_dir]);
            if (mkdirResult.exitCode !== 0) {
              return {
                content: [createErrorContent(`Failed to create output directory: ${mkdirResult.stderr}`)],
                isError: true,
              };
            }

            const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
            const imagePath = `${output_dir}/disk-image-${timestamp}.raw`;

            // Create forensic disk image
            const ddResult = await runForensicCommand(
              "dd",
              [`if=${device}`, `of=${imagePath}`, "bs=4M", "conv=noerror,sync", "status=progress"],
              600_000,
            );

            if (ddResult.exitCode !== 0) {
              return {
                content: [createErrorContent(`Disk imaging failed: ${ddResult.stderr}`)],
                isError: true,
              };
            }

            // Calculate SHA-256 hash
            const hashResult = await runForensicCommand("sha256sum", [imagePath], 300_000);
            const hash = hashResult.exitCode === 0
              ? hashResult.stdout.trim().split(/\s+/)[0]
              : "hash-calculation-failed";

            // Get file size
            const statResult = await runForensicCommand("stat", ["-c", "%s", imagePath]);
            const size = statResult.exitCode === 0 ? statResult.stdout.trim() : "unknown";

            // Capture partition info
            const fdiskResult = await runForensicCommand("fdisk", ["-l", device]);
            const partitionInfo = fdiskResult.exitCode === 0
              ? fdiskResult.stdout.trim()
              : `fdisk failed: ${fdiskResult.stderr}`;

            const lines = [
              `=== Forensic Disk Image ===`,
              `Source Device: ${device}`,
              `Image Path: ${imagePath}`,
              `Size: ${size} bytes`,
              `SHA-256: ${hash}`,
              `Timestamp: ${new Date().toISOString()}`,
              ``,
              `── Partition Info ──`,
              partitionInfo,
            ];

            return { content: [createTextContent(lines.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── network_capture_forensic ───────────────────────────────────
        case "network_capture_forensic": {
          const { output_dir, duration } = params;
          const iface = params.interface ?? "any";
          try {
            // Cap duration at 300 seconds
            const cappedDuration = Math.min(duration ?? 60, 300);

            // Create output directory
            const mkdirResult = await runForensicCommand("mkdir", ["-p", output_dir]);
            if (mkdirResult.exitCode !== 0) {
              return {
                content: [createErrorContent(`Failed to create output directory: ${mkdirResult.stderr}`)],
                isError: true,
              };
            }

            const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
            const capturePath = `${output_dir}/capture-${timestamp}.pcap`;
            const startTime = new Date().toISOString();

            // Full packet capture with tcpdump
            const tcpdumpResult = await runForensicCommand(
              "tcpdump",
              [
                "-i", iface,
                "-s", "0",
                "-w", capturePath,
                "-c", "0",
                "-G", String(cappedDuration),
                "-W", "1",
              ],
              (cappedDuration + 10) * 1000,
            );

            const endTime = new Date().toISOString();

            // Even if tcpdump exits non-zero (e.g. due to timeout/signal), the file may exist
            // Calculate SHA-256 hash
            const hashResult = await runForensicCommand("sha256sum", [capturePath]);
            const hash = hashResult.exitCode === 0
              ? hashResult.stdout.trim().split(/\s+/)[0]
              : "hash-calculation-failed";

            // Get file size
            const statResult = await runForensicCommand("stat", ["-c", "%s", capturePath]);
            const size = statResult.exitCode === 0 ? statResult.stdout.trim() : "unknown";

            // Get packet count using tcpdump -r
            const countResult = await runForensicCommand(
              "tcpdump",
              ["-r", capturePath, "--count"],
              30_000,
            );
            // tcpdump --count outputs like "N packets" on stderr
            const packetCountMatch = (countResult.stdout + countResult.stderr).match(/(\d+)\s+packet/);
            const packetCount = packetCountMatch ? packetCountMatch[1] : "unknown";

            const lines = [
              `=== Forensic Network Capture ===`,
              `Interface: ${iface}`,
              `Capture Path: ${capturePath}`,
              `Duration: ${cappedDuration}s`,
              `Start Time: ${startTime}`,
              `End Time: ${endTime}`,
              `Packets Captured: ${packetCount}`,
              `Size: ${size} bytes`,
              `SHA-256: ${hash}`,
            ];

            return { content: [createTextContent(lines.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── evidence_bag ───────────────────────────────────────────────
        case "evidence_bag": {
          const { output_dir, case_id, evidence_path, description, examiner } = params;
          try {
            if (!evidence_path) {
              return {
                content: [createErrorContent("evidence_path parameter is required for evidence_bag action")],
                isError: true,
              };
            }

            const effectiveCaseId = case_id ?? "default";
            const evidenceDir = `${output_dir}/${effectiveCaseId}/evidence`;

            // Create evidence directory
            const mkdirResult = await runForensicCommand("mkdir", ["-p", evidenceDir]);
            if (mkdirResult.exitCode !== 0) {
              return {
                content: [createErrorContent(`Failed to create evidence directory: ${mkdirResult.stderr}`)],
                isError: true,
              };
            }

            // Copy file to evidence directory
            const basename = evidence_path.split("/").pop() ?? "evidence";
            const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
            const destPath = `${evidenceDir}/${timestamp}-${basename}`;

            const cpResult = await runForensicCommand("cp", ["-p", evidence_path, destPath]);
            if (cpResult.exitCode !== 0) {
              return {
                content: [createErrorContent(`Failed to copy evidence: ${cpResult.stderr}`)],
                isError: true,
              };
            }

            // Calculate SHA-256 hash
            const hashResult = await runForensicCommand("sha256sum", [destPath]);
            const hash = hashResult.exitCode === 0
              ? hashResult.stdout.trim().split(/\s+/)[0]
              : "hash-calculation-failed";

            // Get file size
            const statResult = await runForensicCommand("stat", ["-c", "%s", destPath]);
            const fileSize = statResult.exitCode === 0 ? statResult.stdout.trim() : "unknown";

            // Create metadata sidecar file
            const metadata = {
              original_path: evidence_path,
              hash,
              timestamp: new Date().toISOString(),
              case_id: effectiveCaseId,
              description: description ?? "",
              examiner: examiner ?? "unknown",
              file_size: fileSize,
            };

            const metadataPath = `${destPath}.metadata.json`;
            secureWriteFileSync(metadataPath, JSON.stringify(metadata, null, 2), "utf-8");

            const lines = [
              `=== Evidence Bagged ===`,
              `Original Path: ${evidence_path}`,
              `Evidence Path: ${destPath}`,
              `Metadata: ${metadataPath}`,
              `Case ID: ${effectiveCaseId}`,
              `SHA-256: ${hash}`,
              `Size: ${fileSize} bytes`,
              `Description: ${description ?? "N/A"}`,
              `Examiner: ${examiner ?? "unknown"}`,
              `Timestamp: ${metadata.timestamp}`,
            ];

            return { content: [createTextContent(lines.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── chain_of_custody ───────────────────────────────────────────
        case "chain_of_custody": {
          const { output_dir, case_id, evidence_path, description, examiner, custody_action } = params;
          try {
            if (!case_id) {
              return {
                content: [createErrorContent("case_id parameter is required for chain_of_custody action")],
                isError: true,
              };
            }

            const caseDir = `${output_dir}/${case_id}`;
            const custodyLogPath = `${caseDir}/custody-log.json`;

            // Ensure case directory exists
            const mkdirResult = await runForensicCommand("mkdir", ["-p", caseDir]);
            if (mkdirResult.exitCode !== 0) {
              return {
                content: [createErrorContent(`Failed to create case directory: ${mkdirResult.stderr}`)],
                isError: true,
              };
            }

            const effectiveAction = custody_action ?? "view";

            switch (effectiveAction) {
              case "add": {
                // Read existing log or create new
                let custodyLog: Array<Record<string, unknown>> = [];
                if (existsSync(custodyLogPath)) {
                  try {
                    const raw = readFileSync(custodyLogPath, "utf-8");
                    custodyLog = JSON.parse(raw);
                  } catch {
                    custodyLog = [];
                  }
                }

                // Calculate hash if evidence_path provided
                let evidenceHash = "N/A";
                if (evidence_path) {
                  const hashResult = await runForensicCommand("sha256sum", [evidence_path]);
                  evidenceHash = hashResult.exitCode === 0
                    ? hashResult.stdout.trim().split(/\s+/)[0]
                    : "hash-calculation-failed";
                }

                const entry = {
                  timestamp: new Date().toISOString(),
                  action: "collected",
                  examiner: examiner ?? "unknown",
                  description: description ?? "",
                  evidence_hash: evidenceHash,
                  evidence_path: evidence_path ?? "N/A",
                };

                custodyLog.push(entry);

                // Write log using secureFsWrite
                secureWriteFileSync(custodyLogPath, JSON.stringify(custodyLog, null, 2), "utf-8");

                const lines = [
                  `=== Chain of Custody — Entry Added ===`,
                  `Case ID: ${case_id}`,
                  `Log Path: ${custodyLogPath}`,
                  `Entry #${custodyLog.length}:`,
                  `  Timestamp: ${entry.timestamp}`,
                  `  Action: ${entry.action}`,
                  `  Examiner: ${entry.examiner}`,
                  `  Description: ${entry.description}`,
                  `  Evidence Hash: ${entry.evidence_hash}`,
                  `  Evidence Path: ${entry.evidence_path}`,
                  `Total Entries: ${custodyLog.length}`,
                ];

                return { content: [createTextContent(lines.join("\n"))] };
              }

              case "view": {
                if (!existsSync(custodyLogPath)) {
                  return {
                    content: [createTextContent(`=== Chain of Custody — ${case_id} ===\nNo custody log found for case ${case_id}.\nLog path: ${custodyLogPath}`)],
                  };
                }

                let custodyLog: Array<Record<string, unknown>> = [];
                try {
                  const raw = readFileSync(custodyLogPath, "utf-8");
                  custodyLog = JSON.parse(raw);
                } catch {
                  return {
                    content: [createErrorContent(`Failed to parse custody log at ${custodyLogPath}`)],
                    isError: true,
                  };
                }

                const lines = [
                  `=== Chain of Custody — ${case_id} ===`,
                  `Log Path: ${custodyLogPath}`,
                  `Total Entries: ${custodyLog.length}`,
                  ``,
                ];

                for (let i = 0; i < custodyLog.length; i++) {
                  const entry = custodyLog[i];
                  lines.push(`── Entry #${i + 1} ──`);
                  lines.push(`  Timestamp: ${entry.timestamp ?? "N/A"}`);
                  lines.push(`  Action: ${entry.action ?? "N/A"}`);
                  lines.push(`  Examiner: ${entry.examiner ?? "N/A"}`);
                  lines.push(`  Description: ${entry.description ?? "N/A"}`);
                  lines.push(`  Evidence Hash: ${entry.evidence_hash ?? "N/A"}`);
                  lines.push(`  Evidence Path: ${entry.evidence_path ?? "N/A"}`);
                  lines.push(``);
                }

                return { content: [createTextContent(lines.join("\n"))] };
              }

              case "verify": {
                if (!evidence_path) {
                  return {
                    content: [createErrorContent("evidence_path parameter is required for chain_of_custody verify action")],
                    isError: true,
                  };
                }

                if (!existsSync(custodyLogPath)) {
                  return {
                    content: [createErrorContent(`No custody log found for case ${case_id}`)],
                    isError: true,
                  };
                }

                let custodyLog: Array<Record<string, unknown>> = [];
                try {
                  const raw = readFileSync(custodyLogPath, "utf-8");
                  custodyLog = JSON.parse(raw);
                } catch {
                  return {
                    content: [createErrorContent(`Failed to parse custody log at ${custodyLogPath}`)],
                    isError: true,
                  };
                }

                // Re-hash evidence
                const hashResult = await runForensicCommand("sha256sum", [evidence_path]);
                const currentHash = hashResult.exitCode === 0
                  ? hashResult.stdout.trim().split(/\s+/)[0]
                  : null;

                if (!currentHash) {
                  return {
                    content: [createErrorContent(`Failed to hash evidence file: ${hashResult.stderr}`)],
                    isError: true,
                  };
                }

                // Find matching entry in custody log
                const matchingEntry = custodyLog.find(
                  (entry) => entry.evidence_path === evidence_path || entry.evidence_hash === currentHash,
                );

                const recordedHash = matchingEntry?.evidence_hash as string | undefined;
                const hashMatch = recordedHash === currentHash;

                const lines = [
                  `=== Chain of Custody — Verification ===`,
                  `Case ID: ${case_id}`,
                  `Evidence Path: ${evidence_path}`,
                  `Current SHA-256: ${currentHash}`,
                  `Recorded SHA-256: ${recordedHash ?? "NOT FOUND"}`,
                  `Integrity: ${hashMatch ? "✓ VERIFIED — hashes match" : "✗ MISMATCH — evidence may be tampered"}`,
                ];

                return { content: [createTextContent(lines.join("\n"))] };
              }

              default:
                return {
                  content: [createErrorContent(`Unknown custody_action: ${effectiveAction}`)],
                  isError: true,
                };
            }
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        default:
          return {
            content: [createErrorContent(`Unknown ir_forensics action: ${action}`)],
            isError: true,
          };
      }
    },
  );
}
