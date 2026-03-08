/**
 * Incident response tools for Kali Defense MCP Server.
 *
 * Registers 1 tool: incident_response (actions: collect, ioc_scan, timeline).
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeCommand } from "../core/executor.js";
import { getConfig } from "../core/config.js";
import {
  createTextContent,
  createErrorContent,
} from "../core/parsers.js";

// ── Suspicious port list for IOC scanning ──────────────────────────────────

const SUSPICIOUS_PORTS = [4444, 5555, 6666, 8888, 9999, 1337, 31337];

const CRYPTO_MINER_NAMES = [
  "xmrig", "minerd", "minergate", "cpuminer", "cgminer",
  "bfgminer", "ethminer", "claymore", "nicehash", "kthreaddi",
];

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
}
