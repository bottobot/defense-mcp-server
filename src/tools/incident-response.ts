/**
 * Incident response tools for Kali Defense MCP Server.
 *
 * Registers 3 tools: ir_volatile_collect, ir_ioc_scan,
 * ir_timeline_generate.
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
  // ── 1. ir_volatile_collect ─────────────────────────────────────────────

  server.tool(
    "ir_volatile_collect",
    "Collect volatile system data following RFC 3227 order of volatility for incident response",
    {
      output_dir: z
        .string()
        .optional()
        .default("/tmp/ir-collection")
        .describe("Directory to save collected volatile data"),
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview what would be collected without executing (defaults to KALI_DEFENSE_DRY_RUN env var)"),
    },
    async ({ output_dir, dry_run }) => {
      try {
        const collectionSteps = [
          { name: "01-processes", cmd: "ps auxwww", desc: "Running processes" },
          { name: "02-network-connections", cmd: "ss -tulnpea", desc: "Network connections" },
          { name: "03-ip-addresses", cmd: "ip addr show", desc: "IP addresses" },
          { name: "04-routes", cmd: "ip route show", desc: "Routing table" },
          { name: "05-arp-cache", cmd: "arp -an", desc: "ARP cache" },
          { name: "06-logged-in-users-who", cmd: "who", desc: "Logged in users (who)" },
          { name: "07-logged-in-users-w", cmd: "w", desc: "Logged in users (w)" },
          { name: "08-recent-logins", cmd: "last -n 20", desc: "Recent logins" },
          { name: "09-open-files", cmd: "lsof -n 2>/dev/null | head -500", desc: "Open files (first 500 lines)" },
          { name: "10-kernel-modules", cmd: "lsmod", desc: "Loaded kernel modules" },
          { name: "11-mounts", cmd: "mount", desc: "Mounted filesystems" },
          { name: "12-disk-usage", cmd: "df -h", desc: "Disk usage" },
          { name: "13-environment", cmd: "env", desc: "Environment variables" },
          { name: "14-uptime", cmd: "uptime", desc: "System uptime" },
          { name: "15-hostname", cmd: "hostname", desc: "Hostname" },
          { name: "16-utc-time", cmd: "date -u", desc: "Current UTC time" },
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
            lines.push(`    Command: ${step.cmd}`);
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
          toolName: "ir_volatile_collect",
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
          const result = await executeCommand({
            command: "sh",
            args: ["-c", `${step.cmd} > "${collectionDir}/${step.name}.txt" 2>&1`],
            toolName: "ir_volatile_collect",
            timeout: 30000,
          });

          if (result.exitCode === 0) {
            // Get file size
            const sizeResult = await executeCommand({
              command: "stat",
              args: ["-c", "%s", `${collectionDir}/${step.name}.txt`],
              toolName: "ir_volatile_collect",
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
  );

  // ── 2. ir_ioc_scan ────────────────────────────────────────────────────

  server.tool(
    "ir_ioc_scan",
    "Scan system for Indicators of Compromise (IOCs) — suspicious processes, connections, persistence mechanisms",
    {
      check_type: z
        .enum(["processes", "connections", "persistence", "all"])
        .default("all")
        .describe("Type of IOC check to perform"),
    },
    async ({ check_type }) => {
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

          // Get process list
          const psResult = await executeCommand({
            command: "ps",
            args: ["aux"],
            toolName: "ir_ioc_scan",
            timeout: 15000,
          });

          const psLines = psResult.stdout.split("\n").filter((l) => l.trim());

          // Check processes running from /tmp, /dev/shm, /var/tmp
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

          // Check for deleted executables
          const deletedResult = await executeCommand({
            command: "sh",
            args: [
              "-c",
              `ls -la /proc/*/exe 2>/dev/null | grep "deleted" | head -20`,
            ],
            toolName: "ir_ioc_scan",
            timeout: 15000,
          });

          const deletedProcs = deletedResult.stdout
            .split("\n")
            .filter((l) => l.trim());
          if (deletedProcs.length > 0) {
            lines.push(`  [HIGH] Processes with deleted executables:`);
            for (const proc of deletedProcs) {
              lines.push(`    ${proc.trim()}`);
            }
            totalFindings += deletedProcs.length;
          }

          // Check for crypto miners
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
            toolName: "ir_ioc_scan",
            timeout: 15000,
          });

          const ssLines = ssResult.stdout.split("\n").filter((l) => l.trim());

          // Check for suspicious ports
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

          // Check for ESTABLISHED connections to non-standard high ports
          const establishedHighPort = ssLines.filter((line) => {
            if (!line.includes("ESTAB")) return false;
            // Extract remote port from peer address
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

          // Check for multiple connections to same external IP
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

          // Check cron entries
          lines.push(`  ─ Cron Jobs ─`);
          const cronResult = await executeCommand({
            command: "sh",
            args: [
              "-c",
              `crontab -l 2>/dev/null; echo "---"; for f in /etc/cron.d/* /etc/cron.daily/* /etc/cron.hourly/* /etc/cron.weekly/* /etc/cron.monthly/*; do [ -f "$f" ] && echo "FILE: $f" && head -5 "$f" && echo "---"; done 2>/dev/null`,
            ],
            toolName: "ir_ioc_scan",
            timeout: 15000,
          });

          if (cronResult.stdout.trim() && cronResult.stdout.trim() !== "---") {
            const cronEntries = cronResult.stdout
              .split("---")
              .filter((s) => s.trim());
            lines.push(`    Found ${cronEntries.length} cron source(s):`);
            for (const entry of cronEntries.slice(0, 10)) {
              const trimmed = entry.trim().split("\n").slice(0, 3).join("\n      ");
              lines.push(`      ${trimmed}`);
            }
            // Flag suspicious cron entries
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

          // Check systemd services (recently created)
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
            toolName: "ir_ioc_scan",
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

          // Check rc.local
          lines.push(`  ─ rc.local ─`);
          const rcResult = await executeCommand({
            command: "sh",
            args: [
              "-c",
              `[ -f /etc/rc.local ] && cat /etc/rc.local | grep -v "^#" | grep -v "^$" | grep -v "^exit 0" || echo "not found or empty"`,
            ],
            toolName: "ir_ioc_scan",
            timeout: 10000,
          });

          if (
            rcResult.stdout.trim() &&
            rcResult.stdout.trim() !== "not found or empty"
          ) {
            lines.push(`    [MEDIUM] Non-standard rc.local entries:`);
            for (const entry of rcResult.stdout.trim().split("\n")) {
              lines.push(`      ${entry.trim()}`);
            }
            totalFindings += rcResult.stdout.trim().split("\n").length;
          } else {
            lines.push(`    rc.local is clean or not present.`);
          }

          // Check .bashrc/.profile for suspicious additions
          lines.push(`  ─ Shell Profile Checks ─`);
          const bashrcResult = await executeCommand({
            command: "sh",
            args: [
              "-c",
              `grep -rnH "curl\\|wget\\|base64\\|/dev/tcp\\|nc -e\\|ncat\\|python.*-c.*import" /home/*/.bashrc /home/*/.profile /root/.bashrc /root/.profile 2>/dev/null | head -20`,
            ],
            toolName: "ir_ioc_scan",
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

          // Check recently modified authorized_keys
          lines.push(`  ─ SSH Authorized Keys ─`);
          const akResult = await executeCommand({
            command: "find",
            args: [
              "/home", "/root",
              "-name", "authorized_keys",
              "-mtime", "-7",
              "-type", "f",
            ],
            toolName: "ir_ioc_scan",
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
  );

  // ── 3. ir_timeline_generate ────────────────────────────────────────────

  server.tool(
    "ir_timeline_generate",
    "Generate a filesystem timeline showing recently modified files for forensic analysis",
    {
      path: z
        .string()
        .optional()
        .default("/")
        .describe("Root path to search for modified files"),
      hours: z
        .number()
        .optional()
        .default(24)
        .describe("Look back this many hours for modifications"),
      exclude_paths: z
        .string()
        .optional()
        .default("/proc,/sys,/dev,/run")
        .describe("Comma-separated paths to exclude from search"),
      file_types: z
        .enum(["all", "executables", "configs", "scripts"])
        .default("all")
        .describe("Type of files to include in the timeline"),
    },
    async ({ path: searchPath, hours, exclude_paths, file_types }) => {
      try {
        const minutes = hours * 60;

        // Build exclude arguments
        const excludes = exclude_paths
          .split(",")
          .map((p) => p.trim())
          .filter((p) => p);
        const excludeArgs: string[] = [];
        for (const ex of excludes) {
          excludeArgs.push("-not", "-path", `${ex}/*`);
        }

        // Build type filter arguments
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
            // "all" — no type filter
            break;
        }

        // Build the find command
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
          toolName: "ir_timeline_generate",
          timeout: 60000,
        });

        // Parse and sort results
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
          // Sort newest first
          .sort((a, b) => b.epoch - a.epoch)
          // Limit to 200 results
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
          // Group by hour for readability
          let lastHour = "";
          for (const entry of fileEntries) {
            const hourKey = entry.timestamp.substring(0, 13); // YYYY-MM-DDTHH
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

        // Count by owner
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

        // Count by directory
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
  );
}
