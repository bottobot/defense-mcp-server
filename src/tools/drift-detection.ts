/**
 * Drift detection tools.
 *
 * Registers 1 tool: drift_baseline (actions: create, compare, list).
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeCommand } from "../core/executor.js";
import { getToolTimeout } from "../core/config.js";
import { createErrorContent, formatToolOutput } from "../core/parsers.js";
import { existsSync, readFileSync, writeFileSync, mkdirSync, readdirSync, statSync } from "node:fs";
import { join, basename } from "node:path";
import { homedir } from "node:os";
import { createHash } from "node:crypto";

const BASELINE_DIR = join(homedir(), ".kali-mcp-baselines");

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

export function registerDriftDetectionTools(server: McpServer): void {

  server.tool(
    "drift_baseline",
    "Drift detection: create system baselines, compare current state against baselines, or list available baselines.",
    {
      action: z.enum(["create", "compare", "list"]).describe("Action: create=create baseline, compare=compare against baseline, list=list baselines"),
      // create/compare params
      name: z.string().optional().default("default").describe("Baseline name"),
      directories: z.array(z.string()).optional().default(["/etc"]).describe("Directories to hash (create action)"),
      // shared
      dryRun: z.boolean().optional().default(false).describe("Preview only"),
    },
    async (params) => {
      const { action } = params;

      switch (action) {
        // ── create ──────────────────────────────────────────────────
        case "create": {
          const { directories, name, dryRun } = params;
          try {
            ensureBaselineDir();

            if (dryRun) {
              return {
                content: [formatToolOutput({
                  dryRun: true,
                  directories,
                  baselineName: name,
                  storagePath: join(BASELINE_DIR, `${name}.json`),
                })],
              };
            }

            // Hash files in directories
            const files: BaselineEntry[] = [];
            for (const dir of directories) {
              if (!existsSync(dir)) continue;

              const findResult = await executeCommand({
                command: "find",
                args: [dir, "-maxdepth", "3", "-type", "f", "-not", "-path", "*/proc/*", "-not", "-path", "*/sys/*"],
                timeout: 30000,
              });

              // find may return non-zero due to permission errors but still output valid paths
              if (findResult.stdout.trim()) {
                const paths = findResult.stdout.trim().split("\n").filter(Boolean).slice(0, 5000);
                for (const p of paths) {
                  try {
                    const stat = statSync(p);
                    files.push({
                      path: p,
                      hash: hashFile(p),
                      size: stat.size,
                      mtime: stat.mtime.toISOString(),
                    });
                  } catch { /* skip unreadable */ }
                }
              }
            }

            // Capture sysctl state
            const sysctlState: Record<string, string> = {};
            const sysctlResult = await executeCommand({
              command: "sysctl",
              args: ["-a"],
              timeout: 10000,
            });
            if (sysctlResult.exitCode === 0 && sysctlResult.stdout.trim()) {
              for (const line of sysctlResult.stdout.split("\n")) {
                const idx = line.indexOf("=");
                if (idx > 0) {
                  sysctlState[line.substring(0, idx).trim()] = line.substring(idx + 1).trim();
                }
              }
            }

            // Fallback: read key sysctl values from /proc/sys/ if sysctl binary failed or returned nothing
            if (Object.keys(sysctlState).length === 0) {
              const procSysKeys: [string, string][] = [
                ["net.ipv4.ip_forward", "/proc/sys/net/ipv4/ip_forward"],
                ["net.ipv4.conf.all.accept_redirects", "/proc/sys/net/ipv4/conf/all/accept_redirects"],
                ["net.ipv4.conf.all.send_redirects", "/proc/sys/net/ipv4/conf/all/send_redirects"],
                ["net.ipv4.conf.all.accept_source_route", "/proc/sys/net/ipv4/conf/all/accept_source_route"],
                ["net.ipv4.conf.all.log_martians", "/proc/sys/net/ipv4/conf/all/log_martians"],
                ["net.ipv4.icmp_echo_ignore_broadcasts", "/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts"],
                ["net.ipv4.tcp_syncookies", "/proc/sys/net/ipv4/tcp_syncookies"],
                ["net.ipv6.conf.all.accept_redirects", "/proc/sys/net/ipv6/conf/all/accept_redirects"],
                ["net.ipv6.conf.all.accept_source_route", "/proc/sys/net/ipv6/conf/all/accept_source_route"],
                ["kernel.randomize_va_space", "/proc/sys/kernel/randomize_va_space"],
                ["kernel.dmesg_restrict", "/proc/sys/kernel/dmesg_restrict"],
                ["kernel.kptr_restrict", "/proc/sys/kernel/kptr_restrict"],
                ["kernel.yama.ptrace_scope", "/proc/sys/kernel/yama/ptrace_scope"],
                ["kernel.sysrq", "/proc/sys/kernel/sysrq"],
                ["fs.protected_hardlinks", "/proc/sys/fs/protected_hardlinks"],
                ["fs.protected_symlinks", "/proc/sys/fs/protected_symlinks"],
                ["fs.suid_dumpable", "/proc/sys/fs/suid_dumpable"],
              ];
              for (const [key, procPath] of procSysKeys) {
                try {
                  if (existsSync(procPath)) {
                    const val = readFileSync(procPath, "utf-8").trim();
                    sysctlState[key] = val;
                  }
                } catch { /* skip unreadable */ }
              }
              if (Object.keys(sysctlState).length > 0) {
                console.error(`[drift-detection] sysctl binary unavailable; read ${Object.keys(sysctlState).length} keys from /proc/sys/`);
              } else {
                console.error("[drift-detection] Warning: could not capture any sysctl state (sysctl binary unavailable and /proc/sys/ read failed)");
              }
            }

            // Capture service states
            const services: Record<string, string> = {};
            const svcResult = await executeCommand({
              command: "systemctl",
              args: ["list-units", "--type=service", "--no-pager", "--plain", "--no-legend"],
              timeout: 10000,
            });
            if (svcResult.exitCode === 0) {
              for (const line of svcResult.stdout.split("\n")) {
                const parts = line.trim().split(/\s+/);
                if (parts.length >= 3) {
                  services[parts[0]] = parts[2]; // active/inactive/failed
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
            writeFileSync(outPath, JSON.stringify(baseline, null, 2), "utf-8");

            return {
              content: [formatToolOutput({
                baselineName: name,
                timestamp: baseline.timestamp,
                filesHashed: files.length,
                sysctlKeys: Object.keys(sysctlState).length,
                servicesTracked: Object.keys(services).length,
                savedTo: outPath,
              })],
            };
          } catch (err) {
            return { content: [createErrorContent(`Baseline creation failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true };
          }
        }

        // ── compare ─────────────────────────────────────────────────
        case "compare": {
          const { name, dryRun } = params;
          try {
            const baselinePath = join(BASELINE_DIR, `${name}.json`);
            if (!existsSync(baselinePath)) {
              return { content: [createErrorContent(`Baseline '${name}' not found at ${baselinePath}`)], isError: true };
            }

            const baseline: BaselineData = JSON.parse(readFileSync(baselinePath, "utf-8"));

            const fileChanges: { path: string; type: string; detail: string }[] = [];
            const sysctlChanges: { key: string; baseline: string; current: string }[] = [];
            const serviceChanges: { service: string; baseline: string; current: string }[] = [];

            // Compare files
            for (const entry of baseline.files.slice(0, 2000)) {
              if (!existsSync(entry.path)) {
                fileChanges.push({ path: entry.path, type: "deleted", detail: "File no longer exists" });
                continue;
              }
              const currentHash = hashFile(entry.path);
              if (currentHash !== entry.hash && currentHash !== "unreadable") {
                fileChanges.push({ path: entry.path, type: "modified", detail: `hash changed: ${entry.hash.slice(0, 12)}... → ${currentHash.slice(0, 12)}...` });
              }
            }

            // Compare sysctl
            const sysctlResult = await executeCommand({
              command: "sysctl",
              args: ["-a"],
              timeout: 10000,
            });
            if (sysctlResult.exitCode === 0) {
              const currentSysctl: Record<string, string> = {};
              for (const line of sysctlResult.stdout.split("\n")) {
                const idx = line.indexOf("=");
                if (idx > 0) {
                  currentSysctl[line.substring(0, idx).trim()] = line.substring(idx + 1).trim();
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
              command: "systemctl",
              args: ["list-units", "--type=service", "--no-pager", "--plain", "--no-legend"],
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
                  serviceChanges.push({ service: svc, baseline: state, current });
                }
              }
            }

            const totalDrifts = fileChanges.length + sysctlChanges.length + serviceChanges.length;

            return {
              content: [formatToolOutput({
                baselineName: name,
                baselineTimestamp: baseline.timestamp,
                comparedAt: new Date().toISOString(),
                totalDrifts,
                fileChanges: fileChanges.slice(0, 50),
                sysctlChanges: sysctlChanges.slice(0, 50),
                serviceChanges: serviceChanges.slice(0, 50),
                status: totalDrifts === 0 ? "NO_DRIFT" : "DRIFT_DETECTED",
              })],
            };
          } catch (err) {
            return { content: [createErrorContent(`Baseline comparison failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true };
          }
        }

        // ── list ────────────────────────────────────────────────────
        case "list": {
          try {
            ensureBaselineDir();

            const files = readdirSync(BASELINE_DIR).filter((f) => f.endsWith(".json") && f !== "manifest.json");

            const baselines = files.map((f) => {
              try {
                const data: BaselineData = JSON.parse(readFileSync(join(BASELINE_DIR, f), "utf-8"));
                return {
                  name: data.id,
                  timestamp: data.timestamp,
                  filesTracked: data.files.length,
                  sysctlKeys: Object.keys(data.sysctlState).length,
                  services: Object.keys(data.services).length,
                };
              } catch {
                return { name: f, timestamp: "unknown", filesTracked: 0, sysctlKeys: 0, services: 0 };
              }
            });

            return {
              content: [formatToolOutput({
                baselineDir: BASELINE_DIR,
                totalBaselines: baselines.length,
                baselines,
              })],
            };
          } catch (err) {
            return { content: [createErrorContent(`Drift listing failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true };
          }
        }

        default:
          return { content: [createErrorContent(`Unknown action: ${action}`)], isError: true };
      }
    }
  );
}
