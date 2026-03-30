import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeCommand } from "../core/executor.js";
import { getConfig } from "../core/config.js";
import { createTextContent, createErrorContent, formatToolOutput } from "../core/parsers.js";
import { getDistroAdapter } from "../core/distro-adapter.js";
import { detectDistro } from "../core/distro.js";
import * as https from "node:https";

/** Simple HTTPS GET that returns the response body as a string. Uses networkTimeout from config. */
function httpsGet(url: string): Promise<string> {
  const config = getConfig();
  const timeoutMs = config.networkTimeout;
  return new Promise((resolve, reject) => {
    const req = https.get(url, { timeout: timeoutMs }, (res) => {
      if (res.statusCode === 403) {
        reject(new Error("NVD API rate limit exceeded (HTTP 403). Wait 30s or use an API key."));
        return;
      }
      if (res.statusCode && res.statusCode >= 300) {
        reject(new Error(`HTTP ${res.statusCode}`));
        return;
      }
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolve(Buffer.concat(chunks).toString("utf-8")));
    });
    req.on("error", reject);
    req.on("timeout", () => {
      req.destroy();
      const timeoutSec = Math.round(timeoutMs / 1000);
      reject(new Error(
        `Network request timed out after ${timeoutSec} seconds. ` +
        `The target may be unreachable or the network is slow. ` +
        `Consider increasing DEFENSE_MCP_NETWORK_TIMEOUT (current: ${timeoutSec}s).`
      ));
    });
  });
}

export function registerPatchManagementTools(server: McpServer): void {

  server.tool(
    "patch",
    "Patches: pending updates, unattended upgrades, package integrity, kernel audit, CVE lookup",
    {
      action: z.enum([
        "update_audit",
        "unattended_audit",
        "integrity_check",
        "kernel_audit",
        "vuln_lookup",
        "vuln_scan",
        "vuln_urgency",
      ]).describe("Patch management action"),
      // update_audit params
      security_only: z.boolean().optional().default(false).describe("Only show security-relevant updates"),
      // integrity_check params
      package_name: z.string().optional().describe("Specific package to check"),
      changed_only: z.boolean().optional().default(true).describe("Only show changed files"),
      // vuln_lookup params
      cveId: z.string().optional().describe("CVE ID e.g. CVE-2024-1234"),
      // vuln_scan params
      maxPackages: z.number().optional().default(50).describe("Maximum packages to check"),
      // vuln_urgency params
      packageName: z.string().optional().describe("Package name to check urgency for"),
      // shared
      dryRun: z.boolean().optional().default(true).describe("Preview only"),
    },
    async (params) => {
      const { action } = params;

      switch (action) {
        // ── update_audit ─────────────────────────────────────────────
        case "update_audit": {
          try {
            const da = await getDistroAdapter();
            const pq = da.pkgQuery;

            // Update package cache first (read-only)
            const updateCmd = da.pkg.updateCmd();
            await executeCommand({
              command: "sudo",
              args: updateCmd,
              timeout: 60000,
              toolName: "patch",
            });

            // Get upgradable packages
            const upgradeResult = await executeCommand({
              command: pq.listUpgradableCmd[0],
              args: pq.listUpgradableCmd.slice(1),
              timeout: 30000,
              toolName: "patch",
            });

            // Parse upgradable packages based on distro family
            let packages: Array<{name: string; repo?: string; newVersion?: string; arch?: string; currentVersion?: string; security: boolean}> = [];

            if (da.isDebian) {
              const lines = upgradeResult.stdout.split("\n").filter(l => l.includes("/"));
              packages = lines.map(l => {
                const match = l.match(/^(\S+)\/(\S+)\s+(\S+)\s+(\S+)\s+\[upgradable from: (\S+)\]/);
                if (match) {
                  return {
                    name: match[1], repo: match[2], newVersion: match[3],
                    arch: match[4], currentVersion: match[5],
                    security: match[2].includes("security"),
                  };
                }
                return null;
              }).filter((p): p is NonNullable<typeof p> => p !== null);
            } else if (da.isRhel) {
              const lines = upgradeResult.stdout.split("\n").filter(l => l.trim() && !l.startsWith("Last") && !l.startsWith("Obsoleting") && l.includes("."));
              packages = lines.map(l => {
                const parts = l.trim().split(/\s+/);
                if (parts.length >= 3) {
                  const [nameArch, version, repo] = parts;
                  const dotIdx = nameArch.lastIndexOf(".");
                  return {
                    name: dotIdx > 0 ? nameArch.substring(0, dotIdx) : nameArch,
                    arch: dotIdx > 0 ? nameArch.substring(dotIdx + 1) : "",
                    newVersion: version, repo,
                    security: repo.toLowerCase().includes("security") || repo.toLowerCase().includes("update"),
                  };
                }
                return null;
              }).filter((p): p is NonNullable<typeof p> => p !== null);
            } else if (da.isSuse) {
              const lines = upgradeResult.stdout.split("\n").filter(l => l.includes("|"));
              packages = lines.slice(2).map(l => {
                const cols = l.split("|").map(c => c.trim());
                if (cols.length >= 5) {
                  return {
                    name: cols[2], newVersion: cols[4], repo: cols[1],
                    security: cols[1]?.toLowerCase().includes("update") ?? false,
                  };
                }
                return null;
              }).filter((p): p is NonNullable<typeof p> => p !== null);
            } else if (da.isArch) {
              const lines = upgradeResult.stdout.split("\n").filter(l => l.trim());
              packages = lines.map(l => {
                const parts = l.trim().split(/\s+/);
                return {
                  name: parts[0], currentVersion: parts[1], newVersion: parts[3],
                  security: false,
                };
              }).filter(p => p.name);
            } else if (da.isAlpine) {
              const lines = upgradeResult.stdout.split("\n").filter(l => l.includes("<"));
              packages = lines.map(l => {
                const parts = l.trim().split(/\s+/);
                return { name: parts[0], security: false };
              });
            }

            const securityPkgs = packages.filter(p => p.security);
            const displayPkgs = params.security_only ? securityPkgs : packages;

            // Check held-back packages
            const heldResult = await executeCommand({
              command: pq.showHeldCmd[0],
              args: pq.showHeldCmd.slice(1),
              timeout: 10000,
              toolName: "patch",
            });
            const heldPackages = heldResult.stdout.trim().split("\n").filter(l => l.trim());

            // Check auto-remove candidates
            const autoRemoveResult = await executeCommand({
              command: pq.autoRemoveCmd[0],
              args: pq.autoRemoveCmd.slice(1),
              timeout: 15000,
              toolName: "patch",
            });
            const autoRemoveCount = (() => {
              const match = autoRemoveResult.stdout.match(/(\d+)\s+(?:to remove|packages? will be removed|packages? can be autoremoved)/i);
              return match?.[1] ?? "0";
            })();

            // Kernel version check
            const kernelResult = await executeCommand({
              command: "uname",
              args: ["-r"],
              timeout: 5000,
              toolName: "patch",
            });

            return {
              content: [createTextContent(JSON.stringify({
                distro: da.summary,
                summary: {
                  totalUpgradable: packages.length,
                  securityUpdates: securityPkgs.length,
                  heldBack: heldPackages.length > 0 ? heldPackages : [],
                  autoRemoveCandidates: parseInt(autoRemoveCount),
                  currentKernel: kernelResult.stdout.trim(),
                  status: packages.length === 0 ? "UP_TO_DATE" : securityPkgs.length > 0 ? "SECURITY_UPDATES_PENDING" : "UPDATES_AVAILABLE",
                },
                packages: displayPkgs.slice(0, 100),
              }, null, 2))],
            };
          } catch (error) {
            return {
              content: [createErrorContent(error instanceof Error ? error.message : String(error))],
              isError: true,
            };
          }
        }

        // ── unattended_audit ─────────────────────────────────────────
        case "unattended_audit": {
          try {
            const da = await getDistroAdapter();
            const au = da.autoUpdate;
            const findings: Array<{check: string; status: string; value: string; description: string}> = [];

            if (!au.supported) {
              return {
                content: [createTextContent(JSON.stringify({
                  distro: da.summary,
                  supported: false,
                  message: `Automatic updates are not natively supported on ${da.distro.name}.`,
                  recommendation: au.installHint,
                }, null, 2))],
              };
            }

            const pkgCheckResult = await executeCommand({
              command: au.checkInstalledCmd[0],
              args: au.checkInstalledCmd.slice(1),
              timeout: 10000,
              toolName: "patch",
            });
            const installed = da.isDebian
              ? pkgCheckResult.stdout.includes("ii")
              : pkgCheckResult.exitCode === 0;

            findings.push({
              check: "auto_update_installed",
              status: installed ? "PASS" : "FAIL",
              value: installed ? "installed" : "not installed",
              description: `${au.packageName} package`,
            });

            if (installed && au.serviceName) {
              const serviceResult = await executeCommand({
                command: "systemctl",
                args: ["is-enabled", au.serviceName],
                timeout: 10000,
                toolName: "patch",
              });
              const enabled = serviceResult.stdout.trim() === "enabled";
              findings.push({
                check: "service_enabled",
                status: enabled ? "PASS" : "FAIL",
                value: serviceResult.stdout.trim(),
                description: `${au.serviceName} service enabled`,
              });

              for (const configFile of au.configFiles) {
                const configResult = await executeCommand({
                  command: "cat",
                  args: [configFile],
                  timeout: 5000,
                  toolName: "patch",
                });

                if (configResult.exitCode === 0) {
                  const content = configResult.stdout;

                  if (da.isDebian) {
                    if (configFile.includes("20auto-upgrades")) {
                      const updateEnabled = content.includes('APT::Periodic::Update-Package-Lists "1"');
                      const upgradeEnabled = content.includes('APT::Periodic::Unattended-Upgrade "1"');
                      findings.push({
                        check: "auto_update_lists",
                        status: updateEnabled ? "PASS" : "FAIL",
                        value: updateEnabled ? "enabled" : "disabled",
                        description: "Automatic package list updates",
                      });
                      findings.push({
                        check: "auto_upgrade",
                        status: upgradeEnabled ? "PASS" : "FAIL",
                        value: upgradeEnabled ? "enabled" : "disabled",
                        description: "Automatic unattended upgrades",
                      });
                    } else if (configFile.includes("50unattended")) {
                      const hasSecurityOrigin = content.includes("security") || content.includes("Security");
                      findings.push({
                        check: "security_origins",
                        status: hasSecurityOrigin ? "PASS" : "WARN",
                        value: hasSecurityOrigin ? "configured" : "not found",
                        description: "Security origins in unattended-upgrades config",
                      });
                    }
                  } else if (da.isRhel) {
                    const applyUpdates = content.includes("apply_updates = yes");
                    findings.push({
                      check: "apply_updates",
                      status: applyUpdates ? "PASS" : "FAIL",
                      value: applyUpdates ? "enabled" : "disabled",
                      description: "Automatic application of updates",
                    });
                    const upgradeType = content.match(/upgrade_type\s*=\s*(\S+)/)?.[1] ?? "unknown";
                    findings.push({
                      check: "upgrade_type",
                      status: upgradeType === "security" ? "PASS" : "WARN",
                      value: upgradeType,
                      description: "Update type (security recommended)",
                    });
                  } else if (da.isSuse) {
                    findings.push({
                      check: "config_exists",
                      status: "PASS",
                      value: "present",
                      description: `Config file ${configFile} exists`,
                    });
                  }
                } else {
                  findings.push({
                    check: "config_file",
                    status: "FAIL",
                    value: "missing",
                    description: `${configFile} not found`,
                  });
                }
              }
            }

            const passCount = findings.filter(f => f.status === "PASS").length;
            const failCount = findings.filter(f => f.status === "FAIL").length;

            return {
              content: [createTextContent(JSON.stringify({
                distro: da.summary,
                summary: {
                  total: findings.length,
                  pass: passCount,
                  fail: failCount,
                  warn: findings.filter(f => f.status === "WARN").length,
                },
                findings,
                recommendation: !installed
                  ? `CRITICAL: Install auto-updates: ${au.installHint}`
                  : failCount > 0
                  ? "WARNING: Automatic security updates not fully configured"
                  : "PASS: Automatic security updates properly configured",
              }, null, 2))],
            };
          } catch (error) {
            return {
              content: [createErrorContent(error instanceof Error ? error.message : String(error))],
              isError: true,
            };
          }
        }

        // ── integrity_check ──────────────────────────────────────────
        case "integrity_check": {
          try {
            const da = await getDistroAdapter();
            const ic = da.integrity;

            if (!ic.supported) {
              return {
                content: [createTextContent(JSON.stringify({
                  distro: da.summary,
                  error: "Package integrity checking not supported on this distribution",
                  recommendation: ic.installHint,
                }, null, 2))],
              };
            }

            let cmd: string[];
            if (params.package_name) {
              cmd = ic.checkPackageCmd(params.package_name);
            } else {
              cmd = [...ic.checkCmd];
            }

            if (da.isDebian && params.changed_only && !cmd.includes("--changed")) {
              const idx = cmd.indexOf("-s");
              if (idx >= 0) cmd[idx] = "--changed";
            }

            const result = await executeCommand({
              command: "sudo",
              args: cmd,
              timeout: 120000,
              toolName: "patch",
            });

            const lines = (result.stdout + result.stderr).split("\n").filter(l => l.trim());
            let changes: Array<{file: string; status: string}> = [];

            if (da.isDebian) {
              changes = lines.map(l => {
                const match = l.match(/^(\S+)\s+(OK|CHANGED|MISSING|REPLACED)/i);
                if (match) return { file: match[1], status: match[2] };
                return null;
              }).filter((c): c is NonNullable<typeof c> => c !== null);
            } else if (da.isRhel || da.isSuse) {
              changes = lines.map(l => {
                const match = l.match(/^([.SM5DLUGTP]{9})\s+\S?\s*(.+)/);
                if (match) {
                  const flags = match[1];
                  const file = match[2].trim();
                  const isChanged = flags !== ".........";
                  return { file, status: isChanged ? `CHANGED (${flags})` : "OK" };
                }
                return null;
              }).filter((c): c is NonNullable<typeof c> => c !== null);
            } else if (da.isArch) {
              changes = lines.map(l => {
                if (l.includes("warning:")) {
                  const match = l.match(/warning:\s+(\S+):\s+(.+)/);
                  if (match) return { file: match[1], status: match[2] };
                }
                return null;
              }).filter((c): c is NonNullable<typeof c> => c !== null);
            }

            const changed = changes.filter(c => c.status !== "OK");

            return {
              content: [createTextContent(JSON.stringify({
                distro: da.summary,
                tool: ic.toolName,
                summary: {
                  totalChecked: changes.length,
                  changed: changed.length,
                  status: changed.length === 0 ? "PASS" : "WARN",
                },
                changedFiles: changed,
                note: changed.length > 0
                  ? "Modified files detected. Review if changes are legitimate (config edits) or suspicious (potential compromise)."
                  : "All checked files match their package checksums.",
              }, null, 2))],
            };
          } catch (error) {
            const errMsg = error instanceof Error ? error.message : String(error);
            const da = await getDistroAdapter().catch(() => null);
            if (errMsg.includes("not found") || errMsg.includes("ENOENT")) {
              return {
                content: [createTextContent(JSON.stringify({
                  error: `${da?.integrity.toolName ?? "Integrity tool"} not available`,
                  recommendation: da?.integrity.installHint ?? "Install the appropriate integrity checking tool",
                }, null, 2))],
              };
            }
            return {
              content: [createErrorContent(errMsg)],
              isError: true,
            };
          }
        }

        // ── kernel_audit ─────────────────────────────────────────────
        case "kernel_audit": {
          try {
            const da = await getDistroAdapter();
            const pq = da.pkgQuery;

            const unameResult = await executeCommand({
              command: "uname",
              args: ["-r"],
              timeout: 5000,
              toolName: "patch",
            });
            const currentKernel = unameResult.stdout.trim();

            const kernelResult = await executeCommand({
              command: pq.listKernelsCmd[0],
              args: pq.listKernelsCmd.slice(1),
              timeout: 10000,
              toolName: "patch",
            });

            let installedKernels: Array<{package: string; version?: string}> = [];
            if (da.isDebian) {
              installedKernels = kernelResult.stdout.split("\n")
                .filter(l => l.startsWith("ii") && l.includes("linux-image"))
                .map(l => {
                  const parts = l.split(/\s+/);
                  return { package: parts[1], version: parts[2] };
                });
            } else if (da.isRhel || da.isSuse) {
              installedKernels = kernelResult.stdout.split("\n")
                .filter(l => l.trim() && l.includes("kernel"))
                .map(l => ({ package: l.trim() }));
            } else if (da.isArch) {
              installedKernels = kernelResult.stdout.split("\n")
                .filter(l => l.trim())
                .map(l => {
                  const parts = l.split(/\s+/);
                  return { package: parts[0], version: parts[1] };
                });
            }

            const vulnResult = await executeCommand({
              command: "ls",
              args: ["/sys/devices/system/cpu/vulnerabilities/"],
              timeout: 5000,
              toolName: "patch",
            });
            const vulns: Array<{name: string; status: string; mitigated: boolean}> = [];
            if (vulnResult.exitCode === 0) {
              for (const vuln of vulnResult.stdout.trim().split("\n").filter(v => v.trim())) {
                const catResult = await executeCommand({
                  command: "cat",
                  args: [`/sys/devices/system/cpu/vulnerabilities/${vuln.trim()}`],
                  timeout: 5000,
                  toolName: "patch",
                });
                const status = catResult.stdout.trim();
                vulns.push({
                  name: vuln.trim(),
                  status,
                  mitigated: status.toLowerCase().includes("not affected") || status.toLowerCase().includes("mitigat"),
                });
              }
            }

            const uptimeResult = await executeCommand({
              command: "uptime",
              args: ["-s"],
              timeout: 5000,
              toolName: "patch",
            });

            let livepatchActive = false;
            let livepatchStatus = "not available";
            if (da.isDebian) {
              const livepatchResult = await executeCommand({
                command: "canonical-livepatch",
                args: ["status"],
                timeout: 10000,
                toolName: "patch",
              });
              livepatchActive = livepatchResult.exitCode === 0;
              livepatchStatus = livepatchActive ? livepatchResult.stdout.trim().substring(0, 500) : "not installed";
            } else if (da.isRhel) {
              const kpatchResult = await executeCommand({
                command: "kpatch",
                args: ["list"],
                timeout: 10000,
                toolName: "patch",
              });
              livepatchActive = kpatchResult.exitCode === 0;
              livepatchStatus = livepatchActive ? kpatchResult.stdout.trim().substring(0, 500) : "kpatch not installed";
            } else if (da.isSuse) {
              const klpResult = await executeCommand({
                command: "klp",
                args: ["status"],
                timeout: 10000,
                toolName: "patch",
              });
              livepatchActive = klpResult.exitCode === 0;
              livepatchStatus = livepatchActive ? klpResult.stdout.trim().substring(0, 500) : "kernel livepatch not installed";
            }

            const unmitigated = vulns.filter(v => !v.mitigated);

            const cleanupHint = da.isDebian ? "sudo apt autoremove"
              : da.isRhel ? "sudo dnf remove --oldinstallonly"
              : da.isArch ? "manually remove old kernels"
              : "remove unused kernel packages";

            return {
              content: [createTextContent(JSON.stringify({
                distro: da.summary,
                currentKernel,
                bootTime: uptimeResult.stdout.trim(),
                installedKernels,
                cpuVulnerabilities: {
                  total: vulns.length,
                  mitigated: vulns.length - unmitigated.length,
                  unmitigated: unmitigated.length,
                  details: vulns,
                },
                livepatch: {
                  available: livepatchActive,
                  status: livepatchStatus,
                },
                recommendations: [
                  ...(unmitigated.length > 0 ? [`${unmitigated.length} CPU vulnerabilities not fully mitigated`] : []),
                  ...(installedKernels.length > 3 ? [`Multiple old kernels installed — consider removing unused: ${cleanupHint}`] : []),
                ],
              }, null, 2))],
            };
          } catch (error) {
            return {
              content: [createErrorContent(error instanceof Error ? error.message : String(error))],
              isError: true,
            };
          }
        }

        // ── vuln_lookup ──────────────────────────────────────────────
        case "vuln_lookup": {
          const { cveId, dryRun } = params;
          try {
            if (!cveId) {
              return { content: [createErrorContent("cveId is required for lookup action")], isError: true };
            }
            if (!/^CVE-\d{4}-\d{4,}$/.test(cveId)) {
              return { content: [createErrorContent("cveId must match format CVE-YYYY-NNNN+")], isError: true };
            }

            if (dryRun) {
              return { content: [formatToolOutput({ dryRun: true, url: `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}` })] };
            }

            const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`;
            const body = await httpsGet(url);
            const data = JSON.parse(body);

            const vuln = data?.vulnerabilities?.[0]?.cve;
            if (!vuln) {
              return { content: [formatToolOutput({ cveId, found: false })] };
            }

            const description = vuln.descriptions?.find((d: { lang: string; value: string }) => d.lang === "en")?.value ?? "No description";
            const metrics = vuln.metrics ?? {};
            const cvss31 = metrics.cvssMetricV31?.[0]?.cvssData;
            const cvss2 = metrics.cvssMetricV2?.[0]?.cvssData;

            return {
              content: [formatToolOutput({
                cveId: vuln.id,
                description,
                published: vuln.published,
                lastModified: vuln.lastModified,
                cvssV31: cvss31 ? { score: cvss31.baseScore, severity: cvss31.baseSeverity, vector: cvss31.vectorString } : null,
                cvssV2: cvss2 ? { score: cvss2.baseScore, vector: cvss2.vectorString } : null,
                references: (vuln.references ?? []).slice(0, 10).map((r: { url: string }) => r.url),
              })],
            };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`CVE lookup failed: ${msg}`)], isError: true };
          }
        }

        // ── vuln_scan ────────────────────────────────────────────────
        case "vuln_scan": {
          const { maxPackages, dryRun } = params;
          try {
            const distro = await detectDistro();

            if (dryRun) {
              return { content: [formatToolOutput({ dryRun: true, distro: distro.id, method: distro.family === "debian" ? "apt-get upgrade -s / debsecan" : "dnf updateinfo" })] };
            }

            if (distro.family === "debian") {
              const debsecan = await executeCommand({ toolName: "patch", command: "which", args: ["debsecan"], timeout: 5000 });
              if (debsecan.exitCode === 0) {
                const result = await executeCommand({ toolName: "patch", command: "debsecan", args: ["--format", "detail"], timeout: 60000 });
                const lines = result.stdout.trim().split("\n").filter(Boolean);
                return { content: [formatToolOutput({ tool: "debsecan", totalFindings: lines.length, findings: lines.slice(0, maxPackages) })] };
              }

              const result = await executeCommand({ toolName: "patch", command: "apt-get", args: ["upgrade", "-s"], timeout: 30000 });
              const upgradable = result.stdout.split("\n")
                .filter((l) => l.startsWith("Inst "))
                .slice(0, maxPackages)
                .map((l) => { const match = l.match(/^Inst\s+(\S+)\s+\[(\S+)\]\s+\((\S+)/); return match ? { package: match[1], current: match[2], available: match[3] } : null; })
                .filter(Boolean);

              return { content: [formatToolOutput({ tool: "apt-get upgrade -s", upgradablePackages: upgradable.length, packages: upgradable })] };
            }

            if (distro.family === "rhel") {
              const result = await executeCommand({ toolName: "patch", command: "dnf", args: ["updateinfo", "list", "--security"], timeout: 30000 });
              const lines = result.stdout.trim().split("\n").filter(Boolean).slice(0, maxPackages);
              return { content: [formatToolOutput({ tool: "dnf updateinfo", findings: lines.length, details: lines })] };
            }

            return { content: [createErrorContent(`CVE scanning not supported for distro family: ${distro.family}`)], isError: true };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`Package CVE scan failed: ${msg}`)], isError: true };
          }
        }

        // ── vuln_urgency ─────────────────────────────────────────────
        case "vuln_urgency": {
          const { packageName, dryRun } = params;
          try {
            if (!packageName) {
              return { content: [createErrorContent("packageName is required for urgency action")], isError: true };
            }

            const distro = await detectDistro();

            if (dryRun) {
              return { content: [formatToolOutput({ dryRun: true, package: packageName, distro: distro.id })] };
            }

            const info: Record<string, unknown> = { package: packageName, distro: distro.id };

            if (distro.family === "debian") {
              const dpkg = await executeCommand({ toolName: "patch", command: "dpkg-query", args: ["-W", "-f", "${Version}", packageName], timeout: 10000 });
              info.installedVersion = dpkg.exitCode === 0 ? dpkg.stdout.trim() : "not installed";

              const apt = await executeCommand({ toolName: "patch", command: "apt-cache", args: ["policy", packageName], timeout: 10000 });
              if (apt.exitCode === 0) {
                const candidate = apt.stdout.match(/Candidate:\s*(\S+)/)?.[1];
                info.candidateVersion = candidate ?? "unknown";
                info.updateAvailable = candidate && candidate !== info.installedVersion;
              }

              const changelog = await executeCommand({ toolName: "patch", command: "apt-get", args: ["changelog", packageName], timeout: 15000 });
              if (changelog.exitCode === 0) {
                info.securityEntries = changelog.stdout.split("\n").filter((l) => /CVE-\d{4}-\d{4,}|security/i.test(l)).slice(0, 10);
              }
            } else if (distro.family === "rhel") {
              const rpm = await executeCommand({ toolName: "patch", command: "rpm", args: ["-q", packageName], timeout: 10000 });
              info.installedVersion = rpm.exitCode === 0 ? rpm.stdout.trim() : "not installed";

              const updateinfo = await executeCommand({ toolName: "patch", command: "dnf", args: ["updateinfo", "info", packageName], timeout: 15000 });
              if (updateinfo.exitCode === 0) {
                info.advisories = updateinfo.stdout.slice(0, 5000);
              }
            }

            return { content: [formatToolOutput(info)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`Patch urgency check failed: ${msg}`)], isError: true };
          }
        }

        default:
          return { content: [createErrorContent(`Unknown action: ${action}`)], isError: true };
      }
    }
  );
}
