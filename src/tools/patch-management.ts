import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeCommand } from "../core/executor.js";
import { getConfig } from "../core/config.js";
import { createTextContent, createErrorContent } from "../core/parsers.js";
import { getDistroAdapter } from "../core/distro-adapter.js";

export function registerPatchManagementTools(server: McpServer): void {

  // Tool 1: patch_update_audit - Check for pending updates
  server.tool(
    "patch_update_audit",
    "Audit system for pending security updates, held-back packages, and overall patch status. Checks apt/dpkg on Debian-based or dnf/yum on RHEL-based systems.",
    {
      security_only: z.boolean().optional().default(false).describe("Only show security-relevant updates"),
    },
    async (params) => {
      try {
        const da = await getDistroAdapter();
        const pq = da.pkgQuery;

        // Update package cache first (read-only)
        const updateCmd = da.pkg.updateCmd();
        await executeCommand({
          command: "sudo",
          args: updateCmd,
          timeout: 60000,
          toolName: "patch_update_audit",
        });
        
        // Get upgradable packages
        const upgradeResult = await executeCommand({
          command: pq.listUpgradableCmd[0],
          args: pq.listUpgradableCmd.slice(1),
          timeout: 30000,
          toolName: "patch_update_audit",
        });

        // Parse upgradable packages based on distro family
        let packages: Array<{name: string; repo?: string; newVersion?: string; arch?: string; currentVersion?: string; security: boolean}> = [];

        if (da.isDebian) {
          // apt list --upgradable format: package/repo version arch [upgradable from: old]
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
          // dnf/yum check-update format: package.arch  version  repo
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
          // zypper list-updates format: table output
          const lines = upgradeResult.stdout.split("\n").filter(l => l.includes("|"));
          packages = lines.slice(2).map(l => { // skip header rows
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
          // pacman -Qu format: package oldversion -> newversion
          const lines = upgradeResult.stdout.split("\n").filter(l => l.trim());
          packages = lines.map(l => {
            const parts = l.trim().split(/\s+/);
            return {
              name: parts[0], currentVersion: parts[1], newVersion: parts[3],
              security: false, // Arch doesn't differentiate security updates
            };
          }).filter(p => p.name);
        } else if (da.isAlpine) {
          // apk version -l '<' format: package-version < newversion
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
          toolName: "patch_update_audit",
        });
        const heldPackages = heldResult.stdout.trim().split("\n").filter(l => l.trim());
        
        // Check auto-remove candidates
        const autoRemoveResult = await executeCommand({
          command: pq.autoRemoveCmd[0],
          args: pq.autoRemoveCmd.slice(1),
          timeout: 15000,
          toolName: "patch_update_audit",
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
          toolName: "patch_update_audit",
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
    },
  );

  // Tool 2: patch_unattended_audit - Check auto-update config
  server.tool(
    "patch_unattended_audit",
    "Audit unattended-upgrades configuration to ensure automatic security patching is properly configured.",
    {},
    async () => {
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

        // Check if auto-update package is installed
        const pkgCheckResult = await executeCommand({
          command: au.checkInstalledCmd[0],
          args: au.checkInstalledCmd.slice(1),
          timeout: 10000,
          toolName: "patch_unattended_audit",
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
          // Check service status
          const serviceResult = await executeCommand({
            command: "systemctl",
            args: ["is-enabled", au.serviceName],
            timeout: 10000,
            toolName: "patch_unattended_audit",
          });
          const enabled = serviceResult.stdout.trim() === "enabled";
          findings.push({
            check: "service_enabled",
            status: enabled ? "PASS" : "FAIL",
            value: serviceResult.stdout.trim(),
            description: `${au.serviceName} service enabled`,
          });
          
          // Check config files
          for (const configFile of au.configFiles) {
            const configResult = await executeCommand({
              command: "cat",
              args: [configFile],
              timeout: 5000,
              toolName: "patch_unattended_audit",
            });
            
            if (configResult.exitCode === 0) {
              const content = configResult.stdout;

              if (da.isDebian) {
                // Debian-specific config parsing
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
                // RHEL-specific: /etc/dnf/automatic.conf
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
    },
  );

  // Tool 3: patch_integrity_check - Verify installed package integrity
  server.tool(
    "patch_integrity_check",
    "Verify integrity of installed packages using debsums (Debian/Ubuntu) or rpm -V (RHEL). Detects modified system files that may indicate compromise.",
    {
      package_name: z.string().optional().describe("Specific package to check, or omit for all"),
      changed_only: z.boolean().optional().default(true).describe("Only show files that have changed"),
    },
    async (params) => {
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

        // Build the command based on distro
        let cmd: string[];
        if (params.package_name) {
          cmd = ic.checkPackageCmd(params.package_name);
        } else {
          cmd = [...ic.checkCmd];
        }

        // For debsums, add --changed flag if not already there
        if (da.isDebian && params.changed_only && !cmd.includes("--changed")) {
          // Replace -s with --changed for changed_only mode
          const idx = cmd.indexOf("-s");
          if (idx >= 0) cmd[idx] = "--changed";
        }
        
        const result = await executeCommand({
          command: "sudo",
          args: cmd,
          timeout: 120000,
          toolName: "patch_integrity_check",
        });
        
        const lines = (result.stdout + result.stderr).split("\n").filter(l => l.trim());
        let changes: Array<{file: string; status: string}> = [];

        if (da.isDebian) {
          // debsums output: "file CHANGED" or "file OK" or "file MISSING"
          changes = lines.map(l => {
            const match = l.match(/^(\S+)\s+(OK|CHANGED|MISSING|REPLACED)/i);
            if (match) return { file: match[1], status: match[2] };
            return null;
          }).filter((c): c is NonNullable<typeof c> => c !== null);
        } else if (da.isRhel || da.isSuse) {
          // rpm -V output: SM5DLUGTP c /path/to/file
          // Dots mean OK, letters mean changes
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
          // pacman -Qk output: package: /path (Modification)
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
    },
  );

  // Tool 4: patch_kernel_audit - Audit kernel version and livepatch
  server.tool(
    "patch_kernel_audit",
    "Audit kernel version, check for available kernel updates, livepatch status, and kernel support timeline.",
    {},
    async () => {
      try {
        const da = await getDistroAdapter();
        const pq = da.pkgQuery;

        // Current kernel
        const unameResult = await executeCommand({
          command: "uname",
          args: ["-r"],
          timeout: 5000,
          toolName: "patch_kernel_audit",
        });
        const currentKernel = unameResult.stdout.trim();
        
        // All installed kernels — distro-aware
        const kernelResult = await executeCommand({
          command: pq.listKernelsCmd[0],
          args: pq.listKernelsCmd.slice(1),
          timeout: 10000,
          toolName: "patch_kernel_audit",
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
        
        // Check CPU vulnerabilities (works on all Linux distros)
        const vulnResult = await executeCommand({
          command: "ls",
          args: ["/sys/devices/system/cpu/vulnerabilities/"],
          timeout: 5000,
          toolName: "patch_kernel_audit",
        });
        const vulns: Array<{name: string; status: string; mitigated: boolean}> = [];
        if (vulnResult.exitCode === 0) {
          for (const vuln of vulnResult.stdout.trim().split("\n").filter(v => v.trim())) {
            const catResult = await executeCommand({
              command: "cat",
              args: [`/sys/devices/system/cpu/vulnerabilities/${vuln.trim()}`],
              timeout: 5000,
              toolName: "patch_kernel_audit",
            });
            const status = catResult.stdout.trim();
            vulns.push({
              name: vuln.trim(),
              status,
              mitigated: status.toLowerCase().includes("not affected") || status.toLowerCase().includes("mitigat"),
            });
          }
        }
        
        // Boot time (works everywhere)
        const uptimeResult = await executeCommand({
          command: "uptime",
          args: ["-s"],
          timeout: 5000,
          toolName: "patch_kernel_audit",
        });
        
        // Livepatch status — Debian/Ubuntu specific
        let livepatchActive = false;
        let livepatchStatus = "not available";
        if (da.isDebian) {
          const livepatchResult = await executeCommand({
            command: "canonical-livepatch",
            args: ["status"],
            timeout: 10000,
            toolName: "patch_kernel_audit",
          });
          livepatchActive = livepatchResult.exitCode === 0;
          livepatchStatus = livepatchActive ? livepatchResult.stdout.trim().substring(0, 500) : "not installed";
        } else if (da.isRhel) {
          // RHEL has kpatch
          const kpatchResult = await executeCommand({
            command: "kpatch",
            args: ["list"],
            timeout: 10000,
            toolName: "patch_kernel_audit",
          });
          livepatchActive = kpatchResult.exitCode === 0;
          livepatchStatus = livepatchActive ? kpatchResult.stdout.trim().substring(0, 500) : "kpatch not installed";
        } else if (da.isSuse) {
          const klpResult = await executeCommand({
            command: "klp",
            args: ["status"],
            timeout: 10000,
            toolName: "patch_kernel_audit",
          });
          livepatchActive = klpResult.exitCode === 0;
          livepatchStatus = livepatchActive ? klpResult.stdout.trim().substring(0, 500) : "kernel livepatch not installed";
        }

        const unmitigated = vulns.filter(v => !v.mitigated);

        // Distro-aware cleanup recommendation
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
    },
  );
}
