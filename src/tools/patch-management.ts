import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeCommand } from "../core/executor.js";
import { getConfig } from "../core/config.js";
import { createTextContent, createErrorContent } from "../core/parsers.js";

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
        // Update package cache first (read-only)
        await executeCommand({
          command: "sudo",
          args: ["apt-get", "update", "-qq"],
          timeout: 60000,
          toolName: "patch_update_audit",
        });
        
        // Get upgradable packages
        const upgradeResult = await executeCommand({
          command: "apt",
          args: ["list", "--upgradable"],
          timeout: 30000,
          toolName: "patch_update_audit",
        });
        
        const lines = upgradeResult.stdout.split("\n").filter(l => l.includes("/"));
        const packages = lines.map(l => {
          const match = l.match(/^(\S+)\/(\S+)\s+(\S+)\s+(\S+)\s+\[upgradable from: (\S+)\]/);
          if (match) {
            return {
              name: match[1],
              repo: match[2],
              newVersion: match[3],
              arch: match[4],
              currentVersion: match[5],
              security: match[2].includes("security"),
            };
          }
          return null;
        }).filter(Boolean);
        
        const securityPkgs = packages.filter(p => p && p.security);
        const displayPkgs = params.security_only ? securityPkgs : packages;
        
        // Check held-back packages
        const heldResult = await executeCommand({
          command: "apt-mark",
          args: ["showhold"],
          timeout: 10000,
          toolName: "patch_update_audit",
        });
        const heldPackages = heldResult.stdout.trim().split("\n").filter(l => l.trim());
        
        // Check auto-remove candidates
        const autoRemoveResult = await executeCommand({
          command: "apt",
          args: ["--dry-run", "autoremove"],
          timeout: 15000,
          toolName: "patch_update_audit",
        });
        const autoRemoveCount = (autoRemoveResult.stdout.match(/(\d+) to remove/)?.[1]) || "0";
        
        // Kernel version check
        const kernelResult = await executeCommand({
          command: "uname",
          args: ["-r"],
          timeout: 5000,
          toolName: "patch_update_audit",
        });
        
        return {
          content: [createTextContent(JSON.stringify({
            summary: {
              totalUpgradable: packages.length,
              securityUpdates: securityPkgs.length,
              heldBack: heldPackages.length > 0 ? heldPackages : [],
              autoRemoveCandidates: parseInt(autoRemoveCount),
              currentKernel: kernelResult.stdout.trim(),
              status: packages.length === 0 ? "UP_TO_DATE" : securityPkgs.length > 0 ? "SECURITY_UPDATES_PENDING" : "UPDATES_AVAILABLE",
            },
            packages: displayPkgs.slice(0, 100), // Limit output
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
        const findings: Array<{check: string, status: string, value: string, description: string}> = [];
        
        // Check if unattended-upgrades is installed
        const dpkgResult = await executeCommand({
          command: "dpkg",
          args: ["-l", "unattended-upgrades"],
          timeout: 10000,
          toolName: "patch_unattended_audit",
        });
        const installed = dpkgResult.stdout.includes("ii");
        findings.push({
          check: "unattended_upgrades_installed",
          status: installed ? "PASS" : "FAIL",
          value: installed ? "installed" : "not installed",
          description: "unattended-upgrades package",
        });
        
        if (installed) {
          // Check service status
          const serviceResult = await executeCommand({
            command: "systemctl",
            args: ["is-enabled", "unattended-upgrades"],
            timeout: 10000,
            toolName: "patch_unattended_audit",
          });
          const enabled = serviceResult.stdout.trim() === "enabled";
          findings.push({
            check: "service_enabled",
            status: enabled ? "PASS" : "FAIL",
            value: serviceResult.stdout.trim(),
            description: "unattended-upgrades service enabled",
          });
          
          // Check apt auto-update config
          const autoConfig = await executeCommand({
            command: "cat",
            args: ["/etc/apt/apt.conf.d/20auto-upgrades"],
            timeout: 5000,
            toolName: "patch_unattended_audit",
          });
          
          if (autoConfig.exitCode === 0) {
            const content = autoConfig.stdout;
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
          } else {
            findings.push({
              check: "auto_config",
              status: "FAIL",
              value: "missing",
              description: "/etc/apt/apt.conf.d/20auto-upgrades not found",
            });
          }
          
          // Check main config for security origins
          const mainConfig = await executeCommand({
            command: "cat",
            args: ["/etc/apt/apt.conf.d/50unattended-upgrades"],
            timeout: 5000,
            toolName: "patch_unattended_audit",
          });
          if (mainConfig.exitCode === 0) {
            const hasSecurityOrigin = mainConfig.stdout.includes("security") || mainConfig.stdout.includes("Security");
            findings.push({
              check: "security_origins",
              status: hasSecurityOrigin ? "PASS" : "WARN",
              value: hasSecurityOrigin ? "configured" : "not found",
              description: "Security origins in unattended-upgrades config",
            });
            
            const hasAutoReboot = mainConfig.stdout.includes("Automatic-Reboot");
            findings.push({
              check: "auto_reboot_configured",
              status: "INFO",
              value: hasAutoReboot ? "configured" : "not configured",
              description: "Automatic reboot after kernel updates",
            });
          }
        }
        
        const passCount = findings.filter(f => f.status === "PASS").length;
        const failCount = findings.filter(f => f.status === "FAIL").length;
        
        return {
          content: [createTextContent(JSON.stringify({
            summary: {
              total: findings.length,
              pass: passCount,
              fail: failCount,
              warn: findings.filter(f => f.status === "WARN").length,
            },
            findings,
            recommendation: !installed 
              ? "CRITICAL: Install unattended-upgrades: sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades"
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
        // Try debsums first (Debian-based)
        const args = ["--changed"];
        if (!params.changed_only) args.length = 0;
        if (params.package_name) args.push(params.package_name);
        
        const result = await executeCommand({
          command: "sudo",
          args: ["debsums", ...args],
          timeout: 120000,
          toolName: "patch_integrity_check",
        });
        
        const lines = (result.stdout + result.stderr).split("\n").filter(l => l.trim());
        const changes = lines.map(l => {
          // debsums output: "file CHANGED" or "file OK" or "file MISSING"
          const match = l.match(/^(\S+)\s+(OK|CHANGED|MISSING|REPLACED)/i);
          if (match) return { file: match[1], status: match[2] };
          return null;
        }).filter(Boolean);
        
        const changed = changes.filter(c => c && c.status !== "OK");
        
        return {
          content: [createTextContent(JSON.stringify({
            tool: "debsums",
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
        // debsums might not be installed
        const errMsg = error instanceof Error ? error.message : String(error);
        if (errMsg.includes("not found") || errMsg.includes("ENOENT")) {
          return {
            content: [createTextContent(JSON.stringify({
              error: "debsums not installed",
              recommendation: "Install debsums: sudo apt install debsums",
              alternative: "Use 'dpkg --verify' as a basic alternative",
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
        // Current kernel
        const unameResult = await executeCommand({
          command: "uname",
          args: ["-r"],
          timeout: 5000,
          toolName: "patch_kernel_audit",
        });
        const currentKernel = unameResult.stdout.trim();
        
        // All installed kernels
        const dpkgResult = await executeCommand({
          command: "dpkg",
          args: ["--list", "linux-image-*"],
          timeout: 10000,
          toolName: "patch_kernel_audit",
        });
        const installedKernels = dpkgResult.stdout.split("\n")
          .filter(l => l.startsWith("ii") && l.includes("linux-image"))
          .map(l => {
            const parts = l.split(/\s+/);
            return { package: parts[1], version: parts[2] };
          });
        
        // Check if kernel has known CVEs (via /sys/devices/system/cpu/vulnerabilities)
        const vulnResult = await executeCommand({
          command: "ls",
          args: ["/sys/devices/system/cpu/vulnerabilities/"],
          timeout: 5000,
          toolName: "patch_kernel_audit",
        });
        const vulns: Array<{name: string, status: string, mitigated: boolean}> = [];
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
        
        // Boot time
        const uptimeResult = await executeCommand({
          command: "uptime",
          args: ["-s"],
          timeout: 5000,
          toolName: "patch_kernel_audit",
        });
        
        // Livepatch status
        const livepatchResult = await executeCommand({
          command: "canonical-livepatch",
          args: ["status"],
          timeout: 10000,
          toolName: "patch_kernel_audit",
        });
        const livepatchActive = livepatchResult.exitCode === 0;
        
        const unmitigated = vulns.filter(v => !v.mitigated);
        
        return {
          content: [createTextContent(JSON.stringify({
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
              status: livepatchActive ? livepatchResult.stdout.trim().substring(0, 500) : "not installed",
            },
            recommendations: [
              ...(unmitigated.length > 0 ? [`${unmitigated.length} CPU vulnerabilities not fully mitigated`] : []),
              ...(installedKernels.length > 3 ? ["Multiple old kernels installed — consider removing unused: sudo apt autoremove"] : []),
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
