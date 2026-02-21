/**
 * System hardening tools for Kali Defense MCP Server.
 *
 * Registers 10 tools: harden_sysctl_get, harden_sysctl_set,
 * harden_sysctl_audit, harden_service_manage, harden_service_audit,
 * harden_file_permissions, harden_permissions_audit, harden_systemd_audit,
 * harden_kernel_security_audit, harden_bootloader_audit.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeCommand } from "../core/executor.js";
import { getConfig, getToolTimeout } from "../core/config.js";
import {
  createTextContent,
  createErrorContent,
  parseSysctlOutput,
  parseSystemctlOutput,
  formatToolOutput,
} from "../core/parsers.js";
import {
  logChange,
  createChangeEntry,
  backupFile,
} from "../core/changelog.js";
import {
  validateServiceName,
  validateFilePath,
  sanitizeArgs,
} from "../core/sanitizer.js";

// ── Sysctl key validator (imported from sanitizer) ─────────────────────────

import { validateSysctlKey } from "../core/sanitizer.js";

// ── Hardening recommendation database ──────────────────────────────────────

interface SysctlRecommendation {
  key: string;
  recommended: string;
  description: string;
  category: "network" | "kernel" | "fs";
}

const SYSCTL_RECOMMENDATIONS: SysctlRecommendation[] = [
  // Network hardening
  { key: "net.ipv4.ip_forward", recommended: "0", description: "Disable IP forwarding", category: "network" },
  { key: "net.ipv4.conf.all.rp_filter", recommended: "1", description: "Enable reverse path filtering", category: "network" },
  { key: "net.ipv4.conf.default.rp_filter", recommended: "1", description: "Enable default reverse path filtering", category: "network" },
  { key: "net.ipv4.conf.all.accept_redirects", recommended: "0", description: "Disable ICMP redirects", category: "network" },
  { key: "net.ipv4.conf.default.accept_redirects", recommended: "0", description: "Disable default ICMP redirects", category: "network" },
  { key: "net.ipv4.conf.all.send_redirects", recommended: "0", description: "Disable sending ICMP redirects", category: "network" },
  { key: "net.ipv4.conf.default.send_redirects", recommended: "0", description: "Disable default sending ICMP redirects", category: "network" },
  { key: "net.ipv4.conf.all.accept_source_route", recommended: "0", description: "Disable source routing", category: "network" },
  { key: "net.ipv4.conf.default.accept_source_route", recommended: "0", description: "Disable default source routing", category: "network" },
  { key: "net.ipv4.conf.all.log_martians", recommended: "1", description: "Log martian packets", category: "network" },
  { key: "net.ipv4.conf.default.log_martians", recommended: "1", description: "Log default martian packets", category: "network" },
  { key: "net.ipv4.conf.all.secure_redirects", recommended: "0", description: "Disable secure ICMP redirects", category: "network" },
  { key: "net.ipv4.conf.default.secure_redirects", recommended: "0", description: "Disable default secure ICMP redirects", category: "network" },
  { key: "net.ipv4.icmp_echo_ignore_broadcasts", recommended: "1", description: "Ignore ICMP broadcast requests", category: "network" },
  { key: "net.ipv4.icmp_ignore_bogus_error_responses", recommended: "1", description: "Ignore bogus ICMP error responses", category: "network" },
  { key: "net.ipv4.tcp_syncookies", recommended: "1", description: "Enable TCP SYN cookies", category: "network" },
  { key: "net.ipv6.conf.all.accept_redirects", recommended: "0", description: "Disable IPv6 ICMP redirects", category: "network" },
  { key: "net.ipv6.conf.default.accept_redirects", recommended: "0", description: "Disable default IPv6 ICMP redirects", category: "network" },
  { key: "net.ipv6.conf.all.accept_source_route", recommended: "0", description: "Disable IPv6 source routing", category: "network" },
  { key: "net.ipv6.conf.all.accept_ra", recommended: "0", description: "Disable IPv6 router advertisements", category: "network" },
  { key: "net.ipv6.conf.default.accept_ra", recommended: "0", description: "Disable default IPv6 router advertisements", category: "network" },
  // Kernel hardening
  { key: "kernel.randomize_va_space", recommended: "2", description: "Full ASLR randomization", category: "kernel" },
  { key: "kernel.sysrq", recommended: "0", description: "Disable SysRq key", category: "kernel" },
  { key: "kernel.core_uses_pid", recommended: "1", description: "Append PID to core dumps", category: "kernel" },
  { key: "kernel.dmesg_restrict", recommended: "1", description: "Restrict dmesg access", category: "kernel" },
  { key: "kernel.kptr_restrict", recommended: "2", description: "Restrict kernel pointer access", category: "kernel" },
  { key: "kernel.yama.ptrace_scope", recommended: "1", description: "Restrict ptrace scope", category: "kernel" },
  { key: "kernel.unprivileged_bpf_disabled", recommended: "1", description: "Disable unprivileged BPF", category: "kernel" },
  { key: "net.core.bpf_jit_harden", recommended: "2", description: "Harden BPF JIT compiler", category: "kernel" },
  { key: "kernel.kexec_load_disabled", recommended: "1", description: "Disable kexec loading", category: "kernel" },
  { key: "kernel.perf_event_paranoid", recommended: "3", description: "Restrict perf events", category: "kernel" },
  { key: "kernel.modules_disabled", recommended: "1", description: "Disable kernel module loading", category: "kernel" },
  { key: "vm.unprivileged_userfaultfd", recommended: "0", description: "Disable unprivileged userfaultfd", category: "kernel" },
  { key: "kernel.io_uring_disabled", recommended: "2", description: "Disable io_uring for unprivileged users", category: "kernel" },
  // Filesystem hardening
  { key: "fs.suid_dumpable", recommended: "0", description: "Disable SUID core dumps", category: "fs" },
  { key: "fs.protected_hardlinks", recommended: "1", description: "Protect hardlinks", category: "fs" },
  { key: "fs.protected_symlinks", recommended: "1", description: "Protect symlinks", category: "fs" },
  { key: "fs.protected_fifos", recommended: "2", description: "Protect FIFO files", category: "fs" },
  { key: "fs.protected_regular", recommended: "2", description: "Protect regular files", category: "fs" },
  // SYN flood tuning parameters
  { key: "net.ipv4.tcp_max_syn_backlog", recommended: "2048", description: "Increase SYN backlog queue to resist SYN flood attacks", category: "network" },
  { key: "net.ipv4.tcp_synack_retries", recommended: "2", description: "Reduce SYN-ACK retries to limit half-open connections", category: "network" },
  { key: "net.ipv4.tcp_syn_retries", recommended: "5", description: "Limit SYN retry attempts", category: "network" },
  { key: "net.ipv4.tcp_timestamps", recommended: "0", description: "Disable TCP timestamps to prevent uptime fingerprinting", category: "network" },
];

// ── Known unnecessary/dangerous services ───────────────────────────────────

const UNNECESSARY_SERVICES = [
  { name: "telnet.socket", reason: "Telnet is unencrypted and insecure" },
  { name: "rsh.socket", reason: "Remote shell is unencrypted and insecure" },
  { name: "rlogin.socket", reason: "Remote login is unencrypted and insecure" },
  { name: "finger.socket", reason: "Finger leaks user information" },
  { name: "talk.socket", reason: "Talk is unencrypted" },
  { name: "ntalk.socket", reason: "Ntalk is unencrypted" },
  { name: "tftp.socket", reason: "TFTP is unencrypted and unauthenticated" },
  { name: "xinetd.service", reason: "Legacy super-server, usually unnecessary" },
  { name: "avahi-daemon.service", reason: "mDNS may expose services unnecessarily" },
  { name: "cups.service", reason: "Print server often unnecessary on servers" },
  { name: "bluetooth.service", reason: "Bluetooth often unnecessary on servers" },
  { name: "rpcbind.service", reason: "RPC portmapper often unnecessary" },
  { name: "nfs-server.service", reason: "NFS server if not needed" },
  { name: "vsftpd.service", reason: "FTP is insecure, prefer SFTP" },
  { name: "snmpd.service", reason: "SNMP may expose system information" },
  { name: "isc-dhcp-server.service", reason: "DHCP server often unnecessary" },
  { name: "slapd.service", reason: "LDAP server if not needed" },
  { name: "named.service", reason: "DNS server if not needed" },
  { name: "dovecot.service", reason: "Mail delivery agent if not needed" },
  { name: "smbd.service", reason: "Samba file sharing may expose data" },
  { name: "nmbd.service", reason: "Samba NetBIOS name service may expose data" },
  { name: "squid.service", reason: "Proxy server if not needed" },
  { name: "apache2.service", reason: "Web server if not needed" },
  { name: "nginx.service", reason: "Web server if not needed" },
];

// ── Critical file permission checks ────────────────────────────────────────

interface PermissionCheck {
  path: string;
  expectedMode: string;
  expectedOwner: string;
  expectedGroup: string;
  scope: "passwd" | "shadow" | "ssh" | "cron" | "critical";
  description: string;
}

const PERMISSION_CHECKS: PermissionCheck[] = [
  { path: "/etc/passwd", expectedMode: "644", expectedOwner: "root", expectedGroup: "root", scope: "passwd", description: "User account database" },
  { path: "/etc/group", expectedMode: "644", expectedOwner: "root", expectedGroup: "root", scope: "passwd", description: "Group database" },
  { path: "/etc/shadow", expectedMode: "640", expectedOwner: "root", expectedGroup: "shadow", scope: "shadow", description: "Password hash database" },
  { path: "/etc/gshadow", expectedMode: "640", expectedOwner: "root", expectedGroup: "shadow", scope: "shadow", description: "Group password database" },
  { path: "/etc/ssh/sshd_config", expectedMode: "600", expectedOwner: "root", expectedGroup: "root", scope: "ssh", description: "SSH server configuration" },
  { path: "/etc/crontab", expectedMode: "600", expectedOwner: "root", expectedGroup: "root", scope: "cron", description: "System crontab" },
  { path: "/etc/cron.d", expectedMode: "700", expectedOwner: "root", expectedGroup: "root", scope: "cron", description: "Cron drop-in directory" },
  { path: "/etc/cron.daily", expectedMode: "700", expectedOwner: "root", expectedGroup: "root", scope: "cron", description: "Daily cron directory" },
  { path: "/etc/cron.hourly", expectedMode: "700", expectedOwner: "root", expectedGroup: "root", scope: "cron", description: "Hourly cron directory" },
  { path: "/etc/cron.weekly", expectedMode: "700", expectedOwner: "root", expectedGroup: "root", scope: "cron", description: "Weekly cron directory" },
  { path: "/etc/cron.monthly", expectedMode: "700", expectedOwner: "root", expectedGroup: "root", scope: "cron", description: "Monthly cron directory" },
  { path: "/etc/sudoers", expectedMode: "440", expectedOwner: "root", expectedGroup: "root", scope: "critical", description: "Sudoers configuration" },
  { path: "/etc/sudoers.d", expectedMode: "750", expectedOwner: "root", expectedGroup: "root", scope: "critical", description: "Sudoers drop-in directory" },
  { path: "/boot/grub/grub.cfg", expectedMode: "600", expectedOwner: "root", expectedGroup: "root", scope: "critical", description: "GRUB configuration" },
];

// ── Registration entry point ───────────────────────────────────────────────

export function registerHardeningTools(server: McpServer): void {
  // ── 1. harden_sysctl_get ───────────────────────────────────────────────

  server.tool(
    "harden_sysctl_get",
    "Get sysctl kernel parameter value(s). Query a specific key, all values, or filter by pattern.",
    {
      key: z
        .string()
        .optional()
        .describe("Specific sysctl key to query (e.g., net.ipv4.ip_forward)"),
      all: z
        .boolean()
        .optional()
        .default(false)
        .describe("Return all sysctl values"),
      pattern: z
        .string()
        .optional()
        .describe("Filter sysctl keys matching this substring pattern"),
    },
    async ({ key, all, pattern }) => {
      try {
        if (key) {
          const validatedKey = validateSysctlKey(key);
          const result = await executeCommand({
            command: "sysctl",
            args: [validatedKey],
            toolName: "harden_sysctl_get",
            timeout: getToolTimeout("harden_sysctl_get"),
          });

          if (result.exitCode !== 0) {
            return {
              content: [
                createErrorContent(
                  `sysctl get failed (exit ${result.exitCode}): ${result.stderr}`
                ),
              ],
              isError: true,
            };
          }

          const entries = parseSysctlOutput(result.stdout);
          return { content: [formatToolOutput({ key: validatedKey, entries })] };
        }

        if (all || pattern) {
          const result = await executeCommand({
            command: "sysctl",
            args: ["-a"],
            toolName: "harden_sysctl_get",
            timeout: getToolTimeout("harden_sysctl_get"),
          });

          if (result.exitCode !== 0) {
            return {
              content: [
                createErrorContent(
                  `sysctl -a failed (exit ${result.exitCode}): ${result.stderr}`
                ),
              ],
              isError: true,
            };
          }

          let entries = parseSysctlOutput(result.stdout);

          if (pattern) {
            const lowerPattern = pattern.toLowerCase();
            entries = entries.filter((e) =>
              e.key.toLowerCase().includes(lowerPattern)
            );
          }

          return {
            content: [
              formatToolOutput({
                count: entries.length,
                pattern: pattern ?? "all",
                entries,
              }),
            ],
          };
        }

        return {
          content: [
            createErrorContent(
              "Specify either 'key', 'all: true', or 'pattern' to query sysctl values"
            ),
          ],
          isError: true,
        };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 2. harden_sysctl_set ───────────────────────────────────────────────

  server.tool(
    "harden_sysctl_set",
    "Set a sysctl kernel parameter. Optionally make it persistent across reboots.",
    {
      key: z.string().describe("Sysctl key to set (e.g., net.ipv4.ip_forward)"),
      value: z.string().describe("Value to set"),
      persistent: z
        .boolean()
        .optional()
        .default(false)
        .describe("Write to /etc/sysctl.d/99-kali-defense.conf for persistence"),
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview the command without executing (defaults to KALI_DEFENSE_DRY_RUN env var)"),
    },
    async ({ key, value, persistent, dry_run }) => {
      try {
        const validatedKey = validateSysctlKey(key);
        sanitizeArgs([value]);

        // Get current value for before state
        const currentResult = await executeCommand({
          command: "sysctl",
          args: [validatedKey],
          toolName: "harden_sysctl_set",
        });

        const beforeValue = currentResult.stdout.trim();
        const fullCmd = `sudo sysctl -w ${validatedKey}=${value}`;
        const persistPath = "/etc/sysctl.d/99-kali-defense.conf";

        if (dry_run ?? getConfig().dryRun) {
          let preview = `[DRY-RUN] Would execute:\n  ${fullCmd}\n\nCurrent value: ${beforeValue}`;
          if (persistent) {
            preview += `\n\nWould also append to ${persistPath}:\n  ${validatedKey} = ${value}`;
          }

          const entry = createChangeEntry({
            tool: "harden_sysctl_set",
            action: `[DRY-RUN] Set sysctl ${validatedKey}`,
            target: validatedKey,
            before: beforeValue,
            after: `${validatedKey} = ${value}`,
            dryRun: true,
            success: true,
            rollbackCommand: beforeValue
              ? `sudo sysctl -w ${beforeValue}`
              : undefined,
          });
          logChange(entry);

          return { content: [createTextContent(preview)] };
        }

        // Set the value
        const result = await executeCommand({
          command: "sudo",
          args: ["sysctl", "-w", `${validatedKey}=${value}`],
          toolName: "harden_sysctl_set",
          timeout: getToolTimeout("harden_sysctl_set"),
        });

        const success = result.exitCode === 0;

        // Persist if requested
        let persistResult = "";
        if (success && persistent) {
          // Backup existing file
          try {
            backupFile(persistPath);
          } catch {
            // File may not exist yet
          }

          // Ensure persistence directory exists
          await executeCommand({
            command: "sudo",
            args: ["mkdir", "-p", "/etc/sysctl.d"],
            toolName: "harden_sysctl_set",
          });

          // Dedup: remove any existing entry for this key to prevent duplicate lines
          await executeCommand({
            command: "sudo",
            args: ["sed", "-i", `/^${validatedKey}\\s*=/d`, persistPath],
            toolName: "harden_sysctl_set",
          });

          // Append using printf piped to tee (avoids shell interpretation of value)
          const appendResult = await executeCommand({
            command: "bash",
            args: [
              "-c",
              `printf '%s\\n' '${validatedKey} = ${value}' | sudo tee -a ${persistPath} > /dev/null`,
            ],
            toolName: "harden_sysctl_set",
          });

          persistResult = appendResult.exitCode === 0
            ? `\nPersisted to ${persistPath}`
            : `\nWarning: Failed to persist: ${appendResult.stderr}`;
        }

        const rollbackCmd = beforeValue
          ? `sudo sysctl -w ${beforeValue}`
          : undefined;

        const entry = createChangeEntry({
          tool: "harden_sysctl_set",
          action: `Set sysctl ${validatedKey}=${value}`,
          target: validatedKey,
          before: beforeValue,
          after: `${validatedKey} = ${value}`,
          dryRun: false,
          success,
          error: success ? undefined : result.stderr,
          rollbackCommand: rollbackCmd,
        });
        logChange(entry);

        if (!success) {
          return {
            content: [
              createErrorContent(
                `sysctl set failed (exit ${result.exitCode}): ${result.stderr}`
              ),
            ],
            isError: true,
          };
        }

        return {
          content: [
            createTextContent(
              `Set ${validatedKey} = ${value}\nPrevious: ${beforeValue}${persistResult}\nRollback: ${rollbackCmd ?? "N/A"}`
            ),
          ],
        };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 3. harden_sysctl_audit ─────────────────────────────────────────────

  server.tool(
    "harden_sysctl_audit",
    "Audit sysctl settings against security hardening recommendations. Checks common CIS/STIG parameters.",
    {
      category: z
        .enum(["network", "kernel", "fs", "all"])
        .optional()
        .default("all")
        .describe("Category of settings to audit (default: all)"),
    },
    async ({ category }) => {
      try {
        // Get all current sysctl values
        const result = await executeCommand({
          command: "sysctl",
          args: ["-a"],
          toolName: "harden_sysctl_audit",
          timeout: getToolTimeout("harden_sysctl_audit"),
        });

        if (result.exitCode !== 0) {
          return {
            content: [
              createErrorContent(
                `sysctl -a failed (exit ${result.exitCode}): ${result.stderr}`
              ),
            ],
            isError: true,
          };
        }

        const entries = parseSysctlOutput(result.stdout);
        const currentValues = new Map(entries.map((e) => [e.key, e.value]));

        // Filter recommendations by category
        const checks =
          category === "all"
            ? SYSCTL_RECOMMENDATIONS
            : SYSCTL_RECOMMENDATIONS.filter((r) => r.category === category);

        const findings: Array<{
          key: string;
          current: string;
          recommended: string;
          description: string;
          compliant: boolean;
          category: string;
        }> = [];

        let compliantCount = 0;
        let nonCompliantCount = 0;
        let unknownCount = 0;

        for (const check of checks) {
          const current = currentValues.get(check.key);
          if (current === undefined) {
            unknownCount++;
            findings.push({
              key: check.key,
              current: "NOT SET",
              recommended: check.recommended,
              description: check.description,
              compliant: false,
              category: check.category,
            });
          } else if (current === check.recommended) {
            compliantCount++;
            findings.push({
              key: check.key,
              current,
              recommended: check.recommended,
              description: check.description,
              compliant: true,
              category: check.category,
            });
          } else {
            nonCompliantCount++;
            findings.push({
              key: check.key,
              current,
              recommended: check.recommended,
              description: check.description,
              compliant: false,
              category: check.category,
            });
          }
        }

        const output = {
          category,
          summary: {
            total: checks.length,
            compliant: compliantCount,
            nonCompliant: nonCompliantCount,
            unknown: unknownCount,
            compliancePercent:
              checks.length > 0
                ? Math.round((compliantCount / checks.length) * 100)
                : 0,
          },
          findings,
        };

        return { content: [formatToolOutput(output)] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 4. harden_service_manage ───────────────────────────────────────────

  server.tool(
    "harden_service_manage",
    "Manage systemd services: enable, disable, start, stop, restart, mask, unmask, or check status",
    {
      service: z
        .string()
        .describe("Service name (e.g., ssh.service, bluetooth.service)"),
      action: z
        .enum([
          "enable",
          "disable",
          "stop",
          "start",
          "restart",
          "mask",
          "unmask",
          "status",
        ])
        .describe("Action to perform on the service"),
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview the command without executing (defaults to KALI_DEFENSE_DRY_RUN env var)"),
    },
    async ({ service, action, dry_run }) => {
      try {
        const validatedService = validateServiceName(service);
        const fullCmd = `sudo systemctl ${action} ${validatedService}`;

        // Status is always read-only, skip dry_run check
        if (action === "status") {
          const result = await executeCommand({
            command: "systemctl",
            args: ["status", validatedService],
            toolName: "harden_service_manage",
            timeout: getToolTimeout("harden_service_manage"),
          });

          // systemctl status returns exit 3 for inactive services — not an error
          return {
            content: [
              createTextContent(
                `Service: ${validatedService}\n\n${result.stdout}${result.stderr ? `\n${result.stderr}` : ""}`
              ),
            ],
          };
        }

        // Determine rollback action
        const rollbackActions: Record<string, string> = {
          enable: "disable",
          disable: "enable",
          stop: "start",
          start: "stop",
          restart: "restart",
          mask: "unmask",
          unmask: "mask",
        };
        const rollbackCmd = `sudo systemctl ${rollbackActions[action]} ${validatedService}`;

        if (dry_run ?? getConfig().dryRun) {
          const entry = createChangeEntry({
            tool: "harden_service_manage",
            action: `[DRY-RUN] ${action} service`,
            target: validatedService,
            dryRun: true,
            success: true,
            rollbackCommand: rollbackCmd,
          });
          logChange(entry);

          return {
            content: [
              createTextContent(
                `[DRY-RUN] Would execute:\n  ${fullCmd}\n\nRollback:\n  ${rollbackCmd}`
              ),
            ],
          };
        }

        // Get before state
        const beforeResult = await executeCommand({
          command: "systemctl",
          args: ["is-active", validatedService],
          toolName: "harden_service_manage",
        });
        const beforeState = beforeResult.stdout.trim();

        const result = await executeCommand({
          command: "sudo",
          args: ["systemctl", action, validatedService],
          toolName: "harden_service_manage",
          timeout: getToolTimeout("harden_service_manage"),
        });

        const success = result.exitCode === 0;

        // Get after state
        const afterResult = await executeCommand({
          command: "systemctl",
          args: ["is-active", validatedService],
          toolName: "harden_service_manage",
        });
        const afterState = afterResult.stdout.trim();

        const entry = createChangeEntry({
          tool: "harden_service_manage",
          action: `${action} service`,
          target: validatedService,
          before: beforeState,
          after: afterState,
          dryRun: false,
          success,
          error: success ? undefined : result.stderr,
          rollbackCommand: rollbackCmd,
        });
        logChange(entry);

        if (!success) {
          return {
            content: [
              createErrorContent(
                `systemctl ${action} failed (exit ${result.exitCode}): ${result.stderr}`
              ),
            ],
            isError: true,
          };
        }

        return {
          content: [
            createTextContent(
              `Service ${validatedService}: ${action} completed.\nBefore: ${beforeState}\nAfter: ${afterState}\nRollback: ${rollbackCmd}\n\n${result.stdout}`
            ),
          ],
        };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 5. harden_service_audit ────────────────────────────────────────────

  server.tool(
    "harden_service_audit",
    "Audit running services for unnecessary or potentially dangerous ones",
    {
      show_all: z
        .boolean()
        .optional()
        .default(false)
        .describe("Show all running services, not just flagged ones"),
    },
    async ({ show_all }) => {
      try {
        const result = await executeCommand({
          command: "systemctl",
          args: [
            "list-units",
            "--type=service",
            "--state=running",
            "--no-pager",
            "--no-legend",
          ],
          toolName: "harden_service_audit",
          timeout: getToolTimeout("harden_service_audit"),
        });

        if (result.exitCode !== 0) {
          return {
            content: [
              createErrorContent(
                `systemctl list-units failed (exit ${result.exitCode}): ${result.stderr}`
              ),
            ],
            isError: true,
          };
        }

        const units = parseSystemctlOutput(result.stdout);
        const runningServices = units.map((u) => u.unit);

        // Check for unnecessary services
        const flagged: Array<{
          service: string;
          reason: string;
          running: boolean;
        }> = [];

        for (const check of UNNECESSARY_SERVICES) {
          const isRunning = runningServices.some(
            (s) =>
              s === check.name ||
              s.startsWith(check.name.replace(".service", "").replace(".socket", ""))
          );
          if (isRunning) {
            flagged.push({
              service: check.name,
              reason: check.reason,
              running: true,
            });
          }
        }

        const output: Record<string, unknown> = {
          totalRunning: runningServices.length,
          flaggedCount: flagged.length,
          flaggedServices: flagged,
        };

        if (show_all) {
          output.allRunningServices = units;
        }

        if (flagged.length === 0) {
          output.assessment =
            "No known unnecessary or dangerous services detected running.";
        } else {
          output.assessment = `Found ${flagged.length} potentially unnecessary service(s). Review and consider disabling with harden_service_manage.`;
        }

        return { content: [formatToolOutput(output)] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 6. harden_file_permissions ─────────────────────────────────────────

  server.tool(
    "harden_file_permissions",
    "Audit or fix file permissions, ownership, and group for a given path",
    {
      path: z.string().describe("File or directory path to audit/modify"),
      mode: z
        .string()
        .optional()
        .describe("Desired octal permissions (e.g., '600', '755'). If set, will chmod."),
      owner: z
        .string()
        .optional()
        .describe("Desired owner (e.g., 'root'). If set, will chown."),
      group: z
        .string()
        .optional()
        .describe("Desired group (e.g., 'root'). If set, will chgrp."),
      recursive: z
        .boolean()
        .optional()
        .default(false)
        .describe("Apply changes recursively"),
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview the command without executing (defaults to KALI_DEFENSE_DRY_RUN env var)"),
    },
    async ({ path, mode, owner, group, recursive, dry_run }) => {
      try {
        // Get current permissions
        const statResult = await executeCommand({
          command: "stat",
          args: ["-c", "%a %U %G %n", path],
          toolName: "harden_file_permissions",
        });

        const beforeState = statResult.stdout.trim();
        const isModifying = mode || owner || group;

        // If no modifications requested, just audit
        if (!isModifying) {
          const lsResult = await executeCommand({
            command: "ls",
            args: ["-la", path],
            toolName: "harden_file_permissions",
          });

          return {
            content: [
              createTextContent(
                `File permissions audit for: ${path}\n\nstat: ${beforeState}\n\n${lsResult.stdout}`
              ),
            ],
          };
        }

        const commands: string[] = [];

        if (mode) {
          sanitizeArgs([mode]);
          const chmodArgs = recursive ? ["-R", mode, path] : [mode, path];
          commands.push(`sudo chmod ${chmodArgs.join(" ")}`);
        }

        if (owner || group) {
          const ownerGroup = `${owner ?? ""}${group ? `:${group}` : ""}`;
          sanitizeArgs([ownerGroup]);
          const chownArgs = recursive
            ? ["-R", ownerGroup, path]
            : [ownerGroup, path];
          commands.push(`sudo chown ${chownArgs.join(" ")}`);
        }

        if (dry_run ?? getConfig().dryRun) {
          const entry = createChangeEntry({
            tool: "harden_file_permissions",
            action: `[DRY-RUN] Change permissions`,
            target: path,
            before: beforeState,
            dryRun: true,
            success: true,
          });
          logChange(entry);

          return {
            content: [
              createTextContent(
                `[DRY-RUN] Current: ${beforeState}\n\nWould execute:\n${commands.map((c) => `  ${c}`).join("\n")}`
              ),
            ],
          };
        }

        // Execute chmod if needed
        if (mode) {
          const chmodArgs = recursive
            ? ["chmod", "-R", mode, path]
            : ["chmod", mode, path];
          const chmodResult = await executeCommand({
            command: "sudo",
            args: chmodArgs,
            toolName: "harden_file_permissions",
            timeout: getToolTimeout("harden_file_permissions"),
          });
          if (chmodResult.exitCode !== 0) {
            return {
              content: [
                createErrorContent(
                  `chmod failed (exit ${chmodResult.exitCode}): ${chmodResult.stderr}`
                ),
              ],
              isError: true,
            };
          }
        }

        // Execute chown if needed
        if (owner || group) {
          const ownerGroup = `${owner ?? ""}${group ? `:${group}` : ""}`;
          const chownArgs = recursive
            ? ["chown", "-R", ownerGroup, path]
            : ["chown", ownerGroup, path];
          const chownResult = await executeCommand({
            command: "sudo",
            args: chownArgs,
            toolName: "harden_file_permissions",
            timeout: getToolTimeout("harden_file_permissions"),
          });
          if (chownResult.exitCode !== 0) {
            return {
              content: [
                createErrorContent(
                  `chown failed (exit ${chownResult.exitCode}): ${chownResult.stderr}`
                ),
              ],
              isError: true,
            };
          }
        }

        // Get after state
        const afterStatResult = await executeCommand({
          command: "stat",
          args: ["-c", "%a %U %G %n", path],
          toolName: "harden_file_permissions",
        });
        const afterState = afterStatResult.stdout.trim();

        const entry = createChangeEntry({
          tool: "harden_file_permissions",
          action: `Change permissions`,
          target: path,
          before: beforeState,
          after: afterState,
          dryRun: false,
          success: true,
        });
        logChange(entry);

        return {
          content: [
            createTextContent(
              `Permissions updated for ${path}\nBefore: ${beforeState}\nAfter: ${afterState}\nCommands: ${commands.join("; ")}`
            ),
          ],
        };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 7. harden_permissions_audit ────────────────────────────────────────

  server.tool(
    "harden_permissions_audit",
    "Audit critical system file permissions against security best practices (CIS benchmarks)",
    {
      scope: z
        .enum(["passwd", "shadow", "ssh", "cron", "critical", "all"])
        .optional()
        .default("all")
        .describe("Scope of files to audit (default: all)"),
    },
    async ({ scope }) => {
      try {
        const checks =
          scope === "all"
            ? PERMISSION_CHECKS
            : PERMISSION_CHECKS.filter((c) => c.scope === scope);

        const results: Array<{
          path: string;
          description: string;
          expected: string;
          actual: string;
          compliant: boolean;
          exists: boolean;
        }> = [];

        let compliantCount = 0;
        let nonCompliantCount = 0;
        let missingCount = 0;

        for (const check of checks) {
          const statResult = await executeCommand({
            command: "stat",
            args: ["-c", "%a %U %G", check.path],
            toolName: "harden_permissions_audit",
          });

          if (statResult.exitCode !== 0) {
            missingCount++;
            results.push({
              path: check.path,
              description: check.description,
              expected: `${check.expectedMode} ${check.expectedOwner}:${check.expectedGroup}`,
              actual: "FILE NOT FOUND",
              compliant: false,
              exists: false,
            });
            continue;
          }

          const parts = statResult.stdout.trim().split(" ");
          const actualMode = parts[0] ?? "";
          const actualOwner = parts[1] ?? "";
          const actualGroup = parts[2] ?? "";

          const modeOk = actualMode === check.expectedMode;
          const ownerOk = actualOwner === check.expectedOwner;
          const groupOk = actualGroup === check.expectedGroup;
          const compliant = modeOk && ownerOk && groupOk;

          if (compliant) {
            compliantCount++;
          } else {
            nonCompliantCount++;
          }

          results.push({
            path: check.path,
            description: check.description,
            expected: `${check.expectedMode} ${check.expectedOwner}:${check.expectedGroup}`,
            actual: `${actualMode} ${actualOwner}:${actualGroup}`,
            compliant,
            exists: true,
          });
        }

        const total = checks.length;
        const output = {
          scope,
          summary: {
            total,
            compliant: compliantCount,
            nonCompliant: nonCompliantCount,
            missing: missingCount,
            compliancePercent:
              total > 0
                ? Math.round((compliantCount / total) * 100)
                : 0,
          },
          results,
        };

        return { content: [formatToolOutput(output)] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 8. harden_systemd_audit ──────────────────────────────────────────

  server.tool(
    "harden_systemd_audit",
    "Audit systemd service units for security hardening using systemd-analyze security. Scores 40+ security properties per service including sandboxing, capability restrictions, and namespace isolation.",
    {
      service: z.string().optional().describe("Specific service to audit, e.g. 'sshd'. Omit to audit all running services."),
      threshold: z.number().optional().default(5).describe("Exposure score threshold (0-10). Services scoring above this are flagged."),
    },
    async (params) => {
      try {
        if (params.service) {
          // Audit specific service
          const result = await executeCommand({
            command: "systemd-analyze",
            args: ["security", params.service],
            timeout: 30000,
            toolName: "harden_systemd_audit",
          });

          // Parse the output - extract EXPOSURE line and individual checks
          const lines = (result.stdout + result.stderr).split("\n");
          const exposureLine = lines.find(l => l.includes("EXPOSURE"));
          let score = "unknown";
          let rating = "unknown";
          if (exposureLine) {
            const match = exposureLine.match(/(\d+\.?\d*)\s+(OK|EXPOSED|MEDIUM|UNSAFE)/i);
            if (match) { score = match[1]; rating = match[2]; }
          }

          // Collect failed checks
          const findings: Array<{property: string, status: string, description: string}> = [];
          for (const line of lines) {
            // Lines look like: "✓ PrivateTmp=           yes" or "✗ ProtectSystem=        no"
            const checkMatch = line.match(/^[✓✗→◌]\s+(\S+)=?\s+(.*)/);
            if (checkMatch && (line.startsWith("✗") || line.startsWith("→"))) {
              findings.push({
                property: checkMatch[1].replace(/=$/, ""),
                status: line.startsWith("✗") ? "FAIL" : "WARNING",
                description: checkMatch[2].trim(),
              });
            }
          }

          return {
            content: [createTextContent(JSON.stringify({
              service: params.service,
              exposureScore: parseFloat(score) || 0,
              rating,
              totalFindings: findings.length,
              findings: findings.slice(0, 50), // Limit output
              rawExposureLine: exposureLine || "Not found",
            }, null, 2))],
          };
        } else {
          // Audit all running services
          const result = await executeCommand({
            command: "systemd-analyze",
            args: ["security", "--no-pager"],
            timeout: 60000,
            toolName: "harden_systemd_audit",
          });

          const lines = (result.stdout + result.stderr).split("\n").filter(l => l.trim());
          const services: Array<{unit: string, exposure: number, rating: string, flagged: boolean}> = [];

          for (const line of lines) {
            // Lines: "UNIT                         EXPOSURE PREDICATE HAPPY"
            // or   "sshd.service                     7.8 EXPOSED   🙁"
            const match = line.match(/^(\S+\.service)\s+(\d+\.?\d*)\s+(\S+)\s+/);
            if (match) {
              const exposure = parseFloat(match[2]);
              services.push({
                unit: match[1],
                exposure,
                rating: match[3],
                flagged: exposure > params.threshold,
              });
            }
          }

          services.sort((a, b) => b.exposure - a.exposure);
          const flagged = services.filter(s => s.flagged);

          return {
            content: [createTextContent(JSON.stringify({
              summary: {
                totalServices: services.length,
                flaggedAboveThreshold: flagged.length,
                threshold: params.threshold,
                averageExposure: services.length > 0
                  ? (services.reduce((sum, s) => sum + s.exposure, 0) / services.length).toFixed(1)
                  : 0,
              },
              flaggedServices: flagged,
              allServices: services,
            }, null, 2))],
          };
        }
      } catch (error) {
        return {
          content: [createErrorContent(error instanceof Error ? error.message : String(error))],
          isError: true,
        };
      }
    },
  );

  // ── 9. harden_kernel_security_audit ──────────────────────────────────

  server.tool(
    "harden_kernel_security_audit",
    "Audit Linux kernel security features including CPU vulnerability mitigations, Landlock LSM, lockdown mode, ASLR, and kernel self-protection.",
    {
      check_type: z.enum(["cpu_vulns", "lsm", "lockdown", "features", "all"]).optional().default("all").describe("Type of kernel security check"),
    },
    async (params) => {
      try {
        const findings: Array<{check: string, status: string, value: string, description: string}> = [];
        const checkType = params.check_type;

        // CPU Vulnerability Mitigations
        if (checkType === "cpu_vulns" || checkType === "all") {
          const vulnDir = "/sys/devices/system/cpu/vulnerabilities";
          const lsResult = await executeCommand({
            command: "ls",
            args: [vulnDir],
            timeout: 5000,
            toolName: "harden_kernel_security_audit",
          });

          if (lsResult.exitCode === 0) {
            for (const vuln of lsResult.stdout.trim().split("\n").filter(v => v.trim())) {
              const catResult = await executeCommand({
                command: "cat",
                args: [`${vulnDir}/${vuln.trim()}`],
                timeout: 5000,
                toolName: "harden_kernel_security_audit",
              });
              const value = catResult.stdout.trim();
              const mitigated = value.toLowerCase().includes("not affected") || value.toLowerCase().includes("mitigat");
              findings.push({
                check: `cpu_vuln_${vuln.trim()}`,
                status: mitigated ? "PASS" : (value.toLowerCase().includes("vulnerable") ? "FAIL" : "INFO"),
                value,
                description: `CPU vulnerability: ${vuln.trim()}`,
              });
            }
          }
        }

        // Linux Security Modules
        if (checkType === "lsm" || checkType === "all") {
          const lsmResult = await executeCommand({
            command: "cat",
            args: ["/sys/kernel/security/lsm"],
            timeout: 5000,
            toolName: "harden_kernel_security_audit",
          });
          findings.push({
            check: "active_lsms",
            status: lsmResult.stdout.includes("apparmor") || lsmResult.stdout.includes("selinux") ? "PASS" : "WARN",
            value: lsmResult.stdout.trim(),
            description: "Active Linux Security Modules",
          });

          // Check Landlock
          findings.push({
            check: "landlock_available",
            status: lsmResult.stdout.includes("landlock") ? "PASS" : "INFO",
            value: lsmResult.stdout.includes("landlock") ? "enabled" : "not in LSM list",
            description: "Landlock LSM for filesystem sandboxing",
          });
        }

        // Lockdown mode
        if (checkType === "lockdown" || checkType === "all") {
          const lockdownResult = await executeCommand({
            command: "cat",
            args: ["/sys/kernel/security/lockdown"],
            timeout: 5000,
            toolName: "harden_kernel_security_audit",
          });
          const lockdownValue = lockdownResult.stdout.trim();
          const isLocked = lockdownValue.includes("[integrity]") || lockdownValue.includes("[confidentiality]");
          findings.push({
            check: "kernel_lockdown",
            status: isLocked ? "PASS" : "WARN",
            value: lockdownValue,
            description: "Kernel lockdown mode (integrity/confidentiality)",
          });
        }

        // General features
        if (checkType === "features" || checkType === "all") {
          // KASLR
          const kaslrResult = await executeCommand({
            command: "cat",
            args: ["/proc/cmdline"],
            timeout: 5000,
            toolName: "harden_kernel_security_audit",
          });
          const cmdline = kaslrResult.stdout.trim();
          findings.push({
            check: "kaslr",
            status: cmdline.includes("nokaslr") ? "FAIL" : "PASS",
            value: cmdline.includes("nokaslr") ? "disabled" : "enabled",
            description: "Kernel Address Space Layout Randomization",
          });

          // Secure boot
          const secbootResult = await executeCommand({
            command: "mokutil",
            args: ["--sb-state"],
            timeout: 5000,
            toolName: "harden_kernel_security_audit",
          });
          const secBoot = secbootResult.stdout.trim() || secbootResult.stderr.trim();
          findings.push({
            check: "secure_boot",
            status: secBoot.toLowerCase().includes("secureboot enabled") ? "PASS" : "WARN",
            value: secBoot || "unknown",
            description: "UEFI Secure Boot status",
          });

          // Stack protector / kernel config
          const configResult = await executeCommand({
            command: "zgrep",
            args: ["CONFIG_STACKPROTECTOR", "/proc/config.gz"],
            timeout: 5000,
            toolName: "harden_kernel_security_audit",
          });
          if (configResult.exitCode === 0) {
            findings.push({
              check: "stack_protector",
              status: configResult.stdout.includes("=y") ? "PASS" : "WARN",
              value: configResult.stdout.trim(),
              description: "Kernel stack protector",
            });
          }
        }

        const passCount = findings.filter(f => f.status === "PASS").length;
        const failCount = findings.filter(f => f.status === "FAIL").length;
        const warnCount = findings.filter(f => f.status === "WARN").length;

        return {
          content: [createTextContent(JSON.stringify({
            summary: {
              total: findings.length,
              pass: passCount,
              fail: failCount,
              warn: warnCount,
              info: findings.length - passCount - failCount - warnCount,
            },
            findings,
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

  // ── 10. harden_bootloader_audit ──────────────────────────────────────

  server.tool(
    "harden_bootloader_audit",
    "Audit bootloader (GRUB) security configuration including password protection, Secure Boot status, and kernel command line parameters.",
    {},
    async () => {
      try {
        const findings: Array<{check: string, status: string, value: string, description: string}> = [];

        // Check GRUB password protection
        const grubCfg = await executeCommand({
          command: "sudo",
          args: ["grep", "-r", "password", "/etc/grub.d/", "/boot/grub/grub.cfg"],
          timeout: 10000,
          toolName: "harden_bootloader_audit",
        });
        findings.push({
          check: "grub_password",
          status: grubCfg.stdout.includes("password") ? "PASS" : "FAIL",
          value: grubCfg.stdout.includes("password") ? "configured" : "not configured",
          description: "GRUB bootloader password protection",
        });

        // Check GRUB config permissions
        const grubPerms = await executeCommand({
          command: "stat",
          args: ["-c", "%a %U:%G", "/boot/grub/grub.cfg"],
          timeout: 5000,
          toolName: "harden_bootloader_audit",
        });
        const permsValue = grubPerms.stdout.trim();
        const permOk = permsValue.startsWith("400") || permsValue.startsWith("600");
        findings.push({
          check: "grub_config_perms",
          status: permOk ? "PASS" : "FAIL",
          value: permsValue,
          description: "GRUB config file permissions (should be 400/600 root:root)",
        });

        // Check kernel command line for security params
        const cmdline = await executeCommand({
          command: "cat",
          args: ["/proc/cmdline"],
          timeout: 5000,
          toolName: "harden_bootloader_audit",
        });
        const cmd = cmdline.stdout.trim();

        const kernelParams = [
          { param: "nokaslr", bad: true, desc: "KASLR disabled" },
          { param: "init_on_alloc=1", bad: false, desc: "Zero memory on allocation" },
          { param: "init_on_free=1", bad: false, desc: "Zero memory on free" },
          { param: "slab_nomerge", bad: false, desc: "Disable SLAB merging" },
          { param: "page_alloc.shuffle=1", bad: false, desc: "Page allocator randomization" },
          { param: "randomize_kstack_offset=on", bad: false, desc: "Kernel stack offset randomization" },
          { param: "vsyscall=none", bad: false, desc: "Disable vsyscall" },
          { param: "lockdown=integrity", bad: false, desc: "Kernel lockdown integrity mode" },
          { param: "lockdown=confidentiality", bad: false, desc: "Kernel lockdown confidentiality mode" },
        ];

        for (const kp of kernelParams) {
          const present = cmd.includes(kp.param.split("=")[0]);
          if (kp.bad) {
            findings.push({
              check: `cmdline_${kp.param.replace(/[=]/g, "_")}`,
              status: present ? "FAIL" : "PASS",
              value: present ? "present (BAD)" : "not present (GOOD)",
              description: kp.desc,
            });
          } else {
            findings.push({
              check: `cmdline_${kp.param.replace(/[=]/g, "_")}`,
              status: present ? "PASS" : "INFO",
              value: present ? "present" : "not set (recommended)",
              description: kp.desc,
            });
          }
        }

        // Secure Boot
        const secboot = await executeCommand({
          command: "mokutil",
          args: ["--sb-state"],
          timeout: 5000,
          toolName: "harden_bootloader_audit",
        });
        const sbState = (secboot.stdout + secboot.stderr).trim();
        findings.push({
          check: "secure_boot",
          status: sbState.toLowerCase().includes("secureboot enabled") ? "PASS" : "WARN",
          value: sbState || "unknown",
          description: "UEFI Secure Boot status",
        });

        const passCount = findings.filter(f => f.status === "PASS").length;
        const failCount = findings.filter(f => f.status === "FAIL").length;

        return {
          content: [createTextContent(JSON.stringify({
            summary: {
              total: findings.length,
              pass: passCount,
              fail: failCount,
              warn: findings.filter(f => f.status === "WARN").length,
              info: findings.filter(f => f.status === "INFO").length,
            },
            kernelCommandLine: cmd,
            findings,
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

  // ── harden_module_audit ───────────────────────────────────────────────
  server.tool(
    "harden_module_audit",
    "Audit kernel module blacklisting per CIS benchmark. Checks that unused/dangerous filesystem and network protocol modules are disabled.",
    {},
    async () => {
      try {
        const MODULES_TO_DISABLE = [
          { name: "cramfs", description: "CramFS filesystem", cis: "1.1.1.1" },
          { name: "squashfs", description: "SquashFS filesystem", cis: "1.1.1.2" },
          { name: "udf", description: "UDF filesystem", cis: "1.1.1.3" },
          { name: "freevxfs", description: "FreeVXFS filesystem", cis: "1.1.1.1" },
          { name: "jffs2", description: "JFFS2 filesystem", cis: "1.1.1.1" },
          { name: "hfs", description: "HFS filesystem", cis: "1.1.1.1" },
          { name: "hfsplus", description: "HFS+ filesystem", cis: "1.1.1.1" },
          { name: "usb-storage", description: "USB storage", cis: "1.1.1.4" },
          { name: "dccp", description: "DCCP protocol", cis: "3.4.1" },
          { name: "sctp", description: "SCTP protocol", cis: "3.4.2" },
          { name: "rds", description: "RDS protocol", cis: "3.4.3" },
          { name: "tipc", description: "TIPC protocol", cis: "3.4.4" },
        ];

        const results = [];
        for (const mod of MODULES_TO_DISABLE) {
          // Check if module is blacklisted
          const blacklistResult = await executeCommand({ command: "grep", args: ["-r", `install ${mod.name} /bin/true`, "/etc/modprobe.d/"], timeout: 5000, toolName: "harden_module_audit" });
          const blacklisted = blacklistResult.exitCode === 0 && blacklistResult.stdout.trim().length > 0;
          // Check if module is loaded
          const loadedResult = await executeCommand({ command: "lsmod", args: [], timeout: 5000, toolName: "harden_module_audit" });
          const loaded = loadedResult.stdout.includes(mod.name);
          results.push({ module: mod.name, description: mod.description, cis: mod.cis, blacklisted, loaded, status: blacklisted && !loaded ? "PASS" : loaded ? "FAIL" : "WARN" });
        }

        const passCount = results.filter(r => r.status === "PASS").length;
        return { content: [createTextContent(JSON.stringify({ summary: { total: results.length, pass: passCount, fail: results.filter(r => r.status === "FAIL").length, warn: results.filter(r => r.status === "WARN").length }, results }, null, 2))] };
      } catch (error) {
        return { content: [createErrorContent(error instanceof Error ? error.message : String(error))], isError: true };
      }
    },
  );

  // ── harden_cron_audit ─────────────────────────────────────────────────
  server.tool(
    "harden_cron_audit",
    "Audit cron and at access control configuration per CIS benchmarks (cron.allow, cron.deny, at.allow, at.deny).",
    {},
    async () => {
      try {
        const findings: Array<{check: string, status: string, value: string, description: string}> = [];

        // Check cron.deny vs cron.allow
        const cronDeny = await executeCommand({ command: "ls", args: ["-la", "/etc/cron.deny"], timeout: 5000, toolName: "harden_cron_audit" });
        const cronAllow = await executeCommand({ command: "ls", args: ["-la", "/etc/cron.allow"], timeout: 5000, toolName: "harden_cron_audit" });
        findings.push({ check: "cron_deny", status: cronDeny.exitCode !== 0 ? "PASS" : "WARN", value: cronDeny.exitCode === 0 ? "exists" : "not present", description: "CIS: /etc/cron.deny should not exist (use cron.allow instead)" });
        findings.push({ check: "cron_allow", status: cronAllow.exitCode === 0 ? "PASS" : "WARN", value: cronAllow.exitCode === 0 ? "exists" : "not present", description: "CIS: /etc/cron.allow should exist to restrict cron access" });

        if (cronAllow.exitCode === 0) {
          const permsResult = await executeCommand({ command: "stat", args: ["-c", "%a %U:%G", "/etc/cron.allow"], timeout: 5000, toolName: "harden_cron_audit" });
          findings.push({ check: "cron_allow_perms", status: permsResult.stdout.trim().startsWith("600") ? "PASS" : "WARN", value: permsResult.stdout.trim(), description: "cron.allow permissions (should be 600 root:root)" });
        }

        // Check at.deny vs at.allow
        const atDeny = await executeCommand({ command: "ls", args: ["-la", "/etc/at.deny"], timeout: 5000, toolName: "harden_cron_audit" });
        const atAllow = await executeCommand({ command: "ls", args: ["-la", "/etc/at.allow"], timeout: 5000, toolName: "harden_cron_audit" });
        findings.push({ check: "at_deny", status: atDeny.exitCode !== 0 ? "PASS" : "WARN", value: atDeny.exitCode === 0 ? "exists" : "not present", description: "CIS: /etc/at.deny should not exist" });
        findings.push({ check: "at_allow", status: atAllow.exitCode === 0 ? "PASS" : "WARN", value: atAllow.exitCode === 0 ? "exists" : "not present", description: "CIS: /etc/at.allow should exist" });

        // Check cron directory permissions
        const cronDirs = ["/etc/crontab", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly", "/etc/cron.d"];
        for (const dir of cronDirs) {
          const perms = await executeCommand({ command: "stat", args: ["-c", "%a %U:%G", dir], timeout: 5000, toolName: "harden_cron_audit" });
          if (perms.exitCode === 0) {
            const perm = perms.stdout.trim().split(" ")[0];
            const isFile = dir === "/etc/crontab";
            const expected = isFile ? "600" : "700";
            findings.push({ check: `perms_${dir.replace(/\//g, "_")}`, status: perm === expected ? "PASS" : "WARN", value: perms.stdout.trim(), description: `${dir} permissions (should be ${expected} root:root)` });
          }
        }

        const passCount = findings.filter(f => f.status === "PASS").length;
        return { content: [createTextContent(JSON.stringify({ summary: { total: findings.length, pass: passCount, fail: findings.filter(f => f.status === "FAIL").length, warn: findings.filter(f => f.status === "WARN").length }, findings }, null, 2))] };
      } catch (error) {
        return { content: [createErrorContent(error instanceof Error ? error.message : String(error))], isError: true };
      }
    },
  );

  // ── harden_umask_audit ────────────────────────────────────────────────
  server.tool(
    "harden_umask_audit",
    "Audit default umask configuration in login.defs, profile, and bashrc to ensure secure file creation defaults.",
    {},
    async () => {
      try {
        const findings: Array<{check: string, status: string, value: string, description: string}> = [];
        const files = [
          { path: "/etc/login.defs", pattern: "UMASK" },
          { path: "/etc/profile", pattern: "umask" },
          { path: "/etc/bash.bashrc", pattern: "umask" },
          { path: "/etc/profile.d/", pattern: "umask" },
        ];

        for (const file of files) {
          if (file.path.endsWith("/")) {
            const grepResult = await executeCommand({ command: "grep", args: ["-r", file.pattern, file.path], timeout: 5000, toolName: "harden_umask_audit" });
            findings.push({ check: `umask_${file.path.replace(/\//g, "_")}`, status: grepResult.stdout.includes("027") || grepResult.stdout.includes("077") ? "PASS" : "WARN", value: grepResult.stdout.trim().substring(0, 200) || "not set", description: `umask in ${file.path} (should be 027 or more restrictive)` });
          } else {
            const grepResult = await executeCommand({ command: "grep", args: ["-i", file.pattern, file.path], timeout: 5000, toolName: "harden_umask_audit" });
            const lines = grepResult.stdout.split("\n").filter((l: string) => !l.trim().startsWith("#") && l.includes("mask"));
            const hasSecure = lines.some((l: string) => l.includes("027") || l.includes("077"));
            findings.push({ check: `umask_${file.path.replace(/\//g, "_")}`, status: hasSecure ? "PASS" : "WARN", value: lines.join("; ").substring(0, 200) || "not explicitly set", description: `umask in ${file.path} (should be 027 or 077)` });
          }
        }

        return { content: [createTextContent(JSON.stringify({ summary: { total: findings.length, pass: findings.filter(f => f.status === "PASS").length, warn: findings.filter(f => f.status === "WARN").length }, findings, recommendation: "Set umask 027 in /etc/profile and /etc/login.defs for CIS compliance" }, null, 2))] };
      } catch (error) {
        return { content: [createErrorContent(error instanceof Error ? error.message : String(error))], isError: true };
      }
    },
  );

  // ── harden_banner_audit ───────────────────────────────────────────────
  server.tool(
    "harden_banner_audit",
    "Audit login warning banners (/etc/issue, /etc/issue.net, /etc/motd) per CIS benchmark requirements.",
    {},
    async () => {
      try {
        const findings: Array<{check: string, status: string, value: string, description: string}> = [];
        const bannerFiles = [
          { path: "/etc/issue", description: "Local login banner" },
          { path: "/etc/issue.net", description: "Remote login banner" },
          { path: "/etc/motd", description: "Message of the day" },
        ];

        for (const banner of bannerFiles) {
          const result = await executeCommand({ command: "cat", args: [banner.path], timeout: 5000, toolName: "harden_banner_audit" });
          const content = result.stdout.trim();
          const hasContent = content.length > 10;
          // CIS says banners should NOT contain OS info (\m, \r, \s, \v)
          const hasOsInfo = /\\[mrsv]/.test(content);
          findings.push({ check: `${banner.path.replace(/\//g, "_")}_exists`, status: hasContent ? "PASS" : "WARN", value: hasContent ? `${content.length} chars` : "empty or missing", description: `${banner.description} should contain a warning` });
          if (hasContent) {
            findings.push({ check: `${banner.path.replace(/\//g, "_")}_no_os_info`, status: hasOsInfo ? "FAIL" : "PASS", value: hasOsInfo ? "contains OS info" : "clean", description: `${banner.description} should NOT contain OS version info (\\m, \\r, \\s, \\v)` });
          }
          // Check permissions
          const perms = await executeCommand({ command: "stat", args: ["-c", "%a %U:%G", banner.path], timeout: 5000, toolName: "harden_banner_audit" });
          if (perms.exitCode === 0) {
            findings.push({ check: `${banner.path.replace(/\//g, "_")}_perms`, status: perms.stdout.trim().startsWith("644") ? "PASS" : "WARN", value: perms.stdout.trim(), description: `${banner.description} permissions (should be 644 root:root)` });
          }
        }

        return { content: [createTextContent(JSON.stringify({ summary: { total: findings.length, pass: findings.filter(f => f.status === "PASS").length, fail: findings.filter(f => f.status === "FAIL").length, warn: findings.filter(f => f.status === "WARN").length }, findings }, null, 2))] };
      } catch (error) {
        return { content: [createErrorContent(error instanceof Error ? error.message : String(error))], isError: true };
      }
    },
  );

  // ── harden_umask_set ─────────────────────────────────────────────────

  server.tool(
    "harden_umask_set",
    "Set default umask value in login.defs, /etc/profile, and /etc/bash.bashrc for secure file creation defaults.",
    {
      umask_value: z.enum(["027", "077"]).describe("Umask value to set"),
      targets: z
        .array(z.enum(["login.defs", "profile", "bashrc"]))
        .optional()
        .describe("Which files to update (default: all)"),
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview changes without executing"),
    },
    async ({ umask_value, targets, dry_run }) => {
      try {
        const allTargets = targets ?? ["login.defs", "profile", "bashrc"];
        const results: Array<{ target: string; action: string; status: string }> = [];
        const isDryRun = dry_run ?? getConfig().dryRun;

        const targetMap: Record<string, string> = {
          "login.defs": "/etc/login.defs",
          "profile": "/etc/profile",
          "bashrc": "/etc/bash.bashrc",
        };

        for (const target of allTargets) {
          const filePath = targetMap[target];
          if (!filePath) continue;

          if (isDryRun) {
            results.push({ target: filePath, action: `[DRY-RUN] Would set umask to ${umask_value}`, status: "preview" });
            continue;
          }

          // Backup file before modification
          try { backupFile(filePath); } catch { /* file may not exist */ }

          if (target === "login.defs") {
            // Check if UMASK line exists in login.defs
            const grepResult = await executeCommand({
              command: "grep",
              args: ["-c", "^UMASK", filePath],
              toolName: "harden_umask_set",
            });
            if (parseInt(grepResult.stdout.trim()) > 0) {
              await executeCommand({
                command: "sudo",
                args: ["sed", "-i", `s/^UMASK.*/UMASK\t\t${umask_value}/`, filePath],
                toolName: "harden_umask_set",
              });
              results.push({ target: filePath, action: `Updated UMASK to ${umask_value}`, status: "updated" });
            } else {
              await executeCommand({
                command: "bash",
                args: ["-c", `printf '%s\\n' 'UMASK\t\t${umask_value}' | sudo tee -a ${filePath} > /dev/null`],
                toolName: "harden_umask_set",
              });
              results.push({ target: filePath, action: `Appended UMASK ${umask_value}`, status: "appended" });
            }
          } else {
            // profile or bashrc — check if umask line exists
            const grepResult = await executeCommand({
              command: "grep",
              args: ["-c", "^umask [0-9]", filePath],
              toolName: "harden_umask_set",
            });
            if (parseInt(grepResult.stdout.trim()) > 0) {
              await executeCommand({
                command: "sudo",
                args: ["sed", "-i", `s/^umask [0-9]*/umask ${umask_value}/`, filePath],
                toolName: "harden_umask_set",
              });
              results.push({ target: filePath, action: `Updated umask to ${umask_value}`, status: "updated" });
            } else {
              await executeCommand({
                command: "bash",
                args: ["-c", `printf '%s\\n' 'umask ${umask_value}' | sudo tee -a ${filePath} > /dev/null`],
                toolName: "harden_umask_set",
              });
              results.push({ target: filePath, action: `Appended umask ${umask_value}`, status: "appended" });
            }
          }

          const entry = createChangeEntry({
            tool: "harden_umask_set",
            action: `Set umask ${umask_value} in ${filePath}`,
            target: filePath,
            dryRun: false,
            success: true,
          });
          logChange(entry);
        }

        if (isDryRun) {
          const entry = createChangeEntry({
            tool: "harden_umask_set",
            action: `[DRY-RUN] Set umask ${umask_value}`,
            target: allTargets.join(", "),
            dryRun: true,
            success: true,
          });
          logChange(entry);
        }

        return { content: [formatToolOutput({ umask_value, results, dryRun: isDryRun })] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── harden_coredump_disable ──────────────────────────────────────────

  server.tool(
    "harden_coredump_disable",
    "Disable core dumps via limits.conf, systemd coredump.conf, and sysctl fs.suid_dumpable.",
    {
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview changes without executing"),
    },
    async ({ dry_run }) => {
      try {
        const isDryRun = dry_run ?? getConfig().dryRun;
        const actions: Array<{ target: string; action: string; status: string }> = [];

        // 1. Check/add "* hard core 0" to /etc/security/limits.conf
        const limitsPath = "/etc/security/limits.conf";
        const limitsCheck = await executeCommand({
          command: "grep",
          args: ["-c", "\\* hard core 0", limitsPath],
          toolName: "harden_coredump_disable",
        });
        const limitsHasEntry = parseInt(limitsCheck.stdout.trim()) > 0;

        if (isDryRun) {
          actions.push({
            target: limitsPath,
            action: limitsHasEntry ? "Already present" : "[DRY-RUN] Would add '* hard core 0'",
            status: limitsHasEntry ? "ok" : "preview",
          });
        } else if (!limitsHasEntry) {
          try { backupFile(limitsPath); } catch { /* may not exist */ }
          await executeCommand({
            command: "bash",
            args: ["-c", `printf '%s\\n' '* hard core 0' | sudo tee -a ${limitsPath} > /dev/null`],
            toolName: "harden_coredump_disable",
          });
          actions.push({ target: limitsPath, action: "Added '* hard core 0'", status: "applied" });
        } else {
          actions.push({ target: limitsPath, action: "Already present", status: "ok" });
        }

        // 2. Check/create /etc/systemd/coredump.conf with Storage=none, ProcessSizeMax=0
        const coredumpPath = "/etc/systemd/coredump.conf";

        if (isDryRun) {
          actions.push({
            target: coredumpPath,
            action: "[DRY-RUN] Would write coredump.conf with Storage=none, ProcessSizeMax=0",
            status: "preview",
          });
        } else {
          try { backupFile(coredumpPath); } catch { /* may not exist */ }
          await executeCommand({
            command: "bash",
            args: ["-c", `printf '[Coredump]\\nStorage=none\\nProcessSizeMax=0\\n' | sudo tee ${coredumpPath} > /dev/null`],
            toolName: "harden_coredump_disable",
          });
          actions.push({ target: coredumpPath, action: "Written with Storage=none, ProcessSizeMax=0", status: "applied" });
        }

        // 3. Set fs.suid_dumpable = 0 via sysctl
        if (isDryRun) {
          actions.push({
            target: "fs.suid_dumpable",
            action: "[DRY-RUN] Would set fs.suid_dumpable=0",
            status: "preview",
          });
        } else {
          const sysctlResult = await executeCommand({
            command: "sudo",
            args: ["sysctl", "-w", "fs.suid_dumpable=0"],
            toolName: "harden_coredump_disable",
          });
          actions.push({
            target: "fs.suid_dumpable",
            action: sysctlResult.exitCode === 0 ? "Set to 0" : `Failed: ${sysctlResult.stderr}`,
            status: sysctlResult.exitCode === 0 ? "applied" : "error",
          });
        }

        const entry = createChangeEntry({
          tool: "harden_coredump_disable",
          action: isDryRun ? "[DRY-RUN] Disable core dumps" : "Disable core dumps",
          target: "system",
          dryRun: isDryRun,
          success: true,
        });
        logChange(entry);

        return { content: [formatToolOutput({ actions, dryRun: isDryRun })] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── harden_banner_set ────────────────────────────────────────────────

  server.tool(
    "harden_banner_set",
    "Set login warning banner content in /etc/issue, /etc/issue.net, and /etc/motd per CIS benchmark.",
    {
      banner_text: z
        .string()
        .optional()
        .describe("Custom banner text. If not provided, uses a CIS-compliant default."),
      targets: z
        .array(z.enum(["issue", "issue.net", "motd"]))
        .optional()
        .describe("Which banner files to update (default: all)"),
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview changes without executing"),
    },
    async ({ banner_text, targets, dry_run }) => {
      try {
        const isDryRun = dry_run ?? getConfig().dryRun;
        const allTargets = targets ?? ["issue", "issue.net", "motd"];

        // Default CIS-compliant banner
        const defaultBanner = "Authorized uses only. All activity may be monitored and reported.";
        const text = banner_text ?? defaultBanner;

        // Sanitize banner_text: only printable ASCII, newlines, tabs. Max 2000 chars.
        if (text.length > 2000) {
          return { content: [createErrorContent("Banner text exceeds maximum length of 2000 characters")], isError: true };
        }
        if (!/^[\x20-\x7E\n\r\t]*$/.test(text)) {
          return { content: [createErrorContent("Banner text contains invalid characters. Only printable ASCII, newlines, and common punctuation are allowed.")], isError: true };
        }

        const results: Array<{ target: string; action: string; status: string }> = [];

        for (const target of allTargets) {
          const filePath = `/etc/${target}`;

          if (isDryRun) {
            results.push({ target: filePath, action: `[DRY-RUN] Would write banner text (${text.length} chars)`, status: "preview" });
            continue;
          }

          // Backup file before modification
          try { backupFile(filePath); } catch { /* may not exist */ }

          // Escape single quotes for shell safety
          const escapedText = text.replace(/'/g, "'\\''");

          // Write banner using printf piped to sudo tee
          const writeResult = await executeCommand({
            command: "bash",
            args: ["-c", `printf '%s\\n' '${escapedText}' | sudo tee ${filePath} > /dev/null`],
            toolName: "harden_banner_set",
          });

          if (writeResult.exitCode === 0) {
            results.push({ target: filePath, action: `Written banner (${text.length} chars)`, status: "applied" });
            const entry = createChangeEntry({
              tool: "harden_banner_set",
              action: `Set login banner`,
              target: filePath,
              after: text.substring(0, 100),
              dryRun: false,
              success: true,
            });
            logChange(entry);
          } else {
            results.push({ target: filePath, action: `Failed: ${writeResult.stderr}`, status: "error" });
          }
        }

        if (isDryRun) {
          const entry = createChangeEntry({
            tool: "harden_banner_set",
            action: "[DRY-RUN] Set login banners",
            target: allTargets.join(", "),
            dryRun: true,
            success: true,
          });
          logChange(entry);
        }

        return { content: [formatToolOutput({ targets: allTargets, bannerLength: text.length, results, dryRun: isDryRun })] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── harden_bootloader_configure ──────────────────────────────────────

  server.tool(
    "harden_bootloader_configure",
    "Configure GRUB bootloader kernel parameters for security hardening.",
    {
      action: z.enum(["add_kernel_params", "status"]).describe("Action to perform"),
      kernel_params: z
        .string()
        .optional()
        .describe("Space-separated kernel parameters to add (only with add_kernel_params action)"),
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview changes without executing"),
    },
    async ({ action, kernel_params, dry_run }) => {
      try {
        const isDryRun = dry_run ?? getConfig().dryRun;
        const grubFile = "/etc/default/grub";

        const SAFE_PARAMS = [
          "audit=1", "init_on_alloc=1", "init_on_free=1", "page_poison=1",
          "slab_nomerge", "pti=on", "vsyscall=none", "debugfs=off",
          "oops=panic", "module.sig_enforce=1",
        ];

        if (action === "status") {
          const readResult = await executeCommand({
            command: "grep",
            args: ["^GRUB_CMDLINE_LINUX_DEFAULT", grubFile],
            toolName: "harden_bootloader_configure",
          });

          const currentLine = readResult.stdout.trim();
          const currentParams = currentLine
            .replace(/^GRUB_CMDLINE_LINUX_DEFAULT="/, "")
            .replace(/"$/, "")
            .split(/\s+/)
            .filter(Boolean);

          const paramStatus = SAFE_PARAMS.map((p) => ({
            param: p,
            present: currentParams.some((cp) => cp === p || cp.startsWith(p.split("=")[0] + "=")),
          }));

          return {
            content: [formatToolOutput({
              action: "status",
              grubFile,
              currentLine,
              currentParams,
              safeParamStatus: paramStatus,
              missingCount: paramStatus.filter((p) => !p.present).length,
            })],
          };
        }

        // add_kernel_params action
        if (!kernel_params) {
          return { content: [createErrorContent("kernel_params is required for add_kernel_params action")], isError: true };
        }

        const requestedParams = kernel_params.split(/\s+/).filter(Boolean);

        // Validate each param format
        const paramRegex = /^[a-z_][a-z0-9_.=]+$/i;
        for (const p of requestedParams) {
          if (!paramRegex.test(p)) {
            return { content: [createErrorContent(`Invalid kernel parameter format: ${p}`)], isError: true };
          }
        }

        // Only allow params from the predefined safe list
        const disallowed = requestedParams.filter((p) => !SAFE_PARAMS.includes(p));
        if (disallowed.length > 0) {
          return {
            content: [createErrorContent(`Disallowed kernel parameters: ${disallowed.join(", ")}. Allowed: ${SAFE_PARAMS.join(", ")}`)],
            isError: true,
          };
        }

        // Read current GRUB config
        const readResult = await executeCommand({
          command: "grep",
          args: ["^GRUB_CMDLINE_LINUX_DEFAULT", grubFile],
          toolName: "harden_bootloader_configure",
        });

        const currentLine = readResult.stdout.trim();
        const currentParams = currentLine
          .replace(/^GRUB_CMDLINE_LINUX_DEFAULT="/, "")
          .replace(/"$/, "")
          .split(/\s+/)
          .filter(Boolean);

        // Find which params need to be added (skip already-present ones)
        const toAdd = requestedParams.filter(
          (p) => !currentParams.some((cp) => cp === p || cp.startsWith(p.split("=")[0] + "="))
        );

        if (toAdd.length === 0) {
          return { content: [createTextContent("All requested kernel parameters are already present.")] };
        }

        const newParams = [...currentParams, ...toAdd].join(" ");
        const newLine = `GRUB_CMDLINE_LINUX_DEFAULT="${newParams}"`;

        if (isDryRun) {
          const entry = createChangeEntry({
            tool: "harden_bootloader_configure",
            action: "[DRY-RUN] Add kernel params",
            target: grubFile,
            before: currentLine,
            after: newLine,
            dryRun: true,
            success: true,
          });
          logChange(entry);

          return {
            content: [formatToolOutput({
              action: "add_kernel_params",
              dryRun: true,
              paramsToAdd: toAdd,
              currentLine,
              newLine,
            })],
          };
        }

        // Backup GRUB config before modification
        try { backupFile(grubFile); } catch { /* may not exist */ }

        // Update GRUB config using sed
        const escapedCurrent = currentLine.replace(/[/\\.*+?^${}()|[\]]/g, "\\$&");
        const escapedNew = newLine.replace(/[/\\&]/g, "\\$&");
        await executeCommand({
          command: "sudo",
          args: ["sed", "-i", `s/${escapedCurrent}/${escapedNew}/`, grubFile],
          toolName: "harden_bootloader_configure",
        });

        // Run update-grub to apply changes
        const updateResult = await executeCommand({
          command: "sudo",
          args: ["update-grub"],
          toolName: "harden_bootloader_configure",
          timeout: 30000,
        });

        const entry = createChangeEntry({
          tool: "harden_bootloader_configure",
          action: "Add kernel params",
          target: grubFile,
          before: currentLine,
          after: newLine,
          dryRun: false,
          success: updateResult.exitCode === 0,
          error: updateResult.exitCode !== 0 ? updateResult.stderr : undefined,
          rollbackCommand: `sudo sed -i 's/${escapedNew}/${escapedCurrent}/' ${grubFile} && sudo update-grub`,
        });
        logChange(entry);

        return {
          content: [formatToolOutput({
            action: "add_kernel_params",
            dryRun: false,
            paramsAdded: toAdd,
            updateGrubSuccess: updateResult.exitCode === 0,
            newLine,
          })],
        };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── harden_systemd_apply ─────────────────────────────────────────────

  server.tool(
    "harden_systemd_apply",
    "Apply systemd security hardening overrides to a service unit (sandboxing, capability restrictions).",
    {
      service: z.string().describe("Service name (e.g., sshd.service)"),
      hardening_level: z.enum(["basic", "strict"]).describe("Preset hardening level"),
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview changes without executing"),
    },
    async ({ service, hardening_level, dry_run }) => {
      try {
        const isDryRun = dry_run ?? getConfig().dryRun;

        // Validate service name format
        if (!/^[a-zA-Z0-9_-]+\.service$/.test(service)) {
          return { content: [createErrorContent("Invalid service name. Must match format: name.service")], isError: true };
        }

        const basicDirectives = [
          "ProtectSystem=full",
          "ProtectHome=yes",
          "PrivateTmp=yes",
          "NoNewPrivileges=yes",
        ];

        const strictDirectives = [
          "ProtectSystem=strict",
          "ProtectHome=yes",
          "PrivateTmp=yes",
          "NoNewPrivileges=yes",
          "ProtectKernelTunables=yes",
          "ProtectKernelModules=yes",
          "ProtectControlGroups=yes",
          "RestrictSUIDSGID=yes",
          "MemoryDenyWriteExecute=yes",
        ];

        const directives = hardening_level === "strict" ? strictDirectives : basicDirectives;
        const overrideDir = `/etc/systemd/system/${service}.d`;
        const overrideFile = `${overrideDir}/security.conf`;
        const overrideContent = `[Service]\n${directives.join("\n")}`;

        if (isDryRun) {
          const entry = createChangeEntry({
            tool: "harden_systemd_apply",
            action: `[DRY-RUN] Apply ${hardening_level} hardening to ${service}`,
            target: service,
            after: overrideContent,
            dryRun: true,
            success: true,
          });
          logChange(entry);

          return {
            content: [formatToolOutput({
              service,
              hardening_level,
              dryRun: true,
              overrideFile,
              content: overrideContent,
              directives,
            })],
          };
        }

        // Create override directory
        await executeCommand({
          command: "sudo",
          args: ["mkdir", "-p", overrideDir],
          toolName: "harden_systemd_apply",
        });

        // Backup existing override if present
        try { backupFile(overrideFile); } catch { /* may not exist */ }

        // Write security.conf using printf piped to sudo tee
        const formattedContent = `[Service]\\n${directives.join("\\n")}`;
        const writeResult = await executeCommand({
          command: "bash",
          args: ["-c", `printf '${formattedContent}\\n' | sudo tee ${overrideFile} > /dev/null`],
          toolName: "harden_systemd_apply",
        });

        if (writeResult.exitCode !== 0) {
          return { content: [createErrorContent(`Failed to write override: ${writeResult.stderr}`)], isError: true };
        }

        // Reload systemd daemon to pick up changes
        const reloadResult = await executeCommand({
          command: "sudo",
          args: ["systemctl", "daemon-reload"],
          toolName: "harden_systemd_apply",
          timeout: 15000,
        });

        const entry = createChangeEntry({
          tool: "harden_systemd_apply",
          action: `Apply ${hardening_level} hardening to ${service}`,
          target: service,
          after: overrideContent,
          dryRun: false,
          success: reloadResult.exitCode === 0,
          error: reloadResult.exitCode !== 0 ? reloadResult.stderr : undefined,
          rollbackCommand: `sudo rm ${overrideFile} && sudo systemctl daemon-reload`,
        });
        logChange(entry);

        return {
          content: [formatToolOutput({
            service,
            hardening_level,
            dryRun: false,
            overrideFile,
            directives,
            daemonReload: reloadResult.exitCode === 0 ? "success" : "failed",
          })],
        };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );
}
