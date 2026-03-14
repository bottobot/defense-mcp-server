/**
 * Access control and authentication auditing tools for Defense MCP Server.
 *
 * Registers 1 consolidated tool: access_control
 * Actions: ssh_audit, ssh_harden, ssh_cipher_audit, pam_audit, pam_configure,
 *          sudo_audit, user_audit, password_policy_audit, password_policy_set,
 *          restrict_shell
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeCommand } from "../core/executor.js";
import { getConfig, getToolTimeout } from "../core/config.js";
import { getDistroAdapter } from "../core/distro-adapter.js";
import {
  createTextContent,
  createErrorContent,
  formatToolOutput,
} from "../core/parsers.js";
import {
  logChange,
  createChangeEntry,
  backupFile,
} from "../core/changelog.js";
import { sanitizeArgs } from "../core/sanitizer.js";
import {
  parsePamConfig,
  serializePamConfig,
  validatePamConfig,
  createPamRule,
  removeModuleRules,
  insertBeforeModule,
  insertAfterModule,
  adjustJumpCounts,
  readPamFile,
  writePamFile,
  backupPamFile,
  restorePamFile,
  PamWriteError,
} from "../core/pam-utils.js";

// ── SSH hardening recommendations ────────────────────────────────────────

interface SshCheck {
  key: string;
  recommended: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
}

const SSH_HARDENING_CHECKS: SshCheck[] = [
  {
    key: "PermitRootLogin",
    recommended: "no",
    severity: "critical",
    description: "Root login should be disabled",
  },
  {
    key: "PasswordAuthentication",
    recommended: "no",
    severity: "high",
    description: "Password authentication should be disabled in favor of keys",
  },
  {
    key: "X11Forwarding",
    recommended: "no",
    severity: "medium",
    description: "X11 forwarding should be disabled unless needed",
  },
  {
    key: "MaxAuthTries",
    recommended: "4",
    severity: "medium",
    description: "Max authentication attempts should be limited",
  },
  {
    key: "Protocol",
    recommended: "2",
    severity: "critical",
    description: "Only SSH protocol 2 should be used",
  },
  {
    key: "PermitEmptyPasswords",
    recommended: "no",
    severity: "critical",
    description: "Empty passwords must not be permitted",
  },
  {
    key: "ClientAliveInterval",
    recommended: "300",
    severity: "low",
    description: "Client alive interval should be set for idle timeout",
  },
  {
    key: "ClientAliveCountMax",
    recommended: "3",
    severity: "low",
    description: "Client alive count max should be limited",
  },
  {
    key: "AllowTcpForwarding",
    recommended: "no",
    severity: "medium",
    description: "TCP forwarding should be disabled unless needed",
  },
  {
    key: "Banner",
    recommended: "/etc/issue.net",
    severity: "low",
    description: "A login banner should be displayed",
  },
  // GAP-06: Additional SSH hardening checks
  {
    key: "LoginGraceTime",
    recommended: "60",
    severity: "medium",
    description: "CIS 5.2.16 - Limit login grace time",
  },
  {
    key: "MaxSessions",
    recommended: "4",
    severity: "medium",
    description: "Limit concurrent sessions per connection",
  },
  {
    key: "AllowAgentForwarding",
    recommended: "no",
    severity: "medium",
    description: "Disable SSH agent forwarding",
  },
  {
    key: "PermitUserEnvironment",
    recommended: "no",
    severity: "medium",
    description: "Prevent user environment variable override",
  },
  {
    key: "UseDNS",
    recommended: "no",
    severity: "low",
    description: "Disable DNS lookups for client verification",
  },
  {
    key: "Ciphers",
    recommended: "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr",
    severity: "high",
    description: "Mozilla Modern cipher suite",
  },
  {
    key: "MACs",
    recommended: "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256",
    severity: "high",
    description: "Strong MAC algorithms only",
  },
  {
    key: "KexAlgorithms",
    recommended: "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256",
    severity: "high",
    description: "Strong key exchange algorithms only",
  },
  {
    key: "HostKeyAlgorithms",
    recommended: "ssh-ed25519,rsa-sha2-512,rsa-sha2-256",
    severity: "high",
    description: "Prefer Ed25519 and RSA-SHA2 host keys",
  },
];

// ── TOOL-012 remediation: Valid SSH configuration directives ────────────────

/** Known-good SSH configuration directives (case-sensitive as used in sshd_config) */
const VALID_SSH_CONFIG_KEYS = new Set([
  "PermitRootLogin", "PasswordAuthentication", "X11Forwarding", "MaxAuthTries",
  "Protocol", "PermitEmptyPasswords", "ClientAliveInterval", "ClientAliveCountMax",
  "AllowTcpForwarding", "Banner", "LoginGraceTime", "MaxSessions",
  "AllowAgentForwarding", "PermitUserEnvironment", "UseDNS",
  "Ciphers", "MACs", "KexAlgorithms", "HostKeyAlgorithms",
  "PubkeyAuthentication", "AuthorizedKeysFile", "HostbasedAuthentication",
  "ChallengeResponseAuthentication", "GSSAPIAuthentication", "UsePAM",
  "AcceptEnv", "AllowUsers", "AllowGroups", "DenyUsers", "DenyGroups",
  "GatewayPorts", "PermitTunnel", "PrintMotd", "PrintLastLog",
  "TCPKeepAlive", "Compression", "MaxStartups", "PermitOpen",
  "AuthenticationMethods", "StrictModes", "SyslogFacility", "LogLevel",
  "ListenAddress", "Port", "AddressFamily", "HostKey",
  "RekeyLimit", "Subsystem",
]);

/** Validate an SSH config value — reject shell metacharacters */
const SSH_VALUE_UNSAFE_RE = /[;|&`$(){}<>!]/;

function validateSshConfigKey(key: string): string {
  if (!VALID_SSH_CONFIG_KEYS.has(key)) {
    throw new Error(
      `Invalid SSH configuration directive: '${key}'. ` +
      `Must be a known sshd_config option.`
    );
  }
  return key;
}

function validateSshConfigValue(value: string): string {
  if (SSH_VALUE_UNSAFE_RE.test(value)) {
    throw new Error(
      `Invalid SSH configuration value: contains shell metacharacters. Value: '${value}'`
    );
  }
  return value;
}

// ── Registration entry point ───────────────────────────────────────────────

export function registerAccessControlTools(server: McpServer): void {
  server.tool(
    "access_control",
    "Access control and authentication security. Actions: ssh_audit=check SSH config, ssh_harden=apply SSH hardening, ssh_cipher_audit=audit SSH cryptographic algorithms, pam_audit=check PAM config, pam_configure=set up PAM modules, sudo_audit=audit sudoers, user_audit=audit user accounts, password_policy_audit=audit password policy, password_policy_set=set password policy, restrict_shell=restrict user login shell",
    {
      action: z
        .enum([
          "ssh_audit",
          "ssh_harden",
          "ssh_cipher_audit",
          "pam_audit",
          "pam_configure",
          "sudo_audit",
          "user_audit",
          "password_policy_audit",
          "password_policy_set",
          "restrict_shell",
        ])
        .describe("Action to perform"),
      // ── SSH params ──
      config_path: z
        .string()
        .optional()
        .default("/etc/ssh/sshd_config")
        .describe("Path to sshd_config file (ssh_audit, ssh_harden, ssh_cipher_audit)"),
      settings: z
        .string()
        .optional()
        .describe("Comma-separated key=value pairs for ssh_harden, e.g. 'PermitRootLogin=no,MaxAuthTries=4'"),
      apply_recommended: z
        .boolean()
        .optional()
        .default(false)
        .describe("Apply all recommended SSH hardening settings (ssh_harden)"),
      restart_sshd: z
        .boolean()
        .optional()
        .default(false)
        .describe("Restart sshd after applying changes (ssh_harden)"),
      // ── PAM audit params ──
      service: z
        .string()
        .optional()
        .describe("Specific PAM service to audit, e.g. 'sshd', 'login', 'sudo' (pam_audit)"),
      check_all: z
        .boolean()
        .optional()
        .default(false)
        .describe("Check common-auth, common-password, etc. (pam_audit)"),
      // ── PAM configure params ──
      module: z
        .enum(["pwquality", "faillock"])
        .optional()
        .describe("PAM module to configure (pam_configure)"),
      pam_settings: z
        .object({
          // pwquality settings
          minlen: z.number().optional(),
          dcredit: z.number().optional(),
          ucredit: z.number().optional(),
          lcredit: z.number().optional(),
          ocredit: z.number().optional(),
          minclass: z.number().optional(),
          maxrepeat: z.number().optional(),
          reject_username: z.boolean().optional(),
          // faillock settings
          deny: z.number().optional(),
          unlock_time: z.number().optional(),
          fail_interval: z.number().optional(),
        })
        .optional()
        .describe("PAM module-specific settings (pam_configure)"),
      // ── sudo_audit params ──
      check_nopasswd: z
        .boolean()
        .optional()
        .default(true)
        .describe("Check for NOPASSWD entries (sudo_audit, default: true)"),
      check_insecure: z
        .boolean()
        .optional()
        .default(true)
        .describe("Check for insecure sudoers configurations (sudo_audit, default: true)"),
      // ── user_audit params ──
      check_type: z
        .enum(["all", "privileged", "inactive", "no_password", "shell", "locked"])
        .optional()
        .default("all")
        .describe("Type of user audit to perform (user_audit, default: all)"),
      // ── password_policy params ──
      min_days: z
        .number()
        .optional()
        .describe("Minimum days between password changes (PASS_MIN_DAYS) (password_policy_set)"),
      max_days: z
        .number()
        .optional()
        .describe("Maximum days before password must be changed (PASS_MAX_DAYS) (password_policy_set)"),
      warn_days: z
        .number()
        .optional()
        .describe("Days before expiry to warn user (PASS_WARN_AGE) (password_policy_set)"),
      min_length: z
        .number()
        .optional()
        .describe("Minimum password length (PASS_MIN_LEN) (password_policy_set)"),
      inactive_days: z
        .number()
        .optional()
        .describe("Days after password expires before account is disabled (password_policy_set)"),
      encrypt_method: z
        .enum(["SHA512", "YESCRYPT"])
        .optional()
        .describe("Password hashing algorithm (ENCRYPT_METHOD) (password_policy_set)"),
      // ── restrict_shell params ──
      username: z
        .string()
        .optional()
        .describe("The username to restrict (restrict_shell)"),
      shell: z
        .string()
        .optional()
        .default("/usr/sbin/nologin")
        .describe("Shell to set (restrict_shell, default: /usr/sbin/nologin)"),
      // ── shared ──
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview changes without executing (ssh_harden, pam_configure, password_policy_set, restrict_shell)"),
    },
    async (params) => {
      const { action } = params;

      switch (action) {
        // ── ssh_audit ────────────────────────────────────────────────
        case "ssh_audit": {
          try {
            const config_path = params.config_path ?? "/etc/ssh/sshd_config";
            const result = await executeCommand({
              command: "sudo",
              args: ["cat", config_path],
              toolName: "access_control",
              timeout: getToolTimeout("access_control"),
            });

            if (result.exitCode !== 0) {
              return {
                content: [
                  createErrorContent(
                    `Cannot read SSH config (exit ${result.exitCode}): ${result.stderr}`
                  ),
                ],
                isError: true,
              };
            }

            const configContent = result.stdout;

            // Parse the SSH config into key-value pairs
            const configValues: Record<string, string> = {};
            for (const line of configContent.split("\n")) {
              const trimmed = line.trim();
              if (!trimmed || trimmed.startsWith("#")) continue;

              const parts = trimmed.split(/\s+/);
              if (parts.length >= 2) {
                configValues[parts[0]] = parts.slice(1).join(" ");
              }
            }

            // Check each recommendation
            const findings: Array<{
              setting: string;
              currentValue: string | null;
              recommendedValue: string;
              status: "pass" | "fail" | "warn";
              severity: string;
              description: string;
            }> = [];

            for (const check of SSH_HARDENING_CHECKS) {
              const currentValue = configValues[check.key] ?? null;

              let status: "pass" | "fail" | "warn";

              if (currentValue === null) {
                if (check.key === "MaxAuthTries" || check.key === "ClientAliveCountMax") {
                  status = "warn";
                } else if (check.key === "ClientAliveInterval" || check.key === "Banner") {
                  status = "warn";
                } else {
                  status = "warn";
                }
              } else if (check.key === "MaxAuthTries") {
                status = parseInt(currentValue, 10) <= parseInt(check.recommended, 10) ? "pass" : "fail";
              } else if (check.key === "ClientAliveCountMax") {
                status = parseInt(currentValue, 10) <= parseInt(check.recommended, 10) ? "pass" : "fail";
              } else if (check.key === "ClientAliveInterval") {
                status = parseInt(currentValue, 10) > 0 ? "pass" : "fail";
              } else if (check.key === "Banner") {
                status = currentValue && currentValue !== "none" ? "pass" : "fail";
              } else if (check.key === "LoginGraceTime" || check.key === "MaxSessions") {
                status = parseInt(currentValue, 10) <= parseInt(check.recommended, 10) ? "pass" : "fail";
              } else if (check.key === "Ciphers" || check.key === "MACs" || check.key === "KexAlgorithms" || check.key === "HostKeyAlgorithms") {
                const configuredAlgs = currentValue.split(",").map(s => s.trim());
                const recommendedAlgs = check.recommended.split(",").map(s => s.trim());
                const hasWeak = configuredAlgs.some(a => !recommendedAlgs.includes(a));
                status = hasWeak ? "fail" : "pass";
              } else {
                status = currentValue.toLowerCase() === check.recommended.toLowerCase() ? "pass" : "fail";
              }

              findings.push({
                setting: check.key,
                currentValue,
                recommendedValue: check.recommended,
                status,
                severity: check.severity,
                description: check.description,
              });
            }

            const passed = findings.filter((f) => f.status === "pass").length;
            const failed = findings.filter((f) => f.status === "fail").length;
            const warned = findings.filter((f) => f.status === "warn").length;

            const entry = createChangeEntry({
              tool: "access_control",
              action: "SSH configuration audit",
              target: config_path,
              after: `Pass: ${passed}, Fail: ${failed}, Warn: ${warned}`,
              dryRun: false,
              success: true,
            });
            logChange(entry);

            const output = {
              configPath: config_path,
              summary: { passed, failed, warned, total: findings.length },
              findings,
            };

            return { content: [formatToolOutput(output)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── ssh_harden ───────────────────────────────────────────────
        case "ssh_harden": {
          try {
            const configPath = params.config_path ?? "/etc/ssh/sshd_config";

            // Build the settings to apply
            const settingsToApply: Record<string, string> = {};

            if (params.apply_recommended) {
              for (const check of SSH_HARDENING_CHECKS) {
                settingsToApply[check.key] = check.recommended;
              }
            }

            if (params.settings) {
              for (const pair of params.settings.split(",")) {
                const trimmed = pair.trim();
                const eqIdx = trimmed.indexOf("=");
                if (eqIdx > 0) {
                  const key = trimmed.substring(0, eqIdx).trim();
                  const value = trimmed.substring(eqIdx + 1).trim();
                  // TOOL-012: Validate SSH config keys and values
                  validateSshConfigKey(key);
                  validateSshConfigValue(value);
                  settingsToApply[key] = value;
                }
              }
            }

            if (Object.keys(settingsToApply).length === 0) {
              return {
                content: [
                  createErrorContent(
                    "No settings specified. Provide 'settings' or set 'apply_recommended' to true."
                  ),
                ],
                isError: true,
              };
            }

            const sedCommands: string[] = [];
            for (const [key, value] of Object.entries(settingsToApply)) {
              sedCommands.push(
                `sudo sed -i 's|^#*\\s*${key}\\s.*|${key} ${value}|' ${configPath}`
              );
            }

            const grepCommands: string[] = [];
            for (const key of Object.keys(settingsToApply)) {
              grepCommands.push(
                `grep -q '^#*\\s*${key}\\s' ${configPath} || echo '${key} ${settingsToApply[key]}' | sudo tee -a ${configPath}`
              );
            }

            if (params.dry_run ?? getConfig().dryRun) {
              const entry = createChangeEntry({
                tool: "access_control",
                action: "[DRY-RUN] Apply SSH hardening",
                target: configPath,
                after: JSON.stringify(settingsToApply),
                dryRun: true,
                success: true,
              });
              logChange(entry);

              return {
                content: [
                  createTextContent(
                    `[DRY-RUN] Would apply the following SSH hardening to ${configPath}:\n\n` +
                      Object.entries(settingsToApply)
                        .map(([k, v]) => `  ${k} ${v}`)
                        .join("\n") +
                      `\n\nSed commands:\n${sedCommands.map((c) => `  ${c}`).join("\n")}` +
                      `\n\nAppend commands:\n${grepCommands.map((c) => `  ${c}`).join("\n")}` +
                      (params.restart_sshd
                        ? "\n\nWould also restart sshd."
                        : "\n\nsshd will NOT be restarted.")
                  ),
                ],
              };
            }

            // Backup the config file first
            let backupPath: string | undefined;
            try {
              backupPath = backupFile(configPath);
            } catch {
              await executeCommand({
                command: "sudo",
                args: ["cp", configPath, `${configPath}.bak.${Date.now()}`],
                toolName: "access_control",
              });
            }

            // Apply sed replacements for existing settings
            for (const [key, value] of Object.entries(settingsToApply)) {
              await executeCommand({
                command: "sudo",
                args: [
                  "sed",
                  "-i",
                  `s|^#*\\s*${key}\\s.*|${key} ${value}|`,
                  configPath,
                ],
                toolName: "access_control",
                timeout: getToolTimeout("access_control"),
              });

              const grepResult = await executeCommand({
                command: "grep",
                args: ["-q", `^${key}\\s`, configPath],
                toolName: "access_control",
              });

              if (grepResult.exitCode !== 0) {
                await executeCommand({
                  command: "sudo",
                  args: ["tee", "-a", configPath],
                  stdin: `${key} ${value}\n`,
                  toolName: "access_control",
                });
              }
            }

            // Validate the config
            const testResult = await executeCommand({
              command: "sudo",
              args: ["sshd", "-t"],
              toolName: "access_control",
              timeout: getToolTimeout("access_control"),
            });

            if (testResult.exitCode !== 0) {
              const entry = createChangeEntry({
                tool: "access_control",
                action: "Apply SSH hardening (config validation FAILED)",
                target: configPath,
                after: JSON.stringify(settingsToApply),
                backupPath,
                dryRun: false,
                success: false,
                error: `sshd -t failed: ${testResult.stderr}`,
                rollbackCommand: backupPath
                  ? `sudo cp ${backupPath} ${configPath}`
                  : undefined,
              });
              logChange(entry);

              return {
                content: [
                  createErrorContent(
                    `SSH config validation failed after changes. ` +
                      `Config may be invalid.\n${testResult.stderr}\n\n` +
                      (backupPath
                        ? `Rollback: sudo cp ${backupPath} ${configPath}`
                        : "Manual rollback may be required.")
                  ),
                ],
                isError: true,
              };
            }

            // Restart sshd if requested
            let restartOutput = "";
            if (params.restart_sshd) {
              const restartResult = await executeCommand({
                command: "sudo",
                args: ["systemctl", "restart", "sshd"],
                toolName: "access_control",
                timeout: getToolTimeout("access_control"),
              });

              restartOutput =
                restartResult.exitCode === 0
                  ? "sshd restarted successfully."
                  : `sshd restart failed: ${restartResult.stderr}`;
            }

            const entry = createChangeEntry({
              tool: "access_control",
              action: "Apply SSH hardening",
              target: configPath,
              after: JSON.stringify(settingsToApply),
              backupPath,
              dryRun: false,
              success: true,
              rollbackCommand: backupPath
                ? `sudo cp ${backupPath} ${configPath} && sudo systemctl restart sshd`
                : undefined,
            });
            logChange(entry);

            return {
              content: [
                createTextContent(
                  `SSH hardening applied to ${configPath}.\n\n` +
                    `Settings applied:\n${Object.entries(settingsToApply).map(([k, v]) => `  ${k} = ${v}`).join("\n")}` +
                    (backupPath ? `\n\nBackup: ${backupPath}` : "") +
                    `\nConfig validation: passed` +
                    (restartOutput ? `\n${restartOutput}` : "\nsshd NOT restarted.")
                ),
              ],
            };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── ssh_cipher_audit ─────────────────────────────────────────
        case "ssh_cipher_audit": {
          try {
            const config_path = params.config_path ?? "/etc/ssh/sshd_config";

            // Read the SSH config
            const result = await executeCommand({
              command: "cat",
              args: [config_path],
              timeout: 10000,
              toolName: "access_control",
            });

            const config = result.stdout;

            // Also get runtime config if possible
            const runtimeResult = await executeCommand({
              command: "sudo",
              args: ["sshd", "-T"],
              timeout: 10000,
              toolName: "access_control",
            });
            const runtimeConfig = runtimeResult.exitCode === 0 ? runtimeResult.stdout : "";

            // Define weak algorithms per Mozilla Modern guidelines
            const WEAK_KEXALGORITHMS = [
              "diffie-hellman-group1-sha1",
              "diffie-hellman-group14-sha1",
              "diffie-hellman-group-exchange-sha1",
              "ecdh-sha2-nistp256",
              "ecdh-sha2-nistp384",
              "ecdh-sha2-nistp521",
            ];
            const RECOMMENDED_KEXALGORITHMS = [
              "sntrup761x25519-sha512@openssh.com",
              "curve25519-sha256",
              "curve25519-sha256@libssh.org",
              "diffie-hellman-group16-sha512",
              "diffie-hellman-group18-sha512",
              "diffie-hellman-group-exchange-sha256",
            ];

            const WEAK_CIPHERS = [
              "3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc",
              "blowfish-cbc", "cast128-cbc", "arcfour", "arcfour128", "arcfour256",
              "rijndael-cbc@lysator.liu.se",
            ];
            const RECOMMENDED_CIPHERS = [
              "chacha20-poly1305@openssh.com",
              "aes256-gcm@openssh.com",
              "aes128-gcm@openssh.com",
              "aes256-ctr",
              "aes192-ctr",
              "aes128-ctr",
            ];

            const WEAK_MACS = [
              "hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96",
              "umac-64@openssh.com", "hmac-ripemd160",
              "hmac-sha1-etm@openssh.com", "hmac-md5-etm@openssh.com",
            ];
            const RECOMMENDED_MACS = [
              "hmac-sha2-512-etm@openssh.com",
              "hmac-sha2-256-etm@openssh.com",
              "umac-128-etm@openssh.com",
              "hmac-sha2-512",
              "hmac-sha2-256",
            ];

            const WEAK_HOSTKEYS = [
              "ssh-dss", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
            ];
            const RECOMMENDED_HOSTKEYS = [
              "ssh-ed25519",
              "ssh-ed25519-cert-v01@openssh.com",
              "sk-ssh-ed25519@openssh.com",
              "rsa-sha2-512",
              "rsa-sha2-256",
            ];

            function getAlgorithms(key: string): string[] {
              const runtimeMatch = runtimeConfig.match(new RegExp(`^${key}\\s+(.+)$`, "mi"));
              if (runtimeMatch) return runtimeMatch[1].split(",").map(s => s.trim());
              const configMatch = config.match(new RegExp(`^\\s*${key}\\s+(.+)$`, "mi"));
              if (configMatch) return configMatch[1].split(",").map(s => s.trim());
              return [];
            }

            const findings: Array<{category: string, status: string, configured: string[], weak_found: string[], recommended: string[], note: string}> = [];

            const checks = [
              { key: "KexAlgorithms", label: "Key Exchange", weak: WEAK_KEXALGORITHMS, recommended: RECOMMENDED_KEXALGORITHMS },
              { key: "Ciphers", label: "Ciphers", weak: WEAK_CIPHERS, recommended: RECOMMENDED_CIPHERS },
              { key: "MACs", label: "MACs", weak: WEAK_MACS, recommended: RECOMMENDED_MACS },
              { key: "HostKeyAlgorithms", label: "Host Key Algorithms", weak: WEAK_HOSTKEYS, recommended: RECOMMENDED_HOSTKEYS },
            ];

            for (const check of checks) {
              const configured = getAlgorithms(check.key);
              const weakFound = configured.filter(a => check.weak.includes(a));

              let status = "PASS";
              let note = "";

              if (configured.length === 0) {
                status = "WARN";
                note = `${check.key} not explicitly set — using system defaults which may include weak algorithms`;
              } else if (weakFound.length > 0) {
                status = "FAIL";
                note = `Found ${weakFound.length} weak algorithm(s): ${weakFound.join(", ")}`;
              } else {
                note = `All ${configured.length} configured algorithms are acceptable`;
              }

              findings.push({
                category: check.label,
                status,
                configured,
                weak_found: weakFound,
                recommended: check.recommended,
                note,
              });
            }

            // Check SSH host key files
            const hostKeyCheck = await executeCommand({
              command: "ls",
              args: ["-la", "/etc/ssh/"],
              timeout: 5000,
              toolName: "access_control",
            });

            const hasDSA = hostKeyCheck.stdout.includes("ssh_host_dsa_key");
            const hasECDSA = hostKeyCheck.stdout.includes("ssh_host_ecdsa_key");
            const hasED25519 = hostKeyCheck.stdout.includes("ssh_host_ed25519_key");
            const hasRSA = hostKeyCheck.stdout.includes("ssh_host_rsa_key");

            const hostKeyFindings: Array<{key: string, status: string, note: string}> = [];
            if (hasDSA) hostKeyFindings.push({ key: "DSA", status: "FAIL", note: "DSA host key present — should be removed" });
            if (hasECDSA) hostKeyFindings.push({ key: "ECDSA", status: "WARN", note: "ECDSA host key present — consider ED25519 only" });
            if (hasED25519) hostKeyFindings.push({ key: "ED25519", status: "PASS", note: "ED25519 host key present — recommended" });
            if (hasRSA) hostKeyFindings.push({ key: "RSA", status: "PASS", note: "RSA host key present — acceptable with RSA-SHA2" });

            const passCount = findings.filter(f => f.status === "PASS").length;
            const failCount = findings.filter(f => f.status === "FAIL").length;
            const warnCount = findings.filter(f => f.status === "WARN").length;

            return {
              content: [createTextContent(JSON.stringify({
                summary: {
                  algorithmChecks: findings.length,
                  pass: passCount,
                  fail: failCount,
                  warn: warnCount,
                  hostKeys: hostKeyFindings,
                },
                algorithmAudit: findings,
                hostKeyAudit: hostKeyFindings,
                recommendation: failCount > 0
                  ? "CRITICAL: Weak SSH algorithms detected. Apply Mozilla Modern SSH configuration immediately."
                  : warnCount > 0
                  ? "WARNING: SSH algorithms not explicitly configured. Set explicit algorithms in sshd_config."
                  : "PASS: SSH cryptographic configuration meets modern standards.",
              }, null, 2))],
            };
          } catch (error) {
            return {
              content: [createErrorContent(error instanceof Error ? error.message : String(error))],
              isError: true,
            };
          }
        }

        // ── pam_audit ────────────────────────────────────────────────
        case "pam_audit": {
          try {
            const filesToCheck: string[] = [];

            if (params.service) {
              filesToCheck.push(`/etc/pam.d/${params.service}`);
            }

            if (params.check_all) {
              const daPam = await getDistroAdapter();
              filesToCheck.push(...daPam.paths.pamAllConfigs);
            }

            if (filesToCheck.length === 0) {
              return {
                content: [
                  createErrorContent(
                    "Specify a 'service' name or set 'check_all' to true."
                  ),
                ],
                isError: true,
              };
            }

            const uniqueFiles = [...new Set(filesToCheck)];

            const fileContents: Record<string, string> = {};
            let unreadableCount = 0;
            for (const filePath of uniqueFiles) {
              const result = await executeCommand({
                command: "sudo",
                args: ["cat", filePath],
                toolName: "access_control",
                timeout: getToolTimeout("access_control"),
              });

              if (result.exitCode === 0) {
                fileContents[filePath] = result.stdout;
              } else {
                fileContents[filePath] = `[ERROR: ${result.stderr.trim()}]`;
              }
            }

            const findings: Array<{
              file: string;
              type: string;
              severity: "critical" | "high" | "medium" | "low" | "info" | "warning";
              detail: string;
            }> = [];

            for (const [filePath, content] of Object.entries(fileContents)) {
              if (content.startsWith("[ERROR:")) {
                unreadableCount++;
                const isPermissionDenied =
                  content.toLowerCase().includes("permission denied") ||
                  content.toLowerCase().includes("operation not permitted");
                findings.push({
                  file: filePath,
                  type: "FILE_UNREADABLE",
                  severity: isPermissionDenied ? "warning" : "medium",
                  detail: isPermissionDenied
                    ? `Permission denied — could not read ${filePath}. Results may be incomplete.`
                    : `Could not read ${filePath}: ${content}. Results may be incomplete.`,
                });
                continue;
              }

              // Check for password hashing algorithm
              if (content.includes("pam_unix.so")) {
                if (content.includes("sha512")) {
                  findings.push({
                    file: filePath,
                    type: "HASH_ALGORITHM",
                    severity: "info",
                    detail: "pam_unix.so is using SHA-512 hashing (good)",
                  });
                } else if (content.includes("md5")) {
                  findings.push({
                    file: filePath,
                    type: "HASH_ALGORITHM",
                    severity: "critical",
                    detail:
                      "pam_unix.so is using MD5 hashing — upgrade to SHA-512",
                  });
                } else if (!content.includes("sha256") && !content.includes("sha512")) {
                  findings.push({
                    file: filePath,
                    type: "HASH_ALGORITHM",
                    severity: "medium",
                    detail:
                      "pam_unix.so password hashing algorithm not explicitly set",
                  });
                }
              }

              // Check for account lockout
              const hasLockout =
                content.includes("pam_tally2") ||
                content.includes("pam_faillock");
              if (!hasLockout && (filePath.includes("common-auth") || filePath.includes("sshd"))) {
                findings.push({
                  file: filePath,
                  type: "LOCKOUT_POLICY",
                  severity: "high",
                  detail:
                    "No account lockout module (pam_tally2/pam_faillock) configured",
                });
              } else if (hasLockout) {
                findings.push({
                  file: filePath,
                  type: "LOCKOUT_POLICY",
                  severity: "info",
                  detail: "Account lockout module is present",
                });
              }

              // Check for password complexity
              const hasComplexity =
                content.includes("pam_pwquality") ||
                content.includes("pam_cracklib");
              if (
                !hasComplexity &&
                (filePath.includes("common-password") || filePath.includes("passwd"))
              ) {
                findings.push({
                  file: filePath,
                  type: "PASSWORD_COMPLEXITY",
                  severity: "high",
                  detail:
                    "No password complexity module (pam_pwquality/pam_cracklib) configured",
                });
              } else if (hasComplexity) {
                findings.push({
                  file: filePath,
                  type: "PASSWORD_COMPLEXITY",
                  severity: "info",
                  detail: "Password complexity module is present",
                });
              }

              // Check for pam_limits.so
              if (
                content.includes("pam_limits.so") &&
                filePath.includes("common-session")
              ) {
                findings.push({
                  file: filePath,
                  type: "RESOURCE_LIMITS",
                  severity: "info",
                  detail: "pam_limits.so is configured for resource limits",
                });
              } else if (
                !content.includes("pam_limits.so") &&
                filePath.includes("common-session")
              ) {
                findings.push({
                  file: filePath,
                  type: "RESOURCE_LIMITS",
                  severity: "medium",
                  detail:
                    "pam_limits.so is not configured — resource limits not enforced",
                });
              }

              // Check for ordering issues
              const lines = content
                .split("\n")
                .filter((l) => l.trim() && !l.trim().startsWith("#"));
              let lastType = "";
              for (const line of lines) {
                const parts = line.trim().split(/\s+/);
                const type = parts[0];
                if (type === "account" && lastType === "session") {
                  findings.push({
                    file: filePath,
                    type: "PAM_ORDERING",
                    severity: "medium",
                    detail:
                      "PAM ordering issue: 'account' entries found after 'session' entries",
                  });
                  break;
                }
                if (type) lastType = type;
              }
            }

            const entry = createChangeEntry({
              tool: "access_control",
              action: `PAM audit${params.service ? ` (${params.service})` : ""}${params.check_all ? " (all common)" : ""}`,
              target: uniqueFiles.join(", "),
              after: `Findings: ${findings.length}`,
              dryRun: false,
              success: true,
            });
            logChange(entry);

            const output = {
              filesChecked: uniqueFiles,
              totalFindings: findings.length,
              unreadableFiles: unreadableCount,
              findings,
              ...(unreadableCount > 0
                ? {
                    warning: `${unreadableCount} file(s) could not be read (insufficient permissions?). Audit results may be incomplete.`,
                  }
                : {}),
              fileContents: Object.fromEntries(
                Object.entries(fileContents).map(([k, v]) => [
                  k,
                  v.startsWith("[ERROR:") ? v : `${v.split("\n").length} lines`,
                ])
              ),
            };

            return { content: [formatToolOutput(output)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── pam_configure ────────────────────────────────────────────
        case "pam_configure": {
          try {
            if (!params.module) {
              return { content: [createErrorContent("Error: 'module' is required for pam_configure action (pwquality or faillock)")], isError: true };
            }

            const pamModule = params.module;
            const isDryRun = params.dry_run ?? getConfig().dryRun;

            if (pamModule === "pwquality") {
              const defaults = {
                minlen: 14,
                dcredit: -1,
                ucredit: -1,
                lcredit: -1,
                ocredit: -1,
                minclass: 3,
                maxrepeat: 3,
                reject_username: true,
              };

              const merged = {
                minlen: params.pam_settings?.minlen ?? defaults.minlen,
                dcredit: params.pam_settings?.dcredit ?? defaults.dcredit,
                ucredit: params.pam_settings?.ucredit ?? defaults.ucredit,
                lcredit: params.pam_settings?.lcredit ?? defaults.lcredit,
                ocredit: params.pam_settings?.ocredit ?? defaults.ocredit,
                minclass: params.pam_settings?.minclass ?? defaults.minclass,
                maxrepeat: params.pam_settings?.maxrepeat ?? defaults.maxrepeat,
                reject_username: params.pam_settings?.reject_username ?? defaults.reject_username,
              };

              const targetFile = "/etc/security/pwquality.conf";
              const configLines = [
                `minlen = ${merged.minlen}`,
                `dcredit = ${merged.dcredit}`,
                `ucredit = ${merged.ucredit}`,
                `lcredit = ${merged.lcredit}`,
                `ocredit = ${merged.ocredit}`,
                `minclass = ${merged.minclass}`,
                `maxrepeat = ${merged.maxrepeat}`,
                merged.reject_username ? `reject_username` : `# reject_username`,
              ];

              if (isDryRun) {
                const entry = createChangeEntry({
                  tool: "access_control",
                  action: "[DRY-RUN] Configure pam_pwquality",
                  target: targetFile,
                  after: JSON.stringify(merged),
                  dryRun: true,
                  success: true,
                });
                logChange(entry);

                return {
                  content: [
                    createTextContent(
                      `[DRY-RUN] Would write the following to ${targetFile}:\n\n` +
                        configLines.map((l) => `  ${l}`).join("\n")
                    ),
                  ],
                };
              }

              // Backup the target file using BackupManager
              const pwqBackupPath = backupFile(targetFile);

              try {
                // Read current file content
                const currentResult = await executeCommand({
                  command: "sudo",
                  args: ["cat", targetFile],
                  toolName: "access_control",
                });

                let currentContent = currentResult.exitCode === 0 ? currentResult.stdout : "";

                // Update each setting
                for (const line of configLines) {
                  const key = line.split(/\s*=\s*/)[0].replace(/^#\s*/, "").trim();
                  const keyRegex = new RegExp(`^#?\\s*${key}(\\s*=|\\s|$)`, "m");
                  if (keyRegex.test(currentContent)) {
                    currentContent = currentContent.replace(
                      new RegExp(`^#?\\s*${key}(\\s*=.*|\\s*)$`, "m"),
                      line
                    );
                  } else {
                    currentContent += `\n${line}`;
                  }
                }

                await executeCommand({
                  command: "sudo",
                  args: ["tee", targetFile],
                  toolName: "access_control",
                  timeout: getToolTimeout("access_control"),
                  stdin: currentContent,
                });

                const entry = createChangeEntry({
                  tool: "access_control",
                  action: "Configure pam_pwquality",
                  target: targetFile,
                  after: JSON.stringify(merged),
                  backupPath: pwqBackupPath,
                  dryRun: false,
                  success: true,
                });
                logChange(entry);

                return {
                  content: [
                    createTextContent(
                      `pam_pwquality configured in ${targetFile}:\n\n` +
                        configLines.map((l) => `  ${l}`).join("\n")
                    ),
                  ],
                };
              } catch (pwqErr: unknown) {
                // Auto-rollback on failure
                try {
                  await executeCommand({
                    command: "sudo",
                    args: ["cp", pwqBackupPath, targetFile],
                    toolName: "access_control",
                  });
                  console.error(`[access_control] Rolled back ${targetFile} from ${pwqBackupPath}`);
                } catch (rollbackErr) {
                  console.error(`[access_control] CRITICAL: pwquality rollback failed: ${rollbackErr}`);
                }
                throw pwqErr;
              }
            }

            // module === "faillock"
            const defaults = {
              deny: 5,
              unlock_time: 900,
              fail_interval: 900,
            };

            const merged = {
              deny: params.pam_settings?.deny ?? defaults.deny,
              unlock_time: params.pam_settings?.unlock_time ?? defaults.unlock_time,
              fail_interval: params.pam_settings?.fail_interval ?? defaults.fail_interval,
            };

            const targetFile = (await getDistroAdapter()).paths.pamAuth;
            const failArgsList = [
              `deny=${merged.deny}`,
              `unlock_time=${merged.unlock_time}`,
              `fail_interval=${merged.fail_interval}`,
            ];
            const failArgs = failArgsList.join(" ");
            const preLine = `auth    required    pam_faillock.so preauth silent ${failArgs}`;
            const authLine = `auth    [default=die]    pam_faillock.so authfail ${failArgs}`;

            if (isDryRun) {
              const entry = createChangeEntry({
                tool: "access_control",
                action: "[DRY-RUN] Configure pam_faillock",
                target: targetFile,
                after: JSON.stringify(merged),
                dryRun: true,
                success: true,
              });
              logChange(entry);

              return {
                content: [
                  createTextContent(
                    `[DRY-RUN] Would add/update pam_faillock.so in ${targetFile}:\n\n` +
                      `  ${preLine}\n  ${authLine}\n\n` +
                      `Settings: ${JSON.stringify(merged)}`
                  ),
                ],
              };
            }

            // Safe PAM modification using pam-utils (replaces fragile sed commands)
            // 1. Backup via BackupManager
            const backupEntry = await backupPamFile(targetFile);

            try {
              // 2. Read & parse current PAM config
              const content = await readPamFile(targetFile);
              let lines = parsePamConfig(content);

              // 3. Remove existing faillock rules
              lines = removeModuleRules(lines, "pam_faillock.so");

              // 4. Create new faillock rules
              const preRule = createPamRule("auth", "required", "pam_faillock.so", [
                "preauth", "silent", ...failArgsList,
              ]);
              const authFailRule = createPamRule("auth", "[default=die]", "pam_faillock.so", [
                "authfail", ...failArgsList,
              ]);

              // 5. Insert before/after pam_unix.so (filtered by pamType: "auth")
              lines = insertBeforeModule(lines, "pam_unix.so", preRule, { pamType: "auth" });
              lines = insertAfterModule(lines, "pam_unix.so", authFailRule, { pamType: "auth" });

              // 5b. Adjust [success=N] jump counts after insertions
              lines = adjustJumpCounts(lines);

              // 6. Serialize & validate
              const newContent = serializePamConfig(lines);

              // 7. Double-check: parse the serialized output and validate
              const recheckLines = parsePamConfig(newContent);
              const recheckValidation = validatePamConfig(recheckLines);
              if (!recheckValidation.valid) {
                throw new PamWriteError(
                  `Generated PAM config failed validation: ${recheckValidation.errors.join("; ")}`,
                  targetFile,
                  backupEntry.id,
                );
              }

              // 8. Write (validates pre and post-write internally)
              await writePamFile(targetFile, newContent);

              const entry = createChangeEntry({
                tool: "access_control",
                action: "Configure pam_faillock",
                target: targetFile,
                after: JSON.stringify(merged),
                backupPath: backupEntry.backupPath,
                dryRun: false,
                success: true,
              });
              logChange(entry);

              return {
                content: [
                  createTextContent(
                    `pam_faillock configured in ${targetFile}:\n\n` +
                      `  ${preLine}\n  ${authLine}\n\n` +
                      `Settings: ${JSON.stringify(merged)}\n` +
                      `Backup: ${backupEntry.backupPath}`
                  ),
                ],
              };
            } catch (err) {
              // 9. Auto-rollback on ANY failure
              try {
                await restorePamFile(backupEntry);
                console.error(`[access_control] Rolled back ${targetFile} from backup ${backupEntry.id}`);
              } catch (restoreErr) {
                console.error(
                  `[access_control] CRITICAL: PAM rollback failed for ${targetFile}: ${restoreErr}`,
                );
              }
              throw err;
            }
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── sudo_audit ───────────────────────────────────────────────
        case "sudo_audit": {
          const { check_nopasswd, check_insecure } = params;
          try {
            // Read main sudoers file
            const sudoersResult = await executeCommand({
              command: "sudo",
              args: ["cat", "/etc/sudoers"],
              toolName: "access_control",
              timeout: getToolTimeout("access_control"),
            });

            if (sudoersResult.exitCode !== 0) {
              return {
                content: [
                  createErrorContent(
                    `Cannot read /etc/sudoers: ${sudoersResult.stderr}`
                  ),
                ],
                isError: true,
              };
            }

            // Read sudoers.d directory
            const sudoersDResult = await executeCommand({
              command: "sudo",
              args: ["ls", "/etc/sudoers.d/"],
              toolName: "access_control",
            });

            const dropInFiles = sudoersDResult.stdout
              .split("\n")
              .map((l) => l.trim())
              .filter((l) => l.length > 0);

            // Read all drop-in files
            let allSudoersContent = sudoersResult.stdout;
            for (const file of dropInFiles) {
              const fileResult = await executeCommand({
                command: "sudo",
                args: ["cat", `/etc/sudoers.d/${file}`],
                toolName: "access_control",
              });
              if (fileResult.exitCode === 0) {
                allSudoersContent += `\n# --- ${file} ---\n${fileResult.stdout}`;
              }
            }

            const findings: Array<{
              type: string;
              severity: "critical" | "high" | "medium" | "low";
              detail: string;
              line?: string;
            }> = [];

            const lines = allSudoersContent.split("\n");

            for (const line of lines) {
              const trimmed = line.trim();
              if (!trimmed || trimmed.startsWith("#")) continue;

              if (check_nopasswd && trimmed.includes("NOPASSWD")) {
                findings.push({
                  type: "NOPASSWD",
                  severity: "high",
                  detail: "NOPASSWD allows sudo without password authentication",
                  line: trimmed,
                });
              }

              if (
                check_insecure &&
                trimmed.includes("ALL=(ALL)") &&
                trimmed.includes("ALL") &&
                !trimmed.startsWith("root")
              ) {
                findings.push({
                  type: "BROAD_PRIVILEGE",
                  severity: "high",
                  detail: "Non-root user has full sudo privileges",
                  line: trimmed,
                });
              }

              if (check_insecure && trimmed.includes("!authenticate")) {
                findings.push({
                  type: "NO_AUTHENTICATE",
                  severity: "critical",
                  detail: "Authentication bypass in sudoers",
                  line: trimmed,
                });
              }
            }

            // Check for missing security defaults
            const defaultChecks: Array<{
              pattern: string;
              name: string;
              severity: "critical" | "high" | "medium" | "low";
            }> = [
              { pattern: "env_reset", name: "Defaults env_reset", severity: "medium" },
              { pattern: "secure_path", name: "Defaults secure_path", severity: "medium" },
              { pattern: "logfile", name: "Defaults logfile", severity: "low" },
            ];

            if (check_insecure) {
              for (const check of defaultChecks) {
                if (!allSudoersContent.includes(check.pattern)) {
                  findings.push({
                    type: "MISSING_DEFAULT",
                    severity: check.severity,
                    detail: `${check.name} is not configured`,
                  });
                }
              }
            }

            // List users with sudo access
            const sudoUsersResult = await executeCommand({
              command: "getent",
              args: ["group", "sudo"],
              toolName: "access_control",
            });

            const sudoGroup = sudoUsersResult.stdout.trim();

            const entry = createChangeEntry({
              tool: "access_control",
              action: "Sudoers configuration audit",
              target: "/etc/sudoers",
              after: `Findings: ${findings.length}`,
              dryRun: false,
              success: true,
            });
            logChange(entry);

            const output = {
              totalFindings: findings.length,
              dropInFiles,
              sudoGroup,
              findings,
            };

            return { content: [formatToolOutput(output)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── user_audit ───────────────────────────────────────────────
        case "user_audit": {
          const { check_type } = params;
          try {
            const passwdResult = await executeCommand({
              command: "cat",
              args: ["/etc/passwd"],
              toolName: "access_control",
              timeout: getToolTimeout("access_control"),
            });

            const shadowResult = await executeCommand({
              command: "sudo",
              args: ["cat", "/etc/shadow"],
              toolName: "access_control",
            });

            const lastlogResult = await executeCommand({
              command: "lastlog",
              args: [],
              toolName: "access_control",
            });

            const users = passwdResult.stdout
              .split("\n")
              .filter((l) => l.trim().length > 0)
              .map((line) => {
                const parts = line.split(":");
                return {
                  username: parts[0],
                  uid: parseInt(parts[2], 10),
                  gid: parseInt(parts[3], 10),
                  gecos: parts[4] ?? "",
                  home: parts[5] ?? "",
                  shell: parts[6] ?? "",
                };
              });

            const shadowMap: Record<string, string> = {};
            if (shadowResult.exitCode === 0) {
              for (const line of shadowResult.stdout.split("\n")) {
                const parts = line.split(":");
                if (parts.length >= 2) {
                  shadowMap[parts[0]] = parts[1];
                }
              }
            }

            const lastlogMap: Record<string, string> = {};
            for (const line of lastlogResult.stdout.split("\n").slice(1)) {
              const trimmed = line.trim();
              if (!trimmed) continue;
              const parts = trimmed.split(/\s+/);
              if (parts.length >= 1) {
                const username = parts[0];
                if (trimmed.includes("Never logged in")) {
                  lastlogMap[username] = "never";
                } else {
                  lastlogMap[username] = parts.slice(3).join(" ");
                }
              }
            }

            const nologinShells = [
              "/usr/sbin/nologin",
              "/bin/false",
              "/sbin/nologin",
              "/bin/nologin",
            ];

            const loginShells = [
              "/bin/bash",
              "/bin/sh",
              "/bin/zsh",
              "/bin/fish",
              "/usr/bin/bash",
              "/usr/bin/zsh",
              "/usr/bin/fish",
            ];

            const results: Record<string, Array<Record<string, unknown>>> = {};

            if (check_type === "all" || check_type === "privileged") {
              results.privileged = users
                .filter((u) => u.uid === 0)
                .map((u) => ({
                  username: u.username,
                  uid: u.uid,
                  shell: u.shell,
                  warning:
                    u.username !== "root"
                      ? "NON-ROOT USER WITH UID 0!"
                      : null,
                }));
            }

            if (check_type === "all" || check_type === "inactive") {
              results.inactive = users
                .filter((u) => {
                  const lastLogin = lastlogMap[u.username];
                  if (!lastLogin || lastLogin === "never") return true;
                  const loginDate = new Date(lastLogin);
                  const daysSince =
                    (Date.now() - loginDate.getTime()) / (1000 * 60 * 60 * 24);
                  return daysSince > 90;
                })
                .filter((u) => !nologinShells.includes(u.shell))
                .map((u) => ({
                  username: u.username,
                  uid: u.uid,
                  lastLogin: lastlogMap[u.username] ?? "unknown",
                  shell: u.shell,
                }));
            }

            if (check_type === "all" || check_type === "no_password") {
              results.no_password = users
                .filter((u) => {
                  const hash = shadowMap[u.username];
                  return hash === "" || hash === "!" || hash === "*" || hash === "!!";
                })
                .map((u) => ({
                  username: u.username,
                  uid: u.uid,
                  passwordStatus: shadowMap[u.username] || "empty",
                  shell: u.shell,
                }));
            }

            if (check_type === "all" || check_type === "shell") {
              const systemUsers = users.filter(
                (u) => u.uid < 1000 && u.uid !== 0
              );
              results.shell = systemUsers
                .filter((u) => loginShells.includes(u.shell))
                .map((u) => ({
                  username: u.username,
                  uid: u.uid,
                  shell: u.shell,
                  warning: "System user has interactive login shell",
                }));
            }

            if (check_type === "all" || check_type === "locked") {
              results.locked = users
                .filter((u) => {
                  const hash = shadowMap[u.username];
                  return (
                    hash?.startsWith("!") ||
                    hash?.startsWith("*") ||
                    nologinShells.includes(u.shell)
                  );
                })
                .map((u) => ({
                  username: u.username,
                  uid: u.uid,
                  shell: u.shell,
                  locked: shadowMap[u.username]?.startsWith("!") ?? false,
                  nologin: nologinShells.includes(u.shell),
                }));
            }

            const totalFindings = Object.values(results).reduce(
              (sum, arr) => sum + arr.length,
              0
            );

            const entry = createChangeEntry({
              tool: "access_control",
              action: `User account audit (${check_type})`,
              target: "/etc/passwd",
              after: `Total findings: ${totalFindings}`,
              dryRun: false,
              success: true,
            });
            logChange(entry);

            const output = {
              checkType: check_type,
              totalUsers: users.length,
              totalFindings,
              categories: results,
            };

            return { content: [formatToolOutput(output)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── password_policy_audit ────────────────────────────────────
        case "password_policy_audit": {
          try {
            const loginDefsResult = await executeCommand({
              command: "cat",
              args: ["/etc/login.defs"],
              toolName: "access_control",
              timeout: getToolTimeout("access_control"),
            });

            const pamResult = await executeCommand({
              command: "cat",
              args: [(await getDistroAdapter()).paths.pamPassword],
              toolName: "access_control",
            });

            const loginDefs: Record<string, string> = {};
            const passwordKeys = [
              "PASS_MAX_DAYS",
              "PASS_MIN_DAYS",
              "PASS_WARN_AGE",
              "PASS_MIN_LEN",
              "ENCRYPT_METHOD",
              "SHA_CRYPT_MIN_ROUNDS",
              "SHA_CRYPT_MAX_ROUNDS",
              "INACTIVE",
            ];

            for (const line of loginDefsResult.stdout.split("\n")) {
              const trimmed = line.trim();
              if (!trimmed || trimmed.startsWith("#")) continue;

              const parts = trimmed.split(/\s+/);
              if (parts.length >= 2 && passwordKeys.includes(parts[0])) {
                loginDefs[parts[0]] = parts[1];
              }
            }

            const pamModules: Array<{ module: string; present: boolean }> = [
              { module: "pam_pwquality", present: false },
              { module: "pam_cracklib", present: false },
              { module: "pam_unix", present: false },
            ];

            if (pamResult.exitCode === 0) {
              for (const mod of pamModules) {
                mod.present = pamResult.stdout.includes(mod.module);
              }
            }

            const useraddResult = await executeCommand({
              command: "cat",
              args: ["/etc/default/useradd"],
              toolName: "access_control",
            });
            let inactiveValue = "not set";
            if (useraddResult.exitCode === 0) {
              const inactiveMatch = useraddResult.stdout.match(/^INACTIVE=(.*)$/m);
              if (inactiveMatch) {
                inactiveValue = inactiveMatch[1].trim();
                loginDefs["INACTIVE"] = inactiveValue;
              }
            }

            const recommendations: string[] = [];
            const maxDays = parseInt(loginDefs["PASS_MAX_DAYS"] ?? "99999", 10);
            const minDays = parseInt(loginDefs["PASS_MIN_DAYS"] ?? "0", 10);
            const warnAge = parseInt(loginDefs["PASS_WARN_AGE"] ?? "7", 10);

            if (maxDays > 365) {
              recommendations.push(
                `PASS_MAX_DAYS (${maxDays}) should be <= 365. Set to 365 or less (CIS recommends ≤365 for non-privileged, ≤90 for privileged)`
              );
            }
            if (minDays < 1) {
              recommendations.push(
                `PASS_MIN_DAYS (${minDays}) should be >= 1`
              );
            }
            if (warnAge < 7) {
              recommendations.push(
                `PASS_WARN_AGE (${warnAge}) should be >= 7`
              );
            }
            const encMethod = loginDefs["ENCRYPT_METHOD"] ?? "not set";
            if (encMethod !== "SHA512" && encMethod !== "YESCRYPT") {
              recommendations.push(
                `ENCRYPT_METHOD should be SHA512 or YESCRYPT (current: ${encMethod})`
              );
            }
            if (inactiveValue === "not set" || inactiveValue === "-1") {
              recommendations.push(
                `INACTIVE (${inactiveValue}) should be set to 30 or less to disable accounts after password expiry`
              );
            }
            if (!pamModules.find((m) => m.module === "pam_pwquality")?.present) {
              recommendations.push(
                "pam_pwquality is not configured in PAM - password complexity not enforced"
              );
            }

            const entry = createChangeEntry({
              tool: "access_control",
              action: "Password policy audit",
              target: "/etc/login.defs",
              after: `Recommendations: ${recommendations.length}`,
              dryRun: false,
              success: true,
            });
            logChange(entry);

            const output = {
              loginDefs,
              pamModules,
              recommendations,
            };

            return { content: [formatToolOutput(output)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── password_policy_set ──────────────────────────────────────
        case "password_policy_set": {
          const { min_days, max_days, warn_days, min_length, inactive_days, encrypt_method, dry_run } = params;
          try {
            const settingsToApply: Record<string, string> = {};
            if (min_days !== undefined) settingsToApply["PASS_MIN_DAYS"] = String(min_days);
            if (max_days !== undefined) settingsToApply["PASS_MAX_DAYS"] = String(max_days);
            if (warn_days !== undefined) settingsToApply["PASS_WARN_AGE"] = String(warn_days);
            if (min_length !== undefined) settingsToApply["PASS_MIN_LEN"] = String(min_length);
            if (encrypt_method !== undefined) settingsToApply["ENCRYPT_METHOD"] = encrypt_method;

            const extraCommands: string[] = [];

            if (inactive_days !== undefined) {
              extraCommands.push(`sudo useradd -D -f ${inactive_days}`);
              extraCommands.push(
                `sudo sed -i 's/^INACTIVE.*/INACTIVE=${inactive_days}/' /etc/default/useradd || echo 'INACTIVE=${inactive_days}' | sudo tee -a /etc/default/useradd`
              );
            }

            if (Object.keys(settingsToApply).length === 0 && extraCommands.length === 0) {
              return {
                content: [
                  createErrorContent(
                    "No password policy values specified to set."
                  ),
                ],
                isError: true,
              };
            }

            const sedCommands: string[] = [];
            for (const [key, value] of Object.entries(settingsToApply)) {
              sedCommands.push(
                `sudo sed -i 's/^#*\\s*${key}\\s.*/${key}\\t${value}/' /etc/login.defs`
              );
            }

            if (dry_run ?? getConfig().dryRun) {
              const allSettings = { ...settingsToApply };
              if (inactive_days !== undefined) allSettings["INACTIVE"] = String(inactive_days);

              const entry = createChangeEntry({
                tool: "access_control",
                action: "[DRY-RUN] Set password policy",
                target: "/etc/login.defs",
                after: JSON.stringify(allSettings),
                dryRun: true,
                success: true,
              });
              logChange(entry);

              return {
                content: [
                  createTextContent(
                    `[DRY-RUN] Would apply the following password policy to /etc/login.defs:\n\n` +
                      Object.entries(allSettings)
                        .map(([k, v]) => `  ${k} = ${v}`)
                        .join("\n") +
                      `\n\nSed commands:\n${sedCommands.map((c) => `  ${c}`).join("\n")}` +
                      (extraCommands.length > 0
                        ? `\n\nExtra commands:\n${extraCommands.map((c) => `  ${c}`).join("\n")}`
                        : "")
                  ),
                ],
              };
            }

            // Backup first
            let backupPath: string | undefined;
            try {
              backupPath = backupFile("/etc/login.defs");
            } catch {
              await executeCommand({
                command: "sudo",
                args: [
                  "cp",
                  "/etc/login.defs",
                  `/etc/login.defs.bak.${Date.now()}`,
                ],
                toolName: "access_control",
              });
            }

            // Apply login.defs changes
            for (const [key, value] of Object.entries(settingsToApply)) {
              await executeCommand({
                command: "sudo",
                args: [
                  "sed",
                  "-i",
                  `s/^#*\\s*${key}\\s.*/${key}\\t${value}/`,
                  "/etc/login.defs",
                ],
                toolName: "access_control",
                timeout: getToolTimeout("access_control"),
              });
            }

            // Apply INACTIVE setting if provided
            if (inactive_days !== undefined) {
              await executeCommand({
                command: "sudo",
                args: ["useradd", "-D", "-f", String(inactive_days)],
                toolName: "access_control",
                timeout: getToolTimeout("access_control"),
              });

              const grepInactive = await executeCommand({
                command: "grep",
                args: ["-q", "^INACTIVE", "/etc/default/useradd"],
                toolName: "access_control",
              });

              if (grepInactive.exitCode === 0) {
                await executeCommand({
                  command: "sudo",
                  args: [
                    "sed",
                    "-i",
                    `s/^INACTIVE.*/INACTIVE=${inactive_days}/`,
                    "/etc/default/useradd",
                  ],
                  toolName: "access_control",
                });
              } else {
                await executeCommand({
                  command: "sudo",
                  args: ["tee", "-a", "/etc/default/useradd"],
                  toolName: "access_control",
                  stdin: `INACTIVE=${inactive_days}\n`,
                });
              }
            }

            const allApplied = { ...settingsToApply };
            if (inactive_days !== undefined) allApplied["INACTIVE"] = String(inactive_days);

            const entry = createChangeEntry({
              tool: "access_control",
              action: "Set password policy",
              target: "/etc/login.defs",
              after: JSON.stringify(allApplied),
              backupPath,
              dryRun: false,
              success: true,
              rollbackCommand: backupPath
                ? `sudo cp ${backupPath} /etc/login.defs`
                : undefined,
            });
            logChange(entry);

            return {
              content: [
                createTextContent(
                  `Password policy updated in /etc/login.defs:\n\n` +
                    Object.entries(allApplied)
                      .map(([k, v]) => `  ${k} = ${v}`)
                      .join("\n") +
                    (backupPath ? `\n\nBackup: ${backupPath}` : "")
                ),
              ],
            };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── restrict_shell ───────────────────────────────────────────
        case "restrict_shell": {
          const { username, shell, dry_run } = params;
          try {
            if (!username) {
              return {
                content: [createErrorContent("'username' is required for restrict_shell action")],
                isError: true,
              };
            }

            // Validate username
            if (!/^[a-z_][a-z0-9_-]{0,31}$/.test(username)) {
              return {
                content: [
                  createErrorContent(
                    `Invalid username '${username}'. Must match /^[a-z_][a-z0-9_-]{0,31}$/.`
                  ),
                ],
                isError: true,
              };
            }

            // Validate shell path
            if (!/^\/[a-z\/]+$/.test(shell)) {
              return {
                content: [
                  createErrorContent(
                    `Invalid shell path '${shell}'. Must match /^\\/[a-z\\/]+$/.`
                  ),
                ],
                isError: true,
              };
            }

            // Safety check: refuse to change shell for root
            if (username === "root") {
              return {
                content: [
                  createErrorContent(
                    "Refusing to change shell for root user. This is a safety restriction."
                  ),
                ],
                isError: true,
              };
            }

            // Safety check: refuse to change shell for current user
            const whoamiResult = await executeCommand({
              command: "whoami",
              args: [],
              toolName: "access_control",
            });
            const currentUser = whoamiResult.stdout.trim();
            if (username === currentUser) {
              return {
                content: [
                  createErrorContent(
                    `Refusing to change shell for the current user '${currentUser}'. This is a safety restriction.`
                  ),
                ],
                isError: true,
              };
            }

            // Check that the user exists
            const idResult = await executeCommand({
              command: "id",
              args: [username],
              toolName: "access_control",
            });
            if (idResult.exitCode !== 0) {
              return {
                content: [
                  createErrorContent(`User '${username}' does not exist.`),
                ],
                isError: true,
              };
            }

            // Get current shell
            const getentResult = await executeCommand({
              command: "getent",
              args: ["passwd", username],
              toolName: "access_control",
            });
            const currentShell = getentResult.stdout.trim().split(":").pop() ?? "unknown";

            if (dry_run ?? getConfig().dryRun) {
              const entry = createChangeEntry({
                tool: "access_control",
                action: `[DRY-RUN] Restrict shell for ${username}`,
                target: `/etc/passwd (${username})`,
                before: `shell=${currentShell}`,
                after: `shell=${shell}`,
                dryRun: true,
                success: true,
              });
              logChange(entry);

              return {
                content: [
                  createTextContent(
                    `[DRY-RUN] Would change shell for '${username}':\n\n` +
                      `  Current shell: ${currentShell}\n` +
                      `  New shell:     ${shell}\n\n` +
                      `  Command: sudo usermod -s ${shell} ${username}`
                  ),
                ],
              };
            }

            // Apply the shell change
            const result = await executeCommand({
              command: "sudo",
              args: ["usermod", "-s", shell, username],
              toolName: "access_control",
              timeout: getToolTimeout("access_control"),
            });

            if (result.exitCode !== 0) {
              const entry = createChangeEntry({
                tool: "access_control",
                action: `Restrict shell for ${username}`,
                target: `/etc/passwd (${username})`,
                before: `shell=${currentShell}`,
                after: `shell=${shell}`,
                dryRun: false,
                success: false,
                error: result.stderr,
              });
              logChange(entry);

              return {
                content: [
                  createErrorContent(
                    `Failed to change shell for '${username}': ${result.stderr}`
                  ),
                ],
                isError: true,
              };
            }

            const entry = createChangeEntry({
              tool: "access_control",
              action: `Restrict shell for ${username}`,
              target: `/etc/passwd (${username})`,
              before: `shell=${currentShell}`,
              after: `shell=${shell}`,
              dryRun: false,
              success: true,
              rollbackCommand: `sudo usermod -s ${currentShell} ${username}`,
            });
            logChange(entry);

            return {
              content: [
                createTextContent(
                  `Shell restricted for '${username}':\n\n` +
                    `  Previous shell: ${currentShell}\n` +
                    `  New shell:      ${shell}\n\n` +
                    `  Rollback: sudo usermod -s ${currentShell} ${username}`
                ),
              ],
            };
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
