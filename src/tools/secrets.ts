/**
 * Secrets tools for Defense MCP Server.
 *
 * Registers 1 tool: secrets (actions: scan, env_audit, ssh_key_sprawl, git_history_scan).
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeCommand } from "../core/executor.js";
import {
  createTextContent,
  createErrorContent,
  formatToolOutput,
} from "../core/parsers.js";

// ── TOOL-021 remediation: error message sanitization ───────────────────────

/** Patterns for sensitive environment variable names */
const SENSITIVE_ENV_PATTERNS = [
  /SECRET/i,
  /KEY/i,
  /TOKEN/i,
  /PASSWORD/i,
  /PASSWD/i,
  /CREDENTIAL/i,
  /AUTH/i,
  /API_KEY/i,
  /PRIVATE/i,
];

/**
 * Sanitize an error message by redacting potential environment variable values
 * and other sensitive data that might be exposed in error output.
 * Never logs the full process.env object.
 */
function sanitizeErrorMessage(message: string): string {
  let sanitized = message;

  // Redact values of known-sensitive environment variables
  for (const [key, value] of Object.entries(process.env)) {
    if (!value || value.length < 4) continue; // Skip very short values
    const isSensitive = SENSITIVE_ENV_PATTERNS.some((pattern) =>
      pattern.test(key)
    );
    if (isSensitive) {
      // Replace all occurrences of the sensitive value
      sanitized = sanitized.split(value).join("[REDACTED]");
    }
  }

  // Redact common token-like patterns in the message itself
  sanitized = sanitized.replace(
    /(ghp_|gho_|github_pat_|sk-|sk_live_|AKIA|glpat-|glrt-|hvs\.)[A-Za-z0-9_\-]{8,}/g,
    "$1[REDACTED]"
  );

  // Redact long base64-like strings that may be tokens/keys (40+ chars)
  sanitized = sanitized.replace(
    /(?<==|:\s*)[A-Za-z0-9+/]{40,}={0,2}/g,
    "[REDACTED]"
  );

  return sanitized;
}

// ── Registration entry point ───────────────────────────────────────────────

export function registerSecretsTools(server: McpServer): void {
  server.tool(
    "secrets",
    "Secrets: filesystem scan, env variable audit, SSH key sprawl, git history leak detection",
    {
      action: z.enum(["scan", "env_audit", "ssh_key_sprawl", "git_history_scan"]).describe("Secrets scanning action"),
      // scan params
      path: z.string().default("/home").describe("Root path to scan"),
      scan_type: z.enum(["all", "api_keys", "private_keys", "passwords", "tokens"]).default("all").describe("Type of secrets to scan for"),
      max_depth: z.number().optional().default(5).describe("Maximum directory depth to search"),
      // env_audit params
      check_env: z.boolean().optional().default(true).describe("Check environment variables for sensitive names"),
      check_files: z.boolean().optional().default(true).describe("Check for exposed .env files on disk"),
      // ssh_key_sprawl params
      search_path: z.string().optional().default("/home").describe("Root path to search for SSH keys"),
      check_authorized_keys: z.boolean().optional().default(true).describe("Also audit authorized_keys files"),
      // git_history_scan params
      repoPath: z.string().optional().describe("Path to git repository"),
      dryRun: z.boolean().optional().default(true).describe("Preview only"),
    },
    async (params) => {
      const { action } = params;

      switch (action) {
        // ── scan ─────────────────────────────────────────────────────
        case "scan": {
          const { path: scanPath, scan_type, max_depth } = params;
          try {
            const findings: Record<string, string[]> = {};

            // ── API Keys ───────────────────────────────────────────────────
            if (scan_type === "all" || scan_type === "api_keys") {
              const result = await executeCommand({
                command: "grep",
                args: [
                  "-rnl",
                  "--include=*.py", "--include=*.js", "--include=*.ts",
                  "--include=*.rb", "--include=*.go", "--include=*.java",
                  "--include=*.yaml", "--include=*.yml", "--include=*.json",
                  "--include=*.xml", "--include=*.conf", "--include=*.cfg",
                  "--include=*.env", "--include=*.ini", "--include=*.sh",
                  `-E`,
                  `(api[_-]?key|apikey|api[_-]?secret)\\s*[:=]`,
                  `--max-depth=${max_depth}`,
                  scanPath,
                ],
                toolName: "secrets",
                timeout: 60000,
              });
              const files = result.stdout.split("\n").filter((l) => l.trim());
              if (files.length > 0) {
                findings["api_keys"] = files;
              }
            }

            // ── Private Keys ───────────────────────────────────────────────
            if (scan_type === "all" || scan_type === "private_keys") {
              const result = await executeCommand({
                command: "find",
                args: [
                  scanPath,
                  "-maxdepth", String(max_depth),
                  "(", "-name", "*.pem",
                  "-o", "-name", "*.key",
                  "-o", "-name", "id_rsa",
                  "-o", "-name", "id_ecdsa",
                  "-o", "-name", "id_ed25519",
                  "-o", "-name", "*.p12",
                  "-o", "-name", "*.pfx",
                  ")",
                  "-type", "f",
                ],
                toolName: "secrets",
                timeout: 60000,
              });
              const files = result.stdout.split("\n").filter((l) => l.trim());

              if (files.length > 0) {
                const keyDetails: string[] = [];
                for (const file of files.slice(0, 50)) {
                  const statResult = await executeCommand({
                    command: "stat",
                    args: ["-c", "%a %U:%G %n", file],
                    toolName: "secrets",
                    timeout: 5000,
                  });
                  if (statResult.exitCode === 0 && statResult.stdout.trim()) {
                    const perms = statResult.stdout.trim().split(" ")[0];
                    const permWarning =
                      perms !== "600" && perms !== "400"
                        ? " [WARNING: insecure permissions]"
                        : " [OK]";
                    keyDetails.push(`${statResult.stdout.trim()}${permWarning}`);
                  }
                }
                findings["private_keys"] = keyDetails;
              }
            }

            // ── Passwords ──────────────────────────────────────────────────
            if (scan_type === "all" || scan_type === "passwords") {
              const result = await executeCommand({
                command: "grep",
                args: [
                  "-rnl",
                  "--include=*.py", "--include=*.js", "--include=*.ts",
                  "--include=*.rb", "--include=*.conf", "--include=*.cfg",
                  "--include=*.env", "--include=*.ini", "--include=*.yaml",
                  "--include=*.yml", "--include=*.json",
                  `-E`,
                  `(password|passwd|secret|token)\\s*[:=]\\s*['"][^'"]{4,}`,
                  `--max-depth=${max_depth}`,
                  scanPath,
                ],
                toolName: "secrets",
                timeout: 60000,
              });
              const files = result.stdout.split("\n").filter((l) => l.trim());
              if (files.length > 0) {
                findings["passwords"] = files;
              }
            }

            // ── Tokens ─────────────────────────────────────────────────────
            if (scan_type === "all" || scan_type === "tokens") {
              const tokenPatterns = [
                "ghp_",
                "gho_",
                "github_pat_",
                "sk-",
                "sk_live_[A-Za-z0-9]{24,}",
                "rk_live_",
                "AKIA[0-9A-Z]",
                "xox[bpors]-[A-Za-z0-9-]{10,}",
                "glpat-[A-Za-z0-9_-]{20,}",
                "glrt-[A-Za-z0-9_-]{20,}",
                "hvs\\.[A-Za-z0-9_-]{24,}",
                "s\\.[A-Za-z0-9]{24}",
                '"type":.*"service_account"',
                "AZURE_(CLIENT_SECRET|TENANT_ID|SUBSCRIPTION_KEY)",
                "[A-Za-z0-9+/]{40,}={0,2}",
              ];
              const result = await executeCommand({
                command: "grep",
                args: [
                  "-rnl",
                  `-E`,
                  `(${tokenPatterns.join("|")})`,
                  `--max-depth=${max_depth}`,
                  scanPath,
                ],
                toolName: "secrets",
                timeout: 60000,
              });
              const files = result.stdout.split("\n").filter((l) => l.trim());
              if (files.length > 0) {
                findings["tokens"] = files;
              }
            }

            const totalFindings = Object.values(findings).reduce(
              (sum, arr) => sum + arr.length,
              0
            );

            const lines: string[] = [
              `=== Secrets Scan Report ===`,
              `Path: ${scanPath}`,
              `Scan Type: ${scan_type}`,
              `Max Depth: ${max_depth}`,
              `Total Findings: ${totalFindings}`,
              ``,
            ];

            for (const [category, files] of Object.entries(findings)) {
              lines.push(`── ${category.toUpperCase()} (${files.length} found) ──`);
              for (const file of files) {
                lines.push(`  ${file}`);
              }
              lines.push(``);
            }

            if (totalFindings === 0) {
              lines.push(`No hardcoded secrets detected in the scanned path.`);
            }

            return { content: [createTextContent(lines.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(sanitizeErrorMessage(msg))], isError: true };
          }
        }

        // ── env_audit ────────────────────────────────────────────────
        case "env_audit": {
          const { check_env, check_files } = params;
          try {
            const lines: string[] = [
              `=== Environment Security Audit ===`,
              ``,
            ];

            if (check_env) {
              lines.push(`── SENSITIVE ENVIRONMENT VARIABLES ──`);
              const envResult = await executeCommand({
                command: "env",
                args: [],
                toolName: "secrets",
                timeout: 10000,
              });

              const sensitivePattern = /password|secret|token|key|api/i;
              const envVars = envResult.stdout
                .split("\n")
                .filter((line) => sensitivePattern.test(line.split("=")[0] ?? ""))
                .map((line) => line.replace(/=.*/, "=<REDACTED>"))
                .sort();

              if (envVars.length > 0) {
                lines.push(`Found ${envVars.length} sensitive variable(s) (values redacted):`);
                for (const v of envVars) {
                  lines.push(`  ${v}`);
                }
              } else {
                lines.push(`No sensitive environment variables detected.`);
              }
              lines.push(``);
            }

            if (check_files) {
              lines.push(`── .ENV FILE EXPOSURE ──`);
              const findResult = await executeCommand({
                command: "find",
                args: [
                  "/home", "/tmp", "/var",
                  "(", "-name", ".env",
                  "-o", "-name", ".env.local",
                  "-o", "-name", ".env.production",
                  ")",
                  "-type", "f",
                ],
                toolName: "secrets",
                timeout: 30000,
              });

              const envFiles = findResult.stdout.split("\n").filter((l) => l.trim());

              if (envFiles.length > 0) {
                lines.push(`Found ${envFiles.length} .env file(s):`);
                for (const file of envFiles) {
                  const statResult = await executeCommand({
                    command: "stat",
                    args: ["-c", "%a %U:%G %n", file],
                    toolName: "secrets",
                    timeout: 5000,
                  });
                  if (statResult.exitCode === 0 && statResult.stdout.trim()) {
                    const perms = statResult.stdout.trim().split(" ")[0];
                    let status = "[OK]";
                    if (perms !== "600") {
                      status = `[WARNING: permissions ${perms}, should be 600]`;
                    }
                    const worldReadable = (parseInt(perms, 8) & 0o004) !== 0;
                    if (worldReadable) {
                      status = `[CRITICAL: world-readable (${perms})]`;
                    }
                    lines.push(`  ${statResult.stdout.trim()} ${status}`);
                  }
                }
              } else {
                lines.push(`No .env files found in /home, /tmp, /var.`);
              }
              lines.push(``);

              lines.push(`── /proc/*/environ ACCESSIBILITY ──`);
              const proc1Result = await executeCommand({
                command: "ls",
                args: ["-la", "/proc/1/environ"],
                toolName: "secrets",
                timeout: 5000,
              });
              const procFindResult = await executeCommand({
                command: "find",
                args: ["/proc", "-maxdepth", "2", "-name", "environ", "-readable"],
                toolName: "secrets",
                timeout: 10000,
              });

              const procOutput = [
                ...(proc1Result.exitCode === 0 ? [proc1Result.stdout.trim()] : []),
                ...(procFindResult.exitCode === 0 ? procFindResult.stdout.trim().split("\n") : []),
              ].filter((l) => l.trim());

              if (procOutput.length > 0) {
                const readableFiles = procOutput.filter((l) => l.startsWith("/proc"));
                if (readableFiles.length > 0) {
                  lines.push(`WARNING: ${readableFiles.length} /proc/*/environ file(s) are readable by current user.`);
                  lines.push(`These should only be readable by root (permissions 400).`);
                  for (const f of readableFiles.slice(0, 10)) {
                    lines.push(`  ${f}`);
                  }
                  if (readableFiles.length > 10) {
                    lines.push(`  ... and ${readableFiles.length - 10} more`);
                  }
                } else {
                  lines.push(`/proc/*/environ files are properly restricted.`);
                }
              } else {
                lines.push(`/proc/*/environ files are properly restricted.`);
              }
              lines.push(``);
            }

            return { content: [createTextContent(lines.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(sanitizeErrorMessage(msg))], isError: true };
          }
        }

        // ── ssh_key_sprawl ───────────────────────────────────────────
        case "ssh_key_sprawl": {
          const { search_path, check_authorized_keys } = params;
          try {
            const lines: string[] = [
              `=== SSH Key Sprawl Report ===`,
              `Search Path: ${search_path}`,
              ``,
            ];

            lines.push(`── SSH PRIVATE KEYS ──`);
            const findResult = await executeCommand({
              command: "find",
              args: [
                search_path,
                "-name", "id_*",
                "-not", "-name", "*.pub",
                "-type", "f",
              ],
              toolName: "secrets",
              timeout: 30000,
            });

            const keyFiles = findResult.stdout.split("\n").filter((l) => l.trim());

            if (keyFiles.length > 0) {
              lines.push(`Found ${keyFiles.length} SSH private key(s):`);
              lines.push(``);

              for (const keyFile of keyFiles) {
                lines.push(`  Key: ${keyFile}`);

                const statResult = await executeCommand({
                  command: "stat",
                  args: ["-c", "%a %U:%G %Y", keyFile],
                  toolName: "secrets",
                  timeout: 5000,
                });

                if (statResult.exitCode === 0 && statResult.stdout.trim()) {
                  const parts = statResult.stdout.trim().split(" ");
                  const perms = parts[0];
                  const owner = parts[1];
                  const mtime = parseInt(parts[2], 10);

                  const permStatus =
                    perms === "600" || perms === "400"
                      ? "[OK]"
                      : `[WARNING: permissions ${perms}, should be 600]`;
                  lines.push(`    Permissions: ${perms} ${permStatus}`);
                  lines.push(`    Owner: ${owner}`);

                  const ageMs = Date.now() - mtime * 1000;
                  const ageDays = Math.floor(ageMs / (1000 * 60 * 60 * 24));
                  const ageWarning =
                    ageDays > 365
                      ? ` [WARNING: key is ${ageDays} days old, consider rotation]`
                      : "";
                  lines.push(`    Age: ${ageDays} days${ageWarning}`);
                }

                const keygenResult = await executeCommand({
                  command: "ssh-keygen",
                  args: ["-l", "-f", keyFile],
                  toolName: "secrets",
                  timeout: 5000,
                });

                if (keygenResult.exitCode === 0 && keygenResult.stdout.trim()) {
                  lines.push(`    Key Info: ${keygenResult.stdout.trim()}`);
                }
                lines.push(``);
              }
            } else {
              lines.push(`No SSH private keys found.`);
              lines.push(``);
            }

            if (check_authorized_keys) {
              lines.push(`── AUTHORIZED_KEYS FILES ──`);
              const akResult = await executeCommand({
                command: "find",
                args: [
                  search_path,
                  "-name", "authorized_keys",
                  "-type", "f",
                ],
                toolName: "secrets",
                timeout: 30000,
              });

              const akFiles = akResult.stdout.split("\n").filter((l) => l.trim());

              if (akFiles.length > 0) {
                lines.push(`Found ${akFiles.length} authorized_keys file(s):`);
                lines.push(``);

                for (const akFile of akFiles) {
                  lines.push(`  File: ${akFile}`);

                  const statResult = await executeCommand({
                    command: "stat",
                    args: ["-c", "%a %U:%G", akFile],
                    toolName: "secrets",
                    timeout: 5000,
                  });

                  if (statResult.exitCode === 0 && statResult.stdout.trim()) {
                    const parts = statResult.stdout.trim().split(" ");
                    const perms = parts[0];
                    const owner = parts[1];
                    const permStatus =
                      perms === "600" || perms === "644"
                        ? "[OK]"
                        : `[WARNING: permissions ${perms}, should be 600]`;
                    lines.push(`    Permissions: ${perms} ${permStatus}`);
                    lines.push(`    Owner: ${owner}`);
                  }

                  const wcResult = await executeCommand({
                    command: "grep",
                    args: ["-c", "^[^#]", akFile],
                    toolName: "secrets",
                    timeout: 5000,
                  });
                  const entryCount = parseInt(wcResult.stdout.trim(), 10) || 0;
                  lines.push(`    Entries: ${entryCount}`);

                  const cmdResult = await executeCommand({
                    command: "grep",
                    args: ["-c", "^command=", akFile],
                    toolName: "secrets",
                    timeout: 5000,
                  });
                  const cmdRestricted = parseInt(cmdResult.stdout.trim(), 10) || 0;
                  if (entryCount > 0) {
                    const unrestricted = entryCount - cmdRestricted;
                    if (unrestricted > 0) {
                      lines.push(`    Command-restricted: ${cmdRestricted}/${entryCount} [WARNING: ${unrestricted} unrestricted key(s)]`);
                    } else {
                      lines.push(`    Command-restricted: ${cmdRestricted}/${entryCount} [OK: all keys restricted]`);
                    }
                  }
                  lines.push(``);
                }
              } else {
                lines.push(`No authorized_keys files found.`);
                lines.push(``);
              }
            }

            lines.push(`── SUMMARY ──`);
            lines.push(`Private keys found: ${keyFiles.length}`);
            if (check_authorized_keys) {
              const akFindResult = await executeCommand({
                command: "find",
                args: [search_path, "-name", "authorized_keys", "-type", "f"],
                toolName: "secrets",
                timeout: 10000,
              });
              const akCount = akFindResult.stdout.trim().split("\n").filter((l) => l.trim()).length;
              lines.push(`Authorized_keys files: ${akCount}`);
            }

            return { content: [createTextContent(lines.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(sanitizeErrorMessage(msg))], isError: true };
          }
        }

        // ── git_history_scan ─────────────────────────────────────────
        case "git_history_scan": {
          const { repoPath, dryRun } = params;
          try {
            if (!repoPath) {
              return { content: [createErrorContent("repoPath is required for git_history_scan action")], isError: true };
            }

            if (dryRun) {
              return {
                content: [formatToolOutput({
                  dryRun: true,
                  repoPath,
                  methods: ["truffleHog git", "gitleaks detect"],
                })],
              };
            }

            const thWhich = await executeCommand({ toolName: "secrets", command: "which", args: ["trufflehog"], timeout: 5000 });
            if (thWhich.exitCode === 0) {
              const result = await executeCommand({
                toolName: "secrets",
                command: "trufflehog",
                args: ["git", `file://${repoPath}`, "--json"],
                timeout: 300000,
              });
              const findings = result.stdout.trim().split("\n").filter(Boolean).map((l) => {
                try { return JSON.parse(l); } catch { return { raw: l }; }
              });
              return {
                content: [formatToolOutput({
                  tool: "trufflehog",
                  repoPath,
                  totalFindings: findings.length,
                  findings: findings.slice(0, 50),
                })],
              };
            }

            const glWhich = await executeCommand({ toolName: "secrets", command: "which", args: ["gitleaks"], timeout: 5000 });
            if (glWhich.exitCode === 0) {
              const result = await executeCommand({
                toolName: "secrets",
                command: "gitleaks",
                args: ["detect", "--source", repoPath, "--report-format", "json", "--report-path", "/dev/stdout"],
                timeout: 300000,
              });
              const findings = result.stdout.trim() ? JSON.parse(result.stdout) : [];
              return {
                content: [formatToolOutput({
                  tool: "gitleaks",
                  repoPath,
                  totalFindings: Array.isArray(findings) ? findings.length : 0,
                  findings: Array.isArray(findings) ? findings.slice(0, 50) : findings,
                })],
              };
            }

            return { content: [createErrorContent("Neither truffleHog nor gitleaks found. Install one for git history scanning.")], isError: true };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`Git history scan failed: ${sanitizeErrorMessage(msg)}`)], isError: true };
          }
        }

        default:
          return { content: [createErrorContent(`Unknown action: ${action}`)], isError: true };
      }
    }
  );
}
