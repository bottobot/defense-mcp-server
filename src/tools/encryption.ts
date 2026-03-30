/**
 * Encryption and cryptography tools for Defense MCP Server.
 *
 * Registers 1 tool: crypto (actions: tls_remote_audit, tls_cert_expiry, tls_config_audit,
 * gpg_list, gpg_generate, gpg_export, gpg_import, gpg_verify,
 * luks_status, luks_dump, luks_open, luks_close, luks_list,
 * file_hash, cert_inventory, cert_auto_renew_check, cert_ca_audit,
 * cert_ocsp_check, cert_ct_log_monitor)
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeCommand } from "../core/executor.js";
import { getConfig, getToolTimeout } from "../core/config.js";
import {
  createTextContent,
  createErrorContent,
  formatToolOutput,
} from "../core/parsers.js";
import { logChange, createChangeEntry } from "../core/changelog.js";
import {
  validateTarget,
  sanitizeArgs,
  validateCertPath,
} from "../core/sanitizer.js";

import { validateToolPath } from "../core/sanitizer.js";
import { spawnSafe } from "../core/spawn-safe.js";
import type { ChildProcess } from "node:child_process";

// ── Helpers ────────────────────────────────────────────────────────────────

/** Reject paths containing `..` directory-traversal sequences. */
const PATH_TRAVERSAL_RE = /(^|[\/\\])\.\.([\/\\]|$)/;
function assertNoTraversal(p: string): void {
  if (PATH_TRAVERSAL_RE.test(p)) {
    throw new Error("Path contains forbidden directory traversal (..)");
  }
}

// ── TOOL-023 remediation: encryption parameter validation ──────────────────

/** Allowed directories for key file paths */
const ALLOWED_KEY_DIRS = ["/etc/ssl", "/etc/pki", "/home", "/root", "/tmp", "/var/lib", "/opt"];

/**
 * Validate a key file path for traversal and containment within allowed directories.
 */
function validateKeyPath(keyPath: string): string {
  return validateToolPath(keyPath, ALLOWED_KEY_DIRS, "Key file path");
}

const WEAK_CIPHERS = [
  "RC4",
  "DES",
  "NULL",
  "EXPORT",
  "anon",
  "MD5",
  "RC2",
  "SEED",
  "IDEA",
];

const WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1 "];

function checkWeakCiphers(output: string): string[] {
  const found: string[] = [];
  for (const cipher of WEAK_CIPHERS) {
    if (output.toUpperCase().includes(cipher.toUpperCase())) {
      found.push(cipher);
    }
  }
  return found;
}

function checkWeakProtocols(output: string): string[] {
  const found: string[] = [];
  for (const proto of WEAK_PROTOCOLS) {
    if (output.includes(proto)) {
      found.push(proto.trim());
    }
  }
  return found;
}

// ── Certificate lifecycle command runner ────────────────────────────────────

interface CertCommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

/**
 * Run a command via spawnSafe and collect output as a promise.
 * Handles errors gracefully — returns error info instead of throwing.
 */
async function runCertCommand(
  command: string,
  args: string[],
  timeoutMs = 30_000,
  stdinData?: string,
): Promise<CertCommandResult> {
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

    // Write stdin data if provided, then close
    if (stdinData !== undefined && child.stdin) {
      child.stdin.write(stdinData);
      child.stdin.end();
    }
  });
}

// ── Registration entry point ───────────────────────────────────────────────

export function registerEncryptionTools(server: McpServer): void {
  server.tool(
    "crypto",
    "Crypto: TLS/SSL audit, GPG, LUKS, file hashing, certificate lifecycle",
    {
      action: z.enum([
        "tls_remote_audit",
        "tls_cert_expiry",
        "tls_config_audit",
        "gpg_list",
        "gpg_generate",
        "gpg_export",
        "gpg_import",
        "gpg_verify",
        "luks_status",
        "luks_dump",
        "luks_open",
        "luks_close",
        "luks_list",
        "file_hash",
        "cert_inventory",
        "cert_auto_renew_check",
        "cert_ca_audit",
        "cert_ocsp_check",
        "cert_ct_log_monitor",
      ]).describe("Action to perform"),
      // tls params
      host: z.string().optional().describe("Target hostname or IP"),
      port: z.number().optional().default(443).describe("Target port"),
      check_ciphers: z.boolean().optional().default(true).describe("Check for weak ciphers"),
      check_protocols: z.boolean().optional().default(true).describe("Check for weak protocols"),
      check_certificate: z.boolean().optional().default(true).describe("Check certificate details"),
      cert_path: z.string().optional().describe("Local certificate file path"),
      warn_days: z.number().optional().default(30).describe("Days before expiry to warn"),
      service: z.enum(["apache", "nginx", "system", "all"]).optional().default("all").describe("Service to audit TLS config for"),
      // gpg params
      key_id: z.string().optional().describe("GPG key ID"),
      file_path: z.string().optional().describe("File path for GPG import/verify"),
      dry_run: z.boolean().optional().describe("Preview without executing"),
      // luks params
      device: z.string().optional().describe("Block device path, e.g. /dev/sda2"),
      name: z.string().optional().describe("LUKS mapper name"),
      // file_hash params
      path: z.string().optional().describe("File or directory path to hash"),
      algorithm: z.enum(["sha256", "sha512", "sha1", "md5"]).optional().default("sha256").describe("Hash algorithm"),
      recursive: z.boolean().optional().default(false).describe("Hash files recursively"),
      // certificate_lifecycle params
      domain: z.string().optional().describe("Domain name for certificate checks"),
      search_paths: z.array(z.string()).optional().describe("Additional certificate search paths"),
      output_format: z.enum(["text", "json"]).optional().default("text").describe("Output format"),
    },
    async (params) => {
      const { action } = params;

      switch (action) {
        // ── tls_remote_audit ─────────────────────────────────────────
        case "tls_remote_audit": {
          const { host, port, check_ciphers, check_protocols, check_certificate } = params;
          if (!host) {
            return { content: [createErrorContent("host is required for remote_audit action")], isError: true };
          }
          try {
            const validHost = validateTarget(host);
            const sections: string[] = [];
            sections.push(`🔐 TLS/SSL Audit: ${validHost}:${port}`);
            sections.push("=".repeat(50));

            // Basic connection test
            const connResult = await executeCommand({
              command: "openssl",
              args: [
                "s_client",
                "-connect",
                `${validHost}:${port}`,
                "-servername",
                validHost,
                "-brief",
              ],
              stdin: "",
              toolName: "crypto_tls_audit",
              timeout: getToolTimeout("crypto_tls_audit"),
            });

            const fullOutput = connResult.stdout + "\n" + connResult.stderr;

            if (connResult.exitCode !== 0 && !fullOutput.includes("Protocol")) {
              return {
                content: [
                  createErrorContent(
                    `Failed to connect to ${validHost}:${port}: ${connResult.stderr}`
                  ),
                ],
                isError: true,
              };
            }

            sections.push("\n📡 Connection Info:");
            const protocolMatch = fullOutput.match(/Protocol\s*:\s*(\S+)/);
            const cipherMatch = fullOutput.match(/Cipher\s*:\s*(\S+)/);

            if (protocolMatch) sections.push(`  Protocol: ${protocolMatch[1]}`);
            if (cipherMatch) sections.push(`  Cipher: ${cipherMatch[1]}`);

            const detailResult = await executeCommand({
              command: "openssl",
              args: [
                "s_client",
                "-connect",
                `${validHost}:${port}`,
                "-servername",
                validHost,
              ],
              stdin: "",
              toolName: "crypto_tls_audit",
              timeout: getToolTimeout("crypto_tls_audit"),
            });

            const detailOutput = detailResult.stdout + "\n" + detailResult.stderr;

            if (check_certificate) {
              sections.push("\n📜 Certificate Details:");

              const subjectMatch = detailOutput.match(/subject=([^\n]+)/);
              const issuerMatch = detailOutput.match(/issuer=([^\n]+)/);
              const datesMatch = detailOutput.match(
                /Not Before:\s*([^\n]+)[\s\S]*?Not After\s*:\s*([^\n]+)/
              );
              const verifyMatch = detailOutput.match(
                /Verify return code:\s*(\d+)\s*\(([^)]+)\)/
              );

              if (subjectMatch) sections.push(`  Subject: ${subjectMatch[1].trim()}`);
              if (issuerMatch) sections.push(`  Issuer: ${issuerMatch[1].trim()}`);
              if (datesMatch) {
                sections.push(`  Not Before: ${datesMatch[1].trim()}`);
                sections.push(`  Not After: ${datesMatch[2].trim()}`);

                const expiryDate = new Date(datesMatch[2].trim());
                const now = new Date();
                const daysLeft = Math.floor(
                  (expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
                );
                if (daysLeft < 0) {
                  sections.push(`  ⛔ EXPIRED ${Math.abs(daysLeft)} days ago`);
                } else if (daysLeft < 30) {
                  sections.push(`  ⚠️ WARNING: Expires in ${daysLeft} days`);
                } else {
                  sections.push(`  ✅ Valid for ${daysLeft} more days`);
                }
              }
              if (verifyMatch) {
                const code = parseInt(verifyMatch[1], 10);
                const reason = verifyMatch[2];
                if (code === 0) {
                  sections.push(`  ✅ Verification: OK`);
                } else {
                  sections.push(`  ⛔ Verification FAILED: ${reason} (code ${code})`);
                }
              }

              if (detailOutput.includes("self signed certificate") ||
                  detailOutput.includes("self-signed")) {
                sections.push(`  ⚠️ Self-signed certificate detected`);
              }
            }

            if (check_ciphers) {
              sections.push("\n🔑 Cipher Analysis:");
              const weakFound = checkWeakCiphers(detailOutput);
              if (weakFound.length > 0) {
                sections.push(`  ⛔ Weak ciphers detected: ${weakFound.join(", ")}`);
              } else {
                sections.push(`  ✅ No known weak ciphers detected in connection`);
              }
            }

            if (check_protocols) {
              sections.push("\n🔒 Protocol Analysis:");
              const weakProtos = checkWeakProtocols(detailOutput);
              if (weakProtos.length > 0) {
                sections.push(`  ⛔ Weak protocols detected: ${weakProtos.join(", ")}`);
              } else {
                sections.push(`  ✅ No weak protocols detected in connection`);
              }

              const testProtocols = [
                { name: "TLSv1", arg: "-tls1" },
                { name: "TLSv1.1", arg: "-tls1_1" },
                { name: "TLSv1.2", arg: "-tls1_2" },
              ];

              for (const proto of testProtocols) {
                const protoResult = await executeCommand({
                  command: "openssl",
                  args: [
                    "s_client",
                    "-connect",
                    `${validHost}:${port}`,
                    "-servername",
                    validHost,
                    proto.arg,
                  ],
                  stdin: "",
                  toolName: "crypto_tls_audit",
                  timeout: 10000,
                });

                const protoOutput = protoResult.stdout + protoResult.stderr;
                const connected =
                  protoOutput.includes("Protocol  :") ||
                  protoOutput.includes("Cipher    :") ||
                  (protoResult.exitCode === 0 &&
                    !protoOutput.includes("no protocols available"));

                if (proto.name === "TLSv1" || proto.name === "TLSv1.1") {
                  if (connected) {
                    sections.push(`  ⚠️ ${proto.name}: Supported (deprecated, should be disabled)`);
                  } else {
                    sections.push(`  ✅ ${proto.name}: Not supported (good)`);
                  }
                } else {
                  if (connected) {
                    sections.push(`  ✅ ${proto.name}: Supported`);
                  } else {
                    sections.push(`  ℹ️ ${proto.name}: Not supported`);
                  }
                }
              }
            }

            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── tls_cert_expiry ──────────────────────────────────────────
        case "tls_cert_expiry": {
          const { cert_path, host, port, warn_days } = params;
          try {
            if (!cert_path && !host) {
              return {
                content: [
                  createErrorContent(
                    "Must specify either cert_path (local file) or host (remote check)"
                  ),
                ],
                isError: true,
              };
            }

            const sections: string[] = [];
            sections.push("📅 Certificate Expiry Check");
            sections.push("=".repeat(40));

            let endDate = "";
            let subject = "";
            let issuer = "";

            if (cert_path) {
              const validPath = validateCertPath(cert_path);
              sections.push(`\nLocal certificate: ${validPath}`);

              const result = await executeCommand({
                command: "openssl",
                args: ["x509", "-in", validPath, "-noout", "-enddate", "-subject", "-issuer"],
                toolName: "crypto_cert_expiry",
                timeout: getToolTimeout("crypto_cert_expiry"),
              });

              if (result.exitCode !== 0) {
                return {
                  content: [createErrorContent(`Failed to read certificate: ${result.stderr}`)],
                  isError: true,
                };
              }

              const endMatch = result.stdout.match(/notAfter=(.+)/);
              const subjectMatch = result.stdout.match(/subject=(.+)/);
              const issuerMatch = result.stdout.match(/issuer=(.+)/);

              if (endMatch) endDate = endMatch[1].trim();
              if (subjectMatch) subject = subjectMatch[1].trim();
              if (issuerMatch) issuer = issuerMatch[1].trim();
            } else if (host) {
              const validHost = validateTarget(host);
              sections.push(`\nRemote host: ${validHost}:${port}`);

              const result = await executeCommand({
                command: "openssl",
                args: ["s_client", "-connect", `${validHost}:${port}`, "-servername", validHost],
                stdin: "",
                toolName: "crypto_cert_expiry",
                timeout: getToolTimeout("crypto_cert_expiry"),
              });

              const fullOutput = result.stdout + "\n" + result.stderr;

              const notAfterMatch = fullOutput.match(/Not After\s*:\s*([^\n]+)/);
              const subjectMatch = fullOutput.match(/subject=([^\n]+)/);
              const issuerMatch = fullOutput.match(/issuer=([^\n]+)/);

              if (notAfterMatch) endDate = notAfterMatch[1].trim();
              if (subjectMatch) subject = subjectMatch[1].trim();
              if (issuerMatch) issuer = issuerMatch[1].trim();

              if (!endDate) {
                const certMatch = fullOutput.match(
                  /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/
                );
                if (certMatch) {
                  const dateResult = await executeCommand({
                    command: "openssl",
                    args: ["x509", "-noout", "-enddate", "-subject", "-issuer"],
                    stdin: certMatch[0],
                    toolName: "crypto_cert_expiry",
                    timeout: 10000,
                  });
                  const endM = dateResult.stdout.match(/notAfter=(.+)/);
                  const subM = dateResult.stdout.match(/subject=(.+)/);
                  const issM = dateResult.stdout.match(/issuer=(.+)/);
                  if (endM) endDate = endM[1].trim();
                  if (subM) subject = subM[1].trim();
                  if (issM) issuer = issM[1].trim();
                }
              }
            }

            if (!endDate) {
              return {
                content: [createErrorContent("Could not determine certificate expiry date")],
                isError: true,
              };
            }

            if (subject) sections.push(`  Subject: ${subject}`);
            if (issuer) sections.push(`  Issuer: ${issuer}`);
            sections.push(`  Expiry: ${endDate}`);

            const expiryDate = new Date(endDate);
            const now = new Date();
            const daysLeft = Math.floor(
              (expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
            );

            let status: string;
            if (daysLeft < 0) {
              status = "CRITICAL";
              sections.push(`\n⛔ Status: ${status} - Certificate EXPIRED ${Math.abs(daysLeft)} days ago`);
            } else if (daysLeft <= warn_days) {
              status = "WARNING";
              sections.push(`\n⚠️ Status: ${status} - Certificate expires in ${daysLeft} days (threshold: ${warn_days})`);
            } else {
              status = "OK";
              sections.push(`\n✅ Status: ${status} - Certificate valid for ${daysLeft} more days`);
            }

            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── tls_config_audit ─────────────────────────────────────────
        case "tls_config_audit": {
          const { service } = params;
          try {
            const sections: string[] = [];
            sections.push("🔍 TLS Configuration Audit");
            sections.push("=".repeat(40));

            const findings: Array<{ level: string; msg: string }> = [];

            if (service === "apache" || service === "all") {
              sections.push("\n── Apache TLS Configuration ──");

              const apacheResult = await executeCommand({
                command: "find",
                args: ["/etc/apache2/sites-enabled/", "-type", "f", "-name", "*.conf"],
                toolName: "crypto_tls",
                timeout: 10000,
              });

              if (apacheResult.exitCode === 0 && apacheResult.stdout.trim()) {
                const confFiles = apacheResult.stdout.trim().split("\n").filter((f) => f.trim());

                for (const confFile of confFiles) {
                  const catResult = await executeCommand({
                    command: "cat",
                    args: [confFile.trim()],
                    toolName: "crypto_tls",
                    timeout: 5000,
                  });

                  if (catResult.exitCode === 0) {
                    const content = catResult.stdout;
                    sections.push(`\n  File: ${confFile.trim()}`);

                    const protoMatch = content.match(/SSLProtocol\s+(.+)/);
                    if (protoMatch) {
                      sections.push(`  SSLProtocol: ${protoMatch[1].trim()}`);
                      const proto = protoMatch[1];
                      if (proto.includes("SSLv3") || proto.includes("TLSv1 ") || proto.includes("TLSv1.0") || proto.includes("TLSv1.1")) {
                        findings.push({ level: "CRITICAL", msg: `${confFile}: Weak protocol in SSLProtocol: ${protoMatch[1].trim()}` });
                      }
                    }

                    const cipherMatch = content.match(/SSLCipherSuite\s+(.+)/);
                    if (cipherMatch) {
                      sections.push(`  SSLCipherSuite: ${cipherMatch[1].trim().substring(0, 80)}...`);
                      const weakCiphers = checkWeakCiphers(cipherMatch[1]);
                      if (weakCiphers.length > 0) {
                        findings.push({ level: "WARNING", msg: `${confFile}: Weak ciphers found: ${weakCiphers.join(", ")}` });
                      }
                    }
                  }
                }
              } else {
                sections.push("  Apache not installed or no sites-enabled configuration found.");
              }
            }

            if (service === "nginx" || service === "all") {
              sections.push("\n── Nginx TLS Configuration ──");

              const nginxResult = await executeCommand({
                command: "find",
                args: ["/etc/nginx/", "-type", "f", "-name", "*.conf"],
                toolName: "crypto_tls",
                timeout: 10000,
              });

              if (nginxResult.exitCode === 0 && nginxResult.stdout.trim()) {
                const confFiles = nginxResult.stdout.trim().split("\n").filter((f) => f.trim());

                for (const confFile of confFiles) {
                  const catResult = await executeCommand({
                    command: "cat",
                    args: [confFile.trim()],
                    toolName: "crypto_tls",
                    timeout: 5000,
                  });

                  if (catResult.exitCode === 0) {
                    const content = catResult.stdout;

                    if (content.includes("ssl_protocols") || content.includes("ssl_ciphers")) {
                      sections.push(`\n  File: ${confFile.trim()}`);

                      const protoMatch = content.match(/ssl_protocols\s+([^;]+)/);
                      if (protoMatch) {
                        sections.push(`  ssl_protocols: ${protoMatch[1].trim()}`);
                        const proto = protoMatch[1];
                        if (proto.includes("SSLv3") || proto.includes("TLSv1 ") || proto.includes("TLSv1.0") || proto.includes("TLSv1.1")) {
                          findings.push({ level: "CRITICAL", msg: `${confFile}: Weak protocol in ssl_protocols: ${protoMatch[1].trim()}` });
                        }
                      }

                      const cipherMatch = content.match(/ssl_ciphers\s+['"]?([^;'"]+)/);
                      if (cipherMatch) {
                        sections.push(`  ssl_ciphers: ${cipherMatch[1].trim().substring(0, 80)}...`);
                        const weakCiphers = checkWeakCiphers(cipherMatch[1]);
                        if (weakCiphers.length > 0) {
                          findings.push({ level: "WARNING", msg: `${confFile}: Weak ciphers: ${weakCiphers.join(", ")}` });
                        }
                      }
                    }
                  }
                }
              } else {
                sections.push("  Nginx not installed or no configuration found.");
              }
            }

            if (service === "system" || service === "all") {
              sections.push("\n── System-Wide Crypto Configuration ──");

              const opensslResult = await executeCommand({
                command: "cat",
                args: ["/etc/ssl/openssl.cnf"],
                toolName: "crypto_tls",
                timeout: 5000,
              });

              if (opensslResult.exitCode === 0) {
                sections.push("\n  OpenSSL config (/etc/ssl/openssl.cnf): Found");

                const minProtoMatch = opensslResult.stdout.match(/MinProtocol\s*=\s*(\S+)/);
                if (minProtoMatch) sections.push(`  MinProtocol: ${minProtoMatch[1]}`);

                const cipherStringMatch = opensslResult.stdout.match(/CipherString\s*=\s*(\S+)/);
                if (cipherStringMatch) sections.push(`  CipherString: ${cipherStringMatch[1]}`);
              } else {
                sections.push("  OpenSSL config: Not found at /etc/ssl/openssl.cnf");
              }

              const policyResult = await executeCommand({
                command: "cat",
                args: ["/etc/crypto-policies/config"],
                toolName: "crypto_tls",
                timeout: 5000,
              });

              if (policyResult.exitCode === 0 && policyResult.stdout.trim()) {
                sections.push(`\n  System crypto policy: ${policyResult.stdout.trim()}`);
                const policy = policyResult.stdout.trim().toUpperCase();
                if (policy === "LEGACY" || policy === "DEFAULT") {
                  findings.push({ level: "WARNING", msg: `System crypto policy is '${policyResult.stdout.trim()}' - consider using FUTURE or FIPS` });
                }
              }

              const versionResult = await executeCommand({
                command: "openssl",
                args: ["version"],
                toolName: "crypto_tls",
                timeout: 5000,
              });

              if (versionResult.exitCode === 0) {
                sections.push(`\n  OpenSSL version: ${versionResult.stdout.trim()}`);
              }
            }

            sections.push("\n── Findings Summary ──");
            if (findings.length === 0) {
              sections.push("  ✅ No critical TLS configuration issues found.");
            } else {
              const criticals = findings.filter((f) => f.level === "CRITICAL");
              const warnings = findings.filter((f) => f.level === "WARNING");

              if (criticals.length > 0) {
                sections.push(`\n  ⛔ Critical (${criticals.length}):`);
                for (const f of criticals) sections.push(`    - ${f.msg}`);
              }
              if (warnings.length > 0) {
                sections.push(`\n  ⚠️ Warnings (${warnings.length}):`);
                for (const f of warnings) sections.push(`    - ${f.msg}`);
              }
            }

            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── gpg_list ─────────────────────────────────────────────────
        case "gpg_list": {
          try {
            const sections: string[] = [];
            sections.push(`🔑 GPG Key Management: list`);
            sections.push("=".repeat(40));

            const result = await executeCommand({
              command: "gpg",
              args: ["--list-keys", "--keyid-format", "long"],
              toolName: "crypto_gpg_keys",
              timeout: getToolTimeout("crypto_gpg_keys"),
            });

            if (result.exitCode !== 0 && !result.stdout) {
              sections.push("\nNo GPG keys found or GPG not configured.");
              sections.push(`stderr: ${result.stderr}`);
            } else {
              sections.push("\nPublic Keys:");
              sections.push(result.stdout || "No keys found");
            }

            const secretResult = await executeCommand({
              command: "gpg",
              args: ["--list-secret-keys", "--keyid-format", "long"],
              toolName: "crypto_gpg_keys",
              timeout: getToolTimeout("crypto_gpg_keys"),
            });

            if (secretResult.stdout.trim()) {
              sections.push("\nSecret Keys:");
              sections.push(secretResult.stdout);
            }

            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── gpg_generate ─────────────────────────────────────────────
        case "gpg_generate": {
          const { dry_run } = params;
          try {
            const sections: string[] = [];
            sections.push(`🔑 GPG Key Management: generate`);
            sections.push("=".repeat(40));

            if (dry_run ?? getConfig().dryRun) {
              sections.push("\n[DRY RUN] Would generate a new GPG key pair.");
              sections.push("Command: gpg --full-generate-key");
              sections.push("\nNote: Key generation is interactive and requires user input.");
              sections.push("To generate non-interactively, create a batch file with parameters.");
              sections.push("\nExample batch file content:");
              sections.push("  %no-protection");
              sections.push("  Key-Type: RSA");
              sections.push("  Key-Length: 4096");
              sections.push("  Subkey-Type: RSA");
              sections.push("  Subkey-Length: 4096");
              sections.push("  Name-Real: Your Name");
              sections.push("  Name-Email: your@email.com");
              sections.push("  Expire-Date: 1y");
              sections.push("  %commit");
            } else {
              sections.push("⚠️ Interactive GPG key generation cannot be run in non-interactive mode.");
              sections.push("Use 'gpg --batch --gen-key <batch_file>' for non-interactive generation.");
            }

            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── gpg_export ───────────────────────────────────────────────
        case "gpg_export": {
          const { key_id } = params;
          try {
            if (!key_id) {
              return {
                content: [createErrorContent("key_id is required for GPG key export")],
                isError: true,
              };
            }

            sanitizeArgs([key_id]);

            const sections: string[] = [];
            sections.push(`🔑 GPG Key Management: export`);
            sections.push("=".repeat(40));

            const result = await executeCommand({
              command: "gpg",
              args: ["--export", "--armor", key_id],
              toolName: "crypto_gpg_keys",
              timeout: getToolTimeout("crypto_gpg_keys"),
            });

            if (result.exitCode !== 0 || !result.stdout.trim()) {
              return {
                content: [createErrorContent(`Failed to export key ${key_id}: ${result.stderr}`)],
                isError: true,
              };
            }

            sections.push(`\nExported public key for: ${key_id}`);
            sections.push(result.stdout);

            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── gpg_import ───────────────────────────────────────────────
        case "gpg_import": {
          const { file_path, dry_run } = params;
          try {
            if (!file_path) {
              return {
                content: [createErrorContent("file_path is required for GPG key import")],
                isError: true,
              };
            }

            sanitizeArgs([file_path]);
            // TOOL-023: Validate key file path with containment check
            validateKeyPath(file_path);

            const sections: string[] = [];
            sections.push(`🔑 GPG Key Management: import`);
            sections.push("=".repeat(40));

            if (dry_run ?? getConfig().dryRun) {
              sections.push(`\n[DRY RUN] Would import GPG key from: ${file_path}`);
              sections.push(`Command: gpg --import ${file_path}`);
            } else {
              const result = await executeCommand({
                command: "gpg",
                args: ["--import", file_path],
                toolName: "crypto_gpg_keys",
                timeout: getToolTimeout("crypto_gpg_keys"),
              });

              if (result.exitCode !== 0) {
                return {
                  content: [createErrorContent(`Failed to import key: ${result.stderr}`)],
                  isError: true,
                };
              }

              sections.push(`\n✅ Key imported from: ${file_path}`);
              sections.push(result.stderr || result.stdout);

              logChange(
                createChangeEntry({
                  tool: "crypto",
                  action: "import",
                  target: file_path,
                  after: result.stderr || result.stdout,
                  dryRun: false,
                  success: true,
                })
              );
            }

            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── gpg_verify ───────────────────────────────────────────────
        case "gpg_verify": {
          const { file_path } = params;
          try {
            if (!file_path) {
              return {
                content: [createErrorContent("file_path is required for GPG signature verification")],
                isError: true,
              };
            }

            sanitizeArgs([file_path]);
            // TOOL-023: Validate key file path with containment check
            validateKeyPath(file_path);

            const sections: string[] = [];
            sections.push(`🔑 GPG Key Management: verify`);
            sections.push("=".repeat(40));

            const result = await executeCommand({
              command: "gpg",
              args: ["--verify", file_path],
              toolName: "crypto_gpg_keys",
              timeout: getToolTimeout("crypto_gpg_keys"),
            });

            const output = result.stderr || result.stdout;
            if (result.exitCode !== 0) {
              sections.push(`\n⛔ Signature verification FAILED for: ${file_path}`);
            } else {
              sections.push(`\n✅ Signature verification PASSED for: ${file_path}`);
            }
            sections.push(output);

            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── luks_status ──────────────────────────────────────────────
        case "luks_status": {
          const { name } = params;
          try {
            if (!name) {
              return {
                content: [createErrorContent("name (mapper name) is required for status check")],
                isError: true,
              };
            }

            sanitizeArgs([name]);

            const sections: string[] = [];
            sections.push(`🔐 LUKS Volume Management: status`);
            sections.push("=".repeat(40));

            const result = await executeCommand({
              command: "sudo",
              args: ["cryptsetup", "status", name],
              toolName: "crypto_luks_manage",
              timeout: getToolTimeout("crypto_luks_manage"),
            });

            if (result.exitCode !== 0) {
              sections.push(`\n⚠️ Device mapper '${name}' not found or not active.`);
              sections.push(result.stderr || result.stdout);
            } else {
              sections.push(`\nStatus for /dev/mapper/${name}:`);
              sections.push(result.stdout);
            }

            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── luks_dump ────────────────────────────────────────────────
        case "luks_dump": {
          const { device } = params;
          try {
            if (!device) {
              return {
                content: [createErrorContent("device path is required for LUKS header dump")],
                isError: true,
              };
            }

            sanitizeArgs([device]);
            assertNoTraversal(device);

            const sections: string[] = [];
            sections.push(`🔐 LUKS Volume Management: dump`);
            sections.push("=".repeat(40));

            const result = await executeCommand({
              command: "sudo",
              args: ["cryptsetup", "luksDump", device],
              toolName: "crypto_luks_manage",
              timeout: getToolTimeout("crypto_luks_manage"),
            });

            if (result.exitCode !== 0) {
              return {
                content: [createErrorContent(`Failed to dump LUKS header for ${device}: ${result.stderr}`)],
                isError: true,
              };
            }

            sections.push(`\nLUKS Header Dump for ${device}:`);
            sections.push(result.stdout);

            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── luks_open ────────────────────────────────────────────────
        case "luks_open": {
          const { device, name, dry_run } = params;
          try {
            if (!device || !name) {
              return {
                content: [createErrorContent("Both device and name are required for LUKS open")],
                isError: true,
              };
            }

            sanitizeArgs([device, name]);
            assertNoTraversal(device);

            const sections: string[] = [];
            sections.push(`🔐 LUKS Volume Management: open`);
            sections.push("=".repeat(40));

            if (dry_run ?? getConfig().dryRun) {
              sections.push(`\n[DRY RUN] Would open LUKS volume:`);
              sections.push(`  Device: ${device}`);
              sections.push(`  Mapper name: ${name}`);
              sections.push(`  Command: sudo cryptsetup luksOpen ${device} ${name}`);
              sections.push("\nNote: This operation requires a passphrase and cannot be run non-interactively without a key file.");
            } else {
              sections.push("⚠️ Interactive LUKS open requires a passphrase.");
              sections.push("Use a key file with: sudo cryptsetup luksOpen --key-file <keyfile> <device> <name>");

              logChange(
                createChangeEntry({
                  tool: "crypto",
                  action: "open_attempted",
                  target: device,
                  dryRun: false,
                  success: false,
                  error: "Interactive passphrase required, cannot run non-interactively",
                })
              );
            }

            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── luks_close ───────────────────────────────────────────────
        case "luks_close": {
          const { name, dry_run } = params;
          try {
            if (!name) {
              return {
                content: [createErrorContent("name (mapper name) is required for LUKS close")],
                isError: true,
              };
            }

            sanitizeArgs([name]);

            const sections: string[] = [];
            sections.push(`🔐 LUKS Volume Management: close`);
            sections.push("=".repeat(40));

            if (dry_run ?? getConfig().dryRun) {
              sections.push(`\n[DRY RUN] Would close LUKS volume: /dev/mapper/${name}`);
              sections.push(`  Command: sudo cryptsetup luksClose ${name}`);
            } else {
              const result = await executeCommand({
                command: "sudo",
                args: ["cryptsetup", "luksClose", name],
                toolName: "crypto_luks_manage",
                timeout: getToolTimeout("crypto_luks_manage"),
              });

              if (result.exitCode !== 0) {
                return {
                  content: [createErrorContent(`Failed to close LUKS volume ${name}: ${result.stderr}`)],
                  isError: true,
                };
              }

              sections.push(`\n✅ LUKS volume '${name}' closed successfully.`);

              logChange(
                createChangeEntry({
                  tool: "crypto",
                  action: "close",
                  target: name,
                  dryRun: false,
                  success: true,
                  rollbackCommand: `sudo cryptsetup luksOpen <device> ${name}`,
                })
              );
            }

            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── luks_list ────────────────────────────────────────────────
        case "luks_list": {
          try {
            const sections: string[] = [];
            sections.push(`🔐 LUKS Volume Management: list`);
            sections.push("=".repeat(40));

            const mapperResult = await executeCommand({
              command: "ls",
              args: ["-la", "/dev/mapper/"],
              toolName: "crypto_luks_manage",
              timeout: getToolTimeout("crypto_luks_manage"),
            });

            sections.push("\n📁 Device Mapper Entries:");
            sections.push(mapperResult.stdout || "No entries found");

            const lsblkResult = await executeCommand({
              command: "lsblk",
              args: ["--fs", "-o", "NAME,FSTYPE,SIZE,MOUNTPOINT,UUID"],
              toolName: "crypto_luks_manage",
              timeout: getToolTimeout("crypto_luks_manage"),
            });

            sections.push("\n💾 Block Devices (with filesystem info):");
            sections.push(lsblkResult.stdout || "No block devices found");

            const cryptoLines = (lsblkResult.stdout || "")
              .split("\n")
              .filter((l) => l.includes("crypto_LUKS") || l.includes("crypt"));
            if (cryptoLines.length > 0) {
              sections.push("\n🔐 LUKS Encrypted Devices:");
              for (const line of cryptoLines) {
                sections.push(`  ${line.trim()}`);
              }
            } else {
              sections.push("\nNo LUKS encrypted devices detected.");
            }

            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── file_hash ────────────────────────────────────────────────
        case "file_hash": {
          const { path, algorithm, recursive } = params;
          try {
            if (!path) {
              return {
                content: [createErrorContent("path is required for file_hash action")],
                isError: true,
              };
            }

            sanitizeArgs([path]);
            assertNoTraversal(path);

            const sections: string[] = [];
            const hashCmd = `${algorithm}sum`;
            sections.push(`#️⃣ File Integrity Hash (${algorithm.toUpperCase()})`);
            sections.push("=".repeat(40));

            if (recursive) {
              const result = await executeCommand({
                command: "find",
                args: [path, "-type", "f", "-exec", hashCmd, "{}", "+"],
                toolName: "crypto_file_hash",
                timeout: getToolTimeout("crypto_file_hash"),
              });

              if (result.exitCode !== 0 && !result.stdout) {
                return {
                  content: [createErrorContent(`Failed to hash files in ${path}: ${result.stderr}`)],
                  isError: true,
                };
              }

              const lines = result.stdout.trim().split("\n").filter((l) => l.trim());
              sections.push(`\nDirectory: ${path}`);
              sections.push(`Files hashed: ${lines.length}`);
              sections.push(`\nResults:`);
              sections.push(result.stdout);
            } else {
              const result = await executeCommand({
                command: hashCmd,
                args: [path],
                toolName: "crypto_file_hash",
                timeout: getToolTimeout("crypto_file_hash"),
              });

              if (result.exitCode !== 0) {
                return {
                  content: [createErrorContent(`Failed to hash ${path}: ${result.stderr}`)],
                  isError: true,
                };
              }

              sections.push(`\nFile: ${path}`);
              sections.push(`Algorithm: ${algorithm.toUpperCase()}`);
              const hashValue = result.stdout.trim().split(/\s+/)[0];
              sections.push(`Hash: ${hashValue}`);
              sections.push(`\nFull output: ${result.stdout.trim()}`);
            }

            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        // ── cert_inventory ───────────────────────────────────────────
        case "cert_inventory": {
          try {
            const defaultPaths = [
              "/etc/ssl/certs/",
              "/etc/pki/tls/certs/",
              "/etc/letsencrypt/live/",
              "/usr/local/share/ca-certificates/",
            ];
            const searchPaths = [...defaultPaths, ...(params.search_paths ?? [])];

            for (const p of searchPaths) {
              assertNoTraversal(p);
            }

            const allCerts: string[] = [];

            for (const searchPath of searchPaths) {
              const findResult = await runCertCommand("find", [
                searchPath, "-name", "*.pem", "-o", "-name", "*.crt", "-o", "-name", "*.cer",
              ], 15_000);

              if (findResult.exitCode === 0 && findResult.stdout.trim()) {
                const certs = findResult.stdout.trim().split("\n").filter((c) => c.trim());
                allCerts.push(...certs);
              }
            }

            interface CertInfo {
              path: string;
              subject: string;
              issuer: string;
              notBefore: string;
              notAfter: string;
              serial: string;
              status: "valid" | "expiring_soon" | "expired";
              daysLeft: number;
            }

            const certDetails: CertInfo[] = [];
            let expiredCount = 0;
            let expiringSoonCount = 0;
            let validCount = 0;

            const certsToCheck = allCerts.slice(0, 100);
            for (const certFile of certsToCheck) {
              const certResult = await runCertCommand("openssl", [
                "x509", "-in", certFile.trim(), "-noout",
                "-subject", "-issuer", "-dates", "-serial",
              ], 5_000);

              if (certResult.exitCode === 0) {
                const out = certResult.stdout;
                const subjectMatch = out.match(/subject=(.+)/);
                const issuerMatch = out.match(/issuer=(.+)/);
                const notBeforeMatch = out.match(/notBefore=(.+)/);
                const notAfterMatch = out.match(/notAfter=(.+)/);
                const serialMatch = out.match(/serial=(.+)/);

                const notAfter = notAfterMatch ? notAfterMatch[1].trim() : "";
                let daysLeft = 0;
                let status: "valid" | "expiring_soon" | "expired" = "valid";

                if (notAfter) {
                  const expiryDate = new Date(notAfter);
                  const now = new Date();
                  daysLeft = Math.floor(
                    (expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24),
                  );

                  if (daysLeft < 0) {
                    status = "expired";
                    expiredCount++;
                  } else if (daysLeft < 30) {
                    status = "expiring_soon";
                    expiringSoonCount++;
                  } else {
                    validCount++;
                  }
                }

                certDetails.push({
                  path: certFile.trim(),
                  subject: subjectMatch ? subjectMatch[1].trim() : "unknown",
                  issuer: issuerMatch ? issuerMatch[1].trim() : "unknown",
                  notBefore: notBeforeMatch ? notBeforeMatch[1].trim() : "unknown",
                  notAfter: notAfter || "unknown",
                  serial: serialMatch ? serialMatch[1].trim() : "unknown",
                  status,
                  daysLeft,
                });
              }
            }

            const output = {
              action: "inventory",
              totalCerts: certDetails.length,
              expired: expiredCount,
              expiringSoon: expiringSoonCount,
              valid: validCount,
              certificates: certDetails,
              searchPaths,
            };

            if (params.output_format === "json") {
              return { content: [formatToolOutput(output)] };
            }

            const sections: string[] = [];
            sections.push("📜 Certificate Inventory");
            sections.push("=".repeat(50));
            sections.push(`\nTotal certificates found: ${certDetails.length}`);
            sections.push(`  ✅ Valid: ${validCount}`);
            sections.push(`  ⚠️ Expiring soon (< 30 days): ${expiringSoonCount}`);
            sections.push(`  ⛔ Expired: ${expiredCount}`);

            if (expiredCount > 0) {
              sections.push("\n── Expired Certificates ──");
              for (const cert of certDetails.filter((c) => c.status === "expired")) {
                sections.push(`  ${cert.path}`);
                sections.push(`    Subject: ${cert.subject}`);
                sections.push(`    Expired: ${Math.abs(cert.daysLeft)} days ago`);
              }
            }

            if (expiringSoonCount > 0) {
              sections.push("\n── Expiring Soon ──");
              for (const cert of certDetails.filter((c) => c.status === "expiring_soon")) {
                sections.push(`  ${cert.path}`);
                sections.push(`    Subject: ${cert.subject}`);
                sections.push(`    Expires in: ${cert.daysLeft} days`);
              }
            }

            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`inventory failed: ${msg}`)], isError: true };
          }
        }

        // ── cert_auto_renew_check ────────────────────────────────────
        case "cert_auto_renew_check": {
          try {
            const findings: Record<string, unknown> = { action: "auto_renew_check" };

            const certbotCheck = await runCertCommand("which", ["certbot"], 5_000);
            const certbotInstalled = certbotCheck.exitCode === 0;
            findings.certbotInstalled = certbotInstalled;

            if (!certbotInstalled) {
              findings.status = "certbot_not_found";
              findings.recommendations = ["Certbot is not installed. Install with: apt install certbot"];

              if (params.output_format === "json") {
                return { content: [formatToolOutput(findings)] };
              }

              const sections: string[] = [];
              sections.push("🔄 Auto-Renewal Check");
              sections.push("=".repeat(50));
              sections.push("\n⚠️ Certbot is not installed.");
              sections.push("  Install with: apt install certbot");
              return { content: [createTextContent(sections.join("\n"))] };
            }

            const timerResult = await runCertCommand("systemctl", ["status", "certbot.timer"], 10_000);
            const timerActive = timerResult.exitCode === 0 && timerResult.stdout.includes("active");
            findings.timerActive = timerActive;
            findings.timerOutput = timerResult.stdout.trim();

            const certsResult = await runCertCommand("certbot", ["certificates"], 15_000);
            findings.certificates = certsResult.stdout.trim();
            findings.certbotExitCode = certsResult.exitCode;

            const renewalResult = await runCertCommand("find", [
              "/etc/letsencrypt/renewal/", "-name", "*.conf",
            ], 5_000);
            const renewalConfigs =
              renewalResult.exitCode === 0 && renewalResult.stdout.trim()
                ? renewalResult.stdout.trim().split("\n").filter((l) => l.trim())
                : [];
            findings.renewalConfigs = renewalConfigs;

            const cronResult = await runCertCommand("grep", [
              "-r", "certbot", "/etc/cron.d/", "/etc/cron.daily/", "/etc/crontab",
            ], 5_000);
            const cronJobs =
              cronResult.exitCode === 0 && cronResult.stdout.trim()
                ? cronResult.stdout.trim().split("\n").filter((l) => l.trim())
                : [];
            findings.cronJobs = cronJobs;
            findings.status = "checked";

            if (params.output_format === "json") {
              return { content: [formatToolOutput(findings)] };
            }

            const sections: string[] = [];
            sections.push("🔄 Auto-Renewal Check");
            sections.push("=".repeat(50));
            sections.push(`\nCertbot: installed at ${certbotCheck.stdout.trim()}`);
            sections.push(`Timer: ${timerActive ? "✅ Active" : "⚠️ Not active"}`);
            sections.push("\nManaged Certificates:");
            sections.push(certsResult.stdout.trim() || "  No certificates found");
            sections.push(`\nRenewal Configs (${renewalConfigs.length}):`);
            for (const conf of renewalConfigs) {
              sections.push(`  ${conf}`);
            }
            if (cronJobs.length > 0) {
              sections.push("\nCron Jobs:");
              for (const job of cronJobs) {
                sections.push(`  ${job}`);
              }
            }

            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`auto_renew_check failed: ${msg}`)], isError: true };
          }
        }

        // ── cert_ca_audit ────────────────────────────────────────────
        case "cert_ca_audit": {
          try {
            const findings: Record<string, unknown> = { action: "ca_audit" };

            let trustStorePath = "/etc/ssl/certs/";
            const sslCheck = await runCertCommand("ls", ["/etc/ssl/certs/"], 5_000);
            if (sslCheck.exitCode !== 0) {
              const pkiCheck = await runCertCommand("ls", ["/etc/pki/tls/certs/"], 5_000);
              if (pkiCheck.exitCode === 0) {
                trustStorePath = "/etc/pki/tls/certs/";
              }
            }
            findings.trustStorePath = trustStorePath;

            const caListResult = await runCertCommand("find", [
              trustStorePath, "-name", "*.pem", "-o", "-name", "*.crt",
            ], 10_000);
            const caFiles =
              caListResult.exitCode === 0 && caListResult.stdout.trim()
                ? caListResult.stdout.trim().split("\n").filter((l) => l.trim())
                : [];
            findings.totalCAs = caFiles.length;

            const recentResult = await runCertCommand("find", [
              trustStorePath, "-mtime", "-30", "-name", "*.pem",
              "-o", "-mtime", "-30", "-name", "*.crt",
            ], 10_000);
            const recentlyAdded =
              recentResult.exitCode === 0 && recentResult.stdout.trim()
                ? recentResult.stdout.trim().split("\n").filter((l) => l.trim())
                : [];
            findings.recentlyAdded = recentlyAdded;
            findings.recentlyAddedCount = recentlyAdded.length;

            const suspiciousPatterns = ["test", "debug", "fake", "temporary", "tmp", "self-signed", "localhost", "example"];
            const suspiciousFindings: string[] = [];

            for (const caFile of caFiles.slice(0, 200)) {
              const lower = caFile.toLowerCase();
              for (const pattern of suspiciousPatterns) {
                if (lower.includes(pattern)) {
                  suspiciousFindings.push(caFile);
                  break;
                }
              }
            }
            findings.suspiciousFindings = suspiciousFindings;
            findings.suspiciousCount = suspiciousFindings.length;

            const updateCheck = await runCertCommand("which", ["update-ca-certificates"], 5_000);
            findings.updateCaCertificatesAvailable = updateCheck.exitCode === 0;

            if (params.output_format === "json") {
              return { content: [formatToolOutput(findings)] };
            }

            const sections: string[] = [];
            sections.push("🏛️ CA Trust Store Audit");
            sections.push("=".repeat(50));
            sections.push(`\nTrust store path: ${trustStorePath}`);
            sections.push(`Total trusted CAs: ${caFiles.length}`);
            sections.push(`Recently added (last 30 days): ${recentlyAdded.length}`);

            if (recentlyAdded.length > 0) {
              sections.push("\n── Recently Added CAs ──");
              for (const ca of recentlyAdded.slice(0, 20)) {
                sections.push(`  ${ca}`);
              }
            }

            if (suspiciousFindings.length > 0) {
              sections.push(`\n⚠️ Suspicious CAs Found (${suspiciousFindings.length}):`);
              for (const ca of suspiciousFindings.slice(0, 20)) {
                sections.push(`  ${ca}`);
              }
            } else {
              sections.push("\n✅ No suspicious CA names detected.");
            }

            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`ca_audit failed: ${msg}`)], isError: true };
          }
        }

        // ── cert_ocsp_check ──────────────────────────────────────────
        case "cert_ocsp_check": {
          try {
            if (!params.domain && !params.cert_path) {
              return {
                content: [createErrorContent("domain or cert_path is required for ocsp_check")],
                isError: true,
              };
            }

            const findings: Record<string, unknown> = { action: "ocsp_check" };
            let certPem = "";

            if (params.domain) {
              const validDomain = validateTarget(params.domain);
              findings.domain = validDomain;

              const sClientResult = await runCertCommand("openssl", [
                "s_client", "-connect", `${validDomain}:443`,
                "-servername", validDomain, "-showcerts",
              ], 10_000, "");

              const fullOutput = sClientResult.stdout + "\n" + sClientResult.stderr;
              const certMatches = fullOutput.match(
                /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g,
              );

              if (!certMatches || certMatches.length === 0) {
                findings.error = "Could not retrieve certificate from domain";
                if (params.output_format === "json") {
                  return { content: [formatToolOutput(findings)] };
                }
                return {
                  content: [createErrorContent(`Could not retrieve certificate from ${validDomain}`)],
                  isError: true,
                };
              }

              certPem = certMatches[0];
            } else if (params.cert_path) {
              assertNoTraversal(params.cert_path);
              const validPath = validateCertPath(params.cert_path);
              findings.certPath = validPath;

              const readResult = await runCertCommand("openssl", ["x509", "-in", validPath], 5_000);
              if (readResult.exitCode !== 0) {
                return {
                  content: [createErrorContent(`Failed to read certificate: ${readResult.stderr}`)],
                  isError: true,
                };
              }
              certPem = readResult.stdout;
            }

            const ocspUriResult = await runCertCommand("openssl", ["x509", "-noout", "-ocsp_uri"], 5_000, certPem);
            const ocspUri = ocspUriResult.stdout.trim();
            findings.ocspUri = ocspUri || "not found";

            if (!ocspUri) {
              findings.status = "no_ocsp_uri";
              findings.message = "Certificate does not contain an OCSP responder URI";

              if (params.output_format === "json") {
                return { content: [formatToolOutput(findings)] };
              }

              return {
                content: [
                  createTextContent(
                    "🔍 OCSP Check\n" + "=".repeat(50) +
                    "\n\n⚠️ Certificate does not contain an OCSP responder URI.",
                  ),
                ],
              };
            }

            if (params.domain) {
              const validDomain = validateTarget(params.domain);
              const staplingResult = await runCertCommand("openssl", [
                "s_client", "-connect", `${validDomain}:443`,
                "-servername", validDomain, "-status",
              ], 10_000, "");

              const staplingOutput = staplingResult.stdout + staplingResult.stderr;
              const hasStapling = staplingOutput.includes("OCSP Response Status: successful");
              findings.ocspStapling = hasStapling;

              if (hasStapling) {
                if (staplingOutput.includes("Cert Status: good")) {
                  findings.revocationStatus = "good";
                } else if (staplingOutput.includes("Cert Status: revoked")) {
                  findings.revocationStatus = "revoked";
                } else {
                  findings.revocationStatus = "unknown";
                }
              } else {
                findings.revocationStatus = "unknown";
                findings.message = "OCSP stapling not available; direct OCSP query may be needed";
              }
            } else {
              findings.revocationStatus = "unknown";
              findings.message = "Direct OCSP query requires domain; use domain parameter for full check";
            }

            if (params.output_format === "json") {
              return { content: [formatToolOutput(findings)] };
            }

            const sections: string[] = [];
            sections.push("🔍 OCSP Check");
            sections.push("=".repeat(50));
            sections.push(`\nOCSP Responder: ${ocspUri}`);
            sections.push(`Revocation Status: ${String(findings.revocationStatus)}`);
            if (findings.ocspStapling !== undefined) {
              sections.push(`OCSP Stapling: ${findings.ocspStapling ? "✅ Supported" : "⚠️ Not supported"}`);
            }
            if (findings.message) {
              sections.push(`\nNote: ${String(findings.message)}`);
            }

            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`ocsp_check failed: ${msg}`)], isError: true };
          }
        }

        // ── cert_ct_log_monitor ──────────────────────────────────────
        case "cert_ct_log_monitor": {
          try {
            if (!params.domain) {
              return {
                content: [createErrorContent("domain is required for ct_log_monitor")],
                isError: true,
              };
            }

            const validDomain = validateTarget(params.domain);
            const findings: Record<string, unknown> = {
              action: "ct_log_monitor",
              domain: validDomain,
            };

            const crtshResult = await runCertCommand("curl", [
              "-s", "-m", "15",
              `https://crt.sh/?q=${encodeURIComponent(validDomain)}&output=json`,
            ], 20_000);

            if (crtshResult.exitCode !== 0 || !crtshResult.stdout.trim()) {
              findings.error = "Failed to query crt.sh";
              findings.stderr = crtshResult.stderr;

              if (params.output_format === "json") {
                return { content: [formatToolOutput(findings)] };
              }

              return {
                content: [
                  createTextContent(
                    "🔍 CT Log Monitor\n" + "=".repeat(50) +
                    `\n\n⚠️ Failed to query crt.sh for ${validDomain}.\n` +
                    `Error: ${crtshResult.stderr}`,
                  ),
                ],
              };
            }

            let ctEntries: Array<Record<string, unknown>> = [];
            try {
              ctEntries = JSON.parse(crtshResult.stdout);
            } catch {
              findings.error = "Failed to parse crt.sh response";
              if (params.output_format === "json") {
                return { content: [formatToolOutput(findings)] };
              }
              return {
                content: [createErrorContent("Failed to parse crt.sh JSON response")],
                isError: true,
              };
            }

            findings.totalCerts = ctEntries.length;

            const issuers = new Set<string>();
            const wildcardCerts: Array<Record<string, unknown>> = [];
            const recentCerts: Array<Record<string, unknown>> = [];
            const thirtyDaysAgo = new Date();
            thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

            for (const entry of ctEntries.slice(0, 200)) {
              const issuerName = String(entry.issuer_name ?? "unknown");
              issuers.add(issuerName);

              const commonName = String(entry.common_name ?? "");
              if (commonName.startsWith("*.")) {
                wildcardCerts.push(entry);
              }

              const notBefore = entry.not_before ? new Date(String(entry.not_before)) : null;
              if (notBefore && notBefore > thirtyDaysAgo) {
                recentCerts.push(entry);
              }
            }

            findings.issuers = [...issuers];
            findings.wildcardCount = wildcardCerts.length;
            findings.recentCount = recentCerts.length;
            findings.recentCerts = recentCerts.slice(0, 20).map((e) => ({
              commonName: e.common_name,
              issuer: e.issuer_name,
              notBefore: e.not_before,
              notAfter: e.not_after,
            }));

            const unexpectedFindings: string[] = [];
            if (issuers.size > 3) {
              unexpectedFindings.push(
                `Multiple issuers detected (${issuers.size}) — review for unauthorized certificate issuance`,
              );
            }
            if (wildcardCerts.length > 0) {
              unexpectedFindings.push(`${wildcardCerts.length} wildcard certificate(s) found`);
            }
            findings.unexpectedFindings = unexpectedFindings;

            if (params.output_format === "json") {
              return { content: [formatToolOutput(findings)] };
            }

            const sections: string[] = [];
            sections.push("🔍 CT Log Monitor");
            sections.push("=".repeat(50));
            sections.push(`\nDomain: ${validDomain}`);
            sections.push(`Total certificates in CT logs: ${ctEntries.length}`);
            sections.push(`Unique issuers: ${issuers.size}`);
            sections.push(`Wildcard certificates: ${wildcardCerts.length}`);
            sections.push(`Recently issued (last 30 days): ${recentCerts.length}`);

            if (issuers.size > 0) {
              sections.push("\n── Issuers ──");
              for (const issuer of issuers) {
                sections.push(`  ${issuer}`);
              }
            }

            if (recentCerts.length > 0) {
              sections.push("\n── Recently Issued ──");
              for (const cert of recentCerts.slice(0, 10)) {
                sections.push(`  ${cert.common_name} (issued: ${cert.not_before}, by: ${cert.issuer_name})`);
              }
            }

            if (unexpectedFindings.length > 0) {
              sections.push("\n⚠️ Findings:");
              for (const finding of unexpectedFindings) {
                sections.push(`  ${finding}`);
              }
            }

            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`ct_log_monitor failed: ${msg}`)], isError: true };
          }
        }

        default:
          return {
            content: [createErrorContent(`Unknown action: ${action}`)],
            isError: true,
          };
      }
    },
  );
}
