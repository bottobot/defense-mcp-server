/**
 * Encryption and cryptography tools for Kali Defense MCP Server.
 *
 * Registers 6 tools: crypto_tls_audit, crypto_cert_expiry,
 * crypto_gpg_keys, crypto_luks_manage, crypto_file_hash,
 * crypto_tls_config_audit.
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
import { logChange, createChangeEntry, backupFile } from "../core/changelog.js";
import {
  validateTarget,
  validateFilePath,
  sanitizeArgs,
  validateCertPath,
} from "../core/sanitizer.js";

// ── Helpers ────────────────────────────────────────────────────────────────

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

// ── Registration entry point ───────────────────────────────────────────────

export function registerEncryptionTools(server: McpServer): void {
  // ── 1. crypto_tls_audit ──────────────────────────────────────────────────

  server.tool(
    "crypto_tls_audit",
    "Audit SSL/TLS configuration of a remote host, checking ciphers, protocols, and certificate details",
    {
      host: z.string().describe("Target hostname or IP address"),
      port: z
        .number()
        .optional()
        .default(443)
        .describe("Target port (default: 443)"),
      check_ciphers: z
        .boolean()
        .optional()
        .default(true)
        .describe("Check for weak cipher suites"),
      check_protocols: z
        .boolean()
        .optional()
        .default(true)
        .describe("Check for weak protocol versions"),
      check_certificate: z
        .boolean()
        .optional()
        .default(true)
        .describe("Check certificate details and validity"),
    },
    async ({ host, port, check_ciphers, check_protocols, check_certificate }) => {
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
        // Extract protocol and cipher from output
        const protocolMatch = fullOutput.match(/Protocol\s*:\s*(\S+)/);
        const cipherMatch = fullOutput.match(/Cipher\s*:\s*(\S+)/);

        if (protocolMatch) sections.push(`  Protocol: ${protocolMatch[1]}`);
        if (cipherMatch) sections.push(`  Cipher: ${cipherMatch[1]}`);

        // Detailed connection for more info
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

        // Check certificate details
        if (check_certificate) {
          sections.push("\n📜 Certificate Details:");

          const subjectMatch = detailOutput.match(
            /subject=([^\n]+)/
          );
          const issuerMatch = detailOutput.match(
            /issuer=([^\n]+)/
          );
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

            // Check expiry
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

          // Check for self-signed
          if (detailOutput.includes("self signed certificate") ||
              detailOutput.includes("self-signed")) {
            sections.push(`  ⚠️ Self-signed certificate detected`);
          }
        }

        // Check for weak ciphers
        if (check_ciphers) {
          sections.push("\n🔑 Cipher Analysis:");
          const weakFound = checkWeakCiphers(detailOutput);
          if (weakFound.length > 0) {
            sections.push(`  ⛔ Weak ciphers detected: ${weakFound.join(", ")}`);
          } else {
            sections.push(`  ✅ No known weak ciphers detected in connection`);
          }
        }

        // Check for weak protocols
        if (check_protocols) {
          sections.push("\n🔒 Protocol Analysis:");
          const weakProtos = checkWeakProtocols(detailOutput);
          if (weakProtos.length > 0) {
            sections.push(
              `  ⛔ Weak protocols detected: ${weakProtos.join(", ")}`
            );
          } else {
            sections.push(`  ✅ No weak protocols detected in connection`);
          }

          // Test specific weak protocols
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

            if (
              proto.name === "TLSv1" ||
              proto.name === "TLSv1.1"
            ) {
              if (connected) {
                sections.push(
                  `  ⚠️ ${proto.name}: Supported (deprecated, should be disabled)`
                );
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
  );

  // ── 2. crypto_cert_expiry ────────────────────────────────────────────────

  server.tool(
    "crypto_cert_expiry",
    "Check SSL/TLS certificate expiry dates for local files or remote hosts",
    {
      cert_path: z
        .string()
        .optional()
        .describe("Local certificate file path to check"),
      host: z.string().optional().describe("Remote host to check"),
      port: z
        .number()
        .optional()
        .default(443)
        .describe("Remote port (default: 443)"),
      warn_days: z
        .number()
        .optional()
        .default(30)
        .describe("Days before expiry to issue a warning"),
    },
    async ({ cert_path, host, port, warn_days }) => {
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
            args: [
              "x509",
              "-in",
              validPath,
              "-noout",
              "-enddate",
              "-subject",
              "-issuer",
            ],
            toolName: "crypto_cert_expiry",
            timeout: getToolTimeout("crypto_cert_expiry"),
          });

          if (result.exitCode !== 0) {
            return {
              content: [
                createErrorContent(
                  `Failed to read certificate: ${result.stderr}`
                ),
              ],
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
            args: [
              "s_client",
              "-connect",
              `${validHost}:${port}`,
              "-servername",
              validHost,
            ],
            stdin: "",
            toolName: "crypto_cert_expiry",
            timeout: getToolTimeout("crypto_cert_expiry"),
          });

          const fullOutput = result.stdout + "\n" + result.stderr;

          // Extract dates from the connection output
          const notAfterMatch = fullOutput.match(
            /Not After\s*:\s*([^\n]+)/
          );
          const subjectMatch = fullOutput.match(/subject=([^\n]+)/);
          const issuerMatch = fullOutput.match(/issuer=([^\n]+)/);

          if (notAfterMatch) endDate = notAfterMatch[1].trim();
          if (subjectMatch) subject = subjectMatch[1].trim();
          if (issuerMatch) issuer = issuerMatch[1].trim();

          if (!endDate) {
            // Try parsing cert separately via pipe
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
            content: [
              createErrorContent(
                "Could not determine certificate expiry date"
              ),
            ],
            isError: true,
          };
        }

        if (subject) sections.push(`  Subject: ${subject}`);
        if (issuer) sections.push(`  Issuer: ${issuer}`);
        sections.push(`  Expiry: ${endDate}`);

        // Calculate days until expiry
        const expiryDate = new Date(endDate);
        const now = new Date();
        const daysLeft = Math.floor(
          (expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
        );

        let status: string;
        if (daysLeft < 0) {
          status = "CRITICAL";
          sections.push(
            `\n⛔ Status: ${status} - Certificate EXPIRED ${Math.abs(daysLeft)} days ago`
          );
        } else if (daysLeft <= warn_days) {
          status = "WARNING";
          sections.push(
            `\n⚠️ Status: ${status} - Certificate expires in ${daysLeft} days (threshold: ${warn_days})`
          );
        } else {
          status = "OK";
          sections.push(
            `\n✅ Status: ${status} - Certificate valid for ${daysLeft} more days`
          );
        }

        return { content: [createTextContent(sections.join("\n"))] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 3. crypto_gpg_keys ───────────────────────────────────────────────────

  server.tool(
    "crypto_gpg_keys",
    "Manage GPG keys: list, generate, export, import, or verify signatures",
    {
      action: z
        .enum(["list", "generate", "export", "import", "verify"])
        .describe("GPG action to perform"),
      key_id: z
        .string()
        .optional()
        .describe("GPG key ID (for export/verify)"),
      file_path: z
        .string()
        .optional()
        .describe("File path (for import/verify)"),
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview changes without executing (defaults to KALI_DEFENSE_DRY_RUN env var)"),
    },
    async ({ action, key_id, file_path, dry_run }) => {
      try {
        const sections: string[] = [];
        sections.push(`🔑 GPG Key Management: ${action}`);
        sections.push("=".repeat(40));

        switch (action) {
          case "list": {
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

            // Also list secret keys
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
            break;
          }

          case "generate": {
            if (dry_run ?? getConfig().dryRun) {
              sections.push("\n[DRY RUN] Would generate a new GPG key pair.");
              sections.push(
                "Command: gpg --full-generate-key"
              );
              sections.push(
                "\nNote: Key generation is interactive and requires user input."
              );
              sections.push(
                "To generate non-interactively, create a batch file with parameters."
              );
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
              sections.push(
                "⚠️ Interactive GPG key generation cannot be run in non-interactive mode."
              );
              sections.push(
                "Use 'gpg --batch --gen-key <batch_file>' for non-interactive generation."
              );
            }
            break;
          }

          case "export": {
            if (!key_id) {
              return {
                content: [
                  createErrorContent(
                    "key_id is required for GPG key export"
                  ),
                ],
                isError: true,
              };
            }

            sanitizeArgs([key_id]);

            const result = await executeCommand({
              command: "gpg",
              args: ["--export", "--armor", key_id],
              toolName: "crypto_gpg_keys",
              timeout: getToolTimeout("crypto_gpg_keys"),
            });

            if (result.exitCode !== 0 || !result.stdout.trim()) {
              return {
                content: [
                  createErrorContent(
                    `Failed to export key ${key_id}: ${result.stderr}`
                  ),
                ],
                isError: true,
              };
            }

            sections.push(`\nExported public key for: ${key_id}`);
            sections.push(result.stdout);
            break;
          }

          case "import": {
            if (!file_path) {
              return {
                content: [
                  createErrorContent(
                    "file_path is required for GPG key import"
                  ),
                ],
                isError: true,
              };
            }

            sanitizeArgs([file_path]);

            if (dry_run ?? getConfig().dryRun) {
              sections.push(
                `\n[DRY RUN] Would import GPG key from: ${file_path}`
              );
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
                  content: [
                    createErrorContent(
                      `Failed to import key: ${result.stderr}`
                    ),
                  ],
                  isError: true,
                };
              }

              sections.push(`\n✅ Key imported from: ${file_path}`);
              sections.push(result.stderr || result.stdout);

              logChange(
                createChangeEntry({
                  tool: "crypto_gpg_keys",
                  action: "import",
                  target: file_path,
                  after: result.stderr || result.stdout,
                  dryRun: false,
                  success: true,
                })
              );
            }
            break;
          }

          case "verify": {
            if (!file_path) {
              return {
                content: [
                  createErrorContent(
                    "file_path is required for GPG signature verification"
                  ),
                ],
                isError: true,
              };
            }

            sanitizeArgs([file_path]);

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
            break;
          }
        }

        return { content: [createTextContent(sections.join("\n"))] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 4. crypto_luks_manage ────────────────────────────────────────────────

  server.tool(
    "crypto_luks_manage",
    "Manage LUKS encrypted volumes: check status, dump headers, open/close, or list encrypted devices",
    {
      action: z
        .enum(["status", "dump", "open", "close", "list"])
        .describe("LUKS management action"),
      device: z
        .string()
        .optional()
        .describe("Block device path (e.g., /dev/sda2) for status/dump/open"),
      name: z
        .string()
        .optional()
        .describe("Mapper name for open/close operations"),
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview changes without executing (defaults to KALI_DEFENSE_DRY_RUN env var)"),
    },
    async ({ action, device, name, dry_run }) => {
      try {
        const sections: string[] = [];
        sections.push(`🔐 LUKS Volume Management: ${action}`);
        sections.push("=".repeat(40));

        switch (action) {
          case "status": {
            if (!name) {
              return {
                content: [
                  createErrorContent(
                    "name (mapper name) is required for status check"
                  ),
                ],
                isError: true,
              };
            }

            sanitizeArgs([name]);

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
            break;
          }

          case "dump": {
            if (!device) {
              return {
                content: [
                  createErrorContent(
                    "device path is required for LUKS header dump"
                  ),
                ],
                isError: true,
              };
            }

            sanitizeArgs([device]);

            const result = await executeCommand({
              command: "sudo",
              args: ["cryptsetup", "luksDump", device],
              toolName: "crypto_luks_manage",
              timeout: getToolTimeout("crypto_luks_manage"),
            });

            if (result.exitCode !== 0) {
              return {
                content: [
                  createErrorContent(
                    `Failed to dump LUKS header for ${device}: ${result.stderr}`
                  ),
                ],
                isError: true,
              };
            }

            sections.push(`\nLUKS Header Dump for ${device}:`);
            sections.push(result.stdout);
            break;
          }

          case "open": {
            if (!device || !name) {
              return {
                content: [
                  createErrorContent(
                    "Both device and name are required for LUKS open"
                  ),
                ],
                isError: true,
              };
            }

            sanitizeArgs([device, name]);

            if (dry_run ?? getConfig().dryRun) {
              sections.push(
                `\n[DRY RUN] Would open LUKS volume:`
              );
              sections.push(`  Device: ${device}`);
              sections.push(`  Mapper name: ${name}`);
              sections.push(
                `  Command: sudo cryptsetup luksOpen ${device} ${name}`
              );
              sections.push(
                "\nNote: This operation requires a passphrase and cannot be run non-interactively without a key file."
              );
            } else {
              sections.push(
                "⚠️ Interactive LUKS open requires a passphrase."
              );
              sections.push(
                "Use a key file with: sudo cryptsetup luksOpen --key-file <keyfile> <device> <name>"
              );

              logChange(
                createChangeEntry({
                  tool: "crypto_luks_manage",
                  action: "open_attempted",
                  target: device,
                  dryRun: false,
                  success: false,
                  error:
                    "Interactive passphrase required, cannot run non-interactively",
                })
              );
            }
            break;
          }

          case "close": {
            if (!name) {
              return {
                content: [
                  createErrorContent(
                    "name (mapper name) is required for LUKS close"
                  ),
                ],
                isError: true,
              };
            }

            sanitizeArgs([name]);

            if (dry_run ?? getConfig().dryRun) {
              sections.push(
                `\n[DRY RUN] Would close LUKS volume: /dev/mapper/${name}`
              );
              sections.push(
                `  Command: sudo cryptsetup luksClose ${name}`
              );
            } else {
              const result = await executeCommand({
                command: "sudo",
                args: ["cryptsetup", "luksClose", name],
                toolName: "crypto_luks_manage",
                timeout: getToolTimeout("crypto_luks_manage"),
              });

              if (result.exitCode !== 0) {
                return {
                  content: [
                    createErrorContent(
                      `Failed to close LUKS volume ${name}: ${result.stderr}`
                    ),
                  ],
                  isError: true,
                };
              }

              sections.push(`\n✅ LUKS volume '${name}' closed successfully.`);

              logChange(
                createChangeEntry({
                  tool: "crypto_luks_manage",
                  action: "close",
                  target: name,
                  dryRun: false,
                  success: true,
                  rollbackCommand: `sudo cryptsetup luksOpen <device> ${name}`,
                })
              );
            }
            break;
          }

          case "list": {
            // List device mapper entries
            const mapperResult = await executeCommand({
              command: "ls",
              args: ["-la", "/dev/mapper/"],
              toolName: "crypto_luks_manage",
              timeout: getToolTimeout("crypto_luks_manage"),
            });

            sections.push("\n📁 Device Mapper Entries:");
            sections.push(mapperResult.stdout || "No entries found");

            // List block devices with filesystem info
            const lsblkResult = await executeCommand({
              command: "lsblk",
              args: ["--fs", "-o", "NAME,FSTYPE,SIZE,MOUNTPOINT,UUID"],
              toolName: "crypto_luks_manage",
              timeout: getToolTimeout("crypto_luks_manage"),
            });

            sections.push("\n💾 Block Devices (with filesystem info):");
            sections.push(lsblkResult.stdout || "No block devices found");

            // Filter for crypto entries
            const cryptoLines = (lsblkResult.stdout || "")
              .split("\n")
              .filter(
                (l) =>
                  l.includes("crypto_LUKS") || l.includes("crypt")
              );
            if (cryptoLines.length > 0) {
              sections.push("\n🔐 LUKS Encrypted Devices:");
              for (const line of cryptoLines) {
                sections.push(`  ${line.trim()}`);
              }
            } else {
              sections.push("\nNo LUKS encrypted devices detected.");
            }
            break;
          }
        }

        return { content: [createTextContent(sections.join("\n"))] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 5. crypto_file_hash ──────────────────────────────────────────────────

  server.tool(
    "crypto_file_hash",
    "Calculate cryptographic hashes of files for integrity verification",
    {
      path: z.string().describe("File or directory path to hash"),
      algorithm: z
        .enum(["sha256", "sha512", "sha1", "md5"])
        .optional()
        .default("sha256")
        .describe("Hash algorithm to use (default: sha256)"),
      recursive: z
        .boolean()
        .optional()
        .default(false)
        .describe("Recursively hash all files in a directory"),
    },
    async ({ path, algorithm, recursive }) => {
      try {
        sanitizeArgs([path]);

        const sections: string[] = [];
        const hashCmd = `${algorithm}sum`;
        sections.push(`#️⃣ File Integrity Hash (${algorithm.toUpperCase()})`);
        sections.push("=".repeat(40));

        if (recursive) {
          // Hash all files in directory recursively
          const result = await executeCommand({
            command: "find",
            args: [
              path,
              "-type",
              "f",
              "-exec",
              hashCmd,
              "{}",
              "+",
            ],
            toolName: "crypto_file_hash",
            timeout: getToolTimeout("crypto_file_hash"),
          });

          if (result.exitCode !== 0 && !result.stdout) {
            return {
              content: [
                createErrorContent(
                  `Failed to hash files in ${path}: ${result.stderr}`
                ),
              ],
              isError: true,
            };
          }

          const lines = result.stdout
            .trim()
            .split("\n")
            .filter((l) => l.trim());
          sections.push(`\nDirectory: ${path}`);
          sections.push(`Files hashed: ${lines.length}`);
          sections.push(`\nResults:`);
          sections.push(result.stdout);
        } else {
          // Hash a single file
          const result = await executeCommand({
            command: hashCmd,
            args: [path],
            toolName: "crypto_file_hash",
            timeout: getToolTimeout("crypto_file_hash"),
          });

          if (result.exitCode !== 0) {
            return {
              content: [
                createErrorContent(
                  `Failed to hash ${path}: ${result.stderr}`
                ),
              ],
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
  );

  // ── 6. crypto_tls_config_audit ───────────────────────────────────────────

  server.tool(
    "crypto_tls_config_audit",
    "Audit system TLS configuration for web servers and system-wide crypto policies",
    {
      service: z
        .enum(["apache", "nginx", "system", "all"])
        .optional()
        .default("all")
        .describe("Service to audit TLS config for (default: all)"),
    },
    async ({ service }) => {
      try {
        const sections: string[] = [];
        sections.push("🔍 TLS Configuration Audit");
        sections.push("=".repeat(40));

        const findings: Array<{ level: string; msg: string }> = [];

        // Apache audit
        if (service === "apache" || service === "all") {
          sections.push("\n── Apache TLS Configuration ──");

          const apacheResult = await executeCommand({
            command: "find",
            args: [
              "/etc/apache2/sites-enabled/",
              "-type",
              "f",
              "-name",
              "*.conf",
            ],
            toolName: "crypto_tls_config_audit",
            timeout: 10000,
          });

          if (apacheResult.exitCode === 0 && apacheResult.stdout.trim()) {
            const confFiles = apacheResult.stdout
              .trim()
              .split("\n")
              .filter((f) => f.trim());

            for (const confFile of confFiles) {
              const catResult = await executeCommand({
                command: "cat",
                args: [confFile.trim()],
                toolName: "crypto_tls_config_audit",
                timeout: 5000,
              });

              if (catResult.exitCode === 0) {
                const content = catResult.stdout;
                sections.push(`\n  File: ${confFile.trim()}`);

                // Check SSLProtocol
                const protoMatch = content.match(/SSLProtocol\s+(.+)/);
                if (protoMatch) {
                  sections.push(`  SSLProtocol: ${protoMatch[1].trim()}`);
                  const proto = protoMatch[1];
                  if (
                    proto.includes("SSLv3") ||
                    proto.includes("TLSv1 ") ||
                    proto.includes("TLSv1.0") ||
                    proto.includes("TLSv1.1")
                  ) {
                    findings.push({
                      level: "CRITICAL",
                      msg: `${confFile}: Weak protocol in SSLProtocol: ${protoMatch[1].trim()}`,
                    });
                  }
                }

                // Check SSLCipherSuite
                const cipherMatch = content.match(/SSLCipherSuite\s+(.+)/);
                if (cipherMatch) {
                  sections.push(
                    `  SSLCipherSuite: ${cipherMatch[1].trim().substring(0, 80)}...`
                  );
                  const weakCiphers = checkWeakCiphers(cipherMatch[1]);
                  if (weakCiphers.length > 0) {
                    findings.push({
                      level: "WARNING",
                      msg: `${confFile}: Weak ciphers found: ${weakCiphers.join(", ")}`,
                    });
                  }
                }
              }
            }
          } else {
            sections.push(
              "  Apache not installed or no sites-enabled configuration found."
            );
          }
        }

        // Nginx audit
        if (service === "nginx" || service === "all") {
          sections.push("\n── Nginx TLS Configuration ──");

          const nginxResult = await executeCommand({
            command: "find",
            args: [
              "/etc/nginx/",
              "-type",
              "f",
              "-name",
              "*.conf",
            ],
            toolName: "crypto_tls_config_audit",
            timeout: 10000,
          });

          if (nginxResult.exitCode === 0 && nginxResult.stdout.trim()) {
            const confFiles = nginxResult.stdout
              .trim()
              .split("\n")
              .filter((f) => f.trim());

            for (const confFile of confFiles) {
              const catResult = await executeCommand({
                command: "cat",
                args: [confFile.trim()],
                toolName: "crypto_tls_config_audit",
                timeout: 5000,
              });

              if (catResult.exitCode === 0) {
                const content = catResult.stdout;

                if (
                  content.includes("ssl_protocols") ||
                  content.includes("ssl_ciphers")
                ) {
                  sections.push(`\n  File: ${confFile.trim()}`);

                  // Check ssl_protocols
                  const protoMatch = content.match(
                    /ssl_protocols\s+([^;]+)/
                  );
                  if (protoMatch) {
                    sections.push(
                      `  ssl_protocols: ${protoMatch[1].trim()}`
                    );
                    const proto = protoMatch[1];
                    if (
                      proto.includes("SSLv3") ||
                      proto.includes("TLSv1 ") ||
                      proto.includes("TLSv1.0") ||
                      proto.includes("TLSv1.1")
                    ) {
                      findings.push({
                        level: "CRITICAL",
                        msg: `${confFile}: Weak protocol in ssl_protocols: ${protoMatch[1].trim()}`,
                      });
                    }
                  }

                  // Check ssl_ciphers
                  const cipherMatch = content.match(
                    /ssl_ciphers\s+['"]?([^;'"]+)/
                  );
                  if (cipherMatch) {
                    sections.push(
                      `  ssl_ciphers: ${cipherMatch[1].trim().substring(0, 80)}...`
                    );
                    const weakCiphers = checkWeakCiphers(cipherMatch[1]);
                    if (weakCiphers.length > 0) {
                      findings.push({
                        level: "WARNING",
                        msg: `${confFile}: Weak ciphers: ${weakCiphers.join(", ")}`,
                      });
                    }
                  }
                }
              }
            }
          } else {
            sections.push(
              "  Nginx not installed or no configuration found."
            );
          }
        }

        // System-wide crypto audit
        if (service === "system" || service === "all") {
          sections.push("\n── System-Wide Crypto Configuration ──");

          // Check openssl.cnf
          const opensslResult = await executeCommand({
            command: "cat",
            args: ["/etc/ssl/openssl.cnf"],
            toolName: "crypto_tls_config_audit",
            timeout: 5000,
          });

          if (opensslResult.exitCode === 0) {
            sections.push("\n  OpenSSL config (/etc/ssl/openssl.cnf): Found");

            // Check for MinProtocol
            const minProtoMatch = opensslResult.stdout.match(
              /MinProtocol\s*=\s*(\S+)/
            );
            if (minProtoMatch) {
              sections.push(
                `  MinProtocol: ${minProtoMatch[1]}`
              );
            }

            // Check for CipherString
            const cipherStringMatch = opensslResult.stdout.match(
              /CipherString\s*=\s*(\S+)/
            );
            if (cipherStringMatch) {
              sections.push(
                `  CipherString: ${cipherStringMatch[1]}`
              );
            }
          } else {
            sections.push("  OpenSSL config: Not found at /etc/ssl/openssl.cnf");
          }

          // Check crypto-policies (RHEL/Fedora)
          const policyResult = await executeCommand({
            command: "cat",
            args: ["/etc/crypto-policies/config"],
            toolName: "crypto_tls_config_audit",
            timeout: 5000,
          });

          if (policyResult.exitCode === 0 && policyResult.stdout.trim()) {
            sections.push(
              `\n  System crypto policy: ${policyResult.stdout.trim()}`
            );
            const policy = policyResult.stdout.trim().toUpperCase();
            if (policy === "LEGACY" || policy === "DEFAULT") {
              findings.push({
                level: "WARNING",
                msg: `System crypto policy is '${policyResult.stdout.trim()}' - consider using FUTURE or FIPS`,
              });
            }
          }

          // Check OpenSSL version
          const versionResult = await executeCommand({
            command: "openssl",
            args: ["version"],
            toolName: "crypto_tls_config_audit",
            timeout: 5000,
          });

          if (versionResult.exitCode === 0) {
            sections.push(
              `\n  OpenSSL version: ${versionResult.stdout.trim()}`
            );
          }
        }

        // Summary
        sections.push("\n── Findings Summary ──");
        if (findings.length === 0) {
          sections.push("  ✅ No critical TLS configuration issues found.");
        } else {
          const criticals = findings.filter((f) => f.level === "CRITICAL");
          const warnings = findings.filter((f) => f.level === "WARNING");

          if (criticals.length > 0) {
            sections.push(`\n  ⛔ Critical (${criticals.length}):`);
            for (const f of criticals) {
              sections.push(`    - ${f.msg}`);
            }
          }
          if (warnings.length > 0) {
            sections.push(`\n  ⚠️ Warnings (${warnings.length}):`);
            for (const f of warnings) {
              sections.push(`    - ${f.msg}`);
            }
          }
        }

        return { content: [createTextContent(sections.join("\n"))] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );
}
