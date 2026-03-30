/**
 * Zero-trust network tools.
 *
 * Registers 1 tool: zero_trust (actions: wireguard, wg_peers, mtls, microsegment).
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeCommand } from "../core/executor.js";
import { createErrorContent, formatToolOutput } from "../core/parsers.js";
import { logChange, createChangeEntry, backupFile } from "../core/changelog.js";
import { SafeguardRegistry } from "../core/safeguards.js";
import { validateTarget, validatePort } from "../core/sanitizer.js";
import { existsSync } from "node:fs";

// ── Input validation helpers (TOOL-003 remediation) ────────────────────────

/** Validate a service name for use in iptables comments — alphanumeric, dash, underscore only */
const SERVICE_NAME_RE = /^[a-zA-Z0-9._-]+$/;
function validateServiceName(name: string): string {
  if (!name || !SERVICE_NAME_RE.test(name)) {
    throw new Error(`Invalid service name: '${name}'. Only [a-zA-Z0-9._-] allowed.`);
  }
  return name;
}

export function registerZeroTrustNetworkTools(server: McpServer): void {

  server.tool(
    "zero_trust",
    "Zero-trust: WireGuard VPN, peer management, mTLS certificates, microsegmentation",
    {
      action: z.enum(["wireguard", "wg_peers", "mtls", "microsegment"]).describe("Zero-trust networking action"),
      // wireguard params
      interfaceName: z.string().optional().default("wg0").describe("WireGuard interface name"),
      listenPort: z.number().optional().default(51820).describe("UDP listen port"),
      address: z.string().optional().describe("Interface address with CIDR e.g. 10.0.0.1/24"),
      // wg_peers params
      peer_action: z.enum(["add", "remove", "list"]).optional().describe("Peer sub-action"),
      publicKey: z.string().optional().describe("Peer public key"),
      allowedIps: z.string().optional().describe("Allowed IPs for peer"),
      endpoint: z.string().optional().describe("Peer endpoint ip:port"),
      // mtls params
      outputDir: z.string().optional().describe("Directory to write certificates"),
      commonName: z.string().optional().default("defense-mcp-ca").describe("CA common name"),
      serverCN: z.string().optional().default("server.local").describe("Server common name"),
      clientCN: z.string().optional().default("client.local").describe("Client common name"),
      validDays: z.number().optional().default(365).describe("Certificate validity in days"),
      // microsegment params
      service: z.string().optional().describe("Service name e.g. nginx, postgres"),
      allowPorts: z.array(z.number()).optional().describe("Ports to allow"),
      allowSources: z.array(z.string()).optional().default([]).describe("Source IPs/CIDRs to allow"),
      denyAll: z.boolean().optional().default(true).describe("Add deny-all rule for other ports"),
      // shared
      dryRun: z.boolean().optional().default(true).describe("Preview only"),
    },
    async (params) => {
      const { action } = params;

      switch (action) {
        // ── wireguard ───────────────────────────────────────────────
        case "wireguard": {
          const { interfaceName, listenPort, address, dryRun } = params;
          try {
            if (!address) {
              return { content: [createErrorContent("address is required for wireguard action (e.g. 10.0.0.1/24)")], isError: true };
            }

            const safety = await SafeguardRegistry.getInstance().checkSafety("setup_wireguard", { interfaceName });
            if (!safety.safe) {
              return { content: [formatToolOutput({ blocked: true, ...safety })], isError: true };
            }

            // Generate keys
            const privKeyResult = await executeCommand({ toolName: "zero_trust", command: "wg", args: ["genkey"], timeout: 5000 });
            if (privKeyResult.exitCode !== 0) {
              return { content: [createErrorContent("WireGuard tools not installed. Install wireguard-tools.")], isError: true };
            }
            const privateKey = privKeyResult.stdout.trim();

            const pubKeyResult = await executeCommand({
              toolName: "zero_trust",
              command: "wg",
              args: ["pubkey"],
              stdin: privateKey,
              timeout: 5000,
            });
            const publicKey = pubKeyResult.stdout.trim();

            const config = `[Interface]
PrivateKey = ${privateKey}
Address = ${address}
ListenPort = ${listenPort}
`;

            const configPath = `/etc/wireguard/${interfaceName}.conf`;

            if (dryRun) {
              return {
                content: [formatToolOutput({
                  dryRun: true,
                  publicKey,
                  configPath,
                  configPreview: config.replace(privateKey, "[REDACTED]"),
                  warnings: safety.warnings,
                  nextSteps: [`wg-quick up ${interfaceName}`],
                })],
              };
            }

            // Backup existing config if present
            if (existsSync(configPath)) {
              backupFile(configPath);
            }

            const writeResult = await executeCommand({
              toolName: "zero_trust",
              command: "tee",
              args: [configPath],
              stdin: config,
              timeout: 5000,
            });

            // Set permissions
            await executeCommand({ toolName: "zero_trust", command: "chmod", args: ["600", configPath], timeout: 5000 });

            const entry = createChangeEntry({
              tool: "zero_trust",
              action: `Create WireGuard config for ${interfaceName}`,
              target: configPath,
              dryRun: false,
              success: writeResult.exitCode === 0,
              rollbackCommand: `rm ${configPath}`,
            });
            logChange(entry);

            return {
              content: [formatToolOutput({
                success: writeResult.exitCode === 0,
                publicKey,
                configPath,
                interfaceName,
                listenPort,
                nextSteps: [`wg-quick up ${interfaceName}`],
              })],
            };
          } catch (err) {
            return { content: [createErrorContent(`WireGuard setup failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true };
          }
        }

        // ── wg_peers ────────────────────────────────────────────────
        case "wg_peers": {
          const { peer_action, interfaceName, publicKey, allowedIps, endpoint, dryRun } = params;
          try {
            if (!peer_action) {
              return { content: [createErrorContent("peer_action is required for wg_peers action (add/remove/list)")], isError: true };
            }

            if (peer_action === "list") {
              const result = await executeCommand({
                toolName: "zero_trust",
                command: "wg",
                args: ["show", interfaceName],
                timeout: 10000,
              });
              return {
                content: [formatToolOutput({
                  interface: interfaceName,
                  output: result.stdout || result.stderr,
                  exitCode: result.exitCode,
                })],
              };
            }

            if (!publicKey) {
              return { content: [createErrorContent("publicKey is required for add/remove actions")], isError: true };
            }

            if (peer_action === "add") {
              if (!allowedIps) {
                return { content: [createErrorContent("allowedIps is required for add action")], isError: true };
              }

              const args = ["set", interfaceName, "peer", publicKey, "allowed-ips", allowedIps];
              if (endpoint) args.push("endpoint", endpoint);

              if (dryRun) {
                return { content: [formatToolOutput({ dryRun: true, command: `wg ${args.join(" ")}` })] };
              }

              const result = await executeCommand({ toolName: "zero_trust", command: "wg", args, timeout: 10000 });

              const entry = createChangeEntry({
                tool: "zero_trust",
                action: `Add peer ${publicKey.slice(0, 12)}...`,
                target: interfaceName,
                dryRun: false,
                success: result.exitCode === 0,
                rollbackCommand: `wg set ${interfaceName} peer ${publicKey} remove`,
              });
              logChange(entry);

              return { content: [formatToolOutput({ success: result.exitCode === 0, output: result.stdout || result.stderr })] };
            }

            if (peer_action === "remove") {
              const args = ["set", interfaceName, "peer", publicKey, "remove"];

              if (dryRun) {
                return { content: [formatToolOutput({ dryRun: true, command: `wg ${args.join(" ")}` })] };
              }

              const result = await executeCommand({ toolName: "zero_trust", command: "wg", args, timeout: 10000 });
              const entry = createChangeEntry({
                tool: "zero_trust",
                action: `Remove peer ${publicKey.slice(0, 12)}...`,
                target: interfaceName,
                dryRun: false,
                success: result.exitCode === 0,
              });
              logChange(entry);

              return { content: [formatToolOutput({ success: result.exitCode === 0, output: result.stdout || result.stderr })] };
            }

            return { content: [createErrorContent(`Unknown peer_action: ${peer_action}`)], isError: true };
          } catch (err) {
            return { content: [createErrorContent(`WireGuard peer management failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true };
          }
        }

        // ── mtls ────────────────────────────────────────────────────
        case "mtls": {
          const { outputDir, commonName, serverCN, clientCN, validDays, dryRun } = params;
          try {
            if (!outputDir) {
              return { content: [createErrorContent("outputDir is required for mtls action")], isError: true };
            }

            if (dryRun) {
              return {
                content: [formatToolOutput({
                  dryRun: true,
                  outputDir,
                  files: ["ca.key", "ca.crt", "server.key", "server.crt", "client.key", "client.crt"],
                  commonName,
                  serverCN,
                  clientCN,
                  validDays,
                })],
              };
            }

            // Create output directory
            await executeCommand({ toolName: "zero_trust", command: "mkdir", args: ["-p", outputDir], timeout: 5000 });

            // Generate CA key and cert
            await executeCommand({
              toolName: "zero_trust",
              command: "openssl",
              args: ["req", "-x509", "-newkey", "rsa:4096", "-keyout", `${outputDir}/ca.key`,
                "-out", `${outputDir}/ca.crt`, "-days", String(validDays), "-nodes",
                "-subj", `/CN=${commonName}`],
              timeout: 30000,
            });

            // Generate server key, CSR, and sign with CA
            await executeCommand({
              toolName: "zero_trust",
              command: "openssl",
              args: ["req", "-newkey", "rsa:4096", "-keyout", `${outputDir}/server.key`,
                "-out", `${outputDir}/server.csr`, "-nodes", "-subj", `/CN=${serverCN}`],
              timeout: 30000,
            });
            await executeCommand({
              toolName: "zero_trust",
              command: "openssl",
              args: ["x509", "-req", "-in", `${outputDir}/server.csr`, "-CA", `${outputDir}/ca.crt`,
                "-CAkey", `${outputDir}/ca.key`, "-CAcreateserial", "-out", `${outputDir}/server.crt`,
                "-days", String(validDays)],
              timeout: 30000,
            });

            // Generate client key, CSR, and sign with CA
            await executeCommand({
              toolName: "zero_trust",
              command: "openssl",
              args: ["req", "-newkey", "rsa:4096", "-keyout", `${outputDir}/client.key`,
                "-out", `${outputDir}/client.csr`, "-nodes", "-subj", `/CN=${clientCN}`],
              timeout: 30000,
            });
            await executeCommand({
              toolName: "zero_trust",
              command: "openssl",
              args: ["x509", "-req", "-in", `${outputDir}/client.csr`, "-CA", `${outputDir}/ca.crt`,
                "-CAkey", `${outputDir}/ca.key`, "-CAcreateserial", "-out", `${outputDir}/client.crt`,
                "-days", String(validDays)],
              timeout: 30000,
            });

            // Set permissions on keys
            await executeCommand({ toolName: "zero_trust", command: "chmod", args: ["600", `${outputDir}/ca.key`, `${outputDir}/server.key`, `${outputDir}/client.key`], timeout: 5000 });

            const entry = createChangeEntry({
              tool: "zero_trust",
              action: "Generate mTLS certificate chain",
              target: outputDir,
              dryRun: false,
              success: true,
            });
            logChange(entry);

            return {
              content: [formatToolOutput({
                success: true,
                outputDir,
                filesCreated: ["ca.key", "ca.crt", "server.key", "server.crt", "client.key", "client.crt"],
                validDays,
              })],
            };
          } catch (err) {
            return { content: [createErrorContent(`mTLS setup failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true };
          }
        }

        // ── microsegment ────────────────────────────────────────────
        case "microsegment": {
          const { service, allowPorts, allowSources, denyAll, dryRun } = params;
          try {
            if (!service) {
              return { content: [createErrorContent("service is required for microsegment action")], isError: true };
            }
            if (!allowPorts || allowPorts.length === 0) {
              return { content: [createErrorContent("allowPorts is required for microsegment action")], isError: true };
            }

            // TOOL-003 remediation: validate all user-supplied inputs
            const validatedService = validateServiceName(service);
            const validatedPorts: number[] = allowPorts.map(p => validatePort(p));
            const validatedSources: string[] = allowSources.map(s => validateTarget(s));

            const safety = await SafeguardRegistry.getInstance().checkSafety("configure_microsegmentation", { service: validatedService, ports: validatedPorts });

            // Build rules as structured {command, args} arrays — no string interpolation/splitting
            const rules: { description: string; command: string; args: string[] }[] = [];

            for (const port of validatedPorts) {
              if (validatedSources.length > 0) {
                for (const src of validatedSources) {
                  rules.push({
                    description: `iptables -A INPUT -p tcp --dport ${port} -s ${src} -j ACCEPT -m comment --comment "microseg-${validatedService}"`,
                    command: "iptables",
                    args: ["-A", "INPUT", "-p", "tcp", "--dport", String(port), "-s", src, "-j", "ACCEPT", "-m", "comment", "--comment", `microseg-${validatedService}`],
                  });
                }
              } else {
                rules.push({
                  description: `iptables -A INPUT -p tcp --dport ${port} -j ACCEPT -m comment --comment "microseg-${validatedService}"`,
                  command: "iptables",
                  args: ["-A", "INPUT", "-p", "tcp", "--dport", String(port), "-j", "ACCEPT", "-m", "comment", "--comment", `microseg-${validatedService}`],
                });
              }
            }

            if (denyAll) {
              for (const port of validatedPorts) {
                rules.push({
                  description: `iptables -A INPUT -p tcp --dport ${port} -j DROP -m comment --comment "microseg-${validatedService}-deny"`,
                  command: "iptables",
                  args: ["-A", "INPUT", "-p", "tcp", "--dport", String(port), "-j", "DROP", "-m", "comment", "--comment", `microseg-${validatedService}-deny`],
                });
              }
            }

            if (dryRun) {
              return {
                content: [formatToolOutput({
                  dryRun: true,
                  service: validatedService,
                  rules: rules.map(r => r.description),
                  warnings: safety.warnings,
                })],
              };
            }

            const results: { rule: string; success: boolean; error?: string }[] = [];
            for (const rule of rules) {
              // Execute directly with parameterized arrays — no shell string splitting
              const result = await executeCommand({
                toolName: "zero_trust",
                command: rule.command,
                args: rule.args,
                timeout: 10000,
              });
              results.push({ rule: rule.description, success: result.exitCode === 0, error: result.exitCode !== 0 ? result.stderr : undefined });
            }

            const entry = createChangeEntry({
              tool: "zero_trust",
              action: `Microsegment ${service}`,
              target: service,
              dryRun: false,
              success: results.every((r) => r.success),
            });
            logChange(entry);

            return { content: [formatToolOutput({ service, results })] };
          } catch (err) {
            return { content: [createErrorContent(`Microsegmentation failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true };
          }
        }

        default:
          return { content: [createErrorContent(`Unknown action: ${action}`)], isError: true };
      }
    }
  );
}
