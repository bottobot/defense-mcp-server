/**
 * Zero-trust network tools.
 *
 * Tools: setup_wireguard, manage_wg_peers, setup_mtls, configure_microsegmentation
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeCommand } from "../core/executor.js";
import { createErrorContent, formatToolOutput } from "../core/parsers.js";
import { logChange, createChangeEntry, backupFile } from "../core/changelog.js";
import { SafeguardRegistry } from "../core/safeguards.js";
import { validateFilePath } from "../core/sanitizer.js";
import { existsSync, readFileSync } from "node:fs";

export function registerZeroTrustNetworkTools(server: McpServer): void {

  // ── setup_wireguard ────────────────────────────────────────────────────────

  server.tool(
    "setup_wireguard",
    "Set up a WireGuard VPN interface with key generation and configuration.",
    {
      interfaceName: z.string().optional().default("wg0").describe("WireGuard interface name"),
      listenPort: z.number().optional().default(51820).describe("UDP listen port"),
      address: z.string().describe("Interface address with CIDR (e.g., 10.0.0.1/24)"),
      dryRun: z.boolean().optional().default(true).describe("Preview only"),
    },
    async ({ interfaceName, listenPort, address, dryRun }) => {
      try {
        const safety = await SafeguardRegistry.getInstance().checkSafety("setup_wireguard", { interfaceName });
        if (!safety.safe) {
          return { content: [formatToolOutput({ blocked: true, ...safety })], isError: true };
        }

        // Generate keys
        const privKeyResult = await executeCommand({ command: "wg", args: ["genkey"], timeout: 5000 });
        if (privKeyResult.exitCode !== 0) {
          return { content: [createErrorContent("WireGuard tools not installed. Install wireguard-tools.")], isError: true };
        }
        const privateKey = privKeyResult.stdout.trim();

        const pubKeyResult = await executeCommand({
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
          command: "tee",
          args: [configPath],
          stdin: config,
          timeout: 5000,
        });

        // Set permissions
        await executeCommand({ command: "chmod", args: ["600", configPath], timeout: 5000 });

        const entry = createChangeEntry({
          tool: "setup_wireguard",
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
  );

  // ── manage_wg_peers ────────────────────────────────────────────────────────

  server.tool(
    "manage_wg_peers",
    "Add, remove, or list WireGuard peers.",
    {
      action: z.enum(["add", "remove", "list"]).describe("Action to perform"),
      interfaceName: z.string().optional().default("wg0").describe("WireGuard interface"),
      publicKey: z.string().optional().describe("Peer public key (required for add/remove)"),
      allowedIps: z.string().optional().describe("Allowed IPs for peer (required for add)"),
      endpoint: z.string().optional().describe("Peer endpoint (ip:port)"),
      dryRun: z.boolean().optional().default(true).describe("Preview only"),
    },
    async ({ action, interfaceName, publicKey, allowedIps, endpoint, dryRun }) => {
      try {
        if (action === "list") {
          const result = await executeCommand({
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

        if (action === "add") {
          if (!allowedIps) {
            return { content: [createErrorContent("allowedIps is required for add action")], isError: true };
          }

          const args = ["set", interfaceName, "peer", publicKey, "allowed-ips", allowedIps];
          if (endpoint) args.push("endpoint", endpoint);

          if (dryRun) {
            return { content: [formatToolOutput({ dryRun: true, command: `wg ${args.join(" ")}` })] };
          }

          const result = await executeCommand({ command: "wg", args, timeout: 10000 });

          const entry = createChangeEntry({
            tool: "manage_wg_peers",
            action: `Add peer ${publicKey.slice(0, 12)}...`,
            target: interfaceName,
            dryRun: false,
            success: result.exitCode === 0,
            rollbackCommand: `wg set ${interfaceName} peer ${publicKey} remove`,
          });
          logChange(entry);

          return { content: [formatToolOutput({ success: result.exitCode === 0, output: result.stdout || result.stderr })] };
        }

        if (action === "remove") {
          const args = ["set", interfaceName, "peer", publicKey, "remove"];

          if (dryRun) {
            return { content: [formatToolOutput({ dryRun: true, command: `wg ${args.join(" ")}` })] };
          }

          const result = await executeCommand({ command: "wg", args, timeout: 10000 });
          const entry = createChangeEntry({
            tool: "manage_wg_peers",
            action: `Remove peer ${publicKey.slice(0, 12)}...`,
            target: interfaceName,
            dryRun: false,
            success: result.exitCode === 0,
          });
          logChange(entry);

          return { content: [formatToolOutput({ success: result.exitCode === 0, output: result.stdout || result.stderr })] };
        }

        return { content: [createErrorContent(`Unknown action: ${action}`)], isError: true };
      } catch (err) {
        return { content: [createErrorContent(`WireGuard peer management failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true };
      }
    }
  );

  // ── setup_mtls ─────────────────────────────────────────────────────────────

  server.tool(
    "setup_mtls",
    "Generate CA, server, and client certificates for mutual TLS authentication.",
    {
      outputDir: z.string().describe("Directory to write certificates"),
      commonName: z.string().optional().default("kali-defense-ca").describe("CA common name"),
      serverCN: z.string().optional().default("server.local").describe("Server common name"),
      clientCN: z.string().optional().default("client.local").describe("Client common name"),
      validDays: z.number().optional().default(365).describe("Certificate validity in days"),
      dryRun: z.boolean().optional().default(true).describe("Preview only"),
    },
    async ({ outputDir, commonName, serverCN, clientCN, validDays, dryRun }) => {
      try {
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
        await executeCommand({ command: "mkdir", args: ["-p", outputDir], timeout: 5000 });

        // Generate CA key and cert
        await executeCommand({
          command: "openssl",
          args: ["req", "-x509", "-newkey", "rsa:4096", "-keyout", `${outputDir}/ca.key`,
            "-out", `${outputDir}/ca.crt`, "-days", String(validDays), "-nodes",
            "-subj", `/CN=${commonName}`],
          timeout: 30000,
        });

        // Generate server key, CSR, and sign with CA
        await executeCommand({
          command: "openssl",
          args: ["req", "-newkey", "rsa:4096", "-keyout", `${outputDir}/server.key`,
            "-out", `${outputDir}/server.csr`, "-nodes", "-subj", `/CN=${serverCN}`],
          timeout: 30000,
        });
        await executeCommand({
          command: "openssl",
          args: ["x509", "-req", "-in", `${outputDir}/server.csr`, "-CA", `${outputDir}/ca.crt`,
            "-CAkey", `${outputDir}/ca.key`, "-CAcreateserial", "-out", `${outputDir}/server.crt`,
            "-days", String(validDays)],
          timeout: 30000,
        });

        // Generate client key, CSR, and sign with CA
        await executeCommand({
          command: "openssl",
          args: ["req", "-newkey", "rsa:4096", "-keyout", `${outputDir}/client.key`,
            "-out", `${outputDir}/client.csr`, "-nodes", "-subj", `/CN=${clientCN}`],
          timeout: 30000,
        });
        await executeCommand({
          command: "openssl",
          args: ["x509", "-req", "-in", `${outputDir}/client.csr`, "-CA", `${outputDir}/ca.crt`,
            "-CAkey", `${outputDir}/ca.key`, "-CAcreateserial", "-out", `${outputDir}/client.crt`,
            "-days", String(validDays)],
          timeout: 30000,
        });

        // Set permissions on keys
        await executeCommand({ command: "chmod", args: ["600", `${outputDir}/ca.key`, `${outputDir}/server.key`, `${outputDir}/client.key`], timeout: 5000 });

        const entry = createChangeEntry({
          tool: "setup_mtls",
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
  );

  // ── configure_microsegmentation ────────────────────────────────────────────

  server.tool(
    "configure_microsegmentation",
    "Configure iptables/nftables rules for service-level microsegmentation.",
    {
      service: z.string().describe("Service name (e.g., nginx, postgres)"),
      allowPorts: z.array(z.number()).describe("Ports to allow"),
      allowSources: z.array(z.string()).optional().default([]).describe("Source IPs/CIDRs to allow (empty = all)"),
      denyAll: z.boolean().optional().default(true).describe("Add deny-all rule for other ports"),
      dryRun: z.boolean().optional().default(true).describe("Preview only"),
    },
    async ({ service, allowPorts, allowSources, denyAll, dryRun }) => {
      try {
        const safety = await SafeguardRegistry.getInstance().checkSafety("configure_microsegmentation", { service, ports: allowPorts });

        const rules: string[] = [];

        for (const port of allowPorts) {
          if (allowSources.length > 0) {
            for (const src of allowSources) {
              rules.push(`iptables -A INPUT -p tcp --dport ${port} -s ${src} -j ACCEPT -m comment --comment "microseg-${service}"`);
            }
          } else {
            rules.push(`iptables -A INPUT -p tcp --dport ${port} -j ACCEPT -m comment --comment "microseg-${service}"`);
          }
        }

        if (denyAll) {
          for (const port of allowPorts) {
            rules.push(`iptables -A INPUT -p tcp --dport ${port} -j DROP -m comment --comment "microseg-${service}-deny"`);
          }
        }

        if (dryRun) {
          return {
            content: [formatToolOutput({
              dryRun: true,
              service,
              rules,
              warnings: safety.warnings,
            })],
          };
        }

        const results: { rule: string; success: boolean; error?: string }[] = [];
        for (const rule of rules) {
          const parts = rule.split(/\s+/);
          const result = await executeCommand({
            command: parts[0],
            args: parts.slice(1),
            timeout: 10000,
          });
          results.push({ rule, success: result.exitCode === 0, error: result.exitCode !== 0 ? result.stderr : undefined });
        }

        const entry = createChangeEntry({
          tool: "configure_microsegmentation",
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
  );
}
