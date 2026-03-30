/**
 * Supply chain security tools.
 *
 * Registers 1 tool: supply_chain (actions: sbom, sign, verify_slsa).
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeCommand } from "../core/executor.js";
import { getToolTimeout } from "../core/config.js";
import { createErrorContent, formatToolOutput } from "../core/parsers.js";
import { logChange, createChangeEntry } from "../core/changelog.js";
import { detectDistro } from "../core/distro.js";
import { SafeguardRegistry } from "../core/safeguards.js";

// ── TOOL-025 remediation: supply chain input validation ────────────────────

/**
 * Validate a registry URL.
 * Must be a valid URL and must use HTTPS.
 */
function validateRegistryUrl(url: string): string {
  if (!url || typeof url !== "string") {
    throw new Error("Registry URL must be a non-empty string");
  }

  const trimmed = url.trim();

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error(`Invalid registry URL: '${trimmed}'. Must be a valid URL.`);
  }

  if (parsed.protocol !== "https:") {
    throw new Error(
      `Registry URL must use HTTPS. Got: '${parsed.protocol}'. Reject insecure HTTP connections.`
    );
  }

  return trimmed;
}

export function registerSupplyChainSecurityTools(server: McpServer): void {

  server.tool(
    "supply_chain",
    "Supply chain: SBOM generation, cosign artifact signing, SLSA provenance verification",
    {
      action: z.enum(["sbom", "sign", "verify_slsa"]).describe("Supply chain security action"),
      // sbom params
      path: z.string().optional().default(".").describe("Directory to scan"),
      format: z.enum(["cyclonedx-json", "spdx-json", "table"]).optional().default("cyclonedx-json").describe("SBOM output format"),
      // sign params
      artifact: z.string().optional().describe("Image reference or file path to sign/verify"),
      keyPath: z.string().optional().describe("Path to private key, omit for keyless"),
      // verify_slsa params
      source: z.string().optional().describe("Expected source repository URI"),
      // shared
      dryRun: z.boolean().optional().default(true).describe("Preview only"),
    },
    async (params) => {
      const { action } = params;

      switch (action) {
        // ── sbom ────────────────────────────────────────────────────
        case "sbom": {
          const { path: scanPath, format } = params;
          try {
            // Try syft first
            const syftResult = await executeCommand({
              toolName: "supply_chain",
              command: "which",
              args: ["syft"],
              timeout: 5000,
            });

            if (syftResult.exitCode === 0) {
              const result = await executeCommand({
                toolName: "supply_chain",
                command: "syft",
                args: [scanPath, "-o", format],
                timeout: getToolTimeout("generate_sbom"),
              });
              if (result.exitCode === 0) {
                return { content: [formatToolOutput({ tool: "syft", format, output: result.stdout.slice(0, 50000) })] };
              }
            }

            // Try cdxgen
            const cdxgenResult = await executeCommand({
              toolName: "supply_chain",
              command: "which",
              args: ["cdxgen"],
              timeout: 5000,
            });

            if (cdxgenResult.exitCode === 0) {
              const result = await executeCommand({
                toolName: "supply_chain",
                command: "cdxgen",
                args: ["-o", "-", scanPath],
                timeout: getToolTimeout("generate_sbom"),
              });
              if (result.exitCode === 0) {
                return { content: [formatToolOutput({ tool: "cdxgen", output: result.stdout.slice(0, 50000) })] };
              }
            }

            // Fallback: dpkg or rpm
            const distro = await detectDistro();
            let cmd: string;
            let args: string[];

            if (distro.family === "debian") {
              cmd = "dpkg-query";
              args = ["-W", "-f", "${Package}\t${Version}\t${Architecture}\n"];
            } else if (distro.family === "rhel") {
              cmd = "rpm";
              args = ["-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"];
            } else {
              return { content: [createErrorContent("No SBOM tool (syft/cdxgen) found and unsupported package manager for fallback")], isError: true };
            }

            const result = await executeCommand({ toolName: "supply_chain", command: cmd, args, timeout: 30000 });
            if (result.exitCode !== 0) {
              return { content: [createErrorContent(`Package listing failed: ${result.stderr}`)], isError: true };
            }

            const packages = result.stdout.trim().split("\n").map((line) => {
              const [name, version, arch] = line.split("\t");
              return { name, version, arch };
            });

            return {
              content: [formatToolOutput({
                tool: "package-manager-fallback",
                packageManager: distro.packageManager,
                totalPackages: packages.length,
                packages: packages.slice(0, 200),
                truncated: packages.length > 200,
              })],
            };
          } catch (err) {
            return { content: [createErrorContent(`SBOM generation failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true };
          }
        }

        // ── sign ────────────────────────────────────────────────────
        case "sign": {
          const { artifact, keyPath, dryRun } = params;
          try {
            if (!artifact) {
              return { content: [createErrorContent("artifact is required for sign action")], isError: true };
            }

            // TOOL-025: Validate key path if provided
            if (keyPath) {
              if (keyPath.includes("..")) {
                return { content: [createErrorContent("Key path contains forbidden traversal sequence (..).")], isError: true };
              }
            }

            const safety = await SafeguardRegistry.getInstance().checkSafety("cosign_signing", { artifact });
            if (!safety.safe) {
              return { content: [formatToolOutput({ blocked: true, ...safety })], isError: true };
            }

            if (dryRun) {
              const cmd = keyPath
                ? `cosign sign --key ${keyPath} ${artifact}`
                : `cosign sign --yes ${artifact}`;
              return { content: [formatToolOutput({ dryRun: true, command: cmd, warnings: safety.warnings })] };
            }

            const args = keyPath
              ? ["sign", "--key", keyPath, artifact]
              : ["sign", "--yes", artifact];

            const result = await executeCommand({
              toolName: "supply_chain",
              command: "cosign",
              args,
              timeout: 60000,
            });

            const entry = createChangeEntry({
              tool: "supply_chain",
              action: "sign artifact",
              target: artifact,
              dryRun: false,
              success: result.exitCode === 0,
              error: result.exitCode !== 0 ? result.stderr : undefined,
            });
            logChange(entry);

            return {
              content: [formatToolOutput({
                exitCode: result.exitCode,
                stdout: result.stdout,
                stderr: result.stderr,
                signed: result.exitCode === 0,
              })],
            };
          } catch (err) {
            return { content: [createErrorContent(`Cosign signing failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true };
          }
        }

        // ── verify_slsa ─────────────────────────────────────────────
        case "verify_slsa": {
          const { artifact, source } = params;
          try {
            if (!artifact) {
              return { content: [createErrorContent("artifact is required for verify_slsa action")], isError: true };
            }

            // TOOL-025: Validate source URL if provided (must be HTTPS)
            if (source) {
              validateRegistryUrl(source);
            }

            // Check for slsa-verifier
            const which = await executeCommand({ toolName: "supply_chain", command: "which", args: ["slsa-verifier"], timeout: 5000 });

            if (which.exitCode !== 0) {
              // Try cosign verify-attestation as fallback
              const cosignWhich = await executeCommand({ toolName: "supply_chain", command: "which", args: ["cosign"], timeout: 5000 });
              if (cosignWhich.exitCode !== 0) {
                return { content: [createErrorContent("Neither slsa-verifier nor cosign found. Install one to verify attestations.")], isError: true };
              }

              const args = ["verify-attestation", "--type", "slsaprovenance", artifact];
              const result = await executeCommand({ toolName: "supply_chain", command: "cosign", args, timeout: 30000 });

              return {
                content: [formatToolOutput({
                  tool: "cosign verify-attestation",
                  artifact,
                  verified: result.exitCode === 0,
                  output: result.stdout.slice(0, 10000),
                  errors: result.stderr || undefined,
                })],
              };
            }

            const args = ["verify-artifact", artifact];
            if (source) {
              args.push("--source-uri", source);
            }

            const result = await executeCommand({
              toolName: "supply_chain",
              command: "slsa-verifier",
              args,
              timeout: 30000,
            });

            return {
              content: [formatToolOutput({
                tool: "slsa-verifier",
                artifact,
                source: source ?? "not specified",
                verified: result.exitCode === 0,
                output: result.stdout.slice(0, 10000),
                errors: result.stderr || undefined,
              })],
            };
          } catch (err) {
            return { content: [createErrorContent(`SLSA verification failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true };
          }
        }

        default:
          return { content: [createErrorContent(`Unknown action: ${action}`)], isError: true };
      }
    }
  );
}
