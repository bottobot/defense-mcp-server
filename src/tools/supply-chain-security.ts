/**
 * Supply chain security tools.
 *
 * Registers 1 tool: supply_chain (actions: sbom, sign, verify_slsa).
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeCommand } from "../core/executor.js";
import { getConfig, getToolTimeout } from "../core/config.js";
import { createTextContent, createErrorContent, formatToolOutput } from "../core/parsers.js";
import { logChange, createChangeEntry } from "../core/changelog.js";
import { validateFilePath } from "../core/sanitizer.js";
import { detectDistro } from "../core/distro.js";
import { SafeguardRegistry } from "../core/safeguards.js";

export function registerSupplyChainSecurityTools(server: McpServer): void {

  server.tool(
    "supply_chain",
    "Supply chain security: generate SBOMs, sign artifacts with cosign, or verify SLSA provenance attestations.",
    {
      action: z.enum(["sbom", "sign", "verify_slsa"]).describe("Action: sbom=generate SBOM, sign=cosign signing, verify_slsa=verify SLSA attestation"),
      // sbom params
      path: z.string().optional().default(".").describe("Directory to scan (sbom action)"),
      format: z.enum(["cyclonedx-json", "spdx-json", "table"]).optional().default("cyclonedx-json").describe("Output format (sbom action)"),
      // sign params
      artifact: z.string().optional().describe("Image reference or file path to sign/verify (sign/verify_slsa action)"),
      keyPath: z.string().optional().describe("Path to private key, omit for keyless (sign action)"),
      // verify_slsa params
      source: z.string().optional().describe("Expected source repository URI (verify_slsa action)"),
      // shared
      dryRun: z.boolean().optional().default(false).describe("Preview only"),
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
              command: "which",
              args: ["syft"],
              timeout: 5000,
            });

            if (syftResult.exitCode === 0) {
              const result = await executeCommand({
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
              command: "which",
              args: ["cdxgen"],
              timeout: 5000,
            });

            if (cdxgenResult.exitCode === 0) {
              const result = await executeCommand({
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

            const result = await executeCommand({ command: cmd, args, timeout: 30000 });
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

            // Check for slsa-verifier
            const which = await executeCommand({ command: "which", args: ["slsa-verifier"], timeout: 5000 });

            if (which.exitCode !== 0) {
              // Try cosign verify-attestation as fallback
              const cosignWhich = await executeCommand({ command: "which", args: ["cosign"], timeout: 5000 });
              if (cosignWhich.exitCode !== 0) {
                return { content: [createErrorContent("Neither slsa-verifier nor cosign found. Install one to verify attestations.")], isError: true };
              }

              const args = ["verify-attestation", "--type", "slsaprovenance", artifact];
              const result = await executeCommand({ command: "cosign", args, timeout: 30000 });

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
