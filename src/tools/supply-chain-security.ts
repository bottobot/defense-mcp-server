/**
 * Supply chain security tools.
 *
 * Tools: generate_sbom, verify_package_integrity, setup_cosign_signing,
 *        check_slsa_attestation
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

  // ── generate_sbom ──────────────────────────────────────────────────────────

  server.tool(
    "generate_sbom",
    "Generate a Software Bill of Materials (SBOM) for the system or a directory. Uses syft, cdxgen, or falls back to dpkg/rpm listing.",
    {
      path: z.string().optional().default(".").describe("Directory to scan"),
      format: z.enum(["cyclonedx-json", "spdx-json", "table"]).optional().default("cyclonedx-json").describe("Output format"),
      dryRun: z.boolean().optional().default(false).describe("Preview only, no changes"),
    },
    async ({ path: scanPath, format, dryRun }) => {
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
  );

  // ── verify_package_integrity ───────────────────────────────────────────────

  server.tool(
    "verify_package_integrity",
    "Verify checksums of installed packages using debsums (Debian) or rpm -V (RHEL).",
    {
      packageName: z.string().optional().describe("Specific package to verify (all if omitted)"),
      dryRun: z.boolean().optional().default(false).describe("Preview only"),
    },
    async ({ packageName, dryRun }) => {
      try {
        const distro = await detectDistro();
        let cmd: string;
        let args: string[];

        if (distro.family === "debian") {
          cmd = "debsums";
          args = packageName ? ["-s", packageName] : ["-s"];
        } else if (distro.family === "rhel") {
          cmd = "rpm";
          args = packageName ? ["-V", packageName] : ["-Va"];
        } else {
          return { content: [createErrorContent("Package integrity verification requires Debian (debsums) or RHEL (rpm -V)")], isError: true };
        }

        const result = await executeCommand({
          command: cmd,
          args,
          timeout: getToolTimeout("debsums"),
        });

        const modified = result.stdout.trim().split("\n").filter(Boolean);

        return {
          content: [formatToolOutput({
            tool: cmd,
            packageName: packageName ?? "all",
            exitCode: result.exitCode,
            modifiedFiles: modified.length,
            findings: modified.slice(0, 100),
            status: result.exitCode === 0 ? "PASS — all checksums match" : "WARN — modified files detected",
          })],
        };
      } catch (err) {
        return { content: [createErrorContent(`Integrity check failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true };
      }
    }
  );

  // ── setup_cosign_signing ───────────────────────────────────────────────────

  server.tool(
    "setup_cosign_signing",
    "Sign a container image or artifact using cosign (keyless or with a key).",
    {
      artifact: z.string().describe("Image reference or file path to sign"),
      keyPath: z.string().optional().describe("Path to private key (omit for keyless)"),
      dryRun: z.boolean().optional().default(true).describe("Preview only"),
    },
    async ({ artifact, keyPath, dryRun }) => {
      try {
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
          tool: "setup_cosign_signing",
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
  );

  // ── check_slsa_attestation ─────────────────────────────────────────────────

  server.tool(
    "check_slsa_attestation",
    "Verify SLSA provenance attestation for a binary or artifact.",
    {
      artifact: z.string().describe("Path or image reference to verify"),
      source: z.string().optional().describe("Expected source repository URI"),
      dryRun: z.boolean().optional().default(false).describe("Preview only"),
    },
    async ({ artifact, source, dryRun }) => {
      try {
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
  );
}
