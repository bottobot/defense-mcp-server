/**
 * Advanced container security tools.
 *
 * Tools: generate_seccomp_profile, apply_apparmor_container,
 *        setup_rootless_containers, scan_image_trivy
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeCommand } from "../core/executor.js";
import { createErrorContent, formatToolOutput } from "../core/parsers.js";
import { logChange, createChangeEntry } from "../core/changelog.js";
import { SafeguardRegistry } from "../core/safeguards.js";
import { writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";

export function registerContainerAdvancedTools(server: McpServer): void {

  // ── generate_seccomp_profile ───────────────────────────────────────────────

  server.tool(
    "generate_seccomp_profile",
    "Generate a custom seccomp profile JSON from a list of allowed syscalls.",
    {
      allowedSyscalls: z.array(z.string()).describe("List of syscall names to allow"),
      defaultAction: z.enum(["SCMP_ACT_ERRNO", "SCMP_ACT_KILL", "SCMP_ACT_LOG"]).optional().default("SCMP_ACT_ERRNO").describe("Default action for unlisted syscalls"),
      outputPath: z.string().optional().describe("Path to write the profile (prints to output if omitted)"),
      dryRun: z.boolean().optional().default(false).describe("Preview only"),
    },
    async ({ allowedSyscalls, defaultAction, outputPath, dryRun }) => {
      try {
        const profile = {
          defaultAction,
          architectures: ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_AARCH64"],
          syscalls: [
            {
              names: allowedSyscalls,
              action: "SCMP_ACT_ALLOW",
            },
          ],
        };

        const json = JSON.stringify(profile, null, 2);

        if (dryRun || !outputPath) {
          return {
            content: [formatToolOutput({
              dryRun: dryRun || !outputPath,
              profile,
              syscallCount: allowedSyscalls.length,
              outputPath: outputPath ?? "(stdout)",
            })],
          };
        }

        const dir = dirname(outputPath);
        if (!existsSync(dir)) {
          mkdirSync(dir, { recursive: true });
        }
        writeFileSync(outputPath, json, "utf-8");

        const entry = createChangeEntry({
          tool: "generate_seccomp_profile",
          action: "Create seccomp profile",
          target: outputPath,
          dryRun: false,
          success: true,
        });
        logChange(entry);

        return {
          content: [formatToolOutput({
            success: true,
            outputPath,
            syscallCount: allowedSyscalls.length,
            defaultAction,
          })],
        };
      } catch (err) {
        return { content: [createErrorContent(`Seccomp profile generation failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true };
      }
    }
  );

  // ── apply_apparmor_container ────────────────────────────────────────────────

  server.tool(
    "apply_apparmor_container",
    "Generate and optionally load an AppArmor profile for a container.",
    {
      profileName: z.string().describe("AppArmor profile name"),
      containerName: z.string().optional().describe("Container name for context"),
      allowNetwork: z.boolean().optional().default(true).describe("Allow network access"),
      allowWrite: z.array(z.string()).optional().default([]).describe("Writable paths"),
      dryRun: z.boolean().optional().default(true).describe("Preview only"),
    },
    async ({ profileName, containerName, allowNetwork, allowWrite, dryRun }) => {
      try {
        const writeRules = allowWrite.map((p) => `  ${p} rw,`).join("\n");
        const networkRule = allowNetwork ? "  network,\n" : "  deny network,\n";

        const profile = `#include <tunables/global>

profile ${profileName} flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

${networkRule}
  # File access
  /usr/** r,
  /etc/** r,
  /proc/** r,
  /sys/** r,
  /tmp/** rw,
${writeRules}

  # Deny sensitive paths
  deny /etc/shadow r,
  deny /etc/gshadow r,

  # Capabilities
  capability net_bind_service,
  capability setuid,
  capability setgid,
}
`;

        if (dryRun) {
          return {
            content: [formatToolOutput({
              dryRun: true,
              profileName,
              profile,
              loadCommand: `apparmor_parser -r /etc/apparmor.d/${profileName}`,
            })],
          };
        }

        const profilePath = `/etc/apparmor.d/${profileName}`;
        writeFileSync(profilePath, profile, "utf-8");

        // Load the profile
        const result = await executeCommand({
          command: "apparmor_parser",
          args: ["-r", profilePath],
          timeout: 15000,
        });

        const entry = createChangeEntry({
          tool: "apply_apparmor_container",
          action: `Create AppArmor profile ${profileName}`,
          target: profilePath,
          dryRun: false,
          success: result.exitCode === 0,
          rollbackCommand: `apparmor_parser -R ${profilePath} && rm ${profilePath}`,
        });
        logChange(entry);

        return {
          content: [formatToolOutput({
            success: result.exitCode === 0,
            profilePath,
            loaded: result.exitCode === 0,
            output: result.stdout || result.stderr,
          })],
        };
      } catch (err) {
        return { content: [createErrorContent(`AppArmor profile failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true };
      }
    }
  );

  // ── setup_rootless_containers ──────────────────────────────────────────────

  server.tool(
    "setup_rootless_containers",
    "Configure rootless container support (newuidmap/newgidmap, user namespaces).",
    {
      username: z.string().describe("Username to configure rootless containers for"),
      subuidCount: z.number().optional().default(65536).describe("Number of subordinate UIDs"),
      dryRun: z.boolean().optional().default(true).describe("Preview only"),
    },
    async ({ username, subuidCount, dryRun }) => {
      try {
        const safety = await SafeguardRegistry.getInstance().checkSafety("setup_rootless_containers", { username });

        const checks: Record<string, unknown> = {};

        // Check newuidmap
        const newuidmap = await executeCommand({ command: "which", args: ["newuidmap"], timeout: 5000 });
        checks.newuidmap = newuidmap.exitCode === 0;

        // Check newgidmap
        const newgidmap = await executeCommand({ command: "which", args: ["newgidmap"], timeout: 5000 });
        checks.newgidmap = newgidmap.exitCode === 0;

        // Check user_namespaces
        const ns = await executeCommand({ command: "sysctl", args: ["-n", "kernel.unprivileged_userns_clone"], timeout: 5000 });
        checks.userNamespacesEnabled = ns.exitCode === 0 && ns.stdout.trim() === "1";

        // Check /etc/subuid
        const subuidCheck = await executeCommand({ command: "grep", args: [username, "/etc/subuid"], timeout: 5000 });
        checks.subuidConfigured = subuidCheck.exitCode === 0;

        if (dryRun) {
          return {
            content: [formatToolOutput({
              dryRun: true,
              username,
              currentState: checks,
              commands: [
                `usermod --add-subuids 100000-${100000 + subuidCount - 1} --add-subgids 100000-${100000 + subuidCount - 1} ${username}`,
                "sysctl -w kernel.unprivileged_userns_clone=1",
              ],
              warnings: safety.warnings,
            })],
          };
        }

        const results: { step: string; success: boolean; output: string }[] = [];

        // Configure subuid/subgid
        if (!checks.subuidConfigured) {
          const r = await executeCommand({
            command: "usermod",
            args: ["--add-subuids", `100000-${100000 + subuidCount - 1}`, "--add-subgids", `100000-${100000 + subuidCount - 1}`, username],
            timeout: 10000,
          });
          results.push({ step: "Configure subuid/subgid", success: r.exitCode === 0, output: r.stderr || r.stdout });
        }

        // Enable user namespaces if needed
        if (!checks.userNamespacesEnabled) {
          const r = await executeCommand({
            command: "sysctl",
            args: ["-w", "kernel.unprivileged_userns_clone=1"],
            timeout: 10000,
          });
          results.push({ step: "Enable user namespaces", success: r.exitCode === 0, output: r.stdout });
        }

        const entry = createChangeEntry({
          tool: "setup_rootless_containers",
          action: `Configure rootless containers for ${username}`,
          target: username,
          dryRun: false,
          success: results.every((r) => r.success),
        });
        logChange(entry);

        return { content: [formatToolOutput({ username, results, checks })] };
      } catch (err) {
        return { content: [createErrorContent(`Rootless setup failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true };
      }
    }
  );

  // ── scan_image_trivy ───────────────────────────────────────────────────────

  server.tool(
    "scan_image_trivy",
    "Scan a container image for vulnerabilities using Trivy.",
    {
      image: z.string().describe("Container image to scan (e.g., nginx:latest)"),
      severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW"]).optional().default("HIGH").describe("Minimum severity to report"),
      dryRun: z.boolean().optional().default(false).describe("Preview only"),
    },
    async ({ image, severity, dryRun }) => {
      try {
        if (dryRun) {
          return {
            content: [formatToolOutput({
              dryRun: true,
              command: `trivy image --severity ${severity},CRITICAL --format json ${image}`,
            })],
          };
        }

        // Check for trivy
        const which = await executeCommand({ command: "which", args: ["trivy"], timeout: 5000 });
        if (which.exitCode !== 0) {
          return { content: [createErrorContent("Trivy not installed. Install it: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh")], isError: true };
        }

        const severities = severity === "CRITICAL" ? "CRITICAL" :
          severity === "HIGH" ? "HIGH,CRITICAL" :
          severity === "MEDIUM" ? "MEDIUM,HIGH,CRITICAL" :
          "LOW,MEDIUM,HIGH,CRITICAL";

        const result = await executeCommand({
          command: "trivy",
          args: ["image", "--severity", severities, "--format", "json", "--quiet", image],
          timeout: 300000,
        });

        if (result.exitCode !== 0 && !result.stdout.trim()) {
          return { content: [createErrorContent(`Trivy scan failed: ${result.stderr}`)], isError: true };
        }

        let report: unknown;
        try {
          report = JSON.parse(result.stdout);
        } catch {
          report = { raw: result.stdout.slice(0, 10000) };
        }

        return { content: [formatToolOutput({ image, severity, report })] };
      } catch (err) {
        return { content: [createErrorContent(`Trivy scan failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true };
      }
    }
  );
}
