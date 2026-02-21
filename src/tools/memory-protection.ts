/**
 * Memory protection tools.
 *
 * Tools: audit_memory_protections, enforce_aslr, report_exploit_mitigations
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeCommand } from "../core/executor.js";
import { getToolTimeout } from "../core/config.js";
import { createErrorContent, formatToolOutput } from "../core/parsers.js";
import { logChange, createChangeEntry } from "../core/changelog.js";
import { SafeguardRegistry } from "../core/safeguards.js";
import { readFileSync, existsSync } from "node:fs";

export function registerMemoryProtectionTools(server: McpServer): void {

  // ── audit_memory_protections ───────────────────────────────────────────────

  server.tool(
    "audit_memory_protections",
    "Audit memory protections: ASLR, PIE, RELRO, NX, stack canary on specified binaries.",
    {
      binaries: z.array(z.string()).optional().describe("List of binary paths to check (defaults to common system binaries)"),
      dryRun: z.boolean().optional().default(false).describe("Preview only"),
    },
    async ({ binaries, dryRun }) => {
      try {
        const findings: Record<string, unknown>[] = [];

        // Check ASLR
        let aslrStatus = "unknown";
        try {
          if (existsSync("/proc/sys/kernel/randomize_va_space")) {
            const val = readFileSync("/proc/sys/kernel/randomize_va_space", "utf-8").trim();
            aslrStatus = val === "2" ? "full" : val === "1" ? "partial" : val === "0" ? "disabled" : val;
          }
        } catch { /* not readable */ }

        // Default binaries to check
        const targets = binaries ?? [
          "/usr/bin/ssh", "/usr/sbin/sshd", "/usr/bin/sudo",
          "/usr/bin/passwd", "/usr/sbin/nginx", "/usr/sbin/apache2",
        ];

        for (const binary of targets) {
          if (!existsSync(binary)) {
            findings.push({ binary, status: "not found" });
            continue;
          }

          const result = await executeCommand({
            command: "readelf",
            args: ["-Wl", "-Wd", binary],
            timeout: 10000,
          });

          if (result.exitCode !== 0) {
            findings.push({ binary, status: "readelf failed", error: result.stderr.slice(0, 200) });
            continue;
          }

          const output = result.stdout;
          const pie = output.includes("Type:") && output.includes("DYN") ? "enabled" : "disabled";
          const relro = output.includes("GNU_RELRO")
            ? (output.includes("BIND_NOW") ? "full" : "partial")
            : "disabled";
          const nx = output.includes("GNU_STACK") && !output.includes("RWE") ? "enabled" : "disabled";

          // Check for stack canary via symbols
          const symResult = await executeCommand({
            command: "readelf",
            args: ["-Ws", binary],
            timeout: 10000,
          });
          const canary = symResult.stdout.includes("__stack_chk_fail") ? "enabled" : "not detected";

          findings.push({
            binary,
            pie,
            relro,
            nx,
            stackCanary: canary,
          });
        }

        return {
          content: [formatToolOutput({
            aslr: aslrStatus,
            binariesChecked: findings.length,
            findings,
          })],
        };
      } catch (err) {
        return { content: [createErrorContent(`Memory audit failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true };
      }
    }
  );

  // ── enforce_aslr ───────────────────────────────────────────────────────────

  server.tool(
    "enforce_aslr",
    "Enable full ASLR by setting kernel.randomize_va_space = 2.",
    {
      dryRun: z.boolean().optional().default(true).describe("Preview only"),
    },
    async ({ dryRun }) => {
      try {
        const safety = await SafeguardRegistry.getInstance().checkSafety("enforce_aslr", {});

        // Read current value
        let currentValue = "unknown";
        try {
          currentValue = readFileSync("/proc/sys/kernel/randomize_va_space", "utf-8").trim();
        } catch { /* not readable */ }

        if (currentValue === "2") {
          return { content: [formatToolOutput({ status: "already_enabled", currentValue: "2 (full ASLR)" })] };
        }

        if (dryRun) {
          return {
            content: [formatToolOutput({
              dryRun: true,
              currentValue,
              command: "sysctl -w kernel.randomize_va_space=2",
              warnings: safety.warnings,
            })],
          };
        }

        const result = await executeCommand({
          command: "sysctl",
          args: ["-w", "kernel.randomize_va_space=2"],
          timeout: 10000,
        });

        const entry = createChangeEntry({
          tool: "enforce_aslr",
          action: "Set ASLR to full (2)",
          target: "kernel.randomize_va_space",
          before: currentValue,
          after: "2",
          dryRun: false,
          success: result.exitCode === 0,
          rollbackCommand: `sysctl -w kernel.randomize_va_space=${currentValue}`,
          error: result.exitCode !== 0 ? result.stderr : undefined,
        });
        logChange(entry);

        return {
          content: [formatToolOutput({
            success: result.exitCode === 0,
            before: currentValue,
            after: "2",
            output: result.stdout,
          })],
        };
      } catch (err) {
        return { content: [createErrorContent(`ASLR enforcement failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true };
      }
    }
  );

  // ── report_exploit_mitigations ─────────────────────────────────────────────

  server.tool(
    "report_exploit_mitigations",
    "Report system-wide exploit mitigation status (ASLR, SMEP, SMAP, PTI, KASLR, etc.).",
    {
      dryRun: z.boolean().optional().default(false).describe("Preview only"),
    },
    async ({ dryRun }) => {
      try {
        const mitigations: Record<string, string> = {};

        // ASLR
        try {
          const val = readFileSync("/proc/sys/kernel/randomize_va_space", "utf-8").trim();
          mitigations["ASLR"] = val === "2" ? "Full (2)" : val === "1" ? "Partial (1)" : `Disabled (${val})`;
        } catch {
          mitigations["ASLR"] = "Unable to read";
        }

        // Kernel mitigations from /proc/cmdline
        try {
          const cmdline = readFileSync("/proc/cmdline", "utf-8").trim();
          mitigations["KASLR"] = cmdline.includes("nokaslr") ? "Disabled" : "Enabled (default)";
          mitigations["PTI"] = cmdline.includes("nopti") ? "Disabled" : "Enabled (default)";
          mitigations["Spectre v2"] = cmdline.includes("nospectre_v2") ? "Disabled" : "Enabled (default)";
        } catch {
          mitigations["Kernel cmdline"] = "Unable to read";
        }

        // CPU flags for hardware mitigations
        try {
          const cpuinfo = readFileSync("/proc/cpuinfo", "utf-8");
          const flags = cpuinfo.match(/^flags\s*:\s*(.*)$/m)?.[1] ?? "";
          mitigations["SMEP"] = flags.includes("smep") ? "Supported" : "Not available";
          mitigations["SMAP"] = flags.includes("smap") ? "Supported" : "Not available";
          mitigations["NX/XD"] = flags.includes("nx") ? "Supported" : "Not available";
        } catch {
          mitigations["CPU flags"] = "Unable to read";
        }

        // Kernel hardening sysctls
        const sysctlChecks: [string, string][] = [
          ["kernel.dmesg_restrict", "dmesg_restrict"],
          ["kernel.kptr_restrict", "kptr_restrict"],
          ["kernel.yama.ptrace_scope", "ptrace_scope"],
          ["kernel.unprivileged_bpf_disabled", "unprivileged_bpf"],
          ["kernel.kexec_load_disabled", "kexec_disabled"],
        ];

        for (const [key, label] of sysctlChecks) {
          const r = await executeCommand({
            command: "sysctl",
            args: ["-n", key],
            timeout: 5000,
          });
          mitigations[label] = r.exitCode === 0 ? r.stdout.trim() : "unavailable";
        }

        return { content: [formatToolOutput({ mitigations })] };
      } catch (err) {
        return { content: [createErrorContent(`Mitigation report failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true };
      }
    }
  );
}
