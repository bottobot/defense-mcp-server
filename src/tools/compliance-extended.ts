/**
 * Extended compliance framework tools.
 *
 * Tools: run_compliance_check
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeCommand } from "../core/executor.js";
import { createErrorContent, formatToolOutput } from "../core/parsers.js";
import { SafeguardRegistry } from "../core/safeguards.js";
import { existsSync, readFileSync } from "node:fs";

type Framework = "pci-dss-v4" | "hipaa" | "soc2" | "iso27001" | "gdpr";

interface ComplianceCheck {
  id: string;
  description: string;
  check: () => Promise<{ passed: boolean; detail: string; evidence?: string }>;
}

async function runSysctlCheck(key: string, expected: string): Promise<{ passed: boolean; detail: string }> {
  const r = await executeCommand({ command: "sysctl", args: ["-n", key], timeout: 5000 });
  const actual = r.stdout.trim();
  return { passed: actual === expected, detail: `${key} = ${actual} (expected: ${expected})` };
}

async function serviceInactive(svc: string): Promise<{ passed: boolean; detail: string }> {
  const r = await executeCommand({ command: "systemctl", args: ["is-active", svc], timeout: 5000 });
  const active = r.stdout.trim() === "active";
  return { passed: !active, detail: `${svc}: ${r.stdout.trim()}` };
}

function filePermCheck(filePath: string, maxPerm: string): { passed: boolean; detail: string } {
  try {
    const { statSync } = require("node:fs");
    const stat = statSync(filePath);
    const mode = (stat.mode & 0o777).toString(8);
    return { passed: parseInt(mode, 8) <= parseInt(maxPerm, 8), detail: `${filePath}: ${mode} (max: ${maxPerm})` };
  } catch {
    return { passed: false, detail: `${filePath}: unable to check` };
  }
}

function getFrameworkChecks(framework: Framework): ComplianceCheck[] {
  const commonChecks: ComplianceCheck[] = [
    {
      id: "AUTH-001",
      description: "Ensure no empty passwords in /etc/shadow",
      check: async () => {
        const r = await executeCommand({ command: "awk", args: ["-F:", "($2 == \"\" ) { print $1 }", "/etc/shadow"], timeout: 5000 });
        return { passed: r.stdout.trim().length === 0, detail: r.stdout.trim() || "No empty passwords" };
      },
    },
    {
      id: "NET-001",
      description: "IP forwarding disabled",
      check: async () => runSysctlCheck("net.ipv4.ip_forward", "0"),
    },
    {
      id: "NET-002",
      description: "SYN cookies enabled",
      check: async () => runSysctlCheck("net.ipv4.tcp_syncookies", "1"),
    },
    {
      id: "KERN-001",
      description: "ASLR fully enabled",
      check: async () => runSysctlCheck("kernel.randomize_va_space", "2"),
    },
    {
      id: "KERN-002",
      description: "dmesg access restricted",
      check: async () => runSysctlCheck("kernel.dmesg_restrict", "1"),
    },
    {
      id: "FS-001",
      description: "/etc/passwd permissions ≤ 644",
      check: async () => filePermCheck("/etc/passwd", "644"),
    },
    {
      id: "FS-002",
      description: "/etc/shadow permissions ≤ 640",
      check: async () => filePermCheck("/etc/shadow", "640"),
    },
    {
      id: "SVC-001",
      description: "Telnet service disabled",
      check: async () => serviceInactive("telnet.socket"),
    },
    {
      id: "SSH-001",
      description: "SSH root login disabled",
      check: async () => {
        try {
          const content = readFileSync("/etc/ssh/sshd_config", "utf-8");
          const match = content.match(/^\s*PermitRootLogin\s+(\S+)/m);
          const value = match?.[1] ?? "not set";
          return { passed: value === "no" || value === "prohibit-password", detail: `PermitRootLogin: ${value}` };
        } catch {
          return { passed: false, detail: "Unable to read sshd_config" };
        }
      },
    },
  ];

  const frameworkSpecific: Record<Framework, ComplianceCheck[]> = {
    "pci-dss-v4": [
      {
        id: "PCI-1.1",
        description: "Firewall rules present",
        check: async () => {
          const r = await executeCommand({ command: "iptables", args: ["-L", "-n"], timeout: 10000 });
          const hasRules = r.stdout.split("\n").length > 8;
          return { passed: hasRules, detail: `${r.stdout.split("\n").length} iptables lines` };
        },
      },
      {
        id: "PCI-8.2",
        description: "Password minimum length configured",
        check: async () => {
          try {
            const content = readFileSync("/etc/security/pwquality.conf", "utf-8");
            const match = content.match(/minlen\s*=\s*(\d+)/);
            const len = match ? parseInt(match[1]) : 0;
            return { passed: len >= 12, detail: `minlen = ${len} (required: ≥12)` };
          } catch {
            return { passed: false, detail: "pwquality.conf not found" };
          }
        },
      },
    ],
    hipaa: [
      {
        id: "HIPAA-164.312a",
        description: "Audit logging enabled (auditd)",
        check: async () => {
          const r = await executeCommand({ command: "systemctl", args: ["is-active", "auditd"], timeout: 5000 });
          return { passed: r.stdout.trim() === "active", detail: `auditd: ${r.stdout.trim()}` };
        },
      },
    ],
    soc2: [
      {
        id: "SOC2-CC6.1",
        description: "System monitoring enabled",
        check: async () => {
          const r = await executeCommand({ command: "systemctl", args: ["is-active", "auditd"], timeout: 5000 });
          return { passed: r.stdout.trim() === "active", detail: `auditd: ${r.stdout.trim()}` };
        },
      },
    ],
    iso27001: [
      {
        id: "ISO-A.12.4.1",
        description: "Event logging active",
        check: async () => {
          const rsyslog = await executeCommand({ command: "systemctl", args: ["is-active", "rsyslog"], timeout: 5000 });
          const journald = await executeCommand({ command: "systemctl", args: ["is-active", "systemd-journald"], timeout: 5000 });
          const active = rsyslog.stdout.trim() === "active" || journald.stdout.trim() === "active";
          return { passed: active, detail: `rsyslog: ${rsyslog.stdout.trim()}, journald: ${journald.stdout.trim()}` };
        },
      },
    ],
    gdpr: [
      {
        id: "GDPR-Art32",
        description: "Encryption capabilities available",
        check: async () => {
          const r = await executeCommand({ command: "which", args: ["openssl"], timeout: 5000 });
          return { passed: r.exitCode === 0, detail: r.exitCode === 0 ? "openssl available" : "openssl not found" };
        },
      },
    ],
  };

  return [...commonChecks, ...(frameworkSpecific[framework] ?? [])];
}

export function registerComplianceExtendedTools(server: McpServer): void {

  server.tool(
    "run_compliance_check",
    "Run compliance checks against a specified framework (PCI-DSS v4, HIPAA, SOC2, ISO 27001, GDPR).",
    {
      framework: z.enum(["pci-dss-v4", "hipaa", "soc2", "iso27001", "gdpr"]).describe("Compliance framework"),
      dryRun: z.boolean().optional().default(false).describe("Preview only"),
    },
    async ({ framework, dryRun }) => {
      try {
        if (dryRun) {
          const checks = getFrameworkChecks(framework);
          return {
            content: [formatToolOutput({
              dryRun: true,
              framework,
              checksCount: checks.length,
              checkIds: checks.map((c) => ({ id: c.id, description: c.description })),
            })],
          };
        }

        const checks = getFrameworkChecks(framework);
        const results: { id: string; description: string; passed: boolean; detail: string }[] = [];

        for (const check of checks) {
          try {
            const result = await check.check();
            results.push({ id: check.id, description: check.description, ...result });
          } catch (err) {
            results.push({
              id: check.id,
              description: check.description,
              passed: false,
              detail: `Check error: ${err instanceof Error ? err.message : String(err)}`,
            });
          }
        }

        const passed = results.filter((r) => r.passed).length;
        const failed = results.filter((r) => !r.passed).length;
        const score = Math.round((passed / results.length) * 100);

        return {
          content: [formatToolOutput({
            framework,
            totalChecks: results.length,
            passed,
            failed,
            score,
            rating: score >= 80 ? "COMPLIANT" : score >= 60 ? "PARTIALLY_COMPLIANT" : "NON_COMPLIANT",
            results,
          })],
        };
      } catch (err) {
        return { content: [createErrorContent(`Compliance check failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true };
      }
    }
  );
}
