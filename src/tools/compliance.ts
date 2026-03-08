/**
 * Compliance and audit tools for Kali Defense MCP Server.
 *
 * Registers 6 tools: compliance_lynis_audit, compliance_oscap_scan,
 * compliance_check (actions: cis, framework), compliance_policy_evaluate,
 * compliance_report, compliance_cron_restrict, compliance_tmp_hardening.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeCommand } from "../core/executor.js";
import { getConfig, getToolTimeout } from "../core/config.js";
import {
  createTextContent,
  createErrorContent,
  parseLynisOutput,
  parseOscapOutput,
  formatToolOutput,
} from "../core/parsers.js";
import { logChange, createChangeEntry } from "../core/changelog.js";
import { getDistroAdapter } from "../core/distro-adapter.js";
import { sanitizeArgs, validateFilePath } from "../core/sanitizer.js";
import { existsSync, readFileSync } from "node:fs";
import {
  loadPolicy,
  evaluatePolicy,
  getBuiltinPolicies,
  type PolicyEvaluationSummary,
} from "../core/policy-engine.js";

// ── CIS Benchmark Check Helpers ────────────────────────────────────────────

interface CisCheckResult {
  id: string;
  title: string;
  status: "pass" | "fail" | "warn" | "error";
  detail: string;
  level: string;
}

async function runCisCheck(
  command: string,
  args: string[],
  id: string,
  title: string,
  level: string,
  expectPattern?: RegExp
): Promise<CisCheckResult> {
  try {
    const result = await executeCommand({
      command,
      args,
      timeout: 30_000,
    });

    if (expectPattern) {
      const passed = expectPattern.test(result.stdout.trim());
      return {
        id,
        title,
        status: passed ? "pass" : "fail",
        detail: passed
          ? "Check passed"
          : `Expected pattern not found. Output: ${result.stdout.trim().slice(0, 200)}`,
        level,
      };
    }

    return {
      id,
      title,
      status: result.exitCode === 0 ? "pass" : "fail",
      detail: result.exitCode === 0
        ? "Check passed"
        : `Exit code ${result.exitCode}: ${result.stderr.trim().slice(0, 200)}`,
      level,
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { id, title, status: "error", detail: msg, level };
  }
}

async function cisFilesystemChecks(level: string): Promise<CisCheckResult[]> {
  const results: CisCheckResult[] = [];

  // CIS 1.1.2 - /tmp is a separate mount
  results.push(
    await runCisCheck("findmnt", ["-n", "/tmp"], "CIS-1.1.2", "/tmp is a separate partition", level)
  );

  // CIS 1.1.4 - /tmp has noexec (check mount output AND fstab)
  {
    const mountCheck = await executeCommand({
      command: "findmnt", args: ["-n", "-o", "OPTIONS", "/tmp"], timeout: 10_000,
    });
    const fstabCheck = await executeCommand({
      command: "sudo", args: ["grep", "-E", "^[^#].*\\s/tmp\\s.*noexec", "/etc/fstab"], timeout: 10_000,
    });
    const mountHasNoexec = /noexec/.test(mountCheck.stdout.trim());
    const fstabHasNoexec = fstabCheck.exitCode === 0;
    results.push({
      id: "CIS-1.1.4",
      title: "/tmp has noexec mount option",
      status: (mountHasNoexec || fstabHasNoexec) ? "pass" : "fail",
      detail: mountHasNoexec
        ? "Check passed"
        : fstabHasNoexec
          ? "noexec configured in fstab (will apply on next mount/reboot)"
          : `Expected pattern not found. Output: ${mountCheck.stdout.trim().slice(0, 200)}`,
      level,
    });
  }

  // CIS 1.1.21 - Sticky bit on world-writable dirs
  results.push(
    await runCisCheck(
      "find", ["/", "-xdev", "-type", "d", "-perm", "-0002", "!", "-perm", "-1000", "-print"],
      "CIS-1.1.21", "Sticky bit set on world-writable directories", level, /^$/
    )
  );

  // CIS 1.4.1 - ASLR enabled
  results.push(
    await runCisCheck("sysctl", ["-n", "kernel.randomize_va_space"], "CIS-1.4.1", "ASLR enabled", level, /^2$/)
  );

  // CIS 1.1.22 - Automounting disabled (autofs should NOT be active)
  {
    const autofs = await executeCommand({
      command: "systemctl",
      args: ["is-active", "autofs"],
      timeout: 10_000,
    });
    results.push({
      id: "CIS-1.1.22",
      title: "Automounting (autofs) is disabled",
      status: autofs.stdout.trim() !== "active" ? "pass" : "fail",
      detail: autofs.stdout.trim() === "active"
        ? "autofs service is running — should be disabled"
        : "autofs service is not active",
      level,
    });
  }

  // CIS 1.5.1 - Core dump limits (hard core 0 in limits.conf or limits.d/)
  {
    const limitsCheck = await executeCommand({
      command: "sudo",
      args: ["grep", "-rE", "\\*\\s+hard\\s+core\\s+0", "/etc/security/limits.conf", "/etc/security/limits.d/"],
      timeout: 10_000,
    });
    results.push({
      id: "CIS-1.5.1-limits",
      title: "Core dumps restricted via limits.conf (hard core 0)",
      status: limitsCheck.exitCode === 0 ? "pass" : "fail",
      detail: limitsCheck.exitCode === 0
        ? "Check passed"
        : `hard core 0 not found in limits.conf or limits.d/`,
      level,
    });
  }

  return results;
}

async function cisServicesChecks(level: string): Promise<CisCheckResult[]> {
  const results: CisCheckResult[] = [];

  // Check unnecessary services are not running
  const unnecessaryServices = ["avahi-daemon", "cups", "rpcbind", "telnet.socket"];

  for (const svc of unnecessaryServices) {
    const result = await executeCommand({
      command: "systemctl",
      args: ["is-active", svc],
      timeout: 10_000,
    });

    results.push({
      id: `CIS-2.x-${svc}`,
      title: `Unnecessary service '${svc}' is disabled`,
      status: result.stdout.trim() === "inactive" || result.exitCode !== 0 ? "pass" : "fail",
      detail: result.stdout.trim() === "active" ? `Service ${svc} is running` : `Service ${svc} is not active`,
      level,
    });
  }

  // CIS 2.2.1 - NTP/Chrony time synchronization is active
  {
    const chronyd = await executeCommand({
      command: "systemctl",
      args: ["is-active", "chronyd"],
      timeout: 10_000,
    });
    const ntpSvc = await executeCommand({
      command: "systemctl",
      args: ["is-active", "ntp"],
      timeout: 10_000,
    });
    const isActive = chronyd.stdout.trim() === "active" || ntpSvc.stdout.trim() === "active";
    results.push({
      id: "CIS-2.2.1",
      title: "Time synchronization (chrony/ntp) is active",
      status: isActive ? "pass" : "fail",
      detail: isActive
        ? "Time synchronization service is running"
        : "Neither chronyd nor ntp service is active",
      level,
    });
  }

  return results;
}

async function cisNetworkChecks(level: string): Promise<CisCheckResult[]> {
  const results: CisCheckResult[] = [];

  // CIS 3.1.1 - IP forwarding disabled
  results.push(
    await runCisCheck("sysctl", ["-n", "net.ipv4.ip_forward"], "CIS-3.1.1", "IP forwarding disabled", level, /^0$/)
  );

  // CIS 3.2.2 - ICMP redirects disabled
  results.push(
    await runCisCheck(
      "sysctl", ["-n", "net.ipv4.conf.all.accept_redirects"],
      "CIS-3.2.2", "ICMP redirects not accepted", level, /^0$/
    )
  );

  // CIS 3.2.1 - Source routing disabled
  results.push(
    await runCisCheck(
      "sysctl", ["-n", "net.ipv4.conf.all.accept_source_route"],
      "CIS-3.2.1", "Source routed packets not accepted", level, /^0$/
    )
  );

  // CIS 3.2.8 - TCP SYN cookies
  results.push(
    await runCisCheck("sysctl", ["-n", "net.ipv4.tcp_syncookies"], "CIS-3.2.8", "TCP SYN cookies enabled", level, /^1$/)
  );

  return results;
}

async function cisLoggingChecks(level: string): Promise<CisCheckResult[]> {
  const results: CisCheckResult[] = [];

  // CIS 4.1.1.1 - auditd active
  results.push(
    await runCisCheck("systemctl", ["is-active", "auditd"], "CIS-4.1.1.1", "auditd service is active", level, /^active$/)
  );

  // CIS 4.2.1.1 - rsyslog active
  results.push(
    await runCisCheck("systemctl", ["is-active", "rsyslog"], "CIS-4.2.1.1", "rsyslog service is active", level, /^active$/)
  );

  // Check log file permissions (distro-aware path)
  const daComp = await getDistroAdapter();
  results.push(
    await runCisCheck(
      "stat", ["-c", "%a", daComp.paths.syslog],
      "CIS-4.2.4", "Syslog file has restrictive permissions", level, /^(640|600)$/
    )
  );

  // CIS 4.1.1.3 - GRUB audit param (audit=1 in kernel cmdline)
  results.push(
    await runCisCheck(
      "grep", ["audit=1", "/proc/cmdline"],
      "CIS-4.1.1.3", "Kernel boot parameter audit=1 is set", level
    )
  );

  return results;
}

async function cisAccessChecks(level: string): Promise<CisCheckResult[]> {
  const results: CisCheckResult[] = [];

  // CIS 5.2.10 - SSH PermitRootLogin
  results.push(
    await runCisCheck(
      "grep", ["-i", "^PermitRootLogin", "/etc/ssh/sshd_config"],
      "CIS-5.2.10", "SSH root login disabled", level, /PermitRootLogin\s+no/i
    )
  );

  // CIS 5.2.4 - SSH Protocol 2
  // GAP-20 FIX: Modern OpenSSH (>= 7.6) removed the Protocol directive and
  // always uses Protocol 2. Instead of grepping for a deprecated directive,
  // verify OpenSSH version >= 7.6 and mark as pass.
  {
    let sshStatus: "pass" | "fail" | "warn" | "error" = "pass";
    let sshDetail = "Protocol 2 is enforced by default in OpenSSH 7.6+; directive deprecated";
    try {
      const sshVersionResult = await executeCommand({
        command: "ssh",
        args: ["-V"],
        timeout: 10_000,
      });
      // ssh -V outputs to stderr typically
      const versionOutput = (sshVersionResult.stderr + " " + sshVersionResult.stdout).trim();
      const versionMatch = versionOutput.match(/OpenSSH[_\s](\d+)\.(\d+)/i);
      if (versionMatch) {
        const major = parseInt(versionMatch[1], 10);
        const minor = parseInt(versionMatch[2], 10);
        if (major > 7 || (major === 7 && minor >= 6)) {
          sshStatus = "pass";
          sshDetail = `PASS (deprecated — Protocol 2 enforced by default in OpenSSH ${major}.${minor})`;
        } else {
          // Old OpenSSH — need the explicit directive
          const protoCheck = await executeCommand({
            command: "grep",
            args: ["-i", "^Protocol", "/etc/ssh/sshd_config"],
            timeout: 10_000,
          });
          if (/Protocol\s+2/i.test(protoCheck.stdout.trim())) {
            sshStatus = "pass";
            sshDetail = `Protocol 2 explicitly configured (OpenSSH ${major}.${minor})`;
          } else {
            sshStatus = "fail";
            sshDetail = `OpenSSH ${major}.${minor} requires explicit 'Protocol 2' in sshd_config`;
          }
        }
      } else {
        sshStatus = "warn";
        sshDetail = `Could not parse OpenSSH version from: ${versionOutput.slice(0, 100)}`;
      }
    } catch {
      sshStatus = "error";
      sshDetail = "Failed to determine SSH version";
    }
    results.push({
      id: "CIS-5.2.4",
      title: "SSH uses Protocol 2",
      status: sshStatus,
      detail: sshDetail,
      level,
    });
  }

  // CIS 6.1.2 - /etc/passwd permissions
  results.push(
    await runCisCheck("stat", ["-c", "%a", "/etc/passwd"], "CIS-6.1.2", "/etc/passwd permissions (644)", level, /^644$/)
  );

  // CIS 6.1.3 - /etc/shadow permissions
  results.push(
    await runCisCheck("stat", ["-c", "%a", "/etc/shadow"], "CIS-6.1.3", "/etc/shadow permissions (640 or 600)", level, /^(0|600|640)$/)
  );

  // CIS 5.4.1 - PAM password quality (minlen >= 14)
  results.push(
    await runCisCheck(
      "grep", ["-E", "^minlen", "/etc/security/pwquality.conf"],
      "CIS-5.4.1", "PAM password quality - minlen >= 14", level, /minlen\s*=\s*(1[4-9]|[2-9]\d|\d{3,})/
    )
  );

  // CIS 5.4.2 - PAM account lockout (pam_faillock configured)
  results.push(
    await runCisCheck(
      "grep", ["pam_faillock", (await getDistroAdapter()).paths.pamAuth],
      "CIS-5.4.2", "PAM account lockout (pam_faillock) is configured", level
    )
  );

  // CIS 5.5.5 - Default umask 027 or more restrictive
  // Check login.defs, /etc/profile, and /etc/bash.bashrc for umask 027 or 077
  {
    const umaskCheck = await executeCommand({
      command: "sudo",
      args: ["grep", "-rEh", "(^UMASK\\s+0[2-7]7|^umask\\s+0[2-7]7)", "/etc/login.defs", "/etc/profile", "/etc/bash.bashrc"],
      timeout: 10_000,
    });
    const hasRestrictive = /0[2-7]7/.test(umaskCheck.stdout.trim());
    results.push({
      id: "CIS-5.5.5",
      title: "Default umask is 027 or more restrictive",
      status: hasRestrictive ? "pass" : "fail",
      detail: hasRestrictive
        ? "Check passed"
        : `Restrictive umask not found in login.defs, profile, or bash.bashrc`,
      level,
    });
  }

  // CIS 5.1.8 - /etc/cron.allow exists
  {
    const cronCheck = await executeCommand({
      command: "sudo", args: ["test", "-f", "/etc/cron.allow"], timeout: 10_000,
    });
    results.push({
      id: "CIS-5.1.8",
      title: "/etc/cron.allow exists",
      status: cronCheck.exitCode === 0 ? "pass" : "fail",
      detail: cronCheck.exitCode === 0 ? "Check passed" : "/etc/cron.allow not found",
      level,
    });
  }

  // CIS 5.1.9 - /etc/at.allow exists
  {
    const atCheck = await executeCommand({
      command: "sudo", args: ["test", "-f", "/etc/at.allow"], timeout: 10_000,
    });
    results.push({
      id: "CIS-5.1.9",
      title: "/etc/at.allow exists",
      status: atCheck.exitCode === 0 ? "pass" : "fail",
      detail: atCheck.exitCode === 0 ? "Check passed" : "/etc/at.allow not found",
      level,
    });
  }

  return results;
}

async function cisSystemChecks(level: string): Promise<CisCheckResult[]> {
  const results: CisCheckResult[] = [];

  // CIS 1.5.1 - Core dumps restricted
  results.push(
    await runCisCheck(
      "sysctl", ["-n", "fs.suid_dumpable"],
      "CIS-1.5.1", "Core dumps restricted for SUID programs", level, /^0$/
    )
  );

  // CIS 1.4.1 - ASLR
  results.push(
    await runCisCheck("sysctl", ["-n", "kernel.randomize_va_space"], "CIS-1.6.2", "ASLR enabled", level, /^2$/)
  );

  // Check for login banner
  const bannerResult = await executeCommand({
    command: "cat",
    args: ["/etc/issue"],
    timeout: 10_000,
  });

  results.push({
    id: "CIS-1.7.1",
    title: "Login warning banner configured",
    status: bannerResult.stdout.trim().length > 0 ? "pass" : "warn",
    detail: bannerResult.stdout.trim().length > 0
      ? "Login banner is configured"
      : "No login banner found in /etc/issue",
    level,
  });

  return results;
}

// ── Registration entry point ───────────────────────────────────────────────

export function registerComplianceTools(server: McpServer): void {
  // ── 1. compliance_lynis_audit ───────────────────────────────────────

  server.tool(
    "compliance_lynis_audit",
    "Run Lynis security audit for comprehensive system hardening assessment",
    {
      profile: z.string().optional().describe("Lynis profile file path"),
      test_group: z
        .string()
        .optional()
        .describe("Specific test group like 'firewall', 'ssh', 'kernel'"),
      pentest: z
        .boolean()
        .optional()
        .default(false)
        .describe("Enable pentest mode for more aggressive checks"),
      quick: z
        .boolean()
        .optional()
        .default(false)
        .describe("Run in quick mode (skip some long-running tests)"),
    },
    async ({ profile, test_group, pentest, quick }) => {
      try {
        const args: string[] = ["lynis", "audit", "system"];

        if (profile) {
          sanitizeArgs([profile]);
          args.push("--profile", profile);
        }
        if (test_group) {
          sanitizeArgs([test_group]);
          args.push("--tests-from-group", test_group);
        }
        if (pentest) {
          args.push("--pentest");
        }
        if (quick) {
          args.push("--quick");
        }

        args.push("--no-colors");

        sanitizeArgs(args);

        const result = await executeCommand({
          command: "sudo",
          args,
          toolName: "compliance_lynis_audit",
          timeout: getToolTimeout("lynis"),
        });

        // Lynis may exit with non-zero for findings, which is normal
        const findings = parseLynisOutput(result.stdout);

        // Extract hardening index
        const hardeningMatch = result.stdout.match(/Hardening index\s*:\s*(\d+)/);
        const hardeningIndex = hardeningMatch ? parseInt(hardeningMatch[1], 10) : null;

        const warnings = findings.filter((f) => f.severity === "warning");
        const suggestions = findings.filter((f) => f.severity === "suggestion");

        const output = {
          hardeningIndex,
          totalFindings: findings.length,
          warnings: warnings.length,
          suggestions: suggestions.length,
          warningList: warnings,
          suggestionList: suggestions,
          raw: result.stdout,
        };

        return { content: [formatToolOutput(output)] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 2. compliance_oscap_scan ────────────────────────────────────────

  server.tool(
    "compliance_oscap_scan",
    "Run OpenSCAP compliance scan against XCCDF security profiles",
    {
      profile: z
        .string()
        .optional()
        .default("xccdf_org.ssgproject.content_profile_standard")
        .describe("XCCDF profile ID for the scan"),
      content: z
        .string()
        .optional()
        .describe("Path to SCAP content DS file (auto-detected if omitted)"),
      results_file: z
        .string()
        .optional()
        .describe("Path to save XML results"),
      report_file: z
        .string()
        .optional()
        .describe("Path to save HTML report"),
    },
    async ({ profile, content, results_file, report_file }) => {
      try {
        // Auto-detect SCAP content if not provided
        let contentPath = content;
        if (!contentPath) {
          const candidates = [
            "/usr/share/xml/scap/ssg/content/ssg-debian12-ds.xml",
            "/usr/share/xml/scap/ssg/content/ssg-debian11-ds.xml",
            "/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml",
            "/usr/share/xml/scap/ssg/content/ssg-ubuntu2004-ds.xml",
            "/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml",
            "/usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml",
          ];

          for (const candidate of candidates) {
            const checkResult = await executeCommand({
              command: "test",
              args: ["-f", candidate],
              timeout: 5_000,
            });
            if (checkResult.exitCode === 0) {
              contentPath = candidate;
              break;
            }
          }

          if (!contentPath) {
            return {
              content: [createErrorContent(
                "No SCAP content file found. Install scap-security-guide: sudo apt install ssg-debian\n" +
                "Or specify the content path explicitly."
              )],
              isError: true,
            };
          }
        }

        const args: string[] = ["oscap", "xccdf", "eval", "--profile", profile];

        if (results_file) {
          sanitizeArgs([results_file]);
          args.push("--results", results_file);
        }
        if (report_file) {
          sanitizeArgs([report_file]);
          args.push("--report", report_file);
        }

        args.push(contentPath);

        sanitizeArgs(args);

        const result = await executeCommand({
          command: "sudo",
          args,
          toolName: "compliance_oscap_scan",
          timeout: getToolTimeout("oscap"),
        });

        // oscap exits with 2 for failures found (not actual error)
        if (result.exitCode !== 0 && result.exitCode !== 2) {
          return {
            content: [createErrorContent(`oscap scan failed (exit ${result.exitCode}): ${result.stderr}`)],
            isError: true,
          };
        }

        const parsed = parseOscapOutput(result.stdout);
        const passed = parsed.filter((r) => r.result === "pass").length;
        const failed = parsed.filter((r) => r.result === "fail").length;
        const notApplicable = parsed.filter((r) => r.result.includes("notapplicable")).length;

        const output = {
          profile,
          contentFile: contentPath,
          totalRules: parsed.length,
          passed,
          failed,
          notApplicable,
          compliancePercent: parsed.length > 0 ? Math.round((passed / parsed.length) * 100) : 0,
          resultsFile: results_file ?? "not saved",
          reportFile: report_file ?? "not saved",
          failedRules: parsed.filter((r) => r.result === "fail"),
          raw: result.stdout,
        };

        return { content: [formatToolOutput(output)] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 3. compliance_check (merged: cis + framework) ───────────────────

  server.tool(
    "compliance_check",
    "Run compliance checks: CIS benchmark checks or framework-specific checks (PCI-DSS, HIPAA, SOC2, ISO 27001, GDPR).",
    {
      action: z.enum(["cis", "framework"]).describe("Action: cis=CIS benchmark checks, framework=compliance framework check"),
      // cis params
      section: z.enum(["filesystem", "services", "network", "logging", "access", "system", "all"]).optional().default("all").describe("CIS benchmark section to check (cis action)"),
      level: z.enum(["1", "2"]).optional().default("1").describe("CIS benchmark level (cis action)"),
      // framework params
      framework: z.enum(["pci-dss-v4", "hipaa", "soc2", "iso27001", "gdpr"]).optional().describe("Compliance framework (framework action)"),
      dryRun: z.boolean().optional().default(true).describe("Preview only (framework action)"),
    },
    async (params) => {
      const { action } = params;

      switch (action) {
        case "cis": {
          const { section, level } = params;
          try {
            let results: CisCheckResult[] = [];

            const sections = section === "all"
              ? ["filesystem", "services", "network", "logging", "access", "system"]
              : [section];

            for (const sec of sections) {
              switch (sec) {
                case "filesystem":
                  results = results.concat(await cisFilesystemChecks(level));
                  break;
                case "services":
                  results = results.concat(await cisServicesChecks(level));
                  break;
                case "network":
                  results = results.concat(await cisNetworkChecks(level));
                  break;
                case "logging":
                  results = results.concat(await cisLoggingChecks(level));
                  break;
                case "access":
                  results = results.concat(await cisAccessChecks(level));
                  break;
                case "system":
                  results = results.concat(await cisSystemChecks(level));
                  break;
              }
            }

            const passCount = results.filter((r) => r.status === "pass").length;
            const failCount = results.filter((r) => r.status === "fail").length;
            const warnCount = results.filter((r) => r.status === "warn").length;
            const errorCount = results.filter((r) => r.status === "error").length;

            const output = {
              cisLevel: level,
              sections: sections,
              totalChecks: results.length,
              summary: { pass: passCount, fail: failCount, warn: warnCount, error: errorCount },
              compliancePercent: results.length > 0 ? Math.round((passCount / results.length) * 100) : 0,
              results,
            };

            return { content: [formatToolOutput(output)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(msg)], isError: true };
          }
        }

        case "framework": {
          const { framework, dryRun } = params;
          try {
            if (!framework) {
              return { content: [createErrorContent("framework is required for framework action")], isError: true };
            }

            type Framework = "pci-dss-v4" | "hipaa" | "soc2" | "iso27001" | "gdpr";

            interface ComplianceCheckItem {
              id: string;
              description: string;
              check: () => Promise<{ passed: boolean; detail: string; evidence?: string }>;
            }

            async function runSysctlCheckLocal(key: string, expected: string): Promise<{ passed: boolean; detail: string }> {
              const r = await executeCommand({ command: "sysctl", args: ["-n", key], timeout: 5000 });
              const actual = r.stdout.trim();
              return { passed: actual === expected, detail: `${key} = ${actual} (expected: ${expected})` };
            }

            async function serviceInactiveLocal(svc: string): Promise<{ passed: boolean; detail: string }> {
              const r = await executeCommand({ command: "systemctl", args: ["is-active", svc], timeout: 5000 });
              const active = r.stdout.trim() === "active";
              return { passed: !active, detail: `${svc}: ${r.stdout.trim()}` };
            }

            function filePermCheckLocal(filePath: string, maxPerm: string): { passed: boolean; detail: string } {
              try {
                const { statSync } = require("node:fs");
                const stat = statSync(filePath);
                const mode = (stat.mode & 0o777).toString(8);
                return { passed: parseInt(mode, 8) <= parseInt(maxPerm, 8), detail: `${filePath}: ${mode} (max: ${maxPerm})` };
              } catch {
                return { passed: false, detail: `${filePath}: unable to check` };
              }
            }

            function getFrameworkChecks(fw: Framework): ComplianceCheckItem[] {
              const commonChecks: ComplianceCheckItem[] = [
                { id: "AUTH-001", description: "Ensure no empty passwords in /etc/shadow", check: async () => { const r = await executeCommand({ command: "awk", args: ["-F:", '($2 == "" ) { print $1 }', "/etc/shadow"], timeout: 5000 }); return { passed: r.stdout.trim().length === 0, detail: r.stdout.trim() || "No empty passwords" }; } },
                { id: "NET-001", description: "IP forwarding disabled", check: async () => runSysctlCheckLocal("net.ipv4.ip_forward", "0") },
                { id: "NET-002", description: "SYN cookies enabled", check: async () => runSysctlCheckLocal("net.ipv4.tcp_syncookies", "1") },
                { id: "KERN-001", description: "ASLR fully enabled", check: async () => runSysctlCheckLocal("kernel.randomize_va_space", "2") },
                { id: "KERN-002", description: "dmesg access restricted", check: async () => runSysctlCheckLocal("kernel.dmesg_restrict", "1") },
                { id: "FS-001", description: "/etc/passwd permissions ≤ 644", check: async () => filePermCheckLocal("/etc/passwd", "644") },
                { id: "FS-002", description: "/etc/shadow permissions ≤ 640", check: async () => filePermCheckLocal("/etc/shadow", "640") },
                { id: "SVC-001", description: "Telnet service disabled", check: async () => serviceInactiveLocal("telnet.socket") },
                { id: "SSH-001", description: "SSH root login disabled", check: async () => { try { const content = readFileSync("/etc/ssh/sshd_config", "utf-8"); const match = content.match(/^\s*PermitRootLogin\s+(\S+)/m); const value = match?.[1] ?? "not set"; return { passed: value === "no" || value === "prohibit-password", detail: `PermitRootLogin: ${value}` }; } catch { return { passed: false, detail: "Unable to read sshd_config" }; } } },
              ];

              const frameworkSpecific: Record<Framework, ComplianceCheckItem[]> = {
                "pci-dss-v4": [
                  { id: "PCI-1.1", description: "Firewall rules present", check: async () => { const r = await executeCommand({ command: "iptables", args: ["-L", "-n"], timeout: 10000 }); const hasRules = r.stdout.split("\n").length > 8; return { passed: hasRules, detail: `${r.stdout.split("\n").length} iptables lines` }; } },
                  { id: "PCI-8.2", description: "Password minimum length configured", check: async () => { try { const content = readFileSync("/etc/security/pwquality.conf", "utf-8"); const match = content.match(/minlen\s*=\s*(\d+)/); const len = match ? parseInt(match[1]) : 0; return { passed: len >= 12, detail: `minlen = ${len} (required: ≥12)` }; } catch { return { passed: false, detail: "pwquality.conf not found" }; } } },
                ],
                hipaa: [
                  { id: "HIPAA-164.312a", description: "Audit logging enabled (auditd)", check: async () => { const r = await executeCommand({ command: "systemctl", args: ["is-active", "auditd"], timeout: 5000 }); return { passed: r.stdout.trim() === "active", detail: `auditd: ${r.stdout.trim()}` }; } },
                ],
                soc2: [
                  { id: "SOC2-CC6.1", description: "System monitoring enabled", check: async () => { const r = await executeCommand({ command: "systemctl", args: ["is-active", "auditd"], timeout: 5000 }); return { passed: r.stdout.trim() === "active", detail: `auditd: ${r.stdout.trim()}` }; } },
                ],
                iso27001: [
                  { id: "ISO-A.12.4.1", description: "Event logging active", check: async () => { const rsyslog = await executeCommand({ command: "systemctl", args: ["is-active", "rsyslog"], timeout: 5000 }); const journald = await executeCommand({ command: "systemctl", args: ["is-active", "systemd-journald"], timeout: 5000 }); const active = rsyslog.stdout.trim() === "active" || journald.stdout.trim() === "active"; return { passed: active, detail: `rsyslog: ${rsyslog.stdout.trim()}, journald: ${journald.stdout.trim()}` }; } },
                ],
                gdpr: [
                  { id: "GDPR-Art32", description: "Encryption capabilities available", check: async () => { const r = await executeCommand({ command: "which", args: ["openssl"], timeout: 5000 }); return { passed: r.exitCode === 0, detail: r.exitCode === 0 ? "openssl available" : "openssl not found" }; } },
                ],
              };

              return [...commonChecks, ...(frameworkSpecific[fw] ?? [])];
            }

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
                results.push({ id: check.id, description: check.description, passed: false, detail: `Check error: ${err instanceof Error ? err.message : String(err)}` });
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
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`Compliance check failed: ${msg}`)], isError: true };
          }
        }

        default:
          return { content: [createErrorContent(`Unknown action: ${action}`)], isError: true };
      }
    }
  );

  // ── 4. compliance_policy_evaluate ───────────────────────────────────

  server.tool(
    "compliance_policy_evaluate",
    "Evaluate a compliance policy set (built-in or custom) against the current system",
    {
      policy_name: z
        .string()
        .optional()
        .describe("Built-in policy name (use without policy_path)"),
      policy_path: z
        .string()
        .optional()
        .describe("Path to custom policy JSON file"),
    },
    async ({ policy_name, policy_path }) => {
      try {
        if (!policy_name && !policy_path) {
          // List available policies
          const builtins = getBuiltinPolicies();
          return {
            content: [createTextContent(
              `No policy specified. Available built-in policies:\n${builtins.length > 0 ? builtins.map((p) => `  - ${p}`).join("\n") : "  (none found)"}\n\nProvide policy_name or policy_path to evaluate.`
            )],
          };
        }

        let policyFilePath: string;
        if (policy_path) {
          sanitizeArgs([policy_path]);
          policyFilePath = policy_path;
        } else {
          const config = getConfig();
          policyFilePath = `${config.policyDir}/${policy_name}.json`;
        }

        const policySet = loadPolicy(policyFilePath);
        const evaluation = await evaluatePolicy(policySet);

        const output = {
          policyName: evaluation.policyName,
          totalRules: evaluation.totalRules,
          passed: evaluation.passed,
          failed: evaluation.failed,
          errors: evaluation.errors,
          compliancePercent: evaluation.compliancePercent,
          results: evaluation.results.map((r) => ({
            id: r.rule.id,
            title: r.rule.title,
            severity: r.rule.severity,
            passed: r.passed,
            message: r.message,
            actual: r.actual.slice(0, 200),
          })),
        };

        return { content: [formatToolOutput(output)] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 5. compliance_report ────────────────────────────────────────────

  server.tool(
    "compliance_report",
    "Generate a comprehensive compliance summary report combining multiple check sources",
    {
      format: z
        .enum(["text", "json", "markdown"])
        .optional()
        .default("text")
        .describe("Output format for the report"),
      include_lynis: z
        .boolean()
        .optional()
        .default(true)
        .describe("Include Lynis quick scan results"),
      include_cis: z
        .boolean()
        .optional()
        .default(true)
        .describe("Include CIS benchmark check results"),
      include_policy: z
        .boolean()
        .optional()
        .default(false)
        .describe("Include custom policy evaluation results"),
      policy_name: z
        .string()
        .optional()
        .describe("Policy name to include (required if include_policy is true)"),
    },
    async ({ format, include_lynis, include_cis, include_policy, policy_name }) => {
      try {
        const report: {
          timestamp: string;
          overallScore: number;
          sections: Array<{
            name: string;
            score: number;
            details: unknown;
          }>;
        } = {
          timestamp: new Date().toISOString(),
          overallScore: 0,
          sections: [],
        };

        let totalScore = 0;
        let sectionCount = 0;

        // ── Lynis section ──
        if (include_lynis) {
          try {
            const lynisResult = await executeCommand({
              command: "sudo",
              args: ["lynis", "audit", "system", "--quick", "--no-colors"],
              toolName: "compliance_report",
              timeout: getToolTimeout("lynis"),
            });

            const findings = parseLynisOutput(lynisResult.stdout);
            const hardeningMatch = lynisResult.stdout.match(/Hardening index\s*:\s*(\d+)/);
            const hardeningIndex = hardeningMatch ? parseInt(hardeningMatch[1], 10) : 0;

            report.sections.push({
              name: "Lynis Security Audit",
              score: hardeningIndex,
              details: {
                hardeningIndex,
                warnings: findings.filter((f) => f.severity === "warning").length,
                suggestions: findings.filter((f) => f.severity === "suggestion").length,
                topWarnings: findings.filter((f) => f.severity === "warning").slice(0, 5),
              },
            });

            totalScore += hardeningIndex;
            sectionCount++;
          } catch {
            report.sections.push({
              name: "Lynis Security Audit",
              score: 0,
              details: { error: "Lynis not available or failed to run. Install with: sudo apt install lynis" },
            });
          }
        }

        // ── CIS section ──
        if (include_cis) {
          try {
            let cisResults: CisCheckResult[] = [];

            cisResults = cisResults.concat(await cisFilesystemChecks("1"));
            cisResults = cisResults.concat(await cisNetworkChecks("1"));
            cisResults = cisResults.concat(await cisLoggingChecks("1"));
            cisResults = cisResults.concat(await cisAccessChecks("1"));
            cisResults = cisResults.concat(await cisSystemChecks("1"));
            cisResults = cisResults.concat(await cisServicesChecks("1"));

            const passCount = cisResults.filter((r) => r.status === "pass").length;
            const cisScore = cisResults.length > 0
              ? Math.round((passCount / cisResults.length) * 100)
              : 0;

            report.sections.push({
              name: "CIS Benchmark Checks",
              score: cisScore,
              details: {
                totalChecks: cisResults.length,
                passed: passCount,
                failed: cisResults.filter((r) => r.status === "fail").length,
                warned: cisResults.filter((r) => r.status === "warn").length,
                errors: cisResults.filter((r) => r.status === "error").length,
                failedChecks: cisResults.filter((r) => r.status === "fail"),
              },
            });

            totalScore += cisScore;
            sectionCount++;
          } catch {
            report.sections.push({
              name: "CIS Benchmark Checks",
              score: 0,
              details: { error: "CIS checks failed to run" },
            });
          }
        }

        // ── Policy section ──
        if (include_policy && policy_name) {
          try {
            const config = getConfig();
            const policyPath = `${config.policyDir}/${policy_name}.json`;
            const policySet = loadPolicy(policyPath);
            const evaluation = await evaluatePolicy(policySet);

            report.sections.push({
              name: `Policy: ${evaluation.policyName}`,
              score: evaluation.compliancePercent,
              details: {
                totalRules: evaluation.totalRules,
                passed: evaluation.passed,
                failed: evaluation.failed,
                errors: evaluation.errors,
                failedRules: evaluation.results
                  .filter((r) => !r.passed)
                  .map((r) => ({
                    id: r.rule.id,
                    title: r.rule.title,
                    severity: r.rule.severity,
                    message: r.message,
                  })),
              },
            });

            totalScore += evaluation.compliancePercent;
            sectionCount++;
          } catch {
            report.sections.push({
              name: `Policy: ${policy_name}`,
              score: 0,
              details: { error: `Policy '${policy_name}' not found or failed to evaluate` },
            });
          }
        }

        // Calculate overall score
        report.overallScore = sectionCount > 0
          ? Math.round(totalScore / sectionCount)
          : 0;

        // Format output
        if (format === "json") {
          return { content: [formatToolOutput(report)] };
        }

        if (format === "markdown") {
          let md = `# Compliance Report\n\n`;
          md += `**Generated:** ${report.timestamp}\n`;
          md += `**Overall Score:** ${report.overallScore}/100\n\n`;

          for (const section of report.sections) {
            md += `## ${section.name}\n\n`;
            md += `**Score:** ${section.score}/100\n\n`;
            md += `\`\`\`json\n${JSON.stringify(section.details, null, 2)}\n\`\`\`\n\n`;
          }

          return { content: [createTextContent(md)] };
        }

        // Text format
        let text = `${"=".repeat(60)}\n`;
        text += `  COMPLIANCE REPORT\n`;
        text += `  Generated: ${report.timestamp}\n`;
        text += `  Overall Score: ${report.overallScore}/100\n`;
        text += `${"=".repeat(60)}\n\n`;

        for (const section of report.sections) {
          text += `${"─".repeat(50)}\n`;
          text += `  ${section.name} — Score: ${section.score}/100\n`;
          text += `${"─".repeat(50)}\n`;
          text += `${JSON.stringify(section.details, null, 2)}\n\n`;
        }

        return { content: [createTextContent(text)] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 6. compliance_cron_restrict ─────────────────────────────────────
  // GAP-21: Tool to create/manage cron.allow and at.allow files

  server.tool(
    "compliance_cron_restrict",
    "Create and manage /etc/cron.allow and /etc/at.allow to restrict cron/at access (CIS 5.1.8, 5.1.9)",
    {
      action: z
        .enum(["create_allow_files", "status"])
        .describe("Action: create_allow_files to create allow lists, status to check current state"),
      allowed_users: z
        .array(z.string())
        .optional()
        .default(["root"])
        .describe("Users to include in cron.allow and at.allow (default: ['root'])"),
      dry_run: z
        .boolean()
        .optional()
        .default(true)
        .describe("Preview changes without applying them"),
    },
    async ({ action, allowed_users, dry_run }) => {
      try {
        const usernamePattern = /^[a-z_][a-z0-9_-]{0,31}$/;
        const changes: string[] = [];

        if (action === "status") {
          // Check existence and contents of all 4 files
          const files = ["/etc/cron.allow", "/etc/cron.deny", "/etc/at.allow", "/etc/at.deny"];
          const statusResults: Array<{ file: string; exists: boolean; contents: string }> = [];

          for (const f of files) {
            const existCheck = await executeCommand({
              command: "test",
              args: ["-f", f],
              timeout: 5_000,
            });
            let contents = "";
            if (existCheck.exitCode === 0) {
              const catResult = await executeCommand({
                command: "sudo",
                args: ["cat", f],
                timeout: 5_000,
              });
              contents = catResult.stdout.trim();
            }
            statusResults.push({
              file: f,
              exists: existCheck.exitCode === 0,
              contents,
            });
          }

          const output = {
            action: "status",
            files: statusResults,
            recommendation: "cron.allow and at.allow should exist with only authorized users. cron.deny and at.deny should be removed when allow files are present.",
          };

          return { content: [formatToolOutput(output)] };
        }

        // action === "create_allow_files"
        // Validate usernames
        for (const user of allowed_users) {
          if (!usernamePattern.test(user)) {
            return {
              content: [createErrorContent(`Invalid username '${user}': must match ${usernamePattern}`)],
              isError: true,
            };
          }
        }

        const userListContent = allowed_users.join("\\n");

        if (dry_run) {
          const output = {
            action: "create_allow_files",
            dry_run: true,
            planned_changes: [
              `Create /etc/cron.allow with users: ${allowed_users.join(", ")}`,
              `Create /etc/at.allow with users: ${allowed_users.join(", ")}`,
              "Set permissions 600 on both files",
              "Set ownership root:root on both files",
              "Remove /etc/cron.deny if it exists",
              "Remove /etc/at.deny if it exists",
            ],
            allowed_users,
          };
          return { content: [formatToolOutput(output)] };
        }

        // Create /etc/cron.allow
        await executeCommand({
          command: "sudo",
          args: ["tee", "/etc/cron.allow"],
          stdin: allowed_users.join("\n") + "\n",
          timeout: 10_000,
        });
        changes.push("Created /etc/cron.allow");

        // Create /etc/at.allow
        await executeCommand({
          command: "sudo",
          args: ["tee", "/etc/at.allow"],
          stdin: allowed_users.join("\n") + "\n",
          timeout: 10_000,
        });
        changes.push("Created /etc/at.allow");

        // Set permissions
        await executeCommand({
          command: "sudo",
          args: ["chmod", "600", "/etc/cron.allow", "/etc/at.allow"],
          timeout: 10_000,
        });
        changes.push("Set permissions 600 on /etc/cron.allow and /etc/at.allow");

        // Set ownership
        await executeCommand({
          command: "sudo",
          args: ["chown", "root:root", "/etc/cron.allow", "/etc/at.allow"],
          timeout: 10_000,
        });
        changes.push("Set ownership root:root on /etc/cron.allow and /etc/at.allow");

        // Remove deny files if they exist
        const cronDenyExists = await executeCommand({
          command: "test",
          args: ["-f", "/etc/cron.deny"],
          timeout: 5_000,
        });
        if (cronDenyExists.exitCode === 0) {
          await executeCommand({
            command: "sudo",
            args: ["rm", "-f", "/etc/cron.deny"],
            timeout: 10_000,
          });
          changes.push("Removed /etc/cron.deny (allow-list supersedes)");
        }

        const atDenyExists = await executeCommand({
          command: "test",
          args: ["-f", "/etc/at.deny"],
          timeout: 5_000,
        });
        if (atDenyExists.exitCode === 0) {
          await executeCommand({
            command: "sudo",
            args: ["rm", "-f", "/etc/at.deny"],
            timeout: 10_000,
          });
          changes.push("Removed /etc/at.deny (allow-list supersedes)");
        }

        // Log changes
        logChange(createChangeEntry({
          tool: "compliance_cron_restrict",
          action: "create_allow_files",
          target: "/etc/cron.allow, /etc/at.allow",
          after: changes.join("; "),
          dryRun: false,
          success: true,
        }));

        const output = {
          action: "create_allow_files",
          dry_run: false,
          allowed_users,
          changes,
          cis_checks_addressed: ["CIS-5.1.8 (cron.allow)", "CIS-5.1.9 (at.allow)"],
        };

        return { content: [formatToolOutput(output)] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 7. compliance_tmp_hardening ─────────────────────────────────────
  // GAP-31: Tool to audit and apply /tmp mount hardening (CIS 1.1.4)

  // GAP-31: Tool to audit and apply /tmp mount hardening (CIS 1.1.4)

  server.tool(
    "compliance_tmp_hardening",
    "Audit and apply /tmp mount hardening with nodev,nosuid,noexec options (CIS 1.1.4)",
    {
      action: z
        .enum(["audit", "apply"])
        .describe("Action: audit to check current /tmp mount options, apply to harden"),
      mount_options: z
        .string()
        .optional()
        .default("nodev,nosuid,noexec")
        .describe("Mount options to apply (default: 'nodev,nosuid,noexec')"),
      dry_run: z
        .boolean()
        .optional()
        .default(true)
        .describe("Preview changes without applying them"),
    },
    async ({ action, mount_options, dry_run }) => {
      try {
        if (action === "audit") {
          // Check current mount options for /tmp
          const mountResult = await executeCommand({
            command: "findmnt",
            args: ["-n", "-o", "SOURCE,TARGET,FSTYPE,OPTIONS", "/tmp"],
            timeout: 10_000,
          });

          // Check /etc/fstab for /tmp entry
          const fstabResult = await executeCommand({
            command: "grep",
            args: ["/tmp", "/etc/fstab"],
            timeout: 10_000,
          });

          const currentOptions = mountResult.stdout.trim();
          const fstabEntry = fstabResult.stdout.trim();

          const hasNodev = /nodev/.test(currentOptions);
          const hasNosuid = /nosuid/.test(currentOptions);
          const hasNoexec = /noexec/.test(currentOptions);

          const output = {
            action: "audit",
            tmp_mounted: mountResult.exitCode === 0,
            current_mount_info: currentOptions || "Not mounted or not found",
            fstab_entry: fstabEntry || "No /tmp entry in /etc/fstab",
            options_present: {
              nodev: hasNodev,
              nosuid: hasNosuid,
              noexec: hasNoexec,
            },
            compliant: hasNodev && hasNosuid && hasNoexec,
            cis_check: "CIS-1.1.4",
          };

          return { content: [formatToolOutput(output)] };
        }

        // action === "apply"
        // Validate mount_options
        if (!/^[a-z,]+$/.test(mount_options)) {
          return {
            content: [createErrorContent(
              `Invalid mount_options '${mount_options}': must contain only lowercase letters and commas`
            )],
            isError: true,
          };
        }

        const changes: string[] = [];

        if (dry_run) {
          // Check if /tmp line exists in fstab
          const fstabCheck = await executeCommand({
            command: "grep",
            args: ["-c", "/tmp", "/etc/fstab"],
            timeout: 5_000,
          });
          const hasFstabEntry = fstabCheck.exitCode === 0 && parseInt(fstabCheck.stdout.trim(), 10) > 0;

          const output = {
            action: "apply",
            dry_run: true,
            planned_changes: [
              "Backup /etc/fstab to /etc/fstab.bak.compliance",
              hasFstabEntry
                ? `Update existing /tmp entry in /etc/fstab with options: defaults,${mount_options}`
                : `Add new /tmp entry to /etc/fstab: tmpfs /tmp tmpfs defaults,${mount_options} 0 0`,
              "Remount /tmp with new options",
            ],
            mount_options,
          };
          return { content: [formatToolOutput(output)] };
        }

        // Backup /etc/fstab
        await executeCommand({
          command: "sudo",
          args: ["cp", "-p", "/etc/fstab", "/etc/fstab.bak.compliance"],
          timeout: 10_000,
        });
        changes.push("Backed up /etc/fstab to /etc/fstab.bak.compliance");

        // Check if /tmp line exists in fstab
        const fstabCheck = await executeCommand({
          command: "grep",
          args: ["-c", "/tmp", "/etc/fstab"],
          timeout: 5_000,
        });
        const hasFstabEntry = fstabCheck.exitCode === 0 && parseInt(fstabCheck.stdout.trim(), 10) > 0;

        if (hasFstabEntry) {
          // Update existing /tmp entry — replace its options
          await executeCommand({
            command: "sudo",
            args: [
              "sed", "-i",
              `s|^\\([^#]*\\s\\+/tmp\\s\\+\\S\\+\\s\\+\\)\\S\\+|\\1defaults,${mount_options}|`,
              "/etc/fstab",
            ],
            timeout: 10_000,
          });
          changes.push(`Updated /tmp mount options in /etc/fstab to: defaults,${mount_options}`);
        } else {
          // Add new /tmp line
          const fstabLine = `tmpfs /tmp tmpfs defaults,${mount_options} 0 0`;
          await executeCommand({
            command: "sudo",
            args: ["tee", "-a", "/etc/fstab"],
            stdin: fstabLine + "\n",
            timeout: 10_000,
          });
          changes.push(`Added /tmp entry to /etc/fstab: ${fstabLine}`);
        }

        // Remount /tmp
        const remountResult = await executeCommand({
          command: "sudo",
          args: ["mount", "-o", "remount", "/tmp"],
          timeout: 15_000,
        });

        if (remountResult.exitCode === 0) {
          changes.push("Remounted /tmp with new options");
        } else {
          changes.push(`Warning: remount /tmp returned exit code ${remountResult.exitCode}: ${remountResult.stderr.trim().slice(0, 200)}`);
        }

        // Verify
        const verifyResult = await executeCommand({
          command: "findmnt",
          args: ["-n", "-o", "OPTIONS", "/tmp"],
          timeout: 10_000,
        });

        // Log changes
        logChange(createChangeEntry({
          tool: "compliance_tmp_hardening",
          action: "apply",
          target: "/tmp mount options, /etc/fstab",
          after: changes.join("; "),
          dryRun: false,
          success: true,
        }));

        const output = {
          action: "apply",
          dry_run: false,
          mount_options,
          changes,
          current_mount_options: verifyResult.stdout.trim(),
          cis_check: "CIS-1.1.4",
        };

        return { content: [formatToolOutput(output)] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

}
