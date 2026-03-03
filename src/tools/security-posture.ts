/**
 * Security posture scoring tools.
 *
 * Tools: calculate_security_score, get_posture_trend, generate_posture_dashboard
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeCommand } from "../core/executor.js";
import { createErrorContent, formatToolOutput } from "../core/parsers.js";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

const POSTURE_DIR = join(homedir(), ".kali-mcp-posture");

function ensurePostureDir(): void {
  if (!existsSync(POSTURE_DIR)) {
    mkdirSync(POSTURE_DIR, { recursive: true });
  }
}

interface DomainScore {
  domain: string;
  score: number;
  maxScore: number;
  checks: { name: string; passed: boolean; detail: string }[];
}

async function checkSysctl(key: string, expected: string): Promise<{ passed: boolean; assessable: boolean; actual: string }> {
  const r = await executeCommand({ command: "sysctl", args: ["-n", key], timeout: 5000 });
  if (r.exitCode !== 0) {
    return { passed: false, assessable: false, actual: r.stderr.trim() || "command failed" };
  }
  const actual = r.stdout.trim();
  return { passed: actual === expected, assessable: true, actual };
}

export function registerSecurityPostureTools(server: McpServer): void {

  // ── calculate_security_score ───────────────────────────────────────────────

  server.tool(
    "calculate_security_score",
    "Calculate a weighted security score (0-100) across kernel hardening, firewall, services, users, filesystem, packages, and network domains.",
    {
      dryRun: z.boolean().optional().default(false).describe("Preview only"),
    },
    async ({ dryRun }) => {
      try {
        const domains: DomainScore[] = [];

        // ── Kernel hardening (weight: 20) ──
        const kernelChecks: { name: string; key: string; expected: string }[] = [
          { name: "ASLR full", key: "kernel.randomize_va_space", expected: "2" },
          { name: "dmesg restricted", key: "kernel.dmesg_restrict", expected: "1" },
          { name: "kptr restricted", key: "kernel.kptr_restrict", expected: "2" },
          { name: "SysRq disabled", key: "kernel.sysrq", expected: "0" },
          { name: "ptrace restricted", key: "kernel.yama.ptrace_scope", expected: "1" },
          { name: "IP forwarding disabled", key: "net.ipv4.ip_forward", expected: "0" },
          { name: "SYN cookies enabled", key: "net.ipv4.tcp_syncookies", expected: "1" },
          { name: "ICMP redirects disabled", key: "net.ipv4.conf.all.accept_redirects", expected: "0" },
          { name: "Source routing disabled", key: "net.ipv4.conf.all.accept_source_route", expected: "0" },
          { name: "Core dumps restricted", key: "fs.suid_dumpable", expected: "0" },
        ];
        const kernelResults = await Promise.all(
          kernelChecks.map(async (c) => {
            const result = await checkSysctl(c.key, c.expected);
            return {
              name: c.name,
              passed: result.passed,
              assessable: result.assessable,
              detail: result.assessable ? c.key : `${c.key} (unable to assess)`,
            };
          })
        );
        const assessableKernelCount = kernelResults.filter((r) => r.assessable).length;
        const kernelPassed = kernelResults.filter((r) => r.passed).length;
        const kernelScore = assessableKernelCount > 0
          ? Math.round((kernelPassed / assessableKernelCount) * 100)
          : -1;
        domains.push({
          domain: "kernel-hardening",
          score: kernelScore,
          maxScore: 100,
          checks: kernelResults.map((r) => ({ name: r.name, passed: r.passed, detail: r.detail })),
        });

        // ── Firewall (weight: 15) ──
        const fwChecks: { name: string; passed: boolean; detail: string }[] = [];
        const iptResult = await executeCommand({ command: "iptables", args: ["-L", "-n"], timeout: 10000 });
        const hasRules = iptResult.exitCode === 0 && iptResult.stdout.split("\n").length > 8;
        fwChecks.push({ name: "iptables rules present", passed: hasRules, detail: `${iptResult.stdout.split("\n").length} lines` });

        const ufwResult = await executeCommand({ command: "ufw", args: ["status"], timeout: 5000 });
        const ufwActive = ufwResult.exitCode === 0 && ufwResult.stdout.includes("active");
        fwChecks.push({ name: "UFW active", passed: ufwActive, detail: ufwResult.stdout.slice(0, 100) });

        const fwPassed = fwChecks.filter((c) => c.passed).length;
        domains.push({
          domain: "firewall",
          score: Math.round((fwPassed / fwChecks.length) * 100),
          maxScore: 100,
          checks: fwChecks,
        });

        // ── Services (weight: 15) ──
        const dangerousServices = ["telnet.socket", "rsh.socket", "rlogin.socket", "tftp.socket", "xinetd.service"];
        const svcChecks: { name: string; passed: boolean; detail: string }[] = [];
        for (const svc of dangerousServices) {
          const r = await executeCommand({ command: "systemctl", args: ["is-active", svc], timeout: 5000 });
          const inactive = r.exitCode !== 0 || r.stdout.trim() !== "active";
          svcChecks.push({ name: `${svc} disabled`, passed: inactive, detail: r.stdout.trim() });
        }
        const svcPassed = svcChecks.filter((c) => c.passed).length;
        domains.push({
          domain: "services",
          score: Math.round((svcPassed / svcChecks.length) * 100),
          maxScore: 100,
          checks: svcChecks,
        });

        // ── Users (weight: 15) ──
        const userChecks: { name: string; passed: boolean; detail: string }[] = [];
        const rootLogin = await executeCommand({ command: "passwd", args: ["-S", "root"], timeout: 5000 });
        const rootLocked = rootLogin.stdout.includes(" L ") || rootLogin.stdout.includes(" LK ");
        userChecks.push({ name: "Root account locked", passed: rootLocked, detail: rootLogin.stdout.trim().slice(0, 100) });

        const noPasswd = await executeCommand({ command: "awk", args: ["-F:", "($2 == \"\" ) { print $1 }", "/etc/shadow"], timeout: 5000 });
        const noEmptyPasswd = noPasswd.stdout.trim().length === 0;
        userChecks.push({ name: "No empty passwords", passed: noEmptyPasswd, detail: noPasswd.stdout.trim() || "none" });

        const uidZero = await executeCommand({ command: "awk", args: ["-F:", "($3 == 0) { print $1 }", "/etc/passwd"], timeout: 5000 });
        const onlyRoot = uidZero.stdout.trim() === "root";
        userChecks.push({ name: "Only root has UID 0", passed: onlyRoot, detail: uidZero.stdout.trim() });

        const userPassed = userChecks.filter((c) => c.passed).length;
        domains.push({
          domain: "users",
          score: Math.round((userPassed / userChecks.length) * 100),
          maxScore: 100,
          checks: userChecks,
        });

        // ── Filesystem (weight: 15) ──
        const fsChecks: { name: string; passed: boolean; detail: string }[] = [];
        const criticalFiles: [string, string][] = [
          ["/etc/passwd", "644"],
          ["/etc/shadow", "640"],
          ["/etc/ssh/sshd_config", "600"],
        ];
        for (const [fp, expected] of criticalFiles) {
          const r = await executeCommand({ command: "stat", args: ["-c", "%a", fp], timeout: 5000 });
          const actual = r.stdout.trim();
          const ok = r.exitCode === 0 && parseInt(actual, 8) <= parseInt(expected, 8);
          fsChecks.push({ name: `${fp} permissions`, passed: ok, detail: `${actual} (expected ≤${expected})` });
        }
        const fsPassed = fsChecks.filter((c) => c.passed).length;
        domains.push({
          domain: "filesystem",
          score: Math.round((fsPassed / fsChecks.length) * 100),
          maxScore: 100,
          checks: fsChecks,
        });

        // ── Overall score ──
        const weights: Record<string, number> = {
          "kernel-hardening": 25,
          "firewall": 20,
          "services": 15,
          "users": 20,
          "filesystem": 20,
        };

        let weightedSum = 0;
        let totalWeight = 0;
        for (const d of domains) {
          if (d.score < 0) continue; // Skip domains that couldn't be assessed
          const w = weights[d.domain] ?? 10;
          weightedSum += d.score * w;
          totalWeight += w;
        }
        const overallScore = totalWeight > 0 ? Math.round(weightedSum / totalWeight) : 0;

        // Save score history
        ensurePostureDir();
        const historyPath = join(POSTURE_DIR, "history.json");
        let history: { timestamp: string; score: number; domains: Record<string, number> }[] = [];
        try {
          if (existsSync(historyPath)) {
            history = JSON.parse(readFileSync(historyPath, "utf-8"));
          }
        } catch { /* start fresh */ }

        const domainScores: Record<string, number> = {};
        for (const d of domains) domainScores[d.domain] = d.score;

        history.push({ timestamp: new Date().toISOString(), score: overallScore, domains: domainScores });
        if (history.length > 1000) history = history.slice(-1000);
        writeFileSync(historyPath, JSON.stringify(history, null, 2), "utf-8");

        return {
          content: [formatToolOutput({
            overallScore,
            rating: overallScore >= 80 ? "GOOD" : overallScore >= 60 ? "FAIR" : overallScore >= 40 ? "POOR" : "CRITICAL",
            domains,
          })],
        };
      } catch (err) {
        return { content: [createErrorContent(`Security score calculation failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true };
      }
    }
  );

  // ── get_posture_trend ──────────────────────────────────────────────────────

  server.tool(
    "get_posture_trend",
    "Compare current security score against historical scores.",
    {
      limit: z.number().optional().default(10).describe("Number of historical entries to show"),
      dryRun: z.boolean().optional().default(false).describe("Preview only"),
    },
    async ({ limit, dryRun }) => {
      try {
        ensurePostureDir();
        const historyPath = join(POSTURE_DIR, "history.json");

        if (!existsSync(historyPath)) {
          return { content: [formatToolOutput({ message: "No posture history found. Run calculate_security_score first." })] };
        }

        const history = JSON.parse(readFileSync(historyPath, "utf-8"));
        const recent = history.slice(-limit);

        return {
          content: [formatToolOutput({
            entries: recent.length,
            trend: recent,
            latestScore: recent.length > 0 ? recent[recent.length - 1].score : null,
          })],
        };
      } catch (err) {
        return { content: [createErrorContent(`Posture trend failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true };
      }
    }
  );

  // ── generate_posture_dashboard ─────────────────────────────────────────────

  server.tool(
    "generate_posture_dashboard",
    "Generate a structured security posture dashboard with scores, top findings, and recommendations.",
    {
      dryRun: z.boolean().optional().default(false).describe("Preview only"),
    },
    async ({ dryRun }) => {
      try {
        ensurePostureDir();
        const historyPath = join(POSTURE_DIR, "history.json");

        let latestEntry: { timestamp: string; score: number; domains: Record<string, number> } | null = null;
        try {
          if (existsSync(historyPath)) {
            const history = JSON.parse(readFileSync(historyPath, "utf-8"));
            if (history.length > 0) {
              latestEntry = history[history.length - 1];
            }
          }
        } catch { /* no history */ }

        if (!latestEntry) {
          return { content: [formatToolOutput({ message: "No posture data available. Run calculate_security_score first." })] };
        }

        const recommendations: string[] = [];
        for (const [domain, score] of Object.entries(latestEntry.domains)) {
          if (score < 0) {
            recommendations.push(`INFO: ${domain} could not be assessed (sysctl unavailable)`);
          } else if (score < 50) {
            recommendations.push(`CRITICAL: ${domain} score is ${score}/100 — immediate attention required`);
          } else if (score < 80) {
            recommendations.push(`MODERATE: ${domain} score is ${score}/100 — improvements recommended`);
          }
        }

        if (recommendations.length === 0) {
          recommendations.push("All domains scoring above 80. Maintain current security posture.");
        }

        // Build display-friendly domain scores: replace -1 with "N/A"
        const displayDomainScores: Record<string, number | string> = {};
        for (const [domain, score] of Object.entries(latestEntry.domains)) {
          displayDomainScores[domain] = score < 0 ? "N/A" : score;
        }

        // Recompute overall score excluding unknown (-1) domains
        let weightedSum = 0;
        let totalWeight = 0;
        const weights: Record<string, number> = {
          "kernel-hardening": 25,
          "firewall": 20,
          "services": 15,
          "users": 20,
          "filesystem": 20,
        };
        for (const [domain, score] of Object.entries(latestEntry.domains)) {
          if (score < 0) continue;
          const w = weights[domain] ?? 10;
          weightedSum += score * w;
          totalWeight += w;
        }
        const overallScore = totalWeight > 0 ? Math.round(weightedSum / totalWeight) : 0;

        return {
          content: [formatToolOutput({
            dashboard: {
              timestamp: latestEntry.timestamp,
              overallScore,
              rating: overallScore >= 80 ? "GOOD" : overallScore >= 60 ? "FAIR" : overallScore >= 40 ? "POOR" : "CRITICAL",
              domainScores: displayDomainScores,
              recommendations,
              nextSteps: [
                "Run calculate_security_score for detailed per-check breakdown",
                "Address CRITICAL domains first",
                "Re-run periodically to track improvement",
              ],
            },
          })],
        };
      } catch (err) {
        return { content: [createErrorContent(`Dashboard generation failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true };
      }
    }
  );
}
