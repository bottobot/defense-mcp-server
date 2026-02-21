/**
 * Secrets scanning tools.
 *
 * Tools: scan_for_secrets, audit_env_vars, scan_git_history
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeCommand } from "../core/executor.js";
import { createErrorContent, formatToolOutput } from "../core/parsers.js";
import { SafeguardRegistry } from "../core/safeguards.js";

const SECRET_PATTERNS: { name: string; pattern: string }[] = [
  { name: "AWS Access Key", pattern: "AKIA[0-9A-Z]{16}" },
  { name: "AWS Secret Key", pattern: "(?i)aws_secret_access_key\\s*[=:]\\s*\\S+" },
  { name: "Private Key", pattern: "-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----" },
  { name: "GitHub Token", pattern: "gh[pousr]_[A-Za-z0-9_]{36,}" },
  { name: "Generic API Key", pattern: "(?i)(api[_-]?key|apikey)\\s*[=:]\\s*['\"]?[A-Za-z0-9_\\-]{20,}" },
  { name: "Generic Secret", pattern: "(?i)(secret|password|passwd|token)\\s*[=:]\\s*['\"]?[A-Za-z0-9_\\-!@#$%^&*]{8,}" },
  { name: "Slack Token", pattern: "xox[baprs]-[0-9]{10,}-[0-9a-zA-Z]{10,}" },
  { name: "Generic JWT", pattern: "eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}" },
];

export function registerSecretsScannerTools(server: McpServer): void {

  // ── scan_for_secrets ───────────────────────────────────────────────────────

  server.tool(
    "scan_for_secrets",
    "Scan a directory for hardcoded secrets using truffleHog, gitleaks, or built-in grep patterns.",
    {
      path: z.string().describe("Directory path to scan"),
      maxDepth: z.number().optional().default(5).describe("Maximum directory depth"),
      dryRun: z.boolean().optional().default(false).describe("Preview only"),
    },
    async ({ path: scanPath, maxDepth, dryRun }) => {
      try {
        if (dryRun) {
          return {
            content: [formatToolOutput({
              dryRun: true,
              path: scanPath,
              methods: ["truffleHog", "gitleaks", "grep-patterns"],
            })],
          };
        }

        // Try truffleHog
        const thWhich = await executeCommand({ command: "which", args: ["trufflehog"], timeout: 5000 });
        if (thWhich.exitCode === 0) {
          const result = await executeCommand({
            command: "trufflehog",
            args: ["filesystem", scanPath, "--json"],
            timeout: 120000,
          });
          const findings = result.stdout.trim().split("\n").filter(Boolean).map((l) => {
            try { return JSON.parse(l); } catch { return { raw: l }; }
          });
          return {
            content: [formatToolOutput({
              tool: "trufflehog",
              path: scanPath,
              totalFindings: findings.length,
              findings: findings.slice(0, 50),
            })],
          };
        }

        // Try gitleaks
        const glWhich = await executeCommand({ command: "which", args: ["gitleaks"], timeout: 5000 });
        if (glWhich.exitCode === 0) {
          const result = await executeCommand({
            command: "gitleaks",
            args: ["detect", "--source", scanPath, "--no-git", "--report-format", "json", "--report-path", "/dev/stdout"],
            timeout: 120000,
          });
          const findings = result.stdout.trim() ? JSON.parse(result.stdout) : [];
          return {
            content: [formatToolOutput({
              tool: "gitleaks",
              path: scanPath,
              totalFindings: Array.isArray(findings) ? findings.length : 0,
              findings: Array.isArray(findings) ? findings.slice(0, 50) : findings,
            })],
          };
        }

        // Fallback: grep-based scanning
        const findings: { pattern: string; file: string; line: string }[] = [];
        for (const { name, pattern } of SECRET_PATTERNS) {
          const result = await executeCommand({
            command: "grep",
            args: ["-rn", "-E", pattern, "--include=*.{ts,js,py,yaml,yml,json,env,conf,cfg,ini,xml,properties,toml}", "-l", scanPath],
            timeout: 30000,
          });
          if (result.exitCode === 0) {
            const files = result.stdout.trim().split("\n").filter(Boolean);
            for (const file of files.slice(0, 10)) {
              findings.push({ pattern: name, file, line: "(grep match)" });
            }
          }
        }

        return {
          content: [formatToolOutput({
            tool: "grep-patterns",
            path: scanPath,
            totalFindings: findings.length,
            findings: findings.slice(0, 50),
            note: "Install truffleHog or gitleaks for more accurate scanning",
          })],
        };
      } catch (err) {
        return { content: [createErrorContent(`Secret scan failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true };
      }
    }
  );

  // ── audit_env_vars ─────────────────────────────────────────────────────────

  server.tool(
    "audit_env_vars",
    "Audit current process environment variables for potential secrets.",
    {
      dryRun: z.boolean().optional().default(false).describe("Preview only"),
    },
    async ({ dryRun }) => {
      try {
        const suspiciousPatterns = [
          /password/i, /secret/i, /token/i, /api[_-]?key/i,
          /private[_-]?key/i, /credential/i, /auth/i,
        ];

        const suspiciousVars: { name: string; valuePreview: string }[] = [];

        for (const [key, value] of Object.entries(process.env)) {
          if (value === undefined) continue;
          const isSuspicious = suspiciousPatterns.some((p) => p.test(key));
          if (isSuspicious) {
            // Mask the value — show only first 4 chars
            const preview = value.length > 4 ? value.slice(0, 4) + "****" : "****";
            suspiciousVars.push({ name: key, valuePreview: preview });
          }
        }

        return {
          content: [formatToolOutput({
            totalEnvVars: Object.keys(process.env).length,
            suspiciousVars: suspiciousVars.length,
            findings: suspiciousVars,
            note: "Values are masked. Review the actual environment to confirm whether they contain real secrets.",
          })],
        };
      } catch (err) {
        return { content: [createErrorContent(`Env var audit failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true };
      }
    }
  );

  // ── scan_git_history ───────────────────────────────────────────────────────

  server.tool(
    "scan_git_history",
    "Scan git repository history for leaked secrets using truffleHog or gitleaks.",
    {
      repoPath: z.string().describe("Path to git repository"),
      dryRun: z.boolean().optional().default(false).describe("Preview only"),
    },
    async ({ repoPath, dryRun }) => {
      try {
        if (dryRun) {
          return {
            content: [formatToolOutput({
              dryRun: true,
              repoPath,
              methods: ["truffleHog git", "gitleaks detect"],
            })],
          };
        }

        // Try truffleHog
        const thWhich = await executeCommand({ command: "which", args: ["trufflehog"], timeout: 5000 });
        if (thWhich.exitCode === 0) {
          const result = await executeCommand({
            command: "trufflehog",
            args: ["git", `file://${repoPath}`, "--json"],
            timeout: 300000,
          });
          const findings = result.stdout.trim().split("\n").filter(Boolean).map((l) => {
            try { return JSON.parse(l); } catch { return { raw: l }; }
          });
          return {
            content: [formatToolOutput({
              tool: "trufflehog",
              repoPath,
              totalFindings: findings.length,
              findings: findings.slice(0, 50),
            })],
          };
        }

        // Try gitleaks
        const glWhich = await executeCommand({ command: "which", args: ["gitleaks"], timeout: 5000 });
        if (glWhich.exitCode === 0) {
          const result = await executeCommand({
            command: "gitleaks",
            args: ["detect", "--source", repoPath, "--report-format", "json", "--report-path", "/dev/stdout"],
            timeout: 300000,
          });
          const findings = result.stdout.trim() ? JSON.parse(result.stdout) : [];
          return {
            content: [formatToolOutput({
              tool: "gitleaks",
              repoPath,
              totalFindings: Array.isArray(findings) ? findings.length : 0,
              findings: Array.isArray(findings) ? findings.slice(0, 50) : findings,
            })],
          };
        }

        return { content: [createErrorContent("Neither truffleHog nor gitleaks found. Install one for git history scanning.")], isError: true };
      } catch (err) {
        return { content: [createErrorContent(`Git history scan failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true };
      }
    }
  );
}
