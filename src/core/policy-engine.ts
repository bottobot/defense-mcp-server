import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, basename } from "node:path";
import { z } from "zod";
import { executeCommand } from "./executor.js";
import { getConfig } from "./config.js";
import { isAllowlisted } from "./command-allowlist.js";
import { secureWriteFileSync, secureMkdirSync } from "./secure-fs.js";

/**
 * Severity levels for policy rules, aligned with common security frameworks.
 */
export type PolicySeverity = "critical" | "high" | "medium" | "low" | "info";

/**
 * A single compliance policy rule defining a check and optional remediation.
 */
export interface PolicyRule {
  /** Unique rule identifier (e.g., "CIS-1.1.1") */
  id: string;
  /** Human-readable title */
  title: string;
  /** Detailed description of what this rule checks */
  description: string;
  /** Severity of non-compliance */
  severity: PolicySeverity;
  /** Category (e.g., "filesystem", "network", "authentication") */
  category: string;
  /** Command to run to check compliance (array: [command, ...args]) */
  check: string[];
  /** Expected output pattern (regex string or exact match) */
  expectedOutput?: string;
  /** Command to remediate non-compliance (array: [command, ...args]) */
  remediation?: string[];
  /** Reference IDs (e.g., CIS benchmark, NIST control IDs) */
  references?: string[];
}

/**
 * Result of evaluating a single policy rule.
 */
export interface PolicyResult {
  /** The rule that was evaluated */
  rule: PolicyRule;
  /** Whether the system passed this check */
  passed: boolean;
  /** Actual output from the check command */
  actual: string;
  /** Human-readable result message */
  message: string;
}

/**
 * A collection of policy rules forming a compliance policy set.
 */
export interface PolicySet {
  /** Policy set name (e.g., "CIS Level 1 - Server") */
  name: string;
  /** Version of this policy set */
  version: string;
  /** Description of the policy set */
  description: string;
  /** Array of policy rules */
  rules: PolicyRule[];
}

/**
 * Summary of a policy evaluation.
 */
export interface PolicyEvaluationSummary {
  /** Policy set that was evaluated */
  policyName: string;
  /** Total number of rules */
  totalRules: number;
  /** Number of rules that passed */
  passed: number;
  /** Number of rules that failed */
  failed: number;
  /** Number of rules with errors */
  errors: number;
  /** Compliance percentage (0-100) */
  compliancePercent: number;
  /** Individual rule results */
  results: PolicyResult[];
}

// ── Zod Schemas for Policy Validation ────────────────────────────────────────

const PolicySeveritySchema = z.enum([
  "critical",
  "high",
  "medium",
  "low",
  "info",
]);

/**
 * Zod schema for a single policy rule.
 * Fields that may be absent in legacy policy files have defaults.
 */
const PolicyRuleSchema = z.object({
  id: z.string().min(1).max(128),
  title: z.string().max(256).default(""),
  description: z.string().max(1024).default(""),
  severity: PolicySeveritySchema.default("medium"),
  category: z.string().max(128).default("general"),
  check: z.array(z.string().max(1024)).min(1).max(50),
  // SECURITY (CORE-009): Limit expectedOutput regex to 200 chars to match safeRegexTest limit
  expectedOutput: z.string().max(200).optional(),
  remediation: z.array(z.string().max(1024)).min(1).max(50).optional(),
  references: z.array(z.string().max(256)).max(20).optional(),
});

/**
 * Zod schema for a complete policy set.
 */
const PolicySetSchema = z.object({
  name: z.string().min(1).max(256),
  version: z.string().max(64).default("1.0.0"),
  description: z.string().max(2048).default(""),
  rules: z.array(PolicyRuleSchema).min(1).max(200),
});

// ── Security Validation ──────────────────────────────────────────────────────

/**
 * Shell interpreters that are explicitly blocked in policy rules.
 * Even if somehow added to the command allowlist, these must never be
 * invoked by a policy rule — they would enable arbitrary command execution.
 */
const BLOCKED_INTERPRETERS = new Set([
  "sh",
  "bash",
  "zsh",
  "fish",
  "csh",
  "dash",
  "ksh",
  "tcsh",
  "/bin/sh",
  "/bin/bash",
  "/bin/zsh",
  "/bin/dash",
  "/bin/csh",
  "/bin/ksh",
  "/bin/tcsh",
  "/bin/fish",
  "/usr/bin/sh",
  "/usr/bin/bash",
  "/usr/bin/zsh",
  "/usr/bin/dash",
  "/usr/bin/csh",
  "/usr/bin/ksh",
  "/usr/bin/tcsh",
  "/usr/bin/fish",
]);

/** Control characters regex — matches dangerous non-printable characters */
const CONTROL_CHAR_RE = /[\x00-\x08\x0e-\x1f\x7f]/;

/**
 * Validates a policy rule's check (or remediation) command array.
 *
 * Security controls:
 * 1. Command (check[0]) must be in the security allowlist
 * 2. Shell interpreters are explicitly blocked (even if allowlisted)
 * 3. Arguments are checked for null bytes and control characters
 *
 * Note: Shell metacharacters (|, &, $, etc.) in arguments are NOT blocked
 * because policy rules use execFile (no shell), making these characters
 * harmless literal values. Policy rules legitimately need regex
 * metacharacters as arguments to grep/awk/sed.
 *
 * @param check The command array [command, ...args]
 * @param label Human-readable label for error messages (e.g., "check", "remediation")
 * @throws {Error} If validation fails
 */
export function validateRuleCheck(check: string[], label = "check"): void {
  if (!Array.isArray(check) || check.length === 0) {
    throw new Error(`Policy rule ${label} must be a non-empty array`);
  }

  const command = check[0];

  // Block shell interpreters explicitly — this is defense-in-depth
  // even if they were somehow added to the command allowlist
  if (BLOCKED_INTERPRETERS.has(command)) {
    throw new Error(
      `Shell interpreter '${command}' is not allowed in policy rules`
    );
  }

  // Validate command against the security allowlist
  if (!isAllowlisted(command)) {
    throw new Error(
      `Command '${command}' is not in the security allowlist`
    );
  }

  // Validate arguments for null bytes and control characters
  const args = check.slice(1);
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (typeof arg !== "string") {
      throw new Error(
        `${label} argument at index ${i + 1} is not a string`
      );
    }
    if (arg.includes("\0")) {
      throw new Error(
        `${label} argument at index ${i + 1} contains null bytes`
      );
    }
    if (CONTROL_CHAR_RE.test(arg)) {
      throw new Error(
        `${label} argument at index ${i + 1} contains control characters`
      );
    }
  }
}

/**
 * SECURITY (CORE-009): ReDoS (Regular Expression Denial of Service) protection.
 *
 * Safely tests a regex pattern against input with multiple layers of defense
 * against catastrophic backtracking:
 *
 * 1. **Length limit**: Patterns longer than 200 characters are rejected to reduce
 *    the attack surface for complex regex injection.
 * 2. **Nested quantifier detection**: Patterns like `(a+)+`, `(a*)*`, `(a+)*`
 *    are rejected because they cause exponential backtracking on non-matching
 *    input. The check uses two heuristics:
 *    - Repeated quantifiers: `a++`, `a**`, `{n,m}{` (possessive-like syntax
 *      that JavaScript doesn't support, indicating malformed patterns)
 *    - Group-level nesting: `([...]+)+` or `([...]*)*` where a quantified
 *      group is itself quantified
 * 3. **try-catch**: Invalid regex syntax is caught and reported clearly.
 *
 * These checks are applied to user-supplied `expectedOutput` regex patterns
 * in policy rules before they are compiled or executed.
 *
 * @param pattern The regex pattern string
 * @param input The string to test against
 * @returns Whether the pattern matches the input
 * @throws {Error} If the pattern is dangerous, invalid, or too long
 */
export function safeRegexTest(pattern: string, input: string): boolean {
  // 1. Reject excessively long patterns (reduced from 1024 to 200 for CORE-009)
  if (pattern.length > 200) {
    throw new Error("Regex pattern too long (max 200 characters)");
  }

  // 2a. Reject obviously dangerous patterns that cause catastrophic backtracking:
  //     - Repeated quantifiers: a++, a**, {n,m}{
  if (/(\+\+|\*\*|\{\d+,\d*\}\{)/.test(pattern)) {
    throw new Error("Regex pattern too complex (potential ReDoS)");
  }

  // 2b. Detect nested quantifiers like (a+)+, (a+)*, ([a-z]+)+
  if (/\([^)]*[+*][^)]*\)[+*{]/.test(pattern)) {
    throw new Error(
      "Regex pattern contains nested quantifiers (potential ReDoS)"
    );
  }

  // 3. Compile and execute with error handling
  try {
    const re = new RegExp(pattern, "m");
    return re.test(input);
  } catch {
    throw new Error(`Invalid regex pattern: ${pattern}`);
  }
}

// ── Core Functions ───────────────────────────────────────────────────────────

/**
 * Evaluates a single policy rule by executing its check command
 * and comparing the output against the expected pattern.
 *
 * Before execution, the check command is validated against the
 * security allowlist and shell interpreters are blocked.
 *
 * @param rule The policy rule to evaluate
 * @returns The evaluation result
 */
export async function evaluateRule(rule: PolicyRule): Promise<PolicyResult> {
  try {
    if (!rule.check || rule.check.length === 0) {
      return {
        rule,
        passed: false,
        actual: "",
        message: "Rule has no check command defined",
      };
    }

    // SECURITY: Validate command against allowlist and block shell interpreters
    validateRuleCheck(rule.check, "check");

    const [command, ...args] = rule.check;
    const result = await executeCommand({
      toolName: "_internal",
      command,
      args,
      timeout: 30_000,
    });

    const actual = result.stdout.trim();

    // If no expected output defined, passing means exit code 0
    if (!rule.expectedOutput) {
      const passed = result.exitCode === 0;
      return {
        rule,
        passed,
        actual,
        message: passed
          ? `Check passed (exit code 0)`
          : `Check failed (exit code ${result.exitCode}): ${result.stderr.trim()}`,
      };
    }

    // Use safe regex test with ReDoS protection
    let passed = false;
    try {
      passed = safeRegexTest(rule.expectedOutput, actual);
    } catch (regexErr: unknown) {
      // If regex is invalid or dangerous, try exact match as fallback
      const regexMsg =
        regexErr instanceof Error ? regexErr.message : String(regexErr);
      if (regexMsg.includes("ReDoS") || regexMsg.includes("too complex")) {
        // Don't fallback for ReDoS — that's a security issue
        return {
          rule,
          passed: false,
          actual,
          message: `Error: ${regexMsg}`,
        };
      }
      // For simple invalid regex, fall back to substring match
      passed = actual.includes(rule.expectedOutput);
    }

    return {
      rule,
      passed,
      actual,
      message: passed
        ? `Check passed: output matches expected pattern`
        : `Check failed: expected pattern "${rule.expectedOutput}" not found in output`,
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      rule,
      passed: false,
      actual: "",
      message: `Error evaluating rule: ${message}`,
    };
  }
}

/**
 * Evaluates all rules in a policy set and returns a summary.
 *
 * @param policySet The policy set to evaluate
 * @returns Evaluation summary with individual results
 */
export async function evaluatePolicy(
  policySet: PolicySet
): Promise<PolicyEvaluationSummary> {
  const results: PolicyResult[] = [];
  let passed = 0;
  let failed = 0;
  let errors = 0;

  console.error(
    `[policy-engine] Evaluating policy: ${policySet.name} (${policySet.rules.length} rules)`
  );

  for (const rule of policySet.rules) {
    const result = await evaluateRule(rule);
    results.push(result);

    if (result.passed) {
      passed++;
    } else if (result.message.startsWith("Error")) {
      errors++;
    } else {
      failed++;
    }
  }

  const totalRules = policySet.rules.length;
  const compliancePercent =
    totalRules > 0 ? Math.round((passed / totalRules) * 100) : 0;

  console.error(
    `[policy-engine] Results: ${passed}/${totalRules} passed (${compliancePercent}% compliance)`
  );

  return {
    policyName: policySet.name,
    totalRules,
    passed,
    failed,
    errors,
    compliancePercent,
    results,
  };
}

/**
 * Loads a policy set from a JSON file with strict schema validation.
 *
 * Validates:
 * 1. JSON structure via Zod schema (field types, lengths, required fields)
 * 2. All check commands against the security allowlist
 * 3. All remediation commands against the security allowlist
 *
 * @param path Absolute or relative path to the policy JSON file
 * @returns The loaded and validated policy set
 * @throws If the file cannot be read, parsed, or fails validation
 */
export function loadPolicy(path: string): PolicySet {
  const content = readFileSync(path, "utf-8");
  const parsed = JSON.parse(content);

  // Validate structure with Zod schema
  const result = PolicySetSchema.safeParse(parsed);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `${i.path.join(".")}: ${i.message}`)
      .join("; ");
    throw new Error(`Invalid policy file ${path}: ${issues}`);
  }

  const validated = result.data;

  // Validate all rule commands against the security allowlist
  for (const rule of validated.rules) {
    validateRuleCheck(rule.check, `rule ${rule.id} check`);
    if (rule.remediation) {
      validateRuleCheck(rule.remediation, `rule ${rule.id} remediation`);
    }
  }

  return validated as PolicySet;
}

/**
 * Saves a policy set to a JSON file with secure permissions.
 * Creates parent directories with owner-only permissions (0o700).
 * Files are written with owner-only permissions (0o600).
 *
 * @param path Path to save the policy file
 * @param policy The policy set to save
 */
export function savePolicy(path: string, policy: PolicySet): void {
  // SECURITY (CORE-013): Explicitly create parent directory via secure-fs
  // (0o700 permissions) instead of relying on bare mkdirSync.
  const parentDir = dirname(path);
  secureMkdirSync(parentDir);
  // Use secureWriteFileSync which writes files with 0o600
  secureWriteFileSync(path, JSON.stringify(policy, null, 2), "utf-8");
  console.error(`[policy-engine] Saved policy to ${path}`);
}

/**
 * Returns a list of built-in policy file names from the policy directory.
 * Returns empty array if the directory doesn't exist or is empty.
 */
export function getBuiltinPolicies(): string[] {
  try {
    const config = getConfig();
    const policyDir = config.policyDir;

    const files: string[] = readdirSync(policyDir) as string[];
    return files
      .filter((f: string) => f.endsWith(".json"))
      .map((f: string) => basename(f, ".json"));
  } catch {
    return [];
  }
}

/**
 * Built-in policy rule templates for common hardening checks.
 * These can be used as a starting point for custom policies.
 *
 * SECURITY: All check commands use direct binary invocation (no shell).
 * Shell interpreters (sh, bash, etc.) are never used in check or remediation arrays.
 */
export const BUILTIN_RULE_TEMPLATES: PolicyRule[] = [
  {
    id: "KERN-001",
    title: "IP forwarding disabled",
    description:
      "Ensure IP forwarding is disabled unless the system is a router",
    severity: "high",
    category: "network",
    check: ["sysctl", "-n", "net.ipv4.ip_forward"],
    expectedOutput: "^0$",
    remediation: ["sysctl", "-w", "net.ipv4.ip_forward=0"],
    references: ["CIS-3.1.1", "NIST-SC-7"],
  },
  {
    id: "KERN-002",
    title: "ICMP redirects disabled",
    description: "Ensure ICMP redirects are not accepted",
    severity: "high",
    category: "network",
    check: ["sysctl", "-n", "net.ipv4.conf.all.accept_redirects"],
    expectedOutput: "^0$",
    remediation: ["sysctl", "-w", "net.ipv4.conf.all.accept_redirects=0"],
    references: ["CIS-3.2.2", "NIST-SC-7"],
  },
  {
    id: "KERN-003",
    title: "Source routing disabled",
    description: "Ensure source routed packets are not accepted",
    severity: "high",
    category: "network",
    check: ["sysctl", "-n", "net.ipv4.conf.all.accept_source_route"],
    expectedOutput: "^0$",
    remediation: ["sysctl", "-w", "net.ipv4.conf.all.accept_source_route=0"],
    references: ["CIS-3.2.1", "NIST-SC-7"],
  },
  {
    id: "KERN-004",
    title: "SYN cookies enabled",
    description:
      "Ensure TCP SYN cookies are enabled to prevent SYN flood attacks",
    severity: "high",
    category: "network",
    check: ["sysctl", "-n", "net.ipv4.tcp_syncookies"],
    expectedOutput: "^1$",
    remediation: ["sysctl", "-w", "net.ipv4.tcp_syncookies=1"],
    references: ["CIS-3.2.8", "NIST-SC-5"],
  },
  {
    id: "AUTH-001",
    title: "Root login via SSH disabled",
    description: "Ensure root login is disabled in SSH configuration",
    severity: "critical",
    category: "authentication",
    check: ["grep", "-i", "^PermitRootLogin", "/etc/ssh/sshd_config"],
    expectedOutput: "PermitRootLogin\\s+no",
    remediation: [
      "sed",
      "-i",
      "s/^#\\?PermitRootLogin.*/PermitRootLogin no/",
      "/etc/ssh/sshd_config",
    ],
    references: ["CIS-5.2.10", "NIST-IA-2"],
  },
  {
    id: "AUTH-002",
    title: "Password authentication disabled for SSH",
    description:
      "Ensure password authentication is disabled in favor of key-based auth",
    severity: "high",
    category: "authentication",
    check: [
      "grep",
      "-i",
      "^PasswordAuthentication",
      "/etc/ssh/sshd_config",
    ],
    expectedOutput: "PasswordAuthentication\\s+no",
    references: ["CIS-5.2.12", "NIST-IA-2"],
  },
  {
    id: "FS-001",
    title: "/tmp has noexec mount option",
    description: "Ensure /tmp is mounted with noexec option",
    severity: "medium",
    category: "filesystem",
    check: ["findmnt", "-n", "-o", "OPTIONS", "/tmp"],
    expectedOutput: "noexec",
    references: ["CIS-1.1.4", "NIST-CM-6"],
  },
  {
    id: "FS-002",
    title: "Sticky bit on world-writable directories",
    description:
      "Ensure sticky bit is set on all world-writable directories",
    severity: "medium",
    category: "filesystem",
    check: [
      "find",
      "/",
      "-xdev",
      "-type",
      "d",
      "-perm",
      "-0002",
      "!",
      "-perm",
      "-1000",
      "-print",
    ],
    expectedOutput: "^$",
    references: ["CIS-1.1.21", "NIST-CM-6"],
  },
  {
    id: "SVC-001",
    title: "Firewall service active",
    description:
      "Ensure a firewall service (iptables/nftables/ufw) is running",
    severity: "critical",
    category: "services",
    check: ["systemctl", "is-active", "ufw"],
    expectedOutput: "^active$",
    references: ["CIS-3.5.1", "NIST-SC-7"],
  },
  {
    id: "SVC-002",
    title: "Auditd service active",
    description: "Ensure the audit daemon is running",
    severity: "high",
    category: "services",
    check: ["systemctl", "is-active", "auditd"],
    expectedOutput: "^active$",
    remediation: ["systemctl", "enable", "--now", "auditd"],
    references: ["CIS-4.1.1.1", "NIST-AU-2"],
  },
  {
    id: "SVC-003",
    title: "Fail2ban service active",
    description:
      "Ensure fail2ban is running to protect against brute force attacks",
    severity: "high",
    category: "services",
    check: ["systemctl", "is-active", "fail2ban"],
    expectedOutput: "^active$",
    remediation: ["systemctl", "enable", "--now", "fail2ban"],
    references: ["NIST-SI-4"],
  },
  {
    id: "PERM-001",
    title: "No world-writable files in system directories",
    description:
      "Check for world-writable files in critical system directories",
    severity: "high",
    category: "permissions",
    check: [
      "find",
      "/etc",
      "-xdev",
      "-type",
      "f",
      "-perm",
      "-0002",
      "-print",
    ],
    expectedOutput: "^$",
    references: ["CIS-6.1.10", "NIST-CM-6"],
  },
  {
    id: "PERM-002",
    title: "/etc/shadow permissions",
    description: "Ensure /etc/shadow has restrictive permissions",
    severity: "critical",
    category: "permissions",
    check: ["stat", "-c", "%a", "/etc/shadow"],
    expectedOutput: "^(0|600|640)$",
    references: ["CIS-6.1.3", "NIST-AC-3"],
  },
  {
    id: "PERM-003",
    title: "/etc/passwd permissions",
    description: "Ensure /etc/passwd has proper permissions",
    severity: "high",
    category: "permissions",
    check: ["stat", "-c", "%a", "/etc/passwd"],
    expectedOutput: "^644$",
    references: ["CIS-6.1.2", "NIST-AC-3"],
  },
  {
    id: "AUTH-003",
    title: "PAM Password Quality",
    description:
      "Ensure pam_pwquality is configured with minimum length 14. " +
      "Remediate with: access_pam_configure with module=pwquality",
    severity: "high",
    category: "authentication",
    check: ["grep", "-i", "minlen", "/etc/security/pwquality.conf"],
    expectedOutput: "minlen",
    references: ["CIS-5.3.1", "NIST-IA-5"],
  },
  {
    id: "AUTH-004",
    title: "PAM Account Lockout",
    description:
      "Ensure pam_faillock is configured for account lockout. " +
      "Remediate with: access_pam_configure with module=faillock",
    severity: "high",
    category: "authentication",
    check: ["grep", "-E", "pam_faillock", "/etc/pam.d/common-auth"],
    expectedOutput: "pam_faillock",
    references: ["CIS-5.3.2", "NIST-AC-7"],
  },
  {
    id: "AUTH-005",
    title: "Password Maximum Age",
    description:
      "Ensure password expiry is 365 days or less. " +
      "Remediate with: access_password_policy with action=set, max_days=365",
    severity: "medium",
    category: "authentication",
    check: ["grep", "-E", "^PASS_MAX_DAYS", "/etc/login.defs"],
    expectedOutput:
      "PASS_MAX_DAYS\\s+([1-9]|[1-9][0-9]|[12][0-9]{2}|3[0-5][0-9]|36[0-5])$",
    references: ["CIS-5.4.1.1", "NIST-IA-5"],
  },
  {
    id: "FS-003",
    title: "Default Umask 027",
    description:
      "Ensure default umask is 027 or more restrictive. " +
      "Remediate with: harden_umask_set with umask_value=027",
    severity: "medium",
    category: "filesystem",
    check: ["grep", "UMASK", "/etc/login.defs"],
    expectedOutput: "UMASK\\s+(027|077)",
    references: ["CIS-5.4.4", "NIST-CM-6"],
  },
  {
    id: "FS-004",
    title: "AIDE File Integrity",
    description:
      "Ensure AIDE file integrity monitoring is installed. " +
      "Remediate with: defense_install with tool=aide",
    severity: "high",
    category: "filesystem",
    check: ["which", "aide"],
    references: ["CIS-1.3.1", "NIST-SI-7"],
  },
  {
    id: "SVC-004",
    title: "Fail2Ban Active",
    description:
      "Ensure fail2ban service is running. " +
      "Remediate with: defense_install with tool=fail2ban, then enable the service",
    severity: "high",
    category: "services",
    check: ["systemctl", "is-active", "fail2ban"],
    expectedOutput: "^active$",
    remediation: ["systemctl", "enable", "--now", "fail2ban"],
    references: ["NIST-SI-4"],
  },
  {
    id: "SVC-005",
    title: "Docker Security Options Enabled",
    description:
      "Ensure Docker daemon has security options (seccomp, apparmor) enabled. " +
      "For per-container privileged mode checks, use: container_docker_bench",
    severity: "critical",
    category: "services",
    check: ["docker", "info", "--format", "{{.SecurityOptions}}"],
    expectedOutput: "seccomp",
    references: ["CIS-Docker-5.4"],
  },
  {
    id: "SVC-006",
    title: "AppArmor Enforcing",
    description:
      "Ensure AppArmor is enabled and has enforcing profiles. " +
      "Remediate with: container_apparmor_install with action=install_profiles",
    severity: "medium",
    category: "services",
    check: ["aa-enabled"],
    expectedOutput: "^Yes$",
    references: ["CIS-1.6.1.1", "NIST-AC-3"],
  },
  {
    id: "FS-005",
    title: "Core Dumps Disabled",
    description:
      "Ensure core dumps are restricted. " +
      "Remediate with: harden_coredump_disable",
    severity: "medium",
    category: "filesystem",
    check: [
      "grep",
      "-E",
      "\\*\\s+hard\\s+core\\s+0",
      "/etc/security/limits.conf",
    ],
    expectedOutput: "\\*\\s+hard\\s+core\\s+0",
    references: ["CIS-1.5.1", "NIST-CM-6"],
  },
  {
    id: "FS-006",
    title: "/var/tmp noexec Mount",
    description:
      "Ensure /var/tmp is mounted with noexec option. " +
      "Remediate with: compliance_tmp_hardening with action=apply",
    severity: "medium",
    category: "filesystem",
    check: ["findmnt", "-n", "-o", "OPTIONS", "/var/tmp"],
    expectedOutput: "noexec",
    references: ["CIS-1.1.4", "NIST-CM-6"],
  },
];
