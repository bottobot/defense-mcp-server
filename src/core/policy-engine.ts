import { readFileSync, writeFileSync, mkdirSync, readdirSync } from "node:fs";
import { dirname, join, basename } from "node:path";
import { executeCommand } from "./executor.js";
import { getConfig } from "./config.js";

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

/**
 * Evaluates a single policy rule by executing its check command
 * and comparing the output against the expected pattern.
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

    const [command, ...args] = rule.check;
    const result = await executeCommand({
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

    // Try matching as regex first
    let passed = false;
    try {
      const regex = new RegExp(rule.expectedOutput, "m");
      passed = regex.test(actual);
    } catch {
      // If regex is invalid, do exact match
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
 * Loads a policy set from a JSON file.
 *
 * @param path Absolute or relative path to the policy JSON file
 * @returns The loaded policy set
 * @throws If the file cannot be read or parsed
 */
export function loadPolicy(path: string): PolicySet {
  const content = readFileSync(path, "utf-8");
  const parsed = JSON.parse(content);

  // Basic validation
  if (!parsed.name || !parsed.rules || !Array.isArray(parsed.rules)) {
    throw new Error(
      `Invalid policy file: must contain "name" and "rules" array`
    );
  }

  return parsed as PolicySet;
}

/**
 * Saves a policy set to a JSON file.
 * Creates parent directories if they don't exist.
 *
 * @param path Path to save the policy file
 * @param policy The policy set to save
 */
export function savePolicy(path: string, policy: PolicySet): void {
  const dir = dirname(path);
  mkdirSync(dir, { recursive: true });
  writeFileSync(path, JSON.stringify(policy, null, 2), "utf-8");
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
 */
export const BUILTIN_RULE_TEMPLATES: PolicyRule[] = [
  {
    id: "KERN-001",
    title: "IP forwarding disabled",
    description: "Ensure IP forwarding is disabled unless the system is a router",
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
    description: "Ensure TCP SYN cookies are enabled to prevent SYN flood attacks",
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
    remediation: ["sed", "-i", "s/^#\\?PermitRootLogin.*/PermitRootLogin no/", "/etc/ssh/sshd_config"],
    references: ["CIS-5.2.10", "NIST-IA-2"],
  },
  {
    id: "AUTH-002",
    title: "Password authentication disabled for SSH",
    description: "Ensure password authentication is disabled in favor of key-based auth",
    severity: "high",
    category: "authentication",
    check: ["grep", "-i", "^PasswordAuthentication", "/etc/ssh/sshd_config"],
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
    description: "Ensure sticky bit is set on all world-writable directories",
    severity: "medium",
    category: "filesystem",
    check: ["find", "/", "-xdev", "-type", "d", "-perm", "-0002", "!", "-perm", "-1000", "-print"],
    expectedOutput: "^$",
    references: ["CIS-1.1.21", "NIST-CM-6"],
  },
  {
    id: "SVC-001",
    title: "Firewall service active",
    description: "Ensure a firewall service (iptables/nftables/ufw) is running",
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
    description: "Ensure fail2ban is running to protect against brute force attacks",
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
    description: "Check for world-writable files in critical system directories",
    severity: "high",
    category: "permissions",
    check: ["find", "/etc", "-xdev", "-type", "f", "-perm", "-0002", "-print"],
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
    description: "Ensure pam_pwquality is configured with minimum length 14",
    severity: "high",
    category: "authentication",
    check: ["grep", "-E", "minlen\\s*=\\s*1[4-9]|minlen\\s*=\\s*[2-9][0-9]", "/etc/security/pwquality.conf"],
    expectedOutput: "minlen",
    remediation: ["sh", "-c", "echo 'Use access_pam_configure with module=pwquality'"],
    references: ["CIS-5.3.1", "NIST-IA-5"],
  },
  {
    id: "AUTH-004",
    title: "PAM Account Lockout",
    description: "Ensure pam_faillock is configured for account lockout",
    severity: "high",
    category: "authentication",
    check: ["grep", "-E", "pam_faillock", "/etc/pam.d/common-auth"],
    expectedOutput: "pam_faillock",
    remediation: ["sh", "-c", "echo 'Use access_pam_configure with module=faillock'"],
    references: ["CIS-5.3.2", "NIST-AC-7"],
  },
  {
    id: "AUTH-005",
    title: "Password Maximum Age",
    description: "Ensure password expiry is 365 days or less",
    severity: "medium",
    category: "authentication",
    check: ["grep", "-E", "^PASS_MAX_DAYS", "/etc/login.defs"],
    expectedOutput: "PASS_MAX_DAYS\\s+([1-9]|[1-9][0-9]|[12][0-9]{2}|3[0-5][0-9]|36[0-5])$",
    remediation: ["sh", "-c", "echo 'Use access_password_policy with action=set, max_days=365'"],
    references: ["CIS-5.4.1.1", "NIST-IA-5"],
  },
  {
    id: "FS-003",
    title: "Default Umask 027",
    description: "Ensure default umask is 027 or more restrictive",
    severity: "medium",
    category: "filesystem",
    check: ["grep", "-E", "^UMASK\\s+(027|077)", "/etc/login.defs"],
    expectedOutput: "UMASK\\s+(027|077)",
    remediation: ["sh", "-c", "echo 'Use harden_umask_set with umask_value=027'"],
    references: ["CIS-5.4.4", "NIST-CM-6"],
  },
  {
    id: "FS-004",
    title: "AIDE File Integrity",
    description: "Ensure AIDE file integrity monitoring is installed",
    severity: "high",
    category: "filesystem",
    check: ["which", "aide"],
    remediation: ["sh", "-c", "echo 'Use defense_install with tool=aide'"],
    references: ["CIS-1.3.1", "NIST-SI-7"],
  },
  {
    id: "SVC-004",
    title: "Fail2Ban Active",
    description: "Ensure fail2ban service is running",
    severity: "high",
    category: "services",
    check: ["systemctl", "is-active", "fail2ban"],
    expectedOutput: "^active$",
    remediation: ["sh", "-c", "echo 'Use defense_install with tool=fail2ban, then enable the service'"],
    references: ["NIST-SI-4"],
  },
  {
    id: "SVC-005",
    title: "Docker No Privileged Containers",
    description: "Ensure no Docker containers run in privileged mode",
    severity: "critical",
    category: "services",
    check: ["sh", "-c", "docker ps -q | xargs -r docker inspect --format '{{.HostConfig.Privileged}}' | grep -v false || echo 'PASS'"],
    expectedOutput: "^PASS$",
    remediation: ["sh", "-c", "echo 'Recreate containers without --privileged flag'"],
    references: ["CIS-Docker-5.4"],
  },
  {
    id: "SVC-006",
    title: "AppArmor Enforcing",
    description: "Ensure AppArmor is enabled and has enforcing profiles",
    severity: "medium",
    category: "services",
    check: ["aa-enabled"],
    expectedOutput: "^Yes$",
    remediation: ["sh", "-c", "echo 'Use container_apparmor_install with action=install_profiles'"],
    references: ["CIS-1.6.1.1", "NIST-AC-3"],
  },
  {
    id: "FS-005",
    title: "Core Dumps Disabled",
    description: "Ensure core dumps are restricted",
    severity: "medium",
    category: "filesystem",
    check: ["grep", "-E", "\\*\\s+hard\\s+core\\s+0", "/etc/security/limits.conf"],
    expectedOutput: "\\*\\s+hard\\s+core\\s+0",
    remediation: ["sh", "-c", "echo 'Use harden_coredump_disable'"],
    references: ["CIS-1.5.1", "NIST-CM-6"],
  },
  {
    id: "FS-006",
    title: "/tmp noexec Mount",
    description: "Ensure /tmp is mounted with noexec option",
    severity: "medium",
    category: "filesystem",
    check: ["sh", "-c", "findmnt -n /tmp -o OPTIONS | grep -q noexec && echo PASS || echo FAIL"],
    expectedOutput: "^PASS$",
    remediation: ["sh", "-c", "echo 'Use compliance_tmp_hardening with action=apply'"],
    references: ["CIS-1.1.4", "NIST-CM-6"],
  },
];
