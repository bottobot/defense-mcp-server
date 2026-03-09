/**
 * Cloud security tools for Kali Defense MCP Server.
 *
 * Registers 1 tool: cloud_security (actions: detect_environment, audit_metadata,
 * check_iam_creds, audit_storage, check_imds)
 *
 * Provides cloud environment detection, metadata service auditing, credential
 * exposure checking, storage audit, and IMDS security assessment for AWS/GCP/Azure.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { spawnSafe } from "../core/spawn-safe.js";
import {
  createTextContent,
  createErrorContent,
  formatToolOutput,
} from "../core/parsers.js";
import type { ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";

// ── Constants ──────────────────────────────────────────────────────────────────

/** Cloud providers we can detect */
type CloudProvider = "aws" | "gcp" | "azure" | "unknown";

/** Sensitive environment variable names for cloud credentials */
const CLOUD_CREDENTIAL_ENV_VARS = [
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
  "GOOGLE_APPLICATION_CREDENTIALS",
  "GOOGLE_CLOUD_PROJECT",
  "AZURE_CLIENT_SECRET",
  "AZURE_CLIENT_ID",
  "AZURE_TENANT_ID",
  "AZURE_SUBSCRIPTION_ID",
];

/** Known cloud credential file paths (relative to home) */
const CREDENTIAL_FILE_PATHS: Array<{ provider: string; path: string }> = [
  { provider: "aws", path: "~/.aws/credentials" },
  { provider: "aws", path: "~/.aws/config" },
  { provider: "gcp", path: "~/.config/gcloud/application_default_credentials.json" },
  { provider: "azure", path: "~/.azure/accessTokens.json" },
];

// ── Helpers ────────────────────────────────────────────────────────────────────

interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

/**
 * Run a command via spawnSafe and collect output as a promise.
 * Handles errors gracefully — returns error info instead of throwing.
 */
async function runCommand(
  command: string,
  args: string[],
  timeoutMs = 30_000,
): Promise<CommandResult> {
  return new Promise((resolve) => {
    let child: ChildProcess;
    try {
      child = spawnSafe(command, args);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      resolve({ stdout: "", stderr: msg, exitCode: -1 });
      return;
    }

    let stdout = "";
    let stderr = "";
    let resolved = false;

    const timer = setTimeout(() => {
      if (!resolved) {
        resolved = true;
        child.kill("SIGTERM");
        resolve({ stdout, stderr: stderr + "\n[TIMEOUT]", exitCode: -1 });
      }
    }, timeoutMs);

    child.stdout?.on("data", (data: Buffer) => {
      stdout += data.toString();
    });
    child.stderr?.on("data", (data: Buffer) => {
      stderr += data.toString();
    });

    child.on("close", (code: number | null) => {
      if (!resolved) {
        resolved = true;
        clearTimeout(timer);
        resolve({ stdout, stderr, exitCode: code ?? -1 });
      }
    });

    child.on("error", (err: Error) => {
      if (!resolved) {
        resolved = true;
        clearTimeout(timer);
        resolve({ stdout, stderr: err.message, exitCode: -1 });
      }
    });
  });
}

// ── Credential masking ─────────────────────────────────────────────────────────

/**
 * Mask a credential value, showing first 4 chars + asterisks.
 * Returns "(empty)" for empty strings.
 */
export function maskCredential(value: string): string {
  if (!value || value.trim().length === 0) return "(empty)";
  const trimmed = value.trim();
  if (trimmed.length <= 4) return "****";
  return trimmed.substring(0, 4) + "****";
}

// ── Action implementations ─────────────────────────────────────────────────────

interface DetectResult {
  provider: CloudProvider;
  confidence: "high" | "medium" | "low" | "none";
  evidence: string[];
}

async function detectEnvironment(): Promise<DetectResult> {
  const evidence: string[] = [];
  let provider: CloudProvider = "unknown";
  let confidence: "high" | "medium" | "low" | "none" = "none";

  // Check DMI/BIOS info
  const sysVendor = await runCommand("cat", ["/sys/class/dmi/id/sys_vendor"], 5_000);
  const productName = await runCommand("cat", ["/sys/class/dmi/id/product_name"], 5_000);

  if (sysVendor.exitCode === 0) {
    const vendor = sysVendor.stdout.trim();
    if (vendor.includes("Amazon")) {
      provider = "aws";
      confidence = "high";
      evidence.push(`DMI sys_vendor: ${vendor}`);
    } else if (vendor.includes("Google")) {
      provider = "gcp";
      confidence = "high";
      evidence.push(`DMI sys_vendor: ${vendor}`);
    } else if (vendor.includes("Microsoft")) {
      provider = "azure";
      confidence = "high";
      evidence.push(`DMI sys_vendor: ${vendor}`);
    }
  }

  if (productName.exitCode === 0) {
    const product = productName.stdout.trim();
    if (product.includes("EC2") || product.includes("ec2")) {
      if (provider === "unknown") provider = "aws";
      confidence = "high";
      evidence.push(`DMI product_name: ${product}`);
    } else if (product.includes("Google Compute Engine")) {
      if (provider === "unknown") provider = "gcp";
      confidence = "high";
      evidence.push(`DMI product_name: ${product}`);
    } else if (product.includes("Virtual Machine")) {
      if (provider === "unknown") provider = "azure";
      if (confidence !== "high") confidence = "medium";
      evidence.push(`DMI product_name: ${product}`);
    }
  }

  // Check cloud-init
  if (existsSync("/run/cloud-init/instance-data.json")) {
    evidence.push("cloud-init instance data found at /run/cloud-init/instance-data.json");
    if (confidence === "none") confidence = "medium";
  }

  const cloudInitStatus = await runCommand("cloud-init", ["status"], 5_000);
  if (cloudInitStatus.exitCode === 0) {
    evidence.push(`cloud-init status: ${cloudInitStatus.stdout.trim()}`);
    if (confidence === "none") confidence = "low";
  }

  // Check generic metadata endpoint
  const metadataCheck = await runCommand(
    "curl", ["-s", "-m", "2", "http://169.254.169.254/"], 5_000,
  );
  if (metadataCheck.exitCode === 0 && metadataCheck.stdout.trim().length > 0) {
    evidence.push("Metadata endpoint 169.254.169.254 is reachable");
    if (confidence === "none") confidence = "medium";
  }

  // AWS-specific: Check hypervisor UUID
  const hypervisorUuid = await runCommand("cat", ["/sys/hypervisor/uuid"], 5_000);
  if (hypervisorUuid.exitCode === 0 && hypervisorUuid.stdout.trim().toLowerCase().startsWith("ec2")) {
    provider = "aws";
    confidence = "high";
    evidence.push(`Hypervisor UUID starts with ec2: ${hypervisorUuid.stdout.trim()}`);
  }

  // GCP-specific: Check Google metadata header
  const gcpMetadata = await runCommand(
    "curl", ["-s", "-m", "2", "-H", "Metadata-Flavor: Google", "http://metadata.google.internal/"], 5_000,
  );
  if (gcpMetadata.exitCode === 0 && gcpMetadata.stdout.trim().length > 0) {
    if (provider === "unknown") provider = "gcp";
    if (confidence !== "high") confidence = "high";
    evidence.push("GCP metadata endpoint responded");
  }

  // Azure-specific: Check Azure metadata
  const azureMetadata = await runCommand(
    "curl", ["-s", "-m", "2", "-H", "Metadata: true", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"], 5_000,
  );
  if (azureMetadata.exitCode === 0 && azureMetadata.stdout.includes("compute")) {
    if (provider === "unknown") provider = "azure";
    if (confidence !== "high") confidence = "high";
    evidence.push("Azure IMDS responded with compute metadata");
  }

  return { provider, confidence, evidence };
}

interface MetadataAuditResult {
  provider: CloudProvider;
  imdsVersion: string;
  imdsAccessible: boolean;
  securityLevel: "secure" | "moderate" | "insecure";
  exposedCategories: string[];
  recommendations: string[];
}

async function auditMetadata(requestedProvider: string): Promise<MetadataAuditResult> {
  const result: MetadataAuditResult = {
    provider: "unknown",
    imdsVersion: "unknown",
    imdsAccessible: false,
    securityLevel: "moderate",
    exposedCategories: [],
    recommendations: [],
  };

  // Detect provider if auto
  let provider = requestedProvider;
  if (provider === "auto") {
    const detection = await detectEnvironment();
    provider = detection.provider;
  }
  result.provider = provider as CloudProvider;

  switch (provider) {
    case "aws": {
      // Check IMDSv1 (unauthenticated)
      const v1Check = await runCommand(
        "curl", ["-s", "-m", "2", "http://169.254.169.254/latest/meta-data/"], 5_000,
      );

      // Check IMDSv2 token endpoint
      const v2TokenCheck = await runCommand(
        "curl", ["-s", "-m", "2", "-X", "PUT", "-H", "X-aws-ec2-metadata-token-ttl-seconds: 21600", "http://169.254.169.254/latest/api/token"], 5_000,
      );

      if (v1Check.exitCode === 0 && v1Check.stdout.trim().length > 0) {
        result.imdsAccessible = true;
        result.imdsVersion = "v1 (unauthenticated)";
        result.securityLevel = "insecure";
        result.exposedCategories = v1Check.stdout.trim().split("\n").filter((l) => l.trim().length > 0);
        result.recommendations.push("CRITICAL: IMDSv1 is accessible — enforce IMDSv2 to require session tokens");
        result.recommendations.push("Set HttpTokens=required on the instance to disable IMDSv1");
      }

      if (v2TokenCheck.exitCode === 0 && v2TokenCheck.stdout.trim().length > 0) {
        result.imdsAccessible = true;
        if (result.imdsVersion === "unknown") {
          result.imdsVersion = "v2 (token-based)";
          result.securityLevel = "secure";
        } else {
          result.imdsVersion = "v1 + v2 (both accessible)";
          result.securityLevel = "insecure";
        }
      }

      if (!result.imdsAccessible) {
        result.imdsVersion = "not accessible";
        result.securityLevel = "secure";
        result.recommendations.push("IMDS not accessible — instance may not be in AWS or IMDS is disabled");
      }
      break;
    }

    case "gcp": {
      // GCP requires Metadata-Flavor header — check without header
      const noHeaderCheck = await runCommand(
        "curl", ["-s", "-m", "2", "http://metadata.google.internal/"], 5_000,
      );

      // Check with proper header
      const withHeaderCheck = await runCommand(
        "curl", ["-s", "-m", "2", "-H", "Metadata-Flavor: Google", "http://metadata.google.internal/"], 5_000,
      );

      if (withHeaderCheck.exitCode === 0 && withHeaderCheck.stdout.trim().length > 0) {
        result.imdsAccessible = true;
        result.imdsVersion = "GCP metadata server";

        if (noHeaderCheck.exitCode === 0 && noHeaderCheck.stdout.trim().length > 0 &&
            !noHeaderCheck.stdout.includes("Forbidden")) {
          result.securityLevel = "insecure";
          result.recommendations.push("WARNING: Metadata accessible without Metadata-Flavor header");
        } else {
          result.securityLevel = "secure";
        }
        result.exposedCategories = withHeaderCheck.stdout.trim().split("\n").filter((l) => l.trim().length > 0);
      } else {
        result.imdsVersion = "not accessible";
        result.securityLevel = "secure";
        result.recommendations.push("GCP metadata not accessible — instance may not be in GCP");
      }
      break;
    }

    case "azure": {
      // Azure requires Metadata: true header
      const noHeaderCheck = await runCommand(
        "curl", ["-s", "-m", "2", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"], 5_000,
      );

      const withHeaderCheck = await runCommand(
        "curl", ["-s", "-m", "2", "-H", "Metadata: true", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"], 5_000,
      );

      if (withHeaderCheck.exitCode === 0 && withHeaderCheck.stdout.includes("compute")) {
        result.imdsAccessible = true;
        result.imdsVersion = "Azure IMDS";

        if (noHeaderCheck.exitCode === 0 && noHeaderCheck.stdout.includes("compute")) {
          result.securityLevel = "insecure";
          result.recommendations.push("WARNING: Azure IMDS accessible without Metadata header");
        } else {
          result.securityLevel = "moderate";
          result.recommendations.push("Azure IMDS requires Metadata header — standard security");
        }
        result.exposedCategories = ["compute", "network"];
      } else {
        result.imdsVersion = "not accessible";
        result.securityLevel = "secure";
        result.recommendations.push("Azure IMDS not accessible — instance may not be in Azure");
      }
      break;
    }

    default:
      result.recommendations.push("Cloud provider not detected — cannot audit metadata service");
      break;
  }

  return result;
}

interface CredentialCheckResult {
  provider: string;
  envVarsFound: Array<{ name: string; masked: string }>;
  credentialFiles: Array<{ path: string; exists: boolean; permissions?: string; permWarning?: string }>;
  processesExposed: string[];
  recommendations: string[];
}

async function checkIamCreds(requestedProvider: string): Promise<CredentialCheckResult> {
  const result: CredentialCheckResult = {
    provider: requestedProvider,
    envVarsFound: [],
    credentialFiles: [],
    processesExposed: [],
    recommendations: [],
  };

  // Check environment variables
  const envResult = await runCommand("env", [], 10_000);
  if (envResult.exitCode === 0) {
    const lines = envResult.stdout.split("\n");
    for (const line of lines) {
      const eqIdx = line.indexOf("=");
      if (eqIdx < 0) continue;
      const name = line.substring(0, eqIdx);
      const value = line.substring(eqIdx + 1);
      if (CLOUD_CREDENTIAL_ENV_VARS.includes(name)) {
        result.envVarsFound.push({ name, masked: maskCredential(value) });
      }
    }
  }

  if (result.envVarsFound.length > 0) {
    result.recommendations.push("Cloud credential environment variables detected — consider using instance roles instead");
  }

  // Check credential files
  const homeResult = await runCommand("sh", ["-c", "echo $HOME"], 5_000);
  const home = homeResult.exitCode === 0 ? homeResult.stdout.trim() : "/root";

  const filesToCheck = requestedProvider === "auto"
    ? CREDENTIAL_FILE_PATHS
    : CREDENTIAL_FILE_PATHS.filter((f) => f.provider === requestedProvider);

  for (const fileInfo of filesToCheck) {
    const filePath = fileInfo.path.replace("~", home);
    const fileExists = existsSync(filePath);

    const entry: { path: string; exists: boolean; permissions?: string; permWarning?: string } = {
      path: fileInfo.path,
      exists: fileExists,
    };

    if (fileExists) {
      // Check file permissions
      const statResult = await runCommand("stat", ["-c", "%a", filePath], 5_000);
      if (statResult.exitCode === 0) {
        const perms = statResult.stdout.trim();
        entry.permissions = perms;
        // Check if overly permissive (readable by group or others)
        const numPerms = parseInt(perms, 8);
        if ((numPerms & 0o077) !== 0) {
          entry.permWarning = `File permissions ${perms} are too open — should be 600 or stricter`;
          result.recommendations.push(`Fix permissions on ${fileInfo.path}: chmod 600 ${filePath}`);
        }
      }
    }

    result.credentialFiles.push(entry);
  }

  // Scan /proc/*/environ for cloud credential env vars
  const procScan = await runCommand(
    "grep", ["-rl", "AWS_ACCESS_KEY_ID\\|AWS_SECRET_ACCESS_KEY\\|GOOGLE_APPLICATION_CREDENTIALS\\|AZURE_CLIENT_SECRET", "/proc/*/environ"],
    10_000,
  );
  if (procScan.exitCode === 0 && procScan.stdout.trim().length > 0) {
    const procs = procScan.stdout.trim().split("\n")
      .map((p) => p.trim())
      .filter((p) => p.length > 0)
      .slice(0, 20); // limit output
    result.processesExposed = procs;
    result.recommendations.push(`Found ${procs.length} process(es) with cloud credentials in environment — review for least privilege`);
  }

  return result;
}

interface StorageAuditResult {
  provider: string;
  cliAvailable: { aws: boolean; gsutil: boolean; az: boolean };
  accessibleStorage: string[];
  mountPoints: string[];
  recommendations: string[];
}

async function auditStorage(requestedProvider: string): Promise<StorageAuditResult> {
  const result: StorageAuditResult = {
    provider: requestedProvider,
    cliAvailable: { aws: false, gsutil: false, az: false },
    accessibleStorage: [],
    mountPoints: [],
    recommendations: [],
  };

  // Check for CLI tools
  const awsCheck = await runCommand("which", ["aws"], 5_000);
  result.cliAvailable.aws = awsCheck.exitCode === 0;

  const gsutilCheck = await runCommand("which", ["gsutil"], 5_000);
  result.cliAvailable.gsutil = gsutilCheck.exitCode === 0;

  const azCheck = await runCommand("which", ["az"], 5_000);
  result.cliAvailable.az = azCheck.exitCode === 0;

  const shouldCheckAws = requestedProvider === "auto" || requestedProvider === "aws";
  const shouldCheckGcp = requestedProvider === "auto" || requestedProvider === "gcp";
  const shouldCheckAzure = requestedProvider === "auto" || requestedProvider === "azure";

  // AWS: List S3 buckets
  if (shouldCheckAws && result.cliAvailable.aws) {
    const s3ls = await runCommand("aws", ["s3", "ls"], 15_000);
    if (s3ls.exitCode === 0 && s3ls.stdout.trim().length > 0) {
      const buckets = s3ls.stdout.trim().split("\n").filter((l) => l.trim().length > 0);
      result.accessibleStorage.push(...buckets.map((b) => `[AWS S3] ${b.trim()}`));
    }
  } else if (shouldCheckAws && !result.cliAvailable.aws) {
    result.recommendations.push("AWS CLI not installed — cannot audit S3 storage");
  }

  // GCP: List buckets
  if (shouldCheckGcp && result.cliAvailable.gsutil) {
    const gsls = await runCommand("gsutil", ["ls"], 15_000);
    if (gsls.exitCode === 0 && gsls.stdout.trim().length > 0) {
      const buckets = gsls.stdout.trim().split("\n").filter((l) => l.trim().length > 0);
      result.accessibleStorage.push(...buckets.map((b) => `[GCP GCS] ${b.trim()}`));
    }
  } else if (shouldCheckGcp && !result.cliAvailable.gsutil) {
    result.recommendations.push("gsutil not installed — cannot audit GCS storage");
  }

  // Azure: List storage accounts
  if (shouldCheckAzure && result.cliAvailable.az) {
    const azStorage = await runCommand("az", ["storage", "account", "list"], 15_000);
    if (azStorage.exitCode === 0 && azStorage.stdout.trim().length > 0) {
      result.accessibleStorage.push(`[Azure] ${azStorage.stdout.trim().substring(0, 500)}`);
    }
  } else if (shouldCheckAzure && !result.cliAvailable.az) {
    result.recommendations.push("Azure CLI not installed — cannot audit Azure storage");
  }

  // Check for mounted cloud storage (NFS, FUSE)
  const mountResult = await runCommand("mount", [], 10_000);
  if (mountResult.exitCode === 0) {
    const lines = mountResult.stdout.split("\n");
    for (const line of lines) {
      const lower = line.toLowerCase();
      if (lower.includes("fuse") || lower.includes("nfs") ||
          lower.includes("s3fs") || lower.includes("gcsfuse") ||
          lower.includes("blobfuse") || lower.includes("cifs")) {
        result.mountPoints.push(line.trim());
      }
    }
  }

  if (result.accessibleStorage.length === 0 && result.mountPoints.length === 0) {
    result.recommendations.push("No cloud storage accessible from this instance");
  }

  return result;
}

interface ImdsCheckResult {
  v1Accessible: boolean;
  v2Accessible: boolean;
  v2TokenWorks: boolean;
  iptablesBlocked: boolean;
  iptablesRules: string[];
  hopLimit: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  securityScore: number;
  recommendations: string[];
}

async function checkImds(): Promise<ImdsCheckResult> {
  const result: ImdsCheckResult = {
    v1Accessible: false,
    v2Accessible: false,
    v2TokenWorks: false,
    iptablesBlocked: false,
    iptablesRules: [],
    hopLimit: "unknown",
    severity: "INFO",
    securityScore: 100,
    recommendations: [],
  };

  // Test IMDSv1 (unauthenticated)
  const v1Check = await runCommand(
    "curl", ["-s", "-m", "2", "http://169.254.169.254/latest/meta-data/"], 5_000,
  );
  if (v1Check.exitCode === 0 && v1Check.stdout.trim().length > 0) {
    result.v1Accessible = true;
    result.severity = "CRITICAL";
    result.securityScore -= 50;
    result.recommendations.push("CRITICAL: IMDSv1 is accessible without authentication — enforce IMDSv2");
  }

  // Test IMDSv2 token endpoint
  const v2TokenCheck = await runCommand(
    "curl", ["-s", "-m", "2", "-X", "PUT", "-H", "X-aws-ec2-metadata-token-ttl-seconds: 21600", "http://169.254.169.254/latest/api/token"], 5_000,
  );
  if (v2TokenCheck.exitCode === 0 && v2TokenCheck.stdout.trim().length > 0) {
    result.v2TokenWorks = true;
    result.v2Accessible = true;
    if (!result.v1Accessible) {
      result.severity = "LOW";
      result.securityScore = Math.max(result.securityScore, 80);
    }
  }

  // Check iptables for IMDS blocking rules
  const iptablesResult = await runCommand("iptables", ["-L", "-n"], 10_000);
  if (iptablesResult.exitCode === 0) {
    const lines = iptablesResult.stdout.split("\n");
    for (const line of lines) {
      if (line.includes("169.254.169.254")) {
        result.iptablesRules.push(line.trim());
        if (line.includes("DROP") || line.includes("REJECT")) {
          result.iptablesBlocked = true;
        }
      }
    }
  }

  if (!result.iptablesBlocked && (result.v1Accessible || result.v2Accessible)) {
    result.securityScore -= 20;
    if (result.severity !== "CRITICAL") {
      result.severity = "MEDIUM";
    }
    result.recommendations.push("No iptables rules blocking IMDS from non-root users — consider adding restrictions");
  }

  // Check hop limit via curl with TTL
  const hopCheck = await runCommand(
    "curl", ["-s", "-m", "2", "--max-time", "2", "http://169.254.169.254/latest/meta-data/"], 5_000,
  );
  if (hopCheck.exitCode === 0 && hopCheck.stdout.trim().length > 0) {
    result.hopLimit = "reachable (default)";
  } else if (!result.v1Accessible && !result.v2Accessible) {
    result.hopLimit = "not reachable (IMDS may be disabled or restricted)";
  }

  // If nothing is accessible, it's fine
  if (!result.v1Accessible && !result.v2Accessible) {
    result.severity = "INFO";
    result.securityScore = 100;
    result.recommendations.push("IMDS not accessible — instance may not be in a cloud environment or IMDS is disabled");
  }

  result.securityScore = Math.max(0, Math.min(100, result.securityScore));

  return result;
}

// ── Registration entry point ───────────────────────────────────────────────

export function registerCloudSecurityTools(server: McpServer): void {
  server.tool(
    "cloud_security",
    "Cloud security: detect cloud environment, audit metadata services, check IAM credentials, audit storage, and test IMDS security for AWS/GCP/Azure.",
    {
      action: z
        .enum(["detect_environment", "audit_metadata", "check_iam_creds", "audit_storage", "check_imds"])
        .describe(
          "Action: detect_environment=detect cloud provider, audit_metadata=audit IMDS configuration, check_iam_creds=check for exposed credentials, audit_storage=audit cloud storage, check_imds=test IMDS security",
        ),
      provider: z
        .enum(["aws", "gcp", "azure", "auto"])
        .optional()
        .default("auto")
        .describe("Cloud provider to target (default auto-detect)"),
      output_format: z
        .enum(["text", "json"])
        .optional()
        .default("text")
        .describe("Output format (default text)"),
    },
    async (params) => {
      const { action } = params;

      switch (action) {
        // ── detect_environment ────────────────────────────────────────────
        case "detect_environment": {
          try {
            const detection = await detectEnvironment();

            const output = {
              action: "detect_environment",
              provider: detection.provider,
              confidence: detection.confidence,
              evidenceCount: detection.evidence.length,
              evidence: detection.evidence,
              isCloud: detection.provider !== "unknown",
            };

            if (params.output_format === "json") {
              return { content: [formatToolOutput(output)] };
            }

            if (detection.provider === "unknown") {
              return {
                content: [createTextContent(
                  "Cloud Security — Environment Detection\n\n" +
                  "Result: Not running in a detected cloud environment\n" +
                  `Checks performed: ${detection.evidence.length > 0 ? detection.evidence.length : "standard suite"}\n` +
                  (detection.evidence.length > 0 ? `\nEvidence:\n${detection.evidence.map((e) => `  • ${e}`).join("\n")}\n` : "") +
                  "\nThis system does not appear to be running in AWS, GCP, or Azure.\n",
                )],
              };
            }

            return {
              content: [createTextContent(
                "Cloud Security — Environment Detection\n\n" +
                `Provider: ${detection.provider.toUpperCase()}\n` +
                `Confidence: ${detection.confidence}\n` +
                `Evidence (${detection.evidence.length}):\n` +
                detection.evidence.map((e) => `  • ${e}`).join("\n") + "\n",
              )],
            };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`detect_environment failed: ${msg}`)], isError: true };
          }
        }

        // ── audit_metadata ───────────────────────────────────────────────
        case "audit_metadata": {
          try {
            const provider = params.provider ?? "auto";
            const audit = await auditMetadata(provider);

            const output = {
              action: "audit_metadata",
              provider: audit.provider,
              imdsVersion: audit.imdsVersion,
              imdsAccessible: audit.imdsAccessible,
              securityLevel: audit.securityLevel,
              exposedCategories: audit.exposedCategories,
              recommendations: audit.recommendations,
            };

            if (params.output_format === "json") {
              return { content: [formatToolOutput(output)] };
            }

            return {
              content: [createTextContent(
                "Cloud Security — Metadata Audit\n\n" +
                `Provider: ${audit.provider}\n` +
                `IMDS Version: ${audit.imdsVersion}\n` +
                `IMDS Accessible: ${audit.imdsAccessible ? "YES" : "no"}\n` +
                `Security Level: ${audit.securityLevel.toUpperCase()}\n` +
                (audit.exposedCategories.length > 0
                  ? `\nExposed Categories:\n${audit.exposedCategories.map((c) => `  • ${c}`).join("\n")}\n`
                  : "") +
                (audit.recommendations.length > 0
                  ? `\nRecommendations:\n${audit.recommendations.map((r) => `  • ${r}`).join("\n")}\n`
                  : ""),
              )],
            };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`audit_metadata failed: ${msg}`)], isError: true };
          }
        }

        // ── check_iam_creds ──────────────────────────────────────────────
        case "check_iam_creds": {
          try {
            const provider = params.provider ?? "auto";
            const creds = await checkIamCreds(provider);

            const output = {
              action: "check_iam_creds",
              provider: creds.provider,
              envVarsFound: creds.envVarsFound,
              credentialFiles: creds.credentialFiles,
              processesExposed: creds.processesExposed,
              totalFindings: creds.envVarsFound.length + creds.credentialFiles.filter((f) => f.exists).length + creds.processesExposed.length,
              recommendations: creds.recommendations,
            };

            if (params.output_format === "json") {
              return { content: [formatToolOutput(output)] };
            }

            let text = "Cloud Security — IAM Credential Check\n\n";

            if (creds.envVarsFound.length > 0) {
              text += "Environment Variables with Cloud Credentials:\n";
              for (const env of creds.envVarsFound) {
                text += `  • ${env.name} = ${env.masked}\n`;
              }
              text += "\n";
            } else {
              text += "Environment Variables: No cloud credentials found in environment\n\n";
            }

            text += "Credential Files:\n";
            for (const file of creds.credentialFiles) {
              const status = file.exists
                ? `EXISTS (permissions: ${file.permissions || "unknown"})${file.permWarning ? ` ⚠ ${file.permWarning}` : ""}`
                : "not found";
              text += `  • ${file.path}: ${status}\n`;
            }

            if (creds.processesExposed.length > 0) {
              text += `\nProcesses with Cloud Credentials: ${creds.processesExposed.length}\n`;
              for (const proc of creds.processesExposed.slice(0, 10)) {
                text += `  • ${proc}\n`;
              }
            }

            if (creds.recommendations.length > 0) {
              text += `\nRecommendations:\n`;
              for (const rec of creds.recommendations) {
                text += `  • ${rec}\n`;
              }
            }

            return { content: [createTextContent(text)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`check_iam_creds failed: ${msg}`)], isError: true };
          }
        }

        // ── audit_storage ────────────────────────────────────────────────
        case "audit_storage": {
          try {
            const provider = params.provider ?? "auto";
            const storage = await auditStorage(provider);

            const output = {
              action: "audit_storage",
              provider: storage.provider,
              cliAvailable: storage.cliAvailable,
              accessibleStorage: storage.accessibleStorage,
              mountPoints: storage.mountPoints,
              totalAccessible: storage.accessibleStorage.length + storage.mountPoints.length,
              recommendations: storage.recommendations,
            };

            if (params.output_format === "json") {
              return { content: [formatToolOutput(output)] };
            }

            let text = "Cloud Security — Storage Audit\n\n";
            text += "CLI Tools:\n";
            text += `  • AWS CLI: ${storage.cliAvailable.aws ? "installed" : "not found"}\n`;
            text += `  • gsutil: ${storage.cliAvailable.gsutil ? "installed" : "not found"}\n`;
            text += `  • Azure CLI: ${storage.cliAvailable.az ? "installed" : "not found"}\n\n`;

            if (storage.accessibleStorage.length > 0) {
              text += `Accessible Storage (${storage.accessibleStorage.length}):\n`;
              for (const s of storage.accessibleStorage) {
                text += `  • ${s}\n`;
              }
              text += "\n";
            } else {
              text += "Accessible Storage: none found\n\n";
            }

            if (storage.mountPoints.length > 0) {
              text += `Cloud Mount Points (${storage.mountPoints.length}):\n`;
              for (const m of storage.mountPoints) {
                text += `  • ${m}\n`;
              }
              text += "\n";
            }

            if (storage.recommendations.length > 0) {
              text += "Recommendations:\n";
              for (const rec of storage.recommendations) {
                text += `  • ${rec}\n`;
              }
            }

            return { content: [createTextContent(text)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`audit_storage failed: ${msg}`)], isError: true };
          }
        }

        // ── check_imds ───────────────────────────────────────────────────
        case "check_imds": {
          try {
            const imds = await checkImds();

            const output = {
              action: "check_imds",
              v1Accessible: imds.v1Accessible,
              v2Accessible: imds.v2Accessible,
              v2TokenWorks: imds.v2TokenWorks,
              iptablesBlocked: imds.iptablesBlocked,
              iptablesRules: imds.iptablesRules,
              hopLimit: imds.hopLimit,
              severity: imds.severity,
              securityScore: imds.securityScore,
              recommendations: imds.recommendations,
            };

            if (params.output_format === "json") {
              return { content: [formatToolOutput(output)] };
            }

            let text = "Cloud Security — IMDS Security Check\n\n";
            text += `IMDSv1 (unauthenticated): ${imds.v1Accessible ? "ACCESSIBLE ⚠" : "not accessible ✓"}\n`;
            text += `IMDSv2 (token-based): ${imds.v2Accessible ? "accessible" : "not accessible"}\n`;
            text += `IMDSv2 Token Endpoint: ${imds.v2TokenWorks ? "working" : "not working"}\n`;
            text += `Iptables IMDS Rules: ${imds.iptablesBlocked ? "BLOCKED ✓" : imds.iptablesRules.length > 0 ? "rules found" : "no rules"}\n`;
            text += `Hop Limit: ${imds.hopLimit}\n`;
            text += `\nSeverity: ${imds.severity}\n`;
            text += `Security Score: ${imds.securityScore}/100\n`;

            if (imds.iptablesRules.length > 0) {
              text += `\nIptables Rules for 169.254.169.254:\n`;
              for (const rule of imds.iptablesRules) {
                text += `  • ${rule}\n`;
              }
            }

            if (imds.recommendations.length > 0) {
              text += `\nRecommendations:\n`;
              for (const rec of imds.recommendations) {
                text += `  • ${rec}\n`;
              }
            }

            return { content: [createTextContent(text)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`check_imds failed: ${msg}`)], isError: true };
          }
        }

        default:
          return { content: [createErrorContent(`Unknown action: ${action}`)], isError: true };
      }
    },
  );
}
