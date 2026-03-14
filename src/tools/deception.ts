/**
 * Deception / honeypot tools for Defense MCP Server.
 *
 * Registers 1 tool: honeypot_manage (actions: deploy_canary, deploy_honeyport,
 * check_triggers, remove, list)
 *
 * Provides canary token deployment (file, credential, directory, ssh_key),
 * honeyport listener management, trigger detection, canary removal, and
 * registry listing for deception-based intrusion detection.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { spawnSafe } from "../core/spawn-safe.js";
import { secureWriteFileSync } from "../core/secure-fs.js";
import {
  createTextContent,
  createErrorContent,
  formatToolOutput,
} from "../core/parsers.js";
import type { ChildProcess } from "node:child_process";
import { existsSync, readFileSync, unlinkSync, rmSync } from "node:fs";

// ── Constants ──────────────────────────────────────────────────────────────────

/** Base directory for canary registry and logs */
const CANARY_BASE_DIR = "/var/lib/defense-mcp/canaries";

/** Path to the canary registry file */
const REGISTRY_PATH = `${CANARY_BASE_DIR}/registry.json`;

// ── Types ──────────────────────────────────────────────────────────────────────

type CanaryType = "file" | "credential" | "directory" | "ssh_key";

interface CanaryEntry {
  id: string;
  type: CanaryType | "honeyport";
  path?: string;
  port?: number;
  pid?: number;
  deployedAt: string;
  status: "active" | "triggered" | "removed";
  description: string;
  accessTimeAtDeploy?: string;
}

interface CanaryRegistry {
  canaries: CanaryEntry[];
  lastUpdated: string;
}

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

/**
 * Generate a unique canary ID based on timestamp and random suffix.
 */
function generateCanaryId(): string {
  const ts = Date.now();
  const rand = Math.random().toString(36).substring(2, 8);
  return `canary-${ts}-${rand}`;
}

/**
 * Read the canary registry from disk.
 * Returns an empty registry if the file doesn't exist or is invalid.
 */
function readRegistry(): CanaryRegistry {
  try {
    if (existsSync(REGISTRY_PATH)) {
      const data = readFileSync(REGISTRY_PATH, "utf-8");
      return JSON.parse(data) as CanaryRegistry;
    }
  } catch {
    // Fall through to default
  }
  return { canaries: [], lastUpdated: new Date().toISOString() };
}

/**
 * Write the canary registry to disk using secureWriteFileSync.
 */
function writeRegistry(registry: CanaryRegistry): void {
  registry.lastUpdated = new Date().toISOString();
  secureWriteFileSync(REGISTRY_PATH, JSON.stringify(registry, null, 2));
}

// ── Fake credential generators ─────────────────────────────────────────────

/** Generate realistic-looking fake credential file content */
function generateFakePasswordFile(): string {
  return [
    "# Internal credentials - DO NOT DELETE",
    "# Last rotated: 2025-11-15",
    "",
    "admin_portal=admin:xK9$mP2vL8qR3nT6",
    "database_prod=dbadmin:Wy7#jF4hN1sD9bQ5",
    "api_gateway=svc-account:mH3@kL6pR8wE2xV4",
    "jenkins_ci=deploy:tN5$qJ9fB3yK7gU1",
    "redis_cache=default:vC8#nD4hS6mW2pL9",
    "",
    "# AWS staging credentials",
    "aws_access_key=AKIAIOSFODNN7FAKEXMP",
    "aws_secret_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYFAKEKEY1",
    "",
  ].join("\n");
}

/** Generate realistic-looking fake AWS credentials */
function generateFakeAwsCredentials(): string {
  return [
    "[default]",
    "aws_access_key_id = AKIAIOSFODNN7FAKEXMP",
    "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYFAKEKEY1",
    "region = us-east-1",
    "",
    "[staging]",
    "aws_access_key_id = AKIAI44QH8DHBFAKEKEY",
    "aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbFAKEKEY2",
    "region = us-west-2",
    "",
  ].join("\n");
}

/** Generate realistic-looking fake SSH private key */
function generateFakeSshKey(): string {
  return [
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn",
    "NhAAAAAwEAAQAAAIEA0Z3IkCnr8TcHbGO3LiGx7bV2FAKEFAKEFAKEFAKEFAKEFAKEFAKE",
    "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEF",
    "AKEAAAARaG9uZXlwb3Qta2V5LWZha2UBAAACGA0Z3IkCnr8TcHbGO3LiGx7bV2FAKEFAK",
    "EFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE==",
    "-----END OPENSSH PRIVATE KEY-----",
    "",
  ].join("\n");
}

/** Generate realistic-looking directory listing files */
function generateFakeDirectoryFiles(): Array<{ name: string; content: string }> {
  return [
    {
      name: "passwords.txt",
      content: generateFakePasswordFile(),
    },
    {
      name: "id_rsa",
      content: generateFakeSshKey(),
    },
    {
      name: ".env.backup",
      content: [
        "DATABASE_URL=postgresql://admin:s3cretP@ss@db.internal:5432/production",
        "REDIS_URL=redis://:r3d1sP@ss@cache.internal:6379",
        "JWT_SECRET=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.FAKE.TOKEN",
        "STRIPE_SECRET_KEY=sk_live_FAKEFAKEFAKEFAKEFAKE",
        "SENDGRID_API_KEY=SG.FAKEFAKEFAKEFAKE.FAKEFAKEFAKEFAKE",
        "",
      ].join("\n"),
    },
  ];
}

// ── Action implementations ─────────────────────────────────────────────────────

interface DeployCanaryResult {
  canaryId: string;
  type: CanaryType;
  path: string;
  monitoringSetup: boolean;
  monitoringDetails: string;
  description: string;
}

async function deployCanary(
  canaryType: CanaryType,
  canaryPath: string,
): Promise<DeployCanaryResult> {
  const canaryId = generateCanaryId();
  let monitoringSetup = false;
  let monitoringDetails = "";
  let description = "";

  switch (canaryType) {
    case "file": {
      const targetPath = canaryPath.endsWith("/")
        ? `${canaryPath}passwords.txt`
        : canaryPath;
      const content = generateFakePasswordFile();
      secureWriteFileSync(targetPath, content);
      description = `Canary file deployed at ${targetPath}`;

      // Set up inotifywait monitoring
      const inotifyResult = await runCommand(
        "inotifywait",
        ["-m", "-e", "access,open", "--format", "%T %w%f %e", "--timefmt", "%Y-%m-%dT%H:%M:%S", "-d", "-o", `${CANARY_BASE_DIR}/canary-${canaryId}.log`, targetPath],
        10_000,
      );
      monitoringSetup = inotifyResult.exitCode === 0 || inotifyResult.exitCode === -1;
      monitoringDetails = monitoringSetup
        ? `inotifywait monitoring active, log: ${CANARY_BASE_DIR}/canary-${canaryId}.log`
        : `inotifywait setup failed: ${inotifyResult.stderr}`;

      // Get initial access time for comparison
      const statResult = await runCommand("stat", ["-c", "%X", targetPath], 5_000);
      const accessTime = statResult.exitCode === 0 ? statResult.stdout.trim() : "";

      // Register in registry
      const registry = readRegistry();
      registry.canaries.push({
        id: canaryId,
        type: "file",
        path: targetPath,
        deployedAt: new Date().toISOString(),
        status: "active",
        description,
        accessTimeAtDeploy: accessTime,
      });
      writeRegistry(registry);
      break;
    }

    case "credential": {
      const targetPath = canaryPath.endsWith("/")
        ? `${canaryPath}.aws/credentials`
        : canaryPath;
      const content = generateFakeAwsCredentials();
      secureWriteFileSync(targetPath, content);
      description = `Canary credential file deployed at ${targetPath}`;

      // Set up inotifywait monitoring
      const inotifyResult = await runCommand(
        "inotifywait",
        ["-m", "-e", "access,open", "--format", "%T %w%f %e", "--timefmt", "%Y-%m-%dT%H:%M:%S", "-d", "-o", `${CANARY_BASE_DIR}/canary-${canaryId}.log`, targetPath],
        10_000,
      );
      monitoringSetup = inotifyResult.exitCode === 0 || inotifyResult.exitCode === -1;
      monitoringDetails = monitoringSetup
        ? `inotifywait monitoring active, log: ${CANARY_BASE_DIR}/canary-${canaryId}.log`
        : `inotifywait setup failed: ${inotifyResult.stderr}`;

      const statResult = await runCommand("stat", ["-c", "%X", targetPath], 5_000);
      const accessTime = statResult.exitCode === 0 ? statResult.stdout.trim() : "";

      const registry = readRegistry();
      registry.canaries.push({
        id: canaryId,
        type: "credential",
        path: targetPath,
        deployedAt: new Date().toISOString(),
        status: "active",
        description,
        accessTimeAtDeploy: accessTime,
      });
      writeRegistry(registry);
      break;
    }

    case "directory": {
      const targetDir = canaryPath.endsWith("/") ? canaryPath.slice(0, -1) : canaryPath;
      const files = generateFakeDirectoryFiles();

      // Create the directory and write files
      for (const file of files) {
        const filePath = `${targetDir}/${file.name}`;
        secureWriteFileSync(filePath, file.content);
      }
      description = `Canary directory deployed at ${targetDir} with ${files.length} files`;

      // Set up inotifywait on the directory
      const inotifyResult = await runCommand(
        "inotifywait",
        ["-m", "-r", "-e", "access,open", "--format", "%T %w%f %e", "--timefmt", "%Y-%m-%dT%H:%M:%S", "-d", "-o", `${CANARY_BASE_DIR}/canary-${canaryId}.log`, targetDir],
        10_000,
      );
      monitoringSetup = inotifyResult.exitCode === 0 || inotifyResult.exitCode === -1;
      monitoringDetails = monitoringSetup
        ? `inotifywait monitoring active (recursive), log: ${CANARY_BASE_DIR}/canary-${canaryId}.log`
        : `inotifywait setup failed: ${inotifyResult.stderr}`;

      const statResult = await runCommand("stat", ["-c", "%X", targetDir], 5_000);
      const accessTime = statResult.exitCode === 0 ? statResult.stdout.trim() : "";

      const registry = readRegistry();
      registry.canaries.push({
        id: canaryId,
        type: "directory",
        path: targetDir,
        deployedAt: new Date().toISOString(),
        status: "active",
        description,
        accessTimeAtDeploy: accessTime,
      });
      writeRegistry(registry);
      break;
    }

    case "ssh_key": {
      const targetPath = canaryPath.endsWith("/")
        ? `${canaryPath}id_rsa`
        : canaryPath;
      const content = generateFakeSshKey();
      secureWriteFileSync(targetPath, content);
      description = `Canary SSH key deployed at ${targetPath}`;

      // Set up inotifywait monitoring
      const inotifyResult = await runCommand(
        "inotifywait",
        ["-m", "-e", "access,open", "--format", "%T %w%f %e", "--timefmt", "%Y-%m-%dT%H:%M:%S", "-d", "-o", `${CANARY_BASE_DIR}/canary-${canaryId}.log`, targetPath],
        10_000,
      );
      monitoringSetup = inotifyResult.exitCode === 0 || inotifyResult.exitCode === -1;
      monitoringDetails = monitoringSetup
        ? `inotifywait monitoring active, log: ${CANARY_BASE_DIR}/canary-${canaryId}.log`
        : `inotifywait setup failed: ${inotifyResult.stderr}`;

      const statResult = await runCommand("stat", ["-c", "%X", targetPath], 5_000);
      const accessTime = statResult.exitCode === 0 ? statResult.stdout.trim() : "";

      const registry = readRegistry();
      registry.canaries.push({
        id: canaryId,
        type: "ssh_key",
        path: targetPath,
        deployedAt: new Date().toISOString(),
        status: "active",
        description,
        accessTimeAtDeploy: accessTime,
      });
      writeRegistry(registry);
      break;
    }
  }

  return {
    canaryId,
    type: canaryType,
    path: canaryPath,
    monitoringSetup,
    monitoringDetails,
    description,
  };
}

interface DeployHoneyportResult {
  canaryId: string;
  port: number;
  listenerPid: number | null;
  logPath: string;
  iptablesRuleAdded: boolean;
  description: string;
}

async function deployHoneyport(port: number): Promise<DeployHoneyportResult> {
  const canaryId = generateCanaryId();
  const logPath = `${CANARY_BASE_DIR}/honeyport-${port}.log`;
  let listenerPid: number | null = null;
  let iptablesRuleAdded = false;

  // Start ncat listener in background
  const ncatResult = await runCommand(
    "ncat",
    ["-l", "-k", "-p", String(port), "-o", logPath],
    5_000,
  );

  // ncat runs in background, so we check for PID
  if (ncatResult.exitCode === 0 || ncatResult.exitCode === -1) {
    // Try to find the PID of the ncat process
    const pidResult = await runCommand(
      "sh",
      ["-c", `lsof -ti tcp:${port} -sTCP:LISTEN | head -1`],
      5_000,
    );
    if (pidResult.exitCode === 0 && pidResult.stdout.trim().length > 0) {
      listenerPid = parseInt(pidResult.stdout.trim(), 10);
      if (isNaN(listenerPid)) listenerPid = null;
    }
  }

  // Add iptables LOG rule
  const iptablesResult = await runCommand(
    "iptables",
    ["-A", "INPUT", "-p", "tcp", "--dport", String(port), "-j", "LOG", "--log-prefix", `HONEYPORT:${port}: `],
    10_000,
  );
  iptablesRuleAdded = iptablesResult.exitCode === 0;

  const description = `Honeyport listener on port ${port}`;

  // Register in registry
  const registry = readRegistry();
  registry.canaries.push({
    id: canaryId,
    type: "honeyport",
    port,
    pid: listenerPid ?? undefined,
    deployedAt: new Date().toISOString(),
    status: "active",
    description,
  });
  writeRegistry(registry);

  return {
    canaryId,
    port,
    listenerPid,
    logPath,
    iptablesRuleAdded,
    description,
  };
}

interface TriggeredCanary {
  id: string;
  type: string;
  path?: string;
  port?: number;
  triggered: boolean;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  accessDetails: string[];
  lastAccessed?: string;
}

interface CheckTriggersResult {
  totalCanaries: number;
  triggeredCount: number;
  triggered: TriggeredCanary[];
  notTriggered: string[];
  syslogEntries: string[];
}

async function checkTriggers(): Promise<CheckTriggersResult> {
  const registry = readRegistry();
  const result: CheckTriggersResult = {
    totalCanaries: registry.canaries.length,
    triggeredCount: 0,
    triggered: [],
    notTriggered: [],
    syslogEntries: [],
  };

  for (const canary of registry.canaries) {
    if (canary.status === "removed") continue;

    const triggerInfo: TriggeredCanary = {
      id: canary.id,
      type: canary.type,
      path: canary.path,
      port: canary.port,
      triggered: false,
      severity: "INFO",
      accessDetails: [],
    };

    if (canary.type === "honeyport") {
      // Check honeyport connection logs
      const logPath = `${CANARY_BASE_DIR}/honeyport-${canary.port}.log`;
      if (existsSync(logPath)) {
        try {
          const logContent = readFileSync(logPath, "utf-8");
          if (logContent.trim().length > 0) {
            triggerInfo.triggered = true;
            triggerInfo.severity = "CRITICAL";
            triggerInfo.accessDetails.push(`Connection log entries found in ${logPath}`);
            const lines = logContent.trim().split("\n").slice(-5);
            for (const line of lines) {
              triggerInfo.accessDetails.push(`  ${line.trim()}`);
            }
          }
        } catch {
          // File not readable
        }
      }
    } else if (canary.path) {
      // For file-based canaries: check if access time changed
      const statResult = await runCommand("stat", ["-c", "%X", canary.path], 5_000);
      if (statResult.exitCode === 0) {
        const currentAccessTime = statResult.stdout.trim();
        triggerInfo.lastAccessed = currentAccessTime;

        if (canary.accessTimeAtDeploy && currentAccessTime !== canary.accessTimeAtDeploy) {
          triggerInfo.triggered = true;
          triggerInfo.severity = "HIGH";
          triggerInfo.accessDetails.push(
            `Access time changed: ${canary.accessTimeAtDeploy} → ${currentAccessTime}`,
          );
        }
      }

      // Check inotifywait log
      const inotifyLogPath = `${CANARY_BASE_DIR}/canary-${canary.id}.log`;
      if (existsSync(inotifyLogPath)) {
        try {
          const logContent = readFileSync(inotifyLogPath, "utf-8");
          if (logContent.trim().length > 0) {
            triggerInfo.triggered = true;
            triggerInfo.severity = "CRITICAL";
            triggerInfo.accessDetails.push(`inotify events detected in ${inotifyLogPath}`);
            const lines = logContent.trim().split("\n").slice(-5);
            for (const line of lines) {
              triggerInfo.accessDetails.push(`  ${line.trim()}`);
            }
          }
        } catch {
          // File not readable
        }
      }
    }

    if (triggerInfo.triggered) {
      result.triggeredCount++;
      // Update canary status in registry
      canary.status = "triggered";
      result.triggered.push(triggerInfo);
    } else {
      result.notTriggered.push(canary.id);
    }
  }

  // Check syslog for honeyport entries
  const syslogResult = await runCommand(
    "grep",
    ["-i", "HONEYPORT", "/var/log/syslog"],
    10_000,
  );
  if (syslogResult.exitCode === 0 && syslogResult.stdout.trim().length > 0) {
    const entries = syslogResult.stdout.trim().split("\n").slice(-10);
    result.syslogEntries = entries;
  }

  // Save updated statuses
  writeRegistry(registry);

  return result;
}

interface RemoveCanaryResult {
  canaryId: string;
  found: boolean;
  fileRemoved: boolean;
  listenerKilled: boolean;
  iptablesRemoved: boolean;
  description: string;
}

async function removeCanary(canaryId: string): Promise<RemoveCanaryResult> {
  const registry = readRegistry();
  const result: RemoveCanaryResult = {
    canaryId,
    found: false,
    fileRemoved: false,
    listenerKilled: false,
    iptablesRemoved: false,
    description: "",
  };

  const canaryIndex = registry.canaries.findIndex((c) => c.id === canaryId);
  if (canaryIndex === -1) {
    result.description = `Canary ${canaryId} not found in registry`;
    return result;
  }

  result.found = true;
  const canary = registry.canaries[canaryIndex];

  // Remove the canary file/directory
  if (canary.path) {
    try {
      if (canary.type === "directory") {
        rmSync(canary.path, { recursive: true, force: true });
      } else {
        unlinkSync(canary.path);
      }
      result.fileRemoved = true;
    } catch {
      // File may already be gone
    }
  }

  // Kill honeyport listener if applicable
  if (canary.type === "honeyport" && canary.pid) {
    const killResult = await runCommand("kill", [String(canary.pid)], 5_000);
    result.listenerKilled = killResult.exitCode === 0;
  }

  // Remove iptables rule if honeyport
  if (canary.type === "honeyport" && canary.port) {
    const iptablesResult = await runCommand(
      "iptables",
      ["-D", "INPUT", "-p", "tcp", "--dport", String(canary.port), "-j", "LOG", "--log-prefix", `HONEYPORT:${canary.port}: `],
      10_000,
    );
    result.iptablesRemoved = iptablesResult.exitCode === 0;
  }

  // Remove inotify log if exists
  const inotifyLogPath = `${CANARY_BASE_DIR}/canary-${canary.id}.log`;
  try {
    if (existsSync(inotifyLogPath)) {
      unlinkSync(inotifyLogPath);
    }
  } catch {
    // Ignore cleanup errors
  }

  // Update registry
  canary.status = "removed";
  writeRegistry(registry);

  result.description = `Canary ${canaryId} (${canary.type}) removed`;

  return result;
}

interface ListCanariesResult {
  totalCanaries: number;
  active: number;
  triggered: number;
  removed: number;
  canaries: CanaryEntry[];
}

function listCanaries(): ListCanariesResult {
  const registry = readRegistry();
  const active = registry.canaries.filter((c) => c.status === "active").length;
  const triggered = registry.canaries.filter((c) => c.status === "triggered").length;
  const removed = registry.canaries.filter((c) => c.status === "removed").length;

  return {
    totalCanaries: registry.canaries.length,
    active,
    triggered,
    removed,
    canaries: registry.canaries,
  };
}

// ── Registration entry point ───────────────────────────────────────────────

export function registerDeceptionTools(server: McpServer): void {
  server.tool(
    "honeypot_manage",
    "Honeypot/deception: deploy canary tokens (file, credential, directory, ssh_key), set up honeyport listeners, check triggers, remove canaries, and list deployed deception assets.",
    {
      action: z
        .enum(["deploy_canary", "deploy_honeyport", "check_triggers", "remove", "list"])
        .describe(
          "Action: deploy_canary=deploy canary token/tripwire, deploy_honeyport=set up honeyport listener, check_triggers=check if canaries triggered, remove=remove a canary, list=list all canaries",
        ),
      canary_type: z
        .enum(["file", "credential", "directory", "ssh_key"])
        .optional()
        .describe("Type of canary to deploy (used with deploy_canary): file, credential, directory, ssh_key"),
      canary_path: z
        .string()
        .optional()
        .describe("Path for canary deployment (used with deploy_canary)"),
      port: z
        .number()
        .optional()
        .describe("Port for honeyport listener (used with deploy_honeyport)"),
      canary_id: z
        .string()
        .optional()
        .describe("ID of canary to remove (used with remove)"),
      output_format: z
        .enum(["text", "json"])
        .optional()
        .default("text")
        .describe("Output format (default text)"),
    },
    async (params) => {
      const { action } = params;
      const outputFormat = params.output_format ?? "text";

      switch (action) {
        // ── deploy_canary ────────────────────────────────────────────────
        case "deploy_canary": {
          try {
            const canaryType = params.canary_type;
            const canaryPath = params.canary_path;

            if (!canaryType) {
              return {
                content: [createErrorContent("deploy_canary requires canary_type parameter")],
                isError: true,
              };
            }
            if (!canaryPath) {
              return {
                content: [createErrorContent("deploy_canary requires canary_path parameter")],
                isError: true,
              };
            }

            const deployResult = await deployCanary(canaryType, canaryPath);

            const output = {
              action: "deploy_canary",
              canaryId: deployResult.canaryId,
              type: deployResult.type,
              path: deployResult.path,
              monitoringSetup: deployResult.monitoringSetup,
              monitoringDetails: deployResult.monitoringDetails,
              description: deployResult.description,
            };

            if (outputFormat === "json") {
              return { content: [formatToolOutput(output)] };
            }

            let text = "Honeypot — Deploy Canary\n\n";
            text += `Canary ID: ${deployResult.canaryId}\n`;
            text += `Type: ${deployResult.type}\n`;
            text += `Path: ${deployResult.path}\n`;
            text += `Monitoring: ${deployResult.monitoringSetup ? "active ✓" : "not set up ⚠"}\n`;
            text += `Details: ${deployResult.monitoringDetails}\n`;
            text += `\n${deployResult.description}\n`;

            return { content: [createTextContent(text)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`deploy_canary failed: ${msg}`)], isError: true };
          }
        }

        // ── deploy_honeyport ─────────────────────────────────────────────
        case "deploy_honeyport": {
          try {
            const port = params.port;

            if (!port) {
              return {
                content: [createErrorContent("deploy_honeyport requires port parameter")],
                isError: true,
              };
            }

            const honeyResult = await deployHoneyport(port);

            const output = {
              action: "deploy_honeyport",
              canaryId: honeyResult.canaryId,
              port: honeyResult.port,
              listenerPid: honeyResult.listenerPid,
              logPath: honeyResult.logPath,
              iptablesRuleAdded: honeyResult.iptablesRuleAdded,
              description: honeyResult.description,
            };

            if (outputFormat === "json") {
              return { content: [formatToolOutput(output)] };
            }

            let text = "Honeypot — Deploy Honeyport\n\n";
            text += `Canary ID: ${honeyResult.canaryId}\n`;
            text += `Port: ${honeyResult.port}\n`;
            text += `Listener PID: ${honeyResult.listenerPid ?? "unknown"}\n`;
            text += `Log Path: ${honeyResult.logPath}\n`;
            text += `Iptables LOG Rule: ${honeyResult.iptablesRuleAdded ? "added ✓" : "not added ⚠"}\n`;
            text += `\n${honeyResult.description}\n`;

            return { content: [createTextContent(text)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`deploy_honeyport failed: ${msg}`)], isError: true };
          }
        }

        // ── check_triggers ───────────────────────────────────────────────
        case "check_triggers": {
          try {
            const triggerResult = await checkTriggers();

            const output = {
              action: "check_triggers",
              totalCanaries: triggerResult.totalCanaries,
              triggeredCount: triggerResult.triggeredCount,
              triggered: triggerResult.triggered,
              notTriggered: triggerResult.notTriggered,
              syslogEntries: triggerResult.syslogEntries,
            };

            if (outputFormat === "json") {
              return { content: [formatToolOutput(output)] };
            }

            let text = "Honeypot — Check Triggers\n\n";
            text += `Total Canaries: ${triggerResult.totalCanaries}\n`;
            text += `Triggered: ${triggerResult.triggeredCount}\n`;
            text += `Not Triggered: ${triggerResult.notTriggered.length}\n\n`;

            if (triggerResult.triggered.length > 0) {
              text += "⚠ TRIGGERED CANARIES:\n";
              for (const t of triggerResult.triggered) {
                text += `\n  • ${t.id} [${t.type}] — Severity: ${t.severity}\n`;
                if (t.path) text += `    Path: ${t.path}\n`;
                if (t.port) text += `    Port: ${t.port}\n`;
                for (const detail of t.accessDetails) {
                  text += `    ${detail}\n`;
                }
              }
            }

            if (triggerResult.notTriggered.length > 0) {
              text += "\nNot Triggered:\n";
              for (const id of triggerResult.notTriggered) {
                text += `  • ${id}\n`;
              }
            }

            if (triggerResult.syslogEntries.length > 0) {
              text += "\nSyslog Honeyport Entries:\n";
              for (const entry of triggerResult.syslogEntries) {
                text += `  • ${entry}\n`;
              }
            }

            return { content: [createTextContent(text)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`check_triggers failed: ${msg}`)], isError: true };
          }
        }

        // ── remove ───────────────────────────────────────────────────────
        case "remove": {
          try {
            const canaryId = params.canary_id;

            if (!canaryId) {
              return {
                content: [createErrorContent("remove requires canary_id parameter")],
                isError: true,
              };
            }

            const removeResult = await removeCanary(canaryId);

            const output = {
              action: "remove",
              canaryId: removeResult.canaryId,
              found: removeResult.found,
              fileRemoved: removeResult.fileRemoved,
              listenerKilled: removeResult.listenerKilled,
              iptablesRemoved: removeResult.iptablesRemoved,
              description: removeResult.description,
            };

            if (outputFormat === "json") {
              return { content: [formatToolOutput(output)] };
            }

            let text = "Honeypot — Remove Canary\n\n";
            if (!removeResult.found) {
              text += `Canary ${canaryId} not found in registry\n`;
            } else {
              text += `Canary ID: ${removeResult.canaryId}\n`;
              text += `File/Directory Removed: ${removeResult.fileRemoved ? "yes ✓" : "no"}\n`;
              if (removeResult.listenerKilled) {
                text += `Listener Killed: yes ✓\n`;
              }
              if (removeResult.iptablesRemoved) {
                text += `Iptables Rule Removed: yes ✓\n`;
              }
              text += `\n${removeResult.description}\n`;
            }

            return { content: [createTextContent(text)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`remove failed: ${msg}`)], isError: true };
          }
        }

        // ── list ─────────────────────────────────────────────────────────
        case "list": {
          try {
            const listResult = listCanaries();

            const output = {
              action: "list",
              totalCanaries: listResult.totalCanaries,
              active: listResult.active,
              triggered: listResult.triggered,
              removed: listResult.removed,
              canaries: listResult.canaries,
            };

            if (outputFormat === "json") {
              return { content: [formatToolOutput(output)] };
            }

            let text = "Honeypot — Canary Registry\n\n";
            text += `Total: ${listResult.totalCanaries}\n`;
            text += `Active: ${listResult.active}\n`;
            text += `Triggered: ${listResult.triggered}\n`;
            text += `Removed: ${listResult.removed}\n\n`;

            if (listResult.canaries.length > 0) {
              text += "Canaries:\n";
              for (const canary of listResult.canaries) {
                text += `\n  • ${canary.id} [${canary.type}] — ${canary.status.toUpperCase()}\n`;
                text += `    Deployed: ${canary.deployedAt}\n`;
                if (canary.path) text += `    Path: ${canary.path}\n`;
                if (canary.port) text += `    Port: ${canary.port}\n`;
                text += `    ${canary.description}\n`;
              }
            } else {
              text += "No canaries deployed\n";
            }

            return { content: [createTextContent(text)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`list failed: ${msg}`)], isError: true };
          }
        }

        default:
          return { content: [createErrorContent(`Unknown action: ${action}`)], isError: true };
      }
    },
  );
}
