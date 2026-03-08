/**
 * SafeguardRegistry — singleton that detects running applications and
 * environmental state so defensive operations can be evaluated for safety.
 *
 * Detection domains:
 *   - VS Code (editor process, config dir, IPC sockets)
 *   - Docker (daemon socket, running containers)
 *   - MCP servers (workspace config + node processes)
 *   - Databases (TCP port probing: PostgreSQL, MySQL, MongoDB, Redis)
 *   - Web servers (nginx, apache2, httpd process detection)
 */

import * as fs from "node:fs";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import { z } from "zod";
import { executeCommand } from "./executor.js";

// ── Zod schemas ──────────────────────────────────────────────────────────────

const OperationSchema = z.string().min(1).max(256);
const ParamsSchema = z.record(z.string(), z.unknown());

// ── Types ────────────────────────────────────────────────────────────────────

export interface SafetyResult {
  safe: boolean;
  warnings: string[];
  blockers: string[];
  impactedApps: string[];
}

export interface DetectedApp {
  category: string;
  detected: boolean;
  detail: string;
}

export interface SafeguardReport {
  timestamp: string;
  detectedApps: DetectedApp[];
  summary: string;
  overallSafe: boolean;
}

// ── Operations that affect specific domains ──────────────────────────────────

const DOCKER_OPERATIONS = [
  "container", "docker", "apparmor", "seccomp", "namespace",
  "image", "rootless",
];

const FIREWALL_OPERATIONS = [
  "firewall", "iptables", "nftables", "ufw", "port", "chain",
  "microsegmentation", "wireguard",
];

const SERVICE_OPERATIONS = [
  "service", "systemd", "systemctl", "enable", "disable",
  "start", "stop", "restart", "daemon",
];

const DATABASE_OPERATIONS = [
  "database", "postgres", "mysql", "mongo", "redis", "port",
];

const WEBSERVER_OPERATIONS = [
  "nginx", "apache", "httpd", "webserver", "tls", "cert",
];

const SSH_OPERATIONS = [
  "ssh", "sshd", "access_ssh",
];

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Check if a TCP port accepts connections (timeout 1s). */
function probePort(port: number, host: string = "127.0.0.1"): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = net.createConnection({ port, host, timeout: 1000 });
    sock.once("connect", () => { sock.destroy(); resolve(true); });
    sock.once("error", () => { resolve(false); });
    sock.once("timeout", () => { sock.destroy(); resolve(false); });
  });
}

/** Run pgrep and return true if at least one process matched. */
async function pgrepExists(pattern: string): Promise<boolean> {
  try {
    const r = await executeCommand({ command: "pgrep", args: ["-f", pattern], timeout: 5000 });
    return r.exitCode === 0 && r.stdout.trim().length > 0;
  } catch {
    return false;
  }
}

function matchesAny(operation: string, keywords: string[]): boolean {
  const lower = operation.toLowerCase();
  return keywords.some((k) => lower.includes(k));
}

/** Check if the current session is over SSH. */
export function isSSHSession(): boolean {
  return !!(process.env.SSH_CONNECTION || process.env.SSH_TTY);
}

/** Check if the current user has a non-empty authorized_keys file. */
export function hasAuthorizedKeys(): boolean {
  try {
    const authKeysPath = path.join(os.homedir(), ".ssh", "authorized_keys");
    if (!fs.existsSync(authKeysPath)) return false;
    const stat = fs.statSync(authKeysPath);
    return stat.size > 0;
  } catch {
    return false;
  }
}

/** Safely extract a string parameter value. */
function getParam(params: Record<string, unknown>, key: string): string | undefined {
  const val = params[key];
  return typeof val === "string" ? val : undefined;
}

/** Check if an SSH-related operation is a modification (not an audit/check). */
function isSSHModification(operation: string, params: Record<string, unknown>): boolean {
  if (operation.includes("audit") || operation.includes("check")) {
    return false;
  }
  if (operation.includes("harden")) return true;
  if (getParam(params, "settings")) return true;
  if (params.apply_recommended === true) return true;
  if (params.restart_sshd === true) return true;
  return false;
}

// ── SafeguardRegistry ────────────────────────────────────────────────────────

// SECURITY (CORE-021): Module-scoped singleton variable prevents external
// mutation via (SafeguardRegistry as any).instance — inaccessible outside module.
let _safeguardInstance: SafeguardRegistry | null = null;

export class SafeguardRegistry {
  /** Cached detection results with TTL to avoid re-running on every tool call */
  private detectionCache: {
    result: { vscode: DetectedApp; docker: DetectedApp; mcp: DetectedApp; dbs: DetectedApp; web: DetectedApp } | null;
    timestamp: number;
  } = { result: null, timestamp: 0 };

  private readonly DETECTION_CACHE_TTL = 15_000; // 15 seconds

  private constructor() {}

  /** Get the singleton instance. */
  static getInstance(): SafeguardRegistry {
    if (!_safeguardInstance) {
      _safeguardInstance = new SafeguardRegistry();
    }
    return _safeguardInstance;
  }

  /** Detect VS Code editor presence. */
  async detectVSCode(): Promise<DetectedApp> {
    const details: string[] = [];
    let detected = false;

    try {
      // Check for running VS Code process
      if (await pgrepExists("code")) {
        details.push("VS Code process running");
        detected = true;
      }

      // Check config directory
      const vscodeDir = path.join(os.homedir(), ".vscode");
      if (fs.existsSync(vscodeDir)) {
        details.push(".vscode config dir exists");
        detected = true;
      }

      // Check for IPC sockets
      const uid = process.getuid?.();
      if (uid !== undefined) {
        const runDir = `/run/user/${uid}`;
        try {
          if (fs.existsSync(runDir)) {
            const entries = fs.readdirSync(runDir);
            const ipc = entries.filter((e) => e.startsWith("vscode-ipc-"));
            if (ipc.length > 0) {
              details.push(`${ipc.length} IPC socket(s) found`);
              detected = true;
            }
          }
        } catch { /* no access */ }
      }
    } catch { /* detection failed gracefully */ }

    return {
      category: "VS Code",
      detected,
      detail: detected ? details.join("; ") : "Not detected",
    };
  }

  /** Detect Docker daemon and running containers. */
  async detectDocker(): Promise<DetectedApp> {
    const details: string[] = [];
    let detected = false;

    try {
      // Check for Docker socket
      if (fs.existsSync("/var/run/docker.sock")) {
        details.push("Docker socket exists");
        detected = true;

        // Try to list running containers
        const r = await executeCommand({
          command: "docker",
          args: ["ps", "--format", "{{.Names}}"],
          timeout: 5000,
        });
        if (r.exitCode === 0) {
          const containers = r.stdout.trim().split("\n").filter(Boolean);
          if (containers.length > 0) {
            details.push(`${containers.length} container(s): ${containers.slice(0, 5).join(", ")}`);
          } else {
            details.push("No running containers");
          }
        }
      }
    } catch { /* detection failed gracefully */ }

    return {
      category: "Docker",
      detected,
      detail: detected ? details.join("; ") : "Not detected",
    };
  }

  /** Detect configured MCP servers. */
  async detectMCPServers(): Promise<DetectedApp> {
    const details: string[] = [];
    let detected = false;

    try {
      // SECURITY (CORE-010): Use environment-aware path instead of hardcoded /home/robert/...
      const mcpConfigPath = path.join(os.homedir(), "kali-mcp-workspace", ".mcp.json");
      if (fs.existsSync(mcpConfigPath)) {
        const raw = fs.readFileSync(mcpConfigPath, "utf-8");
        const config = JSON.parse(raw);
        const servers = config.mcpServers ?? config.servers ?? {};
        const names = Object.keys(servers);
        if (names.length > 0) {
          details.push(`${names.length} MCP server(s) configured: ${names.join(", ")}`);
          detected = true;
        }
      }

      // Check for node processes
      const r = await executeCommand({
        command: "pgrep",
        args: ["-a", "node"],
        timeout: 5000,
      });
      if (r.exitCode === 0) {
        const mcpProcs = r.stdout.split("\n").filter((l) => l.includes("mcp"));
        if (mcpProcs.length > 0) {
          details.push(`${mcpProcs.length} MCP-related node process(es)`);
          detected = true;
        }
      }
    } catch { /* detection failed gracefully */ }

    return {
      category: "MCP Servers",
      detected,
      detail: detected ? details.join("; ") : "Not detected",
    };
  }

  /** Detect databases via TCP port probing. */
  async detectDatabases(): Promise<DetectedApp> {
    const portMap: [number, string][] = [
      [5432, "PostgreSQL"],
      [3306, "MySQL"],
      [27017, "MongoDB"],
      [6379, "Redis"],
    ];

    const results = await Promise.all(
      portMap.map(async ([port, name]) => {
        const open = await probePort(port);
        return open ? name : null;
      })
    );

    const found = results.filter(Boolean) as string[];

    return {
      category: "Databases",
      detected: found.length > 0,
      detail: found.length > 0
        ? `Active: ${found.join(", ")}`
        : "No databases detected on standard ports",
    };
  }

  /** Detect web server processes. */
  async detectWebServers(): Promise<DetectedApp> {
    const servers = ["nginx", "apache2", "httpd"];
    const found: string[] = [];

    for (const name of servers) {
      if (await pgrepExists(name)) {
        found.push(name);
      }
    }

    return {
      category: "Web Servers",
      detected: found.length > 0,
      detail: found.length > 0
        ? `Running: ${found.join(", ")}`
        : "No web servers detected",
    };
  }

  /**
   * Check whether an operation is safe given current system state.
   * Returns warnings (non-blocking) and blockers (operation should not proceed).
   */
  async checkSafety(
    operation: string,
    params: Record<string, unknown>
  ): Promise<SafetyResult> {
    const validOp = OperationSchema.safeParse(operation);
    if (!validOp.success) {
      return {
        safe: false,
        warnings: [],
        blockers: ["Invalid operation name"],
        impactedApps: [],
      };
    }

    const warnings: string[] = [];
    const blockers: string[] = [];
    const impactedApps: string[] = [];

    try {
      // Use cached detections if fresh (system state rarely changes within 15s)
      let vscode: DetectedApp, docker: DetectedApp, mcp: DetectedApp, dbs: DetectedApp, web: DetectedApp;
      const now = Date.now();
      if (this.detectionCache.result && (now - this.detectionCache.timestamp) < this.DETECTION_CACHE_TTL) {
        ({ vscode, docker, mcp, dbs, web } = this.detectionCache.result);
      } else {
        [vscode, docker, mcp, dbs, web] = await Promise.all([
          this.detectVSCode(),
          this.detectDocker(),
          this.detectMCPServers(),
          this.detectDatabases(),
          this.detectWebServers(),
        ]);
        this.detectionCache = { result: { vscode, docker, mcp, dbs, web }, timestamp: now };
      }

      const detections = [vscode, docker, mcp, dbs, web];

      // Check Docker impact
      if (docker.detected && matchesAny(operation, DOCKER_OPERATIONS)) {
        warnings.push(`Docker is active (${docker.detail}) — operation may affect containers`);
        impactedApps.push("Docker");
      }

      // Check firewall impact
      if (matchesAny(operation, FIREWALL_OPERATIONS)) {
        if (docker.detected) {
          warnings.push("Firewall changes may disrupt Docker networking");
          impactedApps.push("Docker");
        }
        if (dbs.detected) {
          warnings.push(`Database connectivity may be affected (${dbs.detail})`);
          impactedApps.push("Databases");
        }
        if (web.detected) {
          warnings.push(`Web server traffic may be affected (${web.detail})`);
          impactedApps.push("Web Servers");
        }
        if (mcp.detected) {
          warnings.push("Firewall changes may affect MCP server communication");
          impactedApps.push("MCP Servers");
        }
      }

      // Check service impact
      if (matchesAny(operation, SERVICE_OPERATIONS)) {
        if (docker.detected) {
          warnings.push("Service changes may affect Docker daemon");
          impactedApps.push("Docker");
        }
        if (web.detected) {
          warnings.push(`Web server services may be affected (${web.detail})`);
          impactedApps.push("Web Servers");
        }
      }

      // Check database impact
      if (matchesAny(operation, DATABASE_OPERATIONS) && dbs.detected) {
        warnings.push(`Active databases detected (${dbs.detail}) — proceed with caution`);
        impactedApps.push("Databases");
      }

      // Check web server impact
      if (matchesAny(operation, WEBSERVER_OPERATIONS) && web.detected) {
        warnings.push(`Active web servers detected (${web.detail})`);
        impactedApps.push("Web Servers");
      }

      // VS Code — informational only
      if (vscode.detected) {
        warnings.push(`VS Code is active (${vscode.detail})`);
      }

      // ── Blocker checks (prevent dangerous operations) ───────────────────

      // A. SSH lockout prevention — block SSH config changes during SSH session
      if (
        isSSHSession() &&
        matchesAny(operation, SSH_OPERATIONS) &&
        isSSHModification(operation, params)
      ) {
        blockers.push(
          "BLOCKED: Cannot modify SSH configuration while connected via SSH. " +
            "Changes could lock you out of this remote session. " +
            "Use a local console or ensure alternative access before proceeding.",
        );
      }

      // B. Firewall rules blocking active SSH connections
      if (isSSHSession() && matchesAny(operation, FIREWALL_OPERATIONS)) {
        const port = getParam(params, "port");
        const fwAction = getParam(params, "action")?.toUpperCase();
        const policy = getParam(params, "policy")?.toUpperCase();
        const chain = getParam(params, "chain")?.toUpperCase();

        // Block rules that would drop/reject traffic on SSH port
        if (
          port === "22" &&
          (fwAction === "DROP" || fwAction === "REJECT" || fwAction === "DENY")
        ) {
          blockers.push(
            "BLOCKED: Firewall rule would block SSH port 22 while connected via SSH. " +
              "This would immediately terminate your session.",
          );
        }

        // Block default DROP policy on INPUT chain (would kill SSH)
        if (policy === "DROP" && chain === "INPUT") {
          blockers.push(
            "BLOCKED: Setting INPUT chain default policy to DROP while connected via SSH. " +
              "Ensure an explicit ACCEPT rule for SSH port exists before changing the default policy.",
          );
        }
      }

      // C. Disabling password auth without SSH key auth configured
      if (matchesAny(operation, SSH_OPERATIONS)) {
        const settings = getParam(params, "settings") ?? "";
        const applyRecommended = params.apply_recommended === true;

        if (
          settings.toLowerCase().includes("passwordauthentication=no") ||
          applyRecommended
        ) {
          if (!hasAuthorizedKeys()) {
            blockers.push(
              "BLOCKED: Disabling password authentication without confirming SSH key-based " +
                "access is configured. No authorized_keys file found for the current user. " +
                "Set up SSH key authentication first, then retry.",
            );
          }
        }
      }

      // D. Stopping critical database services with active connections
      if (matchesAny(operation, SERVICE_OPERATIONS)) {
        const svcAction = getParam(params, "action")?.toLowerCase();
        const svcName = getParam(params, "service")?.toLowerCase() ?? "";

        if (svcAction === "stop" || svcAction === "disable" || svcAction === "mask") {
          const dbServiceNames = [
            "postgresql", "postgres", "mysql", "mysqld", "mariadb",
            "mongod", "mongodb", "redis", "redis-server",
          ];
          const isDatabase = dbServiceNames.some((db) => svcName.includes(db));

          if (isDatabase && dbs.detected) {
            blockers.push(
              `BLOCKED: Cannot ${svcAction} database service '${svcName}' while it has ` +
                `active connections (${dbs.detail}). ` +
                `Drain connections first or use '--force' parameter.`,
            );
          }
        }
      }
    } catch (err) {
      warnings.push(`Safety check encountered an error: ${err instanceof Error ? err.message : String(err)}`);
    }

    return {
      safe: blockers.length === 0,
      warnings,
      blockers,
      impactedApps: [...new Set(impactedApps)],
    };
  }

  /** Generate a full safety report of all detected applications. */
  async appSafetyReport(): Promise<SafeguardReport> {
    // Reuse detection cache if fresh
    let vscode: DetectedApp, docker: DetectedApp, mcp: DetectedApp, dbs: DetectedApp, web: DetectedApp;
    const now = Date.now();
    if (this.detectionCache.result && (now - this.detectionCache.timestamp) < this.DETECTION_CACHE_TTL) {
      ({ vscode, docker, mcp, dbs, web } = this.detectionCache.result);
    } else {
      [vscode, docker, mcp, dbs, web] = await Promise.all([
        this.detectVSCode(),
        this.detectDocker(),
        this.detectMCPServers(),
        this.detectDatabases(),
        this.detectWebServers(),
      ]);
      this.detectionCache = { result: { vscode, docker, mcp, dbs, web }, timestamp: now };
    }

    const detectedApps = [vscode, docker, mcp, dbs, web];
    const activeCount = detectedApps.filter((a) => a.detected).length;

    return {
      timestamp: new Date().toISOString(),
      detectedApps,
      summary: `${activeCount} of ${detectedApps.length} application categories detected`,
      overallSafe: true,
    };
  }
}
