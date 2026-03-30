import { homedir } from "node:os";
import { join } from "node:path";
import { getRecommendedTimeout } from "./tool-durations.js";

/**
 * Known defensive tools that support per-tool timeout overrides
 * via DEFENSE_MCP_TIMEOUT_<TOOL> environment variables.
 */
export const KNOWN_TOOLS = [
  "lynis",
  "aide",
  "clamav",
  "oscap",
  "snort",
  "suricata",
  "rkhunter",
  "chkrootkit",
  "tcpdump",
  "auditd",
  "nmap",
  "fail2ban-client",
  "debsums",
  "yara",
] as const;

export type KnownTool = (typeof KNOWN_TOOLS)[number];

/**
 * Configuration interface for the Defense MCP Server.
 * All values are derived from environment variables with sensible defaults.
 */
export interface DefenseConfig {
  /** Default command timeout in milliseconds */
  defaultTimeout: number;
  /** Maximum output buffer size in bytes */
  maxBuffer: number;
  /** Directories allowed for file operations */
  allowedDirs: string[];
  /** Logging level */
  logLevel: "debug" | "info" | "warn" | "error";
  /**
   * SECURITY (CICD-014): Dry-run mode — when true, modifying operations preview
   * commands without executing them. Defaults to `true` so the server operates
   * in a safe, read-only mode until explicitly opted out via
   * DEFENSE_MCP_DRY_RUN=false. This prevents accidental system modifications.
   */
  dryRun: boolean;
  /** Path to the changelog JSON file */
  changelogPath: string;
  /** Directory for file backups */
  backupDir: string;
  /**
   * SECURITY (CICD-014): Whether to create backups before modifying files.
   * Defaults to `true` — every file modification is backed up first so that
   * changes can be rolled back if needed. Disable only in CI/test environments
   * via DEFENSE_MCP_BACKUP_ENABLED=false.
   */
  backupEnabled: boolean;
  /** Whether to auto-install missing tools */
  autoInstall: boolean;
  /** Paths protected from modification */
  protectedPaths: string[];
  /**
   * SECURITY (CICD-014): Whether to require confirmation for destructive
   * actions. Defaults to `true` — the server will request explicit confirmation
   * before executing operations that modify system state. Disable only when
   * running automated/unattended workflows via
   * DEFENSE_MCP_REQUIRE_CONFIRMATION=false.
   */
  requireConfirmation: boolean;
  /** Directory for quarantined files */
  quarantineDir: string;
  /** Directory for policy files */
  policyDir: string;
  /** Per-tool timeout overrides in milliseconds */
  toolTimeouts: Partial<Record<KnownTool, number>>;
  /** Sudo session timeout in milliseconds (default: 15 minutes) */
  sudoSessionTimeout: number;
  /** Command execution timeout in ms (falls back to defaultTimeout; env: DEFENSE_MCP_COMMAND_TIMEOUT) */
  commandTimeout: number;
  /** Network operation timeout in ms (default: 30s; env: DEFENSE_MCP_NETWORK_TIMEOUT) */
  networkTimeout: number;
}

/**
 * Resolves `~` prefix to the user's home directory.
 */
function expandHome(p: string): string {
  if (p.startsWith("~/") || p === "~") {
    return join(homedir(), p.slice(1));
  }
  return p;
}

/**
 * Parses a comma-separated list of paths from an environment variable.
 */
/**
 * SECURITY (CORE-012): Directories that are too broad to be allowed.
 * These grant access to the entire filesystem or critical root-level trees.
 */
const REJECTED_DIRS = new Set(["/"]);

/** Directories that are very broad and deserve a warning. */
const BROAD_DIRS = new Set(["/usr", "/var", "/etc", "/opt", "/lib", "/lib64", "/sbin", "/bin"]);

function parsePaths(value: string | undefined, defaultValue: string): string[] {
  const raw = value ?? defaultValue;
  const paths = raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
    .map(expandHome);

  // SECURITY (CORE-012): Validate allowedDirs to reject overly broad paths
  return paths.filter((p) => {
    // Reject root directory and single-character root-level paths (e.g. "/")
    if (REJECTED_DIRS.has(p) || (p.startsWith("/") && p.length <= 2 && p !== "/" + p.slice(1).replace(/\//g, ""))) {
      console.error(
        `[DEFENSE-MCP] SECURITY: Rejecting overly broad allowedDir '${p}' — ` +
        `granting access to the entire filesystem is not permitted.`
      );
      return false;
    }
    // Reject any single-character root-level path like "/x"
    if (/^\/[^/]$/.test(p)) {
      console.error(
        `[DEFENSE-MCP] SECURITY: Rejecting overly broad allowedDir '${p}' — ` +
        `single-character root-level paths are not permitted.`
      );
      return false;
    }
    // Warn about broad directories
    if (BROAD_DIRS.has(p)) {
      console.error(
        `[DEFENSE-MCP] WARNING: allowedDir '${p}' is very broad. ` +
        `Consider using a more specific subdirectory.`
      );
    }
    return true;
  });
}

/**
 * Parses a log level string, falling back to "info" if invalid.
 */
function parseLogLevel(
  value: string | undefined
): "debug" | "info" | "warn" | "error" {
  const valid = ["debug", "info", "warn", "error"];
  const lower = (value ?? "info").toLowerCase();
  return valid.includes(lower)
    ? (lower as "debug" | "info" | "warn" | "error")
    : "info";
}

/**
 * Reads per-tool timeout overrides from environment variables.
 * Format: DEFENSE_MCP_TIMEOUT_<TOOL> (value in seconds, stored as ms).
 */
function parseToolTimeouts(): Partial<Record<KnownTool, number>> {
  const timeouts: Partial<Record<KnownTool, number>> = {};
  for (const tool of KNOWN_TOOLS) {
    const envKey = `DEFENSE_MCP_TIMEOUT_${tool.toUpperCase()}`;
    const value = process.env[envKey];
    if (value !== undefined) {
      const seconds = parseInt(value, 10);
      if (!isNaN(seconds) && seconds > 0) {
        timeouts[tool] = seconds * 1000;
      }
    }
  }
  return timeouts;
}

// ── Config cache (avoids re-parsing 15+ env vars on every call) ──────────────

let _configCache: DefenseConfig | null = null;
let _configCacheTimestamp = 0;
const CONFIG_CACHE_TTL = 5_000; // 5 seconds

/**
 * Returns the current configuration by reading environment variables.
 * Results are cached for 5 seconds to avoid redundant env-var parsing
 * across the 3–5 calls per tool invocation.
 */
export function getConfig(): DefenseConfig {
  const now = Date.now();
  if (_configCache && (now - _configCacheTimestamp) < CONFIG_CACHE_TTL) {
    return _configCache;
  }
  _configCache = buildConfigFromEnv();
  _configCacheTimestamp = now;
  return _configCache;
}

/**
 * Build the configuration object by reading all environment variables.
 * This is the actual parsing logic, called by the cached `getConfig()` wrapper.
 */
function buildConfigFromEnv(): DefenseConfig {
  const defaultTimeoutSec = parseInt(
    process.env.DEFENSE_MCP_TIMEOUT_DEFAULT ?? "120",
    10
  );
  const maxBufferBytes = parseInt(
    process.env.DEFENSE_MCP_MAX_OUTPUT_SIZE ?? String(10 * 1024 * 1024),
    10
  );

  const config: DefenseConfig = {
    defaultTimeout:
      isNaN(defaultTimeoutSec) || defaultTimeoutSec <= 0
        ? 120_000
        : defaultTimeoutSec * 1000,
    maxBuffer:
      isNaN(maxBufferBytes) || maxBufferBytes <= 0
        ? 10 * 1024 * 1024
        : maxBufferBytes,
    // SECURITY (CICD-013): /etc is excluded from default allowedDirs because it
    // contains sensitive system configuration files (shadow, sudoers, ssh configs).
    // Granting default read/write access to /etc is too permissive. Tools that
    // need /etc access should require explicit configuration via
    // DEFENSE_MCP_ALLOWED_DIRS=/tmp,/home,/var/log,/etc
    allowedDirs: parsePaths(
      process.env.DEFENSE_MCP_ALLOWED_DIRS,
      "/tmp,/home,/var/log"
    ),
    logLevel: parseLogLevel(process.env.DEFENSE_MCP_LOG_LEVEL),
    // SECURITY (CICD-014): Default to dry-run=true (safe preview mode)
    // Set DEFENSE_MCP_DRY_RUN=false to enable live system modifications
    dryRun: process.env.DEFENSE_MCP_DRY_RUN !== "false",
    changelogPath: expandHome(
      process.env.DEFENSE_MCP_CHANGELOG_PATH ??
        "~/.defense-mcp/changelog.json"
    ),
    backupDir: expandHome(
      process.env.DEFENSE_MCP_BACKUP_DIR ?? "~/.defense-mcp/backups"
    ),
    // SECURITY (CICD-014): Backup before modify — enabled by default
    // Set DEFENSE_MCP_BACKUP_ENABLED=false only in CI/test environments
    backupEnabled: process.env.DEFENSE_MCP_BACKUP_ENABLED !== "false",
    autoInstall: process.env.DEFENSE_MCP_AUTO_INSTALL === "true",
    protectedPaths: parsePaths(
      process.env.DEFENSE_MCP_PROTECTED_PATHS,
      "/boot,/usr/lib/systemd,/usr/bin,/usr/sbin"
    ),
    requireConfirmation:
      process.env.DEFENSE_MCP_REQUIRE_CONFIRMATION !== "false",
    quarantineDir: expandHome(
      process.env.DEFENSE_MCP_QUARANTINE_DIR ?? "~/.defense-mcp/quarantine"
    ),
    policyDir: expandHome(
      process.env.DEFENSE_MCP_POLICY_DIR ?? "~/.defense-mcp/policies"
    ),
    toolTimeouts: parseToolTimeouts(),
    sudoSessionTimeout: (() => {
      const envVal = process.env.DEFENSE_MCP_SUDO_TIMEOUT;
      if (envVal) {
        const minutes = parseInt(envVal, 10);
        if (!isNaN(minutes) && minutes > 0) return minutes * 60 * 1000;
      }
      return 15 * 60 * 1000; // default: 15 minutes
    })(),
    commandTimeout: (() => {
      const sec = parseInt(process.env.DEFENSE_MCP_COMMAND_TIMEOUT ?? "120", 10);
      return isNaN(sec) || sec <= 0 ? 120_000 : sec * 1000;
    })(),
    networkTimeout: (() => {
      const sec = parseInt(process.env.DEFENSE_MCP_NETWORK_TIMEOUT ?? "30", 10);
      return isNaN(sec) || sec <= 0 ? 30_000 : sec * 1000;
    })(),
  };

  // Warn when dry-run is active so operators know no changes will be applied
  if (config.dryRun) {
    console.error("[DEFENSE-MCP] DRY_RUN mode is ACTIVE — no changes will be applied");
  }

  return config;
}

/**
 * Invalidate the config cache, forcing the next `getConfig()` call to
 * re-read environment variables. Useful for tests.
 */
export function invalidateConfigCache(): void {
  _configCache = null;
  _configCacheTimestamp = 0;
}

/**
 * Returns the effective timeout for a given tool in milliseconds.
 * Checks per-tool overrides first, then falls back to the default timeout.
 */
export function getToolTimeout(
  toolName: string,
  config?: DefenseConfig
): number {
  const cfg = config ?? getConfig();
  const lowerName = toolName.toLowerCase() as KnownTool;
  return cfg.toolTimeouts[lowerName] ?? cfg.defaultTimeout;
}

/**
 * Returns the effective timeout for a specific tool action in milliseconds.
 *
 * Resolution order:
 * 1. Per-tool env override (DEFENSE_MCP_TIMEOUT_<TOOL>)
 * 2. Duration database recommended timeout for the specific action
 * 3. Default timeout from config
 *
 * This ensures long-running tools (ClamAV, rkhunter, AIDE) get appropriate
 * timeouts automatically without requiring env var configuration.
 */
export function getActionTimeout(
  toolName: string,
  action: string,
  config?: DefenseConfig
): number {
  const cfg = config ?? getConfig();
  const lowerName = toolName.toLowerCase() as KnownTool;

  // 1. Explicit per-tool env override always wins
  const envOverride = cfg.toolTimeouts[lowerName];
  if (envOverride !== undefined) {
    return envOverride;
  }

  // 2. Duration database recommended timeout for the specific action
  const recommended = getRecommendedTimeout(toolName, action, undefined);
  if (recommended) {
    return recommended;
  }

  // 3. Fall back to default
  return cfg.defaultTimeout;
}
