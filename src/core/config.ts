import { homedir } from "node:os";
import { join } from "node:path";

/**
 * Known defensive tools that support per-tool timeout overrides
 * via KALI_DEFENSE_TIMEOUT_<TOOL> environment variables.
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
 * Configuration interface for the Kali Defense MCP Server.
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
  /** Whether to run in dry-run mode (no changes applied) */
  dryRun: boolean;
  /** Path to the changelog JSON file */
  changelogPath: string;
  /** Directory for file backups */
  backupDir: string;
  /** Whether to auto-install missing tools */
  autoInstall: boolean;
  /** Paths protected from modification */
  protectedPaths: string[];
  /** Whether to require confirmation for destructive actions */
  requireConfirmation: boolean;
  /** Directory for quarantined files */
  quarantineDir: string;
  /** Directory for policy files */
  policyDir: string;
  /** Per-tool timeout overrides in milliseconds */
  toolTimeouts: Partial<Record<KnownTool, number>>;
  /** Sudo session timeout in milliseconds (default: 15 minutes) */
  sudoSessionTimeout: number;
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
function parsePaths(value: string | undefined, defaultValue: string): string[] {
  const raw = value ?? defaultValue;
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
    .map(expandHome);
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
 * Format: KALI_DEFENSE_TIMEOUT_<TOOL> (value in seconds, stored as ms).
 */
function parseToolTimeouts(): Partial<Record<KnownTool, number>> {
  const timeouts: Partial<Record<KnownTool, number>> = {};
  for (const tool of KNOWN_TOOLS) {
    const envKey = `KALI_DEFENSE_TIMEOUT_${tool.toUpperCase()}`;
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

/**
 * Returns the current configuration by reading environment variables.
 * Called fresh each invocation to pick up runtime changes.
 */
export function getConfig(): DefenseConfig {
  const defaultTimeoutSec = parseInt(
    process.env.KALI_DEFENSE_TIMEOUT_DEFAULT ?? "120",
    10
  );
  const maxBufferBytes = parseInt(
    process.env.KALI_DEFENSE_MAX_OUTPUT_SIZE ?? String(10 * 1024 * 1024),
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
    allowedDirs: parsePaths(
      process.env.KALI_DEFENSE_ALLOWED_DIRS,
      "/tmp,/home,/var/log,/etc"
    ),
    logLevel: parseLogLevel(process.env.KALI_DEFENSE_LOG_LEVEL),
    dryRun: process.env.KALI_DEFENSE_DRY_RUN === "true",
    changelogPath: expandHome(
      process.env.KALI_DEFENSE_CHANGELOG_PATH ??
        "~/.kali-defense/changelog.json"
    ),
    backupDir: expandHome(
      process.env.KALI_DEFENSE_BACKUP_DIR ?? "~/.kali-defense/backups"
    ),
    autoInstall: process.env.KALI_DEFENSE_AUTO_INSTALL === "true",
    protectedPaths: parsePaths(
      process.env.KALI_DEFENSE_PROTECTED_PATHS,
      "/boot,/usr/lib/systemd,/usr/bin,/usr/sbin"
    ),
    requireConfirmation:
      process.env.KALI_DEFENSE_REQUIRE_CONFIRMATION !== "false",
    quarantineDir: expandHome(
      process.env.KALI_DEFENSE_QUARANTINE_DIR ?? "~/.kali-defense/quarantine"
    ),
    policyDir: expandHome(
      process.env.KALI_DEFENSE_POLICY_DIR ?? "~/.kali-defense/policies"
    ),
    toolTimeouts: parseToolTimeouts(),
    sudoSessionTimeout: (() => {
      const envVal = process.env.KALI_DEFENSE_SUDO_TIMEOUT;
      if (envVal) {
        const minutes = parseInt(envVal, 10);
        if (!isNaN(minutes) && minutes > 0) return minutes * 60 * 1000;
      }
      return 15 * 60 * 1000; // default: 15 minutes
    })(),
  };

  // Warn when dry-run is active so operators know no changes will be applied
  if (config.dryRun) {
    console.error("[KALI-DEFENSE] DRY_RUN mode is ACTIVE — no changes will be applied");
  }

  return config;
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
