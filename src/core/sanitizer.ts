import { resolve, normalize, sep } from "node:path";
import { realpathSync } from "node:fs";
import { getConfig, type DefenseConfig } from "./config.js";

/**
 * Regex matching dangerous shell metacharacters.
 * These characters could enable command injection if passed unsanitized.
 */
const SHELL_METACHAR_RE = /[;|&$`(){}<>!\\\n\r]/;

/**
 * Regex matching control characters (excluding tab, newline, carriage return
 * which are handled by SHELL_METACHAR_RE where dangerous).
 */
const CONTROL_CHAR_RE = /[\x00-\x08\x0e-\x1f\x7f]/;

/**
 * Regex matching path traversal components (`..` as a directory segment).
 */
const PATH_TRAVERSAL_RE = /(^|[\/\\])\.\.([\/\\]|$)/;

/**
 * Validates a target string as hostname, IPv4, IPv6, or CIDR notation.
 * Throws on invalid input.
 */
export function validateTarget(target: string, config?: DefenseConfig): string {
  if (!target || typeof target !== "string") {
    throw new Error("Target must be a non-empty string");
  }

  const trimmed = target.trim();

  if (SHELL_METACHAR_RE.test(trimmed)) {
    throw new Error(`Target contains forbidden shell metacharacters: ${trimmed}`);
  }

  if (CONTROL_CHAR_RE.test(trimmed)) {
    throw new Error(`Target contains control characters: ${trimmed}`);
  }

  // IPv4 with optional CIDR
  const ipv4Re =
    /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
  // IPv6 (simplified)
  const ipv6Re =
    /^[0-9a-fA-F:]+(%[a-zA-Z0-9]+)?(\/\d{1,3})?$/;
  // Hostname
  const hostnameRe =
    /^[a-zA-Z0-9]([a-zA-Z0-9._-]{0,253}[a-zA-Z0-9])?$/;

  if (
    !ipv4Re.test(trimmed) &&
    !ipv6Re.test(trimmed) &&
    !hostnameRe.test(trimmed)
  ) {
    throw new Error(`Invalid target format: ${trimmed}`);
  }

  // Validate IPv4 octets if it looks like IPv4
  if (ipv4Re.test(trimmed)) {
    const ipPart = trimmed.split("/")[0];
    const octets = ipPart.split(".").map(Number);
    if (octets.some((o) => o < 0 || o > 255)) {
      throw new Error(`Invalid IPv4 address: ${trimmed}`);
    }
    // Validate CIDR prefix
    if (trimmed.includes("/")) {
      const prefix = parseInt(trimmed.split("/")[1], 10);
      if (prefix < 0 || prefix > 32) {
        throw new Error(`Invalid CIDR prefix: ${trimmed}`);
      }
    }
  }

  return trimmed;
}

/**
 * Validates a single port number (1-65535).
 * Throws on invalid input.
 */
export function validatePort(port: number | string): number {
  const num = typeof port === "string" ? parseInt(port, 10) : port;
  if (isNaN(num) || num < 1 || num > 65535 || !Number.isInteger(num)) {
    throw new Error(`Invalid port number: ${port}. Must be 1-65535`);
  }
  return num;
}

/**
 * Validates a port range specification (e.g., "80,443,1-1024").
 * Throws on invalid input.
 */
export function validatePortRange(range: string): string {
  if (!range || typeof range !== "string") {
    throw new Error("Port range must be a non-empty string");
  }

  const trimmed = range.trim();

  if (SHELL_METACHAR_RE.test(trimmed)) {
    throw new Error(
      `Port range contains forbidden shell metacharacters: ${trimmed}`
    );
  }

  const portRangeRe = /^(\d{1,5}(-\d{1,5})?,)*\d{1,5}(-\d{1,5})?$/;
  if (!portRangeRe.test(trimmed)) {
    throw new Error(`Invalid port range format: ${trimmed}`);
  }

  // Validate individual port numbers and ranges
  const parts = trimmed.split(",");
  for (const part of parts) {
    if (part.includes("-")) {
      const [startStr, endStr] = part.split("-");
      const start = parseInt(startStr, 10);
      const end = parseInt(endStr, 10);
      if (start < 1 || start > 65535 || end < 1 || end > 65535) {
        throw new Error(`Port out of range in: ${part}`);
      }
      if (start > end) {
        throw new Error(`Invalid port range (start > end): ${part}`);
      }
    } else {
      const p = parseInt(part, 10);
      if (p < 1 || p > 65535) {
        throw new Error(`Port out of range: ${part}`);
      }
    }
  }

  return trimmed;
}

/**
 * Validates a file path is within allowed directories,
 * contains no traversal attacks, no null bytes, no shell metacharacters.
 * Throws on invalid input.
 */
export function validateFilePath(
  filePath: string,
  config?: DefenseConfig
): string {
  if (!filePath || typeof filePath !== "string") {
    throw new Error("File path must be a non-empty string");
  }

  // Check for null bytes
  if (filePath.includes("\0")) {
    throw new Error("File path contains null bytes");
  }

  // Check for path traversal
  if (PATH_TRAVERSAL_RE.test(filePath)) {
    throw new Error(
      "Path contains forbidden directory traversal (..)"
    );
  }

  // Check for shell metacharacters
  if (SHELL_METACHAR_RE.test(filePath)) {
    throw new Error(
      `File path contains forbidden shell metacharacters: ${filePath}`
    );
  }

  // Check for control characters
  if (CONTROL_CHAR_RE.test(filePath)) {
    throw new Error(`File path contains control characters: ${filePath}`);
  }

  const normalized = normalize(resolve(filePath));
  const cfg = config ?? getConfig();

  // Check path traversal - ensure resolved path doesn't escape allowed dirs
  const isAllowed = cfg.allowedDirs.some((dir) => {
    const normalizedDir = normalize(resolve(dir));
    return (
      normalized === normalizedDir || normalized.startsWith(normalizedDir + "/")
    );
  });

  if (!isAllowed) {
    throw new Error(
      `File path is not within allowed directories: ${filePath} (allowed: ${cfg.allowedDirs.join(", ")})`
    );
  }

  // Check against protected paths
  const isProtected = cfg.protectedPaths.some((protectedPath) => {
    const normalizedProtected = normalize(resolve(protectedPath));
    return (
      normalized === normalizedProtected ||
      normalized.startsWith(normalizedProtected + "/")
    );
  });

  if (isProtected) {
    throw new Error(`File path is in a protected location: ${filePath}`);
  }

  // Symlink protection: resolve symlinks and re-validate the resolved path
  // against allowed directories. Only for paths that exist on disk.
  try {
    const realResolved = realpathSync(normalized);
    const realInAllowed = cfg.allowedDirs.some((dir) => {
      const normalizedDir = normalize(resolve(dir));
      return (
        realResolved === normalizedDir ||
        realResolved.startsWith(normalizedDir + "/")
      );
    });

    if (!realInAllowed) {
      throw new Error(
        `Path '${filePath}' resolves to '${realResolved}' which is outside allowed directories: ` +
        `[${cfg.allowedDirs.join(", ")}]. Possible symlink attack.`
      );
    }
  } catch (err: unknown) {
    if (err instanceof Error && err.message.includes("symlink attack")) {
      throw err; // Re-throw our own security errors
    }
    // File doesn't exist yet (e.g., creating a new file) — skip realpath check.
    // The string-level validation above is sufficient for non-existent paths.
  }

  return normalized;
}

/**
 * Validates an array of arguments for shell metacharacters.
 * Throws on invalid input.
 */
export function sanitizeArgs(args: string[]): string[] {
  if (!Array.isArray(args)) {
    throw new Error("Arguments must be an array of strings");
  }

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (typeof arg !== "string") {
      throw new Error(`Argument at index ${i} is not a string`);
    }
    if (SHELL_METACHAR_RE.test(arg)) {
      throw new Error(
        `Argument at index ${i} contains forbidden shell metacharacters: ${arg}`
      );
    }
    if (CONTROL_CHAR_RE.test(arg)) {
      throw new Error(
        `Argument at index ${i} contains control characters: ${arg}`
      );
    }
  }

  return args;
}

/**
 * Validates a systemd service name.
 * Only allows `[a-zA-Z0-9._@-]+`.
 * Throws on invalid input.
 */
export function validateServiceName(name: string): string {
  if (!name || typeof name !== "string") {
    throw new Error("Service name must be a non-empty string");
  }

  const trimmed = name.trim();
  const serviceRe = /^[a-zA-Z0-9._@-]+$/;
  if (!serviceRe.test(trimmed)) {
    throw new Error(
      `Invalid service name: ${trimmed}. Only [a-zA-Z0-9._@-] allowed`
    );
  }

  return trimmed;
}

/**
 * Validates a sysctl key (must be word.word.word... pattern).
 * Throws on invalid input.
 */
export function validateSysctlKey(key: string): string {
  if (!key || typeof key !== "string") {
    throw new Error("Sysctl key must be a non-empty string");
  }

  const trimmed = key.trim();
  const sysctlRe = /^[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+)+$/;
  if (!sysctlRe.test(trimmed)) {
    throw new Error(
      `Invalid sysctl key: ${trimmed}. Must match word.word.word pattern`
    );
  }

  return trimmed;
}

/**
 * Validates a configuration key.
 * Only allows `[a-zA-Z0-9._-]+`.
 * Throws on invalid input.
 */
export function validateConfigKey(key: string): string {
  if (!key || typeof key !== "string") {
    throw new Error("Config key must be a non-empty string");
  }

  const trimmed = key.trim();
  const configRe = /^[a-zA-Z0-9._-]+$/;
  if (!configRe.test(trimmed)) {
    throw new Error(
      `Invalid config key: ${trimmed}. Only [a-zA-Z0-9._-] allowed`
    );
  }

  return trimmed;
}

/**
 * Validates a package name.
 * Only allows `[a-zA-Z0-9._+:-]+`.
 * Throws on invalid input.
 */
export function validatePackageName(name: string): string {
  if (!name || typeof name !== "string") {
    throw new Error("Package name must be a non-empty string");
  }

  const trimmed = name.trim();
  const pkgRe = /^[a-zA-Z0-9._+:-]+$/;
  if (!pkgRe.test(trimmed)) {
    throw new Error(
      `Invalid package name: ${trimmed}. Only [a-zA-Z0-9._+:-] allowed`
    );
  }

  return trimmed;
}

/**
 * Validates an iptables chain name.
 * Allows built-in chains `[A-Z_]+` (e.g., INPUT, OUTPUT, FORWARD)
 * and custom chains matching `[A-Za-z_][A-Za-z0-9_-]{0,28}`.
 * Throws on invalid input.
 */
export function validateIptablesChain(chain: string): string {
  if (!chain || typeof chain !== "string") {
    throw new Error("Iptables chain must be a non-empty string");
  }

  const trimmed = chain.trim();
  // Allow both built-in (e.g. INPUT) and custom chains (e.g. syn_flood)
  const chainRe = /^[A-Za-z_][A-Za-z0-9_-]{0,28}$/;
  if (!chainRe.test(trimmed)) {
    throw new Error(
      `Invalid iptables chain: ${trimmed}. Must match [A-Za-z_][A-Za-z0-9_-]{0,28}`
    );
  }

  return trimmed;
}

/**
 * Validates a network interface name.
 * Only allows `[a-zA-Z0-9._-]+`, max 16 characters.
 * Throws on invalid input.
 */
export function validateInterface(iface: string): string {
  if (!iface || typeof iface !== "string") {
    throw new Error("Interface name must be a non-empty string");
  }

  const trimmed = iface.trim();
  if (trimmed.length > 16) {
    throw new Error(
      `Interface name too long: ${trimmed}. Maximum 16 characters`
    );
  }

  const ifaceRe = /^[a-zA-Z0-9._-]+$/;
  if (!ifaceRe.test(trimmed)) {
    throw new Error(
      `Invalid interface name: ${trimmed}. Only [a-zA-Z0-9._-] allowed`
    );
  }

  return trimmed;
}

/**
 * Validates a Unix username.
 * Only allows `[a-zA-Z0-9._-]+`, max 32 characters.
 * Throws on invalid input.
 */
export function validateUsername(name: string): string {
  if (!name || typeof name !== "string") {
    throw new Error("Username must be a non-empty string");
  }

  const trimmed = name.trim();
  if (trimmed.length > 32) {
    throw new Error(`Username too long: ${trimmed}. Maximum 32 characters`);
  }

  const usernameRe = /^[a-zA-Z0-9._-]+$/;
  if (!usernameRe.test(trimmed)) {
    throw new Error(
      `Invalid username: ${trimmed}. Only [a-zA-Z0-9._-] allowed`
    );
  }

  return trimmed;
}

/**
 * Validates a YARA rule file path (must end in .yar or .yara).
 * Throws on invalid input.
 */
export function validateYaraRule(path: string): string {
  if (!path || typeof path !== "string") {
    throw new Error("YARA rule path must be a non-empty string");
  }

  const trimmed = path.trim();

  if (PATH_TRAVERSAL_RE.test(trimmed)) {
    throw new Error(
      "Path contains forbidden directory traversal (..)"
    );
  }

  if (SHELL_METACHAR_RE.test(trimmed)) {
    throw new Error(
      `YARA rule path contains forbidden shell metacharacters: ${trimmed}`
    );
  }

  if (CONTROL_CHAR_RE.test(trimmed)) {
    throw new Error(`YARA rule path contains control characters: ${trimmed}`);
  }

  if (!trimmed.endsWith(".yar") && !trimmed.endsWith(".yara")) {
    throw new Error(
      `Invalid YARA rule file: ${trimmed}. Must end in .yar or .yara`
    );
  }

  return trimmed;
}

/**
 * Validates a certificate file path (must end in .pem, .crt, .key, .p12, or .pfx).
 * Throws on invalid input.
 */
export function validateCertPath(path: string): string {
  if (!path || typeof path !== "string") {
    throw new Error("Certificate path must be a non-empty string");
  }

  const trimmed = path.trim();

  if (PATH_TRAVERSAL_RE.test(trimmed)) {
    throw new Error(
      "Path contains forbidden directory traversal (..)"
    );
  }

  if (SHELL_METACHAR_RE.test(trimmed)) {
    throw new Error(
      `Certificate path contains forbidden shell metacharacters: ${trimmed}`
    );
  }

  if (CONTROL_CHAR_RE.test(trimmed)) {
    throw new Error(
      `Certificate path contains control characters: ${trimmed}`
    );
  }

  const validExtensions = [".pem", ".crt", ".key", ".p12", ".pfx"];
  const hasValidExt = validExtensions.some((ext) =>
    trimmed.toLowerCase().endsWith(ext)
  );

  if (!hasValidExt) {
    throw new Error(
      `Invalid certificate file: ${trimmed}. Must end in ${validExtensions.join(", ")}`
    );
  }

  return trimmed;
}

/**
 * Validates a firewalld zone name.
 * Only allows `[a-zA-Z0-9_-]+`.
 * Throws on invalid input.
 */
export function validateFirewallZone(zone: string): string {
  if (!zone || typeof zone !== "string") {
    throw new Error("Firewall zone must be a non-empty string");
  }

  const trimmed = zone.trim();
  const zoneRe = /^[a-zA-Z0-9_-]+$/;
  if (!zoneRe.test(trimmed)) {
    throw new Error(
      `Invalid firewall zone: ${trimmed}. Only [a-zA-Z0-9_-] allowed`
    );
  }

  return trimmed;
}

/**
 * Validates an auditd key name.
 * Only allows `[a-zA-Z0-9_-]+`.
 * Throws on invalid input.
 */
export function validateAuditdKey(key: string): string {
  if (!key || typeof key !== "string") {
    throw new Error("Auditd key must be a non-empty string");
  }

  const trimmed = key.trim();
  const keyRe = /^[a-zA-Z0-9_-]+$/;
  if (!keyRe.test(trimmed)) {
    throw new Error(
      `Invalid auditd key: ${trimmed}. Only [a-zA-Z0-9_-] allowed`
    );
  }

  return trimmed;
}

/**
 * Validates a tool-supplied file path against traversal attacks and an explicit
 * list of allowed root directories.
 *
 * 1. Rejects paths containing `..`
 * 2. Uses `path.resolve()` to normalize
 * 3. Verifies resolved path is within one of the allowed directories
 *
 * @param inputPath  The user-supplied path
 * @param allowedDirs  Array of allowed root directories (e.g. ["/var/log", "/etc"])
 * @param label  Human-readable label for error messages (default: "Path")
 * @returns The resolved, validated path
 */
export function validateToolPath(
  inputPath: string,
  allowedDirs: string[],
  label = "Path"
): string {
  if (!inputPath || typeof inputPath !== "string") {
    throw new Error(`${label} must be a non-empty string`);
  }

  if (inputPath.includes("\0")) {
    throw new Error(`${label} contains null bytes`);
  }

  // Defense-in-depth: reject any path containing `..` sequences
  if (PATH_TRAVERSAL_RE.test(inputPath)) {
    throw new Error(
      `${label} contains forbidden directory traversal (..): '${inputPath}'`
    );
  }

  if (SHELL_METACHAR_RE.test(inputPath)) {
    throw new Error(
      `${label} contains forbidden shell metacharacters: '${inputPath}'`
    );
  }

  if (CONTROL_CHAR_RE.test(inputPath)) {
    throw new Error(`${label} contains control characters: '${inputPath}'`);
  }

  const resolved = normalize(resolve(inputPath));

  const isAllowed = allowedDirs.some((dir) => {
    const normalizedDir = normalize(resolve(dir));
    return (
      resolved === normalizedDir || resolved.startsWith(normalizedDir + "/")
    );
  });

  if (!isAllowed) {
    throw new Error(
      `${label} '${resolved}' is not within allowed directories: ${allowedDirs.join(", ")}`
    );
  }

  return resolved;
}

// ── Error Sanitization ───────────────────────────────────────────────────────

/**
 * SECURITY (TOOL-029): Regex to match absolute paths in error messages.
 * Matches paths like /home/user/... or /var/lib/...
 */
const ABS_PATH_RE = /\/(?:home|root|tmp|var|etc|usr|opt|srv|run|mnt|media)\/\S*/gi;

/**
 * SECURITY (TOOL-029): Regex to match stack traces in error messages.
 * Matches lines starting with "    at " (Node.js stack trace format).
 */
const STACK_TRACE_RE = /\n\s+at .+/g;

/**
 * Sanitize error messages before returning them to MCP clients.
 *
 * Strips:
 * 1. Absolute file paths (replaced with `[path]`)
 * 2. Stack traces (removed entirely)
 * 3. Overly long messages (truncated to 500 chars)
 *
 * @param error - The caught error (unknown type)
 * @returns A sanitized error message string safe for external exposure
 */
export function sanitizeToolError(error: unknown): string {
  let message: string;

  if (error instanceof Error) {
    message = error.message;
  } else if (typeof error === "string") {
    message = error;
  } else {
    message = String(error);
  }

  // Strip stack traces
  message = message.replace(STACK_TRACE_RE, "");

  // Strip absolute paths
  message = message.replace(ABS_PATH_RE, "[path]");

  // Truncate overly long messages
  if (message.length > 500) {
    message = message.substring(0, 497) + "...";
  }

  return message;
}
