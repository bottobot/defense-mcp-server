/**
 * PrivilegeManager — detects the current privilege level and checks whether
 * a tool's privilege requirements are satisfied.
 *
 * This module is part of the pre-flight validation system. It queries:
 *   - UID / EUID via `process.getuid()` / `process.geteuid()`
 *   - Linux capabilities via `/proc/self/status` CapEff bitmask
 *   - Passwordless sudo via `sudo -n true`
 *   - Active sudo session via `SudoSession.getInstance().isElevated()`
 *   - User groups via `id -Gn`
 *
 * To avoid circular dependencies with the executor, all subprocess calls
 * use `child_process.execFileSync` directly.
 *
 * @module privilege-manager
 */

import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { SudoSession } from "./sudo-session.js";
import type { ToolManifest } from "./tool-registry.js";

// ── Types ────────────────────────────────────────────────────────────────────

export interface PrivilegeStatus {
  /** Current real user ID */
  uid: number;
  /** Current effective user ID */
  euid: number;
  /** Whether running as root (euid === 0) */
  isRoot: boolean;
  /** Whether `sudo` binary is available on PATH */
  sudoAvailable: boolean;
  /** Whether passwordless sudo works (`sudo -n true`) */
  passwordlessSudo: boolean;
  /** Whether SudoSession has cached credentials */
  sudoSessionActive: boolean;
  /** Currently held Linux capabilities (from CapEff) */
  capabilities: Set<string>;
  /** User's group memberships */
  groups: string[];
}

export interface PrivilegeCheckResult {
  /** All privilege requirements met */
  satisfied: boolean;
  /** Problems found */
  issues: PrivilegeIssue[];
  /** How to fix any issues */
  recommendations: string[];
}

export interface PrivilegeIssue {
  type:
    | "sudo-required"
    | "capability-missing"
    | "sudo-unavailable"
    | "session-expired";
  /** Human-readable description of the issue */
  description: string;
  /** Which tool/operation needs this privilege */
  operation: string;
  /** How to resolve the issue */
  resolution: string;
}

// ── Linux Capability Bit → Name Mapping ──────────────────────────────────────

/**
 * Maps bit position to Linux capability name.
 * Derived from the kernel's `include/uapi/linux/capability.h`.
 */
const CAPABILITY_NAMES: readonly string[] = [
  "CAP_CHOWN",              // 0
  "CAP_DAC_OVERRIDE",       // 1
  "CAP_DAC_READ_SEARCH",    // 2
  "CAP_FOWNER",             // 3
  "CAP_FSETID",             // 4
  "CAP_KILL",               // 5
  "CAP_SETGID",             // 6
  "CAP_SETUID",             // 7
  "CAP_SETPCAP",            // 8
  "CAP_LINUX_IMMUTABLE",    // 9
  "CAP_NET_BIND_SERVICE",   // 10
  "CAP_NET_BROADCAST",      // 11
  "CAP_NET_ADMIN",          // 12
  "CAP_NET_RAW",            // 13
  "CAP_IPC_LOCK",           // 14
  "CAP_IPC_OWNER",          // 15
  "CAP_SYS_MODULE",         // 16
  "CAP_SYS_RAWIO",          // 17
  "CAP_SYS_CHROOT",         // 18
  "CAP_SYS_PTRACE",         // 19
  "CAP_SYS_PACCT",          // 20
  "CAP_SYS_ADMIN",          // 21
  "CAP_SYS_BOOT",           // 22
  "CAP_SYS_NICE",           // 23
  "CAP_SYS_RESOURCE",       // 24
  "CAP_SYS_TIME",           // 25
  "CAP_SYS_TTY_CONFIG",     // 26
  "CAP_MKNOD",              // 27
  "CAP_LEASE",              // 28
  "CAP_AUDIT_WRITE",        // 29
  "CAP_AUDIT_CONTROL",      // 30
  "CAP_SETFCAP",            // 31
  "CAP_MAC_OVERRIDE",       // 32
  "CAP_MAC_ADMIN",          // 33
  "CAP_SYSLOG",             // 34
  "CAP_WAKE_ALARM",         // 35
  "CAP_BLOCK_SUSPEND",      // 36
  "CAP_AUDIT_READ",         // 37
  "CAP_PERFMON",            // 38
  "CAP_BPF",                // 39
  "CAP_CHECKPOINT_RESTORE", // 40
] as const;

// ── Helper: safe execFileSync wrapper ────────────────────────────────────────

/**
 * Run a command synchronously with a timeout, returning stdout on success
 * or `null` on any failure. Never throws.
 */
function execSafe(
  file: string,
  args: string[],
  timeoutMs = 5_000,
): string | null {
  try {
    const result = execFileSync(file, args, {
      encoding: "utf-8",
      timeout: timeoutMs,
      stdio: ["pipe", "pipe", "pipe"],
    });
    return result;
  } catch {
    return null;
  }
}

// ── PrivilegeManager ─────────────────────────────────────────────────────────

export class PrivilegeManager {
  private cachedStatus: PrivilegeStatus | null = null;
  private cacheExpiry: number = 0;
  private static readonly CACHE_TTL = 30_000; // 30 seconds

  private static _instance: PrivilegeManager | null = null;

  private constructor() {
    // Singleton — use PrivilegeManager.instance()
  }

  /** Get or create the singleton instance. */
  static instance(): PrivilegeManager {
    if (!PrivilegeManager._instance) {
      PrivilegeManager._instance = new PrivilegeManager();
    }
    return PrivilegeManager._instance;
  }

  // ── Public API ───────────────────────────────────────────────────────────

  /**
   * Detect current privilege level.
   * Results are cached for {@link CACHE_TTL} ms to avoid repeated
   * subprocess spawns on rapid sequential tool calls.
   */
  async getStatus(): Promise<PrivilegeStatus> {
    const now = Date.now();
    if (this.cachedStatus && now < this.cacheExpiry) {
      return this.cachedStatus;
    }

    const uid = typeof process.getuid === "function" ? process.getuid() : -1;
    const euid =
      typeof process.geteuid === "function" ? process.geteuid() : -1;
    const isRoot = euid === 0;

    const groups = this.getGroups();
    const sudoAvailable = await this.isSudoAvailable();
    const passwordlessSudo = sudoAvailable
      ? await this.testPasswordlessSudo()
      : false;
    const sudoSessionActive = SudoSession.getInstance().isElevated();
    const capabilities = await this.getCurrentCapabilities();

    const status: PrivilegeStatus = {
      uid,
      euid,
      isRoot,
      sudoAvailable,
      passwordlessSudo,
      sudoSessionActive,
      capabilities,
      groups,
    };

    this.cachedStatus = status;
    this.cacheExpiry = now + PrivilegeManager.CACHE_TTL;

    return status;
  }

  /**
   * Check whether a specific tool's privilege requirements are met.
   *
   * Evaluates the tool's `sudo` level and `capabilities` list against
   * the current {@link PrivilegeStatus} and returns actionable issues.
   */
  async checkForTool(manifest: ToolManifest): Promise<PrivilegeCheckResult> {
    const issues: PrivilegeIssue[] = [];
    const recommendations: string[] = [];

    // ── sudo: 'never' → always satisfied ───────────────────────────────
    if (manifest.sudo === "never") {
      return { satisfied: true, issues, recommendations };
    }

    const status = await this.getStatus();

    // ── sudo: 'always' → must have root, session, or passwordless sudo ─
    if (manifest.sudo === "always") {
      if (!status.isRoot && !status.sudoSessionActive && !status.passwordlessSudo) {
        if (!status.sudoAvailable) {
          issues.push({
            type: "sudo-unavailable",
            description:
              `Tool '${manifest.toolName}' requires elevated privileges but ` +
              `the 'sudo' binary is not available on this system.`,
            operation: manifest.toolName,
            resolution:
              "Install sudo (e.g., 'apt install sudo') or run the server as root.",
          });
          recommendations.push(
            "Install the 'sudo' package or run the MCP server as root.",
          );
        } else {
          const reason = manifest.sudoReason
            ? ` to ${manifest.sudoReason.charAt(0).toLowerCase()}${manifest.sudoReason.slice(1)}`
            : "";
          issues.push({
            type: "sudo-required",
            description:
              `Tool '${manifest.toolName}' requires elevated privileges${reason}. ` +
              `No active sudo session or passwordless sudo detected.`,
            operation: manifest.toolName,
            resolution:
              "Call the 'sudo_elevate' tool first to provide your credentials for this session.",
          });
          recommendations.push(
            `Run the 'sudo_elevate' tool to provide credentials before using '${manifest.toolName}'.`,
          );
        }
      }
    }

    // ── sudo: 'conditional' → don't block, but advise ──────────────────
    if (manifest.sudo === "conditional") {
      if (
        !status.isRoot &&
        !status.sudoSessionActive &&
        !status.passwordlessSudo &&
        status.sudoAvailable
      ) {
        recommendations.push(
          `Tool '${manifest.toolName}' may show limited results without elevated privileges. ` +
            `Consider running 'sudo_elevate' first for complete output.`,
        );
      }
    }

    // ── Capability checks ──────────────────────────────────────────────
    if (manifest.capabilities && manifest.capabilities.length > 0) {
      for (const requiredCap of manifest.capabilities) {
        const hasCap = status.capabilities.has(requiredCap);

        // If running as root or have an active sudo session, capabilities
        // will be available when the command runs under sudo, so don't flag.
        if (!hasCap && !status.isRoot && !status.sudoSessionActive && !status.passwordlessSudo) {
          issues.push({
            type: "capability-missing",
            description:
              `Tool '${manifest.toolName}' requires Linux capability '${requiredCap}' ` +
              `which is not in the current effective capability set.`,
            operation: manifest.toolName,
            resolution:
              `Either run 'sudo_elevate' to gain full privileges, or grant '${requiredCap}' ` +
              `to the Node.js binary with: sudo setcap '${requiredCap.toLowerCase()}+ep' $(which node)`,
          });
          recommendations.push(
            `Capability '${requiredCap}' is required for '${manifest.toolName}'. ` +
              `Use 'sudo_elevate' or grant the capability directly to the node binary.`,
          );
        }
      }
    }

    return {
      satisfied: issues.length === 0,
      issues,
      recommendations,
    };
  }

  /**
   * Check if a specific Linux capability is in the current effective set.
   */
  async hasCapability(cap: string): Promise<boolean> {
    const caps = await this.getCurrentCapabilities();
    return caps.has(cap);
  }

  /**
   * Parse the effective capability set from `/proc/self/status`.
   *
   * Reads the `CapEff` line which contains a hex-encoded bitmask,
   * then maps set bits to capability names using the kernel-defined
   * bit positions.
   */
  async getCurrentCapabilities(): Promise<Set<string>> {
    const caps = new Set<string>();

    try {
      const statusContent = readFileSync("/proc/self/status", "utf-8");
      const capEffLine = statusContent
        .split("\n")
        .find((line) => line.startsWith("CapEff:"));

      if (!capEffLine) {
        return caps;
      }

      const hexStr = capEffLine.split(":")[1]?.trim();
      if (!hexStr) {
        return caps;
      }

      // Parse the hex string as a BigInt to handle the full 64-bit bitmask
      const bitmask = BigInt("0x" + hexStr);

      for (let bit = 0; bit < CAPABILITY_NAMES.length; bit++) {
        if (bitmask & (1n << BigInt(bit))) {
          caps.add(CAPABILITY_NAMES[bit]);
        }
      }
    } catch {
      // /proc/self/status may not exist on non-Linux systems;
      // return empty set rather than crashing.
    }

    return caps;
  }

  /**
   * Test whether passwordless sudo works by running `sudo -n true`.
   * The `-n` (non-interactive) flag causes sudo to fail immediately
   * rather than prompting if a password is required.
   */
  async testPasswordlessSudo(): Promise<boolean> {
    const result = execSafe("sudo", ["-n", "true"], 5_000);
    // execFileSync throws on non-zero exit, so if result is non-null it succeeded
    return result !== null;
  }

  /**
   * Check whether the `sudo` binary exists on PATH.
   */
  async isSudoAvailable(): Promise<boolean> {
    const result = execSafe("which", ["sudo"], 3_000);
    return result !== null && result.trim().length > 0;
  }

  /**
   * Invalidate the cached status.
   * Should be called after events that change privilege state,
   * e.g., after `sudo_elevate` or `sudo_drop`.
   */
  clearCache(): void {
    this.cachedStatus = null;
    this.cacheExpiry = 0;
  }

  // ── Private helpers ──────────────────────────────────────────────────────

  /**
   * Get user group memberships via `id -Gn`.
   * Returns an empty array on failure.
   */
  private getGroups(): string[] {
    const output = execSafe("id", ["-Gn"], 3_000);
    if (!output) {
      return [];
    }
    return output
      .trim()
      .split(/\s+/)
      .filter((g) => g.length > 0);
  }
}
