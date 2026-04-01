/**
 * Dependency Validator for Defense MCP Server.
 *
 * Provides three key capabilities:
 * 1. **Startup validation** — checks all tool dependencies when the server starts
 *    and auto-installs missing ones if DEFENSE_MCP_AUTO_INSTALL=true
 * 2. **Runtime dependency check** — `ensureDependencies()` can be called before
 *    any tool execution to verify (and optionally install) required binaries
 * 3. **Dependency status cache** — avoids redundant `which` calls by caching
 *    binary availability results with a configurable TTL
 */

import { executeCommand } from "./executor.js";
import { getConfig } from "./config.js";
import {
  checkTool,
  installTool,
  type ToolRequirement,
  type InstallResult,
} from "./installer.js";
import {
  TOOL_DEPENDENCIES,
  getDependenciesForTool,
  getToolRequirementForBinary,
  getCriticalDependencies,
} from "./tool-dependencies.js";

// ── Types ────────────────────────────────────────────────────────────────────

/**
 * Cached binary availability status.
 */
interface BinaryStatus {
  available: boolean;
  path?: string;
  version?: string;
  checkedAt: number;
}

/**
 * Result of a startup validation run.
 */
export interface ValidationReport {
  /** Total unique binaries checked */
  totalChecked: number;
  /** Binaries that are available */
  available: string[];
  /** Binaries that are missing */
  missing: string[];
  /** Binaries that were auto-installed */
  installed: string[];
  /** Binaries that failed to install */
  installFailed: Array<{ binary: string; error: string }>;
  /** Critical tools with missing dependencies */
  criticalMissing: Array<{ toolName: string; missingBinaries: string[] }>;
  /** Duration of the validation in milliseconds */
  durationMs: number;
  /** Whether auto-install was enabled */
  autoInstallEnabled: boolean;
}

/**
 * Result of ensuring dependencies for a specific tool.
 */
export interface EnsureResult {
  /** Whether all required dependencies are satisfied */
  satisfied: boolean;
  /** Missing required binaries (empty if satisfied) */
  missingRequired: string[];
  /** Missing optional binaries */
  missingOptional: string[];
  /** Binaries that were auto-installed during this check */
  autoInstalled: string[];
  /** Errors from auto-install attempts */
  installErrors: Array<{ binary: string; error: string }>;
}

// ── Cache ────────────────────────────────────────────────────────────────────

/** Cache TTL in milliseconds (5 minutes) */
const CACHE_TTL_MS = 5 * 60 * 1000;

/** Binary availability cache */
const binaryCache = new Map<string, BinaryStatus>();

/**
 * Checks if a binary is available, using cache when possible.
 */
async function isBinaryAvailable(binary: string): Promise<BinaryStatus> {
  const cached = binaryCache.get(binary);
  if (cached && Date.now() - cached.checkedAt < CACHE_TTL_MS) {
    return cached;
  }

  const result = await checkTool(binary);
  const status: BinaryStatus = {
    available: result.installed,
    path: result.path,
    version: result.version,
    checkedAt: Date.now(),
  };

  binaryCache.set(binary, status);
  return status;
}

/**
 * Invalidates the cache for a specific binary (e.g. after installation).
 */
function invalidateCache(binary: string): void {
  binaryCache.delete(binary);
}

/**
 * Clears the entire binary cache.
 */
export function clearDependencyCache(): void {
  binaryCache.clear();
}

// ── Auto-install logic ───────────────────────────────────────────────────────

/**
 * Attempts to install a binary by finding its ToolRequirement in DEFENSIVE_TOOLS.
 * Returns the install result or null if no matching package is known.
 */
async function autoInstallBinary(binary: string): Promise<InstallResult | null> {
  // First check the DEFENSIVE_TOOLS registry
  const toolReq = getToolRequirementForBinary(binary);
  if (toolReq) {
    console.error(`[dep-validator] Auto-installing ${toolReq.name} (provides: ${binary})`);
    const result = await installTool(toolReq);
    if (result.success) {
      invalidateCache(binary);
    }
    return result;
  }

  // For binaries not in DEFENSIVE_TOOLS, try a direct package install
  // Many system utilities have the same package name as the binary
  const directInstallReq: ToolRequirement = {
    name: binary,
    binary,
    packages: {
      debian: binary,
      rhel: binary,
      arch: binary,
      alpine: binary,
      suse: binary,
      fallback: binary,
    },
    category: "hardening",
    required: false,
  };

  console.error(`[dep-validator] Attempting direct install of '${binary}' (no known package mapping)`);
  const result = await installTool(directInstallReq);
  if (result.success) {
    invalidateCache(binary);
  }
  return result;
}

// ── Startup Validation ───────────────────────────────────────────────────────

/**
 * Validates all tool dependencies at server startup.
 *
 * This function:
 * 1. Collects all unique binaries required across all tools
 * 2. Checks each binary's availability
 * 3. If autoInstall is enabled, installs missing binaries
 * 4. Reports critical tools with missing dependencies
 *
 * @returns A detailed validation report
 */
export async function validateAllDependencies(): Promise<ValidationReport> {
  const startTime = Date.now();
  const config = getConfig();

  console.error("[dep-validator] Starting dependency validation...");

  // Collect all unique binaries (required only — optional are checked lazily)
  const allBinaries = new Set<string>();
  for (const dep of TOOL_DEPENDENCIES) {
    for (const bin of dep.requiredBinaries) {
      // Skip trivially-available system utilities
      if (!TRIVIAL_BINARIES.has(bin)) {
        allBinaries.add(bin);
      }
    }
  }

  const available: string[] = [];
  const missing: string[] = [];
  const installed: string[] = [];
  const installFailed: Array<{ binary: string; error: string }> = [];

  // Check all binaries in parallel (batched to avoid overwhelming the system)
  const binaryList = Array.from(allBinaries);
  const BATCH_SIZE = 10;

  for (let i = 0; i < binaryList.length; i += BATCH_SIZE) {
    const batch = binaryList.slice(i, i + BATCH_SIZE);
    const results = await Promise.all(
      batch.map(async (bin) => ({
        binary: bin,
        status: await isBinaryAvailable(bin),
      }))
    );

    for (const { binary, status } of results) {
      if (status.available) {
        available.push(binary);
      } else {
        missing.push(binary);
      }
    }
  }

  // Auto-install missing binaries if enabled
  if (config.autoInstall && missing.length > 0) {
    console.error(
      `[dep-validator] Auto-install enabled. Installing ${missing.length} missing binaries...`
    );

    // Update package lists once before installing
    const { detectDistro, getPackageManager } = await import("./distro.js");
    const distro = await detectDistro();
    const pkgMgr = getPackageManager(distro.packageManager);
    const updateCmd = pkgMgr.updateCmd();

    console.error(`[dep-validator] Updating package lists via ${distro.packageManager}...`);
    await executeCommand({
      toolName: "_internal",
      command: "sudo",
      args: updateCmd,
      timeout: 120_000,
    });

    // Install each missing binary
    const toInstall = [...missing];
    missing.length = 0; // Reset — we'll re-populate with truly-missing ones

    for (const binary of toInstall) {
      const result = await autoInstallBinary(binary);

      if (result?.success) {
        // Verify the binary is now available
        invalidateCache(binary);
        const recheck = await isBinaryAvailable(binary);
        if (recheck.available) {
          installed.push(binary);
          available.push(binary);
          console.error(`[dep-validator] Installed: ${binary}`);
        } else {
          missing.push(binary);
          installFailed.push({
            binary,
            error: "Package installed but binary not found in PATH",
          });
          console.error(`[dep-validator] WARNING: Package installed but binary '${binary}' not found`);
        }
      } else {
        missing.push(binary);
        installFailed.push({
          binary,
          error: result?.message ?? "No package mapping found",
        });
        console.error(`[dep-validator] Failed to install: ${binary}`);
      }
    }
  }

  // Check critical tools
  const criticalMissing: Array<{ toolName: string; missingBinaries: string[] }> = [];
  const criticalDeps = getCriticalDependencies();

  for (const dep of criticalDeps) {
    const missingBins = dep.requiredBinaries.filter(
      (bin) => !TRIVIAL_BINARIES.has(bin) && missing.includes(bin)
    );
    if (missingBins.length > 0) {
      criticalMissing.push({
        toolName: dep.toolName,
        missingBinaries: missingBins,
      });
    }
  }

  const durationMs = Date.now() - startTime;

  const report: ValidationReport = {
    totalChecked: binaryList.length,
    available,
    missing,
    installed,
    installFailed,
    criticalMissing,
    durationMs,
    autoInstallEnabled: config.autoInstall,
  };

  // Log summary
  console.error(
    `[dep-validator] Validation complete in ${durationMs}ms: ` +
      `${available.length} available, ${missing.length} missing` +
      (installed.length > 0 ? `, ${installed.length} auto-installed` : "") +
      (installFailed.length > 0 ? `, ${installFailed.length} install failures` : "")
  );

  if (criticalMissing.length > 0) {
    console.error(
      `[dep-validator] WARNING: CRITICAL: ${criticalMissing.length} critical tools have missing dependencies:`
    );
    for (const cm of criticalMissing) {
      console.error(
        `[dep-validator]   - ${cm.toolName}: needs ${cm.missingBinaries.join(", ")}`
      );
    }
    console.error(
      `[dep-validator] Set DEFENSE_MCP_AUTO_INSTALL=true to auto-install missing tools`
    );
  }

  return report;
}

// ── Runtime Dependency Check ─────────────────────────────────────────────────

/**
 * Ensures all dependencies for a specific MCP tool are satisfied.
 *
 * Call this at the start of any tool handler to verify its binaries are present.
 * If autoInstall is enabled, missing binaries will be installed on-the-fly.
 *
 * @param toolName The MCP tool name (e.g. "ids_rkhunter_scan")
 * @returns EnsureResult with satisfaction status and details
 *
 * @example
 * ```ts
 * const deps = await ensureDependencies("ids_rkhunter_scan");
 * if (!deps.satisfied) {
 *   return {
 *     content: [createErrorContent(
 *       `Missing required tools: ${deps.missingRequired.join(", ")}. ` +
 *       `Install with: sudo apt install ${deps.missingRequired.join(" ")}`
 *     )],
 *     isError: true,
 *   };
 * }
 * ```
 */
export async function ensureDependencies(
  toolName: string
): Promise<EnsureResult> {
  const dep = getDependenciesForTool(toolName);

  // If no dependency info registered, assume satisfied
  if (!dep) {
    return {
      satisfied: true,
      missingRequired: [],
      missingOptional: [],
      autoInstalled: [],
      installErrors: [],
    };
  }

  const config = getConfig();
  const missingRequired: string[] = [];
  const missingOptional: string[] = [];
  const autoInstalled: string[] = [];
  const installErrors: Array<{ binary: string; error: string }> = [];

  // Check required binaries
  for (const bin of dep.requiredBinaries) {
    if (TRIVIAL_BINARIES.has(bin)) continue;

    const status = await isBinaryAvailable(bin);
    if (!status.available) {
      if (config.autoInstall) {
        const result = await autoInstallBinary(bin);
        if (result?.success) {
          invalidateCache(bin);
          const recheck = await isBinaryAvailable(bin);
          if (recheck.available) {
            autoInstalled.push(bin);
            continue;
          }
        }
        installErrors.push({
          binary: bin,
          error: result?.message ?? "Installation failed",
        });
      }
      missingRequired.push(bin);
    }
  }

  // Check optional binaries (never block on these)
  for (const bin of dep.optionalBinaries ?? []) {
    if (TRIVIAL_BINARIES.has(bin)) continue;

    const status = await isBinaryAvailable(bin);
    if (!status.available) {
      // Try auto-install for optional deps too, but don't fail
      if (config.autoInstall) {
        const result = await autoInstallBinary(bin);
        if (result?.success) {
          invalidateCache(bin);
          const recheck = await isBinaryAvailable(bin);
          if (recheck.available) {
            autoInstalled.push(bin);
            continue;
          }
        }
      }
      missingOptional.push(bin);
    }
  }

  return {
    satisfied: missingRequired.length === 0,
    missingRequired,
    missingOptional,
    autoInstalled,
    installErrors,
  };
}

/**
 * Quick check if a single binary is available (cached).
 * Does NOT auto-install. Use for lightweight pre-flight checks.
 */
export async function isBinaryInstalled(binary: string): Promise<boolean> {
  if (TRIVIAL_BINARIES.has(binary)) return true;
  const status = await isBinaryAvailable(binary);
  return status.available;
}

// ── Format helpers ───────────────────────────────────────────────────────────

/**
 * Formats a ValidationReport into a human-readable string for logging.
 */
export function formatValidationReport(report: ValidationReport): string {
  const lines: string[] = [];

  lines.push("╔══════════════════════════════════════════════════════════╗");
  lines.push("║       Defense MCP — Dependency Validation          ║");
  lines.push("╚══════════════════════════════════════════════════════════╝");
  lines.push("");
  lines.push(`  Binaries checked:    ${report.totalChecked}`);
  lines.push(`  Available:           ${report.available.length}`);
  lines.push(`  Missing:             ${report.missing.length}`);

  if (report.installed.length > 0) {
    lines.push(`  Auto-installed:      ${report.installed.length}`);
    for (const bin of report.installed) {
      lines.push(`    PASS: ${bin}`);
    }
  }

  if (report.installFailed.length > 0) {
    lines.push(`  Install failures:    ${report.installFailed.length}`);
    for (const fail of report.installFailed) {
      lines.push(`    ${fail.binary}: ${fail.error}`);
    }
  }

  if (report.missing.length > 0) {
    lines.push("");
    lines.push("  Missing binaries:");
    for (const bin of report.missing) {
      const toolReq = getToolRequirementForBinary(bin);
      const pkg = toolReq ? ` (package: ${toolReq.packages.debian ?? toolReq.packages.fallback})` : "";
      lines.push(`    • ${bin}${pkg}`);
    }
  }

  if (report.criticalMissing.length > 0) {
    lines.push("");
    lines.push("  WARNING: CRITICAL tools with missing dependencies:");
    for (const cm of report.criticalMissing) {
      lines.push(`    CRITICAL: ${cm.toolName}: needs ${cm.missingBinaries.join(", ")}`);
    }
  }

  lines.push("");
  lines.push(`  Auto-install: ${report.autoInstallEnabled ? "ENABLED" : "DISABLED"}`);
  if (!report.autoInstallEnabled && report.missing.length > 0) {
    lines.push("  Set DEFENSE_MCP_AUTO_INSTALL=true to auto-install missing tools");
  }
  lines.push(`  Duration: ${report.durationMs}ms`);

  return lines.join("\n");
}

// ── Trivial binaries ─────────────────────────────────────────────────────────

/**
 * System utilities that are virtually always present on any Linux system.
 * We skip checking these to avoid unnecessary overhead.
 */
const TRIVIAL_BINARIES = new Set([
  "cat",
  "cp",
  "ls",
  "mv",
  "rm",
  "tee",
  "find",
  "grep",
  "awk",
  "sed",
  "stat",
  "chmod",
  "chown",
  "chgrp",
  "mount",
  "umount",
  "uname",
  "ps",
  "ip",
  "lsmod",
  "modprobe",
  "sha256sum",
  "usermod",
  "crontab",
]);
