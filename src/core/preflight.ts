/**
 * Pre-flight Validation Engine — orchestrates the complete pre-flight
 * validation pipeline for MCP tools.
 *
 * Before each tool invocation this module:
 * 1. Resolves the tool's manifest from the {@link ToolRegistry}
 * 2. Checks binary, Python, npm, library, and file dependencies
 * 3. Attempts auto-installation of missing deps when enabled
 * 4. Validates privilege requirements via {@link PrivilegeManager}
 * 5. Returns a structured {@link PreflightResult} with pass/fail, actionable
 *    messages, and a human-readable summary
 *
 * Results are cached for 60 seconds to avoid redundant checks when multiple
 * tools from the same category are invoked in sequence.
 *
 * @module preflight
 */

import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import {
  ToolRegistry,
  initializeRegistry,
  type ToolManifest,
} from "./tool-registry.js";
import {
  PrivilegeManager,
  type PrivilegeIssue,
} from "./privilege-manager.js";
import { AutoInstaller, type InstallAttempt } from "./auto-installer.js";
import {
  isBinaryInstalled,
  clearDependencyCache,
} from "./dependency-validator.js";
import { getConfig } from "./config.js";
import { getToolRequirementForBinary } from "./tool-dependencies.js";
import {
  SafeguardRegistry,
  type SafetyResult,
} from "./safeguards.js";

// ── Types ────────────────────────────────────────────────────────────────────

export interface PreflightResult {
  toolName: string;
  /** Overall pass/fail */
  passed: boolean;
  timestamp: number;
  /** Total pre-flight time in ms */
  duration: number;

  // Dependency checks
  dependencies: {
    /** Everything that was checked */
    checked: DependencyCheck[];
    /** Still missing after install attempts */
    missing: DependencyCheck[];
    /** Successfully auto-installed */
    installed: DependencyCheck[];
    /** Non-fatal dependency issues */
    warnings: string[];
  };

  // Privilege checks
  privileges: {
    satisfied: boolean;
    issues: PrivilegeIssue[];
    recommendations: string[];
  };

  // Safeguard checks (populated when params are provided)
  safeguards?: {
    /** Whether the operation is safe */
    safe: boolean;
    /** Blocking safety issues (prevent execution) */
    blockers: string[];
    /** Non-blocking safety warnings */
    warnings: string[];
    /** Applications impacted by the operation */
    impactedApps: string[];
  };

  /** Human-readable summary */
  summary: string;
  /** Fatal blocking errors */
  errors: string[];
  /** Non-fatal warnings */
  warnings: string[];
}

export interface DependencyCheck {
  name: string;
  type: "binary" | "python-module" | "npm-package" | "library" | "file";
  /** true = required, false = optional */
  required: boolean;
  found: boolean;
  autoInstalled?: boolean;
  installMessage?: string;
}

// ── Python import name mapping ───────────────────────────────────────────────

/**
 * Maps pip package names to their Python import names when they differ.
 * Mirrors the mapping in {@link AutoInstaller} (auto-installer.ts).
 */
const PYTHON_IMPORT_MAP: Record<string, string> = {
  "yara-python": "yara",
  "python-nmap": "nmap",
  "python-apt": "apt",
  PyYAML: "yaml",
  Pillow: "PIL",
  "scikit-learn": "sklearn",
  beautifulsoup4: "bs4",
  "python-dateutil": "dateutil",
  attrs: "attr",
};

// ── Dependency check helpers ─────────────────────────────────────────────────

/**
 * Check if a Python module is importable via `python3 -c "import <module>"`.
 * Uses {@link PYTHON_IMPORT_MAP} to translate pip names to import names.
 */
function isPythonModuleInstalled(moduleName: string): boolean {
  const importName =
    PYTHON_IMPORT_MAP[moduleName] ?? moduleName.replace(/-/g, "_");
  try {
    execFileSync("python3", ["-c", `import ${importName}`], {
      timeout: 5_000,
      stdio: "pipe",
    });
    return true;
  } catch {
    return false;
  }
}

/**
 * Check if an npm package is globally installed (binary on PATH).
 */
function isNpmPackageInstalled(packageName: string): boolean {
  try {
    execFileSync("which", [packageName], {
      timeout: 5_000,
      stdio: "pipe",
    });
    return true;
  } catch {
    return false;
  }
}

/**
 * Check if a system library is available via `pkg-config` or `ldconfig`.
 */
function isLibraryInstalled(libName: string): boolean {
  try {
    // Try pkg-config first
    execFileSync("pkg-config", ["--exists", libName], {
      timeout: 5_000,
      stdio: "pipe",
    });
    return true;
  } catch {
    try {
      // Fallback to ldconfig
      const result = execFileSync("ldconfig", ["-p"], {
        timeout: 5_000,
        stdio: "pipe",
      });
      return result.toString().includes(libName);
    } catch {
      return false;
    }
  }
}

/**
 * Generate an install hint for a missing binary using the
 * `DEFENSIVE_TOOLS` registry from tool-dependencies.
 */
function getInstallHint(binaryName: string): string | undefined {
  const toolReq = getToolRequirementForBinary(binaryName);
  if (!toolReq) return undefined;
  const pkg =
    toolReq.packages.debian ?? toolReq.packages.fallback ?? binaryName;
  return `sudo apt-get install -y ${pkg}`;
}

// ── PreflightEngine ──────────────────────────────────────────────────────────

/**
 * Central orchestration engine for the pre-flight validation pipeline.
 *
 * Singleton — obtain via {@link PreflightEngine.instance}.
 *
 * The main entry point is {@link runPreflight}, which executes the full
 * dependency → auto-install → privilege check pipeline and returns a
 * structured {@link PreflightResult}.
 */
export class PreflightEngine {
  private registry: ToolRegistry;
  private privilegeManager: PrivilegeManager;
  private autoInstaller: AutoInstaller;

  /** Cache to avoid repeated checks for the same tool within a short window */
  private resultCache: Map<string, { result: PreflightResult; expiry: number }>;
  private static readonly CACHE_TTL = 60_000; // 60 seconds

  private static _instance: PreflightEngine | null = null;

  private constructor() {
    this.registry = initializeRegistry();
    this.privilegeManager = PrivilegeManager.instance();
    this.autoInstaller = AutoInstaller.instance();
    this.resultCache = new Map();
  }

  /** Get or create the singleton instance. */
  static instance(): PreflightEngine {
    if (!PreflightEngine._instance) {
      PreflightEngine._instance = new PreflightEngine();
    }
    return PreflightEngine._instance;
  }

  // ── Main entry point ───────────────────────────────────────────────────

  /**
   * Run the full pre-flight validation pipeline for a tool.
   *
   * 1. Check cache — return early for valid passing results
   * 2. Resolve the tool's manifest from the registry
   * 3. Check all dependency types (binary, Python, npm, library, file)
   * 4. Auto-install missing required deps when enabled
   * 5. Validate privilege requirements (sudo, capabilities)
   * 6. Determine overall pass/fail and generate summary
   * 7. Cache and return the result
   */
  async runPreflight(
    toolName: string,
    params?: Record<string, unknown>,
  ): Promise<PreflightResult> {
    const startTime = Date.now();

    // ── Step 1: Check cache ────────────────────────────────────────────
    // Only return cache when no params are provided (safeguard checks
    // depend on runtime params and must always run fresh).
    const cached = this.resultCache.get(toolName);
    if (
      !params &&
      cached &&
      cached.expiry > Date.now() &&
      cached.result.passed
    ) {
      return cached.result;
    }

    console.error(`[preflight] Running pre-flight for '${toolName}'...`);

    // ── Step 2: Get manifest ───────────────────────────────────────────
    const manifest = this.registry.getManifest(toolName);

    if (!manifest) {
      // No manifest found — pass with a warning
      const result: PreflightResult = {
        toolName,
        passed: true,
        timestamp: Date.now(),
        duration: Date.now() - startTime,
        dependencies: {
          checked: [],
          missing: [],
          installed: [],
          warnings: [
            "Tool not registered in manifest — skipping pre-flight",
          ],
        },
        privileges: {
          satisfied: true,
          issues: [],
          recommendations: [],
        },
        summary: "",
        errors: [],
        warnings: [
          "Tool not registered in manifest — skipping pre-flight",
        ],
      };
      result.summary = this.formatSummary(result);
      this.cacheResult(toolName, result);

      console.error(
        `[preflight] ⚠ No manifest for '${toolName}' — skipping (${Date.now() - startTime}ms)`,
      );
      return result;
    }

    // ── Step 3–4: Check dependencies (includes auto-install) ───────────
    const dependencies = await this.checkDependencies(manifest);

    // ── Step 5: Check privileges ───────────────────────────────────────
    const privileges = await this.checkPrivileges(manifest);

    // ── Step 6: Determine overall pass/fail ────────────────────────────
    const errors: string[] = [];
    const warnings: string[] = [...dependencies.warnings];

    // FAIL if any required dependency is still missing after install attempts
    if (dependencies.missing.length > 0) {
      for (const dep of dependencies.missing) {
        const hint =
          dep.type === "binary" ? getInstallHint(dep.name) : undefined;
        errors.push(
          `Missing required ${dep.type}: '${dep.name}'` +
            (hint ? ` — Install with: ${hint}` : ""),
        );
      }
    }

    // FAIL if privilege issues of type 'sudo-required' or 'sudo-unavailable'
    // (but NOT for 'conditional' sudo — those generate recommendations, not issues)
    const blockingPrivilegeIssues = privileges.issues.filter(
      (i) => i.type === "sudo-required" || i.type === "sudo-unavailable",
    );
    if (blockingPrivilegeIssues.length > 0) {
      for (const issue of blockingPrivilegeIssues) {
        errors.push(issue.description);
      }
    }

    // Add non-blocking privilege issues as warnings
    const nonBlockingPrivilegeIssues = privileges.issues.filter(
      (i) => i.type !== "sudo-required" && i.type !== "sudo-unavailable",
    );
    for (const issue of nonBlockingPrivilegeIssues) {
      warnings.push(issue.description);
    }

    // Add privilege recommendations as warnings
    for (const rec of privileges.recommendations) {
      warnings.push(rec);
    }

    // ── Step 6: Safeguard checks ───────────────────────────────────────
    let safeguardResult: SafetyResult | undefined;
    if (params) {
      try {
        const safeguardRegistry = SafeguardRegistry.getInstance();
        safeguardResult = await safeguardRegistry.checkSafety(toolName, params);

        // Add safeguard warnings to the overall warnings
        if (safeguardResult.warnings.length > 0) {
          warnings.push(...safeguardResult.warnings);
        }

        // Add safeguard blockers to the overall errors
        if (!safeguardResult.safe) {
          for (const blocker of safeguardResult.blockers) {
            errors.push(blocker);
          }
        }

        console.error(
          `[preflight] Safeguards: ${safeguardResult.blockers.length} blocker(s), ` +
            `${safeguardResult.warnings.length} warning(s)`,
        );
      } catch (err) {
        console.error(
          `[preflight] ⚠ Safeguard check failed: ${
            err instanceof Error ? err.message : String(err)
          }`,
        );
        // Safeguard failure is non-blocking — log and continue
      }
    }

    const passed = errors.length === 0;
    const duration = Date.now() - startTime;

    const result: PreflightResult = {
      toolName,
      passed,
      timestamp: Date.now(),
      duration,
      dependencies,
      privileges: {
        satisfied: privileges.satisfied,
        issues: privileges.issues,
        recommendations: privileges.recommendations,
      },
      safeguards: safeguardResult
        ? {
            safe: safeguardResult.safe,
            blockers: safeguardResult.blockers,
            warnings: safeguardResult.warnings,
            impactedApps: safeguardResult.impactedApps,
          }
        : undefined,
      summary: "",
      errors,
      warnings,
    };

    // ── Step 7: Generate summary, cache, log ───────────────────────────
    result.summary = this.formatSummary(result);
    this.cacheResult(toolName, result);

    // Log to stderr
    const depCount = dependencies.checked.filter((c) => c.required).length;
    const missingCount = dependencies.missing.length;
    console.error(
      `[preflight] Dependencies: ${depCount} checked, ${missingCount} missing`,
    );
    if (manifest.sudo !== "never") {
      const sudoStatus = privileges.satisfied
        ? "session active ✓"
        : `${privileges.issues.length} issue(s)`;
      console.error(
        `[preflight] Privileges: sudo ${manifest.sudo} — ${sudoStatus}`,
      );
    }
    console.error(
      `[preflight] ${passed ? "✓" : "✗"} Pre-flight ${passed ? "passed" : "FAILED"} (${duration}ms)`,
    );

    return result;
  }

  // ── Individual check phases ────────────────────────────────────────────

  /**
   * Check all dependency types for a tool manifest.
   *
   * Checks binaries, Python modules, npm packages, system libraries,
   * and required files. If any required dependency is missing and
   * auto-install is enabled, attempts installation via {@link AutoInstaller}.
   */
  async checkDependencies(
    manifest: ToolManifest,
  ): Promise<PreflightResult["dependencies"]> {
    const checked: DependencyCheck[] = [];
    const warnings: string[] = [];

    // 1. Required binaries — via isBinaryInstalled from dependency-validator
    for (const bin of manifest.requiredBinaries) {
      const found = await isBinaryInstalled(bin);
      checked.push({ name: bin, type: "binary", required: true, found });
    }

    // 2. Optional binaries — same check, required=false
    for (const bin of manifest.optionalBinaries ?? []) {
      const found = await isBinaryInstalled(bin);
      checked.push({ name: bin, type: "binary", required: false, found });
      if (!found) {
        warnings.push(`Optional dependency '${bin}' (binary) not found`);
      }
    }

    // 3. Required Python modules — via python3 -c "import <module>"
    for (const mod of manifest.requiredPythonModules ?? []) {
      const found = isPythonModuleInstalled(mod);
      checked.push({
        name: mod,
        type: "python-module",
        required: true,
        found,
      });
    }

    // 4. Optional Python modules
    for (const mod of manifest.optionalPythonModules ?? []) {
      const found = isPythonModuleInstalled(mod);
      checked.push({
        name: mod,
        type: "python-module",
        required: false,
        found,
      });
      if (!found) {
        warnings.push(
          `Optional dependency '${mod}' (python-module) not found`,
        );
      }
    }

    // 5. Required npm packages — via which <package>
    for (const pkg of manifest.requiredNpmPackages ?? []) {
      const found = isNpmPackageInstalled(pkg);
      checked.push({
        name: pkg,
        type: "npm-package",
        required: true,
        found,
      });
    }

    // 6. Optional npm packages
    for (const pkg of manifest.optionalNpmPackages ?? []) {
      const found = isNpmPackageInstalled(pkg);
      checked.push({
        name: pkg,
        type: "npm-package",
        required: false,
        found,
      });
      if (!found) {
        warnings.push(
          `Optional dependency '${pkg}' (npm-package) not found`,
        );
      }
    }

    // 7. Required libraries — via pkg-config --exists or ldconfig -p | grep
    for (const lib of manifest.requiredLibraries ?? []) {
      const found = isLibraryInstalled(lib);
      checked.push({ name: lib, type: "library", required: true, found });
    }

    // 8. Required files — via fs.existsSync
    for (const filePath of manifest.requiredFiles ?? []) {
      const found = existsSync(filePath);
      checked.push({ name: filePath, type: "file", required: true, found });
    }

    // ── Auto-install missing required deps ───────────────────────────────
    const missingRequired = checked.filter((c) => c.required && !c.found);

    if (missingRequired.length > 0 && this.autoInstaller.isEnabled()) {
      const missingBinaries = missingRequired
        .filter((c) => c.type === "binary")
        .map((c) => c.name);
      const missingPython = missingRequired
        .filter((c) => c.type === "python-module")
        .map((c) => c.name);
      const missingNpm = missingRequired
        .filter((c) => c.type === "npm-package")
        .map((c) => c.name);
      const missingLibraries = missingRequired
        .filter((c) => c.type === "library")
        .map((c) => c.name);

      const installResult = await this.autoInstaller.resolveAll(
        manifest,
        missingBinaries,
        missingPython.length > 0 ? missingPython : undefined,
        missingNpm.length > 0 ? missingNpm : undefined,
        missingLibraries.length > 0 ? missingLibraries : undefined,
      );

      // Clear dependency cache so re-checks hit disk
      clearDependencyCache();

      // Re-check previously missing deps after install attempts
      for (const check of checked) {
        if (check.required && !check.found) {
          let nowFound = false;
          switch (check.type) {
            case "binary":
              nowFound = await isBinaryInstalled(check.name);
              break;
            case "python-module":
              nowFound = isPythonModuleInstalled(check.name);
              break;
            case "npm-package":
              nowFound = isNpmPackageInstalled(check.name);
              break;
            case "library":
              nowFound = isLibraryInstalled(check.name);
              break;
            case "file":
              nowFound = existsSync(check.name);
              break;
          }
          if (nowFound) {
            check.found = true;
            check.autoInstalled = true;
            // Match to the install attempt for the user-facing message
            const attempt: InstallAttempt | undefined =
              installResult.attempted.find(
                (a) => a.dependency === check.name,
              );
            check.installMessage = attempt?.message;
          }
        }
      }
    }

    const missing = checked.filter((c) => c.required && !c.found);
    const installed = checked.filter((c) => c.autoInstalled === true);

    return { checked, missing, installed, warnings };
  }

  /**
   * Check privilege requirements for a tool manifest.
   * Delegates to {@link PrivilegeManager.checkForTool}.
   */
  async checkPrivileges(
    manifest: ToolManifest,
  ): Promise<PreflightResult["privileges"]> {
    const result = await this.privilegeManager.checkForTool(manifest);
    return {
      satisfied: result.satisfied,
      issues: result.issues,
      recommendations: result.recommendations,
    };
  }

  // ── Summary formatting ─────────────────────────────────────────────────

  /**
   * Generate a human-readable summary of the pre-flight result.
   *
   * @example Passing
   * ```
   * ✅ Pre-flight passed for 'firewall_iptables_list'
   *   Dependencies: 2/2 available (iptables, ip6tables)
   *   Privileges: sudo session active
   *   Ready to execute.
   * ```
   *
   * @example Failing
   * ```
   * ❌ Pre-flight FAILED for 'compliance_oscap_scan'
   *   Missing dependencies:
   *     • oscap (binary) — Install with: sudo apt-get install -y libopenscap8
   *   Privilege issues:
   *     • Root access required for OpenSCAP scanning
   *     → Run 'sudo_elevate' tool first to provide credentials
   *   Cannot proceed until issues are resolved.
   * ```
   */
  formatSummary(result: PreflightResult): string {
    const lines: string[] = [];

    if (result.passed) {
      // ── Passing summary ──────────────────────────────────────────────
      const autoInstalledCount = result.dependencies.installed.length;
      const autoNote =
        autoInstalledCount > 0
          ? ` (auto-installed ${autoInstalledCount} ${autoInstalledCount === 1 ? "dependency" : "dependencies"})`
          : "";
      lines.push(
        `✅ Pre-flight passed for '${result.toolName}'${autoNote}`,
      );

      // Dependencies line
      const requiredChecks = result.dependencies.checked.filter(
        (c) => c.required,
      );
      const requiredFound = requiredChecks.filter((c) => c.found);

      if (requiredChecks.length > 0) {
        const names = requiredFound.map((c) => {
          if (c.autoInstalled && c.installMessage) {
            return `${c.name} — ${c.installMessage}`;
          }
          if (c.autoInstalled) {
            return `${c.name} — auto-installed`;
          }
          return c.name;
        });
        lines.push(
          `  Dependencies: ${requiredFound.length}/${requiredChecks.length} available` +
            (names.length > 0 ? ` (${names.join(", ")})` : ""),
        );
      } else {
        lines.push("  Dependencies: none required");
      }

      // Privileges line
      const manifest = this.registry.getManifest(result.toolName);
      if (manifest && manifest.sudo !== "never") {
        if (result.privileges.satisfied) {
          lines.push("  Privileges: sudo session active");
        } else if (result.privileges.recommendations.length > 0) {
          lines.push(
            `  Privileges: ${result.privileges.recommendations[0]}`,
          );
        }
      } else {
        lines.push("  Privileges: no elevation required");
      }

      lines.push("  Ready to execute.");
    } else {
      // ── Failing summary ──────────────────────────────────────────────
      lines.push(`❌ Pre-flight FAILED for '${result.toolName}'`);

      // Missing dependencies
      if (result.dependencies.missing.length > 0) {
        lines.push("  Missing dependencies:");
        for (const dep of result.dependencies.missing) {
          const hint =
            dep.type === "binary" ? getInstallHint(dep.name) : undefined;
          lines.push(
            `    • ${dep.name} (${dep.type})` +
              (hint ? ` — Install with: ${hint}` : ""),
          );
        }
      }

      // Privilege issues (blocking)
      const blockingIssues = result.privileges.issues.filter(
        (i) =>
          i.type === "sudo-required" || i.type === "sudo-unavailable",
      );
      if (blockingIssues.length > 0) {
        lines.push("  Privilege issues:");
        for (const issue of blockingIssues) {
          lines.push(`    • ${issue.description}`);
          lines.push(`    → ${issue.resolution}`);
        }
      }

      // Safeguard blockers
      if (
        result.safeguards &&
        result.safeguards.blockers.length > 0
      ) {
        lines.push("  Safety blockers:");
        for (const blocker of result.safeguards.blockers) {
          lines.push(`    🛑 ${blocker}`);
        }
      }

      lines.push("  Cannot proceed until issues are resolved.");
    }

    return lines.join("\n");
  }

  /**
   * Generate a shorter status message for prepending to tool output.
   *
   * - Passed (no issues): `"[pre-flight ✓] All checks passed (2 deps, sudo active)"`
   * - Passed (warnings): `"[pre-flight ✓] Passed with warnings: optional dep 'nmap' not found"`
   * - Failed: returns the full error summary from {@link formatSummary}
   */
  formatStatusMessage(result: PreflightResult): string {
    if (!result.passed) {
      // Failed — return full summary
      return this.formatSummary(result);
    }

    const requiredDeps = result.dependencies.checked.filter(
      (c) => c.required,
    );
    const depCount = requiredDeps.length;

    // Determine privilege status string
    const manifest = this.registry.getManifest(result.toolName);
    const needsSudo = manifest != null && manifest.sudo !== "never";
    const privStatus = needsSudo ? ", sudo active" : "";

    // Check for optional missing deps to include as warnings
    const optionalMissing = result.dependencies.checked.filter(
      (c) => !c.required && !c.found,
    );

    if (optionalMissing.length > 0) {
      const missingNames = optionalMissing
        .map((c) => c.name)
        .join("', '");
      return `[pre-flight ✓] Passed with warnings: optional dep '${missingNames}' not found`;
    }

    return `[pre-flight ✓] All checks passed (${depCount} deps${privStatus})`;
  }

  // ── Cache management ───────────────────────────────────────────────────

  /**
   * Clear the result cache.
   * Call after installs, privilege changes, or any event that invalidates
   * previous pre-flight results.
   */
  clearCache(): void {
    this.resultCache.clear();
  }

  // ── Private helpers ────────────────────────────────────────────────────

  /** Store a result in the cache with TTL. */
  private cacheResult(toolName: string, result: PreflightResult): void {
    this.resultCache.set(toolName, {
      result,
      expiry: Date.now() + PreflightEngine.CACHE_TTL,
    });
  }
}
