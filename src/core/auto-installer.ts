/**
 * AutoInstaller — multi-package-manager automatic dependency resolver.
 *
 * Handles installation of missing dependencies across system package managers
 * (apt, dnf, yum, pacman, apk, zypper, brew), pip, and npm.  This module is
 * part of the pre-flight validation pipeline and is invoked when
 * `KALI_DEFENSE_AUTO_INSTALL=true`.
 *
 * Design constraints:
 *   - Uses `execFileSafe` from `spawn-safe.ts` (NOT the executor) to avoid
 *     circular dependencies with `sudo-session`. spawn-safe enforces the
 *     command allowlist and `shell: false` automatically.
 *   - Every `execFileSafe` call is wrapped in try/catch — install failures
 *     must NEVER crash the server.
 *   - Logs exclusively to stderr (`console.error`) because the MCP server
 *     uses stdio for JSON-RPC transport.
 *
 * @module auto-installer
 */

import { execFileSafe } from "./spawn-safe.js";
import { getConfig } from "./config.js";
import { detectDistro, type DistroInfo, type PackageManagerName } from "./distro.js";
import { DEFENSIVE_TOOLS, type ToolRequirement } from "./installer.js";
import { SudoSession } from "./sudo-session.js";
import { resolveCommand } from "./command-allowlist.js";
import { logChange, createChangeEntry } from "./changelog.js";
import type { ToolManifest } from "./tool-registry.js";

// ── Types ────────────────────────────────────────────────────────────────────

export interface InstallAttempt {
  dependency: string;
  type: "binary" | "python-module" | "npm-package" | "library" | "file";
  method:
    | "system-package"
    | "pip"
    | "npm"
    | "cargo"
    | "go-install"
    | "binary-download"
    | "build-from-source"
    | "vendored"
    | "skipped";
  success: boolean;
  message: string;
  duration?: number;
}

export interface AutoInstallResult {
  attempted: InstallAttempt[];
  allResolved: boolean;
  unresolvedDependencies: string[];
}

// ── Python import name mapping ───────────────────────────────────────────────

/**
 * Maps pip package names to their Python import names when they differ.
 */
const PYTHON_IMPORT_MAP: Record<string, string> = {
  "yara-python": "yara",
  "python-nmap": "nmap",
  "python-apt": "apt",
  "PyYAML": "yaml",
  "Pillow": "PIL",
  "scikit-learn": "sklearn",
  "beautifulsoup4": "bs4",
  "python-dateutil": "dateutil",
  "attrs": "attr",
};

// ── Library dev-package suffix mapping per distro family ──────────────────────

const LIB_DEV_PATTERNS: Record<string, (lib: string) => string[]> = {
  debian: (lib) => [`lib${lib}-dev`, `lib${lib}0-dev`, `lib${lib}1-dev`],
  rhel: (lib) => [`${lib}-devel`, `lib${lib}-devel`],
  suse: (lib) => [`${lib}-devel`, `lib${lib}-devel`],
  arch: (lib) => [lib, `lib${lib}`],
  alpine: (lib) => [`${lib}-dev`, `lib${lib}-dev`],
};

// ── Approved packages allowlist ──────────────────────────────────────────────

/**
 * Build a Set of all approved package names derived from DEFENSIVE_TOOLS.
 * Only packages in this set may be installed by the auto-installer.
 */
function buildApprovedPackages(): Set<string> {
  const approved = new Set<string>();
  for (const tool of DEFENSIVE_TOOLS) {
    const pkgs = tool.packages as Record<string, string | undefined>;
    for (const value of Object.values(pkgs)) {
      if (value) approved.add(value);
    }
  }
  return approved;
}

let _approvedPackages: Set<string> | null = null;

/** Get the lazily-built approved packages allowlist. */
function getApprovedPackages(): Set<string> {
  if (!_approvedPackages) {
    _approvedPackages = buildApprovedPackages();
  }
  return _approvedPackages;
}

// ── Package name validation ──────────────────────────────────────────────────

/**
 * Validate that a package name contains only safe characters.
 * Allowed: alphanumeric, hyphens, dots, plus signs, colons (for arch qualifiers).
 * No shell metacharacters, no path separators, no spaces.
 * Max length: 128 characters.
 */
export function validatePackageName(name: string): boolean {
  return /^[a-zA-Z0-9][a-zA-Z0-9.+\-:]{0,127}$/.test(name);
}

/**
 * Validate a pip/npm module name for safe characters.
 * Slightly more permissive than system package names — also allows underscores.
 */
function validateModuleName(name: string): boolean {
  return /^[a-zA-Z0-9][a-zA-Z0-9._+\-]{0,127}$/.test(name);
}

// ── Helper: DEFENSIVE_TOOLS lookup by binary name ────────────────────────────

/** Build a lookup map from binary → ToolRequirement on first access. */
let _binaryLookup: Map<string, ToolRequirement> | null = null;

function getBinaryLookup(): Map<string, ToolRequirement> {
  if (!_binaryLookup) {
    _binaryLookup = new Map();
    for (const tool of DEFENSIVE_TOOLS) {
      _binaryLookup.set(tool.binary, tool);
    }
  }
  return _binaryLookup;
}

// ── Helper: execute with sudo if needed ──────────────────────────────────────

function isRoot(): boolean {
  return process.geteuid?.() === 0;
}

/**
 * Run a command synchronously, optionally with sudo.
 * Returns `{ stdout, success }`.
 *
 * Uses execFileSafe for allowlist enforcement and shell: false.
 * The target command inside sudo args is still resolved manually
 * since execFileSafe only resolves the top-level command.
 */
function execWithSudo(
  args: string[],
  options?: { timeoutMs?: number; useSudo?: boolean },
): { stdout: string; success: boolean; stderr: string } {
  const timeout = options?.timeoutMs ?? 300_000;
  const needsSudo = (options?.useSudo ?? true) && !isRoot();

  if (needsSudo) {
    // Resolve the target command via allowlist (sudo itself is resolved by execFileSafe)
    const resolvedTargetCmd = resolveCommand(args[0]);
    const resolvedArgs = [resolvedTargetCmd, ...args.slice(1)];

    const session = SudoSession.getInstance();
    const passwordBuf = session.getPassword(); // Returns Buffer | null (a copy)
    // Use -S to read password from stdin, -p '' to suppress prompt
    const cmdArgs = ["-S", "-p", "", ...resolvedArgs];

    let inputBuf: Buffer | undefined;
    if (passwordBuf) {
      const newline = Buffer.from("\n");
      inputBuf = Buffer.concat([passwordBuf, newline]);
      passwordBuf.fill(0); // Zero the password copy immediately
    }

    try {
      const stdout = execFileSafe("sudo", cmdArgs, {
        timeout,
        maxBuffer: 10 * 1024 * 1024,
        encoding: "utf-8",
        input: inputBuf,
        stdio: inputBuf ? ["pipe", "pipe", "pipe"] : ["inherit", "pipe", "pipe"],
      });
      return { stdout: (stdout ?? "") as string, success: true, stderr: "" };
    } catch (err: unknown) {
      const execErr = err as { stdout?: string; stderr?: string };
      return {
        stdout: execErr.stdout ?? "",
        success: false,
        stderr: execErr.stderr ?? String(err),
      };
    } finally {
      // Zero the input buffer after use regardless of success/failure
      if (inputBuf) inputBuf.fill(0);
    }
  } else {
    // Running as root — execute directly; execFileSafe resolves via allowlist
    try {
      const stdout = execFileSafe(args[0], args.slice(1), {
        timeout,
        maxBuffer: 10 * 1024 * 1024,
        encoding: "utf-8",
        stdio: ["pipe", "pipe", "pipe"],
      });
      return { stdout: (stdout ?? "") as string, success: true, stderr: "" };
    } catch (err: unknown) {
      const execErr = err as { stdout?: string; stderr?: string };
      return {
        stdout: execErr.stdout ?? "",
        success: false,
        stderr: execErr.stderr ?? String(err),
      };
    }
  }
}

/**
 * Run a command synchronously WITHOUT sudo.
 * execFileSafe handles allowlist resolution and shell: false.
 */
function execSimple(
  command: string,
  args: string[],
  options?: { timeoutMs?: number; input?: string },
): { stdout: string; success: boolean; stderr: string } {
  try {
    const stdout = execFileSafe(command, args, {
      timeout: options?.timeoutMs ?? 30_000,
      maxBuffer: 10 * 1024 * 1024,
      encoding: "utf-8",
      input: options?.input,
      stdio: ["pipe", "pipe", "pipe"],
    });
    return { stdout: (stdout ?? "") as string, success: true, stderr: "" };
  } catch (err: unknown) {
    const execErr = err as { stdout?: string; stderr?: string };
    return {
      stdout: execErr.stdout ?? "",
      success: false,
      stderr: execErr.stderr ?? String(err),
    };
  }
}

// ── Helper: check if a binary is available ───────────────────────────────────

function binaryAvailable(binary: string): boolean {
  try {
    execFileSafe("which", [binary], {
      timeout: 5_000,
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
    });
    return true;
  } catch {
    return false;
  }
}

// ── Helper: resolve package install command args per distro ───────────────────

function getInstallArgs(
  pkgManager: PackageManagerName,
  packageName: string,
): string[] {
  switch (pkgManager) {
    case "apt":
      return ["apt-get", "install", "-y", packageName];
    case "dnf":
      return ["dnf", "install", "-y", packageName];
    case "yum":
      return ["yum", "install", "-y", packageName];
    case "pacman":
      return ["pacman", "-S", "--noconfirm", packageName];
    case "apk":
      return ["apk", "add", packageName];
    case "zypper":
      return ["zypper", "install", "-y", packageName];
    case "brew":
      // brew should never be run with sudo
      return ["brew", "install", packageName];
    default:
      return [];
  }
}

// ── AutoInstaller ────────────────────────────────────────────────────────────

export class AutoInstaller {
  private static _instance: AutoInstaller | null = null;
  private distroCache: DistroInfo | null = null;

  /** Get or create the singleton instance. */
  static instance(): AutoInstaller {
    if (!AutoInstaller._instance) {
      AutoInstaller._instance = new AutoInstaller();
      // Fix E: Warn when auto-install is enabled
      if (AutoInstaller._instance.isEnabled()) {
        console.error(
          "[auto-install] ⚠ Auto-installation is ENABLED. Packages will be installed with sudo when missing dependencies are detected.",
        );
      }
    }
    return AutoInstaller._instance;
  }

  /**
   * Reset the singleton (for testing).
   * @internal
   */
  static resetInstance(): void {
    AutoInstaller._instance = null;
  }

  /** Check if auto-install is enabled via config. */
  isEnabled(): boolean {
    return getConfig().autoInstall;
  }

  /**
   * Resolve all missing dependencies for a tool manifest.
   *
   * If auto-install is disabled, returns all dependencies as unresolved
   * with method `'skipped'`.
   */
  async resolveAll(
    manifest: ToolManifest,
    missingBinaries: string[],
    missingPython?: string[],
    missingNpm?: string[],
    missingLibraries?: string[],
  ): Promise<AutoInstallResult> {
    const attempted: InstallAttempt[] = [];

    // Early return if auto-install is disabled
    if (!this.isEnabled()) {
      const allMissing = [
        ...missingBinaries,
        ...(missingPython ?? []),
        ...(missingNpm ?? []),
        ...(missingLibraries ?? []),
      ];

      for (const dep of missingBinaries) {
        attempted.push({
          dependency: dep,
          type: "binary",
          method: "skipped",
          success: false,
          message: "Auto-install is disabled (set KALI_DEFENSE_AUTO_INSTALL=true to enable)",
        });
      }
      for (const dep of missingPython ?? []) {
        attempted.push({
          dependency: dep,
          type: "python-module",
          method: "skipped",
          success: false,
          message: "Auto-install is disabled (set KALI_DEFENSE_AUTO_INSTALL=true to enable)",
        });
      }
      for (const dep of missingNpm ?? []) {
        attempted.push({
          dependency: dep,
          type: "npm-package",
          method: "skipped",
          success: false,
          message: "Auto-install is disabled (set KALI_DEFENSE_AUTO_INSTALL=true to enable)",
        });
      }
      for (const dep of missingLibraries ?? []) {
        attempted.push({
          dependency: dep,
          type: "library",
          method: "skipped",
          success: false,
          message: "Auto-install is disabled (set KALI_DEFENSE_AUTO_INSTALL=true to enable)",
        });
      }

      return {
        attempted,
        allResolved: false,
        unresolvedDependencies: allMissing,
      };
    }

    console.error(
      `[auto-installer] Resolving dependencies for '${manifest.toolName}': ` +
        `${missingBinaries.length} binaries, ` +
        `${missingPython?.length ?? 0} python, ` +
        `${missingNpm?.length ?? 0} npm, ` +
        `${missingLibraries?.length ?? 0} libraries`,
    );

    // Install binaries
    for (const binary of missingBinaries) {
      const result = await this.installBinary(binary);
      attempted.push(result);
    }

    // Install Python modules
    for (const mod of missingPython ?? []) {
      const result = await this.installPythonModule(mod);
      attempted.push(result);
    }

    // Install npm packages
    for (const pkg of missingNpm ?? []) {
      const result = await this.installNpmPackage(pkg);
      attempted.push(result);
    }

    // Install libraries
    for (const lib of missingLibraries ?? []) {
      const result = await this.installLibrary(lib);
      attempted.push(result);
    }

    // Collect results
    const unresolved = attempted
      .filter((a) => !a.success)
      .map((a) => a.dependency);

    const allResolved = unresolved.length === 0;

    // Summary
    const succeeded = attempted.filter((a) => a.success).length;
    const failed = attempted.filter((a) => !a.success && a.method !== "skipped").length;

    if (attempted.length > 0) {
      console.error(
        `[auto-installer] Summary for '${manifest.toolName}': ` +
          `${succeeded} installed, ${failed} failed, ${unresolved.length} unresolved`,
      );
    }

    return { attempted, allResolved, unresolvedDependencies: unresolved };
  }

  /**
   * Install a system binary via the detected package manager.
   *
   * 1. Look up binary in DEFENSIVE_TOOLS for distro-specific package name
   * 2. If not found, try binary name directly as package name
   * 3. Verify with `which <binary>` after install
   */
  async installBinary(binary: string): Promise<InstallAttempt> {
    const start = Date.now();
    const distro = await this.getDistro();

    if (distro.packageManager === "unknown") {
      return {
        dependency: binary,
        type: "binary",
        method: "system-package",
        success: false,
        message: "Cannot install: unknown package manager",
        duration: Date.now() - start,
      };
    }

    // Step 1: Look up in DEFENSIVE_TOOLS — only approved packages can be installed
    const lookup = getBinaryLookup();
    const toolReq = lookup.get(binary);

    if (!toolReq) {
      // Binary not in approved package list — refuse to install
      console.error(
        `[auto-install] ⚠ Binary "${binary}" not in approved package list — skipping auto-install`,
      );
      return {
        dependency: binary,
        type: "binary",
        method: "system-package",
        success: false,
        message: `Binary "${binary}" is not in the approved DEFENSIVE_TOOLS list. Auto-install refused.`,
        duration: Date.now() - start,
      };
    }

    // Resolve distro-specific package name (no raw binary name fallback)
    const packageName: string =
      (toolReq.packages as Record<string, string | undefined>)[distro.family] ??
      toolReq.packages.fallback ??
      "";

    if (!packageName) {
      console.error(
        `[auto-install] ⚠ No package mapping for binary "${binary}" on ${distro.family} — skipping`,
      );
      return {
        dependency: binary,
        type: "binary",
        method: "system-package",
        success: false,
        message: `No package mapping for "${binary}" on distro family "${distro.family}"`,
        duration: Date.now() - start,
      };
    }

    // Validate package name for safe characters
    if (!validatePackageName(packageName)) {
      console.error(
        `[auto-install] ⚠ Invalid package name "${packageName}" for binary "${binary}" — skipping`,
      );
      return {
        dependency: binary,
        type: "binary",
        method: "system-package",
        success: false,
        message: `Package name "${packageName}" contains invalid characters. Auto-install refused.`,
        duration: Date.now() - start,
      };
    }

    // Verify package is in the approved allowlist
    if (!getApprovedPackages().has(packageName)) {
      console.error(
        `[auto-install] ⚠ Package "${packageName}" not in approved allowlist — skipping`,
      );
      return {
        dependency: binary,
        type: "binary",
        method: "system-package",
        success: false,
        message: `Package "${packageName}" is not in the approved packages allowlist.`,
        duration: Date.now() - start,
      };
    }

    console.error(
      `[auto-installer] Installing binary '${binary}' via ${distro.packageManager} (package: ${packageName})...`,
    );

    // Build install command args
    const installArgs = getInstallArgs(distro.packageManager, packageName);
    if (installArgs.length === 0) {
      return {
        dependency: binary,
        type: "binary",
        method: "system-package",
        success: false,
        message: `No install command available for package manager '${distro.packageManager}'`,
        duration: Date.now() - start,
      };
    }

    // Execute install (brew doesn't use sudo)
    const useSudo = distro.packageManager !== "brew";
    const result = execWithSudo(installArgs, { useSudo, timeoutMs: 300_000 });

    if (!result.success) {
      const elapsed = ((Date.now() - start) / 1000).toFixed(1);
      console.error(
        `[auto-installer] ✗ Failed to install '${binary}' (package: ${packageName}): ${result.stderr.slice(0, 200)}`,
      );
      return {
        dependency: binary,
        type: "binary",
        method: "system-package",
        success: false,
        message: `Failed to install package '${packageName}': ${result.stderr.slice(0, 300)}`,
        duration: Date.now() - start,
      };
    }

    // Verify installation
    const installed = binaryAvailable(binary);
    const elapsed = ((Date.now() - start) / 1000).toFixed(1);

    if (installed) {
      console.error(
        `[auto-installer] ✓ Installed '${binary}' via ${distro.packageManager} (${elapsed}s)`,
      );
      // Log successful installation to the audit changelog
      logChange(createChangeEntry({
        tool: "auto-installer",
        action: `Installed system package: ${packageName}`,
        target: packageName,
        before: "not installed",
        after: `installed via ${distro.packageManager}`,
        dryRun: false,
        success: true,
      }));
    } else {
      console.error(
        `[auto-installer] ⚠ Package '${packageName}' installed but binary '${binary}' not found in PATH`,
      );
    }

    return {
      dependency: binary,
      type: "binary",
      method: "system-package",
      success: installed,
      message: installed
        ? `Installed '${binary}' via ${distro.packageManager} (${packageName})`
        : `Package '${packageName}' installed but binary '${binary}' not found in PATH`,
      duration: Date.now() - start,
    };
  }

  /**
   * Install a Python module via pip.
   *
   * 1. Check if pip3 or pip exists
   * 2. Try user-site install first (no sudo)
   * 3. If that fails, try with sudo
   * 4. Verify with `python3 -c "import <module>"`
   */
  async installPythonModule(module: string): Promise<InstallAttempt> {
    const start = Date.now();

    // Determine pip command
    const pip = binaryAvailable("pip3") ? "pip3" : binaryAvailable("pip") ? "pip" : null;

    if (!pip) {
      console.error(`[auto-installer] ✗ Cannot install Python module '${module}': pip not found`);
      return {
        dependency: module,
        type: "python-module",
        method: "pip",
        success: false,
        message: "pip/pip3 not found. Install python3-pip first.",
        duration: Date.now() - start,
      };
    }

    // Validate module name for safe characters
    if (!validateModuleName(module)) {
      console.error(
        `[auto-install] ⚠ Invalid Python module name "${module}" — skipping`,
      );
      return {
        dependency: module,
        type: "python-module",
        method: "pip",
        success: false,
        message: `Python module name "${module}" contains invalid characters. Auto-install refused.`,
        duration: Date.now() - start,
      };
    }

    console.error(`[auto-installer] Installing Python module '${module}' via ${pip}...`);

    // Try user-site install first (no sudo needed)
    let result = execSimple(pip, ["install", "--user", module], { timeoutMs: 120_000 });

    if (!result.success) {
      // Try with sudo if user-site failed
      console.error(
        `[auto-installer] User-site install failed for '${module}', trying with sudo...`,
      );
      result = execWithSudo([pip, "install", module], { timeoutMs: 120_000 });
    }

    if (!result.success) {
      const elapsed = ((Date.now() - start) / 1000).toFixed(1);
      console.error(
        `[auto-installer] ✗ Failed to install Python module '${module}': ${result.stderr.slice(0, 200)}`,
      );
      return {
        dependency: module,
        type: "python-module",
        method: "pip",
        success: false,
        message: `Failed to install '${module}' via pip: ${result.stderr.slice(0, 300)}`,
        duration: Date.now() - start,
      };
    }

    // Verify: determine the import name
    const importName = PYTHON_IMPORT_MAP[module] ?? module.replace(/-/g, "_");
    const python = binaryAvailable("python3") ? "python3" : "python";
    const verifyResult = execSimple(python, ["-c", `import ${importName}`], { timeoutMs: 10_000 });

    const elapsed = ((Date.now() - start) / 1000).toFixed(1);

    if (verifyResult.success) {
      console.error(`[auto-installer] ✓ Installed Python module '${module}' (${elapsed}s)`);
      // Log successful installation to the audit changelog
      logChange(createChangeEntry({
        tool: "auto-installer",
        action: `Installed Python module: ${module}`,
        target: module,
        before: "not installed",
        after: `installed via ${pip}`,
        dryRun: false,
        success: true,
      }));
    } else {
      console.error(
        `[auto-installer] ⚠ pip install succeeded for '${module}' but import verification failed`,
      );
    }

    return {
      dependency: module,
      type: "python-module",
      method: "pip",
      success: verifyResult.success,
      message: verifyResult.success
        ? `Installed '${module}' via ${pip}`
        : `pip install succeeded but 'import ${importName}' failed`,
      duration: Date.now() - start,
    };
  }

  /**
   * Install an npm package globally.
   *
   * 1. Check if npm exists
   * 2. Run `npm install -g <package>` with sudo if needed
   * 3. Verify by checking if the package provides an expected binary
   */
  async installNpmPackage(pkg: string): Promise<InstallAttempt> {
    const start = Date.now();

    if (!binaryAvailable("npm")) {
      console.error(`[auto-installer] ✗ Cannot install npm package '${pkg}': npm not found`);
      return {
        dependency: pkg,
        type: "npm-package",
        method: "npm",
        success: false,
        message: "npm not found. Install Node.js/npm first.",
        duration: Date.now() - start,
      };
    }

    // Validate npm package name for safe characters
    if (!validateModuleName(pkg)) {
      console.error(
        `[auto-install] ⚠ Invalid npm package name "${pkg}" — skipping`,
      );
      return {
        dependency: pkg,
        type: "npm-package",
        method: "npm",
        success: false,
        message: `npm package name "${pkg}" contains invalid characters. Auto-install refused.`,
        duration: Date.now() - start,
      };
    }

    console.error(`[auto-installer] Installing npm package '${pkg}' globally...`);

    // Try without sudo first (in case npm is configured with a user-writable prefix)
    let result = execSimple("npm", ["install", "-g", pkg], { timeoutMs: 120_000 });

    if (!result.success) {
      // Try with sudo
      console.error(
        `[auto-installer] Non-sudo npm install failed for '${pkg}', trying with sudo...`,
      );
      result = execWithSudo(["npm", "install", "-g", pkg], { timeoutMs: 120_000 });
    }

    const elapsed = ((Date.now() - start) / 1000).toFixed(1);

    if (!result.success) {
      console.error(
        `[auto-installer] ✗ Failed to install npm package '${pkg}': ${result.stderr.slice(0, 200)}`,
      );
      return {
        dependency: pkg,
        type: "npm-package",
        method: "npm",
        success: false,
        message: `Failed to install '${pkg}' via npm: ${result.stderr.slice(0, 300)}`,
        duration: Date.now() - start,
      };
    }

    // Verify — many npm packages provide a binary with the same name
    const installed = binaryAvailable(pkg);

    if (installed) {
      console.error(`[auto-installer] ✓ Installed npm package '${pkg}' (${elapsed}s)`);
    } else {
      // Package installed but binary might have a different name
      console.error(
        `[auto-installer] ✓ npm package '${pkg}' installed (binary may differ from package name)`,
      );
    }

    // Log successful npm installation to the audit changelog
    logChange(createChangeEntry({
      tool: "auto-installer",
      action: `Installed npm package: ${pkg}`,
      target: pkg,
      before: "not installed",
      after: "installed via npm (global)",
      dryRun: false,
      success: true,
    }));

    return {
      dependency: pkg,
      type: "npm-package",
      method: "npm",
      // Consider success if npm install succeeded, even if binary name differs
      success: true,
      message: installed
        ? `Installed '${pkg}' via npm (binary verified)`
        : `Installed '${pkg}' via npm (binary name may differ)`,
      duration: Date.now() - start,
    };
  }

  /**
   * Install a system library (development headers).
   *
   * 1. Determine dev package name based on distro family
   * 2. Try installing the first candidate that works
   * 3. Verify with `ldconfig -p | grep <lib>` or `pkg-config --exists <lib>`
   */
  async installLibrary(lib: string): Promise<InstallAttempt> {
    const start = Date.now();
    const distro = await this.getDistro();

    if (distro.packageManager === "unknown") {
      return {
        dependency: lib,
        type: "library",
        method: "system-package",
        success: false,
        message: "Cannot install: unknown package manager",
        duration: Date.now() - start,
      };
    }

    console.error(
      `[auto-installer] Installing library '${lib}' via ${distro.packageManager}...`,
    );

    // Get candidate package names for this distro family
    const patternFn = LIB_DEV_PATTERNS[distro.family];
    const candidates = patternFn ? patternFn(lib) : [`lib${lib}-dev`, lib];

    let installed = false;
    let lastError = "";

    for (const candidate of candidates) {
      // Validate candidate package name for safe characters
      if (!validatePackageName(candidate)) {
        console.error(
          `[auto-install] ⚠ Invalid library package name "${candidate}" — skipping candidate`,
        );
        continue;
      }

      const installArgs = getInstallArgs(distro.packageManager, candidate);
      if (installArgs.length === 0) continue;

      const useSudo = distro.packageManager !== "brew";
      const result = execWithSudo(installArgs, { useSudo, timeoutMs: 120_000 });

      if (result.success) {
        installed = true;
        console.error(
          `[auto-installer] ✓ Installed library '${lib}' (package: ${candidate})`,
        );
        // Log successful library installation to the audit changelog
        logChange(createChangeEntry({
          tool: "auto-installer",
          action: `Installed library package: ${candidate}`,
          target: candidate,
          before: "not installed",
          after: `installed via ${distro.packageManager}`,
          dryRun: false,
          success: true,
        }));
        break;
      }
      lastError = result.stderr.slice(0, 200);
    }

    if (!installed) {
      const elapsed = ((Date.now() - start) / 1000).toFixed(1);
      console.error(
        `[auto-installer] ✗ Failed to install library '${lib}': ${lastError}`,
      );
      return {
        dependency: lib,
        type: "library",
        method: "system-package",
        success: false,
        message: `Failed to install library '${lib}'. Tried: ${candidates.join(", ")}`,
        duration: Date.now() - start,
      };
    }

    // Verify with ldconfig or pkg-config
    const verified = this.verifyLibrary(lib);
    const elapsed = ((Date.now() - start) / 1000).toFixed(1);

    if (verified) {
      console.error(
        `[auto-installer] ✓ Library '${lib}' verified (${elapsed}s)`,
      );
    } else {
      console.error(
        `[auto-installer] ⚠ Library package installed but '${lib}' not found via ldconfig/pkg-config`,
      );
    }

    return {
      dependency: lib,
      type: "library",
      method: "system-package",
      // Consider success if package install succeeded even if ldconfig doesn't show it yet
      success: true,
      message: verified
        ? `Installed and verified library '${lib}'`
        : `Package installed for '${lib}' (ldconfig/pkg-config verification inconclusive)`,
      duration: Date.now() - start,
    };
  }

  // ── Private helpers ──────────────────────────────────────────────────────

  /**
   * Get (and cache) the detected distro info.
   */
  private async getDistro(): Promise<DistroInfo> {
    if (!this.distroCache) {
      this.distroCache = await detectDistro();
    }
    return this.distroCache;
  }

  /**
   * Verify a library is available via ldconfig or pkg-config.
   */
  private verifyLibrary(lib: string): boolean {
    // Try pkg-config first
    if (binaryAvailable("pkg-config")) {
      const pkgResult = execSimple("pkg-config", ["--exists", lib], { timeoutMs: 5_000 });
      if (pkgResult.success) return true;
    }

    // Try ldconfig -p | grep
    try {
      const ldconfigResult = execSimple("ldconfig", ["-p"], { timeoutMs: 10_000 });
      if (ldconfigResult.success && ldconfigResult.stdout.includes(lib)) {
        return true;
      }
    } catch {
      // ldconfig might not be available or might need sudo
    }

    return false;
  }
}
