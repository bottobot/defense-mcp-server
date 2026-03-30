/**
 * Third-party security tool installer with cryptographic verification.
 *
 * SECURITY: This module NEVER uses curl|sh patterns. All downloads are
 * verified before execution. See docs/adr/third-party-tool-installation.md
 *
 * Installation flow:
 *   1. Download artifact to a temp directory
 *   2. Verify SHA256 checksum against hardcoded manifest value
 *   3. Extract (if tarball) or chmod +x (if single binary)
 *   4. Move binary to /usr/local/bin via sudo
 *   5. Log to changelog audit trail
 *
 * @module third-party-installer
 */

import { createHash, randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, unlinkSync, readdirSync, rmdirSync } from "node:fs";
import { join } from "node:path";

import { execFileSafe } from "./spawn-safe.js";
import { resolveCommand } from "./command-allowlist.js";
import { logChange, createChangeEntry } from "./changelog.js";
import { SudoSession } from "./sudo-session.js";
import {
  THIRD_PARTY_MANIFEST,
  getManifestEntry,
  isChecksumPopulated,
  getPlatformArchKey,
  type ThirdPartyManifestEntry,
} from "./third-party-manifest.js";

// ── Types ────────────────────────────────────────────────────────────────────

export interface ThirdPartyToolStatus {
  binary: string;
  name: string;
  installed: boolean;
  currentVersion?: string;
  manifestVersion: string;
  needsUpdate: boolean;
}

export interface InstallOptions {
  /** Force reinstall even if already installed at correct version */
  force?: boolean;
}

export interface ThirdPartyInstallResult {
  binary: string;
  success: boolean;
  message: string;
}

// ── Constants ────────────────────────────────────────────────────────────────

const INSTALL_TEMP_PREFIX = "/tmp/defense-mcp-install-";

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Check if third-party installation is enabled via environment variable.
 * Requires DEFENSE_MCP_THIRD_PARTY_INSTALL=true.
 */
export function isThirdPartyInstallEnabled(): boolean {
  return process.env.DEFENSE_MCP_THIRD_PARTY_INSTALL === "true";
}

/**
 * Check if auto-install is enabled via environment variable.
 * Requires DEFENSE_MCP_AUTO_INSTALL=true.
 */
function isAutoInstallEnabled(): boolean {
  return process.env.DEFENSE_MCP_AUTO_INSTALL === "true";
}

/**
 * Check if running as root.
 */
function isRoot(): boolean {
  return process.geteuid?.() === 0;
}

/**
 * Execute a command synchronously via execFileSafe.
 * Returns { stdout, success, stderr }.
 */
function execSafe(
  command: string,
  args: string[],
  options?: { timeoutMs?: number; input?: Buffer },
): { stdout: string; success: boolean; stderr: string } {
  try {
    const stdout = execFileSafe(command, args, {
      timeout: options?.timeoutMs ?? 60_000,
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

/**
 * Execute a command with sudo if not root.
 */
function execWithSudo(
  args: string[],
  options?: { timeoutMs?: number },
): { stdout: string; success: boolean; stderr: string } {
  const timeout = options?.timeoutMs ?? 300_000;
  const needsSudo = !isRoot();

  if (needsSudo) {
    const resolvedTargetCmd = resolveCommand(args[0]);
    const resolvedArgs = [resolvedTargetCmd, ...args.slice(1)];

    const session = SudoSession.getInstance();
    const passwordBuf = session.getPassword();
    const cmdArgs = ["-S", "-p", "", ...resolvedArgs];

    let inputBuf: Buffer | undefined;
    if (passwordBuf) {
      const newline = Buffer.from("\n");
      inputBuf = Buffer.concat([passwordBuf, newline]);
      passwordBuf.fill(0);
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
      if (inputBuf) inputBuf.fill(0);
    }
  } else {
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
 * Compute SHA256 hash of a file.
 */
function computeFileSha256(filePath: string): string {
  const data = readFileSync(filePath);
  return createHash("sha256").update(data).digest("hex");
}

/**
 * Create a temporary directory for downloads.
 */
function createTempDir(): string {
  const dir = `${INSTALL_TEMP_PREFIX}${randomUUID()}`;
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

/**
 * Clean up a temporary directory.
 */
function cleanupTempDir(dir: string): void {
  try {
    if (existsSync(dir)) {
      const files = readdirSync(dir);
      for (const file of files) {
        try {
          unlinkSync(join(dir, file));
        } catch {
          // Best effort cleanup
        }
      }
      try {
        rmdirSync(dir);
      } catch {
        // Best effort cleanup
      }
    }
  } catch {
    // Best effort cleanup — don't let cleanup failures propagate
  }
}

/**
 * Resolve the download URL from a template.
 */
function resolveDownloadUrl(template: string, version: string, arch: string): string {
  const archName = arch.replace("linux-", "");
  return template
    .replace(/\{version\}/g, version)
    .replace(/\{arch\}/g, archName);
}

/**
 * Extract the version string from a binary's --version output.
 */
function extractVersion(versionOutput: string): string | undefined {
  const patterns = [
    /(\d+\.\d+\.\d+)/,
    /v(\d+\.\d+\.\d+)/,
  ];
  for (const pattern of patterns) {
    const match = versionOutput.match(pattern);
    if (match) return match[1];
  }
  return undefined;
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Check if a third-party tool is installed and at the correct version.
 * Returns { installed, currentVersion, needsUpdate }
 */
export async function checkThirdPartyTool(binary: string): Promise<ThirdPartyToolStatus> {
  const entry = getManifestEntry(binary);
  if (!entry) {
    return {
      binary,
      name: binary,
      installed: false,
      manifestVersion: "unknown",
      needsUpdate: false,
    };
  }

  // Check if binary exists
  let binaryPath: string | undefined;
  try {
    binaryPath = resolveCommand(binary);
  } catch {
    const standardDirs = ["/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"];
    for (const dir of standardDirs) {
      const candidate = `${dir}/${binary}`;
      if (existsSync(candidate)) {
        binaryPath = candidate;
        break;
      }
    }
  }

  if (!binaryPath) {
    return {
      binary,
      name: entry.name,
      installed: false,
      manifestVersion: entry.version,
      needsUpdate: false,
    };
  }

  // Try to get version
  let currentVersion: string | undefined;
  const versionResult = execSafe(binary, ["--version"], { timeoutMs: 5000 });
  if (versionResult.success) {
    currentVersion = extractVersion(versionResult.stdout);
  } else {
    const altResult = execSafe(binary, ["-V"], { timeoutMs: 5000 });
    if (altResult.success) {
      currentVersion = extractVersion(altResult.stdout);
    }
  }

  const needsUpdate = currentVersion !== undefined && currentVersion !== entry.version;

  return {
    binary,
    name: entry.name,
    installed: true,
    currentVersion,
    manifestVersion: entry.version,
    needsUpdate,
  };
}

/**
 * Install a third-party tool using its manifest entry.
 * Requires DEFENSE_MCP_THIRD_PARTY_INSTALL=true env var.
 * Returns success/failure with detailed message.
 */
export async function installThirdPartyTool(
  binary: string,
  options?: InstallOptions,
): Promise<ThirdPartyInstallResult> {
  const entry = getManifestEntry(binary);
  if (!entry) {
    return {
      binary,
      success: false,
      message: `No manifest entry found for binary "${binary}". It is not a known third-party tool.`,
    };
  }

  // Check consent: both env vars must be set
  if (!isThirdPartyInstallEnabled()) {
    const instructions = getVerifiedInstallInstructions(binary);
    return {
      binary,
      success: false,
      message:
        `Third-party installation is not enabled. ` +
        `Set DEFENSE_MCP_THIRD_PARTY_INSTALL=true (and DEFENSE_MCP_AUTO_INSTALL=true) to enable.\n\n` +
        `Manual installation instructions:\n${instructions}`,
    };
  }

  if (!isAutoInstallEnabled()) {
    return {
      binary,
      success: false,
      message:
        `Auto-install is not enabled. ` +
        `Set DEFENSE_MCP_AUTO_INSTALL=true (in addition to DEFENSE_MCP_THIRD_PARTY_INSTALL=true) to enable.`,
    };
  }

  // Check if already installed at correct version (unless force)
  if (!options?.force) {
    const status = await checkThirdPartyTool(binary);
    if (status.installed && !status.needsUpdate) {
      return {
        binary,
        success: true,
        message: `${entry.name} v${entry.version} is already installed.`,
      };
    }
  }

  console.error(`[third-party-installer] Installing ${entry.name} v${entry.version}...`);

  // Dispatch to the appropriate install method
  switch (entry.installMethod) {
    case "github-release":
      return installGithubRelease(entry);
    case "apt-repo":
      return installAptRepo(entry);
    case "npm-local":
      return installNpmLocal(entry);
    default:
      return {
        binary,
        success: false,
        message: `Unknown install method: ${entry.installMethod}`,
      };
  }
}

/**
 * Get installation instructions (no install) for a tool.
 * Returns human-readable instructions that do NOT use curl|sh.
 */
export function getVerifiedInstallInstructions(binary: string): string {
  const entry = getManifestEntry(binary);
  if (!entry) {
    return `No installation instructions available for "${binary}". It is not a known third-party tool.`;
  }

  switch (entry.installMethod) {
    case "apt-repo":
      return getAptRepoInstructions(entry);
    case "github-release":
      return getGithubReleaseInstructions(entry);
    case "npm-local":
      return getNpmLocalInstructions(entry);
    default:
      return `No installation instructions available for "${binary}".`;
  }
}

/**
 * List all third-party tools with their current status.
 */
export async function listThirdPartyTools(): Promise<ThirdPartyToolStatus[]> {
  const results: ThirdPartyToolStatus[] = [];
  for (const entry of THIRD_PARTY_MANIFEST) {
    const status = await checkThirdPartyTool(entry.binary);
    results.push(status);
  }
  return results;
}

// ── Install Methods ──────────────────────────────────────────────────────────

/**
 * Install a tool from a GitHub release binary.
 * Downloads to temp dir, verifies SHA256, installs to /usr/local/bin.
 */
async function installGithubRelease(
  entry: ThirdPartyManifestEntry,
): Promise<ThirdPartyInstallResult> {
  const archKey = getPlatformArchKey();

  // Verify SHA256 checksum is populated
  if (!entry.sha256 || !entry.sha256[archKey]) {
    return {
      binary: entry.binary,
      success: false,
      message:
        `No SHA256 checksum available for ${entry.name} on ${archKey}. ` +
        `Cannot verify download integrity.`,
    };
  }

  const expectedSha256 = entry.sha256[archKey];
  if (!isChecksumPopulated(expectedSha256)) {
    return {
      binary: entry.binary,
      success: false,
      message:
        `SHA256 checksum for ${entry.name} (${archKey}) is 'PENDING_FETCH'. ` +
        `The operator must populate the checksum in src/core/third-party-manifest.ts ` +
        `before enabling DEFENSE_MCP_THIRD_PARTY_INSTALL=true. ` +
        `Fetch from: https://github.com/${entry.githubRepo}/releases/tag/v${entry.version}`,
    };
  }

  if (!entry.downloadUrlTemplate) {
    return {
      binary: entry.binary,
      success: false,
      message: `No download URL template configured for ${entry.name}.`,
    };
  }

  const downloadUrl = resolveDownloadUrl(entry.downloadUrlTemplate, entry.version, archKey);
  const tempDir = createTempDir();
  const isTarball = downloadUrl.endsWith(".tar.gz");
  const downloadFilename = isTarball
    ? `${entry.binary}.tar.gz`
    : entry.binary;
  const downloadPath = join(tempDir, downloadFilename);

  try {
    // Step 1: Download to temp file (NEVER pipe to sh)
    console.error(`[third-party-installer] Downloading ${downloadUrl}...`);
    const downloadResult = execSafe("curl", [
      "-fsSL",
      "-o", downloadPath,
      "--max-time", "120",
      downloadUrl,
    ], { timeoutMs: 180_000 });

    if (!downloadResult.success) {
      return {
        binary: entry.binary,
        success: false,
        message: `Failed to download ${entry.name}: ${downloadResult.stderr.slice(0, 300)}`,
      };
    }

    // Step 2: Verify SHA256
    console.error(`[third-party-installer] Verifying SHA256 checksum...`);
    const actualSha256 = computeFileSha256(downloadPath);
    if (actualSha256 !== expectedSha256) {
      return {
        binary: entry.binary,
        success: false,
        message:
          `SHA256 MISMATCH for ${entry.name}! ` +
          `Expected: ${expectedSha256}, Got: ${actualSha256}. ` +
          `The download may be corrupted or tampered with. Installation aborted.`,
      };
    }
    console.error(`[third-party-installer] SHA256 verified: ${actualSha256}`);

    // Step 3: Extract or prepare binary
    let binaryPath: string;
    if (isTarball) {
      console.error(`[third-party-installer] Extracting tarball...`);
      const extractResult = execSafe("tar", [
        "-xzf", downloadPath,
        "-C", tempDir,
      ], { timeoutMs: 30_000 });

      if (!extractResult.success) {
        return {
          binary: entry.binary,
          success: false,
          message: `Failed to extract ${entry.name}: ${extractResult.stderr.slice(0, 300)}`,
        };
      }

      binaryPath = join(tempDir, entry.binary);
      if (!existsSync(binaryPath)) {
        return {
          binary: entry.binary,
          success: false,
          message: `Binary "${entry.binary}" not found in extracted tarball.`,
        };
      }
    } else {
      // Single binary download — no chmod +x needed here since /tmp may be
      // mounted with noexec (CIS hardening). We use `sudo install` below which
      // sets permissions atomically on the destination filesystem.
      binaryPath = downloadPath;
    }

    // Step 4: Install to /usr/local/bin via sudo install (atomic: copies + sets
    // permissions + ownership in a single operation, avoids noexec /tmp issues)
    const destPath = `/usr/local/bin/${entry.binary}`;
    console.error(`[third-party-installer] Installing to ${destPath}...`);
    const installResult = execWithSudo(
      ["install", "-m", "755", "-o", "root", "-g", "root", binaryPath, destPath],
      { timeoutMs: 30_000 },
    );

    if (!installResult.success) {
      return {
        binary: entry.binary,
        success: false,
        message: `Failed to install ${entry.name} to ${destPath}: ${installResult.stderr.slice(0, 300)}`,
      };
    }

    // Step 5: Log to changelog
    logChange(createChangeEntry({
      tool: "third-party-installer",
      action: `Installed ${entry.name} v${entry.version} from GitHub release`,
      target: destPath,
      before: "not installed",
      after: `${entry.name} v${entry.version} (SHA256 verified: ${actualSha256.slice(0, 16)}...)`,
      dryRun: false,
      success: true,
    }));

    console.error(`[third-party-installer] ✓ ${entry.name} v${entry.version} installed successfully`);

    return {
      binary: entry.binary,
      success: true,
      message: `${entry.name} v${entry.version} installed to ${destPath} (SHA256 verified)`,
    };
  } finally {
    cleanupTempDir(tempDir);
  }
}

/**
 * Install a tool via APT repo with GPG verification.
 */
async function installAptRepo(
  entry: ThirdPartyManifestEntry,
): Promise<ThirdPartyInstallResult> {
  if (!entry.gpgKeyUrl || !entry.gpgFingerprint || !entry.aptKeyringPath || !entry.aptRepoLine) {
    return {
      binary: entry.binary,
      success: false,
      message: `Incomplete APT repo configuration for ${entry.name}.`,
    };
  }

  const tempDir = createTempDir();
  const gpgKeyPath = join(tempDir, "key.asc");

  try {
    // Step 1: Download GPG key to temp file (NEVER pipe to gpg directly)
    console.error(`[third-party-installer] Downloading GPG key for ${entry.name}...`);
    const downloadResult = execSafe("curl", [
      "-fsSL",
      "-o", gpgKeyPath,
      "--max-time", "30",
      entry.gpgKeyUrl,
    ], { timeoutMs: 60_000 });

    if (!downloadResult.success) {
      return {
        binary: entry.binary,
        success: false,
        message: `Failed to download GPG key for ${entry.name}: ${downloadResult.stderr.slice(0, 300)}`,
      };
    }

    // Step 2: Verify GPG fingerprint
    console.error(`[third-party-installer] Verifying GPG fingerprint...`);
    const fingerprintResult = execSafe("gpg", [
      "--with-fingerprint",
      "--with-colons",
      "--import-options", "show-only",
      "--import",
      gpgKeyPath,
    ], { timeoutMs: 10_000 });

    if (!fingerprintResult.success) {
      return {
        binary: entry.binary,
        success: false,
        message: `Failed to verify GPG key for ${entry.name}: ${fingerprintResult.stderr.slice(0, 300)}`,
      };
    }

    // Normalize fingerprint for comparison (remove spaces)
    const expectedFingerprint = entry.gpgFingerprint.replace(/\s/g, "").toUpperCase();
    const outputNormalized = fingerprintResult.stdout.toUpperCase().replace(/\s/g, "");

    if (!outputNormalized.includes(expectedFingerprint)) {
      return {
        binary: entry.binary,
        success: false,
        message:
          `GPG FINGERPRINT MISMATCH for ${entry.name}! ` +
          `Expected: ${entry.gpgFingerprint}. ` +
          `The GPG key may have been tampered with. Installation aborted.`,
      };
    }
    console.error(`[third-party-installer] GPG fingerprint verified: ${entry.gpgFingerprint}`);

    // Step 3: Dearmor and install keyring
    console.error(`[third-party-installer] Installing keyring to ${entry.aptKeyringPath}...`);
    // Remove existing keyring first to avoid gpg --dearmor failure
    execWithSudo(["rm", "-f", entry.aptKeyringPath], { timeoutMs: 5_000 });
    const dearmorResult = execWithSudo(
      ["gpg", "--dearmor", "-o", entry.aptKeyringPath, gpgKeyPath],
      { timeoutMs: 10_000 },
    );

    if (!dearmorResult.success) {
      return {
        binary: entry.binary,
        success: false,
        message: `Failed to install GPG keyring for ${entry.name}: ${dearmorResult.stderr.slice(0, 300)}`,
      };
    }

    // Step 4: Add APT source with signed-by pinning
    const aptSourcePath = `/etc/apt/sources.list.d/${entry.binary}.list`;
    console.error(`[third-party-installer] Adding APT source: ${aptSourcePath}...`);

    // Write the apt source file via tee with echo input
    const writeResult = execWithSudo(
      ["tee", aptSourcePath],
      { timeoutMs: 5_000 },
    );

    // tee approach may not work without stdin — use a temp file approach instead
    if (!writeResult.success) {
      // Write to temp file, then copy with sudo
      const tempSourcePath = join(tempDir, `${entry.binary}.list`);
      try {
        const { writeFileSync } = await import("node:fs");
        writeFileSync(tempSourcePath, entry.aptRepoLine + "\n", { mode: 0o600 });
        const copyResult = execWithSudo(
          ["cp", tempSourcePath, aptSourcePath],
          { timeoutMs: 5_000 },
        );
        if (!copyResult.success) {
          return {
            binary: entry.binary,
            success: false,
            message: `Failed to add APT source for ${entry.name}: ${copyResult.stderr.slice(0, 300)}`,
          };
        }
      } catch (writeErr) {
        return {
          binary: entry.binary,
          success: false,
          message: `Failed to write APT source file for ${entry.name}: ${String(writeErr)}`,
        };
      }
    }

    // Step 5: Update apt and install
    console.error(`[third-party-installer] Running apt-get update...`);
    const updateResult = execWithSudo(
      ["apt-get", "update"],
      { timeoutMs: 120_000 },
    );

    if (!updateResult.success) {
      console.error(`[third-party-installer] ⚠ apt-get update had issues: ${updateResult.stderr.slice(0, 200)}`);
    }

    const packages = entry.aptPinnedPackages ?? [entry.binary];
    for (const pkg of packages) {
      console.error(`[third-party-installer] Installing package: ${pkg}...`);
      const installResult = execWithSudo(
        ["apt-get", "install", "-y", pkg],
        { timeoutMs: 300_000 },
      );

      if (!installResult.success) {
        return {
          binary: entry.binary,
          success: false,
          message: `Failed to install ${pkg}: ${installResult.stderr.slice(0, 300)}`,
        };
      }
    }

    // Step 6: Log to changelog
    logChange(createChangeEntry({
      tool: "third-party-installer",
      action: `Installed ${entry.name} v${entry.version} from APT repo (GPG verified)`,
      target: entry.binary,
      before: "not installed",
      after: `${entry.name} v${entry.version} (GPG fingerprint verified)`,
      dryRun: false,
      success: true,
    }));

    console.error(`[third-party-installer] ✓ ${entry.name} v${entry.version} installed successfully via APT`);

    return {
      binary: entry.binary,
      success: true,
      message: `${entry.name} v${entry.version} installed via APT repo (GPG fingerprint verified)`,
    };
  } finally {
    cleanupTempDir(tempDir);
  }
}

/**
 * Install a tool via npm with provenance.
 */
async function installNpmLocal(
  entry: ThirdPartyManifestEntry,
): Promise<ThirdPartyInstallResult> {
  if (!entry.npmPackage) {
    return {
      binary: entry.binary,
      success: false,
      message: `No npm package configured for ${entry.name}.`,
    };
  }

  console.error(`[third-party-installer] Installing ${entry.npmPackage}@${entry.version} via npm...`);

  // Try global install first (may need sudo)
  let result = execSafe("npm", [
    "install", "-g",
    `${entry.npmPackage}@${entry.version}`,
  ], { timeoutMs: 120_000 });

  if (!result.success) {
    console.error(`[third-party-installer] Retrying with sudo...`);
    result = execWithSudo(
      ["npm", "install", "-g", `${entry.npmPackage}@${entry.version}`],
      { timeoutMs: 120_000 },
    );
  }

  if (!result.success) {
    return {
      binary: entry.binary,
      success: false,
      message: `Failed to install ${entry.npmPackage}: ${result.stderr.slice(0, 300)}`,
    };
  }

  // Log to changelog
  logChange(createChangeEntry({
    tool: "third-party-installer",
    action: `Installed ${entry.name} v${entry.version} via npm`,
    target: entry.npmPackage,
    before: "not installed",
    after: `${entry.name} v${entry.version} (npm provenance)`,
    dryRun: false,
    success: true,
  }));

  console.error(`[third-party-installer] ✓ ${entry.name} v${entry.version} installed via npm`);

  return {
    binary: entry.binary,
    success: true,
    message: `${entry.name} v${entry.version} installed via npm`,
  };
}

// ── Instruction Generators ───────────────────────────────────────────────────

function getAptRepoInstructions(entry: ThirdPartyManifestEntry): string {
  const lines = [
    `## ${entry.name} v${entry.version} — Verified APT Installation`,
    "",
    "```bash",
    `# Step 1: Download the GPG key to a file (do NOT pipe to gpg)`,
    `curl -fsSL -o /tmp/${entry.binary}-key.asc ${entry.gpgKeyUrl}`,
    "",
    `# Step 2: Verify the GPG fingerprint`,
    `gpg --with-fingerprint --import-options show-only --import /tmp/${entry.binary}-key.asc`,
    `# Expected fingerprint: ${entry.gpgFingerprint}`,
    "",
    `# Step 3: Install the keyring`,
    `sudo gpg --dearmor -o ${entry.aptKeyringPath} /tmp/${entry.binary}-key.asc`,
    "",
    `# Step 4: Add the APT source with signed-by pinning`,
    `echo '${entry.aptRepoLine}' | sudo tee /etc/apt/sources.list.d/${entry.binary}.list`,
    "",
    `# Step 5: Install`,
    `sudo apt-get update`,
    `sudo apt-get install -y ${(entry.aptPinnedPackages ?? [entry.binary]).join(" ")}`,
    "",
    `# Step 6: Clean up`,
    `rm -f /tmp/${entry.binary}-key.asc`,
    "```",
  ];
  return lines.join("\n");
}

function getGithubReleaseInstructions(entry: ThirdPartyManifestEntry): string {
  const archKey = getPlatformArchKey();
  const url = entry.downloadUrlTemplate
    ? resolveDownloadUrl(entry.downloadUrlTemplate, entry.version, archKey)
    : "https://github.com/" + (entry.githubRepo ?? "") + "/releases/tag/v" + entry.version;
  const expectedSha256 = entry.sha256?.[archKey] ?? "PENDING_FETCH";
  const isTarball = url.endsWith(".tar.gz");
  const filename = isTarball ? (entry.binary + ".tar.gz") : entry.binary;

  const lines: string[] = [
    "## " + entry.name + " v" + entry.version + " — Verified GitHub Release",
    "",
    "```bash",
    "# Step 1: Download to a temp file (do NOT pipe to sh)",
    "curl -fsSL -o /tmp/" + filename + " " + url,
    "",
    "# Step 2: Verify SHA256 checksum",
    'echo "' + expectedSha256 + "  /tmp/" + filename + '" | sha256sum -c -',
    "",
  ];

  if (isTarball) {
    lines.push(
      "# Step 3: Extract and install",
      "tar -xzf /tmp/" + filename + " -C /tmp/",
      "sudo install -m 755 /tmp/" + entry.binary + " /usr/local/bin/" + entry.binary,
    );
  } else {
    lines.push(
      "# Step 3: Install",
      "sudo install -m 755 /tmp/" + filename + " /usr/local/bin/" + entry.binary,
    );
  }

  lines.push(
    "",
    "# Step 4: Clean up",
    "rm -f /tmp/" + filename,
    "```",
  );

  return lines.join("\n");
}

function getNpmLocalInstructions(entry: ThirdPartyManifestEntry): string {
  const pkg = entry.npmPackage ?? entry.binary;
  const lines = [
    "## " + entry.name + " v" + entry.version + " — npm Installation",
    "",
    "```bash",
    "# Install globally via npm",
    "sudo npm install -g " + pkg + "@" + entry.version,
    "",
    "# Verify installation",
    entry.binary + " --version",
    "```",
  ];
  return lines.join("\n");
}
