/**
 * PAM configuration parser, serializer, validator, and file I/O manager.
 *
 * Replaces fragile sed-based PAM manipulation with safe in-memory operations:
 *   1. Parse PAM config into structured records
 *   2. Manipulate records (insert, remove, reorder)
 *   3. Serialize back with correct formatting
 *   4. Validate before writing
 *   5. Write atomically with mandatory backup and auto-rollback
 *
 * @see docs/PAM-HARDENING-FIX.md for architecture details
 */

import { existsSync, readFileSync, writeFileSync, unlinkSync, mkdtempSync, rmdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import { executeCommand } from "./executor.js";
import { BackupManager, type BackupEntry } from "./backup-manager.js";
import { getConfig } from "./config.js";

// ── PAM Line Types ──────────────────────────────────────────────────────────

/** A PAM rule line: type control module [args...] */
export interface PamRule {
  kind: "rule";
  /** PAM type: auth, account, password, session (optionally prefixed with -) */
  pamType: string;
  /** Control flag: required, requisite, sufficient, optional, or [value=action ...] */
  control: string;
  /** Module path/name: pam_unix.so, pam_faillock.so, etc. */
  module: string;
  /** Module arguments: nullok, silent, deny=5, etc. */
  args: string[];
  /** Original raw text (preserved for round-trip fidelity). */
  rawLine: string;
}

/** A comment line (starts with #). */
export interface PamComment {
  kind: "comment";
  text: string;
}

/** A blank/empty line. */
export interface PamBlank {
  kind: "blank";
}

/** An @include directive. */
export interface PamInclude {
  kind: "include";
  target: string;
  rawLine: string;
}

/** Union of all PAM line types. */
export type PamLine = PamRule | PamComment | PamBlank | PamInclude;

// ── Error Types ─────────────────────────────────────────────────────────────

/** Thrown when PAM config validation fails. */
export class PamValidationError extends Error {
  constructor(
    public readonly errors: string[],
    public readonly filePath?: string,
  ) {
    super(
      `PAM config validation failed${filePath ? ` for ${filePath}` : ""}: ${errors.join("; ")}`,
    );
    this.name = "PamValidationError";
  }
}

/** Thrown when PAM file write fails or post-write validation fails. */
export class PamWriteError extends Error {
  constructor(
    message: string,
    public readonly filePath: string,
    public readonly backupId?: string,
  ) {
    super(message);
    this.name = "PamWriteError";
  }
}

// ── Valid PAM types ─────────────────────────────────────────────────────────

const VALID_PAM_TYPES = new Set([
  "auth",
  "account",
  "password",
  "session",
  "-auth",
  "-account",
  "-password",
  "-session",
]);

// ── Known concatenation patterns (the bug that caused the lockout) ──────────

const CONCATENATED_PATTERNS = [
  /^auth(required|requisite|sufficient|optional|include|substack)/,
  /^account(required|requisite|sufficient|optional|include|substack)/,
  /^password(required|requisite|sufficient|optional|include|substack)/,
  /^session(required|requisite|sufficient|optional|include|substack)/,
  /^(auth|account|password|session)\[/,
  /required(pam_|\/)/,
  /requisite(pam_|\/)/,
  /sufficient(pam_|\/)/,
  /optional(pam_|\/)/,
];

// ── Parser ──────────────────────────────────────────────────────────────────

/**
 * Parse PAM config file content into structured records.
 *
 * Handles:
 * - Standard rules: auth required pam_unix.so nullok
 * - Complex controls: auth [success=1 default=ignore] pam_unix.so
 * - Comments: # This is a comment
 * - Blank lines: (preserved for formatting fidelity)
 * - Include directives: @include common-auth
 *
 * **Critical**: The parser is **lossless**. Every line in the input appears
 * in the output array. Unknown/unparseable lines are preserved as comments
 * to prevent silent data loss.
 *
 * @param content - Raw PAM config file text
 * @returns Array of PamLine records in file order
 */
export function parsePamConfig(content: string): PamLine[] {
  // Strip a single trailing newline to ensure round-trip idempotency.
  // serializePamConfig() always appends one trailing newline, so without this
  // normalization, parse→serialize→parse would accumulate blank lines.
  const normalized = content.endsWith("\n") ? content.slice(0, -1) : content;
  const rawLines = normalized.split("\n");
  const result: PamLine[] = [];

  for (const raw of rawLines) {
    const trimmed = raw.trim();

    // Blank line
    if (trimmed === "") {
      result.push({ kind: "blank" });
      continue;
    }

    // Comment line
    if (trimmed.startsWith("#")) {
      result.push({ kind: "comment", text: raw });
      continue;
    }

    // @include directive
    if (trimmed.startsWith("@include")) {
      const parts = trimmed.split(/\s+/);
      const target = parts.slice(1).join(" ");
      result.push({ kind: "include", target, rawLine: raw });
      continue;
    }

    // Attempt to parse as a PAM rule
    const rule = parseRuleLine(raw, trimmed);
    if (rule) {
      result.push(rule);
    } else {
      // Unparseable line — preserve as comment to prevent data loss
      console.error(`[pam-utils] WARNING: Could not parse PAM line, preserving as-is: ${raw}`);
      result.push({ kind: "comment", text: raw });
    }
  }

  return result;
}

/**
 * Parse a single PAM rule line.
 *
 * Handles bracket-style controls like `[success=1 default=ignore]`.
 * Returns null if the line doesn't match PAM rule syntax.
 */
function parseRuleLine(raw: string, trimmed: string): PamRule | null {
  // Tokenize carefully — bracket controls contain spaces
  let rest = trimmed;

  // Token 1: pamType
  const typeMatch = rest.match(/^(\S+)\s+/);
  if (!typeMatch) return null;
  const pamType = typeMatch[1];
  rest = rest.slice(typeMatch[0].length);

  // Token 2: control — if starts with [, consume up to ]
  let control: string;
  if (rest.startsWith("[")) {
    const bracketEnd = rest.indexOf("]");
    if (bracketEnd === -1) return null; // malformed bracket
    control = rest.slice(0, bracketEnd + 1);
    rest = rest.slice(bracketEnd + 1).replace(/^\s+/, "");
  } else {
    const controlMatch = rest.match(/^(\S+)\s*/);
    if (!controlMatch) return null;
    control = controlMatch[1];
    rest = rest.slice(controlMatch[0].length);
  }

  // Token 3: module
  const moduleMatch = rest.match(/^(\S+)\s*/);
  if (!moduleMatch) return null;
  const module = moduleMatch[1];
  rest = rest.slice(moduleMatch[0].length);

  // Remaining tokens: args
  const args = rest.length > 0 ? rest.split(/\s+/).filter((a) => a.length > 0) : [];

  return {
    kind: "rule",
    pamType,
    control,
    module,
    args,
    rawLine: raw,
  };
}

// ── Serializer ──────────────────────────────────────────────────────────────

/**
 * Serialize structured PAM records back to file content.
 *
 * For PamRule records, generates lines with consistent formatting:
 *   - Fields separated by 4-space padding
 *   - Module args separated by single spaces
 *
 * For PamComment, PamBlank, and PamInclude records, the original
 * raw text is emitted unchanged (round-trip preservation).
 *
 * @param lines - Array of PamLine records
 * @returns PAM config file content string (with trailing newline)
 */
export function serializePamConfig(lines: PamLine[]): string {
  const outputLines: string[] = [];

  for (const line of lines) {
    switch (line.kind) {
      case "blank":
        outputLines.push("");
        break;
      case "comment":
        outputLines.push(line.text);
        break;
      case "include":
        outputLines.push(line.rawLine);
        break;
      case "rule": {
        const argStr = line.args.length > 0 ? ` ${line.args.join(" ")}` : "";
        outputLines.push(
          `${line.pamType}    ${line.control}    ${line.module}${argStr}`,
        );
        break;
      }
    }
  }

  return outputLines.join("\n") + "\n";
}

// ── Validator ───────────────────────────────────────────────────────────────

/**
 * Validate PAM config for syntactic correctness.
 *
 * Checks:
 * 1. Every PamRule has a valid pamType, non-empty control, and module ending in .so
 * 2. At least one pam_unix.so rule exists (sanity check — PAM needs it)
 * 3. No lines have concatenated fields (the bug that caused the lockout)
 *
 * Does NOT check:
 * - Whether .so files exist on disk
 * - Semantic correctness of control flags
 *
 * @param lines - Parsed PamLine array
 * @returns Validation result with error details
 */
export function validatePamConfig(
  lines: PamLine[],
): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  let hasUnix = false;
  let lineNum = 0;

  for (const line of lines) {
    lineNum++;

    if (line.kind === "blank" || line.kind === "comment" || line.kind === "include") {
      continue;
    }

    if (line.kind === "rule") {
      // Check valid pamType
      if (!VALID_PAM_TYPES.has(line.pamType)) {
        errors.push(
          `Line ${lineNum}: Invalid PAM type '${line.pamType}' (expected auth|account|password|session)`,
        );
      }

      // Check non-empty control
      if (!line.control || line.control.trim().length === 0) {
        errors.push(`Line ${lineNum}: Empty control field`);
      }

      // Check module ends in .so
      if (!line.module.endsWith(".so")) {
        errors.push(
          `Line ${lineNum}: Module '${line.module}' does not end with .so`,
        );
      }

      // Track pam_unix.so presence
      if (line.module === "pam_unix.so") {
        hasUnix = true;
      }

      // Check for concatenated fields (the original bug).
      // The sed bug produced pamType values like "authrequired" or control
      // values like "requiredpam_deny.so". Check each INDIVIDUAL field for
      // patterns that indicate it absorbed an adjacent field.
      const pamTypeConcat = CONCATENATED_PATTERNS.some((p) => p.test(line.pamType));
      const controlConcat = !line.control.startsWith("[") &&
        /^(required|requisite|sufficient|optional|include|substack)(pam_|\/)/.test(line.control);
      const moduleConcat = /^(pam_\S+\.so)(required|requisite|sufficient|optional|auth|account|password|session)/.test(line.module);

      if (pamTypeConcat || controlConcat || moduleConcat) {
        const field = pamTypeConcat ? `pamType='${line.pamType}'` :
          controlConcat ? `control='${line.control}'` : `module='${line.module}'`;
        errors.push(
          `Line ${lineNum}: Suspected concatenated fields in ${field} — looks like missing whitespace`,
        );
      }

      // Validate [success=N] jump counts — ensure N lands on a valid rule
      const successMatch = line.control.match(/^\[.*success=(\d+).*\]$/);
      if (successMatch) {
        const jumpN = parseInt(successMatch[1], 10);
        // Find this rule's index among all rules (not all lines)
        const ruleIndex = lines.slice(0, lineNum).filter((l) => l.kind === "rule").length - 1;
        const allRules = lines.filter((l) => l.kind === "rule") as PamRule[];
        const targetRuleIndex = ruleIndex + jumpN + 1; // +1 because jump skips N rules after current

        if (targetRuleIndex > allRules.length) {
          errors.push(
            `Line ${lineNum}: [success=${jumpN}] on ${line.module} jumps beyond the end of the rule list (only ${allRules.length - ruleIndex - 1} rules follow)`,
          );
        } else if (targetRuleIndex === allRules.length) {
          // Jumping to end of rules — acceptable but check it lands on pam_permit.so
          // (not strictly required, just a warning-level check — we don't add it as an error)
        } else {
          // Check that success jump doesn't land on pam_deny.so (which would deny all logins)
          const landingRule = allRules[targetRuleIndex];
          if (landingRule && landingRule.module === "pam_deny.so") {
            errors.push(
              `Line ${lineNum}: [success=${jumpN}] on ${line.module} lands on pam_deny.so — this would deny all successful authentications`,
            );
          }
        }
      }
    }
  }

  if (!hasUnix) {
    errors.push(
      "No pam_unix.so rule found — PAM requires this module for basic authentication",
    );
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Validate raw PAM config content string.
 *
 * Convenience wrapper that parses then validates.
 *
 * @param content - Raw PAM config file text
 * @returns Validation result
 */
export function validatePamConfigContent(
  content: string,
): { valid: boolean; errors: string[] } {
  const lines = parsePamConfig(content);
  return validatePamConfig(lines);
}

// ── Manipulation Helpers ────────────────────────────────────────────────────

/**
 * Create a new PamRule record.
 *
 * @param pamType - PAM type (auth, account, password, session)
 * @param control - Control flag (required, requisite, [success=1 default=ignore], etc.)
 * @param module - Module name (pam_faillock.so, pam_unix.so, etc.)
 * @param args - Module arguments
 * @returns New PamRule with generated rawLine
 */
export function createPamRule(
  pamType: string,
  control: string,
  module: string,
  args: string[],
): PamRule {
  const argStr = args.length > 0 ? ` ${args.join(" ")}` : "";
  const rawLine = `${pamType}    ${control}    ${module}${argStr}`;
  return {
    kind: "rule",
    pamType,
    control,
    module,
    args,
    rawLine,
  };
}

/**
 * Remove all rules referencing a specific module.
 *
 * @param lines - Current PamLine array
 * @param moduleName - Module to remove (e.g., "pam_faillock.so")
 * @returns New array with matching rules removed
 */
export function removeModuleRules(
  lines: PamLine[],
  moduleName: string,
): PamLine[] {
  return lines.filter(
    (line) => !(line.kind === "rule" && line.module === moduleName),
  );
}

/**
 * Insert a new rule BEFORE the first rule matching targetModule.
 * If targetModule is not found, appends at the end.
 *
 * @param lines - Current PamLine array
 * @param targetModule - Module to insert before (e.g., "pam_unix.so")
 * @param newRule - The rule to insert
 * @param options - Optional filters: pamType restricts match to specific PAM type
 * @returns New array with the rule inserted
 */
export function insertBeforeModule(
  lines: PamLine[],
  targetModule: string,
  newRule: PamRule,
  options?: { pamType?: string },
): PamLine[] {
  const result = [...lines];
  const idx = result.findIndex(
    (line) =>
      line.kind === "rule" &&
      line.module === targetModule &&
      (!options?.pamType || line.pamType === options.pamType),
  );

  if (idx === -1) {
    result.push(newRule);
  } else {
    result.splice(idx, 0, newRule);
  }

  return result;
}

/**
 * Insert a new rule AFTER the first rule matching targetModule.
 * If targetModule is not found, appends at the end.
 *
 * @param lines - Current PamLine array
 * @param targetModule - Module to insert after (e.g., "pam_unix.so")
 * @param newRule - The rule to insert
 * @param options - Optional filters: pamType restricts match to specific PAM type
 * @returns New array with the rule inserted
 */
export function insertAfterModule(
  lines: PamLine[],
  targetModule: string,
  newRule: PamRule,
  options?: { pamType?: string },
): PamLine[] {
  const result = [...lines];
  const idx = result.findIndex(
    (line) =>
      line.kind === "rule" &&
      line.module === targetModule &&
      (!options?.pamType || line.pamType === options.pamType),
  );

  if (idx === -1) {
    result.push(newRule);
  } else {
    result.splice(idx + 1, 0, newRule);
  }

  return result;
}

/**
 * Find all rules referencing a specific module.
 *
 * @param lines - PamLine array to search
 * @param moduleName - Module to find (e.g., "pam_faillock.so")
 * @returns Array of matching PamRule records
 */
export function findModuleRules(
  lines: PamLine[],
  moduleName: string,
): PamRule[] {
  return lines.filter(
    (line): line is PamRule =>
      line.kind === "rule" && line.module === moduleName,
  );
}

/**
 * After inserting rules, adjust [success=N] jump counts on any rule
 * that uses bracket-style controls with a success=N pattern.
 *
 * For each rule with [success=N ...], count how many rules now exist
 * between that rule and pam_deny.so (requisite), and update N so that
 * success still jumps PAST pam_deny.so.
 *
 * @param lines - PamLine array (typically after insertions)
 * @returns New array with corrected jump counts
 */
export function adjustJumpCounts(lines: PamLine[]): PamLine[] {
  const result = lines.map((line, lineIdx) => {
    if (line.kind !== "rule") return line;

    // Only adjust rules with [success=N ...] controls
    const successMatch = line.control.match(/^\[(.*)success=(\d+)(.*)\]$/);
    if (!successMatch) return line;

    // Use the map index directly as the position in the lines array
    const ruleIdx = lineIdx;

    // Find the next pam_deny.so (requisite) rule after this one
    let denyIdx = -1;
    for (let i = ruleIdx + 1; i < lines.length; i++) {
      const candidate = lines[i];
      if (
        candidate.kind === "rule" &&
        candidate.module === "pam_deny.so" &&
        (candidate.control === "requisite" || candidate.control.includes("requisite"))
      ) {
        denyIdx = i;
        break;
      }
    }

    if (denyIdx === -1) {
      // No pam_deny.so found after this rule — can't adjust
      return line;
    }

    // Count how many PamRule entries are between this rule and pam_deny.so (exclusive)
    let rulesBetween = 0;
    for (let i = ruleIdx + 1; i < denyIdx; i++) {
      if (lines[i].kind === "rule") {
        rulesBetween++;
      }
    }

    // The success jump should skip past pam_deny.so, so N = rulesBetween + 1
    // (skip all rules between us and pam_deny.so, plus pam_deny.so itself)
    const newN = rulesBetween + 1;
    const oldN = parseInt(successMatch[2], 10);

    if (newN === oldN) return line; // No change needed

    const prefix = successMatch[1];
    const suffix = successMatch[3];
    const newControl = `[${prefix}success=${newN}${suffix}]`;
    const argStr = line.args.length > 0 ? ` ${line.args.join(" ")}` : "";
    const newRawLine = `${line.pamType}    ${newControl}    ${line.module}${argStr}`;

    return {
      ...line,
      control: newControl,
      rawLine: newRawLine,
    };
  });

  return result;
}

// ── Sudo-Aware I/O Helpers ──────────────────────────────────────────────────

/**
 * Read a PAM config file via sudo.
 *
 * @param filePath - Absolute path (e.g., /etc/pam.d/common-auth)
 * @returns File content string
 * @throws If sudo cat fails
 */
export async function readPamFile(filePath: string): Promise<string> {
  const result = await executeCommand({
    command: "sudo",
    args: ["cat", filePath],
    toolName: "access_control",
  });

  if (result.exitCode !== 0) {
    throw new Error(
      `Failed to read PAM file ${filePath}: ${result.stderr}`,
    );
  }

  return result.stdout;
}

/**
 * Write a PAM config file via sudo, with mandatory pre-write validation.
 *
 * Steps:
 * 1. Parse the content with parsePamConfig()
 * 2. Validate with validatePamConfig() — if invalid, throw (never write bad content)
 * 3. Write to a secure temp directory (mkdtempSync — eliminates symlink race)
 * 4. Use `sudo install -m 644 -o root -g root` for atomic write (eliminates partial-write state)
 * 5. Post-write verification
 *
 * @param filePath - Absolute path
 * @param content - PAM config content to write
 * @throws PamValidationError if pre-write validation fails
 * @throws PamWriteError if write or permission setting fails
 */
export async function writePamFile(
  filePath: string,
  content: string,
): Promise<void> {
  // 1. Parse and validate before writing
  const lines = parsePamConfig(content);
  const validation = validatePamConfig(lines);

  if (!validation.valid) {
    throw new PamValidationError(validation.errors, filePath);
  }

  // 2. Write to a secure temp directory (eliminates symlink race condition)
  const tempDir = mkdtempSync(join(tmpdir(), "pam-safe-"));
  const tempPath = join(tempDir, "pam-config");

  try {
    writeFileSync(tempPath, content, { encoding: "utf-8", mode: 0o600 });

    // 3. Atomic install: set permissions + ownership + copy in a single operation
    //    Eliminates partial-write state on chmod/chown failure
    const installResult = await executeCommand({
      command: "sudo",
      args: ["install", "-m", "644", "-o", "root", "-g", "root", tempPath, filePath],
      toolName: "access_control",
    });

    if (installResult.exitCode !== 0) {
      throw new PamWriteError(
        `Failed to install PAM file to ${filePath}: ${installResult.stderr}`,
        filePath,
      );
    }

    // 4. Post-write verification: re-read and validate
    const reRead = await readPamFile(filePath);
    const postLines = parsePamConfig(reRead);
    const postValidation = validatePamConfig(postLines);

    if (!postValidation.valid) {
      throw new PamWriteError(
        `Post-write validation failed for ${filePath}: ${postValidation.errors.join("; ")}`,
        filePath,
      );
    }
  } finally {
    // Clean up temp file and directory
    try {
      if (existsSync(tempPath)) {
        unlinkSync(tempPath);
      }
      rmdirSync(tempDir);
    } catch {
      // Best-effort cleanup
    }
  }
}

/**
 * Backup a PAM file using the project BackupManager.
 *
 * Since PAM files are root-owned, this:
 * 1. Reads content via sudo cat
 * 2. Writes to a secure temp directory (eliminates symlink race)
 * 3. Uses BackupManager.backupSync() to create a tracked backup
 * 4. Returns a new object (does NOT mutate BackupManager's internal entry)
 * 5. Cleans up the temp file/directory
 *
 * @param filePath - PAM file to backup
 * @returns BackupEntry for later restore (with corrected originalPath)
 */
export async function backupPamFile(
  filePath: string,
): Promise<BackupEntry> {
  // Read the root-owned file via sudo
  const content = await readPamFile(filePath);

  // Write to a secure temp directory (eliminates symlink race condition)
  const tempDir = mkdtempSync(join(tmpdir(), "pam-backup-"));
  const tempPath = join(tempDir, "pam-config");

  try {
    writeFileSync(tempPath, content, { encoding: "utf-8", mode: 0o600 });

    // Use BackupManager to create a tracked backup from the temp copy
    const config = getConfig();
    const manager = new BackupManager(config.backupDir);

    // BackupManager.backupSync expects the file to exist — we have it in temp
    const entry = manager.backupSync(tempPath);

    // Return a new object with the corrected originalPath — do NOT mutate
    // the BackupManager's internal entry to prevent state corruption
    const correctedEntry: BackupEntry = {
      ...entry,
      originalPath: filePath,
    };

    console.error(
      `[pam-utils] Backed up ${filePath} → ${correctedEntry.backupPath} (id: ${correctedEntry.id})`,
    );

    return correctedEntry;
  } finally {
    // Clean up temp file and directory
    try {
      if (existsSync(tempPath)) {
        unlinkSync(tempPath);
      }
      rmdirSync(tempDir);
    } catch {
      // Best-effort cleanup
    }
  }
}

/**
 * Restore a PAM file from backup.
 *
 * 1. Reads backup content from BackupManager's directory
 * 2. Validates the backup content (refuse to restore garbage)
 * 3. Writes to a secure temp file, then uses `sudo install` (eliminates tee stdout leak)
 *
 * @param backupEntry - The BackupEntry from backupPamFile()
 * @throws If backup file is missing, invalid, or restore fails
 */
export async function restorePamFile(
  backupEntry: BackupEntry,
): Promise<void> {
  if (!existsSync(backupEntry.backupPath)) {
    throw new Error(
      `Backup file missing: ${backupEntry.backupPath}`,
    );
  }

  const backupContent = readFileSync(backupEntry.backupPath, "utf-8");

  // Validate backup content before restoring
  const lines = parsePamConfig(backupContent);
  const validation = validatePamConfig(lines);

  if (!validation.valid) {
    throw new PamValidationError(
      [`Backup content is invalid, refusing to restore: ${validation.errors.join("; ")}`],
      backupEntry.originalPath,
    );
  }

  // Write to secure temp file, then use sudo install (eliminates tee stdout leak)
  const tempDir = mkdtempSync(join(tmpdir(), "pam-restore-"));
  const tempPath = join(tempDir, "pam-config");

  try {
    writeFileSync(tempPath, backupContent, { encoding: "utf-8", mode: 0o600 });

    const installResult = await executeCommand({
      command: "sudo",
      args: ["install", "-m", "644", "-o", "root", "-g", "root", tempPath, backupEntry.originalPath],
      toolName: "access_control",
    });

    if (installResult.exitCode !== 0) {
      throw new Error(
        `Failed to restore PAM file ${backupEntry.originalPath}: ${installResult.stderr}`,
      );
    }
  } finally {
    // Clean up temp file and directory
    try {
      if (existsSync(tempPath)) {
        unlinkSync(tempPath);
      }
      rmdirSync(tempDir);
    } catch {
      // Best-effort cleanup
    }
  }

  console.error(
    `[pam-utils] Restored ${backupEntry.backupPath} → ${backupEntry.originalPath}`,
  );
}

// ── PAM Sanity Validation Types ─────────────────────────────────────────────

/** A single finding from PAM policy sanity validation. */
export interface PamSanityFinding {
  /** warning = proceed with caution; critical = blocks operation unless forced */
  severity: "warning" | "critical";
  /** Which module the finding relates to */
  module: "pam_faillock.so" | "pam_pwquality.so" | "general";
  /** The specific parameter that triggered the finding, if applicable */
  parameter?: string;
  /** The problematic value */
  value?: string | number;
  /** Human-readable description of the problem */
  message: string;
  /** What the user should do instead */
  recommendation: string;
}

/** Result of PAM policy sanity validation. */
export interface PamSanityResult {
  /** true if no critical findings exist */
  safe: boolean;
  /** All findings, ordered by severity then module */
  findings: PamSanityFinding[];
  /** Count of critical-severity findings */
  criticalCount: number;
  /** Count of warning-severity findings */
  warningCount: number;
}

// ── PAM Sanity Thresholds ───────────────────────────────────────────────────

/**
 * Thresholds for PAM policy sanity checks.
 * These define what constitutes "sane" vs "dangerous" PAM policy values.
 * Tuned to prevent lockouts while allowing reasonable security hardening.
 */
export const PAM_SANITY_THRESHOLDS = {
  faillock: {
    /** deny below this triggers critical — too few attempts before lockout */
    minDeny: 3,
    /** unlock_time above this triggers warning — extended lockout */
    maxUnlockTimeWarn: 1800,      // 30 minutes
    /** unlock_time above this triggers critical — extreme lockout */
    maxUnlockTimeCritical: 86400, // 24 hours
    /** fail_interval below this triggers warning — unusually short window */
    minFailInterval: 60,          // 1 minute
  },
  pwquality: {
    /** minlen above this triggers warning — unusually long */
    maxMinlenWarn: 24,
    /** minlen above this triggers critical — unreasonably long */
    maxMinlenCritical: 64,
    /** retry below this triggers critical — no second chance */
    minRetry: 2,
    /** Combined credit threshold: all credits at this or below with high minlen */
    restrictiveCreditThreshold: -2,
  },
} as const;

// ── Faillock Parameter Validation ───────────────────────────────────────────

/**
 * Validate faillock parameters for policy sanity.
 *
 * Checks for overly restrictive settings that could cause lockouts:
 * - deny too low (typos cause lockout)
 * - unlock_time too high or zero (extended/permanent lockout)
 * - deny + unlock_time=0 combination (permanent lock on typos)
 * - fail_interval too short
 *
 * @param params - Faillock parameters to validate
 * @returns Array of sanity findings (empty = all sane)
 */
export function validateFaillockParams(params: {
  deny?: number;
  unlock_time?: number;
  fail_interval?: number;
}): PamSanityFinding[] {
  const findings: PamSanityFinding[] = [];
  const T = PAM_SANITY_THRESHOLDS.faillock;

  // Check deny
  if (params.deny !== undefined && params.deny < T.minDeny) {
    findings.push({
      severity: "critical",
      module: "pam_faillock.so",
      parameter: "deny",
      value: params.deny,
      message:
        params.deny === 1
          ? `deny=${params.deny}: A single failed attempt locks the account — typos cause immediate lockout`
          : `deny=${params.deny}: Only ${params.deny} attempts before lockout — insufficient margin for typos`,
      recommendation: `Set deny >= ${T.minDeny} (CIS Benchmark recommends 3-5)`,
    });
  }

  // Check unlock_time
  if (params.unlock_time !== undefined) {
    if (params.unlock_time === 0) {
      findings.push({
        severity: "critical",
        module: "pam_faillock.so",
        parameter: "unlock_time",
        value: 0,
        message: "unlock_time=0: Permanent lock until admin runs 'faillock --reset' — no automatic recovery",
        recommendation: "Set unlock_time to a positive value (e.g., 900 for 15 minutes)",
      });
    } else if (params.unlock_time > T.maxUnlockTimeCritical) {
      findings.push({
        severity: "critical",
        module: "pam_faillock.so",
        parameter: "unlock_time",
        value: params.unlock_time,
        message: `unlock_time=${params.unlock_time}: Lockout exceeds 24 hours — effectively permanent for most users`,
        recommendation: `Set unlock_time <= ${T.maxUnlockTimeWarn} (30 minutes, per CIS Benchmark)`,
      });
    } else if (params.unlock_time > T.maxUnlockTimeWarn) {
      findings.push({
        severity: "warning",
        module: "pam_faillock.so",
        parameter: "unlock_time",
        value: params.unlock_time,
        message: `unlock_time=${params.unlock_time}: Lockout exceeds 30 minutes — consider a shorter unlock time`,
        recommendation: `Set unlock_time <= ${T.maxUnlockTimeWarn} (30 minutes, per CIS Benchmark)`,
      });
    }
  }

  // Check fail_interval
  if (params.fail_interval !== undefined && params.fail_interval < T.minFailInterval) {
    findings.push({
      severity: "warning",
      module: "pam_faillock.so",
      parameter: "fail_interval",
      value: params.fail_interval,
      message: `fail_interval=${params.fail_interval}: Very short failure tracking window (< 60s)`,
      recommendation: `Set fail_interval >= ${T.minFailInterval} (60 seconds or more)`,
    });
  }

  return findings;
}

// ── Pwquality Parameter Validation ──────────────────────────────────────────

/**
 * Validate pwquality parameters for policy sanity.
 *
 * Checks for overly restrictive settings that prevent password creation:
 * - minlen too high
 * - retry too low (no second chance)
 * - All character class requirements simultaneously very strict
 *
 * @param params - Pwquality parameters to validate
 * @returns Array of sanity findings (empty = all sane)
 */
export function validatePwqualityParams(params: {
  minlen?: number;
  dcredit?: number;
  ucredit?: number;
  lcredit?: number;
  ocredit?: number;
  minclass?: number;
  maxrepeat?: number;
  retry?: number;
}): PamSanityFinding[] {
  const findings: PamSanityFinding[] = [];
  const T = PAM_SANITY_THRESHOLDS.pwquality;

  // Check minlen
  if (params.minlen !== undefined) {
    if (params.minlen > T.maxMinlenCritical) {
      findings.push({
        severity: "critical",
        module: "pam_pwquality.so",
        parameter: "minlen",
        value: params.minlen,
        message: `minlen=${params.minlen}: Minimum password length exceeds ${T.maxMinlenCritical} — users cannot create compliant passwords`,
        recommendation: `Set minlen <= ${T.maxMinlenWarn} (NIST SP 800-63B recommends 8-64 characters)`,
      });
    } else if (params.minlen > T.maxMinlenWarn) {
      findings.push({
        severity: "warning",
        module: "pam_pwquality.so",
        parameter: "minlen",
        value: params.minlen,
        message: `minlen=${params.minlen}: Minimum password length exceeds ${T.maxMinlenWarn} — may be difficult for users`,
        recommendation: `Set minlen <= ${T.maxMinlenWarn} for usability (14-16 is a good balance)`,
      });
    }
  }

  // Check retry
  if (params.retry !== undefined && params.retry < T.minRetry) {
    findings.push({
      severity: "critical",
      module: "pam_pwquality.so",
      parameter: "retry",
      value: params.retry,
      message:
        params.retry === 0
          ? "retry=0: Zero retries — password rejected on first attempt with no recovery"
          : `retry=${params.retry}: Only ${params.retry} retry — insufficient for correcting typos`,
      recommendation: `Set retry >= ${T.minRetry}`,
    });
  }

  // Check combined restrictive credit requirements with high minlen
  const minlen = params.minlen ?? 0;
  const credits = [params.dcredit, params.ucredit, params.lcredit, params.ocredit];
  const definedCredits = credits.filter((c): c is number => c !== undefined);

  if (definedCredits.length === 4 && minlen > 16) {
    const allVeryRestrictive = definedCredits.every(
      (c) => c <= T.restrictiveCreditThreshold,
    );
    if (allVeryRestrictive) {
      findings.push({
        severity: "warning",
        module: "pam_pwquality.so",
        parameter: "dcredit+ucredit+lcredit+ocredit",
        message: `All character classes require ${Math.abs(T.restrictiveCreditThreshold)}+ characters with minlen=${minlen} — very restrictive combined requirements`,
        recommendation: "Relax either the character class requirements or the minimum length",
      });
    }
  }

  // Check minclass=4 with high minlen
  if (params.minclass !== undefined && params.minclass >= 4 && minlen > 16) {
    findings.push({
      severity: "warning",
      module: "pam_pwquality.so",
      parameter: "minclass",
      value: params.minclass,
      message: `minclass=${params.minclass} with minlen=${minlen}: All ${params.minclass} character classes required with long minimum — very restrictive`,
      recommendation: "Consider minclass=3 or reducing minlen when requiring all character classes",
    });
  }

  return findings;
}

// ── PAM Config Structure Validation ─────────────────────────────────────────

/**
 * Validate a PAM config structure for dangerous patterns.
 *
 * Checks the resulting PamLine[] after manipulation for patterns
 * that would break authentication:
 * - pam_deny.so as first auth rule (blocks all auth)
 * - Missing pam_unix.so in auth stack
 * - Incomplete faillock setup (preauth without authfail or vice versa)
 * - Missing pam_permit.so in session stack
 *
 * @param lines - Parsed PAM config lines (after manipulation)
 * @returns Array of sanity findings
 */
export function validatePamConfigSanity(lines: PamLine[]): PamSanityFinding[] {
  const findings: PamSanityFinding[] = [];

  const authRules = lines.filter(
    (l): l is PamRule => l.kind === "rule" && (l.pamType === "auth" || l.pamType === "-auth"),
  );
  const sessionRules = lines.filter(
    (l): l is PamRule => l.kind === "rule" && (l.pamType === "session" || l.pamType === "-session"),
  );

  // Check: pam_deny.so as first auth rule
  if (authRules.length > 0 && authRules[0].module === "pam_deny.so") {
    findings.push({
      severity: "critical",
      module: "general",
      message: "pam_deny.so is the first auth rule — this blocks ALL authentication",
      recommendation: "Ensure pam_deny.so is not the first rule in the auth stack",
    });
  }

  // Check: no pam_unix.so in auth stack
  const hasUnixAuth = authRules.some((r) => r.module === "pam_unix.so");
  if (authRules.length > 0 && !hasUnixAuth) {
    findings.push({
      severity: "critical",
      module: "general",
      message: "No pam_unix.so in auth stack — basic password authentication is broken",
      recommendation: "Ensure pam_unix.so is present in the auth stack",
    });
  }

  // Check: incomplete faillock setup
  const faillockRules = authRules.filter((r) => r.module === "pam_faillock.so");
  if (faillockRules.length > 0) {
    const hasPreauth = faillockRules.some((r) => r.args.includes("preauth"));
    const hasAuthfail = faillockRules.some((r) => r.args.includes("authfail"));

    if (hasPreauth && !hasAuthfail) {
      findings.push({
        severity: "warning",
        module: "pam_faillock.so",
        message: "Incomplete faillock setup: preauth rule present but authfail rule missing — failed attempts may not be tracked",
        recommendation: "Add a pam_faillock.so authfail rule after pam_unix.so",
      });
    }

    if (hasAuthfail && !hasPreauth) {
      findings.push({
        severity: "warning",
        module: "pam_faillock.so",
        message: "Incomplete faillock setup: authfail rule present but preauth rule missing — locked accounts may not be checked before authentication",
        recommendation: "Add a pam_faillock.so preauth rule before pam_unix.so",
      });
    }
  }

  // Check: missing pam_permit.so in session stack
  const hasPermitSession = sessionRules.some((r) => r.module === "pam_permit.so");
  if (sessionRules.length > 0 && !hasPermitSession) {
    findings.push({
      severity: "warning",
      module: "general",
      message: "No pam_permit.so in session stack — sessions may fail to initialize",
      recommendation: "Add 'session required pam_permit.so' to the session stack",
    });
  }

  return findings;
}

// ── Combined Entry Point ────────────────────────────────────────────────────

/**
 * Validate PAM policy sanity — combined parameter + config check.
 *
 * This is the main entry point for sanity validation. It runs:
 * 1. Module-specific parameter checks (if module + params provided)
 * 2. Config structure checks (if lines provided)
 *
 * @param options - What to validate
 * @returns Combined sanity result with safe flag and all findings
 */
export function validatePamPolicySanity(options: {
  /** Which PAM module is being configured */
  module?: "faillock" | "pwquality";
  /** Module parameters being applied */
  params?: Record<string, unknown>;
  /** Resulting PAM config lines (after manipulation) */
  lines?: PamLine[];
}): PamSanityResult {
  const findings: PamSanityFinding[] = [];

  // 1. Module-specific parameter checks
  if (options.module && options.params) {
    if (options.module === "faillock") {
      findings.push(
        ...validateFaillockParams({
          deny: typeof options.params.deny === "number" ? options.params.deny : undefined,
          unlock_time: typeof options.params.unlock_time === "number" ? options.params.unlock_time : undefined,
          fail_interval: typeof options.params.fail_interval === "number" ? options.params.fail_interval : undefined,
        }),
      );
    } else if (options.module === "pwquality") {
      findings.push(
        ...validatePwqualityParams({
          minlen: typeof options.params.minlen === "number" ? options.params.minlen : undefined,
          dcredit: typeof options.params.dcredit === "number" ? options.params.dcredit : undefined,
          ucredit: typeof options.params.ucredit === "number" ? options.params.ucredit : undefined,
          lcredit: typeof options.params.lcredit === "number" ? options.params.lcredit : undefined,
          ocredit: typeof options.params.ocredit === "number" ? options.params.ocredit : undefined,
          minclass: typeof options.params.minclass === "number" ? options.params.minclass : undefined,
          maxrepeat: typeof options.params.maxrepeat === "number" ? options.params.maxrepeat : undefined,
          retry: typeof options.params.retry === "number" ? options.params.retry : undefined,
        }),
      );
    }
  }

  // 2. Config structure checks
  if (options.lines) {
    findings.push(...validatePamConfigSanity(options.lines));
  }

  // Sort: critical first, then warning; within same severity, by module
  findings.sort((a, b) => {
    if (a.severity !== b.severity) {
      return a.severity === "critical" ? -1 : 1;
    }
    return a.module.localeCompare(b.module);
  });

  const criticalCount = findings.filter((f) => f.severity === "critical").length;
  const warningCount = findings.filter((f) => f.severity === "warning").length;

  return {
    safe: criticalCount === 0,
    findings,
    criticalCount,
    warningCount,
  };
}
