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
