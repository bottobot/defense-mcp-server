/**
 * Secure filesystem utilities for the defense-mcp-server.
 * All state files (changelog, rollback, backups) must use these helpers
 * to ensure restrictive permissions (owner-only read/write).
 */

import { writeFileSync, mkdirSync, copyFileSync, chmodSync, existsSync, statSync, renameSync, unlinkSync } from "node:fs";
import { dirname, join } from "node:path";
import { randomBytes } from "node:crypto";

/** File permission: owner read/write only (0o600) */
const SECURE_FILE_MODE = 0o600;

/** Directory permission: owner read/write/execute only (0o700) */
const SECURE_DIR_MODE = 0o700;

/** Options for secureWriteFileSync. */
export interface SecureWriteOptions {
    /** Character encoding for string data. Defaults to `"utf-8"`. */
    encoding?: BufferEncoding;
    /** Use atomic write (write to temp file, then rename). Defaults to `false`. */
    atomic?: boolean;
}

/**
 * Write a file with owner-only permissions (0o600).
 * Creates parent directories with 0o700 if they don't exist.
 *
 * @param filePath - Destination file path
 * @param data - Content to write
 * @param encodingOrOptions - Either a BufferEncoding string (legacy) or a SecureWriteOptions object
 */
export function secureWriteFileSync(
    filePath: string,
    data: string | Buffer,
    encodingOrOptions?: BufferEncoding | SecureWriteOptions,
): void {
    // Normalize options
    let encoding: BufferEncoding = "utf-8";
    let atomic = false;

    if (typeof encodingOrOptions === "string") {
        encoding = encodingOrOptions;
    } else if (encodingOrOptions !== undefined) {
        encoding = encodingOrOptions.encoding ?? "utf-8";
        atomic = encodingOrOptions.atomic ?? false;
    }

    // Ensure parent directory exists with secure permissions
    const dir = dirname(filePath);
    if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true, mode: SECURE_DIR_MODE });
    }

    if (atomic) {
        atomicWriteFileSync(filePath, data, { mode: SECURE_FILE_MODE, encoding });
    } else {
        // Write the file
        writeFileSync(filePath, data, { encoding, mode: SECURE_FILE_MODE });
        // Explicitly chmod in case umask interfered
        chmodSync(filePath, SECURE_FILE_MODE);
    }
}

/**
 * Create a directory with owner-only permissions (0o700).
 */
export function secureMkdirSync(dirPath: string): void {
    if (!existsSync(dirPath)) {
        mkdirSync(dirPath, { recursive: true, mode: SECURE_DIR_MODE });
    }
    // Explicitly chmod in case umask interfered
    chmodSync(dirPath, SECURE_DIR_MODE);
}

/**
 * Copy a file and set owner-only permissions on the destination (0o600).
 */
export function secureCopyFileSync(src: string, dest: string): void {
    const dir = dirname(dest);
    if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true, mode: SECURE_DIR_MODE });
    }
    copyFileSync(src, dest);
    chmodSync(dest, SECURE_FILE_MODE);
}

/**
 * Verify that a state file has secure permissions.
 * Returns true if the file is owner-only (no group/other read/write/execute).
 * Returns false if permissions are too open or file doesn't exist.
 */
export function verifySecurePermissions(filePath: string): boolean {
    if (!existsSync(filePath)) return false;
    const stats = statSync(filePath);
    // Check that group and other have no permissions
    // mode & 0o077 should be 0 (no group/other bits set)
    return (stats.mode & 0o077) === 0;
}

/**
 * Fix permissions on an existing file to be owner-only.
 */
export function hardenFilePermissions(filePath: string): void {
    if (existsSync(filePath)) {
        chmodSync(filePath, SECURE_FILE_MODE);
    }
}

/**
 * Fix permissions on an existing directory to be owner-only.
 */
export function hardenDirPermissions(dirPath: string): void {
    if (existsSync(dirPath)) {
        chmodSync(dirPath, SECURE_DIR_MODE);
    }
}

// ── Atomic File Writes ───────────────────────────────────────────────────────

/** Options for atomicWriteFileSync. */
export interface AtomicWriteOptions {
    /** File permissions mode. Defaults to `0o600`. */
    mode?: number;
    /** Character encoding for string data. Defaults to `"utf-8"`. */
    encoding?: BufferEncoding;
}

/**
 * Write a file atomically using a write-to-temp-then-rename strategy.
 *
 * Steps:
 * 1. Write data to a temporary file in the same directory (`.tmp` suffix)
 * 2. Set file permissions on the temp file
 * 3. Rename (atomic on POSIX) from temp to target path
 * 4. If rename fails, clean up the temp file
 *
 * This prevents file corruption from interrupted writes (crash, signal, etc.).
 *
 * @param filePath - Destination file path
 * @param data - Content to write (string or Buffer)
 * @param options - Write options (mode, encoding)
 */
export function atomicWriteFileSync(
    filePath: string,
    data: string | Buffer,
    options?: AtomicWriteOptions,
): void {
    const mode = options?.mode ?? SECURE_FILE_MODE;
    const encoding = options?.encoding ?? "utf-8";

    // Ensure parent directory exists with secure permissions
    const dir = dirname(filePath);
    if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true, mode: SECURE_DIR_MODE });
    }

    // Generate a unique temp file path in the same directory
    const tmpSuffix = `.tmp.${randomBytes(6).toString("hex")}`;
    const tmpPath = join(dir, `${filePath.split("/").pop()}${tmpSuffix}`);

    try {
        // Step 1: Write to temp file
        writeFileSync(tmpPath, data, { encoding, mode });

        // Step 2: Explicitly set permissions (in case umask interfered)
        chmodSync(tmpPath, mode);

        // Step 3: Atomic rename
        renameSync(tmpPath, filePath);
    } catch (error) {
        // Step 4: Clean up temp file on failure
        try {
            if (existsSync(tmpPath)) {
                unlinkSync(tmpPath);
            }
        } catch {
            // Best-effort cleanup — ignore errors
        }
        throw error;
    }
}
