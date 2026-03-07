/**
 * Secure filesystem utilities for the kali-defense-mcp-server.
 * All state files (changelog, rollback, backups) must use these helpers
 * to ensure restrictive permissions (owner-only read/write).
 */

import { writeFileSync, mkdirSync, copyFileSync, chmodSync, existsSync, statSync } from "node:fs";
import { dirname } from "node:path";

/** File permission: owner read/write only (0o600) */
const SECURE_FILE_MODE = 0o600;

/** Directory permission: owner read/write/execute only (0o700) */
const SECURE_DIR_MODE = 0o700;

/**
 * Write a file with owner-only permissions (0o600).
 * Creates parent directories with 0o700 if they don't exist.
 */
export function secureWriteFileSync(filePath: string, data: string | Buffer, encoding?: BufferEncoding): void {
    // Ensure parent directory exists with secure permissions
    const dir = dirname(filePath);
    if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true, mode: SECURE_DIR_MODE });
    }
    // Write the file
    writeFileSync(filePath, data, { encoding: encoding ?? "utf-8", mode: SECURE_FILE_MODE });
    // Explicitly chmod in case umask interfered
    chmodSync(filePath, SECURE_FILE_MODE);
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
