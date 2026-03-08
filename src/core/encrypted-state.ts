/**
 * encrypted-state.ts — Encrypted storage for sensitive state data.
 *
 * Provides AES-256-GCM encrypted at-rest storage for rollback data,
 * policy files, sudo session tokens, and other sensitive state.
 *
 * Key derivation uses PBKDF2 from a configurable secret via the
 * `KALI_DEFENSE_STATE_KEY` environment variable. If no key is
 * configured, falls back to unencrypted mode with a warning.
 *
 * @module encrypted-state
 */

import {
  randomBytes,
  createCipheriv,
  createDecipheriv,
  pbkdf2Sync,
} from "node:crypto";
import {
  readFileSync,
  unlinkSync,
  existsSync,
  mkdirSync,
  chmodSync,
} from "node:fs";
import { join } from "node:path";
import { logger } from "./logger.js";
import { atomicWriteFileSync } from "./secure-fs.js";

// ── Constants ────────────────────────────────────────────────────────────────

/** AES-256-GCM algorithm identifier. */
const ALGORITHM = "aes-256-gcm";

/** Key length in bytes (256 bits). */
const KEY_LENGTH = 32;

/** IV length in bytes (96 bits recommended for GCM). */
const IV_LENGTH = 12;

/** Auth tag length in bytes. */
const AUTH_TAG_LENGTH = 16;

/** PBKDF2 iteration count. */
const PBKDF2_ITERATIONS = 100_000;

/** PBKDF2 digest algorithm. */
const PBKDF2_DIGEST = "sha512";

/** Salt length in bytes. */
const SALT_LENGTH = 16;

/** Default state directory. */
const DEFAULT_STATE_DIR = "/tmp/kali-defense/state/";

/** File permission: owner read/write only. */
const SECURE_FILE_MODE = 0o600;

/** Directory permission: owner read/write/execute only. */
const SECURE_DIR_MODE = 0o700;

/** Environment variable name for the encryption key. */
const ENV_KEY_NAME = "KALI_DEFENSE_STATE_KEY";

// ── Encrypted file format ────────────────────────────────────────────────────
// Binary layout: [salt (16)] [iv (12)] [authTag (16)] [ciphertext (...)]
// JSON fallback (unencrypted): plain JSON text

// ── SecureStateStore ─────────────────────────────────────────────────────────

/**
 * Encrypted state storage for sensitive data at rest.
 *
 * Uses AES-256-GCM with PBKDF2-derived keys when `KALI_DEFENSE_STATE_KEY`
 * is set. Falls back to plaintext JSON when no key is configured.
 */
export class SecureStateStore {
  private readonly stateDir: string;
  private readonly secret: string | null;

  /**
   * @param stateDir - Directory for state files (default: `/tmp/kali-defense/state/`)
   * @param secret - Encryption secret. If omitted, reads from `KALI_DEFENSE_STATE_KEY` env var.
   *                 Pass empty string or omit to use unencrypted fallback.
   */
  constructor(stateDir?: string, secret?: string) {
    this.stateDir = stateDir ?? DEFAULT_STATE_DIR;

    // Determine secret: explicit parameter > env var > null (unencrypted)
    if (secret !== undefined) {
      this.secret = secret.length > 0 ? secret : null;
    } else {
      const envKey = process.env[ENV_KEY_NAME];
      this.secret = envKey && envKey.length > 0 ? envKey : null;
    }

    if (this.secret === null) {
      logger.warn(
        "encrypted-state",
        "init",
        "No encryption key configured — state files will be stored unencrypted. " +
          `Set ${ENV_KEY_NAME} environment variable for encrypted storage.`,
      );
    }

    // Ensure state directory exists with secure permissions
    this.ensureStateDir();
  }

  /**
   * Whether the store is operating in encrypted mode.
   */
  get encrypted(): boolean {
    return this.secret !== null;
  }

  /**
   * Save a state object to disk.
   *
   * @param id - Unique identifier for the state (used as filename stem)
   * @param data - JSON-serializable object to persist
   */
  save(id: string, data: object): void {
    const filePath = this.filePath(id);
    const json = JSON.stringify(data);

    if (this.secret !== null) {
      const encrypted = this.encrypt(json);
      atomicWriteFileSync(filePath, encrypted, { mode: SECURE_FILE_MODE });
    } else {
      atomicWriteFileSync(filePath, json, { mode: SECURE_FILE_MODE });
    }

    logger.debug(
      "encrypted-state",
      "save",
      `State saved: ${id}`,
      { encrypted: this.encrypted },
    );
  }

  /**
   * Load a state object from disk.
   *
   * @param id - Unique identifier for the state
   * @returns The deserialized object, or `null` if the state file doesn't exist
   */
  load(id: string): object | null {
    const filePath = this.filePath(id);

    if (!existsSync(filePath)) {
      return null;
    }

    const raw = readFileSync(filePath);

    if (this.secret !== null) {
      const json = this.decrypt(raw);
      return JSON.parse(json);
    } else {
      return JSON.parse(raw.toString("utf-8"));
    }
  }

  /**
   * Delete a state file from disk.
   *
   * @param id - Unique identifier for the state to delete
   */
  delete(id: string): void {
    const filePath = this.filePath(id);
    if (existsSync(filePath)) {
      unlinkSync(filePath);
      logger.debug(
        "encrypted-state",
        "delete",
        `State deleted: ${id}`,
      );
    }
  }

  // ── Private helpers ──────────────────────────────────────────────────────

  /** Build the full file path for a state ID. */
  private filePath(id: string): string {
    // Sanitize id to prevent path traversal
    const safeId = id.replace(/[^a-zA-Z0-9_-]/g, "_");
    return join(this.stateDir, `${safeId}.state`);
  }

  /** Ensure the state directory exists with secure permissions. */
  private ensureStateDir(): void {
    if (!existsSync(this.stateDir)) {
      mkdirSync(this.stateDir, { recursive: true, mode: SECURE_DIR_MODE });
    }
    chmodSync(this.stateDir, SECURE_DIR_MODE);
  }

  /** Derive an AES-256 key from the secret and a salt. */
  private deriveKey(salt: Buffer): Buffer {
    if (!this.secret) {
      throw new Error("Cannot derive key: no secret configured");
    }
    return pbkdf2Sync(
      this.secret,
      salt,
      PBKDF2_ITERATIONS,
      KEY_LENGTH,
      PBKDF2_DIGEST,
    );
  }

  /**
   * Encrypt plaintext JSON using AES-256-GCM.
   * Returns a Buffer: [salt (16)] [iv (12)] [authTag (16)] [ciphertext]
   */
  private encrypt(plaintext: string): Buffer {
    const salt = randomBytes(SALT_LENGTH);
    const key = this.deriveKey(salt);
    const iv = randomBytes(IV_LENGTH);

    const cipher = createCipheriv(ALGORITHM, key, iv);
    const encrypted = Buffer.concat([
      cipher.update(plaintext, "utf-8"),
      cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();

    // Combine: salt + iv + authTag + ciphertext
    return Buffer.concat([salt, iv, authTag, encrypted]);
  }

  /**
   * Decrypt an AES-256-GCM encrypted buffer.
   * Expects format: [salt (16)] [iv (12)] [authTag (16)] [ciphertext]
   */
  private decrypt(data: Buffer): string {
    const minLength = SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH;
    if (data.length < minLength) {
      throw new Error(
        "Corrupted state file: data too short to contain encryption headers",
      );
    }

    let offset = 0;
    const salt = data.subarray(offset, offset + SALT_LENGTH);
    offset += SALT_LENGTH;

    const iv = data.subarray(offset, offset + IV_LENGTH);
    offset += IV_LENGTH;

    const authTag = data.subarray(offset, offset + AUTH_TAG_LENGTH);
    offset += AUTH_TAG_LENGTH;

    const ciphertext = data.subarray(offset);

    const key = this.deriveKey(salt);
    const decipher = createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);

    try {
      const decrypted = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final(),
      ]);
      return decrypted.toString("utf-8");
    } catch {
      throw new Error(
        "Failed to decrypt state file: invalid key or corrupted data",
      );
    }
  }
}

// ── Singleton Export ─────────────────────────────────────────────────────────

/**
 * Default singleton SecureStateStore instance.
 *
 * Uses the default state directory and reads the encryption key from
 * the `KALI_DEFENSE_STATE_KEY` environment variable.
 */
export const secureState = new SecureStateStore();
