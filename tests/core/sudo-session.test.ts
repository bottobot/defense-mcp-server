/**
 * Tests for SudoSession — the singleton managing sudo credential lifecycle.
 *
 * These tests exercise internal logic WITHOUT requiring actual sudo or root.
 * Private methods are accessed via (instance as any) to test password storage,
 * buffer management, and session expiry without spawning real sudo processes.
 */

import { vi, describe, it, expect, beforeEach, afterEach } from "vitest";
import { SudoSession } from "../../src/core/sudo-session.js";

// Helper: access private storePassword on the session instance
function storePassword(
  session: SudoSession,
  password: string | Buffer,
  timeoutMs?: number
): void {
  (session as any).storePassword(password, timeoutMs);
}

// Helper: read the raw internal passwordBuf (not the copy from getPassword)
function getInternalBuffer(session: SudoSession): Buffer | null {
  return (session as any).passwordBuf;
}

// Helper: reset the singleton so each test gets a fresh instance
function resetSingleton(): void {
  // Drop any existing session to clear timers
  try {
    const existing = SudoSession.getInstance();
    if (existing) {
      existing.drop();
    }
  } catch { /* ignore if not initialized */ }
  SudoSession.resetInstance();
}

describe("SudoSession", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    resetSingleton();
  });

  afterEach(() => {
    // Clean up: drop session and reset singleton
    resetSingleton();
    vi.useRealTimers();
  });

  // ── 1. Singleton behavior ──────────────────────────────────────────────

  describe("singleton", () => {
    it("getInstance() returns the same instance on repeated calls", () => {
      const a = SudoSession.getInstance();
      const b = SudoSession.getInstance();
      expect(a).toBe(b);
    });

    it("initial state: isElevated() returns false", () => {
      const session = SudoSession.getInstance();
      expect(session.isElevated()).toBe(false);
    });

    it("initial state: getPassword() returns null", () => {
      const session = SudoSession.getInstance();
      expect(session.getPassword()).toBeNull();
    });

    it("initial state: getStatus() shows not elevated", () => {
      const session = SudoSession.getInstance();
      const status = session.getStatus();
      expect(status.elevated).toBe(false);
      expect(status.username).toBeNull();
      expect(status.expiresAt).toBeNull();
      expect(status.remainingSeconds).toBeNull();
    });
  });

  // ── 2. Password Buffer management ─────────────────────────────────────

  describe("password buffer management", () => {
    it("storePassword() stores as Buffer (not a string)", () => {
      const session = SudoSession.getInstance();
      storePassword(session, "test-password");

      const internal = getInternalBuffer(session);
      expect(internal).toBeInstanceOf(Buffer);
      expect(internal).not.toBeNull();
    });

    it("getPassword() returns a Buffer", () => {
      const session = SudoSession.getInstance();
      storePassword(session, "secret123");

      const result = session.getPassword();
      expect(result).toBeInstanceOf(Buffer);
      expect(result!.toString("utf-8")).toBe("secret123");
    });

    it("getPassword() returns a copy, not the original buffer", () => {
      const session = SudoSession.getInstance();
      storePassword(session, "original");

      const copy = session.getPassword();
      const internal = getInternalBuffer(session);
      expect(copy).not.toBe(internal);
      // But they have the same content
      expect(copy!.toString("utf-8")).toBe(internal!.toString("utf-8"));
    });

    it("modifying the returned Buffer does not affect the stored one", () => {
      const session = SudoSession.getInstance();
      storePassword(session, "immutable");

      const copy = session.getPassword()!;
      // Mutate the copy
      copy.fill(0);
      expect(copy.toString("utf-8")).toBe("\0\0\0\0\0\0\0\0\0");

      // Internal buffer should be untouched
      const internal = getInternalBuffer(session);
      expect(internal!.toString("utf-8")).toBe("immutable");
    });

    it("drop() zeroes the internal buffer", () => {
      const session = SudoSession.getInstance();
      storePassword(session, "to-be-zeroed");

      // Grab a reference to the actual internal buffer before drop
      const internalRef = getInternalBuffer(session)!;
      expect(internalRef.toString("utf-8")).toBe("to-be-zeroed");

      session.drop();

      // The buffer should be filled with zeros
      const allZeros = internalRef.every((byte) => byte === 0);
      expect(allZeros).toBe(true);
    });

    it("after drop(), getPassword() returns null", () => {
      const session = SudoSession.getInstance();
      storePassword(session, "temporary");
      expect(session.getPassword()).not.toBeNull();

      session.drop();
      expect(session.getPassword()).toBeNull();
    });
  });

  // ── 3. Session expiry ─────────────────────────────────────────────────

  describe("session expiry", () => {
    it("after storePassword(), isElevated() returns true", () => {
      const session = SudoSession.getInstance();
      storePassword(session, "pw");
      expect(session.isElevated()).toBe(true);
    });

    it("isExpired() returns false immediately after storing", () => {
      const session = SudoSession.getInstance();
      storePassword(session, "pw", 60_000);

      const expired = (session as any).isExpired();
      expect(expired).toBe(false);
    });

    it("session TTL defaults to 15 minutes", () => {
      const session = SudoSession.getInstance();
      const defaultMs = (session as any).defaultTimeoutMs;
      expect(defaultMs).toBe(15 * 60 * 1000);
    });

    it("session TTL is configurable via setDefaultTimeout()", () => {
      const session = SudoSession.getInstance();
      session.setDefaultTimeout(5 * 60 * 1000);
      expect((session as any).defaultTimeoutMs).toBe(5 * 60 * 1000);
    });

    it("setDefaultTimeout() ignores non-positive values", () => {
      const session = SudoSession.getInstance();
      const original = (session as any).defaultTimeoutMs;
      session.setDefaultTimeout(0);
      expect((session as any).defaultTimeoutMs).toBe(original);
      session.setDefaultTimeout(-100);
      expect((session as any).defaultTimeoutMs).toBe(original);
    });

    it("after TTL expires, isExpired() returns true", () => {
      const session = SudoSession.getInstance();
      storePassword(session, "pw", 5000); // 5 second TTL

      // Advance time past TTL
      vi.advanceTimersByTime(6000);

      // isExpired is private; check via isElevated which calls it
      expect(session.isElevated()).toBe(false);
    });

    it("after TTL expires, getPassword() returns null", () => {
      const session = SudoSession.getInstance();
      storePassword(session, "expiring", 3000);

      // Advance time past TTL
      vi.advanceTimersByTime(4000);

      expect(session.getPassword()).toBeNull();
    });

    it("extend() resets the expiry timer", () => {
      const session = SudoSession.getInstance();
      storePassword(session, "extending", 5000);

      // Advance 3 seconds (not yet expired)
      vi.advanceTimersByTime(3000);
      expect(session.isElevated()).toBe(true);

      // Extend by another 5 seconds
      const result = session.extend(5000);
      expect(result).toBe(true);

      // Advance another 4 seconds (would have expired without extend)
      vi.advanceTimersByTime(4000);
      expect(session.isElevated()).toBe(true);
    });

    it("extend() returns false when not elevated", () => {
      const session = SudoSession.getInstance();
      expect(session.extend()).toBe(false);
    });
  });

  // ── 4. Input handling ─────────────────────────────────────────────────

  describe("input handling", () => {
    it("storePassword() accepts string input", () => {
      const session = SudoSession.getInstance();
      storePassword(session, "string-input");

      const buf = getInternalBuffer(session);
      expect(buf).toBeInstanceOf(Buffer);
      expect(buf!.toString("utf-8")).toBe("string-input");
    });

    it("storePassword() accepts Buffer input", () => {
      const session = SudoSession.getInstance();
      const inputBuf = Buffer.from("buffer-input", "utf-8");
      storePassword(session, inputBuf);

      const stored = getInternalBuffer(session);
      expect(stored).toBeInstanceOf(Buffer);
      expect(stored!.toString("utf-8")).toBe("buffer-input");
    });

    it("storePassword() makes a defensive copy of Buffer input", () => {
      const session = SudoSession.getInstance();
      const inputBuf = Buffer.from("original-value", "utf-8");
      storePassword(session, inputBuf);

      // Mutate the input buffer
      inputBuf.fill(0);

      // Stored buffer should be unaffected
      const stored = getInternalBuffer(session);
      expect(stored!.toString("utf-8")).toBe("original-value");
    });
  });

  // ── 5. Drop behavior ─────────────────────────────────────────────────

  describe("drop behavior", () => {
    it("drop() zeroes the password buffer (all zeros)", () => {
      const session = SudoSession.getInstance();
      storePassword(session, "zero-me");

      const ref = getInternalBuffer(session)!;
      session.drop();

      expect(ref.every((b) => b === 0)).toBe(true);
    });

    it("drop() sets isElevated() to false", () => {
      const session = SudoSession.getInstance();
      storePassword(session, "elevated");
      expect(session.isElevated()).toBe(true);

      session.drop();
      expect(session.isElevated()).toBe(false);
    });

    it("multiple drop() calls do not throw", () => {
      const session = SudoSession.getInstance();
      storePassword(session, "multi-drop");

      expect(() => session.drop()).not.toThrow();
      expect(() => session.drop()).not.toThrow();
      expect(() => session.drop()).not.toThrow();
    });

    it("drop() clears the username", () => {
      const session = SudoSession.getInstance();
      storePassword(session, "pw");
      (session as any).username = "testuser";

      session.drop();
      expect((session as any).username).toBeNull();
    });

    it("drop() clears the expiry timer", () => {
      const session = SudoSession.getInstance();
      storePassword(session, "pw", 60_000);

      expect((session as any).expiryTimer).not.toBeNull();

      session.drop();
      expect((session as any).expiryTimer).toBeNull();
    });
  });

  // ── 6. getStatus() ────────────────────────────────────────────────────

  describe("getStatus()", () => {
    it("returns elevated status with correct fields when session is active", () => {
      const session = SudoSession.getInstance();
      storePassword(session, "pw", 60_000);
      (session as any).username = "testuser";

      const status = session.getStatus();
      expect(status.elevated).toBe(true);
      expect(status.username).toBe("testuser");
      expect(status.expiresAt).toBeTypeOf("string");
      expect(status.remainingSeconds).toBeTypeOf("number");
      expect(status.remainingSeconds!).toBeGreaterThan(0);
    });

    it("returns non-elevated status after drop()", () => {
      const session = SudoSession.getInstance();
      storePassword(session, "pw");
      session.drop();

      const status = session.getStatus();
      expect(status.elevated).toBe(false);
      expect(status.username).toBeNull();
    });
  });

  // ── 7. Buffer password overwrite ──────────────────────────────────────

  describe("buffer password overwrite", () => {
    it("storePassword() overwrites previous password and zeroes old buffer", () => {
      const session = SudoSession.getInstance();
      storePassword(session, "first-password");

      const firstRef = getInternalBuffer(session)!;
      expect(firstRef.toString("utf-8")).toBe("first-password");

      storePassword(session, "second-password");

      // First buffer should be zeroed
      expect(firstRef.every((b) => b === 0)).toBe(true);

      // New buffer should have the new content
      const secondRef = getInternalBuffer(session)!;
      expect(secondRef.toString("utf-8")).toBe("second-password");
    });
  });

  // ── 8. Extend edge cases ──────────────────────────────────────────────

  describe("extend edge cases", () => {
    it("extend() with custom milliseconds resets timer", () => {
      const session = SudoSession.getInstance();
      storePassword(session, "pw", 5000);

      vi.advanceTimersByTime(2000);
      expect(session.isElevated()).toBe(true);

      const result = session.extend(10000);
      expect(result).toBe(true);

      vi.advanceTimersByTime(8000);
      expect(session.isElevated()).toBe(true);
    });

    it("extend() uses default timeout when no arg provided", () => {
      const session = SudoSession.getInstance();
      session.setDefaultTimeout(3000);
      storePassword(session, "pw", 1000);

      vi.advanceTimersByTime(500);
      
      const result = session.extend();
      expect(result).toBe(true);

      vi.advanceTimersByTime(2000);
      expect(session.isElevated()).toBe(true);
    });

    it("extend() on root session returns true without expiry", () => {
      const session = SudoSession.getInstance();
      storePassword(session, "x");
      (session as any).username = "root";
      (session as any).expiresAt = null;

      const result = session.extend(5000);
      expect(result).toBe(true);
    });
  });

  // ── 9. getStatus() edge cases ─────────────────────────────────────────

  describe("getStatus() edge cases", () => {
    it("returns null remainingSeconds for root sessions", () => {
      const session = SudoSession.getInstance();
      storePassword(session, "x");
      (session as any).username = "root";
      (session as any).expiresAt = null;

      const status = session.getStatus();
      expect(status.elevated).toBe(true);
      expect(status.username).toBe("root");
      expect(status.expiresAt).toBeNull();
      expect(status.remainingSeconds).toBeNull();
    });

    it("returns correct remainingSeconds for timed session", () => {
      const session = SudoSession.getInstance();
      storePassword(session, "pw", 60_000);
      (session as any).username = "testuser";

      const status = session.getStatus();
      expect(status.elevated).toBe(true);
      expect(status.remainingSeconds).toBeGreaterThan(0);
      expect(status.remainingSeconds).toBeLessThanOrEqual(60);
    });
  });

  // ── 10. Auto-drop on expiry ───────────────────────────────────────────

  describe("auto-drop on expiry", () => {
    it("auto-drops session after timeout timer fires", () => {
      const session = SudoSession.getInstance();
      storePassword(session, "auto-drop-pw", 2000);
      expect(session.isElevated()).toBe(true);

      vi.advanceTimersByTime(3000);

      expect(session.isElevated()).toBe(false);
      expect(session.getPassword()).toBeNull();
    });
  });
});
