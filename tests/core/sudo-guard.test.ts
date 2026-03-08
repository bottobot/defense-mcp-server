/**
 * Tests for src/core/sudo-guard.ts
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ── Mock dependencies ────────────────────────────────────────────────────────

vi.mock("../../src/core/sudo-session.js", () => ({
  SudoSession: {
    getInstance: vi.fn(() => ({
      isElevated: vi.fn(() => false),
      getStatus: vi.fn(() => ({
        elevated: false,
        remainingSeconds: null,
      })),
    })),
  },
}));

vi.mock("node:fs", () => ({
  statSync: vi.fn(),
  lstatSync: vi.fn(() => ({
    isSymbolicLink: () => false,
    isFile: () => true,
    uid: 1000,
    mode: 0o100700,
  })),
}));

import { SudoGuard, type ElevationPromptResponse } from "../../src/core/sudo-guard.js";
import { lstatSync } from "node:fs";

describe("SudoGuard", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  // ── isPermissionError ──────────────────────────────────────────────────────

  describe("isPermissionError", () => {
    it("returns false for empty output", () => {
      expect(SudoGuard.isPermissionError("")).toBe(false);
      expect(SudoGuard.isPermissionError("", 1)).toBe(false);
    });

    it("detects 'permission denied' in output", () => {
      expect(SudoGuard.isPermissionError("Error: permission denied")).toBe(true);
    });

    it("detects 'operation not permitted'", () => {
      expect(SudoGuard.isPermissionError("EPERM: operation not permitted")).toBe(true);
    });

    it("detects sudo password prompts", () => {
      expect(SudoGuard.isPermissionError("sudo: a password is required")).toBe(true);
    });

    it("detects 'must be run as root'", () => {
      expect(SudoGuard.isPermissionError("This program must be run as root")).toBe(true);
    });

    it("detects iptables permission errors", () => {
      expect(SudoGuard.isPermissionError("can't initialize iptables table")).toBe(true);
    });

    it("detects Docker permission errors", () => {
      expect(SudoGuard.isPermissionError("docker: permission denied")).toBe(true);
    });

    it("detects interactive authentication required", () => {
      expect(SudoGuard.isPermissionError("interactive authentication required")).toBe(true);
    });

    it("detects 'are you root?' messages", () => {
      expect(SudoGuard.isPermissionError("E: Are you root?")).toBe(true);
    });

    it("returns true for exit code 126 regardless of output", () => {
      expect(SudoGuard.isPermissionError("some output", 126)).toBe(true);
    });

    it("returns false for normal error output without permission patterns", () => {
      expect(SudoGuard.isPermissionError("file not found", 1)).toBe(false);
      expect(SudoGuard.isPermissionError("syntax error", 2)).toBe(false);
    });

    it("detects EACCES errors", () => {
      expect(SudoGuard.isPermissionError("EACCES: access denied")).toBe(true);
    });

    it("detects 'unable to lock' (package manager)", () => {
      expect(SudoGuard.isPermissionError("E: unable to lock the administration directory")).toBe(true);
    });
  });

  // ── createElevationPrompt ──────────────────────────────────────────────────

  describe("createElevationPrompt", () => {
    it("returns a structured elevation prompt response", () => {
      const result = SudoGuard.createElevationPrompt("firewall_iptables");

      expect(result.isError).toBe(true);
      expect(result._meta.elevationRequired).toBe(true);
      expect(result._meta.haltWorkflow).toBe(true);
      expect(result._meta.failedTool).toBe("firewall_iptables");
      expect(result._meta.elevationTool).toBe("sudo_elevate");
      expect(result.content).toHaveLength(1);
      expect(result.content[0].type).toBe("text");
      expect(result.content[0].text).toContain("WORKFLOW HALTED");
    });

    it("includes a custom reason when provided", () => {
      const result = SudoGuard.createElevationPrompt(
        "log_auditd",
        "Auditd requires root for rule management",
      );

      expect(result._meta.reason).toBe("Auditd requires root for rule management");
      expect(result.content[0].text).toContain("Auditd requires root");
    });

    it("includes original error when provided", () => {
      const result = SudoGuard.createElevationPrompt(
        "test_tool",
        undefined,
        "Original error: permission denied at /etc/test",
      );

      expect(result.content[0].text).toContain("Original error");
      expect(result.content[0].text).toContain("permission denied at /etc/test");
    });

    it("uses default reason when none provided", () => {
      const result = SudoGuard.createElevationPrompt("test_tool");
      expect(result._meta.reason).toContain("elevated (root) privileges");
    });
  });

  // ── isResponsePermissionError ──────────────────────────────────────────────

  describe("isResponsePermissionError", () => {
    it("returns false for undefined response", () => {
      expect(SudoGuard.isResponsePermissionError(undefined)).toBe(false);
    });

    it("returns false for non-error responses", () => {
      expect(
        SudoGuard.isResponsePermissionError({
          isError: false,
          content: [{ type: "text", text: "permission denied" }],
        }),
      ).toBe(false);
    });

    it("returns true for error response with permission denied text", () => {
      expect(
        SudoGuard.isResponsePermissionError({
          isError: true,
          content: [{ type: "text", text: "Error: permission denied" }],
        }),
      ).toBe(true);
    });

    it("returns false for error response without permission patterns", () => {
      expect(
        SudoGuard.isResponsePermissionError({
          isError: true,
          content: [{ type: "text", text: "Error: file not found" }],
        }),
      ).toBe(false);
    });

    it("returns false when content is not an array", () => {
      expect(
        SudoGuard.isResponsePermissionError({
          isError: true,
          content: "not an array",
        }),
      ).toBe(false);
    });
  });

  // ── extractResponseText ────────────────────────────────────────────────────

  describe("extractResponseText", () => {
    it("returns undefined for undefined response", () => {
      expect(SudoGuard.extractResponseText(undefined)).toBeUndefined();
    });

    it("extracts text from first text content item", () => {
      const text = SudoGuard.extractResponseText({
        content: [{ type: "text", text: "Hello world" }],
      });
      expect(text).toBe("Hello world");
    });

    it("returns undefined when content is not an array", () => {
      expect(SudoGuard.extractResponseText({ content: "string" })).toBeUndefined();
    });
  });

  // ── hasActiveSession ───────────────────────────────────────────────────────

  describe("hasActiveSession", () => {
    it("returns false when no session is active", () => {
      expect(SudoGuard.hasActiveSession()).toBe(false);
    });
  });

  // ── validateAskpass (CORE-006) ─────────────────────────────────────────────

  describe("validateAskpass", () => {
    it("returns valid when SUDO_ASKPASS is not set", () => {
      delete process.env.SUDO_ASKPASS;
      const result = SudoGuard.validateAskpass();
      expect(result.valid).toBe(true);
    });

    it("rejects symlinks", () => {
      process.env.SUDO_ASKPASS = "/usr/bin/askpass";
      vi.mocked(lstatSync).mockReturnValue({
        isSymbolicLink: () => true,
        isFile: () => false,
        uid: 0,
        mode: 0o100700,
      } as any);

      const result = SudoGuard.validateAskpass();
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("symlink");
    });

    it("rejects non-regular files", () => {
      process.env.SUDO_ASKPASS = "/usr/bin/askpass";
      vi.mocked(lstatSync).mockReturnValue({
        isSymbolicLink: () => false,
        isFile: () => false,
        uid: 0,
        mode: 0o100700,
      } as any);

      const result = SudoGuard.validateAskpass();
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("not a regular file");
    });

    it("rejects files owned by wrong user", () => {
      process.env.SUDO_ASKPASS = "/usr/bin/askpass";
      vi.mocked(lstatSync).mockReturnValue({
        isSymbolicLink: () => false,
        isFile: () => true,
        uid: 9999, // wrong user
        mode: 0o100700,
      } as any);

      const result = SudoGuard.validateAskpass();
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("owned by uid 9999");
    });

    it("rejects overly permissive files (world/group access)", () => {
      process.env.SUDO_ASKPASS = "/usr/bin/askpass";
      vi.mocked(lstatSync).mockReturnValue({
        isSymbolicLink: () => false,
        isFile: () => true,
        uid: 0,
        mode: 0o100755, // group+world executable
      } as any);

      const result = SudoGuard.validateAskpass();
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("overly permissive");
    });

    it("accepts correctly configured askpass (root-owned, 0700)", () => {
      process.env.SUDO_ASKPASS = "/usr/bin/askpass";
      vi.mocked(lstatSync).mockReturnValue({
        isSymbolicLink: () => false,
        isFile: () => true,
        uid: 0,
        mode: 0o100700,
      } as any);

      const result = SudoGuard.validateAskpass();
      expect(result.valid).toBe(true);
    });

    it("accepts askpass owned by current user with 0500", () => {
      process.env.SUDO_ASKPASS = "/home/user/askpass";
      const currentUid = process.getuid?.() ?? 1000;
      vi.mocked(lstatSync).mockReturnValue({
        isSymbolicLink: () => false,
        isFile: () => true,
        uid: currentUid,
        mode: 0o100500,
      } as any);

      const result = SudoGuard.validateAskpass();
      expect(result.valid).toBe(true);
    });

    it("handles lstatSync errors gracefully", () => {
      process.env.SUDO_ASKPASS = "/nonexistent/path";
      vi.mocked(lstatSync).mockImplementation(() => {
        throw new Error("ENOENT: no such file or directory");
      });

      const result = SudoGuard.validateAskpass();
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("Failed to verify");
    });
  });
});
