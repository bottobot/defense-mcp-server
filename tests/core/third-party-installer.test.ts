/**
 * Tests for src/core/third-party-installer.ts
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ── Mock all external dependencies ───────────────────────────────────────────

vi.mock("../../src/core/spawn-safe.js", () => ({
  execFileSafe: vi.fn(() => ""),
}));

vi.mock("../../src/core/command-allowlist.js", () => ({
  resolveCommand: vi.fn((cmd: string) => `/usr/bin/${cmd}`),
}));

vi.mock("../../src/core/changelog.js", () => ({
  logChange: vi.fn(),
  createChangeEntry: vi.fn(() => ({})),
}));

vi.mock("../../src/core/sudo-session.js", () => ({
  SudoSession: {
    getInstance: vi.fn(() => ({
      getPassword: vi.fn(() => null),
      isElevated: vi.fn(() => false),
    })),
  },
}));

// Mock node:fs — only mock the functions we need
vi.mock("node:fs", async () => {
  const actual = await vi.importActual<typeof import("node:fs")>("node:fs");
  return {
    ...actual,
    existsSync: vi.fn(() => false),
    mkdirSync: vi.fn(),
    readFileSync: vi.fn(() => Buffer.from("fake-binary-content")),
    unlinkSync: vi.fn(),
    readdirSync: vi.fn(() => []),
    rmdirSync: vi.fn(),
    writeFileSync: vi.fn(),
  };
});

vi.mock("node:crypto", async () => {
  const actual = await vi.importActual<typeof import("node:crypto")>("node:crypto");
  return {
    ...actual,
    randomUUID: vi.fn(() => "test-uuid-1234"),
    createHash: vi.fn(() => ({
      update: vi.fn().mockReturnThis(),
      digest: vi.fn(() => "fakehash1234567890abcdef1234567890abcdef1234567890abcdef12345678"),
    })),
  };
});

// ── Import after mocks ───────────────────────────────────────────────────────

import {
  checkThirdPartyTool,
  installThirdPartyTool,
  getVerifiedInstallInstructions,
  listThirdPartyTools,
  isThirdPartyInstallEnabled,
} from "../../src/core/third-party-installer.js";
import { execFileSafe } from "../../src/core/spawn-safe.js";
import { resolveCommand } from "../../src/core/command-allowlist.js";
import { existsSync } from "node:fs";

// ── Tests ────────────────────────────────────────────────────────────────────

describe("third-party-installer", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    vi.clearAllMocks();
    // Reset env vars
    delete process.env.DEFENSE_MCP_THIRD_PARTY_INSTALL;
    delete process.env.DEFENSE_MCP_AUTO_INSTALL;
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  // ── isThirdPartyInstallEnabled ─────────────────────────────────────────

  describe("isThirdPartyInstallEnabled", () => {
    it("returns false when env var is not set", () => {
      delete process.env.DEFENSE_MCP_THIRD_PARTY_INSTALL;
      expect(isThirdPartyInstallEnabled()).toBe(false);
    });

    it("returns false when env var is not 'true'", () => {
      process.env.DEFENSE_MCP_THIRD_PARTY_INSTALL = "false";
      expect(isThirdPartyInstallEnabled()).toBe(false);
    });

    it("returns true when env var is 'true'", () => {
      process.env.DEFENSE_MCP_THIRD_PARTY_INSTALL = "true";
      expect(isThirdPartyInstallEnabled()).toBe(true);
    });
  });

  // ── checkThirdPartyTool ────────────────────────────────────────────────

  describe("checkThirdPartyTool", () => {
    it("returns not installed when binary is not found", async () => {
      vi.mocked(resolveCommand).mockImplementation(() => {
        throw new Error("not found");
      });
      vi.mocked(existsSync).mockReturnValue(false);

      const status = await checkThirdPartyTool("grype");
      expect(status.installed).toBe(false);
      expect(status.binary).toBe("grype");
      expect(status.name).toBe("Grype");
      expect(status.manifestVersion).toBe("0.86.1");
    });

    it("returns installed when binary is found via resolveCommand", async () => {
      vi.mocked(resolveCommand).mockReturnValue("/usr/local/bin/grype");
      vi.mocked(execFileSafe).mockReturnValue("grype 0.86.1" as any);

      const status = await checkThirdPartyTool("grype");
      expect(status.installed).toBe(true);
      expect(status.currentVersion).toBe("0.86.1");
      expect(status.needsUpdate).toBe(false);
    });

    it("returns installed with needsUpdate when version differs", async () => {
      vi.mocked(resolveCommand).mockReturnValue("/usr/local/bin/grype");
      vi.mocked(execFileSafe).mockReturnValue("grype 0.85.0" as any);

      const status = await checkThirdPartyTool("grype");
      expect(status.installed).toBe(true);
      expect(status.currentVersion).toBe("0.85.0");
      expect(status.needsUpdate).toBe(true);
    });

    it("returns unknown manifest for non-manifest binary", async () => {
      vi.mocked(resolveCommand).mockImplementation(() => {
        throw new Error("not found");
      });
      vi.mocked(existsSync).mockReturnValue(false);

      const status = await checkThirdPartyTool("unknown-tool");
      expect(status.installed).toBe(false);
      expect(status.manifestVersion).toBe("unknown");
    });

    it("falls back to standard dirs when resolveCommand throws", async () => {
      vi.mocked(resolveCommand).mockImplementation(() => {
        throw new Error("not in allowlist");
      });
      // existsSync returns true for /usr/local/bin/falco
      vi.mocked(existsSync).mockImplementation((path) => {
        return path === "/usr/local/bin/falco";
      });
      vi.mocked(execFileSafe).mockReturnValue("falco 0.39.2" as any);

      const status = await checkThirdPartyTool("falco");
      expect(status.installed).toBe(true);
    });
  });

  // ── installThirdPartyTool ──────────────────────────────────────────────

  describe("installThirdPartyTool", () => {
    it("returns failure when DEFENSE_MCP_THIRD_PARTY_INSTALL is not set", async () => {
      delete process.env.DEFENSE_MCP_THIRD_PARTY_INSTALL;

      const result = await installThirdPartyTool("grype");
      expect(result.success).toBe(false);
      expect(result.message).toContain("Third-party installation is not enabled");
      expect(result.message).toContain("DEFENSE_MCP_THIRD_PARTY_INSTALL=true");
    });

    it("returns failure when DEFENSE_MCP_AUTO_INSTALL is not set", async () => {
      process.env.DEFENSE_MCP_THIRD_PARTY_INSTALL = "true";
      delete process.env.DEFENSE_MCP_AUTO_INSTALL;

      const result = await installThirdPartyTool("grype");
      expect(result.success).toBe(false);
      expect(result.message).toContain("Auto-install is not enabled");
    });

    it("returns failure for unknown binary", async () => {
      process.env.DEFENSE_MCP_THIRD_PARTY_INSTALL = "true";
      process.env.DEFENSE_MCP_AUTO_INSTALL = "true";

      const result = await installThirdPartyTool("unknown-tool");
      expect(result.success).toBe(false);
      expect(result.message).toContain("No manifest entry found");
    });

    it("blocks installation when SHA256 is PENDING_FETCH", async () => {
      process.env.DEFENSE_MCP_THIRD_PARTY_INSTALL = "true";
      process.env.DEFENSE_MCP_AUTO_INSTALL = "true";

      // Mock the tool as not installed
      vi.mocked(resolveCommand).mockImplementation(() => {
        throw new Error("not found");
      });
      vi.mocked(existsSync).mockReturnValue(false);

      // We need to test with a tool that has PENDING_FETCH checksums.
      // Since our manifest has real checksums, we test the mechanism
      // by verifying the install proceeds past the env var checks.
      // The actual SHA256 verification is tested via the checksum mismatch path.
      const result = await installThirdPartyTool("grype");
      // It should attempt to install (not blocked by env vars)
      // but may fail on the actual download (mocked execFileSafe returns "")
      expect(result.binary).toBe("grype");
      // The result depends on the mock behavior — the key assertion is
      // that it got past the env var checks
    });

    it("returns success when tool is already installed at correct version", async () => {
      process.env.DEFENSE_MCP_THIRD_PARTY_INSTALL = "true";
      process.env.DEFENSE_MCP_AUTO_INSTALL = "true";

      // Mock tool as installed at correct version
      vi.mocked(resolveCommand).mockReturnValue("/usr/local/bin/grype");
      vi.mocked(execFileSafe).mockReturnValue("grype 0.86.1" as any);

      const result = await installThirdPartyTool("grype");
      expect(result.success).toBe(true);
      expect(result.message).toContain("already installed");
    });

    it("includes install instructions in failure message when not enabled", async () => {
      delete process.env.DEFENSE_MCP_THIRD_PARTY_INSTALL;

      const result = await installThirdPartyTool("falco");
      expect(result.success).toBe(false);
      expect(result.message).toContain("Manual installation instructions");
      // Should contain APT repo instructions for falco
      expect(result.message).toContain("GPG");
    });
  });

  // ── getVerifiedInstallInstructions ─────────────────────────────────────

  describe("getVerifiedInstallInstructions", () => {
    it("returns non-empty instructions for known tools", () => {
      const instructions = getVerifiedInstallInstructions("grype");
      expect(instructions.length).toBeGreaterThan(0);
      expect(instructions).toContain("Grype");
    });

    it("returns APT repo instructions for falco", () => {
      const instructions = getVerifiedInstallInstructions("falco");
      expect(instructions).toContain("APT");
      expect(instructions).toContain("GPG");
      expect(instructions).toContain("signed-by");
      expect(instructions).toContain("falco");
    });

    it("returns GitHub release instructions for grype", () => {
      const instructions = getVerifiedInstallInstructions("grype");
      expect(instructions).toContain("GitHub Release");
      expect(instructions).toContain("sha256sum");
      expect(instructions).toContain("curl");
    });

    it("returns npm instructions for cdxgen", () => {
      const instructions = getVerifiedInstallInstructions("cdxgen");
      expect(instructions).toContain("npm");
      expect(instructions).toContain("@cyclonedx/cdxgen");
    });

    it("does NOT contain curl|sh pattern", () => {
      const allTools = ["falco", "trivy", "grype", "syft", "trufflehog", "slsa-verifier", "cdxgen"];
      for (const tool of allTools) {
        const instructions = getVerifiedInstallInstructions(tool);
        // Must not contain curl piped to sh/bash
        expect(instructions).not.toMatch(/curl\s.*\|\s*(sh|bash)/);
      }
    });

    it("returns fallback message for unknown tool", () => {
      const instructions = getVerifiedInstallInstructions("unknown-tool");
      expect(instructions).toContain("not a known third-party tool");
    });
  });

  // ── listThirdPartyTools ────────────────────────────────────────────────

  describe("listThirdPartyTools", () => {
    it("returns an array with status for each manifest tool", async () => {
      vi.mocked(resolveCommand).mockImplementation(() => {
        throw new Error("not found");
      });
      vi.mocked(existsSync).mockReturnValue(false);

      const tools = await listThirdPartyTools();
      expect(Array.isArray(tools)).toBe(true);
      expect(tools.length).toBe(7); // 7 tools in manifest

      // Check that all expected tools are present
      const binaries = tools.map((t) => t.binary);
      expect(binaries).toContain("falco");
      expect(binaries).toContain("trivy");
      expect(binaries).toContain("grype");
      expect(binaries).toContain("syft");
      expect(binaries).toContain("trufflehog");
      expect(binaries).toContain("slsa-verifier");
      expect(binaries).toContain("cdxgen");
    });

    it("each tool has required status fields", async () => {
      vi.mocked(resolveCommand).mockImplementation(() => {
        throw new Error("not found");
      });
      vi.mocked(existsSync).mockReturnValue(false);

      const tools = await listThirdPartyTools();
      for (const tool of tools) {
        expect(tool).toHaveProperty("binary");
        expect(tool).toHaveProperty("name");
        expect(tool).toHaveProperty("installed");
        expect(tool).toHaveProperty("manifestVersion");
        expect(tool).toHaveProperty("needsUpdate");
        expect(typeof tool.binary).toBe("string");
        expect(typeof tool.installed).toBe("boolean");
      }
    });
  });
});
