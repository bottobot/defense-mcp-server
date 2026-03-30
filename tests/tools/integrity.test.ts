/**
 * Tests for src/tools/integrity.ts — all 11 actions.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Mocks ──────────────────────────────────────────────────────────────────
vi.mock("../../src/core/executor.js", () => ({
  executeCommand: vi.fn().mockResolvedValue({
    exitCode: 0, stdout: "", stderr: "",
    timedOut: false, duration: 10, permissionDenied: false,
  }),
}));
vi.mock("../../src/core/config.js", () => ({
  getConfig: vi.fn().mockReturnValue({ dryRun: true }),
  getToolTimeout: vi.fn().mockReturnValue(30000),
  getActionTimeout: vi.fn().mockReturnValue(900000),
}));
vi.mock("../../src/core/parsers.js", () => ({
  createTextContent: vi.fn((t: string) => ({ type: "text", text: t })),
  createErrorContent: vi.fn((t: string) => ({ type: "text", text: `Error: ${t}` })),
  formatToolOutput: vi.fn((o: unknown) => ({ type: "text", text: JSON.stringify(o) })),
}));
vi.mock("../../src/core/changelog.js", () => ({
  logChange: vi.fn(),
  createChangeEntry: vi.fn().mockReturnValue({}),
}));
vi.mock("../../src/core/sanitizer.js", () => ({
  validateToolPath: vi.fn((p: string) => p),
  sanitizeArgs: vi.fn((a: string[]) => a),
}));
vi.mock("../../src/core/secure-fs.js", () => ({
  secureWriteFileSync: vi.fn(),
}));
vi.mock("node:fs", () => ({
  existsSync: vi.fn().mockReturnValue(true),
  readFileSync: vi.fn().mockReturnValue("{}"),
  mkdirSync: vi.fn(),
  readdirSync: vi.fn().mockReturnValue([]),
  statSync: vi.fn().mockReturnValue({ size: 1024, mtime: new Date("2025-01-01T00:00:00Z") }),
}));
vi.mock("node:crypto", () => ({
  createHash: vi.fn().mockReturnValue({
    update: vi.fn().mockReturnThis(),
    digest: vi.fn().mockReturnValue("abc123def456"),
  }),
}));
vi.mock("node:os", () => ({ homedir: vi.fn().mockReturnValue("/home/testuser") }));

// ── Imports ────────────────────────────────────────────────────────────────
import { registerIntegrityTools } from "../../src/tools/integrity.js";
import { executeCommand } from "../../src/core/executor.js";
import { getConfig } from "../../src/core/config.js";
import { validateToolPath, sanitizeArgs } from "../../src/core/sanitizer.js";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { createHash } from "node:crypto";

// ── Helpers ────────────────────────────────────────────────────────────────
type TH = (p: Record<string, unknown>) => Promise<{
  content: Array<{ type: string; text: string }>; isError?: boolean;
}>;

function createMockServer() {
  const tools = new Map<string, { handler: TH }>();
  const server = {
    tool: vi.fn((_n: string, _d: string, _s: unknown, h: TH) => {
      tools.set(_n, { handler: h });
    }),
  };
  return { server: server as unknown as Parameters<typeof registerIntegrityTools>[0], tools };
}

function cr(o: { exitCode?: number; stdout?: string; stderr?: string } = {}) {
  return {
    exitCode: o.exitCode ?? 0, stdout: o.stdout ?? "", stderr: o.stderr ?? "",
    timedOut: false, duration: 10, permissionDenied: false,
  };
}

// ── Tests ──────────────────────────────────────────────────────────────────
describe("integrity tools", () => {
  let handler: TH;

  beforeEach(() => {
    vi.clearAllMocks();
    // Re-apply default mock implementations (clearAllMocks resets implementations too)
    vi.mocked(getConfig).mockReturnValue({ dryRun: true } as ReturnType<typeof getConfig>);
    vi.mocked(executeCommand).mockResolvedValue(cr());
    vi.mocked(existsSync).mockReturnValue(true);
    vi.mocked(readFileSync).mockReturnValue("{}");
    vi.mocked(readdirSync).mockReturnValue([] as unknown as ReturnType<typeof readdirSync>);
    vi.mocked(validateToolPath).mockImplementation((p: string) => p);
    vi.mocked(sanitizeArgs).mockImplementation((a: string[]) => a);
    vi.mocked(statSync).mockReturnValue({
      size: 1024, mtime: new Date("2025-01-01T00:00:00Z"),
    } as unknown as ReturnType<typeof statSync>);
    vi.mocked(createHash).mockReturnValue({
      update: vi.fn().mockReturnThis(),
      digest: vi.fn().mockReturnValue("abc123def456"),
    } as unknown as ReturnType<typeof createHash>);

    const m = createMockServer();
    registerIntegrityTools(m.server);
    handler = m.tools.get("integrity")!.handler;
  });

  it("registers the integrity tool", () => {
    const m = createMockServer();
    registerIntegrityTools(m.server);
    expect(m.tools.has("integrity")).toBe(true);
    expect(m.tools.size).toBe(1);
  });

  // ── AIDE actions ─────────────────────────────────────────────────────────
  describe("aide_init", () => {
    it("dry-run preview by default", async () => {
      const r = await handler({ action: "aide_init" });
      expect(r.isError).toBeUndefined();
      expect(r.content[0].text).toContain("DRY-RUN");
      expect(r.content[0].text).toContain("aide --init");
    });

    it("executes when dry_run=false", async () => {
      vi.mocked(executeCommand)
        .mockResolvedValueOnce(cr({ stdout: "AIDE initialized" }))
        .mockResolvedValueOnce(cr());
      const r = await handler({ action: "aide_init", dry_run: false });
      expect(r.isError).toBeUndefined();
      expect(r.content[0].text).toContain("AIDE init completed");
      expect(r.content[0].text).toContain("moved to /var/lib/aide/aide.db");
    });

    it("reports error on failure", async () => {
      vi.mocked(executeCommand).mockResolvedValue(cr({ exitCode: 1, stderr: "not found" }));
      const r = await handler({ action: "aide_init", dry_run: false });
      expect(r.isError).toBe(true);
      expect(r.content[0].text).toContain("AIDE init failed");
    });

    it("warns when db move fails", async () => {
      vi.mocked(executeCommand)
        .mockResolvedValueOnce(cr({ stdout: "OK" }))
        .mockResolvedValueOnce(cr({ exitCode: 1, stderr: "Permission denied" }));
      const r = await handler({ action: "aide_init", dry_run: false });
      expect(r.content[0].text).toContain("failed to move");
    });

    it("validates custom config path", async () => {
      await handler({ action: "aide_init", config: "/etc/aide/aide.conf" });
      expect(validateToolPath).toHaveBeenCalledWith(
        "/etc/aide/aide.conf", expect.any(Array), "AIDE config path"
      );
    });

    it("catches path validation errors", async () => {
      vi.mocked(validateToolPath).mockImplementation(() => { throw new Error("bad path"); });
      const r = await handler({ action: "aide_init", config: "/bad" });
      expect(r.isError).toBe(true);
    });
  });

  describe("aide_check", () => {
    it("dry-run preview", async () => {
      const r = await handler({ action: "aide_check" });
      expect(r.content[0].text).toContain("aide --check");
    });

    it("parses summary lines", async () => {
      vi.mocked(executeCommand).mockResolvedValue(
        cr({ stdout: "Total: 100\nFiles added: 2\nFiles changed: 3" })
      );
      const r = await handler({ action: "aide_check", dry_run: false });
      expect(r.content[0].text).toContain("AIDE check completed");
      expect(r.content[0].text).toContain("Summary");
    });

    it("includes stderr", async () => {
      vi.mocked(executeCommand).mockResolvedValue(cr({ stdout: "OK", stderr: "warn" }));
      const r = await handler({ action: "aide_check", dry_run: false });
      expect(r.content[0].text).toContain("Stderr");
    });
  });

  describe("aide_update", () => {
    it("dry-run preview", async () => {
      const r = await handler({ action: "aide_update" });
      expect(r.content[0].text).toContain("aide --update");
    });

    it("executes", async () => {
      vi.mocked(executeCommand).mockResolvedValue(cr({ stdout: "Updated" }));
      const r = await handler({ action: "aide_update", dry_run: false });
      expect(r.content[0].text).toContain("AIDE update completed");
    });
  });

  describe("aide_compare", () => {
    it("dry-run preview", async () => {
      const r = await handler({ action: "aide_compare" });
      expect(r.content[0].text).toContain("aide --compare");
    });

    it("executes", async () => {
      vi.mocked(executeCommand).mockResolvedValue(cr({ stdout: "Done" }));
      const r = await handler({ action: "aide_compare", dry_run: false });
      expect(r.content[0].text).toContain("AIDE compare completed");
    });
  });

  // ── Rootkit scanning ────────────────────────────────────────────────────
  describe("rootkit_rkhunter", () => {
    it("runs update + check", async () => {
      vi.mocked(executeCommand)
        .mockResolvedValueOnce(cr({ stdout: "Updated" }))
        .mockResolvedValueOnce(cr({ stdout: "All passed\n" }));
      const r = await handler({ action: "rootkit_rkhunter", update_first: true });
      const p = JSON.parse(r.content[0].text);
      expect(p.riskLevel).toBe("CLEAN");
    });

    it("skips update when update_first=false", async () => {
      await handler({ action: "rootkit_rkhunter", update_first: false });
      expect(executeCommand).toHaveBeenCalledTimes(1);
    });

    it("detects warnings", async () => {
      vi.mocked(executeCommand)
        .mockResolvedValueOnce(cr())
        .mockResolvedValueOnce(cr({ stdout: "[ Warning ]\n[ Warning ]\n" }));
      const p = JSON.parse((await handler({ action: "rootkit_rkhunter", update_first: true })).content[0].text);
      expect(p.riskLevel).toBe("WARNING");
      expect(p.warningsCount).toBe(2);
    });

    it("detects infected", async () => {
      vi.mocked(executeCommand)
        .mockResolvedValueOnce(cr())
        .mockResolvedValueOnce(cr({ stdout: "[ Infected ]\n" }));
      const p = JSON.parse((await handler({ action: "rootkit_rkhunter", update_first: true })).content[0].text);
      expect(p.riskLevel).toBe("CRITICAL");
    });

    it("passes --sk and --rwo flags", async () => {
      await handler({ action: "rootkit_rkhunter", update_first: false, skip_keypress: true, report_warnings_only: true });
      expect(executeCommand).toHaveBeenCalledWith(
        expect.objectContaining({ args: expect.arrayContaining(["--sk", "--rwo"]) })
      );
    });

    it("handles errors", async () => {
      vi.mocked(executeCommand).mockRejectedValue(new Error("fail"));
      const r = await handler({ action: "rootkit_rkhunter", update_first: false });
      expect(r.isError).toBe(true);
    });
  });

  describe("rootkit_chkrootkit", () => {
    it("reports clean", async () => {
      vi.mocked(executeCommand).mockResolvedValue(
        cr({ stdout: "not infected\nnot found\nnothing found\n" })
      );
      const p = JSON.parse((await handler({ action: "rootkit_chkrootkit" })).content[0].text);
      expect(p.riskLevel).toBe("CLEAN");
      expect(p.cleanCount).toBe(3);
    });

    it("detects INFECTED", async () => {
      vi.mocked(executeCommand).mockResolvedValue(cr({ stdout: "INFECTED\nnot infected\n" }));
      expect(JSON.parse((await handler({ action: "rootkit_chkrootkit" })).content[0].text).riskLevel).toBe("CRITICAL");
    });

    it("detects suspicious", async () => {
      vi.mocked(executeCommand).mockResolvedValue(cr({ stdout: "Suspicious files\n" }));
      expect(JSON.parse((await handler({ action: "rootkit_chkrootkit" })).content[0].text).riskLevel).toBe("WARNING");
    });

    it("passes -q and -x flags", async () => {
      await handler({ action: "rootkit_chkrootkit", quiet: true, expert: true });
      expect(executeCommand).toHaveBeenCalledWith(
        expect.objectContaining({ args: expect.arrayContaining(["-q", "-x"]) })
      );
    });

    it("handles errors", async () => {
      vi.mocked(executeCommand).mockRejectedValue(new Error("fail"));
      expect((await handler({ action: "rootkit_chkrootkit" })).isError).toBe(true);
    });
  });

  describe("rootkit_all", () => {
    it("both tools available (quick)", async () => {
      vi.mocked(executeCommand)
        .mockResolvedValueOnce(cr({ stdout: "/usr/bin/rkhunter" }))
        .mockResolvedValueOnce(cr({ stdout: "clean\n" }))
        .mockResolvedValueOnce(cr({ stdout: "/usr/bin/chkrootkit" }))
        .mockResolvedValueOnce(cr({ stdout: "not infected\n" }));
      const p = JSON.parse((await handler({ action: "rootkit_all", quick: true })).content[0].text);
      expect(p.overallRisk).toBe("CLEAN");
      expect(p.summary.toolsAvailable).toBe(2);
    });

    it("runs update when quick=false", async () => {
      vi.mocked(executeCommand)
        .mockResolvedValueOnce(cr({ stdout: "/usr/bin/rkhunter" }))
        .mockResolvedValueOnce(cr())
        .mockResolvedValueOnce(cr({ stdout: "clean\n" }))
        .mockResolvedValueOnce(cr({ stdout: "/usr/bin/chkrootkit" }))
        .mockResolvedValueOnce(cr({ stdout: "ok\n" }));
      await handler({ action: "rootkit_all", quick: false });
      expect(executeCommand).toHaveBeenCalledTimes(5);
    });

    it("handles no tools installed", async () => {
      vi.mocked(executeCommand)
        .mockResolvedValueOnce(cr({ exitCode: 1 }))
        .mockResolvedValueOnce(cr({ exitCode: 1 }));
      const p = JSON.parse((await handler({ action: "rootkit_all", quick: true })).content[0].text);
      expect(p.overallRisk).toContain("UNKNOWN");
      expect(p.summary.toolsAvailable).toBe(0);
    });

    it("reports CRITICAL on infection", async () => {
      vi.mocked(executeCommand)
        .mockResolvedValueOnce(cr({ stdout: "/usr/bin/rkhunter" }))
        .mockResolvedValueOnce(cr({ stdout: "[ Infected ]\n" }))
        .mockResolvedValueOnce(cr({ stdout: "/usr/bin/chkrootkit" }))
        .mockResolvedValueOnce(cr({ stdout: "INFECTED\n" }));
      const p = JSON.parse((await handler({ action: "rootkit_all", quick: true })).content[0].text);
      expect(p.overallRisk).toBe("CRITICAL");
    });

    it("reports WARNING", async () => {
      vi.mocked(executeCommand)
        .mockResolvedValueOnce(cr({ stdout: "/usr/bin/rkhunter" }))
        .mockResolvedValueOnce(cr({ stdout: "[ Warning ]\n" }))
        .mockResolvedValueOnce(cr({ stdout: "/usr/bin/chkrootkit" }))
        .mockResolvedValueOnce(cr({ stdout: "ok\n" }));
      expect(JSON.parse((await handler({ action: "rootkit_all", quick: true })).content[0].text).overallRisk).toBe("WARNING");
    });

    it("handles errors", async () => {
      vi.mocked(executeCommand).mockRejectedValue(new Error("fail"));
      expect((await handler({ action: "rootkit_all", quick: true })).isError).toBe(true);
    });
  });

  // ── file_integrity ──────────────────────────────────────────────────────
  describe("file_integrity", () => {
    it("errors when no paths", async () => {
      expect((await handler({ action: "file_integrity" })).isError).toBe(true);
    });

    it("errors on empty string", async () => {
      expect((await handler({ action: "file_integrity", paths: "" })).isError).toBe(true);
    });

    it("displays hashes (string)", async () => {
      vi.mocked(executeCommand).mockResolvedValue(cr({ stdout: "aaa  /etc/passwd\nbbb  /etc/shadow\n" }));
      const p = JSON.parse((await handler({ action: "file_integrity", paths: "/etc/passwd,/etc/shadow" })).content[0].text);
      expect(p.action).toBe("display");
      expect(p.fileCount).toBe(2);
    });

    it("displays hashes (array)", async () => {
      vi.mocked(executeCommand).mockResolvedValue(cr({ stdout: "aaa  /etc/passwd\n" }));
      const p = JSON.parse((await handler({ action: "file_integrity", paths: ["/etc/passwd"] })).content[0].text);
      expect(p.fileCount).toBe(1);
    });

    it("creates baseline", async () => {
      vi.mocked(executeCommand)
        .mockResolvedValueOnce(cr({ stdout: "aaa  /etc/passwd\n" }))
        .mockResolvedValueOnce(cr());
      const p = JSON.parse((await handler({ action: "file_integrity", paths: "/etc/passwd", create_baseline: true })).content[0].text);
      expect(p.action).toBe("baseline_created");
    });

    it("creates baseline with custom path", async () => {
      vi.mocked(executeCommand)
        .mockResolvedValueOnce(cr({ stdout: "aaa  /etc/passwd\n" }))
        .mockResolvedValueOnce(cr());
      const p = JSON.parse((await handler({
        action: "file_integrity", paths: "/etc/passwd", create_baseline: true, baseline_path: "/tmp/b.sha256",
      })).content[0].text);
      expect(p.baselinePath).toBe("/tmp/b.sha256");
    });

    it("errors when baseline write fails", async () => {
      vi.mocked(executeCommand)
        .mockResolvedValueOnce(cr({ stdout: "aaa  /etc/passwd\n" }))
        .mockResolvedValueOnce(cr({ exitCode: 1, stderr: "denied" }));
      const r = await handler({ action: "file_integrity", paths: "/etc/passwd", create_baseline: true });
      expect(r.isError).toBe(true);
      expect(r.content[0].text).toContain("Failed to write baseline");
    });

    it("compares against baseline (MODIFIED)", async () => {
      vi.mocked(executeCommand)
        .mockResolvedValueOnce(cr({ stdout: "aaa  /etc/passwd\nbbb  /etc/shadow\n" }))
        .mockResolvedValueOnce(cr({ stdout: "aaa  /etc/passwd\nccc  /etc/shadow\nxxx  /etc/hosts\n" }));
      const p = JSON.parse((await handler({
        action: "file_integrity", paths: "/etc/passwd,/etc/shadow", baseline_path: "/tmp/b",
      })).content[0].text);
      expect(p.integrityStatus).toBe("MODIFIED");
      expect(p.summary.changed).toBe(1);
      expect(p.summary.missing).toBe(1);
    });

    it("compares against baseline (INTACT)", async () => {
      vi.mocked(executeCommand)
        .mockResolvedValueOnce(cr({ stdout: "aaa  /etc/passwd\n" }))
        .mockResolvedValueOnce(cr({ stdout: "aaa  /etc/passwd\n" }));
      const p = JSON.parse((await handler({
        action: "file_integrity", paths: "/etc/passwd", baseline_path: "/tmp/b",
      })).content[0].text);
      expect(p.integrityStatus).toBe("INTACT");
    });

    it("errors when baseline unreadable", async () => {
      vi.mocked(executeCommand)
        .mockResolvedValueOnce(cr({ stdout: "aaa  /etc/passwd\n" }))
        .mockResolvedValueOnce(cr({ exitCode: 1, stderr: "No such file" }));
      const r = await handler({ action: "file_integrity", paths: "/etc/passwd", baseline_path: "/tmp/x" });
      expect(r.isError).toBe(true);
      expect(r.content[0].text).toContain("Cannot read baseline");
    });

    it("errors when sha256sum fails", async () => {
      vi.mocked(executeCommand).mockResolvedValue(cr({ exitCode: 1, stderr: "not found" }));
      const r = await handler({ action: "file_integrity", paths: "/etc/passwd" });
      expect(r.isError).toBe(true);
      expect(r.content[0].text).toContain("sha256sum failed");
    });

    it("catches path validation errors", async () => {
      vi.mocked(validateToolPath).mockImplementation(() => { throw new Error("bad"); });
      expect((await handler({ action: "file_integrity", paths: "/etc/passwd" })).isError).toBe(true);
    });
  });

  // ── baseline_create ─────────────────────────────────────────────────────
  describe("baseline_create", () => {
    it("dry-run preview", async () => {
      const p = JSON.parse((await handler({
        action: "baseline_create", dryRun: true, name: "test", directories: ["/etc"],
      })).content[0].text);
      expect(p.dryRun).toBe(true);
      expect(p.baselineName).toBe("test");
    });

    it("creates baseline with file hashing", async () => {
      vi.mocked(executeCommand)
        .mockResolvedValueOnce(cr({ stdout: "/etc/file1\n/etc/file2\n" }))
        .mockResolvedValueOnce(cr({ stdout: "key1 = val1\n" }))
        .mockResolvedValueOnce(cr({ stdout: "svc1.service loaded active running\n" }));
      const r = await handler({
        action: "baseline_create", dryRun: false, name: "mybase", directories: ["/etc"],
      });
      expect(r.isError).toBeUndefined();
      const p = JSON.parse(r.content[0].text);
      expect(p.baselineName).toBe("mybase");
      expect(p.filesHashed).toBe(2);
    });

    it("skips non-existent directories", async () => {
      vi.mocked(existsSync).mockImplementation((p) => {
        if (typeof p === "string" && p.includes("nonexistent")) return false;
        return true;
      });
      vi.mocked(executeCommand)
        .mockResolvedValueOnce(cr())
        .mockResolvedValueOnce(cr());
      const p = JSON.parse((await handler({
        action: "baseline_create", dryRun: false, name: "t", directories: ["/nonexistent"],
      })).content[0].text);
      expect(p.filesHashed).toBe(0);
    });

    it("falls back to /proc/sys when sysctl unavailable", async () => {
      vi.mocked(readFileSync).mockReturnValue("1");
      vi.mocked(executeCommand)
        .mockResolvedValueOnce(cr({ stdout: "" }))
        .mockResolvedValueOnce(cr({ exitCode: 1 }))
        .mockResolvedValueOnce(cr());
      const p = JSON.parse((await handler({
        action: "baseline_create", dryRun: false, name: "t", directories: ["/etc"],
      })).content[0].text);
      expect(p.sysctlKeys).toBeGreaterThan(0);
    });

    it("handles errors", async () => {
      vi.mocked(existsSync).mockImplementation(() => { throw new Error("fs error"); });
      const r = await handler({ action: "baseline_create", dryRun: false, name: "t", directories: ["/etc"] });
      expect(r.isError).toBe(true);
      expect(r.content[0].text).toContain("Baseline creation failed");
    });
  });

  // ── baseline_compare ────────────────────────────────────────────────────
  describe("baseline_compare", () => {
    const bd = JSON.stringify({
      id: "test", timestamp: "2025-01-01T00:00:00Z", directories: ["/etc"],
      files: [{ path: "/etc/file1", hash: "oldhash", size: 100, mtime: "2025-01-01T00:00:00Z" }],
      sysctlState: { "net.ipv4.ip_forward": "0" },
      services: { "ssh.service": "active" },
    });

    it("reports NO_DRIFT", async () => {
      vi.mocked(readFileSync).mockReturnValue(bd);
      vi.mocked(createHash).mockReturnValue({
        update: vi.fn().mockReturnThis(),
        digest: vi.fn().mockReturnValue("oldhash"),
      } as unknown as ReturnType<typeof createHash>);
      vi.mocked(executeCommand)
        .mockResolvedValueOnce(cr({ stdout: "net.ipv4.ip_forward = 0\n" }))
        .mockResolvedValueOnce(cr({ stdout: "ssh.service loaded active running\n" }));
      const p = JSON.parse((await handler({ action: "baseline_compare", name: "test" })).content[0].text);
      expect(p.status).toBe("NO_DRIFT");
    });

    it("detects file drift", async () => {
      vi.mocked(readFileSync).mockReturnValue(bd);
      vi.mocked(createHash).mockReturnValue({
        update: vi.fn().mockReturnThis(),
        digest: vi.fn().mockReturnValue("newhash"),
      } as unknown as ReturnType<typeof createHash>);
      vi.mocked(executeCommand)
        .mockResolvedValueOnce(cr({ stdout: "net.ipv4.ip_forward = 0\n" }))
        .mockResolvedValueOnce(cr({ stdout: "ssh.service loaded active running\n" }));
      const p = JSON.parse((await handler({ action: "baseline_compare", name: "test" })).content[0].text);
      expect(p.status).toBe("DRIFT_DETECTED");
      expect(p.fileChanges.length).toBeGreaterThan(0);
    });

    it("detects deleted files", async () => {
      vi.mocked(readFileSync).mockReturnValue(bd);
      vi.mocked(existsSync).mockImplementation((p) => {
        if (typeof p === "string" && p === "/etc/file1") return false;
        return true;
      });
      vi.mocked(executeCommand)
        .mockResolvedValueOnce(cr())
        .mockResolvedValueOnce(cr());
      const p = JSON.parse((await handler({ action: "baseline_compare", name: "test" })).content[0].text);
      expect(p.status).toBe("DRIFT_DETECTED");
      expect(p.fileChanges[0].type).toBe("deleted");
    });

    it("detects sysctl drift", async () => {
      vi.mocked(readFileSync).mockReturnValue(bd);
      vi.mocked(createHash).mockReturnValue({
        update: vi.fn().mockReturnThis(),
        digest: vi.fn().mockReturnValue("oldhash"),
      } as unknown as ReturnType<typeof createHash>);
      vi.mocked(executeCommand)
        .mockResolvedValueOnce(cr({ stdout: "net.ipv4.ip_forward = 1\n" }))
        .mockResolvedValueOnce(cr({ stdout: "ssh.service loaded active running\n" }));
      const p = JSON.parse((await handler({ action: "baseline_compare", name: "test" })).content[0].text);
      expect(p.sysctlChanges.length).toBe(1);
      expect(p.sysctlChanges[0].current).toBe("1");
    });

    it("detects service drift", async () => {
      vi.mocked(readFileSync).mockReturnValue(bd);
      vi.mocked(createHash).mockReturnValue({
        update: vi.fn().mockReturnThis(),
        digest: vi.fn().mockReturnValue("oldhash"),
      } as unknown as ReturnType<typeof createHash>);
      vi.mocked(executeCommand)
        .mockResolvedValueOnce(cr({ stdout: "net.ipv4.ip_forward = 0\n" }))
        .mockResolvedValueOnce(cr({ stdout: "ssh.service loaded inactive stopped\n" }));
      const p = JSON.parse((await handler({ action: "baseline_compare", name: "test" })).content[0].text);
      expect(p.serviceChanges.length).toBe(1);
      expect(p.serviceChanges[0].current).toBe("inactive");
    });

    it("errors when baseline not found", async () => {
      vi.mocked(existsSync).mockReturnValue(false);
      const r = await handler({ action: "baseline_compare", name: "missing" });
      expect(r.isError).toBe(true);
      expect(r.content[0].text).toContain("not found");
    });

    it("handles errors", async () => {
      vi.mocked(readFileSync).mockImplementation(() => { throw new Error("read error"); });
      vi.mocked(existsSync).mockReturnValue(true);
      const r = await handler({ action: "baseline_compare", name: "test" });
      expect(r.isError).toBe(true);
      expect(r.content[0].text).toContain("Baseline comparison failed");
    });
  });

  // ── baseline_list ───────────────────────────────────────────────────────
  describe("baseline_list", () => {
    it("lists empty baselines", async () => {
      vi.mocked(readdirSync).mockReturnValue([] as unknown as ReturnType<typeof readdirSync>);
      const p = JSON.parse((await handler({ action: "baseline_list" })).content[0].text);
      expect(p.totalBaselines).toBe(0);
      expect(p.baselines).toEqual([]);
    });

    it("lists baselines with metadata", async () => {
      vi.mocked(readdirSync).mockReturnValue(["test.json"] as unknown as ReturnType<typeof readdirSync>);
      vi.mocked(readFileSync).mockReturnValue(JSON.stringify({
        id: "test", timestamp: "2025-01-01T00:00:00Z", directories: ["/etc"],
        files: [{ path: "/etc/f", hash: "h", size: 1, mtime: "2025-01-01" }],
        sysctlState: { k: "v" }, services: { s: "r" },
      }));
      const p = JSON.parse((await handler({ action: "baseline_list" })).content[0].text);
      expect(p.totalBaselines).toBe(1);
      expect(p.baselines[0].name).toBe("test");
      expect(p.baselines[0].filesTracked).toBe(1);
    });

    it("filters out manifest.json", async () => {
      vi.mocked(readdirSync).mockReturnValue(
        ["manifest.json", "real.json"] as unknown as ReturnType<typeof readdirSync>
      );
      vi.mocked(readFileSync).mockReturnValue(JSON.stringify({
        id: "real", timestamp: "2025-01-01", directories: [],
        files: [], sysctlState: {}, services: {},
      }));
      const p = JSON.parse((await handler({ action: "baseline_list" })).content[0].text);
      expect(p.totalBaselines).toBe(1);
    });

    it("handles unreadable baseline files gracefully", async () => {
      vi.mocked(readdirSync).mockReturnValue(["bad.json"] as unknown as ReturnType<typeof readdirSync>);
      vi.mocked(readFileSync).mockImplementation(() => { throw new Error("corrupt"); });
      const p = JSON.parse((await handler({ action: "baseline_list" })).content[0].text);
      expect(p.totalBaselines).toBe(1);
      expect(p.baselines[0].timestamp).toBe("unknown");
    });

    it("handles errors", async () => {
      vi.mocked(readdirSync).mockImplementation(() => { throw new Error("fs error"); });
      const r = await handler({ action: "baseline_list" });
      expect(r.isError).toBe(true);
      expect(r.content[0].text).toContain("Drift listing failed");
    });
  });

  // ── Unknown action ──────────────────────────────────────────────────────
  it("returns error for unknown action", async () => {
    const r = await handler({ action: "unknown_action" });
    expect(r.isError).toBe(true);
    expect(r.content[0].text).toContain("Unknown action");
  });
});
