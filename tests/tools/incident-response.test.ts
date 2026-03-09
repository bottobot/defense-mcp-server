/**
 * Tests for src/tools/incident-response.ts
 *
 * Covers: TOOL-001 (parameterized commands),
 * step structure is { command, args } not shell strings,
 * and schema validation.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Mock all external dependencies ─────────────────────────────────────────

const { mockExecuteCommand } = vi.hoisted(() => ({
  mockExecuteCommand: vi.fn().mockResolvedValue({ exitCode: 0, stdout: "", stderr: "" }),
}));

const { mockSpawnSafe, mockSecureWrite, mockExistsSync, mockReadFileSync } = vi.hoisted(() => ({
  mockSpawnSafe: vi.fn(),
  mockSecureWrite: vi.fn(),
  mockExistsSync: vi.fn().mockReturnValue(false),
  mockReadFileSync: vi.fn().mockReturnValue("[]"),
}));

vi.mock("../../src/core/executor.js", () => ({
  executeCommand: mockExecuteCommand,
}));
vi.mock("../../src/core/config.js", () => ({
  getConfig: vi.fn().mockReturnValue({ dryRun: true }),
}));
vi.mock("../../src/core/parsers.js", () => ({
  createTextContent: vi.fn((text: string) => ({ type: "text", text })),
  createErrorContent: vi.fn((text: string) => ({ type: "text", text: `Error: ${text}` })),
}));
vi.mock("../../src/core/spawn-safe.js", () => ({
  spawnSafe: mockSpawnSafe,
}));
vi.mock("../../src/core/secure-fs.js", () => ({
  secureWriteFileSync: mockSecureWrite,
}));
vi.mock("node:fs", () => ({
  existsSync: mockExistsSync,
  readFileSync: mockReadFileSync,
}));

import { registerIncidentResponseTools } from "../../src/tools/incident-response.js";
import { EventEmitter } from "node:events";

// ── Helper ─────────────────────────────────────────────────────────────────

type ToolHandler = (params: Record<string, unknown>) => Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }>;

function createMockServer() {
  const tools = new Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>();
  const server = {
    tool: vi.fn((name: string, _desc: string, schema: Record<string, unknown>, handler: ToolHandler) => {
      tools.set(name, { schema, handler });
    }),
  };
  return { server: server as unknown as Parameters<typeof registerIncidentResponseTools>[0], tools };
}

/**
 * Create a mock ChildProcess that emits stdout/stderr data and a close event.
 * Used to mock spawnSafe return values for runForensicCommand.
 */
function createMockProcess(stdout: string, stderr: string, exitCode: number) {
  const proc = new EventEmitter() as EventEmitter & {
    stdout: EventEmitter;
    stderr: EventEmitter;
    kill: ReturnType<typeof vi.fn>;
  };
  proc.stdout = new EventEmitter();
  proc.stderr = new EventEmitter();
  proc.kill = vi.fn();

  process.nextTick(() => {
    if (stdout) proc.stdout.emit("data", Buffer.from(stdout));
    if (stderr) proc.stderr.emit("data", Buffer.from(stderr));
    proc.emit("close", exitCode);
  });

  return proc;
}

describe("incident-response tools", () => {
  let tools: Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>;

  beforeEach(() => {
    vi.clearAllMocks();
    const mock = createMockServer();
    registerIncidentResponseTools(mock.server);
    tools = mock.tools;
  });

  // ── Registration ──────────────────────────────────────────────────────

  it("should register the incident_response tool", () => {
    expect(tools.has("incident_response")).toBe(true);
  });

  // ── TOOL-001: Parameterized commands ─────────────────────────────────

  it("should use parameterized commands for collection steps (TOOL-001)", async () => {
    const handler = tools.get("incident_response")!.handler;
    await handler({
      action: "collect",
      output_dir: "/tmp/ir-collection",
      dry_run: false,
    });

    // executeCommand should have been called with { command, args } pattern
    // not with shell strings like "ps auxwww > file"
    const calls = mockExecuteCommand.mock.calls;
    // First call is mkdir -p, then collection steps follow
    expect(calls.length).toBeGreaterThan(1);

    // Check that collection steps use command + args pattern
    for (const call of calls) {
      const opts = call[0];
      expect(typeof opts.command).toBe("string");
      expect(Array.isArray(opts.args)).toBe(true);
      // Verify no shell string injection — command should be a single binary name
      expect(opts.command).not.toContain(" ");
      expect(opts.command).not.toContain(";");
      expect(opts.command).not.toContain("|");
    }
  });

  it("should use { command, args } structure not shell strings (TOOL-001)", async () => {
    const handler = tools.get("incident_response")!.handler;
    await handler({
      action: "collect",
      output_dir: "/tmp/ir-test",
      dry_run: false,
    });

    // Verify that steps like "ps auxwww" are passed as { command: "ps", args: ["auxwww"] }
    const psCall = mockExecuteCommand.mock.calls.find(
      (call) => call[0].command === "ps"
    );
    expect(psCall).toBeDefined();
    expect(psCall![0].args).toContain("auxwww");
  });

  // ── Dry-run mode ─────────────────────────────────────────────────────

  it("should produce dry-run output for collect action", async () => {
    const handler = tools.get("incident_response")!.handler;
    const result = await handler({
      action: "collect",
      output_dir: "/tmp/ir-collection",
      dry_run: true,
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("DRY-RUN");
    expect(result.content[0].text).toContain("Volatile Data Collection Plan");
  });

  it("should list all collection steps in dry-run output", async () => {
    const handler = tools.get("incident_response")!.handler;
    const result = await handler({
      action: "collect",
      output_dir: "/tmp/ir-collection",
      dry_run: true,
    });
    // Should list processes, network connections, etc.
    expect(result.content[0].text).toContain("processes");
    expect(result.content[0].text).toContain("Network connections");
  });

  // ── IOC scan ─────────────────────────────────────────────────────────

  it("should run IOC scan without errors", async () => {
    const handler = tools.get("incident_response")!.handler;
    const result = await handler({
      action: "ioc_scan",
      check_type: "all",
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("IOC");
  });

  // ── Timeline ─────────────────────────────────────────────────────────

  it("should run timeline without errors", async () => {
    const handler = tools.get("incident_response")!.handler;
    const result = await handler({
      action: "timeline",
      path: "/",
      hours: 24,
      exclude_paths: "/proc,/sys,/dev,/run",
      file_types: "all",
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("Timeline");
  });

  // ══════════════════════════════════════════════════════════════════════════
  // ir_forensics tool tests
  // ══════════════════════════════════════════════════════════════════════════

  describe("ir_forensics tool", () => {

    it("should register the ir_forensics tool", () => {
      expect(tools.has("ir_forensics")).toBe(true);
    });

    function getHandler() {
      return tools.get("ir_forensics")!.handler;
    }

    // ── memory_dump ──────────────────────────────────────────────────────

    describe("memory_dump", () => {
      it("should succeed with avml", async () => {
        mockSpawnSafe
          .mockImplementationOnce(() => createMockProcess("", "", 0))  // mkdir
          .mockImplementationOnce(() => createMockProcess("", "", 0))  // avml
          .mockImplementationOnce(() => createMockProcess("abc123def456  /tmp/forensics/memory-dump.raw\n", "", 0))  // sha256sum
          .mockImplementationOnce(() => createMockProcess("1048576\n", "", 0));  // stat

        const result = await getHandler()({
          action: "memory_dump",
          output_dir: "/tmp/forensics",
        });

        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("Memory Dump Acquisition");
        expect(result.content[0].text).toContain("avml");
        expect(result.content[0].text).toContain("abc123def456");
        expect(result.content[0].text).toContain("1048576");
      });

      it("should fall back to dd when avml fails", async () => {
        mockSpawnSafe
          .mockImplementationOnce(() => createMockProcess("", "", 0))  // mkdir
          .mockImplementationOnce(() => createMockProcess("", "avml not found", 1))  // avml fails
          .mockImplementationOnce(() => createMockProcess("", "", 0))  // dd fallback
          .mockImplementationOnce(() => createMockProcess("fallbackhash  /path\n", "", 0))  // sha256sum
          .mockImplementationOnce(() => createMockProcess("2097152\n", "", 0));  // stat

        const result = await getHandler()({
          action: "memory_dump",
          output_dir: "/tmp/forensics",
        });

        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("dd (fallback");
        expect(result.content[0].text).toContain("fallbackhash");
      });

      it("should calculate SHA-256 hash of the dump", async () => {
        mockSpawnSafe
          .mockImplementationOnce(() => createMockProcess("", "", 0))  // mkdir
          .mockImplementationOnce(() => createMockProcess("", "", 0))  // avml
          .mockImplementationOnce(() => createMockProcess("sha256hashvalue  /path\n", "", 0))  // sha256sum
          .mockImplementationOnce(() => createMockProcess("4096\n", "", 0));  // stat

        const result = await getHandler()({
          action: "memory_dump",
          output_dir: "/tmp/forensics",
        });

        expect(result.content[0].text).toContain("SHA-256: sha256hashvalue");
      });

      it("should create the output directory", async () => {
        mockSpawnSafe
          .mockImplementationOnce(() => createMockProcess("", "", 0))  // mkdir
          .mockImplementationOnce(() => createMockProcess("", "", 0))  // avml
          .mockImplementationOnce(() => createMockProcess("hash  /path\n", "", 0))  // sha256sum
          .mockImplementationOnce(() => createMockProcess("1024\n", "", 0));  // stat

        await getHandler()({
          action: "memory_dump",
          output_dir: "/tmp/custom-dir",
        });

        expect(mockSpawnSafe).toHaveBeenCalledWith("mkdir", ["-p", "/tmp/custom-dir"]);
      });
    });

    // ── disk_image ───────────────────────────────────────────────────────

    describe("disk_image", () => {
      it("should create a forensic disk image successfully", async () => {
        mockSpawnSafe
          .mockImplementationOnce(() => createMockProcess("", "", 0))  // mkdir
          .mockImplementationOnce(() => createMockProcess("", "", 0))  // dd
          .mockImplementationOnce(() => createMockProcess("diskhash  /path\n", "", 0))  // sha256sum
          .mockImplementationOnce(() => createMockProcess("10485760\n", "", 0))  // stat
          .mockImplementationOnce(() => createMockProcess("Disk /dev/sda1: 10 GiB\n", "", 0));  // fdisk

        const result = await getHandler()({
          action: "disk_image",
          output_dir: "/tmp/forensics",
          device: "/dev/sda1",
        });

        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("Forensic Disk Image");
        expect(result.content[0].text).toContain("/dev/sda1");
        expect(result.content[0].text).toContain("diskhash");
        expect(result.content[0].text).toContain("10485760");
      });

      it("should capture partition info via fdisk", async () => {
        mockSpawnSafe
          .mockImplementationOnce(() => createMockProcess("", "", 0))  // mkdir
          .mockImplementationOnce(() => createMockProcess("", "", 0))  // dd
          .mockImplementationOnce(() => createMockProcess("h  /p\n", "", 0))  // sha256sum
          .mockImplementationOnce(() => createMockProcess("100\n", "", 0))  // stat
          .mockImplementationOnce(() => createMockProcess("Device Boot Start End Sectors\n", "", 0));  // fdisk

        const result = await getHandler()({
          action: "disk_image",
          output_dir: "/tmp/forensics",
          device: "/dev/sda1",
        });

        expect(result.content[0].text).toContain("Partition Info");
        expect(result.content[0].text).toContain("Device Boot Start End Sectors");
      });

      it("should reject non-/dev/ device paths", async () => {
        const result = await getHandler()({
          action: "disk_image",
          output_dir: "/tmp/forensics",
          device: "/tmp/fake-device",
        });

        expect(result.isError).toBe(true);
        expect(result.content[0].text).toContain("Invalid device path");
        expect(result.content[0].text).toContain("Must start with /dev/");
      });

      it("should reject root device imaging", async () => {
        const result = await getHandler()({
          action: "disk_image",
          output_dir: "/tmp/forensics",
          device: "/dev/sda",
        });

        expect(result.isError).toBe(true);
        expect(result.content[0].text).toContain("Refusing to image root device");
      });

      it("should require device parameter", async () => {
        const result = await getHandler()({
          action: "disk_image",
          output_dir: "/tmp/forensics",
        });

        expect(result.isError).toBe(true);
        expect(result.content[0].text).toContain("device parameter is required");
      });

      it("should handle dd failure", async () => {
        mockSpawnSafe
          .mockImplementationOnce(() => createMockProcess("", "", 0))  // mkdir
          .mockImplementationOnce(() => createMockProcess("", "Permission denied", 1));  // dd fails

        const result = await getHandler()({
          action: "disk_image",
          output_dir: "/tmp/forensics",
          device: "/dev/sda1",
        });

        expect(result.isError).toBe(true);
        expect(result.content[0].text).toContain("Disk imaging failed");
      });
    });

    // ── network_capture_forensic ─────────────────────────────────────────

    describe("network_capture_forensic", () => {
      it("should perform a forensic network capture successfully", async () => {
        mockSpawnSafe
          .mockImplementationOnce(() => createMockProcess("", "", 0))  // mkdir
          .mockImplementationOnce(() => createMockProcess("", "", 0))  // tcpdump capture
          .mockImplementationOnce(() => createMockProcess("capturehash  /path\n", "", 0))  // sha256sum
          .mockImplementationOnce(() => createMockProcess("51200\n", "", 0))  // stat
          .mockImplementationOnce(() => createMockProcess("", "42 packets captured\n", 0));  // tcpdump count

        const result = await getHandler()({
          action: "network_capture_forensic",
          output_dir: "/tmp/forensics",
          interface: "eth0",
          duration: 30,
        });

        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("Forensic Network Capture");
        expect(result.content[0].text).toContain("eth0");
        expect(result.content[0].text).toContain("capturehash");
        expect(result.content[0].text).toContain("51200");
        expect(result.content[0].text).toContain("42");
      });

      it("should cap duration at 300 seconds", async () => {
        mockSpawnSafe
          .mockImplementationOnce(() => createMockProcess("", "", 0))  // mkdir
          .mockImplementationOnce(() => createMockProcess("", "", 0))  // tcpdump
          .mockImplementationOnce(() => createMockProcess("h  /p\n", "", 0))  // sha256sum
          .mockImplementationOnce(() => createMockProcess("100\n", "", 0))  // stat
          .mockImplementationOnce(() => createMockProcess("", "10 packets\n", 0));  // count

        const result = await getHandler()({
          action: "network_capture_forensic",
          output_dir: "/tmp/forensics",
          duration: 500,
        });

        expect(result.content[0].text).toContain("Duration: 300s");
        // Verify tcpdump was called with -G 300
        const tcpdumpCall = mockSpawnSafe.mock.calls.find(
          (call: unknown[]) => call[0] === "tcpdump" && (call[1] as string[]).includes("-w"),
        );
        expect(tcpdumpCall).toBeDefined();
        expect(tcpdumpCall![1]).toContain("300");
      });

      it("should use specified interface parameter", async () => {
        mockSpawnSafe
          .mockImplementationOnce(() => createMockProcess("", "", 0))  // mkdir
          .mockImplementationOnce(() => createMockProcess("", "", 0))  // tcpdump
          .mockImplementationOnce(() => createMockProcess("h  /p\n", "", 0))  // sha256sum
          .mockImplementationOnce(() => createMockProcess("100\n", "", 0))  // stat
          .mockImplementationOnce(() => createMockProcess("", "5 packets\n", 0));  // count

        await getHandler()({
          action: "network_capture_forensic",
          output_dir: "/tmp/forensics",
          interface: "wlan0",
          duration: 10,
        });

        const tcpdumpCall = mockSpawnSafe.mock.calls.find(
          (call: unknown[]) => call[0] === "tcpdump" && (call[1] as string[]).includes("-w"),
        );
        expect(tcpdumpCall).toBeDefined();
        expect(tcpdumpCall![1]).toContain("wlan0");
      });

      it("should calculate hash of capture file", async () => {
        mockSpawnSafe
          .mockImplementationOnce(() => createMockProcess("", "", 0))  // mkdir
          .mockImplementationOnce(() => createMockProcess("", "", 0))  // tcpdump
          .mockImplementationOnce(() => createMockProcess("nethash123  /path\n", "", 0))  // sha256sum
          .mockImplementationOnce(() => createMockProcess("2048\n", "", 0))  // stat
          .mockImplementationOnce(() => createMockProcess("", "1 packets\n", 0));  // count

        const result = await getHandler()({
          action: "network_capture_forensic",
          output_dir: "/tmp/forensics",
          duration: 10,
        });

        expect(result.content[0].text).toContain("SHA-256: nethash123");
      });
    });

    // ── evidence_bag ─────────────────────────────────────────────────────

    describe("evidence_bag", () => {
      it("should bag evidence successfully", async () => {
        mockSpawnSafe
          .mockImplementationOnce(() => createMockProcess("", "", 0))  // mkdir
          .mockImplementationOnce(() => createMockProcess("", "", 0))  // cp
          .mockImplementationOnce(() => createMockProcess("evidencehash  /path\n", "", 0))  // sha256sum
          .mockImplementationOnce(() => createMockProcess("4096\n", "", 0));  // stat

        const result = await getHandler()({
          action: "evidence_bag",
          output_dir: "/tmp/forensics",
          case_id: "CASE-001",
          evidence_path: "/var/log/suspicious.log",
          description: "Suspicious log file",
          examiner: "John Doe",
        });

        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("Evidence Bagged");
        expect(result.content[0].text).toContain("evidencehash");
        expect(result.content[0].text).toContain("CASE-001");
        expect(result.content[0].text).toContain("John Doe");
      });

      it("should create metadata sidecar file", async () => {
        mockSpawnSafe
          .mockImplementationOnce(() => createMockProcess("", "", 0))  // mkdir
          .mockImplementationOnce(() => createMockProcess("", "", 0))  // cp
          .mockImplementationOnce(() => createMockProcess("metahash  /path\n", "", 0))  // sha256sum
          .mockImplementationOnce(() => createMockProcess("2048\n", "", 0));  // stat

        await getHandler()({
          action: "evidence_bag",
          output_dir: "/tmp/forensics",
          case_id: "CASE-002",
          evidence_path: "/tmp/artifact.bin",
          description: "Test artifact",
          examiner: "Jane",
        });

        // Verify secureWriteFileSync was called with metadata JSON
        expect(mockSecureWrite).toHaveBeenCalledTimes(1);
        const writeCall = mockSecureWrite.mock.calls[0];
        expect(writeCall[0]).toContain(".metadata.json");
        const metadata = JSON.parse(writeCall[1]);
        expect(metadata.original_path).toBe("/tmp/artifact.bin");
        expect(metadata.case_id).toBe("CASE-002");
        expect(metadata.examiner).toBe("Jane");
        expect(metadata.hash).toBe("metahash");
      });

      it("should require evidence_path parameter", async () => {
        const result = await getHandler()({
          action: "evidence_bag",
          output_dir: "/tmp/forensics",
        });

        expect(result.isError).toBe(true);
        expect(result.content[0].text).toContain("evidence_path parameter is required");
      });

      it("should calculate hash of bagged evidence", async () => {
        mockSpawnSafe
          .mockImplementationOnce(() => createMockProcess("", "", 0))  // mkdir
          .mockImplementationOnce(() => createMockProcess("", "", 0))  // cp
          .mockImplementationOnce(() => createMockProcess("baghash999  /path\n", "", 0))  // sha256sum
          .mockImplementationOnce(() => createMockProcess("8192\n", "", 0));  // stat

        const result = await getHandler()({
          action: "evidence_bag",
          output_dir: "/tmp/forensics",
          evidence_path: "/tmp/file.txt",
        });

        expect(result.content[0].text).toContain("SHA-256: baghash999");
      });
    });

    // ── chain_of_custody ─────────────────────────────────────────────────

    describe("chain_of_custody", () => {
      it("should add a new custody entry", async () => {
        mockExistsSync.mockReturnValue(false);
        mockSpawnSafe
          .mockImplementationOnce(() => createMockProcess("", "", 0))  // mkdir
          .mockImplementationOnce(() => createMockProcess("custodyhash  /path\n", "", 0));  // sha256sum

        const result = await getHandler()({
          action: "chain_of_custody",
          output_dir: "/tmp/forensics",
          case_id: "CASE-100",
          custody_action: "add",
          evidence_path: "/tmp/evidence.bin",
          description: "Collected from server",
          examiner: "Detective Smith",
        });

        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("Entry Added");
        expect(result.content[0].text).toContain("CASE-100");
        expect(result.content[0].text).toContain("Detective Smith");
        expect(result.content[0].text).toContain("custodyhash");

        // Verify secureWriteFileSync was called to write the log
        expect(mockSecureWrite).toHaveBeenCalledTimes(1);
        const logContent = JSON.parse(mockSecureWrite.mock.calls[0][1]);
        expect(logContent).toHaveLength(1);
        expect(logContent[0].examiner).toBe("Detective Smith");
      });

      it("should view the custody log", async () => {
        const existingLog = [
          {
            timestamp: "2025-01-01T00:00:00.000Z",
            action: "collected",
            examiner: "Agent X",
            description: "Initial collection",
            evidence_hash: "abc123",
            evidence_path: "/tmp/file.bin",
          },
        ];
        mockExistsSync.mockReturnValue(true);
        mockReadFileSync.mockReturnValue(JSON.stringify(existingLog));
        mockSpawnSafe
          .mockImplementationOnce(() => createMockProcess("", "", 0));  // mkdir

        const result = await getHandler()({
          action: "chain_of_custody",
          output_dir: "/tmp/forensics",
          case_id: "CASE-200",
          custody_action: "view",
        });

        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("CASE-200");
        expect(result.content[0].text).toContain("Agent X");
        expect(result.content[0].text).toContain("abc123");
        expect(result.content[0].text).toContain("Total Entries: 1");
      });

      it("should verify hash match", async () => {
        const existingLog = [
          {
            timestamp: "2025-01-01T00:00:00.000Z",
            action: "collected",
            examiner: "Agent Y",
            description: "Test evidence",
            evidence_hash: "matchinghash",
            evidence_path: "/tmp/evidence.dat",
          },
        ];
        mockExistsSync.mockReturnValue(true);
        mockReadFileSync.mockReturnValue(JSON.stringify(existingLog));
        mockSpawnSafe
          .mockImplementationOnce(() => createMockProcess("", "", 0))  // mkdir
          .mockImplementationOnce(() => createMockProcess("matchinghash  /tmp/evidence.dat\n", "", 0));  // sha256sum

        const result = await getHandler()({
          action: "chain_of_custody",
          output_dir: "/tmp/forensics",
          case_id: "CASE-300",
          custody_action: "verify",
          evidence_path: "/tmp/evidence.dat",
        });

        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("VERIFIED");
        expect(result.content[0].text).toContain("matchinghash");
      });

      it("should detect hash mismatch", async () => {
        const existingLog = [
          {
            timestamp: "2025-01-01T00:00:00.000Z",
            action: "collected",
            examiner: "Agent Z",
            description: "Test evidence",
            evidence_hash: "originalhash",
            evidence_path: "/tmp/tampered.dat",
          },
        ];
        mockExistsSync.mockReturnValue(true);
        mockReadFileSync.mockReturnValue(JSON.stringify(existingLog));
        mockSpawnSafe
          .mockImplementationOnce(() => createMockProcess("", "", 0))  // mkdir
          .mockImplementationOnce(() => createMockProcess("differenthash  /tmp/tampered.dat\n", "", 0));  // sha256sum

        const result = await getHandler()({
          action: "chain_of_custody",
          output_dir: "/tmp/forensics",
          case_id: "CASE-400",
          custody_action: "verify",
          evidence_path: "/tmp/tampered.dat",
        });

        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("MISMATCH");
        expect(result.content[0].text).toContain("tampered");
      });

      it("should require case_id parameter", async () => {
        const result = await getHandler()({
          action: "chain_of_custody",
          output_dir: "/tmp/forensics",
          custody_action: "view",
        });

        expect(result.isError).toBe(true);
        expect(result.content[0].text).toContain("case_id parameter is required");
      });

      it("should handle empty log on view", async () => {
        mockExistsSync.mockReturnValue(false);
        mockSpawnSafe
          .mockImplementationOnce(() => createMockProcess("", "", 0));  // mkdir

        const result = await getHandler()({
          action: "chain_of_custody",
          output_dir: "/tmp/forensics",
          case_id: "CASE-EMPTY",
          custody_action: "view",
        });

        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("No custody log found");
      });
    });

    // ── Error handling ───────────────────────────────────────────────────

    describe("error handling", () => {
      it("should handle command failures gracefully", async () => {
        mockSpawnSafe
          .mockImplementationOnce(() => createMockProcess("", "No space left on device", 1));  // mkdir fails

        const result = await getHandler()({
          action: "memory_dump",
          output_dir: "/tmp/forensics",
        });

        expect(result.isError).toBe(true);
        expect(result.content[0].text).toContain("Failed to create output directory");
      });

      it("should handle missing tools via spawnSafe error", async () => {
        mockSpawnSafe.mockImplementation(() => {
          throw new Error("Command not in allowlist: avml");
        });

        const result = await getHandler()({
          action: "memory_dump",
          output_dir: "/tmp/forensics",
        });

        expect(result.isError).toBe(true);
      });
    });
  });
});
