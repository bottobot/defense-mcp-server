/**
 * Tests for src/tools/hardening.ts
 *
 * Covers: TOOL-007 (path traversal validation),
 * validatePathWithinAllowed with valid and malicious paths,
 * and rejection of .. sequences.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Mock all external dependencies ─────────────────────────────────────────

vi.mock("../../src/core/executor.js", () => ({
  executeCommand: vi.fn().mockResolvedValue({ exitCode: 0, stdout: "644 root root /etc/passwd", stderr: "" }),
}));
vi.mock("../../src/core/config.js", () => ({
  getConfig: vi.fn().mockReturnValue({ dryRun: true }),
  getToolTimeout: vi.fn().mockReturnValue(30000),
}));
vi.mock("../../src/core/parsers.js", () => ({
  createTextContent: vi.fn((text: string) => ({ type: "text", text })),
  createErrorContent: vi.fn((text: string) => ({ type: "text", text: `Error: ${text}` })),
  parseSysctlOutput: vi.fn().mockReturnValue([]),
  parseSystemctlOutput: vi.fn().mockReturnValue([]),
  formatToolOutput: vi.fn((obj: unknown) => ({ type: "text", text: JSON.stringify(obj) })),
}));
vi.mock("../../src/core/changelog.js", () => ({
  logChange: vi.fn(),
  createChangeEntry: vi.fn().mockReturnValue({}),
  backupFile: vi.fn().mockReturnValue("/tmp/backup"),
}));
vi.mock("../../src/core/sanitizer.js", () => ({
  validateServiceName: vi.fn((s: string) => s),
  validateFilePath: vi.fn((p: string) => p),
  sanitizeArgs: vi.fn((a: string[]) => a),
  validateSysctlKey: vi.fn((k: string) => k),
}));
vi.mock("../../src/core/safeguards.js", () => ({
  SafeguardRegistry: {
    getInstance: vi.fn().mockReturnValue({
      checkSafety: vi.fn().mockResolvedValue({ safe: true, warnings: [], blockers: [], impactedApps: [] }),
    }),
  },
}));
vi.mock("node:fs", () => ({
  readFileSync: vi.fn().mockReturnValue(""),
  existsSync: vi.fn().mockReturnValue(true),
}));
vi.mock("node:child_process", () => ({
  execSync: vi.fn(), // Make checkPrivileges() succeed (no throw = sudo available)
}));
vi.mock("../../src/core/spawn-safe.js", () => ({
  spawnSafe: vi.fn(),
}));
vi.mock("../../src/core/secure-fs.js", () => ({
  secureWriteFileSync: vi.fn(),
}));

import { registerHardeningTools } from "../../src/tools/hardening.js";
import { spawnSafe } from "../../src/core/spawn-safe.js";
import { secureWriteFileSync } from "../../src/core/secure-fs.js";
import { existsSync, readFileSync } from "node:fs";
import { EventEmitter } from "node:events";

const mockSpawnSafe = vi.mocked(spawnSafe);
const mockSecureWriteFileSync = vi.mocked(secureWriteFileSync);
const mockExistsSync = vi.mocked(existsSync);
const mockReadFileSync = vi.mocked(readFileSync);

// ── Helper ─────────────────────────────────────────────────────────────────

type ToolHandler = (params: Record<string, unknown>) => Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }>;

function createMockServer() {
  const tools = new Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>();
  const server = {
    tool: vi.fn((name: string, _desc: string, schema: Record<string, unknown>, handler: ToolHandler) => {
      tools.set(name, { schema, handler });
    }),
  };
  return { server: server as unknown as Parameters<typeof registerHardeningTools>[0], tools };
}

/**
 * Create a mock ChildProcess that emits provided stdout/stderr and close code.
 */
function createMockChildProcess(
  stdout: string,
  stderr: string,
  exitCode: number,
) {
  const cp = new EventEmitter() as EventEmitter & {
    stdout: EventEmitter;
    stderr: EventEmitter;
    kill: ReturnType<typeof vi.fn>;
  };
  cp.stdout = new EventEmitter();
  cp.stderr = new EventEmitter();
  cp.kill = vi.fn();

  // Emit data on next tick so listeners can be set up
  process.nextTick(() => {
    if (stdout) cp.stdout.emit("data", Buffer.from(stdout));
    if (stderr) cp.stderr.emit("data", Buffer.from(stderr));
    cp.emit("close", exitCode);
  });

  return cp;
}

/**
 * Helper to set up spawnSafe mock to return specific results for different commands.
 */
function setupSpawnMock(commandMap: Record<string, { stdout: string; stderr: string; exitCode: number }>) {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    const key = `${command} ${args.join(" ")}`.trim();
    // Find matching command entry — check prefix matches for flexibility
    for (const [pattern, result] of Object.entries(commandMap)) {
      if (key === pattern || key.startsWith(pattern) || command === pattern) {
        return createMockChildProcess(result.stdout, result.stderr, result.exitCode) as any;
      }
    }
    // Default: command not found
    return createMockChildProcess("", "command not found", -1) as any;
  });
}

describe("hardening tools", () => {
  let tools: Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>;

  beforeEach(() => {
    vi.clearAllMocks();
    const mock = createMockServer();
    registerHardeningTools(mock.server);
    tools = mock.tools;
  });

  // ── Registration ──────────────────────────────────────────────────────

  it("should register hardening tools", () => {
    expect(tools.has("harden_kernel")).toBe(true);
    expect(tools.has("harden_host")).toBe(true);
    expect(tools.size).toBe(2);
  });

  // ── TOOL-007: Path traversal validation ──────────────────────────────

  it("should reject path containing .. sequences (TOOL-007)", async () => {
    const handler = tools.get("harden_host")!.handler;
    const result = await handler({
      action: "permissions_check",
      path: "/etc/../root/.ssh/authorized_keys",
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Path traversal");
  });

  it("should reject path with encoded .. traversal (TOOL-007)", async () => {
    const handler = tools.get("harden_host")!.handler;
    const result = await handler({
      action: "permissions_fix",
      path: "/tmp/../../etc/shadow",
      mode: "600",
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Path traversal");
  });

  it("should reject path outside allowed directories (TOOL-007)", async () => {
    const handler = tools.get("harden_host")!.handler;
    const result = await handler({
      action: "permissions_check",
      path: "/proc/self/environ",
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("outside allowed directories");
  });

  it("should accept path within /etc (TOOL-007)", async () => {
    const handler = tools.get("harden_host")!.handler;
    const result = await handler({
      action: "permissions_check",
      path: "/etc/ssh/sshd_config",
    });
    expect(result.isError).toBeUndefined();
  });

  it("should accept path within /var (TOOL-007)", async () => {
    const handler = tools.get("harden_host")!.handler;
    const result = await handler({
      action: "permissions_check",
      path: "/var/log/auth.log",
    });
    expect(result.isError).toBeUndefined();
  });

  // ── Required params ──────────────────────────────────────────────────

  it("should require path for permissions_check action", async () => {
    const handler = tools.get("harden_host")!.handler;
    const result = await handler({ action: "permissions_check" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("path");
  });

  it("should require path for permissions_fix action", async () => {
    const handler = tools.get("harden_host")!.handler;
    const result = await handler({ action: "permissions_fix" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("path");
  });

  it("should require mode/owner/group for permissions_fix action", async () => {
    const handler = tools.get("harden_host")!.handler;
    const result = await handler({
      action: "permissions_fix",
      path: "/etc/passwd",
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("mode");
  });

  // ── harden_kernel (sysctl) tests ─────────────────────────────────────

  describe("harden_kernel sysctl actions", () => {
    it("should handle sysctl_get with key", async () => {
      const handler = tools.get("harden_kernel")!.handler;
      const result = await handler({
        action: "sysctl_get",
        key: "net.ipv4.ip_forward",
      });
      expect(result.content).toBeDefined();
    });

    it("should handle sysctl_get all", async () => {
      const handler = tools.get("harden_kernel")!.handler;
      const result = await handler({
        action: "sysctl_get",
        all: true,
      });
      expect(result.content).toBeDefined();
    });

    it("should handle sysctl_get with pattern", async () => {
      const handler = tools.get("harden_kernel")!.handler;
      const result = await handler({
        action: "sysctl_get",
        pattern: "ipv4",
      });
      expect(result.content).toBeDefined();
    });

    it("should require key or all/pattern for sysctl_get", async () => {
      const handler = tools.get("harden_kernel")!.handler;
      const result = await handler({ action: "sysctl_get" });
      expect(result.isError).toBe(true);
    });

    it("should require key for sysctl_set action", async () => {
      const handler = tools.get("harden_kernel")!.handler;
      const result = await handler({ action: "sysctl_set", value: "0", dry_run: true });
      expect(result.isError).toBe(true);
    });

    it("should require value for sysctl_set action", async () => {
      const handler = tools.get("harden_kernel")!.handler;
      const result = await handler({ action: "sysctl_set", key: "net.ipv4.ip_forward", dry_run: true });
      expect(result.isError).toBe(true);
    });

    it("should handle sysctl_audit action", async () => {
      const handler = tools.get("harden_kernel")!.handler;
      const result = await handler({ action: "sysctl_audit", category: "all" });
      expect(result.content).toBeDefined();
    });
  });

  // ── harden_host (service) tests ──────────────────────────────────────

  describe("harden_host service actions", () => {
    it("should require service for service_manage action", async () => {
      const handler = tools.get("harden_host")!.handler;
      const result = await handler({ action: "service_manage", service_action: "status" });
      expect(result.isError).toBe(true);
    });

    it("should require service_action for service_manage action", async () => {
      const handler = tools.get("harden_host")!.handler;
      const result = await handler({ action: "service_manage", service: "ssh.service" });
      expect(result.isError).toBe(true);
    });

    it("should handle service_audit action", async () => {
      const handler = tools.get("harden_host")!.handler;
      const result = await handler({ action: "service_audit" });
      expect(result.content).toBeDefined();
    });
  });

  // ── harden_host (permissions) audit ─────────────────────────────────

  describe("harden_host permissions_audit", () => {
    it("should handle permissions_audit action with default scope", async () => {
      const handler = tools.get("harden_host")!.handler;
      const result = await handler({ action: "permissions_audit", scope: "all" });
      expect(result.content).toBeDefined();
    });

    it("should handle permissions_audit action with specific scope", async () => {
      const handler = tools.get("harden_host")!.handler;
      const result = await handler({ action: "permissions_audit", scope: "ssh" });
      expect(result.content).toBeDefined();
    });
  });

  // ── harden_kernel (kernel) tests ─────────────────────────────────────

  describe("harden_kernel kernel actions", () => {
    it("should handle kernel_audit action", async () => {
      const handler = tools.get("harden_kernel")!.handler;
      const result = await handler({ action: "kernel_audit", check_type: "all" });
      expect(result.content).toBeDefined();
    });

    it("should handle kernel_modules action", async () => {
      const handler = tools.get("harden_kernel")!.handler;
      const result = await handler({ action: "kernel_modules" });
      expect(result.content).toBeDefined();
    });

    it("should handle kernel_coredump action in dry_run", async () => {
      const handler = tools.get("harden_kernel")!.handler;
      const result = await handler({ action: "kernel_coredump", dry_run: true });
      expect(result.content).toBeDefined();
    });
  });

  // ── harden_kernel (bootloader) tests ────────────────────────────────

  describe("harden_kernel bootloader actions", () => {
    it("should handle bootloader_audit action", async () => {
      const handler = tools.get("harden_kernel")!.handler;
      const result = await handler({ action: "bootloader_audit" });
      expect(result.content).toBeDefined();
    });

    it("should require configure_action for bootloader_configure", async () => {
      const handler = tools.get("harden_kernel")!.handler;
      const result = await handler({ action: "bootloader_configure", dry_run: true });
      expect(result.isError).toBe(true);
    });
  });

  // ── harden_host (usb_device_control) tests ───────────────────────────

  describe("harden_host usb actions", () => {
    // ── Registration ────────────────────────────────────────────────

    it("should register harden_host tool (covers usb_device_control)", () => {
      expect(tools.has("harden_host")).toBe(true);
    });

    // ── usb_audit_devices ────────────────────────────────────────────

    describe("usb_audit_devices", () => {
      it("should list connected USB devices", async () => {
        setupSpawnMock({
          "lsusb": { stdout: "Bus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub\nBus 001 Device 002: ID 0781:5583 SanDisk Corp.", stderr: "", exitCode: 0 },
          "lsblk": { stdout: "NAME TRAN TYPE\nsda  usb  disk", stderr: "", exitCode: 0 },
          "lsmod": { stdout: "usb_storage  65536  1", stderr: "", exitCode: 0 },
          "ls": { stdout: "", stderr: "", exitCode: 0 },
          "systemctl": { stdout: "inactive", stderr: "", exitCode: 3 },
        });

        const handler = tools.get("harden_host")!.handler;
        const result = await handler({ action: "usb_audit_devices" });
        expect(result.content).toBeDefined();
        expect(result.isError).toBeUndefined();
      });

      it("should detect USB storage devices", async () => {
        setupSpawnMock({
          "lsusb": { stdout: "Bus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub", stderr: "", exitCode: 0 },
          "lsblk": { stdout: "NAME TRAN TYPE\nsda  usb  disk\nsdb  usb  disk", stderr: "", exitCode: 0 },
          "lsmod": { stdout: "usb_storage  65536  2", stderr: "", exitCode: 0 },
          "ls": { stdout: "", stderr: "", exitCode: 0 },
          "systemctl": { stdout: "", stderr: "", exitCode: 4 },
        });

        const handler = tools.get("harden_host")!.handler;
        const result = await handler({ action: "usb_audit_devices", output_format: "json" });
        expect(result.content).toBeDefined();
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.storageDeviceCount).toBe(2);
      });

      it("should report kernel module status", async () => {
        setupSpawnMock({
          "lsusb": { stdout: "Bus 001 Device 001: ID 1d6b:0002 Linux Foundation", stderr: "", exitCode: 0 },
          "lsblk": { stdout: "NAME TRAN TYPE", stderr: "", exitCode: 0 },
          "lsmod": { stdout: "some_other_module  65536  0", stderr: "", exitCode: 0 },
          "ls": { stdout: "", stderr: "", exitCode: 0 },
          "systemctl": { stdout: "", stderr: "", exitCode: 4 },
        });

        const handler = tools.get("harden_host")!.handler;
        const result = await handler({ action: "usb_audit_devices", output_format: "json" });
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.usbStorageModuleLoaded).toBe(false);
      });

      it("should check existing udev rules", async () => {
        setupSpawnMock({
          "lsusb": { stdout: "Bus 001 Device 001: ID 1d6b:0002", stderr: "", exitCode: 0 },
          "lsblk": { stdout: "NAME TRAN TYPE", stderr: "", exitCode: 0 },
          "lsmod": { stdout: "", stderr: "", exitCode: 0 },
          "ls": { stdout: "99-usb-storage-block.rules", stderr: "", exitCode: 0 },
          "cat": { stdout: 'ACTION=="add", SUBSYSTEMS=="usb"', stderr: "", exitCode: 0 },
          "systemctl": { stdout: "", stderr: "", exitCode: 4 },
        });

        const handler = tools.get("harden_host")!.handler;
        const result = await handler({ action: "usb_audit_devices", output_format: "json" });
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.existingUdevRules.length).toBeGreaterThan(0);
      });

      it("should check USBGuard status", async () => {
        setupSpawnMock({
          "lsusb": { stdout: "Bus 001 Device 001: ID 1d6b:0002", stderr: "", exitCode: 0 },
          "lsblk": { stdout: "NAME TRAN TYPE", stderr: "", exitCode: 0 },
          "lsmod": { stdout: "", stderr: "", exitCode: 0 },
          "ls": { stdout: "", stderr: "", exitCode: 0 },
          "systemctl": { stdout: "● usbguard.service - USBGuard\n   Active: active (running)", stderr: "", exitCode: 0 },
        });

        const handler = tools.get("harden_host")!.handler;
        const result = await handler({ action: "usb_audit_devices", output_format: "json" });
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.usbguardInstalled).toBe(true);
        expect(parsed.usbguardRunning).toBe(true);
      });

      it("should handle missing lsusb gracefully", async () => {
        setupSpawnMock({
          "lsusb": { stdout: "", stderr: "command not found", exitCode: -1 },
          "lsblk": { stdout: "NAME TRAN TYPE", stderr: "", exitCode: 0 },
          "lsmod": { stdout: "", stderr: "", exitCode: 0 },
          "ls": { stdout: "", stderr: "", exitCode: 0 },
          "systemctl": { stdout: "", stderr: "", exitCode: 4 },
        });

        const handler = tools.get("harden_host")!.handler;
        const result = await handler({ action: "usb_audit_devices", output_format: "json" });
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.lsusbAvailable).toBe(false);
        expect(parsed.lsusbNote).toContain("lsusb not found");
      });
    });

    // ── usb_block_storage ────────────────────────────────────────────

    describe("usb_block_storage", () => {
      it("should block storage via modprobe method", async () => {
        setupSpawnMock({
          "modprobe": { stdout: "", stderr: "", exitCode: 0 },
          "lsmod": { stdout: "some_other_module  65536  0", stderr: "", exitCode: 0 },
        });

        const handler = tools.get("harden_host")!.handler;
        const result = await handler({ action: "usb_block_storage", block_method: "modprobe", output_format: "json" });
        expect(result.content).toBeDefined();
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.method).toBe("modprobe");
        expect(parsed.cisBenchmark).toContain("CIS Benchmark 1.1.10");
        expect(mockSecureWriteFileSync).toHaveBeenCalled();
      });

      it("should block storage via udev method", async () => {
        setupSpawnMock({
          "udevadm": { stdout: "", stderr: "", exitCode: 0 },
        });

        const handler = tools.get("harden_host")!.handler;
        const result = await handler({ action: "usb_block_storage", block_method: "udev", output_format: "json" });
        expect(result.content).toBeDefined();
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.method).toBe("udev");
        expect(parsed.filesCreated).toContain("/etc/udev/rules.d/99-usb-storage-block.rules");
        expect(mockSecureWriteFileSync).toHaveBeenCalled();
      });

      it("should create modprobe config file", async () => {
        setupSpawnMock({
          "modprobe": { stdout: "", stderr: "", exitCode: 0 },
          "lsmod": { stdout: "", stderr: "", exitCode: 0 },
        });

        const handler = tools.get("harden_host")!.handler;
        await handler({ action: "usb_block_storage", block_method: "modprobe" });
        expect(mockSecureWriteFileSync).toHaveBeenCalledWith(
          "/etc/modprobe.d/usb-storage-block.conf",
          expect.stringContaining("blacklist usb-storage"),
        );
      });

      it("should attempt module removal after blacklisting", async () => {
        const calls: string[] = [];
        mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
          const key = `${command} ${args.join(" ")}`.trim();
          calls.push(key);
          if (command === "modprobe" && args[0] === "-r") {
            return createMockChildProcess("", "", 0) as any;
          }
          return createMockChildProcess("", "", 0) as any;
        });

        const handler = tools.get("harden_host")!.handler;
        await handler({ action: "usb_block_storage", block_method: "modprobe" });
        expect(calls.some((c) => c.includes("modprobe -r usb-storage"))).toBe(true);
      });
    });

    // ── usb_whitelist ────────────────────────────────────────────────

    describe("usb_whitelist", () => {
      it("should add a device to the whitelist", async () => {
        mockExistsSync.mockReturnValue(false);
        setupSpawnMock({
          "lsusb": { stdout: "Bus 001 Device 002: ID 0781:5583 SanDisk Corp. Ultra Fit", stderr: "", exitCode: 0 },
        });

        const handler = tools.get("harden_host")!.handler;
        const result = await handler({ action: "usb_whitelist", device_id: "0781:5583", output_format: "json" });
        expect(result.content).toBeDefined();
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.status).toBe("added");
        expect(parsed.device.device_id).toBe("0781:5583");
        expect(mockSecureWriteFileSync).toHaveBeenCalled();
      });

      it("should list devices when no device_id provided", async () => {
        mockExistsSync.mockReturnValue(true);
        mockReadFileSync.mockReturnValue(JSON.stringify({
          devices: [{ device_id: "0781:5583", description: "SanDisk", added_date: "2025-01-01T00:00:00Z" }],
        }));

        const handler = tools.get("harden_host")!.handler;
        const result = await handler({ action: "usb_whitelist", output_format: "json" });
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.status).toBe("list");
        expect(parsed.totalDevices).toBe(1);
      });

      it("should handle empty whitelist", async () => {
        mockExistsSync.mockReturnValue(false);

        const handler = tools.get("harden_host")!.handler;
        const result = await handler({ action: "usb_whitelist", output_format: "json" });
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.status).toBe("list");
        expect(parsed.totalDevices).toBe(0);
      });

      it("should prevent duplicate devices", async () => {
        mockExistsSync.mockReturnValue(true);
        mockReadFileSync.mockReturnValue(JSON.stringify([
          { device_id: "0781:5583", description: "SanDisk", added_date: "2025-01-01T00:00:00Z" },
        ]));
        setupSpawnMock({
          "lsusb": { stdout: "", stderr: "", exitCode: 0 },
        });

        const handler = tools.get("harden_host")!.handler;
        const result = await handler({ action: "usb_whitelist", device_id: "0781:5583", output_format: "json" });
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.status).toBe("duplicate");
      });

      it("should reject invalid device_id format", async () => {
        const handler = tools.get("harden_host")!.handler;
        const result = await handler({ action: "usb_whitelist", device_id: "invalid-id" });
        expect(result.isError).toBe(true);
        expect(result.content[0].text).toContain("Invalid device_id format");
      });
    });

    // ── usb_monitor ──────────────────────────────────────────────────

    describe("usb_monitor", () => {
      it("should report dmesg USB events", async () => {
        setupSpawnMock({
          "dmesg": { stdout: "[12345.678] usb 1-1: new device\n[12346.789] usb 1-1: USB disconnect", stderr: "", exitCode: 0 },
          "journalctl": { stdout: "", stderr: "", exitCode: 1 },
          "grep": { stdout: "", stderr: "", exitCode: 1 },
          "lsusb": { stdout: "Bus 001 Device 001: ID 1d6b:0002", stderr: "", exitCode: 0 },
        });

        const handler = tools.get("harden_host")!.handler;
        const result = await handler({ action: "usb_monitor", output_format: "json" });
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.dmesgEventCount).toBe(2);
      });

      it("should report journalctl USB events", async () => {
        setupSpawnMock({
          "dmesg": { stdout: "", stderr: "", exitCode: 0 },
          "journalctl": { stdout: "Mar 01 10:00:00 kernel: usb 1-1: new device\nMar 01 10:01:00 kernel: usb 1-1: disconnect", stderr: "", exitCode: 0 },
          "grep": { stdout: "", stderr: "", exitCode: 1 },
          "lsusb": { stdout: "", stderr: "", exitCode: 0 },
        });

        const handler = tools.get("harden_host")!.handler;
        const result = await handler({ action: "usb_monitor", output_format: "json" });
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.journalctlEventCount).toBe(2);
      });

      it("should handle no USB events found", async () => {
        setupSpawnMock({
          "dmesg": { stdout: "some other log line\nanother line", stderr: "", exitCode: 0 },
          "journalctl": { stdout: "", stderr: "", exitCode: 1 },
          "grep": { stdout: "", stderr: "", exitCode: 1 },
          "lsusb": { stdout: "", stderr: "", exitCode: 0 },
        });

        const handler = tools.get("harden_host")!.handler;
        const result = await handler({ action: "usb_monitor", output_format: "json" });
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.totalUsbEvents).toBe(0);
      });
    });

    // ── Error handling ──────────────────────────────────────────────

    describe("error handling", () => {
      it("should handle spawnSafe throwing an error", async () => {
        mockSpawnSafe.mockImplementation(() => {
          throw new Error("spawn failed");
        });

        const handler = tools.get("harden_host")!.handler;
        const result = await handler({ action: "usb_audit_devices", output_format: "json" });
        // Should not crash — returns gracefully with error info in stdout/stderr
        expect(result.content).toBeDefined();
      });

      it("should handle command failures gracefully", async () => {
        setupSpawnMock({
          "lsusb": { stdout: "", stderr: "permission denied", exitCode: 1 },
          "lsblk": { stdout: "", stderr: "error", exitCode: 1 },
          "lsmod": { stdout: "", stderr: "error", exitCode: 1 },
          "ls": { stdout: "", stderr: "error", exitCode: 1 },
          "systemctl": { stdout: "", stderr: "error", exitCode: 1 },
        });

        const handler = tools.get("harden_host")!.handler;
        const result = await handler({ action: "usb_audit_devices" });
        // Should handle gracefully, not crash
        expect(result.content).toBeDefined();
      });
    });

    // ── JSON output format ──────────────────────────────────────────

    describe("output format", () => {
      it("should return JSON format when requested for usb_audit_devices", async () => {
        setupSpawnMock({
          "lsusb": { stdout: "Bus 001 Device 001: ID 1d6b:0002", stderr: "", exitCode: 0 },
          "lsblk": { stdout: "NAME TRAN TYPE", stderr: "", exitCode: 0 },
          "lsmod": { stdout: "", stderr: "", exitCode: 0 },
          "ls": { stdout: "", stderr: "", exitCode: 0 },
          "systemctl": { stdout: "", stderr: "", exitCode: 4 },
        });

        const handler = tools.get("harden_host")!.handler;
        const result = await handler({ action: "usb_audit_devices", output_format: "json" });
        // formatToolOutput returns JSON.stringify
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.action).toBe("audit_devices");
      });

      it("should return text format by default for usb_monitor", async () => {
        setupSpawnMock({
          "dmesg": { stdout: "", stderr: "", exitCode: 0 },
          "journalctl": { stdout: "", stderr: "", exitCode: 1 },
          "grep": { stdout: "", stderr: "", exitCode: 1 },
          "lsusb": { stdout: "", stderr: "", exitCode: 0 },
        });

        const handler = tools.get("harden_host")!.handler;
        const result = await handler({ action: "usb_monitor" });
        expect(result.content[0].text).toContain("USB Device Control");
      });
    });
  });
});
