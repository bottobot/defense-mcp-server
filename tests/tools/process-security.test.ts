/**
 * Tests for src/tools/process-security.ts
 *
 * Covers: process_security tool with actions audit_running, check_capabilities,
 * check_namespaces, detect_anomalies, cgroup_audit.
 * Tests input validation, ps output parsing, capability decoding,
 * namespace analysis, anomaly detection, cgroup parsing, error handling,
 * PID-specific queries, filter parameter, and JSON vs text output.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Mock all external dependencies ─────────────────────────────────────────

vi.mock("../../src/core/spawn-safe.js", () => ({
  spawnSafe: vi.fn(),
}));

vi.mock("../../src/core/parsers.js", () => ({
  createTextContent: vi.fn((text: string) => ({ type: "text", text })),
  createErrorContent: vi.fn((text: string) => ({ type: "text", text: `Error: ${text}` })),
  formatToolOutput: vi.fn((obj: unknown) => ({ type: "text", text: JSON.stringify(obj) })),
}));

import { registerProcessSecurityTools } from "../../src/tools/process-security.js";
import { spawnSafe } from "../../src/core/spawn-safe.js";
import { EventEmitter } from "node:events";

const mockSpawnSafe = vi.mocked(spawnSafe);

// ── Helpers ────────────────────────────────────────────────────────────────

type ToolHandler = (
  params: Record<string, unknown>,
) => Promise<{
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}>;

function createMockServer() {
  const tools = new Map<
    string,
    { schema: Record<string, unknown>; handler: ToolHandler }
  >();
  const server = {
    tool: vi.fn(
      (
        name: string,
        _desc: string,
        schema: Record<string, unknown>,
        handler: ToolHandler,
      ) => {
        tools.set(name, { schema, handler });
      },
    ),
  };
  return {
    server: server as unknown as Parameters<typeof registerProcessSecurityTools>[0],
    tools,
  };
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

// ── Mock data ──────────────────────────────────────────────────────────────

const MOCK_PS_OUTPUT = `USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 168940 11788 ?        Ss   Jan01   5:23 /sbin/init
root         2  0.0  0.0      0     0 ?        S    Jan01   0:00 [kthreadd]
root       500  0.0  0.1  72300  9800 ?        Ss   Jan01   0:12 /usr/sbin/sshd -D
www-data  1234  0.5  2.3 345600 23456 ?        Sl   10:00   1:30 /usr/sbin/apache2 -k start
root      2000 95.0  1.0 123456 10240 ?        R    10:30   5:00 /tmp/suspicious_miner
nobody    3000  0.2 55.0 987654 563200 ?       Sl   Jan01  12:00 /usr/bin/memhog
hacker    4000  0.1  0.1  12345  1234 ?        S    10:45   0:01 /home/hacker/.hidden/backdoor`;

const MOCK_PS_PID_OUTPUT = `  PID
    1
    2
  500
 1234
 2000
 3000
 4000`;

const MOCK_PS_PPID_OUTPUT = `  PID  PPID USER     COMMAND
    1     0 root     systemd
  500     1 root     sshd
 1234     1 root     apache2
 2000     1 root     miner
 3000     1 nobody   memhog
 4000  1234 hacker   bash
 5000  2000 root     sh`;

const MOCK_LSNS_OUTPUT = `        NS TYPE   NPROCS   PID USER   COMMAND
4026531836 pid         5     1 root   /sbin/init
4026531837 user        5     1 root   /sbin/init
4026531838 uts         5     1 root   /sbin/init
4026532100 mnt         2  1234 www    /usr/sbin/apache2
4026532200 net         1  3000 nobody /usr/bin/memhog`;

const MOCK_CGROUPS_OUTPUT = `#subsys_name\thierarchy\tnum_cgroups\tenabled
cpuset\t1\t1\t1
cpu\t2\t1\t1
memory\t3\t1\t1
devices\t4\t1\t1`;

const MOCK_SS_OUTPUT = `State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
LISTEN 0      128    0.0.0.0:22        0.0.0.0:*     users:(("sshd",pid=500,fd=3))
LISTEN 0      128    0.0.0.0:80        0.0.0.0:*     users:(("apache2",pid=1234,fd=4))
LISTEN 0      128    0.0.0.0:4444      0.0.0.0:*     users:(("nc",pid=6000,fd=5))`;

// ── Default mock setup ─────────────────────────────────────────────────────

function setupDefaultMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    const fullCmd = `${command} ${args.join(" ")}`;

    // ps auxf
    if (command === "ps" && args.includes("auxf")) {
      return createMockChildProcess(MOCK_PS_OUTPUT, "", 0);
    }

    // ps -eo pid
    if (command === "ps" && args.includes("pid") && args.includes("-eo") && !args.includes("ppid")) {
      return createMockChildProcess(MOCK_PS_PID_OUTPUT, "", 0);
    }

    // ps -eo pid,ppid,user,comm
    if (command === "ps" && args.includes("pid,ppid,user,comm")) {
      return createMockChildProcess(MOCK_PS_PPID_OUTPUT, "", 0);
    }

    // ls -la /proc/<pid>/exe
    if (command === "ls" && args.includes("-la") && args.some((a) => a.includes("/proc/") && a.includes("/exe"))) {
      const pidMatch = args.find((a) => a.includes("/proc/"))?.match(/\/proc\/(\d+)\/exe/);
      const pid = pidMatch?.[1];
      if (pid === "2000") {
        return createMockChildProcess("lrwxrwxrwx 1 root root 0 Jan  1 00:00 /proc/2000/exe -> /tmp/suspicious_miner (deleted)", "", 0);
      }
      return createMockChildProcess(`lrwxrwxrwx 1 root root 0 Jan  1 00:00 /proc/${pid}/exe -> /usr/bin/something`, "", 0);
    }

    // ls -la /proc/<pid>/ns/
    if (command === "ls" && args.some((a) => a.includes("/ns/"))) {
      return createMockChildProcess(
        `total 0
lrwxrwxrwx 1 root root 0 Jan  1 00:00 cgroup -> cgroup:[4026531835]
lrwxrwxrwx 1 root root 0 Jan  1 00:00 ipc -> ipc:[4026531839]
lrwxrwxrwx 1 root root 0 Jan  1 00:00 mnt -> mnt:[4026531840]
lrwxrwxrwx 1 root root 0 Jan  1 00:00 net -> net:[4026531992]
lrwxrwxrwx 1 root root 0 Jan  1 00:00 pid -> pid:[4026531836]
lrwxrwxrwx 1 root root 0 Jan  1 00:00 user -> user:[4026531837]`,
        "",
        0,
      );
    }

    // ls -la /proc/<pid>/fd/
    if (command === "ls" && args.some((a) => a.includes("/fd/"))) {
      const pidMatch = args.find((a) => a.includes("/proc/"))?.match(/\/proc\/(\d+)\/fd/);
      const pid = pidMatch?.[1];
      if (pid === "4000") {
        return createMockChildProcess(
          "lr-x------ 1 hacker hacker 64 Jan  1 00:00 3 -> /etc/shadow\nlr-x------ 1 hacker hacker 64 Jan  1 00:00 4 -> /home/hacker/.ssh/id_rsa",
          "",
          0,
        );
      }
      return createMockChildProcess("lr-x------ 1 root root 64 Jan  1 00:00 0 -> /dev/null", "", 0);
    }

    // cat /proc/<pid>/status (for capability check)
    if (command === "cat" && args.some((a) => a.includes("/status"))) {
      const pidMatch = args[0]?.match(/\/proc\/(\d+)\/status/);
      const pid = pidMatch?.[1];
      if (pid === "1") {
        return createMockChildProcess(
          "Name:\tinit\nCapEff:\t0000003fffffffff\nCapPrm:\t0000003fffffffff",
          "",
          0,
        );
      }
      if (pid === "500") {
        return createMockChildProcess(
          "Name:\tsshd\nCapEff:\t0000000000000000\nCapPrm:\t0000000000000000",
          "",
          0,
        );
      }
      return createMockChildProcess(
        "Name:\tprocess\nCapEff:\t0000000000000000\nCapPrm:\t0000000000000000",
        "",
        0,
      );
    }

    // cat /proc/<pid>/comm
    if (command === "cat" && args.some((a) => a.includes("/comm"))) {
      return createMockChildProcess("process", "", 0);
    }

    // cat /proc/<pid>/environ
    if (command === "cat" && args.some((a) => a.includes("/environ"))) {
      const pidMatch = args[0]?.match(/\/proc\/(\d+)\/environ/);
      const pid = pidMatch?.[1];
      if (pid === "2000") {
        return createMockChildProcess("HOME=/root\0PATH=/usr/bin\0PAYLOAD=aGVsbG8=\0", "", 0);
      }
      return createMockChildProcess("HOME=/root\0PATH=/usr/bin\0TERM=xterm\0", "", 0);
    }

    // cat /proc/cgroups (exact path — must come before generic /cgroup match)
    if (command === "cat" && args.includes("/proc/cgroups")) {
      return createMockChildProcess(MOCK_CGROUPS_OUTPUT, "", 0);
    }

    // cat /proc/self/cgroup (exact path — must come before generic /cgroup match)
    if (command === "cat" && args.includes("/proc/self/cgroup")) {
      return createMockChildProcess("0::/user.slice/user-1000.slice", "", 0);
    }

    // cat /sys/fs/cgroup.../memory.max (must come before generic /cgroup match)
    if (command === "cat" && args.some((a) => a.includes("memory.max"))) {
      return createMockChildProcess("max", "", 0);
    }

    // cat /sys/fs/cgroup.../cpu.max (must come before generic /cgroup match)
    if (command === "cat" && args.some((a) => a.includes("cpu.max"))) {
      return createMockChildProcess("max 100000", "", 0);
    }

    // cat /proc/<pid>/cgroup (generic — must come after specific cgroup matches)
    if (command === "cat" && args.some((a) => a.includes("/cgroup"))) {
      return createMockChildProcess("0::/system.slice/test.service", "", 0);
    }

    // getpcaps
    if (command === "getpcaps") {
      const pid = args[0];
      if (pid === "1") {
        return createMockChildProcess("1: cap_sys_admin,cap_sys_ptrace,cap_net_raw=ep", "", 0);
      }
      return createMockChildProcess(`${pid}: =`, "", 0);
    }

    // capsh
    if (command === "capsh") {
      return createMockChildProcess("0x0000003fffffffff=cap_sys_admin,cap_sys_ptrace,cap_net_raw,cap_dac_override,cap_setuid,cap_setgid", "", 0);
    }

    // lsns
    if (command === "lsns") {
      return createMockChildProcess(MOCK_LSNS_OUTPUT, "", 0);
    }

    // ss -tlnp
    if (command === "ss" && args.includes("-tlnp")) {
      return createMockChildProcess(MOCK_SS_OUTPUT, "", 0);
    }

    // systemd-cgls
    if (command === "systemd-cgls") {
      return createMockChildProcess("Control group /:\n├─1 /sbin/init\n├─system.slice\n│ ├─sshd.service\n│ │ └─500 /usr/sbin/sshd", "", 0);
    }

    // systemd-cgtop
    if (command === "systemd-cgtop") {
      return createMockChildProcess("Control Group\tTasks\t%CPU\tMemory\nSystem\t50\t5.0\t512M", "", 0);
    }

    // sudo lsns (fallback)
    if (command === "sudo" && args.includes("lsns")) {
      return createMockChildProcess(MOCK_LSNS_OUTPUT, "", 0);
    }

    // Default: empty success
    return createMockChildProcess("", "", 0);
  });
}

// ── Tests ──────────────────────────────────────────────────────────────────

describe("process-security tools", () => {
  let tools: Map<
    string,
    { schema: Record<string, unknown>; handler: ToolHandler }
  >;

  beforeEach(() => {
    vi.clearAllMocks();
    const mock = createMockServer();
    registerProcessSecurityTools(mock.server);
    tools = mock.tools;
    setupDefaultMocks();
  });

  // ── Registration ────────────────────────────────────────────────────────

  it("should register the process_security tool", () => {
    expect(tools.has("process_security")).toBe(true);
  });

  it("should register with server.tool called once", () => {
    const mock = createMockServer();
    registerProcessSecurityTools(mock.server);
    expect(mock.server.tool).toHaveBeenCalledTimes(1);
    expect(mock.server.tool).toHaveBeenCalledWith(
      "process_security",
      expect.any(String),
      expect.any(Object),
      expect.any(Function),
    );
  });

  // ── Input validation ────────────────────────────────────────────────────

  it("should return error for unknown action", async () => {
    const handler = tools.get("process_security")!.handler;
    const result = await handler({ action: "nonexistent" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Unknown action");
  });

  // ── audit_running action ────────────────────────────────────────────────

  describe("audit_running", () => {
    it("should audit running processes and detect security concerns", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "audit_running" });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("Process Security Audit");
    });

    it("should detect processes running as root that are not known safe", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "audit_running" });
      // /tmp/suspicious_miner is run as root and not in safe list
      expect(result.content[0].text).toContain("suspicious_miner");
      expect(result.content[0].text).toContain("Unusual Root Processes");
    });

    it("should detect high CPU usage processes", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "audit_running" });
      // PID 2000 has 95% CPU
      expect(result.content[0].text).toContain("High CPU Usage");
      expect(result.content[0].text).toContain("95");
    });

    it("should detect high memory usage processes", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "audit_running" });
      // PID 3000 has 55% memory
      expect(result.content[0].text).toContain("High Memory Usage");
      expect(result.content[0].text).toContain("55");
    });

    it("should detect processes from unusual paths", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "audit_running" });
      // /tmp/suspicious_miner and /home/hacker/.hidden/backdoor are unusual paths
      expect(result.content[0].text).toContain("Unusual Paths");
    });

    it("should detect processes with deleted executables", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "audit_running" });
      expect(result.content[0].text).toContain("Deleted Executables");
      expect(result.content[0].text).toContain("2000");
    });

    it("should filter by PID when specified", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "audit_running", pid: 1234 });
      expect(result.isError).toBeUndefined();
      // Should not include other process PIDs in findings about root processes
      expect(result.content[0].text).not.toContain("suspicious_miner");
    });

    it("should filter by name pattern", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "audit_running", filter: "apache", show_all: true });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("apache2");
    });

    it("should show all processes when show_all is true", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "audit_running", show_all: true });
      expect(result.content[0].text).toContain("All Processes");
    });

    it("should handle ps command failure gracefully", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "ps" && args.includes("auxf")) {
          return createMockChildProcess("", "command not found", 127);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "audit_running" });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("Failed to get process list");
    });

    it("should report no process found for non-existent PID", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "audit_running", pid: 99999 });
      expect(result.content[0].text).toContain("No process found with PID 99999");
    });
  });

  // ── check_capabilities action ───────────────────────────────────────────

  describe("check_capabilities", () => {
    it("should check capabilities for a specific PID", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "check_capabilities", pid: 1 });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("Capabilities for PID 1");
      expect(result.content[0].text).toContain("cap_sys_admin");
    });

    it("should detect dangerous capabilities for specific PID", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "check_capabilities", pid: 1 });
      expect(result.content[0].text).toContain("dangerous capability");
      expect(result.content[0].text).toContain("cap_sys_admin");
    });

    it("should scan all processes when no PID specified", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "check_capabilities" });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("Scanning");
      expect(result.content[0].text).toContain("Elevated Capabilities");
    });

    it("should decode capability hex values", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "check_capabilities" });
      // capsh --decode should be called for non-zero capabilities
      expect(mockSpawnSafe).toHaveBeenCalledWith(
        "capsh",
        expect.arrayContaining(["--decode=0000003fffffffff"]),
      );
    });

    it("should handle getpcaps failure gracefully", async () => {
      mockSpawnSafe.mockImplementation((command: string) => {
        if (command === "getpcaps") {
          return createMockChildProcess("", "No such process", 1);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "check_capabilities", pid: 99999 });
      expect(result.content[0].text).toContain("Failed to get capabilities");
    });

    it("should handle ps failure when scanning all processes", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "ps") {
          return createMockChildProcess("", "error", 1);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "check_capabilities" });
      expect(result.content[0].text).toContain("Failed to list processes");
    });
  });

  // ── check_namespaces action ─────────────────────────────────────────────

  describe("check_namespaces", () => {
    it("should list namespaces via lsns when no PID specified", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "check_namespaces" });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("Namespace Analysis");
      expect(result.content[0].text).toContain("Active Namespaces");
    });

    it("should show namespace details for specific PID", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "check_namespaces", pid: 1234 });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("Namespace details for PID 1234");
    });

    it("should compare namespaces with init (PID 1)", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "check_namespaces", pid: 1234 });
      expect(result.content[0].text).toContain("Namespace Comparison with init");
    });

    it("should flag processes in root namespace", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "check_namespaces", pid: 1234 });
      // Same namespace IDs as PID 1 means in root namespace
      expect(result.content[0].text).toContain("root namespace");
    });

    it("should handle lsns failure and fallback to sudo", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "lsns" && !args.includes("lsns")) {
          return createMockChildProcess("", "permission denied", 1);
        }
        if (command === "sudo" && args.includes("lsns")) {
          return createMockChildProcess(MOCK_LSNS_OUTPUT, "", 0);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "check_namespaces" });
      expect(result.content[0].text).toContain("Active Namespaces");
    });

    it("should handle namespace read failure for specific PID", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "ls" && args.some((a) => a.includes("/ns/"))) {
          return createMockChildProcess("", "No such process", 1);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "check_namespaces", pid: 99999 });
      expect(result.content[0].text).toContain("Cannot read namespaces");
    });
  });

  // ── detect_anomalies action ─────────────────────────────────────────────

  describe("detect_anomalies", () => {
    it("should perform comprehensive anomaly detection", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "detect_anomalies" });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("Anomaly Detection");
    });

    it("should detect processes with deleted binaries", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "detect_anomalies" });
      expect(result.content[0].text).toContain("Deleted Binary");
      expect(result.content[0].text).toContain("2000");
    });

    it("should check network connections", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "detect_anomalies" });
      expect(result.content[0].text).toContain("Network Connections");
      expect(mockSpawnSafe).toHaveBeenCalledWith("ss", ["-tlnp"]);
    });

    it("should detect shell spawning from non-shell parents", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "detect_anomalies" });
      // PID 5000 is sh spawned by miner (PID 2000) — should be flagged
      expect(result.content[0].text).toContain("Shell Spawning");
    });

    it("should detect sensitive file access", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "detect_anomalies" });
      expect(result.content[0].text).toContain("Sensitive File Access");
    });

    it("should detect suspicious environment variables", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "detect_anomalies" });
      expect(result.content[0].text).toContain("Suspicious Environment");
    });

    it("should filter by PID for anomaly detection", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "detect_anomalies", pid: 500 });
      expect(result.isError).toBeUndefined();
    });

    it("should filter by name pattern for anomaly detection", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "detect_anomalies", filter: "sshd" });
      expect(result.isError).toBeUndefined();
    });

    it("should handle ps failure in anomaly detection", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "ps") {
          return createMockChildProcess("", "error", 1);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "detect_anomalies" });
      expect(result.content[0].text).toContain("Failed to get process list");
    });
  });

  // ── cgroup_audit action ─────────────────────────────────────────────────

  describe("cgroup_audit", () => {
    it("should perform system-wide cgroup audit", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "cgroup_audit" });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("Cgroup Resource Audit");
    });

    it("should list available cgroup controllers", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "cgroup_audit" });
      expect(result.content[0].text).toContain("Cgroup Controllers");
      expect(result.content[0].text).toContain("cpuset");
      expect(result.content[0].text).toContain("memory");
    });

    it("should show cgroup hierarchy", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "cgroup_audit" });
      expect(result.content[0].text).toContain("Cgroup Hierarchy");
    });

    it("should detect cgroup version", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "cgroup_audit" });
      expect(result.content[0].text).toContain("Cgroup version");
      expect(result.content[0].text).toContain("v2");
    });

    it("should audit specific PID cgroup membership", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "cgroup_audit", pid: 1234 });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("Cgroup membership for PID 1234");
    });

    it("should detect missing memory limits for specific PID", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "cgroup_audit", pid: 1234 });
      expect(result.content[0].text).toContain("unlimited");
    });

    it("should detect missing CPU limits for specific PID", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "cgroup_audit", pid: 1234 });
      // cpu.max returns "max 100000" which means unlimited
      expect(result.content[0].text).toContain("unlimited");
    });

    it("should handle cgroup read failure for specific PID", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "cat" && args.some((a) => a.includes("/cgroup"))) {
          return createMockChildProcess("", "No such file", 1);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "cgroup_audit", pid: 99999 });
      expect(result.content[0].text).toContain("Cannot read cgroup");
    });
  });

  // ── Output format ───────────────────────────────────────────────────────

  describe("output format", () => {
    it("should return text format by default", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "audit_running" });
      expect(result.content[0].text).toContain("Process Security Audit");
      // Should not be JSON
      expect(() => JSON.parse(result.content[0].text)).toThrow();
    });

    it("should return JSON format when requested", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "audit_running", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("audit_running");
      expect(parsed.timestamp).toBeDefined();
      expect(parsed.findings).toBeInstanceOf(Array);
      expect(parsed.findingsCount).toBeDefined();
      expect(parsed.rawOutput).toBeDefined();
    });

    it("should include finding details in JSON output", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "audit_running", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.findingsCount).toBeGreaterThan(0);
      const finding = parsed.findings[0];
      expect(finding).toHaveProperty("severity");
      expect(finding).toHaveProperty("category");
      expect(finding).toHaveProperty("message");
    });

    it("should format JSON for each action", async () => {
      const handler = tools.get("process_security")!.handler;
      const actions = ["audit_running", "check_capabilities", "check_namespaces", "detect_anomalies", "cgroup_audit"];
      for (const action of actions) {
        const result = await handler({ action, output_format: "json" });
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.action).toBe(action);
      }
    });
  });

  // ── Error handling ──────────────────────────────────────────────────────

  describe("error handling", () => {
    it("should handle spawnSafe throwing an error", async () => {
      mockSpawnSafe.mockImplementation(() => {
        throw new Error("Binary not in allowlist");
      });

      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "audit_running" });
      // runCommand catches the throw, so the tool should still respond
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("Failed to get process list");
    });

    it("should handle spawnSafe throwing for check_capabilities", async () => {
      mockSpawnSafe.mockImplementation(() => {
        throw new Error("Binary not in allowlist");
      });

      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "check_capabilities", pid: 1 });
      expect(result.content[0].text).toContain("Failed to get capabilities");
    });

    it("should skip processes gracefully when /proc reads fail", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "ps" && args.includes("auxf")) {
          return createMockChildProcess(MOCK_PS_OUTPUT, "", 0);
        }
        // All /proc reads fail
        if (command === "ls" || (command === "cat" && args.some((a) => a.startsWith("/proc/")))) {
          return createMockChildProcess("", "Permission denied", 1);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "audit_running" });
      // Should still complete without error
      expect(result.isError).toBeUndefined();
    });
  });

  // ── Findings summary ────────────────────────────────────────────────────

  describe("findings summary", () => {
    it("should include findings summary with severity icons", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "audit_running" });
      expect(result.content[0].text).toContain("Security Findings Summary");
    });

    it("should show no findings message when nothing suspicious", async () => {
      // Override to return clean ps output
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "ps" && args.includes("auxf")) {
          return createMockChildProcess(
            `USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 168940 11788 ?        Ss   Jan01   5:23 /sbin/init
root       500  0.0  0.1  72300  9800 ?        Ss   Jan01   0:12 /usr/sbin/sshd -D`,
            "",
            0,
          );
        }
        if (command === "ls" && args.some((a) => a.includes("/exe"))) {
          return createMockChildProcess("lrwxrwxrwx 1 root root 0 Jan  1 00:00 /proc/1/exe -> /sbin/init", "", 0);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "audit_running" });
      expect(result.content[0].text).toContain("No suspicious processes detected");
    });

    it("should categorize findings by severity", async () => {
      const handler = tools.get("process_security")!.handler;
      const result = await handler({ action: "audit_running", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      // Should have findings of different severities
      const severities = new Set(parsed.findings.map((f: { severity: string }) => f.severity));
      expect(severities.size).toBeGreaterThan(0);
    });
  });
});
