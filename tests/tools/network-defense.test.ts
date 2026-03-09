/**
 * Tests for src/tools/network-defense.ts
 *
 * Covers: TOOL-022 network parameter validation (IP, CIDR, port, protocol),
 * BPF filter validation, capture path validation, tool registration, action routing,
 * and network_segmentation_audit (map_zones, verify_isolation, test_paths, audit_vlans).
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/core/executor.js", () => ({
  executeCommand: vi.fn().mockResolvedValue({ exitCode: 0, stdout: "", stderr: "", timedOut: false, duration: 10, permissionDenied: false }),
}));

const cmdOk = { exitCode: 0, stdout: "", stderr: "", timedOut: false, duration: 10, permissionDenied: false };
vi.mock("../../src/core/config.js", () => ({
  getConfig: vi.fn().mockReturnValue({ dryRun: true }),
  getToolTimeout: vi.fn().mockReturnValue(30000),
}));
vi.mock("../../src/core/parsers.js", () => ({
  createTextContent: vi.fn((text: string) => ({ type: "text", text })),
  createErrorContent: vi.fn((text: string) => ({ type: "text", text: `Error: ${text}` })),
  parseSsOutput: vi.fn().mockReturnValue([]),
  formatToolOutput: vi.fn((obj: unknown) => ({ type: "text", text: JSON.stringify(obj) })),
}));
vi.mock("../../src/core/changelog.js", () => ({
  logChange: vi.fn(),
  createChangeEntry: vi.fn().mockReturnValue({}),
}));
vi.mock("../../src/core/sanitizer.js", () => ({
  validateInterface: vi.fn((i: string) => i),
  sanitizeArgs: vi.fn((a: string[]) => a),
  validateTarget: vi.fn((t: string) => t),
  validateToolPath: vi.fn((p: string, _dirs: string[], _label: string) => {
    if (p.includes("..")) throw new Error("Path contains forbidden directory traversal (..)");
    return p;
  }),
}));
vi.mock("../../src/tools/ebpf-security.js", () => ({
  validateBpfFilter: vi.fn((f: string) => {
    if (f.includes(";")) throw new Error("BPF filter contains forbidden shell metacharacters");
    return f;
  }),
}));
vi.mock("../../src/core/spawn-safe.js", () => ({
  spawnSafe: vi.fn(),
}));

import { registerNetworkDefenseTools } from "../../src/tools/network-defense.js";
import { executeCommand } from "../../src/core/executor.js";
import { spawnSafe } from "../../src/core/spawn-safe.js";
import { EventEmitter } from "node:events";

type ToolHandler = (params: Record<string, unknown>) => Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }>;

const mockSpawnSafe = vi.mocked(spawnSafe);

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

  process.nextTick(() => {
    if (stdout) cp.stdout.emit("data", Buffer.from(stdout));
    if (stderr) cp.stderr.emit("data", Buffer.from(stderr));
    cp.emit("close", exitCode);
  });

  return cp;
}

function createMockServer() {
  const tools = new Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>();
  const server = {
    tool: vi.fn((name: string, _desc: string, schema: Record<string, unknown>, handler: ToolHandler) => {
      tools.set(name, { schema, handler });
    }),
  };
  return { server: server as unknown as Parameters<typeof registerNetworkDefenseTools>[0], tools };
}

describe("network-defense tools", () => {
  let tools: Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>;

  beforeEach(() => {
    vi.clearAllMocks();
    const mock = createMockServer();
    registerNetworkDefenseTools(mock.server);
    tools = mock.tools;
  });

  it("should register all 4 network defense tools", () => {
    expect(tools.has("netdef_connections")).toBe(true);
    expect(tools.has("netdef_capture")).toBe(true);
    expect(tools.has("netdef_security_audit")).toBe(true);
    expect(tools.has("network_segmentation_audit")).toBe(true);
  });

  // ── netdef_connections ────────────────────────────────────────────────

  it("should handle list action", async () => {
    const handler = tools.get("netdef_connections")!.handler;
    const result = await handler({ action: "list", protocol: "all", listening: false, process: true });
    expect(result.isError).toBeUndefined();
  });

  it("should handle audit action", async () => {
    vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk, stdout: "Netid  State  Recv-Q Send-Q Local Address:Port\n" });
    const handler = tools.get("netdef_connections")!.handler;
    const result = await handler({ action: "audit", include_loopback: false });
    expect(result.isError).toBeUndefined();
  });

  // ── netdef_capture ────────────────────────────────────────────────────

  it("should preview custom capture in dry_run mode", async () => {
    const handler = tools.get("netdef_capture")!.handler;
    const result = await handler({
      action: "custom",
      interface: "any",
      count: 10,
      duration: 5,
      dry_run: true,
    });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain("DRY-RUN");
  });

  it("should reject BPF filter with shell metacharacters (TOOL-022/018)", async () => {
    const handler = tools.get("netdef_capture")!.handler;
    const result = await handler({
      action: "custom",
      interface: "any",
      count: 10,
      duration: 5,
      filter: "port 80; rm -rf /",
      dry_run: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("metacharacters");
  });

  it("should reject output_file path with traversal (TOOL-022)", async () => {
    const handler = tools.get("netdef_capture")!.handler;
    const result = await handler({
      action: "custom",
      interface: "any",
      count: 10,
      duration: 5,
      output_file: "/tmp/../../../etc/capture.pcap",
      dry_run: true,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("traversal");
  });

  // ── netdef_security_audit ─────────────────────────────────────────────

  it("should handle scan_detect action", async () => {
    vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk, stdout: "" });
    const handler = tools.get("netdef_security_audit")!.handler;
    const result = await handler({ action: "scan_detect", threshold: 10, timeframe: 60 });
    expect(result.isError).toBeUndefined();
  });

  it("should handle self_scan action", async () => {
    vi.mocked(executeCommand).mockResolvedValue({ ...cmdOk, stdout: "Nmap scan report" });
    const handler = tools.get("netdef_security_audit")!.handler;
    const result = await handler({ action: "self_scan", target: "localhost", scan_type: "quick" });
    expect(result.isError).toBeUndefined();
  });

  // ── network_segmentation_audit ─────────────────────────────────────────

  describe("network_segmentation_audit", () => {
    let handler: ToolHandler;

    beforeEach(() => {
      handler = tools.get("network_segmentation_audit")!.handler;
    });

    it("should be registered as network_segmentation_audit", () => {
      expect(tools.has("network_segmentation_audit")).toBe(true);
    });

    // ── map_zones ─────────────────────────────────────────────────────────

    describe("map_zones", () => {
      it("should parse interfaces and subnets", async () => {
        mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
          const fullCmd = `${command} ${args.join(" ")}`;
          if (fullCmd.includes("ip addr show")) {
            return createMockChildProcess(
              "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0\n3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    inet 10.0.0.1/16 brd 10.0.255.255 scope global eth1\n",
              "", 0,
            );
          }
          if (fullCmd.includes("ip route show")) {
            return createMockChildProcess(
              "default via 192.168.1.1 dev eth0\n10.0.0.0/16 dev eth1 proto kernel scope link src 10.0.0.1\n",
              "", 0,
            );
          }
          return createMockChildProcess("", "", 0);
        });

        const result = await handler({ action: "map_zones", output_format: "text" });
        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("eth0");
        expect(result.content[0].text).toContain("192.168.1.10/24");
        expect(result.content[0].text).toContain("eth1");
        expect(result.content[0].text).toContain("10.0.0.1/16");
      });

      it("should parse routing table and find gateways", async () => {
        mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
          const fullCmd = `${command} ${args.join(" ")}`;
          if (fullCmd.includes("ip addr show")) {
            return createMockChildProcess(
              "2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500\n    inet 192.168.1.10/24 scope global eth0\n",
              "", 0,
            );
          }
          if (fullCmd.includes("ip route show")) {
            return createMockChildProcess("default via 192.168.1.1 dev eth0\n", "", 0);
          }
          return createMockChildProcess("", "", 0);
        });

        const result = await handler({ action: "map_zones", output_format: "text" });
        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("192.168.1.1");
      });

      it("should map firewall rules to zones", async () => {
        mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
          const fullCmd = `${command} ${args.join(" ")}`;
          if (fullCmd.includes("ip addr show")) {
            return createMockChildProcess(
              "2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500\n    inet 192.168.1.10/24 scope global eth0\n",
              "", 0,
            );
          }
          if (fullCmd.includes("iptables -L -n -v")) {
            return createMockChildProcess(
              "Chain INPUT (policy DROP)\n  0  0 ACCEPT tcp -- eth0 * 192.168.1.0/24 0.0.0.0/0\n",
              "", 0,
            );
          }
          return createMockChildProcess("", "", 0);
        });

        const result = await handler({ action: "map_zones", output_format: "text" });
        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("Firewall rules");
      });

      it("should detect bridge interfaces", async () => {
        mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
          const fullCmd = `${command} ${args.join(" ")}`;
          if (fullCmd.includes("ip addr show")) {
            return createMockChildProcess(
              "2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500\n    inet 192.168.1.10/24 scope global eth0\n",
              "", 0,
            );
          }
          if (fullCmd.includes("bridge link show")) {
            return createMockChildProcess(
              "3: veth0 state UP : <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 master br0\n",
              "", 0,
            );
          }
          return createMockChildProcess("", "", 0);
        });

        const result = await handler({ action: "map_zones", output_format: "text" });
        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("Bridge Interfaces");
        expect(result.content[0].text).toContain("veth0");
      });

      it("should return JSON format when requested", async () => {
        mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
          const fullCmd = `${command} ${args.join(" ")}`;
          if (fullCmd.includes("ip addr show")) {
            return createMockChildProcess(
              "2: eth0: <UP> mtu 1500\n    inet 10.0.0.1/24 scope global eth0\n",
              "", 0,
            );
          }
          return createMockChildProcess("", "", 0);
        });

        const result = await handler({ action: "map_zones", output_format: "json" });
        expect(result.isError).toBeUndefined();
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.totalZones).toBeDefined();
        expect(parsed.zones).toBeInstanceOf(Array);
      });
    });

    // ── verify_isolation ──────────────────────────────────────────────────

    describe("verify_isolation", () => {
      it("should check FORWARD chain default policy", async () => {
        mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
          const fullCmd = `${command} ${args.join(" ")}`;
          if (fullCmd.includes("iptables -L FORWARD -n")) {
            return createMockChildProcess(
              "Chain FORWARD (policy DROP)\ntarget  prot opt source  destination\nACCEPT  all  --  192.168.1.0/24  10.0.0.0/24\n",
              "", 0,
            );
          }
          if (fullCmd.includes("-t nat")) {
            return createMockChildProcess("Chain POSTROUTING (policy ACCEPT)\n", "", 0);
          }
          return createMockChildProcess("", "", 0);
        });

        const result = await handler({ action: "verify_isolation", output_format: "text" });
        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("DROP");
        expect(result.content[0].text).toContain("Segmentation Score");
      });

      it("should detect overly permissive FORWARD rules", async () => {
        mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
          const fullCmd = `${command} ${args.join(" ")}`;
          if (fullCmd.includes("iptables -L FORWARD -n")) {
            return createMockChildProcess(
              "Chain FORWARD (policy ACCEPT)\ntarget  prot opt source  destination\nACCEPT  all  --  0.0.0.0/0  0.0.0.0/0\n",
              "", 0,
            );
          }
          if (fullCmd.includes("-t nat")) {
            return createMockChildProcess("", "", 0);
          }
          return createMockChildProcess("", "", 0);
        });

        const result = await handler({ action: "verify_isolation", output_format: "text" });
        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("Violations");
        expect(result.content[0].text).toContain("ACCEPT");
      });

      it("should detect NAT/masquerade bypass rules", async () => {
        mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
          const fullCmd = `${command} ${args.join(" ")}`;
          if (fullCmd.includes("iptables -L FORWARD -n")) {
            return createMockChildProcess(
              "Chain FORWARD (policy DROP)\n",
              "", 0,
            );
          }
          if (fullCmd.includes("-t nat")) {
            return createMockChildProcess(
              "Chain POSTROUTING (policy ACCEPT)\nMASQUERADE  all  --  10.0.0.0/24  0.0.0.0/0\n",
              "", 0,
            );
          }
          return createMockChildProcess("", "", 0);
        });

        const result = await handler({ action: "verify_isolation", output_format: "text" });
        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("NAT");
        expect(result.content[0].text).toContain("MASQUERADE");
      });

      it("should report segmentation score", async () => {
        mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
          const fullCmd = `${command} ${args.join(" ")}`;
          if (fullCmd.includes("iptables -L FORWARD -n")) {
            return createMockChildProcess(
              "Chain FORWARD (policy DROP)\ntarget  prot opt source  destination\nACCEPT  tcp  --  192.168.1.0/24  10.0.0.0/24  tcp dpt:443\n",
              "", 0,
            );
          }
          if (fullCmd.includes("-t nat")) {
            return createMockChildProcess("Chain POSTROUTING (policy ACCEPT)\n", "", 0);
          }
          return createMockChildProcess("", "", 0);
        });

        const result = await handler({ action: "verify_isolation", output_format: "json" });
        expect(result.isError).toBeUndefined();
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.segmentationScore).toBeDefined();
        expect(typeof parsed.segmentationScore).toBe("number");
        expect(parsed.segmentationStatus).toBeDefined();
      });
    });

    // ── test_paths ────────────────────────────────────────────────────────

    describe("test_paths", () => {
      it("should require both source_zone and dest_zone", async () => {
        const result = await handler({ action: "test_paths", output_format: "text" });
        expect(result.isError).toBe(true);
        expect(result.content[0].text).toContain("source_zone");
        expect(result.content[0].text).toContain("dest_zone");
      });

      it("should reject missing dest_zone", async () => {
        const result = await handler({ action: "test_paths", source_zone: "192.168.1.0/24", output_format: "text" });
        expect(result.isError).toBe(true);
      });

      it("should execute traceroute and host discovery", async () => {
        mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
          const fullCmd = `${command} ${args.join(" ")}`;
          if (fullCmd.includes("traceroute")) {
            return createMockChildProcess(
              "traceroute to 10.0.0.1 (10.0.0.1), 15 hops max\n 1  192.168.1.1  1.234 ms\n 2  10.0.0.1  2.345 ms\n",
              "", 0,
            );
          }
          if (fullCmd.includes("nmap")) {
            return createMockChildProcess(
              "Starting Nmap\nNmap scan report for 10.0.0.1\nHost is up\nNmap scan report for 10.0.0.2\nHost is up\nNmap done\n",
              "", 0,
            );
          }
          return createMockChildProcess("", "", 0);
        });

        const result = await handler({
          action: "test_paths",
          source_zone: "192.168.1.0/24",
          dest_zone: "10.0.0.0/24",
          output_format: "text",
        });
        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("10.0.0.1");
        expect(result.content[0].text).toContain("10.0.0.2");
        expect(result.content[0].text).toContain("Reachable hosts");
      });

      it("should return JSON format for test_paths", async () => {
        mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
          const fullCmd = `${command} ${args.join(" ")}`;
          if (fullCmd.includes("traceroute")) {
            return createMockChildProcess("traceroute to 10.0.0.1\n 1  gw  1ms\n", "", 0);
          }
          if (fullCmd.includes("nmap")) {
            return createMockChildProcess(
              "Nmap scan report for 10.0.0.5\nHost is up\n",
              "", 0,
            );
          }
          return createMockChildProcess("", "", 0);
        });

        const result = await handler({
          action: "test_paths",
          source_zone: "192.168.1.0/24",
          dest_zone: "10.0.0.0/24",
          output_format: "json",
        });
        expect(result.isError).toBeUndefined();
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.sourceZone).toBe("192.168.1.0/24");
        expect(parsed.destZone).toBe("10.0.0.0/24");
        expect(parsed.reachableHosts).toBeInstanceOf(Array);
        expect(parsed.reachableHostCount).toBeDefined();
        expect(parsed.pathExists).toBe(true);
      });
    });

    // ── audit_vlans ───────────────────────────────────────────────────────

    describe("audit_vlans", () => {
      it("should detect VLAN interfaces", async () => {
        mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
          const fullCmd = `${command} ${args.join(" ")}`;
          if (fullCmd.includes("ip -d link show")) {
            return createMockChildProcess(
              "4: eth0.100@eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    vlan protocol 802.1Q id 100 <REORDER_HDR>\n5: eth0.200@eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    vlan protocol 802.1Q id 200 <REORDER_HDR>\n",
              "", 0,
            );
          }
          if (fullCmd.includes("/proc/net/vlan/config")) {
            return createMockChildProcess(
              "VLAN Dev name | VLAN ID\neth0.100 | 100 | eth0\neth0.200 | 200 | eth0\n",
              "", 0,
            );
          }
          return createMockChildProcess("", "", 0);
        });

        const result = await handler({ action: "audit_vlans", output_format: "text" });
        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("VLAN");
        expect(result.content[0].text).toContain("100");
        expect(result.content[0].text).toContain("200");
      });

      it("should parse VLAN config from /proc/net/vlan/config", async () => {
        mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
          const fullCmd = `${command} ${args.join(" ")}`;
          if (fullCmd.includes("ip -d link show")) {
            return createMockChildProcess(
              "4: eth0.100@eth0: <BROADCAST,MULTICAST,UP> mtu 1500\n    vlan protocol 802.1Q id 100\n",
              "", 0,
            );
          }
          if (fullCmd.includes("/proc/net/vlan/config")) {
            return createMockChildProcess(
              "VLAN Dev name | VLAN ID\neth0.100 | 100 | eth0\n",
              "", 0,
            );
          }
          return createMockChildProcess("", "", 0);
        });

        const result = await handler({ action: "audit_vlans", output_format: "text" });
        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("VLAN Config");
      });

      it("should check 802.1Q support via lsmod", async () => {
        mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
          const fullCmd = `${command} ${args.join(" ")}`;
          if (fullCmd.includes("ip -d link show")) {
            return createMockChildProcess("2: eth0: <UP> mtu 1500\n", "", 0);
          }
          if (fullCmd.includes("/proc/net/vlan/config")) {
            return createMockChildProcess("", "No such file", 1);
          }
          if (command === "lsmod") {
            return createMockChildProcess("8021q  32768  0\n", "", 0);
          }
          return createMockChildProcess("", "", 0);
        });

        const result = await handler({ action: "audit_vlans", output_format: "json" });
        expect(result.isError).toBeUndefined();
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.dot1qSupported).toBe(true);
      });

      it("should report security concerns when no VLANs found", async () => {
        mockSpawnSafe.mockImplementation(() => {
          return createMockChildProcess("", "", 1);
        });

        const result = await handler({ action: "audit_vlans", output_format: "json" });
        expect(result.isError).toBeUndefined();
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.securityConcerns).toBeInstanceOf(Array);
        expect(parsed.securityConcerns.length).toBeGreaterThan(0);
        expect(parsed.securityConcerns.some((c: string) => c.includes("No VLAN"))).toBe(true);
      });
    });

    // ── Error handling ────────────────────────────────────────────────────

    describe("error handling", () => {
      it("should handle command failures gracefully for map_zones", async () => {
        mockSpawnSafe.mockImplementation(() => {
          return createMockChildProcess("", "command not found", 127);
        });

        const result = await handler({ action: "map_zones", output_format: "text" });
        expect(result.isError).toBeUndefined();
        expect(result.content[0].text).toContain("Total zones detected: 0");
      });

      it("should handle spawnSafe throwing", async () => {
        mockSpawnSafe.mockImplementation(() => {
          throw new Error("Binary not in allowlist");
        });

        const result = await handler({ action: "map_zones", output_format: "text" });
        // runSegmentCommand catches the throw, so the tool should still complete
        expect(result.isError).toBeUndefined();
      });

      it("should handle verify_isolation with inaccessible iptables", async () => {
        mockSpawnSafe.mockImplementation(() => {
          return createMockChildProcess("", "iptables: command not found", 127);
        });

        const result = await handler({ action: "verify_isolation", output_format: "json" });
        expect(result.isError).toBeUndefined();
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.violations.length).toBeGreaterThan(0);
        expect(parsed.segmentationScore).toBeLessThan(100);
      });
    });

    // ── JSON output format ────────────────────────────────────────────────

    describe("JSON output format", () => {
      it("should return JSON for map_zones", async () => {
        mockSpawnSafe.mockImplementation(() => createMockChildProcess("", "", 0));
        const result = await handler({ action: "map_zones", output_format: "json" });
        expect(result.isError).toBeUndefined();
        expect(() => JSON.parse(result.content[0].text)).not.toThrow();
      });

      it("should return JSON for verify_isolation", async () => {
        mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
          const fullCmd = `${command} ${args.join(" ")}`;
          if (fullCmd.includes("iptables -L FORWARD -n")) {
            return createMockChildProcess("Chain FORWARD (policy DROP)\n", "", 0);
          }
          return createMockChildProcess("", "", 0);
        });
        const result = await handler({ action: "verify_isolation", output_format: "json" });
        expect(result.isError).toBeUndefined();
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.forwardPolicy).toBeDefined();
      });

      it("should return JSON for audit_vlans", async () => {
        mockSpawnSafe.mockImplementation(() => createMockChildProcess("", "", 0));
        const result = await handler({ action: "audit_vlans", output_format: "json" });
        expect(result.isError).toBeUndefined();
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.vlanCount).toBeDefined();
        expect(parsed.vlans).toBeInstanceOf(Array);
      });
    });
  });
});
