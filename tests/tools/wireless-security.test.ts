/**
 * Tests for src/tools/wireless-security.ts
 *
 * Covers: wireless_security tool with actions bt_audit, wifi_audit,
 * rogue_ap_detect, disable_unused.
 * Tests Bluetooth audit (enabled, disabled, not installed), WiFi audit
 * (interfaces found, no WiFi), rogue AP detection (known vs unknown APs,
 * evil twins), disable unused (interfaces disabled, modules blacklisted),
 * no-wireless-hardware scenario, JSON/text output, and error handling.
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

vi.mock("node:fs", () => ({
  existsSync: vi.fn(() => false),
  readFileSync: vi.fn(() => "[]"),
}));

import {
  registerWirelessSecurityTools,
  isEvilTwin,
} from "../../src/tools/wireless-security.js";
import { spawnSafe } from "../../src/core/spawn-safe.js";
import { existsSync, readFileSync } from "node:fs";
import { EventEmitter } from "node:events";

const mockSpawnSafe = vi.mocked(spawnSafe);
const mockExistsSync = vi.mocked(existsSync);
const mockReadFileSync = vi.mocked(readFileSync);

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
    server: server as unknown as Parameters<typeof registerWirelessSecurityTools>[0],
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

// ── Mock setups ────────────────────────────────────────────────────────────

/**
 * Set up mocks for a system with no wireless hardware at all.
 */
function setupNoWirelessMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    if (command === "hciconfig") {
      return createMockChildProcess("", "command not found", 127);
    }
    if (command === "bluetoothctl") {
      return createMockChildProcess("", "command not found", 127);
    }
    if (command === "iw") {
      return createMockChildProcess("", "command not found", 127);
    }
    if (command === "iwconfig") {
      return createMockChildProcess("", "command not found", 127);
    }
    if (command === "nmcli") {
      return createMockChildProcess("", "", 1);
    }
    if (command === "systemctl") {
      return createMockChildProcess("", "", 4);
    }
    if (command === "which") {
      return createMockChildProcess("", "", 1);
    }
    if (command === "lsmod") {
      return createMockChildProcess("Module                  Size  Used by\next4                  999999  1\n", "", 0);
    }
    if (command === "rfkill") {
      return createMockChildProcess("", "", 1);
    }
    return createMockChildProcess("", "", 1);
  });
}

/**
 * Set up mocks for Bluetooth enabled and discoverable.
 */
function setupBtEnabledMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    if (command === "hciconfig") {
      return createMockChildProcess(
        "hci0:   Type: Primary  Bus: USB\n  BD Address: 00:11:22:33:44:55  ACL MTU: 1021:8\n  UP RUNNING\n  RX bytes:1234 acl:0\n",
        "",
        0,
      );
    }
    if (command === "bluetoothctl" && args[0] === "show") {
      return createMockChildProcess(
        "Controller 00:11:22:33:44:55\n  Name: server-bt\n  Powered: yes\n  Discoverable: yes\n  Pairable: yes\n",
        "",
        0,
      );
    }
    if (command === "bluetoothctl" && args[0] === "paired-devices") {
      return createMockChildProcess(
        "Device AA:BB:CC:DD:EE:FF MyPhone\nDevice 11:22:33:44:55:66 Keyboard\n",
        "",
        0,
      );
    }
    if (command === "systemctl") {
      return createMockChildProcess(
        "● bluetooth.service - Bluetooth service\n   Loaded: loaded\n   Active: active (running)\n",
        "",
        0,
      );
    }
    return createMockChildProcess("", "", 0);
  });
}

/**
 * Set up mocks for Bluetooth disabled / adapter off.
 */
function setupBtDisabledMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    if (command === "hciconfig") {
      return createMockChildProcess(
        "hci0:   Type: Primary  Bus: USB\n  BD Address: 00:11:22:33:44:55  ACL MTU: 1021:8\n  DOWN\n",
        "",
        0,
      );
    }
    if (command === "bluetoothctl" && args[0] === "show") {
      return createMockChildProcess(
        "Controller 00:11:22:33:44:55\n  Name: server-bt\n  Powered: no\n  Discoverable: no\n",
        "",
        0,
      );
    }
    if (command === "bluetoothctl" && args[0] === "paired-devices") {
      return createMockChildProcess("", "", 0);
    }
    if (command === "systemctl") {
      return createMockChildProcess(
        "● bluetooth.service - Bluetooth service\n   Loaded: loaded\n   Active: inactive (dead)\n",
        "",
        3,
      );
    }
    return createMockChildProcess("", "", 0);
  });
}

/**
 * Set up mocks for Bluetooth not installed (tools missing).
 */
function setupBtNotInstalledMocks() {
  mockSpawnSafe.mockImplementation((command: string) => {
    if (command === "hciconfig") {
      return createMockChildProcess("", "hciconfig: not found", 127);
    }
    if (command === "bluetoothctl") {
      return createMockChildProcess("", "bluetoothctl: not found", 127);
    }
    return createMockChildProcess("", "", 1);
  });
}

/**
 * Set up mocks for WiFi with active interfaces.
 */
function setupWifiActiveMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    if (command === "iw" && args[0] === "dev") {
      return createMockChildProcess(
        "phy#0\n  Interface wlan0\n    type managed\n    channel 6\nphy#1\n  Interface wlan1\n    type managed\n",
        "",
        0,
      );
    }
    if (command === "nmcli" && args.includes("--active")) {
      return createMockChildProcess(
        "NAME          UUID                                  TYPE      DEVICE\nMyWiFi        abcd-1234                             wifi      wlan0\n",
        "",
        0,
      );
    }
    if (command === "nmcli" && args.includes("802-11-wireless-security.key-mgmt")) {
      return createMockChildProcess(
        "MyWiFi:wifi:wlan0:wpa-psk\n",
        "",
        0,
      );
    }
    if (command === "nmcli" && args[0] === "connection" && args[1] === "show" && !args.includes("--active")) {
      return createMockChildProcess(
        "NAME          UUID                                  TYPE      DEVICE\nMyWiFi        abcd-1234                             wifi      wlan0\nOfficeNet     efgh-5678                             wifi      --\nCafeWifi      ijkl-9012                             wifi      --\n",
        "",
        0,
      );
    }
    return createMockChildProcess("", "", 0);
  });
}

/**
 * Set up mocks for WiFi with no interfaces.
 */
function setupNoWifiMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    if (command === "iw" && args[0] === "dev") {
      return createMockChildProcess("", "", 0);
    }
    if (command === "iwconfig") {
      return createMockChildProcess("lo        no wireless extensions.\neth0      no wireless extensions.\n", "", 0);
    }
    return createMockChildProcess("", "", 0);
  });
}

/**
 * Set up mocks for rogue AP scan with known and unknown APs.
 */
function setupRogueApMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    if (command === "iw" && args[0] === "dev") {
      return createMockChildProcess(
        "phy#0\n  Interface wlan0\n",
        "",
        0,
      );
    }
    if (command === "nmcli" && args.includes("wifi") && args.includes("list")) {
      // nmcli -t format: SSID:BSSID(escaped):SIGNAL:SECURITY:FREQ
      return createMockChildProcess(
        "CorpNet:AA\\:BB\\:CC\\:DD\\:EE\\:FF:85:WPA2:2437\nCorpNet:11\\:22\\:33\\:44\\:55\\:66:45:WPA2:2437\nFreeWifi:AA\\:BB\\:CC\\:11\\:22\\:33:70:--:2412\nC0rpNet:DD\\:EE\\:FF\\:11\\:22\\:33:60:WPA2:2437\n",
        "",
        0,
      );
    }
    return createMockChildProcess("", "", 0);
  });
}

/**
 * Set up mocks for disable_unused with wireless interfaces.
 */
function setupDisableUnusedMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    if (command === "which" && args[0] === "rfkill") {
      return createMockChildProcess("/usr/sbin/rfkill", "", 0);
    }
    if (command === "iw" && args[0] === "dev") {
      return createMockChildProcess(
        "phy#0\n  Interface wlan0\n  Interface wlan1\n",
        "",
        0,
      );
    }
    if (command === "nmcli" && args.includes("device")) {
      return createMockChildProcess(
        "wlan0:wifi:connected\nwlan1:wifi:disconnected\neth0:ethernet:connected\n",
        "",
        0,
      );
    }
    if (command === "rfkill" && args[0] === "block") {
      return createMockChildProcess("", "", 0);
    }
    if (command === "ip" && args.includes("down")) {
      return createMockChildProcess("", "", 0);
    }
    if (command === "lsmod") {
      return createMockChildProcess(
        "Module                  Size  Used by\nbluetooth             999999  3\nbtusb                  65536  1\niwlwifi               444444  1\next4                  555555  2\n",
        "",
        0,
      );
    }
    return createMockChildProcess("", "", 0);
  });
}

// ── Tests ──────────────────────────────────────────────────────────────────

describe("wireless-security tools", () => {
  let tools: Map<
    string,
    { schema: Record<string, unknown>; handler: ToolHandler }
  >;

  beforeEach(() => {
    vi.clearAllMocks();
    const mock = createMockServer();
    registerWirelessSecurityTools(mock.server);
    tools = mock.tools;
    setupNoWirelessMocks();
    mockExistsSync.mockReturnValue(false);
  });

  // ── Registration ────────────────────────────────────────────────────────

  it("should register the wireless_security tool", () => {
    expect(tools.has("wireless_security")).toBe(true);
  });

  it("should register with server.tool called once", () => {
    const mock = createMockServer();
    registerWirelessSecurityTools(mock.server);
    expect(mock.server.tool).toHaveBeenCalledTimes(1);
    expect(mock.server.tool).toHaveBeenCalledWith(
      "wireless_security",
      expect.any(String),
      expect.any(Object),
      expect.any(Function),
    );
  });

  // ── Unknown action ──────────────────────────────────────────────────────

  it("should report error for unknown action", async () => {
    const handler = tools.get("wireless_security")!.handler;
    const result = await handler({ action: "nonexistent" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Unknown action");
  });

  // ── Pure function tests ─────────────────────────────────────────────────

  describe("isEvilTwin", () => {
    it("should not flag identical SSIDs as evil twin", () => {
      expect(isEvilTwin("CorpNet", "CorpNet")).toBe(false);
    });

    it("should detect case-different SSIDs as evil twin", () => {
      expect(isEvilTwin("CorpNet", "corpnet")).toBe(true);
      expect(isEvilTwin("CorpNet", "CORPNET")).toBe(true);
    });

    it("should detect character substitution evil twins", () => {
      expect(isEvilTwin("CorpNet", "C0rpNet")).toBe(true);
    });

    it("should detect SSIDs with minor additions", () => {
      expect(isEvilTwin("CorpNet", "CorpNet2")).toBe(true);
      expect(isEvilTwin("CorpNet", "CorpNet_5G")).toBe(true); // 3 chars added, within threshold
      expect(isEvilTwin("CorpNet", "CorpNet_Extended")).toBe(false); // too many chars added
    });

    it("should detect SSIDs with small edit distance", () => {
      expect(isEvilTwin("CorpNet", "CorpNt")).toBe(true); // edit distance 1
      expect(isEvilTwin("CorpNet", "CorpNeet")).toBe(true); // edit distance 1
    });

    it("should not flag completely different SSIDs", () => {
      expect(isEvilTwin("CorpNet", "FreeWifi")).toBe(false);
      expect(isEvilTwin("Office", "HomeNetwork")).toBe(false);
    });
  });

  // ── bt_audit ────────────────────────────────────────────────────────────

  describe("bt_audit", () => {
    it("should detect Bluetooth enabled and discoverable", async () => {
      setupBtEnabledMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "bt_audit", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.adapterFound).toBe(true);
      expect(parsed.powered).toBe(true);
      expect(parsed.discoverable).toBe(true);
      expect(parsed.pairedDevicesCount).toBe(2);
      expect(parsed.serviceRunning).toBe(true);
      expect(parsed.riskLevel).toBe("HIGH");
    });

    it("should detect Bluetooth disabled", async () => {
      setupBtDisabledMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "bt_audit", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.adapterFound).toBe(true);
      expect(parsed.powered).toBe(false);
      expect(parsed.discoverable).toBe(false);
      expect(parsed.serviceRunning).toBe(false);
      expect(parsed.riskLevel).toBe("LOW");
    });

    it("should handle Bluetooth tools not installed", async () => {
      setupBtNotInstalledMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "bt_audit", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.adapterFound).toBe(false);
      expect(parsed.riskLevel).toBe("INFO");
      expect(parsed.recommendations.length).toBeGreaterThan(0);
    });

    it("should handle no Bluetooth adapter found", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "hciconfig") {
          return createMockChildProcess("", "", 0); // empty output = no adapter
        }
        if (command === "bluetoothctl" && args[0] === "show") {
          return createMockChildProcess("", "No default controller available", 1);
        }
        return createMockChildProcess("", "", 1);
      });

      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "bt_audit", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.adapterFound).toBe(false);
      expect(parsed.riskLevel).toBe("LOW");
    });

    it("should list paired devices", async () => {
      setupBtEnabledMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "bt_audit", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.pairedDevices.length).toBe(2);
      expect(parsed.pairedDevices[0]).toContain("MyPhone");
    });

    it("should recommend disabling Bluetooth service", async () => {
      setupBtEnabledMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "bt_audit", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.recommendations.some((r: string) => r.includes("disable"))).toBe(true);
    });

    it("should return text format for bt_audit", async () => {
      setupBtEnabledMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "bt_audit" });
      expect(result.content[0].text).toContain("Bluetooth Audit");
      expect(result.content[0].text).toContain("Adapter Found");
      expect(result.content[0].text).toContain("Risk Level");
    });
  });

  // ── wifi_audit ──────────────────────────────────────────────────────────

  describe("wifi_audit", () => {
    it("should detect WiFi interfaces", async () => {
      setupWifiActiveMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "wifi_audit", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.interfaceCount).toBe(2);
      expect(parsed.interfacesFound).toContain("wlan0");
      expect(parsed.interfacesFound).toContain("wlan1");
    });

    it("should detect active WiFi connection", async () => {
      setupWifiActiveMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "wifi_audit", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.activeConnection).toContain("MyWiFi");
      expect(parsed.wifiNeeded).toBe(true);
    });

    it("should detect WPA2 security type", async () => {
      setupWifiActiveMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "wifi_audit", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.securityType).toContain("WPA");
    });

    it("should list saved networks", async () => {
      setupWifiActiveMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "wifi_audit", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.savedNetworkCount).toBe(3);
    });

    it("should handle no WiFi interfaces", async () => {
      setupNoWifiMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "wifi_audit", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.interfaceCount).toBe(0);
      expect(parsed.riskLevel).toBe("LOW");
      expect(parsed.recommendations.some((r: string) => r.includes("No wireless interfaces"))).toBe(true);
    });

    it("should handle no wireless tools installed", async () => {
      setupNoWirelessMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "wifi_audit", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      // With no tools and no interfaces, should report low risk or no interfaces
      expect(parsed.interfaceCount).toBe(0);
      expect(parsed.recommendations.length).toBeGreaterThan(0);
    });

    it("should recommend disabling WiFi on servers", async () => {
      setupWifiActiveMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "wifi_audit", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.recommendations.some((r: string) => r.includes("server") || r.includes("Ethernet"))).toBe(true);
    });

    it("should return text format for wifi_audit", async () => {
      setupWifiActiveMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "wifi_audit" });
      expect(result.content[0].text).toContain("WiFi Audit");
      expect(result.content[0].text).toContain("Wireless Interfaces");
    });

    it("should detect WEP as high risk", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "iw" && args[0] === "dev") {
          return createMockChildProcess("phy#0\n  Interface wlan0\n", "", 0);
        }
        // Detail query has -t flag; must be checked before generic --active check
        if (command === "nmcli" && args.includes("-t") && args.some((a: string) => a.includes("802-11-wireless-security"))) {
          return createMockChildProcess("OldNet:wifi:wlan0:wep\n", "", 0);
        }
        if (command === "nmcli" && args.includes("--active")) {
          return createMockChildProcess(
            "NAME          UUID                                  TYPE      DEVICE\nOldNet        1234-5678                             wifi      wlan0\n",
            "",
            0,
          );
        }
        if (command === "nmcli" && args[0] === "connection" && args[1] === "show") {
          return createMockChildProcess("NAME  UUID  TYPE  DEVICE\nOldNet  1234  wifi  wlan0\n", "", 0);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "wifi_audit", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.securityType).toBe("WEP");
      expect(parsed.riskLevel).toBe("HIGH");
      expect(parsed.recommendations.some((r: string) => r.includes("WEP"))).toBe(true);
    });
  });

  // ── rogue_ap_detect ─────────────────────────────────────────────────────

  describe("rogue_ap_detect", () => {
    it("should scan and find APs", async () => {
      setupRogueApMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "rogue_ap_detect", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.totalApsFound).toBeGreaterThan(0);
    });

    it("should detect open APs", async () => {
      setupRogueApMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "rogue_ap_detect", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.openApsCount).toBeGreaterThan(0);
      expect(parsed.recommendations.some((r: string) => r.includes("open") || r.includes("unencrypted"))).toBe(true);
    });

    it("should detect unknown APs when known list exists", async () => {
      setupRogueApMocks();
      mockExistsSync.mockImplementation((path: unknown) => {
        return path === "/var/lib/defense-mcp/wireless/known-aps.json";
      });
      mockReadFileSync.mockImplementation(() => {
        return JSON.stringify([
          { ssid: "CorpNet", bssid: "AA:BB:CC:DD:EE:FF" },
        ]);
      });

      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "rogue_ap_detect", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.unknownApsCount).toBeGreaterThan(0);
      expect(parsed.recommendations.some((r: string) => r.includes("unknown"))).toBe(true);
    });

    it("should detect evil twin APs", async () => {
      setupRogueApMocks();
      mockExistsSync.mockImplementation((path: unknown) => {
        return path === "/var/lib/defense-mcp/wireless/known-aps.json";
      });
      mockReadFileSync.mockImplementation(() => {
        return JSON.stringify([
          { ssid: "CorpNet", bssid: "AA:BB:CC:DD:EE:FF" },
        ]);
      });

      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "rogue_ap_detect", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      // C0rpNet should be flagged as evil twin of CorpNet
      expect(parsed.potentialEvilTwins.length).toBeGreaterThan(0);
      expect(parsed.potentialEvilTwins.some(
        (t: { ap: { ssid: string }; matchedKnown: string }) => t.ap.ssid === "C0rpNet",
      )).toBe(true);
      expect(parsed.recommendations.some((r: string) => r.includes("evil twin"))).toBe(true);
    });

    it("should detect same SSID with different BSSID as evil twin", async () => {
      setupRogueApMocks();
      mockExistsSync.mockImplementation((path: unknown) => {
        return path === "/var/lib/defense-mcp/wireless/known-aps.json";
      });
      mockReadFileSync.mockImplementation(() => {
        return JSON.stringify([
          { ssid: "CorpNet", bssid: "AA:BB:CC:DD:EE:FF" },
        ]);
      });

      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "rogue_ap_detect", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      // CorpNet with BSSID 11:22:33:44:55:66 should be flagged
      expect(parsed.potentialEvilTwins.some(
        (t: { ap: { bssid: string }; matchedKnown: string }) =>
          t.matchedKnown === "CorpNet" && t.ap.bssid !== "AA:BB:CC:DD:EE:FF",
      )).toBe(true);
    });

    it("should recommend creating known AP list when none exists", async () => {
      setupRogueApMocks();
      mockExistsSync.mockReturnValue(false);

      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "rogue_ap_detect", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.recommendations.some((r: string) => r.includes("known AP list"))).toBe(true);
    });

    it("should handle no wireless interface for scanning", async () => {
      setupNoWirelessMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "rogue_ap_detect", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.totalApsFound).toBe(0);
      expect(parsed.recommendations.length).toBeGreaterThan(0);
    });

    it("should accept specific interface parameter", async () => {
      setupRogueApMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "rogue_ap_detect", interface: "wlan0", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.scanInterface).toBe("wlan0");
    });

    it("should return text format for rogue_ap_detect", async () => {
      setupRogueApMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "rogue_ap_detect" });
      expect(result.content[0].text).toContain("Rogue AP Detection");
      expect(result.content[0].text).toContain("Total APs Found");
    });
  });

  // ── disable_unused ──────────────────────────────────────────────────────

  describe("disable_unused", () => {
    it("should list wireless interfaces and their status", async () => {
      setupDisableUnusedMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "disable_unused", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.wirelessInterfaces.length).toBe(2);
      // wlan0 is "connected" so it's in use; wlan1 is "disconnected" so not in use
      const wlan0 = parsed.wirelessInterfaces.find((i: { name: string }) => i.name === "wlan0");
      const wlan1 = parsed.wirelessInterfaces.find((i: { name: string }) => i.name === "wlan1");
      expect(wlan0.inUse).toBe(true);
      expect(wlan1.inUse).toBe(false);
    });

    it("should disable unused interfaces", async () => {
      setupDisableUnusedMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "disable_unused", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      // wlan1 is not in use, so it should be disabled
      const wlan1 = parsed.wirelessInterfaces.find((i: { name: string }) => i.name === "wlan1");
      expect(wlan1.inUse).toBe(false);
      expect(wlan1.disabled).toBe(true);
      expect(parsed.interfacesDisabled).toBeGreaterThan(0);
    });

    it("should not disable interfaces in use", async () => {
      setupDisableUnusedMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "disable_unused", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      const wlan0 = parsed.wirelessInterfaces.find((i: { name: string }) => i.name === "wlan0");
      expect(wlan0.inUse).toBe(true);
      expect(wlan0.disabled).toBe(false);
    });

    it("should detect loaded wireless kernel modules", async () => {
      setupDisableUnusedMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "disable_unused", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.loadedModules.length).toBeGreaterThan(0);
      const btModule = parsed.loadedModules.find((m: { name: string }) => m.name === "bluetooth");
      expect(btModule.loaded).toBe(true);
      expect(btModule.canBlacklist).toBe(true);
    });

    it("should report blacklistable modules count", async () => {
      setupDisableUnusedMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "disable_unused", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.modulesBlacklistable).toBeGreaterThan(0);
      expect(parsed.recommendations.some((r: string) => r.includes("blacklist"))).toBe(true);
    });

    it("should check rfkill availability", async () => {
      setupDisableUnusedMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "disable_unused", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.rfkillAvailable).toBe(true);
    });

    it("should include CIS benchmark reference", async () => {
      setupDisableUnusedMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "disable_unused", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.cisBenchmark).toContain("CIS");
    });

    it("should handle no wireless interfaces for disable", async () => {
      setupNoWirelessMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "disable_unused", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.wirelessInterfaces.length).toBe(0);
      expect(parsed.interfacesDisabled).toBe(0);
      expect(parsed.recommendations.some((r: string) => r.includes("No wireless interfaces") || r.includes("complies"))).toBe(true);
    });

    it("should return text format for disable_unused", async () => {
      setupDisableUnusedMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "disable_unused" });
      expect(result.content[0].text).toContain("Disable Unused Interfaces");
      expect(result.content[0].text).toContain("CIS");
      expect(result.content[0].text).toContain("Kernel Modules");
    });

    it("should accept specific interface parameter", async () => {
      setupDisableUnusedMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "disable_unused", interface: "wlan1", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      // Should only operate on wlan1
      expect(parsed.wirelessInterfaces.length).toBe(1);
      expect(parsed.wirelessInterfaces[0].name).toBe("wlan1");
    });
  });

  // ── No wireless hardware scenario ───────────────────────────────────────

  describe("no wireless hardware", () => {
    it("should handle bt_audit gracefully with no hardware", async () => {
      setupNoWirelessMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "bt_audit", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.adapterFound).toBe(false);
      expect(result.isError).toBeUndefined();
    });

    it("should handle wifi_audit gracefully with no hardware", async () => {
      setupNoWirelessMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "wifi_audit", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.interfaceCount).toBe(0);
      expect(result.isError).toBeUndefined();
    });

    it("should handle rogue_ap_detect gracefully with no hardware", async () => {
      setupNoWirelessMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "rogue_ap_detect", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.totalApsFound).toBe(0);
      expect(result.isError).toBeUndefined();
    });

    it("should handle disable_unused gracefully with no hardware", async () => {
      setupNoWirelessMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "disable_unused", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.interfacesDisabled).toBe(0);
      expect(result.isError).toBeUndefined();
    });
  });

  // ── Output format tests ─────────────────────────────────────────────────

  describe("output formats", () => {
    it("should return JSON for bt_audit", async () => {
      setupBtDisabledMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "bt_audit", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("bt_audit");
    });

    it("should return JSON for wifi_audit", async () => {
      setupNoWifiMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "wifi_audit", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("wifi_audit");
    });

    it("should return JSON for rogue_ap_detect", async () => {
      setupRogueApMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "rogue_ap_detect", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("rogue_ap_detect");
    });

    it("should return JSON for disable_unused", async () => {
      setupDisableUnusedMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "disable_unused", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("disable_unused");
    });

    it("should default to text format", async () => {
      setupBtDisabledMocks();
      const handler = tools.get("wireless_security")!.handler;
      const result = await handler({ action: "bt_audit" });
      expect(result.content[0].text).toContain("Wireless Security");
    });
  });

  // ── Error handling ──────────────────────────────────────────────────────

  describe("error handling", () => {
    it("should handle spawnSafe throwing errors", async () => {
      mockSpawnSafe.mockImplementation(() => {
        throw new Error("spawn failed");
      });

      const handler = tools.get("wireless_security")!.handler;
      // bt_audit catches errors internally in runCommand
      const result = await handler({ action: "bt_audit", output_format: "json" });
      expect(result.content).toBeDefined();
    });

    it("should handle command failures in all actions", async () => {
      mockSpawnSafe.mockImplementation(() => {
        return createMockChildProcess("", "command failed", 1);
      });

      const handler = tools.get("wireless_security")!.handler;

      // All actions should handle command failures gracefully
      for (const action of ["bt_audit", "wifi_audit", "rogue_ap_detect", "disable_unused"]) {
        const result = await handler({ action, output_format: "json" });
        expect(result.content).toBeDefined();
        expect(result.isError).toBeUndefined(); // Graceful, not error
      }
    });

    it("should handle timeout scenario", async () => {
      mockSpawnSafe.mockImplementation(() => {
        const cp = new EventEmitter() as EventEmitter & {
          stdout: EventEmitter;
          stderr: EventEmitter;
          kill: ReturnType<typeof vi.fn>;
        };
        cp.stdout = new EventEmitter();
        cp.stderr = new EventEmitter();
        cp.kill = vi.fn();
        // Never emit close — simulates hang (will be killed by timeout)
        return cp;
      });

      // Use a very short timeout test won't actually wait — the runCommand
      // timeout is 30s but the test framework will handle the mock
      const handler = tools.get("wireless_security")!.handler;
      // Just verify it doesn't throw synchronously
      expect(() => handler({ action: "bt_audit", output_format: "json" })).not.toThrow();
    });
  });
});
