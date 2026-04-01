/**
 * Wireless security tools for Defense MCP Server.
 *
 * Registers 1 tool: wireless_security (actions: bt_audit, wifi_audit,
 * rogue_ap_detect, disable_unused)
 *
 * Provides Bluetooth adapter auditing, WiFi configuration assessment,
 * rogue access point detection with evil twin analysis, and unused
 * wireless interface disabling with kernel module blacklist recommendations.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { runCommand } from "../core/run-command.js";
import {
  createTextContent,
  createErrorContent,
  formatToolOutput,
} from "../core/parsers.js";
import { existsSync, readFileSync } from "node:fs";

// ── Constants ──────────────────────────────────────────────────────────────────

/** Path to known APs configuration file */
const KNOWN_APS_PATH = "/var/lib/defense-mcp/wireless/known-aps.json";

/** Wireless kernel modules that can be blacklisted */
const WIRELESS_MODULES = ["bluetooth", "btusb", "iwlwifi", "ath9k", "ath10k_pci", "rt2800usb"];

// ── Types ──────────────────────────────────────────────────────────────────────

interface KnownAp {
  ssid: string;
  bssid?: string;
  security?: string;
}

// ── Helpers ────────────────────────────────────────────────────────────────────


/**
 * Load known APs from the configuration file.
 * Returns empty array if file doesn't exist or is invalid.
 */
function loadKnownAps(): KnownAp[] {
  try {
    if (existsSync(KNOWN_APS_PATH)) {
      const data = readFileSync(KNOWN_APS_PATH, "utf-8");
      const parsed = JSON.parse(data);
      if (Array.isArray(parsed)) return parsed as KnownAp[];
      if (parsed && Array.isArray(parsed.aps)) return parsed.aps as KnownAp[];
    }
  } catch {
    // Fall through to default
  }
  return [];
}

/**
 * Check if two SSIDs are similar enough to be an evil twin.
 * Considers: exact match, case differences, character substitutions,
 * appended/prepended characters.
 */
export function isEvilTwin(knownSsid: string, candidateSsid: string): boolean {
  if (knownSsid === candidateSsid) return false; // same SSID is not evil twin
  const kLower = knownSsid.toLowerCase();
  const cLower = candidateSsid.toLowerCase();

  // Case-insensitive exact match
  if (kLower === cLower) return true;

  // One is a substring of the other with minor additions
  if (cLower.includes(kLower) || kLower.includes(cLower)) {
    const lenDiff = Math.abs(kLower.length - cLower.length);
    if (lenDiff <= 3) return true;
  }

  // Levenshtein distance <= 2 for short SSIDs
  if (kLower.length <= 20 && cLower.length <= 20) {
    const dist = levenshteinDistance(kLower, cLower);
    if (dist <= 2) return true;
  }

  // Common substitutions (0 for O, 1 for l, etc.)
  const normalized = cLower
    .replace(/0/g, "o")
    .replace(/1/g, "l")
    .replace(/3/g, "e")
    .replace(/5/g, "s");
  const knownNormalized = kLower
    .replace(/0/g, "o")
    .replace(/1/g, "l")
    .replace(/3/g, "e")
    .replace(/5/g, "s");
  if (normalized === knownNormalized && kLower !== cLower) return true;

  return false;
}

/**
 * Simple Levenshtein distance implementation.
 */
function levenshteinDistance(a: string, b: string): number {
  const matrix: number[][] = [];
  for (let i = 0; i <= a.length; i++) {
    matrix[i] = [i];
  }
  for (let j = 0; j <= b.length; j++) {
    matrix[0][j] = j;
  }
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,
        matrix[i][j - 1] + 1,
        matrix[i - 1][j - 1] + cost,
      );
    }
  }
  return matrix[a.length][b.length];
}

// ── Action implementations ─────────────────────────────────────────────────────

interface BtAuditResult {
  adapterFound: boolean;
  adapterStatus: string;
  powered: boolean;
  discoverable: boolean;
  pairedDevices: string[];
  pairedDevicesCount: number;
  serviceRunning: boolean;
  serviceStatus: string;
  riskLevel: "LOW" | "MEDIUM" | "HIGH" | "INFO";
  recommendations: string[];
}

async function btAudit(): Promise<BtAuditResult> {
  const result: BtAuditResult = {
    adapterFound: false,
    adapterStatus: "not found",
    powered: false,
    discoverable: false,
    pairedDevices: [],
    pairedDevicesCount: 0,
    serviceRunning: false,
    serviceStatus: "unknown",
    riskLevel: "INFO",
    recommendations: [],
  };

  // Check if Bluetooth adapter exists via hciconfig
  const hciResult = await runCommand("hciconfig", ["-a"], 10_000);
  if (hciResult.exitCode === 0 && hciResult.stdout.trim().length > 0) {
    result.adapterFound = true;
    result.adapterStatus = hciResult.stdout.trim().includes("UP RUNNING")
      ? "up and running"
      : hciResult.stdout.trim().includes("DOWN")
        ? "down"
        : "present";
    result.powered = hciResult.stdout.includes("UP RUNNING");
  } else {
    // Try bluetoothctl as fallback
    const btctlResult = await runCommand("bluetoothctl", ["show"], 10_000);
    if (btctlResult.exitCode === 0 && btctlResult.stdout.trim().length > 0) {
      result.adapterFound = true;
      result.powered = btctlResult.stdout.includes("Powered: yes");
      result.adapterStatus = result.powered ? "powered on" : "powered off";
      result.discoverable = btctlResult.stdout.includes("Discoverable: yes");
    } else if (
      hciResult.stderr.includes("not found") ||
      hciResult.stderr.includes("No such file") ||
      btctlResult.stderr.includes("not found")
    ) {
      // No bluetooth tools installed
      result.adapterStatus = "no bluetooth tools installed";
      result.riskLevel = "INFO";
      result.recommendations.push("Bluetooth tools not installed — no Bluetooth audit possible");
      return result;
    }
  }

  if (!result.adapterFound) {
    result.adapterStatus = "no adapter found";
    result.riskLevel = "LOW";
    result.recommendations.push("No Bluetooth adapter detected — low risk");
    return result;
  }

  // Check discoverability via bluetoothctl if not already checked
  if (!result.discoverable) {
    const discoverResult = await runCommand("bluetoothctl", ["show"], 10_000);
    if (discoverResult.exitCode === 0) {
      result.discoverable = discoverResult.stdout.includes("Discoverable: yes");
    }
  }

  // List paired devices
  const pairedResult = await runCommand("bluetoothctl", ["paired-devices"], 10_000);
  if (pairedResult.exitCode === 0 && pairedResult.stdout.trim().length > 0) {
    result.pairedDevices = pairedResult.stdout
      .trim()
      .split("\n")
      .filter((l) => l.trim().length > 0);
    result.pairedDevicesCount = result.pairedDevices.length;
  }

  // Check Bluetooth service status
  const serviceResult = await runCommand("systemctl", ["status", "bluetooth"], 10_000);
  if (serviceResult.exitCode === 0 || serviceResult.exitCode === 3) {
    result.serviceStatus = serviceResult.stdout.trim();
    result.serviceRunning = serviceResult.stdout.includes("active (running)");
  }

  // Determine risk level and recommendations
  if (result.powered) {
    result.riskLevel = "MEDIUM";
    result.recommendations.push("Bluetooth is enabled — disable if not needed (especially on servers)");
  }

  if (result.discoverable) {
    result.riskLevel = "HIGH";
    result.recommendations.push("CRITICAL: Bluetooth is discoverable — disable discoverability immediately");
  }

  if (result.pairedDevicesCount > 0) {
    result.recommendations.push(`${result.pairedDevicesCount} paired device(s) found — review and remove unnecessary pairings`);
  }

  if (result.serviceRunning) {
    result.recommendations.push("Bluetooth service is running — consider disabling: systemctl disable --now bluetooth");
  }

  if (!result.powered && !result.serviceRunning) {
    result.riskLevel = "LOW";
  }

  return result;
}

interface WifiAuditResult {
  interfacesFound: string[];
  interfaceCount: number;
  activeConnection: string;
  securityType: string;
  savedNetworks: string[];
  savedNetworkCount: number;
  wifiNeeded: boolean;
  riskLevel: "LOW" | "MEDIUM" | "HIGH" | "INFO";
  recommendations: string[];
}

async function wifiAudit(_iface?: string): Promise<WifiAuditResult> {
  const result: WifiAuditResult = {
    interfacesFound: [],
    interfaceCount: 0,
    activeConnection: "none",
    securityType: "unknown",
    savedNetworks: [],
    savedNetworkCount: 0,
    wifiNeeded: false,
    riskLevel: "INFO",
    recommendations: [],
  };

  // List wireless interfaces via iw dev
  const iwResult = await runCommand("iw", ["dev"], 10_000);
  if (iwResult.exitCode === 0 && iwResult.stdout.trim().length > 0) {
    const ifaceMatches = iwResult.stdout.match(/Interface\s+(\S+)/g);
    if (ifaceMatches) {
      result.interfacesFound = ifaceMatches.map((m) => m.replace("Interface ", "").trim());
    }
  } else {
    // Fallback to iwconfig
    const iwconfigResult = await runCommand("iwconfig", [], 10_000);
    if (iwconfigResult.exitCode === 0) {
      const lines = iwconfigResult.stdout.split("\n");
      for (const line of lines) {
        if (line.includes("IEEE 802.11") || line.includes("ESSID")) {
          const match = line.match(/^(\S+)/);
          if (match) result.interfacesFound.push(match[1]);
        }
      }
    } else if (
      iwResult.stderr.includes("not found") &&
      iwconfigResult.stderr.includes("not found")
    ) {
      result.recommendations.push("No wireless tools installed (iw, iwconfig) — cannot audit WiFi");
      return result;
    }
  }

  result.interfaceCount = result.interfacesFound.length;

  if (result.interfaceCount === 0) {
    result.riskLevel = "LOW";
    result.recommendations.push("No wireless interfaces found — low risk");
    return result;
  }

  // Check active connection via nmcli
  const nmcliActiveResult = await runCommand("nmcli", ["connection", "show", "--active"], 10_000);
  if (nmcliActiveResult.exitCode === 0 && nmcliActiveResult.stdout.trim().length > 0) {
    const lines = nmcliActiveResult.stdout.trim().split("\n");
    for (const line of lines) {
      if (line.includes("wifi") || line.includes("wireless")) {
        result.activeConnection = line.trim();
        result.wifiNeeded = true;
      }
    }
  }

  // Check WiFi security type
  if (result.activeConnection !== "none") {
    const nmcliDetailResult = await runCommand(
      "nmcli", ["-t", "-f", "NAME,TYPE,DEVICE,802-11-wireless-security.key-mgmt", "connection", "show", "--active"],
      10_000,
    );
    if (nmcliDetailResult.exitCode === 0) {
      const output = nmcliDetailResult.stdout;
      if (output.includes("wpa-psk") || output.includes("wpa-eap")) {
        result.securityType = "WPA2/WPA3";
      } else if (output.includes("wep")) {
        result.securityType = "WEP";
        result.riskLevel = "HIGH";
        result.recommendations.push("CRITICAL: Using WEP encryption — upgrade to WPA2/WPA3 immediately");
      } else if (output.includes("sae")) {
        result.securityType = "WPA3-SAE";
      } else if (output.includes("none") || output.includes("open")) {
        result.securityType = "Open/None";
        result.riskLevel = "HIGH";
        result.recommendations.push("CRITICAL: Connected to an open network with no encryption");
      } else {
        result.securityType = "WPA2/WPA3";
      }
    }
  }

  // Check saved networks
  const savedResult = await runCommand("nmcli", ["connection", "show"], 10_000);
  if (savedResult.exitCode === 0 && savedResult.stdout.trim().length > 0) {
    const lines = savedResult.stdout.trim().split("\n").slice(1); // skip header
    for (const line of lines) {
      if (line.includes("wifi") || line.includes("wireless")) {
        result.savedNetworks.push(line.trim());
      }
    }
    result.savedNetworkCount = result.savedNetworks.length;
  }

  // Recommendations
  if (result.interfaceCount > 0 && !result.wifiNeeded) {
    result.riskLevel = result.riskLevel === "HIGH" ? "HIGH" : "MEDIUM";
    result.recommendations.push("WiFi interfaces found but no active connection — consider disabling if not needed");
  }

  if (result.savedNetworkCount > 5) {
    result.recommendations.push(`${result.savedNetworkCount} saved WiFi networks — review and remove unnecessary entries`);
  }

  result.recommendations.push("Servers typically should not use WiFi — use wired Ethernet for production systems");

  return result;
}

interface AccessPoint {
  ssid: string;
  bssid: string;
  signal: string;
  security: string;
  frequency: string;
}

interface RogueApResult {
  totalApsFound: number;
  aps: AccessPoint[];
  knownAps: string[];
  unknownAps: AccessPoint[];
  openAps: AccessPoint[];
  potentialEvilTwins: Array<{ ap: AccessPoint; matchedKnown: string }>;
  scanInterface: string;
  recommendations: string[];
}

async function rogueApDetect(iface?: string): Promise<RogueApResult> {
  const result: RogueApResult = {
    totalApsFound: 0,
    aps: [],
    knownAps: [],
    unknownAps: [],
    openAps: [],
    potentialEvilTwins: [],
    scanInterface: iface ?? "auto",
    recommendations: [],
  };

  // Determine interface to scan
  let scanIface = iface;
  if (!scanIface) {
    const iwResult = await runCommand("iw", ["dev"], 10_000);
    if (iwResult.exitCode === 0) {
      const match = iwResult.stdout.match(/Interface\s+(\S+)/);
      if (match) scanIface = match[1];
    }
  }

  // Scan using nmcli device wifi list (more reliable, doesn't need root)
  const scanResult = await runCommand(
    "nmcli", ["-t", "-f", "SSID,BSSID,SIGNAL,SECURITY,FREQ", "device", "wifi", "list"],
    30_000,
  );

  if (scanResult.exitCode === 0 && scanResult.stdout.trim().length > 0) {
    const lines = scanResult.stdout.trim().split("\n");
    for (const line of lines) {
      const parts = line.split(":");
      if (parts.length >= 5) {
        // nmcli -t uses : as separator; BSSID contains \ escaped colons
        // Reassemble BSSID from parts
        const ssid = parts[0].trim();
        // BSSID is in parts 1-6 (MAC address with escaped colons)
        const bssidParts = parts.slice(1, 7);
        const bssid = bssidParts.join(":").replace(/\\\\/g, "").trim();
        const remaining = parts.slice(7);
        const signal = remaining[0]?.trim() ?? "";
        const security = remaining[1]?.trim() ?? "";
        const frequency = remaining[2]?.trim() ?? "";

        if (ssid || bssid) {
          result.aps.push({ ssid, bssid, signal, security, frequency });
        }
      }
    }
  } else if (scanIface) {
    // Fallback: use iw scan (needs root)
    const iwScanResult = await runCommand("iw", ["dev", scanIface, "scan"], 30_000);
    if (iwScanResult.exitCode === 0) {
      let currentAp: Partial<AccessPoint> = {};
      const lines = iwScanResult.stdout.split("\n");
      for (const line of lines) {
        const bssidMatch = line.match(/BSS\s+([0-9a-fA-F:]+)/);
        if (bssidMatch) {
          if (currentAp.bssid) {
            result.aps.push({
              ssid: currentAp.ssid ?? "",
              bssid: currentAp.bssid,
              signal: currentAp.signal ?? "",
              security: currentAp.security ?? "Open",
              frequency: currentAp.frequency ?? "",
            });
          }
          currentAp = { bssid: bssidMatch[1] };
        }
        const ssidMatch = line.match(/SSID:\s*(.+)/);
        if (ssidMatch) currentAp.ssid = ssidMatch[1].trim();
        const signalMatch = line.match(/signal:\s*(.+)/);
        if (signalMatch) currentAp.signal = signalMatch[1].trim();
        const freqMatch = line.match(/freq:\s*(\d+)/);
        if (freqMatch) currentAp.frequency = freqMatch[1];
        if (line.includes("WPA") || line.includes("RSN")) {
          currentAp.security = line.includes("RSN") ? "WPA2" : "WPA";
        }
      }
      // Push last AP
      if (currentAp.bssid) {
        result.aps.push({
          ssid: currentAp.ssid ?? "",
          bssid: currentAp.bssid,
          signal: currentAp.signal ?? "",
          security: currentAp.security ?? "Open",
          frequency: currentAp.frequency ?? "",
        });
      }
    } else {
      result.recommendations.push("WiFi scan failed — may need root privileges or wireless tools installed");
      return result;
    }
  } else {
    result.recommendations.push("No wireless interface available for scanning");
    return result;
  }

  result.totalApsFound = result.aps.length;

  if (result.totalApsFound === 0) {
    result.recommendations.push("No access points found — interface may not support scanning");
    return result;
  }

  // Load known APs
  const knownAps = loadKnownAps();
  result.knownAps = knownAps.map((ap) => ap.ssid);

  // Classify APs
  for (const ap of result.aps) {
    // Check if open (no security)
    if (!ap.security || ap.security === "" || ap.security.toLowerCase() === "open" || ap.security === "--") {
      result.openAps.push(ap);
    }

    // Check if unknown
    if (knownAps.length > 0) {
      const isKnown = knownAps.some(
        (known) =>
          known.ssid === ap.ssid &&
          (!known.bssid || known.bssid === ap.bssid),
      );
      if (!isKnown) {
        result.unknownAps.push(ap);
      }

      // Check for evil twins
      for (const known of knownAps) {
        if (isEvilTwin(known.ssid, ap.ssid)) {
          result.potentialEvilTwins.push({ ap, matchedKnown: known.ssid });
        }
        // Also flag if same SSID but different BSSID
        if (known.ssid === ap.ssid && known.bssid && known.bssid !== ap.bssid) {
          result.potentialEvilTwins.push({ ap, matchedKnown: known.ssid });
        }
      }
    }
  }

  // Recommendations
  if (result.openAps.length > 0) {
    result.recommendations.push(`${result.openAps.length} open (unencrypted) AP(s) detected — avoid connecting`);
  }

  if (result.unknownAps.length > 0) {
    result.recommendations.push(`${result.unknownAps.length} unknown AP(s) detected — review for unauthorized devices`);
  }

  if (result.potentialEvilTwins.length > 0) {
    result.recommendations.push(`WARNING: ${result.potentialEvilTwins.length} potential evil twin(s) detected — investigate immediately`);
  }

  if (knownAps.length === 0) {
    result.recommendations.push(`No known AP list found at ${KNOWN_APS_PATH} — create one to enable evil twin detection`);
  }

  return result;
}

interface DisableUnusedResult {
  wirelessInterfaces: Array<{ name: string; inUse: boolean; disabled: boolean }>;
  loadedModules: Array<{ name: string; loaded: boolean; canBlacklist: boolean }>;
  interfacesDisabled: number;
  modulesBlacklistable: number;
  rfkillAvailable: boolean;
  cisBenchmark: string;
  recommendations: string[];
}

async function disableUnused(iface?: string): Promise<DisableUnusedResult> {
  const result: DisableUnusedResult = {
    wirelessInterfaces: [],
    loadedModules: [],
    interfacesDisabled: 0,
    modulesBlacklistable: 0,
    rfkillAvailable: false,
    cisBenchmark: "CIS Benchmark 3.1.2 — Ensure wireless interfaces are disabled",
    recommendations: [],
  };

  // Check rfkill availability
  const rfkillCheck = await runCommand("which", ["rfkill"], 5_000);
  result.rfkillAvailable = rfkillCheck.exitCode === 0;

  // List all wireless interfaces
  const iwResult = await runCommand("iw", ["dev"], 10_000);
  const interfaces: string[] = [];

  if (iwResult.exitCode === 0 && iwResult.stdout.trim().length > 0) {
    const ifaceMatches = iwResult.stdout.match(/Interface\s+(\S+)/g);
    if (ifaceMatches) {
      for (const m of ifaceMatches) {
        interfaces.push(m.replace("Interface ", "").trim());
      }
    }
  }

  // Check active connections to determine which interfaces are in use
  const nmcliResult = await runCommand("nmcli", ["-t", "-f", "DEVICE,TYPE,STATE", "device"], 10_000);
  const activeDevices = new Set<string>();
  if (nmcliResult.exitCode === 0) {
    const lines = nmcliResult.stdout.trim().split("\n");
    for (const line of lines) {
      const parts = line.split(":");
      if (parts.length >= 3 && parts[2]?.trim() === "connected") {
        activeDevices.add(parts[0].trim());
      }
    }
  }

  // If a specific interface is requested, filter to just that one
  const targetInterfaces = iface ? [iface] : interfaces;

  for (const ifaceName of targetInterfaces) {
    const inUse = activeDevices.has(ifaceName);
    let disabled = false;

    if (!inUse) {
      // Try to disable via rfkill
      if (result.rfkillAvailable) {
        const rfkillResult = await runCommand("rfkill", ["block", ifaceName], 10_000);
        if (rfkillResult.exitCode === 0) {
          disabled = true;
          result.interfacesDisabled++;
        } else {
          // Try ip link set down as fallback
          const ipResult = await runCommand("ip", ["link", "set", ifaceName, "down"], 10_000);
          disabled = ipResult.exitCode === 0;
          if (disabled) result.interfacesDisabled++;
        }
      } else {
        // Try ip link set down
        const ipResult = await runCommand("ip", ["link", "set", ifaceName, "down"], 10_000);
        disabled = ipResult.exitCode === 0;
        if (disabled) result.interfacesDisabled++;
      }
    }

    result.wirelessInterfaces.push({ name: ifaceName, inUse, disabled });
  }

  // Check loaded wireless kernel modules
  const lsmodResult = await runCommand("lsmod", [], 10_000);
  if (lsmodResult.exitCode === 0) {
    const lsmodOutput = lsmodResult.stdout;
    for (const modName of WIRELESS_MODULES) {
      const loaded = new RegExp(`^${modName}\\s`, "m").test(lsmodOutput);
      const canBlacklist = loaded;
      result.loadedModules.push({ name: modName, loaded, canBlacklist });
      if (canBlacklist) result.modulesBlacklistable++;
    }
  } else {
    result.recommendations.push("lsmod not available — cannot check loaded kernel modules");
  }

  // Recommendations
  if (result.wirelessInterfaces.length === 0 && interfaces.length === 0) {
    result.recommendations.push("No wireless interfaces found — system complies with CIS wireless requirements");
  }

  for (const wi of result.wirelessInterfaces) {
    if (wi.inUse) {
      result.recommendations.push(`Interface ${wi.name} is in use — cannot disable while active`);
    } else if (wi.disabled) {
      result.recommendations.push(`Interface ${wi.name} disabled successfully`);
    } else {
      result.recommendations.push(`Failed to disable interface ${wi.name} — may need root privileges`);
    }
  }

  if (result.modulesBlacklistable > 0) {
    const moduleNames = result.loadedModules
      .filter((m) => m.canBlacklist)
      .map((m) => m.name)
      .join(", ");
    result.recommendations.push(
      `${result.modulesBlacklistable} wireless module(s) loaded (${moduleNames}) — ` +
      "consider blacklisting in /etc/modprobe.d/disable-wireless.conf",
    );
  }

  return result;
}

// ── Registration entry point ───────────────────────────────────────────────

export function registerWirelessSecurityTools(server: McpServer): void {
  server.tool(
    "wireless_security",
    "Wireless: Bluetooth audit, WiFi assessment, rogue AP detection, disable unused interfaces",
    {
      action: z
        .enum(["bt_audit", "wifi_audit", "rogue_ap_detect", "disable_unused"])
        .describe("Wireless security action"),
      interface: z
        .string()
        .optional()
        .describe("Specific wireless interface to audit (e.g. wlan0)"),
      output_format: z
        .enum(["text", "json"])
        .optional()
        .default("text")
        .describe("Output format"),
    },
    async (params) => {
      const { action } = params;
      const outputFormat = params.output_format ?? "text";

      switch (action) {
        // ── bt_audit ──────────────────────────────────────────────────────
        case "bt_audit": {
          try {
            const audit = await btAudit();

            const output = {
              action: "bt_audit",
              adapterFound: audit.adapterFound,
              adapterStatus: audit.adapterStatus,
              powered: audit.powered,
              discoverable: audit.discoverable,
              pairedDevicesCount: audit.pairedDevicesCount,
              pairedDevices: audit.pairedDevices,
              serviceRunning: audit.serviceRunning,
              serviceStatus: audit.serviceStatus,
              riskLevel: audit.riskLevel,
              recommendations: audit.recommendations,
            };

            if (outputFormat === "json") {
              return { content: [formatToolOutput(output)] };
            }

            let text = "Wireless Security — Bluetooth Audit\n\n";
            text += `Adapter Found: ${audit.adapterFound ? "yes" : "no"}\n`;
            text += `Adapter Status: ${audit.adapterStatus}\n`;
            text += `Powered: ${audit.powered ? "YES WARNING" : "no"}\n`;
            text += `Discoverable: ${audit.discoverable ? "YES WARNING" : "no OK"}\n`;
            text += `Paired Devices: ${audit.pairedDevicesCount}\n`;

            if (audit.pairedDevices.length > 0) {
              text += "\nPaired Devices:\n";
              for (const dev of audit.pairedDevices) {
                text += `  • ${dev}\n`;
              }
            }

            text += `\nBluetooth Service: ${audit.serviceRunning ? "running WARNING" : "not running OK"}\n`;
            text += `Risk Level: ${audit.riskLevel}\n`;

            if (audit.recommendations.length > 0) {
              text += "\nRecommendations:\n";
              for (const rec of audit.recommendations) {
                text += `  • ${rec}\n`;
              }
            }

            return { content: [createTextContent(text)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`bt_audit failed: ${msg}`)], isError: true };
          }
        }

        // ── wifi_audit ────────────────────────────────────────────────────
        case "wifi_audit": {
          try {
            const audit = await wifiAudit(params.interface);

            const output = {
              action: "wifi_audit",
              interfacesFound: audit.interfacesFound,
              interfaceCount: audit.interfaceCount,
              activeConnection: audit.activeConnection,
              securityType: audit.securityType,
              savedNetworkCount: audit.savedNetworkCount,
              savedNetworks: audit.savedNetworks,
              wifiNeeded: audit.wifiNeeded,
              riskLevel: audit.riskLevel,
              recommendations: audit.recommendations,
            };

            if (outputFormat === "json") {
              return { content: [formatToolOutput(output)] };
            }

            let text = "Wireless Security — WiFi Audit\n\n";
            text += `Wireless Interfaces: ${audit.interfaceCount}\n`;
            if (audit.interfacesFound.length > 0) {
              text += `Interfaces: ${audit.interfacesFound.join(", ")}\n`;
            }
            text += `Active Connection: ${audit.activeConnection}\n`;
            text += `Security Type: ${audit.securityType}\n`;
            text += `Saved Networks: ${audit.savedNetworkCount}\n`;
            text += `WiFi Needed: ${audit.wifiNeeded ? "yes" : "no"}\n`;
            text += `Risk Level: ${audit.riskLevel}\n`;

            if (audit.savedNetworks.length > 0) {
              text += "\nSaved WiFi Networks:\n";
              for (const net of audit.savedNetworks) {
                text += `  • ${net}\n`;
              }
            }

            if (audit.recommendations.length > 0) {
              text += "\nRecommendations:\n";
              for (const rec of audit.recommendations) {
                text += `  • ${rec}\n`;
              }
            }

            return { content: [createTextContent(text)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`wifi_audit failed: ${msg}`)], isError: true };
          }
        }

        // ── rogue_ap_detect ───────────────────────────────────────────────
        case "rogue_ap_detect": {
          try {
            const scan = await rogueApDetect(params.interface);

            const output = {
              action: "rogue_ap_detect",
              totalApsFound: scan.totalApsFound,
              knownAps: scan.knownAps,
              unknownApsCount: scan.unknownAps.length,
              unknownAps: scan.unknownAps,
              openApsCount: scan.openAps.length,
              openAps: scan.openAps,
              potentialEvilTwins: scan.potentialEvilTwins,
              scanInterface: scan.scanInterface,
              recommendations: scan.recommendations,
            };

            if (outputFormat === "json") {
              return { content: [formatToolOutput(output)] };
            }

            let text = "Wireless Security — Rogue AP Detection\n\n";
            text += `Scan Interface: ${scan.scanInterface}\n`;
            text += `Total APs Found: ${scan.totalApsFound}\n`;
            text += `Known APs: ${scan.knownAps.length}\n`;
            text += `Unknown APs: ${scan.unknownAps.length}\n`;
            text += `Open APs: ${scan.openAps.length}\n`;
            text += `Potential Evil Twins: ${scan.potentialEvilTwins.length}\n`;

            if (scan.unknownAps.length > 0) {
              text += "\nUnknown Access Points:\n";
              for (const ap of scan.unknownAps) {
                text += `  • SSID: ${ap.ssid || "(hidden)"} | BSSID: ${ap.bssid} | Signal: ${ap.signal} | Security: ${ap.security}\n`;
              }
            }

            if (scan.openAps.length > 0) {
              text += "\nOpen (Unencrypted) Access Points:\n";
              for (const ap of scan.openAps) {
                text += `  • SSID: ${ap.ssid || "(hidden)"} | BSSID: ${ap.bssid} | Signal: ${ap.signal}\n`;
              }
            }

            if (scan.potentialEvilTwins.length > 0) {
              text += "\nWARNING: Potential Evil Twins:\n";
              for (const twin of scan.potentialEvilTwins) {
                text += `  • SSID: ${twin.ap.ssid} | BSSID: ${twin.ap.bssid} — mimics known AP: ${twin.matchedKnown}\n`;
              }
            }

            if (scan.recommendations.length > 0) {
              text += "\nRecommendations:\n";
              for (const rec of scan.recommendations) {
                text += `  • ${rec}\n`;
              }
            }

            return { content: [createTextContent(text)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`rogue_ap_detect failed: ${msg}`)], isError: true };
          }
        }

        // ── disable_unused ────────────────────────────────────────────────
        case "disable_unused": {
          try {
            const disable = await disableUnused(params.interface);

            const output = {
              action: "disable_unused",
              wirelessInterfaces: disable.wirelessInterfaces,
              loadedModules: disable.loadedModules,
              interfacesDisabled: disable.interfacesDisabled,
              modulesBlacklistable: disable.modulesBlacklistable,
              rfkillAvailable: disable.rfkillAvailable,
              cisBenchmark: disable.cisBenchmark,
              recommendations: disable.recommendations,
            };

            if (outputFormat === "json") {
              return { content: [formatToolOutput(output)] };
            }

            let text = "Wireless Security — Disable Unused Interfaces\n\n";
            text += `CIS Reference: ${disable.cisBenchmark}\n\n`;

            text += "Wireless Interfaces:\n";
            if (disable.wirelessInterfaces.length === 0) {
              text += "  No wireless interfaces found\n";
            } else {
              for (const wi of disable.wirelessInterfaces) {
                const status = wi.inUse
                  ? "IN USE (not disabled)"
                  : wi.disabled
                    ? "DISABLED OK"
                    : "could not disable WARNING";
                text += `  • ${wi.name}: ${status}\n`;
              }
            }

            text += "\nKernel Modules:\n";
            if (disable.loadedModules.length === 0) {
              text += "  Could not check kernel modules\n";
            } else {
              for (const mod of disable.loadedModules) {
                text += `  • ${mod.name}: ${mod.loaded ? "LOADED" : "not loaded"}${mod.canBlacklist ? " WARNING: can be blacklisted" : ""}\n`;
              }
            }

            text += `\nInterfaces Disabled: ${disable.interfacesDisabled}\n`;
            text += `Modules Blacklistable: ${disable.modulesBlacklistable}\n`;
            text += `rfkill Available: ${disable.rfkillAvailable ? "yes" : "no"}\n`;

            if (disable.recommendations.length > 0) {
              text += "\nRecommendations:\n";
              for (const rec of disable.recommendations) {
                text += `  • ${rec}\n`;
              }
            }

            return { content: [createTextContent(text)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`disable_unused failed: ${msg}`)], isError: true };
          }
        }

        default:
          return { content: [createErrorContent(`Unknown action: ${action}`)], isError: true };
      }
    },
  );
}
