#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createRequire } from "node:module";

// ── Dynamic version from package.json ────────────────────────────────────────
const require = createRequire(import.meta.url);
const { version: VERSION } = require("../package.json");

// ── Core: Dependency validation & distro detection ───────────────────────────
import {
  validateAllDependencies,
  formatValidationReport,
} from "./core/dependency-validator.js";
import { getConfig } from "./core/config.js";
import { getDistroAdapter } from "./core/distro-adapter.js";
import { initializeAllowlist, verifyAllBinaries } from "./core/command-allowlist.js";
import { hardenDirPermissions } from "./core/secure-fs.js";
import { homedir } from "node:os";
import { join } from "node:path";

// ── Core: Pre-flight validation system ───────────────────────────────────────
import { createPreflightServer, invalidatePreflightCaches } from './core/tool-wrapper.js';
import { initializeRegistry } from './core/tool-registry.js';

// ── Core: Lifecycle management ───────────────────────────────────────────────
import { SudoSession } from "./core/sudo-session.js";
import { logChange, createChangeEntry } from "./core/changelog.js";

// ── Original tool modules ────────────────────────────────────────────────────
import { registerFirewallTools } from "./tools/firewall.js";
import { registerHardeningTools } from "./tools/hardening.js";
import { registerIdsTools } from "./tools/ids.js";
import { registerLoggingTools } from "./tools/logging.js";
import { registerNetworkDefenseTools } from "./tools/network-defense.js";
import { registerComplianceTools } from "./tools/compliance.js";
import { registerMalwareTools } from "./tools/malware.js";
import { registerBackupTools } from "./tools/backup.js";
import { registerAccessControlTools } from "./tools/access-control.js";
import { registerEncryptionTools } from "./tools/encryption.js";
import { registerContainerSecurityTools } from "./tools/container-security.js";
import { registerMetaTools } from "./tools/meta.js";
import { registerPatchManagementTools } from "./tools/patch-management.js";
import { registerSecretsTools } from "./tools/secrets.js";
import { registerIncidentResponseTools } from "./tools/incident-response.js";

// ── Sudo privilege management ────────────────────────────────────────────────
import { registerSudoManagementTools } from "./tools/sudo-management.js";

// ── New tool modules ─────────────────────────────────────────────────────────
import { registerSupplyChainSecurityTools } from "./tools/supply-chain-security.js";
import { registerDriftDetectionTools } from "./tools/drift-detection.js";
import { registerZeroTrustNetworkTools } from "./tools/zero-trust-network.js";
import { registerEbpfSecurityTools } from "./tools/ebpf-security.js";
import { registerAppHardeningTools } from "./tools/app-hardening.js";

// ── v0.6.0 tool modules ─────────────────────────────────────────────────────
import { registerReportingTools } from "./tools/reporting.js";
import { registerDnsSecurityTools } from "./tools/dns-security.js";
import { registerVulnerabilityManagementTools } from "./tools/vulnerability-management.js";
import { registerProcessSecurityTools } from "./tools/process-security.js";
import { registerWafTools } from "./tools/waf.js";
import { registerThreatIntelTools } from "./tools/threat-intel.js";
import { registerCloudSecurityTools } from "./tools/cloud-security.js";
import { registerApiSecurityTools } from "./tools/api-security.js";
import { registerDeceptionTools } from "./tools/deception.js";
import { registerWirelessSecurityTools } from "./tools/wireless-security.js";
import { registerSiemIntegrationTools } from "./tools/siem-integration.js";

// ── Graceful shutdown handler ────────────────────────────────────────────────

function gracefulShutdown(signal: string) {
  console.error(`\n[shutdown] Received ${signal} — cleaning up...`);

  try {
    // 1. Zero the sudo password buffer
    const session = SudoSession.getInstance();
    if (session.isElevated()) {
      session.drop();
      console.error("[shutdown] Sudo session dropped, password zeroed");
    }
  } catch { /* ignore if not initialized */ }

  try {
    // 2. Log the shutdown to changelog
    logChange(createChangeEntry({
      tool: "server",
      action: `Server shutdown via ${signal}`,
      target: "server",
      before: "running",
      after: "stopped",
      dryRun: false,
      success: true,
    }));
  } catch { /* ignore if changelog unavailable */ }

  console.error("[shutdown] Cleanup complete, exiting");
  process.exit(0);
}

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));

// SECURITY (CORE-020): uncaughtException/unhandledRejection handlers must use
// only synchronous operations. Async operations (file writes, network, cleanup)
// are NOT guaranteed to complete after an uncaught exception. Async cleanup is
// handled by SIGTERM/SIGINT handlers above.
process.on("uncaughtException", (err) => {
  console.error(`[fatal] Uncaught exception: ${err.message}`);
  console.error(err.stack);
  process.exit(1);
});

process.on("unhandledRejection", (reason) => {
  console.error(`[fatal] Unhandled rejection: ${reason}`);
  process.exit(1);
});

// ── Main entry point ─────────────────────────────────────────────────────────

async function main() {
  const server = new McpServer({
    name: "kali-defense-mcp-server",
    version: VERSION,
  });

  // ── Phase 1: Dependency Validation & Auto-Install ────────────────────────
  //
  // Before registering tools, validate that all required system binaries
  // are present. If KALI_DEFENSE_AUTO_INSTALL=true, missing tools will be
  // automatically installed via the system package manager.
  //
  const config = getConfig();
  console.error(`Kali Defense MCP Server v${VERSION} starting...`);
  console.error(
    `[startup] Auto-install: ${config.autoInstall ? "ENABLED" : "DISABLED"} | ` +
    `Dry-run: ${config.dryRun ? "YES" : "NO"}`
  );

  // ── Phase 0a: Initialize command allowlist ────────────────────────────────
  // Must run before any command execution (dependency validation, tool registration).
  // Resolves allowlisted binary names to absolute paths on this system.
  initializeAllowlist();

  // ── Phase 0b: Harden existing state directories ──────────────────────────
  // Fix permissions on any state files/dirs created before this security fix.
  // Best-effort: silently skips if directories don't exist yet.
  try {
    const stateDir = join(homedir(), ".kali-defense");
    hardenDirPermissions(stateDir);
    // Also harden the backups subdirectory if it exists
    hardenDirPermissions(join(stateDir, "backups"));
  } catch {
    // Non-fatal — directories may not exist yet
  }

  // ── Phase 0c: Run independent async startup tasks in parallel ─────────────
  // verifyAllBinaries(), getDistroAdapter(), and validateAllDependencies()
  // are independent of each other — run them concurrently for faster startup.
  const [binaryVerifyResult, distroResult, depValidationResult] = await Promise.allSettled([
    verifyAllBinaries(),
    getDistroAdapter(),
    validateAllDependencies(),
  ]);

  // Log binary integrity results
  if (binaryVerifyResult.status === "rejected") {
    console.error(
      `[startup] ⚠️  Binary integrity verification failed (non-fatal): ${
        binaryVerifyResult.reason instanceof Error ? binaryVerifyResult.reason.message : String(binaryVerifyResult.reason)
      }`
    );
  }

  // Log distro detection results
  if (distroResult.status === "fulfilled") {
    console.error(`[startup] 🐧 ${distroResult.value.summary}`);
  } else {
    console.error(
      `[startup] ⚠️  Distro detection failed: ${
        distroResult.reason instanceof Error ? distroResult.reason.message : String(distroResult.reason)
      }`
    );
    console.error("[startup] Continuing with defaults...");
  }

  // Log dependency validation results
  if (depValidationResult.status === "fulfilled") {
    const report = depValidationResult.value;
    console.error(formatValidationReport(report));

    if (report.criticalMissing.length > 0 && !config.autoInstall) {
      console.error(
        "[startup] ⚠️  Some critical tools are missing. The server will start, " +
        "but affected tools may fail at runtime."
      );
      console.error(
        "[startup] 💡 To auto-install: set KALI_DEFENSE_AUTO_INSTALL=true"
      );
    }

    if (report.installed.length > 0) {
      console.error(
        `[startup] ✅ Auto-installed ${report.installed.length} missing tools: ` +
        report.installed.join(", ")
      );
    }
  } else {
    console.error(
      `[startup] ⚠️  Dependency validation failed: ${
        depValidationResult.reason instanceof Error ? depValidationResult.reason.message : String(depValidationResult.reason)
      }`
    );
    console.error("[startup] Continuing with server startup...");
  }

  // ── Phase 0.5: Initialize pre-flight validation system ───────────────────
  console.error('[startup] Initializing pre-flight validation system...');
  try {
    const registry = initializeRegistry();
    console.error(`[startup] Pre-flight registry initialized with ${registry.getAll().length} tool manifests`);
  } catch (err) {
    console.error(`[startup] Pre-flight registry initialization failed (non-fatal): ${err}`);
  }

  // Wrap server with pre-flight middleware
  const wrappedServer = createPreflightServer(server);

  // ── Phase 2: Register all defensive tool modules (with error isolation) ──

  let registered = 0;
  let failed = 0;
  const failedModules: string[] = [];

  function safeRegister(name: string, fn: (server: any) => void) {
    try {
      fn(wrappedServer);
      registered++;
    } catch (err) {
      failed++;
      failedModules.push(name);
      console.error(`[startup] ⚠ Failed to register ${name} tools: ${err instanceof Error ? err.message : err}`);
    }
  }

  // Sudo privilege management (must be registered first — prerequisite for other tools)
  safeRegister("sudo-management", registerSudoManagementTools);

  // Original tool modules
  safeRegister("firewall", registerFirewallTools);
  safeRegister("hardening", registerHardeningTools);
  safeRegister("ids", registerIdsTools);
  safeRegister("logging", registerLoggingTools);
  safeRegister("network-defense", registerNetworkDefenseTools);
  safeRegister("compliance", registerComplianceTools);
  safeRegister("malware", registerMalwareTools);
  safeRegister("backup", registerBackupTools);
  safeRegister("access-control", registerAccessControlTools);
  safeRegister("encryption", registerEncryptionTools);
  safeRegister("container-security", registerContainerSecurityTools);
  safeRegister("meta", registerMetaTools);
  safeRegister("patch-management", registerPatchManagementTools);
  safeRegister("secrets", registerSecretsTools);
  safeRegister("incident-response", registerIncidentResponseTools);

  // New tool modules
  safeRegister("supply-chain-security", registerSupplyChainSecurityTools);
  safeRegister("drift-detection", registerDriftDetectionTools);
  safeRegister("zero-trust-network", registerZeroTrustNetworkTools);
  safeRegister("ebpf-security", registerEbpfSecurityTools);
  safeRegister("app-hardening", registerAppHardeningTools);

  // v0.6.0 tool modules
  safeRegister("api-security", registerApiSecurityTools);
  safeRegister("cloud-security", registerCloudSecurityTools);
  safeRegister("deception", registerDeceptionTools);
  safeRegister("dns-security", registerDnsSecurityTools);
  safeRegister("process-security", registerProcessSecurityTools);
  safeRegister("reporting", registerReportingTools);
  safeRegister("siem-integration", registerSiemIntegrationTools);
  safeRegister("threat-intel", registerThreatIntelTools);
  safeRegister("vulnerability-management", registerVulnerabilityManagementTools);
  safeRegister("waf", registerWafTools);
  safeRegister("wireless-security", registerWirelessSecurityTools);

  // Fail hard if no modules loaded at all
  if (registered === 0) {
    throw new Error("No tool modules loaded — server cannot start");
  }

  // ── Phase 3: Connect transport ───────────────────────────────────────────

  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`Kali Defense MCP Server v${VERSION} running on stdio`);
  console.error(`Registered ${registered} of ${registered + failed} tool modules with ~78 defensive security tools${failed > 0 ? ` (${failed} failed: ${failedModules.join(", ")})` : ""}`);
  console.error("[startup] 💡 Use sudo_elevate to provide your password once for all privileged operations");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
