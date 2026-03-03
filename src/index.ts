#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

// ── Core: Dependency validation & distro detection ───────────────────────────
import {
  validateAllDependencies,
  formatValidationReport,
} from "./core/dependency-validator.js";
import { getConfig } from "./core/config.js";
import { getDistroAdapter } from "./core/distro-adapter.js";

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
import { registerSecretsManagementTools } from "./tools/secrets-management.js";
import { registerIncidentResponseTools } from "./tools/incident-response.js";

// ── Sudo privilege management ────────────────────────────────────────────────
import { registerSudoManagementTools } from "./tools/sudo-management.js";

// ── New tool modules ─────────────────────────────────────────────────────────
import { registerSupplyChainSecurityTools } from "./tools/supply-chain-security.js";
import { registerMemoryProtectionTools } from "./tools/memory-protection.js";
import { registerDriftDetectionTools } from "./tools/drift-detection.js";
import { registerVulnerabilityIntelTools } from "./tools/vulnerability-intel.js";
import { registerSecurityPostureTools } from "./tools/security-posture.js";
import { registerSecretsScannerTools } from "./tools/secrets-scanner.js";
import { registerZeroTrustNetworkTools } from "./tools/zero-trust-network.js";
import { registerContainerAdvancedTools } from "./tools/container-advanced.js";
import { registerComplianceExtendedTools } from "./tools/compliance-extended.js";
import { registerEbpfSecurityTools } from "./tools/ebpf-security.js";
import { registerAutomationWorkflowTools } from "./tools/automation-workflows.js";
import { registerAppHardeningTools } from "./tools/app-hardening.js";

async function main() {
  const server = new McpServer({
    name: "kali-defense-mcp-server",
    version: "2.1.0",
  });

  // ── Phase 1: Dependency Validation & Auto-Install ────────────────────────
  //
  // Before registering tools, validate that all required system binaries
  // are present. If KALI_DEFENSE_AUTO_INSTALL=true, missing tools will be
  // automatically installed via the system package manager.
  //
  const config = getConfig();
  console.error("Kali Defense MCP Server v2.1.0 starting...");
  console.error(
    `[startup] Auto-install: ${config.autoInstall ? "ENABLED" : "DISABLED"} | ` +
    `Dry-run: ${config.dryRun ? "YES" : "NO"}`
  );

  // ── Phase 0: Detect distribution ─────────────────────────────────────────
  try {
    const da = await getDistroAdapter();
    console.error(`[startup] 🐧 ${da.summary}`);
  } catch (err) {
    console.error(
      `[startup] ⚠️  Distro detection failed: ${err instanceof Error ? err.message : String(err)}`
    );
    console.error("[startup] Continuing with defaults...");
  }

  try {
    const report = await validateAllDependencies();
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
  } catch (err) {
    // Dependency validation failure should NOT prevent server startup
    console.error(
      `[startup] ⚠️  Dependency validation failed: ${err instanceof Error ? err.message : String(err)}`
    );
    console.error("[startup] Continuing with server startup...");
  }

  // ── Phase 2: Register all defensive tool modules ─────────────────────────

  // Sudo privilege management (must be registered first — prerequisite for other tools)
  registerSudoManagementTools(server);

  // Original tool modules
  registerFirewallTools(server);
  registerHardeningTools(server);
  registerIdsTools(server);
  registerLoggingTools(server);
  registerNetworkDefenseTools(server);
  registerComplianceTools(server);
  registerMalwareTools(server);
  registerBackupTools(server);
  registerAccessControlTools(server);
  registerEncryptionTools(server);
  registerContainerSecurityTools(server);
  registerMetaTools(server);
  registerPatchManagementTools(server);
  registerSecretsManagementTools(server);
  registerIncidentResponseTools(server);

  // New tool modules
  registerSupplyChainSecurityTools(server);
  registerMemoryProtectionTools(server);
  registerDriftDetectionTools(server);
  registerVulnerabilityIntelTools(server);
  registerSecurityPostureTools(server);
  registerSecretsScannerTools(server);
  registerZeroTrustNetworkTools(server);
  registerContainerAdvancedTools(server);
  registerComplianceExtendedTools(server);
  registerEbpfSecurityTools(server);
  registerAutomationWorkflowTools(server);
  registerAppHardeningTools(server);

  // ── Phase 3: Connect transport ───────────────────────────────────────────

  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Kali Defense MCP Server v2.1.0 running on stdio");
  console.error("Registered 28 tool modules with 137+ defensive security tools");
  console.error("[startup] 💡 Use sudo_elevate to provide your password once for all privileged operations");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
