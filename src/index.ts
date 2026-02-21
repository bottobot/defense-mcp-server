#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

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

async function main() {
  const server = new McpServer({
    name: "kali-defense-mcp-server",
    version: "2.0.0",
  });

  // Register all defensive tool modules (original)
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

  // Register new tool modules
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

  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Kali Defense MCP Server v2.0.0 running on stdio");
  console.error("Registered 26 tool modules with 130+ defensive security tools");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
