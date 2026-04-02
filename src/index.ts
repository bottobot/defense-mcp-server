#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createServer } from "node:http";
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
import { createPreflightServer } from './core/tool-wrapper.js';
import { initializeRegistry } from './core/tool-registry.js';

// ── Core: Lifecycle management ───────────────────────────────────────────────
import { SudoSession } from "./core/sudo-session.js";
import { SudoGuard } from "./core/sudo-guard.js";
import { logChange, createChangeEntry } from "./core/changelog.js";

// ── Original tool modules ────────────────────────────────────────────────────
import { registerFirewallTools } from "./tools/firewall.js";
import { registerHardeningTools } from "./tools/hardening.js";
import { registerIntegrityTools } from "./tools/integrity.js";
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
import { registerZeroTrustNetworkTools } from "./tools/zero-trust-network.js";
import { registerEbpfSecurityTools } from "./tools/ebpf-security.js";
import { registerAppHardeningTools } from "./tools/app-hardening.js";

// ── v0.6.0 tool modules ─────────────────────────────────────────────────────
import { registerDnsSecurityTools } from "./tools/dns-security.js";
import { registerVulnerabilityManagementTools } from "./tools/vulnerability-management.js";
import { registerProcessSecurityTools } from "./tools/process-security.js";
import { registerWafTools } from "./tools/waf.js";
import { registerThreatIntelTools } from "./tools/threat-intel.js";
import { registerCloudSecurityTools } from "./tools/cloud-security.js";
import { registerApiSecurityTools } from "./tools/api-security.js";
import { registerDeceptionTools } from "./tools/deception.js";
import { registerWirelessSecurityTools } from "./tools/wireless-security.js";

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

// Client disconnected (closed our stdin pipe) — stdio transport convention.
// The MCP client terminates us via stdin close → SIGTERM → SIGKILL.
process.stdin.on("close", () => gracefulShutdown("stdin closed (client disconnected)"));

// SECURITY (CORE-020): uncaughtException/unhandledRejection handlers must use
// only synchronous operations. Async operations (file writes, network, cleanup)
// are NOT guaranteed to complete after an uncaught exception. Async cleanup is
// handled by SIGTERM/SIGINT handlers above.
process.on("uncaughtException", (err) => {
  console.error(`[fatal] Uncaught exception: ${err.message}`);
  console.error(err.stack);
  process.exit(1);
});

// Prevent unhandled rejections from crashing the server silently.
// Don't exit — let the SDK handle protocol-level errors.
process.on("unhandledRejection", (reason) => {
  console.error("[error] Unhandled rejection:", reason);
});

// ── Main entry point ─────────────────────────────────────────────────────────

async function main() {
  const server = new McpServer({
    name: "defense-mcp-server",
    version: VERSION,
  });

  // ── Phase 1: Dependency Validation & Auto-Install ────────────────────────
  //
  // Before registering tools, validate that all required system binaries
  // are present. If DEFENSE_MCP_AUTO_INSTALL=true, missing tools will be
  // automatically installed via the system package manager.
  //
  const config = getConfig();
  console.error(`Defense MCP Server v${VERSION} starting...`);
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
    const stateDir = join(homedir(), ".defense-mcp");
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
        "[startup] 💡 To auto-install: set DEFENSE_MCP_AUTO_INSTALL=true"
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

  // ── Phase 0.6: Sudoers NOPASSWD security check ───────────────────────────
  // Detect whether the dangerous 'NOPASSWD: ALL' grant is still present.
  // If so, emit a CRITICAL security warning — authentication is hollow.
  // This check is synchronous and best-effort (non-fatal on failure).
  try {
    const nopasswdCheck = SudoGuard.checkNopasswdConfiguration();
    if (nopasswdCheck.nopasswdDetected) {
      console.error(
        `[startup] ⚠️  SECURITY CRITICAL: NOPASSWD:ALL detected in sudoers. ` +
        `sudo_elevate credential validation is NON-FUNCTIONAL. ` +
        `Remove the NOPASSWD entry from sudoers and set a real password for the MCP user.`
      );
    } else {
      console.error('[startup] ✅ Sudoers check: NOPASSWD:ALL not detected — credential validation active');
    }
  } catch (err) {
    console.error(`[startup] Sudoers NOPASSWD check failed (non-fatal): ${err}`);
  }

  // ── Phase 0.7: Check optional third-party tools ───────────────────────────
  // Informational only — missing optional tools must NOT prevent server startup.
  try {
    const { listThirdPartyTools } = await import("./core/third-party-installer.js");
    const thirdPartyStatuses = await listThirdPartyTools();
    const missingTools = thirdPartyStatuses.filter(s => !s.installed);
    if (missingTools.length > 0) {
      for (const tool of missingTools) {
        console.error(
          `[third-party] Optional tool '${tool.binary}' (v${tool.manifestVersion}) not installed — ` +
          `${tool.name} functionality limited`
        );
      }
      console.error(
        `[third-party] Run: defense_mgmt → install_optional_deps (dry_run=true) to see install plan`
      );
    }
  } catch {
    // Non-fatal — third-party check failure must not block startup
  }

  // Wrap server with pre-flight middleware
  const wrappedServer = createPreflightServer(server);

  // ── Phase 2: Register all defensive tool modules (with error isolation) ──

  let registered = 0;
  let failed = 0;
  const failedModules: string[] = [];

  function safeRegister(name: string, fn: (server: McpServer) => void) {
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
  safeRegister("integrity", registerIntegrityTools);
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
  safeRegister("zero-trust-network", registerZeroTrustNetworkTools);
  safeRegister("ebpf-security", registerEbpfSecurityTools);
  safeRegister("app-hardening", registerAppHardeningTools);

  // v0.6.0 tool modules
  safeRegister("api-security", registerApiSecurityTools);
  safeRegister("cloud-security", registerCloudSecurityTools);
  safeRegister("deception", registerDeceptionTools);
  safeRegister("dns-security", registerDnsSecurityTools);
  safeRegister("process-security", registerProcessSecurityTools);
  safeRegister("threat-intel", registerThreatIntelTools);
  safeRegister("vulnerability-management", registerVulnerabilityManagementTools);
  safeRegister("waf", registerWafTools);
  safeRegister("wireless-security", registerWirelessSecurityTools);

  // Fail hard if no modules loaded at all
  if (registered === 0) {
    throw new Error("No tool modules loaded — server cannot start");
  }

  // ── Phase 3: Connect transport ───────────────────────────────────────────

  const transportMode = process.env.MCP_TRANSPORT ?? "stdio";
  const registrationMsg =
    `Registered ${registered} tool modules with consolidated defensive security tools` +
    `${failed > 0 ? ` (${failed} failed: ${failedModules.join(", ")})` : ""}`;

  if (transportMode === "http") {
    const port = parseInt(process.env.MCP_PORT ?? "3100", 10);

    // Server card for Smithery discovery
    const serverCard = {
      serverInfo: {
        name: "defense-mcp-server",
        version: VERSION,
        description: "31 defensive security tools (250+ actions) for Linux system hardening, compliance, and threat detection",
      },
      authentication: { required: false },
      tools: [
        { name: "access_control", description: "Access control: SSH, PAM, sudo, user audit, password policy, shell restriction" },
        { name: "api_security", description: "API security: local API discovery, auth audit, rate limiting, TLS verify, CORS check" },
        { name: "app_harden", description: "App hardening: audit running apps, recommendations, firewall rules, systemd sandboxing" },
        { name: "backup", description: "Backup: config files, system state snapshots, restore, verify integrity, list backups" },
        { name: "cloud_security", description: "Cloud: environment detection, metadata audit, IAM credentials, storage audit, IMDS security" },
        { name: "compliance", description: "Compliance: Lynis, OpenSCAP, CIS benchmarks, framework checks, policy, cron/tmp hardening" },
        { name: "container_docker", description: "Docker security: audit, CIS bench, seccomp, daemon config, image scan" },
        { name: "container_isolation", description: "Container isolation: AppArmor, SELinux, namespaces, seccomp, rootless setup" },
        { name: "crypto", description: "Crypto: TLS/SSL audit, GPG, LUKS, file hashing, certificate lifecycle" },
        { name: "defense_mgmt", description: "Defense: tool checks, workflows, change history, posture, scheduled audits, remediation, reports" },
        { name: "dns_security", description: "DNS: resolver audit, DNSSEC check, tunneling detection, domain blocklists, query log audit" },
        { name: "ebpf", description: "eBPF/Falco: list eBPF programs, Falco status, deploy rules, read events" },
        { name: "firewall", description: "Firewall: iptables, UFW, nftables, persistence, policy audit" },
        { name: "harden_host", description: "Host hardening: services, permissions, systemd, cron, umask, banners, USB control" },
        { name: "harden_kernel", description: "Kernel hardening: sysctl, kernel security, bootloader, memory protections" },
        { name: "honeypot_manage", description: "Deception: canary tokens, honeyport listeners, trigger detection, canary management" },
        { name: "incident_response", description: "Incident response: volatile data, IOC scan, timeline, forensics (memory/disk/network/evidence/custody)" },
        { name: "integrity", description: "Integrity: AIDE, rootkit scanning, file hashing, drift baselines" },
        { name: "log_management", description: "Logging: auditd, journalctl, fail2ban, syslog, log rotation, SIEM integration" },
        { name: "malware", description: "Malware: ClamAV scan/update, YARA rules, suspicious files, webshells, quarantine" },
        { name: "network_defense", description: "Network: connections, traffic capture, port scan detection, IPv6 audit, self-scan, segmentation" },
        { name: "patch", description: "Patches: pending updates, unattended upgrades, package integrity, kernel audit, CVE lookup" },
        { name: "process_security", description: "Processes: audit running, capabilities, namespaces, anomaly detection, cgroup limits" },
        { name: "secrets", description: "Secrets: filesystem scan, env variable audit, SSH key sprawl, git history leak detection" },
        { name: "sudo_session", description: "Sudo: elevate privileges, check/drop/extend session, preflight tool checks" },
        { name: "supply_chain", description: "Supply chain: SBOM generation, cosign artifact signing, SLSA provenance verification" },
        { name: "threat_intel", description: "Threat intel: IP/hash/domain reputation, feed management, blocklist application" },
        { name: "vuln_manage", description: "Vulnerabilities: nmap scan, nikto web scan, tracking, risk prioritization, remediation plans" },
        { name: "waf_manage", description: "WAF: ModSecurity audit, rule management, rate limiting, OWASP CRS, blocked request analysis" },
        { name: "wireless_security", description: "Wireless: Bluetooth audit, WiFi assessment, rogue AP detection, disable unused interfaces" },
        { name: "zero_trust", description: "Zero-trust: WireGuard VPN, peer management, mTLS certificates, microsegmentation" },
      ],
      resources: [],
      prompts: [],
    };

    // Track active transports by session ID
    const sessions = new Map<string, StreamableHTTPServerTransport>();

    const httpServer = createServer(async (req, res) => {
      const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
      const pathname = url.pathname;

      // CORS for Smithery Gateway
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type, mcp-session-id, smithery-*");
      res.setHeader("Access-Control-Expose-Headers", "mcp-session-id");

      if (req.method === "OPTIONS") {
        res.writeHead(204).end();
        return;
      }

      // Health check
      if (req.method === "GET" && pathname === "/health") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ status: "ok", version: VERSION, tools: registered }));
        return;
      }

      // Smithery server card
      if (req.method === "GET" && pathname === "/.well-known/mcp/server-card.json") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(serverCard));
        return;
      }

      // MCP Streamable HTTP endpoint
      if (pathname === "/mcp" || pathname === "/") {
        const sessionId = req.headers["mcp-session-id"] as string | undefined;

        if (req.method === "GET" || req.method === "POST") {
          // Reuse existing session or create new one
          let transport = sessionId ? sessions.get(sessionId) : undefined;
          if (!transport) {
            transport = new StreamableHTTPServerTransport({
              sessionIdGenerator: () => crypto.randomUUID(),
            });
            await server.connect(transport);
            // Store session after first request so we can retrieve it by ID
            transport.onclose = () => {
              const sid = [...sessions.entries()].find(([, t]) => t === transport)?.[0];
              if (sid) sessions.delete(sid);
            };
          }
          await transport.handleRequest(req, res);
          // Capture session ID from response headers if new session
          if (!sessionId) {
            const newSid = res.getHeader("mcp-session-id") as string | undefined;
            if (newSid && transport) sessions.set(newSid, transport);
          }
          return;
        }

        if (req.method === "DELETE") {
          if (sessionId && sessions.has(sessionId)) {
            const transport = sessions.get(sessionId)!;
            await transport.handleRequest(req, res);
            sessions.delete(sessionId);
          } else {
            res.writeHead(404).end("Session not found");
          }
          return;
        }
      }

      res.writeHead(404).end("Not found");
    });

    httpServer.listen(port, () => {
      console.error(`Defense MCP Server v${VERSION} running on HTTP port ${port}`);
      console.error(registrationMsg);
      console.error("[startup] MCP endpoint: http://0.0.0.0:" + port + "/mcp");
      console.error("[startup] Health check: http://0.0.0.0:" + port + "/health");
      console.error("[startup] Server card: http://0.0.0.0:" + port + "/.well-known/mcp/server-card.json");
    });
  } else {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error(`Defense MCP Server v${VERSION} running on stdio`);
    console.error(registrationMsg);
  }

  console.error("[startup] 💡 Use sudo_elevate to provide your password once for all privileged operations");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
