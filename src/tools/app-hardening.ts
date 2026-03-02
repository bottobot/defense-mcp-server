/**
 * Application Hardening tools for Kali Defense MCP Server.
 *
 * Detects running applications, assesses their security posture,
 * and applies hardening measures while preserving functionality.
 *
 * Registers 4 tools:
 *   - app_harden_audit: Detect and audit running applications for security risks
 *   - app_harden_recommend: Generate hardening recommendations for a specific app
 *   - app_harden_firewall: Generate/apply firewall rules to restrict an app's network exposure
 *   - app_harden_systemd: Apply systemd sandboxing to an application's service unit
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeCommand } from "../core/executor.js";
import { getConfig } from "../core/config.js";
import {
  createTextContent,
  createErrorContent,
} from "../core/parsers.js";
import { logChange, createChangeEntry } from "../core/changelog.js";

// ── Known Application Profiles ───────────────────────────────────────────────

interface AppProfile {
  name: string;
  processNames: string[];
  category: string;
  typicalPorts: Array<{ port: number; protocol: string; purpose: string }>;
  requiredPorts: Array<{ port: number; protocol: string; purpose: string }>;
  localhostOnlyPorts: Array<{ port: number; protocol: string; purpose: string }>;
  systemdHardening: Record<string, string>;
  writablePaths: string[];
  readablePaths: string[];
  recommendations: string[];
  riskLevel: "low" | "medium" | "high" | "critical";
  securityConcerns: string[];
}

const APP_PROFILES: Record<string, AppProfile> = {
  qbittorrent: {
    name: "qBittorrent",
    processNames: ["qbittorrent", "qbittorrent-nox"],
    category: "torrent",
    typicalPorts: [
      { port: 8080, protocol: "tcp", purpose: "WebUI" },
      { port: 6881, protocol: "tcp", purpose: "BitTorrent TCP" },
      { port: 6881, protocol: "udp", purpose: "BitTorrent UDP/DHT" },
      { port: 6771, protocol: "udp", purpose: "Local Peer Discovery" },
    ],
    requiredPorts: [
      { port: 6881, protocol: "tcp", purpose: "BitTorrent incoming connections" },
      { port: 6881, protocol: "udp", purpose: "BitTorrent DHT" },
    ],
    localhostOnlyPorts: [
      { port: 8080, protocol: "tcp", purpose: "WebUI — restrict to localhost or LAN" },
    ],
    systemdHardening: {
      ProtectSystem: "strict",
      ProtectHome: "read-only",
      PrivateTmp: "true",
      NoNewPrivileges: "true",
      ProtectKernelTunables: "true",
      ProtectKernelModules: "true",
      ProtectControlGroups: "true",
      RestrictNamespaces: "true",
      RestrictRealtime: "true",
      MemoryDenyWriteExecute: "true",
    },
    writablePaths: ["/var/lib/qbittorrent", "/home/*/Downloads"],
    readablePaths: ["/etc/qbittorrent"],
    recommendations: [
      "Bind WebUI to 127.0.0.1 or LAN IP only (not 0.0.0.0)",
      "Enable WebUI authentication with a strong password",
      "Enable HTTPS for WebUI if accessible over network",
      "Restrict listening port to a single port",
      "Disable UPnP/NAT-PMP to prevent automatic port forwarding",
      "Disable DHT, PEX, and LPD if using private trackers only",
      "Set connection limits (global max: 200, per-torrent: 50)",
      "Enable protocol encryption (forced)",
      "Run as a dedicated non-root user",
      "Use a VPN or SOCKS5 proxy for torrent traffic",
      "Create firewall rules to restrict torrent traffic to VPN interface",
    ],
    riskLevel: "high",
    securityConcerns: [
      "Exposes multiple ports to the internet for peer connections",
      "DHT/PEX can leak IP address to peers",
      "WebUI may be accessible from external networks if misconfigured",
      "Local Peer Discovery broadcasts on LAN",
      "UPnP can automatically open router ports",
      "Downloaded files may contain malware",
    ],
  },
  nginx: {
    name: "Nginx",
    processNames: ["nginx"],
    category: "web-server",
    typicalPorts: [
      { port: 80, protocol: "tcp", purpose: "HTTP" },
      { port: 443, protocol: "tcp", purpose: "HTTPS" },
    ],
    requiredPorts: [{ port: 443, protocol: "tcp", purpose: "HTTPS" }],
    localhostOnlyPorts: [],
    systemdHardening: {
      ProtectSystem: "full",
      PrivateTmp: "true",
      NoNewPrivileges: "true",
      ProtectKernelTunables: "true",
      ProtectKernelModules: "true",
      ProtectControlGroups: "true",
    },
    writablePaths: ["/var/log/nginx", "/var/cache/nginx", "/run/nginx"],
    readablePaths: ["/etc/nginx", "/var/www"],
    recommendations: [
      "Disable HTTP (port 80) or redirect to HTTPS",
      "Enable HSTS (Strict-Transport-Security header)",
      "Disable server_tokens to hide version info",
      "Set X-Content-Type-Options: nosniff",
      "Set X-Frame-Options: DENY or SAMEORIGIN",
      "Configure Content-Security-Policy header",
      "Set client_max_body_size to a reasonable limit",
      "Enable rate limiting for login/API endpoints",
      "Use TLS 1.2+ only with strong cipher suites",
    ],
    riskLevel: "high",
    securityConcerns: [
      "Directly exposed to the internet",
      "Misconfigured virtual hosts can leak internal services",
      "Default configs may expose server version",
    ],
  },
  sshd: {
    name: "OpenSSH Server",
    processNames: ["sshd"],
    category: "remote-access",
    typicalPorts: [{ port: 22, protocol: "tcp", purpose: "SSH" }],
    requiredPorts: [{ port: 22, protocol: "tcp", purpose: "SSH" }],
    localhostOnlyPorts: [],
    systemdHardening: {
      ProtectSystem: "strict",
      PrivateTmp: "true",
      NoNewPrivileges: "true",
      ProtectKernelTunables: "true",
      ProtectKernelModules: "true",
    },
    writablePaths: ["/var/log", "/run/sshd"],
    readablePaths: ["/etc/ssh"],
    recommendations: [
      "Disable root login (PermitRootLogin no)",
      "Use key-based authentication only (PasswordAuthentication no)",
      "Set MaxAuthTries to 3",
      "Set LoginGraceTime to 30",
      "Disable X11Forwarding unless needed",
      "Use AllowUsers/AllowGroups to restrict access",
      "Enable fail2ban for SSH brute-force protection",
      "Use Ed25519 or RSA-4096 host keys only",
    ],
    riskLevel: "critical",
    securityConcerns: [
      "Primary remote access vector — #1 brute-force target",
      "Root login may be enabled by default",
      "Password authentication vulnerable to brute-force",
    ],
  },
  postgresql: {
    name: "PostgreSQL",
    processNames: ["postgres", "postgresql"],
    category: "database",
    typicalPorts: [{ port: 5432, protocol: "tcp", purpose: "PostgreSQL" }],
    requiredPorts: [],
    localhostOnlyPorts: [{ port: 5432, protocol: "tcp", purpose: "Database — bind to localhost" }],
    systemdHardening: {
      ProtectSystem: "full",
      PrivateTmp: "true",
      NoNewPrivileges: "true",
      ProtectKernelTunables: "true",
    },
    writablePaths: ["/var/lib/postgresql", "/var/log/postgresql", "/run/postgresql"],
    readablePaths: ["/etc/postgresql"],
    recommendations: [
      "Bind to 127.0.0.1 only (listen_addresses = 'localhost')",
      "Use pg_hba.conf to restrict client authentication",
      "Disable trust authentication — use scram-sha-256",
      "Set strong password for postgres superuser",
      "Enable SSL for remote connections",
      "Restrict CREATE DATABASE and SUPERUSER privileges",
    ],
    riskLevel: "critical",
    securityConcerns: [
      "Contains sensitive application data",
      "Default trust authentication allows unauthenticated local access",
      "Superuser access grants full system control",
    ],
  },
  mysql: {
    name: "MySQL/MariaDB",
    processNames: ["mysqld", "mariadbd", "mariadb"],
    category: "database",
    typicalPorts: [{ port: 3306, protocol: "tcp", purpose: "MySQL" }],
    requiredPorts: [],
    localhostOnlyPorts: [{ port: 3306, protocol: "tcp", purpose: "Database — bind to localhost" }],
    systemdHardening: {
      ProtectSystem: "full",
      PrivateTmp: "true",
      NoNewPrivileges: "true",
    },
    writablePaths: ["/var/lib/mysql", "/var/log/mysql", "/run/mysqld"],
    readablePaths: ["/etc/mysql"],
    recommendations: [
      "Run mysql_secure_installation",
      "Bind to 127.0.0.1 only",
      "Remove anonymous users and test database",
      "Disable remote root login",
      "Use strong passwords for all accounts",
      "Enable SSL for remote connections",
    ],
    riskLevel: "critical",
    securityConcerns: [
      "Contains sensitive application data",
      "Default installation may have anonymous users",
      "Remote root login may be enabled",
    ],
  },
  redis: {
    name: "Redis",
    processNames: ["redis-server"],
    category: "database",
    typicalPorts: [{ port: 6379, protocol: "tcp", purpose: "Redis" }],
    requiredPorts: [],
    localhostOnlyPorts: [{ port: 6379, protocol: "tcp", purpose: "Redis — MUST be localhost only" }],
    systemdHardening: {
      ProtectSystem: "strict",
      PrivateTmp: "true",
      NoNewPrivileges: "true",
      ProtectKernelTunables: "true",
      MemoryDenyWriteExecute: "true",
    },
    writablePaths: ["/var/lib/redis", "/var/log/redis", "/run/redis"],
    readablePaths: ["/etc/redis"],
    recommendations: [
      "Bind to 127.0.0.1 ONLY (never expose to network)",
      "Set a strong requirepass password",
      "Disable dangerous commands (FLUSHALL, CONFIG, DEBUG, EVAL)",
      "Enable protected-mode",
      "Set maxmemory limit",
      "Run as dedicated redis user",
    ],
    riskLevel: "critical",
    securityConcerns: [
      "No authentication by default",
      "Exposed Redis = full server compromise",
      "EVAL command allows Lua code execution",
    ],
  },
  cups: {
    name: "CUPS Print Server",
    processNames: ["cupsd"],
    category: "other",
    typicalPorts: [{ port: 631, protocol: "tcp", purpose: "CUPS WebUI/IPP" }],
    requiredPorts: [],
    localhostOnlyPorts: [{ port: 631, protocol: "tcp", purpose: "CUPS — localhost only" }],
    systemdHardening: {
      ProtectSystem: "full",
      PrivateTmp: "true",
      NoNewPrivileges: "true",
    },
    writablePaths: ["/var/spool/cups", "/var/log/cups", "/run/cups"],
    readablePaths: ["/etc/cups"],
    recommendations: [
      "Disable if no printers are connected",
      "Bind WebUI to 127.0.0.1 only",
      "Require authentication for admin operations",
      "Disable remote printer sharing unless needed",
      "Disable Bonjour/mDNS printer advertising",
    ],
    riskLevel: "medium",
    securityConcerns: [
      "WebUI may be accessible from network",
      "Historical CVEs in CUPS",
      "Unnecessary attack surface if no printers used",
    ],
  },
  avahi: {
    name: "Avahi mDNS/DNS-SD",
    processNames: ["avahi-daemon"],
    category: "dns",
    typicalPorts: [{ port: 5353, protocol: "udp", purpose: "mDNS" }],
    requiredPorts: [],
    localhostOnlyPorts: [],
    systemdHardening: {
      ProtectSystem: "strict",
      PrivateTmp: "true",
      NoNewPrivileges: "true",
      ProtectKernelTunables: "true",
    },
    writablePaths: ["/run/avahi-daemon"],
    readablePaths: ["/etc/avahi"],
    recommendations: [
      "Disable entirely if not using network printer/service discovery",
      "If needed, restrict to specific interfaces only",
      "Disable publishing of local services",
      "Set disable-user-service-publishing=yes",
    ],
    riskLevel: "medium",
    securityConcerns: [
      "Broadcasts service information on the local network",
      "Can be used for network reconnaissance",
      "Unnecessary on servers and most workstations",
    ],
  },
  mongodb: {
    name: "MongoDB",
    processNames: ["mongod", "mongos"],
    category: "database",
    typicalPorts: [{ port: 27017, protocol: "tcp", purpose: "MongoDB" }],
    requiredPorts: [],
    localhostOnlyPorts: [{ port: 27017, protocol: "tcp", purpose: "MongoDB — bind to localhost" }],
    systemdHardening: {
      ProtectSystem: "full",
      PrivateTmp: "true",
      NoNewPrivileges: "true",
    },
    writablePaths: ["/var/lib/mongodb", "/var/log/mongodb"],
    readablePaths: ["/etc/mongod.conf"],
    recommendations: [
      "Enable authentication (security.authorization: enabled)",
      "Bind to 127.0.0.1 only",
      "Create application-specific users with minimal privileges",
      "Enable TLS for connections",
      "Disable JavaScript execution if not needed",
    ],
    riskLevel: "critical",
    securityConcerns: [
      "No authentication by default",
      "Exposed MongoDB = full data breach",
      "JavaScript execution enabled by default",
    ],
  },
  exim: {
    name: "Exim Mail Server",
    processNames: ["exim4", "exim"],
    category: "mail",
    typicalPorts: [
      { port: 25, protocol: "tcp", purpose: "SMTP" },
      { port: 587, protocol: "tcp", purpose: "SMTP Submission" },
    ],
    requiredPorts: [],
    localhostOnlyPorts: [{ port: 25, protocol: "tcp", purpose: "SMTP — localhost only" }],
    systemdHardening: {
      ProtectSystem: "full",
      PrivateTmp: "true",
      NoNewPrivileges: "true",
    },
    writablePaths: ["/var/spool/exim4", "/var/log/exim4"],
    readablePaths: ["/etc/exim4"],
    recommendations: [
      "Disable if not sending mail (use nullmailer/msmtp instead)",
      "Bind to 127.0.0.1 only for local delivery",
      "Disable open relay",
      "Enable TLS for SMTP connections",
    ],
    riskLevel: "high",
    securityConcerns: [
      "Open SMTP relay can be abused for spam",
      "Historical RCE vulnerabilities in Exim",
      "Port 25 is a common attack target",
    ],
  },
  samba: {
    name: "Samba File Sharing",
    processNames: ["smbd", "nmbd"],
    category: "file-sharing",
    typicalPorts: [
      { port: 139, protocol: "tcp", purpose: "NetBIOS Session" },
      { port: 445, protocol: "tcp", purpose: "SMB Direct" },
    ],
    requiredPorts: [{ port: 445, protocol: "tcp", purpose: "SMB" }],
    localhostOnlyPorts: [],
    systemdHardening: {
      ProtectSystem: "full",
      PrivateTmp: "true",
      NoNewPrivileges: "true",
    },
    writablePaths: ["/var/lib/samba", "/var/log/samba", "/run/samba"],
    readablePaths: ["/etc/samba"],
    recommendations: [
      "Disable SMBv1 (min protocol = SMB2)",
      "Restrict to LAN interfaces only",
      "Require authentication (security = user)",
      "Set valid users for each share",
      "Disable guest access",
      "Use firewall to restrict SMB to LAN only",
    ],
    riskLevel: "high",
    securityConcerns: [
      "SMBv1 has critical vulnerabilities (EternalBlue/WannaCry)",
      "Guest access can expose files",
      "Network-exposed file shares are high-value targets",
    ],
  },
};

// ── Helpers ──────────────────────────────────────────────────────────────────

interface DetectedApp {
  profileId: string;
  profile: AppProfile;
  pids: number[];
  user: string;
  listenPorts: Array<{ port: number; protocol: string; address: string }>;
  serviceUnit?: string;
}

async function detectRunningApps(): Promise<DetectedApp[]> {
  const detected: DetectedApp[] = [];

  const psResult = await executeCommand({
    command: "ps",
    args: ["axo", "pid,user,comm"],
    timeout: 10000,
  });
  if (psResult.exitCode !== 0) return detected;

  const processLines = psResult.stdout.trim().split("\n").slice(1);
  const runningProcesses: Array<{ pid: number; user: string; comm: string }> = [];

  for (const line of processLines) {
    const parts = line.trim().split(/\s+/);
    if (parts.length >= 3) {
      runningProcesses.push({ pid: parseInt(parts[0], 10), user: parts[1], comm: parts[2] });
    }
  }

  const ssResult = await executeCommand({ command: "ss", args: ["-tulnp"], timeout: 10000 });
  const ssLines = ssResult.exitCode === 0 ? ssResult.stdout.split("\n") : [];

  const svcResult = await executeCommand({
    command: "systemctl",
    args: ["list-units", "--type=service", "--state=running", "--no-pager", "--no-legend"],
    timeout: 10000,
  });
  const svcLines = svcResult.exitCode === 0 ? svcResult.stdout.split("\n") : [];

  for (const [profileId, profile] of Object.entries(APP_PROFILES)) {
    const matchingProcesses = runningProcesses.filter((p) =>
      profile.processNames.some((name) => p.comm.toLowerCase() === name.toLowerCase())
    );

    if (matchingProcesses.length > 0) {
      const pids = matchingProcesses.map((p) => p.pid);
      const user = matchingProcesses[0].user;

      const listenPorts: Array<{ port: number; protocol: string; address: string }> = [];
      for (const line of ssLines) {
        if (pids.some((pid) => line.includes(`pid=${pid}`))) {
          const addrMatch = line.match(/\s(\S+):(\d+)\s/);
          if (addrMatch) {
            listenPorts.push({
              port: parseInt(addrMatch[2], 10),
              protocol: line.startsWith("tcp") ? "tcp" : "udp",
              address: addrMatch[1],
            });
          }
        }
      }

      let serviceUnit: string | undefined;
      for (const procName of profile.processNames) {
        for (const svcLine of svcLines) {
          if (svcLine.toLowerCase().includes(procName.toLowerCase())) {
            serviceUnit = svcLine.trim().split(/\s+/)[0];
            break;
          }
        }
        if (serviceUnit) break;
      }

      detected.push({ profileId, profile, pids, user, listenPorts, serviceUnit });
    }
  }

  return detected;
}

// ── Registration ─────────────────────────────────────────────────────────────

export function registerAppHardeningTools(server: McpServer): void {

  // ── 1. app_harden_audit ────────────────────────────────────────────────

  server.tool(
    "app_harden_audit",
    "Detect running applications and audit their security posture. Identifies risky apps, open ports, and generates a prioritized hardening plan while preserving functionality.",
    {},
    async () => {
      try {
        const sections: string[] = [];
        sections.push("🔍 Application Security Audit");
        sections.push("=".repeat(55));

        const apps = await detectRunningApps();

        if (apps.length === 0) {
          sections.push("\nNo known applications detected.");
          sections.push("Recognized apps: " + Object.values(APP_PROFILES).map((p) => p.name).join(", "));
          return { content: [createTextContent(sections.join("\n"))] };
        }

        sections.push(`\nDetected ${apps.length} application(s):\n`);

        const riskOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
        apps.sort((a, b) => riskOrder[a.profile.riskLevel] - riskOrder[b.profile.riskLevel]);

        let totalRisks = 0;

        for (const app of apps) {
          const riskIcon = app.profile.riskLevel === "critical" ? "⛔" :
            app.profile.riskLevel === "high" ? "🔴" : app.profile.riskLevel === "medium" ? "🟡" : "🟢";

          sections.push(`── ${riskIcon} ${app.profile.name} ──`);
          sections.push(`  Category:     ${app.profile.category}`);
          sections.push(`  Risk Level:   ${app.profile.riskLevel.toUpperCase()}`);
          sections.push(`  Running as:   ${app.user}`);
          sections.push(`  PIDs:         ${app.pids.join(", ")}`);
          if (app.serviceUnit) sections.push(`  Service Unit: ${app.serviceUnit}`);

          if (app.listenPorts.length > 0) {
            sections.push(`  Listening Ports:`);
            for (const lp of app.listenPorts) {
              const external = !lp.address.includes("127.0.0.1") && !lp.address.includes("::1");
              sections.push(`    ${lp.protocol}/${lp.port} on ${lp.address} [${external ? "⚠️ EXTERNAL" : "✅ localhost"}]`);
            }
          }

          sections.push(`  Security Concerns:`);
          for (const concern of app.profile.securityConcerns) {
            sections.push(`    ⚠️ ${concern}`);
            totalRisks++;
          }

          sections.push(`  Top Recommendations:`);
          for (const rec of app.profile.recommendations.slice(0, 3)) {
            sections.push(`    💡 ${rec}`);
          }
          if (app.profile.recommendations.length > 3) {
            sections.push(`    ... +${app.profile.recommendations.length - 3} more (use app_harden_recommend)`);
          }
          sections.push("");
        }

        sections.push("── Summary ──");
        sections.push(`  Applications: ${apps.length} | Concerns: ${totalRisks} | Critical/High: ${apps.filter((a) => ["critical", "high"].includes(a.profile.riskLevel)).length}`);

        logChange(createChangeEntry({
          tool: "app_harden_audit",
          action: "Application security audit",
          target: "system",
          after: `${apps.length} apps, ${totalRisks} concerns`,
          dryRun: false,
          success: true,
        }));

        return { content: [createTextContent(sections.join("\n"))] };
      } catch (err: unknown) {
        return { content: [createErrorContent(err instanceof Error ? err.message : String(err))], isError: true };
      }
    }
  );

  // ── 2. app_harden_recommend ────────────────────────────────────────────

  server.tool(
    "app_harden_recommend",
    "Generate detailed hardening recommendations for a specific application while preserving its functionality. Covers network, filesystem, systemd, and application-level settings.",
    {
      app_name: z.string().describe(
        "Application name to get recommendations for. Available: " +
        Object.keys(APP_PROFILES).join(", ")
      ),
    },
    async ({ app_name }) => {
      try {
        const profileId = app_name.toLowerCase().replace(/[^a-z0-9]/g, "");
        const profile = APP_PROFILES[profileId];

        if (!profile) {
          const available = Object.entries(APP_PROFILES).map(([k, v]) => `${k} (${v.name})`).join(", ");
          return {
            content: [createErrorContent(`Unknown application '${app_name}'. Available: ${available}`)],
            isError: true,
          };
        }

        const sections: string[] = [];
        sections.push(`🛡️ Hardening Guide: ${profile.name}`);
        sections.push("=".repeat(55));
        sections.push(`Category: ${profile.category} | Risk: ${profile.riskLevel.toUpperCase()}`);

        sections.push("\n── Security Concerns ──");
        for (const concern of profile.securityConcerns) {
          sections.push(`  ⚠️ ${concern}`);
        }

        sections.push("\n── Network Hardening ──");
        if (profile.requiredPorts.length > 0) {
          sections.push("  Ports that MUST remain open (core functionality):");
          for (const p of profile.requiredPorts) {
            sections.push(`    ✅ ${p.protocol}/${p.port} — ${p.purpose}`);
          }
        }
        if (profile.localhostOnlyPorts.length > 0) {
          sections.push("  Ports to restrict to localhost/LAN:");
          for (const p of profile.localhostOnlyPorts) {
            sections.push(`    🔒 ${p.protocol}/${p.port} — ${p.purpose}`);
          }
        }
        sections.push("  Firewall strategy:");
        sections.push("    1. Allow required ports from any source");
        sections.push("    2. Restrict localhost-only ports to 127.0.0.1");
        sections.push("    3. Drop all other traffic to this application");
        sections.push(`    → Use app_harden_firewall --app_name ${profileId} to generate rules`);

        sections.push("\n── Systemd Sandboxing ──");
        sections.push("  Recommended directives for the service unit:");
        for (const [key, value] of Object.entries(profile.systemdHardening)) {
          sections.push(`    ${key}=${value}`);
        }
        if (profile.writablePaths.length > 0) {
          sections.push(`    ReadWritePaths=${profile.writablePaths.join(" ")}`);
        }
        sections.push(`    → Use app_harden_systemd --app_name ${profileId} to apply`);

        sections.push("\n── Application-Level Recommendations ──");
        for (let i = 0; i < profile.recommendations.length; i++) {
          sections.push(`  ${i + 1}. ${profile.recommendations[i]}`);
        }

        sections.push("\n── Filesystem Permissions ──");
        sections.push("  Writable paths (required for operation):");
        for (const p of profile.writablePaths) {
          sections.push(`    📝 ${p}`);
        }
        sections.push("  Read-only paths:");
        for (const p of profile.readablePaths) {
          sections.push(`    📖 ${p}`);
        }

        return { content: [createTextContent(sections.join("\n"))] };
      } catch (err: unknown) {
        return { content: [createErrorContent(err instanceof Error ? err.message : String(err))], isError: true };
      }
    }
  );

  // ── 3. app_harden_firewall ─────────────────────────────────────────────

  server.tool(
    "app_harden_firewall",
    "Generate and optionally apply firewall rules to restrict an application's network exposure while preserving its core functionality.",
    {
      app_name: z.string().describe("Application name (e.g., qbittorrent, nginx, redis)"),
      lan_cidr: z.string().optional().default("192.168.0.0/16").describe("LAN CIDR for localhost-only ports (default: 192.168.0.0/16)"),
      dry_run: z.boolean().optional().describe("Preview rules without applying"),
    },
    async ({ app_name, lan_cidr, dry_run }) => {
      try {
        const profileId = app_name.toLowerCase().replace(/[^a-z0-9]/g, "");
        const profile = APP_PROFILES[profileId];

        if (!profile) {
          return {
            content: [createErrorContent(`Unknown application '${app_name}'. Available: ${Object.keys(APP_PROFILES).join(", ")}`)],
            isError: true,
          };
        }

        const effectiveDryRun = dry_run ?? getConfig().dryRun;
        const sections: string[] = [];

        sections.push(`🔥 Firewall Rules for ${profile.name}`);
        sections.push("=".repeat(55));
        sections.push(`LAN CIDR: ${lan_cidr}`);
        sections.push(effectiveDryRun ? "\n[DRY RUN] Rules that would be applied:\n" : "\nApplying rules:\n");

        const rules: string[] = [];

        // Allow required ports from anywhere
        for (const p of profile.requiredPorts) {
          rules.push(`iptables -A INPUT -p ${p.protocol} --dport ${p.port} -j ACCEPT  # ${p.purpose}`);
        }

        // Restrict localhost-only ports to LAN
        for (const p of profile.localhostOnlyPorts) {
          rules.push(`iptables -A INPUT -p ${p.protocol} --dport ${p.port} -s 127.0.0.0/8 -j ACCEPT  # ${p.purpose} (localhost)`);
          rules.push(`iptables -A INPUT -p ${p.protocol} --dport ${p.port} -s ${lan_cidr} -j ACCEPT  # ${p.purpose} (LAN)`);
          rules.push(`iptables -A INPUT -p ${p.protocol} --dport ${p.port} -j DROP  # ${p.purpose} (block external)`);
        }

        for (const rule of rules) {
          sections.push(`  ${rule}`);
        }

        if (!effectiveDryRun && rules.length > 0) {
          let applied = 0;
          let failed = 0;
          for (const rule of rules) {
            const parts = rule.split("#")[0].trim().split(/\s+/);
            const result = await executeCommand({
              command: "sudo",
              args: parts,
              timeout: 10000,
            });
            if (result.exitCode === 0) applied++;
            else failed++;
          }
          sections.push(`\n✅ Applied ${applied} rules, ❌ ${failed} failed`);
        }

        sections.push("\n── Additional Recommendations ──");
        sections.push("  • Consider using nftables for more granular control");
        sections.push("  • Save rules with: sudo iptables-save > /etc/iptables/rules.v4");
        sections.push("  • Install iptables-persistent for reboot survival");

        logChange(createChangeEntry({
          tool: "app_harden_firewall",
          action: `Firewall rules for ${profile.name}`,
          target: profileId,
          after: `${rules.length} rules`,
          dryRun: effectiveDryRun,
          success: true,
        }));

        return { content: [createTextContent(sections.join("\n"))] };
      } catch (err: unknown) {
        return { content: [createErrorContent(err instanceof Error ? err.message : String(err))], isError: true };
      }
    }
  );

  // ── 4. app_harden_systemd ──────────────────────────────────────────────

  server.tool(
    "app_harden_systemd",
    "Apply systemd sandboxing to an application's service unit. Creates a drop-in override with security directives while preserving the app's ability to function.",
    {
      app_name: z.string().describe("Application name (e.g., qbittorrent, nginx, redis)"),
      service_name: z.string().optional().describe("Override systemd service name (auto-detected if omitted)"),
      dry_run: z.boolean().optional().describe("Preview changes without applying"),
    },
    async ({ app_name, service_name, dry_run }) => {
      try {
        const profileId = app_name.toLowerCase().replace(/[^a-z0-9]/g, "");
        const profile = APP_PROFILES[profileId];

        if (!profile) {
          return {
            content: [createErrorContent(`Unknown application '${app_name}'. Available: ${Object.keys(APP_PROFILES).join(", ")}`)],
            isError: true,
          };
        }

        const effectiveDryRun = dry_run ?? getConfig().dryRun;

        // Detect service unit if not provided
        let svcName = service_name;
        if (!svcName) {
          const svcResult = await executeCommand({
            command: "systemctl",
            args: ["list-units", "--type=service", "--state=running", "--no-pager", "--no-legend"],
            timeout: 10000,
          });
          if (svcResult.exitCode === 0) {
            for (const procName of profile.processNames) {
              for (const line of svcResult.stdout.split("\n")) {
                if (line.toLowerCase().includes(procName.toLowerCase())) {
                  svcName = line.trim().split(/\s+/)[0];
                  break;
                }
              }
              if (svcName) break;
            }
          }
        }

        const sections: string[] = [];
        sections.push(`🔒 Systemd Hardening: ${profile.name}`);
        sections.push("=".repeat(55));

        if (!svcName) {
          sections.push(`\n⚠️ No running systemd service found for ${profile.name}.`);
          sections.push("Provide --service_name manually if the service uses a different name.");
          sections.push("\nRecommended override content for when the service is configured:\n");
        } else {
          sections.push(`Service: ${svcName}`);
        }

        // Build override content
        const overrideLines = ["[Service]"];
        for (const [key, value] of Object.entries(profile.systemdHardening)) {
          overrideLines.push(`${key}=${value}`);
        }
        if (profile.writablePaths.length > 0) {
          overrideLines.push(`ReadWritePaths=${profile.writablePaths.join(" ")}`);
        }

        sections.push(effectiveDryRun ? "\n[DRY RUN] Override that would be created:\n" : "\nApplying override:\n");
        sections.push("  # /etc/systemd/system/" + (svcName ?? `${profileId}.service`) + ".d/hardening.conf");
        for (const line of overrideLines) {
          sections.push(`  ${line}`);
        }

        if (!effectiveDryRun && svcName) {
          const overrideDir = `/etc/systemd/system/${svcName}.d`;
          const overridePath = `${overrideDir}/hardening.conf`;
          const overrideContent = overrideLines.join("\n") + "\n";

          // Create directory
          await executeCommand({ command: "sudo", args: ["mkdir", "-p", overrideDir], timeout: 5000 });

          // Write override
          const writeResult = await executeCommand({
            command: "sudo",
            args: ["tee", overridePath],
            stdin: overrideContent,
            timeout: 5000,
          });

          if (writeResult.exitCode === 0) {
            // Reload systemd
            await executeCommand({ command: "sudo", args: ["systemctl", "daemon-reload"], timeout: 10000 });
            sections.push(`\n✅ Override written to ${overridePath}`);
            sections.push("✅ systemd daemon reloaded");
            sections.push(`\n⚠️ Restart the service to apply: sudo systemctl restart ${svcName}`);
          } else {
            sections.push(`\n❌ Failed to write override: ${writeResult.stderr}`);
          }
        }

        sections.push("\n── What These Directives Do ──");
        const explanations: Record<string, string> = {
          ProtectSystem: "Mounts /usr and /boot read-only (full) or entire filesystem (strict)",
          ProtectHome: "Makes /home, /root, /run/user inaccessible or read-only",
          PrivateTmp: "Creates a private /tmp namespace for this service",
          NoNewPrivileges: "Prevents the service from gaining new privileges via setuid/setgid",
          ProtectKernelTunables: "Makes /proc/sys, /sys read-only",
          ProtectKernelModules: "Prevents loading/unloading kernel modules",
          ProtectControlGroups: "Makes /sys/fs/cgroup read-only",
          RestrictNamespaces: "Restricts creation of new namespaces",
          RestrictRealtime: "Prevents acquiring realtime scheduling",
          MemoryDenyWriteExecute: "Prevents creating writable+executable memory mappings",
        };
        for (const [key] of Object.entries(profile.systemdHardening)) {
          if (explanations[key]) {
            sections.push(`  ${key}: ${explanations[key]}`);
          }
        }

        logChange(createChangeEntry({
          tool: "app_harden_systemd",
          action: `Systemd hardening for ${profile.name}`,
          target: svcName ?? profileId,
          after: `${Object.keys(profile.systemdHardening).length} directives`,
          dryRun: effectiveDryRun,
          success: true,
        }));

        return { content: [createTextContent(sections.join("\n"))] };
      } catch (err: unknown) {
        return { content: [createErrorContent(err instanceof Error ? err.message : String(err))], isError: true };
      }
    }
  );
}
