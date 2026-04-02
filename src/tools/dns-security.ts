/**
 * DNS security tools for Defense MCP Server.
 *
 * Registers 1 tool: dns_security (actions: audit_resolv, check_dnssec,
 * detect_tunneling, block_domains, query_log_audit)
 *
 * Provides DNS configuration auditing, DNSSEC validation checking,
 * DNS tunneling detection, domain blocking, and query log analysis.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { runCommand, type CommandResult } from "../core/run-command.js";
import { secureWriteFileSync, secureCopyFileSync } from "../core/secure-fs.js";
import {
  createErrorContent,
  formatToolOutput,
} from "../core/parsers.js";
import { validateInterface } from "../core/sanitizer.js";

// ── Constants ──────────────────────────────────────────────────────────────────

/** Well-known public DNS resolvers */
const PUBLIC_RESOLVERS: Record<string, string> = {
  "8.8.8.8": "Google Public DNS",
  "8.8.4.4": "Google Public DNS (secondary)",
  "1.1.1.1": "Cloudflare DNS",
  "1.0.0.1": "Cloudflare DNS (secondary)",
  "9.9.9.9": "Quad9 DNS",
  "149.112.112.112": "Quad9 DNS (secondary)",
  "208.67.222.222": "OpenDNS",
  "208.67.220.220": "OpenDNS (secondary)",
};

/** Suspicious TLDs commonly associated with malware/phishing */
const SUSPICIOUS_TLDS = new Set([
  ".top", ".xyz", ".buzz", ".club", ".work", ".date", ".loan",
  ".click", ".gdn", ".racing", ".win", ".bid", ".stream", ".download",
  ".review", ".accountant", ".science", ".party", ".trade",
]);

/** Maximum capture duration in seconds */
const MAX_CAPTURE_DURATION = 120;

/** Default entropy threshold for tunneling detection */
const DEFAULT_ENTROPY_THRESHOLD = 3.5;

// ── Helpers ────────────────────────────────────────────────────────────────────


/**
 * Run a command via sudo through spawnSafe.
 */
async function runSudoCommand(
  command: string,
  args: string[],
  timeoutMs = 30_000,
): Promise<CommandResult> {
  return runCommand("sudo", [command, ...args], timeoutMs);
}

// ── Shannon Entropy ────────────────────────────────────────────────────────────

/**
 * Calculate Shannon entropy of a string.
 * Pure function — no external dependencies.
 *
 * Higher entropy values indicate more randomness, which is characteristic
 * of DNS tunneling and DGA (Domain Generation Algorithm) domains.
 *
 * @param str - Input string to calculate entropy for
 * @returns Entropy value in bits per character
 */
export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;

  const freq: Record<string, number> = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] ?? 0) + 1;
  }

  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    if (p > 0) {
      entropy -= p * Math.log2(p);
    }
  }

  return entropy;
}

// ── DNSSEC Parsing ─────────────────────────────────────────────────────────────

interface DnssecResult {
  domain: string;
  dnssecEnabled: boolean;
  hasRRSIG: boolean;
  hasDNSKEY: boolean;
  hasDS: boolean;
  adFlag: boolean;
  chainValid: boolean;
  records: string[];
  issues: string[];
}

/**
 * Parse dig +dnssec output and determine DNSSEC status.
 */
export function parseDnssecOutput(domain: string, digOutput: string): DnssecResult {
  const result: DnssecResult = {
    domain,
    dnssecEnabled: false,
    hasRRSIG: false,
    hasDNSKEY: false,
    hasDS: false,
    adFlag: false,
    chainValid: false,
    records: [],
    issues: [],
  };

  const lines = digOutput.split("\n");

  for (const line of lines) {
    const trimmed = line.trim();

    // Check for AD (Authenticated Data) flag in header
    if (trimmed.includes("flags:") && trimmed.includes("ad")) {
      result.adFlag = true;
    }

    // Check for RRSIG records
    if (trimmed.includes("RRSIG")) {
      result.hasRRSIG = true;
      result.records.push(trimmed);
    }

    // Check for DNSKEY records
    if (trimmed.includes("DNSKEY")) {
      result.hasDNSKEY = true;
      result.records.push(trimmed);
    }

    // Check for DS records
    if (trimmed.includes("\tDS\t") || trimmed.includes(" DS ")) {
      result.hasDS = true;
      result.records.push(trimmed);
    }

    // Check for SERVFAIL (may indicate DNSSEC validation failure)
    if (trimmed.includes("SERVFAIL")) {
      result.issues.push("SERVFAIL response — DNSSEC validation may have failed");
    }
  }

  // Determine DNSSEC status
  result.dnssecEnabled = result.hasRRSIG || result.hasDNSKEY;
  result.chainValid = result.adFlag && result.hasRRSIG;

  // Add issues if DNSSEC is incomplete
  if (!result.hasRRSIG) {
    result.issues.push("No RRSIG records found — domain may not be DNSSEC-signed");
  }
  if (!result.adFlag && result.hasRRSIG) {
    result.issues.push("RRSIG present but AD flag not set — chain of trust may be broken");
  }

  return result;
}

// ── DNS Tunneling Analysis ────────────────────────────────────────────────────

interface SuspiciousQuery {
  domain: string;
  entropy: number;
  labelLength: number;
  reason: string;
}

/**
 * Analyze captured DNS queries for tunneling indicators.
 */
export function analyzeDnsQueries(
  capturedOutput: string,
  entropyThreshold: number,
): { suspicious: SuspiciousQuery[]; totalQueries: number; txtQueries: number; nullQueries: number; domainCounts: Record<string, number> } {
  const lines = capturedOutput.split("\n").filter((l) => l.trim().length > 0);
  const suspicious: SuspiciousQuery[] = [];
  const domainCounts: Record<string, number> = {};
  let txtQueries = 0;
  let nullQueries = 0;
  let totalQueries = 0;

  // Pattern to extract domain from tcpdump DNS output
  // e.g., "12:00:00.000000 IP 192.168.1.1.12345 > 8.8.8.8.53: 12345+ A? example.com. (30)"
  const dnsQueryRe = /\s(?:A\?|AAAA\?|TXT\?|NULL\?|MX\?|CNAME\?|ANY\?)\s+(\S+?)\.?\s/;
  const txtRe = /\sTXT\?\s/;
  const nullRe = /\sNULL\?\s/;

  for (const line of lines) {
    const match = dnsQueryRe.exec(line);
    if (!match) continue;

    totalQueries++;
    const domain = match[1].replace(/\.$/, "");

    // Count domain frequencies
    const baseDomain = domain.split(".").slice(-2).join(".");
    domainCounts[baseDomain] = (domainCounts[baseDomain] ?? 0) + 1;

    // Count TXT/NULL queries
    if (txtRe.test(line)) txtQueries++;
    if (nullRe.test(line)) nullQueries++;

    // Analyze subdomain labels for tunneling indicators
    const labels = domain.split(".");
    const subdomain = labels.slice(0, -2).join(".");

    if (subdomain.length > 0) {
      const entropy = calculateShannonEntropy(subdomain);
      const longestLabel = Math.max(...labels.map((l) => l.length));

      const reasons: string[] = [];
      if (entropy > entropyThreshold) {
        reasons.push(`high entropy (${entropy.toFixed(2)})`);
      }
      if (longestLabel > 50) {
        reasons.push(`long label (${longestLabel} chars)`);
      }
      if (subdomain.length > 100) {
        reasons.push(`very long subdomain (${subdomain.length} chars)`);
      }

      if (reasons.length > 0) {
        suspicious.push({
          domain,
          entropy,
          labelLength: longestLabel,
          reason: reasons.join(", "),
        });
      }
    }
  }

  return { suspicious, totalQueries, txtQueries, nullQueries, domainCounts };
}

// ── Resolv.conf Parsing ───────────────────────────────────────────────────────

interface ResolvAuditResult {
  nameservers: Array<{ ip: string; type: "public" | "internal" | "loopback"; provider?: string }>;
  searchDomains: string[];
  options: string[];
  findings: Array<{ check: string; status: "PASS" | "FAIL" | "INFO" | "WARN"; detail: string }>;
  recommendations: string[];
}

/**
 * Audit resolv.conf content.
 */
export function auditResolvConf(resolvContent: string, resolvedStatus: string): ResolvAuditResult {
  const result: ResolvAuditResult = {
    nameservers: [],
    searchDomains: [],
    options: [],
    findings: [],
    recommendations: [],
  };

  // Parse resolv.conf
  const lines = resolvContent.split("\n");
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith("#") || trimmed.length === 0) continue;

    if (trimmed.startsWith("nameserver ")) {
      const ip = trimmed.replace("nameserver ", "").trim();
      const provider = PUBLIC_RESOLVERS[ip];
      let type: "public" | "internal" | "loopback" = "internal";
      if (provider) type = "public";
      else if (ip === "127.0.0.1" || ip === "::1" || ip.startsWith("127.0.0.")) type = "loopback";

      result.nameservers.push({ ip, type, provider });
    } else if (trimmed.startsWith("search ")) {
      result.searchDomains = trimmed.replace("search ", "").trim().split(/\s+/);
    } else if (trimmed.startsWith("options ")) {
      result.options = trimmed.replace("options ", "").trim().split(/\s+/);
    }
  }

  // Check number of nameservers
  if (result.nameservers.length === 0) {
    result.findings.push({ check: "nameserver_count", status: "FAIL", detail: "No nameservers configured" });
    result.recommendations.push("Configure at least 2 DNS nameservers for redundancy");
  } else if (result.nameservers.length === 1) {
    result.findings.push({ check: "nameserver_count", status: "WARN", detail: `Only ${result.nameservers.length} nameserver configured` });
    result.recommendations.push("Add a secondary nameserver for redundancy");
  } else {
    result.findings.push({ check: "nameserver_count", status: "PASS", detail: `${result.nameservers.length} nameservers configured` });
  }

  // Check for public vs internal resolvers
  const publicNs = result.nameservers.filter((ns) => ns.type === "public");
  const internalNs = result.nameservers.filter((ns) => ns.type === "internal");
  if (publicNs.length > 0 && internalNs.length === 0) {
    result.findings.push({ check: "resolver_type", status: "INFO", detail: `Using public resolvers: ${publicNs.map((n) => n.provider ?? n.ip).join(", ")}` });
  } else if (internalNs.length > 0) {
    result.findings.push({ check: "resolver_type", status: "INFO", detail: `Using internal resolvers: ${internalNs.map((n) => n.ip).join(", ")}` });
  }

  // Check systemd-resolved for DoT/DNSSEC
  const hasDot = resolvedStatus.includes("DNSOverTLS") && !resolvedStatus.includes("DNSOverTLS: no");
  const hasDnssec = resolvedStatus.includes("DNSSEC") && !resolvedStatus.includes("DNSSEC: no") && !resolvedStatus.includes("DNSSEC setting: no");

  result.findings.push({
    check: "dns_over_tls",
    status: hasDot ? "PASS" : "FAIL",
    detail: hasDot ? "DNS over TLS is enabled" : "DNS over TLS is not enabled",
  });
  if (!hasDot) {
    result.recommendations.push("Enable DNS over TLS in systemd-resolved for encrypted DNS queries");
  }

  result.findings.push({
    check: "dnssec_validation",
    status: hasDnssec ? "PASS" : "FAIL",
    detail: hasDnssec ? "DNSSEC validation is enabled" : "DNSSEC validation is not enabled",
  });
  if (!hasDnssec) {
    result.recommendations.push("Enable DNSSEC validation in systemd-resolved to prevent DNS spoofing");
  }

  return result;
}

// ── Query Log Analysis ────────────────────────────────────────────────────────

interface QueryLogAnalysis {
  totalEntries: number;
  topDomains: Array<{ domain: string; count: number }>;
  suspiciousTldQueries: Array<{ domain: string; tld: string }>;
  nxdomainCount: number;
  nxdomainRate: number;
  queryTimeline: Record<string, number>;
  findings: string[];
}

/**
 * Analyze DNS query log content.
 */
export function analyzeQueryLog(logContent: string): QueryLogAnalysis {
  const lines = logContent.split("\n").filter((l) => l.trim().length > 0);
  const domainCounts: Record<string, number> = {};
  const suspiciousTldQueries: Array<{ domain: string; tld: string }> = [];
  const queryTimeline: Record<string, number> = {};
  let nxdomainCount = 0;
  let totalEntries = 0;

  // Patterns for different DNS log formats
  // dnsmasq: "Jan 01 10:00:00 host dnsmasq[1234]: query[A] example.com from 192.168.1.1"
  // systemd-resolved: "... lookup example.com ..."
  const dnsmasqRe = /query\[(?:A|AAAA|TXT|MX|CNAME|ANY)\]\s+(\S+)/;
  const resolvedRe = /(?:resolved|query)\S*\s+(\S+\.(?:[a-z]{2,}))/i;
  const nxdomainRe = /NXDOMAIN|nxdomain|status: NXDOMAIN/i;
  const hourRe = /\b(\d{2}):\d{2}:\d{2}\b/;

  for (const line of lines) {
    totalEntries++;

    // Extract domain
    let domain: string | null = null;
    const dnsmasqMatch = dnsmasqRe.exec(line);
    if (dnsmasqMatch) {
      domain = dnsmasqMatch[1];
    } else {
      const resolvedMatch = resolvedRe.exec(line);
      if (resolvedMatch) {
        domain = resolvedMatch[1];
      }
    }

    if (domain) {
      domain = domain.replace(/\.$/, "").toLowerCase();
      domainCounts[domain] = (domainCounts[domain] ?? 0) + 1;

      // Check for suspicious TLDs
      for (const tld of SUSPICIOUS_TLDS) {
        if (domain.endsWith(tld)) {
          suspiciousTldQueries.push({ domain, tld });
          break;
        }
      }
    }

    // Count NXDOMAIN responses
    if (nxdomainRe.test(line)) {
      nxdomainCount++;
    }

    // Build timeline by hour
    const hourMatch = hourRe.exec(line);
    if (hourMatch) {
      const hour = `${hourMatch[1]}:00`;
      queryTimeline[hour] = (queryTimeline[hour] ?? 0) + 1;
    }
  }

  // Sort top domains
  const topDomains = Object.entries(domainCounts)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 20)
    .map(([domain, count]) => ({ domain, count }));

  const nxdomainRate = totalEntries > 0 ? nxdomainCount / totalEntries : 0;

  // Generate findings
  const findings: string[] = [];
  if (nxdomainRate > 0.3) {
    findings.push(`High NXDOMAIN rate (${(nxdomainRate * 100).toFixed(1)}%) — may indicate DGA activity`);
  }
  if (suspiciousTldQueries.length > 0) {
    findings.push(`${suspiciousTldQueries.length} queries to suspicious TLDs detected`);
  }
  if (topDomains.length > 0 && topDomains[0].count > 100) {
    findings.push(`Unusually high query volume for ${topDomains[0].domain} (${topDomains[0].count} queries)`);
  }
  if (findings.length === 0) {
    findings.push("No suspicious DNS activity detected in the analyzed logs");
  }

  return {
    totalEntries,
    topDomains,
    suspiciousTldQueries,
    nxdomainCount,
    nxdomainRate,
    queryTimeline,
    findings,
  };
}

// ── Registration entry point ───────────────────────────────────────────────

export function registerDnsSecurityTools(server: McpServer): void {
  server.tool(
    "dns_security",
    "DNS: resolver audit, DNSSEC check, tunneling detection, domain blocklists, query log audit",
    {
      action: z
        .enum(["audit_resolv", "check_dnssec", "detect_tunneling", "block_domains", "query_log_audit"])
        .describe("DNS security action"),
      domain: z
        .string()
        .optional()
        .describe("Domain to check"),
      interface: z
        .string()
        .min(1)
        .optional()
        .default("any")
        .describe("Network interface for capture"),
      duration: z
        .number()
        .optional()
        .default(30)
        .describe("Capture duration in seconds (max 120)"),
      blocklist_path: z
        .string()
        .optional()
        .describe("Path to blocklist file"),
      domains_to_block: z
        .array(z.string())
        .optional()
        .describe("Domains to add to blocklist"),
      log_path: z
        .string()
        .optional()
        .describe("Path to DNS query log"),
      threshold: z
        .number()
        .optional()
        .default(3.5)
        .describe("Entropy threshold for tunneling detection"),
    },
    async (params) => {
      const { action } = params;

      switch (action) {
        // ── audit_resolv ────────────────────────────────────────────────
        case "audit_resolv": {
          try {
            // Read /etc/resolv.conf
            const resolvResult = await runCommand("cat", ["/etc/resolv.conf"]);

            // Try systemd-resolve --status first, fall back to resolvectl
            let resolvedResult = await runCommand("systemd-resolve", ["--status"], 10_000);
            if (resolvedResult.exitCode !== 0) {
              resolvedResult = await runCommand("resolvectl", ["status"], 10_000);
            }

            const audit = auditResolvConf(
              resolvResult.exitCode === 0 ? resolvResult.stdout : "",
              resolvedResult.exitCode === 0 ? resolvedResult.stdout : "",
            );

            return {
              content: [
                formatToolOutput({
                  action: "audit_resolv",
                  nameservers: audit.nameservers,
                  searchDomains: audit.searchDomains,
                  options: audit.options,
                  findings: audit.findings,
                  recommendations: audit.recommendations,
                  rawResolvConf: resolvResult.exitCode === 0 ? resolvResult.stdout.trim() : "[could not read /etc/resolv.conf]",
                }),
              ],
            };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`audit_resolv failed: ${msg}`)], isError: true };
          }
        }

        // ── check_dnssec ────────────────────────────────────────────────
        case "check_dnssec": {
          const { domain } = params;
          if (!domain) {
            return { content: [createErrorContent("check_dnssec requires a 'domain' parameter")], isError: true };
          }

          try {
            // Run dig +dnssec for the domain
            const digResult = await runCommand("dig", ["+dnssec", "+multi", domain], 15_000);

            if (digResult.exitCode !== 0) {
              return { content: [createErrorContent(`dig command failed: ${digResult.stderr}`)], isError: true };
            }

            const dnssec = parseDnssecOutput(domain, digResult.stdout);

            // Also check the DS record at the parent zone
            const dsResult = await runCommand("dig", ["+short", "DS", domain], 15_000);
            if (dsResult.exitCode === 0 && dsResult.stdout.trim().length > 0) {
              dnssec.hasDS = true;
              dnssec.records.push(...dsResult.stdout.trim().split("\n"));
            }

            return {
              content: [
                formatToolOutput({
                  action: "check_dnssec",
                  domain,
                  dnssecEnabled: dnssec.dnssecEnabled,
                  hasRRSIG: dnssec.hasRRSIG,
                  hasDNSKEY: dnssec.hasDNSKEY,
                  hasDS: dnssec.hasDS,
                  adFlag: dnssec.adFlag,
                  chainOfTrustValid: dnssec.chainValid,
                  issues: dnssec.issues,
                  recordCount: dnssec.records.length,
                  records: dnssec.records.slice(0, 20),
                }),
              ],
            };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`check_dnssec failed: ${msg}`)], isError: true };
          }
        }

        // ── detect_tunneling ────────────────────────────────────────────
        case "detect_tunneling": {
          const iface = params.interface ?? "any";
          const duration = Math.min(params.duration ?? 30, MAX_CAPTURE_DURATION);
          const entropyThreshold = params.threshold ?? DEFAULT_ENTROPY_THRESHOLD;

          try {
            if (iface !== "any") validateInterface(iface);

            const captureTimeout = duration * 1000 + 5000;
            const captureResult = await runSudoCommand(
              "tcpdump",
              ["-i", iface, "-c", "1000", "-n", "port", "53", "-l"],
              captureTimeout,
            );

            const analysis = analyzeDnsQueries(captureResult.stdout, entropyThreshold);

            // Check for high TXT/NULL query ratios
            const txtRatio = analysis.totalQueries > 0
              ? analysis.txtQueries / analysis.totalQueries
              : 0;
            const findings: string[] = [];
            if (analysis.suspicious.length > 0) {
              findings.push(`${analysis.suspicious.length} suspicious queries detected with high entropy`);
            }
            if (txtRatio > 0.3) {
              findings.push(`High TXT query ratio (${(txtRatio * 100).toFixed(1)}%) — may indicate tunneling`);
            }
            if (analysis.nullQueries > 0) {
              findings.push(`${analysis.nullQueries} NULL record queries detected — unusual for normal traffic`);
            }

            // Check for single-domain concentration
            const domainEntries = Object.entries(analysis.domainCounts)
              .sort(([, a], [, b]) => b - a);
            if (domainEntries.length > 0 && domainEntries[0][1] > analysis.totalQueries * 0.5) {
              findings.push(`High concentration to ${domainEntries[0][0]} (${domainEntries[0][1]}/${analysis.totalQueries} queries)`);
            }

            if (findings.length === 0) {
              findings.push("No DNS tunneling indicators detected");
            }

            return {
              content: [
                formatToolOutput({
                  action: "detect_tunneling",
                  interface: iface,
                  duration,
                  entropyThreshold,
                  totalQueries: analysis.totalQueries,
                  txtQueries: analysis.txtQueries,
                  nullQueries: analysis.nullQueries,
                  suspiciousQueries: analysis.suspicious,
                  domainDistribution: domainEntries.slice(0, 10).map(([d, c]) => ({ domain: d, count: c })),
                  findings,
                  timedOut: captureResult.stderr.includes("[TIMEOUT]"),
                }),
              ],
            };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`detect_tunneling failed: ${msg}`)], isError: true };
          }
        }

        // ── block_domains ───────────────────────────────────────────────
        case "block_domains": {
          const { blocklist_path, domains_to_block } = params;

          if (!domains_to_block && !blocklist_path) {
            return {
              content: [createErrorContent("block_domains requires either 'domains_to_block' or 'blocklist_path'")],
              isError: true,
            };
          }

          try {
            // Collect domains to block
            let domainsToAdd: string[] = [];

            if (domains_to_block && domains_to_block.length > 0) {
              domainsToAdd.push(...domains_to_block);
            }

            if (blocklist_path) {
              const fileResult = await runCommand("cat", [blocklist_path]);
              if (fileResult.exitCode !== 0) {
                return {
                  content: [createErrorContent(`Failed to read blocklist file: ${fileResult.stderr}`)],
                  isError: true,
                };
              }
              const fileDomains = fileResult.stdout
                .split("\n")
                .map((l) => l.trim())
                .filter((l) => l.length > 0 && !l.startsWith("#"));
              domainsToAdd.push(...fileDomains);
            }

            // Deduplicate
            domainsToAdd = [...new Set(domainsToAdd)];

            if (domainsToAdd.length === 0) {
              return {
                content: [createErrorContent("No domains to block — empty list provided")],
                isError: true,
              };
            }

            // Read current /etc/hosts
            const hostsResult = await runSudoCommand("cat", ["/etc/hosts"]);
            const currentHosts = hostsResult.exitCode === 0 ? hostsResult.stdout : "";

            // Backup /etc/hosts before modifying
            const backupPath = `/etc/hosts.bak.${Date.now()}`;
            try {
              secureCopyFileSync("/etc/hosts", backupPath);
            } catch {
              // If secureCopyFileSync fails, try via sudo cp
              await runSudoCommand("cp", ["/etc/hosts", backupPath]);
            }

            // Build new entries (avoid duplicates)
            const existingBlocked = new Set<string>();
            for (const line of currentHosts.split("\n")) {
              const match = /^0\.0\.0\.0\s+(\S+)/.exec(line.trim());
              if (match) existingBlocked.add(match[1].toLowerCase());
            }

            const newEntries: string[] = [];
            const alreadyBlocked: string[] = [];
            for (const domain of domainsToAdd) {
              const lower = domain.toLowerCase().replace(/\.$/, "");
              if (existingBlocked.has(lower)) {
                alreadyBlocked.push(lower);
              } else {
                newEntries.push(`0.0.0.0 ${lower}`);
              }
            }

            if (newEntries.length === 0) {
              return {
                content: [
                  formatToolOutput({
                    action: "block_domains",
                    domainsAdded: 0,
                    alreadyBlocked: alreadyBlocked.length,
                    message: "All specified domains are already blocked",
                  }),
                ],
              };
            }

            // Append new entries to /etc/hosts
            const separator = "\n# ── Defense DNS Blocklist ──\n";
            const newContent = currentHosts.trimEnd() +
              (currentHosts.includes("Defense DNS Blocklist") ? "\n" : separator) +
              newEntries.join("\n") + "\n";

            try {
              secureWriteFileSync("/etc/hosts", newContent, "utf-8");
            } catch {
              // If direct write fails, try via sudo tee
              const teeResult = await runCommand("sudo", ["tee", "/etc/hosts"], 10_000);
              if (teeResult.exitCode !== 0) {
                return {
                  content: [createErrorContent(`Failed to write to /etc/hosts: ${teeResult.stderr}`)],
                  isError: true,
                };
              }
            }

            return {
              content: [
                formatToolOutput({
                  action: "block_domains",
                  domainsAdded: newEntries.length,
                  alreadyBlocked: alreadyBlocked.length,
                  backupPath,
                  addedDomains: newEntries.map((e) => e.replace("0.0.0.0 ", "")),
                  skippedDomains: alreadyBlocked,
                }),
              ],
            };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`block_domains failed: ${msg}`)], isError: true };
          }
        }

        // ── query_log_audit ─────────────────────────────────────────────
        case "query_log_audit": {
          const { log_path } = params;

          try {
            let logContent = "";

            if (log_path) {
              // Read specified log file
              const fileResult = await runSudoCommand("cat", [log_path]);
              if (fileResult.exitCode !== 0) {
                return {
                  content: [createErrorContent(`Failed to read log file ${log_path}: ${fileResult.stderr}`)],
                  isError: true,
                };
              }
              logContent = fileResult.stdout;
            } else {
              // Try journalctl for systemd-resolved first
              const journalResult = await runCommand(
                "journalctl",
                ["-u", "systemd-resolved", "-n", "500", "--no-pager"],
                15_000,
              );

              if (journalResult.exitCode === 0 && journalResult.stdout.trim().length > 0) {
                logContent = journalResult.stdout;
              } else {
                // Fall back to dnsmasq log
                const dnsmasqResult = await runSudoCommand(
                  "grep",
                  ["-i", "dnsmasq", "/var/log/syslog"],
                  15_000,
                );
                if (dnsmasqResult.exitCode === 0) {
                  logContent = dnsmasqResult.stdout;
                } else {
                  // Try /var/log/messages as last resort
                  const messagesResult = await runSudoCommand(
                    "grep",
                    ["-i", "dns\\|query\\|named", "/var/log/messages"],
                    15_000,
                  );
                  logContent = messagesResult.exitCode === 0 ? messagesResult.stdout : "";
                }
              }
            }

            if (logContent.trim().length === 0) {
              return {
                content: [
                  formatToolOutput({
                    action: "query_log_audit",
                    message: "No DNS query logs found. Enable DNS query logging in systemd-resolved or dnsmasq.",
                    checkedSources: log_path ? [log_path] : ["journalctl (systemd-resolved)", "/var/log/syslog (dnsmasq)", "/var/log/messages"],
                  }),
                ],
              };
            }

            const analysis = analyzeQueryLog(logContent);

            return {
              content: [
                formatToolOutput({
                  action: "query_log_audit",
                  logSource: log_path ?? "system logs",
                  totalEntries: analysis.totalEntries,
                  topQueriedDomains: analysis.topDomains,
                  suspiciousTldQueries: analysis.suspiciousTldQueries.slice(0, 50),
                  nxdomainCount: analysis.nxdomainCount,
                  nxdomainRate: `${(analysis.nxdomainRate * 100).toFixed(1)}%`,
                  queryTimeline: analysis.queryTimeline,
                  findings: analysis.findings,
                }),
              ],
            };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`query_log_audit failed: ${msg}`)], isError: true };
          }
        }

        default:
          return { content: [createErrorContent(`Unknown action: ${action}`)], isError: true };
      }
    },
  );
}
