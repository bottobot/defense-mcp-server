/**
 * Threat intelligence tools for Defense MCP Server.
 *
 * Registers 1 tool: threat_intel (actions: check_ip, check_hash, check_domain,
 * update_feeds, blocklist_apply)
 *
 * Provides IP/hash/domain reputation checking against local threat intelligence
 * feeds, feed management, and blocklist application to iptables/fail2ban/hosts.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { spawnSafe } from "../core/spawn-safe.js";
import {
  createTextContent,
  createErrorContent,
  formatToolOutput,
} from "../core/parsers.js";
import type { ChildProcess } from "node:child_process";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";

// ── Constants ──────────────────────────────────────────────────────────────────

/** Base directory for threat intelligence feeds */
const FEED_BASE_DIR = "/var/lib/defense-mcp/threat-feeds";

/** Subdirectory for hash-based feeds */
const HASH_FEED_DIR = `${FEED_BASE_DIR}/hashes`;

/** Subdirectory for domain-based feeds */
const DOMAIN_FEED_DIR = `${FEED_BASE_DIR}/domains`;

/** ClamAV signature database path */
const CLAMAV_DB_PATH = "/var/lib/clamav";

/** Maximum entries to apply in a single blocklist operation */
const MAX_BATCH_SIZE = 1000;

/** Known sinkhole IPs */
const SINKHOLE_IPS = new Set(["0.0.0.0", "127.0.0.1"]);

/** Basic IPv4 regex for validation */
const IPV4_REGEX = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

// ── Helpers ────────────────────────────────────────────────────────────────────

interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

/**
 * Run a command via spawnSafe and collect output as a promise.
 * Handles errors gracefully — returns error info instead of throwing.
 */
async function runCommand(
  command: string,
  args: string[],
  timeoutMs = 30_000,
): Promise<CommandResult> {
  return new Promise((resolve) => {
    let child: ChildProcess;
    try {
      child = spawnSafe(command, args);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      resolve({ stdout: "", stderr: msg, exitCode: -1 });
      return;
    }

    let stdout = "";
    let stderr = "";
    let resolved = false;

    const timer = setTimeout(() => {
      if (!resolved) {
        resolved = true;
        child.kill("SIGTERM");
        resolve({ stdout, stderr: stderr + "\n[TIMEOUT]", exitCode: -1 });
      }
    }, timeoutMs);

    child.stdout?.on("data", (data: Buffer) => {
      stdout += data.toString();
    });
    child.stderr?.on("data", (data: Buffer) => {
      stderr += data.toString();
    });

    child.on("close", (code: number | null) => {
      if (!resolved) {
        resolved = true;
        clearTimeout(timer);
        resolve({ stdout, stderr, exitCode: code ?? -1 });
      }
    });

    child.on("error", (err: Error) => {
      if (!resolved) {
        resolved = true;
        clearTimeout(timer);
        resolve({ stdout, stderr: err.message, exitCode: -1 });
      }
    });
  });
}

// ── Validation ─────────────────────────────────────────────────────────────────

/**
 * Validate an IPv4 address.
 * Returns true if the address is a valid IPv4 address.
 */
export function isValidIPv4(ip: string): boolean {
  const match = IPV4_REGEX.exec(ip);
  if (!match) return false;
  for (let i = 1; i <= 4; i++) {
    const octet = parseInt(match[i], 10);
    if (octet < 0 || octet > 255) return false;
  }
  return true;
}

/**
 * Auto-detect hash type based on string length.
 * Returns the hash type or "unknown".
 */
export function detectHashType(hash: string): "MD5" | "SHA1" | "SHA256" | "unknown" {
  const cleaned = hash.trim().toLowerCase();
  // Validate hex characters only
  if (!/^[0-9a-f]+$/.test(cleaned)) return "unknown";

  switch (cleaned.length) {
    case 32: return "MD5";
    case 40: return "SHA1";
    case 64: return "SHA256";
    default: return "unknown";
  }
}

/**
 * Read feed files from a directory and return matching indicators.
 * Each file is expected to have one indicator per line, with '#' comments.
 */
function searchFeedDirectory(
  feedDir: string,
  indicator: string,
): Array<{ feed: string; matched: boolean }> {
  const results: Array<{ feed: string; matched: boolean }> = [];

  if (!existsSync(feedDir)) {
    return results;
  }

  try {
    const files = readdirSync(feedDir);
    for (const file of files) {
      const filePath = `${feedDir}/${file}`;
      try {
        const stat = statSync(filePath);
        if (!stat.isFile()) continue;

        const content = readFileSync(filePath, "utf-8");
        const lines = content.split("\n")
          .map((l) => l.trim().toLowerCase())
          .filter((l) => l.length > 0 && !l.startsWith("#"));

        const normalizedIndicator = indicator.trim().toLowerCase();
        // Match exact line or lines that start with the indicator
        // (feeds may include metadata after indicator, e.g. "hash:malware_name")
        const matched = lines.some((l: string) =>
          l === normalizedIndicator || l.startsWith(normalizedIndicator + ":") ||
          l.startsWith(normalizedIndicator + ",") || l.startsWith(normalizedIndicator + "\t") ||
          l.startsWith(normalizedIndicator + " "),
        );
        results.push({ feed: file, matched });
      } catch {
        // Skip unreadable files
      }
    }
  } catch {
    // Directory read failed — return empty
  }

  return results;
}

/**
 * List available feeds with metadata.
 */
function listFeeds(feedDir: string): Array<{
  name: string;
  size: number;
  lastUpdated: string;
  indicatorCount: number;
}> {
  const feeds: Array<{
    name: string;
    size: number;
    lastUpdated: string;
    indicatorCount: number;
  }> = [];

  if (!existsSync(feedDir)) {
    return feeds;
  }

  try {
    const files = readdirSync(feedDir);
    for (const file of files) {
      const filePath = `${feedDir}/${file}`;
      try {
        const stat = statSync(filePath);
        if (!stat.isFile()) continue;

        const content = readFileSync(filePath, "utf-8");
        const indicatorCount = content.split("\n")
          .filter((l) => l.trim().length > 0 && !l.trim().startsWith("#"))
          .length;

        feeds.push({
          name: file,
          size: stat.size,
          lastUpdated: stat.mtime.toISOString(),
          indicatorCount,
        });
      } catch {
        // Skip unreadable files
      }
    }
  } catch {
    // Directory read failed
  }

  return feeds;
}

// ── Registration entry point ───────────────────────────────────────────────

export function registerThreatIntelTools(server: McpServer): void {
  server.tool(
    "threat_intel",
    "Threat intelligence: check IPs, hashes, and domains against local threat feeds, manage feed updates, and apply blocklists to iptables/fail2ban/hosts.",
    {
      action: z
        .enum(["check_ip", "check_hash", "check_domain", "update_feeds", "blocklist_apply"])
        .describe(
          "Action: check_ip=check IP reputation, check_hash=check file hash, check_domain=check domain reputation, update_feeds=manage threat feeds, blocklist_apply=apply blocklist to security tools",
        ),
      indicator: z
        .string()
        .optional()
        .describe("IP address, file hash, or domain to check (used with check_ip, check_hash, check_domain)"),
      feed_name: z
        .string()
        .optional()
        .describe("Name of threat feed to update (used with update_feeds)"),
      feed_url: z
        .string()
        .optional()
        .describe("URL of threat feed to download (used with update_feeds)"),
      blocklist_path: z
        .string()
        .optional()
        .describe("Path to blocklist file (used with blocklist_apply)"),
      apply_to: z
        .enum(["iptables", "fail2ban", "hosts"])
        .optional()
        .default("iptables")
        .describe("Target to apply blocklist to (used with blocklist_apply, default iptables)"),
      output_format: z
        .enum(["text", "json"])
        .optional()
        .default("text")
        .describe("Output format (default text)"),
    },
    async (params) => {
      const { action } = params;

      switch (action) {
        // ── check_ip ──────────────────────────────────────────────────────
        case "check_ip": {
          const { indicator } = params;
          if (!indicator) {
            return {
              content: [createErrorContent("check_ip requires an 'indicator' parameter (IP address)")],
              isError: true,
            };
          }

          if (!isValidIPv4(indicator)) {
            return {
              content: [createErrorContent(`Invalid IP address format: ${indicator}`)],
              isError: true,
            };
          }

          try {
            // Check against local threat feeds
            const feedMatches = searchFeedDirectory(FEED_BASE_DIR, indicator);
            const matchedFeeds = feedMatches.filter((f) => f.matched).map((f) => f.feed);

            // Check fail2ban banned list
            let inFail2ban = false;
            const fail2banResult = await runCommand(
              "fail2ban-client", ["status"], 10_000,
            );
            if (fail2banResult.exitCode === 0) {
              // Extract jail names and check each
              const jailMatch = fail2banResult.stdout.match(/Jail list:\s*(.+)/);
              if (jailMatch) {
                const jails = jailMatch[1].split(",").map((j) => j.trim()).filter((j) => j.length > 0);
                for (const jail of jails) {
                  const jailStatus = await runCommand(
                    "fail2ban-client", ["status", jail], 10_000,
                  );
                  if (jailStatus.exitCode === 0 && jailStatus.stdout.includes(indicator)) {
                    inFail2ban = true;
                    break;
                  }
                }
              }
            }

            // Check iptables DROP rules
            let inIptables = false;
            const iptablesResult = await runCommand(
              "iptables", ["-L", "-n"], 10_000,
            );
            if (iptablesResult.exitCode === 0) {
              const lines = iptablesResult.stdout.split("\n");
              for (const line of lines) {
                if (line.includes("DROP") && line.includes(indicator)) {
                  inIptables = true;
                  break;
                }
              }
            }

            // Get geo/whois info
            let whoisInfo = "";
            const whoisResult = await runCommand(
              "whois", [indicator], 15_000,
            );
            if (whoisResult.exitCode === 0) {
              // Extract key fields
              const lines = whoisResult.stdout.split("\n");
              const relevantFields = ["country", "orgname", "org-name", "netname", "descr"];
              const extracted: string[] = [];
              for (const line of lines) {
                const lower = line.toLowerCase();
                for (const field of relevantFields) {
                  if (lower.startsWith(field + ":")) {
                    extracted.push(line.trim());
                    break;
                  }
                }
              }
              whoisInfo = extracted.join("\n");
            }

            // Calculate a basic reputation score (0=clean, 100=malicious)
            let reputationScore = 0;
            if (matchedFeeds.length > 0) reputationScore += 50 + (matchedFeeds.length * 10);
            if (inFail2ban) reputationScore += 20;
            if (inIptables) reputationScore += 10;
            reputationScore = Math.min(reputationScore, 100);

            const alreadyBlocked = inFail2ban || inIptables;

            const output = {
              action: "check_ip",
              indicator,
              feedsChecked: feedMatches.length,
              feedMatches: matchedFeeds,
              matchFound: matchedFeeds.length > 0,
              reputationScore,
              inFail2ban,
              inIptables,
              alreadyBlocked,
              whoisInfo: whoisInfo || "No whois data available",
            };

            if (params.output_format === "json") {
              return { content: [formatToolOutput(output)] };
            }

            return {
              content: [createTextContent(
                `Threat Intel — IP Check: ${indicator}\n\n` +
                `Reputation Score: ${reputationScore}/100 (${reputationScore === 0 ? "clean" : reputationScore < 50 ? "suspicious" : "malicious"})\n` +
                `Feeds Checked: ${feedMatches.length}\n` +
                `Feed Matches: ${matchedFeeds.length > 0 ? matchedFeeds.join(", ") : "none"}\n` +
                `Fail2ban Banned: ${inFail2ban ? "YES" : "no"}\n` +
                `Iptables Blocked: ${inIptables ? "YES" : "no"}\n` +
                `Already Blocked: ${alreadyBlocked ? "YES" : "no"}\n` +
                (whoisInfo ? `\nWhois Info:\n${whoisInfo}\n` : ""),
              )],
            };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`check_ip failed: ${msg}`)], isError: true };
          }
        }

        // ── check_hash ────────────────────────────────────────────────────
        case "check_hash": {
          const { indicator } = params;
          if (!indicator) {
            return {
              content: [createErrorContent("check_hash requires an 'indicator' parameter (file hash)")],
              isError: true,
            };
          }

          const hashType = detectHashType(indicator);
          if (hashType === "unknown") {
            return {
              content: [createErrorContent(
                `Unable to detect hash type for: ${indicator}. Expected MD5 (32 chars), SHA1 (40 chars), or SHA256 (64 chars) hex string.`,
              )],
              isError: true,
            };
          }

          try {
            const normalizedHash = indicator.trim().toLowerCase();

            // Check against local hash feeds
            const feedMatches = searchFeedDirectory(HASH_FEED_DIR, normalizedHash);
            const matchedFeeds = feedMatches.filter((f) => f.matched).map((f) => f.feed);

            // Check ClamAV signature databases if available
            let clamavMatch = "";
            if (existsSync(CLAMAV_DB_PATH)) {
              const grepResult = await runCommand(
                "grep", ["-rl", normalizedHash, CLAMAV_DB_PATH], 15_000,
              );
              if (grepResult.exitCode === 0 && grepResult.stdout.trim().length > 0) {
                clamavMatch = grepResult.stdout.trim().split("\n")[0];
              }
            }

            // Try to find associated malware name from feed files
            let malwareName = "";
            if (matchedFeeds.length > 0) {
              // Some feeds store "hash:malware_name" or "hash malware_name"
              for (const feedFile of matchedFeeds) {
                try {
                  const content = readFileSync(`${HASH_FEED_DIR}/${feedFile}`, "utf-8");
                  for (const line of content.split("\n")) {
                    const lower = line.trim().toLowerCase();
                    if (lower.startsWith(normalizedHash)) {
                      // Check for separator after hash
                      const rest = line.trim().substring(normalizedHash.length).trim();
                      if (rest.startsWith(":") || rest.startsWith(",") || rest.startsWith("\t") || rest.startsWith(" ")) {
                        malwareName = rest.replace(/^[:\s,\t]+/, "").trim();
                        break;
                      }
                    }
                  }
                  if (malwareName) break;
                } catch {
                  // Skip unreadable files
                }
              }
            }

            const output = {
              action: "check_hash",
              indicator: normalizedHash,
              hashType,
              feedsChecked: feedMatches.length,
              feedMatches: matchedFeeds,
              matchFound: matchedFeeds.length > 0 || clamavMatch.length > 0,
              clamavMatch: clamavMatch || null,
              malwareName: malwareName || null,
            };

            if (params.output_format === "json") {
              return { content: [formatToolOutput(output)] };
            }

            return {
              content: [createTextContent(
                `Threat Intel — Hash Check: ${normalizedHash}\n\n` +
                `Hash Type: ${hashType}\n` +
                `Feeds Checked: ${feedMatches.length}\n` +
                `Feed Matches: ${matchedFeeds.length > 0 ? matchedFeeds.join(", ") : "none"}\n` +
                `ClamAV Match: ${clamavMatch || "none"}\n` +
                `Malware Name: ${malwareName || "unknown"}\n` +
                `Match Found: ${output.matchFound ? "YES" : "no"}\n`,
              )],
            };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`check_hash failed: ${msg}`)], isError: true };
          }
        }

        // ── check_domain ──────────────────────────────────────────────────
        case "check_domain": {
          const { indicator } = params;
          if (!indicator) {
            return {
              content: [createErrorContent("check_domain requires an 'indicator' parameter (domain name)")],
              isError: true,
            };
          }

          try {
            const normalizedDomain = indicator.trim().toLowerCase().replace(/\.$/, "");

            // Check against local domain blocklists
            const feedMatches = searchFeedDirectory(DOMAIN_FEED_DIR, normalizedDomain);
            const matchedFeeds = feedMatches.filter((f) => f.matched).map((f) => f.feed);

            // Check /etc/hosts for existing blocks
            let inHostsFile = false;
            const hostsResult = await runCommand("cat", ["/etc/hosts"], 5_000);
            if (hostsResult.exitCode === 0) {
              const lines = hostsResult.stdout.split("\n");
              for (const line of lines) {
                const trimmed = line.trim().toLowerCase();
                if (trimmed.startsWith("#")) continue;
                // Match "0.0.0.0 domain" or "127.0.0.1 domain"
                if (trimmed.includes(normalizedDomain)) {
                  const parts = trimmed.split(/\s+/);
                  if (parts.length >= 2 && SINKHOLE_IPS.has(parts[0]) && parts[1] === normalizedDomain) {
                    inHostsFile = true;
                    break;
                  }
                }
              }
            }

            // Perform dig lookup to check DNS resolution
            let resolvedIPs: string[] = [];
            let isSinkholed = false;
            const digResult = await runCommand("dig", ["+short", normalizedDomain], 10_000);
            if (digResult.exitCode === 0 && digResult.stdout.trim().length > 0) {
              resolvedIPs = digResult.stdout.trim().split("\n")
                .map((l) => l.trim())
                .filter((l) => l.length > 0);

              // Check if resolves to sinkhole
              for (const ip of resolvedIPs) {
                if (SINKHOLE_IPS.has(ip)) {
                  isSinkholed = true;
                  break;
                }
              }
            }

            const isBlocked = inHostsFile || isSinkholed || matchedFeeds.length > 0;

            const output = {
              action: "check_domain",
              indicator: normalizedDomain,
              feedsChecked: feedMatches.length,
              feedMatches: matchedFeeds,
              matchFound: matchedFeeds.length > 0,
              inHostsFile,
              isSinkholed,
              isBlocked,
              resolvedIPs,
            };

            if (params.output_format === "json") {
              return { content: [formatToolOutput(output)] };
            }

            return {
              content: [createTextContent(
                `Threat Intel — Domain Check: ${normalizedDomain}\n\n` +
                `Feeds Checked: ${feedMatches.length}\n` +
                `Feed Matches: ${matchedFeeds.length > 0 ? matchedFeeds.join(", ") : "none"}\n` +
                `In /etc/hosts: ${inHostsFile ? "YES (blocked)" : "no"}\n` +
                `Sinkholed: ${isSinkholed ? "YES" : "no"}\n` +
                `Blocked: ${isBlocked ? "YES" : "no"}\n` +
                `Resolved IPs: ${resolvedIPs.length > 0 ? resolvedIPs.join(", ") : "no resolution"}\n`,
              )],
            };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`check_domain failed: ${msg}`)], isError: true };
          }
        }

        // ── update_feeds ──────────────────────────────────────────────────
        case "update_feeds": {
          const { feed_name, feed_url } = params;

          try {
            // If no URL provided, list available feeds
            if (!feed_url) {
              const ipFeeds = listFeeds(FEED_BASE_DIR);
              const hashFeeds = listFeeds(HASH_FEED_DIR);
              const domainFeeds = listFeeds(DOMAIN_FEED_DIR);

              const output = {
                action: "update_feeds",
                mode: "list",
                feedDirectories: {
                  ip: FEED_BASE_DIR,
                  hashes: HASH_FEED_DIR,
                  domains: DOMAIN_FEED_DIR,
                },
                ipFeeds,
                hashFeeds,
                domainFeeds,
                totalFeeds: ipFeeds.length + hashFeeds.length + domainFeeds.length,
              };

              if (params.output_format === "json") {
                return { content: [formatToolOutput(output)] };
              }

              let text = "Threat Intel — Available Feeds\n\n";
              text += `Feed Directories:\n  IP: ${FEED_BASE_DIR}\n  Hashes: ${HASH_FEED_DIR}\n  Domains: ${DOMAIN_FEED_DIR}\n\n`;

              const formatFeedList = (label: string, feeds: typeof ipFeeds) => {
                if (feeds.length === 0) return `${label}: (none)\n`;
                return `${label}:\n` + feeds.map((f) =>
                  `  ${f.name} — ${f.indicatorCount} indicators, updated ${f.lastUpdated}, ${f.size} bytes`,
                ).join("\n") + "\n";
              };

              text += formatFeedList("IP Feeds", ipFeeds);
              text += formatFeedList("Hash Feeds", hashFeeds);
              text += formatFeedList("Domain Feeds", domainFeeds);
              text += `\nTotal: ${output.totalFeeds} feeds`;

              return { content: [createTextContent(text)] };
            }

            // Download a feed
            if (!feed_name) {
              return {
                content: [createErrorContent("update_feeds requires 'feed_name' when 'feed_url' is provided")],
                isError: true,
              };
            }


            // SECURITY: Enforce HTTPS for feed downloads (audit finding #11)
            try {
              const parsedUrl = new URL(feed_url);
              if (parsedUrl.protocol !== "https:") {
                return {
                  content: [createErrorContent(
                    `Feed URL must use HTTPS. Got: '${parsedUrl.protocol}'. ` +
                    `Insecure HTTP connections are rejected to prevent MITM attacks on threat feeds.`
                  )],
                  isError: true,
                };
              }
            } catch {
              return {
                content: [createErrorContent(`Invalid feed URL: '${feed_url}'`)],
                isError: true,
              };
            }
            // Ensure feed directory exists
            await runCommand("mkdir", ["-p", FEED_BASE_DIR]);

            const outputPath = `${FEED_BASE_DIR}/${feed_name}`;

            // Try curl first, fall back to wget
            let downloadResult = await runCommand(
              "curl", ["-sS", "--proto", "=https", "-o", outputPath, "-L", "--max-time", "60", feed_url], 65_000,
            );

            if (downloadResult.exitCode !== 0) {
              // Fall back to wget
              downloadResult = await runCommand(
                "wget", ["--https-only", "-q", "-O", outputPath, feed_url], 65_000,
              );
            }

            if (downloadResult.exitCode !== 0) {
              return {
                content: [createErrorContent(
                  `Failed to download feed from ${feed_url}: ${downloadResult.stderr}`,
                )],
                isError: true,
              };
            }

            // Read downloaded file stats
            let indicatorCount = 0;
            let fileSize = 0;
            try {
              const content = readFileSync(outputPath, "utf-8");
              indicatorCount = content.split("\n")
                .filter((l) => l.trim().length > 0 && !l.trim().startsWith("#"))
                .length;
              const stat = statSync(outputPath);
              fileSize = stat.size;
            } catch {
              // Stats unavailable
            }

            const output = {
              action: "update_feeds",
              mode: "download",
              feedName: feed_name,
              feedUrl: feed_url,
              outputPath,
              indicatorCount,
              fileSize,
              downloadSuccess: true,
            };

            if (params.output_format === "json") {
              return { content: [formatToolOutput(output)] };
            }

            return {
              content: [createTextContent(
                `Threat Intel — Feed Updated\n\n` +
                `Feed: ${feed_name}\n` +
                `Source: ${feed_url}\n` +
                `Saved to: ${outputPath}\n` +
                `Indicators: ${indicatorCount}\n` +
                `Size: ${fileSize} bytes\n`,
              )],
            };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`update_feeds failed: ${msg}`)], isError: true };
          }
        }

        // ── blocklist_apply ───────────────────────────────────────────────
        case "blocklist_apply": {
          const { blocklist_path, apply_to } = params;

          if (!blocklist_path) {
            return {
              content: [createErrorContent("blocklist_apply requires a 'blocklist_path' parameter")],
              isError: true,
            };
          }

          const target = apply_to || "iptables";

          try {
            // Read blocklist file
            const fileResult = await runCommand("cat", [blocklist_path]);
            if (fileResult.exitCode !== 0) {
              return {
                content: [createErrorContent(`Failed to read blocklist file: ${fileResult.stderr}`)],
                isError: true,
              };
            }

            let entries = fileResult.stdout
              .split("\n")
              .map((l) => l.trim())
              .filter((l) => l.length > 0 && !l.startsWith("#"));

            // Deduplicate
            entries = [...new Set(entries)];

            if (entries.length === 0) {
              return {
                content: [createErrorContent("Blocklist file is empty or contains only comments")],
                isError: true,
              };
            }

            // Limit batch size
            const totalEntries = entries.length;
            const truncated = totalEntries > MAX_BATCH_SIZE;
            if (truncated) {
              entries = entries.slice(0, MAX_BATCH_SIZE);
            }

            let applied = 0;
            let skipped = 0;
            const errors: string[] = [];

            switch (target) {
              case "iptables": {
                // Get existing iptables rules to check for duplicates
                const existingResult = await runCommand("iptables", ["-L", "INPUT", "-n"], 10_000);
                const existingRules = existingResult.exitCode === 0 ? existingResult.stdout : "";

                for (const ip of entries) {
                  if (!isValidIPv4(ip)) {
                    errors.push(`Invalid IP skipped: ${ip}`);
                    skipped++;
                    continue;
                  }

                  // Check for existing rule
                  if (existingRules.includes(ip)) {
                    skipped++;
                    continue;
                  }

                  const addResult = await runCommand(
                    "iptables", ["-A", "INPUT", "-s", ip, "-j", "DROP"], 5_000,
                  );
                  if (addResult.exitCode === 0) {
                    applied++;
                  } else {
                    errors.push(`Failed to block ${ip}: ${addResult.stderr}`);
                  }
                }
                break;
              }

              case "fail2ban": {
                // Use the default jail or 'recidive'
                const jail = "recidive";

                for (const ip of entries) {
                  if (!isValidIPv4(ip)) {
                    errors.push(`Invalid IP skipped: ${ip}`);
                    skipped++;
                    continue;
                  }

                  const banResult = await runCommand(
                    "fail2ban-client", ["set", jail, "banip", ip], 5_000,
                  );
                  if (banResult.exitCode === 0) {
                    applied++;
                  } else if (banResult.stderr.includes("already") || banResult.stdout.includes("already")) {
                    skipped++;
                  } else {
                    errors.push(`Failed to ban ${ip}: ${banResult.stderr}`);
                  }
                }
                break;
              }

              case "hosts": {
                // Read current /etc/hosts
                const hostsResult = await runCommand("cat", ["/etc/hosts"]);
                const currentHosts = hostsResult.exitCode === 0 ? hostsResult.stdout : "";

                // Parse existing blocked domains
                const existingBlocked = new Set<string>();
                for (const line of currentHosts.split("\n")) {
                  const trimmed = line.trim().toLowerCase();
                  if (trimmed.startsWith("#")) continue;
                  const match = /^0\.0\.0\.0\s+(\S+)/.exec(trimmed);
                  if (match) existingBlocked.add(match[1]);
                }

                const newEntries: string[] = [];
                for (const domain of entries) {
                  const normalized = domain.toLowerCase().replace(/\.$/, "");
                  if (existingBlocked.has(normalized)) {
                    skipped++;
                  } else {
                    newEntries.push(`0.0.0.0 ${normalized}`);
                    applied++;
                  }
                }

                if (newEntries.length > 0) {
                  // Write new entries via tee
                  const appendContent = "\n# ── Defense Threat Intel Blocklist ──\n" +
                    newEntries.join("\n") + "\n";

                  const teeResult = await runCommand(
                    "sudo", ["tee", "-a", "/etc/hosts"],
                    10_000,
                  );
                  if (teeResult.exitCode !== 0) {
                    errors.push(`Failed to write to /etc/hosts: ${teeResult.stderr}`);
                  }
                }
                break;
              }
            }

            const output = {
              action: "blocklist_apply",
              target,
              blocklistPath: blocklist_path,
              totalEntries,
              applied,
              skipped,
              errors: errors.slice(0, 20),
              truncated,
              maxBatchSize: MAX_BATCH_SIZE,
            };

            if (params.output_format === "json") {
              return { content: [formatToolOutput(output)] };
            }

            return {
              content: [createTextContent(
                `Threat Intel — Blocklist Applied\n\n` +
                `Target: ${target}\n` +
                `Blocklist: ${blocklist_path}\n` +
                `Total Entries: ${totalEntries}${truncated ? ` (truncated to ${MAX_BATCH_SIZE})` : ""}\n` +
                `Applied: ${applied}\n` +
                `Skipped (duplicates/invalid): ${skipped}\n` +
                `Errors: ${errors.length}\n` +
                (errors.length > 0 ? `\nErrors:\n${errors.slice(0, 10).map((e) => `  • ${e}`).join("\n")}\n` : ""),
              )],
            };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return { content: [createErrorContent(`blocklist_apply failed: ${msg}`)], isError: true };
          }
        }

        default:
          return { content: [createErrorContent(`Unknown action: ${action}`)], isError: true };
      }
    },
  );
}
