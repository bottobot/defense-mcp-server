/**
 * Output parsing utilities for defensive security tool output.
 * Converts raw command output into structured data for MCP responses.
 */

/** MCP text content type */
export interface McpTextContent {
  type: "text";
  text: string;
}

// ─── Generic Parsers ─────────────────────────────────────────────

/**
 * Parses key:value pair output into a Record.
 * Lines without the separator are skipped.
 */
export function parseKeyValue(
  output: string,
  separator: string = ":"
): Record<string, string> {
  const result: Record<string, string> = {};

  for (const line of output.split("\n")) {
    const idx = line.indexOf(separator);
    if (idx === -1) continue;

    const key = line.substring(0, idx).trim();
    const value = line.substring(idx + separator.length).trim();

    if (key.length > 0) {
      result[key] = value;
    }
  }

  return result;
}

/**
 * Parses whitespace-delimited table output into an array of Records.
 * First non-empty line is treated as the header row.
 */
export function parseTable(output: string): Record<string, string>[] {
  const lines = output
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0);

  if (lines.length < 2) return [];

  const headers = lines[0].split(/\s+/).map((h) => h.toLowerCase());
  const rows: Record<string, string>[] = [];

  for (let i = 1; i < lines.length; i++) {
    const values = lines[i].split(/\s+/);
    const row: Record<string, string> = {};

    for (let j = 0; j < headers.length; j++) {
      // Last column gets remainder of line to handle values with spaces
      if (j === headers.length - 1) {
        row[headers[j]] = values.slice(j).join(" ");
      } else {
        row[headers[j]] = values[j] ?? "";
      }
    }

    rows.push(row);
  }

  return rows;
}

/**
 * Safely parses JSON text. Returns null on parse failure.
 */
export function parseJsonSafe(text: string): unknown | null {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

/**
 * Formats any data into MCP text content.
 * Objects are JSON-stringified with indentation.
 */
export function formatToolOutput(data: unknown): McpTextContent {
  if (typeof data === "string") {
    return { type: "text", text: data };
  }
  return { type: "text", text: JSON.stringify(data, null, 2) };
}

/**
 * Creates a simple MCP text content object.
 */
export function createTextContent(text: string): McpTextContent {
  return { type: "text", text };
}

/**
 * Creates an MCP text content object with an error prefix.
 */
export function createErrorContent(msg: string): McpTextContent {
  return { type: "text", text: `Error: ${msg}` };
}

// ─── Firewall Parsers ────────────────────────────────────────────

/** Structured iptables rule */
export interface IptablesRule {
  chain: string;
  policy?: string;
  packets: string;
  bytes: string;
  target: string;
  protocol: string;
  opt: string;
  in: string;
  out: string;
  source: string;
  destination: string;
  extra: string;
}

/**
 * Parses `iptables -L -n -v` output into structured rules.
 */
export function parseIptablesOutput(output: string): IptablesRule[] {
  const rules: IptablesRule[] = [];
  let currentChain = "";
  let currentPolicy = "";

  for (const line of output.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    // Chain header: "Chain INPUT (policy ACCEPT 0 packets, 0 bytes)"
    const chainMatch = trimmed.match(
      /^Chain\s+(\S+)\s+\(policy\s+(\S+).*\)/
    );
    if (chainMatch) {
      currentChain = chainMatch[1];
      currentPolicy = chainMatch[2];
      continue;
    }

    // Chain header without policy: "Chain DOCKER (1 references)"
    const chainRefMatch = trimmed.match(/^Chain\s+(\S+)\s+\(/);
    if (chainRefMatch) {
      currentChain = chainRefMatch[1];
      currentPolicy = "";
      continue;
    }

    // Skip table header
    if (trimmed.startsWith("pkts") || trimmed.startsWith("num")) continue;

    // Rule line: "pkts bytes target prot opt in out source destination extra..."
    const parts = trimmed.split(/\s+/);
    if (parts.length >= 9) {
      rules.push({
        chain: currentChain,
        policy: currentPolicy || undefined,
        packets: parts[0],
        bytes: parts[1],
        target: parts[2],
        protocol: parts[3],
        opt: parts[4],
        in: parts[5],
        out: parts[6],
        source: parts[7],
        destination: parts[8],
        extra: parts.slice(9).join(" "),
      });
    }
  }

  return rules;
}

/**
 * Parses `nft list ruleset` output into structured sections.
 */
export function parseNftOutput(
  output: string
): Record<string, string[]> {
  const result: Record<string, string[]> = {};
  let currentTable = "";

  for (const line of output.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    const tableMatch = trimmed.match(/^table\s+(\S+\s+\S+)\s*\{/);
    if (tableMatch) {
      currentTable = tableMatch[1];
      result[currentTable] = [];
      continue;
    }

    if (currentTable && trimmed !== "}") {
      result[currentTable]?.push(trimmed);
    }

    if (trimmed === "}" && currentTable) {
      currentTable = "";
    }
  }

  return result;
}

// ─── System Parsers ──────────────────────────────────────────────

/** Structured sysctl entry */
export interface SysctlEntry {
  key: string;
  value: string;
}

/**
 * Parses `sysctl -a` output into structured entries.
 */
export function parseSysctlOutput(output: string): SysctlEntry[] {
  const entries: SysctlEntry[] = [];

  for (const line of output.split("\n")) {
    const idx = line.indexOf("=");
    if (idx === -1) continue;

    const key = line.substring(0, idx).trim();
    const value = line.substring(idx + 1).trim();

    if (key.length > 0) {
      entries.push({ key, value });
    }
  }

  return entries;
}

// ─── Audit Parsers ───────────────────────────────────────────────

/** Structured audit log entry */
export interface AuditEntry {
  type: string;
  timestamp: string;
  fields: Record<string, string>;
}

/**
 * Parses `ausearch` output into structured audit entries.
 */
export function parseAuditdOutput(output: string): AuditEntry[] {
  const entries: AuditEntry[] = [];
  let current: AuditEntry | null = null;

  for (const line of output.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("----") || trimmed.startsWith("time->"))
      continue;

    // type=SYSCALL msg=audit(1234567890.123:456): ...
    const typeMatch = trimmed.match(
      /^type=(\S+)\s+msg=audit\(([^)]+)\):\s*(.*)/
    );
    if (typeMatch) {
      current = {
        type: typeMatch[1],
        timestamp: typeMatch[2],
        fields: {},
      };

      // Parse key=value pairs from rest of line
      const rest = typeMatch[3];
      const kvRe = /(\w+)=("[^"]*"|\S+)/g;
      let match;
      while ((match = kvRe.exec(rest)) !== null) {
        current.fields[match[1]] = match[2].replace(/^"|"$/g, "");
      }

      entries.push(current);
    }
  }

  return entries;
}

// ─── Assessment Parsers ──────────────────────────────────────────

/** Lynis finding */
export interface LynisFinding {
  severity: string;
  testId: string;
  description: string;
}

/**
 * Parses Lynis audit output for findings/warnings/suggestions.
 */
export function parseLynisOutput(output: string): LynisFinding[] {
  const findings: LynisFinding[] = [];

  for (const line of output.split("\n")) {
    const trimmed = line.trim();

    // Warning: [TEST-ID] Description
    const warningMatch = trimmed.match(/^\s*Warning:\s*\[(\S+)\]\s*(.*)/);
    if (warningMatch) {
      findings.push({
        severity: "warning",
        testId: warningMatch[1],
        description: warningMatch[2],
      });
      continue;
    }

    // Suggestion: [TEST-ID] Description
    const suggestionMatch = trimmed.match(
      /^\s*Suggestion:\s*\[(\S+)\]\s*(.*)/
    );
    if (suggestionMatch) {
      findings.push({
        severity: "suggestion",
        testId: suggestionMatch[1],
        description: suggestionMatch[2],
      });
      continue;
    }

    // * Finding [TEST-ID]
    const findingMatch = trimmed.match(/^\s*\*\s*Finding\s*\[(\S+)\]\s*(.*)/);
    if (findingMatch) {
      findings.push({
        severity: "finding",
        testId: findingMatch[1],
        description: findingMatch[2],
      });
    }
  }

  return findings;
}

/** OpenSCAP result entry */
export interface OscapResult {
  ruleId: string;
  result: string;
  severity: string;
  title: string;
}

/**
 * Parses OpenSCAP text/XML results output.
 * Handles the common text report format.
 */
export function parseOscapOutput(output: string): OscapResult[] {
  const results: OscapResult[] = [];

  // Match rule results from oscap text output
  // Title
  //   Rule ID: xccdf_...
  //   Result: pass/fail/notapplicable
  //   Severity: low/medium/high
  let currentTitle = "";
  let currentRule: Partial<OscapResult> = {};

  for (const line of output.split("\n")) {
    const trimmed = line.trim();

    const titleMatch = trimmed.match(/^Title\s*:\s*(.*)/);
    if (titleMatch) {
      currentTitle = titleMatch[1];
      currentRule = { title: currentTitle };
      continue;
    }

    const ruleMatch = trimmed.match(/^Rule\s*:\s*(.*)/);
    if (ruleMatch) {
      currentRule.ruleId = ruleMatch[1];
      continue;
    }

    const resultMatch = trimmed.match(/^Result\s*:\s*(.*)/);
    if (resultMatch) {
      currentRule.result = resultMatch[1];
      continue;
    }

    const sevMatch = trimmed.match(/^Severity\s*:\s*(.*)/);
    if (sevMatch) {
      currentRule.severity = sevMatch[1];

      // We have all fields, push the result
      if (currentRule.ruleId && currentRule.result) {
        results.push({
          ruleId: currentRule.ruleId,
          result: currentRule.result,
          severity: currentRule.severity ?? "unknown",
          title: currentRule.title ?? "",
        });
      }
      currentRule = {};
    }
  }

  return results;
}

// ─── Malware/AV Parsers ─────────────────────────────────────────

/** ClamAV scan result */
export interface ClamavResult {
  file: string;
  status: "OK" | "FOUND" | "ERROR";
  virus?: string;
}

/**
 * Parses `clamscan` output into structured results.
 */
export function parseClamavOutput(output: string): ClamavResult[] {
  const results: ClamavResult[] = [];

  for (const line of output.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    // /path/to/file: OK
    if (trimmed.endsWith(": OK")) {
      results.push({
        file: trimmed.slice(0, -4),
        status: "OK",
      });
      continue;
    }

    // /path/to/file: VirusName FOUND
    const foundMatch = trimmed.match(/^(.+?):\s+(.+?)\s+FOUND$/);
    if (foundMatch) {
      results.push({
        file: foundMatch[1],
        status: "FOUND",
        virus: foundMatch[2],
      });
      continue;
    }

    // /path/to/file: Error message ERROR
    const errorMatch = trimmed.match(/^(.+?):\s+.*ERROR$/);
    if (errorMatch) {
      results.push({
        file: errorMatch[1],
        status: "ERROR",
      });
    }
  }

  return results;
}

// ─── Network Parsers ─────────────────────────────────────────────

/** Structured socket entry from ss */
export interface SsEntry {
  state: string;
  recv: string;
  send: string;
  local: string;
  peer: string;
  process: string;
}

/**
 * Parses `ss -tulnp` output into structured entries.
 */
export function parseSsOutput(output: string): SsEntry[] {
  const entries: SsEntry[] = [];
  const lines = output.split("\n");

  // Skip header
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;

    const parts = line.split(/\s+/);
    if (parts.length >= 5) {
      entries.push({
        state: parts[0],
        recv: parts[1],
        send: parts[2],
        local: parts[3],
        peer: parts[4],
        process: parts.slice(5).join(" "),
      });
    }
  }

  return entries;
}

// ─── Service Parsers ─────────────────────────────────────────────

/** Structured fail2ban jail status */
export interface Fail2banJail {
  name: string;
  status: string;
  currentlyFailed: number;
  totalFailed: number;
  currentlyBanned: number;
  totalBanned: number;
  bannedIPs: string[];
}

/**
 * Parses `fail2ban-client status` output.
 */
export function parseFail2banOutput(output: string): Fail2banJail[] {
  const jails: Fail2banJail[] = [];
  let current: Partial<Fail2banJail> | null = null;

  for (const line of output.split("\n")) {
    const trimmed = line.trim();

    // Jail name from status output
    const jailMatch = trimmed.match(/^Status for the jail:\s*(\S+)/);
    if (jailMatch) {
      current = { name: jailMatch[1], bannedIPs: [] };
      continue;
    }

    if (!current) continue;

    const kvMatch = trimmed.match(/^\|-\s*(\S.*?):\s*(.*)/);
    if (kvMatch) {
      const key = kvMatch[1].trim().toLowerCase();
      const value = kvMatch[2].trim();

      if (key.includes("currently failed")) {
        current.currentlyFailed = parseInt(value, 10) || 0;
      } else if (key.includes("total failed")) {
        current.totalFailed = parseInt(value, 10) || 0;
      } else if (key.includes("currently banned")) {
        current.currentlyBanned = parseInt(value, 10) || 0;
      } else if (key.includes("total banned")) {
        current.totalBanned = parseInt(value, 10) || 0;
      } else if (key.includes("banned ip")) {
        current.bannedIPs = value
          .split(/\s+/)
          .filter((ip) => ip.length > 0);
      }
      continue;
    }

    const leafMatch = trimmed.match(/^`-\s*(\S.*?):\s*(.*)/);
    if (leafMatch) {
      const key = leafMatch[1].trim().toLowerCase();
      const value = leafMatch[2].trim();

      if (key.includes("currently failed")) {
        current.currentlyFailed = parseInt(value, 10) || 0;
      } else if (key.includes("total failed")) {
        current.totalFailed = parseInt(value, 10) || 0;
      } else if (key.includes("currently banned")) {
        current.currentlyBanned = parseInt(value, 10) || 0;
      } else if (key.includes("total banned")) {
        current.totalBanned = parseInt(value, 10) || 0;
      } else if (key.includes("banned ip")) {
        current.bannedIPs = value
          .split(/\s+/)
          .filter((ip) => ip.length > 0);

        // Last field, push the jail
        jails.push({
          name: current.name ?? "unknown",
          status: current.status ?? "active",
          currentlyFailed: current.currentlyFailed ?? 0,
          totalFailed: current.totalFailed ?? 0,
          currentlyBanned: current.currentlyBanned ?? 0,
          totalBanned: current.totalBanned ?? 0,
          bannedIPs: current.bannedIPs ?? [],
        });
        current = null;
      }
    }
  }

  // Push any remaining jail
  if (current?.name) {
    jails.push({
      name: current.name,
      status: current.status ?? "active",
      currentlyFailed: current.currentlyFailed ?? 0,
      totalFailed: current.totalFailed ?? 0,
      currentlyBanned: current.currentlyBanned ?? 0,
      totalBanned: current.totalBanned ?? 0,
      bannedIPs: current.bannedIPs ?? [],
    });
  }

  return jails;
}

/** Structured systemctl unit entry */
export interface SystemctlUnit {
  unit: string;
  load: string;
  active: string;
  sub: string;
  description: string;
}

/**
 * Parses `systemctl list-units` output into structured entries.
 */
export function parseSystemctlOutput(output: string): SystemctlUnit[] {
  const units: SystemctlUnit[] = [];
  const lines = output.split("\n");

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    // Skip header lines and legend
    if (
      trimmed.startsWith("UNIT") ||
      trimmed.startsWith("LOAD") ||
      trimmed.startsWith("To show") ||
      trimmed.includes("loaded units listed") ||
      trimmed.startsWith("LEGEND")
    ) {
      continue;
    }

    // "● unit.service  loaded  active  running  Description text"
    // or "unit.service  loaded  active  running  Description text"
    const cleanLine = trimmed.replace(/^[●○]\s*/, "");
    const parts = cleanLine.split(/\s+/);

    if (parts.length >= 4) {
      units.push({
        unit: parts[0],
        load: parts[1],
        active: parts[2],
        sub: parts[3],
        description: parts.slice(4).join(" "),
      });
    }
  }

  return units;
}
