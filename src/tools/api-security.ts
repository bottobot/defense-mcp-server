/**
 * API security tools for Defense MCP Server.
 *
 * Registers 1 tool: api_security (actions: scan_local_apis, audit_auth,
 * check_rate_limiting, tls_verify, cors_check)
 *
 * Provides local API discovery, authentication auditing, rate limiting
 * verification, TLS configuration checking, and CORS policy analysis.
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

// ── Constants ──────────────────────────────────────────────────────────────────

const DEFAULT_PORT_RANGE = "80,443,3000,4000,5000,8000,8080,8443,9000";

const COMMON_API_PATHS = [
  "/api",
  "/api/v1",
  "/health",
  "/status",
  "/swagger.json",
  "/openapi.json",
  "/.well-known/openid-configuration",
];

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

/**
 * Validate and normalize a target URL.
 * Returns the normalized URL or null if invalid.
 */
function validateTarget(target: string): string | null {
  try {
    // Add scheme if missing
    let url = target;
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      url = `http://${url}`;
    }
    const parsed = new URL(url);
    if (!parsed.hostname) return null;
    return parsed.toString().replace(/\/$/, "");
  } catch {
    return null;
  }
}

/**
 * Parse host and port from a target URL or host:port string.
 */
function parseHostPort(target: string): { host: string; port: string } {
  try {
    let url = target;
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      url = `http://${url}`;
    }
    const parsed = new URL(url);
    const host = parsed.hostname;
    let port = parsed.port;
    if (!port) {
      port = parsed.protocol === "https:" ? "443" : "80";
    }
    return { host, port };
  } catch {
    // Fallback: try host:port parsing
    const parts = target.split(":");
    return { host: parts[0] || "localhost", port: parts[1] || "80" };
  }
}

// ── Action implementations ─────────────────────────────────────────────────────

interface DiscoveredApi {
  port: number;
  httpStatus: number;
  protocol: string;
  frameworkGuess: string;
  apiPaths: string[];
  docsUrl: string | null;
}

interface ScanLocalApisResult {
  listeningPorts: number[];
  discoveredApis: DiscoveredApi[];
  totalDiscovered: number;
  recommendations: string[];
}

async function scanLocalApis(portRange: string): Promise<ScanLocalApisResult> {
  const result: ScanLocalApisResult = {
    listeningPorts: [],
    discoveredApis: [],
    totalDiscovered: 0,
    recommendations: [],
  };

  // Get listening TCP ports
  const ssResult = await runCommand("ss", ["-tlnp"], 10_000);
  const listeningPorts: Set<number> = new Set();

  if (ssResult.exitCode === 0) {
    const lines = ssResult.stdout.split("\n");
    for (const line of lines) {
      const portMatch = line.match(/:(\d+)\s/);
      if (portMatch) {
        listeningPorts.add(parseInt(portMatch[1], 10));
      }
    }
  }

  result.listeningPorts = Array.from(listeningPorts).sort((a, b) => a - b);

  // Parse target ports from range
  const targetPorts = portRange
    .split(",")
    .map((p) => parseInt(p.trim(), 10))
    .filter((p) => !isNaN(p));

  // Check each target port
  for (const port of targetPorts) {
    // Check if HTTP service responds
    const httpCheck = await runCommand(
      "curl",
      ["-s", "-o", "/dev/null", "-w", "%{http_code}", "-m", "5", `http://localhost:${port}/`],
      10_000,
    );

    if (httpCheck.exitCode !== 0 || httpCheck.stdout.trim() === "000") {
      continue; // No HTTP response
    }

    const httpStatus = parseInt(httpCheck.stdout.trim(), 10);
    if (isNaN(httpStatus)) continue;

    const api: DiscoveredApi = {
      port,
      httpStatus,
      protocol: "http",
      frameworkGuess: "unknown",
      apiPaths: [],
      docsUrl: null,
    };

    // Try to identify framework via response headers
    const headerCheck = await runCommand(
      "curl",
      ["-sI", "-m", "5", `http://localhost:${port}/`],
      10_000,
    );

    if (headerCheck.exitCode === 0) {
      const headers = headerCheck.stdout.toLowerCase();
      if (headers.includes("x-powered-by: express")) {
        api.frameworkGuess = "Express.js";
      } else if (headers.includes("x-powered-by: php")) {
        api.frameworkGuess = "PHP";
      } else if (headers.includes("server: nginx")) {
        api.frameworkGuess = "Nginx";
      } else if (headers.includes("server: apache")) {
        api.frameworkGuess = "Apache";
      } else if (
        headers.includes("server: uvicorn") ||
        headers.includes("server: gunicorn")
      ) {
        api.frameworkGuess = "Python (ASGI/WSGI)";
      } else if (headers.includes("x-powered-by: next.js")) {
        api.frameworkGuess = "Next.js";
      } else if (headers.includes("server: kestrel")) {
        api.frameworkGuess = ".NET Kestrel";
      }
    }

    // Check common API paths
    for (const path of COMMON_API_PATHS) {
      const pathCheck = await runCommand(
        "curl",
        [
          "-s",
          "-o",
          "/dev/null",
          "-w",
          "%{http_code}",
          "-m",
          "5",
          `http://localhost:${port}${path}`,
        ],
        10_000,
      );

      if (pathCheck.exitCode === 0) {
        const status = parseInt(pathCheck.stdout.trim(), 10);
        if (status >= 200 && status < 404) {
          api.apiPaths.push(path);
          if (path === "/swagger.json" || path === "/openapi.json") {
            api.docsUrl = `http://localhost:${port}${path}`;
          }
        }
      }
    }

    result.discoveredApis.push(api);
  }

  result.totalDiscovered = result.discoveredApis.length;

  if (result.totalDiscovered === 0) {
    result.recommendations.push(
      "No API services found on scanned ports — verify services are running",
    );
  } else {
    for (const api of result.discoveredApis) {
      if (!api.docsUrl) {
        result.recommendations.push(
          `Port ${api.port}: No API documentation endpoint found — consider adding OpenAPI/Swagger`,
        );
      }
    }
  }

  return result;
}

interface AuthAuditResult {
  target: string;
  accessible: boolean;
  statusWithoutAuth: number;
  statusWithAuth: number;
  authRequired: boolean;
  authType: string;
  verboseErrors: boolean;
  errorDetails: string[];
  recommendations: string[];
}

async function auditAuth(target: string): Promise<AuthAuditResult> {
  const result: AuthAuditResult = {
    target,
    accessible: false,
    statusWithoutAuth: 0,
    statusWithAuth: 0,
    authRequired: false,
    authType: "none",
    verboseErrors: false,
    errorDetails: [],
    recommendations: [],
  };

  // Check without authentication
  const noAuthCheck = await runCommand(
    "curl",
    ["-s", "-o", "/dev/null", "-w", "%{http_code}", "-m", "5", target],
    10_000,
  );

  if (noAuthCheck.exitCode !== 0 || noAuthCheck.stdout.trim() === "000") {
    result.recommendations.push(
      "Target is not reachable — check URL and connectivity",
    );
    return result;
  }

  result.accessible = true;
  result.statusWithoutAuth = parseInt(noAuthCheck.stdout.trim(), 10);

  // Check with Bearer token
  const bearerCheck = await runCommand(
    "curl",
    [
      "-s",
      "-o",
      "/dev/null",
      "-w",
      "%{http_code}",
      "-m",
      "5",
      "-H",
      "Authorization: Bearer test",
      target,
    ],
    10_000,
  );

  if (bearerCheck.exitCode === 0) {
    result.statusWithAuth = parseInt(bearerCheck.stdout.trim(), 10);
  }

  // Determine auth enforcement
  if (
    result.statusWithoutAuth === 401 ||
    result.statusWithoutAuth === 403
  ) {
    result.authRequired = true;
    result.authType = "detected";

    // Try to detect auth type from response headers
    const headerCheck = await runCommand(
      "curl",
      ["-sI", "-m", "5", target],
      10_000,
    );

    if (headerCheck.exitCode === 0) {
      const headers = headerCheck.stdout;
      if (headers.match(/www-authenticate:.*bearer/i)) {
        result.authType = "Bearer/OAuth2";
      } else if (headers.match(/www-authenticate:.*basic/i)) {
        result.authType = "Basic";
      } else if (headers.match(/www-authenticate:.*digest/i)) {
        result.authType = "Digest";
      }
    }
  } else if (
    result.statusWithoutAuth >= 200 &&
    result.statusWithoutAuth < 300
  ) {
    result.authRequired = false;
    result.recommendations.push(
      "WARNING: Endpoint accessible without authentication — enforce auth if this is a protected resource",
    );
  }

  // Check for verbose error messages
  const errorCheck = await runCommand(
    "curl",
    ["-s", "-m", "5", target],
    10_000,
  );

  if (errorCheck.exitCode === 0) {
    const body = errorCheck.stdout;
    if (body.includes("stack") && body.includes("at ")) {
      result.verboseErrors = true;
      result.errorDetails.push("Stack trace detected in response body");
    }
    if (body.match(/\/home\/|\/var\/|\/usr\/|\/opt\//)) {
      result.verboseErrors = true;
      result.errorDetails.push(
        "Internal file paths detected in response body",
      );
    }
    if (
      body.match(/sql|query|database|mysql|postgresql|mongodb/i) &&
      body.match(/error|exception/i)
    ) {
      result.verboseErrors = true;
      result.errorDetails.push(
        "Database error details detected in response body",
      );
    }
  }

  if (result.verboseErrors) {
    result.recommendations.push(
      "CRITICAL: Verbose error messages expose internal details — configure proper error handling",
    );
  }

  // Check API key headers
  const apiKeyCheck = await runCommand(
    "curl",
    [
      "-s",
      "-o",
      "/dev/null",
      "-w",
      "%{http_code}",
      "-m",
      "5",
      "-H",
      "X-API-Key: test",
      target,
    ],
    10_000,
  );

  if (apiKeyCheck.exitCode === 0) {
    const apiKeyStatus = parseInt(apiKeyCheck.stdout.trim(), 10);
    if (
      apiKeyStatus !== result.statusWithoutAuth &&
      apiKeyStatus >= 200 &&
      apiKeyStatus < 300
    ) {
      result.authType = "API Key";
    }
  }

  return result;
}

interface RateLimitResult {
  target: string;
  rateLimitDetected: boolean;
  headers: Record<string, string>;
  got429: boolean;
  requestCount: number;
  responseTimes: number[];
  recommendations: string[];
}

async function checkRateLimiting(target: string): Promise<RateLimitResult> {
  const result: RateLimitResult = {
    target,
    rateLimitDetected: false,
    headers: {},
    got429: false,
    requestCount: 10,
    responseTimes: [],
    recommendations: [],
  };

  const rateLimitHeaders = [
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "retry-after",
  ];

  // Send 10 rapid requests
  for (let i = 0; i < 10; i++) {
    const startTime = Date.now();
    const check = await runCommand(
      "curl",
      [
        "-sI",
        "-m",
        "5",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}\n%{time_total}",
        target,
      ],
      10_000,
    );
    const elapsed = Date.now() - startTime;
    result.responseTimes.push(elapsed);

    if (check.exitCode !== 0) continue;

    const outputParts = check.stdout.trim().split("\n");
    const statusCode = parseInt(outputParts[0], 10);

    if (statusCode === 429) {
      result.got429 = true;
      result.rateLimitDetected = true;
    }

    // Check headers on first request for rate limit headers
    if (i === 0) {
      const headerCheck = await runCommand(
        "curl",
        ["-sI", "-m", "5", target],
        10_000,
      );

      if (headerCheck.exitCode === 0) {
        const headerLines = headerCheck.stdout.split("\n");
        for (const line of headerLines) {
          const colonIdx = line.indexOf(":");
          if (colonIdx < 0) continue;
          const headerName = line
            .substring(0, colonIdx)
            .trim()
            .toLowerCase();
          const headerValue = line.substring(colonIdx + 1).trim();

          if (rateLimitHeaders.includes(headerName)) {
            result.headers[headerName] = headerValue;
            result.rateLimitDetected = true;
          }
        }
      }
    }
  }

  if (!result.rateLimitDetected) {
    result.recommendations.push(
      "WARNING: No rate limiting detected — implement rate limiting to prevent abuse",
    );
    result.recommendations.push(
      "Consider using headers: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset",
    );
  }

  if (result.got429) {
    result.recommendations.push(
      "Rate limiting is active — 429 responses detected",
    );
  }

  // Analyze response time patterns
  if (result.responseTimes.length >= 2) {
    const lastTime = result.responseTimes[result.responseTimes.length - 1];
    const firstTime = result.responseTimes[0];
    if (lastTime > firstTime * 3 && lastTime > 1000) {
      result.recommendations.push(
        "Possible throttling detected — response times increasing significantly",
      );
    }
  }

  return result;
}

interface TlsVerifyResult {
  target: string;
  host: string;
  port: string;
  certificateValid: boolean;
  certSubject: string;
  certIssuer: string;
  certExpiry: string;
  deprecatedProtocols: string[];
  hstsEnabled: boolean;
  hstsValue: string;
  securityGrade: string;
  recommendations: string[];
}

async function tlsVerify(target: string): Promise<TlsVerifyResult> {
  const { host, port } = parseHostPort(target);

  const result: TlsVerifyResult = {
    target,
    host,
    port,
    certificateValid: false,
    certSubject: "unknown",
    certIssuer: "unknown",
    certExpiry: "unknown",
    deprecatedProtocols: [],
    hstsEnabled: false,
    hstsValue: "",
    securityGrade: "F",
    recommendations: [],
  };

  // Check certificate details
  const certCheck = await runCommand(
    "openssl",
    ["s_client", "-connect", `${host}:${port}`, "-servername", host],
    10_000,
  );

  if (
    certCheck.exitCode === 0 ||
    certCheck.stdout.includes("BEGIN CERTIFICATE")
  ) {
    result.certificateValid = true;

    // Parse subject
    const subjectMatch = certCheck.stdout.match(/subject=(.+)/);
    if (subjectMatch) {
      result.certSubject = subjectMatch[1].trim();
    }

    // Parse issuer
    const issuerMatch = certCheck.stdout.match(/issuer=(.+)/);
    if (issuerMatch) {
      result.certIssuer = issuerMatch[1].trim();
    }

    // Parse expiry
    const expiryMatch = certCheck.stdout.match(/notAfter=(.+)/);
    if (expiryMatch) {
      result.certExpiry = expiryMatch[1].trim();
    }
  } else {
    result.recommendations.push(
      "CRITICAL: Cannot establish TLS connection — check if TLS is configured",
    );
    result.securityGrade = "F";
    return result;
  }

  // Check for deprecated TLS 1.0
  const tls10Check = await runCommand(
    "openssl",
    ["s_client", "-connect", `${host}:${port}`, "-tls1"],
    10_000,
  );

  if (
    tls10Check.exitCode === 0 &&
    !tls10Check.stderr.includes("no protocols available")
  ) {
    result.deprecatedProtocols.push("TLSv1.0");
    result.recommendations.push(
      "WARNING: TLSv1.0 is supported — disable this deprecated protocol",
    );
  }

  // Check for deprecated TLS 1.1
  const tls11Check = await runCommand(
    "openssl",
    ["s_client", "-connect", `${host}:${port}`, "-tls1_1"],
    10_000,
  );

  if (
    tls11Check.exitCode === 0 &&
    !tls11Check.stderr.includes("no protocols available")
  ) {
    result.deprecatedProtocols.push("TLSv1.1");
    result.recommendations.push(
      "WARNING: TLSv1.1 is supported — disable this deprecated protocol",
    );
  }

  // Check HSTS header
  const hstsUrl = target.startsWith("https://") ? target : `https://${host}`;
  const hstsCheck = await runCommand(
    "curl",
    ["-sI", "-m", "5", hstsUrl],
    10_000,
  );

  if (hstsCheck.exitCode === 0) {
    const hstsMatch = hstsCheck.stdout.match(
      /strict-transport-security:\s*(.+)/i,
    );
    if (hstsMatch) {
      result.hstsEnabled = true;
      result.hstsValue = hstsMatch[1].trim();
    } else {
      result.recommendations.push(
        "WARNING: HSTS header not found — enable Strict-Transport-Security",
      );
    }
  }

  // Calculate security grade
  let score = 100;
  if (result.deprecatedProtocols.length > 0)
    score -= 30 * result.deprecatedProtocols.length;
  if (!result.hstsEnabled) score -= 20;
  if (!result.certificateValid) score -= 50;

  if (score >= 90) result.securityGrade = "A";
  else if (score >= 80) result.securityGrade = "B";
  else if (score >= 60) result.securityGrade = "C";
  else if (score >= 40) result.securityGrade = "D";
  else result.securityGrade = "F";

  return result;
}

interface CorsCheckResult {
  target: string;
  corsEnabled: boolean;
  allowOrigin: string;
  allowCredentials: boolean;
  allowMethods: string;
  wildcardOrigin: boolean;
  originReflection: boolean;
  criticalIssues: string[];
  recommendations: string[];
}

async function corsCheck(target: string): Promise<CorsCheckResult> {
  const result: CorsCheckResult = {
    target,
    corsEnabled: false,
    allowOrigin: "",
    allowCredentials: false,
    allowMethods: "",
    wildcardOrigin: false,
    originReflection: false,
    criticalIssues: [],
    recommendations: [],
  };

  // Send request with evil origin
  const evilOriginCheck = await runCommand(
    "curl",
    ["-sI", "-m", "5", "-H", "Origin: https://evil.com", target],
    10_000,
  );

  if (evilOriginCheck.exitCode !== 0) {
    result.recommendations.push(
      "Target is not reachable — check URL and connectivity",
    );
    return result;
  }

  const headers = evilOriginCheck.stdout;

  // Check Access-Control-Allow-Origin
  const acaoMatch = headers.match(/access-control-allow-origin:\s*(.+)/i);
  if (acaoMatch) {
    result.corsEnabled = true;
    result.allowOrigin = acaoMatch[1].trim();

    if (result.allowOrigin === "*") {
      result.wildcardOrigin = true;
      result.recommendations.push(
        "WARNING: Access-Control-Allow-Origin is set to * (wildcard) — restrict to specific origins",
      );
    }

    if (result.allowOrigin === "https://evil.com") {
      result.originReflection = true;
      result.criticalIssues.push(
        "CRITICAL: Origin reflection detected — server reflects any origin in ACAO header",
      );
    }
  }

  // Check Access-Control-Allow-Credentials
  const acacMatch = headers.match(
    /access-control-allow-credentials:\s*(.+)/i,
  );
  if (acacMatch) {
    result.allowCredentials =
      acacMatch[1].trim().toLowerCase() === "true";

    if (result.allowCredentials && result.wildcardOrigin) {
      result.criticalIssues.push(
        "CRITICAL: Credentials allowed with wildcard origin — this is a severe security misconfiguration",
      );
    }

    if (result.allowCredentials && result.originReflection) {
      result.criticalIssues.push(
        "CRITICAL: Credentials allowed with origin reflection — any site can steal authenticated data",
      );
    }
  }

  // Check Access-Control-Allow-Methods
  const acamMatch = headers.match(
    /access-control-allow-methods:\s*(.+)/i,
  );
  if (acamMatch) {
    result.allowMethods = acamMatch[1].trim();

    const dangerousMethods = ["DELETE", "PUT", "PATCH"];
    for (const method of dangerousMethods) {
      if (result.allowMethods.toUpperCase().includes(method)) {
        result.recommendations.push(
          `WARNING: ${method} method allowed in CORS — ensure this is intentional`,
        );
      }
    }
  }

  // Test with another origin to check for reflection
  if (!result.originReflection) {
    const anotherOriginCheck = await runCommand(
      "curl",
      [
        "-sI",
        "-m",
        "5",
        "-H",
        "Origin: https://attacker.example.com",
        target,
      ],
      10_000,
    );

    if (anotherOriginCheck.exitCode === 0) {
      const anotherAcao = anotherOriginCheck.stdout.match(
        /access-control-allow-origin:\s*(.+)/i,
      );
      if (
        anotherAcao &&
        anotherAcao[1].trim() === "https://attacker.example.com"
      ) {
        result.originReflection = true;
        result.criticalIssues.push(
          "CRITICAL: Origin reflection confirmed — server reflects arbitrary origins",
        );
      }
    }
  }

  if (!result.corsEnabled) {
    result.recommendations.push(
      "No CORS headers detected — CORS is not configured or not applicable",
    );
  }

  if (
    result.criticalIssues.length === 0 &&
    result.corsEnabled &&
    !result.wildcardOrigin
  ) {
    result.recommendations.push("CORS configuration appears secure");
  }

  return result;
}

// ── Registration entry point ───────────────────────────────────────────────

export function registerApiSecurityTools(server: McpServer): void {
  server.tool(
    "api_security",
    "API security: discover local APIs, audit authentication, check rate limiting, verify TLS configuration, and analyze CORS policies.",
    {
      action: z
        .enum([
          "scan_local_apis",
          "audit_auth",
          "check_rate_limiting",
          "tls_verify",
          "cors_check",
        ])
        .describe(
          "Action: scan_local_apis=discover local API services, audit_auth=audit authentication config, check_rate_limiting=test rate limits, tls_verify=verify TLS configuration, cors_check=check CORS policy",
        ),
      target: z
        .string()
        .optional()
        .describe("URL or host:port to scan (default: http://localhost)"),
      port_range: z
        .string()
        .optional()
        .default(DEFAULT_PORT_RANGE)
        .describe(
          "Port range to scan for APIs (comma-separated, used with scan_local_apis)",
        ),
      output_format: z
        .enum(["text", "json"])
        .optional()
        .default("text")
        .describe("Output format: text or json (default: text)"),
    },
    async (params) => {
      const { action } = params;
      const outputFormat = params.output_format ?? "text";
      const defaultTarget = "http://localhost";

      switch (action) {
        // ── scan_local_apis ────────────────────────────────────────────
        case "scan_local_apis": {
          try {
            const portRange = params.port_range ?? DEFAULT_PORT_RANGE;
            const scanResult = await scanLocalApis(portRange);

            const output = {
              action: "scan_local_apis",
              listeningPorts: scanResult.listeningPorts,
              discoveredApis: scanResult.discoveredApis,
              totalDiscovered: scanResult.totalDiscovered,
              recommendations: scanResult.recommendations,
            };

            if (outputFormat === "json") {
              return { content: [formatToolOutput(output)] };
            }

            let text = "API Security — Local API Discovery\n\n";
            text += `Listening Ports: ${scanResult.listeningPorts.length > 0 ? scanResult.listeningPorts.join(", ") : "none detected"}\n`;
            text += `Scanned Port Range: ${portRange}\n\n`;

            if (scanResult.discoveredApis.length > 0) {
              text += `Discovered APIs (${scanResult.totalDiscovered}):\n`;
              for (const api of scanResult.discoveredApis) {
                text += `  • Port ${api.port}: HTTP ${api.httpStatus} — Framework: ${api.frameworkGuess}\n`;
                if (api.apiPaths.length > 0) {
                  text += `    Active paths: ${api.apiPaths.join(", ")}\n`;
                }
                if (api.docsUrl) {
                  text += `    API Docs: ${api.docsUrl}\n`;
                }
              }
            } else {
              text += "No API services discovered\n";
            }

            if (scanResult.recommendations.length > 0) {
              text += `\nRecommendations:\n`;
              for (const rec of scanResult.recommendations) {
                text += `  • ${rec}\n`;
              }
            }

            return { content: [createTextContent(text)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return {
              content: [
                createErrorContent(`scan_local_apis failed: ${msg}`),
              ],
              isError: true,
            };
          }
        }

        // ── audit_auth ────────────────────────────────────────────────
        case "audit_auth": {
          try {
            const target = params.target
              ? validateTarget(params.target)
              : defaultTarget;
            if (!target) {
              return {
                content: [createErrorContent("Invalid target URL")],
                isError: true,
              };
            }

            const authResult = await auditAuth(target);

            const output = {
              action: "audit_auth",
              target: authResult.target,
              accessible: authResult.accessible,
              statusWithoutAuth: authResult.statusWithoutAuth,
              statusWithAuth: authResult.statusWithAuth,
              authRequired: authResult.authRequired,
              authType: authResult.authType,
              verboseErrors: authResult.verboseErrors,
              errorDetails: authResult.errorDetails,
              recommendations: authResult.recommendations,
            };

            if (outputFormat === "json") {
              return { content: [formatToolOutput(output)] };
            }

            let text = "API Security — Authentication Audit\n\n";
            text += `Target: ${authResult.target}\n`;
            text += `Accessible: ${authResult.accessible ? "yes" : "no"}\n`;
            text += `Auth Required: ${authResult.authRequired ? "YES" : "NO"}\n`;
            text += `Auth Type: ${authResult.authType}\n`;
            text += `Status without auth: ${authResult.statusWithoutAuth}\n`;
            text += `Status with auth: ${authResult.statusWithAuth}\n`;
            text += `Verbose Errors: ${authResult.verboseErrors ? "YES ⚠" : "no"}\n`;

            if (authResult.errorDetails.length > 0) {
              text += `\nError Details:\n`;
              for (const detail of authResult.errorDetails) {
                text += `  • ${detail}\n`;
              }
            }

            if (authResult.recommendations.length > 0) {
              text += `\nRecommendations:\n`;
              for (const rec of authResult.recommendations) {
                text += `  • ${rec}\n`;
              }
            }

            return { content: [createTextContent(text)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return {
              content: [
                createErrorContent(`audit_auth failed: ${msg}`),
              ],
              isError: true,
            };
          }
        }

        // ── check_rate_limiting ────────────────────────────────────────
        case "check_rate_limiting": {
          try {
            const target = params.target
              ? validateTarget(params.target)
              : defaultTarget;
            if (!target) {
              return {
                content: [createErrorContent("Invalid target URL")],
                isError: true,
              };
            }

            const rateResult = await checkRateLimiting(target);

            const output = {
              action: "check_rate_limiting",
              target: rateResult.target,
              rateLimitDetected: rateResult.rateLimitDetected,
              headers: rateResult.headers,
              got429: rateResult.got429,
              requestCount: rateResult.requestCount,
              recommendations: rateResult.recommendations,
            };

            if (outputFormat === "json") {
              return { content: [formatToolOutput(output)] };
            }

            let text = "API Security — Rate Limiting Check\n\n";
            text += `Target: ${rateResult.target}\n`;
            text += `Rate Limiting Detected: ${rateResult.rateLimitDetected ? "YES" : "NO"}\n`;
            text += `429 Responses: ${rateResult.got429 ? "YES" : "no"}\n`;
            text += `Requests Sent: ${rateResult.requestCount}\n`;

            if (Object.keys(rateResult.headers).length > 0) {
              text += `\nRate Limit Headers:\n`;
              for (const [header, value] of Object.entries(
                rateResult.headers,
              )) {
                text += `  • ${header}: ${value}\n`;
              }
            }

            if (rateResult.recommendations.length > 0) {
              text += `\nRecommendations:\n`;
              for (const rec of rateResult.recommendations) {
                text += `  • ${rec}\n`;
              }
            }

            return { content: [createTextContent(text)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return {
              content: [
                createErrorContent(
                  `check_rate_limiting failed: ${msg}`,
                ),
              ],
              isError: true,
            };
          }
        }

        // ── tls_verify ────────────────────────────────────────────────
        case "tls_verify": {
          try {
            const target = params.target
              ? validateTarget(params.target)
              : "https://localhost";
            if (!target) {
              return {
                content: [createErrorContent("Invalid target URL")],
                isError: true,
              };
            }

            const tlsResult = await tlsVerify(target);

            const output = {
              action: "tls_verify",
              target: tlsResult.target,
              host: tlsResult.host,
              port: tlsResult.port,
              certificateValid: tlsResult.certificateValid,
              certSubject: tlsResult.certSubject,
              certIssuer: tlsResult.certIssuer,
              certExpiry: tlsResult.certExpiry,
              deprecatedProtocols: tlsResult.deprecatedProtocols,
              hstsEnabled: tlsResult.hstsEnabled,
              hstsValue: tlsResult.hstsValue,
              securityGrade: tlsResult.securityGrade,
              recommendations: tlsResult.recommendations,
            };

            if (outputFormat === "json") {
              return { content: [formatToolOutput(output)] };
            }

            let text = "API Security — TLS Verification\n\n";
            text += `Target: ${tlsResult.host}:${tlsResult.port}\n`;
            text += `Certificate Valid: ${tlsResult.certificateValid ? "YES" : "NO"}\n`;
            text += `Subject: ${tlsResult.certSubject}\n`;
            text += `Issuer: ${tlsResult.certIssuer}\n`;
            text += `Expiry: ${tlsResult.certExpiry}\n`;
            text += `Deprecated Protocols: ${tlsResult.deprecatedProtocols.length > 0 ? tlsResult.deprecatedProtocols.join(", ") : "none"}\n`;
            text += `HSTS: ${tlsResult.hstsEnabled ? `enabled (${tlsResult.hstsValue})` : "NOT enabled"}\n`;
            text += `Security Grade: ${tlsResult.securityGrade}\n`;

            if (tlsResult.recommendations.length > 0) {
              text += `\nRecommendations:\n`;
              for (const rec of tlsResult.recommendations) {
                text += `  • ${rec}\n`;
              }
            }

            return { content: [createTextContent(text)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return {
              content: [
                createErrorContent(`tls_verify failed: ${msg}`),
              ],
              isError: true,
            };
          }
        }

        // ── cors_check ────────────────────────────────────────────────
        case "cors_check": {
          try {
            const target = params.target
              ? validateTarget(params.target)
              : defaultTarget;
            if (!target) {
              return {
                content: [createErrorContent("Invalid target URL")],
                isError: true,
              };
            }

            const corsResult = await corsCheck(target);

            const output = {
              action: "cors_check",
              target: corsResult.target,
              corsEnabled: corsResult.corsEnabled,
              allowOrigin: corsResult.allowOrigin,
              allowCredentials: corsResult.allowCredentials,
              allowMethods: corsResult.allowMethods,
              wildcardOrigin: corsResult.wildcardOrigin,
              originReflection: corsResult.originReflection,
              criticalIssues: corsResult.criticalIssues,
              recommendations: corsResult.recommendations,
            };

            if (outputFormat === "json") {
              return { content: [formatToolOutput(output)] };
            }

            let text = "API Security — CORS Check\n\n";
            text += `Target: ${corsResult.target}\n`;
            text += `CORS Enabled: ${corsResult.corsEnabled ? "yes" : "no"}\n`;

            if (corsResult.corsEnabled) {
              text += `Allow-Origin: ${corsResult.allowOrigin}\n`;
              text += `Allow-Credentials: ${corsResult.allowCredentials}\n`;
              text += `Allow-Methods: ${corsResult.allowMethods || "not specified"}\n`;
              text += `Wildcard Origin: ${corsResult.wildcardOrigin ? "YES ⚠" : "no"}\n`;
              text += `Origin Reflection: ${corsResult.originReflection ? "YES ⚠" : "no"}\n`;
            }

            if (corsResult.criticalIssues.length > 0) {
              text += `\nCritical Issues:\n`;
              for (const issue of corsResult.criticalIssues) {
                text += `  • ${issue}\n`;
              }
            }

            if (corsResult.recommendations.length > 0) {
              text += `\nRecommendations:\n`;
              for (const rec of corsResult.recommendations) {
                text += `  • ${rec}\n`;
              }
            }

            return { content: [createTextContent(text)] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return {
              content: [
                createErrorContent(`cors_check failed: ${msg}`),
              ],
              isError: true,
            };
          }
        }

        default:
          return {
            content: [createErrorContent(`Unknown action: ${action}`)],
            isError: true,
          };
      }
    },
  );
}
