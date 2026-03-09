/**
 * Tests for src/tools/api-security.ts
 *
 * Covers: api_security tool with actions scan_local_apis, audit_auth,
 * check_rate_limiting, tls_verify, cors_check.
 * Tests API discovery, authentication auditing, rate limiting detection,
 * TLS verification, CORS policy analysis, default target handling,
 * JSON/text output, and error handling.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Mock all external dependencies ─────────────────────────────────────────

vi.mock("../../src/core/spawn-safe.js", () => ({
  spawnSafe: vi.fn(),
}));

vi.mock("../../src/core/parsers.js", () => ({
  createTextContent: vi.fn((text: string) => ({ type: "text", text })),
  createErrorContent: vi.fn((text: string) => ({ type: "text", text: `Error: ${text}` })),
  formatToolOutput: vi.fn((obj: unknown) => ({ type: "text", text: JSON.stringify(obj) })),
}));

import { registerApiSecurityTools } from "../../src/tools/api-security.js";
import { spawnSafe } from "../../src/core/spawn-safe.js";
import { EventEmitter } from "node:events";

const mockSpawnSafe = vi.mocked(spawnSafe);

// ── Helpers ────────────────────────────────────────────────────────────────

type ToolHandler = (
  params: Record<string, unknown>,
) => Promise<{
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}>;

function createMockServer() {
  const tools = new Map<
    string,
    { schema: Record<string, unknown>; handler: ToolHandler }
  >();
  const server = {
    tool: vi.fn(
      (
        name: string,
        _desc: string,
        schema: Record<string, unknown>,
        handler: ToolHandler,
      ) => {
        tools.set(name, { schema, handler });
      },
    ),
  };
  return {
    server: server as unknown as Parameters<typeof registerApiSecurityTools>[0],
    tools,
  };
}

/**
 * Create a mock ChildProcess that emits provided stdout/stderr and close code.
 */
function createMockChildProcess(
  stdout: string,
  stderr: string,
  exitCode: number,
) {
  const cp = new EventEmitter() as EventEmitter & {
    stdout: EventEmitter;
    stderr: EventEmitter;
    kill: ReturnType<typeof vi.fn>;
  };
  cp.stdout = new EventEmitter();
  cp.stderr = new EventEmitter();
  cp.kill = vi.fn();

  // Emit data on next tick so listeners can be set up
  process.nextTick(() => {
    if (stdout) cp.stdout.emit("data", Buffer.from(stdout));
    if (stderr) cp.stderr.emit("data", Buffer.from(stderr));
    cp.emit("close", exitCode);
  });

  return cp;
}

/**
 * Default mock — all commands fail (connection refused / not reachable).
 */
function setupDefaultMocks() {
  mockSpawnSafe.mockImplementation((command: string, _args: string[]) => {
    if (command === "ss") {
      return createMockChildProcess("", "", 0);
    }
    if (command === "curl") {
      return createMockChildProcess("000", "Connection refused", 7);
    }
    if (command === "openssl") {
      return createMockChildProcess("", "Connection refused", 1);
    }
    return createMockChildProcess("", "", 1);
  });
}

/**
 * Mock for scan_local_apis — simulates listening services on ports 3000 and 8080.
 */
function setupScanApiMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    if (command === "ss") {
      return createMockChildProcess(
        "State  Recv-Q Send-Q  Local Address:Port   Peer Address:Port\n" +
        "LISTEN 0      128          0.0.0.0:3000       0.0.0.0:*\n" +
        "LISTEN 0      128          0.0.0.0:8080       0.0.0.0:*\n",
        "",
        0,
      );
    }
    if (command === "curl") {
      // curl -s -o /dev/null -w "%{http_code}" — HTTP status check
      if (args.includes("-w") && args.includes("%{http_code}") && !args.includes("-I") && !args.some(a => a.startsWith("-H"))) {
        const urlArg = args[args.length - 1];
        if (urlArg.includes(":3000/")) {
          return createMockChildProcess("200", "", 0);
        }
        if (urlArg.includes(":8080/")) {
          return createMockChildProcess("200", "", 0);
        }
        if (urlArg.includes(":3000/api")) {
          return createMockChildProcess("200", "", 0);
        }
        if (urlArg.includes(":3000/health")) {
          return createMockChildProcess("200", "", 0);
        }
        if (urlArg.includes(":3000/swagger.json")) {
          return createMockChildProcess("200", "", 0);
        }
        if (urlArg.includes(":8080/api")) {
          return createMockChildProcess("404", "", 0);
        }
        if (urlArg.includes(":8080/health")) {
          return createMockChildProcess("200", "", 0);
        }
        // Other ports — no HTTP
        return createMockChildProcess("000", "", 7);
      }
      // curl -sI — header check
      if (args.includes("-sI") || args.some(a => a === "-I")) {
        if (args.some(a => a.includes(":3000"))) {
          return createMockChildProcess(
            "HTTP/1.1 200 OK\r\nX-Powered-By: Express\r\nContent-Type: application/json\r\n\r\n",
            "",
            0,
          );
        }
        if (args.some(a => a.includes(":8080"))) {
          return createMockChildProcess(
            "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n\r\n",
            "",
            0,
          );
        }
      }
      return createMockChildProcess("000", "", 7);
    }
    return createMockChildProcess("", "", 1);
  });
}

/**
 * Mock for audit_auth — simulates an endpoint requiring auth (401).
 */
function setupAuthRequiredMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    if (command === "curl") {
      // Status code check without auth
      if (args.includes("-w") && args.includes("%{http_code}") && !args.some(a => a.includes("Authorization")) && !args.some(a => a.includes("X-API-Key"))) {
        return createMockChildProcess("401", "", 0);
      }
      // Status code check with Bearer auth
      if (args.includes("-w") && args.includes("%{http_code}") && args.some(a => a.includes("Bearer"))) {
        return createMockChildProcess("401", "", 0);
      }
      // Status code check with API key
      if (args.includes("-w") && args.includes("%{http_code}") && args.some(a => a.includes("X-API-Key"))) {
        return createMockChildProcess("401", "", 0);
      }
      // Header check
      if (args.includes("-sI")) {
        return createMockChildProcess(
          "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"api\"\r\n\r\n",
          "",
          0,
        );
      }
      // Body check
      if (args.includes("-s") && !args.includes("-o") && !args.includes("-I")) {
        return createMockChildProcess('{"error":"unauthorized"}', "", 0);
      }
      return createMockChildProcess("401", "", 0);
    }
    return createMockChildProcess("", "", 1);
  });
}

/**
 * Mock for audit_auth — simulates endpoint open without auth (200).
 */
function setupNoAuthMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    if (command === "curl") {
      if (args.includes("-w") && args.includes("%{http_code}")) {
        return createMockChildProcess("200", "", 0);
      }
      if (args.includes("-sI")) {
        return createMockChildProcess(
          "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n",
          "",
          0,
        );
      }
      if (args.includes("-s") && !args.includes("-o") && !args.includes("-I")) {
        return createMockChildProcess('{"data":"public"}', "", 0);
      }
      return createMockChildProcess("200", "", 0);
    }
    return createMockChildProcess("", "", 1);
  });
}

/**
 * Mock for audit_auth — simulates verbose errors.
 */
function setupVerboseErrorMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    if (command === "curl") {
      if (args.includes("-w") && args.includes("%{http_code}")) {
        return createMockChildProcess("500", "", 0);
      }
      if (args.includes("-sI")) {
        return createMockChildProcess(
          "HTTP/1.1 500 Internal Server Error\r\n\r\n",
          "",
          0,
        );
      }
      if (args.includes("-s") && !args.includes("-o") && !args.includes("-I")) {
        return createMockChildProcess(
          'Error: ENOENT at /var/lib/app/server.js:42\n  stack trace:\n  at Object.<anonymous> (/home/user/app.js:10:5)',
          "",
          0,
        );
      }
      return createMockChildProcess("500", "", 0);
    }
    return createMockChildProcess("", "", 1);
  });
}

/**
 * Mock for check_rate_limiting — simulates rate limit headers present.
 */
function setupRateLimitDetectedMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    if (command === "curl") {
      // Status+time check
      if (args.includes("-w") && args.some(a => a.includes("%{http_code}"))) {
        return createMockChildProcess("200\n0.050", "", 0);
      }
      // Header check
      if (args.includes("-sI")) {
        return createMockChildProcess(
          "HTTP/1.1 200 OK\r\n" +
          "X-RateLimit-Limit: 100\r\n" +
          "X-RateLimit-Remaining: 95\r\n" +
          "X-RateLimit-Reset: 1609459200\r\n" +
          "Content-Type: application/json\r\n\r\n",
          "",
          0,
        );
      }
      return createMockChildProcess("200", "", 0);
    }
    return createMockChildProcess("", "", 1);
  });
}

/**
 * Mock for check_rate_limiting — simulates 429 response.
 */
function setupRateLimit429Mocks() {
  let callCount = 0;
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    if (command === "curl") {
      if (args.includes("-w") && args.some(a => a.includes("%{http_code}"))) {
        callCount++;
        // Return 429 after 5 requests
        if (callCount > 5) {
          return createMockChildProcess("429\n0.010", "", 0);
        }
        return createMockChildProcess("200\n0.010", "", 0);
      }
      if (args.includes("-sI")) {
        return createMockChildProcess(
          "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n",
          "",
          0,
        );
      }
      return createMockChildProcess("200", "", 0);
    }
    return createMockChildProcess("", "", 1);
  });
}

/**
 * Mock for tls_verify — simulates valid TLS with good config.
 */
function setupTlsValidMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    if (command === "openssl") {
      if (args.includes("-tls1")) {
        return createMockChildProcess("", "no protocols available", 1);
      }
      if (args.includes("-tls1_1")) {
        return createMockChildProcess("", "no protocols available", 1);
      }
      // Default s_client connect
      return createMockChildProcess(
        "CONNECTED(00000003)\n" +
        "---\n" +
        "Certificate chain\n" +
        " 0 s:CN = example.com\n" +
        "   i:C = US, O = Let's Encrypt, CN = R3\n" +
        "---\n" +
        "subject=CN = example.com\n" +
        "issuer=C = US, O = Let's Encrypt, CN = R3\n" +
        "---\n" +
        "notAfter=Dec 31 23:59:59 2025 GMT\n" +
        "---\n" +
        "-----BEGIN CERTIFICATE-----\nMIIBfake...\n-----END CERTIFICATE-----\n",
        "",
        0,
      );
    }
    if (command === "curl") {
      if (args.includes("-sI")) {
        return createMockChildProcess(
          "HTTP/1.1 200 OK\r\n" +
          "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n" +
          "Content-Type: text/html\r\n\r\n",
          "",
          0,
        );
      }
      return createMockChildProcess("200", "", 0);
    }
    return createMockChildProcess("", "", 1);
  });
}

/**
 * Mock for tls_verify — simulates deprecated protocols.
 */
function setupTlsDeprecatedMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    if (command === "openssl") {
      if (args.includes("-tls1")) {
        // TLSv1.0 accepted
        return createMockChildProcess("CONNECTED\nProtocol: TLSv1\n", "", 0);
      }
      if (args.includes("-tls1_1")) {
        // TLSv1.1 accepted
        return createMockChildProcess("CONNECTED\nProtocol: TLSv1.1\n", "", 0);
      }
      return createMockChildProcess(
        "CONNECTED(00000003)\n" +
        "subject=CN = example.com\n" +
        "issuer=C = US, O = Let's Encrypt, CN = R3\n" +
        "notAfter=Dec 31 23:59:59 2025 GMT\n" +
        "-----BEGIN CERTIFICATE-----\nMIIBfake...\n-----END CERTIFICATE-----\n",
        "",
        0,
      );
    }
    if (command === "curl") {
      if (args.includes("-sI")) {
        return createMockChildProcess(
          "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n",
          "",
          0,
        );
      }
      return createMockChildProcess("200", "", 0);
    }
    return createMockChildProcess("", "", 1);
  });
}

/**
 * Mock for cors_check — simulates wildcard CORS.
 */
function setupCorsWildcardMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    if (command === "curl") {
      if (args.includes("-sI")) {
        return createMockChildProcess(
          "HTTP/1.1 200 OK\r\n" +
          "Access-Control-Allow-Origin: *\r\n" +
          "Access-Control-Allow-Methods: GET, POST, PUT, DELETE\r\n" +
          "Content-Type: application/json\r\n\r\n",
          "",
          0,
        );
      }
      return createMockChildProcess("200", "", 0);
    }
    return createMockChildProcess("", "", 1);
  });
}

/**
 * Mock for cors_check — simulates origin reflection with credentials.
 */
function setupCorsReflectionMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    if (command === "curl") {
      if (args.includes("-sI")) {
        // Reflect origin for evil.com
        if (args.some(a => a.includes("evil.com"))) {
          return createMockChildProcess(
            "HTTP/1.1 200 OK\r\n" +
            "Access-Control-Allow-Origin: https://evil.com\r\n" +
            "Access-Control-Allow-Credentials: true\r\n" +
            "Access-Control-Allow-Methods: GET, POST\r\n" +
            "Content-Type: application/json\r\n\r\n",
            "",
            0,
          );
        }
        // Reflect origin for attacker.example.com
        if (args.some(a => a.includes("attacker.example.com"))) {
          return createMockChildProcess(
            "HTTP/1.1 200 OK\r\n" +
            "Access-Control-Allow-Origin: https://attacker.example.com\r\n" +
            "Access-Control-Allow-Credentials: true\r\n" +
            "Content-Type: application/json\r\n\r\n",
            "",
            0,
          );
        }
        return createMockChildProcess(
          "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n",
          "",
          0,
        );
      }
      return createMockChildProcess("200", "", 0);
    }
    return createMockChildProcess("", "", 1);
  });
}

/**
 * Mock for cors_check — simulates no CORS headers.
 */
function setupNoCorsHeadersMocks() {
  mockSpawnSafe.mockImplementation((command: string, _args: string[]) => {
    if (command === "curl") {
      return createMockChildProcess(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n",
        "",
        0,
      );
    }
    return createMockChildProcess("", "", 1);
  });
}

// ── Tests ──────────────────────────────────────────────────────────────────

describe("api-security tools", () => {
  let tools: Map<
    string,
    { schema: Record<string, unknown>; handler: ToolHandler }
  >;

  beforeEach(() => {
    vi.clearAllMocks();
    const mock = createMockServer();
    registerApiSecurityTools(mock.server);
    tools = mock.tools;
    setupDefaultMocks();
  });

  // ── Registration ────────────────────────────────────────────────────────

  it("should register the api_security tool", () => {
    expect(tools.has("api_security")).toBe(true);
  });

  it("should register with server.tool called once", () => {
    const mock = createMockServer();
    registerApiSecurityTools(mock.server);
    expect(mock.server.tool).toHaveBeenCalledTimes(1);
    expect(mock.server.tool).toHaveBeenCalledWith(
      "api_security",
      expect.any(String),
      expect.any(Object),
      expect.any(Function),
    );
  });

  // ── Unknown action ──────────────────────────────────────────────────────

  it("should report error for unknown action", async () => {
    const handler = tools.get("api_security")!.handler;
    const result = await handler({ action: "nonexistent" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Unknown action");
  });

  // ── scan_local_apis ─────────────────────────────────────────────────────

  describe("scan_local_apis", () => {
    it("should discover APIs on scanned ports", async () => {
      setupScanApiMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "scan_local_apis",
        port_range: "3000,8080",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("scan_local_apis");
      expect(parsed.totalDiscovered).toBeGreaterThan(0);
      expect(parsed.discoveredApis.length).toBeGreaterThan(0);
    });

    it("should identify Express framework from headers", async () => {
      setupScanApiMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "scan_local_apis",
        port_range: "3000",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      const api3000 = parsed.discoveredApis.find(
        (a: { port: number }) => a.port === 3000,
      );
      expect(api3000).toBeDefined();
      expect(api3000.frameworkGuess).toBe("Express.js");
    });

    it("should identify Nginx from headers", async () => {
      setupScanApiMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "scan_local_apis",
        port_range: "8080",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      const api8080 = parsed.discoveredApis.find(
        (a: { port: number }) => a.port === 8080,
      );
      expect(api8080).toBeDefined();
      expect(api8080.frameworkGuess).toBe("Nginx");
    });

    it("should detect listening ports", async () => {
      setupScanApiMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "scan_local_apis",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.listeningPorts).toContain(3000);
      expect(parsed.listeningPorts).toContain(8080);
    });

    it("should detect API docs URL when swagger.json found", async () => {
      setupScanApiMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "scan_local_apis",
        port_range: "3000",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      const api3000 = parsed.discoveredApis.find(
        (a: { port: number }) => a.port === 3000,
      );
      expect(api3000).toBeDefined();
      expect(api3000.docsUrl).toMatch(/swagger\.json|openapi\.json/);
    });

    it("should handle no services found", async () => {
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "scan_local_apis",
        port_range: "9999",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.totalDiscovered).toBe(0);
      expect(parsed.recommendations.length).toBeGreaterThan(0);
    });

    it("should use default port range", async () => {
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "scan_local_apis",
        output_format: "json",
      });
      expect(result.content).toBeDefined();
    });

    it("should return text format with discovery details", async () => {
      setupScanApiMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "scan_local_apis",
        port_range: "3000,8080",
      });
      expect(result.content[0].text).toContain("Local API Discovery");
      expect(result.content[0].text).toContain("Port");
    });
  });

  // ── audit_auth ──────────────────────────────────────────────────────────

  describe("audit_auth", () => {
    it("should detect 401 as requiring authentication", async () => {
      setupAuthRequiredMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "audit_auth",
        target: "http://localhost:3000/api",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.authRequired).toBe(true);
      expect(parsed.statusWithoutAuth).toBe(401);
    });

    it("should detect Bearer auth type from headers", async () => {
      setupAuthRequiredMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "audit_auth",
        target: "http://localhost:3000/api",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.authType).toBe("Bearer/OAuth2");
    });

    it("should warn when endpoint accessible without auth", async () => {
      setupNoAuthMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "audit_auth",
        target: "http://localhost:3000",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.authRequired).toBe(false);
      expect(
        parsed.recommendations.some((r: string) =>
          r.includes("without authentication"),
        ),
      ).toBe(true);
    });

    it("should detect verbose error messages", async () => {
      setupVerboseErrorMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "audit_auth",
        target: "http://localhost:3000",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.verboseErrors).toBe(true);
      expect(parsed.errorDetails.length).toBeGreaterThan(0);
      expect(
        parsed.recommendations.some((r: string) =>
          r.includes("Verbose error"),
        ),
      ).toBe(true);
    });

    it("should use default target http://localhost", async () => {
      setupNoAuthMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "audit_auth",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.target).toBe("http://localhost");
    });

    it("should handle connection refused gracefully", async () => {
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "audit_auth",
        target: "http://localhost:9999",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.accessible).toBe(false);
      expect(
        parsed.recommendations.some((r: string) =>
          r.includes("not reachable"),
        ),
      ).toBe(true);
    });

    it("should return text format with auth details", async () => {
      setupAuthRequiredMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "audit_auth",
        target: "http://localhost:3000",
      });
      expect(result.content[0].text).toContain("Authentication Audit");
      expect(result.content[0].text).toContain("Auth Required");
    });

    it("should report error for invalid target URL", async () => {
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "audit_auth",
        target: "://invalid",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Invalid target");
    });
  });

  // ── check_rate_limiting ──────────────────────────────────────────────────

  describe("check_rate_limiting", () => {
    it("should detect rate limit headers", async () => {
      setupRateLimitDetectedMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "check_rate_limiting",
        target: "http://localhost:3000",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.rateLimitDetected).toBe(true);
      expect(parsed.headers["x-ratelimit-limit"]).toBe("100");
      expect(parsed.headers["x-ratelimit-remaining"]).toBe("95");
    });

    it("should detect 429 response", async () => {
      setupRateLimit429Mocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "check_rate_limiting",
        target: "http://localhost:3000",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.got429).toBe(true);
      expect(parsed.rateLimitDetected).toBe(true);
    });

    it("should warn when no rate limiting detected", async () => {
      setupNoAuthMocks(); // Reuse — always returns 200 without rate limit headers
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "check_rate_limiting",
        target: "http://localhost:3000",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.rateLimitDetected).toBe(false);
      expect(
        parsed.recommendations.some((r: string) =>
          r.includes("No rate limiting detected"),
        ),
      ).toBe(true);
    });

    it("should use default target", async () => {
      setupDefaultMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "check_rate_limiting",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.target).toBe("http://localhost");
    });

    it("should return text format with rate limit info", async () => {
      setupRateLimitDetectedMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "check_rate_limiting",
        target: "http://localhost:3000",
      });
      expect(result.content[0].text).toContain("Rate Limiting Check");
      expect(result.content[0].text).toContain("Rate Limiting Detected");
    });

    it("should report request count", async () => {
      setupRateLimitDetectedMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "check_rate_limiting",
        target: "http://localhost:3000",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.requestCount).toBe(10);
    });
  });

  // ── tls_verify ──────────────────────────────────────────────────────────

  describe("tls_verify", () => {
    it("should verify valid TLS certificate", async () => {
      setupTlsValidMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "tls_verify",
        target: "https://example.com",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.certificateValid).toBe(true);
      expect(parsed.certSubject).toContain("example.com");
      expect(parsed.certIssuer).toContain("Let's Encrypt");
    });

    it("should parse certificate expiry", async () => {
      setupTlsValidMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "tls_verify",
        target: "https://example.com",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.certExpiry).toContain("2025");
    });

    it("should detect deprecated TLS protocols", async () => {
      setupTlsDeprecatedMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "tls_verify",
        target: "https://example.com",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.deprecatedProtocols).toContain("TLSv1.0");
      expect(parsed.deprecatedProtocols).toContain("TLSv1.1");
      expect(
        parsed.recommendations.some((r: string) =>
          r.includes("TLSv1.0"),
        ),
      ).toBe(true);
    });

    it("should detect HSTS header", async () => {
      setupTlsValidMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "tls_verify",
        target: "https://example.com",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.hstsEnabled).toBe(true);
      expect(parsed.hstsValue).toContain("max-age");
    });

    it("should warn when HSTS not found", async () => {
      setupTlsDeprecatedMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "tls_verify",
        target: "https://example.com",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.hstsEnabled).toBe(false);
      expect(
        parsed.recommendations.some((r: string) => r.includes("HSTS")),
      ).toBe(true);
    });

    it("should assign security grade A for good config", async () => {
      setupTlsValidMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "tls_verify",
        target: "https://example.com",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.securityGrade).toBe("A");
    });

    it("should assign lower grade for deprecated protocols", async () => {
      setupTlsDeprecatedMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "tls_verify",
        target: "https://example.com",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(["D", "F"]).toContain(parsed.securityGrade);
    });

    it("should handle TLS connection failure", async () => {
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "tls_verify",
        target: "https://localhost:9999",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.certificateValid).toBe(false);
      expect(parsed.securityGrade).toBe("F");
      expect(
        parsed.recommendations.some((r: string) =>
          r.includes("Cannot establish TLS"),
        ),
      ).toBe(true);
    });

    it("should default target to https://localhost", async () => {
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "tls_verify",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.host).toBe("localhost");
    });

    it("should return text format with TLS details", async () => {
      setupTlsValidMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "tls_verify",
        target: "https://example.com",
      });
      expect(result.content[0].text).toContain("TLS Verification");
      expect(result.content[0].text).toContain("Security Grade");
    });
  });

  // ── cors_check ──────────────────────────────────────────────────────────

  describe("cors_check", () => {
    it("should detect wildcard CORS origin", async () => {
      setupCorsWildcardMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "cors_check",
        target: "http://localhost:3000",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.corsEnabled).toBe(true);
      expect(parsed.wildcardOrigin).toBe(true);
      expect(parsed.allowOrigin).toBe("*");
      expect(
        parsed.recommendations.some((r: string) =>
          r.includes("wildcard"),
        ),
      ).toBe(true);
    });

    it("should detect origin reflection", async () => {
      setupCorsReflectionMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "cors_check",
        target: "http://localhost:3000",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.originReflection).toBe(true);
      expect(parsed.criticalIssues.length).toBeGreaterThan(0);
      expect(
        parsed.criticalIssues.some((i: string) =>
          i.includes("Origin reflection"),
        ),
      ).toBe(true);
    });

    it("should flag credentials with origin reflection as critical", async () => {
      setupCorsReflectionMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "cors_check",
        target: "http://localhost:3000",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.allowCredentials).toBe(true);
      expect(
        parsed.criticalIssues.some((i: string) =>
          i.includes("Credentials allowed with origin reflection"),
        ),
      ).toBe(true);
    });

    it("should check allowed methods for dangerous verbs", async () => {
      setupCorsWildcardMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "cors_check",
        target: "http://localhost:3000",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.allowMethods).toContain("DELETE");
      expect(
        parsed.recommendations.some((r: string) =>
          r.includes("DELETE"),
        ),
      ).toBe(true);
    });

    it("should detect no CORS headers", async () => {
      setupNoCorsHeadersMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "cors_check",
        target: "http://localhost:3000",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.corsEnabled).toBe(false);
      expect(
        parsed.recommendations.some((r: string) =>
          r.includes("No CORS headers"),
        ),
      ).toBe(true);
    });

    it("should use default target", async () => {
      setupNoCorsHeadersMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "cors_check",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.target).toBe("http://localhost");
    });

    it("should return text format with CORS details", async () => {
      setupCorsWildcardMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "cors_check",
        target: "http://localhost:3000",
      });
      expect(result.content[0].text).toContain("CORS Check");
      expect(result.content[0].text).toContain("CORS Enabled");
    });

    it("should handle connection refused gracefully", async () => {
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "cors_check",
        target: "http://localhost:9999",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(
        parsed.recommendations.some((r: string) =>
          r.includes("not reachable"),
        ),
      ).toBe(true);
    });
  });

  // ── Output format tests ─────────────────────────────────────────────────

  describe("output formats", () => {
    it("should return JSON for scan_local_apis", async () => {
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "scan_local_apis",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("scan_local_apis");
    });

    it("should return JSON for audit_auth", async () => {
      setupNoAuthMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "audit_auth",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("audit_auth");
    });

    it("should return JSON for check_rate_limiting", async () => {
      setupRateLimitDetectedMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "check_rate_limiting",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("check_rate_limiting");
    });

    it("should return JSON for tls_verify", async () => {
      setupTlsValidMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "tls_verify",
        target: "https://example.com",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("tls_verify");
    });

    it("should return JSON for cors_check", async () => {
      setupNoCorsHeadersMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "cors_check",
        output_format: "json",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("cors_check");
    });

    it("should default to text format", async () => {
      setupNoCorsHeadersMocks();
      const handler = tools.get("api_security")!.handler;
      const result = await handler({ action: "cors_check" });
      expect(result.content[0].text).toContain("API Security");
    });
  });

  // ── Error handling ──────────────────────────────────────────────────────

  describe("error handling", () => {
    it("should handle spawnSafe throwing errors", async () => {
      mockSpawnSafe.mockImplementation(() => {
        throw new Error("spawn failed");
      });

      const handler = tools.get("api_security")!.handler;
      // scan_local_apis catches errors internally in runCommand
      const result = await handler({
        action: "scan_local_apis",
        output_format: "json",
      });
      expect(result.content).toBeDefined();
    });

    it("should handle command failures in all actions gracefully", async () => {
      mockSpawnSafe.mockImplementation(() => {
        return createMockChildProcess("", "command failed", 1);
      });

      const handler = tools.get("api_security")!.handler;

      for (const action of [
        "scan_local_apis",
        "audit_auth",
        "check_rate_limiting",
        "cors_check",
      ]) {
        const result = await handler({ action, output_format: "json" });
        expect(result.content).toBeDefined();
        expect(result.isError).toBeUndefined();
      }
    });

    it("should handle timeout in commands", async () => {
      mockSpawnSafe.mockImplementation(() => {
        const cp = new EventEmitter() as EventEmitter & {
          stdout: EventEmitter;
          stderr: EventEmitter;
          kill: ReturnType<typeof vi.fn>;
        };
        cp.stdout = new EventEmitter();
        cp.stderr = new EventEmitter();
        cp.kill = vi.fn();
        // Never emits close — will timeout
        return cp;
      });

      const handler = tools.get("api_security")!.handler;
      // This should timeout but not throw
      const result = await handler({
        action: "scan_local_apis",
        port_range: "3000",
        output_format: "json",
      });
      expect(result.content).toBeDefined();
    }, 60_000);

    it("should report error for invalid target in tls_verify", async () => {
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "tls_verify",
        target: "://invalid",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Invalid target");
    });

    it("should report error for invalid target in check_rate_limiting", async () => {
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "check_rate_limiting",
        target: "://invalid",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Invalid target");
    });

    it("should report error for invalid target in cors_check", async () => {
      const handler = tools.get("api_security")!.handler;
      const result = await handler({
        action: "cors_check",
        target: "://invalid",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Invalid target");
    });
  });
});
