/**
 * Tests for src/tools/encryption.ts
 *
 * Covers: TOOL-023 algorithm validation, key path validation, path traversal
 * rejection, tool registration, and action routing.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/core/executor.js", () => ({
  executeCommand: vi.fn().mockResolvedValue({ exitCode: 0, stdout: "", stderr: "", timedOut: false, duration: 10, permissionDenied: false }),
}));
vi.mock("../../src/core/config.js", () => ({
  getConfig: vi.fn().mockReturnValue({ dryRun: true }),
  getToolTimeout: vi.fn().mockReturnValue(30000),
}));
vi.mock("../../src/core/parsers.js", () => ({
  createTextContent: vi.fn((text: string) => ({ type: "text", text })),
  createErrorContent: vi.fn((text: string) => ({ type: "text", text: `Error: ${text}` })),
  formatToolOutput: vi.fn((obj: unknown) => ({ type: "text", text: JSON.stringify(obj) })),
}));
vi.mock("../../src/core/changelog.js", () => ({
  logChange: vi.fn(),
  createChangeEntry: vi.fn().mockReturnValue({}),
  backupFile: vi.fn().mockReturnValue("/tmp/backup"),
}));
vi.mock("../../src/core/sanitizer.js", () => ({
  validateTarget: vi.fn((t: string) => t),
  validateFilePath: vi.fn((p: string) => p),
  validateCertPath: vi.fn((p: string) => p),
  sanitizeArgs: vi.fn((a: string[]) => a),
  validateToolPath: vi.fn((p: string, _dirs: string[], _label: string) => {
    if (p.includes("..")) throw new Error("Path contains forbidden directory traversal (..)");
    return p;
  }),
}));
vi.mock("../../src/core/spawn-safe.js", () => ({
  spawnSafe: vi.fn(),
}));

import { registerEncryptionTools } from "../../src/tools/encryption.js";
import { spawnSafe } from "../../src/core/spawn-safe.js";
import { EventEmitter } from "node:events";

const mockSpawnSafe = vi.mocked(spawnSafe);

type ToolHandler = (params: Record<string, unknown>) => Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }>;

function createMockServer() {
  const tools = new Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>();
  const server = {
    tool: vi.fn((name: string, _desc: string, schema: Record<string, unknown>, handler: ToolHandler) => {
      tools.set(name, { schema, handler });
    }),
  };
  return { server: server as unknown as Parameters<typeof registerEncryptionTools>[0], tools };
}

describe("encryption tools", () => {
  let tools: Map<string, { schema: Record<string, unknown>; handler: ToolHandler }>;

  beforeEach(() => {
    vi.clearAllMocks();
    const mock = createMockServer();
    registerEncryptionTools(mock.server);
    tools = mock.tools;
  });

  it("should register all 5 encryption tools", () => {
    expect(tools.has("crypto_tls")).toBe(true);
    expect(tools.has("crypto_gpg_keys")).toBe(true);
    expect(tools.has("crypto_luks_manage")).toBe(true);
    expect(tools.has("crypto_file_hash")).toBe(true);
    expect(tools.has("certificate_lifecycle")).toBe(true);
  });

  // ── crypto_tls ────────────────────────────────────────────────────────

  it("should require host for remote_audit action", async () => {
    const handler = tools.get("crypto_tls")!.handler;
    const result = await handler({ action: "remote_audit", port: 443, check_ciphers: true, check_protocols: true, check_certificate: true });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("host is required");
  });

  it("should require cert_path or host for cert_expiry", async () => {
    const handler = tools.get("crypto_tls")!.handler;
    const result = await handler({ action: "cert_expiry", port: 443, warn_days: 30 });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Must specify");
  });

  // ── crypto_gpg_keys ───────────────────────────────────────────────────

  it("should require key_id for GPG export action", async () => {
    const handler = tools.get("crypto_gpg_keys")!.handler;
    const result = await handler({ action: "export" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("key_id is required");
  });

  it("should require file_path for GPG import action", async () => {
    const handler = tools.get("crypto_gpg_keys")!.handler;
    const result = await handler({ action: "import" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("file_path is required");
  });

  it("should reject GPG import path with traversal (TOOL-023)", async () => {
    const handler = tools.get("crypto_gpg_keys")!.handler;
    const result = await handler({ action: "import", file_path: "/tmp/../../../etc/shadow" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("traversal");
  });

  // ── crypto_luks_manage ────────────────────────────────────────────────

  it("should require name for LUKS status action", async () => {
    const handler = tools.get("crypto_luks_manage")!.handler;
    const result = await handler({ action: "status" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("name");
  });

  it("should require device for LUKS dump action", async () => {
    const handler = tools.get("crypto_luks_manage")!.handler;
    const result = await handler({ action: "dump" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("device");
  });

  it("should reject LUKS device path with traversal", async () => {
    const handler = tools.get("crypto_luks_manage")!.handler;
    const result = await handler({ action: "dump", device: "/dev/../etc/shadow" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("traversal");
  });

  // ── crypto_file_hash ──────────────────────────────────────────────────

  it("should reject file hash path with traversal", async () => {
    const handler = tools.get("crypto_file_hash")!.handler;
    const result = await handler({ path: "/etc/../../../etc/shadow", algorithm: "sha256", recursive: false });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("traversal");
  });
  // ── certificate_lifecycle ──────────────────────────────────────────────

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
      stdin: { write: ReturnType<typeof vi.fn>; end: ReturnType<typeof vi.fn> };
      kill: ReturnType<typeof vi.fn>;
    };
    cp.stdout = new EventEmitter();
    cp.stderr = new EventEmitter();
    cp.stdin = { write: vi.fn(), end: vi.fn() };
    cp.kill = vi.fn();

    process.nextTick(() => {
      if (stdout) cp.stdout.emit("data", Buffer.from(stdout));
      if (stderr) cp.stderr.emit("data", Buffer.from(stderr));
      cp.emit("close", exitCode);
    });

    return cp;
  }

  describe("certificate_lifecycle", () => {
    it("should be registered as a tool", () => {
      expect(tools.has("certificate_lifecycle")).toBe(true);
    });

    it("should report error for unknown action", async () => {
      const handler = tools.get("certificate_lifecycle")!.handler;
      const result = await handler({ action: "nonexistent" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Unknown action");
    });

    // ── inventory ──────────────────────────────────────────────────────

    describe("inventory", () => {
      it("should scan for certificates and categorize them", async () => {
        mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
          if (command === "find" && args[0] === "/etc/ssl/certs/") {
            return createMockChildProcess("/etc/ssl/certs/test.pem\n/etc/ssl/certs/expired.crt\n", "", 0);
          }
          if (command === "find") {
            return createMockChildProcess("", "", 1);
          }
          if (command === "openssl" && args.includes("-subject")) {
            const certPath = args[args.indexOf("-in") + 1];
            if (certPath.includes("expired")) {
              return createMockChildProcess(
                "subject=CN = expired.example.com\nissuer=CN = Test CA\nnotBefore=Jan  1 00:00:00 2020 GMT\nnotAfter=Jan  1 00:00:00 2021 GMT\nserial=01\n",
                "",
                0,
              );
            }
            return createMockChildProcess(
              "subject=CN = valid.example.com\nissuer=CN = Test CA\nnotBefore=Jan  1 00:00:00 2024 GMT\nnotAfter=Dec 31 23:59:59 2030 GMT\nserial=02\n",
              "",
              0,
            );
          }
          return createMockChildProcess("", "", 1);
        });

        const handler = tools.get("certificate_lifecycle")!.handler;
        const result = await handler({ action: "inventory", output_format: "json" });
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.totalCerts).toBe(2);
        expect(parsed.expired).toBe(1);
        expect(parsed.valid).toBe(1);
        expect(parsed.certificates.length).toBe(2);
      });

      it("should detect expiring soon certificates", async () => {
        const futureDate = new Date();
        futureDate.setDate(futureDate.getDate() + 15);
        const futureDateStr = futureDate.toUTCString().replace("GMT", "UTC");

        mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
          if (command === "find" && args[0] === "/etc/ssl/certs/") {
            return createMockChildProcess("/etc/ssl/certs/expiring.pem\n", "", 0);
          }
          if (command === "find") {
            return createMockChildProcess("", "", 1);
          }
          if (command === "openssl") {
            return createMockChildProcess(
              `subject=CN = expiring.example.com\nissuer=CN = Test CA\nnotBefore=Jan  1 00:00:00 2024 GMT\nnotAfter=${futureDateStr}\nserial=03\n`,
              "",
              0,
            );
          }
          return createMockChildProcess("", "", 1);
        });

        const handler = tools.get("certificate_lifecycle")!.handler;
        const result = await handler({ action: "inventory", output_format: "json" });
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.expiringSoon).toBe(1);
        expect(parsed.certificates[0].status).toBe("expiring_soon");
      });

      it("should return text format by default", async () => {
        mockSpawnSafe.mockImplementation((command: string) => {
          if (command === "find") {
            return createMockChildProcess("/etc/ssl/certs/test.pem\n", "", 0);
          }
          if (command === "openssl") {
            return createMockChildProcess(
              "subject=CN = test.com\nissuer=CN = CA\nnotBefore=Jan  1 00:00:00 2024 GMT\nnotAfter=Dec 31 23:59:59 2030 GMT\nserial=01\n",
              "",
              0,
            );
          }
          return createMockChildProcess("", "", 1);
        });

        const handler = tools.get("certificate_lifecycle")!.handler;
        const result = await handler({ action: "inventory" });
        expect(result.content[0].text).toContain("Certificate Inventory");
        expect(result.content[0].text).toContain("Valid:");
      });

      it("should handle no certificates found", async () => {
        mockSpawnSafe.mockImplementation(() => {
          return createMockChildProcess("", "", 1);
        });

        const handler = tools.get("certificate_lifecycle")!.handler;
        const result = await handler({ action: "inventory", output_format: "json" });
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.totalCerts).toBe(0);
      });

      it("should use custom search_paths", async () => {
        const calledPaths: string[] = [];
        mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
          if (command === "find") {
            calledPaths.push(args[0]);
            return createMockChildProcess("", "", 1);
          }
          return createMockChildProcess("", "", 1);
        });

        const handler = tools.get("certificate_lifecycle")!.handler;
        await handler({ action: "inventory", search_paths: ["/custom/certs/"], output_format: "json" });
        expect(calledPaths).toContain("/custom/certs/");
      });

      it("should reject search paths with traversal", async () => {
        const handler = tools.get("certificate_lifecycle")!.handler;
        const result = await handler({ action: "inventory", search_paths: ["/etc/../../../tmp"] });
        expect(result.isError).toBe(true);
        expect(result.content[0].text).toContain("traversal");
      });
    });

    // ── auto_renew_check ───────────────────────────────────────────────

    describe("auto_renew_check", () => {
      it("should report when certbot is not installed", async () => {
        mockSpawnSafe.mockImplementation((command: string) => {
          if (command === "which") {
            return createMockChildProcess("", "not found", 1);
          }
          return createMockChildProcess("", "", 1);
        });

        const handler = tools.get("certificate_lifecycle")!.handler;
        const result = await handler({ action: "auto_renew_check", output_format: "json" });
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.certbotInstalled).toBe(false);
        expect(parsed.status).toBe("certbot_not_found");
      });

      it("should check certbot timer status when installed", async () => {
        mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
          if (command === "which" && args[0] === "certbot") {
            return createMockChildProcess("/usr/bin/certbot", "", 0);
          }
          if (command === "systemctl" && args.includes("certbot.timer")) {
            return createMockChildProcess("● certbot.timer - Run certbot twice daily\n   Loaded: loaded\n   Active: active (waiting)\n", "", 0);
          }
          if (command === "certbot" && args.includes("certificates")) {
            return createMockChildProcess("Certificate Name: example.com\n  Domains: example.com\n  Expiry Date: 2030-12-31\n", "", 0);
          }
          if (command === "find") {
            return createMockChildProcess("/etc/letsencrypt/renewal/example.com.conf\n", "", 0);
          }
          if (command === "grep") {
            return createMockChildProcess("0 0,12 * * * root certbot renew\n", "", 0);
          }
          return createMockChildProcess("", "", 1);
        });

        const handler = tools.get("certificate_lifecycle")!.handler;
        const result = await handler({ action: "auto_renew_check", output_format: "json" });
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.certbotInstalled).toBe(true);
        expect(parsed.timerActive).toBe(true);
        expect(parsed.renewalConfigs.length).toBe(1);
        expect(parsed.cronJobs.length).toBe(1);
        expect(parsed.status).toBe("checked");
      });

      it("should detect inactive timer", async () => {
        mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
          if (command === "which" && args[0] === "certbot") {
            return createMockChildProcess("/usr/bin/certbot", "", 0);
          }
          if (command === "systemctl") {
            return createMockChildProcess("● certbot.timer\n   Active: inactive (dead)\n", "", 3);
          }
          if (command === "certbot") {
            return createMockChildProcess("", "", 0);
          }
          return createMockChildProcess("", "", 1);
        });

        const handler = tools.get("certificate_lifecycle")!.handler;
        const result = await handler({ action: "auto_renew_check", output_format: "json" });
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.timerActive).toBe(false);
      });

      it("should return text format when certbot not found", async () => {
        mockSpawnSafe.mockImplementation((command: string) => {
          if (command === "which") {
            return createMockChildProcess("", "", 1);
          }
          return createMockChildProcess("", "", 1);
        });

        const handler = tools.get("certificate_lifecycle")!.handler;
        const result = await handler({ action: "auto_renew_check" });
        expect(result.content[0].text).toContain("Certbot is not installed");
      });
    });

    // ── ca_audit ───────────────────────────────────────────────────────

    describe("ca_audit", () => {
      it("should count CA certificates", async () => {
        mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
          if (command === "ls" && args[0] === "/etc/ssl/certs/") {
            return createMockChildProcess("ca1.pem\nca2.pem\nca3.crt\n", "", 0);
          }
          if (command === "find" && args.includes("-mtime")) {
            return createMockChildProcess("/etc/ssl/certs/ca3.crt\n", "", 0);
          }
          if (command === "find") {
            return createMockChildProcess("/etc/ssl/certs/ca1.pem\n/etc/ssl/certs/ca2.pem\n/etc/ssl/certs/ca3.crt\n", "", 0);
          }
          if (command === "which") {
            return createMockChildProcess("/usr/sbin/update-ca-certificates", "", 0);
          }
          return createMockChildProcess("", "", 1);
        });

        const handler = tools.get("certificate_lifecycle")!.handler;
        const result = await handler({ action: "ca_audit", output_format: "json" });
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.totalCAs).toBe(3);
        expect(parsed.recentlyAddedCount).toBe(1);
        expect(parsed.trustStorePath).toBe("/etc/ssl/certs/");
        expect(parsed.updateCaCertificatesAvailable).toBe(true);
      });

      it("should detect suspicious CA names", async () => {
        mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
          if (command === "ls") {
            return createMockChildProcess("files", "", 0);
          }
          if (command === "find" && args.includes("-mtime")) {
            return createMockChildProcess("", "", 0);
          }
          if (command === "find") {
            return createMockChildProcess(
              "/etc/ssl/certs/legit-ca.pem\n/etc/ssl/certs/test-debug-ca.pem\n/etc/ssl/certs/fake-ca.crt\n",
              "",
              0,
            );
          }
          if (command === "which") {
            return createMockChildProcess("", "", 1);
          }
          return createMockChildProcess("", "", 1);
        });

        const handler = tools.get("certificate_lifecycle")!.handler;
        const result = await handler({ action: "ca_audit", output_format: "json" });
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.suspiciousCount).toBe(2);
        expect(parsed.suspiciousFindings).toContain("/etc/ssl/certs/test-debug-ca.pem");
        expect(parsed.suspiciousFindings).toContain("/etc/ssl/certs/fake-ca.crt");
      });

      it("should fall back to /etc/pki/tls/certs/ if ssl dir missing", async () => {
        mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
          if (command === "ls" && args[0] === "/etc/ssl/certs/") {
            return createMockChildProcess("", "No such file or directory", 2);
          }
          if (command === "ls" && args[0] === "/etc/pki/tls/certs/") {
            return createMockChildProcess("ca-bundle.crt\n", "", 0);
          }
          if (command === "find") {
            return createMockChildProcess("", "", 0);
          }
          if (command === "which") {
            return createMockChildProcess("", "", 1);
          }
          return createMockChildProcess("", "", 1);
        });

        const handler = tools.get("certificate_lifecycle")!.handler;
        const result = await handler({ action: "ca_audit", output_format: "json" });
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.trustStorePath).toBe("/etc/pki/tls/certs/");
      });

      it("should return text format", async () => {
        mockSpawnSafe.mockImplementation((command: string) => {
          if (command === "ls") {
            return createMockChildProcess("certs", "", 0);
          }
          if (command === "find") {
            return createMockChildProcess("", "", 0);
          }
          if (command === "which") {
            return createMockChildProcess("", "", 1);
          }
          return createMockChildProcess("", "", 1);
        });

        const handler = tools.get("certificate_lifecycle")!.handler;
        const result = await handler({ action: "ca_audit" });
        expect(result.content[0].text).toContain("CA Trust Store Audit");
        expect(result.content[0].text).toContain("Trust store path");
      });
    });

    // ── ocsp_check ─────────────────────────────────────────────────────

    describe("ocsp_check", () => {
      it("should require domain or cert_path", async () => {
        const handler = tools.get("certificate_lifecycle")!.handler;
        const result = await handler({ action: "ocsp_check" });
        expect(result.isError).toBe(true);
        expect(result.content[0].text).toContain("domain or cert_path is required");
      });

      it("should check OCSP for a domain", async () => {
        mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
          if (command === "openssl" && args.includes("s_client") && args.includes("-showcerts")) {
            return createMockChildProcess(
              "-----BEGIN CERTIFICATE-----\nMIItest\n-----END CERTIFICATE-----\n",
              "",
              0,
            );
          }
          if (command === "openssl" && args.includes("-ocsp_uri")) {
            return createMockChildProcess("http://ocsp.example.com\n", "", 0);
          }
          if (command === "openssl" && args.includes("-status")) {
            return createMockChildProcess(
              "OCSP Response Status: successful (0x0)\nCert Status: good\n",
              "",
              0,
            );
          }
          return createMockChildProcess("", "", 0);
        });

        const handler = tools.get("certificate_lifecycle")!.handler;
        const result = await handler({ action: "ocsp_check", domain: "example.com", output_format: "json" });
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.domain).toBe("example.com");
        expect(parsed.ocspUri).toBe("http://ocsp.example.com");
        expect(parsed.revocationStatus).toBe("good");
        expect(parsed.ocspStapling).toBe(true);
      });

      it("should detect revoked certificate", async () => {
        mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
          if (command === "openssl" && args.includes("s_client") && args.includes("-showcerts")) {
            return createMockChildProcess(
              "-----BEGIN CERTIFICATE-----\nMIItest\n-----END CERTIFICATE-----\n",
              "",
              0,
            );
          }
          if (command === "openssl" && args.includes("-ocsp_uri")) {
            return createMockChildProcess("http://ocsp.example.com\n", "", 0);
          }
          if (command === "openssl" && args.includes("-status")) {
            return createMockChildProcess(
              "OCSP Response Status: successful (0x0)\nCert Status: revoked\n",
              "",
              0,
            );
          }
          return createMockChildProcess("", "", 0);
        });

        const handler = tools.get("certificate_lifecycle")!.handler;
        const result = await handler({ action: "ocsp_check", domain: "revoked.example.com", output_format: "json" });
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.revocationStatus).toBe("revoked");
      });

      it("should handle no OCSP URI in certificate", async () => {
        mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
          if (command === "openssl" && args.includes("s_client")) {
            return createMockChildProcess(
              "-----BEGIN CERTIFICATE-----\nMIItest\n-----END CERTIFICATE-----\n",
              "",
              0,
            );
          }
          if (command === "openssl" && args.includes("-ocsp_uri")) {
            return createMockChildProcess("", "", 0);
          }
          return createMockChildProcess("", "", 0);
        });

        const handler = tools.get("certificate_lifecycle")!.handler;
        const result = await handler({ action: "ocsp_check", domain: "no-ocsp.example.com", output_format: "json" });
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.status).toBe("no_ocsp_uri");
      });

      it("should handle OCSP responder failure", async () => {
        mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
          if (command === "openssl" && args.includes("s_client") && args.includes("-showcerts")) {
            return createMockChildProcess(
              "-----BEGIN CERTIFICATE-----\nMIItest\n-----END CERTIFICATE-----\n",
              "",
              0,
            );
          }
          if (command === "openssl" && args.includes("-ocsp_uri")) {
            return createMockChildProcess("http://ocsp.fail.com\n", "", 0);
          }
          if (command === "openssl" && args.includes("-status")) {
            return createMockChildProcess("", "connect error", 1);
          }
          return createMockChildProcess("", "", 0);
        });

        const handler = tools.get("certificate_lifecycle")!.handler;
        const result = await handler({ action: "ocsp_check", domain: "fail.example.com", output_format: "json" });
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.ocspStapling).toBe(false);
        expect(parsed.revocationStatus).toBe("unknown");
      });

      it("should return text format for OCSP check", async () => {
        mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
          if (command === "openssl" && args.includes("s_client") && args.includes("-showcerts")) {
            return createMockChildProcess(
              "-----BEGIN CERTIFICATE-----\nMIItest\n-----END CERTIFICATE-----\n",
              "",
              0,
            );
          }
          if (command === "openssl" && args.includes("-ocsp_uri")) {
            return createMockChildProcess("http://ocsp.example.com\n", "", 0);
          }
          if (command === "openssl" && args.includes("-status")) {
            return createMockChildProcess("OCSP Response Status: successful\nCert Status: good\n", "", 0);
          }
          return createMockChildProcess("", "", 0);
        });

        const handler = tools.get("certificate_lifecycle")!.handler;
        const result = await handler({ action: "ocsp_check", domain: "example.com" });
        expect(result.content[0].text).toContain("OCSP Check");
        expect(result.content[0].text).toContain("OCSP Responder");
      });
    });

    // ── ct_log_monitor ─────────────────────────────────────────────────

    describe("ct_log_monitor", () => {
      it("should require domain", async () => {
        const handler = tools.get("certificate_lifecycle")!.handler;
        const result = await handler({ action: "ct_log_monitor" });
        expect(result.isError).toBe(true);
        expect(result.content[0].text).toContain("domain is required");
      });

      it("should query crt.sh and parse results", async () => {
        const ctResponse = JSON.stringify([
          {
            common_name: "example.com",
            issuer_name: "Let's Encrypt Authority X3",
            not_before: "2026-01-01T00:00:00",
            not_after: "2026-04-01T00:00:00",
          },
          {
            common_name: "*.example.com",
            issuer_name: "DigiCert Inc",
            not_before: "2026-03-01T00:00:00",
            not_after: "2027-03-01T00:00:00",
          },
        ]);

        mockSpawnSafe.mockImplementation((command: string) => {
          if (command === "curl") {
            return createMockChildProcess(ctResponse, "", 0);
          }
          return createMockChildProcess("", "", 0);
        });

        const handler = tools.get("certificate_lifecycle")!.handler;
        const result = await handler({ action: "ct_log_monitor", domain: "example.com", output_format: "json" });
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.totalCerts).toBe(2);
        expect(parsed.issuers.length).toBe(2);
        expect(parsed.wildcardCount).toBe(1);
        expect(parsed.unexpectedFindings.length).toBeGreaterThan(0);
      });

      it("should flag unexpected issuers when many found", async () => {
        const ctResponse = JSON.stringify([
          { common_name: "example.com", issuer_name: "CA1", not_before: "2025-01-01T00:00:00" },
          { common_name: "example.com", issuer_name: "CA2", not_before: "2025-02-01T00:00:00" },
          { common_name: "example.com", issuer_name: "CA3", not_before: "2025-03-01T00:00:00" },
          { common_name: "example.com", issuer_name: "CA4", not_before: "2025-04-01T00:00:00" },
        ]);

        mockSpawnSafe.mockImplementation((command: string) => {
          if (command === "curl") {
            return createMockChildProcess(ctResponse, "", 0);
          }
          return createMockChildProcess("", "", 0);
        });

        const handler = tools.get("certificate_lifecycle")!.handler;
        const result = await handler({ action: "ct_log_monitor", domain: "example.com", output_format: "json" });
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.issuers.length).toBe(4);
        expect(parsed.unexpectedFindings.some((f: string) => f.includes("Multiple issuers"))).toBe(true);
      });

      it("should handle crt.sh query failure", async () => {
        mockSpawnSafe.mockImplementation((command: string) => {
          if (command === "curl") {
            return createMockChildProcess("", "Connection refused", 7);
          }
          return createMockChildProcess("", "", 0);
        });

        const handler = tools.get("certificate_lifecycle")!.handler;
        const result = await handler({ action: "ct_log_monitor", domain: "fail.example.com", output_format: "json" });
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.error).toBe("Failed to query crt.sh");
      });

      it("should handle invalid JSON from crt.sh", async () => {
        mockSpawnSafe.mockImplementation((command: string) => {
          if (command === "curl") {
            return createMockChildProcess("not valid json{{{", "", 0);
          }
          return createMockChildProcess("", "", 0);
        });

        const handler = tools.get("certificate_lifecycle")!.handler;
        const result = await handler({ action: "ct_log_monitor", domain: "example.com", output_format: "json" });
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.error).toBe("Failed to parse crt.sh response");
      });

      it("should return text format", async () => {
        const ctResponse = JSON.stringify([
          {
            common_name: "example.com",
            issuer_name: "Let's Encrypt",
            not_before: "2025-01-01T00:00:00",
            not_after: "2025-04-01T00:00:00",
          },
        ]);

        mockSpawnSafe.mockImplementation((command: string) => {
          if (command === "curl") {
            return createMockChildProcess(ctResponse, "", 0);
          }
          return createMockChildProcess("", "", 0);
        });

        const handler = tools.get("certificate_lifecycle")!.handler;
        const result = await handler({ action: "ct_log_monitor", domain: "example.com" });
        expect(result.content[0].text).toContain("CT Log Monitor");
        expect(result.content[0].text).toContain("example.com");
      });
    });

    // ── Error handling ─────────────────────────────────────────────────

    describe("error handling", () => {
      it("should handle spawnSafe throwing in inventory", async () => {
        mockSpawnSafe.mockImplementation(() => {
          throw new Error("spawn failed");
        });

        const handler = tools.get("certificate_lifecycle")!.handler;
        const result = await handler({ action: "inventory" });
        // runCertCommand catches spawn errors, so this should return results
        expect(result.content).toBeDefined();
      });

      it("should handle spawnSafe throwing in auto_renew_check", async () => {
        mockSpawnSafe.mockImplementation(() => {
          throw new Error("spawn failed");
        });

        const handler = tools.get("certificate_lifecycle")!.handler;
        const result = await handler({ action: "auto_renew_check" });
        expect(result.content).toBeDefined();
      });

      it("should handle spawnSafe throwing in ca_audit", async () => {
        mockSpawnSafe.mockImplementation(() => {
          throw new Error("spawn failed");
        });

        const handler = tools.get("certificate_lifecycle")!.handler;
        const result = await handler({ action: "ca_audit" });
        expect(result.content).toBeDefined();
      });

      it("should handle spawnSafe throwing in ocsp_check", async () => {
        mockSpawnSafe.mockImplementation(() => {
          throw new Error("spawn failed");
        });

        const handler = tools.get("certificate_lifecycle")!.handler;
        const result = await handler({ action: "ocsp_check", domain: "test.com" });
        expect(result.content).toBeDefined();
      });

      it("should handle spawnSafe throwing in ct_log_monitor", async () => {
        mockSpawnSafe.mockImplementation(() => {
          throw new Error("spawn failed");
        });

        const handler = tools.get("certificate_lifecycle")!.handler;
        const result = await handler({ action: "ct_log_monitor", domain: "test.com" });
        expect(result.content).toBeDefined();
      });
    });

    // ── JSON output format ─────────────────────────────────────────────

    describe("json output format", () => {
      it("should return valid JSON for inventory", async () => {
        mockSpawnSafe.mockImplementation(() => {
          return createMockChildProcess("", "", 1);
        });

        const handler = tools.get("certificate_lifecycle")!.handler;
        const result = await handler({ action: "inventory", output_format: "json" });
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.action).toBe("inventory");
      });

      it("should return valid JSON for auto_renew_check", async () => {
        mockSpawnSafe.mockImplementation(() => {
          return createMockChildProcess("", "", 1);
        });

        const handler = tools.get("certificate_lifecycle")!.handler;
        const result = await handler({ action: "auto_renew_check", output_format: "json" });
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.action).toBe("auto_renew_check");
      });

      it("should return valid JSON for ca_audit", async () => {
        mockSpawnSafe.mockImplementation((command: string) => {
          if (command === "ls") {
            return createMockChildProcess("certs", "", 0);
          }
          return createMockChildProcess("", "", 1);
        });

        const handler = tools.get("certificate_lifecycle")!.handler;
        const result = await handler({ action: "ca_audit", output_format: "json" });
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.action).toBe("ca_audit");
      });
    });
  });
});
