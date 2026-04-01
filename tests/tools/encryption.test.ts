/**
 * Tests for src/tools/encryption.ts
 *
 * Covers: TOOL-023 algorithm validation, key path validation, path traversal
 * rejection, tool registration, and action routing.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import type { ChildProcess } from "node:child_process";

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

  it("should register 1 crypto tool", () => {
    expect(tools.has("crypto")).toBe(true);
    expect(tools.size).toBe(1);
  });

  // ── tls_remote_audit ──────────────────────────────────────────────────

  it("should require host for tls_remote_audit action", async () => {
    const handler = tools.get("crypto")!.handler;
    const result = await handler({ action: "tls_remote_audit", port: 443, check_ciphers: true, check_protocols: true, check_certificate: true });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("host is required");
  });

  it("should require cert_path or host for tls_cert_expiry", async () => {
    const handler = tools.get("crypto")!.handler;
    const result = await handler({ action: "tls_cert_expiry", port: 443, warn_days: 30 });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Must specify");
  });

  // ── gpg actions ───────────────────────────────────────────────────────

  it("should require key_id for gpg_export action", async () => {
    const handler = tools.get("crypto")!.handler;
    const result = await handler({ action: "gpg_export" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("key_id is required");
  });

  it("should require file_path for gpg_import action", async () => {
    const handler = tools.get("crypto")!.handler;
    const result = await handler({ action: "gpg_import" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("file_path is required");
  });

  it("should reject gpg_import path with traversal (TOOL-023)", async () => {
    const handler = tools.get("crypto")!.handler;
    const result = await handler({ action: "gpg_import", file_path: "/tmp/../../../etc/shadow" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("traversal");
  });

  // ── luks actions ──────────────────────────────────────────────────────

  it("should require name for luks_status action", async () => {
    const handler = tools.get("crypto")!.handler;
    const result = await handler({ action: "luks_status" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("name");
  });

  it("should require device for luks_dump action", async () => {
    const handler = tools.get("crypto")!.handler;
    const result = await handler({ action: "luks_dump" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("device");
  });

  it("should reject LUKS device path with traversal", async () => {
    const handler = tools.get("crypto")!.handler;
    const result = await handler({ action: "luks_dump", device: "/dev/../etc/shadow" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("traversal");
  });

  // ── file_hash ──────────────────────────────────────────────────────────

  it("should reject file_hash path with traversal", async () => {
    const handler = tools.get("crypto")!.handler;
    const result = await handler({ action: "file_hash", path: "/etc/../../../etc/shadow", algorithm: "sha256", recursive: false });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("traversal");
  });

  // ── cert_* actions ─────────────────────────────────────────────────────

  /**
   * Create a mock ChildProcess that emits provided stdout/stderr and close code.
   */
  function createMockChildProcess(
    stdout: string,
    stderr: string,
    exitCode: number,
  ): ChildProcess {
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

    return cp as unknown as ChildProcess;
  }

  describe("cert_inventory", () => {
    it("should be registered as a tool", () => {
      expect(tools.has("crypto")).toBe(true);
    });

    it("should report error for unknown action", async () => {
      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "nonexistent" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Unknown action");
    });

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

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "cert_inventory", output_format: "json" });
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

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "cert_inventory", output_format: "json" });
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

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "cert_inventory" });
      expect(result.content[0].text).toContain("Certificate Inventory");
      expect(result.content[0].text).toContain("Valid:");
    });

    it("should handle no certificates found", async () => {
      mockSpawnSafe.mockImplementation(() => {
        return createMockChildProcess("", "", 1);
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "cert_inventory", output_format: "json" });
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

      const handler = tools.get("crypto")!.handler;
      await handler({ action: "cert_inventory", search_paths: ["/custom/certs/"], output_format: "json" });
      expect(calledPaths).toContain("/custom/certs/");
    });

    it("should reject search paths with traversal", async () => {
      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "cert_inventory", search_paths: ["/etc/../../../tmp"] });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("traversal");
    });
  });

  describe("cert_auto_renew_check", () => {
    it("should report when certbot is not installed", async () => {
      mockSpawnSafe.mockImplementation((command: string) => {
        if (command === "which") {
          return createMockChildProcess("", "not found", 1);
        }
        return createMockChildProcess("", "", 1);
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "cert_auto_renew_check", output_format: "json" });
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

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "cert_auto_renew_check", output_format: "json" });
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

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "cert_auto_renew_check", output_format: "json" });
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

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "cert_auto_renew_check" });
      expect(result.content[0].text).toContain("Certbot is not installed");
    });
  });

  describe("cert_ca_audit", () => {
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

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "cert_ca_audit", output_format: "json" });
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

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "cert_ca_audit", output_format: "json" });
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

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "cert_ca_audit", output_format: "json" });
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

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "cert_ca_audit" });
      expect(result.content[0].text).toContain("CA Trust Store Audit");
      expect(result.content[0].text).toContain("Trust store path");
    });
  });

  describe("cert_ocsp_check", () => {
    it("should require domain or cert_path", async () => {
      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "cert_ocsp_check" });
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

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "cert_ocsp_check", domain: "example.com", output_format: "json" });
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

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "cert_ocsp_check", domain: "revoked.example.com", output_format: "json" });
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

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "cert_ocsp_check", domain: "no-ocsp.example.com", output_format: "json" });
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

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "cert_ocsp_check", domain: "fail.example.com", output_format: "json" });
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

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "cert_ocsp_check", domain: "example.com" });
      expect(result.content[0].text).toContain("OCSP Check");
      expect(result.content[0].text).toContain("OCSP Responder");
    });
  });

  describe("cert_ct_log_monitor", () => {
    it("should require domain", async () => {
      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "cert_ct_log_monitor" });
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

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "cert_ct_log_monitor", domain: "example.com", output_format: "json" });
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

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "cert_ct_log_monitor", domain: "example.com", output_format: "json" });
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

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "cert_ct_log_monitor", domain: "fail.example.com", output_format: "json" });
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

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "cert_ct_log_monitor", domain: "example.com", output_format: "json" });
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

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "cert_ct_log_monitor", domain: "example.com" });
      expect(result.content[0].text).toContain("CT Log Monitor");
      expect(result.content[0].text).toContain("example.com");
    });
  });

  // ── Error handling ─────────────────────────────────────────────────

  describe("error handling", () => {
    it("should handle spawnSafe throwing in cert_inventory", async () => {
      mockSpawnSafe.mockImplementation(() => {
        throw new Error("spawn failed");
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "cert_inventory" });
      // runCertCommand catches spawn errors, so this should return results
      expect(result.content).toBeDefined();
    });

    it("should handle spawnSafe throwing in cert_auto_renew_check", async () => {
      mockSpawnSafe.mockImplementation(() => {
        throw new Error("spawn failed");
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "cert_auto_renew_check" });
      expect(result.content).toBeDefined();
    });

    it("should handle spawnSafe throwing in cert_ca_audit", async () => {
      mockSpawnSafe.mockImplementation(() => {
        throw new Error("spawn failed");
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "cert_ca_audit" });
      expect(result.content).toBeDefined();
    });

    it("should handle spawnSafe throwing in cert_ocsp_check", async () => {
      mockSpawnSafe.mockImplementation(() => {
        throw new Error("spawn failed");
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "cert_ocsp_check", domain: "test.com" });
      expect(result.content).toBeDefined();
    });

    it("should handle spawnSafe throwing in cert_ct_log_monitor", async () => {
      mockSpawnSafe.mockImplementation(() => {
        throw new Error("spawn failed");
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "cert_ct_log_monitor", domain: "test.com" });
      expect(result.content).toBeDefined();
    });
  });

  // ── JSON output format ─────────────────────────────────────────────

  describe("json output format", () => {
    it("should return valid JSON for cert_inventory", async () => {
      mockSpawnSafe.mockImplementation(() => {
        return createMockChildProcess("", "", 1);
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "cert_inventory", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("inventory");
    });

    it("should return valid JSON for cert_auto_renew_check", async () => {
      mockSpawnSafe.mockImplementation(() => {
        return createMockChildProcess("", "", 1);
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "cert_auto_renew_check", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("auto_renew_check");
    });

    it("should return valid JSON for cert_ca_audit", async () => {
      mockSpawnSafe.mockImplementation((command: string) => {
        if (command === "ls") {
          return createMockChildProcess("certs", "", 0);
        }
        return createMockChildProcess("", "", 1);
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "cert_ca_audit", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("ca_audit");
    });
  });

  // ── tls_remote_audit success paths ────────────────────────────────────

  describe("tls_remote_audit", () => {
    it("should perform TLS audit and report connection info", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const mockExec = vi.mocked(executeCommand);
      // First call: brief connection test
      mockExec.mockResolvedValueOnce({
        exitCode: 0,
        stdout: "Protocol  : TLSv1.3\nCipher    : TLS_AES_256_GCM_SHA384",
        stderr: "",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });
      // Second call: detailed connection
      mockExec.mockResolvedValueOnce({
        exitCode: 0,
        stdout: "subject=CN = example.com\nissuer=CN = Let's Encrypt\nNot Before: Jan  1 00:00:00 2024 GMT\nNot After : Dec 31 23:59:59 2030 GMT\nVerify return code: 0 (ok)",
        stderr: "",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });
      // Protocol test calls (TLSv1, TLSv1.1, TLSv1.2)
      mockExec.mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "no protocols available", timedOut: false, duration: 10, permissionDenied: false });
      mockExec.mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "no protocols available", timedOut: false, duration: 10, permissionDenied: false });
      mockExec.mockResolvedValueOnce({ exitCode: 0, stdout: "Protocol  : TLSv1.2", stderr: "", timedOut: false, duration: 10, permissionDenied: false });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "tls_remote_audit", host: "example.com", port: 443, check_ciphers: true, check_protocols: true, check_certificate: true });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("TLS/SSL Audit");
      expect(result.content[0].text).toContain("Protocol: TLSv1.3");
      expect(result.content[0].text).toContain("example.com");
    });

    it("should report connection failure", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const mockExec = vi.mocked(executeCommand);
      mockExec.mockResolvedValueOnce({
        exitCode: 1,
        stdout: "",
        stderr: "Connection refused",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "tls_remote_audit", host: "fail.example.com", port: 443, check_ciphers: false, check_protocols: false, check_certificate: false });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Failed to connect");
    });

    it("should detect weak ciphers in audit", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const mockExec = vi.mocked(executeCommand);
      mockExec.mockResolvedValueOnce({
        exitCode: 0,
        stdout: "Protocol  : TLSv1.2\nCipher    : RC4-SHA",
        stderr: "",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });
      mockExec.mockResolvedValueOnce({
        exitCode: 0,
        stdout: "subject=CN = test.com\nRC4-SHA cipher used\nVerify return code: 0 (ok)",
        stderr: "",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "tls_remote_audit", host: "test.com", port: 443, check_ciphers: true, check_protocols: false, check_certificate: false });
      expect(result.content[0].text).toContain("Weak ciphers detected");
      expect(result.content[0].text).toContain("RC4");
    });

    it("should detect self-signed certificate", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const mockExec = vi.mocked(executeCommand);
      mockExec.mockResolvedValueOnce({
        exitCode: 0,
        stdout: "Protocol  : TLSv1.3",
        stderr: "",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });
      mockExec.mockResolvedValueOnce({
        exitCode: 0,
        stdout: "subject=CN = localhost\nself signed certificate\nVerify return code: 18 (self signed certificate)",
        stderr: "",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "tls_remote_audit", host: "localhost", port: 443, check_ciphers: false, check_protocols: false, check_certificate: true });
      expect(result.content[0].text).toContain("Self-signed certificate");
      expect(result.content[0].text).toContain("Verification FAILED");
    });
  });

  // ── tls_cert_expiry success paths ─────────────────────────────────────

  describe("tls_cert_expiry", () => {
    it("should check local certificate expiry", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const mockExec = vi.mocked(executeCommand);
      mockExec.mockResolvedValueOnce({
        exitCode: 0,
        stdout: "notAfter=Dec 31 23:59:59 2030 GMT\nsubject=CN = test.com\nissuer=CN = Test CA",
        stderr: "",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "tls_cert_expiry", cert_path: "/etc/ssl/certs/test.pem", port: 443, warn_days: 30 });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("Certificate Expiry Check");
      expect(result.content[0].text).toContain("OK");
    });

    it("should check remote host certificate expiry", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const mockExec = vi.mocked(executeCommand);
      mockExec.mockResolvedValueOnce({
        exitCode: 0,
        stdout: "subject=CN = example.com\nissuer=CN = Let's Encrypt\nNot After : Dec 31 23:59:59 2030 GMT",
        stderr: "",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "tls_cert_expiry", host: "example.com", port: 443, warn_days: 30 });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("OK");
    });

    it("should warn for expiring certificate", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const mockExec = vi.mocked(executeCommand);
      const soon = new Date();
      soon.setDate(soon.getDate() + 10);
      mockExec.mockResolvedValueOnce({
        exitCode: 0,
        stdout: `notAfter=${soon.toUTCString()}\nsubject=CN = expiring.com\nissuer=CN = CA`,
        stderr: "",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "tls_cert_expiry", cert_path: "/etc/ssl/certs/expiring.pem", port: 443, warn_days: 30 });
      expect(result.content[0].text).toContain("WARNING");
    });

    it("should report expired certificate", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const mockExec = vi.mocked(executeCommand);
      mockExec.mockResolvedValueOnce({
        exitCode: 0,
        stdout: "notAfter=Jan  1 00:00:00 2020 GMT\nsubject=CN = old.com\nissuer=CN = CA",
        stderr: "",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "tls_cert_expiry", cert_path: "/etc/ssl/certs/old.pem", port: 443, warn_days: 30 });
      expect(result.content[0].text).toContain("CRITICAL");
      expect(result.content[0].text).toContain("EXPIRED");
    });

    it("should report error when cert read fails", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const mockExec = vi.mocked(executeCommand);
      mockExec.mockResolvedValueOnce({
        exitCode: 1,
        stdout: "",
        stderr: "unable to load certificate",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "tls_cert_expiry", cert_path: "/etc/ssl/certs/bad.pem", port: 443, warn_days: 30 });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Failed to read certificate");
    });
  });

  // ── tls_config_audit ──────────────────────────────────────────────────

  describe("tls_config_audit", () => {
    it("should audit apache TLS config with weak protocols", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const mockExec = vi.mocked(executeCommand);
      // find apache config files
      mockExec.mockResolvedValueOnce({
        exitCode: 0,
        stdout: "/etc/apache2/sites-enabled/default-ssl.conf",
        stderr: "",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });
      // cat apache config
      mockExec.mockResolvedValueOnce({
        exitCode: 0,
        stdout: "SSLProtocol all -SSLv2 +TLSv1.0\nSSLCipherSuite HIGH:!aNULL:!MD5",
        stderr: "",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "tls_config_audit", service: "apache", port: 443 });
      expect(result.content[0].text).toContain("Apache TLS Configuration");
      expect(result.content[0].text).toContain("Critical");
    });

    it("should audit nginx TLS config", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const mockExec = vi.mocked(executeCommand);
      // find nginx config files
      mockExec.mockResolvedValueOnce({
        exitCode: 0,
        stdout: "/etc/nginx/conf.d/ssl.conf",
        stderr: "",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });
      // cat nginx config
      mockExec.mockResolvedValueOnce({
        exitCode: 0,
        stdout: "ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384';",
        stderr: "",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "tls_config_audit", service: "nginx", port: 443 });
      expect(result.content[0].text).toContain("Nginx TLS Configuration");
      expect(result.content[0].text).toContain("ssl_protocols");
    });

    it("should audit system crypto config", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const mockExec = vi.mocked(executeCommand);
      // cat openssl.cnf
      mockExec.mockResolvedValueOnce({
        exitCode: 0,
        stdout: "MinProtocol = TLSv1.2\nCipherString = DEFAULT@SECLEVEL=2",
        stderr: "",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });
      // cat crypto-policies
      mockExec.mockResolvedValueOnce({
        exitCode: 0,
        stdout: "LEGACY",
        stderr: "",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });
      // openssl version
      mockExec.mockResolvedValueOnce({
        exitCode: 0,
        stdout: "OpenSSL 3.0.2 15 Mar 2022",
        stderr: "",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "tls_config_audit", service: "system", port: 443 });
      expect(result.content[0].text).toContain("System-Wide Crypto Configuration");
      expect(result.content[0].text).toContain("MinProtocol: TLSv1.2");
      expect(result.content[0].text).toContain("LEGACY");
      expect(result.content[0].text).toContain("OpenSSL 3.0.2");
    });

    it("should report no issues when config is clean", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const mockExec = vi.mocked(executeCommand);
      // apache not found
      mockExec.mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "not found", timedOut: false, duration: 10, permissionDenied: false });
      // nginx not found
      mockExec.mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "not found", timedOut: false, duration: 10, permissionDenied: false });
      // openssl.cnf not found
      mockExec.mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "not found", timedOut: false, duration: 10, permissionDenied: false });
      // crypto-policies not found
      mockExec.mockResolvedValueOnce({ exitCode: 1, stdout: "", stderr: "", timedOut: false, duration: 10, permissionDenied: false });
      // openssl version
      mockExec.mockResolvedValueOnce({ exitCode: 0, stdout: "OpenSSL 3.0.2", stderr: "", timedOut: false, duration: 10, permissionDenied: false });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "tls_config_audit", service: "all", port: 443 });
      expect(result.content[0].text).toContain("No critical TLS configuration issues found");
    });
  });

  // ── gpg_list ──────────────────────────────────────────────────────────

  describe("gpg_list", () => {
    it("should list GPG keys", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const mockExec = vi.mocked(executeCommand);
      mockExec.mockResolvedValueOnce({
        exitCode: 0,
        stdout: "pub   rsa4096/ABCDEF1234567890 2024-01-01\nuid           Test User <test@example.com>",
        stderr: "",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });
      mockExec.mockResolvedValueOnce({
        exitCode: 0,
        stdout: "sec   rsa4096/ABCDEF1234567890 2024-01-01",
        stderr: "",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "gpg_list" });
      expect(result.content[0].text).toContain("GPG Key Management: list");
      expect(result.content[0].text).toContain("Public Keys");
      expect(result.content[0].text).toContain("Secret Keys");
      expect(result.content[0].text).toContain("ABCDEF1234567890");
    });

    it("should handle no GPG keys found", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const mockExec = vi.mocked(executeCommand);
      mockExec.mockResolvedValueOnce({
        exitCode: 2,
        stdout: "",
        stderr: "gpg: no keys found",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });
      mockExec.mockResolvedValueOnce({
        exitCode: 0,
        stdout: "",
        stderr: "",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "gpg_list" });
      expect(result.content[0].text).toContain("No GPG keys found");
    });
  });

  // ── gpg_generate ──────────────────────────────────────────────────────

  describe("gpg_generate", () => {
    it("should show dry run output for key generation", async () => {
      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "gpg_generate", dry_run: true });
      expect(result.content[0].text).toContain("DRY RUN");
      expect(result.content[0].text).toContain("gpg --full-generate-key");
      expect(result.content[0].text).toContain("Key-Type: RSA");
    });

    it("should warn about interactive mode when not dry run", async () => {
      const { getConfig } = await import("../../src/core/config.js");
      vi.mocked(getConfig).mockReturnValue({ dryRun: false } as ReturnType<typeof getConfig>);

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "gpg_generate", dry_run: false });
      expect(result.content[0].text).toContain("Interactive GPG key generation cannot be run");
    });
  });

  // ── gpg_export ────────────────────────────────────────────────────────

  describe("gpg_export success", () => {
    it("should export a GPG key", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const mockExec = vi.mocked(executeCommand);
      mockExec.mockResolvedValueOnce({
        exitCode: 0,
        stdout: "-----BEGIN PGP PUBLIC KEY BLOCK-----\nmQINBF...\n-----END PGP PUBLIC KEY BLOCK-----",
        stderr: "",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "gpg_export", key_id: "ABCDEF1234567890" });
      expect(result.content[0].text).toContain("Exported public key for: ABCDEF1234567890");
      expect(result.content[0].text).toContain("BEGIN PGP PUBLIC KEY BLOCK");
    });

    it("should report error when export fails", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const mockExec = vi.mocked(executeCommand);
      mockExec.mockResolvedValueOnce({
        exitCode: 1,
        stdout: "",
        stderr: "gpg: key not found",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "gpg_export", key_id: "NONEXISTENT" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Failed to export key");
    });
  });

  // ── gpg_import success paths ──────────────────────────────────────────

  describe("gpg_import success", () => {
    it("should show dry run for import", async () => {
      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "gpg_import", file_path: "/tmp/key.asc", dry_run: true });
      expect(result.content[0].text).toContain("DRY RUN");
      expect(result.content[0].text).toContain("/tmp/key.asc");
    });

    it("should import a GPG key when not dry run", async () => {
      const { getConfig } = await import("../../src/core/config.js");
      vi.mocked(getConfig).mockReturnValue({ dryRun: false } as ReturnType<typeof getConfig>);

      const { executeCommand } = await import("../../src/core/executor.js");
      const mockExec = vi.mocked(executeCommand);
      mockExec.mockResolvedValueOnce({
        exitCode: 0,
        stdout: "",
        stderr: "gpg: key ABCDEF: public key imported\ngpg: Total number processed: 1",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "gpg_import", file_path: "/tmp/key.asc", dry_run: false });
      expect(result.content[0].text).toContain("Key imported from: /tmp/key.asc");
    });
  });

  // ── gpg_verify ────────────────────────────────────────────────────────

  describe("gpg_verify", () => {
    it("should require file_path", async () => {
      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "gpg_verify" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("file_path is required");
    });

    it("should verify a valid GPG signature", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const mockExec = vi.mocked(executeCommand);
      mockExec.mockResolvedValueOnce({
        exitCode: 0,
        stdout: "",
        stderr: 'gpg: Good signature from "Test User <test@example.com>"',
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "gpg_verify", file_path: "/tmp/file.sig" });
      expect(result.content[0].text).toContain("Signature verification PASSED");
    });

    it("should report failed GPG signature verification", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const mockExec = vi.mocked(executeCommand);
      mockExec.mockResolvedValueOnce({
        exitCode: 1,
        stdout: "",
        stderr: "gpg: BAD signature",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "gpg_verify", file_path: "/tmp/file.sig" });
      expect(result.content[0].text).toContain("Signature verification FAILED");
    });

    it("should reject verify path with traversal", async () => {
      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "gpg_verify", file_path: "/tmp/../../../etc/shadow" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("traversal");
    });
  });

  // ── luks_status success path ──────────────────────────────────────────

  describe("luks_status success", () => {
    it("should show status for an active LUKS volume", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const mockExec = vi.mocked(executeCommand);
      mockExec.mockResolvedValueOnce({
        exitCode: 0,
        stdout: "/dev/mapper/cryptvol is active.\n  type: LUKS2\n  cipher: aes-xts-plain64",
        stderr: "",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "luks_status", name: "cryptvol" });
      expect(result.content[0].text).toContain("Status for /dev/mapper/cryptvol");
      expect(result.content[0].text).toContain("aes-xts-plain64");
    });

    it("should report inactive LUKS volume", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const mockExec = vi.mocked(executeCommand);
      mockExec.mockResolvedValueOnce({
        exitCode: 4,
        stdout: "",
        stderr: "Device cryptvol is not active.",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "luks_status", name: "cryptvol" });
      expect(result.content[0].text).toContain("not found or not active");
    });
  });

  // ── luks_dump success path ────────────────────────────────────────────

  describe("luks_dump success", () => {
    it("should dump LUKS header info", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const mockExec = vi.mocked(executeCommand);
      mockExec.mockResolvedValueOnce({
        exitCode: 0,
        stdout: "LUKS header information\nVersion: 2\nCipher name: aes\nCipher mode: xts-plain64\nKey Slots: 8",
        stderr: "",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "luks_dump", device: "/dev/sda2" });
      expect(result.content[0].text).toContain("LUKS Header Dump for /dev/sda2");
      expect(result.content[0].text).toContain("Version: 2");
    });

    it("should report error on dump failure", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const mockExec = vi.mocked(executeCommand);
      mockExec.mockResolvedValueOnce({
        exitCode: 1,
        stdout: "",
        stderr: "Device does not exist",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "luks_dump", device: "/dev/sda99" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Failed to dump LUKS header");
    });
  });

  // ── luks_open ─────────────────────────────────────────────────────────

  describe("luks_open", () => {
    it("should require both device and name", async () => {
      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "luks_open", device: "/dev/sda2" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Both device and name are required");
    });

    it("should show dry run output", async () => {
      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "luks_open", device: "/dev/sda2", name: "cryptvol", dry_run: true });
      expect(result.content[0].text).toContain("DRY RUN");
      expect(result.content[0].text).toContain("/dev/sda2");
      expect(result.content[0].text).toContain("cryptvol");
    });

    it("should reject device path with traversal", async () => {
      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "luks_open", device: "/dev/../etc/shadow", name: "test" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("traversal");
    });

    it("should warn about interactive passphrase when not dry run", async () => {
      const { getConfig } = await import("../../src/core/config.js");
      vi.mocked(getConfig).mockReturnValue({ dryRun: false } as ReturnType<typeof getConfig>);

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "luks_open", device: "/dev/sda2", name: "cryptvol", dry_run: false });
      expect(result.content[0].text).toContain("Interactive LUKS open requires a passphrase");
    });
  });

  // ── luks_close ────────────────────────────────────────────────────────

  describe("luks_close", () => {
    it("should require name", async () => {
      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "luks_close" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("name");
    });

    it("should show dry run output for close", async () => {
      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "luks_close", name: "cryptvol", dry_run: true });
      expect(result.content[0].text).toContain("DRY RUN");
      expect(result.content[0].text).toContain("/dev/mapper/cryptvol");
    });

    it("should close LUKS volume when not dry run", async () => {
      const { getConfig } = await import("../../src/core/config.js");
      vi.mocked(getConfig).mockReturnValue({ dryRun: false } as ReturnType<typeof getConfig>);

      const { executeCommand } = await import("../../src/core/executor.js");
      const mockExec = vi.mocked(executeCommand);
      mockExec.mockResolvedValueOnce({
        exitCode: 0,
        stdout: "",
        stderr: "",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "luks_close", name: "cryptvol", dry_run: false });
      expect(result.content[0].text).toContain("closed successfully");
    });

    it("should report error when close fails", async () => {
      const { getConfig } = await import("../../src/core/config.js");
      vi.mocked(getConfig).mockReturnValue({ dryRun: false } as ReturnType<typeof getConfig>);

      const { executeCommand } = await import("../../src/core/executor.js");
      const mockExec = vi.mocked(executeCommand);
      mockExec.mockResolvedValueOnce({
        exitCode: 1,
        stdout: "",
        stderr: "Device is busy",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "luks_close", name: "cryptvol", dry_run: false });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Failed to close LUKS volume");
    });
  });

  // ── luks_list ─────────────────────────────────────────────────────────

  describe("luks_list", () => {
    it("should list LUKS volumes and detect encrypted devices", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const mockExec = vi.mocked(executeCommand);
      mockExec.mockResolvedValueOnce({
        exitCode: 0,
        stdout: "control\ncryptvol -> ../dm-0",
        stderr: "",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });
      mockExec.mockResolvedValueOnce({
        exitCode: 0,
        stdout: "NAME      FSTYPE      SIZE MOUNTPOINT UUID\nsda1      ext4       50G  /          abc-123\nsda2      crypto_LUKS 100G             def-456",
        stderr: "",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "luks_list" });
      expect(result.content[0].text).toContain("Device Mapper Entries");
      expect(result.content[0].text).toContain("LUKS Encrypted Devices");
      expect(result.content[0].text).toContain("crypto_LUKS");
    });

    it("should report no LUKS devices when none found", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const mockExec = vi.mocked(executeCommand);
      mockExec.mockResolvedValueOnce({
        exitCode: 0,
        stdout: "control",
        stderr: "",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });
      mockExec.mockResolvedValueOnce({
        exitCode: 0,
        stdout: "NAME FSTYPE SIZE MOUNTPOINT UUID\nsda1 ext4   50G  /          abc-123",
        stderr: "",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "luks_list" });
      expect(result.content[0].text).toContain("No LUKS encrypted devices detected");
    });
  });

  // ── file_hash ─────────────────────────────────────────────────────────

  describe("file_hash", () => {
    it("should require path parameter", async () => {
      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "file_hash", algorithm: "sha256", recursive: false });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("path is required");
    });

    it("should hash a single file", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const mockExec = vi.mocked(executeCommand);
      mockExec.mockResolvedValueOnce({
        exitCode: 0,
        stdout: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  /etc/passwd",
        stderr: "",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "file_hash", path: "/etc/passwd", algorithm: "sha256", recursive: false });
      expect(result.content[0].text).toContain("File Integrity Hash");
      expect(result.content[0].text).toContain("SHA256");
      expect(result.content[0].text).toContain("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    });

    it("should hash files recursively", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const mockExec = vi.mocked(executeCommand);
      mockExec.mockResolvedValueOnce({
        exitCode: 0,
        stdout: "abc123  /etc/ssl/file1.pem\ndef456  /etc/ssl/file2.pem",
        stderr: "",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "file_hash", path: "/etc/ssl", algorithm: "sha512", recursive: true });
      expect(result.content[0].text).toContain("Directory: /etc/ssl");
      expect(result.content[0].text).toContain("Files hashed: 2");
    });

    it("should report error when hash command fails", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const mockExec = vi.mocked(executeCommand);
      mockExec.mockResolvedValueOnce({
        exitCode: 1,
        stdout: "",
        stderr: "No such file or directory",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "file_hash", path: "/nonexistent", algorithm: "sha256", recursive: false });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Failed to hash");
    });

    it("should report error when recursive hash fails with no output", async () => {
      const { executeCommand } = await import("../../src/core/executor.js");
      const mockExec = vi.mocked(executeCommand);
      mockExec.mockResolvedValueOnce({
        exitCode: 1,
        stdout: "",
        stderr: "Permission denied",
        timedOut: false,
        duration: 10,
        permissionDenied: false,
      });

      const handler = tools.get("crypto")!.handler;
      const result = await handler({ action: "file_hash", path: "/root/secret", algorithm: "sha256", recursive: true });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Failed to hash files");
    });
  });
});
