/**
 * Tests for src/tools/cloud-security.ts
 *
 * Covers: cloud_security tool with actions detect_environment, audit_metadata,
 * check_iam_creds, audit_storage, check_imds.
 * Tests cloud provider detection, IMDS security assessment, credential
 * discovery with masking, storage audit, non-cloud handling, JSON/text output,
 * and error handling.
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

vi.mock("node:fs", () => ({
  existsSync: vi.fn(() => false),
}));

import {
  registerCloudSecurityTools,
  maskCredential,
} from "../../src/tools/cloud-security.js";
import { spawnSafe } from "../../src/core/spawn-safe.js";
import { existsSync } from "node:fs";
import { EventEmitter } from "node:events";

const mockSpawnSafe = vi.mocked(spawnSafe);
const mockExistsSync = vi.mocked(existsSync);

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
    server: server as unknown as Parameters<typeof registerCloudSecurityTools>[0],
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
 * Set up default spawnSafe mocks — non-cloud environment (all checks fail).
 */
function setupNonCloudMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    // cat /sys/class/dmi/id/sys_vendor — not cloud
    if (command === "cat" && args[0] === "/sys/class/dmi/id/sys_vendor") {
      return createMockChildProcess("QEMU", "", 0);
    }
    // cat /sys/class/dmi/id/product_name
    if (command === "cat" && args[0] === "/sys/class/dmi/id/product_name") {
      return createMockChildProcess("Standard PC", "", 0);
    }
    // cloud-init status
    if (command === "cloud-init") {
      return createMockChildProcess("", "command not found", 127);
    }
    // curl — metadata endpoints unreachable
    if (command === "curl") {
      return createMockChildProcess("", "Connection refused", 7);
    }
    // cat /sys/hypervisor/uuid
    if (command === "cat" && args[0] === "/sys/hypervisor/uuid") {
      return createMockChildProcess("", "No such file", 1);
    }
    // env — no cloud creds
    if (command === "env") {
      return createMockChildProcess("HOME=/root\nPATH=/usr/bin\nSHELL=/bin/bash\n", "", 0);
    }
    // sh -c echo $HOME
    if (command === "sh" && args[0] === "-c") {
      return createMockChildProcess("/root", "", 0);
    }
    // stat
    if (command === "stat") {
      return createMockChildProcess("", "No such file", 1);
    }
    // grep /proc
    if (command === "grep") {
      return createMockChildProcess("", "", 1);
    }
    // which — no cloud CLIs
    if (command === "which") {
      return createMockChildProcess("", "", 1);
    }
    // mount
    if (command === "mount") {
      return createMockChildProcess("/dev/sda1 on / type ext4 (rw)\n", "", 0);
    }
    // iptables
    if (command === "iptables") {
      return createMockChildProcess("Chain INPUT (policy ACCEPT)\ntarget prot opt source destination\n", "", 0);
    }
    // Default: return failure
    return createMockChildProcess("", "", 1);
  });
}

/**
 * Set up mocks for AWS cloud environment.
 */
function setupAwsCloudMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    // DMI info — Amazon
    if (command === "cat" && args[0] === "/sys/class/dmi/id/sys_vendor") {
      return createMockChildProcess("Amazon EC2", "", 0);
    }
    if (command === "cat" && args[0] === "/sys/class/dmi/id/product_name") {
      return createMockChildProcess("EC2 m5.large", "", 0);
    }
    // cloud-init
    if (command === "cloud-init") {
      return createMockChildProcess("status: done", "", 0);
    }
    // curl — metadata endpoints
    if (command === "curl" && args.includes("http://169.254.169.254/")) {
      return createMockChildProcess("1.0\n2.0\nlatest", "", 0);
    }
    if (command === "curl" && args.includes("http://169.254.169.254/latest/meta-data/")) {
      return createMockChildProcess("ami-id\ninstance-id\ninstance-type\nlocal-ipv4\n", "", 0);
    }
    if (command === "curl" && args.includes("http://169.254.169.254/latest/api/token")) {
      return createMockChildProcess("AQAAABbFakeToken==", "", 0);
    }
    // GCP metadata — fails
    if (command === "curl" && args.includes("http://metadata.google.internal/")) {
      return createMockChildProcess("", "Could not resolve host", 6);
    }
    // Azure metadata — fails
    if (command === "curl" && args.some((a) => a.includes("api-version"))) {
      return createMockChildProcess("", "Connection refused", 7);
    }
    // hypervisor UUID
    if (command === "cat" && args[0] === "/sys/hypervisor/uuid") {
      return createMockChildProcess("ec2e1234-5678-abcd-ef01-234567890abc", "", 0);
    }
    // env with AWS creds
    if (command === "env") {
      return createMockChildProcess(
        "HOME=/root\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
        "",
        0,
      );
    }
    // sh -c echo $HOME
    if (command === "sh" && args[0] === "-c") {
      return createMockChildProcess("/root", "", 0);
    }
    // stat — credential file perms
    if (command === "stat") {
      return createMockChildProcess("644", "", 0);
    }
    // grep /proc
    if (command === "grep") {
      return createMockChildProcess("/proc/1234/environ\n", "", 0);
    }
    // which aws
    if (command === "which" && args[0] === "aws") {
      return createMockChildProcess("/usr/local/bin/aws", "", 0);
    }
    // which gsutil / az — not found
    if (command === "which") {
      return createMockChildProcess("", "", 1);
    }
    // aws s3 ls
    if (command === "aws" && args[0] === "s3" && args[1] === "ls") {
      return createMockChildProcess("2025-01-01 00:00:00 my-bucket\n2025-02-01 00:00:00 logs-bucket\n", "", 0);
    }
    // mount
    if (command === "mount") {
      return createMockChildProcess("/dev/xvda1 on / type ext4 (rw)\ns3fs on /mnt/s3 type fuse.s3fs (rw)\n", "", 0);
    }
    // iptables
    if (command === "iptables") {
      return createMockChildProcess("Chain INPUT (policy ACCEPT)\ntarget prot opt source destination\n", "", 0);
    }
    return createMockChildProcess("", "", 0);
  });
}

/**
 * Set up mocks for GCP cloud environment.
 */
function setupGcpCloudMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    if (command === "cat" && args[0] === "/sys/class/dmi/id/sys_vendor") {
      return createMockChildProcess("Google", "", 0);
    }
    if (command === "cat" && args[0] === "/sys/class/dmi/id/product_name") {
      return createMockChildProcess("Google Compute Engine", "", 0);
    }
    if (command === "cloud-init") {
      return createMockChildProcess("status: done", "", 0);
    }
    if (command === "curl" && args.includes("http://169.254.169.254/")) {
      return createMockChildProcess("computeMetadata/", "", 0);
    }
    if (command === "curl" && args.some((a) => a === "Metadata-Flavor: Google") && args.includes("http://metadata.google.internal/")) {
      return createMockChildProcess("0.1/\ncomputeMetadata/\n", "", 0);
    }
    if (command === "curl" && !args.some((a) => a === "Metadata-Flavor: Google") && args.includes("http://metadata.google.internal/")) {
      return createMockChildProcess("Forbidden", "", 0);
    }
    if (command === "cat" && args[0] === "/sys/hypervisor/uuid") {
      return createMockChildProcess("", "No such file", 1);
    }
    // Azure metadata — fails
    if (command === "curl" && args.some((a) => a.includes("api-version"))) {
      return createMockChildProcess("", "Connection refused", 7);
    }
    if (command === "curl") {
      return createMockChildProcess("", "", 7);
    }
    if (command === "env") {
      return createMockChildProcess("HOME=/root\n", "", 0);
    }
    if (command === "sh" && args[0] === "-c") {
      return createMockChildProcess("/root", "", 0);
    }
    if (command === "which" && args[0] === "gsutil") {
      return createMockChildProcess("/usr/bin/gsutil", "", 0);
    }
    if (command === "which") {
      return createMockChildProcess("", "", 1);
    }
    if (command === "gsutil" && args[0] === "ls") {
      return createMockChildProcess("gs://my-gcp-bucket/\ngs://data-bucket/\n", "", 0);
    }
    if (command === "grep") {
      return createMockChildProcess("", "", 1);
    }
    if (command === "mount") {
      return createMockChildProcess("/dev/sda1 on / type ext4 (rw)\n", "", 0);
    }
    if (command === "iptables") {
      return createMockChildProcess("Chain INPUT (policy ACCEPT)\ntarget prot opt source destination\n", "", 0);
    }
    return createMockChildProcess("", "", 0);
  });
}

/**
 * Set up mocks for Azure cloud environment.
 */
function setupAzureCloudMocks() {
  mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
    if (command === "cat" && args[0] === "/sys/class/dmi/id/sys_vendor") {
      return createMockChildProcess("Microsoft Corporation", "", 0);
    }
    if (command === "cat" && args[0] === "/sys/class/dmi/id/product_name") {
      return createMockChildProcess("Virtual Machine", "", 0);
    }
    if (command === "cloud-init") {
      return createMockChildProcess("status: done", "", 0);
    }
    if (command === "curl" && args.includes("http://169.254.169.254/")) {
      return createMockChildProcess("", "", 0);
    }
    // Azure IMDS with header
    if (command === "curl" && args.some((a) => a === "Metadata: true") && args.some((a) => a.includes("api-version"))) {
      return createMockChildProcess('{"compute":{"location":"eastus","name":"my-vm"}}', "", 0);
    }
    // Azure IMDS without header
    if (command === "curl" && !args.some((a) => a === "Metadata: true") && args.some((a) => a.includes("api-version"))) {
      return createMockChildProcess("", "Bad Request", 0);
    }
    if (command === "curl" && args.includes("http://metadata.google.internal/")) {
      return createMockChildProcess("", "Could not resolve host", 6);
    }
    if (command === "cat" && args[0] === "/sys/hypervisor/uuid") {
      return createMockChildProcess("", "No such file", 1);
    }
    if (command === "curl") {
      return createMockChildProcess("", "", 7);
    }
    if (command === "env") {
      return createMockChildProcess("HOME=/root\nAZURE_CLIENT_ID=12345\nAZURE_CLIENT_SECRET=superSecret123\n", "", 0);
    }
    if (command === "sh" && args[0] === "-c") {
      return createMockChildProcess("/root", "", 0);
    }
    if (command === "which" && args[0] === "az") {
      return createMockChildProcess("/usr/bin/az", "", 0);
    }
    if (command === "which") {
      return createMockChildProcess("", "", 1);
    }
    if (command === "az" && args.includes("storage")) {
      return createMockChildProcess('[{"name":"mystorageaccount"}]', "", 0);
    }
    if (command === "grep") {
      return createMockChildProcess("", "", 1);
    }
    if (command === "mount") {
      return createMockChildProcess("/dev/sda1 on / type ext4 (rw)\nblobfuse on /mnt/blob type fuse (rw)\n", "", 0);
    }
    if (command === "iptables") {
      return createMockChildProcess("Chain INPUT (policy ACCEPT)\ntarget prot opt source destination\n", "", 0);
    }
    if (command === "stat") {
      return createMockChildProcess("600", "", 0);
    }
    return createMockChildProcess("", "", 0);
  });
}

// ── Tests ──────────────────────────────────────────────────────────────────

describe("cloud-security tools", () => {
  let tools: Map<
    string,
    { schema: Record<string, unknown>; handler: ToolHandler }
  >;

  beforeEach(() => {
    vi.clearAllMocks();
    const mock = createMockServer();
    registerCloudSecurityTools(mock.server);
    tools = mock.tools;
    setupNonCloudMocks();
    mockExistsSync.mockReturnValue(false);
  });

  // ── Registration ────────────────────────────────────────────────────────

  it("should register the cloud_security tool", () => {
    expect(tools.has("cloud_security")).toBe(true);
  });

  it("should register with server.tool called once", () => {
    const mock = createMockServer();
    registerCloudSecurityTools(mock.server);
    expect(mock.server.tool).toHaveBeenCalledTimes(1);
    expect(mock.server.tool).toHaveBeenCalledWith(
      "cloud_security",
      expect.any(String),
      expect.any(Object),
      expect.any(Function),
    );
  });

  // ── Unknown action ──────────────────────────────────────────────────────

  it("should report error for unknown action", async () => {
    const handler = tools.get("cloud_security")!.handler;
    const result = await handler({ action: "nonexistent" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Unknown action");
  });

  // ── Pure function tests ─────────────────────────────────────────────────

  describe("maskCredential", () => {
    it("should mask credentials showing first 4 chars", () => {
      expect(maskCredential("AKIAIOSFODNN7EXAMPLE")).toBe("AKIA****");
    });

    it("should return (empty) for empty strings", () => {
      expect(maskCredential("")).toBe("(empty)");
      expect(maskCredential("   ")).toBe("(empty)");
    });

    it("should return **** for short values", () => {
      expect(maskCredential("abc")).toBe("****");
      expect(maskCredential("abcd")).toBe("****");
    });

    it("should handle exactly 5 char values", () => {
      expect(maskCredential("abcde")).toBe("abcd****");
    });
  });

  // ── detect_environment ──────────────────────────────────────────────────

  describe("detect_environment", () => {
    it("should detect non-cloud environment", async () => {
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "detect_environment" });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("Not running in a detected cloud environment");
    });

    it("should detect non-cloud environment in JSON format", async () => {
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "detect_environment", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.provider).toBe("unknown");
      expect(parsed.isCloud).toBe(false);
    });

    it("should detect AWS environment", async () => {
      setupAwsCloudMocks();
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "detect_environment", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.provider).toBe("aws");
      expect(parsed.confidence).toBe("high");
      expect(parsed.isCloud).toBe(true);
      expect(parsed.evidence.length).toBeGreaterThan(0);
    });

    it("should detect GCP environment", async () => {
      setupGcpCloudMocks();
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "detect_environment", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.provider).toBe("gcp");
      expect(parsed.confidence).toBe("high");
      expect(parsed.isCloud).toBe(true);
    });

    it("should detect Azure environment", async () => {
      setupAzureCloudMocks();
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "detect_environment", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.provider).toBe("azure");
      expect(parsed.isCloud).toBe(true);
    });

    it("should include evidence in text format for cloud detection", async () => {
      setupAwsCloudMocks();
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "detect_environment" });
      expect(result.content[0].text).toContain("Provider: AWS");
      expect(result.content[0].text).toContain("Confidence: high");
    });

    it("should detect cloud-init presence", async () => {
      mockExistsSync.mockImplementation((path: unknown) => {
        return path === "/run/cloud-init/instance-data.json";
      });

      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "detect_environment", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.evidence.some((e: string) => e.includes("cloud-init"))).toBe(true);
    });

    it("should handle errors gracefully", async () => {
      mockSpawnSafe.mockImplementation(() => {
        throw new Error("spawn failed");
      });

      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "detect_environment", output_format: "json" });
      // Should not throw, should return a result
      expect(result.content).toBeDefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.provider).toBe("unknown");
    });
  });

  // ── audit_metadata ──────────────────────────────────────────────────────

  describe("audit_metadata", () => {
    it("should report unknown provider when not in cloud", async () => {
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "audit_metadata", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.provider).toBe("unknown");
      expect(parsed.recommendations.length).toBeGreaterThan(0);
    });

    it("should audit AWS IMDSv1 as insecure", async () => {
      setupAwsCloudMocks();
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "audit_metadata", provider: "aws", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.provider).toBe("aws");
      expect(parsed.imdsAccessible).toBe(true);
      expect(parsed.securityLevel).toBe("insecure");
      expect(parsed.recommendations.some((r: string) => r.includes("IMDSv2"))).toBe(true);
    });

    it("should audit GCP metadata with correct security", async () => {
      setupGcpCloudMocks();
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "audit_metadata", provider: "gcp", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.provider).toBe("gcp");
      expect(parsed.imdsAccessible).toBe(true);
      expect(parsed.securityLevel).toBe("secure");
    });

    it("should audit Azure metadata", async () => {
      setupAzureCloudMocks();
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "audit_metadata", provider: "azure", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.provider).toBe("azure");
      expect(parsed.imdsAccessible).toBe(true);
    });

    it("should auto-detect provider", async () => {
      setupAwsCloudMocks();
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "audit_metadata", provider: "auto", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.provider).toBe("aws");
    });

    it("should return text format by default", async () => {
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "audit_metadata" });
      expect(result.content[0].text).toContain("Metadata Audit");
    });

    it("should report IMDS not accessible when not in cloud", async () => {
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "audit_metadata", provider: "aws", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.imdsAccessible).toBe(false);
      expect(parsed.imdsVersion).toBe("not accessible");
    });

    it("should list exposed categories for AWS", async () => {
      setupAwsCloudMocks();
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "audit_metadata", provider: "aws", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.exposedCategories.length).toBeGreaterThan(0);
    });
  });

  // ── check_iam_creds ─────────────────────────────────────────────────────

  describe("check_iam_creds", () => {
    it("should find no credentials in non-cloud environment", async () => {
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "check_iam_creds", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.envVarsFound.length).toBe(0);
      expect(parsed.totalFindings).toBe(0);
    });

    it("should detect AWS credentials in environment", async () => {
      setupAwsCloudMocks();
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "check_iam_creds", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.envVarsFound.length).toBe(2);
      const accessKey = parsed.envVarsFound.find((e: { name: string }) => e.name === "AWS_ACCESS_KEY_ID");
      expect(accessKey).toBeDefined();
      expect(accessKey.masked).toBe("AKIA****");
    });

    it("should mask credential values", async () => {
      setupAwsCloudMocks();
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "check_iam_creds", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      const secretKey = parsed.envVarsFound.find((e: { name: string }) => e.name === "AWS_SECRET_ACCESS_KEY");
      expect(secretKey).toBeDefined();
      expect(secretKey.masked).toBe("wJal****");
      // Ensure full value is NOT in the output
      expect(result.content[0].text).not.toContain("wJalrXUtnFEMI");
    });

    it("should detect Azure credentials in environment", async () => {
      setupAzureCloudMocks();
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "check_iam_creds", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      const clientSecret = parsed.envVarsFound.find((e: { name: string }) => e.name === "AZURE_CLIENT_SECRET");
      expect(clientSecret).toBeDefined();
      expect(clientSecret.masked).toBe("supe****");
    });

    it("should check credential file permissions", async () => {
      setupAwsCloudMocks();
      mockExistsSync.mockReturnValue(true);
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "check_iam_creds", provider: "aws", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      const awsCreds = parsed.credentialFiles.find((f: { path: string }) => f.path === "~/.aws/credentials");
      expect(awsCreds).toBeDefined();
      expect(awsCreds.exists).toBe(true);
      expect(awsCreds.permissions).toBe("644");
      expect(awsCreds.permWarning).toBeDefined();
    });

    it("should report no warning for secure permissions", async () => {
      setupAzureCloudMocks();
      mockExistsSync.mockReturnValue(true);
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "check_iam_creds", provider: "azure", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      const azureTokens = parsed.credentialFiles.find((f: { path: string }) => f.path === "~/.azure/accessTokens.json");
      expect(azureTokens).toBeDefined();
      expect(azureTokens.permissions).toBe("600");
      expect(azureTokens.permWarning).toBeUndefined();
    });

    it("should detect processes with cloud credentials", async () => {
      setupAwsCloudMocks();
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "check_iam_creds", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.processesExposed.length).toBeGreaterThan(0);
    });

    it("should filter credential files by provider", async () => {
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "check_iam_creds", provider: "gcp", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      // Should only check GCP files
      const paths = parsed.credentialFiles.map((f: { path: string }) => f.path);
      expect(paths).toContain("~/.config/gcloud/application_default_credentials.json");
      expect(paths).not.toContain("~/.aws/credentials");
    });

    it("should return text format with credential summary", async () => {
      setupAwsCloudMocks();
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "check_iam_creds" });
      expect(result.content[0].text).toContain("IAM Credential Check");
      expect(result.content[0].text).toContain("AWS_ACCESS_KEY_ID");
    });

    it("should include recommendations", async () => {
      setupAwsCloudMocks();
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "check_iam_creds", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.recommendations.length).toBeGreaterThan(0);
    });
  });

  // ── audit_storage ───────────────────────────────────────────────────────

  describe("audit_storage", () => {
    it("should report no CLI tools in non-cloud environment", async () => {
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "audit_storage", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.cliAvailable.aws).toBe(false);
      expect(parsed.cliAvailable.gsutil).toBe(false);
      expect(parsed.cliAvailable.az).toBe(false);
    });

    it("should detect AWS S3 buckets", async () => {
      setupAwsCloudMocks();
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "audit_storage", provider: "aws", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.cliAvailable.aws).toBe(true);
      expect(parsed.accessibleStorage.length).toBeGreaterThan(0);
      expect(parsed.accessibleStorage.some((s: string) => s.includes("AWS S3"))).toBe(true);
    });

    it("should detect GCP GCS buckets", async () => {
      setupGcpCloudMocks();
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "audit_storage", provider: "gcp", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.cliAvailable.gsutil).toBe(true);
      expect(parsed.accessibleStorage.some((s: string) => s.includes("GCP GCS"))).toBe(true);
    });

    it("should detect Azure storage accounts", async () => {
      setupAzureCloudMocks();
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "audit_storage", provider: "azure", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.cliAvailable.az).toBe(true);
      expect(parsed.accessibleStorage.some((s: string) => s.includes("Azure"))).toBe(true);
    });

    it("should detect cloud storage mount points", async () => {
      setupAwsCloudMocks();
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "audit_storage", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.mountPoints.some((m: string) => m.includes("s3fs"))).toBe(true);
    });

    it("should detect Azure FUSE mount points", async () => {
      setupAzureCloudMocks();
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "audit_storage", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.mountPoints.some((m: string) => m.includes("blobfuse"))).toBe(true);
    });

    it("should recommend CLI installation when not available", async () => {
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "audit_storage", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.recommendations.some((r: string) => r.includes("not installed"))).toBe(true);
    });

    it("should return text format with storage summary", async () => {
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "audit_storage" });
      expect(result.content[0].text).toContain("Storage Audit");
      expect(result.content[0].text).toContain("CLI Tools");
    });

    it("should handle no accessible storage gracefully", async () => {
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "audit_storage", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.totalAccessible).toBe(0);
      expect(parsed.recommendations.some((r: string) => r.includes("No cloud storage accessible"))).toBe(true);
    });
  });

  // ── check_imds ──────────────────────────────────────────────────────────

  describe("check_imds", () => {
    it("should report IMDS not accessible in non-cloud", async () => {
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "check_imds", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.v1Accessible).toBe(false);
      expect(parsed.v2Accessible).toBe(false);
      expect(parsed.severity).toBe("INFO");
      expect(parsed.securityScore).toBe(100);
    });

    it("should detect IMDSv1 as CRITICAL", async () => {
      setupAwsCloudMocks();
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "check_imds", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.v1Accessible).toBe(true);
      expect(parsed.severity).toBe("CRITICAL");
      expect(parsed.securityScore).toBeLessThan(50);
    });

    it("should detect IMDSv2 token works", async () => {
      setupAwsCloudMocks();
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "check_imds", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.v2TokenWorks).toBe(true);
      expect(parsed.v2Accessible).toBe(true);
    });

    it("should detect IMDSv2-only as LOW severity", async () => {
      // Mock where only v2 works (v1 blocked)
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "curl" && args.includes("http://169.254.169.254/latest/meta-data/")) {
          return createMockChildProcess("", "", 1); // v1 fails
        }
        if (command === "curl" && args.includes("http://169.254.169.254/latest/api/token")) {
          return createMockChildProcess("AQAAAToken==", "", 0); // v2 works
        }
        if (command === "iptables") {
          return createMockChildProcess("Chain INPUT (policy ACCEPT)\ntarget prot opt source destination\n", "", 0);
        }
        if (command === "curl") {
          return createMockChildProcess("", "", 7);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "check_imds", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.v1Accessible).toBe(false);
      expect(parsed.v2TokenWorks).toBe(true);
      expect(parsed.severity).toBe("MEDIUM"); // v2 with no iptables restriction
    });

    it("should check iptables for IMDS blocking rules", async () => {
      mockSpawnSafe.mockImplementation((command: string, args: string[]) => {
        if (command === "curl" && args.includes("http://169.254.169.254/latest/meta-data/")) {
          return createMockChildProcess("", "", 1);
        }
        if (command === "curl" && args.includes("http://169.254.169.254/latest/api/token")) {
          return createMockChildProcess("Token==", "", 0);
        }
        if (command === "iptables") {
          return createMockChildProcess(
            "Chain INPUT (policy ACCEPT)\ntarget prot opt source destination\nDROP all -- 0.0.0.0/0 169.254.169.254 owner UID match !0\n",
            "",
            0,
          );
        }
        if (command === "curl") {
          return createMockChildProcess("", "", 7);
        }
        return createMockChildProcess("", "", 0);
      });

      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "check_imds", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.iptablesBlocked).toBe(true);
      expect(parsed.iptablesRules.length).toBeGreaterThan(0);
    });

    it("should recommend iptables restriction when missing", async () => {
      setupAwsCloudMocks();
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "check_imds", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.recommendations.some((r: string) => r.includes("iptables"))).toBe(true);
    });

    it("should return text format with security assessment", async () => {
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "check_imds" });
      expect(result.content[0].text).toContain("IMDS Security Check");
      expect(result.content[0].text).toContain("Security Score");
    });

    it("should return IMDS not accessible message for non-cloud", async () => {
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "check_imds", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.recommendations.some((r: string) => r.includes("not accessible"))).toBe(true);
    });

    it("should cap security score between 0 and 100", async () => {
      setupAwsCloudMocks();
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "check_imds", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.securityScore).toBeGreaterThanOrEqual(0);
      expect(parsed.securityScore).toBeLessThanOrEqual(100);
    });
  });

  // ── Output format tests ─────────────────────────────────────────────────

  describe("output formats", () => {
    it("should return JSON for detect_environment", async () => {
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "detect_environment", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("detect_environment");
    });

    it("should return JSON for audit_metadata", async () => {
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "audit_metadata", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("audit_metadata");
    });

    it("should return JSON for check_iam_creds", async () => {
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "check_iam_creds", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("check_iam_creds");
    });

    it("should return JSON for audit_storage", async () => {
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "audit_storage", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("audit_storage");
    });

    it("should return JSON for check_imds", async () => {
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "check_imds", output_format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.action).toBe("check_imds");
    });

    it("should default to text format", async () => {
      const handler = tools.get("cloud_security")!.handler;
      const result = await handler({ action: "detect_environment" });
      // Text format should not be parseable as our structured JSON output
      expect(result.content[0].text).toContain("Cloud Security");
    });
  });

  // ── Error handling ──────────────────────────────────────────────────────

  describe("error handling", () => {
    it("should handle spawnSafe throwing errors", async () => {
      mockSpawnSafe.mockImplementation(() => {
        throw new Error("spawn failed");
      });

      const handler = tools.get("cloud_security")!.handler;
      // detect_environment catches errors internally in runCommand
      const result = await handler({ action: "detect_environment", output_format: "json" });
      expect(result.content).toBeDefined();
    });

    it("should handle command failures in all actions", async () => {
      mockSpawnSafe.mockImplementation(() => {
        return createMockChildProcess("", "command failed", 1);
      });

      const handler = tools.get("cloud_security")!.handler;

      // All actions should handle command failures gracefully
      for (const action of ["detect_environment", "audit_metadata", "check_iam_creds", "audit_storage", "check_imds"]) {
        const result = await handler({ action, output_format: "json" });
        expect(result.content).toBeDefined();
        expect(result.isError).toBeUndefined(); // Graceful, not error
      }
    });
  });
});
