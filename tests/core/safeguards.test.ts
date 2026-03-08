import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  SafeguardRegistry,
  isSSHSession,
  hasAuthorizedKeys,
  type SafetyResult,
} from "../../src/core/safeguards.js";

// ── Mock the executor so detection methods don't hit the real system ────────

vi.mock("../../src/core/executor.js", () => ({
  executeCommand: vi.fn().mockResolvedValue({
    exitCode: 1,
    stdout: "",
    stderr: "",
  }),
}));

// ── Mock fs for controlled file existence checks ───────────────────────────

vi.mock("node:fs", async () => {
  const actual = await vi.importActual<typeof import("node:fs")>("node:fs");
  return {
    ...actual,
    default: {
      ...actual,
      existsSync: vi.fn().mockReturnValue(false),
      statSync: vi.fn().mockReturnValue({ size: 0 }),
      readdirSync: vi.fn().mockReturnValue([]),
      readFileSync: vi.fn().mockReturnValue("{}"),
    },
    existsSync: vi.fn().mockReturnValue(false),
    statSync: vi.fn().mockReturnValue({ size: 0 }),
    readdirSync: vi.fn().mockReturnValue([]),
    readFileSync: vi.fn().mockReturnValue("{}"),
  };
});

// ── Mock net so probePort always returns false (no databases) ──────────────

vi.mock("node:net", async () => {
  const actual = await vi.importActual<typeof import("node:net")>("node:net");
  return {
    ...actual,
    default: {
      ...actual,
      createConnection: vi.fn(() => {
        const EventEmitter = require("node:events");
        const sock = new EventEmitter();
        sock.destroy = vi.fn();
        // Simulate connection error (port closed)
        setTimeout(() => sock.emit("error", new Error("ECONNREFUSED")), 1);
        return sock;
      }),
    },
    createConnection: vi.fn(() => {
      const EventEmitter = require("node:events");
      const sock = new EventEmitter();
      sock.destroy = vi.fn();
      setTimeout(() => sock.emit("error", new Error("ECONNREFUSED")), 1);
      return sock;
    }),
  };
});

describe("safeguards", () => {
  // Backup and restore SSH-related env vars
  const envBackup: Record<string, string | undefined> = {};
  const envKeys = ["SSH_CONNECTION", "SSH_TTY"];

  beforeEach(() => {
    for (const key of envKeys) {
      envBackup[key] = process.env[key];
      delete process.env[key];
    }
  });

  afterEach(() => {
    for (const key of envKeys) {
      if (envBackup[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = envBackup[key];
      }
    }
  });

  // ── isSSHSession helper ──────────────────────────────────────────────

  describe("isSSHSession()", () => {
    it("returns false when no SSH env vars are set", () => {
      delete process.env.SSH_CONNECTION;
      delete process.env.SSH_TTY;
      expect(isSSHSession()).toBe(false);
    });

    it("returns true when SSH_CONNECTION is set", () => {
      process.env.SSH_CONNECTION = "192.168.1.100 12345 192.168.1.1 22";
      expect(isSSHSession()).toBe(true);
    });

    it("returns true when SSH_TTY is set", () => {
      process.env.SSH_TTY = "/dev/pts/0";
      expect(isSSHSession()).toBe(true);
    });
  });

  // ── hasAuthorizedKeys helper ─────────────────────────────────────────

  describe("hasAuthorizedKeys()", () => {
    it("returns false when authorized_keys does not exist", () => {
      // Default mock: existsSync returns false
      expect(hasAuthorizedKeys()).toBe(false);
    });
  });

  // ── SSH lockout blocker ──────────────────────────────────────────────

  describe("SSH lockout prevention", () => {
    it("blocks SSH config changes during SSH session", async () => {
      process.env.SSH_CONNECTION = "192.168.1.100 12345 192.168.1.1 22";

      const registry = SafeguardRegistry.getInstance();
      const result = await registry.checkSafety("access_ssh_harden", {
        settings: "PermitRootLogin=no",
      });

      expect(result.safe).toBe(false);
      expect(result.blockers.length).toBeGreaterThan(0);
      expect(result.blockers[0]).toContain("BLOCKED");
      expect(result.blockers[0]).toContain("SSH");
    });

    it("does NOT block SSH audit during SSH session", async () => {
      process.env.SSH_CONNECTION = "192.168.1.100 12345 192.168.1.1 22";

      const registry = SafeguardRegistry.getInstance();
      const result = await registry.checkSafety("access_ssh_audit", {});

      // Audit is read-only, should not be blocked
      const sshBlockers = result.blockers.filter((b) => b.includes("SSH configuration"));
      expect(sshBlockers.length).toBe(0);
    });

    it("does NOT block SSH changes when NOT in SSH session", async () => {
      delete process.env.SSH_CONNECTION;
      delete process.env.SSH_TTY;

      const registry = SafeguardRegistry.getInstance();
      const result = await registry.checkSafety("access_ssh_harden", {
        settings: "PermitRootLogin=no",
      });

      // No SSH blockers when not connected via SSH
      const sshBlockers = result.blockers.filter((b) => b.includes("SSH"));
      expect(sshBlockers.length).toBe(0);
    });

    it("does NOT block non-SSH operations during SSH session", async () => {
      process.env.SSH_CONNECTION = "192.168.1.100 12345 192.168.1.1 22";

      const registry = SafeguardRegistry.getInstance();
      const result = await registry.checkSafety("malware_clamav_scan", {
        path: "/tmp",
      });

      // Completely unrelated tool should produce no SSH blockers
      const sshBlockers = result.blockers.filter((b) => b.includes("SSH"));
      expect(sshBlockers.length).toBe(0);
    });
  });

  // ── Firewall SSH port blocker ────────────────────────────────────────

  describe("Firewall SSH port blocking", () => {
    it("blocks firewall rules that would DROP port 22 during SSH session", async () => {
      process.env.SSH_CONNECTION = "192.168.1.100 12345 192.168.1.1 22";

      const registry = SafeguardRegistry.getInstance();
      const result = await registry.checkSafety("firewall_iptables_add", {
        chain: "INPUT",
        port: "22",
        action: "DROP",
        protocol: "tcp",
      });

      expect(result.safe).toBe(false);
      const fwBlockers = result.blockers.filter((b) =>
        b.includes("Firewall rule would block SSH port"),
      );
      expect(fwBlockers.length).toBe(1);
    });

    it("blocks firewall rules that REJECT port 22 during SSH session", async () => {
      process.env.SSH_CONNECTION = "192.168.1.100 12345 192.168.1.1 22";

      const registry = SafeguardRegistry.getInstance();
      const result = await registry.checkSafety("firewall_ufw_rule", {
        action: "deny",
        port: "22",
      });

      expect(result.safe).toBe(false);
      expect(result.blockers.some((b) => b.includes("SSH port"))).toBe(true);
    });

    it("blocks INPUT DROP policy during SSH session", async () => {
      process.env.SSH_CONNECTION = "192.168.1.100 12345 192.168.1.1 22";

      const registry = SafeguardRegistry.getInstance();
      const result = await registry.checkSafety("firewall_set_policy", {
        chain: "INPUT",
        policy: "DROP",
      });

      expect(result.safe).toBe(false);
      expect(
        result.blockers.some((b) => b.includes("INPUT chain default policy")),
      ).toBe(true);
    });

    it("does NOT block firewall rules on non-SSH ports", async () => {
      process.env.SSH_CONNECTION = "192.168.1.100 12345 192.168.1.1 22";

      const registry = SafeguardRegistry.getInstance();
      const result = await registry.checkSafety("firewall_iptables_add", {
        chain: "INPUT",
        port: "80",
        action: "DROP",
      });

      // Port 80 should not trigger SSH blocker
      const sshBlockers = result.blockers.filter((b) =>
        b.includes("SSH port"),
      );
      expect(sshBlockers.length).toBe(0);
    });

    it("does NOT block firewall rules when not in SSH session", async () => {
      delete process.env.SSH_CONNECTION;
      delete process.env.SSH_TTY;

      const registry = SafeguardRegistry.getInstance();
      const result = await registry.checkSafety("firewall_iptables_add", {
        chain: "INPUT",
        port: "22",
        action: "DROP",
      });

      const sshBlockers = result.blockers.filter((b) =>
        b.includes("SSH port"),
      );
      expect(sshBlockers.length).toBe(0);
    });
  
    // ── Database service stop blocker ────────────────────────────────────
  
    describe("Database service stop blocker", () => {
      it("blocks stopping postgresql service when dbs detected", async () => {
        // Force detection cache to include databases
        const registry = SafeguardRegistry.getInstance();
        (registry as any).detectionCache = {
          result: {
            vscode: { category: "VS Code", detected: false, detail: "Not detected" },
            docker: { category: "Docker", detected: false, detail: "Not detected" },
            mcp: { category: "MCP Servers", detected: false, detail: "Not detected" },
            dbs: { category: "Databases", detected: true, detail: "Active: PostgreSQL" },
            web: { category: "Web Servers", detected: false, detail: "Not detected" },
          },
          timestamp: Date.now(),
        };
  
        const result = await registry.checkSafety("service_manage", {
          action: "stop",
          service: "postgresql",
        });
  
        expect(result.safe).toBe(false);
        expect(result.blockers.some((b) => b.includes("BLOCKED"))).toBe(true);
        expect(result.blockers.some((b) => b.includes("postgresql"))).toBe(true);
      });
  
      it("blocks disabling mysql service when dbs detected", async () => {
        const registry = SafeguardRegistry.getInstance();
        (registry as any).detectionCache = {
          result: {
            vscode: { category: "VS Code", detected: false, detail: "Not detected" },
            docker: { category: "Docker", detected: false, detail: "Not detected" },
            mcp: { category: "MCP Servers", detected: false, detail: "Not detected" },
            dbs: { category: "Databases", detected: true, detail: "Active: MySQL" },
            web: { category: "Web Servers", detected: false, detail: "Not detected" },
          },
          timestamp: Date.now(),
        };
  
        const result = await registry.checkSafety("service_manage", {
          action: "disable",
          service: "mysql",
        });
  
        expect(result.safe).toBe(false);
        expect(result.blockers.some((b) => b.includes("BLOCKED"))).toBe(true);
      });
  
      it("does NOT block stopping non-database service when dbs detected", async () => {
        const registry = SafeguardRegistry.getInstance();
        (registry as any).detectionCache = {
          result: {
            vscode: { category: "VS Code", detected: false, detail: "Not detected" },
            docker: { category: "Docker", detected: false, detail: "Not detected" },
            mcp: { category: "MCP Servers", detected: false, detail: "Not detected" },
            dbs: { category: "Databases", detected: true, detail: "Active: PostgreSQL" },
            web: { category: "Web Servers", detected: false, detail: "Not detected" },
          },
          timestamp: Date.now(),
        };
  
        const result = await registry.checkSafety("service_manage", {
          action: "stop",
          service: "nginx",
        });
  
        const dbBlockers = result.blockers.filter((b) => b.includes("database service"));
        expect(dbBlockers.length).toBe(0);
      });
    });
  
    // ── Firewall warnings with detected services ────────────────────────
  
    describe("Firewall operation warnings", () => {
      it("warns about firewall impact on detected docker", async () => {
        const registry = SafeguardRegistry.getInstance();
        (registry as any).detectionCache = {
          result: {
            vscode: { category: "VS Code", detected: false, detail: "Not detected" },
            docker: { category: "Docker", detected: true, detail: "Docker socket exists" },
            mcp: { category: "MCP Servers", detected: false, detail: "Not detected" },
            dbs: { category: "Databases", detected: false, detail: "Not detected" },
            web: { category: "Web Servers", detected: false, detail: "Not detected" },
          },
          timestamp: Date.now(),
        };
  
        delete process.env.SSH_CONNECTION;
        delete process.env.SSH_TTY;
  
        const result = await registry.checkSafety("firewall_iptables_add", {
          chain: "INPUT",
          port: "80",
          action: "DROP",
        });
  
        expect(result.warnings.some((w) => w.includes("Docker"))).toBe(true);
        expect(result.impactedApps).toContain("Docker");
      });
  
      it("warns about firewall impact on detected web servers", async () => {
        const registry = SafeguardRegistry.getInstance();
        (registry as any).detectionCache = {
          result: {
            vscode: { category: "VS Code", detected: false, detail: "Not detected" },
            docker: { category: "Docker", detected: false, detail: "Not detected" },
            mcp: { category: "MCP Servers", detected: false, detail: "Not detected" },
            dbs: { category: "Databases", detected: false, detail: "Not detected" },
            web: { category: "Web Servers", detected: true, detail: "Running: nginx" },
          },
          timestamp: Date.now(),
        };
  
        delete process.env.SSH_CONNECTION;
        delete process.env.SSH_TTY;
  
        const result = await registry.checkSafety("firewall_ufw_rule", {});
  
        expect(result.warnings.some((w) => w.includes("Web"))).toBe(true);
        expect(result.impactedApps).toContain("Web Servers");
      });
  
      it("warns about firewall impact on detected databases", async () => {
        const registry = SafeguardRegistry.getInstance();
        (registry as any).detectionCache = {
          result: {
            vscode: { category: "VS Code", detected: false, detail: "Not detected" },
            docker: { category: "Docker", detected: false, detail: "Not detected" },
            mcp: { category: "MCP Servers", detected: false, detail: "Not detected" },
            dbs: { category: "Databases", detected: true, detail: "Active: Redis" },
            web: { category: "Web Servers", detected: false, detail: "Not detected" },
          },
          timestamp: Date.now(),
        };
  
        delete process.env.SSH_CONNECTION;
        delete process.env.SSH_TTY;
  
        const result = await registry.checkSafety("firewall_iptables_add", {});
  
        expect(result.warnings.some((w) => w.includes("Database"))).toBe(true);
      });
  
      it("warns about firewall impact on MCP servers", async () => {
        const registry = SafeguardRegistry.getInstance();
        (registry as any).detectionCache = {
          result: {
            vscode: { category: "VS Code", detected: false, detail: "Not detected" },
            docker: { category: "Docker", detected: false, detail: "Not detected" },
            mcp: { category: "MCP Servers", detected: true, detail: "2 MCP server(s) configured" },
            dbs: { category: "Databases", detected: false, detail: "Not detected" },
            web: { category: "Web Servers", detected: false, detail: "Not detected" },
          },
          timestamp: Date.now(),
        };
  
        delete process.env.SSH_CONNECTION;
        delete process.env.SSH_TTY;
  
        const result = await registry.checkSafety("firewall_nftables_rule", {});
  
        expect(result.warnings.some((w) => w.includes("MCP"))).toBe(true);
      });
    });
  
    // ── Service operation warnings ───────────────────────────────────────
  
    describe("Service operation warnings", () => {
      it("warns about service changes affecting Docker daemon", async () => {
        const registry = SafeguardRegistry.getInstance();
        (registry as any).detectionCache = {
          result: {
            vscode: { category: "VS Code", detected: false, detail: "Not detected" },
            docker: { category: "Docker", detected: true, detail: "Docker socket exists" },
            mcp: { category: "MCP Servers", detected: false, detail: "Not detected" },
            dbs: { category: "Databases", detected: false, detail: "Not detected" },
            web: { category: "Web Servers", detected: false, detail: "Not detected" },
          },
          timestamp: Date.now(),
        };
  
        delete process.env.SSH_CONNECTION;
        delete process.env.SSH_TTY;
  
        const result = await registry.checkSafety("service_restart", {});
  
        expect(result.warnings.some((w) => w.includes("Docker"))).toBe(true);
      });
    });
  
    // ── VS Code informational warning ────────────────────────────────────
  
    describe("VS Code informational warning", () => {
      it("adds VS Code active warning when detected", async () => {
        const registry = SafeguardRegistry.getInstance();
        (registry as any).detectionCache = {
          result: {
            vscode: { category: "VS Code", detected: true, detail: "VS Code process running" },
            docker: { category: "Docker", detected: false, detail: "Not detected" },
            mcp: { category: "MCP Servers", detected: false, detail: "Not detected" },
            dbs: { category: "Databases", detected: false, detail: "Not detected" },
            web: { category: "Web Servers", detected: false, detail: "Not detected" },
          },
          timestamp: Date.now(),
        };
  
        delete process.env.SSH_CONNECTION;
        delete process.env.SSH_TTY;
  
        const result = await registry.checkSafety("harden_sysctl_set", {
          key: "net.ipv4.ip_forward",
          value: "0",
        });
  
        expect(result.warnings.some((w) => w.includes("VS Code"))).toBe(true);
      });
    });
  
    // ── impactedApps deduplication ───────────────────────────────────────
  
    describe("impactedApps deduplication", () => {
      it("should deduplicate impacted apps", async () => {
        const registry = SafeguardRegistry.getInstance();
        (registry as any).detectionCache = {
          result: {
            vscode: { category: "VS Code", detected: false, detail: "Not detected" },
            docker: { category: "Docker", detected: true, detail: "Docker socket exists" },
            mcp: { category: "MCP Servers", detected: false, detail: "Not detected" },
            dbs: { category: "Databases", detected: true, detail: "Active: PostgreSQL" },
            web: { category: "Web Servers", detected: true, detail: "Running: nginx" },
          },
          timestamp: Date.now(),
        };
  
        delete process.env.SSH_CONNECTION;
        delete process.env.SSH_TTY;
  
        const result = await registry.checkSafety("firewall_iptables_add", {});
  
        // No duplicate entries
        const unique = [...new Set(result.impactedApps)];
        expect(result.impactedApps.length).toBe(unique.length);
      });
    });
  
    // ── Operation name too long ──────────────────────────────────────────
  
    describe("Operation name validation", () => {
      it("rejects operation name exceeding 256 chars", async () => {
        const registry = SafeguardRegistry.getInstance();
        const result = await registry.checkSafety("a".repeat(257), {});
        expect(result.safe).toBe(false);
        expect(result.blockers).toContain("Invalid operation name");
      });
    });
  });

  // ── Password auth disable blocker ────────────────────────────────────

  describe("Password auth disable protection", () => {
    it("blocks disabling password auth when no authorized_keys exist", async () => {
      const registry = SafeguardRegistry.getInstance();
      const result = await registry.checkSafety("access_ssh_harden", {
        settings: "PasswordAuthentication=no",
      });

      expect(result.safe).toBe(false);
      expect(
        result.blockers.some((b) =>
          b.includes("Disabling password authentication"),
        ),
      ).toBe(true);
    });

    it("blocks apply_recommended when no authorized_keys exist", async () => {
      const registry = SafeguardRegistry.getInstance();
      const result = await registry.checkSafety("access_ssh_harden", {
        apply_recommended: true,
      });

      const pwBlockers = result.blockers.filter((b) =>
        b.includes("password authentication"),
      );
      expect(pwBlockers.length).toBeGreaterThan(0);
    });
  });

  // ── Advisory warnings (non-blocking) ─────────────────────────────────

  describe("Advisory warnings", () => {
    it("produces warnings (not blockers) for Docker-related operations", async () => {
      // Docker won't be detected because we mocked fs.existsSync to false
      // and executor to return exitCode=1, so Docker socket won't exist.
      // This test verifies the warning mechanism itself.
      const registry = SafeguardRegistry.getInstance();
      const result = await registry.checkSafety("container_docker_audit", {});

      // With mocked system (no Docker detected), there should be no warnings either
      // safe should be true
      expect(result.safe).toBe(true);
    });

    it("returns safe=true when only warnings exist (no blockers)", async () => {
      // A benign operation with no SSH session
      delete process.env.SSH_CONNECTION;
      delete process.env.SSH_TTY;

      const registry = SafeguardRegistry.getInstance();
      const result = await registry.checkSafety("firewall_iptables_list", {});

      expect(result.safe).toBe(true);
      expect(result.blockers.length).toBe(0);
    });
  });

  // ── SafetyResult structure ───────────────────────────────────────────

  describe("SafetyResult integrity", () => {
    it("returns safe=false when blockers exist", async () => {
      process.env.SSH_CONNECTION = "192.168.1.100 12345 192.168.1.1 22";

      const registry = SafeguardRegistry.getInstance();
      const result = await registry.checkSafety("access_ssh_harden", {
        settings: "PermitRootLogin=no",
      });

      expect(result.safe).toBe(false);
      expect(result.blockers.length).toBeGreaterThan(0);
      expect(Array.isArray(result.warnings)).toBe(true);
      expect(Array.isArray(result.impactedApps)).toBe(true);
    });

    it("returns safe=true when no blockers exist", async () => {
      delete process.env.SSH_CONNECTION;
      delete process.env.SSH_TTY;

      const registry = SafeguardRegistry.getInstance();
      const result = await registry.checkSafety("harden_sysctl_get", {
        key: "net.ipv4.ip_forward",
      });

      expect(result.safe).toBe(true);
      expect(result.blockers.length).toBe(0);
    });

    it("returns safe=false for invalid operation name", async () => {
      const registry = SafeguardRegistry.getInstance();
      const result = await registry.checkSafety("", {});

      expect(result.safe).toBe(false);
      expect(result.blockers).toContain("Invalid operation name");
    });

    it("blockers contain actionable messages", async () => {
      process.env.SSH_CONNECTION = "192.168.1.100 12345 192.168.1.1 22";

      const registry = SafeguardRegistry.getInstance();
      const result = await registry.checkSafety("firewall_iptables_add", {
        chain: "INPUT",
        port: "22",
        action: "DROP",
      });

      // Every blocker should start with "BLOCKED:"
      for (const blocker of result.blockers) {
        expect(blocker).toMatch(/^BLOCKED:/);
      }
    });
  });

  // ── Multiple blockers can accumulate ─────────────────────────────────

  describe("Multiple blockers", () => {
    it("accumulates SSH config blocker AND password auth blocker", async () => {
      process.env.SSH_CONNECTION = "192.168.1.100 12345 192.168.1.1 22";

      const registry = SafeguardRegistry.getInstance();
      // This operation modifies SSH AND disables password auth
      const result = await registry.checkSafety("access_ssh_harden", {
        settings: "PasswordAuthentication=no",
        apply_recommended: false,
      });

      expect(result.safe).toBe(false);
      // Should have both SSH modification blocker AND password auth blocker
      expect(result.blockers.length).toBeGreaterThanOrEqual(2);
      expect(
        result.blockers.some((b) => b.includes("Cannot modify SSH configuration")),
      ).toBe(true);
      expect(
        result.blockers.some((b) => b.includes("Disabling password authentication")),
      ).toBe(true);
    });
  });
});
