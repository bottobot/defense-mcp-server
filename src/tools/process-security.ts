/**
 * Process security tools for Defense MCP Server.
 *
 * Registers 1 tool: process_security
 * Actions: audit_running, check_capabilities, check_namespaces, detect_anomalies, cgroup_audit
 *
 * Inspects running processes for security concerns including privilege escalation,
 * capability abuse, namespace isolation, anomalous behavior, and cgroup resource limits.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { runCommand, type CommandResult } from "../core/run-command.js";
import {
  createTextContent,
  createErrorContent,
} from "../core/parsers.js";

// ── Constants ──────────────────────────────────────────────────────────────────

/** Processes known to legitimately run as root */
const KNOWN_SAFE_ROOT_PROCESSES = new Set([
  "init", "systemd", "sshd", "cron", "crond", "rsyslogd", "journald",
  "udevd", "dbus-daemon", "NetworkManager", "polkitd", "accounts-daemon",
  "login", "getty", "agetty", "kthreadd", "ksoftirqd", "kworker",
  "rcu_sched", "rcu_bh", "migration", "watchdog", "dockerd", "containerd",
  "snapd", "multipathd", "irqbalance", "thermald", "udisksd",
  "packagekitd", "gdm", "lightdm", "sddm",
]);

/** Linux capabilities considered dangerous */
const DANGEROUS_CAPABILITIES = new Set([
  "cap_sys_admin", "cap_sys_ptrace", "cap_net_raw", "cap_sys_module",
  "cap_dac_override", "cap_setuid", "cap_setgid",
]);

/** Maximum number of processes to inspect to avoid overwhelming output */
const MAX_PROCESSES = 100;

// ── Helpers ────────────────────────────────────────────────────────────────────


// ── Process parsing helpers ────────────────────────────────────────────────────

interface ProcessInfo {
  user: string;
  pid: number;
  cpu: number;
  mem: number;
  vsz: number;
  rss: number;
  tty: string;
  stat: string;
  start: string;
  time: string;
  command: string;
}

/**
 * Parse `ps auxf` output into structured process info.
 */
function parsePsOutput(output: string): ProcessInfo[] {
  const lines = output.trim().split("\n");
  if (lines.length < 2) return [];

  // Skip header line
  const processes: ProcessInfo[] = [];
  for (let i = 1; i < lines.length && processes.length < MAX_PROCESSES; i++) {
    const line = lines[i];
    // ps aux format: USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
    const parts = line.trim().split(/\s+/);
    if (parts.length < 11) continue;

    processes.push({
      user: parts[0],
      pid: parseInt(parts[1], 10),
      cpu: parseFloat(parts[2]),
      mem: parseFloat(parts[3]),
      vsz: parseInt(parts[4], 10),
      rss: parseInt(parts[5], 10),
      tty: parts[6],
      stat: parts[7],
      start: parts[8],
      time: parts[9],
      command: parts.slice(10).join(" "),
    });
  }

  return processes;
}

/**
 * Get the base process name from a full command path.
 */
function getProcessName(command: string): string {
  // Remove leading path modifiers like `\_` from ps tree output
  const cleaned = command.replace(/^[\\|_ ]+/, "");
  // Extract binary name from full path or command
  const parts = cleaned.split(/\s+/);
  const binary = parts[0] || "";
  // Remove path prefix
  const name = binary.split("/").pop() || binary;
  // Remove common suffixes
  return name.replace(/:\s*$/, "");
}

/**
 * Check if a process is running from an unusual path.
 */
function isUnusualPath(command: string): boolean {
  const cleaned = command.replace(/^[\\|_ ]+/, "").split(/\s+/)[0] || "";
  if (!cleaned.startsWith("/")) return false; // relative or just binary name — not unusual
  const safePrefixes = ["/usr/", "/bin/", "/sbin/", "/opt/", "/lib/", "/snap/"];
  return !safePrefixes.some((prefix) => cleaned.startsWith(prefix));
}

interface Finding {
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  category: string;
  message: string;
  pid?: number;
  process?: string;
}

// ── Action implementations ─────────────────────────────────────────────────────

async function auditRunning(
  pid: number | undefined,
  filter: string | undefined,
  showAll: boolean,
): Promise<{ sections: string[]; findings: Finding[] }> {
  const sections: string[] = [];
  const findings: Finding[] = [];

  sections.push("Process Security Audit");
  sections.push("");

  // Get process list
  const psResult = await runCommand("ps", ["auxf"]);
  if (psResult.exitCode !== 0) {
    sections.push(`\nWARNING: Failed to get process list: ${psResult.stderr}`);
    return { sections, findings };
  }

  let processes = parsePsOutput(psResult.stdout);

  // Filter by PID if specified
  if (pid !== undefined) {
    processes = processes.filter((p) => p.pid === pid);
    if (processes.length === 0) {
      sections.push(`\nWARNING: No process found with PID ${pid}`);
      return { sections, findings };
    }
  }

  // Filter by name pattern
  if (filter) {
    const pattern = new RegExp(filter, "i");
    processes = processes.filter((p) => pattern.test(p.command));
  }

  sections.push(`\nTotal processes analyzed: ${processes.length}`);

  // Check for processes running as root that shouldn't be
  const rootProcesses = processes.filter((p) => p.user === "root");
  const suspiciousRoot = rootProcesses.filter((p) => {
    const name = getProcessName(p.command);
    return !KNOWN_SAFE_ROOT_PROCESSES.has(name) && !name.startsWith("[");
  });

  if (suspiciousRoot.length > 0) {
    sections.push("\n── Unusual Root Processes ──");
    for (const p of suspiciousRoot) {
      sections.push(`  PID ${p.pid}: ${p.command}`);
      findings.push({
        severity: "MEDIUM",
        category: "root_process",
        message: `Process running as root: ${getProcessName(p.command)}`,
        pid: p.pid,
        process: p.command,
      });
    }
  }

  // Check for high resource usage
  const highCpu = processes.filter((p) => p.cpu > 90);
  const highMem = processes.filter((p) => p.mem > 50);

  if (highCpu.length > 0) {
    sections.push("\n── High CPU Usage (>90%) ──");
    for (const p of highCpu) {
      sections.push(`  PID ${p.pid} (${p.cpu}% CPU): ${p.command}`);
      findings.push({
        severity: "HIGH",
        category: "high_resource",
        message: `High CPU usage: ${p.cpu}%`,
        pid: p.pid,
        process: p.command,
      });
    }
  }

  if (highMem.length > 0) {
    sections.push("\n── High Memory Usage (>50%) ──");
    for (const p of highMem) {
      sections.push(`  PID ${p.pid} (${p.mem}% MEM): ${p.command}`);
      findings.push({
        severity: "HIGH",
        category: "high_resource",
        message: `High memory usage: ${p.mem}%`,
        pid: p.pid,
        process: p.command,
      });
    }
  }

  // Check for processes from unusual paths
  const unusualPath = processes.filter((p) => isUnusualPath(p.command));
  if (unusualPath.length > 0) {
    sections.push("\n── Processes from Unusual Paths ──");
    for (const p of unusualPath) {
      sections.push(`  PID ${p.pid}: ${p.command}`);
      findings.push({
        severity: "MEDIUM",
        category: "unusual_path",
        message: `Process running from unusual path`,
        pid: p.pid,
        process: p.command,
      });
    }
  }

  // Check for deleted executables
  const pidsToCheck = processes.slice(0, 50).map((p) => p.pid);
  const deletedExe: ProcessInfo[] = [];

  for (const checkPid of pidsToCheck) {
    const exeResult = await runCommand("ls", ["-la", `/proc/${checkPid}/exe`]);
    if (exeResult.exitCode === 0 && exeResult.stdout.includes("(deleted)")) {
      const proc = processes.find((p) => p.pid === checkPid);
      if (proc) deletedExe.push(proc);
    }
  }

  if (deletedExe.length > 0) {
    sections.push("\n── Processes with Deleted Executables ──");
    for (const p of deletedExe) {
      sections.push(`  CRITICAL: PID ${p.pid}: ${p.command}`);
      findings.push({
        severity: "CRITICAL",
        category: "deleted_exe",
        message: `Process running with deleted executable`,
        pid: p.pid,
        process: p.command,
      });
    }
  }

  // Summary
  if (!showAll && findings.length === 0) {
    sections.push("\nNo suspicious processes detected.");
  } else if (showAll) {
    sections.push("\n── All Processes ──");
    for (const p of processes.slice(0, 50)) {
      sections.push(`  ${p.user}\t${p.pid}\t${p.cpu}%\t${p.mem}%\t${p.command}`);
    }
  }

  return { sections, findings };
}

async function checkCapabilities(
  pid: number | undefined,
  filter: string | undefined,
): Promise<{ sections: string[]; findings: Finding[] }> {
  const sections: string[] = [];
  const findings: Finding[] = [];

  sections.push("Process Capabilities Check");
  sections.push("");

  if (pid !== undefined) {
    // Check specific PID capabilities
    const capsResult = await runCommand("getpcaps", [String(pid)]);
    if (capsResult.exitCode !== 0) {
      sections.push(`\nWARNING: Failed to get capabilities for PID ${pid}: ${capsResult.stderr}`);
      return { sections, findings };
    }

    sections.push(`\nCapabilities for PID ${pid}:`);
    sections.push(`  ${capsResult.stdout.trim()}`);

    // Check for dangerous capabilities
    const capsLower = capsResult.stdout.toLowerCase();
    for (const cap of DANGEROUS_CAPABILITIES) {
      if (capsLower.includes(cap)) {
        findings.push({
          severity: "HIGH",
          category: "dangerous_capability",
          message: `Process has dangerous capability: ${cap}`,
          pid,
        });
      }
    }
  } else {
    // Scan processes for elevated capabilities
    const psResult = await runCommand("ps", ["-eo", "pid"]);
    if (psResult.exitCode !== 0) {
      sections.push("\nWARNING: Failed to list processes");
      return { sections, findings };
    }

    const pids = psResult.stdout.trim().split("\n")
      .slice(1) // skip header
      .map((l) => l.trim())
      .filter((l) => l && /^\d+$/.test(l))
      .slice(0, MAX_PROCESSES);

    sections.push(`\nScanning ${pids.length} processes for elevated capabilities...`);
    const elevatedProcesses: Array<{ pid: string; caps: string; decoded: string }> = [];

    for (const checkPid of pids) {
      // Filter by name pattern if specified
      if (filter) {
        const cmdResult = await runCommand("cat", [`/proc/${checkPid}/comm`]);
        if (cmdResult.exitCode !== 0) continue;
        const pattern = new RegExp(filter, "i");
        if (!pattern.test(cmdResult.stdout.trim())) continue;
      }

      const statusResult = await runCommand("cat", [`/proc/${checkPid}/status`]);
      if (statusResult.exitCode !== 0) continue;

      const capEffMatch = statusResult.stdout.match(/CapEff:\s*([0-9a-fA-F]+)/);
      if (!capEffMatch) continue;

      const capHex = capEffMatch[1];
      // Skip processes with no effective capabilities
      if (capHex === "0000000000000000") continue;

      // Decode capabilities
      const decodeResult = await runCommand("capsh", [`--decode=${capHex}`]);
      const decoded = decodeResult.exitCode === 0 ? decodeResult.stdout.trim() : `hex:${capHex}`;

      elevatedProcesses.push({ pid: checkPid, caps: capHex, decoded });

      // Check for dangerous capabilities
      const decodedLower = decoded.toLowerCase();
      for (const cap of DANGEROUS_CAPABILITIES) {
        if (decodedLower.includes(cap)) {
          findings.push({
            severity: "HIGH",
            category: "dangerous_capability",
            message: `PID ${checkPid} has dangerous capability: ${cap}`,
            pid: parseInt(checkPid, 10),
          });
        }
      }
    }

    if (elevatedProcesses.length > 0) {
      sections.push(`\n── Processes with Elevated Capabilities (${elevatedProcesses.length}) ──`);
      for (const ep of elevatedProcesses) {
        sections.push(`  PID ${ep.pid}: ${ep.decoded}`);
      }
    } else {
      sections.push("\nNo processes with elevated capabilities found.");
    }
  }

  return { sections, findings };
}

async function checkNamespaces(
  pid: number | undefined,
  _filter: string | undefined,
): Promise<{ sections: string[]; findings: Finding[] }> {
  const sections: string[] = [];
  const findings: Finding[] = [];

  sections.push("Process Namespace Analysis");
  sections.push("");

  if (pid !== undefined) {
    // Show namespace details for specific PID
    const nsResult = await runCommand("ls", ["-la", `/proc/${pid}/ns/`]);
    if (nsResult.exitCode !== 0) {
      sections.push(`\nCannot read namespaces for PID ${pid}: ${nsResult.stderr}`);
      return { sections, findings };
    }

    sections.push(`\nNamespace details for PID ${pid}:`);
    sections.push(nsResult.stdout.trim());

    // Compare with init namespace (PID 1)
    const initNsResult = await runCommand("ls", ["-la", "/proc/1/ns/"]);
    if (initNsResult.exitCode === 0) {
      sections.push("\n── Namespace Comparison with init (PID 1) ──");
      const pidNsLines = nsResult.stdout.trim().split("\n");
      const initNsLines = initNsResult.stdout.trim().split("\n");

      const pidNsMap = new Map<string, string>();
      for (const line of pidNsLines) {
        const match = line.match(/(\w+)\s*->\s*\w+:\[(\d+)\]/);
        if (match) pidNsMap.set(match[1], match[2]);
      }

      const initNsMap = new Map<string, string>();
      for (const line of initNsLines) {
        const match = line.match(/(\w+)\s*->\s*\w+:\[(\d+)\]/);
        if (match) initNsMap.set(match[1], match[2]);
      }

      for (const [nsType, nsId] of pidNsMap) {
        const initId = initNsMap.get(nsType);
        const inRootNs = initId === nsId;
        const icon = inRootNs ? "WARNING" : "PASS";
        sections.push(`  ${icon} ${nsType}: ${inRootNs ? "in root namespace" : "isolated"} (${nsId})`);

        if (inRootNs && !["user", "cgroup"].includes(nsType)) {
          findings.push({
            severity: "MEDIUM",
            category: "namespace_not_isolated",
            message: `PID ${pid} shares ${nsType} namespace with init`,
            pid,
          });
        }
      }
    }
  } else {
    // List all namespaces via lsns
    const lsnsResult = await runCommand("lsns", []);
    if (lsnsResult.exitCode !== 0) {
      // Retry with sudo
      const sudoLsnsResult = await runCommand("sudo", ["lsns"]);
      if (sudoLsnsResult.exitCode !== 0) {
        sections.push("\nCannot list namespaces (lsns not available or permission denied)");
        return { sections, findings };
      }
      sections.push("\n── Active Namespaces ──");
      sections.push(sudoLsnsResult.stdout.trim());
    } else {
      sections.push("\n── Active Namespaces ──");
      sections.push(lsnsResult.stdout.trim());
    }

    // Parse lsns output for analysis
    const lsnsOutput = lsnsResult.exitCode === 0 ? lsnsResult.stdout : "";
    const nsLines = lsnsOutput.trim().split("\n").slice(1); // skip header

    // Look for namespace sharing patterns
    const nsCountMap = new Map<string, number>();
    for (const line of nsLines) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 4) {
        const nsType = parts[1];
        const nprocs = parseInt(parts[2], 10);
        if (nsType && !isNaN(nprocs)) {
          nsCountMap.set(nsType, (nsCountMap.get(nsType) || 0) + nprocs);
        }
      }
    }

    if (nsCountMap.size > 0) {
      sections.push("\n── Namespace Summary ──");
      for (const [nsType, count] of nsCountMap) {
        sections.push(`  ${nsType}: ${count} processes`);
      }
    }
  }

  return { sections, findings };
}

async function detectAnomalies(
  pid: number | undefined,
  filter: string | undefined,
): Promise<{ sections: string[]; findings: Finding[] }> {
  const sections: string[] = [];
  const findings: Finding[] = [];

  sections.push("Process Anomaly Detection");
  sections.push("");

  // Get process list for analysis
  const psResult = await runCommand("ps", ["-eo", "pid,ppid,user,comm"]);
  if (psResult.exitCode !== 0) {
    sections.push("\nWARNING: Failed to get process list");
    return { sections, findings };
  }

  const psLines = psResult.stdout.trim().split("\n").slice(1);
  let processList = psLines.map((line) => {
    const parts = line.trim().split(/\s+/);
    return {
      pid: parseInt(parts[0], 10),
      ppid: parseInt(parts[1], 10),
      user: parts[2] || "",
      comm: parts[3] || "",
    };
  }).filter((p) => !isNaN(p.pid));

  // Filter by PID or name
  if (pid !== undefined) {
    processList = processList.filter((p) => p.pid === pid);
  }
  if (filter) {
    const pattern = new RegExp(filter, "i");
    processList = processList.filter((p) => pattern.test(p.comm));
  }

  // Limit to prevent overwhelming output
  processList = processList.slice(0, MAX_PROCESSES);

  // 1. Check for deleted binaries
  sections.push("\n── Deleted Binary Check ──");
  let deletedCount = 0;
  for (const proc of processList) {
    const exeResult = await runCommand("ls", ["-la", `/proc/${proc.pid}/exe`]);
    if (exeResult.exitCode === 0 && exeResult.stdout.includes("(deleted)")) {
      deletedCount++;
      sections.push(`  CRITICAL: PID ${proc.pid} (${proc.comm}): executable deleted`);
      findings.push({
        severity: "CRITICAL",
        category: "deleted_binary",
        message: `Process ${proc.comm} running with deleted binary`,
        pid: proc.pid,
        process: proc.comm,
      });
    }
  }
  if (deletedCount === 0) sections.push("  No processes with deleted binaries");

  // 2. Cross-reference network connections with expected services
  sections.push("\n── Unexpected Network Connections ──");
  const ssResult = await runCommand("ss", ["-tlnp"]);
  if (ssResult.exitCode === 0) {
    const ssLines = ssResult.stdout.trim().split("\n").slice(1);
    for (const line of ssLines) {
      sections.push(`  ${line.trim()}`);
    }
    if (ssLines.length === 0) {
      sections.push("  No listening TCP connections");
    }
  } else {
    sections.push("  Could not check network connections");
  }

  // 3. Check for shell spawning from non-shell parents
  sections.push("\n── Shell Spawning Analysis ──");
  const shellNames = new Set(["sh", "bash", "zsh", "dash", "fish", "csh", "ksh"]);
  const shellProcesses = processList.filter((p) => shellNames.has(p.comm));
  let suspiciousShellCount = 0;

  for (const shell of shellProcesses) {
    const parent = processList.find((p) => p.pid === shell.ppid);
    if (parent && !shellNames.has(parent.comm) && parent.comm !== "login" &&
        parent.comm !== "sshd" && parent.comm !== "su" && parent.comm !== "sudo" &&
        parent.comm !== "screen" && parent.comm !== "tmux" && parent.comm !== "script" &&
        parent.comm !== "getty" && parent.comm !== "agetty" && parent.comm !== "systemd") {
      suspiciousShellCount++;
      sections.push(`  WARNING: PID ${shell.pid} (${shell.comm}) spawned by ${parent.comm} (PID ${parent.pid})`);
      findings.push({
        severity: "HIGH",
        category: "suspicious_shell",
        message: `Shell ${shell.comm} spawned by non-shell parent ${parent.comm}`,
        pid: shell.pid,
        process: shell.comm,
      });
    }
  }
  if (suspiciousShellCount === 0) sections.push("  No suspicious shell spawning detected");

  // 4. Check for open file descriptors to sensitive files
  sections.push("\n── Sensitive File Access ──");
  const sensitiveFiles = ["/etc/shadow", "/etc/passwd", ".ssh/id_rsa", ".ssh/id_ed25519", "private.key"];
  const checkProcs = processList.slice(0, 20); // limit deep inspection

  let sensitiveAccessCount = 0;
  for (const proc of checkProcs) {
    const fdResult = await runCommand("ls", ["-la", `/proc/${proc.pid}/fd/`]);
    if (fdResult.exitCode !== 0) continue;

    for (const sf of sensitiveFiles) {
      if (fdResult.stdout.includes(sf)) {
        sensitiveAccessCount++;
        sections.push(`  WARNING: PID ${proc.pid} (${proc.comm}) has open fd to ${sf}`);
        findings.push({
          severity: "HIGH",
          category: "sensitive_file_access",
          message: `Process ${proc.comm} accessing sensitive file: ${sf}`,
          pid: proc.pid,
          process: proc.comm,
        });
      }
    }
  }
  if (sensitiveAccessCount === 0) sections.push("  No suspicious sensitive file access");

  // 5. Check for suspicious environment variables
  sections.push("\n── Suspicious Environment Variables ──");
  let suspiciousEnvCount = 0;
  for (const proc of checkProcs) {
    const envResult = await runCommand("cat", [`/proc/${proc.pid}/environ`]);
    if (envResult.exitCode !== 0) continue;

    const envStr = envResult.stdout;
    // Check for base64-encoded data, reverse shell indicators
    if (envStr.includes("bash -i") || envStr.includes("/dev/tcp") ||
        envStr.includes("nc -e") || envStr.includes("mkfifo") ||
        envStr.includes("PAYLOAD") || envStr.includes("SHELLCODE")) {
      suspiciousEnvCount++;
      sections.push(`  CRITICAL: PID ${proc.pid} (${proc.comm}): suspicious environment variables detected`);
      findings.push({
        severity: "CRITICAL",
        category: "suspicious_env",
        message: `Process ${proc.comm} has suspicious environment variables (possible reverse shell/payload)`,
        pid: proc.pid,
        process: proc.comm,
      });
    }
  }
  if (suspiciousEnvCount === 0) sections.push("  No suspicious environment variables detected");

  return { sections, findings };
}

async function cgroupAudit(
  pid: number | undefined,
  _filter: string | undefined,
): Promise<{ sections: string[]; findings: Finding[] }> {
  const sections: string[] = [];
  const findings: Finding[] = [];

  sections.push("Cgroup Resource Audit");
  sections.push("");

  if (pid !== undefined) {
    // Inspect specific process cgroup membership
    const cgroupResult = await runCommand("cat", [`/proc/${pid}/cgroup`]);
    if (cgroupResult.exitCode !== 0) {
      sections.push(`\nCannot read cgroup for PID ${pid}: ${cgroupResult.stderr}`);
      return { sections, findings };
    }

    sections.push(`\nCgroup membership for PID ${pid}:`);
    sections.push(cgroupResult.stdout.trim());

    // Check cgroup version
    const cgroupLines = cgroupResult.stdout.trim().split("\n");
    const isCgroupV2 = cgroupLines.some((l) => l.startsWith("0::"));
    sections.push(`\n  Cgroup version: ${isCgroupV2 ? "v2 (unified)" : "v1 (legacy)"}`);

    // Check if process has resource limits
    if (isCgroupV2) {
      const cgroupPath = cgroupLines.find((l) => l.startsWith("0::"))?.split("::")[1] || "";
      if (cgroupPath) {
        const memMaxResult = await runCommand("cat", [`/sys/fs/cgroup${cgroupPath}/memory.max`]);
        if (memMaxResult.exitCode === 0) {
          const memMax = memMaxResult.stdout.trim();
          sections.push(`  Memory limit: ${memMax === "max" ? "unlimited WARNING" : memMax}`);
          if (memMax === "max") {
            findings.push({
              severity: "LOW",
              category: "no_memory_limit",
              message: `PID ${pid} has no memory limit`,
              pid,
            });
          }
        }

        const cpuMaxResult = await runCommand("cat", [`/sys/fs/cgroup${cgroupPath}/cpu.max`]);
        if (cpuMaxResult.exitCode === 0) {
          const cpuMax = cpuMaxResult.stdout.trim();
          sections.push(`  CPU limit: ${cpuMax === "max 100000" ? "unlimited WARNING" : cpuMax}`);
          if (cpuMax.startsWith("max")) {
            findings.push({
              severity: "LOW",
              category: "no_cpu_limit",
              message: `PID ${pid} has no CPU limit`,
              pid,
            });
          }
        }
      }
    }
  } else {
    // System-wide cgroup overview
    const cgroupsResult = await runCommand("cat", ["/proc/cgroups"]);
    if (cgroupsResult.exitCode === 0) {
      sections.push("\n── Available Cgroup Controllers ──");
      sections.push(cgroupsResult.stdout.trim());
    }

    // Check cgroup hierarchy
    const cgHierarchy = await runCommand("systemd-cgls", ["--no-pager"]);
    if (cgHierarchy.exitCode === 0) {
      // Limit output length
      const lines = cgHierarchy.stdout.trim().split("\n");
      sections.push("\n── Cgroup Hierarchy (truncated) ──");
      sections.push(lines.slice(0, 50).join("\n"));
      if (lines.length > 50) sections.push(`  ... (${lines.length - 50} more lines)`);
    }

    // Resource usage overview
    const cgtopResult = await runCommand("systemd-cgtop", ["-b", "-n", "1"]);
    if (cgtopResult.exitCode === 0) {
      const lines = cgtopResult.stdout.trim().split("\n");
      sections.push("\n── Cgroup Resource Usage ──");
      sections.push(lines.slice(0, 30).join("\n"));
    }

    // Check for cgroup v1 vs v2
    const mountResult = await runCommand("cat", ["/proc/self/cgroup"]);
    if (mountResult.exitCode === 0) {
      const isCgroupV2 = mountResult.stdout.includes("0::");
      sections.push(`\n  Cgroup version: ${isCgroupV2 ? "v2 (unified)" : "v1 (legacy)"}`);
      if (!isCgroupV2) {
        findings.push({
          severity: "INFO",
          category: "cgroup_v1",
          message: "System using cgroup v1 — consider upgrading to v2 for better security",
        });
      }
    }
  }

  return { sections, findings };
}

// ── Format helpers ─────────────────────────────────────────────────────────────

function formatFindings(findings: Finding[]): string {
  if (findings.length === 0) return "\nNo security findings.";

  const lines: string[] = ["\n── Security Findings Summary ──"];
  const bySeverity: Record<string, Finding[]> = {};

  for (const f of findings) {
    if (!bySeverity[f.severity]) bySeverity[f.severity] = [];
    bySeverity[f.severity].push(f);
  }

  const severityOrder: Array<Finding["severity"]> = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

  for (const sev of severityOrder) {
    const items = bySeverity[sev];
    if (!items || items.length === 0) continue;
    lines.push(`\n  ${sev} (${items.length}):`);
    for (const f of items) {
      const pidStr = f.pid ? ` [PID ${f.pid}]` : "";
      lines.push(`    - ${f.message}${pidStr}`);
    }
  }

  return lines.join("\n");
}

function formatAsJson(
  action: string,
  findings: Finding[],
  rawSections: string[],
): string {
  return JSON.stringify({
    action,
    timestamp: new Date().toISOString(),
    findingsCount: findings.length,
    findings: findings.map((f) => ({
      severity: f.severity,
      category: f.category,
      message: f.message,
      pid: f.pid || null,
      process: f.process || null,
    })),
    rawOutput: rawSections.join("\n"),
  });
}

// ── Registration entry point ───────────────────────────────────────────────

export function registerProcessSecurityTools(server: McpServer): void {
  server.tool(
    "process_security",
    "Processes: audit running, capabilities, namespaces, anomaly detection, cgroup limits",
    {
      action: z
        .enum(["audit_running", "check_capabilities", "check_namespaces", "detect_anomalies", "cgroup_audit"])
        .describe("Process security action"),
      pid: z
        .number()
        .optional()
        .describe("Specific process ID to inspect"),
      filter: z
        .string()
        .optional()
        .describe("Filter processes by name pattern (regex)"),
      show_all: z
        .boolean()
        .optional()
        .default(false)
        .describe("Show all processes, not just suspicious"),
      output_format: z
        .enum(["text", "json"])
        .optional()
        .default("text")
        .describe("Output format"),
    },
    async (params) => {
      const { action, pid, filter, show_all, output_format } = params;

      try {
        let result: { sections: string[]; findings: Finding[] };

        switch (action) {
          case "audit_running":
            result = await auditRunning(pid, filter, show_all ?? false);
            break;
          case "check_capabilities":
            result = await checkCapabilities(pid, filter);
            break;
          case "check_namespaces":
            result = await checkNamespaces(pid, filter);
            break;
          case "detect_anomalies":
            result = await detectAnomalies(pid, filter);
            break;
          case "cgroup_audit":
            result = await cgroupAudit(pid, filter);
            break;
          default:
            return {
              content: [createErrorContent(`Unknown action: ${action}`)],
              isError: true,
            };
        }

        // Append findings summary
        result.sections.push(formatFindings(result.findings));

        if (output_format === "json") {
          return {
            content: [createTextContent(formatAsJson(action, result.findings, result.sections))],
          };
        }

        return {
          content: [createTextContent(result.sections.join("\n"))],
        };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return {
          content: [createErrorContent(`Process security check failed: ${msg}`)],
          isError: true,
        };
      }
    },
  );
}
