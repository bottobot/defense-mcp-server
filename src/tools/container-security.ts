/**
 * Container and mandatory access control security tools for Kali Defense MCP Server.
 *
 * Registers 2 tools:
 *   container_docker (actions: audit, bench, seccomp, daemon, image_scan)
 *   container_isolation (actions: apparmor_status, apparmor_list, apparmor_enforce,
 *     apparmor_complain, apparmor_disable, apparmor_install, apparmor_apply_container,
 *     selinux_status, selinux_getenforce, selinux_setenforce, selinux_booleans, selinux_audit,
 *     namespace_check, seccomp_profile, rootless_setup)
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeCommand } from "../core/executor.js";
import { getConfig, getToolTimeout } from "../core/config.js";
import {
  createTextContent,
  createErrorContent,
  formatToolOutput,
  parseJsonSafe,
} from "../core/parsers.js";
import { logChange, createChangeEntry, backupFile } from "../core/changelog.js";
import { sanitizeArgs } from "../core/sanitizer.js";
import { SafeguardRegistry } from "../core/safeguards.js";
import { existsSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { secureWriteFileSync } from "../core/secure-fs.js";

// ── TOOL-011 remediation: safe directory for seccomp profiles ──────────────
const SECCOMP_PROFILE_DIR = "/tmp/kali-defense/seccomp";

// ── Registration entry point ───────────────────────────────────────────────

export function registerContainerSecurityTools(server: McpServer): void {
  // ── 1. container_docker (audit + bench + seccomp + daemon + image_scan) ─

  server.tool(
    "container_docker",
    "Docker security: audit configuration, run CIS benchmarks, audit seccomp profiles, configure daemon settings, or scan images for vulnerabilities.",
    {
      action: z.enum(["audit", "bench", "seccomp", "daemon", "image_scan"]).describe("Action: audit=security audit, bench=CIS benchmark, seccomp=seccomp audit, daemon=configure daemon, image_scan=scan image for vulnerabilities"),
      // audit params
      check_type: z.enum(["daemon", "images", "containers", "network", "all"]).optional().default("all").describe("Docker check type (audit action)"),
      // bench params
      checks: z.string().optional().describe("Specific check sections e.g. '1,2,4' (bench action)"),
      log_level: z.enum(["INFO", "WARN", "NOTE", "PASS"]).optional().default("WARN").describe("Min log level (bench action)"),
      // daemon params
      daemon_action: z.enum(["audit", "apply"]).optional().describe("Whether to audit or apply daemon settings (daemon action)"),
      settings: z.object({
        userns_remap: z.boolean().optional(),
        no_new_privileges: z.boolean().optional(),
        icc: z.boolean().optional(),
        live_restore: z.boolean().optional(),
        log_driver: z.enum(["json-file", "journald"]).optional(),
        log_max_size: z.string().optional().default("10m"),
        log_max_file: z.string().optional().default("3"),
      }).optional().describe("Settings to apply (daemon action with daemon_action=apply)"),
      // image_scan params
      image: z.string().optional().describe("Docker image name/ID to scan, e.g. 'nginx:latest' (image_scan action)"),
      severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "ALL"]).optional().default("HIGH").describe("Minimum severity to report (image_scan action)"),
      // shared
      dry_run: z.boolean().optional().describe("Preview changes without executing"),
    },
    async (params) => {
      const { action } = params;

      switch (action) {
        // ── audit ───────────────────────────────────────────────────
        case "audit": {
          const { check_type } = params;
          try {
            const sections: string[] = [];
            sections.push("🐳 Docker Security Audit");
            sections.push("=".repeat(50));
            const findings: Array<{ level: string; msg: string }> = [];

            const dockerCheck = await executeCommand({ command: "which", args: ["docker"], toolName: "container_docker", timeout: 5000 });
            if (dockerCheck.exitCode !== 0) {
              return { content: [createTextContent("Docker is not installed or not in PATH. No audit possible.")] };
            }

            if (check_type === "daemon" || check_type === "all") {
              sections.push("\n── Docker Daemon Configuration ──");
              const infoResult = await executeCommand({ command: "docker", args: ["info", "--format", "{{json .}}"], toolName: "container_docker", timeout: getToolTimeout("container_docker_audit") });

              if (infoResult.exitCode === 0) {
                const info = parseJsonSafe(infoResult.stdout) as Record<string, unknown> | null;
                if (info) {
                  sections.push(`  Server Version: ${info["ServerVersion"] ?? "unknown"}`);
                  sections.push(`  Storage Driver: ${info["Driver"] ?? "unknown"}`);
                  sections.push(`  Logging Driver: ${info["LoggingDriver"] ?? "unknown"}`);
                  sections.push(`  Live Restore: ${info["LiveRestoreEnabled"] ?? "unknown"}`);
                  const securityOptions = info["SecurityOptions"] as string[] | undefined;
                  if (securityOptions) {
                    sections.push(`  Security Options: ${securityOptions.join(", ")}`);
                    if (!securityOptions.some((o) => String(o).includes("userns"))) findings.push({ level: "WARNING", msg: "User namespaces not enabled" });
                  }
                  if (info["LiveRestoreEnabled"] !== true) findings.push({ level: "INFO", msg: "Live restore is not enabled" });
                }
              }

              const daemonResult = await executeCommand({ command: "cat", args: ["/etc/docker/daemon.json"], toolName: "container_docker", timeout: 5000 });
              if (daemonResult.exitCode === 0) {
                const daemonConfig = parseJsonSafe(daemonResult.stdout) as Record<string, unknown> | null;
                if (daemonConfig) {
                  if (!daemonConfig["userns-remap"]) findings.push({ level: "WARNING", msg: "userns-remap not configured" });
                  if (!daemonConfig["no-new-privileges"]) findings.push({ level: "INFO", msg: "no-new-privileges not set" });
                  if (!daemonConfig["icc"] || daemonConfig["icc"] === true) findings.push({ level: "WARNING", msg: "Inter-container communication not disabled" });
                }
              } else {
                findings.push({ level: "WARNING", msg: "No custom Docker daemon configuration" });
              }

              const socketResult = await executeCommand({ command: "ls", args: ["-la", "/var/run/docker.sock"], toolName: "container_docker", timeout: 5000 });
              if (socketResult.exitCode === 0 && socketResult.stdout.includes("rw-rw-rw")) {
                findings.push({ level: "CRITICAL", msg: "Docker socket is world-writable!" });
              }
            }

            if (check_type === "images" || check_type === "all") {
              sections.push("\n── Docker Images ──");
              const imagesResult = await executeCommand({ command: "docker", args: ["images", "--format", "{{.Repository}}:{{.Tag}} | {{.Size}} | {{.CreatedSince}} | {{.ID}}"], toolName: "container_docker", timeout: getToolTimeout("container_docker_audit") });
              if (imagesResult.exitCode === 0 && imagesResult.stdout.trim()) {
                const imageLines = imagesResult.stdout.trim().split("\n").filter((l) => l.trim());
                sections.push(`  Total images: ${imageLines.length}`);
                let latestCount = 0;
                for (const line of imageLines) { sections.push(`  ${line}`); if (line.includes(":latest ") || line.endsWith(":latest")) latestCount++; }
                if (latestCount > 0) findings.push({ level: "WARNING", msg: `${latestCount} image(s) using 'latest' tag` });
              } else {
                sections.push("  No Docker images found.");
              }
            }

            if (check_type === "containers" || check_type === "all") {
              sections.push("\n── Running Containers ──");
              const psResult = await executeCommand({ command: "docker", args: ["ps", "--format", "{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}"], toolName: "container_docker", timeout: getToolTimeout("container_docker_audit") });
              if (psResult.exitCode === 0 && psResult.stdout.trim()) {
                const containerLines = psResult.stdout.trim().split("\n").filter((l) => l.trim());
                sections.push(`  Running containers: ${containerLines.length}`);
                for (const line of containerLines) {
                  const parts = line.split("|");
                  const containerId = parts[0] || "unknown";
                  const containerName = parts[1] || "unknown";
                  sections.push(`\n  Container: ${containerName} (${containerId})`);
                  const inspectResult = await executeCommand({ command: "docker", args: ["inspect", "--format", "{{.HostConfig.Privileged}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.PidMode}}|{{.HostConfig.ReadonlyRootfs}}", containerId], toolName: "container_docker", timeout: 10000 });
                  if (inspectResult.exitCode === 0) {
                    const inspParts = inspectResult.stdout.trim().split("|");
                    if (inspParts[0] === "true") findings.push({ level: "CRITICAL", msg: `Container '${containerName}' is running in privileged mode!` });
                    if (inspParts[1] === "host") findings.push({ level: "WARNING", msg: `Container '${containerName}' uses host networking` });
                    if (inspParts[2] === "host") findings.push({ level: "WARNING", msg: `Container '${containerName}' shares host PID namespace` });
                  }
                  const mountInspect = await executeCommand({ command: "docker", args: ["inspect", "--format", "{{json .Mounts}}", containerId], toolName: "container_docker", timeout: 10000 });
                  if (mountInspect.exitCode === 0 && mountInspect.stdout.trim()) {
                    const mounts = parseJsonSafe(mountInspect.stdout.trim()) as Array<{ Source?: string; Destination?: string; RW?: boolean }> | null;
                    if (mounts) {
                      for (const mount of mounts) {
                        const src = mount.Source || "";
                        if (src === "/var/run/docker.sock" || mount.Destination === "/var/run/docker.sock") findings.push({ level: "CRITICAL", msg: `Container '${containerName}': Docker socket mounted` });
                        if (src === "/") findings.push({ level: "CRITICAL", msg: `Container '${containerName}': Root filesystem '/' mounted` });
                      }
                    }
                  }
                }
              }
            }

            if (check_type === "network" || check_type === "all") {
              sections.push("\n── Docker Networks ──");
              const netResult = await executeCommand({ command: "docker", args: ["network", "ls", "--format", "{{.Name}} | {{.Driver}} | {{.Scope}}"], toolName: "container_docker", timeout: getToolTimeout("container_docker_audit") });
              if (netResult.exitCode === 0 && netResult.stdout.trim()) {
                for (const line of netResult.stdout.trim().split("\n")) sections.push(`  ${line}`);
              }
            }

            sections.push("\n── Security Findings Summary ──");
            if (findings.length === 0) { sections.push("  ✅ No significant security issues found."); }
            else {
              for (const lvl of ["CRITICAL", "WARNING", "INFO"]) {
                const items = findings.filter((f) => f.level === lvl);
                if (items.length > 0) {
                  const icon = lvl === "CRITICAL" ? "⛔" : lvl === "WARNING" ? "⚠️" : "ℹ️";
                  sections.push(`\n  ${icon} ${lvl} (${items.length}):`);
                  for (const f of items) sections.push(`    - ${f.msg}`);
                }
              }
            }
            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) { return { content: [createErrorContent(err instanceof Error ? err.message : String(err))], isError: true }; }
        }

        // ── bench ───────────────────────────────────────────────────
        case "bench": {
          const { checks: benchChecks, log_level } = params;
          try {
            const sections: string[] = ["🔒 Docker Bench for Security", "=".repeat(50)];
            const dockerCheck = await executeCommand({ command: "which", args: ["docker"], toolName: "container_docker", timeout: 5000 });
            if (dockerCheck.exitCode !== 0) return { content: [createTextContent("Docker is not installed.")] };

            const benchArgs = ["run", "--rm", "--net", "host", "--pid", "host", "--userns", "host", "--cap-add", "audit_control", "-v", "/etc:/etc:ro", "-v", "/var/lib:/var/lib:ro", "-v", "/var/run/docker.sock:/var/run/docker.sock:ro", "-v", "/usr/lib/systemd:/usr/lib/systemd:ro", "-v", "/usr/bin/containerd:/usr/bin/containerd:ro", "-v", "/usr/bin/runc:/usr/bin/runc:ro", "docker/docker-bench-security"];
            if (benchChecks) { sanitizeArgs([benchChecks]); benchArgs.push("-c", benchChecks); }

            const result = await executeCommand({ command: "docker", args: benchArgs, toolName: "container_docker", timeout: 300000 });
            const output = result.stdout || result.stderr;

            if (result.exitCode !== 0 && !output) {
              sections.push("⚠️ Docker Bench could not run.");
              return { content: [createTextContent(sections.join("\n"))] };
            }

            const levelPriority: Record<string, number> = { PASS: 0, INFO: 1, NOTE: 2, WARN: 3 };
            const minLevel = levelPriority[log_level] ?? 0;
            let passCount = 0, warnCount = 0, infoCount = 0, noteCount = 0;
            const filteredLines: string[] = [];

            for (const line of output.split("\n")) {
              if (line.includes("[PASS]")) passCount++;
              if (line.includes("[WARN]")) warnCount++;
              if (line.includes("[INFO]")) infoCount++;
              if (line.includes("[NOTE]")) noteCount++;
              if (line.match(/^\[INFO\]\s+\d+\s+-\s+/) || line.startsWith("# ")) { filteredLines.push(line); continue; }
              let lineLevel = -1;
              if (line.includes("[PASS]")) lineLevel = 0;
              if (line.includes("[INFO]")) lineLevel = 1;
              if (line.includes("[NOTE]")) lineLevel = 2;
              if (line.includes("[WARN]")) lineLevel = 3;
              if (lineLevel >= minLevel) filteredLines.push(line);
            }

            sections.push("── Results ──", filteredLines.join("\n"), "\n── Summary ──", `  [PASS]: ${passCount}`, `  [WARN]: ${warnCount}`, `  [INFO]: ${infoCount}`, `  [NOTE]: ${noteCount}`);
            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) { return { content: [createErrorContent(err instanceof Error ? err.message : String(err))], isError: true }; }
        }

        // ── seccomp ─────────────────────────────────────────────────
        case "seccomp": {
          try {
            const psResult = await executeCommand({ command: "docker", args: ["ps", "--format", "{{.ID}} {{.Names}} {{.Image}}"], timeout: 10000, toolName: "container_docker" });
            if (psResult.exitCode !== 0) return { content: [createTextContent("Docker is not available or not running")] };

            const containers = psResult.stdout.trim().split("\n").filter((l: string) => l.trim());
            const results = [];

            for (const line of containers) {
              const [id, name, image] = line.split(" ");
              if (!id) continue;
              const inspectResult = await executeCommand({ command: "docker", args: ["inspect", "--format", '{{.HostConfig.SecurityOpt}}', id], timeout: 10000, toolName: "container_docker" });
              const secOpt = inspectResult.stdout.trim();
              const hasSeccomp = secOpt.includes("seccomp");
              const unconfined = secOpt.includes("seccomp=unconfined");
              results.push({
                container: name || id, image: image || "unknown", securityOpt: secOpt,
                seccompEnabled: hasSeccomp && !unconfined,
                status: unconfined ? "FAIL" : hasSeccomp ? "PASS" : secOpt === "[]" ? "WARN" : "PASS",
                note: unconfined ? "seccomp explicitly disabled — HIGH RISK" : !hasSeccomp && secOpt === "[]" ? "Using Docker default seccomp (acceptable)" : "seccomp configured",
              });
            }

            return { content: [createTextContent(JSON.stringify({ summary: { total: results.length, pass: results.filter(r => r.status === "PASS").length, warn: results.filter(r => r.status === "WARN").length, fail: results.filter(r => r.status === "FAIL").length }, containers: results }, null, 2))] };
          } catch (error) { return { content: [createErrorContent(error instanceof Error ? error.message : String(error))], isError: true }; }
        }

        // ── daemon ──────────────────────────────────────────────────
        case "daemon": {
          const { daemon_action, settings, dry_run } = params;
          try {
            if (!daemon_action) return { content: [createErrorContent("daemon_action is required (audit or apply)")], isError: true };

            const sections: string[] = ["🐳 Docker Daemon Configuration", "=".repeat(50)];
            const daemonPath = "/etc/docker/daemon.json";

            const readResult = await executeCommand({ command: "cat", args: [daemonPath], toolName: "container_docker", timeout: 5000 });
            const existingConfig = readResult.exitCode === 0 ? (parseJsonSafe(readResult.stdout) as Record<string, unknown>) || {} : {};

            if (daemon_action === "audit") {
              if (readResult.exitCode !== 0) sections.push("  ⚠️ No /etc/docker/daemon.json found");
              else sections.push(`  ${JSON.stringify(existingConfig, null, 4).replace(/\n/g, "\n  ")}`);

              sections.push("\n── Security Settings Audit ──");
              const checks = [
                { key: "userns-remap", present: !!existingConfig["userns-remap"], recommended: '"default"', severity: "HIGH" },
                { key: "no-new-privileges", present: !!existingConfig["no-new-privileges"], recommended: "true", severity: "MEDIUM" },
                { key: "icc", present: existingConfig["icc"] === false, recommended: "false", severity: "HIGH" },
                { key: "live-restore", present: !!existingConfig["live-restore"], recommended: "true", severity: "LOW" },
                { key: "log-driver", present: !!existingConfig["log-driver"], recommended: '"json-file"', severity: "LOW" },
              ];
              let missingCount = 0;
              for (const c of checks) { if (!c.present) missingCount++; sections.push(`  ${c.present ? "✅ Present" : "❌ Missing"}: ${c.key} [${c.severity}]`); }
              sections.push(`\n  Summary: ${checks.length - missingCount}/${checks.length} configured`);
              return { content: [createTextContent(sections.join("\n"))] };
            }

            // apply
            if (!settings) return { content: [createErrorContent("settings parameter is required for daemon_action=apply")], isError: true };

            const isDryRun = dry_run ?? getConfig().dryRun;
            const changes: string[] = [];
            const newConfig = { ...existingConfig };

            if (settings.userns_remap !== undefined) { if (settings.userns_remap) { newConfig["userns-remap"] = "default"; changes.push('userns-remap: "default"'); } else if (newConfig["userns-remap"]) { delete newConfig["userns-remap"]; changes.push("userns-remap: removed"); } }
            if (settings.no_new_privileges !== undefined) { newConfig["no-new-privileges"] = settings.no_new_privileges; changes.push(`no-new-privileges: ${settings.no_new_privileges}`); }
            if (settings.icc !== undefined) { newConfig["icc"] = settings.icc; changes.push(`icc: ${settings.icc}`); }
            if (settings.live_restore !== undefined) { newConfig["live-restore"] = settings.live_restore; changes.push(`live-restore: ${settings.live_restore}`); }
            if (settings.log_driver) { newConfig["log-driver"] = settings.log_driver; changes.push(`log-driver: "${settings.log_driver}"`); }
            if (settings.log_driver || settings.log_max_size || settings.log_max_file) {
              const logOpts = (newConfig["log-opts"] as Record<string, string>) || {};
              if (settings.log_max_size) logOpts["max-size"] = settings.log_max_size;
              if (settings.log_max_file) logOpts["max-file"] = settings.log_max_file;
              newConfig["log-opts"] = logOpts;
            }

            if (changes.length === 0) { sections.push("\n  No changes to apply."); return { content: [createTextContent(sections.join("\n"))] }; }

            const newJson = JSON.stringify(newConfig, null, 2);
            sections.push("\n── Changes ──");
            for (const c of changes) sections.push(`  • ${c}`);

            if (isDryRun) {
              sections.push("\n[DRY RUN] No changes written.");
            } else {
              if (readResult.exitCode === 0) { await backupFile(daemonPath); sections.push(`\n  ✅ Backed up ${daemonPath}`); }
              const writeResult = await executeCommand({ command: "sudo", args: ["tee", daemonPath], stdin: newJson, toolName: "container_docker", timeout: 10000 });
              if (writeResult.exitCode !== 0) return { content: [createErrorContent(`Failed to write ${daemonPath}: ${writeResult.stderr}`)], isError: true };
              sections.push(`  ✅ Written to ${daemonPath}`);
              sections.push("\n  ⚠️ Restart Docker: sudo systemctl restart docker");
              logChange(createChangeEntry({ tool: "container_docker", action: "apply daemon config", target: daemonPath, before: JSON.stringify(existingConfig), after: newJson, dryRun: false, success: true }));
            }
            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) { return { content: [createErrorContent(err instanceof Error ? err.message : String(err))], isError: true }; }
        }

        // ── image_scan ──────────────────────────────────────────────
        case "image_scan": {
          const { image, severity } = params;
          try {
            if (!image) {
              return { content: [createErrorContent("image is required for image_scan action")], isError: true };
            }

            const trivyResult = await executeCommand({
              command: "trivy",
              args: ["image", "--severity", severity === "ALL" ? "CRITICAL,HIGH,MEDIUM,LOW" : `CRITICAL${severity !== "CRITICAL" ? ",HIGH" : ""}${severity === "MEDIUM" || severity === "LOW" ? ",MEDIUM" : ""}${severity === "LOW" ? ",LOW" : ""}`, "--format", "json", image],
              timeout: 300000, toolName: "container_docker",
            });
            if (trivyResult.exitCode === 0) return { content: [createTextContent(`Trivy scan results for ${image}:\n${trivyResult.stdout.substring(0, 8000)}`)] };

            const grypeResult = await executeCommand({ command: "grype", args: [image, "-o", "json"], timeout: 300000, toolName: "container_docker" });
            if (grypeResult.exitCode === 0) return { content: [createTextContent(`Grype scan results for ${image}:\n${grypeResult.stdout.substring(0, 8000)}`)] };

            return { content: [createTextContent(JSON.stringify({ error: "Neither Trivy nor Grype is installed", recommendation: "Install Trivy or Grype" }, null, 2))] };
          } catch (error) { return { content: [createErrorContent(error instanceof Error ? error.message : String(error))], isError: true }; }
        }

        default:
          return { content: [createErrorContent(`Unknown action: ${action}`)], isError: true };
      }
    }
  );

  // ── 2. container_isolation (apparmor + selinux + namespace + security_config) ──

  server.tool(
    "container_isolation",
    "Container isolation management: AppArmor profiles, SELinux settings, namespace checks, seccomp profile generation, and rootless container setup.",
    {
      action: z.enum([
        "apparmor_status",
        "apparmor_list",
        "apparmor_enforce",
        "apparmor_complain",
        "apparmor_disable",
        "apparmor_install",
        "apparmor_apply_container",
        "selinux_status",
        "selinux_getenforce",
        "selinux_setenforce",
        "selinux_booleans",
        "selinux_audit",
        "namespace_check",
        "seccomp_profile",
        "rootless_setup",
      ]).describe("Action to perform"),
      // apparmor enforce/complain/disable params
      profile: z.string().optional().describe("Profile name (apparmor_enforce/apparmor_complain/apparmor_disable)"),
      // apparmor_apply_container params
      profileName: z.string().optional().describe("AppArmor profile name (apparmor_apply_container / seccomp_profile)"),
      containerName: z.string().optional().describe("Container name for context (apparmor_apply_container)"),
      allowNetwork: z.boolean().optional().default(true).describe("Allow network access (apparmor_apply_container)"),
      allowWrite: z.array(z.string()).optional().default([]).describe("Writable paths (apparmor_apply_container)"),
      // selinux params
      mode: z.enum(["enforcing", "permissive", "disabled"]).optional().describe("SELinux mode (selinux_setenforce)"),
      boolean_name: z.string().optional().describe("SELinux boolean name (selinux_booleans)"),
      boolean_value: z.enum(["on", "off"]).optional().describe("SELinux boolean value (selinux_booleans)"),
      // namespace_check params
      pid: z.number().optional().describe("Process ID to inspect namespaces for (namespace_check)"),
      check_type: z.enum(["user", "network", "pid", "mount", "all"]).optional().default("all").describe("Type of namespace check (namespace_check)"),
      // seccomp_profile params
      allowedSyscalls: z.array(z.string()).optional().describe("List of syscall names to allow (seccomp_profile)"),
      defaultAction: z.enum(["SCMP_ACT_ERRNO", "SCMP_ACT_KILL", "SCMP_ACT_LOG"]).optional().default("SCMP_ACT_ERRNO").describe("Default action for unlisted syscalls (seccomp_profile)"),
      outputPath: z.string().optional().describe("Path to write the profile (seccomp_profile)"),
      // rootless_setup params
      username: z.string().optional().describe("Username to configure (rootless_setup)"),
      subuidCount: z.number().optional().default(65536).describe("Number of subordinate UIDs (rootless_setup)"),
      // shared
      dry_run: z.boolean().optional().describe("Preview changes without executing"),
      dryRun: z.boolean().optional().default(true).describe("Preview only (seccomp_profile / rootless_setup)"),
    },
    async (params) => {
      const { action } = params;

      switch (action) {
        // ── apparmor_status ─────────────────────────────────────────
        case "apparmor_status": {
          try {
            const sections: string[] = ["🛡️ AppArmor System Status", "=".repeat(40)];
            const enabledResult = await executeCommand({ command: "aa-enabled", args: [], toolName: "container_isolation", timeout: 5000 });
            const aaEnabled = enabledResult.exitCode === 0 && enabledResult.stdout.trim() === "Yes";
            sections.push(`\n  AppArmor enabled: ${aaEnabled ? "✅ Yes" : "❌ No"}`);

            const moduleResult = await executeCommand({ command: "cat", args: ["/sys/module/apparmor/parameters/enabled"], toolName: "container_isolation", timeout: 5000 });
            if (moduleResult.exitCode === 0) sections.push(`  Kernel module: ${moduleResult.stdout.trim() === "Y" ? "✅ Loaded" : "❌ Not loaded"}`);

            const pkgChecks = ["apparmor-profiles", "apparmor-profiles-extra", "apparmor-utils"];
            sections.push("\n  Profile Packages:");
            for (const pkg of pkgChecks) {
              const dpkgResult = await executeCommand({ command: "dpkg", args: ["-s", pkg], toolName: "container_isolation", timeout: 5000 });
              const installed = dpkgResult.exitCode === 0 && dpkgResult.stdout.includes("Status: install ok installed");
              sections.push(`    ${pkg}: ${installed ? "✅ Installed" : "❌ Not installed"}`);
            }
            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) { return { content: [createErrorContent(err instanceof Error ? err.message : String(err))], isError: true }; }
        }

        // ── apparmor_list ───────────────────────────────────────────
        case "apparmor_list": {
          try {
            const sections: string[] = ["🛡️ AppArmor Profiles", "=".repeat(40)];
            let result = await executeCommand({ command: "sudo", args: ["aa-status"], toolName: "container_isolation", timeout: getToolTimeout("container_apparmor_manage") });
            if (result.exitCode !== 0) result = await executeCommand({ command: "sudo", args: ["apparmor_status"], toolName: "container_isolation", timeout: getToolTimeout("container_apparmor_manage") });
            if (result.exitCode !== 0) { sections.push("\n⚠️ Cannot list AppArmor profiles."); return { content: [createTextContent(sections.join("\n"))] }; }

            const output = result.stdout;
            const lines = output.split("\n");
            let currentSection = "";
            for (const line of lines) {
              const trimmed = line.trim();
              if (trimmed.includes("enforce mode")) { currentSection = "enforce"; sections.push("\n  🔒 Enforce Mode:"); }
              else if (trimmed.includes("complain mode")) { currentSection = "complain"; sections.push("\n  📝 Complain Mode:"); }
              else if (trimmed.includes("unconfined")) { currentSection = "unconfined"; sections.push("\n  ⚠️ Unconfined:"); }
              else if (currentSection && trimmed && !trimmed.match(/^\d+\s+processes?/)) { sections.push(`    ${trimmed}`); }
            }
            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) { return { content: [createErrorContent(err instanceof Error ? err.message : String(err))], isError: true }; }
        }

        // ── apparmor_enforce / apparmor_complain / apparmor_disable ──
        case "apparmor_enforce":
        case "apparmor_complain":
        case "apparmor_disable": {
          const { profile, dry_run } = params;
          try {
            if (!profile) return { content: [createErrorContent(`profile name is required for '${action}' action`)], isError: true };
            sanitizeArgs([profile]);

            const baseAction = action.replace("apparmor_", "") as "enforce" | "complain" | "disable";
            const cmdMap: Record<string, string> = { enforce: "aa-enforce", complain: "aa-complain", disable: "aa-disable" };
            const cmd = cmdMap[baseAction];

            if (dry_run ?? getConfig().dryRun) {
              return { content: [createTextContent(`[DRY RUN] Would set profile '${profile}' to ${baseAction} mode.\n  Command: sudo ${cmd} ${profile}`)] };
            }

            const result = await executeCommand({ command: "sudo", args: [cmd, profile], toolName: "container_isolation", timeout: getToolTimeout("container_apparmor_manage") });
            if (result.exitCode !== 0) return { content: [createErrorContent(`Failed to ${baseAction} profile '${profile}': ${result.stderr}`)], isError: true };

            logChange(createChangeEntry({ tool: "container_isolation", action: baseAction, target: profile, after: `${baseAction} mode`, dryRun: false, success: true, rollbackCommand: baseAction === "disable" ? `sudo aa-enforce ${profile}` : undefined }));
            return { content: [createTextContent(`✅ Profile '${profile}' set to ${baseAction} mode.\n${result.stdout || result.stderr}`)] };
          } catch (err: unknown) { return { content: [createErrorContent(err instanceof Error ? err.message : String(err))], isError: true }; }
        }

        // ── apparmor_install ────────────────────────────────────────
        case "apparmor_install": {
          const { dry_run } = params;
          try {
            const isDryRun = dry_run ?? getConfig().dryRun;
            const packages = ["apparmor-profiles", "apparmor-profiles-extra"];

            if (isDryRun) {
              return { content: [createTextContent(`[DRY RUN] Would install: ${packages.join(", ")}\n  Command: sudo apt-get install -y ${packages.join(" ")}`)] };
            }

            const installResult = await executeCommand({ command: "sudo", args: ["apt-get", "install", "-y", ...packages], toolName: "container_isolation", timeout: 120000 });
            if (installResult.exitCode !== 0) return { content: [createErrorContent(`Failed to install: ${installResult.stderr}`)], isError: true };

            logChange(createChangeEntry({ tool: "container_isolation", action: "install_profiles", target: packages.join(", "), after: "installed", dryRun: false, success: true, rollbackCommand: `sudo apt-get remove -y ${packages.join(" ")}` }));
            return { content: [createTextContent(`✅ Successfully installed: ${packages.join(", ")}`)] };
          } catch (err: unknown) { return { content: [createErrorContent(err instanceof Error ? err.message : String(err))], isError: true }; }
        }

        // ── apparmor_apply_container ────────────────────────────────
        case "apparmor_apply_container": {
          const { profileName, containerName, allowNetwork, allowWrite, dry_run } = params;
          try {
            if (!profileName) return { content: [createErrorContent("profileName is required for apparmor_apply_container action")], isError: true };

            const writeRules = (allowWrite ?? []).map((p) => `  ${p} rw,`).join("\n");
            const networkRule = allowNetwork ? "  network,\n" : "  deny network,\n";

            const profileContent = `#include <tunables/global>\n\nprofile ${profileName} flags=(attach_disconnected,mediate_deleted) {\n  #include <abstractions/base>\n\n${networkRule}\n  /usr/** r,\n  /etc/** r,\n  /proc/** r,\n  /sys/** r,\n  /tmp/** rw,\n${writeRules}\n\n  deny /etc/shadow r,\n  deny /etc/gshadow r,\n\n  capability net_bind_service,\n  capability setuid,\n  capability setgid,\n}\n`;

            const isDryRun = dry_run ?? getConfig().dryRun;
            if (isDryRun) {
              return { content: [formatToolOutput({ dryRun: true, profileName, profile: profileContent, loadCommand: `apparmor_parser -r /etc/apparmor.d/${profileName}` })] };
            }

            const profilePath = `/etc/apparmor.d/${profileName}`;
            // TOOL-009: Use secure-fs instead of direct writeFileSync
            secureWriteFileSync(profilePath, profileContent, "utf-8");

            const result = await executeCommand({ command: "apparmor_parser", args: ["-r", profilePath], timeout: 15000 });

            logChange(createChangeEntry({ tool: "container_isolation", action: `Create AppArmor profile ${profileName}`, target: profilePath, dryRun: false, success: result.exitCode === 0, rollbackCommand: `apparmor_parser -R ${profilePath} && rm ${profilePath}` }));

            return { content: [formatToolOutput({ success: result.exitCode === 0, profilePath, loaded: result.exitCode === 0, output: result.stdout || result.stderr })] };
          } catch (err: unknown) { return { content: [createErrorContent(`AppArmor profile failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true }; }
        }

        // ── selinux_status ──────────────────────────────────────────
        case "selinux_status": {
          try {
            const sections: string[] = [`🛡️ SELinux Management: status`, "=".repeat(40)];
            const result = await executeCommand({ command: "sestatus", args: [], toolName: "container_isolation", timeout: getToolTimeout("container_selinux_manage") });
            if (result.exitCode !== 0) { sections.push("\n⚠️ SELinux may not be installed."); sections.push(result.stderr || result.stdout); }
            else sections.push("\n" + result.stdout);
            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) { return { content: [createErrorContent(err instanceof Error ? err.message : String(err))], isError: true }; }
        }

        // ── selinux_getenforce ──────────────────────────────────────
        case "selinux_getenforce": {
          try {
            const sections: string[] = [`🛡️ SELinux Management: getenforce`, "=".repeat(40)];
            const result = await executeCommand({ command: "getenforce", args: [], toolName: "container_isolation", timeout: getToolTimeout("container_selinux_manage") });
            if (result.exitCode !== 0) sections.push("\n⚠️ getenforce not available.");
            else sections.push(`\nCurrent SELinux mode: ${result.stdout.trim()}`);
            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) { return { content: [createErrorContent(err instanceof Error ? err.message : String(err))], isError: true }; }
        }

        // ── selinux_setenforce ──────────────────────────────────────
        case "selinux_setenforce": {
          const { mode, dry_run } = params;
          try {
            const sections: string[] = [`🛡️ SELinux Management: setenforce`, "=".repeat(40)];
            if (!mode) return { content: [createErrorContent("mode is required for selinux_setenforce")], isError: true };
            if (mode === "disabled") { sections.push("\n⚠️ Cannot disable SELinux at runtime."); return { content: [createTextContent(sections.join("\n"))] }; }
            const modeValue = mode === "enforcing" ? "1" : "0";
            if (dry_run ?? getConfig().dryRun) { sections.push(`\n[DRY RUN] Would set SELinux to ${mode}.`); return { content: [createTextContent(sections.join("\n"))] }; }
            const result = await executeCommand({ command: "sudo", args: ["setenforce", modeValue], toolName: "container_isolation", timeout: getToolTimeout("container_selinux_manage") });
            if (result.exitCode !== 0) return { content: [createErrorContent(`Failed: ${result.stderr}`)], isError: true };
            sections.push(`\n✅ SELinux mode set to ${mode}.`);
            logChange(createChangeEntry({ tool: "container_isolation", action: "setenforce", target: "SELinux", after: mode, dryRun: false, success: true, rollbackCommand: `sudo setenforce ${mode === "enforcing" ? "0" : "1"}` }));
            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) { return { content: [createErrorContent(err instanceof Error ? err.message : String(err))], isError: true }; }
        }

        // ── selinux_booleans ────────────────────────────────────────
        case "selinux_booleans": {
          const { boolean_name, boolean_value, dry_run } = params;
          try {
            const sections: string[] = [`🛡️ SELinux Management: booleans`, "=".repeat(40)];
            if (boolean_name && boolean_value) {
              sanitizeArgs([boolean_name]);
              if (dry_run ?? getConfig().dryRun) { sections.push(`\n[DRY RUN] Would set '${boolean_name}' to ${boolean_value}.`); return { content: [createTextContent(sections.join("\n"))] }; }
              const result = await executeCommand({ command: "sudo", args: ["setsebool", "-P", boolean_name, boolean_value], toolName: "container_isolation", timeout: getToolTimeout("container_selinux_manage") });
              if (result.exitCode !== 0) return { content: [createErrorContent(`Failed: ${result.stderr}`)], isError: true };
              sections.push(`\n✅ Boolean '${boolean_name}' set to ${boolean_value}.`);
              logChange(createChangeEntry({ tool: "container_isolation", action: "set_boolean", target: boolean_name, after: boolean_value, dryRun: false, success: true, rollbackCommand: `sudo setsebool -P ${boolean_name} ${boolean_value === "on" ? "off" : "on"}` }));
            } else if (boolean_name) {
              sanitizeArgs([boolean_name]);
              const result = await executeCommand({ command: "getsebool", args: [boolean_name], toolName: "container_isolation", timeout: getToolTimeout("container_selinux_manage") });
              if (result.exitCode !== 0) return { content: [createErrorContent(`Failed: ${result.stderr}`)], isError: true };
              sections.push(`\n${result.stdout.trim()}`);
            } else {
              const result = await executeCommand({ command: "getsebool", args: ["-a"], toolName: "container_isolation", timeout: getToolTimeout("container_selinux_manage") });
              if (result.exitCode !== 0) sections.push("\n⚠️ Cannot list booleans.");
              else sections.push(result.stdout);
            }
            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) { return { content: [createErrorContent(err instanceof Error ? err.message : String(err))], isError: true }; }
        }

        // ── selinux_audit ───────────────────────────────────────────
        case "selinux_audit": {
          try {
            const sections: string[] = [`🛡️ SELinux Management: audit`, "=".repeat(40)];
            const result = await executeCommand({ command: "sudo", args: ["ausearch", "-m", "AVC", "-ts", "recent"], toolName: "container_isolation", timeout: getToolTimeout("container_selinux_manage") });
            if (result.exitCode !== 0 && (result.stderr.includes("no matches") || result.stdout.includes("no matches"))) sections.push("\n✅ No recent SELinux AVC denials.");
            else if (result.exitCode !== 0) sections.push("\n⚠️ Could not search audit logs.");
            else sections.push(`\n⚠️ Recent SELinux AVC Denials:\n${result.stdout}`);
            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) { return { content: [createErrorContent(err instanceof Error ? err.message : String(err))], isError: true }; }
        }

        // ── namespace_check ─────────────────────────────────────────
        case "namespace_check": {
          const { pid, check_type } = params;
          try {
            const sections: string[] = ["📦 Namespace Isolation Check", "=".repeat(40)];

            if (pid !== undefined) {
              sections.push(`\nProcess PID: ${pid}`);
              const nsResult = await executeCommand({ command: "ls", args: ["-la", `/proc/${pid}/ns/`], toolName: "container_isolation", timeout: getToolTimeout("container_namespace_check") });
              if (nsResult.exitCode !== 0) return { content: [createErrorContent(`Cannot read namespaces for PID ${pid}: ${nsResult.stderr}`)], isError: true };
              sections.push("\nNamespace symlinks:");
              sections.push(nsResult.stdout);
            } else {
              sections.push("\n── System Namespace Configuration ──");

              if (check_type === "user" || check_type === "all") {
                sections.push("\n🔑 User Namespaces:");
                const maxNsResult = await executeCommand({ command: "cat", args: ["/proc/sys/user/max_user_namespaces"], toolName: "container_isolation", timeout: 5000 });
                if (maxNsResult.exitCode === 0) {
                  const maxNs = maxNsResult.stdout.trim();
                  sections.push(`  max_user_namespaces: ${maxNs}`);
                  sections.push(maxNs === "0" ? "  ⚠️ User namespaces are disabled" : "  ✅ User namespaces are enabled");
                }
              }

              if (check_type === "network" || check_type === "all") {
                sections.push("\n🌐 Network Namespaces:");
                const netnsResult = await executeCommand({ command: "ip", args: ["netns", "list"], toolName: "container_isolation", timeout: getToolTimeout("container_namespace_check") });
                if (netnsResult.exitCode === 0 && netnsResult.stdout.trim()) {
                  const namespaces = netnsResult.stdout.trim().split("\n").filter((l) => l.trim());
                  sections.push(`  Named network namespaces: ${namespaces.length}`);
                  for (const ns of namespaces) sections.push(`    - ${ns.trim()}`);
                } else sections.push("  No named network namespaces found.");
              }

              if (check_type === "all" || check_type === "pid") {
                sections.push("\n📋 All Active Namespaces (lsns):");
                let lsnsResult = await executeCommand({ command: "lsns", args: [], toolName: "container_isolation", timeout: getToolTimeout("container_namespace_check") });
                if (lsnsResult.exitCode !== 0) lsnsResult = await executeCommand({ command: "sudo", args: ["lsns"], toolName: "container_isolation", timeout: getToolTimeout("container_namespace_check") });
                if (lsnsResult.exitCode === 0) sections.push(lsnsResult.stdout);
                else sections.push("  ⚠️ Cannot list namespaces.");
              }

              if (check_type === "mount" || check_type === "all") {
                sections.push("\n📁 Mount Namespace Info:");
                const mountInfoResult = await executeCommand({ command: "cat", args: ["/proc/self/mountinfo"], toolName: "container_isolation", timeout: 5000 });
                if (mountInfoResult.exitCode === 0) sections.push(`  Current mount namespace has ${mountInfoResult.stdout.trim().split("\n").length} mount points`);
              }
            }
            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) { return { content: [createErrorContent(err instanceof Error ? err.message : String(err))], isError: true }; }
        }

        // ── seccomp_profile ─────────────────────────────────────────
        case "seccomp_profile": {
          const { allowedSyscalls, defaultAction, outputPath, dryRun } = params;
          try {
            if (!allowedSyscalls || allowedSyscalls.length === 0) {
              return { content: [createErrorContent("allowedSyscalls is required for seccomp_profile action")], isError: true };
            }

            const profile = {
              defaultAction,
              architectures: ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_AARCH64"],
              syscalls: [{ names: allowedSyscalls, action: "SCMP_ACT_ALLOW" }],
            };

            // TOOL-011: Validate the profile content is valid JSON (it's constructed above, so this verifies serialization)
            const json = JSON.stringify(profile, null, 2);

            if (dryRun || !outputPath) {
              return { content: [formatToolOutput({ dryRun: dryRun || !outputPath, profile, syscallCount: allowedSyscalls.length, outputPath: outputPath ?? "(stdout)" })] };
            }

            // TOOL-011: Restrict seccomp profile output to safe directory
            const safeBaseDir = resolve(SECCOMP_PROFILE_DIR);
            const resolvedOutput = resolve(outputPath);
            if (!resolvedOutput.startsWith(safeBaseDir + "/") && resolvedOutput !== safeBaseDir) {
              // If the user-provided path isn't within the safe dir, place it there instead
              const filename = outputPath.replace(/[^a-zA-Z0-9._-]/g, "_");
              const safePath = resolve(safeBaseDir, filename);
              if (!existsSync(safeBaseDir)) mkdirSync(safeBaseDir, { recursive: true });
              secureWriteFileSync(safePath, json, "utf-8");
              logChange(createChangeEntry({ tool: "container_isolation", action: "Create seccomp profile (path restricted to safe directory)", target: safePath, dryRun: false, success: true }));
              return { content: [formatToolOutput({ success: true, outputPath: safePath, note: `Output path was restricted to safe directory: ${SECCOMP_PROFILE_DIR}`, syscallCount: allowedSyscalls.length, defaultAction })] };
            }

            if (!existsSync(safeBaseDir)) mkdirSync(safeBaseDir, { recursive: true });
            // TOOL-011: Use secure-fs for the write operation
            secureWriteFileSync(resolvedOutput, json, "utf-8");

            logChange(createChangeEntry({ tool: "container_isolation", action: "Create seccomp profile", target: resolvedOutput, dryRun: false, success: true }));
            return { content: [formatToolOutput({ success: true, outputPath: resolvedOutput, syscallCount: allowedSyscalls.length, defaultAction })] };
          } catch (err: unknown) { return { content: [createErrorContent(`Seccomp profile generation failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true }; }
        }

        // ── rootless_setup ──────────────────────────────────────────
        case "rootless_setup": {
          const { username, subuidCount, dryRun } = params;
          try {
            if (!username) return { content: [createErrorContent("username is required for rootless_setup action")], isError: true };

            const safety = await SafeguardRegistry.getInstance().checkSafety("setup_rootless_containers", { username });
            const checks: Record<string, unknown> = {};

            const newuidmap = await executeCommand({ command: "which", args: ["newuidmap"], timeout: 5000 });
            checks.newuidmap = newuidmap.exitCode === 0;
            const newgidmap = await executeCommand({ command: "which", args: ["newgidmap"], timeout: 5000 });
            checks.newgidmap = newgidmap.exitCode === 0;
            const ns = await executeCommand({ command: "sysctl", args: ["-n", "kernel.unprivileged_userns_clone"], timeout: 5000 });
            checks.userNamespacesEnabled = ns.exitCode === 0 && ns.stdout.trim() === "1";
            const subuidCheck = await executeCommand({ command: "grep", args: [username, "/etc/subuid"], timeout: 5000 });
            checks.subuidConfigured = subuidCheck.exitCode === 0;

            if (dryRun) {
              return { content: [formatToolOutput({ dryRun: true, username, currentState: checks, commands: [`usermod --add-subuids 100000-${100000 + subuidCount - 1} --add-subgids 100000-${100000 + subuidCount - 1} ${username}`, "sysctl -w kernel.unprivileged_userns_clone=1"], warnings: safety.warnings })] };
            }

            const results: { step: string; success: boolean; output: string }[] = [];
            if (!checks.subuidConfigured) {
              const r = await executeCommand({ command: "usermod", args: ["--add-subuids", `100000-${100000 + subuidCount - 1}`, "--add-subgids", `100000-${100000 + subuidCount - 1}`, username], timeout: 10000 });
              results.push({ step: "Configure subuid/subgid", success: r.exitCode === 0, output: r.stderr || r.stdout });
            }
            if (!checks.userNamespacesEnabled) {
              const r = await executeCommand({ command: "sysctl", args: ["-w", "kernel.unprivileged_userns_clone=1"], timeout: 10000 });
              results.push({ step: "Enable user namespaces", success: r.exitCode === 0, output: r.stdout });
            }

            logChange(createChangeEntry({ tool: "container_isolation", action: `Configure rootless containers for ${username}`, target: username, dryRun: false, success: results.every((r) => r.success) }));
            return { content: [formatToolOutput({ username, results, checks })] };
          } catch (err: unknown) { return { content: [createErrorContent(`Rootless setup failed: ${err instanceof Error ? err.message : String(err)}`)], isError: true }; }
        }

        default:
          return { content: [createErrorContent(`Unknown action: ${action}`)], isError: true };
      }
    }
  );
}
