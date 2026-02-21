/**
 * Container and mandatory access control security tools for Kali Defense MCP Server.
 *
 * Registers 9 tools: container_docker_audit, container_docker_bench,
 * container_apparmor_manage, container_selinux_manage,
 * container_namespace_check, container_image_scan, container_seccomp_audit,
 * container_daemon_configure, container_apparmor_install.
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

// ── Registration entry point ───────────────────────────────────────────────

export function registerContainerSecurityTools(server: McpServer): void {
  // ── 1. container_docker_audit ────────────────────────────────────────────

  server.tool(
    "container_docker_audit",
    "Audit Docker security configuration: daemon settings, images, running containers, and network isolation",
    {
      check_type: z
        .enum(["daemon", "images", "containers", "network", "all"])
        .optional()
        .default("all")
        .describe("Type of Docker security check to perform (default: all)"),
    },
    async ({ check_type }) => {
      try {
        const sections: string[] = [];
        sections.push("🐳 Docker Security Audit");
        sections.push("=".repeat(50));

        const findings: Array<{ level: string; msg: string }> = [];

        // Check if Docker is available
        const dockerCheck = await executeCommand({
          command: "which",
          args: ["docker"],
          toolName: "container_docker_audit",
          timeout: 5000,
        });

        if (dockerCheck.exitCode !== 0) {
          return {
            content: [
              createTextContent(
                "Docker is not installed or not in PATH. No audit possible."
              ),
            ],
          };
        }

        // Daemon audit
        if (check_type === "daemon" || check_type === "all") {
          sections.push("\n── Docker Daemon Configuration ──");

          // Docker info
          const infoResult = await executeCommand({
            command: "docker",
            args: ["info", "--format", "{{json .}}"],
            toolName: "container_docker_audit",
            timeout: getToolTimeout("container_docker_audit"),
          });

          if (infoResult.exitCode === 0) {
            const info = parseJsonSafe(infoResult.stdout) as Record<
              string,
              unknown
            > | null;
            if (info) {
              sections.push(`  Server Version: ${info["ServerVersion"] ?? "unknown"}`);
              sections.push(`  Storage Driver: ${info["Driver"] ?? "unknown"}`);
              sections.push(`  Logging Driver: ${info["LoggingDriver"] ?? "unknown"}`);
              sections.push(`  Cgroup Driver: ${info["CgroupDriver"] ?? "unknown"}`);
              sections.push(`  Live Restore: ${info["LiveRestoreEnabled"] ?? "unknown"}`);

              // Security checks
              const securityOptions = info["SecurityOptions"] as string[] | undefined;
              if (securityOptions) {
                sections.push(`  Security Options: ${securityOptions.join(", ")}`);
                if (!securityOptions.some((o) => String(o).includes("userns"))) {
                  findings.push({
                    level: "WARNING",
                    msg: "User namespaces not enabled for Docker daemon",
                  });
                }
              }

              if (info["LiveRestoreEnabled"] !== true) {
                findings.push({
                  level: "INFO",
                  msg: "Live restore is not enabled - containers won't survive daemon restart",
                });
              }
            }
          } else {
            sections.push(
              `  ⚠️ Cannot query Docker daemon: ${infoResult.stderr}`
            );
            sections.push(
              "  Ensure Docker is running and current user has access."
            );
          }

          // Check daemon.json
          const daemonResult = await executeCommand({
            command: "cat",
            args: ["/etc/docker/daemon.json"],
            toolName: "container_docker_audit",
            timeout: 5000,
          });

          if (daemonResult.exitCode === 0) {
            sections.push("\n  Daemon config (/etc/docker/daemon.json):");
            const daemonConfig = parseJsonSafe(daemonResult.stdout) as Record<
              string,
              unknown
            > | null;
            if (daemonConfig) {
              sections.push(`  ${JSON.stringify(daemonConfig, null, 4).replace(/\n/g, "\n  ")}`);

              // Check for security settings
              if (!daemonConfig["userns-remap"]) {
                findings.push({
                  level: "WARNING",
                  msg: "userns-remap not configured in daemon.json",
                });
              }
              if (!daemonConfig["no-new-privileges"]) {
                findings.push({
                  level: "INFO",
                  msg: "no-new-privileges not set in daemon.json",
                });
              }
              if (!daemonConfig["icc"] || daemonConfig["icc"] === true) {
                findings.push({
                  level: "WARNING",
                  msg: "Inter-container communication (icc) is not disabled",
                });
              }
            } else {
              sections.push(`  ${daemonResult.stdout}`);
            }
          } else {
            sections.push(
              "\n  No /etc/docker/daemon.json found (using defaults)."
            );
            findings.push({
              level: "WARNING",
              msg: "No custom Docker daemon configuration - using defaults",
            });
          }

          // Check Docker socket permissions
          const socketResult = await executeCommand({
            command: "ls",
            args: ["-la", "/var/run/docker.sock"],
            toolName: "container_docker_audit",
            timeout: 5000,
          });

          if (socketResult.exitCode === 0) {
            sections.push(
              `\n  Docker socket: ${socketResult.stdout.trim()}`
            );
            if (socketResult.stdout.includes("rw-rw-rw")) {
              findings.push({
                level: "CRITICAL",
                msg: "Docker socket is world-writable!",
              });
            }
          }
        }

        // Images audit
        if (check_type === "images" || check_type === "all") {
          sections.push("\n── Docker Images ──");

          const imagesResult = await executeCommand({
            command: "docker",
            args: [
              "images",
              "--format",
              "{{.Repository}}:{{.Tag}} | {{.Size}} | {{.CreatedSince}} | {{.ID}}",
            ],
            toolName: "container_docker_audit",
            timeout: getToolTimeout("container_docker_audit"),
          });

          if (imagesResult.exitCode === 0 && imagesResult.stdout.trim()) {
            const imageLines = imagesResult.stdout
              .trim()
              .split("\n")
              .filter((l) => l.trim());

            sections.push(`  Total images: ${imageLines.length}`);
            sections.push(
              "\n  Repository:Tag | Size | Created | ID"
            );
            sections.push("  " + "-".repeat(60));

            let latestCount = 0;
            for (const line of imageLines) {
              sections.push(`  ${line}`);
              if (line.includes(":latest ") || line.endsWith(":latest")) {
                latestCount++;
              }
            }

            if (latestCount > 0) {
              findings.push({
                level: "WARNING",
                msg: `${latestCount} image(s) using 'latest' tag - pin specific versions for reproducibility`,
              });
            }
          } else {
            sections.push("  No Docker images found.");
          }
        }

        // Containers audit
        if (check_type === "containers" || check_type === "all") {
          sections.push("\n── Running Containers ──");

          const psResult = await executeCommand({
            command: "docker",
            args: [
              "ps",
              "--format",
              "{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}",
            ],
            toolName: "container_docker_audit",
            timeout: getToolTimeout("container_docker_audit"),
          });

          if (psResult.exitCode === 0 && psResult.stdout.trim()) {
            const containerLines = psResult.stdout
              .trim()
              .split("\n")
              .filter((l) => l.trim());

            sections.push(`  Running containers: ${containerLines.length}`);

            for (const line of containerLines) {
              const parts = line.split("|");
              const containerId = parts[0] || "unknown";
              const containerName = parts[1] || "unknown";
              const containerImage = parts[2] || "unknown";

              sections.push(`\n  Container: ${containerName} (${containerId})`);
              sections.push(`    Image: ${containerImage}`);
              sections.push(`    Status: ${parts[3] || "unknown"}`);
              sections.push(`    Ports: ${parts[4] || "none"}`);

              // Inspect for security details
              const inspectResult = await executeCommand({
                command: "docker",
                args: [
                  "inspect",
                  "--format",
                  "{{.HostConfig.Privileged}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.PidMode}}|{{.HostConfig.ReadonlyRootfs}}",
                  containerId,
                ],
                toolName: "container_docker_audit",
                timeout: 10000,
              });

              if (inspectResult.exitCode === 0) {
                const inspParts = inspectResult.stdout.trim().split("|");
                const privileged = inspParts[0] === "true";
                const networkMode = inspParts[1] || "default";
                const pidMode = inspParts[2] || "";
                const readonlyRoot = inspParts[3] === "true";

                sections.push(`    Privileged: ${privileged}`);
                sections.push(`    Network Mode: ${networkMode}`);
                sections.push(`    PID Mode: ${pidMode || "container"}`);
                sections.push(`    Read-only Root: ${readonlyRoot}`);

                if (privileged) {
                  findings.push({
                    level: "CRITICAL",
                    msg: `Container '${containerName}' is running in privileged mode!`,
                  });
                }
                if (networkMode === "host") {
                  findings.push({
                    level: "WARNING",
                    msg: `Container '${containerName}' uses host networking`,
                  });
                }
                if (pidMode === "host") {
                  findings.push({
                    level: "WARNING",
                    msg: `Container '${containerName}' shares host PID namespace`,
                  });
                }
                if (!readonlyRoot) {
                  findings.push({
                    level: "INFO",
                    msg: `Container '${containerName}' root filesystem is writable`,
                  });
                }
              }

              // ── Volume mount security analysis ────────────────────────
              const mountInspect = await executeCommand({
                command: "docker",
                args: [
                  "inspect",
                  "--format",
                  "{{json .Mounts}}",
                  containerId,
                ],
                toolName: "container_docker_audit",
                timeout: 10000,
              });

              if (mountInspect.exitCode === 0 && mountInspect.stdout.trim()) {
                const mounts = parseJsonSafe(mountInspect.stdout.trim()) as Array<{
                  Type?: string;
                  Source?: string;
                  Destination?: string;
                  Mode?: string;
                  RW?: boolean;
                }> | null;

                if (mounts && mounts.length > 0) {
                  sections.push(`    Mounts: ${mounts.length} volume(s)`);
                  for (const mount of mounts) {
                    const src = mount.Source || "";
                    const dst = mount.Destination || "";
                    const mode = mount.RW ? "rw" : "ro";
                    sections.push(`      ${src} → ${dst} (${mode})`);

                    // Flag dangerous mount patterns
                    if (src === "/var/run/docker.sock" || dst === "/var/run/docker.sock") {
                      findings.push({
                        level: "CRITICAL",
                        msg: `Container '${containerName}': Docker socket mounted — container has full host control`,
                      });
                    }
                    if (src === "/") {
                      findings.push({
                        level: "CRITICAL",
                        msg: `Container '${containerName}': Root filesystem '/' mounted from host`,
                      });
                    }
                    if ((src === "/home" || src.startsWith("/home/") || src === "/root" || src.startsWith("/root/")) && mount.RW) {
                      findings.push({
                        level: "WARNING",
                        msg: `Container '${containerName}': Home directory '${src}' mounted read-write`,
                      });
                    }
                    if ((src === "/etc" || src.startsWith("/etc/")) && mount.RW) {
                      findings.push({
                        level: "WARNING",
                        msg: `Container '${containerName}': System config '${src}' mounted read-write`,
                      });
                    }
                    if (src === "/proc" || src === "/sys" || src.startsWith("/proc/") || src.startsWith("/sys/")) {
                      findings.push({
                        level: "INFO",
                        msg: `Container '${containerName}': Kernel interface '${src}' exposed`,
                      });
                    }
                  }
                } else {
                  sections.push("    Mounts: none");
                }
              }
            }
          } else {
            sections.push("  No running containers.");
          }
        }

        // Network audit
        if (check_type === "network" || check_type === "all") {
          sections.push("\n── Docker Networks ──");

          const netResult = await executeCommand({
            command: "docker",
            args: [
              "network",
              "ls",
              "--format",
              "{{.Name}} | {{.Driver}} | {{.Scope}}",
            ],
            toolName: "container_docker_audit",
            timeout: getToolTimeout("container_docker_audit"),
          });

          if (netResult.exitCode === 0 && netResult.stdout.trim()) {
            sections.push("  Name | Driver | Scope");
            sections.push("  " + "-".repeat(40));
            for (const line of netResult.stdout.trim().split("\n")) {
              sections.push(`  ${line}`);
            }
          } else {
            sections.push("  No Docker networks found.");
          }
        }

        // Summary
        sections.push("\n── Security Findings Summary ──");
        if (findings.length === 0) {
          sections.push("  ✅ No significant security issues found.");
        } else {
          const criticals = findings.filter((f) => f.level === "CRITICAL");
          const warnings = findings.filter((f) => f.level === "WARNING");
          const infos = findings.filter((f) => f.level === "INFO");

          if (criticals.length > 0) {
            sections.push(`\n  ⛔ Critical (${criticals.length}):`);
            for (const f of criticals) sections.push(`    - ${f.msg}`);
          }
          if (warnings.length > 0) {
            sections.push(`\n  ⚠️ Warnings (${warnings.length}):`);
            for (const f of warnings) sections.push(`    - ${f.msg}`);
          }
          if (infos.length > 0) {
            sections.push(`\n  ℹ️ Info (${infos.length}):`);
            for (const f of infos) sections.push(`    - ${f.msg}`);
          }
        }

        return { content: [createTextContent(sections.join("\n"))] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 2. container_docker_bench ────────────────────────────────────────────

  server.tool(
    "container_docker_bench",
    "Run Docker Bench for Security to check Docker host and daemon configuration against CIS benchmarks",
    {
      checks: z
        .string()
        .optional()
        .describe(
          "Specific check sections to run, e.g. '1,2,4'. Omit for all checks."
        ),
      log_level: z
        .enum(["INFO", "WARN", "NOTE", "PASS"])
        .optional()
        .default("WARN")
        .describe("Minimum log level to display (default: WARN)"),
    },
    async ({ checks, log_level }) => {
      try {
        const sections: string[] = [];
        sections.push("🔒 Docker Bench for Security");
        sections.push("=".repeat(50));

        // Check if docker-bench-security is available locally
        const localCheck = await executeCommand({
          command: "which",
          args: ["docker-bench-security"],
          toolName: "container_docker_bench",
          timeout: 5000,
        });

        const dockerCheck = await executeCommand({
          command: "which",
          args: ["docker"],
          toolName: "container_docker_bench",
          timeout: 5000,
        });

        if (dockerCheck.exitCode !== 0) {
          return {
            content: [
              createTextContent(
                "Docker is not installed. Docker Bench requires Docker to run."
              ),
            ],
          };
        }

        // Build the docker run command for docker-bench-security
        const benchArgs = [
          "run",
          "--rm",
          "--net",
          "host",
          "--pid",
          "host",
          "--userns",
          "host",
          "--cap-add",
          "audit_control",
          "-v",
          "/etc:/etc:ro",
          "-v",
          "/var/lib:/var/lib:ro",
          "-v",
          "/var/run/docker.sock:/var/run/docker.sock:ro",
          "-v",
          "/usr/lib/systemd:/usr/lib/systemd:ro",
          "-v",
          "/usr/bin/containerd:/usr/bin/containerd:ro",
          "-v",
          "/usr/bin/runc:/usr/bin/runc:ro",
          "docker/docker-bench-security",
        ];

        if (checks) {
          sanitizeArgs([checks]);
          benchArgs.push("-c", checks);
        }

        sections.push("\nRunning Docker Bench for Security...");
        sections.push(
          "(This may take a few minutes)\n"
        );

        const result = await executeCommand({
          command: "docker",
          args: benchArgs,
          toolName: "container_docker_bench",
          timeout: 300000, // 5 minutes
        });

        const output = result.stdout || result.stderr;

        if (result.exitCode !== 0 && !output) {
          sections.push(
            "⚠️ Docker Bench could not run. The image may need to be pulled first."
          );
          sections.push(
            "\nTo install: docker pull docker/docker-bench-security"
          );
          sections.push(
            `\nError: ${result.stderr}`
          );
          return { content: [createTextContent(sections.join("\n"))] };
        }

        // Parse and filter output
        const outputLines = output.split("\n");
        const levelPriority: Record<string, number> = {
          PASS: 0,
          INFO: 1,
          NOTE: 2,
          WARN: 3,
        };
        const minLevel = levelPriority[log_level] ?? 0;

        let passCount = 0;
        let warnCount = 0;
        let infoCount = 0;
        let noteCount = 0;

        const filteredLines: string[] = [];

        for (const line of outputLines) {
          if (line.includes("[PASS]")) passCount++;
          if (line.includes("[WARN]")) warnCount++;
          if (line.includes("[INFO]")) infoCount++;
          if (line.includes("[NOTE]")) noteCount++;

          // Include section headers always
          if (line.match(/^\[INFO\]\s+\d+\s+-\s+/) || line.startsWith("# ")) {
            filteredLines.push(line);
            continue;
          }

          // Filter by level
          let lineLevel = -1;
          if (line.includes("[PASS]")) lineLevel = 0;
          if (line.includes("[INFO]")) lineLevel = 1;
          if (line.includes("[NOTE]")) lineLevel = 2;
          if (line.includes("[WARN]")) lineLevel = 3;

          if (lineLevel >= minLevel) {
            filteredLines.push(line);
          }
        }

        sections.push("── Results ──");
        sections.push(filteredLines.join("\n"));

        sections.push("\n── Summary ──");
        sections.push(`  [PASS]: ${passCount}`);
        sections.push(`  [WARN]: ${warnCount}`);
        sections.push(`  [INFO]: ${infoCount}`);
        sections.push(`  [NOTE]: ${noteCount}`);

        return { content: [createTextContent(sections.join("\n"))] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 3. container_apparmor_manage ─────────────────────────────────────────

  server.tool(
    "container_apparmor_manage",
    "Manage AppArmor security profiles: check status, list profiles, set enforcement mode",
    {
      action: z
        .enum(["status", "list", "enforce", "complain", "disable"])
        .describe("AppArmor management action"),
      profile: z
        .string()
        .optional()
        .describe("Profile name (required for enforce/complain/disable)"),
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview changes without executing (defaults to KALI_DEFENSE_DRY_RUN env var)"),
    },
    async ({ action, profile, dry_run }) => {
      try {
        const sections: string[] = [];
        sections.push(`🛡️ AppArmor Management: ${action}`);
        sections.push("=".repeat(40));

        switch (action) {
          case "status": {
            // Try apparmor_status first, fall back to aa-status
            let result = await executeCommand({
              command: "sudo",
              args: ["apparmor_status"],
              toolName: "container_apparmor_manage",
              timeout: getToolTimeout("container_apparmor_manage"),
            });

            if (result.exitCode !== 0) {
              result = await executeCommand({
                command: "sudo",
                args: ["aa-status"],
                toolName: "container_apparmor_manage",
                timeout: getToolTimeout("container_apparmor_manage"),
              });
            }

            if (result.exitCode !== 0) {
              sections.push(
                "\n⚠️ AppArmor may not be installed or enabled."
              );
              sections.push(`Output: ${result.stderr || result.stdout}`);

              // Check if the module is loaded
              const moduleResult = await executeCommand({
                command: "cat",
                args: ["/sys/module/apparmor/parameters/enabled"],
                toolName: "container_apparmor_manage",
                timeout: 5000,
              });

              if (moduleResult.exitCode === 0) {
                const enabled = moduleResult.stdout.trim();
                sections.push(
                  `\nAppArmor kernel module: ${enabled === "Y" ? "Enabled" : "Disabled"}`
                );
              }
            } else {
              sections.push("\n" + result.stdout);
            }
            break;
          }

          case "list": {
            let result = await executeCommand({
              command: "sudo",
              args: ["aa-status"],
              toolName: "container_apparmor_manage",
              timeout: getToolTimeout("container_apparmor_manage"),
            });

            if (result.exitCode !== 0) {
              result = await executeCommand({
                command: "sudo",
                args: ["apparmor_status"],
                toolName: "container_apparmor_manage",
                timeout: getToolTimeout("container_apparmor_manage"),
              });
            }

            if (result.exitCode !== 0) {
              sections.push("\n⚠️ Cannot list AppArmor profiles.");
              sections.push(result.stderr || result.stdout);
              break;
            }

            // Parse profiles from output
            const output = result.stdout;
            const enforceMatch = output.match(
              /(\d+)\s+profiles? are in enforce mode/
            );
            const complainMatch = output.match(
              /(\d+)\s+profiles? are in complain mode/
            );

            if (enforceMatch) {
              sections.push(
                `\n  Profiles in enforce mode: ${enforceMatch[1]}`
              );
            }
            if (complainMatch) {
              sections.push(
                `  Profiles in complain mode: ${complainMatch[1]}`
              );
            }

            // List individual profiles
            const lines = output.split("\n");
            let currentSection = "";

            for (const line of lines) {
              const trimmed = line.trim();
              if (trimmed.includes("enforce mode")) {
                currentSection = "enforce";
                sections.push("\n  🔒 Enforce Mode:");
              } else if (trimmed.includes("complain mode")) {
                currentSection = "complain";
                sections.push("\n  📝 Complain Mode:");
              } else if (trimmed.includes("unconfined")) {
                currentSection = "unconfined";
                sections.push("\n  ⚠️ Unconfined:");
              } else if (
                currentSection &&
                trimmed &&
                !trimmed.match(/^\d+\s+processes/)
              ) {
                sections.push(`    ${trimmed}`);
              }
            }
            break;
          }

          case "enforce":
          case "complain":
          case "disable": {
            if (!profile) {
              return {
                content: [
                  createErrorContent(
                    `profile name is required for '${action}' action`
                  ),
                ],
                isError: true,
              };
            }

            sanitizeArgs([profile]);

            const cmdMap: Record<string, string> = {
              enforce: "aa-enforce",
              complain: "aa-complain",
              disable: "aa-disable",
            };
            const cmd = cmdMap[action];

            if (dry_run ?? getConfig().dryRun) {
              sections.push(
                `\n[DRY RUN] Would set profile '${profile}' to ${action} mode.`
              );
              sections.push(`  Command: sudo ${cmd} ${profile}`);
            } else {
              const result = await executeCommand({
                command: "sudo",
                args: [cmd, profile],
                toolName: "container_apparmor_manage",
                timeout: getToolTimeout("container_apparmor_manage"),
              });

              if (result.exitCode !== 0) {
                return {
                  content: [
                    createErrorContent(
                      `Failed to ${action} profile '${profile}': ${result.stderr}`
                    ),
                  ],
                  isError: true,
                };
              }

              sections.push(
                `\n✅ Profile '${profile}' set to ${action} mode.`
              );
              sections.push(result.stdout || result.stderr);

              logChange(
                createChangeEntry({
                  tool: "container_apparmor_manage",
                  action: action,
                  target: profile,
                  after: `${action} mode`,
                  dryRun: false,
                  success: true,
                  rollbackCommand:
                    action === "disable"
                      ? `sudo aa-enforce ${profile}`
                      : undefined,
                })
              );
            }
            break;
          }
        }

        return { content: [createTextContent(sections.join("\n"))] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 4. container_selinux_manage ──────────────────────────────────────────

  server.tool(
    "container_selinux_manage",
    "Manage SELinux settings: check status, get/set enforcement mode, manage booleans, audit denials",
    {
      action: z
        .enum(["status", "getenforce", "setenforce", "booleans", "audit"])
        .describe("SELinux management action"),
      mode: z
        .enum(["enforcing", "permissive", "disabled"])
        .optional()
        .describe("SELinux mode (for setenforce action)"),
      boolean_name: z
        .string()
        .optional()
        .describe("SELinux boolean name (for booleans action)"),
      boolean_value: z
        .enum(["on", "off"])
        .optional()
        .describe("SELinux boolean value (for setting a boolean)"),
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview changes without executing (defaults to KALI_DEFENSE_DRY_RUN env var)"),
    },
    async ({ action, mode, boolean_name, boolean_value, dry_run }) => {
      try {
        const sections: string[] = [];
        sections.push(`🛡️ SELinux Management: ${action}`);
        sections.push("=".repeat(40));

        switch (action) {
          case "status": {
            const result = await executeCommand({
              command: "sestatus",
              args: [],
              toolName: "container_selinux_manage",
              timeout: getToolTimeout("container_selinux_manage"),
            });

            if (result.exitCode !== 0) {
              sections.push(
                "\n⚠️ SELinux may not be installed or available on this system."
              );
              sections.push(result.stderr || result.stdout);

              // Try checking if SELinux is compiled into the kernel
              const fsResult = await executeCommand({
                command: "cat",
                args: ["/proc/filesystems"],
                toolName: "container_selinux_manage",
                timeout: 5000,
              });

              if (fsResult.exitCode === 0) {
                if (fsResult.stdout.includes("selinuxfs")) {
                  sections.push(
                    "\nSELinux filesystem is available but tools may not be installed."
                  );
                } else {
                  sections.push(
                    "\nSELinux filesystem not found - SELinux not compiled into kernel."
                  );
                }
              }
            } else {
              sections.push("\n" + result.stdout);
            }
            break;
          }

          case "getenforce": {
            const result = await executeCommand({
              command: "getenforce",
              args: [],
              toolName: "container_selinux_manage",
              timeout: getToolTimeout("container_selinux_manage"),
            });

            if (result.exitCode !== 0) {
              sections.push(
                "\n⚠️ getenforce not available - SELinux may not be installed."
              );
              sections.push(result.stderr || result.stdout);
            } else {
              const currentMode = result.stdout.trim();
              sections.push(`\nCurrent SELinux mode: ${currentMode}`);

              if (currentMode === "Disabled") {
                sections.push(
                  "  ⚠️ SELinux is disabled. Consider enabling for enhanced security."
                );
              } else if (currentMode === "Permissive") {
                sections.push(
                  "  ⚠️ SELinux is permissive - logging violations but not enforcing."
                );
              } else if (currentMode === "Enforcing") {
                sections.push("  ✅ SELinux is actively enforcing policies.");
              }
            }
            break;
          }

          case "setenforce": {
            if (!mode) {
              return {
                content: [
                  createErrorContent(
                    "mode is required for setenforce (enforcing or permissive)"
                  ),
                ],
                isError: true,
              };
            }

            if (mode === "disabled") {
              sections.push(
                "\n⚠️ Cannot disable SELinux at runtime with setenforce."
              );
              sections.push(
                "Edit /etc/selinux/config and reboot to fully disable SELinux."
              );
              break;
            }

            const modeValue = mode === "enforcing" ? "1" : "0";

            if (dry_run ?? getConfig().dryRun) {
              sections.push(
                `\n[DRY RUN] Would set SELinux to ${mode} mode.`
              );
              sections.push(
                `  Command: sudo setenforce ${modeValue}`
              );
            } else {
              const result = await executeCommand({
                command: "sudo",
                args: ["setenforce", modeValue],
                toolName: "container_selinux_manage",
                timeout: getToolTimeout("container_selinux_manage"),
              });

              if (result.exitCode !== 0) {
                return {
                  content: [
                    createErrorContent(
                      `Failed to set SELinux mode: ${result.stderr}`
                    ),
                  ],
                  isError: true,
                };
              }

              sections.push(
                `\n✅ SELinux mode set to ${mode}.`
              );

              logChange(
                createChangeEntry({
                  tool: "container_selinux_manage",
                  action: "setenforce",
                  target: "SELinux",
                  after: mode,
                  dryRun: false,
                  success: true,
                  rollbackCommand: `sudo setenforce ${mode === "enforcing" ? "0" : "1"}`,
                })
              );
            }
            break;
          }

          case "booleans": {
            if (boolean_name && boolean_value) {
              // Set a specific boolean
              sanitizeArgs([boolean_name]);

              if (dry_run ?? getConfig().dryRun) {
                sections.push(
                  `\n[DRY RUN] Would set SELinux boolean '${boolean_name}' to ${boolean_value}.`
                );
                sections.push(
                  `  Command: sudo setsebool -P ${boolean_name} ${boolean_value}`
                );
              } else {
                const result = await executeCommand({
                  command: "sudo",
                  args: [
                    "setsebool",
                    "-P",
                    boolean_name,
                    boolean_value,
                  ],
                  toolName: "container_selinux_manage",
                  timeout: getToolTimeout("container_selinux_manage"),
                });

                if (result.exitCode !== 0) {
                  return {
                    content: [
                      createErrorContent(
                        `Failed to set boolean '${boolean_name}': ${result.stderr}`
                      ),
                    ],
                    isError: true,
                  };
                }

                sections.push(
                  `\n✅ SELinux boolean '${boolean_name}' set to ${boolean_value}.`
                );

                logChange(
                  createChangeEntry({
                    tool: "container_selinux_manage",
                    action: "set_boolean",
                    target: boolean_name,
                    after: boolean_value,
                    dryRun: false,
                    success: true,
                    rollbackCommand: `sudo setsebool -P ${boolean_name} ${boolean_value === "on" ? "off" : "on"}`,
                  })
                );
              }
            } else if (boolean_name) {
              // Get a specific boolean
              sanitizeArgs([boolean_name]);

              const result = await executeCommand({
                command: "getsebool",
                args: [boolean_name],
                toolName: "container_selinux_manage",
                timeout: getToolTimeout("container_selinux_manage"),
              });

              if (result.exitCode !== 0) {
                return {
                  content: [
                    createErrorContent(
                      `Failed to get boolean '${boolean_name}': ${result.stderr}`
                    ),
                  ],
                  isError: true,
                };
              }

              sections.push(`\n${result.stdout.trim()}`);
            } else {
              // List all booleans
              const result = await executeCommand({
                command: "getsebool",
                args: ["-a"],
                toolName: "container_selinux_manage",
                timeout: getToolTimeout("container_selinux_manage"),
              });

              if (result.exitCode !== 0) {
                sections.push(
                  "\n⚠️ Cannot list SELinux booleans."
                );
                sections.push(result.stderr || result.stdout);
              } else {
                const lines = result.stdout
                  .trim()
                  .split("\n")
                  .filter((l) => l.trim());
                sections.push(`\nSELinux Booleans (${lines.length} total):`);
                sections.push(result.stdout);
              }
            }
            break;
          }

          case "audit": {
            const result = await executeCommand({
              command: "sudo",
              args: ["ausearch", "-m", "AVC", "-ts", "recent"],
              toolName: "container_selinux_manage",
              timeout: getToolTimeout("container_selinux_manage"),
            });

            if (result.exitCode !== 0) {
              if (
                result.stderr.includes("no matches") ||
                result.stdout.includes("no matches")
              ) {
                sections.push(
                  "\n✅ No recent SELinux AVC denials found."
                );
              } else {
                sections.push(
                  "\n⚠️ Could not search audit logs."
                );
                sections.push(result.stderr || result.stdout);
              }
            } else {
              const output = result.stdout;
              const denials = output
                .split("\n")
                .filter((l) => l.includes("avc:"));

              sections.push(
                `\n⚠️ Recent SELinux AVC Denials (${denials.length}):`
              );
              sections.push(output);
            }
            break;
          }
        }

        return { content: [createTextContent(sections.join("\n"))] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 5. container_namespace_check ─────────────────────────────────────────

  server.tool(
    "container_namespace_check",
    "Check Linux namespace isolation for processes and system-wide namespace configuration",
    {
      pid: z
        .number()
        .optional()
        .describe(
          "Process ID to inspect namespaces for. Omit for system overview."
        ),
      check_type: z
        .enum(["user", "network", "pid", "mount", "all"])
        .optional()
        .default("all")
        .describe("Type of namespace check (default: all)"),
    },
    async ({ pid, check_type }) => {
      try {
        const sections: string[] = [];
        sections.push("📦 Namespace Isolation Check");
        sections.push("=".repeat(40));

        if (pid !== undefined) {
          // Check specific process namespaces
          sections.push(`\nProcess PID: ${pid}`);

          const nsResult = await executeCommand({
            command: "ls",
            args: ["-la", `/proc/${pid}/ns/`],
            toolName: "container_namespace_check",
            timeout: getToolTimeout("container_namespace_check"),
          });

          if (nsResult.exitCode !== 0) {
            return {
              content: [
                createErrorContent(
                  `Cannot read namespaces for PID ${pid}: ${nsResult.stderr}. Process may not exist.`
                ),
              ],
              isError: true,
            };
          }

          sections.push("\nNamespace symlinks:");
          sections.push(nsResult.stdout);

          // Get process info
          const commResult = await executeCommand({
            command: "cat",
            args: [`/proc/${pid}/comm`],
            toolName: "container_namespace_check",
            timeout: 5000,
          });

          if (commResult.exitCode === 0) {
            sections.push(
              `Process name: ${commResult.stdout.trim()}`
            );
          }

          // Compare with init (PID 1) to detect isolation
          const initNsResult = await executeCommand({
            command: "ls",
            args: ["-la", "/proc/1/ns/"],
            toolName: "container_namespace_check",
            timeout: 5000,
          });

          if (initNsResult.exitCode === 0) {
            sections.push("\nNamespace comparison with PID 1 (init):");

            const nsTypes = [
              "user",
              "net",
              "pid",
              "mnt",
              "uts",
              "ipc",
              "cgroup",
            ];
            const pidNsLines = nsResult.stdout.split("\n");
            const initNsLines = initNsResult.stdout.split("\n");

            for (const ns of nsTypes) {
              if (
                check_type !== "all" &&
                !ns.startsWith(check_type.substring(0, 3))
              ) {
                continue;
              }

              const pidLine = pidNsLines.find((l) =>
                l.includes(`${ns} ->`)
              );
              const initLine = initNsLines.find((l) =>
                l.includes(`${ns} ->`)
              );

              if (pidLine && initLine) {
                const pidInode = pidLine.match(/\[(\d+)\]/)?.[1] || "unknown";
                const initInode =
                  initLine.match(/\[(\d+)\]/)?.[1] || "unknown";

                if (pidInode === initInode) {
                  sections.push(
                    `  ${ns}: Same as init (not isolated)`
                  );
                } else {
                  sections.push(
                    `  ${ns}: ✅ Different from init (isolated) [${pidInode} vs ${initInode}]`
                  );
                }
              }
            }
          }
        } else {
          // System-wide namespace overview
          sections.push("\n── System Namespace Configuration ──");

          // Check user namespace support
          if (check_type === "user" || check_type === "all") {
            sections.push("\n🔑 User Namespaces:");

            const maxNsResult = await executeCommand({
              command: "cat",
              args: ["/proc/sys/user/max_user_namespaces"],
              toolName: "container_namespace_check",
              timeout: 5000,
            });

            if (maxNsResult.exitCode === 0) {
              const maxNs = maxNsResult.stdout.trim();
              sections.push(
                `  max_user_namespaces: ${maxNs}`
              );
              if (maxNs === "0") {
                sections.push(
                  "  ⚠️ User namespaces are disabled (max=0)"
                );
              } else {
                sections.push("  ✅ User namespaces are enabled");
              }
            }

            const unprivResult = await executeCommand({
              command: "cat",
              args: ["/proc/sys/kernel/unprivileged_userns_clone"],
              toolName: "container_namespace_check",
              timeout: 5000,
            });

            if (unprivResult.exitCode === 0) {
              const enabled = unprivResult.stdout.trim();
              sections.push(
                `  unprivileged_userns_clone: ${enabled}`
              );
              if (enabled === "1") {
                sections.push(
                  "  ⚠️ Unprivileged user namespace creation is allowed"
                );
              } else {
                sections.push(
                  "  ✅ Unprivileged user namespace creation is restricted"
                );
              }
            }
          }

          // Check network namespaces
          if (check_type === "network" || check_type === "all") {
            sections.push("\n🌐 Network Namespaces:");

            const netnsResult = await executeCommand({
              command: "ip",
              args: ["netns", "list"],
              toolName: "container_namespace_check",
              timeout: getToolTimeout("container_namespace_check"),
            });

            if (netnsResult.exitCode === 0 && netnsResult.stdout.trim()) {
              const namespaces = netnsResult.stdout
                .trim()
                .split("\n")
                .filter((l) => l.trim());
              sections.push(
                `  Named network namespaces: ${namespaces.length}`
              );
              for (const ns of namespaces) {
                sections.push(`    - ${ns.trim()}`);
              }
            } else {
              sections.push("  No named network namespaces found.");
            }
          }

          // List all namespaces via lsns
          if (check_type === "all" || check_type === "pid") {
            sections.push("\n📋 All Active Namespaces (lsns):");

            const lsnsResult = await executeCommand({
              command: "lsns",
              args: [],
              toolName: "container_namespace_check",
              timeout: getToolTimeout("container_namespace_check"),
            });

            if (lsnsResult.exitCode === 0) {
              sections.push(lsnsResult.stdout);
            } else {
              // Try with sudo
              const sudoResult = await executeCommand({
                command: "sudo",
                args: ["lsns"],
                toolName: "container_namespace_check",
                timeout: getToolTimeout("container_namespace_check"),
              });

              if (sudoResult.exitCode === 0) {
                sections.push(sudoResult.stdout);
              } else {
                sections.push(
                  "  ⚠️ Cannot list namespaces. lsns may not be available."
                );
              }
            }
          }

          // Check mount namespace isolation
          if (check_type === "mount" || check_type === "all") {
            sections.push("\n📁 Mount Namespace Info:");

            const mountInfoResult = await executeCommand({
              command: "cat",
              args: ["/proc/self/mountinfo"],
              toolName: "container_namespace_check",
              timeout: 5000,
            });

            if (mountInfoResult.exitCode === 0) {
              const mountLines = mountInfoResult.stdout
                .trim()
                .split("\n");
              sections.push(
                `  Current mount namespace has ${mountLines.length} mount points`
              );
            }
          }
        }

        return { content: [createTextContent(sections.join("\n"))] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── container_image_scan ──────────────────────────────────────────────
  server.tool(
    "container_image_scan",
    "Scan Docker container images for known vulnerabilities using Trivy or Grype (if installed).",
    {
      image: z.string().describe("Docker image name/ID to scan, e.g. 'nginx:latest'"),
      severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "ALL"]).optional().default("HIGH").describe("Minimum severity to report"),
    },
    async (params) => {
      try {
        // Try Trivy first
        const trivyResult = await executeCommand({
          command: "trivy",
          args: ["image", "--severity", params.severity === "ALL" ? "CRITICAL,HIGH,MEDIUM,LOW" : `CRITICAL${params.severity !== "CRITICAL" ? ",HIGH" : ""}${params.severity === "MEDIUM" || params.severity === "LOW" ? ",MEDIUM" : ""}${params.severity === "LOW" ? ",LOW" : ""}`, "--format", "json", params.image],
          timeout: 300000,
          toolName: "container_image_scan",
        });
        if (trivyResult.exitCode === 0) {
          return { content: [createTextContent(`Trivy scan results for ${params.image}:\n${trivyResult.stdout.substring(0, 8000)}`)] };
        }

        // Fall back to Grype
        const grypeResult = await executeCommand({
          command: "grype",
          args: [params.image, "-o", "json"],
          timeout: 300000,
          toolName: "container_image_scan",
        });
        if (grypeResult.exitCode === 0) {
          return { content: [createTextContent(`Grype scan results for ${params.image}:\n${grypeResult.stdout.substring(0, 8000)}`)] };
        }

        return { content: [createTextContent(JSON.stringify({ error: "Neither Trivy nor Grype is installed", recommendation: "Install Trivy: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin", alternative: "Or install Grype: curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin" }, null, 2))] };
      } catch (error) {
        return { content: [createErrorContent(error instanceof Error ? error.message : String(error))], isError: true };
      }
    },
  );

  // ── container_seccomp_audit ───────────────────────────────────────────
  server.tool(
    "container_seccomp_audit",
    "Audit Docker containers for seccomp profile configuration. Containers should use seccomp profiles to restrict system calls.",
    {},
    async () => {
      try {
        const psResult = await executeCommand({ command: "docker", args: ["ps", "--format", "{{.ID}} {{.Names}} {{.Image}}"], timeout: 10000, toolName: "container_seccomp_audit" });
        if (psResult.exitCode !== 0) {
          return { content: [createTextContent("Docker is not available or not running")] };
        }

        const containers = psResult.stdout.trim().split("\n").filter((l: string) => l.trim());
        const results = [];

        for (const line of containers) {
          const [id, name, image] = line.split(" ");
          if (!id) continue;
          const inspectResult = await executeCommand({
            command: "docker",
            args: ["inspect", "--format", '{{.HostConfig.SecurityOpt}}', id],
            timeout: 10000,
            toolName: "container_seccomp_audit",
          });
          const secOpt = inspectResult.stdout.trim();
          const hasSeccomp = secOpt.includes("seccomp");
          const unconfined = secOpt.includes("seccomp=unconfined");
          results.push({
            container: name || id,
            image: image || "unknown",
            securityOpt: secOpt,
            seccompEnabled: hasSeccomp && !unconfined,
            status: unconfined ? "FAIL" : hasSeccomp ? "PASS" : secOpt === "[]" ? "WARN" : "PASS",
            note: unconfined ? "seccomp explicitly disabled — HIGH RISK" : !hasSeccomp && secOpt === "[]" ? "Using Docker default seccomp (acceptable)" : "seccomp configured",
          });
        }

        return { content: [createTextContent(JSON.stringify({
          summary: { total: results.length, pass: results.filter(r => r.status === "PASS").length, warn: results.filter(r => r.status === "WARN").length, fail: results.filter(r => r.status === "FAIL").length },
          containers: results,
        }, null, 2))] };
      } catch (error) {
        return { content: [createErrorContent(error instanceof Error ? error.message : String(error))], isError: true };
      }
    },
  );

  // ── 8. container_daemon_configure ───────────────────────────────────────
  server.tool(
    "container_daemon_configure",
    "Audit or apply Docker daemon security settings in /etc/docker/daemon.json (userns-remap, no-new-privileges, icc, logging, live-restore)",
    {
      action: z
        .enum(["audit", "apply"])
        .describe("Whether to audit current settings or apply new ones"),
      settings: z
        .object({
          userns_remap: z.boolean().optional().describe("Enable user namespace remapping"),
          no_new_privileges: z.boolean().optional().describe("Set no-new-privileges default"),
          icc: z.boolean().optional().describe("Inter-container communication (false = disabled)"),
          live_restore: z.boolean().optional().describe("Enable live restore"),
          log_driver: z.enum(["json-file", "journald"]).optional().describe("Logging driver"),
          log_max_size: z.string().optional().default("10m").describe("Max log file size"),
          log_max_file: z.string().optional().default("3").describe("Max number of log files"),
        })
        .optional()
        .describe("Settings to apply (required for action=apply)"),
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview changes without executing (defaults to KALI_DEFENSE_DRY_RUN env var)"),
    },
    async ({ action, settings, dry_run }) => {
      try {
        const sections: string[] = [];
        sections.push("🐳 Docker Daemon Configuration");
        sections.push("=".repeat(50));

        const daemonPath = "/etc/docker/daemon.json";

        // Read existing daemon.json
        const readResult = await executeCommand({
          command: "cat",
          args: [daemonPath],
          toolName: "container_daemon_configure",
          timeout: 5000,
        });

        const existingConfig = readResult.exitCode === 0
          ? (parseJsonSafe(readResult.stdout) as Record<string, unknown>) || {}
          : {};

        if (action === "audit") {
          sections.push("\n── Current Daemon Configuration ──");

          if (readResult.exitCode !== 0) {
            sections.push("  ⚠️ No /etc/docker/daemon.json found (using Docker defaults)");
          } else {
            sections.push(`  ${JSON.stringify(existingConfig, null, 4).replace(/\n/g, "\n  ")}`);
          }

          sections.push("\n── Security Settings Audit ──");

          const checks = [
            { key: "userns-remap", present: !!existingConfig["userns-remap"], recommended: '"default"', severity: "HIGH" },
            { key: "no-new-privileges", present: !!existingConfig["no-new-privileges"], recommended: "true", severity: "MEDIUM" },
            { key: "icc", present: existingConfig["icc"] === false, recommended: "false", severity: "HIGH" },
            { key: "live-restore", present: !!existingConfig["live-restore"], recommended: "true", severity: "LOW" },
            { key: "log-driver", present: !!existingConfig["log-driver"], recommended: '"json-file" or "journald"', severity: "LOW" },
            { key: "log-opts", present: !!existingConfig["log-opts"], recommended: '{"max-size": "10m", "max-file": "3"}', severity: "LOW" },
          ];

          let missingCount = 0;
          for (const c of checks) {
            const status = c.present ? "✅ Present" : "❌ Missing";
            if (!c.present) missingCount++;
            sections.push(`  ${status}: ${c.key} (recommended: ${c.recommended}) [${c.severity}]`);
          }

          sections.push(`\n  Summary: ${checks.length - missingCount}/${checks.length} security settings configured`);

          return { content: [createTextContent(sections.join("\n"))] };
        }

        // action === "apply"
        if (!settings) {
          return {
            content: [createErrorContent("settings parameter is required for action=apply")],
            isError: true,
          };
        }

        const isDryRun = dry_run ?? getConfig().dryRun;
        const changes: string[] = [];
        const newConfig = { ...existingConfig };

        // Map settings to daemon.json keys
        if (settings.userns_remap !== undefined) {
          const val = settings.userns_remap ? "default" : undefined;
          if (settings.userns_remap) {
            newConfig["userns-remap"] = val;
            changes.push(`userns-remap: "${val}"`);
          } else if (newConfig["userns-remap"]) {
            delete newConfig["userns-remap"];
            changes.push("userns-remap: removed");
          }
        }

        if (settings.no_new_privileges !== undefined) {
          newConfig["no-new-privileges"] = settings.no_new_privileges;
          changes.push(`no-new-privileges: ${settings.no_new_privileges}`);
        }

        if (settings.icc !== undefined) {
          newConfig["icc"] = settings.icc;
          changes.push(`icc: ${settings.icc}`);
        }

        if (settings.live_restore !== undefined) {
          newConfig["live-restore"] = settings.live_restore;
          changes.push(`live-restore: ${settings.live_restore}`);
        }

        if (settings.log_driver !== undefined) {
          newConfig["log-driver"] = settings.log_driver;
          changes.push(`log-driver: "${settings.log_driver}"`);
        }

        if (settings.log_driver || settings.log_max_size || settings.log_max_file) {
          const logOpts = (newConfig["log-opts"] as Record<string, string>) || {};
          if (settings.log_max_size) {
            logOpts["max-size"] = settings.log_max_size;
            changes.push(`log-opts.max-size: "${settings.log_max_size}"`);
          }
          if (settings.log_max_file) {
            logOpts["max-file"] = settings.log_max_file;
            changes.push(`log-opts.max-file: "${settings.log_max_file}"`);
          }
          newConfig["log-opts"] = logOpts;
        }

        if (changes.length === 0) {
          sections.push("\n  No changes to apply.");
          return { content: [createTextContent(sections.join("\n"))] };
        }

        sections.push("\n── Changes to Apply ──");
        for (const c of changes) {
          sections.push(`  • ${c}`);
        }

        const newJson = JSON.stringify(newConfig, null, 2);
        sections.push(`\n── New Configuration ──`);
        sections.push(`  ${newJson.replace(/\n/g, "\n  ")}`);

        if (isDryRun) {
          sections.push("\n[DRY RUN] No changes written to disk.");
          sections.push(`  Would write to: ${daemonPath}`);
        } else {
          // Backup existing daemon.json
          if (readResult.exitCode === 0) {
            await backupFile(daemonPath);
            sections.push(`\n  ✅ Backed up existing ${daemonPath}`);
          }

          // Write new config
          const escaped = newJson.replace(/'/g, "'\\''");
          const writeResult = await executeCommand({
            command: "sh",
            args: ["-c", `printf '%s' '${escaped}' | sudo tee ${daemonPath} > /dev/null`],
            toolName: "container_daemon_configure",
            timeout: 10000,
          });

          if (writeResult.exitCode !== 0) {
            return {
              content: [createErrorContent(`Failed to write ${daemonPath}: ${writeResult.stderr}`)],
              isError: true,
            };
          }

          sections.push(`  ✅ Written to ${daemonPath}`);
          sections.push("\n  ⚠️ WARNING: Docker daemon must be restarted for changes to take effect.");
          sections.push("  Run: sudo systemctl restart docker");
          sections.push("  NOTE: This will temporarily stop all running containers.");

          logChange(
            createChangeEntry({
              tool: "container_daemon_configure",
              action: "apply",
              target: daemonPath,
              before: JSON.stringify(existingConfig),
              after: newJson,
              dryRun: false,
              success: true,
              rollbackCommand: readResult.exitCode === 0
                ? `printf '%s' '${JSON.stringify(existingConfig).replace(/'/g, "'\\''")}' | sudo tee ${daemonPath} > /dev/null`
                : `sudo rm ${daemonPath}`,
            })
          );
        }

        return { content: [createTextContent(sections.join("\n"))] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );

  // ── 9. container_apparmor_install ───────────────────────────────────────
  server.tool(
    "container_apparmor_install",
    "Install AppArmor profile packages, list loaded profiles, and check AppArmor status",
    {
      action: z
        .enum(["install_profiles", "list_loaded", "status"])
        .describe("Action to perform: install profile packages, list loaded profiles, or check status"),
      dry_run: z
        .boolean()
        .optional()
        .describe("Preview changes without executing (defaults to KALI_DEFENSE_DRY_RUN env var)"),
    },
    async ({ action, dry_run }) => {
      try {
        const sections: string[] = [];
        sections.push("🛡️ AppArmor Profile Management");
        sections.push("=".repeat(50));

        const isDryRun = dry_run ?? getConfig().dryRun;

        switch (action) {
          case "install_profiles": {
            sections.push("\n── Install AppArmor Profile Packages ──");

            const packages = ["apparmor-profiles", "apparmor-profiles-extra"];

            if (isDryRun) {
              sections.push(`\n[DRY RUN] Would install: ${packages.join(", ")}`);
              sections.push(`  Command: sudo apt-get install -y ${packages.join(" ")}`);
            } else {
              const installResult = await executeCommand({
                command: "sudo",
                args: ["apt-get", "install", "-y", ...packages],
                toolName: "container_apparmor_install",
                timeout: 120000,
              });

              if (installResult.exitCode !== 0) {
                sections.push(`\n  ❌ Failed to install packages: ${installResult.stderr}`);
                return {
                  content: [createErrorContent(`Failed to install AppArmor profiles: ${installResult.stderr}`)],
                  isError: true,
                };
              }

              sections.push(`\n  ✅ Successfully installed: ${packages.join(", ")}`);
              sections.push(installResult.stdout.split("\n").slice(-5).join("\n"));

              logChange(
                createChangeEntry({
                  tool: "container_apparmor_install",
                  action: "install_profiles",
                  target: packages.join(", "),
                  after: "installed",
                  dryRun: false,
                  success: true,
                  rollbackCommand: `sudo apt-get remove -y ${packages.join(" ")}`,
                })
              );
            }
            break;
          }

          case "list_loaded": {
            sections.push("\n── Loaded AppArmor Profiles ──");

            const result = await executeCommand({
              command: "sudo",
              args: ["aa-status"],
              toolName: "container_apparmor_install",
              timeout: getToolTimeout("container_apparmor_install"),
            });

            if (result.exitCode !== 0) {
              sections.push("\n  ⚠️ Cannot query AppArmor status. Is AppArmor installed?");
              sections.push(`  Error: ${result.stderr}`);
              break;
            }

            const output = result.stdout;

            // Parse counts
            const enforceMatch = output.match(/(\d+)\s+profiles? are in enforce mode/);
            const complainMatch = output.match(/(\d+)\s+profiles? are in complain mode/);
            const unconfinedMatch = output.match(/(\d+)\s+processes? are unconfined/);

            sections.push(`\n  Enforcing profiles: ${enforceMatch ? enforceMatch[1] : "0"}`);
            sections.push(`  Complain profiles:  ${complainMatch ? complainMatch[1] : "0"}`);
            sections.push(`  Unconfined procs:   ${unconfinedMatch ? unconfinedMatch[1] : "0"}`);

            // Parse profile names
            const lines = output.split("\n");
            let currentSection = "";

            for (const line of lines) {
              const trimmed = line.trim();
              if (trimmed.includes("enforce mode")) {
                currentSection = "enforce";
                sections.push("\n  🔒 Enforce Mode:");
              } else if (trimmed.includes("complain mode")) {
                currentSection = "complain";
                sections.push("\n  📝 Complain Mode:");
              } else if (trimmed.includes("unconfined")) {
                currentSection = "unconfined";
                sections.push("\n  ⚠️ Unconfined:");
              } else if (currentSection && trimmed && !trimmed.match(/^\d+\s+processes?/)) {
                sections.push(`    ${trimmed}`);
              }
            }
            break;
          }

          case "status": {
            sections.push("\n── AppArmor System Status ──");

            // Check if AppArmor is enabled
            const enabledResult = await executeCommand({
              command: "aa-enabled",
              args: [],
              toolName: "container_apparmor_install",
              timeout: 5000,
            });

            const aaEnabled = enabledResult.exitCode === 0 && enabledResult.stdout.trim() === "Yes";
            sections.push(`\n  AppArmor enabled: ${aaEnabled ? "✅ Yes" : "❌ No"}`);

            // Check kernel module
            const moduleResult = await executeCommand({
              command: "cat",
              args: ["/sys/module/apparmor/parameters/enabled"],
              toolName: "container_apparmor_install",
              timeout: 5000,
            });

            if (moduleResult.exitCode === 0) {
              const kernelEnabled = moduleResult.stdout.trim() === "Y";
              sections.push(`  Kernel module:     ${kernelEnabled ? "✅ Loaded" : "❌ Not loaded"}`);
            }

            // Check loaded profile count
            const statusResult = await executeCommand({
              command: "sudo",
              args: ["aa-status", "--enabled"],
              toolName: "container_apparmor_install",
              timeout: 10000,
            });

            if (statusResult.exitCode === 0) {
              // Get full status for counts
              const fullResult = await executeCommand({
                command: "sudo",
                args: ["aa-status"],
                toolName: "container_apparmor_install",
                timeout: 10000,
              });

              if (fullResult.exitCode === 0) {
                const profileCountMatch = fullResult.stdout.match(/(\d+)\s+profiles? are loaded/);
                sections.push(`  Loaded profiles:   ${profileCountMatch ? profileCountMatch[1] : "unknown"}`);
              }
            }

            // Check if profile packages are installed
            sections.push("\n  Profile Packages:");
            const pkgChecks = ["apparmor-profiles", "apparmor-profiles-extra", "apparmor-utils"];
            for (const pkg of pkgChecks) {
              const dpkgResult = await executeCommand({
                command: "dpkg",
                args: ["-s", pkg],
                toolName: "container_apparmor_install",
                timeout: 5000,
              });
              const installed = dpkgResult.exitCode === 0 && dpkgResult.stdout.includes("Status: install ok installed");
              sections.push(`    ${pkg}: ${installed ? "✅ Installed" : "❌ Not installed"}`);
            }
            break;
          }
        }

        return { content: [createTextContent(sections.join("\n"))] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [createErrorContent(msg)], isError: true };
      }
    }
  );
}
