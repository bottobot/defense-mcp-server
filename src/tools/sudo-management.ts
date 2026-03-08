/**
 * Sudo privilege management tools for Kali Defense MCP Server.
 *
 * Registers 6 tools: sudo_elevate, sudo_elevate_gui, sudo_status, sudo_drop,
 * sudo_extend, preflight_batch_check.
 *
 * These tools manage a secure in-process sudo session so that the user
 * only needs to provide their password once. All subsequent `sudo`
 * commands executed by other tools transparently receive the cached
 * credentials via stdin piping.
 *
 * The `preflight_batch_check` tool allows AI clients to pre-check a list
 * of tools before executing them, so they can request sudo elevation
 * ONCE upfront rather than failing tool-by-tool.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { spawnSafe } from "../core/spawn-safe.js";
import { SudoSession } from "../core/sudo-session.js";
import { getConfig } from "../core/config.js";
import {
  createTextContent,
  createErrorContent,
} from "../core/parsers.js";
import { invalidatePreflightCaches } from '../core/tool-wrapper.js';
import { PreflightEngine } from '../core/preflight.js';
import { ToolRegistry } from '../core/tool-registry.js';

// ── Registration entry point ───────────────────────────────────────────────

export function registerSudoManagementTools(server: McpServer): void {

  // ── 1. sudo_elevate ──────────────────────────────────────────────────────

  server.tool(
    "sudo_elevate",
    "Elevate privileges by providing the sudo password once. All subsequent tools that require sudo will use the cached credentials automatically. The password is stored securely in memory and auto-expires after the configured timeout.",
    {
      password: z
        .string()
        .min(1)
        .describe("The user's sudo password. Stored securely in a zeroable buffer and never logged."),
      timeout_minutes: z
        .number()
        .min(1)
        .max(480)
        .optional()
        .default(15)
        .describe("Session timeout in minutes (default: 15, max: 480). Session auto-expires after this duration."),
    },
    async ({ password, timeout_minutes }) => {
      try {
        const session = SudoSession.getInstance();

        // Check if already elevated
        if (session.isElevated()) {
          const status = session.getStatus();
          return {
            content: [
              createTextContent(
                `🔓 Already elevated as '${status.username}'.\n` +
                `Session expires at: ${status.expiresAt ?? "never"}\n` +
                `Remaining: ${status.remainingSeconds !== null ? `${status.remainingSeconds}s` : "∞"}\n\n` +
                `Use sudo_drop to end the current session before re-elevating.`
              ),
            ],
          };
        }

        const timeoutMs = timeout_minutes * 60 * 1000;

        // Apply config-level timeout override if set
        const config = getConfig();
        if (config.sudoSessionTimeout) {
          session.setDefaultTimeout(config.sudoSessionTimeout);
        }

        const result = await session.elevate(password, timeoutMs);

        if (result.success) {
          invalidatePreflightCaches();
          const status = session.getStatus();
          return {
            content: [
              createTextContent(
                `🔓 Privileges elevated successfully!\n\n` +
                `  User: ${status.username}\n` +
                `  Expires: ${status.expiresAt ?? "never (running as root)"}\n` +
                `  Timeout: ${timeout_minutes} minutes\n\n` +
                `All tools that require sudo will now work automatically.\n` +
                `Use sudo_status to check session state, or sudo_drop to end early.`
              ),
            ],
          };
        }

        return {
          content: [
            createErrorContent(
              `❌ Elevation failed: ${result.error}\n\n` +
              `Please verify:\n` +
              `  1. The password is correct\n` +
              `  2. Your user has sudo privileges (is in the sudoers file)\n` +
              `  3. sudo is installed and configured`
            ),
          ],
          isError: true,
        };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return {
          content: [createErrorContent(`Elevation error: ${msg}`)],
          isError: true,
        };
      }
    }
  );

  // ── 1b. sudo_elevate_gui ──────────────────────────────────────────────────
  //
  // Secure two-phase elevation flow:
  //   Phase 1: LLM launches zenity via execute_command, password goes to temp file
  //            (password NEVER appears in terminal output or LLM context)
  //   Phase 2: LLM calls this tool which reads file → elevates → securely wipes
  //
  // The password is NEVER visible to the LLM at any point.

  server.tool(
    "sudo_elevate_gui",
    "Elevate privileges using a secure native GUI password dialog. Opens a system password prompt (zenity/kdialog) so the password never appears in the chat. The password goes directly from the dialog to secure memory. Preferred over sudo_elevate for interactive sessions.",
    {
      timeout_minutes: z
        .number()
        .min(1)
        .max(480)
        .optional()
        .default(15)
        .describe("Session timeout in minutes (default: 15, max: 480). Session auto-expires after this duration."),
    },
    async ({ timeout_minutes }) => {
      try {
        const fs = await import("node:fs");
        const crypto = await import("node:crypto");
        const session = SudoSession.getInstance();
        const SUDO_PW_FILE = "/tmp/.kali-sudo-pw";

        // Check if already elevated
        if (session.isElevated()) {
          const status = session.getStatus();
          return {
            content: [
              createTextContent(
                `🔓 Already elevated as '${status.username}'.\n` +
                `Session expires at: ${status.expiresAt ?? "never"}\n` +
                `Remaining: ${status.remainingSeconds !== null ? `${status.remainingSeconds}s` : "∞"}\n\n` +
                `Use sudo_drop to end the current session before re-elevating.`
              ),
            ],
          };
        }

        // Check if the password file exists (Phase 2 of the two-phase flow)
        if (fs.existsSync(SUDO_PW_FILE)) {
          console.error("[sudo-gui] Phase 2: Reading password from secure temp file...");

          // Verify file ownership and permissions for safety
          const stat = fs.statSync(SUDO_PW_FILE);
          const mode = (stat.mode & 0o777).toString(8);
          if (mode !== "600") {
            // Wipe insecure file
            try {
              const size = stat.size || 64;
              fs.writeFileSync(SUDO_PW_FILE, crypto.randomBytes(size));
              fs.unlinkSync(SUDO_PW_FILE);
            } catch { console.error("[sudo-gui] Failed to wipe insecure password file"); }
            return {
              content: [
                createErrorContent(
                  `❌ Security error: Password file has insecure permissions (${mode}).\n` +
                  `Expected 600. File has been securely wiped.\n` +
                  `Please run the zenity command again.`
                ),
              ],
              isError: true,
            };
          }

          // Read password from file
          let password: string;
          try {
            password = fs.readFileSync(SUDO_PW_FILE, "utf-8").trim();
          } catch (err) {
            return {
              content: [
                createErrorContent(
                  `❌ Could not read password file: ${err instanceof Error ? err.message : String(err)}`
                ),
              ],
              isError: true,
            };
          }

          // Securely wipe the file IMMEDIATELY (before elevation attempt)
          try {
            const fileSize = Buffer.byteLength(password, "utf-8") + 16;
            fs.writeFileSync(SUDO_PW_FILE, crypto.randomBytes(fileSize));
            fs.writeFileSync(SUDO_PW_FILE, crypto.randomBytes(fileSize)); // Double overwrite
            fs.unlinkSync(SUDO_PW_FILE);
            console.error("[sudo-gui] Password file securely wiped (2x random overwrite + unlink)");
          } catch {
            try { fs.unlinkSync(SUDO_PW_FILE); } catch { console.error("[sudo-gui] Failed to unlink password file during wipe fallback"); }
          }

          if (!password || password.length === 0) {
            return {
              content: [
                createErrorContent(
                  `❌ Empty password file. Please run the zenity command again and enter your password.`
                ),
              ],
              isError: true,
            };
          }

          // Elevate using the captured password
          const timeoutMs = timeout_minutes * 60 * 1000;
          const config = getConfig();
          if (config.sudoSessionTimeout) {
            session.setDefaultTimeout(config.sudoSessionTimeout);
          }

          const result = await session.elevate(password, timeoutMs);

          if (result.success) {
            invalidatePreflightCaches();
            const status = session.getStatus();
            return {
              content: [
                createTextContent(
                  `🔓 Privileges elevated successfully!\n\n` +
                  `  User: ${status.username}\n` +
                  `  Expires: ${status.expiresAt ?? "never (running as root)"}\n` +
                  `  Timeout: ${timeout_minutes} minutes\n` +
                  `  Method: Secure GUI dialog (password never visible to AI)\n\n` +
                  `All tools that require sudo will now work automatically.\n` +
                  `Use sudo_status to check session state, or sudo_drop to end early.`
                ),
              ],
            };
          }

          return {
            content: [
              createErrorContent(
                `❌ Elevation failed: ${result.error}\n\n` +
                `The password file was securely wiped. Please try again.`
              ),
            ],
            isError: true,
          };
        }

        // Phase 1: No password file found — instruct the LLM to launch the GUI dialog
        // Detect which GUI tool is available for the instruction
        const guiTool = await detectGuiPasswordTool();
        const toolCmd = guiTool
          ? `${guiTool.command} ${guiTool.args.map(a => `'${a}'`).join(" ")}`
          : "zenity --password --title='Kali Defense — Sudo Authentication' --width=400";

        return {
          content: [
            createTextContent(
              `🔐 SECURE ELEVATION — Step 1 of 2\n` +
              `${"═".repeat(50)}\n\n` +
              `To elevate securely, run this command via execute_command:\n\n` +
              `  ${toolCmd} > /tmp/.kali-sudo-pw 2>/dev/null && chmod 600 /tmp/.kali-sudo-pw && echo "READY" || echo "CANCELLED"\n\n` +
              `This opens a password dialog on the user's screen.\n` +
              `The password goes DIRECTLY to a secure temp file — it\n` +
              `NEVER appears in terminal output or the AI chat.\n\n` +
              `After the user enters their password (output shows "READY"),\n` +
              `call sudo_elevate_gui again to complete elevation.\n` +
              `The tool will read the file, elevate, and securely wipe it.`
            ),
          ],
        };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return {
          content: [createErrorContent(`GUI elevation error: ${msg}`)],
          isError: true,
        };
      }
    }
  );

  // ── 2. sudo_status ───────────────────────────────────────────────────────

  server.tool(
    "sudo_status",
    "Check the current sudo elevation status, including whether credentials are cached, the authenticated user, and remaining session time.",
    {},
    async () => {
      try {
        const session = SudoSession.getInstance();
        const status = session.getStatus();

        if (!status.elevated) {
          return {
            content: [
              createTextContent(
                `🔒 Not elevated — sudo credentials are not cached.\n\n` +
                `Use sudo_elevate to provide your password and enable\n` +
                `transparent sudo for all defensive security tools.`
              ),
            ],
          };
        }

        const sections: string[] = [];
        sections.push("🔓 Sudo Session Active");
        sections.push("=".repeat(40));
        sections.push(`  User: ${status.username}`);
        sections.push(`  Expires: ${status.expiresAt ?? "never (root)"}`);

        if (status.remainingSeconds !== null) {
          const mins = Math.floor(status.remainingSeconds / 60);
          const secs = status.remainingSeconds % 60;
          sections.push(`  Remaining: ${mins}m ${secs}s`);

          if (status.remainingSeconds < 120) {
            sections.push(`\n  ⚠️ Session expiring soon! Use sudo_elevate to re-authenticate.`);
          }
        } else {
          sections.push(`  Remaining: ∞ (running as root)`);
        }

        return { content: [createTextContent(sections.join("\n"))] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return {
          content: [createErrorContent(`Status check error: ${msg}`)],
          isError: true,
        };
      }
    }
  );

  // ── 3. sudo_drop ─────────────────────────────────────────────────────────

  server.tool(
    "sudo_drop",
    "Drop elevated privileges immediately. Zeroes the cached password from memory and invalidates the sudo session. Subsequent tools requiring sudo will fail until sudo_elevate is called again.",
    {},
    async () => {
      try {
        const session = SudoSession.getInstance();
        const wasElevated = session.isElevated();
        const prevStatus = session.getStatus();

        session.drop();
        invalidatePreflightCaches();

        if (wasElevated) {
          return {
            content: [
              createTextContent(
                `🔒 Privileges dropped successfully.\n\n` +
                `  Previous user: ${prevStatus.username}\n` +
                `  Password buffer: zeroed\n` +
                `  System sudo cache: invalidated\n\n` +
                `Tools requiring sudo will now fail until sudo_elevate is called again.`
              ),
            ],
          };
        }

        return {
          content: [
            createTextContent(
              `🔒 No active sudo session to drop.\n` +
              `The system is already in an unprivileged state.`
            ),
          ],
        };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return {
          content: [createErrorContent(`Drop error: ${msg}`)],
          isError: true,
        };
      }
    }
  );

  // ── 4. sudo_extend ────────────────────────────────────────────────────────

  server.tool(
    "sudo_extend",
    "Extend the current sudo session timeout. Resets the expiry timer so you don't have to re-authenticate. Requires an active sudo session (use sudo_elevate first).",
    {
      minutes: z
        .number()
        .min(1)
        .max(480)
        .optional()
        .default(15)
        .describe("Number of minutes to extend the session by (default: 15, max: 480)."),
    },
    async ({ minutes }) => {
      try {
        const session = SudoSession.getInstance();

        if (!session.isElevated()) {
          return {
            content: [
              createErrorContent(
                `🔒 No active sudo session to extend.\n\n` +
                `Use sudo_elevate to provide your password and start a session first.`
              ),
            ],
            isError: true,
          };
        }

        const extraMs = minutes * 60 * 1000;
        const success = session.extend(extraMs);

        if (success) {
          invalidatePreflightCaches();
        }

        if (!success) {
          return {
            content: [
              createErrorContent(
                `Failed to extend sudo session. The session may have expired.\n` +
                `Use sudo_elevate to re-authenticate.`
              ),
            ],
            isError: true,
          };
        }

        const status = session.getStatus();
        return {
          content: [
            createTextContent(
              `🔓 Session extended by ${minutes} minutes.\n\n` +
              `  User: ${status.username}\n` +
              `  New expiry: ${status.expiresAt ?? "never (root)"}\n` +
              `  Remaining: ${status.remainingSeconds !== null ? `${Math.floor(status.remainingSeconds / 60)}m ${status.remainingSeconds % 60}s` : "∞"}`
            ),
          ],
        };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return {
          content: [createErrorContent(`Extend error: ${msg}`)],
          isError: true,
        };
      }
    }
  );

  // ── 5. preflight_batch_check ──────────────────────────────────────────────
  //
  // Allows AI clients to pre-check a list of tools BEFORE executing them.
  // Returns a consolidated report showing which tools will succeed, which
  // need sudo, and which have missing dependencies — so the client can
  // request elevation ONCE upfront instead of failing tool-by-tool.

  server.tool(
    "preflight_batch_check",
    "Pre-check multiple tools before executing them. Returns which tools are ready, which need sudo elevation, and which have missing dependencies. Call this BEFORE running a batch of audit tools so you can request sudo elevation once upfront rather than failing tool-by-tool.",
    {
      tools: z
        .array(z.string())
        .min(1)
        .max(100)
        .describe("Array of tool names to pre-check (e.g., ['access_ssh_audit', 'patch_update_audit', 'harden_sysctl_audit'])"),
    },
    async ({ tools: toolNames }) => {
      try {
        const engine = PreflightEngine.instance();
        const registry = ToolRegistry.instance();
        const session = SudoSession.getInstance();

        interface ToolCheckResult {
          tool: string;
          ready: boolean;
          needsSudo: boolean;
          missingDeps: string[];
          sudoReason?: string;
          issues: string[];
        }

        const results: ToolCheckResult[] = [];

        for (const toolName of toolNames) {
          const manifest = registry.getManifest(toolName);

          if (!manifest) {
            results.push({
              tool: toolName,
              ready: false,
              needsSudo: false,
              missingDeps: [],
              issues: [`Tool '${toolName}' not found in registry`],
            });
            continue;
          }

          // Run preflight (uses cache if available)
          const preflight = await engine.runPreflight(toolName);

          const missingDeps = preflight.dependencies.missing.map(
            (d) => `${d.name} (${d.type})`
          );

          const needsSudo =
            preflight.privileges.issues.some(
              (i) =>
                i.type === "sudo-required" ||
                i.type === "sudo-unavailable" ||
                i.type === "session-expired"
            ) ||
            (manifest.sudo === "always" && !session.isElevated());

          const issues: string[] = [];
          for (const err of preflight.errors) {
            issues.push(err);
          }

          results.push({
            tool: toolName,
            ready: preflight.passed,
            needsSudo,
            missingDeps,
            sudoReason: manifest.sudoReason,
            issues,
          });
        }

        // Categorize results
        const ready = results.filter((r) => r.ready);
        const needSudo = results.filter((r) => r.needsSudo && r.missingDeps.length === 0);
        const needDeps = results.filter((r) => r.missingDeps.length > 0);
        const otherFails = results.filter(
          (r) => !r.ready && !r.needsSudo && r.missingDeps.length === 0
        );

        // Build report
        const lines: string[] = [];
        lines.push("🔍 Pre-flight Batch Check Results");
        lines.push("═".repeat(50));
        lines.push(`Checked: ${toolNames.length} tools`);
        lines.push(`  ✅ Ready: ${ready.length}`);
        lines.push(`  🔒 Need sudo: ${needSudo.length}`);
        lines.push(`  📦 Missing deps: ${needDeps.length}`);
        if (otherFails.length > 0) {
          lines.push(`  ❌ Other issues: ${otherFails.length}`);
        }

        // Section: Tools that need sudo elevation
        if (needSudo.length > 0) {
          lines.push("");
          lines.push("🛑 SUDO ELEVATION REQUIRED");
          lines.push("─".repeat(50));
          lines.push("The following tools need sudo privileges.");
          lines.push("Call sudo_elevate with the user's password BEFORE");
          lines.push("executing any of these tools:");
          lines.push("");
          for (const r of needSudo) {
            lines.push(`  🔒 ${r.tool}`);
            if (r.sudoReason) {
              lines.push(`     Reason: ${r.sudoReason}`);
            }
          }
          lines.push("");
          lines.push("→ Ask the user for their sudo password NOW,");
          lines.push("  then call: sudo_elevate({ password: '<password>' })");
        }

        // Section: Missing dependencies
        if (needDeps.length > 0) {
          lines.push("");
          lines.push("📦 MISSING DEPENDENCIES");
          lines.push("─".repeat(50));
          for (const r of needDeps) {
            lines.push(`  ❌ ${r.tool}`);
            for (const dep of r.missingDeps) {
              lines.push(`     Missing: ${dep}`);
            }
            if (r.needsSudo) {
              lines.push(`     Also needs: sudo elevation`);
            }
          }
        }

        // Section: Ready tools
        if (ready.length > 0) {
          lines.push("");
          lines.push("✅ READY TO EXECUTE");
          lines.push("─".repeat(50));
          for (const r of ready) {
            lines.push(`  ✅ ${r.tool}`);
          }
        }

        // Build machine-readable metadata
        const meta: Record<string, unknown> = {
          totalChecked: toolNames.length,
          readyCount: ready.length,
          needSudoCount: needSudo.length,
          needDepsCount: needDeps.length,
          needsSudoElevation: needSudo.length > 0,
          toolsNeedingSudo: needSudo.map((r) => r.tool),
          toolsReady: ready.map((r) => r.tool),
          toolsMissingDeps: needDeps.map((r) => ({
            tool: r.tool,
            missing: r.missingDeps,
          })),
        };

        if (needSudo.length > 0) {
          (meta as Record<string, unknown>).haltWorkflow = true;
          (meta as Record<string, unknown>).elevationTool = "sudo_elevate";
        }

        return {
          content: [createTextContent(lines.join("\n"))],
          _meta: meta,
        };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return {
          content: [createErrorContent(`Batch check error: ${msg}`)],
          isError: true,
        };
      }
    }
  );
}

// ── GUI Password Dialog Helpers ────────────────────────────────────────────

interface GuiPasswordTool {
  name: string;
  command: string;
  args: string[];
}

/**
 * Detect which GUI password dialog tool is available.
 * Preference order: zenity > kdialog > ssh-askpass
 */
async function detectGuiPasswordTool(): Promise<GuiPasswordTool | null> {
  const candidates: GuiPasswordTool[] = [
    {
      name: "zenity",
      command: "zenity",
      args: [
        "--password",
        "--title=Kali Defense — Sudo Authentication",
        "--window-icon=dialog-password",
        "--width=400",
      ],
    },
    {
      name: "kdialog",
      command: "kdialog",
      args: [
        "--password",
        "Kali Defense MCP Server requires sudo privileges.\nEnter your password to continue:",
        "--title",
        "Kali Defense — Sudo Authentication",
      ],
    },
    {
      name: "ssh-askpass",
      command: "ssh-askpass",
      args: ["Kali Defense MCP Server requires sudo privileges. Enter password:"],
    },
  ];

  for (const tool of candidates) {
    try {
      const result = await new Promise<boolean>((resolve) => {
        const child = spawnSafe("which", [tool.command], {
          stdio: ["ignore", "pipe", "pipe"],
        });
        child.on("close", (code) => resolve(code === 0));
        child.on("error", () => resolve(false));
      });
      if (result) return tool;
    } catch {
      continue;
    }
  }

  return null;
}

/**
 * Discover the graphical session environment by reading /proc/<pid>/environ
 * from a known user desktop process.  Falls back to the current process.env.
 */
async function getGraphicalSessionEnv(): Promise<Record<string, string>> {
  const base: Record<string, string> = { ...process.env as Record<string, string> };

  try {
    const { readFile } = await import("node:fs/promises");
    const { execFileSafe } = await import("../core/spawn-safe.js");

    // Find a PID from the user's graphical session (sddm-greeter, Xwayland, or the desktop itself)
    const uid = process.getuid?.() ?? 1000;
    // Get a graphical session process PID owned by the current user
    let pid: string | null = null;
    const candidates = ["sddm", "kwin_wayland", "plasmashell", "gnome-shell", "Xwayland", "xfce4-session"];
    for (const proc of candidates) {
      try {
        const result = (execFileSafe("pgrep", ["-u", String(uid), "-o", proc], { encoding: "utf-8", stdio: "pipe" }) as string).trim();
        if (result) {
          pid = result.split("\n")[0];
          break;
        }
      } catch {
        continue;
      }
    }

    if (!pid) {
      console.error("[sudo-gui] No graphical session process found, using process.env");
      return base;
    }

    console.error(`[sudo-gui] Reading session env from PID ${pid}`);
    const environ = await readFile(`/proc/${pid}/environ`, "utf-8");
    for (const entry of environ.split("\0")) {
      const eqIdx = entry.indexOf("=");
      if (eqIdx > 0) {
        const key = entry.substring(0, eqIdx);
        const val = entry.substring(eqIdx + 1);
        // Only set missing or display-related keys
        if (!base[key] || ["DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR",
          "DBUS_SESSION_BUS_ADDRESS", "HOME", "USER", "XAUTHORITY",
          "XDG_SESSION_TYPE", "XDG_CURRENT_DESKTOP"].includes(key)) {
          base[key] = val;
        }
      }
    }
  } catch (err) {
    console.error(`[sudo-gui] Session env discovery failed: ${err instanceof Error ? err.message : String(err)}`);
  }

  return base;
}

/**
 * Open a native GUI password dialog and return the entered password.
 * Returns null if the user cancels the dialog.
 * The password is captured directly in-process and never logged.
 *
 * Uses a temp-file approach: spawns zenity via `setsid` in a completely
 * independent session, writing the password to a temp file. We poll
 * asynchronously for the result to keep the Node.js event loop alive
 * (critical — blocking the event loop kills the MCP server connection).
 */
async function openGuiPasswordDialog(tool: GuiPasswordTool): Promise<string | null> {
  const fs = await import("node:fs");
  const path = await import("node:path");
  const crypto = await import("node:crypto");

  // Get full graphical session environment so the dialog can display
  const sessionEnv = await getGraphicalSessionEnv();

  // Create a secure temp directory
  let tmpDir: string;
  try {
    tmpDir = fs.mkdtempSync("/tmp/kali-sudo-gui-");
    fs.chmodSync(tmpDir, 0o700);
  } catch {
    console.error("[sudo-gui] Failed to create temp dir");
    return null;
  }

  const pwFile = path.join(tmpDir, "pw");
  const doneFile = path.join(tmpDir, "done");

  try {
    // Write a self-contained helper script to the secure temp directory
    // instead of passing interpolated strings to bash -c (TOOL-002 remediation).
    const scriptPath = path.join(tmpDir, "gui-helper.sh");

    // Build safe env export lines — only allow validated env var names
    const envExports: string[] = ["#!/bin/sh"];
    for (const [k, v] of Object.entries(sessionEnv)) {
      if (v !== undefined && k !== "_" && /^[A-Za-z_][A-Za-z0-9_]*$/.test(k)) {
        // Single-quote the value with proper escaping
        envExports.push(`export ${k}='${v.replace(/'/g, "'\\''")}'`);
      }
    }

    // Build command args with proper quoting — no template literal interpolation into shell
    const quotedArgs = tool.args.map(a => `'${a.replace(/'/g, "'\\''")}'`).join(" ");
    const scriptLines = [
      ...envExports,
      `PW=$(setsid '${tool.command.replace(/'/g, "'\\''")}' ${quotedArgs} 2>/dev/null)`,
      `RC=$?`,
      `if [ $RC -eq 0 ] && [ -n "$PW" ]; then`,
      `  printf '%s' "$PW" > '${pwFile.replace(/'/g, "'\\''")}'`,
      `  chmod 600 '${pwFile.replace(/'/g, "'\\''")}'`,
      `fi`,
      `touch '${doneFile.replace(/'/g, "'\\''")}'`,
    ];

    fs.writeFileSync(scriptPath, scriptLines.join("\n") + "\n", { mode: 0o700 });

    // Launch the script directly via setsid — no bash -c with interpolated strings
    const bg = spawnSafe("setsid", [scriptPath], {
      stdio: "ignore",
      detached: true,
      env: sessionEnv,
    });
    bg.unref();

    console.error("[sudo-gui] Launched password dialog, polling for result...");

    // Poll for the done file asynchronously (non-blocking!)
    const password = await new Promise<string | null>((resolve) => {
      let elapsed = 0;
      const interval = setInterval(() => {
        elapsed += 250;
        if (elapsed > 60000) {
          clearInterval(interval);
          console.error("[sudo-gui] Dialog timed out after 60s");
          resolve(null);
          return;
        }

        // Check if done file exists
        if (fs.existsSync(doneFile)) {
          clearInterval(interval);

          // Read password if it was written
          if (fs.existsSync(pwFile)) {
            try {
              const pw = fs.readFileSync(pwFile, "utf-8");
              // Zero the file on disk immediately
              const len = Buffer.byteLength(pw, "utf-8");
              fs.writeFileSync(pwFile, crypto.randomBytes(len));
              fs.unlinkSync(pwFile);
              console.error("[sudo-gui] Password captured from GUI dialog");
              resolve(pw || null);
            } catch (err) {
              console.error(`[sudo-gui] Read error: ${err instanceof Error ? err.message : String(err)}`);
              resolve(null);
            }
          } else {
            console.error("[sudo-gui] Dialog cancelled (no password file)");
            resolve(null);
          }
        }
      }, 250);
    });

    return password;
  } catch (err) {
    console.error(`[sudo-gui] Error: ${err instanceof Error ? err.message : String(err)}`);
    return null;
  } finally {
    // Clean up temp dir
    try { fs.unlinkSync(pwFile); } catch { /* best-effort cleanup of sensitive temp file */ }
    try { fs.unlinkSync(doneFile); } catch { /* best-effort cleanup */ }
    try { fs.rmdirSync(tmpDir); } catch { /* best-effort cleanup */ }
  }
}
