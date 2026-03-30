/**
 * Sudo privilege management tools for Defense MCP Server.
 *
 * Registers 1 tool: sudo_session (actions: elevate, elevate_gui, status, drop, extend, preflight_check)
 *
 * These tools manage a secure in-process sudo session so that the user
 * only needs to provide their password once. All subsequent `sudo`
 * commands executed by other tools transparently receive the cached
 * credentials via stdin piping.
 *
 * The `preflight_check` action allows AI clients to pre-check a list
 * of tools before executing them, so they can request sudo elevation
 * ONCE upfront rather than failing tool-by-tool.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { spawnSafe } from "../core/spawn-safe.js";
import { SudoSession } from "../core/sudo-session.js";
import { getConfig } from "../core/config.js";
import { resolveCommand } from "../core/command-allowlist.js";
import {
  createTextContent,
  createErrorContent,
} from "../core/parsers.js";
import { invalidatePreflightCaches } from '../core/tool-wrapper.js';
import { PreflightEngine } from '../core/preflight.js';
import { ToolRegistry } from '../core/tool-registry.js';

// ── Registration entry point ───────────────────────────────────────────────

export function registerSudoManagementTools(server: McpServer): void {

  server.tool(
    "sudo_session",
    "Sudo: elevate privileges, check/drop/extend session, preflight tool checks",
    {
      action: z.enum([
        "elevate",
        "elevate_gui",
        "status",
        "drop",
        "extend",
        "preflight_check",
      ]).describe("Sudo session action"),
      // elevate params
      password: z
        .string()
        .optional()
        .describe("Sudo password (required for elevate). Stored securely, never logged."),
      timeout_minutes: z
        .number()
        .min(1)
        .max(480)
        .optional()
        .default(15)
        .describe("Session timeout in minutes (max 480)"),
      // extend params
      minutes: z
        .number()
        .min(1)
        .max(480)
        .optional()
        .default(15)
        .describe("Minutes to extend session by (max 480)"),
      // preflight_check params
      tools: z
        .array(z.string())
        .min(1)
        .max(100)
        .optional()
        .describe("Tool names to pre-check for sudo/dependency requirements"),
    },
    async (params) => {
      const { action } = params;

      switch (action) {

        // ── elevate ────────────────────────────────────────────────────────
        case "elevate": {
          const { password, timeout_minutes } = params;
          try {
            // Runtime check: password is required for elevate
            if (!password) {
              return {
                content: [
                  createErrorContent(
                    `password parameter is required for the elevate action.\n` +
                    `Provide your sudo password to gain elevated privileges.`
                  ),
                ],
                isError: true,
              };
            }

            const session = SudoSession.getInstance();

            // Headless container notice (informational — doesn't block)
            const isHeadless = !process.env.DISPLAY && !process.env.WAYLAND_DISPLAY;

            // Check if already elevated
            if (session.isElevated()) {
              const status = session.getStatus();
              return {
                content: [
                  createTextContent(
                    `🔓 Already elevated as '${status.username}'.\n` +
                    `Session expires at: ${status.expiresAt ?? "never"}\n` +
                    `Remaining: ${status.remainingSeconds !== null ? `${status.remainingSeconds}s` : "∞"}\n\n` +
                    `Use sudo_session action=drop to end the current session before re-elevating.`
                  ),
                ],
              };
            }

            // ── Phase 4: Pre-flight rate-limit check ──────────────────────
            // Avoid even attempting elevation if already locked out.
            const rlStatus = session.getRateLimitStatus();
            if (rlStatus.limited) {
              const resetAt = rlStatus.resetAt
                ? new Date(rlStatus.resetAt).toLocaleTimeString()
                : "unknown";
              return {
                content: [
                  createErrorContent(
                    `❌ Authentication rate limit exceeded.\n\n` +
                    `Too many failed attempts were detected within the last 5 minutes.\n` +
                    `Please wait until ${resetAt} before trying again.\n\n` +
                    `For security, this lockout cannot be bypassed.\n` +
                    `Contact your system administrator if this is unexpected.`
                  ),
                ],
                isError: true,
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
              const lines: string[] = [
                `🔓 Privileges elevated successfully!`,
                ``,
                `  User: ${status.username}`,
                `  Expires: ${status.expiresAt ?? "never (running as root)"}`,
                `  Timeout: ${timeout_minutes} minutes`,
                `  Auth method: password (sudo -S)`,
              ];
              if (isHeadless) {
                lines.push(`  Environment: headless (no display server)`);
              }
              lines.push(``);
              lines.push(`All tools that require sudo will now work automatically.`);
              lines.push(`Use sudo_session action=status to check session state, or sudo_session action=drop to end early.`);
              return { content: [createTextContent(lines.join("\n"))] };
            }

            // ── Elevation failed ───────────────────────────────────────────────
            if (result.rateLimited) {
              const resetAt = rlStatus.resetAt
                ? new Date(rlStatus.resetAt).toLocaleTimeString()
                : "unknown";
              return {
                content: [
                  createErrorContent(
                    `❌ Authentication rate limit exceeded.\n\n` +
                    `Too many failed attempts. Please wait until ${resetAt} before retrying.\n\n` +
                    `For security, this lockout cannot be bypassed.`
                  ),
                ],
                isError: true,
              };
            }

            // Re-read rate limit status after the attempt
            const rlAfter = session.getRateLimitStatus();
            const attemptsLine = rlAfter.limited
              ? `Rate limit reached — locked out until ${rlAfter.resetAt ? new Date(rlAfter.resetAt).toLocaleTimeString() : "unknown"}.`
              : `Attempts remaining before lockout: ${rlAfter.attemptsRemaining}`;

            const passwordSource = isHeadless
              ? `\n\nNote: Running in a headless environment (no display server).\n` +
                `Use sudo_session action=elevate with your system password.`
              : "";

            return {
              content: [
                createErrorContent(
                  `❌ Authentication failed: ${result.error}\n\n` +
                  `${attemptsLine}\n\n` +
                  `Please verify:\n` +
                  `  1. The password is correct\n` +
                  `  2. Your user has sudo privileges (is in the sudoers file)\n` +
                  `  3. sudo is installed and configured` +
                  passwordSource
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

        // ── elevate_gui ────────────────────────────────────────────────────
        //
        // Single-step secure GUI elevation:
        //   1. Detect graphical session environment (even if MCP server lacks DISPLAY)
        //   2. Spawn a native password dialog (zenity/kdialog/ssh-askpass)
        //   3. Capture password via secure temp file (never visible to AI)
        //   4. Elevate and wipe the password
        //
        // The password is NEVER visible to the LLM at any point.

        case "elevate_gui": {
          const { timeout_minutes } = params;
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
                    `Use sudo_session action=drop to end the current session before re-elevating.`
                  ),
                ],
              };
            }

            // ── Pre-flight rate-limit check ──────────────────────────────────
            const rlStatus = session.getRateLimitStatus();
            if (rlStatus.limited) {
              const resetAt = rlStatus.resetAt
                ? new Date(rlStatus.resetAt).toLocaleTimeString()
                : "unknown";
              return {
                content: [
                  createErrorContent(
                    `❌ Authentication rate limit exceeded.\n\n` +
                    `Too many failed attempts. Please wait until ${resetAt} before retrying.`
                  ),
                ],
                isError: true,
              };
            }

            // ── Detect graphical session ──────────────────────────────────────
            // The MCP server process may not inherit DISPLAY/WAYLAND_DISPLAY,
            // so we probe the user's desktop session processes via /proc.
            const sessionEnv = await getGraphicalSessionEnv();
            const hasDisplay =
              Boolean(sessionEnv.DISPLAY) || Boolean(sessionEnv.WAYLAND_DISPLAY);

            if (!hasDisplay) {
              return {
                content: [
                  createErrorContent(
                    `❌ GUI elevation is not available — no graphical session detected.\n\n` +
                    `Could not find DISPLAY or WAYLAND_DISPLAY in the current process\n` +
                    `or any desktop session process (gnome-shell, plasmashell, etc.).\n\n` +
                    `Use sudo_session action=elevate with your password instead.`
                  ),
                ],
                isError: true,
              };
            }

            // ── Detect available GUI dialog tool ─────────────────────────────
            const guiTool = await detectGuiPasswordTool();
            if (!guiTool) {
              return {
                content: [
                  createErrorContent(
                    `❌ No GUI password dialog tool found.\n\n` +
                    `Install one of: zenity, kdialog, or ssh-askpass\n` +
                    `  sudo apt install zenity    # GNOME/GTK\n` +
                    `  sudo apt install kdialog   # KDE/Qt\n\n` +
                    `Or use sudo_session action=elevate with your password instead.`
                  ),
                ],
                isError: true,
              };
            }

            console.error(`[sudo-gui] Launching ${guiTool.name} password dialog...`);

            // ── Launch GUI dialog and capture password ────────────────────────
            // openGuiPasswordDialog spawns the dialog with the correct graphical
            // session environment, captures the password via a secure temp file,
            // and wipes it immediately after reading.
            const password = await openGuiPasswordDialog(guiTool);

            if (!password) {
              return {
                content: [
                  createErrorContent(
                    `❌ Password dialog was cancelled or timed out.\n\n` +
                    `No password was entered. Try again with:\n` +
                    `  sudo_session action=elevate_gui\n\n` +
                    `Or provide your password directly with:\n` +
                    `  sudo_session action=elevate`
                  ),
                ],
                isError: true,
              };
            }

            // ── Elevate using captured password ──────────────────────────────
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
                    `  Method: Secure GUI dialog (${guiTool.name}) — password never visible to AI\n\n` +
                    `All tools that require sudo will now work automatically.\n` +
                    `Use sudo_session action=status to check session state, or sudo_session action=drop to end early.`
                  ),
                ],
              };
            }

            // ── Elevation failed ─────────────────────────────────────────────
            const rlAfter = session.getRateLimitStatus();
            const attemptsLine = rlAfter.limited
              ? `Rate limit reached — locked out until ${rlAfter.resetAt ? new Date(rlAfter.resetAt).toLocaleTimeString() : "unknown"}.`
              : `Attempts remaining before lockout: ${rlAfter.attemptsRemaining}`;

            return {
              content: [
                createErrorContent(
                  `❌ Authentication failed: ${result.error}\n\n` +
                  `${attemptsLine}\n\n` +
                  `The password was securely wiped. Please try again.`
                ),
              ],
              isError: true,
            };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return {
              content: [createErrorContent(`GUI elevation error: ${msg}`)],
              isError: true,
            };
          }
        }

        // ── status ─────────────────────────────────────────────────────────
        case "status": {
          try {
            const session = SudoSession.getInstance();
            const status = session.getStatus();
            const rl = status.rateLimit;

            if (!status.elevated) {
              const rlLines: string[] = [];
              if (rl.limited) {
                rlLines.push(`  ⚠️  Rate limit ACTIVE — elevation blocked`);
                rlLines.push(`     Unlocks at: ${rl.resetAt ? new Date(rl.resetAt).toLocaleTimeString() : "unknown"}`);
              } else {
                rlLines.push(`  Rate limit: ${rl.attemptsRemaining} attempts remaining`);
              }

              return {
                content: [
                  createTextContent(
                    `🔒 Not elevated — sudo credentials are not cached.\n\n` +
                    rlLines.join("\n") + "\n\n" +
                    `Use sudo_session action=elevate to provide your password and enable\n` +
                    `transparent sudo for all defensive security tools.`
                  ),
                ],
              };
            }

            const sections: string[] = [];
            sections.push("🔓 Sudo Session Active");
            sections.push("═".repeat(40));
            sections.push(`  User: ${status.username}`);
            sections.push(`  Expires: ${status.expiresAt ?? "never (root)"}`);
            sections.push(`  Auth method: password (sudo -S)`);

            if (status.remainingSeconds !== null) {
              const mins = Math.floor(status.remainingSeconds / 60);
              const secs = status.remainingSeconds % 60;
              sections.push(`  Remaining: ${mins}m ${secs}s`);

              if (status.remainingSeconds < 120) {
                sections.push(`\n  ⚠️ Session expiring soon! Use sudo_session action=extend to continue.`);
              }
            } else {
              sections.push(`  Remaining: ∞ (running as root)`);
            }

            // ── Phase 4: Rate-limit status ─────────────────────────────────────
            sections.push(`  Rate limit: ${rl.attemptsRemaining} / 5 attempts remaining`);

            return { content: [createTextContent(sections.join("\n"))] };
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return {
              content: [createErrorContent(`Status check error: ${msg}`)],
              isError: true,
            };
          }
        }

        // ── drop ───────────────────────────────────────────────────────────
        case "drop": {
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
                    `Tools requiring sudo will now fail until sudo_session action=elevate is called again.`
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

        // ── extend ─────────────────────────────────────────────────────────
        case "extend": {
          const { minutes } = params;
          try {
            const session = SudoSession.getInstance();

            if (!session.isElevated()) {
              return {
                content: [
                  createErrorContent(
                    `🔒 No active sudo session to extend.\n\n` +
                    `Use sudo_session action=elevate to provide your password and start a session first.`
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
                    `Use sudo_session action=elevate to re-authenticate.`
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

        // ── preflight_check ────────────────────────────────────────────────
        //
        // Allows AI clients to pre-check a list of tools BEFORE executing them.
        // Returns a consolidated report showing which tools will succeed, which
        // need sudo, and which have missing dependencies — so the client can
        // request elevation ONCE upfront instead of failing tool-by-tool.

        case "preflight_check": {
          const toolNames = params.tools;
          try {
            if (!toolNames || toolNames.length === 0) {
              return {
                content: [createErrorContent("tools array is required for preflight_check action")],
                isError: true,
              };
            }

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
              lines.push("Call sudo_session action=elevate with the user's password BEFORE");
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
              lines.push("  then call: sudo_session action=elevate password='<password>'");
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
              (meta as Record<string, unknown>).elevationTool = "sudo_session";
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

        default:
          return { content: [createErrorContent(`Unknown action: ${action}`)], isError: true };
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
 * Uses the command allowlist for resolution (no spawning `which`).
 * Preference order: zenity > kdialog > ssh-askpass
 */
async function detectGuiPasswordTool(): Promise<GuiPasswordTool | null> {
  const candidates: GuiPasswordTool[] = [
    {
      name: "zenity",
      command: "zenity",
      args: [
        "--password",
        "--title=Defense — Sudo Authentication",
        "--window-icon=dialog-password",
        "--width=400",
      ],
    },
    {
      name: "kdialog",
      command: "kdialog",
      args: [
        "--password",
        "Defense MCP Server requires sudo privileges.\nEnter your password to continue:",
        "--title",
        "Defense — Sudo Authentication",
      ],
    },
    {
      name: "ssh-askpass",
      command: "ssh-askpass",
      args: ["Defense MCP Server requires sudo privileges. Enter password:"],
    },
  ];

  for (const tool of candidates) {
    try {
      // resolveCommand checks the allowlist and verifies the binary exists on disk
      const resolved = resolveCommand(tool.command);
      if (resolved) {
        console.error(`[sudo-gui] Found GUI tool: ${tool.name} at ${resolved}`);
        return { ...tool, command: resolved };
      }
    } catch {
      // Binary not found or not in allowlist — try next candidate
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

    // Find a PID from the user's graphical session.
    // We need a process that INHERITS display vars from the compositor.
    // The compositor itself (gnome-shell, kwin_wayland) often doesn't have
    // DISPLAY/WAYLAND_DISPLAY in its own /proc/environ — so we prefer child
    // processes like gjs, nautilus, plasmashell that do inherit them.
    const uid = process.getuid?.() ?? 1000;
    let pid: string | null = null;
    const candidates = [
      "gjs",               // GNOME shell extensions (always has display vars)
      "nautilus",           // GNOME file manager
      "plasmashell",       // KDE
      "kwin_wayland",      // KDE compositor
      "xfce4-panel",       // XFCE
      "xfce4-session",     // XFCE
      "cinnamon",          // Cinnamon
      "budgie-panel",      // Budgie
      "lxqt-panel",        // LXQt
      "sway",              // Sway
      "hyprland",          // Hyprland
      "Xwayland",          // X11-on-Wayland bridge
      "gnome-shell",       // GNOME compositor (may lack display vars)
    ];
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
    tmpDir = fs.mkdtempSync("/tmp/defense-sudo-gui-");
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

    // Resolve /bin/sh via the allowlist so we can use it as the script interpreter.
    // We MUST invoke `setsid sh scriptPath` rather than `setsid scriptPath` because
    // /tmp may be mounted with noexec (a common CIS hardening), which prevents the
    // kernel from executing scripts directly from /tmp even if chmod +x is set.
    // Using sh as the interpreter bypasses noexec since sh itself lives on a normal
    // filesystem and merely reads the script file as data.
    const resolvedSh = resolveCommand("sh");
    const bg = spawnSafe("setsid", [resolvedSh, scriptPath], {
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

