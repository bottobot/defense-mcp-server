# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Project

MCP (Model Context Protocol) server providing 31 action-based Linux security tools. TypeScript, ESM (`"type": "module"`), Node 18/20/22, Linux only.

## Critical Rules

- **Never use `console.log`** — stdout is the MCP stdio transport. Use `console.error` for logging.
- **All imports must use `.js` extensions** — ESM Node16 resolution requires it even for `.ts` source files.
- **`child_process` imports are ESLint-blocked** except in `executor.ts`, `spawn-safe.ts`, `command-allowlist.ts`.
- **Dry-run defaults to `true`** — tools must check `params.dry_run ?? getConfig().dryRun` before mutating.
- **Config is cached 5 seconds** — call `invalidateConfigCache()` in tests after changing env vars.

## Commands

| Command | Notes |
|---------|-------|
| `npm test` | Vitest (not Jest). Runs all unit tests. |
| `npm test -- tests/tools/firewall.test.ts` | Single test file |
| `npm run build` | `tsc` — outputs to `dist/` |
| `npm run lint:security` | ESLint with security plugin only. **No general lint command exists.** |
| `npm run test:integration` | Builds first, then runs integration tests |

## Architecture

- Tools use **action-based pattern**: one tool with `z.enum([...])` action parameter, not many small tools.
- `createPreflightServer()` in `tool-wrapper.ts` returns a **JS Proxy** wrapping `McpServer` — intercepts `.tool()` to inject preflight checks. Call `server.connect()` on the **real** server, not the proxy.
- Registration in `index.ts` uses `safeRegister()` for error isolation. `sudo-management` must register first.
- Singletons use module-scoped variables (not class statics) — tagged `SECURITY (CORE-021)`.

## Security Layers

- **Command allowlist** (`command-allowlist.ts`): ~150 binaries with absolute path resolution + inode TOCTOU verification.
- **Input sanitization** (`sanitizer.ts`): `validateFilePath()` resolves symlinks, `sanitizeArgs()` strips shell metacharacters.
- **Error sanitization**: `sanitizeToolError()` strips paths/stacks before returning to MCP clients.
- **Sudo credential injection** is transparent — `prepareSudoOptions()` in executor.ts handles it automatically.
- **Passwords must use `Buffer`** and be zeroed after use (`buffer.fill(0)`).
- **`shell: false` always** — enforced in both `executor.ts` and `spawn-safe.ts`.
- **Default allowed dirs**: `/tmp,/home,/var/log` — `/etc` deliberately excluded.

## Adding a New Tool

1. Create `src/tools/my-tool.ts` — export `registerMyToolTools(server)` with action-based pattern
2. Add to `src/core/tool-dependencies.ts` — `TOOL_DEPENDENCIES` with `requiredBinaries`
3. Add sudo overlay to `src/core/tool-registry.ts` — `SUDO_OVERLAYS` entry
4. Add binaries to `src/core/command-allowlist.ts` — `ALLOWLIST_DEFINITIONS` with candidate paths
5. Register in `src/index.ts` via `safeRegister()`
6. Create `tests/tools/my-tool.test.ts` using mock server pattern

## Testing

- All external deps mocked via `vi.mock()` before imports — no real commands execute.
- Mock server pattern: `createMockServer()` captures `.tool()` registrations, call handlers directly.
- MCP response format: `{ content: [{ type: "text", text: "..." }], isError?: boolean }`.
- Use `createTextContent()`, `createErrorContent()`, `formatToolOutput()` from `parsers.ts`.
- Coverage: 70% lines/functions/statements, 60% branches. `src/index.ts` excluded.

## Environment Variables (Non-Obvious Defaults)

| Variable | Default | Note |
|----------|---------|------|
| `DEFENSE_MCP_DRY_RUN` | `true` | Must set `false` to actually modify system |
| `DEFENSE_MCP_ALLOWED_DIRS` | `/tmp,/home,/var/log` | `/etc` excluded by design |
| `DEFENSE_MCP_COMMAND_TIMEOUT` | `120` (sec) | Per-tool: `DEFENSE_MCP_TIMEOUT_<TOOL>` |

## Runtime Dependencies

Only 2: `@modelcontextprotocol/sdk` and `zod`. Everything else is devDependency.

## PAM Safety (v0.8.1+)

- **PAM policy sanity validation**: `validatePamPolicySanity()` in `pam-utils.ts` checks for overly restrictive policies before applying
- Thresholds: `faillock deny < 3` = critical, `unlock_time = 0` = critical (permanent lock), `minlen > 64` = critical
- `force=true` parameter overrides critical blocks with explicit acknowledgment
- All PAM modifications: backup → parse → validate → write → post-write verify → auto-rollback on failure
- No more `sed` commands on PAM files — replaced with in-memory parser/serializer

## SSH Service-Awareness (v0.8.1+)

- `ssh_audit` detects whether sshd is installed/running before flagging config issues
- States: `active` (real findings), `installed_inactive` (downgraded), `removed_residual` (all INFO), `not_installed` (skip)
- Prevents false positives from leftover `/etc/ssh/sshd_config` after package removal
