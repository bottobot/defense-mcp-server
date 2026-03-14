# Safeguards Reference

This document describes the `SafeguardRegistry` system, application detection logic, operation-level safety checks, dry-run usage, and the backup/rollback subsystem for the defense-mcp-server.

---

## Table of Contents

1. [Overview](#overview)
2. [SafeguardRegistry Architecture](#safeguardregistry-architecture)
3. [Application Detection](#application-detection)
   - [VS Code Detection](#vs-code-detection)
   - [Docker Detection](#docker-detection)
   - [MCP Server Detection](#mcp-server-detection)
   - [Database Detection](#database-detection)
   - [Web Server Detection](#web-server-detection)
4. [Operations That Trigger Checks](#operations-that-trigger-checks)
5. [Warning vs Blocker Levels](#warning-vs-blocker-levels)
6. [Dry-Run Mode](#dry-run-mode)
   - [Enabling Dry-Run](#enabling-dry-run)
   - [Per-Call dry_run Parameter](#per-call-dry_run-parameter)
   - [Dry-Run Output Examples](#dry-run-output-examples)
7. [Backup Storage](#backup-storage)
   - [BackupManager Storage Layout](#backupmanager-storage-layout)
   - [Manifest Format](#manifest-format)
   - [Backup Lifecycle](#backup-lifecycle)
8. [Rollback and Restore Guide](#rollback-and-restore-guide)
   - [RollbackManager Overview](#rollbackmanager-overview)
   - [Change Types](#change-types)
   - [Rollback by Operation ID](#rollback-by-operation-id)
   - [Rollback by Session ID](#rollback-by-session-id)
   - [Restore from BackupManager](#restore-from-backupmanager)
   - [Manual Rollback Commands](#manual-rollback-commands)
9. [Changelog and Audit Trail](#changelog-and-audit-trail)

---

## Overview

The safeguard system has two independent layers:

| Layer | Class | Purpose |
|-------|-------|---------|
| Pre-execution detection | `SafeguardRegistry` | Detect running applications; emit warnings before modifying operations run |
| Post-execution recovery | `RollbackManager` + `BackupManager` | Track changes; restore original state on demand |

Both systems operate as singletons loaded at server startup. Neither requires additional configuration beyond the environment variables described in this document.

---

## SafeguardRegistry Architecture

`SafeguardRegistry` is a singleton (`src/core/safeguards.ts`) that runs five detection probes in parallel whenever a modifying tool is invoked:

```
SafeguardRegistry.getInstance().checkSafety(operation, params)
  -> detectVSCode()      (process check + filesystem + IPC sockets)
  -> detectDocker()      (socket + docker ps)
  -> detectMCPServers()  (.mcp.json config + node process scan)
  -> detectDatabases()   (TCP port probes: 5432, 3306, 27017, 6379)
  -> detectWebServers()  (pgrep for nginx, apache2, httpd)
```

The result is a `SafetyResult` object:

```typescript
interface SafetyResult {
  safe: boolean;       // false only when blockers.length > 0
  warnings: string[];  // non-blocking advisory messages
  blockers: string[];  // operation-halting conditions
  impactedApps: string[];  // names of apps that could be affected
}
```

---

## Application Detection

### VS Code Detection

Three independent signals are combined (any one is sufficient for detection):

| Signal | Method | Detail |
|--------|--------|--------|
| Running process | `pgrep -f code` | Detects the `code` binary in process table |
| Config directory | Filesystem check for `~/.vscode` | Indicates VS Code is or was installed |
| IPC sockets | `readdirSync(/run/user/<uid>)` filtered by `vscode-ipc-*` | Indicates active VS Code session |

VS Code detection is always **informational only** — it never produces a blocker. A warning is emitted stating that VS Code is active so operators are aware before making service or firewall changes.

### Docker Detection

| Signal | Method | Detail |
|--------|--------|--------|
| Docker socket | `existsSync("/var/run/docker.sock")` | Primary indicator that Docker daemon is running |
| Running containers | `docker ps --format {{.Names}}` | Lists up to 5 container names in the warning |

Docker warnings are emitted when operations touch any of: `container`, `docker`, `apparmor`, `seccomp`, `namespace`, `image`, `rootless`, `firewall`, `iptables`, `nftables`, `ufw`, `port`, `chain`, `microsegmentation`, `wireguard`, `service`, `systemd`, `systemctl`, `enable`, `disable`, `start`, `stop`, `restart`, `daemon`.

### MCP Server Detection

| Signal | Method | Detail |
|--------|--------|--------|
| MCP config file | Reads `/home/robert/defense-mcp-workspace/.mcp.json` | Counts configured MCP servers |
| Node processes | `pgrep -a node` filtered for `mcp` in command line | Detects running MCP-related node processes |

MCP server warnings are emitted when firewall operations are detected, because iptables/ufw rule changes can break the stdio transport that MCP servers rely on.

### Database Detection

TCP port probing with a 1-second timeout per port:

| Port | Database |
|------|----------|
| 5432 | PostgreSQL |
| 3306 | MySQL/MariaDB |
| 27017 | MongoDB |
| 6379 | Redis |

All four probes run in parallel. Only open ports are reported. Database warnings are triggered when operation keywords include `database`, `postgres`, `mysql`, `mongo`, `redis`, or `port`.

### Web Server Detection

| Process Name | Detection Method |
|-------------|-----------------|
| `nginx` | `pgrep -f nginx` |
| `apache2` | `pgrep -f apache2` |
| `httpd` | `pgrep -f httpd` |

Web server warnings are triggered when operation keywords include `nginx`, `apache`, `httpd`, `webserver`, `tls`, `cert`, or when firewall operations are combined with detected web server activity.

---

## Operations That Trigger Checks

The registry maps tool name keywords to affected application categories:

| Keyword Group | Triggers Warning For |
|--------------|---------------------|
| `container`, `docker`, `apparmor`, `seccomp`, `namespace`, `image`, `rootless` | Docker |
| `firewall`, `iptables`, `nftables`, `ufw`, `port`, `chain`, `microsegmentation`, `wireguard` | Docker, Databases, Web Servers, MCP Servers |
| `service`, `systemd`, `systemctl`, `enable`, `disable`, `start`, `stop`, `restart`, `daemon` | Docker, Web Servers |
| `database`, `postgres`, `mysql`, `mongo`, `redis`, `port` | Databases |
| `nginx`, `apache`, `httpd`, `webserver`, `tls`, `cert` | Web Servers |

The matching is case-insensitive substring matching against the full operation name. For example, the tool name `firewall_iptables_add` matches the `firewall` and `iptables` keyword groups.

---

## Warning vs Blocker Levels

The safeguard system uses two severity levels:

### Warnings (Non-Blocking)

Warnings are advisory messages appended to the tool response. They do not prevent execution. All current safeguard conditions produce warnings, not blockers.

Examples of warning messages:
- `"Docker is active (Docker socket exists; 3 container(s): web, db, cache) — operation may affect containers"`
- `"Firewall changes may disrupt Docker networking"`
- `"Database connectivity may be affected (Active: PostgreSQL, Redis)"`
- `"Web server traffic may be affected (Running: nginx)"`
- `"Firewall changes may affect MCP server communication"`
- `"VS Code is active (.vscode config dir exists; 2 IPC socket(s) found)"`

### Blockers (Operation-Halting)

Blockers set `safe: false` and prevent the operation from proceeding. As of v0.6.0, blockers are generated by:

- **Input validation failures**: Invalid operation name (fails `OperationSchema` validation), invalid chain name, invalid path, shell metacharacters
- **Real runtime blockers**: The safeguard system now includes real blocking conditions beyond validation errors. These are enforced via the `checkSafety()` method which evaluates operation context against detected application state.
- **Pre-flight validation failures**: Missing required binaries or unsatisfied privilege requirements block tool execution before the handler runs (see PREFLIGHT-ARCHITECTURE.md)

### Safety Check Error Handling

If any detection probe throws an exception (for example, due to permission errors reading `/run/user/<uid>`), the error is caught and converted to a warning rather than crashing the server:

```
"Safety check encountered an error: <error message>"
```

This ensures that safeguard failures are never fatal to tool execution.

---

## Dry-Run Mode

Dry-run mode causes all modifying operations to print the exact command that would be executed without actually running it. The tool still logs the planned change to the changelog.

### Enabling Dry-Run

**Default behavior**: The server reads `DEFENSE_MCP_DRY_RUN` at startup. The default is `false` in code, but the provided `.mcp.json` configuration sets it to `true` for safety.

```bash
# Enable dry-run globally (safe — no changes applied)
DEFENSE_MCP_DRY_RUN=true node build/index.js

# Disable dry-run globally (live changes will be applied)
DEFENSE_MCP_DRY_RUN=false node build/index.js
```

When dry-run is active, the server prints to stderr at startup:
```
[DEFENSE-MCP] DRY_RUN mode is ACTIVE — no changes will be applied
```

### Per-Call dry_run Parameter

Tools that support dry-run accept an optional `dry_run` boolean parameter. When provided, it overrides the global `DEFENSE_MCP_DRY_RUN` environment variable for that single call.

Tools that support `dry_run`:

| Category | Tools |
|----------|-------|
| Firewall | `firewall_iptables_add`, `firewall_iptables_delete`, `firewall_ufw_rule`, `firewall_save`, `firewall_restore`, `firewall_set_policy`, `firewall_create_chain`, `firewall_persistence` |
| Hardening | `harden_sysctl_set`, `harden_file_permissions`, `harden_service_manage`, `harden_umask_set`, `harden_coredump_disable`, `harden_banner_set`, `harden_bootloader_configure`, `harden_systemd_apply` |
| Access Control | `access_ssh_harden`, `access_password_policy`, `access_pam_configure`, `access_restrict_shell` |
| Compliance | `compliance_cron_restrict`, `compliance_tmp_hardening` |
| Logging | `log_auditd_rules`, `log_auditd_cis_rules` |
| Zero-Trust | `setup_wireguard`, `configure_microsegmentation`, `setup_mtls` |
| Container Advanced | `generate_seccomp_profile`, `apply_apparmor_container`, `setup_rootless_containers` |
| Automation | `defense_scheduled_audit` (actions: `create`, `remove`) |

### Dry-Run Output Examples

**Adding an iptables rule with global dry-run active:**

```
[DRY-RUN] Would execute:
  sudo iptables -t filter -I INPUT -p tcp --dport 22 -j ACCEPT

Rollback command:
  sudo iptables -t filter -D INPUT -p tcp --dport 22 -j ACCEPT
```

**Overriding dry-run per-call (live mode even when DEFENSE_MCP_DRY_RUN=true):**

```json
{
  "tool": "harden_sysctl_set",
  "params": {
    "key": "net.ipv4.tcp_syncookies",
    "value": "1",
    "persistent": true,
    "dry_run": false
  }
}
```

**Previewing compliance cron restriction:**

```json
{
  "tool": "compliance_cron_restrict",
  "params": {
    "action": "create",
    "allowed_users": ["root", "backup"],
    "dry_run": true
  }
}
```

Output:
```
[DRY-RUN] Would create /etc/cron.allow with users: root, backup
[DRY-RUN] Would create /etc/at.allow with users: root, backup
```

**Running compliance check in dry-run to preview which checks will run:**

```json
{
  "tool": "run_compliance_check",
  "params": {
    "framework": "pci-dss-v4",
    "dryRun": true
  }
}
```

---

## Backup Storage

### BackupManager Storage Layout

The `BackupManager` (`src/core/backup-manager.ts`) stores all file backups under:

```
~/.defense-mcp-backups/
├── manifest.json
├── 2026-02-21_10-30-45_sshd_config
├── 2026-02-21_10-31-02_login.defs
├── 2026-02-21_11-05-17_iptables-rules.v4
└── ...
```

The directory is created automatically on first use. No pre-configuration is required.

Backup filenames follow the pattern: `<ISO-timestamp>_<original-filename>`

Timestamps use the format `YYYY-MM-DD_HH-MM-SS` derived from ISO 8601 with colons and dots replaced by hyphens.

The `DEFENSE_MCP_BACKUP_DIR` environment variable overrides the default `~/.defense-mcp-backups` location:

```bash
DEFENSE_MCP_BACKUP_DIR=/mnt/secure-backup/defense-mcp node build/index.js
```

Note: The `RollbackManager` uses a separate storage path at `~/.defense-mcp/rollback-state.json` for tracking change records. The `BackupManager` at `~/.defense-mcp-backups/` is specifically for explicit file backups triggered by tools.

### Manifest Format

`~/.defense-mcp-backups/manifest.json` is a JSON file maintained by the BackupManager:

```json
{
  "backups": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "originalPath": "/etc/ssh/sshd_config",
      "backupPath": "/home/user/.defense-mcp-backups/2026-02-21_10-30-45_sshd_config",
      "timestamp": "2026-02-21T10:30:45.123Z",
      "sizeBytes": 3421
    }
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID v4 | Unique identifier for restore operations |
| `originalPath` | string | Absolute path of the source file |
| `backupPath` | string | Absolute path of the backup copy |
| `timestamp` | ISO 8601 | When the backup was created |
| `sizeBytes` | number | Size of the backed-up file in bytes |

### Backup Lifecycle

1. **Creation**: A tool calls `BackupManager.backup(filePath)` before modifying a file. The backup is created, the manifest is updated, and the backup ID is returned.

2. **Pruning**: Old backups can be pruned using `BackupManager.pruneOldBackups(daysOld)`. This removes backup files from disk and removes their entries from the manifest.

3. **Restoration**: Call `BackupManager.restore(backupId)` with the UUID from the manifest. The backup file is copied back to its original path.

---

## Rollback and Restore Guide

### RollbackManager Overview

The `RollbackManager` (`src/core/rollback.ts`) tracks system changes made during a session and provides structured rollback for four change types. State is persisted to `~/.defense-mcp/rollback-state.json`.

Each server startup generates a new `sessionId` (UUID). Changes are tagged with both an `operationId` (per tool invocation) and the `sessionId`, enabling rollback at two granularities.

### Change Types

| Type | Target | Original Value Stored | Rollback Mechanism |
|------|--------|-----------------------|-------------------|
| `file` | Absolute file path | Path to backup file | `copyFileSync(backupPath, targetPath)` |
| `sysctl` | Sysctl key (e.g., `kernel.randomize_va_space`) | Previous value string | `sysctl -w key=originalValue` |
| `service` | Service name (e.g., `nginx`) | Previous state (`active`/`inactive`) | `systemctl start/stop serviceName` |
| `firewall` | Chain/table description | Rollback command string | Execute stored rollback command via `spawn` |

### Rollback by Operation ID

Every tool invocation that creates a change entry logs an `operationId` to the changelog. To roll back a specific operation:

```bash
# Find the operation ID in the changelog
cat ~/.defense-mcp/changelog.json | python3 -m json.tool | grep -A5 '"operationId"'
```

Use the `defense_change_history` tool to list recent changes with their operation IDs:

```json
{
  "tool": "defense_change_history",
  "params": {}
}
```

To roll back, the RollbackManager API is called programmatically. Expose via an MCP tool if needed:

```typescript
const rb = RollbackManager.getInstance();
await rb.rollback("operation-uuid-here");
```

Rollback applies changes in **reverse chronological order** within the operation.

### Rollback by Session ID

To roll back all changes from the current session:

```typescript
const rb = RollbackManager.getInstance();
const sessionId = rb.getSessionId();
await rb.rollbackSession(sessionId);
```

This is the safest recovery path after a failed hardening session — it undoes all changes in reverse order.

### Restore from BackupManager

**Step 1**: List available backups using the `backup_list` tool or by reading the manifest:

```json
{
  "tool": "backup_list",
  "params": {}
}
```

The output includes backup IDs and original paths:
```json
{
  "backups": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "originalPath": "/etc/ssh/sshd_config",
      "backupPath": "/home/user/.defense-mcp-backups/2026-02-21_10-30-45_sshd_config",
      "timestamp": "2026-02-21T10:30:45.123Z",
      "sizeBytes": 3421
    }
  ]
}
```

**Step 2**: Restore using the `backup_restore` tool:

```json
{
  "tool": "backup_restore",
  "params": {
    "backup_id": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

The BackupManager copies the backup file back to its original path. The target directory is created if it does not exist.

**Step 3**: Verify the restore using `backup_verify`:

```json
{
  "tool": "backup_verify",
  "params": {
    "backup_id": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

### Manual Rollback Commands

Every tool that modifies state logs a `rollbackCommand` to the changelog. To manually reverse a change:

1. Find the rollback command in `~/.defense-mcp/changelog.json`:
   ```bash
   cat ~/.defense-mcp/changelog.json | python3 -c "
   import json, sys
   entries = json.load(sys.stdin)
   for e in entries[-10:]:
       if e.get('rollbackCommand'):
           print(e['timestamp'], e['tool'], e['rollbackCommand'])
   "
   ```

2. Execute the rollback command directly. Examples:
   ```bash
   # Undo an iptables rule addition
   sudo iptables -t filter -D INPUT -p tcp --dport 22 -j ACCEPT

   # Restore a backed-up file
   sudo cp /home/user/.defense-mcp-backups/2026-02-21_10-30-45_sshd_config /etc/ssh/sshd_config

   # Revert a sysctl change
   sudo sysctl -w kernel.randomize_va_space=1

   # Revert a chain policy change
   sudo iptables -P INPUT ACCEPT
   ```

---

## Changelog and Audit Trail

All changes are logged to `~/.defense-mcp/changelog.json` (configurable via `DEFENSE_MCP_CHANGELOG_PATH`).

Each entry contains:

```json
{
  "id": "uuid-v4",
  "operationId": "uuid-v4",
  "tool": "harden_sysctl_set",
  "action": "Set net.ipv4.tcp_syncookies = 1",
  "target": "net.ipv4.tcp_syncookies",
  "before": "0",
  "after": "1",
  "timestamp": "2026-02-21T10:30:45.123Z",
  "dryRun": false,
  "success": true,
  "rollbackCommand": "sudo sysctl -w net.ipv4.tcp_syncookies=0",
  "backupPath": null
}
```

Use the `defense_change_history` tool to view the audit trail in a formatted way:

```json
{
  "tool": "defense_change_history",
  "params": {
    "limit": 20
  }
}
```
