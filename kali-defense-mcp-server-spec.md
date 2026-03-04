# kali-defense-mcp-server — Implementation Spec
> Machine-readable build specification. Implement sequentially. All constraints are hard requirements unless marked `[OPTIONAL]`.

---

## META

```
LANGUAGE:     Python 3.11+
FRAMEWORK:    FastMCP (mcp[cli] package)
VALIDATION:   Pydantic v2 for all tool inputs
TRANSPORT:    stdio (never HTTP/SSE)
PRIVILEGE:    Unprivileged user + sudoers delegation (never run as root)
DB:           SQLite (aiosqlite, WAL mode) for changelog
ASYNC:        asyncio throughout; long-running tools are background jobs
STYLE:        Verb-noun tool names: check_*, harden_*, verify_*, list_*, run_*, get_*
```

---

## INVARIANTS — Apply to every tool, no exceptions

1. **Never `shell=True`.** All subprocess calls use parameterised list form.
2. **Command allowlist.** Every external binary is declared in `ALLOWED_COMMANDS: dict[str, Path]`. Reject anything not in it.
3. **Dry-run default.** Every `harden_*` tool has `dry_run: bool = True`. With `dry_run=True`: compute diff, return `ChangePreview`, touch nothing.
4. **Backup before mutate.** Any `harden_*` call with `dry_run=False` MUST call `BackupManager.snapshot()` before touching the filesystem. On any exception after snapshot: auto-restore and re-raise.
5. **Validate before restart.** For services with a `--test` flag (sshd, nginx, etc.), run it and assert exit 0 before calling `systemctl restart`.
6. **Return structured data.** All tools return Pydantic models serialised to JSON, never raw strings.
7. **Confirmation gates.** Tools with `risk_level = MEDIUM` require `confirmed: bool` param (must be `True` to apply). Tools with `risk_level = HIGH` require `confirm_string: str` param matching a declared constant.

---

## PYDANTIC MODELS — Define in `src/validators/inputs.py`

```python
class RiskLevel(str, Enum):
    LOW    = "LOW"
    MEDIUM = "MEDIUM"
    HIGH   = "HIGH"

class ConfirmationType(str, Enum):
    NONE         = "none"
    YES_NO       = "yes_no"
    STRING_MATCH = "string_match"
    CHOICE       = "choice"

class ChangePreview(BaseModel):
    tool: str
    risk_level: RiskLevel
    affected_files: list[str]
    diff: dict[str, str]          # {filepath: unified_diff_string}
    estimated_seconds: int
    reversible: bool
    rollback_method: str
    confirmation_required: ConfirmationType
    confirmation_string: str | None = None  # for STRING_MATCH type
    warnings: list[str] = []

class ChangeRecord(BaseModel):
    change_id: str                # uuid4
    timestamp: datetime
    tool: str
    affected_files: list[str]
    backup_paths: dict[str, Path] # {original_path: backup_path}
    applied: bool
    rolled_back: bool = False

class JobStatus(BaseModel):
    job_id: str
    status: Literal["running", "complete", "failed"]
    percent_complete: int
    current_task: str
    eta_seconds: int | None
    result: dict | None = None    # populated when status == "complete"

class EnvironmentProfile(BaseModel):
    distro_family: Literal["debian", "rhel", "arch", "unknown"]
    distro_name: str
    kernel_version: str
    system_role: Literal["server", "desktop", "unknown"]
    has_vpn: bool
    has_containers: bool
    has_asymmetric_routing: bool
    active_ssh_sessions: int
    current_session_auth_method: Literal["key", "password", "unknown"]
    display_manager_present: bool
    package_manager: Literal["apt", "dnf", "pacman", "unknown"]
```

---

## DIRECTORY STRUCTURE

```
kali-defense-mcp-server/
├── pyproject.toml
├── resources/
│   ├── sysctl-hardening.conf      # reference kernel params
│   ├── sshd-hardened.conf         # reference SSH config
│   └── sudoers.d/mcp-hardening    # sudo rules template
├── src/
│   ├── server.py                  # FastMCP app + tool registration
│   ├── config.py                  # Pydantic Settings
│   ├── validators/
│   │   └── inputs.py              # all Pydantic models (see above)
│   ├── executors/
│   │   ├── command_runner.py      # safe_execute() + ALLOWED_COMMANDS
│   │   └── privilege.py           # sudo delegation helpers
│   ├── state/
│   │   ├── changelog.py           # SQLite WAL + plaintext fallback
│   │   └── backups.py             # BackupManager
│   └── tools/
│       ├── environment.py         # EnvironmentFingerprint
│       ├── rollback.py            # list_changes, rollback_change
│       ├── assessment.py          # Lynis, port scan
│       ├── firewall.py            # UFW / firewalld
│       ├── ssh.py                 # sshd_config + ssh-audit + fail2ban
│       ├── kernel.py              # sysctl
│       ├── services.py            # systemd service minimisation
│       ├── mac.py                 # AppArmor / SELinux
│       ├── fim.py                 # AIDE
│       ├── malware.py             # rkhunter, chkrootkit, ClamAV
│       ├── auth.py                # PAM, password policy
│       ├── updates.py             # unattended-upgrades, needrestart
│       ├── compliance.py          # OpenSCAP CIS/STIG
│       └── orchestrator.py        # full_harden workflow
└── tests/
    ├── test_command_runner.py     # injection rejection tests
    └── test_validators.py
```

---

## EXECUTORS

### `src/executors/command_runner.py`

```python
ALLOWED_COMMANDS: dict[str, str] = {
    "ufw":                 "/usr/sbin/ufw",
    "firewall-cmd":        "/usr/bin/firewall-cmd",
    "sshd":                "/usr/sbin/sshd",
    "systemctl":           "/usr/bin/systemctl",
    "sysctl":              "/usr/sbin/sysctl",
    "lynis":               "/usr/bin/lynis",
    "aide":                "/usr/bin/aide",
    "rkhunter":            "/usr/bin/rkhunter",
    "chkrootkit":          "/usr/sbin/chkrootkit",
    "clamscan":            "/usr/bin/clamscan",
    "freshclam":           "/usr/bin/freshclam",
    "ssh-audit":           "/usr/bin/ssh-audit",
    "fail2ban-client":     "/usr/bin/fail2ban-client",
    "aa-status":           "/usr/sbin/aa-status",
    "aa-enforce":          "/usr/sbin/aa-enforce",
    "aa-complain":         "/usr/sbin/aa-complain",
    "getenforce":          "/usr/sbin/getenforce",
    "setenforce":          "/usr/sbin/setenforce",
    "oscap":               "/usr/bin/oscap",
    "ss":                  "/usr/sbin/ss",
    "needrestart":         "/usr/sbin/needrestart",
    "chage":               "/usr/bin/chage",
    "trivy":               "/usr/bin/trivy",
}

async def safe_execute(
    tool: str,
    args: list[str],
    timeout: int = 300,
    use_sudo: bool = False,
) -> tuple[int, str, str]:
    """Returns (returncode, stdout, stderr). Raises ValueError if tool not in allowlist."""
    if tool not in ALLOWED_COMMANDS:
        raise ValueError(f"Command not in allowlist: {tool}")
    # Validate no shell metacharacters in args
    for arg in args:
        if any(c in arg for c in [';', '|', '&', '`', '$', '>', '<', '\n']):
            raise ValueError(f"Illegal character in argument: {arg!r}")
    cmd = (["sudo"] if use_sudo else []) + [ALLOWED_COMMANDS[tool]] + args
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    return proc.returncode, stdout.decode(), stderr.decode()
```

### `src/state/backups.py` — BackupManager

```python
BACKUP_ROOT = Path("/var/backups/mcp-hardening")
MAX_BACKUPS_PER_FILE = 30

class BackupManager:
    async def snapshot(self, files: list[Path], tool: str) -> ChangeRecord:
        """Copy each file to timestamped backup dir. Return ChangeRecord with change_id."""

    async def restore(self, change_id: str) -> None:
        """Restore all files from a ChangeRecord's backup_paths. Raises if backup missing."""
```

### `src/state/changelog.py` — SQLite WAL

```python
# Schema
CREATE TABLE changes (
    change_id    TEXT PRIMARY KEY,
    timestamp    TEXT NOT NULL,
    tool         TEXT NOT NULL,
    affected     TEXT NOT NULL,  -- JSON list of paths
    backup_paths TEXT NOT NULL,  -- JSON dict {original: backup}
    applied      INTEGER NOT NULL,
    rolled_back  INTEGER NOT NULL DEFAULT 0
);
# Always open with: PRAGMA journal_mode=WAL;
# Also write plaintext to /var/backups/mcp-hardening/changelog.txt as fallback
```

---

## TOOLS — Full specification

Format per tool:
```
TOOL NAME         | risk | dry_run | confirmed/confirm_string | background_job
inputs (Pydantic) → output model
logic summary
confirmation prompt (exact text the LLM must present to the user)
```

---

### MODULE: environment.py

#### `fingerprint_environment`
```
RISK: LOW | no dry_run | no confirmation | sync
inputs: none
output: EnvironmentProfile
```
Logic:
- Read `/etc/os-release` → distro_family, distro_name
- `uname -r` → kernel_version
- Check for display managers (`lightdm`, `gdm`, `sddm` in systemd units) → system_role
- `ip link show` → count VPN interfaces (tun*, wg*), bridge interfaces (docker*, br-*)
- `ss -tulnp` → parse; check IP forwarding via `/proc/sys/net/ipv4/ip_forward`
- `who` + `ss` on port 22 → active_ssh_sessions
- Check `$SSH_AUTH_SOCK` and `/proc/$PPID/environ` → current_session_auth_method
- Check `which apt|dnf|pacman` → package_manager

---

### MODULE: rollback.py

#### `list_changes`
```
RISK: LOW | no confirmation | sync
inputs: limit: int = 20, tool_filter: str | None = None
output: list[ChangeRecord]
```

#### `rollback_change`
```
RISK: LOW | confirmed: bool | sync
inputs: change_id: str, confirmed: bool = False
output: ChangeRecord (with rolled_back=True)
confirmation prompt:
  "Rolling back change [{change_id}] will restore: {affected_files}.
   This will overwrite the current versions of those files.
   Proceed? [yes/no]"
```

---

### MODULE: assessment.py

#### `run_lynis_audit`
```
RISK: LOW | background_job=True
inputs: none
output: JobStatus (immediate); final result has LynisReport model
```
`LynisReport`:
```python
class LynisReport(BaseModel):
    hardening_index: int          # 0-100
    warnings: list[LynisItem]
    suggestions: list[LynisItem]
    tests_performed: int
    tests_skipped: int
```
Logic:
- Check lynis binary exists; if not: return error with install instruction
- Run `lynis audit system --no-colors --quiet` as background job
- Parse `/var/log/lynis-report.dat` on completion
- confirmation prompt:
  ```
  "Running a full Lynis audit will take 2–5 minutes.
   It is read-only and makes no changes to your system.
   Proceed? [yes/no]"
  ```

#### `get_lynis_score`
```
RISK: LOW | sync
inputs: none
output: {hardening_index: int, last_run: datetime | None}
```
Logic: Read cached `/var/log/lynis-report.dat` if exists; else prompt to run `run_lynis_audit` first.

#### `check_open_ports`
```
RISK: LOW | sync
inputs: none
output: list[{port, protocol, process, pid, state}]
```
Logic: `ss -tulnp`, parse output.

---

### MODULE: firewall.py

#### `check_firewall_status`
```
RISK: LOW | sync
inputs: none
output: {backend: "ufw"|"firewalld"|"none", enabled: bool, default_policy: str, rules: list[FirewallRule]}
```

#### `harden_firewall_baseline`
```
RISK: MEDIUM | dry_run=True | confirmed: bool
inputs:
  allow_ports: list[str]   # e.g. ["22/tcp", "443/tcp"]
  dry_run: bool = True
  confirmed: bool = False
output: ChangePreview | ChangeRecord
```
Logic:
1. Call `fingerprint_environment()` — get active_ssh_sessions, current session
2. Assert current SSH port is in allow_ports. If not: BLOCK and return error:
   `"BLOCKED: Port {ssh_port} is not in allow_ports. Adding it to prevent lockout."`
   Auto-add it and warn user.
3. Compute diff of current vs proposed rules
4. If `dry_run=True`: return ChangePreview
5. If `confirmed=False`: return ChangePreview with `confirmation_required=YES_NO`
6. Apply: `ufw default deny incoming`, `ufw default allow outgoing`, `ufw allow {port}` for each
7. `ufw --force enable`
8. Snapshot → ChangeRecord

Confirmation prompt:
```
"Applying the firewall baseline will:
 - Set default inbound policy: DENY ALL
 - Allow: {allow_ports}
 - Your current session port ({ssh_port}) IS included in the allow list.

 This is reversible via rollback_change. Proceed? [yes/no]"
```

#### `add_firewall_rule` / `remove_firewall_rule`
```
RISK: MEDIUM | dry_run=True | confirmed: bool
inputs: port: str, protocol: Literal["tcp","udp","any"], direction: Literal["in","out"] = "in", dry_run: bool = True, confirmed: bool = False
```

---

### MODULE: ssh.py

#### `check_ssh_status`
```
RISK: LOW | sync
inputs: none
output: SSHStatus model
```
```python
class SSHStatus(BaseModel):
    port: int
    permit_root_login: str
    password_authentication: str
    pubkey_authentication: str
    max_auth_tries: int
    protocol: str
    allowed_ciphers: list[str]
    cis_failures: list[str]      # human-readable list of CIS benchmark failures
    ssh_audit_score: str | None  # "good" | "warn" | "fail" | None if ssh-audit not installed
```

#### `harden_ssh_config`
```
RISK: HIGH | dry_run=True | confirm_string: str
CONFIRM_STRING_CONSTANT = "CONFIRM-SSH"
inputs:
  disable_password_auth: bool = True
  disable_root_login: bool = True
  max_auth_tries: int = 3
  allowed_users: list[str] = []   # empty = no AllowUsers restriction
  custom_port: int | None = None
  dry_run: bool = True
  confirm_string: str = ""
output: ChangePreview | ChangeRecord
```
Logic:
1. `fingerprint_environment()` → current_session_auth_method, active_ssh_sessions
2. If `disable_password_auth=True` AND `current_session_auth_method == "password"`:
   HARD BLOCK — return error:
   ```
   "BLOCKED: You are currently connected via password authentication.
    Disabling password auth without a working SSH key will lock you out permanently.
    Set up SSH key authentication and reconnect before running this tool."
   ```
3. Generate new sshd_config from template + inputs
4. Write to temp file, run `sshd -t -f {tempfile}`, assert exit 0
5. If `dry_run=True`: return ChangePreview
6. If `confirm_string != CONFIRM_STRING_CONSTANT`: return ChangePreview with:
   `confirmation_required=STRING_MATCH`, `confirmation_string="CONFIRM-SSH"`
7. Snapshot → apply → `systemctl restart sshd` → run `ssh-audit localhost` → return ChangeRecord + audit result

Confirmation prompt:
```
"⚠️  HIGH RISK OPERATION

SSH hardening will modify /etc/ssh/sshd_config and restart the SSH daemon.

Proposed changes:
{diff}

Your current session auth method: {current_session_auth_method}
Active SSH sessions: {active_ssh_sessions}

If disable_password_auth=True and you have no SSH key configured,
you will be permanently locked out of SSH.

To proceed, type exactly: CONFIRM-SSH"
```

#### `check_fail2ban_status`
```
RISK: LOW | sync
output: {installed: bool, active: bool, jails: list[{name, filter, ban_count, currently_banned: list[str]}]}
```

#### `install_fail2ban_baseline`
```
RISK: MEDIUM | dry_run=True | confirmed: bool
inputs: ssh_max_retry: int = 5, ban_time: str = "1h", find_time: str = "10m", dry_run: bool = True, confirmed: bool = False
```
Logic: Before applying, verify no iptables chain conflict with UFW (`ufw status` + `iptables -L` check).

---

### MODULE: kernel.py

#### `check_kernel_params`
```
RISK: LOW | sync
output: list[{param, current_value, cis_recommended, compliant: bool}]
```
CIS params to check (minimum set):
```
kernel.randomize_va_space         = 2
net.ipv4.conf.all.rp_filter       = 1
net.ipv4.conf.default.rp_filter   = 1
net.ipv4.tcp_syncookies           = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects  = 0
net.ipv4.ip_forward               = 0   # SKIP if has_containers or has_vpn
kernel.dmesg_restrict             = 1
kernel.kptr_restrict              = 2
net.ipv6.conf.all.disable_ipv6   = 1   # [OPTIONAL] — only suggest, don't auto-apply
fs.suid_dumpable                  = 0
```

#### `harden_kernel_params`
```
RISK: MEDIUM | dry_run=True | confirmed: bool
inputs: dry_run: bool = True, confirmed: bool = False, skip_params: list[str] = []
output: ChangePreview | ChangeRecord
```
Logic:
1. `fingerprint_environment()` → has_vpn, has_containers, has_asymmetric_routing
2. Auto-exclude `net.ipv4.ip_forward` if `has_containers or has_vpn`
3. Auto-exclude `net.ipv4.conf.all.rp_filter` if `has_asymmetric_routing`
4. Write to `/etc/sysctl.d/99-mcp-hardening.conf`
5. Apply with `sysctl -p /etc/sysctl.d/99-mcp-hardening.conf`
6. Verify each param with `sysctl {param}`

Confirmation prompt:
```
"Kernel parameter hardening will write /etc/sysctl.d/99-mcp-hardening.conf
 and apply changes immediately. Changes persist across reboot.

Environment detection results:
 - VPN interfaces detected: {has_vpn} → ip_forward param: {included/excluded}
 - Container bridges detected: {has_containers} → ip_forward param: {included/excluded}
 - Asymmetric routing detected: {has_asymmetric_routing} → rp_filter: {included/excluded}

Proposed changes:
{diff}

Proceed? [yes/no]"
```

---

### MODULE: services.py

#### `list_enabled_services`
```
RISK: LOW | sync
output: list[{name, description, enabled, active, safe_to_disable_server: bool, safe_to_disable_desktop: bool, reason: str}]
```
Maintain a curated list of services with `safe_to_disable_server` and `safe_to_disable_desktop` flags. Examples:
```python
SAFE_TO_DISABLE = {
    "avahi-daemon":   {"server": True,  "desktop": False, "reason": "mDNS/Bonjour — not needed on servers"},
    "cups":           {"server": True,  "desktop": False, "reason": "Printing service — not needed on servers"},
    "bluetooth":      {"server": True,  "desktop": False, "reason": "Bluetooth — not needed on servers"},
    "whoopsie":       {"server": True,  "desktop": True,  "reason": "Ubuntu error reporting"},
    "apport":         {"server": True,  "desktop": True,  "reason": "Crash reporting"},
    "snapd":          {"server": False, "desktop": False, "reason": "Review manually"},
}
```

#### `disable_service`
```
RISK: MEDIUM | dry_run=True | confirmed: bool
inputs: service_name: str, dry_run: bool = True, confirmed: bool = False
```
Confirmation prompt:
```
"Disabling {service_name} will stop it now and prevent it starting on reboot.
 Description: {description}
 Known dependencies: {dependents}
 Reversal: systemctl enable {service_name} && systemctl start {service_name}

 Proceed? [yes/no]"
```

---

### MODULE: mac.py

#### `check_mac_status`
```
RISK: LOW | sync
output: {backend: "apparmor"|"selinux"|"none", mode: "enforcing"|"permissive"|"disabled", profiles: list[{name, mode, recent_violations: int}]}
```

#### `enable_mac_complain_mode`
```
RISK: LOW | confirmed: bool
```
Confirmation prompt:
```
"Enabling AppArmor COMPLAIN mode will log policy violations but not block them.
 No applications will be interrupted. This is the recommended first step
 before enabling enforcement.
 Proceed? [yes/no]"
```

#### `get_mac_violations`
```
RISK: LOW | sync
inputs: hours_back: int = 168  # 7 days
output: list[{profile, operation, denied_resource, count}] sorted by count desc
```
Logic: Parse `/var/log/audit/audit.log` or `journalctl` for `apparmor="ALLOWED"` type=AVC entries.

#### `enable_mac_enforce_profile`
```
RISK: MEDIUM | confirmed: bool
inputs: profile_name: str, confirmed: bool = False
```
Confirmation prompt:
```
"Enforcing AppArmor profile [{profile_name}] will block all actions
 that violate its rules. Recent violations for this profile: {violation_count}.
 Applications using this profile may be interrupted if violations exist.
 Proceed? [yes/no]"
```

#### `enable_mac_enforce_global`
```
RISK: HIGH | confirm_string: str
CONFIRM_STRING_CONSTANT = "CONFIRM-ENFORCE"
inputs: confirm_string: str = ""
```
Confirmation prompt:
```
"⚠️  HIGH RISK OPERATION

Enabling global AppArmor enforcement will immediately block ALL applications
from performing actions that violate their profiles.

Profiles with recent violations ({violation_count} total):
{violation_summary}

Applications with violations WILL LIKELY CRASH OR BECOME INACCESSIBLE
until their profiles are corrected.

Recommended: Use enable_mac_enforce_profile() per-profile instead.

To proceed anyway, type exactly: CONFIRM-ENFORCE"
```

---

### MODULE: fim.py

#### `check_aide_status`
```
RISK: LOW | sync
output: {installed: bool, database_exists: bool, database_age_days: int | None, last_check: datetime | None}
```

#### `init_aide_database`
```
RISK: LOW | background_job=True
inputs: scope: Literal["critical", "full"] = "critical"
  # critical = /etc /bin /sbin /usr/bin /usr/sbin
  # full     = entire filesystem
output: JobStatus (immediate)
```
Scoped AIDE config:
```
# critical scope — write to /etc/aide/aide-mcp.conf
/etc        Full
/bin        Binlib
/sbin       Binlib
/usr/bin    Binlib
/usr/sbin   Binlib
```
Confirmation prompt:
```
"Building the AIDE baseline will take:
 - Critical directories (/etc, /bin, /sbin, /usr): ~2 minutes
 - Full filesystem: 10–30 minutes

Scope selected: {scope}
Resource impact: Moderate CPU + IO during build. Runs in background.

Note: This is read-only. It creates a snapshot database — no changes to your files.
Proceed? [yes/no]"
```

#### `run_aide_check`
```
RISK: LOW | background_job=True
output: JobStatus → AideReport({added: list[str], removed: list[str], changed: list[str], unchanged_count: int})
```

#### `schedule_aide_check` `[OPTIONAL]`
```
RISK: LOW | confirmed: bool
inputs: schedule: str = "daily"  # creates systemd timer
```

---

### MODULE: malware.py

#### `run_rkhunter`
```
RISK: LOW | background_job=True
output: JobStatus → RkhunterReport({warnings: list[str], found_rootkits: list[str], suspicious_files: list[str]})
```
Logic: `rkhunter --check --sk --rwo`, parse output.

#### `run_chkrootkit`
```
RISK: LOW | background_job=True
output: JobStatus → {infected: list[str], not_infected: list[str]}
```

#### `run_clamav_scan`
```
RISK: LOW | background_job=True
inputs: scope: Literal["targeted", "full"] = "targeted"
  # targeted = /tmp /home /var/www /var/tmp
  # full     = /
```
Confirmation prompt:
```
"ClamAV scan resource requirements:
 - Targeted (/tmp, /home, /var/www): 5–10 minutes, ~400 MB RAM
 - Full filesystem: 20–60 minutes, ~400 MB RAM, sustained CPU usage

Scope selected: {scope}
Runs in background. Read-only — no files will be modified.
Proceed? [yes/no]"
```

#### `full_malware_scan`
```
RISK: LOW | background_job=True
inputs: clamav_scope: Literal["targeted", "full"] = "targeted"
output: JobStatus → {rkhunter: RkhunterReport, chkrootkit: dict, clamav: dict, summary: str}
```
Logic: Run rkhunter, chkrootkit, clamscan in sequence. Return unified report.

---

### MODULE: auth.py

#### `check_auth_policy`
```
RISK: LOW | sync
output: {
  password_min_length: int | None,
  password_complexity: bool,
  account_lockout_enabled: bool,
  lockout_attempts: int | None,
  lockout_duration: str | None,
  cis_failures: list[str]
}
```
Logic: Parse `/etc/pam.d/common-auth`, `/etc/pam.d/common-password`, `/etc/security/pwquality.conf`, `/etc/security/faillock.conf`.

#### `harden_password_policy`
```
RISK: MEDIUM | dry_run=True | confirmed: bool
inputs:
  min_length: int = 14
  require_uppercase: bool = True
  require_lowercase: bool = True
  require_digits: bool = True
  require_special: bool = True
  dry_run: bool = True
  confirmed: bool = False
```
Logic: Modify `/etc/security/pwquality.conf`. Does NOT retroactively affect existing passwords.

#### `harden_account_lockout`
```
RISK: MEDIUM | dry_run=True | confirmed: bool
inputs:
  deny_attempts: int = 5
  unlock_time: int = 900        # seconds (0 = never auto-unlock)
  dry_run: bool = True
  confirmed: bool = False
```
Logic: Configure `pam_faillock` in `/etc/pam.d/common-auth` and `/etc/pam.d/common-account`.

---

### MODULE: updates.py

#### `check_pending_updates`
```
RISK: LOW | sync
output: {security_updates: int, other_updates: int, packages: list[{name, current_version, new_version, is_security: bool}]}
```
Logic: `apt list --upgradable 2>/dev/null` (debian) or `dnf check-update --security` (rhel).

#### `check_needrestart`
```
RISK: LOW | sync
output: {services_needing_restart: list[str], kernel_update_pending: bool}
```

#### `configure_unattended_upgrades`
```
RISK: MEDIUM | dry_run=True | confirmed: bool
inputs:
  mode: Literal["download_only", "auto_install"] = "download_only"
  dry_run: bool = True
  confirmed: bool = False
```
Confirmation prompt:
```
"Configuring automatic security updates in [{mode}] mode.

- download_only: Security patches downloaded automatically, installed manually.
  Safe for production — you control when changes are applied.
- auto_install: Patches applied automatically. May restart services (including sshd).
  On kernel updates, a reboot will be required.

Mode selected: {mode}
Proceed? [yes/no]"
```

---

### MODULE: compliance.py

#### `run_cis_scan`
```
RISK: LOW | background_job=True
inputs: level: Literal[1, 2] = 1
output: JobStatus → ComplianceReport
```
```python
class ComplianceReport(BaseModel):
    profile: str
    pass_count: int
    fail_count: int
    error_count: int
    score_percent: float
    failures: list[{rule_id: str, title: str, severity: str, fix_text: str}]
    report_path: str   # path to generated HTML report
```
Logic: `oscap xccdf eval --profile cis_level{level} --results /tmp/mcp-cis-results.xml --report /tmp/mcp-cis-report.html /usr/share/scap-security-guide/ssg-{distro}-ds.xml`
Confirmation prompt:
```
"Running an OpenSCAP CIS Level {level} benchmark scan will evaluate ~300 rules.
Read-only. Produces an HTML compliance report.
Estimated time: 3–8 minutes.
Proceed? [yes/no]"
```

#### `run_stig_scan` `[OPTIONAL]`
```
RISK: LOW | background_job=True
inputs: none
output: JobStatus → ComplianceReport
```

---

### MODULE: orchestrator.py

#### `full_harden`
```
RISK: varies per step | interactive confirmation flow
inputs:
  allow_ports: list[str] = ["22/tcp"]
  clamav_scope: Literal["targeted", "full"] = "targeted"
  aide_scope: Literal["critical", "full"] = "critical"
  skip_steps: list[str] = []    # tool names to skip
  dry_run: bool = True          # if True: preview entire plan, apply nothing
output: FullHardenReport
```
```python
class FullHardenReport(BaseModel):
    environment: EnvironmentProfile
    lynis_before: int            # hardening_index before
    lynis_after: int | None      # hardening_index after (None if dry_run)
    steps_completed: list[str]
    steps_skipped: list[str]
    steps_failed: list[str]
    change_ids: list[str]        # for rollback
    report_path: str             # HTML report path
```
Execution order:
```
1.  fingerprint_environment()                     — no confirmation
2.  run_lynis_audit()                             — LOW: single prompt
3.  Present full plan with per-step risk levels   — user reviews, confirms plan
4.  check_firewall_status()                       — no confirmation
5.  harden_firewall_baseline()                    — MEDIUM: confirm
6.  check_ssh_status()                            — no confirmation
7.  harden_ssh_config()                           — HIGH: confirm_string
8.  check_kernel_params()                         — no confirmation
9.  harden_kernel_params()                        — MEDIUM: confirm
10. list_enabled_services()                       — no confirmation
11. disable_service() per recommended service     — MEDIUM: confirm each
12. check_auth_policy()                           — no confirmation
13. harden_password_policy()                      — MEDIUM: confirm
14. harden_account_lockout()                      — MEDIUM: confirm
15. check_fail2ban_status()                       — no confirmation
16. install_fail2ban_baseline()                   — MEDIUM: confirm
17. check_aide_status()                           — no confirmation
18. init_aide_database()                          — LOW: single prompt
19. run_rkhunter()                                — LOW
20. run_clamav_scan()                             — LOW: scope prompt
21. check_mac_status()                            — no confirmation
22. enable_mac_complain_mode()                    — LOW: confirm
23. configure_unattended_upgrades()               — MEDIUM: confirm
24. run_lynis_audit()                             — final score
25. generate HTML report                          — write to ~/mcp-harden-report.html
```
On `dry_run=True`: steps 4–25 return ChangePreview only; nothing applied.

---

## BACKGROUND JOB PATTERN

All tools marked `background_job=True` follow this contract:

```python
# Tool returns immediately:
{"job_id": "uuid4", "status": "running", "estimated_seconds": 180, ...}

# Polling tool (always available):
get_job_status(job_id: str) → JobStatus

# Result retrieval:
get_job_result(job_id: str) → JobStatus  # with result populated when complete
```

Implement with `asyncio.Task` stored in a module-level `JOBS: dict[str, asyncio.Task]`.
Poll interval recommendation for LLM: 15 seconds.

---

## SAFETY RULES — Hard stops (non-negotiable)

| Condition | Action |
|-----------|--------|
| SSH port not in firewall allow_ports | Auto-add it, warn user, block raw removal |
| current_session_auth_method == "password" AND disable_password_auth == True | HARD BLOCK — return error, do not proceed |
| confirm_string mismatch on HIGH risk tool | Return ChangePreview, do not apply |
| sshd -t fails on new config | Abort, do not write, do not restart sshd |
| BackupManager.snapshot() fails | Abort entire harden_* call, return error |
| Any harden_* step fails mid-execution | Auto-restore from snapshot, return error with change_id for manual rollback |
| AppArmor global enforce with violation_count > 0 | Require confirm_string AND display per-profile violation summary |

---

## EXTERNAL DEPENDENCIES — Install detection pattern

For every external tool, check binary existence before use:

```python
async def check_tool_available(tool: str) -> bool:
    rc, _, _ = await safe_execute("which", [ALLOWED_COMMANDS[tool]])
    return rc == 0

# If not available, return:
{"error": f"{tool} is not installed.", "install_command": "apt install {package}"}
# Never raise an exception for missing optional tools
```

---

## RESOURCES (MCP Resources — read-only, always current)

Expose as MCP Resources for ambient context in the LLM's conversation:

| Resource URI | Content |
|---|---|
| `system://firewall/rules` | Current UFW/firewalld rules as JSON |
| `system://ssh/config` | Parsed sshd_config key-value pairs |
| `system://open-ports` | Output of check_open_ports() |
| `system://kernel-params` | CIS sysctl params + current values |
| `system://lynis-score` | Latest hardening index score |
| `system://changes` | Last 10 ChangeRecords |

---

## TESTING REQUIREMENTS

`tests/test_command_runner.py` must cover:
- Shell metacharacter injection: `;`, `|`, `&`, `` ` ``, `$()`, `>`, `<`
- Tool not in allowlist → ValueError
- Argument with embedded newline → ValueError
- Valid call returns (returncode, stdout, stderr) tuple

`tests/test_validators.py` must cover:
- confirm_string mismatch on HIGH risk tool → no apply
- dry_run=True → no filesystem mutation
- BackupManager.snapshot() creates files at expected paths
- rollback_change restores file content exactly

---

## pyproject.toml (minimum)

```toml
[project]
name = "kali-defense-mcp-server"
version = "1.0.0"
requires-python = ">=3.11"
dependencies = [
    "mcp[cli]>=1.0.0",
    "pydantic>=2.0.0",
    "pydantic-settings>=2.0.0",
    "aiosqlite>=0.19.0",
    "aiofiles>=23.0.0",
]

[project.scripts]
kali-defense-mcp = "src.server:main"
```

---

## IMPLEMENTATION ORDER

Implement modules in this exact sequence. Each module depends on the previous:

```
1. validators/inputs.py         — all Pydantic models
2. executors/command_runner.py  — safe_execute + ALLOWED_COMMANDS
3. state/backups.py             — BackupManager
4. state/changelog.py           — SQLite changelog
5. tools/environment.py         — fingerprint_environment
6. tools/rollback.py            — list_changes, rollback_change
7. server.py                    — FastMCP app skeleton, register tools from step 5+6
8. tools/assessment.py          — run_lynis_audit, get_lynis_score, check_open_ports
9. tools/firewall.py            — all firewall tools
10. tools/ssh.py                — all SSH tools
11. tools/kernel.py             — all kernel tools
12. tools/services.py           — all service tools
13. tools/mac.py                — all MAC tools
14. tools/fim.py                — all AIDE tools
15. tools/malware.py            — all malware tools
16. tools/auth.py               — all auth tools
17. tools/updates.py            — all update tools
18. tools/compliance.py         — OpenSCAP tools
19. tools/orchestrator.py       — full_harden (depends on all above)
20. tests/                      — test suite
```
