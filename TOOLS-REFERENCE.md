# Tools Reference

Complete reference for all 78 tools registered in the kali-defense-mcp-server v0.5.0. The server registers 21 tool modules providing 78 defensive security tools.

> **v0.5.0 Consolidation**: Former fine-grained tools have been merged into action-based tools. Each consolidated tool accepts an `action` parameter to select sub-operations. All prior functionality is preserved.

---

## Legend

| Column | Meaning |
|--------|---------|
| Tool Name | MCP tool name as registered (use this in `tool` calls) |
| Description | What the tool does |
| Actions | Available `action` parameter values |
| dryRun | Y = supports `dry_run` parameter; N = read-only or not applicable |
| Sudo | never / conditional / always |

---

## Firewall (`firewall.ts`) — 5 tools

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `firewall_iptables` | Manage iptables rules and chains | `list`, `add`, `delete`, `set_policy`, `create_chain` | Y | conditional |
| `firewall_ufw` | Manage UFW (Uncomplicated Firewall) | `status`, `add`, `delete` | Y | conditional |
| `firewall_persist` | Manage firewall rule persistence | `save`, `restore`, `enable`, `status` | Y | always |
| `firewall_nftables_list` | List nftables ruleset | — | N | always |
| `firewall_policy_audit` | Audit firewall configuration for security issues | — | N | conditional |

## Hardening (`hardening.ts`) — 8 tools

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `harden_sysctl` | Manage sysctl kernel parameters | `get`, `set`, `audit` | Y | conditional |
| `harden_service` | Manage and audit systemd services | `manage`, `audit` | Y | conditional |
| `harden_permissions` | Manage file permissions | `check`, `fix`, `audit` | Y | conditional |
| `harden_systemd` | Audit or apply systemd service security hardening | `audit`, `apply` | Y | conditional |
| `harden_kernel` | Kernel security hardening | `audit`, `modules`, `coredump` | Y | conditional |
| `harden_bootloader` | Bootloader security | `audit`, `configure` | Y | conditional |
| `harden_misc` | Miscellaneous hardening (cron, umask, banners) | `cron_audit`, `umask_audit`, `umask_set`, `banner_audit`, `banner_set` | Y | conditional |
| `harden_memory` | Memory and exploit mitigations | `audit`, `enforce_aslr`, `report` | Y | conditional |

## IDS (`ids.ts`) — 3 tools

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `ids_aide_manage` | Manage AIDE file integrity database | `init`, `check`, `update`, `compare` | Y | always |
| `ids_rootkit_scan` | Rootkit detection (rkhunter, chkrootkit, or combined) | `rkhunter`, `chkrootkit`, `all` | N | always |
| `ids_file_integrity_check` | Quick SHA-256 file integrity check | — | N | conditional |

## Logging (`logging.ts`) — 4 tools

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `log_auditd` | Auditd management (rules, search, reports, CIS rules) | `rules`, `search`, `report`, `cis_rules` | Y | always |
| `log_journalctl_query` | Query systemd journal for log entries | — | N | conditional |
| `log_fail2ban` | Fail2ban management | `status`, `ban`, `unban`, `reload`, `audit` | Y | conditional |
| `log_system` | System log analysis and log rotation audit | `analyze`, `rotation_audit` | N | conditional |

## Network Defense (`network-defense.ts`) — 3 tools

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `netdef_connections` | List active connections or audit listening ports | `list`, `audit` | N | conditional |
| `netdef_capture` | Network capture (tcpdump, DNS, ARP monitoring) | `custom`, `dns`, `arp` | Y | always |
| `netdef_security_audit` | Network security audit (scan detect, IPv6, self-scan) | `scan_detect`, `ipv6`, `self_scan` | N | conditional |

## Compliance (`compliance.ts`) — 7 tools

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `compliance_lynis_audit` | Run Lynis security audit | — | N | always |
| `compliance_oscap_scan` | Run OpenSCAP compliance scan | — | N | always |
| `compliance_check` | Run compliance checks (CIS or framework) | `cis`, `framework` | N | conditional |
| `compliance_policy_evaluate` | Evaluate a compliance policy set | — | N | never |
| `compliance_report` | Generate comprehensive compliance summary report | — | N | conditional |
| `compliance_cron_restrict` | Restrict cron/at access (CIS 5.1.8/5.1.9) | `create_allow_files`, `status` | Y | always |
| `compliance_tmp_hardening` | Harden /tmp mount options (CIS 1.1.4) | `audit`, `apply` | Y | always |

## Malware (`malware.ts`) — 4 tools

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `malware_clamav` | ClamAV antivirus (scan or update definitions) | `scan`, `update` | Y | conditional |
| `malware_yara_scan` | Scan files with YARA rules | — | N | never |
| `malware_file_scan` | File scanning (suspicious files or web shells) | `suspicious`, `webshell` | N | conditional |
| `malware_quarantine_manage` | Manage quarantined files | `list`, `restore`, `delete`, `info` | Y | never |

## Backup (`backup.ts`) — 1 tool

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `backup` | Backup management (config, state, restore, verify, list) | `config`, `state`, `restore`, `verify`, `list` | Y | conditional |

## Access Control (`access-control.ts`) — 6 tools

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `access_ssh` | SSH server security (audit, harden, cipher audit) | `audit`, `harden`, `cipher_audit` | Y | conditional |
| `access_sudo_audit` | Audit sudoers configuration | — | N | conditional |
| `access_user_audit` | Audit user accounts for security issues | — | N | conditional |
| `access_password_policy` | Audit or set system password policy | `audit`, `set` | Y | conditional |
| `access_pam` | PAM configuration security | `audit`, `configure` | Y | conditional |
| `access_restrict_shell` | Restrict a user's login shell | — | Y | always |

## Encryption (`encryption.ts`) — 4 tools

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `crypto_tls` | TLS/SSL security (remote audit, cert expiry, config audit) | `remote_audit`, `cert_expiry`, `config_audit` | N | conditional |
| `crypto_gpg_keys` | Manage GPG keys | `list`, `generate`, `export`, `import`, `verify` | N | never |
| `crypto_luks_manage` | Manage LUKS encrypted volumes | `status`, `dump`, `open`, `close`, `list` | Y | always |
| `crypto_file_hash` | Calculate cryptographic hashes of files | — | N | never |

## Container Security (`container-security.ts`) — 6 tools

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `container_docker` | Docker security (audit, bench, seccomp, daemon) | `audit`, `bench`, `seccomp`, `daemon` | Y | conditional |
| `container_apparmor` | AppArmor management | `status`, `list`, `enforce`, `complain`, `disable`, `install`, `apply_container` | Y | conditional |
| `container_selinux_manage` | SELinux management | `status`, `getenforce`, `setenforce`, `booleans`, `audit` | Y | always |
| `container_namespace_check` | Check namespace isolation | — | N | conditional |
| `container_image_scan` | Scan container images for vulnerabilities | — | N | never |
| `container_security_config` | Container security configuration (seccomp, rootless) | `seccomp_profile`, `rootless` | Y | conditional |

## Patch Management (`patch-management.ts`) — 5 tools

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `patch_update_audit` | Audit pending security updates | — | N | always |
| `patch_unattended_audit` | Audit unattended-upgrades configuration | — | N | always |
| `patch_integrity_check` | Verify installed package integrity | — | N | always |
| `patch_kernel_audit` | Audit kernel version and update status | — | N | always |
| `patch_vulnerability_intel` | Vulnerability intelligence (CVE lookup, scan, urgency) | `lookup`, `scan`, `urgency` | N | never |

## Secrets (`secrets.ts`) — 4 tools

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `secrets_scan` | Scan filesystem for hardcoded secrets | — | N | never |
| `secrets_env_audit` | Audit environment variable security and .env exposure | — | N | never |
| `secrets_ssh_key_sprawl` | Detect SSH key sprawl | — | N | never |
| `secrets_git_history_scan` | Scan git repository history for leaked secrets | — | N | never |

## Incident Response (`incident-response.ts`) — 1 tool

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `incident_response` | Incident response (volatile data, IOC scan, timeline) | `collect`, `ioc_scan`, `timeline` | Y | conditional |

## Meta (`meta.ts`) — 5 tools

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `defense_check_tools` | Check availability of defensive security tools | — | N | conditional |
| `defense_workflow` | Defense workflows (suggest or run) | `suggest`, `run` | Y | conditional |
| `defense_change_history` | View audit trail of defensive changes | — | N | never |
| `defense_security_posture` | Security posture (score, trend, dashboard) | `score`, `trend`, `dashboard` | N | conditional |
| `defense_scheduled_audit` | Scheduled security audits | `create`, `list`, `remove`, `history` | Y | conditional |

## Sudo Management (`sudo-management.ts`) — 6 tools

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `sudo_elevate` | Elevate privileges by providing sudo password | — | N | never |
| `sudo_elevate_gui` | Secure GUI-based elevation (password never visible to AI) | — | N | never |
| `sudo_status` | Check current sudo session status | — | N | never |
| `sudo_drop` | Drop elevated privileges and zero password buffer | — | N | never |
| `sudo_extend` | Extend sudo session timeout | — | N | never |
| `preflight_batch_check` | Pre-check multiple tools for requirements | — | N | never |

## Supply Chain Security (`supply-chain-security.ts`) — 1 tool

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `supply_chain` | Supply chain security (SBOM, signing, SLSA verification) | `sbom`, `sign`, `verify_slsa` | Y | conditional |

## Drift Detection (`drift-detection.ts`) — 1 tool

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `drift_baseline` | Drift detection (create, compare, list baselines) | `create`, `compare`, `list` | N | never |

## Zero-Trust Network (`zero-trust-network.ts`) — 1 tool

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `zero_trust` | Zero-trust networking (WireGuard, mTLS, microsegmentation) | `wireguard`, `wg_peers`, `mtls`, `microsegment` | Y | conditional |

## eBPF Security (`ebpf-security.ts`) — 2 tools

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `ebpf_list_programs` | List loaded eBPF programs and pinned maps | — | N | always |
| `ebpf_falco` | Falco runtime security | `status`, `deploy_rules`, `events` | Y | conditional |

## Application Hardening (`app-hardening.ts`) — 1 tool

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `app_harden` | Application hardening (audit, recommend, firewall, systemd) | `audit`, `recommend`, `firewall`, `systemd` | Y | conditional |
