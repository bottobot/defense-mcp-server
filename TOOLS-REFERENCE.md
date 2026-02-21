# Tools Reference

Complete alphabetical reference for all tools registered in the kali-defense-mcp-server v2.0.0. The server registers 26 tool modules providing 130+ defensive security tools.

---

## Legend

| Column | Meaning |
|--------|---------|
| Tool Name | MCP tool name as registered (use this in `tool` calls) |
| Description | What the tool does |
| Key Parameters | Most important parameters (not exhaustive) |
| dryRun | Y = supports `dry_run` parameter; N = read-only or not applicable |
| OS | Primary OS compatibility |
| Safety | Read-only (no system changes), Low (minimal/reversible), Medium (modifying), High (destructive/irreversible without backup) |

**OS abbreviations**: L=Linux, D=Debian/Ubuntu, R=RHEL/CentOS/Fedora, K=Kali Linux, A=Arch, W=WSL2 (limited), M=macOS (partial)

---

## A

| Tool Name | Description | Key Parameters | dryRun | OS | Safety |
|-----------|-------------|----------------|--------|----|--------|
| `access_pam_audit` | Audit PAM configuration for security issues | _(none)_ | N | L | Read-only |
| `access_pam_configure` | Configure PAM modules: pam_pwquality for password complexity, pam_faillock for lockout | `module` (pwquality/faillock), `action` (configure/status), `min_length`, `max_retry` | Y | D, R | High |
| `access_password_policy` | Audit or set system password policy in /etc/login.defs and PAM | `action` (audit/set), `min_length`, `max_days`, `min_days` | Y | L | Medium |
| `access_restrict_shell` | Restrict a user's login shell to /usr/sbin/nologin or /bin/false | `username`, `shell`, `dry_run` | Y | L | Medium |
| `access_ssh_audit` | Audit SSH server configuration against hardening best practices | _(none)_ | N | L | Read-only |
| `access_ssh_cipher_audit` | Audit SSH cryptographic algorithms against Mozilla/NIST recommendations | _(none)_ | N | L | Read-only |
| `access_ssh_harden` | Apply SSH hardening settings to sshd_config | `disable_root_login`, `disable_password_auth`, `max_auth_tries`, `dry_run` | Y | L | High |
| `access_sudo_audit` | Audit sudoers configuration for security weaknesses | _(none)_ | N | L | Read-only |
| `access_user_audit` | Audit user accounts for security issues (privileged, inactive, no password, shells) | _(none)_ | N | L | Read-only |
| `apply_apparmor_container` | Generate and optionally load an AppArmor profile for a container | `container_name`, `load` (boolean), `dry_run` | Y | D, K | Medium |
| `audit_env_vars` | Audit current process environment variables for potential secrets | _(none)_ | N | L | Read-only |
| `audit_memory_protections` | Audit memory protections: ASLR, PIE, RELRO, NX, stack canary on specified binaries | `binaries` (list of paths) | N | L | Read-only |

---

## B

| Tool Name | Description | Key Parameters | dryRun | OS | Safety |
|-----------|-------------|----------------|--------|----|--------|
| `backup_config_files` | Backup critical configuration files to the backup directory | `files` (list of paths, optional — defaults to critical system configs) | N | L | Read-only |
| `backup_list` | List all backup files with metadata (path, timestamp, size, ID) | _(none)_ | N | L | Read-only |
| `backup_restore` | Restore a file from backup to its original location using backup ID | `backup_id` (UUID) | N | L | Medium |
| `backup_system_state` | Capture a comprehensive system state snapshot (packages, services, network, firewall, users) | `output_path` (optional) | N | L | Read-only |
| `backup_verify` | Verify backup file integrity using SHA256 checksums | `backup_id` (UUID) | N | L | Read-only |

---

## C

| Tool Name | Description | Key Parameters | dryRun | OS | Safety |
|-----------|-------------|----------------|--------|----|--------|
| `calculate_security_score` | Calculate a weighted security score (0-100) across kernel hardening, firewall, services, users, filesystem, packages, and network domains | _(none)_ | N | L | Read-only |
| `check_falco` | Check Falco runtime security status, version, and configuration | _(none)_ | N | L | Read-only |
| `check_slsa_attestation` | Verify SLSA provenance attestation for a binary or artifact | `artifact` (path or URI), `source_uri` | N | L | Read-only |
| `compare_to_baseline` | Compare current system state against a saved baseline and report drift | `baseline_id` (optional — uses latest if omitted) | N | L | Read-only |
| `compliance_cis_check` | Run CIS benchmark checks for common system hardening requirements | `profile` (server/workstation, optional) | N | L | Read-only |
| `compliance_cron_restrict` | Create and manage /etc/cron.allow and /etc/at.allow to restrict cron/at access (CIS 5.1.8, 5.1.9) | `action` (create/audit), `allowed_users` (list), `dry_run` | Y | L | Medium |
| `compliance_lynis_audit` | Run Lynis security audit for comprehensive system hardening assessment | `profile` (optional), `tests` (optional subset) | N | L | Read-only |
| `compliance_oscap_scan` | Run OpenSCAP compliance scan against XCCDF security profiles | `profile` (XCCDF profile ID), `datastream` (file path) | N | D, R | Read-only |
| `compliance_policy_evaluate` | Evaluate a compliance policy set (built-in or custom) against the current system | `policy` (name or path), `format` (json/text) | N | L | Read-only |
| `compliance_report` | Generate a comprehensive compliance summary report combining multiple check sources | `include_lynis`, `include_cis`, `format` (json/text) | N | L | Read-only |
| `compliance_tmp_hardening` | Audit and apply /tmp mount hardening with nodev,nosuid,noexec options (CIS 1.1.4) | `action` (audit/apply), `dry_run` | Y | L | High |
| `configure_microsegmentation` | Configure iptables/nftables rules for service-level microsegmentation | `services` (list with ports/protocols), `backend` (iptables/nftables), `dry_run` | Y | L | Medium |
| `container_apparmor_install` | Install AppArmor profile packages, list loaded profiles, and check AppArmor status | `action` (install/list/status) | N | D, K | Low |
| `container_apparmor_manage` | Manage AppArmor security profiles: check status, list profiles, set enforcement mode | `action` (status/list/enforce/complain), `profile` (optional) | N | L | Medium |
| `container_daemon_configure` | Audit or apply Docker daemon security settings in /etc/docker/daemon.json | `action` (audit/apply), `userns_remap`, `no_new_privileges`, `icc` (bool), `dry_run` | Y | L | Medium |
| `container_docker_audit` | Audit Docker security configuration: daemon settings, images, running containers, network isolation | _(none)_ | N | L | Read-only |
| `container_docker_bench` | Run Docker Bench for Security to check host and daemon configuration against CIS benchmarks | _(none)_ | N | L | Read-only |
| `container_image_scan` | Scan Docker container images for known vulnerabilities using Trivy or Grype | `image` (image name:tag) | N | L | Read-only |
| `container_namespace_check` | Check Linux namespace isolation for processes and system-wide namespace configuration | `pid` (optional) | N | L | Read-only |
| `container_seccomp_audit` | Audit Docker containers for seccomp profile configuration | `container` (name/ID, optional — all if omitted) | N | L | Read-only |
| `container_selinux_manage` | Manage SELinux settings: check status, get/set enforcement mode, manage booleans, audit denials | `action` (status/enforce/permissive/boolean), `boolean_name`, `value` | N | R | Medium |
| `create_baseline` | Create a system baseline by hashing files in specified directories, capturing sysctl state, and service states | `directories` (list of paths), `label` (optional name) | N | L | Read-only |
| `crypto_cert_expiry` | Check SSL/TLS certificate expiry dates for local files or remote hosts | `host` or `cert_path`, `port` (default 443), `warn_days` (default 30) | N | L | Read-only |
| `crypto_file_hash` | Calculate cryptographic hashes of files for integrity verification | `path`, `algorithm` (sha256/sha512/md5) | N | L | Read-only |
| `crypto_gpg_keys` | Manage GPG keys: list, generate, export, import, or verify signatures | `action` (list/generate/export/import/verify), `key_id` | N | L | Low |
| `crypto_luks_manage` | Manage LUKS encrypted volumes: check status, dump headers, open/close, or list encrypted devices | `action` (status/dump/list), `device` (optional) | N | L | Read-only |
| `crypto_tls_audit` | Audit SSL/TLS configuration of a remote host, checking ciphers, protocols, and certificate details | `host`, `port` (default 443) | N | L | Read-only |
| `crypto_tls_config_audit` | Audit system TLS configuration for web servers and system-wide crypto policies | _(none)_ | N | L | Read-only |

---

## D

| Tool Name | Description | Key Parameters | dryRun | OS | Safety |
|-----------|-------------|----------------|--------|----|--------|
| `defense_change_history` | View the audit trail of all defensive changes made by this server | `limit` (optional, default all) | N | L | Read-only |
| `defense_check_tools` | Check availability and versions of all defensive security tools, optionally install missing ones | `install_missing` (bool, default false) | N | L | Low |
| `defense_run_workflow` | Execute a predefined multi-step defensive workflow | `workflow` (quick_harden/full_audit/incident_prep/backup_all/network_lockdown) | N | L | Medium |
| `defense_security_posture` | Get an overall security posture assessment with a scored breakdown across key security areas | _(none)_ | N | L | Read-only |
| `defense_suggest_workflow` | Suggest a defensive workflow with ordered tool recommendations based on security objective and system type | `objective` (harden/audit/incident/compliance), `system_type` (server/desktop/container) | N | L | Read-only |
| `deploy_falco_rules` | Deploy custom Falco rules to /etc/falco/rules.d/ | `rules_yaml` (YAML string), `rule_name` (filename) | N | L | Medium |

---

## E

| Tool Name | Description | Key Parameters | dryRun | OS | Safety |
|-----------|-------------|----------------|--------|----|--------|
| `enforce_aslr` | Enable full ASLR by setting kernel.randomize_va_space = 2 | `dry_run` | Y | L | Low |

---

## F

| Tool Name | Description | Key Parameters | dryRun | OS | Safety |
|-----------|-------------|----------------|--------|----|--------|
| `firewall_create_chain` | Create a custom iptables chain (iptables -N chain_name) | `chain_name`, `ipv6` (bool), `dry_run` | Y | L | Low |
| `firewall_iptables_add` | Add an iptables rule to a specified chain and table | `chain`, `table`, `protocol`, `source`, `destination`, `port`, `action`, `position`, `match_module`, `match_options`, `tcp_flags`, `custom_chain`, `dry_run` | Y | L | Medium |
| `firewall_iptables_delete` | Delete an iptables rule by rule number from a specified chain | `chain`, `table`, `rule_number`, `dry_run` | Y | L | High |
| `firewall_iptables_list` | List iptables rules for a given table and optional chain | `table`, `chain`, `verbose` | N | L | Read-only |
| `firewall_nftables_list` | List nftables ruleset (modern replacement for iptables) | `table`, `family` (ip/ip6/inet/arp/bridge/netdev) | N | L | Read-only |
| `firewall_persistence` | Manage iptables-persistent for firewall rule persistence across reboots | `action` (enable/save/status), `dry_run` | Y | D, K | Medium |
| `firewall_policy_audit` | Audit firewall configuration for security issues: default policies, missing rules, misconfigurations | _(none)_ | N | L | Read-only |
| `firewall_restore` | Restore iptables/ip6tables rules from a saved file | `input_path`, `ipv6`, `test_only` (default true), `dry_run` | Y | L | High |
| `firewall_save` | Save current iptables/ip6tables rules to a file for persistence | `output_path` (default /etc/iptables/rules.v4), `ipv6`, `dry_run` | Y | L | Low |
| `firewall_set_policy` | Set the default policy for an iptables chain (INPUT/FORWARD/OUTPUT) | `chain`, `policy` (ACCEPT/DROP), `ipv6`, `dry_run` | Y | L | High |
| `firewall_ufw_rule` | Add or delete a UFW firewall rule | `action`, `direction`, `port`, `protocol`, `from_addr`, `to_addr`, `delete`, `dry_run` | Y | D, K | Medium |
| `firewall_ufw_status` | Show current UFW status and rules | `verbose` | N | D, K | Read-only |

---

## G

| Tool Name | Description | Key Parameters | dryRun | OS | Safety |
|-----------|-------------|----------------|--------|----|--------|
| `generate_posture_dashboard` | Generate a structured security posture dashboard with scores, top findings, and recommendations | `format` (json/text) | N | L | Read-only |
| `generate_sbom` | Generate a Software Bill of Materials for the system or a directory | `target` (directory/system), `format` (spdx/cyclonedx), `output_path` | N | L | Read-only |
| `generate_seccomp_profile` | Generate a custom seccomp profile JSON from a list of allowed syscalls | `allowed_syscalls` (list), `output_path` | N | L | Read-only |
| `get_audit_history` | Read historical output from scheduled audit jobs | `job_name`, `limit` (optional) | N | L | Read-only |
| `get_ebpf_events` | Read recent Falco events from the JSON log | `limit` (default 50), `severity` (filter) | N | L | Read-only |
| `get_patch_urgency` | Get patch urgency for a specific package — checks for available updates and security advisories | `package_name` | N | D, R | Read-only |
| `get_posture_trend` | Compare current security score against historical scores | `days` (lookback window, default 30) | N | L | Read-only |

---

## H

| Tool Name | Description | Key Parameters | dryRun | OS | Safety |
|-----------|-------------|----------------|--------|----|--------|
| `harden_banner_audit` | Audit login warning banners (/etc/issue, /etc/issue.net, /etc/motd) per CIS benchmark | _(none)_ | N | L | Read-only |
| `harden_banner_set` | Set login warning banner content in /etc/issue, /etc/issue.net, and /etc/motd | `banner_text`, `targets` (issue/issue.net/motd list), `dry_run` | Y | L | Low |
| `harden_bootloader_audit` | Audit GRUB security configuration including password protection, Secure Boot, and kernel params | _(none)_ | N | L | Read-only |
| `harden_bootloader_configure` | Configure GRUB bootloader kernel parameters for security hardening | `action` (add_kernel_params/status), `kernel_params`, `dry_run` | Y | D, K | High |
| `harden_coredump_disable` | Disable core dumps via limits.conf, systemd coredump.conf, and sysctl fs.suid_dumpable | `dry_run` | Y | L | Low |
| `harden_cron_audit` | Audit cron and at access control configuration per CIS benchmarks | _(none)_ | N | L | Read-only |
| `harden_file_permissions` | Audit or fix file permissions, ownership, and group for a given path | `path`, `mode`, `owner`, `group`, `fix`, `dry_run` | Y | L | Medium |
| `harden_kernel_security_audit` | Audit Linux kernel security features: CPU mitigations, Landlock, lockdown mode, ASLR, kernel self-protection | _(none)_ | N | L | Read-only |
| `harden_module_audit` | Audit kernel module blacklisting per CIS benchmark | _(none)_ | N | L | Read-only |
| `harden_permissions_audit` | Audit critical system file permissions against security best practices (CIS benchmarks) | _(none)_ | N | L | Read-only |
| `harden_service_audit` | Audit running services for unnecessary or potentially dangerous ones | _(none)_ | N | L | Read-only |
| `harden_service_manage` | Manage systemd services: enable, disable, start, stop, restart, mask, unmask, or check status | `service`, `action`, `dry_run` | Y | L | Medium |
| `harden_sysctl_audit` | Audit sysctl settings against security hardening recommendations (CIS/STIG) | _(none)_ | N | L | Read-only |
| `harden_sysctl_get` | Get sysctl kernel parameter value(s) | `key`, `all`, `pattern` | N | L | Read-only |
| `harden_sysctl_set` | Set a sysctl kernel parameter, optionally making it persistent | `key`, `value`, `persistent`, `dry_run` | Y | L | Medium |
| `harden_systemd_apply` | Apply systemd security hardening overrides to a service unit | `service`, `hardening_level` (basic/strict), `dry_run` | Y | L | Medium |
| `harden_systemd_audit` | Audit systemd service units for security hardening using systemd-analyze security | `service` (optional — all if omitted) | N | L | Read-only |
| `harden_umask_audit` | Audit default umask configuration in login.defs, profile, and bashrc | _(none)_ | N | L | Read-only |
| `harden_umask_set` | Set default umask value in login.defs, /etc/profile, and /etc/bash.bashrc | `umask_value` (027/077), `targets` (list), `dry_run` | Y | L | Low |

---

## I

| Tool Name | Description | Key Parameters | dryRun | OS | Safety |
|-----------|-------------|----------------|--------|----|--------|
| `ids_aide_manage` | Manage AIDE file integrity database: initialize, update, or check | `action` (init/update/check), `config` (optional path) | N | L | Low |
| `ids_chkrootkit_scan` | Run chkrootkit rootkit detection scan | _(none)_ | N | L | Read-only |
| `ids_file_integrity_check` | Quick file integrity check using SHA-256 hashes: create, verify, or display baselines | `action` (create/verify/show), `path`, `baseline_file` | N | L | Read-only |
| `ids_rkhunter_scan` | Run rkhunter rootkit detection scan | `update_db` (bool, default false) | N | L | Read-only |
| `ids_rootkit_summary` | Combined rootkit detection summary using rkhunter and/or chkrootkit | _(none)_ | N | L | Read-only |
| `ir_ioc_scan` | Scan system for Indicators of Compromise: suspicious processes, connections, persistence mechanisms | _(none)_ | N | L | Read-only |
| `ir_timeline_generate` | Generate a filesystem timeline showing recently modified files for forensic analysis | `directory` (default /), `hours` (lookback), `output_path` | N | L | Read-only |
| `ir_volatile_collect` | Collect volatile system data following RFC 3227 order of volatility | `output_path` (optional) | N | L | Read-only |

---

## L

| Tool Name | Description | Key Parameters | dryRun | OS | Safety |
|-----------|-------------|----------------|--------|----|--------|
| `list_drift_alerts` | List available baselines and show summary of changes since last baseline | _(none)_ | N | L | Read-only |
| `list_ebpf_programs` | List loaded eBPF programs and pinned maps | _(none)_ | N | L | Read-only |
| `list_scheduled_audits` | List all scheduled security audits (systemd timers and cron jobs) | _(none)_ | N | L | Read-only |
| `log_auditd_cis_rules` | Check or deploy CIS Benchmark-required auditd rules covering time changes, identity, network, MAC policy, login/session, file access, privileged commands | `action` (check/deploy), `dry_run` | Y | L | Medium |
| `log_auditd_report` | Generate audit summary report using aureport | `report_type` (auth/exec/login/network/all), `start`, `end` | N | L | Read-only |
| `log_auditd_rules` | List, add, or delete auditd rules via auditctl | `action` (list/add/delete), `rule` (for add/delete), `dry_run` | Y | L | Medium |
| `log_auditd_search` | Search audit logs using ausearch with various filters | `key`, `user`, `pid`, `start`, `end`, `type` | N | L | Read-only |
| `log_fail2ban_audit` | Audit fail2ban jail configurations for weak settings | _(none)_ | N | L | Read-only |
| `log_fail2ban_manage` | Manage fail2ban bans: ban/unban IP addresses or reload configuration | `action` (ban/unban/reload), `jail`, `ip` | N | L | Low |
| `log_fail2ban_status` | Check fail2ban status for all jails or a specific jail | `jail` (optional) | N | L | Read-only |
| `log_journalctl_query` | Query systemd journal for log entries with flexible filtering | `unit`, `since`, `until`, `grep`, `priority`, `lines` | N | L | Read-only |
| `log_rotation_audit` | Audit log rotation configuration (logrotate) and journald persistence settings | _(none)_ | N | L | Read-only |
| `log_syslog_analyze` | Analyze syslog for security-related events using pattern matching | `patterns`, `log_file`, `hours` | N | L | Read-only |
| `lookup_cve` | Look up a CVE by ID from the NVD API and return its details | `cve_id` (e.g., CVE-2024-1234) | N | L, W, M | Read-only |

---

## M

| Tool Name | Description | Key Parameters | dryRun | OS | Safety |
|-----------|-------------|----------------|--------|----|--------|
| `malware_clamav_scan` | Scan files or directories with ClamAV antivirus engine | `path`, `recursive` (bool), `remove` (bool, default false) | N | L | Low |
| `malware_clamav_update` | Update ClamAV virus definitions using freshclam | _(none)_ | N | L | Low |
| `malware_quarantine_manage` | Manage quarantined files: list, restore, delete, or get info | `action` (list/restore/delete/info), `file_id` | N | L | Medium |
| `malware_suspicious_files` | Find suspicious files: SUID/SGID, world-writable, hidden executables, recently modified | `directory` (default /), `days` (recently modified threshold) | N | L | Read-only |
| `malware_webshell_detect` | Scan web server directories for potential web shells using pattern matching | `web_root` (default /var/www) | N | L | Read-only |
| `malware_yara_scan` | Scan files with YARA rules for pattern-based malware detection | `path`, `rules_path`, `recursive` (bool) | N | L | Read-only |
| `manage_wg_peers` | Add, remove, or list WireGuard peers | `action` (add/remove/list), `interface`, `public_key`, `allowed_ips`, `endpoint` | N | L | Medium |

---

## N

| Tool Name | Description | Key Parameters | dryRun | OS | Safety |
|-----------|-------------|----------------|--------|----|--------|
| `netdef_arp_monitor` | Monitor ARP traffic to detect potential ARP poisoning attacks | `interface`, `duration` (seconds) | N | L | Read-only |
| `netdef_connections` | List active network connections with optional protocol and state filtering | `protocol` (tcp/udp/all), `state`, `process` (bool) | N | L | Read-only |
| `netdef_dns_monitor` | Monitor DNS queries on the network using tcpdump | `interface`, `duration` (seconds) | N | L | Read-only |
| `netdef_ipv6_audit` | Audit IPv6 configuration and security — check if IPv6 is needed, firewalled, or should be disabled | _(none)_ | N | L | Read-only |
| `netdef_open_ports_audit` | Audit listening ports and their processes, flagging potentially suspicious services | _(none)_ | N | L | Read-only |
| `netdef_port_scan_detect` | Check system logs for signs of port scanning activity | `hours` (lookback, default 24) | N | L | Read-only |
| `netdef_self_scan` | Run an nmap self-scan against localhost to discover exposed services from a network perspective | `target` (default localhost), `scan_type` | N | L | Read-only |
| `netdef_tcpdump_capture` | Capture network traffic using tcpdump with BPF filter support | `interface`, `filter` (BPF), `duration`, `count`, `output_file` | N | L | Read-only |

---

## P

| Tool Name | Description | Key Parameters | dryRun | OS | Safety |
|-----------|-------------|----------------|--------|----|--------|
| `patch_integrity_check` | Verify integrity of installed packages using debsums (Debian) or rpm -V (RHEL) | `package` (optional — all if omitted) | N | D, R | Read-only |
| `patch_kernel_audit` | Audit kernel version, check for available kernel updates, livepatch status, and support timeline | _(none)_ | N | D, R | Read-only |
| `patch_unattended_audit` | Audit unattended-upgrades configuration for automatic security patching | _(none)_ | N | D | Read-only |
| `patch_update_audit` | Audit system for pending security updates, held-back packages, and overall patch status | _(none)_ | N | D, R | Read-only |

---

## R

| Tool Name | Description | Key Parameters | dryRun | OS | Safety |
|-----------|-------------|----------------|--------|----|--------|
| `remove_scheduled_audit` | Remove a scheduled security audit by name | `name`, `type` (systemd/cron), `dry_run` | Y | L | Medium |
| `report_exploit_mitigations` | Report system-wide exploit mitigation status (ASLR, SMEP, SMAP, PTI, KASLR, etc.) | _(none)_ | N | L | Read-only |
| `run_compliance_check` | Run compliance checks against a specified framework (PCI-DSS v4, HIPAA, SOC2, ISO 27001, GDPR) | `framework`, `dryRun` | Y | L | Read-only |

---

## S

| Tool Name | Description | Key Parameters | dryRun | OS | Safety |
|-----------|-------------|----------------|--------|----|--------|
| `scan_for_secrets` | Scan a directory for hardcoded secrets using truffleHog, gitleaks, or built-in grep patterns | `directory`, `tool` (trufflehog/gitleaks/grep, auto-detected) | N | L | Read-only |
| `scan_git_history` | Scan git repository history for leaked secrets using truffleHog or gitleaks | `repo_path`, `tool` (auto-detected) | N | L | Read-only |
| `scan_image_trivy` | Scan a container image for vulnerabilities using Trivy | `image` (image name:tag), `severity` (CRITICAL/HIGH/...) | N | L | Read-only |
| `scan_packages_cves` | Scan installed packages for known CVEs using local vulnerability databases or package manager audit | _(none)_ | N | D, R | Read-only |
| `secrets_env_audit` | Audit environment variable security and .env file exposure | _(none)_ | N | L | Read-only |
| `secrets_scan` | Scan filesystem for hardcoded secrets: API keys, passwords, private keys, tokens | `path`, `patterns` (optional custom patterns) | N | L | Read-only |
| `secrets_ssh_key_sprawl` | Detect SSH key sprawl: find all SSH keys, check age, permissions, and authorized_keys files | `scan_home` (bool, default true) | N | L | Read-only |
| `setup_cosign_signing` | Sign a container image or artifact using cosign (keyless or with a key) | `image`, `key_path` (optional for keyless), `dry_run` | Y | L | Low |
| `setup_mtls` | Generate CA, server, and client certificates for mutual TLS authentication | `cn`, `output_dir`, `days` (validity), `dry_run` | Y | L | Low |
| `setup_rootless_containers` | Configure rootless container support (newuidmap/newgidmap, user namespaces) | `user`, `dry_run` | Y | L | Low |
| `setup_scheduled_audit` | Create a scheduled security audit using systemd timer or cron | `name`, `schedule` (cron expression), `tools` (list), `type` (systemd/cron), `dry_run` | Y | L | Low |
| `setup_wireguard` | Set up a WireGuard VPN interface with key generation and configuration | `interface` (default wg0), `address` (CIDR), `port`, `dry_run` | Y | L | Medium |

---

## V

| Tool Name | Description | Key Parameters | dryRun | OS | Safety |
|-----------|-------------|----------------|--------|----|--------|
| `verify_package_integrity` | Verify checksums of installed packages using debsums (Debian) or rpm -V (RHEL) | `package` (optional — all if omitted) | N | D, R | Read-only |

---

## Summary by Category

| Category | Module File | Tool Count |
|----------|-------------|-----------|
| Firewall Management | `firewall.ts` | 12 |
| System Hardening | `hardening.ts` | 19 |
| Intrusion Detection | `ids.ts` | 5 |
| Log Analysis & Monitoring | `logging.ts` | 10 |
| Network Defense | `network-defense.ts` | 8 |
| Compliance & Benchmarking | `compliance.ts` | 7 |
| Malware Analysis | `malware.ts` | 6 |
| Backup & Recovery | `backup.ts` | 5 |
| Access Control | `access-control.ts` | 9 |
| Encryption & PKI | `encryption.ts` | 6 |
| Container Security | `container-security.ts` | 9 |
| Meta & Orchestration | `meta.ts` | 5 |
| Patch Management | `patch-management.ts` | 4 |
| Secrets Management | `secrets-management.ts` | 3 |
| Incident Response | `incident-response.ts` | 3 |
| Supply Chain Security | `supply-chain-security.ts` | 4 |
| Memory Protection | `memory-protection.ts` | 3 |
| Drift Detection | `drift-detection.ts` | 3 |
| Vulnerability Intelligence | `vulnerability-intel.ts` | 3 |
| Security Posture | `security-posture.ts` | 3 |
| Secrets Scanner | `secrets-scanner.ts` | 3 |
| Zero-Trust Network | `zero-trust-network.ts` | 4 |
| Container Advanced | `container-advanced.ts` | 4 |
| Compliance Extended | `compliance-extended.ts` | 1 |
| eBPF Security | `ebpf-security.ts` | 4 |
| Automation Workflows | `automation-workflows.ts` | 4 |
| **Total** | **26 modules** | **130+** |
