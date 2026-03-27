# Tools Reference

> **v0.7.0 — Consolidated from 94 tools (v0.6.x) to 31 tools (v0.7.0)**

Complete reference for all 31 tools registered in the defense-mcp-server v0.7.0. The server registers 29 tool source files providing 31 defensive security tools.

> **Action-based tools**: Each tool accepts an `action` parameter to select sub-operations, keeping MCP tool registration overhead low while preserving all functionality.

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

## Consolidated Tools (18)

### Firewall (`firewall.ts`)

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `firewall` | All firewall management (iptables, UFW, nftables, policy audit, persistence) | `iptables_list`, `iptables_add`, `iptables_delete`, `iptables_set_policy`, `iptables_create_chain`, `ufw_status`, `ufw_add`, `ufw_delete`, `persist_save`, `persist_restore`, `persist_enable`, `persist_status`, `nftables_list`, `policy_audit` | Y | conditional |

**Actions:**
- `iptables_list` — List current iptables rules and chains
- `iptables_add` — Add an iptables rule
- `iptables_delete` — Delete an iptables rule
- `iptables_set_policy` — Set default policy for a chain (ACCEPT/DROP)
- `iptables_create_chain` — Create a new iptables chain
- `ufw_status` — Show UFW status and current rules
- `ufw_add` — Add a UFW allow/deny rule
- `ufw_delete` — Delete a UFW rule
- `persist_save` — Save current firewall rules to disk
- `persist_restore` — Restore firewall rules from disk
- `persist_enable` — Enable firewall rule persistence across reboots
- `persist_status` — Check firewall persistence status
- `nftables_list` — List current nftables ruleset
- `policy_audit` — Audit firewall configuration for security issues

---

### Kernel Hardening (`hardening.ts`) — `harden_kernel`

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `harden_kernel` | Kernel-layer hardening (sysctl, kernel modules, bootloader, memory) | `sysctl_get`, `sysctl_set`, `sysctl_audit`, `kernel_audit`, `kernel_modules`, `kernel_coredump`, `bootloader_audit`, `bootloader_configure`, `memory_audit`, `memory_enforce_aslr`, `memory_report` | Y | conditional |

**Actions:**
- `sysctl_get` — Read a sysctl kernel parameter value
- `sysctl_set` — Set a sysctl kernel parameter
- `sysctl_audit` — Audit sysctl parameters against security baseline
- `kernel_audit` — Audit kernel version, patches, and security configuration
- `kernel_modules` — List and audit loaded kernel modules
- `kernel_coredump` — Audit or restrict core dump settings
- `bootloader_audit` — Audit bootloader (GRUB) security configuration
- `bootloader_configure` — Apply bootloader security hardening (`add_kernel_params`, `status`, `set_password`). The `set_password` sub-action sets a GRUB bootloader password with PBKDF2 hashing.
- `memory_audit` — Audit memory and exploit mitigation settings
- `memory_enforce_aslr` — Enforce Address Space Layout Randomization
- `memory_report` — Generate memory hardening status report

---

### Host Hardening (`hardening.ts`) — `harden_host`

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `harden_host` | Host-layer hardening (services, permissions, systemd, misc, USB) | `service_manage`, `service_audit`, `permissions_check`, `permissions_fix`, `permissions_audit`, `systemd_audit`, `systemd_apply`, `cron_audit`, `umask_audit`, `umask_set`, `banner_audit`, `banner_set`, `usb_audit_devices`, `usb_block_storage`, `usb_whitelist`, `usb_monitor` | Y | conditional |

**Actions:**
- `service_manage` — Start, stop, enable, or disable a systemd service
- `service_audit` — Audit running services for unnecessary or risky services
- `permissions_check` — Check file/directory permissions against security baseline
- `permissions_fix` — Fix insecure file/directory permissions
- `permissions_audit` — Comprehensive filesystem permissions audit
- `systemd_audit` — Audit systemd service unit security settings
- `systemd_apply` — Apply systemd service hardening (sandboxing, capabilities). Supports `basic`, `strict`, and `custom` levels. Custom level accepts `custom_directives` array with allowlist validation.
- `cron_audit` — Audit cron jobs for suspicious or risky entries
- `umask_audit` — Audit system umask settings
- `umask_set` — Set system umask value
- `banner_audit` — Audit login banners (MOTD, /etc/issue)
- `banner_set` — Set login banner content
- `usb_audit_devices` — Audit connected USB devices via lsusb and lsblk
- `usb_block_storage` — Block USB mass storage via kernel module blacklisting
- `usb_whitelist` — Manage USB device whitelist via udev rules
- `usb_monitor` — Monitor USB device events via udevadm

---

### Access Control (`access-control.ts`)

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `access_control` | Authentication and authorization (SSH, PAM, sudo, users, passwords, shell) | `ssh_audit`, `ssh_harden`, `ssh_cipher_audit`, `pam_audit`, `pam_configure`, `sudo_audit`, `sudoers_manage`, `user_audit`, `password_policy_audit`, `password_policy_set`, `restrict_shell` | Y | conditional |

**Actions:**
- `ssh_audit` — Audit SSH server configuration for security issues
- `ssh_harden` — Apply SSH server hardening recommendations
- `ssh_cipher_audit` — Audit enabled SSH ciphers, MACs, and key exchange algorithms
- `pam_audit` — Audit PAM (Pluggable Authentication Modules) configuration
- `pam_configure` — Apply PAM security configuration (password quality, lockout)
- `sudo_audit` — Audit sudoers configuration for overly permissive rules
- `sudoers_manage` — Manage sudoers drop-in files under `/etc/sudoers.d/` (write, remove, validate). Validates with `visudo -cf`, atomic write, backup, and rollback.
- `user_audit` — Audit user accounts (empty passwords, UID 0, inactive users)
- `password_policy_audit` — Audit system password policy settings
- `password_policy_set` — Set system password policy parameters. Supports `target_user` for per-user policy via `chage` (min_days, max_days, warn_days, inactive_days).
- `restrict_shell` — Restrict a user's login shell

---

### Compliance (`compliance.ts`)

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `compliance` | Compliance auditing and hardening (Lynis, OpenSCAP, CIS, policies, reports) | `lynis_audit`, `oscap_scan`, `cis_check`, `framework_check`, `policy_evaluate`, `report`, `cron_restrict`, `cron_restrict_status`, `tmp_audit`, `tmp_harden` | Y | always |

**Actions:**
- `lynis_audit` — Run Lynis security audit and return scored findings
- `oscap_scan` — Run OpenSCAP compliance scan against a profile
- `cis_check` — Run CIS Benchmark compliance checks
- `framework_check` — Run compliance checks against a named framework
- `policy_evaluate` — Evaluate a compliance policy set against current configuration
- `report` — Generate comprehensive compliance summary report
- `cron_restrict` — Restrict cron/at access (CIS 5.1.8/5.1.9) by creating allow files
- `cron_restrict_status` — Check current cron/at restriction status
- `tmp_audit` — Audit /tmp mount options and security settings
- `tmp_harden` — Apply /tmp hardening (noexec, nosuid, nodev mount options)

---

### File Integrity (`integrity.ts`)

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `integrity` | File integrity and drift detection (AIDE, rootkit scanning, file hashing, baselines) | `aide_init`, `aide_check`, `aide_update`, `aide_compare`, `rootkit_rkhunter`, `rootkit_chkrootkit`, `rootkit_all`, `file_integrity`, `baseline_create`, `baseline_compare`, `baseline_list` | Y | conditional |

**Actions:**
- `aide_init` — Initialize AIDE file integrity database
- `aide_check` — Run AIDE check against existing database
- `aide_update` — Update AIDE database to reflect current state
- `aide_compare` — Compare two AIDE database snapshots
- `rootkit_rkhunter` — Scan for rootkits using rkhunter
- `rootkit_chkrootkit` — Scan for rootkits using chkrootkit
- `rootkit_all` — Run both rkhunter and chkrootkit and combine results
- `file_integrity` — Quick SHA-256 file integrity check for a path
- `baseline_create` — Create a filesystem baseline snapshot
- `baseline_compare` — Compare current state against a saved baseline (drift detection)
- `baseline_list` — List all saved baselines

---

### Log Management (`logging.ts`)

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `log_management` | Logging, monitoring, and SIEM integration (auditd, journalctl, fail2ban, syslog, SIEM) | `auditd_rules`, `auditd_search`, `auditd_report`, `auditd_cis_rules`, `journalctl_query`, `fail2ban_status`, `fail2ban_ban`, `fail2ban_unban`, `fail2ban_reload`, `fail2ban_audit`, `syslog_analyze`, `rotation_audit`, `rotation_configure`, `siem_syslog_forward`, `siem_filebeat`, `siem_audit_forwarding`, `siem_test_connectivity` | Y | conditional |

**Actions:**
- `auditd_rules` — Manage auditd rules (list, add, delete)
- `auditd_search` — Search auditd logs for events
- `auditd_report` — Generate auditd summary report
- `auditd_cis_rules` — Apply CIS-recommended auditd rules
- `journalctl_query` — Query systemd journal for log entries
- `fail2ban_status` — Check fail2ban status and active jails
- `fail2ban_ban` — Manually ban an IP in a fail2ban jail
- `fail2ban_unban` — Unban an IP from a fail2ban jail
- `fail2ban_reload` — Reload fail2ban configuration
- `fail2ban_audit` — Audit fail2ban configuration for best practices
- `syslog_analyze` — Analyze syslog for security events and anomalies
- `rotation_audit` — Audit log rotation configuration (logrotate)
- `rotation_configure` — Create/update logrotate configs under `/etc/logrotate.d/` with frequency, retention, compression, and safe directive validation
- `siem_syslog_forward` — Audit/configure rsyslog remote forwarding (TCP/UDP/TLS)
- `siem_filebeat` — Audit Filebeat installation, modules, and output configuration
- `siem_audit_forwarding` — Comprehensive log forwarding audit with CIS compliance check
- `siem_test_connectivity` — Test SIEM endpoint connectivity and send test syslog message

---

### Malware Detection (`malware.ts`)

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `malware` | Malware detection and quarantine (ClamAV, YARA, file scanning, quarantine) | `clamav_scan`, `clamav_update`, `yara_scan`, `file_scan_suspicious`, `file_scan_webshell`, `quarantine_list`, `quarantine_restore`, `quarantine_delete`, `quarantine_info` | Y | conditional |

**Actions:**
- `clamav_scan` — Scan a path with ClamAV antivirus
- `clamav_update` — Update ClamAV virus definitions
- `yara_scan` — Scan files using YARA rules
- `file_scan_suspicious` — Scan for suspicious files (SUID, world-writable, hidden executables)
- `file_scan_webshell` — Scan web directories for web shell indicators
- `quarantine_list` — List quarantined files
- `quarantine_restore` — Restore a quarantined file to original location
- `quarantine_delete` — Permanently delete a quarantined file
- `quarantine_info` — Show metadata and hash for a quarantined file

---

### Docker Security (`container-security.ts`) — `container_docker`

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `container_docker` | Docker security (audit, CIS benchmark, seccomp, daemon, image scanning) | `audit`, `bench`, `seccomp`, `daemon`, `image_scan` | Y | conditional |

**Actions:**
- `audit` — Audit Docker configuration and running containers for security issues
- `bench` — Run Docker Bench for Security (CIS Docker Benchmark)
- `seccomp` — Audit or generate seccomp profiles for containers
- `daemon` — Audit Docker daemon configuration (`/etc/docker/daemon.json`)
- `image_scan` — Scan a container image for known vulnerabilities

---

### Container Isolation (`container-security.ts`) — `container_isolation`

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `container_isolation` | Container isolation mechanisms (AppArmor, SELinux, namespaces, seccomp profiles) | `apparmor_status`, `apparmor_list`, `apparmor_enforce`, `apparmor_complain`, `apparmor_disable`, `apparmor_install`, `apparmor_apply_container`, `selinux_status`, `selinux_getenforce`, `selinux_setenforce`, `selinux_booleans`, `selinux_audit`, `namespace_check`, `seccomp_profile`, `rootless_setup` | Y | conditional |

**Actions:**
- `apparmor_status` — Show AppArmor status and loaded profiles
- `apparmor_list` — List AppArmor profiles with enforcement mode
- `apparmor_enforce` — Set an AppArmor profile to enforce mode
- `apparmor_complain` — Set an AppArmor profile to complain mode
- `apparmor_disable` — Disable an AppArmor profile
- `apparmor_install` — Install AppArmor utilities and profiles
- `apparmor_apply_container` — Apply an AppArmor profile to a container
- `selinux_status` — Show SELinux status and current mode
- `selinux_getenforce` — Get current SELinux enforcement mode
- `selinux_setenforce` — Set SELinux enforcement mode (enforcing/permissive)
- `selinux_booleans` — List or set SELinux booleans
- `selinux_audit` — Audit SELinux denials and AVCs
- `namespace_check` — Check namespace isolation for a PID or list all namespaces
- `seccomp_profile` — Generate or audit a seccomp profile for containers
- `rootless_setup` — Configure rootless container runtime

---

### eBPF & Runtime Security (`ebpf-security.ts`) — `ebpf`

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `ebpf` | eBPF and runtime security (program listing, Falco) | `list_programs`, `falco_status`, `falco_deploy_rules`, `falco_events` | Y | conditional |

**Actions:**
- `list_programs` — List loaded eBPF programs and pinned maps
- `falco_status` — Check Falco runtime security status
- `falco_deploy_rules` — Deploy or update Falco detection rules
- `falco_events` — Query recent Falco security events

---

### Cryptography (`encryption.ts`) — `crypto`

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `crypto` | Cryptography and certificate management (TLS, GPG, LUKS, file hashing, cert lifecycle) | `tls_remote_audit`, `tls_cert_expiry`, `tls_config_audit`, `gpg_list`, `gpg_generate`, `gpg_export`, `gpg_import`, `gpg_verify`, `luks_status`, `luks_dump`, `luks_open`, `luks_close`, `luks_list`, `file_hash`, `cert_inventory`, `cert_auto_renew_check`, `cert_ca_audit`, `cert_ocsp_check`, `cert_ct_log_monitor` | Y | conditional |

**Actions:**
- `tls_remote_audit` — Audit TLS/SSL configuration of a remote host
- `tls_cert_expiry` — Check TLS certificate expiry for a host
- `tls_config_audit` — Audit local TLS configuration files (nginx, Apache)
- `gpg_list` — List GPG keys in the keyring
- `gpg_generate` — Generate a new GPG key pair
- `gpg_export` — Export a GPG public key
- `gpg_import` — Import a GPG public key
- `gpg_verify` — Verify a GPG-signed file or message
- `luks_status` — Show LUKS encryption status for block devices
- `luks_dump` — Dump LUKS header information for a device
- `luks_open` — Open (decrypt) a LUKS-encrypted volume
- `luks_close` — Close an open LUKS-encrypted volume
- `luks_list` — List all LUKS-encrypted volumes
- `file_hash` — Calculate cryptographic hashes (MD5/SHA-1/SHA-256/SHA-512) of files
- `cert_inventory` — Scan filesystem for certificates and report expiry status
- `cert_auto_renew_check` — Check certbot auto-renewal configuration and certificate expiry
- `cert_ca_audit` — Audit trusted CA certificates in the system trust store
- `cert_ocsp_check` — Check OCSP responder status for a certificate
- `cert_ct_log_monitor` — Monitor Certificate Transparency logs for a domain

---

### Network Defense (`network-defense.ts`) — `network_defense`

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `network_defense` | Network security monitoring (connections, capture, security audit, segmentation) | `connections_list`, `connections_audit`, `capture_custom`, `capture_dns`, `capture_arp`, `security_scan_detect`, `security_ipv6`, `security_self_scan`, `segmentation_map_zones`, `segmentation_verify_isolation`, `segmentation_test_paths`, `segmentation_audit_vlans` | Y | conditional |

**Actions:**
- `connections_list` — List active network connections
- `connections_audit` — Audit listening ports and unexpected connections
- `capture_custom` — Custom tcpdump network capture
- `capture_dns` — Capture and analyze DNS traffic
- `capture_arp` — Monitor ARP traffic for poisoning indicators
- `security_scan_detect` — Detect active port scans against this host
- `security_ipv6` — Audit IPv6 configuration and exposure
- `security_self_scan` — Run a self nmap scan to view exposed attack surface
- `segmentation_map_zones` — Map network zones from interface and routing table analysis
- `segmentation_verify_isolation` — Verify network isolation between zones using iptables rules
- `segmentation_test_paths` — Test network paths between endpoints using traceroute/nmap
- `segmentation_audit_vlans` — Audit VLAN configuration and bridge interfaces

---

### Patch Management (`patch-management.ts`) — `patch`

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `patch` | Patch and update management (update audit, unattended, integrity, kernel, vuln intel) | `update_audit`, `unattended_audit`, `integrity_check`, `kernel_audit`, `vuln_lookup`, `vuln_scan`, `vuln_urgency` | Y | conditional |

**Actions:**
- `update_audit` — Audit pending security updates and missing patches
- `unattended_audit` — Audit unattended-upgrades configuration
- `integrity_check` — Verify installed package integrity via package manager checksums
- `kernel_audit` — Audit running kernel version and available kernel updates
- `vuln_lookup` — Look up a CVE identifier for details and severity
- `vuln_scan` — Scan installed packages for known vulnerabilities
- `vuln_urgency` — Assess urgency of a vulnerability based on system exposure

---

### Secrets Detection (`secrets.ts`) — `secrets`

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `secrets` | Secrets detection (filesystem scan, env audit, SSH key sprawl, git history) | `scan`, `env_audit`, `ssh_key_sprawl`, `git_history_scan` | N | never |

**Actions:**
- `scan` — Scan filesystem paths for hardcoded secrets (tokens, passwords, API keys)
- `env_audit` — Audit environment variables and .env file exposure
- `ssh_key_sprawl` — Detect SSH key sprawl across user home directories
- `git_history_scan` — Scan git repository history for leaked secrets

---

### Incident Response (`incident-response.ts`) — `incident_response`

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `incident_response` | Incident response and forensics (collection, IOC scan, timeline, forensic acquisition) | `collect`, `ioc_scan`, `timeline`, `forensics_memory_dump`, `forensics_disk_image`, `forensics_network_capture`, `forensics_evidence_bag`, `forensics_chain_of_custody` | Y | conditional |

**Actions:**
- `collect` — Collect volatile system data (processes, connections, users, memory)
- `ioc_scan` — Scan for Indicators of Compromise against known IOC lists
- `timeline` — Build a filesystem and log activity timeline for forensic analysis
- `forensics_memory_dump` — Acquire system memory using avml or /proc/kcore
- `forensics_disk_image` — Create forensic disk image with dd and SHA-256 verification
- `forensics_network_capture` — Forensic network capture with tcpdump
- `forensics_evidence_bag` — Package and hash evidence files for chain of custody
- `forensics_chain_of_custody` — View or export the chain of custody log

---

### Defense Management (`meta.ts`) — `defense_mgmt`

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `defense_mgmt` | Server management and reporting (tool checks, workflows, posture, scheduling, reporting) | `check_tools`, `workflow_suggest`, `workflow_run`, `change_history`, `posture_score`, `posture_trend`, `posture_dashboard`, `scheduled_create`, `scheduled_list`, `scheduled_remove`, `scheduled_history`, `remediate_plan`, `remediate_apply`, `remediate_rollback`, `remediate_status`, `report_generate`, `report_list`, `report_formats` | Y | conditional |

**Actions:**
- `check_tools` — Check availability of defensive security tools on the system
- `workflow_suggest` — Suggest a defense workflow for a given scenario or goal
- `workflow_run` — Execute a named defense workflow
- `change_history` — View audit trail of all defensive changes made by this server
- `posture_score` — Calculate overall security posture score
- `posture_trend` — Show security posture trend over time
- `posture_dashboard` — Generate a security posture dashboard summary
- `scheduled_create` — Create a scheduled security audit job
- `scheduled_list` — List all scheduled audit jobs
- `scheduled_remove` — Remove a scheduled audit job
- `scheduled_history` — View execution history for scheduled jobs
- `remediate_plan` — Analyze system and generate a prioritized remediation plan
- `remediate_apply` — Apply planned remediations with rollback support
- `remediate_rollback` — Rollback a previously applied remediation session
- `remediate_status` — Check current remediation session status
- `report_generate` — Collect system audit data and generate a consolidated security report
- `report_list` — List previously saved reports in the report directory
- `report_formats` — Show available output formats, report types, and sections

**Report parameters (for `report_generate`):**
- `report_type` — `executive_summary`, `technical_detail`, `compliance_evidence`, `vulnerability_report`, `hardening_status` (default: `technical_detail`)
- `format` — `markdown`, `html`, `json`, `csv` (default: `markdown`)
- `output_path` — File path to save the report
- `include_sections` — Specific sections to include (default: all)
- `since` — Only include findings since this date (ISO 8601)

---

### Sudo Session (`sudo-management.ts`) — `sudo_session`

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `sudo_session` | Privilege management (elevate, GUI elevate, status, drop, extend, preflight) | `elevate`, `elevate_gui`, `status`, `drop`, `extend`, `preflight_check` | N | never |

**Actions:**
- `elevate` — Elevate privileges by providing sudo password to start a session
- `elevate_gui` — Secure GUI-based elevation (password never visible to AI)
- `status` — Check current sudo session status and time remaining
- `drop` — Drop elevated privileges and zero password buffer
- `extend` — Extend sudo session timeout
- `preflight_check` — Pre-check multiple tools for requirements and sudo needs

---

## Solo Tools (13)

These tools were not consolidated; their names and actions are unchanged from v0.6.x.

| Tool Name | Source | Description | Actions | dryRun | Sudo |
|-----------|--------|-------------|---------|--------|------|
| `api_security` | `api-security.ts` | API security scanning and auditing | `scan_local_apis`, `audit_auth`, `check_rate_limiting`, `tls_verify`, `cors_check` | N | conditional |
| `app_harden` | `app-hardening.ts` | Application hardening (audit, firewall, systemd) | `audit`, `recommend`, `firewall`, `systemd` | Y | conditional |
| `backup` | `backup.ts` | Backup management | `config`, `state`, `restore`, `verify`, `list` | Y | conditional |
| `cloud_security` | `cloud-security.ts` | Cloud environment security | `detect_environment`, `audit_metadata`, `check_iam_creds`, `audit_storage`, `check_imds` | N | conditional |
| `honeypot_manage` | `deception.ts` | Honeypot and deception infrastructure | `deploy_canary`, `deploy_honeyport`, `check_triggers`, `remove`, `list` | N | conditional |
| `dns_security` | `dns-security.ts` | DNS security auditing and defense | `audit_resolv`, `check_dnssec`, `detect_tunneling`, `block_domains`, `query_log_audit` | N | conditional |
| `process_security` | `process-security.ts` | Process security analysis and anomaly detection | `audit_running`, `check_capabilities`, `check_namespaces`, `detect_anomalies`, `cgroup_audit` | N | conditional |
| `supply_chain` | `supply-chain-security.ts` | Supply chain security (SBOM, signing, SLSA) | `sbom`, `sign`, `verify_slsa` | Y | conditional |
| `threat_intel` | `threat-intel.ts` | Threat intelligence (IPs, hashes, domains, feeds) | `check_ip`, `check_hash`, `check_domain`, `update_feeds`, `blocklist_apply` | N | conditional |
| `vuln_manage` | `vulnerability-management.ts` | Vulnerability scanning, tracking, and remediation | `scan_system`, `scan_web`, `track`, `prioritize`, `remediation_plan` | N | conditional |
| `waf_manage` | `waf.ts` | Web Application Firewall management | `modsec_audit`, `modsec_rules`, `rate_limit_config`, `owasp_crs_deploy`, `blocked_requests` | N | conditional |
| `wireless_security` | `wireless-security.ts` | Wireless security (Bluetooth, WiFi, rogue APs) | `bt_audit`, `wifi_audit`, `rogue_ap_detect`, `disable_unused` | N | conditional |
| `zero_trust` | `zero-trust-network.ts` | Zero-trust networking (WireGuard, mTLS, microsegmentation) | `wireguard`, `wg_peers`, `mtls`, `microsegment` | Y | conditional |

---

## Solo Tool Detail

### `dns_security`

**Actions:**
- `audit_resolv` — Audit /etc/resolv.conf and systemd-resolved configuration (DNS over TLS, DNSSEC)
- `check_dnssec` — Check DNSSEC validation for a domain using dig
- `detect_tunneling` — Capture and analyze DNS traffic for tunneling indicators (entropy analysis)
- `block_domains` — Add domains to /etc/hosts blocklist (0.0.0.0 sinkhole)
- `query_log_audit` — Analyze DNS query logs for suspicious activity (DGA, suspicious TLDs)

**Parameters:**
- `action` (required) — Action to perform
- `domain` — Domain to check (for `check_dnssec`)
- `interface` — Network interface for capture (for `detect_tunneling`, default: `any`)
- `duration` — Capture duration in seconds (for `detect_tunneling`, max 120)
- `blocklist_path` — Path to blocklist file (for `block_domains`)
- `domains_to_block` — Array of domains to block (for `block_domains`)
- `log_path` — Path to DNS query log (for `query_log_audit`)
- `threshold` — Entropy threshold for tunneling detection (default 3.5)

**Example:**
```json
{ "action": "check_dnssec", "domain": "example.com" }
```

---

### `vuln_manage`

**Actions:**
- `scan_system` — Run nmap vulnerability scan with NSE scripts and searchsploit exploit lookup
- `scan_web` — Run nikto web vulnerability scan against a target URL
- `track` — Manage vulnerability tracker (add, update status, list)
- `prioritize` — Risk-based prioritization of open vulnerabilities with scoring
- `remediation_plan` — Generate a prioritized remediation plan (immediate/short/medium/long term)

**Parameters:**
- `action` (required) — Action to perform
- `target` — IP/hostname/URL to scan
- `port_range` — Port range for scanning (default: `1-1024`)
- `scan_type` — Scan type: `quick`, `full`, `stealth` (default: `quick`)
- `vuln_id` — Vulnerability ID for tracking
- `severity` — Severity level for new vulnerability
- `description` — Vulnerability description
- `status` — Vulnerability status: `open`, `mitigated`, `accepted`, `false_positive`
- `severity_filter` — Filter for prioritization (default: `all`)
- `output_format` — Output format: `text`, `json`

**Example:**
```json
{ "action": "scan_system", "target": "192.168.1.1", "scan_type": "quick" }
```

---

### `process_security`

**Actions:**
- `audit_running` — Audit running processes for security concerns (root processes, high resource, unusual paths, deleted executables)
- `check_capabilities` — Inspect Linux capabilities on processes; detect dangerous capabilities
- `check_namespaces` — Inspect namespace isolation for a specific PID or list all namespaces via lsns
- `detect_anomalies` — Comprehensive anomaly detection (deleted binaries, unexpected connections, suspicious shells, sensitive file access)
- `cgroup_audit` — Audit cgroup resource limits and hierarchy

**Parameters:**
- `action` (required) — Action to perform
- `pid` — Specific process ID to inspect
- `filter` — Filter processes by name pattern (regex)
- `show_all` — Show all processes or only suspicious ones (default: false)
- `output_format` — Output format: `text`, `json`

**Example:**
```json
{ "action": "detect_anomalies" }
```

---

### `waf_manage`

**Actions:**
- `modsec_audit` — Audit ModSecurity WAF installation and configuration
- `modsec_rules` — Manage ModSecurity rules (list, enable, disable)
- `rate_limit_config` — Audit and recommend rate limiting configuration for nginx/Apache
- `owasp_crs_deploy` — Check OWASP Core Rule Set deployment status and integration
- `blocked_requests` — Analyze WAF audit logs for blocked requests, top IPs, attack categories

**Parameters:**
- `action` (required) — Action to perform
- `web_server` — Web server type: `nginx`, `apache` (default: `nginx`)
- `rule_id` — ModSecurity rule ID (for `modsec_rules`)
- `rule_action` — Rule action: `enable`, `disable`, `list` (default: `list`)
- `rate_limit` — Requests per second (for `rate_limit_config`)
- `rate_limit_zone` — Zone name for rate limiting
- `log_path` — Path to WAF log file (for `blocked_requests`)
- `output_format` — Output format: `text`, `json`

**Example:**
```json
{ "action": "modsec_audit", "web_server": "nginx" }
```

---

### `threat_intel`

**Actions:**
- `check_ip` — Check IP reputation against local feeds, fail2ban, iptables, and whois
- `check_hash` — Check file hash against local hash feeds and ClamAV databases
- `check_domain` — Check domain against local blocklists, /etc/hosts, and DNS resolution
- `update_feeds` — List available feeds or download new threat intelligence feeds
- `blocklist_apply` — Apply a blocklist file to iptables, fail2ban, or /etc/hosts

**Parameters:**
- `action` (required) — Action to perform
- `indicator` — IP address, file hash, or domain to check
- `feed_name` — Name of threat feed (for `update_feeds`)
- `feed_url` — URL of threat feed to download (for `update_feeds`)
- `blocklist_path` — Path to blocklist file (for `blocklist_apply`)
- `apply_to` — Target: `iptables`, `fail2ban`, `hosts` (default: `iptables`)
- `output_format` — Output format: `text`, `json`

**Example:**
```json
{ "action": "check_ip", "indicator": "203.0.113.50" }
```

---

### `cloud_security`

**Actions:**
- `detect_environment` — Detect cloud provider (AWS/GCP/Azure) from DMI, metadata, hypervisor UUID
- `audit_metadata` — Audit instance metadata service (IMDS) configuration and security
- `check_iam_creds` — Check for exposed cloud credentials in environment variables, files, and process environments
- `audit_storage` — Audit accessible cloud storage (S3, GCS, Azure) and mount points
- `check_imds` — Test IMDS security: v1/v2 accessibility, iptables rules, hop limit

**Parameters:**
- `action` (required) — Action to perform
- `provider` — Cloud provider: `aws`, `gcp`, `azure`, `auto` (default: `auto`)
- `output_format` — Output format: `text`, `json`

**Example:**
```json
{ "action": "detect_environment" }
```

---

### `api_security`

**Actions:**
- `scan_local_apis` — Discover local API services on common ports, detect frameworks, find API documentation endpoints
- `audit_auth` — Audit API authentication enforcement: test with/without credentials, detect verbose errors
- `check_rate_limiting` — Send rapid requests to detect rate limiting headers and 429 responses
- `tls_verify` — Verify TLS certificate, check deprecated protocols (TLS 1.0/1.1), HSTS header
- `cors_check` — Analyze CORS policy: test origin reflection, wildcard origins, credential allowance

**Parameters:**
- `action` (required) — Action to perform
- `target` — URL or host:port to scan (default: `http://localhost`)
- `port_range` — Comma-separated ports for API discovery (default: `80,443,3000,4000,5000,8000,8080,8443,9000`)
- `output_format` — Output format: `text`, `json`

**Example:**
```json
{ "action": "cors_check", "target": "https://api.example.com" }
```

---

### `honeypot_manage`

**Actions:**
- `deploy_canary` — Deploy canary token/tripwire (types: file, credential, directory, ssh_key) with inotifywait monitoring
- `deploy_honeyport` — Start a honeyport listener (ncat) with iptables LOG rules for intrusion detection
- `check_triggers` — Check all canaries for access (access time changes, inotify events, connection logs)
- `remove` — Remove a deployed canary by ID (delete files, kill listeners, remove iptables rules)
- `list` — List all canaries in the registry with status

**Parameters:**
- `action` (required) — Action to perform
- `canary_type` — Type of canary: `file`, `credential`, `directory`, `ssh_key` (for `deploy_canary`)
- `canary_path` — Path for canary deployment (for `deploy_canary`)
- `port` — Port for honeyport listener (for `deploy_honeyport`)
- `canary_id` — ID of canary to remove (for `remove`)
- `output_format` — Output format: `text`, `json`

**Example:**
```json
{ "action": "deploy_canary", "canary_type": "credential", "canary_path": "/opt/backup/.aws/credentials" }
```

---

### `wireless_security`

**Actions:**
- `bt_audit` — Audit Bluetooth adapter status, discoverability, paired devices, service state
- `wifi_audit` — Assess WiFi configuration: interfaces, active connections, security type, saved networks
- `rogue_ap_detect` — Scan for rogue access points: unknown APs, open networks, evil twin detection (Levenshtein + substitution)
- `disable_unused` — Disable unused wireless interfaces via rfkill/ip; check loaded kernel modules for blacklisting

**Parameters:**
- `action` (required) — Action to perform
- `interface` — Specific wireless interface to audit (e.g., `wlan0`)
- `output_format` — Output format: `text`, `json`

**Example:**
```json
{ "action": "rogue_ap_detect" }
```

---

### `supply_chain`

**Actions:**
- `sbom` — Generate a Software Bill of Materials for installed packages
- `sign` — Sign an artifact using GPG or sigstore
- `verify_slsa` — Verify SLSA (Supply-chain Levels for Software Artifacts) provenance

**Example:**
```json
{ "action": "sbom" }
```

---

### `zero_trust`

**Actions:**
- `wireguard` — Audit or configure WireGuard VPN interface
- `wg_peers` — List and audit WireGuard peers
- `mtls` — Audit mutual TLS configuration for services
- `microsegment` — Audit or configure network microsegmentation rules

**Example:**
```json
{ "action": "wireguard" }
```

---

### `app_harden`

**Actions:**
- `audit` — Audit application security configuration
- `recommend` — Generate application hardening recommendations
- `firewall` — Apply application-layer firewall rules
- `systemd` — Apply systemd hardening for an application service unit

**Example:**
```json
{ "action": "audit" }
```

---

### `backup`

**Actions:**
- `config` — Back up current system configuration files
- `state` — Back up current security state (firewall rules, sysctl, etc.)
- `restore` — Restore a previously saved backup
- `verify` — Verify backup integrity
- `list` — List all available backups

**Example:**
```json
{ "action": "list" }
```
