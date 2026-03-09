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

---

## Reporting (`reporting.ts`) — 1 tool

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `report_export` | Generate, list, or query consolidated security reports in multiple formats | `generate`, `list_reports`, `formats` | N | conditional |

### `report_export`

**Actions:**
- `generate` — Collect system audit data (firewall, services, connections, logins, compliance) and format as a consolidated security report
- `list_reports` — List previously saved reports in the report directory
- `formats` — Show available output formats, report types, and sections

**Parameters:**
- `action` (required) — Action to perform
- `report_type` — Report type: `executive_summary`, `technical_detail`, `compliance_evidence`, `vulnerability_report`, `hardening_status` (default: `technical_detail`)
- `format` — Output format: `markdown`, `html`, `json`, `csv` (default: `markdown`)
- `output_path` — File path to save the report
- `include_sections` — Specific sections to include (default: all)
- `since` — Only include findings since this date (ISO 8601)

**Example:**
```json
{ "action": "generate", "report_type": "executive_summary", "format": "html", "output_path": "/tmp/security-report.html" }
```

---

## DNS Security (`dns-security.ts`) — 1 tool

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `dns_security` | DNS security auditing, DNSSEC validation, tunneling detection, domain blocking, query log analysis | `audit_resolv`, `check_dnssec`, `detect_tunneling`, `block_domains`, `query_log_audit` | N | conditional |

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

## Vulnerability Management (`vulnerability-management.ts`) — 1 tool

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `vuln_manage` | Vulnerability scanning, tracking, prioritization, and remediation planning | `scan_system`, `scan_web`, `track`, `prioritize`, `remediation_plan` | N | conditional |

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

## Forensics (`incident-response.ts`) — 1 tool (extends incident-response module)

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `ir_forensics` | Digital forensics: memory dumps, disk imaging, network capture, evidence bagging, chain of custody | `memory_dump`, `disk_image`, `network_capture_forensic`, `evidence_bag`, `chain_of_custody` | N | always |

### `ir_forensics`

**Actions:**
- `memory_dump` — Acquire system memory using avml or /proc/kcore
- `disk_image` — Create forensic disk image with dd and SHA-256 verification
- `network_capture_forensic` — Forensic network capture with tcpdump
- `evidence_bag` — Package and hash evidence files for chain of custody
- `chain_of_custody` — View or export the chain of custody log

**Parameters:**
- `action` (required) — Action to perform
- `output_path` — Path to save forensic output
- `device` — Disk device for imaging (e.g., `/dev/sda1`)
- `interface` — Network interface for capture
- `duration` — Capture duration in seconds

**Example:**
```json
{ "action": "memory_dump", "output_path": "/evidence/memory.lime" }
```

---

## Process Security (`process-security.ts`) — 1 tool

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `process_security` | Process security analysis: audit running processes, check capabilities, inspect namespaces, detect anomalies, audit cgroup limits | `audit_running`, `check_capabilities`, `check_namespaces`, `detect_anomalies`, `cgroup_audit` | N | conditional |

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

## WAF Management (`waf.ts`) — 1 tool

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `waf_manage` | Web Application Firewall management: audit ModSecurity, manage rules, configure rate limiting, deploy OWASP CRS, analyze blocked requests | `modsec_audit`, `modsec_rules`, `rate_limit_config`, `owasp_crs_deploy`, `blocked_requests` | N | conditional |

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

## Network Segmentation (`network-defense.ts`) — 1 tool (extends network-defense module)

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `network_segmentation_audit` | Network segmentation: map zones, verify isolation, test paths, audit VLANs | `map_zones`, `verify_isolation`, `test_paths`, `audit_vlans` | N | conditional |

### `network_segmentation_audit`

**Actions:**
- `map_zones` — Map network zones from interface and routing table analysis
- `verify_isolation` — Verify network isolation between zones using iptables rules
- `test_paths` — Test network paths between endpoints using traceroute/nmap
- `audit_vlans` — Audit VLAN configuration and bridge interfaces

**Parameters:**
- `action` (required) — Action to perform
- `source` — Source IP/subnet for path testing
- `destination` — Destination IP/subnet for path testing
- `output_format` — Output format: `text`, `json`

**Example:**
```json
{ "action": "map_zones" }
```

---

## Threat Intelligence (`threat-intel.ts`) — 1 tool

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `threat_intel` | Threat intelligence: check IPs, hashes, and domains against local feeds, manage feeds, apply blocklists | `check_ip`, `check_hash`, `check_domain`, `update_feeds`, `blocklist_apply` | N | conditional |

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

## Auto-Remediation (`meta.ts`) — 1 tool (extends meta module)

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `auto_remediate` | Auto-remediation: plan fixes, apply remediations, rollback sessions, check status | `plan`, `apply`, `rollback_session`, `status` | Y | conditional |

### `auto_remediate`

**Actions:**
- `plan` — Analyze system and generate a remediation plan based on findings
- `apply` — Apply planned remediations (sysctl, iptables, sed-based config fixes)
- `rollback_session` — Rollback a previously applied remediation session
- `status` — Check current remediation session status

**Parameters:**
- `action` (required) — Action to perform
- `session_id` — Remediation session ID (for `rollback_session`)
- `dry_run` — Preview changes without applying (default: true)

**Example:**
```json
{ "action": "plan" }
```

---

## Cloud Security (`cloud-security.ts`) — 1 tool

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `cloud_security` | Cloud security: detect environment, audit metadata services, check IAM credentials, audit storage, test IMDS security | `detect_environment`, `audit_metadata`, `check_iam_creds`, `audit_storage`, `check_imds` | N | conditional |

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

## API Security (`api-security.ts`) — 1 tool

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `api_security` | API security: discover local APIs, audit authentication, check rate limiting, verify TLS, analyze CORS | `scan_local_apis`, `audit_auth`, `check_rate_limiting`, `tls_verify`, `cors_check` | N | conditional |

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

## Deception / Honeypots (`deception.ts`) — 1 tool

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `honeypot_manage` | Honeypot/deception: deploy canary tokens, set up honeyport listeners, check triggers, remove canaries, list deployed assets | `deploy_canary`, `deploy_honeyport`, `check_triggers`, `remove`, `list` | N | conditional |

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

## Wireless Security (`wireless-security.ts`) — 1 tool

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `wireless_security` | Wireless security: audit Bluetooth, assess WiFi, detect rogue APs with evil twin analysis, disable unused interfaces | `bt_audit`, `wifi_audit`, `rogue_ap_detect`, `disable_unused` | N | conditional |

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

## Certificate Lifecycle (`encryption.ts`) — 1 tool (extends encryption module)

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `certificate_lifecycle` | Certificate lifecycle: inventory, auto-renewal check, CA audit, OCSP check, CT log monitoring | `inventory`, `auto_renew_check`, `ca_audit`, `ocsp_check`, `ct_log_monitor` | N | conditional |

### `certificate_lifecycle`

**Actions:**
- `inventory` — Scan for certificates across the filesystem using find + openssl
- `auto_renew_check` — Check certbot auto-renewal configuration and certificate expiry
- `ca_audit` — Audit trusted CA certificates in the system trust store
- `ocsp_check` — Check OCSP responder status for a certificate
- `ct_log_monitor` — Monitor Certificate Transparency logs for a domain

**Parameters:**
- `action` (required) — Action to perform
- `domain` — Domain for CT log monitoring or OCSP check
- `cert_path` — Path to certificate file
- `output_format` — Output format: `text`, `json`

**Example:**
```json
{ "action": "inventory" }
```

---

## SIEM Integration (`siem-integration.ts`) — 1 tool

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `siem_export` | SIEM integration: configure syslog forwarding, audit Filebeat, comprehensive log forwarding audit, test connectivity | `configure_syslog_forward`, `configure_filebeat`, `audit_forwarding`, `test_connectivity` | N | conditional |

### `siem_export`

**Actions:**
- `configure_syslog_forward` — Audit/configure rsyslog remote forwarding (TCP/UDP/TLS), check existing rules and TLS support
- `configure_filebeat` — Audit Filebeat installation, modules, service status, and output configuration
- `audit_forwarding` — Comprehensive log forwarding audit with CIS benchmark compliance check
- `test_connectivity` — Test SIEM endpoint connectivity: DNS resolution, TCP, TLS, firewall rules, test syslog message

**Parameters:**
- `action` (required) — Action to perform
- `siem_host` — SIEM server hostname or IP address
- `siem_port` — SIEM server port (default: 514 for syslog, 5044 for filebeat)
- `protocol` — Transport protocol: `tcp`, `udp`, `tls` (default: `tcp`)
- `log_sources` — Log sources to forward (e.g., `auth`, `syslog`, `kern`, `audit`)
- `output_format` — Output format: `text`, `json`

**Example:**
```json
{ "action": "test_connectivity", "siem_host": "siem.example.com", "siem_port": 514 }
```

---

## USB Device Control (`hardening.ts`) — 1 tool (extends hardening module)

| Tool Name | Description | Actions | dryRun | Sudo |
|-----------|-------------|---------|--------|------|
| `usb_device_control` | USB device control: audit devices, block storage, whitelist, monitor | `audit_devices`, `block_storage`, `whitelist`, `monitor` | Y | conditional |

### `usb_device_control`

**Actions:**
- `audit_devices` — Audit connected USB devices using lsusb and lsblk
- `block_storage` — Block USB mass storage via kernel module blacklisting (modprobe)
- `whitelist` — Manage USB device whitelist via udev rules
- `monitor` — Monitor USB device events via udevadm

**Parameters:**
- `action` (required) — Action to perform
- `device_id` — USB device vendor:product ID for whitelisting
- `dry_run` — Preview changes without applying (default: true)
- `output_format` — Output format: `text`, `json`

**Example:**
```json
{ "action": "audit_devices" }
```
