# Changelog

All notable changes to the kali-defense-mcp-server are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [2.0.0] — 2026-02-21

### Summary

Major release expanding the server from 69 tools across 12 categories to 130+ tools across 26 categories. Introduces application safeguards, rollback infrastructure, a dedicated BackupManager, 11 new tool modules, and multi-framework compliance support.

---

### New Tool Modules (11 modules, ~65 new tools)

#### Supply Chain Security (`supply-chain-security.ts`)
- `generate_sbom` — Generate Software Bill of Materials using syft, cdxgen, or dpkg/rpm fallback
- `verify_package_integrity` — Verify installed package checksums (debsums/rpm -V)
- `setup_cosign_signing` — Sign container images or artifacts with cosign (keyless or key-based)
- `check_slsa_attestation` — Verify SLSA provenance attestation for binaries or artifacts

#### Memory Protection (`memory-protection.ts`)
- `audit_memory_protections` — Audit ASLR, PIE, RELRO, NX, stack canary on specified binaries
- `enforce_aslr` — Enable full ASLR by setting kernel.randomize_va_space=2
- `report_exploit_mitigations` — Report system-wide exploit mitigation status (SMEP, SMAP, PTI, KASLR)

#### Drift Detection (`drift-detection.ts`)
- `create_baseline` — Create system baseline (file hashes, sysctl state, service states)
- `compare_to_baseline` — Compare current system state against a saved baseline
- `list_drift_alerts` — List available baselines and summarize changes since last baseline

#### Vulnerability Intelligence (`vulnerability-intel.ts`)
- `lookup_cve` — Look up CVE details from the NVD API
- `scan_packages_cves` — Scan installed packages for known CVEs
- `get_patch_urgency` — Get patch urgency for a specific package

#### Security Posture (`security-posture.ts`)
- `calculate_security_score` — Weighted security score (0-100) across 7 security domains
- `get_posture_trend` — Compare current score against historical scores
- `generate_posture_dashboard` — Structured posture dashboard with findings and recommendations

#### Secrets Scanner (`secrets-scanner.ts`)
- `scan_for_secrets` — Directory secrets scan using truffleHog, gitleaks, or built-in grep patterns
- `audit_env_vars` — Audit current process environment variables for potential secrets
- `scan_git_history` — Scan git repository history for leaked secrets

#### Zero-Trust Network (`zero-trust-network.ts`)
- `setup_wireguard` — Set up WireGuard VPN interface with key generation and configuration
- `manage_wg_peers` — Add, remove, or list WireGuard peers
- `setup_mtls` — Generate CA, server, and client certificates for mutual TLS authentication
- `configure_microsegmentation` — Configure iptables/nftables rules for service-level microsegmentation

#### Container Advanced (`container-advanced.ts`)
- `generate_seccomp_profile` — Generate custom seccomp profile JSON from allowed syscall list
- `apply_apparmor_container` — Generate and optionally load an AppArmor profile for a container
- `setup_rootless_containers` — Configure rootless container support (newuidmap/newgidmap, user namespaces)
- `scan_image_trivy` — Scan container image for vulnerabilities using Trivy

#### Compliance Extended (`compliance-extended.ts`)
- `run_compliance_check` — Run structured compliance checks against PCI-DSS v4, HIPAA, SOC 2, ISO 27001, or GDPR frameworks

#### eBPF Security (`ebpf-security.ts`)
- `list_ebpf_programs` — List loaded eBPF programs and pinned maps
- `check_falco` — Check Falco runtime security status, version, and configuration
- `deploy_falco_rules` — Deploy custom Falco rules to /etc/falco/rules.d/
- `get_ebpf_events` — Read recent Falco events from the JSON log

#### Automation Workflows (`automation-workflows.ts`)
- `setup_scheduled_audit` — Create scheduled security audit using systemd timer or cron
- `list_scheduled_audits` — List all scheduled security audits
- `remove_scheduled_audit` — Remove a scheduled security audit by name
- `get_audit_history` — Read historical output from scheduled audit jobs

---

### New Tools in Existing Modules

#### Firewall Management (5 new tools, 12 total)
- `firewall_nftables_list` — List nftables ruleset; nftables is the modern replacement for iptables
- `firewall_set_policy` — Set default chain policy (INPUT/FORWARD/OUTPUT) with rollback tracking
- `firewall_create_chain` — Create custom iptables chain with optional ip6tables mirror
- `firewall_persistence` — Manage iptables-persistent: install, save, and check persistence status
- `firewall_policy_audit` — Audit firewall configuration for default policy issues and misconfigurations

#### System Hardening (12 new tools, 19 total)
- `harden_systemd_audit` — Audit service units using systemd-analyze security; scores 40+ properties
- `harden_kernel_security_audit` — Audit CPU vulnerability mitigations, Landlock, lockdown mode, ASLR
- `harden_bootloader_audit` — Audit GRUB: password protection, Secure Boot status, kernel parameters
- `harden_module_audit` — Audit kernel module blacklisting per CIS benchmark
- `harden_cron_audit` — Audit cron and at access control configuration (cron.allow/deny)
- `harden_umask_audit` — Audit default umask in login.defs, profile, bashrc
- `harden_banner_audit` — Audit login warning banners per CIS benchmark
- `harden_umask_set` — Set default umask across login.defs, /etc/profile, /etc/bash.bashrc
- `harden_coredump_disable` — Disable core dumps via limits.conf, coredump.conf, and sysctl
- `harden_banner_set` — Set CIS-compliant login warning banner content
- `harden_bootloader_configure` — Configure GRUB kernel parameters (add_kernel_params/status)
- `harden_systemd_apply` — Apply systemd security hardening overrides (basic/strict preset)

#### Logging and Monitoring (3 new tools, 10 total)
- `log_auditd_cis_rules` — Check or deploy complete set of CIS Benchmark-required auditd rules
- `log_rotation_audit` — Audit logrotate configuration and journald persistence settings
- `log_fail2ban_audit` — Audit fail2ban jail configurations for weak ban times and missing jails

#### Network Defense (2 new tools, 8 total)
- `netdef_ipv6_audit` — Audit IPv6 configuration, firewall status, and whether IPv6 should be disabled
- `netdef_self_scan` — Run nmap self-scan to discover exposed services from a network perspective

#### Compliance and Benchmarking (2 new tools, 7 total)
- `compliance_cron_restrict` — Create/manage /etc/cron.allow and /etc/at.allow (CIS 5.1.8, 5.1.9)
- `compliance_tmp_hardening` — Audit and apply /tmp mount hardening with nodev,nosuid,noexec

#### Malware Analysis (1 new tool, 6 total)
- `malware_webshell_detect` — Scan web server directories for web shells using pattern matching

#### Access Control (3 new tools, 9 total)
- `access_ssh_cipher_audit` — Audit SSH cryptographic algorithms against Mozilla/NIST recommendations
- `access_pam_configure` — Configure PAM modules: pam_pwquality (complexity) and pam_faillock (lockout)
- `access_restrict_shell` — Restrict a user's login shell to nologin or /bin/false

#### Container Security (4 new tools, 9 total)
- `container_image_scan` — Scan Docker images for vulnerabilities using Trivy or Grype
- `container_seccomp_audit` — Audit Docker containers for seccomp profile configuration
- `container_daemon_configure` — Audit/apply Docker daemon security settings in /etc/docker/daemon.json
- `container_apparmor_install` — Install AppArmor profile packages and list loaded profiles

---

### New Core Infrastructure

#### `src/core/safeguards.ts` — SafeguardRegistry
- Singleton that detects running applications before modifying operations execute
- Parallel detection of VS Code (process + `.vscode` dir + IPC sockets), Docker (socket + container list), MCP servers (`.mcp.json` + node processes), databases (TCP port probes: PostgreSQL 5432, MySQL 3306, MongoDB 27017, Redis 6379), and web servers (nginx/apache2/httpd via pgrep)
- `checkSafety(operation, params)` returns `SafetyResult` with `warnings[]`, `blockers[]`, and `impactedApps[]`
- `appSafetyReport()` generates a full detection report across all application categories
- All detection errors are caught gracefully and converted to warnings rather than failures

#### `src/core/backup-manager.ts` — BackupManager
- Manages file backups with manifest tracking under `~/.kali-mcp-backups/`
- Each backup entry has a UUID, original path, backup path, timestamp, and size
- `manifest.json` maintains the full backup inventory for list and restore operations
- `backup(filePath)` — creates timestamped copy and adds to manifest, returns UUID
- `restore(backupId)` — restores by UUID with target directory auto-creation
- `listBackups()` — returns all entries sorted by timestamp (newest first)
- `pruneOldBackups(daysOld)` — removes backups older than N days and updates manifest

#### `src/core/rollback.ts` — RollbackManager
- Singleton that tracks system changes within and across sessions
- State persisted to `~/.kali-defense/rollback-state.json`
- Supports four change types: `file` (backup path), `sysctl` (previous value), `service` (previous state), `firewall` (rollback command)
- `rollback(operationId)` — reverses all changes for a specific operation in reverse order
- `rollbackSession(sessionId)` — reverses all changes from the current session
- `listChanges()` — returns all tracked changes sorted by timestamp

---

### Documentation Added

- `SAFEGUARDS.md` — Complete SafeguardRegistry reference: detection methods, operation trigger mapping, warning vs blocker levels, dry-run examples, backup storage layout, rollback and restore guide
- `TOOLS-REFERENCE.md` — Alphabetical table of all 130+ tools with MCP tool name, description, key parameters, dryRun support, OS compatibility, and safety level
- `STANDARDS.md` — Security standards mapping covering CIS Benchmark section-by-section, NIST SP 800-53 control families, and five compliance frameworks (PCI-DSS v4, HIPAA, SOC 2, ISO 27001, GDPR) with coverage estimates and evidence types
- `CHANGELOG.md` — This file; version history beginning at v2.0.0
- `README.md` — Updated with new tool categories, application safeguards section, OS compatibility matrix, and quick-start examples for each new tool category

---

### Changed

- `src/index.ts` — Updated server version to `2.0.0`, added imports and registration calls for all 11 new modules; server now registers 26 tool modules
- `README.md` — Complete rewrite to reflect 130+ tools; added OS matrix, safeguards section, quick-start examples for all new categories
- Tool count in server startup message updated to `130+`

---

## [1.0.0] — 2025 (initial release)

### Initial Release

69 defensive security tools across 12 categories:

- Firewall Management (7 tools): iptables list/add/delete, UFW status/rule, save, restore
- System Hardening (7 tools): sysctl get/set/audit, service manage/audit, file permissions, permissions audit
- Intrusion Detection (5 tools): AIDE, rkhunter, chkrootkit, file integrity check, rootkit summary
- Log Analysis (7 tools): auditd rules/search/report, journalctl, fail2ban status/manage, syslog analyze
- Network Defense (6 tools): connections, port scan detect, tcpdump, DNS monitor, ARP monitor, open ports audit
- Compliance (5 tools): lynis, oscap, CIS check, policy evaluate, report
- Malware Analysis (5 tools): ClamAV scan/update, YARA scan, suspicious files, quarantine manage
- Backup and Recovery (5 tools): config backup, system state, restore, verify, list
- Access Control (6 tools): SSH audit/harden, sudo audit, user audit, password policy, PAM audit
- Encryption and PKI (6 tools): TLS audit, cert expiry, GPG keys, LUKS manage, file hash, TLS config audit
- Container Security (5 tools): Docker audit/bench, AppArmor manage, SELinux manage, namespace check
- Meta and Orchestration (5 tools): check tools, suggest workflow, security posture, change history, run workflow

Core infrastructure: executor (spawn with shell:false), sanitizer (17+ validators), config (env-based), parsers, distro detection, installer, changelog, policy engine
