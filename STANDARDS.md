# Security Standards Mapping

This document maps kali-defense-mcp-server tools to recognized security standards and compliance frameworks. Use this reference to identify which tools provide evidence for specific controls during audits, assessments, or self-attestation exercises.

---

## Table of Contents

1. [CIS Benchmark Controls](#cis-benchmark-controls)
2. [NIST SP 800-53 Controls](#nist-sp-800-53-controls)
3. [Compliance Frameworks](#compliance-frameworks)
   - [PCI-DSS v4.0](#pci-dss-v40)
   - [HIPAA Security Rule](#hipaa-security-rule)
   - [SOC 2 Type II](#soc-2-type-ii)
   - [ISO/IEC 27001:2022](#isoiec-270012022)
   - [GDPR Article 32](#gdpr-article-32)
4. [Cross-Framework Tool Coverage Summary](#cross-framework-tool-coverage-summary)

---

## CIS Benchmark Controls

Reference: CIS Benchmarks for Linux (v3.0+) — Ubuntu/Debian, RHEL families.

### Section 1 — Initial Setup: Filesystem Configuration

| CIS Control | Title | Tool(s) | Evidence Type |
|-------------|-------|---------|---------------|
| 1.1.1 | Disable unused filesystems (cramfs, hfs, hfsplus, jffs2, udf) | `harden_module_audit` | Audit findings with pass/fail per module |
| 1.1.4 | Ensure /tmp is configured with nodev,nosuid,noexec | `compliance_tmp_hardening` | Mount options output + compliance status |
| 1.2.x | Configure Software Updates | `patch_update_audit`, `patch_unattended_audit` | Pending packages list, unattended config |

### Section 2 — Services

| CIS Control | Title | Tool(s) | Evidence Type |
|-------------|-------|---------|---------------|
| 2.1.x | Special Purpose Services (disable time, print, proxy servers) | `harden_service_audit` | List of running services with risk flags |
| 2.2.x | Service Clients (disable unneeded clients) | `harden_service_audit` | Service status and recommendations |
| 2.3 | Ensure mail transfer agent is configured for local-only mode | `netdef_open_ports_audit`, `netdef_connections` | Listening port list |

### Section 3 — Network Configuration

| CIS Control | Title | Tool(s) | Evidence Type |
|-------------|-------|---------|---------------|
| 3.1.1 | Ensure IP forwarding is disabled | `harden_sysctl_audit`, `harden_sysctl_get` | `net.ipv4.ip_forward = 0` confirmed |
| 3.1.2 | Ensure packet redirect sending is disabled | `harden_sysctl_audit` | `net.ipv4.conf.all.send_redirects = 0` |
| 3.2.1 | Ensure source routed packets are not accepted | `harden_sysctl_audit` | `accept_source_route = 0` |
| 3.2.2 | Ensure ICMP redirects are not accepted | `harden_sysctl_audit` | `accept_redirects = 0` |
| 3.2.3 | Ensure secure ICMP redirects are not accepted | `harden_sysctl_audit` | `secure_redirects = 0` |
| 3.2.4 | Ensure suspicious packets are logged | `harden_sysctl_audit` | `log_martians = 1` |
| 3.2.5 | Ensure broadcast ICMP requests are ignored | `harden_sysctl_audit` | `ignore_broadcasts = 1` |
| 3.2.6 | Ensure bogus ICMP responses are ignored | `harden_sysctl_audit` | `ignore_bogus_error_responses = 1` |
| 3.2.7 | Ensure Reverse Path Filtering is enabled | `harden_sysctl_audit` | `rp_filter = 1` |
| 3.2.8 | Ensure TCP SYN Cookies is enabled | `harden_sysctl_audit` | `tcp_syncookies = 1` |
| 3.3.x | IPv6 | `netdef_ipv6_audit` | IPv6 config and firewall status |
| 3.5.1 | Ensure a firewall package is installed | `firewall_policy_audit` | UFW/iptables presence check |
| 3.5.1.1 | Ensure UFW is installed and enabled | `firewall_ufw_status` | UFW status output |
| 3.5.1.2 | Ensure UFW loopback traffic is configured | `firewall_iptables_list` | Loopback rule check |
| 3.5.2.x | Configure nftables | `firewall_nftables_list` | nftables ruleset |
| 3.5.3.x | Configure iptables: default deny policies | `firewall_policy_audit`, `firewall_set_policy` | Chain policies (INPUT/FORWARD DROP) |
| 3.5.3.7 | Ensure iptables rules are saved | `firewall_persistence` | Persistence status |

### Section 4 — Logging and Auditing

| CIS Control | Title | Tool(s) | Evidence Type |
|-------------|-------|---------|---------------|
| 4.1.1.1 | Ensure auditd is installed | `log_auditd_rules` | auditctl -l output |
| 4.1.1.2 | Ensure auditd service is enabled | `harden_service_audit` | systemctl status auditd |
| 4.1.1.3 | Ensure auditing for processes before auditd starts | `log_auditd_cis_rules` | GRUB audit=1 parameter check |
| 4.1.2.x | Configure Data Retention | `log_auditd_rules` | max_log_file and action settings |
| 4.1.3.x | Configure auditd rules — time changes | `log_auditd_cis_rules` | Rule deployment and verification |
| 4.1.3.x | Configure auditd rules — identity changes | `log_auditd_cis_rules` | /etc/passwd, /etc/group watch rules |
| 4.1.3.x | Configure auditd rules — network config changes | `log_auditd_cis_rules` | sysctl network rule watches |
| 4.1.3.x | Configure auditd rules — MAC policy | `log_auditd_cis_rules` | AppArmor/SELinux policy change watches |
| 4.1.3.x | Configure auditd rules — login/logout events | `log_auditd_cis_rules` | /var/log/lastlog, faillog watches |
| 4.1.3.x | Configure auditd rules — session initiation | `log_auditd_cis_rules` | /var/run/utmp, wtmp, btmp watches |
| 4.1.3.x | Configure auditd rules — file access by unauthorized users | `log_auditd_cis_rules` | EACCES/EPERM exit rules |
| 4.1.3.x | Configure auditd rules — privileged commands | `log_auditd_cis_rules` | setuid/setgid binary watches |
| 4.2.1.x | Configure rsyslog | `log_syslog_analyze` | syslog service status |
| 4.2.2.x | Configure journald | `log_rotation_audit` | journald persistence settings |
| 4.2.3 | Ensure log rotation is configured | `log_rotation_audit` | logrotate config findings |

### Section 5 — Access, Authentication and Authorization

| CIS Control | Title | Tool(s) | Evidence Type |
|-------------|-------|---------|---------------|
| 5.1.1–5.1.7 | Configure cron permissions | `harden_cron_audit` | cron.deny/cron.allow status |
| 5.1.8 | Ensure cron is restricted to authorized users | `compliance_cron_restrict`, `harden_cron_audit` | /etc/cron.allow contents |
| 5.1.9 | Ensure at is restricted to authorized users | `compliance_cron_restrict`, `harden_cron_audit` | /etc/at.allow contents |
| 5.2.1 | Ensure sudo is installed | `access_sudo_audit` | sudo package check |
| 5.2.2 | Ensure sudo commands use pty | `access_sudo_audit` | Defaults requiretty check |
| 5.2.3 | Ensure sudo log file exists | `access_sudo_audit` | Defaults logfile check |
| 5.3.x | Configure PAM | `access_pam_audit`, `access_pam_configure` | PAM config findings |
| 5.3.1 | Ensure password creation requirements are configured | `access_pam_configure`, `access_password_policy` | pwquality settings |
| 5.3.2 | Ensure lockout for failed password attempts | `access_pam_configure` | faillock/pam_tally settings |
| 5.3.3 | Ensure password reuse is limited | `access_pam_audit` | PAM remember setting |
| 5.3.4 | Ensure password hashing algorithm is up to date | `access_pam_audit` | SHA-512 hash check |
| 5.4.1.x | Password aging policies | `access_password_policy` | /etc/login.defs values |
| 5.4.2 | Ensure system accounts are secured | `access_user_audit` | Non-login shell check |
| 5.4.3 | Ensure default group for root is GID 0 | `access_user_audit` | root group check |
| 5.4.4 | Ensure default user umask is 027 or more restrictive | `harden_umask_audit`, `harden_umask_set` | umask value in login.defs |
| 5.5.x | Configure SSH Server | `access_ssh_audit`, `access_ssh_harden`, `access_ssh_cipher_audit` | sshd_config findings |
| 5.5.1.1 | Ensure permissions on /etc/ssh/sshd_config are configured | `harden_permissions_audit` | File permission findings |
| 5.5.2 | Ensure SSH access is limited | `access_ssh_audit` | AllowUsers/AllowGroups check |
| 5.5.3 | Ensure SSH LogLevel is appropriate | `access_ssh_audit` | LogLevel INFO/VERBOSE check |
| 5.5.4 | Ensure SSH X11 forwarding is disabled | `access_ssh_audit` | X11Forwarding no check |
| 5.5.6 | Ensure SSH IgnoreRhosts is enabled | `access_ssh_audit` | IgnoreRhosts yes check |
| 5.5.7 | Ensure SSH HostbasedAuthentication is disabled | `access_ssh_audit` | HostbasedAuthentication no |
| 5.5.8 | Ensure SSH root login is disabled | `access_ssh_audit` | PermitRootLogin no/prohibit-password |
| 5.5.9 | Ensure SSH PermitEmptyPasswords is disabled | `access_ssh_audit` | PermitEmptyPasswords no |
| 5.6 | Ensure access to the su command is restricted | `access_sudo_audit` | /etc/pam.d/su check |
| 5.7 | Configure login warning banners | `harden_banner_audit`, `harden_banner_set` | /etc/issue, /etc/issue.net content |

### Section 6 — System Maintenance

| CIS Control | Title | Tool(s) | Evidence Type |
|-------------|-------|---------|---------------|
| 6.1.x | System file permissions | `harden_permissions_audit`, `harden_file_permissions` | Permission audit findings |
| 6.2.x | Local user and group settings | `access_user_audit` | User account audit results |

---

## NIST SP 800-53 Controls

Reference: NIST Special Publication 800-53 Revision 5 — Security and Privacy Controls for Information Systems and Organizations.

### AC — Access Control

| Control | Title | Tool(s) | Evidence Type |
|---------|-------|---------|---------------|
| AC-2 | Account Management | `access_user_audit` | Privileged/inactive account list |
| AC-3 | Access Enforcement | `access_sudo_audit`, `access_pam_audit` | sudo/PAM configuration |
| AC-6 | Least Privilege | `access_sudo_audit`, `access_user_audit` | NOPASSWD and wildcard findings |
| AC-7 | Unsuccessful Logon Attempts | `access_pam_configure`, `log_fail2ban_status` | faillock/fail2ban config |
| AC-8 | System Use Notification | `harden_banner_audit`, `harden_banner_set` | Login banner content |
| AC-17 | Remote Access | `access_ssh_audit`, `access_ssh_harden`, `access_ssh_cipher_audit` | sshd_config compliance |

### AU — Audit and Accountability

| Control | Title | Tool(s) | Evidence Type |
|---------|-------|---------|---------------|
| AU-2 | Event Logging | `log_auditd_rules`, `log_auditd_cis_rules` | auditd rule set |
| AU-3 | Content of Audit Records | `log_auditd_search`, `log_auditd_report` | Audit log samples |
| AU-5 | Response to Audit Logging Process Failures | `log_auditd_rules` | Action on full disk setting |
| AU-6 | Audit Record Review | `log_auditd_report`, `log_syslog_analyze` | Analysis outputs |
| AU-9 | Protection of Audit Information | `harden_permissions_audit` | /var/log permissions |
| AU-11 | Audit Record Retention | `log_rotation_audit` | Retention configuration |
| AU-12 | Audit Record Generation | `log_auditd_cis_rules` | Full rule deployment |

### CA — Assessment, Authorization, and Monitoring

| Control | Title | Tool(s) | Evidence Type |
|---------|-------|---------|---------------|
| CA-2 | Control Assessments | `compliance_lynis_audit`, `compliance_cis_check` | Lynis/CIS audit report |
| CA-7 | Continuous Monitoring | `setup_scheduled_audit`, `calculate_security_score`, `get_posture_trend` | Scheduled audit history |

### CM — Configuration Management

| Control | Title | Tool(s) | Evidence Type |
|---------|-------|---------|---------------|
| CM-2 | Baseline Configuration | `create_baseline`, `backup_system_state` | System baseline snapshot |
| CM-3 | Configuration Change Control | `defense_change_history` | Change audit trail |
| CM-4 | Security Impact Analysis | Dry-run output from modifying tools | Pre-execution impact preview |
| CM-6 | Configuration Settings | `harden_sysctl_audit`, `harden_permissions_audit` | Sysctl/permission findings |
| CM-7 | Least Functionality | `harden_service_audit`, `netdef_open_ports_audit` | Unnecessary service/port findings |
| CM-8 | System Component Inventory | `backup_system_state`, `generate_sbom` | Package list, SBOM |
| CM-11 | User-Installed Software | `patch_integrity_check`, `verify_package_integrity` | Package integrity verification |

### IA — Identification and Authentication

| Control | Title | Tool(s) | Evidence Type |
|---------|-------|---------|---------------|
| IA-3 | Device Identification | `access_ssh_cipher_audit`, `setup_mtls` | Certificate/key config |
| IA-5 | Authenticator Management | `access_password_policy`, `access_pam_configure` | Password/lockout policy |
| IA-5(1) | Password-Based Authentication | `access_pam_configure` | pwquality settings |

### IR — Incident Response

| Control | Title | Tool(s) | Evidence Type |
|---------|-------|---------|---------------|
| IR-4 | Incident Handling | `ir_volatile_collect`, `ir_ioc_scan`, `ir_timeline_generate` | Forensic collection package |
| IR-5 | Incident Monitoring | `log_auditd_search`, `ids_rootkit_summary` | Event search results |
| IR-6 | Incident Reporting | `defense_change_history`, `log_auditd_report` | Change and audit reports |

### RA — Risk Assessment

| Control | Title | Tool(s) | Evidence Type |
|---------|-------|---------|---------------|
| RA-5 | Vulnerability Monitoring and Scanning | `patch_update_audit`, `lookup_cve`, `scan_packages_cves` | CVE and patch findings |
| RA-5(2) | Update Vulnerabilities to Be Scanned | `malware_clamav_update` | Signature update confirmation |

### SA — System and Services Acquisition

| Control | Title | Tool(s) | Evidence Type |
|---------|-------|---------|---------------|
| SA-10 | Developer Configuration Management | `generate_sbom`, `verify_package_integrity`, `check_slsa_attestation` | SBOM, integrity checks |
| SA-11 | Developer Testing and Evaluation | `scan_for_secrets`, `scan_git_history` | Secret scan findings |

### SC — System and Communications Protection

| Control | Title | Tool(s) | Evidence Type |
|---------|-------|---------|---------------|
| SC-5 | Denial of Service Protection | `harden_sysctl_audit` | tcp_syncookies, rp_filter settings |
| SC-7 | Boundary Protection | `firewall_policy_audit`, `netdef_open_ports_audit` | Firewall rules and open ports |
| SC-8 | Transmission Confidentiality and Integrity | `crypto_tls_audit`, `crypto_tls_config_audit` | TLS audit results |
| SC-12 | Cryptographic Key Establishment and Management | `crypto_gpg_keys`, `setup_mtls` | Key management records |
| SC-13 | Cryptographic Protection | `crypto_tls_audit`, `crypto_file_hash` | Cipher/hash verification |
| SC-17 | Public Key Infrastructure Certificates | `crypto_cert_expiry`, `setup_mtls` | Certificate validity |
| SC-28 | Protection of Information at Rest | `crypto_luks_manage` | LUKS volume status |
| SC-39 | Process Isolation | `container_namespace_check`, `audit_memory_protections` | Namespace and ASLR status |

### SI — System and Information Integrity

| Control | Title | Tool(s) | Evidence Type |
|---------|-------|---------|---------------|
| SI-2 | Flaw Remediation | `patch_update_audit`, `get_patch_urgency`, `scan_packages_cves` | Patch and CVE findings |
| SI-3 | Malicious Code Protection | `malware_clamav_scan`, `malware_yara_scan` | Scan results |
| SI-4 | System Monitoring | `ids_aide_manage`, `ids_rootkit_summary`, `create_baseline`, `compare_to_baseline` | IDS and drift alerts |
| SI-5 | Security Alerts, Advisories, and Directives | `lookup_cve`, `get_patch_urgency` | CVE advisory details |
| SI-6 | Security and Privacy Function Verification | `harden_kernel_security_audit`, `report_exploit_mitigations` | Kernel mitigation status |
| SI-7 | Software, Firmware, and Information Integrity | `patch_integrity_check`, `ids_file_integrity_check`, `generate_sbom` | File integrity and SBOM |
| SI-10 | Information Input Validation | Built-in sanitizer (all tools) | Input validation architecture |

---

## Compliance Frameworks

### PCI-DSS v4.0

Payment Card Industry Data Security Standard, version 4.0 (effective March 2024).

**Estimated coverage with this toolset: 55–70% of applicable technical controls**

Key tools and their PCI-DSS requirement mappings:

| PCI-DSS Requirement | Title | Tool(s) | Evidence Type |
|---------------------|-------|---------|---------------|
| Req 1.1–1.3 | Network Security Controls (firewall) | `firewall_policy_audit`, `firewall_iptables_list`, `firewall_ufw_status`, `netdef_open_ports_audit` | Firewall rule sets, port audit |
| Req 1.4 | Network access controls between trusted and untrusted networks | `configure_microsegmentation`, `firewall_set_policy` | Microsegmentation rules |
| Req 2.2 | System components configured and managed securely | `harden_sysctl_audit`, `harden_service_audit`, `compliance_cis_check` | Hardening audit findings |
| Req 2.2.1 | All system components' configuration standards documented | `backup_system_state`, `create_baseline` | System state snapshot |
| Req 3.5 | Primary account numbers protected where stored | `crypto_luks_manage`, `crypto_file_hash` | Encryption status |
| Req 4.2 | Strong cryptography in transit | `crypto_tls_audit`, `crypto_tls_config_audit`, `access_ssh_cipher_audit` | TLS/SSH cipher findings |
| Req 5.2 | Malicious software detection | `malware_clamav_scan`, `malware_clamav_update`, `malware_yara_scan` | Scan results, signature dates |
| Req 5.3 | Anti-malware mechanisms actively running | `malware_clamav_update`, `ids_aide_manage` | Update status, IDS active |
| Req 6.2 | Bespoke software security | `scan_for_secrets`, `scan_git_history`, `generate_sbom` | Secret scan, SBOM |
| Req 6.3 | Security vulnerabilities identified and addressed | `patch_update_audit`, `lookup_cve`, `scan_packages_cves` | Vulnerability findings |
| Req 7.2 | Access control system implemented | `access_user_audit`, `access_sudo_audit`, `access_pam_configure` | Account and PAM config |
| Req 8.2 | User account management | `access_user_audit`, `access_password_policy` | Account audit |
| Req 8.3 | MFA for all administrative access | `access_pam_configure` | PAM/MFA configuration |
| Req 8.6 | System passwords — complexity and rotation | `access_pam_configure`, `access_password_policy` | pwquality, login.defs |
| Req 10.2 | Implement audit logs | `log_auditd_rules`, `log_auditd_cis_rules` | auditd rule set |
| Req 10.3 | Protect audit logs | `harden_permissions_audit`, `log_rotation_audit` | Log permissions, retention |
| Req 10.5 | Retain audit logs | `log_rotation_audit` | logrotate config |
| Req 10.7 | Monitor security control failures | `log_fail2ban_status`, `ids_rootkit_summary` | Monitoring status |
| Req 11.3 | External and internal vulnerability scans | `netdef_self_scan`, `scan_packages_cves`, `patch_update_audit` | Scan results |
| Req 11.4 | Intrusion detection | `ids_aide_manage`, `create_baseline`, `compare_to_baseline` | IDS and drift status |
| Req 11.5 | Change detection | `create_baseline`, `compare_to_baseline`, `defense_change_history` | Drift alerts, change log |
| Req 12.5 | Identify and maintain documented configurations | `backup_system_state`, `generate_sbom` | Configuration snapshots |

**Gaps (out of scope for this toolset)**:
- Physical security controls (Req 9)
- Security awareness training (Req 12.6)
- Third-party/vendor management (Req 12.8–12.9)

---

### HIPAA Security Rule

45 CFR Part 164, Subpart C — Security Standards for the Protection of Electronic Protected Health Information (ePHI).

**Estimated coverage: 50–65% of applicable Administrative and Technical Safeguards**

| HIPAA Safeguard | Standard | Tool(s) | Evidence Type |
|----------------|----------|---------|---------------|
| 164.308(a)(1) | Security Management Process — Risk Analysis | `compliance_lynis_audit`, `calculate_security_score`, `patch_update_audit` | Risk assessment outputs |
| 164.308(a)(1) | Security Management Process — Risk Management | `harden_sysctl_audit`, `firewall_policy_audit`, `access_ssh_harden` | Remediation evidence |
| 164.308(a)(2) | Assigned Security Responsibility | `defense_change_history` | Change ownership trail |
| 164.308(a)(3) | Workforce Security | `access_user_audit`, `access_sudo_audit` | Account access review |
| 164.308(a)(4) | Information Access Management | `access_pam_configure`, `access_password_policy` | Access controls |
| 164.308(a)(5) | Security Awareness and Training — Login Monitoring | `log_fail2ban_status`, `log_auditd_report` | Login audit reports |
| 164.308(a)(5) | Security Awareness and Training — Password Management | `access_password_policy`, `access_pam_configure` | Password policy settings |
| 164.308(a)(6) | Security Incident Procedures | `ir_volatile_collect`, `ir_ioc_scan`, `ir_timeline_generate` | IR collection evidence |
| 164.308(a)(7) | Contingency Plan — Data Backup | `backup_config_files`, `backup_system_state`, `backup_list` | Backup records |
| 164.308(a)(8) | Evaluation | `compliance_report`, `compliance_cis_check`, `run_compliance_check` | Periodic audit reports |
| 164.312(a)(1) | Access Control — Unique User Identification | `access_user_audit` | UID uniqueness check |
| 164.312(a)(1) | Access Control — Automatic Logoff | `access_ssh_audit` | ClientAliveInterval check |
| 164.312(a)(2) | Encryption and Decryption | `crypto_luks_manage`, `crypto_tls_audit` | Encryption status |
| 164.312(b) | Audit Controls | `log_auditd_rules`, `log_auditd_cis_rules`, `log_auditd_report` | Audit rule set and reports |
| 164.312(c)(1) | Integrity — ePHI Alteration Controls | `ids_file_integrity_check`, `ids_aide_manage`, `create_baseline` | Integrity baseline |
| 164.312(d) | Person or Entity Authentication | `access_pam_audit`, `access_pam_configure` | Authentication config |
| 164.312(e)(1) | Transmission Security — Encryption | `crypto_tls_audit`, `access_ssh_cipher_audit` | TLS/SSH cipher audit |

**Gaps**:
- Administrative safeguards requiring policy documents (164.308(a)(1)(ii)(A) — documented risk analysis report)
- Workforce training records
- Business Associate Agreements (164.308(b))

---

### SOC 2 Type II

AICPA Trust Services Criteria (2017 edition with 2022 points of focus updates). Focus on the Common Criteria (CC) relevant to security.

**Estimated coverage: 45–60% of applicable Common Criteria**

| Trust Services Criterion | Description | Tool(s) | Evidence Type |
|--------------------------|-------------|---------|---------------|
| CC1.4 (Integrity) | Commitment to competence | `defense_check_tools` | Tool availability evidence |
| CC2.1 (Communication) | Internal communication of control information | `defense_change_history` | Change audit trail |
| CC5.1 | Risk assessment | `calculate_security_score`, `compliance_report` | Risk scoring |
| CC5.2 | Risk mitigation | `harden_sysctl_set`, `access_ssh_harden`, `firewall_set_policy` | Hardening actions |
| CC6.1 | Logical access security software | `access_pam_configure`, `access_password_policy` | Authentication controls |
| CC6.1 | Logical access — authorization | `access_sudo_audit`, `access_user_audit` | Privilege review |
| CC6.2 | Registration and authorization of new users | `access_user_audit` | Account audit |
| CC6.3 | Role-based access | `access_sudo_audit`, `access_restrict_shell` | RBAC evidence |
| CC6.6 | Logical access boundaries — network controls | `firewall_policy_audit`, `netdef_open_ports_audit` | Network boundary controls |
| CC6.7 | Restrict data transmission | `crypto_tls_audit`, `configure_microsegmentation` | TLS and segmentation |
| CC6.8 | Malicious code prevention | `malware_clamav_scan`, `malware_yara_scan`, `ids_rootkit_summary` | Malware scan results |
| CC7.1 | Configuration monitoring | `create_baseline`, `compare_to_baseline`, `list_drift_alerts` | Drift detection records |
| CC7.2 | System monitoring | `setup_scheduled_audit`, `log_auditd_cis_rules` | Scheduled audit records |
| CC7.3 | Vulnerability monitoring | `patch_update_audit`, `scan_packages_cves`, `lookup_cve` | Vulnerability scan reports |
| CC7.4 | Incident detection and response | `ir_ioc_scan`, `ir_volatile_collect`, `ids_aide_manage` | IOC and forensic data |
| CC8.1 | Change management | `defense_change_history`, `backup_config_files` | Change log with backups |

---

### ISO/IEC 27001:2022

Annex A Controls (ISO/IEC 27001:2022 / ISO/IEC 27002:2022).

**Estimated coverage: 40–55% of applicable Annex A controls**

| Annex A Control | Title | Tool(s) | Evidence Type |
|-----------------|-------|---------|---------------|
| A.5.15 | Access Control | `access_user_audit`, `access_sudo_audit`, `access_pam_configure` | Access control review |
| A.5.16 | Identity Management | `access_user_audit`, `access_restrict_shell` | Account management records |
| A.5.17 | Authentication Information | `access_password_policy`, `access_pam_configure` | Password and lockout policy |
| A.5.18 | Access Rights | `access_sudo_audit`, `access_user_audit` | Privilege audit |
| A.5.23 | Information Security for Cloud Services | `container_docker_audit`, `container_daemon_configure` | Container security audit |
| A.5.36 | Compliance with Security Policies | `compliance_cis_check`, `compliance_lynis_audit`, `run_compliance_check` | Compliance reports |
| A.6.3 | Information Security Awareness | `harden_banner_set`, `harden_banner_audit` | Login warning banner |
| A.7.5 | Protecting Assets | `crypto_luks_manage`, `crypto_file_hash` | Data-at-rest encryption |
| A.8.2 | Privileged Access Rights | `access_sudo_audit`, `access_user_audit` | Privileged account review |
| A.8.3 | Information Access Restriction | `firewall_policy_audit`, `netdef_open_ports_audit` | Network access review |
| A.8.4 | Access to Source Code | `scan_for_secrets`, `scan_git_history` | Source code secret scan |
| A.8.5 | Secure Authentication | `access_ssh_harden`, `access_ssh_cipher_audit`, `crypto_tls_audit` | Secure auth config |
| A.8.6 | Capacity Management | `backup_system_state` | System snapshot |
| A.8.7 | Malware Protection | `malware_clamav_scan`, `malware_clamav_update`, `ids_rootkit_summary` | Antimalware evidence |
| A.8.8 | Management of Technical Vulnerabilities | `patch_update_audit`, `scan_packages_cves`, `lookup_cve` | Patch and CVE reports |
| A.8.9 | Configuration Management | `create_baseline`, `compare_to_baseline`, `harden_sysctl_audit` | Config baseline and drift |
| A.8.11 | Data Masking | `secrets_scan`, `secrets_env_audit` | Secret exposure findings |
| A.8.12 | Data Leakage Prevention | `scan_for_secrets`, `secrets_ssh_key_sprawl` | Data leakage evidence |
| A.8.15 | Logging | `log_auditd_rules`, `log_auditd_cis_rules`, `log_rotation_audit` | Logging configuration |
| A.8.16 | Monitoring Activities | `setup_scheduled_audit`, `get_posture_trend` | Monitoring records |
| A.8.17 | Clock Synchronization | `log_auditd_cis_rules` | Time change audit rules |
| A.8.20 | Networks Security | `firewall_policy_audit`, `netdef_ipv6_audit` | Network security controls |
| A.8.21 | Security of Network Services | `crypto_tls_audit`, `netdef_open_ports_audit` | Service security audit |
| A.8.22 | Segregation of Networks | `configure_microsegmentation`, `container_namespace_check` | Segmentation evidence |
| A.8.23 | Web Filtering | `netdef_port_scan_detect`, `netdef_dns_monitor` | Network monitoring data |
| A.8.24 | Use of Cryptography | `crypto_tls_config_audit`, `crypto_gpg_keys`, `crypto_luks_manage` | Cryptography controls |
| A.8.25 | Secure Development Lifecycle | `generate_sbom`, `verify_package_integrity`, `check_slsa_attestation` | Supply chain controls |
| A.8.26 | Application Security Requirements | `scan_for_secrets`, `generate_sbom` | Application security findings |
| A.8.28 | Secure Coding | `scan_for_secrets`, `scan_git_history` | Code secret scanning |
| A.8.29 | Security Testing in Dev/Acceptance | `netdef_self_scan`, `scan_packages_cves` | Vulnerability testing |
| A.8.32 | Change Management | `defense_change_history`, `backup_config_files` | Change records with rollback |
| A.8.33 | Test Information | `create_baseline`, `backup_system_state` | Pre-change snapshots |
| A.8.34 | Protection During Audit Testing | Dry-run mode across all tools | Non-destructive audit |

---

### GDPR Article 32

General Data Protection Regulation, Article 32 — Security of Processing. Requires appropriate technical measures proportionate to the risk.

**Estimated coverage: 50–70% of applicable technical measures**

| GDPR Art. 32 Requirement | Measure | Tool(s) | Evidence Type |
|--------------------------|---------|---------|---------------|
| Art. 32(1)(a) — Pseudonymisation and encryption | Encryption of personal data | `crypto_luks_manage`, `crypto_tls_audit`, `crypto_tls_config_audit` | Encryption verification |
| Art. 32(1)(b) — Confidentiality | Ongoing confidentiality | `access_user_audit`, `firewall_policy_audit`, `netdef_open_ports_audit` | Access and network controls |
| Art. 32(1)(b) — Integrity | Data integrity | `ids_file_integrity_check`, `ids_aide_manage`, `create_baseline` | Integrity monitoring |
| Art. 32(1)(b) — Availability | System availability | `backup_config_files`, `backup_system_state`, `backup_list` | Backup evidence |
| Art. 32(1)(b) — Resilience | Resilience of systems | `patch_update_audit`, `harden_sysctl_audit` | Patch and hardening status |
| Art. 32(1)(c) — Restore availability | Timely restore capability | `backup_restore`, `backup_verify` | Restore capability demonstration |
| Art. 32(1)(d) — Regular testing | Effectiveness testing | `compliance_report`, `run_compliance_check`, `calculate_security_score` | Periodic assessment reports |
| Art. 32(2) — Appropriate measures | Risk-proportionate controls | `defense_security_posture`, `get_posture_trend` | Posture scoring over time |
| Recital 83 — Personal data breach | Breach detection | `ir_ioc_scan`, `ids_rootkit_summary`, `log_auditd_search` | IOC and audit search results |
| Recital 83 — Access logging | Authentication logging | `log_auditd_cis_rules`, `log_auditd_report` | Login event audit records |

**Gaps**:
- Data Processing Agreements (legal/contractual, not technical)
- Data subject rights procedures (Art. 15–22)
- Data Protection Impact Assessments (Art. 35) beyond technical scanning
- Cross-border transfer safeguards (Art. 46)

---

## Cross-Framework Tool Coverage Summary

The following table shows which compliance frameworks each tool category primarily serves:

| Tool Category | PCI-DSS | HIPAA | SOC 2 | ISO 27001 | GDPR |
|---------------|---------|-------|-------|-----------|------|
| Firewall (12 tools) | High | Medium | High | High | Medium |
| System Hardening (19 tools) | High | High | High | High | High |
| Intrusion Detection (5 tools) | High | Medium | High | Medium | High |
| Log Analysis (10 tools) | High | High | High | High | Medium |
| Network Defense (8 tools) | High | Low | High | High | Medium |
| Compliance (7 tools) | High | Medium | Medium | High | Medium |
| Malware Analysis (6 tools) | High | Medium | High | High | Medium |
| Backup & Recovery (5 tools) | Medium | High | Medium | Medium | High |
| Access Control (9 tools) | High | High | High | High | High |
| Encryption & PKI (6 tools) | High | High | High | High | High |
| Container Security (9 tools) | Medium | Low | Medium | Medium | Low |
| Meta & Orchestration (5 tools) | Low | Low | Medium | Medium | Low |
| Patch Management (4 tools) | High | Medium | High | High | Medium |
| Secrets Management (3 tools) | High | Medium | Medium | High | High |
| Incident Response (3 tools) | Medium | High | High | Medium | High |
| Supply Chain Security (4 tools) | Low | Low | Medium | High | Low |
| Memory Protection (3 tools) | Low | Low | Low | Medium | Low |
| Drift Detection (3 tools) | Medium | Low | High | High | Medium |
| Vulnerability Intelligence (3 tools) | High | Medium | High | High | Medium |
| Security Posture (3 tools) | Medium | Medium | High | High | Medium |
| Secrets Scanner (3 tools) | High | Medium | Medium | High | High |
| Zero-Trust Network (4 tools) | High | Low | Medium | High | Low |
| Container Advanced (4 tools) | Low | Low | Low | Medium | Low |
| Compliance Extended (1 tool) | High | High | High | High | High |
| eBPF Security (4 tools) | Low | Low | Medium | Medium | Low |
| Automation Workflows (4 tools) | Medium | Medium | High | Medium | Medium |

**Coverage Level Definitions**:
- High: Multiple tools directly address key controls in this framework
- Medium: Some tools provide supporting evidence for this framework
- Low: Minimal applicability; framework requires capabilities outside this toolset's scope
