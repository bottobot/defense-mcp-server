# Comprehensive Remediation & Hardening Workflow

> **Defense MCP Server — Full System Hardening**
> Takes audit findings and applies all possible remediations using every available tool.
> Estimated total time: ~60–120 minutes depending on system state and findings.

---

## Overview

This workflow is designed to be executed **after** the [Security Audit Workflow](./SECURITY-AUDIT-WORKFLOW.md). It takes the audit findings and systematically hardens every layer of the system using all 31 Defense MCP Server tools.

**⚠️ CRITICAL: All mutating steps require `dry_run: false` to actually apply changes.**
The workflow is written with `dry_run: false` for clarity, but the agent should:
1. First run each step with `dry_run: true` (default) to preview changes
2. Present the preview to the user for approval
3. Only then execute with `dry_run: false`

**⚠️ IMPORTANT: Every mutating step creates a backup first.** If anything goes wrong, rollback is possible.

---

## ⚠️ DNS Resolver Safety — CRITICAL

> **NEVER install `systemd-resolved`, `resolvconf`, `openresolv`, or standalone `dnsmasq` on this workstation.**
>
> DNS is managed by **NetworkManager via OPNsense gateway** (192.168.1.1). Installing any package that
> replaces the DNS resolver stack will **immediately break DNS** and kill all internet connectivity.
>
> **For DNS security findings (DoT, DNSSEC):** Configure on the **OPNsense gateway**, not the workstation.
> Use the `opnsense-firewall` skill to enable Unbound DoT and DNSSEC on 192.168.1.1.
> Verify from workstation: `dig +dnssec example.com @192.168.1.1`
>
> **If DNS breaks:** `sudo rm -f /etc/resolv.conf; echo "nameserver 192.168.1.1" | sudo tee /etc/resolv.conf; sudo systemctl restart NetworkManager`
>
> See [docs/adr/dns-resolver-safety.md](../adr/dns-resolver-safety.md) for full rationale.

---

## Pre-Requisites

### Phase 0: Setup & Safety Net (~3 min)

#### Step 0.1 — Elevate Sudo Session
```json
Tool: sudo_session
{ "action": "elevate_gui" }
```
> Uses secure GUI dialog so the password is never visible to the AI.

#### Step 0.2 — Verify Tool Availability
```json
Tool: defense_mgmt
{ "action": "check_tools" }
```
> Confirms all required tools are installed before starting remediation.

#### Step 0.3 — Install Missing Optional Dependencies

> **Prerequisites:** `DEFENSE_MCP_AUTO_INSTALL=true` and `DEFENSE_MCP_THIRD_PARTY_INSTALL=true` must be set in `.roo/mcp.json` env (already configured in this project).

**a) Check what's missing:**
```json
Tool: defense_mgmt
{ "action": "check_optional_deps" }
```

**b) Preview install (dry run):**
```json
Tool: defense_mgmt
{ "action": "install_optional_deps", "dry_run": true }
```
> Review the list of packages that will be installed before proceeding.

**c) Execute install:**
```json
Tool: defense_mgmt
{ "action": "install_optional_deps", "dry_run": false }
```

> **Fallback:** If MCP install fails, use `scripts/install-optional-deps.sh` or manual `sudo apt-get install <package>`.
>
> **Graceful degradation:** If a tool cannot be installed (e.g., unavailable on this distro/arch), skip its checks in later phases and note the gap in the final report. The workflow should continue with available tools.

#### Step 0.4 — Full Configuration Backup
```json
Tool: backup
{ "action": "config", "dry_run": false }
```
> Creates a complete backup of all critical configuration files.

#### Step 0.5 — Full System State Snapshot
```json
Tool: backup
{ "action": "state", "dry_run": false }
```
> Captures complete system state (firewall, network, services, packages, users).

#### Step 0.6 — Create Filesystem Integrity Baseline
```json
Tool: integrity
{ "action": "baseline_create", "name": "pre-hardening", "directories": ["/etc", "/usr/bin", "/usr/sbin"], "dryRun": false }
```
> Creates a baseline snapshot before any changes for drift detection.

#### Step 0.7 — Initialize AIDE Database
```json
Tool: integrity
{ "action": "aide_init", "dry_run": false }
```
> Initializes AIDE file integrity database (or updates if exists).

---

## Phase 1: Kernel Hardening (~5 min)

### Step 1.1 — Enable Full ASLR
```json
Tool: harden_kernel
{ "action": "sysctl_set", "key": "kernel.randomize_va_space", "value": "2", "persistent": true, "dry_run": false }
```
> Enables full Address Space Layout Randomization.

### Step 1.2 — Restrict dmesg Access
```json
Tool: harden_kernel
{ "action": "sysctl_set", "key": "kernel.dmesg_restrict", "value": "1", "persistent": true, "dry_run": false }
```
> Restricts kernel log access to root only.

### Step 1.3 — Restrict Kernel Pointer Exposure
```json
Tool: harden_kernel
{ "action": "sysctl_set", "key": "kernel.kptr_restrict", "value": "2", "persistent": true, "dry_run": false }
```
> Hides kernel pointers from all users.

### Step 1.4 — Disable SysRq Key
```json
Tool: harden_kernel
{ "action": "sysctl_set", "key": "kernel.sysrq", "value": "0", "persistent": true, "dry_run": false }
```
> Disables the magic SysRq key to prevent console-level attacks.

### Step 1.5 — Restrict ptrace
```json
Tool: harden_kernel
{ "action": "sysctl_set", "key": "kernel.yama.ptrace_scope", "value": "1", "persistent": true, "dry_run": false }
```
> Restricts ptrace to parent processes only.

### Step 1.6 — Disable IP Forwarding
```json
Tool: harden_kernel
{ "action": "sysctl_set", "key": "net.ipv4.ip_forward", "value": "0", "persistent": true, "dry_run": false }
```
> Disables IP forwarding (skip if system is a router/gateway).

### Step 1.7 — Enable SYN Cookies
```json
Tool: harden_kernel
{ "action": "sysctl_set", "key": "net.ipv4.tcp_syncookies", "value": "1", "persistent": true, "dry_run": false }
```
> Enables TCP SYN cookie protection against SYN flood attacks.

### Step 1.8 — Disable ICMP Redirects
```json
Tool: harden_kernel
{ "action": "sysctl_set", "key": "net.ipv4.conf.all.accept_redirects", "value": "0", "persistent": true, "dry_run": false }
```
> Disables ICMP redirect acceptance to prevent routing table manipulation.

### Step 1.9 — Disable Source Routing
```json
Tool: harden_kernel
{ "action": "sysctl_set", "key": "net.ipv4.conf.all.accept_source_route", "value": "0", "persistent": true, "dry_run": false }
```
> Disables source-routed packets.

### Step 1.10 — Enable Reverse Path Filtering
```json
Tool: harden_kernel
{ "action": "sysctl_set", "key": "net.ipv4.conf.all.rp_filter", "value": "1", "persistent": true, "dry_run": false }
```
> Enables reverse path filtering to prevent IP spoofing.

### Step 1.11 — Disable ICMP Redirect Sending
```json
Tool: harden_kernel
{ "action": "sysctl_set", "key": "net.ipv4.conf.all.send_redirects", "value": "0", "persistent": true, "dry_run": false }
```
> Prevents the system from sending ICMP redirects.

### Step 1.12 — Log Martian Packets
```json
Tool: harden_kernel
{ "action": "sysctl_set", "key": "net.ipv4.conf.all.log_martians", "value": "1", "persistent": true, "dry_run": false }
```
> Logs packets with impossible source addresses.

### Step 1.13 — Disable IPv6 Redirects
```json
Tool: harden_kernel
{ "action": "sysctl_set", "key": "net.ipv6.conf.all.accept_redirects", "value": "0", "persistent": true, "dry_run": false }
```
> Disables IPv6 ICMP redirect acceptance.

### Step 1.14 — Restrict Core Dumps
```json
Tool: harden_kernel
{ "action": "sysctl_set", "key": "fs.suid_dumpable", "value": "0", "persistent": true, "dry_run": false }
```
> Prevents SUID programs from creating core dumps.

### Step 1.15 — Enforce ASLR via Memory Tool
```json
Tool: harden_kernel
{ "action": "memory_enforce_aslr", "dry_run": false }
```
> Enforces ASLR through the dedicated memory protection tool.

### Step 1.16 — Harden Bootloader (Add Kernel Parameters)
```json
Tool: harden_kernel
{ "action": "bootloader_configure", "configure_action": "add_kernel_params", "kernel_params": "slab_nomerge init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 randomize_kstack_offset=on", "dry_run": false }
```
> Adds security-focused kernel boot parameters for memory hardening.

---

## Phase 2: Host Hardening (~5 min)

### Step 2.1 — Disable Unnecessary Services
```json
Tool: harden_host
{ "action": "service_manage", "service": "avahi-daemon.service", "service_action": "disable", "dry_run": false }
```
> Disables Avahi mDNS daemon (repeat for each unnecessary service found in audit).

**Repeat for each unnecessary service identified in the audit:**
- `cups.service` (if no printing needed)
- `bluetooth.service` (if no Bluetooth needed)
- `ModemManager.service` (if no modem)
- Other services flagged by `service_audit`

### Step 2.2 — Fix Critical File Permissions
```json
Tool: harden_host
{ "action": "permissions_fix", "path": "/etc/shadow", "owner": "root", "group": "shadow", "mode": "640", "dry_run": false }
```
> Fixes /etc/shadow permissions.

### Step 2.3 — Fix SSH Directory Permissions
```json
Tool: harden_host
{ "action": "permissions_fix", "path": "/etc/ssh", "owner": "root", "group": "root", "mode": "755", "dry_run": false }
```
> Fixes SSH directory permissions.

### Step 2.4 — Fix Cron Permissions
```json
Tool: harden_host
{ "action": "permissions_fix", "path": "/etc/crontab", "owner": "root", "group": "root", "mode": "600", "dry_run": false }
```
> Restricts crontab file permissions.

### Step 2.5 — Apply Systemd Service Hardening (Basic)
```json
Tool: harden_host
{ "action": "systemd_apply", "service": "ssh.service", "hardening_level": "basic", "dry_run": false }
```
> Applies basic systemd sandboxing to SSH service.

### Step 2.6 — Apply Systemd Service Hardening (Strict for non-critical)
```json
Tool: harden_host
{ "action": "systemd_apply", "service": "cron.service", "hardening_level": "strict", "dry_run": false }
```
> Applies strict systemd sandboxing to cron service.

### Step 2.7 — Set Secure Umask
```json
Tool: harden_host
{ "action": "umask_set", "umask_value": "027", "targets": ["login.defs", "profile", "bashrc"], "dry_run": false }
```
> Sets restrictive umask (027) across all configuration files.

### Step 2.8 — Set Login Warning Banner
```json
Tool: harden_host
{ "action": "banner_set", "banner_targets": ["issue", "issue.net", "motd"], "dry_run": false }
```
> Sets CIS-compliant warning banners on all login interfaces.

### Step 2.9 — Block USB Mass Storage
```json
Tool: harden_host
{ "action": "usb_block_storage", "block_method": "modprobe", "dry_run": false }
```
> Blocks USB mass storage via kernel module blacklisting.

---

## Phase 3: Access Control Hardening (~5 min)

### Step 3.1 — Harden SSH Configuration
```json
Tool: access_control
{ "action": "ssh_harden", "apply_recommended": true, "dry_run": false }
```
> Applies all recommended SSH hardening settings at once.

### Step 3.2 — Harden SSH (Specific Critical Settings)
```json
Tool: access_control
{ "action": "ssh_harden", "settings": "PermitRootLogin=no,PermitEmptyPasswords=no,MaxAuthTries=4,X11Forwarding=no,AllowAgentForwarding=no,AllowTcpForwarding=no,ClientAliveInterval=300,ClientAliveCountMax=3,LoginGraceTime=60,MaxSessions=4", "dry_run": false }
```
> Applies specific SSH hardening settings for maximum security.

### Step 3.3 — Configure PAM Password Quality
```json
Tool: access_control
{ "action": "pam_configure", "module": "pwquality", "pam_settings": { "minlen": 14, "dcredit": -1, "ucredit": -1, "lcredit": -1, "ocredit": -1, "maxrepeat": 3, "minclass": 4, "reject_username": true }, "dry_run": false }
```
> Configures strong password quality requirements via PAM.

### Step 3.4 — Configure PAM Account Lockout
```json
Tool: access_control
{ "action": "pam_configure", "module": "faillock", "pam_settings": { "deny": 5, "unlock_time": 900, "fail_interval": 900 }, "dry_run": false }
```
> Configures account lockout after 5 failed attempts (15-minute lockout).

### Step 3.5 — Set System Password Policy
```json
Tool: access_control
{ "action": "password_policy_set", "max_days": 365, "min_days": 1, "warn_days": 14, "min_length": 14, "inactive_days": 30, "encrypt_method": "YESCRYPT", "dry_run": false }
```
> Sets system-wide password policy (max age, min length, encryption).

### Step 3.6 — Restrict Shell for Service Accounts
```json
Tool: access_control
{ "action": "restrict_shell", "username": "nobody", "shell": "/usr/sbin/nologin", "dry_run": false }
```
> Restricts login shell for service accounts (repeat for each service account).

**Repeat for service accounts identified in audit:**
- `www-data`
- `daemon`
- `bin`
- `sys`
- Other accounts with unnecessary shell access

### Step 3.7 — Manage Sudoers (Harden)
```json
Tool: access_control
{ "action": "sudoers_manage", "sudoers_action": "write", "sudoers_filename": "defense-hardening", "sudoers_content": "Defaults use_pty\nDefaults logfile=/var/log/sudo.log\nDefaults log_input,log_output\nDefaults passwd_timeout=1\nDefaults timestamp_timeout=5", "dry_run": false }
```
> Creates a sudoers drop-in file with hardened defaults.

---

## Phase 4: Firewall Hardening (~5 min)

### Step 4.1 — Set INPUT Chain Default to DROP
```json
Tool: firewall
{ "action": "iptables_set_policy", "chain": "INPUT", "policy": "DROP", "dry_run": false }
```
> Sets default INPUT policy to DROP (deny all inbound by default).

### Step 4.2 — Set FORWARD Chain Default to DROP
```json
Tool: firewall
{ "action": "iptables_set_policy", "chain": "FORWARD", "policy": "DROP", "dry_run": false }
```
> Sets default FORWARD policy to DROP.

### Step 4.3 — Allow Established Connections
```json
Tool: firewall
{ "action": "iptables_add", "chain": "INPUT", "protocol": "all", "target_action": "ACCEPT", "match_module": "conntrack", "match_options": "--ctstate ESTABLISHED,RELATED", "position": 1, "dry_run": false }
```
> Allows established and related connections (essential for connectivity).

### Step 4.4 — Allow Loopback
```json
Tool: firewall
{ "action": "iptables_add", "chain": "INPUT", "protocol": "all", "target_action": "ACCEPT", "source": "127.0.0.0/8", "position": 2, "dry_run": false }
```
> Allows loopback traffic.

### Step 4.5 — Allow SSH (Rate Limited)
```json
Tool: firewall
{ "action": "iptables_add", "chain": "INPUT", "protocol": "tcp", "port": "22", "target_action": "ACCEPT", "match_module": "limit", "match_options": "--limit 3/min --limit-burst 5", "dry_run": false }
```
> Allows SSH with rate limiting to prevent brute force.

### Step 4.6 — Drop Invalid Packets
```json
Tool: firewall
{ "action": "iptables_add", "chain": "INPUT", "protocol": "all", "target_action": "DROP", "match_module": "conntrack", "match_options": "--ctstate INVALID", "dry_run": false }
```
> Drops invalid packets.

### Step 4.7 — Log Dropped Packets
```json
Tool: firewall
{ "action": "iptables_add", "chain": "INPUT", "protocol": "all", "target_action": "LOG", "match_module": "limit", "match_options": "--limit 5/min", "dry_run": false }
```
> Logs dropped packets (rate limited to prevent log flooding).

### Step 4.8 — Apply IPv6 DROP Policy
```json
Tool: firewall
{ "action": "iptables_set_policy", "chain": "INPUT", "policy": "DROP", "ipv6": true, "dry_run": false }
```
> Sets IPv6 INPUT policy to DROP.

### Step 4.9 — Enable Firewall Persistence
```json
Tool: firewall
{ "action": "persist_enable", "dry_run": false }
```
> Installs iptables-persistent for rules to survive reboots.

### Step 4.10 — Save Firewall Rules
```json
Tool: firewall
{ "action": "persist_save", "dry_run": false }
```
> Saves current firewall rules to disk.

---

## Phase 5: Logging & Monitoring Hardening (~5 min)

### Step 5.1 — Deploy CIS Auditd Rules
```json
Tool: log_management
{ "action": "auditd_cis_rules", "cis_action": "generate", "dry_run": false }
```
> Generates and deploys CIS-recommended auditd rules.

### Step 5.2 — Add Custom Audit Rules (File Access)
```json
Tool: log_management
{ "action": "auditd_rules", "rules_action": "add", "rule": "-w /etc/passwd -p wa -k identity", "dry_run": false }
```
> Monitors /etc/passwd for write and attribute changes.

### Step 5.3 — Add Custom Audit Rules (Shadow)
```json
Tool: log_management
{ "action": "auditd_rules", "rules_action": "add", "rule": "-w /etc/shadow -p wa -k identity", "dry_run": false }
```
> Monitors /etc/shadow for changes.

### Step 5.4 — Add Custom Audit Rules (Sudoers)
```json
Tool: log_management
{ "action": "auditd_rules", "rules_action": "add", "rule": "-w /etc/sudoers -p wa -k sudoers", "dry_run": false }
```
> Monitors sudoers for changes.

### Step 5.5 — Add Custom Audit Rules (SSH Config)
```json
Tool: log_management
{ "action": "auditd_rules", "rules_action": "add", "rule": "-w /etc/ssh/sshd_config -p wa -k sshd_config", "dry_run": false }
```
> Monitors SSH configuration for changes.

### Step 5.6 — Configure Log Rotation
```json
Tool: log_management
{ "action": "rotation_configure", "logrotate_name": "defense-security", "logrotate_path": "/var/log/auth.log", "rotate_frequency": "daily", "rotate_count": 30, "compress_logs": true, "extra_directives": ["missingok", "notifempty", "delaycompress"], "dry_run": false }
```
> Configures proper log rotation for security logs.

### Step 5.7 — Reload Fail2ban
```json
Tool: log_management
{ "action": "fail2ban_reload" }
```
> Reloads fail2ban to pick up any configuration changes.

---

## Phase 6: Compliance Hardening (~5 min)

### Step 6.1 — Restrict Cron/At Access
```json
Tool: compliance
{ "action": "cron_restrict", "allowed_users": ["root"], "dry_run": false }
```
> Creates cron.allow and at.allow files restricting access to root only (CIS 5.1.8/5.1.9).

### Step 6.2 — Harden /tmp Mount
```json
Tool: compliance
{ "action": "tmp_harden", "mount_options": "nodev,nosuid,noexec", "dry_run": false }
```
> Applies nodev, nosuid, noexec mount options to /tmp.

---

## Phase 7: Malware Defense Setup (~3 min)

### Step 7.1 — Update ClamAV Definitions
```json
Tool: malware
{ "action": "clamav_update" }
```
> Ensures ClamAV virus definitions are current.

### Step 7.2 — Full System Malware Scan
```json
Tool: malware
{ "action": "clamav_scan", "path": "/", "recursive": true, "move_to_quarantine": true }
```
> Scans entire system and quarantines any infected files found.

### Step 7.3 — Rootkit Scan & Clean
```json
Tool: integrity
{ "action": "rootkit_all", "update_first": true, "quick": false }
```
> Runs comprehensive rootkit scan with both rkhunter and chkrootkit.

---

## Phase 8: File Integrity Setup (~2 min)

### Step 8.1 — Create Post-Hardening Baseline
```json
Tool: integrity
{ "action": "baseline_create", "name": "post-hardening", "directories": ["/etc", "/usr/bin", "/usr/sbin"], "dryRun": false }
```
> Creates a new baseline after all hardening changes for future drift detection.

### Step 8.2 — Update AIDE Database
```json
Tool: integrity
{ "action": "aide_update", "dry_run": false }
```
> Updates AIDE database to reflect the hardened state.

### Step 8.3 — Hash Critical System Files
```json
Tool: integrity
{ "action": "file_integrity", "paths": "/etc/passwd,/etc/shadow,/etc/ssh/sshd_config,/etc/sudoers,/etc/pam.d/common-auth", "create_baseline": true }
```
> Creates SHA-256 baseline hashes of critical system files.

---

## Phase 9: Application Hardening (~5 min)

### Step 9.1 — Get Application Recommendations
```json
Tool: app_harden
{ "action": "recommend", "app_name": "sshd" }
```
> Gets hardening recommendations for SSH daemon.

### Step 9.2 — Apply Application Firewall Rules (SSH)
```json
Tool: app_harden
{ "action": "firewall", "app_name": "sshd", "dry_run": false }
```
> Applies application-specific firewall rules for SSH.

### Step 9.3 — Apply Systemd Sandboxing (SSH)
```json
Tool: app_harden
{ "action": "systemd", "app_name": "sshd", "dry_run": false }
```
> Applies systemd sandboxing for SSH service.

**Repeat Steps 9.1–9.3 for each detected application:**
- `nginx` (if web server)
- `postgresql` / `mysql` / `redis` / `mongodb` (if databases)
- `cups` (if printing)
- Other applications detected by `app_harden audit`

### Step 9.4 — WAF Rate Limiting Configuration
```json
Tool: waf_manage
{ "action": "rate_limit_config", "web_server": "nginx", "rate_limit": 10, "rate_limit_zone": "defense_limit" }
```
> Configures rate limiting for web server (if applicable).

---

## Phase 10: Container Hardening (~5 min)

> **Skip this phase if Docker is not installed.**

### Step 10.1 — Apply Docker Daemon Hardening
```json
Tool: container_docker
{ "action": "daemon", "daemon_action": "apply", "settings": { "icc": false, "live_restore": true, "no_new_privileges": true, "log_driver": "json-file", "log_max_size": "10m", "log_max_file": "3", "ip": "127.0.0.1" }, "dry_run": false }
```
> Applies Docker daemon security settings (disable ICC, enable live restore, restrict privileges).

### Step 10.2 — Enforce AppArmor Profiles
```json
Tool: container_isolation
{ "action": "apparmor_enforce", "profile": "docker-default", "dry_run": false }
```
> Sets Docker default AppArmor profile to enforce mode.

### Step 10.3 — Install AppArmor Utilities
```json
Tool: container_isolation
{ "action": "apparmor_install", "dry_run": false }
```
> Installs AppArmor utilities and additional profiles.

### Step 10.4 — Generate Seccomp Profile
```json
Tool: container_isolation
{ "action": "seccomp_profile", "profileName": "defense-hardened", "defaultAction": "SCMP_ACT_ERRNO", "outputPath": "/etc/docker/seccomp-defense.json", "dryRun": false }
```
> Generates a hardened seccomp profile for containers.

### Step 10.5 — Configure Rootless Docker
```json
Tool: container_isolation
{ "action": "rootless_setup", "username": "docker-user", "dryRun": false }
```
> Configures rootless container runtime for improved isolation.

---

## Phase 11: Network Defense Hardening (~3 min)

### Step 11.1 — Deploy Microsegmentation Rules
```json
Tool: zero_trust
{ "action": "microsegment", "service": "sshd", "allowPorts": [22], "allowSources": ["192.168.1.0/24"], "denyAll": true, "dryRun": false }
```
> Applies microsegmentation rules for SSH (restrict to LAN only).

**Repeat for each service that should be network-restricted:**
```json
Tool: zero_trust
{ "action": "microsegment", "service": "postgresql", "allowPorts": [5432], "allowSources": ["127.0.0.1"], "denyAll": true, "dryRun": false }
```
> Restricts database access to localhost only.

### Step 11.2 — Generate mTLS Certificates
```json
Tool: zero_trust
{ "action": "mtls", "commonName": "defense-mcp-ca", "serverCN": "server.local", "clientCN": "client.local", "validDays": 365, "dryRun": false }
```
> Generates mutual TLS certificates for service-to-service authentication.

### Step 11.3 — Block Malicious Domains
```json
Tool: dns_security
{ "action": "block_domains", "domains_to_block": ["malware.example.com", "phishing.example.com"] }
```
> Adds known malicious domains to /etc/hosts blocklist.
> **Note:** Populate with domains from threat intelligence feeds.

### Step 11.4 — Disable Unused Wireless Interfaces
```json
Tool: wireless_security
{ "action": "disable_unused" }
```
> Disables unused wireless interfaces and recommends kernel module blacklisting.

---

## Phase 12: Deception & Early Warning (~3 min)

### Step 12.1 — Deploy Credential Canary
```json
Tool: honeypot_manage
{ "action": "deploy_canary", "canary_type": "credential", "canary_path": "/opt/backup/.aws/credentials" }
```
> Deploys a fake AWS credentials file as a canary token.

### Step 12.2 — Deploy File Canary
```json
Tool: honeypot_manage
{ "action": "deploy_canary", "canary_type": "file", "canary_path": "/root/.ssh/id_rsa_backup" }
```
> Deploys a fake SSH key as a canary token.

### Step 12.3 — Deploy Directory Canary
```json
Tool: honeypot_manage
{ "action": "deploy_canary", "canary_type": "directory", "canary_path": "/opt/secrets" }
```
> Deploys a monitored directory as a canary.

### Step 12.4 — Deploy SSH Key Canary
```json
Tool: honeypot_manage
{ "action": "deploy_canary", "canary_type": "ssh_key", "canary_path": "/home/admin/.ssh/authorized_keys_backup" }
```
> Deploys a fake SSH authorized_keys file as a canary.

### Step 12.5 — Deploy Honeyport
```json
Tool: honeypot_manage
{ "action": "deploy_honeyport", "port": 8888 }
```
> Sets up a honeyport listener on port 8888 with iptables LOG rules.

---

## Phase 13: Threat Intelligence Integration (~2 min)

### Step 13.1 — Update Threat Feeds
```json
Tool: threat_intel
{ "action": "update_feeds", "feed_name": "abuse-ipdb", "feed_url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt" }
```
> Downloads threat intelligence feed for IP blocklisting.

### Step 13.2 — Apply IP Blocklist
```json
Tool: threat_intel
{ "action": "blocklist_apply", "blocklist_path": "/var/lib/defense-mcp/feeds/abuse-ipdb.txt", "apply_to": "iptables" }
```
> Applies threat intelligence blocklist to iptables.

---

## Phase 14: Runtime Security (~2 min)

> **Skip if Falco is not installed.**

### Step 14.1 — Deploy Falco Detection Rules
```json
Tool: ebpf
{ "action": "falco_deploy_rules", "ruleName": "defense-hardening", "ruleContent": "- rule: Detect Shell in Container\n  desc: Detect shell execution in containers\n  condition: container and spawned_process and proc.name in (bash, sh, zsh)\n  output: Shell spawned in container (user=%user.name command=%proc.cmdline container=%container.name)\n  priority: WARNING", "dryRun": false }
```
> Deploys custom Falco rules for runtime threat detection.

---

## Phase 15: Scheduled Audits (~3 min)

### Step 15.1 — Schedule Daily Lynis Audit
```json
Tool: defense_mgmt
{ "action": "scheduled_create", "name": "daily-lynis", "command": "lynis audit system", "schedule": "daily", "useSystemd": true, "dry_run": false }
```
> Creates a daily Lynis security audit via systemd timer.

### Step 15.2 — Schedule Weekly Rootkit Scan
```json
Tool: defense_mgmt
{ "action": "scheduled_create", "name": "weekly-rkhunter", "command": "rkhunter --check --skip-keypress", "schedule": "weekly", "useSystemd": true, "dry_run": false }
```
> Creates a weekly rootkit scan via systemd timer.

### Step 15.3 — Schedule Daily ClamAV Update
```json
Tool: defense_mgmt
{ "action": "scheduled_create", "name": "daily-freshclam", "command": "freshclam", "schedule": "daily", "useSystemd": true, "dry_run": false }
```
> Schedules daily ClamAV definition updates.

### Step 15.4 — Schedule Weekly AIDE Check
```json
Tool: defense_mgmt
{ "action": "scheduled_create", "name": "weekly-aide", "command": "aide --check", "schedule": "weekly", "useSystemd": true, "dry_run": false }
```
> Schedules weekly AIDE file integrity checks.

### Step 15.5 — Schedule Weekly ClamAV Scan
```json
Tool: defense_mgmt
{ "action": "scheduled_create", "name": "weekly-clamscan", "command": "clamscan -r /home", "schedule": "weekly", "useSystemd": true, "dry_run": false }
```
> Schedules weekly ClamAV scan of home directories.

---

## Phase 16: Auto-Remediation (~3 min)

### Step 16.1 — Generate Remediation Plan
```json
Tool: defense_mgmt
{ "action": "remediate_plan", "source": "all", "severity_filter": "low" }
```
> Generates a comprehensive remediation plan from all findings.

### Step 16.2 — Apply Safe Auto-Remediations
```json
Tool: defense_mgmt
{ "action": "remediate_apply", "source": "all", "severity_filter": "medium", "dry_run": false }
```
> Applies all safe auto-remediations (sysctl hardening, SSH fixes, etc.).

### Step 16.3 — Check Remediation Status
```json
Tool: defense_mgmt
{ "action": "remediate_status" }
```
> Verifies the status of the remediation session.

---

## Phase 17: Verification & Reporting (~5 min)

### Step 17.1 — Post-Hardening Security Posture Score
```json
Tool: defense_mgmt
{ "action": "posture_score" }
```
> Calculates security posture score after all hardening.

### Step 17.2 — Post-Hardening Posture Dashboard
```json
Tool: defense_mgmt
{ "action": "posture_dashboard" }
```
> Generates dashboard showing improvement from hardening.

### Step 17.3 — Post-Hardening Posture Trend
```json
Tool: defense_mgmt
{ "action": "posture_trend", "limit": 10 }
```
> Shows security posture trend over time (before vs after).

### Step 17.4 — Generate Hardening Status Report
```json
Tool: defense_mgmt
{ "action": "report_generate", "report_type": "hardening_status", "format": "markdown" }
```
> Generates a report focused on hardening changes made.

### Step 17.5 — Generate Technical Detail Report
```json
Tool: defense_mgmt
{ "action": "report_generate", "report_type": "technical_detail", "format": "markdown" }
```
> Generates comprehensive technical report of all changes.

### Step 17.6 — Generate Compliance Evidence Report
```json
Tool: defense_mgmt
{ "action": "report_generate", "report_type": "compliance_evidence", "format": "markdown" }
```
> Generates compliance evidence report for auditors.

### Step 17.7 — Review Change History
```json
Tool: defense_mgmt
{ "action": "change_history", "limit": 100 }
```
> Reviews complete audit trail of all changes made during hardening.

### Step 17.8 — Save Final Firewall Rules
```json
Tool: firewall
{ "action": "persist_save", "dry_run": false }
```
> Saves final firewall state to persist across reboots.

### Step 17.9 — Final Configuration Backup
```json
Tool: backup
{ "action": "config", "tag": "post-hardening", "dry_run": false }
```
> Creates a final backup of the hardened configuration.

### Step 17.10 — Final System State Snapshot
```json
Tool: backup
{ "action": "state", "dry_run": false }
```
> Captures final system state for comparison.

### Step 17.11 — Verify Backup Integrity
```json
Tool: backup
{ "action": "verify", "check_integrity": true }
```
> Verifies integrity of all backups created during the process.

### Step 17.12 — Drop Sudo Session
```json
Tool: sudo_session
{ "action": "drop" }
```
> Drops elevated privileges and zeros password buffer.

---

## Tool Coverage Summary

| # | Tool Name | Actions Used | Phase |
|---|-----------|-------------|-------|
| 1 | `sudo_session` | `elevate_gui`, `drop` | 0, 17 |
| 2 | `defense_mgmt` | `check_tools`, `install_optional_deps`, `scheduled_create`, `remediate_plan`, `remediate_apply`, `remediate_status`, `posture_score`, `posture_dashboard`, `posture_trend`, `report_generate`, `change_history` | 0, 15, 16, 17 |
| 3 | `backup` | `config`, `state`, `verify` | 0, 17 |
| 4 | `integrity` | `baseline_create`, `aide_init`, `aide_update`, `rootkit_all`, `file_integrity` | 0, 7, 8 |
| 5 | `harden_kernel` | `sysctl_set` (×14), `memory_enforce_aslr`, `bootloader_configure` | 1 |
| 6 | `harden_host` | `service_manage`, `permissions_fix`, `systemd_apply`, `umask_set`, `banner_set`, `usb_block_storage` | 2 |
| 7 | `access_control` | `ssh_harden`, `pam_configure`, `password_policy_set`, `restrict_shell`, `sudoers_manage` | 3 |
| 8 | `firewall` | `iptables_set_policy`, `iptables_add`, `persist_enable`, `persist_save` | 4, 17 |
| 9 | `log_management` | `auditd_cis_rules`, `auditd_rules`, `rotation_configure`, `fail2ban_reload` | 5 |
| 10 | `compliance` | `cron_restrict`, `tmp_harden` | 6 |
| 11 | `malware` | `clamav_update`, `clamav_scan` | 7 |
| 12 | `app_harden` | `recommend`, `firewall`, `systemd` | 9 |
| 13 | `waf_manage` | `rate_limit_config` | 9 |
| 14 | `container_docker` | `daemon` (apply) | 10 |
| 15 | `container_isolation` | `apparmor_enforce`, `apparmor_install`, `seccomp_profile`, `rootless_setup` | 10 |
| 16 | `zero_trust` | `microsegment`, `mtls` | 11 |
| 17 | `dns_security` | `block_domains` | 11 |
| 18 | `wireless_security` | `disable_unused` | 11 |
| 19 | `honeypot_manage` | `deploy_canary` (×4), `deploy_honeyport` | 12 |
| 20 | `threat_intel` | `update_feeds`, `blocklist_apply` | 13 |
| 21 | `ebpf` | `falco_deploy_rules` | 14 |

**Tools used in audit-only mode (from the Audit Workflow) that inform this workflow:**
| # | Tool Name | Role |
|---|-----------|------|
| 22 | `network_defense` | Audit findings drive firewall rules |
| 23 | `patch` | Audit findings drive update priorities |
| 24 | `vuln_manage` | Vulnerability scan drives remediation plan |
| 25 | `process_security` | Anomaly detection informs service hardening |
| 26 | `secrets` | Secret scan informs credential rotation |
| 27 | `supply_chain` | SBOM informs dependency management |
| 28 | `cloud_security` | Cloud detection informs IMDS hardening |
| 29 | `api_security` | API scan informs WAF/rate limiting |
| 30 | `crypto` | Certificate audit informs TLS hardening |
| 31 | `incident_response` | IOC scan validates clean state |

**Total: 31 tools utilized, 17 phases, 80+ hardening actions.**

---

## Rollback Procedures

If any hardening step causes issues:

### Rollback Auto-Remediations
```json
Tool: defense_mgmt
{ "action": "remediate_rollback", "session_id": "<session_id_from_remediate_apply>" }
```

### Restore Configuration Backup
```json
Tool: backup
{ "action": "restore", "backup_path": "<path_from_backup_list>", "dry_run": false }
```

### Compare Baseline Drift
```json
Tool: integrity
{ "action": "baseline_compare", "name": "pre-hardening" }
```
> Compares current state against the pre-hardening baseline to identify what changed.

---

## Execution Order Rationale

1. **Phase 0 (Setup)** — Backup everything first. No changes without a safety net.
2. **Phase 1 (Kernel)** — Kernel parameters are the foundation; harden first.
3. **Phase 2 (Host)** — Services and permissions build on kernel security.
4. **Phase 3 (Access)** — Authentication hardening after host is secured.
5. **Phase 4 (Firewall)** — Network perimeter after access controls are in place.
6. **Phase 5 (Logging)** — Enable monitoring before making more changes.
7. **Phase 6 (Compliance)** — CIS-specific hardening items.
8. **Phase 7 (Malware)** — Scan and clean before establishing integrity baselines.
9. **Phase 8 (Integrity)** — Establish baselines after system is clean and hardened.
10. **Phase 9 (Applications)** — Application-specific hardening.
11. **Phase 10 (Containers)** — Container isolation if Docker is present.
12. **Phase 11 (Network)** — Zero-trust and microsegmentation.
13. **Phase 12 (Deception)** — Deploy canaries as early warning system.
14. **Phase 13 (Threat Intel)** — Apply threat intelligence blocklists.
15. **Phase 14 (Runtime)** — Deploy runtime detection rules.
16. **Phase 15 (Scheduling)** — Set up ongoing automated audits.
17. **Phase 16 (Auto-Remediate)** — Catch any remaining findings.
18. **Phase 17 (Verify)** — Score, report, and backup the final state.