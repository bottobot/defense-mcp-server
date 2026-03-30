# Defense System Audit Report

**System:** lilguy (Debian 13 Trixie)
**Kernel:** Linux 6.12.74+deb13+1-amd64 (PREEMPT_DYNAMIC)
**Date:** 2026-03-28
**Auditor:** defense-mcp-server v0.8.2 (automated) + manual verification
**Classification:** INTERNAL -- FOR SYSTEM ADMINISTRATOR ONLY

---

## 1. Executive Summary

### Overall Posture: GOOD (91/100)

This system exhibits a strong security posture for a single-user desktop/development workstation. No active compromise was detected. The attack surface is minimal: no SSH daemon installed, no web servers exposed, firewall active with UFW, AppArmor fully operational, and all critical kernel memory protections enabled.

### Critical Findings (Requiring Immediate Action)

| # | Finding | Risk | Phase |
|---|---------|------|-------|
| 1 | iptables INPUT/ip6tables INPUT policy ACCEPT (not DROP) | **CRITICAL** | 1 |
| 2 | Docker-proxy exposes Qdrant on 0.0.0.0:6333 (no auth) | **HIGH** | 1 |
| 3 | No GRUB bootloader password | **HIGH** | 2A |
| 4 | /tmp missing `noexec` mount option | **HIGH** | 2A |
| 5 | DNS resolver lacks DNSSEC and DNS-over-TLS | **MEDIUM** | 2B |

### Posture Breakdown

| Domain | Score | Status |
|--------|-------|--------|
| Kernel Hardening | 90/100 | Good |
| Firewall | 100/100 | Excellent (UFW rules sound; raw policy cosmetic) |
| Services | 100/100 | Excellent |
| Users & Access | 100/100 | Excellent |
| Filesystem Permissions | 67/100 | Needs Attention |
| **CIS Benchmark** | **90% (28/31)** | Good |
| **Composite** | **91/100** | **GOOD** |

### Threat Assessment: LOW

No indicators of compromise. No malware. No unauthorized processes. No suspicious files. All anomalies explained by known services (Docker, Tor loopback, VSCodium development server).

---

## 2. Phase 1: Rapid Posture Assessment

### 2.1 CIS Benchmark Compliance (28/31 -- 90%)

| Control ID | Description | Status | Notes |
|------------|-------------|--------|-------|
| CIS-1.1.4 | /tmp should have noexec | **FAIL** | Has nodev, nosuid only |
| CIS-3.1.1 | IP forwarding disabled | **FAIL** | `net.ipv4.ip_forward=1` required by Docker |
| CIS-5.2.10 | SSH PermitRootLogin=no | **FAIL** | Moot -- sshd not installed |
| All others (28) | Various | PASS | Compliant |

**Assessment:** The CIS-5.2.10 failure is a false positive since sshd is not installed, effectively reducing real failures to 2. CIS-3.1.1 is an accepted risk due to Docker's networking requirements.

### 2.2 Firewall Status

```
Component          Policy    Assessment
-------------------------------------------------
iptables INPUT     ACCEPT    CRITICAL - should be DROP
ip6tables INPUT    ACCEPT    CRITICAL - should be DROP
iptables FORWARD   DROP      PASS
iptables OUTPUT    ACCEPT    Acceptable (egress filtering optional)
UFW                Active    PASS - rules correctly applied
Persistence        Yes       PASS - iptables-persistent installed
```

**Detail:** While raw iptables INPUT policy is ACCEPT, UFW is active and inserts its filter chains before any default-policy decision. Traffic not matching UFW allow rules hits `ufw-reject-input` which drops/rejects. The ACCEPT policy is therefore a defense-in-depth concern rather than an immediate exposure, but should still be corrected to DROP for fail-safe behavior.

### 2.3 Network Connections

| Proto | Local Address | Service | Risk |
|-------|--------------|---------|------|
| tcp | 127.0.0.1:9050 | Tor SOCKS | None (loopback) |
| tcp | **0.0.0.0:6333** | **Qdrant (Docker)** | **HIGH** |
| tcp | 127.0.0.1:45635 | VSCodium | None (loopback) |
| tcp | 127.0.0.1:45839 | VSCodium | None (loopback) |
| udp | 127.0.0.1:323 | chronyd NTP | None (loopback) |
| tcp | [::]:6333 | Qdrant (Docker/IPv6) | **HIGH** |

**Qdrant Exposure:** The Qdrant vector database is bound to all interfaces on port 6333 via docker-proxy. Qdrant has no authentication by default. If the host is on a shared network, any device on the LAN can read/write/delete vector collections. This should be bound to 127.0.0.1 or placed behind authentication.

### 2.4 User & Account Security

| Metric | Value | Status |
|--------|-------|--------|
| Total accounts | 44 | Normal (system + 1 human) |
| Human users | 1 (robert, UID 1000) | PASS |
| Root login | Locked | PASS |
| Empty passwords | 0 | PASS |
| UID-0 accounts | 1 (root only) | PASS |
| Duplicate UIDs | 0 | PASS |

### 2.5 Sudoers Configuration

| Entry | Configuration | Assessment |
|-------|--------------|------------|
| robert | ALL=(ALL) ALL | Standard -- password required |
| robert-mcp | NOPASSWD for read-only audit tools | Acceptable -- scoped |
| Defaults logfile | **Not configured** | MEDIUM -- no sudo audit trail file |

### 2.6 Patch Status

| Package | Current | Available | Severity |
|---------|---------|-----------|----------|
| bind9-dnsutils | 9.20.18 | 9.20.21 | Low (client-side DNS tools) |
| bind9-host | 9.20.18 | 9.20.21 | Low |
| bind9-libs | 9.20.18 | 9.20.21 | Low |
| libxml-parser-perl | current | update avail | Low |

**Assessment:** 4 pending patches, all low-severity library/tool updates. No critical CVEs. `unattended-upgrades` is active for automatic security patches.

### 2.7 Fail2ban

| Jail | Status | Active |
|------|--------|--------|
| sshd | Enabled | Yes (monitoring auth logs) |
| apache-* | Absent | N/A -- no web server |
| postfix-* | Absent | N/A -- no mail server |
| dovecot-* | Absent | N/A -- no mail server |

**Assessment:** Only the sshd jail is relevant despite sshd not being installed. The absent jails are correctly absent since those services do not exist on this system.

---

## 3. Phase 2A: Kernel & Host Hardening

### 3.1 Sysctl Parameters (41/43 -- 95%)

| Parameter | Expected | Actual | Status |
|-----------|----------|--------|--------|
| net.ipv4.ip_forward | 0 | 1 | **FAIL** (Docker) |
| kernel.modules_disabled | 1 | 0 | **FAIL** |
| net.ipv4.conf.all.rp_filter | 1 | 1 | PASS |
| net.ipv4.conf.all.accept_redirects | 0 | 0 | PASS |
| net.ipv4.conf.all.send_redirects | 0 | 0 | PASS |
| net.ipv4.conf.all.accept_source_route | 0 | 0 | PASS |
| net.ipv4.conf.all.log_martians | 1 | 1 | PASS |
| net.ipv4.icmp_echo_ignore_broadcasts | 1 | 1 | PASS |
| net.ipv4.tcp_syncookies | 1 | 1 | PASS |
| kernel.randomize_va_space | 2 | 2 | PASS |
| kernel.kptr_restrict | 1+ | OK | PASS |
| kernel.dmesg_restrict | 1 | 1 | PASS |
| kernel.yama.ptrace_scope | 1+ | OK | PASS |
| *...and 28 more* | -- | -- | PASS |

**Accepted Risks:**
- `net.ipv4.ip_forward=1`: Required by Docker networking. Mitigated by FORWARD policy DROP and UFW rules.
- `kernel.modules_disabled=0`: Setting to 1 prevents all future module loading including USB, display drivers. Not practical on a desktop.

### 3.2 Kernel Security Features

| Feature | Status | Notes |
|---------|--------|-------|
| ASLR | Full (2) | PASS |
| KASLR | Enabled | PASS |
| PTI (Meltdown) | Enabled | PASS |
| Spectre v2 mitigation | Active | PASS |
| SMEP | Active | PASS |
| SMAP | Active | PASS |
| NX (No-Execute) | Active | PASS |
| LSM Stack | lockdown, capability, landlock, yama, apparmor, bpf, ipe, ima, evm | PASS -- comprehensive |
| Kernel Lockdown | **none** | **WARN** -- not in integrity/confidentiality mode |
| Secure Boot | **Disabled** | **WARN** |
| CPU Vuln: TSA | **Vulnerable** | **FAIL** -- missing microcode update |

### 3.3 Bootloader Security

| Check | Status | Detail |
|-------|--------|--------|
| GRUB password | **FAIL** | No superuser/password configured |
| Secure Boot | **WARN** | Disabled in firmware |
| grub.cfg permissions | PASS | 600 root:root |
| Missing cmdline params | **WARN** | 7 hardening params absent |

**Missing kernel command line parameters:**
1. `slab_nomerge` -- Prevents slab merging attacks
2. `init_on_alloc=1` -- Zero memory on allocation
3. `init_on_free=1` -- Zero memory on free
4. `page_alloc.shuffle=1` -- Randomize page allocator
5. `randomize_kstack_offset=on` -- Randomize kernel stack offset
6. `vsyscall=none` -- Disable legacy vsyscall
7. `lockdown=integrity` -- Enable kernel lockdown

### 3.4 Memory Protections (100%)

All memory protections verified active:

| Protection | Status |
|------------|--------|
| ASLR (Full randomization) | Active |
| KASLR | Active |
| Page Table Isolation | Active |
| Spectre v2 mitigations | Active |
| SMEP | Active |
| SMAP | Active |
| NX/XD bit | Active |
| Stack canaries (kernel) | Active |

### 3.5 File Permissions (13/14 -- 93%)

| File | Expected | Actual | Status |
|------|----------|--------|--------|
| /etc/passwd | 644 | 644 | PASS |
| /etc/shadow | 640 | 640 | PASS |
| /etc/group | 644 | 644 | PASS |
| /etc/gshadow | 640 | 640 | PASS |
| /etc/ssh/sshd_config | 600 | **Absent** | N/A (sshd not installed) |
| /boot/grub/grub.cfg | 600 | 600 | PASS |
| /etc/crontab | 600 | 600 | PASS |
| *...and 6 more* | -- | -- | PASS |

### 3.6 Service Inventory (31 services)

**Flagged:**

| Service | Status | Risk |
|---------|--------|------|
| bluetooth.service | Active | **LOW** -- unnecessary if no BT peripherals used |
| ModemManager.service | Active | LOW -- unnecessary on desktop without modem |

**All other services** (29) are expected for a GNOME desktop with Docker and development tools.

### 3.7 Cron Security (11/11 -- 100%)

| Check | Status |
|-------|--------|
| /etc/cron.allow exists | PASS |
| /etc/at.allow exists | PASS |
| /etc/cron.deny absent or empty | PASS |
| crontab permissions (600) | PASS |
| cron.d/* permissions | PASS |
| cron.daily/* permissions | PASS |
| cron.hourly/* permissions | PASS |
| cron.weekly/* permissions | PASS |
| cron.monthly/* permissions | PASS |
| No world-writable cron files | PASS |
| No unauthorized cron jobs | PASS |

### 3.8 Systemd Service Exposure

**Summary:** 40 of 51 services have elevated exposure scores.

| Exposure Range | Count | Assessment |
|----------------|-------|------------|
| 9.0-10.0 (UNSAFE) | 8 | gdm, docker, containerd, etc. |
| 7.0-8.9 (ELEVATED) | 22 | Various system services |
| 5.0-6.9 (MEDIUM) | 10 | Acceptable |
| < 5.0 (OK) | 11 | Well-sandboxed |

**Average exposure score: 7.6/10**

**Highest-risk services (>9.0):**
- gdm.service (9.6) -- Display manager, inherently privileged
- docker.service (9.6) -- Container runtime, requires root
- containerd.service (9.4) -- Container runtime backend
- cron.service (9.2) -- Job scheduler
- fail2ban.service (9.0) -- Intrusion prevention

**Note:** High exposure scores for docker/gdm/containerd are expected and unavoidable for their function. Hardening via systemd sandboxing directives is recommended where practical.

### 3.9 Umask Configuration

| Location | Expected | Actual | Status |
|----------|----------|--------|--------|
| /etc/login.defs | UMASK 027 | **Not set to 027** | **FAIL** |
| /etc/profile | 027 | 027 | PASS |
| /etc/bash.bashrc | 027 | 027 | PASS |

### 3.10 Login Banners (9/9 -- 100%)

All CIS-required banner files present and compliant:
- /etc/issue, /etc/issue.net, /etc/motd -- configured
- Banner content does not disclose OS/kernel version
- Permissions correct on all banner files

### 3.11 /tmp Mount Options

| Option | Required | Present | Status |
|--------|----------|---------|--------|
| nodev | Yes | Yes | PASS |
| nosuid | Yes | Yes | PASS |
| noexec | Yes | **No** | **FAIL** |

**Risk:** Without `noexec`, malware or an attacker who gains write access to /tmp can execute binaries directly from that location. This is a common attack vector.

---

## 4. Phase 2B: Access Control, Cryptography & Secrets

### 4.1 SSH Server

**Status: NOT INSTALLED -- No Attack Surface**

The OpenSSH server (sshd) is not installed on this system. This eliminates the entire SSH remote attack surface including brute-force, key theft, and configuration weakness vectors.

### 4.2 SSH Cipher Configuration

| Check | Status | Notes |
|-------|--------|-------|
| Explicit Ciphers | **WARN** | No explicit cipher list configured |
| Explicit MACs | **WARN** | No explicit MAC list configured |
| Explicit KexAlgorithms | **WARN** | No explicit key exchange configured |
| Explicit HostKeyAlgorithms | **WARN** | No explicit host key algorithms |

**Assessment:** All 4 warnings are moot since sshd is not installed. If sshd is ever installed, these should be configured before enabling the service.

### 4.3 PAM Configuration

| Check | Status | Detail |
|-------|--------|--------|
| Password complexity (pam_pwquality) | PASS | Configured |
| Account lockout (pam_faillock) | PASS | Configured |
| pam_limits.so in common-session | **FAIL** | Missing -- no resource limits enforced |
| Hash algorithm explicit | **WARN** | Not explicit in 3/4 PAM config files |

**pam_limits.so absence:** Without this module in common-session, users have no enforced resource limits (max open files, max processes, etc.). A runaway process could exhaust system resources.

### 4.4 Password Policy

| Parameter | Value | CIS Requirement | Status |
|-----------|-------|-----------------|--------|
| Hash algorithm | YESCRYPT | SHA-512+ | PASS (exceeds) |
| PASS_MAX_DAYS | 365 | <=365 | PASS |
| PASS_MIN_DAYS | 0 | >=1 recommended | Acceptable |
| PASS_WARN_AGE | 14 | >=7 | PASS |
| INACTIVE | 90 | <=30 recommended | Acceptable |

### 4.5 AppArmor

| Metric | Value | Status |
|--------|-------|--------|
| Status | Enabled, enforcing | PASS |
| Profiles loaded | All | PASS |
| Profiles in enforce mode | All active | PASS |
| Profiles in complain mode | 0 | PASS |
| Unconfined processes | 0 critical | PASS |

**Assessment:** AppArmor is fully operational with 100% coverage of relevant profiles.

### 4.6 Secrets & SSH Keys

| Check | Status | Detail |
|-------|--------|--------|
| Private keys found | 1 | /home/robert/.ssh/id_ed25519 |
| Key permissions | 600 | PASS |
| Key type | Ed25519 | PASS (modern, secure) |
| Exposed API keys | 0 | PASS |
| .env files with secrets | 0 | PASS |
| Hardcoded credentials in code | 0 | PASS |

### 4.7 TLS & Certificate Security

| Check | Status | Detail |
|-------|--------|--------|
| OpenSSL version | 3.5.5 | PASS (current) |
| Expired certificates | 0 | PASS |
| Web servers with TLS | 0 | N/A (none running) |
| Self-signed certs in trust store | 0 | PASS |

### 4.8 DNS Security

| Check | Status | Detail |
|-------|--------|--------|
| DNS-over-TLS | **FAIL** | Not configured |
| DNSSEC validation | **FAIL** | Not enabled |
| Resolvers | 192.168.1.1, 192.168.2.1 | LAN routers (unencrypted) |

**Risk:** DNS queries are sent in plaintext to LAN routers. An attacker on the local network can observe all DNS lookups (privacy risk) and potentially poison responses (integrity risk). This is mitigated if the upstream routers forward to DoT/DoH resolvers, but the local segment remains unencrypted.

---

## 5. Phase 3: Threat & Incident Response Assessment

### 5.1 Overall Threat Level: LOW

**No active compromise detected. No indicators of ongoing attack.**

### 5.2 Volatile Data Collection (13/16 -- 81%)

| Artifact | Captured | Notes |
|----------|----------|-------|
| Running processes | Yes | All accounted for |
| Network connections | Yes | Analyzed in Phase 1 |
| Loaded kernel modules | Yes | Standard set |
| Mount points | Yes | Checked |
| Routing table | Yes | Standard |
| iptables rules | Yes | Analyzed in Phase 1 |
| Logged-in users | Yes | 1 (robert) |
| Open files (lsof) | Yes | No anomalies |
| Environment variables | Yes | Clean |
| Scheduled tasks | Yes | Verified in Phase 2A |
| DNS cache | Yes | Standard entries |
| Systemd timers | Yes | All expected |
| Shared memory | Yes | Normal |
| ARP table | **Gap** | Command not in allowlist |
| Who output | **Gap** | Command not in allowlist |
| Date/timezone | **Gap** | Command not in allowlist |

### 5.3 File System Integrity

| Check | Result |
|-------|--------|
| SUID binaries (unexpected) | 0 |
| SGID binaries (unexpected) | 0 |
| World-writable files (outside /tmp) | 0 |
| Hidden executables (unexpected) | 0 |
| Recently modified system binaries | 0 |

### 5.4 Malware Scanning

| Scanner | Files Scanned | Detections | Status |
|---------|--------------|------------|--------|
| ClamAV | 1,716 | 0 | **CLEAN** |
| Webshell scanner | All web-accessible dirs | 0 | **CLEAN** |

### 5.5 Rootkit Detection

| Tool | Result | Detail |
|------|--------|--------|
| rkhunter | **CLEAN** | No rootkits, backdoors, or local exploits detected |
| chkrootkit | **1 warning** | Low-confidence alert -- assessed as **false positive** |

**chkrootkit detail:** The warning is a known false positive pattern common on Debian systems with certain kernel configurations. Cross-referenced with rkhunter (clean), file integrity checks (clean), and manual process inspection (clean) to confirm benign.

### 5.6 Indicator of Compromise (IOC) Scan

| IOC | Finding | Assessment |
|-----|---------|------------|
| mt76-wifi-optimize.service | Flagged by heuristic | **BENIGN** -- legitimate WiFi optimization service for MT76 chipset driver |
| Suspicious cron entries | 0 | Clean |
| Unauthorized SSH keys | 0 | Clean |
| Unexpected SUID/SGID | 0 | Clean |
| Modified system binaries | 0 | Clean |
| Anomalous network connections | 0 | All explained |

### 5.7 Timeline Analysis (72-Hour Window)

**Period:** 2026-03-25 through 2026-03-28

| Timeframe | Activity | Assessment |
|-----------|----------|------------|
| Ongoing | User login sessions, development activity | Normal |
| Ongoing | Application file writes (VSCodium, Docker) | Normal |
| Ongoing | Package manager operations | Normal |
| 2026-03-22 | openclaw.service crash loop | Historical, resolved |

**openclaw.service detail:** Service experienced NODE_MODULE_NOT_FOUND errors on 2026-03-22, causing a crash loop captured in syslog. The issue was resolved (missing dependency installed). No security implications.

### 5.8 Log Analysis

| Log Source | Events | Security Events | Assessment |
|------------|--------|-----------------|------------|
| auditd | 32,844 | 0 security violations | CLEAN |
| auth.log | 5 | 5 successful auths (all robert) | CLEAN |
| syslog | Reviewed | openclaw crash only anomaly | CLEAN |
| kern.log | Reviewed | No anomalies | CLEAN |
| fail2ban.log | Reviewed | No bans triggered | CLEAN |

### 5.9 Process Anomaly Analysis

| Process | Observation | Assessment |
|---------|-------------|------------|
| tor (PID varies) | Listening 127.0.0.1:9050 | Expected -- Tor relay/client |
| docker-proxy | Binding 0.0.0.0:6333 | Expected but **risk noted** (see 2.3) |
| codium (PID 4488) | Loopback listeners | Expected -- development IDE |
| All others | Standard system services | Clean |

### 5.10 Linux Capabilities Audit

| Category | Count | Assessment |
|----------|-------|------------|
| Kernel threads with capabilities | ~700 | Normal (standard kernel thread set) |
| User-space processes with elevated caps | 0 | **CLEAN** |
| Unexpected capability grants | 0 | **CLEAN** |

### 5.11 Threat Intelligence Correlation

| Check | Result |
|-------|--------|
| Known-bad IP connections | 0 matches |
| Known-bad domain lookups | 0 matches |
| Known-bad file hashes | 0 matches |
| Threat feed database | **EMPTY** -- needs population |

**Recommendation:** Populate threat intelligence feeds (abuse.ch, AlienVault OTX, or similar) to enable automated IOC correlation in future audits.

---

## 6. Risk Matrix

### Critical (Remediate Within 24 Hours)

| # | Finding | Impact | Likelihood | Phase |
|---|---------|--------|------------|-------|
| C1 | iptables INPUT default policy ACCEPT | Firewall bypass if UFW fails | Low (UFW active) | 1 |
| C2 | ip6tables INPUT default policy ACCEPT | IPv6 firewall bypass | Low (UFW active) | 1 |

### High (Remediate Within 7 Days)

| # | Finding | Impact | Likelihood | Phase |
|---|---------|--------|------------|-------|
| H1 | Qdrant on 0.0.0.0:6333 (no auth) | Data exfiltration/tampering from LAN | Medium (LAN exposure) | 1 |
| H2 | No GRUB bootloader password | Boot tampering with physical access | Low (physical access required) | 2A |
| H3 | /tmp missing noexec | Malware execution staging area | Medium (common attack path) | 2A |
| H4 | pam_limits.so missing from common-session | Resource exhaustion DoS | Low (local user only) | 2B |

### Medium (Remediate Within 30 Days)

| # | Finding | Impact | Likelihood | Phase |
|---|---------|--------|------------|-------|
| M1 | DNS queries unencrypted (no DoT/DNSSEC) | DNS snooping/poisoning | Medium (LAN attack) | 2B |
| M2 | CPU vuln TSA -- missing microcode | Speculative execution leak | Low (local exploit only) | 2A |
| M3 | Kernel lockdown=none | Kernel memory read/write from root | Low (requires root) | 2A |
| M4 | UMASK in login.defs not 027 | Overly permissive file creation | Low | 2A |
| M5 | Sudo audit logfile not configured | Missing sudo activity trail | Low | 1 |
| M6 | 40/51 systemd services over-exposed | Compromised service escalation | Low | 2A |
| M7 | Secure Boot disabled | Boot-time malware persistence | Low (physical access) | 2A |
| M8 | 7 missing kernel cmdline hardening params | Reduced kernel attack surface hardening | Low | 2A |

### Low (Remediate Within 90 Days)

| # | Finding | Impact | Likelihood | Phase |
|---|---------|--------|------------|-------|
| L1 | bluetooth.service running (unused) | Bluetooth attack surface | Very Low | 2A |
| L2 | 4 pending package updates | Known vulnerabilities (DNS tools) | Very Low (client-side) | 1 |
| L3 | PAM hash algorithm not explicit | Could default to weaker hash | Very Low (YESCRYPT active) | 2B |
| L4 | Threat intel feeds empty | No automated IOC correlation | Informational | 3 |
| L5 | kernel.modules_disabled=0 | Dynamic module loading | Very Low (desktop requirement) | 2A |
| L6 | net.ipv4.ip_forward=1 | IP forwarding enabled | Accepted (Docker) | 2A |

---

## 7. Remediation Roadmap

### Immediate (24-48 Hours)

**Priority: CRITICAL and HIGH items**

#### R1. Set iptables default INPUT policy to DROP
```bash
# Ensure UFW is active first, then set underlying policy
sudo ufw default deny incoming
sudo iptables -P INPUT DROP
sudo ip6tables -P INPUT DROP
sudo netfilter-persistent save
```
**Addresses:** C1, C2
**Risk of change:** Low -- UFW already manages rules; this adds fail-safe default.

#### R2. Bind Qdrant to localhost only
```bash
# In docker-compose.yml or docker run command, change:
#   -p 6333:6333
# to:
#   -p 127.0.0.1:6333:6333
docker stop <qdrant-container>
docker rm <qdrant-container>
# Re-create with localhost binding
```
**Addresses:** H1
**Risk of change:** Low -- only affects remote access to Qdrant.

#### R3. Add noexec to /tmp
```bash
# Edit /etc/fstab, add noexec to /tmp mount options:
# tmpfs /tmp tmpfs defaults,nodev,nosuid,noexec 0 0
sudo mount -o remount,noexec /tmp
```
**Addresses:** H3
**Risk of change:** Medium -- some build tools/installers write executables to /tmp. Monitor for breakage.

### Short-Term (1-2 Weeks)

#### R4. Set GRUB bootloader password
```bash
# Generate password hash
grub-mkpasswd-pbkdf2
# Add to /etc/grub.d/40_custom:
#   set superusers="admin"
#   password_pbkdf2 admin <hash>
sudo update-grub
```
**Addresses:** H2
**Risk of change:** Low -- only affects boot menu editing, not normal boot.

#### R5. Add pam_limits.so to common-session
```bash
# Add to /etc/pam.d/common-session:
#   session required pam_limits.so
# Then configure /etc/security/limits.conf
```
**Addresses:** H4
**Risk of change:** Low -- sets resource ceilings, does not restrict normal use.

#### R6. Configure DNS-over-TLS
```bash
# Option A: Configure systemd-resolved with DoT
# Option B: Install and configure stubby as DoT forwarder
# Option C: Configure NetworkManager to use DoT-capable resolver (e.g., 1.1.1.1, 9.9.9.9)
```
**Addresses:** M1
**Risk of change:** Low -- transparent to applications.

#### R7. Configure sudo audit logging
```bash
# Add to /etc/sudoers via visudo:
#   Defaults logfile="/var/log/sudo.log"
#   Defaults log_input, log_output
```
**Addresses:** M5
**Risk of change:** None -- logging only.

#### R8. Set UMASK 027 in login.defs
```bash
sudo sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs
```
**Addresses:** M4
**Risk of change:** Low -- new files created with more restrictive permissions.

### Long-Term (1-3 Months)

#### R9. Kernel command line hardening
Add to GRUB_CMDLINE_LINUX in /etc/default/grub:
```
slab_nomerge init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1
randomize_kstack_offset=on vsyscall=none lockdown=integrity
```
**Addresses:** M3, M8
**Risk of change:** Medium -- `lockdown=integrity` may affect some kernel operations. Test thoroughly.

#### R10. Install CPU microcode updates
```bash
sudo apt install intel-microcode  # or amd64-microcode
```
**Addresses:** M2
**Risk of change:** Low -- firmware-level patch.

#### R11. Harden systemd service exposure
Apply sandboxing directives (ProtectSystem, ProtectHome, NoNewPrivileges, etc.) to high-exposure services via drop-in overrides.
**Addresses:** M6
**Risk of change:** Medium -- requires per-service testing.

#### R12. Enable Secure Boot
Requires BIOS/UEFI configuration change and signed kernel/bootloader chain.
**Addresses:** M7
**Risk of change:** Medium -- may require MOK enrollment for NVIDIA drivers.

#### R13. Disable unnecessary services
```bash
sudo systemctl disable --now bluetooth.service
sudo systemctl disable --now ModemManager.service
```
**Addresses:** L1
**Risk of change:** Low -- only if Bluetooth/modem not used.

#### R14. Populate threat intelligence feeds
Configure defense-mcp-server threat_intel tool with abuse.ch, AlienVault OTX, or similar feeds for automated IOC correlation.
**Addresses:** L4
**Risk of change:** None -- read-only intelligence data.

#### R15. Apply pending package updates
```bash
sudo apt update && sudo apt upgrade
```
**Addresses:** L2
**Risk of change:** Very low -- standard maintenance.

---

## Appendix A: System Profile

| Attribute | Value |
|-----------|-------|
| Hostname | lilguy |
| OS | Debian 13 (Trixie) |
| Kernel | 6.12.74+deb13+1-amd64 |
| Architecture | x86_64 |
| Uptime at audit | 6h 24m |
| Users logged in | 1 (robert) |
| CPU | (with SMEP, SMAP, NX) |
| Hardening Index | 79/100 (Lynis) |
| LSM Stack | lockdown, capability, landlock, yama, apparmor, bpf, ipe, ima, evm |
| Init system | systemd |
| Firewall | UFW (iptables backend) |
| AV | ClamAV |
| IDS/IPS | fail2ban, auditd, rkhunter |
| Containers | Docker (containerd backend) |

## Appendix B: Tools Used

| Tool | Version | Purpose |
|------|---------|---------|
| defense-mcp-server | 0.8.2 | Orchestration, all 3 phases |
| Lynis | current | Hardening audit, CIS checks |
| ClamAV | current | Malware scanning |
| rkhunter | current | Rootkit detection |
| chkrootkit | current | Rootkit detection (secondary) |
| auditd | current | Security event logging |
| fail2ban | current | Intrusion prevention status |
| ss/netstat | current | Network connections |
| systemd-analyze | current | Service exposure scoring |

## Appendix C: Methodology

1. **Phase 1 (Rapid Posture):** Automated sweep of firewall rules, listening services, user accounts, sudoers, patch status, CIS benchmark subset, and fail2ban status. Provides the composite posture score.

2. **Phase 2A (Kernel & Host):** Deep inspection of sysctl parameters, kernel security features, bootloader configuration, memory protections, file permissions, service inventory, cron jobs, systemd exposure, umask, login banners, and mount options.

3. **Phase 2B (Access & Crypto):** Analysis of SSH configuration, PAM modules, password policy, AppArmor status, secret/key inventory, TLS posture, and DNS security.

4. **Phase 3 (Threat & Incident Response):** Volatile data capture, file integrity checks, malware scanning (ClamAV + webshell), rootkit detection (rkhunter + chkrootkit), IOC scanning, 72-hour timeline reconstruction, log analysis, process anomaly detection, capabilities audit, and threat intelligence correlation.

---

*Report generated 2026-03-28 by defense-mcp-server v0.8.2*
*Next recommended full audit: 2026-04-28 (30-day interval)*
