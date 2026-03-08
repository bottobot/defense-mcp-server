# 🛡️ Full System Hardening Assessment Report

**Host:** `lildude` — Kali GNU/Linux Rolling 2025.4  
**Kernel:** Linux 6.18.9+kali-amd64 (SMP PREEMPT_DYNAMIC)  
**Assessment Date:** 2026-02-20  
**Assessed By:** Kali Defense MCP Server v1.0.0  
**Assessment Type:** READ-ONLY (No modifications made)  

---

## Executive Summary

This assessment evaluated the security posture of a Kali Linux workstation across 6 phases covering firewall configuration, kernel hardening, access control, user management, file integrity, and container security. The system is running a recent kernel (10 days old) and is fully patched, but has **significant hardening gaps** typical of a default Kali installation optimized for penetration testing rather than defense.

### Overall Security Grade: **D+ (42/100)**

| Category | Score | Grade | Weight |
|----------|-------|-------|--------|
| Firewall & Network | 15/100 | F | 20% |
| Kernel & Sysctl Hardening | 45/100 | D | 15% |
| SSH & Access Control | 55/100 | C- | 15% |
| User & Password Policy | 30/100 | F | 15% |
| File Permissions & Integrity | 70/100 | B- | 15% |
| Container & MAC Security | 50/100 | D | 20% |

---

## Critical Findings (Immediate Action Required)

### 🔴 C1: No Inbound Firewall Protection
- **Severity:** CRITICAL
- **Category:** Firewall
- **Detail:** iptables INPUT chain policy is `ACCEPT` with zero rules. UFW is not installed. Any service listening on `192.168.1.150` is directly accessible from the LAN.
- **Impact:** Full exposure of all network services to local network. Combined with qbittorrent listening on external interface (port 21853/TCP, 55667/UDP), any device on the network can reach these services.
- **Remediation:**
  ```bash
  # Install and configure UFW
  sudo apt install ufw
  sudo ufw default deny incoming
  sudo ufw default allow outgoing
  sudo ufw enable
  # Or use iptables directly via the MCP server's firewall_iptables_add tool
  ```

### 🔴 C2: Passwordless Root via kali-trusted Group
- **Severity:** CRITICAL
- **Category:** Access Control
- **Detail:** `/etc/sudoers.d/kali-grant-root` contains `%kali-trusted ALL=(ALL:ALL) NOPASSWD: ALL`. Any user in the `kali-trusted` group has unrestricted passwordless root access.
- **Impact:** Privilege escalation without authentication. If any process or user is added to this group, they gain full root access.
- **Remediation:**
  ```bash
  # Review group membership
  getent group kali-trusted
  # Remove NOPASSWD or restrict to specific commands
  sudo visudo -f /etc/sudoers.d/kali-grant-root
  ```

### 🔴 C3: Docker Socket Mounted in Portainer Container
- **Severity:** CRITICAL
- **Category:** Container Security
- **Detail:** Portainer container (`portainer/portainer-ce:lts`) has `/var/run/docker.sock` mounted, granting full Docker API access — equivalent to root on the host.
- **Impact:** Container escape. Any vulnerability in Portainer allows full host compromise.
- **Remediation:** Use Portainer Agent mode or restrict socket access via Docker socket proxy (e.g., `tecnativa/docker-socket-proxy`).

---

## High Severity Findings

### 🟠 H1: Network Sysctl Parameters at Insecure Defaults
- **Detail:** 8 of 16 network sysctl parameters fail CIS benchmarks:
  - `net.ipv4.conf.all.send_redirects = 1` (should be 0)
  - `net.ipv4.conf.default.accept_redirects = 1` (should be 0)
  - `net.ipv4.conf.all.secure_redirects = 1` (should be 0)
  - `net.ipv4.conf.all.log_martians = 0` (should be 1)
  - `net.ipv4.conf.all.rp_filter = 0` (should be 1)
  - IPv6: all.accept_redirects=1, all.accept_ra=1 (both should be 0)
- **Impact:** Susceptible to ICMP redirect attacks, IPv6 MITM, and source-routed packet attacks. Martian packets not logged.
- **Remediation:**
  ```bash
  # Create persistent hardening config
  sudo tee /etc/sysctl.d/99-hardening.conf << 'EOF'
  net.ipv4.conf.all.send_redirects = 0
  net.ipv4.conf.default.send_redirects = 0
  net.ipv4.conf.default.accept_redirects = 0
  net.ipv4.conf.all.secure_redirects = 0
  net.ipv4.conf.default.secure_redirects = 0
  net.ipv4.conf.all.log_martians = 1
  net.ipv4.conf.default.log_martians = 1
  net.ipv4.conf.all.rp_filter = 1
  net.ipv6.conf.all.accept_redirects = 0
  net.ipv6.conf.default.accept_redirects = 0
  net.ipv6.conf.all.accept_ra = 0
  net.ipv6.conf.default.accept_ra = 0
  kernel.kptr_restrict = 1
  kernel.yama.ptrace_scope = 1
  EOF
  sudo sysctl -p /etc/sysctl.d/99-hardening.conf
  ```

### 🟠 H2: No Password Complexity or Expiry Enforcement
- **Detail:** 
  - `PASS_MAX_DAYS = 99999` (never expires)
  - `PASS_MIN_DAYS = 0` (can change immediately)
  - No `pam_pwquality` or `pam_cracklib` module configured
  - User `robert` password never expires
- **Impact:** Passwords can be weak and never need changing. No protection against brute force at the policy level.
- **Remediation:**
  ```bash
  sudo apt install libpam-pwquality
  # Edit /etc/login.defs: PASS_MAX_DAYS 365, PASS_MIN_DAYS 1
  # Edit /etc/pam.d/common-password to add pam_pwquality
  ```

### 🟠 H3: Kernel Pointer and Ptrace Exposure
- **Detail:**
  - `kernel.kptr_restrict = 0` — kernel pointer addresses visible to all users
  - `kernel.yama.ptrace_scope = 0` — any process can ptrace any other
- **Impact:** Aids exploit development (kptr_restrict) and allows process injection/debugging (ptrace). An attacker with local access can read kernel addresses and attach to other users' processes.
- **Remediation:** Included in the sysctl config above.

### 🟠 H4: Legacy SUID rsh Binaries
- **Detail:** `rsh-redone-rlogin` and `rsh-redone-rsh` are SUID root binaries.
- **Impact:** These are legacy remote shell tools with known security vulnerabilities. As SUID binaries, they are potential privilege escalation vectors.
- **Remediation:**
  ```bash
  sudo apt remove rsh-redone-client
  ```

---

## Medium Severity Findings

### 🟡 M1: IP Forwarding Enabled
- `net.ipv4.ip_forward = 1` — Expected for Docker but allows the host to route packets between interfaces. If not needed for Docker, disable.

### 🟡 M2: /tmp Missing noexec Mount Option
- `/tmp` is mounted as tmpfs with `nosuid,nodev` but lacks `noexec`. Attackers can download and execute binaries from `/tmp`. CIS Level 1 requires `noexec` on `/tmp`.
- **Remediation:** Add `noexec` to `/tmp` mount in `/etc/fstab` or via `mount -o remount,noexec /tmp`.

### 🟡 M3: 3 Service Accounts with Interactive Shells
- `cntlm` (UID 104), `arpwatch` (UID 117), `postgres` (UID 128) have `/bin/sh` or `/bin/bash` shells instead of `/usr/sbin/nologin`.
- **Remediation:** `sudo usermod -s /usr/sbin/nologin cntlm arpwatch postgres`

### 🟡 M4: No Docker User Namespace Remapping
- Docker containers run as root in the host's user namespace. Enabling `userns-remap` provides an additional isolation layer.
- **Remediation:** Configure `"userns-remap": "default"` in `/etc/docker/daemon.json`.

### 🟡 M5: Only Docker AppArmor Profile Loaded
- Only `docker-default` AppArmor profile is active. No profiles for host services (sshd, exim4, etc.).
- **Remediation:** Install `apparmor-profiles` and `apparmor-profiles-extra` packages.

### 🟡 M6: 3 Containers Mount /home/robert Read-Write
- MCP filesystem containers and supercorp/supergateway mount the home directory with full read-write access.
- **Remediation:** Scope mounts to specific subdirectories or use read-only mounts where possible.

### 🟡 M7: SysRq Key Broadly Enabled
- `kernel.sysrq = 438` enables most SysRq functions. While useful for debugging, it can be used for privilege escalation.
- **Remediation:** Set `kernel.sysrq = 4` (only enable sync) or `0` to disable.

### 🟡 M8: No Persistent Sysctl Hardening
- No `/etc/sysctl.conf` found. Only Kali default tweaks in `/etc/sysctl.d/`. Any runtime sysctl changes won't survive reboot.

---

## Low Severity Findings

### 🟢 L1: sshd_config and crontab World-Readable (644)
- CIS recommends 600 for both files to prevent information disclosure. Not critical since SSH daemon is inactive.

### 🟢 L2: SSH Config Mostly at Defaults
- SSH daemon is **disabled** (not running), which is good. However, if enabled in the future, it lacks hardening: PasswordAuthentication defaults to yes, X11Forwarding is yes, no AllowUsers/Banner set.

### 🟢 L3: High System Load (5.63)
- CPU load is elevated, likely from Docker containers and qbittorrent. Monitor for resource exhaustion.

### 🟢 L4: 5 Failed sudo Attempts in 24h
- All from local user `robert` — likely mistyped passwords. No remote brute force detected.

### 🟢 L5: 11 Kismet SUID Binaries
- Expected on Kali for wireless capture but represents a broad SUID surface. Consider using Linux capabilities (`setcap`) instead.

---

## Positive Findings ✅

| Finding | Detail |
|---------|--------|
| System fully patched | No pending updates, kernel 10 days old |
| OpenSnitch running | Application-level outbound firewall active |
| SSH daemon disabled | Reduces remote attack surface |
| Only root has UID 0 | No unauthorized root-level accounts |
| No empty passwords | All accounts have password hashes or are locked |
| No world-writable system files | Clean in /etc, /usr, /var |
| No SUID files in /tmp or /home | No planted privilege escalation |
| No hidden executables in /tmp | Clean temporary directory |
| No orphaned files | All files properly owned |
| AppArmor + seccomp for Docker | Container security baseline active |
| Docker socket properly restricted | 660 root:docker permissions |
| No privileged containers | All containers run without --privileged |
| ASLR fully enabled | kernel.randomize_va_space = 2 |
| dmesg restricted | kernel.dmesg_restrict = 1 |
| Filesystem protections | hardlinks, symlinks, fifos, regular all protected |
| TCP SynCookies enabled | Protection against SYN flood attacks |
| rsyslog + journald active | System logging operational |

---

## Remediation Priority Matrix

| Priority | Finding | Effort | Impact |
|----------|---------|--------|--------|
| **P0 — Now** | C1: Install UFW / configure iptables | 5 min | Eliminates network exposure |
| **P0 — Now** | C2: Review/restrict kali-trusted NOPASSWD | 5 min | Eliminates auth bypass |
| **P0 — Now** | C3: Replace Portainer docker.sock mount | 15 min | Eliminates container escape |
| **P1 — Today** | H1: Apply sysctl hardening config | 5 min | Hardens network stack |
| **P1 — Today** | H4: Remove rsh-redone-client | 1 min | Removes SUID risk |
| **P1 — Today** | H3: Set kptr_restrict=1, ptrace_scope=1 | Included in H1 | Hardens kernel |
| **P2 — This Week** | H2: Install pam_pwquality, set expiry | 10 min | Enforces password policy |
| **P2 — This Week** | M2: Add noexec to /tmp | 5 min | Prevents /tmp execution |
| **P2 — This Week** | M3: Fix service account shells | 2 min | Removes login vector |
| **P3 — This Month** | M4: Docker userns-remap | 15 min | Adds container isolation |
| **P3 — This Month** | M5: Install AppArmor profiles | 5 min | Hardens host services |
| **P3 — This Month** | M6: Restrict container volume mounts | 15 min | Reduces data exposure |

---

## Assessment Methodology

This assessment was conducted using the **Kali Defense MCP Server v1.0.0** (69 defensive security tools) implementing checks equivalent to:

| Tool/Standard | Checks Performed |
|--------------|-----------------|
| CIS Benchmark Level 1 | Filesystem, services, network, logging, access, system |
| NIST 800-53 | AC, AU, CM, IA, SC control families |
| Lynis categories | Kernel, firewall, authentication, SSH, file permissions |
| Docker CIS Benchmark | Daemon config, container flags, socket permissions, AppArmor |

### Phases Executed:
1. **Security Posture Overview** — Firewall, ports, services, updates, logins
2. **Sysctl & Kernel Hardening** — 35 parameters across network/kernel/IPv6/filesystem
3. **SSH & Access Control** — sshd_config, sudoers, sudoers.d
4. **User & Password Policy** — Account audit, password aging, PAM, expiry
5. **File Permissions & Integrity** — Critical files, SUID/SGID, world-writable, /tmp mounts, cron
6. **Container & MAC Security** — Docker audit, AppArmor, namespace isolation, suspicious files

---

*Report generated by Kali Defense MCP Server — the ultimate defensive security and system hardening MCP server for Linux.*
