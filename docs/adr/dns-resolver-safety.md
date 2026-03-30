# ADR: DNS Resolver Change Safety Protocol

## Status: Accepted

## Date: 2026-03-30

## Context

During remediation of audit findings M-15 (DNS over TLS) and M-16 (DNSSEC validation), the agent installed `systemd-resolved` on a Debian 13 workstation that was using NetworkManager for DNS resolution via OPNsense gateway (192.168.1.1).

### What Happened

1. The workstation used NetworkManager to manage DNS, with `/etc/resolv.conf` pointing to the OPNsense gateway at 192.168.1.1
2. `systemd-resolved` was **not** installed — DNS was handled entirely by NetworkManager
3. The agent ran `sudo apt-get install -y systemd-resolved` to enable DoT and DNSSEC
4. The Debian postinst script for `systemd-resolved` **immediately** converted `/etc/resolv.conf` from a regular file to a symlink pointing to `/run/systemd/resolve/stub-resolv.conf`
5. The `systemd-resolved` service was not yet configured with the correct upstream DNS (192.168.1.1), so it had no working nameservers
6. **DNS resolution broke instantly** — all internet connectivity was lost
7. The agent could no longer communicate with MCP servers, download packages, or continue remediation
8. Manual user intervention was required to restore DNS

### Root Cause

The Debian `systemd-resolved` package's postinst script performs a destructive, immediate action: it replaces `/etc/resolv.conf` with a symlink **before** the service is configured or started. This is a known Debian behavior but is not safe to trigger without preparation.

### Impact

- **Severity**: Critical — complete loss of DNS resolution and internet connectivity
- **Duration**: Required manual user intervention to restore
- **Blast radius**: All network-dependent operations on the workstation

## Decision

### NEVER modify the DNS resolver stack on this workstation

DNS resolution is handled by the **OPNsense gateway** at 192.168.1.1. DNS security features (DoT, DNSSEC) should be configured at the **gateway level**, not on the workstation.

### Mandatory Rules

1. **NEVER install `systemd-resolved`** on a system using NetworkManager for DNS unless the full migration procedure is followed (see below)
2. **NEVER modify `/etc/resolv.conf`** directly — it is managed by NetworkManager
3. **NEVER install packages that replace the DNS resolver** without first:
   a. Saving a known-good `/etc/resolv.conf` backup
   b. Pre-configuring the new resolver with the correct upstream DNS
   c. Verifying DNS works after the change
   d. Having a tested rollback command ready
4. **DNS security (DoT/DNSSEC) should be configured on OPNsense**, not the workstation:
   - OPNsense Unbound → Enable "Use System Nameservers over TLS" for DoT
   - OPNsense Unbound → Enable "DNSSEC" validation
   - Verify from workstation: `dig +dnssec example.com @192.168.1.1`

### Safe Migration Procedure (if ever needed in the future)

If there is ever a legitimate need to install `systemd-resolved` locally:

```bash
# 1. Back up resolv.conf
sudo cp /etc/resolv.conf /etc/resolv.conf.pre-resolved

# 2. Pre-configure resolved BEFORE installing
sudo mkdir -p /etc/systemd/resolved.conf.d
cat <<EOF | sudo tee /etc/systemd/resolved.conf.d/local.conf
[Resolve]
DNS=192.168.1.1
FallbackDNS=8.8.8.8 1.1.1.1
Domains=~.
DNSOverTLS=opportunistic
DNSSEC=allow-downgrade
EOF

# 3. Install the package (postinst will symlink resolv.conf)
sudo apt-get install -y systemd-resolved

# 4. Start and enable the service
sudo systemctl enable --now systemd-resolved

# 5. Verify DNS works
dig +short google.com
resolvectl status

# 6. If DNS is broken, immediately rollback:
sudo systemctl stop systemd-resolved
sudo rm /etc/resolv.conf
sudo cp /etc/resolv.conf.pre-resolved /etc/resolv.conf
sudo systemctl restart NetworkManager
sudo apt-get purge -y systemd-resolved libnss-resolve
```

### Rollback Command (emergency)

If DNS breaks due to resolver changes:
```bash
sudo rm -f /etc/resolv.conf
echo -e "nameserver 192.168.1.1\nnameserver 8.8.8.8" | sudo tee /etc/resolv.conf
sudo systemctl restart NetworkManager
```

## Consequences

- DNS security (DoT, DNSSEC) will be configured on the OPNsense gateway, not locally
- The workstation trusts its gateway for DNS security — this is the correct architecture for a managed network
- Any future DNS resolver changes require following the safe migration procedure above
- The IT-ops rules, diagnostic patterns, and remediation workflow have been updated with this safety rule
