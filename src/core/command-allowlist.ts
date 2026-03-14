/**
 * Command Allowlist — security control that restricts which binaries the
 * MCP server may execute.
 *
 * Every command passed to `executeCommand()` (and the bypass modules that
 * use `execFileSync` / `spawn` directly) MUST be present in this allowlist.
 * Bare command names are resolved to absolute paths at startup, eliminating
 * PATH-manipulation attacks when running under sudo.
 *
 * Design constraints:
 *   - **No circular dependencies**: only imports from `node:fs` (no executor,
 *     no sudo-session, no tool-registry).
 *   - Uses `fs.existsSync` for path resolution — never shells out to `which`.
 *   - Candidate paths are checked in order; the first match wins.
 *   - Unresolvable binaries are logged as warnings but don't block startup
 *     (not every system has every tool installed).
 *
 * @module command-allowlist
 */

import { existsSync, lstatSync, type Stats } from "node:fs";
// INTENTIONAL EXCEPTION: This module uses execFileSync/execFile directly from node:child_process
// because the command allowlist must be initialized before spawn-safe.ts can function.
// spawn-safe.ts depends on this module for allowlist resolution, so routing through
// spawn-safe here would create a circular dependency. This is the only module (besides
// executor.ts) permitted to import child_process directly.
import { execFileSync, execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

// ── Types ────────────────────────────────────────────────────────────────────

export interface AllowlistEntry {
  /** Bare binary name, e.g. "iptables" */
  binary: string;
  /** Ordered candidate absolute paths on Linux */
  candidates: string[];
  /** Filled at startup after resolution; `undefined` if not found on disk */
  resolvedPath?: string;
  /** Which distro package should own this binary (for integrity verification) */
  expectedPackage?: string;
  /** Inode number recorded at startup for TOCTOU detection (CORE-007) */
  resolvedInode?: number;
}

/** Result of a binary ownership verification check */
export interface BinaryVerificationResult {
  binary: string;
  path: string;
  verified: boolean;
  owner?: string;
  message: string;
}

// ── Critical Binary Package Mappings ─────────────────────────────────────────

/**
 * Maps critical security binaries to their expected distro packages.
 * These are the binaries where integrity matters most — a trojanized binary
 * in any of these would undermine the entire defensive posture.
 */
const CRITICAL_BINARY_PACKAGES: Record<string, string[]> = {
  "iptables":        ["iptables"],
  "nft":             ["nftables"],
  "sysctl":          ["procps"],
  "lynis":           ["lynis"],
  "rkhunter":        ["rkhunter"],
  "chkrootkit":      ["chkrootkit"],
  "clamscan":        ["clamav"],
  "aide":            ["aide", "aide-common"],
  "auditctl":        ["auditd"],
  "fail2ban-client": ["fail2ban"],
  "sshd":            ["openssh-server"],
  "openssl":         ["openssl"],
  "gpg":             ["gnupg", "gnupg2", "gpg"],
  "sudo":            ["sudo"],
};

// ── The Allowlist ────────────────────────────────────────────────────────────

/**
 * Comprehensive mapping of every binary the MCP server may execute.
 *
 * Derived by scanning:
 *   - All `src/tools/*.ts` files for `command:` values passed to `executeCommand()`
 *   - `src/core/tool-dependencies.ts` for required/optional binaries
 *   - `src/core/auto-installer.ts` for direct `execFileSync` calls
 *   - `src/core/sudo-session.ts` and `src/core/privilege-manager.ts` for
 *     direct `spawn` / `execFileSync` calls
 */
const ALLOWLIST_DEFINITIONS: AllowlistEntry[] = [
  // ── Privilege / session management ──────────────────────────────────────
  { binary: "sudo",         candidates: ["/usr/bin/sudo", "/bin/sudo"] },
  { binary: "whoami",       candidates: ["/usr/bin/whoami", "/bin/whoami"] },
  { binary: "id",           candidates: ["/usr/bin/id", "/bin/id"] },
  { binary: "env",          candidates: ["/usr/bin/env", "/bin/env"] },

  // ── Firewall ───────────────────────────────────────────────────────────
  { binary: "iptables",          candidates: ["/usr/sbin/iptables", "/sbin/iptables"] },
  { binary: "ip6tables",         candidates: ["/usr/sbin/ip6tables", "/sbin/ip6tables"] },
  { binary: "iptables-save",     candidates: ["/usr/sbin/iptables-save", "/sbin/iptables-save"] },
  { binary: "ip6tables-save",    candidates: ["/usr/sbin/ip6tables-save", "/sbin/ip6tables-save"] },
  { binary: "iptables-restore",  candidates: ["/usr/sbin/iptables-restore", "/sbin/iptables-restore"] },
  { binary: "ip6tables-restore", candidates: ["/usr/sbin/ip6tables-restore", "/sbin/ip6tables-restore"] },
  { binary: "nft",               candidates: ["/usr/sbin/nft", "/sbin/nft"] },
  { binary: "ufw",               candidates: ["/usr/sbin/ufw", "/sbin/ufw"] },
  { binary: "netfilter-persistent", candidates: ["/usr/sbin/netfilter-persistent", "/sbin/netfilter-persistent"] },

  // ── Kernel / sysctl ────────────────────────────────────────────────────
  { binary: "sysctl",       candidates: ["/usr/sbin/sysctl", "/sbin/sysctl", "/usr/bin/sysctl"] },
  { binary: "lsmod",        candidates: ["/usr/sbin/lsmod", "/sbin/lsmod", "/usr/bin/lsmod", "/bin/lsmod"] },
  { binary: "modprobe",     candidates: ["/usr/sbin/modprobe", "/sbin/modprobe"] },

  // ── Systemd / services ─────────────────────────────────────────────────
  { binary: "systemctl",       candidates: ["/usr/bin/systemctl", "/bin/systemctl"] },
  { binary: "systemd-analyze", candidates: ["/usr/bin/systemd-analyze", "/bin/systemd-analyze"] },

  // ── Networking ─────────────────────────────────────────────────────────
  { binary: "ss",        candidates: ["/usr/bin/ss", "/bin/ss", "/usr/sbin/ss", "/sbin/ss"] },
  { binary: "ip",        candidates: ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"] },
  { binary: "nmap",      candidates: ["/usr/bin/nmap", "/usr/local/bin/nmap"] },
  { binary: "tcpdump",   candidates: ["/usr/bin/tcpdump", "/usr/sbin/tcpdump", "/sbin/tcpdump"] },
  { binary: "hostname",  candidates: ["/usr/bin/hostname", "/bin/hostname"] },
  { binary: "curl",      candidates: ["/usr/bin/curl", "/bin/curl"] },
  { binary: "wget",      candidates: ["/usr/bin/wget", "/bin/wget"] },

  // ── Logging / audit ────────────────────────────────────────────────────
  { binary: "journalctl",     candidates: ["/usr/bin/journalctl", "/bin/journalctl"] },
  { binary: "dmesg",          candidates: ["/usr/bin/dmesg", "/bin/dmesg"] },
  { binary: "auditctl",       candidates: ["/usr/sbin/auditctl", "/sbin/auditctl"] },
  { binary: "ausearch",       candidates: ["/usr/sbin/ausearch", "/sbin/ausearch"] },
  { binary: "aureport",       candidates: ["/usr/sbin/aureport", "/sbin/aureport"] },
  { binary: "fail2ban-client", candidates: ["/usr/bin/fail2ban-client", "/usr/local/bin/fail2ban-client"] },
  { binary: "logrotate",      candidates: ["/usr/sbin/logrotate", "/sbin/logrotate"] },

  // ── IDS / rootkit detection ────────────────────────────────────────────
  { binary: "aide",       candidates: ["/usr/bin/aide", "/usr/sbin/aide"] },
  { binary: "rkhunter",   candidates: ["/usr/bin/rkhunter", "/usr/local/bin/rkhunter"] },
  { binary: "chkrootkit", candidates: ["/usr/bin/chkrootkit", "/usr/sbin/chkrootkit", "/usr/local/bin/chkrootkit"] },

  // ── Malware scanning ──────────────────────────────────────────────────
  { binary: "clamscan",  candidates: ["/usr/bin/clamscan", "/usr/local/bin/clamscan"] },
  { binary: "freshclam", candidates: ["/usr/bin/freshclam", "/usr/local/bin/freshclam"] },
  { binary: "yara",      candidates: ["/usr/bin/yara", "/usr/local/bin/yara"] },

  // ── Compliance / audit frameworks ──────────────────────────────────────
  { binary: "lynis",  candidates: ["/usr/bin/lynis", "/usr/sbin/lynis", "/usr/local/bin/lynis"] },
  { binary: "oscap",  candidates: ["/usr/bin/oscap", "/usr/local/bin/oscap"] },
  { binary: "tiger",  candidates: ["/usr/bin/tiger", "/usr/sbin/tiger", "/usr/local/bin/tiger"] },

  // ── Container / sandboxing ─────────────────────────────────────────────
  { binary: "docker",               candidates: ["/usr/bin/docker", "/usr/local/bin/docker"] },
  { binary: "docker-bench-security", candidates: ["/usr/bin/docker-bench-security", "/usr/local/bin/docker-bench-security"] },
  { binary: "trivy",                candidates: ["/usr/bin/trivy", "/usr/local/bin/trivy"] },
  { binary: "grype",                candidates: ["/usr/bin/grype", "/usr/local/bin/grype"] },
  { binary: "apparmor_status",      candidates: ["/usr/sbin/apparmor_status", "/sbin/apparmor_status"] },
  { binary: "aa-status",            candidates: ["/usr/sbin/aa-status", "/sbin/aa-status"] },
  { binary: "aa-enabled",           candidates: ["/usr/sbin/aa-enabled", "/sbin/aa-enabled"] },
  { binary: "apparmor_parser",      candidates: ["/usr/sbin/apparmor_parser", "/sbin/apparmor_parser"] },
  { binary: "getenforce",           candidates: ["/usr/sbin/getenforce", "/sbin/getenforce"] },
  { binary: "setenforce",           candidates: ["/usr/sbin/setenforce", "/sbin/setenforce"] },
  { binary: "sestatus",             candidates: ["/usr/sbin/sestatus", "/sbin/sestatus"] },
  { binary: "getsebool",            candidates: ["/usr/sbin/getsebool", "/sbin/getsebool"] },
  { binary: "lsns",                 candidates: ["/usr/bin/lsns", "/bin/lsns"] },
  { binary: "newuidmap",            candidates: ["/usr/bin/newuidmap"] },
  { binary: "newgidmap",            candidates: ["/usr/bin/newgidmap"] },

  // ── Encryption / crypto ────────────────────────────────────────────────
  { binary: "openssl",    candidates: ["/usr/bin/openssl", "/bin/openssl"] },
  { binary: "gpg",        candidates: ["/usr/bin/gpg", "/bin/gpg"] },
  { binary: "gpg2",       candidates: ["/usr/bin/gpg2", "/bin/gpg2"] },
  { binary: "cryptsetup", candidates: ["/usr/sbin/cryptsetup", "/sbin/cryptsetup"] },

  // ── WireGuard / VPN ────────────────────────────────────────────────────
  { binary: "wg",        candidates: ["/usr/bin/wg", "/usr/local/bin/wg"] },
  { binary: "wireguard", candidates: ["/usr/bin/wireguard", "/usr/local/bin/wireguard"] },

  // ── SSH ────────────────────────────────────────────────────────────────
  { binary: "sshd",        candidates: ["/usr/sbin/sshd", "/sbin/sshd"] },
  { binary: "ssh",         candidates: ["/usr/bin/ssh", "/bin/ssh"] },
  { binary: "ssh-keygen",  candidates: ["/usr/bin/ssh-keygen", "/bin/ssh-keygen"] },
  { binary: "ssh-askpass", candidates: ["/usr/bin/ssh-askpass", "/usr/lib/ssh/x11-ssh-askpass"] },

  // ── User / access management ───────────────────────────────────────────
  { binary: "passwd",   candidates: ["/usr/bin/passwd", "/bin/passwd"] },
  { binary: "usermod",  candidates: ["/usr/sbin/usermod", "/sbin/usermod"] },
  { binary: "useradd",  candidates: ["/usr/sbin/useradd", "/sbin/useradd"] },
  { binary: "visudo",   candidates: ["/usr/sbin/visudo", "/sbin/visudo"] },
  { binary: "getent",   candidates: ["/usr/bin/getent", "/bin/getent"] },
  { binary: "chage",    candidates: ["/usr/bin/chage", "/bin/chage"] },
  { binary: "lastlog",  candidates: ["/usr/bin/lastlog", "/bin/lastlog"] },

  // ── Package managers ───────────────────────────────────────────────────
  { binary: "apt",       candidates: ["/usr/bin/apt"] },
  { binary: "apt-get",   candidates: ["/usr/bin/apt-get"] },
  { binary: "apt-cache", candidates: ["/usr/bin/apt-cache"] },
  { binary: "dpkg",      candidates: ["/usr/bin/dpkg", "/bin/dpkg"] },
  { binary: "dpkg-query", candidates: ["/usr/bin/dpkg-query"] },
  { binary: "debsums",   candidates: ["/usr/bin/debsums"] },
  { binary: "debsecan",  candidates: ["/usr/bin/debsecan"] },
  { binary: "rpm",       candidates: ["/usr/bin/rpm", "/bin/rpm"] },
  { binary: "dnf",       candidates: ["/usr/bin/dnf"] },
  { binary: "yum",       candidates: ["/usr/bin/yum"] },
  { binary: "pacman",    candidates: ["/usr/bin/pacman"] },
  { binary: "apk",       candidates: ["/sbin/apk", "/usr/sbin/apk"] },
  { binary: "zypper",    candidates: ["/usr/bin/zypper"] },
  { binary: "brew",      candidates: ["/usr/local/bin/brew", "/opt/homebrew/bin/brew", "/home/linuxbrew/.linuxbrew/bin/brew"] },
  { binary: "pip3",      candidates: ["/usr/bin/pip3", "/usr/local/bin/pip3"] },
  { binary: "pip",       candidates: ["/usr/bin/pip", "/usr/local/bin/pip"] },
  { binary: "npm",       candidates: ["/usr/bin/npm", "/usr/local/bin/npm"] },

  // ── Coreutils / standard POSIX ─────────────────────────────────────────
  { binary: "cat",       candidates: ["/usr/bin/cat", "/bin/cat"] },
  { binary: "ls",        candidates: ["/usr/bin/ls", "/bin/ls"] },
  { binary: "cp",        candidates: ["/usr/bin/cp", "/bin/cp"] },
  { binary: "rm",        candidates: ["/usr/bin/rm", "/bin/rm"] },
  { binary: "mv",        candidates: ["/usr/bin/mv", "/bin/mv"] },
  { binary: "mkdir",     candidates: ["/usr/bin/mkdir", "/bin/mkdir"] },
  { binary: "chmod",     candidates: ["/usr/bin/chmod", "/bin/chmod"] },
  { binary: "chown",     candidates: ["/usr/bin/chown", "/bin/chown"] },
  { binary: "chgrp",     candidates: ["/usr/bin/chgrp", "/bin/chgrp"] },
  { binary: "stat",      candidates: ["/usr/bin/stat", "/bin/stat"] },
  { binary: "head",      candidates: ["/usr/bin/head", "/bin/head"] },
  { binary: "tail",      candidates: ["/usr/bin/tail", "/bin/tail"] },
  { binary: "wc",        candidates: ["/usr/bin/wc", "/bin/wc"] },
  { binary: "tee",       candidates: ["/usr/bin/tee", "/bin/tee"] },
  { binary: "find",      candidates: ["/usr/bin/find", "/bin/find"] },
  { binary: "grep",      candidates: ["/usr/bin/grep", "/bin/grep"] },
  { binary: "zgrep",     candidates: ["/usr/bin/zgrep", "/bin/zgrep"] },
  { binary: "awk",       candidates: ["/usr/bin/awk", "/bin/awk", "/usr/bin/gawk", "/bin/gawk"] },
  { binary: "sed",       candidates: ["/usr/bin/sed", "/bin/sed"] },
  { binary: "test",      candidates: ["/usr/bin/test", "/bin/test"] },
  { binary: "df",        candidates: ["/usr/bin/df", "/bin/df"] },
  { binary: "mount",     candidates: ["/usr/bin/mount", "/bin/mount", "/sbin/mount"] },
  { binary: "findmnt",   candidates: ["/usr/bin/findmnt", "/bin/findmnt"] },
  { binary: "lsblk",     candidates: ["/usr/bin/lsblk", "/bin/lsblk"] },
  { binary: "file",      candidates: ["/usr/bin/file", "/bin/file"] },
  { binary: "uptime",    candidates: ["/usr/bin/uptime", "/bin/uptime"] },

  // ── Hashing / integrity ────────────────────────────────────────────────
  { binary: "sha256sum", candidates: ["/usr/bin/sha256sum", "/bin/sha256sum"] },
  { binary: "sha512sum", candidates: ["/usr/bin/sha512sum", "/bin/sha512sum"] },
  { binary: "md5sum",    candidates: ["/usr/bin/md5sum", "/bin/md5sum"] },

  // ── Process inspection ─────────────────────────────────────────────────
  { binary: "ps",     candidates: ["/usr/bin/ps", "/bin/ps"] },
  { binary: "pgrep",  candidates: ["/usr/bin/pgrep", "/bin/pgrep"] },
  { binary: "lsof",   candidates: ["/usr/bin/lsof", "/usr/sbin/lsof"] },

  // ── Boot / secure boot ─────────────────────────────────────────────────
  { binary: "mokutil",     candidates: ["/usr/bin/mokutil"] },
  { binary: "update-grub", candidates: ["/usr/sbin/update-grub", "/sbin/update-grub"] },

  // ── Python (for auto-installer verification) ───────────────────────────
  { binary: "python3", candidates: ["/usr/bin/python3", "/usr/local/bin/python3"] },
  { binary: "python",  candidates: ["/usr/bin/python", "/usr/local/bin/python"] },

  // ── Library verification (auto-installer) ──────────────────────────────
  { binary: "pkg-config", candidates: ["/usr/bin/pkg-config", "/usr/local/bin/pkg-config"] },
  { binary: "ldconfig",   candidates: ["/usr/sbin/ldconfig", "/sbin/ldconfig"] },
  { binary: "which",      candidates: ["/usr/bin/which", "/bin/which"] },

  // ── Binary analysis / memory protections ───────────────────────────────
  { binary: "readelf",  candidates: ["/usr/bin/readelf", "/bin/readelf"] },
  { binary: "checksec", candidates: ["/usr/bin/checksec", "/usr/local/bin/checksec"] },

  // ── Cron / scheduling ──────────────────────────────────────────────────
  { binary: "crontab", candidates: ["/usr/bin/crontab", "/bin/crontab"] },

  // ── Kernel live-patching ───────────────────────────────────────────────
  { binary: "uname",              candidates: ["/usr/bin/uname", "/bin/uname"] },
  { binary: "canonical-livepatch", candidates: ["/usr/bin/canonical-livepatch", "/snap/bin/canonical-livepatch"] },
  { binary: "kpatch",             candidates: ["/usr/sbin/kpatch", "/usr/bin/kpatch"] },
  { binary: "klp",                candidates: ["/usr/sbin/klp", "/usr/bin/klp"] },

  // ── Supply chain security ──────────────────────────────────────────────
  { binary: "cosign",        candidates: ["/usr/bin/cosign", "/usr/local/bin/cosign"] },
  { binary: "slsa-verifier", candidates: ["/usr/bin/slsa-verifier", "/usr/local/bin/slsa-verifier"] },
  { binary: "syft",          candidates: ["/usr/bin/syft", "/usr/local/bin/syft"] },
  { binary: "cdxgen",        candidates: ["/usr/bin/cdxgen", "/usr/local/bin/cdxgen"] },

  // ── Secrets scanners ───────────────────────────────────────────────────
  { binary: "trufflehog", candidates: ["/usr/bin/trufflehog", "/usr/local/bin/trufflehog"] },
  { binary: "gitleaks",   candidates: ["/usr/bin/gitleaks", "/usr/local/bin/gitleaks"] },
  { binary: "git",         candidates: ["/usr/bin/git", "/bin/git"] },

  // ── eBPF / runtime security ────────────────────────────────────────────
  { binary: "bpftool", candidates: ["/usr/sbin/bpftool", "/sbin/bpftool", "/usr/bin/bpftool"] },
  { binary: "falco",   candidates: ["/usr/bin/falco", "/usr/local/bin/falco"] },

  // ── IDS / network ──────────────────────────────────────────────────────
  { binary: "snort",    candidates: ["/usr/bin/snort", "/usr/sbin/snort", "/usr/local/bin/snort"] },
  { binary: "suricata", candidates: ["/usr/bin/suricata", "/usr/sbin/suricata"] },

  // ── macOS detection (distro.ts) ────────────────────────────────────────
  { binary: "sw_vers",     candidates: ["/usr/bin/sw_vers"] },
  { binary: "lsb_release", candidates: ["/usr/bin/lsb_release"] },

  // ── GUI askpass helpers (sudo-management.ts) ───────────────────────────
  { binary: "zenity",       candidates: ["/usr/bin/zenity"] },
  { binary: "kdialog",      candidates: ["/usr/bin/kdialog"] },
  { binary: "setsid",       candidates: ["/usr/bin/setsid", "/usr/sbin/setsid"] },
  { binary: "ksshaskpass",  candidates: ["/usr/bin/ksshaskpass"] },
  { binary: "lxqt-sudo",    candidates: ["/usr/bin/lxqt-sudo"] },

  // ── DNS security ───────────────────────────────────────────────────────
  { binary: "dig",             candidates: ["/usr/bin/dig", "/usr/local/bin/dig"] },
  { binary: "systemd-resolve", candidates: ["/usr/bin/systemd-resolve"] },
  { binary: "resolvectl",     candidates: ["/usr/bin/resolvectl"] },
  { binary: "whois",          candidates: ["/usr/bin/whois", "/bin/whois"] },

  // ── Vulnerability scanning ─────────────────────────────────────────────
  { binary: "nikto",         candidates: ["/usr/bin/nikto", "/usr/local/bin/nikto"] },
  { binary: "searchsploit",  candidates: ["/usr/bin/searchsploit", "/usr/local/bin/searchsploit"] },

  // ── Process security ───────────────────────────────────────────────────
  { binary: "getpcaps",      candidates: ["/usr/sbin/getpcaps", "/sbin/getpcaps", "/usr/bin/getpcaps"] },
  { binary: "capsh",         candidates: ["/usr/sbin/capsh", "/sbin/capsh", "/usr/bin/capsh"] },
  { binary: "systemd-cgls",  candidates: ["/usr/bin/systemd-cgls", "/bin/systemd-cgls"] },
  { binary: "systemd-cgtop", candidates: ["/usr/bin/systemd-cgtop", "/bin/systemd-cgtop"] },

  // ── WAF / web server ──────────────────────────────────────────────────
  { binary: "apache2ctl",    candidates: ["/usr/sbin/apache2ctl", "/sbin/apache2ctl"] },

  // ── Cloud security ────────────────────────────────────────────────────
  { binary: "cloud-init",    candidates: ["/usr/bin/cloud-init", "/usr/local/bin/cloud-init"] },
  { binary: "aws",           candidates: ["/usr/bin/aws", "/usr/local/bin/aws"] },
  { binary: "gsutil",        candidates: ["/usr/bin/gsutil", "/usr/local/bin/gsutil", "/snap/bin/gsutil"] },
  { binary: "az",            candidates: ["/usr/bin/az", "/usr/local/bin/az"] },

  // ── Deception / honeypots ─────────────────────────────────────────────
  { binary: "ncat",          candidates: ["/usr/bin/ncat", "/usr/local/bin/ncat"] },
  { binary: "inotifywait",   candidates: ["/usr/bin/inotifywait", "/usr/local/bin/inotifywait"] },

  // ── Wireless security ─────────────────────────────────────────────────
  { binary: "hciconfig",     candidates: ["/usr/bin/hciconfig", "/usr/sbin/hciconfig", "/bin/hciconfig"] },
  { binary: "bluetoothctl",  candidates: ["/usr/bin/bluetoothctl"] },
  { binary: "iwconfig",      candidates: ["/usr/sbin/iwconfig", "/sbin/iwconfig"] },
  { binary: "iw",            candidates: ["/usr/sbin/iw", "/sbin/iw", "/usr/bin/iw"] },
  { binary: "nmcli",         candidates: ["/usr/bin/nmcli"] },
  { binary: "rfkill",        candidates: ["/usr/sbin/rfkill", "/usr/bin/rfkill", "/sbin/rfkill"] },

  // ── SIEM integration ──────────────────────────────────────────────────
  { binary: "nc",            candidates: ["/usr/bin/nc", "/bin/nc", "/usr/bin/nc.openbsd", "/usr/bin/nc.traditional"] },
  { binary: "logger",        candidates: ["/usr/bin/logger", "/bin/logger"] },
  { binary: "filebeat",      candidates: ["/usr/bin/filebeat", "/usr/local/bin/filebeat"] },

  // ── Certificate lifecycle ─────────────────────────────────────────────
  { binary: "certbot",       candidates: ["/usr/bin/certbot", "/usr/local/bin/certbot", "/snap/bin/certbot"] },

  // ── Forensics / incident response ─────────────────────────────────────
  { binary: "avml",          candidates: ["/usr/bin/avml", "/usr/local/bin/avml"] },
  { binary: "dd",            candidates: ["/usr/bin/dd", "/bin/dd"] },
  { binary: "fdisk",         candidates: ["/usr/sbin/fdisk", "/sbin/fdisk"] },

  // ── Network segmentation ──────────────────────────────────────────────
  { binary: "traceroute",    candidates: ["/usr/bin/traceroute", "/usr/sbin/traceroute", "/bin/traceroute"] },
  { binary: "tracepath",     candidates: ["/usr/bin/tracepath", "/bin/tracepath"] },
  { binary: "bridge",        candidates: ["/usr/sbin/bridge", "/sbin/bridge"] },

  // ── USB device control ────────────────────────────────────────────────
  { binary: "lsusb",         candidates: ["/usr/bin/lsusb", "/bin/lsusb"] },
  { binary: "udevadm",       candidates: ["/usr/bin/udevadm", "/bin/udevadm", "/sbin/udevadm"] },

  // ── Reporting (optional conversion tools) ─────────────────────────────
  { binary: "pandoc",        candidates: ["/usr/bin/pandoc", "/usr/local/bin/pandoc"] },
  { binary: "wkhtmltopdf",   candidates: ["/usr/bin/wkhtmltopdf", "/usr/local/bin/wkhtmltopdf"] },

  // ── General utilities ─────────────────────────────────────────────────
  { binary: "sh",            candidates: ["/usr/bin/sh", "/bin/sh"] },
  { binary: "kill",          candidates: ["/usr/bin/kill", "/bin/kill"] },
];

// ── Module-level constants for resolveSudoCommand() (Opt 6) ──────────────────

/** Sudo flags that take NO argument */
const SUDO_FLAGS_NO_ARG = new Set([
  "-S", "-A", "-k", "-K", "-n", "-v", "-b", "-e", "-H", "-i", "-l", "-s",
  "--stdin", "--askpass", "--reset-timestamp", "--remove-timestamp",
  "--non-interactive", "--validate", "--background", "--edit",
  "--set-home", "--login", "--list", "--shell",
]);

/** Sudo flags that take an argument (the next token) */
const SUDO_FLAGS_WITH_ARG = new Set([
  "-p", "-u", "-g", "-C", "-T", "-r",
  "--prompt", "--user", "--group", "--close-from", "--command-timeout", "--role",
]);

// ── Internal state ───────────────────────────────────────────────────────────

/** O(1) lookup by bare binary name. */
const allowlistMap = new Map<string, AllowlistEntry>();

/** O(1) reverse lookup: absolute path → AllowlistEntry */
const reversePathMap = new Map<string, AllowlistEntry>();

/** Whether `initializeAllowlist()` has been called. */
let initialized = false;

/**
 * SECURITY (CORE-007): Whether to re-verify binary paths at execution time.
 * When enabled, resolveCommand() confirms that the binary at the resolved path
 * still exists as a regular file with the same inode as recorded at startup,
 * mitigating TOCTOU (time-of-check-time-of-use) attacks where a binary is
 * replaced between startup resolution and runtime execution.
 *
 * Configurable via DEFENSE_MCP_RUNTIME_PATH_VERIFY env var.
 * Default: true (verify at runtime). Set to "false" to disable for performance.
 */
let runtimePathVerification = process.env.DEFENSE_MCP_RUNTIME_PATH_VERIFY !== "false";

// Populate the map immediately so `isAllowlisted()` works before init
for (const entry of ALLOWLIST_DEFINITIONS) {
  allowlistMap.set(entry.binary, entry);
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Initialize the allowlist by resolving candidate paths on the current system.
 *
 * For each allowlisted binary, checks which candidate paths actually exist
 * on disk and caches the first match. This should be called once at server
 * startup, before any tool registration.
 *
 * Binaries that cannot be found are logged as warnings but do not prevent
 * startup — not every system has every tool installed.
 */
export function initializeAllowlist(): void {
  let resolved = 0;
  let unresolved = 0;

  // Clear reverse map for re-initialization
  reversePathMap.clear();

  // Re-read runtime path verification setting on re-init
  runtimePathVerification = process.env.DEFENSE_MCP_RUNTIME_PATH_VERIFY !== "false";

  for (const entry of ALLOWLIST_DEFINITIONS) {
    entry.resolvedPath = undefined;
    entry.resolvedInode = undefined;

    for (const candidate of entry.candidates) {
      if (existsSync(candidate)) {
        entry.resolvedPath = candidate;
        // SECURITY (CORE-007): Record inode at startup for TOCTOU detection
        try {
          const stats = lstatSync(candidate);
          entry.resolvedInode = stats.ino;
        } catch {
          // Best effort — inode recording is not critical
        }
        resolved++;
        break;
      }
    }

    if (!entry.resolvedPath) {
      unresolved++;
    }

    // Populate reverse path map for O(1) absolute-path lookups
    if (entry.resolvedPath) {
      reversePathMap.set(entry.resolvedPath, entry);
    }
    for (const candidate of entry.candidates) {
      if (existsSync(candidate)) {
        reversePathMap.set(candidate, entry);
      }
    }
  }

  initialized = true;
  console.error(
    `[command-allowlist] Initialized: ${resolved} binaries resolved, ` +
    `${unresolved} not found on this system (${ALLOWLIST_DEFINITIONS.length} total allowlisted)` +
    (runtimePathVerification ? " [runtime path verification ON]" : " [runtime path verification OFF]")
  );
}

/**
 * Resolve a bare command name to its absolute path via the allowlist.
 *
 * @param command - Bare binary name (e.g. `"iptables"`)
 * @returns The absolute path to the binary (e.g. `"/usr/sbin/iptables"`)
 * @throws {Error} If the command is not in the allowlist or cannot be found
 */
export function resolveCommand(command: string): string {
  // If the command is already an absolute path, use O(1) reverse lookup
  if (command.startsWith("/")) {
    if (reversePathMap.has(command)) {
      // SECURITY (CORE-007): Re-verify at runtime if enabled
      if (runtimePathVerification) {
        verifyBinaryPathAtRuntime(command, reversePathMap.get(command)!);
      }
      return command;
    }
    // Fallback: linear scan for paths not yet in the reverse map
    // (e.g., binaries installed after initializeAllowlist)
    for (const entry of ALLOWLIST_DEFINITIONS) {
      if (entry.candidates.includes(command) || entry.resolvedPath === command) {
        reversePathMap.set(command, entry); // cache for next time
        return command;
      }
    }
    throw new Error(
      `Command not in allowlist: ${command}. ` +
      `Only pre-approved security binaries may be executed.`
    );
  }

  const entry = allowlistMap.get(command);
  if (!entry) {
    throw new Error(
      `Command not in allowlist: ${command}. ` +
      `Only pre-approved security binaries may be executed.`
    );
  }

  // If already resolved (from initializeAllowlist), return cached path
  if (entry.resolvedPath) {
    // SECURITY (CORE-007): Re-verify at runtime if enabled
    if (runtimePathVerification) {
      verifyBinaryPathAtRuntime(entry.resolvedPath, entry);
    }
    return entry.resolvedPath;
  }

  // Lazy resolution: if initializeAllowlist() hasn't run or if the binary
  // was installed after startup, try resolving now
  for (const candidate of entry.candidates) {
    if (existsSync(candidate)) {
      entry.resolvedPath = candidate;
      return candidate;
    }
  }

  throw new Error(
    `Allowlisted command '${command}' not found on this system. ` +
    `Checked paths: ${entry.candidates.join(", ")}`
  );
}

/**
 * Check whether a bare command name is in the allowlist (without resolving).
 *
 * @param command - Bare binary name or absolute path
 * @returns `true` if the command is allowlisted
 */
export function isAllowlisted(command: string): boolean {
  if (command.startsWith("/")) {
    // O(1) reverse lookup first
    if (reversePathMap.has(command)) return true;
    // Fallback: linear scan for paths not in the reverse map
    for (const entry of ALLOWLIST_DEFINITIONS) {
      if (entry.candidates.includes(command) || entry.resolvedPath === command) {
        reversePathMap.set(command, entry); // cache for next time
        return true;
      }
    }
    return false;
  }
  return allowlistMap.has(command);
}

/**
 * Resolve a sudo command and its target binary.
 *
 * When `command` is `"sudo"`, this function:
 * 1. Resolves `sudo` itself to its absolute path
 * 2. Finds the actual binary in the args array (skipping sudo flags like `-S`, `-p`, `-A`, `-k`, `-n`, `-v`)
 * 3. Resolves that binary against the allowlist
 * 4. Returns the resolved sudo path, the index of the target binary in args, and its resolved path
 *
 * @param args - The args array passed to sudo
 * @returns Object with resolved paths and the index of the target command in args
 * @throws {Error} If sudo or the target command is not allowlisted
 */
export function resolveSudoCommand(args: string[]): {
  sudoPath: string;
  targetIndex: number;
  targetPath: string;
} {
  const sudoPath = resolveCommand("sudo");

  // Find the target command in args by skipping sudo flags
  // Uses module-level SUDO_FLAGS_NO_ARG / SUDO_FLAGS_WITH_ARG constants
  let targetIndex = -1;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    // Skip empty strings (like empty prompt "")
    if (arg === "") {
      continue;
    }

    // Skip known flags
    if (SUDO_FLAGS_NO_ARG.has(arg)) {
      continue;
    }

    if (SUDO_FLAGS_WITH_ARG.has(arg)) {
      // Skip the flag AND its argument
      i++;
      continue;
    }

    // If it starts with "-", it's an unknown flag — skip it
    if (arg.startsWith("-")) {
      continue;
    }

    // This is the target command
    targetIndex = i;
    break;
  }

  if (targetIndex === -1) {
    // No target command found (e.g., `sudo -v` or `sudo -k`)
    // These are sudo self-management commands, just return sudo
    return { sudoPath, targetIndex: -1, targetPath: "" };
  }

  const targetCmd = args[targetIndex];
  const targetPath = resolveCommand(targetCmd);

  return { sudoPath, targetIndex, targetPath };
}

/**
 * Returns the full allowlist for inspection/debugging.
 * Each entry includes resolution status.
 */
export function getAllowlistEntries(): ReadonlyArray<Readonly<AllowlistEntry>> {
  return ALLOWLIST_DEFINITIONS;
}

/**
 * Returns whether the allowlist has been initialized.
 */
export function isInitialized(): boolean {
  return initialized;
}

/**
 * Returns whether runtime path verification is currently enabled.
 */
export function isRuntimePathVerificationEnabled(): boolean {
  return runtimePathVerification;
}

/**
 * Enable or disable runtime path verification.
 * Useful for testing or performance-sensitive environments.
 */
export function setRuntimePathVerification(enabled: boolean): void {
  runtimePathVerification = enabled;
}

/**
 * SECURITY (CORE-007): Re-verify a binary path at execution time.
 *
 * Mitigates TOCTOU attacks where a binary resolved at startup could be
 * replaced before runtime execution. Checks:
 * 1. File still exists at the resolved path
 * 2. File is a regular file (not a symlink to something else)
 * 3. Inode matches what was recorded at startup (if available)
 *
 * @param binaryPath The absolute path to verify
 * @param entry The allowlist entry with startup inode data
 * @throws {Error} If the binary fails verification
 */
function verifyBinaryPathAtRuntime(binaryPath: string, entry: AllowlistEntry): void {
  try {
    const stats = lstatSync(binaryPath);

    // Must still be a regular file (not replaced with a symlink)
    if (!stats.isFile()) {
      throw new Error(
        `SECURITY: Binary '${binaryPath}' is no longer a regular file ` +
        `(may have been replaced with a symlink). Refusing to execute.`
      );
    }

    // If we recorded an inode at startup, verify it hasn't changed
    if (entry.resolvedInode !== undefined && stats.ino !== entry.resolvedInode) {
      throw new Error(
        `SECURITY: Binary '${binaryPath}' inode changed since startup ` +
        `(was ${entry.resolvedInode}, now ${stats.ino}). Binary may have been replaced. Refusing to execute.`
      );
    }
  } catch (err: unknown) {
    if (err instanceof Error && err.message.startsWith("SECURITY:")) {
      throw err; // Re-throw our own security errors
    }
    // File doesn't exist or can't be stat'd
    throw new Error(
      `SECURITY: Binary '${binaryPath}' could not be verified at runtime: ` +
      `${err instanceof Error ? err.message : String(err)}`
    );
  }
}

/**
 * Returns the critical binary package mappings for inspection/testing.
 */
export function getCriticalBinaryPackages(): Readonly<Record<string, string[]>> {
  return CRITICAL_BINARY_PACKAGES;
}

// ── Binary Integrity Verification ────────────────────────────────────────────

/**
 * Detect which package manager verification command is available.
 * Returns the command prefix to use, or null if none found.
 */
function detectPackageVerifier(): "dpkg" | "rpm" | "pacman" | null {
  if (existsSync("/usr/bin/dpkg") || existsSync("/bin/dpkg")) return "dpkg";
  if (existsSync("/usr/bin/rpm") || existsSync("/bin/rpm")) return "rpm";
  if (existsSync("/usr/bin/pacman")) return "pacman";
  return null;
}

/**
 * Verify that a resolved binary is owned by its expected system package.
 *
 * Uses `dpkg -S` on Debian/Ubuntu, `rpm -qf` on RHEL/Fedora,
 * or `pacman -Qo` on Arch to determine the owning package.
 *
 * @param binaryPath - Absolute path to the binary
 * @param expectedPackage - Optional expected package name; if omitted, only ownership is checked
 * @returns Verification result with owner info and status
 */
export function verifyBinaryOwnership(
  binaryPath: string,
  expectedPackage?: string,
): BinaryVerificationResult {
  const binary = binaryPath.split("/").pop() ?? binaryPath;

  if (!existsSync(binaryPath)) {
    return {
      binary,
      path: binaryPath,
      verified: false,
      message: `Binary not found at ${binaryPath}`,
    };
  }

  const verifier = detectPackageVerifier();
  if (!verifier) {
    return {
      binary,
      path: binaryPath,
      verified: false,
      message: "No package manager found for verification (need dpkg, rpm, or pacman)",
    };
  }

  try {
    let output: string;
    let ownerPackage: string;

    switch (verifier) {
      case "dpkg": {
        // dpkg -S /path/to/binary → "package-name: /path/to/binary"
        const dpkgPath = existsSync("/usr/bin/dpkg") ? "/usr/bin/dpkg" : "/bin/dpkg";
        output = execFileSync(dpkgPath, ["-S", binaryPath], {
          encoding: "utf-8",
          timeout: 10_000,
          stdio: ["pipe", "pipe", "pipe"],
        }).trim();
        // Parse "package:arch: /path" or "package: /path"
        const dpkgMatch = output.match(/^([^:]+?)(?::[^:]+)?:\s/);
        ownerPackage = dpkgMatch ? dpkgMatch[1].trim() : output.split(":")[0].trim();
        break;
      }
      case "rpm": {
        // rpm -qf /path/to/binary → "package-name-version-release.arch"
        const rpmPath = existsSync("/usr/bin/rpm") ? "/usr/bin/rpm" : "/bin/rpm";
        output = execFileSync(rpmPath, ["-qf", binaryPath], {
          encoding: "utf-8",
          timeout: 10_000,
          stdio: ["pipe", "pipe", "pipe"],
        }).trim();
        // Extract package name (strip version-release.arch)
        const rpmMatch = output.match(/^(.+?)-\d/);
        ownerPackage = rpmMatch ? rpmMatch[1] : output;
        break;
      }
      case "pacman": {
        // pacman -Qo /path/to/binary → "/path/to/binary is owned by package-name version"
        output = execFileSync("/usr/bin/pacman", ["-Qo", binaryPath], {
          encoding: "utf-8",
          timeout: 10_000,
          stdio: ["pipe", "pipe", "pipe"],
        }).trim();
        const pacmanMatch = output.match(/is owned by (\S+)/);
        ownerPackage = pacmanMatch ? pacmanMatch[1] : output;
        break;
      }
    }

    // If no expectedPackage specified, just report ownership
    if (!expectedPackage) {
      return {
        binary,
        path: binaryPath,
        verified: true,
        owner: ownerPackage,
        message: `Owned by package: ${ownerPackage}`,
      };
    }

    // Check if the owner matches one of the expected packages
    const expectedPackages = CRITICAL_BINARY_PACKAGES[binary] ?? [expectedPackage];
    const isExpected = expectedPackages.some((pkg) =>
      ownerPackage === pkg || ownerPackage.startsWith(`${pkg}:`)
    );

    if (isExpected) {
      return {
        binary,
        path: binaryPath,
        verified: true,
        owner: ownerPackage,
        message: `Verified: owned by expected package ${ownerPackage}`,
      };
    }

    return {
      binary,
      path: binaryPath,
      verified: false,
      owner: ownerPackage,
      message: `WARNING: owned by '${ownerPackage}', expected one of [${expectedPackages.join(", ")}]`,
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      binary,
      path: binaryPath,
      verified: false,
      message: `Verification failed: ${msg}`,
    };
  }
}

/**
 * Async version of binary ownership verification using execFile (non-blocking).
 * Used by the parallelized `verifyAllBinaries()`.
 */
async function verifyBinaryOwnershipAsync(
  binaryPath: string,
  expectedPackage?: string,
): Promise<BinaryVerificationResult> {
  const binary = binaryPath.split("/").pop() ?? binaryPath;

  if (!existsSync(binaryPath)) {
    return {
      binary,
      path: binaryPath,
      verified: false,
      message: `Binary not found at ${binaryPath}`,
    };
  }

  const verifier = detectPackageVerifier();
  if (!verifier) {
    return {
      binary,
      path: binaryPath,
      verified: false,
      message: "No package manager found for verification (need dpkg, rpm, or pacman)",
    };
  }

  try {
    let output: string;
    let ownerPackage: string;

    switch (verifier) {
      case "dpkg": {
        const dpkgPath = existsSync("/usr/bin/dpkg") ? "/usr/bin/dpkg" : "/bin/dpkg";
        const { stdout } = await execFileAsync(dpkgPath, ["-S", binaryPath], {
          encoding: "utf-8",
          timeout: 10_000,
        });
        output = stdout.trim();
        const dpkgMatch = output.match(/^([^:]+?)(?::[^:]+)?:\s/);
        ownerPackage = dpkgMatch ? dpkgMatch[1].trim() : output.split(":")[0].trim();
        break;
      }
      case "rpm": {
        const rpmPath = existsSync("/usr/bin/rpm") ? "/usr/bin/rpm" : "/bin/rpm";
        const { stdout } = await execFileAsync(rpmPath, ["-qf", binaryPath], {
          encoding: "utf-8",
          timeout: 10_000,
        });
        output = stdout.trim();
        const rpmMatch = output.match(/^(.+?)-\d/);
        ownerPackage = rpmMatch ? rpmMatch[1] : output;
        break;
      }
      case "pacman": {
        const { stdout } = await execFileAsync("/usr/bin/pacman", ["-Qo", binaryPath], {
          encoding: "utf-8",
          timeout: 10_000,
        });
        output = stdout.trim();
        const pacmanMatch = output.match(/is owned by (\S+)/);
        ownerPackage = pacmanMatch ? pacmanMatch[1] : output;
        break;
      }
    }

    if (!expectedPackage) {
      return {
        binary,
        path: binaryPath,
        verified: true,
        owner: ownerPackage,
        message: `Owned by package: ${ownerPackage}`,
      };
    }

    const expectedPackages = CRITICAL_BINARY_PACKAGES[binary] ?? [expectedPackage];
    const isExpected = expectedPackages.some((pkg) =>
      ownerPackage === pkg || ownerPackage.startsWith(`${pkg}:`)
    );

    if (isExpected) {
      return {
        binary,
        path: binaryPath,
        verified: true,
        owner: ownerPackage,
        message: `Verified: owned by expected package ${ownerPackage}`,
      };
    }

    return {
      binary,
      path: binaryPath,
      verified: false,
      owner: ownerPackage,
      message: `WARNING: owned by '${ownerPackage}', expected one of [${expectedPackages.join(", ")}]`,
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      binary,
      path: binaryPath,
      verified: false,
      message: `Verification failed: ${msg}`,
    };
  }
}

/**
 * Verify all resolved critical binaries against their expected packages.
 *
 * Runs after `initializeAllowlist()` and logs warnings for any binaries
 * that can't be verified or are owned by unexpected packages.
 *
 * All verifications run in parallel for faster startup.
 * This is best-effort — it never throws or blocks startup.
 *
 * @returns Array of verification results for all critical binaries that were resolved
 */
export async function verifyAllBinaries(): Promise<BinaryVerificationResult[]> {
  let skipped = 0;

  // Build list of verification tasks to run in parallel
  const tasks: Promise<BinaryVerificationResult>[] = [];

  for (const [binaryName, expectedPackages] of Object.entries(CRITICAL_BINARY_PACKAGES)) {
    const entry = allowlistMap.get(binaryName);
    if (!entry?.resolvedPath) {
      skipped++;
      continue; // Binary not found on system — nothing to verify
    }

    tasks.push(
      verifyBinaryOwnershipAsync(entry.resolvedPath, expectedPackages[0])
        .catch((): BinaryVerificationResult => ({
          binary: binaryName,
          path: entry.resolvedPath!,
          verified: false,
          message: `Verification failed unexpectedly`,
        }))
    );
  }

  // Run all verifications in parallel
  const results = await Promise.all(tasks);

  let verified = 0;
  let warnings = 0;

  for (const result of results) {
    if (result.verified) {
      verified++;
    } else {
      warnings++;
      console.error(`[binary-integrity] ⚠ ${result.message}`);
    }
  }

  console.error(
    `[binary-integrity] Checked ${results.length} critical binaries: ` +
    `${verified} verified, ${warnings} warnings, ${skipped} skipped (not installed)`
  );

  return results;
}
