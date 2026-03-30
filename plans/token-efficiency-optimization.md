# Token Efficiency Optimization Plan

## Context7 Validation Summary

All key technical assumptions have been validated against authoritative documentation:

| Assumption | Validated Via | Result |
|-----------|--------------|--------|
| Zod `.describe()` maps to JSON Schema `description` | zod-to-json-schema docs, Zod v3 docs | ✅ Confirmed |
| Zod `.default()` maps to JSON Schema `default` | MCP SDK source (`zod-json-schema-compat.js` line 27-30) | ✅ Confirmed |
| MCP SDK uses `zodToJsonSchema()` from `zod-to-json-schema` | SDK source `dist/esm/server/zod-json-schema-compat.js` line 8 | ✅ Confirmed |
| `tools/list` response includes full JSON Schema with descriptions | SDK source `dist/esm/server/mcp.js` lines 67-87 | ✅ Confirmed |
| Roo Code injects full JSON Schema into system prompt | Observed in this conversation's system prompt | ✅ Confirmed |
| Rules files are aggregated (global + workspace) | Roo Code docs: "both global and workspace rule directories are aggregated" | ✅ Confirmed |
| Mode-specific rules complement, not replace, global rules | Roo Code docs: "Mode-specific rules are designed to complement, not replace" | ✅ Confirmed |
| AGENTS.md in project root is auto-loaded | Roo Code docs: "AGENTS.md in project root is automatically loaded" | ✅ Confirmed |
| Skills use progressive disclosure (loaded on-demand) | Roo Code docs: "skills remain dormant until activated—they don't bloat your base prompt" | ✅ Confirmed |
| Project skills override global skills | Roo Code docs: "project skills override global skills" | ✅ Confirmed |

**Key finding**: The MCP SDK v1.27.1 (used by this project) converts Zod schemas via `zodToJsonSchema()` with `strictUnions: true` and `pipeStrategy: 'input'`. Both `description` and `default` fields are preserved in the JSON Schema output. This means every `.describe()` string and every redundant default mention in descriptions directly costs tokens in every conversation.

---

## Problem Statement

Every conversation with this project's MCP server incurs massive token overhead from:
1. **31 MCP tool schemas** injected into every system prompt (~15,000+ tokens)
2. **Rules files** loaded per-mode into system prompt (~2,000-4,000 tokens each)
3. **Skills** loaded on trigger (~1,000-3,000 tokens each)
4. **Slash commands** loaded on invocation (~200-500 tokens each)
5. **AGENTS.md** loaded into every mode's system prompt (~1,500 tokens)
6. **Tool `.describe()` strings** — verbose, redundant, and repetitive across 31 tools

The goal: reduce token consumption across ALL of these surfaces without losing functionality.

---

## Token Budget Analysis (Current State)

### MCP Tool Schemas (BIGGEST cost — loaded EVERY conversation)

| Tool | Params | Est. Schema Tokens |
|------|--------|--------------------|
| `firewall` | 26 params, 14 actions | ~800 |
| `log_management` | 30+ params, 17 actions | ~900 |
| `defense_mgmt` | 25+ params, 21 actions | ~850 |
| `access_control` | 25+ params, 12 actions | ~800 |
| `harden_kernel` | 15+ params, 11 actions | ~600 |
| `harden_host` | 20+ params, 18 actions | ~700 |
| `compliance` | 20+ params, 11 actions | ~650 |
| `crypto` | 20+ params, 19 actions | ~700 |
| `container_isolation` | 20+ params, 15 actions | ~650 |
| `container_docker` | 10+ params, 5 actions | ~400 |
| `incident_response` | 15+ params, 8 actions | ~550 |
| `integrity` | 15+ params, 11 actions | ~500 |
| `malware` | 15+ params, 9 actions | ~500 |
| `network_defense` | 15+ params, 12 actions | ~550 |
| `backup` | 15+ params, 5 actions | ~450 |
| `secrets` | 10+ params, 4 actions | ~350 |
| `patch` | 10+ params, 7 actions | ~400 |
| `sudo_session` | 5+ params, 6 actions | ~300 |
| Other 13 tools | ~8 params avg | ~4,000 |
| **TOTAL** | | **~13,000-15,000** |

### Rules Files (loaded per-mode)

| File | Location | Est. Tokens | Loaded When |
|------|----------|-------------|-------------|
| `AGENTS.md` (root) | project | ~1,500 | Every mode (duplicated in rules-*) |
| `rules-architect/AGENTS.md` | project | ~600 | Architect mode |
| `rules-code/AGENTS.md` | project | ~550 | Code mode |
| `rules-ask/AGENTS.md` | project | ~500 | Ask mode |
| `rules-debug/AGENTS.md` | project | ~550 | Debug mode |
| `rules/no-parallel-image-reads.md` | global | ~300 | Every mode |
| `rules/sudo-infrastructure.md` | global | ~700 | Every mode |
| `rules-it-ops/1_core_rules.xml` | global | ~500 | IT-Ops mode |
| `rules-it-ops/2_diagnostic_patterns.xml` | global | ~600 | IT-Ops mode |
| **TOTAL per conversation** | | **~3,000-5,800** | |

### Skills (loaded on trigger)

| Skill | Location | Est. Tokens | Trigger |
|--------|----------|-------------|---------|
| `defense-mcp-operator` | global | ~1,200 | Security ops |
| `defense-mcp-operator/references/tool-categories.md` | global | ~2,000 | Tool selection |
| `opnsense-firewall` | global | ~800 | OPNsense tasks |
| `release-publisher` | global | ~900 | Release tasks |
| `security-audit` (project) | project | ~3,500 | Full audit |
| `security-audit` (global) | global | ~2,000 | Audit tasks |
| **TOTAL if all loaded** | | **~10,400** | |

### Slash Commands

| Command | Est. Tokens |
|---------|-------------|
| `security-audit.md` | ~400 |
| `security-audit-full.md` | ~200 |
| `security-posture.md` | ~200 |
| `security-hardening.md` | ~250 |
| `security-compliance.md` | ~250 |
| `security-incident.md` | ~200 |
| `security-malware.md` | ~250 |
| **TOTAL** | **~1,750** |

### Grand Total: ~30,000-33,000 tokens of overhead per fully-loaded conversation

---

## Optimization Strategy

### Layer 1: MCP Tool Schema Optimization (HIGHEST IMPACT — ~40% reduction)

The tool schemas are the single largest token consumer because they are injected into EVERY conversation regardless of what the user is doing. The MCP SDK converts Zod schemas to JSON Schema which gets embedded in the system prompt.

#### 1.1 Shorten ALL `.describe()` strings

**Current pattern** (verbose):
```typescript
.describe("Action: iptables_list=show iptables rules, iptables_add=insert rule, iptables_delete=remove rule, iptables_set_policy=set chain default policy, iptables_create_chain=create custom chain, ufw_status=show UFW status, ufw_add=add UFW rule, ufw_delete=delete UFW rule, persist_save=save rules to file, persist_restore=restore rules from file, persist_enable=install persistence package, persist_status=check persistence status, nftables_list=list nftables ruleset, policy_audit=audit firewall configuration")
```

**Optimized pattern** (terse — the enum values are already self-documenting):
```typescript
.describe("Firewall action to perform")
```

**Rule**: If the `z.enum()` values are self-documenting (e.g., `iptables_list`, `ssh_audit`, `posture_score`), the `.describe()` should NOT repeat them. The enum values themselves serve as documentation.

**Specific changes for each tool file:**

| File | Current describe pattern | Optimized describe |
|------|------------------------|--------------------|
| `firewall.ts` | Repeats all 14 actions with explanations | `"Firewall action"` |
| `log_management.ts` | Repeats all 17 actions | `"Log management action"` |
| `defense_mgmt.ts` | Repeats all 21 actions with explanations | `"Management action"` |
| `access_control.ts` | Repeats all 12 actions | `"Access control action"` |
| `harden_kernel.ts` | Repeats all 11 actions | `"Kernel hardening action"` |
| `harden_host.ts` | Repeats all 18 actions | `"Host hardening action"` |
| `compliance.ts` | Repeats all 11 actions | `"Compliance action"` |
| `crypto.ts` | Repeats all 19 actions | `"Crypto/TLS action"` |
| ALL other tools | Same pattern | Same fix |

**Estimated savings**: ~3,000-4,000 tokens (action descriptions alone)

#### 1.2 Shorten parameter `.describe()` strings

**Current pattern** (verbose):
```typescript
.describe("Preview changes (for iptables_add/iptables_delete/iptables_set_policy/iptables_create_chain, ufw_add/ufw_delete, persist_save/persist_restore/persist_enable)")
```

**Optimized pattern**:
```typescript
.describe("Preview changes without applying")
```

**Rule**: Parameter descriptions should NOT list which actions they apply to. The LLM can infer this from context. Only describe WHAT the parameter does.

**Specific parameter description patterns to fix across ALL 31 tools:**

| Current Pattern | Replacement | Savings |
|----------------|-------------|---------|
| `"X (for action_a/action_b/action_c)"` | `"X"` | ~5-15 tokens each |
| `"X (action_name action)"` | `"X"` | ~3-8 tokens each |
| `"X (used with action_name)"` | `"X"` | ~3-8 tokens each |
| `"X (required for action_name)"` | `"X"` | ~3-8 tokens each |
| `"X (default: value)"` when `.default(value)` exists | `"X"` | ~3-5 tokens each |
| Repeating default value in describe when Zod `.default()` already sets it | Remove from describe | ~3-5 tokens each |

**Estimated savings**: ~2,000-3,000 tokens across all 31 tools

#### 1.3 Shorten tool-level description strings

**Current pattern**:
```typescript
"Unified firewall management. Covers iptables rules/chains, UFW, firewall rule persistence, nftables ruleset listing, and firewall policy audit."
```

**Optimized pattern**:
```typescript
"Firewall: iptables, UFW, nftables, persistence, policy audit"
```

**Apply to all 31 tools:**

| Tool | Current Description | Optimized |
|------|-------------------|-----------|
| `firewall` | "Unified firewall management. Covers iptables rules/chains, UFW, firewall rule persistence, nftables ruleset listing, and firewall policy audit." | "Firewall: iptables, UFW, nftables, persistence, policy audit" |
| `log_management` | "Log management: auditd rules/search/reporting, journalctl queries, fail2ban management, syslog analysis, log rotation audit/configure, and SIEM integration (syslog forwarding, Filebeat, connectivity testing)." | "Logs: auditd, journalctl, fail2ban, syslog, rotation, SIEM" |
| `defense_mgmt` | "Defense management: check tools, run workflows, view change history, assess security posture, manage scheduled audits, auto-remediate findings, and generate security reports." | "Meta: tools, workflows, posture, scheduling, remediation, reports" |
| `access_control` | Full sentence description | "Access: SSH, PAM, sudo, users, passwords, shells" |
| `harden_kernel` | Full sentence | "Kernel: sysctl, modules, coredump, bootloader, memory, ASLR" |
| `harden_host` | Full sentence | "Host: services, permissions, systemd, cron, umask, banner, USB" |
| `compliance` | Full sentence | "Compliance: Lynis, OpenSCAP, CIS, frameworks, cron restrict, /tmp" |
| `crypto` | Full sentence | "Crypto: TLS audit, GPG, LUKS, hashing, cert lifecycle" |
| `container_docker` | Full sentence | "Docker: audit, CIS bench, seccomp, daemon, image scan" |
| `container_isolation` | Full sentence | "Isolation: AppArmor, SELinux, namespaces, seccomp, rootless" |
| `incident_response` | Full sentence | "IR: volatile data, IOC scan, timeline, forensics" |
| `integrity` | Full sentence | "Integrity: AIDE, rootkit scan, file hashing, baselines" |
| `malware` | Full sentence | "Malware: ClamAV, YARA, suspicious files, webshells, quarantine" |
| `network_defense` | Full sentence | "Network: connections, capture, scan detect, IPv6, self-scan, segmentation" |
| `backup` | Full sentence | "Backup: config files, system state, restore, verify" |
| `secrets` | Full sentence | "Secrets: filesystem scan, env audit, SSH key sprawl, git history" |
| `patch` | Full sentence | "Patches: updates, unattended, integrity, kernel, vuln intel" |
| `sudo_session` | Full sentence | "Sudo: elevate, status, drop, extend, preflight" |
| `supply_chain` | Full sentence | "Supply chain: SBOM, cosign, SLSA verify" |
| `zero_trust` | Full sentence | "Zero trust: WireGuard, mTLS, microsegmentation" |
| `ebpf` | Full sentence | "eBPF: programs, Falco status/rules/events" |
| `app_harden` | Full sentence | "Apps: audit, recommend, firewall rules, systemd sandbox" |
| `api_security` | Full sentence | "API: scan, auth audit, rate limits, TLS, CORS" |
| `cloud_security` | Full sentence | "Cloud: detect env, metadata, IAM, storage, IMDS" |
| `honeypot_manage` | Full sentence | "Deception: canary tokens, honeyports, triggers" |
| `dns_security` | Full sentence | "DNS: resolver audit, DNSSEC, tunneling, blocklists, query logs" |
| `process_security` | Full sentence | "Processes: audit, capabilities, namespaces, anomalies, cgroups" |
| `threat_intel` | Full sentence | "Threat intel: IP/hash/domain check, feeds, blocklists" |
| `vuln_manage` | Full sentence | "Vulns: system scan, web scan, tracking, prioritize, remediation" |
| `waf_manage` | Full sentence | "WAF: ModSecurity, rules, rate limiting, OWASP CRS, blocked requests" |
| `wireless_security` | Full sentence | "Wireless: Bluetooth, WiFi, rogue AP, disable unused" |

**Estimated savings**: ~1,000-1,500 tokens

#### 1.4 Total MCP Schema Savings: ~6,000-8,500 tokens (40-55% reduction)

---

### Layer 2: Rules File Optimization (MEDIUM IMPACT — ~30% reduction)

#### 2.1 Deduplicate root AGENTS.md vs mode-specific AGENTS.md

**Problem**: The root `AGENTS.md` (86 lines, ~1,500 tokens) is loaded into EVERY mode's system prompt via the Roo Code rules system. Then each mode-specific `rules-*/AGENTS.md` REPEATS much of the same content.

**Current duplication:**
- Root `AGENTS.md` has: Critical Rules, Commands, Architecture, Security Layers, Adding a New Tool, Testing, Env Vars, Runtime Deps, PAM Safety, SSH Service-Awareness
- `rules-architect/AGENTS.md` repeats: Constraints (=Architecture), Security Architecture (=Security Layers), PAM Safety, Known Dependency Bugs
- `rules-code/AGENTS.md` repeats: Imports (=Critical Rules), Tool Pattern (=Architecture), Tests (=Testing), PAM (=PAM Safety), Service-Aware Audit
- `rules-debug/AGENTS.md` repeats: Logging (=Critical Rules), Common Failures (unique!), Tests (=Testing), PAM Debug (unique!), SSH False Positives (unique!)
- `rules-ask/AGENTS.md` repeats: Context (=Project), Docs (unique!), Counterintuitive (partially unique), History (unique!)

**Fix**: Each mode-specific file should contain ONLY mode-unique content. Remove all content that duplicates the root `AGENTS.md`.

**Specific changes:**

**`.roo/rules-architect/AGENTS.md`** — Remove duplicated sections, keep only:
```markdown
# Architect Rules
## Constraints (unique framing for architects)
## New Tool = 6 Files (unique)
## Known Dependency Bugs (unique)
## Service-Aware Audit Pattern (unique extension guidance)
```
Remove: Security Architecture (dup), Performance (dup), PAM Safety (dup)
**Savings**: ~200 tokens

**`.roo/rules-code/AGENTS.md`** — Remove duplicated sections, keep only:
```markdown
# Code Rules
## Imports (condensed — just the 3 rules)
## Tool Pattern (condensed — just the checklist)
## PAM (unique code-level detail)
## Service-Aware Audit (unique extension guidance)
```
Remove: Tests section (dup of root), redundant import rules
**Savings**: ~150 tokens

**`.roo/rules-debug/AGENTS.md`** — Already mostly unique! Keep as-is but condense:
```markdown
# Debug Rules
## Common Failures (unique — the table is high-value)
## PAM Debug (unique)
## SSH False Positives (unique)
```
Remove: Logging (dup), Tests (dup)
**Savings**: ~100 tokens

**`.roo/rules-ask/AGENTS.md`** — Already mostly unique! Keep as-is but condense:
```markdown
# Ask Rules
## Context (1 line)
## Docs (unique — the table)
## Counterintuitive (unique)
## History (unique)
```
**Savings**: ~50 tokens

#### 2.2 Compress global rules

**`rules/no-parallel-image-reads.md`** — Currently 22 lines (~300 tokens). Can be compressed to:

```markdown
# No Parallel Image Reads
Never issue multiple parallel read_file calls on image files (PNG/JPG/JPEG/GIF/BMP/SVG/WEBP/ICO/AVIF). Read images one at a time. Parallel text file reads are fine. Bug: parallel image reads produce malformed API messages.
```
**Savings**: ~200 tokens

**`rules/sudo-infrastructure.md`** — Currently 50 lines (~700 tokens). Can be compressed to:

```markdown
# Sudo Infrastructure
Layer 1 (NOPASSWD): journalctl, dmesg, last, systemctl status/show/cat/list-*, ss, iptables -L/-S, nft list, lsblk, fdisk -l, blkid, apt list/show, dpkg -l/-L/-s, cat/head/tail /etc/* /var/log/* — use sudo confidently.
Layer 2 (admin toggle): `sudo roo-sudo-on` (15min timeout, 2hr auto-off) → password once → all terminals share creds. `sudo roo-sudo-off` when done. `sudo roo-sudo-status` to check. Toggle scripts are NOPASSWD. Never create /etc/sudoers.d/roo-session manually.
```
**Savings**: ~400 tokens

#### 2.3 Compress IT-Ops rules

**`rules-it-ops/1_core_rules.xml`** — Currently 38 lines (~500 tokens). Compress XML:

```xml
<it_ops>
  <system>Debian 13/GNOME dev workstation. Gateway: OPNsense 192.168.1.1:92</system>
  <workflow>investigate→diagnose→remediate→harden; evidence→backup→modify→verify</workflow>
  <rules>Defense MCP for security ops; browser for CVE research; dry_run=true default; check sudo_session before privileged ops; NOPASSWD for read-only; balance security+usability; local stack first then OPNsense</rules>
  <skills>defense-mcp-operator=security ops; opnsense-firewall=gateway; security-audit=full audit</skills>
  <boundaries owns="config,packages,services,hardening,network,containers,TLS,performance">code→code; debug→debug; design→architect</boundaries>
  <recovery>sudo expired→elevate_gui; missing dep→check_tools; apt locked→lsof+dpkg --configure -a; network→ip addr→ping gw→ping 8.8.8.8→dig→OPNsense; service fail→journalctl→validate→restore→retry; disk full→apt clean+autoremove+vacuum+prune; firewall lockout→restore backup</recovery>
</it_ops>
```
**Savings**: ~200 tokens

**`rules-it-ops/2_diagnostic_patterns.xml`** — Currently 75 lines (~600 tokens). Compress:

```xml
<diagnostics>
  <pattern name="network">ip addr; nmcli; ping gw; dns_security→audit_resolv; dig; ping 8.8.8.8; curl; ip route; firewall→iptables_list; OPNsense skill</pattern>
  <pattern name="service">systemctl status+journalctl; list-units --failed; config validate; resource limits; harden_host→systemd_audit</pattern>
  <pattern name="incident">process_security→detect_anomalies; network_defense→connections_audit; incident_response→ioc_scan; log_management→syslog_analyze; malware→file_scan_suspicious; integrity→rootkit_all; threat_intel→check_ip; incident_response→timeline</pattern>
  <pattern name="performance">uptime; free; df; top; ps sort mem/cpu; process_security→audit_running; iostat; vmstat; journalctl -p err</pattern>
  <pattern name="packages">apt-get check; dpkg --audit; patch→update_audit; dpkg -l broken; dpkg --configure -a; patch→integrity_check</pattern>
  <pattern name="dns">dns_security→audit_resolv; dig local/gw/8.8.8.8; dns_security→check_dnssec; resolvectl status</pattern>
  <pattern name="wireless">nmcli wifi; rfkill; wireless_security→wifi_audit+bt_audit; lspci wireless; dmesg firmware</pattern>
  <pattern name="docker">systemctl status docker; docker info/ps; container_docker→audit; container_isolation→apparmor_status; docker network/volume ls; df docker</pattern>
  <pattern name="tls">crypto→cert_inventory+tls_cert_expiry+tls_config_audit+cert_ca_audit</pattern>
</diagnostics>
```
**Savings**: ~250 tokens

#### 2.4 Total Rules Savings: ~1,350 tokens per conversation

---

### Layer 3: Skills Optimization (MEDIUM IMPACT)

#### 3.1 Deduplicate project vs global security-audit skill

**Problem**: There are TWO security-audit skills:
- `.roo/skills/security-audit/SKILL.md` (project, 149 lines, ~2,000 tokens) — simpler version
- `/home/robert/.roo/skills/security-audit/SKILL.md` (global, 255 lines, ~3,500 tokens) — progressive update version

**Fix**: Keep ONLY the global version (it's more complete with progressive updates). Delete the project-level one. The global version supersedes it.

**Savings**: Eliminates confusion + ensures the better version is always used.

#### 3.2 Compress defense-mcp-operator skill

**Current**: 87 lines (~1,200 tokens)

**Optimized** — remove the "Corrected Tool Names" table (outdated from pre-consolidation era), compress query patterns:

```markdown
## Trigger
Security audits; hardening; compliance; IR; threat/malware; network defense; access control
✗ General Linux/DevOps; ✗ code/debug/architect

## Workflow
1. Context: system, objective, constraints (dry_run? sudo?)
2. Decompose: sequenced sub-queries with dependencies
3. Select Tools: use references/tool-categories.md; audit before apply; preflight_batch_check for ≥3 sudo tools
4. Execute+Analyze: L1=facts L2=anomalies L3=CIS/STIG L4=gaps L5=synthesis+confidence
5. Synthesize: BLUF/SUMMARY/FINDINGS/GAPS/ACTIONS/FOLLOW-ON

## Known Bugs
firewall requires ufw for iptables_list; patch requires rpm on Debian

## Query Patterns
Posture: defense_mgmt→posture_score → compliance→cis_check → firewall→iptables_list → access_control→user_audit → patch→update_audit
Hardening: harden_kernel→sysctl_audit → kernel_audit → harden_host→permissions_audit → remediate_plan
IR (RFC 3227): incident_response→collect → ioc_scan → log_management→syslog_analyze → auditd_search → forensics→evidence_bag
Compliance: compliance→lynis_audit → cis_check → framework_check → report_generate
Threat: malware→file_scan_suspicious → integrity→rootkit_all → malware→clamav_scan → incident_response→ioc_scan → threat_intel→check_ip/hash/domain
```

**Savings**: ~400 tokens

#### 3.3 Compress tool-categories.md reference

**Current**: 168 lines (~2,000 tokens)

This file is the MOST expensive skill reference. It lists every tool with actions, dry_run, and sudo requirements.

**Optimized** — use ultra-compact table format:

```markdown
# Tool Categories — 21 modules | 78 actions
D=dry_run Y/N | S=sudo N/C/A

## Quick Ref (tool→actions)
firewall: iptables_list/add/delete/set_policy/create_chain, ufw_status/add/delete, persist_save/restore/enable/status, nftables_list, policy_audit | D:Y S:C
harden_kernel: sysctl_get/set/audit, kernel_audit/modules/coredump, bootloader_audit/configure, memory_audit/enforce_aslr/report | D:Y S:C
harden_host: service_manage/audit, permissions_check/fix/audit, systemd_audit/apply, cron_audit, umask_audit/set, banner_audit/set, usb_* | D:Y S:C
[... same pattern for all ...]

## Lookup
Posture→defense_mgmt:posture_score | CIS→compliance:cis_check | Kernel→harden_kernel:sysctl_audit+kernel_audit | Ports→network_defense:connections_audit | SSH→access_control:ssh_audit | Users→access_control:user_audit | Rootkits→integrity:rootkit_all | Patches→patch:update_audit | Malware→malware:clamav_scan+file_scan_suspicious | IR→incident_response:collect | Containers→container_docker:audit | Secrets→secrets:scan+git_history_scan | Auto-fix→defense_mgmt:remediate_plan
```

**Savings**: ~800 tokens

#### 3.4 Compress opnsense-firewall skill

**Current**: 60 lines (~800 tokens). Already fairly compact. Minor optimizations:

- Remove the "Languages & Tools" section (rarely needed, can be discovered)
- Compress command patterns into a single template line

**Savings**: ~150 tokens

#### 3.5 Compress release-publisher skill

**Current**: 68 lines (~900 tokens). Already fairly compact. Minor optimizations:

- Compress error handling table
- Remove npm auth section (edge case, can be looked up)

**Savings**: ~200 tokens

#### 3.6 Total Skills Savings: ~1,550 tokens when skills are loaded

---

### Layer 4: Slash Commands Optimization (LOW IMPACT but easy)

#### 4.1 Compress all 7 slash commands

The slash commands are verbose with numbered lists and full parameter specifications. They should be terse since they just trigger a workflow.

**Pattern**: Replace numbered step lists with single-line tool sequences.

**`security-audit.md`** (31 lines → ~8 lines):
```markdown
Three-phase security audit using Defense MCP Server.
Phase 0: defense_mgmt→check_tools, check_optional_deps; sudo_session→elevate_gui
Phase 1: defense_mgmt→posture_score; compliance→cis_check L1; firewall→iptables_list; access_control→user_audit; patch→update_audit
Phase 2: harden_kernel→sysctl_audit+kernel_audit; harden_host→permissions_audit; access_control→ssh_audit; container_isolation→apparmor_status
Phase 3: Cross-reference, severity-rank, save SECURITY-AUDIT-YYYY-MM-DD.md, drop sudo
Use defense-mcp-operator skill.
```

**Apply same compression to all 7 commands.**

**Savings**: ~800 tokens total across all commands

---

### Layer 5: Root AGENTS.md Optimization (MEDIUM IMPACT)

#### 5.1 Compress root AGENTS.md

**Current**: 86 lines (~1,500 tokens). This is loaded into EVERY conversation.

**Optimized version** (~60 lines, ~1,000 tokens):

Key changes:
- Remove "Adding a New Tool" section (only needed in code mode — move to rules-code)
- Compress tables to inline format
- Remove redundant explanations where the rule name is self-documenting
- Compress "Security Layers" into a single paragraph
- Compress "Testing" into 3 lines
- Remove "Runtime Dependencies" (2 deps — not worth a section)

**Savings**: ~500 tokens per conversation

---

### Layer 6: Project-Level Security Audit Skill Consolidation

#### 6.1 Merge and deduplicate the two security-audit skills

**Problem**: Project `.roo/skills/security-audit/SKILL.md` (149 lines) and global `/home/robert/.roo/skills/security-audit/SKILL.md` (255 lines) overlap significantly but have different features:
- Project version: simpler, no progressive updates, no Phase 0 optional deps check
- Global version: progressive updates, Phase 0 with optional deps, report template

**Fix**: 
1. Delete project-level `.roo/skills/security-audit/SKILL.md`
2. Keep and optimize the global version
3. Compress the global version's report template (currently ~60 lines of markdown template that gets loaded as skill instructions)

The report template in the global skill is ~1,000 tokens of markdown scaffold. This should be compressed to a structural description rather than a literal template.

**Savings**: ~1,500 tokens (eliminating project duplicate + compressing template)

---

## Implementation Checklist

### Phase A: MCP Tool Schema Optimization (31 files)

Each file in `src/tools/*.ts` needs these changes:

- [ ] **A1**: `firewall.ts` — Shorten tool description, action describe, all 26 param describes
- [ ] **A2**: `logging.ts` — Shorten tool description, action describe, all 30+ param describes
- [ ] **A3**: `meta.ts` — Shorten tool description, action describe, all 25+ param describes
- [ ] **A4**: `access-control.ts` — Shorten tool description, action describe, all 25+ param describes
- [ ] **A5**: `hardening.ts` — Shorten both tool descriptions (harden_kernel + harden_host), action describes, all param describes
- [ ] **A6**: `compliance.ts` — Shorten tool description, action describe, all param describes
- [ ] **A7**: `encryption.ts` — Shorten tool description, action describe, all param describes
- [ ] **A8**: `container-security.ts` — Shorten both tool descriptions, action describes, all param describes
- [ ] **A9**: `incident-response.ts` — Shorten tool description, action describe, all param describes
- [ ] **A10**: `integrity.ts` — Shorten tool description, action describe, all param describes
- [ ] **A11**: `malware.ts` — Shorten tool description, action describe, all param describes
- [ ] **A12**: `network-defense.ts` — Shorten tool description, action describe, all param describes
- [ ] **A13**: `backup.ts` — Shorten tool description, action describe, all param describes
- [ ] **A14**: `secrets.ts` — Shorten tool description, action describe, all param describes
- [ ] **A15**: `patch-management.ts` — Shorten tool description, action describe, all param describes
- [ ] **A16**: `sudo-management.ts` — Shorten tool description, action describe, all param describes
- [ ] **A17**: `supply-chain-security.ts` — Shorten tool description, action describe, all param describes
- [ ] **A18**: `zero-trust-network.ts` — Shorten tool description, action describe, all param describes
- [ ] **A19**: `ebpf-security.ts` — Shorten tool description, action describe, all param describes
- [ ] **A20**: `app-hardening.ts` — Shorten tool description, action describe, all param describes
- [ ] **A21**: `api-security.ts` — Shorten tool description, action describe, all param describes
- [ ] **A22**: `cloud-security.ts` — Shorten tool description, action describe, all param describes
- [ ] **A23**: `deception.ts` — Shorten tool description, action describe, all param describes
- [ ] **A24**: `dns-security.ts` — Shorten tool description, action describe, all param describes
- [ ] **A25**: `process-security.ts` — Shorten tool description, action describe, all param describes
- [ ] **A26**: `threat-intel.ts` — Shorten tool description, action describe, all param describes
- [ ] **A27**: `vulnerability-management.ts` — Shorten tool description, action describe, all param describes
- [ ] **A28**: `waf.ts` — Shorten tool description, action describe, all param describes
- [ ] **A29**: `wireless-security.ts` — Shorten tool description, action describe, all param describes
- [ ] **A30**: Run `npm run build` to verify all changes compile
- [ ] **A31**: Run `npm test` to verify no test regressions

### Phase B: Rules File Optimization (9 files)

- [ ] **B1**: Compress `AGENTS.md` (root) — remove "Adding a New Tool" section (move to rules-code), compress Security Layers, compress Testing, remove Runtime Dependencies section
- [ ] **B2**: Deduplicate `.roo/rules-architect/AGENTS.md` — remove sections that duplicate root AGENTS.md
- [ ] **B3**: Deduplicate `.roo/rules-code/AGENTS.md` — remove duplicated sections, add "Adding a New Tool" from root
- [ ] **B4**: Deduplicate `.roo/rules-debug/AGENTS.md` — remove Logging and Tests sections (duplicated)
- [ ] **B5**: Deduplicate `.roo/rules-ask/AGENTS.md` — minor compression only (already mostly unique)
- [ ] **B6**: Compress `/home/robert/.roo/rules/no-parallel-image-reads.md` — reduce from 22 lines to 3 lines
- [ ] **B7**: Compress `/home/robert/.roo/rules/sudo-infrastructure.md` — reduce from 50 lines to ~10 lines
- [ ] **B8**: Compress `/home/robert/.roo/rules-it-ops/1_core_rules.xml` — tighten XML
- [ ] **B9**: Compress `/home/robert/.roo/rules-it-ops/2_diagnostic_patterns.xml` — single-line patterns

### Phase C: Skills Optimization (5 skills + 1 reference)

- [ ] **C1**: Delete project-level `.roo/skills/security-audit/SKILL.md` (superseded by global)
- [ ] **C2**: Compress global `/home/robert/.roo/skills/security-audit/SKILL.md` — compress report template from literal markdown to structural description, remove redundant phase numbering
- [ ] **C3**: Compress `/home/robert/.roo/skills/defense-mcp-operator/SKILL.md` — remove "Corrected Tool Names" table, compress query patterns
- [ ] **C4**: Compress `/home/robert/.roo/skills/defense-mcp-operator/references/tool-categories.md` — ultra-compact single-line-per-tool format
- [ ] **C5**: Compress `/home/robert/.roo/skills/opnsense-firewall/SKILL.md` — remove Languages & Tools section, compress command patterns
- [ ] **C6**: Compress `/home/robert/.roo/skills/release-publisher/SKILL.md` — compress error table, remove npm auth section

### Phase D: Slash Commands Optimization (7 files)

- [ ] **D1**: Compress `.roo/commands/security-audit.md` — numbered steps to single-line phases
- [ ] **D2**: Compress `.roo/commands/security-audit-full.md` — already short, minor tightening
- [ ] **D3**: Compress `.roo/commands/security-posture.md` — numbered steps to tool sequence
- [ ] **D4**: Compress `.roo/commands/security-hardening.md` — numbered steps to tool sequence
- [ ] **D5**: Compress `.roo/commands/security-compliance.md` — numbered steps to tool sequence
- [ ] **D6**: Compress `.roo/commands/security-incident.md` — numbered steps to tool sequence
- [ ] **D7**: Compress `.roo/commands/security-malware.md` — numbered steps to tool sequence

### Phase E: Verification

- [ ] **E1**: Build project (`npm run build`) — verify no compilation errors
- [ ] **E2**: Run full test suite (`npm test`) — verify no regressions
- [ ] **E3**: Verify MCP server starts correctly with `node build/index.js`
- [ ] **E4**: Spot-check 3-4 tool invocations to verify descriptions still make sense
- [ ] **E5**: Count token reduction by comparing before/after schema sizes

---

## Optimization Principles Applied

### Principle 1: Enum Values Are Self-Documenting
If a Zod `z.enum()` has values like `iptables_list`, `ssh_audit`, `posture_score`, the `.describe()` should NOT repeat what each value does. The LLM can infer meaning from the name.

### Principle 2: Don't Repeat Defaults
If `.default("filter")` is set on a Zod schema, don't also say `"(default: filter)"` in the `.describe()`. The JSON Schema already includes the default.

### Principle 3: Don't List Applicable Actions
Parameter descriptions like `"Source IP (for iptables_add)"` waste tokens. The LLM can figure out which params apply to which actions from context. Just say `"Source IP/CIDR"`.

### Principle 4: Colon-Separated Lists Beat Sentences
`"Firewall: iptables, UFW, nftables, persistence, policy audit"` beats `"Unified firewall management. Covers iptables rules/chains, UFW, firewall rule persistence, nftables ruleset listing, and firewall policy audit."` — same info, 60% fewer tokens.

### Principle 5: Rules Should Be Unique Per Mode
Mode-specific rules files should contain ONLY content unique to that mode. Anything in root `AGENTS.md` should not be repeated.

### Principle 6: Skills Should Be Compressed Reference, Not Prose
Skills are loaded into context — every word costs tokens. Use tables, abbreviations, and single-line patterns instead of numbered lists and full sentences.

### Principle 7: Slash Commands Are Triggers, Not Tutorials
Slash commands should be terse workflow triggers, not step-by-step guides. The skill handles the detailed procedure.

---

## Expected Total Savings

| Layer | Current Est. | After Optimization | Savings |
|-------|-------------|-------------------|---------|
| MCP Tool Schemas | ~14,000 tokens | ~7,500 tokens | ~6,500 (46%) |
| Rules (per conversation) | ~4,000 tokens | ~2,650 tokens | ~1,350 (34%) |
| Skills (when loaded) | ~10,400 tokens | ~7,350 tokens | ~3,050 (29%) |
| Slash Commands | ~1,750 tokens | ~950 tokens | ~800 (46%) |
| **TOTAL** | **~30,150** | **~18,450** | **~11,700 (39%)** |

The MCP tool schemas provide the highest ROI because they are loaded in EVERY conversation. A 46% reduction there saves ~6,500 tokens on every single interaction.

---

## Risk Assessment

| Risk | Mitigation |
|------|-----------|
| Shortened descriptions confuse the LLM | Enum values are self-documenting; test with real queries |
| Tests break from description changes | Descriptions are not tested — only behavior is |
| Skill compression loses critical workflow steps | Keep all tool sequences; only remove prose |
| Mode rules too sparse | Root AGENTS.md still provides baseline; mode rules add unique content |

## Files Modified (Complete List)

### Source Code (29 tool files)
`src/tools/firewall.ts`, `src/tools/logging.ts`, `src/tools/meta.ts`, `src/tools/access-control.ts`, `src/tools/hardening.ts`, `src/tools/compliance.ts`, `src/tools/encryption.ts`, `src/tools/container-security.ts`, `src/tools/incident-response.ts`, `src/tools/integrity.ts`, `src/tools/malware.ts`, `src/tools/network-defense.ts`, `src/tools/backup.ts`, `src/tools/secrets.ts`, `src/tools/patch-management.ts`, `src/tools/sudo-management.ts`, `src/tools/supply-chain-security.ts`, `src/tools/zero-trust-network.ts`, `src/tools/ebpf-security.ts`, `src/tools/app-hardening.ts`, `src/tools/api-security.ts`, `src/tools/cloud-security.ts`, `src/tools/deception.ts`, `src/tools/dns-security.ts`, `src/tools/process-security.ts`, `src/tools/threat-intel.ts`, `src/tools/vulnerability-management.ts`, `src/tools/waf.ts`, `src/tools/wireless-security.ts`

### Project Config Files (12 files + 1 deletion)
`AGENTS.md`, `.roo/rules-architect/AGENTS.md`, `.roo/rules-code/AGENTS.md`, `.roo/rules-debug/AGENTS.md`, `.roo/rules-ask/AGENTS.md`, `.roo/commands/security-audit.md`, `.roo/commands/security-audit-full.md`, `.roo/commands/security-posture.md`, `.roo/commands/security-hardening.md`, `.roo/commands/security-compliance.md`, `.roo/commands/security-incident.md`, `.roo/commands/security-malware.md`, `.roo/skills/security-audit/SKILL.md` (DELETE)

### Global Config Files (9 files in /home/robert/.roo/)
`rules/no-parallel-image-reads.md`, `rules/sudo-infrastructure.md`, `rules-it-ops/1_core_rules.xml`, `rules-it-ops/2_diagnostic_patterns.xml`, `skills/defense-mcp-operator/SKILL.md`, `skills/defense-mcp-operator/references/tool-categories.md`, `skills/opnsense-firewall/SKILL.md`, `skills/release-publisher/SKILL.md`, `skills/security-audit/SKILL.md`

**Total: ~50 files modified, 1 file deleted**