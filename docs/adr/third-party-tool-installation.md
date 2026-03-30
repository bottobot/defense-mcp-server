# ADR: Third-Party Security Tool Installation Policy

**Status:** Accepted  
**Date:** 2026-03-29  

## Context

The defense-mcp-server wraps 31 security tools. 7 require third-party sources not available in standard Debian/RHEL repos:

| Tool | Binary | Required By | Source |
|------|--------|-------------|--------|
| Falco | `falco` | `ebpf` | CNCF / Falco Security APT repo |
| Trivy | `trivy` | `container_docker` | Aqua Security APT repo |
| Grype | `grype` | `supply_chain` | GitHub releases (Anchore) |
| Syft | `syft` | `supply_chain` | GitHub releases (Anchore) |
| TruffleHog | `trufflehog` | `secrets` | GitHub releases |
| slsa-verifier | `slsa-verifier` | `supply_chain` | GitHub releases (OpenSSF) |
| cdxgen | `cdxgen` | `supply_chain` | npm (@cyclonedx/cdxgen) |

## Decision

Implement a **three-tier system**:

**Tier 1 — Graceful Degradation** (always active): When a third-party tool is missing, return a structured error with verified install instructions. Never suggest `curl | sh`.

**Tier 2 — Verified Auto-Install** (opt-in via `DEFENSE_MCP_THIRD_PARTY_INSTALL=true`): Install using verified methods only — GPG-fingerprint-verified APT repos, SHA256+cosign-verified binary downloads, or npm with provenance. Full audit trail.

**Tier 3 — Standalone Script**: `scripts/install-optional-deps.sh` for operators who prefer manual installation.

## Security Principles

1. **No `curl | sh`** — ever. All downloads to temp file first, then verify, then install.
2. **Explicit consent** — `DEFENSE_MCP_AUTO_INSTALL=true` AND `DEFENSE_MCP_THIRD_PARTY_INSTALL=true` both required.
3. **Version pinning** — hardcoded versions and checksums in `src/core/third-party-manifest.ts`.
4. **Minimal privilege** — downloads as unprivileged user; only final binary placement uses sudo.
5. **Audit trail** — all installations logged to changelog.
6. **Idempotency** — skip if correct version already installed.

## Trust Assessment

| Tool | Trust | Basis |
|------|-------|-------|
| Falco | HIGH | CNCF graduated, signed APT repo |
| Trivy | HIGH | Aqua Security, signed APT repo + cosign |
| slsa-verifier | HIGH | OpenSSF/Google, SLSA Level 3 provenance |
| Grype | MEDIUM | Anchore, checksums + cosign, no APT repo |
| Syft | MEDIUM | Anchore, checksums + cosign, no APT repo |
| TruffleHog | MEDIUM | GitHub releases + checksums |
| cdxgen | MEDIUM | OWASP, npm provenance |

## Installation Methods by Tool

| Tool | Method | Verification |
|------|--------|-------------|
| Falco | APT repo | GPG fingerprint (hardcoded) |
| Trivy | APT repo | GPG fingerprint (hardcoded) |
| Grype | GitHub release binary | SHA256 + cosign |
| Syft | GitHub release binary | SHA256 + cosign |
| TruffleHog | GitHub release binary | SHA256 |
| slsa-verifier | GitHub release binary | SHA256 + SLSA provenance |
| cdxgen | npm local prefix | npm provenance |

## Consequences

- `falco` and `trivy` move from "unavailable" to installable via verified APT repos
- `grype`, `syft`, `trufflehog`, `slsa-verifier` installable via verified binary download
- `cdxgen` installable via npm with provenance
- Checksums in manifest require maintenance on each tool version bump
- `scripts/install-optional-deps.sh` provides operator-friendly manual path
