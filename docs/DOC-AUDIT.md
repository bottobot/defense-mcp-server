# Documentation Audit — defense-mcp-server v0.8.1

## Status: Complete (2026-03-26)
Major consolidation (157→31 tools, v0.7.0) left docs out of sync. Full remediation completed: markdown updates, orphaned code deletion, ADR directory creation, CONTRIBUTING.md, and PREFLIGHT-ARCHITECTURE merge.

## Document Classifications

| File | Class | Action |
|---|---|---|
| `AGENTS.md` | ESSENTIAL | Retain |
| `docs/TOOLS-REFERENCE.md` | ESSENTIAL (source of truth) | Retain |
| `docs/STANDARDS.md` | ESSENTIAL | Retain |
| `docs/SAFEGUARDS.md` | ESSENTIAL | Add PAM sanity section |
| `docs/ARCHITECTURE.md` | ESSENTIAL/UPDATE | Fix version (0.7.3→0.8.1), remove ids.ts, fix orphaned files in tree |
| `docs/SPECIFICATION.md` | ESSENTIAL/UPDATE | Fix version (0.7.3→0.8.1), remove ids.ts, sync module list to TOOLS-REFERENCE |
| `README.md` | NEEDS UPDATE | Remove IDS/Reporting/SIEM/Drift as top-level modules; sync to TOOLS-REFERENCE |
| `CHANGELOG.md` | NEEDS UPDATE (critical) | Add v0.8.0+v0.8.1 entries; annotate v2.0.0/v1.0.0 ordering anomaly |
| `docs/PENTEST-REQUIREMENTS.md` | NEEDS UPDATE | Change "94 tools" → "31 tools" |
| ~~`docs/PREFLIGHT-ARCHITECTURE.md`~~ | MERGED (deleted) | Content merged into `docs/ARCHITECTURE.md` Pre-flight section; standalone file deleted |
| `docs/adr/PAM-HARDENING-FIX.md` | HISTORICAL (archived) | Moved to docs/adr/, status → Implemented (v0.7.1) |
| `docs/adr/SUDO-SESSION-DESIGN.md` | HISTORICAL (archived) | Moved to docs/adr/ |
| `scripts/plans/apparmor-hardening-plan.md` | USEFUL | Retain or move to docs/scripts/ |
| ~~`TODO.md`~~ | OBSOLETE (deleted) | Deleted — instructed creating files already implemented elsewhere |
| `docs/adr/pam-sanity-validation.md` | HISTORICAL (archived) | Moved to docs/adr/, status → Implemented (v0.8.1) |

## Critical Issues

### Orphaned Code (highest priority)
- ~~`src/tools/drift-detection.ts`~~ — deleted ✅
- ~~`src/tools/reporting.ts`~~ — deleted ✅
- ~~`src/tools/siem-integration.ts`~~ — deleted ✅
- ~~`tests/tools/ids.test.ts`~~ — deleted ✅
- ~~`tests/tools/drift-detection.test.ts`~~ — deleted ✅
- ~~`tests/tools/reporting.test.ts`~~ — deleted ✅ (orphaned by reporting.ts deletion)
- ~~`tests/tools/siem-integration.test.ts`~~ — deleted ✅ (orphaned by siem-integration.ts deletion)

### Contradictions

| Conflict | Files | Fix |
|---|---|---|
| Tool count: 31 vs 94 vs 150+ | AGENTS.md, PENTEST-REQUIREMENTS, PREFLIGHT-ARCHITECTURE, README | Standardize: "31 tools, 150+ actions" |
| ids.ts listed as active | ARCHITECTURE.md, SPECIFICATION.md | Remove from both |
| v2.0.0 appears before v0.3.0 in changelog | CHANGELOG.md | Annotate or reorder |
| ~~TODO.md requests already-implemented files~~ | ~~TODO.md vs meta.ts, vulnerability-management.ts~~ | ~~Deleted TODO.md~~ ✅ |

### Changelog Gaps
- v0.8.0: SIEM integration absorbed into logging.ts, reporting into meta.ts, drift detection into integrity.ts
- v0.8.1: PAM sanity validation (validatePamPolicySanity), SSH service-awareness in ssh_audit

## Missing Documentation

| Gap | Priority | Status |
|---|---|---|
| v0.8.0 + v0.8.1 release notes | HIGH | ✅ Added to CHANGELOG.md |
| CI lint: verify all src/tools/*.ts imported by index.ts | MEDIUM | ✅ `scripts/verify-tool-imports.mjs` — runs via `pretest` hook |
| ~~CONTRIBUTING.md (action-based pattern, test mock pattern, "Adding a New Tool" workflow)~~ | ~~MEDIUM~~ | ✅ Created |
| ~~docs/adr/ directory for completed design decisions~~ | ~~LOW~~ | ✅ Created with 3 ADRs |

## Action Plan

### Immediate — ✅ Complete
1. ✅ Deleted `src/tools/drift-detection.ts`, `src/tools/reporting.ts`, `src/tools/siem-integration.ts`
2. ✅ Deleted `tests/tools/ids.test.ts`, `tests/tools/drift-detection.test.ts`
3. ✅ Deleted `TODO.md`

### Short-term — ✅ Complete
4. ✅ Update `CHANGELOG.md`: added v0.8.0/v0.8.1 entries; annotated v2.0.0 ordering anomaly
5. ✅ Update `ARCHITECTURE.md`, `SPECIFICATION.md`, `PENTEST-REQUIREMENTS.md`, `README.md` to v0.8.1 using TOOLS-REFERENCE as source of truth
6. ✅ Created `docs/adr/`; moved PAM-HARDENING-FIX.md, SUDO-SESSION-DESIGN.md, pam-sanity-validation.md into it with "Status: Implemented" headers
7. ✅ Add PAM sanity validation section to SAFEGUARDS.md

### Long-term — ✅ Complete
8. ✅ Created `CONTRIBUTING.md` (formalized tool addition workflow from AGENTS.md)
9. ✅ Merged `PREFLIGHT-ARCHITECTURE.md` into `ARCHITECTURE.md` as subsection; deleted standalone file
10. ✅ Added `scripts/verify-tool-imports.mjs` — CI lint rule that fails if any `src/tools/*.ts` is not imported by `src/index.ts`. Runs automatically via `pretest` hook (`npm test`) and standalone via `npm run verify:tools`.
