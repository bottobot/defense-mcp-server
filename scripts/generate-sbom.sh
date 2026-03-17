#!/bin/bash
# generate-sbom.sh — Generate Software Bill of Materials (SBOM)
#
# Produces CycloneDX SBOM in JSON format for the npm package.
# Requires: @cyclonedx/cyclonedx-npm (installed as devDependency or npx)
#
# Usage:
#   ./scripts/generate-sbom.sh              # Output to sbom.json
#   ./scripts/generate-sbom.sh output.json  # Output to custom path
#
# Environment:
#   SBOM_FORMAT=json|xml   (default: json)

set -euo pipefail

OUTPUT="${1:-sbom.json}"
FORMAT="${SBOM_FORMAT:-json}"

echo "[sbom] Generating CycloneDX SBOM (${FORMAT}) → ${OUTPUT}" >&2

# Use npx to avoid requiring global install
npx --yes @cyclonedx/cyclonedx-npm \
  --output-file "${OUTPUT}" \
  --output-format "${FORMAT}" \
  --omit dev \
  --spec-version 1.5 \
  --mc-type application

echo "[sbom] SBOM written to ${OUTPUT}" >&2
echo "[sbom] To verify: npx @cyclonedx/cyclonedx-npm validate --input-file ${OUTPUT}" >&2
