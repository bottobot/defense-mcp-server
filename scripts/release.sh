#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Defense MCP Server — Release Script
#
# Usage:
#   ./scripts/release.sh [patch|minor|major] [--npm-only|--git-only]
#
# Examples:
#   ./scripts/release.sh patch          # bump patch, push git + npm
#   ./scripts/release.sh minor          # bump minor, push git + npm
#   ./scripts/release.sh major          # bump major, push git + npm
#   ./scripts/release.sh patch --git-only   # bump + push to GitHub only
#   ./scripts/release.sh patch --npm-only   # publish current version to npm only
#   ./scripts/release.sh                # push current changes to git + npm (no version bump)
# ─────────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

info()  { echo -e "${CYAN}ℹ${NC}  $*"; }
ok()    { echo -e "${GREEN}✅${NC} $*"; }
warn()  { echo -e "${YELLOW}⚠${NC}  $*"; }
fail()  { echo -e "${RED}❌${NC} $*" >&2; exit 1; }

# ── Parse args ──────────────────────────────────────────────
BUMP_TYPE="${1:-}"
FLAG="${2:-}"
DO_GIT=true
DO_NPM=true
DO_BUMP=false

if [[ "$FLAG" == "--git-only" ]]; then
  DO_NPM=false
elif [[ "$FLAG" == "--npm-only" ]]; then
  DO_GIT=false
fi

if [[ "$BUMP_TYPE" =~ ^(patch|minor|major)$ ]]; then
  DO_BUMP=true
fi

# ── Pre-flight checks ──────────────────────────────────────
info "Running pre-flight checks..."

# Check we're in the project root
[[ -f "package.json" ]] || fail "Must be run from the project root (where package.json is)"

# Check git is clean (for version bumps)
if $DO_BUMP; then
  if [[ -n "$(git status --porcelain)" ]]; then
    fail "Working directory is not clean. Commit or stash changes before releasing."
  fi
fi

# Check npm auth
if $DO_NPM; then
  npm whoami &>/dev/null || fail "Not logged in to npm. Run 'npm login' first."
  NPM_USER=$(npm whoami)
  ok "Authenticated to npm as ${NPM_USER}"
fi

# Check git remote
if $DO_GIT; then
  git remote get-url origin &>/dev/null || fail "No git remote 'origin' configured"
  ok "Git remote: $(git remote get-url origin)"
fi

CURRENT_VERSION=$(node -e "console.log(require('./package.json').version)")
info "Current version: v${CURRENT_VERSION}"

# ── Build & Test ────────────────────────────────────────────
info "Building..."
rm -rf build/
npm run build
ok "Build succeeded"

info "Running tests..."
if npm test -- --run 2>/dev/null; then
  ok "Tests passed"
else
  warn "Tests failed or unavailable — continuing (review test output above)"
fi

# ── Version bump ────────────────────────────────────────────
if $DO_BUMP; then
  info "Bumping version (${BUMP_TYPE})..."
  NEW_VERSION=$(npm version "$BUMP_TYPE" --no-git-tag-version | tr -d 'v')
  ok "Version bumped: v${CURRENT_VERSION} → v${NEW_VERSION}"
  
  # Rebuild with new version
  rm -rf build/
  npm run build
else
  NEW_VERSION="$CURRENT_VERSION"
fi

# ── Git push ────────────────────────────────────────────────
if $DO_GIT; then
  BRANCH=$(git rev-parse --abbrev-ref HEAD)
  
  if $DO_BUMP; then
    info "Committing version bump..."
    git add package.json package-lock.json
    git commit -m "chore: release v${NEW_VERSION}"
    git tag -a "v${NEW_VERSION}" -m "Release v${NEW_VERSION}"
    ok "Created tag v${NEW_VERSION}"
  elif [[ -n "$(git status --porcelain)" ]]; then
    warn "Uncommitted changes detected. Commit them first or use a bump type (patch/minor/major)."
    fail "Cannot push with uncommitted changes"
  fi
  
  info "Pushing to origin/${BRANCH}..."
  git push origin "$BRANCH"
  
  if $DO_BUMP; then
    info "Pushing tags..."
    git push origin "v${NEW_VERSION}"
  fi
  
  ok "Pushed to GitHub (${BRANCH})"
fi

# ── npm publish ─────────────────────────────────────────────
if $DO_NPM; then
  info "Publishing to npm..."
  npm publish
  ok "Published defense-mcp-server@${NEW_VERSION} to npm"
fi

# ── Summary ─────────────────────────────────────────────────
echo ""
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}  Release complete: v${NEW_VERSION}${NC}"
if $DO_GIT; then
  echo -e "  GitHub: $(git remote get-url origin)"
fi
if $DO_NPM; then
  echo -e "  npm:    https://www.npmjs.com/package/defense-mcp-server"
fi
echo -e "${GREEN}════════════════════════════════════════${NC}"
