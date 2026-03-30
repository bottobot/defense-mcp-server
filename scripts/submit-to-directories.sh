#!/usr/bin/env bash
# Submit defense-mcp-server to MCP directories
# Usage: ./scripts/submit-to-directories.sh [all|smithery|glama|mcp-registry|awesome-punkpeye|awesome-appcypher|mcpservers]
set -euo pipefail

REPO="bottobot/defense-mcp-server"
REPO_URL="https://github.com/$REPO"
DESCRIPTION="31 defensive security tools with 250+ actions for system hardening, compliance, firewall management, vulnerability scanning, and incident response on Linux."
SHORT_DESC="Defensive security MCP server for Linux — 31 tools, 250+ actions, dry-run by default."

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[DONE]${NC} $*"; }
warn()  { echo -e "${YELLOW}[TODO]${NC} $*"; }
err()   { echo -e "${RED}[ERR]${NC} $*"; }

# ─── Smithery.ai ──────────────────────────────────────────────
submit_smithery() {
  info "Smithery.ai — Publishing via CLI..."
  if ! command -v smithery &>/dev/null; then
    info "Installing Smithery CLI..."
    npm install -g @smithery/cli@latest
  fi
  if [ -f smithery.yaml ]; then
    ok "smithery.yaml already exists in repo root"
  else
    err "smithery.yaml not found — run this from the repo root"
    return 1
  fi
  warn "Manual step: Sign in to https://smithery.ai and publish your server."
  warn "  Option 1 (web): Go to https://smithery.ai/new and enter your GitHub repo URL"
  warn "  Option 2 (CLI): smithery mcp publish $REPO_URL -n @bottobot/defense-mcp-server"
  echo ""
}

# ─── Glama.ai ─────────────────────────────────────────────────
submit_glama() {
  info "Glama.ai — Checking glama.json..."
  if [ -f glama.json ]; then
    ok "glama.json already exists in repo root"
  else
    err "glama.json not found — run this from the repo root"
    return 1
  fi
  warn "Manual step: Visit https://glama.ai/mcp/servers and claim ownership of your server."
  warn "  1. Sign in with your GitHub account (bottobot)"
  warn "  2. Search for defense-mcp-server or click 'Add Server'"
  warn "  3. Claim ownership (glama.json in repo validates you)"
  echo ""
}

# ─── Official MCP Registry ────────────────────────────────────
submit_mcp_registry() {
  info "Official MCP Registry — Publishing..."
  if ! command -v mcp-publisher &>/dev/null; then
    info "Installing mcp-publisher..."
    npm install -g @anthropic-ai/mcp-publisher 2>/dev/null || npm install -g mcp-publisher 2>/dev/null || true
  fi
  if [ -f .mcp/server.json ]; then
    ok ".mcp/server.json already exists"
  else
    err ".mcp/server.json not found"
    return 1
  fi
  warn "Manual step: Run 'mcp-publisher publish .mcp/server.json' to publish."
  warn "  You may need to verify namespace ownership for io.github.bottobot"
  echo ""
}

# ─── awesome-mcp-servers (punkpeye) ──────────────────────────
submit_awesome_punkpeye() {
  local UPSTREAM="punkpeye/awesome-mcp-servers"
  local BRANCH="add-defense-mcp-server"

  info "awesome-mcp-servers (punkpeye) — Creating PR..."

  # Check if fork exists, create if not
  if ! gh repo view "$REPO_OWNER/$( echo $UPSTREAM | cut -d/ -f2 )" &>/dev/null 2>&1; then
    info "Forking $UPSTREAM..."
    gh repo fork "$UPSTREAM" --clone=false
  else
    ok "Fork already exists"
  fi

  # Clone fork to temp dir
  local TMPDIR
  TMPDIR=$(mktemp -d)
  local FORK_REPO="bottobot/awesome-mcp-servers"

  info "Cloning fork to $TMPDIR..."
  gh repo clone "$FORK_REPO" "$TMPDIR" -- --depth=1 2>/dev/null

  cd "$TMPDIR"
  git checkout -b "$BRANCH" 2>/dev/null || git checkout "$BRANCH" 2>/dev/null

  # Add entry to Security section
  # Find the Security section and add our entry in alphabetical order
  if grep -q "defense-mcp-server" README.md 2>/dev/null; then
    ok "Entry already exists in README.md"
  else
    # Insert after the Security heading, maintaining alphabetical order
    # We look for the 🔒 Security section and add after the first entry that comes after 'd' alphabetically
    python3 -c "
import re

with open('README.md', 'r') as f:
    content = f.read()

entry = '- [bottobot/defense-mcp-server](https://github.com/bottobot/defense-mcp-server) 📇 🏠 🐧 - $DESCRIPTION'

# Find the Security section
# Look for a line containing 'Security' as a heading
lines = content.split('\n')
in_security = False
inserted = False
new_lines = []

for i, line in enumerate(lines):
    # Detect security section header (various formats)
    if re.search(r'#+.*Security', line) or '🔒' in line:
        in_security = True
        new_lines.append(line)
        continue

    # Detect next section header (end of security section)
    if in_security and line.startswith('#'):
        if not inserted:
            new_lines.append(entry)
            inserted = True
        in_security = False

    # Insert alphabetically within the security section
    if in_security and line.startswith('- [') and not inserted:
        # Extract the repo name for comparison
        match = re.search(r'\[([^\]]+)\]', line)
        if match:
            existing_name = match.group(1).lower()
            if existing_name > 'bottobot/defense-mcp-server':
                new_lines.append(entry)
                inserted = True

    new_lines.append(line)

if not inserted:
    print('WARNING: Could not find insertion point, appending to end of file')
    new_lines.append(entry)

with open('README.md', 'w') as f:
    f.write('\n'.join(new_lines))

print('Entry added successfully' if inserted else 'Entry appended (check placement)')
"
    ok "Entry added to README.md"
  fi

  git add README.md
  git diff --cached --stat

  if git diff --cached --quiet; then
    warn "No changes to commit — entry may already exist"
  else
    git commit -m "Add defense-mcp-server to Security section"
    git push origin "$BRANCH" 2>/dev/null || git push --set-upstream origin "$BRANCH"

    # Create PR
    gh pr create \
      --repo "$UPSTREAM" \
      --head "bottobot:$BRANCH" \
      --title "Add defense-mcp-server to Security section" \
      --body "$(cat <<'PREOF'
## What
Adds [defense-mcp-server](https://github.com/bottobot/defense-mcp-server) to the Security section.

## Description
defense-mcp-server is an MCP server providing 31 defensive security tools with 250+ actions for Linux system hardening, compliance auditing (CIS/HIPAA/SOC2), firewall management, vulnerability scanning, malware detection, incident response, and more. All tools include dry-run-by-default safety guardrails.

- **Language:** TypeScript (📇)
- **Transport:** Local/STDIO (🏠)
- **Platform:** Linux (🐧)
- **License:** MIT

## Category
Security (🔒) — This is a defensive security toolset for hardening and protecting Linux systems.
PREOF
)"
    ok "PR created on $UPSTREAM"
  fi

  cd - >/dev/null
  rm -rf "$TMPDIR"
  echo ""
}

# ─── awesome-mcp-servers (appcypher) ─────────────────────────
submit_awesome_appcypher() {
  local UPSTREAM="appcypher/awesome-mcp-servers"
  local BRANCH="add-defense-mcp-server"

  info "awesome-mcp-servers (appcypher) — Creating PR..."

  # Check if fork exists
  if ! gh repo view "bottobot/$(echo $UPSTREAM | cut -d/ -f2)" &>/dev/null 2>&1; then
    info "Forking $UPSTREAM..."
    gh repo fork "$UPSTREAM" --clone=false
  fi

  local TMPDIR
  TMPDIR=$(mktemp -d)

  # This fork may conflict with punkpeye fork name — gh handles with suffix
  info "Cloning fork to $TMPDIR..."
  gh repo clone "bottobot/awesome-mcp-servers" "$TMPDIR" -- --depth=1 2>/dev/null || \
    gh repo clone "$UPSTREAM" "$TMPDIR" -- --depth=1 2>/dev/null

  cd "$TMPDIR"
  git checkout -b "$BRANCH" 2>/dev/null || git checkout "$BRANCH" 2>/dev/null

  if grep -q "defense-mcp-server" README.md 2>/dev/null; then
    ok "Entry already exists"
  else
    python3 -c "
import re

with open('README.md', 'r') as f:
    content = f.read()

entry = '**[Defense MCP Server](https://github.com/bottobot/defense-mcp-server)** - $DESCRIPTION'

lines = content.split('\n')
in_security = False
inserted = False
new_lines = []

for i, line in enumerate(lines):
    if re.search(r'#+.*Security', line):
        in_security = True
        new_lines.append(line)
        continue

    if in_security and line.startswith('#'):
        if not inserted:
            new_lines.append('- ' + entry)
            inserted = True
        in_security = False

    if in_security and line.strip().startswith('- **[') and not inserted:
        match = re.search(r'\*\*\[([^\]]+)\]', line)
        if match:
            existing = match.group(1).lower()
            if existing > 'defense mcp server':
                new_lines.append('- ' + entry)
                inserted = True

    new_lines.append(line)

if not inserted:
    new_lines.append('- ' + entry)

with open('README.md', 'w') as f:
    f.write('\n'.join(new_lines))
"
    ok "Entry added"
  fi

  git add README.md
  if ! git diff --cached --quiet; then
    git commit -m "Add Defense MCP Server to Security section"
    git push origin "$BRANCH" 2>/dev/null || git push --set-upstream origin "$BRANCH"

    gh pr create \
      --repo "$UPSTREAM" \
      --head "bottobot:$BRANCH" \
      --title "Add Defense MCP Server to Security section" \
      --body "$(cat <<'PREOF'
## What
Adds [Defense MCP Server](https://github.com/bottobot/defense-mcp-server) to the Security section.

## Description
Defense MCP Server provides 31 defensive security tools with 250+ actions for Linux — system hardening, CIS/HIPAA/SOC2 compliance, firewall management, malware scanning, vulnerability detection, incident response, and more. Dry-run by default with safety guardrails.

**License:** MIT | **Language:** TypeScript | **Platform:** Linux
PREOF
)"
    ok "PR created on $UPSTREAM"
  else
    warn "No changes to commit"
  fi

  cd - >/dev/null
  rm -rf "$TMPDIR"
  echo ""
}

# ─── mcpservers.org (wong2) ───────────────────────────────────
submit_mcpservers() {
  info "mcpservers.org — Web form submission required"
  warn "Manual step: Visit https://mcpservers.org/submit and fill in:"
  warn "  Server Name: Defense MCP Server"
  warn "  Short Description: $SHORT_DESC"
  warn "  Link: $REPO_URL"
  warn "  Category: Security (or Other)"
  warn "  Contact Email: (your email)"
  echo ""
}

# ─── Anthropic Connectors Directory ──────────────────────────
submit_anthropic() {
  info "Anthropic Connectors Directory — Google Form submission"
  warn "Manual step: Submit via Google Form:"
  warn "  https://docs.google.com/forms/d/e/1FAIpQLSeafJF2NDI7oYx1r8o0ycivCSVLNq92Mpc1FPxMKSw1CzDkqA/viewform"
  warn ""
  warn "  Requirements before submitting:"
  warn "  - All tools must have readOnlyHint/destructiveHint annotations"
  warn "  - Privacy policy section in README.md"
  warn "  - Tool-level descriptions (already done)"
  echo ""
}

# ─── Main ─────────────────────────────────────────────────────
print_summary() {
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo " SUBMISSION CHECKLIST"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
  echo " Config files (commit these to your repo):"
  echo "   [✓] smithery.yaml   — Smithery.ai server config"
  echo "   [✓] glama.json      — Glama.ai ownership claim"
  echo "   [✓] .mcp/server.json — Official MCP Registry"
  echo ""
  echo " Automated PRs:"
  echo "   [ ] punkpeye/awesome-mcp-servers — run: $0 awesome-punkpeye"
  echo "   [ ] appcypher/awesome-mcp-servers — run: $0 awesome-appcypher"
  echo ""
  echo " Manual submissions:"
  echo "   [ ] Smithery.ai — sign in + publish"
  echo "   [ ] Glama.ai — sign in + claim"
  echo "   [ ] mcpservers.org — web form"
  echo "   [ ] Anthropic Connectors — Google Form"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

TARGET="${1:-summary}"

case "$TARGET" in
  all)
    submit_smithery
    submit_glama
    submit_mcp_registry
    submit_awesome_punkpeye
    submit_awesome_appcypher
    submit_mcpservers
    submit_anthropic
    print_summary
    ;;
  smithery)        submit_smithery ;;
  glama)           submit_glama ;;
  mcp-registry)    submit_mcp_registry ;;
  awesome-punkpeye)  submit_awesome_punkpeye ;;
  awesome-appcypher) submit_awesome_appcypher ;;
  mcpservers)      submit_mcpservers ;;
  anthropic)       submit_anthropic ;;
  summary|help|*)
    print_summary
    ;;
esac
