#!/bin/bash
# MCP Tool Caller - Invokes kali-defense-mcp-server tools via JSON-RPC over stdio
# Usage: ./mcp-call.sh <tool_name> [json_params]

TOOL_NAME="$1"
PARAMS="${2:-{}}"
DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -z "$TOOL_NAME" ]; then
  printf 'Usage: %s <tool_name> [json_params]\n' "$0"
  exit 1
fi

# Validate tool name - only allow alphanumeric and underscore
if ! printf '%s' "$TOOL_NAME" | grep -qE '^[a-zA-Z0-9_]+$'; then
  printf 'Error: Invalid tool name\n' >&2
  exit 1
fi

# Validate params is valid JSON
if ! printf '%s' "$PARAMS" | python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null; then
  printf 'Error: Invalid JSON params\n' >&2
  exit 1
fi

export KALI_DEFENSE_DRY_RUN=true

# Create temp file for output with restrictive permissions
umask 077
TMPFILE=$(mktemp)
printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"mcp-caller","version":"1.0.0"}}}\n{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"%s","arguments":%s}}\n' "$TOOL_NAME" "$PARAMS" | timeout 120 node "$DIR/build/index.js" 2>/dev/null > "$TMPFILE"

# Parse the response - find the id:2 response line and extract text content
python3 -c "
import json, sys
with open(sys.argv[1]) as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try:
            data = json.loads(line)
            if data.get('id') == 2 and 'result' in data:
                result = data['result']
                if 'content' in result:
                    for item in result['content']:
                        if item.get('type') == 'text':
                            print(item['text'])
                if result.get('isError'):
                    print('[MCP ERROR]', file=sys.stderr)
        except: pass
" "$TMPFILE"

rm -f "$TMPFILE"
