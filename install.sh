#!/usr/bin/env bash
set -e

SCRIPT_DIR=""
if [ -n "${BASH_SOURCE[0]}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
fi

GEMINI_CONFIG_DIR="$HOME/.gemini/config"
SCRIPTS_DIR="$GEMINI_CONFIG_DIR/scripts"
CLI_SETTINGS_DIR="$HOME/.gemini/antigravity-cli"
SETTINGS_FILE="$CLI_SETTINGS_DIR/settings.json"
HOOKS_FILE="$GEMINI_CONFIG_DIR/hooks.json"
REPO_RAW_URL="${LGTM_RAW_URL:-https://raw.githubusercontent.com/Y-T-G/lgtm/main}"

mkdir -p "$SCRIPTS_DIR"
mkdir -p "$CLI_SETTINGS_DIR"

download_file() {
    local url="$1"
    local dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$dest"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$dest" "$url"
    else
        echo "❌ Error: curl or wget is required to download scripts." >&2
        exit 1
    fi
}

# Copy or download the AI approval hook and daemon
if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/scripts/ai_approval_hook.py" ]; then
    cp "$SCRIPT_DIR/scripts/ai_approval_hook.py" "$SCRIPTS_DIR/"
    cp "$SCRIPT_DIR/scripts/lgtm_daemon.py" "$SCRIPTS_DIR/"
elif [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/ai_approval_hook.py" ]; then
    cp "$SCRIPT_DIR/ai_approval_hook.py" "$SCRIPTS_DIR/"
    cp "$SCRIPT_DIR/lgtm_daemon.py" "$SCRIPTS_DIR/"
else
    echo "Downloading LGTM scripts..."
    download_file "$REPO_RAW_URL/scripts/ai_approval_hook.py" "$SCRIPTS_DIR/ai_approval_hook.py"
    download_file "$REPO_RAW_URL/scripts/lgtm_daemon.py" "$SCRIPTS_DIR/lgtm_daemon.py"
fi

chmod +x "$SCRIPTS_DIR/ai_approval_hook.py"
chmod +x "$SCRIPTS_DIR/lgtm_daemon.py"

# Update Antigravity settings to always-proceed
PYTHON_BIN="$(command -v python3 || command -v python || true)"
if [ -n "$PYTHON_BIN" ]; then
    if [ -f "$SETTINGS_FILE" ]; then
        cp "$SETTINGS_FILE" "$SETTINGS_FILE.bak"
    fi
    "$PYTHON_BIN" -c '
import json, sys, os
path = sys.argv[1]
os.makedirs(os.path.dirname(path), exist_ok=True)
data = {}
if os.path.exists(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        data = {}
data["toolPermission"] = "always-proceed"
with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
' "$SETTINGS_FILE"
else
    echo "⚠️  Python not found; please manually set \"toolPermission\": \"always-proceed\" in $SETTINGS_FILE" >&2
fi

# Configure the pre-tool hook in Antigravity
if [ -f "$HOOKS_FILE" ]; then
    cp "$HOOKS_FILE" "$HOOKS_FILE.bak"
fi

cat << 'EOF' > "$HOOKS_FILE"
{
  "ai-approval-hook": {
    "PreToolUse": [
      {
        "matcher": "run_command",
        "hooks": [
          {
            "type": "command",
            "command": "python3 ./scripts/ai_approval_hook.py",
            "timeout": 45
          }
        ]
      }
    ]
  }
}
EOF

echo "✅ LGTM installed! All run_command tool calls will now be evaluated by the LLM."
