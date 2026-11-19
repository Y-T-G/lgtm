#!/usr/bin/env bash
set -e

ENABLE_STATUSLINE="${LGTM_STATUSLINE:-1}"
for arg in "$@"; do
    case "$arg" in
        --no-statusline) ENABLE_STATUSLINE=0 ;;
    esac
done

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

# Copy or download the AI approval hook, daemon, and statusline helper
if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/scripts/lgtm_hook.py" ]; then
    if [ "$SCRIPT_DIR/scripts" != "$SCRIPTS_DIR" ]; then
        cp "$SCRIPT_DIR/scripts/lgtm_hook.py" "$SCRIPTS_DIR/"
        cp "$SCRIPT_DIR/scripts/lgtm_daemon.py" "$SCRIPTS_DIR/"
        cp "$SCRIPT_DIR/scripts/lgtm_status.py" "$SCRIPTS_DIR/"
    fi
elif [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/lgtm_hook.py" ]; then
    if [ "$SCRIPT_DIR" != "$SCRIPTS_DIR" ]; then
        cp "$SCRIPT_DIR/lgtm_hook.py" "$SCRIPTS_DIR/"
        cp "$SCRIPT_DIR/lgtm_daemon.py" "$SCRIPTS_DIR/"
        cp "$SCRIPT_DIR/lgtm_status.py" "$SCRIPTS_DIR/"
    fi
else
    echo "Downloading LGTM scripts..."
    download_file "$REPO_RAW_URL/scripts/lgtm_hook.py" "$SCRIPTS_DIR/lgtm_hook.py"
    download_file "$REPO_RAW_URL/scripts/lgtm_daemon.py" "$SCRIPTS_DIR/lgtm_daemon.py"
    download_file "$REPO_RAW_URL/scripts/lgtm_status.py" "$SCRIPTS_DIR/lgtm_status.py"
fi

chmod +x "$SCRIPTS_DIR/lgtm_hook.py"
chmod +x "$SCRIPTS_DIR/lgtm_daemon.py"
chmod +x "$SCRIPTS_DIR/lgtm_status.py"

# Update Antigravity settings and merge hook configuration
PYTHON_BIN="$(command -v python3 || command -v python || true)"
if [ -n "$PYTHON_BIN" ]; then
    PYTHON_CMD="$(basename "$PYTHON_BIN")"
    if [ -f "$SETTINGS_FILE" ]; then
        cp "$SETTINGS_FILE" "$SETTINGS_FILE.bak"
    fi
    if [ -f "$HOOKS_FILE" ]; then
        cp "$HOOKS_FILE" "$HOOKS_FILE.bak"
    fi
    "$PYTHON_BIN" -c '
import json, sys, os, signal, tempfile, getpass

settings_path, hooks_path, py_cmd, enable_statusline = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

def load_json(path):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
        except Exception:
            pass
    return {}

def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")

settings = load_json(settings_path)
settings["toolPermission"] = "always-proceed"
status_script = os.path.join(os.path.dirname(hooks_path), "scripts", "lgtm_status.py")
if enable_statusline.strip().lower() in ("0", "false", "no", "off"):
    cur_sl = settings.get("statusLine")
    if isinstance(cur_sl, dict) and "lgtm_status.py" in str(cur_sl.get("command", "")):
        del settings["statusLine"]
elif "statusLine" not in settings:
    settings["statusLine"] = {
        "type": "command",
        "command": f"{py_cmd} \"{status_script}\""
    }
save_json(settings_path, settings)

hooks = load_json(hooks_path)
hooks["lgtm-hook"] = {
    "PreToolUse": [
        {
            "matcher": "run_command",
            "hooks": [
                {
                    "type": "command",
                    "command": f"{py_cmd} ./scripts/lgtm_hook.py",
                    "timeout": 45
                }
            ]
        }
    ]
}
save_json(hooks_path, hooks)

# Gracefully stop any running daemon tracked by lockfile so upgrades take effect
lock_file = os.path.join(tempfile.gettempdir(), f"lgtm_daemon_{getpass.getuser()}.lock")
if os.path.exists(lock_file):
    try:
        with open(lock_file, "r", encoding="utf-8") as f:
            pid = int(f.read().strip())
        if pid > 0 and pid != os.getpid():
            os.kill(pid, signal.SIGTERM)
    except Exception:
        pass
' "$SETTINGS_FILE" "$HOOKS_FILE" "$PYTHON_CMD" "$ENABLE_STATUSLINE"
else
    echo "⚠️  Python not found; please manually set \"toolPermission\": \"always-proceed\" in $SETTINGS_FILE" >&2
    if [ -f "$HOOKS_FILE" ]; then
        cp "$HOOKS_FILE" "$HOOKS_FILE.bak"
    fi
    cat << 'EOF' > "$HOOKS_FILE"
{
  "lgtm-hook": {
    "PreToolUse": [
      {
        "matcher": "run_command",
        "hooks": [
          {
            "type": "command",
            "command": "python3 ./scripts/lgtm_hook.py",
            "timeout": 45
          }
        ]
      }
    ]
  }
}
EOF
fi

echo "✅ LGTM installed! All run_command tool calls will now be evaluated by the LLM."
