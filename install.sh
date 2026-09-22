#!/usr/bin/env bash
# Install the LGTM AI approval hook for Antigravity (agy).
#
# Usage:
#   ./install.sh [destination_dir]   install (default: .agents)
set -euo pipefail

DEST_DIR="${1:-.agents}"
SCRIPTS_DIR="$DEST_DIR/scripts"
HOOKS_FILE="$DEST_DIR/hooks.json"
SCRIPT_FILE="$SCRIPTS_DIR/ai_approval_hook.py"

command -v jq >/dev/null || { echo "install: jq is required" >&2; exit 1; }
command -v python3 >/dev/null || { echo "install: python3 is required" >&2; exit 1; }

echo "Installing AI approval hook to $DEST_DIR..."

mkdir -p "$SCRIPTS_DIR"

cat << 'INNER_EOF' > "$SCRIPT_FILE"
#!/usr/bin/env python3
import sys, json, subprocess, os

def main():
    # Prevent infinite recursion and disable tool use in the inner evaluation
    if os.environ.get("AGY_HOOK_BYPASS") == "1":
        print(json.dumps({"decision": "deny", "reason": "Tools are disabled during LLM evaluation"}))
        return

    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError:
        print(json.dumps({"decision": "deny", "reason": "Failed to parse hook input"}))
        return

    tool_call = input_data.get("toolCall", {})
    if tool_call.get("name") != "run_command":
        print(json.dumps({"decision": "allow", "reason": "Not a run_command tool"}))
        return

    args = tool_call.get("args", {})
    command_line = args.get("CommandLine", "").strip()

    if not command_line:
        print(json.dumps({"decision": "allow", "reason": "Empty command"}))
        return

    # Fast-path for safe read commands
    safe_prefixes = (
        "ls ", "ls", "grep ", "head ", "tail ", "find ", "pwd", "whoami",
        "ps ", "ps", "env", "git diff", "git status", "git log", "git show",
        "file ", "stat ", "wc ", "tree ", "jq ", "date", "uname", "git "
    )
    if command_line.startswith(safe_prefixes):
        print(json.dumps({
            "decision": "allow",
            "reason": "Fast-path: Safe read command"
        }))
        return

    # LLM evaluation for unknown commands
    prompt = (
        f"You are a security assistant. Evaluate if the following shell command is safe to run automatically "
        f"without human approval in a local development environment. "
        f"IMPORTANT GUIDELINES:\n"
        f"1. Standard development commands (e.g., git push, git commit, npm install, build scripts) are SAFE and MUST BE ALLOWED. Do not evaluate the safety of the *contents* of a commit/push, only the command itself.\n"
        f"2. Commands like `cat` and `echo` are generally safe for reading project files or printing text and SHOULD BE ALLOWED.\n"
        f"3. You MUST DENY commands that are fundamentally destructive (e.g., rm -rf /, chmod -R 777 /) or attempt to access sensitive secrets (e.g., cat ~/.aws/credentials, echo $API_KEY).\n"
        f"Respond with ONLY a raw JSON object (no markdown) with this schema: {{\"decision\": \"allow\"|\"deny\", \"reason\": \"<explanation>\"}}. "
        f"Command: `{command_line}`"
    )

    try:
        # Pass AGY_HOOK_BYPASS to prevent the inner agy from triggering the hook recursively
        eval_env = os.environ.copy()
        eval_env["AGY_HOOK_BYPASS"] = "1"

        # Add a timeout of 15 seconds to prevent the hook from getting stuck and killed by Antigravity
        result = subprocess.run(
            ["agy", "-p", prompt, "--model", "gemini-3.8-flash-low"],
            capture_output=True, text=True, check=True, env=eval_env, timeout=15
        )
        llm_response = result.stdout.strip()

        if llm_response.startswith("```json"): llm_response = llm_response[7:]
        elif llm_response.startswith("```"): llm_response = llm_response[3:]
        if llm_response.endswith("```"): llm_response = llm_response[:-3]

        parsed_resp = json.loads(llm_response.strip())
        decision = parsed_resp.get("decision", "deny")
        reason = parsed_resp.get("reason", "LLM decision")

        if decision != "allow":
            decision = "deny"

        print(json.dumps({"decision": decision, "reason": reason}))

    except subprocess.TimeoutExpired:
        print(json.dumps({"decision": "deny", "reason": "LLM evaluation timed out"}))
    except Exception as e:
        print(json.dumps({"decision": "deny", "reason": f"Error calling AI: {str(e)}"}))

if __name__ == "__main__":
    main()
INNER_EOF

chmod +x "$SCRIPT_FILE"

if [ ! -f "$HOOKS_FILE" ]; then
    echo '{}' > "$HOOKS_FILE"
fi

cp "$HOOKS_FILE" "${HOOKS_FILE}.bak"
jq '.["ai-approval-hook"] = {
  "PreToolUse": [
    {
      "matcher": "run_command",
      "hooks": [
        {
          "type": "command",
          "command": "./scripts/ai_approval_hook.py",
          "timeout": 30
        }
      ]
    }
  ]
}' "$HOOKS_FILE" > "${HOOKS_FILE}.tmp"
mv "${HOOKS_FILE}.tmp" "$HOOKS_FILE"

echo "Installation complete! (backup saved to ${HOOKS_FILE}.bak)"
echo "AI approval hook is now active in $DEST_DIR."
