#!/bin/bash
set -e

# Copy the AI approval hook and daemon to the global scripts directory
mkdir -p ~/.gemini/config/scripts

cat << 'EOF' > ~/.gemini/config/scripts/ai_approval_hook.py
#!/usr/bin/env python3
import sys
import json
import os
import subprocess
import socket
import time

def main():
    try:
        input_data = sys.stdin.read()
        if not input_data:
            print(json.dumps({"decision": "deny", "reason": "No input provided"}))
            return
            
        payload = json.loads(input_data)
        command_line = payload.get("toolCall", {}).get("args", {}).get("CommandLine", "")

        if os.environ.get("AGY_HOOK_BYPASS") == "1":
            print(json.dumps({"decision": "allow", "reason": "Bypass loop explicitly allowed"}))
            return

        safe_prefixes = (
            "ls ", "ls", "grep ", "head ", "tail ", "find ", "pwd", "whoami",
            "ps ", "ps", "env", "git diff", "git status", "git log", "git show",
            "file ", "stat ", "wc ", "tree ", "jq ", "date", "uname", "cat "
        )
        if command_line.startswith(safe_prefixes):
            print(json.dumps({"decision": "allow", "reason": "Fast-path: Safe read command"}))
            return

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

        SOCK_FILE = "/tmp/lgtm_daemon.sock"
        daemon_script = os.path.join(os.path.dirname(__file__), "lgtm_daemon.py")
        
        # Check if daemon is running
        if not os.path.exists(SOCK_FILE):
            if not os.path.exists(daemon_script):
                print(json.dumps({"decision": "deny", "reason": "daemon script missing"}))
                return
            
            # Spawn daemon
            eval_env = os.environ.copy()
            eval_env["AGY_HOOK_BYPASS"] = "1"
            subprocess.Popen(
                [sys.executable, daemon_script], 
                env=eval_env, 
                start_new_session=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            # Wait for socket
            for _ in range(100):
                if os.path.exists(SOCK_FILE):
                    break
                time.sleep(0.1)
                
        # Connect to daemon
        client = None
        for attempt in range(2):
            try:
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.settimeout(30.0)
                client.connect(SOCK_FILE)
                break
            except ConnectionRefusedError:
                if attempt == 0:
                    try:
                        os.remove(SOCK_FILE)
                    except OSError:
                        pass
                    eval_env = os.environ.copy()
                    eval_env["AGY_HOOK_BYPASS"] = "1"
                    subprocess.Popen(
                        [sys.executable, daemon_script], 
                        env=eval_env, 
                        start_new_session=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                    time.sleep(1)
                    
                    for _ in range(50):
                        if os.path.exists(SOCK_FILE):
                            break
                        time.sleep(0.1)
                else:
                    client = None
                    break
            except Exception:
                client = None
                break

        if client:
            client.send(json.dumps({"prompt": prompt}).encode('utf-8'))
            try:
                llm_response = client.recv(65536).decode('utf-8').strip()
            except socket.timeout:
                llm_response = ""
            client.close()
        else:
            llm_response = ""

        if not llm_response:
            # Fallback to slow mode
            eval_env = os.environ.copy()
            eval_env["AGY_HOOK_BYPASS"] = "1"
            result = subprocess.run(
                ["agy", "-p", prompt, "--model", "gemini-3.8-flash-low", "--new-project"],
                capture_output=True, text=True, env=eval_env, cwd="/tmp"
            )
            llm_response = result.stdout.strip()
        
        if not llm_response:
            print(json.dumps({"decision": "deny", "reason": "Empty response from Gemini API"}))
            return
            
        try:
            parsed_response = json.loads(llm_response)
            if "decision" in parsed_response:
                print(json.dumps(parsed_response))
            else:
                print(json.dumps({"decision": "deny", "reason": "Invalid response schema"}))
        except json.JSONDecodeError:
            print(json.dumps({"decision": "deny", "reason": f"Failed to parse LLM JSON: {llm_response}"}))
            
    except Exception as e:
        print(json.dumps({"decision": "deny", "reason": f"Hook exception: {str(e)}"}))

if __name__ == "__main__":
    main()

EOF

cat << 'EOF' > ~/.gemini/config/scripts/lgtm_daemon.py
import socket
import os
import sys
import subprocess
import json
import time

SOCK_FILE = "/tmp/lgtm_daemon.sock"

def spawn_agy():
    env = os.environ.copy()
    env["AGY_HOOK_BYPASS"] = "1"
    proc = subprocess.Popen(
        ["agy", "--input-format", "stream-json", "--output-format", "stream-json", "--model", "gemini-3.8-flash-low", "--new-project"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=env, cwd="/tmp"
    )
    for line in proc.stdout:
        if "init" in line:
            break
    return proc

def main():
    if os.path.exists(SOCK_FILE):
        os.remove(SOCK_FILE)
        
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCK_FILE)
    server.listen(5)
    
    proc = spawn_agy()
    count = 0
    
    while True:
        conn, _ = server.accept()
        data = conn.recv(65536).decode('utf-8')
        if not data:
            conn.close()
            continue
            
        try:
            req = json.loads(data)
            prompt = req.get("prompt", "")
            
            payload = {"event": "user", "message": {"content": prompt}}
            proc.stdin.write(json.dumps(payload) + "\n")
            proc.stdin.flush()
            
            response = ""
            for line in proc.stdout:
                if "result" in line.lower() and "response" in line.lower():
                    try:
                        res = json.loads(line)
                        response = res.get("result", {}).get("response", "")
                    except:
                        pass
                    break
            
            # Extract JSON block if surrounded by markdown
            if response.startswith("```json"):
                response = response.split("```json")[1].split("```")[0].strip()
            elif response.startswith("```"):
                response = response.split("```")[1].split("```")[0].strip()
                
            conn.send(response.encode('utf-8'))
            
            count += 1
            if count >= 20:
                proc.terminate()
                proc = spawn_agy()
                count = 0
                
        except Exception as e:
            conn.send(f'{{"decision": "deny", "reason": "daemon error: {str(e)}"}}\n'.encode('utf-8'))
        finally:
            conn.close()

if __name__ == "__main__":
    main()

EOF

chmod +x ~/.gemini/config/scripts/ai_approval_hook.py
chmod +x ~/.gemini/config/scripts/lgtm_daemon.py

# Configure the pre-tool hook in Antigravity
mkdir -p ~/.gemini/config
if [ -f ~/.gemini/config/hooks.json ]; then
    cp ~/.gemini/config/hooks.json ~/.gemini/config/hooks.json.bak
fi

cat << 'EOF' > ~/.gemini/config/hooks.json
{
  "ai-approval-hook": {
    "PreToolUse": [
      {
        "matcher": "run_command",
        "hooks": [
          {
            "type": "command",
            "command": "./scripts/ai_approval_hook.py",
            "timeout": 45
          }
        ]
      }
    ]
  }
}
EOF

echo "✅ LGTM installed! All run_command tool calls will now be evaluated by the LLM."
