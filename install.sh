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
import tempfile

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
            f"You are a permissive security guard for a developer's local shell. Your job is to act as a second pair of eyes, NOT a strict hindrance. "
            f"DEFAULT TO ALLOWING commands unless they are explicitly and unambiguously destructive (e.g., 'rm -rf /') or obvious attempts to steal secrets.\n\n"
            f"GUIDELINES:\n"
            f"1. ALLOW almost everything. The developer is actively working. Creating, moving, reading, compiling, or executing files (even from /tmp) is completely normal.\n"
            f"2. ALLOW all standard tools (git, python, npm, docker, bash, mv, cp, etc.) with normal arguments.\n"
            f"3. DENY ONLY if the command is catastrophically destructive to the system or clearly exfiltrating private keys/passwords.\n\n"
            f"Command to evaluate: `{command_line}`\n\n"
            f"Respond with ONLY a raw JSON object (no markdown): {{\"decision\": \"allow\"|\"deny\", \"reason\": \"<brief reason>\"}}"
        )

        SOCK_FILE = os.path.join(tempfile.gettempdir(), "lgtm_daemon.sock")
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
                capture_output=True, text=True, env=eval_env, cwd=tempfile.gettempdir()
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
import tempfile

SOCK_FILE = os.path.join(tempfile.gettempdir(), "lgtm_daemon.sock")

def spawn_agy():
    env = os.environ.copy()
    env["AGY_HOOK_BYPASS"] = "1"
    proc = subprocess.Popen(
        ["agy", "--input-format", "stream-json", "--output-format", "stream-json", "--model", "gemini-3.8-flash-low", "--new-project"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=env, cwd=tempfile.gettempdir()
    )
    while True:
        line = proc.stdout.readline()
        if not line or "init" in line:
            break
    return proc

def main():
    if os.path.exists(SOCK_FILE):
        try:
            os.remove(SOCK_FILE)
        except OSError:
            pass
        
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
            while True:
                line = proc.stdout.readline()
                if not line:
                    break
                if "result" in line.lower() and "response" in line.lower():
                    try:
                        res = json.loads(line)
                        result_obj = res.get("result", {})
                        if result_obj.get("status") == "ERROR":
                            err_msg = result_obj.get("error", "Unknown error")
                            response = f'{{"decision": "deny", "reason": "API Error: {err_msg}"}}'
                        else:
                            response = result_obj.get("response", "")
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
            try:
                conn.send(f'{{"decision": "deny", "reason": "daemon error: {str(e)}"}}\n'.encode('utf-8'))
            except:
                pass
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
