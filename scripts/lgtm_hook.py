#!/usr/bin/env python3
import sys
import json
import os
import re
import subprocess
import socket
import time
import tempfile
import getpass
import shutil
import urllib.request

USER = getpass.getuser()
PORT_FILE = os.path.join(tempfile.gettempdir(), f"lgtm_daemon_{USER}.port")
LGTM_GEMINI_DIR = os.path.join(tempfile.gettempdir(), f"lgtm_gemini_{USER}")
MAX_RETRIES = 3

def is_network_error(msg: str) -> bool:
    if not msg:
        return True
    msg_lower = msg.lower()
    keywords = (
        "stream reading error",
        "software caused connection abort",
        "connection reset",
        "connection refused",
        "connection closed",
        "connection abort",
        "broken pipe",
        "network is unreachable",
        "no route to host",
        "timed out",
        "timeout",
        "deadline_exceeded",
        "deadline exceeded",
        "unavailable",
        "service unavailable",
        "bad gateway",
        "gateway timeout",
        "502",
        "503",
        "504",
        "read tcp",
        "write tcp",
        "dial tcp",
        "temporary failure in name resolution",
        "getaddrinfo",
        "unexpected eof",
        "eof reading",
        "handshake",
        "transport",
        "socket error",
        "reset by peer",
        "resource_exhausted",
        "rate limit",
        "429",
    )
    return any(k in msg_lower for k in keywords)

def setup_isolated_gemini_dir():
    cli_dir = os.path.join(LGTM_GEMINI_DIR, "antigravity-cli")
    os.makedirs(cli_dir, exist_ok=True)
    real_gemini = os.path.expanduser("~/.gemini/antigravity-cli")
    for item in ("antigravity-oauth-token", "settings.json"):
        src = os.path.join(real_gemini, item)
        dst = os.path.join(cli_dir, item)
        if os.path.exists(src):
            if os.path.islink(dst) or os.path.exists(dst):
                try:
                    os.remove(dst)
                except OSError:
                    pass
            try:
                os.symlink(src, dst)
            except (OSError, NotImplementedError, AttributeError):
                try:
                    shutil.copy2(src, dst)
                except OSError:
                    pass

def get_daemon_conn():
    if not os.path.exists(PORT_FILE):
        return None, None
    try:
        with open(PORT_FILE, "r", encoding="utf-8") as f:
            content = f.read().strip()
        if not content or ":" not in content:
            return None, None
        port_str, token = content.split(":", 1)
        port = int(port_str)
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(28.0)
        client.connect(("127.0.0.1", port))
        return client, token
    except Exception:
        return None, None

def spawn_daemon(daemon_script):
    eval_env = os.environ.copy()
    eval_env["AGY_HOOK_BYPASS"] = "1"
    subprocess.Popen(
        [sys.executable, daemon_script],
        env=eval_env,
        start_new_session=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

def extract_json_payload(text: str):
    if not text:
        return None
    text = text.strip()
    try:
        return json.loads(text)
    except Exception:
        pass
    if "```" in text:
        parts = text.split("```")
        for i in range(1, len(parts), 2):
            block = parts[i]
            if block.startswith("json"):
                block = block[4:]
            block = block.strip()
            try:
                return json.loads(block)
            except Exception:
                pass
    first_brace = text.find("{")
    last_brace = text.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        try:
            return json.loads(text[first_brace:last_brace + 1])
        except Exception:
            pass
    return None

SENSITIVE_PATTERNS = (
    "antigravity-oauth-token",
    ".ssh/id_",
    ".ssh/authorized_keys",
    ".aws/credentials",
    ".config/gcloud/credentials",
    "/etc/shadow",
    "/etc/sudoers",
    "aws_secret_access_key",
)

SAFE_REDIRECT_RE = re.compile(
    r"(?:\b[12]?>>?\s*/dev/null\b|&>>?\s*/dev/null\b|\b2>&1\b|\b1>&2\b)"
)

OBVIOUS_DENY_PATTERNS = (
    (
        re.compile(
            r"(?:^|[;&|]\s*|\b(?:sudo|env)\s+)rm\s+.*(?:-[a-zA-Z]*[rf][a-zA-Z]*|--recursive|--no-preserve-root).*"
            r"(?:\s+/(?:\s|$|[;&|])|\s+/\*|\s+/(?:system|data|etc|boot|usr|var|proc|sys|dev)(?:/|\s|$|[;&|]))"
        ),
        "Fast-deny: Catastrophic filesystem deletion",
    ),
    (
        re.compile(r"\bdd\b.*\bof=/dev/(?:block|sd|nvme|mmcblk|vd|hd|loop)"),
        "Fast-deny: Raw block device overwrite",
    ),
    (
        re.compile(r"\bmkfs(?:\.[a-zA-Z0-9]+)?\s+/dev/"),
        "Fast-deny: Partition format",
    ),
    (
        re.compile(r"\bfind\s+/(?:\s+|$).*(?:-delete\b|-exec(?:dir)?\s+rm\b)"),
        "Fast-deny: Destructive root find operation",
    ),
    (
        re.compile(r">{1,2}\s*/etc/(?:passwd|shadow|sudoers|hosts\.allow)\b"),
        "Fast-deny: Critical system file overwrite",
    ),
)

def check_fast_deny(command_line: str):
    cmd = command_line.strip()
    if not cmd:
        return None
    cmd_lower = cmd.lower()
    for regex, reason in OBVIOUS_DENY_PATTERNS:
        if regex.search(cmd_lower):
            return reason
    if any(sp in cmd_lower for sp in SENSITIVE_PATTERNS):
        if re.search(r"\b(?:curl|wget|nc|ncat|netcat|ssh|scp|rsync)\b", cmd_lower):
            return "Fast-deny: Potential credential exfiltration over network"
    return None

def split_compound_command(cmd: str):
    """Split command on top-level |, &&, ||, ; while rejecting substitutions and unsafe redirects."""
    cleaned = SAFE_REDIRECT_RE.sub(" ", cmd)
    in_single = False
    in_double = False
    escaped = False
    i = 0
    n = len(cleaned)
    segments = []
    cur = []

    while i < n:
        c = cleaned[i]
        if escaped:
            cur.append(c)
            escaped = False
            i += 1
            continue
        if c == "\\" and not in_single:
            cur.append(c)
            escaped = True
            i += 1
            continue
        if c == "'" and not in_double:
            in_single = not in_single
            cur.append(c)
            i += 1
            continue
        if c == '"' and not in_single:
            in_double = not in_double
            cur.append(c)
            i += 1
            continue
        if in_double:
            if c == "`":
                return None
            if c == "$" and i + 1 < n and cleaned[i + 1] in ("(", "{"):
                return None
            cur.append(c)
            i += 1
            continue
        if not in_single and not in_double:
            if c in ("`", "$", ">", "<", "\n", "(", ")"):
                return None
            if c == ";":
                segments.append("".join(cur).strip())
                cur = []
                i += 1
                continue
            if c in ("|", "&"):
                if i + 1 < n and cleaned[i + 1] == c:
                    segments.append("".join(cur).strip())
                    cur = []
                    i += 2
                    continue
                elif c == "|":
                    segments.append("".join(cur).strip())
                    cur = []
                    i += 1
                    continue
                else:
                    return None
        cur.append(c)
        i += 1

    if in_single or in_double or escaped:
        return None
    segments.append("".join(cur).strip())
    return [s for s in segments if s]

def is_safe_segment(cmd: str) -> bool:
    cmd = cmd.strip()
    if not cmd:
        return False

    cmd_lower = cmd.lower()
    if any(sp in cmd_lower for sp in SENSITIVE_PATTERNS):
        return False

    safe_commands = (
        "ls", "grep", "rg", "egrep", "fgrep", "head", "tail", "find", "fd",
        "pwd", "whoami", "id", "ps", "pgrep", "git diff", "git status",
        "git log", "git show", "git branch", "git rev-parse", "git remote",
        "file", "stat", "wc", "tree", "jq", "date", "uname", "cat",
        "echo", "printf", "sqlite3", "python3", "python", "which", "type",
        "realpath", "readlink", "dirname", "basename", "sort", "uniq",
        "cut", "tr", "diff", "du", "df", "free", "uptime", "true", "false", "cd"
    )

    matched_cmd = None
    for sc in safe_commands:
        if cmd == sc or cmd.startswith(sc + " "):
            matched_cmd = sc
            break

    if not matched_cmd:
        if cmd == "env" or cmd == "printenv" or cmd.startswith("printenv "):
            return True
        return False

    if matched_cmd == "find":
        danger_find = ("-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fls")
        if any(df in cmd for df in danger_find):
            return False

    if matched_cmd == "sort":
        if " -o " in cmd or cmd.endswith(" -o") or "--output" in cmd:
            return False

    if matched_cmd in ("git diff", "git log", "git show", "git branch", "git remote"):
        if "--output" in cmd or " -d " in cmd or " -D " in cmd or "--delete" in cmd or " set-url " in cmd or " add " in cmd or " remove " in cmd:
            return False

    if matched_cmd == "sqlite3":
        danger_sql = (".shell", ".system", ".output", ".once", "drop ", "delete ", "update ", "insert ", "alter ", "attach ")
        if any(ds in cmd_lower for ds in danger_sql):
            return False

    if matched_cmd in ("python3", "python"):
        danger_py = (
            "shutil", "os.system", "os.remove", "os.unlink", "os.rmdir", "os.popen",
            "subprocess", "rmtree", "socket", "urllib", "requests", "http.client",
            "pathlib", "open(", "write("
        )
        if any(dp in cmd for dp in danger_py):
            return False

    return True

def is_safe_fast_path(command_line: str) -> bool:
    cmd = command_line.strip()
    if not cmd:
        return False
    segments = split_compound_command(cmd)
    if not segments:
        return False
    return all(is_safe_segment(seg) for seg in segments)

def evaluate_via_free_api_key(prompt: str) -> str:
    groq_key = os.environ.get("GROQ_API_KEY", "").strip()
    if groq_key:
        try:
            req = urllib.request.Request(
                "https://api.groq.com/openai/v1/chat/completions",
                data=json.dumps({
                    "model": "llama-3.1-8b-instant",
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.0,
                    "max_tokens": 64,
                    "response_format": {"type": "json_object"}
                }).encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {groq_key}",
                    "Content-Type": "application/json",
                    "User-Agent": "lgtm/1.0"
                }
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data["choices"][0]["message"]["content"].strip()
        except Exception:
            pass

    gemini_key = (os.environ.get("LGTM_GEMINI_API_KEY") or os.environ.get("GEMINI_API_KEY") or "").strip()
    if gemini_key:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-lite:generateContent?key={gemini_key}"
            req = urllib.request.Request(
                url,
                data=json.dumps({
                    "contents": [{"role": "user", "parts": [{"text": prompt}]}],
                    "generationConfig": {
                        "temperature": 0.0,
                        "maxOutputTokens": 64,
                        "responseMimeType": "application/json",
                        "thinkingConfig": {"thinkingBudget": 0}
                    }
                }).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                parts = data.get("candidates", [{}])[0].get("content", {}).get("parts", [])
                return "".join(p.get("text", "") for p in parts if not p.get("thought")).strip()
        except Exception:
            pass

    return ""

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

        fast_deny_reason = check_fast_deny(command_line)
        if fast_deny_reason:
            print(json.dumps({"decision": "deny", "reason": fast_deny_reason}))
            return

        if is_safe_fast_path(command_line):
            print(json.dumps({"decision": "allow", "reason": "Fast-path: Safe read command"}))
            return

        prompt = (
            "You are a second set of eyes reviewing shell commands before they execute. "
            "The commands are generated by an experienced, trusted AI agent actively working on the user's machine. "
            "The agent is highly capable, NOT untrustworthy. You are only here to catch rare, catastrophic oversights.\n\n"
            "GUIDELINES:\n"
            "1. DEFAULT TO ALLOWING the command. Trust the agent's intent. Normal development workflows (creating, modifying, or executing scripts, even in /tmp) are perfectly safe.\n"
            "2. ALLOW all standard tools and complex scripts unconditionally.\n"
            "3. DENY ONLY if the command is a clear and catastrophic mistake (e.g., 'rm -rf /', wiping critical system directories) or an explicit secret leak.\n\n"
            f"Command to evaluate:\n```\n{command_line}\n```\n\n"
            'Respond with ONLY a raw JSON object (no markdown): {"decision": "allow"|"deny", "reason": "<brief reason>"}'
        )

        llm_response = evaluate_via_free_api_key(prompt)

        daemon_script = os.path.join(os.path.dirname(__file__), "lgtm_daemon.py")
        
        if not llm_response:
            client, token = get_daemon_conn()
            if not client:
                if os.path.exists(daemon_script):
                    spawn_daemon(daemon_script)
                    for _ in range(400):
                        time.sleep(0.05)
                        client, token = get_daemon_conn()
                        if client:
                            break

            if client and token:
                try:
                    msg = json.dumps({"token": token, "prompt": prompt})
                    client.sendall(msg.encode("utf-8"))
                    llm_response = client.recv(65536).decode("utf-8").strip()
                except Exception:
                    llm_response = ""
                finally:
                    client.close()

        if llm_response:
            parsed_check = extract_json_payload(llm_response)
            if parsed_check:
                reason = parsed_check.get("reason", "")
                if is_network_error(reason):
                    llm_response = ""
            else:
                llm_response = ""

        if not llm_response:
            # Fallback to slow mode with isolated gemini directory
            setup_isolated_gemini_dir()
            eval_env = os.environ.copy()
            eval_env["AGY_HOOK_BYPASS"] = "1"
            last_err = "Empty response from Gemini API"
            for attempt in range(MAX_RETRIES):
                try:
                    stream_input = json.dumps({"event": "user", "message": {"content": prompt}}) + "\n"
                    result = subprocess.run(
                        [
                            "agy",
                            f"--gemini_dir={LGTM_GEMINI_DIR}",
                            "--disable-slash-commands",
                            "--input-format", "stream-json",
                            "--output-format", "stream-json",
                            "--model", "gemini-3.8-flash-low"
                        ],
                        input=stream_input,
                        capture_output=True, text=True, env=eval_env, cwd=tempfile.gettempdir(), timeout=20
                    )
                    out = result.stdout.strip()
                    err = result.stderr.strip()
                    if out:
                        for line in out.splitlines():
                            try:
                                res = json.loads(line)
                                if res.get("event") == "result":
                                    result_obj = res.get("result", {})
                                    if result_obj.get("status") != "ERROR":
                                        raw_resp = result_obj.get("response", "")
                                        parsed_check = extract_json_payload(raw_resp)
                                        if parsed_check and "decision" in parsed_check:
                                            llm_response = json.dumps(parsed_check)
                                            break
                                    else:
                                        err = result_obj.get("error", "Unknown error")
                            except Exception:
                                pass
                        if llm_response:
                            break
                    last_err = err or out or "Empty response from Gemini API"
                    if attempt < MAX_RETRIES - 1 and (is_network_error(err) or is_network_error(out) or not out):
                        time.sleep(1.0 * (attempt + 1))
                        continue
                except subprocess.TimeoutExpired:
                    last_err = "Command timed out"
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(1.0 * (attempt + 1))
                        continue
                except Exception as e:
                    last_err = str(e)
                    break

        if not llm_response:
            print(json.dumps({"decision": "deny", "reason": f"API Error: {last_err}"}))
            return
            
        parsed_response = extract_json_payload(llm_response)
        if parsed_response and "decision" in parsed_response:
            print(json.dumps(parsed_response))
        elif parsed_response:
            print(json.dumps({"decision": "deny", "reason": "Invalid response schema"}))
        else:
            print(json.dumps({"decision": "deny", "reason": f"Failed to parse LLM JSON: {llm_response}"}))
            
    except Exception as e:
        print(json.dumps({"decision": "deny", "reason": f"Hook exception: {str(e)}"}))

if __name__ == "__main__":
    main()
