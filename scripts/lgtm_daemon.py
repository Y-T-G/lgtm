#!/usr/bin/env python3
import socket
import os
import sys
import subprocess
import json
import time
import tempfile
import getpass
import secrets
import atexit
import shutil

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

def kill_stale_workers():
    if os.name != "nt":
        try:
            subprocess.run(["pkill", "-9", "-f", f"agy.*--gemini_dir={LGTM_GEMINI_DIR}"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

def kill_other_daemons():
    if os.name != "nt":
        my_pid = str(os.getpid())
        try:
            out = subprocess.check_output(["pgrep", "-f", "lgtm_daemon.py"], text=True)
            for pid_str in out.strip().split():
                if pid_str != my_pid:
                    try:
                        os.kill(int(pid_str), 9)
                    except OSError:
                        pass
        except Exception:
            pass

def spawn_agy():
    setup_isolated_gemini_dir()
    kill_stale_workers()
    env = os.environ.copy()
    env["AGY_HOOK_BYPASS"] = "1"
    proc = subprocess.Popen(
        [
            "agy",
            f"--gemini_dir={LGTM_GEMINI_DIR}",
            "--input-format", "stream-json",
            "--output-format", "stream-json",
            "--model", "gemini-3.8-flash-low"
        ],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=env, cwd=tempfile.gettempdir()
    )
    while True:
        line = proc.stdout.readline()
        if not line or "init" in line:
            break
    return proc

def main():
    if os.path.exists(PORT_FILE):
        try:
            with open(PORT_FILE, "r", encoding="utf-8") as f:
                port_str, _ = f.read().strip().split(":", 1)
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(1.0)
            test_sock.connect(("127.0.0.1", int(port_str)))
            test_sock.close()
            return
        except Exception:
            try:
                os.remove(PORT_FILE)
            except OSError:
                pass

    kill_other_daemons()
    kill_stale_workers()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]
    server.listen(5)

    auth_token = secrets.token_hex(16)
    with open(PORT_FILE, "w", encoding="utf-8") as f:
        f.write(f"{port}:{auth_token}")

    proc = spawn_agy()
    count = 0

    def cleanup():
        try:
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except Exception:
                    proc.kill()
        except Exception:
            pass
        kill_stale_workers()
        if os.path.exists(PORT_FILE):
            try:
                os.remove(PORT_FILE)
            except OSError:
                pass
        shutil.rmtree(LGTM_GEMINI_DIR, ignore_errors=True)

    atexit.register(cleanup)

    while True:
        conn = None
        try:
            conn, _ = server.accept()
            data = conn.recv(65536).decode("utf-8")
            if not data:
                continue

            req = json.loads(data)
            if req.get("token") != auth_token:
                conn.sendall(b'{"decision": "deny", "reason": "unauthorized"}')
                continue

            prompt = req.get("prompt", "")
            payload = {"event": "user", "message": {"content": prompt}}

            response = ""
            for attempt in range(MAX_RETRIES):
                if proc.poll() is not None:
                    proc = spawn_agy()

                try:
                    proc.stdin.write(json.dumps(payload) + "\n")
                    proc.stdin.flush()
                except (BrokenPipeError, OSError):
                    proc = spawn_agy()
                    try:
                        proc.stdin.write(json.dumps(payload) + "\n")
                        proc.stdin.flush()
                    except Exception:
                        pass

                raw_response = ""
                err_msg = ""
                is_error = False

                while True:
                    line = proc.stdout.readline()
                    if not line:
                        is_error = True
                        err_msg = "EOF reading from agy stream"
                        break
                    try:
                        res = json.loads(line)
                        if res.get("event") == "result":
                            result_obj = res.get("result", {})
                            if result_obj.get("status") == "ERROR":
                                is_error = True
                                err_msg = result_obj.get("error", "Unknown error")
                            else:
                                raw_response = result_obj.get("response", "")
                            break
                    except Exception:
                        pass

                if is_error and is_network_error(err_msg):
                    if attempt < MAX_RETRIES - 1:
                        try:
                            if proc and proc.poll() is None:
                                proc.terminate()
                                try:
                                    proc.wait(timeout=2)
                                except Exception:
                                    proc.kill()
                        except Exception:
                            pass
                        kill_stale_workers()
                        time.sleep(1.0 * (attempt + 1))
                        proc = spawn_agy()
                        continue
                    else:
                        response = json.dumps({"decision": "deny", "reason": f"API Error: {err_msg}"})
                        break
                elif is_error:
                    response = json.dumps({"decision": "deny", "reason": f"API Error: {err_msg}"})
                    break
                else:
                    parsed_obj = extract_json_payload(raw_response)
                    if parsed_obj is not None:
                        response = json.dumps(parsed_obj)
                    else:
                        response = raw_response
                    break

            conn.sendall(response.encode("utf-8"))

            count += 1
            if count >= 20:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except Exception:
                    proc.kill()
                kill_stale_workers()
                shutil.rmtree(LGTM_GEMINI_DIR, ignore_errors=True)
                proc = spawn_agy()
                count = 0

        except Exception as e:
            try:
                if conn:
                    conn.sendall(json.dumps({"decision": "deny", "reason": f"daemon error: {str(e)}"}).encode("utf-8") + b"\n")
            except Exception:
                pass
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

if __name__ == "__main__":
    main()
