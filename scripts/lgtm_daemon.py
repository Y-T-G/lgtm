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

            # Check if child worker process is still alive, respawn if terminated
            if proc.poll() is not None:
                proc = spawn_agy()

            prompt = req.get("prompt", "")
            payload = {"event": "user", "message": {"content": prompt}}

            try:
                proc.stdin.write(json.dumps(payload) + "\n")
                proc.stdin.flush()
            except (BrokenPipeError, OSError):
                # Worker died or pipe broken; respawn and retry once
                proc = spawn_agy()
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
                            response = json.dumps({"decision": "deny", "reason": f"API Error: {err_msg}"})
                        else:
                            response = result_obj.get("response", "")
                    except Exception:
                        pass
                    break

            if response.startswith("```json"):
                response = response.split("```json")[1].split("```")[0].strip()
            elif response.startswith("```"):
                response = response.split("```")[1].split("```")[0].strip()

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

