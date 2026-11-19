#!/usr/bin/env python3
import socket
import os
import sys
import re
import select
import signal
import subprocess
import json
import time
import tempfile
import getpass
import secrets
import atexit
import shutil

try:
    import fcntl
except ImportError:
    fcntl = None

USER = getpass.getuser()
PORT_FILE = os.path.join(tempfile.gettempdir(), f"lgtm_daemon_{USER}.port")
LOCK_FILE = os.path.join(tempfile.gettempdir(), f"lgtm_daemon_{USER}.lock")
LGTM_GEMINI_DIR = os.path.join(tempfile.gettempdir(), f"lgtm_gemini_{USER}")
MAX_RETRIES = 3
INIT_TIMEOUT = 20.0
EVAL_TIMEOUT = 22.0
CLIENT_READ_TIMEOUT = 5.0
MAX_REQUEST_BYTES = 4 * 1024 * 1024

def is_network_error(msg: str) -> bool:
    if not msg:
        return False
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
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass
    if "```" in text:
        parts = text.split("```")
        for i in range(1, len(parts), 2):
            block = re.sub(r"^json[a-zA-Z0-9_-]*\s*", "", parts[i].strip(), flags=re.IGNORECASE)
            try:
                obj = json.loads(block)
                if isinstance(obj, dict):
                    return obj
            except Exception:
                pass
    decoder = json.JSONDecoder()
    idx = 0
    while True:
        brace = text.find("{", idx)
        if brace == -1:
            break
        try:
            obj, _ = decoder.raw_decode(text, brace)
            if isinstance(obj, dict):
                return obj
        except Exception:
            pass
        idx = brace + 1
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
            pattern = f"agy.*--gemini_dir={re.escape(LGTM_GEMINI_DIR)}"
            subprocess.run(
                ["pkill", "-9", "-f", pattern],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass

def reset_conversation_state():
    cli_dir = os.path.join(LGTM_GEMINI_DIR, "antigravity-cli")
    conv_dir = os.path.join(cli_dir, "conversations")
    shutil.rmtree(conv_dir, ignore_errors=True)
    for name in ("conversation_summaries.db", "conversation_summaries.db-shm", "conversation_summaries.db-wal", "jetbox_summaries_proto.pb"):
        p = os.path.join(cli_dir, name)
        if os.path.exists(p):
            try:
                os.remove(p)
            except OSError:
                pass

class AgyProcess:
    def __init__(self, proc: subprocess.Popen):
        self.proc = proc
        self._buf = bytearray()

    def poll(self):
        return self.proc.poll()

    def write_json_line(self, payload: dict):
        raw = (json.dumps(payload) + "\n").encode("utf-8")
        self.proc.stdin.write(raw)
        self.proc.stdin.flush()

    def readline(self, timeout: float):
        """Read one UTF-8 line with timeout. Returns (line, timed_out). Empty line + False = EOF."""
        nl = self._buf.find(b"\n")
        if nl != -1:
            line = bytes(self._buf[: nl + 1])
            del self._buf[: nl + 1]
            return line.decode("utf-8", errors="replace"), False

        if os.name == "nt":
            line = self.proc.stdout.readline()
            return line.decode("utf-8", errors="replace"), False

        fd = self.proc.stdout.fileno()
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return "", True
            ready, _, _ = select.select([fd], [], [], remaining)
            if not ready:
                return "", True
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                return "", False
            if not chunk:
                if self._buf:
                    line = bytes(self._buf)
                    self._buf.clear()
                    return line.decode("utf-8", errors="replace"), False
                return "", False
            self._buf.extend(chunk)
            nl = self._buf.find(b"\n")
            if nl != -1:
                line = bytes(self._buf[: nl + 1])
                del self._buf[: nl + 1]
                return line.decode("utf-8", errors="replace"), False

    def stop(self, wait_timeout: float = 3.0):
        try:
            if self.proc and self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=wait_timeout)
                except Exception:
                    self.proc.kill()
                    try:
                        self.proc.wait(timeout=1.0)
                    except Exception:
                        pass
        except Exception:
            pass
        for stream in (self.proc.stdin, self.proc.stdout):
            if stream:
                try:
                    stream.close()
                except Exception:
                    pass

def spawn_agy() -> AgyProcess:
    setup_isolated_gemini_dir()
    kill_stale_workers()
    env = os.environ.copy()
    env["AGY_HOOK_BYPASS"] = "1"
    agy_bin = shutil.which("agy") or "agy"
    kwargs = {
        "stdin": subprocess.PIPE,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.DEVNULL,
        "bufsize": 0,
        "env": env,
        "cwd": tempfile.gettempdir(),
    }
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    raw_proc = subprocess.Popen(
        [
            agy_bin,
            f"--gemini_dir={LGTM_GEMINI_DIR}",
            "--disable-slash-commands",
            "--input-format", "stream-json",
            "--output-format", "stream-json",
            "--model", "gemini-3.8-flash-low"
        ],
        **kwargs,
    )
    worker = AgyProcess(raw_proc)
    deadline = time.monotonic() + INIT_TIMEOUT
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        line, timed_out = worker.readline(remaining)
        if timed_out or not line:
            break
        try:
            evt = json.loads(line)
            if isinstance(evt, dict) and evt.get("event") == "init":
                break
        except Exception:
            if '"init"' in line:
                break
    return worker

def _acquire_instance_lock():
    if fcntl is None:
        return None
    flags = os.O_RDWR | os.O_CREAT
    fd = os.open(LOCK_FILE, flags, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return False
    try:
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, f"{os.getpid()}\n".encode("utf-8"))
    except OSError:
        pass
    return fd

def _write_port_file_atomic(content: str):
    tmp_dir = os.path.dirname(PORT_FILE) or tempfile.gettempdir()
    fd, tmp_path = tempfile.mkstemp(prefix=f".lgtm_port_{USER}_", dir=tmp_dir)
    try:
        if os.name != "nt":
            try:
                os.fchmod(fd, 0o600)
            except OSError:
                pass
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
        os.replace(tmp_path, PORT_FILE)
    except Exception:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise

def _recv_request(conn: socket.socket):
    conn.settimeout(CLIENT_READ_TIMEOUT)
    buf = bytearray()
    while len(buf) < MAX_REQUEST_BYTES:
        try:
            chunk = conn.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        buf.extend(chunk)
        if b"\n" in chunk:
            break
        # Backwards compatibility with older hooks that omit trailing newline and SHUT_WR
        stripped = buf.strip()
        if stripped.endswith(b"}"):
            try:
                return json.loads(stripped.decode("utf-8"))
            except Exception:
                pass
    text = buf.decode("utf-8", errors="replace").strip()
    if not text:
        return None
    return json.loads(text)

def main():
    lock_fd = _acquire_instance_lock()
    if lock_fd is False:
        return

    if os.path.exists(PORT_FILE):
        test_sock = None
        try:
            with open(PORT_FILE, "r", encoding="utf-8") as f:
                port_str, _ = f.read().strip().split(":", 1)
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(1.0)
            test_sock.connect(("127.0.0.1", int(port_str)))
            return
        except Exception:
            try:
                os.remove(PORT_FILE)
            except OSError:
                pass
        finally:
            if test_sock is not None:
                try:
                    test_sock.close()
                except Exception:
                    pass

    kill_stale_workers()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]
    server.listen(16)

    auth_token = secrets.token_hex(16)
    port_content = f"{port}:{auth_token}"
    proc = None
    cleaned_up = False

    def cleanup():
        nonlocal cleaned_up
        if cleaned_up:
            return
        cleaned_up = True
        try:
            server.close()
        except Exception:
            pass
        if proc is not None:
            proc.stop(wait_timeout=3.0)
        kill_stale_workers()
        if os.path.exists(PORT_FILE):
            try:
                with open(PORT_FILE, "r", encoding="utf-8") as f:
                    cur = f.read().strip()
                if cur == port_content:
                    os.remove(PORT_FILE)
            except OSError:
                pass
        shutil.rmtree(LGTM_GEMINI_DIR, ignore_errors=True)
        if isinstance(lock_fd, int):
            try:
                os.close(lock_fd)
            except OSError:
                pass

    atexit.register(cleanup)

    def handle_signal(signum, frame):
        cleanup()
        sys.exit(0)

    for sig_name in ("SIGTERM", "SIGINT"):
        sig = getattr(signal, sig_name, None)
        if sig is not None:
            try:
                signal.signal(sig, handle_signal)
            except Exception:
                pass

    proc = spawn_agy()
    _write_port_file_atomic(port_content)
    count = 0

    while True:
        conn = None
        try:
            conn, _ = server.accept()
            req = _recv_request(conn)
            if not isinstance(req, dict):
                continue

            if req.get("token") != auth_token:
                conn.sendall(b'{"decision": "deny", "reason": "unauthorized"}\n')
                continue

            prompt = req.get("prompt", "")
            payload = {"event": "user", "message": {"content": prompt}}

            response = ""
            for attempt in range(MAX_RETRIES):
                if proc is None or proc.poll() is not None:
                    proc = spawn_agy()

                try:
                    proc.write_json_line(payload)
                except (BrokenPipeError, OSError):
                    if proc is not None:
                        proc.stop(wait_timeout=1.0)
                    proc = spawn_agy()
                    try:
                        proc.write_json_line(payload)
                    except Exception:
                        pass

                raw_response = ""
                err_msg = ""
                is_error = False

                eval_deadline = time.monotonic() + EVAL_TIMEOUT
                while True:
                    remaining = eval_deadline - time.monotonic()
                    if remaining <= 0:
                        is_error = True
                        err_msg = "Timeout reading from agy stream"
                        break
                    line, timed_out = proc.readline(remaining)
                    if timed_out:
                        is_error = True
                        err_msg = "Timeout reading from agy stream"
                        break
                    if not line:
                        is_error = True
                        err_msg = "EOF reading from agy stream"
                        break
                    try:
                        res = json.loads(line)
                        if isinstance(res, dict) and res.get("event") == "result":
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
                        proc.stop(wait_timeout=2.0)
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

            conn.sendall((response + "\n").encode("utf-8"))
            try:
                conn.close()
                conn = None
            except Exception:
                pass

            count += 1
            if count >= 20:
                proc.stop(wait_timeout=5.0)
                kill_stale_workers()
                reset_conversation_state()
                proc = spawn_agy()
                count = 0

        except Exception as e:
            try:
                if conn:
                    conn.sendall((json.dumps({"decision": "deny", "reason": f"daemon error: {str(e)}"}) + "\n").encode("utf-8"))
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
