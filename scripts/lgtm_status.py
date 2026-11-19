#!/usr/bin/env python3
import getpass
import json
import os
import sys
import tempfile

try:
    import fcntl
except ImportError:
    fcntl = None

USER = getpass.getuser()
PORT_FILE = os.path.join(tempfile.gettempdir(), f"lgtm_daemon_{USER}.port")
LOCK_FILE = os.path.join(tempfile.gettempdir(), f"lgtm_daemon_{USER}.lock")
HOOKS_FILE = os.path.expanduser("~/.gemini/config/hooks.json")

GREEN = "\033[38;5;108m"
ORANGE = "\033[38;5;214m"
RESET = "\033[0m"

def hook_is_registered() -> bool:
    if not os.path.exists(HOOKS_FILE):
        return False
    try:
        with open(HOOKS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return isinstance(data, dict) and "lgtm-hook" in data
    except Exception:
        return False

def daemon_is_warm() -> bool:
    if fcntl is not None and os.path.exists(LOCK_FILE):
        fd = None
        try:
            fd = os.open(LOCK_FILE, os.O_RDONLY)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(fd, fcntl.LOCK_UN)
            return False
        except OSError:
            return os.path.exists(PORT_FILE)
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
    return os.path.exists(PORT_FILE)

def main():
    if os.environ.get("LGTM_STATUSLINE", "1").strip().lower() in ("0", "false", "no", "off"):
        return
    if not hook_is_registered():
        return
    if os.environ.get("AGY_HOOK_BYPASS") == "1":
        sys.stdout.write(f"{ORANGE}lgtm off{RESET}")
    elif daemon_is_warm():
        sys.stdout.write(f"{GREEN}● lgtm{RESET}")
    else:
        sys.stdout.write(f"{GREEN}○ lgtm{RESET}")

if __name__ == "__main__":
    main()
