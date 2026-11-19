#!/usr/bin/env python3
import sys
import json
import os
import re
import shlex
import posixpath
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

def setup_isolated_gemini_dir(target_dir: str = None):
    base_dir = target_dir or LGTM_GEMINI_DIR
    cli_dir = os.path.join(base_dir, "antigravity-cli")
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
    client = None
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
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
        return None, None

def spawn_daemon(daemon_script):
    eval_env = os.environ.copy()
    eval_env["AGY_HOOK_BYPASS"] = "1"
    kwargs = {
        "env": eval_env,
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
    }
    if os.name == "nt":
        flags = 0
        for name in ("CREATE_NEW_PROCESS_GROUP", "DETACHED_PROCESS", "CREATE_NO_WINDOW"):
            flags |= getattr(subprocess, name, 0)
        kwargs["creationflags"] = flags
    else:
        kwargs["start_new_session"] = True
    subprocess.Popen([sys.executable, daemon_script], **kwargs)

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

def normalize_decision_payload(obj):
    if not isinstance(obj, dict) or "decision" not in obj:
        return None
    decision = str(obj.get("decision", "")).strip().lower()
    if decision not in ("allow", "deny"):
        return None
    reason = obj.get("reason", "")
    if reason is None:
        reason = ""
    return {"decision": decision, "reason": str(reason)}

def _recv_all(sock: socket.socket, max_bytes: int = 1048576) -> str:
    chunks = []
    total = 0
    while total < max_bytes:
        chunk = sock.recv(65536)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace").strip()

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

CRITICAL_FILES = frozenset({
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/fstab",
    "/etc/hosts.allow",
})

CRITICAL_OS_DIRS = frozenset({
    "/",
    "/bin", "/boot", "/dev", "/etc", "/lib", "/lib64",
    "/proc", "/sbin", "/sys", "/system", "/usr",
    "/vendor", "/apex", "/product",
})

def _build_critical_dirs():
    dirs = set(CRITICAL_OS_DIRS)
    dirs.update({
        "/home", "/opt", "/root", "/run", "/srv", "/var",
        "/data", "/data/data", "/data/user", "/data/user_de",
        "/data/system", "/data/adb",
        "/storage", "/storage/emulated", "/storage/emulated/0",
        "~", "$home", "${home}",
    })
    home = os.path.expanduser("~")
    if home and home != "~":
        for candidate in (home, os.path.realpath(home)):
            norm = posixpath.normpath(candidate.replace("\\", "/")).lower()
            if norm and norm != "/":
                dirs.add(norm)
    return frozenset(dirs)

CRITICAL_DIRS = _build_critical_dirs()

ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
DD_BLOCK_RE = re.compile(r"^of=/dev/(?:block|sd|nvme|mmcblk|vd|hd|loop|disk|dm-|mapper/|mtd|md)")
SAFE_REDIRECT_INLINE_RE = re.compile(
    r"(?:(?:[12]|&)?>>?[ \t]*/dev/null|2>&1|1>&2)(?=$|[ \t;&|])"
)
SSH_IDENTITY_RE = re.compile(
    r"(?:(?<=\s)-i[ \t]*['\"]?[^\s'\"]*\.ssh/id_[^\s'\"]*['\"]?"
    r"|(?<=\s)identityfile[= \t]+['\"]?[^\s'\"]*\.ssh/id_[^\s'\"]*['\"]?)",
    re.IGNORECASE,
)

def _extract_command_segments(cmd: str):
    """Best-effort split of shell command into unquoted segments, recursing into subshells."""
    segments = []
    cur = []
    in_single = False
    in_double = False
    escaped = False
    i = 0
    n = len(cmd)

    def flush():
        seg = "".join(cur).strip()
        if seg:
            segments.append(seg)
        cur.clear()

    while i < n:
        c = cmd[i]
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

        if not in_single and c == "$" and i + 1 < n and cmd[i + 1] == "(":
            depth = 1
            j = i + 2
            sub_in_s = False
            sub_in_d = False
            sub_esc = False
            while j < n and depth > 0:
                sc = cmd[j]
                if sub_esc:
                    sub_esc = False
                elif sc == "\\" and not sub_in_s:
                    sub_esc = True
                elif sc == "'" and not sub_in_d:
                    sub_in_s = not sub_in_s
                elif sc == '"' and not sub_in_s:
                    sub_in_d = not sub_in_d
                elif not sub_in_s and not sub_in_d:
                    if sc == "(":
                        depth += 1
                    elif sc == ")":
                        depth -= 1
                j += 1
            inner = cmd[i + 2 : j - 1 if depth == 0 else j]
            segments.extend(_extract_command_segments(inner))
            cur.append(cmd[i:j])
            i = j
            continue

        if not in_single and c == "`":
            j = i + 1
            sub_esc = False
            while j < n:
                sc = cmd[j]
                if sub_esc:
                    sub_esc = False
                elif sc == "\\":
                    sub_esc = True
                elif sc == "`":
                    break
                j += 1
            inner = cmd[i + 1 : j]
            segments.extend(_extract_command_segments(inner))
            cur.append(cmd[i : j + 1])
            i = j + 1
            continue

        if not in_single and not in_double:
            if c in (";", "\n", "\r"):
                flush()
                i += 1
                continue
            if c in ("|", "&"):
                flush()
                if i + 1 < n and cmd[i + 1] == c:
                    i += 2
                else:
                    i += 1
                continue
            if c in ("(", ")"):
                flush()
                i += 1
                continue

        cur.append(c)
        i += 1

    flush()
    return segments

def _tokenize_segment(seg: str):
    try:
        return shlex.split(seg, posix=True)
    except ValueError:
        return seg.split()

def _unwrap_tokens(tokens):
    nested = []
    idx = 0
    n = len(tokens)
    while idx < n:
        tok = tokens[idx]
        if ENV_ASSIGN_RE.match(tok):
            idx += 1
            continue
        base = os.path.basename(tok).lower()
        if base in ("command", "nohup", "time", "exec", "builtin"):
            idx += 1
            while idx < n and tokens[idx].startswith("-"):
                idx += 1
            continue
        if base == "busybox":
            idx += 1
            continue
        if base == "env":
            idx += 1
            while idx < n and (tokens[idx].startswith("-") or ENV_ASSIGN_RE.match(tokens[idx])):
                if tokens[idx] in ("-u", "-C", "--unset", "--chdir") and idx + 1 < n:
                    idx += 2
                else:
                    idx += 1
            continue
        if base == "sudo":
            idx += 1
            while idx < n and tokens[idx].startswith("-"):
                if tokens[idx] in ("-u", "-g", "-C", "-p", "-r", "-t", "-h", "-U") and idx + 1 < n:
                    idx += 2
                else:
                    idx += 1
            continue
        if base == "nice":
            idx += 1
            while idx < n and tokens[idx].startswith("-"):
                if tokens[idx] == "-n" and idx + 1 < n:
                    idx += 2
                else:
                    idx += 1
            continue
        if base == "timeout":
            idx += 1
            while idx < n and tokens[idx].startswith("-"):
                if tokens[idx] in ("-k", "-s", "--kill-after", "--signal") and idx + 1 < n:
                    idx += 2
                else:
                    idx += 1
            if idx < n:
                idx += 1
            continue
        if base in ("sh", "bash", "zsh", "dash", "ash", "ksh", "su"):
            j = idx + 1
            while j < n:
                t = tokens[j]
                if t == "-c" and j + 1 < n:
                    nested.append(tokens[j + 1])
                    break
                if t.startswith("-") and not t.startswith("--") and "c" in t[1:] and j + 1 < n:
                    nested.append(tokens[j + 1])
                    break
                j += 1
            return base, tokens[idx + 1 :], nested
        return base, tokens[idx + 1 :], nested
    return "", [], nested

def _normalize_path_for_deny(raw: str):
    p = raw.strip()
    if not p:
        return "", False
    is_glob = False
    if re.search(r"/+\.?[*?]+$", p):
        is_glob = True
        p = re.sub(r"/+\.?[*?]+$", "", p) or "/"
    p = re.sub(r"/+", "/", p)
    if p.startswith("/"):
        norm = posixpath.normpath(p)
        if norm.startswith("//"):
            norm = "/" + norm.lstrip("/")
        return norm.lower(), is_glob
    p_trimmed = p.rstrip("/")
    return p_trimmed.lower(), is_glob

def _check_rm_catastrophic(args):
    is_recursive = False
    no_preserve_root = False
    targets = []
    after_double_dash = False

    for arg in args:
        if not after_double_dash and arg == "--":
            after_double_dash = True
            continue
        if not after_double_dash and arg.startswith("-") and arg != "-":
            if arg.startswith("--"):
                if arg == "--recursive":
                    is_recursive = True
                elif arg == "--no-preserve-root":
                    no_preserve_root = True
            else:
                flags = arg[1:]
                if "r" in flags or "R" in flags:
                    is_recursive = True
        else:
            targets.append(arg)

    for target in targets:
        norm, is_glob = _normalize_path_for_deny(target)
        if not norm:
            continue
        if norm in CRITICAL_FILES and not is_glob:
            return "Fast-deny: Critical system file deletion"
        if norm == "/" and (is_recursive or no_preserve_root or is_glob):
            return "Fast-deny: Catastrophic filesystem deletion"
        if is_glob and norm in CRITICAL_OS_DIRS:
            return "Fast-deny: Catastrophic filesystem deletion"
        if is_recursive and norm in CRITICAL_DIRS:
            return "Fast-deny: Catastrophic filesystem deletion"
    return None

def _check_unquoted_critical_redirect(seg: str):
    in_single = False
    in_double = False
    escaped = False
    i = 0
    n = len(seg)
    while i < n:
        c = seg[i]
        if escaped:
            escaped = False
            i += 1
            continue
        if c == "\\" and not in_single:
            escaped = True
            i += 1
            continue
        if c == "'" and not in_double:
            in_single = not in_single
            i += 1
            continue
        if c == '"' and not in_single:
            in_double = not in_double
            i += 1
            continue
        if not in_single and not in_double and c == ">":
            j = i + 1
            if j < n and seg[j] == ">":
                j += 1
            if j < n and seg[j] == "&":
                i = j + 1
                continue
            while j < n and seg[j] in (" ", "\t"):
                j += 1
            k = j
            t_in_s = False
            t_in_d = False
            while k < n:
                tc = seg[k]
                if tc == "'" and not t_in_d:
                    t_in_s = not t_in_s
                elif tc == '"' and not t_in_s:
                    t_in_d = not t_in_d
                elif not t_in_s and not t_in_d and tc in (" ", "\t", ";", "|", "&", "<", ">"):
                    break
                k += 1
            raw_target = seg[j:k].strip().strip("'\"")
            norm, _ = _normalize_path_for_deny(raw_target)
            if norm in CRITICAL_FILES:
                return "Fast-deny: Critical system file overwrite"
            i = k
            continue
        i += 1
    return None

def _check_find_catastrophic(args):
    roots = []
    idx = 0
    n = len(args)
    while idx < n and args[idx] in ("-H", "-L", "-P"):
        idx += 1
    while idx < n:
        a = args[idx]
        if a.startswith("-") or a in ("!", "(", ")"):
            break
        roots.append(a)
        idx += 1
    predicates = args[idx:]
    has_critical_root = any(_normalize_path_for_deny(r)[0] in CRITICAL_DIRS for r in roots)
    if not has_critical_root:
        return None
    for j, p in enumerate(predicates):
        if p == "-delete":
            return "Fast-deny: Destructive root find operation"
        if p in ("-exec", "-execdir", "-ok", "-okdir") and j + 1 < len(predicates):
            if os.path.basename(predicates[j + 1]).lower() == "rm":
                return "Fast-deny: Destructive root find operation"
    return None

def _check_segment_fast_deny(seg: str, depth: int = 0):
    if depth > 4:
        return None
    redir_reason = _check_unquoted_critical_redirect(seg)
    if redir_reason:
        return redir_reason

    tokens = _tokenize_segment(seg)
    if not tokens:
        return None
    cmd_name, args, nested_scripts = _unwrap_tokens(tokens)

    for script in nested_scripts:
        for sub_seg in _extract_command_segments(script):
            reason = _check_segment_fast_deny(sub_seg, depth + 1)
            if reason:
                return reason

    if cmd_name == "rm":
        return _check_rm_catastrophic(args)

    if cmd_name == "dd":
        for a in args:
            if DD_BLOCK_RE.match(a.lower()):
                return "Fast-deny: Raw block device overwrite"

    if cmd_name == "mkfs" or cmd_name.startswith("mkfs."):
        for a in args:
            if a.lower().startswith("/dev/"):
                return "Fast-deny: Partition format"

    if cmd_name == "find":
        return _check_find_catastrophic(args)

    return None

def check_fast_deny(command_line: str):
    cmd = command_line.strip()
    if not cmd:
        return None

    segments = _extract_command_segments(cmd)
    for seg in segments:
        reason = _check_segment_fast_deny(seg)
        if reason:
            return reason

    cmd_lower = cmd.lower()
    has_general_net = bool(re.search(r"\b(?:curl|wget|nc|ncat|netcat)\b", cmd_lower))
    has_ssh_net = bool(re.search(r"\b(?:ssh|scp|rsync)\b", cmd_lower))
    if has_general_net or has_ssh_net:
        check_str = cmd_lower
        if has_ssh_net and not has_general_net:
            check_str = SSH_IDENTITY_RE.sub(" ", check_str)
        if any(sp in check_str for sp in SENSITIVE_PATTERNS):
            return "Fast-deny: Potential credential exfiltration over network"
    return None

def split_compound_command(cmd: str):
    """Split command on top-level |, &&, ||, ; while rejecting substitutions and unsafe redirects."""
    in_single = False
    in_double = False
    escaped = False
    i = 0
    n = len(cmd)
    segments = []
    cur = []

    while i < n:
        c = cmd[i]
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
            if c == "$" and i + 1 < n and cmd[i + 1] in ("(", "{"):
                return None
            cur.append(c)
            i += 1
            continue
        if not in_single and not in_double:
            # Handle safe redirects inline only when unquoted and properly bounded
            if c in ("1", "2", "&", ">"):
                prev_ok = (i == 0) or (cmd[i - 1] in (" ", "\t", ";", "|", "&")) or (c == ">" and cmd[i - 1] not in ("0", "1", "2", "3", "4", "5", "6", "7", "8", "9"))
                if prev_ok:
                    m = SAFE_REDIRECT_INLINE_RE.match(cmd, i)
                    if m:
                        cur.append(" ")
                        i = m.end()
                        continue
            if c in ("`", "$", ">", "<", "\n", "\r", "(", ")"):
                return None
            if c == ";":
                segments.append("".join(cur).strip())
                cur = []
                i += 1
                continue
            if c in ("|", "&"):
                if i + 1 < n and cmd[i + 1] == c:
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

DANGER_SQL_RE = re.compile(
    r"(?:^|[\s\"';])\.(?:sh(?:ell)?|sy(?:stem)?|ou(?:tput)?|on(?:ce)?|lo(?:ad|g)?|"
    r"im(?:port)?|re(?:ad|store)?|ba(?:ckup)?|sa(?:ve)?|cl(?:one)?|ar(?:chive)?|"
    r"ed(?:it)?|op(?:en)?)\b|"
    r"\b(?:drop|delete|update|insert|replace|alter|attach|detach|create|vacuum|reindex|load_extension)\b",
    re.IGNORECASE,
)

DANGER_PY_RE = re.compile(
    r"\b(?:shutil|subprocess|rmtree|socket|urllib|requests|httpx|aiohttp|ftplib|smtplib|"
    r"pathlib|ctypes|pty|importlib|runpy|webbrowser|__import__)\b|"
    r"http\.client|"
    r"\bos\.(?:system|remove|unlink|rmdir|removedirs|popen|exec\w*|spawn\w*|kill\w*|"
    r"chmod|chown|rename|replace|truncate|mkdir|makedirs|symlink|link|open)\b|"
    r"\bfrom\s+os\s+import\b|"
    r"\b(?:open|write|exec|eval|compile|getattr)\s*\("
)

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
        if cmd == sc or (cmd.startswith(sc) and cmd[len(sc)].isspace()):
            matched_cmd = sc
            break

    if not matched_cmd:
        if cmd == "env" or cmd == "printenv" or (cmd.startswith("printenv") and cmd[len("printenv")].isspace()):
            return True
        return False

    if matched_cmd == "find":
        danger_find = ("-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fls")
        if any(df in cmd for df in danger_find):
            return False

    if matched_cmd == "fd":
        tokens = _tokenize_segment(cmd)[1:]
        for t in tokens:
            if t in ("-x", "-X", "--exec", "--exec-batch") or t.startswith("--exec="):
                return False
            if t.startswith("-") and not t.startswith("--") and ("x" in t[1:] or "X" in t[1:]):
                return False

    if matched_cmd == "rg":
        if "--pre" in cmd:
            return False

    if matched_cmd == "sort":
        if re.search(r"(?:^|\s)-[a-zA-Z]*o(?:\s|$|\S)|--output", cmd):
            return False

    if matched_cmd == "uniq":
        tokens = _tokenize_segment(cmd)[1:]
        positional = []
        skip_next = False
        for idx, t in enumerate(tokens):
            if skip_next:
                skip_next = False
                continue
            if t in ("-f", "-s", "-w", "--skip-fields", "--skip-chars", "--check-chars"):
                skip_next = True
                continue
            if t == "--":
                positional.extend(tokens[idx + 1 :])
                break
            if not t.startswith("-") or t == "-":
                positional.append(t)
        if len(positional) >= 2:
            return False

    if matched_cmd == "date":
        tokens = _tokenize_segment(cmd)[1:]
        for t in tokens:
            if t == "--":
                break
            if t == "--set" or t.startswith("--set="):
                return False
            if t.startswith("-") and not t.startswith("--"):
                if t.startswith(("-I", "-d", "-f", "-r")):
                    continue
                if "s" in t[1:]:
                    return False

    if matched_cmd in ("git diff", "git log", "git show"):
        if "--output" in cmd or "--ext-diff" in cmd:
            return False

    if matched_cmd == "git branch":
        tokens = _tokenize_segment(cmd)[2:]
        mutating_flags = ("--delete", "--move", "--copy", "--force", "--edit-description", "--set-upstream", "--unset-upstream")
        for t in tokens:
            if any(t == mf or t.startswith(mf + "=") for mf in mutating_flags):
                return False
            if t.startswith("-") and not t.startswith("--") and any(ch in t[1:] for ch in "dDmMcCf"):
                return False
        list_arg_flags = ("-l", "--list", "--contains", "--no-contains", "--merged", "--no-merged", "--points-at")
        if tokens and not any(t in list_arg_flags for t in tokens):
            if any(not t.startswith("-") for t in tokens):
                return False

    if matched_cmd == "git remote":
        tokens = _tokenize_segment(cmd)[2:]
        mutating_subs = ("add", "rename", "remove", "rm", "set-head", "set-branches", "set-url", "prune", "update")
        if any(t in mutating_subs for t in tokens):
            return False

    if matched_cmd == "sqlite3":
        if DANGER_SQL_RE.search(cmd):
            return False

    if matched_cmd in ("python3", "python"):
        if DANGER_PY_RE.search(cmd):
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
                    "max_tokens": 256,
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
                        "maxOutputTokens": 256,
                        "responseMimeType": "application/json",
                        "thinkingConfig": {"thinkingBudget": 0}
                    }
                }).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                candidates = data.get("candidates") or []
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    return "".join(p.get("text", "") for p in parts if not p.get("thought")).strip()
        except Exception:
            pass

    return ""

def _is_daemon_error_response(parsed_obj: dict) -> bool:
    if not isinstance(parsed_obj, dict):
        return True
    if parsed_obj.get("decision") != "deny":
        return False
    reason = str(parsed_obj.get("reason", ""))
    return reason == "unauthorized" or reason.startswith(("API Error:", "daemon error:"))

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

        daemon_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lgtm_daemon.py")

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
                    msg = json.dumps({"token": token, "prompt": prompt}) + "\n"
                    client.sendall(msg.encode("utf-8"))
                    try:
                        client.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    llm_response = _recv_all(client)
                except Exception:
                    llm_response = ""
                finally:
                    client.close()

        if llm_response:
            parsed_check = normalize_decision_payload(extract_json_payload(llm_response))
            if not parsed_check or _is_daemon_error_response(parsed_check):
                llm_response = ""
            else:
                llm_response = json.dumps(parsed_check)

        last_err = "Empty response from Gemini API"
        if not llm_response:
            # Fallback to slow mode with an isolated per-invocation gemini directory
            fallback_dir = tempfile.mkdtemp(prefix=f"lgtm_fallback_{USER}_")
            try:
                setup_isolated_gemini_dir(fallback_dir)
                eval_env = os.environ.copy()
                eval_env["AGY_HOOK_BYPASS"] = "1"
                agy_bin = shutil.which("agy") or "agy"
                for attempt in range(MAX_RETRIES):
                    try:
                        stream_input = json.dumps({"event": "user", "message": {"content": prompt}}) + "\n"
                        result = subprocess.run(
                            [
                                agy_bin,
                                f"--gemini_dir={fallback_dir}",
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
                                            parsed_check = normalize_decision_payload(extract_json_payload(raw_resp))
                                            if parsed_check:
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
            finally:
                shutil.rmtree(fallback_dir, ignore_errors=True)

        if not llm_response:
            print(json.dumps({"decision": "deny", "reason": f"API Error: {last_err}"}))
            return

        parsed_response = normalize_decision_payload(extract_json_payload(llm_response))
        if parsed_response:
            print(json.dumps(parsed_response))
        else:
            print(json.dumps({"decision": "deny", "reason": f"Invalid LLM response: {llm_response}"}))

    except Exception as e:
        print(json.dumps({"decision": "deny", "reason": f"Hook exception: {str(e)}"}))

if __name__ == "__main__":
    main()
