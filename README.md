<h1 align="center">lgtm</h1>

<p align="center">
  A fast local security daemon that uses an LLM to auto approve shell commands for Google Antigravity (agy), blocking destructive actions and secret leaks before they run.
</p>

<p align="center">
  <a href="https://github.com/Y-T-G/lgtm"><img alt="Python" src="https://img.shields.io/badge/Python-%3E%3D3.10-3776ab?logo=python&logoColor=white"></a>
  <a href="https://github.com/Y-T-G/lgtm"><img alt="agy" src="https://img.shields.io/badge/Requires-agy-0055ff"></a>
  <a href="LICENSE"><img alt="license" src="https://img.shields.io/github/license/Y-T-G/lgtm?color=blue"></a>
</p>

## Highlights

- **Persistent evaluation daemon.** Spawns an `agy` background process in stream mode. The daemon evaluates commands in ~2 seconds instead of the ~15 seconds required for a cold boot.
- **Fast-path allow & fast-deny.** Read-only commands (`ls`, `cat`, `grep`, `git status`, etc.) and unambiguous destructive patterns (`rm -rf /`, partition overwrites, credential exfiltration) resolve locally in milliseconds without LLM latency.
- **Optional direct API fast-lane.** Automatically uses `GROQ_API_KEY` or `LGTM_GEMINI_API_KEY` / `GEMINI_API_KEY` if set in the environment, falling back to the local `agy` daemon seamlessly.
- **Auto-fallback.** If the daemon fails, times out, or hits transient network errors, the hook falls back to an isolated standalone `agy` process with retries.
- **Token limit protection.** The background daemon restarts every 20 evaluations to prevent its context window from growing indefinitely.

## Why LGTM vs. Built-in Auto Mode

Antigravity CLI includes a built-in Auto mode (`--mode auto`), but `lgtm` provides several advantages:

- **Universal Platform Support**: Native Auto mode requires an OS-level terminal sandbox (Seatbelt on macOS, user namespaces on Linux, or ZeroG microVMs). On Android/Termux, WSL, or systems where container namespaces are restricted, native Auto mode is disabled. `lgtm` runs purely in user space anywhere `agy` and Python run.
- **No Account Entitlement Restrictions**: Native Auto mode is server-side gated by Google account tier. `lgtm` works across any standard Google account.
- **Sub-100ms Fast-Path**: Common inspection and read commands (`ls`, `git status`, `cat`, `grep`, etc.) resolve locally in Python in ~0.10s without network latency or LLM token overhead.
- **Customizable Safety Policy**: Fast-path commands, blacklisted tokens, and review criteria are fully configurable in `lgtm_hook.py`.

## Architecture

The system uses two components:

1. **The pre-tool hook** (`lgtm_hook.py`): Antigravity calls this script before running a command. It runs local fast-deny and fast-path checks first. If LLM review is needed, it checks optional API keys (`GROQ_API_KEY`, `LGTM_GEMINI_API_KEY` / `GEMINI_API_KEY`) or sends the prompt to the local daemon over a token-authenticated localhost TCP socket (`127.0.0.1`).
2. **The background daemon** (`lgtm_daemon.py`): The hook spawns this daemon if it is not running. The daemon keeps an isolated `agy` instance alive, receives prompts over localhost TCP, feeds them into the `agy` stream, and returns the LLM's decision.

## Install

Run the install script to copy the hook and daemon to your Antigravity configuration directory:

**Mac/Linux:**
```bash
curl -fsSL https://raw.githubusercontent.com/Y-T-G/lgtm/main/install.sh | bash
```

**Windows:**
```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Y-T-G/lgtm/main/install.ps1" -OutFile "$env:TEMP\install.ps1"; & "$env:TEMP\install.ps1"
```

The script sets up `~/.gemini/config/scripts/lgtm_hook.py`, merges `lgtm-hook` into `~/.gemini/config/hooks.json`, and updates `~/.gemini/antigravity-cli/settings.json` to enable `toolPermission: "always-proceed"`.

`always-proceed` is currently required due to an upstream bug in the `agy` CLI where hook approval does not automatically bypass the interactive tool permission prompt (tracked in [google-antigravity/antigravity-cli#1059](https://github.com/google-antigravity/antigravity-cli/issues/1059)).

### Manual Bypass

If you need to launch an `agy` session with the hook disabled, set `AGY_HOOK_BYPASS=1` in the environment when starting `agy`:

```bash
AGY_HOOK_BYPASS=1 agy
```

The hook checks this environment variable on its own process and allows commands immediately.

### Statusline Indicator

The installer adds `scripts/lgtm_status.py` as `statusLine` in `~/.gemini/antigravity-cli/settings.json` when no custom statusline is already configured.

| Badge | State |
|---|---|
| `● lgtm` | Hook active and daemon running |
| `○ lgtm` | Hook active and daemon idle |
| `lgtm off` | `AGY_HOOK_BYPASS=1` is set |

Disable the indicator at runtime or during install:

| Scope | Command |
|---|---|
| Single session | `LGTM_STATUSLINE=0 agy` |
| Install on macOS and Linux | `bash install.sh --no-statusline` |
| Install on Windows | `.\install.ps1 -NoStatusline` |

If you already use a custom statusline script, call `~/.gemini/config/scripts/lgtm_status.py` from it to append the badge.

## Testing

Run the built-in test suite to verify that the security hook correctly blocks destructive actions, command injections, and secret exfiltration:

```bash
python3 test.py
# or
./test.sh
```

Run only the fast local unit tests (no LLM calls):

```bash
python3 test.py --unit
```

To test an individual command:

```bash
python3 test.py --cmd "rm -rf /"
```

To test the globally installed configuration (`~/.gemini/config/scripts/lgtm_hook.py`):

```bash
python3 test.py --installed
```

## License

MIT
