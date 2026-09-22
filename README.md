<h1 align="center">lgtm</h1>

<p align="center">
  A fast local security daemon for Google Antigravity (agy). It evaluates shell commands before they run and blocks destructive actions or secret leaks.
</p>

<p align="center">
  <a href="https://github.com/Y-T-G/lgtm"><img alt="Python" src="https://img.shields.io/badge/Python-%3E%3D3.10-3776ab?logo=python&logoColor=white"></a>
  <a href="https://github.com/Y-T-G/lgtm"><img alt="agy" src="https://img.shields.io/badge/Requires-agy-0055ff"></a>
  <a href="LICENSE"><img alt="license" src="https://img.shields.io/github/license/Y-T-G/lgtm?color=blue"></a>
</p>

## Highlights

- **Persistent evaluation daemon.** Spawns an `agy` background process in stream mode. The daemon evaluates commands in 2 seconds instead of the 15 seconds required for a cold boot.
- **Fast-path for safe commands.** Commands like `ls`, `cat`, `grep` and `git status` are approved instantly without LLM evaluation.
- **Auto-fallback.** If the Gemini API is rate limited or times out, the hook falls back to a slow standalone process.
- **Token limit protection.** The background daemon restarts every 20 evaluations to prevent its context window from growing indefinitely.

## Architecture

The system uses two components:

1. **The pre-tool hook** (`ai_approval_hook.py`): Antigravity calls this script before running a command. It checks the fast-path list. If the command is not on the list, it connects to a local Unix socket.
2. **The background daemon** (`lgtm_daemon.py`): The hook spawns this daemon if it is not running. The daemon keeps an `agy` instance alive, receives prompts over the socket, feeds them into the `agy` stream, and returns the LLM's decision.

## Install

Run the install script to copy the hook and daemon to your Antigravity configuration directory:

```bash
curl -fsSL https://raw.githubusercontent.com/Y-T-G/lgtm/main/install.sh | bash
```

The script sets up `~/.gemini/config/scripts/ai_approval_hook.py` and registers it in `~/.gemini/config/hooks.json`.

### Manual Bypass

If you need to run a blocked command, you can explicitly bypass the hook by setting the environment variable:

```bash
AGY_HOOK_BYPASS=1 rm -rf build/
```

The hook reads this variable and allows the command instantly.

## License

MIT
