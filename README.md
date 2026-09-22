<h1 align="center">LGTM</h1>

<p align="center">
  An AI-powered auto-approval hook for <a href="https://antigravity.google">Google Antigravity</a> (agy) that automatically evaluates and approves safe shell commands while pausing on dangerous ones.
</p>

<p align="center">
  <a href="https://antigravity.google"><img alt="Antigravity" src="https://img.shields.io/badge/Antigravity-agy-d97757"></a>
  <a href="https://www.gnu.org/software/bash/"><img alt="bash" src="https://img.shields.io/badge/bash-%3E%3D4.0-4eaa25?logo=gnubash&logoColor=white"></a>
  <a href="https://jqlang.github.io/jq/"><img alt="jq" src="https://img.shields.io/badge/requires-jq-1e88e5"></a>
  <a href="https://www.python.org/"><img alt="python" src="https://img.shields.io/badge/python-3-3776ab?logo=python&logoColor=white"></a>
</p>

## Highlights

- **Fast and light.** Uses `gemini-3.8-flash-low` to evaluate commands in milliseconds.
- **Smart security.** Auto-approves harmless read-only or build commands (`ls`, `npm test`), but strictly denies or asks for approval on destructive commands (`rm -rf /`).
- **Seamless integration.** Runs synchronously in the `PreToolUse` lifecycle event of Antigravity, requiring zero manual configuration after installation.

## Install

Needs `bash`, `jq`, and `python3`.

### Workspace Installation (Local)

Run the following command at the root of your project to install the hook into your `.agents/` directory:

```bash
curl -fsSL https://raw.githubusercontent.com/Y-T-G/lgtm/main/install.sh | bash
```

### Global Installation

To install the hook globally so it applies to all your Antigravity sessions on your machine:

```bash
curl -fsSL https://raw.githubusercontent.com/toxite/lgtm/main/install.sh | bash -s -- ~/.gemini/config
```

## Usage

To fully delegate permission handling to this hook and prevent Antigravity's default prompt from appearing, you must start your Antigravity sessions with the `--dangerously-skip-permissions` flag:

```bash
agy --dangerously-skip-permissions
```

Because the hook runs in the `PreToolUse` lifecycle, it will still intercept and strictly block any dangerous commands before they execute, but safe commands will now execute instantly without a secondary system prompt.

## How it works

The installer creates a Python script that hooks into the `run_command` tool execution. When Antigravity attempts to run a terminal command, the hook intercepts it and prompts a lightweight Gemini model to evaluate its safety.

The model responds with one of three decisions:
- `allow`: The command executes immediately without user intervention.
- `ask`: Antigravity pauses and prompts you for permission.
- `deny`: The command is blocked outright.

## License

MIT
