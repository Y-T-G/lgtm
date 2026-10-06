$ErrorActionPreference = "Stop"

$GeminiConfigDir = Join-Path $env:USERPROFILE ".gemini\config"
$ScriptsDir = Join-Path $GeminiConfigDir "scripts"
$HooksJsonPath = Join-Path $GeminiConfigDir "hooks.json"
$RepoRawUrl = if ($env:LGTM_RAW_URL) { $env:LGTM_RAW_URL } else { "https://raw.githubusercontent.com/Y-T-G/lgtm/main" }

New-Item -Path $ScriptsDir -ItemType Directory -Force | Out-Null

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path 2>$null

# Copy or download the AI approval hook and daemon
if ($ScriptDir -and (Test-Path (Join-Path $ScriptDir "scripts\ai_approval_hook.py"))) {
    Copy-Item -Path (Join-Path $ScriptDir "scripts\ai_approval_hook.py") -Destination (Join-Path $ScriptsDir "ai_approval_hook.py") -Force
    Copy-Item -Path (Join-Path $ScriptDir "scripts\lgtm_daemon.py") -Destination (Join-Path $ScriptsDir "lgtm_daemon.py") -Force
} elseif ($ScriptDir -and (Test-Path (Join-Path $ScriptDir "ai_approval_hook.py"))) {
    Copy-Item -Path (Join-Path $ScriptDir "ai_approval_hook.py") -Destination (Join-Path $ScriptsDir "ai_approval_hook.py") -Force
    Copy-Item -Path (Join-Path $ScriptDir "lgtm_daemon.py") -Destination (Join-Path $ScriptsDir "lgtm_daemon.py") -Force
} else {
    Write-Host "Downloading LGTM scripts..."
    Invoke-WebRequest -Uri "$RepoRawUrl/scripts/ai_approval_hook.py" -OutFile (Join-Path $ScriptsDir "ai_approval_hook.py")
    Invoke-WebRequest -Uri "$RepoRawUrl/scripts/lgtm_daemon.py" -OutFile (Join-Path $ScriptsDir "lgtm_daemon.py")
}

# Configure hooks.json
if (Test-Path $HooksJsonPath) {
    Copy-Item -Path $HooksJsonPath -Destination "$HooksJsonPath.bak" -Force
}

$HooksJsonCode = @"
{
  "ai-approval-hook": {
    "PreToolUse": [
      {
        "matcher": "run_command",
        "hooks": [
          {
            "type": "command",
            "command": "python ./scripts/ai_approval_hook.py",
            "timeout": 45
          }
        ]
      }
    ]
  }
}
"@

Set-Content -Path $HooksJsonPath -Value $HooksJsonCode -Encoding UTF8

Write-Host "✅ LGTM installed! All run_command tool calls will now be evaluated by the LLM." -ForegroundColor Green
