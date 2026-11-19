$ErrorActionPreference = "Stop"

$GeminiConfigDir = Join-Path $env:USERPROFILE ".gemini\config"
$ScriptsDir = Join-Path $GeminiConfigDir "scripts"
$CliSettingsDir = Join-Path $env:USERPROFILE ".gemini\antigravity-cli"
$SettingsFile = Join-Path $CliSettingsDir "settings.json"
$HooksJsonPath = Join-Path $GeminiConfigDir "hooks.json"
$RepoRawUrl = if ($env:LGTM_RAW_URL) { $env:LGTM_RAW_URL } else { "https://raw.githubusercontent.com/Y-T-G/lgtm/main" }

New-Item -Path $ScriptsDir -ItemType Directory -Force | Out-Null
New-Item -Path $CliSettingsDir -ItemType Directory -Force | Out-Null

$ScriptDir = if ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path } else { $null }

# Copy or download the AI approval hook and daemon
if ($ScriptDir -and (Test-Path (Join-Path $ScriptDir "scripts\lgtm_hook.py"))) {
    $srcDir = Join-Path $ScriptDir "scripts"
    if ((Resolve-Path $srcDir).Path -ne (Resolve-Path $ScriptsDir).Path) {
        Copy-Item -Path (Join-Path $srcDir "lgtm_hook.py") -Destination (Join-Path $ScriptsDir "lgtm_hook.py") -Force
        Copy-Item -Path (Join-Path $srcDir "lgtm_daemon.py") -Destination (Join-Path $ScriptsDir "lgtm_daemon.py") -Force
    }
} elseif ($ScriptDir -and (Test-Path (Join-Path $ScriptDir "lgtm_hook.py"))) {
    if ((Resolve-Path $ScriptDir).Path -ne (Resolve-Path $ScriptsDir).Path) {
        Copy-Item -Path (Join-Path $ScriptDir "lgtm_hook.py") -Destination (Join-Path $ScriptsDir "lgtm_hook.py") -Force
        Copy-Item -Path (Join-Path $ScriptDir "lgtm_daemon.py") -Destination (Join-Path $ScriptsDir "lgtm_daemon.py") -Force
    }
} else {
    Write-Host "Downloading LGTM scripts..."
    Invoke-WebRequest -Uri "$RepoRawUrl/scripts/lgtm_hook.py" -OutFile (Join-Path $ScriptsDir "lgtm_hook.py")
    Invoke-WebRequest -Uri "$RepoRawUrl/scripts/lgtm_daemon.py" -OutFile (Join-Path $ScriptsDir "lgtm_daemon.py")
}

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

# Update Antigravity settings to always-proceed
if (Test-Path $SettingsFile) {
    Copy-Item -Path $SettingsFile -Destination "$SettingsFile.bak" -Force
    try {
        $settings = Get-Content -Path $SettingsFile -Raw | ConvertFrom-Json
    } catch {
        $settings = New-Object PSObject
    }
} else {
    $settings = New-Object PSObject
}
if ($null -eq $settings) {
    $settings = New-Object PSObject
}
$settings | Add-Member -NotePropertyName "toolPermission" -NotePropertyValue "always-proceed" -Force
[System.IO.File]::WriteAllText($SettingsFile, (($settings | ConvertTo-Json -Depth 10) + "`n"), $utf8NoBom)

# Merge lgtm-hook into hooks.json without clobbering existing hooks
if (Test-Path $HooksJsonPath) {
    Copy-Item -Path $HooksJsonPath -Destination "$HooksJsonPath.bak" -Force
    try {
        $hooks = Get-Content -Path $HooksJsonPath -Raw | ConvertFrom-Json
    } catch {
        $hooks = New-Object PSObject
    }
} else {
    $hooks = New-Object PSObject
}
if ($null -eq $hooks) {
    $hooks = New-Object PSObject
}

$lgtmHookEntry = [ordered]@{
    PreToolUse = @(
        [ordered]@{
            matcher = "run_command"
            hooks   = @(
                [ordered]@{
                    type    = "command"
                    command = "python ./scripts/lgtm_hook.py"
                    timeout = 45
                }
            )
        }
    )
}
$hooks | Add-Member -NotePropertyName "lgtm-hook" -NotePropertyValue $lgtmHookEntry -Force
[System.IO.File]::WriteAllText($HooksJsonPath, (($hooks | ConvertTo-Json -Depth 10) + "`n"), $utf8NoBom)

Write-Host "✅ LGTM installed! All run_command tool calls will now be evaluated by the LLM." -ForegroundColor Green
