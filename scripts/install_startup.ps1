param(
    [string]$ExePath = ".\dist\Organizer.exe"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$resolvedExe = Resolve-Path $ExePath -ErrorAction Stop
$startupDir = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup"
New-Item -ItemType Directory -Path $startupDir -Force | Out-Null
$cmdPath = Join-Path $startupDir "OrganizerWatcher.cmd"
$logDir = Join-Path $env:LOCALAPPDATA "Organizer"
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$logPath = Join-Path $logDir "autostart.log"

$content = @(
    '@echo off',
    "echo %DATE% %TIME% launching \"$resolvedExe\" --startup >> \"$logPath\" 2>&1",
    "start \"\" /B \"$resolvedExe\" --startup >> \"$logPath\" 2>&1",
    'exit /b 0'
) -join "`r`n"

Set-Content -Path $cmdPath -Value $content -Encoding UTF8
Write-Host "Startup entry created: $cmdPath"
