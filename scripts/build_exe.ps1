param(
    [string]$PythonExe = ".\.venv\Scripts\python.exe"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

if (-not (Test-Path $PythonExe)) {
    throw "Python executable not found at $PythonExe. Recreate the venv with Python 3.12+ first."
}

& $PythonExe -c "import sys; assert sys.version_info >= (3, 12), sys.version"
& $PythonExe -m PyInstaller --noconfirm --clean organizer.spec

Write-Host "Built executable: $repoRoot\dist\Organizer.exe"
