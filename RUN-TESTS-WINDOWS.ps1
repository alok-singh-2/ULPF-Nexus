$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$Backend = Join-Path $ProjectRoot "backend"
Set-Location $ProjectRoot

$Python = Join-Path $Backend ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) {
    throw "Virtual environment not found. Run .\START-WINDOWS.ps1 first."
}

$env:PYTHONPATH = $ProjectRoot
& $Python -m pytest -q
