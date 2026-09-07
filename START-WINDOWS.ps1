$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$Backend = Join-Path $ProjectRoot "backend"
Set-Location $Backend

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    Write-Host "Creating Python virtual environment..."
    py -3.14 -m venv .venv
}

$Python = Join-Path $Backend ".venv\Scripts\python.exe"

Write-Host "Installing/verifying dependencies..."
& $Python -m pip install -r requirements.txt

Write-Host "Starting ULPF Nexus on http://127.0.0.1:8000"
& $Python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
