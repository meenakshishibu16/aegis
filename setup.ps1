# One-time setup on Windows: Python venv, backend deps, dashboard deps, Ollama model.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path .venv)) { py -3.13 -m venv .venv }
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
if (-not (Test-Path .env)) { Copy-Item .env.example .env }

Push-Location dashboard
npm install
Pop-Location

ollama pull qwen2.5:3b
Write-Host "Setup complete. Start the backend with .\run_backend.ps1 and the dashboard with .\run_dashboard.ps1"
