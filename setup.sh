#!/usr/bin/env bash
# One-time setup on Linux/macOS: Python venv, backend deps, dashboard deps, Ollama model.
set -euo pipefail
cd "$(dirname "$0")"

[ -d .venv ] || python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r backend/requirements.txt
[ -f .env ] || cp .env.example .env

(cd dashboard && npm install)
ollama pull qwen2.5:3b
echo "Setup complete. Start the backend with ./run_backend.sh and the dashboard with ./run_dashboard.sh"
