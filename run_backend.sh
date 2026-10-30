#!/usr/bin/env bash
# Start the AEGIS API on http://localhost:8000
cd "$(dirname "$0")/backend"
exec ../.venv/bin/python -m uvicorn aegis.api.main:app --host 127.0.0.1 --port 8000
