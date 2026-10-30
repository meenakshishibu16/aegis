# Start the AEGIS API on http://localhost:8000
Set-Location "$PSScriptRoot\backend"
& "$PSScriptRoot\.venv\Scripts\python.exe" -m uvicorn aegis.api.main:app --host 127.0.0.1 --port 8000
