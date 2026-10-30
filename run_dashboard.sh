#!/usr/bin/env bash
# Start the dashboard on http://localhost:5173
cd "$(dirname "$0")/dashboard"
exec npm run dev
