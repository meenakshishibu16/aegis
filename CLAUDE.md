# AEGIS — notes for Claude / contributors

Runtime security layer for tool-using LLM agents. A hackathon project (Zero Trust track) that must run fully locally on a CPU-only Windows laptop.

## Architecture

```
user task ─► agent/loop.py (Ollama qwen2.5:3b, temp 0)
               │ tool call
               ├─► gateway.authorize_action  → core/policy.py (allow/deny, arg constraints, rate limit, taint rule)
               ├─► gateway.check_egress      → core/egress.py (send_email, fetch_url, rendered markdown images)
               ▼
           agent/tools.py (mock tools, per-session state in backend/runs/<session>/)
               │ output
               ├─► gateway.inspect_content   → core/detector/pipeline.py (heuristics → classifier) + core/taint.py
               ▼
   <untrusted source=… id=…> spotlighted content enters the context
Every check → core/events.py Event → EventBus → SQLite (storage/db.py) + WebSocket (/ws/events)
```

- `protected=False` skips every hook (the "before" agent). `protected=True` runs all of them and also inspects the user prompt.
- Detection is heuristics + `protectai/deberta-v3-base-prompt-injection-v2` (Apache-2.0, labels SAFE/INJECTION, 512 tokens). Long text is split into overlapping windows; the max score wins. A heuristic score ≥ block threshold short-circuits the classifier.
- Actions: score ≥ `BLOCK_THRESHOLD` (0.85) → BLOCK, ≥ `SANITIZE_THRESHOLD` (0.5) → SANITIZE (flagged spans redacted), else ALLOW.
- Taint: web and email content always taints the session; files taint unless listed in `trusted_files`. Taint is sticky. Tools with `if_tainted: deny` are refused afterwards.
- Egress: every value in `sandbox/workspace/secrets.env` is a canary. Canary anywhere outbound → DENY (risk 1.0). Secrets, PII and long URL query values → DENY only for non-allowlisted destinations.
- `fetch_url` never touches the network: `*.test` hosts are served from `simulator/attack_server/<host>/`; everything else returns an error.
- Out of scope (deliberately): LLM judge, intent alignment, approval queue, policy editor, SDK, ONNX, PDF/DOCX, run_code.

## Layout

- `backend/aegis/` — `config.py`, `llm.py` (Ollama / recording / replay / scripted clients), `core/`, `agent/`, `api/main.py`, `storage/db.py`, `simulator.py`
- `backend/policy.yaml` — the one policy (hot-reloaded on file change)
- `backend/cassettes/` — recorded LLM responses `<scenario>__on|off.json`
- `simulator/scenarios/*.yaml` — 6 scenarios (5 attacks, 1 benign); `inboxes/`, `attack_server/` hold their assets; `runner.py` is the CLI
- `dashboard/` — Vite + React + TS + Tailwind + Recharts single page (Attack Lab, Live Feed, Stats)

## Commands (from repo root)

```
.\setup.ps1                       # one-time (or ./setup.sh)
.\run_backend.ps1                 # API on :8000
.\run_dashboard.ps1               # UI on :5173
.venv\Scripts\python -m pytest backend          # tests (no Ollama needed)
.venv\Scripts\python simulator\runner.py         # all scenarios OFF vs ON, live
.venv\Scripts\python simulator\runner.py --record   # also save cassettes for runs that behaved as expected
.venv\Scripts\python simulator\runner.py --replay   # deterministic, from cassettes
```

## Event schema (`core/events.py`)

| field | type | notes |
|---|---|---|
| id, session_id | str | |
| timestamp | datetime (UTC) | |
| stage | `inspect` \| `authorize` \| `egress` \| `agent` | |
| decision | inspect: `ALLOW` `SANITIZE` `BLOCK`; authorize/egress: `ALLOW` `DENY`; agent: `START` `TOOL` `TAINT` `FINAL` | |
| risk_score | float 0..1 | |
| reasons, rule_ids | list[str] | rule ids like `send_email.recipient_domains`, `heur.hidden_instruction`, `clf.injection`, `egress.canary` |
| tool_name, args_excerpt, content_excerpt | str? | for inspect, `tool_name` is the content source (`web`, `email`, `user`) |
| spans | list[str] | detected spans (for highlighting) |
| latency_ms, step, protected, scenario_id | | |

## Conventions

- Type hints everywhere; dataclasses for internal results, Pydantic for config/policy/events/API.
- Tests never call Ollama: use `ScriptedClient` + `tool_call()` / `final()` from `aegis.llm`. The `gateway` fixture runs heuristics only; `test_classifier.py` loads the real model.
- Never add real network calls, real email, or code execution. New attack assets go under `simulator/` with `.test` domains.
- Keep it small and readable; prefer one obvious module over layers of abstraction.
