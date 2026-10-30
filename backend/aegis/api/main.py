"""FastAPI app: standalone check endpoints, agent/simulator runs, events, stats, and a live WebSocket."""

import asyncio
import statistics
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncIterator

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from aegis.agent.loop import run_agent
from aegis.agent.tools import ToolContext
from aegis.config import INBOXES_DIR, RUNS_DIR, settings
from aegis.core.events import Event, bus
from aegis.core.gateway import Gateway, Session, default_gateway
from aegis.core.taint import TaintSource
from aegis.llm import OllamaClient
from aegis.simulator import get_scenario, load_scenarios, run_scenario
from aegis.storage.db import Store

state: dict[str, Any] = {}


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    store = Store()
    state["store"] = store
    state["gateway"] = default_gateway()
    state["loop"] = asyncio.get_running_loop()
    state["sockets"] = set()
    unsub_db = bus.subscribe(store.save_event)
    unsub_ws = bus.subscribe(_broadcast_threadsafe)
    if settings.classifier_enabled:
        await asyncio.to_thread(state["gateway"].detector.inspect, "warm up the classifier")
    yield
    unsub_db()
    unsub_ws()


app = FastAPI(title="AEGIS", version="0.1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_methods=["*"], allow_headers=["*"])


def gateway() -> Gateway:
    return state["gateway"]


def store() -> Store:
    return state["store"]


# ---------- WebSocket ----------

def _broadcast_threadsafe(event: Event) -> None:
    loop: asyncio.AbstractEventLoop = state["loop"]
    payload = event.model_dump_json()
    for ws in list(state["sockets"]):
        asyncio.run_coroutine_threadsafe(_send(ws, payload), loop)


async def _send(ws: WebSocket, payload: str) -> None:
    try:
        await ws.send_text(payload)
    except Exception:
        state["sockets"].discard(ws)


@app.websocket("/ws/events")
async def ws_events(ws: WebSocket) -> None:
    await ws.accept()
    state["sockets"].add(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        state["sockets"].discard(ws)


# ---------- Standalone checks (AEGIS as a service) ----------

class InspectRequest(BaseModel):
    content: str
    source: str = "web"
    content_type: str = "text"
    session_id: str | None = None


class ActionRequest(BaseModel):
    tool: str
    args: dict[str, Any] = {}
    session_id: str | None = None
    tainted: bool = False


def _adhoc_session(session_id: str | None, tainted: bool = False) -> Session:
    s = Session(id=session_id or Session().id, task="api")
    if tainted:
        s.taint.sources.append(TaintSource(content_id="api", source="api", ref="caller-declared", step=0))
    return s


@app.post("/inspect")
def inspect(req: InspectRequest) -> dict[str, Any]:
    result = gateway().inspect_content(_adhoc_session(req.session_id), req.content, req.source, content_type=req.content_type)
    return result.__dict__


@app.post("/authorize")
def authorize(req: ActionRequest) -> dict[str, Any]:
    return gateway().authorize_action(_adhoc_session(req.session_id, req.tainted), req.tool, req.args).model_dump()


@app.post("/egress")
def egress(req: ActionRequest) -> dict[str, Any]:
    return gateway().check_egress(_adhoc_session(req.session_id), req.tool, req.args).model_dump()


# ---------- Agent + simulator ----------

class AgentRunRequest(BaseModel):
    task: str
    protected: bool = True
    agent_id: str = "assistant"


@app.post("/agent/run")
def agent_run(req: AgentRunRequest) -> dict[str, Any]:
    session = Session(task=req.task, protected=req.protected)
    store().save_session(session.id, req.task, req.protected, None, datetime.now(timezone.utc))
    llm = OllamaClient(settings.agent_model, settings.ollama_url, settings.ollama_num_ctx, settings.ollama_timeout_s)
    ctx = ToolContext(run_dir=RUNS_DIR / session.id, inbox_path=INBOXES_DIR / "benign.json")
    result = run_agent(req.task, req.protected, llm, ctx, gateway(), session=session).to_dict()
    store().save_session(session.id, req.task, req.protected, None, datetime.now(timezone.utc), result)
    return result


@app.get("/scenarios")
def scenarios() -> list[dict[str, Any]]:
    return [s.model_dump() for s in load_scenarios()]


@app.post("/simulator/run/{scenario_id}")
def simulator_run(scenario_id: str, protected: bool = True) -> dict[str, Any]:
    try:
        scenario = get_scenario(scenario_id)
    except KeyError:
        raise HTTPException(404, f"Unknown scenario {scenario_id}")
    try:
        result, run = run_scenario(scenario, protected, gateway())
    except FileNotFoundError as exc:
        raise HTTPException(409, str(exc))
    now = datetime.now(timezone.utc)
    store().save_session(run.session_id, scenario.user_task, protected, scenario.id, now, run.to_dict())
    payload = {**result.to_dict(), "steps": run.to_dict()["steps"]}
    store().save_scenario_run(scenario.id, protected, now, payload)
    return payload


# ---------- Read APIs ----------

@app.get("/sessions")
def sessions() -> list[dict[str, Any]]:
    return store().sessions()


@app.get("/sessions/{session_id}")
def session_detail(session_id: str) -> dict[str, Any]:
    s = store().session(session_id)
    if s is None:
        raise HTTPException(404, "Unknown session")
    return {**s, "events": store().events(session_id=session_id)}


@app.get("/events")
def events(session_id: str | None = None, stage: str | None = None, decision: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
    return store().events(session_id, stage, decision, limit)


@app.get("/policy")
def policy() -> dict[str, Any]:
    return gateway().store.get().model_dump()


@app.get("/config")
def config() -> dict[str, Any]:
    return {"replay_mode": settings.replay_mode, "agent_model": settings.agent_model,
            "classifier_model": settings.classifier_model if settings.classifier_enabled else None}


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    return round(statistics.quantiles(values, n=100, method="inclusive")[int(pct) - 1], 2)


@app.get("/stats")
def stats() -> dict[str, Any]:
    runs = store().latest_scenario_runs()
    attacks = [r for r in runs if r["kind"] == "attack"]
    off = [r for r in attacks if not r["protected"]]
    on = [r for r in attacks if r["protected"]]
    benign_on = [r for r in runs if r["kind"] == "benign" and r["protected"]]

    by_stage: dict[str, int] = {}
    for e in store().events(limit=5000):
        if e["decision"] in ("BLOCK", "DENY", "SANITIZE"):
            by_stage[e["stage"]] = by_stage.get(e["stage"], 0) + 1

    lat: dict[str, list[float]] = {}
    for stage, ms in store().latencies():
        lat.setdefault(stage, []).append(ms)
    latency = {s: {"p50": _percentile(v, 50), "p95": _percentile(v, 95), "n": len(v)} for s, v in lat.items()}

    def rate(rs: list[dict[str, Any]]) -> float | None:
        return round(sum(r["condition_met"] for r in rs) / len(rs), 3) if rs else None

    return {
        "attack_success_rate_off": rate(off),
        "attack_success_rate_on": rate(on),
        "attacks_run_off": len(off),
        "attacks_run_on": len(on),
        "false_positive_rate": round(sum(r["aegis_decision"] == "BLOCKED" for r in benign_on) / len(benign_on), 3) if benign_on else None,
        "blocks_by_stage": by_stage,
        "latency_ms": latency,
        "scenario_runs": runs,
    }
