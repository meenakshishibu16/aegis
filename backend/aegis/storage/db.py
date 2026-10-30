"""SQLite persistence via SQLModel. Swap `db_url` for Postgres without code changes."""

import json
from datetime import datetime
from typing import Any

from sqlmodel import Field, Session, SQLModel, create_engine, select

from aegis.config import settings
from aegis.core.events import Event


class EventRow(SQLModel, table=True):
    id: str = Field(primary_key=True)
    session_id: str = Field(index=True)
    timestamp: datetime
    stage: str
    decision: str
    risk_score: float
    data: str  # full event JSON


class SessionRow(SQLModel, table=True):
    id: str = Field(primary_key=True)
    task: str
    protected: bool
    scenario_id: str | None = None
    started_at: datetime
    result: str = "{}"  # JSON of RunResult once finished


class ScenarioRunRow(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    scenario_id: str = Field(index=True)
    protected: bool
    created_at: datetime
    data: str  # JSON of ScenarioResult


class Store:
    def __init__(self, url: str = settings.db_url) -> None:
        self.engine = create_engine(url, connect_args={"check_same_thread": False} if url.startswith("sqlite") else {})
        SQLModel.metadata.create_all(self.engine)

    def save_event(self, event: Event) -> None:
        with Session(self.engine) as s:
            s.add(EventRow(id=event.id, session_id=event.session_id, timestamp=event.timestamp, stage=event.stage,
                           decision=event.decision, risk_score=event.risk_score, data=event.model_dump_json()))
            s.commit()

    def events(self, session_id: str | None = None, stage: str | None = None, decision: str | None = None,
               limit: int = 500) -> list[dict[str, Any]]:
        with Session(self.engine) as s:
            q = select(EventRow).order_by(EventRow.timestamp.desc()).limit(limit)
            if session_id:
                q = q.where(EventRow.session_id == session_id)
            if stage:
                q = q.where(EventRow.stage == stage)
            if decision:
                q = q.where(EventRow.decision == decision)
            return [json.loads(r.data) for r in s.exec(q)]

    def save_session(self, session_id: str, task: str, protected: bool, scenario_id: str | None, started_at: datetime,
                     result: dict[str, Any] | None = None) -> None:
        with Session(self.engine) as s:
            row = s.get(SessionRow, session_id) or SessionRow(id=session_id, task=task, protected=protected,
                                                               scenario_id=scenario_id, started_at=started_at)
            if result is not None:
                row.result = json.dumps(result, default=str)
            s.add(row)
            s.commit()

    def sessions(self, limit: int = 100) -> list[dict[str, Any]]:
        with Session(self.engine) as s:
            rows = s.exec(select(SessionRow).order_by(SessionRow.started_at.desc()).limit(limit))
            return [{**r.model_dump(exclude={"result"}), "result": json.loads(r.result)} for r in rows]

    def session(self, session_id: str) -> dict[str, Any] | None:
        with Session(self.engine) as s:
            row = s.get(SessionRow, session_id)
            return {**row.model_dump(exclude={"result"}), "result": json.loads(row.result)} if row else None

    def save_scenario_run(self, scenario_id: str, protected: bool, created_at: datetime, data: dict[str, Any]) -> None:
        with Session(self.engine) as s:
            s.add(ScenarioRunRow(scenario_id=scenario_id, protected=protected, created_at=created_at, data=json.dumps(data, default=str)))
            s.commit()

    def latest_scenario_runs(self) -> list[dict[str, Any]]:
        """Most recent run per (scenario, protected) pair."""
        with Session(self.engine) as s:
            rows = s.exec(select(ScenarioRunRow).order_by(ScenarioRunRow.created_at.desc()))
            latest: dict[tuple[str, bool], dict[str, Any]] = {}
            for r in rows:
                latest.setdefault((r.scenario_id, r.protected), json.loads(r.data))
            return list(latest.values())

    def latencies(self) -> list[tuple[str, float]]:
        with Session(self.engine) as s:
            rows = s.exec(select(EventRow).where(EventRow.stage.in_(["inspect", "authorize", "egress"])))  # type: ignore[attr-defined]
            return [(r.stage, json.loads(r.data)["latency_ms"]) for r in rows]
