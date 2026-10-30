"""Event schema and an in-process publish/subscribe bus."""

import threading
import uuid
from datetime import datetime, timezone
from typing import Callable, Literal

from pydantic import BaseModel, Field

Stage = Literal["inspect", "authorize", "egress", "agent"]
# inspect: ALLOW | SANITIZE | BLOCK   authorize/egress: ALLOW | DENY   agent: START | TOOL | TAINT | FINAL
DecisionName = Literal["ALLOW", "SANITIZE", "BLOCK", "DENY", "START", "TOOL", "TAINT", "FINAL"]


def excerpt(value: object, limit: int = 300) -> str:
    text = str(value)
    return text if len(text) <= limit else text[:limit] + "…"


class Event(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    session_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    stage: Stage
    decision: DecisionName
    risk_score: float = 0.0
    reasons: list[str] = Field(default_factory=list)
    rule_ids: list[str] = Field(default_factory=list)
    tool_name: str | None = None
    args_excerpt: str | None = None
    content_excerpt: str | None = None
    spans: list[str] = Field(default_factory=list)
    latency_ms: float = 0.0
    step: int = 0
    protected: bool = True
    scenario_id: str | None = None


Subscriber = Callable[[Event], None]


class EventBus:
    def __init__(self) -> None:
        self._subscribers: list[Subscriber] = []
        self._lock = threading.Lock()

    def subscribe(self, fn: Subscriber) -> Callable[[], None]:
        with self._lock:
            self._subscribers.append(fn)
        return lambda: self._unsubscribe(fn)

    def _unsubscribe(self, fn: Subscriber) -> None:
        with self._lock:
            if fn in self._subscribers:
                self._subscribers.remove(fn)

    def publish(self, event: Event) -> None:
        with self._lock:
            subscribers = list(self._subscribers)
        for fn in subscribers:
            fn(event)


bus = EventBus()
