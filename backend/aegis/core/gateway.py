"""Single entry point for all AEGIS checks. Every check emits an Event."""

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from aegis.config import settings
from aegis.core import policy as policy_engine
from aegis.core import taint
from aegis.core.detector.classifier import get_classifier
from aegis.core.detector.pipeline import DetectionResult, Detector
from aegis.core.egress import EgressChecker
from aegis.core.events import Event, EventBus, bus, excerpt
from aegis.core.policy import Decision, PolicyStore
from aegis.core.taint import TaintState


@dataclass
class Session:
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    task: str = ""
    protected: bool = True
    scenario_id: str | None = None
    taint: TaintState = field(default_factory=TaintState)
    tool_counts: dict[str, int] = field(default_factory=dict)


class Gateway:
    def __init__(self, store: PolicyStore, detector: Detector, event_bus: EventBus = bus) -> None:
        self.store = store
        self.detector = detector
        self.bus = event_bus

    def emit(self, session: Session, **fields: Any) -> Event:
        event = Event(session_id=session.id, protected=session.protected, scenario_id=session.scenario_id, **fields)
        self.bus.publish(event)
        return event

    def inspect_content(
        self, session: Session, content: str, source: str, ref: str = "", content_type: str = "text",
        content_id: str = "", step: int = 0,
    ) -> DetectionResult:
        result = self.detector.inspect(content, content_type)
        self.emit(
            session, stage="inspect", decision=result.action, risk_score=result.score, reasons=result.reasons or ["No injection indicators"],
            rule_ids=result.rule_ids, content_excerpt=excerpt(content, 400), spans=[excerpt(s, 200) for s in result.spans[:5]],
            latency_ms=result.latency_ms, step=step, tool_name=source,
        )
        if taint.mark(session.taint, content_id, source, ref, step, self.store.get().trusted_files):
            if len(session.taint.sources) == 1:
                self.emit(session, stage="agent", decision="TAINT", risk_score=0.5, step=step,
                          reasons=[f"Session tainted by untrusted {source} content ({ref or content_id})"], rule_ids=["taint.untrusted_source"])
        return result

    def authorize_action(self, session: Session, tool: str, args: dict[str, Any], step: int = 0) -> Decision:
        start = time.perf_counter()
        decision = policy_engine.evaluate(self.store.get(), tool, args, session.tool_counts.get(tool, 0), session.taint.tainted)
        self.emit(session, stage="authorize", decision=decision.verdict, risk_score=decision.risk_score, reasons=decision.reasons,
                  rule_ids=decision.rule_ids, tool_name=tool, args_excerpt=excerpt(json.dumps(args)), step=step,
                  latency_ms=round((time.perf_counter() - start) * 1000, 2))
        return decision

    def check_egress(self, session: Session, tool: str, args: dict[str, Any], step: int = 0) -> Decision:
        start = time.perf_counter()
        decision = EgressChecker(self.store.get().egress_allow_domains).check(tool, args)
        self.emit(session, stage="egress", decision=decision.verdict, risk_score=decision.risk_score, reasons=decision.reasons,
                  rule_ids=decision.rule_ids, tool_name=tool, args_excerpt=excerpt(json.dumps(args)), step=step,
                  latency_ms=round((time.perf_counter() - start) * 1000, 2))
        return decision


def default_gateway(event_bus: EventBus = bus) -> Gateway:
    classifier = get_classifier() if settings.classifier_enabled else None
    return Gateway(PolicyStore(settings.policy_path), Detector(classifier), event_bus)
