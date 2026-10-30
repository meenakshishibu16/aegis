"""Layered detection: extraction -> heuristics -> classifier (short-circuits on a strong heuristic hit)."""

import time
from dataclasses import dataclass, field
from typing import Literal, Protocol

from aegis.config import settings
from aegis.core.detector import heuristics
from aegis.core.detector.classifier import ClassifierResult
from aegis.core.detector.extract import html_to_text

Action = Literal["ALLOW", "SANITIZE", "BLOCK"]
REDACTED = "[REDACTED BY AEGIS]"


class Scorer(Protocol):
    def score(self, text: str) -> ClassifierResult: ...


@dataclass
class DetectionResult:
    score: float
    label: Literal["benign", "suspicious", "injection"]
    action: Action
    triggered_layers: list[str] = field(default_factory=list)
    spans: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    rule_ids: list[str] = field(default_factory=list)
    latency_ms: float = 0.0
    sanitized_text: str = ""


class Detector:
    def __init__(
        self,
        classifier: Scorer | None = None,
        block_threshold: float = settings.block_threshold,
        sanitize_threshold: float = settings.sanitize_threshold,
    ) -> None:
        self.classifier = classifier
        self.block_threshold = block_threshold
        self.sanitize_threshold = sanitize_threshold

    def inspect(self, content: str, content_type: str = "text") -> DetectionResult:
        start = time.perf_counter()
        if content_type == "html":
            ext = html_to_text(content)
            text, hidden = ext.full_text, ext.hidden_segments
        else:
            text, hidden = content, []

        findings = heuristics.scan(text, hidden)
        score = heuristics.combined_score(findings)
        layers = ["heuristics"] if findings else []
        reasons = sorted({f.reason for f in findings})
        rule_ids = sorted({f.rule_id for f in findings})
        spans = [f.text for f in findings if f.text]

        # Short-circuit: a strong heuristic hit is enough to block without the model.
        if score < self.block_threshold and self.classifier is not None:
            clf = self.classifier.score(text)
            if clf.score >= self.sanitize_threshold:
                layers.append("classifier")
                reasons.append(f"Classifier injection score {clf.score:.2f} (chunk {clf.chunk_index + 1}/{clf.n_chunks})")
                rule_ids.append("clf.injection")
                if not spans:
                    spans.append(clf.chunk_text)
            score = max(score, clf.score)

        if score >= self.block_threshold:
            action: Action = "BLOCK"
        elif score >= self.sanitize_threshold:
            action = "SANITIZE"
        else:
            action = "ALLOW"

        sanitized = text
        if action == "SANITIZE":
            for span in sorted(set(spans), key=len, reverse=True):
                sanitized = sanitized.replace(span, REDACTED)

        label = "injection" if action == "BLOCK" else "suspicious" if action == "SANITIZE" else "benign"
        return DetectionResult(
            score=round(score, 4),
            label=label,
            action=action,
            triggered_layers=layers,
            spans=spans,
            reasons=reasons,
            rule_ids=rule_ids,
            latency_ms=round((time.perf_counter() - start) * 1000, 2),
            sanitized_text=sanitized,
        )
