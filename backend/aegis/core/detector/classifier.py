"""Pretrained prompt-injection classifier (protectai/deberta-v3-base-prompt-injection-v2).

Long content is split into overlapping ~512-token windows; the max score wins.
The model is loaded lazily, once per process.
"""

import threading
from dataclasses import dataclass
from typing import Any

from aegis.config import settings

WINDOW_TOKENS = 510
STRIDE_TOKENS = 384
INJECTION_LABEL = "INJECTION"


@dataclass
class ClassifierResult:
    score: float
    chunk_index: int
    chunk_text: str
    n_chunks: int


class Classifier:
    def __init__(self, model_id: str = settings.classifier_model) -> None:
        self.model_id = model_id
        self._lock = threading.Lock()
        self._tokenizer: Any = None
        self._model: Any = None

    def _load(self) -> None:
        with self._lock:
            if self._model is not None:
                return
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer

            torch.set_num_threads(max(1, torch.get_num_threads()))
            self._tokenizer = AutoTokenizer.from_pretrained(self.model_id)
            self._model = AutoModelForSequenceClassification.from_pretrained(self.model_id).eval()
            self._injection_idx = self._model.config.label2id.get(INJECTION_LABEL, 1)

    def chunks(self, text: str) -> list[str]:
        self._load()
        ids = self._tokenizer(text, add_special_tokens=False)["input_ids"]
        if len(ids) <= WINDOW_TOKENS:
            return [text]
        out = []
        for start in range(0, len(ids), STRIDE_TOKENS):
            out.append(self._tokenizer.decode(ids[start:start + WINDOW_TOKENS]))
            if start + WINDOW_TOKENS >= len(ids):
                break
        return out

    def score(self, text: str) -> ClassifierResult:
        import torch

        chunks = self.chunks(text)
        with torch.inference_mode():
            enc = self._tokenizer(chunks, truncation=True, max_length=512, padding=True, return_tensors="pt")
            probs = torch.softmax(self._model(**enc).logits, dim=-1)[:, self._injection_idx]
        best = int(torch.argmax(probs))
        return ClassifierResult(float(probs[best]), best, chunks[best], len(chunks))


_default: Classifier | None = None


def get_classifier() -> Classifier:
    global _default
    if _default is None:
        _default = Classifier()
    return _default
