"""Session taint tracking.

A session becomes tainted the moment content from an untrusted source enters
the agent's context, even if the detector passed it. Taint never clears.
"""

import fnmatch
from dataclasses import dataclass, field

UNTRUSTED_SOURCES = {"web", "email"}


@dataclass
class TaintSource:
    content_id: str
    source: str
    ref: str
    step: int


@dataclass
class TaintState:
    sources: list[TaintSource] = field(default_factory=list)

    @property
    def tainted(self) -> bool:
        return bool(self.sources)

    @property
    def tainted_at_step(self) -> int | None:
        return self.sources[0].step if self.sources else None


def is_untrusted(source: str, ref: str, trusted_files: list[str]) -> bool:
    if source in UNTRUSTED_SOURCES:
        return True
    if source == "file":
        return not any(fnmatch.fnmatch(ref, pattern) for pattern in trusted_files)
    return False


def mark(state: TaintState, content_id: str, source: str, ref: str, step: int, trusted_files: list[str]) -> bool:
    """Record taint if the content is untrusted. Returns True if this content tainted the session."""
    if not is_untrusted(source, ref, trusted_files):
        return False
    state.sources.append(TaintSource(content_id, source, ref, step))
    return True
