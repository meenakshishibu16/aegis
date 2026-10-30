import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.agent.tools import ToolContext  # noqa: E402
from aegis.config import BACKEND_DIR, INBOXES_DIR  # noqa: E402
from aegis.core.detector.pipeline import Detector  # noqa: E402
from aegis.core.events import EventBus  # noqa: E402
from aegis.core.gateway import Gateway  # noqa: E402
from aegis.core.policy import PolicyStore  # noqa: E402


@pytest.fixture
def ctx(tmp_path: Path) -> ToolContext:
    return ToolContext(run_dir=tmp_path / "run", inbox_path=INBOXES_DIR / "benign.json")


@pytest.fixture
def event_bus() -> EventBus:
    return EventBus()


@pytest.fixture
def gateway(event_bus: EventBus) -> Gateway:
    """Gateway with heuristics only (no classifier) for fast, deterministic tests."""
    return Gateway(PolicyStore(BACKEND_DIR / "policy.yaml"), Detector(classifier=None), event_bus)
