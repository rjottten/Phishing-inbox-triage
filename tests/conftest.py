from __future__ import annotations

from pathlib import Path

import pytest

from phish_triage import Config, triage
from phish_triage.sources.json_export import load_queue

ROOT = Path(__file__).resolve().parent.parent
EXPORT = ROOT / "test-data" / "mailbox_export.json"


@pytest.fixture(scope="session")
def queue():
    return load_queue(EXPORT)


@pytest.fixture(scope="session")
def results(queue):
    """Triaged sample queue. `now` comes from the export window, so this is stable."""
    return triage(queue, Config())


@pytest.fixture(scope="session")
def by_id(results):
    return {r.message.id: r for r in results}
