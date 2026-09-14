"""phish_triage — exception-only triage of a user-reported phishing queue.

The pipeline is: a source adapter produces a `Queue`, `rules.triage` sorts every
item into handled-by-automation / automation-gap / exception and works only the
exceptions, and `report` renders the handover an analyst actually reads.

The engine never fetches a URL, opens an attachment, contacts a sender, or
executes a response action. It recommends, with the decision owner named.
"""
from .config import Config
from .models import Action, Category, Finding, Lane, Priority, Queue, ReportedMessage, TriageResult
from .rules import triage, triage_message

__version__ = "0.1.0"

__all__ = [
    "Action", "Category", "Config", "Finding", "Lane", "Priority", "Queue",
    "ReportedMessage", "TriageResult", "triage", "triage_message", "__version__",
]
