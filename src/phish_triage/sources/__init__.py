"""Source adapters: whatever the queue lives in, out comes a `Queue` of `ReportedMessage`.

Adding a source means implementing one function that returns a `Queue`. The rules
engine and the report writer never learn where the data came from.
"""
from .json_export import load_queue, parse_queue

__all__ = ["load_queue", "parse_queue"]
