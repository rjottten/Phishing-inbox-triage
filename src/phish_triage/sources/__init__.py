"""Source adapters: whatever the queue lives in, out comes a `Queue` of `ReportedMessage`.

Adding a source means implementing one function that returns a `Queue`. The rules
engine and the report writer never learn where the data came from.
"""
from .defender_csv import inspect as inspect_csv
from .defender_csv import load_queue as load_defender_csv
from .json_export import load_queue, parse_queue

__all__ = ["load_queue", "parse_queue", "load_defender_csv", "inspect_csv"]
