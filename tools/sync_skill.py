#!/usr/bin/env python3
"""Copy the canonical header parser into the Claude skill bundle.

The skill ships as a standalone folder, so it cannot import from `phish_triage`.
Rather than maintain two parsers, `src/phish_triage/headers.py` is written to be
dependency-free and is copied here verbatim. `tests/test_skill_bundle.py` fails
if the two drift.

    python tools/sync_skill.py          # copy
    python tools/sync_skill.py --check  # exit 1 if out of sync
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "src" / "phish_triage" / "headers.py"
TARGET = ROOT / "skills" / "phishing-inbox-triage" / "scripts" / "parse_headers.py"


def main(argv: list[str]) -> int:
    source = SOURCE.read_text()
    if "--check" in argv:
        if not TARGET.exists() or TARGET.read_text() != source:
            print(f"out of sync: {TARGET.relative_to(ROOT)} — run `python tools/sync_skill.py`", file=sys.stderr)
            return 1
        print("skill bundle in sync")
        return 0
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text(source)
    TARGET.chmod(0o755)
    print(f"synced {TARGET.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
