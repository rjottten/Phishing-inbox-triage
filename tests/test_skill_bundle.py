"""The Claude skill ships standalone, so its vendored copies must not drift."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILL = ROOT / "skills" / "phishing-inbox-triage"


def test_header_parser_copy_is_in_sync():
    assert subprocess.run([sys.executable, str(ROOT / "tools" / "sync_skill.py"), "--check"]).returncode == 0


def test_vendored_parser_runs_without_the_package(tmp_path):
    """It must work when the skill folder is unzipped on its own."""
    headers = tmp_path / "raw.txt"
    headers.write_text("From: a@b.example\nSubject: Urgent wire\n")
    proc = subprocess.run(
        [sys.executable, str(SKILL / "scripts" / "parse_headers.py"), str(headers)],
        capture_output=True, text=True, cwd=tmp_path,
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["flags"] == ["urgency_or_finance_subject"]


def test_skill_has_the_files_its_frontmatter_promises():
    assert (SKILL / "SKILL.md").exists()
    for name in ("exception-criteria.md", "response-actions.md", "report-template.md"):
        assert (SKILL / "references" / name).exists(), name
    assert (SKILL / "evals" / "evals.json").exists()


def test_skill_frontmatter_is_well_formed():
    text = (SKILL / "SKILL.md").read_text()
    assert text.startswith("---\n")
    front = text.split("---", 2)[1]
    assert "name: phishing-inbox-triage" in front
    assert "description:" in front


def test_eval_file_points_at_files_that_exist():
    evals = json.loads((SKILL / "evals" / "evals.json").read_text())
    for case in evals["evals"]:
        for rel in case.get("files", []):
            assert (ROOT / rel).exists(), f"eval {case['id']} references missing {rel}"
