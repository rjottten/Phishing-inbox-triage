"""End-to-end through the command line, the way it will actually be run."""
from __future__ import annotations

import json

from phish_triage.cli import main


def test_run_writes_a_markdown_report(capsys, export_path):
    assert main(["run", "-i", str(export_path)]) == 0
    out = capsys.readouterr().out
    assert "# Phishing queue —" in out
    assert "## Exceptions needing an analyst" in out


def test_run_json_format(capsys, export_path):
    assert main(["run", "-i", str(export_path), "-f", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["total"] == 10


def test_run_writes_to_a_file(tmp_path, capsys, export_path):
    out = tmp_path / "report.md"
    assert main(["run", "-i", str(export_path), "-o", str(out)]) == 0
    assert "Phishing queue" in out.read_text()
    assert "wrote" in capsys.readouterr().err


def test_fail_on_p1_signals_through_the_exit_code(capsys, export_path):
    """A scheduled run alerts by exiting non-zero, so any runner can pick it up."""
    assert main(["run", "-i", str(export_path), "-f", "summary", "--fail-on", "p1"]) == 1
    capsys.readouterr()


def test_fail_on_never_is_the_default(capsys, export_path):
    assert main(["run", "-i", str(export_path), "-f", "summary"]) == 0
    capsys.readouterr()


def test_missing_input_is_an_error_not_a_traceback(capsys):
    assert main(["run", "-i", "/nonexistent/queue.json"]) == 2
    assert "error: could not read" in capsys.readouterr().err


def test_malformed_export_is_an_error(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text('{"nope": 1}')
    assert main(["run", "-i", str(bad)]) == 2
    assert "items" in capsys.readouterr().err


def test_message_from_raw_headers(tmp_path, capsys):
    headers = tmp_path / "raw.txt"
    headers.write_text(
        'From: "Dana Whitfield (CFO)" <dwhitfield@contoso-finance.co>\n'
        "Reply-To: dana.whitfield.cfo@gmail.com\n"
        "Subject: Urgent wire - vendor payment today\n"
        "Authentication-Results: spf=pass; dkim=pass; dmarc=none\n"
        "\n"
        "I'm stuck in board prep and can't take calls. Pay the Halvorsen invoice today via wire. Keep this between us.\n"
    )
    config = tmp_path / "config.toml"
    config.write_text('org_domain = "contoso.com"\n')
    assert main(["message", "--headers", str(headers), "-c", str(config), "--note", "I haven't replied"]) == 0
    out = capsys.readouterr().out
    assert "BEC / impersonation" in out
    assert "**Decision owner:**" in out


def test_headers_subcommand_emits_json(tmp_path, capsys):
    headers = tmp_path / "raw.txt"
    headers.write_text("From: a@b.example\nSubject: hi\n")
    assert main(["headers", str(headers)]) == 0
    assert json.loads(capsys.readouterr().out)["from"]["address"] == "a@b.example"
