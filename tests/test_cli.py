from __future__ import annotations

import io
import json
import sys

import pytest

from cname_watch import cli
from cname_watch.models import Verdict
from tests.helpers import make_result


@pytest.fixture
def fake_scan(monkeypatch):
    """Replace DNS and scanning with deterministic fakes."""

    captured: dict = {"domains": None}

    async def scan(domains, resolver, options, client):
        captured["domains"] = list(domains)
        captured["options"] = options
        captured["client"] = client
        return [make_result(domains[0], Verdict.DANGLING)]

    monkeypatch.setattr(cli, "scan_domains", scan)
    monkeypatch.setattr(cli, "build_resolver", lambda **kwargs: object())
    return captured


def test_main_returns_one_when_candidate_found(fake_scan, capsys):
    code = cli.main(["blog.example.com", "--no-probe"])

    assert code == 1
    output = capsys.readouterr().out
    assert "DANGLING" in output
    assert "blog.example.com" in output
    assert "Scanned 1 domain(s)" in output
    assert fake_scan["client"] is None


def test_main_quiet_suppresses_summary(fake_scan, capsys):
    code = cli.main(["blog.example.com", "--no-probe", "--quiet"])

    assert code == 1
    output = capsys.readouterr().out
    assert "DANGLING" in output
    assert "Scanned" not in output


def test_main_returns_zero_when_clean(fake_scan, monkeypatch, capsys):
    async def scan(domains, resolver, options, client):
        return [make_result(domains[0], Verdict.CLEAN, target=None, provider=None)]

    monkeypatch.setattr(cli, "scan_domains", scan)

    code = cli.main(["blog.example.com", "--no-probe"])

    assert code == 0
    assert "No takeover candidates found." in capsys.readouterr().out


def test_main_json_output(fake_scan, capsys):
    code = cli.main(["blog.example.com", "--no-probe", "--format", "json"])

    assert code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["candidates"] == 1


def test_main_writes_csv_to_file(fake_scan, tmp_path, capsys):
    destination = tmp_path / "findings.csv"

    code = cli.main(["blog.example.com", "--no-probe", "--format", "csv", "-o", str(destination)])

    assert code == 1
    assert destination.exists()
    assert destination.read_text(encoding="utf-8").startswith("domain,verdict,reason")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Wrote results" in captured.err


def test_main_reads_domains_from_file(fake_scan, tmp_path):
    source = tmp_path / "domains.txt"
    source.write_text("# comment\nblog.example.com\nhttps://www.example.com/\n", encoding="utf-8")

    code = cli.main(["-l", str(source), "--no-probe"])

    assert code == 1
    assert fake_scan["domains"] == ["blog.example.com", "www.example.com"]


def test_main_reads_domains_from_stdin(fake_scan, monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO("blog.example.com\n"))

    code = cli.main(["--no-probe"])

    assert code == 1
    assert fake_scan["domains"] == ["blog.example.com"]


def test_main_invalid_domains_return_two(capsys):
    code = cli.main(["not a domain"])

    assert code == 2
    captured = capsys.readouterr()
    assert "warning:" in captured.err
    assert "no valid domains" in captured.err


def test_main_invalid_rules_file_returns_two(fake_scan, tmp_path, capsys):
    bad_rules = tmp_path / "rules.json"
    bad_rules.write_text("{", encoding="utf-8")

    code = cli.main(["blog.example.com", "--no-probe", "--rules", str(bad_rules)])

    assert code == 2
    assert "invalid rules file" in capsys.readouterr().err


def test_main_rejects_bad_options():
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["example.com", "--timeout", "0"])
    assert excinfo.value.code == 2

    with pytest.raises(SystemExit) as excinfo:
        cli.main(["example.com", "--timeout", "nan"])
    assert excinfo.value.code == 2

    with pytest.raises(SystemExit) as excinfo:
        cli.main(["example.com", "--concurrency", "0"])
    assert excinfo.value.code == 2

    with pytest.raises(SystemExit) as excinfo:
        cli.main(["example.com", "--nameserver", "not-an-ip"])
    assert excinfo.value.code == 2


def test_version_flag():
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--version"])
    assert excinfo.value.code == 0
