from __future__ import annotations

import csv
import io
import json

from cname_watch.models import HttpProbe, ProbeAttempt, TerminalState, Verdict
from cname_watch.report import (
    exit_code,
    render_csv,
    render_details,
    render_json,
    render_table,
    summary,
    summary_line,
)
from tests.helpers import make_match, make_result


def all_verdict_results():
    return [
        make_result("dangling.example.com", Verdict.DANGLING),
        make_result(
            "claimable.example.com",
            Verdict.CLAIMABLE,
            target="acme.s3.amazonaws.com",
            provider="Amazon S3",
            detail="Amazon S3 reports the resource as unclaimed",
        ),
        make_result(
            "clean.example.com",
            Verdict.CLEAN,
            target="app.example.net",
            provider=None,
            detail="CNAME target resolves",
        ),
        make_result(
            "missing.example.com",
            Verdict.NOT_FOUND,
            target=None,
            provider=None,
            detail="Domain does not exist",
        ),
        make_result(
            "error.example.com",
            Verdict.ERROR,
            target=None,
            provider=None,
            detail="DNS lookup failed",
        ),
    ]


def test_summary_counts():
    counts = summary(all_verdict_results())
    assert counts == {
        "total": 5,
        "candidates": 2,
        "dangling": 1,
        "claimable": 1,
        "clean": 1,
        "not_found": 1,
        "errors": 1,
    }


def test_summary_line():
    line = summary_line(all_verdict_results())
    assert "Scanned 5 domain(s)" in line
    assert "2 candidate(s)" in line
    assert "1 dangling" in line
    assert "1 claimable" in line


def test_exit_code():
    assert exit_code([make_result(verdict=Verdict.DANGLING)]) == 1
    assert exit_code([make_result(verdict=Verdict.CLEAN)]) == 0
    assert exit_code([]) == 0


def test_table_hides_clean_and_not_found_by_default():
    text = render_table(all_verdict_results())
    assert "DANGLING" in text
    assert "CLAIMABLE" in text
    assert "ERROR" in text
    assert "clean.example.com" not in text
    assert "missing.example.com" not in text
    assert "Scanned 5 domain(s)" in text


def test_table_show_all():
    text = render_table(all_verdict_results(), show_all=True)
    assert "clean.example.com" in text
    assert "NOT FOUND" in text
    assert "missing.example.com" in text


def test_table_no_candidates():
    text = render_table([make_result(verdict=Verdict.CLEAN, target=None, provider=None)])
    assert text.startswith("No takeover candidates found.")
    assert "Scanned 1 domain(s)" in text


def test_table_no_cname_shows_dash_for_target():
    text = render_table(
        [
            make_result(
                domain="clean.example.com",
                verdict=Verdict.CLEAN,
                target=None,
                provider=None,
            )
        ],
        show_all=True,
    )
    assert "clean.example.com" in text
    row = next(line for line in text.splitlines() if "clean.example.com" in line)
    assert " - " in row


def test_table_color_only_when_requested():
    plain = render_table([make_result()], color=False)
    colored = render_table([make_result()], color=True)
    assert "\033[" not in plain
    assert "\033[1;31m" in colored


def test_json_output_shape():
    payload = json.loads(
        render_json(all_verdict_results(), generated_at="2026-01-01T00:00:00+00:00")
    )
    assert payload["tool"] == "cname-watch"
    assert payload["generated_at"] == "2026-01-01T00:00:00+00:00"
    assert payload["summary"]["candidates"] == 2
    assert len(payload["results"]) == 5
    dangling = payload["results"][0]
    assert dangling["verdict"] == "dangling"
    assert dangling["candidate"] is True
    assert dangling["resolution"]["chain"][0]["target"] == "old-blog.github.io"


def test_csv_output():
    match = make_match()
    probe = HttpProbe(
        attempts=[ProbeAttempt("http://blog.example.com/", 404, "text/html", "body")],
        match=match,
    )
    result = make_result(verdict=Verdict.CLAIMABLE, http=probe)

    reader = csv.DictReader(io.StringIO(render_csv([result])))
    row = next(reader)

    assert row["domain"] == "blog.example.com"
    assert row["verdict"] == "claimable"
    assert row["provider"] == "GitHub Pages"
    assert row["cname_chain"] == "blog.example.com -> old-blog.github.io"
    assert row["terminal_state"] == "resolved"
    assert row["http_status"] == "404"
    assert "HTTP 404" in row["evidence"]


def test_details_include_chain_and_probes():
    match = make_match()
    probe = HttpProbe(
        attempts=[ProbeAttempt("http://blog.example.com/", 404, "text/html", "body")],
        match=match,
    )
    result = make_result(verdict=Verdict.CLAIMABLE, http=probe)

    text = render_details([result])

    assert "blog.example.com -> old-blog.github.io" in text
    assert "http://blog.example.com/ -> HTTP 404" in text
    assert "match:    github-pages" in text
    assert "There isn't a GitHub Pages site here" in text


def test_details_empty_when_nothing_to_show():
    assert render_details([make_result(verdict=Verdict.CLEAN, target=None, provider=None)]) == ""


def test_json_serialises_no_cname_result():
    payload = json.loads(
        render_json(
            [
                make_result(
                    domain="clean.example.com",
                    verdict=Verdict.CLEAN,
                    target=None,
                    provider=None,
                )
            ]
        )
    )
    result = payload["results"][0]
    assert result["resolution"]["terminal"] == "clean.example.com"
    assert result["resolution"]["state"] == TerminalState.RESOLVED.value
    assert result["http"] is None
