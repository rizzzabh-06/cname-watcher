"""Human-readable and machine-readable output."""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterable, Sequence
from datetime import datetime, timezone

from . import __version__
from .models import ScanResult, Verdict

_COLORS = {
    Verdict.DANGLING: "\033[1;31m",
    Verdict.CLAIMABLE: "\033[1;31m",
    Verdict.ERROR: "\033[1;33m",
    Verdict.CLEAN: "\033[32m",
    Verdict.NOT_FOUND: "\033[2m",
}
_RESET = "\033[0m"
_HEADERS = ("STATUS", "DOMAIN", "CNAME TARGET", "PROVIDER", "EVIDENCE")
_LIMITS = (12, 40, 46, 20, 84)


def summary(results: Iterable[ScanResult]) -> dict[str, int]:
    result_list = list(results)
    counts = {
        "total": len(result_list),
        "candidates": 0,
        "dangling": 0,
        "claimable": 0,
        "clean": 0,
        "not_found": 0,
        "errors": 0,
    }
    for result in result_list:
        if result.verdict is Verdict.DANGLING:
            counts["dangling"] += 1
            counts["candidates"] += 1
        elif result.verdict is Verdict.CLAIMABLE:
            counts["claimable"] += 1
            counts["candidates"] += 1
        elif result.verdict is Verdict.CLEAN:
            counts["clean"] += 1
        elif result.verdict is Verdict.NOT_FOUND:
            counts["not_found"] += 1
        elif result.verdict is Verdict.ERROR:
            counts["errors"] += 1
    return counts


def summary_line(results: Iterable[ScanResult]) -> str:
    counts = summary(results)
    return (
        f"Scanned {counts['total']} domain(s): {counts['candidates']} candidate(s) "
        f"({counts['dangling']} dangling, {counts['claimable']} claimable), "
        f"{counts['clean']} clean, {counts['not_found']} not found, "
        f"{counts['errors']} error(s)."
    )


def exit_code(results: Iterable[ScanResult]) -> int:
    return 1 if any(result.is_candidate for result in results) else 0


def _truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    if limit <= 1:
        return value[:limit]
    return value[: limit - 1] + "…"


def _visible_rows(results: Sequence[ScanResult]) -> list[tuple[str, str, str, str, str]]:
    rows: list[tuple[str, str, str, str, str]] = []
    for result in results:
        target = result.resolution.terminal if result.resolution.has_cname else "-"
        rows.append(
            (
                result.verdict.label,
                _truncate(result.domain, _LIMITS[1]),
                _truncate(target or "-", _LIMITS[2]),
                _truncate(result.provider or "-", _LIMITS[3]),
                _truncate(result.evidence or "-", _LIMITS[4]),
            )
        )
    return rows


def render_table(
    results: Sequence[ScanResult],
    *,
    show_all: bool = False,
    color: bool = False,
    include_summary: bool = True,
) -> str:
    """Render a compact aligned table, hiding non-findings by default."""

    shown = [
        result
        for result in results
        if show_all or result.is_candidate or result.verdict is Verdict.ERROR
    ]
    lines: list[str] = []

    if shown:
        rows = _visible_rows(shown)
        widths = [
            max(len(_HEADERS[index]), *(len(row[index]) for row in rows))
            for index in range(len(_HEADERS))
        ]
        header = "  ".join(_HEADERS[index].ljust(widths[index]) for index in range(len(_HEADERS)))
        lines.append(header.rstrip())
        lines.append("  ".join("-" * width for width in widths))

        for result, row in zip(shown, rows, strict=True):
            cells = [row[index].ljust(widths[index]) for index in range(1, len(_HEADERS) - 1)]
            status = row[0].ljust(widths[0])
            if color:
                status = f"{_COLORS.get(result.verdict, '')}{status}{_RESET}"
            lines.append("  ".join([status, *cells, row[-1]]).rstrip())
    else:
        lines.append("No takeover candidates found.")

    if include_summary:
        if lines:
            lines.append("")
        lines.append(summary_line(results))
    return "\n".join(lines)


def render_details(results: Sequence[ScanResult], *, show_all: bool = False) -> str:
    """Render CNAME chains and probe attempts for verbose output."""

    shown = [
        result
        for result in results
        if show_all or result.is_candidate or result.verdict is Verdict.ERROR
    ]
    lines: list[str] = []
    for result in shown:
        if lines:
            lines.append("")
        if result.resolution.chain:
            chain = " -> ".join([result.domain, *(link.target for link in result.resolution.chain)])
        else:
            chain = f"{result.domain} (no CNAME)"
        lines.append(f"{result.domain} [{result.verdict.label}]")
        lines.append(f"  CNAME:    {chain}")
        lines.append(
            f"  terminal: {result.resolution.terminal or '-'} ({result.resolution.state.value})"
        )
        if result.resolution.addresses:
            lines.append(f"  addresses: {', '.join(result.resolution.addresses)}")
        if result.http:
            for attempt in result.http.attempts:
                if attempt.error:
                    lines.append(f"  probe:    {attempt.url} -> {attempt.error}")
                else:
                    lines.append(f"  probe:    {attempt.url} -> HTTP {attempt.status_code}")
            if result.http.match:
                match = result.http.match
                lines.append(f"  match:    {match.rule_id} ({match.provider})")
                if match.snippet:
                    lines.append(f"  evidence: {match.snippet}")
    return "\n".join(lines)


def render_json(results: Sequence[ScanResult], *, generated_at: str | None = None) -> str:
    payload = {
        "tool": "cname-watch",
        "version": __version__,
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": summary(results),
        "results": [result.to_dict() for result in results],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def render_csv(results: Sequence[ScanResult]) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(
        (
            "domain",
            "verdict",
            "reason",
            "provider",
            "terminal",
            "cname_chain",
            "terminal_state",
            "http_status",
            "evidence",
        )
    )
    for result in results:
        chain = " -> ".join([result.domain, *(link.target for link in result.resolution.chain)])
        writer.writerow(
            (
                result.domain,
                result.verdict.value,
                result.reason,
                result.provider or "",
                result.resolution.terminal,
                chain,
                result.resolution.state.value,
                result.http_status if result.http_status is not None else "",
                result.evidence,
            )
        )
    return output.getvalue()
