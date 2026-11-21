"""Command-line interface."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import math
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .dns_chain import MAX_DEPTH, build_resolver
from .input import read_domains
from .models import ScanResult
from .report import (
    exit_code,
    render_csv,
    render_details,
    render_json,
    render_table,
    summary_line,
)
from .rules import BUILTIN_RULES, RuleError, load_rules, merge_rules
from .scanner import ScanOptions, build_http_client, scan_domains

_EPILOG = """\
examples:
  cname-watch www.example.com blog.example.com
  cname-watch -l subdomains.txt --all
  cat subdomains.txt | cname-watch --format json
  cname-watch -l subdomains.txt --format csv -o findings.csv

Only scan domains you own or have explicit permission to test.
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cname-watch",
        description=(
            "Resolve CNAME chains and detect dangling records or unclaimed "
            "AWS S3, GitHub Pages, Vercel, and Azure resources."
        ),
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("domains", nargs="*", metavar="DOMAIN", help="subdomain(s) to scan")
    parser.add_argument(
        "-l",
        "--list",
        dest="list_file",
        metavar="FILE",
        help="read domains from FILE (use '-' for stdin), one per line",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=("table", "json", "csv"),
        default="table",
        help="output format (default: table)",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="write output to FILE instead of stdout (use '-' for stdout)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        metavar="SECONDS",
        help="DNS and HTTP timeout per operation (default: 5)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=20,
        metavar="N",
        help="number of domains to scan concurrently (default: 20)",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=MAX_DEPTH,
        metavar="N",
        help=f"maximum CNAME chain length (default: {MAX_DEPTH})",
    )
    parser.add_argument(
        "--nameserver",
        action="append",
        metavar="IP",
        help="DNS resolver to use (repeatable; default: system resolvers)",
    )
    parser.add_argument(
        "--rules",
        metavar="FILE",
        help="custom fingerprint rules in JSON format",
    )
    parser.add_argument(
        "--no-probe",
        action="store_true",
        help="skip HTTP fingerprinting and only analyse DNS",
    )
    parser.add_argument(
        "--https-only",
        action="store_true",
        help="do not make plain-HTTP probes",
    )
    parser.add_argument(
        "--verify-tls",
        action="store_true",
        help="verify TLS certificates during probes (off by default)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="show clean and not-found domains in the table",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="show CNAME chains and probe attempts"
    )
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress the summary line")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be a positive finite number")
    if args.concurrency < 1:
        parser.error("--concurrency must be at least 1")
    if not 1 <= args.max_depth <= 50:
        parser.error("--max-depth must be between 1 and 50")
    for nameserver in args.nameserver or []:
        try:
            ipaddress.ip_address(nameserver)
        except ValueError:
            parser.error(f"invalid --nameserver address: {nameserver!r}")


def _load_domains(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
) -> tuple[list[str], list[str]]:
    """Collect domains from arguments, a file, or stdin."""

    domains: list[str] = []
    problems: list[str] = []

    if args.list_file:
        try:
            if args.list_file == "-":
                lines = sys.stdin.read().splitlines()
                source = "stdin"
            else:
                lines = Path(args.list_file).read_text(encoding="utf-8-sig").splitlines()
                source = str(args.list_file)
        except OSError as exc:
            parser.error(f"cannot read {args.list_file}: {exc}")
        parsed, errors = read_domains(lines)
        domains.extend(parsed)
        problems.extend(f"{source}:{line}: {raw!r}: {reason}" for line, raw, reason in errors)

    if args.domains:
        parsed, errors = read_domains(args.domains)
        domains.extend(parsed)
        problems.extend(f"argument {line}: {raw!r}: {reason}" for line, raw, reason in errors)

    if not args.domains and not args.list_file and not sys.stdin.isatty():
        parsed, errors = read_domains(sys.stdin.read().splitlines())
        domains.extend(parsed)
        problems.extend(f"stdin:{line}: {raw!r}: {reason}" for line, raw, reason in errors)

    if not domains and not problems:
        parser.error("provide at least one domain, use --list FILE, or pipe domains on stdin")

    # Preserve order across all sources while de-duplicating.
    domains = list(dict.fromkeys(domains))
    return domains, problems


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _validate_args(parser, args)

    domains, problems = _load_domains(args, parser)
    for problem in problems:
        print(f"warning: {problem}", file=sys.stderr)
    if not domains:
        print("error: no valid domains to scan", file=sys.stderr)
        return 2

    rules = BUILTIN_RULES
    if args.rules:
        try:
            rules = merge_rules(BUILTIN_RULES, load_rules(args.rules))
        except RuleError as exc:
            print(f"error: invalid rules file: {exc}", file=sys.stderr)
            return 2

    options = ScanOptions(
        timeout=args.timeout,
        concurrency=args.concurrency,
        max_depth=args.max_depth,
        probe_http=not args.no_probe,
        allow_http=not args.https_only,
        rules=rules,
    )
    resolver = build_resolver(timeout=args.timeout, nameservers=args.nameserver or None)

    async def run() -> list[ScanResult]:
        client = (
            build_http_client(args.timeout, args.concurrency, args.verify_tls)
            if options.probe_http
            else None
        )
        try:
            return await scan_domains(domains, resolver, options, client)
        finally:
            if client is not None:
                await client.aclose()

    try:
        results = asyncio.run(run())
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130

    to_stdout = not args.output or args.output == "-"
    color = (
        args.format == "table"
        and to_stdout
        and not args.no_color
        and "NO_COLOR" not in os.environ
        and sys.stdout.isatty()
    )

    if args.format == "table":
        text = render_table(
            results,
            show_all=args.all,
            color=color,
            include_summary=not args.quiet,
        )
        if args.verbose:
            details = render_details(results, show_all=args.all)
            if details:
                text = f"{text}\n\n{details}"
    elif args.format == "json":
        text = render_json(results)
    else:
        text = render_csv(results)
        if not args.quiet:
            print(summary_line(results), file=sys.stderr)

    if to_stdout:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")
    else:
        try:
            Path(args.output).write_text(text, encoding="utf-8")
        except OSError as exc:
            print(f"error: cannot write {args.output}: {exc}", file=sys.stderr)
            return 2
        if not args.quiet:
            print(f"Wrote results to {args.output}", file=sys.stderr)

    return exit_code(results)
