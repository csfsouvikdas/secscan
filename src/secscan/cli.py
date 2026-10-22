"""Command line interface."""
from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from . import __version__
from .models import SEV_RANK, SEVERITIES
from .reporters import render
from .rules import RULES
from .scanner import scan_paths

FORMATS = ["console", "json", "sarif", "html", "markdown"]


def _list_rules() -> str:
    rows = [f"{'ID':8}{'SEVERITY':10}{'CWE':9}{'KIND':8}TITLE"]
    for r in RULES:
        rows.append(f"{r.id:8}{r.severity:10}{r.cwe:9}{r.kind:8}{r.title}")
    return "\n".join(rows)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="secscan", description="Audit source code for common security weaknesses.")
    p.add_argument("paths", nargs="*", default=["."], help="files or directories to scan (default: .)")
    p.add_argument("-f", "--format", choices=FORMATS, default="console", help="report format")
    p.add_argument("-o", "--output", help="write the report to a file instead of stdout")
    p.add_argument("--min-severity", choices=SEVERITIES, default="info", help="hide findings below this level")
    p.add_argument("--fail-on", choices=SEVERITIES + ["none"], default="high",
                   help="exit with status 1 if a finding at/above this level exists (default: high)")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="glob to skip (repeatable)")
    p.add_argument("--disable", default="", metavar="IDS", help="comma separated rule IDs to disable")
    p.add_argument("--no-color", action="store_true", help="disable coloured console output")
    p.add_argument("--list-rules", action="store_true", help="print the rule catalogue and exit")
    p.add_argument("--version", action="version", version=f"secscan {__version__}")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_rules:
        print(_list_rules())
        return 0
    missing = [p for p in args.paths if not os.path.exists(p)]
    if missing:
        print(f"secscan: path not found: {', '.join(missing)}", file=sys.stderr)
        return 2
    disabled = {i.strip().upper() for i in args.disable.split(",") if i.strip()}
    unknown = disabled - {r.id for r in RULES}
    if unknown:
        print(f"secscan: unknown rule id(s): {', '.join(sorted(unknown))}", file=sys.stderr)
        return 2
    rules = [r for r in RULES if r.id not in disabled]
    base = args.paths[0] if len(args.paths) == 1 and os.path.isdir(args.paths[0]) else None
    result = scan_paths(args.paths, rules, args.exclude, args.min_severity, base=base)

    color = (not args.no_color) and sys.stdout.isatty() and not args.output and "NO_COLOR" not in os.environ
    text = render(args.format, result, color)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"secscan: wrote {args.format} report to {args.output} ({len(result.findings)} finding(s))",
              file=sys.stderr)
    else:
        sys.stdout.write(text)

    if args.fail_on != "none":
        limit = SEV_RANK[args.fail_on]
        if any(SEV_RANK[f.severity] >= limit for f in result.findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
