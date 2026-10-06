"""hhc-report: turn http-hardening-check results in Nmap XML into reports and
a CI exit code.

Exit codes:
  0  the gate passed
  1  the gate failed (findings at or above --fail-on, or scan errors with
     --fail-on-error)
  2  usage or input error (missing file, malformed XML or baseline, no results)
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from collections.abc import Callable

from hhc_report import __version__
from hhc_report.gate import apply_baseline, evaluate_gate
from hhc_report.html_report import to_html
from hhc_report.model import SEVERITIES, InputError, Report, load
from hhc_report.render import to_csv, to_json, to_markdown, to_table
from hhc_report.sarif import to_sarif

FORMATS = ["table", "json", "csv", "markdown", "html", "sarif"]
EXTENSIONS = {
    ".json": "json",
    ".csv": "csv",
    ".md": "markdown",
    ".html": "html",
    ".htm": "html",
    ".sarif": "sarif",
}


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="hhc-report", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("xml", nargs="+", help="Nmap XML files (nmap -oX) that ran http-hardening-check")
    ap.add_argument(
        "-f",
        "--format",
        choices=FORMATS,
        help="output format (default: from the --output extension, else table)",
    )
    ap.add_argument("-o", "--output", help="write to this file instead of standard output")
    ap.add_argument(
        "--fail-on",
        default="policy",
        choices=[*SEVERITIES, "policy", "none"],
        help="lowest severity that fails the run; 'policy' (default) uses each target's own "
        "PASS/FAIL from its policy; 'none' never fails on findings",
    )
    ap.add_argument(
        "--fail-on-error",
        action="store_true",
        help="also fail when a target could not be scanned (connection error, timeout)",
    )
    ap.add_argument(
        "--baseline",
        metavar="PREVIOUS_JSON",
        help="earlier hhc-report JSON output; only findings that are new since then fail the gate",
    )
    ap.add_argument(
        "--sarif-artifact",
        metavar="PATH",
        help="repository file SARIF results point at (default: the XML file name)",
    )
    ap.add_argument("-q", "--quiet", action="store_true", help="do not print the gate summary to stderr")
    ap.add_argument("--version", action="version", version=f"hhc-report {__version__}")
    return ap


def write_atomic(path: str, text: str) -> None:
    """Writes via a private temp file in the same directory, then renames, so
    a crash never leaves a half-written report and a symlink at the target
    path is replaced rather than followed."""
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".hhc-report-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def render(report: Report, fmt: str, sarif_artifact: str | None) -> str:
    renderers: dict[str, Callable[[Report], str]] = {
        "table": to_table,
        "json": to_json,
        "csv": to_csv,
        "markdown": to_markdown,
        "html": to_html,
        "sarif": lambda r: to_sarif(r, sarif_artifact),
    }
    return renderers[fmt](report)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    fmt = args.format
    if not fmt:
        ext = os.path.splitext(args.output or "")[1].lower()
        fmt = EXTENSIONS.get(ext, "table")
    if args.output:
        out_real = os.path.realpath(args.output)
        if any(os.path.realpath(p) == out_real for p in [*args.xml, args.baseline or ""]):
            print("hhc-report: refusing to overwrite an input file with the report", file=sys.stderr)
            return 2

    try:
        report = load(args.xml)
        if not report["targets"]:
            print(
                "hhc-report: no http-hardening-check results in the input "
                "(did the scan use --script http-hardening-check and -oX?)",
                file=sys.stderr,
            )
            return 2
        if args.baseline:
            apply_baseline(report, args.baseline)
    except InputError as e:
        print(f"hhc-report: {e}", file=sys.stderr)
        return 2

    failed = evaluate_gate(report, args.fail_on, args.fail_on_error)
    text = render(report, fmt, args.sarif_artifact)
    try:
        if args.output:
            write_atomic(args.output, text)
        else:
            sys.stdout.write(text)
    except OSError as e:
        print(f"hhc-report: cannot write {args.output}: {e.strerror or e}", file=sys.stderr)
        return 2

    if not args.quiet:
        g = report["gate"]
        assert g is not None
        verdict = "FAIL" if failed else "PASS"
        detail = "; ".join(g["reasons"]) or "nothing at or above the threshold"
        print(f"hhc-report: {verdict} (fail-on {args.fail_on}): {detail}", file=sys.stderr)
    return 1 if failed else 0
