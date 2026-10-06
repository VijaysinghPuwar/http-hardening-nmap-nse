"""Text renderers: table, JSON, CSV and Markdown."""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from hhc_report.model import Report, Target

CSV_FIELDS = [
    "host",
    "port",
    "url",
    "result",
    "score",
    "grade",
    "policy",
    "severity",
    "id",
    "title",
    "detail",
    "evidence",
    "path",
    "cwe",
    "owasp",
    "asvs",
    "recommendation",
    "baseline",
    "fingerprint",
]

# A cell starting with one of these is a formula in Excel, LibreOffice and
# Google Sheets. Prefixing a quote makes it inert text (OWASP CSV injection).
FORMULA_START = ("=", "+", "-", "@", "\t", "\r", "\n", "|")


def safe_cell(value: Any) -> Any:
    if isinstance(value, str) and value.startswith(FORMULA_START):
        return "'" + value
    return value


def oneline(value: Any) -> str:
    """Collapses control characters so untrusted text stays on one line."""
    text = "" if value is None else str(value)
    return " ".join("".join(ch if ch.isprintable() else " " for ch in text).split())


def to_json(report: Report) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


def target_rows(t: Target) -> list[dict[str, Any]]:
    base = {k: t.get(k) for k in ("host", "port", "url", "result", "score", "grade", "policy")}
    if t["result"] == "ERROR":
        return [{**base, "detail": f"{t['error']}: {t['error_detail'] or ''}".strip()}]
    if not t["findings"]:
        return [base]
    return [{**base, **{k: f.get(k) for k in CSV_FIELDS if k in f}} for f in t["findings"]]


def to_csv(report: Report) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_FIELDS, extrasaction="ignore", lineterminator="\n")
    w.writeheader()
    for t in report["targets"]:
        for row in target_rows(t):
            w.writerow({k: safe_cell(oneline(v) if isinstance(v, str) else v) for k, v in row.items()})
    return buf.getvalue()


def to_table(report: Report) -> str:
    lines = []
    for t in report["targets"]:
        head = f"{t['host']}:{t['port']}"
        if t["result"] == "ERROR":
            lines.append(f"{head:<22} ERROR  {t['error']}: {oneline(t['error_detail'])}")
            continue
        lines.append(
            f"{head:<22} {t['result']:<5}  score {t['score']}/100  grade {t['grade']}  {oneline(t['url'])}"
        )
        for f in t["findings"]:
            mark = "  NEW" if f["baseline"] == "new" else ""
            lines.append(f"    {f['severity'].upper():<8} {f['id']:<32} {oneline(f['detail'])}{mark}")
    return "\n".join(lines) + "\n"


def md(value: Any) -> str:
    """Escapes text for a Markdown table cell. HTML is neutralised because
    GitHub and most viewers render inline HTML."""
    text = oneline(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    for ch in ("\\", "`", "*", "_", "[", "]", "|", "#"):
        text = text.replace(ch, "\\" + ch)
    return text


def to_markdown(report: Report) -> str:
    s = report["summary"]
    c = s["findings"]
    out = ["# HTTP hardening report", ""]
    out.append(
        f"{s['targets']} target(s): {s['passed']} pass, {s['failed']} fail, {s['errors']} error. "
        f"Lowest score {s['lowest_score'] if s['lowest_score'] is not None else '-'}, "
        f"worst grade {s['worst_grade'] or '-'}."
    )
    out.append("")
    out.append("| Critical | High | Medium | Low | Info |")
    out.append("|---:|---:|---:|---:|---:|")
    out.append(f"| {c['critical']} | {c['high']} | {c['medium']} | {c['low']} | {c['info']} |")
    if report["gate"]:
        g = report["gate"]
        verdict = "FAILED" if g["failed"] else "passed"
        reasons = "; ".join(g["reasons"]) or "no findings at or above the threshold"
        out += ["", f"**CI gate {verdict}** (fail-on {md(g['fail_on'])}): {md(reasons)}"]
    if report["baseline"]:
        b = report["baseline"]
        out += [
            "",
            f"Baseline {md(b['file'])}: {b['new']} new, {b['existing']} unchanged, "
            f"{len(b['resolved'])} resolved.",
        ]
    out += ["", "## Targets", "", "| Target | Result | Score | Grade | Policy |", "|---|---|---:|---|---|"]
    for t in report["targets"]:
        score = "-" if t["score"] is None else t["score"]
        result = t["result"] + (f" ({md(t['error'])})" if t["error"] else "")
        out.append(
            f"| {md(t['url'] or t['key'])} | {result} | {score} | {t['grade'] or '-'} | {md(t['policy'])} |"
        )
    for t in report["targets"]:
        if not t["findings"]:
            continue
        out += [
            "",
            f"## {md(t['url'] or t['key'])}",
            "",
            "| Severity | Finding | Detail | Fix |",
            "|---|---|---|---|",
        ]
        for f in t["findings"]:
            new = " (new)" if f["baseline"] == "new" else ""
            out.append(
                f"| {f['severity'].upper()}{new} | {md(f['id'])} | {md(f['detail'])} | "
                f"{md(f['recommendation'])} |"
            )
    return "\n".join(out) + "\n"
