"""Self-contained HTML report. No scripts, no external resources; every value
from the scan is escaped. The page sends its own restrictive CSP."""

from __future__ import annotations

import datetime as dt
from html import escape
from typing import Any

from hhc_report.model import SEVERITIES, Report, Target

CSS = """
:root{--bg:#f7f8fa;--card:#fff;--fg:#1d2330;--muted:#5d6676;--line:#dde1e8;
--critical:#8b1a1a;--high:#c62828;--medium:#b45309;--low:#2563a8;--info:#5d6676;
--pass:#1b7f3b;--fail:#c62828;--error:#7a5c00;--chip:#eef1f5}
@media (prefers-color-scheme:dark){:root{--bg:#12151b;--card:#1b2029;--fg:#e4e8ef;--muted:#9aa4b5;
--line:#2c3340;--critical:#ff8a80;--high:#ff6b6b;--medium:#f0a64a;--low:#7fb2f0;--info:#9aa4b5;
--pass:#5fd38a;--fail:#ff6b6b;--error:#e6c35c;--chip:#252b36}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:1.5rem;margin:0 0 4px}h2{font-size:1.15rem;margin:32px 0 12px}h3{font-size:1rem;margin:0}
.muted{color:var(--muted)}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.85em}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.card .v{font-size:1.6rem;font-weight:650}.card .k{color:var(--muted);font-size:.8rem;text-transform:uppercase;
letter-spacing:.04em}
.bar{display:flex;gap:2px;height:12px;border-radius:6px;overflow:hidden;background:var(--chip);margin:8px 0}
.bar span{display:block;height:100%}
.legend{display:flex;flex-wrap:wrap;gap:12px;font-size:.85rem;color:var(--muted)}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:5px;vertical-align:-1px}
.target{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:16px 0;overflow:hidden}
.thead{display:flex;flex-wrap:wrap;align-items:center;gap:12px;padding:14px 16px;border-bottom:1px solid var(--line)}
.grade{font-weight:700;font-size:1.3rem;width:44px;height:44px;border-radius:8px;display:grid;place-items:center;
background:var(--chip)}
.g-A,.g-B{color:var(--pass)}.g-C,.g-D{color:var(--medium)}.g-F{color:var(--fail)}
.result{font-weight:650;font-size:.8rem;padding:2px 8px;border-radius:4px;background:var(--chip)}
.r-PASS{color:var(--pass)}.r-FAIL{color:var(--fail)}.r-ERROR{color:var(--error)}
.tbody{padding:4px 16px 16px}
table{width:100%;border-collapse:collapse;font-size:.9rem}
th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:.78rem;text-transform:uppercase;letter-spacing:.03em}
.sev{font-weight:700;font-size:.78rem}
.s-critical{color:var(--critical)}.s-high{color:var(--high)}.s-medium{color:var(--medium)}
.s-low{color:var(--low)}.s-info{color:var(--info)}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.chip{background:var(--chip);border-radius:4px;padding:1px 8px;font-size:.8rem}
.new{color:var(--fail);font-weight:700;font-size:.72rem;margin-left:4px}
details{margin-top:10px}summary{cursor:pointer;color:var(--muted)}
.table-wrap{overflow-x:auto}
footer{margin-top:40px;color:var(--muted);font-size:.85rem}
"""

SEV_COLOR = {s: f"var(--{s})" for s in SEVERITIES}


def e(value: Any) -> str:
    return escape("" if value is None else str(value), quote=True)


def _finding_rows(t: Target) -> str:
    rows = []
    for f in t["findings"]:
        refs = " ".join(
            x for x in (f.get("cwe"), f.get("owasp"), f"ASVS {f['asvs']}" if f.get("asvs") else None) if x
        )
        new = '<span class="new">NEW</span>' if f["baseline"] == "new" else ""
        # Evidence is shown only when it adds something to the detail line.
        shown = f.get("evidence") and f.get("evidence") != f.get("detail")
        evidence = f'<div class="mono muted">{e(f.get("evidence"))}</div>' if shown else ""
        rows.append(
            f'<tr><td class="sev s-{e(f["severity"])}">{e(f["severity"].upper())}{new}</td>'
            f'<td><b>{e(f.get("title") or f["id"])}</b><div class="mono muted">{e(f["id"])}</div></td>'
            f"<td>{e(f.get('detail'))}{evidence}</td>"
            f'<td>{e(f.get("recommendation"))}<div class="muted">{e(refs)}</div></td></tr>'
        )
    return "".join(rows)


def _target(t: Target) -> str:
    grade = t["grade"] or "-"
    score = "-" if t["score"] is None else f"{t['score']}/100"
    head = (
        f'<div class="thead"><div class="grade g-{e(grade)}">{e(grade)}</div>'
        f'<div><h3 class="mono">{e(t["url"] or t["key"])}</h3>'
        f'<div class="muted">{e(t["host"])}:{e(t["port"])} &middot; HTTP {e(t["status"] or "-")} &middot; '
        f"score {e(score)} &middot; policy {e(t['policy'] or '-')}</div></div>"
        f'<span class="result r-{e(t["result"])}">{e(t["result"])}</span></div>'
    )
    body = []
    if t["result"] == "ERROR":
        body.append(
            f'<p>Could not be evaluated: <b>{e(t["error"])}</b> <span class="mono muted">'
            f"{e(t['error_detail'])}</span></p>"
        )
    if t["note"]:
        body.append(f'<p class="muted">{e(t["note"])}</p>')
    if t["findings"]:
        body.append(
            '<div class="table-wrap"><table><thead><tr><th>Severity</th><th>Finding</th><th>Detail</th>'
            f"<th>Recommendation</th></tr></thead><tbody>{_finding_rows(t)}</tbody></table></div>"
        )
    elif t["result"] != "ERROR":
        body.append("<p>No findings under this policy.</p>")
    if t["passed"]:
        chips = "".join(f'<span class="chip">{e(p)}</span>' for p in t["passed"])
        body.append(
            f'<div class="muted" style="margin-top:12px">Passed checks</div><div class="chips">{chips}</div>'
        )
    if t["paths"]:
        rows = "".join(
            f'<tr><td class="mono">{e(p["path"])}</td><td>{e(p["status"] if p["status"] is not None else "-")}'
            f"</td><td>{e(p['verdict'])}</td></tr>"
            for p in t["paths"]
        )
        body.append(
            f"<details><summary>Probed paths ({len(t['paths'])})</summary><table><thead><tr><th>Path</th>"
            f"<th>Status</th><th>Verdict</th></tr></thead><tbody>{rows}</tbody></table></details>"
        )
    for w in t["warnings"]:
        body.append(f'<p class="muted">Warning: {e(w)}</p>')
    return f'<section class="target">{head}<div class="tbody">{"".join(body)}</div></section>'


def to_html(report: Report) -> str:
    s = report["summary"]
    counts = s["findings"]
    total = sum(counts.values())
    bar = (
        "".join(
            f'<span title="{e(sev)}: {n}" style="width:{100 * n / total:.2f}%;background:{SEV_COLOR[sev]}">'
            f"</span>"
            for sev, n in counts.items()
            if n
        )
        if total
        else ""
    )
    legend = "".join(
        f'<span><span class="dot" style="background:{SEV_COLOR[sev]}"></span>{e(sev)} {n}</span>'
        for sev, n in counts.items()
    )
    started = report["scan"]["started"]
    when = (
        dt.datetime.fromtimestamp(started, tz=dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        if started
        else "-"
    )
    policies = sorted({t["policy"] for t in report["targets"] if t["policy"]})
    gate = ""
    if report["gate"]:
        g = report["gate"]
        verdict = "FAILED" if g["failed"] else "passed"
        why = "; ".join(g["reasons"]) or "no findings at or above the threshold"
        gate = (
            f'<div class="card"><div class="k">CI gate (fail-on {e(g["fail_on"])})</div>'
            f'<div class="v r-{"FAIL" if g["failed"] else "PASS"}">{verdict}</div><div class="muted">{e(why)}'
            f"</div></div>"
        )
    baseline = ""
    if report["baseline"]:
        b = report["baseline"]
        baseline = (
            f'<div class="card"><div class="k">Since baseline</div><div class="v">{b["new"]} new</div>'
            f'<div class="muted">{len(b["resolved"])} resolved, {b["existing"]} unchanged</div></div>'
        )
    worst = s["worst_grade"] or "-"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<meta name="referrer" content="no-referrer">
<title>HTTP hardening report</title><style>{CSS}</style></head>
<body><main>
<h1>HTTP hardening report</h1>
<div class="muted">http-hardening-check &middot; hhc-report {e(report["tool"]["version"])} &middot; scan started {e(when)}
&middot; Nmap {e(", ".join(report["scan"]["nmap_versions"]) or "-")}</div>
<div class="cards">
<div class="card"><div class="k">Targets</div><div class="v">{s["targets"]}</div>
<div class="muted">{s["passed"]} pass &middot; {s["failed"]} fail &middot; {s["errors"]} error</div></div>
<div class="card"><div class="k">Worst grade</div><div class="v g-{e(worst)}">{e(worst)}</div>
<div class="muted">lowest score {e(s["lowest_score"] if s["lowest_score"] is not None else "-")}</div></div>
<div class="card"><div class="k">Findings</div><div class="v">{total}</div>
<div class="muted">{counts["critical"] + counts["high"]} critical or high</div></div>
{gate}{baseline}
</div>
<h2>Findings by severity</h2>
<div class="bar">{bar}</div><div class="legend">{legend}</div>
<h2>Targets</h2>
{"".join(_target(t) for t in report["targets"]) or "<p>No results from http-hardening-check in the input.</p>"}
<h2>Scan details</h2>
<table><tbody>
<tr><th>Input files</th><td class="mono">{e(", ".join(report["scan"]["files"]))}</td></tr>
<tr><th>Policies</th><td>{e(", ".join(policies) or "-")}</td></tr>
<tr><th>Scoring</th><td>100 minus 40 per critical, 25 per high, 10 per medium, 3 per low finding; info is free.
A high finding caps the grade at C, a critical one at F.</td></tr>
</tbody></table>
<h2>Limitations</h2>
<ul class="muted">
<li>Each port is judged on one page (and its same-site redirects); headers set only on other routes are not seen.</li>
<li>Findings describe HTTP responses, not application logic. A clean result is not proof that a site is secure.</li>
<li>Exposure checks run only when enabled and test a short list of paths.</li>
</ul>
<footer>Generated by hhc-report from Nmap XML. Only scan systems you own or are authorized to test.</footer>
</main></body></html>
"""
