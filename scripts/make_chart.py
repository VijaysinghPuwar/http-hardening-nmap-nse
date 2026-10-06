#!/usr/bin/env python3
"""Draws docs/img/demo-lab-scores.svg from a real Docker lab report.

    make demo
    python3 scripts/make_chart.py lab/docker/out/report.json docs/img/demo-lab-scores.svg

One series (score per target), so one color and no legend; the value and
grade are printed at each bar tip. Colors follow the light and dark steps
validated for the chart surfaces.
"""

from __future__ import annotations

import json
import sys
from html import escape

ROW, BAR, LEFT, WIDTH, TOP = 34, 20, 230, 760, 58


def main(src: str, dest: str) -> None:
    with open(src, encoding="utf-8") as f:
        report = json.load(f)
    rows = [t for t in report["targets"] if t["score"] is not None]
    rows.sort(key=lambda t: (-t["score"], t["url"]))
    plot = WIDTH - LEFT - 90
    height = TOP + ROW * len(rows) + 40
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {WIDTH} {height}" width="{WIDTH}" '
        f'height="{height}" role="img" aria-labelledby="t d">',
        "<title id='t'>Demo lab results: score per target</title>",
        "<desc id='d'>Scores from the Docker demo lab with the baseline policy. "
        + escape("; ".join(f"{t['url']} {t['score']} ({t['grade']})" for t in rows))
        + "</desc>",
        "<style>",
        ".bar{fill:#2a78d6}.t1{fill:#0b0b0b}.t2{fill:#52514e}.grid{stroke:#d9d8d4}",
        "text{font:13px -apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif}",
        ".h{font-size:15px;font-weight:600}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}",
        "@media (prefers-color-scheme:dark){.bar{fill:#3987e5}.t1{fill:#ffffff}.t2{fill:#c3c2b7}"
        ".grid{stroke:#3a3a37}}",
        "</style>",
        '<text class="h t1" x="0" y="20">Demo lab results: score per target</text>',
        '<text class="t2" x="0" y="40">Docker lab, baseline policy, Nmap '
        + escape(", ".join(report["scan"]["nmap_versions"]))
        + ". Lab targets, not real sites.</text>",
    ]
    for tick in (0, 50, 100):
        x = LEFT + plot * tick / 100
        out.append(
            f'<line class="grid" x1="{x:.1f}" y1="{TOP - 8}" x2="{x:.1f}" '
            f'y2="{TOP + ROW * len(rows) - 6}" stroke-width="1"/>'
        )
        axis_y = TOP + ROW * len(rows) + 12
        out.append(f'<text class="t2" x="{x:.1f}" y="{axis_y}" text-anchor="middle">{tick}</text>')
    for i, t in enumerate(rows):
        y = TOP + i * ROW
        w = max(plot * t["score"] / 100, 2)
        label = t["url"].rstrip("/")
        # Square at the baseline, 4px rounded data end.
        r = min(4, w / 2)
        path = (
            f"M{LEFT},{y} H{LEFT + w - r} Q{LEFT + w},{y} {LEFT + w},{y + r} V{y + BAR - r} "
            f"Q{LEFT + w},{y + BAR} {LEFT + w - r},{y + BAR} H{LEFT} Z"
        )
        out.append(f"<g><title>{escape(label)}: {t['score']}/100, grade {t['grade']}</title>")
        out.append(
            f'<text class="t1 mono" x="{LEFT - 10}" y="{y + 14}" text-anchor="end">{escape(label)}</text>'
        )
        out.append(f'<path class="bar" d="{path}"/>')
        out.append(
            f'<text class="t1" x="{LEFT + w + 8}" y="{y + 14}">{t["score"]}'
            f'<tspan class="t2" dx="6">grade {t["grade"]}</tspan></text></g>'
        )
    out.append("</svg>")
    with open(dest, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
