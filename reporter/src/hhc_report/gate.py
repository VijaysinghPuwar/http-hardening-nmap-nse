"""Baseline comparison and the CI pass/fail decision."""

from __future__ import annotations

import json
import os
from typing import Any

from hhc_report.model import RANK, SEVERITIES, InputError, Report, all_findings


def load_baseline(path: str) -> dict[str, dict[str, Any]]:
    """Reads a previous `hhc-report --format json` output and returns its
    findings keyed by fingerprint."""
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except OSError as e:
        raise InputError(f"baseline {path}: {e.strerror or e}") from e
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise InputError(f"baseline {path}: not valid JSON ({e})") from e
    if not isinstance(doc, dict) or not isinstance(doc.get("targets"), list):
        raise InputError(f"baseline {path}: not an hhc-report JSON report (no 'targets' list)")
    out: dict[str, dict[str, Any]] = {}
    for t in doc["targets"]:
        if not isinstance(t, dict):
            raise InputError(f"baseline {path}: malformed target entry")
        for f in t.get("findings") or []:
            if not isinstance(f, dict) or not isinstance(f.get("fingerprint"), str):
                raise InputError(f"baseline {path}: finding without a fingerprint")
            out[f["fingerprint"]] = {
                "target": t.get("key") or t.get("url"),
                "id": f.get("id"),
                "severity": f.get("severity"),
                "detail": f.get("detail"),
            }
    return out


def apply_baseline(report: Report, path: str) -> None:
    """Marks each finding new or existing and lists the ones that went away."""
    previous = load_baseline(path)
    current = set()
    new = 0
    for _, f in all_findings(report):
        current.add(f["fingerprint"])
        if f["fingerprint"] in previous:
            f["baseline"] = "existing"
        else:
            f["baseline"] = "new"
            new += 1
    resolved = [dict(v, fingerprint=k) for k, v in sorted(previous.items()) if k not in current]
    report["baseline"] = {
        "file": os.path.basename(path),
        "new": new,
        "existing": len(current) - new,
        "resolved": resolved,
    }


def evaluate_gate(report: Report, fail_on: str, fail_on_error: bool) -> bool:
    """Decides whether the run fails and records why in report['gate'].

    fail_on is a severity, 'policy' (use each target's own PASS/FAIL, which
    reflects its policy file) or 'none'. With a baseline only new findings
    can fail the gate.
    """
    only_new = report["baseline"] is not None
    reasons: list[str] = []
    failing = 0
    if fail_on in SEVERITIES:
        limit = RANK[fail_on]
        for _, f in all_findings(report):
            if RANK[f["severity"]] <= limit and (not only_new or f["baseline"] == "new"):
                failing += 1
        if failing:
            reasons.append(f"{failing} {'new ' if only_new else ''}finding(s) at {fail_on} or above")
    elif fail_on == "policy":
        for t in report["targets"]:
            if t["result"] != "FAIL":
                continue
            limit = RANK.get((t["fail_on"] or "medium").lower(), RANK["medium"])
            hits = [
                f
                for f in t["findings"]
                if RANK[f["severity"]] <= limit and (not only_new or f["baseline"] == "new")
            ]
            failing += len(hits)
        if failing:
            reasons.append(f"{failing} {'new ' if only_new else ''}finding(s) fail their target's policy")
    errors = report["summary"]["errors"]
    if fail_on_error and errors:
        reasons.append(f"{errors} target(s) could not be scanned")
    report["gate"] = {
        "fail_on": fail_on,
        "only_new": only_new,
        "fail_on_error": fail_on_error,
        "failing_findings": failing,
        "failed": bool(reasons),
        "reasons": reasons,
    }
    return bool(reasons)
