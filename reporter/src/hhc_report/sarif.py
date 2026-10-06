"""SARIF 2.1.0 output for code-scanning style consumers.

Web findings have no source file, but GitHub code scanning requires a
physical location. Each result therefore points at --sarif-artifact (default:
the scanned XML file name) and carries the target URL as a logical location
and in its message.
"""

from __future__ import annotations

import json
from typing import Any

from hhc_report import __version__
from hhc_report.model import RANK, Report, all_findings

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
DOCS = "https://github.com/VijaysinghPuwar/http-hardening-nmap-nse/blob/main/docs/checks.md"

LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
# GitHub maps security-severity to critical (9.0+), high (7.0+), medium (4.0+), low (0.1+).
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}


def _rule(rule_id: str, f: dict[str, Any], severity: str) -> dict[str, Any]:
    tags = ["security", "http-hardening"] + [t for t in (f.get("cwe"), f.get("owasp")) if t]
    rule: dict[str, Any] = {
        "id": rule_id,
        "name": "".join(part.capitalize() for part in rule_id.split("-")),
        "shortDescription": {"text": f.get("title") or rule_id},
        "fullDescription": {"text": f.get("title") or rule_id},
        "help": {"text": f.get("recommendation") or "", "markdown": f.get("recommendation") or ""},
        "helpUri": f"{DOCS}#{rule_id}",
        "defaultConfiguration": {"level": LEVEL[severity]},
        "properties": {"tags": tags, "precision": "high", "security-severity": SECURITY_SEVERITY[severity]},
    }
    return rule


def to_sarif(report: Report, artifact: str | None = None) -> str:
    uri = artifact or (report["scan"]["files"][0] if report["scan"]["files"] else "scan.xml")
    rules: dict[str, dict[str, Any]] = {}
    worst: dict[str, str] = {}
    for _, f in all_findings(report):
        if f["id"] not in worst or RANK[f["severity"]] < RANK[worst[f["id"]]]:
            worst[f["id"]] = f["severity"]
    order = sorted(worst)
    for _, f in all_findings(report):
        if f["id"] not in rules:
            rules[f["id"]] = _rule(f["id"], f, worst[f["id"]])

    results = []
    for t, f in all_findings(report):
        target = t["url"] or t["key"]
        props: dict[str, Any] = {"severity": f["severity"], "target": target}
        for k in ("evidence", "path", "cwe", "owasp", "asvs", "recommendation", "baseline"):
            if f.get(k):
                props[k] = f[k]
        results.append(
            {
                "ruleId": f["id"],
                "ruleIndex": order.index(f["id"]),
                "level": LEVEL[f["severity"]],
                "message": {
                    "text": f"{f.get('title') or f['id']} on {target}: {f.get('detail') or ''}".strip()
                },
                "locations": [
                    {
                        "physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": 1}},
                        "logicalLocations": [{"fullyQualifiedName": target, "kind": "resource"}],
                    }
                ],
                "partialFingerprints": {"hhcFinding/v1": f["fingerprint"]},
                "properties": props,
            }
        )

    doc = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "http-hardening-check",
                        "fullName": "http-hardening-check (Nmap NSE) with hhc-report",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/VijaysinghPuwar/http-hardening-nmap-nse",
                        "rules": [rules[i] for i in order],
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": report["summary"]["errors"] == 0,
                        "toolExecutionNotifications": [
                            {"level": "warning", "message": {"text": f"{t['url'] or t['key']}: {t['error']}"}}
                            for t in report["targets"]
                            if t["result"] == "ERROR"
                        ],
                    }
                ],
            }
        ],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
