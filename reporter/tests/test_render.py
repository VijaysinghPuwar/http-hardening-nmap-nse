from __future__ import annotations

import csv
import io
import json
import re
from typing import Any

import jsonschema
import pytest
from conftest import finding, target

from hhc_report.gate import evaluate_gate
from hhc_report.html_report import to_html
from hhc_report.model import load
from hhc_report.render import CSV_FIELDS, to_csv, to_json, to_markdown, to_table
from hhc_report.sarif import to_sarif

HOSTILE = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    '=HYPERLINK("http://evil.example","x")',
    "+cmd|' /C calc'!A0",
    "-2+3",
    "@SUM(1,1)",
    "| col | injection |",
    "line1\nline2\r\nline3",
    "`code` *bold* [link](http://evil.example)",
    "Ünïcødé 漢字 ‮",
]


def hostile_report(write_xml) -> dict[str, Any]:
    findings = [finding(fid="csp-missing", detail=d, evidence=d, recommendation=d, title=d) for d in HOSTILE]
    xml = write_xml([target(url="https://lab.test/<b>x</b>", findings=findings, policy="<i>p</i>")])
    r = load([xml])
    evaluate_gate(r, "medium", False)
    return r


def test_json_matches_schema(lab_xml: str, report_schema: dict[str, Any]) -> None:
    r = load([lab_xml])
    evaluate_gate(r, "policy", False)
    jsonschema.validate(json.loads(to_json(r)), report_schema)


def test_json_is_deterministic(lab_xml: str) -> None:
    assert to_json(load([lab_xml])) == to_json(load([lab_xml]))


def test_csv_shape(lab_xml: str) -> None:
    rows = list(csv.DictReader(io.StringIO(to_csv(load([lab_xml])))))
    assert list(rows[0].keys()) == CSV_FIELDS
    by_port: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        by_port.setdefault(row["port"], []).append(row)
    assert len(by_port["8080"]) == 1 and by_port["8080"][0]["result"] == "PASS"
    assert by_port["8000"][0]["result"] == "ERROR"
    assert by_port["8000"][0]["detail"].startswith("unsupported-response")


def test_csv_escapes_formulas_and_newlines(write_xml) -> None:
    text = to_csv(hostile_report(write_xml))
    rows = list(csv.DictReader(io.StringIO(text)))
    details = [r["detail"] for r in rows]
    for d in details:
        assert not d.startswith(("=", "+", "-", "@", "|")), d
        assert "\n" not in d and "\r" not in d
    assert '\'=HYPERLINK("http://evil.example","x")' in details
    assert "'-2+3" in details


def test_markdown_escapes(write_xml) -> None:
    text = to_markdown(hostile_report(write_xml))
    assert "<script>" not in text and "<img" not in text
    for line in text.splitlines():
        if line.startswith("| MEDIUM"):
            assert line.count(" | ") == 3, line  # pipes inside cells are escaped
    assert "[link](http" not in text


def test_html_escapes_and_has_no_scripts(write_xml) -> None:
    html = to_html(hostile_report(write_xml))
    assert "<script" not in html.lower()
    assert "<img" not in html and "&quot;&gt;&lt;img src=x onerror=alert(1)&gt;" in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<b>x</b>" not in html and "<i>p</i>" not in html
    assert "default-src 'none'" in html
    assert not re.search(r"(src|href)=\"https?://", html), "report must not load external resources"


def test_html_sections(lab_xml: str) -> None:
    r = load([lab_xml])
    evaluate_gate(r, "high", False)
    html = to_html(r)
    for needle in (
        "Targets",
        "Worst grade",
        "Findings by severity",
        "CI gate",
        "Limitations",
        "Scan details",
        "exposed-git",
        "Probed paths",
        "https://localhost:8443/",
    ):
        assert needle in html, needle
    assert "prefers-color-scheme:dark" in html


def test_table(lab_xml: str) -> None:
    text = to_table(load([lab_xml]))
    assert "127.0.0.1:8000         ERROR" in text
    assert "HIGH     cors-reflected-credentials" in text


def test_sarif_valid(lab_xml: str, sarif_schema: dict[str, Any]) -> None:
    doc = json.loads(to_sarif(load([lab_xml])))
    jsonschema.Draft7Validator(sarif_schema).validate(doc)
    run = doc["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == sorted(r["id"] for r in rules)
    for res in run["results"]:
        assert rules[res["ruleIndex"]]["id"] == res["ruleId"]
        assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "lab-scan.xml"
        assert res["partialFingerprints"]["hhcFinding/v1"]
    levels = {r["ruleId"]: r["level"] for r in run["results"]}
    assert levels["cors-reflected-credentials"] == "error"
    assert levels["csp-missing"] == "warning"
    assert levels["xcto-missing"] == "note"
    sev = {r["id"]: r["properties"]["security-severity"] for r in rules}
    assert sev["exposed-git"] == "8.0"
    assert run["invocations"][0]["executionSuccessful"] is False  # port 8000 errored


def test_sarif_hostile_strings_and_artifact(write_xml, sarif_schema: dict[str, Any]) -> None:
    doc = json.loads(to_sarif(hostile_report(write_xml), artifact="deploy/nginx conf/site.conf"))
    jsonschema.Draft7Validator(sarif_schema).validate(doc)
    texts = [r["message"]["text"] for r in doc["runs"][0]["results"]]
    assert any("<script>alert(1)</script>" in t for t in texts)  # JSON-escaped, not altered
    loc = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert loc == "deploy/nginx conf/site.conf"


def test_sarif_empty_findings(hardened_xml: str, sarif_schema: dict[str, Any]) -> None:
    doc = json.loads(to_sarif(load([hardened_xml])))
    jsonschema.Draft7Validator(sarif_schema).validate(doc)
    assert doc["runs"][0]["results"] == []


@pytest.mark.parametrize("render", [to_json, to_csv, to_markdown, to_html, to_table])
def test_unicode_in_every_format(write_xml, render) -> None:
    xml = write_xml([target(findings=[finding(detail="漢字 Ünïcødé")])])
    assert "漢字" in render(load([xml]))
