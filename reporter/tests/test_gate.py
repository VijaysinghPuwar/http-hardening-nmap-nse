from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import finding, target

from hhc_report.gate import apply_baseline, evaluate_gate
from hhc_report.model import InputError, load
from hhc_report.render import to_json


def scan(write_xml, *severities: str, name: str = "scan.xml", **fields):
    findings = [finding(fid=f"f-{i}", severity=s) for i, s in enumerate(severities)]
    return load([write_xml([target(findings=findings, **fields)], name)])


@pytest.mark.parametrize(
    "fail_on, severities, failed",
    [
        ("high", ["MEDIUM", "LOW"], False),
        ("high", ["HIGH"], True),
        ("high", ["CRITICAL"], True),
        ("medium", ["MEDIUM"], True),
        ("low", ["INFO"], False),
        ("info", ["INFO"], True),
        ("critical", ["HIGH"], False),
        ("none", ["CRITICAL"], False),
        ("medium", [], False),
    ],
)
def test_severity_threshold(write_xml, fail_on, severities, failed) -> None:
    r = scan(write_xml, *severities)
    assert evaluate_gate(r, fail_on, False) is failed
    assert r["gate"]["failed"] is failed


def test_policy_mode_uses_each_targets_result(write_xml) -> None:
    r = scan(write_xml, "LOW", result="FAIL", fail_on="low")
    assert evaluate_gate(r, "policy", False) is True
    r = scan(write_xml, "LOW", result="PASS", fail_on="medium")
    assert evaluate_gate(r, "policy", False) is False


def test_errors_only_fail_with_flag(write_xml) -> None:
    xml = write_xml([target(result="ERROR", error="timeout", score=None, grade=None)])
    r = load([xml])
    assert evaluate_gate(r, "info", False) is False
    assert evaluate_gate(r, "info", True) is True
    assert "could not be scanned" in r["gate"]["reasons"][0]


def write_report(r, path: Path) -> str:
    path.write_text(to_json(r))
    return str(path)


def test_baseline_marks_new_existing_and_resolved(write_xml, tmp_path: Path) -> None:
    old = load(
        [write_xml([target(findings=[finding("csp-missing"), finding("xcto-missing", "LOW")])], "old.xml")]
    )
    base = write_report(old, tmp_path / "old.json")
    new = load(
        [write_xml([target(findings=[finding("csp-missing"), finding("hsts-missing", "HIGH")])], "new.xml")]
    )
    apply_baseline(new, base)
    status = {f["id"]: f["baseline"] for f in new["targets"][0]["findings"]}
    assert status == {"csp-missing": "existing", "hsts-missing": "new"}
    assert new["baseline"]["new"] == 1 and new["baseline"]["existing"] == 1
    assert [x["id"] for x in new["baseline"]["resolved"]] == ["xcto-missing"]


def test_baseline_gate_counts_only_new(write_xml, tmp_path: Path) -> None:
    old = load([write_xml([target(findings=[finding("csp-missing", "HIGH")])], "old.xml")])
    base = write_report(old, tmp_path / "old.json")
    same = load([write_xml([target(findings=[finding("csp-missing", "HIGH")])], "same.xml")])
    apply_baseline(same, base)
    assert evaluate_gate(same, "high", False) is False
    worse = load(
        [write_xml([target(findings=[finding("csp-missing", "HIGH"), finding("x", "HIGH")])], "w.xml")]
    )
    apply_baseline(worse, base)
    assert evaluate_gate(worse, "high", False) is True
    assert "1 new finding" in worse["gate"]["reasons"][0]


def test_version_bump_is_not_new(write_xml, tmp_path: Path) -> None:
    old = load(
        [
            write_xml(
                [target(findings=[finding("info-disclosure", "LOW", detail="Server: nginx/1.24.0")])], "o.xml"
            )
        ]
    )
    base = write_report(old, tmp_path / "o.json")
    new = load(
        [
            write_xml(
                [target(findings=[finding("info-disclosure", "LOW", detail="Server: nginx/1.25.3")])], "n.xml"
            )
        ]
    )
    apply_baseline(new, base)
    assert new["targets"][0]["findings"][0]["baseline"] == "existing"


@pytest.mark.parametrize(
    "content, message",
    [
        ("{not json", "not valid JSON"),
        ("[]", "not an hhc-report JSON report"),
        ('{"targets": "x"}', "not an hhc-report JSON report"),
        ('{"targets": [1]}', "malformed target"),
        ('{"targets": [{"findings": [{"id": "x"}]}]}', "without a fingerprint"),
    ],
)
def test_corrupted_baseline(write_xml, tmp_path: Path, content: str, message: str) -> None:
    p = tmp_path / "bad.json"
    p.write_text(content)
    r = scan(write_xml, "LOW")
    with pytest.raises(InputError, match=message):
        apply_baseline(r, str(p))


def test_missing_baseline(write_xml) -> None:
    with pytest.raises(InputError, match="No such file"):
        apply_baseline(scan(write_xml, "LOW"), "/nonexistent/base.json")


def test_baseline_with_binary_garbage(write_xml, tmp_path: Path) -> None:
    p = tmp_path / "bin.json"
    p.write_bytes(b"\xff\xfe\x00garbage")
    with pytest.raises(InputError):
        apply_baseline(scan(write_xml, "LOW"), str(p))


def test_baseline_round_trip_from_real_scan(lab_xml: str, tmp_path: Path) -> None:
    base = write_report(load([lab_xml]), tmp_path / "lab.json")
    r = load([lab_xml])
    apply_baseline(r, base)
    assert r["baseline"]["new"] == 0 and r["baseline"]["resolved"] == []
    assert evaluate_gate(r, "info", False) is False
    assert json.loads(Path(base).read_text())["schema_version"] == "1.0"
