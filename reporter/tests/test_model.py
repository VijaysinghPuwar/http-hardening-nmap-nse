from __future__ import annotations

from pathlib import Path

import pytest
from conftest import finding, target

from hhc_report import model
from hhc_report.model import InputError, load


def test_lab_scan_targets_and_results(lab_xml: str) -> None:
    r = load([lab_xml])
    by_port = {t["port"]: t for t in r["targets"]}
    assert sorted(by_port) == [8000, 8080, 8081, 8082, 8180, 8443, 8445]
    assert by_port[8080]["result"] == "PASS" and by_port[8080]["passed"] == ["https-redirect"]
    assert by_port[8000]["result"] == "ERROR"
    assert by_port[8000]["error"] == "unsupported-response"
    assert by_port[8000]["findings"] == []
    assert by_port[8443]["grade"] == "F"
    ids = {f["id"] for f in by_port[8180]["findings"]}
    assert {"exposed-git", "exposed-env", "trace-enabled"} <= ids
    assert r["scan"]["nmap_versions"] and r["scan"]["started"]
    assert r["summary"]["targets"] == 7 and r["summary"]["errors"] == 1


def test_error_text_is_never_a_finding(lab_xml: str) -> None:
    for t in load([lab_xml])["targets"]:
        for f in t["findings"]:
            assert "no-response" not in f["id"] and "ERROR" not in (f["detail"] or "")


def test_findings_are_sorted_and_counted(lab_xml: str) -> None:
    for t in load([lab_xml])["targets"]:
        ranks = [model.RANK[f["severity"]] for f in t["findings"]]
        assert ranks == sorted(ranks)
        assert sum(t["counts"].values()) == len(t["findings"])


def test_scan_args_and_local_paths_are_not_copied(lab_xml: str) -> None:
    r = load([lab_xml])
    assert "args" not in r["scan"]
    assert r["scan"]["files"] == ["lab-scan.xml"]


def test_fingerprints_unique_and_stable(lab_xml: str) -> None:
    a = [f["fingerprint"] for t in load([lab_xml])["targets"] for f in t["findings"]]
    b = [f["fingerprint"] for t in load([lab_xml])["targets"] for f in t["findings"]]
    assert a == b
    assert len(set(a)) == len(a)


def test_fingerprint_ignores_version_numbers() -> None:
    f1 = {"id": "info-disclosure", "path": "/", "detail": "Server: nginx/1.24.0"}
    f2 = {"id": "info-disclosure", "path": "/", "detail": "Server: nginx/1.25.3"}
    assert model.fingerprint("https://a:443", f1) == model.fingerprint("https://a:443", f2)
    assert model.fingerprint("https://a:443", f1) != model.fingerprint("https://b:443", f1)


def test_vhost_url_is_the_target_key(hardened_xml: str) -> None:
    t = load([hardened_xml])["targets"][0]
    assert t["url"] == "https://app.lab.test:8444/"
    assert t["key"] == "https://app.lab.test:8444"
    assert t["result"] == "PASS" and t["score"] == 100 and t["grade"] == "A"


def test_unexpected_and_missing_fields(write_xml) -> None:
    t = target(
        findings=[finding(severity="SEVERE", extra_field="x"), {"severity": "HIGH"}],
        score="not-a-number",
        grade="Z",
        brand_new_field="ignored",
        result="WEIRD",
    )
    r = load([write_xml([t])])
    got = r["targets"][0]
    assert got["score"] is None and got["grade"] is None and got["result"] == "ERROR"
    assert len(got["findings"]) == 1  # the entry without an id is dropped
    assert got["findings"][0]["severity"] == "info"  # unknown severity is not inflated
    assert "brand_new_field" not in got


def test_script_without_structured_output(tmp_path: Path) -> None:
    p = tmp_path / "old.xml"
    p.write_text(
        '<nmaprun><host><address addr="10.0.0.1"/><ports><port portid="80">'
        '<script id="http-hardening-check" output="FINDING: missing=[]"/></port></ports></host></nmaprun>'
    )
    t = load([str(p)])["targets"][0]
    assert t["result"] == "ERROR" and t["findings"] == []


def test_other_scripts_are_ignored(tmp_path: Path) -> None:
    p = tmp_path / "x.xml"
    p.write_text(
        '<nmaprun><host><address addr="10.0.0.1"/><ports><port portid="80">'
        '<script id="http-title" output="x"/></port></ports></host></nmaprun>'
    )
    assert load([str(p)])["targets"] == []


def test_multiple_files_merge(write_xml) -> None:
    a = write_xml([target(port=443)], "a.xml")
    b = write_xml([target(port=8443, host="192.0.2.11")], "b.xml")
    r = load([a, b])
    assert [t["port"] for t in r["targets"]] == [443, 8443]
    assert r["scan"]["files"] == ["a.xml", "b.xml"]


@pytest.mark.parametrize(
    "content, message",
    [
        ("", "empty"),
        ("   \n", "empty"),
        ("<nmaprun><host>", "not well-formed"),
        ("<html><body>hi</body></html>", "not Nmap XML"),
        (
            '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;">]>'
            "<nmaprun>&b;</nmaprun>",
            "entity declarations",
        ),
        (
            '<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><nmaprun>&xxe;</nmaprun>',
            "entity declarations",
        ),
    ],
)
def test_bad_input_is_rejected(tmp_path: Path, content: str, message: str) -> None:
    p = tmp_path / "bad.xml"
    p.write_text(content)
    with pytest.raises(InputError, match=message):
        load([str(p)])


def test_missing_file() -> None:
    with pytest.raises(InputError, match="No such file"):
        load(["/nonexistent/scan.xml"])


def test_size_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    p = tmp_path / "big.xml"
    p.write_text("<nmaprun>" + " " * 2000 + "</nmaprun>")
    monkeypatch.setattr(model, "MAX_XML_BYTES", 1000)
    with pytest.raises(InputError, match="larger than"):
        load([str(p)])


def test_unicode_survives(write_xml) -> None:
    t = target(findings=[finding(detail="Server: Ünïcødé/1.0 ‮漢字")])
    f = load([write_xml([t])])["targets"][0]["findings"][0]
    assert f["detail"] == "Server: Ünïcødé/1.0 ‮漢字"
