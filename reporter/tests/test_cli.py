from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from conftest import finding, target

from hhc_report.cli import main


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "hhc_report", *args], capture_output=True, text=True, timeout=120, check=False
    )


def test_module_entry_point_and_exit_codes(lab_xml: str) -> None:
    assert run(lab_xml).returncode == 1  # policy failures in the lab
    assert run(lab_xml, "--fail-on", "none").returncode == 0
    assert run(lab_xml, "--fail-on", "critical").returncode == 0
    assert run(lab_xml, "--fail-on", "high").returncode == 1
    assert run(lab_xml, "--fail-on", "none", "--fail-on-error").returncode == 1  # port 8000 errored


def test_hardened_passes_every_threshold(hardened_xml: str) -> None:
    for level in ("critical", "high", "medium", "low", "info", "policy"):
        assert main([hardened_xml, "--fail-on", level, "-q"]) == 0, level


def test_usage_errors_exit_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["/nonexistent.xml"]) == 2
    assert "No such file" in capsys.readouterr().err
    empty = tmp_path / "empty.xml"
    empty.write_text('<nmaprun scanner="nmap"></nmaprun>')
    assert main([str(empty)]) == 2
    assert "no http-hardening-check results" in capsys.readouterr().err
    with pytest.raises(SystemExit) as e:
        main(["x.xml", "--fail-on", "urgent"])
    assert e.value.code == 2


def test_output_format_from_extension(lab_xml: str, tmp_path: Path) -> None:
    for name, check in [
        ("r.json", lambda s: json.loads(s)["schema_version"] == "1.0"),
        ("r.sarif", lambda s: json.loads(s)["version"] == "2.1.0"),
        ("r.html", lambda s: s.startswith("<!doctype html>")),
        ("r.md", lambda s: s.startswith("# HTTP hardening report")),
        ("r.csv", lambda s: s.startswith("host,port,url")),
    ]:
        out = tmp_path / name
        assert main([lab_xml, "-o", str(out), "--fail-on", "none", "-q"]) == 0
        assert check(out.read_text(encoding="utf-8")), name


def test_paths_with_spaces(write_xml, tmp_path: Path) -> None:
    d = tmp_path / "dir with spaces"
    d.mkdir()
    xml = write_xml([target(findings=[finding()])], "scan.xml")
    src = d / "my scan.xml"
    src.write_text(Path(xml).read_text())
    out = d / "my report.html"
    assert main([str(src), "-o", str(out), "-q"]) == 1
    assert out.exists()


def test_refuses_to_overwrite_input(lab_xml: str, tmp_path: Path) -> None:
    copy = tmp_path / "scan.xml"
    copy.write_text(Path(lab_xml).read_text())
    before = copy.read_text()
    assert main([str(copy), "-o", str(copy), "-f", "json"]) == 2
    assert copy.read_text() == before


def test_output_replaces_symlink_not_target(lab_xml: str, tmp_path: Path) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me")
    link = tmp_path / "report.json"
    os.symlink(victim, link)
    assert main([lab_xml, "-o", str(link), "--fail-on", "none", "-q"]) == 0
    assert victim.read_text() == "keep me"
    assert not link.is_symlink()


def test_unwritable_output(lab_xml: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert main([lab_xml, "-o", "/nonexistent-dir/report.json", "-q"]) == 2
    assert "cannot write" in capsys.readouterr().err


def test_no_leftover_temp_files(lab_xml: str, tmp_path: Path) -> None:
    main([lab_xml, "-o", str(tmp_path / "r.json"), "-q"])
    assert sorted(p.name for p in tmp_path.iterdir()) == ["r.json"]


def test_baseline_cli(lab_xml: str, tmp_path: Path) -> None:
    base = tmp_path / "base.json"
    assert main([lab_xml, "-o", str(base), "--fail-on", "none", "-q"]) == 0
    assert main([lab_xml, "--baseline", str(base), "--fail-on", "info", "-q"]) == 0
    bad = tmp_path / "bad.json"
    bad.write_text("{")
    assert main([lab_xml, "--baseline", str(bad)]) == 2


def test_many_hosts_many_findings(write_xml, tmp_path: Path) -> None:
    """Reporter stress: 2000 targets x 12 findings renders every format quickly."""
    targets = [
        target(
            port=1000 + i % 60000,
            host=f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}",
            findings=[
                finding(fid=f"f{j}", severity=["HIGH", "MEDIUM", "LOW", "INFO"][j % 4], detail=f"d{i}-{j}")
                for j in range(12)
            ],
        )
        for i in range(2000)
    ]
    xml = write_xml(targets, "big.xml")
    start = time.monotonic()
    for ext in ("json", "csv", "md", "html", "sarif"):
        out = tmp_path / f"big.{ext}"
        assert main([xml, "-o", str(out), "--fail-on", "none", "-q"]) == 0
        assert out.stat().st_size > 0
    assert time.monotonic() - start < 60
    data = json.loads((tmp_path / "big.json").read_text())
    assert data["summary"]["targets"] == 2000
    assert sum(data["summary"]["findings"].values()) == 24000


def test_duplicate_findings_are_kept_with_distinct_details(write_xml) -> None:
    xml = write_xml(
        [
            target(
                findings=[
                    finding("info-disclosure", "LOW", detail="Server: a/1"),
                    finding("info-disclosure", "LOW", detail="X-Powered-By: b/2"),
                ]
            )
        ]
    )
    out = run(xml, "-f", "json", "--fail-on", "none")
    fps = [f["fingerprint"] for f in json.loads(out.stdout)["targets"][0]["findings"]]
    assert len(set(fps)) == 2
