"""End-to-end test against real nginx and Apache in lab/docker.

The scanner container runs Alpine's Nmap (a different version from the host),
scans the targets by name (so Nmap sets SNI and Host itself) and renders every
report format. Skipped only when Docker is unavailable; CI sets
HHC_REQUIRE_DOCKER=1 so a missing Docker fails instead of skipping.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from conftest import ROOT, ids
from hhc_report.model import load

LAB = ROOT / "lab" / "docker"
OUT = LAB / "out"


def docker_ok() -> bool:
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "info"], capture_output=True, check=False).returncode == 0


def compose(*args: str, timeout: int = 900) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "HHC_UID": str(os.getuid()), "HHC_GID": str(os.getgid())}
    return subprocess.run(
        ["docker", "compose", "-f", str(LAB / "docker-compose.yml"), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
        check=False,
    )


@pytest.fixture(scope="module")
def docker_scan():
    if not docker_ok():
        if os.environ.get("HHC_REQUIRE_DOCKER") == "1":
            pytest.fail("Docker is required (HHC_REQUIRE_DOCKER=1) but not available")
        pytest.skip("Docker is not available")
    up = compose("up", "-d", "--build", "--wait")
    assert up.returncode == 0, up.stderr
    for f in OUT.glob("report.*"):
        f.unlink()
    run = compose("run", "--rm", "--build", "scanner")
    assert run.returncode == 0, run.stdout + run.stderr
    report = load([str(OUT / "scan.xml")])
    yield {(t["url"].split("//")[1].split(":")[0], t["port"]): t for t in report["targets"]}, run.stdout


def test_hardened_nginx(docker_scan):
    t, _ = docker_scan
    assert t[("hardened.lab", 80)]["passed"] == ["https-redirect"]
    h = t[("hardened.lab", 443)]
    assert ids(h) == set(), h["findings"]
    assert (h["score"], h["grade"], h["result"]) == (100, "A", "PASS")


def test_weak_nginx(docker_scan):
    t, _ = docker_scan
    w = t[("weak.lab", 443)]
    assert {
        "cors-reflected-credentials",
        "exposed-git",
        "exposed-env",
        "directory-listing",
        "cookie-no-secure",
        "csp-unsafe-inline",
        "csp-broad-script-source",
        "framing-allowed",
        "hsts-short-max-age",
        "info-disclosure",
    } <= ids(w)
    assert w["grade"] == "F"
    plain = t[("weak.lab", 80)]
    assert "hsts-over-http" in ids(plain) and "hsts-missing" not in ids(plain)


def test_spa_soft_404(docker_scan):
    t, _ = docker_scan
    for port in (80, 443):
        s = t[("spa.lab", port)]
        assert not {
            i
            for i in ids(s)
            if i.startswith("exposed-")
            or i in ("path-exposed", "admin-interface-reachable", "directory-listing")
        }
        verdicts = {p["path"]: p["verdict"] for p in s["paths"]}
        assert verdicts["/admin"] == "absent (soft-404)"
        assert verdicts["/.env"] == "absent (content not recognised)"
    assert "hsts-missing" in ids(t[("spa.lab", 443)])
    assert "no-https-redirect" in ids(t[("spa.lab", 80)])


def test_mixed_apache(docker_scan):
    t, _ = docker_scan
    m = t[("mixed.lab", 80)]
    assert {
        "exposed-server-status",
        "trace-enabled",
        "csp-report-only",
        "info-disclosure",
        "referrer-policy-leaky",
    } <= ids(m)
    assert "framing-missing" not in ids(m)  # X-Frame-Options SAMEORIGIN


def test_reports_rendered_without_secrets(docker_scan):
    _, stdout = docker_scan
    assert "cors-reflected-credentials" in stdout
    for ext in ("json", "csv", "md", "html", "sarif"):
        text = (OUT / f"report.{ext}").read_text(encoding="utf-8")
        assert text and "not-a-real-secret" not in text, ext
    assert json.loads((OUT / "report.sarif").read_text())["version"] == "2.1.0"
    assert not any(str(Path.home()) in (OUT / f"report.{e}").read_text() for e in ("json", "html", "md"))
