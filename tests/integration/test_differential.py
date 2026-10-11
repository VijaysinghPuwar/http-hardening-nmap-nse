"""Compares this script with Nmap's own http-security-headers on the same
targets.

http-security-headers lists the headers it finds. This script judges their
values. These tests pin that difference: for every header the other script
reports, we must either pass it or raise a finding about its value, and every
header that is present but ineffective must produce a finding.
"""

from __future__ import annotations

import re
import shlex
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from conftest import NMAP, SCRIPT, by_port, ids

# Header name -> (the check that passes it, the checks that judge its value).
JUDGED = {
    "Strict-Transport-Security": (
        "hsts",
        {
            "hsts-invalid",
            "hsts-disabled",
            "hsts-short-max-age",
            "hsts-no-subdomains",
            "hsts-no-preload",
            "hsts-over-http",  # the header is there and browsers ignore it
        },
    ),
    "X-Frame-Options": ("framing", {"framing-allowed", "framing-missing"}),
    "X-Content-Type-Options": ("x-content-type-options", {"xcto-missing"}),
    "Content-Security-Policy": (
        "csp",
        {
            "csp-no-script-restriction",
            "csp-unsafe-inline",
            "csp-unsafe-eval",
            "csp-broad-script-source",
            "csp-no-object-src",
            "csp-no-base-uri",
        },
    ),
    "X-XSS-Protection": (None, {"xxp-enabled"}),
}


def listed_headers(xml_path: str, port: int) -> dict[str, str]:
    """Header name -> value, as http-security-headers reported them."""
    root = ET.parse(xml_path).getroot()
    for p in root.iter("port"):
        if int(str(p.get("portid"))) != port:
            continue
        script = p.find("script[@id='http-security-headers']")
        if script is None:
            return {}
        found = {}
        for elem in script.iter("elem"):
            m = re.match(r"^Header:\s*([A-Za-z-]+):\s*(.*)$", (elem.text or "").strip(), re.DOTALL)
            if m:
                found[m.group(1)] = m.group(2).strip()
        return found
    return {}


@pytest.fixture(scope="module")
def both(lab, tmp_path_factory: pytest.TempPathFactory) -> dict[int, tuple[dict[str, str], dict]]:
    """Runs both scripts in one scan so they see the same responses."""
    out = tmp_path_factory.mktemp("diff") / "both.xml"
    ports = "8081,8082,8443,8445"
    cmd = [
        *NMAP,
        "-Pn",
        "-sT",
        "-sV",
        "--version-light",
        "-p",
        ports,
        "--script",
        f"{SCRIPT},http-security-headers",
        "-oX",
        str(out),
        "127.0.0.1",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
    assert proc.returncode == 0, proc.stderr
    from hhc_report.model import load

    ours = by_port(load([str(out)]))
    return {port: (listed_headers(str(out), port), ours[port]) for port in (8081, 8082, 8443, 8445)}


def test_both_scripts_ran(both):
    # 8081 sends no security headers at all, so the other script stays silent.
    assert both[8081][0] == {}
    assert all(both[p][0] for p in (8082, 8443, 8445)), "http-security-headers found nothing to compare"


@pytest.mark.parametrize("port", [8082, 8443, 8445])
def test_every_listed_header_is_judged(both, port):
    """No header is merely acknowledged: each one is passed or judged."""
    listed, ours = both[port]
    found = ids(ours)
    passed = set(ours["passed"])
    for name, value in listed.items():
        if name not in JUDGED:
            continue
        passes, verdicts = JUDGED[name]
        judged = bool(verdicts & found) or (passes is not None and passes in passed)
        assert judged, f"{name}: {value!r} on port {port} was listed but not judged"


def test_headers_that_are_present_but_ineffective_are_findings(both):
    """The cases the README promises: a header is there, and it does nothing."""
    listed, ours = both[8443]
    found = ids(ours)
    assert listed["Strict-Transport-Security"] == "max-age=0"
    assert "hsts-disabled" in found
    assert listed["X-Frame-Options"].lower().startswith("allow-from")
    assert "framing-allowed" in found
    assert listed["X-Content-Type-Options"] == "sniff"
    assert "xcto-missing" in found
    assert "unsafe-inline" in listed["Content-Security-Policy"]
    assert {"csp-unsafe-inline", "csp-unsafe-eval", "csp-broad-script-source"} <= found
    assert listed["X-XSS-Protection"].startswith("1")
    assert "xxp-enabled" in found
    # The other script lists five headers and calls it a day; we grade the port.
    assert ours["grade"] == "F" and ours["result"] == "FAIL"


def test_a_long_hsts_header_is_not_a_finding_for_either(both):
    # 8082 sends HSTS over plain HTTP: listed by the other script, and we say
    # why it does nothing (browsers ignore it) instead of treating it as a pass.
    listed, ours = both[8082]
    assert listed["Strict-Transport-Security"] == "max-age=31536000"
    assert "hsts-over-http" in ids(ours)
    assert "hsts" not in ours["passed"]


def test_findings_we_raise_that_the_other_script_cannot_see(both):
    """Checks with no counterpart in http-security-headers at all."""
    _, ours = both[8443]
    found = ids(ours)
    assert {"cors-reflected-credentials", "cookie-no-secure", "referrer-policy-leaky"} <= found
    _, partial = both[8445]
    assert "permissions-policy-missing" in ids(partial)


def test_our_script_name_is_stable(both):
    # The reporter keys off this id; renaming the file would break both.
    assert Path(SCRIPT).name == "http-hardening-check.nse"
    assert shlex.split(" ".join(NMAP))[0]
