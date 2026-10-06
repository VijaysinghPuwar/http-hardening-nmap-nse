"""End-to-end tests: real Nmap and the real script against lab/server.py.

Each test names the audit bug or behaviour it guards. Expected finding sets
are exact, so a new false positive fails the test as surely as a miss.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import ROOT, by_port, ids

LAB_PORTS = "8080,8081,8082,8443,8444,8445"


@pytest.fixture(scope="module")
def default(scan):
    return by_port(scan(LAB_PORTS, "http-hardening-check.paths={/admin,/.git/HEAD}"))


@pytest.fixture(scope="module")
def vhost(scan):
    # Quoted-string list form, SNI, suppression and threshold in one run.
    return by_port(
        scan(
            "8443,8444",
            "http-hardening-check.vhost=app.lab.test,"
            'http-hardening-check.paths="/admin,/.git/HEAD",'
            "http-hardening-check.skip={info-disclosure},"
            "http-hardening-check.fail-on=high",
        )
    )


def test_redirect_to_https_passes(default):
    t = default[8080]
    assert ids(t) == set() and t["result"] == "PASS" and t["score"] == 100
    assert t["passed"] == ["https-redirect"]
    assert "redirects (301) to https://localhost:8444/" in t["note"]


def test_bare_http(default):
    assert ids(default[8081]) == {
        "no-https-redirect",
        "csp-missing",
        "framing-missing",
        "xcto-missing",
        "referrer-policy-missing",
        "permissions-policy-missing",
        "info-disclosure",
        "path-exposed",
    }


def test_hsts_not_required_over_http(default):
    # Audit bug #3: plain HTTP is judged on the redirect, never on HSTS.
    for port in (8081, 8082):
        assert "hsts-missing" not in ids(default[port])
    assert ids(default[8082]) == {
        "no-https-redirect",
        "hsts-over-http",
        "csp-report-only",
        "info-disclosure",
        "permissions-policy-missing",
    }


def test_weak_https_values_are_judged(default):
    assert ids(default[8443]) == {
        "hsts-disabled",
        "csp-unsafe-inline",
        "csp-unsafe-eval",
        "csp-broad-script-source",
        "csp-no-base-uri",
        "framing-allowed",
        "xcto-missing",
        "referrer-policy-leaky",
        "xxp-enabled",
        "info-disclosure",
        "permissions-policy-missing",
        "cookie-no-secure",
        "cookie-no-httponly",
        "cookie-no-samesite",
        "cookie-samesite-none-insecure",
        "cookie-flags-nonsession",
        "cors-reflected-credentials",
    }
    t = default[8443]
    assert t["grade"] == "F" and t["result"] == "FAIL"
    cors = next(f for f in t["findings"] if f["id"] == "cors-reflected-credentials")
    assert cors["severity"] == "high" and cors["cwe"] == "CWE-942" and cors["asvs"] == "14.5.3"
    assert "hardening-check.invalid" in cors["evidence"]


def test_soft_404_is_not_reported_as_exposed(default):
    # Audit bug #7: the weak server returns 200 for every path.
    t = default[8443]
    assert "path-exposed" not in ids(t)
    verdicts = {p["path"]: p["verdict"] for p in t["paths"]}
    assert verdicts["/.git/HEAD"] == "absent (soft-404)"
    assert verdicts["/admin"] == "protected"


def test_without_sni_the_default_vhost_is_judged(default):
    assert {"hsts-missing", "csp-missing"} <= ids(default[8444])


def test_partial_edge_cases(default):
    # frame-ancestors * wins over X-Frame-Options SAMEORIGIN (audit bug #4).
    assert ids(default[8445]) == {
        "hsts-short-max-age",
        "hsts-no-subdomains",
        "csp-no-script-restriction",
        "csp-no-base-uri",
        "framing-allowed",
        "referrer-policy-leaky",
        "cors-reflected-origin",
        "permissions-policy-missing",
    }


def test_vhost_sets_sni_and_host(vhost):
    # Audit bug #2: the hardened profile is served only when SNI is app.lab.test.
    # HEAD returns 405 on that server; the script uses GET (audit bug #6).
    t = vhost[8444]
    assert ids(t) == set()
    assert t["url"] == "https://app.lab.test:8444/"
    assert (t["score"], t["grade"], t["result"]) == (100, "A", "PASS")
    assert set(t["passed"]) >= {"hsts", "csp", "framing", "cookies", "permissions-policy"}


def test_quoted_list_skip_and_fail_on(vhost):
    # Audit bug #1: both list syntaxes reach the script intact.
    t = vhost[8443]
    assert "info-disclosure" not in ids(t)
    assert "cors-reflected-credentials" in ids(t)
    assert [p["path"] for p in t["paths"]] == ["/admin", "/.git/HEAD"]
    assert t["fail_on"] == "high"


def test_relative_redirect_is_followed(scan):
    t = by_port(scan("8081", "http-hardening-check.path=/old/page", service=False))[8081]
    assert t["url"].endswith(":8081/index.html")


def test_paths_on_a_redirecting_port(scan):
    # Regression: http.get rewrote options.scheme after a redirect, so later
    # probes were sent over TLS to a plain-HTTP port and got no response.
    t = by_port(scan("8080", "http-hardening-check.paths={/x,/y}", service=False))[8080]
    assert [(p["path"], p["status"]) for p in t["paths"]] == [("/x", 301), ("/y", 301)]


def test_exposure_catalog(scan):
    r = by_port(
        scan(
            "8180,8443",
            "http-hardening-check.exposure=true,http-hardening-check.paths={/files/}",
            service=False,
        )
    )
    exposed = r[8180]
    assert {"exposed-git", "exposed-env", "trace-enabled", "directory-listing"} <= ids(exposed)
    env = next(f for f in exposed["findings"] if f["id"] == "exposed-env")
    assert "not-a-real-secret" not in json.dumps(exposed)  # bodies are never copied into results
    assert env["severity"] == "high" and env["path"] == "/.env"
    # 200-for-everything server: content signatures keep the catalog quiet.
    weak = r[8443]
    assert not {i for i in ids(weak) if i.startswith("exposed-")}
    assert "admin-interface-reachable" not in ids(weak)
    verdicts = {p["path"]: p["verdict"] for p in weak["paths"]}
    assert verdicts["/.env"] == "absent (content not recognised)"
    assert verdicts["TRACE /"] == "not enabled"


def test_exposure_is_off_by_default(default):
    assert default[8081]["paths"] and all(
        p["path"] in ("/admin", "/.git/HEAD") for p in default[8081]["paths"]
    )
    assert not any(p["path"] == "TRACE /" for p in default[8081]["paths"])


def test_request_budget(lab, scan):
    # One GET per port by default. The lab counts requests that carry the
    # script's probe Origin (Nmap's own -sV and soft-404 probes do not).
    lab.SCRIPT_REQUESTS.clear()
    t = by_port(scan("8081,8443", service=False))
    assert lab.SCRIPT_REQUESTS[8081] == 1 and lab.SCRIPT_REQUESTS[8443] == 1
    assert t[8081]["requests"] == 1
    lab.SCRIPT_REQUESTS.clear()
    t = by_port(scan("8180", "http-hardening-check.exposure=true", service=False))
    # 9 catalog paths plus the main page; TRACE has no Origin-counting GET.
    assert lab.SCRIPT_REQUESTS[8180] == 10
    assert t[8180]["requests"] == 11


def test_error_states(scan):
    r = by_port(scan("8000,8088", "http-hardening-check.timeout=1000", service=False))
    assert r[8000]["result"] == "ERROR" and r[8000]["error"] == "unsupported-response"
    assert r[8088]["result"] == "ERROR" and r[8088]["error"] == "no-response"
    for t in r.values():
        assert t["findings"] == [] and t["score"] is None


def test_policy_presets(scan):
    root = ROOT / "policies"
    strict = by_port(
        scan(
            "8444",
            f'http-hardening-check.vhost=app.lab.test,http-hardening-check.policy="{root}/strict.json"',
            service=False,
        )
    )
    t = strict[8444]
    assert t["policy"] == "strict" and t["fail_on"] == "low"
    # Hardened lab sends max-age=63072000; includeSubDomains; preload: strict still passes.
    assert ids(t) == {"cross-origin-isolation-missing"} and t["result"] == "PASS"
    asvs = by_port(scan("8445", f'http-hardening-check.policy="{root}/owasp-asvs-l1.json"', service=False))[
        8445
    ]
    assert asvs["policy"] == "owasp-asvs-l1"
    hsts = next(f for f in asvs["findings"] if f["id"] == "hsts-no-subdomains")
    assert hsts["severity"] == "low"  # required by ASVS 14.4.5, so raised from info


def test_bad_policy_is_an_error_not_a_pass(scan, tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"fail_on": "urgent"}')
    typo = tmp_path / "typo.json"
    typo.write_text('{"checks": {"csp-mising": {"enabled": false}}}')
    for path, needle in [
        (bad, "fail_on"),
        (typo, "csp-mising"),
        (tmp_path / "missing.json", "cannot open"),
        (tmp_path, ""),
    ]:
        t = by_port(scan("8081", f'http-hardening-check.policy="{path}"', service=False))[8081]
        assert t["result"] == "ERROR" and t["error"] == "policy-error", path
        assert needle in (t["error_detail"] or "")


def test_bad_arguments_are_errors(scan):
    t = by_port(scan("8081", "http-hardening-check.fail-on=urgent", service=False))[8081]
    assert t["error"] == "policy-error"
    t = by_port(scan("8081", "http-hardening-check.skip={not-a-check}", service=False))[8081]
    assert t["error"] == "policy-error" and "not-a-check" in t["error_detail"]


def test_reporter_ci_gate_on_real_scan(scan, tmp_path: Path):
    xml = scan(LAB_PORTS, "http-hardening-check.vhost=app.lab.test", service=False)["_xml"]

    def report(*args: str) -> int:
        return subprocess.run([sys.executable, "-m", "hhc_report", xml, "-q", *args], check=False).returncode

    assert report("--fail-on", "high") == 1  # CORS with credentials on 8443
    assert report("--fail-on", "critical") == 0
    assert report() == 1  # policy mode
    hardened = scan("8444", "http-hardening-check.vhost=app.lab.test", service=False)["_xml"]
    assert (
        subprocess.run(
            [sys.executable, "-m", "hhc_report", hardened, "-q", "--fail-on", "info"], check=False
        ).returncode
        == 0
    )
    for fmt in ("json", "csv", "markdown", "html", "sarif"):
        out = tmp_path / f"r.{fmt}"
        rc = subprocess.run(
            [sys.executable, "-m", "hhc_report", xml, "-q", "-f", fmt, "-o", str(out), "--fail-on", "none"],
            check=False,
        ).returncode
        assert rc == 0 and out.stat().st_size > 0
