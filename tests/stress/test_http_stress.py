"""Stress and robustness tests: odd HTTP behaviour and argument edge cases,
against lab/server.py with real Nmap. Run with: make stress"""

from __future__ import annotations

import concurrent.futures
import subprocess
from pathlib import Path

import pytest
from conftest import ROOT, by_port, ids


def one(scan, port: int, args: str = "") -> dict:
    return by_port(scan(str(port), args, service=False))[port]


# ---- HTTP status codes on the evaluated page --------------------------------


@pytest.mark.parametrize("code", [200, 204, 400, 401, 403, 404, 405, 429, 500, 501])
def test_status_codes_are_judged_not_errors(scan, code):
    t = one(scan, 8081, f"http-hardening-check.path=/status/{code}")
    assert t["result"] in ("PASS", "FAIL") and t["status"] == code
    assert "no-https-redirect" in ids(t)  # headers are still judged
    if code >= 400:
        assert f"status {code}: headers judged on an error response" in t["note"]


@pytest.mark.parametrize("code", [301, 302, 307, 308])
def test_redirect_without_location(scan, code):
    t = one(scan, 8081, f"http-hardening-check.path=/status/{code}")
    assert t["status"] == code and "without a usable Location header" in t["note"]


def test_redirect_loop_terminates(scan):
    t = one(scan, 8081, "http-hardening-check.path=/loop/a")
    assert "redirect loop" in t["note"] and t["requests"] <= 4


def test_redirect_chain_to_https_on_another_port(scan):
    t = one(scan, 8080)
    assert t["passed"] == ["https-redirect"] and t["requests"] == 1


# ---- header edge cases ----------------------------------------------------------


def test_duplicate_csp_headers_are_combined(scan):
    # script-src * in one policy is closed by script-src 'self' in the other.
    t = one(scan, 8445, "http-hardening-check.path=/dup-csp")
    assert "csp-broad-script-source" not in ids(t)
    assert "csp-no-script-restriction" not in ids(t)
    assert "csp" in t["passed"]


def test_oversized_header(scan):
    t = one(scan, 8445, "http-hardening-check.path=/big-header")
    assert t["result"] != "ERROR" and t["status"] == 200


def test_many_set_cookie_headers(scan):
    t = one(scan, 8445, "http-hardening-check.path=/cookies")
    secure = next(f for f in t["findings"] if f["id"] == "cookie-no-secure")
    assert secure["detail"].endswith(": sessionid")  # the 29 well-flagged cookies pass


def test_head_405_does_not_matter(scan):
    # 8444 answers HEAD with 405; the script only uses GET.
    t = one(scan, 8444, "http-hardening-check.vhost=app.lab.test")
    assert t["status"] == 200 and ids(t) == set()


# ---- script arguments -----------------------------------------------------------


def test_no_arguments(scan):
    t = one(scan, 8081)
    assert t["paths"] == [] and t["policy"] == "baseline" and t["fail_on"] == "medium"


@pytest.mark.parametrize(
    "value, expected",
    [
        ("/a", ["/a"]),
        ('"/a,/b"', ["/a", "/b"]),
        ("{/a,/b}", ["/a", "/b"]),
        ("{/a,/a,/b}", ["/a", "/b"]),
        ('"/a,,/b, "', ["/a", "/b"]),
        ("{a}", ["/a"]),
        ('"/%2e%2e/,/search?q=1"', ["/%2e%2e/", "/search?q=1"]),
    ],
)
def test_path_list_forms(scan, value, expected):
    t = one(scan, 8081, f"http-hardening-check.paths={value}")
    assert [p["path"] for p in t["paths"]] == expected


def test_large_path_list_is_bounded(scan):
    paths = ",".join(f"/p{i}" for i in range(200))
    t = one(scan, 8081, f'http-hardening-check.paths="{paths}"')
    assert len(t["paths"]) == 25
    assert any("truncated" in w for w in t["warnings"])
    t = one(scan, 8081, f'http-hardening-check.paths="{paths}",http-hardening-check.max-paths=3')
    assert len(t["paths"]) == 3


def test_url_instead_of_path_is_refused(scan):
    t = one(scan, 8081, 'http-hardening-check.paths="http://example.com/,/ok"')
    assert [p["path"] for p in t["paths"]] == ["/ok"]
    assert any("absolute URLs are not allowed" in w for w in t["warnings"])


@pytest.mark.parametrize(
    "args",
    [
        "http-hardening-check.hsts-min=abc",
        "http-hardening-check.max-paths=-1",
        "http-hardening-check.fail-on=",
        "http-hardening-check.skip={hsts-missing,bogus}",
    ],
)
def test_malformed_values_are_policy_errors(scan, args):
    t = one(scan, 8081, args)
    assert t["result"] == "ERROR" and t["error"] == "policy-error"


@pytest.mark.parametrize(
    "args",
    [
        "http-hardening-check.timeout=abc",
        "http-hardening-check.exposure=maybe",
    ],
)
def test_unparseable_optional_values_fall_back_to_defaults(scan, args):
    t = one(scan, 8081, args)
    assert t["result"] == "FAIL" and t["paths"] == []


def test_removed_v1_arguments_warn(scan):
    t = one(scan, 8081, "http-hardening-check.headers=hsts,http-hardening-check.brief=true")
    assert len([w for w in t["warnings"] if "was removed in v2" in w]) == 2


def test_fail_on_every_level(scan):
    results = {
        lvl: one(scan, 8445, f"http-hardening-check.fail-on={lvl}")["result"]
        for lvl in ("critical", "high", "medium", "low", "info")
    }
    # 8445 has medium, low and info findings and no high or critical.
    assert results == {"critical": "PASS", "high": "PASS", "medium": "FAIL", "low": "FAIL", "info": "FAIL"}


# ---- concurrency ------------------------------------------------------------------


def test_parallel_scans_agree(scan):
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: ids(one(scan, 8443)), range(4)))
    assert all(r == results[0] for r in results)


# ---- parser fuzzing (Lua engine on arbitrary bytes) -----------------------------

FUZZ = """
local root = arg[1]
package.path = root .. "tests/unit/?.lua;" .. package.path
local H = require "harness"
local E = H.load_engine(root .. "http-hardening-check.nse")
math.randomseed(tonumber(arg[2]))
local alphabet = "abcdefghijklmnopqrstuvwxyz-;,='\\" *:/%0123456789 \\t\\0\\255"
for _ = 1, 3000 do
  local n = math.random(0, 300)
  local t = {}
  for i = 1, n do
    local k = math.random(1, #alphabet)
    t[i] = alphabet:sub(k, k)
  end
  local s = table.concat(t)
  E.csp_weaknesses(E.parse_csp(s))
  E.parse_hsts(s)
  E.referrer_policy(s)
  E.permissions_open(s)
  E.framing(E.parse_csp(s), s)
  E.meta_csp("<meta http-equiv='Content-Security-Policy' content='" .. s .. "'>")
  E.clean_path(s)
  E.cookie_kind(s)
  E.is_directory_listing(s)
end
print("fuzz ok")
"""


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_parsers_survive_random_input(tmp_path: Path, seed: int):
    lua = next(
        (c for c in ("lua5.4", "lua") if subprocess.run(["which", c], capture_output=True).returncode == 0),
        None,
    )
    if lua is None:
        pytest.fail("no Lua interpreter found (install lua5.4)")
    script = tmp_path / "fuzz.lua"
    script.write_text(FUZZ)
    out = subprocess.run(
        [lua, str(script), str(ROOT) + "/", str(seed)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert out.returncode == 0 and "fuzz ok" in out.stdout, out.stderr
