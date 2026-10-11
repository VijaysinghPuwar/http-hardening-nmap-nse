"""Stress and robustness tests: odd HTTP behaviour and argument edge cases,
against lab/server.py with real Nmap. Run with: make stress"""

from __future__ import annotations

import concurrent.futures
import socket
import subprocess
from pathlib import Path

import pytest
from conftest import ROOT, by_port, ids, nmap_exit

LUA = next(
    (c for c in ("lua5.4", "lua") if subprocess.run(["which", c], capture_output=True).returncode == 0),
    None,
)


def one(scan, port: int, args: str = "") -> dict:
    return by_port(scan(str(port), args, service=False))[port]


def run_lua(tmp_path: Path, name: str, source: str, *args: str) -> subprocess.CompletedProcess:
    if LUA is None:
        pytest.fail("no Lua interpreter found (install lua5.4)")
    script = tmp_path / name
    script.write_text(source)
    return subprocess.run(
        [LUA, str(script), str(ROOT) + "/", *args],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )


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
    out = run_lua(tmp_path, "fuzz.lua", FUZZ, str(seed))
    assert out.returncode == 0 and "fuzz ok" in out.stdout, out.stderr


# ---- engine invariants under random input ---------------------------------------

PROPERTIES = """
local root = arg[1]
package.path = root .. "tests/unit/?.lua;" .. package.path
local H = require "harness"
local E = H.load_engine(root .. "http-hardening-check.nse")
math.randomseed(tonumber(arg[2]))
local fails = {}
local function chk(c, m) if not c then fails[#fails + 1] = m end end

-- Adding a policy that closes every gap must silence every CSP weakness,
-- because a browser requires a resource to pass all enforced policies.
local STRICT = "default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'none'"
for _, s in ipairs({"script-src *", "default-src 'unsafe-inline'", "script-src 'unsafe-eval' data:",
                    "", "script-src", ";;;", "script-src 'self'", "default-src https:",
                    "script-src 'nonce-a' 'unsafe-inline'", "script-src 'strict-dynamic' https:"}) do
  for id in pairs(E.csp_weaknesses(E.parse_csp(s .. "," .. STRICT))) do
    chk(false, ("%q combined with a strict policy still reports %s"):format(s, id))
  end
end

-- The score never rises as findings are added, and every grade is a letter.
local f, prev = {}, 101
for _, s in ipairs({"INFO", "INFO", "LOW", "LOW", "MEDIUM", "HIGH", "CRITICAL"}) do
  f[#f + 1] = {severity = s}
  local score, grade = E.score(f)
  chk(score <= prev, "score rose")
  chk(("ABCDF"):find(grade, 1, true), "bad grade " .. tostring(grade))
  prev = score
end

-- clean_paths honours its bound and only emits request-safe absolute paths.
local alpha = "/abc .-_%\\0\\t?#=&\\255AZ09"
for _ = 1, 3000 do
  local list = {}
  for i = 1, math.random(0, 12) do
    local t = {}
    for j = 1, math.random(0, 20) do local k = math.random(1, #alpha); t[j] = alpha:sub(k, k) end
    list[i] = table.concat(t)
  end
  local max = math.random(0, 6)
  local out = E.clean_paths(list, max)
  chk(#out <= max, "clean_paths exceeded max-paths")
  local seen = {}
  for _, p in ipairs(out) do
    chk(p:sub(1, 1) == "/", "not absolute: " .. p)
    chk(not p:find("[%c%s]"), "whitespace survived cleaning")
    chk(#p <= 512, "path longer than the limit survived")
    chk(not seen[p], "duplicate path")
    seen[p] = true
  end
end

-- Anything parse_hsts accepts must be formattable with %d, or check_headers
-- aborts the script when it reports a short max-age.
for _ = 1, 3000 do
  local digits = {}
  for i = 1, math.random(1, 30) do digits[i] = tostring(math.random(0, 9)) end
  local v = E.parse_hsts("max-age=" .. table.concat(digits))
  if v then
    chk(math.type(v.max_age) == "integer", "max-age is not an integer")
    chk(pcall(string.format, "%d", v.max_age), "max-age cannot be formatted")
  end
end

-- Only severities the catalog knows come out, and every id maps to a check.
for _ = 1, 2000 do
  local fs = {}
  for i = 1, math.random(0, 40) do
    fs[i] = {severity = E.SEVERITIES[math.random(1, 5)], id = "id" .. math.random(1, 4), detail = "d"}
  end
  local result, counts = E.summarise(fs, E.SEVERITIES[math.random(1, 5)])
  chk(result == "PASS" or result == "FAIL", "bad result")
  local total = 0
  for _, s in ipairs(E.SEVERITIES) do total = total + counts[s] end
  chk(total == #fs, "counts do not add up")
  for i = 2, #fs do chk(E.RANK[fs[i - 1].severity] <= E.RANK[fs[i].severity], "not sorted by severity") end
end

-- Exposure signatures run on whatever the server returned.
for _, e in ipairs(E.EXPOSURE) do
  if e.sig then
    for _, b in ipairs({"", "\\0\\0\\0\\1Bud1", "PK\\3\\4", string.rep("\\255", 1000),
                        string.rep("a", 70000), "<html>x</html>", "\\n\\n\\n"}) do
      chk(pcall(e.sig, b), e.id .. " signature raised an error")
    end
  end
end

-- judge_probe never invents a finding id the catalog does not have.
for _, status in ipairs({100, 200, 204, 301, 400, 401, 404, 410, 500, 599}) do
  for _, exists in ipairs({{true}, {false}, {}}) do
    local _, id = E.judge_probe("/x", status, "body", nil, exists[1])
    chk(id == nil or E.CHECKS[id], "unknown id " .. tostring(id))
  end
end

print(#fails .. " property failures")
for _, m in ipairs(fails) do print("  - " .. m) end
"""


@pytest.mark.parametrize("seed", [11, 12])
def test_engine_invariants_hold(tmp_path: Path, seed: int):
    out = run_lua(tmp_path, "properties.lua", PROPERTIES, str(seed))
    assert out.returncode == 0, out.stderr
    assert out.stdout.startswith("0 property failures"), out.stdout


# ---- arguments that reach a request or string.format ----------------------------
# Each value below either aborted the script with a Lua error, aborted the
# whole Nmap run, or produced a malformed request line.


@pytest.mark.parametrize("value", ["", "/a b", "/a\tb", "http://example.com/", "/" + "a" * 600])
def test_invalid_path_is_an_argument_error(scan, value):
    t = one(scan, 8445, f'http-hardening-check.path="{value}"')
    assert t["result"] == "ERROR" and t["error"] == "argument-error"
    assert "path" in (t["error_detail"] or "")


def test_path_without_a_leading_slash_is_normalised(scan):
    t = one(scan, 8445, "http-hardening-check.path=meta-csp")
    assert t["result"] != "ERROR" and t["url"].endswith("/meta-csp")


@pytest.mark.parametrize("value", ["", "   ", "a b", "a" * 256])
def test_invalid_vhost_is_an_error_and_does_not_abort_the_scan(scan, value):
    # An empty or over-long SNI name made OpenSSL fail fatally, so Nmap gave up
    # on every host and port in the run.
    report = scan("8445,8081", f'http-hardening-check.vhost="{value}"', service=False)
    assert nmap_exit(report) == "success"
    targets = by_port(report)
    assert set(targets) == {8081, 8445}
    for t in targets.values():
        assert t["result"] == "ERROR" and t["error"] == "argument-error"
        assert "vhost" in (t["error_detail"] or "")


@pytest.mark.parametrize(
    "args",
    [
        "http-hardening-check.hsts-min=1.5",
        "http-hardening-check.hsts-min=1e400",
        "http-hardening-check.hsts-min=-1",
        "http-hardening-check.max-paths=1.5",
        "http-hardening-check.max-paths=1e400",
    ],
)
def test_numeric_arguments_must_be_whole_numbers(scan, args):
    t = one(scan, 8445, args)
    assert t["result"] == "ERROR" and t["error"] == "policy-error"


@pytest.mark.parametrize("value", ["0", "-5", "abc", "1.5", "1e400"])
def test_timeout_edge_values_fall_back_to_the_default(scan, value):
    t = one(scan, 8445, f"http-hardening-check.timeout={value}")
    assert t["result"] == "FAIL" and t["status"] == 200


@pytest.mark.parametrize("document", ["[]", "null", "42", '"text"', "true"])
def test_policy_document_must_be_a_json_object(scan, tmp_path: Path, document):
    path = tmp_path / "policy.json"
    path.write_text(document)
    t = one(scan, 8445, f"http-hardening-check.policy={path}")
    assert t["result"] == "ERROR" and t["error"] == "policy-error"
    assert "JSON object" in (t["error_detail"] or "")


def test_explicit_paths_are_probed_before_the_catalog(scan):
    # With a tight budget the operator's own list must survive, not the catalog.
    t = one(
        scan,
        8180,
        "http-hardening-check.exposure=true,http-hardening-check.max-paths=3,"
        'http-hardening-check.paths="/files/,/mine"',
    )
    probed = [p["path"] for p in t["paths"]]
    assert probed[:2] == ["/files/", "/mine"]
    assert len([p for p in probed if p != "TRACE /"]) == 3


# ---- header values a proxy duplicated or padded ---------------------------------


def test_duplicate_nosniff_header_is_not_a_finding(scan):
    t = one(scan, 8445, "http-hardening-check.path=/dup-xcto")
    assert "xcto-missing" not in ids(t)
    assert "x-content-type-options" in t["passed"]


def test_xcto_is_judged_on_its_first_value(scan):
    t = one(scan, 8445, "http-hardening-check.path=/xcto-sniff-first")
    assert "xcto-missing" in ids(t)


def test_padded_cors_reflection_is_still_high(scan):
    t = one(scan, 8445, "http-hardening-check.path=/cors-padded")
    f = next(f for f in t["findings"] if f["id"] == "cors-reflected-credentials")
    assert f["severity"] == "high"


def test_padded_cors_wildcard_with_credentials_is_flagged(scan):
    t = one(scan, 8445, "http-hardening-check.path=/cors-wildcard-padded")
    assert "cors-wildcard-credentials" in ids(t)


def test_hsts_max_age_larger_than_an_integer(scan):
    t = one(scan, 8445, "http-hardening-check.path=/hsts-huge")
    assert t["result"] != "ERROR"
    assert "hsts" in t["passed"]
    assert not {i for i in ids(t) if i.startswith("hsts-")} - {"hsts-no-subdomains"}


def test_repeated_hsts_directive_is_invalid(scan):
    t = one(scan, 8445, "http-hardening-check.path=/hsts-repeated-directive")
    assert "hsts-invalid" in ids(t)


def test_meta_csp_counts_but_cannot_set_frame_ancestors(scan):
    t = one(scan, 8445, "http-hardening-check.path=/meta-csp")
    assert "csp-missing" not in ids(t) and "csp" in t["passed"]
    # frame-ancestors in a meta tag is ignored, so X-Frame-Options decides.
    assert "framing" in t["passed"]


# ---- redirects a server did not finish ------------------------------------------


@pytest.mark.parametrize("path", ["/empty-location", "/blank-location"])
def test_redirect_without_a_usable_location(scan, path):
    t = one(scan, 8445, f"http-hardening-check.path={path}")
    assert t["status"] == 302
    assert "without a usable Location header" in t["note"]
    assert t["requests"] == 1


def test_redirect_to_an_unusable_target_is_reported(scan):
    t = one(scan, 8445, "http-hardening-check.path=/long-location")
    assert t["status"] == 302 and "unusable Location" in t["note"]
    assert len(t["note"]) < 300  # the server's value is truncated, not echoed whole


# ---- URL formatting -------------------------------------------------------------


def test_ipv6_urls_are_bracketed(scan):
    try:
        with socket.create_connection(("::1", 8086), timeout=2):
            pass
    except OSError:
        pytest.skip("no IPv6 loopback listener in the lab")
    t = by_port(scan("8086", service=False, target="::1"))[8086]
    assert t["url"] == "http://[::1]:8086/"
    assert t["key"] == "http://[::1]:8086"


# ---- soak ------------------------------------------------------------------------

ALL_PORTS = "8080,8081,8082,8180,8443,8444,8445,8000,8088"


def test_every_lab_port_in_one_scan(scan):
    report = scan(ALL_PORTS, service=False)
    targets = by_port(report)
    assert set(targets) == {8080, 8081, 8082, 8180, 8443, 8444, 8445, 8000, 8088}
    # Only the two non-HTTP ports may be errors, and never a Lua failure.
    errors = {p: t["error"] for p, t in targets.items() if t["result"] == "ERROR"}
    assert set(errors) == {8000, 8088}, errors
    assert "Script execution failed" not in report["_stdout"]
    assert nmap_exit(report) == "success"


def test_repeated_scans_are_deterministic(scan):
    runs = [
        {
            p: (t["result"], t["score"], tuple(sorted(ids(t))))
            for p, t in by_port(scan(ALL_PORTS, service=False)).items()
        }
        for _ in range(3)
    ]
    assert runs[1] == runs[0] and runs[2] == runs[0]


def test_many_probe_paths_against_a_silent_port(scan):
    # 25 probes against a server that never answers must still finish and
    # report, not hang or raise.
    paths = ",".join(f"/p{i}" for i in range(25))
    t = one(scan, 8088, f'http-hardening-check.paths="{paths}",http-hardening-check.timeout=400')
    assert t["result"] == "ERROR" and t["error"] == "no-response"
