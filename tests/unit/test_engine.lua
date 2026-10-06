-- Unit tests for the evaluation engine in http-hardening-check.nse.
--   lua tests/unit/test_engine.lua        (from the repository root)
local root = (arg and arg[0] or ""):match("^(.*)tests[/\\]unit[/\\]") or "./"
package.path = root .. "tests/unit/?.lua;" .. package.path

local H = require "harness"
local json = require "json"
local E = H.load_engine(root .. "http-hardening-check.nse")
local test, eq, ok = H.test, H.eq, H.ok

-- Runs check_headers on a synthetic response and returns {id = severity}.
local function judge(header, opts)
  opts = opts or {}
  local r = E.new_result(opts.policy or E.default_policy())
  E.check_headers({header = header, cookies = opts.cookies or {}, body = opts.body}, opts.tls ~= false, r, "/")
  local ids = {}
  for _, f in ipairs(r.findings) do ids[f.id] = f.severity end
  return ids, r
end

local HARDENED = {
  ["strict-transport-security"] = "max-age=63072000; includeSubDomains; preload",
  ["content-security-policy"] = "default-src 'self'; script-src 'self' 'nonce-abc'; object-src 'none'; "
    .. "base-uri 'none'; frame-ancestors 'none'",
  ["x-content-type-options"] = "nosniff",
  ["referrer-policy"] = "strict-origin-when-cross-origin",
  ["permissions-policy"] = "camera=(), microphone=(), geolocation=()",
}

local function with(base, changes)
  local t = {}
  for k, v in pairs(base) do t[k] = v end
  for k, v in pairs(changes) do
    if v == false then t[k] = nil else t[k] = v end
  end
  return t
end

-- ---- argument parsing (audit bug #1) ---------------------------------------

test("to_list: comma string", function() eq(E.to_list("/a,/b"), {"/a", "/b"}) end)
test("to_list: Nmap table form", function() eq(E.to_list({"/a", "/b"}), {"/a", "/b"}) end)
test("to_list: single value", function() eq(E.to_list("/admin"), {"/admin"}) end)
test("to_list: nil and empty", function()
  eq(E.to_list(nil), {})
  eq(E.to_list(""), {})
  eq(E.to_list(",,,"), {})
end)
test("to_list: trims, drops empties and duplicates, keeps order", function()
  eq(E.to_list(" /b , /a,,/b ,/a"), {"/b", "/a"})
end)
test("to_bool", function()
  eq(E.to_bool("true", false), true)
  eq(E.to_bool("YES", false), true)
  eq(E.to_bool("0", true), false)
  eq(E.to_bool(nil, true), true)
  eq(E.to_bool("maybe", false), false)
end)

-- ---- path cleaning ---------------------------------------------------------

test("clean_path: adds leading slash", function() eq(E.clean_path("admin"), "/admin") end)
test("clean_path: rejects whitespace, control characters and URLs", function()
  ok(not E.clean_path("/a b"))
  ok(not E.clean_path("/a\r\nHost: x"))
  ok(not E.clean_path("http://evil.example/"))
  ok(not E.clean_path(""))
  ok(not E.clean_path("/" .. string.rep("a", 600)))
end)
test("clean_path: keeps query strings and encoded characters", function()
  eq(E.clean_path("/search?q=%2e%2e/"), "/search?q=%2e%2e/")
end)
test("clean_paths: dedupes after normalising and bounds the list", function()
  local list = {}
  for i = 1, 100 do list[#list + 1] = "/p" .. i end
  table.insert(list, 1, "p1")
  local out, warnings = E.clean_paths(list, 25)
  eq(#out, 25)
  eq(out[1], "/p1")
  ok(warnings[1]:find("truncated"), "expected a truncation warning")
end)
test("clean_paths: reports skipped values", function()
  local out, warnings = E.clean_paths({"/ok", "/bad path"}, 10)
  eq(out, {"/ok"})
  eq(#warnings, 1)
end)

-- ---- HSTS (audit bug #3) ---------------------------------------------------

test("parse_hsts: valid header", function()
  eq(E.parse_hsts("max-age=31536000; includeSubDomains; preload"),
    {max_age = 31536000, subdomains = true, preload = true})
end)
test("parse_hsts: quoted max-age", function() eq(E.parse_hsts('max-age="600"').max_age, 600) end)
test("parse_hsts: only the first header counts", function()
  eq(E.parse_hsts("max-age=0, max-age=31536000").max_age, 0)
end)
test("parse_hsts: duplicate directive is invalid", function()
  local v, why = E.parse_hsts("max-age=1; max-age=2")
  ok(not v)
  ok(why:find("twice"))
end)
test("parse_hsts: missing or non-numeric max-age is invalid", function()
  ok(not E.parse_hsts("includeSubDomains"))
  ok(not E.parse_hsts("max-age=abc"))
end)
test("HSTS is not required over plain HTTP", function()
  local ids = judge({}, {tls = false})
  eq(ids["hsts-missing"], nil)
  eq(ids["no-https-redirect"], "MEDIUM")
end)
test("HSTS sent over HTTP is noted as INFO only", function()
  local ids = judge({["strict-transport-security"] = "max-age=31536000"}, {tls = false})
  eq(ids["hsts-over-http"], "INFO")
end)
test("HSTS missing over HTTPS is MEDIUM", function()
  eq(judge(with(HARDENED, {["strict-transport-security"] = false}))["hsts-missing"], "MEDIUM")
end)
test("HSTS max-age=0 and short max-age", function()
  eq(judge(with(HARDENED, {["strict-transport-security"] = "max-age=0"}))["hsts-disabled"], "MEDIUM")
  eq(judge(with(HARDENED, {["strict-transport-security"] = "max-age=86400"}))["hsts-short-max-age"], "LOW")
end)
test("HSTS invalid header is reported", function()
  eq(judge(with(HARDENED, {["strict-transport-security"] = "max-age=1; max-age=2"}))["hsts-invalid"], "MEDIUM")
end)
test("HSTS includeSubDomains: INFO by default, LOW when the policy requires it", function()
  local h = with(HARDENED, {["strict-transport-security"] = "max-age=31536000"})
  eq(judge(h)["hsts-no-subdomains"], "INFO")
  local p = E.default_policy()
  p.hsts.require_include_subdomains = true
  eq(judge(h, {policy = p})["hsts-no-subdomains"], "LOW")
end)
test("HSTS preload: off by default, LOW when required, never inferred from the directive", function()
  local h = with(HARDENED, {["strict-transport-security"] = "max-age=31536000; includeSubDomains"})
  eq(judge(h)["hsts-no-preload"], nil)
  local p = E.default_policy()
  p.hsts.require_preload = true
  eq(judge(h, {policy = p})["hsts-no-preload"], "LOW")
  local _, r = judge(HARDENED, {policy = p})
  eq(#r.findings, 0)
end)

-- ---- CSP -------------------------------------------------------------------

test("parse_csp: first directive occurrence wins", function()
  local p = E.parse_csp("script-src 'self'; script-src *")
  eq(p[1]["script-src"], {"'self'"})
end)
test("parse_csp: comma separates policies", function()
  eq(#E.parse_csp("script-src *, script-src 'self'"), 2)
end)
test("CSP missing and Report-Only", function()
  eq(judge(with(HARDENED, {["content-security-policy"] = false}))["csp-missing"], "MEDIUM")
  local ids = judge(with(HARDENED, {["content-security-policy"] = false,
    ["content-security-policy-report-only"] = "default-src 'self'"}))
  eq(ids["csp-report-only"], "LOW")
  eq(ids["csp-missing"], nil)
end)
test("CSP unsafe-inline is ignored when a nonce or hash is present", function()
  local ids = judge(with(HARDENED, {["content-security-policy"] =
    "script-src 'self' 'nonce-x' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"}))
  eq(ids["csp-unsafe-inline"], nil)
  ids = judge(with(HARDENED, {["content-security-policy"] =
    "script-src 'self' 'sha256-abc=' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"}))
  eq(ids["csp-unsafe-inline"], nil)
end)
test("CSP weak script sources", function()
  local ids = judge(with(HARDENED, {["content-security-policy"] =
    "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https: data:; frame-ancestors 'none'"}))
  eq(ids["csp-unsafe-inline"], "MEDIUM")
  eq(ids["csp-unsafe-eval"], "LOW")
  eq(ids["csp-broad-script-source"], "MEDIUM")
end)
test("CSP strict-dynamic neutralises host and scheme sources", function()
  local ids = judge(with(HARDENED, {["content-security-policy"] =
    "script-src 'nonce-x' 'strict-dynamic' https: http:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"}))
  eq(ids["csp-broad-script-source"], nil)
end)
test("CSP falls back to default-src for scripts and objects", function()
  local ids = judge(with(HARDENED,
    {["content-security-policy"] = "default-src *; base-uri 'self'; frame-ancestors 'self'"}))
  eq(ids["csp-broad-script-source"], "MEDIUM")
  eq(ids["csp-no-object-src"], "LOW")
end)
test("CSP without script-src or default-src", function()
  local ids = judge(with(HARDENED, {["content-security-policy"] = "frame-ancestors 'none'"}))
  eq(ids["csp-no-script-restriction"], "MEDIUM")
  eq(ids["csp-no-object-src"], "LOW")
  eq(ids["csp-no-base-uri"], "INFO")
end)
test("CSP: a weakness counts only if every enforced policy has it", function()
  -- The second policy restricts scripts, so the first policy's * is closed.
  local w = E.csp_weaknesses(E.parse_csp("script-src *; object-src 'none'; base-uri 'none', script-src 'self'"))
  eq(w["csp-broad-script-source"], nil)
  eq(w["csp-no-script-restriction"], nil)
  -- Both policies allow inline script: still a weakness.
  w = E.csp_weaknesses(E.parse_csp("script-src 'unsafe-inline', default-src 'self' 'unsafe-inline'"))
  ok(w["csp-unsafe-inline"])
end)
test("CSP from a meta tag is evaluated, but its frame-ancestors is ignored", function()
  local body = [[<html><head><meta http-equiv="Content-Security-Policy"
    content="default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"></head>]]
  local ids = judge(with(HARDENED, {["content-security-policy"] = false}), {body = body})
  eq(ids["csp-missing"], nil)
  eq(ids["framing-missing"], "MEDIUM")
end)
test("meta_csp: single quotes, entities, case", function()
  eq(E.meta_csp([[<META HTTP-EQUIV='content-security-policy' CONTENT='script-src &#39;self&#39;'>]]),
    "script-src 'self'")
  eq(E.meta_csp("<meta name=viewport content=x>"), nil)
end)

-- ---- framing (audit bug #4) ------------------------------------------------

test("frame-ancestors alone satisfies framing protection", function()
  local ids = judge(HARDENED)
  eq(ids["framing-missing"], nil)
  eq(ids["framing-allowed"], nil)
end)
test("frame-ancestors * is reported even with X-Frame-Options DENY", function()
  local ids = judge(with(HARDENED, {["content-security-policy"] = "default-src 'self'; frame-ancestors *",
    ["x-frame-options"] = "DENY"}))
  eq(ids["framing-allowed"], "MEDIUM")
end)
test("X-Frame-Options values", function()
  local base = with(HARDENED, {["content-security-policy"] = "default-src 'self'; base-uri 'none'"})
  eq(judge(with(base, {["x-frame-options"] = "SAMEORIGIN"}))["framing-allowed"], nil)
  eq(judge(with(base, {["x-frame-options"] = "DENY, DENY"}))["framing-allowed"], nil)
  eq(judge(with(base, {["x-frame-options"] = "DENY, SAMEORIGIN"}))["framing-allowed"], "MEDIUM")
  eq(judge(with(base, {["x-frame-options"] = "ALLOW-FROM https://a.example"}))["framing-allowed"], "MEDIUM")
  eq(judge(with(base, {["x-frame-options"] = "bogus"}))["framing-allowed"], "MEDIUM")
  eq(judge(base)["framing-missing"], "MEDIUM")
end)

-- ---- other headers -----------------------------------------------------------

test("X-Content-Type-Options must be nosniff", function()
  eq(judge(with(HARDENED, {["x-content-type-options"] = "sniff"}))["xcto-missing"], "LOW")
  eq(judge(with(HARDENED, {["x-content-type-options"] = " NoSniff "}))["xcto-missing"], nil)
end)
test("Referrer-Policy: last recognised value wins", function()
  eq(E.referrer_policy("no-referrer, unsafe-url"), "unsafe-url")
  eq(E.referrer_policy("unsafe-url, bogus"), "unsafe-url")
  eq(E.referrer_policy("bogus"), nil)
  eq(judge(with(HARDENED, {["referrer-policy"] = "no-referrer-when-downgrade"}))["referrer-policy-leaky"], "LOW")
  eq(judge(with(HARDENED, {["referrer-policy"] = "bogus"}))["referrer-policy-missing"], "INFO")
end)
test("Permissions-Policy: missing, permissive, restrictive", function()
  eq(judge(with(HARDENED, {["permissions-policy"] = false}))["permissions-policy-missing"], "INFO")
  eq(E.permissions_open("camera=*, geolocation=(self), microphone=(*)"), {"camera", "microphone"})
  eq(judge(with(HARDENED, {["permissions-policy"] = "camera=*"}))["permissions-policy-permissive"], "LOW")
  eq(E.permissions_open("camera=(), display-capture=(self)"), {})
end)
test("Cross-origin isolation headers are off by default", function()
  eq(judge(HARDENED)["cross-origin-isolation-missing"], nil)
  local p = E.apply_policy({checks = {["cross-origin-isolation-missing"] = {enabled = true}}})
  eq(judge(HARDENED, {policy = p})["cross-origin-isolation-missing"], "INFO")
end)
test("Version disclosure: versioned is LOW, unversioned is INFO", function()
  local ids = judge(with(HARDENED, {server = "nginx/1.25.3", ["x-powered-by"] = "Express"}))
  eq(ids["info-disclosure"], "LOW")
  eq(ids["tech-disclosure"], "INFO")
  eq(judge(with(HARDENED, {server = "nginx"}))["info-disclosure"], nil)
end)
test("Deprecated headers are INFO", function()
  local ids = judge(with(HARDENED, {["x-xss-protection"] = "1; mode=block", ["expect-ct"] = "max-age=0",
    ["public-key-pins"] = "pin-sha256=\"x\""}))
  eq(ids["xxp-enabled"], "INFO")
  eq(ids["expect-ct-present"], "INFO")
  eq(ids["hpkp-present"], "INFO")
  eq(judge(with(HARDENED, {["x-xss-protection"] = "0"}))["xxp-enabled"], nil)
end)

-- ---- CORS --------------------------------------------------------------------

test("CORS reflection with and without credentials", function()
  local ids = judge(with(HARDENED, {["access-control-allow-origin"] = E.PROBE_ORIGIN,
    ["access-control-allow-credentials"] = "true"}))
  eq(ids["cors-reflected-credentials"], "HIGH")
  ids = judge(with(HARDENED, {["access-control-allow-origin"] = E.PROBE_ORIGIN}))
  eq(ids["cors-reflected-origin"], "LOW")
end)
test("CORS wildcard alone is not a finding; with credentials it is LOW", function()
  eq(judge(with(HARDENED, {["access-control-allow-origin"] = "*"}))["cors-wildcard-credentials"], nil)
  eq(judge(with(HARDENED, {["access-control-allow-origin"] = "*",
    ["access-control-allow-credentials"] = "true"}))["cors-wildcard-credentials"], "LOW")
  eq(judge(with(HARDENED, {["access-control-allow-origin"] = "https://partner.example",
    ["access-control-allow-credentials"] = "true"}))["cors-reflected-credentials"], nil)
end)

-- ---- cookies -----------------------------------------------------------------

test("cookie_kind", function()
  eq(E.cookie_kind("PHPSESSID"), "session")
  eq(E.cookie_kind("connect.sid"), "session")
  eq(E.cookie_kind("auth_token"), "session")
  eq(E.cookie_kind("csrftoken"), "csrf")
  eq(E.cookie_kind("XSRF-TOKEN"), "csrf")
  eq(E.cookie_kind("theme"), "other")
  eq(E.cookie_kind("side_panel"), "other")
end)
test("Session cookie flags over HTTPS", function()
  local ids = judge(HARDENED, {cookies = {{name = "session", value = "x"}}})
  eq(ids["cookie-no-secure"], "MEDIUM")
  eq(ids["cookie-no-httponly"], "LOW")
  eq(ids["cookie-no-samesite"], "INFO")
end)
test("Secure is not demanded over plain HTTP", function()
  local ids = judge({}, {tls = false, cookies = {{name = "session", value = "x", httponly = ""}}})
  eq(ids["cookie-no-secure"], nil)
end)
test("CSRF cookies may be readable by scripts", function()
  local ids = judge(HARDENED, {cookies = {{name = "csrftoken", value = "x", secure = "", samesite = "Strict"}}})
  eq(ids["cookie-no-httponly"], nil)
  eq(ids["cookie-flags-nonsession"], nil)
end)
test("Non-session cookies are INFO with the reason", function()
  local ids, r = judge(HARDENED, {cookies = {{name = "theme", value = "dark"}}})
  eq(ids["cookie-flags-nonsession"], "INFO")
  ok(r.findings[1].detail:find("theme %(no Secure, HttpOnly%)"))
end)
test("SameSite=None without Secure", function()
  eq(judge(HARDENED, {cookies = {{name = "t", value = "1", samesite = "None", httponly = ""}}})
    ["cookie-samesite-none-insecure"], "LOW")
end)
test("A fully flagged session cookie passes", function()
  local _, r = judge(HARDENED, {cookies = {{name = "sid", value = "x", secure = "", httponly = "", samesite = "Lax"}}})
  eq(#r.findings, 0)
end)

-- ---- directory listing, probes (audit bugs #5 and #7) ------------------------

test("is_directory_listing", function()
  ok(E.is_directory_listing("<html><head><title>Index of /files</title>"))
  ok(E.is_directory_listing("<title>Directory listing for /</title>"))
  ok(not E.is_directory_listing("<h1>Welcome</h1>"))
  ok(not E.is_directory_listing(nil))
end)
local catalog = {}
for _, e in ipairs(E.EXPOSURE) do catalog[e.path] = e end
test("judge_probe: soft-404 is not exposed", function()
  eq(E.judge_probe("/admin", 200, "<h1>Not found</h1>", nil, false), "absent (soft-404)")
  eq(select(2, E.judge_probe("/admin", 200, "<h1>Admin</h1>", nil, true)), "path-exposed")
end)
test("judge_probe: signatures decide for catalog paths", function()
  eq(select(2, E.judge_probe("/.git/HEAD", 200, "ref: refs/heads/main\n", catalog["/.git/HEAD"])), "exposed-git")
  eq(E.judge_probe("/.git/HEAD", 200, "<html>app shell</html>", catalog["/.git/HEAD"], true),
    "absent (content not recognised)")
  eq(select(2, E.judge_probe("/.git/HEAD", 200, string.rep("a", 40), catalog["/.git/HEAD"])), "exposed-git")
  eq(select(2, E.judge_probe("/.env", 200, "# cfg\nDB_PASSWORD=x\n", catalog["/.env"])), "exposed-env")
  eq(select(2, E.judge_probe("/.env", 200, "<html>A=1</html>", catalog["/.env"])), nil)
  eq(select(2, E.judge_probe("/.DS_Store", 200, "\0\0\0\1Bud1\0", catalog["/.DS_Store"])), "exposed-ds-store")
  eq(select(2, E.judge_probe("/backup.zip", 200, "PK\3\4....", catalog["/backup.zip"])), "exposed-backup-archive")
  eq(select(2, E.judge_probe("/actuator/env", 200, '{"activeProfiles":[]}', catalog["/actuator/env"])),
    "exposed-actuator-env")
end)
test("judge_probe: status codes", function()
  eq(E.judge_probe("/a", 401), "protected")
  eq(E.judge_probe("/a", 403), "protected")
  eq(E.judge_probe("/a", 404), "absent")
  eq(E.judge_probe("/a", 410), "absent")
  eq(E.judge_probe("/a", 301), "redirect")
  eq(E.judge_probe("/a", 500), "status 500")
  eq(E.judge_probe("/a", 429), "status 429")
  eq(E.judge_probe("/a", nil), "no response")
  eq(select(2, E.judge_probe("/a", 204, "", nil, true)), "path-exposed")
end)
test("judge_probe: directory listing on a probed path", function()
  eq(select(2, E.judge_probe("/files/", 200, "<title>Index of /files</title>", nil, true)), "directory-listing")
end)
test("Directory listing on the main page", function()
  eq(judge(HARDENED, {body = "<title>Index of /</title>"})["directory-listing"], "MEDIUM")
end)

-- ---- policy ------------------------------------------------------------------

test("apply_policy: empty document gives the defaults, named custom", function()
  local p = E.apply_policy({})
  local d = E.default_policy()
  d.name = "custom"
  eq(p, d)
end)
test("apply_policy: rejects malformed documents", function()
  local bad = {
    {"not an object", {"a", "b"}},
    {"unknown key", {fail_on = "high", unknown = 1}},
    {"bad severity", {fail_on = "urgent"}},
    {"unknown check", {checks = {["nope"] = {severity = "high"}}}},
    {"bad check key", {checks = {["csp-missing"] = {level = "high"}}}},
    {"bad enabled type", {checks = {["csp-missing"] = {enabled = "yes"}}}},
    {"bad hsts type", {hsts = {min_max_age = "1y"}}},
    {"negative number", {hsts = {min_max_age = -1}}},
    {"fractional number", {exposure = {max_paths = 2.5}}},
    {"paths not array", {exposure = {paths = {a = "/x"}}}},
    {"paths entries", {exposure = {paths = {1, 2}}}},
    {"unknown skip id", {skip = {"nope"}}},
    {"empty name", {name = ""}},
    {"hsts not object", {hsts = true}},
    {"checks entry not object", {checks = {["csp-missing"] = "off"}}},
  }
  for _, case in ipairs(bad) do
    local p, err = E.apply_policy(case[2])
    ok(p == nil and type(err) == "string", "accepted: " .. case[1])
  end
end)
test("apply_policy: severities are case-insensitive", function()
  local p = E.apply_policy({fail_on = "High", checks = {["csp-missing"] = {severity = "LOW"}}})
  eq(p.fail_on, "HIGH")
  eq(E.effective(p, "csp-missing"), "LOW")
end)
test("effective: skip and enabled=false disable a check", function()
  local p = E.apply_policy({skip = {"xcto-missing"}, checks = {["csp-missing"] = {enabled = false}}})
  eq(E.effective(p, "xcto-missing"), nil)
  eq(E.effective(p, "csp-missing"), nil)
  eq(E.effective(p, "hsts-missing"), "MEDIUM")
end)
test("effective: an explicit disable beats a policy requirement", function()
  local p = E.apply_policy({hsts = {require_preload = true}, checks = {["hsts-no-preload"] = {enabled = false}}})
  eq(E.effective(p, "hsts-no-preload", true), nil)
end)

local function load_json(path) return json.decode(H.read(root .. path)) end

test("policies/baseline.json is identical to the built-in defaults", function()
  local doc = load_json("policies/baseline.json")
  local p = assert(E.apply_policy(doc))
  eq(p, E.default_policy())
end)
for _, name in ipairs({"baseline", "strict", "owasp-asvs-l1"}) do
  test("policies/" .. name .. ".json is valid", function()
    local p, err = E.apply_policy(load_json("policies/" .. name .. ".json"))
    ok(p, err)
    eq(p.name, name)
  end)
end
test("policy.schema.json lists exactly the script's check IDs", function()
  local schema = load_json("policies/policy.schema.json")
  local listed = {}
  for _, id in ipairs(schema["$defs"].check_id.enum) do listed[id] = true end
  local actual = {}
  for id in pairs(E.CHECKS) do actual[id] = true end
  eq(listed, actual)
end)
test("strict policy changes results", function()
  local strict = E.apply_policy(load_json("policies/strict.json"))
  local h = with(HARDENED, {["strict-transport-security"] = "max-age=15768000; includeSubDomains"})
  eq(judge(h)["hsts-short-max-age"], nil)
  eq(judge(h, {policy = strict})["hsts-short-max-age"], "LOW")
  eq(judge(h, {policy = strict})["hsts-no-preload"], "INFO")
end)

-- ---- catalog -----------------------------------------------------------------

test("every check has a title, a valid severity and a recommendation", function()
  for id, c in pairs(E.CHECKS) do
    ok(E.RANK[c.severity], id .. " severity")
    ok(type(c.title) == "string" and #c.title > 0, id .. " title")
    ok(type(c.recommendation) == "string" and #c.recommendation > 0, id .. " recommendation")
    if c.cwe then ok(c.cwe:match("^CWE%-%d+$"), id .. " cwe format") end
    if c.owasp then ok(c.owasp:match("^A%d%d:2021$"), id .. " owasp format") end
  end
end)
test("docs/checks.md documents exactly the script's checks", function()
  local doc = H.read(root .. "docs/checks.md")
  local listed = {}
  for id in doc:gmatch('<a id="([%w%-]+)"></a>') do listed[id] = true end
  local actual = {}
  for id in pairs(E.CHECKS) do actual[id] = true end
  eq(listed, actual)
end)
test("every exposure entry maps to a known check", function()
  for _, e in ipairs(E.EXPOSURE) do ok(E.CHECKS[e.id], e.path) end
end)
test("hardened headers produce no findings", function()
  local _, r = judge(HARDENED)
  eq(#r.findings, 0, H.show(r.findings))
  eq(r.passed, {"hsts", "csp", "framing", "x-content-type-options", "referrer-policy", "permissions-policy"})
end)

-- ---- scoring and summary -------------------------------------------------------

local function F(...)
  local out = {}
  for _, s in ipairs({...}) do out[#out + 1] = {id = "x", severity = s, detail = ""} end
  return out
end
test("score: no findings is 100/A", function() eq({E.score({})}, {100, "A"}) end)
test("score: INFO never lowers the score", function() eq({E.score(F("INFO", "INFO", "INFO", "INFO"))}, {100, "A"}) end)
test("score: one MEDIUM costs one grade", function() eq({E.score(F("MEDIUM"))}, {90, "A"}) end)
test("score: weights", function()
  eq({E.score(F("MEDIUM", "MEDIUM"))}, {80, "B"})
  eq({E.score(F("LOW", "LOW", "LOW"))}, {91, "A"})
  eq({E.score(F("MEDIUM", "MEDIUM", "MEDIUM", "LOW"))}, {67, "D"})
end)
test("score: HIGH caps the grade at C", function()
  eq({E.score(F("HIGH"))}, {75, "C"})
end)
test("score: CRITICAL is always F", function()
  eq({E.score(F("CRITICAL"))}, {60, "F"})
end)
test("score: floor at 0", function()
  eq({E.score(F("HIGH", "HIGH", "HIGH", "HIGH", "HIGH"))}, {0, "F"})
end)
test("score: grade boundaries", function()
  local function low(n) local t = {} for i = 1, n do t[i] = "LOW" end return F(table.unpack(t)) end
  eq(select(2, E.score(low(3))), "A")   -- 91
  eq(select(2, E.score(low(4))), "B")   -- 88
  eq(select(2, E.score(low(6))), "B")   -- 82
  eq(select(2, E.score(low(7))), "C")   -- 79
  eq(select(2, E.score(low(10))), "C")  -- 70
  eq(select(2, E.score(low(11))), "D")  -- 67
  eq(select(2, E.score(low(14))), "F")  -- 58
end)
test("summarise: order, counts, threshold", function()
  local findings = {
    {id = "b", severity = "LOW", detail = ""}, {id = "a", severity = "HIGH", detail = ""},
    {id = "c", severity = "INFO", detail = ""},
  }
  local result, counts, summary = E.summarise(findings, "HIGH")
  eq(result, "FAIL")
  eq(findings[1].id, "a")
  eq(counts.LOW, 1)
  eq(summary, "critical=0 high=1 medium=0 low=1 info=1")
  eq((E.summarise({{id = "b", severity = "LOW", detail = ""}}, "MEDIUM")), "PASS")
  eq((E.summarise({}, "INFO")), "PASS")
end)

-- ---- error classification (no error strings inside findings) -------------------

test("classify_error", function()
  eq(E.classify_error("ERROR: TIMEOUT"), "timeout")
  eq(E.classify_error("Connection refused"), "connection-refused")
  eq(E.classify_error("Error in next_response function; Header field named \"x\" didn't end with CRLF"),
    "unsupported-response")
  eq(E.classify_error(nil), "no-response")
  eq(E.classify_error("Error creating socket."), "no-response")
  eq(E.classify_error([[Error in next_response function; Error parsing status-line "\0\1 junk".]]),
    "unsupported-response")
  eq(E.classify_error("something else"), "connection-error")
end)
test("printable strips control characters", function()
  eq(E.printable("a\r\nb\0c"), "a b c")
end)

os.exit(H.run() and 0 or 1)
