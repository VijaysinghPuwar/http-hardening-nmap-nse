local http      = require "http"
local shortport = require "shortport"
local stdnse    = require "stdnse"
local string    = require "string"
local table     = require "table"
local url       = require "url"

description = [[
Audits the HTTP response hardening of a web service and reports each weakness
with a severity, so results can be triaged or used to gate a CI pipeline.

Unlike http-security-headers, which lists the headers it finds, this script
checks their values. A header that is present but does nothing is reported
the same as one that is missing.

Checks performed against one page (default "/"), using GET:

* Transport: plaintext HTTP that does not redirect to HTTPS.
* HSTS: missing, max-age=0, max-age below a threshold, missing includeSubDomains.
  HSTS sent over plain HTTP is ignored by browsers (RFC 6797 8.1) and noted.
* Content-Security-Policy: missing, report-only, no script restriction,
  'unsafe-inline' without a nonce or hash, 'unsafe-eval', wildcard script sources.
* Clickjacking: X-Frame-Options or CSP frame-ancestors. frame-ancestors alone
  passes; ALLOW-FROM is ignored by current browsers and fails.
* X-Content-Type-Options: nosniff. Referrer-Policy: leaky values.
* Cookies: missing Secure over HTTPS, missing HttpOnly, SameSite=None without Secure.
* CORS: the request carries a fake Origin; reflecting it is reported, and
  reflecting it with Access-Control-Allow-Credentials: true is HIGH.
* Version disclosure in Server, X-Powered-By, X-AspNet-Version.
* Optional exposure probe of a list of paths (e.g. /admin, /.git/HEAD), with
  soft-404 detection so "200 for everything" servers are not reported as exposed.

The script sends 1 request per page plus 1 per probed path, and a few more for
soft-404 calibration when paths are given. It does not send payloads.
]]

---
-- @usage
-- nmap -sV -p80,443 --script ./http-hardening-check.nse <target>
--
-- nmap -sV -p443 --script ./http-hardening-check.nse \
--   --script-args 'http-hardening-check.vhost=app.example.com,http-hardening-check.paths={/admin,/.git/HEAD,/server-status}' \
--   -oX scan.xml <target>
--
-- @args http-hardening-check.path      Page to evaluate. Default: "/".
-- @args http-hardening-check.vhost     Hostname for the Host header and TLS SNI.
--                                      Default: the name given on the command line.
-- @args http-hardening-check.paths     Paths to probe for exposure, as an Nmap list:
--                                      {/admin,/.env}. Default: none.
-- @args http-hardening-check.skip      Finding IDs to suppress (accepted risk), as a list.
-- @args http-hardening-check.fail-on   Lowest severity that makes the result FAIL:
--                                      high, medium, low or info. Default: medium.
-- @args http-hardening-check.hsts-min  Minimum acceptable HSTS max-age in seconds.
--                                      Default: 15768000 (182.5 days).
-- @args http-hardening-check.timeout   Per-request timeout in ms. Default: 8000.
--
-- @output
-- 8443/tcp open  ssl/http nginx 1.18.0
-- | http-hardening-check:
-- |   url: https://localhost:8443/ (200)
-- |   result: FAIL (high=1 medium=6 low=6 info=1, fail-on=medium)
-- |   HIGH    cors-reflected-credentials     Origin reflected in Access-Control-Allow-Origin with credentials allowed
-- |   MEDIUM  cookie-no-secure               Cookie sent without Secure over HTTPS: session, tracker
-- |   MEDIUM  cookie-samesite-none-insecure  SameSite=None without Secure (rejected by browsers): tracker
-- |   MEDIUM  csp-broad-script-source        script-src allows any script from https:
-- |   MEDIUM  csp-unsafe-inline              script-src allows 'unsafe-inline' without a nonce or hash
-- |   MEDIUM  framing-allowed                X-Frame-Options ALLOW-FROM is ignored by current browsers; use CSP frame-ancestors
-- |   MEDIUM  hsts-disabled                  Strict-Transport-Security max-age=0 turns HSTS off
-- |   LOW     cookie-no-httponly             Cookie readable by JavaScript: session, tracker
-- |   LOW     csp-unsafe-eval                script-src allows 'unsafe-eval'
-- |   LOW     info-disclosure                Server: nginx/1.18.0
-- |   LOW     info-disclosure                X-Powered-By: PHP/8.1.2
-- |   LOW     referrer-policy-leaky          Referrer-Policy unsafe-url sends full URLs cross-origin
-- |   LOW     xcto-missing                   X-Content-Type-Options is not nosniff
-- |   INFO    xxp-enabled                    X-XSS-Protection enables the removed XSS auditor; set 0 or drop it
-- |   paths:
-- |     /admin      403  protected
-- |_    /.git/HEAD  200  absent (soft-404)
--
-- @xmloutput
-- <elem key="url">https://localhost:8443/</elem>
-- <elem key="status">200</elem>
-- <elem key="result">FAIL</elem>
-- <elem key="summary">high=1 medium=6 low=6 info=1</elem>
-- <elem key="fail_on">medium</elem>
-- <table key="findings">
--   <table>
--     <elem key="severity">HIGH</elem>
--     <elem key="id">cors-reflected-credentials</elem>
--     <elem key="detail">Origin reflected in Access-Control-Allow-Origin with credentials allowed</elem>
--   </table>
-- </table>
-- <table key="passed"></table>
-- <table key="paths">
--   <table>
--     <elem key="path">/admin</elem>
--     <elem key="status">403</elem>
--     <elem key="verdict">protected</elem>
--   </table>
-- </table>

author = "Vijaysingh Puwar"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

-- An origin no real site uses. If a server echoes it back, it echoes anything.
local PROBE_ORIGIN = "https://hardening-check.invalid"

local SEVERITIES = {"HIGH", "MEDIUM", "LOW", "INFO"}
local RANK = {HIGH = 1, MEDIUM = 2, LOW = 3, INFO = 4}

local function arg(name, default)
  local v = stdnse.get_script_args(SCRIPT_NAME .. "." .. name)
  if v == nil then return default end
  return v
end

-- Accepts the Nmap list form {a,b} (a table) or a quoted "a,b" string.
local function arg_list(name)
  local v = arg(name)
  if type(v) == "table" then return v end
  local out = {}
  for item in tostring(v or ""):gmatch("[^,%s]+") do out[#out + 1] = item end
  return out
end

local function set_of(list)
  local s = {}
  for _, v in ipairs(list) do s[v:lower()] = true end
  return s
end

-- Parses an enforced CSP into directive -> list of lowercased source tokens.
-- Several CSP headers arrive joined by ", "; each policy is enforced, so the
-- first occurrence of a directive is used.
local function parse_csp(value)
  local d = {}
  for part in value:gmatch("[^;,]+") do
    local name, rest = part:match("^%s*([%w%-]+)%s*(.-)%s*$")
    if name then
      name = name:lower()
      if not d[name] then
        local tokens = {}
        for tok in rest:gmatch("%S+") do tokens[#tokens + 1] = tok:lower() end
        d[name] = tokens
      end
    end
  end
  return d
end

local function has_token(tokens, wanted)
  for _, t in ipairs(tokens or {}) do
    if t == wanted then return true end
  end
  return false
end

local function has_nonce_or_hash(tokens)
  for _, t in ipairs(tokens or {}) do
    if t:match("^'nonce%-") or t:match("^'sha%d+%-") then return true end
  end
  return false
end

-- Follows same-origin redirects so a "/" -> "/login" hop evaluates the real
-- page. Stops at a redirect to HTTPS (a pass for plaintext ports) or off-site.
local function fetch_page(target, port, path, opts)
  local hostname = stdnse.get_hostname(target)
  local resp, upgrade, offsite
  for _ = 1, 4 do
    resp = http.get(target, port, path, opts)
    if not (resp and resp.status) then return nil end
    local loc = resp.status >= 300 and resp.status < 400 and resp.header.location
    if not loc then break end

    local scheme = resp.ssl and "https" or "http"
    local u = url.parse(url.absolute(("%s://%s:%d%s"):format(scheme, hostname, port.number, path), loc))
    if u.scheme == "https" and not resp.ssl then
      upgrade = loc
      break
    end
    local same_host = (u.host or ""):lower() == hostname:lower()
    local same_port = tonumber(u.port or (u.scheme == "https" and 443 or 80)) == port.number
    if not (same_host and same_port) or not u.path then
      offsite = loc
      break
    end
    path = u.path .. (u.query and ("?" .. u.query) or "")
  end
  return resp, path, upgrade, offsite
end

local function check_headers(resp, tls, add, pass, hsts_min)
  local h = resp.header or {}

  -- Transport-level: HSTS only means something over TLS.
  local hsts = h["strict-transport-security"]
  if not tls then
    add("MEDIUM", "no-https-redirect", "Serves content over plain HTTP without redirecting to HTTPS")
    if hsts then
      add("INFO", "hsts-over-http", "Strict-Transport-Security sent over plain HTTP is ignored by browsers")
    end
  elseif not hsts then
    add("MEDIUM", "hsts-missing", "No Strict-Transport-Security header")
  else
    local age = tonumber(hsts:lower():match("max%-age%s*=%s*\"?(%d+)"))
    if not age then
      add("MEDIUM", "hsts-invalid", ("Strict-Transport-Security has no valid max-age: %s"):format(hsts))
    elseif age == 0 then
      add("MEDIUM", "hsts-disabled", "Strict-Transport-Security max-age=0 turns HSTS off")
    elseif age < hsts_min then
      add("LOW", "hsts-short-max-age", ("max-age=%d is below %d"):format(age, hsts_min))
    else
      pass("hsts")
    end
    if age and age > 0 and not hsts:lower():find("includesubdomains", 1, true) then
      add("INFO", "hsts-no-subdomains", "HSTS does not set includeSubDomains")
    end
  end

  -- Content-Security-Policy: judge what it allows for scripts, not that it exists.
  local csp_raw = h["content-security-policy"]
  local csp = csp_raw and parse_csp(csp_raw) or {}
  if not csp_raw then
    if h["content-security-policy-report-only"] then
      add("LOW", "csp-report-only", "CSP is Report-Only, so it is not enforced")
    else
      add("MEDIUM", "csp-missing", "No Content-Security-Policy header")
    end
  else
    local script = csp["script-src"] or csp["default-src"]
    local which = csp["script-src"] and "script-src" or "default-src"
    if not script then
      add("MEDIUM", "csp-no-script-restriction", "CSP has neither script-src nor default-src")
    else
      local strict_dynamic = has_token(script, "'strict-dynamic'")
      local csp_ok = true
      if has_token(script, "'unsafe-inline'") and not has_nonce_or_hash(script) then
        add("MEDIUM", "csp-unsafe-inline", ("%s allows 'unsafe-inline' without a nonce or hash"):format(which))
        csp_ok = false
      end
      if has_token(script, "'unsafe-eval'") then
        add("LOW", "csp-unsafe-eval", ("%s allows 'unsafe-eval'"):format(which))
        csp_ok = false
      end
      if not strict_dynamic then
        for _, broad in ipairs({"*", "http:", "https:", "data:"}) do
          if has_token(script, broad) then
            add("MEDIUM", "csp-broad-script-source", ("%s allows any script from %s"):format(which, broad))
            csp_ok = false
          end
        end
      end
      if csp_ok then pass("csp") end
    end
  end

  -- Clickjacking: CSP frame-ancestors supersedes X-Frame-Options.
  local xfo = (h["x-frame-options"] or ""):lower():match("^%s*(.-)%s*$")
  local fa = csp["frame-ancestors"]
  if fa then
    if has_token(fa, "*") then
      add("MEDIUM", "framing-allowed", "CSP frame-ancestors * lets any site frame the page")
    else
      pass("framing")
    end
  elseif xfo == "deny" or xfo == "sameorigin" then
    pass("framing")
  elseif xfo:find("^allow%-from") then
    add("MEDIUM", "framing-allowed", "X-Frame-Options ALLOW-FROM is ignored by current browsers; use CSP frame-ancestors")
  elseif xfo ~= "" then
    add("MEDIUM", "framing-allowed", ("Invalid X-Frame-Options value: %s"):format(xfo))
  else
    add("MEDIUM", "framing-missing", "No X-Frame-Options or CSP frame-ancestors (clickjacking)")
  end

  if (h["x-content-type-options"] or ""):lower():match("^%s*nosniff%s*$") then
    pass("x-content-type-options")
  else
    add("LOW", "xcto-missing", "X-Content-Type-Options is not nosniff")
  end

  -- Referrer-Policy: the last recognised token wins, so check the last one.
  local rp = h["referrer-policy"]
  if not rp then
    add("INFO", "referrer-policy-missing", "No Referrer-Policy; browser default applies")
  else
    local last
    for tok in rp:lower():gmatch("[%w%-]+") do last = tok end
    if last == "unsafe-url" or last == "no-referrer-when-downgrade" then
      add("LOW", "referrer-policy-leaky", ("Referrer-Policy %s sends full URLs cross-origin"):format(last))
    else
      pass("referrer-policy")
    end
  end

  local xxp = h["x-xss-protection"]
  if xxp and xxp:match("^%s*1") then
    add("INFO", "xxp-enabled", "X-XSS-Protection enables the removed XSS auditor; set 0 or drop it")
  end

  -- CORS: the request sent PROBE_ORIGIN, so seeing it back means reflection.
  local acao = h["access-control-allow-origin"]
  if acao and acao:lower() == PROBE_ORIGIN then
    if (h["access-control-allow-credentials"] or ""):lower():match("true") then
      add("HIGH", "cors-reflected-credentials",
        "Origin reflected in Access-Control-Allow-Origin with credentials allowed")
    else
      add("LOW", "cors-reflected-origin", "Arbitrary Origin reflected in Access-Control-Allow-Origin")
    end
  end

  -- Version strings make exploit matching trivial for an attacker.
  local server = h["server"]
  if server and server:match("%d+%.%d+") then
    add("LOW", "info-disclosure", ("Server: %s"):format(server))
  end
  for _, name in ipairs({"x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"}) do
    if h[name] then
      local pretty = name:gsub("^%l", string.upper):gsub("%-(%l)", function(c) return "-" .. c:upper() end)
      add("LOW", "info-disclosure", ("%s: %s"):format(pretty, h[name]))
    end
  end

  -- Cookies, grouped by problem so a site with 20 cookies stays readable.
  local no_secure, no_httponly, bad_samesite = {}, {}, {}
  for _, c in ipairs(resp.cookies or {}) do
    if tls and c.secure == nil then no_secure[#no_secure + 1] = c.name end
    if c.httponly == nil then no_httponly[#no_httponly + 1] = c.name end
    if (c.samesite or ""):lower() == "none" and c.secure == nil then
      bad_samesite[#bad_samesite + 1] = c.name
    end
  end
  if #no_secure > 0 then
    add("MEDIUM", "cookie-no-secure", "Cookie sent without Secure over HTTPS: " .. table.concat(no_secure, ", "))
  end
  if #bad_samesite > 0 then
    add("MEDIUM", "cookie-samesite-none-insecure",
      "SameSite=None without Secure (rejected by browsers): " .. table.concat(bad_samesite, ", "))
  end
  if #no_httponly > 0 then
    add("LOW", "cookie-no-httponly", "Cookie readable by JavaScript: " .. table.concat(no_httponly, ", "))
  end
  if #(resp.cookies or {}) > 0 and #no_secure + #no_httponly + #bad_samesite == 0 then
    pass("cookies")
  end
end

local function probe_paths(target, port, paths, opts, add)
  local results = {}
  local ok404, result_404, known_404 = http.identify_404(target, port)
  if not ok404 then
    stdnse.debug1("soft-404 calibration failed: %s", tostring(result_404))
  end

  for _, p in ipairs(paths) do
    if not p:match("^/") then p = "/" .. p end
    local r = http.get(target, port, p, opts)
    local status, verdict = "-", "no response"
    if r and r.status then
      status = r.status
      if status >= 200 and status < 300 then
        if ok404 and not http.page_exists(r, result_404, known_404, p, false) then
          verdict = "absent (soft-404)"
        else
          verdict = "exposed"
          add("MEDIUM", "path-exposed", ("%s returned %d"):format(p, status))
        end
      elseif status == 401 or status == 403 then
        verdict = "protected"
      elseif status == 404 or status == 410 then
        verdict = "absent"
      elseif status >= 300 and status < 400 then
        verdict = "redirect -> " .. (r.header.location or "?")
      else
        verdict = "status " .. status
      end
    end
    results[#results + 1] = {path = p, status = status, verdict = verdict}
  end
  return results
end

local function render(out, findings, passed, paths)
  local lines = {}
  lines[#lines + 1] = ("url: %s (%s)"):format(out.url, out.status)
  if out.note then lines[#lines + 1] = out.note end
  lines[#lines + 1] = ("result: %s (%s, fail-on=%s)"):format(out.result, out.summary, out.fail_on)

  local idw = 0
  for _, f in ipairs(findings) do idw = math.max(idw, #f.id) end
  for _, f in ipairs(findings) do
    lines[#lines + 1] = ("%-7s %-" .. idw .. "s  %s"):format(f.severity, f.id, f.detail)
  end
  if #passed > 0 then
    lines[#lines + 1] = "passed: " .. table.concat(passed, ", ")
  end

  if paths and #paths > 0 then
    local pw = 0
    for _, r in ipairs(paths) do pw = math.max(pw, #r.path) end
    local sub = {name = "paths:"}
    for _, r in ipairs(paths) do
      sub[#sub + 1] = ("%-" .. pw .. "s  %-3s  %s"):format(r.path, tostring(r.status), r.verdict)
    end
    lines[#lines + 1] = sub
  end
  return stdnse.format_output(true, lines)
end

action = function(host, port)
  local timeout   = tonumber(arg("timeout", 8000)) or 8000
  local hsts_min  = tonumber(arg("hsts-min", 15768000)) or 15768000
  local fail_on   = tostring(arg("fail-on", "medium")):upper()
  local skip      = set_of(arg_list("skip"))
  local vhost     = arg("vhost")
  if not RANK[fail_on] then fail_on = "MEDIUM" end

  -- nsock takes the TLS server name from host.targetname and the http library
  -- takes the Host header from it too, so a vhost needs a modified host table.
  local target = host
  if vhost then
    target = {}
    for k, v in pairs(host) do target[k] = v end
    target.targetname = vhost
    target.name = vhost
  end

  local opts = {
    timeout = timeout,
    redirect_ok = false,
    no_cache = true,
    header = {Origin = PROBE_ORIGIN},
  }

  local resp, path, upgrade, offsite = fetch_page(target, port, arg("path", "/"), opts)
  if not resp then
    return nil
  end

  local tls = resp.ssl and true or false
  local findings, passed = {}, {}
  local function add(severity, id, detail)
    if not skip[id] then
      findings[#findings + 1] = {severity = severity, id = id, detail = detail}
    end
  end
  local function pass(name) passed[#passed + 1] = name end

  local out = stdnse.output_table()
  out.url = ("%s://%s:%d%s"):format(tls and "https" or "http", stdnse.get_hostname(target), port.number, path)
  out.status = resp.status

  if upgrade then
    pass("https-redirect")
    out.note = "redirects to " .. upgrade .. "; headers are judged on the HTTPS port"
  else
    if offsite then
      out.note = "redirects off-site to " .. offsite .. "; judging the redirect response"
    end
    check_headers(resp, tls, add, pass, hsts_min)
  end

  local path_results
  local paths = arg_list("paths")
  if #paths > 0 then
    path_results = probe_paths(target, port, paths, opts, add)
  end

  table.sort(findings, function(a, b)
    if RANK[a.severity] ~= RANK[b.severity] then return RANK[a.severity] < RANK[b.severity] end
    return a.id < b.id
  end)

  local counts, failing = {}, false
  for _, s in ipairs(SEVERITIES) do counts[s] = 0 end
  for _, f in ipairs(findings) do
    counts[f.severity] = counts[f.severity] + 1
    if RANK[f.severity] <= RANK[fail_on] then failing = true end
  end
  local summary = {}
  for _, s in ipairs(SEVERITIES) do summary[#summary + 1] = ("%s=%d"):format(s:lower(), counts[s]) end

  out.result = failing and "FAIL" or "PASS"
  out.summary = table.concat(summary, " ")
  out.fail_on = fail_on:lower()
  out.findings = findings
  out.passed = passed
  out.paths = path_results

  return out, render(out, findings, passed, path_results)
end
