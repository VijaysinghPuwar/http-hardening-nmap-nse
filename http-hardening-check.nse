local http      = require "http"
local json      = require "json"
local shortport = require "shortport"
local stdnse    = require "stdnse"
local table     = require "table"
local url       = require "url"

description = [[
Evaluates the HTTP hardening of a web service against a policy and reports
each weakness as a finding with a severity, a 0-100 score and a letter grade.

Nmap's http-security-headers lists the security headers it finds. This script
judges their values: a header that is present but ineffective (for example
HSTS max-age=0, or a CSP that allows 'unsafe-inline' scripts) is a finding.

Checks against one page (default "/"), using a single GET:

* Transport: plain HTTP that does not redirect to HTTPS. HSTS is only required
  over TLS, because browsers ignore it on plain HTTP (RFC 6797 section 8.1).
* HSTS: missing, invalid, max-age=0, max-age below the policy minimum,
  includeSubDomains and preload when the policy requires them.
* Content-Security-Policy (header or meta tag): missing, Report-Only,
  'unsafe-inline' without a nonce or hash, 'unsafe-eval', scheme or wildcard
  script sources, object-src and base-uri. Several policies are combined the
  way browsers combine them: a weakness counts only if every policy has it.
* Framing: CSP frame-ancestors, or X-Frame-Options when frame-ancestors is absent.
* X-Content-Type-Options, Referrer-Policy, Permissions-Policy and (optionally)
  Cross-Origin-Opener/Embedder/Resource-Policy.
* Cookies: Secure, HttpOnly and SameSite, with session cookies judged more
  strictly than cookies that scripts may legitimately read.
* CORS: the request carries an Origin no real site uses. Reflecting it with
  credentials allowed is HIGH.
* Version disclosure in Server, X-Powered-By and X-AspNet-Version.
* Deprecated headers: X-XSS-Protection, Public-Key-Pins, Expect-CT.
* Directory listings in any response the script fetched.

Optional and off by default (exposure=true): a soft-404-aware probe of a short
list of sensitive paths with content signatures (/.git/HEAD, /.env, ...), and
one TRACE request. Custom paths can be probed with the paths argument.

Request budget: 1 GET per port (plus up to 3 same-site redirects). Exposure
probing adds 1 GET per path, Nmap's soft-404 calibration requests, and one
TRACE. No payloads, credentials or state-changing methods are sent.
]]

---
-- @usage
-- nmap -sV -p80,443 --script ./http-hardening-check.nse <target>
--
-- nmap -sV -p443 --script ./http-hardening-check.nse \
--   --script-args 'http-hardening-check.policy=policies/strict.json,http-hardening-check.vhost=app.example.com' \
--   -oX scan.xml <target>
--
-- nmap -sV -p443 --script ./http-hardening-check.nse \
--   --script-args 'http-hardening-check.exposure=true,http-hardening-check.paths={/internal,/debug}' <target>
--
-- @args http-hardening-check.policy    Policy file (JSON). Default: built-in baseline,
--                                      identical to policies/baseline.json.
-- @args http-hardening-check.path      Page to evaluate. Default: "/".
-- @args http-hardening-check.vhost     Hostname for the Host header and TLS SNI.
--                                      Default: the name given on the command line.
-- @args http-hardening-check.exposure  true to probe the built-in sensitive paths and TRACE.
--                                      Default: false (or the policy's exposure.enabled).
-- @args http-hardening-check.paths     Extra paths to probe, as a list: {/admin,/debug}
--                                      or "/admin,/debug". Probed even without exposure=true.
-- @args http-hardening-check.max-paths Upper bound on probed paths. Default: 25.
-- @args http-hardening-check.skip      Finding IDs to suppress (accepted risk), as a list.
-- @args http-hardening-check.fail-on   Lowest severity that makes the result FAIL:
--                                      critical, high, medium, low or info. Default: medium.
-- @args http-hardening-check.hsts-min  Minimum acceptable HSTS max-age in seconds.
--                                      Default: 15768000 (182.5 days).
-- @args http-hardening-check.timeout   Per-request timeout in ms. Default: 8000.
--
-- @output
-- 8443/tcp open  ssl/http
-- | http-hardening-check:
-- |   url: https://localhost:8443/ (200)
-- |   result: FAIL  score: 0/100  grade: F  policy: baseline
-- |   summary: critical=0 high=1 medium=4 low=8 info=4 (fail-on=medium)
-- |   HIGH    cors-reflected-credentials     Origin reflected in Access-Control-Allow-Origin with credentials allowed
-- |   MEDIUM  cookie-no-secure               Session cookie sent without Secure over HTTPS: session
-- |   ...
-- |   passed: https-redirect
-- |   paths:
-- |     /admin      403  protected
-- |_    /.git/HEAD  200  absent (soft-404)
--
-- @xmloutput
-- <elem key="url">https://localhost:8443/</elem>
-- <elem key="status">200</elem>
-- <elem key="result">FAIL</elem>
-- <elem key="score">0</elem>
-- <elem key="grade">F</elem>
-- <elem key="policy">baseline</elem>
-- <elem key="fail_on">medium</elem>
-- <elem key="summary">critical=0 high=1 medium=4 low=8 info=4</elem>
-- <table key="counts">
--   <elem key="critical">0</elem>
--   <elem key="high">1</elem>
--   ...
-- </table>
-- <table key="findings">
--   <table>
--     <elem key="id">cors-reflected-credentials</elem>
--     <elem key="severity">HIGH</elem>
--     <elem key="title">CORS reflects arbitrary origins with credentials</elem>
--     <elem key="detail">Origin reflected in Access-Control-Allow-Origin with credentials allowed</elem>
--     <elem key="evidence">Access-Control-Allow-Origin: https://hardening-check.invalid</elem>
--     <elem key="path">/</elem>
--     <elem key="cwe">CWE-942</elem>
--     <elem key="owasp">A05:2021</elem>
--     <elem key="asvs">14.5.3</elem>
--     <elem key="recommendation">Match the Origin against an allowlist ...</elem>
--   </table>
-- </table>
-- <table key="passed"></table>
-- <table key="paths"></table>
-- <elem key="requests">1</elem>

author = "Vijaysingh Puwar"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

-- ---------------------------------------------------------------------------
-- Evaluation engine. Everything in Engine is pure (no network, no Nmap state)
-- so tests/unit can load this file with stub libraries and exercise it.
-- ---------------------------------------------------------------------------

local Engine = {}

-- An origin no real site uses. If a server echoes it back, it echoes anything.
local PROBE_ORIGIN = "https://hardening-check.invalid"
Engine.PROBE_ORIGIN = PROBE_ORIGIN

local SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
local RANK = {CRITICAL = 1, HIGH = 2, MEDIUM = 3, LOW = 4, INFO = 5}
Engine.SEVERITIES, Engine.RANK = SEVERITIES, RANK

-- Points deducted from 100 per finding. See docs/scoring.md for the rationale.
local WEIGHT = {CRITICAL = 40, HIGH = 25, MEDIUM = 10, LOW = 3, INFO = 0}
Engine.WEIGHT = WEIGHT

-- Every finding the script can emit. severity is the built-in default; a
-- policy can change it or disable the check. References are only given where
-- the mapping is direct (OWASP ASVS 4.0.3 requirement numbers).
local CHECKS = {
  ["no-https-redirect"] = {"MEDIUM", "Plain HTTP without redirect to HTTPS", "CWE-319", "A02:2021", "9.1.1",
    "Redirect all plain HTTP requests to HTTPS with 301 or 308."},
  ["hsts-missing"] = {"MEDIUM", "HSTS header missing", "CWE-319", "A05:2021", "14.4.5",
    "Send Strict-Transport-Security: max-age=31536000; includeSubDomains on HTTPS responses."},
  ["hsts-invalid"] = {"MEDIUM", "HSTS header is invalid and ignored", "CWE-319", "A05:2021", "14.4.5",
    "Send exactly one max-age directive with a numeric value."},
  ["hsts-disabled"] = {"MEDIUM", "HSTS disabled with max-age=0", "CWE-319", "A05:2021", "14.4.5",
    "Set max-age to at least one year once HTTPS works for the whole site."},
  ["hsts-short-max-age"] = {"LOW", "HSTS max-age below policy minimum", "CWE-319", "A05:2021", "14.4.5",
    "Raise max-age to the policy minimum (one year is common)."},
  ["hsts-no-subdomains"] = {"INFO", "HSTS does not cover subdomains", nil, nil, "14.4.5",
    "Add includeSubDomains once every subdomain serves HTTPS."},
  ["hsts-no-preload"] = {"INFO", "HSTS preload directive absent", nil, nil, nil,
    "Add preload and submit the domain at hstspreload.org if every subdomain is HTTPS-only."},
  ["hsts-over-http"] = {"INFO", "HSTS sent over plain HTTP is ignored", nil, nil, nil,
    "Send HSTS on HTTPS responses; redirect plain HTTP to HTTPS."},
  ["csp-missing"] = {"MEDIUM", "Content-Security-Policy missing", "CWE-693", "A05:2021", "14.4.3",
    "Deploy a CSP that restricts script-src, starting in Report-Only mode."},
  ["csp-report-only"] = {"LOW", "CSP is Report-Only and not enforced", "CWE-693", "A05:2021", "14.4.3",
    "Promote the policy to Content-Security-Policy once reports are clean."},
  ["csp-no-script-restriction"] = {"MEDIUM", "CSP does not restrict scripts", "CWE-693", "A05:2021", "14.4.3",
    "Add script-src or default-src to the policy."},
  ["csp-unsafe-inline"] = {"MEDIUM", "CSP allows inline scripts", "CWE-693", "A05:2021", "14.4.3",
    "Replace 'unsafe-inline' with nonces or hashes."},
  ["csp-unsafe-eval"] = {"LOW", "CSP allows eval()", "CWE-693", "A05:2021", "14.4.3",
    "Remove 'unsafe-eval'; refactor code that builds scripts from strings."},
  ["csp-broad-script-source"] = {"MEDIUM", "CSP allows scripts from any host or data: URLs", "CWE-693", "A05:2021",
    "14.4.3", "List specific script hosts, or use nonces with 'strict-dynamic'."},
  ["csp-no-object-src"] = {"LOW", "CSP does not restrict plugins (object-src)", "CWE-693", "A05:2021", "14.4.3",
    "Add object-src 'none'."},
  ["csp-no-base-uri"] = {"INFO", "CSP does not restrict base-uri", "CWE-693", nil, "14.4.3",
    "Add base-uri 'none' or 'self'; base-uri does not fall back to default-src."},
  ["framing-missing"] = {"MEDIUM", "No clickjacking protection", "CWE-1021", "A05:2021", "14.4.7",
    "Add CSP frame-ancestors 'none' (or 'self'); X-Frame-Options DENY for old browsers."},
  ["framing-allowed"] = {"MEDIUM", "Framing protection is ineffective", "CWE-1021", "A05:2021", "14.4.7",
    "Use CSP frame-ancestors with explicit origins instead of * or ALLOW-FROM."},
  ["xcto-missing"] = {"LOW", "X-Content-Type-Options is not nosniff", "CWE-693", "A05:2021", "14.4.4",
    "Send X-Content-Type-Options: nosniff on all responses."},
  ["referrer-policy-missing"] = {"INFO", "Referrer-Policy missing or unrecognised", nil, nil, "14.4.6",
    "Send Referrer-Policy: strict-origin-when-cross-origin (or stricter)."},
  ["referrer-policy-leaky"] = {"LOW", "Referrer-Policy leaks full URLs cross-origin", "CWE-200", "A05:2021", "14.4.6",
    "Use strict-origin-when-cross-origin, same-origin or no-referrer."},
  ["permissions-policy-missing"] = {"INFO", "Permissions-Policy missing", nil, nil, nil,
    "Disable browser features the site does not use, e.g. camera=(), microphone=(), geolocation=()."},
  ["permissions-policy-permissive"] = {"LOW", "Permissions-Policy grants powerful features to any origin", nil, nil,
    nil, "Restrict powerful features to self or named origins instead of *."},
  ["cross-origin-isolation-missing"] = {"INFO", "Cross-origin isolation headers missing", nil, nil, nil,
    "Consider Cross-Origin-Opener-Policy: same-origin and Cross-Origin-Resource-Policy where compatible."},
  ["cookie-no-secure"] = {"MEDIUM", "Session cookie without Secure over HTTPS", "CWE-614", "A05:2021", "3.4.1",
    "Add the Secure attribute to session cookies."},
  ["cookie-no-httponly"] = {"LOW", "Session cookie readable by JavaScript", "CWE-1004", "A05:2021", "3.4.2",
    "Add HttpOnly to session cookies that scripts do not need to read."},
  ["cookie-samesite-none-insecure"] = {"LOW", "SameSite=None cookie without Secure", "CWE-1275", "A05:2021", "3.4.3",
    "Browsers reject SameSite=None without Secure; add Secure or use Lax."},
  ["cookie-no-samesite"] = {"INFO", "Session cookie without SameSite", "CWE-1275", nil, "3.4.3",
    "Set SameSite=Lax (or Strict) explicitly; browser defaults differ."},
  ["cookie-flags-nonsession"] = {"INFO", "Non-session cookies without Secure or HttpOnly", nil, nil, nil,
    "Review whether these cookies need to be readable by scripts or sent over plain HTTP."},
  ["cors-reflected-credentials"] = {"HIGH", "CORS reflects arbitrary origins with credentials", "CWE-942", "A05:2021",
    "14.5.3", "Match the Origin against an allowlist before echoing it; never reflect it with credentials."},
  ["cors-reflected-origin"] = {"LOW", "CORS reflects arbitrary origins", "CWE-942", "A05:2021", "14.5.3",
    "Match the Origin against an allowlist, or use * deliberately for public resources."},
  ["cors-wildcard-credentials"] = {"LOW", "CORS wildcard combined with credentials", "CWE-942", "A05:2021", "14.5.3",
    "Browsers refuse this combination; decide whether credentials are needed and list origins explicitly."},
  ["info-disclosure"] = {"LOW", "Software version disclosed", "CWE-200", "A05:2021", "14.3.3",
    "Remove version numbers from Server and X-Powered-By style headers."},
  ["tech-disclosure"] = {"INFO", "Technology disclosed in headers", "CWE-200", nil, "14.3.3",
    "Drop X-Powered-By and similar headers; they help fingerprinting only."},
  ["xxp-enabled"] = {"INFO", "Legacy X-XSS-Protection filter enabled", nil, nil, nil,
    "Set X-XSS-Protection: 0 or drop it; rely on CSP."},
  ["hpkp-present"] = {"INFO", "Deprecated Public-Key-Pins header", nil, nil, nil,
    "Remove Public-Key-Pins; browsers removed HPKP support."},
  ["expect-ct-present"] = {"INFO", "Deprecated Expect-CT header", nil, nil, nil,
    "Remove Expect-CT; Certificate Transparency is enforced by browsers without it."},
  ["directory-listing"] = {"MEDIUM", "Directory listing enabled", "CWE-548", "A05:2021", "4.3.2",
    "Disable autoindex/directory browsing."},
  ["trace-enabled"] = {"LOW", "HTTP TRACE method enabled", nil, "A05:2021", "14.5.1",
    "Disable TRACE (TraceEnable Off, or deny the method at the proxy)."},
  ["path-exposed"] = {"MEDIUM", "Configured path is reachable", nil, "A05:2021", nil,
    "Restrict or remove the path if it should not be public."},
  ["admin-interface-reachable"] = {"LOW", "Administrative interface reachable", nil, "A05:2021", nil,
    "Restrict administrative paths by network or authentication."},
  ["exposed-git"] = {"HIGH", "Git repository metadata exposed", "CWE-538", "A05:2021", nil,
    "Block /.git/ at the web server and remove it from the document root."},
  ["exposed-env"] = {"HIGH", "Environment file exposed", "CWE-538", "A05:2021", nil,
    "Remove .env from the document root and rotate any secrets it contained."},
  ["exposed-actuator-env"] = {"HIGH", "Spring Boot actuator env endpoint exposed", "CWE-200", "A05:2021", "14.3.2",
    "Do not expose actuator endpoints publicly; require authentication."},
  ["exposed-backup-archive"] = {"HIGH", "Backup archive downloadable", "CWE-538", "A05:2021", nil,
    "Remove backup files from the document root."},
  ["exposed-server-status"] = {"MEDIUM", "Apache server-status exposed", "CWE-200", "A05:2021", "14.3.2",
    "Restrict mod_status to localhost or an admin network."},
  ["exposed-phpinfo"] = {"MEDIUM", "phpinfo() page exposed", "CWE-200", "A05:2021", "14.3.2",
    "Remove phpinfo pages from production."},
  ["exposed-ds-store"] = {"LOW", ".DS_Store file exposed", "CWE-538", "A05:2021", nil,
    "Remove .DS_Store files and block dotfiles at the web server."},
}

-- Checks a deployment may not want by default. Policies can enable them.
local DISABLED_BY_DEFAULT = {["hsts-no-preload"] = true, ["cross-origin-isolation-missing"] = true}

Engine.CHECKS = {}
for id, c in pairs(CHECKS) do
  Engine.CHECKS[id] = {
    id = id, severity = c[1], title = c[2], cwe = c[3], owasp = c[4], asvs = c[5],
    recommendation = c[6], enabled = not DISABLED_BY_DEFAULT[id],
  }
end

-- Exposure catalog. A signature proves the content is what the path suggests,
-- so a SPA that answers every path with index.html is not a finding.
local EXPOSURE = {
  {path = "/.git/HEAD", id = "exposed-git", evidence = "body is a git HEAD reference", sig = function(b)
    return b:match("^%s*ref:%s*refs/") or b:match("^%s*%x+%s*$") and #b:match("%x+") == 40
  end},
  {path = "/.env", id = "exposed-env", evidence = "body has KEY=value lines (content not recorded)", sig = function(b)
    return not b:lower():find("<html", 1, true) and (b:match("^%s*[A-Z][A-Z0-9_]*%s*=")
      or b:match("\n%s*[A-Z][A-Z0-9_]*%s*="))
  end},
  {path = "/server-status", id = "exposed-server-status", evidence = "body is an Apache status page",
    sig = function(b)
    return b:find("Apache Server Status", 1, true) or b:find("Server uptime", 1, true)
  end},
  {path = "/actuator/env", id = "exposed-actuator-env", evidence = "body is actuator env JSON (content not recorded)",
    sig = function(b)
    return b:find('"propertySources"', 1, true) or b:find('"activeProfiles"', 1, true)
  end},
  {path = "/phpinfo.php", id = "exposed-phpinfo", evidence = "body is phpinfo() output", sig = function(b)
    return b:find("phpinfo()", 1, true) or b:find("<title>PHP %d") or b:find("PHP Version", 1, true)
  end},
  {path = "/.DS_Store", id = "exposed-ds-store", evidence = "body has the .DS_Store magic bytes", sig = function(b)
    return b:sub(1, 8) == "\0\0\0\1Bud1"
  end},
  {path = "/backup.zip", id = "exposed-backup-archive", evidence = "body starts with the ZIP magic bytes",
    sig = function(b)
    return b:sub(1, 4) == "PK\3\4"
  end},
  {path = "/admin", id = "admin-interface-reachable"},
  {path = "/wp-admin/", id = "admin-interface-reachable"},
}
Engine.EXPOSURE = EXPOSURE

-- Built-in policy. policies/baseline.json must stay identical; a unit test
-- enforces it.
local function default_policy()
  return {
    name = "baseline",
    fail_on = "MEDIUM",
    hsts = {min_max_age = 15768000, require_include_subdomains = false, require_preload = false},
    exposure = {enabled = false, trace = true, paths = {}, max_paths = 25},
    skip = {},
    checks = {},
  }
end
Engine.default_policy = default_policy

-- ---- small helpers --------------------------------------------------------

local function trim(s) return (tostring(s):gsub("^%s+", ""):gsub("%s+$", "")) end

-- Accepts the Nmap list form {a,b} (a table), a quoted "a,b" string, or a
-- single value. Empty entries and duplicates are dropped; order is kept.
function Engine.to_list(v)
  local raw = {}
  if type(v) == "table" then
    for _, item in ipairs(v) do raw[#raw + 1] = tostring(item) end
  elseif v ~= nil then
    for item in tostring(v):gmatch("[^,]+") do raw[#raw + 1] = item end
  end
  local out, seen = {}, {}
  for _, item in ipairs(raw) do
    local t = trim(item)
    if t ~= "" and not seen[t] then
      seen[t] = true
      out[#out + 1] = t
    end
  end
  return out
end

function Engine.to_bool(v, default)
  if v == nil then return default end
  if type(v) == "boolean" then return v end
  local s = tostring(v):lower()
  if s == "1" or s == "true" or s == "yes" or s == "on" then return true end
  if s == "0" or s == "false" or s == "no" or s == "off" then return false end
  return default
end

-- Normalises a probe path. Returns nil and a reason for values that are not
-- a plain absolute path, so odd input is reported instead of sent.
function Engine.clean_path(p)
  p = trim(p)
  if p == "" then return nil, "empty" end
  if p:find("[%c%s]") then return nil, "contains whitespace or control characters" end
  if p:match("^%a[%w+.-]*://") then return nil, "absolute URLs are not allowed; give a path" end
  if p:sub(1, 1) ~= "/" then p = "/" .. p end
  if #p > 512 then return nil, "longer than 512 characters" end
  return p
end

-- Returns the cleaned, de-duplicated path list (bounded by max) and warnings.
function Engine.clean_paths(list, max)
  local out, seen, warnings = {}, {}, {}
  for _, raw in ipairs(list) do
    local p, why = Engine.clean_path(raw)
    if not p then
      warnings[#warnings + 1] = ("skipped path %q: %s"):format(raw, why)
    elseif not seen[p] then
      seen[p] = true
      if #out >= max then
        warnings[#warnings + 1] = ("path list truncated to max-paths=%d"):format(max)
        break
      end
      out[#out + 1] = p
    end
  end
  return out, warnings
end

-- ---- policy ---------------------------------------------------------------

local POLICY_KEYS = {name = true, description = true, fail_on = true, hsts = true, exposure = true,
  checks = true, skip = true, ["$schema"] = true}
local HSTS_KEYS = {min_max_age = "number", require_include_subdomains = "boolean", require_preload = "boolean"}
local EXPOSURE_KEYS = {enabled = "boolean", trace = "boolean", paths = "table", max_paths = "number"}

local function is_array(t)
  if type(t) ~= "table" then return false end
  local n = 0
  for _ in pairs(t) do n = n + 1 end
  return n == #t
end

-- Merges a decoded policy document over the defaults. Unknown keys and check
-- IDs are errors: a typo in a policy must not silently weaken it.
function Engine.apply_policy(doc)
  if type(doc) ~= "table" or is_array(doc) and #doc > 0 then
    return nil, "policy must be a JSON object"
  end
  local p = default_policy()
  for k in pairs(doc) do
    if not POLICY_KEYS[k] then return nil, ("unknown policy key %q"):format(tostring(k)) end
  end
  if doc.name ~= nil then
    if type(doc.name) ~= "string" or doc.name == "" then return nil, "name must be a non-empty string" end
    p.name = doc.name
  else
    p.name = "custom"
  end
  if doc.fail_on ~= nil then
    local s = tostring(doc.fail_on):upper()
    if not RANK[s] then return nil, ("fail_on must be one of critical, high, medium, low, info (got %q)")
      :format(tostring(doc.fail_on)) end
    p.fail_on = s
  end
  for section, keys in pairs({hsts = HSTS_KEYS, exposure = EXPOSURE_KEYS}) do
    local v = doc[section]
    if v ~= nil then
      if type(v) ~= "table" or (is_array(v) and #v > 0) then return nil, section .. " must be an object" end
      for k, val in pairs(v) do
        local want = keys[k]
        if not want then return nil, ("unknown key %s.%s"):format(section, tostring(k)) end
        if type(val) ~= want then return nil, ("%s.%s must be a %s"):format(section, k, want) end
        if want == "number" and (val < 0 or val ~= math.floor(val)) then
          return nil, ("%s.%s must be a non-negative integer"):format(section, k)
        end
        if k == "paths" then
          if not is_array(val) then return nil, "exposure.paths must be an array" end
          for _, item in ipairs(val) do
            if type(item) ~= "string" then return nil, "exposure.paths entries must be strings" end
          end
        end
        p[section][k] = val
      end
    end
  end
  if doc.skip ~= nil then
    if not is_array(doc.skip) then return nil, "skip must be an array of finding IDs" end
    for _, id in ipairs(doc.skip) do
      if not Engine.CHECKS[id] then return nil, ("skip: unknown finding ID %q"):format(tostring(id)) end
      p.skip[#p.skip + 1] = id
    end
  end
  if doc.checks ~= nil then
    if type(doc.checks) ~= "table" or (is_array(doc.checks) and #doc.checks > 0) then
      return nil, "checks must be an object keyed by finding ID"
    end
    for id, cfg in pairs(doc.checks) do
      if not Engine.CHECKS[id] then return nil, ("checks: unknown finding ID %q"):format(tostring(id)) end
      if type(cfg) ~= "table" then return nil, ("checks.%s must be an object"):format(id) end
      local entry = {}
      for k, v in pairs(cfg) do
        if k == "severity" then
          local s = tostring(v):upper()
          if not RANK[s] then return nil, ("checks.%s.severity is not a severity: %q"):format(id, tostring(v)) end
          entry.severity = s
        elseif k == "enabled" then
          if type(v) ~= "boolean" then return nil, ("checks.%s.enabled must be a boolean"):format(id) end
          entry.enabled = v
        else
          return nil, ("unknown key checks.%s.%s"):format(id, tostring(k))
        end
      end
      p.checks[id] = entry
    end
  end
  return p
end

-- Effective severity of a check under a policy, or nil when it is disabled.
-- required = the policy demands the property elsewhere (e.g. hsts.require_*),
-- which turns on a check that is off by default unless explicitly disabled.
function Engine.effective(policy, id, required)
  local base = Engine.CHECKS[id]
  local o = policy.checks[id] or {}
  local enabled = o.enabled
  if enabled == nil then enabled = base.enabled or required or false end
  for _, s in ipairs(policy.skip) do
    if s == id then enabled = false end
  end
  if not enabled then return nil end
  return o.severity or base.severity
end

-- ---- header parsers -------------------------------------------------------

-- Parses one CSP header value into a list of policies. Each policy maps a
-- directive to its lowercased source tokens. Within a policy only the first
-- occurrence of a directive counts (CSP3 section 2.2.1).
function Engine.parse_csp(value)
  local policies = {}
  for chunk in (value or ""):gmatch("[^,]+") do
    local d, any = {}, false
    for part in chunk:gmatch("[^;]+") do
      local name, rest = part:match("^%s*([%w%-]+)%s*(.-)%s*$")
      if name then
        name = name:lower()
        if not d[name] then
          local tokens = {}
          for tok in rest:gmatch("%S+") do tokens[#tokens + 1] = tok:lower() end
          d[name] = tokens
          any = true
        end
      end
    end
    if any then policies[#policies + 1] = d end
  end
  return policies
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

local BROAD_SOURCES = {"*", "http:", "https:", "data:"}

-- Weaknesses of one CSP policy, as id -> detail. Only directives that a
-- browser enforces from this delivery mechanism are considered.
local function csp_policy_weaknesses(d)
  local w = {}
  local script = d["script-src"] or d["default-src"]
  local which = d["script-src"] and "script-src" or "default-src"
  if not script then
    w["csp-no-script-restriction"] = "CSP has neither script-src nor default-src"
  else
    local nonce_or_hash = has_nonce_or_hash(script)
    -- With a nonce or hash, browsers ignore 'unsafe-inline'. With
    -- 'strict-dynamic' they also ignore host and scheme sources.
    if has_token(script, "'unsafe-inline'") and not nonce_or_hash then
      w["csp-unsafe-inline"] = ("%s allows 'unsafe-inline' without a nonce or hash"):format(which)
    end
    if has_token(script, "'unsafe-eval'") then
      w["csp-unsafe-eval"] = ("%s allows 'unsafe-eval'"):format(which)
    end
    if not has_token(script, "'strict-dynamic'") then
      local broad = {}
      for _, b in ipairs(BROAD_SOURCES) do
        if has_token(script, b) then broad[#broad + 1] = b end
      end
      if #broad > 0 then
        w["csp-broad-script-source"] = ("%s allows scripts from %s"):format(which, table.concat(broad, " "))
      end
    end
  end
  local object = d["object-src"] or d["default-src"]
  if not object then
    w["csp-no-object-src"] = "CSP has neither object-src nor default-src"
  elseif not has_token(object, "'none'") then
    for _, b in ipairs(BROAD_SOURCES) do
      if has_token(object, b) then
        w["csp-no-object-src"] = ("%s allows plugins from %s"):format(d["object-src"] and "object-src"
          or "default-src", b)
        break
      end
    end
  end
  local base = d["base-uri"]
  if not base then
    w["csp-no-base-uri"] = "CSP has no base-uri (it does not fall back to default-src)"
  elseif has_token(base, "*") or has_token(base, "https:") or has_token(base, "http:") then
    w["csp-no-base-uri"] = "base-uri allows any origin"
  end
  return w
end

-- Combines several enforced policies: a resource must pass every policy, so
-- a weakness is real only if no policy closes it.
function Engine.csp_weaknesses(policies)
  if #policies == 0 then return {} end
  local result = csp_policy_weaknesses(policies[1])
  for i = 2, #policies do
    local w = csp_policy_weaknesses(policies[i])
    for id in pairs(result) do
      if not w[id] then result[id] = nil end
    end
  end
  return result
end

-- Extracts a CSP delivered with <meta http-equiv="Content-Security-Policy">.
function Engine.meta_csp(body)
  if not body then return nil end
  for tag in body:gmatch("<[mM][eE][tT][aA][^>]+>") do
    local lower = tag:lower()
    if lower:find("http%-equiv%s*=%s*[\"']?content%-security%-policy[\"'%s>/]") then
      local v = tag:match("[cC][oO][nN][tT][eE][nN][tT]%s*=%s*\"([^\"]*)\"")
        or tag:match("[cC][oO][nN][tT][eE][nN][tT]%s*=%s*'([^']*)'")
      if v then return (v:gsub("&#39;", "'"):gsub("&quot;", "\""):gsub("&amp;", "&")) end
    end
  end
  return nil
end

-- RFC 6797: the UA processes only the first HSTS header, and a header with a
-- repeated directive is invalid. Returns {max_age, subdomains, preload} or
-- nil with a reason.
function Engine.parse_hsts(value)
  local first = (value or ""):match("^[^,]*")
  local seen, out = {}, {subdomains = false, preload = false}
  for part in first:gmatch("[^;]+") do
    local name, val = part:match("^%s*([%w%-]+)%s*=?%s*(.-)%s*$")
    if name then
      name = name:lower()
      if seen[name] then return nil, ("directive %s appears twice"):format(name) end
      seen[name] = true
      if name == "max-age" then
        local n = val:match('^"(%d+)"$') or val:match("^(%d+)$")
        if not n then return nil, ("max-age value %q is not a number"):format(val) end
        out.max_age = tonumber(n)
      elseif name == "includesubdomains" then
        out.subdomains = true
      elseif name == "preload" then
        out.preload = true
      end
    end
  end
  if not out.max_age then return nil, "no max-age directive" end
  return out
end

local REFERRER_VALUES = {
  ["no-referrer"] = true, ["no-referrer-when-downgrade"] = true, ["same-origin"] = true, ["origin"] = true,
  ["strict-origin"] = true, ["origin-when-cross-origin"] = true, ["strict-origin-when-cross-origin"] = true,
  ["unsafe-url"] = true,
}

-- Several values may be listed; the last one the browser recognises wins.
function Engine.referrer_policy(value)
  local last
  for tok in (value or ""):lower():gmatch("[^,%s]+") do
    if REFERRER_VALUES[tok] then last = tok end
  end
  return last
end

-- Returns "protected", or "allowed"/"missing" plus a detail string.
-- frame-ancestors (header CSP only) overrides X-Frame-Options in browsers.
function Engine.framing(csp_policies, xfo_value)
  local any_fa, restrictive = false, false
  for _, d in ipairs(csp_policies) do
    local fa = d["frame-ancestors"]
    if fa then
      any_fa = true
      local open = false
      for _, t in ipairs(fa) do
        if t == "*" or t == "http:" or t == "https:" then open = true end
      end
      if not open then restrictive = true end
    end
  end
  if any_fa then
    if restrictive then return "protected" end
    return "allowed", "CSP frame-ancestors allows any site to frame the page"
  end
  if not xfo_value then
    return "missing", "No X-Frame-Options or CSP frame-ancestors"
  end
  -- HTML spec: repeated values are fine only if they all agree.
  local value
  for tok in xfo_value:lower():gmatch("[^,]+") do
    local t = trim(tok)
    if value and value ~= t then return "allowed", "Conflicting X-Frame-Options values are ignored" end
    value = t
  end
  if value == "deny" or value == "sameorigin" then return "protected" end
  if value and value:find("^allow%-from") then
    return "allowed", "X-Frame-Options ALLOW-FROM is ignored by current browsers"
  end
  return "allowed", ("Invalid X-Frame-Options value: %s"):format(value or "")
end

local POWERFUL_FEATURES = {"camera", "microphone", "geolocation", "usb", "payment", "display-capture",
  "serial", "hid", "bluetooth"}

-- Returns the list of powerful features granted to every origin.
function Engine.permissions_open(value)
  local open = {}
  local v = (value or ""):lower()
  for _, f in ipairs(POWERFUL_FEATURES) do
    local allow = v:match("%f[%w%-]" .. f:gsub("%-", "%%-") .. "%s*=%s*(%b())")
      or v:match("%f[%w%-]" .. f:gsub("%-", "%%-") .. "%s*=%s*(%*)")
    if allow and allow:find("*", 1, true) then open[#open + 1] = f end
  end
  return open
end

local SESSION_PATTERNS = {"sess", "^sid$", "[_%.%-]sid$", "auth", "token", "jwt", "login", "remember",
  "^id$", "identity"}

-- CSRF tokens are meant to be read by scripts (double-submit pattern).
function Engine.cookie_kind(name)
  local n = tostring(name):lower()
  if n:find("csrf", 1, true) or n:find("xsrf", 1, true) then return "csrf" end
  for _, pat in ipairs(SESSION_PATTERNS) do
    if n:find(pat) then return "session" end
  end
  return "other"
end

local function has_version(s) return s and s:match("%d+%.%d+") ~= nil end

-- Directory listing pages of common servers.
function Engine.is_directory_listing(body)
  if not body then return false end
  local head = body:sub(1, 4096)
  return head:find("<[Tt][Ii][Tt][Ll][Ee]>%s*Index of /") ~= nil
    or head:find("<h1>Index of /", 1, true) ~= nil
    or head:find("Directory listing for /", 1, true) ~= nil
end

-- ---- evaluation -----------------------------------------------------------

-- Creates the finding collector for one target.
function Engine.new_result(policy)
  local r = {policy = policy, findings = {}, passed = {}}
  -- min_severity raises the effective severity, e.g. when a policy requires
  -- something whose default severity is INFO.
  function r.add(id, detail, evidence, path, min_severity)
    local sev = Engine.effective(policy, id, min_severity ~= nil)
    if not sev then return end
    if min_severity and RANK[min_severity] < RANK[sev] then sev = min_severity end
    local c = Engine.CHECKS[id]
    r.findings[#r.findings + 1] = {
      id = id, severity = sev, title = c.title, detail = detail, evidence = evidence,
      path = path, cwe = c.cwe, owasp = c.owasp, asvs = c.asvs, recommendation = c.recommendation,
    }
  end
  function r.pass(name) r.passed[#r.passed + 1] = name end
  return r
end

-- Judges the headers and body of one response.
-- resp = {header = {lowercase name -> value}, cookies = {...}, body = string}
function Engine.check_headers(resp, tls, r, path)
  local h = resp.header or {}
  local policy = r.policy
  local function add(id, detail, evidence, min_severity) r.add(id, detail, evidence, path, min_severity) end

  -- Transport. HSTS only means something over TLS.
  local hsts = h["strict-transport-security"]
  if not tls then
    add("no-https-redirect", "Serves content over plain HTTP without redirecting to HTTPS")
    if hsts then
      add("hsts-over-http", "Strict-Transport-Security sent over plain HTTP is ignored by browsers",
        "Strict-Transport-Security: " .. hsts)
    end
  elseif not hsts then
    add("hsts-missing", "No Strict-Transport-Security header")
  else
    local ev = "Strict-Transport-Security: " .. hsts
    local v, why = Engine.parse_hsts(hsts)
    if not v then
      add("hsts-invalid", "Strict-Transport-Security is ignored by browsers: " .. why, ev)
    elseif v.max_age == 0 then
      add("hsts-disabled", "Strict-Transport-Security max-age=0 turns HSTS off", ev)
    else
      local ok = true
      if v.max_age < policy.hsts.min_max_age then
        add("hsts-short-max-age", ("max-age=%d is below %d"):format(v.max_age, policy.hsts.min_max_age), ev)
        ok = false
      end
      -- A requirement the policy states explicitly is at least LOW, so it
      -- can affect the score and the result.
      if not v.subdomains then
        local required = policy.hsts.require_include_subdomains
        add("hsts-no-subdomains", "HSTS does not set includeSubDomains", ev, required and "LOW" or nil)
        if required then ok = false end
      end
      -- Off by default. Enabled by a policy check entry, or required (and at
      -- least LOW) by hsts.require_preload. The directive alone does not prove
      -- the domain is on the preload list.
      if not v.preload then
        local required = policy.hsts.require_preload
        add("hsts-no-preload", "HSTS does not set preload", ev, required and "LOW" or nil)
        if required then ok = false end
      end
      if ok then r.pass("hsts") end
    end
  end

  -- Content-Security-Policy. A meta tag counts, but cannot set frame-ancestors.
  local csp_raw = h["content-security-policy"]
  local header_policies = csp_raw and Engine.parse_csp(csp_raw) or {}
  local policies = {}
  for _, d in ipairs(header_policies) do policies[#policies + 1] = d end
  local meta = Engine.meta_csp(resp.body)
  if meta then
    local mp = Engine.parse_csp(meta)
    for _, d in ipairs(mp) do
      d["frame-ancestors"] = nil
      policies[#policies + 1] = d
    end
  end
  if #policies == 0 then
    if h["content-security-policy-report-only"] then
      add("csp-report-only", "CSP is Report-Only, so it is not enforced",
        "Content-Security-Policy-Report-Only: " .. h["content-security-policy-report-only"])
    else
      add("csp-missing", "No Content-Security-Policy header or meta tag")
    end
  else
    local ev = csp_raw and ("Content-Security-Policy: " .. csp_raw) or ("<meta> CSP: " .. meta)
    local weak = Engine.csp_weaknesses(policies)
    local order = {"csp-no-script-restriction", "csp-unsafe-inline", "csp-unsafe-eval", "csp-broad-script-source",
      "csp-no-object-src", "csp-no-base-uri"}
    local script_ok = true
    for _, id in ipairs(order) do
      if weak[id] then
        add(id, weak[id], ev)
        if id ~= "csp-no-object-src" and id ~= "csp-no-base-uri" then script_ok = false end
      end
    end
    if script_ok then r.pass("csp") end
  end

  -- Framing. Uses header CSP only: browsers ignore frame-ancestors in <meta>.
  local state, detail = Engine.framing(header_policies, h["x-frame-options"])
  if state == "protected" then
    r.pass("framing")
  elseif state == "missing" then
    add("framing-missing", detail)
  else
    add("framing-allowed", detail, h["x-frame-options"] and ("X-Frame-Options: " .. h["x-frame-options"]) or nil)
  end

  local xcto = h["x-content-type-options"]
  if xcto and xcto:lower():match("^%s*nosniff%s*$") then
    r.pass("x-content-type-options")
  else
    add("xcto-missing", "X-Content-Type-Options is not nosniff",
      xcto and ("X-Content-Type-Options: " .. xcto) or nil)
  end

  local rp_raw = h["referrer-policy"]
  local rp = Engine.referrer_policy(rp_raw)
  if not rp then
    add("referrer-policy-missing", rp_raw and "Referrer-Policy has no recognised value"
      or "No Referrer-Policy; the browser default applies", rp_raw and ("Referrer-Policy: " .. rp_raw) or nil)
  elseif rp == "unsafe-url" or rp == "no-referrer-when-downgrade" then
    add("referrer-policy-leaky", ("Referrer-Policy %s sends full URLs cross-origin"):format(rp),
      "Referrer-Policy: " .. rp_raw)
  else
    r.pass("referrer-policy")
  end

  local pp = h["permissions-policy"]
  if not pp then
    local note = h["feature-policy"] and " (only the legacy Feature-Policy header is sent)" or ""
    add("permissions-policy-missing", "No Permissions-Policy header" .. note)
  else
    local open = Engine.permissions_open(pp)
    if #open > 0 then
      add("permissions-policy-permissive", "Granted to every origin: " .. table.concat(open, ", "),
        "Permissions-Policy: " .. pp)
    else
      r.pass("permissions-policy")
    end
  end

  local missing_coi = {}
  for _, name in ipairs({"cross-origin-opener-policy", "cross-origin-resource-policy",
      "cross-origin-embedder-policy"}) do
    if not h[name] then missing_coi[#missing_coi + 1] = name end
  end
  if #missing_coi > 0 then
    add("cross-origin-isolation-missing", "Not set: " .. table.concat(missing_coi, ", "))
  end

  -- CORS. The request carried PROBE_ORIGIN, so seeing it back means reflection.
  local acao = h["access-control-allow-origin"]
  local acac = (h["access-control-allow-credentials"] or ""):lower():match("^%s*true%s*$") ~= nil
  if acao then
    local ev = "Access-Control-Allow-Origin: " .. acao .. (acac and "; Access-Control-Allow-Credentials: true" or "")
    if acao:lower() == PROBE_ORIGIN then
      if acac then
        add("cors-reflected-credentials", "Origin reflected in Access-Control-Allow-Origin with credentials allowed",
          ev)
      else
        add("cors-reflected-origin", "Arbitrary Origin reflected in Access-Control-Allow-Origin", ev)
      end
    elseif trim(acao) == "*" and acac then
      add("cors-wildcard-credentials",
        "Access-Control-Allow-Origin * with credentials; browsers refuse it, so the intent is unclear", ev)
    end
  end

  -- Version strings help an attacker match known vulnerabilities.
  local server = h["server"]
  if has_version(server) then
    add("info-disclosure", "Server: " .. server, "Server: " .. server)
  end
  for _, pair in ipairs({{"x-powered-by", "X-Powered-By"}, {"x-aspnet-version", "X-AspNet-Version"},
      {"x-aspnetmvc-version", "X-AspNetMvc-Version"}}) do
    local v = h[pair[1]]
    if v then
      local ev = pair[2] .. ": " .. v
      if has_version(v) then add("info-disclosure", ev, ev) else add("tech-disclosure", ev, ev) end
    end
  end

  local xxp = h["x-xss-protection"]
  if xxp and xxp:match("^%s*1") then
    add("xxp-enabled", "X-XSS-Protection enables the removed XSS auditor", "X-XSS-Protection: " .. xxp)
  end
  if h["public-key-pins"] or h["public-key-pins-report-only"] then
    add("hpkp-present", "Public-Key-Pins is ignored by current browsers")
  end
  if h["expect-ct"] then
    add("expect-ct-present", "Expect-CT is obsolete", "Expect-CT: " .. h["expect-ct"])
  end

  -- Cookies, grouped by problem so a site with 20 cookies stays readable.
  local no_secure, no_httponly, bad_samesite, no_samesite, other = {}, {}, {}, {}, {}
  for _, c in ipairs(resp.cookies or {}) do
    local kind = Engine.cookie_kind(c.name)
    local secure, httponly = c.secure ~= nil, c.httponly ~= nil
    local samesite = c.samesite and c.samesite:lower() or nil
    if samesite == "none" and not secure then bad_samesite[#bad_samesite + 1] = c.name end
    if kind == "session" then
      if tls and not secure then no_secure[#no_secure + 1] = c.name end
      if not httponly then no_httponly[#no_httponly + 1] = c.name end
      if not samesite then no_samesite[#no_samesite + 1] = c.name end
    elseif kind == "other" then
      local miss = {}
      if tls and not secure then miss[#miss + 1] = "Secure" end
      if not httponly then miss[#miss + 1] = "HttpOnly" end
      if #miss > 0 then other[#other + 1] = ("%s (no %s)"):format(c.name, table.concat(miss, ", ")) end
    end
  end
  if #no_secure > 0 then
    add("cookie-no-secure", "Session cookie sent without Secure over HTTPS: " .. table.concat(no_secure, ", "))
  end
  if #no_httponly > 0 then
    add("cookie-no-httponly", "Session cookie readable by JavaScript: " .. table.concat(no_httponly, ", "))
  end
  if #bad_samesite > 0 then
    add("cookie-samesite-none-insecure", "SameSite=None without Secure (browsers reject the cookie): "
      .. table.concat(bad_samesite, ", "))
  end
  if #no_samesite > 0 then
    add("cookie-no-samesite", "Session cookie without SameSite: " .. table.concat(no_samesite, ", "))
  end
  if #other > 0 then
    add("cookie-flags-nonsession", "Not recognised as session cookies, so judged leniently: "
      .. table.concat(other, "; "))
  end
  if #(resp.cookies or {}) > 0 and #no_secure + #no_httponly + #bad_samesite == 0 then
    r.pass("cookies")
  end

  if Engine.is_directory_listing(resp.body) then
    add("directory-listing", "The page is an automatic directory listing")
  end
end

-- Verdict for one probed path. entry is the EXPOSURE catalog entry or nil
-- for a user-supplied path. exists is the soft-404 decision (nil = unknown).
function Engine.judge_probe(_path, status, body, entry, exists)
  if not status then return "no response" end
  if status >= 200 and status < 300 then
    if entry and entry.sig then
      if entry.sig(body or "") then return "exposed", entry.id end
      return "absent (content not recognised)"
    end
    if exists == false then return "absent (soft-404)" end
    if Engine.is_directory_listing(body) then return "exposed (directory listing)", "directory-listing" end
    return "exposed", entry and entry.id or "path-exposed"
  elseif status == 401 or status == 403 then
    return "protected"
  elseif status == 404 or status == 410 then
    return "absent"
  elseif status >= 300 and status < 400 then
    return "redirect"
  end
  return "status " .. status
end

-- Score: 100 minus a fixed weight per finding, floored at 0. A HIGH finding
-- caps the grade at C and a CRITICAL finding at F, whatever the score.
function Engine.score(findings)
  local score, worst = 100, 99
  for _, f in ipairs(findings) do
    score = score - (WEIGHT[f.severity] or 0)
    worst = math.min(worst, RANK[f.severity] or 99)
  end
  score = math.max(0, score)
  local grade
  if score >= 90 then grade = "A" elseif score >= 80 then grade = "B" elseif score >= 70 then grade = "C"
  elseif score >= 60 then grade = "D" else grade = "F" end
  if worst == RANK.CRITICAL then
    grade = "F"
  elseif worst == RANK.HIGH and (grade == "A" or grade == "B") then
    grade = "C"
  end
  return score, grade
end

-- Sorts findings, counts them and decides PASS/FAIL.
function Engine.summarise(findings, fail_on)
  table.sort(findings, function(a, b)
    if RANK[a.severity] ~= RANK[b.severity] then return RANK[a.severity] < RANK[b.severity] end
    if a.id ~= b.id then return a.id < b.id end
    return (a.detail or "") < (b.detail or "")
  end)
  local counts, failing = {}, false
  for _, s in ipairs(SEVERITIES) do counts[s] = 0 end
  for _, f in ipairs(findings) do
    counts[f.severity] = counts[f.severity] + 1
    if RANK[f.severity] <= RANK[fail_on] then failing = true end
  end
  local parts = {}
  for _, s in ipairs(SEVERITIES) do parts[#parts + 1] = ("%s=%d"):format(s:lower(), counts[s]) end
  return failing and "FAIL" or "PASS", counts, table.concat(parts, " ")
end

-- Classifies an http library error ("status-line" of a failed request).
-- When a plain connection times out, the library retries over TLS and only
-- reports "Error creating socket", so a silent server is "no-response".
function Engine.classify_error(line)
  local l = tostring(line or ""):lower()
  if l:find("timeout") or l:find("timed out") then return "timeout" end
  if l:find("refused") then return "connection-refused" end
  if l:find("reset") or l:find("eof") or l:find("closed") then return "connection-closed" end
  if l:find("status[ %-]line") or l:find("crlf") or l:find("header") or l:find("chunk") or l:find("pars") then
    return "unsupported-response"
  end
  if l == "" or l:find("creating socket") then return "no-response" end
  return "connection-error"
end

-- Error text from the network can hold any byte; keep output on one line.
function Engine.printable(s)
  return (tostring(s or ""):gsub("[%c\127]", " "):gsub("%s+", " "))
end

-- ---------------------------------------------------------------------------
-- Nmap runtime: arguments, requests, output.
-- ---------------------------------------------------------------------------

local function arg(name, default)
  local v = stdnse.get_script_args(SCRIPT_NAME .. "." .. name)
  if v == nil then return default end
  return v
end

local function load_policy(path)
  local f, err = io.open(path, "rb")
  if not f then return nil, ("cannot open policy %s: %s"):format(path, tostring(err)) end
  local text = f:read("a")
  f:close()
  local ok, doc = json.parse(text or "")
  if not ok then return nil, ("policy %s is not valid JSON: %s"):format(path, tostring(doc)) end
  local p, why = Engine.apply_policy(doc)
  if not p then return nil, ("policy %s: %s"):format(path, why) end
  return p
end

-- Builds the policy from file and script arguments (arguments win).
local function resolve_policy()
  local policy = default_policy()
  local file = arg("policy")
  if file then
    local p, err = load_policy(file)
    if not p then return nil, err end
    policy = p
  end
  local fail_on = arg("fail-on")
  if fail_on then
    local s = tostring(fail_on):upper()
    if not RANK[s] then return nil, ("fail-on must be critical, high, medium, low or info (got %q)"):format(fail_on) end
    policy.fail_on = s
  end
  local hsts_min = arg("hsts-min")
  if hsts_min then
    local n = tonumber(hsts_min)
    if not n or n < 0 then
      return nil, ("hsts-min must be a non-negative number (got %q)"):format(tostring(hsts_min))
    end
    policy.hsts.min_max_age = n
  end
  for _, id in ipairs(Engine.to_list(arg("skip"))) do
    if not Engine.CHECKS[id] then return nil, ("skip: unknown finding ID %q"):format(id) end
    policy.skip[#policy.skip + 1] = id
  end
  policy.exposure.enabled = Engine.to_bool(arg("exposure"), policy.exposure.enabled)
  local max_paths = tonumber(arg("max-paths", policy.exposure.max_paths))
  if not max_paths or max_paths < 0 then return nil, "max-paths must be a non-negative number" end
  policy.exposure.max_paths = math.floor(max_paths)
  return policy
end

-- http.get writes options.scheme into the table it is given when it sees a
-- redirect (even with redirect_ok=false), which would force TLS on the next
-- request to a plain-HTTP port. Every request therefore gets a fresh copy.
local function fresh(opts, overrides)
  local o = {}
  for k, v in pairs(opts) do o[k] = v end
  local h = {}
  for k, v in pairs(opts.header or {}) do h[k] = v end
  o.header = h
  for k, v in pairs(overrides or {}) do o[k] = v end
  return o
end

local function copy_target(host, vhost)
  -- nsock takes the TLS server name from host.targetname and the http library
  -- takes the Host header from it too, so a vhost needs a modified host table.
  if not vhost then return host end
  local target = {}
  for k, v in pairs(host) do target[k] = v end
  target.targetname = vhost
  target.name = vhost
  return target
end

-- Follows same-origin redirects so a "/" -> "/login" hop evaluates the real
-- page. Stops at a redirect to HTTPS (a pass for plaintext ports) or off-site.
local function fetch_page(target, port, path, opts, counter)
  local hostname = stdnse.get_hostname(target)
  local resp, upgrade, offsite, hops, loop = nil, nil, nil, 0, false
  local seen = {}
  for attempt = 1, 4 do
    counter.n = counter.n + 1
    resp = http.get(target, port, path, fresh(opts))
    if not (resp and resp.status) then return nil, resp and resp["status-line"] end
    local loc = resp.status >= 300 and resp.status < 400 and resp.header.location
    if not loc then break end

    local scheme = resp.ssl and "https" or "http"
    local u = url.parse(url.absolute(("%s://%s:%d%s"):format(scheme, hostname, port.number, path), loc))
    if u.scheme == "https" and not resp.ssl then
      upgrade = {location = loc, status = resp.status, host = u.host}
      break
    end
    local same_host = (u.host or ""):lower() == hostname:lower()
    local same_port = tonumber(u.port or (u.scheme == "https" and 443 or 80)) == port.number
    if not (same_host and same_port) or not u.path then
      offsite = loc
      break
    end
    local next_path = u.path .. (u.query and ("?" .. u.query) or "")
    seen[path] = true
    if seen[next_path] or attempt == 4 then
      loop = true
      break
    end
    path = next_path
    hops = hops + 1
  end
  return {resp = resp, path = path, upgrade = upgrade, offsite = offsite, hops = hops, loop = loop}
end

local function probe(target, port, policy, extra_paths, opts, r, counter)
  local entries = {}
  local by_path = {}
  if policy.exposure.enabled then
    for _, e in ipairs(EXPOSURE) do by_path[e.path] = e end
  end
  local raw = {}
  if policy.exposure.enabled then
    for _, e in ipairs(EXPOSURE) do raw[#raw + 1] = e.path end
  end
  for _, p in ipairs(policy.exposure.paths) do raw[#raw + 1] = p end
  for _, p in ipairs(extra_paths) do raw[#raw + 1] = p end
  local paths, warnings = Engine.clean_paths(raw, policy.exposure.max_paths)
  if #paths == 0 then return nil, warnings end

  local ok404, result_404, known_404 = http.identify_404(target, port)
  if not ok404 then
    warnings[#warnings + 1] = "soft-404 calibration failed: " .. tostring(result_404)
  end

  local probe_overrides = {max_body_size = 65536}

  for _, p in ipairs(paths) do
    counter.n = counter.n + 1
    local resp = http.get(target, port, p, fresh(opts, probe_overrides))
    local status = resp and resp.status
    local exists
    if status and status >= 200 and status < 300 and ok404 then
      exists = http.page_exists(resp, result_404, known_404, p, false) and true or false
    end
    local verdict, id = Engine.judge_probe(p, status, resp and resp.body, by_path[p], exists)
    if verdict == "redirect" then verdict = "redirect -> " .. tostring(resp.header.location or "?") end
    if id then
      -- Evidence describes the match; response bodies are never copied into
      -- the report because they may contain secrets.
      local entry = by_path[p]
      r.add(id, ("%s returned %d"):format(p, status), entry and entry.evidence or ("HTTP " .. status), p)
    end
    entries[#entries + 1] = {path = p, status = status or "-", verdict = verdict}
  end

  if policy.exposure.enabled and policy.exposure.trace then
    counter.n = counter.n + 1
    local resp = http.generic_request(target, port, "TRACE", "/", fresh(opts, probe_overrides))
    if resp and resp.status == 200 and (resp.body or ""):find("^TRACE / HTTP") then
      r.add("trace-enabled", "TRACE / echoed the request", "TRACE / HTTP/1.1 -> 200", "/")
      entries[#entries + 1] = {path = "TRACE /", status = 200, verdict = "enabled"}
    else
      entries[#entries + 1] = {path = "TRACE /", status = resp and resp.status or "-", verdict = "not enabled"}
    end
  end
  return entries, warnings
end

local function render(out, findings, passed, paths)
  local lines = {}
  lines[#lines + 1] = ("url: %s (%s)"):format(out.url, out.status or "-")
  if out.note then lines[#lines + 1] = "note: " .. out.note end
  if out.result == "ERROR" then
    lines[#lines + 1] = ("result: ERROR (%s: %s)"):format(out.error, out.error_detail or "")
    return stdnse.format_output(true, lines)
  end
  lines[#lines + 1] = ("result: %s  score: %d/100  grade: %s  policy: %s"):format(out.result, out.score,
    out.grade, out.policy)
  lines[#lines + 1] = ("summary: %s (fail-on=%s)"):format(out.summary, out.fail_on)

  local idw = 0
  for _, f in ipairs(findings) do idw = math.max(idw, #f.id) end
  for _, f in ipairs(findings) do
    lines[#lines + 1] = ("%-8s %-" .. idw .. "s  %s"):format(f.severity, f.id, f.detail)
  end
  if #passed > 0 then lines[#lines + 1] = "passed: " .. table.concat(passed, ", ") end
  for _, w in ipairs(out.warnings or {}) do lines[#lines + 1] = "warning: " .. w end

  if paths and #paths > 0 then
    local pw = 0
    for _, e in ipairs(paths) do pw = math.max(pw, #e.path) end
    local sub = {name = "paths:"}
    for _, e in ipairs(paths) do
      sub[#sub + 1] = ("%-" .. pw .. "s  %-3s  %s"):format(e.path, tostring(e.status), e.verdict)
    end
    lines[#lines + 1] = sub
  end
  return stdnse.format_output(true, lines)
end

local function error_output(out, kind, detail)
  out.result = "ERROR"
  out.error = kind
  out.error_detail = Engine.printable(detail)
  return out, render(out)
end

action = function(host, port)
  local target = copy_target(host, arg("vhost"))
  local tls_guess = shortport.ssl(host, port)
  local out = stdnse.output_table()
  out.url = ("%s://%s:%d%s"):format(tls_guess and "https" or "http", stdnse.get_hostname(target), port.number,
    arg("path", "/"))

  local policy, perr = resolve_policy()
  if not policy then return error_output(out, "policy-error", perr) end
  out.policy = policy.name

  local opts = {
    timeout = tonumber(arg("timeout", 8000)) or 8000,
    redirect_ok = false,
    no_cache = true,
    max_body_size = 262144,
    truncated_ok = true,
    header = {Origin = PROBE_ORIGIN},
  }
  local counter = {n = 0}

  local page, ferr = fetch_page(target, port, arg("path", "/"), opts, counter)
  if not page then
    out.requests = counter.n
    return error_output(out, Engine.classify_error(ferr), ferr or "no response")
  end
  local resp = page.resp
  local tls = resp.ssl and true or false
  out.url = ("%s://%s:%d%s"):format(tls and "https" or "http", stdnse.get_hostname(target), port.number, page.path)
  out.status = resp.status

  local r = Engine.new_result(policy)
  local notes = {}
  if page.upgrade then
    r.pass("https-redirect")
    notes[#notes + 1] = ("redirects (%d) to %s; headers are judged on the HTTPS port"):format(page.upgrade.status,
      page.upgrade.location)
  else
    if page.offsite then
      notes[#notes + 1] = "redirects off-site to " .. page.offsite .. "; judging the redirect response"
    elseif page.loop then
      notes[#notes + 1] = "redirect loop or limit reached; judging the last redirect response"
    elseif resp.status >= 300 and resp.status < 400 then
      notes[#notes + 1] = ("status %d without a usable Location header"):format(resp.status)
    elseif resp.status >= 400 then
      notes[#notes + 1] = ("status %d: headers judged on an error response"):format(resp.status)
    end
    Engine.check_headers(resp, tls, r, page.path)
  end
  if #notes > 0 then out.note = table.concat(notes, "; ") end

  local path_results, warnings = probe(target, port, policy, Engine.to_list(arg("paths")), opts, r, counter)
  warnings = warnings or {}
  -- Arguments from version 1 that no longer exist; say so instead of
  -- silently running with different settings.
  local removed = {
    headers = "use a policy file (policy=...) to choose checks",
    brief = "console output is always brief; use -oX and hhc-report for detail",
    host = "use vhost=...",
  }
  for old, hint in pairs(removed) do
    if arg(old) ~= nil then
      warnings[#warnings + 1] = ("argument %s.%s was removed in v2: %s"):format(SCRIPT_NAME, old, hint)
    end
  end
  table.sort(warnings)

  local result, counts, summary = Engine.summarise(r.findings, policy.fail_on)
  local score, grade = Engine.score(r.findings)
  out.result = result
  out.score = score
  out.grade = grade
  out.fail_on = policy.fail_on:lower()
  out.summary = summary
  local c = stdnse.output_table()
  for _, s in ipairs(SEVERITIES) do c[s:lower()] = counts[s] end
  out.counts = c

  local findings = {}
  for _, f in ipairs(r.findings) do
    local t = stdnse.output_table()
    for _, k in ipairs({"id", "severity", "title", "detail", "evidence", "path", "cwe", "owasp", "asvs",
        "recommendation"}) do
      t[k] = f[k]
    end
    findings[#findings + 1] = t
  end
  out.findings = findings
  out.passed = r.passed
  out.paths = path_results
  if #warnings > 0 then out.warnings = warnings end
  out.requests = counter.n

  return out, render(out, r.findings, r.passed, path_results)
end

-- Test hook: tests/unit/run.lua sets this to receive the engine.
local hook = rawget(_ENV, "HHC_TEST_EXPORT")
if hook then hook(Engine) end
