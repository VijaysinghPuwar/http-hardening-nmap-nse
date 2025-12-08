local stdnse    = require "stdnse"
local shortport = require "shortport"
local http      = require "http"

description = [[
Checks basic HTTP hardening on a target:

• Verifies security headers on "/" (configurable): HSTS, CSP, X-Frame-Options
• Optionally probes "/admin" and flags whether it is exposed (200) or protected (401/403)

Emits a concise, grep/CSV-friendly finding line per host/port.
]]

---
-- @usage
-- sudo nmap -Pn -sV -p80,443 <target> \
--   --script http_hardening_check \
--   --script-args "http_hardening_check.headers=hsts,csp,xfo,http_hardening_check.paths=/,/admin,http_hardening_check.brief=true"
--
-- @args http_hardening_check.headers  Comma list or shorthands: hsts,csp,xfo (or full header names).
-- @args http_hardening_check.paths    Comma list of paths to request (default "/"; add "/admin" to test it).
-- @args http_hardening_check.host     Virtual host (Host header + SNI).
-- @args http_hardening_check.brief    true/false; brief single-line output (default true).
--
-- Example output:
-- | http_hardening_check:
-- |   FINDING: missing=[strict-transport-security,content-security-policy,x-frame-options] admin=[]
-- |_  target=10.20.30.31 port=80
--

author = "Vijaysingh"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe","discovery","default"}

portrule = shortport.http

-- -------------- helpers ----------------

local function split_csv(s)
  if not s or s == "" then return {} end
  local t = {}
  for part in tostring(s):gmatch("[^,]+") do
    local x = part:gsub("^%s+",""):gsub("%s+$","")
    if x ~= "" then table.insert(t, x) end
  end
  return t
end

local function norm_header_name(tok)
  tok = tostring(tok):lower()
  if tok == "hsts" then return "strict-transport-security" end
  if tok == "csp"  then return "content-security-policy" end
  if tok == "xfo"  then return "x-frame-options" end
  return tok
end

local function to_bool(v)
  if v == nil then return true end
  v = tostring(v):lower()
  return (v == "1" or v == "true" or v == "yes" or v == "y")
end

local function head_request(host, port, path, vhost)
  local opts = { timeout = 8000 }
  if vhost and vhost ~= "" then
    opts.host = vhost
    opts.header = opts.header or {}
    opts.header["Host"] = vhost
  end
  -- Try HEAD first; many minimal servers still support it. Fallback to GET.
  local r = http.head(host, port, path, opts)
  if not (r and r.status) then
    r = http.get(host, port, path, opts)
  end
  return r
end

-- Lowercase keys, stringify multi-value headers "a, b"
local function lower_headers_map(h)
  local out = {}
  if type(h) == "table" then
    for k, v in pairs(h) do
      if type(k) == "string" then
        local value
        if type(v) == "table" then
          local parts = {}
          for _, vv in ipairs(v) do table.insert(parts, tostring(vv)) end
          value = table.concat(parts, ", ")
        else
          value = tostring(v)
        end
        out[k:lower()] = value
      end
    end
  end
  return out
end

-- -------------- main ----------------

action = function(host, port)
  local ok, res = pcall(function()
    local vhost      = stdnse.get_script_args("http_hardening_check.host")
    local headersArg = stdnse.get_script_args("http_hardening_check.headers") or "hsts,csp,xfo"
    local pathsArg   = stdnse.get_script_args("http_hardening_check.paths")   or "/"
    local briefArg   = stdnse.get_script_args("http_hardening_check.brief")
    local brief      = to_bool(briefArg)

    -- required set
    local required = {}
    for _, tok in ipairs(split_csv(headersArg)) do
      required[norm_header_name(tok)] = true
    end

    local paths = split_csv(pathsArg)
    if #paths == 0 then paths = {"/"} end

    -- Always check "/" for headers
    local hdr_resp = head_request(host, port, "/", vhost)
    if not (hdr_resp and hdr_resp.status) then
      return stdnse.format_output(true,
        ("FINDING: missing=[*no-response*] admin=[]\n  target=%s port=%s")
          :format(host.ip or host.targetname or "unknown", tostring(port.number)))
    end

    local hdrs = lower_headers_map(hdr_resp.header or {})
    local missing = {}
    for name, _ in pairs(required) do
      if not hdrs[name] then table.insert(missing, name) end
    end
    table.sort(missing)

    -- Optionally check /admin exposure
    local want_admin = false
    for _, p in ipairs(paths) do if p == "/admin" then want_admin = true break end end

    local admin_note = ""
    if want_admin then
      local a = head_request(host, port, "/admin", vhost)
      if a and a.status then
        local code = tonumber(a.status) or 0
        if     code == 200 then admin_note = "/admin -> 200 (exposed)"
        elseif code == 401 or code == 403 then admin_note = "/admin -> " .. code .. " (protected)"
        elseif code == 404 then admin_note = "/admin -> 404 (absent)"
        else                 admin_note = "/admin -> " .. code
        end
      else
        admin_note = "/admin -> no-response"
      end
    end

    local miss_str  = (#missing > 0) and ("[" .. table.concat(missing, ",") .. "]") or "[]"
    local admin_str = (admin_note ~= "") and ("[" .. admin_note .. "]") or "[]"

    local finding = ("FINDING: missing=%s admin=%s"):format(miss_str, admin_str)
    local tip   = host.ip or host.targetname or "unknown"
    local tport = tostring(port.number)

    if brief then
      return stdnse.format_output(true, finding .. ("\n  target=%s port=%s"):format(tip, tport))
    else
      local lines = {
        finding,
        ("target=%s"):format(tip),
        ("port=%s"):format(tport),
        ("vhost=%s"):format(vhost or "-"),
        ("status_root=%s"):format(hdr_resp.status or "-"),
      }
      return stdnse.format_output(true, table.concat(lines, "\n  "))
    end
  end)

  if ok then
    return res
  else
    -- Don’t crash NSE; surface a clear error
    return stdnse.format_output(true, "INTERNAL ERROR: " .. tostring(res))
  end
end
