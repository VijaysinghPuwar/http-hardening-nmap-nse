-- Tiny test harness: no dependencies, runs on Lua 5.4 (Nmap's version) and 5.5.
-- Loads http-hardening-check.nse with stub Nmap libraries and returns its
-- evaluation engine.
local H = {}

local tests = {}

function H.test(name, fn) tests[#tests + 1] = {name = name, fn = fn} end

local function show(v, depth)
  depth = depth or 0
  if type(v) == "string" then return ("%q"):format(v) end
  if type(v) ~= "table" or depth > 3 then return tostring(v) end
  local keys = {}
  for k in pairs(v) do keys[#keys + 1] = k end
  table.sort(keys, function(a, b) return tostring(a) < tostring(b) end)
  local parts = {}
  for _, k in ipairs(keys) do parts[#parts + 1] = tostring(k) .. "=" .. show(v[k], depth + 1) end
  return "{" .. table.concat(parts, ", ") .. "}"
end
H.show = show

local function deep_eq(a, b)
  if type(a) ~= type(b) then return false end
  if type(a) ~= "table" then return a == b end
  for k, v in pairs(a) do
    if not deep_eq(v, b[k]) then return false end
  end
  for k in pairs(b) do
    if a[k] == nil then return false end
  end
  return true
end
H.deep_eq = deep_eq

function H.eq(actual, expected, msg)
  if not deep_eq(actual, expected) then
    error(("%sexpected %s, got %s"):format(msg and (msg .. ": ") or "", show(expected), show(actual)), 2)
  end
end

function H.ok(v, msg)
  if not v then error(msg or "expected a truthy value", 2) end
end

function H.run()
  local passed, failed = 0, 0
  for _, t in ipairs(tests) do
    local ok, e = pcall(t.fn)
    if ok then
      passed = passed + 1
    else
      failed = failed + 1
      io.stderr:write(("FAIL  %s\n      %s\n"):format(t.name, tostring(e)))
    end
  end
  print(("%d passed, %d failed (%s)"):format(passed, failed, _VERSION))
  return failed == 0
end

-- Stubs cover only what the script touches while loading. Runtime functions
-- (http.get and friends) are never called by the unit tests.
local STUBS = {
  http = {}, json = {}, stdnse = {}, url = {},
  shortport = {http = function() return true end, ssl = function() return false end},
  string = string, table = table,
}

function H.load_engine(path)
  local engine
  local env = setmetatable({
    require = function(name)
      local m = STUBS[name]
      if not m then error("unexpected require: " .. name) end
      return m
    end,
    HHC_TEST_EXPORT = function(e) engine = e end,
  }, {__index = _G})
  local chunk, err = loadfile(path, "t", env)
  if not chunk then error(err) end
  chunk()
  assert(engine, "script did not export its engine")
  return engine
end

function H.read(path)
  local f = assert(io.open(path, "rb"))
  local s = f:read("a")
  f:close()
  return s
end

return H
