-- Minimal JSON decoder for the unit tests (objects, arrays, strings, numbers,
-- booleans, null). Test-only; the NSE script uses Nmap's json library.
local M = {}
M.null = setmetatable({}, {__tostring = function() return "null" end})

local function err(s, i, msg) error(("json: %s at byte %d near %q"):format(msg, i, s:sub(i, i + 10)), 0) end

local function skip(s, i)
  return s:find("[^ \t\r\n]", i) or #s + 1
end

local decode_value

local ESC = {['"'] = '"', ["\\"] = "\\", ["/"] = "/", b = "\b", f = "\f", n = "\n", r = "\r", t = "\t"}

local function decode_string(s, i)
  local out, j = {}, i + 1
  while true do
    local c = s:sub(j, j)
    if c == "" then err(s, j, "unterminated string") end
    if c == '"' then return table.concat(out), j + 1 end
    if c == "\\" then
      local e = s:sub(j + 1, j + 1)
      if e == "u" then
        local hex = s:sub(j + 2, j + 5)
        if not hex:match("^%x%x%x%x$") then err(s, j, "bad \\u escape") end
        out[#out + 1] = utf8.char(tonumber(hex, 16))
        j = j + 6
      elseif ESC[e] then
        out[#out + 1] = ESC[e]
        j = j + 2
      else
        err(s, j, "bad escape")
      end
    else
      out[#out + 1] = c
      j = j + 1
    end
  end
end

function decode_value(s, i)
  i = skip(s, i)
  local c = s:sub(i, i)
  if c == "{" then
    local obj = {}
    i = skip(s, i + 1)
    if s:sub(i, i) == "}" then return obj, i + 1 end
    while true do
      if s:sub(i, i) ~= '"' then err(s, i, "expected key") end
      local k
      k, i = decode_string(s, i)
      i = skip(s, i)
      if s:sub(i, i) ~= ":" then err(s, i, "expected ':'") end
      local v
      v, i = decode_value(s, i + 1)
      obj[k] = v
      i = skip(s, i)
      local d = s:sub(i, i)
      if d == "}" then return obj, i + 1 end
      if d ~= "," then err(s, i, "expected ',' or '}'") end
      i = skip(s, i + 1)
    end
  elseif c == "[" then
    local arr = {}
    i = skip(s, i + 1)
    if s:sub(i, i) == "]" then return arr, i + 1 end
    while true do
      local v
      v, i = decode_value(s, i)
      arr[#arr + 1] = v
      i = skip(s, i)
      local d = s:sub(i, i)
      if d == "]" then return arr, i + 1 end
      if d ~= "," then err(s, i, "expected ',' or ']'") end
      i = i + 1
    end
  elseif c == '"' then
    return decode_string(s, i)
  elseif s:find("^true", i) then
    return true, i + 4
  elseif s:find("^false", i) then
    return false, i + 5
  elseif s:find("^null", i) then
    return M.null, i + 4
  else
    local num = s:match("^-?%d+%.?%d*[eE]?[-+]?%d*", i)
    if not num or num == "" then err(s, i, "unexpected character") end
    return math.tointeger(tonumber(num)) or tonumber(num), i + #num
  end
end

function M.decode(s)
  local v, i = decode_value(s, 1)
  i = skip(s, i)
  if i <= #s then err(s, i, "trailing data") end
  return v
end

return M
