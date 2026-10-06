-- luacheck configuration. NSE scripts define these globals for Nmap.
std = "lua54"
max_line_length = 120

files["http-hardening-check.nse"] = {
  globals = {"description", "author", "license", "categories", "portrule", "action"},
  read_globals = {"SCRIPT_NAME"},
}

files["tests/unit"] = {
  -- The test JSON decoder and harness only use the standard library.
  std = "lua54",
}
