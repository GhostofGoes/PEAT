-- Unit tests for distribution/wireshark/selascii.lua with a plain Lua interpreter
-- (5.2, 5.3 or 5.4), outside of Wireshark:
--
--   lua5.4 tests/wireshark/selascii_unit.lua distribution/wireshark/selascii.lua
--
-- A small mock of the Wireshark Lua API lets the plugin load, so the helpers and
-- the dissector itself run on every Lua version that Wireshark builds use. The
-- mock checks argument types and tvb bounds like Wireshark does. tshark-based
-- tests are in tests/test_wireshark_dissector.py.
-- Prints "ALL OK" and exits 0 on success.

local plugin_path = assert(arg[1], "usage: selascii_unit.lua path/to/selascii.lua")

-------------------------------------------------------------------------------
-- Mock of the Wireshark Lua API
-------------------------------------------------------------------------------
local registry = { protos = {}, heuristics = {}, calls = {}, tables = {} }

local function enum(prefix)
  return setmetatable({}, { __index = function(_, k) return prefix .. "." .. k end })
end
base = enum("base")
expert = { group = enum("group"), severity = enum("severity") }
frametype = enum("frametype")
DESEGMENT_ONE_MORE_SEGMENT = 0x0fffffff
wtap_encaps = { RTAC_SERIAL = 153 }

ProtoField = setmetatable({}, {
  __index = function(_, ftype)
    return function(abbr, name) return { abbr = abbr, name = name, ftype = ftype } end
  end,
})
ProtoExpert = {
  new = function(abbr, text) return { abbr = abbr, text = text, is_expert = true } end,
}
Pref = {
  bool = function(_, default) return { default = default } end,
  uint = function(_, default) return { default = default } end,
  range = function(_, default) return { default = default } end,
}

Proto = setmetatable({}, {
  __call = function(_, name, desc)
    local values = {}
    local prefs = setmetatable({}, {
      __newindex = function(_, k, v) values[k] = v.default end,
      __index = function(_, k) return values[k] end,
    })
    local p = { name = name, description = desc, fields = {}, prefs = prefs, is_proto = true }
    function p:register_heuristic(list, fn) registry.heuristics[list] = fn end
    registry.protos[name] = p
    return p
  end,
})

local Tvb, Range = {}, {}
Tvb.__index, Range.__index = Tvb, Range
local function new_tvb(data, off, name)
  return setmetatable({ data = data, off = off or 0, name = name }, Tvb)
end
function Tvb:len() return #self.data end
function Tvb:offset() return self.off end
function Tvb:raw(o, l)
  o = o or 0
  l = l or (#self.data - o)
  return self.data:sub(o + 1, o + l)
end
Tvb.__call = function(self, o, l)
  o = o or 0
  if l == nil or l < 0 then l = #self.data - o end
  if o < 0 or l < 0 or o + l > #self.data or o ~= math.floor(o) or l ~= math.floor(l) then
    error("Range is out of bounds: " .. tostring(o) .. "+" .. tostring(l) .. " of " .. #self.data, 2)
  end
  return setmetatable({ tvb_ = self, o = o, l = l }, Range)
end
function Range:tvb() return new_tvb(self:raw(), self.tvb_.off + self.o) end
function Range:raw() return self.tvb_.data:sub(self.o + 1, self.o + self.l) end
function Range:len() return self.l end
function Range:uint()
  local v = 0
  for i = 1, self.l do v = v * 256 + self.tvb_.data:byte(self.o + i) end
  return v
end

ByteArray = {
  new = function(s, raw)
    assert(raw == true, "ByteArray.new must be called with raw=true")
    return { tvb = function(_, name) return new_tvb(s, 0, name) end }
  end,
}

local INT_MAX = { uint8 = 255, uint16 = 65535, uint32 = 4294967295, framenum = 4294967295 }

local Item = {}
Item.__index = Item
local function new_item(store) return setmetatable({ store = store }, Item) end
function Item:add(field, a, b)
  local range, value = nil, a
  if getmetatable(a) == Range then range, value = a, b end
  if field.is_proto then
    self.store[#self.store + 1] = { abbr = field.name }
    return new_item(self.store)
  end
  assert(field.abbr, "tree:add() with something that is not a ProtoField")
  if value == nil then
    assert(range, field.abbr .. ": no value and no range")
    if INT_MAX[field.ftype] then value = range:uint() else value = range:raw() end
  end
  local ftype = field.ftype
  if ftype == "string" then
    assert(type(value) == "string", field.abbr .. ": string field got " .. type(value))
  elseif INT_MAX[ftype] then
    assert(type(value) == "number", field.abbr .. ": integer field got " .. type(value))
    assert(value == math.floor(value) and value >= 0 and value <= INT_MAX[ftype],
      field.abbr .. ": bad integer " .. tostring(value))
  elseif ftype == "bool" then
    assert(type(value) == "boolean", field.abbr .. ": bool field got " .. type(value))
  end
  self.store[#self.store + 1] = { abbr = field.abbr, value = value }
  return new_item(self.store)
end
function Item:add_proto_expert_info(e, text)
  assert(e.is_expert, "add_proto_expert_info() without a ProtoExpert")
  assert(text == nil or type(text) == "string")
  self.store[#self.store + 1] = { abbr = e.abbr, value = text or e.text }
  return self
end
function Item:append_text(s) assert(type(s) == "string", "append_text() needs a string") end
function Item:set_generated() end

local function handle(name)
  return {
    name = name,
    call = function(_, tvb, pinfo, tree)
      assert(getmetatable(tvb) == Tvb and pinfo and tree)
      registry.calls[#registry.calls + 1] = { name = name, data = tvb.data }
      return tvb:len()
    end,
  }
end
Dissector = { get = function(name) return handle(name) end }
DissectorTable = {
  get = function(name)
    local t = registry.tables[name] or { entries = {} }
    registry.tables[name] = t
    function t:add(key, value) self.entries[tostring(key)] = value end
    function t:remove(key) self.entries[tostring(key)] = nil end
    function t:add_for_decode_as() end
    return t
  end,
}

-------------------------------------------------------------------------------
-- Load the plugin
-------------------------------------------------------------------------------
local chunk = assert(loadfile(plugin_path))
local T = chunk()._test
local selascii = registry.protos.selascii
assert(selascii and selascii.dissector, "the plugin did not register its dissector")
assert(registry.heuristics.tcp and registry.heuristics["usb.bulk"], "heuristics missing")
assert(registry.tables["tcp.port"].entries["23"] == selascii, "port 23 not registered")
assert(registry.tables["wtap_encap"].entries["153"] == registry.protos.selascii_rtac,
  "LINKTYPE_RTAC_SERIAL wrapper not registered")

local fails, checks = 0, 0
local function eq(got, want, msg)
  checks = checks + 1
  if got ~= want then
    fails = fails + 1
    print("FAIL " .. msg .. ": got " .. tostring(got) .. ", want " .. tostring(want))
  end
end
local function ok(cond, msg) eq(not not cond, true, msg) end

-------------------------------------------------------------------------------
-- Compressed ASCII checksums. Vectors are the SEL-700G ID output in
-- docs/sel.rst; the others are synthetic and computed independently.
-------------------------------------------------------------------------------
local vectors = {
  { '"FID=SEL-700G-R200-V0-Z006003-D20180629","08F0"', 0x08F0 },
  { '"BFID=BOOTLDR-R501-V0-Z000000-D20140224","0947"', 0x0947 },
  { '"CID=59A0","025C"', 0x025C },
  { '"PARTNO=0700G12B1B1B7281A230","06C2"', 0x06C2 },
  { '"SEL DISPLAY PACKAGE=1.0.50700.2000","087C"', 0x087C },
  { '"iedName=","0360"', 0x0360 },
  { '"RID","SID","FID","03e2"', 0x03E2 }, -- lowercase hex
  { '  "RID","SID","FID","03E2"  ', 0x03E2 }, -- surrounding blanks are not summed
}
for _, v in ipairs(vectors) do
  local _, ck, calc = T.parse_cascii(v[1])
  eq(ck, v[2], "checksum field of " .. v[1])
  eq(calc, v[2], "calculated checksum of " .. v[1])
end
local fields, ck, calc = T.parse_cascii('7,26,1995,15,38,39,947,"048C"')
eq(#fields, 7, "unquoted field count")
eq(fields[3], "1995", "unquoted field")
eq(calc, 0x048C, "unquoted record checksum")
fields = T.parse_cascii('-8,,"....... ........"," ....","0000"')
eq(fields[2], "", "empty field")
eq(fields[3], "....... ........", "quoted field with a space")
eq(fields[4], " ....", "quoted field keeps leading blank")
fields = T.parse_cascii('"SID : "Station A"","0000"')
eq(fields[1], 'SID : "Station A"', "quoted field with unescaped quotes")
fields, ck = T.parse_cascii("SELF TESTS OK")
eq(ck, nil, "plain line has no checksum")
eq(T.sum16(string.rep("\255", 300)), (255 * 300) % 65536, "16-bit wrap")

-- Records spanning lines while a quoted field is open
local lines = T.parse_message('\2\r\n"SETTINGS",' .. '"x\r\nGroup 1\r\n",' .. '"0000"\r\n\3').lines
local items = T.group_records(lines)
eq(#items, 1, "multi-line record is one item")
ok(items[1].multiline and items[1].ck == 0, "multi-line record checksum parsed")
local body = '"A","b\r\nc",'
local good = string.format('%s"%04X"', body, T.sum16(body))
items = T.group_records(T.parse_message("\2\r\n" .. good .. "\r\n\3").lines)
eq(items[1].ck, items[1].calc, "multi-line checksum includes CRLF")
items = T.group_records(T.parse_message('\2\r\n"open\r\nnever closed\r\n\3').lines)
eq(#items, 2, "unclosed quote falls back to plain lines")

-------------------------------------------------------------------------------
-- Telnet IAC removal and offset mapping
-------------------------------------------------------------------------------
local raw = "\255\251\1\255\253\3AB\255\255C\255\250\24\0VT100\255\240D"
local clean, map, cmds, incomplete = T.telnet_clean(raw)
eq(clean, "AB\255CD", "IAC removed")
eq(#cmds, 3, "IAC command count")
eq(incomplete, nil, "IAC complete")
eq(T.clean_to_raw(map, 1), 7, "map first data byte")
eq(T.clean_to_raw(map, 3), 9, "map escaped 0xFF")
eq(T.clean_end_to_raw(map, raw, 3), 10, "escaped 0xFF spans two raw bytes")
eq(T.clean_to_raw(map, 4), 11, "map after escape")
eq(T.clean_to_raw(map, 5), #raw, "map after subnegotiation")
clean, map, cmds, incomplete = T.telnet_clean("AB\255")
eq(clean, "AB", "trailing IAC removed")
eq(incomplete, 3, "trailing IAC is incomplete")
clean, map, cmds, incomplete = T.telnet_clean("AB\255\250\24\0")
eq(incomplete, 3, "open subnegotiation is incomplete")
clean, map, cmds, incomplete = T.telnet_clean("AB\255\250\24CD", true)
eq(clean, "ABCD", "unterminated subnegotiation removed on request")
eq(incomplete, nil, "unterminated subnegotiation is not incomplete on request")
ok(cmds[1][2] == 3 and cmds[1][3], "unterminated subnegotiation marked")
clean, map, cmds = T.telnet_clean("AB\255\250", true)
eq(clean, "AB", "IAC SB at the end")
eq(cmds[1][2], 2, "IAC SB at the end is two bytes")
clean, map = T.telnet_clean("plain")
eq(map, nil, "no map without IAC")

-------------------------------------------------------------------------------
-- Message boundaries
-------------------------------------------------------------------------------
local REQ, RESP = 0, 1
local function pe(data, dir, s) return T.find_pdu_end(data, s or 1, dir) end
eq(pe("ID\r\nSTA\r\n", REQ), 4, "request ends at CRLF")
eq(pe("ID\r\nSTA\r\n", REQ, 5), 9, "second request")
eq(pe("ID\r\0X", REQ), 4, "CR NUL ends a request")
eq(pe("ID\r", REQ), 3, "bare CR ends a request")
eq(pe("I", REQ), nil, "typing waits")
eq(pe("C\6", REQ), 1, "text before a control byte")
eq(select(2, pe("\6", REQ)), "control", "ACK is transfer control")
eq(select(2, pe("\19abc", RESP)), "flow", "XOFF is flow control")
eq(pe("\165\192ID\r\n", REQ), 2, "bare Fast Meter request is 2 bytes")
eq(pe("\165\192\36" .. string.rep("x", 10), RESP), nil, "Fast response waits for its length")
eq(pe("\165\192\5abcXYZ", RESP), 5, "Fast response length byte")
eq(pe("\165\99", RESP), 1, "unknown 0xA5 byte is binary")
eq(pe("ID\r\n\2\r\nFID", RESP), nil, "response waits for ETX")
eq(pe("ID\r\n\2x\3\2\r\n=>\3", RESP), 7, "response ends at the first ETX")
eq(select(2, pe("ID\r\n\2x\3", RESP)), "message", "echo and message together")
eq(pe("C", RESP), 1, "echoed character")
eq(pe("x\3", RESP), 2, "ETX without STX")
eq(pe("\2", RESP), nil, "lone STX waits")
local block1 = "\2\1\254" .. string.rep("\3", 1024) .. "\0\0"
eq(pe(block1 .. "\2\r\n=>\3", RESP), 1029, "YMODEM 1K block is not cut at ETX")
eq(pe(block1:sub(1, 500), RESP), nil, "partial YMODEM block waits")
eq(pe("\1\0\255" .. string.rep("\0", 130), REQ), 133, "YMODEM 128-byte block")
eq(pe("\1", REQ), nil, "SOH waits for the block header")
eq(select(2, pe("\128\129\2\r\n=\3", RESP)), "binary", "binary data")
eq(pe("\128\129\2\r\n=\3", RESP), 2, "binary stops at STX")

-------------------------------------------------------------------------------
-- Prompts, commands and passwords
-------------------------------------------------------------------------------
local prompts = { ["="] = "0", ["=>"] = "1", ["==>"] = "B", ["=>>"] = "2", ["==>>"] = "C",
  ["P=>"] = "P", ["A=>"] = "A", ["O=>"] = "O", ["*>>"] = "2", ["!>"] = "SELBOOT" }
for p, level in pairs(prompts) do eq(T.prompt_level(p, true), level, "prompt " .. p) end
eq(T.prompt_level("=", false), nil, "unframed '=' is not a prompt")
eq(T.prompt_level("=>", false), "1", "unframed '=>' is a prompt")
ok(T.is_password_prompt("Password: ?"), "password prompt")
ok(T.is_password_prompt("Old Password:"), "PAS old password prompt")
ok(not T.is_password_prompt("Invalid Password"), "error is not a password prompt")
eq(T.request_line("ACX\8C\r\n"), "ACC", "backspace editing")
eq(T.find_error("Invalid Access Level"), "Invalid Access Level", "device error")
eq(T.find_error("Invalid Group Number"), "Invalid Group Number", "other Invalid error")

local C = T.CAT
local cases = {
  { "ACC", "ACC", C.ACCESS }, { "access", "ACC", C.ACCESS }, { "2AC", "2AC", C.ACCESS },
  { "id", "ID", C.READ }, { "STA", "STA", C.READ }, { "sta c", "STA", C.MAINT },
  { "SER 100", "SER", C.READ }, { "SER C", "SER", C.MAINT }, { "MET RMS", "MET", C.READ },
  { "MET RD", "MET", C.MAINT }, { "GRO", "GRO", C.READ }, { "GRO 2", "GRO", C.SETTINGS },
  { "DAT", "DAT", C.READ }, { "DAT 1/2/2026", "DAT", C.SETTINGS },
  { "FIL DIR", "FIL", C.READ }, { "fil read SET_1.TXT", "FIL", C.READ },
  { "FIL WRITE SET_1.TXT", "FIL", C.SETTINGS }, { "PUL OUT101", "PUL", C.CONTROL },
  { "OPEN", "OPE", C.CONTROL }, { "SET P 1", "SET", C.SETTINGS }, { "L_D", "L_D", C.FIRMWARE },
  { "XYZ", "XYZ", nil },
}
for _, c in ipairs(cases) do
  local mnem, _, _, cat = T.classify(c[1])
  eq(mnem, c[2], "mnemonic of " .. c[1])
  eq(cat, c[3], "category of " .. c[1])
end
ok(T.is_interactive("ACC", C.ACCESS), "ACC asks for a password")
ok(not T.is_interactive("QUI", C.ACCESS), "QUI is not interactive")
ok(not T.is_interactive("SHO", C.READ), "read commands are not interactive")
ok(T.is_factory_password("1", "OTTER"), "OTTER is the level 1 default")
ok(not T.is_factory_password("1", "otter"), "passwords are case-sensitive")
ok(not T.is_factory_password("1", "TAIL"), "TAIL is not the level 1 default")
ok(T.is_factory_password("C", "Sel-1"), "400-series level C default")
ok(T.is_factory_password(nil, "TAIL"), "any level")

local blk, size, name, fsize = T.ymodem_info("\1\0\255SET_1.TXT\0" .. "200 0\0" .. string.rep("\0", 112) .. "\0\0")
eq(blk, 0, "YMODEM block number")
eq(size, 128, "YMODEM block size")
eq(name, "SET_1.TXT", "YMODEM file name")
eq(fsize, "200", "YMODEM file size")

ok(T.looks_like_sel("\2\r\n=>\3"), "heuristic: prompt")
ok(T.looks_like_sel('"CID=59A0","025C"\r\n'), "heuristic: valid record")
ok(not T.looks_like_sel('"CID=59A0","0000"\r\n'), "heuristic: invalid record")
ok(T.looks_like_sel("ID\r\n"), "heuristic: ID command")
ok(T.looks_like_sel("SET P 1\r\n"), "heuristic: command with arguments")
ok(not T.looks_like_sel("acc\r\n"), "heuristic: lowercase command is not enough")
ok(not T.looks_like_sel("set k 0 0 5\r\n"), "heuristic: memcached set")
ok(not T.looks_like_sel("id\r\n"), "heuristic: shell id")
ok(not T.looks_like_sel("QUIT\r\n"), "heuristic: FTP QUIT")
ok(not T.looks_like_sel("PASS secret\r\n"), "heuristic: FTP PASS")
ok(not T.looks_like_sel("GET / HTTP/1.1\r\n"), "heuristic: HTTP")
ok(not T.looks_like_sel("\2" .. "1H|\\^&\r\3"), "heuristic: ASTM frame")
local ports = T.parse_ports("2300, 4000-4002")
ok(ports[2300] and ports[4001] and not ports[4003], "port range preference")

-------------------------------------------------------------------------------
-- Dissector with the mock API: a Telnet session over emulated TCP reassembly
-------------------------------------------------------------------------------
local function new_pinfo(t)
  return {
    number = t.number, visited = t.visited, port_type = t.port_type or 0,
    src = t.src or "10.0.0.1", dst = t.dst or "10.0.0.2",
    src_port = t.src_port or 0, dst_port = t.dst_port or 0,
    p2p_dir = t.p2p_dir or -1, can_desegment = t.can_desegment or 0,
    desegment_len = 0, desegment_offset = 0, match_uint = 0, cols = {},
  }
end

local function values(store, abbr)
  local out = {}
  for _, rec in ipairs(store) do
    if rec.abbr == abbr then out[#out + 1] = tostring(rec.value) end
  end
  return table.concat(out, ";")
end

-- segments: list of {to_device, data}. Returns frames[pass][i] = tree records.
-- With entry "heuristic" the first segments go to the TCP heuristic; once it
-- claims the stream, the conversation dissector gets the rest (as in Wireshark).
-- Like TCP on later passes, the second pass hands each frame only the bytes
-- that the first pass consumed (and skips frames whose bytes were all deferred).
-- Like TCP, a request for more data at an offset inside the bytes of earlier
-- segments extends the reassembly: the frame's results are not kept.
local function run_tcp(segments, sport, entry)
  selascii.init()
  local frames, first = {}, {}
  local conversation = false
  for pass = 1, 2 do
    frames[pass] = {}
    local buf = { [true] = "", [false] = "" }
    for i, seg in ipairs(segments) do
      local c2s, data, off = seg[1], buf[seg[1]] .. seg[2], (#buf[seg[1]] > 0) and 0 or 54
      if pass == 2 then data, off = first[i].data:sub(1, first[i].consumed), first[i].off end
      local store = {}
      if #data > 0 then
        local pinfo = new_pinfo({
          number = i, visited = pass == 2, port_type = 2, can_desegment = 1,
          src = c2s and "10.0.0.1" or "10.0.0.2", dst = c2s and "10.0.0.2" or "10.0.0.1",
          src_port = c2s and 50000 or sport, dst_port = c2s and sport or 50000,
        })
        local tvb = new_tvb(data, off)
        if entry == "heuristic" then
          local used = conversation and selascii.dissector(tvb, pinfo, new_item(store)) or 0
          if used == 0 then
            store = {}
            if registry.heuristics.tcp(tvb, pinfo, new_item(store)) then conversation = true end
          end
        else
          selascii.dissector(tvb, pinfo, new_item(store))
        end
        if pass == 1 then
          local consumed = (pinfo.desegment_len > 0) and pinfo.desegment_offset or #data
          local old = #buf[c2s]
          if consumed < #data and old > 0 and consumed <= old then consumed = 0 end
          first[i] = { data = data, off = off, consumed = consumed }
          buf[c2s] = data:sub(consumed + 1)
        end
      end
      frames[pass][i] = store
    end
  end
  return frames
end

local function has_proto(store)
  for _, rec in ipairs(store) do
    if rec.abbr == "selascii" then return true end
  end
  return false
end

local function cascii(body) return string.format('%s"%04X"', body, T.sum16(body)) end
local id_lines = table.concat({
  '"FID=SEL-700G-R200-V0-Z006003-D20180629","08F0"', '"CID=59A0","025C"',
  '"iedName=SEL_700G_1",' .. string.format('"%04X"', T.sum16('"iedName=SEL_700G_1",')),
}, "\r\n")
local session = {
  { false, "\255\251\1\255\251\3" },
  { true, "\255\253\1\255\253\3" },
  { false, "\2\r\n=\3" },
  { true, "ID\r\n" },
  { false, "ID\r\n\2\r\n" .. id_lines:sub(1, 20) },
  { false, id_lines:sub(21) .. "\r\n\3\2\r\n=\3" },
  { true, "ACC\r\n" },
  { false, "ACC\r\n\2\r\nPassword: ?\3" },
  { true, "OTTER\r\n" },
  { false, "\r\n\2\r\nLevel 1\r\n=>\3" },
  { true, "C" }, { false, "C" }, { true, "AS\r\n" },
  { false, "AS\r\n\2\r\n" .. cascii('"CAS",1,') .. "\r\n" .. '"1H","FID","0000"' .. "\r\n\3\2\r\n=>\3" },
  { true, "PUL OUT101\r\n" },
  { false, "PUL OUT101\r\n\2\r\nPulse OUT101 (Y,N)?\3" },
  { true, "N\r\n" },
  { false, "\r\n\2\r\n=>\3" },
  { true, "\165\192" },
  { false, "\165\192\6\255\255\0\1" },
  { true, "QUI\r\n" },
  { false, "QUI\r\n\2\r\n=\3" },
}
local frames = run_tcp(session, 23)
for pass = 1, 2 do
  local fr = frames[pass]
  local p = " (pass " .. pass .. ")"
  eq(values(fr[3], "selascii.access_level"), "0", "level 0 prompt" .. p)
  eq(values(fr[4], "selascii.cmd"), "ID", "ID command" .. p)
  eq(values(fr[5], "selascii.cmd"), "", "first ID segment waits" .. p)
  eq(values(fr[6], "selascii.id.fid"), "SEL-700G-R200-V0-Z006003-D20180629", "FID" .. p)
  eq(values(fr[6], "selascii.id.iedname"), "SEL_700G_1", "iedName" .. p)
  eq(values(fr[6], "selascii.cascii.checksum.status"), "1;1;1", "ID checksums" .. p)
  eq(values(fr[6], "selascii.response_to"), "ID;ID", "ID pairing" .. p)
  eq(values(fr[8], "selascii.type"), "Password prompt", "password prompt" .. p)
  eq(values(fr[9], "selascii.password"), "*****", "password masked" .. p)
  ok(values(fr[9], "selascii.password.factory_default") ~= "", "factory default" .. p)
  ok(values(fr[10], "selascii.access_level.changed") ~= "", "level change" .. p)
  eq(values(fr[13], "selascii.cmd"), "CAS", "typed command" .. p)
  eq(values(fr[14], "selascii.cascii.checksum.status"), "1;0", "CAS checksums" .. p)
  ok(values(fr[14], "selascii.cascii.bad_checksum") ~= "", "bad checksum expert" .. p)
  eq(values(fr[15], "selascii.cmd.category"), C.CONTROL, "control command" .. p)
  ok(values(fr[15], "selascii.cmd.operates_equipment") ~= "", "control expert" .. p)
  eq(values(fr[16], "selascii.question"), "Pulse OUT101 (Y,N)?", "question" .. p)
  eq(values(fr[17], "selascii.input"), "N", "answer" .. p)
  eq(values(fr[17], "selascii.response_to"), "PUL OUT101", "answer pairing" .. p)
  eq(values(fr[19], "selascii.fast.type"), tostring(0xA5C0), "Fast request" .. p)
  eq(values(fr[20], "selascii.fast.type"), tostring(0xA5C0), "Fast response" .. p)
  eq(values(fr[21], "selascii.cmd"), "QUI", "command after Fast frames" .. p)
  eq(values(fr[22], "selascii.access_level"), "0", "back to level 0" .. p)
end
-- selfm gets the on-the-wire bytes of the Fast response (0xFF still escaped)
local got_fast = false
for _, c in ipairs(registry.calls) do
  if c.name == "selfm" and c.data == "\165\192\6\255\255\0\1" then got_fast = true end
end
ok(got_fast, "selfm called with the escaped frame")

-- The same session over a raw tunnel: found by the heuristic, no Telnet
local tunnel = {}
for i = 3, #session do
  if i ~= 19 and i ~= 20 then tunnel[#tunnel + 1] = session[i] end
end
frames = run_tcp(tunnel, 2300, "heuristic")
eq(values(frames[2][2], "selascii.cmd"), "ID", "heuristic stream")
eq(values(frames[2][7], "selascii.password"), "*****", "heuristic stream password")

-- Segments that end a message and start the next one. The second pass gets
-- shorter reassembled data than the first, and must find the same results.
local id_resp = "ID\r\n\2\r\n" .. id_lines .. "\r\n\3\2\r\n=\3"
local cut = #("ID\r\n\2\r\n" .. id_lines .. "\r\n\3") + 3
local split = {
  { false, "\2\r\n=\3" },
  { true, "ID\r\n" },
  { false, id_resp:sub(1, 30) },
  { false, id_resp:sub(31, cut) }, -- end of the ID message and start of the prompt
  { false, id_resp:sub(cut + 1) },
  { true, "ACC\r\n" },
  { false, "ACC\r\n\2\r\nPassword: ?\3" },
  { true, "OT" },
  { true, "TER\r\nQ" }, -- end of the password and start of the next command
  { true, "UI\r\n" },
  { false, "\r\n\2\r\nLevel 1\r\n=>\3" },
  { false, "QUI\r\n\2\r\n=\3" },
}
frames = run_tcp(split, 23)
for pass = 1, 2 do
  local fr = frames[pass]
  local p = " (split, pass " .. pass .. ")"
  eq(values(fr[4], "selascii.response_to"), "ID", "ID response pairing" .. p)
  eq(values(fr[4], "selascii.id.fid"), "SEL-700G-R200-V0-Z006003-D20180629", "ID response" .. p)
  eq(values(fr[5], "selascii.response_to"), "ID", "prompt pairing" .. p)
  eq(values(fr[9], "selascii.password"), "*****", "split password" .. p)
  eq(values(fr[9], "selascii.command"), "", "split password is not a command" .. p)
  ok(values(fr[9], "selascii.password.cleartext") ~= "", "cleartext expert" .. p)
  eq(values(fr[10], "selascii.cmd"), "QUI", "one password per prompt" .. p)
  eq(values(fr[11], "selascii.response_to"), "ACC", "level prompt pairing" .. p)
  eq(values(fr[12], "selascii.response_to"), "QUI", "QUI pairing" .. p)
  eq(values(fr[12], "selascii.access_level"), "0", "QUI level" .. p)
end
-- Should a later pass ever get a frame cut differently, the first-pass note of
-- the same line is used, and a frame that carried a password never shows it as
-- a command
local function later_pass(data, off)
  local store = {}
  selascii.dissector(new_tvb(data, off), new_pinfo({ number = 9, visited = true, port_type = 2,
    can_desegment = 1, src_port = 50000, dst_port = 23 }), new_item(store))
  return store
end
eq(values(later_pass("OTTER\r\n", 7), "selascii.password"), "*****", "fallback by line")
eq(values(later_pass("TTER\r\n", 8), "selascii.command"), "", "fallback masks the password")
eq(values(later_pass("TTER\r\n", 8), "selascii.password"), "****", "fallback password")

-- Passwords typed ahead of their prompts: for an access command that is not the
-- oldest pending command, for PAS (old, new and confirmed password), and a second
-- guess for an access command. A command typed ahead stays a command.
frames = run_tcp({
  { false, "\2\r\n=\3" },
  { true, "ACC\r\nOTTER\r\n2AC\r\nTAIL\r\n" },
  { false, "ACC\r\n\2\r\nPassword: ?\3" },
  { false, "\r\n\2\r\nLevel 1\r\n=>\3" },
  { false, "2AC\r\n\2\r\nPassword: ?\3" },
  { false, "\r\n\2\r\nLevel 2\r\n=>>\3" },
  { true, "PAS 1\r\n" },
  { false, "PAS 1\r\n\2\r\nOld Password: ?\3" },
  { true, "OTTER\r\nID\r\nID\r\n" },
  { false, "\r\n\2\r\nNew Password: ?\3" },
  { false, "\r\n\2\r\nConfirm New Password: ?\3" },
  { false, "\r\n\2\r\nPassword Changed\r\n=>>\3" },
  { true, "QUI\r\nACC\r\notter\r\nOTTER\r\nSHO\r\n" },
  { false, "QUI\r\n\2\r\n=\3ACC\r\n\2\r\nPassword: ?\3" },
  { false, "\r\n\2\r\nPassword: ?\3" },
  { false, "\r\n\2\r\nLevel 1\r\n=>\3" },
  { false, "SHO\r\n\2\r\nGroup 1\r\n=>\3" },
}, 23)
for pass = 1, 2 do
  local fr = frames[pass]
  local p = " (typed ahead, pass " .. pass .. ")"
  eq(values(fr[2], "selascii.command"), "ACC;2AC", "pipelined access commands" .. p)
  eq(values(fr[2], "selascii.password"), "*****;****", "pipelined passwords masked" .. p)
  eq(values(fr[2], "selascii.response_to"), "ACC;2AC", "pipelined password pairing" .. p)
  eq(values(fr[2], "selascii.password.factory_default"),
    "Factory-default password;Factory-default password", "pipelined defaults" .. p)
  eq(values(fr[6], "selascii.response_to"), "2AC", "2AC level prompt pairing" .. p)
  eq(values(fr[9], "selascii.password"), "*****;**;**", "PAS passwords masked" .. p)
  eq(values(fr[9], "selascii.command"), "", "PAS passwords are not commands" .. p)
  eq(values(fr[12], "selascii.response_to"), "PAS 1", "PAS level prompt pairing" .. p)
  eq(values(fr[13], "selascii.command"), "QUI;ACC;SHO", "commands around a retry" .. p)
  eq(values(fr[13], "selascii.password"), "*****;*****", "typed-ahead retry masked" .. p)
  eq(values(fr[17], "selascii.response_to"), "SHO", "SHO pairing after the retry" .. p)
end

-- A message that ends at the end of deferred data, followed by the start of a
-- message that needs more data: decoded once, in the frame that completes both
frames = run_tcp({
  { false, "\2\r\n=>\3" }, { true, "C" }, { true, "\165" }, { true, "\192" },
}, 23)
for pass = 1, 2 do
  local seen_c = {}
  for i = 1, 4 do
    if values(frames[pass][i], "selascii.command") == "C" then seen_c[#seen_c + 1] = i end
  end
  eq(table.concat(seen_c, ","), "4", "message before a deferred one decoded once " .. pass)
  eq(values(frames[pass][4], "selascii.fast.type"), tostring(0xA5C0), "Fast request " .. pass)
end

-- A stray IAC SB (no IAC SE) is waited for one segment, then shown as unterminated
local stray = {
  { false, "\2\r\n=>\3\255\250\24" },
  { true, "ID\r\n" },
  { false, id_resp },
  { true, "ID\r\n" },
  { false, id_resp },
}
frames = run_tcp(stray, 23)
for pass = 1, 2 do
  local fr = frames[pass]
  local p = " (stray IAC SB, pass " .. pass .. ")"
  eq(values(fr[1], "selascii.access_level"), "1", "prompt before IAC SB" .. p)
  ok(values(fr[3], "selascii.telnet_sb_unterminated") ~= "", "unterminated subnegotiation" .. p)
  eq(values(fr[3], "selascii.id.fid"), "SEL-700G-R200-V0-Z006003-D20180629", "after IAC SB" .. p)
  eq(values(fr[5], "selascii.id.fid"), "SEL-700G-R200-V0-Z006003-D20180629", "later frames" .. p)
end
-- A subnegotiation split over two segments is still reassembled
frames = run_tcp({
  { false, "\2\r\n=\3" }, { false, "\255\250\24\0VT" }, { false, "100\255\240\2\r\n=>\3" },
}, 23)
for pass = 1, 2 do
  eq(values(frames[pass][3], "selascii.access_level"), "1", "split subnegotiation " .. pass)
  eq(values(frames[pass][3], "selascii.telnet_sb_unterminated"), "",
    "complete subnegotiation " .. pass)
  eq(values(frames[pass][3], "selascii.line_count"), "", "subnegotiation removed " .. pass)
end

-- Other Telnet sessions on port 23 stay with the Telnet dissector
registry.calls = {}
local other = {
  { false, "\255\253\24\255\253\32" }, { true, "\255\251\24" },
  { false, "Ubuntu 24.04 LTS\r\nhost login: " }, { true, "admin\r\n" },
  { false, "admin\r\nPassword: " }, { true, "hunter2\r\n" },
  { false, "\r\nWelcome\r\n$ " }, { true, "id\r\n" }, { false, "id\r\nuid=1000\r\n$ " },
  { true, "set\r\n" },
}
frames = run_tcp(other, 23)
local decoded = false
for pass = 1, 2 do
  for i = 1, #other do decoded = decoded or has_proto(frames[pass][i]) end
end
ok(not decoded, "non-SEL Telnet session is not decoded")
eq(#registry.calls, 2 * #other, "non-SEL Telnet session goes to the Telnet dissector")
frames = run_tcp(other, 4000, "heuristic")
decoded = false
for i = 1, #other do decoded = decoded or has_proto(frames[2][i]) end
ok(not decoded, "non-SEL text session is not claimed by the heuristic")

-------------------------------------------------------------------------------
-- Non-TCP link (exported PDU direction) with reassembly across records
-------------------------------------------------------------------------------
local function run_stream(records, opts)
  selascii.init()
  local out = {}
  for pass = 1, 2 do
    out[pass] = {}
    for i, rec in ipairs(records) do
      local pinfo = new_pinfo({ number = i, visited = pass == 2, p2p_dir = rec[1] })
      local store = {}
      selascii.dissector(new_tvb(rec[2], 16), pinfo, new_item(store))
      out[pass][i] = store
    end
  end
  return out
end
local resp = "ID\r\n\2\r\n" .. id_lines .. "\r\n\3\2\r\n=>\3"
frames = run_stream({ { 0, "I" }, { 0, "D\r\n" }, { 1, resp:sub(1, 30) }, { 1, resp:sub(31) } })
for pass = 1, 2 do
  eq(values(frames[pass][2], "selascii.cmd"), "ID", "stream command" .. pass)
  -- Only the second pass knows where a fragment ends up
  eq(values(frames[pass][1], "selascii.reassembled_in"), (pass == 2) and "2" or "",
    "stream fragment" .. pass)
  eq(values(frames[pass][4], "selascii.id.fid"), "SEL-700G-R200-V0-Z006003-D20180629",
    "stream response" .. pass)
end

-------------------------------------------------------------------------------
-- Robustness: random input must never raise an error and must make progress
-------------------------------------------------------------------------------
math.randomseed(53)
local alphabet = { "\2", "\3", "\r", "\n", "\255", "\165", "\1", "\6", "\17", "\19", "=>", "\"",
  ",", "ID", "ACC", "Password: ?", "\250", "\240", "\251", "\192", "\0", "?", "A", "0" }
local function random_bytes(n)
  local t = {}
  for i = 1, n do
    if math.random() < 0.5 then
      t[i] = alphabet[math.random(#alphabet)]
    else
      t[i] = string.char(math.random(0, 255))
    end
  end
  return table.concat(t)
end
for _ = 1, 300 do
  local data = random_bytes(math.random(1, 60))
  for _, dir in ipairs({ REQ, RESP }) do
    local pos = 1
    while pos <= #data do
      local e = T.find_pdu_end(data, pos, dir)
      if not e then break end
      assert(e >= pos, "find_pdu_end went backwards")
      pos = e + 1
    end
  end
  T.telnet_clean(data)
  T.group_records(T.parse_message(data).lines)
  T.looks_like_sel(data)
end
local fuzz_ok, fuzz_err = pcall(function()
  for round = 1, 40 do
    local segs, recs = {}, {}
    for i = 1, 12 do
      local d = random_bytes(math.random(1, 40))
      segs[i] = { math.random() < 0.5, d }
      recs[i] = { math.random(0, 1) - ((round % 3 == 0) and 1 or 0), d }
    end
    run_tcp(segs, 23)
    run_tcp(segs, 2300, "heuristic")
    run_stream(recs)
  end
end)
ok(fuzz_ok, "random segments through the dissector: " .. tostring(fuzz_err))

print(string.format("%s: %d checks, %d failures", _VERSION, checks, fails))
if fails == 0 then print("ALL OK") end
os.exit(fails == 0 and 0 or 1)
