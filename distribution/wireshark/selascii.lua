--[[
selascii.lua: Wireshark dissector for SEL ASCII and SEL Compressed ASCII

Decodes the text command interface of Schweitzer Engineering Laboratories (SEL)
protection relays, RTACs and communications processors: the commands sent to the
device, its framed responses (STX ... ETX) as a list of lines, access level
prompts, passwords (masked), Compressed ASCII records and their checksums, and the
ID command output. SEL Fast binary messages (0xA5 ...) in the same stream are
handed to Wireshark's built-in "selfm" dissector, and YMODEM file transfer blocks
(FILE READ / FILE WRITE) are recognized so they do not break the text framing.

Transports: Telnet (TCP port 23), raw TCP (heuristic, Decode As or the "TCP ports"
preference), RTAC Communication Monitor captures (LINKTYPE_RTAC_SERIAL, 250),
exported PDUs (LINKTYPE_WIRESHARK_UPPER_PDU, 252), USB serial ports (usbmon and
USBPcap captures) and user DLTs (DLT_USER). README.md next to this file has the
installation steps and capture recipes.

Written for Wireshark 4.2 (Lua 5.2) through 4.6 (Lua 5.4); PEAT's CI runs the
tests with both. The code avoids Lua 5.3+ operators so that one file works with
every Lua version that Wireshark builds use.

This file is part of PEAT (https://github.com/sandialabs/PEAT).
Copyright 2026 National Technology & Engineering Solutions of Sandia, LLC (NTESS).
Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains
certain rights in this software.
SPDX-License-Identifier: GPL-3.0-only
--]]

local PLUGIN_VERSION = "1.0.0"

if set_plugin_info then
  set_plugin_info({
    version = PLUGIN_VERSION,
    description = "SEL ASCII and SEL Compressed ASCII",
    repository = "https://github.com/sandialabs/PEAT/tree/main/distribution/wireshark",
  })
end

local selascii = Proto("selascii", "SEL ASCII")

-------------------------------------------------------------------------------
-- Protocol constants
-------------------------------------------------------------------------------
local SOH, STX, ETX, EOT, ACK = 0x01, 0x02, 0x03, 0x04, 0x06
local LF, CR, NAK = 0x0A, 0x0D, 0x15
local XON, XOFF, CAN = 0x11, 0x13, 0x18
local FAST_SYNC = 0xA5
local IAC, SB, SE, WILL, DONT = 0xFF, 0xFA, 0xF0, 0xFB, 0xFE

local DIR_REQUEST, DIR_RESPONSE = 0, 1
local PT_TCP, PT_USB = 2, 8 -- pinfo.port_type values (epan/address.h port_type)

-- Bytes that can appear in typed text: printable ASCII, TAB, CR, LF, BS, DEL and
-- NUL (Telnet sends CR NUL for a bare carriage return).
local NOT_REQUEST_TEXT = "[^\32-\126\t\r\n\8\127\0]"
-- Device text output may also carry XON/XOFF flow control bytes.
local NOT_RESPONSE_TEXT = "[^\32-\126\t\r\n\8\127\0\17\19]"
-- Anything that is neither text nor STX/ETX framing.
local NOT_SEL_TEXT = "[^\32-\126\t\r\n\8\127\0\2\3\17\19]"

-- Joining physical lines of a Compressed ASCII record whose quoted field spans
-- several lines (for example the SETTINGS block of a CEV report) stops here.
local MAX_RECORD_LINES = 500
-- Commands kept waiting for their prompt (bounds memory on odd streams).
local MAX_PENDING = 16
-- A Telnet subnegotiation (IAC SB) without IAC SE is waited for over one more
-- segment at most, and not at all once it is this long. After that it counts
-- as unterminated, so a stray IAC SB cannot hide the rest of the session.
local MAX_TELNET_SB = 1024

-- Access level prompts. The SEL-400 series adds P, A and O, the SEL-2030/2032
-- communications processors use '*' prompts, and '!>' is the SELBOOT loader.
local PROMPT_LEVEL = {
  ["="] = "0", ["=>"] = "1", ["==>"] = "B", ["=>>"] = "2", ["==>>"] = "C",
  ["P=>"] = "P", ["A=>"] = "A", ["O=>"] = "O",
  ["*"] = "0", ["*>"] = "1", ["*>>"] = "2",
  ["!>"] = "SELBOOT",
}
-- Prompts that are too short to trust when they arrive without STX/ETX framing.
local AMBIGUOUS_PROMPT = { ["="] = true, ["*"] = true }

local CAT_ACCESS = "Access level"
local CAT_READ = "Read"
local CAT_CONTROL = "Control (operates equipment)"
local CAT_SETTINGS = "Settings change"
local CAT_MAINT = "Maintenance (resets, clears or restarts)"
local CAT_FIRMWARE = "Firmware"

-- SEL relays accept commands shortened to their first three characters, so the
-- table is keyed by that mnemonic. Descriptions are short labels in PEAT's own
-- words; availability and the required access level vary by model.
local COMMANDS = {
  ACC = { "Go to access level 1", CAT_ACCESS },
  BAC = { "Go to access level B (breaker)", CAT_ACCESS },
  PAC = { "Go to access level P (protection)", CAT_ACCESS },
  AAC = { "Go to access level A (automation)", CAT_ACCESS },
  OAC = { "Go to access level O (output)", CAT_ACCESS },
  ["2AC"] = { "Go to access level 2", CAT_ACCESS },
  CAL = { "Go to access level C (calibration)", CAT_ACCESS },
  QUI = { "Return to access level 0", CAT_ACCESS },
  EXI = { "End the session", CAT_ACCESS },

  ID = { "Device identification", CAT_READ },
  VER = { "Firmware and hardware version", CAT_READ },
  STA = { "Self-test status", CAT_READ },
  TAR = { "Relay Word bits and front-panel targets", CAT_READ },
  MET = { "Metering", CAT_READ },
  EVE = { "Event report", CAT_READ },
  HIS = { "Event history", CAT_READ },
  SER = { "Sequential Events Recorder", CAT_READ },
  SUM = { "Event summary", CAT_READ },
  SHO = { "Show settings", CAT_READ },
  DAT = { "Date", CAT_READ },
  TIM = { "Time", CAT_READ },
  ETH = { "Ethernet port status", CAT_READ },
  MAC = { "MAC addresses", CAT_READ },
  GRO = { "Active settings group", CAT_READ },
  BRE = { "Breaker monitor", CAT_READ },
  COM = { "Communication channel statistics", CAT_READ },
  GOO = { "IEC 61850 GOOSE status", CAT_READ },
  PIN = { "Ping a network host", CAT_READ },
  LDP = { "Load profile report", CAT_READ },
  SSI = { "Sag, swell and interruption report", CAT_READ },
  FIL = { "File commands (DIR, SHOW, READ, WRITE)", CAT_READ },
  HEL = { "Help", CAT_READ }, -- codespell:ignore
  POR = { "Connect to another port (transparent mode)", CAT_READ },
  CAS = { "Compressed ASCII configuration", CAT_READ },
  CST = { "Compressed status", CAT_READ },
  CHI = { "Compressed event history", CAT_READ },
  CEV = { "Compressed event report", CAT_READ },
  CSE = { "Compressed SER", CAT_READ },
  CSU = { "Compressed event summary", CAT_READ },
  BNA = { "Names of the Fast Meter status bits", CAT_READ },
  DNA = { "Names of the Relay Word bits", CAT_READ },
  SNS = { "Names of the SER points", CAT_READ },

  OPE = { "Open a breaker", CAT_CONTROL },
  CLO = { "Close a breaker", CAT_CONTROL },
  PUL = { "Pulse an output contact", CAT_CONTROL },
  CON = { "Control a remote bit", CAT_CONTROL },

  SET = { "Change settings", CAT_SETTINGS },
  PAS = { "Change a password", CAT_SETTINGS },
  COP = { "Copy a settings group", CAT_SETTINGS },
  R_S = { "Restore factory default settings", CAT_SETTINGS },
  TRI = { "Trigger an event report", CAT_MAINT },
  TES = { "Test mode (overrides reported values)", CAT_MAINT },
  LOO = { "Communications loopback test", CAT_MAINT },
  BAU = { "Change the port speed (SELBOOT)", CAT_MAINT },
  L_D = { "Load new firmware", CAT_FIRMWARE },
  REC = { "Receive new firmware (SELBOOT)", CAT_FIRMWARE },
}

-- Target access level of each access command, and the factory-default passwords
-- published in SEL instruction manuals (for example SEL-351S Table 10.21 and
-- SEL-421 Table 4.4). Passwords are case-sensitive.
local ACCESS_TARGET = {
  ACC = "1", BAC = "B", PAC = "P", AAC = "A", OAC = "O", ["2AC"] = "2", CAL = "C",
}
local FACTORY_PASSWORDS = {
  ["1"] = { "OTTER" }, B = { "EDITH" }, P = { "AMPERE" }, A = { "VOLTA" },
  O = { "WATT" }, ["2"] = { "TAIL" }, C = { "CLARKE", "Sel-1" },
}

local ERRORS = {
  "Invalid Command", "Invalid Access Level", "Invalid Password", "Invalid Data",
  "Invalid Event", "Invalid Access", "Command Unavailable",
}

-- SEL Fast binary messages. Fast Meter and configuration requests are bare
-- two-byte commands; every other frame carries its total length in byte 3.
local FAST_NAMES = {
  [0xA546] = "Fast Message",
  [0xA5B9] = "Fast Meter status acknowledge",
  [0xA5C0] = "Relay definition block",
  [0xA5C1] = "Fast Meter configuration",
  [0xA5C2] = "Demand Fast Meter configuration",
  [0xA5C3] = "Peak demand Fast Meter configuration",
  [0xA5CD] = "Fast Operate reset definition",
  [0xA5CE] = "Fast Operate configuration",
  [0xA5CF] = "Alternate Fast Operate configuration",
  [0xA5D1] = "Fast Meter data",
  [0xA5D2] = "Demand Fast Meter data",
  [0xA5D3] = "Peak demand Fast Meter data",
  [0xA5E0] = "Fast Operate remote bit control",
  [0xA5E3] = "Fast Operate breaker control",
  [0xA5E5] = "Alternate Fast Operate open",
  [0xA5E6] = "Alternate Fast Operate close",
  [0xA5E7] = "Alternate Fast Operate set",
  [0xA5E8] = "Alternate Fast Operate clear",
  [0xA5E9] = "Alternate Fast Operate pulse",
  [0xA5ED] = "Fast Operate reset",
}
local FAST_BARE_REQUEST = {
  [0xB9] = true, [0xC0] = true, [0xC1] = true, [0xC2] = true, [0xC3] = true,
  [0xCD] = true, [0xCE] = true, [0xCF] = true, [0xD1] = true, [0xD2] = true, [0xD3] = true,
}
local FAST_OPERATE = {
  [0xE0] = true, [0xE3] = true, [0xE5] = true, [0xE6] = true, [0xE7] = true,
  [0xE8] = true, [0xE9] = true, [0xED] = true,
}

-------------------------------------------------------------------------------
-- Pure helpers (no Wireshark API; unit tested with a plain Lua interpreter)
-------------------------------------------------------------------------------
local function trim(s)
  return (s:gsub("^[%s%c]+", ""):gsub("[%s%c]+$", ""))
end

local function strip_flow(s)
  return (s:gsub("[\17\19]", ""))
end

local function count_quotes(s)
  local _, n = s:gsub('"', "")
  return n
end

-- 16-bit sum of the bytes (the Compressed ASCII checksum).
local function sum16(s)
  local total = 0
  for i = 1, #s do
    total = total + s:byte(i)
  end
  return total % 65536
end

-- Parse one Compressed ASCII record. The checksum is the 16-bit sum of the
-- bytes from the first character of the record through the comma in front of
-- the quoted four hex digit checksum, which ends the record. Returns the field
-- values, the checksum (nil when the line has none) and the calculated checksum.
local function parse_cascii(line)
  local body, ck = line:match('^%s*(.*,)"(%x%x%x%x)"%s*$')
  local src = body or line
  local fields, i, n = {}, 1, #src
  while i <= n do
    if src:sub(i, i) == '"' then
      -- Embedded quotes are not escaped, so a quoted field ends at a quote that
      -- is followed by a comma or by the end of the record.
      local j = i + 1
      while true do
        local q = src:find('"', j, true)
        if not q then j = n + 1; break end
        local after = src:sub(q + 1, q + 1)
        if after == "," or after == "" then j = q; break end
        j = q + 1
      end
      fields[#fields + 1] = src:sub(i + 1, j - 1)
      i = j + 1
      if src:sub(i, i) == "," then i = i + 1 end
    else
      local j = src:find(",", i, true) or (n + 1)
      fields[#fields + 1] = trim(src:sub(i, j - 1))
      i = j + 1
    end
  end
  if not body then return fields, nil, nil end
  return fields, tonumber(ck, 16), sum16(body)
end

-- Remove Telnet commands (IAC ...) from raw TCP payload. With sb_unterminated,
-- an IAC SB without IAC SE is removed (IAC, SB and the option byte) instead of
-- being reported as incomplete.
-- Returns:
--   clean: the payload with commands removed and IAC IAC replaced by one 0xFF
--   map: breakpoints {clean_index, raw_index} (nil when nothing was removed)
--   cmds: list of {raw_start, raw_length, unterminated} of the removed commands
--   incomplete: raw index of a truncated trailing command, or nil
local function telnet_clean(raw, sb_unterminated)
  if not raw:find("\255", 1, true) then return raw, nil, {}, nil end
  local out, map, cmds = {}, {}, {}
  local n, i, clean_len = #raw, 1, 0
  while i <= n do
    local k = raw:find("\255", i, true) or (n + 1)
    if k > i then
      map[#map + 1] = { clean_len + 1, i }
      out[#out + 1] = raw:sub(i, k - 1)
      clean_len = clean_len + (k - i)
    end
    if k > n then break end
    if k == n then return table.concat(out), map, cmds, k end
    local c = raw:byte(k + 1)
    if c == IAC then
      map[#map + 1] = { clean_len + 1, k }
      out[#out + 1] = "\255"
      clean_len = clean_len + 1
      i = k + 2
    elseif c >= WILL and c <= DONT then
      if k + 2 > n then return table.concat(out), map, cmds, k end
      cmds[#cmds + 1] = { k, 3 }
      i = k + 3
    elseif c == SB then
      local j, stop = k + 2, nil
      while true do
        local q = raw:find("\255", j, true)
        if not q or q == n then break end
        if raw:byte(q + 1) == SE then stop = q + 1; break end
        j = q + 2
      end
      if stop then
        cmds[#cmds + 1] = { k, stop - k + 1 }
        i = stop + 1
      elseif sb_unterminated then
        local len = math.min(3, n - k + 1)
        cmds[#cmds + 1] = { k, len, true }
        i = k + len
      else
        return table.concat(out), map, cmds, k
      end
    else
      cmds[#cmds + 1] = { k, 2 }
      i = k + 2
    end
  end
  return table.concat(out), map, cmds, nil
end

-- Raw index (1-based) of a clean index, using the breakpoints of telnet_clean.
local function clean_to_raw(map, c)
  if not map or #map == 0 then return c end
  local lo, hi = 1, #map
  while lo < hi do
    local mid = math.floor((lo + hi + 1) / 2)
    if map[mid][1] <= c then lo = mid else hi = mid - 1 end
  end
  local bp = map[lo]
  if bp[1] > c then return c end
  return bp[2] + (c - bp[1])
end

-- Raw index of the last raw byte of clean index c (an escaped 0xFF uses two).
local function clean_end_to_raw(map, raw, c)
  local r = clean_to_raw(map, c)
  if map and raw:byte(r) == IAC and raw:byte(r + 1) == IAC then return r + 1 end
  return r
end

local function ymodem_block_size(data, s)
  local b, blk, nblk = data:byte(s, s + 2)
  if (b == SOH or b == STX) and blk and nblk and blk + nblk == 255 then
    return (b == SOH) and 133 or 1029
  end
  return nil
end

-- Find the end (1-based, inclusive) of the message that starts at index s.
-- Returns end_index and kind, or nil when more data is needed. The returned end
-- is never smaller than s, so callers always make progress.
-- Kinds: flow, control, fast, ymodem, text (request), message (STX..ETX),
-- unframed (device text without framing), binary.
local function find_pdu_end(data, s, dir)
  local n = #data
  local b = data:byte(s)
  if b == XON or b == XOFF or b == CAN then return s, "flow" end
  if b == EOT or b == ACK or b == NAK then return s, "control" end

  if b == FAST_SYNC then
    local op = data:byte(s + 1)
    if not op then return nil end
    if not FAST_NAMES[0xA500 + op] then return s, "binary" end
    if dir == DIR_REQUEST and FAST_BARE_REQUEST[op] then return s + 1, "fast" end
    local len = data:byte(s + 2)
    if not len then return nil end
    if len < 4 then return s + 1, "fast" end
    if s + len - 1 <= n then return s + len - 1, "fast" end
    return nil
  end

  if b == SOH or b == STX then
    local size = ymodem_block_size(data, s)
    if size then
      if s + size - 1 <= n then return s + size - 1, "ymodem" end
      return nil
    end
    if s + 2 > n then
      -- Too short to tell a YMODEM block header from SEL framing yet
      if b == SOH or dir == DIR_REQUEST then return nil end
    end
  end

  if dir == DIR_REQUEST then
    local stop = data:find(NOT_REQUEST_TEXT, s)
    if stop == s then
      local q = data:find("[\1\2\165]", s + 1)
      return (q and q - 1) or n, "binary"
    end
    local run_end = (stop or (n + 1)) - 1
    local e = data:find("[\r\n]", s)
    if e and e <= run_end then
      local nb = data:byte(e + 1)
      if data:byte(e) == CR and (nb == LF or nb == 0) then e = e + 1 end
      return e, "text"
    end
    if stop then return run_end, "text" end
    return nil -- still typing
  end

  if b == STX then
    local x = data:find("\3", s + 1, true)
    if x then return x, "message" end
    return nil
  end
  local stop = data:find(NOT_RESPONSE_TEXT, s)
  if not stop then return n, "unframed" end
  local c = data:byte(stop)
  if c == STX then
    if stop + 2 <= n and ymodem_block_size(data, stop) then return stop - 1, "unframed" end
    -- Echoed command followed by the framed response: keep them together
    local x = data:find("\3", stop + 1, true)
    if x then return x, "message" end
    return nil
  elseif c == ETX then
    return stop, "message" -- the start of this message was not captured
  end
  if stop == s then
    local q = data:find("[\1\2\165]", s + 1)
    return (q and q - 1) or n, "binary"
  end
  return stop - 1, "unframed"
end

-- Split a device message into echo, framing and lines. Offsets are 0-based.
local function parse_message(s)
  local stx = s:find("\2", 1, true)
  local etx = s:find("\3", (stx or 0) + 1, true)
  local body_start = stx and (stx + 1) or 1
  local body_end = etx and (etx - 1) or #s
  local msg = { stx = stx, etx = etx, lines = {} }
  if stx and stx > 1 then msg.echo = s:sub(1, stx - 1) end
  local pos = body_start
  while pos <= body_end do
    local e = s:find("[\r\n]", pos)
    local text_end, nxt
    if not e or e > body_end then
      text_end, nxt = body_end, body_end + 1
    else
      text_end, nxt = e - 1, e + 1
      if s:byte(e) == CR and e + 1 <= body_end and s:byte(e + 1) == LF then nxt = e + 2 end
    end
    msg.lines[#msg.lines + 1] = { text = s:sub(pos, text_end), off = pos - 1, len = text_end - pos + 1 }
    pos = nxt
  end
  return msg
end

-- Group message lines into plain lines and Compressed ASCII records. A record
-- whose quoted field is still open at the end of a line continues on the next
-- lines; its checksum is reported as unverified when it does not match, since
-- the checksum rules for such records are not documented.
local function group_records(lines)
  local items, i, n = {}, 1, #lines
  while i <= n do
    local t = strip_flow(lines[i].text)
    if trim(t) == "" then
      i = i + 1
    else
      local fields, ck, calc = parse_cascii(t)
      local item = { first = i, last = i, text = t }
      if ck then
        item.fields, item.ck, item.calc = fields, ck, calc
      elseif count_quotes(t) % 2 == 1 then
        local j, joined = i, t
        while j < n and j - i < MAX_RECORD_LINES do
          j = j + 1
          local nt = strip_flow(lines[j].text)
          joined = joined .. "\r\n" .. nt
          if nt:find('"%x%x%x%x"%s*$') and count_quotes(joined) % 2 == 0 then
            local f2, ck2, calc2 = parse_cascii(joined)
            if ck2 then
              item.last, item.text, item.multiline = j, joined, true
              item.fields, item.ck, item.calc = f2, ck2, calc2
              break
            end
          end
        end
      end
      items[#items + 1] = item
      i = item.last + 1
    end
  end
  return items
end

local function find_error(line)
  for _, err in ipairs(ERRORS) do
    if line:find(err, 1, true) then return err end
  end
  return line:match("^%s*(Invalid %a[%a ]*%a)")
end

local function prompt_level(text, framed)
  local t = trim(text)
  local level = PROMPT_LEVEL[t]
  if level and (framed or not AMBIGUOUS_PROMPT[t]) then return level, t end
  return nil
end

-- "Password: ?", "Old Password:" and similar (but not "Invalid Password").
local function is_password_prompt(text)
  return text:find("[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]%s*[:?][%s:?]*$") ~= nil
end

-- Typed request line: apply backspace and delete, drop CR, LF and NUL.
local function request_line(s)
  local chars = {}
  for i = 1, #s do
    local c = s:byte(i)
    if c == 0x08 or c == 0x7F then
      chars[#chars] = nil
    elseif c ~= CR and c ~= LF and c ~= 0 then
      chars[#chars + 1] = string.char(c)
    end
  end
  return trim(table.concat(chars))
end

-- Classify a command line. Returns mnemonic, arguments, description, category.
local function classify(line)
  local word, args = line:match("^(%S+)%s*(.-)%s*$")
  if not word then return nil end
  local mnem = word:upper():sub(1, 3)
  local entry = COMMANDS[mnem]
  local desc, cat = entry and entry[1], entry and entry[2]
  local a1 = (args:match("^(%S+)") or ""):upper()
  if mnem == "STA" and (a1 == "C" or a1 == "R") then
    desc, cat = "Clear self-test status and restart", CAT_MAINT
  elseif (mnem == "SER" or mnem == "HIS" or mnem == "TAR" or mnem == "LDP" or mnem == "SSI")
      and (a1 == "C" or a1 == "R") then
    desc, cat = "Clear or reset stored records", CAT_MAINT
  elseif mnem == "MET" and (a1 == "RD" or a1 == "RP" or a1 == "RE" or a1 == "RM") then
    desc, cat = "Reset metering values", CAT_MAINT
  elseif mnem == "BRE" and (a1 == "R" or a1 == "W" or a1 == "P") then
    desc, cat = "Reset or preset breaker monitor data", CAT_MAINT
  elseif mnem == "GRO" and a1:find("^%d") then
    desc, cat = "Change the active settings group", CAT_SETTINGS
  elseif (mnem == "DAT" or mnem == "TIM") and a1:find("%d") then
    desc, cat = "Set the clock", CAT_SETTINGS
  elseif mnem == "FIL" and (a1:sub(1, 1) == "W" or a1:sub(1, 3) == "DEL") then
    desc, cat = "Write or delete a file on the device", CAT_SETTINGS
  end
  return mnem, args, desc, cat
end

local function changes_state(cat)
  return cat == CAT_CONTROL or cat == CAT_SETTINGS or cat == CAT_MAINT or cat == CAT_FIRMWARE
end

-- Commands that may ask questions or passwords before the next level prompt;
-- request lines sent in between are answers to the command.
local function is_interactive(mnem, cat)
  if mnem == "QUI" or mnem == "EXI" then return false end
  return cat == CAT_ACCESS or changes_state(cat)
end

local function is_factory_password(level, pw)
  local lists = level and { FACTORY_PASSWORDS[level] } or FACTORY_PASSWORDS
  for _, list in pairs(lists) do
    for _, candidate in ipairs(list) do
      if pw == candidate then return true end
    end
  end
  return false
end

-- YMODEM block: block number, data length and, for block 0, file name and size.
local function ymodem_info(s)
  local b, blk = s:byte(1, 2)
  local size = (b == SOH) and 128 or 1024
  local name, fsize
  if blk == 0 then
    local data = s:sub(4, 3 + size)
    local rest
    name, rest = data:match("^([^\0]*)\0([^\0]*)")
    fsize = rest and rest:match("^(%d+)")
  end
  return blk, size, name, fsize
end

-- Heuristic: does this payload look like SEL ASCII?
local function looks_like_sel(data)
  if #data < 2 or data:find(NOT_SEL_TEXT) then return false end
  -- Device output: messages start with STX CR LF and end with ETX
  if data:find("\2[\r\n]") and data:find("\3", 1, true) then return true end
  local before_etx = data:match("([^\2\3\r\n]*)\3")
  if before_etx and prompt_level(before_etx, true) then return true end
  -- A Compressed ASCII record with a valid checksum
  local checked = 0
  for line in data:gmatch("[^\r\n]+") do
    local _, ck, calc = parse_cascii(line)
    if ck and ck == calc then return true end
    checked = checked + 1
    if checked >= 20 then break end
  end
  -- A command: a known 2 or 3 character mnemonic in upper case (relays accept
  -- lower case too, but "set", "id" or "com" are common words of other text
  -- protocols and shells), optional arguments, CR or CRLF
  if #data <= 80 then
    local word, rest = data:match("^([%w_]+)([^\r\n]*)\r\n?$")
    if word and #word >= 2 and #word <= 3 and (rest == "" or rest:find("^ "))
        and COMMANDS[word] then
      return true
    end
  end
  return false
end

-------------------------------------------------------------------------------
-- Fields, expert info and preferences
-------------------------------------------------------------------------------
local f = selascii.fields
f.direction = ProtoField.uint8("selascii.direction", "Direction", base.DEC,
  { [0] = "Request (to device)", [1] = "Response (from device)" })
f.pdu_type = ProtoField.string("selascii.type", "Message type")
f.command = ProtoField.string("selascii.command", "Command line")
f.cmd = ProtoField.string("selascii.cmd", "Command mnemonic")
f.cmd_desc = ProtoField.string("selascii.cmd.description", "Command description")
f.cmd_cat = ProtoField.string("selascii.cmd.category", "Command category")
f.cmd_state = ProtoField.bool("selascii.cmd.changes_state", "Changes device state")
f.args = ProtoField.string("selascii.args", "Arguments")
f.input = ProtoField.string("selascii.input", "Answer to device question")
f.password = ProtoField.string("selascii.password", "Password")
f.session_level = ProtoField.string("selascii.session_level", "Access level when sent")
f.response_in = ProtoField.framenum("selascii.response_in", "Response in frame", base.NONE,
  frametype and frametype.RESPONSE)
f.request_in = ProtoField.framenum("selascii.request_in", "Request in frame", base.NONE,
  frametype and frametype.REQUEST)
f.response_to = ProtoField.string("selascii.response_to", "Response to command")
f.echo = ProtoField.string("selascii.echo", "Echo")
f.stx = ProtoField.uint8("selascii.stx", "STX", base.HEX)
f.etx = ProtoField.uint8("selascii.etx", "ETX", base.HEX)
f.prompt = ProtoField.string("selascii.prompt", "Prompt")
f.level = ProtoField.string("selascii.access_level", "Access level")
f.question = ProtoField.string("selascii.question", "Question")
f.line = ProtoField.string("selascii.line", "Line")
f.line_count = ProtoField.uint32("selascii.line_count", "Line count")
f.error = ProtoField.string("selascii.error", "Device error")
f.cas = ProtoField.string("selascii.cascii", "Compressed ASCII record")
f.cas_field = ProtoField.string("selascii.cascii.field", "Field")
f.cas_nfield = ProtoField.uint32("selascii.cascii.field_count", "Field count")
f.cas_ck = ProtoField.uint16("selascii.cascii.checksum", "Checksum", base.HEX)
f.cas_ckcalc = ProtoField.uint16("selascii.cascii.checksum.calculated", "Calculated checksum",
  base.HEX)
f.cas_ckstat = ProtoField.uint8("selascii.cascii.checksum.status", "Checksum status", base.DEC,
  { [0] = "Bad", [1] = "Good", [2] = "Unverified" })
f.id_key = ProtoField.string("selascii.id.key", "ID key")
f.id_value = ProtoField.string("selascii.id.value", "ID value")
f.id_fid = ProtoField.string("selascii.id.fid", "Firmware ID (FID)")
f.id_bfid = ProtoField.string("selascii.id.bfid", "Boot firmware ID (BFID)")
f.id_partno = ProtoField.string("selascii.id.partno", "Part number")
f.id_devid = ProtoField.string("selascii.id.devid", "Device ID (DEVID)")
f.id_serial = ProtoField.string("selascii.id.serialno", "Serial number")
f.id_ied = ProtoField.string("selascii.id.iedname", "IEC 61850 iedName")
f.flow = ProtoField.uint8("selascii.flow", "Flow control", base.HEX,
  { [0x11] = "XON", [0x13] = "XOFF", [0x18] = "CAN" })
f.control = ProtoField.uint8("selascii.control", "Transfer control", base.HEX,
  { [0x04] = "EOT", [0x06] = "ACK", [0x15] = "NAK" })
f.ymodem_block = ProtoField.uint8("selascii.ymodem.block", "YMODEM block number")
f.ymodem_len = ProtoField.uint16("selascii.ymodem.data_length", "YMODEM data length")
f.ymodem_name = ProtoField.string("selascii.ymodem.filename", "YMODEM file name")
f.ymodem_size = ProtoField.string("selascii.ymodem.filesize", "YMODEM file size")
f.fast = ProtoField.uint16("selascii.fast.type", "SEL Fast message type", base.HEX, FAST_NAMES)
f.binary = ProtoField.bytes("selascii.binary", "Binary data")
f.telnet_cmd = ProtoField.bytes("selascii.telnet_cmd", "Telnet command (removed)")
f.reasm_in = ProtoField.framenum("selascii.reassembled_in", "Reassembled in frame")
f.reasm_from = ProtoField.framenum("selascii.reassembled_from", "Reassembled from frame")
f.reasm_len = ProtoField.uint32("selascii.reassembled_length", "Reassembled length")

local e_bad_ck = ProtoExpert.new("selascii.cascii.bad_checksum",
  "Compressed ASCII checksum mismatch", expert.group.CHECKSUM, expert.severity.ERROR)
local e_dev_err = ProtoExpert.new("selascii.error.expert",
  "Device returned an error", expert.group.RESPONSE_CODE, expert.severity.WARN)
local e_password = ProtoExpert.new("selascii.password.cleartext",
  "Password sent in cleartext", expert.group.SECURITY, expert.severity.WARN)
local e_default_pw = ProtoExpert.new("selascii.password.factory_default",
  "Factory-default password", expert.group.SECURITY, expert.severity.WARN)
local e_level = ProtoExpert.new("selascii.access_level.changed",
  "Access level changed", expert.group.SEQUENCE, expert.severity.CHAT)
local e_control = ProtoExpert.new("selascii.cmd.operates_equipment",
  "Command operates equipment", expert.group.REQUEST_CODE, expert.severity.WARN)
local e_change = ProtoExpert.new("selascii.cmd.state_change",
  "Command changes device state or settings", expert.group.REQUEST_CODE, expert.severity.NOTE)
local e_unterm = ProtoExpert.new("selascii.unterminated",
  "Message not terminated", expert.group.MALFORMED, expert.severity.NOTE)
local e_malformed = ProtoExpert.new("selascii.malformed",
  "Embedded frame could not be decoded", expert.group.MALFORMED, expert.severity.ERROR)
local e_telnet_sb = ProtoExpert.new("selascii.telnet_sb_unterminated",
  "Telnet subnegotiation not terminated (no IAC SE)", expert.group.PROTOCOL, expert.severity.WARN)
selascii.experts = { e_bad_ck, e_dev_err, e_password, e_default_pw, e_level, e_control,
  e_change, e_unterm, e_malformed, e_telnet_sb }

selascii.prefs.tcp_ports = Pref.range("TCP ports", "",
  "TCP ports that carry SEL ASCII without Telnet, for example RTAC tunnel ports", 65535)
selascii.prefs.wrap_telnet = Pref.bool("Decode Telnet port 23 as SEL ASCII", true,
  "Take over TCP port 23: show the Telnet tree, then decode the sessions that look like"
  .. " SEL ASCII (add 23 to the TCP ports to decode every port 23 session)")
selascii.prefs.rtac_default = Pref.bool("Decode RTAC serial payloads as SEL ASCII", false,
  "Decode LINKTYPE_RTAC_SERIAL payloads as SEL ASCII without a Decode As rule")
selascii.prefs.rtac_tx_is_request = Pref.bool("RTAC transmit is a request", true,
  "RTAC DATA_TX events are commands to the device (the RTAC is the master on the port)")
selascii.prefs.show_passwords = Pref.bool("Show passwords", false,
  "Show passwords in the protocol tree instead of masking them")
selascii.prefs.max_pdu = Pref.uint("Maximum message size", 1048576,
  "Stop waiting for the end of a message after this many bytes")

-------------------------------------------------------------------------------
-- Dissection state (reset whenever a capture is (re)dissected)
-------------------------------------------------------------------------------
local streams     -- stream key -> session state
local notes       -- PDU key -> results computed on the first pass
local layouts     -- "frame:tvb offset" -> TCP message boundaries of the first pass
local frame_requests -- frame number -> request notes by line (fallback on later passes)
local reasm       -- non-TCP reassembly buffers, per stream and direction
local frame_reasm -- frame number -> PDUs completed in it (non-TCP)
local usb_claimed -- USB device key -> first frame claimed by the heuristic
local current_rtac_event -- RTAC event type of the record being dissected
local tcp_port_set = {}

local function reset_state()
  streams, notes, layouts, frame_requests = {}, {}, {}, {}
  reasm, frame_reasm, usb_claimed = {}, {}, {}
  current_rtac_event = nil
end
reset_state()
selascii.init = reset_state

local function get_stream(key)
  local st = streams[key]
  if not st then
    st = { pending = {}, sb_wait = {}, deferred = {} }
    streams[key] = st
  end
  return st
end

local function get_note(key)
  local note = notes[key]
  if not note then
    note = {}
    notes[key] = note
  end
  return note
end

local function parse_ports(spec)
  local set = {}
  for token in spec:gmatch("[^,]+") do
    local a, b = token:match("^%s*(%d+)%s*%-%s*(%d+)%s*$")
    a = tonumber(a or token:match("^%s*(%d+)%s*$"))
    b = tonumber(b) or a
    if a and b and b - a < 65536 then
      for p = a, b do set[p] = true end
    end
  end
  return set
end

local function endpoint(addr, port)
  return tostring(addr) .. ":" .. tostring(port)
end

local function tcp_stream_key(pinfo)
  local a, b = endpoint(pinfo.src, pinfo.src_port), endpoint(pinfo.dst, pinfo.dst_port)
  if a > b then a, b = b, a end
  return "tcp:" .. a .. "-" .. b
end

local function usb_device(addr)
  local a = tostring(addr)
  if a == "host" then return nil end
  return a:match("^(%d+%.%d+)") or a
end

local function stream_key(pinfo)
  if pinfo.port_type == PT_USB then
    return "usb:" .. tostring(usb_device(pinfo.src) or usb_device(pinfo.dst))
  end
  if current_rtac_event then return "rtac" end
  return "serial"
end

-- Request or response on TCP: the server endpoint is learned once per stream.
local function tcp_direction(pinfo, st, raw)
  if not st.server then
    local sp, dp = pinfo.src_port, pinfo.dst_port
    local src, dst = endpoint(pinfo.src, sp), endpoint(pinfo.dst, dp)
    if dp == 23 or (tcp_port_set[dp] and not tcp_port_set[sp]) then
      st.server = dst
    elseif sp == 23 or tcp_port_set[sp] then
      st.server = src
    elseif raw:find("[\2\3]") then
      st.server = src -- device output is framed with STX/ETX
    elseif raw:find("^%s*[%w_]+[^\r\n]*\r") then
      st.server = dst -- a typed command
    else
      st.server = (sp < dp) and src or dst
    end
  end
  return (endpoint(pinfo.dst, pinfo.dst_port) == st.server) and DIR_REQUEST or DIR_RESPONSE
end

-- Request or response on a link without TCP.
local function stream_direction(pinfo, raw)
  local ev = current_rtac_event
  if ev and ev >= 1 and ev <= 4 then
    local tx = (ev == 1 or ev == 3)
    if selascii.prefs.rtac_tx_is_request then
      return tx and DIR_REQUEST or DIR_RESPONSE
    end
    return tx and DIR_RESPONSE or DIR_REQUEST
  end
  if pinfo.p2p_dir == 0 then return DIR_REQUEST end -- P2P_DIR_SENT (host to device)
  if pinfo.p2p_dir == 1 then return DIR_RESPONSE end -- P2P_DIR_RECV
  return raw:find("[\2\3]") and DIR_RESPONSE or DIR_REQUEST
end

local telnet_handle = Dissector.get("telnet")
local selfm_handle = Dissector.get("selfm")
local rtacser_handle = Dissector.get("rtacser")

-------------------------------------------------------------------------------
-- Message dissection. Each function gets a tvb that holds exactly one message.
-------------------------------------------------------------------------------
local function add_range(tree, field, tvb, off, len, value)
  if off >= 0 and len > 0 and off + len <= tvb:len() then
    if value == nil then return tree:add(field, tvb(off, len)) end
    return tree:add(field, tvb(off, len), value)
  end
  return tree:add(field, value)
end

-- Call another dissector. Its exceptions (for example a malformed SEL Fast frame)
-- become an expert item instead of a Lua error, and it cannot change the TCP
-- reassembly request of this dissector.
local function call_dissector(handle, tvb, pinfo, tree, expert_tree)
  local dl, doff = pinfo.desegment_len, pinfo.desegment_offset
  local ok, err = pcall(function() return handle:call(tvb, pinfo, tree) end)
  pinfo.desegment_len, pinfo.desegment_offset = dl, doff
  if not ok then
    (expert_tree or tree):add_proto_expert_info(e_malformed, (tostring(err):gsub("^.-: ", "")))
  end
  return ok
end

local function generated(tree, field, value)
  local item = tree:add(field, value)
  item:set_generated()
  return item
end

local function display_line(text)
  if text == "" then return "<CR>" end
  return text
end

local function mask(text)
  if selascii.prefs.show_passwords then return text end
  return string.rep("*", #text)
end

-- The access command or PAS that a request line is a password for. Each takes one
-- password per password prompt, and passwords may be typed ahead of their prompts
-- (entry.ahead), so this is the oldest one with a password still to come. A line
-- that is not an SEL command, typed ahead of the level prompt right after an access
-- command or PAS (for example a second guess), is masked as a password as well.
local function password_owner(st, line)
  for _, e in ipairs(st.pending) do
    if e.password_input and e.answers < math.max(e.password_prompts, e.ahead) then return e end
  end
  local last = st.pending[#st.pending]
  if last and last.password_input and line ~= "" and not COMMANDS[classify(line) or ""] then
    return last
  end
  return nil
end

local function first_pass_request(pinfo, st, note, line, unterminated)
  local head = st.pending[1]
  note.level = st.level
  if unterminated and line == "C" and head and head.mnem == "FIL" then
    -- The receiver of a YMODEM transfer (FILE READ) starts it with "C"
    note.kind, note.parent = "YMODEM start", head
    return
  end
  -- A password (see password_owner), or an answer: other interactive commands
  -- (SET, STA C, PUL ...) take any number of answers until their level prompt.
  local owner = password_owner(st, line)
  local input = owner ~= nil or (head ~= nil and head.interactive and not head.password_input)
      or st.expect_input or st.expect_password or (line == "" and head ~= nil)
  if input then
    note.parent = owner or head
    note.secret = owner ~= nil or st.expect_password
        or (st.question ~= nil and is_password_prompt(st.question))
    if owner then owner.answers = owner.answers + 1 end
    if note.secret then
      local target = note.parent and ACCESS_TARGET[note.parent.mnem]
      note.factory_default = is_factory_password(target, line)
    end
    note.kind = note.secret and "Password" or "Input"
    st.expect_input, st.expect_password, st.question = false, false, nil
    return
  end
  local mnem, args, desc, cat = classify(line)
  local entry = { text = line, frame = pinfo.number, mnem = mnem, args = args,
    desc = desc, cat = cat }
  entry.interactive = mnem ~= nil and is_interactive(mnem, cat)
  entry.password_input = mnem ~= nil and (ACCESS_TARGET[mnem] ~= nil or mnem == "PAS")
  if entry.password_input then
    -- Passwords that may be typed ahead of their prompts: one for an access
    -- command, the old, new and confirmed one for PAS, and none for
    -- "PAS <level> <password>" (older relays), which has it on the line
    entry.ahead = 1
    if mnem == "PAS" then entry.ahead = args:find("^%S+%s+%S") and 0 or 3 end
    entry.password_prompts, entry.answers = 0, 0
  end
  if #st.pending >= MAX_PENDING then table.remove(st.pending, 1) end
  st.pending[#st.pending + 1] = entry
  note.kind = (line == "") and "Empty line" or "Command"
  note.cmd = entry
end

local function dissect_text_request(tvb, pinfo, tree, st, note, unterminated)
  local s = tvb:raw()
  local only_eol = not s:find("[^\n\0]")
  if only_eol then
    tree:add(f.pdu_type, "Line terminator")
    return nil
  end
  local line = request_line(s)
  local seen = frame_requests[pinfo.number]
  if not pinfo.visited and not note.kind then
    first_pass_request(pinfo, st, note, line, unterminated)
    seen = seen or {}
    frame_requests[pinfo.number] = seen
    seen[line] = seen[line] or note
    if note.secret then seen.secret = true end
  elseif not note.kind and seen then
    -- Not cut the same way as on the first pass (should not happen): use the
    -- note of the same line in this frame, and never show a password in clear.
    note = seen[line] or (seen.secret and { kind = "Password" }) or note
  end
  local kind = note.kind or "Command"
  if kind == "YMODEM start" then
    tree:add(f.pdu_type, "Transfer control")
    if note.parent then generated(tree, f.response_to, note.parent.text) end
    return "YMODEM start (C)"
  end
  if unterminated then tree:add_proto_expert_info(e_unterm) end
  tree:add(f.pdu_type, kind)
  if note.level then generated(tree, f.session_level, note.level) end

  if kind == "Password" then
    local item = tree:add(f.password, tvb(), mask(line))
    item:add_proto_expert_info(e_password)
    if note.factory_default then item:add_proto_expert_info(e_default_pw) end
    if note.parent then
      generated(tree, f.response_to, display_line(note.parent.text))
    end
    return "Password " .. mask(line)
  end
  if kind == "Input" then
    tree:add(f.input, tvb(), display_line(line))
    if note.parent then generated(tree, f.response_to, display_line(note.parent.text)) end
    return "Input " .. display_line(line)
  end
  if kind == "Empty line" then
    if note.cmd and note.cmd.response_frame then
      generated(tree, f.response_in, note.cmd.response_frame)
    end
    return "Command <CR>"
  end

  local mnem, args, desc, cat = classify(line)
  local shown = line
  if mnem == "PAS" and args ~= "" then
    -- Older relays take the new password on the command line: PAS <level> <password>
    local lvl, pw = args:match("^(%S+)%s+(.+)$")
    if pw then
      shown = line:match("^(%S+)") .. " " .. lvl .. " " .. mask(pw)
      args = lvl .. " " .. mask(pw)
    end
  end
  tree:add(f.command, tvb(), shown)
  if mnem then
    local ci = tree:add(f.cmd, tvb(), mnem)
    if desc then generated(ci, f.cmd_desc, desc) end
    if cat then
      generated(ci, f.cmd_cat, cat)
      if changes_state(cat) then
        generated(ci, f.cmd_state, true)
        if cat == CAT_CONTROL then
          ci:add_proto_expert_info(e_control)
        else
          ci:add_proto_expert_info(e_change)
        end
      end
    end
    if args ~= "" then tree:add(f.args, tvb(), args) end
  end
  if note.cmd and note.cmd.response_frame then
    generated(tree, f.response_in, note.cmd.response_frame)
  end
  return "Command " .. shown
end

local ID_FIELDS = { FID = f.id_fid, BFID = f.id_bfid, PARTNO = f.id_partno, DEVID = f.id_devid,
  SERIALNO = f.id_serial, iedName = f.id_ied }

local function add_record(tree, tvb, line_item, item, lines, top, is_id)
  local first, last = lines[item.first], lines[item.last]
  local off, len = first.off, last.off + last.len - first.off
  local rec = add_range(line_item, f.cas, tvb, off, len, item.text)
  generated(rec, f.cas_nfield, #item.fields)
  for _, v in ipairs(item.fields) do add_range(rec, f.cas_field, tvb, off, len, v) end
  local ck_item = add_range(rec, f.cas_ck, tvb, last.off + last.len - 5, 4, item.ck)
  generated(rec, f.cas_ckcalc, item.calc)
  local status = 1
  if item.ck ~= item.calc then status = item.multiline and 2 or 0 end
  generated(rec, f.cas_ckstat, status)
  if status == 0 then
    ck_item:add_proto_expert_info(e_bad_ck, string.format(
      "Compressed ASCII checksum mismatch: 0x%04X received, 0x%04X calculated", item.ck, item.calc))
  end
  local k, v = (item.fields[1] or ""):match("^([^=]+)=(.*)$")
  if k and #item.fields == 1 then
    k = trim(k)
    if is_id or k:find("^[%w ]+$") then
      add_range(rec, f.id_key, tvb, off, len, k)
      add_range(rec, f.id_value, tvb, off, len, v)
      local top_field = ID_FIELDS[k]
      if top_field and not top[k] then
        top[k] = true
        add_range(tree, top_field, tvb, off, len, v)
      end
    end
  end
end

local function first_pass_response(pinfo, st, note, kind, level, last)
  local head = st.pending[1]
  note.cmd = head
  if head and not head.response_frame then head.response_frame = pinfo.number end
  if level then
    note.level_old, note.level_new = st.level, level
    st.level = level
    if head then table.remove(st.pending, 1) end
    st.expect_input, st.expect_password, st.question = false, false, nil
  elseif kind == "Password prompt" then
    if head and head.password_input then
      head.password_prompts = head.password_prompts + 1
    else
      st.expect_password = true
    end
    st.question = last
  elseif kind == "Question" then
    st.expect_input, st.question = true, last
  end
end

local function dissect_response(tvb, pinfo, tree, st, note)
  local s = tvb:raw()
  local msg = parse_message(s)
  local framed = msg.stx ~= nil or msg.etx ~= nil
  -- The last non-empty line decides whether this is a prompt or a question
  local last_idx
  for i = #msg.lines, 1, -1 do
    if trim(strip_flow(msg.lines[i].text)) ~= "" then last_idx = i; break end
  end
  local last = last_idx and trim(strip_flow(msg.lines[last_idx].text)) or ""
  local level = last_idx and prompt_level(last, framed)
  local kind
  if level then
    kind = "Prompt"
  elseif last_idx and is_password_prompt(last) then
    kind = "Password prompt"
  elseif last_idx and last:sub(-1) == "?" and (framed or #last >= 3) then
    kind = "Question"
  elseif not framed then
    kind = "Echo / unframed text"
  else
    kind = "Response"
  end
  -- Lines in front of a prompt or question are the response content
  local content_end = #msg.lines
  if kind == "Prompt" or kind == "Password prompt" or kind == "Question" then
    content_end = last_idx - 1
  end
  local content = {}
  for i = 1, content_end do content[i] = msg.lines[i] end
  local items = group_records(content)
  if kind == "Prompt" and #items > 0 then kind = "Response" end

  if not pinfo.visited and not note.kind then
    note.kind = kind
    first_pass_response(pinfo, st, note, kind, level, last)
  end

  tree:add(f.pdu_type, kind)
  local cmd = note.cmd
  if cmd then
    generated(tree, f.response_to, display_line(cmd.text))
    generated(tree, f.request_in, cmd.frame)
  end
  if msg.echo then
    local echo = trim(strip_flow(msg.echo))
    if echo ~= "" then add_range(tree, f.echo, tvb, 0, #msg.echo, echo) end
  end
  if msg.stx then tree:add(f.stx, tvb(msg.stx - 1, 1)) end

  local top, count, first_text = {}, 0, nil
  local is_id = cmd ~= nil and cmd.mnem == "ID"
  for _, item in ipairs(items) do
    local a, b = msg.lines[item.first], msg.lines[item.last]
    local text = trim(item.text)
    count = count + 1
    first_text = first_text or text
    local li = add_range(tree, f.line, tvb, a.off, b.off + b.len - a.off, text)
    if item.ck then add_record(tree, tvb, li, item, msg.lines, top, is_id) end
    local err = find_error(text)
    if err then
      local ei = add_range(tree, f.error, tvb, a.off, b.off + b.len - a.off, err)
      ei:add_proto_expert_info(e_dev_err, "Device error: " .. err)
    end
  end
  if kind ~= "Prompt" then generated(tree, f.line_count, count) end

  local info
  if level then
    local pl = msg.lines[last_idx]
    add_range(tree, f.prompt, tvb, pl.off, pl.len, last)
    local li = generated(tree, f.level, level)
    if note.level_old and note.level_old ~= note.level_new then
      li:add_proto_expert_info(e_level, "Access level changed from " .. note.level_old ..
        " to " .. note.level_new)
    end
    info = "Prompt " .. last .. " (level " .. level .. ")"
  elseif kind == "Password prompt" or kind == "Question" then
    local pl = msg.lines[last_idx]
    add_range(tree, (kind == "Question") and f.question or f.prompt, tvb, pl.off, pl.len, last)
    info = (kind == "Question") and ("Question " .. last) or "Password prompt"
  end
  if msg.etx then
    tree:add(f.etx, tvb(msg.etx - 1, 1))
  elseif msg.stx then
    tree:add_proto_expert_info(e_unterm)
  end

  if count > 0 or not info then
    local what = (kind == "Echo / unframed text") and "Text" or "Response"
    local resp = what .. ((cmd and what == "Response") and (" to " .. display_line(cmd.text)) or "")
    if first_text then resp = resp .. ": " .. first_text:sub(1, 60) end
    if count > 1 then resp = resp .. " (" .. count .. " lines)" end
    info = info and (resp .. "; " .. info) or resp
  end
  return info
end

-- SEL Fast frame: label it, then let the built-in "selfm" dissector decode it.
-- selfm removes Telnet escapes itself, so it gets the on-the-wire bytes.
local function dissect_fast(tvb, pinfo, parent, sub, raw_tvb, dir)
  local b1, b2 = tvb:raw():byte(1, 2)
  local mtype = 0xA500 + (b2 or 0)
  local item = sub:add(f.fast, tvb(0, math.min(2, tvb:len())), mtype)
  sub:add(f.pdu_type, "SEL Fast message")
  if dir == DIR_REQUEST and b1 == FAST_SYNC and FAST_OPERATE[b2 or 0] then
    item:add_proto_expert_info(e_control)
  end
  if selfm_handle then call_dissector(selfm_handle, raw_tvb or tvb, pinfo, parent, sub) end
  return "SEL Fast " .. (FAST_NAMES[mtype] or string.format("%04X", mtype))
end

local function dissect_ymodem(tvb, tree)
  local blk, size, name, fsize = ymodem_info(tvb:raw())
  tree:add(f.pdu_type, "YMODEM block")
  tree:add(f.ymodem_block, tvb(1, 1), blk)
  add_range(tree, f.ymodem_len, tvb, 3, size, size)
  local info = "YMODEM block " .. blk
  if name and name ~= "" then
    add_range(tree, f.ymodem_name, tvb, 3, #name, name)
    if fsize then generated(tree, f.ymodem_size, fsize) end
    info = info .. ": " .. name .. (fsize and (" (" .. fsize .. " bytes)") or "")
  end
  return info
end

local FLOW_NAMES = { [XON] = "XON", [XOFF] = "XOFF", [CAN] = "CAN" }
local CONTROL_NAMES = { [EOT] = "EOT", [ACK] = "ACK", [NAK] = "NAK" }

-- Dissect one message. kind comes from find_pdu_end, or "partial" when the end
-- was not seen. raw_tvb is the on-the-wire range (with Telnet escapes), if any.
local function dissect_pdu(tvb, pinfo, tree, dir, st, note_key, kind, raw_tvb)
  local note = get_note(note_key)
  local sub = tree:add(selascii, raw_tvb or tvb)
  sub:add(f.direction, dir)
  local first = tvb:raw():byte(1)
  if kind == "partial" then
    if first == FAST_SYNC or first == SOH or (first == STX and dir == DIR_REQUEST) then
      kind = "binary"
      sub:add_proto_expert_info(e_unterm)
    else
      kind = (dir == DIR_REQUEST) and "text" or "message"
    end
  end
  local info
  if kind == "flow" then
    sub:add(f.flow, tvb(0, 1))
    sub:add(f.pdu_type, "Flow control")
    info = FLOW_NAMES[first]
  elseif kind == "control" then
    sub:add(f.control, tvb(0, 1))
    sub:add(f.pdu_type, "Transfer control")
    info = CONTROL_NAMES[first]
  elseif kind == "fast" then
    info = dissect_fast(tvb, pinfo, tree, sub, raw_tvb, dir)
  elseif kind == "ymodem" then
    info = dissect_ymodem(tvb, sub)
  elseif kind == "binary" then
    sub:add(f.binary, tvb())
    sub:add(f.pdu_type, "Binary data")
    info = "Binary data (" .. tvb:len() .. " bytes)"
  elseif dir == DIR_REQUEST then
    info = dissect_text_request(tvb, pinfo, sub, st, note, tvb:raw():find("[\r\n]") == nil)
  else
    info = dissect_response(tvb, pinfo, sub, st, note)
  end
  if info then sub:append_text(", " .. info) end
  return info, sub
end

local function set_columns(pinfo, infos)
  if #infos == 0 then return end
  pinfo.cols.protocol = "SEL ASCII"
  pinfo.cols.info = table.concat(infos, "; ")
end

-------------------------------------------------------------------------------
-- TCP: Telnet handling and TCP reassembly
-------------------------------------------------------------------------------
-- Telnet-cleaned text for the heuristics (a stray IAC SB does not hide the rest).
local function heuristic_text(raw)
  if raw:find("\255", 1, true) then return (telnet_clean(raw, true)) end
  return raw
end

-- Cut a TCP segment into messages. Returns the layout (messages and the bytes
-- consumed now) and the Telnet-cleaned data, offset map and Telnet commands.
-- Only the first pass (first_pass) changes the stream state.
local function cut_tcp(raw, telnet, dir, st, can_wait, first_pass)
  local data, map, cmds, incomplete = raw, nil, {}, nil
  local sb_unterminated = false
  if telnet then
    data, map, cmds, incomplete = telnet_clean(raw)
    if incomplete and raw:byte(incomplete + 1) == SB then
      -- Wait for IAC SE over one more segment at most
      if not can_wait or st.sb_wait[dir] or #raw - incomplete + 1 >= MAX_TELNET_SB then
        sb_unterminated = true
        data, map, cmds, incomplete = telnet_clean(raw, true)
        if first_pass then st.sb_wait[dir] = nil end
      elseif first_pass then
        st.sb_wait[dir] = true
      end
    elseif first_pass then
      st.sb_wait[dir] = nil
    end
  end

  local pdus, pos, n, wait_from = {}, 1, #data, nil
  while pos <= n do
    local e, kind = find_pdu_end(data, pos, dir)
    if not e then
      if can_wait and (n - pos + 1) < selascii.prefs.max_pdu then
        wait_from = pos
        break
      end
      e, kind = n, "partial"
    end
    pdus[#pdus + 1] = { s = pos, e = e, kind = kind }
    pos = e + 1
  end

  local consumed = #raw
  if wait_from then
    consumed = clean_to_raw(map, wait_from) - 1
  elseif incomplete and can_wait then
    consumed = incomplete - 1
  end
  if first_pass then
    -- Data deferred on the previous call is at the start of this one. TCP cannot
    -- start a new reassembly inside those bytes: it extends the current one and
    -- hands them over again, so wait for all of it instead of decoding a part twice.
    local old = st.deferred[dir]
    if old and consumed > 0 and consumed < #raw and consumed <= old then
      pdus, consumed = {}, 0
    end
    st.deferred[dir] = (consumed < #raw and can_wait) and (#raw - consumed) or nil
  end
  return { pdus = pdus, consumed = consumed, sb_unterminated = sb_unterminated }, data, map, cmds
end

local function dissect_tcp(tvb, pinfo, tree)
  local raw = tvb:raw()
  local st = get_stream(tcp_stream_key(pinfo))
  local port23 = pinfo.src_port == 23 or pinfo.dst_port == 23
  if port23 and not tcp_port_set[23] then
    -- Port 23 carries all kinds of Telnet sessions. Decode a session from the
    -- first frame that looks like SEL ASCII; until then it is plain Telnet.
    if not pinfo.visited and not st.claim_frame and looks_like_sel(heuristic_text(raw)) then
      st.claim_frame = pinfo.number
    end
    if not st.claim_frame or pinfo.number < st.claim_frame then
      if not telnet_handle then return 0 end
      call_dissector(telnet_handle, tvb, pinfo, tree)
      return tvb:len()
    end
  elseif st.claim_frame and pinfo.number < st.claim_frame then
    return 0
  end
  -- Telnet is in use on port 23 and wherever Telnet negotiation was seen
  if not pinfo.visited and not st.telnet_since and raw:find("^\255[\250-\254]") then
    st.telnet_since = pinfo.number
  end
  local telnet = port23 or (st.telnet_since ~= nil and pinfo.number >= st.telnet_since)
  local dir = tcp_direction(pinfo, st, raw)
  local can_wait = pinfo.can_desegment > 0

  -- Messages are cut on the first pass. Later passes (tshark -2 and the GUI)
  -- get only the bytes consumed on the first pass, so they reuse its cuts and
  -- find the notes of the first pass under the same keys. The key must not
  -- depend on the tvb length, which is shorter on later passes.
  local key_base = pinfo.number .. ":" .. tvb:offset() .. ":"
  local layout, data, map, cmds = layouts[key_base], raw, nil, {}
  if layout then
    if telnet then data, map, cmds = telnet_clean(raw, layout.sb_unterminated) end
  else
    layout, data, map, cmds = cut_tcp(raw, telnet, dir, st, can_wait, not pinfo.visited)
    if not pinfo.visited then layouts[key_base] = layout end
  end
  local consumed = math.min(layout.consumed, #raw)

  -- Show the normal Telnet tree for the part of the segment handled now
  local called_telnet = false
  if telnet and telnet_handle and consumed > 0 then
    call_dissector(telnet_handle, (consumed == #raw) and tvb or tvb(0, consumed):tvb(), pinfo, tree)
    called_telnet = true
  end
  if consumed < #raw and can_wait then
    pinfo.desegment_offset = consumed
    pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
  end

  local infos = {}
  for _, p in ipairs(layout.pdus) do
    if p.e <= #data then
      local rs = clean_to_raw(map, p.s)
      local re = clean_end_to_raw(map, raw, p.e)
      local raw_tvb = tvb(rs - 1, re - rs + 1):tvb()
      local pdu_tvb = raw_tvb
      if re - rs ~= p.e - p.s then
        pdu_tvb = ByteArray.new(data:sub(p.s, p.e), true):tvb("SEL ASCII (Telnet commands removed)")
      end
      local info = dissect_pdu(pdu_tvb, pinfo, tree, dir, st, key_base .. p.s, p.kind, raw_tvb)
      if info then infos[#infos + 1] = info end
    end
  end
  for _, c in ipairs(cmds) do
    if c[1] + c[2] - 1 <= consumed then
      local range = tvb(c[1] - 1, c[2])
      if c[3] then
        local t = tree:add(selascii, range)
        t:append_text(", Telnet subnegotiation without IAC SE")
        t:add(f.telnet_cmd, range):add_proto_expert_info(e_telnet_sb)
        infos[#infos + 1] = "Unterminated Telnet subnegotiation"
      elseif not called_telnet then
        tree:add(f.telnet_cmd, range)
      end
    end
  end
  set_columns(pinfo, infos)
  return tvb:len()
end

-------------------------------------------------------------------------------
-- Other links (RTAC serial, exported PDU, USB, user DLT): own reassembly. The
-- messages are cut on the first pass and cached per frame.
-------------------------------------------------------------------------------
local function dissect_stream(tvb, pinfo, tree)
  local raw = tvb:raw()
  local dir = stream_direction(pinfo, raw)
  local key = stream_key(pinfo)
  local st = get_stream(key)
  if not pinfo.visited and not frame_reasm[pinfo.number] then
    local rkey = key .. ":" .. dir
    local r = reasm[rkey]
    if not r then
      r = { buf = "", first = pinfo.number, frames = {} }
      reasm[rkey] = r
    end
    if r.buf == "" then r.first, r.frames = pinfo.number, {} end
    local before = #r.buf
    r.buf = r.buf .. raw
    r.frames[#r.frames + 1] = pinfo.number
    local fr = { pdus = {} }
    frame_reasm[pinfo.number] = fr
    local pos, n = 1, #r.buf
    while pos <= n do
      local e, kind = find_pdu_end(r.buf, pos, dir)
      if not e then
        if n - pos + 1 < selascii.prefs.max_pdu then break end
        e, kind = n, "partial"
      end
      local pdu = { data = r.buf:sub(pos, e), first = r.first, kind = kind }
      if pos > before then pdu.offset = pos - before - 1 end
      fr.pdus[#fr.pdus + 1] = pdu
      pos = e + 1
      r.first = pinfo.number
    end
    r.buf = r.buf:sub(pos)
    if #fr.pdus > 0 then
      for _, fn in ipairs(r.frames) do
        if fn ~= pinfo.number then
          frame_reasm[fn] = frame_reasm[fn] or { pdus = {} }
          frame_reasm[fn].part_of = frame_reasm[fn].part_of or pinfo.number
        end
      end
      r.frames = (#r.buf > 0) and { pinfo.number } or {}
    end
  end

  local fr = frame_reasm[pinfo.number]
  local infos = {}
  if fr then
    if fr.part_of or #fr.pdus == 0 then
      local t = tree:add(selascii, tvb())
      t:add(f.direction, dir)
      if fr.part_of then
        generated(t, f.reasm_in, fr.part_of)
        t:append_text(", fragment")
        infos[#infos + 1] = "Fragment (reassembled in " .. fr.part_of .. ")"
      else
        -- First pass: the end of the message has not been seen yet
        t:append_text(", fragment")
      end
    end
    for i, p in ipairs(fr.pdus) do
      local ptvb
      if p.first == pinfo.number and p.offset and p.offset + #p.data <= tvb:len() then
        ptvb = tvb(p.offset, #p.data):tvb()
      else
        ptvb = ByteArray.new(p.data, true):tvb("Reassembled SEL ASCII")
      end
      local info, sub = dissect_pdu(ptvb, pinfo, tree, dir, st, pinfo.number .. ":s" .. i, p.kind)
      if info then infos[#infos + 1] = info end
      if p.first ~= pinfo.number then
        generated(sub, f.reasm_from, p.first)
        generated(sub, f.reasm_len, #p.data)
      end
    end
  end
  if #infos == 0 then
    pinfo.cols.protocol = "SEL ASCII"
    pinfo.cols.info = "Fragment (incomplete)"
  end
  set_columns(pinfo, infos)
  return tvb:len()
end

local function dissect_any(tvb, pinfo, tree)
  if tvb:len() == 0 then return 0 end
  if pinfo.port_type == PT_TCP then return dissect_tcp(tvb, pinfo, tree) end
  return dissect_stream(tvb, pinfo, tree)
end

function selascii.dissector(tvb, pinfo, tree)
  return dissect_any(tvb, pinfo, tree)
end

-------------------------------------------------------------------------------
-- Heuristics
-------------------------------------------------------------------------------
local function heur_tcp(tvb, pinfo, tree)
  local raw = tvb:raw()
  local key = tcp_stream_key(pinfo)
  local st = streams[key]
  if not (st and st.claim_frame) then
    -- The claim is decided on the first pass, at the first frame that matches
    if pinfo.visited or not looks_like_sel(heuristic_text(raw)) then return false end
    st = get_stream(key)
    st.claim_frame = pinfo.number
  elseif pinfo.number < st.claim_frame then
    return false
  end
  if not pinfo.visited and not st.telnet_since and raw:find("\255[\250-\254]") then
    st.telnet_since = pinfo.number
  end
  pinfo.conversation = selascii
  dissect_any(tvb, pinfo, tree)
  return true
end

local function heur_usb(tvb, pinfo, tree)
  local key = stream_key(pinfo)
  local claimed = usb_claimed[key]
  if not claimed or pinfo.number < claimed then
    if not looks_like_sel(tvb:raw()) then return false end
    if not pinfo.visited then usb_claimed[key] = pinfo.number end
  end
  dissect_any(tvb, pinfo, tree)
  return true
end

selascii:register_heuristic("tcp", heur_tcp)
pcall(function() selascii:register_heuristic("usb.bulk", heur_usb) end)

-------------------------------------------------------------------------------
-- Registration
-------------------------------------------------------------------------------
local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add_for_decode_as(selascii)
local rtac_table = DissectorTable.get("rtacser.data")
if rtac_table then rtac_table:add_for_decode_as(selascii) end

-- LINKTYPE_RTAC_SERIAL: a thin wrapper around the built-in "rtacser" dissector.
-- It records the RTAC event type (transmit or receive) of each record, so SEL
-- ASCII knows the direction also through Decode As, where Field extractors are
-- not reliable. With the rtac_default preference it decodes the payload itself.
local selascii_rtac = Proto("selascii_rtac", "SEL ASCII RTAC serial wrapper")
function selascii_rtac.dissector(tvb, pinfo, tree)
  if tvb:len() < 12 then
    call_dissector(rtacser_handle, tvb, pinfo, tree)
    return tvb:len()
  end
  current_rtac_event = tvb(8, 1):uint()
  local ok, err = pcall(function()
    if selascii.prefs.rtac_default and tvb:len() > 12 then
      call_dissector(rtacser_handle, tvb(0, 12):tvb(), pinfo, tree)
      dissect_stream(tvb(12):tvb(), pinfo, tree)
    else
      call_dissector(rtacser_handle, tvb, pinfo, tree)
    end
  end)
  current_rtac_event = nil
  if not ok then error(err, 0) end
  return tvb:len()
end
local wtap_table = DissectorTable.get("wtap_encap")
local rtac_encap = wtap_encaps and wtap_encaps.RTAC_SERIAL
if wtap_table and rtac_encap and rtacser_handle then
  wtap_table:add(rtac_encap, selascii_rtac)
end

local registered_ports = ""
function selascii.prefs_changed()
  local ports = tostring(selascii.prefs.tcp_ports)
  if ports ~= registered_ports then
    if registered_ports ~= "" then tcp_table:remove(registered_ports, selascii) end
    if ports ~= "" then tcp_table:add(ports, selascii) end
    registered_ports = ports
    tcp_port_set = parse_ports(ports)
  end
  if selascii.prefs.wrap_telnet then
    tcp_table:add(23, selascii)
  elseif telnet_handle then
    tcp_table:add(23, telnet_handle)
  end
end
tcp_table:add(23, selascii)

-- Wireshark ignores the value returned by a plugin; the unit tests use it.
return {
  _test = {
    trim = trim, sum16 = sum16, parse_cascii = parse_cascii, telnet_clean = telnet_clean,
    clean_to_raw = clean_to_raw, clean_end_to_raw = clean_end_to_raw,
    find_pdu_end = find_pdu_end, parse_message = parse_message, group_records = group_records,
    find_error = find_error, prompt_level = prompt_level, is_password_prompt = is_password_prompt,
    request_line = request_line, classify = classify, changes_state = changes_state,
    is_interactive = is_interactive, is_factory_password = is_factory_password,
    ymodem_info = ymodem_info, looks_like_sel = looks_like_sel, parse_ports = parse_ports,
    CAT = { ACCESS = CAT_ACCESS, READ = CAT_READ, CONTROL = CAT_CONTROL,
      SETTINGS = CAT_SETTINGS, MAINT = CAT_MAINT, FIRMWARE = CAT_FIRMWARE },
  },
}
