# SEL ASCII dissector for Wireshark

`selascii.lua` is a Wireshark Lua plugin for the text command interface of
Schweitzer Engineering Laboratories (SEL) protection relays, RTACs and
communications processors ("SEL ASCII"), including Compressed ASCII. It is part
of PEAT, but it is a single file that works without PEAT.

For each message it shows:

- **Requests**: the command line, the 3-character mnemonic with a short
  description and a category (read, access level, settings change, control,
  maintenance, firmware), the arguments, answers to device questions and
  passwords (masked).
- **Responses**: the list of response lines, the access level prompt
  (`=`, `=>`, `==>`, `=>>`, `==>>`, the SEL-400 `P=>`/`A=>`/`O=>`, the SEL-2030/2032
  `*` prompts and the SELBOOT `!>` prompt), password prompts and questions such as
  `Save changes (Y,N)?`, device errors such as `Invalid Command`, and the frame of
  the command they answer.
- **Compressed ASCII**: every record with its fields, its checksum, the
  calculated checksum and the checksum status. The ID command output is split
  into keys and values, with the firmware ID (FID), part number and IEC 61850
  `iedName` available as their own fields.
- **Other content of the same stream**: SEL Fast binary messages (`0xA5 ...`)
  are passed to Wireshark's built-in "SEL Protocol" (`selfm`) dissector, YMODEM
  blocks of `FILE READ`/`FILE WRITE` transfers show the block number and the file
  name, and XON/XOFF flow control is labeled.

Messages split over several TCP segments, serial records or USB transfers are
reassembled. The plugin only reads captures; it never sends anything.

## Installation

Requires Wireshark 4.2 or newer (Lua 5.2, 5.3 or 5.4).

1. Copy `selascii.lua` into your personal Lua plugins folder:
   - Linux and macOS: `~/.local/lib/wireshark/plugins/`
   - Windows: `%APPDATA%\Wireshark\plugins\`

   *Help > About Wireshark > Folders* shows the exact "Personal Lua Plugins" path.
2. Restart Wireshark, or use *Analyze > Reload Lua Plugins*.
3. *Help > About Wireshark > Plugins* now lists `selascii.lua`.

To use it once without installing: `wireshark -X lua_script:selascii.lua capture.pcap`
(the same option works with `tshark`).

Wireshark does not load personal Lua plugins or `-X lua_script:` when it runs as
root. Run Wireshark as a normal user and let `dumpcap` capture with the needed
privileges.

## Capture recipes

### Telnet (TCP port 23)

Nothing to configure. The plugin takes over TCP port 23 and still shows the
normal Telnet tree. It adds the SEL ASCII tree from the first frame of a session
that looks like SEL ASCII, with the same rules as the TCP heuristic below. Other
Telnet sessions (switches, routers, servers) stay plain Telnet. Frames of an SEL
session before that point are not decoded, for example a login banner, or
commands typed in lower case before the first framed device response. To decode
a port 23 session from its first frame, add 23 to the "TCP ports" preference.
To leave port 23 to the Telnet dissector, turn off the "Decode Telnet port 23 as
SEL ASCII" preference; with *Try heuristic sub-dissectors first*
(`tcp.try_heuristic_first`) enabled, the heuristic still finds SEL sessions on
port 23.

### Other TCP ports (RTAC engineering access, SEL-3620, terminal servers)

A TCP heuristic (`selascii_tcp`) recognizes a session from its first SEL message
(framed device output, a valid Compressed ASCII record or a short SEL command in
upper case, such as `ID` or `ACC`).
If a session is not found, add its port to the "TCP ports" preference, or use
*Decode As...* on the TCP port. Telnet option negotiation is detected and removed
on any port. The heuristic can be turned off in *Analyze > Enabled Protocols*
or with `--disable-heuristic selascii_tcp`.

### RTAC Communication Monitor (LINKTYPE_RTAC_SERIAL, 250)

Captures saved from an SEL RTAC's Communication Monitor use the
LINKTYPE_RTAC_SERIAL link type, which Wireshark decodes as "RTAC Serial". To
decode the serial payload as SEL ASCII, either enable the "Decode RTAC serial
payloads as SEL ASCII" preference, or use *Decode As...* on the RTAC Serial
payload. With tshark: `-o selascii.rtac_default:TRUE` or `-d rtacser.data,selascii`.

RTAC transmit events are treated as requests to the device (the RTAC is the
master on the port). Turn off "RTAC transmit is a request" when the RTAC port is
the device side of the conversation.

Older RTAC captures use DLT 147 (USER0). Map them in *Edit > Preferences >
Protocols > DLT_USER* with header size 12, header protocol `rtacser` and payload
protocol `selascii`.

### Serial ports (EIA-232) with socat

On Linux and macOS, [socat](http://www.dest-unreach.org/socat/) can sit between
the application and the device and log every byte in both directions:

```bash
# /dev/ttyUSB0 is the adapter cabled to the relay; use the relay port's speed
socat -x -v PTY,link=/tmp/ttySEL,rawer /dev/ttyUSB0,b9600,cs8,rawer 2> sel.log
```

Point the application at `/tmp/ttySEL` (for example
`peat pull -d selrelay -s /tmp/ttySEL --baudrates 9600`, or a terminal program),
stop socat with Ctrl+C, and convert the log:

```bash
python3 socat2pcap.py sel.log sel.pcap           # exported PDUs (link type 252)
python3 socat2pcap.py --rtac sel.log sel.pcap    # LINKTYPE_RTAC_SERIAL (250)
```

The default output names the `selascii` dissector in every record, so Wireshark
decodes it without configuration. `socat2pcap.py` only needs Python 3; `--swap`
handles transcripts where the device is the first socat address, and `--utc`
reads the socat timestamps as UTC instead of local time.

### Serial captures without direction (DLT_USER)

Tools such as SerialPCAP write DLT 147 (USER0) captures with no direction
information. Map the link type in *Edit > Preferences > Protocols > DLT_USER* to
payload protocol `selascii`, or with tshark:
`-o 'uat:user_dlts:"User 0 (DLT=147)","selascii","0","","0",""'`.
The direction then comes from the content: device output is framed with
STX/ETX, typed commands are not.

### USB (SEL front-panel USB ports and USB serial adapters)

SEL front-panel USB ports are USB CDC class devices. Capture the USB bus with
`usbmon` on Linux (`sudo modprobe usbmon`, then capture the `usbmonN` interface
of the bus shown by `lsusb`) or with USBPcap on Windows. A USB bulk heuristic
(`selascii_usb.bulk`) claims a device once it sees SEL output from it.
This also covers USB serial adapters that pass the serial bytes through unchanged
(CDC-ACM, and from Wireshark's USB code also Prolific and Silicon Labs chips; not
yet tested with hardware), which makes USBPcap an option for serial captures on
Windows. FTDI-based adapters do not work: Wireshark's FTDI dissector consumes
their data, so use socat with those.

## Display filter examples

| Filter | Shows |
|---|---|
| `selascii` | All SEL ASCII messages |
| `selascii.cmd == "ACC"` | `ACC` commands |
| `selascii.cmd.changes_state` | Commands that change settings, operate equipment, reset data or load firmware |
| `selascii.cmd.operates_equipment` | Commands that operate equipment (`OPE`, `CLO`, `PUL`, `CON`, Fast Operate) |
| `selascii.password` | Passwords sent to the device |
| `selascii.password.factory_default` | Factory-default passwords |
| `selascii.access_level == "2"` | Prompts at access level 2 |
| `selascii.error` | Device errors |
| `selascii.cascii.checksum.status == 0` | Compressed ASCII records with a bad checksum |
| `selascii.id.fid` | ID output, with the firmware ID |
| `selascii.line contains "Powered Up"` | Response lines with some text |

Other fields: `selascii.command`, `selascii.args`, `selascii.cmd.category`,
`selascii.input`, `selascii.question`, `selascii.prompt`,
`selascii.session_level` (level when a request was sent), `selascii.response_to`,
`selascii.request_in`, `selascii.response_in`, `selascii.cascii.field`,
`selascii.id.key`, `selascii.id.value`, `selascii.id.partno`,
`selascii.id.iedname`, `selascii.fast.type`, `selascii.ymodem.block`,
`selascii.ymodem.filename` and `selascii.reassembled_in`.

Expert information: password sent in cleartext, factory-default password, access
level changed, command operates equipment, command changes device state, device
error, bad Compressed ASCII checksum, message not terminated, embedded frame
that could not be decoded, and Telnet subnegotiation not terminated.

## Preferences

| Preference | Default | Meaning |
|---|---|---|
| TCP ports (`selascii.tcp_ports`) | none | TCP ports that carry SEL ASCII without Telnet |
| Decode Telnet port 23 as SEL ASCII (`selascii.wrap_telnet`) | on | Take over TCP port 23 and decode the sessions that look like SEL ASCII |
| Decode RTAC serial payloads as SEL ASCII (`selascii.rtac_default`) | off | No Decode As rule needed for RTAC captures |
| RTAC transmit is a request (`selascii.rtac_tx_is_request`) | on | Direction of RTAC transmit events |
| Show passwords (`selascii.show_passwords`) | off | Show passwords instead of `*****` |
| Maximum message size (`selascii.max_pdu`) | 1048576 | Stop waiting for the end of a message after this many bytes |

## Passwords and safety

- SEL ASCII has no encryption. **Passwords travel in cleartext**, and every
  capture of an SEL ASCII session that logs in contains them. Masking only
  changes the protocol tree: the bytes are still in the capture. Handle captures
  as sensitive data, and do not share them without removing the sessions'
  passwords. The factory-default password expert is a prompt to change those
  passwords on the device.
- Prefer passive capture points (a SPAN port, the RTAC Communication Monitor).
  socat puts a process in the serial path: if it stops, the application loses
  its connection. Do not insert it on a port that an RTAC or SCADA master polls
  without coordinating with the people who operate the system.

## Limitations

- The dissector has been tested with synthetic captures modeled on public SEL
  documentation. Echo and framing details may vary by device family; reports and
  sample captures from real devices are welcome.
- A question is recognized by its last line ending in `?`. Access level
  commands take one password per password prompt and `PAS` up to three (old,
  new and confirmation); these may be typed ahead of their prompts, also after
  other pipelined commands. A further line typed ahead of the level prompt, for
  example a second guess at a password, is masked unless it starts with an SEL
  command mnemonic, in which case it is shown as a command. Request lines sent
  while a settings, control or maintenance command waits for its level prompt
  are treated as answers.
- A Telnet subnegotiation (`IAC SB`) without `IAC SE` is waited for over one more
  segment at most; after that it is shown as unterminated and the rest of the
  segment is decoded.
- The checksum rule for Compressed ASCII records that span several lines (for
  example the settings in a `CEV` report) is not documented; such records are
  marked "Unverified" when the checksum does not match.
- SEL Fast messages are decoded by Wireshark's `selfm` dissector; its own
  preferences apply.

## Tests

From the root of the PEAT repository, as a normal user:

```bash
pdm run pytest tests/test_wireshark_dissector.py
lua5.4 tests/wireshark/selascii_unit.lua distribution/wireshark/selascii.lua
```

The pytest tests build synthetic captures, run tshark with the plugin and compare
the output with the files in `tests/wireshark/golden/`. After an intended change,
regenerate them with `SELASCII_UPDATE_GOLDEN=1` and review the diff.

## License

GPL-3.0-only, like the rest of PEAT. Copyright 2026 National Technology &
Engineering Solutions of Sandia, LLC (NTESS). See `LICENSE` and `COPYRIGHT.rst`
at the root of the repository.
