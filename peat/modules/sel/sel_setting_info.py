"""
Full names, descriptions, allowed values, and units of SEL relay settings
and SELOGIC control equations.

Many SEL settings files only have the name and value of each setting
(``NETMODE,"FAILOVER"``), and the names are short mnemonics. This module
annotates the settings records from
:func:`~peat.modules.sel.relay_parse.settings_to_records` with:

- ``full_name``: a short name, e.g. ``"Ethernet operating mode"``
- ``description``: what the setting does
- ``allowed_values``: the values or ranges the setting can have, e.g.
  ``["FIXED", "FAILOVER", "SWITCHED"]`` or ``["23", "1025-65534"]``
- ``units``: e.g. ``"min"``, ``"s"``, ``"cycles"``
- ``security``: if the setting enables a network service or limits access
  (e.g. Telnet, FTP, the maximum access level of a port)

Where the information comes from, in order of precedence:

#. The device: the description and range columns of the settings file
   (most 400-series files have these). A device description is never replaced.
#. A user file with the same format as :data:`SETTING_INFO`
   (the ``sel.setting_descriptions_file`` option), e.g. made from the manuals
   for the user's own relays.
#. :data:`SETTING_INFO`: PEAT's descriptions of about 200 common and
   security-relevant settings, with values for a model (e.g. ``351S``)
   taking precedence over values for a family (``3xx``, ``4xx``, ``7xx``).
#. Patterns for numbered settings (:data:`PATTERN_INFO`, e.g. ``SV05``,
   ``OUT403``, ``PCT03PU``), protection element settings (``50P1P`` is
   the pickup of phase instantaneous overcurrent level 1), and element
   enables (``E87M``), using the names in :mod:`peat.modules.sel.sel_elements`.

Provenance: the descriptions are written by PEAT authors. Setting names,
allowed values, ranges and units are facts from the settings sheets and
settings tables of these public SEL instruction manuals: SEL-351S (date code
20171023), SEL-421 (20130627), SEL-487B (20090519), SEL-700G (20150521),
SEL-710 (20090327), SEL-751A (20130329) and SEL-787 (20150130). Values change
between firmware versions, so the values of the device's own range column
are used when it has them. Don't add text copied from the manuals here.

Authors

- Christopher Goes
"""

import json
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, Final

from peat import log

from .sel_elements import ELEMENT_ENABLE_RE, ansi_name, element_name
from .sel_logic import RelayFamily, logic_assignment

#: Information about a setting. All keys are optional:
#:
#: - ``name``: full name of the setting
#: - ``desc``: description, in PEAT's own words
#: - ``values``: allowed values, as a string (``"Y, N"``, ``"OFF, 1-30"``) or a list
#: - ``units``: units of the value, e.g. ``"min"``
#: - ``security``: True if the setting enables a service or limits access
#: - ``sections``: regular expression for the settings classes (sections) the
#:   entry applies to, e.g. ``^P`` for the ports. The entry applies to every
#:   class if this isn't set, or if the class isn't known.
#: - ``only``: families the entry applies to, e.g. ``["4xx"]``
#: - ``by_family``: dict of family (``3xx``, ``4xx``, ``7xx``) to keys that
#:   are different for that family
#: - ``by_model``: dict of model (e.g. ``351S``) to keys that are different
#:   for that model. These take precedence over ``by_family``.
SettingEntry = dict[str, Any]

#: Fields of an entry that are copied into an annotation
ENTRY_FIELDS: Final = ("name", "desc", "values", "units", "security")

#: Fields that are added to a settings record by :func:`annotate_record`
ANNOTATION_FIELDS: Final = (
    "full_name",
    "description_source",
    "allowed_values",
    "allowed_values_source",
    "units",
    "security",
)

# Settings classes (sections)
_PORT: Final = r"^P(?:\d+|F)$"
_GROUP: Final = r"^S?\d$"
_GLOBAL: Final = r"^G\d*$"
_FRONT: Final = r"^F\d*$"
_REPORT: Final = r"^R\d*$"
_LOGIC: Final = r"^L\d*$"
_INFO: Final = r"^INFO$"
_MODBUS_MAP: Final = r"^M$"

_Y_N: Final = "Y, N"
_FAMILIES_3_7: Final = ("3xx", "7xx")

#: Names of the settings classes (sections), by family. The meaning of
#: some letters depends on the family: ``M`` is the Modbus map on 300- and
#: 700-series relays and the breaker monitor on 400-series relays, and
#: ``T`` is text labels on 300-series and aliases on 400-series relays.
CLASS_NAMES: Final[dict[str, dict[str, str]]] = {
    "3xx": {
        "G": "Global",
        "R": "Report",
        "T": "Text labels",
        "M": "Modbus map",
        "PF": "Port F",
    },
    "4xx": {
        "G": "Global",
        "R": "Report",
        "F": "Front panel",
        "M": "Breaker monitor",
        "T": "Alias",
        "O": "Output",
        "D": "DNP3 map",
        "N": "Notes",
        "B": "Bay control",
        "PF": "Port F",
    },
    "7xx": {
        "G": "Global",
        "R": "Report",
        "F": "Front panel",
        "M": "Modbus map",
        "PF": "Port F",
    },
}

#: PEAT's information about common and security-relevant SEL relay settings,
#: keyed by setting name. See :data:`SettingEntry` for the format.
SETTING_INFO: Final[dict[str, SettingEntry]] = {
    # --- Device information ([INFO]) ---
    "RELAYTYPE": {
        "name": "Relay type",
        "desc": "Relay model the settings are for.",
        "sections": _INFO,
    },
    "FID": {
        "name": "Firmware identifier",
        "desc": "Firmware ID string: model, release, point release, settings version and date.",
        "sections": _INFO,
    },
    "BFID": {
        "name": "Boot firmware identifier",
        "desc": "Firmware ID string of the boot loader.",
        "sections": _INFO,
    },
    "PARTNO": {
        "name": "Part number",
        "desc": "Ordering part number, which encodes the hardware options.",
        "sections": _INFO,
    },
    # --- Serial ports (SET P) ---
    "EPORT": {
        "name": "Port enable",
        "desc": "Turns the port on or off. N disables all communications on the port.",
        "values": _Y_N,
        "security": True,
        "sections": _PORT,
    },
    "PROTO": {
        "name": "Port protocol",
        "desc": (
            "Protocol of the port. SEL is the SEL ASCII command line (with SEL Fast and "
            "Compressed ASCII messages), LMD is SEL distributed port switch (multidrop), DNP is "
            "DNP3, MOD is Modbus RTU, MBA, MBB, MB8A, MB8B, MBTA and MBTB are MIRRORED BITS "
            "channels, EVMSG is the event messenger, PMU is IEEE C37.118 synchrophasors, RTD is "
            "an external RTD module, and DNET is DeviceNet. "
            "The protocols that are available depend on the model and the port."
        ),
        "security": True,
        "sections": _PORT,
    },
    "MAXACC": {
        "name": "Maximum access level",
        "desc": (
            "Highest access level that can be reached on the port. A lower level keeps users of "
            "the port from changing settings or controlling the relay."
        ),
        "security": True,
        "sections": _PORT,
        "by_model": {"351S": {"values": "0, 1, B, 2, C"}},
        "by_family": {"4xx": {"values": "1, B, P, A, O, 2, C"}},
    },
    "SPEED": {
        "name": "Baud rate",
        "desc": "Data rate of the serial port.",
        "units": "bps",
        "sections": _PORT,
        "by_family": {
            "7xx": {"values": "300, 1200, 2400, 4800, 9600, 19200, 38400"},
            "4xx": {
                "values": "300, 600, 1200, 2400, 4800, 9600, 19200, 38400, 57600, SYNC",
                "desc": "Data rate of the serial port. SYNC is only for MIRRORED BITS.",
            },
        },
        "by_model": {"351S": {"values": "300, 1200, 2400, 4800, 9600, 19200, 38400, 57600"}},
    },
    "BITS": {
        "name": "Data bits",
        "desc": "Number of data bits in each serial character.",
        "sections": _PORT,
        "by_family": {"7xx": {"values": "7, 8"}},
        "by_model": {"351S": {"values": "6, 7, 8"}},
    },
    "DATABIT": {
        "name": "Data bits",
        "desc": "Number of data bits in each serial character.",
        "sections": _PORT,
        "by_family": {"4xx": {"values": "7, 8"}},
    },
    "PARITY": {
        "name": "Parity",
        "desc": "Serial parity: O is odd, E is even, and N is none.",
        "values": "O, E, N",
        "sections": _PORT,
    },
    "STOP": {
        "name": "Stop bits",
        "desc": "Number of stop bits in each serial character.",
        "values": "1, 2",
        "sections": _PORT,
    },
    "STOPBIT": {
        "name": "Stop bits",
        "desc": "Number of stop bits in each serial character.",
        "values": "1, 2",
        "sections": _PORT,
    },
    "T_OUT": {
        "name": "Port time-out",
        "desc": (
            "Minutes without activity before the relay ends the session on the port and drops it "
            "to access level 0. 0 means sessions never time out."
        ),
        "units": "min",
        "security": True,
        "sections": _PORT,
        "only": _FAMILIES_3_7,
        "values": "0-30",
    },
    "TIMEOUT": {
        "name": "Port time-out",
        "desc": (
            "Minutes without activity before the relay ends the session on the port and drops it "
            "to access level 0. OFF means sessions never time out."
        ),
        "units": "min",
        "security": True,
        "sections": _PORT,
        "by_family": {"4xx": {"values": "OFF, 1-60"}},
    },
    "AUTO": {
        "name": "Automatic messages",
        "desc": (
            "If the relay sends unsolicited messages, such as event summaries and status "
            "warnings, to the port."
        ),
        "sections": _PORT,
        "values": _Y_N,
        "by_model": {"351S": {"values": "Y, N, DTA"}},
    },
    "RTSCTS": {
        "name": "Hardware handshaking",
        "desc": "RTS/CTS hardware flow control on the serial port.",
        "values": _Y_N,
        "sections": _PORT,
    },
    "FASTOP": {
        "name": "Fast Operate",
        "desc": (
            "If the port accepts SEL Fast Operate messages, binary commands that operate the "
            "breaker and remote bits."
        ),
        "values": _Y_N,
        "security": True,
        "sections": _PORT,
    },
    "COMMINF": {
        "name": "Communications interface",
        "desc": "Electrical interface of the serial port, e.g. 232 (EIA-232) or 485 (EIA-485).",
        "sections": _PORT,
    },
    "SLAVEID": {
        "name": "Modbus slave ID",
        "desc": "Modbus RTU address of the relay on the port.",
        "values": "1-247",
        "sections": _PORT,
    },
    "PREFIX": {
        "name": "LMD prefix",
        "desc": "Character that starts an SEL distributed port switch (LMD) address.",
        "values": "@, #, $, %, &",
        "sections": _PORT,
        "only": ("3xx",),
    },
    "ADDR": {
        "name": "LMD address",
        "desc": "Address of the relay on an SEL distributed port switch (LMD) network.",
        "values": "1-99",
        "sections": _PORT,
        "only": ("3xx",),
    },
    "SETTLE": {
        "name": "LMD settling time",
        "desc": "Time the relay waits after the LMD address before it sends data.",
        "values": "0.00-30.00",
        "units": "s",
        "sections": _PORT,
        "only": ("3xx",),
    },
    "TXID": {
        "name": "MIRRORED BITS transmit ID",
        "desc": "Identifier the relay puts in the MIRRORED BITS messages it sends.",
        "values": "1-4",
        "sections": _PORT,
    },
    "RXID": {
        "name": "MIRRORED BITS receive ID",
        "desc": "Identifier the relay expects in the MIRRORED BITS messages it receives.",
        "values": "1-4",
        "sections": _PORT,
    },
    "RBADPU": {
        "name": "MIRRORED BITS receive bad pickup",
        "desc": (
            "How long received MIRRORED BITS messages have to be bad before the relay reports "
            "the channel as bad."
        ),
        "units": "s",
        "sections": _PORT,
        "by_family": {"7xx": {"values": "0-10000"}},
        "by_model": {"351S": {"values": "1-10000"}},
    },
    "CBADPU": {
        "name": "MIRRORED BITS channel bad pickup",
        "desc": "Error rate of the MIRRORED BITS channel at which the relay reports it as bad.",
        "values": "1-10000",
        "units": "ppm",
        "sections": _PORT,
    },
    "RXDFLT": {
        "name": "MIRRORED BITS receive default",
        "desc": (
            "States (1, 0, or X to keep the last value) of the eight received MIRRORED BITS when "
            "the channel fails."
        ),
        "sections": _PORT,
    },
    "TERTIM1": {
        "name": "Transparent termination idle time",
        "desc": (
            "Seconds a transparent (pass-through) connection has to be idle before the relay "
            "looks for the termination string."
        ),
        "units": "s",
        "sections": _PORT,
    },
    "TERSTRN": {
        "name": "Transparent termination string",
        "desc": (
            "Characters that end a transparent (pass-through) connection. The usual default is "
            "Ctrl+E (\\005)."
        ),
        "sections": _PORT,
    },
    "TERTIM2": {
        "name": "Transparent termination wait",
        "desc": (
            "Seconds the connection has to be idle after the termination string before the relay "
            "ends it."
        ),
        "units": "s",
        "sections": _PORT,
    },
    # --- Ethernet ports (P1 on most 700-series, P4 on some, P5 on 300- and 400-series) ---
    "IPADDR": {
        "name": "IP address",
        "desc": (
            "IPv4 address of the Ethernet port. Some 400-series relays include the prefix length "
            "(192.0.2.10/24)."
        ),
        "sections": _PORT,
    },
    "SUBNETM": {
        "name": "Subnet mask",
        "desc": "IPv4 subnet mask of the Ethernet port.",
        "sections": _PORT,
    },
    "DEFRTR": {
        "name": "Default router",
        "desc": "IPv4 address of the default gateway.",
        "sections": _PORT,
    },
    "ETCPKA": {
        "name": "TCP keep-alive",
        "desc": "If the relay sends TCP keep-alive probes on idle connections.",
        "values": _Y_N,
        "sections": _PORT,
    },
    "KAIDLE": {
        "name": "TCP keep-alive idle time",
        "desc": "Seconds a connection has to be idle before the first keep-alive probe.",
        "values": "1-20",
        "units": "s",
        "sections": _PORT,
    },
    "KAINTV": {
        "name": "TCP keep-alive interval",
        "desc": "Seconds between keep-alive probes when there's no answer.",
        "values": "1-20",
        "units": "s",
        "sections": _PORT,
    },
    "KACNT": {
        "name": "TCP keep-alive count",
        "desc": "Number of unanswered keep-alive probes before the relay closes the connection.",
        "values": "1-20",
        "sections": _PORT,
    },
    "NETMODE": {
        "name": "Ethernet operating mode",
        "desc": (
            "How the two Ethernet ports are used. FIXED only uses the port in NETPORT, "
            "FAILOVER switches to the other port when the active link is down for FTIME, "
            "SWITCHED connects both ports to an internal switch, and PRP sends every frame on "
            "both ports (IEC 62439-3 Parallel Redundancy Protocol). Some later 400-series "
            "firmware also has ISOLATEIP (GOOSE on both ports, other traffic only on NETPORT)."
        ),
        "sections": _PORT,
        "by_family": {"7xx": {"values": "FIXED, FAILOVER, SWITCHED"}},
        "by_model": {"351S": {"values": "FIXED, FAILOVER, SWITCHED, PRP"}},
    },
    "FAILOVR": {
        "name": "Automatic failover",
        "desc": "If the relay switches to the other Ethernet port when the active link fails.",
        "values": _Y_N,
        "sections": _PORT,
    },
    "FTIME": {
        "name": "Failover time-out",
        "desc": (
            "How long the active link has to be down before the relay switches to the other "
            "Ethernet port."
        ),
        "sections": _PORT,
        "by_family": {
            "7xx": {"values": "0.10-65.00", "units": "s"},
            "4xx": {"values": "5-65535", "units": "ms"},
        },
        "by_model": {"351S": {"values": "OFF, 0.10-65.00", "units": "s"}},
    },
    "NETPORT": {
        "name": "Primary network port",
        "desc": (
            "Ethernet port that's used (FIXED) or preferred (FAILOVER). D disables all of the "
            "network ports."
        ),
        "sections": _PORT,
        "by_family": {"7xx": {"values": "A, B, D"}, "4xx": {"values": "A, B, D"}},
        "by_model": {"351S": {"values": "A, B"}},
    },
    "NETASPD": {
        "name": "Port A speed",
        "desc": "Link speed of Ethernet port A, or automatic negotiation.",
        "units": "Mbps",
        "sections": _PORT,
        "by_family": {"7xx": {"values": "AUTO, 10, 100"}, "4xx": {"values": "A, 10, 100"}},
    },
    "NETBSPD": {
        "name": "Port B speed",
        "desc": "Link speed of Ethernet port B, or automatic negotiation.",
        "units": "Mbps",
        "sections": _PORT,
        "by_family": {"7xx": {"values": "AUTO, 10, 100"}, "4xx": {"values": "A, 10, 100"}},
    },
    "NET5ASPD": {
        "name": "Port 5A speed",
        "desc": "Link speed of Ethernet port 5A, or automatic negotiation.",
        "values": "AUTO, 10, 100",
        "units": "Mbps",
        "sections": _PORT,
    },
    "NET5BSPD": {
        "name": "Port 5B speed",
        "desc": "Link speed of Ethernet port 5B, or automatic negotiation.",
        "values": "AUTO, 10, 100",
        "units": "Mbps",
        "sections": _PORT,
    },
    "PRPTOUT": {
        "name": "PRP entry time-out",
        "desc": "How long the relay remembers a received PRP frame, to drop its duplicate.",
        "values": "400-10000",
        "units": "ms",
        "sections": _PORT,
    },
    "PRPADDR": {
        "name": "PRP supervision address",
        "desc": "Last byte of the multicast address of PRP supervision frames.",
        "values": "0-255",
        "sections": _PORT,
    },
    "PRPINTV": {
        "name": "PRP supervision interval",
        "desc": "Time between PRP supervision frames.",
        "values": "1-10",
        "units": "s",
        "sections": _PORT,
    },
    "ETELNET": {
        "name": "Telnet server",
        "desc": (
            "If the relay accepts Telnet connections to its command line. Telnet isn't "
            "encrypted, so passwords are sent in the clear."
        ),
        "values": _Y_N,
        "security": True,
        "sections": _PORT,
    },
    "TPORT": {
        "name": "Telnet port",
        "desc": "TCP port of the Telnet server.",
        "values": "23, 1025-65534",
        "security": True,
        "sections": _PORT,
    },
    "TPORTC": {
        "name": "Telnet port for card access",
        "desc": "TCP port for Telnet sessions to the Ethernet card.",
        "security": True,
        "sections": _PORT,
    },
    "TIDLE": {
        "name": "Telnet time-out",
        "desc": "Minutes without activity before the relay closes a Telnet session.",
        "units": "min",
        "security": True,
        "sections": _PORT,
        "by_family": {
            "3xx": {"values": "1-30"},
            "7xx": {"values": "1-30"},
            "4xx": {
                "values": "0-255",
                "desc": (
                    "Minutes without activity before the relay closes a Telnet session. 0 means "
                    "sessions never time out."
                ),
            },
        },
    },
    "TCBAN": {
        "name": "Telnet connect banner",
        "desc": "Text the relay sends when a Telnet session connects.",
        "sections": _PORT,
    },
    "T1PNUM": {
        "name": "Host Telnet port",
        "desc": "TCP port for Telnet sessions to the relay's command line.",
        "values": "1-65534",
        "security": True,
        "sections": _PORT,
    },
    "T2PNUM": {
        "name": "Ethernet card Telnet port",
        "desc": "TCP port for Telnet sessions to the command line of the Ethernet card.",
        "values": "1-65534",
        "security": True,
        "sections": _PORT,
    },
    "T1CBAN": {
        "name": "Host Telnet connect banner",
        "desc": "Text sent when a Telnet session to the relay connects.",
        "sections": _PORT,
    },
    "T2CBAN": {
        "name": "Ethernet card Telnet connect banner",
        "desc": "Text sent when a Telnet session to the Ethernet card connects.",
        "sections": _PORT,
    },
    "T1INIT": {
        "name": "Telnet from host",
        "desc": (
            "If the relay can open Telnet sessions to other devices through the Ethernet card."
        ),
        "values": _Y_N,
        "security": True,
        "sections": _PORT,
    },
    "T1RECV": {
        "name": "Telnet to host",
        "desc": "If the Ethernet card accepts Telnet sessions to the relay's command line.",
        "values": _Y_N,
        "security": True,
        "sections": _PORT,
    },
    "T2RECV": {
        "name": "Telnet to Ethernet card",
        "desc": "If the Ethernet card accepts Telnet sessions to its own command line.",
        "values": _Y_N,
        "security": True,
        "sections": _PORT,
    },
    "EFTPSERV": {
        "name": "FTP server",
        "desc": (
            "If the relay accepts FTP connections, which can read the settings and other files. "
            "FTP isn't encrypted."
        ),
        "values": _Y_N,
        "security": True,
        "sections": _PORT,
    },
    "FTPSERV": {
        "name": "FTP server",
        "desc": (
            "If the relay accepts FTP connections, which can read the settings and other files. "
            "FTP isn't encrypted."
        ),
        "values": _Y_N,
        "security": True,
        "sections": _PORT,
    },
    "FTPUSER": {
        "name": "FTP user name",
        "desc": "User name for FTP logins. The factory default is FTPUSER.",
        "security": True,
        "sections": _PORT,
    },
    "FTPCBAN": {
        "name": "FTP connect banner",
        "desc": "Text the relay sends when an FTP session connects.",
        "sections": _PORT,
    },
    "FTPIDLE": {
        "name": "FTP time-out",
        "desc": "Minutes without activity before the relay closes an FTP session.",
        "values": "5-255",
        "units": "min",
        "security": True,
        "sections": _PORT,
    },
    "FTPANMS": {
        "name": "Anonymous FTP",
        "desc": "If FTP logins with the user name anonymous are allowed, without a password.",
        "values": _Y_N,
        "security": True,
        "sections": _PORT,
    },
    "FTPAUSR": {
        "name": "Anonymous FTP access",
        "desc": "Relay user (access level) whose rights the anonymous FTP user gets.",
        "security": True,
        "sections": _PORT,
    },
    "EHTTP": {
        "name": "Web server",
        "desc": "If the relay's web server (HTTP) is enabled.",
        "values": _Y_N,
        "security": True,
        "sections": _PORT,
    },
    "HTTPACC": {
        "name": "Web server maximum access level",
        "desc": "Highest access level that can be reached from the web server.",
        "security": True,
        "sections": _PORT,
        "by_model": {"351S": {"values": "1, 2"}},
    },
    "HTTPPORT": {
        "name": "Web server port",
        "desc": "TCP port of the web server.",
        "security": True,
        "sections": _PORT,
        "by_model": {"351S": {"values": "1-65535"}},
    },
    "HTTPIDLE": {
        "name": "Web server time-out",
        "desc": "Minutes without activity before the relay ends a web session.",
        "units": "min",
        "security": True,
        "sections": _PORT,
        "by_model": {"351S": {"values": "1-30"}},
    },
    "FWFPC": {
        "name": "Firmware upgrade front-panel confirmation",
        "desc": (
            "If firmware upgrades have to be confirmed on the front panel, so they can't be done "
            "only over the network."
        ),
        "values": _Y_N,
        "security": True,
        "sections": _PORT,
    },
    "E61850": {
        "name": "IEC 61850",
        "desc": "If the IEC 61850 protocol (MMS server) is enabled.",
        "values": _Y_N,
        "security": True,
        "sections": _PORT,
    },
    "EGSE": {
        "name": "IEC 61850 GOOSE",
        "desc": "If the relay sends and receives IEC 61850 GOOSE messages.",
        "values": _Y_N,
        "security": True,
        "sections": _PORT,
    },
    "EMMSFS": {
        "name": "MMS file services",
        "desc": "If IEC 61850 MMS clients can access files on the relay.",
        "values": _Y_N,
        "security": True,
        "sections": _PORT,
    },
    "EMOD": {
        "name": "Modbus TCP sessions",
        "desc": "Number of Modbus TCP sessions. 0 disables Modbus TCP.",
        "security": True,
        "sections": _PORT,
        "by_family": {"7xx": {"values": "0-2"}},
    },
    "MODNUM": {
        "name": "Modbus TCP port",
        "desc": "TCP port of a Modbus TCP session.",
        "security": True,
        "sections": _PORT,
        "by_family": {"7xx": {"values": "1-65534"}},
    },
    "MTIMEO": {
        "name": "Modbus session time-out",
        "desc": "Seconds without a Modbus request before the relay closes the session.",
        "values": "15-900",
        "units": "s",
        "sections": _PORT,
    },
    "EDNP": {
        "name": "DNP3 sessions",
        "desc": "Number of DNP3 sessions over Ethernet. 0 disables DNP3 over Ethernet.",
        "security": True,
        "sections": _PORT,
        "by_family": {"7xx": {"values": "0-3"}},
        "by_model": {"351S": {"values": "0-6"}},
    },
    "DNPNUM": {
        "name": "DNP3 port",
        "desc": "TCP and UDP port of the DNP3 server.",
        "values": "1-65534",
        "security": True,
        "sections": _PORT,
    },
    "DNPADR": {
        "name": "DNP3 address",
        "desc": "DNP3 outstation address of the relay.",
        "values": "0-65519",
        "sections": _PORT,
    },
    "DNPID": {
        "name": "DNP3 device ID",
        "desc": "Identifier the relay reports in DNP3 device attributes.",
        "sections": _PORT,
    },
    "DNPIP": {
        "name": "DNP3 master IP address",
        "desc": "IP address of the DNP3 master of the session.",
        "security": True,
        "sections": _PORT,
    },
    "DNPTR": {
        "name": "DNP3 transport",
        "desc": "Transport protocol of the DNP3 session.",
        "values": "UDP, TCP",
        "sections": _PORT,
    },
    "DNPUDP": {
        "name": "DNP3 UDP response port",
        "desc": "UDP port the relay sends responses to. REQ means the port the request came from.",
        "values": "REQ, 1-65534",
        "sections": _PORT,
    },
    "REPADR": {
        "name": "DNP3 master address",
        "desc": "DNP3 address of the master the relay reports to.",
        "values": "0-65519",
        "sections": _PORT,
    },
    "DNPMAP": {"name": "DNP3 map", "desc": "DNP3 point map the session uses.", "sections": _PORT},
    "UNSOL": {
        "name": "Unsolicited reporting",
        "desc": "If the relay sends unsolicited DNP3 event reports to the master.",
        "values": _Y_N,
        "sections": _PORT,
    },
    "PUNSOL": {
        "name": "Unsolicited reporting at power-up",
        "desc": "If unsolicited DNP3 reporting is on when the relay starts.",
        "values": _Y_N,
        "sections": _PORT,
    },
    "NUM1EVE": {
        "name": "Unsolicited event count",
        "desc": "Number of events that triggers an unsolicited DNP3 report.",
        "sections": _PORT,
    },
    "AGE1EVE": {
        "name": "Unsolicited event age",
        "desc": "Age of the oldest event that triggers an unsolicited DNP3 report.",
        "units": "s",
        "sections": _PORT,
    },
    "URETRY": {
        "name": "Unsolicited retries",
        "desc": "Number of times the relay resends an unconfirmed unsolicited report.",
        "values": "2-10",
        "sections": _PORT,
    },
    "UTIMEO": {
        "name": "Unsolicited offline time-out",
        "desc": "Seconds the relay waits before it tries the master again after the retries fail.",
        "values": "1-5000",
        "units": "s",
        "sections": _PORT,
    },
    "ECLASSB": {
        "name": "Binary event class",
        "desc": "DNP3 event class of binary input events. 0 disables them.",
        "sections": _PORT,
        "by_family": {"7xx": {"values": "0-3"}},
    },
    "ECLASSC": {
        "name": "Counter event class",
        "desc": "DNP3 event class of counter events. 0 disables them.",
        "sections": _PORT,
        "by_family": {"7xx": {"values": "0-3"}},
    },
    "ECLASSA": {
        "name": "Analog event class",
        "desc": "DNP3 event class of analog input events. 0 disables them.",
        "sections": _PORT,
        "by_family": {"7xx": {"values": "0-3"}},
    },
    "TIMERQ": {
        "name": "Time-sync request interval",
        "desc": "How often the relay asks the DNP3 master to set its clock.",
        "values": "I, M, 1-32767",
        "units": "min",
        "sections": _PORT,
    },
    "STIMEO": {
        "name": "Select/operate time-out",
        "desc": "Seconds allowed between a DNP3 select and the operate that follows it.",
        "values": "0.0-30.0",
        "units": "s",
        "sections": _PORT,
    },
    "DNPINA": {
        "name": "Link heartbeat interval",
        "desc": "Seconds of inactivity before the relay checks the link to the DNP3 master.",
        "values": "0-7200",
        "units": "s",
        "sections": _PORT,
    },
    "ETIMEO": {
        "name": "Event confirmation time-out",
        "desc": "Seconds the relay waits for the master to confirm an event message.",
        "values": "1-50",
        "units": "s",
        "sections": _PORT,
    },
    "ESNTP": {
        "name": "SNTP client",
        "desc": (
            "How the relay gets the time with SNTP: OFF, UNICAST (asks the servers), MANYCAST or "
            "BROADCAST (listens)."
        ),
        "values": "OFF, UNICAST, MANYCAST, BROADCAST",
        "sections": _PORT,
    },
    "SNTPPSIP": {
        "name": "SNTP primary server",
        "desc": "IP address of the primary SNTP time server.",
        "sections": _PORT,
    },
    "SNTPBSIP": {
        "name": "SNTP backup server",
        "desc": "IP address of the backup SNTP time server.",
        "sections": _PORT,
    },
    "SNTPPORT": {"name": "SNTP port", "desc": "UDP port for SNTP.", "sections": _PORT},
    "SNTPRATE": {
        "name": "SNTP update rate",
        "desc": "Seconds between SNTP time requests.",
        "values": "15-3600",
        "units": "s",
        "sections": _PORT,
    },
    "SNTPTO": {
        "name": "SNTP time-out",
        "desc": "Seconds the relay waits for an answer from an SNTP server.",
        "values": "5-20",
        "units": "s",
        "sections": _PORT,
    },
    # --- Identity, time and global settings ---
    "RID": {
        "name": "Relay identifier",
        "desc": "Name of the relay, shown in reports and on the front panel.",
    },
    "TID": {
        "name": "Terminal identifier",
        "desc": "Name of the station or terminal, shown in reports.",
    },
    "SID": {"name": "Station identifier", "desc": "Name of the station, shown in reports."},
    "DATE_F": {
        "name": "Date format",
        "desc": "Order of the month, day and year in dates the relay shows and reports.",
        "by_family": {"7xx": {"values": "MDY, YMD, DMY"}},
        "by_model": {"351S": {"values": "MDY, YMD"}},
    },
    "PHROT": {
        "name": "Phase rotation",
        "desc": "Phase sequence of the power system.",
        "values": "ABC, ACB",
    },
    "FNOM": {
        "name": "Nominal frequency",
        "desc": "Nominal frequency of the power system.",
        "units": "Hz",
        "by_family": {"7xx": {"values": "50, 60"}},
    },
    "NFREQ": {
        "name": "Nominal frequency",
        "desc": "Nominal frequency of the power system.",
        "values": "50, 60",
        "units": "Hz",
    },
    "TGR": {
        "name": "Group change delay",
        "desc": (
            "How long a settings group selection (SS1-SS6) has to be true before the relay "
            "changes to that group."
        ),
        "sections": _GLOBAL,
        "by_family": {"7xx": {"values": "0-400", "units": "s"}},
        "by_model": {"351S": {"values": "0.00-16000.00", "units": "cycles"}},
    },
    "FP_TO": {
        "name": "Front-panel time-out",
        "desc": (
            "Minutes without a key press before the front panel returns to its default display. "
            "OFF means it never times out."
        ),
        "values": "OFF, 1-30",
        "units": "min",
    },
    "FP_CONT": {
        "name": "LCD contrast",
        "desc": "Contrast of the front-panel display.",
        "by_family": {"7xx": {"values": "1-8"}},
    },
    "FP_AUTO": {
        "name": "Front-panel automatic messages",
        "desc": (
            "If automatic messages replace the rotating display (OVERRIDE) or are part of it "
            "(ROTATING)."
        ),
        "by_family": {"7xx": {"values": "OVERRIDE, ROTATING"}},
    },
    "RSTLED": {
        "name": "Reset LEDs on close",
        "desc": "If the latched target LEDs reset when the breaker closes.",
        "by_family": {"7xx": {"values": _Y_N}},
        "by_model": {"351S": {"values": "Y, Y1, N, N1"}},
    },
    "DSABLSET": {
        "name": "Disable settings changes",
        "desc": "SELOGIC equation that blocks settings changes while it's true.",
        "security": True,
    },
    "BLKMBSET": {
        "name": "Block Modbus settings changes",
        "desc": "Which settings changes over Modbus are blocked.",
        "security": True,
        "by_family": {"7xx": {"values": "NONE, R_S, ALL"}},
    },
    "TIME_SRC": {
        "name": "IRIG time source",
        "desc": "IRIG-B input the relay takes its time from.",
        "by_family": {"7xx": {"values": "IRIG1, IRIG2"}},
    },
    "IRIGC": {
        "name": "IRIG-B control bits",
        "desc": (
            "If the relay uses the IEEE C37.118 extensions in the IRIG-B control bits (year, "
            "time zone and time quality)."
        ),
        "values": "NONE, C37.118",
    },
    "UTC_OFF": {
        "name": "UTC offset",
        "desc": "Hours between the relay's local time and UTC.",
        "values": "-24.00 to 24.00",
        "units": "h",
    },
    "DST_BEGM": {
        "name": "DST start month",
        "desc": "Month daylight saving time starts.",
        "by_family": {"7xx": {"values": "OFF, 1-12"}},
        "by_model": {"351S": {"values": "NA, 1-12"}},
    },
    "DST_BEGW": {
        "name": "DST start week",
        "desc": "Week of the month daylight saving time starts.",
    },
    "DST_BEGD": {
        "name": "DST start day",
        "desc": "Day of the week daylight saving time starts.",
        "values": "SUN, MON, TUE, WED, THU, FRI, SAT",
    },
    "DST_BEGH": {
        "name": "DST start hour",
        "desc": "Local hour daylight saving time starts.",
        "values": "0-23",
    },
    "DST_ENDM": {
        "name": "DST end month",
        "desc": "Month daylight saving time ends.",
        "by_family": {"7xx": {"values": "OFF, 1-12"}},
        "by_model": {"351S": {"values": "NA, 1-12"}},
    },
    "DST_ENDW": {"name": "DST end week", "desc": "Week of the month daylight saving time ends."},
    "DST_ENDD": {
        "name": "DST end day",
        "desc": "Day of the week daylight saving time ends.",
        "values": "SUN, MON, TUE, WED, THU, FRI, SAT",
    },
    "DST_ENDH": {
        "name": "DST end hour",
        "desc": "Local hour daylight saving time ends.",
        "values": "0-23",
    },
    "EPMU": {
        "name": "Synchrophasors",
        "desc": "If the relay measures and sends IEEE C37.118 synchrophasor data.",
        "values": _Y_N,
    },
    "PMID": {
        "name": "PMU ID",
        "desc": "IEEE C37.118 identifier of the relay's phasor measurement unit.",
    },
    "PMSTN": {
        "name": "PMU station name",
        "desc": "Station name in the IEEE C37.118 configuration.",
    },
    "EBMON": {
        "name": "Breaker monitor",
        "desc": "If the breaker wear monitor is enabled.",
        "values": _Y_N,
    },
    "BKMON": {
        "name": "Breaker monitor initiate",
        "desc": "SELOGIC equation that tells the breaker monitor the breaker operated.",
    },
    "52ABF": {
        "name": "Breaker failure 52A interlock",
        "desc": "If the breaker failure logic also checks the breaker status (52A).",
        "by_family": {"7xx": {"values": _Y_N}},
    },
    "BFD": {
        "name": "Breaker failure delay",
        "desc": (
            "How long the breaker can take to open after a trip before the relay declares a "
            "breaker failure."
        ),
        "units": "s",
        "by_family": {"7xx": {"values": "0.00-2.00"}},
    },
    "BFI": {
        "name": "Breaker failure initiate",
        "desc": "SELOGIC equation that starts the breaker failure timer.",
    },
    "FAULT": {
        "name": "Fault condition",
        "desc": (
            "SELOGIC equation that tells the relay a fault is present, for event reports and "
            "fault-related functions."
        ),
    },
    "RSTTRGT": {
        "name": "Reset targets",
        "desc": "SELOGIC equation that resets the front-panel target LEDs.",
    },
    "RSTENRGY": {
        "name": "Reset energy metering",
        "desc": "SELOGIC equation that resets the energy meters.",
    },
    "RSTMXMN": {
        "name": "Reset maximum/minimum metering",
        "desc": "SELOGIC equation that resets the maximum and minimum meters.",
    },
    "RSTDEM": {
        "name": "Reset demand metering",
        "desc": "SELOGIC equation that resets the demand meters.",
    },
    "RSTPKDEM": {
        "name": "Reset peak demand metering",
        "desc": "SELOGIC equation that resets the peak demand meters.",
    },
    # --- Group settings and logic ---
    "CTR": {"name": "Phase CT ratio", "desc": "Ratio of the phase current transformers."},
    "CTR1": {"name": "Phase CT ratio", "desc": "Ratio of the phase current transformers."},
    "CTR2": {
        "name": "Phase CT ratio (speed 2)",
        "desc": (
            "Ratio of the phase current transformers for the second speed of a two-speed motor."
        ),
    },
    "CTRN": {"name": "Neutral CT ratio", "desc": "Ratio of the neutral current transformer."},
    "PTR": {"name": "Phase PT ratio", "desc": "Ratio of the phase voltage transformers."},
    "PTRS": {
        "name": "Synchronism-check PT ratio",
        "desc": "Ratio of the voltage transformer of the synchronism-check voltage channel (VS).",
    },
    "VNOM": {
        "name": "Nominal voltage",
        "desc": "Nominal line-to-line voltage of the power system.",
    },
    "FLA1": {
        "name": "Motor full-load current",
        "desc": "Full-load current of the motor, from its nameplate.",
        "units": "A",
    },
    "FLA2": {
        "name": "Motor full-load current (speed 2)",
        "desc": "Full-load current of the motor at its second speed.",
        "units": "A",
    },
    "E2SPEED": {
        "name": "Two-speed motor",
        "desc": "If the motor has two speeds, each with its own settings.",
        "values": _Y_N,
    },
    "TR": {
        "name": "Trip equation",
        "desc": "SELOGIC equation with the conditions that trip the breaker.",
    },
    "ULTR": {
        "name": "Unlatch trip",
        "desc": "SELOGIC equation that resets (unlatches) the trip output after a trip.",
    },
    "TRCOMM": {
        "name": "Communications-assisted trip",
        "desc": (
            "SELOGIC equation with the conditions that trip through a communications-assisted "
            "(pilot) scheme."
        ),
    },
    "TRSOTF": {
        "name": "Switch-onto-fault trip",
        "desc": (
            "SELOGIC equation with the conditions that trip when the breaker closes onto a fault."
        ),
    },
    "DTT": {
        "name": "Direct transfer trip",
        "desc": "SELOGIC equation with the trip signals received from the remote end.",
    },
    "TDURD": {
        "name": "Minimum trip duration",
        "desc": "Minimum time the trip output stays on after a trip.",
        "by_family": {"7xx": {"values": "0.0-400.0", "units": "s"}},
        "by_model": {"351S": {"values": "4.00-16000.00", "units": "cycles"}},
    },
    "REMTRIP": {
        "name": "Remote trip",
        "desc": (
            "SELOGIC equation for trips from a remote source, e.g. a contact input or a remote "
            "bit."
        ),
    },
    "ULTRIP": {
        "name": "Unlatch trip",
        "desc": "SELOGIC equation that resets (unlatches) the trip output after a trip.",
    },
    "52A": {
        "name": "Breaker status",
        "desc": (
            "SELOGIC equation, usually a contact input, that's true when the breaker or "
            "contactor is closed."
        ),
    },
    "CL": {
        "name": "Close equation",
        "desc": "SELOGIC equation with the conditions that close the breaker.",
    },
    "ULCL": {
        "name": "Unlatch close",
        "desc": "SELOGIC equation that cancels a close that's in progress.",
    },
    "CFD": {
        "name": "Close failure delay",
        "desc": "How long a close can take before the relay declares a close failure.",
        "by_family": {"7xx": {"values": "0.0-400.0", "units": "s"}},
        "by_model": {"351S": {"values": "OFF, 0.00-16000.00", "units": "cycles"}},
    },
    "STREQ": {"name": "Motor start request", "desc": "SELOGIC equation that starts the motor."},
    "EMRSTR": {
        "name": "Emergency restart",
        "desc": (
            "SELOGIC equation that allows a motor start even when the thermal or starts-per-hour "
            "limits would block it."
        ),
    },
    "79RI": {
        "name": "Reclose initiate",
        "desc": "SELOGIC equation that starts the reclosing sequence after a trip.",
    },
    "79RIS": {
        "name": "Reclose initiate supervision",
        "desc": "SELOGIC equation that has to be true for a reclose initiate to be accepted.",
    },
    "79DTL": {
        "name": "Drive to lockout",
        "desc": "SELOGIC equation that sends the recloser to lockout.",
    },
    "79DLS": {
        "name": "Drive to last shot",
        "desc": "SELOGIC equation that skips to the last reclose shot.",
    },
    "79SKP": {"name": "Skip shot", "desc": "SELOGIC equation that skips the next reclose shot."},
    "79STL": {
        "name": "Stall open interval timing",
        "desc": "SELOGIC equation that pauses the open interval timer.",
    },
    "79BRS": {
        "name": "Block reset timing",
        "desc": "SELOGIC equation that pauses the recloser reset timer.",
    },
    "79SEQ": {
        "name": "Sequence coordination",
        "desc": (
            "SELOGIC equation that advances the reclose shot counter to coordinate with "
            "downstream reclosers."
        ),
    },
    "79CLS": {
        "name": "Reclose supervision",
        "desc": "SELOGIC equation that has to be true for the relay to reclose.",
    },
    "ER": {
        "name": "Event report trigger",
        "desc": "SELOGIC equation that triggers an event report.",
    },
    "ESV": {
        "name": "SELOGIC variables enabled",
        "desc": "How many SELOGIC variables (with timers) are enabled. N means none.",
        "by_family": {"7xx": {"values": "N, 1-32"}},
        "by_model": {"351S": {"values": "N, 1-16"}},
    },
    "ELAT": {
        "name": "Latches enabled",
        "desc": "How many SELOGIC latches are enabled. N means none.",
        "by_family": {"7xx": {"values": "N, 1-32"}},
    },
    "ESC": {
        "name": "Counters enabled",
        "desc": "How many SELOGIC counters are enabled. N means none.",
        "by_family": {"7xx": {"values": "N, 1-32"}},
    },
    "EMV": {
        "name": "Math variables enabled",
        "desc": "How many SELOGIC math variables are enabled. N means none.",
        "by_family": {"7xx": {"values": "N, 1-32"}},
    },
    "EDP": {
        "name": "Display points enabled",
        "desc": "How many front-panel display points are enabled. N means none.",
        "by_family": {"7xx": {"values": "N, 1-32"}},
    },
    "ELB": {
        "name": "Local bits enabled",
        "desc": "How many local bits (front-panel control switches) are enabled. N means none.",
        "by_family": {"7xx": {"values": "N, 1-32"}},
    },
    "EALIAS": {
        "name": "Aliases enabled",
        "desc": "How many Relay Word bit aliases are enabled. N means none.",
        "by_family": {"7xx": {"values": "N, 1-20"}},
    },
    "EVOLT": {
        "name": "Voltage elements",
        "desc": "If the voltage elements are enabled.",
        "values": _Y_N,
    },
    "EDEM": {
        "name": "Demand metering",
        "desc": (
            "Type of demand meter: thermal (THM) or rolling (ROL), or on some models the winding."
        ),
        "by_model": {"751A": {"values": "THM, ROL"}, "787": {"values": "OFF, W1, W2"}},
    },
    "46UBT": {
        "name": "Current unbalance trip level",
        "desc": "Current unbalance, in percent, at which the relay trips.",
        "units": "%",
        "by_model": {"710": {"values": "OFF, 5-80"}},
    },
    "46UBA": {
        "name": "Current unbalance alarm level",
        "desc": "Current unbalance, in percent, at which the relay alarms.",
        "units": "%",
        "by_model": {"710": {"values": "OFF, 5-80"}},
    },
    "46UBTD": {
        "name": "Current unbalance trip delay",
        "desc": "How long the unbalance has to be above the trip level before the relay trips.",
        "units": "s",
    },
    "46UBAD": {
        "name": "Current unbalance alarm delay",
        "desc": "How long the unbalance has to be above the alarm level before the relay alarms.",
        "units": "s",
    },
    # Element enables. The name and description come from the element enable pattern.
    "E32": {"by_family": {"3xx": {"values": "Y, AUTO, N"}}},
    "E25": {"values": _Y_N},
    "E79": {"by_model": {"351S": {"values": "N, 1-4, C1-C4"}, "751A": {"values": "OFF, 1-4"}}},
    "E81": {"by_model": {"351S": {"values": "N, 1-6"}}},
    "E81R": {"by_model": {"351S": {"values": "N, 1-4"}, "751A": {"values": "OFF, 1-4"}}},
    "E50P": {"by_model": {"351S": {"values": "N, 1-6"}}},
    "E50G": {"by_model": {"351S": {"values": "N, 1-6"}}},
    "E50N": {"by_model": {"351S": {"values": "N, 1-6"}}},
    "E50Q": {"by_model": {"351S": {"values": "N, 1-6"}}},
    "E51P": {"by_model": {"351S": {"values": "N, 1, 2"}}},
    "E51G": {"by_model": {"351S": {"values": "N, 1, 2"}}},
    "E51N": {"by_model": {"351S": {"values": "N, 1, 2"}}},
    "E51Q": {"by_model": {"351S": {"values": _Y_N}}},
    "E47T": {"values": _Y_N},
    "E49MOTOR": {"values": _Y_N},
    "E87M": {"values": _Y_N},
    "E49RTD": {
        "by_model": {"751A": {"values": "INT, EXT, NONE"}, "787": {"values": "INT, EXT, NONE"}}
    },
    "E87": {"by_model": {"700G": {"values": "GEN, TRANS, NONE"}, "787": {"values": _Y_N}}},
    "E78": {"by_model": {"700G": {"values": "N, 1B, 2B"}}},
    # --- Report and front-panel settings ---
    "LER": {
        "name": "Event report length",
        "desc": "Length of each event report.",
        "units": "cycles",
        "by_model": {
            "351S": {"values": "15, 30, 60"},
            "700G": {"values": "15, 64, 180"},
            "710": {"values": "15, 64"},
            "751A": {"values": "15, 64"},
            "787": {"values": "15, 64"},
        },
    },
    "PRE": {
        "name": "Prefault length",
        "desc": "Part of each event report from before the trigger.",
        "units": "cycles",
    },
    "ESERDEL": {
        "name": "SER automatic removal",
        "desc": "If the relay stops recording SER points that change state too often (chatter).",
        "values": _Y_N,
    },
    "LDAR": {
        "name": "Load profile acquisition rate",
        "desc": "Minutes between load profile records.",
        "values": "5, 10, 15, 30, 60",
        "units": "min",
    },
    "LDLIST": {
        "name": "Load profile list",
        "desc": "Analog quantities recorded in the load profile.",
    },
    "MSRTRG": {
        "name": "Motor start report trigger",
        "desc": "SELOGIC equation that triggers a motor start report.",
    },
    "MSRR": {
        "name": "Motor start report resolution",
        "desc": "Time between the samples of a motor start report.",
        "units": "cycles",
    },
}

#: Names that are short versions of other names (the SEL-451 truncates
#: names longer than 7 characters, and some models use other names)
SETTING_ALIASES: Final[dict[str, str]] = {
    "HTTPPOR": "HTTPPORT",
    "HIDLE": "HTTPIDLE",
    "SNTPPOR": "SNTPPORT",
    "SNTPRAT": "SNTPRATE",
    "SNTPPIP": "SNTPPSIP",
    "SNTPBIP": "SNTPBSIP",
    "DNPPNUM": "DNPNUM",
    "EFTPSER": "EFTPSERV",
}

#: Settings that are repeated for each DNP3 or Modbus TCP session,
#: e.g. ``DNPIP1`` and ``DNPIP2``, and the protocol of the session
SESSION_SETTINGS: Final[dict[str, str]] = {
    **dict.fromkeys(
        [
            "DNPIP",
            "DNPTR",
            "DNPUDP",
            "REPADR",
            "DNPMAP",
            "UNSOL",
            "PUNSOL",
            "NUM1EVE",
            "AGE1EVE",
            "URETRY",
            "UTIMEO",
            "ECLASSB",
            "ECLASSC",
            "ECLASSA",
            "TIMERQ",
            "STIMEO",
            "DNPINA",
            "ETIMEO",
        ],
        "DNP3",
    ),
    "MODNUM": "Modbus",
    "MTIMEO": "Modbus",
}

_SESSION_RE: Final = re.compile(r"^(?P<base>[A-Z0-9]+?)(?P<n>[1-6])$")

#: Settings that the SEL-700G has for each side (the X and Y breakers or
#: terminals), e.g. ``TRX``, ``CLY``, ``CFDX``
SIDE_SETTINGS: Final = frozenset(
    {"TR", "ULTR", "CL", "ULCL", "52A", "CFD", "BFD", "BFI", "BKMON", "EBMON", "CTR", "PTR"}
)

_SIDE_RE: Final = re.compile(r"^(?P<base>[A-Z0-9_]+?)(?P<side>[XY])$")

#: Torque control equations that aren't of a known protection element,
#: e.g. ``REF1TC`` (the names are from the SELOGIC classifier)
_TORQUE_CONTROL_RE: Final = re.compile(r"^(?P<x>\d{2}[A-Z0-9]*|REF\d|OOS|INAD|HBL\d)TC$")

_LOGIC_UNITS_3XX: Final = {"units": "cycles"}
_LOGIC_UNITS_7XX: Final = {"units": "s"}

#: Information about numbered settings, e.g. ``SV05`` or ``OUT403``: pairs of a
#: regular expression and an entry. The named groups of the expression can be
#: used in the ``name`` and ``desc`` of the entry, e.g. ``{n}``.
PATTERN_INFO: Final[tuple[tuple[re.Pattern[str], SettingEntry], ...]] = tuple(
    (re.compile(pattern), entry)
    for pattern, entry in [
        # SELOGIC variables and timers
        (
            r"^SV(?P<n>\d{1,3})PU$",
            {
                "name": "SV{n} timer pickup time",
                "desc": (
                    "How long SELOGIC variable SV{n} has to be true before its timer output "
                    "SV{n}T asserts."
                ),
                "by_family": {
                    "7xx": {"values": "0.00-3000.00", "units": "s"},
                    "3xx": _LOGIC_UNITS_3XX,
                },
            },
        ),
        (
            r"^SV(?P<n>\d{1,3})DO$",
            {
                "name": "SV{n} timer dropout time",
                "desc": (
                    "How long timer output SV{n}T stays asserted after SELOGIC variable SV{n} is "
                    "false."
                ),
                "by_family": {
                    "7xx": {"values": "0.00-3000.00", "units": "s"},
                    "3xx": _LOGIC_UNITS_3XX,
                },
            },
        ),
        (
            r"^SV(?P<n>\d{1,3})$",
            {
                "name": "SELOGIC variable SV{n}",
                "desc": "General-purpose SELOGIC control equation. Its timer output is SV{n}T.",
            },
        ),
        # Latches
        (
            r"^SET(?P<n>\d{1,2})$",
            {
                "name": "Latch LT{n} set",
                "desc": "SELOGIC equation that sets (turns on) latch bit LT{n}.",
            },
        ),
        (
            r"^RST(?P<n>\d{1,2})$",
            {
                "name": "Latch LT{n} reset",
                "desc": "SELOGIC equation that resets (turns off) latch bit LT{n}.",
            },
        ),
        (
            r"^LT(?P<n>\d{1,2})$",
            {
                "name": "Latch bit LT{n}",
                "desc": (
                    "Latch bit that's set by SET{n} and reset by RST{n}. It keeps its state when "
                    "the relay loses power."
                ),
            },
        ),
        # Counters and math variables
        (
            r"^SC(?P<n>\d{2})PV$",
            {
                "name": "Counter SC{n} preset value",
                "desc": "Count at which counter SC{n} asserts its output SC{n}QU.",
                "by_family": {"7xx": {"values": "1-65000"}},
            },
        ),
        (
            r"^SC(?P<n>\d{2})R$",
            {
                "name": "Counter SC{n} reset",
                "desc": "SELOGIC equation that resets counter SC{n} to zero.",
            },
        ),
        (
            r"^SC(?P<n>\d{2})LD$",
            {
                "name": "Counter SC{n} load",
                "desc": "SELOGIC equation that loads the preset value into counter SC{n}.",
            },
        ),
        (
            r"^SC(?P<n>\d{2})CU$",
            {
                "name": "Counter SC{n} count up",
                "desc": "SELOGIC equation that counts counter SC{n} up on each rising edge.",
            },
        ),
        (
            r"^SC(?P<n>\d{2})CD$",
            {
                "name": "Counter SC{n} count down",
                "desc": "SELOGIC equation that counts counter SC{n} down on each rising edge.",
            },
        ),
        (
            r"^SC(?P<n>\d{2})$",
            {
                "name": "SELOGIC counter SC{n}",
                "desc": (
                    "Up/down counter with a preset (SC{n}PV), reset, load, count-up and "
                    "count-down equations."
                ),
            },
        ),
        (
            r"^MV(?P<n>\d{2})$",
            {
                "name": "Math variable MV{n}",
                "desc": "SELOGIC math equation. The result is the analog quantity MV{n}.",
            },
        ),
        # Outputs and inputs
        (
            r"^OUT(?P<n>\d{3})FS$",
            {
                "name": "Output OUT{n} fail-safe",
                "desc": (
                    "If output contact OUT{n} is fail-safe: its coil is energized in normal "
                    "operation and it drops out when the relay fails or loses power."
                ),
                "values": _Y_N,
            },
        ),
        (
            r"^OUT(?P<n>\d{3})$",
            {
                "name": "Output contact OUT{n}",
                "desc": "SELOGIC equation that operates output contact OUT{n}.",
            },
        ),
        (
            r"^IN(?P<n>\d{3})D$",
            {
                "name": "Input IN{n} debounce time",
                "desc": (
                    "How long contact input IN{n} has to be stable before the relay accepts a "
                    "change. AC is for inputs that are driven by AC voltage."
                ),
                "by_family": {"7xx": {"values": "AC, 0-65000", "units": "ms"}},
                "by_model": {"351S": {"values": "AC, 0.00-2.00", "units": "cycles"}},
            },
        ),
        # MIRRORED BITS
        (
            r"^TMB(?P<n>\d)(?P<ch>[AB])$",
            {
                "name": "Transmit MIRRORED BIT TMB{n}{ch}",
                "desc": "SELOGIC equation for MIRRORED BIT {n} sent on channel {ch}.",
            },
        ),
        (
            r"^RMB(?P<n>\d)PU$",
            {
                "name": "Receive MIRRORED BIT RMB{n} pickup",
                "desc": (
                    "Number of messages received MIRRORED BIT {n} has to be set before it asserts."
                ),
                "values": "1-8",
            },
        ),
        (
            r"^RMB(?P<n>\d)DO$",
            {
                "name": "Receive MIRRORED BIT RMB{n} dropout",
                "desc": (
                    "Number of messages received MIRRORED BIT {n} has to be clear before it "
                    "deasserts."
                ),
                "values": "1-8",
            },
        ),
        # Front panel
        (
            r"^T(?P<n>\d{2})_LED$",
            {
                "name": "Target LED T{n}",
                "desc": "SELOGIC equation that turns on front-panel target LED T{n}.",
            },
        ),
        (
            r"^T(?P<n>\d{2})LEDL$",
            {
                "name": "Target LED T{n} latch",
                "desc": (
                    "If target LED {n} stays on after its equation is false, until the targets "
                    "are reset."
                ),
                "values": _Y_N,
            },
        ),
        (
            r"^TLED_?(?P<n>\d{1,2})$",
            {
                "name": "Target LED {n}",
                "desc": "SELOGIC equation that turns on front-panel target LED {n}.",
            },
        ),
        (
            r"^PB(?P<n>\d{1,2})(?P<x>[AB])_LED$",
            {
                "name": "Pushbutton {n} LED {x}",
                "desc": "SELOGIC equation that turns on LED {x} of front-panel pushbutton {n}.",
            },
        ),
        (
            r"^LED(?P<n>\d{1,2})L$",
            {
                "name": "LED {n} latch",
                "desc": (
                    "If front-panel LED {n} stays on after its equation is false, until the "
                    "targets are reset."
                ),
            },
        ),
        (
            r"^LED(?P<n>\d{1,2})$",
            {"name": "LED {n}", "desc": "SELOGIC equation that turns on front-panel LED {n}."},
        ),
        (
            r"^DP(?P<n>\d{1,2})$",
            {
                "name": "Display point DP{n}",
                "desc": (
                    "Item on the front-panel rotating display: a Relay Word bit or analog "
                    "quantity and its label text."
                ),
                "sections": f"{_FRONT}|{_GLOBAL}|{_LOGIC}",
            },
        ),
        (
            r"^NLB(?P<n>\d{2})$",
            {
                "name": "Local bit LB{n} name",
                "desc": "Name of local bit LB{n}, a control switch on the front panel.",
            },
        ),
        (
            r"^CLB(?P<n>\d{2})$",
            {
                "name": "Local bit LB{n} clear label",
                "desc": "Front-panel label of local bit LB{n} when it's clear (off).",
            },
        ),
        (
            r"^SLB(?P<n>\d{2})$",
            {
                "name": "Local bit LB{n} set label",
                "desc": "Front-panel label of local bit LB{n} when it's set (on).",
            },
        ),
        (
            r"^PLB(?P<n>\d{2})$",
            {
                "name": "Local bit LB{n} pulse label",
                "desc": "Front-panel label of local bit LB{n} when it's pulsed.",
            },
        ),
        # Settings group selection
        (
            r"^SS(?P<n>\d)$",
            {
                "name": "Select settings group {n}",
                "desc": (
                    "SELOGIC equation that changes to settings group {n} when it's true (after "
                    "the TGR delay)."
                ),
            },
        ),
        # Reports
        (
            r"^SER(?P<n>\d+)$",
            {
                "name": "SER trigger list {n}",
                "desc": (
                    "Relay Word bits that the Sequential Events Recorder (SER) records changes of."
                ),
            },
        ),
        (
            r"^ALIAS(?P<n>\d+)$",
            {
                "name": "Alias {n}",
                "desc": (
                    "A Relay Word bit, the alias name it has in reports, and the text for when "
                    "it asserts and deasserts. NA means it isn't used."
                ),
            },
        ),
        # Modbus user map (M on 300- and 700-series relays, breaker monitor on 400-series)
        (
            r"^MOD_(?P<n>\d+)$",
            {
                "name": "Modbus map register {n}",
                "desc": "Quantity at address {n} of the Modbus user map.",
                "sections": _MODBUS_MAP,
                "only": _FAMILIES_3_7,
            },
        ),
        # RTDs (700-series)
        (
            r"^RTD(?P<n>\d{1,2})LOC$",
            {
                "name": "RTD {n} location",
                "desc": (
                    "Where RTD {n} is, e.g. WDG (winding), BRG (bearing), AMB (ambient), OTH "
                    "(other), or OFF."
                ),
            },
        ),
        (
            r"^RTD(?P<n>\d{1,2})TY$",
            {"name": "RTD {n} type", "desc": "Sensor type of RTD {n}, e.g. PT100."},
        ),
        (
            r"^TRTMP(?P<n>\d{1,2})$",
            {
                "name": "RTD {n} trip temperature",
                "desc": "Temperature of RTD {n} at which the relay trips.",
            },
        ),
        (
            r"^ALTMP(?P<n>\d{1,2})$",
            {
                "name": "RTD {n} alarm temperature",
                "desc": "Temperature of RTD {n} at which the relay alarms.",
            },
        ),
        # Analog inputs and outputs (700-series)
        (
            r"^AI(?P<n>\d{3})NAM$",  # codespell:ignore nam
            {"name": "Analog input AI{n} name", "desc": "Name (tag) of analog input AI{n}."},
        ),
        (
            r"^AI(?P<n>\d{3})TYP$",
            {
                "name": "Analog input AI{n} type",
                "desc": "If analog input AI{n} measures current (I) or voltage (V).",
            },
        ),
        (
            r"^AI(?P<n>\d{3})L$",
            {
                "name": "Analog input AI{n} low level",
                "desc": "Lowest input level of analog input AI{n}.",
            },
        ),
        (
            r"^AI(?P<n>\d{3})H$",
            {
                "name": "Analog input AI{n} high level",
                "desc": "Highest input level of analog input AI{n}.",
            },
        ),
        (
            r"^AI(?P<n>\d{3})EU$",
            {
                "name": "Analog input AI{n} engineering units",
                "desc": "Units of the scaled value of analog input AI{n}.",
            },
        ),
        (
            r"^AI(?P<n>\d{3})EL$",
            {
                "name": "Analog input AI{n} low engineering value",
                "desc": "Scaled value of analog input AI{n} at its low input level.",
            },
        ),
        (
            r"^AI(?P<n>\d{3})EH$",
            {
                "name": "Analog input AI{n} high engineering value",
                "desc": "Scaled value of analog input AI{n} at its high input level.",
            },
        ),
        (
            r"^AI(?P<n>\d{3})LW(?P<w>[12])$",
            {
                "name": "Analog input AI{n} low warning {w}",
                "desc": "Value of analog input AI{n} below which low warning {w} asserts.",
            },
        ),
        (
            r"^AI(?P<n>\d{3})HW(?P<w>[12])$",
            {
                "name": "Analog input AI{n} high warning {w}",
                "desc": "Value of analog input AI{n} above which high warning {w} asserts.",
            },
        ),
        (
            r"^AI(?P<n>\d{3})LAL$",
            {
                "name": "Analog input AI{n} low alarm",
                "desc": "Value of analog input AI{n} below which its low alarm asserts.",
            },
        ),
        (
            r"^AI(?P<n>\d{3})HAL$",
            {
                "name": "Analog input AI{n} high alarm",
                "desc": "Value of analog input AI{n} above which its high alarm asserts.",
            },
        ),
        (
            r"^AO(?P<n>\d{3})AQ$",
            {
                "name": "Analog output AO{n} quantity",
                "desc": "Analog quantity that analog output AO{n} sends.",
            },
        ),
        (
            r"^AO(?P<n>\d{3})TYP$",
            {
                "name": "Analog output AO{n} type",
                "desc": "If analog output AO{n} is a current (I) or voltage (V) output.",
            },
        ),
        (
            r"^AO(?P<n>\d{3})AQL$",
            {
                "name": "Analog output AO{n} quantity low",
                "desc": "Value of the quantity that gives the low level of analog output AO{n}.",
            },
        ),
        (
            r"^AO(?P<n>\d{3})AQH$",
            {
                "name": "Analog output AO{n} quantity high",
                "desc": "Value of the quantity that gives the high level of analog output AO{n}.",
            },
        ),
        (
            r"^AO(?P<n>\d{3})L$",
            {
                "name": "Analog output AO{n} low level",
                "desc": "Lowest output level of analog output AO{n}.",
            },
        ),
        (
            r"^AO(?P<n>\d{3})H$",
            {
                "name": "Analog output AO{n} high level",
                "desc": "Highest output level of analog output AO{n}.",
            },
        ),
        # Reclosing
        (
            r"^79OI(?P<n>\d)$",
            {
                "name": "Open interval {n}",
                "desc": "How long the breaker stays open before reclose shot {n}.",
                "by_family": {"7xx": _LOGIC_UNITS_7XX, "3xx": _LOGIC_UNITS_3XX},
            },
        ),
        # 400-series protection logic variables, timers, latches and counters
        (
            r"^PSV(?P<n>\d{2})$",
            {
                "name": "Protection SELOGIC variable PSV{n}",
                "desc": "Boolean variable of the protection logic.",
            },
        ),
        (
            r"^PMV(?P<n>\d{2})$",
            {
                "name": "Protection math variable PMV{n}",
                "desc": "Math variable of the protection logic.",
            },
        ),
        (
            r"^PLT(?P<n>\d{2})S$",
            {
                "name": "Protection latch PLT{n} set",
                "desc": "Equation that sets protection latch PLT{n}.",
            },
        ),
        (
            r"^PLT(?P<n>\d{2})R$",
            {
                "name": "Protection latch PLT{n} reset",
                "desc": "Equation that resets protection latch PLT{n}.",
            },
        ),
        (
            r"^PLT(?P<n>\d{2})$",
            {
                "name": "Protection latch PLT{n}",
                "desc": (
                    "Latch of the protection logic, with set (PLT{n}S) and reset (PLT{n}R) "
                    "equations."
                ),
            },
        ),
        (
            r"^PCT(?P<n>\d{2})IN$",
            {
                "name": "Protection conditioning timer PCT{n} input",
                "desc": "Input of conditioning timer PCT{n}.",
            },
        ),
        (
            r"^PCT(?P<n>\d{2})PU$",
            {
                "name": "Protection conditioning timer PCT{n} pickup time",
                "desc": (
                    "How long the input of PCT{n} has to be true before its output PCT{n}Q "
                    "asserts."
                ),
                "units": "cycles",
            },
        ),
        (
            r"^PCT(?P<n>\d{2})DO$",
            {
                "name": "Protection conditioning timer PCT{n} dropout time",
                "desc": "How long output PCT{n}Q stays asserted after the input is false.",
                "units": "cycles",
            },
        ),
        (
            r"^PCT(?P<n>\d{2})$",
            {
                "name": "Protection conditioning timer PCT{n}",
                "desc": "Pickup/dropout timer of the protection logic.",
            },
        ),
        (
            r"^PST(?P<n>\d{2})IN$",
            {
                "name": "Protection sequencing timer PST{n} input",
                "desc": "Input of sequencing timer PST{n}.",
            },
        ),
        (
            r"^PST(?P<n>\d{2})PT$",
            {
                "name": "Protection sequencing timer PST{n} preset time",
                "desc": (
                    "Elapsed time at which sequencing timer PST{n} asserts its output PST{n}Q."
                ),
                "units": "cycles",
            },
        ),
        (
            r"^PST(?P<n>\d{2})R$",
            {
                "name": "Protection sequencing timer PST{n} reset",
                "desc": "Equation that resets sequencing timer PST{n}.",
            },
        ),
        (
            r"^PST(?P<n>\d{2})$",
            {
                "name": "Protection sequencing timer PST{n}",
                "desc": "Timer of the protection logic that measures how long its input is true.",
            },
        ),
        (
            r"^PCN(?P<n>\d{2})IN$",
            {
                "name": "Protection counter PCN{n} input",
                "desc": "Input of counter PCN{n}; each rising edge counts.",
            },
        ),
        (
            r"^PCN(?P<n>\d{2})PV$",
            {
                "name": "Protection counter PCN{n} preset value",
                "desc": "Count at which counter PCN{n} asserts its output PCN{n}Q.",
            },
        ),
        (
            r"^PCN(?P<n>\d{2})R$",
            {
                "name": "Protection counter PCN{n} reset",
                "desc": "Equation that resets counter PCN{n}.",
            },
        ),
        (
            r"^PCN(?P<n>\d{2})$",
            {"name": "Protection counter PCN{n}", "desc": "Counter of the protection logic."},
        ),
        # 400-series automation logic
        (
            r"^ASV(?P<n>\d{3})$",
            {
                "name": "Automation SELOGIC variable ASV{n}",
                "desc": "Boolean variable of the automation logic.",
            },
        ),
        (
            r"^AMV(?P<n>\d{3})$",
            {
                "name": "Automation math variable AMV{n}",
                "desc": "Math variable of the automation logic.",
            },
        ),
        (
            r"^ALT(?P<n>\d{2})S$",
            {
                "name": "Automation latch ALT{n} set",
                "desc": "Equation that sets automation latch ALT{n}.",
            },
        ),
        (
            r"^ALT(?P<n>\d{2})R$",
            {
                "name": "Automation latch ALT{n} reset",
                "desc": "Equation that resets automation latch ALT{n}.",
            },
        ),
        (
            r"^ALT(?P<n>\d{2})$",
            {"name": "Automation latch ALT{n}", "desc": "Latch of the automation logic."},
        ),
        (
            r"^AST(?P<n>\d{2})IN$",
            {
                "name": "Automation sequencing timer AST{n} input",
                "desc": "Input of automation sequencing timer AST{n}.",
            },
        ),
        (
            r"^AST(?P<n>\d{2})PT$",
            {
                "name": "Automation sequencing timer AST{n} preset time",
                "desc": (
                    "Elapsed time at which automation sequencing timer AST{n} asserts its output."
                ),
                "units": "s",
            },
        ),
        (
            r"^AST(?P<n>\d{2})R$",
            {
                "name": "Automation sequencing timer AST{n} reset",
                "desc": "Equation that resets automation sequencing timer AST{n}.",
            },
        ),
        (
            r"^AST(?P<n>\d{2})$",
            {
                "name": "Automation sequencing timer AST{n}",
                "desc": "Timer of the automation logic.",
            },
        ),
        (
            r"^ACN(?P<n>\d{2})IN$",  # codespell:ignore acn
            {
                "name": "Automation counter ACN{n} input",  # codespell:ignore acn
                "desc": "Input of the automation counter; each rising edge counts.",
            },
        ),
        (
            r"^ACN(?P<n>\d{2})PV$",  # codespell:ignore acn
            {
                "name": "Automation counter ACN{n} preset value",  # codespell:ignore acn
                "desc": "Count at which the automation counter asserts its output.",
            },
        ),
        (
            r"^ACN(?P<n>\d{2})R$",  # codespell:ignore acn
            {
                "name": "Automation counter ACN{n} reset",  # codespell:ignore acn
                "desc": "Equation that resets the automation counter.",
            },
        ),
        (
            r"^ACN(?P<n>\d{2})$",  # codespell:ignore acn
            {
                "name": "Automation counter ACN{n}",  # codespell:ignore acn
                "desc": "Counter of the automation logic.",
            },
        ),
        # 400-series free-form logic lines
        (
            r"^PROTSEL_?(?P<n>\d+)$",
            {
                "name": "Protection logic line {n}",
                "desc": (
                    "Line {n} of the free-form protection logic (variable := equation # comment)."
                ),
            },
        ),
        (
            r"^AUTO_(?P<n>\d+)$",
            {
                "name": "Automation logic line {n}",
                "desc": (
                    "Line {n} of the free-form automation logic (variable := equation # comment)."
                ),
            },
        ),
    ]
)

#: Settings of protection elements: the element code, then what the setting is.
#: The element code is as short as possible (51ATC is 51A and TC, not 51AT and C).
ELEMENT_SETTING_RE: Final = re.compile(
    r"^(?P<code>\d{2}[A-Z0-9]*?)(?P<suffix>TD|RS|CT|MR|TC|TP|P|D|C)$"
)

# What the element settings are. Some only apply to inverse-time (51) elements.
_TIME_UNITS: Final = {"7xx": {"units": "s"}, "3xx": {"units": "cycles"}}
_ELEMENT_SUFFIXES: Final[dict[str, SettingEntry]] = {
    "P": {
        "name": "pickup",
        "desc": "Pickup (operating) level of the {element} element. OFF disables it.",
    },
    "TP": {
        "name": "trip pickup",
        "desc": "Level at which the {element} element trips. OFF disables it.",
    },
    "D": {
        "name": "time delay",
        "desc": "Definite-time delay of the {element} element.",
        "by_family": _TIME_UNITS,
    },
    # TD is the time dial of inverse-time (51) elements, and a delay of other elements
    "TD": {
        "name": "time delay",
        "desc": "Time delay of the {element} element.",
        "by_family": _TIME_UNITS,
    },
    "TC": {
        "name": "torque control",
        "desc": (
            "SELOGIC equation that has to be true for the {element} element to operate. 1 means "
            "it can always operate."
        ),
    },
}
_INVERSE_TIME_SUFFIXES: Final[dict[str, SettingEntry]] = {
    "C": {
        "name": "curve",
        "desc": (
            "Inverse-time curve of the {element} element. U1-U5 are the US curves and C1-C5 are "
            "the IEC curves."
        ),
        "by_family": {"7xx": {"values": "U1, U2, U3, U4, U5, C1, C2, C3, C4, C5"}},
    },
    "TD": {
        "name": "time dial",
        "desc": "Time dial (multiplier) of the inverse-time curve of the {element} element.",
    },
    "RS": {
        "name": "electromechanical reset",
        "desc": (
            "If the {element} element resets slowly like an induction-disk relay (Y), or right "
            "away (N)."
        ),
        "values": _Y_N,
    },
    "CT": {
        "name": "constant time adder",
        "desc": "Fixed time added to the operating time of the {element} element.",
        "by_family": {
            "7xx": {"values": "0.00-1.00", "units": "s"},
            "3xx": {"values": "0.00-60.00", "units": "cycles"},
        },
    },
    "MR": {
        "name": "minimum response time",
        "desc": "Shortest operating time of the {element} element.",
        "by_family": {
            "7xx": {"values": "0.00-1.00", "units": "s"},
            "3xx": {"values": "0.00-60.00", "units": "cycles"},
        },
    },
}

#: Units in setting ranges, and the name PEAT uses for them
_UNITS: Final[dict[str, str]] = {
    **dict.fromkeys(["s", "sec", "secs", "second", "seconds"], "s"),
    "ms": "ms",
    **dict.fromkeys(["min", "mins", "minute", "minutes"], "min"),
    **dict.fromkeys(["h", "hr", "hrs", "hour", "hours"], "h"),
    **dict.fromkeys(["cyc", "cycle", "cycles"], "cycles"),
    "hz": "Hz",
    "mbps": "Mbps",
    "bps": "bps",
    "ppm": "ppm",
    "%": "%",
    "bits": "bits",
    "shots": "shots",
    "xfla": "xFLA",
    "xvnm": "xVnm",
    "v": "V",
    "a": "A",
    "ohms": "ohms",
}

_DASHES: Final = str.maketrans({"\u2013": "-", "\u2014": "-", "\u2212": "-", "~": "-"})
_STEPS_RE: Final = re.compile(r"\s+in\s+[\d.]+[- ]?\w*\s+steps?\b.*$", re.IGNORECASE)
_TRAILING_PAREN_RE: Final = re.compile(r"\s*\(([^()]*)\)\s*$")
_VALUE_UNIT_RE: Final = re.compile(r"^(?P<value>.*?\d)\s*(?P<unit>[A-Za-z%]+)\.?$")
_VALUE_TOKEN_RE: Final = re.compile(
    r"^(?:[-+]?[A-Za-z0-9_.$#@%&/]+(?:\s*-\s*[-+]?[A-Za-z0-9_.]+)?"  # Value or range
    r"|[-+]?[\d.]+\s+to\s+[-+]?[\d.]+)$"  # Range with negative numbers, "-24.00 to 24.00"
)
# Ranges that aren't a list of values: text length, IP addresses, equations, references
_NOT_VALUES_RE: Final = re.compile(
    r"characters?|selogic|zzz|yyy|ip address|\bsee\b|\bfigure\b|\btable\b", re.IGNORECASE
)


def parse_range(text: str | None) -> tuple[list[str] | None, str | None]:
    """
    Parse a range of allowed values (e.g. ``"OFF, 1-30 min"``) into
    the values and the units.

    Ranges use ``-`` (or ``~``, as some 400-series files do), so ``2~10``
    is ``2-10``. A range that's free text (``30 characters``), an IP
    address, or a SELOGIC equation isn't a list of values.

    Examples:

    - ``"Y, N"`` => ``(["Y", "N"], None)``
    - ``"23,1025-65534"`` => ``(["23", "1025-65534"], None)``
    - ``"OFF, 1-30 min"`` => ``(["OFF", "1-30"], "min")``
    - ``"2~10"`` => ``(["2-10"], None)``
    - ``"AUTO, 10, 100 Mbps"`` => ``(["AUTO", "10", "100"], "Mbps")``

    Returns:
        Tuple of the values (None if it isn't a list of values) and the units (None if none)
    """
    if not text or not isinstance(text, str):
        return None, None

    text = _STEPS_RE.sub("", text.translate(_DASHES).strip())
    if not text or _NOT_VALUES_RE.search(text):
        return None, None

    values = []  # type: list[str]
    units = None  # type: str | None

    for token in (t.strip() for t in text.split(",")):
        if not token:
            continue

        unit_match = _VALUE_UNIT_RE.match(token)
        if unit_match and unit_match.group("unit").lower() in _UNITS:
            units = _UNITS[unit_match.group("unit").lower()]
            token = unit_match.group("value").strip()

        if not _VALUE_TOKEN_RE.match(token):
            return None, None
        values.append(
            re.sub(r"(?<=\S)\s*-\s*(?=\S)", "-", token) if " to " not in token else token
        )

    if not values:
        return None, None

    return values, units


def parse_allowed_values(
    range_text: str | None = None, description: str | None = None
) -> list[str] | None:
    """
    Get the allowed values of a setting from its range column (e.g. ``2~10``
    or ``23,1025-65534``), or from a list of values in parentheses at the end
    of its description (e.g. ``Transport Protocol (UDP,TCP)`` or
    ``UDP Response Port (REQ, 1025-65534)``).

    Returns:
        The values, or None if there aren't any
    """
    values, _ = parse_range(range_text)
    if values:
        return values

    if description:
        paren = _TRAILING_PAREN_RE.search(description)
        if paren:
            values, _ = parse_range(paren.group(1))
            return values

    return None


def _device_range(record: Mapping[str, Any]) -> tuple[list[str] | None, str | None]:
    # The allowed values and units from the device's range column or description
    values, units = parse_range(record.get("range"))
    if values:
        return values, units

    description = record.get("description_raw") or record.get("description")
    if description:
        paren = _TRAILING_PAREN_RE.search(description)
        if paren:
            return parse_range(paren.group(1))

    return None, None


def _device_full_name(record: Mapping[str, Any]) -> str | None:
    # The description in the settings file without the range at the end
    # ("Telnet Port (23,1025-65534)" => "Telnet Port"). Indented descriptions
    # are items under a heading ("      Phase"), which aren't a full name.
    raw = record.get("description_raw") or record.get("description") or ""
    if not raw.strip() or raw[:1].isspace():
        return None
    return _TRAILING_PAREN_RE.sub("", raw).strip() or None


def normalize_model(model: str | None) -> str:
    """
    Normalize a relay model for lookups, e.g. ``SEL-0351S`` => ``351S``.
    """
    return str(model or "").strip().upper().removeprefix("SEL-").lstrip("0")


def _applies(entry: Mapping[str, Any], section: str, family: RelayFamily | None) -> bool:
    only = entry.get("only")
    if only and family and family not in only:
        return False

    sections = entry.get("sections")
    if sections and section and section != "SHOW" and not re.match(sections, section):
        return False

    return True


def resolve_entry(
    entry: Mapping[str, Any], family: RelayFamily | None = None, model: str | None = None
) -> SettingEntry:
    """
    Get the fields of an entry (see :data:`SettingEntry`) for a relay family
    and model. Values for the model take precedence over values for the
    family, which take precedence over the entry's own values.
    """
    resolved = {k: entry[k] for k in ENTRY_FIELDS if entry.get(k) is not None}

    by_family = entry.get("by_family") or {}
    if family and isinstance(by_family.get(family), Mapping):
        resolved.update({k: v for k, v in by_family[family].items() if k in ENTRY_FIELDS})

    by_model = entry.get("by_model") or {}
    model_key = normalize_model(model)
    if model_key and isinstance(by_model.get(model_key), Mapping):
        resolved.update({k: v for k, v in by_model[model_key].items() if k in ENTRY_FIELDS})

    return resolved


def _lower_first(name: str) -> str:
    # "Phase time-overcurrent" => "phase time-overcurrent", but not "RTD ..."
    if len(name) > 1 and name[0].isupper() and name[1].islower():
        return name[0].lower() + name[1:]
    return name


def _format_entry(entry: SettingEntry, **fields: str) -> SettingEntry:
    return {k: (v.format(**fields) if isinstance(v, str) else v) for k, v in entry.items()}


def _element_setting_info(
    name: str, family: RelayFamily | None, model: str | None
) -> SettingEntry | None:
    # Protection element settings, e.g. 50P1P, 51AC, 87M2TC, 81D1TP
    match = ELEMENT_SETTING_RE.match(name)
    if not match:
        return None

    code, suffix = match.group("code"), match.group("suffix")
    element = element_name(code, model)
    if not element:
        return None

    inverse_time = code.startswith("51")
    if suffix in _INVERSE_TIME_SUFFIXES and inverse_time:
        entry = _INVERSE_TIME_SUFFIXES[suffix]
    elif suffix in _ELEMENT_SUFFIXES:
        entry = _ELEMENT_SUFFIXES[suffix]
    else:
        return None  # e.g. "C" (curve) of an element that isn't inverse-time

    resolved = resolve_entry(entry, family, model)
    resolved["name"] = f"{element} {resolved['name']}"
    resolved["desc"] = resolved["desc"].format(element=_lower_first(element))
    return resolved


def _element_enable_info(name: str, model: str | None) -> SettingEntry | None:
    # Element enables, e.g. E50P, E87M, E49MOTOR
    match = ELEMENT_ENABLE_RE.match(name)
    if not match:
        return None

    code = match.group(1)
    element = element_name(code, model)
    if not element:
        generic = ansi_name(code, model)
        if not generic or "(suffix " in generic:
            return None
        element = generic

    return {
        "name": f"{element} enable",
        "desc": (
            f"Enables the {_lower_first(element)} element. N, OFF or NONE disables it. "
            "On some relays the value is the number of levels or shots, or a mode."
        ),
    }


def _pattern_info(
    name: str, section: str, family: RelayFamily | None, model: str | None
) -> SettingEntry | None:
    for pattern, entry in PATTERN_INFO:
        match = pattern.match(name)
        if match and _applies(entry, section, family):
            return resolve_entry(_format_entry(entry, **match.groupdict()), family, model)

    session = _SESSION_RE.match(name)
    if session and session.group("base") in SESSION_SETTINGS:
        base = SETTING_INFO.get(session.group("base"))
        if base and _applies(base, section, family):
            resolved = resolve_entry(base, family, model)
            protocol = SESSION_SETTINGS[session.group("base")]
            if resolved.get("name"):
                resolved["name"] = f"{resolved['name']} ({protocol} session {session.group('n')})"
            return resolved

    side = _SIDE_RE.match(name)
    if side and side.group("base") in SIDE_SETTINGS:
        base = SETTING_INFO[side.group("base")]
        if _applies(base, section, family):
            resolved = resolve_entry(base, family, model)
            resolved["name"] = f"{resolved['name']} ({side.group('side')} side)"
            return resolved

    return (
        _element_setting_info(name, family, model)
        or _element_enable_info(name, model)
        or _torque_control_info(name)
    )


def _torque_control_info(name: str) -> SettingEntry | None:
    match = _TORQUE_CONTROL_RE.match(name)
    if not match:
        return None
    return {
        "name": f"{match.group('x')} torque control",
        "desc": (
            f"SELOGIC equation that has to be true for {match.group('x')} to operate. "
            "1 means it can always operate."
        ),
    }


def setting_info(
    name: str,
    section: str = "",
    family: RelayFamily | None = None,
    model: str | None = None,
    overrides: Mapping[str, SettingEntry] | None = None,
) -> dict[str, Any]:
    """
    Get what's known about a setting from the user's override file,
    :data:`SETTING_INFO`, and the patterns (but not from the device).

    Each field is taken from the first source that has it, in this order:
    the user's entry (``overrides``), PEAT's entry, then the patterns.

    Args:
        name: Setting name, e.g. ``NETMODE``
        section: Settings class (section), e.g. ``P1``
        family: Relay family, ``3xx``, ``4xx`` or ``7xx``
        model: Relay model, e.g. ``351S``
        overrides: The user's entries, from :func:`load_setting_descriptions`

    Returns:
        Dict with the fields that are known: ``name``, ``desc``, ``values``,
        ``units`` and ``security``, and the source of each in ``sources``
        (``"user"``, ``"peat"`` or ``"pattern"``). Empty if nothing is known.
    """
    name = str(name).strip().upper()
    section = str(section or "").strip().upper()
    if not name:
        return {}

    candidates = []  # type: list[tuple[str, SettingEntry]]
    for lookup in dict.fromkeys([name, SETTING_ALIASES.get(name, name)]):
        if overrides and isinstance(overrides.get(lookup), Mapping):
            if _applies(overrides[lookup], section, family):
                candidates.append(("user", resolve_entry(overrides[lookup], family, model)))
        if lookup in SETTING_INFO and _applies(SETTING_INFO[lookup], section, family):
            candidates.append(("peat", resolve_entry(SETTING_INFO[lookup], family, model)))

    pattern = _pattern_info(name, section, family, model)
    if pattern:
        candidates.append(("pattern", pattern))

    info = {}  # type: dict[str, Any]
    sources = {}  # type: dict[str, str]
    for source, entry in candidates:
        for field in ENTRY_FIELDS:
            if field not in info and entry.get(field) not in (None, "", []):
                info[field] = entry[field]
                sources[field] = source

    if info:
        info["sources"] = sources
    return info


def _values_list(values: Any) -> list[str] | None:
    if isinstance(values, str):
        parsed, _ = parse_range(values)
        return parsed or [v.strip() for v in values.split(",") if v.strip()] or None
    if isinstance(values, Iterable):
        return [str(v) for v in values] or None
    return None


def annotate_record(
    record: Mapping[str, Any],
    family: RelayFamily | None = None,
    model: str | None = None,
    overrides: Mapping[str, SettingEntry] | None = None,
) -> dict[str, Any]:
    """
    Add the full name, description, allowed values, units and security
    flag to a settings record (see the module documentation).

    The record isn't changed. The returned copy has the fields in
    :data:`ANNOTATION_FIELDS`, and ``description`` is filled in if the
    device didn't have one. For a line of 400-series free-form logic,
    the description is of the variable the line assigns (e.g. ``PSV01``).
    The class name is filled in from :data:`CLASS_NAMES` if the settings
    don't have a ``[CLASSES]`` section.

    Args:
        record: Settings record from :func:`~peat.modules.sel.relay_parse.settings_to_records`
        family: Relay family, ``3xx``, ``4xx`` or ``7xx``
        model: Relay model, e.g. ``351S``
        overrides: The user's entries, from :func:`load_setting_descriptions`

    Returns:
        The annotated record
    """
    annotated = dict(record)
    section = str(record.get("section") or "")

    info = {}  # type: dict[str, Any]
    if record.get("lhs"):  # Free-form logic: describe the variable, e.g. PSV01
        info = setting_info(record["lhs"], section, family, model, overrides)
    if not info:
        info = setting_info(str(record.get("name") or ""), section, family, model, overrides)
    sources = info.get("sources", {})

    device_description = (record.get("description") or "").strip()
    device_values, device_units = _device_range(record)
    info_values = _values_list(info.get("values"))

    annotated["full_name"] = _device_full_name(record) or info.get("name")
    if device_description:
        annotated["description"] = device_description
        annotated["description_source"] = "device"
    else:
        annotated["description"] = info.get("desc")
        annotated["description_source"] = sources.get("desc")

    if device_values:
        annotated["allowed_values"] = device_values
        annotated["allowed_values_source"] = "device"
    else:
        annotated["allowed_values"] = info_values
        annotated["allowed_values_source"] = sources.get("values") if info_values else None

    annotated["units"] = device_units or info.get("units")
    annotated["security"] = bool(info.get("security"))

    if not annotated.get("class_name") and family:
        annotated["class_name"] = class_name(section, family)

    return annotated


def class_name(section: str, family: RelayFamily | None = None) -> str | None:
    """
    PEAT's name for a settings class (section), e.g. ``P5`` => ``"Port 5"``,
    or ``M`` => ``"Modbus map"`` (300- and 700-series) or ``"Breaker monitor"`` (400-series).
    """
    section = str(section or "").strip().upper()
    names = CLASS_NAMES.get(family or "", {})

    if section in names:
        return names[section]
    if re.match(r"^P\d+$", section):
        return f"Port {section[1:]}"
    if re.match(r"^S?\d$", section):
        return f"Group {section.lstrip('S')}"
    if re.match(r"^L\d+$", section):
        return f"Protection logic {section[1:]}" if family == "4xx" else f"Logic {section[1:]}"
    if family == "4xx" and re.match(r"^A\d+$", section):
        return f"Automation logic {section[1:]}"
    if re.match(r"^D\d+$", section):
        return f"DNP3 map {section[1:]}"
    return None


def annotate_records(
    records: Iterable[Mapping[str, Any]],
    family: RelayFamily | None = None,
    model: str | None = None,
    overrides: Mapping[str, SettingEntry] | None = None,
) -> list[dict[str, Any]]:
    """
    Annotate settings records with :func:`annotate_record`.

    Returns:
        New list of annotated records (the records passed in aren't changed)
    """
    return [annotate_record(rec, family, model, overrides) for rec in records]


def annotate_logic(
    grouped: dict[str, dict[str, dict]],
    records: Iterable[Mapping[str, Any]],
    family: RelayFamily | None = None,
    model: str | None = None,
    overrides: Mapping[str, SettingEntry] | None = None,
) -> dict[str, dict[str, dict]]:
    """
    Add names and descriptions to SELOGIC equations grouped by
    :func:`~peat.modules.sel.sel_logic.group_logic`.

    Each variable gets a ``full_name`` and ``description`` (if they're known),
    and ``part_names`` with the full names of its parts (e.g. ``SV01PU``
    is ``"SV01 timer pickup time"``). The grouped equations are changed in place.

    Args:
        grouped: Equations grouped by section and variable
        records: Annotated settings records, from :func:`annotate_records`.
            A device description of a variable's own setting is used first.

    Returns:
        The grouped equations
    """
    by_name = {}  # type: dict[tuple[str, str], Mapping[str, Any]]
    for rec in records:
        name, _ = logic_assignment(dict(rec))
        by_name.setdefault((rec["section"], name), rec)

    for section, variables in grouped.items():
        for variable, entry in variables.items():
            rec = by_name.get((section, variable))
            if rec and rec.get("description_source") == "device":
                full_name, description = rec.get("full_name"), rec.get("description")
            else:
                info = setting_info(variable, section, family, model, overrides)
                full_name, description = info.get("name"), info.get("desc")

            if full_name:
                entry["full_name"] = full_name
            if description:
                entry["description"] = description

            part_names = {}  # type: dict[str, str]
            for part in entry.get("parts", {}):
                part_rec = by_name.get((section, part))
                part_name = part_rec.get("full_name") if part_rec else None
                if not part_name:
                    part_name = setting_info(part, section, family, model, overrides).get("name")
                if part_name:
                    part_names[part] = part_name
            if part_names:
                entry["part_names"] = part_names

    return grouped


def format_annotated_equations(records: Iterable[Mapping[str, Any]]) -> str:
    """
    Text listing of the SELOGIC control equations that are set, by section,
    with the full name and description of each under it as a comment.

    Example:

    .. code-block:: text

       [1]
       TR := 49T OR LOSSTRIP OR JAMTRIP
           # Trip equation: SELOGIC equation with the conditions that trip the breaker.

    Args:
        records: Annotated settings records, from :func:`annotate_records`

    Returns:
        The listing, or an empty string if there are no equations
    """
    lines = []  # type: list[str]
    section = None

    for rec in records:
        if rec.get("kind") != "equation":
            continue

        if rec["section"] != section:
            section = rec["section"]
            lines.append(f"[{section}]")

        name, value = logic_assignment(dict(rec))
        line = f"{name} := {value}"
        if rec.get("comment"):
            line += f" # {rec['comment']}"
        lines.append(line)

        about = ": ".join(x for x in (rec.get("full_name"), rec.get("description")) if x)
        if about:
            lines.append(f"    # {about}")

    return "\n".join(lines) + "\n" if lines else ""


#: Settings whose value ``Y`` enables a network service, and the service
_SERVICE_ENABLES: Final[dict[str, str]] = {
    "ETELNET": "telnet",
    "T1RECV": "telnet",
    "T2RECV": "telnet",
    "EFTPSERV": "ftp",
    "FTPSERV": "ftp",
    "EHTTP": "http",
    "E61850": "iec61850",
    "EGSE": "goose",
    "EMMSFS": "mms_file_services",
}

#: Settings whose value is the number of sessions of a network service
_SERVICE_SESSIONS: Final[dict[str, str]] = {"EDNP": "dnp3", "EMOD": "modbus"}


def security_summary(records: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """
    Small, flat summary of the security-relevant settings of a relay: the
    value of each setting flagged as ``security`` (keyed by
    ``"<section>.<name>"``, e.g. ``"P1.ETELNET"``), plus:

    - ``enabled_services``: network services that are enabled on ports that
      aren't disabled, e.g. ``["ftp", "telnet"]``. Can include ``telnet``,
      ``ftp``, ``http``, ``iec61850``, ``goose``, ``mms_file_services``,
      ``dnp3`` and ``modbus``.
    - ``anonymous_ftp``: if anonymous FTP logins are allowed (if the relay has the setting)
    - ``fast_operate_ports``: ports that accept SEL Fast Operate messages
    - ``disabled_ports``: ports that are turned off (``EPORT := N``)

    Args:
        records: Annotated settings records, from :func:`annotate_records`

    Returns:
        The summary, or an empty dict if there are no security-relevant settings
    """
    records = list(records)
    disabled = sorted(
        {
            rec["section"]
            for rec in records
            if rec.get("name") == "EPORT" and str(rec.get("value")).strip().upper() == "N"
        }
    )

    flagged = {}  # type: dict[str, Any]
    services = set()  # type: set[str]
    fast_operate = []  # type: list[str]
    anonymous_ftp = None  # type: bool | None

    for rec in records:
        if not rec.get("security"):
            continue

        section, name = rec["section"], rec["name"]
        value = str(rec.get("value") or "").strip()
        flagged[f"{section}.{name}"] = value

        if section in disabled:
            continue

        upper = value.upper()
        if name in _SERVICE_ENABLES and upper == "Y":
            services.add(_SERVICE_ENABLES[name])
        elif name in _SERVICE_SESSIONS and upper.isdigit() and int(upper) > 0:
            services.add(_SERVICE_SESSIONS[name])
        elif name == "FASTOP" and upper == "Y":
            fast_operate.append(section)
        elif name == "FTPANMS":
            anonymous_ftp = bool(anonymous_ftp) or upper == "Y"

    if not flagged:
        return {}

    summary = {
        "enabled_services": sorted(services),
        "fast_operate_ports": fast_operate,
        "disabled_ports": disabled,
    }  # type: dict[str, Any]
    if anonymous_ftp is not None:
        summary["anonymous_ftp"] = anonymous_ftp
    summary.update(flagged)

    return summary


#: What the value of each field of a user's entry has to be
_USER_FIELD_TYPES: Final[dict[str, str]] = {
    "name": "a string",
    "desc": "a string",
    "units": "a string",
    "values": "a string or a list of values",
    "security": "true or false",
}


def _valid_user_field(key: str, value: Any) -> bool:
    # If the value of a field (ENTRY_FIELDS) of a user's entry has the right type
    if key == "values":
        if isinstance(value, list):
            return all(isinstance(v, (str, int, float)) and not isinstance(v, bool) for v in value)
        return isinstance(value, str)
    if key == "security":
        return isinstance(value, bool)
    return isinstance(value, str)


def _clean_user_fields(
    entry: Mapping[str, Any], where: str, path: str | Path, extra_keys: Iterable[str] = ()
) -> SettingEntry:
    # Keep the fields of a user's entry that have the right type, with a
    # warning for the others. Keys in extra_keys are kept as they are.
    cleaned = {}  # type: SettingEntry

    for key, value in entry.items():
        if key in extra_keys:
            cleaned[key] = value
        elif key not in _USER_FIELD_TYPES:
            log.warning(f"Ignoring unknown key '{key}' of {where} in '{path}'")
        elif value is None:
            continue
        elif _valid_user_field(key, value):
            cleaned[key] = value
        else:
            log.warning(
                f"Ignoring '{key}' of {where} in '{path}': it has to be {_USER_FIELD_TYPES[key]}"
            )

    return cleaned


def _clean_user_entry(name: str, entry: Mapping[str, Any], path: str | Path) -> SettingEntry:
    # Drop the keys of a user's entry that can't be used, with a warning, so
    # a mistake in one entry doesn't break the annotations of other settings
    where = f"setting '{name}'"
    cleaned = _clean_user_fields(
        entry, where, path, extra_keys=("sections", "only", "by_family", "by_model")
    )

    sections = cleaned.pop("sections", None)
    if sections is not None:
        if not isinstance(sections, str):
            log.warning(f"Ignoring 'sections' of {where} in '{path}': it has to be a string")
        else:
            try:
                re.compile(sections)
                cleaned["sections"] = sections
            except re.error as ex:
                log.warning(f"Ignoring the 'sections' of {where} in '{path}': {ex}")

    only = cleaned.pop("only", None)
    if isinstance(only, str):
        only = [only]
    if isinstance(only, list) and all(isinstance(f, str) for f in only):
        if only:
            cleaned["only"] = [f.strip().lower() for f in only]
    elif only is not None:
        log.warning(
            f"Ignoring 'only' of {where} in '{path}': it has to be a family (e.g. \"4xx\") "
            "or a list of families"
        )

    for key, normalize in (("by_family", str.lower), ("by_model", normalize_model)):
        values = cleaned.pop(key, None)
        if values is None:
            continue
        if not isinstance(values, dict):
            log.warning(f"Ignoring '{key}' of {where} in '{path}': it isn't an object")
            continue

        cleaned[key] = {}
        for item, item_entry in values.items():
            item_where = f"{where} ({key} '{item}')"
            if isinstance(item_entry, dict):
                item_key = normalize(str(item).strip())
                cleaned[key][item_key] = _clean_user_fields(item_entry, item_where, path)
            else:
                log.warning(f"Ignoring {item_where} in '{path}': it isn't an object")

    return cleaned


# Loaded override files, keyed by path, modification time and size
_OVERRIDE_CACHE: dict[tuple[str, int, int], dict[str, SettingEntry]] = {}


def load_setting_descriptions(path: str | Path) -> dict[str, SettingEntry]:
    """
    Load a user's setting descriptions from a JSON file.

    The file has the same format as :data:`SETTING_INFO`: an object keyed by
    setting name, where each value is an entry (see :data:`SettingEntry`):

    .. code-block:: json

       {
           "NETMODE": {
               "name": "Ethernet operating mode",
               "desc": "How the Ethernet ports are used",
               "values": "FIXED, FAILOVER, SWITCHED, PRP",
               "by_model": {"710": {"values": "FIXED, FAILOVER, SWITCHED"}}
           }
       }

    Entries that aren't objects are skipped with a warning, and so are keys
    with values of the wrong type (e.g. ``"security": "no"`` instead of
    ``false``), so a mistake in one entry doesn't affect the other settings.
    Errors reading the file are logged and an empty dict is returned, so a
    bad file doesn't stop parsing.

    Returns:
        The entries, keyed by uppercase setting name
    """
    try:
        file = Path(path).expanduser()
        stat = file.stat()
        key = (str(file.resolve()), stat.st_mtime_ns, stat.st_size)
        if key in _OVERRIDE_CACHE:
            return _OVERRIDE_CACHE[key]

        data = json.loads(file.read_text(encoding="utf-8"))
    except Exception as ex:
        log.warning(f"Failed to read the SEL setting descriptions file '{path}': {ex}")
        return {}

    if not isinstance(data, dict):
        log.warning(f"SEL setting descriptions file '{path}' isn't a JSON object, ignoring it")
        return {}

    entries = {}  # type: dict[str, SettingEntry]
    for name, entry in data.items():
        if not isinstance(entry, dict):
            log.warning(f"Skipping setting '{name}' in '{path}': the value isn't an object")
            continue
        entries[str(name).strip().upper()] = _clean_user_entry(name, entry, path)

    log.debug(f"Loaded {len(entries)} SEL setting descriptions from '{path}'")
    _OVERRIDE_CACHE[key] = entries
    return entries


__all__ = [
    "ANNOTATION_FIELDS",
    "CLASS_NAMES",
    "PATTERN_INFO",
    "SETTING_INFO",
    "SettingEntry",
    "annotate_logic",
    "annotate_record",
    "annotate_records",
    "class_name",
    "format_annotated_equations",
    "load_setting_descriptions",
    "parse_allowed_values",
    "parse_range",
    "security_summary",
    "setting_info",
]
