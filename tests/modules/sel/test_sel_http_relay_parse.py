"""
Tests for parsing the pages of the web interface of SEL relays
(:class:`~peat.modules.sel.sel_http.SELHTTP` and the shared parsers in
:mod:`peat.modules.sel.relay_parse`).

The "characterization" tests run the ``SELHTTP`` methods against a fake web
server. They were written before the parsing was split out of ``SELHTTP``,
and lock in its behavior. The pages are synthetic, see data_files/web/README.md.
"""

from datetime import datetime
from pathlib import Path

import pytest
from requests import Response

from peat import DeviceData, PeatError, config, datastore
from peat.modules.sel import relay_command_parse, relay_parse, sel_http
from peat.modules.sel.sel_default_creds import web_candidates
from peat.modules.sel.sel_http import SELHTTP
from peat.modules.sel.sel_relay import SELRelay
from peat.protocols import HTTP

WEB_DIR = Path(__file__).resolve().parent / "data_files" / "web"
RELAY_IP = "192.0.2.30"
SESSION_URL = f"http://{RELAY_IP}:80/protected/N1a2b3c4d/"

#: Pages of a 400-series relay, which use "static_command.html?cmd=<cmd>&param=<param>"
PAGES_451 = {
    "static_command.html?cmd=ver": "relay_451_ver.html",
    "static_command.html?cmd=eth": "relay_451_eth.html",
    "static_command.html?cmd=sho&param=P%201": "relay_451_sho_p1.html",
    "static_command.html?cmd=sho&param=P%20F": "relay_451_sho_pf.html",
    "static_command.html?cmd=sho&param=P%205": "relay_451_sho_p5.html",
    "static_command.html?cmd=sho&param=F": "relay_451_sho_f.html",
    "static_command.html?cmd=sho&param=O": "relay_451_sho_o.html",
    "static_command.html?cmd=met&param=AMV": "relay_451_met_amv.html",
    "static_command.html?cmd=met&param=PMV": "relay_451_met_pmv.html",
}

#: Pages of a SEL-351S, which use "<cmd>.html"
PAGES_351S = {
    "ver.html": "relay_351s_ver.html",
    "eth.html": "relay_351s_eth.html",
    "shop1.html": "relay_351s_shop1.html",
    "shop4.html": "relay_351s_shop4.html",
    "shop5.html": "relay_351s_shop5.html",
    "mete.html": "relay_351s_mete.html",
}

INVALID_COMMAND = b"<html><body><pre>\nInvalid Command\n</pre></body></html>"


@pytest.fixture(autouse=True)
def env(tmp_path, mocker):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "TEMP_DIR": tmp_path / "temp_results",
        },
    )
    mocker.patch.object(datastore, "objects", [])
    mocker.patch.object(HTTP, "page_cache", {})
    mocker.patch("peat.modules.sel.sel_http.sleep")
    return tmp_path


def _page(text: str) -> bytes:
    """A relay page with the output of a command in the ``<pre>`` section."""
    return f"<html><body><pre>\n{text}</pre></body></html>".encode()


class FakeRelayWeb:
    """
    A relay's web server. Pages are keyed by the part of the URL after the
    session URL, e.g. ``static_command.html?cmd=ver``. Other pages are 404.
    """

    def __init__(self, pages: dict[str, bytes | str]) -> None:
        self.pages = {
            name: (WEB_DIR / data).read_bytes() if isinstance(data, str) else data
            for name, data in pages.items()
        }
        self.requests: list[str] = []

    def get(self, url: str, **kwargs) -> Response:  # noqa: ARG002
        name = url.removeprefix(SESSION_URL)
        self.requests.append(name)

        resp = Response()
        resp.url = url
        resp.encoding = "utf-8"
        if name in self.pages:
            resp.status_code = 200
            resp._content = self.pages[name]
        else:
            resp.status_code = 404
            resp._content = b"<html><body>Not Found</body></html>"
        return resp

    def close(self) -> None:
        pass


def _relay(pages: dict[str, bytes | str]) -> tuple[SELHTTP, DeviceData]:
    http = SELHTTP(RELAY_IP, 80)
    http._session = FakeRelayWeb(pages)
    http._session_url = SESSION_URL
    http.relay_logged_in = True
    return http, datastore.get(RELAY_IP, "ip")


def _iface(dev: DeviceData, name: str):
    matches = [i for i in dev.interface if i.name == name]
    assert len(matches) == 1, f"{len(matches)} interfaces named {name}: {dev.interface}"
    return matches[0]


# ---------------------------------------------------------------------------
# Characterization: "ver" (get_device_features)
# ---------------------------------------------------------------------------


def test_get_device_features_451():
    http, dev = _relay(PAGES_451)

    assert http.get_device_features(dev) is True

    assert dev.description.model == "451"
    assert dev.description.product == "SEL-451-5"
    assert dev.firmware.id == "SEL-451-5-R320-V1-Z021011-D20190415"
    assert dev.firmware.revision == "R320"
    assert dev.firmware.version == "V1"
    assert dev.firmware.release_date == datetime(2019, 4, 15)
    assert dev.boot_firmware.id == "SLBT-4XX-R300-V0-Z001001-D20180801"
    assert dev.firmware.checksum == "4E2F"
    assert dev.serial_number == "1234567890"
    assert dev.part_number == "0451512345678X9"
    assert dev.hardware.memory_total == 64 * 1024 * 1024
    assert dev.hardware.memory_type == "ram"

    assert dev.extra["CID"] == "1A2B"
    assert dev.extra["mainboard"] == {
        "Code FLASH Size": "16 MB",
        "Data FLASH Size": "32 MB",
        "RAM Size": "64 MB",
        "EEPROM Size": "64 kB",
    }
    assert dev.extra["front_panel"] == "installed"
    assert dev.extra["analog_inputs"] == {
        "W": "Currents: 5 Amp",
        "X": "Currents: 5 Amp",
        "Y": "Voltage:  67 Volts",
        "Z": "Voltage:  67 Volts",
    }
    assert dev.extra["interface_boards"] == {
        "Board 1": "INT4 installed",
        "Board 2": "not installed",
    }
    assert dev.extra["e4_configuration"] == "installed"
    assert dev.extra["extended_relay_features"] == ["DNP3", "IEC 61850", "Synchrophasors"]
    assert "relay_features" not in dev.extra

    # Probed "ver.html" first, then found the 400-series URL style
    assert http._session.requests == ["ver.html", "static_command.html?cmd=ver"]
    assert http._url_parts == ("static_command.html?cmd=", "")


def test_get_device_features_351s():
    http, dev = _relay(PAGES_351S)

    assert http.get_device_features(dev) is True

    assert dev.description.model == "351S"
    assert dev.description.product == "SEL-351S-6"
    assert dev.firmware.revision == "R514"
    assert dev.boot_firmware.id == "SLBT-3CF1-R102-V0-Z100100-D20090925"
    assert dev.firmware.checksum == "2C4B"
    assert dev.serial_number == "3456789012"
    assert dev.part_number == "0351S6H3351X1X"
    assert dev.extra["relay_features"] == [
        "DNP",
        "Modbus",
        "Mirrored Bits",
        "Load Profile",
        "Two 10/100BASE-T Ports",
    ]
    for key in ["CID", "mainboard", "front_panel", "extended_relay_features"]:
        assert key not in dev.extra
    assert http._url_parts == ("", ".html")


def test_get_device_features_311l_two_space_indent():
    http, dev = _relay({"ver.html": "relay_311l_ver.html"})

    assert http.get_device_features(dev) is True

    assert dev.description.model == "311L"
    assert dev.firmware.checksum == "77AA"
    assert dev.part_number == "0311L1234567X"
    assert dev.extra["mainboard"] == {"Code FLASH Size": "4 MB", "RAM Size": "8 MB"}
    assert dev.hardware.memory_total == 8 * 1024 * 1024
    assert dev.extra["analog_inputs"] == {"Currents": "5 Amp", "Voltages": "67 Volts"}
    assert dev.extra["interface_boards"] == {"Board 1": "not installed"}
    assert dev.extra["extended_relay_features"] == ["None"]


def test_get_device_features_page_missing():
    http, dev = _relay({})
    assert http.get_device_features(dev) is False


# ---------------------------------------------------------------------------
# Characterization: "eth" (get_communications)
# ---------------------------------------------------------------------------


def test_get_communications_451():
    http, dev = _relay(PAGES_451)

    assert http.get_communications(dev) is True

    comms = dict(dev.extra["communications"])
    assert sorted(comms.pop("mac_addresses")) == ["00:30:a7:00:00:01", "00:30:a7:00:00:02"]
    assert {k: v for k, v in comms.items() if k != "port_sections"} == {
        "ipv4_address": "192.0.2.30",
        "ipv4_subnet_mask": "255.255.255.0",
        "gateway": "192.0.2.1",
        "network_mode": "FAILOVER",
        "primary_port": "5A",
        "active_port": "5A",
        "port_information": {
            "5A": {"link": "up", "speed": "100M", "duplex": "Full", "media": "TX"},
            "5B": {"link": "down", "speed": "", "duplex": "", "media": "TX"},
        },
        "statistics": {
            "packets_sent": -1,
            "packets_received": -1,
            "bytes_sent": 1463657022,
            "bytes_received": 1664082074,
            "errors_sent": 0,
            "errors_received": 0,
        },
    }


def test_get_communications_page_missing():
    http, dev = _relay({})
    assert http.get_communications(dev) is False
    assert "communications" not in dev.extra


# ---------------------------------------------------------------------------
# Characterization: port settings, front panel, and outputs ("sho")
# ---------------------------------------------------------------------------


def test_get_port_settings_451():
    pages = {
        **PAGES_451,
        "static_command.html?cmd=sho&param=P%202": INVALID_COMMAND,
        "static_command.html?cmd=sho&param=P%203": INVALID_COMMAND,
    }
    http, dev = _relay(pages)

    assert http.get_port_settings(dev) is True

    assert dev.extra["interfaces"] == {
        "Port 1": {
            "Protocol Selection": {"EPORT": "Y", "MAXACC": "2", "PROTO": "SEL"},
            "Communications Settings": {
                "SPEED": "9600",
                "BITS": "8",
                "PARITY": "N",
                "STOPBIT": "1",
                "RTSCTS": "N",
                "T_OUT": "15",
            },
        },
        "Port 2": {},
        "Port 3": {},
        "Port F": {
            "Protocol Selection": {"EPORT": "Y", "MAXACC": "2"},
            "Communications Settings": {
                "SPEED": "9600",
                "BITS": "8",
                "PARITY": "N",
                "STOPBIT": "1",
            },
        },
        "Port 5": {
            "Protocol Card Settings": {
                "EPORT": "Y",
                "IPADDR": "192.0.2.30/24",
                "DEFRTR": "192.0.2.1",
                "NETPORT": "A",
                "FAILOVR": "Y",
            },
            "FTP Settings": {
                "FTPSERV": "Y",
                "FTPCBAN": "FTP SERVER:",
                "FTPIDLE": "5",
                "FTPANMS": "N",
            },
        },
    }

    port_1 = _iface(dev, "Port 1")
    assert port_1.type == "serial"
    assert port_1.application == "sel"
    assert port_1.baudrate == 9600
    assert port_1.data_bits == 8
    assert port_1.parity == "none"
    assert port_1.stop_bits == 1
    assert port_1.flow_control == "none"
    assert port_1.extra == {"inactivity_timeout": 15.0, "max_privilege_level": "2"}

    port_5 = _iface(dev, "Port 5")
    assert port_5.type == "ethernet"
    assert port_5.enabled is True
    assert port_5.ip == "192.0.2.30"
    assert port_5.subnet_mask == "255.255.255.0"
    assert port_5.gateway == "192.0.2.1"
    ftp = [s for s in dev.service if s.protocol == "ftp"]
    assert len(ftp) == 1
    assert ftp[0].enabled is True
    assert ftp[0].extra["idle_timeout"] == 5.0
    assert ftp[0].extra["anonymous_login_enabled"] is False

    assert _iface(dev, "Port F").baudrate == 9600
    assert http._port_args_len == 2


def test_get_port_settings_351s():
    pages = {
        **PAGES_351S,
        "shop2.html": INVALID_COMMAND,
        "shop3.html": INVALID_COMMAND,
    }
    http, dev = _relay(pages)

    assert http.get_port_settings(dev) is True

    assert dev.extra["interfaces"] == {
        "Port 1": {
            "EPORT": "Y",
            "PROTO": "SEL",
            "MAXACC": "C",
            "SPEED": "2400",
            "BITS": "8",
            "PARITY": "N",
            "STOP": "1",
            "RTSCTS": "N",
            "T_OUT": "5",
            "AUTO": "N",
            "FASTOP": "N",
        },
        "Port 2": {},
        "Port 3": {},
        "Port F": {
            "EPORT": "Y",
            "PROTO": "SEL",
            "MAXACC": "C",
            "SPEED": "9600",
            "BITS": "8",
            "PARITY": "N",
            "STOP": "1",
        },
        "Port 5": {
            "EPORT": "Y",
            "IPADDR": "192.0.2.31",
            "SUBNETM": "255.255.255.0",
            "DEFRTR": "192.0.2.1",
            "NETMODE": "FAILOVER",
            "FTIME": "1.00",
            "NETPORT": "A",
            "ETELNET": "Y",
            "EFTPSERV": "N",
            "EHTTP": "Y",
        },
    }

    port_1 = _iface(dev, "Port 1")
    assert port_1.baudrate == 2400
    assert port_1.stop_bits == 1
    assert port_1.extra["max_privilege_level"] == "C"
    port_5 = _iface(dev, "Port 5")
    assert port_5.ip == "192.0.2.31"
    assert port_5.subnet_mask == "255.255.255.0"
    assert port_5.gateway == "192.0.2.1"
    assert http._port_args_len == 1


def test_get_port_settings_no_page():
    http, dev = _relay({})
    assert http.get_port_settings(dev) is False
    assert "interfaces" not in dev.extra


def test_get_front_panel_settings_451():
    http, dev = _relay(PAGES_451)

    assert http.get_front_panel_settings(dev) is True

    assert dev.extra["front_panel_data"] == {
        "front_panel_settings": {
            "FP_TO": {"value": "15", "comment": "minutes"},
            "FP_CONT": {"value": "5", "comment": ""},
            "FP_AUTO": {"value": "OVERRIDE", "comment": ""},
            "RSTLED": {"value": "Y", "comment": ""},
        },
        "selectable_screens": {"SCROLD": "5"},
    }


def test_get_output_data_451():
    http, dev = _relay(PAGES_451)

    assert http.get_output_data(dev) is True

    assert dev.extra["output_data"] == {
        "main_board": {
            "OUT101": {"value": "TRIP", "comment": "trip coil"},
            "OUT102": {"value": "CLOSE", "comment": ""},
            "OUT103": {"value": "NA", "comment": ""},
        },
        "interface_board_1": {"OUT201": "PSV01"},
    }


# ---------------------------------------------------------------------------
# Characterization: metering ("met")
# ---------------------------------------------------------------------------


def test_get_meter_automation_and_protection_451():
    http, dev = _relay(PAGES_451)

    assert http.get_meter_automation(dev) is True
    assert http.get_meter_protection(dev) is True

    assert dev.extra["meter_automation"] == {
        "AMV001": 0.0,
        "AMV002": 12.5,
        "AMV003": -1.25,
        "AMV004": 100.0,
    }
    assert dev.extra["meter_protection"] == {"PMV01": 1.0, "PMV02": 2.5, "PMV03": -3.0}


#: Energy metering page of a 400-series relay, laid out the way the original
#: parser expects it (the column labels are padded to the width of the table)
MET_E_451 = (
    "Energy (MWh)          A            B            C            3P            \n"
    "IN                1.250        1.300        1.350         3.900\n"
    "OUT               0.100        0.200        0.300         0.600\n"
    "TOTAL             1.350        1.500        1.650         4.500\n"
    "\n"
    "LAST ENERGY RESET: 03/01/2021 00:00:00.000\n"
)


def test_get_meter_energy_451():
    http, dev = _relay({"static_command.html?cmd=met&param=E": _page(MET_E_451)})
    dev.description.model = "451"

    assert http.get_meter_energy(dev) is True

    assert dev.extra["meter_energy"] == {
        "last_energy_reset": "2021-03-01T00:00:00",
        "A": {"in": 1.25, "out": 0.1, "total": 1.35},
        "B": {"in": 1.3, "out": 0.2, "total": 1.5},
        "C": {"in": 1.35, "out": 0.3, "total": 1.65},
        "3P": {"in": 3.9, "out": 0.6, "total": 4.5},
    }


# ---------------------------------------------------------------------------
# Characterization: page parsing and helpers
# ---------------------------------------------------------------------------


def test_parse_page_data_crlf():
    http = SELHTTP(RELAY_IP, 80)
    assert http.parse_page_data(b"<html><pre>\r\nFID=X\r\nCID=Y\r\n</pre></html>") == (
        "\nFID=X\nCID=Y\n"
    )


def test_parse_page_data_no_pre():
    http = SELHTTP(RELAY_IP, 80)
    with pytest.raises(PeatError):
        http.parse_page_data(b"<html><body>Login</body></html>")


def test_read_page_records_and_returns_pre_text(env):
    http, dev = _relay({"ver.html": _page("FID=SEL-351S-6-R514-V0-Z103103-D20110429\n")})

    assert http.read_page("ver") == "\nFID=SEL-351S-6-R514-V0-Z103103-D20110429\n"
    assert (env / "devices" / RELAY_IP / "http_files/protected/session/ver.html").is_file()
    assert [f.name for f in dev.files] == ["ver.html"]


def test_read_page_no_url_style():
    http, _ = _relay({})
    with pytest.raises(PeatError, match="could not determine command URL"):
        http.read_page("ver")
    assert http._url_parts is None


def test_helper_parse_show_groups():
    # Replaces parse_multiple_lists(), which returned {} if a page
    # had an odd number of blocks, e.g. a title line (see below)
    page = 'Heading 1\n\nA        := 1       B := "two"\n\nHeading 2\n\nC := 3\n'
    expected = {"Heading 1": {"A": "1", "B": "two"}, "Heading 2": {"C": "3"}}
    assert relay_command_parse.parse_show_groups(page) == expected
    assert relay_command_parse.parse_show_groups(f"Port 5\n\n{page}") == expected


def test_helper_normalize_keys_and_parse_comments():
    assert sel_http.normalize_keys({" Main Board ": 1, "Front Panel Settings": 2}) == {
        "main_board": 1,
        "front_panel_settings": 2,
    }
    assert sel_http.parse_comments({"A": "1 # one", "B": "2"}) == {
        "A": {"value": "1", "comment": "one"},
        "B": {"value": "2", "comment": ""},
    }


def test_helper_parse_simple_line():
    page = "\nFID=SEL-451\nSerial Number: 1234\n  BFID= SLBT-4XX\n"
    assert sel_http.parse_simple_line("FID", page) == "SEL-451"
    assert sel_http.parse_simple_line("Serial Number", page) == "1234"
    assert sel_http.parse_simple_line("BFID", page) == "SLBT-4XX"
    assert sel_http.parse_simple_line("CID", page) == ""


# ---------------------------------------------------------------------------
# Characterization: login and session URL
# ---------------------------------------------------------------------------

LOGIN_PAGE = b"""<html><body><form action="/login" method="post">
<input type="text" name="usrid"/><input type="password" name="pswd"/>
<input type="hidden" name="rando" value="314159"/>
</form></body></html>"""


@pytest.fixture
def relay_login(requests_mock):
    base = f"http://{RELAY_IP}:80"
    requests_mock.get(f"{base}/", content=LOGIN_PAGE)
    return base, requests_mock


@pytest.mark.parametrize(
    ("location", "body"),
    [
        # SEL-351S: the session ID and "protected" are in the URL
        ("/protected/N1a2b3c4d/login.html", b"<html></html>"),
        # SEL-451: the session ID is in the URL, without "protected"
        ("/N1a2b3c4d/login_query.html", b"<html></html>"),
        # SEL-351: no redirect, the session ID is in the first link in the page
        (None, b'<html><a href="/N1a2b3c4d/ver.html">Version</a></html>'),
    ],
    ids=["351S", "451", "351"],
)
def test_login_session_url(relay_login, location, body):
    base, mock = relay_login
    if location:
        mock.post(f"{base}/login", status_code=302, headers={"Location": location})
        mock.get(f"{base}{location}", content=body)
    else:
        mock.post(f"{base}/login", content=body)

    http = SELHTTP(RELAY_IP, 80)
    assert http.login("ACC", "OTTER") is True

    assert http._session_url == f"{base}/protected/N1a2b3c4d/"
    assert http.successful_creds == ("ACC", "OTTER")
    assert http.relay_logged_in is True
    assert http.protocol == "http"
    assert http._rando == "314159"
    sent = mock.request_history[1]
    assert sent.method == "POST"
    assert sent.text == "usrid=ACC&pswd=OTTER&rando=314159"


def test_login_invalid_credentials(relay_login):
    base, mock = relay_login
    mock.post(f"{base}/login", status_code=302, headers={"Location": "/login.html?error=invalid"})
    mock.get(f"{base}/login.html?error=invalid", content=b"<html></html>")

    http = SELHTTP(RELAY_IP, 80)
    assert http.login("ACC", "WRONG") is False
    assert http.relay_logged_in is False
    assert http.successful_creds is None


def test_login_no_login_page(requests_mock):
    requests_mock.get(f"http://{RELAY_IP}:80/", status_code=404)
    http = SELHTTP(RELAY_IP, 80)
    assert http.login() is False


def test_login_no_input_in_page(requests_mock):
    requests_mock.get(f"http://{RELAY_IP}:80/", content=b"<html><body>Hi</body></html>")
    http = SELHTTP(RELAY_IP, 80)
    assert http.login() is False
    assert len(requests_mock.request_history) == 1  # Never sent the credentials


# ---------------------------------------------------------------------------
# Parsers that also work for Telnet and serial output
# ---------------------------------------------------------------------------


def test_shared_parsers_are_used_by_selhttp():
    # SELHTTP uses the command output parsers, which also accept Telnet/serial
    # output. STA, SER and HIS are already shared with the Telnet/serial code.
    for name in ["parse_ver_output", "parse_eth_output", "parse_show_groups"]:
        assert getattr(sel_http, name) is getattr(relay_command_parse, name)
    assert sel_http.parse_and_process_events is relay_parse.parse_and_process_events
    assert sel_http.parse_status_output is relay_parse.parse_status_output


# ---------------------------------------------------------------------------
# Fixed bugs and new behavior (after the parsing was split out of SELHTTP)
# ---------------------------------------------------------------------------


def test_parse_page_data_with_links():
    # The <pre> of the "his" page has links. pre.string was None for these.
    http = SELHTTP(RELAY_IP, 80)
    page = b'<html><pre>\n#  DATE\n<a href="eve.html&param=1">1</a>  04/10/19\n</pre></html>'
    assert http.parse_page_data(page) == "\n#  DATE\n1  04/10/19\n"


def test_parse_page_data_multiple_sections():
    # The SEL-351 "sho1" page has the group settings and the logic settings
    http = SELHTTP(RELAY_IP, 80)
    page = (
        b"<html><pre>\nGroup 1\nRID =FEEDER\n</pre><pre>\nSELogic group 1\nTR =51PT\n</pre></html>"
    )
    assert http.parse_page_data(page) == (
        "\nGroup 1\nRID =FEEDER\n\n\n\nSELogic group 1\nTR =51PT\n"
    )


def test_parse_simple_line_fixes():
    # The first line of the text (no newline before it)
    assert (
        relay_command_parse.parse_simple_line("Partnumber", "Partnumber: 0351S6H3") == "0351S6H3"
    )
    # Names with regex characters
    assert relay_command_parse.parse_simple_line("Main Board I/O", "Main Board I/O: 2 out") == "2"
    assert relay_command_parse.parse_simple_line("PT (V)", "PT (V)= 120") == "120"
    assert relay_command_parse.parse_simple_line("PT (V)", "PT V= 120") == ""
    # "|" isn't a separator, ":=" is
    assert relay_command_parse.parse_simple_line("A", "A| 1\nB := 2") == ""
    assert relay_command_parse.parse_simple_line("B", "A| 1\nB := 2") == "2"
    # A name must be at the start of a line ("FID" isn't in "BFID")
    assert relay_command_parse.parse_simple_line("FID", "  BFID=SLBT\n") == ""
    # The old function is still importable from sel_http
    assert sel_http.parse_simple_line is relay_command_parse.parse_simple_line


def test_get_device_features_fid_on_first_line():
    # The old parser missed values on the first line of the <pre> section
    page = b"<html><pre>FID=SEL-451-5-R320-V1-Z021011-D20190415\nCID=1A2B\n</pre></html>"
    http, dev = _relay({"ver.html": page})

    assert http.get_device_features(dev) is True
    assert dev.description.model == "451"
    assert dev.extra["CID"] == "1A2B"


def test_get_device_features_boot_checksum_and_no_empty_values():
    http, dev = _relay(PAGES_351S)
    dev.part_number = "FROM-STATUS"
    http._session.pages["ver.html"] = _page("FID=SEL-351S-6-R514-V0-Z103103-D20110429\n")

    assert http.get_device_features(dev) is True

    # The part number wasn't replaced with an empty string,
    # and no empty "FID"/"BFID" values were put in extra
    assert dev.part_number == "FROM-STATUS"
    assert "BFID" not in dev.extra
    assert "FID" not in dev.extra


def test_process_ver_info_boot_firmware_checksum():
    dev = DeviceData()
    relay_command_parse.process_ver_info({"checksum": "D507"}, dev)
    assert dev.boot_firmware.checksum == "D507"
    assert dev.firmware.checksum == "D507"  # Kept, as before


#: SEL-421 layout of VER output (from a Telnet session): fiber port and
#: communications card lines, and a different note at the end
VER_421_TELNET = """=>>VER
FID=SEL-421-R101-V0-Z001001-D20010315
CID=5EEA
Part Number: 04210415X11XXHX
Serial Number: 2001001234
SELboot:
    BFID= SLBT-4XX-R1XX-V0-Z001001-D20010703
    Checksum: D507
Mainboard:
    Code FLASH Size:     4 MB
    RAM Size:            2 MB
Front Panel: installed  Warning - hardware does not match part number
Analog Inputs:
    W: Currents: 5 Amp
    Y: Voltage:    67 Volts
Fiber Port: not installed
Interface Boards:
    Board 1: not installed
Communications Card:
    not installed
Extended Relay Features:
    None

If the information above is unexpected, contact SEL.

=>>""".replace("\n", "\r\n")


def test_parse_ver_output_421_telnet():
    assert relay_command_parse.parse_ver_output(VER_421_TELNET) == {
        "FID": "SEL-421-R101-V0-Z001001-D20010315",
        "BFID": "SLBT-4XX-R1XX-V0-Z001001-D20010703",
        "CID": "5EEA",
        "part_number": "04210415X11XXHX",
        "serial_number": "2001001234",
        "checksum": "D507",
        "mainboard": {"Code FLASH Size": "4 MB", "RAM Size": "2 MB"},
        "front_panel": "installed",
        "analog_inputs": {"W": "Currents: 5 Amp", "Y": "Voltage:    67 Volts"},
        "interface_boards": {"Board 1": "not installed"},
        "extended_relay_features": ["None"],
        "hardware_warnings": [
            "Front Panel: installed  Warning - hardware does not match part number"
        ],
    }


def test_parse_ver_output_351s():
    text = sel_http.extract_pre_text((WEB_DIR / "relay_351s_ver.html").read_bytes())
    info = relay_command_parse.parse_ver_output(text)

    assert info["part_number"] == "0351S6H3351X1X"
    assert info["checksum"] == "2C4B"
    assert info["analog_input_voltage"] == "300 Vac, Wye"
    assert info["analog_input_current"] == "5 Amp Phase, 5 Amp Neutral"
    assert info["main_board_io"] == "2 High I/C Outputs, 6 Standard Outputs, 6 Inputs"
    assert info["additional_io"] == "4 Standard Outputs, 16 Inputs"
    assert info["relay_features"][0] == "DNP"


def test_parse_ver_output_nothing():
    assert relay_command_parse.parse_ver_output("") == {}
    assert relay_command_parse.parse_ver_output("=>>\nInvalid Command\n=>>") == {}


def test_get_communications_351s():
    http, dev = _relay(PAGES_351S)

    assert http.get_communications(dev) is True

    comms = dev.extra["communications"]
    assert comms["mac_addresses"] == ["00:30:a7:00:00:11", "00:30:a7:00:00:12"]
    assert comms["ipv4_address"] == "192.0.2.31"
    # "SUBNET MASK" is a separate line on the 351S
    assert comms["ipv4_subnet_mask"] == "255.255.255.0"
    assert comms["primary_port"] == "5A"
    assert comms["active_port"] == "5B"
    # "--" is an unknown value, like "---"
    assert comms["port_information"]["5A"] == {
        "link": "down",
        "speed": "",
        "duplex": "",
        "media": "TX",
    }
    assert comms["statistics"]["packets_received"] == 340
    assert comms["port_sections"]["IP Port"]["mac_address"] == "00:30:a7:00:00:11"
    assert comms["port_sections"]["GOOSE Port"]["statistics"]["bytes_sent"] == 512000
    assert {"00:30:A7:00:00:11", "00:30:A7:00:00:12"} <= dev.related.mac


def test_get_communications_451_mac_order():
    http, dev = _relay(PAGES_451)
    assert http.get_communications(dev) is True
    # In the order of the page (a set was used before, so the order was random)
    assert dev.extra["communications"]["mac_addresses"] == [
        "00:30:a7:00:00:01",
        "00:30:a7:00:00:02",
    ]
    assert "port_sections" not in dev.extra["communications"]


#: ETH output of a SEL-751A-style relay from a Telnet session
ETH_751A_TELNET = """=>>ETH

SEL-751A                                            Date: 06/05/2008   Time: 10:41:37
FEEDER RELAY                                        Time Source: Internal

 MAC: 00-30-A7-00-75-6A
 IP ADDRESS: 192.0.2.2
 SUBNET MASK: 255.255.255.0
 DEFAULT GATEWAY: 192.0.2.1

 PRIMARY PORT:       PORT 1A
 ACTIVE PORT:        PORT 1B

                  LINK    SPEED   DUPLEX    MEDIA
PORT 1A           Up     100M      Full     FX
PORT 1B           Down    --       --       FX

=>>"""


def test_parse_eth_output_751a_telnet():
    assert relay_command_parse.parse_eth_output(ETH_751A_TELNET) == {
        "mac_addresses": ["00:30:a7:00:75:6a"],
        "ipv4_address": "192.0.2.2",
        "ipv4_subnet_mask": "255.255.255.0",
        "gateway": "192.0.2.1",
        "network_mode": "",
        # The whole value (the old parser only kept "PORT")
        "primary_port": "PORT 1A",
        "active_port": "PORT 1B",
        "port_information": {
            "1A": {"link": "up", "speed": "100M", "duplex": "Full", "media": "FX"},
            "1B": {"link": "down", "speed": "", "duplex": "", "media": "FX"},
        },
        "statistics": {},
    }


@pytest.mark.parametrize("value", ["garbage/xx", "192.0.2.300/24", "192.0.2.5/40"])
def test_parse_eth_output_invalid_cidr(value):
    # Raised AddressValueError/NetmaskValueError before, which lost all of the output
    text = f"IP ADDRESS: {value}\nDEFAULT GATEWAY: 192.0.2.1\nMAC 1: 00-30-A7-00-00-01\n"

    result = relay_command_parse.parse_eth_output(text)

    assert result["ipv4_address"] == value
    assert result["ipv4_subnet_mask"] == ""
    assert result["gateway"] == "192.0.2.1"
    assert result["mac_addresses"] == ["00:30:a7:00:00:01"]


def test_parse_eth_output_empty():
    result = relay_command_parse.parse_eth_output("Invalid Command")
    assert result["mac_addresses"] == []
    assert result["port_information"] == {}
    assert result["statistics"] == {}


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # MAC command, documented for the SEL-351S and SEL-751A
        ("=>MAC\nPort 1 MAC Address:   00-30-A7-00-00-00\n=>", {"Port 1": "00:30:A7:00:00:00"}),
        # Format PEAT has seen on a SEL-351S
        (
            "(IP) MAC Address: 00-30-A7-00-00-01\r\n(GOOSE) MAC Address: 00-30-a7-00-00-02\r\n",
            {"IP": "00:30:A7:00:00:01", "GOOSE": "00:30:A7:00:00:02"},
        ),
        (
            "Port 5 (IP) MAC\n00-30-A7-00-00-01\nPort 5 (GOOSE) MAC\n00-30-A7-00-00-02\n",
            {"IP": "00:30:A7:00:00:01", "GOOSE": "00:30:A7:00:00:02"},
        ),
        # ETH output
        (
            "MAC 1: 00-30-A7-00-00-01\nMAC 2: 00-30-A7-00-00-02",
            {"MAC 1": "00:30:A7:00:00:01", "MAC 2": "00:30:A7:00:00:02"},
        ),
        (
            "MAC: 00-30-A7-00-00-01\nMAC: 00-30-A7-00-00-03",
            {"MAC": "00:30:A7:00:00:01", "MAC (2)": "00:30:A7:00:00:03"},
        ),
        ("Invalid Command", {}),
    ],
)
def test_parse_mac_output(text, expected):
    assert relay_command_parse.parse_mac_output(text) == expected


def test_parse_show_groups_continuation_and_prompts():
    text = (
        "=>>SHO L 1\n"
        "SELogic group 1\n"
        "\n"
        "TR      := 51P1T OR 50P1T OR 51G1T OR\n"
        "           50G1T\n"
        "ULTR    := NOT (50L OR 51S1)\n"
        "\n"
        "Output Settings\n"
        "\n"
        "OUT101  := TRIP  OUT102 := CLOSE\n"
        "=>>"
    )
    assert relay_command_parse.parse_show_groups(text) == {
        "SELogic group 1": {
            "TR": "51P1T OR 50P1T OR 51G1T OR 50G1T",
            "ULTR": "NOT (50L OR 51S1)",
        },
        "Output Settings": {"OUT101": "TRIP", "OUT102": "CLOSE"},
    }


def test_parse_show_groups_no_heading_and_values_with_spaces():
    text = "FTPCBAN = FTP SERVER:  FTPIDLE = 5\nRID     =FEEDER 1\n"
    assert relay_command_parse.parse_show_groups(text) == {
        "": {"FTPCBAN": "FTP SERVER:", "FTPIDLE": "5", "RID": "FEEDER 1"}
    }


def test_get_port_settings_400_series_rejects_shop1():
    # "static_command.html?cmd=shop1" is a page with "Invalid Command" on a
    # 400-series relay. The other URL format is tried, instead of parsing
    # all ports as if it was a SEL-351.
    pages = {
        **PAGES_451,
        "static_command.html?cmd=shop1": INVALID_COMMAND,
        "static_command.html?cmd=sho&param=P%202": INVALID_COMMAND,
        "static_command.html?cmd=sho&param=P%203": INVALID_COMMAND,
    }
    http, dev = _relay(pages)
    http._url_parts = ("static_command.html?cmd=", "")

    assert http.get_port_settings(dev) is True

    assert http._port_args_len == 2
    assert dev.extra["interfaces"]["Port 1"]["Protocol Selection"]["PROTO"] == "SEL"
    assert _iface(dev, "Port 5").ip == "192.0.2.30"


def test_get_port_settings_invalid_port_1_falls_back():
    # A relay without port 1: the first URL format is still used
    pages = {**PAGES_351S, "shop1.html": INVALID_COMMAND}
    http, dev = _relay(pages)

    assert http.get_port_settings(dev) is True

    assert http._port_args_len == 1
    assert dev.extra["interfaces"]["Port 1"] == {}
    assert dev.extra["interfaces"]["Port 5"]["IPADDR"] == "192.0.2.31"


def test_get_port_settings_value_with_spaces():
    page = _page("Port 5\n\nEPORT = Y  IPADDR = 192.0.2.31\nFTPCBAN = FTP SERVER:\n")
    http, dev = _relay({"shop1.html": page, "shop5.html": page})

    assert http.get_port_settings(dev) is True
    # The old parser split values on spaces ("FTP")
    assert dev.extra["interfaces"]["Port 1"]["FTPCBAN"] == "FTP SERVER:"


def test_get_front_panel_settings_without_heading():
    # The old code raised KeyError if there wasn't a "Front Panel Settings" heading
    page = _page("Front Panel\n\nFP_TO := 15\n")
    http, dev = _relay({"static_command.html?cmd=sho&param=F": page})

    assert http.get_front_panel_settings(dev) is True
    assert dev.extra["front_panel_data"] == {"front_panel": {"FP_TO": "15"}}


def test_parse_meter_values_skips_non_numbers():
    text = "AMV001 = $$$$$$  AMV002 =  1.5  XAMV003 = 2\nAMV004:= 3\n"
    assert relay_command_parse.parse_meter_values(text, "AMV") == {"AMV002": 1.5, "AMV004": 3.0}


def test_get_meter_automation_overflow_value():
    # float("$$$$$$") raised ValueError before, which failed the whole page
    page = _page("AMV001 = $$$$$$  AMV002 = 2.000\n")
    http, dev = _relay({"static_command.html?cmd=met&param=AMV": page})

    assert http.get_meter_automation(dev) is True
    assert dev.extra["meter_automation"] == {"AMV002": 2.0}


def test_get_meter_energy_351s():
    # Only the last reset was parsed before (the values only worked on the 451)
    http, dev = _relay(PAGES_351S)
    dev.description.model = "351S"

    assert http.get_meter_energy(dev) is True

    energy = dev.extra["meter_energy"]
    assert energy["last_energy_reset"] == "2021-03-01T00:00:00"
    assert energy["MWhA"] == {"in": 0.1, "out": 12.5}
    assert energy["MWh3P"] == {"in": 0.6, "out": 38.25}
    assert energy["MVARh3P"] == {"in": 0.06, "out": 3.6}
    assert len(energy) == 9


def test_parse_meter_energy_date_format_and_layouts():
    text = "          A B C 3P\nIN  1 2 3 6\nOUT 0 0 0 0\nLAST ENERGY RESET: 01/03/2021 00:00:00\n"
    result = relay_command_parse.parse_meter_energy(text, date_format="DMY")
    assert result["last_energy_reset"] == "2021-03-01T00:00:00"
    assert result["3P"] == {"in": 6.0, "out": 0.0}

    assert relay_command_parse.parse_meter_energy("No data\n") == {}


def test_get_logic_data_451_style():
    page = _page("Protection 1\n\nTR      := 51P1T OR\n           50G1T\nSV01    := IN101\n")
    pages = {f"static_command.html?cmd=sho&param=L%20{i}": page for i in range(1, 7)}
    pages["static_command.html?cmd=sho&param=L%203"] = INVALID_COMMAND
    http, dev = _relay(pages)
    http._url_parts = ("static_command.html?cmd=", "")

    assert http.get_logic_data(dev) is True

    assert http._logic_page_style == "451"
    logic = dev.extra["control_equations"]
    assert logic["group_1"] == {"TR": "51P1T OR 50G1T", "SV01": "IN101"}
    assert logic["group_3"] == {}
    assert len([f for f in dev.files if f.name.startswith("raw_logic_group_")]) == 6


def test_get_logic_data_no_settings_keeps_page():
    http, dev = _relay({"shol.html": _page("Logic not available\n")})
    for i in range(2, 7):
        http._session.pages[f"shol{i}.html"] = _page("Logic not available\n")

    assert http.get_logic_data(dev) is True
    assert dev.extra["control_equations"]["raw_logic_group_1"] == "Logic not available"


@pytest.mark.parametrize(
    ("response_url", "content", "expected"),
    [
        ("http://192.0.2.1:80/protected/N1/login.html", b"", "http://192.0.2.1:80/protected/N1/"),
        # The query string isn't part of the session URL
        ("http://192.0.2.1:80/N1/login_query.html?x=1", b"", "http://192.0.2.1:80/protected/N1/"),
        (
            "http://192.0.2.1/login",
            b'<a href="/N9/ver.html">v</a>',
            "http://192.0.2.1/protected/N9/",
        ),
        # A session link must be a path on the relay
        ("http://192.0.2.1/login", b'<a href="http://198.51.100.1/N9/ver.html">v</a>', ""),
        ("http://192.0.2.1/login", b'<a href="/help.html">Help</a>', ""),
        ("http://192.0.2.1/login", b"<html></html>", ""),
        # A redirect to another host
        ("http://198.51.100.1/protected/N1/login.html", b"", ""),
        ("http://192.0.2.1/login.html?error=invalid", b"", ""),
    ],
)
def test_derive_relay_session_url(response_url, content, expected):
    assert (
        sel_http.derive_relay_session_url(
            response_url, content, base_url="http://192.0.2.1:80/login"
        )
        == expected
    )


def test_login_351_without_session_link(relay_login):
    # TypeError (soup.find("a") was None) before. The relay didn't reject the
    # credentials, so this still raises, and callers don't try other credentials.
    base, mock = relay_login
    mock.post(f"{base}/login", content=b"<html>No links</html>")

    http = SELHTTP(RELAY_IP, 80)
    with pytest.raises(PeatError, match="session URL"):
        http.login()
    assert http.relay_logged_in is False
    assert http.successful_creds is None


def test_login_redirect_to_other_host(relay_login):
    base, mock = relay_login
    other = "http://198.51.100.1/protected/N1a2b3c4d/login.html"
    mock.post(f"{base}/login", status_code=302, headers={"Location": other})
    mock.get(other, content=b"<html></html>")

    http = SELHTTP(RELAY_IP, 80)
    with pytest.raises(PeatError, match="session URL"):
        http.login()
    assert http.relay_logged_in is False


@pytest.mark.parametrize(
    "body",
    [b"<html>No links</html>", b'<html><a href="/help.html">Help</a></html>'],
    ids=["no-link", "not-a-session-link"],
)
def test_verify_http_stops_when_session_is_unknown(relay_login, body):
    # Credentials that weren't rejected must not be followed by more login
    # attempts (failed logins on the relay, which may cause an alarm or lockout)
    base, mock = relay_login
    mock.post(f"{base}/login", content=body)
    dev = datastore.get(RELAY_IP, "ip")
    dev._runtime_options["web"] = {"user": "", "pass": ""}
    assert len(dev.options["sel"]["creds"]) > 1

    with pytest.raises(PeatError):
        SELRelay._verify_http(dev)

    posts = [r for r in mock.request_history if r.method == "POST"]
    assert len(posts) == 1


def test_verify_http_tries_next_credentials_when_rejected(relay_login):
    base, mock = relay_login
    invalid = f"{base}/login.html?error=invalid"
    mock.post(f"{base}/login", status_code=302, headers={"Location": invalid})
    mock.get(invalid, content=b"<html></html>")
    dev = datastore.get(RELAY_IP, "ip")
    dev._runtime_options["web"] = {"user": "", "pass": ""}

    assert SELRelay._verify_http(dev) is False

    posts = [r for r in mock.request_history if r.method == "POST"]
    assert len(posts) == len(web_candidates(SELRelay._level_passwords(dev)))


def test_login_token_without_value(requests_mock):
    requests_mock.get(f"http://{RELAY_IP}:80/", content=b"<html><input name='rando'/></html>")
    requests_mock.post(
        f"http://{RELAY_IP}:80/login",
        status_code=302,
        headers={"Location": "/protected/N1/login.html"},
    )
    requests_mock.get(f"http://{RELAY_IP}:80/protected/N1/login.html", content=b"<html></html>")

    http = SELHTTP(RELAY_IP, 80)
    assert http.login() is True
    # "None" was sent before
    assert requests_mock.request_history[1].text == "usrid=ACC&pswd=OTTER&rando="
