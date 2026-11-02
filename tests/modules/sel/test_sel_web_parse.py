"""
Tests for parsing the web pages of SEL RTACs and the SEL-3620 Ethernet
Security Gateway (:class:`~peat.modules.sel.sel_http.SELHTTP` and
:mod:`peat.modules.sel.sel_web_parse`).

The "characterization" tests run the ``SELHTTP`` methods against a fake web
server. They were written before the parsing was split out of ``SELHTTP``,
and lock in its behavior. The pages are synthetic, see data_files/web/README.md.
"""

import json
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from requests import Response

from peat import DeviceData, config, datastore
from peat.modules.sel import sel_web_parse
from peat.modules.sel.sel_3620 import SEL3620
from peat.modules.sel.sel_http import SELHTTP, login_with_web_credentials
from peat.modules.sel.sel_web_parse import GATEWAY_PAGES
from peat.protocols import HTTP

WEB_DIR = Path(__file__).resolve().parent / "data_files" / "web"
RTAC_IP = "192.0.2.40"
GATEWAY_IP = "192.0.2.22"

#: The gateway_* methods of SELHTTP. SEL3620._pull() calls every method
#: of SELHTTP with a name that starts with "gateway_".
GATEWAY_METHODS = {
    "gateway_accounts",
    "gateway_ldap",
    "gateway_radius",
    "gateway_local_groups",
    "gateway_network_settings",
    "gateway_static_routes",
    "gateway_firewall",
    "gateway_nat",
    "gateway_hosts",
    "gateway_snmp",
    "gateway_port_settings",
    "gateway_port_profiles",
    "gateway_port_mappings",
    "gateway_ipsec",
    "gateway_macsec",
    "gateway_allowed_clients",
    "gateway_sshkey",
    "gateway_password_management",
    "gateway_system_logs",
    "gateway_diagnostics",
    "gateway_proxy_reports",
    "gateway_cert_export",
}

#: Gateway pages that aren't parsed yet: (method, page, key in dev.extra, key in result)
GATEWAY_STUB_PAGES = [
    ("gateway_ldap", "LDAP.sel", "ldap", "ldap_data"),
    ("gateway_radius", "RADIUS.sel", "radius_settings", "radius_settings"),
    ("gateway_local_groups", "LocalGroups.sel", "local_groups", "local_groups"),
    (
        "gateway_network_settings",
        "NetworkSettings.sel",
        "gateway_network_settings",
        "gateway_network_settings",
    ),
    ("gateway_static_routes", "StaticRoutes.sel", "static_routes", "static_routes"),
    ("gateway_firewall", "Firewall.sel", "firewall_settings", "firewall_settings"),
    ("gateway_nat", "NAT.sel", "nat_settings", "nat_settings"),
    ("gateway_hosts", "Hosts.sel", "gateway_hosts", "gateway_hosts"),
    ("gateway_snmp", "SNMP.sel", "snmp_settings", "snmp_settings"),
    ("gateway_port_settings", "SerialPortSettings.sel", "port_settings", "port_settings"),
    ("gateway_port_profiles", "SerialPortProfiles.sel", "port_profiles", "port_profiles"),
    ("gateway_port_mappings", "PortMappings.sel", "port_mappings", "port_mappings"),
    ("gateway_ipsec", "IPsec.sel", "ipsec", "ipsec"),
    ("gateway_macsec", "MACsec.sel", "macsec", "macsec"),
    ("gateway_allowed_clients", "AllowedClients.sel", "allowed_clients", "allowed_clients"),
    ("gateway_sshkey", "SSH_Host_Key.sel", "ssh_host_key", "ssh_host_key"),
    (
        "gateway_password_management",
        "PasswordManagement.sel",
        "password_management",
        "password_management",
    ),
    ("gateway_diagnostics", "Diagnostics.sel", "gateway_diagnostics", "gateway_diagnostics"),
    ("gateway_proxy_reports", "ProxyReports.sel", "proxy_reports", "proxy_reports"),
]


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
    return tmp_path


class FakeWeb:
    """
    A RTAC's or gateway's web server. Pages are keyed by their path, without
    the leading "/" or the query string, e.g. ``device_info.sel``.
    Other pages are 404.
    """

    def __init__(self, pages: dict[str, bytes | str]) -> None:
        self.pages = {
            name: (WEB_DIR / data).read_bytes() if isinstance(data, str) else data
            for name, data in pages.items()
        }
        self.requests: list[tuple[str, str, dict]] = []

    def _respond(self, method: str, url: str, **kwargs) -> Response:
        name = urlparse(url).path.lstrip("/")
        self.requests.append((method, url, kwargs))

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

    def get(self, url: str, **kwargs) -> Response:
        return self._respond("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> Response:
        return self._respond("POST", url, **kwargs)

    def close(self) -> None:
        pass


def _rtac(pages: dict[str, bytes | str]) -> tuple[SELHTTP, DeviceData]:
    http = SELHTTP(RTAC_IP, 443, protocol="https")
    http._session = FakeWeb(pages)
    http.session_id = "SESSION123"
    http.rtac_l1_user = "admin"
    return http, datastore.get(RTAC_IP, "ip")


def _gateway(pages: dict[str, bytes | str]) -> tuple[SELHTTP, DeviceData]:
    http = SELHTTP(GATEWAY_IP, 443, protocol="https")
    http._session = FakeWeb(pages)
    http._rando = "GWTOKEN"
    return http, datastore.get(GATEWAY_IP, "ip")


def _requested(http: SELHTTP) -> list[str]:
    return [urlparse(url).path.lstrip("/") for _, url, _ in http._session.requests]


# ---------------------------------------------------------------------------
# Characterization: RTAC dashboard (view_dashboard)
# ---------------------------------------------------------------------------

RTAC_DASHBOARD = {
    "device_info.sel": "rtac_device_info.html",
    "diagnostics.sel": "rtac_diagnostics.html",
    "post_summary.sel": "rtac_post_summary.html",
}

EXPECTED_DEVICE_INFO = {
    "Host Name": "RTAC-TEST-1",
    "Device Name": "Test RTAC",
    "Device Location": "Substation A",
    "Device Description": "Automation controller for PEAT tests",
    "Firmware Version": "SEL-3530-4-R151-V2-Z008004-D20230830",
    "Firmware Hash": "SHA256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "Firmware Checksum": "B0AB",
    "BIOS Version": "1.2.3.4",
    "Project ID": "0123456789ABCDEF0123456789ABCDEF",
    "Serial Number": "1234567890",
    "Part Number": "35304X1A2B3C4D",
    "Enable Login Banner": "true",
}


def test_view_dashboard():
    http, dev = _rtac(RTAC_DASHBOARD)

    result = http.view_dashboard(dev)

    assert result == {
        "web_device_info": EXPECTED_DEVICE_INFO,
        "web_diagnostics": {
            "main_task_usage": 0.35,
            "automation_task_usage": 0.12,
            "power_source_voltage": 24.1,
            "number_of_users_logged_in": 1,
            "CPU Temperature": "45 C",
        },
        "web_post_summary": {
            "DDR2 SDRAM OK": "Pass",
            "Flash File System": "Pass",
            "Real Time Clock": "Pass",
        },
    }
    assert dev.extra["web_device_info"] == EXPECTED_DEVICE_INFO
    assert dev.extra["web_diagnostics"] == result["web_diagnostics"]
    assert dev.extra["web_post_summary"] == result["web_post_summary"]

    # Device info
    assert dev.id == "RTAC-TEST-1"
    assert dev.hostname == "RTAC-TEST-1"
    assert dev.name == "Test RTAC"
    assert dev.description.model == "3530"
    assert dev.description.product == "SEL-3530-4"
    assert dev.description.description == "Automation controller for PEAT tests"
    assert dev.firmware.revision == "R151"
    assert dev.firmware.version == "V2"
    assert dev.firmware.hash.sha256 == "0123456789ABCDEF" * 4
    assert dev.firmware.checksum == "B0AB"
    assert dev.boot_firmware.version == "1.2.3.4"
    assert dev.logic.id == "0123456789ABCDEF0123456789ABCDEF"
    assert dev.logic.hash.md5 == "0123456789ABCDEF0123456789ABCDEF"
    assert "0123456789ABCDEF0123456789ABCDEF" in dev.related.hash
    assert dev.serial_number == "1234567890"
    assert dev.part_number == "35304X1A2B3C4D"
    assert dev.geo.name == "Substation A"

    # Diagnostics. The page shows KB, and the data model is in bytes.
    # (Before the parsing was split out, the number of KB was stored as bytes.)
    assert dev.hardware.memory_usage == 524288 * 1024
    assert dev.hardware.memory_available == 1048576 * 1024
    assert dev.hardware.storage_usage == 2048 * 1024
    assert dev.hardware.storage_available == 4096 * 1024
    assert dev.logic.name == "Substation_A_v3"
    assert dev.logic.last_updated == datetime(2023, 5, 1, 12, 34, 56)

    # Post summary
    assert dev.hardware.memory_type == "ddr2_sdram"

    assert _requested(http) == ["device_info.sel", "diagnostics.sel", "post_summary.sel"]
    for _, url, kwargs in http._session.requests:
        assert kwargs["params"] == {"session_id": "SESSION123", "session_username": "admin"}
        assert urlparse(url).query.startswith("asfdasfowefsj=")


def test_view_dashboard_diagnostics_fallback():
    pages = {**RTAC_DASHBOARD, "diag_report.sel": "rtac_diagnostics.html"}
    del pages["diagnostics.sel"]
    http, dev = _rtac(pages)

    result = http.view_dashboard(dev)

    assert result["web_diagnostics"]["main_task_usage"] == 0.35
    assert _requested(http) == [
        "device_info.sel",
        "diagnostics.sel",
        "diag_report.sel",
        "post_summary.sel",
    ]


def test_view_dashboard_firmware_checksum_hash():
    page = (
        b"<table><tr><td>Firmware Checksum:</td>"
        b"<td>0123456789abcdef0123456789abcdef</td></tr></table>"
    )
    http, dev = _rtac({**RTAC_DASHBOARD, "device_info.sel": page})

    http.view_dashboard(dev)

    assert dev.firmware.checksum == "0123456789abcdef0123456789abcdef"
    assert dev.firmware.hash.md5 == "0123456789ABCDEF0123456789ABCDEF"
    assert "0123456789ABCDEF0123456789ABCDEF" in dev.related.hash


# ---------------------------------------------------------------------------
# Characterization: RTAC files, accounts, and roles
# ---------------------------------------------------------------------------


def test_view_filesondevice():
    http, dev = _rtac({"file_repository.sel": "rtac_file_repository.html"})

    result = http.view_filesondevice(dev)

    expected = {
        "project_backup.zip": {
            "name": "project_backup.zip",
            "size": 102400,
            "timestamp": datetime(2023, 5, 1, 12, 0, 0),
        },
        "notes.txt": {
            "name": "notes.txt",
            "size": 512,
            "timestamp": datetime(2023, 4, 2, 8, 30, 0),
        },
    }
    assert result == {"web_files": expected}
    assert dev.extra["web_files"] == expected
    assert {"project_backup.zip", "notes.txt"} <= dev.related.files


EXPECTED_ACCOUNTS = {
    "admin": {
        "status": "Enabled",
        "created": "2023-01-01 00:00:00",
        "last_login": "2023-05-01 08:00:00",
        "password_changed": "2023-01-01 00:00:00",
    },
    "operator": {"status": "Disabled"},
    "engineer": {"status": "Enabled"},
}


def _check_accounts(result: dict, dev: DeviceData) -> None:
    assert result == {"web_accounts": EXPECTED_ACCOUNTS}
    assert dev.extra["web_accounts"] == EXPECTED_ACCOUNTS
    assert {"admin", "operator", "engineer", "olduser"} <= dev.related.user
    users = {u.name: u.extra for u in dev.users}
    assert users == EXPECTED_ACCOUNTS


def test_view_accounts():
    http, dev = _rtac({"user_table.sel": "rtac_user_table.html"})
    _check_accounts(http.view_accounts(dev), dev)


def test_gateway_accounts():
    http, dev = _gateway({"Users.sel": "rtac_user_table.html"})
    _check_accounts(http.gateway_accounts(dev), dev)
    _, url, kwargs = http._session.requests[0]
    assert url == f"https://{GATEWAY_IP}:443/Users.sel"
    assert kwargs["data"] == "GWTOKEN"


def test_view_user_roles():
    page = b"<table><tr><td> Administrator </td><td>Full access</td></tr></table>"
    http, dev = _rtac({"list_user_roles.sel": page})

    assert http.view_user_roles(dev) == {"web_user_roles": {"Administrator": "Full access"}}
    assert "Administrator" in dev.related.roles


# ---------------------------------------------------------------------------
# Characterization: RTAC Sequence of Events (view_syslog)
# ---------------------------------------------------------------------------


def _soe_events(dev: DeviceData) -> dict[str, object]:
    return {e.message: e for e in dev.event if e.dataset == "web_syslog"}


def test_view_syslog(env):
    http, dev = _rtac({"soe.csv": "rtac_soe.csv"})

    result = http.view_syslog(dev)

    rows = result["web_syslog_events"]
    assert len(rows) == 8
    assert rows[0] == {
        "creation_timestamp": "2023-05-01 12:00:05",
        "t_value": "2023-05-01 12:00:00",
        "t_dst_enabled": "f",
        "category": "System",
        "priority": "1",
        "tag_name": "",
        "message": "Device power up",
        "host_name": "RTAC-TEST-1",
        "device_name": "",
        "device_guid": "",
        "comment": "",
        "ack_operator_username": "",
    }
    raw_json = env / "devices" / RTAC_IP / "raw-web-syslog-events.json"
    assert json.loads(raw_json.read_text()) == rows

    events = _soe_events(dev)
    assert len(events) == 8

    power_up = events["Device power up"]
    assert power_up.action == "device-power-up"
    assert power_up.type == {"info", "start"}
    assert power_up.category == {"host"}
    assert power_up.kind == {"event"}
    assert power_up.outcome == ""
    assert power_up.created == datetime(2023, 5, 1, 12, 0, 0)
    assert power_up.extra == {
        "creation_timestamp": datetime(2023, 5, 1, 12, 0, 5),
        "category": "System",
        "priority": "1",
        "host_name": "RTAC-TEST-1",
    }
    assert power_up.sequence == 1
    assert power_up.module == "SELRTAC"
    assert power_up.original.startswith('"2023-05-01 12:00:05","2023-05-01 12:00:00"')

    logon = events["admin logged on device via Web"]
    assert logon.action == "user-logged-on-via-web"
    assert logon.outcome == "success"
    assert logon.category == {"host", "authentication", "network", "session", "database"}
    assert logon.type == {"info", "access", "allowed", "connection", "user"}
    assert logon.extra["logon_user"] == "admin"
    assert logon.extra["logon_service"] == "web"
    assert logon.extra["tag_name"] == "RTAC.SystemTags.User_Logon"

    failed = events["Unknown login attempt from 192.0.2.50 failed"]
    assert failed.action == "login-attempt"
    assert failed.outcome == "failure"
    assert failed.category == {"host", "authentication", "network", "session"}
    assert failed.type == {"info", "access", "connection", "denied", "user"}
    assert failed.extra["user"] == "Unknown"

    password = events["admin changed password for operator"]
    assert password.action == "admin-changed-password-for-operator"
    assert password.category == {"host", "configuration"}
    assert password.type == {"info", "change"}

    cleared = events["SOE archive cleared"]
    assert cleared.category == {"host", "database"}
    assert cleared.type == {"info", "change", "deletion"}
    assert cleared.extra["ack_operator_username"] == "admin"

    logoff = events["operator logged off device via ODBC"]
    assert logoff.action == "user-logged-off-via-odbc"
    assert logoff.extra["device_name"] == "Feeder1_SEL"
    assert logoff.extra["comment"] == "Shift change"
    assert logoff.extra["ack_operator_username"] is True

    reset = events["Factory reset requested"]
    assert reset.created is None
    assert reset.category == {"host", "configuration"}
    assert reset.type == {"info", "change"}

    started = events["Firmware: SEL-3530-4-R151-V2-Z008004-D20230830, Project: Substation_A_v3"]
    assert started.action == "rtac-started"
    assert started.kind == {"event", "state"}

    assert {"admin", "operator", "Unknown"} <= dev.related.user
    assert "192.0.2.50" in dev.related.ip
    assert {"RTAC-TEST-1", "Feeder1_SEL"} <= dev.related.hosts


# ---------------------------------------------------------------------------
# Characterization: SEL-3620 pages
# ---------------------------------------------------------------------------


def test_get_index():
    http, dev = _gateway({"index.sel": "sel3620_index.html"})
    http.cookies = {"Cookie": "SELSESSID=GWTOKEN"}  # Set by login_3620()

    result = http.get_index(dev)

    info = result["web_device_info"]
    assert info["Host Name"] == "GW-TEST-1"
    assert info["Serial Number"] == "4567890123"
    assert info["Firmware Version"] == "SEL-3620-R203-V1-Z003003-D20201015"
    assert info["Version Information"].startswith("Version Information\nFID String")


def test_gateway_system_logs(env):
    http, dev = _gateway({"SysLogReport.sel": "sel3620_syslog_report.html"})

    result = http.gateway_system_logs(dev)

    expected = [
        {
            "recvTime": "2023-05-01 12:00:01",
            "tag": "kernel",
            "severity": "warning",
            "facility": "kern",
            "msg": "eth1 link down",
            "id": "000101",
        },
        {
            "recvTime": "2023-05-01 12:00:02",
            "tag": "sshd",
            "severity": "info",
            "facility": "auth",
            "msg": " Accepted password for admin from 192.0.2.60 ",
            "id": "000102",
        },
    ]
    assert result == {"gateway_system_logs": expected}
    raw_json = env / "devices" / GATEWAY_IP / "gateway-system-logs.json"
    assert json.loads(raw_json.read_text()) == expected

    events = sorted(
        (e for e in dev.event if e.dataset == "gateway_system_logs"), key=lambda e: e.sequence
    )
    assert [e.sequence for e in events] == [101, 102]
    assert events[0].id == "000101"
    assert events[0].message == "eth1 link down"
    assert events[0].severity == "warning"
    assert events[0].created == datetime(2023, 5, 1, 12, 0, 1)
    assert events[0].extra == {"tag": "kernel", "facility": "kern"}
    assert events[1].message == "Accepted password for admin from 192.0.2.60"
    assert events[1].original == " Accepted password for admin from 192.0.2.60 "


@pytest.mark.parametrize(("method", "page", "extra_key", "result_key"), GATEWAY_STUB_PAGES)
def test_gateway_stub_pages(method, page, extra_key, result_key):
    http, dev = _gateway({page: b"<html><body><table></table></body></html>"})

    assert getattr(http, method)(dev) == {result_key: {}}
    assert dev.extra[extra_key] == {}
    _, url, kwargs = http._session.requests[0]
    assert url == f"https://{GATEWAY_IP}:443/{page}"
    assert kwargs["data"] == "GWTOKEN"


@pytest.mark.parametrize(("method", "page", "extra_key", "result_key"), GATEWAY_STUB_PAGES)
def test_gateway_stub_pages_failed(method, page, extra_key, result_key):  # noqa: ARG001
    http, dev = _gateway({})

    assert getattr(http, method)(dev) == {}
    assert extra_key not in dev.extra


def test_sel3620_reflection_finds_gateway_methods():
    # SEL3620._pull() calls all methods of SELHTTP that start with "gateway_"
    found = {
        k for k, f in SELHTTP.__dict__.items() if callable(f) and f.__name__.startswith("gateway_")
    }
    assert found == GATEWAY_METHODS


def test_sel3620_pull_calls_gateway_methods(mocker):
    http, dev = _gateway({})
    called = []
    for name in GATEWAY_METHODS:
        mocker.patch.object(http, name, side_effect=lambda _dev, n=name: called.append(n) or {})
    dev._cache["web_session"] = http

    assert SEL3620._pull(dev) is True
    assert set(called) == GATEWAY_METHODS


# ---------------------------------------------------------------------------
# Characterization: logins
# ---------------------------------------------------------------------------

TOKEN_PAGE = b"""<html><body><form>
<input type="text" name="username"/>
<input type="hidden" name="token" value="TOKEN42"/>
</form></body></html>"""


def test_login_rtac(requests_mock):
    base = f"https://{RTAC_IP}:443"
    requests_mock.get(f"{base}/", content=TOKEN_PAGE)
    requests_mock.post(f"{base}/auth.sel", text="SESSION123")

    http = SELHTTP(RTAC_IP, 443)
    assert http.login_rtac("admin", "secret") is True

    assert http.session_id == "SESSION123"
    assert http.rtac_l1_user == "admin"
    assert http.rtac_logged_in is True
    assert http.protocol == "https"
    query = parse_qs(urlparse(requests_mock.request_history[1].url).query)
    assert query["session_username"] == ["admin"]
    assert query["password"] == ["secret"]
    assert query["temp_auth_token"] == ["TOKEN42"]


def test_login_rtac_failure(requests_mock):
    base = f"https://{RTAC_IP}:443"
    requests_mock.get(f"{base}/", content=TOKEN_PAGE)
    requests_mock.post(f"{base}/auth.sel", text="Failure to login invalid user/pass")

    http = SELHTTP(RTAC_IP, 443)
    assert http.login_rtac("admin", "wrong") is False
    assert http.rtac_logged_in is False


def test_login_rtac_no_token(requests_mock):
    requests_mock.get(f"https://{RTAC_IP}:443/", content=b"<html><input name='x'/></html>")
    http = SELHTTP(RTAC_IP, 443)
    assert http.login_rtac("admin", "secret") is False
    assert len(requests_mock.request_history) == 1


def test_login_3620(requests_mock):
    base = f"https://{GATEWAY_IP}:443"
    requests_mock.get(f"{base}/", content=TOKEN_PAGE)
    requests_mock.post(f"{base}/Login.sel", text="<html>Welcome</html>")

    http = SELHTTP(GATEWAY_IP, 443)
    assert http.login_3620("admin", "secret") is True

    assert http._rando == "TOKEN42"
    assert http.cookies == {"Cookie": "SELSESSID=TOKEN42"}
    assert http.gateway_logged_in is True
    assert http.gateway_l1_user == "admin"
    assert parse_qs(requests_mock.request_history[1].text) == {
        "Username": ["admin"],
        "Password": ["secret"],
        "submit": ["Submit"],
        "SELSESSID": ["TOKEN42"],
    }


def test_login_3620_error(requests_mock):
    base = f"https://{GATEWAY_IP}:443"
    requests_mock.get(f"{base}/", content=TOKEN_PAGE)
    requests_mock.post(f"{base}/Login.sel", text="<html>ERROR MESSAGES: bad login</html>")

    http = SELHTTP(GATEWAY_IP, 443)
    assert http.login_3620("admin", "wrong") is False


# ---------------------------------------------------------------------------
# Characterization: SEL-3620 verification login loop
# ---------------------------------------------------------------------------

GATEWAY_DASHBOARD = {"web_device_info": {"Firmware Version": "SEL-3620-R203-V1-Z003003-D20201015"}}


@pytest.fixture
def gateway_dev(mocker):
    dev = datastore.get(GATEWAY_IP, "ip")
    mocker.patch.object(SELHTTP, "get_index", return_value=GATEWAY_DASHBOARD)
    mocker.patch("peat.modules.sel.sel_3620.exit_handler")
    return dev


def _options(dev: DeviceData, **web) -> None:
    dev._runtime_options["web"] = {"user": "", "pass": "", **web}


def test_sel3620_verify_tries_candidates(mocker, gateway_dev):
    _options(gateway_dev, users=["admin", "Admin"], passwords=["one", "two"])
    attempts = []

    def fake_login(self, user, passwd):  # noqa: ARG001
        attempts.append((user, passwd))
        return (user, passwd) == ("Admin", "one")

    mocker.patch.object(SELHTTP, "login_3620", fake_login)

    assert SEL3620._verify_http(gateway_dev) is True

    assert attempts == [("admin", "one"), ("admin", "two"), ("Admin", "one")]
    assert gateway_dev._cache["verified_web_user"] == "Admin"
    assert gateway_dev._cache["verified_web_pass"] == "one"
    assert "Admin" in gateway_dev.related.user
    assert isinstance(gateway_dev._cache["web_session"], SELHTTP)


def test_sel3620_verify_user_supplied_creds(mocker, gateway_dev):
    _options(gateway_dev, user="me", users=["admin"], **{"pass": "mine"}, passwords=["x"])
    login = mocker.patch.object(SELHTTP, "login_3620", return_value=True)

    assert SEL3620._verify_http(gateway_dev) is True
    login.assert_called_once_with("me", "mine")


def test_sel3620_verify_cached_creds(mocker, gateway_dev):
    _options(gateway_dev, users=["admin"], passwords=["x"])
    gateway_dev._cache["verified_web_user"] = "cached"
    gateway_dev._cache["verified_web_pass"] = "pw"
    login = mocker.patch.object(SELHTTP, "login_3620", return_value=False)

    assert SEL3620._verify_http(gateway_dev) is False
    login.assert_called_once_with("cached", "pw")


def test_sel3620_verify_all_fail(mocker, gateway_dev):
    _options(gateway_dev, users=["a", "b"], passwords=["1", "2"])
    login = mocker.patch.object(SELHTTP, "login_3620", return_value=False)

    assert SEL3620._verify_http(gateway_dev) is False
    assert login.call_count == 4
    assert "verified_web_user" not in gateway_dev._cache


def test_sel3620_verify_not_a_3620(mocker, gateway_dev):
    _options(gateway_dev, users=["admin"], passwords=["x"])
    mocker.patch.object(SELHTTP, "login_3620", return_value=True)
    mocker.patch.object(
        SELHTTP, "get_index", return_value={"web_device_info": {"Firmware Version": "SEL-2730M"}}
    )

    assert SEL3620._verify_http(gateway_dev) is False
    assert "web_session" not in gateway_dev._cache


# ---------------------------------------------------------------------------
# Fixed bugs and new behavior (after the parsing was split out of SELHTTP)
# ---------------------------------------------------------------------------


def test_view_dashboard_no_diagnostics():
    # Raised AttributeError if both diagnostics pages failed, which also
    # failed the RTAC verification (it calls view_dashboard())
    pages = dict(RTAC_DASHBOARD)
    del pages["diagnostics.sel"]
    http, dev = _rtac(pages)

    result = http.view_dashboard(dev)

    assert result["web_device_info"] == EXPECTED_DEVICE_INFO
    assert result["web_diagnostics"] == {}
    assert dev.description.model == "3530"
    assert "web_diagnostics" not in dev.extra


def test_view_dashboard_no_pages():
    http, dev = _rtac({})
    assert http.view_dashboard(dev) == {
        "web_device_info": {},
        "web_diagnostics": {},
        "web_post_summary": {},
    }


def test_parse_rtac_diagnostics_conversions():
    page = (
        b"<table>"
        b"<tr><td>Main Task Usage:</td><td>35%</td></tr>"
        b"<tr><td>Power Source Voltage:</td><td>24.1 V</td></tr>"
        b"<tr><td>Memory Usage (RAM):</td><td>2 MB</td></tr>"
        b"<tr><td>Storage Usage:</td><td>unknown</td></tr>"
        b"<tr><td>Number of Users Logged In:</td><td>2 users</td></tr>"
        b"</table>"
    )
    # A value that can't be converted is kept, the others still work
    # (all of them were lost before if one failed)
    assert sel_web_parse.parse_rtac_diagnostics(page) == {
        "main_task_usage": 0.35,
        "power_source_voltage": 24.1,
        "memory_usage_ram": 2 * 1024 * 1024,
        "Storage Usage": "unknown",
        "number_of_users_logged_in": 2,
    }


def test_process_rtac_diagnostics_returns_remaining():
    dev = DeviceData()
    diag = {"memory_usage_ram": 1024, "Current Project": "P1", "Other": "x"}
    assert sel_web_parse.process_rtac_diagnostics(diag, dev) == {"Other": "x"}
    assert diag == {"memory_usage_ram": 1024, "Current Project": "P1", "Other": "x"}
    assert dev.hardware.memory_usage == 1024
    assert dev.logic.name == "P1"


def test_parse_rtac_files_bad_values():
    page = (
        b"<table><tr><td>a.txt</td><td>2023-01-01 00:00:00</td><td>big</td></tr>"
        b"<tr><td>b.txt</td><td>2023-01-02</td></tr></table>"
    )
    # int("big") failed the whole page before
    assert sel_web_parse.parse_rtac_files(page) == {
        "a.txt": {"name": "a.txt", "timestamp": datetime(2023, 1, 1)},
        "b.txt": {"name": "b.txt"},
    }


def test_view_filesondevice_no_page_and_download():
    http, dev = _rtac({})
    assert http.view_filesondevice(dev) == {"web_files": {}}
    assert http.download_http_files(dev) == {}

    # KeyError before, if view_filesondevice() didn't run
    dev2 = DeviceData()
    assert http.download_http_files(dev2) == {}


def test_parse_web_accounts():
    page = (
        b"<table><tr><td>u1</td><td>Disabled</td></tr>"
        b"<tr><td>u2</td><td>Enabled</td><td>2023-01-01 00:00:00\n2023-01-02 00:00:00\n"
        b"2023-01-03 00:00:00</td></tr><tr><td>u3</td><td></td></tr></table>"
    )
    accounts, usernames = sel_web_parse.parse_web_accounts(page)

    assert accounts == {
        # The status was the first letter ("D") before
        "u1": {"status": "Disabled"},
        # Dates on separate lines
        "u2": {
            "status": "Enabled",
            "created": "2023-01-01 00:00:00",
            "last_login": "2023-01-02 00:00:00",
            "password_changed": "2023-01-03 00:00:00",
        },
    }
    assert usernames == ["u1", "u2", "u3"]
    assert sel_web_parse.parse_web_accounts(None) == ({}, [])


def test_view_accounts_and_gateway_accounts_share_parser(mocker):
    spy = mocker.spy(sel_web_parse, "parse_web_accounts")
    mocker.patch("peat.modules.sel.sel_http.parse_web_accounts", spy)

    http, dev = _rtac({"user_table.sel": "rtac_user_table.html"})
    http.view_accounts(dev)
    gw, gw_dev = _gateway({"Users.sel": "rtac_user_table.html"})
    gw.gateway_accounts(gw_dev)

    assert spy.call_count == 2
    assert dev.extra["web_accounts"] == gw_dev.extra["web_accounts"]


SOE_TRICKY = (
    "\ufeff"  # Byte order mark (BOM)
    '"t_value","tag_name","message","host_name"\r\n'
    '"2023-05-01 12:00:00","","Tag ""BKR1"", value changed","RTAC-1"\r\n'
    '"2023-05-01 12:00:01","","Line one\nline two","RTAC-1"\r\n'
    '"short"\r\n'
    "\r\n"
    "2023-05-01 12:00:02,,admin logged on device via Web,RTAC-1\r\n"
)


def test_parse_soe_csv_quotes_commas_and_lines():
    records = sel_web_parse.parse_soe_csv(SOE_TRICKY)

    # The old parser split lines on '",', which broke on the first message
    assert [r.fields["message"] for r in records] == [
        'Tag "BKR1", value changed',
        "Line one\nline two",
        "admin logged on device via Web",
    ]
    assert records[0].fields == {
        "t_value": "2023-05-01 12:00:00",
        "tag_name": "",
        "message": 'Tag "BKR1", value changed',
        "host_name": "RTAC-1",
    }
    assert [r.line for r in records] == [1, 2, 6]
    assert records[0].original == '"2023-05-01 12:00:00","","Tag ""BKR1"", value changed","RTAC-1"'
    assert records[1].original == '"2023-05-01 12:00:01","","Line one\nline two","RTAC-1"'


def test_parse_soe_csv_no_message_column_and_empty():
    assert sel_web_parse.parse_soe_csv('"a","b"\n"1","2"\n') == []
    assert sel_web_parse.parse_soe_csv("") == []
    assert sel_web_parse.parse_soe_csv('"t_value","message"\r\n') == []


@pytest.mark.parametrize(
    ("message", "action", "event_type", "outcome", "extra"),
    [
        # "log_On" was compared with the lowercase message, so it never matched
        (
            "User log_on via SSH",
            "user-log_on-via-ssh",
            {"info", "access", "allowed", "connection", "user"},
            "success",
            {},
        ),
        (
            "Admin user_changed_settings: admin changed settings",
            "admin-user_changed_settings-admin-changed-settings",
            {"info", "change", "access", "user"},
            "",
            {"user": "Admin user_changed_settings: admin"},
        ),
        (
            "application_status: The rtacsnmpmgr application has been restarted",
            "application-restarted",
            {"info", "change"},
            "unknown",
            {},
        ),
        (
            "admin login attempt failed",
            "login-attempt",
            {"info", "access", "connection", "denied", "user"},
            "failure",
            {"user": "admin"},
        ),
        (
            "Unauthorized access from web",
            "unauthorized-access-from-web",
            {"info", "access", "connection", "denied", "user"},
            "failure",
            {},
        ),
    ],
)
def test_classify_soe_event(message, action, event_type, outcome, extra):
    result = sel_web_parse.classify_soe_event({"message": message, "t_value": "f"})
    assert result["action"] == action
    assert result["type"] == event_type
    assert result["outcome"] == outcome
    assert result["extra"] == extra
    assert result["created"] is None


def test_classify_soe_event_firmware_and_project_case():
    result = sel_web_parse.classify_soe_event(
        {"message": "Firmware: SEL-3530-R148-V1-Z005004-D20210908, Project: Sub_A v2"}
    )
    # The message was lowercased before, so the FID didn't parse as the
    # RTAC firmware (it ended up in boot_firmware), and the project was "sub_a v2"
    assert result["firmware"] == "SEL-3530-R148-V1-Z005004-D20210908"
    assert result["project_name"] == "Sub_A v2"
    assert result["action"] == "rtac-started"
    assert result["kind"] == {"event", "state"}


def test_view_syslog_firmware_and_project():
    http, dev = _rtac({"soe.csv": "rtac_soe.csv"})

    http.view_syslog(dev)

    assert dev.description.model == "3530"
    assert dev.firmware.revision == "R151"
    assert not dev.boot_firmware.id
    assert dev.logic.name == "Substation_A_v3"


SOE_UPGRADE = (
    '"t_value","message"\n'
    '"2023-06-01 08:00:00","Firmware: SEL-3530-R150-V1-Z001001-D20230101, Project: Sub_New"\n'
    '"2020-03-01 08:00:00","Firmware: SEL-3530-R140-V0-Z001001-D20200101, Project: Sub_Old"\n'
    '"","Firmware: SEL-3530-R130-V0-Z001001-D20190101, Project: Sub_Older"\n'
)


def test_process_soe_events_keeps_current_firmware():
    # The log is a history: older "Firmware:" messages (before an upgrade) replaced
    # the firmware and model that view_dashboard got from device_info.sel
    dev = DeviceData(ip=RTAC_IP)
    sel_web_parse.process_fid("SEL-3555-R151-V2-Z008004-D20230830", dev)
    dev.logic.name = "Sub_Current"

    sel_web_parse.process_soe_events(sel_web_parse.parse_soe_csv(SOE_UPGRADE), dev)

    assert dev.firmware.revision == "R151"
    assert dev.firmware.version == "V2"
    assert dev.firmware.release_date == datetime(2023, 8, 30)
    assert dev.description.model == "3555"
    assert dev.logic.name == "Sub_Current"
    assert not dev.boot_firmware.id
    # The firmware of each message is still in its event
    firmware = sorted(e.extra["firmware"] for e in dev.event)
    assert firmware == [
        "SEL-3530-R130-V0-Z001001-D20190101",
        "SEL-3530-R140-V0-Z001001-D20200101",
        "SEL-3530-R150-V1-Z001001-D20230101",
    ]


@pytest.mark.parametrize("reverse", [False, True], ids=["newest-first", "oldest-first"])
def test_process_soe_events_uses_newest_firmware(reverse):
    # Without firmware from the dashboard, the newest message is used, in any order
    header, *rows = SOE_UPGRADE.splitlines(keepends=True)
    text = header + "".join(reversed(rows) if reverse else rows)
    dev = DeviceData(ip=RTAC_IP)

    sel_web_parse.process_soe_events(sel_web_parse.parse_soe_csv(text), dev)

    assert dev.firmware.id == "SEL-3530-R150-V1-Z001001-D20230101"
    assert dev.firmware.revision == "R150"
    assert dev.logic.name == "Sub_New"


def test_view_syslog_after_dashboard_keeps_firmware():
    http, dev = _rtac({"soe.csv": SOE_UPGRADE.encode()})
    sel_web_parse.process_fid("SEL-3530-R152-V0-Z009001-D20240101", dev)

    http.view_syslog(dev)

    assert dev.firmware.revision == "R152"


def test_view_syslog_no_data():
    # Wrote response.text of a failed response before (fixed the same way
    # in the fork's security fixes)
    http, dev = _rtac({})
    assert http.view_syslog(dev) == {}
    assert not dev.files
    assert not dev.event


def test_view_syslog_tricky_csv():
    http, dev = _rtac({"soe.csv": SOE_TRICKY.encode()})

    result = http.view_syslog(dev)

    assert len(result["web_syslog_events"]) == 3
    events = _soe_events(dev)
    assert events["admin logged on device via Web"].sequence == 6
    assert events["admin logged on device via Web"].extra["logon_user"] == "admin"


@pytest.mark.parametrize("separator", ["\r", "\x0b", "\x0c", "\x1c", "\x85", "\u2028"])
def test_parse_soe_csv_original_with_other_line_separators(separator):
    # str.splitlines() also splits on these, which put the original text
    # of this row and of every row after it on the wrong lines
    text = (
        '"message","t_value"\r\n'
        f'"a{separator}b","2024-01-01"\r\n'
        '"c","2024-01-02"\r\n'
        '"d","2024-01-03"\r\n'
    )

    records = sel_web_parse.parse_soe_csv(text)

    assert [r.fields["message"] for r in records] == [f"a{separator}b", "c", "d"]
    assert [r.original for r in records] == [
        f'"a{separator}b","2024-01-01"',
        '"c","2024-01-02"',
        '"d","2024-01-03"',
    ]
    assert [r.line for r in records] == [1, 2, 3]


def test_parse_gateway_index_edge_cases():
    # IndexError before, when "FID String" was the last line
    page = b"<table><tr><td>Version Information\nFID String</td><td></td></tr></table>"
    info = sel_web_parse.parse_gateway_index(page)
    assert "Firmware Version" not in info
    assert info["Version Information"] == "Version Information\nFID String"
    assert sel_web_parse.parse_gateway_index(None) == {"Version Information": ""}


def test_get_index_request_unchanged():
    # Characterization: the cookie dict is sent as query parameters, as before.
    # It's unknown if the gateway needs them, so it isn't changed without a device.
    http, dev = _gateway({"index.sel": "sel3620_index.html"})
    http.cookies = {"Cookie": "SELSESSID=GWTOKEN"}

    http.get_index(dev)

    method, url, kwargs = http._session.requests[0]
    assert method == "GET"
    assert url == f"https://{GATEWAY_IP}:443/index.sel"
    assert kwargs.get("params") == {"Cookie": "SELSESSID=GWTOKEN"}


def test_get_index_before_login():
    # AttributeError before: the cookies weren't set until login_3620()
    http, dev = _gateway({"index.sel": "sel3620_index.html"})

    assert http.get_index(dev)["web_device_info"]["Firmware Version"]


def test_parse_gateway_syslog_edge_cases():
    # KeyError before, for a cell without a class or a row without an id
    page = (
        b"<table id='syslogReport'><tr><td>sort</td></tr>"
        b"<tr><td>no class</td><td class='msg'>m</td></tr></table>"
    )
    assert sel_web_parse.parse_gateway_syslog(page) == [{"msg": "m"}]
    # AttributeError before, if there wasn't a table
    assert sel_web_parse.parse_gateway_syslog(b"<html></html>") == []


def test_gateway_system_logs_no_table():
    http, dev = _gateway({"SysLogReport.sel": b"<html>Session expired</html>"})
    assert http.gateway_system_logs(dev) == {"gateway_system_logs": []}


def test_parse_x509_export_links():
    page = (WEB_DIR / "sel3620_x509.html").read_bytes()
    assert sel_web_parse.parse_x509_export_links(page) == [
        "/X509_export.sel?id=1",
        "https://192.0.2.22/X509_export.sel?id=2",
        "https://198.51.100.9/X509_export.sel?id=3",
    ]
    assert sel_web_parse.parse_x509_export_links(None) == []


CERT = Path(__file__).resolve().parents[2] / "protocols/data_files/sel_3530_certificate.cert"


def test_gateway_cert_export_absolute_links():
    cert = CERT.read_bytes()
    http, dev = _gateway(
        {
            "X509.sel": "sel3620_x509.html",
            "X509_export.sel": cert,
        }
    )

    result = http.gateway_cert_export(dev)

    exported = [url for _, url, _ in http._session.requests[1:]]
    # The absolute link was fetched (it was turned into the base URL before),
    # the link to another host was skipped, and the duplicate was fetched once
    assert exported == [
        f"https://{GATEWAY_IP}:443/X509_export.sel?id=1",
        f"https://{GATEWAY_IP}/X509_export.sel?id=2",
    ]
    assert len(result["x509_certificates"]) == 2
    assert dev.extra["x509_certificates"] == result["x509_certificates"]


def test_gateway_cert_export_no_page():
    # AttributeError (raise_for_status() on None) before
    http, dev = _gateway({})
    assert http.gateway_cert_export(dev) == {}
    assert "x509_certificates" not in dev.extra


def test_gateway_pages_table_matches_methods():
    # Each page in the table has a gateway_<name> method
    assert set(GATEWAY_PAGES) == {m.removeprefix("gateway_") for m, *_ in GATEWAY_STUB_PAGES}
    for name, page in GATEWAY_PAGES.items():
        _, page_name, extra_key, result_key = next(
            p for p in GATEWAY_STUB_PAGES if p[0] == f"gateway_{name}"
        )
        assert (page.page, page.extra_key, page.result_key) == (page_name, extra_key, result_key)

    # The helper isn't called by SEL3620._pull()
    assert not SELHTTP._pull_gateway_page.__name__.startswith("gateway_")


def test_gateway_diagnostics_empty_response():
    http, dev = _gateway({"Diagnostics.sel": b""})
    assert http.gateway_diagnostics(dev) == {}
    assert "gateway_diagnostics" not in dev.extra

    http, dev = _gateway({"LDAP.sel": b""})
    assert http.gateway_ldap(dev) == {"ldap_data": {}}


def test_dump_htmltable_none():
    results = {"a": 1}
    SELHTTP.dump_htmltable(None, results)
    assert results == {"a": 1}


def test_view_ldap():
    page = b"<table><tr><td>Server:</td><td>ldap.example.com</td></tr></table>"
    http, dev = _rtac({"ldap_server_table.sel": page})

    result = http.view_ldap(dev)

    assert result == {
        "web_ldap": {
            "servers": {"Server": "ldap.example.com"},
            "ldap_setting": {},
            "ldap_group_mapping": {},
            "ldap_attribute_mapping": {},
        }
    }
    assert dev.extra["web_ldap_accounts"] == {"Server": "ldap.example.com"}
    assert dev.extra["web_ldap_attmapping"] == {}


@pytest.mark.parametrize(
    ("page", "hidden_only", "expected"),
    [
        (b"<input type='hidden' name='t' value='T1'/>", True, "T1"),
        (b"<input type='hidden' name='t'/>", True, ""),
        (b"<input name='t' value='T2'/>", True, None),
        (b"<input name='t' value='T2'/>", False, "T2"),
        (b"<html></html>", False, None),
    ],
)
def test_extract_login_token(page, hidden_only, expected):
    assert sel_web_parse.extract_login_token(page, hidden_only=hidden_only) == expected


def test_login_with_web_credentials_no_passwords():
    dev = DeviceData()
    attempts = []

    def login(user, passwd):
        attempts.append((user, passwd))
        return True

    assert login_with_web_credentials(dev, login, {"user": "", "users": ["admin"]}) is False
    assert attempts == []

    assert login_with_web_credentials(dev, login, {"user": "a", "pass": "b"}) is True
    assert attempts == [("a", "b")]
    assert dev._cache["verified_web_user"] == "a"


def test_parse_soe_csv_too_large_field():
    # Larger than the default limit of the csv module (131072 characters)
    text = f'"t_value","message"\n"1","ok"\n"2","{"x" * 200000}"\n"3","after"\n'
    records = sel_web_parse.parse_soe_csv(text)
    # The rows before the bad one are kept
    assert [r.fields["message"] for r in records] == ["ok"]
