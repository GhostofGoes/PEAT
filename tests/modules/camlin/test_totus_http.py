"""
Processing of Camlin Totus API data (synthetic JSON in the shape the module reads).
"""

import json

import pytest

from peat import DeviceData, config
from peat.modules.camlin import totus_http
from peat.modules.camlin.totus_http import TotusHTTP


@pytest.fixture
def dev(mocker, tmp_path):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})
    return DeviceData(id="test_totus", ip="192.0.2.30")


def test_redact_secrets():
    data = {
        "ssid": "totus",
        "password": "hunter2",
        "passwordRequired": True,
        "nested": [{"psk": "abc", "name": "x"}, {"client_secret": ""}],
    }
    redacted = totus_http.redact_secrets(data)
    assert redacted == {
        "ssid": "totus",
        "password": "<redacted>",
        "passwordRequired": True,
        "nested": [{"psk": "<redacted>", "name": "x"}, {"client_secret": ""}],
    }
    # The input isn't modified
    assert data["password"] == "hunter2"


def test_redact_secrets_key_names_and_values():
    data = {
        "passwd": "a",
        "pwd": "b",
        "key": "c",
        "preSharedKey": "d",
        "wpaKey": "e",
        "community": "f",
        "tls_auth": "g",
        "token": "h",
        "pre-shared-key": "i",
        "publicKey": "ssh-ed25519 AAAA user@host",
        "keyboard": "us",
        "inline": "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
        "ta": "-----BEGIN OpenVPN Static key V1-----\nabcd\n-----END OpenVPN Static key V1-----",
        "cert": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
    }
    redacted = totus_http.redact_secrets(data)
    for key in ("passwd", "pwd", "key", "preSharedKey", "wpaKey", "community", "tls_auth"):
        assert redacted[key] == "<redacted>", key
    for key in ("token", "pre-shared-key", "inline", "ta"):
        assert redacted[key] == "<redacted>", key
    assert redacted["publicKey"] == data["publicKey"]
    assert redacted["keyboard"] == "us"
    assert redacted["cert"] == data["cert"]


def test_redact_secrets_non_string_values_and_suffixed_names():
    data = {
        "community": ["public", "s3cret2"],
        "password": 123456,
        "passwords": ["a1"],
        "password1": "p1",
        "password_2": "p2",
        "communityString": "s3cret",
        "communities": {"read": "r0"},
        "snmp": {"community_string": "y"},
        "key1": "wep-key",
        "passwordRequired": True,
        "psk": False,
        "password_set": "yes",
        "token": None,
        "secret": [],
    }
    redacted = totus_http.redact_secrets(data)
    for key in (
        "community",
        "password",
        "passwords",
        "password1",
        "password_2",
        "communityString",
        "communities",
        "key1",
    ):
        assert redacted[key] == "<redacted>", key
    assert redacted["snmp"] == {"community_string": "<redacted>"}
    for secret in ("s3cret", "123456", "a1", "p1", "p2", "r0", "wep-key"):
        assert secret not in str(redacted), secret
    # Flags and empty values are not secrets
    assert redacted["passwordRequired"] is True
    assert redacted["psk"] is False
    assert redacted["password_set"] == "yes"
    assert redacted["token"] is None
    assert redacted["secret"] == []


class _FakeResponse:
    def __init__(self, data):
        self.text = json.dumps(data)

    def json(self):
        return json.loads(self.text)


def test_mapped_api_data_not_copied_to_extra(dev, mocker):
    """Data moved to first-class fields is not duplicated in dev.extra."""
    api = {
        "ntp_config": ["192.0.2.1", "pool.ntp.org"],
        "ntp_status": {"status": {"peers": [{"remote": "*192.0.2.1"}], "leap": "00"}},
        "openvpn": {
            "profiles": [
                {
                    "name": "site-vpn",
                    "key": "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----",
                    "remotes": [{"host": "vpn.example.com", "port": 1194}],
                }
            ]
        },
        "timedate": {"timezone": "UTC", "time": "2024-05-01T10:00:00Z", "ntp": True},
    }
    http = TotusHTTP("192.0.2.30", 80, 1.0)
    http.methods = {
        "ntp_config": {"page": "ntp_config", "process_method": http.process_ntp_config},
        "ntp_status": {"page": "ntp_status", "process_method": http.process_ntp_status},
        "openvpn": {"page": "openvpn", "process_method": http.process_openvpn},
        "timedate": {"page": "timedate", "process_method": http.process_timedate},
    }
    mocker.patch.object(http, "get", side_effect=lambda page: _FakeResponse(api[page]))
    assert http.get_and_process_all(dev)

    assert {s.address for s in dev.clock.sources} == {"192.0.2.1", "pool.ntp.org"}
    assert "ntp_config" not in dev.extra
    assert dev.extra["ntp_status"] == {"status": {"leap": "00"}}
    assert dev.extra["openvpn"] == {"profiles": [{"name": "site-vpn", "key": "<redacted>"}]}
    assert dev.extra["timedate"] == {"ntp": True}
    assert dev.clock.time is not None
    assert [r.remote.hostname for r in dev.relationships if r.type == "tunnel"] == [
        "vpn.example.com"
    ]
    side_file = dev.get_sub_dir("http_json_data") / "openvpn.json"
    assert "PRIVATE KEY" not in side_file.read_text()


def test_wifi_password_not_stored(dev, mocker):
    """Bug fix: the Wi-Fi password was copied to dev.extra and the JSON file."""
    wifi = {"status": "on", "ssid": "totus", "password": "hunter2", "channel": 6}

    class FakeResponse:
        text = json.dumps(wifi)

        def json(self):
            return json.loads(self.text)

    http = TotusHTTP("192.0.2.30", 80, 1.0)
    http.methods = {
        "wifihotspot": {
            "page": "system/api/1/wifihotspot",
            "process_method": http.process_wifihotspot,
        }
    }
    mocker.patch.object(http, "get", return_value=FakeResponse())

    assert http.get_and_process_all(dev)

    assert "wifihotspot" not in dev.extra
    iface = dev.retrieve("interface", {"name": "wifihotspot"})
    assert iface.enabled is True
    assert iface.extra == {"status": "on", "ssid": "totus", "channel": 6}

    side_file = dev.get_sub_dir("http_json_data") / "wifihotspot.json"
    assert "hunter2" not in side_file.read_text()
    assert json.loads(side_file.read_text())["password"] == "<redacted>"
    assert "hunter2" not in json.dumps(dev.export(), default=str)


def test_login_never_logs_password(mocker, caplog):
    """Bug fix: the web password was logged at TRACE level with -V (config.DEBUG)."""
    caplog.set_level(0)
    mocker.patch.dict(config["CONFIG"], {"DEBUG": 4})
    http = TotusHTTP("192.0.2.30", 80, 1.0)
    mocker.patch.object(http, "get", return_value=None)
    assert not http.login("totusadmin", "TotusCanaryPw5")
    assert "totusadmin" in caplog.text
    assert "TotusCanaryPw5" not in caplog.text


def test_ntp_sources(dev):
    TotusHTTP.process_ntp_config(dev, ["192.0.2.1", "pool.ntp.org"])
    TotusHTTP.process_ntp_status(
        dev,
        {
            "status": {
                "peers": [
                    {
                        "remote": "*192.0.2.1",
                        "refid": "GPS",
                        "st": 1,
                        "reach": "377",
                        "offset": "-0.125",
                        "jitter": "0.030",
                    },
                    {"remote": "+pool.ntp.org", "st": "2", "reach": "377", "offset": "1.5"},
                    {"remote": "198.51.100.7", "st": 16, "reach": "0"},
                    {"remote": ""},
                ]
            }
        },
    )

    sources = {s.address: s for s in dev.clock.sources}
    assert set(sources) == {"192.0.2.1", "pool.ntp.org", "198.51.100.7"}
    assert all(s.protocol == "ntp" for s in sources.values())

    selected = sources["192.0.2.1"]
    assert selected.enabled is True  # configured
    assert selected.selected is True
    assert selected.state == "active"
    assert selected.stratum == 1
    assert selected.offset == pytest.approx(-0.000125)  # ntpq milliseconds -> seconds
    assert selected.extra == {"refid": "GPS", "reach": "377", "jitter": "0.030"}

    assert sources["pool.ntp.org"].state == "candidate"
    assert sources["pool.ntp.org"].selected is False
    assert sources["198.51.100.7"].state == "unreachable"
    assert sources["198.51.100.7"].enabled is None  # not configured

    assert {"192.0.2.1", "198.51.100.7"} <= dev.related.ip
    assert "pool.ntp.org" in dev.related.hosts

    # Time sources become "syncs_time_from" relationships
    exported = dev.export()
    assert exported["clock"]["source"] == "ntp"
    time_rels = [r for r in exported["relationships"] if r["type"] == "syncs_time_from"]
    assert len(time_rels) == 3


def test_ntp_peer_to_time_source():
    assert totus_http.ntp_peer_to_time_source({}) is None
    assert totus_http.ntp_peer_to_time_source("bad") is None
    src = totus_http.ntp_peer_to_time_source({"remote": "time.example.com", "offset": "abc"})
    assert src.address == "time.example.com"
    assert src.state == ""
    assert src.selected is None
    assert src.offset is None
    assert src.extra == {"offset_raw": "abc"}


def test_ntp_peer_hostname_starting_with_tally_letter():
    src = totus_http.ntp_peer_to_time_source({"remote": " ozlabs.ntp.org"})
    assert (src.address, src.state, src.selected) == ("ozlabs.ntp.org", "", None)
    src = totus_http.ntp_peer_to_time_source({"remote": "xntp.example.com"})
    assert (src.address, src.state) == ("xntp.example.com", "")
    src = totus_http.ntp_peer_to_time_source({"remote": "x192.0.2.9"})
    assert (src.address, src.state) == ("192.0.2.9", "falseticker")
    src = totus_http.ntp_peer_to_time_source({"remote": "o192.0.2.8"})
    assert (src.address, src.selected) == ("192.0.2.8", True)
    src = totus_http.ntp_peer_to_time_source({"remote": "*ntp.example.com"})
    assert (src.address, src.selected) == ("ntp.example.com", True)


def test_ntp_peer_refclock_tally():
    """ntpq (without -n) shows reference clocks by name: "o" + "PPS(0)" is a selected PPS peer."""
    pps = "PPS(0)"
    src = totus_http.ntp_peer_to_time_source({"remote": f"o{pps}"})
    assert (src.address, src.state, src.selected) == ("PPS(0)", "active", True)
    src = totus_http.ntp_peer_to_time_source({"remote": "xGPS_NMEA(0)"})
    assert (src.address, src.state, src.selected) == ("GPS_NMEA(0)", "falseticker", False)
    src = totus_http.ntp_peer_to_time_source({"remote": "*SHM(0)"})
    assert (src.address, src.selected) == ("SHM(0)", True)
    src = totus_http.ntp_peer_to_time_source({"remote": " LOCAL(0)"})
    assert (src.address, src.state, src.selected) == ("LOCAL(0)", "", None)


def test_ntp_refclocks_are_not_network_servers(dev):
    """
    ntpd reference clocks (local drivers, by name or as 127.127.x.y with
    ``ntpq -n``) are not NTP servers: no relationship, no related host or IP.
    """
    pps = "PPS(0)"
    TotusHTTP.process_ntp_config(dev, ["127.127.22.0", "192.0.2.1"])
    TotusHTTP.process_ntp_status(
        dev,
        {
            "status": {
                "peers": [
                    {"remote": f"o{pps}", "refid": ".PPS.", "st": "0"},
                    {"remote": " LOCAL(0)", "refid": ".LOCL.", "st": "10"},
                    {"remote": "+192.0.2.1", "st": "2"},
                    {"remote": "o127.127.22.0", "refid": ".PPS.", "st": "0"},
                ]
            }
        },
    )

    sources = {s.address: s for s in dev.clock.sources}
    assert {a: s.protocol for a, s in sources.items()} == {
        "PPS(0)": "gps",
        "LOCAL(0)": "internal",
        "192.0.2.1": "ntp",
        "127.127.22.0": "gps",
    }
    pps = sources["PPS(0)"]
    assert (pps.selected, pps.state) == (True, "active")
    assert pps.extra == {"refclock": "PPS(0)", "refid": ".PPS."}
    assert sources["LOCAL(0)"].extra["refclock"] == "LOCAL(0)"
    assert "refclock" not in sources["192.0.2.1"].extra
    # Configured and reported (ntpq -n) refclock: one source
    assert (sources["127.127.22.0"].enabled, sources["127.127.22.0"].selected) == (True, True)

    exported = dev.export()
    time_rels = [r for r in exported["relationships"] if r["type"] == "syncs_time_from"]
    assert [(r["protocol"], r["remote"]) for r in time_rels] == [
        ("ntp", {"ip": "192.0.2.1", "role": "time_server"})
    ]
    assert not {"PPS(0)", "LOCAL(0)"} & dev.related.hosts
    assert "127.127.22.0" not in dev.related.ip
    assert "192.0.2.1" in dev.related.ip


@pytest.mark.parametrize(
    ("address", "protocol"),
    [
        ("PPS(0)", "gps"),
        ("GPS_NMEA(1)", "gps"),
        ("SHM(0)", "gps"),
        ("LOCAL(0)", "internal"),
        ("IRIG(0)", "irig_b"),
        ("DCF77(0)", "dcf77"),
        ("GENERIC(0)", "internal"),
        ("127.127.20.0", "gps"),
        ("127.127.1.0", "internal"),
        ("127.127.99.0", "internal"),
        ("127.0.0.1", ""),
        ("192.0.2.1", ""),
        ("pool.ntp.org", ""),
        ("::1", ""),
    ],
)
def test_ntp_refclock_protocol(address, protocol):
    assert totus_http.ntp_refclock_protocol(address) == protocol


def test_timedate_clock(dev):
    dev.uptime = 3600
    TotusHTTP.process_timedate(dev, {"timezone": "UTC", "time": "2024-05-01T10:00:00Z"})
    assert dev.geo.timezone == "UTC"
    assert dev.clock.time is not None
    assert dev.clock.observed is not None
    assert dev.clock.observed.tzinfo is not None
    assert dev.start_time is not None


def test_openvpn_relationships(dev):
    TotusHTTP.process_openvpn(
        dev,
        {
            "profiles": [
                {
                    "name": "site-vpn",
                    "address": "10.8.0.6",
                    "remotes": [
                        {"host": "vpn.example.com", "port": 1194, "proto": "udp"},
                        {"host": "203.0.113.10"},
                        {"host": ""},
                    ],
                }
            ]
        },
    )
    rels = {r.remote.hostname or r.remote.ip: r for r in dev.relationships}
    assert set(rels) == {"vpn.example.com", "203.0.113.10"}
    for rel in rels.values():
        assert rel.type == "tunnel"
        assert rel.protocol == "openvpn"
        assert rel.direction == "egress"
        assert rel.evidence == {"config"}
        assert rel.extra == {"profile": "site-vpn"}
    assert rels["vpn.example.com"].remote.port == 1194
    assert rels["vpn.example.com"].transport == "udp"
    assert rels["203.0.113.10"].remote.port is None
    assert {"10.8.0.6", "203.0.113.10"} <= dev.related.ip
    assert "vpn.example.com" in dev.related.hosts


@pytest.mark.parametrize(
    ("proto", "transport", "extra_proto"),
    [
        ("udp", "udp", None),
        ("TCP", "tcp", None),
        ("udp4", "udp", "udp4"),
        ("udp6", "udp", "udp6"),
        ("tcp-client", "tcp", "tcp-client"),
        ("tcp6-client", "tcp", "tcp6-client"),
        ("sctp", "", "sctp"),
    ],
)
def test_openvpn_remote_proto(proto, transport, extra_proto):
    rel = totus_http.openvpn_remote_relationship(
        {"name": "p"}, {"host": "192.0.2.1", "proto": proto}
    )
    assert rel.transport == transport
    assert rel.extra.get("proto") == extra_proto
    assert rel.extra["profile"] == "p"


def test_dnp3_channels(dev):
    TotusHTTP.process_dnp3_channels(
        dev,
        [
            {
                "id": 1,
                "name": "SCADA",
                "channel": "TCP",
                "localAddress": 10,
                "remoteAddress": 1,
                "bufferSize": 2048,
                "config": {"port": 20000},
            }
        ],
    )
    svc = dev.service[0]
    assert svc.protocol == "dnp3"
    assert svc.port == 20000
    assert svc.protocol_id == "10"
    assert "remote_address" not in svc.extra
    assert svc.extra["buffer_size"] == 2048

    assert len(dev.relationships) == 1
    rel = dev.relationships[0]
    assert rel.protocol == "dnp3"
    assert rel.transport == "tcp"
    assert rel.direction == "ingress"  # the master connects to the outstation's port
    assert rel.local.role == "outstation"
    assert rel.local.port == 20000
    assert rel.local.protocol_address == "10"
    assert rel.remote.role == "master"
    assert rel.remote.protocol_address == "1"
    assert rel.evidence == {"config"}
    assert rel.description == "SCADA"
