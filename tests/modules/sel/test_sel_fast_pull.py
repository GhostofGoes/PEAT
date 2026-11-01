"""
Tests for read-only SEL Fast collection (SELFast) over binary Telnet and serial
sessions, the binary-safe transports, and the "fast" pull method of SELRelay.

The relay is the scripted emulator in fast_relay_emulator.py (synthetic data, with
the formats of public SEL documentation, refer to its docstring). No hardware is
needed.
"""

import json
import socket
import threading
import time

import pytest
import serial

from peat import CommError, SELRelay, Service, config, datastore
from peat.modules.sel import sel_fast as fast
from peat.modules.sel.sel_ascii import SELAscii
from peat.modules.sel.sel_fast import FastRequestRefused, SELFast
from peat.modules.sel.sel_serial import SELSerial
from peat.modules.sel.sel_telnet import SELTelnet
from peat.protocols import forked_telnetlib as telnetlib
from peat.protocols.telnet import BinaryNegotiation, Telnet

from .fake_sel_relay import FakeSELRelay, FakeSerialPort
from .fast_relay_emulator import (
    FID_421,
    RELAY_NEGOTIATION,
    SNS_NAMES,
    FakeRegion,
    FastRelay,
    Item,
    TelnetRelayServer,
    fast_ser_body,
    fo_config,
    make_400_relay,
    relay_definition,
)


@pytest.fixture(autouse=True)
def env(tmp_path, mocker):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "TEMP_DIR": tmp_path / "temp",
        },
    )
    mocker.patch.object(datastore, "objects", [])
    mocker.patch.object(SELAscii, "FIRST_COMMAND_QUIET", 0.0)
    mocker.patch.object(SELAscii, "_failed_passwords", {})
    mocker.patch.object(SELAscii, "_good_passwords", {})
    mocker.patch.object(SELFast, "REQUEST_TIMEOUT", 0.3)
    mocker.patch.object(SELFast, "FAST_SER_IDLE", 0.4)


@pytest.fixture
def telnet_server():
    servers = []

    def _make(factory=None, **kwargs) -> TelnetRelayServer:
        server = TelnetRelayServer(factory or make_400_relay, **kwargs)
        servers.append(server)
        return server

    yield _make
    for server in servers:
        server.close()


def _negotiation(server: TelnetRelayServer, count: int = 4) -> list[bytes]:
    # The emulator records the client's replies in its own thread
    deadline = time.monotonic() + 2.0
    while len(server.servers[0].negotiation) < count and time.monotonic() < deadline:
        time.sleep(0.01)
    return server.servers[0].negotiation


def _telnet(server: TelnetRelayServer, **kwargs) -> SELTelnet:
    return SELTelnet("127.0.0.1", server.port, timeout=2.0, binary=True, **kwargs)


SER_MESSAGES = [
    fast_ser_body(2024, 2, 3_600_000, [(0xFE, 600, 1), (1, 1_000, 1)]),
    fast_ser_body(2024, 2, 3_700_000, [(0, 0, 1), (3, 250, 0)]),
]


# ---------------------------------------------------------------------------
# Telnet: default behavior, keep_nulls, and BINARY negotiation
# ---------------------------------------------------------------------------


def _telnetlib_pair(keep_nulls: bool):
    ours, theirs = socket.socketpair()
    tn = telnetlib.Telnet()
    tn.sock = ours
    tn.keep_nulls = keep_nulls
    return tn, theirs


def test_telnetlib_default_drops_nul_and_xon():
    # The default is unchanged for other modules: NUL and XON are removed
    tn, theirs = _telnetlib_pair(keep_nulls=False)
    theirs.sendall(b"a\x00b\x11c\xff\xffd\x13")
    assert tn.read_until(b"\x13", timeout=2) == b"abc\xffd\x13"
    tn.close()
    theirs.close()
    assert telnetlib.Telnet().keep_nulls is False


def test_telnetlib_keep_nulls():
    tn, theirs = _telnetlib_pair(keep_nulls=True)
    theirs.sendall(b"a\x00b\x11c\xff\xffd\x13")
    # IAC doubling is still undone
    assert tn.read_until(b"\x13", timeout=2) == b"a\x00b\x11c\xffd\x13"
    tn.close()
    theirs.close()


def test_telnet_is_not_binary_by_default():
    tn = Telnet("192.0.2.1")
    assert tn.binary is False
    assert tn.negotiation is None
    assert tn._comm.option_callback is None
    assert tn._comm.keep_nulls is False

    binary = Telnet("192.0.2.1", binary=True)
    assert binary._comm.keep_nulls is True
    assert binary._comm.option_callback is binary.negotiation


def test_binary_negotiation_replies():
    neg = BinaryNegotiation()
    iac, will, wont, do, dont = (
        telnetlib.IAC,
        telnetlib.WILL,
        telnetlib.WONT,
        telnetlib.DO,
        telnetlib.DONT,
    )
    binary, echo, sga, ttype = telnetlib.BINARY, telnetlib.ECHO, telnetlib.SGA, telnetlib.TTYPE
    # What relays offer, answered as SEL's masters do
    assert neg.reply(will, echo) == iac + do + echo
    assert neg.reply(will, sga) == iac + do + sga
    assert neg.reply(will, binary) == iac + do + binary
    assert neg.reply(do, binary) == iac + will + binary
    assert neg.binary
    # Already in that state: no reply (no loop)
    assert neg.reply(will, binary) == b""
    assert neg.reply(do, binary) == b""
    # Other options are refused
    assert neg.reply(will, ttype) == iac + dont + ttype
    assert neg.reply(do, ttype) == iac + wont + ttype
    assert neg.reply(do, echo) == iac + wont + echo
    # Disabling
    assert neg.reply(wont, binary) == iac + dont + binary
    assert neg.reply(dont, binary) == iac + wont + binary
    assert not neg.binary
    assert neg.reply(wont, binary) == b""
    assert neg.reply(dont, ttype) == b""
    assert neg.reply(telnetlib.SB, telnetlib.NOOPT) == b""


def test_binary_session_negotiation(telnet_server):
    server = telnet_server()
    tn = _telnet(server)
    assert tn.sync_access_level() == "0"
    assert tn.binary_negotiated is True
    # DO ECHO, DO SGA, DO BINARY, WILL BINARY (what the relay offered, in order)
    assert _negotiation(server) == [
        b"\xff\xfd\x01",
        b"\xff\xfd\x03",
        b"\xff\xfd\x00",
        b"\xff\xfb\x00",
    ]
    tn.disconnect()


def test_binary_negotiation_after_reconnect(telnet_server):
    # The same Telnet object, connected twice: each connection negotiates BINARY
    server = telnet_server()
    tn = Telnet("127.0.0.1", server.port, timeout=2.0, binary=True)
    for number in range(2):
        tn.write_raw(b"\r\n")
        assert tn.expect([rb"=>?"]).matched
        deadline = time.monotonic() + 2.0
        while len(server.servers) <= number and time.monotonic() < deadline:
            time.sleep(0.01)
        negotiation = server.servers[number].negotiation
        while len(negotiation) < 4 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert negotiation == [b"\xff\xfd\x01", b"\xff\xfd\x03", b"\xff\xfd\x00", b"\xff\xfb\x00"]
        assert tn.negotiation.binary
        tn.disconnect()
    assert len(server.servers) == 2


def test_ascii_session_still_refuses_options(telnet_server):
    server = telnet_server(FakeSELRelay)
    tn = SELTelnet("127.0.0.1", server.port, timeout=2.0)
    assert tn.sync_access_level() == "0"
    assert tn.binary_negotiated is None
    # The default telnetlib answer: DONT for each WILL, WONT for DO
    assert _negotiation(server) == [
        b"\xff\xfe\x01",
        b"\xff\xfe\x03",
        b"\xff\xfe\x00",
        b"\xff\xfc\x00",
    ]
    tn.disconnect()


def test_binary_frames_with_iac_and_nul_bytes(telnet_server):
    # Region values with 0xFF (doubled on the wire) and 0x00, 0x11, 0x13 bytes
    region = FakeRegion(
        "LOCAL", 0, [Item("V", 0x31, 4, [-1, 0x11, 0x13, 0]), Item("S", 0x11, 4, "")]
    )
    server = telnet_server(lambda: make_400_relay(regions=[region], meter={}))
    tn = _telnet(server)
    results = SELFast(tn).collect()
    tn.disconnect()
    assert results.regions["LOCAL"] == {"V": [-1, 0x11, 0x13, 0], "S": ""}
    assert results.region_data["LOCAL"] == region.data


# ---------------------------------------------------------------------------
# Collection over Telnet
# ---------------------------------------------------------------------------


def test_collect_400_series_relay(telnet_server):
    server = telnet_server()
    tn = _telnet(server)
    fast_session = SELFast(tn)
    results = fast_session.collect()
    tn.disconnect()
    relay = server.relays[0]

    assert results.supported
    assert results.relay_definition.meter_messages == [(0xA5C1, 0xA5D1), (0xA5C2, 0xA5D2)]
    meter = results.meter[0]["data"]
    assert meter.analogs == {"IA": [1.5, 2.5], "VA": [66.5, 120.0], "FREQ": [0.0, 60.0]}
    assert results.meter[1]["data"].analogs == {"IA": 50.0, "IB": -50.0}
    assert results.device_time.year == 2024
    assert results.status_names[3] == "STSET"
    assert results.digital_names[:2] == ["EN", "TRIP"]
    assert results.fast_operate is None  # FASTOP=N: no answer
    assert results.message_config.accepts(0x30)
    assert [r.name for r in results.device_description.regions] == [
        "LOCAL",
        "METER",
        "HISTORY",
        "STATUS",
    ]
    # Data formats of every region, reads of the inventory regions only
    assert set(results.data_formats) == {"LOCAL", "METER", "HISTORY", "STATUS"}
    assert set(results.regions) == {"LOCAL", "HISTORY", "STATUS"}
    assert results.regions["LOCAL"]["SER_NUM"] == "9999000001"
    assert results.errors == []
    assert results.unsolicited_ignored == 0

    # Only read-only requests, and no Fast SER, bit labels, ping, or A5B9
    assert all(fast.check_request(r) for r in relay.binary_requests)
    functions = {r[9] for r in relay.binary_requests if r[:2] == b"\xa5\x46"}
    assert functions == {0x00, 0x30, 0x31, 0x10}
    assert b"\xa5\xb9" not in relay.binary_requests
    assert not relay.fast_ser_enabled
    # ASCII commands on the same session (and the prompt was seen first)
    assert relay.lines[:3] == [b"", b"BNA", b"DNA"]

    # Every frame is in the transcript, and binary frames aren't in the ASCII output
    assert fast_session.transcript[0]["direction"] == "tx"
    assert fast_session.transcript[0]["frame"] == "a5c0"
    assert b"\xa5" not in b"".join(tn.raw_output)
    assert any(w.startswith(b"<SEL Fast a5c0") for w in tn.all_writes)


def test_collect_multi_frame_region(telnet_server):
    # A region larger than one read response frame (117 words per frame)
    big = FakeRegion("STATUS", 0x6000, [Item("CH", 0x31, 300, list(range(300)))])
    server = telnet_server(lambda: make_400_relay(regions=[big], meter={}))
    tn = _telnet(server)
    results = SELFast(tn).collect()
    tn.disconnect()
    assert results.regions["STATUS"]["CH"] == list(range(300))
    reads = [r for r in server.relays[0].binary_requests if r[:2] == b"\xa5\x46" and r[9] == 0x10]
    # Frames 0, 1, and 2 were requested (sequence bytes C0, C1, C2)
    assert [r[10] for r in reads] == [0xC0, 0xC1, 0xC2]


def test_collect_bit_labels(telnet_server):
    region = FakeRegion(
        "TARGET",
        0x3000,
        [Item("_YEAR", 0x32, 1, 2024), Item("TARGET", 0x21, 2, [0x80, 0x01])],
        labels={0x3001: ["TLED_1", "", "", "", "", "", "", "EN"], 0x3002: ["A"] * 8},
    )
    region.name = "STATUS_T"  # an inventory region name
    server = telnet_server(lambda: make_400_relay(regions=[region], meter={}))
    tn = _telnet(server)
    results = SELFast(tn, bit_labels=True).collect()
    tn.disconnect()
    assert results.bit_labels["STATUS_T"] == {
        "TARGET[0]": ["TLED_1", "", "", "", "", "", "", "EN"],
        "TARGET[1]": ["A"] * 8,
    }


def test_collect_relay_without_fast_message(telnet_server):
    def factory():
        return FastRelay(
            definition=relay_definition([(0xA5C1, 0xA5D1)], [(4, b"\xa5\xc1")], [0x0100, 0x0101]),
            fast_operate=fo_config(1, 8),
            fid="SEL-551-R999-V0-D20240101",
        )

    server = telnet_server(factory)
    tn = _telnet(server)
    results = SELFast(tn).collect()
    tn.disconnect()

    assert results.supported
    assert not results.relay_definition.fast_message
    assert results.meter == []  # the relay didn't answer A5C1
    assert "no response to A5C1" in results.errors
    assert results.fast_operate.breakers == 1  # FASTOP=Y
    assert results.message_config is None
    assert not [r for r in server.relays[0].binary_requests if r[:2] == b"\xa5\x46"]


def test_collect_no_answer_logs_in_and_retries(telnet_server):
    # The relay only answers binary requests at access level 1
    server = telnet_server(lambda: make_400_relay(binary_level="1"))
    tn = _telnet(server)
    results = SELFast(tn).collect(elevate=lambda: tn.elevate(1))
    tn.disconnect()
    relay = server.relays[0]
    assert results.supported
    assert relay.password_attempts == {"acc": ["OTTER"]}
    assert relay.binary_requests[:2] == [b"\xa5\xc0", b"\xa5\xc0"]


def test_collect_not_a_fast_device(telnet_server):
    server = telnet_server(lambda: FastRelay(definition=None))
    tn = _telnet(server)
    results = SELFast(tn).collect()
    tn.disconnect()
    assert not results.supported
    assert server.relays[0].binary_requests == [b"\xa5\xc0"]
    assert "no response to A5C0" in results.errors[0]


def test_collect_sends_nothing_binary_without_a_prompt():
    # A Telnet server that never answers: no binary request is sent
    received = []
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)

    def serve():
        conn, _ = listener.accept()
        conn.settimeout(5)
        try:
            while data := conn.recv(100):
                received.append(data)
        except OSError:
            pass
        conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    tn = SELTelnet("127.0.0.1", listener.getsockname()[1], timeout=0.5, binary=True)
    results = SELFast(tn).collect()
    tn.disconnect()
    thread.join(timeout=5)
    listener.close()
    assert not results.supported
    assert "no SEL prompt" in results.errors[0]
    assert b"\xa5" not in b"".join(received)


def test_collect_errors_and_wrong_response_numbers(telnet_server):
    # Data formats are refused (response code 3), and nothing else answers properly
    server = telnet_server(lambda: make_400_relay(nak={0x31: 3}))
    tn = _telnet(server)
    results = SELFast(tn).collect()
    tn.disconnect()
    assert results.device_description is not None
    assert results.data_formats == {}
    assert results.regions == {}
    assert any("response code 3 (invalid data address)" in e for e in results.errors)

    server = telnet_server(lambda: make_400_relay(wrong_resp_num=True))
    tn = _telnet(server)
    results = SELFast(tn).collect()
    tn.disconnect()
    assert results.message_config is None  # the response number didn't match
    assert "no Fast Message configuration block" in results.errors


def test_collect_ignores_unsolicited_fast_ser(telnet_server):
    # Fast SER that another master enabled on the port isn't acknowledged
    def factory():
        relay = make_400_relay(fast_ser=SER_MESSAGES)
        relay.fast_ser_enabled = True
        return relay

    server = telnet_server(factory)
    tn = _telnet(server)
    fast_session = SELFast(tn)
    assert fast_session.request_meter(fast.RELAY_DEFINITION)
    server.relays[0]._send_fast_ser()
    assert fast_session.request_meter(fast.FAST_METER_CONFIG)
    tn.disconnect()
    assert fast_session.results.unsolicited_ignored == 1
    assert server.relays[0].fast_ser_acks == []


# ---------------------------------------------------------------------------
# Fast SER (opt-in)
# ---------------------------------------------------------------------------


def test_fast_ser(telnet_server):
    server = telnet_server(lambda: make_400_relay(fast_ser=SER_MESSAGES))
    tn = _telnet(server)
    results = SELFast(tn).collect(fast_ser=True)
    relay = server.relays[0]

    assert results.fast_ser_enabled
    assert results.fast_ser_response == 0
    assert results.ser_names == SNS_NAMES
    assert len(results.fast_ser) == 2
    names = [r.name for m in results.fast_ser for r in m.records]
    assert names == ["Power-up", "OUT101", "IN101", "TRIP"]
    # Each message was acknowledged with its response number, then disabled
    assert relay.fast_ser_acks == [0, 1]
    assert not relay.fast_ser_enabled
    functions = [r[9] for r in relay.binary_requests if r[:2] == b"\xa5\x46"]
    assert functions[-4:] == [0x01, 0x98, 0x98, 0x02]
    assert b"SNS" in relay.lines
    # The permission to send Fast SER requests ends with the collection
    assert tn.fast_ser_allowed is False
    with pytest.raises(FastRequestRefused):
        tn.write_fast(fast.build_enable_fast_ser())
    tn.disconnect()


def test_fast_ser_settings_changed_is_not_acknowledged(telnet_server):
    server = telnet_server(
        lambda: make_400_relay(fast_ser=SER_MESSAGES, fast_ser_status=[0x01, 0x03])
    )
    tn = _telnet(server)
    results = SELFast(tn).collect(fast_ser=True)
    tn.disconnect()
    relay = server.relays[0]
    assert len(results.fast_ser) == 2
    assert results.fast_ser[1].settings_changed
    # Only the first message was acknowledged, and Fast SER was disabled
    assert relay.fast_ser_acks == [0]
    assert not relay.fast_ser_enabled
    assert any("settings changed" in e for e in results.errors)


def test_fast_ser_first_message_settings_changed(telnet_server):
    # The first message (sent right after the enable) says the settings changed
    server = telnet_server(lambda: make_400_relay(fast_ser=SER_MESSAGES, fast_ser_status=[0x03]))
    tn = _telnet(server)
    results = SELFast(tn).collect(fast_ser=True)
    tn.disconnect()
    assert server.relays[0].fast_ser_acks == []
    assert not server.relays[0].fast_ser_enabled
    assert results.fast_ser_response == 0
    assert len(results.fast_ser) == 1
    assert not any("no acknowledge" in e for e in results.errors)


def test_fast_ser_duplicate_messages_and_disabled_triggers(telnet_server):
    # The relay sends each message twice (an acknowledge that was late), and
    # answers the enable with response code 2 (the SER triggers are NA)
    server = telnet_server(
        lambda: make_400_relay(
            fast_ser=SER_MESSAGES[:1], resend_unacked=True, fast_ser_enable_code=2
        )
    )
    tn = _telnet(server)
    results = SELFast(tn).collect(fast_ser=True)
    tn.disconnect()
    assert len(results.fast_ser) == 1
    assert results.fast_ser_response == 2
    assert any("response code 2" in e for e in results.errors)
    # Disabled even though the enable "failed" (Fast SER is still enabled on the relay)
    assert not server.relays[0].fast_ser_enabled


def test_fast_ser_not_supported(telnet_server):
    def factory():
        relay = make_400_relay(fast_ser=SER_MESSAGES)
        relay.message_config = ([0x00, 0x30, 0x31, 0x10], [0xB0, 0xB1, 0x90])
        return relay

    server = telnet_server(factory)
    tn = _telnet(server)
    results = SELFast(tn).collect(fast_ser=True)
    tn.disconnect()
    assert not results.fast_ser_enabled
    assert "doesn't accept unsolicited Fast SER" in results.errors[-1]
    assert not [r for r in server.relays[0].binary_requests if r[:2] == b"\xa5\x46" and r[9] == 1]


def _fast_ser_requests(relay: FastRelay) -> list[bytes]:
    return [r for r in relay.binary_requests if r[:2] == b"\xa5\x46" and r[9] in (1, 2, 0x98)]


def test_fast_ser_not_enabled_when_stset_is_set(telnet_server):
    # Any acknowledge clears STSET (SEL-351A IM 20080213, the notes after Table J.5)
    server = telnet_server(lambda: make_400_relay(fast_ser=SER_MESSAGES, meter_status=0x10))
    tn = _telnet(server)
    results = SELFast(tn).collect(fast_ser=True)
    relay = server.relays[0]
    assert not results.fast_ser_enabled
    assert results.fast_ser == []
    assert any("STSET) is set" in e for e in results.errors)
    assert _fast_ser_requests(relay) == []
    assert not relay.fast_ser_enabled
    # A5D1 was read again just before (the status can change)
    assert relay.binary_requests.count(b"\xa5\xd1") == 2
    assert tn.fast_ser_allowed is False
    tn.disconnect()


def test_fast_ser_stset_from_the_status_flag(telnet_server):
    # Without BNA names, the relay definition status flag for A5C1 is the STSET bit
    server = telnet_server(
        lambda: make_400_relay(fast_ser=SER_MESSAGES, meter_status=0x10, bna=None)
    )
    tn = _telnet(server)
    results = SELFast(tn).collect(fast_ser=True)
    tn.disconnect()
    assert results.status_names == []
    assert any("STSET) is set" in e for e in results.errors)
    assert _fast_ser_requests(server.relays[0]) == []


def test_fast_ser_stset_set_after_the_first_read(telnet_server):
    server = telnet_server(lambda: make_400_relay(fast_ser=SER_MESSAGES))
    tn = _telnet(server)
    fast_session = SELFast(tn)
    fast_session.collect()
    relay = server.relays[0]
    # Another master's settings change, after PEAT read A5D1
    relay.meter[fast.FAST_METER_DATA] = make_400_relay(meter_status=0x10).meter[
        fast.FAST_METER_DATA
    ]
    assert fast_session.collect_fast_ser() == []
    tn.disconnect()
    assert any("STSET) is set" in e for e in fast_session.results.errors)
    assert _fast_ser_requests(relay) == []


def test_fast_ser_stset_unknown(telnet_server):
    # A5D1 doesn't answer, so the state of STSET isn't known
    def factory():
        relay = make_400_relay(fast_ser=SER_MESSAGES)
        del relay.meter[fast.FAST_METER_DATA]
        return relay

    server = telnet_server(factory)
    tn = _telnet(server)
    results = SELFast(tn).collect(fast_ser=True)
    tn.disconnect()
    assert any("STSET) isn't known" in e for e in results.errors)
    assert _fast_ser_requests(server.relays[0]) == []


@pytest.mark.parametrize("bna", [["*"] * 8, None])
def test_fast_ser_without_stset_status_flag(telnet_server, bna):
    # No status flag for A5C1. If BNA names no STSET bit, the relay has none
    # (nothing to clear), but if BNA doesn't answer, it isn't known.
    def factory():
        relay = make_400_relay(fast_ser=SER_MESSAGES[:1], meter_status=0x10, bna=bna)
        relay.definition = relay_definition(
            [(fast.FAST_METER_CONFIG, fast.FAST_METER_DATA)], [], [0x0300]
        )
        return relay

    server = telnet_server(factory)
    tn = _telnet(server)
    results = SELFast(tn).collect(fast_ser=True)
    tn.disconnect()
    if bna:
        assert results.status_names == ["*"] * 8
        assert results.fast_ser_enabled
        assert len(results.fast_ser) == 1
        assert server.relays[0].fast_ser_acks == [0]
    else:
        assert not results.fast_ser_enabled
        assert any("STSET) isn't known" in e for e in results.errors)
        assert _fast_ser_requests(server.relays[0]) == []


# ---------------------------------------------------------------------------
# Safety: the write guard
# ---------------------------------------------------------------------------


def test_control_frames_are_refused_on_every_write(telnet_server):
    server = telnet_server()
    tn = _telnet(server)
    assert tn.sync_access_level()
    for frame in (bytes.fromhex("A5E006430DDB"), b"\xa5\xb9", bytes.fromhex("A5ED06000101")):
        with pytest.raises(FastRequestRefused):
            tn.write_fast(frame)
        with pytest.raises(FastRequestRefused):
            tn.write(frame)
        with pytest.raises(FastRequestRefused):
            tn._send(frame, terminator=False)
    tn.disconnect()
    assert server.relays[0].binary_requests == []


def test_ascii_session_cannot_send_frames(telnet_server):
    server = telnet_server()
    tn = SELTelnet("127.0.0.1", server.port, timeout=2.0)
    with pytest.raises(CommError):
        tn.write_fast(b"\xa5\xc0")
    with pytest.raises(CommError):
        tn.read_fast_frame(0.1)
    with pytest.raises(FastRequestRefused):
        tn.write(b"\xa5\xc0")  # the line terminator makes it invalid
    tn.disconnect()


def test_write_fast_only_sends_requests(telnet_server):
    server = telnet_server()
    tn = _telnet(server)
    with pytest.raises(CommError):
        tn.write_fast(b"ID\r\n")
    tn.disconnect()


def test_binary_session_cannot_use_legacy_timing():
    with pytest.raises(ValueError):
        SELTelnet("192.0.2.1", binary=True, legacy_timing=True)


# ---------------------------------------------------------------------------
# Serial
# ---------------------------------------------------------------------------


def test_collect_over_serial():
    # XON and XOFF bytes in a binary frame are kept, but not in the ASCII data
    region = FakeRegion("LOCAL", 0, [Item("V", 0x32, 2, [0x1113, 0x0011])])
    relay = make_400_relay(regions=[region])
    port = FakeSerialPort(relay, chunk_size=7, chunk_delay=0.0005)
    ser = SELSerial("/dev/ttyFAKE0", timeout=2.0, binary=True)
    ser.comm = port
    # The relay sends XON before its ASCII output (but not in binary frames)
    real_send = relay.send
    relay.send = lambda data: real_send(data if data[:1] == b"\xa5" else b"\x11" + data)
    results = SELFast(ser).collect()
    assert results.regions["LOCAL"] == {"V": [0x1113, 0x0011]}
    assert results.status_names[3] == "STSET"  # ASCII still works (XON removed)
    assert b"\x11" not in b"".join(ser.raw_output)
    ser.disconnect()


def test_serial_loop_frames_are_binary_safe():
    # pyserial's loop:// echoes what's written, like a relay sending the frame
    port = serial.serial_for_url("loop://", timeout=0.1)
    ser = SELSerial("loop://", timeout=1.0, binary=True)
    ser.comm = port
    frame = fast.build_fast_message(0x90, b"\x00\x00\x00\x00\x00\x02\x11\x13\x00\xff", status=0)
    port.write(b"\x13\x02\r\n=>\x03\x11" + frame + b"\x11")
    assert ser.read_fast_frame(1.0) == frame
    assert ser.read_fast_frame(0.1) is None
    assert ser._read_available() == b"\x02\r\n=>\x03"
    ser.disconnect()


def test_serial_binary_read_and_read_until_keep_frames():
    # read() and read_until() of a binary session also take the frames out
    port = serial.serial_for_url("loop://", timeout=0.1)
    ser = SELSerial("loop://", timeout=1.0, binary=True)
    ser.comm = port
    frame = fast.build_fast_message(0x90, b"\x00\x00\x00\x00\x00\x01\xa5\xff", status=0)
    port.write(frame + b"\x02ID\r\n\x03\r\n=" + frame)
    assert ser.read_until("\x03") == "\x02ID\r\n\x03"
    # What's after "until" isn't discarded
    assert ser.read_fast_frame(1.0) == frame
    assert ser.read_fast_frame(1.0) == frame
    assert ser.read(delay=0.0) == "="
    assert ser.access_level == "0"

    port.write(b"\x02SNS\r\n" + frame + b"\x03")
    assert ser.read(delay=0.05) == "\x02SNS\r\n\x03"
    assert ser.read_fast_frame(1.0) == frame
    assert b"\xa5" not in b"".join(ser.raw_output)
    ser.disconnect()


def test_serial_is_not_binary_by_default():
    relay = FakeSELRelay()
    port = FakeSerialPort(relay)
    ser = SELSerial("/dev/ttyFAKE0", timeout=1.0)
    ser.comm = port
    ser.sync_access_level()
    assert ser._fast_link is None
    with pytest.raises(CommError):
        ser.read_fast_frame(0.1)
    ser.disconnect()


# ---------------------------------------------------------------------------
# SELRelay: the "fast" pull method
# ---------------------------------------------------------------------------


def test_pull_methods_defaults():
    assert "fast" not in SELRelay.default_options["sel"]["pull_methods"]
    assert SELRelay.default_options["sel"]["fast_ser"] is False


def test_pull_fast(telnet_server):
    server = telnet_server(lambda: make_400_relay(fast_ser=SER_MESSAGES))
    dev = datastore.get("127.0.0.1", "ip")
    dev._runtime_options["telnet"] = {"port": server.port, "timeout": 2.0}

    assert SELRelay.pull_fast(dev) is True
    relay = server.relays[0]
    # Fast SER is off by default
    assert not [r for r in relay.binary_requests if r[:2] == b"\xa5\x46" and r[9] == 1]
    # The FID from ID (the device didn't have one)
    assert relay.lines[0] == b"id"
    assert dev.firmware.id == FID_421
    assert dev.serial_number == "9999000001"
    assert dev.extra["RID"] == "TEST RELAY 1"
    assert dev.extra["active_settings_group"] == "2"
    assert {"sel_fast_meter", "sel_fast_message", "dnp3"} <= set(dev.related.protocols)
    assert [e.extra["event"] for e in dev.event if e.dataset == "history"] == ["AG T", "TRIG"]
    assert dev.retrieve("service", {"protocol": "telnet"}).extra["sel_fast"] == [
        "sel_fast_meter",
        "sel_fast_message",
    ]

    out_dir = dev.get_out_dir()
    saved = json.loads((out_dir / "sel-fast.json").read_text())
    assert saved["device_description"]["fid"] == FID_421
    frames = json.loads((out_dir / "sel-fast-frames.json").read_text())
    assert frames[0]["frame"] == "a5c0"
    recorded = {f.name for f in dev.files}
    assert {"sel-fast.json", "sel-fast-frames.json"} <= recorded


def test_pull_fast_with_fast_ser(telnet_server):
    server = telnet_server(lambda: make_400_relay(fast_ser=SER_MESSAGES))
    dev = datastore.get("127.0.0.1", "ip")
    dev._runtime_options["telnet"] = {"port": server.port, "timeout": 2.0}
    dev._runtime_options["sel"] = {"fast_ser": True}

    assert SELRelay.pull_fast(dev) is True
    assert not server.relays[0].fast_ser_enabled
    ser_events = [e for e in dev.event if e.dataset == "ser"]
    assert {e.extra["element"] for e in ser_events} == {"Power-up", "OUT101", "IN101", "TRIP"}
    assert dev.extra["last_boot_device_time"].hour == 1
    assert dev.uptime is not None
    assert dev.extra["sel_fast"]["fast_ser_enabled"] is True


def test_pull_fast_unsupported(telnet_server):
    server = telnet_server(lambda: FastRelay(definition=None))
    dev = datastore.get("127.0.0.1", "ip")
    dev._runtime_options["telnet"] = {"port": server.port, "timeout": 2.0}
    assert SELRelay.pull_fast(dev) is False
    # It tried at level 0, logged in, and tried once more
    assert server.relays[0].binary_requests == [b"\xa5\xc0", b"\xa5\xc0"]
    assert (dev.get_out_dir() / "sel-fast.json").exists()


def test_pull_with_fast_method(telnet_server, mocker):
    server = telnet_server()
    dev = datastore.get("127.0.0.1", "ip")
    dev._runtime_options["telnet"] = {"port": server.port, "timeout": 2.0}
    dev._runtime_options["sel"] = {"pull_methods": ["fast"]}
    spy = mocker.spy(SELRelay, "pull_fast")
    assert SELRelay._pull(dev) is True
    assert spy.call_count == 1

    dev._runtime_options["sel"] = {"pull_methods": ["fast", "carrier-pigeon"]}
    assert SELRelay._pull(dev) is False
    assert spy.call_count == 1


def test_pull_fast_skipped_when_telnet_is_closed(mocker):
    dev = datastore.get("192.0.2.9", "ip")
    dev._runtime_options["sel"] = {"pull_methods": ["fast"]}
    dev.store("service", Service(protocol="telnet", port=23, status="closed"))
    spy = mocker.patch.object(SELRelay, "pull_fast")
    assert SELRelay._pull(dev) is True  # nothing was attempted
    spy.assert_not_called()


def test_serial_pull_with_fast(mocker):
    dev = datastore.get("/dev/ttyFAKE0", "serial_port")
    dev.serial_port = "/dev/ttyFAKE0"
    dev._runtime_options["sel"] = {"pull_methods": ["fast"], "force_serial_pull": True}
    dev._runtime_options["serial"] = {"baudrate": 9600}
    pull_serial = mocker.patch.object(SELRelay, "pull_serial", return_value=True)

    relay = make_400_relay(meter={})

    def make_serial(**kwargs):
        ser = SELSerial(**kwargs)
        ser.comm = FakeSerialPort(relay)
        return ser

    mocker.patch("peat.modules.sel.sel_relay.SELSerial", side_effect=make_serial)
    assert SELRelay._pull(dev) is True
    pull_serial.assert_called_once()
    assert dev.serial_number == "9999000001"
    assert not dev.retrieve("service", {"protocol": "telnet"})


def test_relay_negotiation_bytes():
    # What relays send when a Telnet session starts (WILL ECHO, WILL SGA, WILL BINARY,
    # DO BINARY), and what the emulator sends
    assert RELAY_NEGOTIATION == bytes.fromhex("fffb01fffb03fffb00fffd00")
