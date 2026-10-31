import binascii
import json
from datetime import UTC, datetime

import pytest
from scapy.layers.inet import IP, TCP
from scapy.utils import rdpcap

from peat import DeviceError, config, datastore, state
from peat.modules.schneider.m340 import m340 as m340_module
from peat.modules.schneider.m340.m340 import M340
from peat.modules.schneider.m340.umas_packets import (
    Modbus,
    UMASConnectionResponse,
    UMASResponse,
    connect_packet,
    describe_modbus_payload,
    poll_packet,
    pull_packet,
    start_pull_packet,
    tracker_to_records,
    umas_tracker_to_pcapng,
    update_tracker,
)

LOCAL = ("192.0.2.10", 40000)
REMOTE = ("192.0.2.41", 502)


def _response(data: bytes) -> bytes:
    return bytes(Modbus(data=data))


def _ok(**kwargs) -> bytes:
    return _response(bytes(UMASResponse(connectionCode=0, commandCode=0xFE, **kwargs)))


# Responses for poll, connect, poll, start pull, one data block (EOF), and stop pull
RESPONSES = [
    _ok(),
    _response(bytes(UMASConnectionResponse(commandCode=0xFE, newConnectionCode=1))),
    _ok(),
    _ok(num=0, dataLen=4),
    _response(bytes(UMASResponse(connectionCode=1, commandCode=0xFE, num=1, dataLen=4)) + b"APX!"),
    _ok(),
]


class FakeSock:
    """Fake TCP socket that returns canned UMAS responses."""

    fail_after: int | None = None

    def __init__(self, *args, **kwargs):  # noqa: ARG002
        self.responses = list(RESPONSES)
        self.sent = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def settimeout(self, timeout):
        pass

    def connect(self, address):
        pass

    def getsockname(self):
        return LOCAL

    def getpeername(self):
        return REMOTE

    def send(self, data):
        self.sent.append(data)
        return len(data)

    def recv(self, size):  # noqa: ARG002
        if FakeSock.fail_after is not None and len(self.sent) > FakeSock.fail_after:
            raise OSError("connection reset by peer")
        return self.responses.pop(0)


@pytest.fixture
def m340_env(mocker, tmp_path):
    FakeSock.fail_after = None
    mocker.patch.object(datastore, "objects", [])
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path, "DEBUG": 0})
    mocker.patch.dict(state["CONFIG"], {"written_files": set(), "local_interface_details": {}})
    mocker.patch.object(m340_module.socket, "socket", FakeSock)
    mocker.patch.object(M340, "update_dev")
    return tmp_path


def _tcp_payload(pkt) -> bytes:
    """
    TCP payload from the raw frame bytes. Unlike ``pkt[TCP].payload``, this doesn't
    depend on which Scapy layers are bound to the port (e.g. scapy.contrib.modbus).
    """
    raw = bytes(pkt)
    ihl = (raw[14] & 0x0F) * 4
    data_offset = (raw[14 + ihl + 12] >> 4) * 4
    total_length = int.from_bytes(raw[16:18], "big")
    return raw[14 + ihl + data_offset : 14 + total_length]


def _tracker() -> list[dict]:
    sock = FakeSock()
    tracker = []
    packets = [
        (poll_packet(0), RESPONSES[0], UMASResponse),
        (connect_packet(), RESPONSES[1], UMASConnectionResponse),
        (start_pull_packet(1), RESPONSES[3], UMASResponse),
        (pull_packet(1, 1), RESPONSES[4], UMASResponse),
    ]
    for request, raw_response, response_class in packets:
        update_tracker("send", request, bytes(request), sock, tracker)
        response = response_class(Modbus(raw_response).data)
        update_tracker("receive", response, raw_response, sock, tracker)
    return tracker


def test_describe_modbus_payload():
    assert describe_modbus_payload(bytes(poll_packet(0)), "send") == (
        "UMAS request READ_PLC_INFO (0x04), session key 0x00, 10 bytes"
    )
    assert "TAKE_PLC_RESERVATION (0x10)" in describe_modbus_payload(
        bytes(connect_packet()), "send"
    )
    assert describe_modbus_payload(bytes(pull_packet(1, 1)), "send").startswith(
        "UMAS request DOWNLOAD_BLOCK (0x34), session key 0x01"
    )
    assert describe_modbus_payload(RESPONSES[0], "receive", 0x04) == (
        "UMAS response RESPONSE_OK (0xfe) to READ_PLC_INFO, 14 bytes"
    )
    assert "to ?" in describe_modbus_payload(RESPONSES[0], "receive")
    error = _response(bytes([0x00, 0xFD]))
    assert "RESPONSE_ERROR (0xfd)" in describe_modbus_payload(error, "receive", 0x33)
    unknown = _response(bytes([0x00, 0xEE]))
    assert "UNKNOWN_0xee" in describe_modbus_payload(unknown, "send")
    assert describe_modbus_payload(bytes.fromhex("000100000006012b0e01"), "send") == (
        "Modbus/TCP function 0x2b request, 10 bytes"
    )
    assert describe_modbus_payload(b"\x00\x01", "receive") == (
        "Modbus/TCP response (truncated, 2 bytes)"
    )
    assert describe_modbus_payload(bytes.fromhex("000100000003005a00"), "send") == (
        "UMAS request (truncated, 9 bytes)"
    )


def test_tracker_to_records():
    tracker = _tracker()
    # Entries loaded back from umas-metadata.json have string values
    json_entry = json.loads(json.dumps(tracker[0], default=str))
    json_entry["payload"] = tracker[0]["payload"].decode()
    json_entry["timestamp"] = tracker[0]["timestamp"].isoformat()
    bad = [{"direction": "send"}, {**json_entry, "payload": "zz"}, {**json_entry, "payload": b""}]

    records = tracker_to_records([*tracker, json_entry, *bad])
    assert len(records) == len(tracker) + 1
    assert records[0].direction == "send"
    assert records[0].local == LOCAL
    assert records[0].remote == REMOTE
    assert records[0].payload == bytes(poll_packet(0))
    assert records[0].time == tracker[0]["timestamp"].timestamp()
    assert records[1].comment.endswith("to READ_PLC_INFO, 14 bytes")
    assert "to TAKE_PLC_RESERVATION" in records[3].comment
    assert records[-1].time == records[0].time


def test_umas_tracker_to_pcapng(tmp_path):
    tracker = _tracker()
    data = umas_tracker_to_pcapng(tracker, remote_mac="00:00:5e:00:53:41")
    path = tmp_path / "umas.pcapng"
    path.write_bytes(data)
    packets = rdpcap(str(path))

    data_frames = [p for p in packets if p[TCP].flags == "PA"]
    assert len(packets) == 3 + len(tracker) + 3  # handshake + data + teardown
    assert len(data_frames) == len(tracker)
    for frame, entry in zip(data_frames, tracker, strict=True):
        assert _tcp_payload(frame) == binascii.unhexlify(entry["payload"])
        assert frame.comment.startswith(
            b"UMAS request" if entry["direction"] == "send" else b"UMAS response"
        )
        if entry["direction"] == "send":
            assert frame[IP].src == LOCAL[0]
            assert frame[TCP].dport == 502
        else:
            assert frame[IP].src == REMOTE[0]
            assert frame[TCP].sport == 502
            assert frame.src == "00:00:5e:00:53:41"

    assert b"DOWNLOAD_BLOCK" in data_frames[6].comment
    assert b"Synthesized by PEAT" in packets[0].comment

    # Valid Modbus/TCP framing (MBAP header) with function code 90 (UMAS), which
    # is what Wireshark's Modbus/TCP dissector expects on TCP port 502
    for frame in data_frames:
        adu = _tcp_payload(frame)
        assert adu[2:4] == b"\x00\x00"  # Protocol ID
        assert int.from_bytes(adu[4:6], "big") == len(adu) - 6  # Length
        assert adu[7] == 0x5A

    assert umas_tracker_to_pcapng([]).startswith(b"\x0a\x0d\x0d\x0a")


def test_pull_apx_file_writes_pcap(m340_env):
    blob = M340.pull_apx_file(REMOTE[0])
    assert blob == b"APX!"

    dev_dir = next(m340_env.iterdir())
    pcap_path = dev_dir / "umas-packets.pcapng"
    metadata = json.loads((dev_dir / "umas-metadata.json").read_text())
    assert len(metadata) == 2 * len(RESPONSES)

    packets = rdpcap(str(pcap_path))
    assert len([p for p in packets if p[TCP].flags == "PA"]) == 2 * len(RESPONSES)
    assert pcap_path.as_posix() in state.written_files


def test_pull_apx_file_failure_still_writes(m340_env):
    FakeSock.fail_after = 2  # Fails after the third request (second poll) was sent
    with pytest.raises(DeviceError):
        M340.pull_apx_file(REMOTE[0])

    dev_dir = next(m340_env.iterdir())
    assert (dev_dir / "umas-metadata.json").is_file()
    packets = rdpcap(str(dev_dir / "umas-packets.pcapng"))
    # poll, connect and the second poll requests, and the first two responses
    assert len([p for p in packets if p[TCP].flags == "PA"]) == 5


def test_save_umas_pcap_disabled(m340_env, mocker):
    # Equivalent of "device_options: m340: save_umas_pcap: false" in a YAML config
    mocker.patch.dict(datastore.global_options, {"m340": {"save_umas_pcap": False}})
    M340.pull_apx_file(REMOTE[0])
    dev_dir = next(m340_env.iterdir())
    assert (dev_dir / "umas-metadata.json").is_file()
    assert not (dev_dir / "umas-packets.pcapng").exists()


@pytest.mark.usefixtures("m340_env")
def test_save_umas_pcap_error_does_not_fail_pull(mocker, caplog):
    mocker.patch.object(m340_module, "umas_tracker_to_pcapng", side_effect=ValueError("bad"))
    assert M340.pull_apx_file(REMOTE[0]) == b"APX!"
    assert "Failed to save UMAS packets" in caplog.text


def test_tracker_timestamps_are_utc():
    entry = _tracker()[0]
    assert entry["timestamp"].tzinfo is not None
    assert entry["timestamp"] <= datetime.now(UTC)
