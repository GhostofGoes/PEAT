"""
Tests for the SEL Fast codec in peat/modules/sel/sel_fast.py: integrity checks,
the request allowlist, frame extraction, the parsers, and the data model mapping.

Frames are built with the builders, with the layouts of public documentation
(SEL-351A IM 20080213 Appendix D and Appendix J, SEL-487B RM 20090519 Table
3.23) and the Fast Message layouts the Wireshark dissector packet-selfm.c
decodes. All of the values are synthetic.
"""

import json
import struct
import time
from datetime import datetime, timedelta

import pytest

from peat import DeviceData
from peat.modules.sel import sel_fast as fast
from peat.modules.sel.relay_parse import process_events
from peat.modules.sel.sel_fast import (
    FastFrameError,
    FastLink,
    FastRequestRefused,
    FrameExtractor,
)

from .fast_relay_emulator import (
    BFID_421,
    FID_421,
    FakeRegion,
    Item,
    data_format_bodies,
    device_description_bodies,
    fast_ser_body,
    fm_config,
    fm_data,
    fm_timestamp,
    fo_config,
    history_region,
    local_region,
    relay_definition,
)


def _message(fc: int, body: bytes, seq: int = fast.SEQ_SINGLE, rn: int = 0, status: int = 0):
    return fast.parse_fast_message(fast.build_fast_message(fc, body, seq, rn, status))


# ---------------------------------------------------------------------------
# Integrity
# ---------------------------------------------------------------------------


def test_crc16_check_value():
    # CRC-16 with the polynomial 0x8005 reflected, initial value 0xFFFF
    # (the Modbus CRC math), check value for "123456789"
    assert fast.sel_crc16(b"123456789") == 0x4B37
    assert fast.sel_crc16(b"") == 0xFFFF


def test_checksum8_manual_example():
    # SEL-351A IM 20080213 Table D.9: "A5E006430DDB" (pulse remote bit RB4).
    # Used only as a checksum vector: PEAT never sends it.
    frame = bytes.fromhex("A5E006430DDB")
    assert fast.sel_checksum8(frame[:-1]) == 0xDB
    assert fast.verify_frame(frame)
    assert not fast.verify_frame(frame[:-1] + b"\xdc")


def test_crc_is_sent_big_endian():
    frame = fast.build_config_request(0)
    crc = fast.sel_crc16(frame[:-2])
    assert frame[-2:] == crc.to_bytes(2, "big")
    assert fast.verify_frame(frame)
    assert not fast.verify_frame(frame[:-2] + crc.to_bytes(2, "little"))


@pytest.mark.parametrize(
    ("built", "expected"),
    [
        (fast.build_config_request(0), "a5460e00000000000100c0008f90"),
        (fast.build_config_request(3), "a5460e00000000000100c0038ed0"),
        (fast.build_device_description_request(frame=1), "a5460e00000000000130c1001091"),
        (fast.build_data_format_request(0), "a5461200000000000131c00000000000f421"),
        (fast.build_read_request(0, 8), "a5461400000000000110c000000000000008e20f"),
        (fast.build_bit_label_request(0x3004), "a5461200000000000133c00000003004f717"),
        (fast.build_enable_fast_ser(32), "a5461200000000000101c000180000208f16"),
        (fast.build_disable_fast_ser(0), "a5461000000000000102c00018004c76"),
        (fast.build_ack(fast.FC_FAST_SER, 0, 0), "a5460e0000000000009800009c40"),
        (fast.build_ack(fast.FC_FAST_SER, 0, 3), "a5460e0000000000009800039d00"),
    ],
)
def test_request_vectors(built, expected):
    assert built.hex() == expected
    assert fast.verify_frame(built)


def test_message_id_and_description():
    assert fast.message_id(b"\xa5\xc0") == 0xA5C0
    assert "Relay definition" in fast.describe_frame(b"\xa5\xc0")
    assert "read response" in fast.describe_frame(_message(0x90, b"\x00" * 6).raw)
    assert "Fast Operate" in fast.describe_frame(bytes.fromhex("a5e3"))
    with pytest.raises(FastFrameError):
        fast.message_id(b"\xa5")


# ---------------------------------------------------------------------------
# Allowlist
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("command", sorted(k for k in fast.ALLOWED_REQUESTS if isinstance(k, int)))
def test_allowed_two_byte_requests(command):
    request = fast.build_meter_request(command)
    assert request == command.to_bytes(2, "big")
    assert fast.check_request(request) == fast.ALLOWED_REQUESTS[command]


@pytest.mark.parametrize(
    "command", [0xA5B9, 0xA5E0, 0xA5E3, 0xA5E5, 0xA5E6, 0xA5E7, 0xA5E8, 0xA5E9, 0xA5ED, 0xA5CF]
)
def test_control_requests_cannot_be_built(command):
    with pytest.raises(FastRequestRefused):
        fast.build_meter_request(command)
    with pytest.raises(FastRequestRefused):
        fast.build_meter_frame(command, b"\x00")
    with pytest.raises(FastRequestRefused):
        fast.check_request(command.to_bytes(2, "big"))


@pytest.mark.parametrize("function_code", [0x05, 0x12, 0x16, 0x20, 0x21, 0x32, 0x40, 0x7F])
def test_fast_message_functions_that_cannot_be_built(function_code):
    with pytest.raises(FastRequestRefused):
        fast.build_fast_message(function_code)
    # Built anyway (as an attacker or a bug would), it's refused before it's sent
    frame = fast._fast_message(function_code, b"\x00\x00", 0xC0, 0, 1)
    with pytest.raises(FastRequestRefused):
        fast.check_outgoing(frame, allow_fast_ser=True)


def test_never_sent_requests_are_not_allowed():
    for key in fast.NEVER_SENT:
        assert key not in fast.ALLOWED_REQUESTS
    for key in fast.FAST_SER_REQUESTS:
        assert key in fast.ALLOWED_REQUESTS


@pytest.mark.parametrize(
    "frame",
    [
        # Fast Operate commands from the manual examples (SEL-351A IM Table D.9)
        bytes.fromhex("A5E006430DDB"),
        bytes.fromhex("A5E306") + bytes([0x31, 0xC5]) + bytes([0]),
        # A two-byte request with a line terminator, as SELAscii.write() would send it
        b"\xa5\xc0\r\n",
        b"\xa5\xc0\x00",
        b"\xa5\xb9",
        b"\xa5",
        b"ACC\xa5",
    ],
)
def test_check_outgoing_refuses(frame):
    with pytest.raises(FastRequestRefused):
        fast.check_outgoing(frame, allow_fast_ser=True)


def test_check_outgoing_allows_ascii():
    assert fast.check_outgoing(b"ID\r\n") is None
    assert fast.check_outgoing(b"") is None
    assert fast.check_outgoing(b"\x18") is None


def test_fast_ser_requests_need_permission():
    for frame in (
        fast.build_enable_fast_ser(32),
        fast.build_disable_fast_ser(),
        fast.build_ack(fast.FC_FAST_SER, 0, 2),
    ):
        with pytest.raises(FastRequestRefused, match=r"sel\.fast_ser"):
            fast.check_request(frame)
        assert fast.check_request(frame, allow_fast_ser=True)


def test_unsolicited_functions_other_than_fast_ser_are_refused():
    # Function 01/02 for 0x20 (unsolicited writes, e.g. synchrophasors)
    enable_writes = fast._fast_message(0x01, bytes([0x20, 0, 0, 1]), 0xC0, 0, 1)
    disable_writes = fast._fast_message(0x02, bytes([0x20, 0]), 0xC0, 0, 1)
    too_many = fast._fast_message(0x01, bytes([0x18, 0, 0, 0x21]), 0xC0, 0, 1)
    for frame in (enable_writes, disable_writes, too_many):
        with pytest.raises(FastRequestRefused):
            fast.check_request(frame, allow_fast_ser=True)
    with pytest.raises(ValueError):
        fast.build_enable_fast_ser(33)


def test_check_request_validates_fast_messages():
    good = fast.build_read_request(0x4000, 10)
    assert fast.check_request(good)
    # Wrong CRC
    with pytest.raises(FastRequestRefused):
        fast.check_request(good[:-1] + bytes([good[-1] ^ 1]))
    # Routing address that isn't zero
    routed = bytearray(good)
    routed[3] = 1
    routed[-2:] = fast.sel_crc16(routed[:-2]).to_bytes(2, "big")
    with pytest.raises(FastRequestRefused):
        fast.check_request(bytes(routed))
    # A relay's response, sent by PEAT
    with pytest.raises(FastRequestRefused):
        fast.check_request(fast.build_fast_message(0x90, b"\x00" * 6))
    # A read of zero words, a body of the wrong size, a frame number
    with pytest.raises(FastRequestRefused):
        fast.check_request(fast._fast_message(0x10, struct.pack(">IH", 0, 0), 0xC0, 0, 1))
    with pytest.raises(FastRequestRefused):
        fast.check_request(fast._fast_message(0x30, b"\x00", 0xC0, 0, 1))
    with pytest.raises(FastRequestRefused):
        fast.check_request(fast._fast_message(0x30, b"", 0x00, 0, 1))
    assert fast.check_request(fast.build_device_description_request(frame=3))


def test_refusal_message_does_not_include_the_data():
    with pytest.raises(FastRequestRefused) as info:
        fast.check_outgoing(b"secret\xa5password")
    assert "secret" not in str(info.value)
    assert "password" not in str(info.value)


def test_build_ack_only_for_acknowledged_functions():
    assert fast.build_ack(fast.FC_ENABLE_UNSOLICITED, 2, 1)[9:12] == bytes([0x81, 2, 1])
    with pytest.raises(FastRequestRefused):
        fast.build_ack(fast.FC_READ)


# ---------------------------------------------------------------------------
# Fast Message frames
# ---------------------------------------------------------------------------


def test_fast_message_roundtrip():
    frame = fast.build_fast_message(0x90, b"\x01\x02", seq=0x41, resp_num=2, status=0)
    message = fast.parse_fast_message(frame)
    assert message.function_code == 0x90
    assert message.body == b"\x01\x02"
    assert message.response_number == 2
    assert message.is_response
    assert not message.is_ack
    assert message.fin
    assert not message.fir
    assert message.frame_number == 1
    assert message.raw == frame

    ack = fast.parse_fast_message(fast.build_ack(fast.FC_FAST_SER, 4, 3))
    assert ack.is_ack
    assert ack.response_code == 4
    assert ack.response_number == 3


@pytest.mark.parametrize(
    "frame",
    [
        b"\xa5\x46\x0e",
        fast.build_config_request()[:-1],
        fast.build_config_request()[:-1] + b"\x00",
        b"\xa5\xc0" + fast.build_config_request()[2:],
    ],
)
def test_parse_fast_message_errors(frame):
    with pytest.raises(FastFrameError):
        fast.parse_fast_message(frame)


def test_fast_message_too_long():
    with pytest.raises(ValueError):
        fast.build_fast_message(0x90, b"\x00" * 242)


# ---------------------------------------------------------------------------
# FrameExtractor
# ---------------------------------------------------------------------------


def _frames(chunks):
    return [data for kind, data in chunks if kind == fast.KIND_BINARY]


def _ascii(chunks):
    return b"".join(data for kind, data in chunks if kind == fast.KIND_ASCII)


def test_extractor_interleaved():
    definition = relay_definition([], [], [0x0300])
    message = fast.build_fast_message(0x90, b"\x00\x00\x00\x00\x00\x01\xff\x0d", status=0)
    data = b"\x02\r\n=>\x03" + definition + b"text" + message + b"\r\n=>"
    extractor = FrameExtractor()
    chunks = extractor.feed(data)
    assert _frames(chunks) == [definition, message]
    assert _ascii(chunks) == b"\x02\r\n=>\x03text\r\n=>"
    assert extractor.pending == b""
    assert extractor.rejected == 0


def test_extractor_byte_by_byte():
    message = fast.build_fast_message(0x90, bytes(range(0, 256, 17)), status=0)
    data = b"abc" + message + b"def" + fast.build_meter_frame(0xA5D1, b"\x00\x11\x13")
    extractor = FrameExtractor()
    chunks = []
    for byte in data:
        chunks += extractor.feed(bytes([byte]))
    assert _frames(chunks) == [message, fast.build_meter_frame(0xA5D1, b"\x00\x11\x13")]
    assert _ascii(chunks) == b"abcdef"


def test_extractor_echo_of_two_byte_request():
    # A two-byte request that's echoed has no length: it's followed by the response
    response = fast.build_meter_frame(0xA5C1, b"\x01" * 20)
    extractor = FrameExtractor()
    chunks = extractor.feed(b"\xa5\xc1" + response)
    assert chunks == [(fast.KIND_INVALID, b"\xa5\xc1"), (fast.KIND_BINARY, response)]
    assert extractor.rejected == 1


def test_extractor_bad_checksum_and_text():
    frame = bytearray(fast.build_meter_frame(0xA5C0, b"\x00\x00\x00"))
    frame[-1] ^= 0xFF
    extractor = FrameExtractor()
    chunks = extractor.feed(bytes(frame) + b"\xa5Z=>")
    assert chunks[0] == (fast.KIND_INVALID, b"\xa5\xc0")
    # The rest isn't a frame: it's data, and 0xA5 followed by "Z" is text
    assert _ascii(chunks).endswith(b"\xa5Z=>")
    assert not _frames(chunks)


def test_extractor_partial_frame_and_flush():
    message = fast.build_fast_message(0xB0, b"\x00" * 100, status=0)
    extractor = FrameExtractor()
    assert extractor.feed(b"=>" + message[:50]) == [(fast.KIND_ASCII, b"=>")]
    assert extractor.pending == message[:50]
    assert extractor.feed(message[50:]) == [(fast.KIND_BINARY, message)]

    # A frame that never completes is given up on when flushed
    assert extractor.feed(message[:20]) == []
    flushed = extractor.flush()
    assert flushed[0] == (fast.KIND_INVALID, message[:2])
    assert _ascii(flushed) == message[2:20]
    assert extractor.pending == b""

    # A single 0xA5 at the end is text when flushed
    assert extractor.feed(b"x\xa5") == [(fast.KIND_ASCII, b"x")]
    assert extractor.flush() == [(fast.KIND_ASCII, b"\xa5")]


def test_extractor_short_length_is_invalid():
    # A length shorter than the smallest frame (e.g. the bytes after a bare request)
    extractor = FrameExtractor()
    chunks = extractor.feed(b"\xa5\x46\x02\x0d\x0a=>")
    assert chunks[0] == (fast.KIND_INVALID, b"\xa5\x46")
    assert _ascii(chunks) == b"\x02\r\n=>"


# ---------------------------------------------------------------------------
# Relay definition block
# ---------------------------------------------------------------------------


def test_relay_definition_manual_example():
    # SEL-351A IM 20080213 Table D.3 (the checksum is calculated)
    frame = relay_definition(
        meter=[(0xA5C1, 0xA5D1), (0xA5C2, 0xA5D2), (0xA5C3, 0xA5D3)],
        flags=[(0x0004, bytes.fromhex("A5C100000000"))],
        protocols=[0x0300, 0x0301, 0x0005, 0x0006],
    )
    assert frame[2] == 0x24
    definition = fast.parse_relay_definition(frame)
    assert definition.meter_messages == [(0xA5C1, 0xA5D1), (0xA5C2, 0xA5D2), (0xA5C3, 0xA5D3)]
    assert [(f.bit, f.text) for f in definition.status_flags] == [(4, "A5C1")]
    assert [p.name for p in definition.protocols] == [
        "SEL Fast Meter",
        "SEL Distributed Port Switch (LMD)",
        "DNP3",
        "SEL MIRRORED BITS",
    ]
    assert definition.protocols[0].fast_operate
    assert definition.protocols[0].fast_message
    assert not definition.protocols[3].fast_operate
    assert definition.fast_message
    assert definition.fast_operate
    assert definition.reserved == b"\x00"
    assert definition.to_dict()["status_flags"][0]["command"] == "A5C1"


def test_relay_definition_without_pad_byte():
    # Some relays have no reserved byte before the checksum: it's found with the length
    frame = relay_definition(
        meter=[(0xA5C1, 0xA5D1)],
        flags=[(1, b"\xa5\xc1"), (1, b"ID\r"), (2, b"sho l\r")],
        protocols=[0x0300, 0x0002, 0x0006, 0x0108],
        pad=False,
    )
    definition = fast.parse_relay_definition(frame)
    assert definition.reserved == b""
    assert [f.text for f in definition.status_flags] == ["A5C1", "ID", "sho l"]
    assert [p.protocol for p in definition.protocols] == [0, 2, 6, 8]
    assert definition.protocols[3].name == "IEC 61850"
    assert fast.ProtocolWord(0x0042).name == "unknown protocol 42"


def test_relay_definition_errors():
    with pytest.raises(FastFrameError):
        fast.parse_relay_definition(fast.build_meter_frame(0xA5C0, bytes([5, 5, 5, 0])))
    with pytest.raises(FastFrameError):
        fast.parse_relay_definition(fast.build_meter_frame(0xA5C1, bytes([0, 0, 0])))
    frame = bytearray(relay_definition([], [], [0x0300]))
    frame[-1] ^= 1
    with pytest.raises(FastFrameError, match="checksum"):
        fast.parse_relay_definition(bytes(frame))


# ---------------------------------------------------------------------------
# Fast Meter
# ---------------------------------------------------------------------------


def test_fast_meter_int16_scale_factors_in_data_message():
    # int16 channels with float32 scale factors in the data message, 4 samples
    # (quarter-cycles), digital banks (like the SEL-551 layout)
    config_frame = fm_config(
        0xA5C1,
        [("IA", 0, 1, 4), ("IB", 0, 1, 4), ("IN", 0, 1, 8)],
        samples=4,
        digital_banks=3,
    )
    config = fast.parse_fm_config(config_frame)
    assert [c.name for c in config.channels] == ["IA", "IB", "IN"]
    assert config.scale_factor_location == 0
    assert config.samples == 4
    assert config.data_command == 0xA5D1

    raw = [491, -541, -6, 342, 261, 0, 494, -538, 0, 339, 258, -6]
    data_frame = fm_data(
        0xA5D1,
        status=b"\x00",
        scale_factors=[0.5, 0.25],
        values=raw,
        types=[0] * 12,
        timestamp=fm_timestamp(12, 1, 2023, 13, 1, 13, 373),
        digital=bytes([0x80, 0x00, 0x3F]),
    )
    data = fast.parse_fm_data(data_frame, config)
    assert data.analogs["IA"] == [245.5, 171.0, 247.0, 169.5]
    assert data.analogs["IB"] == [-270.5, 130.5, -269.0, 129.0]
    assert data.analogs["IN"] == [-1.5, 0.0, 0.0, -1.5]
    assert data.timestamp == datetime(2023, 12, 1, 13, 1, 13, 373000)
    assert data.digital == bytes([0x80, 0x00, 0x3F])
    assert data.to_dict()["timestamp"] == "2023-12-01T13:01:13.373000"


def test_fast_meter_scale_factors_in_config_message():
    config_frame = fm_config(
        0xA5C1, [("ia", 0, 1, 0), ("va", 0, 1, 0)], samples=1, scale_factors=[1.25, 5.0]
    )
    config = fast.parse_fm_config(config_frame)
    assert config.scale_factor_location == 1
    assert [c.scale_factor for c in config.channels] == [1.25, 5.0]
    data = fast.parse_fm_data(
        fm_data(
            0xA5D1, b"\x02", [], [-28, -8], [0, 0], fm_timestamp(12, 4, 2023, 11, 27, 50, 912)
        ),
        config,
    )
    assert data.status == b"\x02"
    assert data.analogs == {"ia": -35.0, "va": -40.0}


def test_fast_meter_float_types_and_no_timestamp():
    config_frame = fm_config(0xA5C2, [("MW3", 2, 0xFF, 0), ("FREQ", 1, 0xFF, 0)])
    config = fast.parse_fm_config(config_frame)
    assert config.data_command == 0xA5D2
    data = fast.parse_fm_data(
        fm_data(0xA5D2, b"\x00", [], [12.375, 60.0], [2, 1], fm_timestamp(0, 0, 0, 0, 0, 0, 0)),
        config,
    )
    assert data.analogs == {"MW3": 12.375, "FREQ": 60.0}
    assert data.timestamp is None  # month 0 isn't a date
    assert fast.parse_fm_timestamp(b"\x01\x02") is None


def test_fast_meter_errors():
    config = fast.parse_fm_config(fm_config(0xA5C1, [("IA", 1, 0xFF, 0)], samples=2))
    with pytest.raises(FastFrameError, match="too short"):
        fast.parse_fm_data(fast.build_meter_frame(0xA5D1, b"\x00\x00\x00"), config)
    with pytest.raises(FastFrameError):
        fast.parse_fm_data(fast.build_meter_frame(0xA5D2, b"\x00" * 30), config)
    with pytest.raises(FastFrameError):
        fast.parse_fm_config(fast.build_meter_frame(0xA5C1, bytes([1, 0, 0, 9, 1, 0, 0])))


def test_fast_meter_calculation_block():
    config = fast.parse_fm_config(
        fm_config(0xA5C1, [("IA", 1, 0xFF, 0), ("VA", 1, 0xFF, 0)], calc_blocks=1)
    )
    block = config.calculation_blocks[0]
    assert block["deskew_offset"] == 0xFFFF
    assert block["channel_indexes"]["IA"] == 0
    assert config.to_dict()["channels"][0]["type"] == "float32"


# ---------------------------------------------------------------------------
# Fast Operate configuration
# ---------------------------------------------------------------------------


def test_fast_operate_config():
    config = fast.parse_fo_config(fo_config(breakers=1, remote_bits=8, pulse=True))
    assert config.breakers == 1
    assert config.remote_bits == 8
    assert config.pulse_supported
    assert config.breaker_codes == [(0x31, 0x11)]
    assert config.remote_bit_codes[3] == (3, 0x23, 0x43)

    config = fast.parse_fo_config(fo_config(breakers=2, remote_bits=2, pulse=False))
    assert config.breaker_codes == [(0x31, 0x11), (0x32, 0x12)]
    assert config.remote_bit_codes == [(0, 0x20, None), (1, 0x21, None)]
    assert config.to_dict()["remote_bits"] == 2

    with pytest.raises(FastFrameError):
        fast.parse_fo_config(fast.build_meter_frame(0xA5CE, bytes([4, 0, 32, 1, 0])))


# ---------------------------------------------------------------------------
# Fast Message configuration, device description, data formats, reads, labels
# ---------------------------------------------------------------------------


def test_fast_message_config():
    body = bytes([0, 1, 7, 1, 2]) + b"\x00" * 6
    body += bytes([3, 0x00, 0, 0x30, 0, 0x10, 0]) + bytes([1, 0x18, 0])
    config = fast.parse_fm_cfg_block_resp(_message(0x80, body))
    assert config.rx_functions == [0x00, 0x30, 0x10]
    assert config.tx_functions == [0x18]
    assert config.accepts(0x30)
    assert not config.accepts(0x01)
    assert config.to_dict()["rx_functions"] == ["00", "30", "10"]

    with pytest.raises(FastFrameError):
        fast.parse_fm_cfg_block_resp(_message(0x80, body[:12] + bytes([5, 0])))
    with pytest.raises(FastFrameError):
        fast.parse_fm_cfg_block_resp(_message(0x90, body))


def _regions(count: int) -> list[FakeRegion]:
    return [
        FakeRegion(f"REG{i}", 0x1000 * i, [Item("X", 0x32, 3, [1, 2, 3])]) for i in range(count)
    ]


def test_device_description_multiple_frames():
    regions = _regions(9)
    bodies = device_description_bodies(f"FID={FID_421}", "SEL-421", regions)
    assert len(bodies) == 2
    frames = [
        fast.parse_device_description(_message(0xB0, body, seq=seq))
        for body, seq in zip(bodies, (0x80, 0x41), strict=True)
    ]
    assert len(frames[0].regions) == 7
    assert len(frames[1].regions) == 2  # and the 8 reserved bytes are skipped
    description = fast.merge_device_description(frames)
    assert description.fid == FID_421  # without "FID="
    assert description.rid == "SEL-421"
    assert description.region_count == 9
    assert [r.name for r in description.regions] == [f"REG{i}" for i in range(9)]
    assert description.regions[8].base == 0x8000
    assert description.regions[8].words == 3
    assert description.complete

    # A missing frame
    assert not fast.merge_device_description(frames[:1]).complete
    assert not fast.merge_device_description(frames, complete=False).complete


def test_device_description_without_prefix_or_reserved_bytes():
    body = device_description_bodies("SEL-2411-R399", "SEL-2411", _regions(1), reserved=False)[0]
    description = fast.parse_device_description(_message(0xB0, body))
    assert description.fid == "SEL-2411-R399"
    assert len(description.regions) == 1
    with pytest.raises(FastFrameError):
        fast.parse_device_description(_message(0xB0, body[:50]))


def test_data_format_multiple_frames():
    items = [Item(f"ITEM{i}", 0x31, 1, i) for i in range(20)] + [Item("NAME", 0x11, 5, "abc")]
    region = FakeRegion("TEST", 0x2000, items)
    bodies = data_format_bodies(region)
    assert len(bodies) == 2
    frames = [fast.parse_data_format(_message(0xB1, body)) for body in bodies]
    data_format = fast.merge_data_format(frames)
    assert data_format.base == 0x2000
    assert data_format.item_count == 21
    assert len(data_format.items) == 21
    assert data_format.items[20].offset == 40
    assert data_format.size == 45
    assert data_format.complete
    assert not fast.merge_data_format(frames[:1]).complete
    assert data_format.to_dict()["items"][20] == {
        "name": "NAME",
        "quantity": 5,
        "type": "char8",
        "offset": 40,
    }


def test_decode_region_types():
    items = [
        Item("TEXT", 0x11, 8, "ABC"),
        Item("WIDE", 0x12, 4, "Hi"),
        Item("DIG8", 0x22, 2, [0x80, 0x01]),
        Item("DIG16L", 0x23, 1, 0x8001),
        Item("I16", 0x31, 2, [-1, 2]),
        Item("U16", 0x32, 1, 65535),
        Item("I32", 0x33, 1, -100000),
        Item("U32", 0x34, 1, 4000000000),
        Item("F32", 0x41, 2, [1.5, float("nan")]),
        Item("I16", 0x31, 1, 7),  # the same name again
    ]
    region = FakeRegion("TEST", 0, items)
    data_format = fast.merge_data_format([fast.parse_data_format(_message(0xB1, b))
                                          for b in data_format_bodies(region)])  # fmt: skip
    values = fast.decode_region(region.data, data_format.items)
    assert values == {
        "TEXT": "ABC",
        "WIDE": "Hi",
        "DIG8": [0x80, 0x01],
        "DIG16L": 0x8001,
        "I16": [-1, 2],
        "U16": 65535,
        "I32": -100000,
        "U32": 4000000000,
        "F32": [1.5, None],
        "I16_2": 7,
    }
    # Items that aren't in the data, and items of an unknown type, are left out
    assert fast.decode_region(region.data[:8], data_format.items) == {"TEXT": "ABC"}
    unknown = [fast.DataItem("ODD", 1, 0x99)]
    assert fast.decode_region(b"\x01\x02", unknown) == {}


def test_read_frames():
    first = _message(0x90, struct.pack(">IH", 0x4000, 2) + b"\x00\x01\xff\xff", seq=0x80)
    second = _message(0x90, struct.pack(">IH", 0x4000, 1) + b"\x12\x34", seq=0x41)
    assert fast.join_read_frames([first, second]) == (0x4000, b"\x00\x01\xff\xff\x12\x34")
    assert fast.parse_read_response(first.raw) == (0x4000, b"\x00\x01\xff\xff")

    other = _message(0x90, struct.pack(">IH", 0x5000, 1) + b"\x00\x00")
    with pytest.raises(FastFrameError):
        fast.join_read_frames([first, other])
    with pytest.raises(FastFrameError):
        fast.parse_read_response(_message(0x90, struct.pack(">IH", 0, 5) + b"\x00\x00"))


def test_bit_labels_lsb_first():
    labels = [b"TLED_1", b"TLED_2", b"", b"", b"", b"", b"TRIP", b"EN"]
    message = _message(0xB3, b"\x00".join(labels) + b"\x00")
    parsed = fast.parse_bit_labels(message)
    assert parsed[0] == "TLED_1"  # bit 0
    assert parsed[7] == "EN"  # bit 7
    assert len(parsed) == 8
    assert fast.parse_bit_labels(_message(0xB3, b"A\x00")) == ["A", ""] + [""] * 6
    with pytest.raises(FastFrameError):
        fast.parse_bit_labels(_message(0x90, b""))


# ---------------------------------------------------------------------------
# Fast SER
# ---------------------------------------------------------------------------


def test_fast_ser_records():
    body = fast_ser_body(2024, 280, 22924213, [(0, 0, 1), (3, 4150, 0), (0xFE, 600, 1)])
    message = fast.parse_fast_ser(
        _message(0x18, body, rn=2, status=0x01), names=["IN101", "OUT101", "52A", "TRIP"]
    )
    assert message.response_number == 2
    assert message.timestamp == datetime(2024, 10, 6, 6, 22, 4, 213000)
    assert [(r.index, r.name, r.state) for r in message.records] == [
        (0, "IN101", 1),
        (3, "TRIP", 0),
        (0xFE, "Power-up", 1),
    ]
    assert message.records[1].timestamp == message.timestamp + timedelta(microseconds=4150)
    assert not message.settings_changed
    assert not message.records_lost

    events = fast.fast_ser_events([message])
    assert events[0]["element"] == "IN101"
    assert events[0]["state"] == "Asserted"
    assert events[1]["state"] == "Deasserted"
    # Power-up records have no state, like in SER output
    assert events[2]["element"] == "Power-up"
    assert events[2]["state"] == ""


def test_fast_ser_lost_records_and_settings_changed():
    # SEL-351A IM 20080213 Table J.4: no records means records were lost
    body = fast_ser_body(2024, 1, 0, [])
    message = fast.parse_fast_ser(_message(0x18, body, status=0x03))
    assert message.records_lost
    assert message.settings_changed
    assert message.to_dict()["records_lost"]


def test_fast_ser_unknown_names_and_errors():
    body = fast_ser_body(2024, 1, 0, [(9, 0, 1), (0xFF, 0, 1), (0xFD, 0, 0)])
    names = [r.name for r in fast.parse_fast_ser(_message(0x18, body)).records]
    assert names == ["SER element 9", "Settings changed", "Element removed from the SER triggers"]
    with pytest.raises(FastFrameError, match="end-of-records"):
        fast.parse_fast_ser(_message(0x18, body.replace(fast.FAST_SER_END, b"\x00" * 4)))
    with pytest.raises(FastFrameError):
        fast.parse_fast_ser(_message(0x90, body))
    assert fast.fast_ser_time(1, 0, 0) is None


# ---------------------------------------------------------------------------
# HISTORY region
# ---------------------------------------------------------------------------


def _decoded(region: FakeRegion):
    data_format = fast.merge_data_format(
        [fast.parse_data_format(_message(0xB1, b)) for b in data_format_bodies(region)]
    )
    return region.data, data_format


def test_history_events():
    region = history_region(
        [
            {"ref": 2, "month": 1, "day": 2, "year": 2024, "hour": 3, "minute": 4, "second": 5,
             "ms": 6, "event": "AG T", "group": 1, "freq": 60.0, "current": 1500,
             "targets": "TRIP"},
            {"ref": 1, "month": 1, "day": 1, "year": 24, "hour": 0, "minute": 0, "second": 0,
             "event": "TRIG", "group": 2},
            # A slot with an invalid date is skipped
            {"month": 13, "day": 1, "year": 2024, "event": "BAD"},
        ],
        slots=5,
    )  # fmt: skip
    data, data_format = _decoded(region)
    events = fast.history_events(data, data_format.items)
    assert len(events) == 2
    assert events[0]["created"] == datetime(2024, 1, 2, 3, 4, 5, 6000)
    assert events[0]["event"] == "AG T"
    assert events[0]["current"] == 1500
    assert events[0]["frequency"] == 60.0
    assert events[0]["group"] == 1
    assert events[0]["targets"] == "TRIP"
    assert "(ref 2)" in events[0]["original"]
    assert events[1]["created"] == datetime(2024, 1, 1)  # 2-digit year
    assert "targets" not in events[1]

    dev = DeviceData()
    process_events(events, dev, dataset="Fast Message HISTORY")
    assert [e.dataset for e in dev.event] == ["history", "history"]
    assert dev.event[0].extra["source_datasets"] == ["Fast Message HISTORY"]
    assert "change" in dev.event[0].type  # a trip


def test_history_events_unknown_layout():
    region = FakeRegion("HISTORY", 0, [Item("X", 0x31, 2, [1, 2])])
    data, data_format = _decoded(region)
    assert fast.history_events(data, data_format.items) == []


# ---------------------------------------------------------------------------
# FastLink
# ---------------------------------------------------------------------------


def _reader(chunks):
    chunks = list(chunks)

    def read_chunk(_wait):
        if not chunks:
            raise EOFError
        chunk = chunks.pop(0)
        if isinstance(chunk, BaseException):
            raise chunk
        return chunk

    return read_chunk


def test_fast_link_splits_ascii_and_frames():
    message = fast.build_fast_message(0x90, b"\x00\x11\x13\xff", status=0)
    link = FastLink(_reader([b"\x11=>\x00" + message[:5], message[5:] + b"\x13ok", b""]))
    # Frames are found while ASCII is read, and XON, XOFF, and NUL are removed
    assert link.read_ascii(0.1) == b"=>"
    assert link.read_ascii(0.1) == b"ok"
    assert link.read_frame(0.1) == message
    assert link.read_frame(0.0) is None


def test_fast_link_ascii_arriving_while_waiting_for_a_frame():
    frame = fast.build_meter_frame(0xA5C0, b"\x00\x00\x00")
    link = FastLink(_reader([b"banner\r\n", frame]))
    assert link.read_frame(1.0) == frame
    assert link.read_ascii(0.1) == b"banner\r\n"


def test_fast_link_gives_up_on_a_frame_that_never_completes():
    message = fast.build_fast_message(0x90, b"\x00" * 20, status=0)
    link = FastLink(_reader([message[:10]] + [b""] * 1000), pending_timeout=0.05)
    assert link.read_frame(0.3) is None
    assert link.invalid == 1
    # The rest is ASCII data (without NUL characters)
    assert link.read_ascii(0.0) == message[2:10].replace(b"\x00", b"")


def test_fast_link_eof():
    frame = fast.build_meter_frame(0xA5C0, b"\x00\x00\x00")
    link = FastLink(_reader([frame[:-1]]))
    assert link.read_frame(1.0) is None
    assert link.eof
    # The frame that didn't complete is given up on, the rest is ASCII data
    assert link.read_ascii(0.0) == frame[2:-1].replace(b"\x00", b"")
    with pytest.raises(EOFError):
        link.read_ascii(0.0)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


def _results_with_local(**local_kwargs) -> fast.FastResults:
    region = local_region(**local_kwargs)
    data, data_format = _decoded(region)
    results = fast.FastResults(
        relay_definition=fast.parse_relay_definition(
            relay_definition([(0xA5C1, 0xA5D1)], [], [0x0300, 0x0005, 0x0006])
        ),
        message_config=fast.FastMessageConfig(0, 1, 7, 1, 2, [0x00, 0x30], [0x18]),
        device_description=fast.DeviceDescription(
            fid=FID_421, rid="SEL-421", regions=[fast.Region("LOCAL", 0, region.words)]
        ),
    )
    results.data_formats["LOCAL"] = data_format
    results.region_data["LOCAL"] = data
    results.regions["LOCAL"] = fast.decode_region(data, data_format.items)
    return results


def test_process_fast_results_local_region():
    results = _results_with_local(group=3, status=0)
    dev = DeviceData()
    fast.process_fast_results(results, dev, port=23)

    assert dev.firmware.id == FID_421  # "FID=" was removed
    assert dev.description.model == "421"
    assert dev.boot_firmware.id == BFID_421
    assert dev.serial_number == "9999000001"
    assert dev.part_number == "0421XXXXXXXXXXXXXX"
    assert dev.extra["RID"] == "TEST RELAY 1"
    assert dev.extra["TID"] == "TEST STATION"
    assert dev.extra["active_settings_group"] == "3"
    assert dev.name == "TEST RELAY 1"
    assert {"sel_fast_meter", "sel_fast_message", "dnp3", "sel_mirrored_bits"} <= set(
        dev.related.protocols
    )
    summary = dev.extra["sel_fast"]
    assert summary["regions"] == ["LOCAL"]
    assert summary["local_status"] == 0
    assert summary["protocols"] == ["sel_fast_meter", "sel_fast_message"]
    service = dev.retrieve("service", {"protocol": "telnet"})
    assert service.port == 23
    assert service.extra["sel_fast"] == ["sel_fast_meter", "sel_fast_message"]


def test_process_fast_results_keeps_existing_values():
    results = _results_with_local(prefix_keys=False)
    dev = DeviceData()
    dev.serial_number = "FROM-ID"
    dev.part_number = "FROM-ID-PART"
    dev.firmware.id = "SEL-421-5-R100-V0-Z001001-D20200101"
    dev.extra["RID"] = "ASCII RID"
    dev.name = "ASCII NAME"
    fast.process_fast_results(results, dev)
    assert dev.serial_number == "FROM-ID"
    assert dev.part_number == "FROM-ID-PART"
    assert dev.firmware.id == "SEL-421-5-R100-V0-Z001001-D20200101"
    assert dev.extra["RID"] == "ASCII RID"
    assert dev.name == "ASCII NAME"
    assert dev.boot_firmware.id == BFID_421
    assert not dev.retrieve("service", {"protocol": "telnet"})  # serial (no port)


def test_process_fast_results_fast_operate_and_status():
    results = _results_with_local(status=0x0004)
    results.fast_operate = fast.parse_fo_config(fo_config(1, 16))
    dev = DeviceData()
    fast.process_fast_results(results, dev)
    assert dev.extra["sel_fast"]["fast_operate"] == {
        "enabled_on_port": True,
        "breakers": 1,
        "remote_bits": 16,
        "pulse_supported": True,
    }
    assert "sel_fast_operate" in dev.related.protocols
    assert dev.extra["sel_fast"]["local_status"] == 4


def test_process_fast_results_fast_ser_and_uptime():
    message = fast.parse_fast_ser(
        _message(0x18, fast_ser_body(2024, 2, 3600_000, [(0xFE, 0, 1), (0, 500, 1)])),
        names=["IN101"],
    )
    results = fast.FastResults(fast_ser=[message], fast_ser_enabled=True)
    results.device_time = datetime(2024, 1, 2, 3, 0, 0)
    results.device_time_read_at = time.monotonic()
    dev = DeviceData()
    fast.process_fast_results(results, dev)

    assert sorted(e.extra["element"] for e in dev.event) == ["IN101", "Power-up"]
    assert all(e.dataset == "ser" for e in dev.event)
    power_up = next(e for e in dev.event if e.extra["element"] == "Power-up")
    assert "start" in power_up.type
    # The power-up was at 01:00 on the relay's clock, which said 03:00
    assert timedelta(hours=1, minutes=59) < dev.uptime < timedelta(hours=2, minutes=1)
    assert dev.extra["uptime_source"] == "ser_power_up"
    assert dev.extra["sel_fast"]["fast_ser_records"] == 2


def test_fast_results_to_dict_is_json():
    results = _results_with_local()
    results.meter.append(
        {"config": fast.parse_fm_config(fm_config(0xA5C1, [("IA", 1, 0xFF, 0)])), "data": None}
    )
    results.fast_ser.append(fast.parse_fast_ser(_message(0x18, fast_ser_body(2024, 1, 0, []))))
    text = json.dumps(results.to_dict())
    assert "LOCAL" in text
    assert results.to_dict()["fast_meter"][0]["config"]["channels"][0]["name"] == "IA"
    assert results.supported
    assert not fast.FastResults().supported
    assert fast.FastResults().device_now() is None


def test_bit_names():
    names = ["*", "*", "*", "STSET", "*", "*", "*", "PWR", "A", "B"]
    assert fast.bit_names(names, bytes([0x11, 0x80])) == {"STSET": 1, "PWR": 1, "A": 1, "B": 0}


def test_settings_changed_bits():
    # The status flag of SEL-351A IM 20080213 Table D.3: bit 4 (STSET), re-read A5C1
    definition = fast.parse_relay_definition(
        relay_definition([(0xA5C1, 0xA5D1)], [(4, b"\xa5\xc1")], [0x0300])
    )
    assert fast.settings_changed_bits(definition, []) == {(0, 4)}
    assert fast.settings_changed(b"\x10", {(0, 4)}) is True
    assert fast.settings_changed(b"\xef", {(0, 4)}) is False
    assert fast.settings_changed(b"", {(0, 4)}) is None
    assert fast.settings_changed(b"", set()) is False
    # A bit that's set wins over one that isn't in the status
    assert fast.settings_changed(b"\x01", {(0, 0), (1, 0)}) is True

    # By the BNA name (MSB first): STSET is the 7th name on the SEL-351S
    names = ["*", "*", "*", "*", "*", "PWRUP", "STSET", "*"]
    assert fast.settings_changed_bits(None, names) == {(0, 1)}
    assert fast.settings_changed_bits(None, ["*"] * 8 + ["STSET"]) == {(1, 7)}

    # Flags for other commands (e.g. DNA, SNS, STA) aren't settings changed bits
    definition = fast.parse_relay_definition(
        relay_definition(
            [(0xA5C1, 0xA5D1), (0xA5C2, 0xA5D2)],
            [(0, b"\xa5\xc1"), (0, b"\xa5\xc2"), (4, b"DNA"), (1, b"SNS"), (2, b"sta\r")],
            [0x0300],
        )
    )
    assert fast.settings_changed_bits(definition, []) == {(0, 0)}
    assert fast.settings_changed_bits(fast.RelayDefinition(), []) == set()
