import socket
import struct

import pytest

from peat import CommError
from peat.modules.siemens.s7comm import (
    S7CommClient,
    build_cotp_connect,
    build_setup_communication,
    build_szl_request,
    calc_tsap,
    parse_block_counts,
    parse_szl_001c,
    parse_szl_0011,
    parse_szl_0424,
    parse_userdata_response,
)

from .s7_helpers import SZL_001C, SZL_0011, FakePLC, szl, szl_001c_record, userdata_response


def test_calc_tsap():
    assert calc_tsap(0, 2) == 0x0102
    assert calc_tsap(0, 0) == 0x0100
    assert calc_tsap(1, 3, connection_type=0x03) == 0x0323
    with pytest.raises(ValueError):
        calc_tsap(8, 0)


def test_build_cotp_connect():
    pkt = build_cotp_connect(0x0100, 0x0102)
    assert pkt == bytes.fromhex("0300001611e00000000100c1020100c2020102c0010a")


def test_build_setup_communication():
    pdu = build_setup_communication(pdu_ref=1, pdu_size=960)
    assert pdu == bytes.fromhex("32010000000100080000f0000001000103c0")


def test_build_szl_request():
    pdu = build_szl_request(0x0011, 0x0000, pdu_ref=2)
    assert pdu == bytes.fromhex("320700000002000800080001120411440100ff09000400110000")


def test_parse_szl_0011():
    assert parse_szl_0011(SZL_0011) == {
        "module": {"order_number": "6ES7 315-2EH14-0AB0", "version": "4"},
        "hardware": {"order_number": "6ES7 315-2EH14-0AB0", "version": "4"},
        "firmware": {"order_number": "", "version": "3.2.6"},
    }


def test_parse_szl_001c():
    assert parse_szl_001c(SZL_001C) == {
        "plc_name": "Pump Station 1",
        "module_name": "CPU 315-2 PN/DP",
        "plant_id": "PLANT-A",
        "copyright": "Original Siemens Equipment",
        "serial_number": "S C-X4U421302009",
        "module_type_name": "CPU 315-2 PN/DP",
        "memory_card_serial_number": "MMC 267FF11F",
    }


def test_parse_szl_001c_no_record_header():
    # Some emulators (e.g. python-snap7's server) leave the header and indexes empty
    data = struct.pack(">HHHH", 0x001C, 0, 0, 0) + b"".join(
        szl_001c_record(0, v) for v in ["SNAP7-SERVER", "CPU 315-2 PN/DP"]
    )
    assert parse_szl_001c(data) == {"plc_name": "SNAP7-SERVER", "module_name": "CPU 315-2 PN/DP"}


def test_parse_szl_0424():
    run = szl(0x0424, 20, [b"\x51\x44\xff\x08" + b"\x00" * 16])
    stop = szl(0x0424, 20, [b"\x51\x44\xff\x04" + b"\x00" * 16])
    assert parse_szl_0424(run) == "RUN"
    assert parse_szl_0424(stop) == "STOP"
    assert parse_szl_0424(szl(0x0424, 20, [])) == ""


def test_parse_block_counts():
    data = bytes.fromhex("3038000130410003304300023045000130440010")
    assert parse_block_counts(data) == {"OB": 1, "DB": 3, "FC": 2, "FB": 1, "SFC": 16}


def test_parse_userdata_response():
    resp = parse_userdata_response(userdata_response(SZL_0011, last=False, sequence=5))
    assert resp.data == SZL_0011
    assert resp.sequence == 5
    assert not resp.last_data_unit
    assert resp.return_code == 0xFF

    with pytest.raises(CommError):
        parse_userdata_response(b"\x32\x03" + b"\x00" * 20)


def test_client_read_szl():
    plc = FakePLC({0x0011: SZL_0011})
    try:
        with S7CommClient("127.0.0.1", port=plc.port, timeout=5) as client:
            assert client.pdu_size == 240
            assert parse_szl_0011(client.read_szl(0x0011))["firmware"]["version"] == "3.2.6"
    finally:
        plc.close()


def test_client_read_szl_fragmented():
    plc = FakePLC({0x001C: SZL_001C}, fragment_size=100)
    try:
        with S7CommClient("127.0.0.1", port=plc.port, timeout=5) as client:
            assert client.read_szl(0x001C) == SZL_001C
        # 1 request, then continuation requests carrying the response's sequence number
        assert len(plc.requests) == 3
        assert plc.requests[1][17] == 7
    finally:
        plc.close()


def test_client_read_szl_too_many_fragments():
    plc = FakePLC({0x001C: SZL_001C}, fragment_size=1)
    try:
        with S7CommClient("127.0.0.1", port=plc.port, timeout=5) as client:
            with pytest.raises(CommError, match="more than 64 response fragments"):
                client.read_szl(0x001C)
    finally:
        plc.close()


def test_client_reassemble_error_fragment(mocker):
    """An error in a continuation fragment fails the read, not truncates it."""
    client = S7CommClient("127.0.0.1")
    first = parse_userdata_response(userdata_response(SZL_001C[:50], last=False, sequence=3))
    error = parse_userdata_response(userdata_response(b"", error=0xD401, return_code=0x0A))
    mocker.patch.object(client, "_userdata", return_value=error)
    with pytest.raises(CommError, match="error 0xd401"):
        client._reassemble(first, 0x04, 0x01, "SZL 0x001c")


def test_parse_userdata_error_without_data():
    resp = userdata_response(b"", error=0xD401, return_code=0x0A)
    # Strip the data section, like CPUs that send only the parameters on errors
    params_len = struct.unpack(">H", resp[6:8])[0]
    pdu = resp[:8] + b"\x00\x00" + resp[10 : 10 + params_len]
    parsed = parse_userdata_response(pdu)
    assert parsed.error_code == 0xD401
    assert parsed.data == b""


def test_client_connection_refused():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    with pytest.raises(OSError):
        S7CommClient("127.0.0.1", port=port, timeout=1).connect()


def test_client_against_snap7_server():
    snap7_server = pytest.importorskip("snap7.server")
    server = snap7_server.Server()
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    server.start(tcp_port=port)
    try:
        with S7CommClient("127.0.0.1", port=port, timeout=5) as client:
            identity = parse_szl_0011(client.read_szl(0x0011))
            components = parse_szl_001c(client.read_szl(0x001C))
            blocks = client.list_blocks()
    finally:
        server.stop()

    assert identity["module"]["order_number"] == "6ES7 315-2EH14-0AB0"
    assert components["module_type_name"] == "CPU 315-2 PN/DP"
    assert "OB" in blocks
