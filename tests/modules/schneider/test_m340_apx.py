"""
Tests for parsing Schneider Modicon APX project files.

There are no real APX files available for testing, so these tests build
synthetic APX files that follow the format as documented by apxutil
(https://github.com/finngineering/apxutil, MIT License).
"""

import struct
import zlib

import pytest

from peat.modules.schneider.m340.m340_parse import (
    _scan_decompress,
    chunkify,
    crc16_kermit,
    extract_chunk,
    extract_logic_blocks,
    parse_config_to_dict,
    parse_sd_section,
)

ATTR_COMPRESSED = 1 << 13
ATTR_NO_DATA = 1 << 28
# RTE attributes for blocks used by PEAT ("type" in the chunks)
ATTR_METADATA = 0xE08F0000  # b"\x00\x00\x8f\xe0"
ATTR_VARIABLES = 0xE0CF2403  # b"\x03\x24\xcf\xe0", compressed

# 0x78 0xDA followed by a valid zlib stream. If the bytes were scanned
# for zlib signatures, this would wrongly be decompressed.
FAKE_ZLIB = zlib.compress(b"should not be decompressed", 9)
assert FAKE_ZLIB[:2] == b"\x78\xda"


def apx_header(rte_type: int = 2, rte_size: int = 16, version: int = 0x0100) -> bytes:
    header = bytearray(32)
    header[0:3] = b"APX"
    struct.pack_into("<HBB", header, 4, version, rte_type, 1)
    header[10] = rte_size
    return bytes(header)


def rte_header(
    data: bytes = b"",
    attributes: int = 0,
    crc: int | None = None,
    membyte: int = 0,
    rte_size: int = 16,
) -> bytes:
    if crc is None:
        crc = crc16_kermit(data) if data else 0
    rte = struct.pack("<IIIHB", 1, max(len(data) - 1, 0), attributes, crc, membyte)
    return rte.ljust(rte_size, b"\x00")


def section(
    section_type: int,
    number: int,
    data: bytes = b"",
    attributes: int = 0,
    crc: int | None = None,
    membyte: int = 0,
    rte_size: int = 16,
    data_size: int | None = None,
) -> bytes:
    if section_type == 0:
        header = struct.pack("<HHHH", 0, 0, number, 0)
    elif section_type == 1:
        header = struct.pack("<HHH", 1, 0, number).ljust(16, b"\x00")
    elif section_type == 2:
        if data_size is None:
            data_size = len(data)
        header = struct.pack("<HHHIIH", 2, 0, number, 0, data_size, 0)
    else:
        header = struct.pack("<HHH", section_type, 0, number).ljust(24, b"\x00")

    rte = rte_header(data, attributes, crc, membyte, rte_size)
    if section_type != 2:
        data = b""
    return header + rte + data


def pk_compress(raw: bytes) -> bytes:
    header = bytearray(0x2E)
    header[0:4] = b"PK\x01\x02"
    return bytes(header) + zlib.compress(raw, 9)[2:-4]  # raw deflate


def zlib_compress(raw: bytes) -> bytes:
    return b"ZLIB" + struct.pack("<H", len(raw)) + b"\x00" * 10 + zlib.compress(raw, 9)


def sd_data() -> bytes:
    data = bytearray(16)
    data[0:4] = b"SD\x00\x00"
    struct.pack_into("<HH", data, 4, 16, 0x110)  # mem header offset, data size
    struct.pack_into("<H", data, 12, 0x1)  # data flag
    # mem header: header size, area entry size, folio entry size, area count
    data += struct.pack("<HHHB", 8, 8, 16, 1).ljust(8, b"\x00")
    data += struct.pack("<BBBI", 1, 2, 3, 0x1000).ljust(8, b"\x00")
    for folio_num in range(2):
        folio = struct.pack("<BIH", folio_num, 0x100 * (folio_num + 1), 0x5).ljust(9, b"\x00")
        data += (folio + struct.pack("<I", 0x200)).ljust(16, b"\x00")
    return bytes(data)


def chunk_list(blob: bytes) -> list[dict]:
    return list(chunkify(blob).values())


def test_crc16_kermit_known_answer():
    # Expected values computed with apxutil's table-driven algorithm
    assert crc16_kermit(b"123456789") == 0x6F91
    assert crc16_kermit(b"123456789", init=0) == 0x2189  # Standard CRC-16/KERMIT check
    assert crc16_kermit(b"") == 0xFFFF


def test_chunkify_apx_header():
    chunks = chunk_list(apx_header(version=0x0100) + section(0, 1))
    assert chunks[0]["tag"] == "APX"
    assert chunks[0]["number"] == 0
    assert chunks[0]["type"] == ""
    assert chunks[0]["version"] == 0x0100
    assert chunks[0]["rte_type"] == 2
    assert chunks[0]["rte_size"] == 16
    assert len(chunks[0]["head"]) == 32


def test_chunkify_all_section_types():
    raw = b"Hello, PEAT! " * 20
    multi_streams = zlib.compress(b"first stream,") + zlib.compress(b" second stream")
    blob = b"".join(
        [
            apx_header(),
            section(0, 0x01),
            section(1, 0x02),
            section(2, 0x10, FAKE_ZLIB, membyte=(5 << 3) | 2),
            section(3, 0x03),
            section(4, 0x04),
            section(2, 0x20, pk_compress(raw), ATTR_COMPRESSED),
            section(2, 0x21, zlib_compress(raw), ATTR_COMPRESSED),
            section(2, 0x22, multi_streams, ATTR_COMPRESSED),
            section(2, 0x23, b"tampered data", crc=0x1234),
            section(0, 0x05),
        ]
    )
    chunks = chunkify(blob)
    offsets = list(chunks)
    found = list(chunks.values())

    assert [c["tag"] for c in found] == ["APX", "0", "1", "2", "3", "4", "2", "2", "2", "2", "0"]
    assert [c["section_number"] for c in found[1:]] == [
        0x01,
        0x02,
        0x10,
        0x03,
        0x04,
        0x20,
        0x21,
        0x22,
        0x23,
        0x05,
    ]
    assert offsets[:5] == [0, 32, 32 + 24, 32 + 24 + 32, 32 + 24 + 32 + 32 + len(FAKE_ZLIB)]
    # Type 3 and 4 sections have 24 byte headers and are skipped over
    assert len(found[4]["head"]) == 24 + 16
    assert offsets[5] - offsets[4] == 24 + 16
    assert "data" not in found[4]

    uncompressed = found[3]
    assert uncompressed["data"] == FAKE_ZLIB
    assert uncompressed["compressed"] is False
    assert uncompressed["crc_valid"] is True
    assert uncompressed["length"] == len(FAKE_ZLIB)
    assert uncompressed["mem_area"] == 5
    assert uncompressed["mem_folio"] == 2
    assert uncompressed["block_count"] == 1
    assert uncompressed["size_minus1"] == len(FAKE_ZLIB) - 1

    for pos in (6, 7):  # PK and ZLIB
        assert found[pos]["compressed"] is True
        assert found[pos]["crc_valid"] is True
        assert found[pos]["data"] == raw

    assert found[8]["data"] == b"first stream, second stream"

    assert found[9]["data"] == b"tampered data"
    assert found[9]["crc16"] == 0x1234
    assert found[9]["crc_valid"] is False

    # Sections without data
    assert found[1]["crc_valid"] is None
    assert found[10]["tag"] == "0"


def test_chunkify_bad_crc_logs_warning(caplog):
    blob = apx_header() + section(2, 0x23, b"tampered data", crc=0x1234)
    chunks = chunk_list(blob)
    assert chunks[1]["crc_valid"] is False
    assert "CRC16 mismatch" in caplog.text


def test_chunkify_legacy_fields_unchanged():
    """The common case (RTE type 2, RTE size 16) keeps the same fields as before."""
    data = b"\x01\x02\x03\x04"
    blob = apx_header() + section(0, 7) + section(1, 8) + section(2, 9, data, ATTR_METADATA)
    chunks = chunkify(blob)

    assert chunks[32]["number"] == 7
    assert chunks[32]["head"] == blob[32 : 32 + 24]
    assert chunks[56]["number"] == 8
    assert chunks[56]["head"] == blob[56 : 56 + 32]

    chunk = chunks[88]
    assert chunk["tag"] == "2"
    assert chunk["number"] == 9
    assert chunk["head"] == blob[88 : 88 + 32]
    assert chunk["type"] == blob[88 + 24 : 88 + 28] == b"\x00\x00\x8f\xe0"
    assert chunk["length"] == len(data)
    assert chunk["data"] == data
    assert chunk["attributes"] == ATTR_METADATA


def test_chunkify_custom_rte_size():
    raw = b"some data"
    blob = (
        apx_header(rte_size=24)
        + section(0, 1, rte_size=24)
        + section(2, 2, zlib.compress(raw), ATTR_COMPRESSED, rte_size=24)
        + section(1, 3, rte_size=24)
    )
    chunks = chunk_list(blob)
    assert [c["tag"] for c in chunks] == ["APX", "0", "2", "1"]
    assert chunks[2]["data"] == raw
    assert chunks[2]["crc_valid"] is True
    assert len(chunks[2]["head"]) == 16 + 24
    assert len(chunks[3]["head"]) == 16 + 24


def test_chunkify_no_data_attribute_forces_zero_length():
    blob = (
        apx_header()
        # The data size in the section header is ignored if bit 28 is set
        + section(2, 1, attributes=ATTR_NO_DATA, data_size=100)
        + section(2, 2, b"next", ATTR_METADATA)
    )
    chunks = chunk_list(blob)
    assert chunks[1]["length"] == 0
    assert chunks[1]["data"] == b""
    assert chunks[2]["section_number"] == 2
    assert chunks[2]["data"] == b"next"


def test_chunkify_rte_type_1_falls_back_to_scanning():
    raw = b"compressed contents"
    data = b"\x00\x01" + zlib.compress(raw)
    blob = apx_header(rte_type=1) + section(2, 1, data, ATTR_COMPRESSED)
    chunks = chunk_list(blob)
    assert chunks[0]["rte_type"] == 1
    assert chunks[1]["attributes"] is None
    assert chunks[1]["compressed"] is None
    assert chunks[1]["crc_valid"] is None
    assert chunks[1]["data"] == b"\x00\x01" + raw


def test_chunkify_unknown_section_type_stops():
    blob = apx_header() + section(0, 1) + b"\x09\x00" + b"\x00" * 30
    chunks = chunkify(blob)
    assert [c.get("tag") for c in chunks.values()] == ["APX", "0", None]


def test_chunkify_truncated_section():
    blob = apx_header() + section(2, 1, b"0123456789", ATTR_METADATA)[:-4]
    chunks = chunk_list(blob)
    assert chunks[1]["data"] == b"012345"
    assert chunks[1]["crc_valid"] is False


@pytest.mark.parametrize(
    "data",
    [
        b"\x78\xda not actually zlib",
        b"PK\x01\x02" + b"\xff" * 60,
        b"ZLIB" + b"\x00" * 12 + b"garbage",
        b"no compression signature",
        zlib.compress(b"valid stream") + b"\x00\x00 trailing junk",
    ],
)
def test_extract_chunk_compressed_falls_back_to_scanning(data):
    assert extract_chunk(data, compressed=True) == _scan_decompress(data)


def test_extract_chunk_defaults_to_scanning():
    raw = b"legacy behavior"
    data = b"prefix" + zlib.compress(raw)
    assert extract_chunk(data) == b"prefix" + raw
    assert extract_chunk(data, compressed=False) == data


def test_extract_chunk_pk_trailing_data():
    raw = b"pk contents" * 10
    assert extract_chunk(pk_compress(raw) + b"trailer", compressed=True) == raw


def test_parse_sd_section():
    layout = parse_sd_section(sd_data())
    assert layout == {
        "data_size": 0x110,
        "data_flag": 0x1,
        "mem_area_count": 1,
        "mem_areas": [
            {
                "area_num": 1,
                "area_type": 3,
                "area_address": 0x1000,
                "folio_count": 2,
                "folios": [
                    {
                        "folio_num": 0,
                        "folio_size": 0x100,
                        "folio_attributes": 0x5,
                        "folio_size2": 0x200,
                    },
                    {
                        "folio_num": 1,
                        "folio_size": 0x200,
                        "folio_attributes": 0x5,
                        "folio_size2": 0x200,
                    },
                ],
            }
        ],
    }


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"XX" + sd_data()[2:],
        sd_data()[:40],
        b"SD\x00\x00\xff\xff",
        # Zero size area and folio entries
        sd_data()[:16] + struct.pack("<HHHB", 8, 0, 0, 255).ljust(8, b"\x00"),
    ],
)
def test_parse_sd_section_malformed(data):
    assert parse_sd_section(data) is None


def test_parse_config_to_dict():
    metadata = (
        b"\x00" * 256
        + b"MyProject"
        + b"\x00" * 9
        + b"V14.1"
        + b"\x00"
        + b"alice"
        + b"\x00"
        + b"C:\\project.stu"
        + b"\x00"
    )
    blob = (
        apx_header()
        + section(0, 1)
        + section(2, 0x01, sd_data())
        + section(2, 20, metadata, ATTR_METADATA)
        + section(2, 0x30, b"bad crc", crc=0x1234)
    )
    parsed = parse_config_to_dict(blob)
    assert parsed["project_file_metadata"] == {
        "project_name": "MyProject",
        "unity_version": "V14.1",
        "user_name": "alice",
        "file_path": "C:\\project.stu",
    }
    assert parsed["memory_layout"]["mem_areas"][0]["area_address"] == 0x1000


def test_parse_config_to_dict_bad_sd_section():
    blob = apx_header() + section(2, 0x01, b"SD\x00\x00\x40\x00")
    assert "memory_layout" not in parse_config_to_dict(blob)


def test_extract_logic_blocks_compressed_variables():
    variables = b"\x06\x00MyVar\x00INT\x00\x00\x30\x00\x01\x00"
    blob = apx_header() + section(
        2, 0x40, zlib.compress(variables), ATTR_VARIABLES | ATTR_COMPRESSED
    )
    blocks = extract_logic_blocks(blob)
    assert blocks["vars"]["MyVar"]["type"] == "INT"
    assert blocks["vars"]["MyVar"]["location"] == 0


def test_crc_not_set():
    # A stored CRC of 0 means the CRC wasn't set, so it isn't checked
    chunks = chunkify(apx_header() + section(2, 0x30, b"data", crc=0))
    assert chunks[32]["crc_valid"] is None


def test_real_apx_file(datapath):
    data = datapath("apx/estradege_m340_Station.apx").read_bytes()
    chunks = chunkify(data)

    assert chunks[0]["tag"] == "APX"
    assert chunks[0]["rte_type"] == 2
    assert chunks[0]["rte_size"] == 16
    # Every section was parsed, and none failed the CRC check
    assert len(chunks) == 103
    assert sum(c["tag"] == "2" for c in chunks.values()) > 50
    assert not [c for c in chunks.values() if c.get("crc_valid") is False]
    assert any(c.get("crc_valid") for c in chunks.values())

    parsed = parse_config_to_dict(data)
    assert parsed["project_file_metadata"]["project_name"] == "Projet"
    assert parsed["project_file_metadata"]["unity_version"] == "V15.0"
    assert parsed["project_file_metadata"]["user_name"] == "GENEVE"
    layout = parsed["memory_layout"]
    assert layout["mem_area_count"] == 3
    assert layout["mem_areas"][0]["area_address"] == 0x100000

    assert len(extract_logic_blocks(data)["vars"]) == 12
