import struct

import pytest

from peat.parsing.mfc_archive import (
    MfcFormatError,
    MfcReader,
    find_class_defs,
    read_cstring,
)


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"\x00", ""),
        (b"\x05hello", "hello"),
        (b"\xff" + struct.pack("<H", 300) + b"a" * 300, "a" * 300),
        (b"\xff\xff\xff" + struct.pack("<I", 70000) + b"b" * 70000, "b" * 70000),
        # Wide (UTF-16) strings
        (b"\xff\xfe\xff\x02" + "hé".encode("utf-16-le"), "hé"),
        (
            b"\xff\xfe\xff\xff" + struct.pack("<H", 300) + ("x" * 300).encode("utf-16-le"),
            "x" * 300,
        ),
        # cp1252
        (b"\x03\x80\xe9\x9f", "€éŸ"),
    ],
)
def test_read_cstring(data, expected):
    value, end = read_cstring(data + b"trailing", 0)
    assert value == expected
    assert end == len(data)


@pytest.mark.parametrize(
    ("data", "length"),
    [
        (b"\x00", 0),
        (b"\x05hello", 5),
        (b"\xff" + struct.pack("<H", 300) + b"a" * 300, 300),
        (b"\xff\xfe\xff\x02" + "hé".encode("utf-16-le"), 2),
    ],
)
def test_skip_cstring(data, length):
    reader = MfcReader(data + b"trailing")
    assert reader.skip_cstring() == length
    assert reader.pos == len(data)


@pytest.mark.parametrize(
    "data",
    [b"\x05abc", b"\xff\xfe\xff\x02a", b"\xff\xfe\xff\xfe\xff"],
)
def test_skip_cstring_truncated_or_invalid(data):
    with pytest.raises(MfcFormatError):
        MfcReader(data).skip_cstring()


def test_skip_cstring_max_length():
    with pytest.raises(MfcFormatError, match="exceeds limit"):
        MfcReader(b"\x05hello").skip_cstring(max_length=4)


def test_read_cstring_offset():
    assert read_cstring(b"xx\x02ab", 2) == ("ab", 5)


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\x05abc",
        b"\xff\x01",
        b"\xff\x05\x00abc",
        b"\xff\xff\xff\x01\x00",
        b"\xff\xfe\xff\x02a",
        b"\xff\xfe\xff\xfe\xff",  # Wide marker twice
    ],
)
def test_read_cstring_truncated_or_invalid(data):
    with pytest.raises(MfcFormatError):
        read_cstring(data)


def test_read_cstring_max_length():
    with pytest.raises(MfcFormatError, match="exceeds limit"):
        read_cstring(b"\x05hello", max_length=4)


def test_reader_integers_and_bounds():
    reader = MfcReader(b"\x01\x02\x00\x03\x00\x00\x00\x04")
    assert reader.u8() == 1
    assert reader.u16() == 2
    assert reader.u32() == 3
    assert reader.remaining == 1
    with pytest.raises(MfcFormatError):
        reader.u16()
    assert reader.pos == 7  # Failed reads don't move the position
    reader.skip(1)
    assert reader.remaining == 0
    with pytest.raises(MfcFormatError):
        reader.read(-1)


def test_reader_end_limit():
    reader = MfcReader(b"\x01\x02\x03\x04", 1, end=3)
    assert reader.remaining == 2
    assert reader.read(2) == b"\x02\x03"
    with pytest.raises(MfcFormatError):
        reader.u8()


@pytest.mark.parametrize("pos", [-1, 5])
def test_reader_invalid_start(pos):
    with pytest.raises(MfcFormatError):
        MfcReader(b"abcd", pos)


def test_expect_class():
    reader = MfcReader(b"\xff\xff\x71\x00\x05\x00CProc\x2a\x00")
    assert reader.expect_class("CProc") == 0x71
    assert reader.u16() == 42


@pytest.mark.parametrize(
    "data",
    [
        b"\x01\x80\x00\x00",  # Class reference, not a definition
        b"\xff\xff\x80\x00\x05\x00CRung",  # Wrong class
        b"\xff\xff\x80\x00\x05\x00CPr",  # Truncated
    ],
)
def test_expect_class_mismatch(data):
    with pytest.raises(MfcFormatError):
        MfcReader(data).expect_class("CProc")


def test_find_class_defs():
    data = (
        b"\xff\xff\x80\x00\x0b\x00CProgHolder\x03\x00"
        b"\xff\xff\x80\x00\x20\x00Bogus\x01"  # Length is longer than the name
        b"junk\xff\xff\x71\x00\x04\x00CInsAB\x00"  # Name followed by letters
    )
    found = find_class_defs(data)
    assert [(c.name, c.schema) for c in found] == [("CProgHolder", 0x80), ("CIns", 0x71)]
    assert data[found[0].end : found[0].end + 2] == b"\x03\x00"
    assert data[found[1].end : found[1].end + 2] == b"AB"
    assert found[1].offset == data.index(b"\xff\xff\x71")


def test_find_class_defs_empty():
    assert find_class_defs(b"") == []
    assert find_class_defs(b"\xff\xff\x80\x00") == []


def test_find_class_defs_limit():
    data = b"\xff\xff\x80\x00\x02\x00AB" * 10
    assert len(find_class_defs(data)) == 10
    assert len(find_class_defs(data, limit=3)) == 3
    assert find_class_defs(data, limit=0) == []
