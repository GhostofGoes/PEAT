import inspect
import io
import struct
import time
import tracemalloc

import pytest

from peat.modules.woodward import csharp_reader
from peat.modules.woodward.csharp_reader import make_unique, serialization

# Minimal .NET Remoting Binary Format (NRBF) records, built in memory


def _i32(value: int) -> bytes:
    return struct.pack("<i", value)


def _lps(text: str) -> bytes:
    """LengthPrefixedString (only lengths < 128 are used here)."""
    data = text.encode()
    assert len(data) < 128
    return bytes([len(data)]) + data


def _header(root_id: int = 1) -> bytes:
    """SerializationHeaderRecord"""
    return b"\x00" + _i32(root_id) + _i32(-1) + _i32(1) + _i32(0)


MESSAGE_END = b"\x0b"


def _null_multiple(count: int) -> bytes:
    return b"\x0e" + _i32(count)


def _read(data: bytes):
    return serialization(io.BytesIO(data)).read_stream()


def _rectangular(lengths: list[int], binary_type: int, info: bytes = b"") -> bytes:
    """BinaryArray (rectangular) header with object id 1."""
    return (
        b"\x07"
        + _i32(1)
        + b"\x02"
        + _i32(len(lengths))
        + b"".join(_i32(n) for n in lengths)
        + bytes([binary_type])
        + info
    )


def test_read_valid_arrays():
    # ArraySinglePrimitive of Int32
    data = _header() + b"\x0f" + _i32(1) + _i32(3) + b"\x08" + _i32(7) + _i32(8) + _i32(9)
    assert list(_read(data + MESSAGE_END)) == [7, 8, 9]

    # ArraySingleObject with a run of nulls and a string
    data = _header() + b"\x10" + _i32(1) + _i32(4) + _null_multiple(3)
    data += b"\x06" + _i32(2) + _lps("x") + MESSAGE_END
    assert _read(data) == [None, None, None, "x"]


def test_read_rectangular_arrays():
    """Rectangular arrays (previously indexed with eval()/exec())."""
    # 2x2 Int32 (a Python Array is used for the last dimension)
    data = _rectangular([2, 2], 0, b"\x08") + b"".join(_i32(i) for i in range(4))
    result = _read(_header() + data + MESSAGE_END)
    assert [list(row) for row in result] == [[0, 1], [2, 3]]

    # 2x2 strings, with a MemberReference to an earlier string
    data = _rectangular([2, 2], 1)
    data += b"\x06" + _i32(2) + _lps("a") + b"\x06" + _i32(3) + _lps("b")
    data += b"\x06" + _i32(4) + _lps("c") + b"\x09" + _i32(2)  # reference to "a"
    assert _read(_header() + data + MESSAGE_END) == [["a", "b"], ["c", "a"]]

    # 2x3 objects, with a run of nulls spanning rows
    data = _rectangular([2, 3], 2) + _null_multiple(4)
    data += b"\x06" + _i32(2) + _lps("y") + b"\x0a"
    assert _read(_header() + data + MESSAGE_END) == [[None, None, None], [None, "y", None]]


def test_no_eval_or_exec():
    source = inspect.getsource(csharp_reader)
    assert "eval(" not in source
    assert "exec(" not in source


@pytest.mark.parametrize(
    "record",
    [
        # ArraySingleObject: 20 million elements
        pytest.param(b"\x10" + _i32(1) + _i32(20_000_000), id="ArraySingleObject"),
        # ArraySinglePrimitive of String (not a native array type): 20 million elements
        pytest.param(b"\x0f" + _i32(1) + _i32(20_000_000) + b"\x12", id="ArraySinglePrimitive"),
        # ArraySinglePrimitive of Int64: 20 million elements (160 MB)
        pytest.param(
            b"\x0f" + _i32(1) + _i32(20_000_000) + b"\x09", id="ArraySinglePrimitive-native"
        ),
        # BinaryArray: 3000 x 3000 objects
        pytest.param(_rectangular([3000, 3000], 2), id="BinaryArray"),
        # BinaryArray: 3000 x 3000 x 0 objects (the 0 doesn't make it empty)
        pytest.param(_rectangular([3000, 3000, 0], 2), id="BinaryArray-zero"),
        # BinaryArray: 1 x 20 million Int32
        pytest.param(_rectangular([1, 20_000_000], 0, b"\x08"), id="BinaryArray-native"),
        # BinaryArray: rank of 1000 (more than 32)
        pytest.param(_rectangular([1] * 1000, 2), id="BinaryArray-rank"),
        # LengthPrefixedString: 2 GB string
        pytest.param(b"\x06" + _i32(1) + b"\xff\xff\xff\xff\x07", id="LengthPrefixedString"),
        # ObjectNullMultiple with a negative count
        pytest.param(b"\x10" + _i32(1) + _i32(4) + _null_multiple(-2), id="ObjectNullMultiple"),
        # SystemClassWithMembers: 100 million members
        pytest.param(b"\x02" + _i32(1) + _lps("C") + _i32(100_000_000), id="ClassInfo"),
    ],
)
def test_hostile_counts_rejected_before_allocation(record):
    """A few dozen bytes declaring huge counts must not allocate huge amounts of memory."""
    data = _header() + record + MESSAGE_END
    assert len(data) < 4100

    tracemalloc.start()
    try:
        with pytest.raises(ValueError, match="invalid"):
            _read(data)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 10 * 1024 * 1024


def test_duplicate_member_names_linear():
    """make_unique() was O(n) per duplicate name: 20,000 identical names took ~36 seconds."""
    count = 20_000
    data = _header() + b"\x02" + _i32(1) + _lps("Cls") + _i32(count) + _lps("a") * count
    data += _null_multiple(count) + MESSAGE_END  # all members are null

    start = time.monotonic()
    obj = _read(data)
    assert time.monotonic() - start < 5.0
    assert obj._fields[:4] == ("a", "a2", "a3", "a4")
    assert len(set(obj._fields)) == count


def test_make_unique_same_results():
    unique, counters = {"a", "a3", "b"}, {}
    results = []
    for name in ["a", "a", "a", "b", "c", "a3"]:
        new = make_unique(name, unique, counters)
        unique.add(new)
        results.append(new)
    assert results == ["a2", "a4", "a5", "b2", "c", "a32"]
    # Without counters, the result is the same (but O(n))
    assert make_unique("a", {"a", "a2"}) == "a3"


def _nested_sparse_arrays(children: int, child_length: int) -> bytes:
    """ArraySingleObject of ``children`` ArraySingleObjects that are all nulls."""
    data = _header() + b"\x10" + _i32(1) + _i32(children)
    for k in range(children):
        data += b"\x10" + _i32(k + 2) + _i32(child_length) + _null_multiple(child_length)
    return data + MESSAGE_END


def test_nested_sparse_arrays_have_a_total_limit():
    """Each sparse array was limited, but not the total: 1.4 KB allocated 909 MiB."""
    data = _nested_sparse_arrays(100, 1_000_000)
    assert len(data) < 1500

    tracemalloc.start()
    try:
        with pytest.raises(ValueError, match="in total"):
            _read(data)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    # At most MAX_TOTAL_SPARSE_ELEMENTS pointers (128 MiB) are allocated
    assert peak < 200 * 1024 * 1024

    # A few sparse arrays are still allowed
    assert _read(_nested_sparse_arrays(3, 1000)) == [[None] * 1000] * 3


def test_repeated_class_instances_have_a_total_limit(monkeypatch):
    """ClassWithId allocates all the members of an earlier class for a few bytes."""
    monkeypatch.setattr(csharp_reader, "MAX_TOTAL_SPARSE_ELEMENTS", 100_000)
    members = 1000
    cls = b"\x02" + _i32(2) + _lps("C") + _i32(members) + _lps("a") * members
    cls += _null_multiple(members)

    def instances(count: int) -> bytes:
        data = _header() + b"\x10" + _i32(1) + _i32(count + 1) + cls
        for k in range(count):
            data += b"\x01" + _i32(k + 3) + _i32(2) + _null_multiple(members)  # ClassWithId
        return data + MESSAGE_END

    assert len(_read(instances(10))) == 11
    with pytest.raises(ValueError, match="in total"):
        _read(instances(200))
