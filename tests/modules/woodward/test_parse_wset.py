import io
import json
import struct

import pytest

from peat import config, datastore
from peat.modules.woodward.csharp_reader import JSONEncoder, read_stream
from peat.modules.woodward.easygen_3500xt import Easygen3500XT
from peat.modules.woodward.parse_wset import parse_wset


def _i32(value: int) -> bytes:
    return struct.pack("<i", value)


def _wset() -> bytes:
    """A .wset file: 10-byte Woodward header followed by two NRBF streams."""
    header = b"\x00" + _i32(1) + _i32(-1) + _i32(1) + _i32(0)
    first = header + b"\x06" + _i32(1) + b"\x05hello" + b"\x0b"
    second = header + b"\x0f" + _i32(1) + _i32(2) + b"\x08" + _i32(4) + _i32(2) + b"\x0b"
    return b"WOODWARD\x00\x00" + first + second


def test_parse_wset_does_not_write_to_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    result = parse_wset(_wset())
    assert {k: json.loads(v) for k, v in result.items()} == {0: "hello", 1: [4, 2]}

    wset = tmp_path / "input" / "settings.wset"
    wset.parent.mkdir()
    wset.write_bytes(_wset())
    assert parse_wset(wset) == result

    assert sorted(p.name for p in tmp_path.iterdir()) == ["input"]  # no "out_N" files


def test_easygen_parse_wset_writes_to_device_dir(mocker, tmp_path, monkeypatch):
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    mocker.patch.object(datastore, "objects", [])
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path / "devices"})
    wset = tmp_path / "settings.wset"
    wset.write_bytes(_wset())

    dev = Easygen3500XT._parse(wset)

    saved = json.loads((dev.get_out_dir() / "parsed-config.json").read_text(encoding="utf-8"))
    assert json.loads(saved["0"]) == "hello"
    assert not list(cwd.iterdir())


def _nrbf_stream(root_id: int, records: bytes) -> bytes:
    return b"\x00" + _i32(root_id) + _i32(-1) + _i32(1) + _i32(0) + records + b"\x0b"


def test_parse_wset_references_expanded_once():
    """Each level of 4 MemberReferences to the level below multiplied the JSON by 4.

    334 bytes produced 165 MB of JSON (and 14 bytes more, 40 GB).
    """
    levels, fanout = 10, 4
    records = b"\x10" + _i32(2) + _i32(1) + b"\x06" + _i32(1000) + b"\x01x"  # id 2: ["x"]
    for k in range(1, levels + 1):
        records += b"\x10" + _i32(k + 2) + _i32(fanout) + (b"\x09" + _i32(k + 1)) * fanout
    data = b"\x00" * 10 + _nrbf_stream(levels + 2, records)
    assert len(data) < 400

    result = parse_wset(data)
    assert len(result[0]) < 10_000
    top = json.loads(result[0])
    assert top[1] == {"$ref": "$[0]"}
    assert top[0][1] == {"$ref": "$[0][0]"}
    assert top[0][0][0][0][0][0][0][0][0][0] == ["x"]


def test_parse_wset_json_size_limited():
    """A long string referenced many times is still limited by the output size."""
    text = "x" * 100
    records = b"\x10" + _i32(1) + _i32(1001)
    records += b"\x06" + _i32(2) + bytes([len(text)]) + text.encode()
    records += (b"\x09" + _i32(2)) * 1000
    stream = _nrbf_stream(1, records)

    obj = read_stream(io.BytesIO(stream))
    assert len(JSONEncoder().encode(obj)) > 100_000
    with pytest.raises(ValueError, match="larger than"):
        JSONEncoder(max_size=50_000).encode(obj)
    with pytest.raises(ValueError, match="larger than"):
        json.dumps(obj, cls=JSONEncoder, max_size=50_000)


def test_json_encoder_shared_and_circular_references():
    shared = ["a", "b"]
    obj = [shared, {"k": shared}, []]
    obj.append(obj)
    assert json.loads(JSONEncoder().encode(obj)) == [
        ["a", "b"],
        {"k": {"$ref": "$[0]"}},
        [],
        {"$ref": "$"},
    ]
