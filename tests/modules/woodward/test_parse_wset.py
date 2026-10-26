import json
import struct

from peat import config, datastore
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
