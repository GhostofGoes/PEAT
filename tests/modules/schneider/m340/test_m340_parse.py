import struct
import zlib

import pytest

from peat import DeviceData, config, datastore, utils
from peat.modules.schneider.m340 import m340_parse
from peat.modules.schneider.m340.m340 import M340


def _apx(*payloads: bytes) -> bytes:
    """Minimal APX project blob with a 0x0200 data chunk for each payload."""
    blob = b"APX" + b"\x00" * 29
    for payload in payloads:
        head = (
            b"\x02\x00\x00\x00"
            + struct.pack("<I", 7)  # number
            + b"\x00\x00"
            + struct.pack("<I", len(payload))  # length
            + b"\x00" * 10
            + b"\x03\x20\xcf\xe0"  # type
            + b"\x00" * 4
        )
        blob += head + payload
    return blob


def test_extract_chunk_multiple_zlib_streams():
    data = b"ab" + zlib.compress(b"hello world", 9) + b"cd" + zlib.compress(b"second", 6)
    assert m340_parse.extract_chunk(data) == b"abhello worldcdsecond"
    assert m340_parse.chunkify(_apx(data))[32]["data"] == b"abhello worldcdsecond"


def test_extract_chunk_zlib_bomb():
    bomb = zlib.compress(b"\x00" * (4 * 1024 * 1024), 9)  # ~4 KB -> 4 MiB
    assert len(bomb) < 10_000
    with pytest.raises(ValueError, match="inflates to more than"):
        m340_parse.extract_chunk(b"xx" + bomb, limit=1024 * 1024)


def test_chunkify_total_inflate_limit(mocker):
    """The limit applies to the total of all chunks, not to each chunk."""
    mocker.patch.object(utils, "MAX_INFLATE", 3 * 1024 * 1024, create=True)
    part = zlib.compress(b"\x00" * (1024 * 1024), 9)  # ~1 KB -> 1 MiB
    assert len(m340_parse.chunkify(_apx(part, part))) == 3
    with pytest.raises(ValueError, match="more than"):
        m340_parse.chunkify(_apx(part, part, part, part))


def test_parse_blob_decompresses_once(mocker, tmp_path):
    mocker.patch.object(datastore, "objects", [])
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path / "devices"})
    spy = mocker.spy(m340_parse, "chunkify")
    blob = _apx(b"ab" + zlib.compress(b"hello world", 9))

    dev = M340._parse_blob(blob, dev=DeviceData(id="m340-test"))
    assert dev.id == "m340-test"
    assert spy.call_count == 1


@pytest.mark.parametrize("project_name", ["../../../escape", "..\\..\\escape", "a/b", ".."])
def test_generate_openplc_project_contained(mocker, tmp_path, project_name):
    """The APX project name is used in a directory name, it must stay in the device's dir."""
    mocker.patch.object(datastore, "objects", [])
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path / "devices"})
    dev = DeviceData(ip="192.0.2.1")
    dev._runtime_options["m340"] = {"generate_openplc_project": "dev_out_dir"}
    dev.logic.formats["tc6"] = "<project/>"
    object.__setattr__(dev.logic, "name", project_name)  # as if from the APX file
    tc6 = mocker.MagicMock()
    tc6.element_empty.return_value = False
    dev._cache["tc6"] = tc6

    proj_path = M340.generate_openplc_project(dev)
    assert proj_path.parent == dev.get_out_dir()
    assert proj_path.name.startswith("openplc_project_")
    assert (proj_path / "plc.xml").read_text(encoding="utf-8") == "<project/>"
    assert not list(tmp_path.rglob("escape*"))
