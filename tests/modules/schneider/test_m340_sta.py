import io
import zipfile

import pytest

from peat import M340, datastore
from peat.api.parse_api import parsable_file_by_signature
from peat.modules.schneider.m340 import m340_parse

APX_DATA = b"APX\x00" + bytes(28) + b"\x00\x00" * 4


def make_sta(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return buf.getvalue()


@pytest.fixture
def sta_data():
    return make_sta(
        {
            "BinAppli/Station.apx": APX_DATA,
            "BinAppli/Station.apd": b"backup",
            "Station.ini": b"[Station]",
        }
    )


def test_is_sta_file(sta_data):
    assert m340_parse.is_sta_file(sta_data)
    assert m340_parse.is_sta_file(io.BytesIO(sta_data))
    assert not m340_parse.is_sta_file(make_sta({"other.txt": b"text"}))
    assert not m340_parse.is_sta_file(APX_DATA)
    assert not m340_parse.is_sta_file(b"PK\x03\x04 truncated")


def test_extract_apx_from_sta(sta_data):
    assert m340_parse.extract_apx_from_sta(sta_data) == APX_DATA
    # Case and path separators don't matter
    assert m340_parse.extract_apx_from_sta(make_sta({"binappli\\STATION.APX": b"APX1"})) == b"APX1"


def test_extract_apx_from_sta_invalid(mocker, sta_data):
    with pytest.raises(ValueError, match=r"No Station\.apx"):
        m340_parse.extract_apx_from_sta(make_sta({"other.txt": b"text"}))
    with pytest.raises(ValueError, match="Invalid STA/STU file"):
        m340_parse.extract_apx_from_sta(b"PK\x03\x04 truncated")

    mocker.patch.object(m340_parse, "MAX_STA_APX_SIZE", 4)
    with pytest.raises(ValueError, match="too large"):
        m340_parse.extract_apx_from_sta(sta_data)


def test_m340_sta_file_signature(sta_data):
    assert any(sig.matches(sta_data) for sig in M340.file_signatures)
    assert not any(sig.matches(make_sta({"other.txt": b"text"})) for sig in M340.file_signatures)


def test_m340_parse_sta(mocker, tmp_path, sta_data):
    sta_path = tmp_path / "project.sta"
    sta_path.write_bytes(sta_data)
    parse_blob = mocker.patch.object(M340, "_parse_blob", return_value=mocker.MagicMock())

    M340._parse(sta_path)

    assert parse_blob.call_args.args[0] == APX_DATA


def test_extract_apx_from_stu():
    # STU files may have a PreviousStation.apx, which must not be used
    stu_data = make_sta(
        {
            "ASPROG.db": b"db",
            "BinAppli/PreviousStation.apx": b"APX old",
            "BinAppli/Station.apx": APX_DATA,
        }
    )
    assert m340_parse.extract_apx_from_sta(stu_data) == APX_DATA

    # A STU file of a project that hasn't been built has no Station.apx
    with pytest.raises(ValueError, match="has the project been built"):
        m340_parse.extract_apx_from_sta(make_sta({"ASPROG.db": b"db"}))


def test_m340_parse_real_sta(datapath, mocker):
    mocker.patch.object(datastore, "objects", [])
    dev = M340.parse(datapath("sta/estradege_m340.sta"))

    assert dev.logic.name == "Projet"
    assert dev.logic.author == "GENEVE"
    assert dev.extra["project_file_metadata"]["unity_version"] == "V15.0"


def test_sta_file_signatures(datapath, tmp_path, sta_data):
    # Copy without the extension, so only the file contents identify the file
    real_sta = tmp_path / "real_sta"
    real_sta.write_bytes(datapath("sta/estradege_m340.sta").read_bytes())
    small_sta = tmp_path / "small_sta"
    small_sta.write_bytes(sta_data)
    other_zip = tmp_path / "other_zip"
    other_zip.write_bytes(make_sta({"other.txt": b"text"}))

    assert parsable_file_by_signature(str(real_sta), M340)
    assert parsable_file_by_signature(str(small_sta), M340)
    assert not parsable_file_by_signature(str(other_zip), M340)
