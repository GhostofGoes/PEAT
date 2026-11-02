"""
Tests for the generic IEC 61850 SCL parse module (peat/modules/iec61850).

Uses the synthetic SCL fixture of the SCL parser tests
(tests/parsing/data_files/scl/synthetic_substation.scd); variants are derived at runtime.
"""

import io
import json
import zlib
from pathlib import Path

import pytest

from peat import IEC61850SCL, DeviceData, SELRelay, config, datastore, module_api
from peat.api.parse_api import parsable_file_by_pattern, parsable_file_by_signature
from peat.modules.iec61850.iec61850_scl import is_plain_xml_scl
from peat.parsing import scl

SCD_PATH = (
    Path(__file__).resolve().parents[2]
    / "parsing"
    / "data_files"
    / "scl"
    / "synthetic_substation.scd"
)

# A second GOOSE control block on MU1 with the same APPID and VLAN as PROT1's gcbTrip
DUPLICATE_APPID_GSE = (
    b'<ConnectedAP iedName="MU1" apName="P1">\n'
    b'        <GSE ldInst="MU" cbName="gcbMU">\n'
    b"          <Address>\n"
    b'            <P type="MAC-Address">01-0C-CD-01-00-11</P>\n'
    b'            <P type="APPID">1000</P>\n'
    b'            <P type="VLAN-ID">064</P>\n'
    b"          </Address>\n"
    b"        </GSE>\n"
)
DUPLICATE_APPID_GSECONTROL = (
    b'<GSEControl name="gcbMU" appID="MU1_G" datSet="dsSV" confRev="1"/>\n'
    b'            <SampledValueControl name="svcb1"'
)


@pytest.fixture(scope="module")
def raw() -> bytes:
    return SCD_PATH.read_bytes()


@pytest.fixture
def out_config(mocker, tmp_path) -> Path:
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "TEMP_DIR": tmp_path / "temp",
        },
    )
    mocker.patch.object(datastore, "objects", [])
    return tmp_path


def _write(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


def _claims(module, path: Path) -> bool:
    """Same test as parse_api.find_parsable_files(): pattern OR signature."""
    name = path.as_posix()
    return parsable_file_by_pattern(name, module) or parsable_file_by_signature(name, module)


def test_module_registered():
    assert module_api.get_module("IEC61850SCL") is IEC61850SCL
    for alias in ("iec61850", "scl", "scd", "cid", "icd"):
        assert "IEC61850SCL" in module_api.alias_to_names(alias)
    assert IEC61850SCL.device_type == "IED"
    assert IEC61850SCL in module_api.lookup_types(subclass_method="_parse")


@pytest.mark.usefixtures("out_config")
def test_parse_scd_one_device_per_ied(assert_glob_path):
    dev = IEC61850SCL.parse(SCD_PATH)

    # First IED is returned
    assert isinstance(dev, DeviceData)
    assert dev.name == "PROT1"
    assert dev.ip == "192.0.2.10"
    assert dev.type == "IED"
    assert dev.description.vendor.name == "ACME"
    assert dev.description.model == "PR-100"
    assert dev.description.description == "Feeder protection"
    assert dev.iec61850.ied_name == "PROT1"
    assert dev.iec61850.header.file_type == "SCD"
    assert dev.iec61850.scl_file == SCD_PATH.as_posix()
    assert sorted(s.protocol for s in dev.service) == ["goose", "mms"]
    assert len(dev.relationships) == 4
    assert dev.interface[0].name == "5A"
    scl_file = dev.files[0]
    assert scl_file.category == {"configuration", "iec61850"}
    assert scl_file.name == SCD_PATH.name
    assert scl_file.hash.sha256

    # Every other IED is in the datastore
    assert len(datastore.objects) == 2
    mu = datastore.search("MU1", "name")
    assert mu is not None
    assert mu is not dev
    assert mu.type == "IED"
    assert mu.description.model == "MU-9"
    assert mu.iec61850.ied_name == "MU1"
    assert sorted(s.protocol for s in mu.service) == ["mms", "sv"]
    assert [r.type for r in mu.relationships] == ["publishes_to"]
    assert mu.files[0].category == {"configuration", "iec61850"}

    # Both devices are exported
    for d in (dev, mu):
        out_dir = d.get_out_dir()
        assert_glob_path(out_dir, "device-data-summary.json")
        full = assert_glob_path(out_dir, "device-data-full.json")
        assert json.loads(full.read_text())["iec61850"]["ied_name"] == d.name
        assert_glob_path(out_dir, "device-data-relationships.jsonl")
    # The input file is moved to the output directory of the returned device
    assert (dev.get_out_dir() / SCD_PATH.name).is_file()


@pytest.mark.usefixtures("out_config")
def test_parse_reuses_existing_devices():
    existing = datastore.get("192.0.2.10", "ip")
    dev = IEC61850SCL.parse(SCD_PATH)
    assert dev is existing
    assert dev.name == "PROT1"
    # Parsing the same file again does not create new devices or duplicates
    again = IEC61850SCL.parse(SCD_PATH)
    assert again is dev
    assert len(datastore.objects) == 2
    assert len(dev.relationships) == 4
    assert len(datastore.search("MU1", "name").relationships) == 1


@pytest.mark.usefixtures("out_config")
def test_parse_into_given_device():
    given = DeviceData(id="my-relay")
    dev = IEC61850SCL.parse(SCD_PATH, dev=given)
    assert dev is given
    assert dev.iec61850.ied_name == "PROT1"
    assert datastore.search("MU1", "name") is not None


def test_parse_plain_xml_cid_and_raw_bytes(out_config, raw):
    cid = _write(out_config / "PROT1.cid", raw)
    dev = IEC61850SCL.parse(cid)
    assert dev.iec61850.header.file_type == "CID"
    datastore.objects.clear()
    dev = IEC61850SCL.parse(raw)  # raw data (e.g. stdin): claimed by the signature
    assert dev.name == "PROT1"
    assert dev.iec61850.header.file_type == "SCD"  # signature default_filename iec61850.scd


def test_cross_ied_duplicate_appid_alerts(out_config, raw):
    data = raw.replace(b'<ConnectedAP iedName="MU1" apName="P1">\n', DUPLICATE_APPID_GSE, 1)
    data = data.replace(b'<SampledValueControl name="svcb1"', DUPLICATE_APPID_GSECONTROL, 1)
    assert data.count(b"gcbMU") == 2
    dev = IEC61850SCL.parse(_write(out_config / "dup.scd", data))
    mu = datastore.search("MU1", "name")
    for d in (dev, mu):
        alerts = [e for e in d.event if e.action == "scl-validation"]
        assert len(alerts) == 1, d.name
        assert "PROT1/gcbTrip" in alerts[0].reason
        assert "MU1/gcbMU" in alerts[0].reason
        assert "alert" in alerts[0].kind
        assert alerts[0].extra["ied_names"] == ["MU1", "PROT1"]


def test_malformed_value_keeps_both_ieds(out_config, raw):
    data = raw.replace(b'<P type="APPID">1000</P>', b'<P type="APPID">10000</P>', 1)
    dev = IEC61850SCL.parse(_write(out_config / "bad.scd", data))
    assert dev.name == "PROT1"
    assert dev.iec61850.extra["invalid_addresses"][0]["parameter"] == "APPID"
    assert [e.reason for e in dev.event] == ["invalid APPID '10000' (PRO/gcbTrip)"]
    assert datastore.search("MU1", "name") is not None


@pytest.mark.usefixtures("out_config")
def test_one_bad_ied_does_not_lose_the_others(mocker):
    real_apply = scl.apply_iec61850

    def failing_apply(dev, ied, **kwargs):
        if ied.ied_name == "PROT1":
            raise ValueError("boom")
        return real_apply(dev, ied, **kwargs)

    mocker.patch.object(scl, "apply_iec61850", side_effect=failing_apply)
    dev = IEC61850SCL.parse(SCD_PATH)
    assert dev is not None
    assert dev.iec61850.ied_name == "MU1"
    # The half-filled new PROT1 device is not left in the datastore
    assert datastore.objects == [dev]


def test_not_scl(out_config):
    assert IEC61850SCL.parse(_write(out_config / "other.scd", b"<NotSCL/>")) is None
    assert IEC61850SCL.parse(_write(out_config / "text.scd", b"plain text")) is None
    assert datastore.objects == []


def test_scl_without_ieds(out_config):
    ssd = _write(
        out_config / "spec.ssd",
        b'<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B">'
        b'<Header id="SSD"/><Substation name="SUB1"/></SCL>',
    )
    assert IEC61850SCL.parse(ssd) is None


# --------------------------------------------------------------------------- #
# File claiming (R26, critique OT-19)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("ext", ["scd", "SCD", "icd", "iid", "ssd", "sed"])
def test_claims_scl_extensions(tmp_path, ext):
    path = _write(tmp_path / f"file.{ext}", b"not even xml")
    assert parsable_file_by_pattern(path.as_posix(), IEC61850SCL)


def test_plain_xml_scl_claimed_by_signature(tmp_path, raw):
    for name in ("PROT1.cid", "PROT1.CID", "export.xml", "noext"):
        path = _write(tmp_path / name, raw)
        assert not parsable_file_by_pattern(path.as_posix(), IEC61850SCL), name
        assert parsable_file_by_signature(path.as_posix(), IEC61850SCL), name
    # Other XML documents are not claimed (only the root element is checked)
    other = _write(tmp_path / "other.xml", b"<RSLogix5000Content><SCL/></RSLogix5000Content>")
    assert not _claims(IEC61850SCL, other)
    no_ns = _write(tmp_path / "nons.xml", b"<SCL><IED name='X'/></SCL>")
    assert not _claims(IEC61850SCL, no_ns)
    assert not _claims(IEC61850SCL, _write(tmp_path / "binary.bin", bytes(range(256))))
    assert not _claims(IEC61850SCL, _write(tmp_path / "empty.xml", b""))


@pytest.mark.parametrize("level", [1, 6, 9])  # zlib headers 7801, 789C, 78DA
def test_zlib_cid_claimed_only_by_selrelay(tmp_path, raw, level):
    # SELRelay's CID signature also looks for the text "IEC 61850" in the content
    data = raw.replace(b'toolID="PEAT synthetic fixture"', b'toolID="PEAT IEC 61850 fixture"')
    path = _write(tmp_path / "SET_61850.CID", zlib.compress(data, level))
    assert not _claims(IEC61850SCL, path)
    assert _claims(SELRelay, path)
    assert scl.is_scl(path)


def test_plain_xml_cid_not_claimed_by_selrelay(tmp_path, raw):
    path = _write(tmp_path / "PROT1.cid", raw)
    assert _claims(IEC61850SCL, path)
    assert not _claims(SELRelay, path)


def test_is_plain_xml_scl(raw):
    assert is_plain_xml_scl(io.BytesIO(raw)) is True
    assert is_plain_xml_scl(io.BytesIO(zlib.compress(raw))) is False
    assert is_plain_xml_scl(io.BytesIO(b"<x/>")) is False
    assert is_plain_xml_scl(io.BytesIO(b"")) is False
