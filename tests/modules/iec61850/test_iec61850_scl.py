"""
Tests for the generic IEC 61850 SCL parse module (peat/modules/iec61850).

Uses the synthetic SCL fixture of the SCL parser tests
(tests/parsing/data_files/scl/synthetic_substation.scd); variants are derived at runtime.
"""

import hashlib
import io
import json
import zlib
from pathlib import Path

import pytest

from peat import IEC61850SCL, DeviceData, File, SELRelay, config, datastore, module_api, utils
from peat.api.parse_api import parsable_file_by_pattern, parsable_file_by_signature, parse
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
    # LF line endings whatever the checkout (CRLF on Windows): variants patch b"...\n"
    return SCD_PATH.read_bytes().replace(b"\r\n", b"\n")


@pytest.fixture
def out_config(mocker, tmp_path) -> Path:
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "SUMMARIES_DIR": tmp_path / "summaries",
            "TEMP_DIR": tmp_path / "temp",
        },
    )
    mocker.patch.object(datastore, "objects", [])
    return tmp_path


def _write(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _scd(*ieds: tuple[str, str, str]) -> bytes:
    """SCD with one IED per (name, manufacturer, IP) tuple (IP "" = no address)."""
    connected_aps = "".join(
        f'<ConnectedAP iedName="{name}" apName="AP1"><Address>'
        f'<P type="IP">{ip}</P></Address></ConnectedAP>'
        for name, _, ip in ieds
        if ip
    )
    ied_elements = "".join(
        f'<IED name="{name}" manufacturer="{manufacturer}" type="T{i}"><AccessPoint name="AP1">'
        f'<Server><Authentication/><LDevice inst="LD{i}"><LN0 lnClass="LLN0" inst=""/>'
        "</LDevice></Server></AccessPoint></IED>"
        for i, (name, manufacturer, _) in enumerate(ieds)
    )
    return (
        '<SCL xmlns="http://www.iec.ch/61850/2003/SCL"><Header id="x"/>'
        f'<Communication><SubNetwork name="S1">{connected_aps}</SubNetwork></Communication>'
        f"{ied_elements}</SCL>"
    ).encode()


def _parse_run(*paths: Path) -> list[DeviceData]:
    """Run 'peat parse -d IEC61850SCL' (parse API, including de-duplication)."""
    assert parse(list(paths), ["IEC61850SCL"]) is not None
    return list(datastore.objects)


def _output_files(run_dir: Path) -> list[Path]:
    """device-data-* files written in the run directory, relative to it."""
    return sorted(p.relative_to(run_dir) for p in run_dir.rglob("device-data-*"))


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
    assert scl_file.mime_type == "application/xml"  # not guessed from ".scd"

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
def test_scl_file_hashed_once(mocker):
    """The SCL file is hashed once per parse, not read again for every IED (R3-21)."""
    # The files record of each IED before the fix: hashed and sized from the local file
    before = File(
        local_path=SCD_PATH,
        mime_type="application/xml",
        category={"configuration", "iec61850"},
    )
    before.annotate()
    gen_hashes = mocker.spy(utils, "gen_hashes")

    assert IEC61850SCL.parse(SCD_PATH) is not None
    assert len(datastore.objects) == 2
    assert gen_hashes.call_count == 1
    assert not isinstance(gen_hashes.call_args.args[0], Path)  # the bytes already read
    sha256 = hashlib.sha256(SCD_PATH.read_bytes()).hexdigest().upper()
    for ied_dev in datastore.objects:
        (record,) = ied_dev.files
        assert record.hash.sha256 == sha256
        assert record.dict(exclude={"device"}) == before.dict(exclude={"device"})


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


def _icd(manufacturer: str, ied_type: str, ld_inst: str, ip: str = "") -> str:
    communication = (
        '<Communication><SubNetwork name="S1"><ConnectedAP iedName="TEMPLATE" apName="AP1">'
        f'<Address><P type="IP">{ip}</P></Address></ConnectedAP></SubNetwork></Communication>'
        if ip
        else ""
    )
    return (
        f'<SCL xmlns="http://www.iec.ch/61850/2003/SCL"><Header id="x"/>{communication}'
        f'<IED name="TEMPLATE" manufacturer="{manufacturer}" type="{ied_type}">'
        '<AccessPoint name="AP1"><Server><Authentication/>'
        f'<LDevice inst="{ld_inst}"><LN0 lnClass="LLN0" inst=""/></LDevice>'
        "</Server></AccessPoint></IED></SCL>"
    )


def test_parse_template_icds_are_separate_devices(out_config):
    """Every ICD names its IED TEMPLATE (IEC 61850-6): never merged by that name."""
    a = IEC61850SCL.parse(_write(out_config / "a.icd", _icd("VendorA", "RelayA", "LDA").encode()))
    b = IEC61850SCL.parse(_write(out_config / "b.icd", _icd("VendorB", "MeterB", "LDB").encode()))
    assert a is not b
    assert len(datastore.objects) == 2
    assert (a.description.vendor.name, a.description.model) == ("VendorA", "RelayA")
    assert (b.description.vendor.name, b.description.model) == ("VendorB", "MeterB")
    assert [ld.inst for ld in a.iec61850.logical_devices] == ["LDA"]
    assert [ld.inst for ld in b.iec61850.logical_devices] == ["LDB"]
    # parsing the same ICD again reuses its device
    assert IEC61850SCL.parse(out_config / "a.icd") is a
    assert len(datastore.objects) == 2
    # Each ICD device has its own name, ID and output directory
    assert (a.name, b.name) == ("TEMPLATE@a", "TEMPLATE@b")
    assert a.iec61850.ied_name == b.iec61850.ied_name == "TEMPLATE"
    assert a.get_out_dir() != b.get_out_dir()
    assert a.files[0].mime_type == "application/xml"  # not guessed from ".icd"


def test_parse_api_template_icds_with_default_ip(out_config):
    """
    ICDs with the same default IP (or the same file name in two directories) stay
    separate devices after de-duplication, with their own output directory.
    """
    paths = [
        _write(
            out_config / "in" / "a.icd", _icd("VendorA", "RelayA", "LDA", "192.168.1.100").encode()
        ),
        _write(
            out_config / "in" / "b.icd", _icd("VendorB", "MeterB", "LDB", "192.168.1.100").encode()
        ),
        _write(
            out_config / "in2" / "a.icd",
            _icd("VendorC", "RelayC", "LDC", "192.168.1.100").encode(),
        ),
    ]
    devices = _parse_run(*paths)
    assert sorted(d.description.model for d in devices) == ["MeterB", "RelayA", "RelayC"]
    assert sorted(d.name for d in devices) == ["TEMPLATE@a", "TEMPLATE@a-2", "TEMPLATE@b"]
    for d in devices:
        assert d.ip == ""  # a template's address is a placeholder, not the device's
        assert d.iec61850.access_points[0].ip == "192.168.1.100"
    written = _output_files(out_config / "devices")
    # One directory per device, no "device-data-full.json.1" files (ignored by baselining)
    assert {p.parts[0] for p in written} == {d.get_out_dir().name for d in devices}
    assert [p for p in written if p.name == "device-data-full.json"] == sorted(
        Path(d.get_out_dir().name) / "device-data-full.json" for d in devices
    )
    assert all(p.suffix in (".json", ".jsonl") for p in written), written


def test_parse_ieds_with_same_ip_are_separate_devices(out_config):
    scd = (
        '<SCL xmlns="http://www.iec.ch/61850/2003/SCL"><Header id="x"/>'
        '<Communication><SubNetwork name="S1">'
        '<ConnectedAP iedName="IED_A" apName="AP1"><Address>'
        '<P type="IP">192.168.1.100</P></Address></ConnectedAP>'
        '<ConnectedAP iedName="IED_B" apName="AP1"><Address>'
        '<P type="IP">192.168.1.100</P></Address></ConnectedAP>'
        "</SubNetwork></Communication>"
        '<IED name="IED_A" manufacturer="ACME" type="RelayA"><AccessPoint name="AP1">'
        '<Server><Authentication/><LDevice inst="LDA"><LN0 lnClass="LLN0" inst=""/>'
        "</LDevice></Server></AccessPoint></IED>"
        '<IED name="IED_B" manufacturer="OTHER" type="RelayB"><AccessPoint name="AP1">'
        '<Server><Authentication/><LDevice inst="LDB"><LN0 lnClass="LLN0" inst=""/>'
        "</LDevice></Server></AccessPoint></IED></SCL>"
    )
    IEC61850SCL.parse(_write(out_config / "same_ip.scd", scd.encode()))
    by_name = {d.iec61850.ied_name: d for d in datastore.objects}
    assert set(by_name) == {"IED_A", "IED_B"}
    assert by_name["IED_A"].description.model == "RelayA"
    assert by_name["IED_B"].description.model == "RelayB"
    assert [ld.inst for ld in by_name["IED_B"].iec61850.logical_devices] == ["LDB"]


def test_parse_api_same_ied_names_in_two_scds(out_config):
    """The IEDs of two substations with the same IED names are not merged."""
    sub_a = _write(
        out_config / "in" / "sub_a.scd",
        _scd(("IEDA", "VendorA", "10.1.1.10"), ("IEDB", "VendorA", "10.1.1.11")),
    )
    sub_b = _write(
        out_config / "in" / "sub_b.scd",
        _scd(("IEDA", "OtherVendor", "10.2.2.10"), ("IEDB", "VendorA", "10.2.2.11")),
    )
    devices = _parse_run(sub_a, sub_b)
    assert sorted((d.iec61850.ied_name, d.ip, d.description.vendor.name) for d in devices) == [
        ("IEDA", "10.1.1.10", "VendorA"),
        ("IEDA", "10.2.2.10", "OtherVendor"),
        ("IEDB", "10.1.1.11", "VendorA"),
        ("IEDB", "10.2.2.11", "VendorA"),
    ]
    for d in devices:
        assert [f.name for f in d.files] == [Path(d.iec61850.scl_file).name]
    # Parsing a file again reuses its devices
    assert len(_parse_run(sub_b)) == 4


def test_parse_api_same_ied_names_without_addresses(out_config):
    """Same IED name, no IP of its own: a distinct name keeps the output apart."""
    sub_a = _write(out_config / "in" / "sub_a.scd", _scd(("IEDA", "VendorA", "")))
    sub_b = _write(out_config / "in" / "sub_b.scd", _scd(("IEDA", "VendorB", "")))
    devices = _parse_run(sub_a, sub_b)
    assert sorted((d.name, d.description.vendor.name) for d in devices) == [
        ("IEDA", "VendorA"),
        ("IEDA@sub_b", "VendorB"),
    ]
    assert len({d.get_out_dir() for d in devices}) == 2
    assert len(_parse_run(sub_a, sub_b)) == 2


def test_parse_api_shared_and_unspecified_ips(out_config):
    """IEDs that share an IP, or have 0.0.0.0, are not merged by de-duplication."""
    shared = _write(
        out_config / "in" / "shared_ip.scd",
        _scd(("IEDA", "VendorA", "192.0.2.50"), ("IEDB", "VendorB", "192.0.2.50")),
    )
    zero = _write(
        out_config / "in" / "zero.scd",
        _scd(("IEDC", "VendorC", "0.0.0.0"), ("IEDD", "VendorD", "0.0.0.0")),
    )
    devices = {d.iec61850.ied_name: d for d in _parse_run(shared, zero)}
    assert sorted(devices) == ["IEDA", "IEDB", "IEDC", "IEDD"]
    assert devices["IEDA"].ip == "192.0.2.50"
    assert devices["IEDB"].ip == ""  # the IP is the identity of IEDA
    assert [i.ip for i in devices["IEDB"].interface] == ["192.0.2.50"]
    assert devices["IEDB"].description.vendor.name == "VendorB"
    for name in ("IEDC", "IEDD"):
        dev = devices[name]
        assert dev.ip == ""
        assert dev.interface == []
        assert "0.0.0.0" not in dev.related.ip
        assert dev.iec61850.access_points[0].ip == "0.0.0.0"  # kept in the SCL summary
    assert len({d.get_out_dir() for d in devices.values()}) == 4


def test_ied_name_cannot_escape_output_dir(out_config):
    """An IED named '..' gets an output directory inside the devices directory."""
    two = _write(out_config / "in" / "evil.scd", _scd(("REAL1", "ACME", ""), ("..", "ACME", "")))
    one = _write(out_config / "in" / "evil2.scd", _scd(("..", "ACME", "")))
    IEC61850SCL.parse(two)
    dev = IEC61850SCL.parse(one)
    devices_dir = out_config / "devices"
    assert dev.get_out_dir().parent == devices_dir
    assert (dev.get_out_dir() / "evil2.scd").is_file()  # the input file copy
    assert not (out_config / "evil2.scd").exists()
    written = _output_files(out_config)
    assert written
    assert all(p.parts[0] == "devices" and len(p.parts) == 3 for p in written), written


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
    path = _write(tmp_path / "SET_61850.CID", zlib.compress(raw, level))
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
