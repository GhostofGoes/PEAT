"""
Tests for the IEC 61850-6 SCL parser (peat/parsing/scl.py).

The fixture ``data_files/scl/synthetic_substation.scd`` is a synthetic SCL file
authored for PEAT (two IEDs: PROT1 publishing GOOSE, MU1 publishing signed SV).
Other variants (single-IED CID, zlib-compressed CID, malformed values, XXE) are
derived from it at runtime.
"""

import copy
import zlib
from pathlib import Path

import pytest
from lxml import etree

from peat import DeviceData, ParseError
from peat.data.models import IEC61850, IEC61850Address, IEC61850Publication, Interface, Vlan
from peat.parsing import scl

SCD_PATH = Path(__file__).resolve().parent / "data_files" / "scl" / "synthetic_substation.scd"


@pytest.fixture(scope="module")
def raw() -> bytes:
    return SCD_PATH.read_bytes()


@pytest.fixture
def root(raw):
    return scl.load_scl(raw)


@pytest.fixture
def all_ieds(root) -> dict[str, IEC61850]:
    return scl.parse_scl_all(root, "SCD")


def _variant(raw: bytes, old: bytes, new: bytes) -> bytes:
    assert old in raw, old
    return raw.replace(old, new, 1)


def _applied(ied: IEC61850, **kwargs) -> DeviceData:
    dev = DeviceData(name=ied.ied_name)
    scl.apply_iec61850(dev, ied, **kwargs)
    dev.export()  # runs annotate() on everything
    return dev


def _rels(dev: DeviceData, rtype: str, protocol: str | None = None) -> list:
    return [
        r
        for r in dev.relationships
        if r.type == rtype and (protocol is None or r.protocol == protocol)
    ]


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #
def test_load_scl_sources(raw, tmp_path):
    assert scl.list_ieds(scl.load_scl(raw)) == ["PROT1", "MU1"]
    assert scl.list_ieds(scl.load_scl(raw.decode("utf-8"))) == ["PROT1", "MU1"]
    path = tmp_path / "substation.scd"
    path.write_bytes(raw)
    assert scl.list_ieds(scl.load_scl(path)) == ["PROT1", "MU1"]
    # UTF-8 BOM and zlib (SEL SET_61850.CID) wrapping
    assert scl.list_ieds(scl.load_scl(b"\xef\xbb\xbf" + raw)) == ["PROT1", "MU1"]
    for level in (1, 6, 9):  # zlib headers 7801, 789C, 78DA
        compressed = zlib.compress(raw, level)
        assert compressed[:1] == b"\x78"
        assert scl.decode_scl_bytes(compressed) == raw
        assert scl.list_ieds(scl.load_scl(compressed)) == ["PROT1", "MU1"]


def test_is_scl(raw, tmp_path):
    assert scl.is_scl(raw)
    assert scl.is_scl(zlib.compress(raw))
    assert scl.is_scl(raw.decode("utf-8"))
    path = tmp_path / "x.cid"
    path.write_bytes(raw)
    assert scl.is_scl(path)
    assert not scl.is_scl(b"<x/>")
    assert not scl.is_scl(b"")
    assert not scl.is_scl(b"not xml at all")
    assert not scl.is_scl(b"x\x9c garbage that looks like zlib")
    assert not scl.is_scl(tmp_path / "does_not_exist.scd")


def test_load_scl_rejects_non_scl():
    with pytest.raises(ParseError, match="expected 'SCL'"):
        scl.load_scl(b"<RSLogix5000Content/>")
    with pytest.raises(ParseError, match="invalid SCL XML"):
        scl.load_scl(b"<SCL><unclosed></SCL>")


@pytest.mark.parametrize(
    "doc",
    [
        # external entity in an attribute
        b'<?xml version="1.0"?><!DOCTYPE SCL [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
        b'<SCL xmlns="http://www.iec.ch/61850/2003/SCL"><Header id="&x;"/></SCL>',
        # external entity in element text
        b'<?xml version="1.0"?><!DOCTYPE SCL [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
        b'<SCL xmlns="http://www.iec.ch/61850/2003/SCL"><Header id="h">&x;</Header></SCL>',
        # entity expansion ("billion laughs")
        b'<?xml version="1.0"?><!DOCTYPE SCL [<!ENTITY a "aaaaaaaaaa">'
        b'<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;">]>'
        b'<SCL xmlns="http://www.iec.ch/61850/2003/SCL"><Header id="h">&c;</Header></SCL>',
        # external DTD
        b'<?xml version="1.0"?><!DOCTYPE SCL SYSTEM "http://192.0.2.1/scl.dtd">'
        b'<SCL xmlns="http://www.iec.ch/61850/2003/SCL"><Header id="h"/></SCL>',
    ],
)
def test_load_scl_xxe_rejected(doc):
    with pytest.raises(ParseError):
        scl.load_scl(doc)


def test_load_scl_rejects_huge_decompression(monkeypatch, raw):
    monkeypatch.setattr(scl, "MAX_DECOMPRESSED_SIZE", 100)
    with pytest.raises(ParseError, match="larger than"):
        scl.load_scl(zlib.compress(raw))


def test_file_type_from_name():
    assert scl.file_type_from_name("SET_61850.CID") == "CID"
    assert scl.file_type_from_name("substation.scd") == "SCD"
    assert scl.file_type_from_name(Path("/a/b/relay.icd")) == "ICD"
    for ext in ("iid", "ssd", "sed"):
        assert scl.file_type_from_name(f"x.{ext}") == ext.upper()
    assert scl.file_type_from_name("config.xml") == ""
    assert scl.file_type_from_name("noext") == ""


# --------------------------------------------------------------------------- #
# Parsing (DESIGN.md 7.5 assertions)
# --------------------------------------------------------------------------- #
def test_parse_prot1_publication(all_ieds):
    g = all_ieds["PROT1"].publications[0]
    assert g.type == "GOOSE"
    assert g.reference == "PROT1PRO/LLN0$GO$gcbTrip"
    assert g.id == "PROT1_TRIP"
    assert g.address.appid == 0x1000  # APPID is hex
    assert g.address.vlan.id == "100"  # VLAN-ID "064" is hex
    assert g.address.vlan.priority == 4
    assert g.address.vlan.tagged is True
    assert g.address.mac == "01:0C:CD:01:00:10"
    assert g.min_time == 4
    assert g.max_time == 1000
    assert g.dataset == "dsTrip"
    assert g.conf_rev == 2
    assert g.dataset_members_count == 2
    assert g.security == "None"
    assert g.subscribers == ["MU1"]


def test_parse_prot1_access_point(all_ieds):
    ap = all_ieds["PROT1"].access_points[0]
    assert ap.name == "S1"
    assert ap.server is True
    assert ap.subnetwork == "StationBus"
    assert ap.subnetwork_type == "8-MMS"
    assert ap.ip == "192.0.2.10"
    assert ap.subnet_mask == "255.255.255.0"
    assert ap.gateway == "192.0.2.1"
    assert ap.authentication == {"none"}  # empty <Authentication/> (XSD default)
    assert ap.redundancy == "prp"
    assert ap.physical_ports == ["5A", "5B"]
    assert ap.mms_port == 102
    assert ap.osi == {"OSI-TSEL": "0001", "OSI-PSEL": "00000001"}


def test_parse_prot1_report_control(all_ieds):
    rc = all_ieds["PROT1"].report_controls[0]
    assert rc.name == "urcbMeas"
    assert rc.ln == "LLN0"
    assert rc.ld_inst == "PRO"
    assert rc.report_id == "PROT1/Meas"
    assert rc.dataset == "dsMeas"
    assert rc.conf_rev == 1
    assert rc.buffered is False
    assert rc.buffer_time == 50
    assert rc.integrity_period == 1000
    assert rc.trigger_options == {"dchg", "period", "gi"}  # gi defaults to true
    assert rc.max_clients == 2
    assert rc.clients == ["HMI1"]


def test_parse_prot1_subscriptions(all_ieds):
    subs = {
        (s.service_type, s.publisher_ied, s.control_block): s
        for s in all_ieds["PROT1"].subscriptions
    }
    assert len(subs) == 2
    sv = subs[("SMV", "MU1", "svcb1")]
    assert sv.ext_ref_count == 2
    assert sv.publisher_ld_inst == "MU"
    assert sv.address.appid == 0x4000
    assert sv.address.vlan.id == "100"
    assert sv.address.mac == "01:0C:CD:04:00:01"
    assert sv.reference == "MU1MU/LLN0$MS$svcb1"
    # Edition-1 style ExtRef (no serviceType/srcCBName): nothing is inferred
    ed1 = subs[("", "BUS1", "")]
    assert ed1.reference == ""
    assert ed1.ext_ref_count == 1
    assert ed1.publisher_ld_inst == "PRO"
    assert ed1.address == IEC61850Address()


def test_parse_prot1_ied(all_ieds):
    p = all_ieds["PROT1"]
    assert p.ied_name == "PROT1"
    assert p.description == "Feeder protection"
    assert p.manufacturer == "ACME"
    assert p.ied_type == "PR-100"
    assert p.config_version == "2.1"
    assert p.original_scl_version == "2007B4"
    assert p.header.file_type == "SCD"
    assert p.header.scl_version == "2007B4"
    assert p.header.id == "PEAT_TEST_SUB"
    assert p.header.version == "3"
    assert p.header.revision == "7"
    assert p.header.tool_id == "PEAT synthetic fixture"
    assert p.header.name_structure == "IEDName"
    assert [h.what for h in p.header.history] == ["Added GOOSE trip", "Changed VLAN"]
    assert p.header.history[1].who == "engineer-b"
    assert p.setting_groups == 6
    assert p.active_setting_group == 1
    assert p.datasets_count == 2
    assert p.functional_locations == ["SUB1/E1/Q01"]
    assert p.capabilities["GOOSE"] == {"max": "8"}
    assert p.capabilities["ClientServices"] == {"goose": "true", "sv": "true"}
    assert p.capabilities["FileHandling"] == {}
    ld = p.logical_devices[0]
    assert ld.inst == "PRO"
    assert ld.name == "PROT1PRO"
    assert ld.access_point == "S1"
    assert ld.description == "Protection"
    assert ld.logical_nodes == ["LLN0", "LPHD1", "PTOC1", "XCBR1"]
    assert "invalid_addresses" not in p.extra


def test_parse_mu1(all_ieds):
    mu = all_ieds["MU1"]
    pub = mu.publications[0]
    assert pub.type == "SV"
    assert pub.reference == "MU1MU/LLN0$MS$svcb1"
    assert pub.id == "MU1_SV1"
    assert pub.security == "Signature"
    assert pub.smp_rate == 80
    assert pub.nof_asdu == 1
    assert pub.dataset_members_count == 2
    assert pub.address.appid == 0x4000
    assert pub.address.vlan.id == "100"
    assert pub.subscribers == ["PROT1"]
    ap = mu.access_points[0]
    assert ap.authentication == {"password"}
    assert ap.ip == ""  # process-bus AP without an IP address
    assert ap.subnetwork == "ProcessBus"
    assert ap.mms_port == 102
    assert mu.functional_locations == ["SUB1/E1/Q02"]
    assert mu.subscriptions == []
    assert mu.report_controls == []
    assert mu.header.scl_version == "2007B4"
    assert mu.original_scl_version == ""


def test_parse_scl_selection(root):
    assert scl.parse_scl(root, "MU1").ied_name == "MU1"
    assert scl.parse_scl(root).ied_name == "PROT1"  # first IED (with a warning)
    assert scl.parse_scl(root, file_type="cid").header.file_type == "CID"
    assert scl.parse_scl(root, file_type="xml").header.file_type == ""
    with pytest.raises(ParseError, match="not found"):
        scl.parse_scl(root, "NOPE")
    empty = scl.load_scl(b'<SCL xmlns="http://www.iec.ch/61850/2003/SCL"><Header id="x"/></SCL>')
    with pytest.raises(ParseError, match="no IED"):
        scl.parse_scl(empty)
    assert scl.parse_scl_all(empty) == {}
    assert scl.list_ieds(empty) == []


def test_single_ied_cid(root):
    """A CID of PROT1 alone: references of publishers are built from the ExtRef."""
    cid_root = copy.deepcopy(root)
    for ied_el in [e for e in cid_root if etree.QName(e).localname == "IED"]:
        if ied_el.get("name") != "PROT1":
            cid_root.remove(ied_el)
    cid = scl.load_scl(etree.tostring(cid_root, xml_declaration=True, encoding="UTF-8"))
    assert scl.list_ieds(cid) == ["PROT1"]
    ied = scl.parse_scl(cid, file_type=scl.file_type_from_name("PROT1.cid"))
    assert ied.ied_name == "PROT1"
    assert ied.header.file_type == "CID"
    sv = next(s for s in ied.subscriptions if s.service_type == "SMV")
    # MU1 is not in the file: the reference is built best effort from the ExtRef
    assert sv.reference == "MU1MU/LLN0$MS$svcb1"
    # The Communication section still has MU1's SMV address
    assert sv.address.appid == 0x4000


def test_parse_namespace_less_edition1():
    doc = b"""<SCL>
      <Header id="ed1"/>
      <IED name="OLD1" manufacturer="ACME">
        <AccessPoint name="AP1"><Server><Authentication none="true"/>
          <LDevice inst="LD0" ldName="CUSTOMLD"><LN0 lnClass="LLN0" inst="">
            <GSEControl name="gcb" type="GSSE" appID="OLD"/>
            <SampledValueControl name="usv" smvID="X" multicast="false"/>
            <ReportControl name="brcb" buffered="true"><RptEnabled/></ReportControl>
          </LN0></LDevice>
        </Server></AccessPoint>
      </IED></SCL>"""
    ied = scl.parse_scl(scl.load_scl(doc))
    assert ied.header.scl_version == "2003"  # no version attributes: Edition 1
    refs = {p.name: p.reference for p in ied.publications}
    assert refs == {"gcb": "CUSTOMLD/LLN0$GS$gcb", "usv": "CUSTOMLD/LLN0$US$usv"}
    assert ied.publications[0].type == "GSSE"
    rc = ied.report_controls[0]
    assert rc.buffered is True
    assert rc.max_clients == 1
    assert rc.clients == []
    assert rc.trigger_options == {"gi"}
    assert ied.access_points[0].ip == ""
    assert ied.access_points[0].mms_port == 102
    dev = _applied(ied)
    assert dev.interface == []  # no address -> no interface


def test_parse_malformed_numbers_do_not_abort(raw):
    bad = _variant(raw, b'confRev="2"', b'confRev="-1"')
    bad = _variant(bad, b'smpRate="80"', b'smpRate="eighty"')
    bad = _variant(bad, b'<GSEControl name="gcbTrip"', b'<GSEControl type="FOO" name="gcbTrip"')
    bad = _variant(bad, b'<MinTime unit="s" multiplier="m">4', b'<MinTime unit="s">-4')
    bad = _variant(bad, b'<RptEnabled max="2">', b'<RptEnabled max="many">')
    ieds = scl.parse_scl_all(scl.load_scl(bad), "SCD")
    g = ieds["PROT1"].publications[0]
    assert g.conf_rev is None
    assert g.min_time is None
    assert g.type == "GOOSE"
    assert ieds["PROT1"].report_controls[0].max_clients == 1
    assert ieds["MU1"].publications[0].smp_rate is None


def test_parse_out_of_range_numbers_are_dropped(raw):
    """xs:unsignedInt values above 2^32-1 would be rejected by the ES long mapping."""
    big = b"99999999999999999999"
    bad = _variant(raw, b'confRev="2"', b'confRev="' + big + b'"')
    bad = _variant(
        bad, b'<MaxTime unit="s" multiplier="m">1000', b'<MaxTime unit="s" multiplier="m">1e300'
    )
    ieds = scl.parse_scl_all(scl.load_scl(bad), "SCD")
    g = ieds["PROT1"].publications[0]
    assert g.conf_rev is None
    assert g.max_time is None
    assert g.min_time == 4
    assert scl._uint(str(scl.UINT32_MAX)) == scl.UINT32_MAX
    assert scl._uint(str(scl.UINT32_MAX + 1)) is None


# --------------------------------------------------------------------------- #
# Robustness: malformed address values (ECS-4 / ECS-9)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("parameter", "old", "value"),
    [
        ("VLAN-ID", "064", "1064"),
        ("VLAN-PRIORITY", "4", "9"),
        ("APPID", "1000", "10000"),
        ("MAC-Address", "01-0C-CD-01-00-10", "010CCD01001"),
        ("IP", "192.0.2.10", "192.0.2.300"),
        ("IP-SUBNET", "255.255.255.0", "x"),
        ("IP-GATEWAY", "192.0.2.1", "1.2.3"),
    ],
)
def test_malformed_address_values(raw, parameter, old, value):
    p_old = f'<P type="{parameter}">{old}</P>'.encode()
    p_new = f'<P type="{parameter}">{value}</P>'.encode()
    all_bad = scl.parse_scl_all(scl.load_scl(_variant(raw, p_old, p_new)), "SCD")
    assert set(all_bad) == {"PROT1", "MU1"}  # never loses the IED or the SCD
    bad = all_bad["PROT1"]
    problems = bad.extra.get("invalid_addresses")
    assert len(problems) == 1
    assert problems[0]["parameter"] == parameter
    assert problems[0]["value"] == value
    assert problems[0]["error"]
    assert (
        "control_block"
        if parameter in ("VLAN-ID", "VLAN-PRIORITY", "APPID", "MAC-Address")
        else "access_point"
    ) in problems[0]
    assert len(bad.publications) == 1
    assert bad.publications[0].reference
    evs = scl.scl_configuration_events(bad)
    invalid = [e for e in evs if e.reason.startswith(f"invalid {parameter} ")]
    assert invalid
    ev = invalid[0]
    assert ev.action == "scl-validation"
    assert ev.kind == {"alert"}
    assert ev.category == {"configuration"}
    assert ev.type == {"info"}
    assert ev.dataset == "scl"
    assert ev.extra["ied_names"] == ["PROT1"]
    # the device still gets everything else
    dev = _applied(bad)
    assert any(e.reason == ev.reason for e in dev.event)
    assert _rels(dev, "publishes_to", "goose")


def test_malformed_vlan_keeps_other_values(raw):
    bad = scl.parse_scl(
        scl.load_scl(_variant(raw, b'<P type="VLAN-ID">064</P>', b'<P type="VLAN-ID">zz</P>')),
        "PROT1",
    )
    addr = bad.publications[0].address
    assert addr.vlan.id == ""
    assert addr.vlan.priority == 4  # priority still read
    assert addr.appid == 0x1000
    assert addr.mac == "01:0C:CD:01:00:10"


def test_mms_port(raw):
    with_port = _variant(
        raw,
        b'<P type="IP">192.0.2.10</P>',
        b'<P type="IP">192.0.2.10</P><P type="MMS-Port">3102</P>',
    )
    ied = scl.parse_scl(scl.load_scl(with_port), "PROT1")
    assert ied.access_points[0].mms_port == 3102
    dev = _applied(ied)
    mms = next(s for s in dev.service if s.protocol == "mms")
    assert mms.port == 3102
    assert _rels(dev, "reports_to")[0].local.port == 3102

    bad_port = _variant(
        raw,
        b'<P type="IP">192.0.2.10</P>',
        b'<P type="IP">192.0.2.10</P><P type="MMS-Port">70000</P>',
    )
    ied = scl.parse_scl(scl.load_scl(bad_port), "PROT1")
    assert ied.access_points[0].mms_port == 102
    assert ied.extra["invalid_addresses"][0]["parameter"] == "MMS-Port"


def test_zero_gateway_ignored(raw):
    g0 = scl.parse_scl(
        scl.load_scl(
            _variant(
                raw,
                b'<P type="IP-GATEWAY">192.0.2.1</P>',
                b'<P type="IP-GATEWAY">0.0.0.0</P>',
            )
        ),
        "PROT1",
    )
    assert g0.access_points[0].gateway == "0.0.0.0"  # kept in the SCL summary
    dev = _applied(g0)
    assert "0.0.0.0" not in dev.related.ip
    assert dev.interface[0].gateway == ""


def test_unspecified_ip_is_not_an_interface(raw):
    zero = scl.parse_scl(
        scl.load_scl(_variant(raw, b'<P type="IP">192.0.2.10</P>', b'<P type="IP">0.0.0.0</P>')),
        "PROT1",
    )
    assert zero.access_points[0].ip == "0.0.0.0"  # kept in the SCL summary
    dev = _applied(zero)
    assert dev.interface == []
    assert dev.ip == ""
    assert "0.0.0.0" not in dev.related.ip


# --------------------------------------------------------------------------- #
# Configuration alerts
# --------------------------------------------------------------------------- #
def test_duplicate_appid_in_ied(all_ieds):
    dup = all_ieds["PROT1"].copy(deep=True)
    dup.publications.append(dup.publications[0].copy(update={"name": "gcbOther"}, deep=True))
    evs = scl.scl_configuration_events(dup)
    assert [e.reason for e in evs] == ["duplicate GOOSE APPID 0x1000 (gcbTrip, gcbOther)"]
    assert evs[0].extra["control_blocks"] == ["gcbTrip", "gcbOther"]
    assert evs[0].message == evs[0].reason


def test_appid_out_of_range():
    ied = IEC61850(
        ied_name="X",
        publications=[
            IEC61850Publication(type="GOOSE", name="g", address=IEC61850Address(appid=0x4001)),
            IEC61850Publication(type="SV", name="s", address=IEC61850Address(appid=0x0001)),
            IEC61850Publication(type="SV", name="ok", address=IEC61850Address(appid=0x4002)),
        ],
    )
    reasons = sorted(e.reason for e in scl.scl_configuration_events(ied))
    assert reasons == [
        "GOOSE APPID 0x4001 of g outside 0x0000-0x3FFF",
        "SV APPID 0x0001 of s outside 0x4000-0x7FFF",
    ]


def test_no_alerts_for_valid_fixture(all_ieds):
    assert scl.scl_configuration_events(all_ieds["PROT1"]) == []
    assert scl.scl_configuration_events(all_ieds["MU1"]) == []
    assert scl.scl_cross_ied_events(all_ieds) == []


def test_cross_ied_duplicates(all_ieds):
    cross_mu = all_ieds["MU1"].copy(deep=True)
    cross_mu.publications[0].type = "GOOSE"
    cross_mu.publications[0].address.appid = 0x1000
    xevs = scl.scl_cross_ied_events({"PROT1": all_ieds["PROT1"], "MU1": cross_mu})
    assert len(xevs) == 1
    assert "PROT1/gcbTrip" in xevs[0].reason
    assert "MU1/svcb1" in xevs[0].reason
    assert "VLAN 100" in xevs[0].reason
    assert xevs[0].extra["ied_names"] == ["MU1", "PROT1"]
    # Same APPID on another VLAN is not a conflict
    cross_mu.publications[0].address.vlan = Vlan(id="200")
    assert scl.scl_cross_ied_events({"PROT1": all_ieds["PROT1"], "MU1": cross_mu}) == []


# --------------------------------------------------------------------------- #
# apply_iec61850 (DESIGN.md 7.3)
# --------------------------------------------------------------------------- #
def test_apply_prot1(all_ieds):
    dev = _applied(all_ieds["PROT1"])
    assert dev.iec61850.ied_name == "PROT1"
    types = sorted((r.type, r.protocol) for r in dev.relationships)
    assert types == [
        ("publishes_to", "goose"),
        ("reports_to", "mms"),
        ("subscribes_to", ""),
        ("subscribes_to", "sv"),
    ]
    assert sorted(s.protocol for s in dev.service) == ["goose", "mms"]
    iface = dev.interface[0]
    assert iface.name == "5A"
    assert iface.ip == "192.0.2.10"
    assert iface.type == "ethernet"
    assert iface.subnet_mask == "255.255.255.0"
    assert iface.gateway == "192.0.2.1"
    assert iface.application == "iec61850"
    assert dev.ip == "192.0.2.10"
    assert dev.related.vlans == {"100"}
    assert {"HMI1", "MU1", "BUS1"} <= dev.related.hosts
    assert "192.0.2.1" in dev.related.ip
    # multicast MACs are never in related.mac (R13)
    assert "01:0C:CD:01:00:10" not in dev.related.mac
    assert "01:0C:CD:04:00:01" not in dev.related.mac
    assert dev.event == []

    pub = _rels(dev, "publishes_to")[0]
    assert pub.direction == "egress"
    assert pub.medium == "ethernet"
    assert pub.enabled is True
    assert pub.local.role == "publisher"
    assert pub.local.protocol_address == "0x1000"
    assert pub.remote.mac == "01:0C:CD:01:00:10"
    assert pub.remote.role == "subscriber"
    assert pub.vlan.id == "100"
    assert pub.reference == "PROT1PRO/LLN0$GO$gcbTrip"
    assert pub.evidence == {"scl"}
    assert pub.id
    assert pub.extra == {
        "publication_id": "PROT1_TRIP",
        "subscribers": ["MU1"],
        "security": "None",
    }

    sv = _rels(dev, "subscribes_to", "sv")[0]
    assert sv.direction == "ingress"
    assert sv.local.role == "subscriber"
    assert sv.remote.name == "MU1"
    assert sv.remote.role == "publisher"
    assert sv.remote.mac == "01:0C:CD:04:00:01"
    assert sv.remote.protocol_address == "0x4000"
    assert sv.vlan.id == "100"
    assert sv.extra == {"control_block": "svcb1", "ext_ref_count": 2}

    ed1 = _rels(dev, "subscribes_to", "")[0]
    assert ed1.remote.name == "BUS1"
    assert ed1.direction == ""
    assert ed1.reference == ""
    assert ed1.local.role == ""
    assert ed1.remote.role == ""

    rep = _rels(dev, "reports_to")[0]
    assert rep.reference == "PROT1PRO/LLN0$RP$urcbMeas"
    assert rep.direction == "ingress"
    assert rep.transport == "tcp"
    assert rep.local.role == "server"
    assert rep.local.port == 102
    assert rep.remote.name == "HMI1"
    assert rep.remote.role == "client"


def test_apply_service_security(all_ieds):
    prot = _applied(all_ieds["PROT1"])
    mms = next(s for s in prot.service if s.protocol == "mms")
    assert mms.port == 102
    assert mms.transport == "tcp"
    assert mms.role == "server"
    assert mms.enabled is True
    assert mms.security.authentication_required is False
    assert mms.security.encrypted is False
    goose = next(s for s in prot.service if s.protocol == "goose")
    assert goose.role == "publisher"
    assert goose.security.security_mode == "none"
    assert goose.security.encrypted is False
    assert goose.port is None

    mu = _applied(all_ieds["MU1"])
    sv = next(s for s in mu.service if s.protocol == "sv")
    assert sv.security.security_mode == "sign"
    assert sv.security.encrypted is False
    mms = next(s for s in mu.service if s.protocol == "mms")
    assert mms.security.authentication_required is True
    assert mms.security.authentication_methods == {"password"}
    assert mu.interface == []  # process-bus AP has no IP


def test_apply_security_modes(all_ieds):
    ied = all_ieds["MU1"].copy(deep=True)
    ied.publications[0].security = "SignatureAndEncryption"
    dev = _applied(ied)
    sv = next(s for s in dev.service if s.protocol == "sv")
    assert sv.security.security_mode == "sign_and_encrypt"
    assert sv.security.encrypted is True

    extra = ied.publications[0].copy(update={"name": "svcb2", "security": "None"}, deep=True)
    ied.publications.append(extra)
    dev = _applied(ied)
    sv = next(s for s in dev.service if s.protocol == "sv")
    assert sv.security.security_mode == "mixed"


def test_reference_join_publisher_subscriber(all_ieds):
    """OT-8: both ends of the SV stream report the same reference."""
    prot = _applied(all_ieds["PROT1"])
    mu = _applied(all_ieds["MU1"])
    pub_ref = _rels(mu, "publishes_to", "sv")[0].reference
    sub_ref = _rels(prot, "subscribes_to", "sv")[0].reference
    assert pub_ref == sub_ref == "MU1MU/LLN0$MS$svcb1"


def test_report_subscription_is_mms_client(raw):
    """ECS-6: a Report ExtRef -> subscribes_to(mms), egress, tcp/102, local role client."""
    rep = _variant(
        raw,
        b'serviceType="SMV" srcLDInst="MU" srcCBName="svcb1"/>\n',
        b'serviceType="SMV" srcLDInst="MU" srcCBName="svcb1"/>\n'
        b'<ExtRef iedName="MU1" ldInst="MU" lnClass="MMXU" lnInst="1" '
        b'serviceType="Report" srcLDInst="MU" srcCBName="urcbM"/>\n',
    )
    ied = scl.parse_scl(scl.load_scl(rep), "PROT1")
    report_sub = next(s for s in ied.subscriptions if s.service_type == "Report")
    assert report_sub.reference == ""  # MU1 has no urcbM in the file: $RP$/$BR$ unknown
    dev = _applied(ied)
    mms_sub = _rels(dev, "subscribes_to", "mms")[0]
    assert mms_sub.direction == "egress"
    assert mms_sub.transport == "tcp"
    assert mms_sub.remote.port == 102
    assert mms_sub.remote.role == "server"
    assert mms_sub.local.role == "client"
    assert mms_sub.remote.name == "MU1"


def test_report_subscription_reference_from_publisher(raw):
    """A Report ExtRef to an RCB that is in the same file gets the real reference."""
    rep = _variant(
        raw,
        b'serviceType="SMV" srcLDInst="MU" srcCBName="svcb1"/>\n',
        b'serviceType="SMV" srcLDInst="MU" srcCBName="svcb1"/>\n'
        b'<ExtRef iedName="PROT1" ldInst="PRO" serviceType="Report" srcLDInst="PRO" '
        b'srcCBName="urcbMeas"/>\n',
    )
    ied = scl.parse_scl(scl.load_scl(rep), "PROT1")
    report_sub = next(s for s in ied.subscriptions if s.service_type == "Report")
    assert report_sub.reference == "PROT1PRO/LLN0$RP$urcbMeas"


def test_apply_without_interfaces(all_ieds):
    dev = DeviceData(name="SEL")
    scl.apply_iec61850(dev, all_ieds["PROT1"], populate_interfaces=False, evidence="config")
    dev.export()
    assert dev.interface == []
    assert all(r.evidence == {"config"} for r in dev.relationships)


def test_apply_existing_interface_not_duplicated(all_ieds):
    dev = DeviceData(name="PROT1")
    dev.store("interface", Interface(name="eth0", ip="192.0.2.10"))
    scl.apply_iec61850(dev, all_ieds["PROT1"])
    assert [i.name for i in dev.interface] == ["eth0"]


def test_apply_is_idempotent(all_ieds):
    dev = DeviceData(name="PROT1")
    scl.apply_iec61850(dev, all_ieds["PROT1"])
    scl.apply_iec61850(dev, all_ieds["PROT1"].copy(deep=True))
    dev.export()
    assert len(dev.relationships) == 4
    assert len(dev.service) == 2
    assert len(dev.interface) == 1
    assert len(dev.iec61850.publications) == 1
    assert len(dev.iec61850.subscriptions) == 2


def test_relationship_documents_l2(all_ieds):
    """ECS-1: group MACs only as destination.mac, no IPs, unicast-only related.mac."""
    prot = DeviceData(name="PROT1", mac="00:30:A7:00:00:01")
    scl.apply_iec61850(prot, all_ieds["PROT1"])
    prot.export()
    dsv = _rels(prot, "subscribes_to", "sv")[0].gen_elastic_content(prot)
    assert "source" not in dsv
    assert dsv["destination"] == {"mac": "01:0C:CD:04:00:01"}
    assert "mac" not in dsv["related"]
    assert "ip" not in dsv["related"]
    dgo = _rels(prot, "publishes_to")[0].gen_elastic_content(prot)
    assert dgo["source"] == {"mac": "00:30:A7:00:00:01"}
    assert dgo["destination"]["mac"] == "01:0C:CD:01:00:10"
    assert dgo["related"]["mac"] == ["00:30:A7:00:00:01"]
