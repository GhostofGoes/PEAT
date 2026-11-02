"""
Tests for IEC 61850 CID file and SCL parsing, and the IEC 61850 values from
the ``ID`` command (``peat/modules/sel/sel_scl.py`` and its callers in
``relay_parse.py`` and ``sel_relay.py``).

The SCL files are synthetic, with the structure of the SCL schema in
IEC 61850-6 (SCL namespace ``http://www.iec.ch/61850/2003/SCL``). They're
compressed with zlib at test time, like the ``SET_61850.CID`` files on SEL
relays. All IP addresses are documentation addresses (RFC 5737). The ``ID``
lines with the source next to them are quoted from public SEL instruction
manuals as test vectors, the others are built with ``format_record``.
"""

import codecs
import hashlib
import io
import random
import xml.etree.ElementTree as ET
import zlib
from pathlib import PurePosixPath

import pytest

from peat import DeviceData, Interface, SELRelay, config, datastore
from peat.modules.sel import relay_parse, sel_scl
from peat.modules.sel.relay_parse import (
    extract_cid_content,
    process_cid_file,
    process_info_into_dev,
)
from peat.modules.sel.sel_cascii import format_record, parse_id_output
from peat.modules.sel.sel_scl import (
    decode_xml,
    decompress_cid,
    has_dtd,
    is_sel_ied,
    is_zlib_header,
    looks_like_xml,
    parse_scl,
    process_id_info,
    process_scl_into_dev,
    read_zlib_prefix,
    select_ied,
)
from peat.protocols import FTP


@pytest.fixture(autouse=True)
def env(tmp_path, mocker):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "TEMP_DIR": tmp_path / "temp_results",
        },
    )
    mocker.patch.object(datastore, "objects", [])


# Synthetic CID file of a feeder relay that publishes one GOOSE message and
# subscribes to a GOOSE message from a transformer relay ("SEL_387E_1").
SCL_XML = """<?xml version="1.0" encoding="UTF-8"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" xmlns:peat="urn:example:peat-test"
     version="2007" revision="B" release="4">
  <Header id="SEL_751_1" version="1" revision="2" nameStructure="IEDName"
          toolID="Synthetic SCL for PEAT tests (IEC 61850)">
    <History>
      <Hitem version="1" revision="1" when="2024-01-15T10:00:00" who="engineer1" what="Created"/>
      <Hitem version="1" revision="2" when="2024-02-20T14:30:00" who="engineer2"
             what="Added GOOSE subscription"/>
    </History>
  </Header>
  <Communication>
    <SubNetwork name="StationBus" type="8-MMS">
      <ConnectedAP iedName="SEL_751_1" apName="S1">
        <Address>
          <P type="IP">192.0.2.50</P>
          <P type="IP-SUBNET">255.255.255.0</P>
          <P type="IP-GATEWAY">192.0.2.1</P>
          <P type="OSI-AP-Title">1,1,9999,1</P>
          <P type="OSI-AE-Qualifier">12</P>
          <P type="OSI-PSEL">00000001</P>
          <P type="OSI-SSEL">0001</P>
          <P type="OSI-TSEL">0001</P>
        </Address>
        <GSE ldInst="CFG" cbName="GooseDSet1">
          <Address>
            <P type="MAC-Address">01-0C-CD-01-00-01</P>
            <P type="APPID">0001</P>
            <P type="VLAN-ID">00A</P>
            <P type="VLAN-PRIORITY">4</P>
          </Address>
          <MinTime unit="s" multiplier="m">4</MinTime>
          <MaxTime unit="s" multiplier="m">1000</MaxTime>
        </GSE>
      </ConnectedAP>
      <ConnectedAP iedName="SEL_387E_1" apName="S1">
        <Address>
          <P type="IP">192.0.2.51</P>
        </Address>
        <GSE ldInst="CFG" cbName="GooseDSet1">
          <Address>
            <P type="MAC-Address">01-0C-CD-01-00-02</P>
            <P type="APPID">0002</P>
          </Address>
        </GSE>
      </ConnectedAP>
    </SubNetwork>
  </Communication>
  <IED name="SEL_751_1" type="SEL_751" manufacturer="SEL" desc="Feeder 1"
       configVersion="ICD-751-R100-V0-Z001001-D20200101"
       originalSclVersion="2007" originalSclRevision="B">
    <Services>
      <DynAssociation/>
      <GetDirectory/>
      <GOOSE max="8"/>
      <FileHandling/>
    </Services>
    <AccessPoint name="S1" router="false" clock="false">
      <Server>
        <Authentication none="true"/>
        <LDevice inst="CFG">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0_0">
            <DataSet name="DSet01">
              <FCDA ldInst="PRO" lnClass="PTOC" lnInst="1" doName="Op" fc="ST"/>
            </DataSet>
            <DataSet name="DSet02"/>
            <ReportControl name="BRep01" datSet="DSet02" confRev="1"/>
            <GSEControl name="GooseDSet1" datSet="DSet01" appID="SEL_751_1_GOOSE1"
                        confRev="3" type="GOOSE"/>
            <Inputs>
              <ExtRef iedName="SEL_387E_1" ldInst="CFG" lnClass="LLN0" doName="Beh"/>
              <ExtRef iedName="SEL_387E_1" ldInst="CFG" lnClass="LLN0" doName="Mod"/>
              <ExtRef iedName="SEL_751_1" ldInst="PRO" lnClass="PTOC" lnInst="1"/>
            </Inputs>
          </LN0>
          <LN lnClass="LPHD" inst="1" lnType="LPHD_0"/>
        </LDevice>
        <LDevice inst="PRO">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0_1"/>
          <LN lnClass="PTOC" inst="1" lnType="PTOC_0"/>
          <LN lnClass="XCBR" inst="1" lnType="XCBR_0"/>
          <LN lnClass="CSWI" inst="1" lnType="CSWI_0"/>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  <peat:IED name="NOT_AN_IED"/>
  <DataTypeTemplates/>
</SCL>
"""

SCL_BYTES = SCL_XML.encode("utf-8")

# A minimal SCL, with only what's needed for the tests that use it
MINIMAL_SCL = """<?xml version="1.0" encoding="UTF-8"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL">
  <Header id="{name}" toolID="IEC 61850 test"/>
  <Communication>
    <SubNetwork name="NET1">
      <ConnectedAP iedName="{name}" apName="S1">
        <Address>{address}</Address>
      </ConnectedAP>
    </SubNetwork>
  </Communication>
  <IED name="{name}" type="{type}" manufacturer="{manufacturer}" configVersion="{version}">
    <AccessPoint name="S1">{server}</AccessPoint>
  </IED>
</SCL>
"""


def _minimal_scl(
    name: str = "SEL_351S_1",
    ied_type: str = "SEL_351S",
    manufacturer: str = "SEL",
    version: str = "ICD-351S-R201-V0-Z001001-D20120615",
    address: str = '<P type="IP">192.0.2.60</P>',
    server: str = '<Server><LDevice inst="CFG"/></Server>',
) -> str:
    return MINIMAL_SCL.format(
        name=name,
        type=ied_type,
        manufacturer=manufacturer,
        version=version,
        address=address,
        server=server,
    )


# "ID" output of a SEL-351S with a valid CID file
# (SEL-351S Instruction Manual 20171023, Appendix P, "IEC 61850 Configuration")
ID_351S = "\r\n".join(
    [
        "ID",
        "\x02",
        '"FID=SEL-351S-5-R512-V0-Z104104-D20120830","095B"',
        '"DEVID=STATION A","049C"',
        '"iedName=SEL_351S_1","061F"',
        '"type=SEL_351S","049E"',
        '"configVersion=ICD-351S-R201-V0-Z001001-D20120615","0D62"',
        "\x03",
        "=>",
    ]
)

# "ID" output of a SEL-351S with an invalid CID file (same manual and section)
ID_351S_PARSE_FAILURE = "\r\n".join(
    [
        '"FID=SEL-351S-5-R512-V0-Z104104-D20120830","095B"',
        '"iedName=PARSE FAILURE","0703"',
        '"type=PARSE FAILURE","0612"',
        '"configVersion=PARSE FAILURE","09AC"',
    ]
)

# "ID" output captured by PEAT from a SEL-700G without a CID file (docs/sel.rst)
ID_700G = "\r\n".join(
    [
        '"FID=SEL-700G-R200-V0-Z006003-D20180629","08F0"',
        '"DEVID=SEL-700G","0408"',
        '"iedName=","0360"',
        '"type=","026F"',
        '"configVersion=","0609"',
        '"LIB61850ID=5C9A14CB","04F1"',
    ]
)


def _hashes(data: bytes) -> dict[str, str]:
    return {
        algo: getattr(hashlib, algo)(data).hexdigest().upper()
        for algo in ["md5", "sha1", "sha256", "sha512"]
    }


def _files(dev: DeviceData, name: str) -> list:
    return [f for f in dev.files if f.name == name]


def _services(dev: DeviceData, protocol: str = "iec61850") -> list:
    return [s for s in dev.service if s.protocol == protocol]


def _random_bytes(size: int) -> bytes:
    """Data that doesn't compress, so the compressed data is several chunks."""
    return random.Random(61850).randbytes(size)


# ---------------------------------------------------------------------------
# Decompression
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        (b"\x78\x01", True),  # SET_61850.CID on SEL relays (and zlib level 1)
        (b"\x78\x5e", True),
        (b"\x78\x9c", True),  # zlib default level
        (b"\x78\xda", True),  # zlib level 9
        (b"\x08\x1d", True),  # Smallest window size
        (b"\x78\x00", False),  # Wrong check bits
        (b"\x78\xbb", False),  # Preset dictionary
        (b"\x88\x15", False),  # Window size too large
        (b"\x79\x9c", False),  # Not DEFLATE
        (b"<?", False),
        (b"\x78", False),
        (b"", False),
    ],
)
def test_is_zlib_header(header, expected):
    assert is_zlib_header(header) is expected


@pytest.mark.parametrize(("level", "header"), [(0, "7801"), (1, "7801"), (6, "789C"), (9, "78DA")])
def test_decompress_cid_levels(level, header):
    content = decompress_cid(zlib.compress(SCL_BYTES, level))

    assert content.data == SCL_BYTES
    assert content.compressed
    assert content.zlib_header == header
    assert content.complete
    assert content.trailing_bytes == 0
    assert content.error == ""


def test_decompress_cid_trailing_bytes():
    content = decompress_cid(zlib.compress(SCL_BYTES, 9) + b"\x00" * 100)
    assert content.data == SCL_BYTES
    assert content.trailing_bytes == 100
    assert content.complete

    # The end of the compressed data is in a later chunk than the start
    data = _random_bytes(200_000)
    content = decompress_cid(zlib.compress(data, 1) + b"padding" * 20_000)
    assert content.data == data
    assert content.trailing_bytes == 140_000


@pytest.mark.parametrize(
    "data",
    [
        SCL_BYTES,
        codecs.BOM_UTF8 + SCL_BYTES,
        b"  \r\n" + SCL_BYTES,
        b'<SCL xmlns="http://www.iec.ch/61850/2003/SCL"/>',
        SCL_XML.encode("utf-16"),
    ],
)
def test_decompress_cid_uncompressed_xml(data):
    content = decompress_cid(data)
    assert content.data == data
    assert not content.compressed
    assert content.zlib_header == ""


def test_decompress_cid_text_input():
    # A file that was received as text, e.g. a FILE SHOW transfer
    content = decompress_cid(SCL_XML)
    assert content.data == SCL_BYTES
    assert not content.compressed

    # Compressed data that survived a transfer as text
    compressed = zlib.compress(SCL_BYTES)
    assert decompress_cid(compressed.decode("latin-1")).data == SCL_BYTES

    with pytest.raises(ValueError, match="text that isn't XML"):
        decompress_cid("x\u0153\u2018 corrupted by a text transfer")


@pytest.mark.parametrize("encoding", ["ISO-8859-1", "latin1", "windows-1252", "unknown-x"])
def test_decompress_cid_text_declared_encoding(encoding):
    # Text has already been decoded, so the declared encoding doesn't apply to it
    text = (
        f'<?xml version="1.0" encoding="{encoding}"?>'
        '<SCL xmlns="http://www.iec.ch/61850/2003/SCL">'
        '<IED name="R" desc="Feeder \u00c5 \u20ac"/></SCL>'
    )

    content = decompress_cid(text)

    assert content.data == codecs.BOM_UTF8 + text.encode("utf-8")
    assert decode_xml(content.data) == text
    assert extract_cid_content(text) == text
    assert parse_scl(content.data)["ieds"][0]["desc"] == "Feeder \u00c5 \u20ac"

    dev = DeviceData(id="relay")
    process_cid_file(text, PurePosixPath("/SET_61850.CID"), dev, from_device=True)
    assert dev.extra["iec61850"]["scl"]["ied"]["desc"] == "Feeder \u00c5 \u20ac"


def test_decompress_cid_text_utf8_declaration():
    text = '<?xml version="1.0" encoding="utf8"?><SCL desc="Feeder \u00c5"/>'
    # No byte order mark is needed
    assert decompress_cid(text).data == text.encode("utf-8")
    # A byte order mark in the text is kept
    assert decompress_cid("\ufeff" + text).data == codecs.BOM_UTF8 + text.encode("utf-8")


def test_decompress_cid_truncated():
    data = _random_bytes(200_000)
    compressed = zlib.compress(data, 1)

    content = decompress_cid(compressed[: len(compressed) // 2])

    assert content.compressed
    assert not content.complete
    assert "truncated" in content.error
    assert content.data
    assert data.startswith(content.data)


def test_decompress_cid_corrupted_checksum():
    compressed = zlib.compress(SCL_BYTES)
    corrupted = compressed[:-4] + bytes(b ^ 0xFF for b in compressed[-4:])

    content = decompress_cid(corrupted)

    # Everything was decompressed, but the checksum (Adler-32) doesn't match
    assert not content.complete
    assert "checksum (Adler-32)" in content.error
    assert content.data == SCL_BYTES
    assert content.trailing_bytes == 0

    # Only the checksum is missing
    content = decompress_cid(compressed[:-4])
    assert not content.complete
    assert "checksum is missing" in content.error
    assert content.data == SCL_BYTES


@pytest.mark.parametrize(
    "data",
    [
        b"\x78\x01",  # Only the zlib header
        b"\x78\x9c\x00",
        zlib.compress(SCL_BYTES)[:3],  # Truncated in the first DEFLATE block
        zlib.compress(b"")[:-1],  # Empty, and the checksum is truncated
    ],
)
def test_decompress_cid_nothing_decompressed(data):
    with pytest.raises(zlib.error, match="nothing could be decompressed"):
        decompress_cid(data)


def test_decompress_cid_empty():
    # Valid compressed data, of nothing
    content = decompress_cid(zlib.compress(b""))
    assert content.data == b""
    assert content.complete


def test_decompress_cid_invalid():
    with pytest.raises(zlib.error):
        decompress_cid(b"\x78\x9c" + b"\xff" * 64)

    with pytest.raises(ValueError, match="not zlib-compressed data or XML"):
        decompress_cid(b"definitely not a CID file")

    # Raw DEFLATE data, without the zlib header
    with pytest.raises(ValueError, match="not zlib-compressed data or XML"):
        decompress_cid(zlib.compress(SCL_BYTES)[2:-4])


def test_decompress_cid_bomb(mocker):
    bomb = zlib.compress(b"<SCL>" + b" " * (8 * 1024 * 1024), 9)
    assert len(bomb) < 20_000

    with pytest.raises(ValueError, match="more than 1048576 bytes"):
        decompress_cid(bomb, limit=1024 * 1024)

    mocker.patch.object(sel_scl, "MAX_CID_SIZE", 64 * 1024)
    with pytest.raises(ValueError, match="more than 65536 bytes"):
        decompress_cid(bomb)
    with pytest.raises(ValueError, match="more than 65536 bytes"):
        extract_cid_content(bomb)

    # The limit is the size of the data, not one byte less
    exact = b"<SCL>" + b" " * (64 * 1024 - 5)
    assert decompress_cid(zlib.compress(exact)).data == exact


def test_extract_cid_content():
    assert extract_cid_content(b"") == ""
    assert extract_cid_content(zlib.compress(SCL_BYTES, 1)) == SCL_XML
    # The byte order mark isn't in the text
    assert extract_cid_content(zlib.compress(codecs.BOM_UTF8 + SCL_BYTES)) == SCL_XML
    assert extract_cid_content(SCL_BYTES) == SCL_XML


# ---------------------------------------------------------------------------
# Decoding
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (codecs.BOM_UTF8 + "<a>\u00e9</a>".encode(), "<a>\u00e9</a>"),
        ("<a>\u00e9</a>".encode("utf-16"), "<a>\u00e9</a>"),
        ("<a>\u00e9</a>".encode("utf-16-be"), "<a>\u00e9</a>"),
        (
            '<?xml version="1.0" encoding="ISO-8859-1"?><a>\u00e9</a>'.encode("latin-1"),
            '<?xml version="1.0" encoding="ISO-8859-1"?><a>\u00e9</a>',
        ),
        # Not valid UTF-8 and no encoding declared
        (b"<a>\xe9</a>", "<a>\u00e9</a>"),
        # A UTF-16 declaration in a file that isn't UTF-16
        (
            b'<?xml version="1.0" encoding="UTF-16"?><a>x</a>',
            '<?xml version="1.0" encoding="UTF-16"?><a>x</a>',
        ),
        # An unknown encoding
        (
            b"<?xml version='1.0' encoding='no-such-codec'?><a/>",
            "<?xml version='1.0' encoding='no-such-codec'?><a/>",
        ),
    ],
)
def test_decode_xml(data, expected):
    assert decode_xml(data) == expected


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        ("<SCL/>", True),
        ("\ufeff<SCL/>", True),
        (b"\r\n  <SCL/>", True),
        (codecs.BOM_UTF8 + b"<?xml?>", True),
        ("<SCL/>".encode("utf-16"), True),
        (b"\x78\x9c\x01\x02", False),
        ("SCL", False),
        (b"", False),
    ],
)
def test_looks_like_xml(data, expected):
    assert looks_like_xml(data) is expected


# ---------------------------------------------------------------------------
# File signature
# ---------------------------------------------------------------------------


def _cid_signature():
    (sig,) = [s for s in SELRelay.file_signatures if s.default_filename == "SET_61850.CID"]
    return sig


@pytest.mark.parametrize("level", [0, 1, 6, 9])
def test_cid_signature_matches_all_levels(level):
    assert _cid_signature().matches(zlib.compress(SCL_BYTES, level))


def test_cid_signature_does_not_match():
    sig = _cid_signature()

    # Not compressed (the filename pattern matches *.CID files instead)
    assert not sig.matches(SCL_BYTES)
    # Compressed, but not SCL
    assert not sig.matches(zlib.compress(b"<root>IEC 61850</root>"))
    # SCL without "IEC 61850" in it
    assert not sig.matches(
        zlib.compress(b'<SCL xmlns="http://www.iec.ch/61850/2003/SCL"><Header id="x"/></SCL>')
    )
    # A document type declaration
    dtd = SCL_XML.replace("<SCL ", '<!DOCTYPE SCL [<!ENTITY a "IEC 61850">]>\n<SCL ', 1)
    assert not sig.matches(zlib.compress(dtd.encode()))


def test_cid_signature_only_decompresses_zlib(mocker):
    decompressobj = mocker.spy(zlib, "decompressobj")
    decompress = mocker.spy(zlib, "decompress")

    assert not _cid_signature().matches(b"not a CID file" * 100)
    assert not _cid_signature().matches(SCL_BYTES)

    assert decompressobj.call_count == 0
    assert decompress.call_count == 0


def test_cid_signature_bomb(mocker):
    mocker.patch.object(sel_scl, "MAX_CID_CHECK_SIZE", 1024 * 1024)
    read_prefix = mocker.spy(sel_scl, "read_zlib_prefix")
    bomb = zlib.compress(SCL_BYTES + b" " * (32 * 1024 * 1024), 9)
    assert len(bomb) < 100_000

    # Only the start of the data is decompressed, and the SCL is there
    assert _cid_signature().matches(bomb)
    assert len(read_prefix.spy_return) == 1024 * 1024


def test_read_zlib_prefix():
    data = _random_bytes(300_000)
    compressed = zlib.compress(data, 1)

    assert read_zlib_prefix(io.BytesIO(compressed)) == data
    assert read_zlib_prefix(io.BytesIO(compressed), limit=100_000) == data[:100_000]
    assert read_zlib_prefix(io.BytesIO(SCL_BYTES)) == b""
    assert read_zlib_prefix(io.BytesIO(b"")) == b""

    # Invalid data after the start: what was decompressed is returned
    prefix = read_zlib_prefix(io.BytesIO(compressed[:150_000] + b"\xff" * 50_000))
    assert prefix
    assert data.startswith(prefix)


# ---------------------------------------------------------------------------
# SCL parsing
# ---------------------------------------------------------------------------


def test_parse_scl():
    scl = parse_scl(SCL_XML)

    assert scl["scl_version"] == "2007"
    assert scl["scl_revision"] == "B"
    assert scl["scl_release"] == "4"
    assert scl["header"] == {
        "id": "SEL_751_1",
        "version": "1",
        "revision": "2",
        "tool_id": "Synthetic SCL for PEAT tests (IEC 61850)",
        "name_structure": "IEDName",
        "history_count": 2,
        "last_history": {
            "version": "1",
            "revision": "2",
            "when": "2024-02-20T14:30:00",
            "who": "engineer2",
            "what": "Added GOOSE subscription",
        },
    }

    # The IED in another namespace ("peat:IED") isn't an IED
    assert len(scl["ieds"]) == 1
    ied = scl["ieds"][0]
    assert {k: ied[k] for k in ("name", "type", "manufacturer", "config_version", "desc")} == {
        "name": "SEL_751_1",
        "type": "SEL_751",
        "manufacturer": "SEL",
        "config_version": "ICD-751-R100-V0-Z001001-D20200101",
        "desc": "Feeder 1",
    }
    assert ied["original_scl_version"] == "2007"
    assert ied["original_scl_revision"] == "B"
    assert ied["services"] == ["DynAssociation", "FileHandling", "GOOSE", "GetDirectory"]
    assert ied["access_points"] == [
        {
            "name": "S1",
            "router": False,
            "clock": False,
            "has_server": True,
            "authentication": {"none": True},
            "ldevices": ["CFG", "PRO"],
        }
    ]
    assert ied["ldevices"] == [
        {"inst": "CFG", "access_point": "S1", "ln_count": 2},
        {"inst": "PRO", "access_point": "S1", "ln_count": 4},
    ]
    assert ied["ln_classes"] == ["CSWI", "LLN0", "LPHD", "PTOC", "XCBR"]
    assert ied["gse_controls"] == [
        {
            "ld_inst": "CFG",
            "name": "GooseDSet1",
            "dataset": "DSet01",
            "go_id": "SEL_751_1_GOOSE1",
            "conf_rev": "3",
            "type": "GOOSE",
        }
    ]
    assert ied["smv_controls"] == []
    # The IED's own name isn't in the subscriptions
    assert ied["input_ieds"] == ["SEL_387E_1"]
    assert ied["counts"] == {
        "access_point": 1,
        "ldevice": 2,
        "ln": 6,
        "dataset": 2,
        "report_control": 1,
        "log_control": 0,
        "gse_control": 1,
        "smv_control": 0,
        "ext_ref": 3,
    }

    (subnetwork,) = scl["subnetworks"]
    assert subnetwork["name"] == "StationBus"
    assert subnetwork["type"] == "8-MMS"
    own, peer = subnetwork["connected_aps"]
    assert own == {
        "ied_name": "SEL_751_1",
        "ap_name": "S1",
        "address": {
            "ip": "192.0.2.50",
            "ip_subnet": "255.255.255.0",
            "ip_gateway": "192.0.2.1",
            "osi_ap_title": "1,1,9999,1",
            "osi_ae_qualifier": "12",
            "osi_psel": "00000001",
            "osi_ssel": "0001",
            "osi_tsel": "0001",
        },
        "gse": [
            {
                "ld_inst": "CFG",
                "cb_name": "GooseDSet1",
                "mac_address": "01:0C:CD:01:00:01",
                "appid": "0001",
                "vlan_id": "00A",
                "vlan_priority": "4",
                "min_time_ms": 4,
                "max_time_ms": 1000,
            }
        ],
    }
    assert peer["ied_name"] == "SEL_387E_1"
    assert peer["gse"][0]["mac_address"] == "01:0C:CD:01:00:02"


def test_parse_scl_without_namespace_and_bytes():
    xml = SCL_XML.replace(' xmlns="http://www.iec.ch/61850/2003/SCL"', "", 1)
    assert parse_scl(xml)["ieds"][0]["name"] == "SEL_751_1"

    # Bytes with a byte order mark, and Latin-1 with a declaration
    assert parse_scl(codecs.BOM_UTF8 + SCL_BYTES)["ieds"][0]["name"] == "SEL_751_1"
    latin1 = SCL_XML.replace('encoding="UTF-8"', 'encoding="ISO-8859-1"').replace(
        'desc="Feeder 1"', 'desc="Feeder \u00e9"'
    )
    assert parse_scl(latin1.encode("latin-1"))["ieds"][0]["desc"] == "Feeder \u00e9"


def test_parse_scl_minimal_and_empty():
    assert parse_scl('<SCL xmlns="http://www.iec.ch/61850/2003/SCL"/>') == {
        "header": {},
        "ieds": [],
        "subnetworks": [],
    }

    ied = parse_scl('<SCL><IED name="X"><AccessPoint name="P1"/></IED></SCL>')["ieds"][0]
    assert ied["access_points"] == [{"name": "P1", "has_server": False}]
    assert ied["counts"]["ldevice"] == 0
    assert "services" not in ied


@pytest.mark.parametrize(
    "xml",
    [
        # Entity expansion ("billion laughs")
        '<?xml version="1.0"?>\n<!DOCTYPE SCL [\n<!ENTITY a "aaaaaaaaaa">\n'
        '<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">\n'
        '<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">\n]>\n'
        '<SCL xmlns="http://www.iec.ch/61850/2003/SCL"><Header id="&c;"/></SCL>',
        # External entity
        '<?xml version="1.0"?><!DOCTYPE SCL [<!ENTITY e SYSTEM "file:///etc/passwd">]>'
        '<SCL xmlns="http://www.iec.ch/61850/2003/SCL"><Header id="&e;"/></SCL>',
        # External DTD
        '<!DOCTYPE SCL SYSTEM "http://192.0.2.99/scl.dtd"><SCL/>',
        # Lowercase, after a comment with an element in it
        "<!-- <a> --><!doctype SCL><SCL/>",
        # Parameter entity
        '<!DOCTYPE SCL [<!ENTITY % p "x">]><SCL/>',
    ],
)
def test_parse_scl_rejects_dtd(xml):
    assert has_dtd(xml)
    assert has_dtd(xml.encode())
    with pytest.raises(ValueError, match="document type"):
        parse_scl(xml)


def test_parse_scl_rejects_dtd_in_parser(mocker):
    # The parser refuses a document type declaration even if the text check misses it
    mocker.patch.object(sel_scl, "has_dtd", return_value=False)
    with pytest.raises(ValueError, match="document type declarations aren't allowed"):
        parse_scl('<!DOCTYPE SCL [<!ENTITY a "a">]><SCL>&a;</SCL>')


def test_parse_scl_invalid():
    with pytest.raises(ValueError, match="not 'SCL'"):
        parse_scl("<root/>")
    with pytest.raises(ValueError, match="not 'SCL'"):
        parse_scl('<SCL xmlns="urn:example:not-scl"/>')
    with pytest.raises(ET.ParseError):
        parse_scl("<SCL><IED></SCL>")
    # Entities aren't defined without a DTD
    with pytest.raises(ET.ParseError, match="undefined entity"):
        parse_scl("<SCL>&foo;</SCL>")


@pytest.mark.parametrize(
    ("xml", "expected"),
    [
        ('<MinTime unit="s" multiplier="m">4</MinTime>', 4),
        ("<MinTime>8</MinTime>", 8),
        ('<MaxTime unit="s" multiplier="">2</MaxTime>', 2000),
        ('<MaxTime unit="s" multiplier="u">1500</MaxTime>', 1.5),
        ('<MaxTime unit="m">1</MaxTime>', None),
        ('<MaxTime multiplier="k">1</MaxTime>', None),
        ("<MaxTime>soon</MaxTime>", None),
        ("<MaxTime/>", None),
    ],
)
def test_time_ms(xml, expected):
    assert sel_scl._time_ms(ET.fromstring(xml)) == expected


def test_select_ied():
    scl = {"ieds": [{"name": "A", "manufacturer": "Other"}, {"name": "B", "manufacturer": "SEL"}]}

    assert select_ied(scl, "A")["name"] == "A"
    assert select_ied(scl, "missing")["name"] == "B"
    assert select_ied(scl)["name"] == "B"
    assert select_ied({"ieds": [{"name": "C", "manufacturer": "Other"}]})["name"] == "C"
    assert select_ied({"ieds": []}) is None


@pytest.mark.parametrize(
    ("ied", "expected"),
    [
        ({"manufacturer": "SEL"}, True),
        ({"manufacturer": "Schweitzer Engineering Laboratories, Inc."}, True),
        ({}, True),
        ({"manufacturer": "Other", "type": "SEL_2411"}, True),
        ({"manufacturer": "Other", "type": "X1"}, False),
    ],
)
def test_is_sel_ied(ied, expected):
    assert is_sel_ied(ied) is expected


# ---------------------------------------------------------------------------
# Processing into the device
# ---------------------------------------------------------------------------


def _dev(ip: str = "192.0.2.50") -> DeviceData:
    dev = datastore.get(ip, "ip")
    dev.store("interface", Interface(type="ethernet", ip=ip))
    return dev


def test_process_scl_into_dev():
    dev = _dev()

    ied = process_scl_into_dev(parse_scl(SCL_XML), dev, source="SET_61850.CID")

    assert ied["name"] == "SEL_751_1"
    iec = dev.extra["iec61850"]
    assert iec["ied_name"] == "SEL_751_1"
    assert iec["ied_type"] == "SEL_751"
    assert iec["config_version"] == "ICD-751-R100-V0-Z001001-D20200101"
    assert iec["manufacturer"] == "SEL"
    assert "mismatches" not in iec

    summary = iec["scl"]
    assert summary["file"] == "SET_61850.CID"
    assert summary["scl_version"] == "2007"
    assert summary["header"]["id"] == "SEL_751_1"
    assert summary["ied"]["name"] == "SEL_751_1"
    assert summary["ied_count"] == 1
    assert summary["other_ieds"] == []
    assert [c["ied_name"] for c in summary["connected_aps"]] == ["SEL_751_1"]
    assert summary["connected_aps"][0]["subnetwork"] == "StationBus"
    assert [c["ied_name"] for c in summary["peers"]] == ["SEL_387E_1"]

    (svc,) = _services(dev)
    assert svc.port == 102
    assert svc.transport == "tcp"
    assert svc.extra == {"ied_name": "SEL_751_1", "access_point": "S1"}
    # On the interface with the IP address in the SCL
    assert [s.protocol for s in dev.interface[0].services] == ["iec61850"]

    assert {"192.0.2.50", "192.0.2.1", "192.0.2.51"} <= dev.related.ip
    assert {"01:0C:CD:01:00:01", "01:0C:CD:01:00:02"} <= dev.related.mac
    assert "iec61850" in dev.related.protocols
    assert 102 in dev.related.ports
    assert dev.name == "SEL_751_1"

    # The device data can be exported
    assert dev.export()["extra"]["iec61850"]["ied_name"] == "SEL_751_1"


def test_process_scl_into_dev_keeps_name_and_other_ip(caplog):
    dev = _dev("192.0.2.70")
    dev.name = "FEEDER 1"

    process_scl_into_dev(parse_scl(SCL_XML), dev)

    assert dev.name == "FEEDER 1"
    assert "file" not in dev.extra["iec61850"]["scl"]
    # Not on the interface, since the IP address is different
    assert len(_services(dev)) == 1
    assert dev.interface[0].services == []
    assert "is different from the IP address" in caplog.text


def test_process_scl_into_dev_invalid_addresses():
    xml = _minimal_scl(
        address=(
            '<P type="IP">not-an-ip</P><P type="IP-GATEWAY">0.0.0.0</P>'
            '<P type="IPv6">2001:db8::5</P><P type="MMS-Port">10102</P>'
        )
    ).replace(
        "</ConnectedAP>",
        '<GSE ldInst="CFG" cbName="G1"><Address><P type="MAC-Address">zz-zz</P>'
        "</Address></GSE></ConnectedAP>",
    )
    dev = DeviceData(id="relay")

    process_scl_into_dev(parse_scl(xml), dev)

    assert dev.related.ip == {"2001:db8::5"}
    assert dev.related.mac == set()
    (svc,) = _services(dev)
    assert svc.port == 10102  # MMS-Port (IEC 61850-6 Edition 2.1)


def test_process_scl_into_dev_goose_only():
    dev = DeviceData(id="relay")

    process_scl_into_dev(parse_scl(_minimal_scl(server="")), dev)

    # No MMS server, so no MMS service
    assert _services(dev) == []
    assert "iec61850" in dev.related.protocols
    assert dev.extra["iec61850"]["ied_name"] == "SEL_351S_1"


def test_process_scl_into_dev_multiple_ieds():
    xml = SCL_XML.replace(
        "  <DataTypeTemplates/>",
        '  <IED name="SEL_387E_1" type="SEL_387E" manufacturer="SEL"/>\n  <DataTypeTemplates/>',
    )
    dev = DeviceData(id="relay")
    dev.extra["iec61850"] = {"id_command": {"ied_name": "SEL_387E_1"}}

    process_scl_into_dev(parse_scl(xml), dev)

    summary = dev.extra["iec61850"]["scl"]
    assert summary["ied"]["name"] == "SEL_387E_1"
    assert summary["ied_count"] == 2
    assert summary["other_ieds"] == ["SEL_751_1"]
    assert [c["ied_name"] for c in summary["connected_aps"]] == ["SEL_387E_1"]
    # The IED doesn't have an access point with a server
    assert _services(dev) == []


def test_process_scl_into_dev_two_files(caplog):
    dev = _dev("192.0.2.60")
    first = _minimal_scl()
    second = _minimal_scl(
        name="SEL_351S_2",
        version="ICD-351S-R204-V0-Z516005-D20150101",
        address='<P type="IP">192.0.2.61</P><P type="MMS-Port">10102</P>',
    )

    process_scl_into_dev(parse_scl(first), dev, source="SET_61850.CID")
    assert "other_scl_files" not in dev.extra["iec61850"]
    process_scl_into_dev(parse_scl(second), dev, source="OLD.CID")

    iec = dev.extra["iec61850"]
    # The values are from the first file, and the second file's summary is kept
    assert iec["scl"]["file"] == "SET_61850.CID"
    assert iec["ied_name"] == "SEL_351S_1"
    assert iec["config_version"] == "ICD-351S-R201-V0-Z001001-D20120615"
    assert [s["file"] for s in iec["other_scl_files"]] == ["OLD.CID"]
    assert iec["other_scl_files"][0]["ied"]["name"] == "SEL_351S_2"
    assert "mismatches" not in iec
    assert "has more than one SCL file" in caplog.text
    assert "'OLD.CID'" in caplog.text
    # Only the addresses of the second file are used (not its service or name)
    assert {"192.0.2.60", "192.0.2.61"} <= dev.related.ip
    assert [s.port for s in _services(dev)] == [102]
    assert dev.name == "SEL_351S_1"

    # The same file again replaces its summary
    process_scl_into_dev(parse_scl(second), dev, source="OLD.CID")
    process_scl_into_dev(parse_scl(first), dev, source="SET_61850.CID")
    assert iec["scl"]["file"] == "SET_61850.CID"
    assert [s["file"] for s in iec["other_scl_files"]] == ["OLD.CID"]


def test_process_scl_into_dev_file_without_ied_first():
    dev = DeviceData(id="relay")

    process_scl_into_dev(parse_scl("<SCL/>"), dev, source="EMPTY.CID")
    process_scl_into_dev(parse_scl(_minimal_scl()), dev, source="SET_61850.CID")

    # The first file with an IED is used
    iec = dev.extra["iec61850"]
    assert iec["scl"]["file"] == "SET_61850.CID"
    assert iec["ied_name"] == "SEL_351S_1"
    assert [s["file"] for s in iec["other_scl_files"]] == ["EMPTY.CID"]
    assert len(_services(dev)) == 1

    # A file without an IED after it doesn't replace it
    process_scl_into_dev(parse_scl("<SCL/>"), dev, source="EMPTY2.CID")
    assert iec["scl"]["file"] == "SET_61850.CID"
    assert [s["file"] for s in iec["other_scl_files"]] == ["EMPTY.CID", "EMPTY2.CID"]


def test_process_scl_into_dev_no_ied(caplog):
    dev = DeviceData(id="relay")

    assert process_scl_into_dev(parse_scl("<SCL/>"), dev, source="X.CID") is None

    assert dev.extra["iec61850"]["scl"] == {"file": "X.CID", "header": {}, "ied_count": 0}
    assert "No IED in the SCL in X.CID" in caplog.text
    assert not dev.name


# ---------------------------------------------------------------------------
# ID command
# ---------------------------------------------------------------------------


def test_process_info_into_dev_id_351s():
    dev = DeviceData(id="relay")

    process_info_into_dev(parse_id_output(ID_351S), dev)

    assert dev.extra["iec61850"] == {
        "ied_name": "SEL_351S_1",
        "ied_type": "SEL_351S",
        "config_version": "ICD-351S-R201-V0-Z001001-D20120615",
        "id_command": {
            "ied_name": "SEL_351S_1",
            "ied_type": "SEL_351S",
            "config_version": "ICD-351S-R201-V0-Z001001-D20120615",
        },
    }
    # Still in the top level of extra, as before (iedName is a fallback for the name)
    assert dev.extra["iedName"] == "SEL_351S_1"
    assert dev.extra["type"] == "SEL_351S"
    assert dev.extra["configVersion"] == "ICD-351S-R201-V0-Z001001-D20120615"
    assert "iec61850_parse_failure" not in dev.extra
    assert dev.extra["DEVID"] == "STATION A"
    assert dev.description.model == "351S"

    (svc,) = _services(dev)
    assert svc.port == 102
    assert svc.transport == "tcp"
    assert svc.extra == {"ied_name": "SEL_351S_1"}


def test_process_info_into_dev_id_700g_docs_sample():
    dev = DeviceData(id="relay")

    process_info_into_dev(parse_id_output(ID_700G), dev)

    # No CID file loaded: only the IEC 61850 library ID
    assert dev.extra["iec61850"] == {
        "lib61850_id": "5C9A14CB",
        "id_command": {"lib61850_id": "5C9A14CB"},
    }
    assert dev.extra["LIB61850ID"] == "5C9A14CB"
    assert "iedName" not in dev.extra
    assert _services(dev) == []


def test_process_info_into_dev_id_parse_failure():
    dev = DeviceData(id="relay")

    process_info_into_dev(parse_id_output(ID_351S_PARSE_FAILURE), dev)

    assert dev.extra["iec61850"] == {"parse_failure": ["iedName", "type", "configVersion"]}
    assert "iec61850_parse_failure" not in dev.extra
    assert "iedName" not in dev.extra
    assert _services(dev) == []

    # The relay loaded a valid CID file since the last time
    process_info_into_dev(parse_id_output(ID_351S), dev)
    assert "parse_failure" not in dev.extra["iec61850"]
    assert dev.extra["iec61850"]["ied_name"] == "SEL_351S_1"


def test_process_info_into_dev_not_id_output():
    dev = DeviceData(id="relay")

    # "type" by itself isn't from the ID command, so it's left alone
    process_info_into_dev({"type": "something", "DEVID": "STATION B"}, dev)

    assert dev.extra["type"] == "something"
    assert "iec61850" not in dev.extra

    info = {"RID": "R1"}
    process_id_info(info, dev)
    assert info == {"RID": "R1"}
    assert "iec61850" not in dev.extra


def test_id_then_scl_mismatch(caplog):
    dev = DeviceData(id="relay")
    process_info_into_dev(parse_id_output(ID_351S), dev)

    xml = _minimal_scl(name="SEL_351S_2", version="ICD-351S-R204-V0-Z516005-D20150101")
    process_scl_into_dev(parse_scl(xml), dev, source="SET_61850.CID")

    iec = dev.extra["iec61850"]
    # The values the relay reports are kept
    assert iec["ied_name"] == "SEL_351S_1"
    assert iec["config_version"] == "ICD-351S-R201-V0-Z001001-D20120615"
    assert iec["manufacturer"] == "SEL"
    assert iec["mismatches"] == {
        "ied_name": {"id_command": "SEL_351S_1", "scl": "SEL_351S_2"},
        "config_version": {
            "id_command": "ICD-351S-R201-V0-Z001001-D20120615",
            "scl": "ICD-351S-R204-V0-Z516005-D20150101",
        },
    }
    assert "('SEL_351S_1') is different from the ied_name in the SCL file" in caplog.text
    assert caplog.text.count("is different from the") == 2

    # Processing the same file again doesn't repeat the warnings
    process_scl_into_dev(parse_scl(xml), dev)
    assert caplog.text.count("is different from the") == 2

    # The service has the name the relay reports
    (svc,) = _services(dev)
    assert svc.extra["ied_name"] == "SEL_351S_1"
    assert svc.extra["access_point"] == "S1"


def test_scl_then_id(caplog):
    dev = DeviceData(id="relay")
    process_scl_into_dev(parse_scl(_minimal_scl(name="TEMPLATE")), dev)
    assert dev.extra["iec61850"]["ied_name"] == "TEMPLATE"

    process_info_into_dev(parse_id_output(ID_351S), dev)

    iec = dev.extra["iec61850"]
    assert iec["ied_name"] == "SEL_351S_1"
    assert iec["mismatches"] == {"ied_name": {"id_command": "SEL_351S_1", "scl": "TEMPLATE"}}
    assert "is different from the ied_name in the SCL file ('TEMPLATE')" in caplog.text


def test_id_and_scl_match(caplog):
    dev = DeviceData(id="relay")
    process_info_into_dev(parse_id_output(ID_351S), dev)
    process_scl_into_dev(parse_scl(_minimal_scl()), dev)

    assert "mismatches" not in dev.extra["iec61850"]
    assert "is different from the" not in caplog.text


def test_selascii_get_id(mocker):
    dev = datastore.get("192.0.2.80", "ip")
    comm = mocker.Mock(type="Telnet", address="192.0.2.80")
    comm.get_id.return_value = parse_id_output(
        "\r\n".join(
            [
                format_record(["FID=SEL-751-R300-V3-Z008004-D20210104"]),
                format_record(["iedName =TEMPLATE"]),
                format_record(["type =SEL_751"]),
                format_record(["LIB61850ID=0011AABB"]),
            ]
        )
    )

    assert SELRelay._selascii_get_id(dev, comm)

    assert dev.extra["iec61850"]["ied_name"] == "TEMPLATE"
    assert dev.extra["iec61850"]["ied_type"] == "SEL_751"
    assert dev.extra["iec61850"]["lib61850_id"] == "0011AABB"
    assert dev.extra["iedName"] == "TEMPLATE"


# ---------------------------------------------------------------------------
# CID files in pulls and parses
# ---------------------------------------------------------------------------


class FakeFTP(FTP):
    """A relay's FTP server, with the files in memory."""

    def __init__(self, files: dict[str, bytes], ip: str) -> None:
        super().__init__(ip)
        self.files = files

    def nlst_files(self, directory: str | None = None) -> list[str]:
        if not directory:
            return sorted({path.split("/")[0] for path in self.files})
        return sorted(
            path.split("/", 1)[1] for path in self.files if path.startswith(f"{directory}/")
        )

    def download_binary(self, filename, save_path=None, save_to_file=True) -> bytes | None:  # noqa: ARG002
        return self.files.get(filename)


def test_pull_configs_cid():
    raw = codecs.BOM_UTF8 + SCL_BYTES
    compressed = zlib.compress(raw, 6)
    dev = _dev()

    SELRelay.pull_configs(dev, FakeFTP({"SET_61850.CID": compressed}, ip="192.0.2.50"))

    (cid,) = _files(dev, "SET_61850.CID")
    assert cid.hash.dict(exclude_none=True) == _hashes(compressed)

    # The decompressed data is saved exactly as it was decompressed
    (decompressed,) = _files(dev, "SET_61850_decompressed.xml")
    assert decompressed.hash.dict(exclude_none=True) == _hashes(raw)
    assert decompressed.local_path.read_bytes() == raw
    assert decompressed.extra["source"] == "derived"
    assert decompressed.extra["derived_from"] == ["SET_61850.CID"]
    assert decompressed.extra["zlib_header"] == "789C"
    assert set(_hashes(raw).values()) <= dev.related.hash

    assert dev.extra["iec61850"]["scl"]["file"] == "SET_61850.CID"
    assert dev.extra["iec61850"]["ied_name"] == "SEL_751_1"
    assert [s.port for s in _services(dev)] == [102]


def test_pull_configs_uncompressed_cid_other_manufacturer(caplog):
    # Files downloaded from the relay are processed, whatever the manufacturer
    xml = _minimal_scl(name="IED1", ied_type="X1", manufacturer="Other")
    dev = _dev()

    SELRelay.pull_configs(dev, FakeFTP({"SET_61850.CID": xml.encode()}, ip="192.0.2.50"))

    assert dev.extra["iec61850"]["ied_name"] == "IED1"
    assert dev.extra["iec61850"]["manufacturer"] == "Other"
    assert "it isn't from a SEL relay" not in caplog.text
    # It isn't compressed, so it's not saved again
    assert not [f for f in dev.files if "decompressed" in f.name]


def test_parse_cid_file(tmp_path):
    path = tmp_path / "SET_61850.CID"
    path.write_bytes(zlib.compress(SCL_BYTES, 9) + b"\x00\x00")

    dev = SELRelay.parse(path)

    assert dev.name == "SEL_751_1"
    assert dev.extra["iec61850"]["ied_type"] == "SEL_751"
    assert _files(dev, "SET_61850.CID")[0].extra["source"] == "parse_input"
    (decompressed,) = _files(dev, "SET_61850_decompressed.xml")
    assert decompressed.hash.dict(exclude_none=True) == _hashes(SCL_BYTES)
    assert decompressed.extra["trailing_bytes"] == 2
    assert {"192.0.2.50", "192.0.2.51"} <= dev.related.ip


def test_parse_uncompressed_cid_file(tmp_path):
    path = tmp_path / "relay.cid"
    path.write_bytes(SCL_BYTES)

    dev = SELRelay.parse(path)

    assert dev.extra["iec61850"]["ied_name"] == "SEL_751_1"
    # It isn't compressed, so it's not saved again
    assert not [f for f in dev.files if "decompressed" in f.name]


def test_parse_uncompressed_cid_other_manufacturer(tmp_path, caplog):
    path = tmp_path / "OTHER.CID"
    path.write_text(_minimal_scl(name="IED1", ied_type="X1", manufacturer="Other"))

    assert SELRelay.parse(path) is None
    assert "it isn't from a SEL relay" in caplog.text


def test_parse_cid_file_with_dtd(tmp_path, caplog):
    xml = SCL_XML.replace("<SCL ", '<!DOCTYPE SCL [<!ENTITY a "a">]>\n<SCL ', 1)
    path = tmp_path / "SET_61850.CID"
    path.write_bytes(zlib.compress(xml.encode()))

    dev = SELRelay.parse(path)

    # The decompressed file is saved, but it isn't parsed
    assert _files(dev, "SET_61850_decompressed.xml")
    assert "scl" not in dev.extra.get("iec61850", {})
    assert "document type or entity declaration" in caplog.text


def test_parse_dir_with_cid(tmp_path):
    relay = tmp_path / "relay_files"
    relay.mkdir()
    (relay / "SET_61850.CID").write_bytes(zlib.compress(SCL_BYTES))

    dev = SELRelay.parse(relay)

    assert dev.extra["iec61850"]["ied_name"] == "SEL_751_1"
    assert _files(dev, "SET_61850_decompressed.xml")


def test_parse_dir_with_two_cids(tmp_path, caplog):
    relay = tmp_path / "relay_files"
    relay.mkdir()
    (relay / "SET_61850.CID").write_bytes(zlib.compress(SCL_BYTES))
    old = _minimal_scl(name="SEL_751_OLD", version="ICD-751-R099-V0-Z000000-D20190101")
    (relay / "SET_61850_OLD.CID").write_bytes(zlib.compress(old.encode()))

    dev = SELRelay.parse(relay)

    iec = dev.extra["iec61850"]
    assert iec["scl"]["file"] == "SET_61850.CID"
    assert iec["ied_name"] == "SEL_751_1"
    assert [s["file"] for s in iec["other_scl_files"]] == ["SET_61850_OLD.CID"]
    assert _files(dev, "SET_61850_decompressed.xml")
    assert _files(dev, "SET_61850_OLD_decompressed.xml")
    assert "has more than one SCL file" in caplog.text


def test_process_cid_file_text_transfer(caplog):
    dev = DeviceData(id="relay")
    path = PurePosixPath("/SET_61850.CID")

    # A compressed file read with FILE SHOW over Telnet
    assert process_cid_file("x\u0153\u2018\u2019 garbled", path, dev) == ""
    assert "download it with FTP or YMODEM" in caplog.text
    assert dev.files == []

    # A text file that's XML is parsed
    assert process_cid_file(SCL_XML, path, dev) == SCL_XML
    assert dev.extra["iec61850"]["ied_name"] == "SEL_751_1"


def test_process_cid_file_truncated(caplog):
    dev = DeviceData(id="relay")
    compressed = zlib.compress(SCL_BYTES)

    extracted = process_cid_file(compressed[:-60], PurePosixPath("/SET_61850.CID"), dev)

    assert extracted
    assert SCL_XML.startswith(extracted)
    (decompressed,) = _files(dev, "SET_61850_decompressed.xml")
    assert decompressed.extra["incomplete"] is True
    assert "may be incomplete or corrupted" in caplog.text
    assert "Failed to parse the IEC 61850 SCL" in caplog.text


def test_process_cid_file_not_xml(caplog):
    dev = DeviceData(id="relay")

    assert process_cid_file(zlib.compress(b"plain text"), PurePosixPath("A.CID"), dev)

    assert _files(dev, "A_decompressed.txt")
    assert "doesn't have XML data" in caplog.text
    assert "iec61850" not in dev.extra


def test_process_cid_file_errors(caplog):
    dev = DeviceData(id="relay")

    assert process_cid_file(b"", PurePosixPath("A.CID"), dev) == ""
    assert process_cid_file(b"\x00\x01\x02", PurePosixPath("A.CID"), dev) == ""
    assert "Failed to extract CID file A.CID" in caplog.text
    assert dev.files == []


@pytest.mark.parametrize("data", [b"\x78\x01", zlib.compress(SCL_BYTES)[:3]])
def test_process_cid_file_nothing_decompressed(data, caplog):
    dev = DeviceData(id="relay")

    assert process_cid_file(data, PurePosixPath("A.CID"), dev) == ""

    # No empty "decompressed" file is saved
    assert dev.files == []
    assert "Failed to extract CID file A.CID: nothing could be decompressed" in caplog.text
    assert "iec61850" not in dev.extra


def test_process_cid_file_empty(caplog):
    dev = DeviceData(id="relay")

    assert process_cid_file(zlib.compress(b""), PurePosixPath("A.CID"), dev) == ""

    assert dev.files == []
    assert "No data extracted from CID file A.CID" in caplog.text


def test_module_exports():
    for name in sel_scl.__all__:
        assert hasattr(sel_scl, name)
    assert relay_parse.extract_cid_content is extract_cid_content
