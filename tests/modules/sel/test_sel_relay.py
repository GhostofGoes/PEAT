import zlib

from peat import DeviceData
from peat.data.models import Service
from peat.modules.sel import relay_parse, sel_relay
from peat.modules.sel.sel_relay import SELRelay

CID_XML = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n'
    b'<SCL xmlns="http://www.iec.ch/61850/2003/SCL">'
    b'<Header id="SEL_751" toolID="IEC 61850 configurator"/></SCL>'
)


def _cid_signature():
    (sig,) = [s for s in SELRelay.file_signatures if s.default_filename == "SET_61850.CID"]
    return sig


def _as_7801(compressed: bytes) -> bytes:
    # 0x7801 is a valid zlib header (the level bits are informational only)
    return b"\x78\x01" + compressed[2:]


def test_cid_signature_matches_real_cid():
    cid = zlib.compress(CID_XML, 0)
    assert cid[:2] == b"\x78\x01"
    assert _cid_signature().matches(cid)
    assert relay_parse.extract_cid_content(cid) == CID_XML.decode()


def test_cid_signature_does_not_inflate_wrong_magic(mocker):
    """The custom check must not decompress files that fail the magic number check."""
    decompress = mocker.spy(zlib, "decompress")
    decompressobj = mocker.spy(zlib, "decompressobj")

    # Valid zlib data (with a different header) containing a real CID
    assert not _cid_signature().matches(zlib.compress(CID_XML, 9))
    assert not _cid_signature().matches(b"not a CID file" * 100)
    assert decompress.call_count == 0
    assert decompressobj.call_count == 0


def test_cid_signature_bomb(mocker):
    mocker.patch.object(sel_relay, "MAX_CID_CHECK_INFLATE", 1024 * 1024, create=True)
    bomb = _as_7801(zlib.compress(CID_XML + b" " * (8 * 1024 * 1024), 9))
    assert len(bomb) < 20_000
    assert not _cid_signature().matches(bomb)


def test_setup_ftp_does_not_log_password(mocker, log_messages):
    dev = DeviceData(ip="192.0.2.1")
    dev._module = SELRelay
    dev._runtime_options["ftp"] = {"creds": [("FTPUSER", "Ftp-UNIQUE-pw")]}
    dev.store("service", Service(port=21, transport="tcp", status="open"), lookup="port")

    ftp = mocker.MagicMock()
    ftp.__enter__.return_value.login.return_value = False
    mocker.patch.object(sel_relay, "FTP", return_value=ftp)

    assert SELRelay._setup_ftp(dev) is False
    assert any("FTPUSER" in m for m in log_messages)
    assert not any("Ftp-UNIQUE-pw" in m for m in log_messages)
