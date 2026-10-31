import pytest

from peat import CommError, config
from peat.protocols import telnet
from peat.protocols.cache import data_cache


def test_telnet_class(mocker, tmp_path):
    mocker.patch.dict(config["CONFIG"], {"LOG_DIR": tmp_path})
    ip = "127.0.0.1"
    tn = telnet.Telnet(ip)
    assert str(tn) == ip
    assert not tn.connected


class FakeTelnetlib:
    """Minimal stand-in for telnetlib.Telnet that returns scripted data."""

    def __init__(self, reads: list[bytes], fail_open: bool = False) -> None:
        self.reads = list(reads)
        self.fail_open = fail_open
        self.written: list[bytes] = []
        self.opened = 0

    def open(self, host, port, timeout) -> None:  # noqa: ARG002
        if self.fail_open:
            raise OSError("connection refused")
        self.opened += 1

    def read_very_eager(self) -> bytes:
        return self.reads.pop(0) if self.reads else b""

    def read_until(self, match, timeout=None) -> bytes:  # noqa: ARG002
        return self.read_very_eager()

    def write(self, data: bytes) -> None:
        self.written.append(data)

    def close(self) -> None:
        pass


@pytest.fixture
def _fast_telnet(mocker, tmp_path):
    mocker.patch.dict(config["CONFIG"], {"LOG_DIR": tmp_path})
    mocker.patch.object(telnet, "sleep")
    mocker.patch.object(telnet.peat.data.datastore, "get")  # don't write files


def make_telnet(reads, fail_open=False, port=23) -> tuple[telnet.Telnet, FakeTelnetlib]:
    tn = telnet.Telnet("192.0.2.23", port)
    fake = FakeTelnetlib(reads, fail_open)
    tn.comm = fake
    return tn, fake


@pytest.mark.usefixtures("_fast_telnet")
def test_banner_captured_before_first_write():
    tn, _ = make_telnet([b"VxWorks login: ", b"more\r\n", b"Password: "])
    assert tn.read() == "VxWorks login:"
    assert tn.read() == "more"
    tn.write("admin")
    assert tn.read() == "Password:"
    assert tn.banner == "VxWorks login: more\r\n"
    assert telnet.Telnet.cached_banner("192.0.2.23") == "VxWorks login: more\r\n"
    assert telnet.Telnet.cached_banner("192.0.2.23", 2323) is None
    assert data_cache.get(telnet.Telnet.banner_key("192.0.2.23", 23)) == b"VxWorks login: more\r\n"
    tn.disconnect()


@pytest.mark.usefixtures("_fast_telnet")
def test_banner_captured_on_disconnect():
    tn, _ = make_telnet([b"=>"])
    tn.read()
    assert telnet.Telnet.cached_banner("192.0.2.23") is None
    tn.disconnect()
    assert telnet.Telnet.cached_banner("192.0.2.23") == "=>"


@pytest.mark.usefixtures("_fast_telnet")
def test_write_before_read_has_no_banner():
    tn, fake = make_telnet([b"response"])
    tn.write("ID")
    assert fake.written == [b"ID\r\n"]
    tn.read()
    tn.disconnect()
    assert tn.banner is None
    assert telnet.Telnet.cached_banner("192.0.2.23") is None


@pytest.mark.usefixtures("_fast_telnet")
def test_get_banner_reads_and_caches():
    tn, fake = make_telnet([b"Welcome\r\nlogin: "])
    assert tn.get_banner() == "Welcome\r\nlogin: "
    assert fake.opened == 1
    # Already captured: served from the cache without reading
    assert tn.get_banner() == "Welcome\r\nlogin: "
    tn.disconnect()


@pytest.mark.usefixtures("_fast_telnet")
def test_get_banner_served_from_cache_without_connecting():
    first, _ = make_telnet([b"SEL-751\r\n=>"])
    first.get_banner()
    first.disconnect()

    second, fake = make_telnet([], fail_open=True)
    assert second.get_banner() == "SEL-751\r\n=>"
    assert fake.opened == 0
    assert not second.connected


@pytest.mark.usefixtures("_fast_telnet")
def test_get_banner_use_cache_false_reads_connection():
    data_cache.put(telnet.Telnet.banner_key("192.0.2.23", 23), b"old banner")
    tn, fake = make_telnet([b"new banner"])
    assert tn.get_banner(use_cache=False) == "new banner"
    assert fake.opened == 1
    assert telnet.Telnet.cached_banner("192.0.2.23") == "new banner"
    tn.disconnect()


@pytest.mark.usefixtures("_fast_telnet")
def test_get_banner_after_input_returns_captured():
    tn, _ = make_telnet([b"login: ", b"after input"])
    tn.read()
    tn.write("user")
    assert tn.get_banner(use_cache=False) == "login: "
    tn.disconnect()


@pytest.mark.usefixtures("_fast_telnet")
def test_get_banner_connect_failure():
    tn, _ = make_telnet([], fail_open=True)
    with pytest.raises(CommError):
        tn.get_banner()


@pytest.mark.usefixtures("_fast_telnet")
def test_banner_not_cached_when_disabled(mocker):
    mocker.patch.dict(config["CONFIG"], {"CACHE_ENABLED": False})
    tn, _ = make_telnet([b"login: "])
    assert tn.get_banner() == "login: "
    tn.disconnect()
    assert len(data_cache) == 0
    assert telnet.Telnet.cached_banner("192.0.2.23") is None


@pytest.mark.usefixtures("_fast_telnet")
def test_banner_reset_on_reconnect():
    tn, fake = make_telnet([b"first", b"x", b"second"])
    tn.read()
    tn.write("cmd")
    tn.read()
    tn.disconnect()
    fake.reads = [b"second banner"]
    tn.read()
    tn.disconnect()
    assert tn.banner == "second banner"
    assert telnet.Telnet.cached_banner("192.0.2.23") == "second banner"


@pytest.mark.usefixtures("_fast_telnet")
def test_banner_size_is_bounded(mocker):
    mocker.patch.object(telnet.Telnet, "BANNER_MAX_BYTES", 10)
    tn, _ = make_telnet([b"0123456789abcdef"])
    assert tn.get_banner() == "0123456789"
    tn.disconnect()
    assert telnet.Telnet.cached_banner("192.0.2.23") == "0123456789"


@pytest.mark.usefixtures("_fast_telnet")
def test_write_raw_marks_input_sent():
    tn, fake = make_telnet([b"login: ", b"reply to raw write"])
    assert tn.read() == "login:"
    tn.write_raw(b"raw\x00bytes")
    assert fake.written == [b"raw\x00bytes"]  # sent as-is, no line terminator
    assert tn.read() == "reply to raw write"
    tn.disconnect()
    assert tn.banner == "login: "
    assert telnet.Telnet.cached_banner("192.0.2.23") == "login: "


@pytest.mark.usefixtures("_fast_telnet")
def test_write_raw_before_read_has_no_banner():
    tn, fake = make_telnet([b"response"])
    tn.write_raw(b"cmd\r\n")
    assert fake.opened == 1  # connects first
    assert tn.read() == "response"
    tn.disconnect()
    assert tn.banner is None
    assert telnet.Telnet.cached_banner("192.0.2.23") is None


@pytest.mark.usefixtures("_fast_telnet")
def test_pre_input_data_is_bounded(mocker):
    mocker.patch.object(telnet.Telnet, "BANNER_MAX_BYTES", 10)
    tn, _ = make_telnet([b"0123456"] * 50)
    for _ in range(50):
        tn.read()
    # Data that can't be part of the banner isn't kept a second time
    assert sum(len(chunk) for chunk in tn._pre_input_raw) < 20
    assert len(tn.raw_output) == 50
    tn.disconnect()
    assert tn.banner == "0123456012"


@pytest.mark.usefixtures("_fast_telnet")
def test_sel_telnet_banner_excludes_session_data(mocker):
    """SELTelnet writes through SELAscii.write(), so it must still end the banner."""
    from peat.modules.sel import sel_ascii, sel_telnet

    mocker.patch.object(sel_ascii, "sleep")
    mocker.patch.object(sel_telnet, "sleep")

    sel = sel_telnet.SELTelnet("192.0.2.50")
    sel.PRE_WRITE_SLEEP = 0
    sel.POST_WRITE_SLEEP = 0
    tn = sel.comm
    fake = FakeTelnetlib(
        [b"\r\n=", b"ACC\r\nPassword: ?", b"Level 1\r\n=>", b"SECRET FILE CONTENTS\r\n=>"]
    )
    tn.comm = fake

    assert sel.read() == "="
    sel.write("ACC")
    sel.read()
    sel.write("OTTER")
    sel.read()
    sel.write("fil show SET_1.TXT")
    assert "SECRET" in sel.read()

    # The banner is complete as soon as the first command is written
    assert tn.banner == "\r\n="
    assert tn._pre_input_raw == []
    sel.disconnect()

    assert fake.written[:3] == [b"ACC\r\n", b"OTTER\r\n", b"fil show SET_1.TXT\r\n"]
    assert tn.banner == "\r\n="
    assert telnet.Telnet.cached_banner("192.0.2.50") == "\r\n="
