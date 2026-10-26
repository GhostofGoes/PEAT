import time

import pytest

from peat.modules.ge import ge_rtu
from peat.modules.ge.ge_rtu import D25Telnet


class _FakeSock:
    """Telnet socket of a D25 whose Digital Input menu never reaches the last page."""

    def __init__(self, pages: list[bytes], endless: bytes | None = None) -> None:
        self.pages = list(pages)
        self.endless = endless
        self.sent = []

    def send(self, data: bytes) -> int:
        self.sent.append(data)
        if len(self.sent) > 5000:
            raise RuntimeError("still reading after 5000 pages")
        return len(data)

    def recv(self, _size: int) -> bytes:
        if self.pages:
            return self.pages.pop(0)
        return self.endless if self.endless is not None else b""


def _telnet(sock: _FakeSock) -> D25Telnet:
    telnet = D25Telnet("127.0.0.1", menu_sleep_seconds=0)
    telnet.sock = sock
    return telnet


def test_digital_inputs_last_page():
    sock = _FakeSock([b"DI 1  ON", b"garbage", b"DI 2  OFF", b"DI 3  ON", b"  "])
    data = _telnet(sock).get_data_digital_io("I")
    assert data == "DI 1,ONDI 2,OFFDI 3,ON,"
    assert sock.sent == [b"b", b"n", b"n", b"n"]


@pytest.mark.parametrize("endless", [b"DI 9  ON", b""])
def test_digital_inputs_endless_or_closed(mocker, endless):
    """A device that never sends the last page (or closed the connection)."""
    mocker.patch.object(ge_rtu, "MAX_MENU_PAGES", 100, create=True)
    sock = _FakeSock([b"DI 1  ON", b"garbage"], endless=endless)
    _telnet(sock).get_data_digital_io("I")
    assert len(sock.sent) <= 101


def test_digital_inputs_deadline(mocker):
    """500 pages just under the timeout each (plus the menu sleeps) could take hours."""
    sock = _FakeSock([b"DI 1  ON", b"garbage"], endless=b"DI 9  ON")
    original_recv = sock.recv

    def slow_recv(size: int) -> bytes:
        time.sleep(0.01)
        return original_recv(size)

    mocker.patch.object(sock, "recv", side_effect=slow_recv)
    telnet = D25Telnet("127.0.0.1", menu_sleep_seconds=0, menu_read_deadline=0.2)
    telnet.sock = sock

    start = time.monotonic()
    telnet.get_data_digital_io("I")
    assert time.monotonic() - start < 1.0
    assert 2 <= len(sock.sent) < 100
    assert D25Telnet("127.0.0.1").menu_read_deadline == ge_rtu.MENU_READ_DEADLINE
