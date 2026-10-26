import socket
import struct
import threading
import time

import pytest

from peat import CommError, DeviceError, config, datastore
from peat.modules.schneider.m340 import m340
from peat.modules.schneider.m340.m340 import M340


def _frame(umas: bytes) -> bytes:
    """Modbus/TCP frame (function code 90) carrying a UMAS payload."""
    return struct.pack(">HHH", 1, 0, len(umas) + 2) + bytes([0, 90]) + umas


def _block(load: bytes, num: int = 0, data_len: int | None = None) -> bytes:
    """UMAS response: connection code, command code 0xFE, num, dataLen, data."""
    if data_len is None:
        data_len = len(load)
    return _frame(
        bytes([0x00, 0xFE]) + struct.pack(">H", num) + struct.pack("<H", data_len) + load
    )


class _FakeUMASDevice:
    """
    Minimal fake M340 that answers project download (0x34) requests with the
    data returned by ``blocks(n)`` for the n-th request (None closes the connection).
    """

    def __init__(self, blocks, max_requests: int = 2000) -> None:
        self.blocks = blocks
        self.max_requests = max_requests  # stops a runaway client
        self.requests = 0
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        conn, _ = self.sock.accept()
        with conn:
            while True:
                try:
                    req = conn.recv(4096)
                except OSError:
                    return
                if not req:
                    return
                command = req[9] if len(req) > 9 else 0
                if command == 0x10:  # connect
                    conn.sendall(_frame(bytes([0x00, 0xFE, 0x05])))
                elif command == 0x34:  # download block
                    self.requests += 1
                    if self.requests > self.max_requests:
                        return
                    for part in self.blocks(self.requests):
                        if part is None:  # close the connection
                            return
                        conn.sendall(part)
                        time.sleep(0.01)
                else:  # poll, start/stop download
                    conn.sendall(_block(b"\x00" * 8 if command == 0x33 else b""))


@pytest.fixture
def m340_dev(mocker, tmp_path):
    mocker.patch.object(datastore, "objects", [])
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path / "devices", "DEBUG": 0})

    def _setup(device: _FakeUMASDevice) -> None:
        dev = datastore.get("127.0.0.1")
        dev._runtime_options["modbus_tcp"] = {"port": device.port, "timeout": 5}

    return _setup


def test_pull_apx_file(m340_dev):
    def blocks(n):
        if n < 3:
            return [_block(bytes([n]) * 1000)]
        # Last block, split into two TCP segments
        last = _block(b"END", num=0x01)
        return [last[:7], last[7:]]

    device = _FakeUMASDevice(blocks)
    m340_dev(device)
    assert M340.pull_apx_file("127.0.0.1") == b"\x01" * 1000 + b"\x02" * 1000 + b"END"
    assert device.requests == 3


def test_pull_apx_file_endless_device(m340_dev, mocker):
    """A device that never says the download is finished must not keep PEAT looping."""
    mocker.patch.object(m340, "MAX_APX_BLOCKS", 50, create=True)
    device = _FakeUMASDevice(lambda _n: [_block(b"A" * 1000)], max_requests=500)
    m340_dev(device)

    with pytest.raises(DeviceError, match="without finishing"):
        M340.pull_apx_file("127.0.0.1")
    assert device.requests == 50


def test_pull_apx_file_size_limit(m340_dev, mocker):
    mocker.patch.object(m340, "MAX_APX_SIZE", 20_000, create=True)
    device = _FakeUMASDevice(lambda _n: [_block(b"A" * 1000)], max_requests=500)
    m340_dev(device)

    with pytest.raises(DeviceError, match="without finishing"):
        M340.pull_apx_file("127.0.0.1")
    assert device.requests == 21


def test_pull_apx_file_length_mismatch(m340_dev):
    device = _FakeUMASDevice(lambda _n: [_block(b"A" * 10, data_len=4000)])
    m340_dev(device)

    with pytest.raises(DeviceError, match="length field is 4000"):
        M340.pull_apx_file("127.0.0.1")
    assert device.requests == 1


@pytest.mark.parametrize(
    "response",
    [
        _frame(b"\x00\xfe\x00"),  # truncated: no dataLen
        _frame(b"\x00\xfe\x00\x00\x10"),  # truncated: half of dataLen
    ],
)
def test_pull_apx_file_truncated_response(m340_dev, response):
    device = _FakeUMASDevice(lambda _n: [response])
    m340_dev(device)

    with pytest.raises((DeviceError, CommError)):
        M340.pull_apx_file("127.0.0.1")
    assert device.requests == 1


def test_pull_apx_file_connection_closed_mid_frame(m340_dev):
    device = _FakeUMASDevice(lambda _n: [_block(b"A" * 100)[:20], None])
    m340_dev(device)

    with pytest.raises(CommError, match="Connection closed"):
        M340.pull_apx_file("127.0.0.1")
