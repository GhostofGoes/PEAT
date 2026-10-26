import pytest

from peat.protocols.enip import EnipSocket
from peat.protocols.enip.enip_const import EnipCommError


def test_enip_socket_class():
    e_sock = EnipSocket("127.0.0.1", 44818, 1.0)
    assert "127.0.0.1" in str(e_sock)
    assert "127.0.0.1" in repr(e_sock)
    assert "1.0" in repr(e_sock)


class _FakeSocket:
    """Returns the given chunks from recv(), then b"" (connection closed)."""

    def __init__(self, chunks):
        self.chunks = list(chunks)

    def recv(self, size):
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        if len(chunk) > size:  # Like a real socket, the rest is returned later
            self.chunks.insert(0, chunk[size:])
        return chunk[:size]


def _enip_socket(chunks) -> EnipSocket:
    e_sock = EnipSocket("127.0.0.1", 44818, 1.0)
    e_sock.sock.close()
    e_sock.sock = _FakeSocket(chunks)
    return e_sock


@pytest.mark.parametrize(
    "chunks", [[b"\x6f"], [b"\x6f\x00\x04"], [b"\x6f\x00\x04\x00" + b"\x00" * 20]]
)
def test_enip_socket_receive_truncated(chunks):
    # Previously, a short first chunk raised struct.error instead of EnipCommError
    with pytest.raises(EnipCommError):
        _enip_socket(chunks).receive()


def test_enip_socket_receive_split_header():
    header = b"\x6f\x00\x04\x00" + b"\x00" * 20
    body = b"\x01\x02\x03\x04"
    message = header + body
    # Delivered one byte at a time
    assert _enip_socket([bytes([b]) for b in message]).receive() == message
    assert _enip_socket([message[:3], message[3:26], message[26:]]).receive() == message
