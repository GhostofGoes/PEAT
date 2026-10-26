import struct
import time

import pytest

from peat.modules.rockwell import clx_cip
from peat.modules.rockwell.clx_cip import ClxCIP
from peat.protocols.data_packing import unpack_bool


def test_clx_cip_class():
    assert "127.0.0.1" in str(ClxCIP("127.0.0.1", 44818, 1.0, 1))
    assert "127.0.0.1" in repr(ClxCIP("127.0.0.1", 44818, 1.0, 1))


INSUFFICIENT_SPACE = 0x06


class _MockDriver:
    """Stands in for EnipDriver, replying with ``replies(n)`` for the n-th request."""

    def __init__(self, replies, max_requests: int = 2000) -> None:
        self.replies = replies
        self.max_requests = max_requests  # stops a runaway loop
        self.requests = []

    def send_connected_command(self, service, path, cmd_data):
        self.requests.append((service, path, cmd_data))
        if len(self.requests) > self.max_requests:
            raise RuntimeError(f"still looping after {self.max_requests} requests")
        return self.replies(len(self.requests))


def _cip(replies, max_requests: int = 2000) -> clx_cip.ClxCIP:
    cip = clx_cip.ClxCIP("127.0.0.1", 44818)
    cip.driver = _MockDriver(replies, max_requests)
    return cip


def _reply(service: int, status: int, data: bytes = b"") -> bytes:
    return bytes([service, 0, status, 0]) + data


def _ids(*ids: int) -> bytes:
    return b"".join(struct.pack("<i", i) for i in ids)


def test_get_instance_list():
    def replies(n):
        if n == 1:
            return _reply(0xCB, INSUFFICIENT_SPACE, _ids(1, 2, 3))
        return _reply(0xCB, 0, _ids(10, 11))

    cip = _cip(replies)
    buffer = bytes(cip.get_instance_list_tag_buffer((0x6B,)))
    assert clx_cip.parse_get_instance_list(buffer) == [1, 2, 3, 10, 11]
    assert len(cip.driver.requests) == 2
    assert cip.driver.requests[1][1] == clx_cip.path_to_string((0x6B, 4))


@pytest.mark.parametrize(
    "data",
    [
        _ids(-1),  # next instance is 0 again: the same request forever
        _ids(5, 3),  # (after the first reply) next instance doesn't increase
        _ids(0x7FFFFFFE),  # next instance doesn't fit in the request path
        b"",  # max() of nothing
        b"\x01\x02\x03",  # not a multiple of 4
    ],
)
def test_get_instance_list_hostile_device(data):
    cip = _cip(lambda _n: _reply(0xCB, INSUFFICIENT_SPACE, data))
    cip.get_instance_list_tag_buffer((0x6B,))
    assert len(cip.driver.requests) <= 2


def test_get_instance_list_request_limit(mocker):
    mocker.patch.object(clx_cip, "MAX_REQUESTS_PER_READ", 100, create=True)
    # Always "more data" with increasing instance IDs
    cip = _cip(lambda n: _reply(0xCB, INSUFFICIENT_SPACE, _ids(n)), max_requests=1000)
    cip.get_instance_list_tag_buffer((0x6B,))
    assert len(cip.driver.requests) == 100


@pytest.mark.parametrize("method", ["read_tag", "read_tag_fragmented"])
def test_read_tag_no_progress(method):
    """Replies with no data (so the offset never advances) must not loop forever."""
    if method == "read_tag":
        reply = _reply(0xCC, INSUFFICIENT_SPACE, b"\x00" * 4)
    else:
        reply = _reply(0xD2, INSUFFICIENT_SPACE, b"\x00" * 8)  # tag address only
    cip = _cip(lambda _n: reply)
    getattr(cip, method)((0x6B, 1))
    assert len(cip.driver.requests) <= 2


def test_read_tag_request_limit(mocker):
    mocker.patch.object(clx_cip, "MAX_REQUESTS_PER_READ", 100, create=True)
    reply = _reply(0xCC, INSUFFICIENT_SPACE, b"\x00" * 4 + b"\xaa" * 4)  # always more data
    cip = _cip(lambda _n: reply, max_requests=1000)
    assert cip.read_tag((0x6B, 1)) == [0xAA] * 400
    assert len(cip.driver.requests) == 100


def test_read_template_size_handling():
    # The device returns more data than the template size, then keeps going
    reply = _reply(0xCC, INSUFFICIENT_SPACE, b"\x00" * 4 + b"\xaa" * 400)
    cip = _cip(lambda _n: reply)
    cip.read_template((0x6C, 1), size=50)
    assert len(cip.driver.requests) == 1

    # A size larger than the 16-bit request field
    cip = _cip(lambda _n: _reply(0xCC, 0, b"\x00" * 4 + b"\xaa" * 4))
    cip.read_template((0x6C, 1), size=0x12345)
    assert len(cip.driver.requests) == 1


def test_get_attributes_no_progress():
    reply = _reply(0x83, INSUFFICIENT_SPACE, b"\x00\x00")  # attribute count of 0
    cip = _cip(lambda _n: reply)
    cip.get_attributes_tag_buffer((0x6B, 1), [1, 2, 3])
    assert len(cip.driver.requests) <= 2


@pytest.mark.parametrize("path", [(0x6B, 0x10000), (0x6B, -5), (0x10000, 1), (0x6B,)])
def test_path_to_string_invalid(path):
    with pytest.raises(ValueError, match="CIP"):
        clx_cip.path_to_string(path)


def test_path_to_string():
    assert clx_cip.path_to_string((0x6B, 1)) == b"\x02\x20\x6b\x24\x01"
    assert clx_cip.path_to_string((0x6B, 0x1234)) == b"\x03\x20\x6b\x25\x00\x34\x12"


def test_unpack_bool():
    assert unpack_bool(b"\xff") == 1
    assert unpack_bool(b"\x01") == 1
    assert unpack_bool(b"\x00") == 0
    with pytest.raises(struct.error):
        unpack_bool(b"")


def _slow_cip(reply, delay: float = 0.02, read_deadline: float = 0.2) -> clx_cip.ClxCIP:
    """A device that always has more data, but replies slowly."""

    def replies(n):
        time.sleep(delay)
        return reply(n)

    cip = clx_cip.ClxCIP("127.0.0.1", 44818, read_deadline=read_deadline)
    cip.driver = _MockDriver(replies, max_requests=1000)
    return cip


@pytest.mark.parametrize(
    ("method", "args", "reply"),
    [
        (
            "get_instance_list_tag_buffer",
            ((0x6B,),),
            lambda n: _reply(0xCB, INSUFFICIENT_SPACE, _ids(n)),
        ),
        (
            "get_attributes_tag_buffer",
            ((0x6B, 1), list(range(1000))),
            lambda _n: _reply(0x83, INSUFFICIENT_SPACE, b"\x01\x00\xaa\xaa"),
        ),
        (
            "read_tag",
            ((0x6B, 1),),
            lambda _n: _reply(0xCC, INSUFFICIENT_SPACE, b"\x00" * 4 + b"\xaa" * 4),
        ),
        (
            "read_tag_fragmented",
            ((0x6B, 1),),
            lambda _n: _reply(0xD2, INSUFFICIENT_SPACE, b"\x00" * 8 + b"\xaa" * 4),
        ),
        (
            "read_template",
            ((0x6C, 1), 0xFFFF),
            lambda _n: _reply(0xCC, INSUFFICIENT_SPACE, b"\x00" * 4 + b"\xaa" * 4),
        ),
    ],
)
def test_multi_request_read_deadline(method, args, reply):
    """Up to 10,000 requests just under the timeout each could take many hours."""
    cip = _slow_cip(reply)
    start = time.monotonic()
    getattr(cip, method)(*args)
    assert time.monotonic() - start < 1.0
    assert 2 <= len(cip.driver.requests) < 50


def test_read_deadline_default():
    assert clx_cip.ClxCIP("127.0.0.1", 44818).read_deadline == clx_cip.READ_DEADLINE == 60.0
