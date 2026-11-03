"""
Tests for peat/protocols/expect.py (Expecter and the transport adapters)
and Telnet.expect() in peat/protocols/telnet.py.
"""

import re
import socket
import threading
import time

import pytest
import serial

from peat import config
from peat.protocols import Telnet
from peat.protocols import forked_telnetlib as telnetlib
from peat.protocols.expect import (
    Expecter,
    ExpectResult,
    channel_reader,
    compile_patterns,
    serial_reader,
    socket_reader,
    telnet_reader,
)


class ChunkReader:
    """read_chunk() that returns pre-defined chunks, with optional pauses."""

    def __init__(self, chunks: list[bytes | float | type[EOFError]]):
        self.chunks = list(chunks)
        self.calls = 0

    def __call__(self, wait: float) -> bytes:
        self.calls += 1
        while self.chunks:
            item = self.chunks[0]
            if item is EOFError:
                raise EOFError
            if isinstance(item, float):
                if wait < item:
                    self.chunks[0] = item - wait
                    time.sleep(wait)
                    return b""
                time.sleep(item)
                self.chunks.pop(0)
                continue
            return self.chunks.pop(0)
        time.sleep(min(wait, 0.01))
        return b""


@pytest.fixture
def pair():
    ours, theirs = socket.socketpair()
    yield ours, theirs
    for sock in (ours, theirs):
        try:
            sock.close()
        except OSError:
            pass


def test_match_split_across_chunks():
    exp = Expecter(ChunkReader([b"abc\r\n=", b">", b">\x03rest"]))
    result = exp.expect([rb"=>>\x03"], timeout=2.0)

    assert result.index == 0
    assert result.matched
    assert result.data == b"abc\r\n=>>\x03"
    assert result.before == b"abc\r\n"
    assert result.match.group(0) == b"=>>\x03"
    # Data after the match is kept for the next call
    assert exp.buffered == b"rest"
    assert exp.expect([b"rest"], timeout=0.5).data == b"rest"


def test_earliest_match_wins():
    exp = Expecter(ChunkReader([b"one Password: ? two =>"]))
    result = exp.expect([rb"=>", rb"Password: \?"], timeout=1.0)
    assert result.index == 1
    assert result.data == b"one Password: ?"


def test_same_position_first_pattern_wins():
    exp = Expecter(ChunkReader([b"=>>"]))
    assert exp.expect([rb"=>>", rb"=>"], timeout=1.0).index == 0
    exp = Expecter(ChunkReader([b"=>>"]))
    assert exp.expect([rb"=>", rb"=>>"], timeout=1.0).index == 0


def test_match_object_is_valid_after_consuming():
    exp = Expecter(ChunkReader([b"xx(?P<a>)", b"\x02\r\n=>>\x03yy"]))
    result = exp.expect([re.compile(rb"\x02\r\n(?P<prompt>=>>)\x03")], timeout=1.0)
    exp.expect([b"yy"], timeout=1.0)
    assert result.match.group("prompt") == b"=>>"


def test_timeout_returns_partial_data():
    exp = Expecter(ChunkReader([b"partial "]))
    started = time.monotonic()
    result = exp.expect([b"never"], timeout=0.3)

    assert time.monotonic() - started >= 0.3
    assert result.timed_out
    assert not result.matched
    assert result.index == -1
    assert result.data == b"partial "
    assert result.text() == "partial "
    assert exp.buffered == b""


def test_idle_timeout_resets_when_data_arrives():
    # 6 chunks 0.1 s apart (0.5 s total) never pause for the 0.25 s idle timeout
    chunks = []
    for i in range(6):
        chunks += [0.1, b"line %d\r\n" % i]
    exp = Expecter(ChunkReader([*chunks, b"END"]))
    result = exp.expect([b"END"], timeout=5.0, idle_timeout=0.25)
    assert result.matched
    assert result.data.count(b"line") == 6


def test_idle_timeout_stops_waiting():
    exp = Expecter(ChunkReader([b"start", 2.0, b"END"]))
    started = time.monotonic()
    result = exp.expect([b"END"], timeout=10.0, idle_timeout=0.2)
    assert result.timed_out
    assert result.data == b"start"
    assert time.monotonic() - started < 1.5


def test_eof():
    exp = Expecter(ChunkReader([b"bye", EOFError]))
    result = exp.expect([b"never"], timeout=2.0)
    assert result.eof
    assert result.data == b"bye"
    assert exp.eof
    # After EOF, nothing is read anymore
    assert exp.expect([b"x"], timeout=0.1).eof


def test_match_before_eof_is_returned():
    exp = Expecter(ChunkReader([b"Rebooting the relay\r\n", EOFError]))
    result = exp.expect([b"Rebooting"], timeout=1.0)
    assert result.matched
    assert not result.eof


def test_buffer_cap():
    exp = Expecter(ChunkReader([b"x" * 100] * 5), max_buffer=250)
    result = exp.expect([b"never"], timeout=2.0)
    assert result.overflow
    assert len(result.data) == 300
    assert not result.matched


def test_settle_waits_for_longer_match():
    # "=>" could be the start of "=>>": wait for more data before using it
    exp = Expecter(ChunkReader([b"\r\n=>", 0.05, b">"]))
    result = exp.expect([rb"\r\n(=>>|=>)\Z"], timeout=2.0, settle=0.3)
    assert result.match.group(1) == b"=>>"


def test_settle_uses_match_when_no_more_data():
    exp = Expecter(ChunkReader([b"\r\n=>"]))
    started = time.monotonic()
    result = exp.expect([rb"\r\n(=>>|=>)\Z"], timeout=2.0, settle=0.2)
    assert result.match.group(1) == b"=>"
    assert 0.15 < time.monotonic() - started < 1.0


def test_settle_per_pattern():
    exp = Expecter(ChunkReader([b"abc"]))
    started = time.monotonic()
    assert exp.expect([b"abc", b"zzz"], timeout=2.0, settle=[0.0, 5.0]).matched
    assert time.monotonic() - started < 0.5

    with pytest.raises(ValueError, match="one value per pattern"):
        exp.expect([b"a", b"b"], timeout=0.1, settle=[0.1])


def test_accept_callback_rejects_matches():
    exp = Expecter(ChunkReader([b"\x02data\r\n=>", 0.05, b"\r\nmore\x03\r\n=>"]))

    def accept(_index, match, buffer):
        # Not inside an open STX ... ETX message
        return buffer.rfind(b"\x02", 0, match.start()) <= buffer.rfind(b"\x03", 0, match.start())

    result = exp.expect([rb"\r\n=>"], timeout=2.0, accept=accept)
    assert result.data == b"\x02data\r\n=>\r\nmore\x03\r\n=>"


def test_window_limits_search():
    calls = []
    exp = Expecter(ChunkReader([b"a" * 1000, b"b" * 1000, b"END"]))
    original = exp._search

    def spy(patterns, pos, accept=None):
        calls.append(pos)
        return original(patterns, pos, accept)

    exp._search = spy
    assert exp.expect([b"END"], timeout=2.0, window=10).matched
    assert max(calls) >= 1990


def test_read_available_and_feed():
    exp = Expecter(ChunkReader([b"one", b"two"]))
    exp.feed(b"zero")
    assert exp.read_available() == b"zeroonetwo"
    assert exp.read_available() == b""


def test_on_data_and_compile_patterns():
    seen = []
    exp = Expecter(ChunkReader([b"abc"]), on_data=seen.append)
    assert exp.expect(["b"], timeout=1.0).data == b"ab"
    assert seen == [b"abc"]

    assert [p.pattern for p in compile_patterns(["x", b"y", re.compile(b"z")])] == [
        b"x",
        b"y",
        b"z",
    ]
    with pytest.raises(TypeError):
        compile_patterns([re.compile("text")])


def test_expect_result_without_match():
    result = ExpectResult(index=-1, match=None, data=b"abc\xff", timed_out=True)
    assert result.before == b"abc\xff"
    assert result.text() == "abc�"


def test_socket_reader(pair):
    ours, theirs = pair
    exp = Expecter(socket_reader(ours))

    def slow_sender():
        for byte in b"Password: ?":
            theirs.sendall(bytes([byte]))
            time.sleep(0.005)
        theirs.close()

    threading.Thread(target=slow_sender, daemon=True).start()
    result = exp.expect([rb"Password: \?"], timeout=3.0)
    assert result.data == b"Password: ?"
    # The other side closed the connection
    assert exp.expect([b"x"], timeout=2.0).eof


def test_serial_reader_loop():
    # pyserial's loop:// returns what's written
    port = serial.serial_for_url("loop://", timeout=0.1)
    exp = Expecter(serial_reader(port))

    def writer():
        for byte in b"id\r\n\x02\r\nFID=SEL-751\r\n\x03\x02\r\n=>\x03":
            port.write(bytes([byte]))
            time.sleep(0.002)

    thread = threading.Thread(target=writer, daemon=True)
    thread.start()
    result = exp.expect([rb"\x02\r\n(?P<prompt>=>)\x03"], timeout=3.0)
    thread.join()

    assert result.match.group("prompt") == b"=>"
    assert b"FID=SEL-751" in result.data
    assert serial_reader(port)(0.0) == b""
    port.close()


def test_serial_reader_error_is_eof():
    class BrokenPort:
        @property
        def in_waiting(self):
            raise serial.SerialException("device disconnected")

    with pytest.raises(EOFError, match="device disconnected"):
        serial_reader(BrokenPort())(0.1)


def test_channel_reader():
    class Channel:
        def __init__(self):
            self.data = [b"hello ", b"world"]
            self.closed = False

        def recv_ready(self):
            return bool(self.data)

        def recv(self, _size):
            return self.data.pop(0)

    channel = Channel()
    exp = Expecter(channel_reader(channel))
    assert exp.expect([b"world"], timeout=1.0).data == b"hello world"
    channel.closed = True
    assert exp.expect([b"x"], timeout=1.0).eof


def _serve(handler):
    """Serve one connection on 127.0.0.1 with handler(conn) in a thread."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)

    def run():
        conn, _ = listener.accept()
        try:
            handler(conn)
        finally:
            conn.close()
            listener.close()

    threading.Thread(target=run, daemon=True).start()
    return listener.getsockname()[1]


def test_telnet_reader_handles_negotiation():
    def handler(conn):
        # IAC DO ECHO, then data with an escaped 0xFF byte
        conn.sendall(bytes([255, 253, 1]) + b"data\xff\xff end")
        time.sleep(0.2)

    port = _serve(handler)
    tn = telnetlib.Telnet("127.0.0.1", port, timeout=2)
    exp = Expecter(telnet_reader(tn))
    result = exp.expect([b"end"], timeout=2.0)
    assert result.data == b"data\xff end"
    assert exp.expect([b"x"], timeout=2.0).eof
    tn.close()


def test_telnet_expect(tmp_path, mocker):
    mocker.patch.dict(config["CONFIG"], {"LOG_DIR": tmp_path, "DEVICE_DIR": tmp_path})
    received = []

    def handler(conn):
        conn.sendall(b"Password: ?")
        received.append(conn.recv(100))
        conn.sendall(b" ******\r\nLevel 1\r\n\x02\r\n=>\x03leftover")
        time.sleep(0.3)

    port = _serve(handler)
    tn = Telnet("127.0.0.1", port, timeout=2.0)
    tn.ENCODING = "ascii"

    first = tn.expect([rb"Password: \?"])
    assert first.index == 0
    tn.register_secret("Secret1")
    tn.write_raw(b"Secret1\r\n", sensitive=True)
    second = tn.expect([rb"\x02\r\n(?P<p>=>)\x03"], timeout=2.0)
    assert second.match.group("p") == b"=>"

    # read() returns what expect() left in the buffer
    assert tn.read(delay=0.0) == "leftover"
    assert tn.all_output[:2] == ["Password: ?", " ******\r\nLevel 1\r\n\x02\r\n=>\x03"]
    assert received == [b"Secret1\r\n"]

    # The end of the connection is in the result, not an exception
    assert tn.expect([b"never"], timeout=2.0).eof
    tn.disconnect()


def test_telnet_records_secrets_redacted(mocker, tmp_path):
    mocker.patch.dict(config["CONFIG"], {"LOG_DIR": tmp_path, "DEVICE_DIR": tmp_path})

    def handler(conn):
        conn.recv(100)
        # A device that echoes the password
        conn.sendall(b"MyPass99\r\n=>")
        time.sleep(0.3)

    port = _serve(handler)
    tn = Telnet("127.0.0.1", port, timeout=2.0)
    trace = mocker.spy(tn.comm.log, "trace3")
    tn.register_secret("MyPass99")
    tn.write_raw(b"MyPass99\r\n", sensitive=True)
    result = tn.expect([b"=>"], timeout=2.0)

    # The returned data is unchanged, the recorded data is redacted
    assert result.data == b"MyPass99\r\n=>"
    assert tn.all_output[-1] == "<redacted>\r\n=>"
    assert tn.raw_output[-1] == b"<redacted>\r\n=>"
    # telnetlib logs what it sends, so sensitive data doesn't go through it
    sent = [str(c) for c in trace.call_args_list if "send" in str(c)]
    assert not any("MyPass99" in c for c in sent)
    tn.write_raw(b"not secret\r\n")
    assert any("not secret" in str(c) for c in trace.call_args_list)
    tn.disconnect()


def test_telnet_read_until_uses_buffered_data(mocker, tmp_path):
    mocker.patch.dict(config["CONFIG"], {"LOG_DIR": tmp_path, "DEVICE_DIR": tmp_path})

    def handler(conn):
        conn.sendall(b"first\x03second\x03")
        time.sleep(0.3)

    port = _serve(handler)
    tn = Telnet("127.0.0.1", port, timeout=2.0)
    assert tn.expect([b"first"], timeout=2.0).matched
    time.sleep(0.1)
    tn.expect([b"\x03"], timeout=2.0)
    assert tn.read_until("\x03", delay=0.0) == "second\x03"
    tn.disconnect()
