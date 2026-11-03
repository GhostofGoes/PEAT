"""
Wait for patterns in the output of a device, on any transport ("expect").

A device module often needs to send a command and then wait until the device
has finished answering, for example until a SEL relay shows its prompt again.
Sleeping for a fixed time is either too short (the output is cut off) or too
long (every command is slow). :class:`Expecter` reads from a transport until
one of a list of regular expressions matches the data that was received.

- The patterns and the data are bytes, so binary data and any text encoding work.
- The transport is a function, ``read_chunk(wait) -> bytes``, that waits up to
  ``wait`` seconds for data and returns what arrived (``b""`` if nothing did),
  and raises :class:`EOFError` when the connection is closed. The functions
  :func:`socket_reader`, :func:`serial_reader`, :func:`telnet_reader` and
  :func:`channel_reader` make one for a socket, a pyserial port, a
  :class:`telnetlib.Telnet` object, and a paramiko channel.
- Each call has an overall timeout, and optionally an idle timeout, which
  resets every time data arrives. A large report can take minutes, but if the
  device stops sending, the idle timeout ends the wait early.
- Data after a match stays in the buffer for the next call.
- A timeout, the end of the connection, or a full buffer isn't an exception:
  :class:`ExpectResult` says what happened and has all the data that was read.

``pexpect`` isn't used: ``pexpect.spawn`` doesn't exist on Windows, and
``pexpect.fdpexpect`` needs a file descriptor that works with ``select()``,
which pyserial ports and sockets on Windows don't provide. PEAT is distributed
as a Windows executable, and uses pyserial 3.4.
"""

from __future__ import annotations

import re
import select
import socket
import ssl
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from time import monotonic, sleep
from typing import Any, Final

#: Type of the function an :class:`Expecter` reads from (refer to the module docstring)
ReadChunk = Callable[[float], bytes]

#: Patterns accepted by :meth:`Expecter.expect`: compiled bytes regular
#: expressions, or bytes or strings that are compiled (strings as ASCII).
PatternLike = re.Pattern[bytes] | bytes | str

#: Type of the optional function that checks a match before :meth:`Expecter.expect`
#: uses it: ``accept(index, match, buffer) -> bool``, where ``index`` is the index of
#: the pattern and ``buffer`` is all the data that wasn't consumed yet.
AcceptMatch = Callable[[int, re.Match[bytes], bytearray], bool]

#: Default maximum number of bytes buffered by an :class:`Expecter` (16 MiB)
DEFAULT_MAX_BUFFER: Final[int] = 16 * 1024 * 1024


@dataclass
class ExpectResult:
    """
    Result of :meth:`Expecter.expect`.
    """

    #: Index of the pattern that matched, or ``-1`` if none did
    index: int
    #: The match, or :obj:`None` if no pattern matched
    match: re.Match[bytes] | None
    #: All the bytes that were consumed: up to the end of the match, or
    #: everything that was read if no pattern matched
    data: bytes
    #: No pattern matched before the timeout (or the idle timeout)
    timed_out: bool = False
    #: The connection was closed before a pattern matched
    eof: bool = False
    #: The buffer was full before a pattern matched
    overflow: bool = False
    #: Seconds the call took
    elapsed: float = 0.0

    @property
    def matched(self) -> bool:
        """If one of the patterns matched."""
        return self.match is not None

    @property
    def before(self) -> bytes:
        """The data before the match (all of the data if there's no match)."""
        if self.match is None:
            return self.data
        return self.data[: self.match.start()]

    def text(self, encoding: str = "ascii") -> str:
        """The data, decoded. Bytes that can't be decoded are replaced."""
        return self.data.decode(encoding, errors="replace")


def compile_patterns(patterns: Sequence[PatternLike]) -> list[re.Pattern[bytes]]:
    """
    Compile patterns for :meth:`Expecter.expect`. Strings are encoded as ASCII.
    """
    compiled = []
    for pattern in patterns:
        if isinstance(pattern, re.Pattern):
            if not isinstance(pattern.pattern, bytes):
                raise TypeError(f"expected a bytes pattern, got a str pattern: {pattern!r}")
            compiled.append(pattern)
        elif isinstance(pattern, str):
            compiled.append(re.compile(pattern.encode("ascii")))
        else:
            compiled.append(re.compile(pattern))
    return compiled


class Expecter:
    """
    Read from a transport until a pattern matches (refer to the module docstring).

    .. code-block:: python

       >>> import socket
       >>> from peat.protocols.expect import Expecter, socket_reader
       >>> ours, theirs = socket.socketpair()
       >>> exp = Expecter(socket_reader(ours))
       >>> theirs.sendall(b"Password: ?")
       >>> result = exp.expect([rb"Password: \\?"], timeout=2.0)
       >>> result.index, result.data
       (0, b'Password: ?')
       >>> ours.close(); theirs.close()
    """

    def __init__(
        self,
        read_chunk: ReadChunk,
        max_buffer: int = DEFAULT_MAX_BUFFER,
        poll_interval: float = 0.05,
        on_data: Callable[[bytes], Any] | None = None,
    ) -> None:
        """
        Args:
            read_chunk: Function that reads from the transport (refer to the module docstring)
            max_buffer: Maximum number of bytes to buffer while waiting for a match
            poll_interval: Seconds to sleep between reads, if ``read_chunk``
                returns immediately when there isn't any data
            on_data: Function called with every chunk of data that's read,
                e.g. to record the raw data
        """
        self._read_chunk: ReadChunk = read_chunk
        self.max_buffer: int = max_buffer
        self.poll_interval: float = poll_interval
        self.on_data: Callable[[bytes], Any] | None = on_data
        self._buffer: bytearray = bytearray()
        #: The transport reported that the connection is closed
        self.eof: bool = False

    @property
    def buffered(self) -> bytes:
        """Bytes that were read, but not consumed yet."""
        return bytes(self._buffer)

    def feed(self, data: bytes) -> None:
        """Add data to the end of the buffer, as if it was read from the transport."""
        self._buffer += data

    def _read(self, wait: float) -> bytes:
        if self.eof:
            return b""

        started = monotonic()
        try:
            chunk = self._read_chunk(max(wait, 0.0))
        except EOFError:
            self.eof = True
            return b""

        if not chunk:
            # Don't spin if the transport returns immediately without data
            pause = min(self.poll_interval, wait)
            if pause > 0 and monotonic() - started < pause / 2:
                sleep(pause)
            return b""

        if self.on_data:
            self.on_data(chunk)

        return chunk

    def read_available(self) -> bytes:
        """
        Consume everything that's buffered, and whatever the transport
        has available right now, without waiting.
        """
        data = bytes(self._buffer)
        self._buffer.clear()

        while not self.eof:
            chunk = self._read(0.0)
            if not chunk:
                break
            data += chunk

        return data

    def _search(
        self,
        patterns: list[re.Pattern[bytes]],
        pos: int,
        accept: AcceptMatch | None = None,
    ) -> tuple[int, re.Match[bytes]] | None:
        # The earliest match wins, then the first pattern in the list.
        # This doesn't depend on the order the patterns are listed in,
        # unless two of them match at the same position.
        best = None  # type: tuple[int, re.Match[bytes]] | None
        for index, pattern in enumerate(patterns):
            start = pos
            while start <= len(self._buffer):
                match = pattern.search(self._buffer, start)
                if match is None:
                    break
                if accept is None or accept(index, match, self._buffer):
                    if best is None or match.start() < best[1].start():
                        best = (index, match)
                    break
                start = match.start() + 1  # rejected, look for a later match
        return best

    def _consume(self, length: int) -> bytes:
        data = bytes(self._buffer[:length])
        del self._buffer[:length]
        return data

    def expect(
        self,
        patterns: Sequence[PatternLike],
        timeout: float,
        idle_timeout: float | None = None,
        settle: float | Sequence[float] = 0.0,
        window: int | None = None,
        accept: AcceptMatch | None = None,
    ) -> ExpectResult:
        """
        Read until one of the patterns matches.

        Args:
            patterns: Regular expressions to look for (refer to :data:`PatternLike`).
                If several match, the one that starts first is used, and if
                they start at the same position, the first one in the list.
            timeout: Maximum number of seconds to wait for a match
            idle_timeout: Stop waiting if no data arrives for this many seconds
                (it starts again whenever data arrives)
            settle: If a match ends at the end of the data that was received,
                wait up to this many seconds (since the last data arrived) for
                more data before using the match. If more data arrives, the
                patterns are searched again. This is for patterns that can
                match the beginning of something longer, e.g. a ``=>`` prompt
                that may be the start of a ``=>>`` prompt. Either one number for
                all of the patterns, or one number per pattern.
            window: Only search the last ``window`` bytes that were buffered
                before the new data, plus the new data. This avoids searching
                the beginning of a large response again for every chunk. Only use
                this for patterns that can't be longer than ``window`` bytes.
            accept: Function that checks each match (refer to :data:`AcceptMatch`).
                A match it rejects is ignored, and later matches are searched for.
                This is for checks a regular expression can't do, e.g. that a
                match isn't inside a message that hasn't ended yet.

        Returns:
            The result. It isn't an exception if no pattern matched.
        """
        compiled = compile_patterns(patterns)
        if isinstance(settle, int | float):
            settles = [float(settle)] * len(compiled)
        else:
            settles = [float(x) for x in settle]
            if len(settles) != len(compiled):
                raise ValueError("'settle' must have one value per pattern")

        started = monotonic()
        deadline = started + timeout
        last_data = started
        pos = 0

        while True:
            found = self._search(compiled, pos, accept)
            now = monotonic()

            if found:
                index, match = found
                settle_for = settles[index]
                at_end = match.end() == len(self._buffer)
                settle_until = min(last_data + settle_for, deadline)

                if at_end and settle_for > 0 and now < settle_until and not self.eof:
                    before = len(self._buffer)
                    chunk = self._read(settle_until - now)
                    if chunk:
                        self._buffer += chunk
                        last_data = monotonic()
                        pos = max(0, before - window) if window else 0
                    continue

                # Search again on an immutable copy, so the match object
                # stays valid after the data is removed from the buffer.
                snapshot = bytes(self._buffer)
                final = compiled[index].search(snapshot, match.start()) or match
                data = snapshot[: final.end()]
                del self._buffer[: final.end()]
                return ExpectResult(
                    index=index,
                    match=final,
                    data=data,
                    elapsed=monotonic() - started,
                )

            if self.eof:
                return ExpectResult(
                    index=-1,
                    match=None,
                    data=self._consume(len(self._buffer)),
                    eof=True,
                    elapsed=now - started,
                )

            if len(self._buffer) > self.max_buffer:
                return ExpectResult(
                    index=-1,
                    match=None,
                    data=self._consume(len(self._buffer)),
                    overflow=True,
                    elapsed=now - started,
                )

            stop_at = deadline
            if idle_timeout is not None:
                stop_at = min(stop_at, last_data + idle_timeout)

            if now >= stop_at:
                return ExpectResult(
                    index=-1,
                    match=None,
                    data=self._consume(len(self._buffer)),
                    timed_out=True,
                    elapsed=now - started,
                )

            before = len(self._buffer)
            chunk = self._read(stop_at - now)
            if chunk:
                self._buffer += chunk
                last_data = monotonic()
                pos = max(0, before - window) if window else 0


def socket_reader(sock: socket.socket) -> ReadChunk:
    """
    :data:`ReadChunk` for a connected socket (TCP, a :class:`ssl.SSLSocket`, or a
    ``socket.socketpair()`` in tests). A reset connection is reported as the end
    of the connection.
    """
    # A TLS socket can have decrypted data buffered, which select() doesn't see
    pending = getattr(sock, "pending", None)

    def read_chunk(wait: float) -> bytes:
        if not (pending and pending()):
            readable, _, _ = select.select([sock], [], [], wait)
            if not readable:
                return b""
        try:
            data = sock.recv(65536)
        except (BlockingIOError, InterruptedError, TimeoutError, ssl.SSLWantReadError):
            # e.g. only part of a TLS record arrived
            return b""
        except OSError as ex:  # e.g. ConnectionResetError
            raise EOFError(str(ex)) from ex
        if not data:
            raise EOFError("connection closed")
        return data

    return read_chunk


def serial_reader(port: Any, poll_interval: float = 0.01) -> ReadChunk:
    """
    :data:`ReadChunk` for a pyserial port (:class:`serial.Serial`, or
    ``serial.serial_for_url("loop://")`` in tests).

    It checks ``in_waiting`` and reads only the bytes that are waiting, so the
    port's own timeout doesn't matter. This works with pyserial 3.4 on Windows,
    Linux, and macOS. A serial error (e.g. a USB adapter was unplugged) is
    reported as the end of the connection.
    """

    def read_chunk(wait: float) -> bytes:
        stop_at = monotonic() + wait
        while True:
            try:
                waiting = port.in_waiting
                if waiting:
                    return port.read(waiting)
            except OSError as ex:  # serial.SerialException is an OSError
                raise EOFError(str(ex)) from ex

            remaining = stop_at - monotonic()
            if remaining <= 0:
                return b""
            sleep(min(poll_interval, remaining))

    return read_chunk


def telnet_reader(tn: Any) -> ReadChunk:
    """
    :data:`ReadChunk` for a connected :class:`telnetlib.Telnet` object
    (e.g. :mod:`peat.protocols.forked_telnetlib`). Telnet option negotiation
    is handled by ``telnetlib``, so only the data is returned.
    """

    def read_chunk(wait: float) -> bytes:
        try:
            data = tn.read_very_eager()  # raises EOFError when closed
            if data or wait <= 0:
                return data

            sock = tn.get_socket()
            if sock is None:
                raise EOFError("telnet connection closed")

            readable, _, _ = select.select([sock], [], [], wait)
            if not readable:
                return b""
            return tn.read_very_eager()
        except OSError as ex:  # e.g. ConnectionResetError
            raise EOFError(str(ex)) from ex

    return read_chunk


def channel_reader(channel: Any, poll_interval: float = 0.01) -> ReadChunk:
    """
    :data:`ReadChunk` for a paramiko channel (e.g. from ``invoke_shell()``),
    or any object with ``recv_ready()``, ``recv(n)`` and ``closed``.
    """

    def read_chunk(wait: float) -> bytes:
        stop_at = monotonic() + wait
        while True:
            if channel.recv_ready():
                data = channel.recv(65536)
                if not data:
                    raise EOFError("channel closed")
                return data

            if channel.closed or getattr(channel, "eof_received", False):
                raise EOFError("channel closed")

            remaining = stop_at - monotonic()
            if remaining <= 0:
                return b""
            sleep(min(poll_interval, remaining))

    return read_chunk


__all__ = [
    "DEFAULT_MAX_BUFFER",
    "AcceptMatch",
    "ExpectResult",
    "Expecter",
    "PatternLike",
    "ReadChunk",
    "channel_reader",
    "compile_patterns",
    "serial_reader",
    "socket_reader",
    "telnet_reader",
]
