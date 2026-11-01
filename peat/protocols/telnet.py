import re
import traceback
from collections.abc import Callable, Sequence
from time import sleep
from typing import Any

import peat
from peat import CommError, log

from . import forked_telnetlib as telnetlib
from .expect import AcceptMatch, Expecter, ExpectResult, PatternLike, ReadChunk, telnet_reader

#: Text that replaces secrets (e.g. passwords) in the recorded output
REDACTED = "<redacted>"


class BinaryNegotiation:
    """
    Telnet option negotiation for a binary session (RFC 856, ``BINARY``), used as
    the ``telnetlib`` option negotiation callback by :class:`Telnet` with
    ``binary=True``.

    PEAT accepts the server's offers to echo, to suppress go-ahead, and to send
    binary data (``WILL ECHO``, ``WILL SGA``, ``WILL BINARY`` are answered with
    ``DO``), and its request that PEAT sends binary data (``DO BINARY`` is answered
    with ``WILL``, and ``DO SGA`` too). This is what SEL relays offer when a Telnet
    session starts, and what SEL's own masters (e.g. RTACs) answer. Other options are
    refused (``DONT`` or ``WONT``). An option that's already in the requested state
    isn't acknowledged again, so the negotiation can't loop (RFC 854).
    """

    #: Options the server may enable on its side (``WILL``), accepted with ``DO``
    ACCEPT_WILL = (telnetlib.BINARY, telnetlib.ECHO, telnetlib.SGA)
    #: Options the server may ask PEAT to enable (``DO``), accepted with ``WILL``
    ACCEPT_DO = (telnetlib.BINARY, telnetlib.SGA)

    def __init__(self) -> None:
        #: Options enabled on the server's side
        self.remote: set[bytes] = set()
        #: Options enabled on PEAT's side
        self.local: set[bytes] = set()
        #: Every reply that was sent
        self.sent: list[bytes] = []

    @property
    def binary(self) -> bool:
        """If binary mode was agreed in both directions."""
        return telnetlib.BINARY in self.remote and telnetlib.BINARY in self.local

    def reply(self, command: bytes, option: bytes) -> bytes:
        """The reply to an option command from the server (empty if there's none)."""
        iac = telnetlib.IAC
        if command == telnetlib.WILL:
            if option not in self.ACCEPT_WILL:
                return iac + telnetlib.DONT + option
            if option in self.remote:
                return b""
            self.remote.add(option)
            return iac + telnetlib.DO + option
        if command == telnetlib.WONT:
            if option in self.remote:
                self.remote.discard(option)
                return iac + telnetlib.DONT + option
            return b""
        if command == telnetlib.DO:
            if option not in self.ACCEPT_DO:
                return iac + telnetlib.WONT + option
            if option in self.local:
                return b""
            self.local.add(option)
            return iac + telnetlib.WILL + option
        if command == telnetlib.DONT:
            if option in self.local:
                self.local.discard(option)
                return iac + telnetlib.WONT + option
            return b""
        return b""  # e.g. subnegotiation or NOP, which PEAT ignores

    def __call__(self, sock: Any, command: bytes, option: bytes) -> None:
        reply = self.reply(command, option)
        if reply and sock is not None:
            sock.sendall(reply)
            self.sent.append(reply)


class Telnet:
    """
    Telnet functionality for interacting with devices.

    Added features:

    - Improved error handling
    - Improved cleanup of connections on exit, even if exceptions happen
    - Logging messages
    - Records all commands and responses and saves to a file
    - Simpler function calls
    - Waiting for patterns in the output (:meth:`expect`)
    """

    # These will vary by device and should be overridden as needed
    ENCODING: str = "utf-8"
    PRE_WRITE_SLEEP: float = 0.15
    POST_WRITE_SLEEP: float = 0.1
    READ_DELAY: float = 0.15
    LINE_TERMINATOR: str = "\r\n"

    def __init__(
        self, ip: str, port: int = 23, timeout: float = 5.0, binary: bool = False
    ) -> None:
        """
        Args:
            ip: Address of the device
            port: TCP port
            timeout: Seconds to wait for the connection and for responses
            binary: Binary session: the Telnet ``BINARY`` option is negotiated
                (refer to :class:`BinaryNegotiation`), and NUL and XON bytes
                are kept in the data. By default (off), they're removed, and
                the options the server offers are refused, as before.
        """
        self.ip: str = ip
        self.port: int = port
        self.timeout: float = timeout
        self.binary: bool = binary

        self.log = log.bind(
            classname=self.__class__.__name__,
            target=f"{self.ip}:{self.port}",
        )

        self.connected: bool = False

        self.all_output: list[str] = []
        self.raw_output: list[bytes] = []
        self.info: dict[str, Any] = {}

        self.successful_creds: tuple[str, str] | None = None
        self._comm: telnetlib.Telnet = telnetlib.Telnet()
        self._expecter: Expecter | None = None
        self._secrets: set[str] = set()

        #: Option negotiation of a binary session (``None`` if it isn't one)
        self.negotiation: BinaryNegotiation | None = None
        #: Function that wraps the reader of the :attr:`expecter`, e.g. to take
        #: binary messages out of the data (``reader -> reader``)
        self.stream_filter: Callable[[ReadChunk], ReadChunk] | None = None
        if binary:
            self._setup_binary(self._comm)

        self.log.trace2(f"Initialized {repr(self)}")

    def _setup_binary(self, comm: telnetlib.Telnet) -> None:
        self.negotiation = BinaryNegotiation()
        comm.keep_nulls = True
        comm.set_option_negotiation_callback(self.negotiation)

    def __enter__(self) -> "Telnet":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.disconnect()
        if exc_type:
            self.log.debug(f"Unhandled exception while exiting - {exc_type.__name__}: {exc_val}")
            self.log.trace(
                f"Exception traceback\n"
                f"{''.join(traceback.format_tb(exc_tb))}"
                f"{exc_type.__name__}: {exc_val}"
            )

    def __str__(self) -> str:
        return self.ip

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.ip}, {self.port}, {self.timeout})"

    @property
    def comm(self) -> telnetlib.Telnet:
        """
        Python Telnet instance used for interacting with the device.
        """
        if not self.connected:
            if self.binary:
                # Each connection negotiates the options again, from the start
                self._setup_binary(self._comm)
            try:
                self._comm.open(self.ip, self.port, self.timeout)
                self.connected = True
                self.log.info(f"Connected to {self.ip}:{self.port}")
            except Exception as ex:
                raise CommError(f"Failed to connect to {self.ip}:{self.port}: {ex}") from ex

        return self._comm

    @comm.setter
    def comm(self, obj: telnetlib.Telnet) -> None:
        self._comm = obj
        if self.binary:
            self._setup_binary(obj)

    def test_connection(self) -> bool:
        """
        Test connection to the device.
        """
        try:
            if self.comm:
                return True
            return False
        except CommError:
            return False

    def disconnect(self) -> None:
        """
        Cleanly disconnect from the device.
        """
        if self.connected and self._comm:
            self._comm.close()
            self.connected = False
            self._expecter = None
            self.log.debug(f"Disconnected from {self.ip}")

            if self.all_output:
                # Save the raw output to disk as an artifact
                try:
                    dev = peat.data.datastore.get(self.ip)
                    dev.write_file(self.all_output, "raw-telnet-output.json", merge_existing=True)
                except Exception as ex:
                    self.log.warning(f"Failed to write raw output to file: {ex}")

    def write(self, command: bytes | str | int, flush: bool = False) -> None:
        """
        Send a Telnet command to the device.

        Args:
            command: Command to send (this will be automatically encoded)
            flush: If the responses to the command should be dropped
        """
        self.log.debug(f"Writing command: {command}")

        # If it's an int, first convert to a string, which will then be encoded
        if isinstance(command, int):
            command = str(command)

        # If it's a string, encode to bytes with the device's encoding
        if isinstance(command, str):
            command = command.encode(self.ENCODING)

        # Append the line terminator (encode here to ensure proper encoding)
        command += self.LINE_TERMINATOR.encode(self.ENCODING)

        # NOTE(cegoes): If we don't sleep, things get REALLY wonky.
        # Wasted an hour figuring out why the exact same telnet commands
        # worked in the REPL, but not the script...well, it was the pauses
        # between sending and reading commands. JustTelnetThings.
        sleep(self.PRE_WRITE_SLEEP)
        self.comm.write(command)
        sleep(self.POST_WRITE_SLEEP)

        if flush:
            self.comm.read_very_eager()

    def write_raw(self, data: bytes, sensitive: bool = False) -> None:
        """
        Send bytes to the device as they are, without a line terminator or delays.

        IAC bytes (``0xFF``) are doubled, as Telnet requires.

        Args:
            data: Bytes to send
            sensitive: The data is a secret, such as a password, so it's not
                logged. To also remove it from the recorded output if the
                device echoes it, use :meth:`register_secret`.
        """
        if sensitive:
            # Don't use telnetlib's write(), it logs the data
            sock = self.comm.get_socket()
            if sock is None:
                raise CommError(f"Not connected to {self.ip}:{self.port}")
            sock.sendall(data.replace(telnetlib.IAC, telnetlib.IAC + telnetlib.IAC))
        else:
            self.comm.write(data)

    def register_secret(self, secret: str) -> None:
        """
        Replace ``secret`` with ``<redacted>`` in the recorded output
        (``all_output`` and ``raw_output``, which are saved to files),
        in case the device echoes it.
        """
        if secret:
            self._secrets.add(secret)

    def _redact(self, text: str) -> str:
        for secret in self._secrets:
            text = text.replace(secret, REDACTED)
        return text

    def _redact_bytes(self, data: bytes) -> bytes:
        for secret in self._secrets:
            try:
                data = data.replace(secret.encode(self.ENCODING), REDACTED.encode("ascii"))
            except UnicodeEncodeError:
                pass
        return data

    @property
    def expecter(self) -> Expecter:
        """
        :class:`~peat.protocols.expect.Expecter` reading from the connection
        (it's created when it's first used, and connects if needed).
        """
        if self._expecter is None:
            reader = telnet_reader(self.comm)
            if self.stream_filter is not None:
                reader = self.stream_filter(reader)
            self._expecter = Expecter(reader)
        return self._expecter

    def expect(
        self,
        patterns: Sequence[PatternLike],
        timeout: float | None = None,
        idle_timeout: float | None = None,
        settle: float | Sequence[float] = 0.0,
        window: int | None = None,
        accept: AcceptMatch | None = None,
    ) -> ExpectResult:
        """
        Read until one of the patterns matches the output.

        Refer to :meth:`peat.protocols.expect.Expecter.expect` for the arguments.
        Unlike ``telnetlib.Telnet.expect()``, this always has a timeout
        (by default, the timeout of this object), and the end of the
        connection is reported in the result (``eof``) instead of raising
        :class:`EOFError`. Data after the match is kept for the next call
        (of this method, :meth:`read` or :meth:`read_until`).
        All the data that was read is added to ``all_output`` and ``raw_output``.

        Returns:
            The result, which has the data that was read (``data``), the match,
            and if the read timed out (``timed_out``) or the connection
            was closed (``eof``).
        """
        if timeout is None:
            timeout = self.timeout

        result = self.expecter.expect(
            patterns,
            timeout,
            idle_timeout=idle_timeout,
            settle=settle,
            window=window,
            accept=accept,
        )

        if result.data:
            self._add_data(result.data, strip_whitespace=False, errors="replace")

        if result.eof:
            self.log.debug("Connection closed by the device")

        return result

    def read_available(self) -> bytes:
        """
        Read everything that's available now, without waiting, as bytes.
        The data is added to ``all_output`` and ``raw_output``.
        """
        data = self.expecter.read_available()
        if data:
            self._add_data(data, strip_whitespace=False, errors="replace")
        return data

    def login(self, user: str, passwd: str) -> dict | None:
        """
        Login to the telnet device.
        """
        pass

    def read(self, delay: float | None = None, strip_whitespace: bool = True) -> str:
        """
        Read all data currently in the telnet response buffer.

        This is a stateful operation, so calling this method again will
        not result in the same information. The results are saved in the
        ``all_output`` class attribute for future access.

        Args:
            delay: Seconds to sleep before querying for data
            strip_whitespace: If ``str.strip()`` should be called on the results

        Returns:
            Decoded data read from the Telnet receive stream
        """
        if delay is None:
            delay = self.READ_DELAY

        sleep(delay)

        if self._expecter or self.stream_filter is not None:
            # Data buffered by expect() comes first (and a filtered stream
            # must always be read through the expecter)
            data = self.expecter.read_available()
            if not data and self._expecter.eof:
                raise EOFError("telnet connection closed")
        else:
            data = self.comm.read_very_eager()

        return self._add_data(data, strip_whitespace)

    def read_until(
        self,
        until: bytes | str,
        delay: float = 0.15,
        timeout: float | None = None,
        strip_whitespace: bool = True,
    ) -> str:
        """
        Read the telnet response buffer until the specified string is reached.

        This is a stateful operation, so calling this method again will
        not result in the same information. The results are saved in the
        all_output class attribute for future access.

        Args:
            until: String to read all data up to
            delay: Seconds to sleep before querying for data
            timeout: Seconds to wait for the string before timing out
            (if None, this defaults to the Telnet class's timeout configuration)
            strip_whitespace: If ``strip()`` should be called on the results

        Returns:
            Decoded data read from the telnet receive stream
        """
        if isinstance(until, str):
            until = until.encode(self.ENCODING)

        if timeout is None:
            timeout = self.timeout

        sleep(delay)

        if (self._expecter and self._expecter.buffered) or self.stream_filter is not None:
            # Data buffered by expect() comes first (and a filtered stream
            # must always be read through the expecter)
            result = self.expecter.expect([re.escape(until)], timeout)
            return self._add_data(result.data, strip_whitespace)

        return self._add_data(self.comm.read_until(until, timeout), strip_whitespace)

    def _add_data(
        self, raw_data: bytes, strip_whitespace: bool = True, errors: str = "strict"
    ) -> str:
        """
        Decodes and saves responses from device.

        Secrets (refer to :meth:`register_secret`) are replaced in the
        saved data, but not in the returned data.
        """
        self.raw_output.append(self._redact_bytes(raw_data) if self._secrets else raw_data)

        data = raw_data.decode(self.ENCODING, errors=errors)
        self.all_output.append(self._redact(data) if self._secrets else data)

        if "Goodbye" in data:
            self.log.debug("Device said goodbye")
            self.disconnect()

        if strip_whitespace:
            data = data.strip()

        return data


__all__ = ["Telnet"]
