import json
import re
import traceback
from abc import ABC, abstractmethod
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from time import monotonic, sleep
from typing import Any, ClassVar, Final

from dateutil.parser import parse as date_parse

from peat import CommError, DeviceError, config, consts, exit_handler, log, state, utils
from peat.protocols.expect import ExpectResult, PatternLike

from .relay_command_parse import parse_mac_output
from .relay_parse import parse_status_output
from .sel_cascii import parse_id_output
from .sel_commands import (
    SELCommandRefused,
    check_command,
    command_refusal,
    normalize_command,
    ser_command,
)
from .sel_default_creds import (
    GENERIC_PASSWORDS,
    LEVEL_COMMANDS,
    Credential,
    normalize_model,
    resolve_level_passwords,
)

# Prompts of each access level, longest first, so "=>>" isn't read as "=>".
#
# - 300, 400, and 700 series relays (SEL-421 IM 20130627 Table 4.3, SEL-351S IM
#   20171023 Section 10): "=" level 0, "=>" level 1, "==>" level B, "=>>" level 2,
#   "==>>" level C. The 400 series also has "P=>", "A=>", and "O=>" (levels P, A, O).
# - SEL-734B meters: "E=>" (level E).
# - SEL-2030/2032 communications processors: "*", "*>", "*>>" (SEL-2032 IM 20120126).
# - SEL-2701/2702 Ethernet cards: "#", "#>", "#>>" (SEL-421 IM Table 4.11).
# - SELBOOT (firmware loader, the relay is disabled): "!>".
_PROMPT_ALTERNATIVES: Final = rb"==>>|=>>|==>|[PAOE]=>|=>|=|\*>>|\*>|\*|#>>|#>|#|!>"

#: A prompt in its own message, e.g. ``b"\x02\r\n=>>\x03"`` (after the ETX of the output).
#: The SEL-2032 sends a space before the prompt: ``<ETX><STX> <PROMPT><ETX>``
#: (SEL-2032 IM 20120126, Figure 8.1 "Noninteractive Message Format").
FRAMED_PROMPT_RE: Final = re.compile(
    rb"\x02[\r\n \t]*(?P<prompt>" + _PROMPT_ALTERNATIVES + rb")[ \t]*\x03"
)

#: A prompt that isn't framed, at the start of a line, at the end of the data so far.
#: A prompt right after a STX is the start of a framed prompt, so it's excluded.
UNFRAMED_PROMPT_RE: Final = re.compile(
    rb"(?:\A|(?<=[\r\n]))(?<!\x02\r\n)(?<!\x02\n)(?<!\x02\r)(?P<prompt>"
    + _PROMPT_ALTERNATIVES
    + rb")[ \t]*\Z"
)

#: A prompt at the end of output, framed or not (for output read without waiting for it)
TRAILING_PROMPT_RE: Final = re.compile(
    rb"(?:\A|[\r\n]|\x02[ \t]*)(?P<prompt>" + _PROMPT_ALTERNATIVES + rb")[ \t\x03]*\Z"
)

#: The relay asks for a password ("Password: ?"). It asks again if the password was wrong.
PASSWORD_RE: Final = re.compile(rb"Password:\s*\?")

#: The relay asks for confirmation, e.g. "Are you sure (Y/N) ?" or "Save settings (Y,N) ?"
CONFIRM_RE: Final = re.compile(rb"\((?:Y/N|Y,N)\)\s*\?", re.IGNORECASE)

#: A confirmation question at the end of the data so far: the relay is waiting
#: for the answer. Used to notice a question after a command that shouldn't ask one.
PENDING_CONFIRM_RE: Final = re.compile(rb"\((?:Y/N|Y,N)\)[ \t]*\?[ \t]*\Z", re.IGNORECASE)

#: The relay says it's restarting, after STA C is confirmed ("Rebooting the relay")
REBOOTING_RE: Final = re.compile(rb"reboot|restart|resetting", re.IGNORECASE)

#: The relay is ready to send a file with YMODEM (``FILE READ``)
READY_TO_SEND_RE: Final = re.compile(rb"ready to send", re.IGNORECASE)

#: Error messages from the relay, e.g. "Invalid Command" or "Invalid Access Level"
ERROR_RE: Final = re.compile(r"\s*(Invalid\b[^\r\n]*)", re.IGNORECASE)

#: Messages the relay sends instead of a file (``FILE SHOW``). Like all of its
#: messages, they can be framed with STX and ETX, like the contents of a file.
FILE_ERROR_RE: Final = re.compile(
    r"\s*(?:Invalid\b|File specified does not exist|Command requires)", re.IGNORECASE
)

#: Confirmation questions that PEAT must never answer with "Y". The SEL-400 series
#: may ask "Accept new hardware configuration (Y/N)?" after a board change.
NEVER_CONFIRM_RE: Final = re.compile(r"hardware|firmware|default|erase|disable", re.IGNORECASE)

#: Access level shown by each prompt
PROMPT_LEVELS: Final[dict[str, str]] = {
    "=": "0",
    "=>": "1",
    "==>": "B",
    "P=>": "P",
    "A=>": "A",
    "O=>": "O",
    "E=>": "E",
    "=>>": "2",
    "==>>": "C",
    "*": "0",
    "*>": "1",
    "*>>": "2",
    "#": "0",
    "#>": "1",
    "#>>": "2",
    "!>": "SELBOOT",
}

#: Rank of each access level, as used by ``priv_level`` (levels B, P, A, O, and E are
#: between levels 1 and 2: they're reached from level 1, and 2AC works from them)
LEVEL_RANKS: Final[dict[str, int]] = {
    "0": 0,
    "1": 1,
    "B": 1,
    "P": 1,
    "A": 1,
    "O": 1,
    "E": 1,
    "2": 2,
    "C": 3,
    "SELBOOT": 0,
}

#: Level to elevate to from each rank, and its name in the credentials
_NEXT_LEVEL: Final[dict[int, str]] = {0: "acc", 1: "2ac", 2: "cal"}
_LEVEL_TARGET: Final[dict[str, int]] = {"acc": 1, "2ac": 2, "cal": 3}

#: Recorded instead of a password in ``all_writes``
REDACTED_WRITE: Final = b"<redacted>"

#: Cancel character (Ctrl+X), aborts the current output or dialog
CAN: Final = b"\x18"

STX: Final = "\x02"
ETX: Final = "\x03"


class SELSessionHalted(CommError):
    """
    PEAT stopped sending to a SEL device on this connection (refer to
    :attr:`SELAscii.halted`), because anything it sent could be taken as an
    answer to a dialog, e.g. as another wrong password.
    """


def _in_open_message(buffer: bytes | bytearray, pos: int) -> bool:
    """If ``pos`` is after a STX that hasn't been closed by an ETX."""
    return buffer.rfind(b"\x02", 0, pos) > buffer.rfind(b"\x03", 0, pos)


def clean_lines(text: str) -> list[str]:
    """
    Split SEL ASCII output into lines, without the STX and ETX characters,
    surrounding whitespace, and empty lines.
    """
    lines = []
    for line in re.split(r"\r\n|\r|\n", text):
        line = line.replace(STX, "").replace(ETX, "").strip()
        if line:
            lines.append(line)
    return lines


def mac_result_key(label: str) -> str:
    """
    Key for a MAC address from :func:`~peat.modules.sel.relay_command_parse.parse_mac_output`
    in the result of :meth:`SELAscii.show_mac`, e.g. ``"IP"`` => ``"ip_mac"``,
    ``"Port 1"`` => ``"port_1_mac"``, ``"MAC"`` => ``"mac"``.
    """
    key = re.sub(r"[^a-z0-9]+", "_", label.lower()).strip("_")
    return key if key.startswith("mac") else f"{key}_mac"


@dataclass
class SELResponse:
    """
    Output of a SEL ASCII command, from :meth:`SELAscii.run_command`.
    """

    #: The command that was sent
    command: str
    #: Everything that was received, including the echo of the command and the prompt
    raw: str = ""
    #: What was received before the prompt (the echo and the output)
    body: str = ""
    #: Lines of the output, without the echo of the command, framing, or the prompt
    lines: list[str] = field(default_factory=list)
    #: The prompt at the end of the output (e.g. ``"=>>"``), or empty if it wasn't seen
    prompt: str = ""
    #: The access level shown by the prompt (e.g. ``"2"``), or empty
    level: str = ""
    #: The prompt wasn't seen before the timeout
    timed_out: bool = False
    #: The connection was closed
    eof: bool = False
    #: Error message in the output, e.g. ``"Invalid Command"``
    error: str = ""
    #: The command wasn't sent, since the device answered "Invalid Command"
    #: to it before (refer to :meth:`SELAscii.run_read_command`)
    skipped: bool = False

    @property
    def complete(self) -> bool:
        """If the output ended with a prompt."""
        return bool(self.prompt)


@dataclass
class RestartResult:
    """
    Result of :meth:`SELAscii.restart_device`. It's "truthy" if the restart was initiated.
    """

    #: ``"initiated"``, ``"failed"``, ``"unsupported"``, or ``"unknown"``
    #: (the connection was lost before the relay confirmed the command)
    status: str
    #: Why the restart failed, or how PEAT knows it was initiated
    reason: str = ""
    #: The dialog with the relay
    transcript: list[str] = field(default_factory=list)
    #: FID of the relay before the restart
    fid: str = ""
    #: Time on the relay before the restart, if it was read
    device_time: datetime | None = None
    #: When the restart was confirmed (UTC)
    initiated_at: datetime | None = None

    def __bool__(self) -> bool:
        return self.status == "initiated"

    @property
    def initiated(self) -> bool:
        """If the relay accepted the restart."""
        return self.status == "initiated"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason": self.reason,
            "fid": self.fid,
            "device_time": self.device_time.isoformat() if self.device_time else None,
            "initiated_at": self.initiated_at.isoformat() if self.initiated_at else None,
            "transcript": self.transcript,
        }


class SELAscii(ABC):
    """
    Commands and parsers for the SEL ASCII command interface.

    PEAT sends a command and waits for the relay's prompt, which ends the output
    of every command (refer to "Command timing" in the SEL documentation, ``docs/sel.rst``).
    The prompt also shows the current access level, which is tracked in
    ``access_level`` and ``priv_level``.

    Transports (:class:`~peat.modules.sel.sel_telnet.SELTelnet` and
    :class:`~peat.modules.sel.sel_serial.SELSerial`) implement :meth:`_write_raw`,
    :meth:`_read_available`, and :meth:`_expect_raw`.

    If ``legacy_timing`` is set, PEAT instead sleeps for a fixed time after each
    command and reads what arrived, as PEAT did before. Logins and the restart
    dialog always wait for the prompts.
    """

    DATA_REGEX = re.compile(r"\x02([^\x03]*)\x03", re.ASCII)
    ENCODING = "ascii"
    # These are only used with legacy_timing
    PRE_WRITE_SLEEP = 0.15
    POST_WRITE_SLEEP = 0.1
    READ_DELAY = 0.15
    LINE_TERMINATOR = "\r\n"
    #: Kept for compatibility. The defaults depend on the model, refer to
    #: :mod:`peat.modules.sel.sel_default_creds`.
    DEFAULT_CREDS = dict(GENERIC_PASSWORDS)

    #: Maximum seconds to wait for the prompt after a command with little output
    COMMAND_TIMEOUT: float = 15.0
    #: Maximum seconds to wait for the prompt after a command with a lot of output
    #: (e.g. SER or FILE SHOW). The idle timeout usually ends the wait earlier.
    LONG_COMMAND_TIMEOUT: float = 900.0
    #: Seconds to wait for more data after something that looks like a prompt,
    #: but isn't framed with STX and ETX, before treating it as the prompt
    PROMPT_SETTLE: float = 0.3
    #: Seconds to wait for more data after a confirmation question at the end
    #: of the output, before treating it as a question (the relay waits for the
    #: answer, so this only costs time if it's output that looks like a question)
    QUESTION_SETTLE: float = 1.0
    #: Seconds to wait for output to stop when the connection is first used
    #: (e.g. a banner), so it isn't mistaken for the response to the first command
    FIRST_COMMAND_QUIET: float = 0.3
    #: Only search for the prompt in this many bytes before new data
    PROMPT_WINDOW: int = 4096

    # Passwords that failed (or worked) for an address and level, shared by
    # instances, so a password that failed isn't tried again on a new connection.
    _failed_passwords: ClassVar[dict[tuple[str, str], set[str]]] = {}
    _good_passwords: ClassVar[dict[tuple[str, str], str]] = {}

    # Commands that devices answered with "Invalid Command", keyed by the
    # address and the FID (or model, if the FID isn't known) of the device,
    # shared by the connections to the device. SELRelay forgets them at the
    # start of each pull and restart (refer to forget_unsupported_commands()).
    _unsupported_commands: ClassVar[dict[tuple[str, str], set[str]]] = {}

    def __init__(
        self,
        address: str,
        timeout: int | float = 5.0,
        legacy_timing: bool = False,
        idle_timeout: float = 30.0,
    ) -> None:
        """
        Args:
            address: Address of the device (IP address or serial port)
            timeout: Seconds to wait for a response to a command with little output,
                and for the connection
            legacy_timing: Use fixed delays instead of waiting for prompts
                (refer to the class docstring)
            idle_timeout: Seconds without any output from the relay after which
                PEAT stops waiting for the end of a command with a lot of output
        """
        self.address: str = address
        self.timeout: int | float = timeout
        self.legacy_timing: bool = legacy_timing
        self.idle_timeout: float = idle_timeout

        self.log = log.bind(classname=self.__class__.__name__, target=self.address)

        self.all_writes: list[bytes] = []
        self.all_output: list[str] = []
        self.raw_output: list[bytes] = []
        self.successful_usernames: set[str] = set()

        #: Rank of the current access level: 0, 1 (levels 1, B, P, A, O), 2, or 3 (level C)
        self.priv_level: int = 0
        #: Current access level from the last prompt ("0", "1", "B", "2", "C", ...),
        #: or an empty string if it isn't known
        self.access_level: str = ""

        #: Passwords of each level (``{"acc": "...", "2ac": "..."}``), set by
        #: :meth:`elevate`. Levels that aren't set use the model's defaults.
        self.creds: dict[str, Any] = {}
        #: Also try "CLARKE" for level C on 400 series relays (``sel.cal_clarke_fallback``)
        self.cal_fallback: bool = False

        #: The response to the last command
        self.last_response: SELResponse | None = None
        #: Output of the commands sent when disconnecting (QUIT and EXIT)
        self.exit_output: str = ""

        # A hint about what the model is. This is helpful
        # for devices where we're pretty confident in the
        # commands available.
        self.model: str = ""
        #: Firmware ID (FID) of the device, if it's known (e.g. from ``ID``).
        #: Commands that aren't supported are remembered for the FID.
        self.fid: str = ""

        #: Responses to the commands sent with :meth:`run_command`, in order
        self.responses: list[SELResponse] = []
        #: Commands the device answered with "Invalid Command" on this connection
        #: (normalized, refer to :func:`~peat.modules.sel.sel_commands.normalize_command`)
        self.unsupported_commands: set[str] = set()
        # Why commands that change the state of the device may be sent now
        # (refer to _allow_state_changes()), or an empty string
        self._state_change_reason: str = ""
        # A password is being sent in answer to a password prompt (refer to _send_password())
        self._answering_password: bool = False

        # friendly name of the communication method, either Telnet or Serial
        self.type = self.__class__.__name__.partition("SEL")[2].capitalize()

        self._secrets: set[str] = set()
        # Levels a password was sent for on this connection (each is tried once)
        self._attempted_levels: set[str] = set()
        self._first_command: bool = True
        self._seen_prompt: bool = False
        # Don't send anything when disconnecting: a dialog may still be waiting for
        # input (e.g. a password), or the relay is restarting.
        self._no_exit_commands: bool = False
        #: Why PEAT stopped sending anything on this connection, or an empty string.
        #: It's set if the relay may still be waiting for an answer that PEAT
        #: can't give safely (e.g. it didn't show its prompt after CAN at a password
        #: prompt), or shows the SELBOOT prompt. Writes then raise
        #: :class:`SELSessionHalted`. A Telnet connection is usable again after
        #: :meth:`disconnect`. A serial port keeps its state when it's closed,
        #: so on serial it stays set: use a new object to try again.
        self.halted: str = ""

        if config.LOG_DIR and config.OUT_DIR:
            # Ensure data gets saved when PEAT exits if it doesn't exit with context
            exit_handler.register(self._save_state_to_file, "FILE")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if config.LOG_DIR and config.OUT_DIR:
            try:
                self._save_state_to_file()
            except Exception:
                self.log.exception("file save failed")
            exit_handler.unregister(self._save_state_to_file, "FILE")

        self.disconnect()
        exit_handler.unregister(self.disconnect, "CONNECTION")

        if exc_type:
            self.log.debug(f"Unhandled exception while exiting - {exc_type.__name__}: {exc_val}")
            self.log.trace(
                f"Exception traceback\n"
                f"{''.join(traceback.format_tb(exc_tb))}"
                f"{exc_type.__name__}: {exc_val}"
            )

    def __str__(self) -> str:
        return self.address

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(address={self.address}, timeout={self.timeout})"

    @classmethod
    def forget_passwords(cls, address: str | None = None) -> None:
        """
        Forget which passwords failed (and worked) on a device, so they're tried
        again on the next connection. PEAT remembers them for the whole process
        otherwise. :class:`~peat.modules.sel.sel_relay.SELRelay` calls this at
        the start of each pull and restart.

        Args:
            address: Address of the device (IP address or serial port), or
                :obj:`None` for all devices
        """
        for memory in (cls._failed_passwords, cls._good_passwords):
            for key in [k for k in memory if address is None or k[0] == address]:
                del memory[key]

    def _check_halted(self) -> None:
        """Raise :class:`SELSessionHalted` if nothing may be sent (:attr:`halted`)."""
        if self.halted:
            raise SELSessionHalted(f"not sending anything to {self.address}: {self.halted}")

    def _halt(self, reason: str) -> None:
        """Stop sending anything on this connection (refer to :attr:`halted`)."""
        if not self.halted:
            self.log.error(
                f"PEAT won't send anything else to {self.address} on this connection: {reason}"
            )
            self.halted = reason
        self._no_exit_commands = True

    def _save_state_to_file(self) -> bool:
        """
        Save all data sent/received to a file in ``peat_results/<run-dir>/logs/``.

        Passwords sent to the device are replaced with ``<redacted>``.
        """
        data = {
            "class": self.__class__.__name__,
            "address": self.address,
            "timeout": self.timeout,
            "legacy_timing": self.legacy_timing,
            "successful_usernames": sorted(self.successful_usernames),
            "final_privilege_level": self.priv_level,
            "final_access_level": self.access_level,
            "all_writes": self.all_writes,
            "all_output": self.all_output,
            "raw_output": self.raw_output,
        }

        if hasattr(self, "baud"):
            data["baudrate"] = getattr(self, "baud", 0)

        # "/dev/ttyUSB0" => "ttyUSB0"
        basename = f"selascii-protocol-data_{self.address.split('/')[-1]}"
        if data.get("baudrate") is not None:
            basename += f"_{data['baudrate']}"
        f_path = config.LOG_DIR / consts.sanitize_filename(f"{basename}.json")

        # If file already exists, read JSON, append current object as a dict
        # to the list of dicts in the file, then overwrite the file.
        #
        # This can happen if multiple SELASCII instances are created
        # and destroyed for the same port, e.g. during scanning.
        if f_path.exists():
            raw_file = f_path.read_text(encoding="utf-8")  # type: str
            file_data = json.loads(raw_file)  # type: list[dict]
            file_data.append(data)
            return utils.write_file(file_data, f_path, overwrite_existing=True)
        else:
            # Write a new file with a list with a single dict
            return utils.write_file([data], f_path)

    @property
    @abstractmethod
    def comm(self):
        """
        Underlying communication protocol class instance used for interacting
        with the device (e.g. :class:`~peat.protocols.telnet.Telnet`).
        """
        pass

    @comm.setter
    @abstractmethod
    def comm(self, obj):
        pass

    @abstractmethod
    def test_connection(self) -> bool:
        """
        Test connection to the device.
        """
        pass

    @abstractmethod
    def disconnect(self) -> None:
        """
        Cleanly disconnect from the device.
        """
        pass

    @abstractmethod
    def read(self, delay: float | None = None, strip_whitespace: bool = True) -> str:
        """
        Sleep, then read everything that arrived (this is how PEAT read output before
        it waited for prompts, and it's used with ``legacy_timing``).
        """
        pass

    @abstractmethod
    def read_until(self, until: bytes | str, strip_whitespace: bool = True) -> str:
        """
        Read until a string is received, or the timeout.
        """
        pass

    @abstractmethod
    def _write_raw(self, data: bytes, sensitive: bool = False) -> None:
        """
        Send bytes to the device as they are. If ``sensitive``, they must not be logged.
        """
        pass

    @abstractmethod
    def _read_available(self) -> bytes:
        """
        Read everything that's available now, without waiting
        (including data that was buffered by :meth:`_expect_raw`).
        """
        pass

    @abstractmethod
    def _expect_raw(
        self,
        patterns: Sequence[PatternLike],
        timeout: float,
        idle_timeout: float | None = None,
        settle: float | Sequence[float] = 0.0,
        window: int | None = None,
        accept=None,
    ) -> ExpectResult:
        """
        Read until a pattern matches, refer to
        :meth:`peat.protocols.expect.Expecter.expect`.
        """
        pass

    # ---------------------------------------------------------------------
    # Sending, receiving, and recording
    # ---------------------------------------------------------------------

    def register_secret(self, secret: str) -> None:
        """
        Replace ``secret`` with ``<redacted>`` in the recorded output
        (``all_output`` and ``raw_output``), in case the device echoes it.
        """
        if secret:
            self._secrets.add(secret)

    def _decode(self, data: bytes) -> str:
        try:
            return data.decode(self.ENCODING)
        except UnicodeDecodeError:
            # e.g. a degree sign in an event report. Latin-1 decodes every byte.
            return data.decode("latin-1")

    def _record(self, data: bytes) -> str:
        """Save received data in ``raw_output`` and ``all_output``, and decode it."""
        text = self._decode(data)

        raw = data
        recorded = text
        for secret in self._secrets:
            recorded = recorded.replace(secret, "<redacted>")
            raw = raw.replace(secret.encode(self.ENCODING, errors="replace"), b"<redacted>")

        self.raw_output.append(raw)
        self.all_output.append(recorded)
        return text

    def write(self, command: bytes | str | int, sensitive: bool = False) -> None:
        """
        Send a command to the device.

        Commands that may change the state of the device (e.g. ``SER C`` or
        ``STA C``) are refused, refer to :mod:`peat.modules.sel.sel_commands`.

        Args:
            command: Command to send (this will be automatically encoded,
                and the line terminator is added)
            sensitive: The command is a secret. It's recorded as ``<redacted>``
                in ``all_writes`` and isn't logged. It's still checked (only the
                answer to a password prompt during :meth:`elevate` isn't).

        Raises:
            SELCommandRefused: The command may change the state of the device
            SELSessionHalted: Nothing may be sent on this connection (:attr:`halted`)
        """
        self._send(command, sensitive=sensitive)

    @contextmanager
    def _allow_state_changes(self, reason: str) -> Iterator[None]:
        """
        Allow commands that change the state of the device (e.g. ``STA C``, or
        ``Y`` to confirm a question) while in this context. Only the code paths
        that are meant to change the device use this, and only when the user asks
        for them: restarts, pushes, active group changes, and logins to level C.

        Args:
            reason: What the commands are for, e.g. ``"restart (STA C)"``
        """
        previous = self._state_change_reason
        self._state_change_reason = reason
        self.log.debug(f"Commands that change the state of {self.address} allowed: {reason}")
        try:
            yield
        finally:
            self._state_change_reason = previous

    def _check_command(self, command: bytes, terminator: bool, sensitive: bool = False) -> None:
        """
        Refuse to send a command that may change the state of the device
        (:func:`~peat.modules.sel.sel_commands.check_command`), unless that's
        allowed now (:meth:`_allow_state_changes`). If ``sensitive``, the
        command isn't in the error.
        """
        if self._state_change_reason:
            return

        text = command.decode("latin-1")
        try:
            if not terminator:
                # Only CAN is sent without a line terminator
                if command != CAN:
                    raise SELCommandRefused(
                        f"PEAT won't send {'<redacted>' if sensitive else repr(text)} "
                        f"without a line terminator to {self.address}"
                    )
                return
            reason = command_refusal(text)
            if reason:
                raise SELCommandRefused(
                    f"PEAT won't send {'<redacted>' if sensitive else repr(text)} "
                    f"to {self.address}: {reason}"
                )
        except SELCommandRefused as ex:
            self.log.error(str(ex))
            raise

    def _send_password(self, password: str) -> None:
        """
        Answer the device's password prompt during a login (:meth:`elevate`).
        A password isn't a command, so it isn't checked (refer to :meth:`_send`),
        and it isn't recorded or logged.
        """
        self._answering_password = True
        try:
            self._send(password, sensitive=True)
        finally:
            self._answering_password = False

    def _send(
        self,
        command: bytes | str | int,
        sensitive: bool = False,
        terminator: bool = True,
    ) -> None:
        # Every write goes through here, so this is the one place to refuse them
        self._check_halted()

        # If it's an int, first convert to a string, which will then be encoded
        if isinstance(command, int):
            command = str(command)

        # If it's a string, encode to bytes with the device's encoding
        if isinstance(command, str):
            command = command.encode(self.ENCODING)

        # The answer to a password prompt isn't a command. Other secrets are
        # checked, but not logged.
        if not (sensitive and self._answering_password):
            self._check_command(command, terminator, sensitive=sensitive)

        if terminator:
            # Append the line terminator (encode here to ensure proper encoding)
            command += self.LINE_TERMINATOR.encode(self.ENCODING)

        if sensitive:
            self.all_writes.append(REDACTED_WRITE + (b"\r\n" if terminator else b""))
        else:
            self.all_writes.append(command)

        # Before PEAT waited for prompts, it slept around every write
        if self.legacy_timing and self.PRE_WRITE_SLEEP:
            sleep(self.PRE_WRITE_SLEEP)

        self._write_raw(command, sensitive=sensitive)

        if self.legacy_timing and self.POST_WRITE_SLEEP:
            sleep(self.POST_WRITE_SLEEP)

    def _flush(self) -> str:
        """
        Read and record whatever output is waiting, so it isn't mistaken for the
        output of the next command. The first time, wait until the output stops
        (e.g. a banner when the connection is opened).
        """
        data = self._read_available()

        if self._first_command:
            self._first_command = False
            quiet_until = monotonic() + self.FIRST_COMMAND_QUIET
            deadline = monotonic() + max(self.timeout, self.FIRST_COMMAND_QUIET)
            while monotonic() < min(quiet_until, deadline):
                result = self._expect_raw([], timeout=quiet_until - monotonic())
                if result.data:
                    data += result.data
                    quiet_until = monotonic() + self.FIRST_COMMAND_QUIET
                if result.eof:
                    break

        if not data:
            return ""

        text = self._record(data)
        self._note_prompt_in_text(text)
        return text

    def _accept_prompt(self, index: int, match: re.Match, buffer: bytearray) -> bool:
        # Index 1 is the unframed prompt. Something that looks like a prompt
        # inside a message (after a STX, before its ETX) is output, e.g. a file.
        if index == 1:
            return not _in_open_message(buffer, match.start())
        return True

    def _expect(
        self,
        extra: Sequence[re.Pattern] = (),
        timeout: float | None = None,
        idle_timeout: float | None = None,
        extra_settle: float = 0.0,
        extra_outside_messages: bool = False,
    ) -> ExpectResult:
        """
        Wait for a prompt (patterns 0 and 1), or one of the ``extra`` patterns
        (patterns 2, 3, ...). The data is recorded, and the access level is
        updated from the prompt.

        Args:
            extra: More patterns to wait for
            timeout: Maximum seconds to wait
            idle_timeout: Stop waiting if nothing arrives for this many seconds
            extra_settle: Seconds to wait for more data after an ``extra`` pattern
                matched at the end of the data, before using it
            extra_outside_messages: Ignore ``extra`` patterns inside a message
                that hasn't ended yet (after a STX, before its ETX), e.g. in a file
        """
        if timeout is None:
            timeout = self.COMMAND_TIMEOUT

        patterns = [FRAMED_PROMPT_RE, UNFRAMED_PROMPT_RE, *extra]
        settle = [0.0, self.PROMPT_SETTLE] + [extra_settle] * len(extra)

        def accept(index: int, match: re.Match, buffer: bytearray) -> bool:
            if index >= 2 and extra_outside_messages:
                return not _in_open_message(buffer, match.start())
            return self._accept_prompt(index, match, buffer)

        result = self._expect_raw(
            patterns,
            timeout=timeout,
            idle_timeout=idle_timeout,
            settle=settle,
            window=self.PROMPT_WINDOW,
            accept=accept,
        )

        if result.data:
            self._record(result.data)

        if result.match is not None and result.index in (0, 1):
            self._set_level_from_prompt(result.match.group("prompt").decode("ascii"))
        elif not result.matched:
            # The relay may be in the middle of something, so the level is unknown
            self.access_level = ""

        return result

    def _set_level_from_prompt(self, prompt: str) -> bool:
        """
        Set the access level from a prompt, e.g. ``"=>>"``. Returns if it was a prompt.

        This works on Telnet and serial. If you disconnect from a serial connection
        without running ``quit``, the access level is preserved when you reconnect,
        and the prompt is how PEAT finds out.
        """
        level = PROMPT_LEVELS.get(prompt.strip())
        if level is None:
            return False

        if level == "SELBOOT":
            self.log.critical(
                f"{self.address} shows the SELBOOT prompt ('!>'): the relay is "
                f"disabled and in its firmware loader. PEAT won't send commands to it."
            )
            self._halt("the relay is in SELBOOT (its firmware loader)")

        self.access_level = level
        self.priv_level = LEVEL_RANKS[level]
        self._seen_prompt = True
        return True

    def _note_prompt_in_text(self, text: str) -> None:
        # The prompt at the end of output that was read without waiting for it
        match = TRAILING_PROMPT_RE.search(text.rstrip().encode(self.ENCODING, errors="replace"))
        if match:
            self._set_level_from_prompt(match.group("prompt").decode("ascii"))

    def _make_response(self, command: str, result: ExpectResult) -> SELResponse:
        raw = self._decode(result.data)
        response = SELResponse(
            command=command,
            raw=raw,
            timed_out=result.timed_out or result.overflow,
            eof=result.eof,
        )

        if result.match is not None and result.index in (0, 1):
            response.prompt = result.match.group("prompt").decode("ascii")
            response.level = PROMPT_LEVELS.get(response.prompt, "")
            response.body = self._decode(result.data[: result.match.start()])
        else:
            response.body = raw

        response.lines = self._output_lines(command, response.body)
        response.error = self._error_message(response.lines)
        return response

    @staticmethod
    def _output_lines(command: str, text: str) -> list[str]:
        lines = clean_lines(text)
        # The relay echoes the command
        if lines and command.strip() and lines[0].casefold().endswith(command.strip().casefold()):
            lines = lines[1:]
        return lines

    @staticmethod
    def _error_message(lines: list[str]) -> str:
        # An error is the only output of a command. Other lines starting with
        # "Invalid" can be output, e.g. the "Invalid Data" SER record.
        error = ERROR_RE.match(lines[0]) if lines else None
        return error.group(1).strip() if error else ""

    def run_command(
        self,
        command: str,
        timeout: float | None = None,
        idle_timeout: float | None = None,
        long: bool = False,
        legacy_delay: float | None = None,
    ) -> SELResponse:
        """
        Send a command, and wait for the prompt that ends its output.

        Args:
            command: The command, e.g. ``"ID"``
            timeout: Maximum seconds to wait for the prompt (the default depends on ``long``)
            idle_timeout: Stop waiting if the relay doesn't send anything for this many
                seconds (default: ``timeout`` of this object, or ``idle_timeout``
                of this object if ``long``)
            long: The command may have a lot of output or take a while to start
                (e.g. SER, HIS, FILE DIR, FILE SHOW)
            legacy_delay: With ``legacy_timing``, sleep this many seconds before
                reading the output (instead of waiting for the prompt)

        Returns:
            The output. If the prompt wasn't seen, ``timed_out`` or ``eof`` is set.

        Raises:
            SELCommandRefused: The command may change the state of the device
                (refer to :mod:`peat.modules.sel.sel_commands`)
            SELSessionHalted: Nothing may be sent on this connection (:attr:`halted`)
        """
        # Before reading, which could open the connection again
        self._check_halted()
        self._check_command(command.encode("latin-1", errors="replace"), terminator=True)

        if self.legacy_timing:
            response = self._legacy_run_command(command, legacy_delay)
        else:
            if timeout is None:
                timeout = self.LONG_COMMAND_TIMEOUT if long else self.COMMAND_TIMEOUT
            if idle_timeout is None:
                idle_timeout = self.idle_timeout if long else self.timeout

            self._flush()
            self._send(command)
            # A question at the end of the output (outside of a message, so not
            # in a file) means the relay is waiting for an answer, e.g. STA at
            # level 2 on a SEL-400 after a board change: "Accept new hardware
            # configuration (Y/N)?" (SEL-421 IM 20130627, Table 9.125). Without
            # this, the next command would be taken as the answer.
            result = self._expect(
                [PENDING_CONFIRM_RE],
                timeout=timeout,
                idle_timeout=idle_timeout,
                extra_settle=self.QUESTION_SETTLE,
                extra_outside_messages=True,
            )
            response = self._make_response(command, result)

            if result.index == 2:
                question = (clean_lines(self._decode(result.data)) or ["?"])[-1]
                response.error = f"Unexpected question: {question}"
                self.log.error(
                    f"{self.address} asked '{question}' after '{command}'. "
                    f"PEAT doesn't answer questions it doesn't expect with Y, answering N."
                )
                self._decline(question)
            elif response.timed_out:
                message = (
                    f"No prompt from {self.address} after '{command}' "
                    f"({len(result.data)} bytes received). The output may be "
                    f"incomplete. If this happens for every command, try the "
                    f"'sel.legacy_ascii_timing' option."
                )
                if self._seen_prompt:
                    self.log.warning(message)
                else:
                    # e.g. a device that isn't a SEL device, during a scan
                    self.log.debug(message)
            elif response.eof:
                self.log.warning(f"Connection to {self.address} closed after '{command}'")

        if response.error.lower().startswith("invalid command"):
            self._mark_unsupported(command)

        self.last_response = response
        self.responses.append(response)
        return response

    def _device_key(self) -> tuple[str, str] | None:
        # Commands that aren't supported are remembered for this device: its
        # address, and its firmware (FID), or its model if the FID isn't known.
        # Not for other devices with the same firmware: one garbled command
        # (e.g. on a noisy serial line) would stop it from being sent to all of them.
        firmware = self.fid or normalize_model(self.model)
        return (self.address, firmware) if firmware else None

    def _mark_unsupported(self, command: str) -> None:
        normalized = normalize_command(command)
        self.unsupported_commands.add(normalized)
        key = self._device_key()
        if key:
            SELAscii._unsupported_commands.setdefault(key, set()).add(normalized)

    def is_unsupported(self, command: str) -> bool:
        """
        If the device answered "Invalid Command" to a command before, on this
        connection, or on an earlier connection to the device (the same address,
        and the same FID, or the same model if the FID isn't known) since
        :meth:`forget_unsupported_commands`.
        """
        normalized = normalize_command(command)
        if normalized in self.unsupported_commands:
            return True
        key = self._device_key()
        return key is not None and normalized in SELAscii._unsupported_commands.get(key, set())

    @classmethod
    def forget_unsupported_commands(cls, address: str | None = None) -> None:
        """
        Forget which commands devices answered with "Invalid Command"
        (refer to :meth:`run_read_command`), so they're sent again.
        :class:`~peat.modules.sel.sel_relay.SELRelay` calls this at the start
        of each pull and restart.

        Args:
            address: Address of the device (IP address or serial port), or
                :obj:`None` for all devices
        """
        for key in [k for k in cls._unsupported_commands if address is None or k[0] == address]:
            del cls._unsupported_commands[key]

    def run_read_command(
        self,
        command: str,
        long: bool = False,
        legacy_delay: float | None = 2.0,
    ) -> SELResponse:
        """
        Run a read-only command, e.g. ``VER`` or ``TIM Q``, and wait for the prompt
        (refer to :meth:`run_command`).

        The command must be one of the read-only commands PEAT uses
        (:data:`~peat.modules.sel.sel_commands.ALLOWED_COMMANDS`). If the device
        answered "Invalid Command" to it before (on this connection, or on an
        earlier connection to the device, refer to :meth:`is_unsupported`), it isn't
        sent again, and the response has ``skipped`` set.

        Args:
            command: The command
            long: The command may have a lot of output (refer to :meth:`run_command`)
            legacy_delay: With ``legacy_timing``, sleep this many seconds before
                reading the output

        Raises:
            SELCommandRefused: The command isn't one of the read-only commands PEAT uses
            SELSessionHalted: Nothing may be sent on this connection (:attr:`halted`)
        """
        check_command(command, strict=True)

        if self.is_unsupported(command):
            self.log.debug(f"Not sending '{command}' to {self.address}: it isn't supported")
            return SELResponse(command=command, error="Invalid Command", skipped=True)

        return self.run_command(command, long=long, legacy_delay=legacy_delay)

    def _legacy_run_command(self, command: str, delay: float | None) -> SELResponse:
        self.read()  # Flush any output from previous operations
        self._send(command)
        if delay:
            sleep(delay)
        raw = self.read(strip_whitespace=False)
        self._note_prompt_in_text(raw)

        response = SELResponse(command=command, raw=raw, body=raw)
        lines = self._output_lines(command, raw)
        response.lines = [x for x in lines if x not in PROMPT_LEVELS]
        response.error = self._error_message(response.lines)
        return response

    def read_lines(self, exclude_command: bool = True, read_until_str: bool = False) -> list[str]:
        """
        Read raw data and process it into a clean trimmed list.

        Args:
            exclude_command: Exclude the first item in the list,
                which is generally the command that was executed
            read_until_str: read until ASCII "0x0003" character
                is encountered, which according to SEL's documentation
                indicates the end of output from a command.
        """
        if read_until_str is True:
            raw_data = self.read_until("\u0003")
        else:
            raw_data = self.read()

        lines = [
            x.strip().replace("\x03\x02", "").replace("\x02", "").strip()
            for x in raw_data.split("\r\n")
            if x
        ]

        # Another filter for empty strings
        # Strings that contain "0x03" and not "0x0302" are
        # strings that contain the prompt, e.g. "=>\u0003".
        lines = [x for x in lines if x and not x.endswith("\x03")]

        if exclude_command:
            return lines[1:]
        else:
            return lines

    def exec_read(
        self,
        command: str,
        return_lines: bool = True,
        added_delay: float | None = None,
        read_until_prompt: bool = False,
        timeout: float | None = None,
    ) -> str | list[str]:
        """
        Execute a command and return the results.

        Args:
            command: The command to execute, e.g. "date" or "id"
            return_lines: If the return value should be a list of
                cleaned and trimmed strings. If False, then the raw
                output is returned unmodified.
            added_delay: With ``legacy_timing``, sleep this long before reading the
                output. Otherwise, PEAT waits for the prompt, and stops waiting if the
                relay doesn't send anything for this long (at least ``timeout`` of this
                object), so the output can take longer than :attr:`COMMAND_TIMEOUT`.
                Until PEAT has seen a SEL prompt on the connection, it stops waiting
                after this long (at least ``timeout`` of this object) in any case.
            read_until_prompt: The command may have a lot of output, or take a while
                to start (refer to ``long`` in :meth:`run_command`)
            timeout: Maximum seconds to wait for the prompt

        Returns:
            The output. :attr:`last_response` has the details, e.g. if the prompt
            wasn't seen before the timeout (``timed_out``).

        Raises:
            SELCommandRefused: The command may change the state of the device
                (refer to :mod:`peat.modules.sel.sel_commands`)
            SELSessionHalted: Nothing may be sent on this connection (:attr:`halted`)
        """
        self._check_halted()
        self._check_command(command.encode("latin-1", errors="replace"), terminator=True)

        if self.legacy_timing:
            self.read()  # Flush any output from previous operations
            self.write(command)
            if added_delay:
                sleep(added_delay)
            if return_lines:
                return self.read_lines(True, read_until_prompt)
            return self.read()

        idle_timeout = None
        if added_delay and not read_until_prompt:
            idle_timeout = max(float(self.timeout), added_delay)
            if timeout is None:
                if self._seen_prompt:
                    timeout = self.LONG_COMMAND_TIMEOUT
                else:
                    # Not known to be a SEL device yet (e.g. "id" during a scan):
                    # a device that keeps sending data, but never a SEL prompt,
                    # isn't read for longer than the old fixed delay.
                    timeout = idle_timeout

        response = self.run_command(
            command,
            timeout=timeout,
            idle_timeout=idle_timeout,
            long=read_until_prompt,
        )

        if return_lines:
            return response.lines

        return response.raw.strip()

    def extract(self, raw_data: str) -> str:
        """
        Extract the actual data payload from raw command output.
        """
        match = self.DATA_REGEX.search(raw_data)

        if not match:
            self.log.error(
                f"Failed to find data in command output.\n** raw data **\n{repr(raw_data)}"
            )
            return ""

        return match.groups()[0].strip()

    # ---------------------------------------------------------------------
    # Access levels
    # ---------------------------------------------------------------------

    def _ensure_priv(self, method_name: str, level: int = 1) -> None:
        """
        Ensure the current command terminal is at a certain privilege level.
        The credentials given to :meth:`elevate` before are used.
        """
        if self.priv_level < level:
            self.log.info(
                f"Method {method_name}() requires privilege level {level}, "
                f"current level is {self.priv_level}. Attempting "
                f"to elevate automatically..."
            )

            if not self.elevate(level, self.creds or None):
                raise DeviceError(f"failed to auto-elevate privilege level on {self.address}")

    def sync_access_level(self) -> str:
        """
        Find out the current access level, by sending an empty line,
        which makes the relay show its prompt.

        Returns:
            The access level (e.g. ``"1"``), or an empty string if no prompt was seen
        """
        if self.legacy_timing:
            self.read()
            self._send("")
            self._note_prompt_in_text(self.read(strip_whitespace=False))
            return self.access_level

        self._flush()
        self._send("")
        self._expect(timeout=self.timeout)
        return self.access_level

    def wait_for_prompt(self, timeout: float, poke_interval: float = 5.0) -> bool:
        """
        Wait until the relay shows its prompt, e.g. after it restarted.

        If the relay doesn't send anything for ``poke_interval`` seconds, a
        carriage return is sent, which makes the relay show its prompt once it's
        ready. With ``AUTO=Y``, a relay on a serial port sends a power-up message
        and the prompt by itself when it starts.

        Returns:
            If the prompt was seen before the timeout (if it's the SELBOOT prompt,
            :attr:`halted` is set)
        """
        if self.halted:
            self.log.error(f"Not waiting for the prompt of {self.address}: {self.halted}")
            return False

        deadline = monotonic() + timeout
        while True:
            remaining = deadline - monotonic()
            if remaining <= 0:
                return False

            result = self._expect(timeout=min(poke_interval, remaining))
            if result.index in (0, 1):
                self._no_exit_commands = self.access_level == "SELBOOT"
                return True
            if result.eof:
                return False
            if deadline - monotonic() > 0:
                self._send("")

    def _cancel_dialog(self) -> bool:
        """
        Send CAN (Ctrl+X) to end a dialog that's waiting for input, e.g. a password
        prompt, without sending anything the relay would take as an answer.

        Returns:
            If the relay showed its prompt again. If it didn't, nothing else is
            sent on this connection (not even QUIT when disconnecting), since it
            would be taken as an answer, e.g. another wrong password (refer to
            :attr:`halted`).
        """
        try:
            self._send(CAN, terminator=False)
            result = self._expect(timeout=self.timeout)
        except Exception as ex:
            self.log.warning(f"Failed to cancel the dialog on {self.address}: {ex}")
            result = None

        if result is None or result.index not in (0, 1):
            self._halt(
                "the relay didn't show its prompt after CAN, so it may still be "
                "waiting for input (e.g. a password)"
            )
            return False
        return True

    def _decline(self, question: str) -> ExpectResult | None:
        """
        Answer ``N`` to a confirmation question, and wait for the prompt. The
        SEL-421 manual documents ``N`` as the way to abort (e.g. "Command aborted").
        If the relay doesn't show its prompt, nothing else is sent on this connection.

        Returns:
            What the relay sent after ``N``, or :obj:`None` if it couldn't be sent
        """
        try:
            self._send("N")
            result = self._expect(timeout=self.timeout)
        except Exception as ex:
            self.log.warning(f"Failed to answer N on {self.address}: {ex}")
            result = None

        if result is None or result.index not in (0, 1):
            self._halt(f"the relay didn't show its prompt after PEAT answered N to '{question}'")
        return result

    def _password_candidates(self, level: str) -> list[Credential]:
        candidates = resolve_level_passwords(
            self.model, self.creds, cal_fallback=self.cal_fallback
        ).get(level, [])

        failed = SELAscii._failed_passwords.get((self.address, level), set())
        remaining = [c for c in candidates if c.password not in failed]

        good = SELAscii._good_passwords.get((self.address, level))
        remaining.sort(key=lambda c: c.password != good)
        return remaining

    def _login_level(self, level: str) -> bool:
        """
        Change to an access level with its command (ACC, 2AC, or CAL), and one
        password at most. Refer to :meth:`elevate`.
        """
        command = LEVEL_COMMANDS[level]
        target = _LEVEL_TARGET[level]

        if level in self._attempted_levels:
            self.log.error(
                f"A {command} password was already sent on this connection to "
                f"{self.address}, not trying again (to avoid a lockout)"
            )
            return False

        candidates = self._password_candidates(level)
        if not candidates:
            self.log.error(f"No {command} password left to try for {self.address}")
            return False
        cred = candidates[0]

        self.log.debug(f"Elevating to level {target} ({command})")
        self._flush()
        if level == "cal":
            # Level C allows calibration commands, so the login is only allowed here
            with self._allow_state_changes("login to access level C (CAL)"):
                self._send(command)
        else:
            self._send(command)
        first = self._expect(
            [PASSWORD_RE], timeout=self.COMMAND_TIMEOUT, idle_timeout=self.timeout
        )

        if not first.matched:
            self.log.error(
                f"No response from {self.address} to {command} "
                f"({'connection closed' if first.eof else 'timed out'})"
            )
            if not first.eof and b"assword" in first.data:
                # Probably a password prompt PEAT doesn't know. Anything sent
                # now would be taken as a password.
                self._cancel_dialog()
            return False

        if first.index == 2:  # Password prompt
            self._attempted_levels.add(level)
            if cred.source == "configured":
                self.register_secret(cred.password)

            self.log.debug(f"Sending {command} password {cred}")
            self._send_password(cred.password)
            second = self._expect(
                [PASSWORD_RE], timeout=self.COMMAND_TIMEOUT, idle_timeout=self.timeout
            )

            if second.index == 2:
                # A wrong password: the relay asks again. After three wrong
                # passwords, the relay blocks access for 30 s and pulses BADPASS.
                SELAscii._failed_passwords.setdefault((self.address, level), set()).add(
                    cred.password
                )
                self.log.error(
                    f"{self.address} rejected the {command} password {cred}. "
                    f"Not trying another password on this connection, to avoid "
                    f"an alarm or a lockout."
                )
                self._cancel_dialog()
                return False

            if not second.matched:
                self.log.error(
                    f"No prompt from {self.address} after the {command} password "
                    f"({'connection closed' if second.eof else 'timed out'})"
                )
                if not second.eof:
                    # The relay may still be asking for the password
                    self._cancel_dialog()
                return False
            response = self._make_response(command, second)
        else:
            # A prompt without a password prompt: no password is needed
            # (e.g. the access jumper is installed), or the level isn't allowed
            response = self._make_response(command, first)

        if self.priv_level >= target:
            self.successful_usernames.add(level)
            if first.index == 2:
                SELAscii._good_passwords[(self.address, level)] = cred.password
            self.log.debug(f"Now at access level {self.access_level} ({response.prompt})")
            return True

        text = response.error or " ".join(response.lines)[:200]
        if "access level" in text.lower() and level != "acc":
            self.log.error(
                f"{self.address} refused {command}: '{text}'. The port's maximum "
                f"access level (MAXACC setting) probably doesn't allow it."
            )
        else:
            self.log.error(
                f"{command} failed on {self.address}: the access level is "
                f"'{self.access_level or 'unknown'}' after the command ('{text}')"
            )
        if first.index == 2:
            SELAscii._failed_passwords.setdefault((self.address, level), set()).add(cred.password)
        return False

    def elevate(self, level: int, creds: Mapping[str, Any] | None = None) -> bool:
        """
        Elevates user privileges on the device.

        PEAT sends the command for each level (ACC, then 2AC, then CAL), waits
        for the relay to ask for the password, sends it, and checks the prompt
        the relay shows next. If the relay asks for the password again, it was
        wrong: PEAT cancels the dialog (CAN) and doesn't try another password on
        the same connection, since three wrong passwords lock out access for 30
        seconds and assert the BADPASS alarm. A password that failed isn't tried
        again for the same device (until :meth:`forget_passwords`), but the next
        candidate (if any) is tried on a new connection. If the relay doesn't show
        its prompt after CAN, nothing else is sent on the connection (:attr:`halted`).

        Args:
            level: Privilege level to elevate to, as a :class:`int`. Available levels:

                - ``1`` : The ``acc`` level
                - ``2`` : The ``2ac`` level
                - ``3`` : The ``cal`` level (aka the ``calibration`` level)
            creds: Login credentials to use for each level, as a :class:`dict`.
                Example: ``{"acc": "l1pass", "2ac": "l2pass", "cal": "calpass"}``.
                A value can also be a list of passwords to try (one per connection).
                Levels that aren't set use the factory defaults for the model
                (``model``), refer to :mod:`peat.modules.sel.sel_default_creds`.
                The credentials are remembered and used for automatic elevations.

        Returns:
            If the privilege elevation was successful
        """
        self.log.debug(f"Elevating to privilege level {level} from {self.priv_level}")

        if level > 3 or level < 1:
            self.log.error(f"Invalid SEL privilege level: {level}")
            return False

        if creds:
            self.creds = {str(k).lower(): v for k, v in creds.items()}

        if self.halted:
            self.log.error(f"Not elevating on {self.address}: {self.halted}")
            return False

        try:
            if not self.access_level:
                self.sync_access_level()

            if self.access_level == "SELBOOT":
                self.log.error(f"Not elevating on {self.address}: the relay is in SELBOOT")
                return False

            if self.priv_level >= level:
                self.log.debug(f"Already at privilege level {level}, no elevation commands sent")
                return True

            while self.priv_level < level:
                next_level = _NEXT_LEVEL.get(self.priv_level)
                if next_level is None:
                    self.log.critical(f"Unexpected elevation level: {level}")
                    state.error = True
                    return False
                if not self._login_level(next_level):
                    return False
        except SELSessionHalted as ex:
            # Keep the connection: disconnecting could reopen it (and on Telnet,
            # it would forget that it's halted)
            self.log.error(f"Failed elevation to privilege level {level}: {ex}")
            return False
        except Exception as ex:
            self.log.debug(
                f"Failed elevation to privilege level {level} from {self.priv_level}: {ex}"
            )
            self.disconnect()
            return False

        self.log.info(f"Elevated to privilege level {level}")
        return True

    # ---------------------------------------------------------------------
    # Commands
    # ---------------------------------------------------------------------

    def _confirm_dialog(self, command: str, answer: str = "Y") -> tuple[bool, list[str]]:
        """
        Send a command that asks for confirmation, and answer it.
        Returns if the command was confirmed, and the dialog.
        """
        transcript = []
        self._flush()
        self._send(command)
        result = self._expect([CONFIRM_RE], timeout=self.COMMAND_TIMEOUT)
        text = self._decode(result.data)
        transcript.append(text)

        if result.index != 2:
            return False, transcript

        if NEVER_CONFIRM_RE.search(text):
            self.log.error(f"Unexpected question from {self.address}, answering N: {text!r}")
            self._decline(text.strip())
            return False, transcript

        self._send(answer)
        after = self._expect(timeout=self.COMMAND_TIMEOUT)
        transcript.append(self._decode(after.data))
        return True, transcript

    def get_active_group(self) -> str:
        """
        Determine the currently active settings group on a relay (``gro`` command)

        Returns:
            The active settings group
        """
        self.log.debug("Checking the active settings group")

        # "gro" command requires level 1 (show the active group)
        self._ensure_priv("get_active_group", level=1)

        raw_grp = self.run_command("gro", legacy_delay=self.POST_WRITE_SLEEP).raw
        active_res = re.search(
            r".*Active\s+Group\s+=\s+(\d+).*", raw_grp, re.ASCII | re.IGNORECASE
        )

        if not active_res:
            self.log.warning("Unable to determine active settings group")
            return ""

        active_group = str(active_res.groups()[0])

        self.log.debug(f"Active settings group: {active_group}")
        return active_group

    def change_active_group(self, new_group: str) -> None:
        """
        Change the active setting group via the ``gro`` command.

        .. note::
           If the currently active group matches the group to change to then
           the group change command will NOT be executed.

        .. warning::
           This method will NOT validate if the group number being changed
           to is valid for this particular relay!

        Args:
            new_group: Group to change to. Examples: ``"6"``, ``"1"``
        """
        # TODO: validate the group number is valid
        current_group = self.get_active_group()

        if not current_group:
            self.log.warning("Unable to determine active settings group")
        elif current_group == new_group:
            self.log.info(f"Settings group '{new_group}' is already active, skipping change")
            return

        # Change active group requires level 2
        self._ensure_priv("change_active_group", level=2)

        self.log.info(f"Changing active group from '{current_group}' to '{new_group}'")

        with self._allow_state_changes(f"change the active settings group to {new_group}"):
            if self.legacy_timing:
                self.write(f"gro {new_group}")
                sleep(self.POST_WRITE_SLEEP)
                self.write("y")  # answer yes to prompt
            else:
                confirmed, transcript = self._confirm_dialog(f"gro {new_group}")
                if not confirmed:
                    self.log.error(f"Active group change was not confirmed: {transcript}")
                    return

        self.log.info(f"Active group changed to '{new_group}'")

    def restart_device(
        self,
        confirm_timeout: float = 10.0,
        reboot_timeout: float = 10.0,
    ) -> RestartResult:
        """
        Execute a system restart on the SEL relay (``STA C`` command).

        PEAT checks that the relay shows the level 2 prompt (``=>>``), records the
        FID and the relay's time, sends ``STA C``, and waits for the confirmation question
        ("Are you sure (Y/N) ?"). It answers ``Y`` and then the relay says it's
        rebooting ("Rebooting the relay"), closes the connection, or stops
        responding, any of which mean the restart was initiated. If the relay
        answers with an error (e.g. "Invalid Access Level") or the prompt, or
        doesn't ask for confirmation, the restart failed. Questions about the
        hardware configuration, firmware, or defaults are answered with ``N``.

        After the restart was initiated, nothing else is sent on this
        connection (the relay isn't sent QUIT when disconnecting).

        .. warning::
           This interrupts protection while the relay restarts, and clears all
           relay self-test warnings and failures

        Args:
            confirm_timeout: Seconds to wait for the confirmation question
            reboot_timeout: Seconds to wait for the relay to respond after ``Y``.
                If it doesn't, it's assumed to be restarting.

        Returns:
            The result. It's "truthy" if the restart was initiated, so it can be
            used like the :class:`bool` this method returned before.
        """
        self.log.warning(f"Restarting relay {self.address} (STA C)")

        if self.model and normalize_model(self.model) in ("2030", "2032"):
            return RestartResult(
                "unsupported",
                f"the SEL-{normalize_model(self.model)} has no SEL ASCII command to restart it",
            )

        result = RestartResult("failed")

        try:
            self._ensure_priv("restart_device", level=2)

            # The level must be shown by the relay, not assumed
            self.sync_access_level()
            if LEVEL_RANKS.get(self.access_level, 0) < 2:
                result.reason = (
                    f"the relay isn't at access level 2 (prompt shows level "
                    f"'{self.access_level or 'unknown'}')"
                )
                return result

            info = self.get_id()
            result.fid = str(info.get("FID", ""))
            try:
                # The relay's clock, to compare with the power-up record in the SER
                result.device_time = self.get_device_time()
            except Exception as ex:
                self.log.debug(f"Failed to read the time before the restart: {ex}")

            self._flush()
            with self._allow_state_changes("restart (STA C)"):
                self._send("STA C")
            confirm = self._expect([CONFIRM_RE], timeout=confirm_timeout)
            text = self._decode(confirm.data)
            result.transcript.append(text)

            if confirm.eof:
                result.status = "unknown"
                result.reason = "the connection closed before the relay asked for confirmation"
                self._no_exit_commands = True
                return result

            if confirm.index != 2:
                response = self._make_response("STA C", confirm)
                if response.error:
                    result.reason = f"the relay answered '{response.error}'"
                elif confirm.matched:
                    result.reason = "the relay showed its prompt without asking for confirmation"
                else:
                    result.reason = (
                        f"the relay didn't ask for confirmation within {confirm_timeout} s"
                    )
                    self._cancel_dialog()
                return result

            if NEVER_CONFIRM_RE.search(text):
                result.reason = f"unexpected question, answered N: {text.strip()!r}"
                declined = self._decline(text.strip())
                if declined is not None:
                    result.transcript.append(self._decode(declined.data))
                return result

            result.initiated_at = utils.utc_now()
            try:
                with self._allow_state_changes("confirm the restart (STA C)"):
                    self._send("Y")
                after = self._expect([REBOOTING_RE], timeout=reboot_timeout)
                result.transcript.append(self._decode(after.data))
            except (OSError, EOFError) as ex:  # e.g. ConnectionResetError
                after = None
                result.transcript.append(f"<{type(ex).__name__}: {ex}>")

            if after is None or after.eof:
                result.status = "initiated"
                result.reason = "the relay closed the connection"
            elif after.index == 2:
                result.status = "initiated"
                result.reason = "the relay said it's restarting"
            elif after.timed_out:
                result.status = "initiated"
                result.reason = f"the relay stopped responding for {reboot_timeout} s"
            elif self.access_level == "SELBOOT":
                # It restarted, but in its firmware loader (nothing is sent to it now)
                result.status = "initiated"
                result.reason = "the relay showed the SELBOOT prompt (it restarted in SELBOOT)"
                self.priv_level = 0
                self.log.critical(f"Relay {self.address} restarted in SELBOOT")
                return result
            elif self.access_level == "0":
                # A relay that restarted starts at level 0. On a serial port with
                # AUTO=Y, it sends a power-up message and the prompt.
                result.status = "initiated"
                result.reason = "the relay showed the access level 0 prompt (it restarted)"
                self._no_exit_commands = False
                self.priv_level = 0
                self.log.warning(f"Relay {self.address} restarted: {result.reason}")
                return result
            else:
                response = self._make_response("Y", after)
                result.reason = (
                    f"the relay showed its prompt after Y ('{' '.join(response.lines)}')"
                )
                return result
        except DeviceError as ex:
            result.reason = f"failed to elevate to level 2: {ex}"
            return result
        except Exception as ex:
            self.log.error(f"Exception during restart: {ex}")
            result.reason = f"exception: {ex}"
            if result.initiated_at:
                # The relay may have dropped the connection when it restarted
                result.status = "unknown"
            return result

        # The relay is restarting. Don't send anything else on this connection.
        self._no_exit_commands = True
        self.priv_level = 0
        self.access_level = ""
        self.log.warning(f"Relay {self.address} restart initiated: {result.reason}")
        return result

    def get_sta(self) -> dict[str, datetime | str]:
        """
        ``sta`` command (basic device information and status).

        .. warning::
           This function currently does not work reliably on all devices

        Returns:
            Data extracted from the command output.
            Refer to :func:`~peat.modules.sel.relay_parse.parse_status_output`
            for details on the data extracted from the command.
        """
        self._ensure_priv("get_sta", level=1)

        if self.legacy_timing:
            output = self.exec_read("sta", read_until_prompt=True)
        else:
            output = self.run_command("sta", long=True).lines

        return parse_status_output(output)

    def get_id(self) -> dict[str, str | list[str]]:
        """
        ``id`` command.

        Typical information pulled by ``id``

        - FID
        - BFID
        - CID
        - Device name (``DEVID``)
        - Part number (``PARTNO``)
        - Serial number (``SERIALNO``)
        - Hardware configuration (?) (``CONFIG``)
        - ``Special``
        - IED Name (``iedName``)
        - Type
        - Configuration version (``configVersion``)

        Refer to :func:`~peat.modules.sel.sel_cascii.parse_id_output`
        for details on how the output is parsed.
        """
        raw = self.exec_read("id", return_lines=False, added_delay=5.0)

        self.log.trace2(f"** Unparsed 'id' command output **\n{raw!r}")
        if not raw:
            return {}

        info = parse_id_output(raw)

        # The model determines the default passwords
        if not self.model and info.get("FID"):
            self.model = normalize_model(str(info["FID"]))
        if info.get("FID"):
            self.fid = str(info["FID"])

        self.log.trace2(f"** get_id() => 'info' **\n{info}")
        return info

    def parse_exit_info(self, raw: str) -> dict[str, datetime | str]:
        """
        Extract info returned when we disconnect cleanly (run ``exit``).

        Info keys

        - ``time_source`` (Optional)
        - ``RID``
        - ``device_time``
        - ``TID``

        Info includes the RID, TID, and current device time. It may also
        include the time source identifier.
        """
        # TODO: unit test
        # TODO: merge this parsing with relay_parse.parse_status_info()
        info = {}
        clean = raw.replace("\x02", "").replace("\x03", "").strip("=")
        if "Time Source" in clean:
            ts_match = re.search(r"Time Source: ([\w ]*)\s", clean)
            if ts_match:
                info["time_source"] = ts_match.groups()[0]
            clean = clean.split("Time Source")[0]

        # TODO: group 4 (TID) may not exist on some devices, like weird a SEL-311L
        regex = r"(?:quit|exit)\s*([\S ]*)\s*Date\: (\S*)\s*Time\: (\S*)\s*([\S ]*)\s"
        match = re.search(regex, clean, re.ASCII)
        if not match:
            self.log.warning("Failed to parse info returned on exit")
            return info

        data = match.groups()
        info["RID"] = data[0].strip()
        info["device_time"] = date_parse(f"{data[1]} {data[2]}")
        info["TID"] = data[3].strip()

        if info["TID"] == "#exit":
            info["TID"] = ""

        return info

    def list_files(self, directory: str | None = None) -> list[str]:
        """
        List files in a directory on the device.

        .. note::
           File listing requires level 1 (``acc``) permissions on all devices
           we've seen. The privilege level will be automatically escalated
           when this function is called, if needed.

        Args:
            directory: Case-insensitive name of directory to list the contents of.
                If :obj:`None` or empty string, the current directory is listed.

        Returns:
            List of names of files in the directory.

        Raises:
            DeviceError: Automatic privilege elevation failed
        """
        self._ensure_priv("list_files", level=1)

        if directory:
            dir_name = f"directory '{directory}'"
        else:
            dir_name = "the current directory"

        self.log.info(f"Reading file listing of {dir_name}")

        command = f"fil dir {directory}" if directory else "fil dir"
        # It takes 5-15 seconds for the listing to start on some relays
        response = self.run_command(command, long=True, legacy_delay=10.0)

        if response.timed_out:
            self.log.warning(f"The file listing of {dir_name} may be incomplete")

        # parse the filenames into a list of strings
        parsed_file_list = []

        for line in response.lines:
            # If directory is empty or doesn't exist
            if "file specified does not exist" in line.lower():
                self.log.warning(f"{dir_name} is empty or doesn't exist")
                return []

            if line in PROMPT_LEVELS or ERROR_RE.match(line):
                continue

            m = re.search(r"(?P<item>[\w.]+)\s+(?P<type>\w)", line, re.ASCII | re.IGNORECASE)

            if m:
                name = m.groups()[0]  # name, filetype ('R' or 'D')
                if name.lower() != "fil":
                    parsed_file_list.append(name)
            elif config.DEBUG >= 3:
                self.log.trace3(f"Failed to match line: {line}")

        self.log.trace(f"** File listing of {dir_name} **\n{parsed_file_list}")
        return parsed_file_list

    def show_file(self, filename: str) -> str | None:
        """
        Read a file with the ``FILE SHOW`` command (``fil show <filename>``).

        PEAT waits for the end of the file (ETX) and the prompt, so slow
        connections don't cut the file off.

        Args:
            filename: Name of the file, or the directory and file name
                separated by a space (e.g. ``"SETTINGS SET_1.TXT"``)

        Returns:
            The contents of the file (without the framing), or :obj:`None`
            if it wasn't received completely or the relay returned an error
        """
        command = f"fil show {filename}"
        response = self.run_command(command, long=True)

        match = self.DATA_REGEX.search(response.body)
        if match:
            # The relay frames an error message with STX and ETX, like a file
            # (SEL-2032 IM 20120126, Figure 8.1), e.g. "\x02\r\nInvalid File Name\r\n\x03"
            message = self._output_lines(command, match.group(1))
            if len(message) == 1 and FILE_ERROR_RE.match(message[0]):
                response.error = response.error or message[0]
                self.log.error(f"Failed to read '{filename}': '{message[0]}'")
                return None

        if not match:
            if response.error:
                self.log.error(f"Failed to read '{filename}': '{response.error}'")
            elif response.timed_out or response.eof:
                self.log.error(
                    f"Failed to read '{filename}' from {self.address}: no end of file "
                    f"was received ({len(response.raw)} characters received)"
                )
            else:
                self.log.error(
                    f"Failed to find the data in the output of 'fil show {filename}' "
                    f"from {self.address}"
                )
            return None

        if response.timed_out:
            # The file was received completely (ETX), only the prompt is missing
            self.log.warning(f"No prompt after the end of '{filename}' from {self.address}")

        return match.group(1)

    def show_bre(self) -> list[str]:
        """
        ``bre`` command. Provides the Breaker monitor report.
        """
        self._ensure_priv("show_bre", level=1)

        return self.exec_read("bre", added_delay=2.0)

    def show_mac(self) -> dict[str, str]:
        """
        ``mac`` command: the MAC addresses of the Ethernet ports.

        Both formats are read (refer to
        :func:`~peat.modules.sel.relay_command_parse.parse_mac_output`):
        ``Port 1 MAC Address: 00-30-A7-00-00-00`` (in the SEL-351S and SEL-751A
        manuals) and ``(IP) MAC`` / ``(GOOSE) MAC`` (seen on a SEL-351S).

        Returns:
            MAC addresses (uppercase, colon-separated), keyed by ``ip_mac`` and
            ``goose_mac`` (the second format, as before), ``port_<n>_mac``
            (e.g. ``port_1_mac``), or ``mac``
        """
        self._ensure_priv("show_mac", level=1)

        output = self.exec_read("mac", return_lines=False, read_until_prompt=True)
        return {mac_result_key(label): mac for label, mac in parse_mac_output(output).items()}

    def show_eth(self) -> list[str]:
        """
        ``eth`` command.
        """
        return self.exec_read("eth", added_delay=2.0)

    def get_device_time(self) -> datetime | None:
        """
        Combines output of ``date`` and ``time`` commands.

        On the SEL-451 and some other models, the output may also contain timezone information.
        This information will be returned as part of the :class:`datetime.datetime` object.
        """
        self._ensure_priv("get_device_time", level=1)

        raw_date = self.exec_read("date")
        raw_time = self.exec_read("time")

        if not raw_date or not raw_time:
            return None

        raw_date = raw_date[0]
        raw_time = raw_time[0]

        # Attempt to infer the device's timezone from UTC offset in output of commands
        tz_offset = ""

        # SEL-451
        if "UTC " in raw_date:
            # date: "local: 02/09/2023     UTC: 02/09/2023     UTC Offset: -08.0 hrs"
            # time: "local: 14:35:20     UTC: 22:35:20     UTC Offset: -08.0 hrs"
            regex = re.compile(
                (
                    r"local\: (?P<local>[\d/:]+) \s+ UTC\: (?P<utc>[\d/:]+) "
                    r"\s+ UTC Offset\: (?P<offset>.+) hrs"
                ),
                re.ASCII | re.IGNORECASE,
            )
            d_match = regex.match(raw_date)
            t_match = regex.match(raw_time)

            if not d_match or not t_match:
                return None

            dates = d_match.groupdict()
            times = t_match.groupdict()

            raw_date = dates["local"]
            raw_time = times["local"]
            tz_offset = dates["offset"].replace(".", ":")

        # SEL-700G
        elif ":=" in raw_date:
            # date: "Date     := 02/09/2023"
            # time: "Time     := 15:51:00.265"
            raw_date = raw_date.partition(":=")[2].strip()
            raw_time = raw_time.partition(":=")[2].strip()

        # 2032, 351, 351S
        # "02/09/23"
        # "14:28:06"

        # "02/09/23 15:51:00.265"
        ts_string = f"{raw_date} {raw_time} {tz_offset}".strip()

        return utils.parse_date(ts_string)

    def show_his(self) -> list[str]:
        """
        ``his`` command.
        """
        return self.exec_read("his", added_delay=15.0, read_until_prompt=True)

    def show_status(self) -> list[str]:
        """
        ``sta s`` command.

        Known devices that DO NOT support this command:

        - SEL-2032
        - SEL-351
        - SEL-351S
        """
        return self.exec_read("sta s")

    def show_ser(self) -> list[str]:
        """
        ``ser`` command. Sequential Event Recorder (SER).

        The command depends on the model (refer to
        :func:`~peat.modules.sel.sel_commands.ser_command`): ``SER 1000`` on
        SEL-400 series relays, where ``SER`` returns only the 20 newest records
        (if the relay rejects ``SER 1000``, ``SER`` is used), ``SER GLOBAL 100``
        on the SEL-2032, which keeps a SER for each port, and ``SER`` on other
        relays, which returns all of the records.

        NOTE: this can take a while if the SER has a lot of entries.
        PEAT waits until the relay stops sending (refer to ``idle_timeout``).
        """
        command = ser_command(self.model)

        if normalize_model(self.model) in ("2030", "2032"):
            return self.exec_read(command, added_delay=5.0)

        if command.upper() != "SER":
            # e.g. "SER 1000" on 400 series relays
            if not self.is_unsupported(command):
                start = len(self.responses)
                result = self.exec_read(command, read_until_prompt=True, added_delay=10.0)
                responses = self.responses[start:]
                if responses:
                    error = responses[-1].error
                else:
                    # With legacy_timing, exec_read() doesn't record a response
                    # (and last_response is from an earlier command), so the
                    # error is read from the output
                    lines = result if isinstance(result, list) else clean_lines(result)
                    error = self._error_message(lines)
                    if error.lower().startswith("invalid command"):
                        self._mark_unsupported(command)
                if not error:
                    return result
                self.log.warning(f"{self.address} answered '{error}' to '{command}', using 'SER'")
            command = "SER"

        return self.exec_read(command, read_until_prompt=True, added_delay=10.0)

    def show_sum(self) -> list[str]:
        """
        ``sum`` command.

        Potentially not present on:

        - SEL-2032
        - SEL-351
        """
        return self.exec_read("sum")

    def show_eve(self) -> list[str]:
        """
        ``eve`` command. Event reports.
        """
        return self.exec_read("eve", added_delay=2.0)


__all__ = [
    "RestartResult",
    "SELAscii",
    "SELCommandRefused",
    "SELResponse",
    "SELSessionHalted",
    "clean_lines",
    "mac_result_key",
]
