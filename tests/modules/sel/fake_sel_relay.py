"""
A scripted SEL relay for testing PEAT's SEL ASCII sessions without hardware.

It's modeled on the behavior documented in public SEL instruction manuals
(SEL-351S IM 20171023 Section 10 "Communications", SEL-421 IM 20130627
User's Guide Section 4 and Reference Manual Section 5):

- The relay echoes each command line. Output is framed as a message
  (STX, CR LF lines, ETX), followed by the prompt in its own message
  (``b"\\x02\\r\\n=>>\\x03"``), as in the ``id`` example in docs/sel.rst.
  Error messages (e.g. "Invalid Command") are framed too, as the SEL-2032 IM
  (20120126, Figure 8.1 "Noninteractive Message Format") says for all messages.
- ACC, 2AC, and CAL ask "Password: ?" and echo a "*" for each character. A wrong
  password makes the relay ask again. After three wrong passwords the relay
  says "Invalid Access" and the lockout starts (counted in ``lockouts``).
- CAN (Ctrl+X) cancels the password dialog.
- With ``sta_question``, STA at level 2 asks "Accept new hardware configuration
  (Y/N)?", and N aborts it (SEL-421 IM 20130627, Table 9.125).
- STA C asks "Reboot the relay and clear status" / "Are you sure (Y/N) ?",
  then answers "Rebooting the relay" (300 series dialog, 351S IM p.10.79).

The engine (:class:`FakeSELRelay`) isn't tied to a transport: :class:`SocketRelay`
serves it on a socket (TCP on 127.0.0.1, or a socket pair), and
:class:`FakeSerialPort` is a pyserial-like port for SELSerial.
All data is synthetic.
"""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Callable

from peat.modules.sel.sel_cascii import format_record

STX = b"\x02"
ETX = b"\x03"
CAN = b"\x18"

PROMPTS = {"0": "=", "1": "=>", "B": "==>", "2": "=>>", "C": "==>>"}
RANKS = {"0": 0, "1": 1, "B": 1, "2": 2, "C": 3}

FID_351S = "SEL-351S-7-R516-V2-Z106105-D20190111"
FID_451 = "SEL-451-5-R324-V1-Z027013-D20201009"
FID_751 = "SEL-751-R300-V3-Z008004-D20210104"


class FakeSELRelay:
    """
    The relay's command interpreter. ``send`` is called with the bytes the relay sends.
    """

    def __init__(
        self,
        fid: str = FID_351S,
        passwords: dict[str, str | None] | None = None,
        files: dict[str, str] | None = None,
        level: str = "0",
        framed_prompts: bool = True,
        maxacc: str = "C",
        sta_c: str = "close",
        echo_passwords: bool = False,
        frame_errors: bool = True,
        prompt_prefix: bytes = b"\r\n",
        ignore_can: bool = False,
        sta_question: bool = False,
    ) -> None:
        """
        Args:
            fid: The FID in the ``id`` output
            passwords: Password of each level (None: no password needed)
            files: Files for FIL DIR and FIL SHOW, ``{"SETTINGS SET_1.TXT": "..."}``
            level: The access level at the start
            framed_prompts: Frame prompts with STX/ETX, as SEL relays do
            maxacc: Highest level the port allows (MAXACC setting)
            sta_c: What the relay does after STA C is confirmed: ``"close"`` (says it's
                rebooting and closes the connection), ``"silent"`` (closes without a
                message), ``"hang"`` (says nothing, keeps the connection),
                ``"prompt"`` (shows the prompt again), ``"no_confirm"``
                (shows the prompt without asking), ``"hardware"`` (asks about
                a new hardware configuration), ``"ignore"`` (doesn't answer STA C),
                ``"drop"`` (closes the connection when it gets STA C)
            echo_passwords: Echo passwords as typed, instead of a "*" per character
            frame_errors: Frame error messages with STX and ETX
            prompt_prefix: What's between the STX and a framed prompt (the SEL-2032
                sends a space, ``<STX> <PROMPT><ETX>``)
            ignore_can: Ignore CAN: a password dialog stays open
            sta_question: STA at level 2 asks about a new hardware configuration
        """
        self.fid = fid
        self.passwords = (
            passwords
            if passwords is not None
            else {
                "acc": "OTTER",
                "2ac": "TAIL",
                "cal": "CLARKE",
            }
        )
        self.files = files or {}
        self.level = level
        self.framed_prompts = framed_prompts
        self.maxacc = maxacc
        self.sta_c = sta_c
        self.echo_passwords = echo_passwords
        self.frame_errors = frame_errors
        self.prompt_prefix = prompt_prefix
        self.ignore_can = ignore_can
        self.sta_question = sta_question

        self.send: Callable[[bytes], None] = lambda _data: None
        self.close: Callable[[], None] = lambda: None

        #: Every line received (passwords included), for assertions
        self.lines: list[bytes] = []
        #: Passwords received, per level
        self.password_attempts: dict[str, list[str]] = {}
        self.bad_password_count = 0
        self.lockouts = 0
        self.cancels = 0
        #: Answers to questions: (command, answer)
        self.answers: list[tuple[str, str]] = []
        self.restarted = False
        self.closed = False
        #: Called when the relay restarts
        self.on_restart: Callable[[], None] = lambda: None

        self._buffer = b""
        self._pending_level: str | None = None  # waiting for this level's password
        self._pending_confirm: str | None = None  # waiting for Y/N for this command

    # -- output helpers --------------------------------------------------

    def prompt(self) -> bytes:
        text = PROMPTS[self.level].encode()
        if self.framed_prompts:
            return STX + self.prompt_prefix + text + ETX
        return b"\r\n" + text

    def message(self, lines: list[str]) -> bytes:
        body = "".join(f"{line}\r\n" for line in lines).encode("latin-1")
        return STX + b"\r\n" + body + ETX

    def respond(self, lines: list[str] | None = None, text: str = "") -> None:
        data = b""
        if lines is not None:
            data += self.message(lines)
        if text:
            data += STX + text.encode() + ETX if self.frame_errors else text.encode()
        self.send(data + self.prompt())

    def header(self) -> list[str]:
        return [
            "FEEDER 1                         Date: 02/02/09    Time: 08:31:10.361",
            "STATION A",
        ]

    # -- input -----------------------------------------------------------

    def feed(self, data: bytes) -> None:
        if self.closed:
            return
        self._buffer += data
        while not self.closed:
            found = [
                (index, kind)
                for kind, index in (
                    ("can", self._buffer.find(CAN)),
                    ("cr", self._buffer.find(b"\r")),
                    ("lf", self._buffer.find(b"\n")),
                )
                if index >= 0
            ]
            if not found:
                return
            index, kind = min(found)

            if kind == "can":
                # CAN discards what was typed, and cancels the dialog
                self._buffer = self._buffer[index + 1 :]
                self.cancels += 1
                if not self.ignore_can:
                    self._cancel()
                continue

            line = self._buffer[:index]
            rest = self._buffer[index + 1 :]
            if kind == "cr" and rest.startswith(b"\n"):
                rest = rest[1:]
            self._buffer = rest
            self.lines.append(line)
            self._handle(line.decode("latin-1"))

    def boot(self) -> None:
        """Start again after a restart: level 0, and the power-up message and prompt."""
        self.closed = False
        self.level = "0"
        self._pending_level = None
        self._pending_confirm = None
        self.send(b"\r\n" + self.message(self.header()) + self.prompt())

    def _cancel(self) -> None:
        self._pending_level = None
        self._pending_confirm = None
        self.send(b"\r\n" + self.prompt())

    def _password(self, text: str) -> None:
        level = self._pending_level
        key = {"1": "acc", "2": "2ac", "C": "cal"}[level]
        self.password_attempts.setdefault(key, []).append(text)
        echo = text.encode("latin-1") if self.echo_passwords else b"*" * len(text)
        self.send(echo + b"\r\n")

        if text == self.passwords.get(key):
            self._pending_level = None
            self.level = level
            self.respond([*self.header(), "", f"Level {level}"])
            return

        self.bad_password_count += 1
        if len(self.password_attempts[key]) % 3 == 0:
            # Third wrong password: lockout
            self.lockouts += 1
            self._pending_level = None
            self.respond(text="Invalid Access\r\n")
        else:
            self.send(b"Password: ? ")

    def _login(self, target: str) -> None:
        key = {"1": "acc", "2": "2ac", "C": "cal"}[target]
        required = {"1": 0, "2": 1, "C": 2}[target]
        if RANKS[self.level] < required or RANKS[target] > RANKS[self.maxacc]:
            self.respond(text="Invalid Access Level\r\n")
            return
        if self.passwords.get(key) is None:
            self.level = target
            self.respond([*self.header(), "", f"Level {target}"])
            return
        self._pending_level = target
        self.send(b"Password: ? ")

    def _handle(self, text: str) -> None:
        if self._pending_level is not None:
            self._password(text)
            return

        # Echo the command
        self.send(text.encode("latin-1") + b"\r\n")

        if self._pending_confirm is not None:
            command = self._pending_confirm
            self._pending_confirm = None
            self._answer(command, text.strip().upper())
            return

        words = text.strip().split()
        cmd = words[0].upper()[:3] if words else ""
        args = words[1:]

        if cmd == "":
            self.send(self.prompt())
        elif cmd == "ACC":
            self._login("1")
        elif cmd == "2AC":
            self._login("2")
        elif cmd == "CAL":
            self._login("C")
        elif cmd == "ID":
            self.respond(
                [
                    format_record([f"FID={self.fid}"]),
                    format_record(["CID=59A0"]),
                    format_record([f"DEVID={self.fid.split('-R')[0]}"]),
                    format_record(["PARTNO=0351S61H4455421"]),
                ]
            )
        elif cmd == "QUI":
            self.level = "0"
            self.respond(self.header())
        elif cmd == "EXI":
            self.closed = True
            self.close()
        elif cmd == "FIL":
            self._file(args)
        elif cmd == "STA":
            if args and args[0].upper() in ("C", "R"):
                self._sta_c()
            elif RANKS[self.level] < 1:
                self.respond(text="Invalid Access Level\r\n")
            elif self.sta_question and RANKS[self.level] >= 2:
                self.send(
                    self.message([f"FID={self.fid}  CID=59A0", "Warnings: hardware"])
                    + b"Accept new hardware configuration (Y/N)?"
                )
                self._pending_confirm = "STA"
            else:
                self.respond([f"FID={self.fid}  CID=59A0", "Relay Enabled"])
        elif cmd == "DAT":
            self.respond(["02/02/09"])
        elif cmd == "TIM":
            self.respond(["08:31:10"])
        else:
            self.respond(text="Invalid Command\r\n")

    def _file(self, args: list[str]) -> None:
        if RANKS[self.level] < 1:
            self.respond(text="Invalid Access Level\r\n")
            return
        sub = args[0].upper()[:3] if args else ""
        if sub == "DIR":
            directory = args[1].upper() if len(args) > 1 else ""
            names = set()
            for path in self.files:
                parts = path.split()
                if not directory:
                    names.add(parts[0])
                elif len(parts) > 1 and parts[0] == directory:
                    names.add(parts[1])
            if not names:
                self.respond(text="File specified does not exist\r\n")
                return
            rows = [f"{name:<16} {'R' if '.' in name else 'D'}" for name in sorted(names)]
            self.respond(rows)
        elif sub == "SHO":
            name = " ".join(args[1:]).upper()
            if not name:
                self.respond(text="Command requires a filename\r\n")
            elif name not in self.files:
                self.respond(text="Invalid File Name\r\n")
            else:
                content = self.files[name].encode("latin-1")
                self.send(STX + content + ETX + self.prompt())
        else:
            self.respond(text="Invalid Parameter\r\n")

    def _sta_c(self) -> None:
        if RANKS[self.level] < 2:
            self.respond(text="Invalid Access Level\r\n")
            return
        if self.sta_c == "no_confirm":
            self.respond(["Relay Enabled"])
            return
        if self.sta_c == "ignore":
            return
        if self.sta_c == "drop":
            self.closed = True
            self.close()
            return
        if self.sta_c == "hardware":
            self.send(b"Accept new hardware configuration (Y/N) ? ")
        else:
            self.send(b"Reboot the relay and clear status\r\nAre you sure (Y/N) ? ")
        self._pending_confirm = "STA C"

    def _answer(self, command: str, answer: str) -> None:
        self.answers.append((command, answer))
        if answer != "Y":
            self.respond(text="Command aborted\r\n" if command == "STA" else "Canceled\r\n")
            return
        if command != "STA C" or self.sta_c == "hardware":
            self.respond(text="Hardware configuration accepted\r\n")
            return
        if self.sta_c == "prompt":
            self.respond(text="Command failed\r\n")
            return

        self.restarted = True
        if self.sta_c == "close":
            self.send(b"Rebooting the relay\r\n")
            self.closed = True
            self.close()
        elif self.sta_c == "silent":
            self.closed = True
            self.close()
        else:  # "hang": the relay stops responding, the connection stays open
            self.closed = True
        self.on_restart()


class SocketRelay:
    """
    Serves a :class:`FakeSELRelay` on a socket, in a thread. The output can be
    sent in small chunks with pauses, like a slow link.
    """

    def __init__(
        self,
        relay: FakeSELRelay,
        sock: socket.socket,
        chunk_size: int = 0,
        chunk_delay: float = 0.0,
        response_delay: float = 0.0,
        pause_at: tuple[bytes, float | threading.Event] | None = None,
    ) -> None:
        """
        Args:
            relay: The relay
            sock: Connected socket
            chunk_size: Send the output in chunks of this many bytes (0: all at once)
            chunk_delay: Seconds between chunks
            response_delay: Seconds before each response
            pause_at: Pause for this many seconds after sending these bytes
                (the first time), e.g. a slow link that stalls in the middle of a file.
                If the pause is a :class:`threading.Event`, the relay stalls until
                the event is set (at most 30 seconds), so a test doesn't depend
                on how fast the client reads.
        """
        self.relay = relay
        self.sock = sock
        self.chunk_size = chunk_size
        self.chunk_delay = chunk_delay
        self.response_delay = response_delay
        self.pause_at = pause_at
        self.received = b""
        relay.send = self._send
        relay.close = self._close
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _send(self, data: bytes) -> None:
        if self.response_delay:
            time.sleep(self.response_delay)
        try:
            if self.pause_at and self.pause_at[0] in data:
                marker, pause = self.pause_at
                self.pause_at = None
                end = data.index(marker) + len(marker)
                self._send_chunks(data[:end])
                if isinstance(pause, threading.Event):
                    pause.wait(timeout=30)
                else:
                    time.sleep(pause)
                data = data[end:]
            self._send_chunks(data)
        except OSError:
            pass

    def _send_chunks(self, data: bytes) -> None:
        if not self.chunk_size:
            self.sock.sendall(data)
            return
        for i in range(0, len(data), self.chunk_size):
            self.sock.sendall(data[i : i + self.chunk_size])
            if self.chunk_delay:
                time.sleep(self.chunk_delay)

    def _close(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()

    def _run(self) -> None:
        while not self.relay.closed:
            try:
                data = self.sock.recv(4096)
            except OSError:
                return
            if not data:
                return
            self.received += data
            self.relay.feed(data)

    def stop(self) -> None:
        self.relay.closed = True
        self._close()
        self._thread.join(timeout=2)


class TCPRelayServer:
    """
    Accepts Telnet connections on 127.0.0.1 (an ephemeral port), each served by a
    new :class:`FakeSELRelay` from ``factory``. The relays are kept in ``relays``.
    """

    def __init__(self, factory: Callable[[], FakeSELRelay], **socket_relay_kwargs) -> None:
        self.factory = factory
        self.kwargs = socket_relay_kwargs
        self.relays: list[FakeSELRelay] = []
        self.servers: list[SocketRelay] = []
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(5)
        self.port = self.listener.getsockname()[1]
        self._running = True
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()

    def _accept(self) -> None:
        while self._running:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            relay = self.factory()
            self.relays.append(relay)
            self.servers.append(SocketRelay(relay, conn, **self.kwargs))

    def close(self) -> None:
        self._running = False
        self.listener.close()
        for server in self.servers:
            server.stop()


class FakeSerialPort:
    """
    A pyserial-like port connected to a :class:`FakeSELRelay`. Output is released
    ``chunk_size`` bytes at a time, ``chunk_delay`` seconds apart.
    """

    def __init__(self, relay: FakeSELRelay, chunk_size: int = 0, chunk_delay: float = 0.0):
        self.relay = relay
        self.chunk_size = chunk_size
        self.chunk_delay = chunk_delay
        self.timeout = 1.0
        self.is_open = True
        self.written = b""
        self._rx: list[tuple[float, bytes]] = []
        self._lock = threading.Lock()
        relay.send = self._relay_send
        relay.close = lambda: None  # a serial line doesn't close

    def _relay_send(self, data: bytes) -> None:
        with self._lock:
            start = max([t for t, _ in self._rx] + [time.monotonic()])
            if not self.chunk_size:
                self._rx.append((start, data))
                return
            for n, i in enumerate(range(0, len(data), self.chunk_size)):
                self._rx.append((start + n * self.chunk_delay, data[i : i + self.chunk_size]))

    def _ready(self) -> bytes:
        now = time.monotonic()
        with self._lock:
            ready = b"".join(chunk for t, chunk in self._rx if t <= now)
            self._rx = [(t, chunk) for t, chunk in self._rx if t > now]
        return ready

    def _peek(self) -> int:
        now = time.monotonic()
        with self._lock:
            return sum(len(chunk) for t, chunk in self._rx if t <= now)

    # pyserial API used by SELSerial and serial_reader()
    @property
    def in_waiting(self) -> int:
        return self._peek() + len(getattr(self, "_unread", b""))

    def read(self, size: int = 1) -> bytes:
        data = getattr(self, "_unread", b"") + self._ready()
        self._unread = data[size:]
        return data[:size]

    def read_all(self) -> bytes:
        return self.read(self.in_waiting)

    def write(self, data: bytes) -> int:
        self.written += data
        self.relay.feed(data)
        return len(data)

    def reset_input_buffer(self) -> None:
        self._unread = b""
        with self._lock:
            self._rx = []

    def reset_output_buffer(self) -> None:
        pass

    def isOpen(self) -> bool:  # pyserial name
        return self.is_open

    def close(self) -> None:
        self.is_open = False
