"""
A scripted SEL RTAC engineering access port, for testing PEAT's RTAC tunnels
(``sel_tunnel.py``, ``sel_gateway.py``) without hardware.

It's modeled on the sessions in public SEL documents: the "SEL-3530 RTAC Hands-On
Session" (HD2014-34, Engineering Access Exercise, Figures 24 and 25) and the white
paper LWP0018-01 (Section 5, Figure 8). All data is synthetic.

- SEL server (``kind="sel_server"``): an optional RTAC login (``login:``,
  ``password:``), the prompt ``*``, ``ACC`` (level 1, prompt ``*>``, optionally
  with a password), ``WHO`` (a table of ports, devices, and protocols), ``PORT n``
  ("Establishing connection..."), then a transparent connection to a
  :class:`~tests.modules.sel.fake_sel_relay.FakeSELRelay`, until the termination
  string (Ctrl+D) arrives after the line was idle for ``pre_term_s``. A termination
  string that arrives earlier is passed to the relay (counted in
  ``early_terminations``). ``QUI`` returns to level 0.
- Access point (``kind="access_point"``): an optional RTAC login, then the relay.

:class:`RTACServer` serves it on 127.0.0.1 with raw TCP (which PEAT's Telnet client
also works with), TLS, or SSH (paramiko). :class:`ChunkingProxy` forwards a TCP
connection and sends the server's data in small chunks with delays.
"""

from __future__ import annotations

import datetime
import socket
import ssl
import threading
import time
from collections.abc import Callable
from pathlib import Path

import paramiko

from .fake_sel_relay import FakeSELRelay
from .sel_command_transcripts import FID_351S

STX = b"\x02"
ETX = b"\x03"
CAN = b"\x18"


class GatewayRelay(FakeSELRelay):
    """A :class:`FakeSELRelay` whose ``ID`` also has ``SERIALNO`` and ``iedName``."""

    def __init__(self, serial: str = "", ied_name: str = "", **kwargs) -> None:
        super().__init__(**kwargs)
        self.serial = serial
        self.ied_name = ied_name

    def _handle(self, text: str) -> None:
        if self._pending_level is None and self._pending_confirm is None:
            if text.strip().upper()[:2] == "ID":
                from peat.modules.sel.sel_cascii import format_record

                self.send(text.encode("latin-1") + b"\r\n")
                lines = [
                    format_record([f"FID={self.fid}"]),
                    format_record(["CID=59A0"]),
                    format_record([f"DEVID={self.fid.split('-R')[0]}"]),
                ]
                if self.serial:
                    lines.append(format_record([f"SERIALNO={self.serial}"]))
                if self.ied_name:
                    lines.append(format_record([f"iedName={self.ied_name}"]))
                self.respond(lines)
                return
        super()._handle(text)


class FakeRTAC:
    """
    The RTAC's side of one engineering access connection. ``send`` and ``close``
    are set by the server.
    """

    def __init__(
        self,
        kind: str = "sel_server",
        relays: dict[int, FakeSELRelay] | None = None,
        names: dict[int, str] | None = None,
        login: tuple[str, str] | None = None,
        acc_password: str | None = None,
        greet: bool = True,
        framed: bool = False,
        termination: bytes = b"\x04",
        pre_term_s: float = 0.2,
        port_error: str = "",
        who: list[str] | None = None,
    ) -> None:
        """
        Args:
            kind: ``sel_server`` or ``access_point``
            relays: The relays, keyed by their port (``PORT n``). An access point
                uses the relay of port 1.
            names: Names of the relays in ``WHO``
            login: RTAC user name and password, if the RTAC asks for a login
            acc_password: Password of the SEL server's ``ACC``, if it asks for one
            greet: The SEL server shows its prompt when the client connects
            framed: Frame the SEL server's prompts with STX and ETX
            termination: The termination string
            pre_term_s: Seconds the line must be idle before the termination string
            port_error: Answer ``PORT n`` with this error after "Establishing connection..."
            who: Rows of ``WHO`` (default: the relays, and the SEL server itself)
        """
        self.kind = kind
        self.relays = relays if relays is not None else {1: FakeSELRelay(fid=FID_351S)}
        self.names = names or {n: f"Feeder_{n}" for n in self.relays}
        self.login = login
        self.acc_password = acc_password
        self.greet = greet
        self.framed = framed
        self.termination = termination
        self.pre_term_s = pre_term_s
        self.port_error = port_error
        self.who = who

        self.send: Callable[[bytes], None] = lambda _data: None
        self.close: Callable[[], None] = lambda: None

        self.state = "login_user" if login else ("rtac" if kind == "sel_server" else "device")
        self.level = "0"
        self.current: FakeSELRelay | None = None
        self.closed = False

        #: Lines received by the RTAC itself (not the relay), passwords included
        self.lines: list[bytes] = []
        #: Commands the SEL server received (uppercase)
        self.commands: list[str] = []
        #: All bytes received
        self.received = b""
        self.login_failures = 0
        self.login_attempts = 0
        self.acc_attempts = 0
        self.terminations = 0
        self.early_terminations = 0
        self.cancels = 0
        #: The client closed the connection while a transparent connection was open
        self.closed_while_transparent = False
        self._buffer = b""
        self._user = ""
        self._last_rx = time.monotonic()

        for port, relay in self.relays.items():
            relay.send = self._relay_sender(relay)
            relay.close = self._relay_closer()
            relay.port = port

    # -- output -------------------------------------------------------------

    def prompt(self) -> bytes:
        text = b"*>" if self.level == "1" else b"*"
        if self.framed:
            return STX + b"\r\n" + text + ETX
        return b"\r\n" + text

    def _relay_sender(self, relay: FakeSELRelay) -> Callable[[bytes], None]:
        def send(data: bytes) -> None:
            if self.current is relay:
                self.send(data)

        return send

    def _relay_closer(self) -> Callable[[], None]:
        def close() -> None:
            # A relay behind an access point closes the connection (e.g. EXIT on
            # its Telnet port), a serial relay behind the SEL server doesn't
            if self.kind == "access_point":
                self.closed = True
                self.close()

        return close

    # -- connection ---------------------------------------------------------

    def connected(self) -> None:
        if self.login:
            self.send(b"\r\nlogin: ")
        elif self.kind == "sel_server" and self.greet:
            self.send(self.prompt())
        elif self.kind == "access_point":
            self._open_device()

    def disconnected(self) -> None:
        if self.state == "transparent":
            self.closed_while_transparent = True
        self.closed = True

    def _open_device(self) -> None:
        self.state = "device"
        self.current = self.relays[min(self.relays)]

    def feed(self, data: bytes) -> None:
        if self.closed:
            return
        self.received += data
        now = time.monotonic()
        idle = now - self._last_rx
        self._last_rx = now

        if self.state == "transparent" and self.termination in data:
            before, _, after = data.partition(self.termination)
            if before or idle < self.pre_term_s:
                # Not after the idle time: it's data for the relay
                self.early_terminations += 1
                self.current.feed(data)
                return
            self.terminations += 1
            self.state = "rtac"
            self.current = None
            self.send(b"\r\n" + self.prompt())
            if after:
                self._feed_lines(after)
            return

        if self.state in ("transparent", "device"):
            self.current.feed(data)
            return

        self._feed_lines(data)

    def _feed_lines(self, data: bytes) -> None:
        self._buffer += data
        while not self.closed and self.state not in ("transparent", "device"):
            positions = [
                (i, kind)
                for kind, i in (
                    ("can", self._buffer.find(CAN)),
                    ("cr", self._buffer.find(b"\r")),
                    ("lf", self._buffer.find(b"\n")),
                )
                if i >= 0
            ]
            if not positions:
                return
            index, kind = min(positions)
            if kind == "can":
                self._buffer = self._buffer[index + 1 :]
                self.cancels += 1
                if self.state == "acc_password":
                    self.state = "rtac"
                    self.send(b"\r\n" + self.prompt())
                continue
            line = self._buffer[:index]
            rest = self._buffer[index + 1 :]
            if kind == "cr" and rest.startswith(b"\n"):
                rest = rest[1:]
            self._buffer = rest
            self.lines.append(line)
            self._line(line.decode("latin-1"))

        if self.state in ("transparent", "device") and self._buffer:
            rest, self._buffer = self._buffer, b""
            self.current.feed(rest)

    def _line(self, text: str) -> None:
        if self.state == "login_user":
            self._user = text.strip()
            self.login_attempts += 1
            self.send(text.encode("latin-1") + b"\r\npassword: ")
            self.state = "login_password"
            return
        if self.state == "login_password":
            self.send(b"\r\n")
            if (self._user, text) == self.login:
                if self.kind == "sel_server":
                    self.state = "rtac"
                    self.send(self.prompt())
                else:
                    self._open_device()
            else:
                self.login_failures += 1
                self.state = "login_user"
                self.send(b"Login incorrect\r\nlogin: ")
            return
        if self.state == "acc_password":
            self.acc_attempts += 1
            self.send(b"*" * len(text) + b"\r\n")
            if text == self.acc_password:
                self.state = "rtac"
                self.level = "1"
                self.send(b"Level 1" + self.prompt())
            else:
                self.send(b"Password: ? ")
            return

        # The SEL server echoes the command
        self.send(text.encode("latin-1") + b"\r\n")
        words = text.strip().upper().split()
        command = " ".join(words)
        if command:
            self.commands.append(command)
        cmd = words[0][:3] if words else ""

        if cmd == "":
            self.send(self.prompt())
        elif cmd == "ACC":
            if self.acc_password:
                self.state = "acc_password"
                self.send(b"Password: ? ")
            else:
                self.level = "1"
                self.send(
                    b"Date: 06/15/2026 (mm/dd/yyyy) Time: 18:59:57\r\n\r\nLevel 1" + self.prompt()
                )
        elif cmd == "QUI":
            self.level = "0"
            self.send(self.prompt())
        elif self.level != "1":
            self.send(b"Invalid Access Level" + self.prompt())
        elif cmd == "WHO":
            rows = self.who
            if rows is None:
                rows = [f"{n:<6} {self.names[n]:<22} Client - Serial" for n in sorted(self.relays)]
                rows.append(f"{254:<6} {'Remote_Access_Server':<22} Server - Ethernet")
            table = "Port#  Device                 Protocol\r\n" + "\r\n".join(rows)
            self.send(table.encode("latin-1") + b"\r\n" + self.prompt())
        elif cmd == "POR" and len(words) == 2 and words[1].isdigit():
            port = int(words[1])
            if port not in self.relays:
                self.send(b"Invalid port number" + self.prompt())
                return
            self.send(b"Establishing connection...\r\n")
            if self.port_error:
                self.send(self.port_error.encode() + b"\r\n" + self.prompt())
                return
            self.state = "transparent"
            self.current = self.relays[port]
        else:
            self.send(b"Invalid Command" + self.prompt())


def make_tls_files(directory: Path) -> tuple[Path, Path]:
    """A self-signed certificate and its key (like a RTAC's default certificate)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SEL-3530 RTAC")])
    now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    cert_file = directory / "rtac.crt"
    key_file = directory / "rtac.key"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert_file, key_file


class _SSHInterface(paramiko.ServerInterface):
    def __init__(self, creds: tuple[str, str]) -> None:
        self.creds = creds
        self.shell = threading.Event()
        self.auth_attempts = 0

    def check_channel_request(self, kind, chanid):  # noqa: ARG002
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):  # noqa: ARG002
        return "password"

    def check_auth_password(self, username, password):
        self.auth_attempts += 1
        if (username, password) == self.creds:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_pty_request(self, *args):  # noqa: ARG002
        return True

    def check_channel_shell_request(self, channel):  # noqa: ARG002
        self.shell.set()
        return True


class RTACServer:
    """
    Accepts connections on 127.0.0.1 (an ephemeral port), each served by a new
    :class:`FakeRTAC` from ``factory``, in a thread. The engines are in ``rtacs``.
    """

    def __init__(
        self,
        factory: Callable[[], FakeRTAC],
        transport: str = "raw",
        tls_files: tuple[Path, Path] | None = None,
        ssh_key: paramiko.PKey | None = None,
        ssh_creds: tuple[str, str] = ("engineer", "rtac-pass"),
    ) -> None:
        self.factory = factory
        self.transport = transport
        self.ssh_key = ssh_key
        self.ssh_creds = ssh_creds
        self.rtacs: list[FakeRTAC] = []
        self.ssh_interfaces: list[_SSHInterface] = []
        self.connections = 0
        #: Most connections that were open at the same time
        self.max_open = 0
        self._open = 0
        self._lock = threading.Condition()
        self._closers: list[Callable[[], None]] = []
        self._tls = None
        if transport == "tls":
            self._tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self._tls.load_cert_chain(*tls_files)

        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(5)
        self.port = self.listener.getsockname()[1]
        self._running = True
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while self._running:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            self.connections += 1
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        with self._lock:
            # The thread of a connection the client just closed may not have seen
            # the end of it yet (e.g. on a busy machine). A connection the client
            # keeps open is still counted, since it doesn't end in that time.
            self._lock.wait_for(lambda: self._open == 0, timeout=1.0)
            self._open += 1
            self.max_open = max(self.max_open, self._open)
        try:
            if self.transport == "ssh":
                try:
                    self._serve_ssh(conn)
                except Exception:  # e.g. EOFError when the client gives up after the login
                    conn.close()
            else:
                if self._tls is not None:
                    try:
                        conn = self._tls.wrap_socket(conn, server_side=True)
                    except (OSError, ssl.SSLError):
                        conn.close()
                        return
                self._serve_stream(conn.recv, conn.sendall, conn)
        finally:
            with self._lock:
                self._open -= 1
                self._lock.notify_all()

    def _serve_stream(self, recv, sendall, closable) -> None:
        rtac = self.factory()
        self.rtacs.append(rtac)
        lock = threading.Lock()

        def send(data: bytes) -> None:
            with lock:
                try:
                    sendall(data)
                except OSError:
                    pass

        def close() -> None:
            try:
                if isinstance(closable, socket.socket):
                    closable.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            closable.close()

        rtac.send = send
        rtac.close = close
        self._closers.append(close)
        rtac.connected()
        while not rtac.closed:
            try:
                data = recv(4096)
            except (OSError, EOFError):
                break
            if not data:
                break
            rtac.feed(data)
        rtac.disconnected()
        try:
            close()
        except OSError:
            pass

    def _serve_ssh(self, conn: socket.socket) -> None:
        transport = paramiko.Transport(conn)
        transport.add_server_key(self.ssh_key)
        interface = _SSHInterface(self.ssh_creds)
        self.ssh_interfaces.append(interface)
        try:
            transport.start_server(server=interface)
        except (paramiko.SSHException, EOFError):
            transport.close()
            return
        channel = transport.accept(5)
        if channel is None or not interface.shell.wait(5):
            transport.close()
            return
        self._closers.append(transport.close)

        class _Closer:
            def close(self) -> None:
                channel.close()
                transport.close()

        self._serve_stream(channel.recv, channel.sendall, _Closer())

    def close(self) -> None:
        self._running = False
        self.listener.close()
        for closer in self._closers:
            try:
                closer()
            except Exception:
                pass


class ChunkingProxy:
    """
    Forwards connections on 127.0.0.1 to ``port``. The server's data is sent to
    the client in chunks of ``chunk_size`` bytes, ``delay`` seconds apart (like a
    slow serial link behind the RTAC).
    """

    def __init__(self, port: int, chunk_size: int = 2, delay: float = 0.001) -> None:
        self.target = port
        self.chunk_size = chunk_size
        self.delay = delay
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(5)
        self.port = self.listener.getsockname()[1]
        self.chunks = 0
        self._sockets: list[socket.socket] = []
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while True:
            try:
                client, _ = self.listener.accept()
            except OSError:
                return
            upstream = socket.create_connection(("127.0.0.1", self.target))
            self._sockets += [client, upstream]
            threading.Thread(target=self._pump, args=(client, upstream, 0), daemon=True).start()
            threading.Thread(
                target=self._pump, args=(upstream, client, self.chunk_size), daemon=True
            ).start()

    def _pump(self, src: socket.socket, dst: socket.socket, chunk_size: int) -> None:
        while True:
            try:
                data = src.recv(4096)
            except OSError:
                break
            if not data:
                break
            try:
                if not chunk_size:
                    dst.sendall(data)
                    continue
                for i in range(0, len(data), chunk_size):
                    dst.sendall(data[i : i + chunk_size])
                    self.chunks += 1
                    time.sleep(self.delay)
            except OSError:
                break
        for sock in (src, dst):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def close(self) -> None:
        self.listener.close()
        for sock in self._sockets:
            try:
                sock.close()
            except OSError:
                pass
