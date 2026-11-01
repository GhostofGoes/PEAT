"""
A scripted SEL relay that answers binary SEL Fast requests, for testing
:mod:`peat.modules.sel.sel_fast` without hardware.

It extends :class:`~tests.modules.sel.fake_sel_relay.FakeSELRelay` (SEL ASCII),
and answers the requests that PEAT sends, with frames built by the builders in
:mod:`peat.modules.sel.sel_fast`. The formats are from public documentation:

- Relay definition, Fast Meter, and Fast Operate configuration blocks:
  SEL-351A IM 20080213, Appendix D (Tables D.3 to D.8).
- Fast SER (functions 01, 02, 18, 98): SEL-351A IM 20080213, Appendix J.
- The other Fast Message functions (00, 10, 30, 31, 33): the layouts that the
  Wireshark dissector ``packet-selfm.c`` decodes. The LOCAL region items are
  the ones the SEL-487B RM 20090519 (Table 3.23) lists for the LOCAL region.

All of the values (FIDs, serial numbers, names) are synthetic.

:class:`TelnetRelayServer` serves relays on 127.0.0.1 with Telnet option
negotiation (the relay offers ``WILL ECHO``, ``WILL SGA``, ``WILL BINARY``,
``DO BINARY``, as relays do) and IAC doubling.
"""

from __future__ import annotations

import socket
import struct
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from peat.modules.sel import sel_fast as fast
from peat.modules.sel.sel_cascii import format_record

from .fake_sel_relay import RANKS, FakeSELRelay

IAC = 0xFF
WILL, WONT, DO, DONT = 0xFB, 0xFC, 0xFD, 0xFE
BINARY, ECHO, SGA = 0x00, 0x01, 0x03

#: What relays send when a Telnet session starts
RELAY_NEGOTIATION = bytes([IAC, WILL, ECHO, IAC, WILL, SGA, IAC, WILL, BINARY, IAC, DO, BINARY])

FID_421 = "SEL-421-5-R399-V0-Z016013-D20240102"
BFID_421 = "SLBT-4XX-R299-V0-Z001002-D20240101"


# ---------------------------------------------------------------------------
# Building frames
# ---------------------------------------------------------------------------


def relay_definition(
    meter: list[tuple[int, int]],
    flags: list[tuple[int, bytes]],
    protocols: list[int],
    pad: bool = True,
) -> bytes:
    """A relay definition block (SEL-351A IM 20080213 Table D.3)."""
    body = bytes([len(protocols), len(meter), len(flags)])
    for config, data in meter:
        body += struct.pack(">HH", config, data)
    for bit, command in flags:
        body += struct.pack(">H", bit) + command.ljust(6, b"\x00")
    for word in protocols:
        body += struct.pack(">H", word)
    if pad:
        body += b"\x00"
    return fast.build_meter_frame(fast.RELAY_DEFINITION, body)


def fm_config(
    command: int,
    channels: list[tuple[str, int, int, int]],
    samples: int = 1,
    digital_banks: int = 0,
    status_bytes: int = 1,
    scale_factors: list[float] | None = None,
    calc_blocks: int = 0,
) -> bytes:
    """
    A Fast Meter configuration block (SEL-351A IM 20080213 Tables D.4 and D.6).
    ``channels`` are (name, type, scale factor type, scale factor offset). With
    ``scale_factors``, they're in this message (``sf_location`` 1), after the
    channels, and the offsets are calculated.
    """
    size = {0: 2, 1: 4, 2: 8}
    analog_offset = 3 + status_bytes
    if scale_factors is None:
        # Scale factors (float32) are in the data message, before the analogs
        analog_offset += 4 * len({c[3] for c in channels if c[2] != 0xFF})
    analogs = samples * sum(size[c[1]] for c in channels)
    timestamp_offset = analog_offset + analogs
    digital_offset = timestamp_offset + 8 if digital_banks else 0xFFFF
    body = bytes(
        [
            status_bytes,
            1 if scale_factors is not None else 0,
            len(scale_factors or []) or len({c[3] for c in channels if c[2] != 0xFF}),
            len(channels),
            samples,
            digital_banks,
            calc_blocks,
        ]
    )
    body += struct.pack(">HHH", analog_offset, timestamp_offset, digital_offset)
    sf_start = 3 + len(body) + 10 * len(channels) + 14 * calc_blocks
    for number, (name, value_type, sf_type, sf_offset) in enumerate(channels):
        if scale_factors is not None and sf_type != 0xFF:
            sf_offset = sf_start + 4 * number
        body += name.encode().ljust(6, b"\x00") + bytes([value_type, sf_type])
        body += struct.pack(">H", sf_offset)
    for _ in range(calc_blocks):
        body += bytes([0, 0]) + b"\xff" * 6 + bytes([0, 1, 2, 3, 4, 5])
    for value in scale_factors or []:
        body += struct.pack(">f", value)
    body += b"\x00"
    return fast.build_meter_frame(command, body)


def fm_data(
    command: int,
    status: bytes,
    scale_factors: list[float],
    values: list[float | int],
    types: list[int],
    timestamp: bytes = b"",
    digital: bytes = b"",
) -> bytes:
    """A Fast Meter data message: status, scale factors, analogs, timestamp, digital banks."""
    body = bytes(status)
    for value in scale_factors:
        body += struct.pack(">f", value)
    fmt = {0: ">h", 1: ">f", 2: ">d"}
    for value, value_type in zip(values, types, strict=True):
        body += struct.pack(fmt[value_type], value)
    body += timestamp + digital + b"\x00"
    return fast.build_meter_frame(command, body)


def fm_timestamp(month: int, day: int, year: int, hour: int, minute: int, sec: int, ms: int):
    """Fast Meter timestamp (8 bytes)."""
    return bytes([month, day, year % 100, hour, minute, sec]) + struct.pack(">H", ms)


def fo_config(breakers: int, remote_bits: int, pulse: bool = True) -> bytes:
    """
    A Fast Operate configuration block (SEL-351A IM 20080213 Table D.8), with
    the typical codes: breaker k open 0x30+k and close 0x10+k, remote bit n
    clear n-1, set 0x20+n-1, pulse 0x40+n-1.
    """
    body = bytes([breakers]) + struct.pack(">H", remote_bits) + bytes([int(pulse), 0])
    for k in range(1, breakers + 1):
        body += bytes([0x30 + k, 0x10 + k])
    for n in range(remote_bits):
        body += bytes([n, 0x20 + n] + ([0x40 + n] if pulse else []))
    return fast.build_meter_frame(fast.FAST_OPERATE_CONFIG, body + b"\x00")


@dataclass
class Item:
    """A data item of a region, and its value(s)."""

    name: str
    type: int
    quantity: int
    value: object = None

    def encode(self) -> bytes:
        size = fast.ITEM_TYPES[self.type][1]
        if self.type == 0x11:
            return str(self.value or "").encode("latin-1").ljust(self.quantity, b"\x00")
        if self.type == 0x12:
            return str(self.value or "").encode("utf-16-be").ljust(2 * self.quantity, b"\x00")
        values = self.value if isinstance(self.value, list) else [self.value or 0]
        values = (values + [0] * self.quantity)[: self.quantity]
        fmt = {0x41: "f"}.get(self.type) or fast._ITEM_FORMATS[self.type]
        data = struct.pack(f">{self.quantity}{fmt}", *values)
        assert len(data) == size * self.quantity
        return data


@dataclass
class FakeRegion:
    name: str
    base: int
    items: list[Item]
    flags: int = 0
    labels: dict[int, list[str]] = field(default_factory=dict)

    @property
    def data(self) -> bytes:
        data = b"".join(i.encode() for i in self.items)
        return data + b"\x00" * (len(data) % 2)

    @property
    def words(self) -> int:
        return len(self.data) // 2


def local_region(
    fid: str = FID_421,
    serial: str = "9999000001",
    part: str = "0421XXXXXXXXXXXXXX",
    relay_id: str = "TEST RELAY 1",
    station_id: str = "TEST STATION",
    group: int = 2,
    status: int = 0,
    prefix_keys: bool = True,
) -> FakeRegion:
    """A LOCAL region (items as in SEL-487B RM 20090519 Table 3.23, synthetic values)."""
    return FakeRegion(
        "LOCAL",
        0x0000,
        [
            Item("FID", 0x11, 48, f"FID={fid}" if prefix_keys else fid),
            Item("BFID", 0x11, 48, f"BFID={BFID_421}" if prefix_keys else BFID_421),
            Item("SER_NUM", 0x11, 16, serial),
            Item("PART_NUM", 0x11, 24, part),
            Item("CONFIG", 0x11, 8, "11202200"),
            Item("SPECIAL", 0x11, 8, "000000"),
            Item("DEVICE_ID", 0x11, 40, relay_id),
            Item("NODE_ID", 0x11, 40, station_id),
            Item("GROUP", 0x32, 1, group),
            Item("STATUS", 0x32, 1, status),
        ],
    )


def history_region(events: list[dict], slots: int = 4, base: int = 0x4000) -> FakeRegion:
    """A HISTORY region: one array per column, ``slots`` events (synthetic layout)."""
    rows = (events + [{}] * slots)[:slots]

    def col(key, default=0):
        return [row.get(key, default) for row in rows]

    return FakeRegion(
        "HISTORY",
        base,
        [
            Item("_YEAR", 0x32, 1, 2024),
            Item("REF_NUM", 0x31, slots, col("ref")),
            Item("MONTH", 0x32, slots, col("month")),
            Item("DAY", 0x32, slots, col("day")),
            Item("YEAR", 0x32, slots, col("year")),
            Item("HOUR", 0x31, slots, col("hour")),
            Item("MIN", 0x31, slots, col("minute")),
            Item("SEC", 0x31, slots, col("second")),
            Item("MSEC", 0x31, slots, col("ms")),
            Item("EVENT", 0x11, 6 * slots, "".join(r.get("event", "").ljust(6) for r in rows)),
            Item("GROUP", 0x31, slots, col("group")),
            Item("FREQ", 0x41, slots, col("freq", 0.0)),
            Item("CURR", 0x31, slots, col("current")),
            Item(
                "TARGETS", 0x11, 10 * slots, "".join(r.get("targets", "").ljust(10) for r in rows)
            ),
        ],
    )


def device_description_bodies(
    fid: str, rid: str, regions: list[FakeRegion], per_frame: int = 7, reserved: bool = True
) -> list[bytes]:
    """Bodies of the device description frames (up to 7 regions per frame)."""
    head = fid.encode().ljust(50, b"\x00") + rid.encode().ljust(40, b"\x00")
    head += struct.pack(">HH", len(regions), 0)
    chunks = [regions[i : i + per_frame] for i in range(0, len(regions), per_frame)] or [[]]
    bodies = []
    for number, chunk in enumerate(chunks):
        body = head
        for region in chunk:
            body += region.name.encode().ljust(10, b"\x00")
            body += struct.pack(">IHH", region.base, region.words, region.flags)
        if reserved and number == len(chunks) - 1:
            body += b"\x00" * 8
        bodies.append(body)
    return bodies


def data_format_bodies(region: FakeRegion, per_frame: int = 16) -> list[bytes]:
    """Bodies of the data format frames of a region (up to 16 items per frame)."""
    head = struct.pack(">IH", region.base, len(region.items))
    items = region.items
    chunks = [items[i : i + per_frame] for i in range(0, len(items), per_frame)] or [[]]
    return [
        head
        + b"".join(
            i.name.encode().ljust(10, b"\x00") + struct.pack(">HH", i.quantity, i.type)
            for i in chunk
        )
        for chunk in chunks
    ]


def fast_ser_body(
    year: int, day_of_year: int, millis: int, records: list[tuple[int, int, int]]
) -> bytes:
    """Body of a Fast SER message: (index, microseconds, state) records."""
    body = b"\x00" * 4 + struct.pack(">HHI", day_of_year, year, millis)
    states = 0
    for number, (index, micros, state) in enumerate(records):
        body += bytes([index]) + micros.to_bytes(3, "big")
        states |= (state & 1) << number
    return body + fast.FAST_SER_END + struct.pack(">I", states)


def _seq(number: int, count: int) -> int:
    seq = number
    if number == 0:
        seq |= fast.SEQ_FIR
    if number == count - 1:
        seq |= fast.SEQ_FIN
    return seq


# ---------------------------------------------------------------------------
# The relay
# ---------------------------------------------------------------------------


class FastRelay(FakeSELRelay):
    """
    :class:`FakeSELRelay` that also answers binary SEL Fast requests.

    Binary requests are taken out of the input (a two-byte request, or a Fast
    Message with its length), and the rest is SEL ASCII.
    """

    def __init__(
        self,
        definition: bytes | None = None,
        meter: dict[int, bytes] | None = None,
        fast_operate: bytes | None = None,
        message_config: tuple[list[int], list[int]] | None = None,
        regions: list[FakeRegion] | None = None,
        device_fid: str = f"FID={FID_421}",
        device_rid: str = "SEL-421",
        fast_ser: list[bytes] | None = None,
        fast_ser_status: list[int] | None = None,
        fast_ser_enable_code: int = 0,
        resend_unacked: bool = False,
        binary_level: str = "0",
        bna: list[str] | None = None,
        dna: list[list[str]] | None = None,
        sns: list[str] | None = None,
        nak: dict[int, int] | None = None,
        wrong_resp_num: bool = False,
        **kwargs,
    ) -> None:
        """
        Args:
            definition: Relay definition block (None: no answer to A5C0)
            meter: Responses to the Fast Meter requests, by request
            fast_operate: Fast Operate configuration block (None: FASTOP=N, no answer)
            message_config: Function codes accepted and sent (None: no Fast Message)
            regions: Database regions
            fast_ser: Bodies of the Fast SER messages sent after the enable
            fast_ser_status: Status byte of each Fast SER message (default 01)
            fast_ser_enable_code: Response code of the enable acknowledge
            resend_unacked: Send each Fast SER message twice (like a late acknowledge)
            binary_level: Access level needed for binary requests
            bna, dna, sns: Names for the BNA, DNA, and SNS commands
            nak: Response code to answer instead, by function code
            wrong_resp_num: Answer with a different response number
        """
        super().__init__(**kwargs)
        self.definition = definition
        self.meter = meter or {}
        self.fast_operate = fast_operate
        self.message_config = message_config
        self.regions = regions or []
        self.device_fid = device_fid
        self.device_rid = device_rid
        self.fast_ser = list(fast_ser or [])
        self.fast_ser_status = list(fast_ser_status or [])
        self.fast_ser_enable_code = fast_ser_enable_code
        self.resend_unacked = resend_unacked
        self.binary_level = binary_level
        self.bna = bna
        self.dna = dna
        self.sns = sns
        self.nak = nak or {}
        self.wrong_resp_num = wrong_resp_num

        #: Every binary request received, in order
        self.binary_requests: list[bytes] = []
        #: Fast SER: enabled, the messages sent, and the acknowledges received
        self.fast_ser_enabled = False
        self.fast_ser_sent: list[bytes] = []
        self.fast_ser_acks: list[int] = []
        self._ser_resp_num = 0
        self._ser_index = 0
        self._binary_buffer = b""

    # -- input -----------------------------------------------------------

    def feed(self, data: bytes) -> None:
        if self.closed:
            return
        buf = self._binary_buffer + data
        self._binary_buffer = b""
        while buf:
            start = buf.find(b"\xa5")
            if start < 0:
                super().feed(buf)
                return
            if start:
                super().feed(buf[:start])
                buf = buf[start:]
            if len(buf) < 2:
                break
            if buf[1] == 0x46:
                if len(buf) < 3 or len(buf) < buf[2]:
                    break
                frame, buf = buf[: buf[2]], buf[buf[2] :]
                self.binary_requests.append(frame)
                self._message(frame)
            else:
                request, buf = buf[:2], buf[2:]
                self.binary_requests.append(request)
                self._meter(request)
        self._binary_buffer = buf

    def _binary_allowed(self) -> bool:
        return RANKS[self.level] >= RANKS[self.binary_level]

    def _meter(self, request: bytes) -> None:
        if not self._binary_allowed():
            return
        mid = int.from_bytes(request, "big")
        if mid == fast.RELAY_DEFINITION:
            response = self.definition
        elif mid == fast.FAST_OPERATE_CONFIG:
            response = self.fast_operate
        else:
            response = self.meter.get(mid)
        if response:
            self.send(response)

    def _reply(self, request: fast.FastMessage, body: bytes, seq: int = fast.SEQ_SINGLE):
        resp_num = (request.response_number + 1) % 4 if self.wrong_resp_num else None
        self.send(
            fast.build_fast_message(
                request.function_code | fast.RESPONSE,
                body,
                seq=seq,
                resp_num=request.response_number if resp_num is None else resp_num,
                status=0,
            )
        )

    def _ack(self, function_code: int, code: int, resp_num: int) -> None:
        self.send(fast.build_ack(function_code, code, resp_num))

    def _frames(self, request: fast.FastMessage, bodies: list[bytes]) -> None:
        number = request.frame_number
        if number < len(bodies):
            self._reply(request, bodies[number], seq=_seq(number, len(bodies)))

    def _message(self, frame: bytes) -> None:
        try:
            request = fast.parse_fast_message(frame)
        except fast.FastFrameError:
            return  # bad CRC: ignored, like a relay
        if not self._binary_allowed():
            return
        fc = request.function_code
        if fc in self.nak:
            self.send(
                fast._fast_message(
                    fc | fast.RESPONSE, b"", self.nak[fc], request.response_number, 0
                )
            )
            return

        if fc == fast.FC_FAST_SER_ACK:
            self.fast_ser_acks.append(request.response_number)
            if request.response_number == self._ser_resp_num:
                self._ser_resp_num = (self._ser_resp_num + 1) % 4
                self._ser_index += 1
                self._send_fast_ser()
            return
        if self.message_config is None:
            return
        rx, tx = self.message_config
        if fc not in rx:
            self._ack_unknown(request)
            return

        if fc == fast.FC_CONFIG:
            body = bytes([0, 1, 7, 1, 2]) + b"\x00" * 6
            body += bytes([len(rx)]) + b"".join(bytes([c, 0]) for c in rx)
            body += bytes([len(tx)]) + b"".join(bytes([c, 0]) for c in tx)
            self._reply(request, body)
        elif fc == fast.FC_DEVICE_DESCRIPTION:
            self._frames(
                request, device_description_bodies(self.device_fid, self.device_rid, self.regions)
            )
        elif fc == fast.FC_DATA_FORMAT:
            base = struct.unpack(">I", request.body)[0]
            region = self._region(base)
            if region is None:
                self._ack_code(request, 3)
            else:
                self._frames(request, data_format_bodies(region))
        elif fc == fast.FC_READ:
            base, words = struct.unpack(">IH", request.body)
            region = self._region(base)
            if region is None:
                self._ack_code(request, 3)
                return
            data = region.data[: 2 * words]
            chunks = [data[i : i + 234] for i in range(0, len(data), 234)] or [b""]
            bodies = [struct.pack(">IH", base, len(c) // 2) + c for c in chunks]
            self._frames(request, bodies)
        elif fc == fast.FC_BIT_LABEL:
            address = struct.unpack(">I", request.body)[0]
            for region in self.regions:
                if address in region.labels:
                    labels = region.labels[address]
                    self._reply(request, b"".join(x.encode() + b"\x00" for x in labels))
                    return
            self._ack_code(request, 3)
        # The state is changed before the reply is sent: the test thread can
        # check it as soon as PEAT has the reply
        elif fc == fast.FC_ENABLE_UNSOLICITED:
            self.fast_ser_enabled = True
            self._ack(fc, self.fast_ser_enable_code, request.response_number)
            self._send_fast_ser()
        elif fc == fast.FC_DISABLE_UNSOLICITED:
            self.fast_ser_enabled = False
            self._ack(fc, 0, request.response_number)

    def _ack_unknown(self, request: fast.FastMessage) -> None:
        self._ack_code(request, 1)

    def _ack_code(self, request: fast.FastMessage, code: int) -> None:
        self.send(
            fast._fast_message(
                request.function_code | fast.RESPONSE, b"", code, request.response_number, 0
            )
        )

    def _region(self, base: int) -> FakeRegion | None:
        return next((r for r in self.regions if r.base == base), None)

    def _send_fast_ser(self) -> None:
        if not self.fast_ser_enabled or self._ser_index >= len(self.fast_ser):
            return
        status = (
            self.fast_ser_status[self._ser_index]
            if self._ser_index < len(self.fast_ser_status)
            else 0x01
        )
        frame = fast.build_fast_message(
            fast.FC_FAST_SER,
            self.fast_ser[self._ser_index],
            resp_num=self._ser_resp_num,
            status=status,
        )
        self.fast_ser_sent.append(frame)
        self.send(frame)
        if self.resend_unacked:
            self.send(frame)

    # -- ASCII -----------------------------------------------------------

    def _handle(self, text: str) -> None:
        cmd = text.strip().upper()[:3]
        names = {"BNA": self.bna, "SNS": self.sns}
        if cmd in names and names[cmd] is not None and self._pending_level is None:
            self.send(text.encode("latin-1") + b"\r\n")
            rows = [names[cmd][i : i + 8] for i in range(0, len(names[cmd]), 8)]
            self.respond([format_record(row) for row in rows])
            return
        if cmd == "DNA" and self.dna is not None and self._pending_level is None:
            self.send(text.encode("latin-1") + b"\r\n")
            self.respond([format_record(row) for row in self.dna])
            return
        super()._handle(text)


# ---------------------------------------------------------------------------
# Telnet transport
# ---------------------------------------------------------------------------


class TelnetSocketRelay:
    """
    Serves a relay on a socket with Telnet: the relay's option offers are sent
    first, IAC sequences from the client are recorded (``negotiation``) and
    removed, and 0xFF bytes in the data are doubled (and un-doubled).
    """

    def __init__(
        self,
        relay: FakeSELRelay,
        sock: socket.socket,
        offer: bytes = RELAY_NEGOTIATION,
        chunk_size: int = 0,
    ) -> None:
        self.relay = relay
        self.sock = sock
        self.chunk_size = chunk_size
        #: IAC commands the client sent, e.g. b"\xff\xfd\x00"
        self.negotiation: list[bytes] = []
        #: Data from the client, without the IAC commands
        self.received = b""
        self._iac = b""
        self._lock = threading.Lock()
        self.offer = offer
        relay.send = self._send
        relay.close = self._close
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        """Send the option offers, and serve the relay (in a thread)."""
        if self.offer:
            self.sock.sendall(self.offer)
        self._thread.start()

    def _send(self, data: bytes) -> None:
        data = data.replace(b"\xff", b"\xff\xff")
        try:
            with self._lock:
                if not self.chunk_size:
                    self.sock.sendall(data)
                    return
                for i in range(0, len(data), self.chunk_size):
                    self.sock.sendall(data[i : i + self.chunk_size])
                    time.sleep(0.001)
        except OSError:
            pass

    def _close(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()

    def _unescape(self, data: bytes) -> bytes:
        out = bytearray()
        for byte in data:
            if self._iac:
                self._iac += bytes([byte])
                if len(self._iac) == 2 and byte == IAC:
                    out.append(IAC)  # doubled 0xFF
                    self._iac = b""
                elif len(self._iac) == 2 and byte not in (WILL, WONT, DO, DONT):
                    self.negotiation.append(self._iac)
                    self._iac = b""
                elif len(self._iac) == 3:
                    self.negotiation.append(self._iac)
                    self._iac = b""
            elif byte == IAC:
                self._iac = b"\xff"
            else:
                out.append(byte)
        return bytes(out)

    def _run(self) -> None:
        while not self.relay.closed:
            try:
                data = self.sock.recv(4096)
            except OSError:
                return
            if not data:
                return
            data = self._unescape(data)
            self.received += data
            if data:
                self.relay.feed(data)

    def stop(self) -> None:
        self.relay.closed = True
        self._close()
        if self._thread.is_alive():
            self._thread.join(timeout=2)


class TelnetRelayServer:
    """Accepts Telnet connections on 127.0.0.1, each served by a new relay from ``factory``."""

    def __init__(self, factory: Callable[[], FakeSELRelay], **kwargs) -> None:
        self.factory = factory
        self.kwargs = kwargs
        self.relays: list[FakeSELRelay] = []
        self.servers: list[TelnetSocketRelay] = []
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
            server = TelnetSocketRelay(relay, conn, **self.kwargs)
            # Listed before anything is sent, so a test that has the relay's
            # answer always finds its relay and server here
            self.relays.append(relay)
            self.servers.append(server)
            server.start()

    def close(self) -> None:
        self._running = False
        self.listener.close()
        for server in self.servers:
            server.stop()


# ---------------------------------------------------------------------------
# A relay like a SEL-400 series relay (synthetic data)
# ---------------------------------------------------------------------------

#: Names of the Fast Meter status byte bits (MSB first), like BNA output
BNA_NAMES = ["*", "*", "*", "STSET", "STFAIL", "STWARN", "STEVE", "STPWR"]
#: SER element names, like SNS output
SNS_NAMES = ["IN101", "OUT101", "52A", "TRIP"]


def make_400_relay(meter_status: int = 0x00, **overrides) -> FastRelay:
    """
    A relay with Fast Meter (A5C1 with float32 values and no scale factors, A5C2
    with int16 values and scale factors in the data message), no Fast Operate
    (FASTOP=N), and Fast Message with LOCAL, METER, HISTORY, and STATUS regions.
    ``meter_status`` is the status byte of A5D1 (0x10 is STSET, refer to
    :data:`BNA_NAMES`).
    """
    meter_config = fm_config(
        fast.FAST_METER_CONFIG,
        [("IA", 1, 0xFF, 0), ("VA", 1, 0xFF, 0), ("FREQ", 1, 0xFF, 0)],
        samples=2,
        digital_banks=2,
    )
    meter_data = fm_data(
        fast.FAST_METER_DATA,
        status=bytes([meter_status]),
        scale_factors=[],
        values=[1.5, 66.5, 0.0, 2.5, 120.0, 60.0],
        types=[1] * 6,
        timestamp=fm_timestamp(1, 2, 2024, 3, 4, 5, 678),
        digital=bytes([0x80, 0x01]),
    )
    demand_config = fm_config(
        fast.DEMAND_CONFIG, [("IA", 0, 1, 4), ("IB", 0, 1, 4)], samples=1, digital_banks=0
    )
    demand_data = fm_data(
        fast.DEMAND_DATA,
        status=b"\x00",
        scale_factors=[0.5],
        values=[100, -100],
        types=[0, 0],
        timestamp=fm_timestamp(1, 2, 2024, 3, 4, 5, 700),
    )
    history = history_region(
        [
            {"ref": 10002, "month": 1, "day": 1, "year": 2024, "hour": 12, "minute": 30,
             "second": 15, "ms": 250, "event": "AG T", "group": 1, "freq": 60.0,
             "current": 1234, "targets": "TRIP ZONE1"},
            {"ref": 10001, "month": 12, "day": 31, "year": 2023, "hour": 23, "minute": 59,
             "second": 59, "ms": 999, "event": "TRIG", "group": 1, "freq": 59.98,
             "current": 12, "targets": ""},
        ]
    )  # fmt: skip
    regions = [
        local_region(),
        FakeRegion("METER", 0x1000, [Item("IA_MAG", 0x41, 1, 1.0)]),
        history,
        FakeRegion(
            "STATUS",
            0x6000,
            [Item("WARN", 0x11, 32, ""), Item("FAIL", 0x11, 32, ""), Item("PS5(V)", 0x41, 1, 5.0)],
        ),
    ]
    kwargs = {
        "fid": FID_421,
        "definition": relay_definition(
            meter=[
                (fast.FAST_METER_CONFIG, fast.FAST_METER_DATA),
                (fast.DEMAND_CONFIG, fast.DEMAND_DATA),
            ],
            flags=[(4, b"\xa5\xc1"), (1, b"SNS")],
            protocols=[0x0300, 0x0005, 0x0004],
        ),
        "meter": {
            fast.FAST_METER_CONFIG: meter_config,
            fast.FAST_METER_DATA: meter_data,
            fast.DEMAND_CONFIG: demand_config,
            fast.DEMAND_DATA: demand_data,
        },
        "message_config": (
            [0x00, 0x01, 0x02, 0x30, 0x31, 0x33, 0x10],
            [0x18, 0xB0, 0xB1, 0xB3, 0x90],
        ),
        "regions": regions,
        "bna": BNA_NAMES,
        "dna": [["EN", "TRIP", "*", "*", "*", "*", "*", "IN101"], ["*"] * 7 + ["OUT101"]],
        "sns": SNS_NAMES,
    }
    kwargs.update(overrides)
    return FastRelay(**kwargs)


__all__ = [
    "BNA_NAMES",
    "FID_421",
    "RELAY_NEGOTIATION",
    "SNS_NAMES",
    "FakeRegion",
    "FastRelay",
    "Item",
    "TelnetRelayServer",
    "TelnetSocketRelay",
    "data_format_bodies",
    "device_description_bodies",
    "fast_ser_body",
    "fm_config",
    "fm_data",
    "fm_timestamp",
    "fo_config",
    "history_region",
    "local_region",
    "make_400_relay",
    "relay_definition",
]
