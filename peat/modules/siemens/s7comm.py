"""
Minimal client for the Siemens S7 communication protocol ("S7comm").

S7comm is the protocol used by STEP 7, TIA Portal, HMIs, and other S7 PLCs to
talk to SIMATIC S7-300, S7-400, S7-1200, and S7-1500 PLCs. It runs on top of
ISO-on-TCP (RFC 1006, TPKT and COTP) on TCP port 102.

This client implements only the read-only functions PEAT needs to identify
a PLC and collect basic information from it:

- COTP connection and S7 "Setup Communication"
- Reading System Status Lists (SZL, German "System-Zustandsliste"),
  e.g. module identification (``0x0011``) and component identification (``0x001C``)
- Listing the number of blocks of each type that are loaded on the PLC

It never writes to the PLC, changes the CPU mode, or uploads blocks.

S7-1200 (firmware 4.0+) and S7-1500 PLCs primarily use the newer and
integrity-protected "S7comm-plus" protocol for engineering access, but
still respond to classic S7comm SZL reads for identification, the same as
the ``s7-info`` Nmap script relies on.

References

- Wireshark S7comm dissector: https://wiki.wireshark.org/S7comm
- Snap7: https://snap7.sourceforge.net/
- Nmap s7-info script: https://nmap.org/nsedoc/scripts/s7-info.html
- Siemens "System Software for S7-300/400 System and Standard Functions"
  reference manual, chapter "System Status Lists (SSL)"

Authors

- Christopher Goes
"""

import socket
import struct
from dataclasses import dataclass, field

from peat import CommError, log

# COTP PDU types
COTP_CONNECT_REQUEST = 0xE0
COTP_CONNECT_CONFIRM = 0xD0
COTP_DATA = 0xF0

# S7 PDU types ("ROSCTR")
S7_JOB = 0x01
S7_ACK_DATA = 0x03
S7_USERDATA = 0x07

S7_PROTOCOL_ID = 0x32

# Userdata function groups
GROUP_BLOCK = 0x03
GROUP_SZL = 0x04

# Block type codes used by the "list blocks" userdata function
BLOCK_TYPES: dict[int, str] = {
    0x38: "OB",
    0x41: "DB",
    0x42: "SDB",
    0x43: "FC",
    0x44: "SFC",
    0x45: "FB",
    0x46: "SFB",
}

# Connection resource types, used as the high byte of the remote TSAP
CONNECTION_TYPES: dict[str, int] = {"pg": 0x01, "op": 0x02, "basic": 0x03}

# Indexes of the records in SZL 0x001C (component identification)
SZL_001C_FIELDS: dict[int, str] = {
    0x0001: "plc_name",
    0x0002: "module_name",
    0x0003: "plant_id",
    0x0004: "copyright",
    0x0005: "serial_number",
    0x0007: "module_type_name",
    0x0008: "memory_card_serial_number",
    0x0009: "manufacturer_and_profile",
    0x000A: "oem_id",
    0x000B: "location_id",
}

# Indexes of the records in SZL 0x0011 (module identification)
SZL_0011_FIELDS: dict[int, str] = {
    0x0001: "module",
    0x0006: "hardware",
    0x0007: "firmware",
    0x0081: "firmware_extension",
    0x0082: "boot_loader",
}

# Operating modes from SZL 0x0424 (current mode transition)
CPU_MODES: dict[int, str] = {
    0x00: "UNKNOWN",
    0x01: "STOP_UPDATE",
    0x02: "STOP_RESET",
    0x03: "STOP_INIT",
    0x04: "STOP",
    0x05: "STARTUP_COLD",
    0x06: "STARTUP_WARM",
    0x07: "STARTUP_HOT",
    0x08: "RUN",
    0x09: "RUN_R",
    0x0A: "HOLD",
    0x0D: "DEFECT",
}


def calc_tsap(rack: int, slot: int, connection_type: int = 0x01) -> int:
    """
    Calculate the remote TSAP (Transport Service Access Point) for a CPU.

    The low byte encodes the rack and slot of the CPU, the high byte the
    connection resource type. Most S7-300 CPUs are in rack 0, slot 2,
    and S7-1200/1500 CPUs are in rack 0, slot 0 or 1.
    """
    if not 0 <= rack <= 7 or not 0 <= slot <= 31:
        raise ValueError(f"Invalid S7 rack/slot {rack}/{slot}")
    return (connection_type << 8) | (rack * 0x20 + slot)


def build_tpkt(payload: bytes) -> bytes:
    """Wrap a payload in a TPKT header (RFC 1006)."""
    return struct.pack(">BBH", 0x03, 0x00, len(payload) + 4) + payload


def build_cotp_connect(local_tsap: int, remote_tsap: int, tpdu_size: int = 0x0A) -> bytes:
    """Build a TPKT-wrapped COTP Connection Request (CR) TPDU."""
    params = (
        struct.pack(">BBH", 0xC1, 2, local_tsap)
        + struct.pack(">BBH", 0xC2, 2, remote_tsap)
        + struct.pack(">BBB", 0xC0, 1, tpdu_size)
    )
    # Header: PDU type, destination reference, source reference, class 0
    header = struct.pack(">BHHB", COTP_CONNECT_REQUEST, 0x0000, 0x0001, 0x00) + params
    return build_tpkt(bytes([len(header)]) + header)


def build_cotp_data(s7_pdu: bytes) -> bytes:
    """Wrap a S7 PDU in a COTP Data (DT) TPDU and TPKT header."""
    return build_tpkt(bytes([0x02, COTP_DATA, 0x80]) + s7_pdu)


def build_s7_header(rosctr: int, pdu_ref: int, param_len: int, data_len: int) -> bytes:
    """Build the 10-byte S7 header used by job and userdata PDUs."""
    return struct.pack(">BBHHHH", S7_PROTOCOL_ID, rosctr, 0x0000, pdu_ref, param_len, data_len)


def build_setup_communication(pdu_ref: int = 0, pdu_size: int = 960) -> bytes:
    """Build a S7 "Setup Communication" job PDU."""
    params = struct.pack(">BBHHH", 0xF0, 0x00, 1, 1, pdu_size)
    return build_s7_header(S7_JOB, pdu_ref, len(params), 0) + params


def build_userdata_request(
    group: int,
    subfunction: int,
    data: bytes,
    pdu_ref: int = 0,
    sequence: int = 0,
    continuation: bool = False,
) -> bytes:
    """
    Build a S7 userdata request PDU.

    Continuation requests ask for the next fragment of a response that didn't
    fit into a single PDU, and carry the sequence number from that response.
    """
    if continuation:
        # Type 4 (request) and the "follow-up" parameter layout (12 bytes)
        params = struct.pack(
            ">BBBBBBBBBBH", 0x00, 0x01, 0x12, 0x08, 0x12, 0x40 | group, subfunction, sequence,
            0x00, 0x00, 0x0000,
        )  # fmt: skip
    else:
        params = struct.pack(
            ">BBBBBBBB", 0x00, 0x01, 0x12, 0x04, 0x11, 0x40 | group, subfunction, sequence
        )
    return build_s7_header(S7_USERDATA, pdu_ref, len(params), len(data)) + params + data


def build_szl_request(szl_id: int, szl_index: int, pdu_ref: int = 0) -> bytes:
    """Build a userdata request to read a SZL."""
    data = struct.pack(">BBHHH", 0xFF, 0x09, 4, szl_id, szl_index)
    return build_userdata_request(GROUP_SZL, 0x01, data, pdu_ref)


def build_list_blocks_request(pdu_ref: int = 0) -> bytes:
    """Build a userdata request for the number of blocks of each type."""
    return build_userdata_request(GROUP_BLOCK, 0x01, b"\x0a\x00\x00\x00", pdu_ref)


@dataclass
class UserdataResponse:
    """Parsed S7 userdata response PDU."""

    group: int
    subfunction: int
    sequence: int
    last_data_unit: bool
    error_code: int
    return_code: int
    data: bytes


def parse_cotp(packet: bytes) -> tuple[int, bytes]:
    """
    Strip the TPKT and COTP headers from a received packet.

    Returns:
        Tuple of the COTP PDU type and the remaining payload
    """
    if len(packet) < 7 or packet[0] != 0x03:
        raise CommError(f"Invalid TPKT packet: {packet[:16].hex()}")
    cotp_len = packet[4]
    pdu_type = packet[5] & 0xF0
    return pdu_type, packet[5 + cotp_len :]


def parse_setup_communication(pdu: bytes) -> int:
    """
    Parse a "Setup Communication" ack data PDU.

    Returns:
        The PDU size negotiated by the PLC
    """
    if len(pdu) < 20 or pdu[0] != S7_PROTOCOL_ID or pdu[1] != S7_ACK_DATA:
        raise CommError(f"Invalid S7 Setup Communication response: {pdu[:20].hex()}")
    error_class, error_code = pdu[10], pdu[11]
    if error_class or error_code:
        raise CommError(
            f"S7 Setup Communication rejected (error class 0x{error_class:02x}, "
            f"code 0x{error_code:02x})"
        )
    return struct.unpack(">H", pdu[18:20])[0]


def parse_userdata_response(pdu: bytes) -> UserdataResponse:
    """Parse a S7 userdata response PDU."""
    if len(pdu) < 10 or pdu[0] != S7_PROTOCOL_ID or pdu[1] != S7_USERDATA:
        raise CommError(f"Invalid S7 userdata response: {pdu[:16].hex()}")

    param_len, data_len = struct.unpack(">HH", pdu[6:10])
    params = pdu[10 : 10 + param_len]
    data = pdu[10 + param_len : 10 + param_len + data_len]
    if len(params) < 12 or len(data) < 4:
        raise CommError(f"Truncated S7 userdata response: {pdu.hex()}")

    return UserdataResponse(
        group=params[5] & 0x0F,
        subfunction=params[6],
        sequence=params[7],
        last_data_unit=params[9] == 0x00,
        error_code=struct.unpack(">H", params[10:12])[0],
        return_code=data[0],
        data=data[4 : 4 + struct.unpack(">H", data[2:4])[0]],
    )


def _decode_str(raw: bytes) -> str:
    return raw.split(b"\x00")[0].decode("latin-1", errors="replace").strip()


def split_szl_records(szl: bytes) -> tuple[int, int, list[bytes]]:
    """
    Split the data of a SZL into its records.

    The data starts with the SZL ID (2 bytes), index (2 bytes), length of a
    record in bytes (2 bytes), and number of records (2 bytes).

    Returns:
        Tuple of the SZL ID, SZL index, and list of raw records
    """
    if len(szl) < 8:
        raise CommError(f"SZL data is too short ({len(szl)} bytes)")

    szl_id, szl_index, record_len, num_records = struct.unpack(">HHHH", szl[:8])
    body = szl[8:]

    # Some emulators don't fill in the record header, infer it from the data
    if not record_len:
        record_len = {0x001C: 34, 0x0011: 28}.get(szl_id, len(body))
    if not num_records:
        num_records = len(body) // record_len if record_len else 0

    records = [
        body[i * record_len : (i + 1) * record_len]
        for i in range(num_records)
        if len(body) >= (i + 1) * record_len
    ]
    return szl_id, szl_index, records


def parse_szl_0011(szl: bytes) -> dict[str, dict[str, str]]:
    """
    Parse SZL 0x0011 (module identification).

    Each 28-byte record has an index (2 bytes), the order number (20 bytes,
    the MLFB, e.g. ``6ES7 315-2EH14-0AB0``), the module type (2 bytes),
    and two version words. For firmware records, the version words are
    ``V`` followed by the major, minor, and patch numbers. For module and
    hardware records, the second version word is the hardware revision.
    """
    _, _, records = split_szl_records(szl)
    results = {}

    for record in records:
        if len(record) < 22:
            continue
        index = struct.unpack(">H", record[:2])[0]
        name = SZL_0011_FIELDS.get(index, f"index_0x{index:04x}")

        entry = {"order_number": _decode_str(record[2:22])}
        if len(record) >= 28:
            if record[24] == ord("V"):
                entry["version"] = f"{record[25]}.{record[26]}.{record[27]}"
            elif any(record[26:28]):
                entry["version"] = str(struct.unpack(">H", record[26:28])[0])
        elif len(record) > 22 and any(record[23:]):
            # Non-standard short records (e.g. emulators): treat the tail as the version
            entry["version"] = ".".join(str(b) for b in record[23:26])
        results[name] = entry

    return results


def parse_szl_001c(szl: bytes) -> dict[str, str]:
    """
    Parse SZL 0x001C (component identification).

    Each record is a 2-byte index followed by a 32-byte string, such as the
    PLC name, module type, serial number, and plant identifier.
    """
    _, _, records = split_szl_records(szl)
    fields = list(SZL_001C_FIELDS.items())
    results = {}

    for position, record in enumerate(records):
        if len(record) < 4:
            continue
        index = struct.unpack(">H", record[:2])[0]
        if index in SZL_001C_FIELDS:
            name = SZL_001C_FIELDS[index]
        elif not index and position < len(fields):
            # Emulators may leave the index empty, so fall back to the record order
            name = fields[position][1]
        else:
            name = f"index_0x{index:04x}"

        # The manufacturer/profile record holds binary IDs, not a string
        if index == 0x0009:
            value = record[2:].hex()
        else:
            value = _decode_str(record[2:])
        if value:
            results[name] = value

    return results


def parse_szl_0424(szl: bytes) -> str:
    """
    Parse SZL 0x0424 (current mode transition) into the CPU operating mode.
    """
    _, _, records = split_szl_records(szl)
    if not records or len(records[0]) < 4:
        return ""
    return CPU_MODES.get(records[0][3], f"UNKNOWN_0x{records[0][3]:02x}")


def parse_block_counts(data: bytes) -> dict[str, int]:
    """
    Parse the response to a "list blocks" request.

    Each entry is 4 bytes: ``0x30``, the block type code, and the count.
    """
    counts = {}
    for i in range(0, len(data) - 3, 4):
        block_type = BLOCK_TYPES.get(data[i + 1], f"0x{data[i + 1]:02x}")
        counts[block_type] = struct.unpack(">H", data[i + 2 : i + 4])[0]
    return counts


@dataclass
class S7CommClient:
    """
    Read-only S7comm client.

    Usage:

    .. code-block:: python

       with S7CommClient("192.0.2.10", rack=0, slot=2) as client:
           identity = parse_szl_0011(client.read_szl(0x0011))
    """

    ip: str
    port: int = 102
    timeout: float = 5.0
    rack: int = 0
    slot: int = 2
    connection_type: int = 0x01
    pdu_size: int = 0
    _sock: socket.socket | None = field(default=None, repr=False)
    _pdu_ref: int = field(default=0, repr=False)

    def __enter__(self) -> "S7CommClient":
        self.connect()
        return self

    def __exit__(self, *args) -> None:
        self.disconnect()

    def connect(self) -> None:
        """Open the TCP connection, then perform the COTP and S7 handshakes."""
        self.disconnect()
        self._sock = socket.create_connection((self.ip, self.port), timeout=self.timeout)

        try:
            remote_tsap = calc_tsap(self.rack, self.slot, self.connection_type)
            self._sock.sendall(build_cotp_connect(0x0100, remote_tsap))
            pdu_type, _ = parse_cotp(self._recv_tpkt())
            if pdu_type != COTP_CONNECT_CONFIRM:
                raise CommError(f"COTP connection refused (PDU type 0x{pdu_type:02x})")

            self.pdu_size = parse_setup_communication(
                self._transact(build_setup_communication(self._next_ref()))
            )
        except Exception:
            self.disconnect()
            raise

        log.trace(
            f"S7comm connected to {self.ip}:{self.port} "
            f"(rack {self.rack}, slot {self.slot}, PDU size {self.pdu_size})"
        )

    def disconnect(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def read_szl(self, szl_id: int, szl_index: int = 0x0000) -> bytes:
        """
        Read a System Status List (SZL).

        Responses that don't fit in a single PDU are reassembled.

        Returns:
            The SZL data, starting with the SZL ID and index
        """
        response = self._userdata(build_szl_request(szl_id, szl_index, self._next_ref()))
        return self._reassemble(response, GROUP_SZL, 0x01, f"SZL 0x{szl_id:04x}")

    def list_blocks(self) -> dict[str, int]:
        """Get the number of blocks of each type loaded on the PLC."""
        response = self._userdata(build_list_blocks_request(self._next_ref()))
        return parse_block_counts(self._reassemble(response, GROUP_BLOCK, 0x01, "block list"))

    def _reassemble(
        self, response: UserdataResponse, group: int, subfunction: int, what: str
    ) -> bytes:
        if response.error_code or response.return_code != 0xFF:
            raise CommError(
                f"Reading {what} failed (error 0x{response.error_code:04x}, "
                f"return code 0x{response.return_code:02x})"
            )

        data = response.data
        # Guard against a PLC that never sets the "last data unit" flag
        for _ in range(64):
            if response.last_data_unit:
                break
            response = self._userdata(
                build_userdata_request(
                    group,
                    subfunction,
                    b"\x0a\x00\x00\x00",
                    self._next_ref(),
                    sequence=response.sequence,
                    continuation=True,
                )
            )
            data += response.data
        return data

    def _userdata(self, request: bytes) -> UserdataResponse:
        return parse_userdata_response(self._transact(request))

    def _transact(self, s7_pdu: bytes) -> bytes:
        if self._sock is None:
            raise CommError("S7comm client is not connected")
        self._sock.sendall(build_cotp_data(s7_pdu))
        pdu_type, payload = parse_cotp(self._recv_tpkt())
        if pdu_type != COTP_DATA:
            raise CommError(f"Unexpected COTP PDU type 0x{pdu_type:02x}")
        return payload

    def _recv_tpkt(self) -> bytes:
        header = self._recv_exact(4)
        length = struct.unpack(">H", header[2:4])[0]
        if length < 7:
            raise CommError(f"Invalid TPKT length {length}")
        return header + self._recv_exact(length - 4)

    def _recv_exact(self, size: int) -> bytes:
        buf = b""
        while len(buf) < size:
            chunk = self._sock.recv(size - len(buf))  # type: ignore[union-attr]
            if not chunk:
                raise CommError("S7comm connection closed by the PLC")
            buf += chunk
        return buf

    def _next_ref(self) -> int:
        self._pdu_ref = (self._pdu_ref + 1) % 0x10000
        return self._pdu_ref


__all__ = [
    "S7CommClient",
    "calc_tsap",
    "parse_block_counts",
    "parse_szl_001c",
    "parse_szl_0011",
    "parse_szl_0424",
]
