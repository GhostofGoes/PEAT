"""Helpers for building S7comm responses and a minimal fake S7 PLC for tests."""

import socket
import struct
import threading

from peat.modules.siemens import s7comm


def szl(szl_id: int, record_len: int, records: list[bytes]) -> bytes:
    """Build SZL data with the standard header (ID, index, record length, count)."""
    return struct.pack(">HHHH", szl_id, 0, record_len, len(records)) + b"".join(records)


def szl_0011_record(index: int, mlfb: str, version: bytes) -> bytes:
    return struct.pack(">H", index) + mlfb.encode().ljust(20, b" ") + b"\x00\xc0" + version


def szl_001c_record(index: int, value: str) -> bytes:
    return struct.pack(">H", index) + value.encode().ljust(32, b"\x00")


# Layout of a CPU 315-2 PN/DP response as described in the Siemens
# "System Software for S7-300/400" manual (SSL-ID W#16#xy11 and W#16#xy1C)
SZL_0011 = szl(
    0x0011,
    28,
    [
        szl_0011_record(0x0001, "6ES7 315-2EH14-0AB0", b"\x00\x00\x00\x04"),
        szl_0011_record(0x0006, "6ES7 315-2EH14-0AB0", b"\x00\x00\x00\x04"),
        szl_0011_record(0x0007, "", b"V\x03\x02\x06"),
    ],
)
SZL_001C = szl(
    0x001C,
    34,
    [
        szl_001c_record(0x0001, "Pump Station 1"),
        szl_001c_record(0x0002, "CPU 315-2 PN/DP"),
        szl_001c_record(0x0003, "PLANT-A"),
        szl_001c_record(0x0004, "Original Siemens Equipment"),
        szl_001c_record(0x0005, "S C-X4U421302009"),
        szl_001c_record(0x0007, "CPU 315-2 PN/DP"),
        szl_001c_record(0x0008, "MMC 267FF11F"),
    ],
)
SZL_0424_RUN = szl(0x0424, 20, [b"\x51\x44\xff\x08" + b"\x00" * 16])
BLOCK_COUNTS = bytes.fromhex("3038000130410003304300023045000130440010")


def userdata_response(
    data: bytes,
    last: bool = True,
    sequence: int = 0,
    error: int = 0,
    return_code: int = 0xFF,
    group: int = s7comm.GROUP_SZL,
) -> bytes:
    params = struct.pack(
        ">BBBBBBBBBBH", 0x00, 0x01, 0x12, 0x08, 0x12, 0x80 | group, 0x01, sequence, 0x00,
        0x00 if last else 0x01, error,
    )  # fmt: skip
    body = struct.pack(">BBH", return_code, 0x09, len(data)) + data
    return struct.pack(">BBHHHH", 0x32, 0x07, 0, 1, len(params), len(body)) + params + body


class FakePLC:
    """
    Minimal S7comm server that answers SZL reads and block list requests,
    optionally split into several response fragments.

    Unknown SZL IDs get an error response, like a CPU that doesn't support them.
    Connections for any rack/slot other than ``accept_slot`` are refused at the
    COTP level, like a CPU in a different slot. If ``drop_after`` is set, the
    connection is closed after that many userdata requests.
    """

    def __init__(
        self,
        szls: dict[int, bytes],
        fragment_size: int = 0,
        blocks: bytes = BLOCK_COUNTS,
        accept_slot: int | None = None,
        drop_after: int | None = None,
    ):
        self.szls = szls
        self.fragment_size = fragment_size
        self.blocks = blocks
        self.accept_slot = accept_slot
        self.drop_after = drop_after
        self.requests: list[bytes] = []
        self.connections = 0
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _send(self, conn: socket.socket, s7_pdu: bytes) -> None:
        conn.sendall(s7comm.build_cotp_data(s7_pdu))

    def _recv(self, conn: socket.socket) -> bytes:
        header = conn.recv(4)
        if len(header) < 4:
            return b""
        length = struct.unpack(">H", header[2:4])[0]
        body = b""
        while len(body) < length - 4:
            chunk = conn.recv(length - 4 - len(body))
            if not chunk:
                return b""
            body += chunk
        return header + body

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.connections += 1
            with conn:
                try:
                    self._handle(conn)
                except OSError:
                    pass

    def _handle(self, conn: socket.socket) -> None:
        cotp_cr = self._recv(conn)
        slot = cotp_cr[-4] & 0x1F  # Low byte of the remote TSAP
        if self.accept_slot is not None and slot != self.accept_slot:
            # COTP disconnect request
            conn.sendall(s7comm.build_tpkt(bytes.fromhex("0680000001000180")))
            return
        conn.sendall(s7comm.build_tpkt(bytes.fromhex("11d00001000100c0010a")))
        self._recv(conn)  # Setup communication
        params = struct.pack(">BBHHH", 0xF0, 0x00, 1, 1, 240)
        self._send(conn, struct.pack(">BBHHHHBB", 0x32, 0x03, 0, 1, 8, 0, 0, 0) + params)

        pending = b""
        group = s7comm.GROUP_SZL
        while True:
            packet = self._recv(conn)
            if not packet:
                return
            pdu = packet[7:]
            self.requests.append(pdu)
            if self.drop_after is not None and len(self.requests) > self.drop_after:
                return
            if not pending:
                param_len = struct.unpack(">H", pdu[6:8])[0]
                group = pdu[15] & 0x0F
                if group == s7comm.GROUP_BLOCK:
                    pending = self.blocks
                else:
                    data_start = 10 + param_len
                    szl_id = struct.unpack(">H", pdu[data_start + 4 : data_start + 6])[0]
                    if szl_id not in self.szls:
                        self._send(conn, userdata_response(b"", error=0xD401, return_code=0x0A))
                        continue
                    pending = self.szls[szl_id]
            size = self.fragment_size or len(pending)
            chunk, pending = pending[:size], pending[size:]
            self._send(conn, userdata_response(chunk, last=not pending, sequence=7, group=group))

    def close(self) -> None:
        self.sock.close()
