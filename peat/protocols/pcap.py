"""
Packet capture (PCAP) support.

This module provides two related capabilities:

- **Traffic capture**: record the network traffic PEAT sends and receives
  during a run to a PCAP file, using ``tcpdump`` (if available) or
  Scapy's :class:`~scapy.sendrecv.AsyncSniffer`
  (:class:`TrafficCapture`, :func:`start_traffic_capture` and
  :func:`stop_traffic_capture`). Capture is best-effort: if it can't
  be started (e.g. missing privileges, Npcap or tcpdump), a warning
  is logged and the run continues without it.
- **Synthesized captures**: build a PCAPNG file from application-layer
  payloads that a device module sent and received over a TCP socket
  (:class:`PayloadRecord`, :func:`synthesize_tcp_sessions`,
  :func:`packets_to_pcapng_bytes`). The Ethernet, IPv4 and TCP headers
  are reconstructed, which makes the payloads viewable in Wireshark
  without requiring privileges to sniff.

Scapy is imported lazily inside functions, since this module is only
imported when it's used (``from peat.protocols import pcap``).

.. code-block:: python
   :caption: Capturing traffic while using PEAT as a library

   from peat import pull
   from peat.protocols.pcap import TrafficCapture

   capture = TrafficCapture.for_targets(["192.0.2.0/24"], "unicast_ip")
   with capture:
       pull(["192.0.2.0/24"], "unicast_ip", ["m340"])
   print(capture.summary())
"""

from __future__ import annotations

import re
import signal
import struct
import subprocess
import tempfile
import threading
import time
import zlib
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network, collapse_addresses
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any, Literal
from urllib.parse import urlparse

from peat import config, consts, exit_handler, log, state, utils
from peat.consts import PeatError

if TYPE_CHECKING:
    from scapy.packet import Packet

PLACEHOLDER_LOCAL_MAC = "02:00:00:00:00:01"
"""Placeholder (locally administered) MAC used for PEAT's side of synthesized frames."""

PLACEHOLDER_REMOTE_MAC = "02:00:00:00:00:02"
"""Placeholder (locally administered) MAC used for the device's side of synthesized frames."""

SYNTH_NOTE = (
    "Synthesized by PEAT {version} from application payloads. The Ethernet, IP and "
    "TCP headers, segmentation and ACKs are reconstructed, not captured on the wire."
)
"""Comment added to the first frame of synthesized captures."""

PLACEHOLDER_MAC_NOTE = " MAC addresses 02:00:00:00:00:0x are placeholders."

MAX_FILTER_TERMS = 64
"""
Maximum number of host/network terms in a generated BPF filter.
This keeps generated programs well below the Linux limit of 4096 BPF instructions.
"""

ICMP_ERRORS_BPF = "icmp[icmptype] == icmp-unreach or icmp[icmptype] == icmp-timxceed"
"""BPF expression for ICMP errors (e.g. "port unreachable" responses to probes)."""

CAPTURE_TOOLS = ("auto", "tcpdump", "scapy")
"""Valid values for :attr:`~peat.settings.Configuration.CAPTURE_TOOL`."""

_STARTUP_TIMEOUT = 5.0  # seconds to wait for a capture backend to start
_FLUSH_INTERVAL = 1.0  # seconds between flushes of the scapy PCAPNG writer
_LOOPBACK_DUP_WINDOW = 0.005  # seconds
_MAX_STDERR_LINES = 200

# Before stopping, wait for packets that are still in flight (kernel buffers,
# capture tool): at least _DRAIN_MIN seconds, then until no packet arrived
# for _DRAIN_QUIET seconds, but no longer than _DRAIN_MAX seconds in total.
_DRAIN_MIN = 0.25
_DRAIN_QUIET = 0.25
_DRAIN_MAX = 2.0
# tcpdump without --immediate-mode buffers packets for up to ~1 second
_DRAIN_MIN_BUFFERED = 1.2


def _sleep(seconds: float) -> None:
    """
    :func:`time.sleep`, wrapped so tests can patch it for this module only.
    """
    time.sleep(seconds)


class CaptureError(PeatError):
    """
    Traffic capture failed to start or encountered an error.
    """


# ---------------------------------------------------------------------------
# Frame synthesis
# ---------------------------------------------------------------------------


@dataclass
class PayloadRecord:
    """
    An application-layer payload sent or received on a TCP connection.

    PEAT is always assumed to be the TCP client.
    """

    direction: Literal["send", "receive"]
    """``send`` if PEAT sent the payload, ``receive`` if PEAT received it."""

    payload: bytes
    """Raw TCP payload bytes."""

    time: float
    """Time the payload was sent or received, in seconds since the epoch."""

    local: tuple[str, int]
    """PEAT's (IP, port) for the connection."""

    remote: tuple[str, int]
    """The device's (IP, port) for the connection."""

    comment: str | None = None
    """Optional comment to add to the first frame carrying the payload."""


def _frame_us(frame: Packet) -> int:
    """
    Timestamp of a frame in integer microseconds.
    """
    return int(frame.time * 1_000_000)


def _to_time(microseconds: int) -> Any:
    """
    Convert integer microseconds to an exact Scapy timestamp.

    Floats can't represent microseconds for current epoch times
    exactly, which would cause timestamps to be off by one.
    """
    from scapy.utils import EDecimal

    return EDecimal(microseconds) / 1_000_000


_TCP_FLAGS = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08, "A": 0x10}
_MAX_MSS = 65535 - 20 - 20 - 4  # IPv4 total length limit, minus headers and options


def _mac_bytes(mac: str | None, default: str) -> bytes:
    """
    Convert a MAC address string (e.g. ``00:11:22:33:44:55``) to bytes.

    Invalid addresses (e.g. from untrusted device data) are replaced with ``default``.
    """
    digits = re.sub(r"[:.-]", "", str(mac or ""))
    if not re.fullmatch(r"[0-9a-fA-F]{12}", digits):
        digits = default.replace(":", "")
    return bytes.fromhex(digits)


class TcpStreamSynthesizer:
    """
    Generate Ethernet/IPv4/TCP frames for a single TCP connection.

    PEAT is always the client. Initial sequence numbers are derived from the
    connection 4-tuple, so the output is deterministic for the same input.
    Headers are built directly (instead of with Scapy layers), which is
    several times faster for large captures.

    Args:
        local: PEAT's (IP, port)
        remote: The device's (IP, port)
        local_mac: MAC address of PEAT's interface (placeholder if unset)
        remote_mac: MAC address of the device (placeholder if unset)
        mss: Maximum segment size. Payloads larger than this are split.
    """

    def __init__(
        self,
        local: tuple[str, int],
        remote: tuple[str, int],
        local_mac: str | None = None,
        remote_mac: str | None = None,
        mss: int = 1460,
    ) -> None:
        self.local = (str(local[0]), int(local[1]))
        self.remote = (str(remote[0]), int(remote[1]))
        self.local_mac = local_mac or PLACEHOLDER_LOCAL_MAC
        self.remote_mac = remote_mac or PLACEHOLDER_REMOTE_MAC
        self.mss = min(max(int(mss), 1), _MAX_MSS)
        self.client_seq = zlib.crc32(f"{self.local}{self.remote}".encode())
        self.server_seq = zlib.crc32(f"{self.remote}{self.local}".encode())
        self._ip_ids = {True: 1, False: 1}
        self._ips = (IPv4Address(self.local[0]).packed, IPv4Address(self.remote[0]).packed)
        self._macs = (
            _mac_bytes(self.local_mac, PLACEHOLDER_LOCAL_MAC),
            _mac_bytes(self.remote_mac, PLACEHOLDER_REMOTE_MAC),
        )

    def _frame(
        self,
        from_client: bool,
        flags: str,
        seq: int,
        ack: int,
        ts_us: int,
        payload: bytes = b"",
        comment: str | None = None,
        mss: int | None = None,
    ) -> Packet:
        from scapy.layers.l2 import Ether
        from scapy.utils import checksum

        if from_client:
            (_, sport), (_, dport) = self.local, self.remote
            (src, dst), (smac, dmac) = self._ips, self._macs
        else:
            (_, sport), (_, dport) = self.remote, self.local
            (dst, src), (dmac, smac) = self._ips, self._macs

        ip_id = self._ip_ids[from_client]
        self._ip_ids[from_client] = (ip_id + 1) & 0xFFFF

        options = struct.pack("!BBH", 2, 4, mss) if mss else b""  # MSS option
        offset_flags = ((5 + len(options) // 4) << 12) | sum(_TCP_FLAGS[f] for f in flags)
        tcp = (
            struct.pack(
                "!HHIIHHHH",
                sport,
                dport,
                seq & 0xFFFFFFFF,
                ack & 0xFFFFFFFF,
                offset_flags,
                64240,  # window
                0,  # checksum
                0,  # urgent pointer
            )
            + options
            + payload
        )
        pseudo_header = src + dst + struct.pack("!BBH", 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack("!H", checksum(pseudo_header + tcp)) + tcp[18:]

        # Version 4, IHL 5, total length, ID, DF flag, TTL 64, protocol TCP
        ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(tcp), ip_id, 0x4000, 64, 6, 0)
        ip = ip + src + dst
        ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]

        frame = Ether(dmac + smac + b"\x08\x00" + ip + tcp)
        frame.time = _to_time(ts_us)
        if comment:
            frame.comment = comment.encode("utf-8", "backslashreplace")
        return frame

    def handshake(self, ts_us: int, comment: str | None = None) -> list[Packet]:
        """
        TCP three-way handshake (SYN, SYN/ACK, ACK) at ``ts_us`` microseconds.
        """
        frames = [
            self._frame(True, "S", self.client_seq, 0, ts_us, comment=comment, mss=self.mss),
            self._frame(
                False, "SA", self.server_seq, self.client_seq + 1, ts_us + 1, mss=self.mss
            ),
        ]
        self.client_seq += 1
        self.server_seq += 1
        frames.append(self._frame(True, "A", self.client_seq, self.server_seq, ts_us + 2))
        return frames

    def data(
        self,
        from_client: bool,
        payload: bytes,
        ts_us: int,
        comment: str | None = None,
    ) -> list[Packet]:
        """
        Frames carrying ``payload``, split into segments of at most ``mss`` bytes.

        The comment is only added to the first segment.
        """
        frames = []
        for i, offset in enumerate(range(0, len(payload), self.mss)):
            chunk = payload[offset : offset + self.mss]
            if from_client:
                seq, ack = self.client_seq, self.server_seq
                self.client_seq += len(chunk)
            else:
                seq, ack = self.server_seq, self.client_seq
                self.server_seq += len(chunk)
            frames.append(
                self._frame(
                    from_client,
                    "PA",
                    seq,
                    ack,
                    ts_us + i,
                    payload=chunk,
                    comment=comment if i == 0 else None,
                )
            )
        return frames

    def teardown(self, ts_us: int) -> list[Packet]:
        """
        Connection teardown initiated by PEAT (FIN/ACK, FIN/ACK, ACK).
        """
        frames = [self._frame(True, "FA", self.client_seq, self.server_seq, ts_us)]
        self.client_seq += 1
        frames.append(self._frame(False, "FA", self.server_seq, self.client_seq, ts_us + 1))
        self.server_seq += 1
        frames.append(self._frame(True, "A", self.client_seq, self.server_seq, ts_us + 2))
        return frames


def synthesize_tcp_sessions(
    records: Iterable[PayloadRecord],
    local_mac: str | None = None,
    remote_mac: str | None = None,
    note: bool = True,
) -> list[Packet]:
    """
    Convert application-layer payloads into Ethernet/IPv4/TCP frames.

    See :func:`iter_tcp_sessions` for details.

    Returns:
        The synthesized frames (:class:`~scapy.layers.l2.Ether` packets)
    """
    return list(iter_tcp_sessions(records, local_mac, remote_mac, note))


def iter_tcp_sessions(
    records: Iterable[PayloadRecord],
    local_mac: str | None = None,
    remote_mac: str | None = None,
    note: bool = True,
) -> Iterator[Packet]:
    """
    Convert application-layer payloads into Ethernet/IPv4/TCP frames,
    one frame at a time (e.g. to stream them to :func:`write_pcapng`).

    Records are grouped into connections by their (local, remote) 4-tuple.
    Each connection gets a handshake before its first record and a teardown
    after its last record. Frames are returned in time order and their
    timestamps are strictly increasing.

    Args:
        records: The payloads, e.g. from a device module's packet tracker
        local_mac: MAC address of PEAT's interface (placeholder if unset)
        remote_mac: MAC address of the device (placeholder if unset)
        note: Add :data:`SYNTH_NOTE` as a comment on the first frame

    Yields:
        The synthesized frames (:class:`~scapy.layers.l2.Ether` packets)
    """
    from peat import __version__

    recs = sorted((r for r in records if r.payload), key=lambda r: r.time)
    last_index = {}  # type: dict[tuple, int]
    for i, rec in enumerate(recs):
        last_index[(rec.local, rec.remote)] = i

    streams = {}  # type: dict[tuple, TcpStreamSynthesizer]
    last_us = None  # type: int | None

    def _next_us(rec_time: float) -> int:
        # Timestamps must strictly increase, even if the source clock didn't
        wanted = round(rec_time * 1_000_000)
        return wanted if last_us is None else max(wanted, last_us + 1)

    for i, rec in enumerate(recs):
        key = (rec.local, rec.remote)
        stream = streams.get(key)
        batch = []  # type: list[Packet]
        if stream is None:
            stream = TcpStreamSynthesizer(rec.local, rec.remote, local_mac, remote_mac)
            streams[key] = stream
            comment = None
            if note and last_us is None:
                comment = SYNTH_NOTE.format(version=__version__)
                if not (local_mac and remote_mac):
                    comment += PLACEHOLDER_MAC_NOTE
            # Handshake shortly before the first payload on the connection
            batch.extend(stream.handshake(_next_us(rec.time - 0.0003), comment=comment))
            last_us = _frame_us(batch[-1])

        batch.extend(
            stream.data(rec.direction == "send", rec.payload, _next_us(rec.time), rec.comment)
        )
        last_us = _frame_us(batch[-1])
        if i == last_index[key]:
            batch.extend(stream.teardown(last_us + 100))
            last_us = _frame_us(batch[-1])

        yield from batch


def write_pcapng(path: Path, packets: Iterable[Packet]) -> int:
    """
    Write packets to a PCAPNG file, including per-packet comments.

    Args:
        path: File to write (overwritten if it exists)
        packets: Packets to write

    Returns:
        Number of packets written
    """
    from scapy.utils import PcapNgWriter

    count = 0
    writer = PcapNgWriter(str(path))
    try:
        for pkt in packets:
            if not writer.header_present:
                writer.write_header(pkt)
            writer.write_packet(pkt)
            count += 1
        if not writer.header_present:
            writer.linktype = 1  # Ethernet. Avoids Scapy's "unknown LL type" warning.
    finally:
        writer.close()
    return count


def packets_to_pcapng_bytes(packets: Iterable[Packet]) -> bytes:
    """
    Serialize packets to the bytes of a PCAPNG file.

    Scapy's writer requires a filename, so the file is written to a
    temporary directory (which also works on Windows) and read back.
    """
    with tempfile.TemporaryDirectory(prefix="peat-pcap-") as tmp:
        tmp_path = Path(tmp, "packets.pcapng")
        write_pcapng(tmp_path, packets)
        return tmp_path.read_bytes()


def local_mac_for_ip(ip: str) -> str | None:
    """
    MAC address of the local interface with the IPv4 address ``ip``, if known.
    """
    for details in state.local_interface_details.values():
        addrs = details.get("af_inet") or []
        if any(isinstance(a, dict) and a.get("addr") == ip for a in addrs):
            links = details.get("af_link") or []
            if links and isinstance(links[0], dict) and utils.is_mac(links[0].get("addr", "")):
                return links[0]["addr"]
    return None


# ---------------------------------------------------------------------------
# Target scoping: networks, BPF filters and the Python packet matcher
# ---------------------------------------------------------------------------


def target_networks(targets: Iterable[Any], comm_type: str) -> list[IPv4Network]:
    """
    Networks that are in scope for capture for a set of PEAT targets.

    - ``unicast_ip``: the targets (addresses, CIDR networks, ranges, hostnames
      and files of hosts). Networks are not expanded into addresses.
    - ``broadcast_ip``: the local networks of interface targets
      (e.g. ``eth0``), the local networks overlapping network or broadcast
      address targets, or all local networks for ``255.255.255.255`` and
      MAC broadcast targets. ``255.255.255.255/32`` is always included.
    - ``serial``: no networks.

    Returns:
        Sorted list of collapsed networks
    """
    from peat.protocols.addresses import (
        expand_commas_and_clean_strings,
        expand_filenames_to_hosts,
        hosts_to_objs,
    )

    nets = set()  # type: set[IPv4Network]

    if comm_type == "unicast_ip":
        hosts = expand_filenames_to_hosts(expand_commas_and_clean_strings(list(targets)))
        for obj in hosts_to_objs(hosts):
            nets.add(IPv4Network(obj) if isinstance(obj, IPv4Address) else obj)
    elif comm_type == "broadcast_ip":
        for raw in targets:
            target = str(raw).strip()
            if target in state.local_interface_networks:
                nets.update(state.local_interface_networks[target])
                continue
            try:
                net = IPv4Network(target, strict=False)
            except ValueError:
                # MAC broadcast address or something unexpected: all local networks
                nets.update(state.local_networks)
                continue
            if net == IPv4Network("255.255.255.255/32"):
                nets.update(state.local_networks)
            else:
                overlapping = [n for n in state.local_networks if n.overlaps(net)]
                nets.update(overlapping or [net])
        nets.add(IPv4Network("255.255.255.255/32"))

    return list(collapse_addresses(nets))


def reduce_networks(
    nets: Iterable[IPv4Network], limit: int = MAX_FILTER_TERMS
) -> list[IPv4Network] | None:
    """
    Reduce a list of networks to at most ``limit`` entries by summarizing them.

    Networks are summarized to their ``/24``, then ``/16``, then ``/8``
    supernets until there are ``limit`` or fewer.

    Returns:
        The reduced networks, or :obj:`None` if they couldn't be reduced enough
    """
    reduced = list(collapse_addresses(nets))
    for prefix in (24, 16, 8):
        if len(reduced) <= limit:
            return reduced
        reduced = list(
            collapse_addresses(
                n.supernet(new_prefix=prefix) if n.prefixlen > prefix else n for n in reduced
            )
        )
    return reduced if len(reduced) <= limit else None


def build_bpf_filter(nets: Iterable[IPv4Network], exclude_hosts: Iterable[str] = ()) -> str | None:
    """
    Build a BPF filter expression matching traffic to or from the networks.

    ``host`` and ``net`` terms also match ARP traffic. ICMP errors are always
    included, since they're often sent by routers rather than the targets.

    Args:
        nets: Networks in scope
        exclude_hosts: IPv4 addresses whose traffic is excluded

    Returns:
        The filter expression, or :obj:`None` if no filter is needed
    """
    terms = [
        f"host {n.network_address}" if n.prefixlen == 32 else f"net {n.with_prefixlen}"
        for n in nets
    ]
    excludes = [f"host {IPv4Address(h)}" for h in exclude_hosts]
    expr = f"({' or '.join(terms)}) or {ICMP_ERRORS_BPF}" if terms else ""
    if excludes:
        exclusion = f"not ({' or '.join(excludes)})"
        expr = f"({expr}) and {exclusion}" if expr else exclusion
    return expr or None


class TargetMatcher:
    """
    Python equivalent of :func:`build_bpf_filter`, used as a Scapy ``lfilter``
    when BPF filters can't be compiled (e.g. libpcap isn't installed).

    Matches IPv4 and ARP traffic to or from the networks, and ICMP errors
    about traffic to the networks. Traffic to or from excluded hosts is
    rejected. This never raises, since exceptions in an ``lfilter``
    cause Scapy to close the sniffing socket.
    """

    def __init__(self, nets: Iterable[IPv4Network], exclude_hosts: Iterable[str] = ()) -> None:
        nets = list(nets)
        self.hosts = frozenset(int(n.network_address) for n in nets if n.prefixlen == 32)
        self.nets = tuple(
            (int(n.network_address), int(n.netmask)) for n in nets if n.prefixlen != 32
        )
        self.exclude = frozenset(int(IPv4Address(h)) for h in exclude_hosts)

        from scapy.layers.inet import ICMP, IP, IPerror
        from scapy.layers.l2 import ARP

        self._layers = (IP, ARP, ICMP, IPerror)

    def _in_scope(self, addr: int) -> bool:
        return addr in self.hosts or any((addr & mask) == net for net, mask in self.nets)

    def __call__(self, pkt: Packet) -> bool:
        IP, ARP, ICMP, IPerror = self._layers

        try:
            if IP in pkt:
                src, dst = int(IPv4Address(pkt[IP].src)), int(IPv4Address(pkt[IP].dst))
            elif ARP in pkt:
                src, dst = int(IPv4Address(pkt[ARP].psrc)), int(IPv4Address(pkt[ARP].pdst))
            else:
                return False

            if src in self.exclude or dst in self.exclude:
                return False
            if self._in_scope(src) or self._in_scope(dst):
                return True
            if ICMP in pkt and pkt[ICMP].type in (3, 11) and IPerror in pkt:
                return self._in_scope(int(IPv4Address(pkt[IPerror].dst)))
        except Exception:
            return False
        return False


def _bpf_error(expr: str, iface: str | None = None) -> str:
    """
    Why Scapy can't compile a BPF filter expression (requires libpcap or Npcap),
    or an empty string if it can.
    """
    try:
        from scapy.arch.common import compile_filter

        compile_filter(expr, iface=iface)
    except ImportError:
        reason = "libpcap is not installed"
    except Exception as ex:
        reason = f"invalid filter, or interface error: {str(ex) or type(ex).__name__}"
    else:
        return ""
    log.debug(f"Unable to compile BPF filter '{expr}': {reason}")
    return reason


def _elastic_exclusions(nets: list[IPv4Network]) -> list[str]:
    """
    Address of the Elasticsearch server to exclude from the capture filter.

    This keeps the server's credentials and PEAT's pushes out of the capture,
    unless the server itself is explicitly a target. The server is excluded
    even if it's not on a target network, since the generated filter may
    summarize targets into larger networks that contain it.
    """
    if not config.ELASTIC_SERVER:
        return []

    from peat.protocols.addresses import resolve_hostname_to_ip

    try:
        hostname = urlparse(str(config.ELASTIC_SERVER)).hostname or ""
        ip = IPv4Address(resolve_hostname_to_ip(hostname))
    except ValueError:
        return []

    if IPv4Network(ip) in nets:  # explicit target
        return []
    return [str(ip)]


def route_interfaces(nets: list[IPv4Network], limit: int = 256) -> list[str]:
    """
    Names of the interfaces that Scapy would route traffic to the networks through.

    Args:
        nets: Networks in scope
        limit: Maximum number of route lookups. If there are more networks,
            the default interface is also added.

    Returns:
        Sorted list of interface names
    """
    from scapy.config import conf

    ifaces = set()  # type: set[str]
    for net in nets[:limit]:
        addr = net.network_address + 1 if net.num_addresses > 2 else net.network_address
        try:
            iface = conf.route.route(str(addr))[0]
        except Exception as ex:
            log.debug(f"Failed to look up route to {addr}: {ex}")
            continue
        if iface:
            ifaces.add(str(iface))

    if (not ifaces or len(nets) > limit) and conf.iface:
        ifaces.add(str(conf.iface))

    return sorted(ifaces)


def capture_supported() -> tuple[bool, str]:
    """
    If the system has what Scapy needs to sniff packets.

    Returns:
        Tuple of if capture is supported and the reason if it isn't
    """
    if consts.WINDOWS:
        from scapy.config import conf

        if not conf.use_pcap:
            return False, "Npcap is not installed (install it from https://npcap.com)"
    elif not state.raw_socket_capable:
        if consts.MACOS:
            return False, (
                "unable to open BPF devices (/dev/bpf*). Re-run PEAT with 'sudo', "
                "or install Wireshark's ChmodBPF to allow capturing as your user"
            )
        return False, (
            "raw sockets are unavailable. Re-run PEAT with 'sudo', or grant "
            "the CAP_NET_RAW capability (e.g. 'setcap cap_net_raw,cap_net_admin=eip')"
        )
    return True, ""


# ---------------------------------------------------------------------------
# Traffic capture
# ---------------------------------------------------------------------------


class TrafficCapture:
    """
    Capture network traffic to a file in the background.

    Two backends are available:

    - ``tcpdump``: runs ``tcpdump`` as a subprocess and writes a ``.pcap``
      file. tcpdump writes to a pipe (``-w -``) instead of opening the file
      itself, which avoids privilege-dropping and AppArmor problems and
      means it exits if PEAT dies.
    - ``scapy``: uses Scapy's :class:`~scapy.sendrecv.AsyncSniffer` and
      writes a ``.pcapng`` file (with one interface block per interface).

    :meth:`start` and :meth:`stop` never raise exceptions. Instances can be
    used as a context manager.

    Args:
        out_dir: Directory to write the capture file to
        interfaces: Interfaces to capture on. ``["all"]`` captures on all
            interfaces. If empty, Scapy's default interface is used.
        bpf: BPF filter expression (:obj:`None` for no filter)
        matcher: Python packet filter to use if ``bpf`` can't be compiled
            by Scapy (e.g. libpcap isn't installed)
        tool: Backend to use: ``auto``, ``tcpdump`` or ``scapy``
    """

    def __init__(
        self,
        out_dir: Path,
        interfaces: list[str],
        bpf: str | None = None,
        matcher: Callable[[Packet], bool] | None = None,
        tool: str = "auto",
    ) -> None:
        self.out_dir = Path(out_dir)
        self.interfaces = [str(i).strip() for i in interfaces if str(i).strip()]
        if any(i.lower() == "all" for i in self.interfaces):
            self.interfaces = ["all"]
        self.bpf = bpf or None
        self.matcher = matcher

        tool = str(tool or "auto").strip().lower()
        if tool not in CAPTURE_TOOLS:
            log.warning(f"Invalid capture tool '{tool}', using 'auto' (valid: {CAPTURE_TOOLS})")
            tool = "auto"
        self.tool = tool

        self.backend = ""
        self.path = None  # type: Path | None
        self.running = False
        self.error = ""
        self.active_filter = ""  # BPF filter applied by the capture tool
        self.python_filter = False  # If packets are filtered by the matcher in Python
        self.packets_written = 0
        self.packets_dropped = 0
        self.packets_skipped = 0
        self.started: datetime | None = None
        self.stopped: datetime | None = None

        self._lock = threading.Lock()
        self._custom_filter = False
        self._last_activity = 0.0  # time.monotonic() of the last captured data
        self._drain_min = _DRAIN_MIN
        # tcpdump backend
        self._proc = None  # type: subprocess.Popen | None
        self._file: IO[bytes] | None = None
        self._threads = []  # type: list[threading.Thread]
        self._stderr_lines = []  # type: list[str]
        # scapy backend
        self._sniffer = None  # type: Any
        self._writer = None  # type: Any
        self._started_event = threading.Event()
        self._last_flush = 0.0
        self._last_loopback = None  # type: tuple[bytes, float] | None
        self._loopback_name = ""
        self._errors = 0

    @classmethod
    def for_targets(
        cls, targets: list[str], comm_type: str, out_dir: Path | None = None
    ) -> TrafficCapture | None:
        """
        Create a capture scoped to PEAT targets, using the global configuration.

        Uses :attr:`~peat.settings.Configuration.CAPTURE_DIR`,
        :attr:`~peat.settings.Configuration.CAPTURE_INTERFACES`,
        :attr:`~peat.settings.Configuration.CAPTURE_FILTER` and
        :attr:`~peat.settings.Configuration.CAPTURE_TOOL`.

        Args:
            targets: Targets, as passed to :func:`~peat.api.scan_api.scan`
            comm_type: ``unicast_ip`` or ``broadcast_ip``
            out_dir: Override of the output directory

        Returns:
            The (not yet started) capture, or :obj:`None` if the
            output directory is unset or ``comm_type`` is ``serial``
        """
        out_dir = out_dir or config.CAPTURE_DIR
        if not out_dir:
            log.warning("Traffic capture is enabled but CAPTURE_DIR is unset, skipping capture")
            return None
        if comm_type == "serial":
            log.info("Serial traffic can't be captured to PCAP, skipping traffic capture")
            return None

        nets = target_networks(targets, comm_type)
        if not nets:
            log.warning("Unable to determine target networks for the traffic capture filter")
        exclude = _elastic_exclusions(nets)

        filter_setting = config.CAPTURE_FILTER
        filter_setting = "auto" if filter_setting is None else str(filter_setting).strip()
        matcher = None  # type: TargetMatcher | None

        if filter_setting.lower() == "auto":
            reduced = reduce_networks(nets)
            if reduced is None:
                log.warning(
                    "Too many target networks to build a capture filter, all traffic on "
                    "the capture interfaces will be captured. Set 'capture_filter' to "
                    "use a custom filter."
                )
            bpf = build_bpf_filter(reduced or [], exclude)
            if nets:
                matcher = TargetMatcher(nets, exclude)
        elif filter_setting == "":
            bpf = None
        else:
            bpf = filter_setting
            if nets:  # fallback if the custom filter can't be compiled
                matcher = TargetMatcher(nets, exclude)

        interfaces = list(config.CAPTURE_INTERFACES or [])
        if not interfaces:
            interfaces = route_interfaces(nets)

        capture = cls(
            out_dir=Path(out_dir),
            interfaces=interfaces,
            bpf=bpf,
            matcher=matcher,
            tool=config.CAPTURE_TOOL,
        )
        # The target matcher isn't equivalent to a custom filter, so warn if it's used
        capture._custom_filter = filter_setting.lower() not in ["auto", ""]
        return capture

    # -- lifecycle ----------------------------------------------------------

    def start(self) -> bool:
        """
        Start capturing. This never raises (except for :exc:`KeyboardInterrupt`).

        Returns:
            If the capture was started successfully
        """
        if self.running:
            return True

        tool = self._select_tool()
        started = False
        try:
            if tool == "tcpdump":
                started = self._try_start(self._start_tcpdump)
                if not started and self.tool == "auto":
                    log.warning(f"tcpdump failed to start ({self.error}), trying Scapy instead")
                    tool = "scapy"
            if tool == "scapy":
                started = self._try_start(self._start_scapy)
        except BaseException:  # e.g. Ctrl-C while starting: don't leave tcpdump behind
            self._cleanup()
            self._discard_file()
            raise

        if not started:
            log.warning(f"Traffic capture disabled: {self.error}")
            return False

        self.backend = tool
        self.error = ""
        self.running = True
        self.started = utils.utc_now()
        log.info(
            f"Capturing traffic with {tool} on {', '.join(self.interfaces) or 'default interface'}"
            f" to {self.path.as_posix() if self.path else ''}"
        )
        if self.python_filter:
            log.debug("Capture filter: traffic to or from the targets (filtered in Python)")
        else:
            log.debug(f"Capture filter: {self.active_filter or '(none)'}")
        return True

    def stop(self) -> dict[str, Any]:
        """
        Stop capturing and close the file. Safe to call multiple times.

        Returns:
            Summary of the capture (see :meth:`summary`)
        """
        if self.running:
            self.running = False
            try:
                if self.backend == "tcpdump":
                    self._stop_tcpdump()
                else:
                    self._stop_scapy()
            except Exception as ex:
                log.warning(f"Error while stopping traffic capture: {ex}")
            finally:
                self._cleanup()
            self.stopped = utils.utc_now()

            if self.path and self.path.exists():
                state.written_files.add(self.path.as_posix())
            msg = (
                f"Traffic capture finished: {self.packets_written} packets written "
                f"to {self.path.name if self.path else ''}"
            )
            if self.packets_skipped:
                msg += f" ({self.packets_skipped} skipped)"
            log.info(msg)
            if self.packets_dropped:
                log.warning(
                    f"{self.packets_dropped} packets were dropped by the kernel during "
                    f"traffic capture, the capture is incomplete"
                )

        return self.summary()

    def summary(self) -> dict[str, Any]:
        """
        Summary of the capture, as stored in ``state.traffic_capture``.

        ``filter`` is the BPF filter that was applied by the capture tool, which
        may differ from the requested filter if it couldn't be compiled.
        ``python_filter`` is :obj:`True` if packets were filtered in Python
        by the target matcher instead.
        """
        return {
            "tool": self.backend or self.tool,
            "interfaces": list(self.interfaces),
            "filter": self.active_filter,
            "python_filter": self.python_filter,
            "files": [self.path.as_posix()] if self.path and self.path.exists() else [],
            "packets_written": self.packets_written,
            "packets_dropped": self.packets_dropped,
            "packets_skipped": self.packets_skipped,
            "started": self.started.isoformat() if self.started else "",
            "stopped": self.stopped.isoformat() if self.stopped else "",
            "error": self.error,
        }

    def __enter__(self) -> TrafficCapture:
        self.start()
        return self

    def __exit__(self, *args: object) -> None:
        self.stop()

    # -- helpers ------------------------------------------------------------

    def _select_tool(self) -> str:
        # tcpdump captures on one interface, or on all interfaces ("-i any", Linux only)
        if self.tool == "scapy":
            return "scapy"
        if self.tool == "tcpdump":
            if len(self.interfaces) > 1 and consts.LINUX:
                log.warning(
                    "tcpdump can only capture on one interface or on all interfaces, "
                    "capturing on all interfaces ('-i any'). Use '--capture-tool scapy' "
                    "to capture on specific interfaces."
                )
                self.interfaces = ["all"]
            elif len(self.interfaces) > 1:
                log.warning(
                    f"tcpdump can only capture on one interface on this platform, "
                    f"capturing on '{self.interfaces[0]}' only"
                )
                self.interfaces = self.interfaces[:1]
            return "tcpdump"
        if not (consts.POSIX and consts.SYSINFO.get("tcpdump")):
            return "scapy"
        if len(self.interfaces) > 1 or (self.interfaces == ["all"] and not consts.LINUX):
            log.info(
                "Using Scapy to capture traffic, since tcpdump can't capture "
                "on multiple specific interfaces"
            )
            return "scapy"
        return "tcpdump"

    def _drain(self) -> None:
        """
        Wait for packets that are still in flight before stopping the capture,
        so the end of the run (e.g. the last responses and TCP teardowns)
        isn't missing from the capture.
        """
        start = time.monotonic()
        while True:
            now = time.monotonic()
            if now - start >= _DRAIN_MAX:
                break
            if now - start >= self._drain_min and now - self._last_activity >= _DRAIN_QUIET:
                break
            _sleep(0.02)

    def _try_start(self, func: Callable[[], None]) -> bool:
        try:
            func()
        except Exception as ex:
            self.error = str(ex) or type(ex).__name__
            log.debug(f"Failed to start {func.__name__}: {self.error}")
            self._cleanup()
            self._discard_file()
            self.active_filter = ""
            self.python_filter = False
            return False
        return True

    def _discard_file(self) -> None:
        """
        Remove the partial capture file of a capture that failed to start.
        """
        if self.path is not None:
            try:
                self.path.unlink(missing_ok=True)
            except OSError:
                pass
            self.path = None

    def _new_path(self, ext: str) -> Path:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        path = self.out_dir / f"peat-traffic{ext}"
        count = 1
        while path.exists():
            path = self.out_dir / f"peat-traffic_{count}{ext}"
            count += 1
        return path

    def _cleanup(self) -> None:
        """
        Release all resources. Must be safe to call in any state.
        """
        proc, self._proc = self._proc, None
        if proc is not None and proc.poll() is None:
            try:
                proc.kill()
                proc.wait(2)
            except Exception:
                pass

        for thread in self._threads:
            thread.join(2)
        self._threads = []

        if self._file is not None:
            try:
                self._file.close()
            except Exception:
                pass
            self._file = None

        sniffer, self._sniffer = self._sniffer, None
        if sniffer is not None and sniffer.thread is not None and sniffer.thread.is_alive():
            try:
                sniffer.stop(join=True)
            except Exception:
                pass

        with self._lock:
            writer, self._writer = self._writer, None
            if writer is not None:
                try:
                    if not writer.header_present:
                        writer.linktype = 1  # Ethernet, for a valid empty file
                    writer.close()
                except Exception:
                    pass

    # -- tcpdump backend ----------------------------------------------------

    def _start_tcpdump(self) -> None:
        tcpdump = str(consts.SYSINFO.get("tcpdump") or "")
        if consts.WINDOWS or not tcpdump:
            raise CaptureError("tcpdump is not installed")

        if consts.LINUX and (self.interfaces == ["all"] or len(self.interfaces) != 1):
            iface = "any"  # Can't be promiscuous, captures on all interfaces
            self.interfaces = ["all"]
        elif self.interfaces and self.interfaces != ["all"]:
            iface = self.interfaces[0]
        else:
            raise CaptureError("an interface must be specified when capturing with tcpdump")

        try:
            self._launch_tcpdump(tcpdump, iface, immediate=True)
        except CaptureError as ex:
            if "immediate-mode" not in str(ex):
                raise
            # tcpdump older than 4.6 (or built with an old libpcap)
            log.debug("tcpdump doesn't support --immediate-mode, retrying without it")
            self._cleanup()
            self._discard_file()
            self._drain_min = _DRAIN_MIN_BUFFERED
            self._launch_tcpdump(tcpdump, iface, immediate=False)
        self.active_filter = self.bpf or ""

    def _launch_tcpdump(self, tcpdump: str, iface: str, immediate: bool) -> None:
        # Argument list without a shell, and "--" so the filter can't add options.
        # "--immediate-mode" delivers packets as they arrive, instead of in blocks
        # that are only written every ~1 second (and lost when tcpdump is stopped).
        cmd = [tcpdump, "-i", iface, "-p", "-n", "-U"]
        if immediate:
            cmd.append("--immediate-mode")
        cmd.extend(["-B", "4096", "-w", "-"])
        if self.bpf:
            cmd.extend(["--", self.bpf])

        self.path = self._new_path(".pcap")
        self._file = self.path.open("wb")
        self._stderr_lines = []
        log.debug(f"Running tcpdump: {cmd}")

        self._proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            # Separate process group, so Ctrl-C in a terminal doesn't kill
            # tcpdump before PEAT finishes closing connections with devices
            start_new_session=True,
        )
        self._threads = [
            threading.Thread(target=self._copy_stdout, name="peat-tcpdump-out", daemon=True),
            threading.Thread(target=self._read_stderr, name="peat-tcpdump-err", daemon=True),
        ]
        for thread in self._threads:
            thread.start()

        deadline = time.monotonic() + _STARTUP_TIMEOUT
        while time.monotonic() < deadline:
            if any("listening on" in line for line in self._stderr_lines):
                return
            if self._proc.poll() is not None:
                break
            _sleep(0.05)

        if self._proc.poll() is not None:
            for thread in self._threads:
                thread.join(2)
            stderr = " ".join(self._stderr_lines).strip()
            raise CaptureError(
                f"tcpdump exited with code {self._proc.returncode}: {stderr or 'no output'}"
            )
        log.debug("tcpdump didn't report that it's listening, assuming it's running")

    def _copy_stdout(self) -> None:
        proc, out = self._proc, self._file
        if proc is None or proc.stdout is None or out is None:
            return
        try:
            while True:
                chunk = proc.stdout.read1(65536)  # type: ignore[attr-defined]
                if not chunk:
                    break
                out.write(chunk)
                out.flush()
                self._last_activity = time.monotonic()
        except Exception as ex:
            log.debug(f"Error copying tcpdump output: {ex}")

    def _read_stderr(self) -> None:
        proc = self._proc
        if proc is None or proc.stderr is None:
            return
        try:
            for raw in iter(proc.stderr.readline, b""):
                if len(self._stderr_lines) < _MAX_STDERR_LINES:
                    self._stderr_lines.append(raw.decode("utf-8", "replace").strip())
        except Exception as ex:
            log.debug(f"Error reading tcpdump stderr: {ex}")

    def _stop_tcpdump(self) -> None:
        proc = self._proc
        if proc is None:
            return

        if proc.poll() is not None:
            log.warning(
                f"tcpdump exited unexpectedly during the run (code {proc.returncode}), "
                f"the capture is incomplete"
            )
        else:
            self._drain()
            try:
                proc.send_signal(signal.SIGINT)  # tcpdump prints statistics on SIGINT
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.terminate()
                try:
                    proc.wait(3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(3)
            except OSError:
                pass

        for thread in self._threads:
            thread.join(5)
        self._threads = []
        if self._file is not None:
            self._file.close()
            self._file = None

        stderr = "\n".join(self._stderr_lines)
        self.parse_tcpdump_stats(stderr)
        if config.LOG_DIR and stderr:
            utils.write_file(stderr + "\n", Path(config.LOG_DIR, "tcpdump.log"))

    def parse_tcpdump_stats(self, stderr: str) -> None:
        """
        Parse the statistics tcpdump prints when it exits.
        """
        stats = {}
        for key, pattern in (
            ("captured", r"(\d+) packets? captured"),
            ("dropped", r"(\d+) packets? dropped by kernel"),
        ):
            match = re.search(pattern, stderr)
            if match:
                stats[key] = int(match.group(1))
        self.packets_written = stats.get("captured", self.packets_written)
        self.packets_dropped = stats.get("dropped", self.packets_dropped)

    # -- scapy backend ------------------------------------------------------

    def _start_scapy(self) -> None:
        supported, reason = capture_supported()
        if not supported:
            raise CaptureError(reason)

        # Register link types, otherwise sniffed frames are Raw and can't be written
        import scapy.layers.inet
        import scapy.layers.l2  # noqa: F401
        from scapy.config import conf
        from scapy.sendrecv import AsyncSniffer
        from scapy.utils import PcapNgWriter

        if self.interfaces == ["all"]:
            from scapy.interfaces import get_if_list

            ifaces = list(get_if_list())
        else:
            ifaces = list(self.interfaces)
        self._loopback_name = str(conf.loopback_name)

        requested = bpf = self.bpf or ""
        error = _bpf_error(bpf, ifaces[0] if ifaces else None) if bpf else ""
        if error:
            bpf = ""
            if self.matcher is not None:
                fallback = (
                    "filtering traffic to or from the targets in Python instead (higher "
                    "CPU usage, packets may be dropped on busy networks)"
                )
            else:
                fallback = "all traffic will be captured"
            if self._custom_filter or self.matcher is None:
                expr = requested if len(requested) <= 200 else f"{requested[:200]}..."
                log.warning(f"Unable to use the capture filter '{expr}' ({error}), {fallback}")
            else:  # The matcher is equivalent to the generated filter
                log.info(f"Unable to compile the capture filter ({error}), {fallback}")

        self.path = self._new_path(".pcapng")
        self._writer = PcapNgWriter(str(self.path))
        self._started_event.clear()

        kwargs = {
            "store": False,
            "prn": self._on_packet,
            "started_callback": self._started_event.set,
            "promisc": False,  # PEAT only needs its own traffic
        }  # type: dict[str, Any]
        if ifaces:
            kwargs["iface"] = ifaces if len(ifaces) > 1 else ifaces[0]
        if bpf:
            kwargs["filter"] = bpf
        elif self.matcher is not None:
            kwargs["lfilter"] = self.matcher

        self._sniffer = AsyncSniffer(**kwargs)
        self._sniffer.start()

        # Wait for the sniffer to start, or for its thread to die
        # (e.g. invalid interface, insufficient permissions or bad filter)
        deadline = time.monotonic() + _STARTUP_TIMEOUT
        while not self._started_event.wait(0.05):
            thread = self._sniffer.thread
            if thread is None or not thread.is_alive() or time.monotonic() > deadline:
                raise CaptureError(
                    f"packet sniffer failed to start: {self._sniffer.exception or 'timed out'}"
                )
        self.active_filter = bpf or ""
        self.python_filter = "lfilter" in kwargs

    def _is_loopback_dup(self, pkt: Packet) -> bool:
        """
        Linux loopback interfaces deliver each frame twice (outgoing and incoming).
        """
        if str(getattr(pkt, "sniffed_on", "")) != self._loopback_name:
            return False
        raw, ts = bytes(pkt), float(pkt.time)
        prev = self._last_loopback
        if prev is not None and prev[0] == raw and abs(ts - prev[1]) < _LOOPBACK_DUP_WINDOW:
            self._last_loopback = None
            return True
        self._last_loopback = (raw, ts)
        return False

    def _on_packet(self, pkt: Packet) -> None:
        """
        Write a sniffed packet. This MUST NOT raise exceptions, since that
        causes Scapy to close the sniffing socket.
        """
        try:
            self._last_activity = time.monotonic()
            if self._is_loopback_dup(pkt):
                return
            with self._lock:
                writer = self._writer
                if writer is None:
                    return
                if not writer.header_present:
                    writer.write_header(pkt)
                writer.write_packet(pkt)
                self.packets_written += 1
                now = time.monotonic()
                if now - self._last_flush >= _FLUSH_INTERVAL:
                    writer.flush()
                    self._last_flush = now
        except KeyError:  # Unknown link type
            self.packets_skipped += 1
        except Exception as ex:
            self.packets_skipped += 1
            self._errors += 1
            if self._errors == 1:
                log.warning(f"Failed to write a captured packet: {ex}")

    def _stop_scapy(self) -> None:
        sniffer = self._sniffer
        if sniffer is None:
            return

        thread = sniffer.thread
        if thread is not None and thread.is_alive():
            self._drain()
            try:
                sniffer.stop(join=True)
            except Exception as ex:
                log.debug(f"Error stopping packet sniffer: {ex}")
        self._sniffer = None

        if sniffer.exception is not None:
            log.warning(
                f"Packet sniffer stopped early with an error, the capture "
                f"is incomplete: {sniffer.exception}"
            )


# ---------------------------------------------------------------------------
# Global capture used by the CLI
# ---------------------------------------------------------------------------

_ACTIVE = None  # type: TrafficCapture | None
_ACTIVE_LOCK = threading.RLock()


def start_traffic_capture(targets: list[str], comm_type: str) -> TrafficCapture | None:
    """
    Start the global traffic capture for a run, if it's not already running.

    Capture failures are logged as warnings and never raise. If started,
    :func:`stop_traffic_capture` is registered as an exit handler,
    so the capture is stopped and flushed even on abnormal exits.

    Args:
        targets: Targets of the run
        comm_type: ``unicast_ip``, ``broadcast_ip`` or ``serial``

    Returns:
        The running capture, or :obj:`None` if it wasn't started
    """
    global _ACTIVE

    with _ACTIVE_LOCK:
        if _ACTIVE is not None and _ACTIVE.running:
            return _ACTIVE

        try:
            capture = TrafficCapture.for_targets(targets, comm_type)
        except Exception as ex:
            log.warning(f"Traffic capture disabled: failed to configure capture: {ex}")
            state.traffic_capture = {"error": str(ex)}
            return None

        if capture is None:
            return None

        if not capture.start():
            state.traffic_capture = capture.summary()
            return None

        _ACTIVE = capture
        state.traffic_capture = capture.summary()
        exit_handler.register(stop_traffic_capture, "FILE")
        return capture


def stop_traffic_capture() -> dict[str, Any]:
    """
    Stop the global traffic capture, if one is running. Safe to call multiple times.

    Returns:
        Summary of the capture (also stored in ``state.traffic_capture``),
        or an empty :class:`dict` if no capture was running
    """
    global _ACTIVE

    with _ACTIVE_LOCK:
        capture, _ACTIVE = _ACTIVE, None
        if capture is None:
            return {}

        try:
            exit_handler.unregister(stop_traffic_capture, "FILE")
        except ValueError:
            pass

        summary = capture.stop()
        state.traffic_capture = summary
        return summary


__all__ = [
    "PLACEHOLDER_LOCAL_MAC",
    "PLACEHOLDER_REMOTE_MAC",
    "SYNTH_NOTE",
    "CaptureError",
    "PayloadRecord",
    "TargetMatcher",
    "TcpStreamSynthesizer",
    "TrafficCapture",
    "build_bpf_filter",
    "capture_supported",
    "iter_tcp_sessions",
    "local_mac_for_ip",
    "packets_to_pcapng_bytes",
    "reduce_networks",
    "route_interfaces",
    "start_traffic_capture",
    "stop_traffic_capture",
    "synthesize_tcp_sessions",
    "target_networks",
    "write_pcapng",
]
