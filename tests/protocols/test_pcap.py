import io
import os
import socket
import threading
import time
from ipaddress import IPv4Network
from pathlib import Path

import pytest
from scapy.layers.inet import ICMP, IP, TCP, UDP, IPerror, UDPerror
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import rdpcap

from peat import config, consts, exit_handler, state
from peat.protocols import pcap

# Real values, since the _isolate fixture disables waiting for in-flight packets
DRAIN = {k: getattr(pcap, k) for k in ["_DRAIN_MIN", "_DRAIN_QUIET", "_DRAIN_MAX"]}

LOCAL = ("192.0.2.10", 40000)
REMOTE = ("192.0.2.20", 502)


@pytest.fixture(autouse=True)
def _isolate(mocker):
    """Isolate the global capture, state and configuration used by these tests."""
    mocker.patch.object(pcap, "_ACTIVE", None)
    mocker.patch.dict(state["CONFIG"], {"traffic_capture": {}, "written_files": set()})
    mocker.patch.dict(
        config["CONFIG"],
        {
            "CAPTURE_FILTER": "auto",
            "CAPTURE_INTERFACES": [],
            "CAPTURE_TOOL": "auto",
            "ELASTIC_SERVER": None,
            "LOG_DIR": None,
        },
    )
    # Don't wait for in-flight packets when stopping fake captures
    mocker.patch.multiple(pcap, _DRAIN_MIN=0.0, _DRAIN_QUIET=0.0, _DRAIN_MAX=0.0)


def _tcp_payload(pkt) -> bytes:
    """
    TCP payload from the raw frame bytes. Unlike ``pkt[TCP].payload``, this doesn't
    depend on which Scapy layers are bound to the port (e.g. scapy.contrib.modbus).
    """
    raw = bytes(pkt)
    ihl = (raw[14] & 0x0F) * 4
    data_offset = (raw[14 + ihl + 12] >> 4) * 4
    total_length = int.from_bytes(raw[16:18], "big")
    return raw[14 + ihl + data_offset : 14 + total_length]


def _eth() -> Ether:
    # Explicit MACs, so Scapy never resolves them using ARP (network access)
    return Ether(src="00:00:5e:00:53:01", dst="00:00:5e:00:53:02")


def _ts(pkt) -> int:
    return int(pkt.time * 1_000_000)


# ---------------------------------------------------------------------------
# Frame synthesis
# ---------------------------------------------------------------------------


def test_handshake_seq_ack():
    syn, synack, ack = pcap.TcpStreamSynthesizer(LOCAL, REMOTE).handshake(1_000_000)
    assert syn[TCP].flags == "S"
    assert syn[TCP].ack == 0
    assert ("MSS", 1460) in syn[TCP].options
    assert synack[TCP].flags == "SA"
    assert synack[TCP].ack == syn[TCP].seq + 1
    assert ack[TCP].flags == "A"
    assert ack[TCP].seq == syn[TCP].seq + 1
    assert ack[TCP].ack == synack[TCP].seq + 1
    assert (syn[IP].src, syn[TCP].sport, syn[IP].dst, syn[TCP].dport) == (*LOCAL, *REMOTE)
    assert (synack[IP].src, synack[TCP].sport) == REMOTE
    assert syn[Ether].src == pcap.PLACEHOLDER_LOCAL_MAC
    assert syn[Ether].dst == pcap.PLACEHOLDER_REMOTE_MAC
    assert _ts(syn) < _ts(synack) < _ts(ack)

    # Initial sequence numbers are deterministic
    again = pcap.TcpStreamSynthesizer(LOCAL, REMOTE).handshake(5)
    assert again[0][TCP].seq == syn[TCP].seq
    assert again[1][TCP].seq == synack[TCP].seq


def test_data_advances_seq_and_segments():
    stream = pcap.TcpStreamSynthesizer(LOCAL, REMOTE, local_mac="00:00:5e:00:53:01")
    stream.handshake(0)
    client_seq, server_seq = stream.client_seq, stream.server_seq

    (request,) = stream.data(True, b"A" * 10, 100, comment="request")
    assert request[TCP].flags == "PA"
    assert request[TCP].seq == client_seq
    assert request[TCP].ack == server_seq
    assert request.comment == b"request"
    assert request[Ether].src == "00:00:5e:00:53:01"

    response = stream.data(False, b"B" * 3000, 200, comment="response")
    assert len(response) == 3  # 1460 + 1460 + 80
    assert [len(_tcp_payload(p)) for p in response] == [1460, 1460, 80]
    assert response[0].comment == b"response"
    assert all(getattr(p, "comment", None) is None for p in response[1:])
    assert response[0][TCP].ack == client_seq + 10
    assert response[1][TCP].seq == response[0][TCP].seq + 1460
    assert response[2][TCP].seq == response[1][TCP].seq + 1460
    assert [_ts(p) for p in response] == [200, 201, 202]
    assert stream.server_seq == server_seq + 3000

    assert stream.data(True, b"", 300) == []


def test_teardown():
    stream = pcap.TcpStreamSynthesizer(LOCAL, REMOTE)
    stream.handshake(0)
    stream.data(True, b"hello", 10)
    client_seq, server_seq = stream.client_seq, stream.server_seq
    fin1, fin2, last = stream.teardown(20)
    assert (fin1[TCP].flags, fin2[TCP].flags, last[TCP].flags) == ("FA", "FA", "A")
    assert fin1[TCP].seq == client_seq
    assert fin2[TCP].ack == client_seq + 1
    assert last[TCP].ack == server_seq + 1


def test_checksums_valid():
    stream = pcap.TcpStreamSynthesizer(LOCAL, REMOTE)
    frames = stream.handshake(0) + stream.data(True, b"\x00\x01payload", 10)
    for frame in frames:
        rebuilt = frame.copy()
        del rebuilt[IP].chksum
        del rebuilt[TCP].chksum
        rebuilt = Ether(bytes(rebuilt))
        assert rebuilt[IP].chksum == frame[IP].chksum
        assert rebuilt[TCP].chksum == frame[TCP].chksum


def test_frames_match_scapy():
    """Frames built with struct are identical to frames built with Scapy layers."""
    stream = pcap.TcpStreamSynthesizer(LOCAL, REMOTE, "00-00-5E-00-53-01", "00:00:5e:00:53:02")
    frames = (
        stream.handshake(0)
        + stream.data(True, bytes(range(256)) * 12, 10)  # 3 segments
        + stream.data(False, b"\x01", 20)  # odd length
        + stream.teardown(30)
    )
    for frame in frames:
        ip, tcp = frame[IP], frame[TCP]
        expected = (
            Ether(src=frame.src, dst=frame.dst)
            / IP(src=ip.src, dst=ip.dst, id=ip.id, ttl=64, flags="DF")
            / TCP(
                sport=tcp.sport,
                dport=tcp.dport,
                flags=tcp.flags,
                seq=tcp.seq,
                ack=tcp.ack,
                window=64240,
                options=tcp.options,
            )
        )
        if tcp.payload:
            expected = expected / bytes(tcp.payload)
        assert bytes(expected) == bytes(frame)
    assert frames[0].src == "00:00:5e:00:53:01"
    assert frames[0][TCP].options == [("MSS", 1460)]


def test_invalid_macs_and_mss():
    # MACs from device data are untrusted: invalid ones are replaced with placeholders
    stream = pcap.TcpStreamSynthesizer(
        LOCAL, REMOTE, "not-a-mac", "00:11:22:33:44:55:66", mss=10**6
    )
    frame = stream.handshake(0)[0]
    assert frame.src == pcap.PLACEHOLDER_LOCAL_MAC
    assert frame.dst == pcap.PLACEHOLDER_REMOTE_MAC
    assert stream.mss == pcap._MAX_MSS
    frames = stream.data(True, b"x" * (pcap._MAX_MSS + 1), 10)
    assert [len(_tcp_payload(f)) for f in frames] == [pcap._MAX_MSS, 1]


def test_iter_tcp_sessions_is_lazy():
    records = [_record("send", b"one", 100.0), _record("receive", b"two", 100.1)]
    frames = pcap.iter_tcp_sessions(records)
    assert not isinstance(frames, list)
    assert [bytes(f) for f in frames] == [bytes(f) for f in pcap.synthesize_tcp_sessions(records)]


def _record(direction, payload, t, local=LOCAL, comment=None):
    return pcap.PayloadRecord(direction, payload, t, local, REMOTE, comment)


def test_synthesize_tcp_sessions():
    other = ("192.0.2.10", 40001)
    records = [
        _record("send", b"one", 100.0, comment="first"),
        _record("receive", b"two", 100.0),  # same timestamp as the request
        _record("send", b"", 100.5),  # empty payloads are skipped
        _record("send", b"three", 101.0, local=other),
        _record("receive", b"four", 101.5, local=other),
    ]
    frames = pcap.synthesize_tcp_sessions(records)

    syns = [f for f in frames if f[TCP].flags == "S"]
    fins = [f for f in frames if f[TCP].flags == "FA"]
    assert len(syns) == 2
    assert len(fins) == 4
    assert [f[TCP].sport for f in syns] == [40000, 40001]

    # Strictly increasing timestamps, even with identical input timestamps
    times = [_ts(f) for f in frames]
    assert times == sorted(times)
    assert len(set(times)) == len(times)

    # First connection is torn down before the second starts
    first_conn = [i for i, f in enumerate(frames) if 40000 in (f[TCP].sport, f[TCP].dport)]
    assert first_conn == list(range(len(first_conn)))

    payloads = [_tcp_payload(f) for f in frames if f[TCP].flags == "PA"]
    assert payloads == [b"one", b"two", b"three", b"four"]
    assert b"Synthesized by PEAT" in syns[0].comment
    assert b"placeholders" in syns[0].comment
    assert getattr(syns[1], "comment", None) is None

    data = [f for f in frames if f[TCP].flags == "PA"]
    assert data[0].comment == b"first"

    assert pcap.synthesize_tcp_sessions([]) == []
    with_macs = pcap.synthesize_tcp_sessions(
        records[:1], local_mac="00:00:5e:00:53:01", remote_mac="00:00:5e:00:53:02"
    )
    assert b"placeholders" not in with_macs[0].comment
    assert pcap.synthesize_tcp_sessions(records[:1], note=False)[0].comment is None


def test_write_pcapng_roundtrip(tmp_path):
    frames = pcap.synthesize_tcp_sessions(
        [_record("send", b"req", 1700000000.123456, comment="UMAS request")]
    )
    path = tmp_path / "test.pcapng"
    assert pcap.write_pcapng(path, frames) == len(frames)

    read = rdpcap(str(path))
    assert len(read) == len(frames)
    assert all(Ether in p for p in read)
    assert [float(p.time) for p in read] == [float(p.time) for p in frames]
    assert [bytes(p) for p in read] == [bytes(p) for p in frames]
    assert read[3].comment == b"UMAS request"
    assert float(read[3].time) == pytest.approx(1700000000.123456, abs=1e-6)


def test_packets_to_pcapng_bytes():
    frames = pcap.synthesize_tcp_sessions([_record("send", b"req", 10.0)])
    data = pcap.packets_to_pcapng_bytes(frames)
    assert data.startswith(b"\x0a\x0d\x0d\x0a")
    assert b"req" in data

    # Empty capture is still a valid file
    assert pcap.packets_to_pcapng_bytes([]).startswith(b"\x0a\x0d\x0d\x0a")


def test_local_mac_for_ip(mocker):
    mocker.patch.dict(
        state["CONFIG"],
        {
            "local_interface_details": {
                "eth0": {
                    "af_inet": [{"addr": "192.0.2.10", "netmask": "255.255.255.0"}],
                    "af_link": [{"addr": "00:00:5e:00:53:01"}],
                },
                "eth1": {"af_inet": [{"addr": "198.51.100.1"}]},
            }
        },
    )
    assert pcap.local_mac_for_ip("192.0.2.10") == "00:00:5e:00:53:01"
    assert pcap.local_mac_for_ip("198.51.100.1") is None
    assert pcap.local_mac_for_ip("203.0.113.1") is None


# ---------------------------------------------------------------------------
# Target scoping
# ---------------------------------------------------------------------------


def test_target_networks_unicast(mocker):
    spy = mocker.spy(pcap.IPv4Network, "hosts")
    nets = pcap.target_networks(
        ["10.0.0.0/8", "192.0.2.5", "192.0.2.0/24", "198.51.100.1-2,203.0.113.7"],
        "unicast_ip",
    )
    assert nets == [
        IPv4Network("10.0.0.0/8"),
        IPv4Network("192.0.2.0/24"),
        IPv4Network("198.51.100.1/32"),
        IPv4Network("198.51.100.2/32"),
        IPv4Network("203.0.113.7/32"),
    ]
    spy.assert_not_called()  # Large networks are never expanded


def test_target_networks_file(tmp_path):
    hosts = tmp_path / "hosts.txt"
    hosts.write_text("192.0.2.1\n192.0.2.2\n")
    assert pcap.target_networks([hosts.as_posix()], "unicast_ip") == [
        IPv4Network("192.0.2.1/32"),
        IPv4Network("192.0.2.2/32"),
    ]


def test_target_networks_broadcast(mocker):
    mocker.patch.dict(
        state["CONFIG"],
        {
            "local_interface_networks": {
                "eth0": [IPv4Network("192.0.2.0/24")],
                "eth1": [IPv4Network("198.51.100.0/24")],
            },
            "local_networks": [IPv4Network("192.0.2.0/24"), IPv4Network("198.51.100.0/24")],
        },
    )
    bcast = IPv4Network("255.255.255.255/32")
    assert pcap.target_networks(["eth1"], "broadcast_ip") == [
        IPv4Network("198.51.100.0/24"),
        bcast,
    ]
    assert pcap.target_networks(["192.0.2.255"], "broadcast_ip") == [
        IPv4Network("192.0.2.0/24"),
        bcast,
    ]
    everything = [IPv4Network("192.0.2.0/24"), IPv4Network("198.51.100.0/24"), bcast]
    assert pcap.target_networks(["255.255.255.255"], "broadcast_ip") == everything
    assert pcap.target_networks(["ff:ff:ff:ff:ff:ff"], "broadcast_ip") == everything
    # Non-local network: used as-is
    assert pcap.target_networks(["203.0.113.0/24"], "broadcast_ip") == [
        IPv4Network("203.0.113.0/24"),
        bcast,
    ]


def test_target_networks_serial():
    assert pcap.target_networks(["/dev/ttyS0"], "serial") == []


def test_reduce_networks():
    small = [IPv4Network("192.0.2.1/32"), IPv4Network("192.0.2.7/32")]
    assert pcap.reduce_networks(small) == small

    many = [IPv4Network(f"10.1.{i // 200}.{i % 200}/32") for i in range(0, 600, 2)]
    many += [IPv4Network(f"10.2.{i}.1/32") for i in range(150)]
    reduced = pcap.reduce_networks(many)
    assert reduced is not None
    assert len(reduced) <= pcap.MAX_FILTER_TERMS
    for net in many:
        assert any(net.subnet_of(r) for r in reduced)

    scattered = [IPv4Network(f"{i}.0.0.1/32") for i in range(1, 200, 2)]  # Not adjacent
    assert pcap.reduce_networks(scattered) is None
    assert pcap.reduce_networks(scattered, limit=200) == scattered


def test_build_bpf_filter():
    nets = [IPv4Network("192.0.2.0/24"), IPv4Network("198.51.100.7/32")]
    assert pcap.build_bpf_filter(nets) == (
        f"(net 192.0.2.0/24 or host 198.51.100.7) or {pcap.ICMP_ERRORS_BPF}"
    )
    assert pcap.build_bpf_filter(nets, exclude_hosts=["192.0.2.50"]) == (
        f"((net 192.0.2.0/24 or host 198.51.100.7) or {pcap.ICMP_ERRORS_BPF}) "
        f"and not (host 192.0.2.50)"
    )
    assert pcap.build_bpf_filter([]) is None
    assert pcap.build_bpf_filter([], exclude_hosts=["192.0.2.50"]) == "not (host 192.0.2.50)"
    with pytest.raises(ValueError):
        pcap.build_bpf_filter(nets, exclude_hosts=["192.0.2.50; rm -rf /"])


def test_target_matcher():
    matcher = pcap.TargetMatcher(
        [IPv4Network("192.0.2.0/24"), IPv4Network("198.51.100.7/32")],
        exclude_hosts=["192.0.2.50"],
    )
    me = "203.0.113.1"
    assert matcher(_eth() / IP(src=me, dst="192.0.2.20") / TCP())
    assert matcher(_eth() / IP(src="198.51.100.7", dst=me) / UDP())
    assert not matcher(_eth() / IP(src=me, dst="198.51.100.8") / TCP())
    assert not matcher(_eth() / IP(src=me, dst="192.0.2.50") / TCP())  # excluded
    assert matcher(_eth() / ARP(psrc=me, pdst="192.0.2.30"))
    assert not matcher(_eth() / ARP(psrc=me, pdst="203.0.113.9"))
    # ICMP error from a router about traffic to a target
    unreach = IP(src="203.0.113.254", dst=me) / ICMP(type=3, code=3)
    assert matcher(_eth() / unreach / IPerror(src=me, dst="192.0.2.9") / UDPerror())
    assert not matcher(_eth() / unreach / IPerror(src=me, dst="203.0.113.9") / UDPerror())
    assert not matcher(_eth() / IP(src="203.0.113.254", dst=me) / ICMP(type=8))
    # Not IP or ARP, and malformed packets, never raise
    assert not matcher(Raw(b"\x00" * 10))
    assert not matcher(None)  # type: ignore[arg-type]


def test_elastic_exclusions(mocker):
    nets = [IPv4Network("192.0.2.0/24"), IPv4Network("198.51.100.9/32")]
    assert pcap._elastic_exclusions(nets) == []
    mocker.patch.dict(config["CONFIG"], {"ELASTIC_SERVER": "http://user:pass@192.0.2.5:9200"})
    assert pcap._elastic_exclusions(nets) == ["192.0.2.5"]
    mocker.patch.dict(config["CONFIG"], {"ELASTIC_SERVER": "http://198.51.100.9:9200"})
    assert pcap._elastic_exclusions(nets) == []  # explicit target
    # Excluded even if it's not on a target network (filters may summarize networks)
    mocker.patch.dict(config["CONFIG"], {"ELASTIC_SERVER": "http://203.0.113.5:9200"})
    assert pcap._elastic_exclusions(nets) == ["203.0.113.5"]
    mocker.patch.dict(config["CONFIG"], {"ELASTIC_SERVER": "http://localhost:9200"})
    assert pcap._elastic_exclusions(nets) == ["127.0.0.1"]
    mocker.patch.dict(config["CONFIG"], {"ELASTIC_SERVER": "not a url"})
    assert pcap._elastic_exclusions(nets) == []


def test_for_targets_excludes_elastic_in_summarized_networks(mocker, tmp_path):
    """The Elasticsearch server is excluded even if only a summarized network contains it."""
    mocker.patch.object(pcap, "route_interfaces", return_value=["eth0"])
    mocker.patch.dict(
        config["CONFIG"],
        {"CAPTURE_DIR": tmp_path, "ELASTIC_SERVER": "http://elastic:changeme@192.0.2.200:9200"},
    )
    targets = [f"192.0.2.{i}" for i in range(1, 140, 2)]  # 70 hosts, summarized to a /24
    capture = pcap.TrafficCapture.for_targets(targets, "unicast_ip")
    assert capture.bpf.startswith("((net 192.0.2.0/24) or icmp")
    assert capture.bpf.endswith("and not (host 192.0.2.200)")
    es_frame = _eth() / IP(src="192.0.2.10", dst="192.0.2.200") / TCP(dport=9200)
    assert not capture.matcher(es_frame)
    assert capture.matcher(_eth() / IP(src="192.0.2.10", dst="192.0.2.1") / TCP())

    # Too many networks to filter: everything but the Elasticsearch server
    many = [f"{i}.0.0.1" for i in range(1, 160, 2)]
    assert pcap.TrafficCapture.for_targets(many, "unicast_ip").bpf == "not (host 192.0.2.200)"


def test_route_interfaces(mocker):
    import scapy.config

    routes = {"192.0.2.1": "eth0", "198.51.100.7": "eth1", "203.0.113.1": "eth0"}
    route = mocker.Mock(side_effect=lambda addr: (routes[addr], "0.0.0.0", "0.0.0.0"))
    # Scapy's conf validates assignments, so replace it entirely
    fake_conf = mocker.Mock(iface="eth9", route=mocker.Mock(route=route))
    mocker.patch.object(scapy.config, "conf", fake_conf)
    nets = [
        IPv4Network("192.0.2.0/24"),
        IPv4Network("198.51.100.7/32"),
        IPv4Network("203.0.113.0/30"),
    ]
    assert pcap.route_interfaces(nets) == ["eth0", "eth1"]
    assert route.call_count == 3
    assert pcap.route_interfaces(nets, limit=1) == ["eth0", "eth9"]
    assert pcap.route_interfaces([]) == ["eth9"]

    route.side_effect = OSError("no route")
    assert pcap.route_interfaces(nets) == ["eth9"]


def test_capture_supported(mocker):
    mocker.patch.object(consts, "WINDOWS", False)
    mocker.patch.object(consts, "MACOS", False)
    mocker.patch.dict(state["CONFIG"], {"raw_socket_capable": True})
    assert pcap.capture_supported() == (True, "")

    mocker.patch.dict(state["CONFIG"], {"raw_socket_capable": False})
    ok, reason = pcap.capture_supported()
    assert not ok
    assert "CAP_NET_RAW" in reason

    mocker.patch.object(consts, "MACOS", True)
    assert "ChmodBPF" in pcap.capture_supported()[1]

    import scapy.config

    mocker.patch.object(consts, "WINDOWS", True)
    mocker.patch.object(consts, "MACOS", False)
    mocker.patch.object(scapy.config, "conf", mocker.Mock(use_pcap=False))
    ok, reason = pcap.capture_supported()
    assert not ok
    assert "npcap.com" in reason


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("platform", "tcpdump", "tool", "interfaces", "expected"),
    [
        ("linux", "/usr/bin/tcpdump", "auto", ["eth0"], "tcpdump"),
        ("linux", "/usr/bin/tcpdump", "auto", ["eth0", "eth1"], "scapy"),
        ("linux", "/usr/bin/tcpdump", "auto", ["all"], "tcpdump"),
        ("linux", "", "auto", ["eth0"], "scapy"),
        ("linux", "/usr/bin/tcpdump", "scapy", ["eth0"], "scapy"),
        ("linux", "", "tcpdump", ["eth0"], "tcpdump"),
        ("linux", "/usr/bin/tcpdump", "invalid", ["eth0"], "tcpdump"),
        ("macos", "/usr/sbin/tcpdump", "auto", ["en0"], "tcpdump"),
        ("macos", "/usr/sbin/tcpdump", "auto", ["en0", "en1"], "scapy"),
        ("macos", "/usr/sbin/tcpdump", "auto", ["all"], "scapy"),
        ("windows", "", "auto", ["Ethernet"], "scapy"),
        ("windows", "C:/tcpdump.exe", "auto", ["Ethernet"], "scapy"),
    ],
)
def test_select_tool(mocker, tmp_path, platform, tcpdump, tool, interfaces, expected):
    mocker.patch.object(consts, "LINUX", platform == "linux")
    mocker.patch.object(consts, "MACOS", platform == "macos")
    mocker.patch.object(consts, "WINDOWS", platform == "windows")
    mocker.patch.object(consts, "POSIX", platform != "windows")
    mocker.patch.dict(consts.SYSINFO, {"tcpdump": tcpdump})
    capture = pcap.TrafficCapture(tmp_path, interfaces, tool=tool)
    if tool == "invalid":
        assert capture.tool == "auto"
    assert capture._select_tool() == expected


def test_select_tool_explicit_tcpdump_multiple_interfaces(mocker, tmp_path, caplog):
    mocker.patch.object(consts, "LINUX", False)
    capture = pcap.TrafficCapture(tmp_path, ["en0", "en1"], tool="tcpdump")
    assert capture._select_tool() == "tcpdump"
    assert capture.interfaces == ["en0"]
    assert "capturing on 'en0' only" in caplog.text

    # Linux: all interfaces, and the summary says so
    mocker.patch.object(consts, "LINUX", True)
    capture = pcap.TrafficCapture(tmp_path, ["eth0", "eth1"], tool="tcpdump")
    assert capture._select_tool() == "tcpdump"
    assert capture.summary()["interfaces"] == ["all"]
    assert "capturing on all interfaces ('-i any')" in caplog.text


TCPDUMP_STDERR = (
    b"tcpdump: listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes\n"
    b"42 packets captured\n"
    b"45 packets received by filter\n"
    b"3 packets dropped by kernel\n"
)


class FakePopen:
    """Fake tcpdump process that writes canned output to its pipes."""

    instances: list["FakePopen"] = []

    def __init__(self, cmd, stdout_data=b"", stderr_data=TCPDUMP_STDERR, exit_code=None, **kw):
        self.args = cmd
        self.kwargs = kw
        self.stdout = io.BufferedReader(io.BytesIO(stdout_data))
        self.stderr = io.BytesIO(stderr_data)
        self.returncode = exit_code
        self.signals = []
        FakePopen.instances.append(self)

    def poll(self):
        return self.returncode

    def send_signal(self, sig):
        self.signals.append(sig)
        self.returncode = 0

    def wait(self, timeout=None):  # noqa: ARG002
        return self.returncode

    def terminate(self):
        self.returncode = -15

    def kill(self):
        self.returncode = -9


@pytest.fixture
def fake_tcpdump(mocker):
    """Patch subprocess.Popen with a fake tcpdump. Returns a function to configure it."""
    FakePopen.instances = []
    mocker.patch.object(consts, "LINUX", True)
    mocker.patch.object(consts, "WINDOWS", False)
    mocker.patch.object(consts, "POSIX", True)
    mocker.patch.dict(consts.SYSINFO, {"tcpdump": "/usr/bin/tcpdump"})

    def _configure(**kwargs):
        popen = mocker.patch.object(
            pcap.subprocess,
            "Popen",
            side_effect=lambda cmd, **kw: FakePopen(cmd, **kwargs, **kw),
        )
        return popen

    return _configure


def test_tcpdump_backend(fake_tcpdump, tmp_path, mocker, caplog):
    pcap_bytes = pcap.packets_to_pcapng_bytes(
        pcap.synthesize_tcp_sessions([_record("send", b"req", 10.0)])
    )
    popen = fake_tcpdump(stdout_data=pcap_bytes)
    mocker.patch.dict(config["CONFIG"], {"LOG_DIR": tmp_path / "logs"})

    bpf = "host 192.0.2.20 or icmp"
    capture = pcap.TrafficCapture(tmp_path / "pcaps", ["eth0"], bpf=bpf)
    assert capture.start()
    assert capture.running
    assert capture.backend == "tcpdump"

    args, kwargs = popen.call_args
    assert args[0] == [
        "/usr/bin/tcpdump",
        *("-i", "eth0", "-p", "-n", "-U", "--immediate-mode", "-B", "4096", "-w", "-"),
        "--",
        bpf,
    ]
    assert kwargs["start_new_session"] is True
    assert not kwargs.get("shell")

    summary = capture.stop()
    assert not capture.running
    assert FakePopen.instances[0].signals  # Stopped with SIGINT
    assert capture.path == tmp_path / "pcaps" / "peat-traffic.pcap"
    assert capture.path.read_bytes() == pcap_bytes
    assert summary["files"] == [capture.path.as_posix()]
    assert summary["tool"] == "tcpdump"
    assert summary["filter"] == bpf
    assert summary["python_filter"] is False
    assert summary["packets_written"] == 42
    assert summary["packets_dropped"] == 3
    assert summary["started"]
    assert summary["stopped"]
    assert "3 packets were dropped" in caplog.text
    assert capture.path.as_posix() in state.written_files
    assert "42 packets captured" in (tmp_path / "logs" / "tcpdump.log").read_text()

    assert capture.stop() == summary  # idempotent


def test_tcpdump_multiple_interfaces_linux(fake_tcpdump, tmp_path):
    popen = fake_tcpdump()
    capture = pcap.TrafficCapture(tmp_path, ["eth0", "eth1"], tool="tcpdump")
    assert capture.start()
    assert popen.call_args[0][0][1:3] == ["-i", "any"]
    assert popen.call_args[0][0][-1] == "-"  # No filter
    assert capture.stop()["interfaces"] == ["all"]

    # A second capture in the same directory doesn't overwrite the first
    capture2 = pcap.TrafficCapture(tmp_path, ["eth0", "ALL"], tool="tcpdump")
    assert capture2.interfaces == ["all"]
    assert capture2.start()
    assert popen.call_args[0][0][1:3] == ["-i", "any"]
    capture2.stop()
    assert capture2.path == tmp_path / "peat-traffic_1.pcap"


def test_tcpdump_failure_falls_back_to_scapy(fake_tcpdump, tmp_path, mocker, caplog):
    fake_tcpdump(stderr_data=b"tcpdump: eth0: You don't have permission\n", exit_code=1)
    start_scapy = mocker.patch.object(pcap.TrafficCapture, "_start_scapy")

    capture = pcap.TrafficCapture(tmp_path, ["eth0"])
    assert capture.start()
    assert capture.backend == "scapy"
    start_scapy.assert_called_once()
    assert "You don't have permission" in caplog.text
    assert not (tmp_path / "peat-traffic.pcap").exists()  # Partial file removed


def test_tcpdump_explicit_failure_does_not_raise(fake_tcpdump, tmp_path, mocker, caplog):
    fake_tcpdump(stderr_data=b"tcpdump: eth0: No such device exists\n", exit_code=1)
    start_scapy = mocker.patch.object(pcap.TrafficCapture, "_start_scapy")

    capture = pcap.TrafficCapture(tmp_path, ["eth0"], tool="tcpdump")
    assert not capture.start()
    assert not capture.running
    start_scapy.assert_not_called()
    assert "Traffic capture disabled" in caplog.text
    assert "No such device" in capture.summary()["error"]
    assert capture.stop()["files"] == []
    assert list(tmp_path.iterdir()) == []


def test_tcpdump_without_immediate_mode(fake_tcpdump, tmp_path):
    """Old tcpdump versions without --immediate-mode are retried without it."""
    popen = fake_tcpdump()
    old = b"tcpdump: unrecognized option '--immediate-mode'\n"

    def _popen(cmd, **kw):
        if "--immediate-mode" in cmd:
            return FakePopen(cmd, stderr_data=old, exit_code=1, **kw)
        return FakePopen(cmd, **kw)

    popen.side_effect = _popen
    capture = pcap.TrafficCapture(tmp_path, ["eth0"], tool="tcpdump")
    assert capture.start()
    assert popen.call_count == 2
    assert "--immediate-mode" not in popen.call_args[0][0]
    assert capture._drain_min == pcap._DRAIN_MIN_BUFFERED  # Waits longer for buffered packets
    assert FakePopen.instances[0].returncode == 1
    assert capture.path == tmp_path / "peat-traffic.pcap"
    capture.stop()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["peat-traffic.pcap"]


@pytest.mark.usefixtures("fake_sniffer")
def test_stop_drains_before_stopping(fake_tcpdump, tmp_path, mocker):
    """In-flight packets are waited for before tcpdump or the sniffer are stopped."""
    events = mocker.Mock()
    mocker.patch.object(pcap.TrafficCapture, "_drain", events.drain)
    fake_tcpdump()
    capture = pcap.TrafficCapture(tmp_path, ["eth0"], tool="tcpdump")
    assert capture.start()
    mocker.patch.object(capture._proc, "send_signal", events.send_signal)
    capture.stop()
    assert [c[0] for c in events.mock_calls] == ["drain", "send_signal"]

    events.reset_mock()
    capture = pcap.TrafficCapture(tmp_path, ["eth0"], tool="scapy")
    assert capture.start()
    mocker.patch.object(capture._sniffer, "stop", events.stop)
    capture.stop()
    assert [c[0] for c in events.mock_calls] == ["drain", "stop"]


def test_drain(tmp_path, mocker):
    mocker.patch.multiple(pcap, _DRAIN_MIN=0.05, _DRAIN_QUIET=0.05, _DRAIN_MAX=0.3)
    capture = pcap.TrafficCapture(tmp_path, ["eth0"])

    # Nothing captured recently: only the minimum wait
    start = time.monotonic()
    capture._drain()
    assert 0.05 <= time.monotonic() - start < 0.3

    # Packets keep arriving: stops waiting at the maximum
    def _busy(seconds):
        capture._last_activity = time.monotonic()
        time.sleep(seconds)

    mocker.patch.object(pcap, "_sleep", side_effect=_busy)
    start = time.monotonic()
    capture._drain()
    assert time.monotonic() - start >= 0.3


def test_tcpdump_ctrl_c_while_starting(fake_tcpdump, tmp_path, mocker):
    fake_tcpdump(stderr_data=b"")  # Never reports that it's listening
    mocker.patch.object(pcap, "_sleep", side_effect=KeyboardInterrupt)

    capture = pcap.TrafficCapture(tmp_path, ["eth0"])
    with pytest.raises(KeyboardInterrupt):
        capture.start()
    assert not capture.running
    assert FakePopen.instances[0].returncode == -9  # Killed
    assert list(tmp_path.iterdir()) == []


def test_parse_tcpdump_stats(tmp_path):
    capture = pcap.TrafficCapture(tmp_path, ["eth0"])
    capture.parse_tcpdump_stats("1 packet captured\n2 packets received by filter\n")
    assert capture.packets_written == 1
    assert capture.packets_dropped == 0
    capture.parse_tcpdump_stats("garbage")
    assert capture.packets_written == 1


class FakeThread:
    def __init__(self, alive=True):
        self.alive = alive

    def is_alive(self):
        return self.alive


class FakeSniffer:
    """Fake AsyncSniffer that 'sniffs' canned packets when started."""

    packets: list = []
    fail: Exception | None = None
    instances: list["FakeSniffer"] = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.thread = None
        self.exception = None
        self.stopped = False
        FakeSniffer.instances.append(self)

    def start(self):
        if FakeSniffer.fail is not None:
            self.thread = FakeThread(alive=False)
            self.exception = FakeSniffer.fail
            return
        self.thread = FakeThread()
        self.kwargs["started_callback"]()
        lfilter = self.kwargs.get("lfilter")
        for pkt in FakeSniffer.packets:
            if lfilter is None or lfilter(pkt):
                self.kwargs["prn"](pkt)

    def stop(self, join=True):  # noqa: ARG002
        self.stopped = True
        self.thread.alive = False


def _sniffed(pkt, iface="eth0", t=100.0):
    pkt = Ether(bytes(pkt))
    pkt.sniffed_on = iface
    pkt.time = t
    return pkt


@pytest.fixture
def fake_sniffer(mocker):
    import scapy.sendrecv

    FakeSniffer.packets = []
    FakeSniffer.fail = None
    FakeSniffer.instances = []
    mocker.patch.object(scapy.sendrecv, "AsyncSniffer", FakeSniffer)
    mocker.patch.object(pcap, "capture_supported", return_value=(True, ""))
    return FakeSniffer


def test_scapy_backend(fake_sniffer, tmp_path, mocker):
    mocker.patch.object(pcap, "_bpf_error", return_value="")
    fake_sniffer.packets = [
        _sniffed(_eth() / IP(src="192.0.2.10", dst="192.0.2.20") / TCP(), "eth0", 100.0),
        _sniffed(_eth() / IP(src="192.0.2.20", dst="192.0.2.10") / TCP(), "eth1", 100.5),
    ]
    capture = pcap.TrafficCapture(tmp_path, ["eth0", "eth1"], bpf="host 192.0.2.20", tool="scapy")
    assert capture.start()
    assert capture.backend == "scapy"

    sniffer = fake_sniffer.instances[0]
    assert sniffer.kwargs["iface"] == ["eth0", "eth1"]
    assert sniffer.kwargs["filter"] == "host 192.0.2.20"
    assert sniffer.kwargs["promisc"] is False
    assert sniffer.kwargs["store"] is False
    assert "lfilter" not in sniffer.kwargs

    summary = capture.stop()
    assert sniffer.stopped
    assert summary["filter"] == "host 192.0.2.20"
    assert summary["python_filter"] is False
    assert summary["packets_written"] == 2
    assert summary["files"] == [(tmp_path / "peat-traffic.pcapng").as_posix()]

    read = rdpcap(summary["files"][0])
    assert len(read) == 2
    assert [p.sniffed_on for p in read] == ["eth0", "eth1"]
    assert [float(p.time) for p in read] == [100.0, 100.5]


def test_scapy_bpf_unavailable_uses_matcher(fake_sniffer, tmp_path, mocker):
    from scapy.arch import common

    mocker.patch.object(common, "compile_filter", side_effect=ImportError("no libpcap"))
    matcher = pcap.TargetMatcher([IPv4Network("192.0.2.20/32")])
    fake_sniffer.packets = [
        _sniffed(_eth() / IP(src="192.0.2.10", dst="192.0.2.20") / TCP()),
        _sniffed(_eth() / IP(src="192.0.2.10", dst="192.0.2.99") / TCP()),
    ]
    capture = pcap.TrafficCapture(tmp_path, ["eth0"], bpf="host 192.0.2.20", matcher=matcher)
    capture.tool = "scapy"
    assert capture.start()

    sniffer = fake_sniffer.instances[0]
    assert sniffer.kwargs["iface"] == "eth0"
    assert "filter" not in sniffer.kwargs
    assert sniffer.kwargs["lfilter"] is matcher
    summary = capture.stop()
    assert summary["packets_written"] == 1
    assert summary["filter"] == ""  # Not applied
    assert summary["python_filter"] is True


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (ImportError("no libpcap"), "libpcap is not installed"),
        (Exception("Failed to compile filter expression"), "invalid filter"),
    ],
)
def test_scapy_custom_filter_unavailable_warns(
    fake_sniffer, tmp_path, mocker, caplog, error, reason
):
    """A custom filter that can't be used is named in a warning, and isn't reported as applied."""
    from scapy.arch import common

    mocker.patch.object(common, "compile_filter", side_effect=error)
    mocker.patch.object(pcap, "route_interfaces", return_value=["eth0"])
    mocker.patch.dict(
        config["CONFIG"],
        {"CAPTURE_DIR": tmp_path, "CAPTURE_FILTER": "tcp port 502", "CAPTURE_TOOL": "scapy"},
    )
    capture = pcap.TrafficCapture.for_targets(["192.0.2.20"], "unicast_ip")
    assert capture.start()
    assert "Unable to use the capture filter 'tcp port 502'" in caplog.text
    assert reason in caplog.text
    assert "filtering traffic to or from the targets in Python" in caplog.text
    summary = capture.stop()
    assert summary["filter"] == ""
    assert summary["python_filter"] is True

    # Without a matcher, everything is captured
    caplog.clear()
    capture = pcap.TrafficCapture(tmp_path, ["eth0"], bpf="tcp port 502", tool="scapy")
    assert capture.start()
    assert "all traffic will be captured" in caplog.text
    assert "lfilter" not in fake_sniffer.instances[-1].kwargs
    assert capture.stop()["python_filter"] is False


def test_scapy_start_failure(fake_sniffer, tmp_path, caplog):
    fake_sniffer.fail = OSError("No such device")
    capture = pcap.TrafficCapture(tmp_path, ["eth9"], tool="scapy")
    assert not capture.start()
    assert "No such device" in caplog.text
    assert "No such device" in capture.error
    assert list(tmp_path.iterdir()) == []  # Partial file removed
    assert capture.stop()["files"] == []


def test_scapy_unsupported(tmp_path, mocker, caplog):
    mocker.patch.object(pcap, "capture_supported", return_value=(False, "no privileges"))
    capture = pcap.TrafficCapture(tmp_path, ["eth0"], tool="scapy")
    assert not capture.start()
    assert "Traffic capture disabled: no privileges" in caplog.text
    assert list(tmp_path.iterdir()) == []


def test_scapy_sniffer_died_during_capture(fake_sniffer, tmp_path, caplog):
    capture = pcap.TrafficCapture(tmp_path, ["eth0"], tool="scapy")
    assert capture.start()
    sniffer = fake_sniffer.instances[0]
    sniffer.thread.alive = False
    sniffer.exception = OSError("interface went down")
    summary = capture.stop()
    assert not sniffer.stopped
    assert "interface went down" in caplog.text
    # The file is still valid (empty capture)
    assert len(rdpcap(summary["files"][0])) == 0


def test_on_packet_never_raises(tmp_path, mocker):
    capture = pcap.TrafficCapture(tmp_path, ["eth0"])
    capture._on_packet(_sniffed(_eth() / IP() / TCP()))  # No writer: ignored

    from scapy.utils import PcapNgWriter

    capture._writer = PcapNgWriter(str(tmp_path / "test.pcapng"))
    capture._on_packet(_sniffed(_eth() / IP() / TCP()))
    assert capture.packets_written == 1

    capture._on_packet(Raw(b"unknown link type"))
    assert capture.packets_skipped == 1

    mocker.patch.object(capture._writer, "write_packet", side_effect=OSError("disk full"))
    capture._on_packet(_sniffed(_eth() / IP() / TCP()))
    capture._on_packet(_sniffed(_eth() / IP() / TCP()))
    assert capture.packets_skipped == 3
    capture._cleanup()


def test_loopback_dedupe(tmp_path):
    capture = pcap.TrafficCapture(tmp_path, ["lo"])
    capture._loopback_name = "lo"
    frame = _eth() / IP(src="127.0.0.1", dst="127.0.0.1") / TCP()
    assert not capture._is_loopback_dup(_sniffed(frame, "lo", 1.0))
    assert capture._is_loopback_dup(_sniffed(frame, "lo", 1.001))
    assert not capture._is_loopback_dup(_sniffed(frame, "lo", 1.002))  # Third copy is kept
    assert not capture._is_loopback_dup(_sniffed(frame, "lo", 2.0))
    assert not capture._is_loopback_dup(_sniffed(frame, "eth0", 2.0))
    assert not capture._is_loopback_dup(_sniffed(frame, "eth0", 2.0))


# ---------------------------------------------------------------------------
# Global capture lifecycle
# ---------------------------------------------------------------------------


class FakeCapture:
    def __init__(self, ok=True):
        self.ok = ok
        self.running = False
        self.stop_calls = 0

    def start(self):
        self.running = self.ok
        return self.ok

    def stop(self):
        self.stop_calls += 1
        self.running = False
        return self.summary()

    def summary(self):
        return {"tool": "scapy", "files": [], "error": "" if self.ok else "failed"}


def test_start_stop_traffic_capture(mocker):
    fake = FakeCapture()
    for_targets = mocker.patch.object(pcap.TrafficCapture, "for_targets", return_value=fake)
    register = mocker.patch.object(exit_handler, "register")
    unregister = mocker.patch.object(exit_handler, "unregister")

    assert pcap.start_traffic_capture(["192.0.2.1"], "unicast_ip") is fake
    for_targets.assert_called_once_with(["192.0.2.1"], "unicast_ip")
    register.assert_called_once_with(pcap.stop_traffic_capture, "FILE")
    assert state.traffic_capture["tool"] == "scapy"

    # Nested commands (e.g. pull calling scan) reuse the running capture
    assert pcap.start_traffic_capture(["192.0.2.1"], "unicast_ip") is fake
    assert for_targets.call_count == 1
    assert register.call_count == 1

    assert pcap.stop_traffic_capture() == fake.summary()
    unregister.assert_called_once_with(pcap.stop_traffic_capture, "FILE")
    assert pcap.stop_traffic_capture() == {}
    assert fake.stop_calls == 1


def test_start_traffic_capture_failures(mocker):
    register = mocker.patch.object(exit_handler, "register")

    mocker.patch.object(pcap.TrafficCapture, "for_targets", return_value=FakeCapture(ok=False))
    assert pcap.start_traffic_capture(["192.0.2.1"], "unicast_ip") is None
    assert state.traffic_capture["error"] == "failed"

    mocker.patch.object(pcap.TrafficCapture, "for_targets", side_effect=ValueError("bad"))
    assert pcap.start_traffic_capture(["192.0.2.1"], "unicast_ip") is None
    assert state.traffic_capture["error"] == "bad"

    mocker.patch.object(pcap.TrafficCapture, "for_targets", return_value=None)
    assert pcap.start_traffic_capture(["192.0.2.1"], "unicast_ip") is None

    register.assert_not_called()
    assert pcap.stop_traffic_capture() == {}


def test_for_targets(mocker, tmp_path, caplog):
    mocker.patch.object(pcap, "route_interfaces", return_value=["eth0"])
    mocker.patch.dict(config["CONFIG"], {"CAPTURE_DIR": tmp_path})

    capture = pcap.TrafficCapture.for_targets(["192.0.2.0/24", "198.51.100.1"], "unicast_ip")
    assert capture.out_dir == tmp_path
    assert capture.interfaces == ["eth0"]
    assert capture.tool == "auto"
    assert capture.bpf.startswith("(net 192.0.2.0/24 or host 198.51.100.1) or icmp")
    assert isinstance(capture.matcher, pcap.TargetMatcher)

    mocker.patch.dict(
        config["CONFIG"],
        {"CAPTURE_FILTER": "", "CAPTURE_INTERFACES": ["eth1"], "CAPTURE_TOOL": "scapy"},
    )
    capture = pcap.TrafficCapture.for_targets(["192.0.2.1"], "unicast_ip")
    assert capture.bpf is None
    assert capture.matcher is None
    assert capture.interfaces == ["eth1"]
    assert capture.tool == "scapy"

    mocker.patch.dict(config["CONFIG"], {"CAPTURE_FILTER": "tcp port 502"})
    capture = pcap.TrafficCapture.for_targets(["192.0.2.1"], "unicast_ip")
    assert capture.bpf == "tcp port 502"
    assert capture.matcher is not None

    # Too many networks for a filter: capture everything, with a warning
    mocker.patch.dict(config["CONFIG"], {"CAPTURE_FILTER": "auto"})
    many = [f"{i}.0.0.1" for i in range(1, 160, 2)]
    capture = pcap.TrafficCapture.for_targets(many, "unicast_ip")
    assert capture.bpf is None
    assert "Too many target networks" in caplog.text

    assert pcap.TrafficCapture.for_targets(["/dev/ttyS0"], "serial") is None


def test_for_targets_capture_dir_unset(mocker, caplog):
    for value in ["", None]:
        mocker.patch.dict(config["CONFIG"], {"CAPTURE_DIR": value})
        assert pcap.TrafficCapture.for_targets(["192.0.2.1"], "unicast_ip") is None
    assert "CAPTURE_DIR is unset" in caplog.text


@pytest.mark.usefixtures("fake_sniffer")
def test_context_manager(tmp_path):
    with pcap.TrafficCapture(tmp_path, ["eth0"], tool="scapy") as capture:
        assert capture.running
    assert not capture.running
    assert capture.summary()["files"]


LIVE = pytest.mark.skipif(
    not (consts.LINUX and hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="requires root on Linux",
)


@pytest.mark.slow
@LIVE
@pytest.mark.parametrize("tool", ["scapy", "tcpdump"])
def test_live_capture_loopback(tmp_path, mocker, tool):
    """
    Real capture of TCP and UDP traffic on the loopback interface.

    The capture is stopped right after the last packet is sent, so packets
    that are still in flight must not be lost.
    """
    if tool == "tcpdump" and not consts.SYSINFO.get("tcpdump"):
        pytest.skip("tcpdump is not installed")
    mocker.patch.multiple(pcap, **DRAIN)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    udp_port = receiver.getsockname()[1]
    matcher = pcap.TargetMatcher([IPv4Network("127.0.0.1/32")])

    bpf = f"host 127.0.0.1 and (port {port} or port {udp_port})"
    capture = pcap.TrafficCapture(tmp_path, ["lo"], bpf, matcher, tool=tool)
    assert capture.start(), capture.error
    try:

        def _serve():
            conn, _ = server.accept()
            conn.sendall(conn.recv(1024)[::-1])
            conn.close()

        thread = threading.Thread(target=_serve, daemon=True)
        thread.start()
        with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
            client.sendall(b"PEAT-LIVE-CAPTURE")
            assert client.recv(1024) == b"ERUTPAC-EVIL-TAEP"
        thread.join(5)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            for i in range(50):
                sender.sendto(b"PEAT-UDP-%03d" % i, ("127.0.0.1", udp_port))
    finally:
        summary = capture.stop()  # Immediately after sending
        server.close()
        receiver.close()

    packets = rdpcap(summary["files"][0])
    payloads = [_tcp_payload(p) for p in packets if TCP in p]
    assert payloads.count(b"PEAT-LIVE-CAPTURE") == 1
    assert payloads.count(b"ERUTPAC-EVIL-TAEP") == 1
    assert any(p[TCP].flags.F for p in packets if TCP in p)  # Teardown was captured
    udp = [bytes(p[UDP].payload) for p in packets if UDP in p and ICMP not in p]
    assert sorted(udp) == [b"PEAT-UDP-%03d" % i for i in range(50)]
    assert Path(summary["files"][0]).suffix == (".pcap" if tool == "tcpdump" else ".pcapng")
