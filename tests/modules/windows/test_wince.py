"""
Windows CE pillage results (synthetic, in the shape the module reads).
"""

import json
from pathlib import PureWindowsPath

import pytest

from peat import config, datastore
from peat.modules.windows import wince
from peat.modules.windows.wince import WindowsCE

PILLAGE = {
    "ip": "192.0.2.60",
    "OS Version": "7.0",
    "network_interfaces": [
        {
            "ip": "192.0.2.60",
            "mac": "00:00:5E:00:53:60",
            "name": "ENET1",
            "subnet_mask": "255.255.255.0",
            "gateway": "192.0.2.1",
        }
    ],
    "file_list": [
        {"Name": "\\Windows\\HmiRTm.exe", "Type": "File", "SHA256": "AB" * 32, "Size": 1024},
        {"Name": "\\Flash\\Simatic", "Type": "Directory"},
    ],
    "network_sockets": {
        "TCP Sockets": [
            {"state": "LISTEN", "Local Port": 44818},
            {"state": "LISTEN", "Local Port": 21},
            {
                "state": "ESTABLISHED",
                "Local Address": "192.0.2.60",
                "Local Port": 44818,
                "Remote Address": "192.0.2.10",
                "Remote Port": 50001,
            },
            {
                "state": "ESTABLISHED",
                "Local Address": "192.0.2.60",
                "Local Port": 44818,
                "Remote Address": "192.0.2.10",
                "Remote Port": 50002,
            },
            {"state": "TIME_WAIT", "Local Port": 1050, "Remote Address": "192.0.2.20"},
            {"state": "CLOSED", "Local Port": 1051},
        ],
        "UDP Sockets": [{"Local Port": 161}, {"Local Port": 50000}],
    },
    "process_list": [
        {
            "Process Name": "HmiRTm.exe",
            "PID": "0x0A1B",
            "modules": [{"Module Name": "coredll.dll"}],
            "Threads": 4,
        },
        {"Process Name": "nk.exe"},
    ],
    "HKEY_CLASSES_ROOT": [{"Key Name": "\\HKCR\\x", "Key Values": []}],
    "HKEY_USERS": [{"Key Name": "\\HKU\\y", "Key Values": []}],
}


@pytest.fixture
def parsed(mocker, tmp_path):
    mocker.patch.dict(
        config["CONFIG"],
        {"DEVICE_DIR": tmp_path / "devices", "TEMP_DIR": tmp_path / "temp"},
    )
    mocker.patch.object(datastore, "objects", [])
    source = tmp_path / "pillage-results.json"
    source.write_text(json.dumps(PILLAGE))
    return WindowsCE.parse(source)


def test_processes(parsed):
    assert "process_list" not in parsed.extra
    procs = {p.name: p for p in parsed.processes}
    assert set(procs) == {"HmiRTm.exe", "nk.exe"}

    hmi = procs["HmiRTm.exe"]
    assert hmi.type == "process"
    assert hmi.pid == 0x0A1B
    assert hmi.extra == {"modules": [{"Module Name": "coredll.dll"}], "threads": 4}
    assert procs["nk.exe"].pid is None
    assert {"HmiRTm.exe", "nk.exe"} <= parsed.related.process
    assert "coredll.dll" in parsed.related.files


def test_files(parsed):
    assert "file_list" not in parsed.extra
    files = {f.name: f for f in parsed.files}
    assert set(files) == {"HmiRTm.exe", "Simatic"}

    exe = files["HmiRTm.exe"]
    assert exe.path == PureWindowsPath("\\Windows\\HmiRTm.exe")
    assert exe.type == "file"
    assert exe.extension == "exe"
    assert exe.hash.sha256 == "AB" * 32
    assert exe.extra == {"size": 1024}
    assert files["Simatic"].type == "dir"
    assert "AB" * 32 in parsed.related.hash


def test_sockets(parsed):
    # LISTEN sockets are services, the others relationships
    ports = {(s.port, s.transport) for s in parsed.service}
    assert {(44818, "tcp"), (21, "tcp"), (161, "udp")} <= ports
    # Only sockets that aren't services or relationships stay in extra
    assert parsed.extra["network_sockets"] == {
        "TCP Sockets": [{"Local Port": 1051, "state": "CLOSED"}],  # no remote address
        "UDP Sockets": [{"Local Port": 50000}],
    }

    rels = {r.remote.ip: r for r in parsed.relationships}
    assert set(rels) == {"192.0.2.10", "192.0.2.20"}

    cip = rels["192.0.2.10"]
    assert cip.evidence == {"netstat"}
    assert cip.direction == "ingress"  # the device listens on 44818
    assert cip.protocol == "cip"
    assert cip.local.port == 44818
    assert cip.count == 2  # two sessions of the same client
    assert cip.state == "established"

    assert rels["192.0.2.20"].state == "time_wait"
    assert rels["192.0.2.20"].remote.port is None


def test_registry_hives(parsed):
    """Bug fix: HKEY_CLASSES_ROOT was copied twice and HKEY_USERS never."""
    assert parsed.extra["HKEY_CLASSES_ROOT"] == PILLAGE["HKEY_CLASSES_ROOT"]
    assert parsed.extra["HKEY_USERS"] == PILLAGE["HKEY_USERS"]


def test_helpers():
    assert wince.process_from_pillage({}) is None
    assert wince.file_from_pillage({"Type": "File"}) is None
    assert wince.connection_from_socket({"Remote Address": "0.0.0.0"}, "tcp") is None
    proc = wince.process_from_pillage({"Process Name": "x.exe", "PID": "abc"})
    assert proc.pid is None
    assert proc.extra == {"pid_raw": "abc"}


def test_extra_keys():
    """Multi-word keys of the pillage results are snake_case extra keys."""
    proc = wince.process_from_pillage(
        {"Process Name": "x.exe", "Base Address": "0x10000", "HeapSize": 4, "CPU Time": 1}
    )
    assert proc.extra == {"base_address": "0x10000", "heap_size": 4, "cpu_time": 1}
    file_obj = wince.file_from_pillage(
        {"Name": "\\A\\b.txt", "Type": "File", "Last Write Time": "t", "Size (KB)": 1}
    )
    assert file_obj.extra == {"last_write_time": "t", "size_kb": 1}
