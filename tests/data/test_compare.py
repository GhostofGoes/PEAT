import json
from copy import deepcopy
from datetime import datetime
from itertools import cycle
from pathlib import Path, PurePath

import pytest
from deepdiff import DeepDiff

from peat import SCEPTRE, config, datastore
from peat.data.compare import (
    DEFAULT_COMPARE_EXCLUDES,
    MAX_DEPTH,
    Change,
    DeviceDiff,
    _quote,
    compare_device_data,
)
from peat.data.models import (
    DeviceData,
    Event,
    File,
    Interface,
    Memory,
    Register,
    Service,
    SSHKey,
    Tag,
    User,
)


def _paths(diff: DeviceDiff) -> list[tuple[str, str]]:
    return [(c.kind, c.path) for c in diff.changes]


def _file_sel(path: str) -> str:
    """Selector for a ``File.path`` set on a model.

    ``File.path`` is a ``PurePath``, so on Windows ``/etc/passwd`` is stored
    and exported as ``\\etc\\passwd``, which the path then quotes.
    """
    return f"files[path={_quote(str(PurePath(path)))}]"


@pytest.fixture
def make_device():
    def _make(firmware_version: str = "1.0", reverse: bool = False) -> DeviceData:
        dev = DeviceData(ip="192.0.2.10", name="plc-1", uptime=100)
        dev.firmware.version = firmware_version
        dev.description.vendor.id = "ACME"

        interfaces = [
            Interface(name="eth0", type="ethernet", ip="192.0.2.10", mac="00:00:5E:00:53:01"),
            Interface(name="eth1", type="ethernet", ip="192.0.2.11"),
        ]
        services = [
            Service(port=21, protocol="ftp", transport="tcp"),
            Service(port=502, protocol="modbus_tcp", transport="tcp"),
        ]
        registers = [
            Register(protocol="modbus_tcp", address="40001", name="speed"),
            Register(protocol="modbus_tcp", address="40002", name="temp"),
        ]
        if reverse:
            interfaces.reverse()
            services.reverse()
            registers.reverse()

        # Assign lists directly, store() would reorder/merge them
        dev.interface = interfaces
        dev.service = services
        dev.registers = registers
        return dev

    return _make


def test_identical_devices_are_same(make_device):
    diff = make_device().compare(make_device())

    assert isinstance(diff, DeviceDiff)
    assert diff.is_same
    assert diff.changes == []
    assert diff.similarity == 1.0
    assert diff.same_values > 0
    assert diff.different_values == 0
    assert diff.format() == "No differences"
    assert diff.summary()["is_same"] is True


def test_empty_data_is_same():
    diff = compare_device_data({}, {})
    assert diff.is_same
    assert diff.similarity == 1.0
    assert diff.same_values == 0


def test_reordered_lists_are_same(make_device):
    old = make_device()
    new = make_device(reverse=True)

    assert old.compare(new).is_same

    # Cross-check with DeepDiff, ignoring order
    assert DeepDiff(old.export(), new.export(), ignore_order=True) == {}

    # Positional comparison reports the reordering
    positional = old.compare(new, ignore_order=False)
    assert not positional.is_same
    assert ("changed", "registers[0].name") in _paths(positional)


def test_config_drift_between_pulls(make_device):
    old = make_device()
    new = make_device(firmware_version="1.1")
    new.uptime = 99999  # excluded by default
    new.interface[1].ip = "192.0.2.12"
    new.service = [
        Service(port=21, protocol="ftp", transport="tcp"),
        Service(port=23, protocol="telnet", transport="tcp"),
    ]
    new.registers[0].name = "velocity"

    diff = old.compare(new)

    assert not diff.is_same
    assert _paths(diff) == [
        ("changed", "firmware.version"),
        ("changed", "interface[name=eth1].ip"),
        ("removed", "service[port=502,protocol=modbus_tcp,transport=tcp]"),
        ("added", "service[port=23,protocol=telnet,transport=tcp]"),
        ("changed", "registers[protocol=modbus_tcp,address=40001].name"),
    ]
    assert diff.changes[0] == Change(kind="changed", path="firmware.version", old="1.0", new="1.1")
    assert diff.changes[1].old == "192.0.2.11"
    assert diff.changes[1].new == "192.0.2.12"
    assert diff.changes[2].old == {"port": 502, "protocol": "modbus_tcp", "transport": "tcp"}
    assert diff.changes[2].new is None
    assert diff.changes[3].old is None
    assert diff.changes[3].new == {"port": 23, "protocol": "telnet", "transport": "tcp"}

    assert [c.path for c in diff.added] == ["service[port=23,protocol=telnet,transport=tcp]"]
    assert [c.path for c in diff.removed] == [
        "service[port=502,protocol=modbus_tcp,transport=tcp]"
    ]
    assert len(diff.changed) == 3
    assert 0.0 < diff.similarity < 1.0

    summary = diff.summary()
    assert summary["total_changes"] == 5
    assert (summary["added"], summary["removed"], summary["changed"]) == (1, 1, 3)


def test_direction_is_reversed(make_device):
    old = make_device()
    new = make_device()
    new.service.append(Service(port=80, protocol="http", transport="tcp"))

    forward = old.compare(new)
    backward = new.compare(old)

    assert [c.path for c in forward.added] == ["service[port=80,protocol=http,transport=tcp]"]
    assert forward.removed == []
    assert [c.path for c in backward.removed] == ["service[port=80,protocol=http,transport=tcp]"]
    assert backward.added == []
    assert forward.similarity == backward.similarity


def test_compare_to_baseline_file(make_device, mocker, tmp_path):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})
    dev = make_device()
    dev.logic.original = "raw logic"
    assert dev.export_to_files() is True

    baseline_path = next(tmp_path.rglob("device-data-full.json"))
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    assert "created" in baseline  # file timestamp is ignored

    assert dev.compare(baseline).is_same
    assert dev.compare(baseline, include_original=True).is_same

    dev.firmware.version = "2.0"
    assert _paths(dev.compare(baseline)) == [("changed", "firmware.version")]


def test_compare_to_summary_file(make_device, mocker, tmp_path):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})
    dev = make_device()
    dev.tag = [Tag(name="T1", address="1")]
    dev.files = [File(path="/etc/hosts", hash={"sha256": "c" * 64})]
    assert dev.export_to_files() is True

    summary_path = next(tmp_path.rglob("device-data-summary.json"))
    summary = json.loads(summary_path.read_text(encoding="utf-8"))

    # Summaries leave out some fields, which then show up as removed
    assert _paths(dev.compare(summary)) == [
        ("removed", "files"),
        ("removed", "registers"),
        ("removed", "tag"),
    ]
    assert dev.compare(summary, exclude=["registers", "tag", "io", "files", "raw-values"]).is_same

    dev.firmware.version = "2.0"
    assert _paths(dev.compare(summary, exclude=["registers", "tag", "files"])) == [
        ("changed", "firmware.version")
    ]


@pytest.mark.parametrize(
    "extra",
    [
        {"rows": [{"a": ""}, {"b": 1}]},  # becomes empty only after stripping
        {"slots": {0: {"name": "cpu"}, 1: {"name": "io"}}},  # keys that are not strings
        {"values": (1, 2.5, None, True), "nested": [[{"x": None}], [1]]},
        {"when": datetime(2024, 1, 2, 3, 4, 5), "raw": b"\x00\xff"},
    ],
)
def test_device_is_same_as_its_json_export(extra):
    dev = DeviceData(ip="192.0.2.20", name="rtu")
    dev.extra = extra
    exported = json.loads(json.dumps(dev.export()))

    assert dev.compare(exported).is_same
    assert compare_device_data(exported, dev).is_same
    assert compare_device_data(dev.export(), exported).is_same


def test_dict_inputs_are_normalized():
    old = {"name": "plc", "hostname": "", "os": {}, "extra": {"a": None}, "_private": 1}
    new = {"name": "plc", "users": [{"name": "admin", "roles": {"write", "read"}}]}
    diff = compare_device_data(old, new)
    assert _paths(diff) == [("added", "users")]
    assert diff.changes[0].new == [{"name": "admin", "roles": ["read", "write"]}]


@pytest.mark.parametrize("bad", [None, "device-data-full.json", Path("x.json"), [1, 2], 5])
def test_invalid_input_types(bad):
    with pytest.raises(TypeError):
        compare_device_data({}, bad)
    with pytest.raises(TypeError):
        compare_device_data(bad, {})
    with pytest.raises(TypeError):
        DeviceData().compare(bad)


def test_interface_matching_by_mac_and_ip():
    old = {"interface": [{"mac": "00:00:5E:00:53:01", "ip": "192.0.2.1"}, {"ip": "192.0.2.9"}]}
    new = {
        "interface": [
            {"ip": "192.0.2.9", "speed": 100},
            {"mac": "00:00:5E:00:53:01", "ip": "192.0.2.2"},
        ]
    }
    diff = compare_device_data(old, new)
    assert _paths(diff) == [
        ("changed", "interface[mac=00:00:5E:00:53:01].ip"),
        ("added", "interface[ip=192.0.2.9].speed"),
    ]


def test_service_identity_keys():
    # A different protocol on the same port is a different service
    old = {"service": [{"port": 80, "protocol": "http", "transport": "tcp"}]}
    new = {"service": [{"port": 80, "protocol": "https", "transport": "tcp"}]}
    assert _paths(compare_device_data(old, new)) == [
        ("removed", "service[port=80,protocol=http,transport=tcp]"),
        ("added", "service[port=80,protocol=https,transport=tcp]"),
    ]

    # Fall back to the port if the protocol is only known in one of them
    old = {"service": [{"port": 8080, "transport": "tcp"}]}
    new = {"service": [{"port": 8080, "transport": "tcp", "protocol": "http"}]}
    diff = compare_device_data(old, new)
    assert _paths(diff) == [("added", "service[port=8080,transport=tcp].protocol")]
    assert diff.changes[0].new == "http"

    # The same port and protocol with different transports are different services
    old = {
        "service": [
            {"port": 53, "protocol": "dns", "transport": "tcp"},
            {"port": 53, "protocol": "dns", "transport": "udp"},
        ]
    }
    new = {"service": [{"port": 53, "protocol": "dns", "transport": "udp", "status": "open"}]}
    assert _paths(compare_device_data(old, new)) == [
        ("removed", "service[port=53,protocol=dns,transport=tcp]"),
        ("added", "service[port=53,protocol=dns,transport=udp].status"),
    ]


def test_nested_interface_services(make_device):
    old = make_device()
    new = make_device()
    old.interface[0].services = [Service(port=102, protocol="s7comm", transport="tcp")]
    new.interface[0].services = [Service(port=102, protocol="s7comm", status="open")]

    diff = old.compare(new)
    assert _paths(diff) == [
        ("removed", "interface[name=eth0].services[port=102,protocol=s7comm].transport"),
        ("added", "interface[name=eth0].services[port=102,protocol=s7comm].status"),
    ]


def test_registers_matched_by_group():
    old = {
        "registers": [
            {"protocol": "dnp3", "group": "1", "address": "0", "name": "breaker"},
            {"protocol": "dnp3", "group": "30", "address": "0", "name": "amps"},
        ]
    }
    new = {
        "registers": [
            {"protocol": "dnp3", "group": "30", "address": "0", "name": "current"},
            {"protocol": "dnp3", "group": "1", "address": "0", "name": "breaker"},
        ]
    }
    diff = compare_device_data(old, new)
    assert _paths(diff) == [("changed", "registers[protocol=dnp3,group=30,address=0].name")]


def test_registers_with_the_same_address_and_different_types(examples_path, mocker, tmp_path):
    # Real config with DNP3 analog and binary points at the same addresses
    mocker.patch.dict(
        config["CONFIG"], {"DEVICE_DIR": tmp_path / "devices", "TEMP_DIR": tmp_path / "temp"}
    )
    mocker.patch.object(datastore, "objects", [])
    dev = SCEPTRE.parse(examples_path("devices/sceptre/soap/rtu-1_config.xml"))
    old = dev.export()
    new = deepcopy(old)

    regs = new["registers"]
    analog = [r for r in regs if r["address"] == "0" and r["measurement_type"] == "analog"]
    binary = [r for r in regs if r["address"] == "0" and r["measurement_type"] == "binary"]
    assert len(analog) == 1
    assert len(binary) == 1
    regs.remove(analog[0])
    binary[0]["tag"] += "_renamed"

    diff = compare_device_data(old, new)
    assert _paths(diff) == [
        ("removed", "registers[protocol=dnp3,measurement_type=analog,address=0]"),
        ("changed", "registers[protocol=dnp3,measurement_type=binary,address=0].tag"),
    ]
    assert diff.changes[0].old == analog[0]
    assert diff.changes[1].new == binary[0]["tag"]

    assert compare_device_data(old, deepcopy(old)).is_same


@pytest.mark.parametrize(
    ("field", "old_items", "new_items", "expected"),
    [
        (
            "registers",
            [{"protocol": "dnp3", "group": "1", "address": "0", "name": "breaker_status"}],
            [{"protocol": "dnp3", "group": "30", "address": "0", "name": "phase_a_amps"}],
            [
                ("removed", "registers[protocol=dnp3,group=1,address=0]"),
                ("added", "registers[protocol=dnp3,group=30,address=0]"),
            ],
        ),
        (
            "interface",
            [{"name": "eth0", "ip": "192.0.2.5", "type": "ethernet"}],
            [{"name": "wlan0", "ip": "192.0.2.5", "type": "wifi"}],
            [("removed", "interface[name=eth0]"), ("added", "interface[name=wlan0]")],
        ),
        (
            "users",
            [{"name": "admin", "id": "1", "roles": ["admin"]}],
            [{"name": "operator", "id": "1", "roles": ["view"]}],
            [("removed", "users[name=admin]"), ("added", "users[name=operator]")],
        ),
        (
            "files",
            [{"path": "/etc/app/config.xml", "name": "config.xml", "hash": {"sha256": "A"}}],
            [{"path": "/var/www/config.xml", "name": "config.xml", "hash": {"sha256": "B"}}],
            [
                ("removed", "files[path=/etc/app/config.xml]"),
                ("added", "files[path=/var/www/config.xml]"),
            ],
        ),
    ],
)
def test_conflicting_identities_are_not_paired(field, old_items, new_items, expected):
    assert _paths(compare_device_data({field: old_items}, {field: new_items})) == expected


def test_lower_priority_keys_used_if_higher_key_is_unset_in_one():
    old = {"users": [{"id": "1", "roles": ["admin"]}]}
    new = {"users": [{"name": "operator", "id": "1", "roles": ["view"]}]}
    assert _paths(compare_device_data(old, new)) == [
        ("changed", "users[id=1].roles"),
        ("added", "users[id=1].name"),
    ]


def test_files_matched_by_path_and_host_fields_excluded():
    old = DeviceData()
    new = DeviceData()
    old.files = [
        File(
            path="/etc/passwd",
            mtime="2024-01-01T00:00:00",
            created="2024-01-01T00:00:00",
            local_path="/tmp/run1/passwd",
            hash={"sha256": "a" * 64},
        ),
        File(path="/etc/hosts", hash={"sha256": "c" * 64}),
    ]
    new.files = [
        File(path="/etc/hosts", hash={"sha256": "c" * 64}),
        File(
            path="/etc/passwd",
            mtime="2025-06-01T00:00:00",
            created="2025-06-01T00:00:00",
            local_path="/tmp/run2/passwd",
            hash={"sha256": "b" * 64},
        ),
    ]

    diff = old.compare(new)
    assert _paths(diff) == [("changed", f"{_file_sel('/etc/passwd')}.hash.sha256")]

    all_diff = old.compare(new, use_default_excludes=False)
    paths = [c.path for c in all_diff.changes]
    assert f"{_file_sel('/etc/passwd')}.mtime" in paths
    assert f"{_file_sel('/etc/passwd')}.local_path" in paths


def test_default_excludes(make_device):
    old = make_device()
    new = make_device()
    new.uptime = 5000
    new.successful_pulls["http"] = True
    new.related.ip.add("198.51.100.1")
    new.store("event", Event(message="login", dataset="log", sequence=1))
    new.store("memory", Memory(address="10", value="ff"))
    new.interface[0].uptime = 30

    assert old.compare(new).is_same

    paths = [c.path for c in old.compare(new, use_default_excludes=False).changes]
    for expected in ("uptime", "successful_pulls", "event", "memory"):
        assert expected in paths
    assert "related.ip" in paths
    assert "interface[name=eth0].uptime" in paths

    assert "uptime" in DEFAULT_COMPARE_EXCLUDES


def test_include(make_device):
    old = make_device()
    new = make_device(firmware_version="9.9")
    new.name = "renamed"
    new.interface[0].ip = "192.0.2.99"
    new.interface[0].mtu = 9000

    assert _paths(old.compare(new, include=["firmware"])) == [("changed", "firmware.version")]
    assert _paths(old.compare(new, include="name")) == [("changed", "name")]
    assert _paths(old.compare(new, include="firmware.version")) == [
        ("changed", "firmware.version")
    ]
    assert _paths(old.compare(new, include=["interface.ip", "name"])) == [
        ("changed", "name"),
        ("changed", "interface[name=eth0].ip"),
    ]
    assert old.compare(new, include="description.vendor").is_same

    # Identity keys are used even if they are not included
    swapped = make_device()
    swapped.interface[0].ip, swapped.interface[1].ip = "192.0.2.11", "192.0.2.10"
    assert _paths(old.compare(swapped, include="interface.ip")) == [
        ("changed", "interface[name=eth0].ip"),
        ("changed", "interface[name=eth1].ip"),
    ]

    # Fields that are only in exported data (e.g. from a newer version of PEAT)
    assert not compare_device_data({"new_field": 1}, {"new_field": 2}, include="new_field").is_same


@pytest.mark.parametrize(
    "include", [[], "", "interfaces", "Firmware", "firmware.vers", "firmware.", "a\x1b[0m"]
)
def test_invalid_include(make_device, include):
    with pytest.raises(ValueError, match="include") as exc_info:
        make_device().compare(make_device(), include=include)
    assert "\x1b" not in str(exc_info.value)


@pytest.mark.parametrize(
    ("pattern", "remaining"),
    [
        ("ip", ["interface[name=eth0].mtu", "extra.vendor.notes"]),
        ("interface.*", ["extra.vendor.ip", "extra.vendor.notes"]),
        ("*.notes", ["interface[name=eth0].ip", "interface[name=eth0].mtu", "extra.vendor.ip"]),
        ("extra", ["interface[name=eth0].ip", "interface[name=eth0].mtu"]),
        (["mtu", "extra.vendor"], ["interface[name=eth0].ip"]),
    ],
)
def test_exclude_patterns(pattern, remaining):
    old = {
        "interface": [{"name": "eth0", "ip": "192.0.2.1", "mtu": 1500}],
        "extra": {"vendor": {"ip": "192.0.2.1", "notes": "a"}},
    }
    new = {
        "interface": [{"name": "eth0", "ip": "192.0.2.2", "mtu": 9000}],
        "extra": {"vendor": {"ip": "192.0.2.2", "notes": "b"}},
    }
    diff = compare_device_data(old, new, exclude=pattern)
    assert [c.path for c in diff.changes] == remaining


def test_excluded_fields_pruned_from_added_values():
    old = {"interface": [{"name": "eth0"}]}
    new = {"interface": [{"name": "eth0"}, {"name": "eth1", "uptime": "1:00:00", "ip": "x"}]}
    diff = compare_device_data(old, new)
    assert _paths(diff) == [("added", "interface[name=eth1]")]
    assert diff.changes[0].new == {"name": "eth1", "ip": "x"}


def test_original_excluded_by_default():
    old = {"logic": {"original": "aaa", "hash": {"md5": "1"}}, "event": []}
    new = {"logic": {"original": "bbb", "hash": {"md5": "2"}}}
    assert _paths(compare_device_data(old, new)) == [("changed", "logic.hash.md5")]
    assert _paths(compare_device_data(old, new, include_original=True)) == [
        ("changed", "logic.original"),
        ("changed", "logic.hash.md5"),
    ]


def test_scalar_lists_compared_as_sets():
    old = {"users": [{"name": "admin", "roles": ["read", "write"]}]}
    same = {"users": [{"name": "admin", "roles": ["write", "read"]}]}
    new = {"users": [{"name": "admin", "roles": ["read"]}]}

    assert compare_device_data(old, same).is_same
    assert not compare_device_data(old, same, ignore_order=False).is_same

    diff = compare_device_data(old, new)
    assert _paths(diff) == [("changed", "users[name=admin].roles")]
    assert diff.changes[0].old == ["read", "write"]
    assert diff.changes[0].new == ["read"]


def test_users_matched_by_domain_and_name():
    old = DeviceData()
    new = DeviceData()
    old.users = [User(name="admin", domain="A"), User(name="admin", domain="B", uid="1")]
    new.users = [User(name="admin", domain="B", uid="2"), User(name="admin", domain="A")]
    assert _paths(old.compare(new)) == [("changed", "users[domain=B,name=admin].uid")]


@pytest.mark.parametrize(
    ("old_value", "new_value", "same"),
    [
        (1, 1.0, True),
        (1, True, False),
        (0, False, False),
        (float("nan"), float("nan"), True),
        ("1", 1, False),
        (None, 0, False),
        ({"a": 1}, [1], False),
    ],
)
def test_value_equality(old_value, new_value, same):
    diff = compare_device_data({"extra": {"v": old_value}}, {"extra": {"v": new_value}})
    assert diff.is_same is same


def test_duplicate_identities_paired_in_order():
    old = {"tag": [{"name": "T1", "address": "1"}]}
    new = {"tag": [{"name": "T1", "address": "1"}, {"name": "T1", "address": "2"}]}
    assert _paths(compare_device_data(old, new)) == [("added", "tag[name=T1,index=1]")]

    # The paths of items with the same identity include their index
    old = {"tag": [{"name": "T1", "address": "1"}, {"name": "T1", "address": "2"}]}
    new = {"tag": [{"name": "T1", "address": "1"}, {"name": "T1", "address": "3"}]}
    assert _paths(compare_device_data(old, new)) == [("changed", "tag[name=T1,index=1].address")]


def test_unkeyed_lists_use_index():
    old = {"extra": {"rows": [{"a": 1}, {"a": 2}]}}
    new = {"extra": {"rows": [{"a": 2}, {"a": 3}]}}
    diff = compare_device_data(old, new)
    assert _paths(diff) == [("removed", "extra.rows[0]"), ("added", "extra.rows[1]")]


def test_sub_modules():
    old = DeviceData(ip="192.0.2.1")
    new = DeviceData(ip="192.0.2.1")
    old.module = [
        DeviceData(slot="1", name="cpu", firmware={"version": "1"}),
        DeviceData(slot="2", name="io"),
    ]
    new.module = [
        DeviceData(slot="2", name="io"),
        DeviceData(slot="1", name="cpu", firmware={"version": "2"}),
    ]
    new.module[0].files = [File(path="/a", mtime="2025-01-01T00:00:00")]
    old.module[1].files = [File(path="/a", mtime="2024-01-01T00:00:00")]

    diff = old.compare(new)
    assert _paths(diff) == [("changed", "module[slot=1].firmware.version")]


def test_untrusted_values_are_escaped():
    evil = "eth0\x1b[31m]=x,y\n"
    old = {"interface": [{"name": evil, "ip": "192.0.2.1"}], "extra": {"a b]": 1}}
    new = {"interface": [{"name": evil, "ip": "192.0.2.2"}], "extra": {"a b]": 2}}
    diff = compare_device_data(old, new)

    assert _paths(diff) == [
        ("changed", 'interface[name="eth0\\u001b[31m]=x,y\\n"].ip'),
        ("changed", 'extra["a b]"]'),
    ]
    text = diff.format()
    assert "\x1b" not in text
    assert "\n" not in text.replace("\n~", "")

    long_name = "n" * 500
    diff = compare_device_data({"tag": [{"name": long_name}]}, {})
    assert len(diff.changes[0].path) < 100

    # Non-ASCII is escaped in the text output, values keep the original data
    diff = compare_device_data({"name": "r\xe9sum\xe9"}, {"name": "resume\u0301\u202e"})
    assert diff.changes[0].new == "resume\u0301\u202e"
    assert diff.format().isascii()


def test_format_limits():
    old = {"extra": {"keep": 1} | {f"k{i}": "x" * 500 for i in range(5)}}
    diff = compare_device_data(old, {"extra": {"keep": 1}})
    lines = diff.format(max_changes=2, max_value_length=20).splitlines()
    assert len(lines) == 3
    assert lines[0] == '- extra.k0: "xxxxxxxxxxxxxxxx...'
    assert lines[-1] == "... and 3 more changes"
    assert len(diff.format().splitlines()) == 5
    assert diff.format(max_changes=0).splitlines() == ["... and 5 more changes"]

    changed = compare_device_data({"name": "a"}, {"name": "b"})
    assert changed.format() == '~ name: "a" -> "b"'


def test_deeply_nested_data_is_bounded():
    def nest(depth: int, leaf: str) -> dict:
        value: dict = {"leaf": leaf}
        for _ in range(depth):
            value = {"n": value}
        return value

    old = {"extra": nest(MAX_DEPTH + 50, "a")}
    new = {"extra": nest(MAX_DEPTH + 50, "b")}
    diff = compare_device_data(old, new)
    assert len(diff.changes) == 1
    assert diff.changes[0].kind == "changed"

    assert compare_device_data(old, old).is_same

    # Deeper than what can be loaded from JSON or exported
    too_deep = {"extra": nest(5000, "a")}
    with pytest.raises(ValueError, match="nested too deeply"):
        compare_device_data(too_deep, {})


def test_export_is_json_serializable(make_device):
    old = make_device()
    new = make_device(firmware_version="2")
    new.service.append(Service(port=80, protocol="http"))

    exported = old.compare(new).export()
    round_tripped = json.loads(json.dumps(exported))
    assert round_tripped["summary"]["total_changes"] == 2
    assert round_tripped["changes"][0] == {
        "kind": "changed",
        "path": "firmware.version",
        "old": "1.0",
        "new": "2",
    }


def test_mixed_key_types_in_lists():
    old = {"extra": {"rows": [{1: "a", "b": 2}, {"c": 3}]}}
    new = {"extra": {"rows": [{"c": 3}, {"1": "a", "b": 2}]}}  # keys are compared as JSON
    assert compare_device_data(old, new).is_same
    assert _paths(compare_device_data(old, {"extra": {"rows": [{1: "z", "b": 2}]}})) == [
        ("removed", "extra.rows[0]"),
        ("removed", "extra.rows[1]"),
        ("added", "extra.rows[0]"),
    ]


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (
            {"module": [{"description": {"model": "1756-EN2T"}, "uptime": "1:00:00"}]},
            {"module": [{"description": {"model": "1756-EN2T"}, "uptime": "2:00:00"}]},
        ),
        (
            {"extra": {"rows": [{"a": 1, "original": "x"}, {"a": 2}]}},
            {"extra": {"rows": [{"a": 2}, {"a": 1, "original": "y"}]}},
        ),
    ],
)
def test_items_that_only_differ_in_excluded_fields_are_same(old, new):
    diff = compare_device_data(old, new)
    assert diff.is_same
    assert diff.similarity == 1.0
    assert compare_device_data(old, new, ignore_order=False).is_same == ("rows" not in str(old))
    assert not compare_device_data(
        old, new, use_default_excludes=False, include_original=True
    ).is_same


def test_ssh_key_material_not_in_paths():
    secret = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIBYuF0aSECRETSECRETSECRETSECRET\n"
    old = DeviceData()
    new = DeviceData()
    old.ssh_keys = [SSHKey(original=secret, description="old")]
    new.ssh_keys = [SSHKey(original=secret, description="new")]

    for include_original in (False, True):
        diff = old.compare(new, include_original=include_original)
        assert len(diff.changes) == 1
        assert diff.changes[0].path.startswith("ssh_keys[original=sha256:")
        assert diff.changes[0].path.endswith("].description")
        assert "SECRET" not in json.dumps(diff.export())
        assert "MHcC" not in diff.format()

    removed = compare_device_data({"ssh_keys": [{"original": secret, "user": "root"}]}, {})
    assert "SECRET" not in json.dumps(removed.export())

    # A rotated key (same ID, different key material) is a removed and an added key
    rotated = compare_device_data(
        {"ssh_keys": [{"id": "k1", "original": secret, "user": "root"}]},
        {
            "ssh_keys": [
                {"id": "k1", "original": secret.replace("SECRET", "OTHER"), "user": "root"}
            ]
        },
    )
    assert [c.kind for c in rotated.changes] == ["removed", "added"]
    assert rotated.changes[0].old == {"id": "k1", "user": "root"}
    assert rotated.changes[0].path != rotated.changes[1].path
    assert "SECRET" not in json.dumps(rotated.export())


def test_compare_makes_no_network_requests(mocker):
    mocker.patch.dict(
        config["CONFIG"], {"RESOLVE_IP": True, "RESOLVE_MAC": True, "RESOLVE_HOSTNAME": True}
    )
    to_host = mocker.patch(
        "peat.data.models.addresses.resolve_ip_to_hostname", return_value="resolved.example"
    )
    to_ip = mocker.patch("peat.data.models.addresses.resolve_hostname_to_ip", return_value="")
    to_mac = mocker.patch("peat.data.models.ip_to_mac", return_value="00:00:5E:00:53:99")
    mac_ip = mocker.patch("peat.data.models.mac_to_ip", return_value="")

    old = DeviceData(ip="192.0.2.7")
    new = DeviceData(ip="192.0.2.7")
    new.interface = [Interface(type="ethernet", hostname="plc.example")]
    old.interface = [Interface(type="ethernet", ip="192.0.2.8", hostname="plc.example")]

    diff = old.compare(new)
    assert [m.call_count for m in (to_host, to_ip, to_mac, mac_ip)] == [0, 0, 0, 0]
    assert "resolved.example" not in json.dumps(diff.export())
    baseline = {"ip": "192.0.2.7", "interface": [{"type": "ethernet", "ip": "192.0.2.7"}]}
    diff = DeviceData(ip="192.0.2.7").compare(baseline)
    assert not any("hostname" in c.path or "mac" in c.path for c in diff.changes)
    assert [m.call_count for m in (to_host, to_ip, to_mac, mac_ip)] == [0, 0, 0, 0]

    # Address resolution still works outside of a comparison
    DeviceData(ip="192.0.2.9").export()
    assert to_host.call_count == 1
    assert to_mac.call_count == 1


def _pulled_device(run_dir: Path, user: str, content: str) -> DeviceData:
    """A device pulled into a run directory, with local copies of the files."""
    device_dir = run_dir / "devices" / "192.0.2.30"
    device_dir.mkdir(parents=True)
    logic_path = device_dir / "logic.txt"
    logic_path.write_text(content, encoding="utf-8")
    hosts_path = device_dir / "hosts"
    hosts_path.write_text("127.0.0.1 localhost", encoding="utf-8")
    conf_path = device_dir / "app.conf"
    conf_path.write_text("debug=0", encoding="utf-8")

    dev = DeviceData(ip="192.0.2.30")
    dev.logic.file.local_path = logic_path
    dev.files = [
        File(local_path=hosts_path),
        # Device path set by the module, ownership from the local copy
        File(path="/etc/app.conf", local_path=conf_path),
        # Device file listing, no local copy
        File(path="/etc/shadow", owner=user, group=user),
    ]
    return dev


def test_local_copies_in_different_run_dirs(mocker, tmp_path):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": None})
    # Different users running PEAT
    mocker.patch("pathlib.Path.owner", side_effect=cycle(["root", "nobody"]))
    mocker.patch("pathlib.Path.group", side_effect=cycle(["wheel", "nogroup"]))

    old = _pulled_device(tmp_path / "pull_2026-01-01_111", "root", "logic")
    new = _pulled_device(tmp_path / "pull_2026-02-01_222", "root", "logic")
    old_export = old.export()
    new_export = new.export()
    assert old_export["files"][0]["path"] != new_export["files"][0]["path"]

    diff = compare_device_data(old_export, new_export)
    assert diff.is_same, diff.format()

    # Device paths and ownership from the device are still compared
    new_export["files"][1]["path"] = "/etc/app2.conf"
    new_export["files"][2]["owner"] = "admin"
    paths = _paths(compare_device_data(old_export, new_export))
    assert ("removed", _file_sel("/etc/app.conf")) in paths
    assert ("added", "files[path=/etc/app2.conf]") in paths
    assert ("changed", f"{_file_sel('/etc/shadow')}.owner") in paths

    # Changed content of a local copy is still detected
    changed = _pulled_device(tmp_path / "pull_2026-03-01_333", "root", "new logic")
    paths = _paths(old.compare(changed))
    assert ("changed", "logic.file.hash.sha256") in paths
    assert not any(p.endswith((".path", ".directory", ".owner", ".group")) for _, p in paths)

    raw_paths = [
        c.path
        for c in compare_device_data(old_export, new_export, use_default_excludes=False).changes
    ]
    assert "logic.file.path" in raw_paths
    assert "logic.file.directory" in raw_paths
