import pytest

from peat.consts import PeatError
from peat.data.data_utils import (
    DeepChainMap,
    dedupe_model_list,
    find_position,
    lookup_by_str,
    match_all,
    merge_models,
    only_include_keys,
    strip_empty_and_private,
    strip_key,
)
from peat.data.models import (
    OS,
    DeviceData,
    File,
    Geo,
    Interface,
    Memory,
    Register,
    Service,
    Vendor,
)


def test_deep_chain_map():
    assert DeepChainMap().to_dict() == {}

    layer1 = {}
    layer2 = {"key": 9999}
    layer3 = {"deep_object": {"deep_key": "The Deep"}}
    dmap = DeepChainMap(layer1, layer2, layer3)

    assert dmap["key"] == 9999
    assert dmap.to_dict() == {"deep_object": {"deep_key": "The Deep"}, "key": 9999}

    layer1["key"] = -1111
    assert dmap["key"] == -1111
    assert layer2["key"] == 9999
    assert dmap["deep_object"]["deep_key"] == "The Deep"

    layer1["deep_object"] = {"another_key": "another_value"}
    assert dmap["deep_object"]["deep_key"] == "The Deep"
    assert dmap["deep_object"]["another_key"] == "another_value"


def test_lookup_by_str():
    # empty container
    assert lookup_by_str([], Vendor(name="vend"), "name") is None

    # bad lookup
    assert lookup_by_str([Vendor(name="vend")], Vendor(name="vend"), "") is None

    # invalid attribute ("bogus")
    assert lookup_by_str([Vendor(name="vend")], Vendor(name="vend"), "bogus") is None

    # "id" is a default on the value
    assert lookup_by_str([Vendor(id="v_id")], Vendor(name="vend"), "id") is None

    # Fail lookup even if it's set on value being searched
    assert lookup_by_str([Vendor()], Vendor(id="vend_id"), "id") is None

    # successful lookups
    assert lookup_by_str([Vendor(id="vend_id")], Vendor(id="vend_id"), "id") == 0

    # multiple objects
    to_search = [Vendor(name="vend_name"), Vendor(id="vend_id"), Vendor(id="vend_id")]
    assert lookup_by_str(to_search, Vendor(id="vend_id"), "id") == 1


def test_find_position():
    obj = [File, Vendor(name="vend")]
    assert find_position(obj, "name", "vend") == 1
    assert find_position(obj, "doesnotexist", "vend") is None


def test_match_all():
    assert match_all([], {}) is None
    assert match_all([OS(family="test_family")], {}) is None
    assert match_all([Vendor(name="test_name")], {"name": "test_name"}) == 0

    test_vendor_list = [
        OS(),
        Vendor(name="tst"),
        Vendor(name="tst", id="vnd_id"),
        Vendor(name="tst", id="other_id"),
        Vendor(id="vnd_id"),
    ]
    assert match_all(test_vendor_list, {"name": "tst", "id": "vnd_id"}) == 2


def test_strip_empty_and_private():
    assert strip_empty_and_private({}) == {}
    assert strip_empty_and_private({"x": {None, ""}, "y": [], "z": {}}) == {}
    assert strip_empty_and_private({"x": set(), "y": [], "z": {}}) == {}
    assert strip_empty_and_private({"x": {None}}) == {}
    assert strip_empty_and_private({"x": {""}}) == {}

    original = {
        "empty": "",
        "_private": "priv",
        "t": "t",
        "x": {"_p": 1, "y": 2, "z": 0, "n": -1},
        "b": False,
        "l": [],
        "la": [-1, 0, 1],
        "lal": [-1, 1, None, [], [0, 1, 2, -3], ""],
    }
    expected = {
        "t": "t",
        "x": {"y": 2, "z": 0, "n": -1},
        "b": False,
        "la": [-1, 0, 1],
        "lal": [-1, 1, [0, 1, 2, -3]],
    }
    assert strip_empty_and_private(original) == expected
    assert strip_empty_and_private(original, False, False) == original

    empty_with = {
        "empty": "",
        "_private": "priv",
        "t": "t",
    }
    empty_without = {
        "_private": "priv",
        "t": "t",
    }
    assert strip_empty_and_private(empty_with, strip_private=False) == empty_without

    priv_with = {
        "empty": "",
        "_private": "priv",
        "t": "t",
    }
    priv_without = {
        "empty": "",
        "t": "t",
    }
    assert strip_empty_and_private(priv_with, strip_empty=False) == priv_without


def test_strip_key():
    data = {"x": "y", "b": "e", "z": 0}
    assert strip_key(data, "b") == {"x": "y", "z": 0}
    assert strip_key({}, "shrug") == {}
    assert strip_key({}, "") == {}


def test_only_include_keys():
    data = {"x": "y", "b": "e", "z": 0}
    assert only_include_keys(data, ["x"]) == {"x": "y"}
    assert only_include_keys(data, "x") == {"x": "y"}
    assert only_include_keys(data, ["z", "b"]) == {"b": "e", "z": 0}
    assert only_include_keys(data, []) == {}

    assert only_include_keys({}, ["something"]) == {}
    assert only_include_keys({}, "something") == {}
    assert only_include_keys({}, "") == {}
    assert only_include_keys({}, []) == {}


def test_dedupe_model_list():
    assert dedupe_model_list([]) == []
    assert dedupe_model_list(None) is None

    assert dedupe_model_list([Service(port=80)]) == [Service(port=80)]
    assert dedupe_model_list([Service(port=80), Service(port=80)]) == [Service(port=80)]

    # Registers
    registers = []
    deduped_registers = []

    for i in range(100):
        registers.append(
            Register(
                address=str(i),
                name=f"testing_{i}",
                protocol="dnp3",
            )
        )

        reg2 = Register(
            address=str(i),
            name=f"testing_{i}",
            protocol="dnp3",
            read_write="read",
        )
        registers.append(reg2)
        deduped_registers.append(reg2)

    assert dedupe_model_list(registers) == deduped_registers

    # Services
    services = [
        Service(port=80),
        Service(port=80, protocol="http"),
        Service(),
        Service(port=80, protocol="http", enabled=True),
        Service(port=80),
        Service(port=8080, protocol="http"),
        Service(port=161, protocol="snmp"),
        Service(protocol="snmp"),
        Service(enabled=False),
        Service(),
        Service(port=80),
    ]
    deduped_services = [
        Service(port=80, protocol="http", enabled=True),
        Service(port=8080, protocol="http"),
        Service(port=161, protocol="snmp"),
        Service(enabled=False),
    ]

    assert dedupe_model_list(services) == deduped_services

    # Interfaces
    interfaces = [
        Interface(
            ip="192.168.0.1",
            services=[Service(port=80), Service(port=80, protocol="http")],
        ),
        Interface(services=[Service(port=80), Service(port=80, protocol="http")]),
        Interface(ip="192.168.0.1"),
        Interface(),
        Interface(ip="10.0.0.1"),
    ]
    deduped_interfaces = [
        Interface(
            ip="192.168.0.1",
            services=[Service(port=80), Service(port=80, protocol="http")],
        ),
        Interface(ip="10.0.0.1"),
    ]

    assert dedupe_model_list(interfaces) == deduped_interfaces

    # Deduplicate services on an interface
    iface_services = [Service(port=80), Service(port=80, protocol="http")]
    iface = Interface(ip="192.168.0.1", services=iface_services)

    iface.services = dedupe_model_list(iface.services)
    assert iface.services == [Service(port=80, protocol="http")]


def test_dedupe_model_list_keeps_services_of_other_transports():
    """tcp/20000 and udp/20000 are two services; one transport is merged (R5-2)."""
    tcp = Service(port=20000, transport="tcp", status="open")
    udp = Service(port=20000, transport="udp", status="open")
    assert dedupe_model_list([tcp, udp]) == [tcp, udp]

    deduped = dedupe_model_list(
        [
            Service(port=20000, transport="tcp", status="open"),
            Service(port=20000, transport="udp", status="open"),
            Service(port=20000, transport="tcp", process_name="dnp3d"),
        ]
    )
    assert deduped == [
        Service(port=20000, transport="tcp", status="open", process_name="dnp3d"),
        Service(port=20000, transport="udp", status="open"),
    ]
    # a service without a transport is still merged into one with the same port
    assert len(dedupe_model_list([Service(port=20000), tcp, udp])) == 2


def test_merge_models():
    """assert there are no duplicates in various places."""
    assert merge_models(None, None) is None

    with pytest.raises(PeatError):
        merge_models(Service(port=80), {"bad": "attribute"})

    mem_dst = Memory(address="0000", value="0000")
    mem_src = Memory(dataset="test_dataset")
    merge_models(mem_dst, mem_src)
    assert mem_dst.dataset == "test_dataset"

    dev_dst = DeviceData(
        id="dst",
        module=[
            DeviceData(id="mod1", slot="1"),
            DeviceData(id="mod2", slot="2"),
        ],
    )
    dev_src = DeviceData(
        id="src",
        ip="192.0.2.1",
        module=[
            DeviceData(id="mod1", slot="1"),
            DeviceData(id="mod3", slot="3"),
        ],
    )
    merge_models(dev_dst, dev_src)
    assert dev_src.id == "src"  # ensure source is unmodified
    assert dev_src.ip == "192.0.2.1"
    assert dev_dst.id == "dst"
    assert dev_dst.ip == "192.0.2.1"
    assert len(dev_dst.module) == 3
    assert dev_dst.module[0].slot == "1"
    assert dev_dst.module[1].slot == "2"
    assert dev_dst.module[2].slot == "3"

    # test lists, dataclasses, and basic attributes
    dest = DeviceData()
    src = DeviceData(type="test_type", service=[Service()])
    src.description.full = "test_description_full"
    merge_models(dest, src)
    assert dest.service == src.service
    assert dest.description.full == src.description.full
    assert dest.type == src.type

    # test zero int isn't overwritten by unset or set value
    z_int = Interface(speed=0)
    merge_models(z_int, Interface())
    assert z_int.speed == 0
    merge_models(z_int, Interface(speed=9001))
    assert z_int.speed == 0

    # test that empty values in src doesn't replace set values set in dest
    os_dst = OS(family="dest_os_family")
    src_os = OS()
    merge_models(os_dst, src_os)
    assert os_dst.family == "dest_os_family"
    assert src_os.family == ""  # Ensure the source didn't get modified

    # test set values (non-empty) in src don't replace set values in dest
    geo_dst = Geo(city_name="dest_city")
    geo_src = Geo(city_name="src_city", country_name="USA")
    merge_models(geo_dst, geo_src)
    assert geo_dst.city_name == "dest_city"
    assert geo_src.city_name == "src_city"
    assert geo_dst.country_name == geo_src.country_name

    # test .module attribute gets copied and
    # test values in src don't overwrite values in dest
    mod = DeviceData(id="mod_id")
    with_mod = DeviceData(id="with_mod", module=[mod])
    no_mod = DeviceData(id="no_mod")
    assert not no_mod.module
    merge_models(no_mod, with_mod)
    assert no_mod.id == "no_mod"
    assert mod in no_mod.module
    assert no_mod.module == with_mod.module
    assert no_mod.id != with_mod.id
    assert no_mod.module[0].id == "mod_id"

    # test empty values in src .module don't overwrite existing values in dest
    dest_data = DeviceData(type="dest_type")
    src_data = DeviceData()
    merge_models(dest_data, src_data)
    assert dest_data.type == "dest_type"
    assert not src_data.type

    # test that module list is sorted by Slot ID
    sort_dest = DeviceData()
    mod1 = DeviceData(slot="1")
    mod2 = DeviceData(slot="2")
    sort_src = DeviceData(module=[mod2, mod1])
    merge_models(sort_dest, sort_src)
    assert sort_dest.module[0] == mod1
    assert sort_dest.module[1] == mod2


# --------------------------------------------------------------------------- #
# Issue #48 machinery: identity keys, newest-wins, nested lists
# --------------------------------------------------------------------------- #
import time  # noqa: E402
from datetime import UTC, datetime, timedelta  # noqa: E402

from peat.data.data_utils import (  # noqa: E402
    as_utc,
    dedupe_is_linear,
    dedupe_nested_lists,
    has_nested_lists,
    lookup_by_key,
    model_key,
    nested_list_fields,
    sort_model_list,
    submodel_fields,
)
from peat.data.models import (  # noqa: E402
    IEC61850,
    Clock,
    Event,
    IEC61850Publication,
    Indicator,
    Logic,
    LogicTask,
    NetworkStatistics,
    NetworkTraffic,
    Relationship,
    RelationshipEndpoint,
    Route,
    TimeSource,
    Vlan,
)

T0 = datetime(2026, 10, 30, 12, 0, 0, tzinfo=UTC)
T1 = T0 + timedelta(hours=1)


def test_strip_key_recurse_lists():
    data = {
        "original": "x",
        "files": [{"name": "a", "original": b"1"}, {"name": "b"}, "raw"],
        "module": [{"files": [{"original": b"2", "name": "c"}], "original": "m"}],
        "event": [{"original": "log line"}],
        "logic": {"original": "x", "name": "y"},
    }
    assert strip_key(data, "original") == {
        "files": [{"name": "a", "original": b"1"}, {"name": "b"}, "raw"],
        "module": [{"files": [{"original": b"2", "name": "c"}], "original": "m"}],
        "event": [{"original": "log line"}],
        "logic": {"name": "y"},
    }
    assert strip_key(data, "original", recurse_lists=("files", "module")) == {
        "files": [{"name": "a"}, {"name": "b"}, "raw"],
        "module": [{"files": [{"name": "c"}]}],
        "event": [{"original": "log line"}],  # not in recurse_lists: kept
        "logic": {"name": "y"},
    }


def test_model_key_and_lookup_by_key():
    routes = [
        Route(destination="10.0.0.0/8", gateway="192.0.2.1"),
        Route(destination="10.0.0.0/8", gateway="192.0.2.2"),
    ]
    fields = ("destination", "gateway", "interface")
    assert model_key(routes[1], fields) == ("10.0.0.0/8", "192.0.2.2", "")
    assert lookup_by_key(routes, Route(destination="10.0.0.0/8", gateway="192.0.2.2"), fields) == 1
    assert lookup_by_key(routes, Route(destination="10.0.0.0/8"), fields) is None
    assert lookup_by_key(routes, Route(), fields) is None  # empty key never matches
    assert lookup_by_key([], routes[0], fields) is None


def test_as_utc():
    naive = datetime(2026, 1, 1, 12, 0)
    assert as_utc(naive) == datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    assert as_utc(T0) is T0


def test_dedupe_model_list_dedupe_key():
    # the FIRST item with a key survives, later items are merged into it
    items = [
        Interface(name="eth0", ip="192.0.2.1"),
        Interface(name="eth1"),
        Interface(name="eth0", ip="198.51.100.1", mtu=1500),
        Interface(ip="192.0.2.9"),  # no key: handled by the subset pass
        Interface(ip="192.0.2.9", mtu=9000),
    ]
    deduped = dedupe_model_list(items)
    assert [(i.name, i.ip, i.mtu) for i in deduped] == [
        ("eth0", "192.0.2.1", 1500),
        ("eth1", "", None),
        ("", "192.0.2.9", 9000),
    ]

    # Service identity is (protocol, port)
    services = [
        Service(protocol="http", port=80, enabled=True),
        Service(protocol="http", port=80, status="open", extra={"banner": "x"}),
        Service(protocol="http", port=8080),
    ]
    deduped = dedupe_model_list(services)
    assert len(deduped) == 2
    assert deduped[0].status == "open"
    assert deduped[0].extra == {"banner": "x"}


def test_dedupe_is_linear():
    assert not dedupe_is_linear([])
    assert dedupe_is_linear([Vlan(id="1"), Vlan(id="2")])
    assert not dedupe_is_linear([Vlan(id="1"), Vlan(name="x")])  # incomplete key
    assert not dedupe_is_linear([Register(address="1")])  # no _dedupe_key
    assert dedupe_is_linear([Relationship(id="a"), Relationship(id="b")])


def test_dedupe_model_list_linear_for_complete_keys():
    rels = [
        Relationship(id=f"{i:016x}", remote=RelationshipEndpoint(ip=f"10.0.{i // 250}.{i % 250}"))
        for i in range(6000)
    ]
    rels.extend(r.copy(deep=True) for r in rels[:500])
    start = time.perf_counter()
    deduped = dedupe_model_list(rels)
    assert len(deduped) == 6000
    assert time.perf_counter() - start < 30


def test_purge_duplicates_large_keyed_lists():
    dev = DeviceData()
    dev.routes = [
        Route(destination=f"10.{i // 250}.{i % 250}.0/24", gateway="192.0.2.1", interface="eth0")
        for i in range(5200)
    ]
    dev.routes.extend(r.copy(deep=True) for r in dev.routes[:10])
    dev.purge_duplicates(force=True)
    assert len(dev.routes) == 5200
    # lists without a complete key keep the 5000-item guard
    dev.registers = [Register(address=str(i % 10)) for i in range(5001)]
    dev.purge_duplicates(force=True)
    assert len(dev.registers) == 5001


def test_merge_models_statistics_never_mixed():
    # no timestamps: destination sample kept
    dst = NetworkStatistics(ingress=NetworkTraffic(bytes=100))
    merge_models(dst, NetworkStatistics(egress=NetworkTraffic(bytes=5)))
    assert dst.ingress.bytes == 100
    assert dst.egress.bytes is None
    # one timestamp (destination): destination kept
    dst = NetworkStatistics(timestamp=T0, ingress=NetworkTraffic(bytes=1))
    merge_models(dst, NetworkStatistics(egress=NetworkTraffic(bytes=7)))
    assert dst.egress.bytes is None
    # one timestamp (source) and an empty destination: source copied
    dst = NetworkStatistics(interface="eth0")
    merge_models(dst, NetworkStatistics(timestamp=T0, egress=NetworkTraffic(bytes=7)))
    assert dst.egress.bytes == 7
    assert dst.timestamp == T0
    # both timestamps: newer replaces wholesale, older ignored
    dst = NetworkStatistics(timestamp=T0, ingress=NetworkTraffic(bytes=1))
    merge_models(dst, NetworkStatistics(timestamp=T1, egress=NetworkTraffic(bytes=2)))
    assert dst.ingress.bytes is None
    assert dst.egress.bytes == 2
    assert dst.timestamp == T1
    merge_models(dst, NetworkStatistics(timestamp=T0, ingress=NetworkTraffic(bytes=9)))
    assert dst.ingress.bytes is None
    assert dst.timestamp == T1


def test_merge_models_newest_wins():
    dst = Indicator(name="RUN", type="led", state="on", label="RUN", timestamp=T0)
    merge_models(dst, Indicator(name="RUN", type="led", state="off", timestamp=T1))
    assert dst.state == "off"
    assert dst.timestamp == T1
    assert dst.label == "RUN"
    merge_models(dst, Indicator(name="RUN", type="led", state="on", timestamp=T0))
    assert dst.state == "off"  # older reading ignored
    # naive and aware timestamps compare safely
    dst = Clock(observed=datetime(2026, 10, 30, 12, 0), source="sntp")
    merge_models(dst, Clock(observed=T1, source="irig_b"))
    assert dst.source == "irig_b"


def test_merge_models_newer_clock_replaces_sources_and_offset():
    old = Clock(
        time=T0 + timedelta(seconds=10),
        observed=T0,
        sources=[
            TimeSource(protocol="sntp", address="192.0.2.1", selected=True, state="active"),
            TimeSource(protocol="sntp", address="192.0.2.2", selected=False, state="standby"),
        ],
    )
    old.annotate()
    assert old.offset == 10.0
    new = Clock(
        time=None,
        observed=T1,
        sources=[
            TimeSource(protocol="sntp", address="192.0.2.1", selected=False, state="unreachable"),
            TimeSource(protocol="sntp", address="192.0.2.2", selected=True, state="active"),
        ],
    )
    merge_models(old, new)
    old.annotate()
    assert old.observed == T1
    assert [(s.address, s.selected, s.state) for s in old.sources] == [
        ("192.0.2.1", False, "unreachable"),
        ("192.0.2.2", True, "active"),
    ]
    # the newer sample has no device time: no stale time/offset from the older one
    assert old.time is None
    assert old.offset is None

    # an older sample does not replace the live source state
    merge_models(
        old,
        Clock(
            observed=T0,
            sources=[TimeSource(protocol="sntp", address="192.0.2.1", state="active", stratum=2)],
        ),
    )
    first = old.sources[0]
    assert (first.address, first.state, first.stratum) == ("192.0.2.1", "unreachable", 2)


def test_merge_models_newer_indicator_unknown_state():
    dst = Indicator(name="ALARM", type="led", state="on", timestamp=T0)
    merge_models(dst, Indicator(name="ALARM", type="led", state="unknown", timestamp=T1))
    assert dst.state == ""
    assert dst.value == "unknown"
    assert dst.timestamp == T1
    # a definition (no timestamp) still only fills gaps
    merge_models(dst, Indicator(name="ALARM", type="led", label="ALARM", color="red"))
    assert dst.state == ""
    assert dst.label == "ALARM"
    assert dst.color == "red"
    # an older reading is ignored
    merge_models(dst, Indicator(name="ALARM", type="led", state="off", timestamp=T0))
    assert dst.state == ""


def test_merge_models_equal_timestamps_incoming_wins():
    """
    Two reads can get the same timestamp (coarse clock, e.g. on Windows): the
    incoming (later stored) sample wins, for every newest-wins model.
    """
    dst = NetworkStatistics(timestamp=T0, ingress=NetworkTraffic(packets=1))
    merge_models(dst, NetworkStatistics(timestamp=T0, ingress=NetworkTraffic(packets=2)))
    assert dst.ingress.packets == 2
    # counters are still never mixed
    merge_models(dst, NetworkStatistics(timestamp=T0, egress=NetworkTraffic(packets=5)))
    assert (dst.ingress.packets, dst.egress.packets) == (None, 5)

    dst = Indicator(name="KEY", type="switch", value="REMOTE", label="Key", timestamp=T0)
    merge_models(
        dst, Indicator(name="KEY", type="switch", value="RUN", timestamp=T0, extra={"a": 2})
    )
    assert (dst.value, dst.label) == ("RUN", "Key")
    assert dst.extra == {"a": 2}

    dst = Clock(time=T0 + timedelta(seconds=10), observed=T0)
    dst.annotate()
    merge_models(dst, Clock(time=T0 + timedelta(seconds=3), observed=T0))
    dst.annotate()
    assert (dst.time, dst.offset) == (T0 + timedelta(seconds=3), 3.0)

    rel = Relationship(remote=RelationshipEndpoint(ip="192.0.2.50"), last_seen=T0, state="a")
    merge_models(
        rel, Relationship(remote=RelationshipEndpoint(ip="192.0.2.50"), last_seen=T0, state="b")
    )
    assert rel.state == "b"

    # a sample that adds nothing (e.g. a copy, or one without a reading) changes nothing
    dst = Indicator(name="RUN", type="led", state="on", health="normal", timestamp=T0)
    merge_models(dst, Indicator(name="RUN", type="led", state="on", timestamp=T0))
    merge_models(dst, Indicator(name="RUN", type="led", label="RUN", timestamp=T0))
    assert (dst.state, dst.health, dst.label) == ("on", "normal", "RUN")
    dst = NetworkStatistics(timestamp=T0, ingress=NetworkTraffic(packets=1, errors=2))
    merge_models(dst, NetworkStatistics(timestamp=T0, ingress=NetworkTraffic(packets=1)))
    assert dst.ingress.errors == 2

    # the same through store() and dedupe_model_list() (order of storing)
    dev = DeviceData()
    for packets in (1, 2):
        dev.store(
            "protocol_statistics",
            NetworkStatistics(type="ipv4", timestamp=T0, ingress=NetworkTraffic(packets=packets)),
        )
    assert [s.ingress.packets for s in dev.protocol_statistics] == [2]
    items = [
        Indicator(name="KEY", type="switch", value=v, timestamp=T0) for v in ("REMOTE", "RUN")
    ]
    assert [i.value for i in dedupe_model_list(items)] == ["RUN"]


def test_merge_models_relationship_rules():
    dst = Relationship(
        remote=RelationshipEndpoint(ip="192.0.2.50"),
        evidence={"config"},
        first_seen=T0,
        last_seen=T0,
        count=2,
        state="established",
    )
    merge_models(
        dst,
        Relationship(
            remote=RelationshipEndpoint(ip="192.0.2.50"),
            evidence={"log"},
            first_seen=T0 - timedelta(days=1),
            last_seen=T1,
            count=1,
            state="closed",
        ),
    )
    assert dst.evidence == {"config", "log"}
    assert dst.first_seen == T0 - timedelta(days=1)
    assert dst.last_seen == T1
    assert dst.state == "closed"  # state of the latest observation
    assert dst.count == 2  # max


def test_merge_models_dedupes_nested_lists():
    # the result of dedupe_model_list() used to be discarded
    dst = Logic(tasks=[LogicTask(name="Main", priority=1)])
    merge_models(dst, Logic(tasks=[LogicTask(name="Main", scan_count=5), LogicTask(name="Fast")]))
    assert [(t.name, t.priority, t.scan_count) for t in dst.tasks] == [
        ("Fast", None, None),
        ("Main", 1, 5),
    ]


def test_nested_list_helpers():
    assert nested_list_fields(Interface) == ("vlans", "services")
    assert "statistics" in submodel_fields(Interface)
    assert "module" not in nested_list_fields(DeviceData)
    assert has_nested_lists(Interface)
    assert has_nested_lists(Clock)
    assert has_nested_lists(IEC61850)
    assert not has_nested_lists(Vlan)
    assert has_nested_lists(DeviceData)  # self-referencing model (cycle guard)
    assert not has_nested_lists(Event)


def test_dedupe_nested_lists():
    iface = Interface(
        name="port1",
        vlans=[Vlan(id="200"), Vlan(id="100"), Vlan(id="100", name="scada")],
        services=[Service(protocol="http", port=80), Service(protocol="http", port=80)],
    )
    dedupe_nested_lists(iface)
    assert [(v.id, v.name) for v in iface.vlans] == [("100", "scada"), ("200", "")]
    assert len(iface.services) == 1

    iec = IEC61850(
        publications=[
            IEC61850Publication(type="SV", ld_inst="MU", name="svcb1"),
            IEC61850Publication(type="GOOSE", ld_inst="PRO", name="gcb"),
            IEC61850Publication(type="GOOSE", ld_inst="PRO", name="gcb", conf_rev=2),
        ]
    )
    dedupe_nested_lists(iec)
    assert [(p.type, p.conf_rev) for p in iec.publications] == [("GOOSE", 2), ("SV", None)]

    clock = Clock(
        sources=[TimeSource(protocol="ntp", address="a"), TimeSource(protocol="ntp", address="a")]
    )
    dedupe_nested_lists(clock)
    assert len(clock.sources) == 1
    dedupe_nested_lists(None)  # no-op


def test_sort_model_list_mixed_naive_aware_datetimes():
    events = [
        Event(action="b", created=T1),
        Event(action="a", created=datetime(2026, 1, 1, 0, 0)),
        Event(action="c"),
    ]
    sort_model_list(events)
    assert [e.action for e in events] == ["a", "b", "c"]


def test_merge_models_newer_clock_sample_wins_in_both_directions():
    """R2-1: a newer destination keeps its own device time and offset."""
    old = Clock(time=T0 + timedelta(seconds=10), observed=T0, synchronized=True)
    old.annotate()
    assert old.offset == 10.0
    new = Clock(time=T1 + timedelta(seconds=5), observed=T1)
    merge_models(new, old)
    new.annotate()
    assert (new.time, new.offset, new.observed) == (T1 + timedelta(seconds=5), 5.0, T1)
    assert new.synchronized is True  # not bound to "observed": still fills the gap

    # a newer sample without a device time does not take the older time/offset
    new = Clock(observed=T1)
    merge_models(new, old)
    new.annotate()
    assert (new.time, new.offset, new.observed) == (None, None, T1)


def _older_alarm() -> Indicator:
    return Indicator(
        name="ALARM",
        type="led",
        state="blinking",
        health="failure",
        blink_rate=2.0,
        latched=True,
        label="ALARM",
        extra={"state": 3, "oid_index": 2},
        timestamp=T0,
    )


def _newer_alarm() -> Indicator:
    return Indicator(name="ALARM", type="led", state="unknown", extra={"state": 5}, timestamp=T1)


@pytest.mark.parametrize("newer_is_dest", [False, True])
def test_merge_models_newer_indicator_reading_wins_in_both_directions(newer_is_dest):
    """R2-2: no reading field of an older Indicator reading fills the newer one."""
    if newer_is_dest:
        dst, src = _newer_alarm(), _older_alarm()
    else:
        dst, src = _older_alarm(), _newer_alarm()
    merge_models(dst, src)
    assert (dst.state, dst.value, dst.health, dst.blink_rate) == ("", "unknown", "", None)
    assert dst.extra == {"state": 5, "oid_index": 2}  # keys of the newer reading win
    assert dst.timestamp == T1
    # configured properties still fill gaps
    assert (dst.label, dst.latched) == ("ALARM", True)
