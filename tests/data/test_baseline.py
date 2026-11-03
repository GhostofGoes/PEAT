import json
from datetime import timedelta
from pathlib import PurePosixPath, PureWindowsPath

import pytest

from peat import DeviceModule, module_api
from peat.data import baseline as bl
from peat.data.models import (
    Baseline,
    BaselineFinding,
    BaselineRule,
    BaselineSelector,
    DeviceData,
    File,
    Relationship,
    RelationshipEndpoint,
    Service,
)
from peat.data.validators import ECS_EVENT_VALUES

from .example_devices import T0, T1, sel_relay

FACTORY_RID = ["FEEDER 1", "feeder 1", "feeder_1"]
FACTORY_TID = ["STATION A", "station a", "station_a"]

# The SEL known-default pair of DESIGN.md 6.6 (factory values + hardening checks)
SEL_FACTORY = Baseline(
    id="sel-relay-factory-defaults",
    name="SEL relay factory defaults",
    version="1",
    kind="factory_default",
    scope="device_type",
    selector=BaselineSelector(vendor_id="SEL", device_type="Relay"),
    rules=[
        BaselineRule(
            id="sel.default.telnet-port",
            path="service[protocol=telnet].port",
            operator="equals",
            value=23,
            category="ports_services",
            severity="info",
            reason="Telnet port changed from factory default 23 to {actual}",
        ),
        BaselineRule(
            id="sel.default.rid",
            path="name",
            operator="in",
            value=FACTORY_RID,
            category="identity",
            severity="info",
            reason="Relay ID changed from factory default",
        ),
        BaselineRule(
            id="sel.default.tid",
            path="extra.terminal_id",
            operator="in",
            value=FACTORY_TID,
            category="identity",
            severity="info",
        ),
    ],
)
SEL_VENDOR = Baseline(
    id="sel-relay-vendor-recommended",
    name="SEL relay hardening",
    version="1",
    kind="vendor_recommended",
    scope="device_type",
    selector=BaselineSelector(vendor_id="SEL", device_type="Relay"),
    rules=[
        BaselineRule(
            id="sel.service.telnet.absent",
            path="service[protocol=telnet]",
            operator="absent",
            category="ports_services",
            severity="low",
            reason="Telnet (23/tcp, cleartext) is exposed",
        ),
        BaselineRule(
            id="sel.accounts.default-credentials",
            path="service[*].security.default_credentials",
            operator="not_equals",
            value=True,
            category="accounts",
            severity="high",
            alert=True,
            reason="A factory default password was accepted",
        ),
        BaselineRule(
            id="sel.identity.rid-changed",
            path="name",
            operator="not_in",
            value=FACTORY_RID,
            category="identity",
            severity="low",
            reason="Relay ID is still the factory default {actual}",
        ),
        BaselineRule(
            id="sel.iec61850.goose.signed",
            path="iec61850.publications[type=GOOSE].security",
            operator="not_equals",
            value="None",
            category="settings",
            severity="info",
        ),
    ],
)


def _exported(dev: DeviceData) -> DeviceData:
    """Copy of a device as loaded from device-data-full.json."""
    raw = json.loads(json.dumps(dev.export(include_original=True), default=str))
    return DeviceData.parse_obj(raw)


def _snapshot(dev: DeviceData, kind: str = "first_observed", **kwargs) -> Baseline:
    expected = _exported(dev)
    return Baseline(
        id="relay-1",
        name="relay-1 first pull",
        kind=kind,
        scope="device",
        selector=BaselineSelector(device_id=expected.id),
        expected=expected,
        **kwargs,
    )


def _diffs(findings: list[BaselineFinding]) -> set[tuple[str, str]]:
    return {(f.difference, f.path) for f in findings}


# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
def test_split_path():
    assert bl.split_path("firmware.version") == [("firmware", None), ("version", None)]
    assert bl.split_path("service[protocol=ftp,port=21].enabled") == [
        ("service", {"protocol": "ftp", "port": "21"}),
        ("enabled", None),
    ]
    assert bl.split_path("service[*].security.default_credentials") == [
        ("service", {}),
        ("security", None),
        ("default_credentials", None),
    ]
    assert bl.split_path("service[]") == [("service", {})]
    # dots inside a selector do not split the path
    assert bl.split_path("interface[ip=192.0.2.10].mtu") == [
        ("interface", {"ip": "192.0.2.10"}),
        ("mtu", None),
    ]
    for bad in ("firmware..version", "a[b]c", "", "a]"):
        with pytest.raises(ValueError, match="invalid baseline path"):
            bl.split_path(bad)


def test_plain_path():
    assert bl.plain_path("interface[name=eth0].mtu") == "interface.mtu"
    assert bl.plain_path("service[protocol=http,port=80]") == "service"
    assert bl.plain_path("firmware.version") == "firmware.version"


def test_resolve_path():
    doc = bl.device_to_doc(sel_relay())
    assert bl.resolve_path(doc, "firmware.version") == [("firmware.version", "R516")]
    assert bl.resolve_path(doc, "service[protocol=telnet].port") == [
        ("service[protocol=telnet,port=23].port", 23)
    ]
    ports = [v for _, v in bl.resolve_path(doc, "service[*].port")]
    assert sorted(ports) == [21, 23, 102, 20000]
    assert bl.resolve_path(doc, "service[protocol=nope]") == []
    assert bl.resolve_path(doc, "nope.nothing") == []
    # a selector on a non-list value resolves nothing
    assert bl.resolve_path(doc, "firmware[version=R516]") == []
    # booleans match "true"/"false" (JSON spelling) and "True"/"False"
    assert len(bl.resolve_path(doc, "service[enabled=true]")) == 3
    assert len(bl.resolve_path(doc, "service[enabled=True]")) == 3


def test_device_to_doc_is_json_friendly_and_has_no_original():
    dev = sel_relay()
    dev.files[0].original = b"raw settings"
    doc = bl.device_to_doc(dev)
    json.dumps(doc)  # no datetimes/sets left
    assert "original" not in doc["files"][0]
    assert isinstance(doc["interface"][0]["statistics"]["timestamp"], str)
    # the device is not modified
    assert dev.files[0].original == b"raw settings"
    dev.ip = "192.0.2.99"
    bl.device_to_doc(dev)
    assert "192.0.2.99" not in dev.related.ip  # no populate_fields()


def test_device_to_doc_file_paths_are_posix():
    """str() of a Windows path has backslashes: device paths are compared in POSIX form."""
    dev = DeviceData(ip="192.0.2.10")
    dev.store("files", File(path=PureWindowsPath("/SETTINGS/SET_1.TXT")))
    dev.store("files", File(path=PureWindowsPath("/EVENTS/HR"), target_path=PureWindowsPath("x")))
    # a path from device data written on Windows, loaded on Linux
    dev.store("files", File(path=PurePosixPath("\\LOGS\\SER.TXT")))
    files = bl.device_to_doc(dev)["files"]
    assert [f["path"] for f in files] == ["/SETTINGS/SET_1.TXT", "/EVENTS/HR", "/LOGS/SER.TXT"]
    assert files[1]["target_path"] == "x"
    assert bl.posix_path(PureWindowsPath("C:\\peat\\in.scd")) == "C:/peat/in.scd"
    assert bl.posix_path(PurePosixPath("/SETTINGS/SET_1.TXT")) == "/SETTINGS/SET_1.TXT"


def _with_path_flavour(dev: DeviceData, path_cls: type) -> DeviceData:
    """The device as built on another OS (``PurePath`` is ``PureWindowsPath`` on Windows)."""
    for f in dev.files:
        if f.path is not None:
            f.path = path_cls(f.path.as_posix())
    return dev


@pytest.mark.parametrize(
    ("baseline_paths", "device_paths"),
    [(PurePosixPath, PureWindowsPath), (PureWindowsPath, PurePosixPath)],
)
def test_snapshot_file_paths_compare_across_operating_systems(baseline_paths, device_paths):
    """A baseline made on Linux compares cleanly on Windows, and vice versa."""
    dev = sel_relay()
    dev.files[0].hash.sha256 = "A" * 64
    baseline = _snapshot(dev)
    baseline.expected = _with_path_flavour(baseline.expected, baseline_paths)

    cur = _with_path_flavour(_exported(sel_relay()), device_paths)
    cur.files[0].hash.sha256 = "A" * 64
    assert bl.compare_device(cur, baseline) == []
    cur.files[0].hash.sha256 = "B" * 64
    assert _diffs(bl.compare_device(cur, baseline)) == {
        ("change", "files[path=/SETTINGS/SET_1.TXT].hash.sha256")
    }

    # rule selectors use POSIX paths on every OS
    rules = Baseline(
        id="files",
        kind="engineer_provided",
        rules=[
            BaselineRule(
                id="set1",
                path="files[path=/SETTINGS/SET_1.TXT].name",
                operator="equals",
                value="SET_1.TXT",
            )
        ],
    )
    (finding,) = bl.compare_device(cur, rules)
    assert (finding.result, finding.actual) == ("pass", "SET_1.TXT")


def test_is_ignored():
    patterns = ("extra", "*.extra", "clock.time", "files.created")
    assert bl.is_ignored("extra", patterns)
    assert bl.is_ignored("extra.terminal_id", patterns)
    assert bl.is_ignored("service[protocol=ftp,port=21].extra.foo", patterns)
    assert bl.is_ignored("clock.time", patterns)
    assert bl.is_ignored("files[path=/a].created", patterns)
    assert not bl.is_ignored("clock.utc_offset", patterns)
    assert not bl.is_ignored("extras", patterns)


# --------------------------------------------------------------------------- #
# Rule operators
# --------------------------------------------------------------------------- #
DOC = {
    "name": "FEEDER 1",
    "firmware": {"version": "R516-V0"},
    "service": [
        {"protocol": "telnet", "port": 23, "enabled": True},
        {"protocol": "ftp", "port": 21, "enabled": False},
    ],
    "hardware": {"memory_total": 1024},
}


@pytest.mark.parametrize(
    ("path", "operator", "value", "result"),
    [
        # equals: every value equals; JSON 23 equals "23"
        ("service[protocol=telnet].port", "equals", 23, "pass"),
        ("service[protocol=telnet].port", "equals", "23", "pass"),
        ("service[*].port", "equals", 23, "fail"),
        ("service[protocol=http].port", "equals", 80, "unknown"),
        # not_equals: no value equals
        ("service[*].enabled", "not_equals", "x", "pass"),
        ("service[*].enabled", "not_equals", True, "fail"),
        ("service[protocol=http].enabled", "not_equals", True, "pass"),
        # in / not_in
        ("name", "in", ["FEEDER 1", "feeder 1"], "pass"),
        ("name", "in", ["BAY 7"], "fail"),
        ("nope", "in", ["x"], "unknown"),
        ("name", "not_in", ["FEEDER 1"], "fail"),
        ("name", "not_in", ["BAY 7"], "pass"),
        ("nope", "not_in", ["x"], "pass"),
        # present / absent
        ("service[protocol=telnet]", "present", None, "pass"),
        ("service[protocol=http]", "present", None, "fail"),
        ("service[protocol=telnet]", "absent", None, "fail"),
        ("service[protocol=http]", "absent", None, "pass"),
        # regex
        ("firmware.version", "regex", r"^R5\d\d", "pass"),
        ("firmware.version", "regex", r"^R6", "fail"),
        ("nope", "regex", ".*", "unknown"),
        # min / max
        ("hardware.memory_total", "min", 512, "pass"),
        ("hardware.memory_total", "min", 2048, "fail"),
        ("hardware.memory_total", "max", 2048, "pass"),
        ("hardware.memory_total", "max", 512, "fail"),
        ("nope", "min", 1, "unknown"),
        ("nope", "max", 1, "unknown"),
        # conversion errors
        ("name", "min", 1, "error"),
        ("firmware.version", "regex", "(", "error"),
    ],
)
def test_evaluate_rule_operators(path, operator, value, result):
    rule = BaselineRule(path=path, operator=operator, value=value)
    assert bl.evaluate_rule(DOC, rule)[0] == result


def test_evaluate_rule_actual_values():
    rule = BaselineRule(path="service[*].port", operator="equals", value=23)
    assert bl.evaluate_rule(DOC, rule) == ("fail", 21)  # only the offending value
    rule = BaselineRule(path="service[*].port", operator="min", value=1)
    assert bl.evaluate_rule(DOC, rule) == ("pass", [23, 21])
    rule = BaselineRule(path="service[protocol=http]", operator="present")
    assert bl.evaluate_rule(DOC, rule) == ("fail", [])


def test_known_defaults_findings():
    dev = sel_relay()
    findings = bl.compare_device(dev, SEL_FACTORY, timestamp=T1) + bl.compare_device(
        dev, SEL_VENDOR, timestamp=T1
    )
    by_id = {f.rule_id: f for f in findings}
    assert len(by_id) == 7
    # the device still has the factory values
    for rule_id in ("sel.default.telnet-port", "sel.default.rid", "sel.default.tid"):
        assert by_id[rule_id].result == "pass"
        assert not by_id[rule_id].severity
        assert not by_id[rule_id].reason
    # hardening checks fail
    for rule_id in (
        "sel.service.telnet.absent",
        "sel.accounts.default-credentials",
        "sel.identity.rid-changed",
        "sel.iec61850.goose.signed",
    ):
        assert by_id[rule_id].result == "fail", rule_id
        assert by_id[rule_id].difference == "mismatch"
    finding = by_id["sel.identity.rid-changed"]
    assert finding.reason == "Relay ID is still the factory default FEEDER 1"
    assert finding.severity == "low"
    assert finding.expected == json.dumps(FACTORY_RID, sort_keys=True)
    assert finding.actual == "FEEDER 1"
    assert finding.baseline_kind == "vendor_recommended"
    assert finding.timestamp == T1
    assert by_id["sel.accounts.default-credentials"].alert

    # a changed relay ID fails the factory rule ("changed from factory default")
    changed = sel_relay()
    changed.name = "BAY 7 FEEDER"
    factory = {f.rule_id: f for f in bl.compare_device(changed, SEL_FACTORY)}
    assert factory["sel.default.rid"].result == "fail"
    assert factory["sel.default.rid"].severity == "info"
    event = factory["sel.default.rid"].gen_elastic_content(changed)["event"]
    assert event["action"] == "baseline-changed-from-default"
    assert event["kind"] == "state"

    # passed findings can be omitted
    assert bl.compare_device(dev, SEL_FACTORY, include_passed=False) == []


def test_disabled_rules_are_skipped():
    baseline = Baseline(
        id="b",
        rules=[
            BaselineRule(path="name", operator="present", enabled=False),
            BaselineRule(path="nope", operator="present"),
        ],
    )
    findings = bl.compare_device(sel_relay(), baseline)
    assert [(f.rule_id, f.result) for f in findings] == [("nope:present", "fail")]
    assert findings[0].category == "settings"  # default category of unknown paths


def test_rule_reason_template_is_safe():
    templates = [
        "{path} is {actual}, expected {expected} {unknown}",
        "{path} {0}",  # positional field: kept as is
        "{path} {unclosed",  # invalid format string: kept as is
    ]
    baseline = Baseline(
        id="b",
        rules=[
            BaselineRule(path="name", operator="equals", value="X", reason=t) for t in templates
        ],
    )
    reasons = [f.reason for f in bl.compare_device(sel_relay(), baseline)]
    assert reasons == ["name is FEEDER 1, expected X {unknown}", "{path} {0}", "{path} {unclosed"]


# --------------------------------------------------------------------------- #
# Snapshot comparison
# --------------------------------------------------------------------------- #
def test_snapshot_identical_device_has_no_findings():
    dev = sel_relay()
    baseline = _snapshot(dev)
    assert bl.compare_device(_exported(dev), baseline) == []
    # JSON round trip of the baseline (as saved to a file)
    loaded = Baseline.parse_raw(baseline.json(exclude_defaults=True))
    assert loaded.expected is not None
    assert loaded == Baseline.parse_raw(loaded.json(exclude_defaults=True))
    assert bl.compare_device(_exported(dev), loaded) == []


def test_snapshot_differences():
    dev = sel_relay()
    dev.files[0].hash.sha256 = "A" * 64
    baseline = _snapshot(dev)
    cur = sel_relay()
    cur.firmware.version = "R517"
    cur.store("service", Service(protocol="http", port=80, status="open"))
    cur.service = [s for s in cur.service if s.protocol != "ftp"]
    cur.files[0].hash.sha256 = "B" * 64
    cur.iec61850.publications[0].conf_rev = 3
    # volatile values are ignored
    cur.interface[0].statistics.ingress.bytes = 1
    cur.interface[0].statistics.timestamp = T1
    cur.clock.time = T1 + timedelta(seconds=5)
    cur.clock.observed = T1
    cur.label = "relay-1"

    findings = bl.compare_device(_exported(cur), baseline, timestamp=T1)
    diffs = _diffs(findings)
    assert ("change", "firmware.version") in diffs
    assert ("unexpected", "service[protocol=http,port=80]") in diffs
    assert ("missing", "service[protocol=ftp,port=21]") in diffs
    assert ("change", "iec61850.publications[type=GOOSE,ld_inst=PRO,name=gcbTrip].conf_rev") in (
        diffs
    )
    assert ("change", "files[path=/SETTINGS/SET_1.TXT].hash.sha256") in diffs
    for _, path in diffs:
        assert "statistics" not in path
        assert not path.startswith(("clock", "label", "related", "id"))

    by_path = {f.path: f for f in findings}
    fw = by_path["firmware.version"]
    assert (fw.category, fw.severity, fw.result) == ("firmware", "high", "fail")
    assert fw.expected == "R516"
    assert fw.actual == "R517"
    assert fw.reason == "firmware.version changed compared to baseline 'relay-1 first pull'"
    assert not fw.rule_id
    http = by_path["service[protocol=http,port=80]"]
    assert http.category == "ports_services"
    assert json.loads(http.actual)["protocol"] == "http"


def test_snapshot_custom_ignore():
    dev = sel_relay()
    cur = sel_relay()
    cur.firmware.version = "R517"
    cur = _exported(cur)
    assert _diffs(bl.compare_device(cur, _snapshot(dev))) == {("change", "firmware.version")}
    assert bl.compare_device(cur, _snapshot(dev, ignore=["firmware.version"])) == []
    assert bl.compare_device(cur, _snapshot(dev, ignore=["firm*"])) == []


def test_snapshot_observed_vs_partial_kinds():
    dev = sel_relay()
    cur = sel_relay()
    cur.os.name = "VxWorks"  # a value the snapshot does not have
    cur = _exported(cur)
    assert _diffs(bl.compare_device(cur, _snapshot(dev, "first_observed"))) == {
        ("unexpected", "os")
    }
    assert _diffs(bl.compare_device(cur, _snapshot(dev, "previous_observed"))) == {
        ("unexpected", "os")
    }
    # engineer/factory snapshots only check what they specify ...
    partial = Baseline(id="golden", kind="engineer_provided", expected=DeviceData(name="FEEDER 1"))
    partial.expected.firmware.version = "R516"
    assert bl.compare_device(cur, partial) == []
    cur.firmware.version = "R517"
    assert _diffs(bl.compare_device(cur, partial)) == {("change", "firmware.version")}
    # ... but new list items are always reported
    partial.expected.store("service", Service(protocol="telnet", port=23))
    diffs = _diffs(bl.compare_device(cur, partial))
    assert ("unexpected", "service[protocol=ftp,port=21]") in diffs
    assert ("change", "firmware.version") in diffs


def test_snapshot_volatile_files_and_relationships():
    dev = sel_relay()
    dev.store("files", File(path="/logs/SER.TXT", category={"event_record"}, size=10))
    baseline = _snapshot(dev)

    cur = sel_relay()
    cur.store("files", File(path="/logs/SER.TXT", category={"event_record"}, size=99))
    cur = _exported(cur)
    # observed-only peers come and go, configured ones are reported when missing
    assert {"config"} in [r.evidence for r in cur.relationships]
    cur.relationships = [r for r in cur.relationships if "config" in r.evidence]
    assert bl.compare_device(cur, baseline) == []

    cur.files = [f for f in cur.files if f.path.as_posix() != "/logs/SER.TXT"]
    cur.relationships = []
    diffs = _diffs(bl.compare_device(cur, baseline))
    assert ("missing", "files[path=/logs/SER.TXT]") in diffs
    missing_rels = [p for d, p in diffs if p.startswith("relationships")]
    assert len(missing_rels) == 1  # the configured DNP3 master only

    # a NEW peer is reported, even if only observed
    new = sel_relay()
    new.store(
        "relationships",
        Relationship(
            protocol="modbus_tcp",
            remote=RelationshipEndpoint(ip="198.51.100.7", port=502),
            evidence={"netstat"},
        ),
    )
    diffs = _diffs(bl.compare_device(_exported(new), baseline))
    assert [d for d, p in diffs if p.startswith("relationships")] == ["unexpected"]


def test_snapshot_new_volatile_files_are_not_reported():
    dev = sel_relay()
    dev.store("files", File(path="/EVENTS/HR_1.CEV", category={"event_record"}, size=100))
    baseline = _snapshot(dev, kind="previous_observed")
    cur = sel_relay()
    cur.store("files", File(path="/EVENTS/HR_1.CEV", category={"event_record"}, size=100))
    cur.store("files", File(path="/EVENTS/HR_2.CEV", category={"event_record"}, size=100))
    cur.store("files", File(path="/LOGS/SYSLOG.TXT", category={"log"}, size=5))
    assert bl.compare_device(_exported(cur), baseline) == []
    # other new files are still reported
    cur.store("files", File(path="/SETTINGS/SET_9.TXT", category={"configuration"}))
    assert _diffs(bl.compare_device(_exported(cur), baseline)) == {
        ("unexpected", "files[path=/SETTINGS/SET_9.TXT]")
    }


def _routes_device(*cache_destinations: str, static=("0.0.0.0/0",), module=False) -> DeviceData:
    from peat.data.models import Route

    dev = DeviceData(ip="192.0.2.40", id="192.0.2.40", name="FGT")
    # a configured peer, so the relationships list never disappears entirely
    dev.store(
        "relationships",
        Relationship(
            type="depends_on",
            protocol="dns",
            remote=RelationshipEndpoint(ip="192.0.2.53", role="dns_server"),
            evidence={"config"},
        ),
    )
    target = DeviceData(slot="1", name="mod1") if module else dev
    for dst in static:
        target.store(
            "routes",
            Route(destination=dst, gateway="192.0.2.1", interface="port1", type="static"),
        )
    for dst in cache_destinations:  # FortiGate "diagnose ip rtcache list" entries
        target.store(
            "routes",
            Route(destination=dst, gateway="192.0.2.1", interface="port1", type="cache"),
        )
    if module:
        dev.module.append(target)
    return dev


@pytest.mark.parametrize("module", [False, True])
def test_snapshot_route_cache_entries_are_not_compared(module):
    def compare(cur: DeviceData, base: DeviceData) -> set:
        return _diffs(bl.compare_device(_exported(cur), _snapshot(base, kind="previous_observed")))

    base = _routes_device("198.51.100.7", module=module)
    # other cache entries, or none at all
    assert compare(_routes_device("198.51.100.8", module=module), base) == set()
    assert compare(_routes_device(module=module), base) == set()
    assert compare(base, _routes_device(module=module)) == set()
    # only cache entries on one or both sides
    only_cache = _routes_device("198.51.100.7", static=(), module=module)
    assert compare(_routes_device("198.51.100.8", static=(), module=module), only_cache) == set()
    assert compare(_routes_device(static=(), module=module), only_cache) == set()
    # (the gateway of the cache entries is a new routes_via peer, which is reported)
    assert not {
        d
        for d in compare(only_cache, _routes_device(static=(), module=module))
        if "routes" in d[1]
    }

    # the other routes are still compared, as if the cache entries did not exist
    prefix = "module[slot=1].routes" if module else "routes"
    more = _routes_device("198.51.100.8", static=("0.0.0.0/0", "203.0.113.0/24"), module=module)
    assert compare(more, base) == {
        ("unexpected", f"{prefix}[destination=203.0.113.0/24,gateway=192.0.2.1,interface=port1]")
    }
    assert compare(base, more) == {
        ("missing", f"{prefix}[destination=203.0.113.0/24,gateway=192.0.2.1,interface=port1]")
    }
    # (a route table with only cache entries is compared like an empty one)
    assert compare(only_cache, base) == {("missing", prefix)}
    assert compare(base, only_cache) == {("unexpected", prefix)}


def _module_device(when, pid: int) -> DeviceData:
    from peat.data.models import Indicator, Interface

    dev = DeviceData(ip="192.0.2.30", id="192.0.2.30", name="CLX")
    dev.store("interface", Interface(name="eth0", ip="192.0.2.30", type="ethernet"))
    dev.store(
        "service",
        Service(protocol="ssh", port=22, transport="tcp", status="open", process_pid=pid),
        interface_lookup={"name": "eth0"},
    )
    for slot in ("0", "1"):
        mod = DeviceData(slot=slot, name=f"mod{slot}")
        mod.store(
            "indicators",
            Indicator(type="status_flag", name="cip_state", state="on", timestamp=when),
        )
        mod.store("interface", Interface(name="port1", type="ethernet", connected=slot == "0"))
        mod.store(
            "service",
            Service(protocol="http", port=80, status="open", process_pid=pid),
            interface_lookup={"name": "port1"},
        )
        dev.module.append(mod)
    return dev


def test_snapshot_volatile_values_of_modules_and_interface_services():
    baseline = _snapshot(_module_device(T0, pid=100), kind="previous_observed")
    cur = _module_device(T1, pid=200)
    cur.module[0].interface[0].connected = False
    for svc in [*cur.service, *cur.interface[0].services, *cur.module[0].service]:
        svc.status = "closed"
    assert bl.compare_device(_exported(cur), baseline) == []
    for pattern in (
        "module.indicators.timestamp",
        "interface.services.status",
        "module.interface.services.process_pid",
        "service.process_pid",
    ):
        assert bl.is_ignored(pattern, bl.DEFAULT_IGNORE), pattern


def test_device_type_profile_ignores_per_unit_service_and_module_addresses():
    from peat.data.models import Interface

    def unit(ip: str) -> DeviceData:
        dev = DeviceData(ip=ip, id=ip, name="M1")
        dev.description.vendor.id = "X"
        dev.description.model = "Y"
        dev.store("interface", Interface(name="eth0", ip=ip, type="ethernet"))
        dev.store(
            "service",
            Service(protocol="ssh", port=22, transport="tcp", listen_address=ip),
            interface_lookup={"name": "eth0"},
        )
        mod = DeviceData(slot="1")
        mod.store(
            "interface",
            Interface(
                name="port1",
                ip=ip.replace("192.0.2", "198.51.100"),
                mac=f"00:00:5E:00:53:{ip[-2:]}",
            ),
        )
        dev.module.append(mod)
        return _exported(dev)

    profile = Baseline(
        id="x-y-typical",
        kind="approved",
        scope="device_type",
        selector=BaselineSelector(vendor_id="X", model="Y"),
        expected=bl.device_type_profile([unit("192.0.2.10")]),
    )
    assert bl.compare_device(unit("192.0.2.11"), profile) == []


def test_device_type_profile_compares_wildcard_and_loopback_listen_addresses():
    def unit(n: int, listen: str) -> DeviceData:
        """Unit n with SSH and a module web server listening on ``listen`` (own IP if "")."""
        ip = f"192.0.2.{n}"
        dev = DeviceData(ip=ip, id=ip, serial_number=f"SN{n}")
        dev.description.vendor.id = "X"
        dev.description.model = "Y"
        dev.store(
            "service",
            Service(protocol="ssh", port=22, transport="tcp", listen_address=listen or ip),
        )
        mod = DeviceData(slot="1")
        mod.store("service", Service(protocol="http", port=80, listen_address=listen or ip))
        dev.module.append(mod)
        return _exported(dev)

    loopback = [unit(1, "127.0.0.1"), unit(2, "127.0.0.1")]
    assert bl.varying_paths(loopback) == []
    profile = Baseline(
        id="x-y-typical",
        kind="approved",
        scope="device_type",
        selector=BaselineSelector(vendor_id="X", model="Y"),
        expected=bl.device_type_profile(loopback),
    )
    assert bl.compare_device(unit(3, "127.0.0.1"), profile) == []
    ssh = "service[protocol=ssh,port=22].listen_address"
    http = "module[slot=1].service[protocol=http,port=80].listen_address"
    # loopback -> all addresses: the services are now exposed on the network
    assert _diffs(bl.compare_device(unit(3, "0.0.0.0"), profile)) == {
        ("change", ssh),
        ("change", http),
    }
    # loopback -> the address of the unit itself
    assert _diffs(bl.compare_device(unit(3, ""), profile)) == {("missing", ssh), ("missing", http)}

    # the address of each unit itself is per-unit identity, a wildcard address is not
    own = bl.device_type_profile([unit(1, ""), unit(2, "")])
    assert "listen_address" not in bl.device_to_doc(own)["service"][0]
    wildcard = bl.device_type_profile([unit(1, "::")])
    assert bl.device_to_doc(wildcard)["service"][0]["listen_address"] == "::"


def test_snapshot_ignores_relationship_client_ports():
    def session(direction: str, client_port: int, server_port: int = 20000) -> DeviceData:
        """A DNP3 session: the device is the server (ingress) or the client (egress)."""
        dev = DeviceData(ip="192.0.2.10", id="192.0.2.10")
        ingress = direction == "ingress"
        dev.store(
            "relationships",
            Relationship(
                protocol="dnp3",
                transport="tcp",
                direction=direction,
                local=RelationshipEndpoint(
                    ip="192.0.2.10", port=server_port if ingress else client_port
                ),
                remote=RelationshipEndpoint(
                    ip="192.0.2.50", port=client_port if ingress else server_port
                ),
                evidence={"config", "netstat"},
            ),
        )
        return _exported(dev)

    for direction in ("ingress", "egress"):
        baseline = _snapshot(session(direction, 51234), kind="previous_observed")
        # a new ephemeral client port: the same relationship
        assert bl.compare_device(session(direction, 51987), baseline) == [], direction
        # a new server port: another relationship
        diffs = _diffs(bl.compare_device(session(direction, 51987, 20001), baseline))
        assert sorted(d for d, _ in diffs) == ["missing", "unexpected"], direction


def test_snapshot_aligns_list_items_without_ignored_values():
    from peat.data.models import Interface, NetworkStatistics, NetworkTraffic

    def unit(ip: str, mac: str, packets: int, connected: bool) -> DeviceData:
        dev = DeviceData(ip=ip, id=ip)
        dev.description.vendor.id = "X"
        dev.description.model = "Y"
        # no name: aligned by the values that are compared
        dev.interface.append(
            Interface(
                type="ethernet",
                ip=ip,
                mac=mac,
                connected=connected,
                statistics=NetworkStatistics(ingress=NetworkTraffic(packets=packets)),
            )
        )
        return _exported(dev)

    first = unit("10.0.0.1", "00:11:22:33:44:55", 100, True)
    profile = Baseline(
        id="x-y-typical",
        kind="first_observed",
        scope="device_type",
        selector=BaselineSelector(vendor_id="X", model="Y"),
        expected=bl.device_type_profile([first]),
    )
    assert bl.compare_device(first, profile) == []
    assert bl.compare_device(unit("10.0.0.2", "00:11:22:33:44:66", 999, False), profile) == []

    def serial(packets: int) -> DeviceData:
        dev = DeviceData(ip="10.0.0.9", id="10.0.0.9")
        dev.interface.append(
            Interface(
                type="serial",
                baudrate=9600,
                statistics=NetworkStatistics(ingress=NetworkTraffic(packets=packets)),
            )
        )
        return _exported(dev)

    baseline = _snapshot(serial(1))
    assert bl.compare_device(serial(2), baseline) == []
    changed = serial(2)
    changed.interface[0].baudrate = 19200
    assert {d for d, _ in _diffs(bl.compare_device(changed, baseline))} == {
        "missing",
        "unexpected",
    }


def test_snapshot_parse_input_files_are_not_device_files(tmp_path):
    def parsed(scd: str, content: bytes = b"<SCL/>") -> DeviceData:
        """Device from 'peat parse' of an SCL file (IEC61850SCL stores it like this)."""
        path = tmp_path / scd
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        dev = DeviceData(ip="192.0.2.60", id="192.0.2.60", name="PROT1")
        dev.iec61850.ied_name = "PROT1"
        dev.iec61850.scl_file = path.as_posix()
        dev.store("files", File(local_path=path, category={"configuration", "iec61850"}))
        dev.store("files", File(path="/SETTINGS/SET_61850.CID", category={"configuration"}))
        return _exported(dev)

    baseline = _snapshot(parsed("v1/substation.scd"), kind="engineer_provided")
    # the same SCD file parsed from another folder and under another name
    assert bl.compare_device(parsed("v2/substation_v2.scd"), baseline) == []
    observed = _snapshot(parsed("v1/substation.scd"))
    assert bl.compare_device(parsed("v2/substation_v2.scd"), observed) == []

    # an input file at the same path is still compared ...
    diffs = _diffs(bl.compare_device(parsed("v1/substation.scd", b"<SCL></SCL>"), observed))
    scd = f"files[path={(tmp_path / 'v1/substation.scd').resolve().as_posix()}]"
    assert ("change", f"{scd}.hash.sha256") in diffs
    assert {d for d, _ in diffs} == {"change"}
    assert all(p.startswith(scd) for _, p in diffs)
    # ... and so are the device files
    cur = parsed("v3/substation.scd")
    cur.files = [f for f in cur.files if f.local_path]
    assert _diffs(bl.compare_device(cur, baseline)) == {
        ("missing", "files[path=/SETTINGS/SET_61850.CID]")
    }


def test_snapshot_operating_mode_change_is_high():
    dev = sel_relay()
    dev.key_switch = "RUN"
    cur = sel_relay()
    cur.key_switch = "PROG"
    (finding,) = bl.compare_device(_exported(cur), _snapshot(dev))
    assert (finding.path, finding.severity, finding.category) == ("key_switch", "high", "settings")


def test_selector_mismatch_has_no_findings():
    other = DeviceData(ip="198.51.100.1", type="Relay")
    other.description.vendor.id = "Siemens"
    assert bl.compare_device(other, SEL_FACTORY) == []
    assert bl.compare_device(other, SEL_VENDOR) == []
    assert bl.compare_device(other, _snapshot(sel_relay())) == []


def test_snapshot_truncation(mocker, caplog):
    mocker.patch.object(bl, "MAX_FINDINGS_PER_BASELINE", 2)
    dev = sel_relay()
    baseline = _snapshot(dev)
    cur = sel_relay()
    cur.firmware.version = "R517"
    cur.os.name = "VxWorks"
    cur.serial_number = "1234"
    assert len(bl.compare_device(_exported(cur), baseline)) == 2
    assert "Truncated 3 differences for baseline relay-1" in caplog.text


def test_finding_ecs_values():
    dev = sel_relay()
    changed = sel_relay()
    changed.firmware.version = "R517"
    changed.store("service", Service(protocol="http", port=80))
    changed.service = [s for s in changed.service if s.protocol != "ftp"]
    changed = _exported(changed)
    findings = (
        bl.compare_device(changed, SEL_FACTORY)
        + bl.compare_device(changed, SEL_VENDOR)
        + bl.compare_device(changed, _snapshot(dev, "first_observed"))
        + bl.compare_device(changed, _snapshot(dev, "previous_observed"))
    )
    kinds = set()
    for finding in findings:
        doc = finding.gen_elastic_content(changed)
        event = doc["event"]
        kinds.add(event["kind"])
        assert event["kind"] in ECS_EVENT_VALUES["kind"]
        assert set(event["category"]) <= ECS_EVENT_VALUES["category"]
        assert set(event["type"]) <= ECS_EVENT_VALUES["type"]
        assert event["dataset"] == "peat.baseline"
        if finding.severity:
            assert 1 <= event["severity"] <= 5
        else:
            assert "severity" not in event
        assert "version" not in doc.get("rule", {})
        assert doc["host"]["ip"] == "192.0.2.10"
    assert kinds == {"alert", "state", "event"}


# --------------------------------------------------------------------------- #
# Storing findings
# --------------------------------------------------------------------------- #
def test_store_findings_replaces_findings_of_the_same_baseline():
    dev = sel_relay()
    first = bl.compare_device(dev, SEL_VENDOR, timestamp=T0)
    other = bl.compare_device(dev, SEL_FACTORY, timestamp=T0)
    bl.store_findings(dev, first + other)
    assert len(dev.baseline_findings) == len(first) + len(other)

    dev.name = "BAY 7"
    again = bl.compare_device(dev, SEL_VENDOR, timestamp=T1)
    bl.store_findings(dev, again)
    vendor = [f for f in dev.baseline_findings if f.baseline_id == SEL_VENDOR.id]
    assert len(vendor) == len(again)
    assert {f.timestamp for f in vendor} == {T1}
    rid = next(f for f in vendor if f.rule_id == "sel.identity.rid-changed")
    assert rid.result == "pass"  # no stale "fail" left next to it
    assert len([f for f in dev.baseline_findings if f.baseline_id == SEL_FACTORY.id]) == len(other)
    # findings are not part of the host document or the summary
    assert "baseline_findings" not in dev.elastic()
    assert "baseline_findings" not in dev.export_summary()
    assert dev.export()["baseline_findings"]


# --------------------------------------------------------------------------- #
# Device type profiles
# --------------------------------------------------------------------------- #
def _unit(n: int, firmware: str = "R516") -> DeviceData:
    dev = sel_relay()
    dev.ip = f"192.0.2.{20 + n}"
    dev.id = dev.ip
    dev.name = f"BAY {n}"
    dev.serial_number = f"SN{n}"
    for iface in dev.interface:
        if iface.ip:
            iface.ip = dev.ip
    dev.files[0].hash.sha256 = f"{n}" * 64
    dev.firmware.version = firmware
    return _exported(dev)


def _profile(devices: list[DeviceData]) -> Baseline:
    return Baseline(
        id="sel-351s-typical",
        kind="first_observed",
        scope="device_type",
        selector=BaselineSelector(vendor_id="SEL", model="351S"),
        expected=bl.device_type_profile(devices),
        ignore=bl.varying_paths(devices),
    )


def test_device_type_profile_removes_identity():
    profile = bl.device_type_profile([_unit(0)])
    doc = bl.device_to_doc(profile)
    for key in ("ip", "name", "serial_number", "relationships", "id", "related", "extra"):
        assert key not in doc, key
    assert "ip" not in doc["interface"][0]
    assert "hash" not in doc["files"][0]
    assert "logic" not in doc  # only had a name: removed entirely
    assert doc["firmware"]["version"] == "R516"
    assert doc["description"]["model"] == "351S"
    # every unit matches a profile built from one of them
    baseline = _profile([_unit(0)])
    for n in range(1, 4):
        assert bl.compare_device(_unit(n), baseline) == [], n


def test_device_type_profile_of_several_units():
    units = [_unit(0), _unit(1), _unit(2, firmware="R517")]
    assert bl.varying_paths(units) == ["firmware.version"]
    assert bl.varying_paths(units[:1]) == []
    baseline = _profile(units)
    assert "firmware" not in bl.device_to_doc(baseline.expected)  # not shared
    for unit in units:
        assert bl.compare_device(unit, baseline) == []

    odd = _unit(5, firmware="R999")
    odd.store("service", Service(protocol="http", port=80))
    assert _diffs(bl.compare_device(odd, baseline)) == {
        ("unexpected", "service[protocol=http,port=80]")
    }


def test_intersect_docs():
    docs = [
        {"a": 1, "b": {"c": 2, "d": 3}, "service": [{"protocol": "x", "port": 1}], "e": [1]},
        {"a": 1, "b": {"c": 2, "d": 4}, "service": [{"protocol": "x", "port": 1}], "e": [2]},
    ]
    assert bl.intersect_docs(docs) == {
        "a": 1,
        "b": {"c": 2},
        "service": [{"protocol": "x", "port": 1}],
    }
    assert bl.intersect_docs([{"a": 1}, {"a": 2}]) == {}


def test_strip_paths():
    doc = {"logic": {"name": "x"}, "interface": [{"ip": "1"}, {"ip": "2", "mtu": 1}], "a": {}}
    assert bl.strip_paths(doc, ("logic.name", "interface.ip")) == {
        "interface": [{"mtu": 1}],
        "a": {},
    }


def test_index_items_numbers_duplicates():
    items = [{"name": "a"}, {"name": "a"}, {"other": 1}]
    index = bl.index_items("users", items)
    assert set(index) == {
        ((("name", "a"),), 0),
        ((("name", "a"),), 1),
        ((("json", '{"other": 1}'),), 0),
    }
    assert bl.item_label("service", {"protocol": "http", "port": 80}) == "protocol=http,port=80"
    assert bl.item_key("files", "scalar") == ("value", '"scalar"')


# --------------------------------------------------------------------------- #
# Known defaults declared by modules
# --------------------------------------------------------------------------- #
def _check_known_defaults(module: type) -> int:
    """Check the known-defaults contract of a module, return the number of rules."""
    empty_doc = bl.device_to_doc(DeviceData())
    declared = vars(module).get("known_defaults", None) or []
    assert len(declared) <= 2, module.__name__
    count = 0
    for baseline in module.get_known_defaults():
        assert baseline.id, module.__name__
        assert baseline.kind in ("factory_default", "vendor_recommended"), baseline.id
        assert baseline.expected is None, baseline.id
        assert baseline.rules, baseline.id
        rule_ids = [rule.id for rule in baseline.rules]
        assert all(rule_ids), baseline.id
        assert len(set(rule_ids)) == len(rule_ids), baseline.id
        for rule in baseline.rules:
            bl.split_path(rule.path)  # raises ValueError if invalid
            assert rule.operator
            assert bl.evaluate_rule(empty_doc, rule)[0] != "error", rule.id
            count += 1
    return count


def test_known_default_rule_paths_parse():
    """
    Contract of the known defaults declared by modules: every rule path uses the
    path syntax, at most a factory_default and a vendor_recommended baseline per
    module, rules only, unique rule IDs, and rules that evaluate without errors.
    """
    for module in module_api.classes:
        _check_known_defaults(module)

    class _SELLike(DeviceModule):
        vendor_id = "SEL"
        device_type = "Relay"
        known_defaults = [SEL_FACTORY, SEL_VENDOR]

    assert _check_known_defaults(_SELLike) == 7

    class _Broken(DeviceModule):
        known_defaults = [
            Baseline(id="x", kind="vendor_recommended", rules=[{"id": "x.y", "path": "a[b"}])
        ]

    with pytest.raises(ValueError, match="invalid baseline path"):
        _check_known_defaults(_Broken)
