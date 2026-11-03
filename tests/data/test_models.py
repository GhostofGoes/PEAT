import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from peat import Elastic, PeatError, config
from peat.data.models import (
    OS,
    Description,
    DeviceData,
    Event,
    Geo,
    Interface,
    LatLon,
    Logic,
    Register,
    Service,
    Tag,
    Vendor,
)


def test_device_data_dict():
    dev = DeviceData(name="n")
    assert isinstance(dev.dict(), dict)
    assert dev.dict()["name"] == "n"
    assert len(dev.dict(exclude_defaults=True)) == 1


def test_device_data_purge_duplicates():
    data = DeviceData()
    data.service = [
        Service(port=80),
        Service(port=80, protocol="http"),
        Service(port=80, protocol="http", enabled=True),
        Service(port=8080, protocol="http"),
        Service(),
        Service(port=161, protocol="snmp"),
        Service(protocol="snmp"),
        Service(enabled=False),
        Service(port=80),
        Service(port=80),
        Service(),
        Service(port=80),
    ]
    deduped = [
        Service(port=80, protocol="http", enabled=True),
        Service(port=161, protocol="snmp"),
        Service(port=8080, protocol="http"),
        Service(enabled=False),
    ]
    assert data.purge_duplicates() is None
    assert data.service == deduped


def test_device_data_export(mocker, tmp_path, assert_glob_path):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})

    logic_text = "original logic"
    dev = DeviceData(
        name="tn",
        description=Description(product="prod"),
        logic=Logic(parsed="parsed logic", original=logic_text),
    )

    res = dev.export()

    assert "original" not in res["logic"]
    assert res["logic"]["parsed"]
    assert res["name"] == "tn"
    assert "_out_dir" not in res
    assert "modules" not in res
    assert res["description"]["product"] == "prod"

    assert dev.export(include_original=True)["logic"]["original"] == logic_text

    assert "logic" not in dev.export(exclude_fields=["logic"])

    assert dev.export(only_fields=["name"]) == {"name": "tn"}

    logic_path = assert_glob_path(dev._out_dir, "logic.txt")
    assert logic_path.read_text(encoding="utf-8") == logic_text


def test_device_data_export_to_files(mocker, tmp_path, assert_glob_path):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})
    base = Path(tmp_path, "export_to_files_test")

    dev = DeviceData(
        id="export_to_files_test",
        logic={"original": "123"},
        interface=[{"type": "ethernet", "ip": "192.168.2.2"}],  # trigger interface model jsonl
    )

    assert not base.exists()

    assert dev.export_to_files() is True

    assert base.is_dir()
    fd_data_path = assert_glob_path(base, "device-data-full.json")
    dev_data_path = assert_glob_path(base, "device-data-summary.json")

    # load data from files as JSON and compare against exported data
    fd_data = json.loads(fd_data_path.read_text())

    # check for timestamp and remove it
    assert fd_data.pop("created", None) is not None
    assert dev.export(include_original=True) == fd_data

    dev_data = json.loads(dev_data_path.read_text())
    assert "original" not in dev_data["logic"]

    # test data model splitting
    jsonl_data_path = assert_glob_path(base, "device-data-interface.jsonl")
    lines = jsonl_data_path.read_text().strip().split("\n")
    interface_json = json.loads(lines[0])

    assert interface_json["type"] == "ethernet"
    assert interface_json["ip"] == "192.168.2.2"


def test_minified_device_data_export_to_files(mocker, tmp_path, assert_glob_path):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})
    base = Path(tmp_path, "export_to_files_test")

    dev = DeviceData(
        id="export_to_files_test",
        logic={"original": "123"},
        interface=[{"type": "ethernet", "ip": "192.168.2.2"}],  # trigger interface model jsonl
    )
    assert not base.exists()

    assert dev.export_to_files() is True

    assert base.is_dir()
    fd_data_path = assert_glob_path(base, "device-data-full.json")

    # load data from file and check for pretty printing
    fd_data = fd_data_path.read_text()

    # default is minified
    assert "\n" not in fd_data
    assert ": " not in fd_data
    assert ", " not in fd_data


def test_device_data_elastic():
    dev_id = "elastic_test"
    geo = Geo(location=LatLon(lat=-40.002, lon=0.00))
    dev = DeviceData(id=dev_id, type="RTU", os=OS(name="linux"), geo=geo)
    service = Service(protocol="modbus", enabled=False, port=502)
    dev.store("service", service)
    event = Event(sequence=0, ingested=datetime.now(UTC))
    dev.store("event", event)
    assert dev.elastic() == {
        "id": dev_id,
        "type": "RTU",
        "os": {"full": "linux", "name": "linux"},
        "related": {"ports": {502}, "protocols": {"modbus"}},
        "service": [service.dict(exclude_defaults=True)],
        "geo": geo.dict(exclude_defaults=True),
        "event": [{"provider": dev_id, "kind": {"event"}, **event.dict(exclude_defaults=True)}],
    }


def test_device_data_json():
    dev = DeviceData(id="testing123json", type="PLC")
    res = dev.json()
    assert isinstance(res, str)
    assert "PLC" in res
    assert json.loads(res)["type"] == "PLC"

    indent_res = dev.json(indent=4)
    assert isinstance(indent_res, str)
    assert "PLC" in indent_res
    assert json.loads(indent_res)["type"] == "PLC"
    assert "    " in indent_res


def test_device_data_export_to_elastic(mocker):
    mocker.patch.dict(config["CONFIG"], {"ELASTIC_TIMEOUT": 0.1})
    dev = DeviceData(id="test_es_export")
    assert dev.export_to_elastic() is False
    assert dev.export_to_elastic(elastic=Elastic("localhost:56789")) is False


def test_device_data_gen_elastic_content():
    dev = DeviceData(type="PLC", id="gen_elastic_test")
    content = dev.gen_elastic_content()
    assert content["@timestamp"]
    assert content["message"]
    assert content["tags"]
    assert content["host"] == dev.elastic()


def test_device_data_get_id():
    populated_dev = DeviceData(ip="192.168.2.2", name="hello")
    assert populated_dev.get_id() == "192.168.2.2"
    empty_dev = DeviceData()
    assert empty_dev.get_id()
    assert empty_dev._cache.get("_rand_id")


def test_device_data_get_comm_id():
    dev = DeviceData()
    dev.serial_port = "port"
    dev.ip = "192.0.2.3"
    assert dev.get_comm_id() == "port"
    assert dev.get_id() != dev.get_comm_id()


def test_device_data_populate_fields():
    # Test network interfaces are being added
    net_dev = DeviceData(serial_port="test_serial_port")
    assert net_dev.populate_fields(network_only=True) is None
    assert net_dev.interface[0].serial_port == "test_serial_port"

    # Test vendor and description fields are being populated
    v = Vendor(id="vendorid")
    desc = Description(brand="somebrand", vendor=v)
    dev = DeviceData(description=desc)
    assert dev.populate_fields() is None
    assert "vendorid" in dev.description.full
    assert "somebrand" in dev.description.full
    assert dev.description.vendor.name == "vendorid"


def test_device_data_write_file(mocker, tmp_path):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})

    base = Path(tmp_path, "write_test")
    assert not base.exists()

    dev = DeviceData(id="write_test")

    write_result = dev.write_file("789", filename="fname.f")
    assert write_result.name == "fname.f"
    assert base.is_dir()
    assert write_result.is_file()
    assert Path(base, "fname.f").read_text("utf-8") == "789"

    sub_dir = base / "test_sub_dir"
    sub_result = dev.write_file(
        data="testingsubdir123", filename="testingsubdir.f", out_dir=sub_dir
    )
    assert sub_result.name == "testingsubdir.f"
    assert sub_result.parent.name == "test_sub_dir"
    assert sub_dir.is_dir()
    assert sub_result.is_file()


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("../../../../escaped.txt", "escaped.txt"),
        ("ok/../../escaped.txt", "escaped.txt"),
        ("/tmp/escaped.txt", "tmp/escaped.txt"),
    ],
)
def test_device_data_write_file_stays_in_out_dir(mocker, tmp_path, filename, expected):
    """File names from a device (FTP listing) can't write outside of the output directory."""
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path / "devices"})
    dev = DeviceData(id="write_test")
    out_dir = dev.get_sub_dir("ftp_files")

    result = dev.write_file("x", filename=filename, out_dir=out_dir)
    assert result == out_dir / expected
    assert result.read_text() == "x"
    assert list(tmp_path.rglob("escaped.txt")) == [result]


@pytest.mark.parametrize("typ", ["logic", "firmware", "boot_firmware"])
def test_device_data_file_read_original(datapath, text_data, typ):
    dev = DeviceData()
    getattr(dev, typ).file.local_path = datapath("test_data.txt")
    dev.populate_fields()
    data = text_data("test_data.txt")
    data = data.encode("utf-8") if typ != "logic" else data
    assert getattr(dev, typ).original == data


@pytest.mark.parametrize(
    ("typ", "ext", "data"),
    [
        ("logic", "txt", "logic_testing123"),
        ("firmware", "bin", b"firmware_testing123"),
        ("boot_firmware", "bin", b"boot_firmware_testing123"),
    ],
)
def test_device_data_file_save_original(mocker, tmp_path, typ, ext, data):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})
    dev = DeviceData(id="store_test")
    getattr(dev, typ).original = data

    dev.populate_fields()

    res = Path(tmp_path, "store_test", f"{typ.replace('_', '-')}.{ext}")
    assert res.is_file()

    assert res.read_text("utf-8") if ext == "txt" else res.read_bytes() == data
    assert getattr(dev, typ).original == data


def test_device_data_retrieve():
    dev = DeviceData(id="retrieve_test")
    with pytest.raises(PeatError):
        dev.retrieve("attrthatdoesnotexist", {})
    assert dev.retrieve("interface", {}) is None
    ip = "192.168.223.223"
    iface_type = "ethernet"
    dev.store("interface", Interface(ip=ip, type=iface_type))
    assert dev.retrieve("interface", {"ip": ip}).ip == ip
    assert dev.retrieve("interface", {"ip": "10.11.12.13"}) is None
    # Ensure it still returns right result when there are multiple entries
    dev.store("interface", Interface(ip="172.16.17.18", type=iface_type))
    assert dev.retrieve("interface", {"ip": ip}).ip == ip
    # Retrieving multiple values (in this case, all ethernet interfaces)
    assert len(dev.retrieve("interface", {"type": iface_type})) == 2


def test_device_data_store_bad_value():
    """test value is not base model raises exception."""
    dev = DeviceData()
    with pytest.raises(PeatError):
        dev.store("event", {"bad": "bad"})


def test_device_data_store_interface_autopopulate(mocker):
    mocker.patch.dict(config["CONFIG"], {"RESOLVE_HOSTNAME": True, "RESOLVE_IP": True})
    mgr_ip = DeviceData(name="test_int_ip")
    ip = "127.0.0.1"
    # NOTE (cegoes): VMWare Horizon messes with hosts file on Windows (*sigh*)\
    # NOTE 2 (cegoes, 12/12/2022): on Windows server, 127.0.0.1 resolves to
    # hostname on the Windows CI server. Just disabling check for now.
    # (03/14/2022): k8s does as well
    # localhosts = ["localhost", "view-localhost", "kubernetes.docker.internal"]

    mgr_ip.store("interface", Interface(ip=ip))
    assert mgr_ip.id == ip
    assert mgr_ip.ip == ip
    # assert mgr_ip.hostname in localhosts
    assert len(mgr_ip.interface) == 1

    mgr_host = DeviceData(name="test_int_host")
    mgr_host.store("interface", Interface(hostname="localhost"))
    assert mgr_host.id == ip
    assert mgr_host.ip == ip
    # assert mgr_host.hostname in localhosts
    assert len(mgr_host.interface) == 1


def test_device_data_store_service():
    dev = DeviceData(name="test_int_svc")
    ip = "127.0.0.1"
    test_svc = Service(protocol="http", port=80, transport="tcp", enabled=True)

    dev.store("interface", Interface(ip=ip))
    dev.store(
        key="service",
        value=test_svc,
        interface_lookup={"ip": ip},  # Interface for the service
    )

    assert len(dev.service) == 1
    assert len(dev.interface[0].services) == 1
    svc = dev.interface[0].services[0]
    # ensure service on interface matches that in dev.services
    assert svc == dev.service[0]
    assert svc == test_svc  # check it matches original


def test_device_data_store_register():
    dev = DeviceData(name="test_store_register")
    dev.store("registers", Register(protocol="dnp3", address="10000"))
    assert len(dev.registers) == 1
    assert dev.registers[0].protocol == "dnp3"
    reg = Register(address="23", tag="var_rtu-8_IO")
    dev.store("registers", reg)
    assert len(dev.registers) == 2
    assert dev.registers[1] == reg


def test_device_data_store_tag():
    dev = DeviceData(name="test_store_tag")
    dev.store("tag", Tag(name="var_rtu-8_I0", type="analog"))
    assert len(dev.tag) == 1
    assert dev.tag[0].type == "analog"
    tag = Tag(io="rtu-8_I0")
    dev.store("tag", tag)
    assert len(dev.tag) == 2
    assert dev.tag[1] == tag


def test_device_data_store_module():
    dev = DeviceData()
    dev.id = "testing"
    io_module = DeviceData(name="digitalIO", type="I/O", slot="1")
    dev.store("module", io_module)
    assert dev.module[0] == io_module
    assert "digitalIO" in str(dev)


def test_device_data_store_append():
    dev = DeviceData(name="test_store_append")
    dev.store(key="tag", value=Tag(name="test_append_tag", type="digital"), append=True)
    assert len(dev.tag) == 1
    assert dev.tag[0].type == "digital"
    tag = Tag(io="append_tag_2")
    dev.store("tag", tag, append=True)
    assert len(dev.tag) == 2
    assert dev.tag[1] == tag


def test_device_data_is_duplicate():
    assert DeviceData().is_duplicate(DeviceData()) is False
    dupe_1 = DeviceData()
    dupe_1.serial_port = "test_port"
    dupe_2 = DeviceData()
    dupe_2.serial_port = "test_port"
    assert dupe_1.is_duplicate(dupe_2) is True
    non_dupe_1 = DeviceData()
    non_dupe_1.ip = "192.0.2.20"
    non_dupe_2 = DeviceData()
    non_dupe_2.ip = "10.0.0.20"
    assert non_dupe_1.is_duplicate(non_dupe_2) is False


def test_device_data_validation_failures():
    dev = DeviceData()
    with pytest.raises(ValueError):
        dev.ip = 0
    with pytest.raises(ValueError):
        dev.ip = "thisisn't a valid IP"
    iface = Interface()
    with pytest.raises(ValueError):
        iface.mtu = -1
    with pytest.raises(ValueError):
        iface.description = "hello"


def test_device_data_validation_clean():
    dev = DeviceData()
    dev.ip = "    192.0.2.1   "
    assert dev.ip == "192.0.2.1"


def test_device_data_label_autopopulate(mocker, examples_path):
    """Hacky test but gets the job done."""
    yml_config = yaml.safe_load(examples_path("peat-config.yaml").read_text())
    mocker.patch.dict(config["CONFIG"], {"HOSTS": yml_config["hosts"]})

    dev = DeviceData(ip="192.168.0.1")
    assert dev.label == "example-host"
    assert dev.comment.startswith("User-specified text")

    assert DeviceData(mac="00:00:00:00:00:00").label == "example-host"
    assert DeviceData(serial_port="COM0").label == "example-host"
    assert DeviceData(name="some-device-name").label == "example-host"
    assert DeviceData(hostname="a-hostname").label == "example-host"

    assert DeviceData(label="test-label").label == "test-label"

    assert not DeviceData(ip="192.168.0.2").label
    assert not DeviceData(ip="192.168.0.2").comment
    assert not DeviceData().label
    assert not DeviceData().comment


# --------------------------------------------------------------------------- #
# Issue #48 data model additions
# --------------------------------------------------------------------------- #
from datetime import timedelta  # noqa: E402
from pathlib import PurePosixPath  # noqa: E402

from pydantic import ValidationError  # noqa: E402

from peat.data.data_utils import dedupe_model_list, merge_models, sort_model_list  # noqa: E402
from peat.data.models import (  # noqa: E402
    Asset,
    Baseline,
    BaselineFinding,
    BaselineProvenance,
    BaselineRule,
    BaselineSelector,
    Clock,
    ConnectionStatistics,
    File,
    HostProcess,
    IEC61850AccessPoint,
    IEC61850HistoryItem,
    IEC61850LogicalDevice,
    Indicator,
    LogicTask,
    NetworkStatistics,
    NetworkTraffic,
    Package,
    Redundancy,
    Relationship,
    RelationshipEndpoint,
    Route,
    TimeSource,
    User,
    Vlan,
    process_file,
)
from peat.data.validators import ECS_EVENT_VALUES  # noqa: E402

from .example_devices import (  # noqa: E402
    SIPROTEC_HOSTS,
    T0,
    T1,
    controllogix,
    fortigate,
    sage_rtu,
    sel_relay,
    siprotec,
)


@pytest.fixture
def siprotec_hosts(mocker):
    mocker.patch.dict(config["CONFIG"], {"HOSTS": SIPROTEC_HOSTS})


def test_new_models_validation():
    assert Vlan(id=100).id == "100"
    assert Vlan(id=" 0100 ").id == "100"
    assert Vlan(id="").id == ""
    assert Vlan.from_hex("064", 4) == Vlan(id="100", priority=4, tagged=True)
    assert Asset(criticality="High").criticality == "high_impact"
    assert Asset(purdue_level="L2").purdue_level == "2"
    assert Asset(purdue_level=2.0).purdue_level == "2"
    assert Asset(purdue_level="3.5").purdue_level == "3.5"
    assert Indicator(name="ALARM", state="unknown").state == ""
    assert Indicator(name="ALARM", state="unknown").value == "unknown"
    red = Indicator(name="LED1", state="Red")
    assert red.state == "on"
    assert red.color == "red"
    assert Indicator(name="DOOR", type="sensor", state="active").state == "on"
    assert Indicator(name="RUN", state="flashing").state == "blinking"
    assert Relationship(protocol="c37.118").protocol == "c37_118"
    assert Service(protocol="iec-104").protocol == "iec104"
    assert NetworkStatistics(protocol="Modbus-TCP").protocol == "modbus_tcp"
    assert Route(destination="default").destination == "0.0.0.0/0"
    assert Route(destination="192.0.2.0 255.255.255.0").destination == "192.0.2.0/24"
    for bad in (
        lambda: Vlan(id=5000),
        lambda: Vlan(id="abc"),
        lambda: Vlan(priority=8),
        lambda: Asset(purdue_level="7"),
        lambda: Asset(criticality="catastrophic"),
        lambda: Indicator(type="bulb"),
        lambda: Relationship(direction="sideways"),
        lambda: Redundancy(lan="C"),
        lambda: LogicTask(type="sometimes"),
        lambda: HostProcess(memory_percent=101),
        lambda: NetworkTraffic(bytes=-1),
        lambda: DeviceData(health="broken"),
        lambda: BaselineRule(id="no-path"),
        lambda: BaselineFinding(result="maybe"),
    ):
        with pytest.raises((ValidationError, ValueError)):
            bad()


def test_route_non_ip_gateways():
    r1 = Route(destination="192.0.2.0 255.255.255.0", gateway="00:0c:29:aa:bb:cc")
    assert r1.destination == "192.0.2.0/24"
    assert r1.gateway == ""
    assert r1.type == "connected"
    assert r1.extra["gateway_mac"] == "00:0C:29:AA:BB:CC"
    r2 = Route(destination="10.0.0.0/8", gateway="link#1")
    assert r2.extra["gateway_raw"] == "link#1"
    assert r2.gateway == ""
    dev = DeviceData(ip="192.0.2.40")
    dev.store("routes", r1)
    assert "00:0C:29:AA:BB:CC" in dev.related.mac


def test_route_gateway_assignment_never_raises():
    r = Route(destination="10.0.0.0/8")
    r.gateway = "link#3"
    assert r.gateway == ""
    assert r.extra["gateway_raw"] == "link#3"
    assert r.type == "connected"
    r.gateway = "192.0.2.1"
    assert r.gateway == "192.0.2.1"


def _routes_via_device() -> DeviceData:
    """300 routes via 2 gateways; the first routes have no interface."""
    dev = DeviceData(ip="192.0.2.40")
    dev.store("interface", Interface(name="port1", type="ethernet", ip="192.0.2.40"))
    dev.store("interface", Interface(name="port2", type="wireless"))
    # A module's edge to one of the gateways (merged with: evidence union)
    dev.store(
        "relationships",
        Relationship(
            type="routes_via",
            remote=RelationshipEndpoint(ip="198.51.100.1", role="gateway"),
            evidence={"config"},
        ),
    )
    routes = [Route(destination="0.0.0.0/0", gateway="0.0.0.0")]
    for i in range(300):
        gateway = "192.0.2.1" if i % 2 else "198.51.100.1"
        interface = "" if i < 4 else ("port2" if i % 4 == 0 else "port1")
        routes.append(
            Route(
                destination=f"10.{i // 256}.{i % 256}.0/24", gateway=gateway, interface=interface
            )
        )
    dev.routes = routes
    return dev


def test_routes_via_one_store_per_gateway(mocker):
    """One routes_via store() per gateway, not per route, with the same result (R3-18)."""
    # Reference: one store() per route (what _derive_relationships() did before)
    expected = _routes_via_device()
    for route in expected.routes:
        if route.gateway and route.gateway not in ("0.0.0.0", "::"):
            expected.store(
                "relationships",
                Relationship(
                    type="routes_via",
                    local=RelationshipEndpoint(interface=route.interface),
                    remote=RelationshipEndpoint(ip=route.gateway, role="gateway"),
                    evidence={"routing_table"},
                ),
            )

    dev = _routes_via_device()
    store = mocker.patch.object(DeviceData, "store", autospec=True, side_effect=DeviceData.store)
    dev._derive_relationships()
    assert [c.args[1] for c in store.call_args_list] == ["relationships", "relationships"]
    assert dev.relationships == expected.relationships
    edges = {r.remote.ip: r for r in dev.relationships}
    assert len(edges) == 2
    assert (edges["192.0.2.1"].local.interface, edges["192.0.2.1"].medium) == (
        "port1",
        "ethernet",
    )
    assert (edges["198.51.100.1"].local.interface, edges["198.51.100.1"].medium) == (
        "port2",
        "wireless",
    )
    assert edges["198.51.100.1"].evidence == {"config", "routing_table"}


class _CountingList(list):
    """A list that counts how often it is iterated."""

    iterations = 0

    def __iter__(self):
        self.iterations += 1
        return super().__iter__()


def test_relationship_listening_ports_only_read_when_needed():
    """The device's listening ports are only read by edges that use them (R3-20)."""
    dev = DeviceData(ip="192.0.2.40")
    dev.store("service", Service(protocol="dnp3", port=20000, transport="tcp", status="open"))
    services = _CountingList(dev.service)
    dev.__dict__["service"] = services  # bypass validation (it would copy the list)

    neighbor = Relationship(
        type="neighbor_of",
        remote=RelationshipEndpoint(ip="192.0.2.1", mac="00:00:5E:00:53:01"),
        evidence={"arp"},
    )
    route = Relationship(
        type="routes_via",
        remote=RelationshipEndpoint(ip="192.0.2.1", role="gateway"),
        evidence={"routing_table"},
    )
    egress = Relationship(
        direction="egress", protocol="dnp3", remote=RelationshipEndpoint(ip="192.0.2.9")
    )
    for rel in (neighbor, route, egress):
        rel.annotate(dev)
    assert services.iterations == 0
    assert (neighbor.direction, neighbor.protocol, neighbor.transport) == ("", "", "")
    assert (route.direction, route.protocol, route.transport) == ("", "", "")
    assert (egress.direction, egress.protocol, egress.remote.port) == ("egress", "dnp3", None)

    # Edges that infer their direction or fill in an ingress edge still use them
    socket = Relationship(
        transport="tcp",
        local=RelationshipEndpoint(port=20000),
        remote=RelationshipEndpoint(ip="192.0.2.5", port=49210),
    )
    socket.annotate(dev)
    assert services.iterations == 1
    assert (socket.direction, socket.protocol) == ("ingress", "dnp3")
    log_edge = Relationship(
        direction="ingress",
        protocol="dnp3",
        remote=RelationshipEndpoint(ip="192.0.2.5"),
        evidence={"log"},
    )
    log_edge.annotate(dev)
    assert services.iterations == 2
    assert (log_edge.local.port, log_edge.transport) == (20000, "tcp")


def test_indicator_state_assignment_is_normalized():
    ind = Indicator(name="RUN", type="led")
    ind.state = "lit"
    assert ind.state == "on"
    ind.state = "red"
    assert ind.state == "on"
    assert ind.color == "red"
    ind = Indicator(name="RUN", type="led")
    ind.state = "unknown"
    assert ind.state == ""
    assert ind.value == "unknown"


def test_event_severity_out_of_es_long_range():
    doc = Event(action="x", severity="99999999999999999999").gen_elastic_content(None)
    assert "severity" not in doc["event"]
    assert doc["log"] == {"level": "99999999999999999999"}
    assert Event(action="x", severity=str(-(2**63))).gen_elastic_content(None)["event"][
        "severity"
    ] == -(2**63)
    dev = DeviceData(ip="192.0.2.10")
    dev.store("event", Event(action="a", severity=str(2**63), created=T0))
    assert dev.elastic()["event"][0].get("severity") is None


def test_firmware_written_by_peat_has_no_local_stat_metadata(mocker, tmp_path):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})
    dev = DeviceData(ip="192.0.2.10")
    dev.firmware.original = b"\x00\x01firmware-bytes"
    dev.logic.original = "logic text"
    for _ in range(2):  # the skip persists across populate_fields() runs
        dev.populate_fields()
        for f in (dev.firmware.file, dev.logic.file):
            assert f.local_path is not None
            assert f.local_path.is_file()
            assert f.size
            assert f.hash.sha256
            assert f.mtime is None
            assert f.created is None
            assert f.owner == ""
            assert f.group == ""


def test_event_severity_and_log_level():
    dev = DeviceData(ip="192.0.2.10")
    ev = Event(action="login", severity="INFO")
    ev.annotate(dev)
    assert ev.log_level == "INFO"
    doc = ev.gen_elastic_content(dev)
    assert "severity" not in doc["event"]
    assert "log_level" not in doc["event"]
    assert doc["log"] == {"level": "INFO"}

    doc = Event(action="x", severity="3").gen_elastic_content(dev)
    assert doc["event"]["severity"] == 3
    assert "log" not in doc

    doc = Event(action="x", severity="ERR", log_level="err").gen_elastic_content(dev)
    assert doc["log"] == {"level": "err"}
    assert "severity" not in doc["event"]

    doc = Event(action="x", log_level="warning").gen_elastic_content(None)
    assert doc["log"] == {"level": "warning"}

    # events index: single most specific event.kind
    assert Event(action="trip", kind={"alert"}).gen_elastic_content(dev)["event"]["kind"] == (
        "alert"
    )
    assert Event(action="x").gen_elastic_content(None)["event"]["kind"] == "event"
    with pytest.raises(ValidationError):
        Event(kind={"signal"})

    # host document: numeric severities as int, text moved to log_level
    dev.store("event", Event(action="a", severity="INFO", created=T0))
    dev.store("event", Event(action="b", severity="4", created=T1))
    host_events = dev.elastic()["event"]
    assert host_events[0].get("severity") is None
    assert host_events[0]["log_level"] == "INFO"
    assert host_events[1]["severity"] == 4


def test_store_default_lookups():
    sel = sel_relay()
    assert len(sel.relationships) == 1
    rel = sel.relationships[0]
    assert rel.evidence == {"config", "netstat"}
    assert rel.count == 3
    assert rel.state == "established"
    assert rel.extra["station_num"] == 1
    assert rel.first_seen == T0
    assert rel.direction == "ingress"
    assert rel.local.interface == "Port 5"
    assert rel.local.ip == "192.0.2.10"

    # LED definition + live reading merged on (type, name, interface)
    assert len(sel.indicators) == 2
    tled = next(i for i in sel.indicators if i.name == "TLED12")
    assert tled.state == "on"
    assert tled.equation == "TRIP"
    assert tled.color == "red"

    clx = controllogix()
    tcp = [s for s in clx.protocol_statistics if s.transport == "tcp"]
    assert len(tcp) == 1
    assert tcp[0].connections.active == 4
    assert tcp[0].connections.failed is None  # newer sample replaced wholesale

    sage = sage_rtu()
    assert len(sage.processes) == 2
    assert len(sage.software) == 2
    assert next(p for p in sage.software if p.name == "OpenSSL").vendor == "OpenSSL Project"

    # explicit tuple lookup
    dev = DeviceData()
    dev.store("routes", Route(destination="10.0.0.0/8", gateway="192.0.2.1", metric=1))
    dev.store(
        "routes",
        Route(destination="10.0.0.0/8", gateway="192.0.2.1", type="static"),
        lookup=("destination", "gateway"),
    )
    assert len(dev.routes) == 1
    assert dev.routes[0].type == "static"
    assert dev.routes[0].metric == 1
    with pytest.raises(PeatError):
        dev.store("routes", Route(), lookup=1)


def test_store_and_dedupe_keep_the_first_item():
    items = [Interface(name="eth0", ip="192.0.2.1"), Interface(name="eth0", ip="198.51.100.1")]
    assert [i.ip for i in dedupe_model_list([i.copy(deep=True) for i in items])] == ["192.0.2.1"]
    dev = DeviceData()
    for item in items:
        dev.store("interface", item.copy(deep=True))
    assert [i.ip for i in dev.interface] == ["192.0.2.1"]

    procs = [
        HostProcess(pid=1, name="sshd", user=User(name="root")),
        HostProcess(pid=1, name="sshd", user=User(name="daemon")),
    ]
    assert dedupe_model_list([p.copy(deep=True) for p in procs])[0].user.name == "root"
    dev = DeviceData()
    for proc in procs:
        dev.store("processes", proc.copy(deep=True))
    assert dev.processes[0].user.name == "root"

    routes = [
        Route(destination="0.0.0.0/0", gateway="192.0.2.1", metric=1),
        Route(destination="0.0.0.0/0", gateway="192.0.2.1", metric=9),
    ]
    assert dedupe_model_list([r.copy(deep=True) for r in routes])[0].metric == 1

    m1, m2 = DeviceData(ip="192.0.2.1"), DeviceData(ip="192.0.2.1")
    m1.store("interface", Interface(name="eth0", ip="192.0.2.1"))
    m2.store("interface", Interface(name="eth0", ip="198.51.100.9", mtu=9000))
    merge_models(m1, m2)
    assert len(m1.interface) == 1
    assert m1.interface[0].ip == m1.ip == "192.0.2.1"
    assert m1.interface[0].mtu == 9000


def test_no_duplicate_services_after_device_merge():
    x1, x2 = DeviceData(ip="192.0.2.8"), DeviceData(ip="192.0.2.8")
    for dev, count, ts in ((x1, 100, T0), (x2, 200, T1)):
        svc = Service(
            protocol="http",
            port=80,
            statistics=NetworkStatistics(timestamp=ts, ingress=NetworkTraffic(messages=count)),
        )
        dev.store("interface", Interface(name="eth0", ip="192.0.2.8"))
        dev.store("service", svc, interface_lookup={"ip": "192.0.2.8"})
    merge_models(x1, x2)
    x1.purge_duplicates(force=True)
    x1.populate_fields()
    assert [(s.protocol, s.port) for s in x1.service] == [("http", 80)]
    assert x1.service[0].statistics.ingress.messages == 200
    assert len(x1.interface[0].services) == 1


def test_relationship_identity():
    # client-side socket-table records + a config record -> one egress edge
    c = DeviceData(ip="192.0.2.30")
    for port in (50001, 50002):
        c.store(
            "relationships",
            Relationship(
                transport="tcp",
                evidence={"netstat"},
                local=RelationshipEndpoint(ip="192.0.2.30", port=port),
                remote=RelationshipEndpoint(ip="192.0.2.99", port=502),
            ),
        )
    c.store(
        "relationships",
        Relationship(
            protocol="modbus_tcp",
            direction="egress",
            evidence={"config"},
            local=RelationshipEndpoint(role="client"),
            remote=RelationshipEndpoint(ip="192.0.2.99", port=502, role="server"),
        ),
    )
    assert len(c.relationships) == 1
    assert c.relationships[0].direction == "egress"
    assert c.relationships[0].protocol == "modbus_tcp"
    assert c.relationships[0].evidence == {"netstat", "config"}
    assert 502 in c.related.ports

    # a log record that names only the service: local port from dev.service
    lg = sel_relay()
    lg.store("service", Service(protocol="https", port=443, status="open"))
    lg.store(
        "relationships",
        Relationship(
            protocol="https",
            direction="ingress",
            evidence={"log"},
            remote=RelationshipEndpoint(ip="198.51.100.7"),
            count=4,
        ),
    )
    lg.store(
        "relationships",
        Relationship(
            transport="tcp",
            evidence={"netstat"},
            local=RelationshipEndpoint(port=443),
            remote=RelationshipEndpoint(ip="198.51.100.7", port=61000),
        ),
    )
    web = [r for r in lg.relationships if r.remote.ip == "198.51.100.7"]
    assert len(web) == 1
    assert web[0].evidence == {"log", "netstat"}
    assert web[0].local.port == 443

    # config record without transport + an appended socket-table record
    nt = DeviceData(ip="192.0.2.10")
    nt.store("interface", Interface(name="Port 5", ip="192.0.2.10", type="ethernet"))
    nt.store("service", Service(protocol="dnp3", port=20000, transport="tcp", status="open"))
    nt.store(
        "relationships",
        Relationship(
            protocol="dnp3",
            direction="ingress",
            evidence={"config"},
            local=RelationshipEndpoint(port=20000),
            remote=RelationshipEndpoint(ip="192.0.2.50"),
        ),
    )
    nt.relationships.append(
        Relationship(
            transport="tcp",
            evidence={"netstat"},
            local=RelationshipEndpoint(ip="192.0.2.10", port=20000),
            remote=RelationshipEndpoint(ip="192.0.2.50", port=49152),
        )
    )
    exported = nt.export()["relationships"]
    assert len(exported) == 1
    assert exported[0]["transport"] == "tcp"
    assert exported[0]["medium"] == "ethernet"
    assert sorted(exported[0]["evidence"]) == ["config", "netstat"]

    # the id is always recomputed: a copied record with a new peer is a new edge
    sel = sel_relay()
    copied = sel.relationships[0].copy(deep=True)
    copied.remote.ip = "192.0.2.99"
    sel.store("relationships", copied)
    assert {r.remote.ip for r in sel.relationships} == {"192.0.2.50", "192.0.2.99"}
    assert len({r.id for r in sel.relationships}) == 2

    # appended relationships get their id in populate_fields() and are exported once
    ap = DeviceData(ip="192.0.2.31")
    for _ in range(2):
        ap.relationships.append(
            Relationship(
                protocol="dnp3",
                direction="egress",
                remote=RelationshipEndpoint(ip="192.0.2.5", port=20000),
            )
        )
    exported = ap.export()["relationships"]
    assert len(exported) == 1
    assert len(exported[0]["id"]) == 16
    assert exported[0]["type"] == "communicates_with"


def test_relationship_identity_tunnels_per_local_interface():
    # Two IPsec tunnels to one gateway over two WAN links are two edges
    dev = DeviceData(ip="192.0.2.1")
    for iface in ("wan1", "wan2", "wan1"):
        dev.store(
            "relationships",
            Relationship(
                type="tunnel",
                protocol="ipsec",
                local=RelationshipEndpoint(interface=iface),
                remote=RelationshipEndpoint(ip="203.0.113.1", role="peer"),
                evidence={"config"},
            ),
        )
    assert sorted(r.local.interface for r in dev.relationships) == ["wan1", "wan2"]
    assert len({r.id for r in dev.relationships}) == 2

    # Other types: local.interface is an attribute that merges
    other = DeviceData(ip="192.0.2.1")
    for iface in ("eth0", ""):
        other.store(
            "relationships",
            Relationship(
                type="neighbor_of",
                local=RelationshipEndpoint(interface=iface),
                remote=RelationshipEndpoint(ip="192.0.2.7"),
                evidence={"arp"},
            ),
        )
    assert [r.local.interface for r in other.relationships] == ["eth0"]


def test_relationship_medium_vocabulary():
    dev = DeviceData(ip="192.0.2.40")
    dev.store("interface", Interface(name="port1", type="physical", ip="192.0.2.40"))
    dev.store("interface", Interface(name="wlan0", type="wifi", ip="192.0.2.41"))
    for local, remote in (("192.0.2.40", "192.0.2.1"), ("192.0.2.41", "192.0.2.2")):
        dev.store(
            "relationships",
            Relationship(
                local=RelationshipEndpoint(ip=local), remote=RelationshipEndpoint(ip=remote)
            ),
        )
    assert {r.remote.ip: r.medium for r in dev.relationships} == {
        "192.0.2.1": "",
        "192.0.2.2": "wireless",
    }


def test_relationship_merge_rules_and_device_merge():
    d1, d2 = sel_relay(), sel_relay()
    d2.store(
        "relationships",
        Relationship(
            protocol="dnp3",
            transport="tcp",
            direction="ingress",
            evidence={"log"},
            local=RelationshipEndpoint(
                interface="Port 5", port=20000, role="outstation", protocol_address="10"
            ),
            remote=RelationshipEndpoint(ip="192.0.2.50", role="master", protocol_address="1"),
            first_seen=T0 - timedelta(days=3),
            last_seen=T1 + timedelta(minutes=5),
            count=7,
            state="closed",
        ),
    )
    d2.interface[0].statistics = NetworkStatistics(
        timestamp=T1, ingress=NetworkTraffic(bytes=1700000000)
    )
    merge_models(d1, d2)
    d1.purge_duplicates(force=True)
    d1.populate_fields()
    dnp = [r for r in d1.relationships if r.protocol == "dnp3"]
    assert len(dnp) == 1
    assert dnp[0].first_seen == T0 - timedelta(days=3)
    assert dnp[0].last_seen == T1 + timedelta(minutes=5)
    assert dnp[0].count == 7
    assert dnp[0].state == "closed"
    assert dnp[0].evidence == {"config", "netstat", "log"}
    port5 = next(i for i in d1.interface if i.name == "Port 5")
    assert port5.statistics.ingress.bytes == 1700000000
    assert port5.statistics.egress.bytes is None  # samples are never mixed
    assert len(d1.service) == 5
    assert len(d1.indicators) == 2
    assert len(d1.clock.sources) == 3


def test_statistics_samples_never_mixed():
    s1 = NetworkStatistics(ingress=NetworkTraffic(bytes=100, packets=10))
    merge_models(s1, NetworkStatistics(egress=NetworkTraffic(bytes=5)))
    assert s1.egress.bytes is None
    assert s1.ingress.bytes == 100

    s2 = NetworkStatistics(timestamp=T0, ingress=NetworkTraffic(bytes=1, packets=1))
    merge_models(s2, NetworkStatistics(egress=NetworkTraffic(bytes=7)))
    assert s2.egress.bytes is None

    s3 = NetworkStatistics()
    merge_models(s3, NetworkStatistics(timestamp=T0, egress=NetworkTraffic(bytes=7)))
    assert s3.egress.bytes == 7
    assert s3.timestamp == T0

    s4 = NetworkStatistics(timestamp=T0, ingress=NetworkTraffic(bytes=1))
    merge_models(s4, NetworkStatistics(timestamp=T1, egress=NetworkTraffic(bytes=2)))
    assert s4.ingress.bytes is None
    assert s4.egress.bytes == 2

    # counters > 2^63-1 (Elasticsearch long) are moved to extra
    big = NetworkStatistics(
        connections=ConnectionStatistics(total=2**64), collisions=2**63, link_down_count=1
    )
    big.annotate()
    assert big.connections.total is None
    assert big.collisions is None
    assert big.link_down_count == 1
    assert set(big.extra["out_of_range"]) == {"connections.total", "collisions"}
    sage = sage_rtu()
    assert sage.interface[0].statistics.ingress.bytes is None
    assert sage.interface[0].statistics.extra["out_of_range"] == {"ingress.bytes": str(2**64 - 1)}


def test_indicator_newest_wins():
    items = [
        Indicator(name="RUN", type="led", state="on", timestamp=T0),
        Indicator(name="RUN", type="led", state="off", timestamp=T1),
        Indicator(name="RUN", type="led", label="RUN", color="green"),
    ]
    deduped = dedupe_model_list(items)
    assert len(deduped) == 1
    assert deduped[0].state == "off"
    assert deduped[0].color == "green"
    assert deduped[0].label == "RUN"


def test_new_list_models_dedupe_sort_merge_roundtrip():
    sel = sel_relay()
    examples = {
        Vlan: [Vlan(id="10"), Vlan(id=10, name="ops"), Vlan(id="20", tagged=True)],
        NetworkStatistics: [
            NetworkStatistics(transport="tcp", timestamp=T0),
            NetworkStatistics(transport="tcp", timestamp=T1, ingress=NetworkTraffic(packets=5)),
            NetworkStatistics(type="ipv4"),
        ],
        Route: [
            Route(destination="0.0.0.0/0", gateway="192.0.2.1"),
            Route(destination="default", gateway="192.0.2.1", metric=10),
            Route(destination="10.1.0.0/16", gateway="192.0.2.2"),
        ],
        TimeSource: [
            TimeSource(protocol="ntp", address="192.0.2.5"),
            TimeSource(protocol="ntp", address="192.0.2.5", stratum=2),
            TimeSource(protocol="ptp", address="eth0"),
        ],
        Relationship: [r.copy(deep=True) for r in sel.relationships]
        + [sel.relationships[0].copy(update={"evidence": {"log"}, "count": 9}, deep=True)],
        HostProcess: [
            HostProcess(name="sshd", pid=1),
            HostProcess(name="sshd", pid=2),
            HostProcess(name="sshd", pid=1, state="running"),
        ],
        Package: [
            Package(name="a", version="1"),
            Package(name="a", version="1", license="MIT"),
            Package(name="a", version="2"),
        ],
        LogicTask: [LogicTask(name="t1"), LogicTask(name="t1", priority=1), LogicTask(name="t0")],
        IEC61850HistoryItem: [
            IEC61850HistoryItem(version="1", revision="2"),
            IEC61850HistoryItem(version="1", revision="1"),
        ],
        IEC61850AccessPoint: [
            IEC61850AccessPoint(name="S1", ip="192.0.2.10"),
            IEC61850AccessPoint(name="S1", server=True),
        ],
        IEC61850LogicalDevice: [
            IEC61850LogicalDevice(inst="PRO", logical_nodes=["LLN0"]),
            IEC61850LogicalDevice(inst="CTRL"),
        ],
        BaselineFinding: [
            BaselineFinding(baseline_id="b", path="name", result="fail"),
            BaselineFinding(baseline_id="b", path="name", result="fail", reason="x"),
            BaselineFinding(baseline_id="b", path="firmware.version", result="fail"),
        ],
        BaselineRule: [
            BaselineRule(id="r2", path="name"),
            BaselineRule(id="r1", path="firmware.version", operator="present"),
        ],
    }
    expected_lengths = {
        Vlan: 2,
        NetworkStatistics: 2,
        Route: 2,
        TimeSource: 2,
        Relationship: 1,
        HostProcess: 2,
        Package: 2,
        LogicTask: 2,
        IEC61850HistoryItem: 2,
        IEC61850AccessPoint: 1,
        IEC61850LogicalDevice: 2,
        BaselineFinding: 2,
        BaselineRule: 2,
    }
    for cls, items in examples.items():
        items = [i.copy(deep=True) for i in items]
        deduped = dedupe_model_list([i.copy(deep=True) for i in items])
        sort_model_list(deduped)
        assert len(deduped) == expected_lengths[cls], cls
        first, last = items[0].copy(deep=True), items[-1].copy(deep=True)
        merge_models(first, last)
        for item in items:
            back = cls.parse_raw(item.json(exclude_defaults=True))
            assert back.dict(exclude_defaults=True) == item.dict(exclude_defaults=True), cls

    rels = dedupe_model_list([r.copy(deep=True) for r in examples[Relationship]])
    assert rels[0].evidence == {"config", "netstat", "log"}
    assert rels[0].count == 9


@pytest.mark.usefixtures("siprotec_hosts")
def test_populate_fields_nested_lists_and_related():
    sel = sel_relay()
    exported = sel.export()
    assert exported["related"]["vlans"] == ["100"]
    assert "01:0C:CD:01:00:10" not in sel.related.mac  # multicast MACs are not related
    assert {"192.0.2.5", "192.0.2.6", "192.0.2.50", "192.0.2.1"} <= sel.related.ip
    assert {"BUS1", "HMI1"} <= sel.related.hosts
    dnp3 = next(s for s in exported["service"] if s["protocol"] == "dnp3")
    assert dnp3["security"] == {"encrypted": False}  # derived from the protocol
    assert sel.clock.offset == 2.5
    assert sel.clock.source == "irig_b"
    cid = next(f for f in sel.files if f.name == "SET_61850.CID")
    assert cid.category == {"configuration", "iec61850"}

    # derived relationships (time sources, routes) and module hoisting
    assert sorted(r.type for r in sel.relationships) == [
        "communicates_with",
        "syncs_time_from",
        "syncs_time_from",
    ]
    clx = controllogix()
    clx.export()
    assert any(r.type == "routes_via" for r in clx.relationships)
    hoisted = [r for r in clx.relationships if r.type == "physical_link"]
    assert len(hoisted) == 1
    assert hoisted[0].local.id == "slot:2"
    assert not clx.module[0].relationships
    assert [t.name for t in clx.logic.tasks] == ["MainTask", "Periodic10ms"]
    assert clx.logic.tasks[0].scan_count == 123
    route = next(r for r in clx.routes if r.gateway == "192.0.2.1")
    assert route.destination == "0.0.0.0/0"

    sip = siprotec()
    sip.export()
    assert sorted(r.remote.hostname for r in sip.relationships) == [
        "ntp1.example.org",
        "ntp2.example.org",
    ]
    assert {"ntp1.example.org", "ntp2.example.org"} <= sip.related.hosts

    fg = fortigate()
    fg.export()
    port1 = next(i for i in fg.interface if i.name == "port1")
    assert [v.id for v in port1.vlans] == ["100", "200"]
    assert port1.vlans[0].name == "scada"
    assert fg.related.vlans == {"100", "200"}
    assert fg.related.process == {"miglogd", "sshd"}
    assert "/bin/sshd" in fg.related.files
    assert "admin" in fg.related.user

    sage = sage_rtu()
    sage.export()
    assert sage.service[0].process_name == "tTelnetd"
    assert "tTelnetd" in sage.related.process

    # values added with .add() bypass validation and are normalized
    vl = DeviceData(ip="192.0.2.9")
    vl.related.vlans.update({"10", 5, "005"})
    assert vl.export()["related"]["vlans"] == ["10", "5"]
    fc = File(path="/SET_1.TXT", category={"settings"})
    fc.category.add("CONFIGURATION ")
    fc.annotate(None)
    assert fc.category == {"settings", "configuration"}


def test_service_annotate_canonical_names_and_security():
    telnet = Service(protocol="telnet", port=23)
    telnet.annotate(None)
    assert telnet.security.encrypted is False
    ssh = Service(protocol="ssh", port=22)
    ssh.annotate(None)
    assert ssh.security.encrypted is True
    custom = Service(protocol="https", security={"encrypted": False})
    custom.annotate(None)
    assert custom.security.encrypted is False  # module value is kept
    modbus = Service(protocol="modbus", port=502, transport="tcp")
    modbus.annotate(None)
    assert modbus.protocol == "modbus_tcp"
    mms = Service(protocol="mms", port=102)
    mms.annotate(None)
    assert mms.transport == "tcp"
    assert Service(protocol="c37.118").protocol == "c37_118"


def test_naive_datetimes_are_device_local():
    dev = DeviceData(ip="192.0.2.12")
    dev.geo.timezone = "America/Denver"
    dev.store("processes", HostProcess(pid=7, name="init", start=datetime(2026, 7, 1, 8, 0)))
    assert dev.processes[0].start == datetime(2026, 7, 1, 14, 0, tzinfo=UTC)
    clock = Clock(time=datetime(2026, 10, 30, 5, 0, 2), observed=T0, utc_offset="-07:00")
    clock.annotate(None)
    assert clock.offset == 2.0
    assert Clock(time=datetime(2026, 1, 1), observed=T0).offset is None  # naive vs aware

    # sorting lists with naive and aware datetimes
    mix = DeviceData(ip="192.0.2.13")
    mix.store("event", Event(action="a", created=datetime(2026, 1, 1, 0, 0)))
    mix.store("event", Event(action="b", created=T0))
    mix.export()


def test_naive_datetimes_without_system_tz_database(mocker):
    """
    Windows has no system time zone database (and ``tzdata`` is not a dependency):
    the database bundled with python-dateutil resolves the device time zone.
    """
    from zoneinfo import ZoneInfoNotFoundError

    from peat.data import models

    def no_tz_database(key: str):
        raise ZoneInfoNotFoundError(f"No time zone found with key {key}")

    mocker.patch.object(models, "ZoneInfo", side_effect=no_tz_database)
    models.resolve_timezone.cache_clear()
    try:
        dev = DeviceData(ip="192.0.2.12")
        dev.geo.timezone = "America/Denver"
        dev.store("processes", HostProcess(pid=7, name="init", start=datetime(2026, 7, 1, 8, 0)))
        assert dev.processes[0].start == datetime(2026, 7, 1, 14, 0, tzinfo=UTC)  # MDT
        winter = datetime(2026, 1, 15, 8, 0)
        assert models.resolve_timezone("America/Denver").utcoffset(winter) == timedelta(hours=-7)
        assert models.resolve_timezone("EST").utcoffset(winter) == timedelta(hours=-5)

        # an unknown name: naive times are UTC, logged once (debug)
        logger = mocker.patch.object(models, "log")
        assert models.resolve_timezone("Not/AZone") is None
        assert models.resolve_timezone("Not/AZone") is None
        assert logger.debug.call_count == 1
        assert models._utc(winter, "Not/AZone") == winter.replace(tzinfo=UTC)
    finally:
        models.resolve_timezone.cache_clear()


@pytest.mark.usefixtures("siprotec_hosts")
def test_export_summary_elastic_exclusions():
    for builder in (sel_relay, controllogix, sage_rtu, fortigate, siprotec):
        dev = builder()
        full = dev.export(include_original=True)
        summary = dev.export_summary()
        assert "relationships" not in summary
        assert "baseline_findings" not in summary
        host = dev.elastic()
        assert "relationships" not in host
        assert "baseline_findings" not in host
        for mod in host.get("module", []):
            assert "relationships" not in mod
        for ev in host.get("event", []):
            assert "severity" not in ev or isinstance(ev["severity"], int)
        for f in host.get("files", []):
            assert "original" not in f
        doc = dev.gen_elastic_content()
        assert {k: v for k, v in doc["event"].items() if k != "module"} == {
            "kind": "asset",
            "category": ["host"],
            "type": ["info"],
        }
        json.dumps(full, default=str)

    # files[*].original is not exported (it is kept with include_original=True)
    sel = sel_relay()
    assert "original" not in sel.export()["files"][0]
    assert "original" in sel.export(include_original=True)["files"][0]


@pytest.mark.usefixtures("siprotec_hosts")
def test_host_document_derived_fields():
    sip = siprotec()
    assert sip.label == "siprotec-feeder-7"
    assert sip.asset.criticality == "high_impact"
    assert sip.asset.purdue_level == "1"
    host_doc = sip.gen_elastic_content()
    assert host_doc["host"]["tags"] == ["feeder", "protection"]
    assert host_doc["host"]["asset"]["zone"] == "station-bus"
    base = sip.gen_base_host_fields_content()
    assert base["tags"] == ["feeder", "protection"]
    assert base["asset"]["criticality"] == "high_impact"

    clx = controllogix()
    host = clx.gen_elastic_content()["host"]
    assert host["indicator_states"] == {
        "key_switch": "REMOTE RUN",
        "minor_recoverable_fault": "on",
    }
    assert host["module"][0]["indicator_states"] == {"OK": "on"}


def test_asset_from_config_invalid(mocker):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "HOSTS": [
                {
                    "label": "bad-asset",
                    "identifiers": {"ip": "192.0.2.77"},
                    "asset": {"purdue_level": "9"},
                }
            ]
        },
    )
    dev = DeviceData(ip="192.0.2.77")
    assert dev.label == "bad-asset"
    assert dev.is_default("asset")


def test_example_config_asset(mocker, examples_path):
    yml_config = yaml.safe_load(examples_path("peat-config.yaml").read_text())
    mocker.patch.dict(config["CONFIG"], {"HOSTS": yml_config["hosts"]})
    dev = DeviceData(ip="192.168.0.1")
    assert dev.asset.criticality == "high_impact"
    assert dev.asset.tags == {"protection", "feeder"}
    assert dev.asset.conduits == {"station-to-control-center"}
    assert dev.asset.safety is True


def test_relationship_documents():
    sel = sel_relay()
    sel.export()
    for rel in sel.relationships:
        doc = rel.gen_elastic_content(sel)
        assert doc["event"]["kind"] in ECS_EVENT_VALUES["kind"]
        assert set(doc["event"]["type"]) <= ECS_EVENT_VALUES["type"]
        assert set(doc["event"]["category"]) <= ECS_EVENT_VALUES["category"]
        assert doc["relationship"]["id"] == rel.id
    dnp = next(r for r in sel.relationships if r.protocol == "dnp3")
    doc = dnp.gen_elastic_content(sel)
    assert doc["source"]["ip"] == "192.0.2.50"  # the master initiates (ingress)
    assert doc["destination"]["ip"] == "192.0.2.10"
    assert doc["destination"]["port"] == 20000
    assert doc["event"]["type"] == ["connection"]
    assert doc["event"]["start"] == T0
    assert doc["host"]["ip"] == "192.0.2.10"
    assert doc["network"] == {"protocol": "dnp3", "transport": "tcp", "direction": "ingress"}
    assert doc["message"] == "FEEDER 1 (outstation) communicates_with 192.0.2.50 (dnp3)"

    # unknown direction: no "connection" type, network.direction passed through
    und = Relationship(
        transport="tcp",
        direction="unknown",
        local=RelationshipEndpoint(ip="192.0.2.10", port=60001),
        remote=RelationshipEndpoint(ip="192.0.2.50", port=60002),
    )
    doc = und.gen_elastic_content(DeviceData(ip="192.0.2.10"))
    assert doc["event"]["type"] == ["info"]
    assert doc["network"]["direction"] == "unknown"

    # L2 GOOSE publication: group MAC only as destination.mac, own MAC as source.mac
    pub = DeviceData(name="PROT1", mac="00:30:A7:00:00:01")
    pub.store(
        "relationships",
        Relationship(
            type="publishes_to",
            protocol="goose",
            direction="egress",
            reference="PROT1PRO/LLN0$GO$gcbTrip",
            remote=RelationshipEndpoint(mac="01:0C:CD:01:00:10", protocol_address="0x1000"),
            vlan=Vlan(id="100", priority=4),
            evidence={"scl"},
        ),
    )
    doc = pub.relationships[0].gen_elastic_content(pub)
    assert doc["source"] == {"mac": "00:30:A7:00:00:01"}
    assert doc["destination"] == {"mac": "01:0C:CD:01:00:10"}
    assert doc["related"] == {"mac": ["00:30:A7:00:00:01"]}
    assert doc["network"]["vlan"] == {"id": "100"}
    assert "01:0C:CD:01:00:10" not in pub.related.mac
    assert pub.related.vlans == {"100"}

    # hostname peers are exported as *.domain
    ts = Relationship(
        type="syncs_time_from",
        protocol="ntp",
        transport="udp",
        direction="egress",
        remote=RelationshipEndpoint(hostname="ntp1.example.org", role="time_server"),
    )
    doc = ts.gen_elastic_content(DeviceData(ip="192.0.2.70"))
    assert doc["destination"]["domain"] == "ntp1.example.org"
    assert doc["destination"]["address"] == "ntp1.example.org"


def test_module_relationships_keep_module_identity():
    chassis = DeviceData(ip="192.0.2.20")
    for slot, ip in (("1", "192.0.2.21"), ("2", "192.0.2.22")):
        mod = DeviceData(slot=slot, ip=ip)
        mod.store(
            "relationships",
            Relationship(
                direction="egress",
                transport="tcp",
                remote=RelationshipEndpoint(ip="192.0.2.99", port=44818),
            ),
        )
        chassis.store("module", mod)
    chassis.populate_fields()
    hoisted = [r for r in chassis.relationships if r.remote.ip == "192.0.2.99"]
    assert sorted(r.local.ip for r in hoisted) == ["192.0.2.21", "192.0.2.22"]
    assert sorted(r.local.id for r in hoisted) == ["slot:1", "slot:2"]
    assert all(r.protocol == "cip" for r in hoisted)
    docs = [r.gen_elastic_content(chassis) for r in hoisted]
    assert sorted(d["source"]["ip"] for d in docs) == ["192.0.2.21", "192.0.2.22"]


def test_large_relationship_lists_are_deduped():
    dev = DeviceData(ip="192.0.2.14")
    for i in range(6000):
        dev.relationships.append(
            Relationship(
                direction="egress",
                transport="tcp",
                remote=RelationshipEndpoint(ip=f"10.{i // 250}.{i % 250}.1", port=20000),
            )
        )
    dev.relationships.extend(r.copy(deep=True) for r in dev.relationships[:500])
    dev.populate_fields()
    dev.purge_duplicates(force=True)
    assert len(dev.relationships) == 6000


def test_baseline_finding_documents():
    sel = sel_relay()

    def finding(**kwargs):
        return BaselineFinding(
            baseline_id="b",
            baseline_name="B",
            baseline_version="7",
            path="x",
            timestamp=T0,
            **kwargs,
        )

    doc = finding(
        baseline_kind="factory_default", result="fail", difference="missing", severity="info"
    ).gen_elastic_content(sel)
    assert doc["event"]["kind"] == "state"
    assert doc["event"]["type"] == ["info"]
    assert doc["event"]["action"] == "baseline-changed-from-default"
    assert "version" not in doc["rule"]
    assert doc["host"]["ip"] == "192.0.2.10"

    doc = finding(
        baseline_kind="previous_observed", result="fail", difference="change", severity="high"
    ).gen_elastic_content(None)
    assert doc["event"]["kind"] == "event"
    assert doc["event"]["type"] == ["change"]

    doc = finding(baseline_kind="vendor_recommended", result="pass").gen_elastic_content(None)
    assert "severity" not in doc["event"]
    assert doc["event"]["action"] == "baseline-check"

    alert = BaselineFinding(
        baseline_id="sel-relay-vendor-recommended",
        baseline_kind="vendor_recommended",
        baseline_name="SEL relay hardening",
        rule_id="sel.accounts.default-credentials",
        path="service[*].security.default_credentials",
        category="accounts",
        result="fail",
        difference="mismatch",
        operator="not_equals",
        expected=True,
        actual=[True],
        severity="high",
        alert=True,
        reason="A factory default password was accepted",
        timestamp=T0,
    )
    doc = alert.gen_elastic_content(sel)
    assert doc["event"]["kind"] == "alert"
    assert doc["event"]["category"] == ["configuration", "iam"]
    assert doc["event"]["severity"] == 4
    assert doc["baseline"]["finding"]["expected"] == "true"
    assert doc["baseline"]["finding"]["actual"] == "[true]"
    for key in ("kind", "category", "type"):
        values = doc["event"][key] if isinstance(doc["event"][key], list) else [doc["event"][key]]
        assert set(values) <= ECS_EVENT_VALUES[key]

    # a re-compare replaces the finding of the same (baseline_id, rule_id, path)
    dev = DeviceData(ip="192.0.2.15")
    old = BaselineFinding(baseline_id="b", rule_id="r", path="p", result="fail")
    new = BaselineFinding(baseline_id="b", rule_id="r", path="p", result="pass")
    assert len(dedupe_model_list([old.copy(), new.copy()])) == 1
    dev.store("baseline_findings", old)
    dev.store("baseline_findings", new)
    assert len(dev.baseline_findings) == 1


def test_file_documents_and_local_metadata(tmp_path):
    local = tmp_path / "SET_1.TXT"
    local.write_text("RID,FEEDER 1")
    # pulled from a device: local copy metadata is NOT the device file's metadata
    pulled = process_file(File(path=PurePosixPath("/SETTINGS/SET_1.TXT"), local_path=local))
    assert pulled.mtime is None
    assert pulled.created is None
    assert not pulled.owner
    assert pulled.size == local.stat().st_size
    assert pulled.hash.sha256
    # the local file IS the artifact (e.g. "peat parse" input)
    parsed = process_file(File(local_path=local))
    assert parsed.mtime is not None
    assert parsed.size == local.stat().st_size

    doc = File(path=PurePosixPath("/SETTINGS/SET_1.TXT")).gen_elastic_content(None)
    assert doc["event"]["kind"] == "event"
    assert doc["event"]["category"] == ["file"]
    assert doc["event"]["type"] == ["info"]


def test_export_to_files_and_full_json_roundtrip(tmp_path):
    dev = sel_relay()
    dev._out_dir = tmp_path
    assert dev.export_to_files(overwrite_existing=True)
    names = sorted(p.name for p in tmp_path.iterdir())
    for want in (
        "device-data-relationships.jsonl",
        "device-data-indicators.jsonl",
        "device-data-full.json",
        "device-data-summary.json",
    ):
        assert want in names
    raw = json.loads((tmp_path / "device-data-full.json").read_text())
    raw.pop("created", None)
    back = DeviceData.parse_obj(raw)
    assert back.iec61850.publications[0].address.appid == 4096
    assert back.iec61850.publications[0].address.vlan.id == "100"
    assert back.relationships[0].id == dev.relationships[0].id

    baseline = Baseline(
        id="relay-1@2026-10-30",
        name="relay-1 first pull",
        version="1",
        kind="first_observed",
        scope="device",
        selector=BaselineSelector(device_id="192.0.2.10"),
        provenance=BaselineProvenance(
            created=T0, author="peat baseline-create", source_file="device-data-full.json"
        ),
        expected=back,
        rules=[
            BaselineRule(
                id="sel.service.ftp.disabled",
                path="service[protocol=ftp].enabled",
                operator="not_equals",
                value=True,
                category="ports_services",
                severity="medium",
                reason="FTP is enabled",
            )
        ],
        ignore=["files.mtime"],
    )
    back_baseline = Baseline.parse_raw(baseline.json(exclude_defaults=True))
    assert back_baseline.expected.relationships[0].id == dev.relationships[0].id
    assert back_baseline.rules[0].value is True
    assert back_baseline.selector.matches(dev)
    assert not BaselineSelector(vendor_id="Siemens").matches(dev)
    assert BaselineSelector(vendor_id="sel", model="351*").matches(dev)
    assert BaselineSelector().is_default_selector()


def test_port_102_protocol_is_not_inferred():
    """R2-26: tcp/102 carries IEC 61850 MMS and Siemens S7comm: no "mms" from the port."""
    hmi = DeviceData(ip="192.168.0.20")
    hmi.store(
        "relationships",
        Relationship(
            transport="tcp",
            evidence={"netstat"},
            local=RelationshipEndpoint(ip="192.168.0.20", port=49200),
            remote=RelationshipEndpoint(ip="192.168.0.1", port=102),
        ),
    )
    hmi.populate_fields()
    rel = hmi.relationships[0]
    assert (rel.direction, rel.protocol) == ("egress", "")
    assert "mms" not in hmi.related.protocols

    # the device's own mms service still names the protocol of ingress sessions
    ied = DeviceData(ip="192.0.2.10")
    ied.store("service", Service(protocol="mms", port=102, transport="tcp", status="open"))
    ied.store(
        "relationships",
        Relationship(
            transport="tcp",
            evidence={"netstat"},
            local=RelationshipEndpoint(port=102),
            remote=RelationshipEndpoint(ip="192.0.2.50", port=50000),
        ),
    )
    assert (ied.relationships[0].direction, ied.relationships[0].protocol) == ("ingress", "mms")


def test_elastic_host_doc_has_annotated_values_without_export():
    """R2-45: "peat pull" builds host documents before export() annotates the models."""
    dev = DeviceData(ip="192.0.2.10")
    dev.clock.observed = T0
    dev.clock.time = T0 + timedelta(seconds=30)
    dev.clock.sources.append(TimeSource(protocol="sntp", address="192.0.2.1", selected=True))
    dev.purge_duplicates(force=True)
    host = dev.gen_elastic_content()["host"]
    assert host["clock"]["offset"] == 30.0
    assert host["clock"]["source"] == "sntp"
    assert "192.0.2.1" in host["related"]["ip"]


def test_mixed_ip_versions_export():
    """R2-43/R2-44: IPv6 in related.ip and IPv4-mapped addresses do not break exports."""
    dev = DeviceData(ip="192.0.2.20")
    dev.store("interface", Interface(name="eth0", ip="::ffff:192.0.2.20"))
    dev.related.ip.update({"2001:db8::50", "192.0.2.9", "2001:db8::10"})
    assert dev.interface[0].ip == "192.0.2.20"
    assert RelationshipEndpoint(ip="::FFFF:198.51.100.7").ip == "198.51.100.7"
    assert RelationshipEndpoint(ip="2001:DB8::1").ip == "2001:db8::1"
    expected = ["192.0.2.9", "192.0.2.20", "2001:db8::10", "2001:db8::50"]
    assert dev.export()["related"]["ip"] == expected
    assert dev.elastic()["related"]["ip"] == expected
