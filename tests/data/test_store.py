import pytest

from peat import Datastore, DeviceData
from peat.data.models import Interface, Service


def test_datastore_create():
    store = Datastore()
    dev = store.create("192.168.0.1", "ip")
    assert isinstance(dev, DeviceData)
    assert len(store.objects) == 1
    assert store.objects[0] is dev
    assert store.objects[0].ip == "192.168.0.1"


def test_datastore_get():
    store = Datastore()
    dev = store.get("192.168.1.2")
    assert dev.ip == "192.168.1.2"
    assert len(store.objects) == 1
    dm = DeviceData()
    dm.ip = "10.0.0.2"
    store.objects.append(dm)
    assert store.get("10.0.0.2") is dm


def test_datastore_search():
    store = Datastore()
    dm = DeviceData(mac="00:11:22:33:44:55")
    store.objects.append(dm)
    assert store.search("00:11:22:33:44:55", "mac") is dm
    assert not store.search("192.168.1.1", "ip")


def test_datastore_remove():
    store = Datastore()
    dm = DeviceData(mac="00:11:22:33:44:55")
    store.objects.append(dm)
    assert store.objects[0] is dm
    assert store.remove(dm)
    assert not store.objects
    assert not store.remove(dm)


def test_datastore_prune_inactive():
    store = Datastore()
    assert store.prune_inactive() is None
    dm = DeviceData(mac="00:11:22:33:44:55")
    dm._is_active = True
    store.objects.append(dm)
    d2 = DeviceData(ip="1.1.1.1")
    d2._is_active = False
    store.objects.append(d2)
    store.prune_inactive()
    assert d2 not in store.objects
    assert store.objects[0] is dm


def test_datastore_deduplicate():
    store = Datastore()
    assert store.deduplicate() is None
    dupe_ip = "192.0.2.3"
    d1 = store.get(dupe_ip)
    d1._is_verified = True
    d1._is_active = True
    d2 = store.get("192.0.2.2")
    d2._is_active = True
    d3 = store.get("172.16.3.3")
    d4 = DeviceData(ip=dupe_ip)
    store.objects.append(d4)
    assert len(store.objects) == 4
    store.deduplicate(prune_inactive=False)
    assert len(store.objects) == 3
    assert d3 in store.objects
    store.deduplicate(prune_inactive=True)
    assert len(store.objects) == 2
    assert d3 not in store.objects


def test_datastore_properties():
    store = Datastore()
    d1 = store.get("192.0.2.3")
    d1._is_verified = True
    d1._is_active = True
    d2 = store.get("192.0.2.2")
    d2._is_active = True
    d3 = store.get("172.16.3.3")
    assert store.verified == [d1]
    assert store.objects == [d1, d2, d3]


def _clx_comm_module(ip: str, mac: str, comm_serial: str) -> DeviceData:
    """ControlLogix device as seen via one of its communication modules."""
    dev = DeviceData(ip=ip, mac=mac, serial_number="1111")
    dev.extra["cpu_serial"] = "1111"
    dev.extra["comm_module_serial"] = comm_serial
    dev.extra["http_home_info"] = {"device_name": f"module-{ip}"}
    dev.store("service", Service(port=80, protocol="http", status="open"))
    dev.store("interface", Interface(ip=ip, mac=mac, type="ethernet"))
    dev.store("module", DeviceData(slot="0", serial_number="1111", type="PLC"), lookup="slot")
    dev.store("module", DeviceData(slot="2", serial_number="2222"), lookup="slot")
    dev.store("module", DeviceData(slot="10", serial_number="3333"), lookup="slot")
    return dev


def _clx_datastore(order: list[int]) -> tuple[Datastore, list[DeviceData]]:
    store = Datastore()
    devs = [
        _clx_comm_module("192.0.2.11", "00:00:BC:00:00:11", "3333"),
        _clx_comm_module("192.0.2.10", "00:00:BC:00:00:10", "2222"),
    ]
    devs[0].store("service", Service(port=21, protocol="ftp", status="open"))
    for i in order:
        store.objects.append(devs[i])
    return store, devs


@pytest.mark.parametrize("order", [[0, 1], [1, 0]])
def test_datastore_deduplicate_controllogix_comm_modules(order):
    store, _ = _clx_datastore(order)
    store.deduplicate(prune_inactive=False)
    assert len(store.objects) == 1
    dev = store.objects[0]

    # Primary is the module with the lowest IP, regardless of datastore order
    assert dev.ip == "192.0.2.10"
    assert dev.mac == "00:00:BC:00:00:10"
    assert dev.slot == "2"
    assert dev.extra["comm_module_serial"] == "2222"
    assert dev.extra["http_home_info"] == {"device_name": "module-192.0.2.10"}
    assert {"192.0.2.10", "192.0.2.11"} <= dev.related.ip

    # Services of the secondary module don't get mixed in with the primary's
    assert [(s.port, s.protocol) for s in dev.service] == [(80, "http")]

    # Each comm module has its own network info
    assert sorted(m.slot for m in dev.module) == ["0", "10", "2"]
    mods = {m.slot: m for m in dev.module}
    cpu, primary_mod, secondary_mod = mods["0"], mods["2"], mods["10"]
    assert not cpu.ip
    assert primary_mod.ip == "192.0.2.10"
    assert primary_mod.mac == "00:00:BC:00:00:10"
    assert [(s.port, s.protocol) for s in primary_mod.service] == [(80, "http")]
    assert secondary_mod.ip == "192.0.2.11"
    assert secondary_mod.mac == "00:00:BC:00:00:11"
    assert sorted((s.port, s.protocol) for s in secondary_mod.service) == [
        (21, "ftp"),
        (80, "http"),
    ]
    assert [i.ip for i in secondary_mod.interface] == ["192.0.2.11"]
    assert secondary_mod.extra["http_home_info"] == {"device_name": "module-192.0.2.11"}

    # Interfaces of both comm modules are on the device
    assert sorted(i.ip for i in dev.interface) == ["192.0.2.10", "192.0.2.11"]


def test_datastore_deduplicate_controllogix_deterministic():
    results = []
    for order in ([0, 1], [1, 0]):
        store, _ = _clx_datastore(order)
        store.deduplicate(prune_inactive=False)
        results.append(store.objects[0].export())
    assert results[0] == results[1]


def test_datastore_deduplicate_controllogix_different_cpus():
    store, devs = _clx_datastore([0, 1])
    devs[1].extra["cpu_serial"] = "9999"
    store.deduplicate(prune_inactive=False)
    assert len(store.objects) == 2


def test_datastore_deduplicate_same_ip_keeps_first():
    store = Datastore()
    d1 = DeviceData(ip="192.0.2.5", name="first")
    d2 = DeviceData(ip="192.0.2.5", mac="00:00:BC:00:00:05", name="second")
    d3 = DeviceData(mac="00:00:BC:00:00:05")
    store.objects.extend([d1, d2, d3])
    store.deduplicate(prune_inactive=False)
    # d3 only matches d1 through d2's MAC
    assert store.objects == [d1]
    assert d1.name == "first"
    assert d1.mac == "00:00:BC:00:00:05"
