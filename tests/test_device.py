import pytest

from peat import SCEPTRE, ControlLogix, DeviceData, DeviceModule, SELRelay
from peat.protocols.cache import CacheKey, data_cache


def test_device_method_implemented():
    assert ControlLogix.method_implemented("_parse") is False
    assert SELRelay.method_implemented("_parse")
    assert SCEPTRE.method_implemented("_parse")


def test_device_base_methods():
    """
    This is mostly for coverage purposes.
    """
    dev = DeviceData()
    assert DeviceModule._pull(dev) is None
    assert DeviceModule._push(dev, "", "config") is None
    assert DeviceModule._parse(None, None) is None


def test_push_bypasses_and_invalidates_cache():
    calls = []

    class PushModule(DeviceModule):
        @classmethod
        def _push(cls, dev, to_push, push_type):  # noqa: ARG003
            calls.append(data_cache.active)
            # Cached data is not used during the push
            assert data_cache.get(CacheKey("http", "192.0.2.5", 80, "GET /")) is None
            return True

    data_cache.put(CacheKey("http", "192.0.2.5", 80, "GET /"), "page")
    data_cache.put(CacheKey("ftp-file", "192.0.2.5", 21, "binary:/x"), b"file")
    data_cache.put(CacheKey("http", "relay-1", 80, "GET /"), "by hostname")
    data_cache.put(CacheKey("http", "192.0.2.6", 80, "GET /"), "other device")

    dev = DeviceData(ip="192.0.2.5", hostname="relay-1")
    assert PushModule.push(dev, "config data", "config") is True
    assert calls == [False]
    assert data_cache.active

    # Data from the device is removed, data from other devices is kept
    assert len(data_cache) == 1
    assert data_cache.get(CacheKey("http", "192.0.2.6", 80, "GET /")) == "other device"


def test_push_invalidates_cache_on_failure():
    class FailingPushModule(DeviceModule):
        @classmethod
        def _push(cls, dev, to_push, push_type):  # noqa: ARG003
            raise RuntimeError("push failed")

    data_cache.put(CacheKey("http", "192.0.2.5", 80, "GET /"), "page")
    with pytest.raises(RuntimeError):
        FailingPushModule.push(DeviceData(ip="192.0.2.5"), "config data", "config")
    assert len(data_cache) == 0
    assert data_cache.active
