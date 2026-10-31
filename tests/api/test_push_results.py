"""
Tests for what happens when a push to a device fails: the push to the
other devices continues (``peat.api.push_api.push``), and the device
results are still exported (``peat.cli_main.oneshot_main``).
"""

from unittest.mock import MagicMock

import pytest

from peat import cli_main, config, datastore
from peat.api import push_api


def _dev(ip: str, result: bool | Exception) -> MagicMock:
    dev = datastore.get(ip, "ip")
    dev._is_verified = True
    module = MagicMock(name=f"module for {ip}")
    if isinstance(result, Exception):
        module.push.side_effect = result
    else:
        module.push.return_value = result
    dev._module = module
    return dev


@pytest.fixture(autouse=True)
def _empty_datastore(mocker):
    mocker.patch.object(datastore, "objects", [])


def test_push_continues_after_failed_device(mocker, tmp_path, caplog):
    devices = [
        _dev("192.0.2.1", RuntimeError("relay exploded")),
        _dev("192.0.2.2", False),
        _dev("192.0.2.3", True),
    ]
    mocker.patch.object(push_api, "scan", return_value={"hosts_verified": 3})

    assert not push_api.push(["192.0.2.0/30"], "unicast_ip", ["selrelay"], tmp_path, "config")

    for dev in devices:
        dev._module.push.assert_called_once_with(dev=dev, to_push=tmp_path, push_type="config")

    # The exception is logged for the device that raised it (not an UnboundLocalError)
    assert "Failed to push to 192.0.2.1" in caplog.text
    assert "relay exploded" in caplog.text
    assert "Push failed for 2 of 3 devices: 192.0.2.1, 192.0.2.2" in caplog.text


def test_push_all_devices_successful(mocker, tmp_path):
    devices = [_dev("192.0.2.1", True), _dev("192.0.2.2", True)]
    mocker.patch.object(push_api, "scan", return_value={"hosts_verified": 2})

    assert push_api.push(["192.0.2.1", "192.0.2.2"], "unicast_ip", ["clx"], tmp_path, "config")
    assert all(dev._module.push.call_count == 1 for dev in devices)


def test_push_skip_scan_names_failed_device(mocker, tmp_path, caplog):
    module = MagicMock()
    module.push.side_effect = [RuntimeError("first failed"), True]
    mocker.patch.object(push_api.module_api, "lookup_types", return_value=[module])

    assert not push_api.push(
        ["192.0.2.1", "192.0.2.2"], "unicast_ip", ["clx"], tmp_path, "config", skip_scan=True
    )

    assert module.push.call_count == 2
    # The device that failed, not the last device in the list
    assert "Failed to push to 192.0.2.1" in caplog.text
    assert "Failed to push to 192.0.2.2" not in caplog.text
    assert "Push failed for 1 of 2 devices: 192.0.2.1" in caplog.text


@pytest.mark.parametrize(
    ("push_result", "export_result", "expected"),
    [
        (False, True, False),
        (True, True, True),
        (True, False, False),
        (False, False, False),
    ],
)
def test_cli_push_exports_results_when_push_fails(
    mocker, tmp_path, push_result, export_result, expected
):
    mocker.patch.dict(config["CONFIG"], {"DRY_RUN": False, "PUSH_SKIP_SCAN": False})
    mocker.patch.object(
        cli_main, "get_targets", return_value=(["192.0.2.1"], "unicast_ip", ["selrelay"])
    )
    push = mocker.patch.object(cli_main, "push", return_value=push_result)
    export = mocker.patch.object(cli_main, "export_device_data", return_value=export_result)
    args = {"func": "push", "input_source": tmp_path, "push_type": "config"}

    assert cli_main.oneshot_main(args) is expected

    push.assert_called_once()
    export.assert_called_once_with(args)
