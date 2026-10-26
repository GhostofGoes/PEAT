import pytest

from peat import CommError, DeviceData, datastore, exit_handler
from peat.modules.idirect import idirect
from peat.modules.idirect.idirect import Idirect


@pytest.fixture
def dev(mocker):
    mocker.patch.object(datastore, "objects", [])
    mocker.patch.object(exit_handler, "register")
    device = datastore.get("192.0.2.5")
    device._runtime_options["ssh"] = {
        "port": 22,
        "timeout": 1.0,
        "user": "admin",
        "pass": "p",
    }
    return device


def test_pull_ssh_read_timeout(mocker, dev):
    """SSH.read() raises CommError when a device sends nothing (it used to wait)."""
    session = mocker.MagicMock()
    session.read.side_effect = CommError("No SSH data from 192.0.2.5 within 1.0 seconds")
    mocker.patch.object(idirect, "IdirectSSH", return_value=session)

    assert Idirect._pull_ssh(dev) is False
    session.disconnect.assert_called_once()
    assert "idirect_ssh_session" not in dev._cache


def test_verify_protocol_login_failed(mocker):
    dev = DeviceData(ip="192.0.2.1")
    dev._module = Idirect
    mocker.patch.object(Idirect, "_login_ssh", return_value=None)

    # Previously, AttributeError from conn.disconnect() on None
    assert Idirect._verify_protocol(dev, "ssh") is False


def test_pull_uses_idirect_pull_methods(mocker, log_messages):
    dev = DeviceData(ip="192.0.2.1")
    dev._module = Idirect
    # Only SSL, so SSH must not be pulled
    dev._runtime_options["idirect"] = {"pull_methods": ["ssl"]}
    dev._runtime_options["sage"] = {"pull_methods": ["ssh"]}
    pull_ssh = mocker.patch.object(Idirect, "_pull_ssh", return_value=True)
    mocker.patch.object(Idirect, "_verify_protocol", return_value=True)
    mocker.patch.object(Idirect, "_verify_https_ssl_certificate", return_value=False)

    Idirect._pull(dev)
    assert not pull_ssh.called
    assert any("'idirect.pull_methods'" in m and "'Ssh'" in m for m in log_messages)
