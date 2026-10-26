import pytest

from peat import CommError, datastore, exit_handler
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
