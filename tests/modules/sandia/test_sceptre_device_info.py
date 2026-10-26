import pytest

from peat import SCEPTRE, datastore
from peat.modules.sandia.sceptre_fcd import BRASH_PORT, FIRMWARE_UPLOAD_NAME, _initial_value

# Firmware with the "START_SHELL_0" string from bennu-field-deviced's main.cpp
ORIGINAL = b"\x7fELF bennu START_SHELL_0"
SHELL = ORIGINAL.replace(b"_SHELL_0", b"_SHELL_1")


@pytest.fixture
def dev(mocker):
    mocker.patch.object(datastore, "objects", [])
    return datastore.get("192.0.2.10")


def _mock_download(mocker, uploaded: bytes | None, original: bytes | None) -> None:
    def download(_dev, candidates, *_args, **_kwargs):
        data = uploaded if candidates == [FIRMWARE_UPLOAD_NAME] else original
        return (data, None, candidates[0]) if data is not None else (None, None, "")

    mocker.patch.object(SCEPTRE, "_download_ftp", side_effect=download)


def _brash_services(dev) -> list:
    return [s for s in dev.service if s.protocol == "brash"]


@pytest.mark.parametrize("port_open", [True, False])
def test_pull_firmware_shell_enabled(dev, mocker, port_open):
    _mock_download(mocker, SHELL, ORIGINAL)
    check = mocker.patch("peat.modules.sandia.sceptre_fcd.check_tcp_port", return_value=port_open)

    assert SCEPTRE.pull_firmware(dev) == SHELL

    check.assert_called_once()
    assert check.call_args.args[:2] == ("192.0.2.10", BRASH_PORT)
    assert dev.firmware.extra["shell_enabled"] is True
    assert dev.firmware.extra["watcher_accepted"] is True
    services = _brash_services(dev)
    assert len(services) == 1
    assert services[0].port == BRASH_PORT
    assert services[0].transport == "tcp"
    assert services[0].status == ("open" if port_open else "closed")
    alert = dev.event[-1]
    assert alert.action == "shell-firmware"
    assert "alert" in alert.kind
    assert alert.category == {"intrusion_detection"}


def test_pull_firmware_shell_disabled(dev, mocker):
    _mock_download(mocker, None, ORIGINAL)
    check = mocker.patch("peat.modules.sandia.sceptre_fcd.check_tcp_port")

    assert SCEPTRE.pull_firmware(dev) == ORIGINAL

    check.assert_not_called()
    assert dev.firmware.extra["shell_enabled"] is False
    # Nothing was uploaded, so there's nothing for the watcher to accept
    assert "watcher_accepted" not in dev.firmware.extra
    assert not _brash_services(dev)
    assert not dev.event


def test_pull_firmware_rejected_upload(dev, mocker):
    # The watcher ignores the upload, so the original binary (no shell) is running
    _mock_download(mocker, SHELL + b"junk", ORIGINAL)
    check = mocker.patch("peat.modules.sandia.sceptre_fcd.check_tcp_port")

    assert SCEPTRE.pull_firmware(dev) == ORIGINAL

    check.assert_not_called()
    assert dev.firmware.extra["watcher_accepted"] is False
    assert dev.firmware.extra["shell_enabled"] is False


def test_pull_firmware_no_shell_marker(dev, mocker):
    _mock_download(mocker, None, b"\x7fELF")
    assert SCEPTRE.pull_firmware(dev) == b"\x7fELF"
    assert "shell_enabled" not in dev.firmware.extra


@pytest.mark.parametrize(
    ("username", "password", "default"),
    [("sceptre", "sceptre", True), ("sceptre", "changed", False), ("other", "sceptre", False)],
)
def test_store_ftp_user(dev, username, password, default):
    SCEPTRE._store_ftp_user(dev, username, password)
    SCEPTRE._store_ftp_user(dev, username, password)

    assert len(dev.users) == 1
    user = dev.users[0]
    assert user.name == username
    assert user.extra == {"default_credentials": default}
    assert username in dev.related.user


@pytest.mark.parametrize(
    ("value", "tag_type", "expected"),
    [
        ("false", "binary", False),
        ("1", "binary", True),
        (" true ", "binary", True),
        # bennu can't read these, so they stay strings
        ("TRUE", "binary", "TRUE"),
        ("nan", "analog", "nan"),
        ("inf", "analog", "inf"),
        ("1_0", "analog", "1_0"),
        ("1e3", "analog", 1000.0),
        (".5", "analog", 0.5),
        ("0.0", "analog", 0.0),
        ("-2", "analog", -2.0),
        ("65535", "analog", 65535.0),
        ("not a number", "analog", "not a number"),
        ("maybe", "binary", "maybe"),
        ("hello", "string", "hello"),
    ],
)
def test_initial_value(value, tag_type, expected):
    result = _initial_value(value, tag_type)
    assert result == expected
    assert type(result) is type(expected)


def test_pull_firmware_shell_alert_once(dev, mocker):
    _mock_download(mocker, SHELL, ORIGINAL)
    mocker.patch("peat.modules.sandia.sceptre_fcd.check_tcp_port", return_value=True)
    SCEPTRE.pull_firmware(dev)
    SCEPTRE.pull_firmware(dev)
    assert [e.action for e in dev.event] == ["shell-firmware"]
    assert len(_brash_services(dev)) == 1


def test_pull_firmware_shell_unverified(dev, mocker):
    # The original binary is missing, so the upload can't be checked
    _mock_download(mocker, SHELL, None)
    mocker.patch("peat.modules.sandia.sceptre_fcd.check_tcp_port", return_value=True)
    assert SCEPTRE.pull_firmware(dev) == SHELL
    assert dev.firmware.extra["shell_enabled"] is True
    assert "watcher_accepted" not in dev.firmware.extra
    assert "may not be installed" in dev.event[-1].message
