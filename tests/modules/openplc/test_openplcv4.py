import pytest

from peat import DeviceData, config
from peat.modules.openplc.openplcv4 import OpenPLCv4
from peat.protocols import http as http_module


@pytest.fixture
def dev(mocker, https_server) -> DeviceData:
    mocker.patch.object(http_module, "_tls_warned_hosts", set(), create=True)
    dev = DeviceData(ip="127.0.0.1")
    dev._module = OpenPLCv4
    dev._runtime_options["https"] = {"port": https_server.port}
    return dev


def test_openplc_session_settings(dev, mocker, tmp_path):
    session = OpenPLCv4._gen_session(dev)
    assert session.verify is True
    assert session.trust_env is False  # ignore https_proxy, .netrc, etc.

    mocker.patch.dict(config["CONFIG"], {"TLS_CA_BUNDLE": tmp_path / "ca.pem"})
    assert OpenPLCv4._gen_session(dev).verify == str(tmp_path / "ca.pem")

    dev._runtime_options["https"]["verify"] = False
    assert OpenPLCv4._gen_session(dev).verify is False


def test_openplc_login_self_signed_rejected(dev, https_server):
    dev._runtime_options["openplcv4"] = {"username": "admin", "password": "OpenPLC-pw-7f3a"}
    session = OpenPLCv4._gen_session(dev)
    assert OpenPLCv4._login(dev, session) is False
    # The credentials were never sent to the untrusted server
    assert https_server.requests == []


def test_openplc_verify_self_signed(dev, https_server, log_messages):
    assert OpenPLCv4._verify_https_api(dev) is False
    assert https_server.requests == []
    assert any("verify: false" in m for m in log_messages)

    dev._runtime_options["https"]["verify"] = False
    OpenPLCv4._verify_https_api(dev)
    assert https_server.requests[-1]["path"] == "/api/version"
