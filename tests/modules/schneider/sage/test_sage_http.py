import pytest

from peat import config, datastore
from peat.modules.schneider.sage.sage_http import SageHTTP
from peat.protocols import http as http_module
from peat.protocols.http import HTTP


@pytest.fixture
def sage_env(mocker, tmp_path):
    mocker.patch.object(datastore, "objects", [])
    mocker.patch.object(HTTP, "page_cache", type(HTTP.page_cache)())
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path / "devices", "TEMP_DIR": None})
    mocker.patch("peat.modules.schneider.sage.sage_http.sleep")


def test_sage_config_filename_body_limit(sage_env, requests_mock, mocker, log_messages):  # noqa: ARG001
    mocker.patch.object(http_module, "MAX_HTTP_BODY", 1024)
    requests_mock.post("http://192.0.2.10:80/cgi/fx/command.html", content=b"A" * 4096)

    assert SageHTTP("192.0.2.10", 80).get_config_filename() == ""
    assert any("too large" in m for m in log_messages)


def test_sage_config_filename_off_host_redirect(sage_env, requests_mock):  # noqa: ARG001
    requests_mock.post(
        "http://192.0.2.10:80/cgi/fx/command.html",
        status_code=307,
        headers={"Location": "http://127.0.0.1/collect"},
    )
    other = requests_mock.post("http://127.0.0.1/collect", text='"status": "5"}')

    assert SageHTTP("192.0.2.10", 80).get_config_filename() == ""
    assert not other.called


def test_sage_config_filename(sage_env, requests_mock):  # noqa: ARG001
    requests_mock.post(
        "http://192.0.2.10:80/cgi/fx/command.html",
        text='{"status": "5", "fw_fileName" : "cfg.tgz"}',
    )
    assert SageHTTP("192.0.2.10", 80).get_config_filename() == "cfg.tgz"
