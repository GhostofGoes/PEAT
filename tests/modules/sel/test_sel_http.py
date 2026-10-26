import pytest
import requests

from peat import config, datastore
from peat.modules.sel.sel_http import SELHTTP
from peat.protocols.http import HTTP

LOGIN_PAGE = '<html><input type="hidden" value="12345"></html>'


@pytest.fixture
def sel_env(mocker, tmp_path):
    mocker.patch.object(datastore, "objects", [])
    mocker.patch.object(HTTP, "page_cache", type(HTTP.page_cache)())
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path / "devices", "TEMP_DIR": None})


@pytest.mark.parametrize("plain_session", [False, True])
def test_sel_http_login_refuses_off_host_redirect(sel_env, requests_mock, plain_session):  # noqa: ARG001
    requests_mock.get("http://192.0.2.10:80/", text=LOGIN_PAGE)
    requests_mock.post(
        "http://192.0.2.10:80/login",
        status_code=302,
        headers={"Location": "http://127.0.0.1:8080/N1234/protected/"},
    )
    other = requests_mock.get(
        "http://127.0.0.1:8080/N1234/protected/", text='<a href="/N1234/ver.html">x</a>'
    )

    sel = SELHTTP("192.0.2.10", 80)
    if plain_session:  # follows any redirect, so the session URL check must catch it
        sel.session = requests.Session()

    assert sel.login() is False
    assert sel._session_url == ""
    assert not sel.relay_logged_in
    if not plain_session:
        assert not other.called


@pytest.mark.parametrize(
    "body",
    [
        '<a href="http://127.0.0.1/N1234/ver.html">x</a>',
        '<a href="//127.0.0.1/N1234/ver.html">x</a>',
        "<p>no link</p>",
    ],
)
def test_sel_http_login_rejects_bad_session_link(sel_env, requests_mock, body):  # noqa: ARG001
    requests_mock.get("http://192.0.2.10:80/", text=LOGIN_PAGE)
    requests_mock.post("http://192.0.2.10:80/login", text=body)

    sel = SELHTTP("192.0.2.10", 80)
    assert sel.login() is False
    assert sel._session_url == ""


def test_sel_http_login_relative_session_link(sel_env, requests_mock):  # noqa: ARG001
    requests_mock.get("http://192.0.2.10:80/", text=LOGIN_PAGE)
    requests_mock.post("http://192.0.2.10:80/login", text='<a href="/N1234/ver.html">x</a>')

    sel = SELHTTP("192.0.2.10", 80)
    assert sel.login() is True
    assert sel._session_url == "http://192.0.2.10:80/protected/N1234/"
