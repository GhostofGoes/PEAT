import re

import pytest
import requests
import requests_mock as requests_mock_module

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


def test_sel_http_view_syslog_short_line(sel_env, requests_mock):  # noqa: ARG001
    soe = (
        '"message","t_value","device_name"\n'
        '"admin logged on device via Web","2024-01-02 03:04:05","rtac1"\n'
        '"truncated line"\n'
    )
    requests_mock.get("http://192.0.2.10:80/soe.csv", text=soe)
    dev = datastore.get("192.0.2.10")

    # Previously, IndexError
    result = SELHTTP("192.0.2.10", 80).view_syslog(dev)
    assert len(result["web_syslog_events"]) == 1
    assert result["web_syslog_events"][0]["device_name"] == "rtac1"
    assert "admin" in dev.related.user


@pytest.mark.parametrize(
    "href",
    [
        "http://127.0.0.1\\@192.0.2.10/cert.pem",
        "//127.0.0.1\\@192.0.2.10/cert.pem",
        "http://127.0.0.1/cert.pem",
        "/cert\t.pem",
    ],
)
def test_sel_http_cert_export_skips_off_host_links(sel_env, requests_mock, href):  # noqa: ARG001
    requests_mock.post(
        "http://192.0.2.10:80/X509.sel",
        text=f'<a class="listButton" href="{href}">Export</a>',
    )
    other = requests_mock.register_uri(
        requests_mock_module.ANY, re.compile(r"^https?://127\.0\.0\.1"), text="secret"
    )
    cert = requests_mock.post(re.compile(r"^http://192\.0\.2\.10:80/cert"), text="x")

    dev = datastore.get("192.0.2.10")
    assert SELHTTP("192.0.2.10", 80).gateway_cert_export(dev) == {"x509_certificates": {}}
    assert not other.called
    assert not cert.called


@pytest.mark.parametrize("href", ["/N1234\\@127.0.0.1/ver.html", "/N1234 /ver.html"])
def test_sel_http_login_rejects_unsafe_session_link(sel_env, requests_mock, href):  # noqa: ARG001
    requests_mock.get("http://192.0.2.10:80/", text=LOGIN_PAGE)
    requests_mock.post("http://192.0.2.10:80/login", text=f'<a href="{href}">x</a>')

    sel = SELHTTP("192.0.2.10", 80)
    assert sel.login() is False
    assert sel._session_url == ""
