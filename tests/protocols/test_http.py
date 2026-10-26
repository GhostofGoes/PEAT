import io
import subprocess
import sys
from pathlib import Path

import pytest
from requests import Response

from peat import config, consts, datastore
from peat.protocols import http as http_module
from peat.protocols.http import HTTP


def test_http_class():
    ip = "127.0.0.1"
    obj = HTTP(ip)
    assert str(obj) == ip
    assert obj.gen_soup("")
    assert obj.gen_soup(b"")
    assert obj.gen_session()


def test_http_decode_ssl_certificate(mocker, datapath, deep_compare, tmp_path, read_text):
    mocker.patch.dict(config["CONFIG"], {"TEMP_DIR": None})

    cert_path = datapath("sage_certificate.cert")
    cert_data = read_text(cert_path)
    expected = {
        "version": 1,
        "serialNumber": "D8796CC54080FB3E",
        "notBefore": "Mar 30 16:54:51 2012 GMT",
        "notAfter": "Mar 30 16:54:51 2042 GMT",
    }

    h = HTTP("127.0.0.1")

    file_res = h.decode_ssl_certificate(cert_path)
    assert file_res[1] == cert_data
    deep_compare(file_res[0], expected, exclude_regexes=r"\['(issuer|subject)'\]")

    text_res = h.decode_ssl_certificate(cert_path.read_text(encoding="utf-8"))
    assert text_res[1] == cert_data
    deep_compare(text_res[0], expected, exclude_regexes=r"\['(issuer|subject)'\]")
    assert file_res == text_res

    # ensure it works with TEMP_DIR set
    mocker.patch.dict(config["CONFIG"], {"TEMP_DIR": tmp_path})
    h2 = HTTP("127.0.0.1")
    tempfile_res = h2.decode_ssl_certificate(cert_path)
    assert tempfile_res[1] == cert_data
    deep_compare(tempfile_res[0], expected, exclude_regexes=r"\['(issuer|subject)'\]")


@pytest.mark.parametrize("device_name", ["sage", "sel_2730m", "sel_3530"])
def test_http_parse_decoded_ssl_certificate(mocker, json_data, datapath, tmp_path, device_name):
    mocker.patch.dict(config["CONFIG"], {"TEMP_DIR": tmp_path})

    expected = json_data(f"expected_parsed_{device_name}_certificate.json")
    cert_pth = datapath(f"{device_name}_certificate.cert")

    h = HTTP("127.0.0.1")
    decoded, raw = h.decode_ssl_certificate(cert_pth)
    parsed = h.parse_decoded_ssl_certificate(decoded, raw)
    parsed.annotate()  # populate hash fields
    data = consts.convert(parsed.dict(exclude_defaults=True, exclude_none=True))
    assert data == expected


@pytest.mark.parametrize(
    "disposition",
    [
        'attachment; filename="../../../../../http_rel_escape.html"',
        "attachment; filename={tmp_path}/http_abs_escape.html",
        'attachment; filename="..\\\\..\\\\http_win_escape.html"; size=10',
    ],
)
def test_http_save_response_content_disposition_contained(mocker, tmp_path, disposition):
    mocker.patch.object(datastore, "objects", [])
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path / "devices"})
    dev = datastore.get("127.0.0.1")

    response = Response()
    response.status_code = 200
    response._content = b"<html>hello</html>"
    response.headers["Content-Disposition"] = disposition.format(tmp_path=tmp_path.as_posix())

    h = HTTP("127.0.0.1", dev=dev)
    path = h._save_response_to_file(response, "", "http://127.0.0.1/download", dev)

    http_dir = dev.get_sub_dir("http_files")
    assert path is not None
    assert path.parent == http_dir
    assert path.name.startswith("http_")
    assert path.name.endswith("_escape.html")
    written = [p for p in tmp_path.rglob("*") if p.is_file()]
    assert written == [path]


@pytest.fixture
def tls_env(mocker):
    """Fresh TLS warning state and an empty datastore."""
    mocker.patch.object(http_module, "_tls_warned_hosts", set(), create=True)
    mocker.patch.object(http_module, "_tls_hint_hosts", set(), create=True)
    mocker.patch.object(http_module, "_tls_bad_ca_bundles", set(), create=True)
    mocker.patch.object(datastore, "objects", [])
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": None, "TEMP_DIR": None})


def test_gen_session_verifies_by_default(tls_env):  # noqa: ARG001
    session = HTTP.gen_session()
    assert session.verify is True
    assert session.trust_env is False
    assert HTTP("127.0.0.1", 443).session.verify is True


def test_gen_session_ca_bundle(tls_env, mocker, tmp_path):  # noqa: ARG001
    bundle = tmp_path / "ca.pem"
    bundle.write_text("", encoding="utf-8")
    mocker.patch.dict(config["CONFIG"], {"TLS_CA_BUNDLE": bundle})
    assert HTTP.gen_session().verify == str(bundle)
    assert HTTP("127.0.0.1", 443).session.verify == str(bundle)


def test_gen_session_missing_ca_bundle(tls_env, mocker, tmp_path, log_messages):  # noqa: ARG001
    bundle = tmp_path / "missing-ca.pem"
    mocker.patch.dict(config["CONFIG"], {"TLS_CA_BUNDLE": bundle})
    # Still verifies (with the missing bundle, so connections fail closed)
    assert HTTP.gen_session().verify == str(bundle)
    assert HTTP("127.0.0.1", 443).session.verify == str(bundle)

    errors = [m for m in log_messages if "'tls_ca_bundle'" in m and str(bundle) in m]
    assert len(errors) == 1  # logged once
    assert "doesn't exist" in errors[0]


def test_tls_verify_disabled_globally_warns(tls_env, mocker, log_messages):  # noqa: ARG001
    mocker.patch.dict(config["CONFIG"], {"TLS_VERIFY": False, "TLS_CA_BUNDLE": Path("x.pem")})
    assert HTTP("127.0.0.1", 443).session.verify is False
    assert HTTP("127.0.0.1", 443).session.verify is False

    warnings = [m for m in log_messages if "verification is DISABLED" in m]
    assert len(warnings) == 1  # once per host
    assert "tls_verify: true" in warnings[0]


def test_tls_verify_disabled_per_device(tls_env, log_messages):  # noqa: ARG001
    dev = datastore.get("127.0.0.2")
    dev._runtime_options["https"] = {"verify": False}

    assert HTTP("127.0.0.2", 443, dev=dev).session.verify is False
    assert HTTP("127.0.0.2", 443).session.verify is False  # found via the datastore
    assert HTTP("127.0.0.3", 443).session.verify is True  # other hosts are unaffected
    assert any("'https.verify' is false" in m for m in log_messages)


def test_http_get_self_signed_rejected(tls_env, https_server, log_messages):  # noqa: ARG001
    http = HTTP("127.0.0.1", https_server.port, protocol="https")
    assert http.get("index.html", use_cache=False) is None
    assert https_server.requests == []
    assert any(
        "TLS certificate verification failed" in m and "verify: false" in m for m in log_messages
    )


def test_http_tls_failure_hint_logged_once_per_host(tls_env, https_server, log_messages):  # noqa: ARG001
    http = HTTP("127.0.0.1", https_server.port, protocol="https")
    for page in ["a.html", "b.html", "c.html"]:
        assert http.get(page, use_cache=False) is None
    assert http.post(f"{https_server.url}d.html") is None

    failures = [m for m in log_messages if "TLS certificate verification failed" in m]
    assert len(failures) == 4  # every failure is still logged
    assert len([m for m in failures if "verify: false" in m]) == 1


def test_http_get_self_signed_trusted_bundle(tls_env, mocker, https_server):  # noqa: ARG001
    # Negative control: refused with the default CA certificates
    http = HTTP("127.0.0.1", https_server.port, protocol="https")
    assert http.get("index.html", use_cache=False) is None
    assert https_server.requests == []

    mocker.patch.dict(config["CONFIG"], {"TLS_CA_BUNDLE": https_server.cert_path})
    http = HTTP("127.0.0.1", https_server.port, protocol="https")
    response = http.get("index.html", use_cache=False)
    assert response is not None
    assert response.status_code == 200


def test_http_get_self_signed_verify_disabled(tls_env, https_server):  # noqa: ARG001
    # Negative control: refused while verification is enabled
    http = HTTP("127.0.0.1", https_server.port, protocol="https")
    assert http.get("index.html", use_cache=False) is None
    assert https_server.requests == []

    dev = datastore.get("127.0.0.1")
    dev._runtime_options["https"] = {"verify": False}
    http = HTTP("127.0.0.1", https_server.port, protocol="https", dev=dev)
    response = http.get("index.html", use_cache=False)
    assert response is not None
    assert response.status_code == 200


def test_import_does_not_silence_urllib3_warnings():
    # Run in a new interpreter, since other tests may have disabled the warning
    code = (
        "import warnings, peat, urllib3\n"
        "with warnings.catch_warnings(record=True) as w:\n"
        "    warnings.warn('x', urllib3.exceptions.InsecureRequestWarning)\n"
        "print(len(w))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip().splitlines()[-1] == "1"


@pytest.fixture
def http_env(mocker, tmp_path):
    """Empty datastore, empty page cache, and files written under tmp_path."""
    mocker.patch.object(datastore, "objects", [])
    mocker.patch.object(HTTP, "page_cache", type(HTTP.page_cache)())
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path / "devices", "TEMP_DIR": None})


def test_http_get_refuses_off_host_redirect(http_env, requests_mock, log_messages):  # noqa: ARG001
    requests_mock.get(
        "http://192.0.2.10:80/redir",
        status_code=302,
        headers={"Location": "http://127.0.0.1:8080/internal-admin"},
    )
    internal = requests_mock.get("http://127.0.0.1:8080/internal-admin", text="secret")

    assert HTTP("192.0.2.10").get("redir", use_cache=False) is None
    assert not internal.called
    assert any("different host" in m for m in log_messages)


def test_http_post_refuses_off_host_redirect(http_env, requests_mock):  # noqa: ARG001
    requests_mock.post(
        "http://192.0.2.10:80/login",
        status_code=307,
        headers={"Location": "//198.51.100.1/collect"},
    )
    other = requests_mock.post("http://198.51.100.1/collect", text="x")

    assert HTTP("192.0.2.10").post("http://192.0.2.10:80/login", data={"pw": "x"}) is None
    assert not other.called


def test_http_get_follows_same_host_redirect(http_env, requests_mock):  # noqa: ARG001
    requests_mock.get(
        "http://192.0.2.10:80/", status_code=302, headers={"Location": "https://192.0.2.10/home"}
    )
    requests_mock.get("https://192.0.2.10/home", text="<html>home</html>")

    response = HTTP("192.0.2.10").get(use_cache=False)
    assert response is not None
    assert response.status_code == 200
    assert response.text == "<html>home</html>"
    assert response.url == "https://192.0.2.10/home"
    assert [r.status_code for r in response.history] == [302]


def test_http_post_same_host_redirect_becomes_get(http_env, requests_mock):  # noqa: ARG001
    requests_mock.post(
        "http://192.0.2.10:80/login", status_code=303, headers={"Location": "/welcome"}
    )
    welcome = requests_mock.get("http://192.0.2.10:80/welcome", text="ok")

    response = HTTP("192.0.2.10").post("http://192.0.2.10:80/login", data={"user": "x"})
    assert response is not None
    assert response.text == "ok"
    assert welcome.call_count == 1
    assert welcome.last_request.body is None


def test_http_get_redirect_limit(http_env, requests_mock, log_messages):  # noqa: ARG001
    requests_mock.get("http://192.0.2.10:80/loop", status_code=302, headers={"Location": "/loop"})

    assert HTTP("192.0.2.10").get("loop", use_cache=False) is None
    assert requests_mock.call_count == http_module.MAX_HTTP_REDIRECTS + 1
    assert any("too many redirects" in m for m in log_messages)


def test_same_host_session_refuses_off_host_redirect(requests_mock):
    requests_mock.get(
        "http://192.0.2.10/login", status_code=302, headers={"Location": "http://127.0.0.1/"}
    )
    internal = requests_mock.get("http://127.0.0.1/", text="internal")
    requests_mock.get(
        "http://192.0.2.10/a", status_code=301, headers={"Location": "http://192.0.2.10/b"}
    )
    requests_mock.get("http://192.0.2.10/b", text="b")

    session = HTTP.gen_session(verify=False)
    response = session.get("http://192.0.2.10/login")
    assert response.status_code == 302  # The redirect isn't followed
    assert response.url == "http://192.0.2.10/login"
    assert not internal.called
    assert session.get("http://192.0.2.10/a").text == "b"


def test_http_get_refuses_oversize_body(http_env, requests_mock, log_messages):  # noqa: ARG001
    requests_mock.get("http://192.0.2.10:80/big", content=b"A" * 2048)

    http = HTTP("192.0.2.10")
    assert http.get("big", use_cache=False, max_body_size=1024) is None
    assert any("too large" in m for m in log_messages)
    assert http.get("big", use_cache=False, max_body_size=4096).content == b"A" * 2048


def test_http_get_refuses_oversize_body_without_content_length(
    http_env,  # noqa: ARG001
    requests_mock,
    mocker,
):
    class EndlessBody(io.RawIOBase):
        """Endless response body, with no Content-Length."""

        bytes_read = 0

        def readable(self) -> bool:
            return True

        def readinto(self, buffer) -> int:
            buffer[:] = b"A" * len(buffer)
            EndlessBody.bytes_read += len(buffer)
            return len(buffer)

    mocker.patch.object(http_module, "MAX_HTTP_BODY", 1024 * 1024)
    requests_mock.get("http://192.0.2.10:80/stream", body=EndlessBody())

    assert HTTP("192.0.2.10").get("stream", use_cache=False) is None
    assert EndlessBody.bytes_read < 2 * 1024 * 1024  # Stopped reading once over the limit


def test_page_cache_is_bounded():
    def resp(size: int) -> Response:
        r = Response()
        r._content = b"x" * size
        return r

    cache = http_module.PageCache(max_entries=3, max_bytes=100)
    for i in range(5):
        cache[f"u{i}"] = resp(10)
    assert len(cache) == 3
    assert "u0" not in cache
    assert cache.get("u4") is not None

    cache.get("u2")  # most recently used, so u3 is removed next
    cache["big"] = resp(80)
    assert "u3" not in cache
    assert "u2" in cache
    assert cache.total_bytes <= 100

    cache["huge"] = resp(1000)  # larger than the whole cache, not cached
    assert "huge" not in cache
