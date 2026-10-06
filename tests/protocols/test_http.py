import pytest

from peat import config, consts, datastore
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


@pytest.fixture(autouse=True)
def http_dirs(mocker, tmp_path):
    mocker.patch.dict(
        config["CONFIG"],
        {"DEVICE_DIR": tmp_path / "devices", "TEMP_DIR": tmp_path / "temp"},
    )
    # Device objects (and their output directories) are global, keyed by IP
    mocker.patch.object(datastore, "objects", [])
    HTTP.page_cache.clear()
    yield tmp_path / "devices"
    HTTP.page_cache.clear()


def test_http_get(requests_mock, http_dirs):
    requests_mock.get("http://192.0.2.10:80/status.html", text="<html>status</html>")

    http = HTTP("192.0.2.10")
    response = http.get("/status.html")

    assert response is not None
    assert response.text == "<html>status</html>"
    assert response.request_timestamp is not None
    assert response.response_timestamp >= response.request_timestamp
    assert response.file_path.name == "status.html"
    assert response.file_path.read_text(encoding="utf-8") == "<html>status</html>"
    assert http_dirs in response.file_path.parents

    # Second call is served from the page cache
    assert http.get("status.html") is response
    assert requests_mock.call_count == 1

    # Unless caching is disabled
    assert http.get("status.html", use_cache=False) is not response
    assert requests_mock.call_count == 2


def test_http_get_params_and_auth(requests_mock):
    requests_mock.get("http://192.0.2.10:8080/cgi", text="ok")

    response = HTTP("192.0.2.10", port=8080).get(
        "cgi", params={"page": "1"}, auth=("user", "pass"), use_cache=False
    )

    assert response.text == "ok"
    request = requests_mock.last_request
    assert request.qs == {"page": ["1"]}
    assert request.headers["Authorization"].startswith("Basic ")


@pytest.mark.parametrize(
    ("status_code", "allow_errors", "expect_response"),
    [(200, False, True), (404, False, False), (500, False, False), (404, True, True)],
)
def test_http_get_status_codes(
    requests_mock, http_dirs, status_code, allow_errors, expect_response
):
    requests_mock.get("http://192.0.2.10:80/page", text="body", status_code=status_code)

    response = HTTP("192.0.2.10").get("page", allow_errors=allow_errors, use_cache=False)

    assert (response is not None) is expect_response
    # Body is saved to disk even for error responses
    assert list(http_dirs.rglob("page.html"))


def test_http_get_connection_error(requests_mock):
    import requests

    requests_mock.get("http://192.0.2.10:80/", exc=requests.exceptions.ConnectionError)
    assert HTTP("192.0.2.10").get() is None


def test_http_get_https_on_port_80(requests_mock):
    requests_mock.get("https://192.0.2.10:443/secure", text="secure")
    response = HTTP("192.0.2.10", port=80).get("secure", protocol="https")
    assert response.text == "secure"


def test_http_get_full_url_and_query_filename(requests_mock):
    requests_mock.get("http://192.0.2.10:80/diag?0x0D00", text="diag")

    response = HTTP("192.0.2.10").get(url="http://192.0.2.10:80/diag?0x0D00")

    assert response.text == "diag"
    assert response.file_path.name == "diag0x0D00.html"


def test_http_get_content_disposition_filename(requests_mock):
    requests_mock.get(
        "http://192.0.2.10:80/download",
        text="config data",
        headers={"Content-Disposition": 'attachment; filename="SET_ALL.TXT"'},
    )

    response = HTTP("192.0.2.10").get("download")

    assert response.file_path.name == "SET_ALL.TXT"
    assert response.file_path.read_text(encoding="utf-8") == "config data"


def test_http_post(requests_mock):
    requests_mock.post("http://192.0.2.10:80/login.cgi", text="welcome")

    http = HTTP("192.0.2.10")
    response = http.post("http://192.0.2.10:80/login.cgi", data={"user": "admin"})

    assert response.text == "welcome"
    assert requests_mock.last_request.text == "user=admin"
    assert response.file_path.name == "login.cgi.html"

    # POST responses aren't served from the cache by default
    second = http.post("http://192.0.2.10:80/login.cgi")
    assert second is not response
    assert http.post("http://192.0.2.10:80/login.cgi", use_cache=True) is second
    assert requests_mock.call_count == 2


def test_http_post_error_status(requests_mock):
    requests_mock.post("http://192.0.2.10:80/login.cgi", text="denied", status_code=403)
    assert HTTP("192.0.2.10").post("http://192.0.2.10:80/login.cgi") is None


def test_http_session_lifecycle():
    http = HTTP("192.0.2.10", port=443)
    assert http.protocol == "https"
    assert http.url == "https://192.0.2.10:443"
    assert not http.connected

    class Headers(HTTP):
        DEFAULT_HEADERS = {"Connection": "close"}

    with Headers("192.0.2.10") as h:
        assert h.session.headers["Connection"] == "close"
        assert h.connected
