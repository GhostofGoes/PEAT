import pytest
import requests_mock
from requests.auth import AuthBase, HTTPDigestAuth

from peat import DeviceData, config
from peat.modules.ge.ge_relay import GERelay
from peat.modules.idirect.idirect import Idirect
from peat.modules.schneider.sage.sage import Sage
from peat.modules.sel.sel_rtac import SELRTAC
from peat.protocols.cache import NS_HTTP, NS_TLS_CERT, data_cache
from peat.protocols.http import HTTP

IP = "192.0.2.10"
BASE = f"http://{IP}:80"


@pytest.fixture(autouse=True)
def _no_files(mocker):
    """Don't write HTTP responses to files."""
    mocker.patch.object(HTTP, "_save_response_to_file", return_value=None)


@pytest.fixture
def mock_http():
    with requests_mock.Mocker() as mocker:
        yield mocker


def test_two_instances_share_get(mock_http):
    mock_http.get(f"{BASE}/", text="<html>GE Power relay</html>")
    first = HTTP(IP).get()
    second = HTTP(IP).get("")
    assert mock_http.call_count == 1
    assert first.from_cache is False
    assert second.from_cache is True
    assert second.text == first.text
    assert second.request_timestamp == first.request_timestamp
    assert second.response_timestamp == first.response_timestamp
    assert second is not first
    assert data_cache.stats()["by_namespace"][NS_HTTP]["hits"] == 1


def test_url_with_and_without_default_port_share(mock_http):
    mock_http.get(f"{BASE}/x.htm", text="x")
    HTTP(IP).get("x.htm")
    HTTP(IP).get(url=f"http://{IP}/x.htm")
    HTTP(IP).get(url=f"HTTP://{IP}:80/x.htm#fragment")
    assert mock_http.call_count == 1


def test_params_auth_headers_cookies_isolate(mock_http):
    mock_http.get(f"{BASE}/index.sel", text="page")
    http = HTTP(IP)
    http.get("index.sel")
    http.get("index.sel", params={"sid": "1"})
    http.get("index.sel", auth=("acc", "otter"))
    http.get("index.sel", auth=("acc", "wrong"))
    http.get("index.sel", auth=HTTPDigestAuth("acc", "otter"))
    http.get("index.sel", headers={"X-Requested-With": "XMLHttpRequest"})
    http.get("index.sel", cookies={"SID": "abc"})
    http.get("index.sel", allow_redirects=False)
    other = HTTP(IP)
    other.session.cookies.set("SID", "def")
    other.get("index.sel")
    assert mock_http.call_count == 9

    # Repeats are served from the cache
    http.get("index.sel", auth=("acc", "otter"))
    http.get("index.sel", params={"sid": "1"})
    HTTP(IP).get("index.sel")
    assert mock_http.call_count == 9


def test_subclass_default_headers_isolate(mock_http):
    class TotusLikeHTTP(HTTP):
        DEFAULT_HEADERS = {"X-Requested-With": "XMLHttpRequest"}

    mock_http.get(f"{BASE}/", text="x")
    HTTP(IP).get()
    TotusLikeHTTP(IP).get()
    TotusLikeHTTP(IP).get()
    assert mock_http.call_count == 2


def test_subclass_use_cache_false(mock_http):
    class DynamicHTTP(HTTP):
        USE_CACHE = False

    mock_http.get(f"{BASE}/", text="x")
    DynamicHTTP(IP).get()
    DynamicHTTP(IP).get()
    DynamicHTTP(IP).get(use_cache=True)
    DynamicHTTP(IP).get(use_cache=True)
    assert mock_http.call_count == 3


@pytest.mark.parametrize("status", [301, 401, 403, 404, 407, 500])
def test_error_status_not_stored(mock_http, status):
    mock_http.get(f"{BASE}/p", status_code=status, text="no")
    assert HTTP(IP).get("p") is None
    response = HTTP(IP).get("p", allow_errors=True)
    assert response.status_code == status
    assert HTTP(IP).get("p", allow_errors=True).status_code == status
    assert mock_http.call_count == 3
    assert len(data_cache) == 0


def test_set_cookie_response_not_stored(mock_http):
    mock_http.get(f"{BASE}/login", text="login", headers={"Set-Cookie": "SID=1; Path=/"})
    HTTP(IP).get("login")
    HTTP(IP).get("login")
    assert mock_http.call_count == 2


def test_set_cookie_in_redirect_history_not_stored(mock_http):
    mock_http.get(
        f"{BASE}/start",
        status_code=302,
        headers={"Location": f"{BASE}/home", "Set-Cookie": "SID=1; Path=/"},
    )
    mock_http.get(f"{BASE}/home", text="home")
    first = HTTP(IP).get("start")
    assert first.text == "home"
    assert first.history
    HTTP(IP).get("start")
    assert mock_http.call_count == 4
    assert len(data_cache) == 0


def test_use_cache_false_neither_reads_nor_writes(mock_http):
    mock_http.get(f"{BASE}/uptime", text="1")
    HTTP(IP).get("uptime", use_cache=False)
    HTTP(IP).get("uptime")  # not written by the previous call
    HTTP(IP).get("uptime", use_cache=False)  # doesn't read the cached copy
    assert mock_http.call_count == 3
    HTTP(IP).get("uptime")
    assert mock_http.call_count == 3


def test_cache_ttl_argument(mock_http, mocker):
    clock = mocker.patch.object(data_cache, "_clock", return_value=100.0)
    mock_http.get(f"{BASE}/brief", text="x")
    HTTP(IP).get("brief", cache_ttl=5)
    clock.return_value = 104.0
    HTTP(IP).get("brief")
    assert mock_http.call_count == 1
    clock.return_value = 105.0
    HTTP(IP).get("brief")
    assert mock_http.call_count == 2
    mock_http.get(f"{BASE}/never", text="x")
    HTTP(IP).get("never", cache_ttl=0)
    HTTP(IP).get("never", cache_ttl=0)
    assert mock_http.call_count == 4


def test_ttl_expiry_refetch(mock_http, mocker):
    clock = mocker.patch.object(data_cache, "_clock", return_value=100.0)
    mocker.patch.dict(config["CONFIG"], {"CACHE_TTL": 60.0})
    mock_http.get(f"{BASE}/", text="x")
    HTTP(IP).get()
    clock.return_value = 159.9
    assert HTTP(IP).get().from_cache is True
    clock.return_value = 160.0
    assert HTTP(IP).get().from_cache is False
    assert mock_http.call_count == 2


def test_post_never_answers_get_and_invalidates_target_uri(mock_http):
    url = f"{BASE}/X509.sel"
    mock_http.get(url, text="get-version")
    mock_http.post(url, text="post-version")
    http = HTTP(IP)
    assert http.get("X509.sel").text == "get-version"
    assert http.post(url, data="rando").text == "post-version"
    assert mock_http.call_count == 2
    # The POST removed the cached GET for the same URL
    assert http.get("X509.sel").text == "get-version"
    assert mock_http.call_count == 3
    assert http.get("X509.sel").text == "get-version"
    assert mock_http.call_count == 3

    # POST responses are only cached when requested, keyed by the body
    http.post(url, data="rando")
    http.post(url, data="rando")
    assert mock_http.call_count == 5
    assert http.post(url, data="rando", use_cache=True).from_cache is False
    assert http.post(url, data="rando", use_cache=True).from_cache is True
    http.post(url, data="other", use_cache=True)
    assert mock_http.call_count == 7
    # A cached POST doesn't answer a GET
    assert http.get("X509.sel").text == "get-version"


def test_post_error_status(mock_http):
    mock_http.post(f"{BASE}/fail", status_code=500, text="error")
    assert HTTP(IP).post(f"{BASE}/fail", use_cache=True) is None
    assert HTTP(IP).post(f"{BASE}/fail", use_cache=True) is None
    assert mock_http.call_count == 2


def test_hit_isolated_from_caller_mutation(mock_http):
    mock_http.get(f"{BASE}/", text="x", headers={"Server": "GoAhead"})
    first = HTTP(IP).get()
    second = HTTP(IP).get()
    second.headers["Server"] = "mutated"
    second.encoding = "latin-1"
    second.cookies.set("injected", "1")
    third = HTTP(IP).get()
    assert third.headers["Server"] == "GoAhead"
    assert third.encoding != "latin-1"
    assert "injected" not in third.cookies
    second.request.headers["X-Injected"] = "1"
    third = HTTP(IP).get()
    assert "X-Injected" not in third.request.headers
    # Cached copies don't keep network connection objects in memory
    assert getattr(third, "connection", None) is None
    assert third.raw is None
    assert first.connection is not None


def test_cached_redirect_history_has_no_connections(mock_http):
    mock_http.get(f"{BASE}/", status_code=302, headers={"Location": f"{BASE}/index.htm"})
    mock_http.get(f"{BASE}/index.htm", text="home")
    first = HTTP(IP).get()
    assert first.history[0].connection is not None
    second = HTTP(IP).get()
    assert mock_http.call_count == 2
    assert second.text == "home"
    assert [h.status_code for h in second.history] == [302]
    assert second.history[0].headers["Location"] == f"{BASE}/index.htm"
    # Redirect responses in the cached copy don't hold connections either
    for resp in (second, *second.history):
        assert getattr(resp, "connection", None) is None
        assert resp.raw is None
    # Mutating the history of a hit doesn't change the cached entry
    second.history[0].headers["Location"] = "mutated"
    second.history.append(second)
    third = HTTP(IP).get()
    assert len(third.history) == 1
    assert third.history[0].headers["Location"] == f"{BASE}/index.htm"


def test_stream_and_unknown_kwargs_bypass(mock_http):
    mock_http.get(f"{BASE}/f", text="x")
    HTTP(IP).get("f", stream=True)
    HTTP(IP).get("f", stream=True)
    HTTP(IP).get("f", hooks={})
    HTTP(IP).get("f", hooks={})
    assert mock_http.call_count == 4
    assert len(data_cache) == 0


def test_unknown_auth_object_bypass(mock_http):
    class CustomAuth(AuthBase):
        def __call__(self, r):
            r.headers["X-Token"] = "secret"
            return r

    mock_http.get(f"{BASE}/a", text="x")
    HTTP(IP).get("a", auth=CustomAuth())
    HTTP(IP).get("a", auth=CustomAuth())
    assert mock_http.call_count == 2
    assert len(data_cache) == 0


def test_cache_disabled_equals_no_cache(mock_http, mocker):
    mocker.patch.dict(config["CONFIG"], {"CACHE_ENABLED": False})
    mock_http.get(f"{BASE}/", text="x")
    assert HTTP(IP).get().from_cache is False
    assert HTTP(IP).get().from_cache is False
    assert mock_http.call_count == 2
    assert len(data_cache) == 0


def test_request_exception_not_stored(mock_http):
    mock_http.get(f"{BASE}/", exc=ConnectionError("refused"))
    assert HTTP(IP).get() is None
    assert HTTP(IP).get() is None
    assert mock_http.call_count == 2


def test_regression_params_not_ignored(mock_http):
    mock_http.get(f"{BASE}/index.sel", text="pre-login page")
    mock_http.get(f"{BASE}/index.sel?sid=1", text="logged in page")
    assert HTTP(IP).get("index.sel").text == "pre-login page"
    assert HTTP(IP).get("index.sel", params={"sid": "1"}).text == "logged in page"


def test_regression_auth_not_ignored(mock_http):
    def _callback(request, context):
        if "Authorization" in request.headers:
            return "authenticated log"
        context.status_code = 401
        return "denied"

    mock_http.get(f"{BASE}/log", text=_callback)
    assert HTTP(IP).get("log", auth=("user", "pass")).text == "authenticated log"
    assert HTTP(IP).get("log") is None


def test_regression_post_not_returned_for_get(mock_http):
    mock_http.post(f"{BASE}/page", text="POST body")
    mock_http.get(f"{BASE}/page", text="GET body")
    assert HTTP(IP).post(f"{BASE}/page", data="x").text == "POST body"
    assert HTTP(IP).get("page").text == "GET body"


def test_identify_methods_share_index_page(mock_http):
    mock_http.get(f"{BASE}/", text="<html><title>Telvent Config@WEB</title></html>")
    dev = DeviceData(ip=IP)
    assert GERelay._verify_http(dev) is False
    assert Sage._verify_http(dev, "http") is True
    assert mock_http.call_count == 1


@pytest.fixture
def sage_cert(datapath, tmp_path, mocker):
    mocker.patch.dict(config["CONFIG"], {"TEMP_DIR": tmp_path})
    http = HTTP(IP, 443)
    decoded, raw = http.decode_ssl_certificate(datapath("sage_certificate.cert"))
    return http.parse_decoded_ssl_certificate(decoded, raw)


def test_tls_certificate_shared_across_modules(mocker, sage_cert):
    fetch = mocker.patch.object(HTTP, "_fetch_ssl_certificate", return_value=sage_cert)
    dev = DeviceData(ip=IP)

    assert SELRTAC._verify_https_ssl_certificate(dev) is False
    assert Sage._verify_https_ssl_certificate(dev) is True
    assert Idirect._verify_https_ssl_certificate(dev) is False
    assert fetch.call_count == 1
    assert data_cache.stats()["by_namespace"][NS_TLS_CERT]["hits"] == 2

    # Each call returns an equal, separate copy
    first = HTTP(IP, 443).get_ssl_certificate()
    second = HTTP(IP, 443).get_ssl_certificate()
    assert first == second == sage_cert
    assert first is not second
    assert first is not sage_cert
    first.subject.organization = "mutated"
    assert HTTP(IP, 443).get_ssl_certificate().subject.organization == "Telvent"
    assert fetch.call_count == 1

    # Different port, or not using the cache, fetches again
    HTTP(IP, 8443).get_ssl_certificate()
    assert fetch.call_count == 2
    HTTP(IP, 443).get_ssl_certificate(use_cache=False)
    assert fetch.call_count == 3


def test_tls_certificate_failure_not_stored(mocker):
    fetch = mocker.patch.object(HTTP, "_fetch_ssl_certificate", return_value=None)
    assert HTTP(IP, 443).get_ssl_certificate() is None
    assert HTTP(IP, 443).get_ssl_certificate() is None
    assert fetch.call_count == 2


def test_credentials_in_url_isolate():
    http = HTTP(IP)

    def _key(url):
        return http._cache_key("GET", url, None, None, {})

    assert _key(f"http://user:pass@{IP}/") == _key(f"http://user:pass@{IP}:80/")
    assert _key(f"http://user:pass@{IP}/") != _key(f"http://user:other@{IP}/")
    assert _key(f"http://user:pass@{IP}/") != _key(f"http://{IP}/")
    # Credentials are not logged as part of the cache key
    assert "pass" not in _key(f"http://user:pass@{IP}/").label


def test_tuple_timeout(mock_http):
    mock_http.get(f"{BASE}/", text="x")
    HTTP(IP).get(timeout=(1.0, 2.0))
    assert HTTP(IP).get(timeout=(1.0, 2.0)).from_cache is True
