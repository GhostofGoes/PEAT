"""
Tests for PEAT's HTTP sessions against local servers that mimic the
old TLS stacks and quirky web servers found on ICS/OT devices.

These guard against regressions from the urllib3 2.x defaults (TLS 1.2
minimum, system cipher list, strict Content-Length enforcement).
"""

import datetime
import pickle
import socket
import ssl
import threading
import warnings
from collections.abc import Callable
from pathlib import Path

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from peat import config
from peat.modules.schneider.sage.sage_http import SAGE_TLS_CIPHERS, SageHTTP
from peat.protocols.http import HTTP, LegacyHTTPAdapter, create_legacy_ssl_context

OK_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/html\r\n"
    b"Content-Length: 5\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    b"hello"
)

_CERT_CACHE: dict[tuple, Path] = {}


def _make_cert(tmp_dir: Path, bits: int = 2048, sha1: bool = False) -> Path:
    """
    Self-signed certificate with only a commonName (no subjectAltName),
    like most device certificates.
    """
    cache_key = (bits, sha1)
    if cache_key in _CERT_CACHE and _CERT_CACHE[cache_key].exists():
        return _CERT_CACHE[cache_key]

    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "legacy-device")])
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(0x1234ABCD)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
    )
    with warnings.catch_warnings():  # "SHA1 signatures are deprecated"
        warnings.simplefilter("ignore")
        cert = builder.sign(key, hashes.SHA1() if sha1 else hashes.SHA256())

    path = tmp_dir / f"cert_{bits}_{'sha1' if sha1 else 'sha256'}.pem"
    path.write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
        + key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    _CERT_CACHE[cache_key] = path
    return path


def _server_context(
    cert: Path,
    version: ssl.TLSVersion | None = None,
    ciphers: str | None = None,
) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if ciphers:
        ctx.set_ciphers(ciphers)
    ctx.load_cert_chain(cert)
    if version:
        with warnings.catch_warnings():  # "ssl.TLSVersion.TLSv1 is deprecated"
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = version
            ctx.maximum_version = version
    return ctx


@pytest.fixture(scope="module")
def cert_dir(tmp_path_factory) -> Path:
    return tmp_path_factory.mktemp("certs")


@pytest.fixture
def raw_server() -> Callable[[bytes, ssl.SSLContext | None], int]:
    """
    Start a minimal threaded server on localhost that reads a request and
    replies with a fixed raw HTTP response. Returns the port it's listening on.
    """
    servers = []

    def _start(response: bytes, ctx: ssl.SSLContext | None = None) -> int:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)
        servers.append(srv)

        def _serve() -> None:
            while True:
                try:
                    conn, _ = srv.accept()
                except OSError:
                    return  # server socket closed
                try:
                    conn.settimeout(5)
                    if ctx:
                        conn = ctx.wrap_socket(conn, server_side=True)
                    data = b""
                    while b"\r\n\r\n" not in data:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                    conn.sendall(response)
                except (OSError, ssl.SSLError):
                    pass
                finally:
                    conn.close()

        threading.Thread(target=_serve, daemon=True).start()
        return srv.getsockname()[1]

    yield _start

    for srv in servers:
        srv.close()


@pytest.fixture(autouse=True)
def _clear_page_cache():
    HTTP.page_cache.clear()
    yield
    HTTP.page_cache.clear()


@pytest.fixture(autouse=True)
def device_dirs(mocker, tmp_path):
    mocker.patch.dict(
        config["CONFIG"],
        {"DEVICE_DIR": tmp_path / "devices", "TEMP_DIR": tmp_path / "temp"},
    )


# (name, TLS version, server cipher string, RSA key bits, SHA-1 signed certificate)
LEGACY_TLS_SERVERS = [
    ("tls1_0_rsa_kx_sha1_mac", ssl.TLSVersion.TLSv1, "AES128-SHA:@SECLEVEL=0", 2048, False),
    ("tls1_1_rsa_kx_sha1_mac", ssl.TLSVersion.TLSv1_1, "AES256-SHA:@SECLEVEL=0", 2048, False),
    ("tls1_2_rsa_kx_gcm", ssl.TLSVersion.TLSv1_2, "AES256-GCM-SHA384", 2048, False),
    (
        "tls1_2_ecdhe_sha1_mac",
        ssl.TLSVersion.TLSv1_2,
        "ECDHE-RSA-AES128-SHA:@SECLEVEL=0",
        2048,
        False,
    ),
    ("tls1_2_1024_bit_key", ssl.TLSVersion.TLSv1_2, "DEFAULT:@SECLEVEL=0", 1024, False),
    ("tls1_2_sha1_signed_cert", ssl.TLSVersion.TLSv1_2, "DEFAULT:@SECLEVEL=0", 2048, True),
    ("modern_default", None, None, 2048, False),
]


def _legacy_server_context(cert_dir: Path, version, ciphers, bits, sha1) -> ssl.SSLContext:
    try:
        return _server_context(_make_cert(cert_dir, bits, sha1), version, ciphers)
    except (ssl.SSLError, ValueError) as ex:
        pytest.skip(f"Local OpenSSL can't run this server configuration: {ex}")


@pytest.mark.parametrize(
    ("version", "ciphers", "bits", "sha1"),
    [pytest.param(*s[1:], id=s[0]) for s in LEGACY_TLS_SERVERS],
)
def test_http_get_legacy_tls(raw_server, cert_dir, version, ciphers, bits, sha1):
    port = raw_server(OK_RESPONSE, _legacy_server_context(cert_dir, version, ciphers, bits, sha1))

    with HTTP("127.0.0.1", port, timeout=5.0, protocol="https") as http:
        response = http.get("index.html", use_cache=False)

    assert response is not None
    assert response.status_code == 200
    assert response.text == "hello"


@pytest.mark.parametrize(
    ("version", "ciphers", "bits", "sha1"),
    [pytest.param(*s[1:], id=s[0]) for s in LEGACY_TLS_SERVERS],
)
def test_http_get_ssl_certificate_legacy_tls(raw_server, cert_dir, version, ciphers, bits, sha1):
    port = raw_server(OK_RESPONSE, _legacy_server_context(cert_dir, version, ciphers, bits, sha1))

    cert = HTTP("127.0.0.1", port, timeout=5.0, protocol="https").get_ssl_certificate()

    assert cert is not None
    assert cert.serial_number == "1234ABCD"
    assert cert.subject.common_name == "legacy-device"


def test_http_get_short_content_length(raw_server, caplog):
    """
    Device web servers sometimes send a Content-Length that's longer than
    the body. urllib3 1.x silently accepted this, urllib3 2.x raises an
    error by default. PEAT should keep the partial body and warn.
    """
    port = raw_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nhello",
    )

    with HTTP("127.0.0.1", port, timeout=5.0, protocol="http") as http:
        response = http.get("short", use_cache=False)

    assert response is not None
    assert response.text == "hello"
    assert "may be truncated: received 5 bytes" in caplog.text


@pytest.mark.parametrize(
    "raw_response",
    [
        pytest.param(
            b"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\nhello", id="http1_0_no_length"
        ),
        pytest.param(
            b"HTTP/1.1 200 OK\r\nServer: Ger\xe4t\r\n"
            b"Content-Length: 5\r\nConnection: close\r\n\r\nhello",
            id="latin1_header",
        ),
        pytest.param(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
            b"3\r\nhel\r\n2\r\nlo\r\n0\r\n\r\n",
            id="chunked",
        ),
    ],
)
def test_http_get_quirky_responses(raw_server, raw_response):
    port = raw_server(raw_response)

    with HTTP("127.0.0.1", port, timeout=5.0, protocol="http") as http:
        response = http.get(use_cache=False)

    assert response is not None
    assert response.text == "hello"


def test_sage_http_session_restricted_cipher(raw_server, cert_dir):
    """The Sage session should negotiate the single cipher the device expects."""
    ctx = _server_context(_make_cert(cert_dir), ssl.TLSVersion.TLSv1_2, "AES256-GCM-SHA384")
    port = raw_server(OK_RESPONSE, ctx)

    sage = SageHTTP("127.0.0.1", port, timeout=5.0, protocol="https")
    adapter = sage.session.get_adapter(f"https://127.0.0.1:{port}")
    assert isinstance(adapter, LegacyHTTPAdapter)
    assert {
        c["name"] for c in adapter.ssl_context.get_ciphers() if c["protocol"] == "TLSv1.2"
    } == {"AES256-GCM-SHA384"}

    response = sage.get("index.html", use_cache=False)
    assert response is not None
    assert response.text == "hello"
    assert SAGE_TLS_CIPHERS.startswith("AES256-GCM-SHA384")


def test_create_legacy_ssl_context():
    ctx = create_legacy_ssl_context()
    assert ctx.verify_mode == ssl.CERT_NONE
    assert not ctx.check_hostname
    assert ctx.minimum_version == ssl.TLSVersion.MINIMUM_SUPPORTED
    assert ctx.options & getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)

    # RSA key exchange and SHA-1 MAC ciphers are offered
    names = {c["name"] for c in ctx.get_ciphers()}
    assert "AES256-GCM-SHA384" in names
    assert "AES128-SHA" in names

    custom = create_legacy_ssl_context("AES256-GCM-SHA384")
    assert "AES128-SHA" not in {c["name"] for c in custom.get_ciphers()}


def test_gen_session_mounts_legacy_adapter():
    session = HTTP.gen_session()
    assert session.verify is False
    assert session.trust_env is False
    assert isinstance(session.get_adapter("http://127.0.0.1"), LegacyHTTPAdapter)
    assert isinstance(session.get_adapter("https://127.0.0.1"), LegacyHTTPAdapter)


def test_legacy_adapter_only_used_without_verification():
    """Requests made with certificate verification should use the default (secure) context."""
    adapter = LegacyHTTPAdapter()
    request = requests.Request("GET", "https://127.0.0.1:8443/").prepare()

    _, unverified = adapter.build_connection_pool_key_attributes(request, verify=False)
    assert unverified["ssl_context"] is adapter.ssl_context

    _, verified = adapter.build_connection_pool_key_attributes(request, verify=True)
    assert "ssl_context" not in verified or verified["ssl_context"] is not adapter.ssl_context


def test_legacy_adapter_pickle():
    adapter = pickle.loads(pickle.dumps(LegacyHTTPAdapter()))
    request = requests.Request("GET", "https://127.0.0.1:8443/").prepare()
    _, pool_kwargs = adapter.build_connection_pool_key_attributes(request, verify=False)
    assert isinstance(pool_kwargs["ssl_context"], ssl.SSLContext)
