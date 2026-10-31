import hashlib
import ipaddress
import socket
import ssl
import threading
import warnings
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from peat import consts
from peat.data.models import X509
from peat.protocols import tls

# Expected values for tests/protocols/data_files/sel_3530_certificate.cert (the
# factory-default certificate of a SEL-3530-4 RTAC), checked with "openssl x509".
SEL_3530_FINGERPRINTS = {
    "md5": "E289C2E307B5BDDBDD992FC685FE9C0D",
    "sha1": "8A00FF94DF652F7A8E402D50A31CA305D6F54BB2",
    "sha256": "075EAE062895601C16BDB2478BB019A25ED83F4F74E94A0E537D9157FC4A0D84",
    "spki_sha256": "3A2C29FC6979B57155B0BA1FF2E5FF570FA8E8E0F3884D4AAE9608C794F2CB16",
}


def _name(common_name: str, **attrs) -> x509.Name:
    oids = {
        "organization": NameOID.ORGANIZATION_NAME,
        "organizational_unit": NameOID.ORGANIZATIONAL_UNIT_NAME,
        "email": NameOID.EMAIL_ADDRESS,
    }
    rdns = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    rdns.extend(x509.NameAttribute(oids[key], value) for key, value in attrs.items())
    return x509.Name(rdns)


def make_cert(
    subject: x509.Name,
    key=None,
    issuer: x509.Name | None = None,
    issuer_key=None,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    extensions: list | None = None,
    hash_alg=None,
) -> tuple[x509.Certificate, object]:
    """Make a certificate (self-signed by default)."""
    if key is None:
        key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer if issuer is not None else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before if not_before else now - timedelta(days=1))
        .not_valid_after(not_after if not_after else now + timedelta(days=30))
    )
    for ext, critical in extensions or []:
        builder = builder.add_extension(ext, critical=critical)
    signing_key = issuer_key if issuer_key is not None else key
    if isinstance(signing_key, ed25519.Ed25519PrivateKey):
        hash_alg = None
    elif hash_alg is None:
        hash_alg = hashes.SHA256()
    return builder.sign(signing_key, hash_alg), key


def der_of(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


@pytest.fixture
def sel_3530_der(datapath) -> bytes:
    return ssl.PEM_cert_to_DER_cert(datapath("sel_3530_certificate.cert").read_text())


@pytest.fixture
def server_cert(tmp_path):
    """Self-signed certificate and key files for a local TLS server."""
    cert, key = make_cert(_name("SEL-3555 RTAC"))
    cert_path = tmp_path / "server-cert.pem"
    key_path = tmp_path / "server-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert, cert_path, key_path


@pytest.fixture
def local_server():
    """
    Run a local TCP server in a thread. Each accepted connection is passed
    to the handler. Returns the port, and a dict with the number of
    connections and the SNI names the TLS server received.
    """
    servers = []

    def _start(handler):
        lsock = socket.create_server(("127.0.0.1", 0))
        lsock.settimeout(0.1)
        stop = threading.Event()
        stats = {"connections": 0, "sni": []}

        def _run():
            while not stop.is_set():
                try:
                    conn, _ = lsock.accept()
                except TimeoutError:
                    continue
                except OSError:
                    return
                stats["connections"] += 1
                conn.settimeout(5.0)
                try:
                    handler(conn, stop)
                except (OSError, ssl.SSLError):
                    pass  # the client failed or aborted the handshake
                finally:
                    conn.close()

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        servers.append((lsock, stop, thread))
        return lsock.getsockname()[1], stats

    yield _start

    for lsock, stop, thread in servers:
        stop.set()
        thread.join(timeout=5.0)
        lsock.close()


def tls_handler(context: ssl.SSLContext):
    def _handle(conn, _stop):
        with context.wrap_socket(conn, server_side=True):
            pass

    return _handle


def server_context(cert_path, key_path, stats=None) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    if stats is not None:

        def _sni(_sock, server_name, _ctx):
            stats["sni"].append(server_name)

        context.sni_callback = _sni
    return context


# ---------- parse_der_certificate ----------


def test_parse_sel_3530_certificate(sel_3530_der):
    parsed = tls.parse_der_certificate(sel_3530_der)
    cert = parsed.x509

    assert parsed.fingerprints == SEL_3530_FINGERPRINTS
    assert parsed.self_signed is True
    assert parsed.ca is True
    assert parsed.subject_key_identifier == "AE2A25BA035D3518F4F2020D0545B154B8B11C24"
    # The authority key identifier only has the issuer name and serial, no key ID
    assert parsed.authority_key_identifier == ""

    assert cert.subject.common_name == "SEL-3530-4 RTAC"
    assert cert.subject.organization == "Schweitzer Engineering Laboratories, Inc."
    assert cert.subject.organizational_unit == "Automation and Integration Engineering"
    assert cert.subject.locality == "Pullman"
    assert cert.subject.state_or_province == "Washington"
    assert cert.subject.country == "US"
    assert cert.subject.distinguished_name == (
        "CN=SEL-3530-4 RTAC,OU=Automation and Integration Engineering,"
        "O=Schweitzer Engineering Laboratories\\, Inc.,L=Pullman,ST=Washington,C=US"
    )
    assert cert.issuer == cert.subject
    assert cert.serial_number == "A4F7F452597221F4"
    assert cert.version_number == "3"
    assert cert.not_before == datetime(2019, 3, 6, 20, 14, 56, tzinfo=UTC)
    assert cert.not_after == datetime(2038, 1, 19, 3, 14, 7, tzinfo=UTC)
    assert cert.public_key_algorithm == "RSA"
    assert cert.public_key_size == 2048
    assert cert.public_key_exponent == 65537
    assert cert.public_key_curve == ""
    assert cert.signature_algorithm == "SHA256-RSA"
    assert cert.alternative_names == []
    assert cert.original == ssl.DER_cert_to_PEM_cert(sel_3530_der)


@pytest.mark.parametrize("device_name", ["sage", "sel_2730m", "sel_3530"])
def test_parse_der_certificate_matches_http_parser(json_data, datapath, device_name):
    """
    The same values as the existing HTTP parser (decode_ssl_certificate), and
    X509.hash is still the hash of the PEM text (not the DER fingerprint).
    """
    expected = json_data(f"expected_parsed_{device_name}_certificate.json")
    der = ssl.PEM_cert_to_DER_cert(datapath(f"{device_name}_certificate.cert").read_text())

    parsed = tls.parse_der_certificate(der)
    parsed.x509.annotate()
    data = consts.convert(parsed.x509.dict(exclude_defaults=True, exclude_none=True))

    for entity in ["issuer", "subject"]:
        assert data[entity].pop("distinguished_name")
    assert {key: data[key] for key in expected} == expected
    assert parsed.fingerprints["sha256"] != data["hash"]["sha256"]


def test_parse_der_certificate_email_in_distinguished_name(datapath):
    der = ssl.PEM_cert_to_DER_cert(datapath("sel_2730m_certificate.cert").read_text())
    cert = tls.parse_der_certificate(der).x509

    assert cert.subject.distinguished_name.startswith("emailAddress=info@selinc.com,CN=")
    assert cert.alternative_names == ["info@selinc.com"]
    assert cert.signature_algorithm == "SHA1-RSA"
    assert cert.public_key_size == 1024


def test_parse_der_certificate_ec_with_alternative_names():
    key = ec.generate_private_key(ec.SECP384R1())
    san = x509.SubjectAlternativeName(
        [
            x509.DNSName("rtac.example"),
            x509.IPAddress(ipaddress.ip_address("192.0.2.10")),
            x509.RFC822Name("admin@example.com"),
            x509.UniformResourceIdentifier("https://rtac.example/"),
        ]
    )
    cert, _ = make_cert(
        _name("rtac.example", email="pki@example.com"),
        key=key,
        extensions=[(san, False), (x509.BasicConstraints(ca=False, path_length=None), True)],
        hash_alg=hashes.SHA384(),
    )

    parsed = tls.parse_der_certificate(der_of(cert))

    assert parsed.x509.public_key_algorithm == "ECDSA"
    assert parsed.x509.public_key_curve == "nistp384"
    assert parsed.x509.public_key_size == 384
    assert parsed.x509.public_key_exponent is None
    assert parsed.x509.signature_algorithm == "ECDSA-SHA384"
    assert parsed.x509.alternative_names == [
        "pki@example.com",
        "rtac.example",
        "192.0.2.10",
        "admin@example.com",
        "https://rtac.example/",
    ]
    assert parsed.self_signed is True
    assert parsed.ca is False
    assert len(parsed.fingerprints["spki_sha256"]) == 64


def test_parse_der_certificate_ed25519():
    cert, _ = make_cert(_name("ed25519.example"), key=ed25519.Ed25519PrivateKey.generate())
    parsed = tls.parse_der_certificate(der_of(cert))

    assert parsed.x509.public_key_algorithm == "Ed25519"
    assert parsed.x509.public_key_size == 256
    assert parsed.x509.signature_algorithm == "Ed25519"
    assert parsed.self_signed is True


def test_parse_der_certificate_ca_signed():
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = _name("Example Utility CA", organization="Example Utility")
    leaf, _ = make_cert(
        _name("rtac1.substation.example"),
        issuer=ca_name,
        issuer_key=ca_key,
        extensions=[
            (x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
        ],
    )

    parsed = tls.parse_der_certificate(der_of(leaf))

    assert parsed.self_signed is False
    assert parsed.ca is None
    assert parsed.x509.issuer.common_name == "Example Utility CA"
    assert parsed.x509.issuer.organization == "Example Utility"
    assert parsed.x509.signature_algorithm == "SHA256-RSA"
    assert len(parsed.authority_key_identifier) == 40


def test_parse_der_certificate_same_name_different_key():
    # Issuer and subject are the same, but it's not signed by its own key
    name = _name("SEL-3530 RTAC")
    cert, _ = make_cert(name, issuer=name, issuer_key=ec.generate_private_key(ec.SECP256R1()))
    assert tls.parse_der_certificate(der_of(cert)).self_signed is False


def test_parse_der_certificate_invalid():
    with pytest.raises(ValueError):
        tls.parse_der_certificate(b"not a certificate")


def with_bad_not_after(der: bytes) -> bytes:
    """
    The SEL-3530 certificate with the month 13 in notAfter (same length).
    ``cryptography`` rejects it, but OpenSSL decodes it.
    """
    assert der.count(b"380119031407Z") == 1
    return der.replace(b"380119031407Z", b"381319031407Z")


def with_bad_name_string_type(der: bytes) -> bytes:
    """
    The SEL-3530 certificate with the Common Name of the issuer encoded as an
    ASN.1 VideotexString, which ``cryptography`` 38 rejects with a KeyError.
    """
    offset = der.index(b"SEL-3530-4 RTAC")
    assert der[offset - 2] == 0x0C  # UTF8String
    return der[: offset - 2] + b"\x15" + der[offset - 1 :]


def test_parse_der_certificate_only_raises_value_error(mocker, sel_3530_der):
    # cryptography raises KeyError, TypeError, etc. for some malformed certificates
    mocker.patch.object(tls, "_parse_with_cryptography", side_effect=KeyError(21))
    mocker.patch.object(tls, "_parse_with_openssl", side_effect=ssl.SSLError("bad"))

    with pytest.raises(ValueError, match=r"Invalid certificate \(KeyError: 21\)") as exc_info:
        tls.parse_der_certificate(sel_3530_der)
    assert isinstance(exc_info.value.__cause__, KeyError)


def test_parse_der_certificate_malformed_name(sel_3530_der):
    der = with_bad_name_string_type(sel_3530_der)

    try:
        parsed = tls.parse_der_certificate(der)
    except ValueError:
        pass  # Neither parser accepts it (with the OpenSSL versions PEAT was tested with)
    else:
        assert parsed.parser == "openssl"


def test_parse_der_certificate_openssl_fallback(sel_3530_der):
    der = with_bad_not_after(sel_3530_der)
    try:
        tls._decode_with_openssl(der)
    except ssl.SSLError:
        pytest.skip("The local OpenSSL doesn't decode certificates with invalid dates")
    valid = tls.parse_der_certificate(sel_3530_der)

    parsed = tls.parse_der_certificate(der)

    assert parsed.parser == "openssl"
    assert parsed.x509.original == ssl.DER_cert_to_PEM_cert(der)
    # Same names (including the distinguished names), serial number and version
    assert parsed.x509.subject == valid.x509.subject
    assert parsed.x509.issuer == valid.x509.issuer
    assert parsed.x509.subject.distinguished_name.startswith("CN=SEL-3530-4 RTAC,OU=")
    assert parsed.x509.serial_number == valid.x509.serial_number == "A4F7F452597221F4"
    assert parsed.x509.version_number == "3"
    assert parsed.x509.not_before == valid.x509.not_before
    assert parsed.x509.not_after is None  # the invalid date
    # No key, signature or extensions
    assert parsed.x509.public_key_algorithm == ""
    assert parsed.x509.signature_algorithm == ""
    assert parsed.ca is None
    # The fingerprints of the DER are still available, except for the key
    assert parsed.fingerprints == {
        "md5": hashlib.md5(der).hexdigest().upper(),
        "sha1": hashlib.sha1(der).hexdigest().upper(),
        "sha256": hashlib.sha256(der).hexdigest().upper(),
    }
    # Only based on the names
    assert parsed.self_signed is True
    assert not parsed.x509.hash.sha256  # set by X509.annotate()


def test_parse_with_openssl_matches_cryptography():
    # Characters that must be escaped in distinguished names,
    # and alternative names, parsed by both parsers
    subject = _name(
        'rtac "main";<1>\\',
        organization="Example, Utility",
        organizational_unit="#OT+Substations",
        email="ot@utility.example",
    )
    alt_names = x509.SubjectAlternativeName(
        [
            x509.DNSName("rtac1.substation.example"),
            x509.IPAddress(ipaddress.ip_address("192.0.2.20")),
            x509.RFC822Name("admin@utility.example"),
            x509.UniformResourceIdentifier("https://rtac1.substation.example/"),
        ]
    )
    cert, _ = make_cert(subject, extensions=[(alt_names, False)])
    der = der_of(cert)

    expected = tls._parse_with_cryptography(der).x509
    parsed = tls._parse_with_openssl(der)

    assert parsed.x509.subject == expected.subject
    assert parsed.x509.subject.distinguished_name == (
        "emailAddress=ot@utility.example,"
        "OU=\\#OT\\+Substations,"
        "O=Example\\, Utility,"
        'CN=rtac \\"main\\"\;\\<1\\>\\\\'
    )
    assert parsed.x509.issuer == expected.issuer
    assert parsed.x509.alternative_names == expected.alternative_names
    assert parsed.x509.serial_number == expected.serial_number
    assert parsed.x509.not_before == expected.not_before
    assert parsed.x509.not_after == expected.not_after


def test_parse_with_openssl_multi_valued_rdn():
    # NOTE: cryptography 38 keeps the attributes of a parsed multi-valued RDN in a
    # set (the order of its distinguished name varies), OpenSSL uses the DER order.
    subject = x509.Name(
        [
            x509.RelativeDistinguishedName(
                [
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Utility"),
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Substations"),
                ]
            ),
            x509.RelativeDistinguishedName([x509.NameAttribute(NameOID.COMMON_NAME, "rtac1")]),
        ]
    )
    cert, _ = make_cert(subject)

    entity = tls._parse_with_openssl(der_of(cert)).x509.subject

    # DER sorts the attributes of the RDN by their encoding (the shorter one first)
    assert entity.distinguished_name == "CN=rtac1,OU=Substations+O=Example Utility"
    assert entity.organization == "Example Utility"
    assert entity.organizational_unit == "Substations"
    assert entity.common_name == "rtac1"


def test_validity_status():
    cert = X509(
        not_before=datetime(2020, 1, 1, tzinfo=UTC),
        not_after=datetime(2030, 1, 1, tzinfo=UTC),
    )

    assert tls.validity_status(cert, now=datetime(2029, 12, 1, 12, tzinfo=UTC)) == {
        "expired": False,
        "not_yet_valid": False,
        "days_remaining": 30,
    }
    assert tls.validity_status(cert, now=datetime(2030, 1, 3, tzinfo=UTC)) == {
        "expired": True,
        "not_yet_valid": False,
        "days_remaining": -2,
    }
    assert tls.validity_status(cert, now=datetime(2019, 1, 1, tzinfo=UTC))["not_yet_valid"]
    assert tls.validity_status(X509()) == {
        "expired": None,
        "not_yet_valid": None,
        "days_remaining": None,
    }
    # Defaults to the current time
    assert tls.validity_status(cert)["expired"] is (datetime.now(UTC) > cert.not_after)


# ---------- create_client_context ----------


def test_create_client_context():
    context = tls.create_client_context()
    assert context.verify_mode == ssl.CERT_NONE
    assert context.check_hostname is False
    assert context.minimum_version != ssl.TLSVersion.MINIMUM_SUPPORTED

    legacy = tls.create_client_context(legacy=True)
    assert legacy.verify_mode == ssl.CERT_NONE
    assert legacy.check_hostname is False
    assert legacy.minimum_version == ssl.TLSVersion.MINIMUM_SUPPORTED
    assert legacy.options & getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)


# ---------- fetch_peer_certificate ----------


def test_fetch_peer_certificate(local_server, server_cert):
    cert, cert_path, key_path = server_cert
    port, stats = local_server(tls_handler(server_context(cert_path, key_path)))

    peer = tls.fetch_peer_certificate("127.0.0.1", port, timeout=5.0)

    assert peer is not None
    assert peer.der == der_of(cert)
    assert peer.pem == cert.public_bytes(serialization.Encoding.PEM).decode()
    assert peer.tls_version.startswith("TLSv1.")
    assert peer.cipher
    assert peer.legacy is False
    if hasattr(ssl.SSLSocket, "get_unverified_chain"):  # Python 3.13+
        assert peer.chain == [peer.der]
    assert stats["connections"] == 1
    # The DER bytes aren't in the repr (it's logged)
    assert "der=" not in repr(peer)

    parsed = tls.parse_der_certificate(peer.der)
    assert parsed.x509.subject.common_name == "SEL-3555 RTAC"


def test_fetch_peer_certificate_sni(local_server, server_cert):
    _, cert_path, key_path = server_cert
    stats_holder = {"sni": []}
    port, stats = local_server(tls_handler(server_context(cert_path, key_path, stats_holder)))

    assert tls.fetch_peer_certificate("127.0.0.1", port, timeout=5.0)
    assert tls.fetch_peer_certificate("localhost", port, timeout=5.0)
    # No Server Name Indication for IP addresses
    assert stats_holder["sni"][-1] == "localhost"
    assert "127.0.0.1" not in stats_holder["sni"]
    assert stats["connections"] == 2


def _legacy_server_context(cert_path, key_path) -> ssl.SSLContext:
    """TLS 1.0 only server, or skip the test if the local OpenSSL can't do it."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)  # ssl.TLSVersion.TLSv1
        try:
            context = server_context(cert_path, key_path)
            context.set_ciphers("DEFAULT:@SECLEVEL=0")
            context.minimum_version = ssl.TLSVersion.TLSv1
            context.maximum_version = ssl.TLSVersion.TLSv1
        except (ssl.SSLError, ValueError) as ex:
            pytest.skip(f"Local OpenSSL can't run a TLS 1.0 server: {ex}")
    return context


def _can_negotiate_tls1(port: int) -> bool:
    """If the local OpenSSL client can connect to the TLS 1.0 server."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        context = tls.create_client_context(legacy=True)
        context.maximum_version = ssl.TLSVersion.TLSv1
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5.0) as sock:
            with context.wrap_socket(sock) as tls_sock:
                return tls_sock.version() == "TLSv1"
    except (OSError, ssl.SSLError):
        return False


def test_fetch_peer_certificate_legacy_fallback(local_server, server_cert):
    cert, cert_path, key_path = server_cert
    port, stats = local_server(tls_handler(_legacy_server_context(cert_path, key_path)))
    if not _can_negotiate_tls1(port):
        pytest.skip("Local OpenSSL can't negotiate TLS 1.0")
    stats["connections"] = 0

    # The default context requires TLS 1.2+, so the handshake is retried
    peer = tls.fetch_peer_certificate("127.0.0.1", port, timeout=5.0)
    assert peer is not None
    assert peer.der == der_of(cert)
    assert peer.legacy is True
    assert peer.tls_version == "TLSv1"
    assert stats["connections"] == 2

    # Without the fallback, the certificate can't be retrieved
    assert tls.fetch_peer_certificate("127.0.0.1", port, 5.0, legacy_fallback=False) is None
    assert stats["connections"] == 3


def test_fetch_peer_certificate_not_tls(local_server):
    def _http_handler(conn, _stop):
        conn.recv(4096)
        conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")

    port, stats = local_server(_http_handler)

    assert tls.fetch_peer_certificate("127.0.0.1", port, timeout=5.0) is None
    # Retried once with the legacy context
    assert stats["connections"] == 2


def test_fetch_peer_certificate_timeout_not_retried(local_server):
    def _silent_handler(_conn, stop):
        stop.wait(5.0)

    port, stats = local_server(_silent_handler)

    assert tls.fetch_peer_certificate("127.0.0.1", port, timeout=0.3) is None
    assert stats["connections"] == 1


def test_fetch_peer_certificate_connection_refused_not_retried(mocker):
    create_connection = mocker.patch.object(
        tls.socket, "create_connection", side_effect=ConnectionRefusedError("refused")
    )

    assert tls.fetch_peer_certificate("192.0.2.20", 443, timeout=1.0) is None
    create_connection.assert_called_once_with(("192.0.2.20", 443), timeout=1.0)


def test_fetch_peer_certificate_no_certificate(mocker):
    mocker.patch.object(tls, "_handshake", return_value=None)
    assert tls.fetch_peer_certificate("192.0.2.20", 443) is None
