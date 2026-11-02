"""
Tests for the collection and analysis of the TLS certificate of the RTAC web
server, and the fixes to the RTAC web pull credentials and returned fields.
"""

import hashlib
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from peat import SELRTAC, DeviceData, config, datastore
from peat.modules.sel import sel_rtac
from peat.protocols import tls
from peat.protocols.tls import PeerCertificate

# The factory-default certificate of a SEL-3530-4 RTAC (also used by the HTTP tests)
SEL_3530_CERT = (
    Path(__file__).resolve().parents[2] / "protocols" / "data_files" / "sel_3530_certificate.cert"
)
SEL_3530_DER_SHA256 = "075EAE062895601C16BDB2478BB019A25ED83F4F74E94A0E537D9157FC4A0D84"
SEL_3530_SPKI_SHA256 = "3A2C29FC6979B57155B0BA1FF2E5FF570FA8E8E0F3884D4AAE9608C794F2CB16"
# X509.hash is the SHA-256 of the PEM text (as in expected_parsed_sel_3530_certificate.json)
SEL_3530_PEM_SHA256 = "338CA18AF89855A3965019114918800D74D59B3393CD3EFBD32B90699740DA85"


@pytest.fixture
def dev(mocker, tmp_path) -> DeviceData:
    mocker.patch.dict(
        config["CONFIG"],
        {"DEVICE_DIR": tmp_path / "devices", "TEMP_DIR": tmp_path / "temp"},
    )
    mocker.patch.object(datastore, "objects", [])
    device = DeviceData(ip="192.0.2.20")
    device._module = SELRTAC
    return device


@pytest.fixture
def sel_3530_peer() -> PeerCertificate:
    der = ssl.PEM_cert_to_DER_cert(SEL_3530_CERT.read_text(encoding="utf-8"))
    return PeerCertificate(der=der, tls_version="TLSv1.2", cipher="ECDHE-RSA-AES256-GCM-SHA384")


@pytest.fixture
def fake_fetch(mocker, sel_3530_peer):
    return mocker.patch.object(sel_rtac, "fetch_peer_certificate", return_value=sel_3530_peer)


def make_peer(
    common_name: str,
    organization: str = "Example Utility",
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    ca_signed: bool = False,
) -> PeerCertificate:
    """A certificate like one a utility installs on its RTAC (not the factory default)."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        ]
    )
    issuer = subject
    signing_key = key
    if ca_signed:
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Example Utility CA")])
        signing_key = ec.generate_private_key(ec.SECP256R1())

    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before if not_before else now - timedelta(days=1))
        .not_valid_after(not_after if not_after else now + timedelta(days=365))
        .sign(signing_key, hashes.SHA256())
    )
    return PeerCertificate(
        der=cert.public_bytes(serialization.Encoding.DER),
        tls_version="TLSv1",
        cipher="ECDHE-ECDSA-AES256-SHA",
        legacy=True,
    )


# ---------- _process_ssl_certificate ----------


def test_process_default_rtac_certificate(dev, sel_3530_peer, mocker):
    mocker.patch.object(tls.utils, "utc_now", return_value=datetime(2026, 1, 1, tzinfo=UTC))

    parsed = SELRTAC._process_ssl_certificate(dev, sel_3530_peer, 443)
    assert parsed is not None

    # The X509 model, with the hash of the PEM text (unchanged semantics)
    assert dev.x509.subject.common_name == "SEL-3530-4 RTAC"
    assert dev.x509.issuer.organization == "Schweitzer Engineering Laboratories, Inc."
    assert dev.x509.hash.sha256 == SEL_3530_PEM_SHA256
    assert dev.x509.public_key_algorithm == "RSA"
    assert dev.x509.public_key_size == 2048
    assert dev.x509.signature_algorithm == "SHA256-RSA"
    assert dev.description.model == "3530-4"

    # The DER fingerprints and the checks
    summary = dev.extra["ssl_certificate"]
    assert summary["fingerprints"]["sha256"] == SEL_3530_DER_SHA256
    assert summary["fingerprints"]["spki_sha256"] == SEL_3530_SPKI_SHA256
    assert summary["default_sel_certificate"] is True
    assert summary["self_signed"] is True
    assert summary["ca"] is True
    assert summary["expired"] is False
    assert summary["not_yet_valid"] is False
    expected_days = datetime(2038, 1, 19, 3, 14, 7, tzinfo=UTC) - datetime(2026, 1, 1, tzinfo=UTC)
    assert summary["days_remaining"] == expected_days.days
    assert summary["port"] == 443
    assert summary["tls_version"] == "TLSv1.2"
    assert summary["cipher"] == "ECDHE-RSA-AES256-GCM-SHA384"
    assert summary["legacy_tls"] is False
    assert summary["parser"] == "cryptography"
    assert "chain" not in summary

    # Both kinds of hashes can be searched for
    assert SEL_3530_DER_SHA256 in dev.related.hash
    assert SEL_3530_SPKI_SHA256 in dev.related.hash
    assert SEL_3530_PEM_SHA256 in dev.related.hash

    # The HTTPS service has the TLS details
    services = [svc for svc in dev.service if svc.port == 443]
    assert len(services) == 1
    assert services[0].protocol == "https"
    assert services[0].status == "verified"
    assert services[0].extra == {
        "tls_version": "TLSv1.2",
        "tls_cipher": "ECDHE-RSA-AES256-GCM-SHA384",
        "tls_legacy": False,
        "certificate_sha256": SEL_3530_DER_SHA256,
        "certificate_spki_sha256": SEL_3530_SPKI_SHA256,
    }

    # The PEM file is the same as the certificate text, and is hashed
    pem_path = dev.get_out_dir() / "ssl-certificate.pem"
    assert pem_path.read_text(encoding="utf-8") == SEL_3530_CERT.read_text(encoding="utf-8")
    pem_files = [f for f in dev.files if f.name == "ssl-certificate.pem"]
    assert len(pem_files) == 1
    assert pem_files[0].local_path == pem_path.resolve()
    assert pem_files[0].hash.sha256 == SEL_3530_PEM_SHA256
    assert pem_files[0].extra == {"source": "tls_certificate", "transport": "tls"}


def test_process_certificate_refines_model(dev, sel_3530_peer):
    dev.description.model = "3530"
    SELRTAC._process_ssl_certificate(dev, sel_3530_peer, 443)
    assert dev.description.model == "3530-4"


def test_process_certificate_keeps_different_model(dev, sel_3530_peer):
    dev.description.model = "3555"
    SELRTAC._process_ssl_certificate(dev, sel_3530_peer, 443)
    assert dev.description.model == "3555"


def test_process_custom_ca_signed_certificate(dev):
    peer = make_peer("rtac1.substation.example", ca_signed=True)

    SELRTAC._process_ssl_certificate(dev, peer, 8443)

    summary = dev.extra["ssl_certificate"]
    assert summary["default_sel_certificate"] is False
    assert summary["self_signed"] is False
    assert summary["legacy_tls"] is True
    assert summary["port"] == 8443
    assert dev.description.model == ""
    assert dev.x509.subject.common_name == "rtac1.substation.example"
    assert dev.service[0].port == 8443
    assert dev.service[0].extra["tls_version"] == "TLSv1"


def test_process_self_signed_certificate_not_from_sel(dev):
    # Self-signed, with the default common name, but not issued to SEL
    peer = make_peer("SEL-3530 RTAC", organization="Example Utility")
    SELRTAC._process_ssl_certificate(dev, peer, 443)

    summary = dev.extra["ssl_certificate"]
    assert summary["self_signed"] is True
    assert summary["default_sel_certificate"] is False
    assert dev.description.model == "3530"


def test_process_expired_certificate(dev, caplog):
    now = datetime.now(UTC)
    peer = make_peer(
        "rtac.example", not_before=now - timedelta(days=400), not_after=now - timedelta(days=10)
    )

    SELRTAC._process_ssl_certificate(dev, peer, 443)

    summary = dev.extra["ssl_certificate"]
    assert summary["expired"] is True
    assert summary["days_remaining"] in (-10, -11)
    assert "expired on" in caplog.text


def test_process_certificate_with_chain(dev, sel_3530_peer):
    leaf = make_peer("rtac1.substation.example", ca_signed=True)
    leaf.chain = [leaf.der, sel_3530_peer.der]

    SELRTAC._process_ssl_certificate(dev, leaf, 443)

    chain = dev.extra["ssl_certificate"]["chain"]
    assert [c["sha256"] for c in chain] == [
        hashlib.sha256(leaf.der).hexdigest().upper(),
        SEL_3530_DER_SHA256,
    ]
    assert chain[1]["subject"].startswith("CN=SEL-3530-4 RTAC,")
    chain_pem = (dev.get_out_dir() / "ssl-certificate-chain.pem").read_text(encoding="utf-8")
    assert chain_pem.count("BEGIN CERTIFICATE") == 2
    assert {f.name for f in dev.files} == {"ssl-certificate.pem", "ssl-certificate-chain.pem"}


def test_process_certificate_with_malformed_chain_member(dev, sel_3530_peer, mocker):
    # A certificate in the chain that makes the parser raise an unexpected
    # exception doesn't leave the device half-processed
    leaf = make_peer("rtac1.substation.example", ca_signed=True)
    bad = b"\x30\x03\x02\x01\x00"
    leaf.chain = [leaf.der, bad, sel_3530_peer.der]
    real_parse = sel_rtac.parse_der_certificate

    def _parse(der):
        if der == bad:
            raise KeyError(21)
        return real_parse(der)

    mocker.patch.object(sel_rtac, "parse_der_certificate", side_effect=_parse)

    assert SELRTAC._process_ssl_certificate(dev, leaf, 443) is not None

    chain = dev.extra["ssl_certificate"]["chain"]
    assert chain[1] == {"sha256": hashlib.sha256(bad).hexdigest().upper()}
    assert chain[2]["sha256"] == SEL_3530_DER_SHA256
    assert dev.x509.subject.common_name == "rtac1.substation.example"
    assert [svc.port for svc in dev.service] == [443]
    assert {f.name for f in dev.files} == {"ssl-certificate.pem", "ssl-certificate-chain.pem"}


def test_process_certificate_parsed_with_openssl(dev, sel_3530_peer, caplog):
    # A notAfter with the month 13: cryptography rejects it, OpenSSL decodes it
    assert sel_3530_peer.der.count(b"380119031407Z") == 1
    der = sel_3530_peer.der.replace(b"380119031407Z", b"381319031407Z")
    try:
        tls._decode_with_openssl(der)
    except ssl.SSLError:
        pytest.skip("The local OpenSSL doesn't decode certificates with invalid dates")
    peer = PeerCertificate(der=der, tls_version="TLSv1.2", cipher="AES256-SHA")

    parsed = SELRTAC._process_ssl_certificate(dev, peer, 443)

    assert parsed is not None
    assert parsed.parser == "openssl"
    assert "only some of its fields were parsed (with openssl)" in caplog.text
    assert dev.x509.subject.common_name == "SEL-3530-4 RTAC"
    assert dev.x509.not_after is None
    assert dev.description.model == "3530-4"

    summary = dev.extra["ssl_certificate"]
    assert summary["parser"] == "openssl"
    assert summary["fingerprints"] == {
        "md5": hashlib.md5(der).hexdigest().upper(),
        "sha1": hashlib.sha1(der).hexdigest().upper(),
        "sha256": hashlib.sha256(der).hexdigest().upper(),
    }
    # Self-signed and the default certificate, by its names (the signature can't be checked)
    assert summary["self_signed"] is True
    assert summary["default_sel_certificate"] is True
    assert summary["expired"] is None
    assert summary["days_remaining"] is None
    assert summary["not_yet_valid"] is False
    assert dev.service[0].extra == {
        "tls_version": "TLSv1.2",
        "tls_cipher": "AES256-SHA",
        "tls_legacy": False,
        "certificate_sha256": hashlib.sha256(der).hexdigest().upper(),
    }
    assert (dev.get_out_dir() / "ssl-certificate.pem").read_text(
        encoding="utf-8"
    ) == ssl.DER_cert_to_PEM_cert(der)


def test_process_invalid_certificate(dev):
    assert SELRTAC._process_ssl_certificate(dev, PeerCertificate(der=b"junk"), 443) is None
    assert not dev.x509.original
    assert "ssl_certificate" not in dev.extra
    assert not dev.files


def test_process_different_certificate_replaces_old(dev, sel_3530_peer, caplog):
    SELRTAC._process_ssl_certificate(dev, make_peer("old.example", ca_signed=True), 443)
    SELRTAC._process_ssl_certificate(dev, sel_3530_peer, 443)

    assert "is different from the certificate that was collected before" in caplog.text
    assert dev.x509.subject.common_name == "SEL-3530-4 RTAC"
    assert dev.x509.issuer.common_name == "SEL-3530-4 RTAC"
    assert dev.x509.subject.organization == "Schweitzer Engineering Laboratories, Inc."


def test_process_certificate_without_device_dir(dev, sel_3530_peer, mocker):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": None})
    dev._out_dir = None

    SELRTAC._process_ssl_certificate(dev, sel_3530_peer, 443)

    assert dev.extra["ssl_certificate"]["fingerprints"]["sha256"] == SEL_3530_DER_SHA256
    assert len(dev.files) == 1
    assert dev.files[0].local_path is None
    assert dev.files[0].hash.sha256 == SEL_3530_PEM_SHA256


# ---------- Identification (scan) ----------


def test_verify_https_ssl_certificate(dev, fake_fetch):
    dev._runtime_options["https"] = {"port": 8443, "timeout": 2.5}

    assert SELRTAC._verify_https_ssl_certificate(dev) is True

    fake_fetch.assert_called_once_with("192.0.2.20", 8443, 2.5)
    assert dev.type == "RTAC"
    assert dev.description.model == "3530-4"
    assert dev.x509.subject.common_name == "SEL-3530-4 RTAC"
    assert dev.extra["ssl_certificate"]["default_sel_certificate"] is True
    # The dead "selrtac_ssl_fingerprinted" cache key is gone
    assert "selrtac_ssl_fingerprinted" not in dev._cache


def test_verify_https_ssl_certificate_parsed_with_openssl(dev, mocker, sel_3530_peer):
    # An RTAC with a certificate that only OpenSSL can parse is still identified
    der = sel_3530_peer.der.replace(b"380119031407Z", b"381319031407Z")
    try:
        tls._decode_with_openssl(der)
    except ssl.SSLError:
        pytest.skip("The local OpenSSL doesn't decode certificates with invalid dates")
    mocker.patch.object(sel_rtac, "fetch_peer_certificate", return_value=PeerCertificate(der=der))

    assert SELRTAC._verify_https_ssl_certificate(dev) is True
    assert dev.type == "RTAC"
    assert dev.description.model == "3530-4"
    assert dev.extra["ssl_certificate"]["parser"] == "openssl"


def test_verify_https_ssl_certificate_not_rtac(dev, mocker):
    mocker.patch.object(
        sel_rtac, "fetch_peer_certificate", return_value=make_peer("plc.example", ca_signed=True)
    )

    assert SELRTAC._verify_https_ssl_certificate(dev) is False
    # Nothing is added to a device that isn't a RTAC
    assert not dev.x509.original
    assert "ssl_certificate" not in dev.extra
    assert not dev.files


@pytest.mark.parametrize("peer", [None, PeerCertificate(der=b"junk")])
def test_verify_https_ssl_certificate_failures(dev, mocker, peer):
    mocker.patch.object(sel_rtac, "fetch_peer_certificate", return_value=peer)
    assert SELRTAC._verify_https_ssl_certificate(dev) is False


# ---------- Pull ----------


def test_pull_ssl_certificate_skip_scan(dev, fake_fetch):
    # With --skip-scan, dev.x509 is empty when the pull starts
    assert not dev.x509.original

    assert SELRTAC.pull_ssl_certificate(dev) is True

    fake_fetch.assert_called_once_with("192.0.2.20", 443, dev.options["https"]["timeout"])
    assert dev.x509.subject.common_name == "SEL-3530-4 RTAC"
    assert dev.description.model == "3530-4"

    # The certificate is only fetched once
    assert SELRTAC.pull_ssl_certificate(dev) is True
    assert fake_fetch.call_count == 1


def test_pull_ssl_certificate_after_scan(dev, fake_fetch):
    SELRTAC._verify_https_ssl_certificate(dev)  # the scan
    assert fake_fetch.call_count == 1

    assert SELRTAC.pull_ssl_certificate(dev) is True
    assert fake_fetch.call_count == 1


def test_pull_ssl_certificate_failure(dev, mocker):
    mocker.patch.object(sel_rtac, "fetch_peer_certificate", return_value=None)

    assert SELRTAC.pull_ssl_certificate(dev) is False
    assert not dev.x509.original


def test_pull_ssl_certificate_keeps_summary_for_monitor(dev, fake_fetch):
    SELRTAC.pull_ssl_certificate(dev)
    summary = dict(dev.extra["ssl_certificate"])

    # The RTAC monitor (update_history) clears dev.extra between pulls
    dev.extra = {}
    SELRTAC.pull_ssl_certificate(dev)

    assert dev.extra["ssl_certificate"] == summary
    assert fake_fetch.call_count == 1


def test_pull_config_gets_certificate(dev, fake_fetch):
    dev._runtime_options["sel"] = {"pull_http": False, "pull_postgres": False}

    SELRTAC.pull_config(dev)

    fake_fetch.assert_called_once()
    assert dev.x509.subject.common_name == "SEL-3530-4 RTAC"


def test_pull_config_certificate_disabled(dev, fake_fetch):
    dev._runtime_options["sel"] = {
        "pull_http": False,
        "pull_postgres": False,
        "pull_ssl_cert": False,
    }

    SELRTAC.pull_config(dev)

    fake_fetch.assert_not_called()
    assert not dev.x509.original


def test_pull_config_certificate_error_does_not_stop_pull(dev, mocker):
    mocker.patch.object(sel_rtac, "fetch_peer_certificate", side_effect=RuntimeError("bug"))
    pull_postgres = mocker.patch.object(SELRTAC, "pull_postgres")
    dev._runtime_options["sel"] = {"pull_http": False}

    SELRTAC.pull_config(dev)

    pull_postgres.assert_called_once_with(dev)


def test_pull_ssl_cert_option_default():
    assert SELRTAC.default_options["sel"]["pull_ssl_cert"] is True


# ---------- Web pull fixes ----------


class FakeRTACWeb:
    """Stand-in for SELHTTP with the RTAC web methods that pull_web() calls."""

    def __init__(self, logged_in: bool = True, login_result: bool = True):
        self.session = requests.Session()
        self.rtac_logged_in = logged_in
        self.login_result = login_result
        self.logins = []
        self.disconnected = False

    def login_rtac(self, user, passwd, protocol):
        self.logins.append((user, passwd, protocol))
        self.rtac_logged_in = self.login_result
        return self.login_result

    def disconnect(self):
        self.disconnected = True

    def view_dashboard(self, _dev):
        return {"web_device_info": {"Host Name": "SEL-3530"}, "web_diagnostics": {"CPU": "1%"}}

    def view_usagepolicy(self, _dev):
        return {"web_usagepolicy": "Authorized use only"}

    def view_filesondevice(self, dev):
        dev.extra["web_files"] = {}
        return {"web_files": {}}

    def view_features(self, _dev):
        return {}

    def view_accounts(self, _dev):
        return {"web_accounts": {"admin": {"Enabled": "Yes"}}}

    def view_user_roles(self, _dev):
        return {}

    def view_ldap(self, _dev):
        return {}

    def download_http_files(self, _dev):
        return {}

    def view_ip_tables(self, _dev):
        return {}

    def view_syslog(self, _dev):
        return {"web_syslog_events": [{"message": "User admin logged in"}]}


@pytest.fixture
def no_sleep(mocker):
    mocker.patch.object(sel_rtac, "sleep")


@pytest.mark.usefixtures("no_sleep")
def test_pull_web_uses_verified_web_pass(dev):
    session = FakeRTACWeb(logged_in=False, login_result=False)
    dev._cache["web_session"] = session
    dev._cache["verified_web_user"] = "admin"
    dev._cache["verified_web_pass"] = "S3cret!"

    assert SELRTAC.pull_web(dev, "https") is None
    assert session.logins == [("admin", "S3cret!", "https")]


@pytest.mark.usefixtures("no_sleep")
def test_pull_web_uses_configured_credentials(dev):
    session = FakeRTACWeb(logged_in=False, login_result=False)
    dev._cache["web_session"] = session
    dev._runtime_options["web"] = {"user": "engineer", "pass": "configured"}

    SELRTAC.pull_web(dev, "https")
    assert session.logins == [("engineer", "configured", "https")]


@pytest.mark.usefixtures("no_sleep")
def test_pull_web_no_relay_default_credentials(dev, caplog):
    # RTACs don't have the relay ACC/OTTER accounts, so they aren't tried
    session = FakeRTACWeb(logged_in=False)
    dev._cache["web_session"] = session

    assert SELRTAC.pull_web(dev, "https") is None
    assert session.logins == []
    assert "No web credentials" in caplog.text


@pytest.mark.usefixtures("no_sleep")
def test_pull_web_removes_fields_from_result(dev, read_text):
    dev._cache["web_session"] = FakeRTACWeb()

    pulled = SELRTAC.pull_web(dev, "https")

    for field in ["web_syslog_events", "web_usagepolicy", "web_device_info"]:
        assert field not in pulled
    assert pulled["web_diagnostics"] == {"CPU": "1%"}
    assert pulled["web_accounts"] == {"admin": {"Enabled": "Yes"}}

    # The file still has everything
    out_file = dev.get_out_dir() / "pulled-web-config.json"
    assert '"web_device_info"' in read_text(out_file)
    assert '"web_syslog_events"' in read_text(out_file)
    assert dev._cache["web_session"].disconnected

    # The file is hashed
    recorded = [f for f in dev.files if f.name == "pulled-web-config.json"]
    assert len(recorded) == 1
    assert recorded[0].hash.sha256 == hashlib.sha256(out_file.read_bytes()).hexdigest().upper()
    assert recorded[0].extra == {"source": "derived"}
