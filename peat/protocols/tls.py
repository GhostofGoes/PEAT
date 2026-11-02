"""
Retrieve and parse the X.509 certificate of a TLS server.

:func:`fetch_peer_certificate` does a single TLS handshake to get the server's
certificate. It doesn't verify the certificate (the self-signed certificates
used by most :term:`OT` devices would fail verification), and it doesn't send
any application data, so it's safe to use with any TLS service (HTTPS, TLS
tunnels, etc.). If the handshake fails with the default settings, it's retried
once with a "legacy" context that allows TLS 1.0 and 1.1, weak ciphers and
keys, and servers without secure renegotiation (:rfc:`5746`), which is needed
for older devices.

:func:`parse_der_certificate` parses the certificate with the ``cryptography``
library into a :class:`~peat.data.models.X509` model, and calculates the
certificate fingerprints that other tools use. Certificates that
``cryptography`` rejects (e.g. with an invalid date) are parsed with the
OpenSSL decoder of the :mod:`ssl` module instead, which gives fewer fields.

.. note::
   :attr:`X509.hash <peat.data.models.X509.hash>` has the hashes of the
   certificate in PEM format (the text in ``X509.original``), which is how
   PEAT has always calculated them. Browsers, ``openssl x509 -fingerprint``,
   Zeek, Shodan and the :term:`ECS` ``tls.server.hash`` fields use the hashes
   of the DER encoding, which are in :attr:`ParsedCertificate.fingerprints`.

Example:

.. code-block:: python

   >>> from peat.protocols.tls import fetch_peer_certificate, parse_der_certificate
   >>> peer = fetch_peer_certificate("192.0.2.20", 443, timeout=5.0)  # doctest: +SKIP
   >>> parsed = parse_der_certificate(peer.der)  # doctest: +SKIP
   >>> parsed.x509.subject.common_name  # doctest: +SKIP
   'SEL-3530-4 RTAC'
   >>> parsed.fingerprints["sha256"]  # doctest: +SKIP
   '075EAE062895601C16BDB2478BB019A25ED83F4F74E94A0E537D9157FC4A0D84'
"""

from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import os
import socket
import ssl
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime

from cryptography import x509 as crypto_x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, padding, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

import peat  # Avoid circular imports
from peat import log, utils

#: Names of signature algorithms, by OID, in the format used by
#: the :term:`ECS` ``x509.signature_algorithm`` field (e.g. ``SHA256-RSA``).
SIGNATURE_ALGORITHMS: dict[str, str] = {
    "1.2.840.113549.1.1.2": "MD2-RSA",
    "1.2.840.113549.1.1.4": "MD5-RSA",
    "1.2.840.113549.1.1.5": "SHA1-RSA",
    "1.2.840.113549.1.1.14": "SHA224-RSA",
    "1.2.840.113549.1.1.11": "SHA256-RSA",
    "1.2.840.113549.1.1.12": "SHA384-RSA",
    "1.2.840.113549.1.1.13": "SHA512-RSA",
    "1.2.840.10040.4.3": "DSA-SHA1",
    "2.16.840.1.101.3.4.3.1": "DSA-SHA224",
    "2.16.840.1.101.3.4.3.2": "DSA-SHA256",
    "1.2.840.10045.4.1": "ECDSA-SHA1",
    "1.2.840.10045.4.3.1": "ECDSA-SHA224",
    "1.2.840.10045.4.3.2": "ECDSA-SHA256",
    "1.2.840.10045.4.3.3": "ECDSA-SHA384",
    "1.2.840.10045.4.3.4": "ECDSA-SHA512",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
}

#: OID of RSASSA-PSS signatures. The name depends on the hash in the parameters.
_RSA_PSS_OID = "1.2.840.113549.1.1.10"

#: Names of NIST curves in the format used by the :term:`ECS`
#: ``x509.public_key_curve`` field. Other curves keep their name.
_CURVE_NAMES: dict[str, str] = {
    "secp192r1": "nistp192",
    "secp224r1": "nistp224",
    "secp256r1": "nistp256",
    "secp384r1": "nistp384",
    "secp521r1": "nistp521",
}

#: Attributes of the issuer and subject, and the
#: :class:`~peat.data.models.CertEntity` fields they're saved in.
_ENTITY_ATTRIBUTES: dict[str, crypto_x509.ObjectIdentifier] = {
    "common_name": NameOID.COMMON_NAME,
    "country": NameOID.COUNTRY_NAME,
    "locality": NameOID.LOCALITY_NAME,
    "organization": NameOID.ORGANIZATION_NAME,
    "organizational_unit": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "state_or_province": NameOID.STATE_OR_PROVINCE_NAME,
}

#: The same attributes, by the names the OpenSSL decoder of the :mod:`ssl` module uses.
_OPENSSL_ENTITY_ATTRIBUTES: dict[str, str] = {
    "commonName": "common_name",
    "countryName": "country",
    "localityName": "locality",
    "organizationName": "organization",
    "organizationalUnitName": "organizational_unit",
    "stateOrProvinceName": "state_or_province",
}

#: Names of attributes in distinguished names (:rfc:`4514`), by OpenSSL name.
#: Other attributes keep the OpenSSL name.
_DN_SHORT_NAMES: dict[str, str] = {
    "commonName": "CN",
    "countryName": "C",
    "domainComponent": "DC",
    "localityName": "L",
    "organizationName": "O",
    "organizationalUnitName": "OU",
    "stateOrProvinceName": "ST",
    "streetAddress": "STREET",
    "userId": "UID",
}


@dataclass
class PeerCertificate:
    """
    Certificate a TLS server sent during the handshake,
    and the parameters of the TLS session.
    """

    der: bytes = field(repr=False)
    """The server's (leaf) certificate, DER-encoded."""

    chain: list[bytes] = field(default_factory=list, repr=False)
    """
    Every certificate the server sent, DER-encoded, starting with the leaf
    certificate. This is only available with Python 3.13 and newer, and is
    empty otherwise.
    """

    tls_version: str = ""
    """Version of TLS that was negotiated, e.g. ``TLSv1.2``."""

    cipher: str = ""
    """Name of the cipher suite that was negotiated, e.g. ``ECDHE-RSA-AES256-GCM-SHA384``."""

    legacy: bool = False
    """
    If the legacy context (TLS 1.0 and 1.1, weak ciphers) was needed
    to complete the handshake.
    """

    @property
    def pem(self) -> str:
        """The server's certificate, PEM-encoded."""
        return ssl.DER_cert_to_PEM_cert(self.der)


@dataclass
class ParsedCertificate:
    """
    Result of :func:`parse_der_certificate`.
    """

    x509: peat.data.models.X509
    """
    The certificate in PEAT's data model. ``original`` is the PEM text, and
    ``hash`` is left unset (it's set by :meth:`~peat.data.models.X509.annotate`).
    """

    fingerprints: dict[str, str]
    """
    Uppercase hex fingerprints of the certificate. ``md5``, ``sha1``
    and ``sha256`` are hashes of the DER encoding (like ``openssl x509
    -fingerprint`` and the :term:`ECS` ``tls.server.hash`` fields).
    ``spki_sha256`` is the SHA-256 hash of the DER-encoded public key
    (SubjectPublicKeyInfo), which is the same for every certificate made
    with the same key (key pinning). It's not set if the key type isn't
    supported by ``cryptography``, or if the certificate was parsed with OpenSSL.
    """

    self_signed: bool
    """
    If the certificate is self-signed: the issuer is the same as the subject,
    and (if PEAT can check it) the certificate is signed by its own key.
    """

    ca: bool | None = None
    """
    If the certificate is a certificate authority (the ``basicConstraints``
    extension), or :obj:`None` if it doesn't have the extension.
    """

    subject_key_identifier: str = ""
    """Uppercase hex subject key identifier, if the certificate has one."""

    authority_key_identifier: str = ""
    """Uppercase hex authority key identifier, if the certificate has one."""

    parser: str = "cryptography"
    """
    What parsed the certificate: ``cryptography``, or ``openssl`` if
    ``cryptography`` rejected it. With ``openssl``, only the names, serial
    number, version, validity dates and alternative names are set (not the
    key, the signature algorithm or the other extensions), ``spki_sha256``
    isn't set, and ``self_signed`` only means the issuer is the same as
    the subject (the signature can't be checked).
    """


def create_client_context(legacy: bool = False) -> ssl.SSLContext:
    """
    Create a TLS client context that doesn't verify the server's certificate
    or host name.

    Args:
        legacy: Allow every TLS version the local OpenSSL supports (including
            TLS 1.0 and 1.1), weak ciphers and keys (OpenSSL security level 0),
            and servers that don't support secure renegotiation.

    Returns:
        The TLS context
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # NOTE: check_hostname must be disabled before verify_mode is set to CERT_NONE
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    if legacy:
        context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        try:
            context.set_ciphers("DEFAULT:@SECLEVEL=0")
        except ssl.SSLError:  # Security levels are specific to OpenSSL
            context.set_ciphers("DEFAULT")
        # ssl.OP_LEGACY_SERVER_CONNECT was added in Python 3.12
        context.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)

    return context


def _handshake(host: str, port: int, timeout: float, legacy: bool) -> PeerCertificate | None:
    context = create_client_context(legacy)

    # Server Name Indication (SNI) is only used for host names, not IP addresses
    try:
        ipaddress.ip_address(host)
        server_hostname = None
    except ValueError:
        server_hostname = host

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=server_hostname) as tls:
            # NOTE: getpeercert() returns an empty dict with CERT_NONE,
            # the certificate is only available in binary (DER) form.
            der = tls.getpeercert(binary_form=True)
            if not der:
                return None

            chain = []
            if hasattr(tls, "get_unverified_chain"):  # Python 3.13+
                chain = [bytes(cert) for cert in tls.get_unverified_chain()]

            cipher = tls.cipher()

            return PeerCertificate(
                der=der,
                chain=chain,
                tls_version=tls.version() or "",
                cipher=cipher[0] if cipher else "",
                legacy=legacy,
            )


def fetch_peer_certificate(
    host: str,
    port: int = 443,
    timeout: float = 5.0,
    legacy_fallback: bool = True,
) -> PeerCertificate | None:
    """
    Get the certificate of a TLS server, without verifying it.

    This makes one TCP connection and does one TLS handshake, then closes the
    connection without sending any data. If the handshake fails with a TLS
    error or the server resets the connection (which is what many older
    devices do if they don't support the TLS version), it's retried once with
    the legacy context (refer to :func:`create_client_context`). It's not
    retried if the TCP connection fails (e.g. it's refused or times out).

    Args:
        host: IP address or host name of the server
        port: TCP port of the server
        timeout: Timeout for the connection and handshake, in seconds
        legacy_fallback: If the handshake should be retried with the legacy context

    Returns:
        The certificate and the TLS session parameters,
        or :obj:`None` if the certificate couldn't be retrieved
    """
    _log = log.bind(classname="TLS", target=f"{host}:{port}")
    attempts = [False, True] if legacy_fallback else [False]

    for legacy in attempts:
        try:
            peer = _handshake(host, port, timeout, legacy)
        except (ssl.SSLError, ConnectionResetError, ConnectionAbortedError) as ex:
            if not legacy and legacy_fallback:
                _log.debug(f"TLS handshake failed ({ex}), retrying with the legacy TLS context")
                continue
            _log.warning(f"Failed to get the TLS certificate: {ex}")
            return None
        except OSError as ex:  # Connection refused, timeout, unreachable, etc.
            _log.warning(f"Failed to get the TLS certificate: {ex}")
            return None

        if peer is None:
            _log.warning("Failed to get the TLS certificate: the server didn't send one")
            return None

        if peer.legacy:
            _log.info(f"Server only supports legacy TLS ({peer.tls_version}, {peer.cipher})")
        _log.debug(f"Got TLS certificate ({peer.tls_version}, {peer.cipher})")
        return peer

    return None


def parse_der_certificate(der: bytes) -> ParsedCertificate:
    """
    Parse a DER-encoded X.509 certificate.

    The certificate is parsed with ``cryptography``. If ``cryptography``
    rejects it (it's stricter than OpenSSL, e.g. about invalid dates or
    string types, which are common in certificates made by :term:`OT`
    devices), it's parsed with the OpenSSL decoder of the :mod:`ssl` module
    instead, which gives fewer fields (refer to :attr:`ParsedCertificate.parser`).

    Args:
        der: The DER-encoded certificate

    Returns:
        The parsed certificate, with its fingerprints

    Raises:
        ValueError: The data isn't a valid certificate
    """
    try:
        return _parse_with_cryptography(der)
    except Exception as ex:  # cryptography raises ValueError, KeyError, TypeError, etc.
        crypto_error = ex

    try:
        parsed = _parse_with_openssl(der)
    except Exception as ex:
        log.trace(f"Failed to parse the certificate with OpenSSL: {ex}")
        raise ValueError(
            f"Invalid certificate ({type(crypto_error).__name__}: {crypto_error})"
        ) from crypto_error

    log.debug(
        f"Parsed the certificate with OpenSSL, because cryptography couldn't parse it "
        f"({crypto_error}). Its key, signature and extensions aren't available."
    )
    return parsed


def _fingerprints(der: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(der, usedforsecurity=False).hexdigest().upper(),
        "sha1": hashlib.sha1(der, usedforsecurity=False).hexdigest().upper(),
        "sha256": hashlib.sha256(der).hexdigest().upper(),
    }


def _parse_with_cryptography(der: bytes) -> ParsedCertificate:
    cert = crypto_x509.load_der_x509_certificate(der)

    x509_model = peat.data.models.X509(
        original=ssl.DER_cert_to_PEM_cert(der),
        serial_number=_format_serial(cert.serial_number),
        version_number=_version_number(cert),
        not_before=_validity(cert, "not_valid_before"),
        not_after=_validity(cert, "not_valid_after"),
        issuer=_cert_entity(cert.issuer),
        subject=_cert_entity(cert.subject),
        signature_algorithm=_signature_algorithm(cert),
    )

    fingerprints = _fingerprints(der)

    public_key = None
    try:
        public_key = cert.public_key()
    except Exception as ex:  # Unsupported key types raise various exceptions
        log.debug(f"Unsupported public key in certificate: {ex}")

    if public_key is not None:
        _set_public_key_fields(x509_model, public_key)
        spki = public_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        fingerprints["spki_sha256"] = hashlib.sha256(spki).hexdigest().upper()

    # Subject email addresses are kept with the alternative names (the
    # CertEntity model doesn't have an email field), like HTTP does.
    alternative_names = [
        str(attr.value).strip()
        for attr in cert.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)
    ]

    parsed = ParsedCertificate(
        x509=x509_model,
        fingerprints=fingerprints,
        self_signed=False,
    )

    try:
        extensions = cert.extensions
    except Exception as ex:  # Malformed or duplicate extensions
        log.warning(f"Failed to parse the extensions of the certificate: {ex}")
        extensions = crypto_x509.Extensions([])

    for ext in extensions:
        value = ext.value
        if ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
            for general_name in value:
                if isinstance(
                    general_name,
                    (
                        crypto_x509.DNSName,
                        crypto_x509.IPAddress,
                        crypto_x509.RFC822Name,
                        crypto_x509.UniformResourceIdentifier,
                    ),
                ):
                    alternative_names.append(str(general_name.value).strip())
        elif ext.oid == ExtensionOID.BASIC_CONSTRAINTS:
            parsed.ca = value.ca
        elif ext.oid == ExtensionOID.SUBJECT_KEY_IDENTIFIER:
            parsed.subject_key_identifier = value.digest.hex().upper()
        elif ext.oid == ExtensionOID.AUTHORITY_KEY_IDENTIFIER and value.key_identifier:
            parsed.authority_key_identifier = value.key_identifier.hex().upper()

    x509_model.alternative_names = list(dict.fromkeys(n for n in alternative_names if n))

    if cert.issuer == cert.subject:
        # Only rule it out if the signature is definitely
        # invalid, not if PEAT can't check it.
        parsed.self_signed = _signed_by_own_key(cert, public_key) is not False

    return parsed


def _decode_with_openssl(der: bytes) -> dict:
    """
    Decode a certificate with OpenSSL, using the same (private) function of
    the :mod:`ssl` module as :meth:`HTTP.decode_ssl_certificate()
    <peat.protocols.http.HTTP.decode_ssl_certificate>`. It only reads files.
    """
    fd, name = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as tmp:
            tmp.write(ssl.DER_cert_to_PEM_cert(der))
        return ssl._ssl._test_decode_cert(name)
    finally:
        with contextlib.suppress(OSError):
            os.unlink(name)


def _parse_with_openssl(der: bytes) -> ParsedCertificate:
    """
    Parse a certificate that ``cryptography`` rejected. The names, serial
    number, version, validity dates and alternative names are available,
    but not the key, the signature algorithm or the other extensions.
    """
    decoded = _decode_with_openssl(der)
    if not decoded.get("subject") and not decoded.get("issuer"):
        raise ValueError("no subject or issuer")

    x509_model = peat.data.models.X509(
        original=ssl.DER_cert_to_PEM_cert(der),
        serial_number=str(decoded.get("serialNumber", "")).strip().upper().replace(":", ""),
        version_number=str(decoded.get("version", "")),
        not_before=_openssl_time(decoded.get("notBefore")),
        not_after=_openssl_time(decoded.get("notAfter")),
        issuer=_openssl_entity(decoded.get("issuer", ())),
        subject=_openssl_entity(decoded.get("subject", ())),
    )

    alternative_names = [
        str(value).strip()
        for rdn in decoded.get("subject", ())
        for key, value in rdn
        if key == "emailAddress"
    ]
    alternative_names.extend(
        str(value).strip()
        for kind, value in decoded.get("subjectAltName", ())
        if kind in ("DNS", "IP Address", "email", "URI")
    )
    x509_model.alternative_names = list(dict.fromkeys(n for n in alternative_names if n))

    return ParsedCertificate(
        x509=x509_model,
        fingerprints=_fingerprints(der),
        # The signature can't be checked without the key
        self_signed=decoded.get("issuer") == decoded.get("subject"),
        parser="openssl",
    )


def _openssl_time(value: str | None) -> datetime | None:
    # e.g. "Mar  6 20:14:56 2019 GMT", or "Bad time value" if it's invalid
    if not value:
        return None
    try:
        return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), UTC)
    except (ValueError, OverflowError, OSError):
        return None


def _openssl_entity(rdns: tuple) -> peat.data.models.CertEntity:
    values: dict[str, list[str]] = {}
    dn_parts = []

    for rdn in rdns:
        rdn_parts = []
        for key, raw_value in rdn:
            rdn_parts.append(f"{_DN_SHORT_NAMES.get(key, key)}={_escape_dn_value(str(raw_value))}")
            value = str(raw_value).strip()
            field_name = _OPENSSL_ENTITY_ATTRIBUTES.get(key)
            if field_name and value and value not in values.setdefault(field_name, []):
                values[field_name].append(value)
        dn_parts.append("+".join(rdn_parts))

    # RFC 4514 lists the most specific attribute first (the reverse of the encoding)
    entity = peat.data.models.CertEntity(distinguished_name=",".join(reversed(dn_parts)))
    for field_name, field_values in values.items():
        setattr(entity, field_name, ", ".join(field_values))

    return entity


def _escape_dn_value(value: str) -> str:
    """Escape a value of a distinguished name (:rfc:`4514#section-2.4`)."""
    if not value:
        return ""
    value = value.replace("\\", "\\\\")
    for char in ',+"<>;':
        value = value.replace(char, f"\\{char}")
    value = value.replace("\0", "\\00")
    if value[0] in ("#", " "):
        value = f"\\{value}"
    if value[-1] == " ":
        value = f"{value[:-1]}\\ "
    return value


def validity_status(cert: peat.data.models.X509, now: datetime | None = None) -> dict:
    """
    Check the validity period of a certificate.

    Args:
        cert: The certificate
        now: Time to check against. Defaults to the current time (UTC).

    Returns:
        :class:`dict` with the keys ``expired``, ``not_yet_valid`` (:class:`bool`,
        or :obj:`None` if the certificate has no validity dates), and
        ``days_remaining`` (whole days until the certificate expires,
        negative if it's expired, or :obj:`None`).
    """
    if now is None:
        now = utils.utc_now()

    status = {"expired": None, "not_yet_valid": None, "days_remaining": None}
    if cert.not_after:
        status["expired"] = now > cert.not_after
        status["days_remaining"] = (cert.not_after - now).days
    if cert.not_before:
        status["not_yet_valid"] = now < cert.not_before

    return status


def _format_serial(serial: int) -> str:
    """Uppercase hex, without colons, padded to whole bytes (like OpenSSL)."""
    sign = "-" if serial < 0 else ""
    hex_serial = format(abs(serial), "X")
    if len(hex_serial) % 2:
        hex_serial = f"0{hex_serial}"
    return f"{sign}{hex_serial}"


def _version_number(cert: crypto_x509.Certificate) -> str:
    try:
        return str(cert.version.value + 1)  # v1 is 0, v3 is 2
    except crypto_x509.InvalidVersion as ex:
        return str(ex.parsed_version + 1)


def _validity(cert: crypto_x509.Certificate, attr: str) -> datetime:
    # cryptography 42+ has timezone-aware "*_utc" attributes,
    # older versions return naive datetimes that are in UTC.
    aware = getattr(cert, f"{attr}_utc", None)
    if aware is not None:
        return aware
    return getattr(cert, attr).replace(tzinfo=UTC)


def _cert_entity(name: crypto_x509.Name) -> peat.data.models.CertEntity:
    # RFC 4514 format, e.g. "CN=SEL-3530-4 RTAC,O=Schweitzer Engineering Laboratories\, Inc.,C=US"
    entity = peat.data.models.CertEntity(
        distinguished_name=name.rfc4514_string({NameOID.EMAIL_ADDRESS: "emailAddress"})
    )

    for field_name, oid in _ENTITY_ATTRIBUTES.items():
        values = []
        for attr in name.get_attributes_for_oid(oid):
            value = str(attr.value).strip()
            if value and value not in values:
                values.append(value)
        if values:
            setattr(entity, field_name, ", ".join(values))

    return entity


def _signature_algorithm(cert: crypto_x509.Certificate) -> str:
    oid = cert.signature_algorithm_oid.dotted_string

    if oid == _RSA_PSS_OID:
        try:
            hash_alg = cert.signature_hash_algorithm
        except Exception:
            hash_alg = None
        return f"{hash_alg.name.upper()}-RSAPSS" if hash_alg else "RSAPSS"

    return SIGNATURE_ALGORITHMS.get(oid, oid)


def _set_public_key_fields(cert: peat.data.models.X509, public_key) -> None:
    if isinstance(public_key, rsa.RSAPublicKey):
        cert.public_key_algorithm = "RSA"
        cert.public_key_size = public_key.key_size
        cert.public_key_exponent = public_key.public_numbers().e
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        cert.public_key_algorithm = "ECDSA"
        cert.public_key_size = public_key.key_size
        cert.public_key_curve = _CURVE_NAMES.get(public_key.curve.name, public_key.curve.name)
    elif isinstance(public_key, dsa.DSAPublicKey):
        cert.public_key_algorithm = "DSA"
        cert.public_key_size = public_key.key_size
    elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        cert.public_key_algorithm = (
            "Ed25519" if isinstance(public_key, ed25519.Ed25519PublicKey) else "Ed448"
        )
        raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        cert.public_key_size = len(raw) * 8


def _signed_by_own_key(cert: crypto_x509.Certificate, public_key) -> bool | None:
    """
    Check if a certificate is signed by its own public key.

    Returns:
        :obj:`True` if the signature is valid, :obj:`False` if it's invalid,
        or :obj:`None` if it can't be checked (e.g. unsupported algorithm)
    """
    if public_key is None or cert.signature_algorithm_oid.dotted_string == _RSA_PSS_OID:
        return None

    try:
        signature = cert.signature
        data = cert.tbs_certificate_bytes
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, data, padding.PKCS1v15(), cert.signature_hash_algorithm)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, data, ec.ECDSA(cert.signature_hash_algorithm))
        elif isinstance(public_key, dsa.DSAPublicKey):
            public_key.verify(signature, data, cert.signature_hash_algorithm)
        elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            public_key.verify(signature, data)
        else:
            return None
    except InvalidSignature:
        return False
    except Exception as ex:  # e.g. a key type that doesn't match the signature
        log.debug(f"Unable to check the signature of the certificate: {ex}")
        return None

    return True


__all__ = [
    "SIGNATURE_ALGORITHMS",
    "ParsedCertificate",
    "PeerCertificate",
    "create_client_context",
    "fetch_peer_certificate",
    "parse_der_certificate",
    "validity_status",
]
