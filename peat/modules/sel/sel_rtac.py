"""
Core functionality for interrogating a SEL Real-Time Automation Controller (RTAC).

.. note::
   The 3530 RTAC (and possibly others ) disable ping (ICMP) responses by default.
   If using PEAT against an RTAC on another subnet or VLAN and the online check
   fails, try again with the ``--assume-online`` flag set. Another option is to
   force TCP SYN checks to be used with port 443.

SEL RTACs store data in a PostgreSQL database, but it can be exported as XML.
ACSELERATOR RTAC (SEL-5033) exports a project as a directory of XML files,
with one XML file for each item in the project tree (devices, tag lists,
programs, system settings, etc.). PEAT can parse the directory, a tarball of
the directory (``.tar``, ``.tar.gz`` or ``.tgz``), or a single XML file.
Refer to :ref:`sel-rtac-project-exports` for details on the file format.

To test Postgres (connecting to the "3530" database table):
``psql -h <ip> -U <username> -d 3530``

Note: Nginx is the web server used by the SEL RTAC devices.

The TLS certificate of the web server (HTTPS) is collected during the scan
(identification) or the pull, and checked for the factory-default self-signed
certificate. Refer to :ref:`sel-rtac-tls-certificate` for details.

Listening network services

- HTTP (TCP 80) (This redirects to 443 HTTPS)
- HTTPS (TCP 443)
- PostgreSQL (TCP 5432)

Supported models

- SEL-3530
- SEL-3530-4
- SEL-3350

Authors

- Ryan Vrecenar
- Christopher Goes
"""

import base64
import functools
import hashlib
import ipaddress
import json
import math
import re
import ssl
import tarfile
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from time import sleep
from typing import Any, Literal
from urllib.parse import parse_qs, urlparse

import psycopg2
from requests import Response

from peat import (
    DeviceData,
    DeviceModule,
    Interface,
    IPMethod,
    config,
    consts,
    datastore,
    exit_handler,
    log,
    state,
    utils,
)
from peat.consts import DeviceError
from peat.data.data_utils import merge_models
from peat.data.models import X509, File, Hash, Register, Service, SSHKey, User
from peat.data.validators import validate_hash
from peat.file_signature import FileSignature
from peat.protocols.ssh import fetch_ssh_host_key
from peat.protocols.tls import (
    ParsedCertificate,
    PeerCertificate,
    fetch_peer_certificate,
    parse_der_certificate,
    validity_status,
)

from .rtac_engineering_access import (
    PG_TABLES,
    Discovery,
    Listener,
    discover_from_export,
    discover_from_postgres,
    merge_entries,
    unique_paths,
)
from .rtac_parse import (
    build_structured_text,
    parse_accesspointrouters,
    parse_backupable_objects,
    parse_contact_ios,
    parse_data_types,
    parse_devices,
    parse_export_source,
    parse_goose_devices,
    parse_gvls,
    parse_iec61850_info,
    parse_logic_engine_objects,
    parse_maincontroller,
    parse_pous,
    parse_project_info,
    parse_system_time_control,
    parse_systemtags,
    parse_tag_lists,
    parse_tagprocessor,
    parse_user_libraries,
    parse_visualizations,
)
from .sel_consts import (
    RTAC_DB_NAME,
    RTAC_DB_TABLES,
    RTAC_EXPORT_ADDRESS_COLUMNS,
    RTAC_EXPORT_IP_SETTINGS,
    RTAC_EXPORT_PORT_SETTINGS,
    RTAC_EXPORT_PROTOCOLS,
    RTAC_TRANSIENT_KEYS,
)
from .sel_http import SELHTTP


@dataclass(frozen=True)
class _Digest:
    """
    Size and hashes of the contents of a file, so large
    contents don't have to be kept in memory to record them.
    """

    size: int
    sha256: str
    """SHA-256 (lowercase hex), to find the file PEAT wrote with these contents."""
    hashes: dict[str, str]
    """Hashes from :func:`peat.utils.gen_hashes` (``HASH_ALGORITHMS``)."""

    @classmethod
    def of(cls, data: bytes) -> "_Digest":
        return cls(
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
            hashes=utils.gen_hashes(data),
        )


class SELRTAC(DeviceModule):
    """
    SEL Real-Time Automation Controller (RTAC).
    """

    device_type = "RTAC"
    vendor_id = "SEL"
    vendor_name = "Schweitzer Engineering Laboratories"
    brand = "SEL"

    can_parse_dir = True
    filename_patterns = [
        # "*.tar.gz"
        "*accesspointrouter*.tar.gz",
        "*AccessPoints*.tar.gz",
        "devices.tar.gz",
        "*rtacexport*.tar.gz",  # rtacexport3.tar.gz
        "*rtac*.tar*",
        "*rtac*.tgz",
        "Tag Processor.xml",
        "SystemTags.xml",
        "Main Controller.xml",
        "Contact I_O.xml",
        "System_Time_Control.xml",
        "Project Info.xml",
    ]
    file_signatures = [
        FileSignature(
            default_filename="rtac-export.xml",
            xml_tags=("RTACModule",),
        ),
    ]

    # These are what's known to work. Others may work as well
    supported_models = ["3530", "3530-4", "3350"]
    module_aliases = [f"sel-{x}" for x in supported_models]

    default_options = {
        "web": {
            "user": "",
            "pass": "",
            "users": [
                "Admin",
                "admin",
                "administrator",
            ],
            "passwords": ["admin", "rtac"],
        },
        "postgres": {
            "user": "",
            "pass": "",
            "users": ["Admin", "admin", "administrator", "rtac"],
            "passwords": ["admin", "rtac"],
        },
        "sel": {
            "pull_http": True,
            "pull_postgres": True,
            # One TLS handshake with the web server, which doesn't log in or
            # send any requests. Skipped if the scan already got the certificate.
            "pull_ssl_cert": True,
            # Connect to the engineering access ports found in the RTAC
            # configuration that use TLS or SSH, to get their certificates and
            # host keys. Off by default, since it makes extra connections.
            "rtac_probe_tunnel_ports": False,
            "rtac_monitor_enable": False,
            "rtac_monitor_count": 3,
            "rtac_monitor_pause_for": 4.0,
        },
    }

    _tag_to_parser_map = {
        "AccessPointRouter": parse_accesspointrouters,
        "Device": parse_devices,
        "GooseDevice": parse_goose_devices,
        "TagList": parse_tag_lists,
        "TagProcessor": parse_tagprocessor,
        "ContactIO": parse_contact_ios,
        "SystemTags": parse_systemtags,
        "SystemTimeControl": parse_system_time_control,
        "MainController": parse_maincontroller,
        "POU": parse_pous,
        "LogicEngineObject": parse_logic_engine_objects,
        "DataType": parse_data_types,
        "GVL": parse_gvls,
        "UserLibrary": parse_user_libraries,
        "ProjectInfo": parse_project_info,
        "IEC61850Info": parse_iec61850_info,
        "RTACBackupableObject": parse_backupable_objects,
        "Visualization": parse_visualizations,
        "VisualizationManager": parse_visualizations,
    }

    # Items in a project export that don't have any useful data
    _ignored_tags = {"NavigatorLayout"}

    # Subject of the factory-default (self-signed) certificate of the RTAC web
    # server, e.g. "CN=SEL-3530-4 RTAC,OU=Automation and Integration Engineering,
    # O=Schweitzer Engineering Laboratories, Inc.,L=Pullman,ST=Washington,C=US"
    _default_cert_organization = "Schweitzer Engineering Laboratories, Inc."
    _default_cert_unit = "Automation and Integration Engineering"
    _cert_cn_regex = re.compile(r"^SEL-(?P<model>\d{4}(?:-\d+)?)\s+RTAC\b")

    @classmethod
    def _verify_http(cls, dev: DeviceData, protocol: Literal["http", "https"] = "http") -> bool:
        """
        Verify a device is a SEL RTAC via the HTTP web interface.
        """
        port = dev.options[protocol]["port"]
        timeout = dev.options[protocol]["timeout"]

        cls.log.debug(
            f"Verifying RTAC HTTP for {dev.ip}:{port} using {protocol} (timeout: {timeout})"
        )

        session = SELHTTP(dev.ip, port, timeout)
        logged_in = False

        if dev._cache.get("verified_web_user") and dev._cache.get("verified_web_pass"):
            logged_in = session.login_rtac(
                dev._cache["verified_web_user"],
                dev._cache["verified_web_pass"],
                protocol,
            )
        # Check all user, and pass, only proceed when logged_in is True, or exhausted
        else:
            if dev.options["web"]["user"]:
                users = [dev.options["web"]["user"]]
            else:
                users = dev.options["web"]["users"]

            if dev.options["web"]["pass"]:
                passwords = [dev.options["web"]["pass"]]
            else:
                passwords = dev.options["web"]["passwords"]

            for username in users:
                cls.log.debug(f"Attempting RTAC login to {dev.ip} with user '{username}'")

                for password in passwords:
                    logged_in = session.login_rtac(username, password, protocol)
                    if logged_in:
                        dev._cache["verified_web_user"] = username
                        dev._cache["verified_web_pass"] = password
                        dev.related.user.add(username)
                        break

                if logged_in:
                    break

        if logged_in:
            try:
                dashboard = session.view_dashboard(dev)
            except Exception:
                cls.log.exception(f"Failed to view dashboard for {dev.ip}")
                session.disconnect()
                return False

            # Check if dashboard has appropriate fields
            if (
                (not dashboard.get("web_device_info"))
                or ("Firmware Version" not in dashboard["web_device_info"])
                or ("Host Name" not in dashboard["web_device_info"])
            ):
                session.disconnect()
                return False

            # Only cache session of it's a known RTAC
            if any(m in dev.description.model for m in cls.supported_models) or (
                "3530" in dashboard["web_device_info"].get("Firmware Version", "")
                and "3530" in dashboard["web_device_info"].get("Host Name", "")
            ):
                # Cache the session using this protocol
                # TODO: we should try to prefer HTTPS when possible for security
                if not dev._cache.get("web_session"):
                    dev._cache["web_session"] = session
                    dev._cache["web_protocol"] = protocol
                    exit_handler.register(session.disconnect, "CONNECTION")
                else:
                    session.disconnect()
                return True

        session.disconnect()
        cls.log.debug(f"RTAC HTTP verification failed for {dev.ip}:{port}")
        return False

    @classmethod
    def _verify_https_ssl_certificate(cls, dev: DeviceData) -> bool:
        """
        Verify a device is a SEL RTAC via inspection of the Common Name
        attribute of the TLS certificate of the web server (HTTPS).
        """
        timeout = dev.options["https"]["timeout"]
        port = dev.options["https"]["port"]

        cls.log.debug(f"Verifying {dev.ip}:{port} using SSL (timeout: {timeout})")

        peer = fetch_peer_certificate(dev.ip, port, timeout)
        if not peer:
            return False

        try:
            parsed = parse_der_certificate(peer.der)
        except ValueError as ex:
            cls.log.debug(f"Invalid TLS certificate from {dev.ip}:{port}: {ex}")
            return False

        common_name = parsed.x509.subject.common_name or parsed.x509.issuer.common_name
        if "SEL" not in common_name or "RTAC" not in common_name:
            return False

        cls.log.debug(f"SSL verification successful for {dev.ip}:{port}")
        cls._process_ssl_certificate(dev, peer, port, parsed)
        dev.type = "RTAC"
        cls.update_dev(dev)
        return True

    @classmethod
    def pull_ssl_certificate(cls, dev: DeviceData) -> bool:
        """
        Get and process the TLS certificate of the RTAC's web server (HTTPS),
        if it wasn't already collected during the scan.

        This is a single TLS handshake, which doesn't log in or send any
        HTTP requests. If the RTAC only supports TLS 1.0 or 1.1, a second
        handshake is done with a legacy TLS context.

        Returns:
            If the RTAC's certificate was collected (now or during the scan)
        """
        if dev.x509.original:
            cls.log.debug(f"Already have the TLS certificate of {dev.ip}, skipping")
            # The RTAC monitor clears dev.extra between pulls,
            # keep the certificate summary in each pull.
            if "ssl_certificate" not in dev.extra and dev._cache.get("ssl_certificate"):
                dev.extra["ssl_certificate"] = deepcopy(dev._cache["ssl_certificate"])
            return True

        port = dev.options["https"]["port"]
        timeout = dev.options["https"]["timeout"]
        cls.log.info(f"Getting the TLS certificate of the web server on {dev.ip}:{port}")

        peer = fetch_peer_certificate(dev.ip, port, timeout)
        if not peer:
            cls.log.warning(f"Failed to get the TLS certificate from {dev.ip}:{port}")
            return False

        return cls._process_ssl_certificate(dev, peer, port) is not None

    @classmethod
    def _process_ssl_certificate(
        cls,
        dev: DeviceData,
        peer: PeerCertificate,
        port: int,
        parsed: ParsedCertificate | None = None,
    ) -> ParsedCertificate | None:
        """
        Add the TLS certificate of the RTAC's web server to the device data.

        - The certificate is merged into ``dev.x509`` (``X509.hash`` is the hash
          of the PEM text, as it always has been).
        - The DER fingerprints, the TLS session parameters and the results of
          the checks (factory-default certificate, self-signed, expired,
          days remaining) are saved in ``dev.extra["ssl_certificate"]``.
        - The DER SHA-256 fingerprint and TLS version are added to the
          ``extra`` of the HTTPS :class:`~peat.data.models.Service`.
        - The model is set from a Common Name like ``SEL-3530-4 RTAC``
          (the model ``3530-4``), if the model is unknown or less specific.
        - The certificate is saved to ``ssl-certificate.pem``.

        Everything that's parsed or checked is done before the device data is
        changed, so a bad certificate doesn't leave the device half-updated.

        Returns:
            The parsed certificate, or :obj:`None` if it couldn't be parsed
        """
        if parsed is None:
            try:
                parsed = parse_der_certificate(peer.der)
            except ValueError as ex:
                cls.log.warning(f"Failed to parse the TLS certificate from {dev.ip}:{port}: {ex}")
                return None

        cert = parsed.x509
        common_name = cert.subject.common_name or cert.issuer.common_name

        summary = {
            "port": port,
            "tls_version": peer.tls_version,
            "cipher": peer.cipher,
            "legacy_tls": peer.legacy,
            "fingerprints": dict(parsed.fingerprints),
            "self_signed": parsed.self_signed,
            "ca": parsed.ca,
            "default_sel_certificate": cls._is_default_certificate(parsed),
            "parser": parsed.parser,
            **validity_status(cert),
        }

        # The rest of the chain, if the server sent one (Python 3.13+)
        chain_pem = ""
        if len(peer.chain) > 1:
            summary["chain"] = cls._summarize_chain(peer.chain)
            chain_pem = "".join(ssl.DER_cert_to_PEM_cert(der) for der in peer.chain)

        if parsed.parser != "cryptography":
            cls.log.warning(
                f"The TLS certificate from {dev.ip}:{port} isn't a valid DER certificate, "
                f"only some of its fields were parsed (with {parsed.parser})"
            )

        if dev.x509.original and dev.x509.original != cert.original:
            cls.log.warning(
                f"The TLS certificate from {dev.ip}:{port} is different from "
                f"the certificate that was collected before, replacing it"
            )
            dev.x509 = X509()
        merge_models(dev.x509, cert)
        dev.x509.annotate(dev)

        # The DER fingerprints are what other tools show and search for
        for fingerprint in parsed.fingerprints.values():
            dev.related.hash.add(fingerprint)

        model_match = cls._cert_cn_regex.match(common_name)
        if model_match:
            model = model_match.group("model")
            current_model = dev.description.model
            # Use a more specific model, e.g. "3530-4" instead of "3530"
            if not current_model or (model != current_model and model.startswith(current_model)):
                dev.description.model = model
            elif model != current_model:
                cls.log.debug(
                    f"Model '{model}' in the TLS certificate of {dev.ip} is "
                    f"different from the model '{current_model}', keeping '{current_model}'"
                )

        if summary["default_sel_certificate"]:
            cls.log.info(
                f"{dev.ip} uses the factory-default self-signed TLS "
                f"certificate of the RTAC ('{common_name}')"
            )
        if summary["expired"]:
            cls.log.warning(f"The TLS certificate of {dev.ip} expired on {cert.not_after}")
        elif summary["not_yet_valid"]:
            cls.log.warning(f"The TLS certificate of {dev.ip} isn't valid until {cert.not_before}")

        cls._write_and_record_file(
            dev,
            cert.original,
            "ssl-certificate.pem",
            source="tls_certificate",
            transport="tls",
            description=f"TLS certificate of the web server (port {port})",
        )

        if chain_pem:
            cls._write_and_record_file(
                dev,
                chain_pem,
                "ssl-certificate-chain.pem",
                source="tls_certificate",
                transport="tls",
                description=f"TLS certificate chain of the web server (port {port})",
            )

        dev.extra["ssl_certificate"] = summary
        dev._cache["ssl_certificate"] = deepcopy(summary)

        service = Service(
            port=port,
            protocol="https",
            transport="tcp",
            status="verified",
            extra={
                "tls_version": peer.tls_version,
                "tls_cipher": peer.cipher,
                "tls_legacy": peer.legacy,
                "certificate_sha256": parsed.fingerprints["sha256"],
            },
        )
        if parsed.fingerprints.get("spki_sha256"):
            service.extra["certificate_spki_sha256"] = parsed.fingerprints["spki_sha256"]
        dev.store("service", service, interface_lookup={"ip": dev.ip})

        return parsed

    @classmethod
    def _is_default_certificate(cls, parsed: ParsedCertificate) -> bool:
        """
        If a certificate looks like the factory-default certificate of an
        RTAC web server: self-signed, issued to SEL, with a Common Name
        like ``SEL-3530-4 RTAC``.
        """
        subject = parsed.x509.subject
        return bool(
            parsed.self_signed
            and subject.organization == cls._default_cert_organization
            and subject.organizational_unit == cls._default_cert_unit
            and cls._cert_cn_regex.fullmatch(subject.common_name)
        )

    @classmethod
    def _summarize_chain(cls, chain: list[bytes]) -> list[dict]:
        """
        Subject, issuer and DER SHA-256 fingerprint of each certificate in a
        chain. Only the fingerprint is listed for a certificate that can't be parsed.
        """
        summary = []
        for der in chain:
            try:
                parsed = parse_der_certificate(der)
            except Exception as ex:  # Anything in the chain that isn't the leaf certificate
                cls.log.debug(f"Failed to parse a certificate in the TLS certificate chain: {ex}")
                summary.append({"sha256": utils.calc_hash(der, "sha256")})
                continue
            summary.append(
                {
                    "subject": parsed.x509.subject.distinguished_name,
                    "issuer": parsed.x509.issuer.distinguished_name,
                    "sha256": parsed.fingerprints["sha256"],
                }
            )
        return summary

    @classmethod
    def _verify_postgres(cls, dev: DeviceData) -> bool:
        """
        Verify a device is a SEL RTAC via a PostgreSQL database connection.
        """
        # TODO: cache the connection in dev._cache
        conn = None
        curs = None
        try:
            # If we have a working password from logging in web
            try:
                user = dev.options["postgres"]["user"]
                if not user:
                    user = dev._cache.get("verified_pg_user")
                if not user:
                    user = "postgres"
                kwargs = {
                    "host": dev.ip,
                    "port": dev.options["postgres"]["port"],
                    "dbname": RTAC_DB_NAME,
                    "user": user,
                }
                if dev.options["postgres"]["pass"]:
                    kwargs["password"] = dev.options["postgres"]["pass"]
                elif dev._cache.get("verified_pg_pass"):
                    kwargs["password"] = dev._cache["verified_pg_pass"]
                conn = psycopg2.connect(**kwargs)
                curs = conn.cursor()
            except BaseException:  # Always cleanup regardless of error
                if conn is not None:
                    conn.close()
                return False

            # No valid logged in session created
            if conn is None:
                return False

            dev._cache["verified_pg_user"] = kwargs["user"]
            dev.related.user.add(kwargs["user"])
            if "password" in kwargs:
                dev._cache["verified_pg_pass"] = kwargs["password"]

            cmd = "SELECT * from device_info;"
            curs.execute(cmd)
            conn.commit()

            # if no columns in table continue
            if curs.description is None:
                curs.close()
                conn.close()
                return False

            data = curs.fetchall()
            cols = [desc[0] for desc in curs.description]
            for datum in data:
                for col_idx in range(len(cols)):
                    if "3530" in datum[col_idx]:
                        curs.close()
                        conn.close()
                        return True
            curs.close()
            conn.close()
        except Exception:
            cls.log.exception("CLEANED UP")
            if curs is not None:
                curs.close()
            if conn is not None:
                conn.close()
        return False

    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:
        # Ensure postgres cursor and connection is properly cleaned up on exit
        # TODO: better way of ensuring postgres connections are cleaned up
        def _ensure_close_db():
            for k in ["pg_cursor", "pg_conn"]:
                if dev._cache.get(k):
                    try:
                        dev._cache[k].close()
                    except Exception:
                        pass

        exit_handler.register(_ensure_close_db, "CONNECTION")

        # Pull and compare history over time
        if dev.options["sel"]["rtac_monitor_enable"]:
            pull_count = dev.options["sel"]["rtac_monitor_count"]
            pause_time = dev.options["sel"]["rtac_monitor_pause_for"]
            cls.log.info(
                f"Pulling {pull_count} times with a pause for "
                f"{pause_time:.2f} seconds between each pull"
            )
            dev._cache["history"] = {}

            for i in range(2, pull_count):
                try:
                    cls.log.info("Pulling config")
                    cls.log.info(f"\tRecording history {i}")
                    cls.update_history(dev)
                    sleep(dev.options["sel"]["rtac_monitor_pause_for"])
                    cls.log.info("\tChecking history")
                    cls.check_history(dev)
                except Exception:
                    cls.log.exception(f"failed history check of {dev.ip}")
                    return False

            return True

        # Regular pull and return
        cls.pull_config(dev)
        return True

    # --------- Monitor Functionality ---------
    @classmethod
    def chk_transient_path(cls, path: list[str]) -> bool:
        """Check if path is defined in transient keys."""
        for key in RTAC_TRANSIENT_KEYS:
            i = 0
            # if lengths do not match, proceed
            if not len(key) == len(path):
                continue

            # assume match is true, until proven otherwise
            match = True
            # iterate over whitelist keys to compare
            for pattern in key:
                if re.match(pattern, path[i]) is None:
                    match = False
                    break
                i += 1
            if match is True:
                return True
        return False

    @classmethod
    def compare_dictionaries(
        cls,
        dict_1: dict,
        dict_2: dict,
        dict_1_name: str,
        dict_2_name: str,
        path: list[str] | None = None,
        err: list[str] | None = None,
        key_err: list[str] | None = None,
        value_err: list[str] | None = None,
    ) -> tuple[list[str], list[str], list[str]]:
        if err is None:
            err = []
        if key_err is None:
            key_err = []
        if value_err is None:
            value_err = []

        for k1, v1 in dict_1.items():
            if path is None:
                old_path = []
            else:
                old_path = path[:]
            old_path.append(f"{k1}")
            # Check if test path in transient keys
            if cls.chk_transient_path(old_path):
                continue
            if k1 not in dict_2:
                key_err.append(f"Key {dict_2_name}{old_path} not in {dict_2_name}\n")
            elif isinstance(v1, dict) and isinstance(dict_2[k1], dict):
                cls.compare_dictionaries(
                    v1, dict_2[k1], "d1", "d2", old_path[:], err, key_err, value_err
                )
            elif v1 != dict_2[k1]:
                value_err.append(
                    f"Value of {dict_1_name}{old_path} ({v1}) not same "
                    f"as {dict_2_name}{old_path} ({dict_2[k1]})\n"
                )

        for k in dict_2.keys():
            if path is None:
                old_path = []
            else:
                old_path = path[:]
            old_path.append(f"{k}")
            if k not in dict_1:
                key_err.append(f"Key {dict_2_name}{old_path} not in {dict_1_name}\n")

        return key_err, value_err, err

    @classmethod
    def update_history(cls, dev: DeviceData) -> None:
        cls.pull_config(dev)
        timestamp = utils.utc_now().strftime("%Y-%m-%dT%H:%M:%S")
        dev._cache["history"][timestamp] = deepcopy(dev.extra)
        dev.extra = {}

    @classmethod
    def check_history(cls, dev: DeviceData) -> None:
        if len(dev._cache["history"].keys()) < 2:
            cls.log.info("baselined.")
            return
        d1_name: str = list(dev._cache["history"].keys())[-1]
        d2_name: str = list(dev._cache["history"].keys())[-2]
        d1 = dev._cache["history"][d1_name]
        d2 = dev._cache["history"][d2_name]
        cls.log.info(f"Comparing dictionaries '{d1_name}' and '{d2_name}'")
        res1 = cls.compare_dictionaries(d1, d2, "d1", "d2")
        res2 = ([], [], [])
        if (res1[0] == [] and res1[1] == [] and res1[2] == []) and (
            res2[0] == [] and res2[1] == [] and res2[2] == []
        ):
            cls.log.info("nominal")
        else:
            cls.log.error("abnominal")
            if state.elastic:
                # update action to key that is changed
                state.elastic.push(
                    "alerts",
                    {
                        "message": "device configuration changed",
                        "event": {
                            "action": "config-change",
                            "category": "device-config-change",
                            "kind": {"alert"},
                            "module": cls.__name__,  # "SELRTAC"
                            "severity": 10,
                        },
                    },
                )

    @classmethod
    def pull_config(cls, dev: DeviceData) -> None:
        """Pull and parse configuration from an RTAC."""
        # NOTE: this method is used by update_history() and _pull()
        # NOTE: if web pull fails, attempt postgres pull anyway to make sure we get data
        if dev.options["sel"]["pull_ssl_cert"]:
            try:
                cls.pull_ssl_certificate(dev)
            except Exception:
                cls.log.exception(f"failed to get the TLS certificate from {dev.ip}")
                state.error = True
        else:
            cls.log.debug(f"Skipping TLS certificate pull from {dev.ip} (sel.pull_ssl_cert=False)")

        web_exception = None
        if dev.options["sel"]["pull_http"]:
            try:
                cls.pull_web(dev)
                cls.update_dev(dev)
            except Exception as ex:
                cls.log.exception(f"failed http pull from {dev.ip}")
                state.error = True
                web_exception = ex
        else:
            cls.log.warning(f"Skipping HTTP pull from {dev.ip} (sel.pull_http=False)")

        if dev.options["sel"]["pull_postgres"]:
            cls.pull_postgres(dev)
            cls.update_dev(dev)
        else:
            cls.log.warning(f"Skipping postgres pull from {dev.ip} (sel.pull_postgres=False)")

        # Opt-in: TLS certificates and SSH host keys of the engineering access
        # ports that were found in the configuration (by pull_postgres)
        if dev.options["sel"]["rtac_probe_tunnel_ports"]:
            try:
                cls.probe_tunnel_ports(dev)
            except Exception:
                cls.log.exception(f"failed to probe the engineering access ports of {dev.ip}")
                state.error = True

        # NOTE: exceptions are handled by pull_api, it doesn't check method
        # return status at the moment, so we re-raise web exception here.
        if web_exception:
            raise web_exception from None

    @classmethod
    def pull_web(cls, dev: DeviceData, protocol: str | None = None) -> dict | None:
        cls.log.info(f"Pulling RTAC data via web interface from {dev.ip}")

        if not protocol:
            protocol = dev._cache.get("web_protocol", "http")

        if not dev._cache.get("web_protocol"):
            dev._cache["web_protocol"] = protocol

        port = dev.options[protocol]["port"]
        timeout = dev.options[protocol]["timeout"]

        if not dev._cache.get("web_session"):
            cls.log.info(f"No web session cached for {dev.ip}, creating new session...")
            dev._cache["web_session"] = SELHTTP(dev.ip, port, timeout)

        session = dev._cache["web_session"]
        if not session.rtac_logged_in:
            # Credentials that worked during the scan, or the ones the user configured.
            # NOTE: RTACs don't have default credentials (the first user is
            # created by the operator), so PEAT doesn't guess any here.
            username = dev._cache.get("verified_web_user")
            if not username:
                username = dev.options["web"]["user"]
            password = dev._cache.get("verified_web_pass")
            if not password:
                password = dev.options["web"]["pass"]
            if not username or not password:
                cls.log.error(
                    f"No web credentials for {dev.ip}, skipping the web pull. Set the "
                    f"'web.user' and 'web.pass' options, or scan the RTAC first to try "
                    f"the 'web.users' and 'web.passwords' options."
                )
                return None
            if not session.login_rtac(username, password, protocol):
                cls.log.error(
                    f"Failed to login to web interface on {dev.ip} with user '{username}'"
                )
                return None
            dev.related.user.add(username)

        web_methods = [
            session.view_dashboard,
            session.view_usagepolicy,
            session.view_filesondevice,
            session.view_features,  # TODO: not working currently
            session.view_accounts,  # NOTE: added to pull
            session.view_user_roles,
            session.view_ldap,
            session.download_http_files,
            session.view_ip_tables,  # TODO: not implemented yet
            session.view_syslog,  # this is slowest, do last
        ]

        cls.log.info(
            f"Completed web session setup, beginning pull from "
            f"{dev.ip}:{port} using {len(web_methods)} web methods"
        )

        pulled_config = {}
        dev._cache["num_successful_methods"] = 0

        # Files from the RTAC's file repository are captured, so they can be hashed
        with _capture_downloads(session, cls._web_download_pages) as downloads:
            for method in web_methods:
                sleep(0.3)  # attempt to avoid overloading web server

                cls.log.info(f"Running '{method.__name__}' for {dev.ip}:{port}")
                try:
                    method_result = method(dev)  # type: dict

                    if not method_result or not any(bool(val) for val in method_result.values()):
                        cls.log.warning(
                            f"No data from HTTP method '{method.__name__}' on {dev.ip}:{port}"
                        )
                    else:
                        pulled_config.update(method_result)
                        dev._cache["num_successful_methods"] += 1
                except Exception:
                    cls.log.exception(f"'{method.__name__}' failed on {dev.ip}:{port}")
                    continue

        cls._record_web_downloads(dev, downloads, protocol)

        if dev._cache["num_successful_methods"] == 0:
            dev._cache["web_session"].disconnect()
            raise DeviceError(f"all web methods failed from {dev.ip}")

        cls.log.info(
            f"Finished pulling data via web interface from {dev.ip}:{port} "
            f"({dev._cache['num_successful_methods']} methods were "
            f"successful out of {len(web_methods)} methods attempted)"
        )

        cls._write_and_record_file(
            dev,
            pulled_config,
            "pulled-web-config.json",
            source="derived",
            description="Data PEAT collected from the RTAC web interface",
        )

        # Close the web session
        dev._cache["web_session"].disconnect()

        # Remove fields we don't want in elasticsearch
        for bad_field in ["web_syslog_events", "web_usagepolicy", "web_device_info"]:
            pulled_config.pop(bad_field, None)

        return pulled_config

    @classmethod
    def pull_postgres(cls, dev: DeviceData) -> dict | None:
        cls.log.info(f"Pulling postgres data from {dev.ip}")

        if not dev._cache.get("pg_conn"):  # TODO: check if connected
            username = dev._cache.get("verified_pg_user")
            if not username:
                username = dev.options["postgres"]["user"]
            if not username:
                username = "postgres"
            dev.related.user.add(username)
            password = dev._cache.get("verified_pg_pass")
            if not password:
                password = dev.options["postgres"]["pass"]

            dev._cache["pg_conn"] = psycopg2.connect(
                host=dev.ip,
                dbname=RTAC_DB_NAME,
                user=username,
                password=password,
                port=dev.options["postgres"]["port"],
            )
            # TODO: check if login succeeded, if not return None

        conn = dev._cache["pg_conn"]
        if not dev._cache.get("pg_cursor"):  # TODO: check if connected
            dev._cache["pg_cursor"] = conn.cursor()
        cursor = dev._cache["pg_cursor"]

        config = {}
        # Every row of the tables with engineering access settings. In "config",
        # rows are keyed by their first column, so rows with the same value in
        # the first column overwrite each other.
        engineering_tables: dict[str, list[dict]] = {}

        for table in RTAC_DB_TABLES:
            config[table] = {}
            command = f"SELECT * from {table};"
            cls.execute(cursor, command)
            conn.commit()

            # if no columns in table continue
            if cursor.description is None:
                continue
            data = cursor.fetchall()
            cols = [desc[0] for desc in cursor.description]
            for datum in data:
                config[table][datum[0]] = {}
                if table in PG_TABLES:
                    engineering_tables.setdefault(table, []).append(config[table][datum[0]])
                for col_idx in range(len(cols)):
                    # do conversions based on column label
                    if cols[col_idx] == "data" or cols[col_idx] == "project_image":
                        # if binary blob, hash binary blob
                        if datum[col_idx] is None:
                            config[table][datum[0]][cols[col_idx]] = ""
                            continue
                        # TODO: should we save hash in one place and raw in another?
                        decoded = (base64.b64encode(datum[col_idx].tobytes())).decode()
                        config[table][datum[0]][cols[col_idx]] = decoded
                    elif cols[col_idx] in [
                        "set_dst_start_time",
                        "set_dst_stop_time",
                        "set_system_time_dst_start_time",
                        "set_system_time_dst_stop_time",
                        "last_access",
                        "account_creation",
                        "last_modified_time",
                    ]:
                        # if datetime object, convert to string
                        # TODO: use utils.parse_date().isoformat()
                        # to generate ISO-format time string.
                        config[table][datum[0]][cols[col_idx]] = str(datum[col_idx])
                    elif cols[col_idx] == "new_event_reset_location_value":
                        # if floating point object, and NaN, then convert to -999999
                        val = datum[col_idx]
                        if not math.isfinite(datum[col_idx]):
                            val = float(-999999999)
                        config[table][datum[0]][cols[col_idx]] = val
                    else:
                        config[table][datum[0]][cols[col_idx]] = datum[col_idx]

        # TODO: compare device data with what's pulled from web and emit warning if it differs
        #  e.g. firmware rev, checksums, etc.
        dev_info = config.get("device_info")
        if dev_info:
            if len(dev_info) > 1:
                cls.log.warning(
                    f"Multiple devices found in PostgreSQL data "
                    f"in 'device_info' from {dev.ip}: {dev_info}"
                )

            first = next(iter(dev_info.values()))

            host_name = first.get("host_name")
            if host_name and not dev.hostname:
                dev.hostname = host_name
            dev.related.hosts.add(host_name)

            dev_name = first.get("device_name")
            if dev_name and not dev.name:
                dev.name = dev_name
            dev.related.hosts.add(dev_name)

            location = first.get("location")  # TODO: is this lat/lon?
            if location and not dev.geo.name:
                dev.geo.name = location

            dev.extra["postgres_device_info"] = dev_info
            fw_checksum = first.get("current_fw_checksum")
            if fw_checksum:
                if not dev.firmware.checksum:
                    dev.firmware.checksum = fw_checksum
                # This may or may not be an actual hash, and in some
                # cases it's definitely not, e.g. "B0AB".
                try:
                    checksum_hash = validate_hash(fw_checksum)
                    dev.related.hash.add(checksum_hash)
                    if not dev.firmware.hash.md5 and len(fw_checksum) == 32:
                        dev.firmware.hash.md5 = checksum_hash
                except ValueError:
                    pass
            desc = first.get("description")
            if desc and not dev.description.description:
                dev.description.description = desc
            fw_rev = first.get("fw_release_version")
            if fw_rev and not dev.firmware.revision:
                dev.firmware.revision = fw_rev

        projects = config.get("projects", {})
        if projects:
            if len(projects) > 1:
                cls.log.warning(
                    f"{len(projects)} projects on {dev.ip}, using "
                    f"metadata from first one to populate "
                    f"fields for 'host.logic'"
                )

            projs = list(projects.values())
            if not projs:
                cls.log.error(f"Failed to get a project for {dev.ip}")
                state.error = True
            else:
                proj = projs[0]
                dev.logic.name = proj["project_name"]
                dev.logic.description = proj["description"]
                dev.related.user.add(proj["last_modified_user"])
                if not dev.logic.author:
                    dev.logic.author = proj["last_modified_user"]
                dev.logic.last_updated = utils.parse_date(proj["last_modified_time"])

        # Add device names from "remote_devices"
        # TODO: models
        # "32": {
        #     "remote_device_id": 32,
        #     "project_id": 1,
        #     "name": "SEL_411L_E1",
        #     "model": "411L",
        #     "version_hash": null,
        #     "manufacturer": null,
        #     "version": null
        # },
        remote_devices = config.get("remote_devices", {})
        for rem_dev in remote_devices.values():
            # Engineering access objects (tunnels), e.g "Eng_Access_40", aren't
            # hosts. Their names are recorded by _process_engineering_access().
            name = rem_dev.get("name")
            if name and "Eng_Access_" not in str(name):
                dev.related.hosts.add(name)

        # "role_master" and "system_roles" have almost the same format
        for role_key in ["role_master", "system_roles"]:
            # TODO: system_roles has a "unix_home_dir" value, useful?
            role_dict = config.get(role_key)
            if role_dict:
                for rv in role_dict.values():
                    # Note: db_name usually matches name, and
                    # lc_name is lowercase version of name.
                    for key in ["name", "lc_name", "db_name"]:
                        if rv.get(key):
                            dev.related.roles.add(rv[key])

        root_devices = config.get("root_devices")
        if root_devices:
            for rd in root_devices.values():
                if rd.get("name"):
                    dev.related.hosts.add(rd["name"])

        # TODO:
        #   role_master
        #   role_membership
        #   system_permissions
        #   system_role_resource_assoc
        #   system_roles
        #   user_lockouts
        #   user_membership

        users = config.get("users", {})
        for user_dict in users.values():
            user = User()

            # Values could be null, so gotta check
            if user_dict.get("description"):
                user.description = user_dict["description"]
            if user_dict.get("username"):
                user.name = user_dict["username"]

            for extra_key in [
                "user_id",
                "status",
                "account_creation",
                "last_access",
                "account_expiration",
                "auto_login",
            ]:
                if user_dict.get(extra_key) is not None:
                    user.extra[extra_key] = str(user_dict[extra_key])

            dev.store("users", user, lookup="name")

        users_transient_history = config.get("users_transient_history", {})
        for user_dict in users_transient_history.values():
            dev.related.user.add(user_dict.get("username", ""))

        serial_ports = config.get("serial_ports", {})  # type: dict
        for sp in serial_ports.values():
            extra = {}

            for m_key in [
                "connection_method_id",
                "protocol_id",
                "serial_port_type_id",
            ]:
                if sp.get(m_key):
                    extra[m_key] = str(sp[m_key])

            if "full_duplex" in sp:
                extra["full_duplex"] = bool(sp["full_duplex"])

            flow_control = ""  # "none"
            for fc_key in ["hardware_flow_control", "software_flow_control"]:
                if sp.get(fc_key):
                    flow_control = fc_key

            s_type = "serial"
            s_port_id = str(sp.get("serial_port_type_id", ""))
            if s_port_id == "232":
                s_type = "rs-232"

            iface = Interface(
                connected=bool(sp.get("port_power")),
                name=str(sp.get("device_file", "")),
                type=s_type,
                id=str(sp.get("serial_port_id", "")),
                serial_port=str(sp.get("device_file", "")),
                baudrate=int(sp.get("baud_rate")) if "baud_rate" in sp else None,
                data_bits=int(sp.get("data_bits")) if "data_bits" in sp else None,
                # TODO: determine parity value
                stop_bits=int(sp.get("stop_bit")) if "stop_bit" in sp else None,
                flow_control=flow_control,
                extra=extra,
            )

            dev.store("interface", iface, lookup="serial_port")

        for conn_group_name in [
            "local_tcp_network_port_connections",
            "local_udp_network_port_connections",
        ]:
            conn_group = config.get(conn_group_name, {})  # type: dict
            for conn_value in conn_group.values():
                for port_key in ["tcp_port", "udp_port"]:
                    if conn_value.get(port_key):
                        dev.related.ports.add(int(conn_value[port_key]))

        # If protocol_id isn't null, it may be of interest
        for port_group_name in [
            "local_tcp_network_ports",
            "local_udp_network_ports",
        ]:
            port_group = config.get(port_group_name, {})  # type: dict
            for port_values in port_group.values():
                if port_values.get("protocol_id") and port_values.get("port_number"):
                    dev.related.ports.add(int(port_values["port_number"]))

        # Pull some useful info out of various setting groups
        for eth_group_name in [
            "dnp_client_ethernet_settings",
            "dnp_client_unique_settings",
            "sel_client_ethernet_settings",
            # NOTE: this section is untested
            "modbus_ethernet_settings",
        ]:
            dnp_group = config.get(eth_group_name, {})  # type: dict
            for eth_settings in dnp_group.values():
                if eth_settings.get("server_ip_address"):
                    dev.related.ip.add(eth_settings["server_ip_address"])

                for port_key in [
                    "server_ip_port",
                    "local_tcp_port",
                    "local_udp_port",
                    "client_udp_port",
                ]:
                    if eth_settings.get(port_key):
                        dev.related.ports.add(int(eth_settings[port_key]))

                # This only appears in dnp_client_ethernet_settings
                if eth_settings.get("ssh_username"):
                    dev.related.user.add(eth_settings["ssh_username"])

        # Access points, access point routers and SEL servers (engineering access)
        try:
            cls._process_engineering_access(dev, discover_from_postgres(engineering_tables))
        except Exception:
            cls.log.exception(f"Failed to process the engineering access settings of {dev.ip}")

        # config is large and leads to excessive-sized device-data-summary.json

        # Can't save as JSON, too large and has some data types that are not human-reader friendly
        cls._write_and_record_file(
            dev,
            config,
            "raw-pulled-postgres-config.txt",
            source="command_output",
            transport="postgres",
            description="Tables PEAT read from the RTAC PostgreSQL database",
        )
        del config["tag_task_settings"]
        del config["tags"]
        cls._write_and_record_file(
            dev,
            config,
            "pulled-postgres-config.json",
            source="command_output",
            transport="postgres",
            description="Tables PEAT read from the RTAC PostgreSQL database (without tags)",
        )

        cursor.close()  # TODO: set cache to None?
        conn.close()  # TODO: set cache to None?

        cls.log.debug(f"Finished pulling postgres data from {dev.ip}")
        return config

    @classmethod
    def execute(cls, cursor, statement: str, args: tuple | None = None) -> None:
        """Wrapper code for database execute."""
        if args is None:
            args = ()
        while True:  # TODO: change to better method than while loop
            try:
                cursor.execute(statement, args)
            except Exception as e:
                # if the db is locked, try again
                cls.log.trace2(f"Postgres operational error: {e}")
                sleep(0.1)
            # break out when successful
            break

    # --------- Engineering access ---------
    # Protocol of the service for each tunnel transport. Raw TCP and UDP ports
    # don't have a protocol of their own (only the "transport").
    _tunnel_service_protocols = {"telnet": "telnet", "ssh": "ssh", "tls": "tls"}

    @classmethod
    def _process_engineering_access(cls, dev: DeviceData, discovery: Discovery) -> list[dict]:
        """
        Add the engineering access paths found in the RTAC's configuration (by
        :func:`~peat.modules.sel.rtac_engineering_access.discover_from_export`
        or :func:`~peat.modules.sel.rtac_engineering_access.discover_from_postgres`)
        to the device data. Refer to :ref:`sel-rtac-engineering-access`.

        - ``extra.engineering_access``: one entry for each device that's
          reachable through an access point or SEL server of the RTAC (refer to
          :meth:`Listener.entries()
          <peat.modules.sel.rtac_engineering_access.Listener.entries>`).
          Entries that are already there (e.g. from the other source) are kept.
        - ``extra.engineering_access_devices``: names of the RTAC's
          engineering access objects, e.g. ``Eng_Access_40``.
        - A :class:`~peat.data.models.Service` for each port of an access
          point or SEL server, which also adds the port to ``related.ports``.

        Returns:
            The new ``extra.engineering_access`` entries
        """
        for warning in discovery.warnings:
            cls.log.warning(warning)
        for note in discovery.notes:
            cls.log.debug(note)

        entries = discovery.entries(dev.ip if dev.ip else None)
        existing = dev.extra.get("engineering_access")
        if not isinstance(existing, list):
            existing = []
        if entries or existing:
            dev.extra["engineering_access"] = merge_entries(existing, entries)

        if discovery.engineering_access_devices:
            names = dev.extra.get("engineering_access_devices")
            if not isinstance(names, list):
                names = []
            dev.extra["engineering_access_devices"] = sorted(
                set(names) | set(discovery.engineering_access_devices)
            )
            cls.log.debug(
                f"Engineering access objects in the configuration of {dev.ip}: "
                f"{', '.join(discovery.engineering_access_devices)}"
            )

        for listener in discovery.listeners:
            cls._store_engineering_access_service(dev, listener)

        if entries:
            direct = sum(entry["route"] == "direct" for entry in entries)
            cls.log.info(
                f"Found {len(entries)} engineering access paths to devices behind the RTAC "
                f"{dev.ip} in its configuration ({len(discovery.listeners)} access points "
                f"and SEL servers, {direct} paths are direct transparent connections, which "
                f"stop the RTAC's polling of the device while they're open)"
            )

        return entries

    @classmethod
    def _store_engineering_access_service(cls, dev: DeviceData, listener: Listener) -> None:
        """
        Add a :class:`~peat.data.models.Service` for the port of an access point
        or SEL server. The ``role`` is ``engineering_access`` if it reaches any
        devices, otherwise the kind of listener (``access_point`` or ``sel_server``).
        """
        if not listener.port:
            return

        if listener.transport == "udp":
            transport = "udp"
        elif listener.transport:
            transport = "tcp"
        else:
            transport = ""

        extra = {
            "name": listener.name,
            "kind": listener.kind,
            "connection_type": listener.connection_type,
            "tunnel_transport": listener.transport,
            "needs_rtac_login": listener.needs_rtac_login,
            "termination_string": listener.termination_string,
            "source": listener.source,
            **listener.settings,
        }
        # The devices of a SEL server are all of the SEL devices, so they're
        # only listed if the SEL server reaches them
        if listener.destinations and (listener.kind != "sel_server" or listener.gives_access):
            extra["destinations"] = [dest.summary() for dest in listener.destinations]

        service = Service(
            port=listener.port,
            configured_port=listener.port,
            protocol=cls._tunnel_service_protocols.get(listener.transport or "", ""),
            transport=transport,
            role="engineering_access" if listener.gives_access else listener.kind,
            enabled=True,
            extra={k: v for k, v in extra.items() if v is not None and v != ""},
        )
        dev.store(
            "service",
            service,
            lookup={"port": listener.port, "transport": transport},
            interface_lookup={"ip": dev.ip} if dev.ip else None,
        )

    @classmethod
    def downstream_targets(cls, dev: DeviceData) -> list[dict]:
        """
        The devices that are reachable through this RTAC (the RTAC is a
        "gateway" to them): copies of the ``extra.engineering_access``
        entries that have an RTAC IP address and a TCP port, with one entry
        for each path (refer to
        :func:`~peat.modules.sel.rtac_engineering_access.unique_paths`), so a
        path that's in both a project export and the database is only once
        in the results.

        Modules that front other devices can implement this method, so code
        that pulls devices through a gateway can find them with
        ``getattr(module, "downstream_targets", None)``.

        .. warning::
           This includes ``direct`` routes, and routes that are not known
           (``None``), which may be direct. Opening a direct route stops the
           RTAC's polling of the device (and so the SCADA data from it) while
           the connection is open. Don't use them unless the user allows it.

        Returns:
            Dicts with the keys in
            :data:`~peat.modules.sel.rtac_engineering_access.ENGINEERING_ACCESS_KEYS`
        """
        entries = dev.extra.get("engineering_access")
        if not isinstance(entries, list):
            return []
        return unique_paths(
            entry
            for entry in entries
            if isinstance(entry, dict) and entry.get("rtac_ip") and entry.get("tcp_port")
        )

    @classmethod
    def probe_tunnel_ports(cls, dev: DeviceData) -> dict[str, dict]:
        """
        Get the TLS certificates and SSH host keys of the engineering access
        ports of the RTAC that use TLS or SSH (the ``sel.rtac_probe_tunnel_ports``
        option, off by default).

        Each port gets one TLS handshake (and one retry with a legacy TLS
        context if it fails), or one SSH key exchange. PEAT doesn't log in or
        send any data, so no tunnel to a device is opened, but the RTAC may
        log the connections. A port is only probed if all of its paths are
        SEL servers (which need the ``PORT`` command to reach a device) or
        ``interleaved`` (``_TAP``) routes. Ports with a direct route (``_AP``)
        or a route that isn't known are never probed, since an access point
        router may connect to the device as soon as a client connects, and on
        a direct route that stops the RTAC's polling of the device. Ports
        whose paths have different transports aren't probed either.

        The results are in ``extra.engineering_access_probes``, keyed by
        ``tcp/<port>``. TLS certificates are saved to
        ``engineering-access-tcp-<port>-certificate.pem`` and SSH host keys are
        added to ``ssh_keys``. The fingerprints are added to ``related.hash``
        and to the service of the port, which is marked as verified.

        Returns:
            The results of the ports that were probed, keyed by ``tcp/<port>``
        """
        paths: dict[int, list[dict]] = {}
        for entry in cls.downstream_targets(dev):
            if entry["rtac_ip"] == dev.ip:
                paths.setdefault(entry["tcp_port"], []).append(entry)
        # Only the ports that use TLS or SSH
        ports = {
            port: entries
            for port, entries in paths.items()
            if any(e.get("transport") in ("tls", "ssh") for e in entries)
        }

        if not ports:
            cls.log.debug(f"No TLS or SSH engineering access ports to probe on {dev.ip}")
            return {}

        results = dev.extra.get("engineering_access_probes")
        if not isinstance(results, dict):
            results = {}

        cls.log.info(
            f"Probing the TLS and SSH engineering access ports of {dev.ip} for their "
            f"certificates and host keys (the RTAC may log these connections)"
        )
        probed = {}
        for port, entries in sorted(ports.items()):
            transports = {e.get("transport") for e in entries}
            if len(transports) > 1:
                cls.log.info(
                    f"Not probing {dev.ip}:{port}, the RTAC configuration has different "
                    f"transports for it ({', '.join(sorted(map(str, transports)))})"
                )
                continue
            # Allow-list: SEL servers, and interleaved (_TAP) routes
            unsafe = {
                e.get("route")
                for e in entries
                if e.get("kind") != "sel_server" and e.get("route") != "interleaved"
            }
            if unsafe:
                reason = (
                    "it has a direct route to a device"
                    if "direct" in unsafe
                    else "the route of one of its paths isn't known (it may be direct)"
                )
                cls.log.info(
                    f"Not probing {dev.ip}:{port}, {reason} (connecting could stop "
                    f"the RTAC's polling of the device)"
                )
                continue

            if transports == {"tls"}:
                result = cls._probe_tls_port(dev, port)
            else:
                result = cls._probe_ssh_port(dev, port)
            if result:
                probed[f"tcp/{port}"] = result

        if probed:
            results.update(probed)
            dev.extra["engineering_access_probes"] = results
        return probed

    @classmethod
    def _probe_tls_port(cls, dev: DeviceData, port: int) -> dict | None:
        """Get and record the TLS certificate of an engineering access port."""
        peer = fetch_peer_certificate(dev.ip, port, dev.options["https"]["timeout"])
        if not peer:
            return None
        try:
            parsed = parse_der_certificate(peer.der)
        except ValueError as ex:
            cls.log.warning(f"Failed to parse the TLS certificate from {dev.ip}:{port}: {ex}")
            return None

        cert = parsed.x509
        web_cert = dev.extra.get("ssl_certificate")
        web_sha256 = None
        if isinstance(web_cert, dict) and isinstance(web_cert.get("fingerprints"), dict):
            web_sha256 = web_cert["fingerprints"].get("sha256")

        result = {
            "transport": "tls",
            "tls_version": peer.tls_version,
            "cipher": peer.cipher,
            "legacy_tls": peer.legacy,
            "subject": cert.subject.distinguished_name,
            "issuer": cert.issuer.distinguished_name,
            "not_after": cert.not_after.isoformat() if cert.not_after else None,
            "fingerprints": dict(parsed.fingerprints),
            "self_signed": parsed.self_signed,
            "default_sel_certificate": cls._is_default_certificate(parsed),
            # The TLS servers of the RTAC normally use the same certificate as the web server
            "same_as_web_certificate": (
                web_sha256 == parsed.fingerprints["sha256"] if web_sha256 else None
            ),
            **validity_status(cert),
        }

        for fingerprint in parsed.fingerprints.values():
            dev.related.hash.add(fingerprint)

        cls._write_and_record_file(
            dev,
            cert.original,
            f"engineering-access-tcp-{port}-certificate.pem",
            source="tls_certificate",
            transport="tls",
            description=f"TLS certificate of the engineering access port {port}",
        )

        service_extra = {
            "tls_version": peer.tls_version,
            "tls_cipher": peer.cipher,
            "tls_legacy": peer.legacy,
            "certificate_sha256": parsed.fingerprints["sha256"],
        }
        if parsed.fingerprints.get("spki_sha256"):
            service_extra["certificate_spki_sha256"] = parsed.fingerprints["spki_sha256"]
        dev.store(
            "service",
            Service(
                port=port, protocol="tls", transport="tcp", status="verified", extra=service_extra
            ),
            lookup={"port": port, "transport": "tcp"},
            interface_lookup={"ip": dev.ip} if dev.ip else None,
        )

        cls.log.info(
            f"Got the TLS certificate of the engineering access port {dev.ip}:{port} "
            f"('{cert.subject.common_name}', SHA-256 {parsed.fingerprints['sha256']})"
        )
        return result

    @classmethod
    def _probe_ssh_port(cls, dev: DeviceData, port: int) -> dict | None:
        """Get and record the SSH host key of an engineering access port."""
        host_key = fetch_ssh_host_key(dev.ip, port, dev.options["ssh"]["timeout"])
        if not host_key:
            return None

        dev.store(
            "ssh_keys",
            SSHKey(
                type="public",
                host=dev.ip,
                id=host_key.fingerprint,
                original=host_key.public_key,
                description=(
                    f"SSH host key ({host_key.key_type}, {host_key.bits} bits) "
                    f"of the engineering access port {port}"
                ),
            ),
            lookup="original",
        )
        dev.related.hash.add(host_key.md5)
        dev.related.hash.add(host_key.sha256)

        service_extra = {
            "host_key_type": host_key.key_type,
            "host_key_fingerprint": host_key.fingerprint,
        }
        if host_key.banner:
            service_extra["ssh_banner"] = host_key.banner
        dev.store(
            "service",
            Service(
                port=port, protocol="ssh", transport="tcp", status="verified", extra=service_extra
            ),
            lookup={"port": port, "transport": "tcp"},
            interface_lookup={"ip": dev.ip} if dev.ip else None,
        )

        cls.log.info(
            f"Got the SSH host key of the engineering access port {dev.ip}:{port} "
            f"({host_key.key_type}, {host_key.fingerprint})"
        )
        return {
            "transport": "ssh",
            "key_type": host_key.key_type,
            "bits": host_key.bits,
            "fingerprint": host_key.fingerprint,
            "md5": host_key.md5,
            "sha256": host_key.sha256,
            "banner": host_key.banner,
        }

    # --------- File hashing ---------
    # Page that sends the files in the RTAC's file repository (hashed by pull_web())
    _web_download_pages = ("/download.sel",)

    @classmethod
    def _record_file(
        cls,
        dev: DeviceData,
        data: bytes | _Digest,
        name: str,
        source: str,
        local_path: Path | None = None,
        path: str | None = None,
        transport: str = "",
        mtime: datetime | None = None,
        description: str = "",
        extra: dict | None = None,
    ) -> File:
        """
        Hash a file and add it to ``dev.files`` (the hashes are also added to
        ``dev.related.hash``). The hashes are of ``data``, so files are
        recorded even if device file output is disabled.

        Args:
            dev: Device the file is from
            data: Contents of the file, as they were received or written,
                or their :class:`_Digest` (so the contents don't need to be kept)
            name: Name of the file
            source: What the file is, saved in ``File.extra["source"]``:
                ``web_download`` (file from the web interface),
                ``command_output`` (database query results),
                ``tls_certificate`` (certificate from a TLS handshake),
                ``derived`` (file PEAT made from other data), or
                ``parse_input`` (file from a parsed project export)
            local_path: The file PEAT saved, if any. It must have the same
                contents as ``data``.
            path: Path of the file on the device or in a parsed archive
            transport: How the file was transferred, if it's from the
                device (``http``, ``https``, ``postgres``, ``tls``)
            mtime: Modification time of the file on the device or in the archive
            description: Human-readable description of the file
            extra: Additional values for ``File.extra``

        Returns:
            The :class:`~peat.data.models.File` that was added
        """
        file_extra: dict[str, Any] = {"source": source}
        if transport:
            file_extra["transport"] = transport
        if extra:
            file_extra.update(extra)

        digest = data if isinstance(data, _Digest) else _Digest.of(data)
        file_obj = File(
            name=name,
            size=digest.size,
            hash=Hash.parse_obj(digest.hashes),
            type="file",
            peat_module=cls.__name__,
            description=description,
            extra=file_extra,
        )
        if path:
            file_obj.path = PurePosixPath(path)
        if local_path:
            file_obj.local_path = local_path
        if mtime:
            file_obj.mtime = mtime

        # NOTE: store() with a lookup compares every file in dev.files, which
        # is slow for project exports with hundreds of files. Each file has
        # a different local path, so just append it.
        dev.store("files", file_obj, append=True)

        return file_obj

    @classmethod
    def _write_and_record_file(
        cls,
        dev: DeviceData,
        data: Any,
        filename: str,
        source: str,
        name: str = "",
        **kwargs,
    ) -> File:
        """
        Write data to a file in the device's output directory (like
        :meth:`~peat.data.models.DeviceData.write_file`), then hash and record
        it with :meth:`_record_file`.

        The recorded local path is the file that was actually written. If a
        file with the name already exists, the ``<name>.<num>`` name that
        :func:`peat.utils.write_file` would use is chosen before writing.
        Nothing is written if device file output is disabled, but the file
        is still hashed and recorded.

        Args:
            dev: Device the file is for
            data: Data to write. If ``filename`` ends in ``.json``, it's
                serialized to JSON, like :func:`peat.utils.write_file` does.
            filename: Name of the file, which may include sub-directories
            source: What the file is (refer to :meth:`_record_file`)
            name: Name to record. Defaults to the name of ``filename``.
            kwargs: Other arguments for :meth:`_record_file`

        Returns:
            The :class:`~peat.data.models.File` that was added
        """
        filename = consts.sanitize_filepath(filename)
        raw = _serialize(data, filename)
        digest = _Digest.of(raw)

        local_path = None
        if dev._out_dir or config.DEVICE_DIR:
            target = dev.get_out_dir() / filename
            if target.exists():
                target = utils.dup_path(target)
            # NOTE: write_file() serializes JSON itself, other data is written
            # as the bytes that were hashed (the same bytes write_file() writes).
            to_write = data if ".json" in target.suffixes else raw
            if utils.write_file(to_write, target):
                local_path = _matching_file([target], digest)
        else:
            cls.log.debug(f"Device file output is disabled, skipping write to file {filename}")

        return cls._record_file(
            dev,
            digest,
            name if name else PurePosixPath(filename).name,
            source,
            local_path=local_path,
            **kwargs,
        )

    @classmethod
    def _record_web_downloads(
        cls, dev: DeviceData, downloads: list[tuple[str, _Digest]], protocol: str
    ) -> None:
        """
        Record the files downloaded from the RTAC's file repository
        (``download.sel``) by :meth:`SELHTTP.download_http_files()
        <peat.modules.sel.sel_http.SELHTTP.download_http_files>`.

        Args:
            dev: The RTAC
            downloads: URL and :class:`_Digest` of each download, from
                :func:`_capture_downloads`
            protocol: ``http`` or ``https``

        The hashes are of the bytes the RTAC sent, and the modification
        time and size are from the file listing (``dev.extra["web_files"]``).
        """
        web_files = dev.extra.get("web_files")
        if not isinstance(web_files, dict):
            web_files = {}

        for response_url, digest in downloads:
            url = urlparse(response_url)
            filename = parse_qs(url.query).get("filename", [""])[0]
            if not url.path.endswith("/download.sel") or not filename:
                continue

            listing = web_files.get(filename)
            if not isinstance(listing, dict):
                listing = {}

            extra = {}
            if isinstance(listing.get("size"), int):
                extra["listed_size"] = listing["size"]
            mtime = listing.get("timestamp")

            cls._record_file(
                dev,
                digest,
                PurePosixPath(filename).name,
                "web_download",
                local_path=_find_written_file(dev, filename, digest),
                transport=protocol,
                mtime=mtime if isinstance(mtime, datetime) else None,
                description="File from the RTAC file repository",
                extra=extra,
            )

    @classmethod
    def parse_xml(cls, data: str, filename: str, device_info: dict) -> bool:
        """
        Parse one XML file from a RTAC project export into ``device_info``.

        Returns:
            If the file was a RTAC XML file with a known item type
        """
        xml_root = ET.fromstring(data)
        if xml_root.tag != "RTACModule" or not len(xml_root):
            cls.log.debug(f"Skipping non-RTAC XML file '{filename}' (root: '{xml_root.tag}')")
            return False

        tag = xml_root[0].tag

        # Keep track of the RTAC models and the export schema versions
        export_source = parse_export_source(xml_root[0])
        sources = device_info.setdefault("ExportSource", {"Schema": [], "DeviceMOT": []})
        for key, value in export_source.items():
            if value not in sources[key]:
                sources[key].append(value)

        if tag in cls._tag_to_parser_map:
            cls._tag_to_parser_map[tag](xml_root, device_info)
            return True

        if tag not in cls._ignored_tags:
            cls.log.debug(f"Skipping unknown XML file '{filename}' with tag '{tag}'")
        return False

    @classmethod
    def _parse_file(cls, data: bytes, name: str, dev: DeviceData, device_info: dict) -> None:
        """Parse a XML file, and log a error if the parse fails (instead of raising)."""
        try:
            # NOTE: all RTAC XML files must be read with encoding "utf-8-sig".
            # The RTAC editor saves some XML files as "UTF-8 with BOM" encoding.
            # The XML parser handles this fine on Linux, but for some reason it
            # isn't handled well on Windows. This is fixed by decoding the text
            # using the "utf-8-sig" encoding, which will skip the BOM if present.
            # Per the Python documentation:
            #   "On decoding utf-8-sig will skip those three bytes if they appear
            #   as the first three bytes in the file."
            # Ref: https://docs.python.org/3/library/codecs.html#encodings-and-unicode
            text = data.decode(encoding="utf-8-sig")
            if cls.parse_xml(text, name, device_info):
                dev.related.files.add(Path(name).name)
        except Exception as ex:
            cls.log.error(f"Failed to parse '{name}': {ex}")
            device_info.setdefault("parse_errors", []).append(name)

    @classmethod
    def _parse(cls, file: Path, dev: DeviceData | None = None) -> DeviceData:
        if not dev:
            dev = datastore.get(file.name.partition(".")[0], "id")

        device_info = {}

        # Possible inputs:
        # - directory of XML files (a project export)
        # - .tar.gz/.tar file containing XML files
        # - single XML file
        if file.is_dir():
            xml_files = [f for f in file.rglob("*") if f.is_file() and f.suffix.lower() == ".xml"]
            for xf in sorted(xml_files):
                cls._parse_file(xf.read_bytes(), xf.relative_to(file).as_posix(), dev, device_info)
        elif file.suffix.lower() == ".xml":
            cls._parse_file(file.read_bytes(), file.name, dev, device_info)
        elif tarfile.is_tarfile(file):
            device_info["existing_files"] = []
            # Mode "r" detects the compression (none, gzip, bz2, xz)
            with tarfile.open(name=file.as_posix(), mode="r", encoding="utf-8") as tar:
                for member in tar.getmembers():
                    if not member.isfile():  # skip directories and links
                        continue

                    member_path = Path(member.name)
                    if member_path.is_absolute() or ".." in member_path.parts:
                        cls.log.warning(f"Skipping unsafe path '{member.name}' in '{file.name}'")
                        continue

                    cls.log.debug(f"Parsing '{member.name}' from '{file.name}'")
                    f_handle = tar.extractfile(member)
                    if f_handle is None:
                        continue

                    data = f_handle.read()
                    device_info["existing_files"].append(member.name)
                    if member_path.suffix.lower() == ".xml":
                        cls._parse_file(data, member.name, dev, device_info)

                    # still save the data to file even if parsing failed
                    cls._write_and_record_file(
                        dev,
                        data,
                        f"extracted_files/{member.name}",
                        source="parse_input",
                        path=member.name,
                        mtime=_tar_member_mtime(member),
                        extra={"archive": file.name},
                    )
        else:
            raise DeviceError(f"Unknown type of file for SEL RTAC parsing: {file.name}")

        dev.extra.update(device_info)
        cls._process_export(dev, device_info)

        if not dev.description.model:
            cls.log.warning(
                "No RTAC model found in the project export, defaulting to '3530'. "
                "The model is in the 'DeviceMOT' element of 'Project Info.xml' "
                "and most other files in the export."
            )
            dev.description.model = "3530"

        cls.update_dev(dev)

        return dev

    @classmethod
    def _process_export(cls, dev: DeviceData, device_info: dict) -> None:
        """
        Populate the device data model with the
        data parsed from a RTAC project export.
        """
        # --- Model and part number ---
        project_info = device_info.get("ProjectInfo", {})
        project_rtacs = project_info.get("Devices", [])
        if len(project_rtacs) > 1:
            cls.log.warning(
                f"The project export has {len(project_rtacs)} RTACs "
                f"({[r.get('FolderName') for r in project_rtacs]}). PEAT parses "
                f"them as one device, so items with the same name in different "
                f"RTACs overwrite each other. Parse the folder of each RTAC on "
                f"its own to keep the data separate."
            )

        # DeviceMOT is a model (e.g. "3530") or a part number (e.g. "3530HB0AX313X1XXXXXX")
        mots = [str(r["DeviceMOT"]) for r in project_rtacs if r.get("DeviceMOT")]
        for mot in device_info.get("ExportSource", {}).get("DeviceMOT", []):
            if str(mot) not in mots:
                mots.append(str(mot))
        if len({mot[:4] for mot in mots}) > 1:
            cls.log.warning(f"Project export has data from more than one RTAC model: {mots}")
        if mots and not dev.description.model:
            mot = mots[0]
            model_match = re.match(r"\d{4}", mot)
            if model_match:
                dev.description.model = model_match.group(0)
            else:
                dev.description.model = mot
        # Use the first value that is a full part number
        for mot in mots:
            if re.fullmatch(r"\d{4}[0-9A-Z]{6,}", mot) and not dev.part_number:
                dev.part_number = mot
                break

        # --- Host name and Ethernet interfaces ---
        # NOTE: set the host name before adding interfaces, since the first
        # interface stored is copied to the device's ip, mac, and hostname.
        advanced = device_info.get("AdvancedSettings", {})
        for web_info in advanced.get("Website Settings", {}).get("device_info", []):
            host_name = web_info.get("host_name", "").strip()
            if host_name:
                if not dev.hostname:
                    dev.hostname = host_name
                dev.related.hosts.add(host_name)
                # The default host name has the model, e.g. "SEL3530-4-0030A702E165"
                host_match = re.match(r"SEL-?(\d{4}(?:-\d)?)-", host_name)
                if host_match and (
                    not dev.description.model
                    or host_match.group(1).startswith(dev.description.model)
                ):
                    dev.description.model = host_match.group(1)
            if web_info.get("description") and not dev.description.description:
                dev.description.description = web_info["description"]

        cls._process_ethernet_settings(dev, advanced.get("Ethernet Settings", {}))

        rtac_name = device_info.get("IEC61850Info", {}).get("RtacName")
        if rtac_name:
            if not dev.name:
                dev.name = rtac_name
            dev.related.hosts.add(rtac_name)

        # --- Remote devices, protocols, IPs, ports, and registers ---
        for dev_name, rem_dev in device_info.get("Devices", {}).items():
            protocol = cls._normalize_protocol(rem_dev.get("Protocol", ""))
            if protocol:
                dev.related.protocols.add(protocol)

            # Skip access points (local sockets) and tunnels, e.g "Eng_Access_40"
            if (
                "Eng_Access_" not in dev_name
                and "accesspoint" not in str(rem_dev.get("Protocol", "")).lower()
            ):
                dev.related.hosts.add(dev_name)

            settings = rem_dev.get("Settings", {})
            for ip_key in RTAC_EXPORT_IP_SETTINGS:
                ip = str(settings.get(ip_key, "")).strip()
                if not utils.is_ip(ip):
                    continue
                ip_obj = ipaddress.ip_address(ip)
                # Multicast groups and "0.0.0.0" are not hosts
                if not ip_obj.is_unspecified and not ip_obj.is_multicast:
                    dev.related.ip.add(ip)

            for port_key in RTAC_EXPORT_PORT_SETTINGS:
                # The client port isn't fixed if it's automatically assigned
                if port_key == "Client IP Port" and settings.get("Auto Client IP Port") is True:
                    continue
                port = settings.get(port_key)
                if type(port) is int and 0 < port < 65536:
                    dev.related.ports.add(port)

            cls._process_device_registers(dev, dev_name, rem_dev, protocol)

        # --- Engineering access (access points, access point routers, SEL servers) ---
        try:
            cls._process_engineering_access(dev, discover_from_export(device_info))
        except Exception:
            cls.log.exception("Failed to process the engineering access settings of the export")

        for goose in device_info.get("GooseDevices", {}).values():
            dev.related.protocols.add(cls._normalize_protocol(goose.get("Protocol", "goose")))
            if goose.get("IED Name"):
                dev.related.hosts.add(goose["IED Name"])

        # --- Logic ---
        if project_info.get("Description") and not dev.logic.description:
            dev.logic.description = project_info["Description"]

        st_logic = build_structured_text(device_info)
        if st_logic:
            dev.logic.formats["structured_text"] = st_logic
            if not dev.logic.parsed:
                dev.logic.parsed = st_logic
            cls._write_and_record_file(
                dev,
                st_logic,
                "logic.st",
                source="derived",
                description="Structured Text logic of the RTAC project",
            )

    @classmethod
    def _process_ethernet_settings(cls, dev: DeviceData, eth_settings: dict) -> None:
        """Add interfaces from the "Ethernet Settings" in a project export."""
        ipv6_by_id = {}
        for ipv6 in eth_settings.get("ipv6_network_interfaces", []):
            if ipv6.get("network_interface_id") is not None:
                ipv6_by_id[ipv6["network_interface_id"]] = ipv6

        for ipv4 in eth_settings.get("ipv4_network_interfaces", []):
            name = ipv4.get("name", "")
            try:
                iface = cls._make_interface(ipv4, ipv6_by_id.get(ipv4.get("network_interface_id")))
            except Exception as ex:
                cls.log.warning(f"Failed to parse Ethernet interface '{name}': {ex}")
                continue
            dev.store("interface", iface, lookup="name")

    @classmethod
    def _make_interface(cls, ipv4: dict, ipv6: dict | None) -> Interface:
        """
        Make an Interface from the attributes of a ``ipv4_network_interfaces``
        element (and the matching ``ipv6_network_interfaces`` element, if any).
        """
        name = ipv4.get("name", "")
        iface = Interface(
            name=name,
            id=ipv4.get("network_interface_id", ""),
            type="usb" if name.upper().startswith("USB") else "ethernet",
        )
        if ipv4.get("interface_enabled"):
            iface.enabled = ipv4["interface_enabled"].lower() == "true"
        if ipv4.get("mac"):
            iface.mac = ipv4["mac"]

        address = ipv4.get("ipv4_address", "").strip()
        if address:
            try:
                ip_iface = ipaddress.IPv4Interface(address)
                iface.ip = str(ip_iface.ip)
                # Only set the mask if the address has a prefix, e.g. "/24"
                if "/" in address:
                    iface.subnet_mask = str(ip_iface.netmask)
            except ValueError:
                cls.log.warning(f"Invalid IPv4 address '{address}' for interface '{name}'")

        # Keep the attributes that aren't fields of the Interface in "extra"
        used = {"name", "network_interface_id", "interface_enabled", "mac", "ipv4_address"}
        iface.extra = {k: v for k, v in ipv4.items() if k not in used}
        if ipv6 and ipv6.get("ip_address"):
            iface.extra["ipv6_address"] = ipv6["ip_address"]
            if ipv6.get("interface_enabled"):
                iface.extra["ipv6_enabled"] = ipv6["interface_enabled"].lower() == "true"

        return iface

    @classmethod
    def _normalize_protocol(cls, protocol: str) -> str:
        """
        Convert a protocol name from a project export (e.g. "ModbusClient")
        to a PEAT protocol name (e.g. "modbus").
        """
        if not protocol:
            return ""
        lowered = protocol.lower()
        for substring, name in RTAC_EXPORT_PROTOCOLS:
            if substring in lowered:
                return name
        return lowered

    @classmethod
    def _process_device_registers(
        cls, dev: DeviceData, dev_name: str, rem_dev: dict, protocol: str
    ) -> None:
        """
        Add registers for the tags of a remote device that have a
        protocol address, e.g. Modbus registers or DNP3 points.
        """
        for page_key, page in rem_dev.items():
            if not isinstance(page, dict) or page_key == "Settings":
                continue

            for tag_key, row in page.items():
                if not isinstance(row, dict):
                    continue

                address = None
                for column in RTAC_EXPORT_ADDRESS_COLUMNS:
                    if row.get(column) is not None:
                        address = row[column]
                        break
                if address is None:
                    continue

                tag_name = str(row.get("Tag Name", tag_key))
                if "binary" in page_key or "coil" in page_key or "discrete" in page_key:
                    measurement = "binary"
                elif "analog" in page_key or "register" in page_key:
                    measurement = "analog"
                else:
                    measurement = ""

                extra = {"remote_device": dev_name, "page": page_key}
                if row.get("Register Address Stop") is not None:
                    extra["address_stop"] = str(row["Register Address Stop"])
                if row.get("Tag Alias"):
                    extra["alias"] = str(row["Tag Alias"])

                reg = Register(
                    address=str(address),
                    name=tag_name,
                    tag=tag_name,
                    data_type=str(row.get("Tag Type", "")),
                    measurement_type=measurement,
                    protocol=protocol,
                    group=dev_name,
                    extra=extra,
                )
                if isinstance(row.get("Enable"), bool):
                    reg.enabled = row["Enable"]
                if row.get("Comment"):
                    reg.description = str(row["Comment"])

                dev.store("registers", reg)


def _tar_member_mtime(member: tarfile.TarInfo) -> datetime | None:
    """
    Modification time of a member of a tarball, or :obj:`None` if it's
    not set or out of range (e.g. hand-made or damaged archives).
    """
    if not member.mtime:
        return None
    try:
        return datetime.fromtimestamp(member.mtime, UTC)
    except (ValueError, OverflowError, OSError) as ex:
        log.debug(f"Invalid modification time {member.mtime!r} for '{member.name}': {ex}")
        return None


def _serialize(data: Any, filename: str) -> bytes:
    """
    The bytes :func:`peat.utils.write_file` writes for ``data``,
    so the hash is the same if device file output is disabled.
    """
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)

    if ".json" in PurePosixPath(filename).suffixes:
        return json.dumps(consts.convert(data), indent=4).encode("utf-8")

    return str(data).encode("utf-8")


def _matching_file(candidates: Iterable[Path], digest: _Digest) -> Path | None:
    """
    The first of ``candidates`` that's a file with the contents of ``digest``.
    """
    for candidate in candidates:
        try:
            if not candidate.is_file() or candidate.stat().st_size != digest.size:
                continue
            with candidate.open("rb") as file:
                if hashlib.file_digest(file, "sha256").hexdigest() == digest.sha256:
                    return candidate.resolve()
        except OSError:
            continue

    return None


def _find_written_file(dev: DeviceData, filename: str, digest: _Digest) -> Path | None:
    """
    Find the file :meth:`~peat.data.models.DeviceData.write_file` saved the
    contents of ``digest`` to, which may be ``<name>.<num>`` if the name
    already existed.

    Returns:
        Path of the file, or :obj:`None` if file output is disabled or no
        file in the device's output directory has the contents
    """
    if not dev._out_dir and not config.DEVICE_DIR:
        return None

    out_dir = dev.get_out_dir().resolve()
    target = (out_dir / consts.sanitize_filepath(filename)).resolve()
    if not target.is_relative_to(out_dir):
        return None

    candidates = [target]
    while True:
        duplicate = target.with_name(f"{target.name}.{len(candidates)}")
        if not duplicate.exists():
            break
        candidates.append(duplicate)

    # The most recent file is the one with the highest number
    return _matching_file(reversed(candidates), digest)


@contextmanager
def _capture_downloads(
    session: SELHTTP, pages: tuple[str, ...]
) -> Iterator[list[tuple[str, _Digest]]]:
    """
    Hash the successful responses for the pages (URL paths ending in one of
    ``pages``) that the session receives inside the ``with`` block, and
    collect their URL and :class:`_Digest`.

    This uses a ``requests`` response hook, so the content of downloads can be
    hashed without changing :class:`~peat.modules.sel.sel_http.SELHTTP`. Each
    response is hashed when it arrives, and isn't kept, so the contents of
    large files aren't kept in memory until the end of the pull.
    """
    downloads: list[tuple[str, _Digest]] = []

    def _capture(response: Response, **_kwargs) -> None:
        if response.status_code != 200 or not urlparse(response.url).path.endswith(pages):
            return
        # NOTE: errors reading the response are left to the code that sent the request
        content = response.content
        try:
            downloads.append((response.url, _Digest.of(content)))
        except Exception as ex:  # Never break the download itself
            log.warning(f"Failed to hash the download from '{response.url}': {ex}")

    hooks = session.session.hooks.setdefault("response", [])
    hooks.append(_capture)
    try:
        yield downloads
    finally:
        hooks.remove(_capture)


SELRTAC.ip_methods = [
    IPMethod(
        name="SEL RTAC login HTTP",
        description=str(SELRTAC._verify_http.__doc__).strip(),
        type="unicast_ip",
        identify_function=functools.partial(SELRTAC._verify_http, protocol="http"),
        reliability=6,  # Modern RTACs just redirect from HTTP to HTTPS
        protocol="http",
        transport="tcp",
        default_port=80,
    ),
    IPMethod(
        name="SEL RTAC login HTTPS",
        description=str(SELRTAC._verify_http.__doc__).strip(),
        type="unicast_ip",
        identify_function=functools.partial(SELRTAC._verify_http, protocol="https"),
        reliability=8,
        protocol="https",
        transport="tcp",
        default_port=443,
    ),
    IPMethod(
        name="SEL RTAC SSL certificate",
        description=str(SELRTAC._verify_https_ssl_certificate.__doc__).strip(),
        type="unicast_ip",
        identify_function=SELRTAC._verify_https_ssl_certificate,
        reliability=9,
        protocol="https",
        transport="tcp",
        default_port=443,
    ),
    IPMethod(
        name="SEL RTAC login PostgreSQL",
        description=str(SELRTAC._verify_postgres.__doc__).strip(),
        type="unicast_ip",
        identify_function=SELRTAC._verify_postgres,
        reliability=5,
        protocol="postgres",
        transport="tcp",
        default_port=5432,  # TODO: don't auto scan for postgres
        # TODO: better workaround for postgres port identification
        #   The TCP SYN check may put the database in a weird state or ban us
        #   since the relay's server is configured with a strict limit on connections,
        #   and the port check counts as a new connection.
        #   Implement a custom port_function?
    ),
]


__all__ = ["SELRTAC"]
