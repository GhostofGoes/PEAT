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
    mocker.patch.dict(config["CONFIG"], {"TLS_CA_BUNDLE": https_server.cert_path})
    http = HTTP("127.0.0.1", https_server.port, protocol="https")
    response = http.get("index.html", use_cache=False)
    assert response is not None
    assert response.status_code == 200


def test_http_get_self_signed_verify_disabled(tls_env, https_server):  # noqa: ARG001
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
