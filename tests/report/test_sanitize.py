import re
from pathlib import Path

import pytest

from peat.report import consts as report_consts
from peat.report.sanitize import (
    REDACTED,
    anchor_id,
    clean_text,
    hosts_overview,
    ip_sort_key,
    neutralize,
    redact_argv,
    redact_mapping,
    redact_url_credentials,
    safe_href,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("abc\u202eexe.txt", "abc\\u202eexe.txt"),  # RLO (Trojan Source)
        ("a\u2066b\u2069", "a\\u2066b\\u2069"),  # bidi isolates
        ("nul\x00byte", "nul\\u0000byte"),
        ("esc\x1b[31m", "esc\\u001b[31m"),  # terminal escape
        ("c1\x85", "c1\\u0085"),
        ("zero\u200bwidth\ufeff", "zero\\u200bwidth\\ufeff"),
        ("tab\tnewline\ncr\r", "tab\tnewline\ncr\r"),  # kept
        ("日本語 ü", "日本語 ü"),  # normal non-ASCII is kept
    ],
)
def test_neutralize(raw, expected):
    assert neutralize(raw) == expected
    assert neutralize(neutralize(raw)) == expected  # idempotent


def test_clean_text(monkeypatch):
    assert clean_text(None) == ""
    assert clean_text(0) == "0"
    assert clean_text(False) == "False"
    assert clean_text("x" * 10, max_len=4) == "xxxx... [6 more characters]"
    assert clean_text("x" * 10, max_len=0) == "x" * 10
    monkeypatch.setattr(report_consts, "MAX_TEXT_LEN", 3)
    assert clean_text("abcdef") == "abc... [3 more characters]"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://elastic:changeme@192.0.2.5:9200/", f"https://{REDACTED}@192.0.2.5:9200/"),
        ("http://user@host/", f"http://{REDACTED}@host/"),
        ("-e ftp://a:b@h x http://h/", f"-e ftp://{REDACTED}@h x http://h/"),
        ("user@example.com", "user@example.com"),
        ("http://192.0.2.5:9200", "http://192.0.2.5:9200"),
        # An unencoded "@" in the password: urlparse uses the last "@"
        ("http://elastic:p@ss@host:9200/", f"http://{REDACTED}@host:9200/"),
        ("http://u:a@b@c@host?q=x@y", f"http://{REDACTED}@host?q=x@y"),
        ("http://host/path@x", "http://host/path@x"),
        ("http://a:b@h1 and https://c:d@h2/", f"http://{REDACTED}@h1 and https://{REDACTED}@h2/"),
    ],
)
def test_redact_url_credentials(raw, expected):
    assert redact_url_credentials(raw) == expected


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["peat", "encrypt-results", "-p", "pw"], ["peat", "encrypt-results", "-p", REDACTED]),
        (["peat", "encrypt", "-ppw"], ["peat", "encrypt", f"-p{REDACTED}"]),
        (
            ["peat", "decrypt-config", "--password", "pw", "-f", "x"],
            ["peat", "decrypt-config", "--password", REDACTED, "-f", "x"],
        ),
        (
            ["peat", "decrypt-results", "--password=pw"],
            ["peat", "decrypt-results", f"--password={REDACTED}"],
        ),
        # "-p" means something else for other commands, don't redact it
        (["peat", "pull", "-p", "modbus"], ["peat", "pull", "-p", "modbus"]),
        (["peat", "scan", "-pmodbus"], ["peat", "scan", "-pmodbus"]),
        (
            ["peat", "pull", "-e", "https://u:p@h:9200"],
            ["peat", "pull", "-e", f"https://{REDACTED}@h:9200"],
        ),
        ([], []),
    ],
)
def test_redact_argv(argv, expected):
    assert redact_argv(argv) == expected


def test_redact_mapping():
    data = {
        "ELASTIC_SERVER": "https://u:secret1@h:9200",
        "DEBUG": 1,
        "nested": {"api_key": "secret2", "Token": "secret3", "name": "ok", "auth": None},
        "list": [{"password": "secret4"}, "http://u:secret5@h/"],
        "DEVICE_OPTIONS": {"sel": {"pass": "secret6"}, "ftp": {"user": "a"}},
        "HOSTS": [{"ip": "192.0.2.1", "options": {"pass": "secret7"}}],
        # Nested in a section (e.g. per-command configuration sections)
        "pull": {"device_options": {"sel": {"pass": "secret8"}}, "hosts": []},
        "pillage": {"location": "secret9"},
    }
    result = redact_mapping(data)
    text = repr(result)
    for i in range(1, 10):
        assert f"secret{i}" not in text
    assert result["DEBUG"] == 1
    assert result["nested"]["name"] == "ok"
    assert result["nested"]["auth"] is None  # empty values aren't "secrets"
    assert result["DEVICE_OPTIONS"] == "2 option group(s): ftp, sel (values not shown)"
    assert result["HOSTS"] == "1 hosts entry (not shown)"
    assert result["pull"]["device_options"].startswith("1 option group(s)")
    assert result["pull"]["hosts"] == "0 hosts entries (not shown)"
    assert data["DEVICE_OPTIONS"]["sel"]["pass"] == "secret6"  # input unchanged


def test_hosts_overview():
    hosts = [
        {
            "label": "relay",
            "identifiers": {"ip": "192.0.2.1", "mac": "00:00:00:00:00:01", "junk": "x"},
            "peat_module": "SELRelay",
            "comment": "c",
            "options": {"sel": {"pass": "secret"}},
        },
        {"ip": "192.0.2.2"},
        "not-a-dict",
    ]
    rows = hosts_overview(hosts)
    assert rows == [
        {
            "label": "relay",
            "identifiers": "ip: 192.0.2.1, mac: 00:00:00:00:00:01",
            "peat_module": "SELRelay",
            "comment": "c",
        },
        {"label": "", "identifiers": "ip: 192.0.2.2", "peat_module": "", "comment": ""},
    ]
    assert "secret" not in repr(rows)
    assert hosts_overview(None) == []
    assert hosts_overview({"a": 1}) == []


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("devices/x/javascript:alert(1)", "./devices/x/javascript%3Aalert%281%29"),
        ("a b/c#d?e.txt", "./a%20b/c%23d%3Fe.txt"),
        ("日本.txt", "./%E6%97%A5%E6%9C%AC.txt"),
        ("../other/f.json", "../other/f.json"),
        ("", "./"),
    ],
)
def test_safe_href(tmp_path, target, expected):
    base = tmp_path / "run"
    href = safe_href(base / target, base)
    assert href == expected
    assert not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", href)


def test_safe_href_different_drive(mocker, tmp_path):
    mocker.patch("os.path.relpath", side_effect=ValueError("different drive"))
    href = safe_href(tmp_path / "a b.txt", Path("/elsewhere"))
    assert href.startswith("file:")
    assert " " not in href


def test_anchor_id():
    ids = {anchor_id("dev", k) for k in ["192.0.2.1", "192.0.2.1 ", "<script>", "", "日本"]}
    assert len(ids) == 5
    for i in ids:
        assert re.fullmatch(r"[A-Za-z0-9_-]+", i)
    assert anchor_id("dev", "x") == anchor_id("dev", "x")


def test_ip_sort_key():
    values = ["COM4", "10.0.0.10", "fe80::1", "10.0.0.2", "10.0.0.2:502", "abc", "9.0.0.1"]
    assert sorted(values, key=ip_sort_key) == [
        "9.0.0.1",
        "10.0.0.2",
        "10.0.0.2:502",
        "10.0.0.10",
        "fe80::1",
        "abc",
        "COM4",
    ]
