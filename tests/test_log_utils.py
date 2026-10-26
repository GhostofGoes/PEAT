import json

import pytest
from loguru import logger

from peat import config, log_utils


@pytest.fixture
def secrets():
    """Isolate the registered secrets and the global logger configuration."""
    clear = getattr(log_utils, "clear_secrets", lambda: None)
    clear()
    yield
    clear()
    logger.remove()
    logger.configure(patcher=lambda _record: None)


def test_redact_secrets(secrets):  # noqa: ARG001
    log_utils.register_secret("Hunter2-UNIQUE", b"bytes-secret", "abc", "", None, 1234)
    assert log_utils.redact_secrets("pw=Hunter2-UNIQUE;") == "pw=<redacted>;"
    assert log_utils.redact_secrets("send b'bytes-secret\\r\\n'") == "send b'<redacted>\\r\\n'"
    # Very short values aren't redacted
    assert log_utils.redact_secrets("abc 1234") == "abc 1234"
    assert log_utils.redact_secrets("") == ""


def test_redact_secrets_word_boundaries(secrets):  # noqa: ARG001
    log_utils.register_secret("TAIL", "!pa$$", "TAILGATE")
    assert log_utils.redact_secrets("DETAIL TAIL TAILS") == "DETAIL <redacted> TAILS"
    assert log_utils.redact_secrets("TAILGATE") == "<redacted>"  # longest first
    assert log_utils.redact_secrets("x!pa$$y") == "x<redacted>y"


def test_no_secrets_is_noop(secrets):  # noqa: ARG001
    assert log_utils._secrets_re is None
    assert log_utils.redact_secrets("anything") == "anything"


def test_register_secrets_from_config(secrets, mocker):  # noqa: ARG001
    mocker.patch.dict(
        config["CONFIG"],
        {
            "DEVICE_OPTIONS": {
                "ssh": {"user": "admin-user", "pass": "ssh-pass-1", "port": 2222},
                "sel": {"creds": {"acc": "OTTER", "2ac": "TAIL"}},
                "ftp": {"creds": [["ftp-user", "ftp-pass-1"]]},
                "snmp": {"community": "comm-1", "communities": ["comm-2", "comm-3"]},
                "sel_rtac": {"web": {"users": ["web-user"], "passwords": ["web-pass-1"]}},
            },
            "HOSTS": [
                {"identifiers": {"ip": "192.0.2.1"}, "options": {"web": {"pass": "host-pw"}}}
            ],
            "ELASTIC_SERVER": "https://elastic:es%40pass-1@localhost:9200/",
        },
    )
    log_utils.register_secrets_from_config()

    for secret in [
        "ssh-pass-1",
        "OTTER",
        "TAIL",
        "ftp-pass-1",
        "comm-1",
        "comm-2",
        "comm-3",
        "web-pass-1",
        "host-pw",
        "es@pass-1",
        "es%40pass-1",
    ]:
        assert log_utils.redact_secrets(f"value {secret} end") == "value <redacted> end", secret

    # Usernames and other options aren't secrets
    for value in ["admin-user", "ftp-user", "web-user", "2222", "elastic"]:
        assert log_utils.redact_secrets(value) == value


def test_setup_logging_redacts_secrets(secrets, mocker, tmp_path):  # noqa: ARG001
    password = "Hunter2-UNIQUE-PW-7f3a"
    mocker.patch.dict(
        config["CONFIG"],
        {
            "LOG_DIR": tmp_path,
            "QUIET": True,
            "DEBUG": 0,
            "ELASTIC_SERVER": None,
            "DEVICE_OPTIONS": {"telnet": {"user": "Admin", "pass": password}},
            "HOSTS": [],
        },
    )
    log_utils.setup_logging(file=tmp_path / "peat.log", json_file=tmp_path / "json-log.jsonl")

    logger.debug(f"Writing command: {password}")
    logger.bind(is_telnetlib=True).trace3(f"send {password.encode()!r}")
    logger.complete()

    names = ["peat.log", "json-log.jsonl", "telnet.log"]
    logs = {name: (tmp_path / name).read_text(encoding="utf-8") for name in names}
    for name, text in logs.items():
        assert password not in text, name
        assert "<redacted>" in text, name

    record = json.loads(logs["json-log.jsonl"].splitlines()[-1])
    assert record["event"]["original"] == "Writing command: <redacted>"
