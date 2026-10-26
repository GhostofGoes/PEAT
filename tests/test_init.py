import json

import pytest
import yaml

from peat import config_crypto, consts, init

PASSWORD = "Marker-PW-9e4d"

CONFIG_YAML = f"""
# A comment
metadata:
  name: "test config"
elastic_server: "http://elastic:{PASSWORD}@localhost:9200/"
device_options:
  ssh:
    user: admin
    pass: "{PASSWORD}"
  snmp:
    communities: ["{PASSWORD}"]
  sel:
    creds: [["acc", "{PASSWORD}"]]
hosts:
  - identifier: 192.0.2.1
    options:
      web:
        pass: "{PASSWORD}"
"""


def test_copy_config_file_yaml(tmp_path):
    src = tmp_path / "config.yaml"
    src.write_text(CONFIG_YAML, encoding="utf-8")
    dest = tmp_path / "meta" / "config.yaml"

    assert init.copy_config_file(src, dest)

    text = dest.read_text(encoding="utf-8")
    assert PASSWORD not in text
    data = yaml.safe_load(text)
    assert data["metadata"] == {"name": "test config"}
    assert data["elastic_server"] == "http://elastic:<redacted>@localhost:9200/"
    assert data["device_options"]["ssh"] == {"user": "admin", "pass": "<redacted>"}
    assert data["device_options"]["snmp"]["communities"] == ["<redacted>"]
    assert data["device_options"]["sel"]["creds"] == [["acc", "<redacted>"]]
    assert data["hosts"][0]["options"]["web"]["pass"] == "<redacted>"
    assert PASSWORD in src.read_text(encoding="utf-8")  # original isn't changed


def test_copy_config_file_json(tmp_path):
    src = tmp_path / "config.json"
    src.write_text(json.dumps(yaml.safe_load(CONFIG_YAML)), encoding="utf-8")
    dest = tmp_path / "meta" / "config.json"

    assert init.copy_config_file(src, dest)

    text = dest.read_text(encoding="utf-8")
    assert PASSWORD not in text
    assert json.loads(text)["device_options"]["ssh"]["pass"] == "<redacted>"


def test_copy_config_file_example_config(tmp_path, examples_dir):
    # The example config uses custom YAML tags (e.g. "!JOIN")
    src = examples_dir / "peat-config.yaml"
    dest = tmp_path / "peat-config.yaml"

    assert init.copy_config_file(src, dest)
    data = yaml.safe_load(dest.read_text(encoding="utf-8"))
    assert data["device_options"] == consts.redact_secrets(
        yaml.safe_load(src.read_text(encoding="utf-8"))["device_options"]
    )


def test_copy_config_file_encrypted(tmp_path):
    src = tmp_path / "config.yaml"
    src.write_text(CONFIG_YAML, encoding="utf-8")
    assert config_crypto.encrypt_config(src, "user-password")
    encrypted = tmp_path / "encrypted_config.yaml"
    dest = tmp_path / "meta" / "encrypted_config.yaml"

    assert init.copy_config_file(encrypted, dest)
    assert dest.read_bytes() == encrypted.read_bytes()


@pytest.mark.parametrize("content", ["", "- a list\n", "{invalid: [yaml"])
def test_copy_config_file_invalid(tmp_path, content):
    src = tmp_path / "config.yaml"
    src.write_text(content, encoding="utf-8")
    dest = tmp_path / "meta" / "config.yaml"

    assert not init.copy_config_file(src, dest)
    assert not dest.exists()
