import json
import os
import stat

import pytest
import yaml

from peat import config, config_crypto, consts, init

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
    assert "<redacted>" not in text
    assert text.splitlines()[0] == (
        "# Copy of config.yaml with secrets omitted by PEAT: elastic_server (password), "
        "device_options.ssh.pass, device_options.snmp.communities, "
        "device_options.sel.creds, hosts[0].options.web.pass"
    )
    data = yaml.safe_load(text)
    assert data["metadata"] == {"name": "test config"}
    assert data["elastic_server"] == "http://elastic@localhost:9200/"
    assert data["device_options"] == {"ssh": {"user": "admin"}, "snmp": {}, "sel": {}}
    assert data["hosts"][0]["options"]["web"] == {}
    assert PASSWORD in src.read_text(encoding="utf-8")  # original isn't changed


def test_copy_config_file_json(tmp_path):
    src = tmp_path / "config.json"
    src.write_text(json.dumps(yaml.safe_load(CONFIG_YAML)), encoding="utf-8")
    dest = tmp_path / "meta" / "config.json"

    assert init.copy_config_file(src, dest)

    text = dest.read_text(encoding="utf-8")
    assert PASSWORD not in text
    assert json.loads(text)["device_options"]["ssh"] == {"user": "admin"}


def test_copy_config_file_example_config(tmp_path, examples_dir):
    # The example config uses custom YAML tags (e.g. "!JOIN")
    src = examples_dir / "peat-config.yaml"
    dest = tmp_path / "peat-config.yaml"

    assert init.copy_config_file(src, dest)
    data = yaml.safe_load(dest.read_text(encoding="utf-8"))
    assert (
        data["device_options"]
        == consts.omit_secrets(yaml.safe_load(src.read_text(encoding="utf-8"))["device_options"])[
            0
        ]
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


@pytest.fixture
def restore_umask():
    original = os.umask(0o022)
    yield
    os.umask(original)


@pytest.mark.skipif(not consts.POSIX, reason="umask only restricts access on POSIX systems")
def test_restrict_results_permissions(tmp_path, mocker, restore_umask):  # noqa: ARG001
    out_dir = tmp_path / "peat_results"
    run_dir = out_dir / "run"
    mocker.patch.dict(config["CONFIG"], {"OUT_DIR": out_dir, "RUN_DIR": run_dir})
    mocker.patch.dict(consts.SYSINFO, {"containerized": False})

    init.restrict_results_permissions()
    (run_dir / "logs").mkdir(parents=True)
    (run_dir / "logs" / "peat.log").write_text("secret", encoding="utf-8")

    # The directory with the results of all runs can still be shared
    assert stat.S_IMODE(out_dir.stat().st_mode) == 0o755
    assert stat.S_IMODE(run_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE((run_dir / "logs").stat().st_mode) == 0o700
    assert stat.S_IMODE((run_dir / "logs" / "peat.log").stat().st_mode) == 0o600


@pytest.mark.skipif(not consts.POSIX, reason="umask only restricts access on POSIX systems")
def test_restrict_results_permissions_container(tmp_path, mocker, restore_umask):  # noqa: ARG001
    mocker.patch.dict(config["CONFIG"], {"RUN_DIR": tmp_path / "run"})
    mocker.patch.dict(consts.SYSINFO, {"containerized": True})

    init.restrict_results_permissions()
    (tmp_path / "run").mkdir()
    assert stat.S_IMODE((tmp_path / "run").stat().st_mode) == 0o755
