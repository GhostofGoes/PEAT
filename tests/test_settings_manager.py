"""
This module is sort of implicitly tested via other tests, notably the CLI tests
and anything that mocks out the config. These tests ensure edge cases don't break
things, as well as verifying that breakages in other tests aren't due to breakages
in the config or state.
"""

import json
import os
from pathlib import Path

import pytest
import yaml

from peat.consts import PeatError, lower_dict
from peat.settings_manager import SettingsManager


@pytest.fixture
def settings_cls() -> type[SettingsManager]:
    class TestSettings(SettingsManager):
        TEST_OPTION: str = "default_value"
        ALPHA: bool = False

    return TestSettings


@pytest.fixture  # scope="function"
def settings_instance(settings_cls: type[SettingsManager]) -> SettingsManager:
    return settings_cls(label="configuration", env_prefix="TEST_", init_env=False)


def test_load_from_dict(settings_instance):
    settings_instance.load_from_dict({"ALPHA": True, "test_option": "string"})
    assert settings_instance.ALPHA
    assert settings_instance.TEST_OPTION == "string"


def test_load_from_environment(settings_instance, mocker):
    mocker.patch.dict(os.environ, {"TEST_ALPHA": "true"})
    settings_instance.load_from_environment()
    assert settings_instance.ALPHA


@pytest.mark.parametrize("file_ext", ["json", "yaml"])
def test_load_from_file(settings_instance, datapath, file_ext):
    assert settings_instance.load_from_file(datapath(f"test_load_from_file.{file_ext}"))
    assert settings_instance.export() == {
        "ALPHA": False,
        "ENV_PREFIX": "TEST_",
        "TEST_OPTION": "default_value",
    }


def test_save_to_file(settings_instance, tmp_path, assert_glob_path):
    settings_instance.save_to_file(outdir=tmp_path)

    json_path = assert_glob_path(tmp_path, "peat_configuration.json")
    assert json.loads(json_path.read_text()) == settings_instance.export()

    yaml_path = assert_glob_path(tmp_path, "peat_configuration.yaml")
    assert yaml.safe_load(yaml_path.read_text()) == lower_dict(settings_instance.export())


def test_save_to_file_no_yaml(settings_instance, tmp_path, assert_glob_path):
    settings_instance.save_to_file(outdir=tmp_path, save_yaml=False)

    json_path = assert_glob_path(tmp_path, "peat_configuration.json")  # only a JSON file
    assert json.loads(json_path.read_text()) == settings_instance.export()


def test_save_to_file_no_json(settings_instance, tmp_path, assert_glob_path):
    settings_instance.save_to_file(outdir=tmp_path, save_json=False)

    yaml_path = assert_glob_path(tmp_path, "peat_configuration.yaml")
    assert yaml.safe_load(yaml_path.read_text()) == lower_dict(settings_instance.export())


def test_save_to_file_raises(settings_instance, tmp_path):
    with pytest.raises(PeatError):
        settings_instance.save_to_file(outdir=tmp_path, save_yaml=False, save_json=False)


def test_export(settings_instance):
    assert settings_instance.export() == {
        "ALPHA": False,
        "ENV_PREFIX": "TEST_",
        "TEST_OPTION": "default_value",
    }
    settings_instance.TEST_OPTION = "non-default_value"
    assert settings_instance.export() == {
        "ALPHA": False,
        "ENV_PREFIX": "TEST_",
        "TEST_OPTION": "non-default_value",
    }
    settings_instance.TEST_OPTION = None
    assert settings_instance.export() == {"ALPHA": False, "ENV_PREFIX": "TEST_"}


def test_export_omits_secrets(tmp_path):
    password = "Marker-PW-41f0"

    class SecretSettings(SettingsManager):
        ELASTIC_SERVER: str = ""
        DEVICE_OPTIONS: dict = {}

    settings = SecretSettings(label="configuration", env_prefix="TEST_", init_env=False)
    settings.ELASTIC_SERVER = f"https://elastic:{password}@localhost:9200/"
    settings.DEVICE_OPTIONS = {
        "ssh": {"user": "admin", "pass": password},
        "snmp": {"communities": [password]},
        "sel": {"creds": [["acc", password]]},
    }

    exported = settings.export()
    assert exported["ELASTIC_SERVER"] == "https://elastic@localhost:9200/"
    assert exported["DEVICE_OPTIONS"] == {"ssh": {"user": "admin"}, "snmp": {}, "sel": {}}
    assert password not in settings.yaml()
    assert password not in settings.json()

    settings.save_to_file(outdir=tmp_path)
    for name in ["peat_configuration.json", "peat_configuration.yaml"]:
        text = (tmp_path / name).read_text(encoding="utf-8")
        assert password not in text, name
        assert "<redacted>" not in text, name
    yaml_text = (tmp_path / "peat_configuration.yaml").read_text(encoding="utf-8")
    assert yaml_text.splitlines()[0] == (
        "# Secrets omitted by PEAT (set them again to reuse this file): "
        "device_options.sel.creds, device_options.snmp.communities, "
        "device_options.ssh.pass, elastic_server (password)"
    )

    # The values used by PEAT aren't changed
    assert settings.DEVICE_OPTIONS["ssh"]["pass"] == password
    assert password in settings.ELASTIC_SERVER


def test_yaml(settings_instance):
    assert settings_instance.yaml()
    assert yaml.safe_load(settings_instance.yaml()) == lower_dict(settings_instance.export())


def test_json(settings_instance):
    assert settings_instance.json()
    assert json.loads(settings_instance.json()) == settings_instance.export()


def test_json_dict(settings_instance):
    assert settings_instance.json_dict() == {
        "ALPHA": False,
        "ENV_PREFIX": "TEST_",
        "TEST_OPTION": "default_value",
    }
    settings_instance.TEST_OPTION = "non-default_value"
    assert settings_instance.json_dict() == {
        "ALPHA": False,
        "ENV_PREFIX": "TEST_",
        "TEST_OPTION": "non-default_value",
    }
    settings_instance.TEST_OPTION = None
    assert settings_instance.json_dict() == {"ALPHA": False, "ENV_PREFIX": "TEST_"}


def test_get_serialized_value(settings_instance):
    assert settings_instance.get_serialized_value("ALPHA") is False
    settings_instance.ALPHA = True
    assert settings_instance.get_serialized_value("ALPHA") is True


def test_typecast(tmp_path):
    class TestTypecast(SettingsManager):
        TEST_OPTION: str = "default_value"
        ALPHA: bool = False
        PTH: Path = Path("somepath")
        PATHS: list[str | Path] = []
        OPTS: str | None = None

    inst = TestTypecast(label="configuration", env_prefix="TEST_", init_env=False)
    assert inst.typecast("ALPHA", False) is False
    assert inst.typecast("ALPHA", "yes") is True
    assert inst.typecast("ALPHA", "false") is False
    assert inst.typecast("ALPHA", "yes") is True
    assert inst.typecast("PTH", tmp_path) == tmp_path
    assert inst.typecast("PTH", tmp_path.as_posix()) == tmp_path
    assert inst.typecast("TEST_OPTION", 1) == "1"
    assert inst.typecast("PATHS", []) == []
    assert inst.typecast("PATHS", ["/some/path/", "somefile.txt"]) == [
        "/some/path/",
        "somefile.txt",
    ]
    assert inst.typecast("OPTS", None) is None
    assert inst.typecast("OPTS", "{'one': 1}") == "{'one': 1}"


def test_non_default(settings_instance):
    assert not settings_instance.non_default("TEST_OPTION")
    settings_instance.TEST_OPTION = "some new value"
    assert settings_instance.non_default("TEST_OPTION")


def test_is_default_value(settings_instance):
    assert settings_instance.is_default_value("TEST_OPTION")
    settings_instance.TEST_OPTION = "some other non-default value"
    assert not settings_instance.is_default_value("TEST_OPTION")


class _DeviceSettings(SettingsManager):
    ELASTIC_SERVER: str = ""
    DEVICE_OPTIONS: dict = {}
    COUNT: int = 3


def test_reused_export_keeps_default_secrets(tmp_path):
    """Reusing a saved configuration used "<redacted>" as passwords and communities."""
    settings = _DeviceSettings(label="configuration", env_prefix="TEST_", init_env=False)
    settings.ELASTIC_SERVER = "https://elastic:Marker-PW-77@localhost:9200/"
    settings.DEVICE_OPTIONS = {
        "sel": {"pass": "Marker-PW-77", "creds": [["acc", "Marker-PW-77"]], "user": "acc"},
        "snmp": {"community": "Marker-PW-77", "port": 1161},
    }
    settings.save_to_file(outdir=tmp_path)

    for name in ["peat_configuration.json", "peat_configuration.yaml"]:
        reused = _DeviceSettings(label="configuration", env_prefix="TEST_", init_env=False)
        assert reused.load_from_file(tmp_path / name)
        assert reused.DEVICE_OPTIONS == {"sel": {"user": "acc"}, "snmp": {"port": 1161}}
        assert reused.ELASTIC_SERVER == "https://elastic@localhost:9200/"
        assert "<redacted>" not in str(reused.export())


def test_load_ignores_redacted_values(tmp_path, caplog):
    file = tmp_path / "config.yaml"
    file.write_text(
        """
elastic_server: "https://elastic:<redacted>@localhost:9200/"
count: "<redacted>"
device_options:
  sel:
    pass: "<redacted>"
    creds: [[acc, "<redacted>"], [acc2, real-pw]]
    user: acc
  snmp:
    communities: ["<redacted>"]
""",
        encoding="utf-8",
    )
    settings = _DeviceSettings(label="configuration", env_prefix="TEST_", init_env=False)
    with caplog.at_level("WARNING"):
        assert settings.load_from_file(file)

    assert settings.ELASTIC_SERVER == ""
    assert settings.COUNT == 3
    assert settings.DEVICE_OPTIONS == {"sel": {"creds": [["acc2", "real-pw"]], "user": "acc"}}
    assert "Ignoring redacted values in config 'DEVICE_OPTIONS'" in caplog.text
    assert "sel.pass, sel.creds[0], snmp.communities[0]" in caplog.text
    assert "Ignoring redacted values in config 'ELASTIC_SERVER'" in caplog.text
