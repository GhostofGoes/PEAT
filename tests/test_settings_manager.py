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


def test_typecast_list_from_string():
    class TestTypecastList(SettingsManager):
        NAMES: list[str] = []
        PATHS: list[str | Path] = []
        UNIQUE: set[str] = set()
        ITEMS: list = []

    inst = TestTypecastList(label="configuration", env_prefix="TEST_", init_env=False)

    # Comma-separated strings (e.g. environment variables)
    assert inst.typecast("NAMES", "a, b,,c ") == ["a", "b", "c"]
    assert inst.typecast("NAMES", "single") == ["single"]
    assert inst.typecast("NAMES", "") == []
    assert inst.typecast("NAMES", "   ") == []
    assert inst.typecast("PATHS", "/one/path,two.txt") == ["/one/path", "two.txt"]
    assert inst.typecast("UNIQUE", "a,b,a") == {"a", "b"}
    assert inst.typecast("ITEMS", "x,y") == ["x", "y"]

    # JSON or YAML lists
    assert inst.typecast("NAMES", '["a", "b,c"]') == ["a", "b,c"]
    assert inst.typecast("NAMES", "[ftp, 502]") == ["ftp", "502"]  # str items
    assert inst.typecast("NAMES", " [] ") == []
    with pytest.raises(ValueError, match="valid JSON or YAML list") as exc_info:
        inst.typecast("NAMES", "[unclosed-secret")
    assert "secret" not in str(exc_info.value)  # Values aren't included in errors
    with pytest.raises(ValueError, match="valid JSON or YAML list"):
        inst.typecast("NAMES", "[502")

    # A single number (e.g. "protocol_filter: 502" in a YAML file) is a list of one item
    assert inst.typecast("NAMES", 502) == ["502"]
    assert inst.typecast("ITEMS", 1.5) == [1.5]
    assert inst.typecast("UNIQUE", 21) == {"21"}

    # Values that are already lists aren't split, list[str] items become strings
    assert inst.typecast("NAMES", ["a", "b"]) == ["a", "b"]
    assert inst.typecast("NAMES", ["ftp", 502]) == ["ftp", "502"]
    assert inst.typecast("PATHS", [Path("x")]) == [Path("x")]


def test_load_list_from_environment(mocker):
    class TestEnvList(SettingsManager):
        PROTOCOL_FILTER: list[str] = []

    mocker.patch.dict(os.environ, {"TESTLIST_PROTOCOL_FILTER": "ftp,502, 161/udp"})
    inst = TestEnvList(label="configuration", env_prefix="TESTLIST_", init_env=True)
    assert inst.PROTOCOL_FILTER == ["ftp", "502", "161/udp"]


def test_load_errors_recorded(mocker):
    class TestLoadErrors(SettingsManager):
        PROTOCOL_FILTER: list[str] = []
        NUMBER: int = 0

    mocker.patch.dict(
        os.environ, {"TESTERR_PROTOCOL_FILTER": "[502", "TESTERR_NUMBER": "not-a-number"}
    )
    inst = TestLoadErrors(label="configuration", env_prefix="TESTERR_", init_env=True)

    # Values that failed to load keep their defaults, and the errors are recorded
    assert inst.PROTOCOL_FILTER == []
    assert inst.NUMBER == 0
    assert set(inst["load_errors"]) == {"PROTOCOL_FILTER", "NUMBER"}
    assert "valid JSON or YAML list" in inst["load_errors"]["PROTOCOL_FILTER"]

    # A later successful load clears the error
    inst.load_from_dict({"protocol_filter": ["ftp"]})
    assert inst.PROTOCOL_FILTER == ["ftp"]
    assert "PROTOCOL_FILTER" not in inst["load_errors"]
    assert "NUMBER" in inst["load_errors"]


def test_load_scalar_list_from_file(tmp_path):
    class TestFileList(SettingsManager):
        PROTOCOL_FILTER: list[str] = []

    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("protocol_filter: 502\n", encoding="utf-8")
    inst = TestFileList(label="configuration", env_prefix="TESTFILELIST_", init_env=False)
    inst.load_from_file(cfg)
    assert inst.PROTOCOL_FILTER == ["502"]
    assert not inst["load_errors"]
