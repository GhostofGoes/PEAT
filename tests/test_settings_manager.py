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
from peat.settings_manager import SettingsManager, yaml_error_summary


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


class ContainerSettings(SettingsManager):
    ITEMS: list[str] = []
    ANY_ITEMS: list = []
    ITEM_SET: set[str] = set()
    MAPPING: dict = {}
    PATHS: list[str | Path] = []
    NUMBER: int = 1


@pytest.fixture
def container_settings() -> ContainerSettings:
    return ContainerSettings(label="test", env_prefix="TEST_", init_env=False)


@pytest.mark.parametrize(
    ("key", "value", "expected"),
    [
        ("ITEMS", "a,b", ["a", "b"]),
        ("ITEMS", " a , b ,", ["a", "b"]),
        ("ITEMS", '["a", "b"]', ["a", "b"]),
        ("ITEMS", "[a, b]", ["a", "b"]),
        ("ITEMS", "", []),
        ("ITEMS", "   ", []),
        ("ITEMS", "[1, 2]", ["1", "2"]),
        ("ITEMS", [1, "b"], ["1", "b"]),
        ("ITEMS", "schneider electric,sel", ["schneider electric", "sel"]),
        ("ANY_ITEMS", "x,y", ["x", "y"]),
        ("ANY_ITEMS", "[1, 2]", [1, 2]),
        ("ITEM_SET", "a,b,a", {"a", "b"}),
        ("PATHS", "/one,/two", ["/one", "/two"]),
    ],
)
def test_typecast_list_from_string(container_settings, key, value, expected):
    assert container_settings.typecast(key, value) == expected


def test_typecast_list_from_yaml_scalar(container_settings):
    # Regression test: this used to result in ['m', 'd', '5']
    assert container_settings.typecast("ITEMS", "md5") == ["md5"]


def test_typecast_dict_from_string(container_settings):
    assert container_settings.typecast("MAPPING", '{"a": 1}') == {"a": 1}
    assert container_settings.typecast("MAPPING", "{a: {b: [1, 2]}}") == {"a": {"b": [1, 2]}}
    assert container_settings.typecast("MAPPING", "") == {}
    assert container_settings.typecast("MAPPING", {"a": 1}) == {"a": 1}

    with pytest.raises(ValueError, match="expected a mapping"):
        container_settings.typecast("MAPPING", "a,b")
    with pytest.raises(ValueError, match="expected a mapping"):
        container_settings.typecast("MAPPING", "[1]")
    with pytest.raises(ValueError, match="expected a list"):
        container_settings.typecast("ITEMS", "{a: 1}")
    with pytest.raises(ValueError, match="invalid JSON or YAML"):
        container_settings.typecast("ITEMS", "[a, b")


def test_load_from_environment_list_and_dict(container_settings, mocker):
    mocker.patch.dict(
        os.environ,
        {"TEST_ITEMS": "x, y", "TEST_MAPPING": '{"k": 1}', "TEST_ITEM_SET": '["z"]'},
    )
    container_settings.load_from_environment()
    assert container_settings.ITEMS == ["x", "y"]
    assert container_settings.MAPPING == {"k": 1}
    assert container_settings.ITEM_SET == {"z"}
    assert container_settings.source_of("ITEMS") == "env_configs"
    assert not container_settings["load_errors"]


def test_section_layer_precedence(container_settings):
    inst = container_settings
    assert inst.source_of("NUMBER") == "default_configs"
    assert not inst.non_default("NUMBER")

    inst["file_configs"]["NUMBER"] = 2
    assert inst.NUMBER == 2
    assert inst.source_of("NUMBER") == "file_configs"

    inst["section_configs"]["NUMBER"] = 3
    assert inst.NUMBER == 3
    assert inst.source_of("NUMBER") == "section_configs"

    inst["env_configs"]["NUMBER"] = 4
    assert inst.NUMBER == 4
    assert inst.source_of("NUMBER") == "env_configs"

    inst.NUMBER = 5
    assert inst.NUMBER == 5
    assert inst.source_of("NUMBER") == "runtime_configs"

    for layer, expected in [
        ("runtime_configs", 4),
        ("env_configs", 3),
        ("file_configs", 3),
    ]:
        del inst[layer]["NUMBER"]
        assert inst.NUMBER == expected

    # Only the section layer has a value now
    assert inst.non_default("NUMBER")
    assert not inst.is_default_value("NUMBER")
    del inst["section_configs"]["NUMBER"]
    assert inst.NUMBER == 1
    assert not inst.non_default("NUMBER")

    with pytest.raises(KeyError):
        inst.source_of("NOT_AN_OPTION")


def test_load_errors_recorded(container_settings):
    inst = container_settings
    inst._load_values({"number": "hunter2"}, load_to="file_configs")
    assert ("file_configs", "NUMBER") in inst["load_errors"]
    # The raw value isn't in the error, since it may be sensitive
    assert "hunter2" not in inst["load_errors"][("file_configs", "NUMBER")]
    assert "<value>" in inst["load_errors"][("file_configs", "NUMBER")]
    assert inst.NUMBER == 1  # The bad value isn't loaded

    # A later successful load of the same layer clears the error
    inst._load_values({"number": "7"}, load_to="file_configs")
    assert not inst["load_errors"]
    assert inst.NUMBER == 7


def test_load_from_mapping(container_settings):
    inst = container_settings
    assert inst.load_from_mapping(None, source="empty.yaml") is True
    assert not inst["file_configs"]

    assert inst.load_from_mapping(["not", "a", "mapping"], source="list.yaml") is False
    assert not inst["file_configs"]

    # Legacy multi-app layout
    assert inst.load_from_mapping({"PEAT": {"number": 3}, "OTHER_APP": {}}) is True
    assert inst.NUMBER == 3

    # Errors from a previous file are cleared when a new file is loaded
    inst.load_from_mapping({"number": "bad"})
    assert ("file_configs", "NUMBER") in inst["load_errors"]
    inst.load_from_mapping({"items": "a"})
    assert not inst["load_errors"]
    assert inst.ITEMS == ["a"]


def test_load_from_file_scalar_list(container_settings, tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("items: md5\nmapping: {a: 1}\n", encoding="utf-8")
    assert container_settings.load_from_file(path)
    assert container_settings.ITEMS == ["md5"]
    assert container_settings.MAPPING == {"a": 1}


@pytest.mark.parametrize(
    "value",
    [
        '{"sel": {"user": "admin", "pass": "hunter2" "x": 1}}',
        "{sel: {pass: hunter2}, [",
        '["hunter2", ',
    ],
)
def test_yaml_errors_dont_include_the_value(container_settings, value):
    # The snippet of the input in PyYAML errors may contain passwords
    inst = container_settings
    key = "ITEMS" if value.startswith("[") else "MAPPING"
    inst._load_values({key: value}, load_to="env_configs")
    err = inst["load_errors"][("env_configs", key)]
    assert "invalid JSON or YAML value" in err
    assert "line 1, column" in err
    assert "hunter2" not in err
    assert "admin" not in err


def test_yaml_error_summary():
    try:
        yaml.safe_load('{"pass": "hunter2" "x": 1}')
    except yaml.YAMLError as ex:
        summary = yaml_error_summary(ex)
    assert "hunter2" not in summary
    assert summary.endswith("(line 1, column 20)")
    assert yaml_error_summary(yaml.YAMLError("no mark")) == "syntax error"
