import pytest
import yaml

from peat.consts import lower_dict
from peat.data import DeviceData
from peat.settings import (
    Configuration,
    exclusions_to_tokens,
    merge_excluded_modules,
    merged_excluded_modules,
    normalize_excluded_modules,
)


@pytest.fixture
def yml_config(examples_path) -> dict:
    return yaml.safe_load(examples_path("peat-config.yaml").read_text())


def test_example_yaml_config_matches_settings(yml_config):
    conf = Configuration("configuration", env_prefix="TEST_CONF_", init_env=False)
    exported = lower_dict(conf.json_dict(include_none_vals=True))
    assert sorted(exported.keys()) == sorted(yml_config.keys())


def test_device_options_defaults(yml_config, deep_compare):
    deep_compare(
        DeviceData().options.to_dict(),
        yml_config["device_options"],
        exclude_regexes=r"\['(user|pass|users|passwords|creds|pull_delay|ec)'\]",
    )


def test_simple_example_yaml_config_matches_settings(examples_path):
    conf = Configuration("configuration", env_prefix="TEST_CONF_", init_env=False)
    exported = lower_dict(conf.json_dict(include_none_vals=True))
    yml_config = yaml.safe_load(examples_path("peat-config-simple.yaml").read_text())
    assert sorted(exported.keys()) == sorted(yml_config.keys())


# ---------------------------------------------------------------------------
# Command sections, device_types, and excluded_modules
# ---------------------------------------------------------------------------


@pytest.fixture
def fresh_config() -> Configuration:
    return Configuration("configuration", env_prefix="TEST_CONF_", init_env=False)


def test_apply_command_section_basic(fresh_config):
    conf = fresh_config
    conf.load_from_mapping({"intensive_scan": False, "pull": {"intensive_scan": True}})

    applied, warnings = conf.apply_command_section("pull")
    assert applied == {"INTENSIVE_SCAN": True}
    assert warnings == []
    assert conf.INTENSIVE_SCAN is True
    assert conf.source_of("INTENSIVE_SCAN") == "section_configs"
    assert conf["section_command"] == "pull"

    # The section for another command doesn't apply
    assert conf.apply_command_section("scan") == ({}, [])
    assert conf.INTENSIVE_SCAN is False
    assert conf.source_of("INTENSIVE_SCAN") == "file_configs"

    # Environment variables override sections, and CLI/runtime override both
    conf.apply_command_section("pull")
    conf["env_configs"]["INTENSIVE_SCAN"] = False
    assert conf.INTENSIVE_SCAN is False
    conf.INTENSIVE_SCAN = True
    assert conf.INTENSIVE_SCAN is True
    assert conf.source_of("INTENSIVE_SCAN") == "runtime_configs"


@pytest.mark.parametrize("command", [None, "", "heat", "pillage", "encrypt-config"])
def test_apply_command_section_no_section(fresh_config, command):
    fresh_config.load_from_mapping({"pull": {"intensive_scan": True}})
    assert fresh_config.apply_command_section(command) == ({}, [])
    assert not fresh_config["section_configs"]


def test_apply_command_section_aliases(fresh_config):
    conf = fresh_config
    conf.load_from_mapping(
        {
            "scan": {"sweep": True, "skip_scan": True},
            "pull": {"skip_scan": True},
            "push": {"Skip_Scan": "yes"},
        }
    )

    applied, warnings = conf.apply_command_section("scan")
    assert applied == {"SCAN_SWEEP": True}
    assert len(warnings) == 1
    assert "Unknown option 'skip_scan'" in warnings[0]

    assert conf.apply_command_section("pull") == ({"PULL_SKIP_SCAN": True}, [])
    assert conf.PULL_SKIP_SCAN is True
    assert conf.SCAN_SWEEP is False

    assert conf.apply_command_section("push") == ({"PUSH_SKIP_SCAN": True}, [])
    assert conf.PUSH_SKIP_SCAN is True
    assert conf.PULL_SKIP_SCAN is False


def test_apply_command_section_warnings(fresh_config):
    conf = fresh_config
    conf.load_from_mapping(
        {
            "pull": {
                "metadata": {"name": "x"},
                "scan": {"intensive_scan": True},
                "skip-scan": True,
                "device_types": ["sel"],
                "DEVICE_TYPES": ["m340"],
                "intensive_scan": None,
            }
        }
    )

    applied, warnings = conf.apply_command_section("pull")
    assert applied == {"DEVICE_TYPES": ["m340"]}
    assert len(warnings) == 4
    assert "'metadata' isn't allowed" in warnings[0]
    assert "'scan' isn't allowed" in warnings[1]
    assert "Unknown option 'skip-scan'" in warnings[2]
    assert "more than once" in warnings[3]
    assert conf.METADATA.get("name") != "x"
    assert conf.INTENSIVE_SCAN is False


def test_apply_command_section_non_mapping(fresh_config):
    fresh_config["file_configs"]["PULL"] = ["a"]
    applied, warnings = fresh_config.apply_command_section("pull")
    assert applied == {}
    assert len(warnings) == 1
    assert "must be a mapping" in warnings[0]


def test_apply_command_section_deep_merge(fresh_config):
    conf = fresh_config
    conf.load_from_mapping(
        {
            "hash_algorithms": ["md5", "sha1"],
            "device_options": {"ftp": {"user": "admin"}, "sel": {"pull_methods": ["ftp"]}},
            "pull": {
                "device_options": {"sel": {"pull_methods": ["telnet"]}},
                "hash_algorithms": ["sha256"],
            },
        }
    )

    conf.apply_command_section("pull")
    assert conf.DEVICE_OPTIONS == {
        "ftp": {"user": "admin"},
        "sel": {"pull_methods": ["telnet"]},
    }
    assert conf.HASH_ALGORITHMS == ["sha256"]  # Lists replace

    # The values in the file aren't modified by the merge
    assert conf["file_configs"]["DEVICE_OPTIONS"]["sel"] == {"pull_methods": ["ftp"]}


def test_apply_command_section_clears_previous(fresh_config):
    conf = fresh_config
    conf.load_from_mapping({"pull": {"device_types": ["sel"]}, "parse": {"debug": 1}})

    conf.apply_command_section("pull")
    assert conf.DEVICE_TYPES == ["sel"]

    applied, _ = conf.apply_command_section("parse")
    assert applied == {"DEBUG": 1}
    assert conf.DEVICE_TYPES == []
    assert "DEVICE_TYPES" not in conf["section_configs"]


def test_apply_command_section_bad_value(fresh_config):
    fresh_config.load_from_mapping({"pull": {"max_threads": "abc", "debug": 2}})
    applied, _ = fresh_config.apply_command_section("pull")
    assert applied == {"DEBUG": 2}
    assert ("section_configs", "MAX_THREADS") in fresh_config["load_errors"]

    # Errors from a section are removed when another section is applied
    fresh_config.apply_command_section("scan")
    assert ("section_configs", "MAX_THREADS") not in fresh_config["load_errors"]


def test_apply_command_section_overridden_not_applied(fresh_config):
    conf = fresh_config
    conf.load_from_mapping(
        {
            "pull": {
                "skip_scan": True,
                "debug": 2,
                "intensive_scan": True,
                "excluded_modules": {"M340": True},
            }
        }
    )
    conf["env_configs"]["DEBUG"] = 1
    conf.PULL_SKIP_SCAN = False  # e.g. from the command line
    conf.EXCLUDED_MODULES = {"SELRelay": True}

    applied, _ = conf.apply_command_section("pull")
    # Exclusions are combined from every source, so they're always applied
    assert applied == {"INTENSIVE_SCAN": True, "EXCLUDED_MODULES": {"M340": True}}
    assert set(conf["section_configs"]) == {
        "PULL_SKIP_SCAN",
        "DEBUG",
        "INTENSIVE_SCAN",
        "EXCLUDED_MODULES",
    }


def test_apply_command_section_out_dir(fresh_config, tmp_path):
    # A section's out_dir overrides the top-level out_dir
    conf = fresh_config
    conf.load_from_mapping(
        {"out_dir": str(tmp_path / "top"), "scan": {"out_dir": str(tmp_path / "scan")}}
    )
    assert conf.OUT_DIR == tmp_path / "top"
    assert conf.source_of("OUT_DIR") == "file_configs"
    assert conf.RUN_DIR.parent == tmp_path / "top"

    applied, _ = conf.apply_command_section("scan")
    assert "OUT_DIR" in applied
    assert conf.OUT_DIR == tmp_path / "scan"

    # The section's value doesn't apply to other commands
    conf.apply_command_section("pull")
    assert conf.OUT_DIR == tmp_path / "top"

    # A runtime value (e.g. "-o") overrides both
    conf.OUT_DIR = tmp_path / "cli"
    applied, _ = conf.apply_command_section("scan")
    assert "OUT_DIR" not in applied
    assert conf.OUT_DIR == tmp_path / "cli"


def test_apply_command_section_from_env(fresh_config, mocker):
    mocker.patch.dict("os.environ", {"TEST_CONF_PULL": '{"intensive_scan": true}'})
    fresh_config.load_from_environment()
    applied, _ = fresh_config.apply_command_section("pull")
    assert applied == {"INTENSIVE_SCAN": True}


def test_section_yaml_merge_keys(fresh_config, tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        "common: &common\n"
        "  intensive_scan: true\n"
        "  assume_online: true\n"
        "scan:\n"
        "  <<: *common\n"
        "  sweep: true\n"
        "pull:\n"
        "  <<: *common\n"
        "  assume_online: false\n",
        encoding="utf-8",
    )
    assert fresh_config.load_from_file(path)

    applied, warnings = fresh_config.apply_command_section("scan")
    assert warnings == []
    assert applied == {"INTENSIVE_SCAN": True, "ASSUME_ONLINE": True, "SCAN_SWEEP": True}

    applied, warnings = fresh_config.apply_command_section("pull")
    assert warnings == []
    assert applied == {"INTENSIVE_SCAN": True, "ASSUME_ONLINE": False}


def test_example_module_selection_config(examples_path, fresh_config):
    assert fresh_config.load_from_file(examples_path("peat-config-module-selection.yaml"))
    assert not fresh_config["load_errors"]

    for command in ["scan", "pull", "push", "parse"]:
        applied, warnings = fresh_config.apply_command_section(command)
        assert applied, command
        assert warnings == [], command

    fresh_config.apply_command_section("pull")
    assert fresh_config.DEVICE_TYPES == ["sel"]
    assert fresh_config.DEVICE_OPTIONS["ftp"]["timeout"] == 10.0
    assert fresh_config.DEVICE_OPTIONS["sel"]["pull_methods"] == ["ftp", "telnet"]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, {}),
        ("", {}),
        ({}, {}),
        (
            {"ControlLogix": True, "SEL": ["192.0.2.5", "192.0.2.6"]},
            {"ControlLogix": True, "SEL": ["192.0.2.5", "192.0.2.6"]},
        ),
        (["ControlLogix", "M340"], {"ControlLogix": True, "M340": True}),
        ({"ControlLogix": None}, {"ControlLogix": True}),
        ({"SEL": "192.0.2.5, 192.0.2.6"}, {"SEL": ["192.0.2.5", "192.0.2.6"]}),
        ({"SEL": False}, {"SEL": False}),
        ({"SEL": "yes", "M340": "Off"}, {"SEL": True, "M340": False}),
        ({"SEL": []}, {"SEL": []}),
        ({"SEL": [1234, "COM4"]}, {"SEL": ["1234", "COM4"]}),
        ("ControlLogix,M340", {"ControlLogix": True, "M340": True}),
        (
            "ControlLogix SEL=192.0.2.5,192.0.2.6",
            {"ControlLogix": True, "SEL": ["192.0.2.5", "192.0.2.6"]},
        ),
        # Whitespace around "," and "=" doesn't separate tokens
        ("SEL=192.0.2.5, 192.0.2.6", {"SEL": ["192.0.2.5", "192.0.2.6"]}),
        (
            "ControlLogix  SEL = 192.0.2.5 ,192.0.2.6\tM340",
            {"ControlLogix": True, "SEL": ["192.0.2.5", "192.0.2.6"], "M340": True},
        ),
        ("ControlLogix, M340", {"ControlLogix": True, "M340": True}),
        ('{ControlLogix: true, SEL: ["192.0.2.5"]}', {"ControlLogix": True, "SEL": ["192.0.2.5"]}),
        ('{"ControlLogix": true}', {"ControlLogix": True}),
        ("[m340, sel3620]", {"m340": True, "sel3620": True}),
        (
            ["clx", "sel=192.0.2.5,192.0.2.6", "m340,sel3620"],
            {"clx": True, "sel": ["192.0.2.5", "192.0.2.6"], "m340": True, "sel3620": True},
        ),
        # Combining rules for the same module, case-insensitive
        (["SEL=192.0.2.1", "sel=192.0.2.2", "Sel=192.0.2.1"], {"SEL": ["192.0.2.1", "192.0.2.2"]}),
        (["sel=192.0.2.1", "SEL"], {"sel": True}),
        ({"SEL": True, "sel": False}, {"SEL": True}),
    ],
)
def test_normalize_excluded_modules(value, expected):
    assert normalize_excluded_modules(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        5,
        {"SEL": 5},
        {"SEL": {"a": 1}},
        {"SEL": [None]},
        {"SEL": [True]},
        {"": True},
        ["SEL="],
        "SEL = ",
        "ControlLogix SEL=",
        ["=192.0.2.5"],
        [1],
        "{bad",
        "[1, [2]]",
    ],
)
def test_normalize_excluded_modules_invalid(value):
    with pytest.raises(ValueError):
        normalize_excluded_modules(value)


def test_excluded_modules_typecast(fresh_config):
    assert fresh_config.typecast("EXCLUDED_MODULES", "clx") == {"clx": True}
    fresh_config.load_from_dict({"excluded_modules": ["clx", "sel=192.0.2.5"]})
    assert fresh_config.EXCLUDED_MODULES == {"clx": True, "sel": ["192.0.2.5"]}

    fresh_config.load_from_mapping({"excluded_modules": 5})
    assert ("file_configs", "EXCLUDED_MODULES") in fresh_config["load_errors"]


def test_merged_excluded_modules_union(fresh_config):
    conf = fresh_config
    conf["file_configs"]["EXCLUDED_MODULES"] = {"SEL": ["192.0.2.1"], "m340": ["192.0.2.9"]}
    conf["section_configs"]["EXCLUDED_MODULES"] = {"M340": False}
    conf["env_configs"]["EXCLUDED_MODULES"] = normalize_excluded_modules(
        "sel=192.0.2.2 ControlLogix"
    )
    conf["runtime_configs"]["EXCLUDED_MODULES"] = {"selrtac": True}

    assert merged_excluded_modules(conf) == {
        "SEL": ["192.0.2.1", "192.0.2.2"],
        "m340": ["192.0.2.9"],
        "ControlLogix": True,
        "selrtac": True,
    }

    # A higher precedence source can't remove anything
    conf["runtime_configs"]["EXCLUDED_MODULES"] = {"SEL": True, "ControlLogix": False}
    merged = merged_excluded_modules(conf)
    assert merged["SEL"] is True
    assert merged["ControlLogix"] is True

    # The input isn't modified
    assert conf["file_configs"]["EXCLUDED_MODULES"]["SEL"] == ["192.0.2.1"]


def test_merge_excluded_modules():
    first = {"SEL": ["192.0.2.1"]}
    assert merge_excluded_modules(first, None, {"sel": ["192.0.2.2"]}) == {
        "SEL": ["192.0.2.1", "192.0.2.2"]
    }
    assert first == {"SEL": ["192.0.2.1"]}
    assert merge_excluded_modules() == {}


def test_exclusions_to_tokens():
    rules = {"ControlLogix": True, "SEL": ["192.0.2.5", "192.0.2.6"], "M340": False, "X": []}
    tokens = exclusions_to_tokens(rules)
    assert tokens == ["ControlLogix", "SEL=192.0.2.5,192.0.2.6"]
    assert normalize_excluded_modules(tokens) == {
        "ControlLogix": True,
        "SEL": ["192.0.2.5", "192.0.2.6"],
    }


def test_device_types_and_targets_options(fresh_config, mocker):
    mocker.patch.dict(
        "os.environ",
        {"TEST_CONF_DEVICE_TYPES": "sel, schneider electric", "TEST_CONF_TARGETS": "192.0.2.1"},
    )
    fresh_config.load_from_environment()
    assert fresh_config.DEVICE_TYPES == ["sel", "schneider electric"]
    assert fresh_config.TARGETS == ["192.0.2.1"]

    fresh_config.load_from_mapping({"device_types": "m340"})
    assert fresh_config["file_configs"]["DEVICE_TYPES"] == ["m340"]
