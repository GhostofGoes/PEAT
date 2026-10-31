"""
Tests for how initialize_peat() loads the configuration file, applies
command sections, and handles excluded_modules.
"""

from pathlib import Path

import pytest
import yaml

from peat import PeatError, config, config_crypto, datastore, state
from peat.api.config_builder_api import generate_simple_config
from peat.init import initialize_peat
from peat.settings import Configuration


@pytest.fixture
def init_env(isolated_config, mocker):
    """Isolate the global state changed by initialize_peat()."""
    # setup_logging() removes all loguru sinks, including the one used by caplog
    mocker.patch("peat.init.setup_logging")
    mocker.patch.object(datastore, "objects", [])
    mocker.patch.dict(datastore.global_options, {}, clear=True)
    mocker.patch.dict(state["runtime_configs"])
    return isolated_config


def _write_config(tmp_path: Path, data: dict, name: str = "config.yaml") -> Path:
    path = tmp_path / name
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def _init(path: Path | None, func: str, **kwargs) -> None:
    conf = {"out_dir": None, "run_dir": None, "func": func, **kwargs}
    if path is not None:
        conf["config_file"] = str(path)
    initialize_peat(conf)


@pytest.mark.usefixtures("init_env")
def test_initialize_applies_section(tmp_path, caplog):
    path = _write_config(
        tmp_path,
        {
            "device_types": ["all"],
            "intensive_scan": False,
            "pull": {"device_types": ["sel"], "intensive_scan": True, "skip-scan": True},
        },
    )

    _init(path, "pull")
    assert config.DEVICE_TYPES == ["sel"]
    assert config.INTENSIVE_SCAN is True
    assert config.source_of("DEVICE_TYPES") == "section_configs"
    assert "Applied the 'pull' section of the config: device_types, intensive_scan" in (
        caplog.text
    )
    assert "Unknown option 'skip-scan' in the 'pull' section" in caplog.text


@pytest.mark.usefixtures("init_env")
def test_initialize_other_command_ignores_section(tmp_path):
    path = _write_config(tmp_path, {"device_types": ["all"], "pull": {"device_types": ["sel"]}})
    _init(path, "parse")
    assert config.DEVICE_TYPES == ["all"]
    assert not config["section_configs"]


@pytest.mark.usefixtures("init_env")
def test_initialize_cli_beats_section(tmp_path, mocker):
    path = _write_config(tmp_path, {"pull": {"device_types": ["sel"], "debug": 1}})
    mocker.patch.dict("os.environ", {"PEAT_DEBUG": "2"})
    config.load_from_environment()

    _init(path, "pull", device_types=["m340"])
    assert config.DEVICE_TYPES == ["m340"]
    assert config.source_of("DEVICE_TYPES") == "runtime_configs"
    assert config.DEBUG == 2  # The environment variable beats the section


@pytest.mark.usefixtures("init_env")
def test_initialize_sweep_from_config(tmp_path):
    # Regression test: "--sweep" not being specified used to override the config
    path = _write_config(tmp_path, {"scan": {"sweep": True}})
    _init(path, "scan", scan_sweep=None)
    assert config.SCAN_SWEEP is True


@pytest.mark.usefixtures("init_env")
def test_initialize_merges_exclusions(tmp_path, mocker):
    path = _write_config(
        tmp_path,
        {
            "excluded_modules": {"SEL": ["192.0.2.5"]},
            "pull": {"excluded_modules": {"M340": True}},
        },
    )
    mocker.patch.dict("os.environ", {"PEAT_EXCLUDED_MODULES": "SEL=192.0.2.6"})
    config.load_from_environment()

    _init(path, "pull", excluded_modules=["ControlLogix"])
    assert config.EXCLUDED_MODULES == {
        "SEL": ["192.0.2.5", "192.0.2.6"],
        "M340": True,
        "ControlLogix": True,
    }


@pytest.mark.parametrize(
    "data",
    [{"excluded_modules": 5}, {"pull": {"excluded_modules": {"SEL": 5}}}],
)
@pytest.mark.usefixtures("init_env")
def test_initialize_bad_exclusions_aborts(tmp_path, caplog, data):
    path = _write_config(tmp_path, data)
    with pytest.raises(PeatError, match="refusing to run"):
        _init(path, "pull")
    assert "Failed to load configuration option 'excluded_modules'" in caplog.text


@pytest.mark.usefixtures("init_env")
def test_initialize_bad_exclusions_env_aborts(mocker):
    mocker.patch.dict("os.environ", {"PEAT_EXCLUDED_MODULES": "SEL="})
    config.load_from_environment()
    with pytest.raises(PeatError, match="excluded_modules"):
        _init(None, "scan")


@pytest.mark.usefixtures("init_env")
def test_initialize_logs_load_errors(tmp_path, caplog, mocker):
    # Previously these errors were logged before logging was configured (never shown)
    mocker.patch.dict("os.environ", {"PEAT_MAX_THREADS": "abc"})
    config.load_from_environment()
    path = _write_config(tmp_path, {"default_timeout": "slow"})

    _init(path, "scan")
    assert (
        "Failed to load configuration option 'max_threads' (environment variable "
        "PEAT_MAX_THREADS)" in caplog.text
    )
    assert "Failed to load configuration option 'default_timeout' (config file)" in caplog.text


@pytest.mark.parametrize("content", ["- just\n- a list\n", "key: [unclosed\n"])
@pytest.mark.usefixtures("init_env")
def test_initialize_bad_config_file_aborts(tmp_path, caplog, content):
    path = tmp_path / "bad.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(PeatError, match="Failed to load the configuration file"):
        _init(path, "scan")
    assert "bad.yaml" in caplog.text


@pytest.mark.usefixtures("init_env")
def test_initialize_missing_config_file_aborts(tmp_path):
    with pytest.raises(PeatError, match="Failed to load the configuration file"):
        _init(tmp_path / "missing.yaml", "scan")


@pytest.mark.usefixtures("init_env")
def test_initialize_encrypted_config_with_sections(tmp_path, mocker):
    # Regression test: encrypted configs used to fail with a TypeError
    path = _write_config(
        tmp_path, {"pull": {"skip_scan": True}, "excluded_modules": ["M340"]}, "plain.yaml"
    )
    assert config_crypto.encrypt_config(path, "pw")
    enc_path = tmp_path / "encrypted_plain.yaml"
    assert config_crypto.is_encrypted_file(enc_path)
    assert not config_crypto.is_encrypted_file(path)

    mock_getpass = mocker.patch("peat.config_crypto.getpass.getpass", return_value="pw")
    _init(enc_path, "pull")
    mock_getpass.assert_called_once()
    assert config.PULL_SKIP_SCAN is True
    assert config.EXCLUDED_MODULES == {"M340": True}


@pytest.mark.usefixtures("init_env")
def test_initialize_encrypted_config_wrong_password(tmp_path, mocker, caplog):
    path = _write_config(tmp_path, {"debug": 1}, "plain.yaml")
    assert config_crypto.encrypt_config(path, "pw")
    mocker.patch("peat.config_crypto.getpass.getpass", return_value="wrong")

    with pytest.raises(PeatError, match="Failed to load the configuration file"):
        _init(tmp_path / "encrypted_plain.yaml", "scan")
    assert "is the password correct?" in caplog.text


def test_is_encrypted_file_missing(tmp_path):
    assert config_crypto.is_encrypted_file(tmp_path / "missing.yaml") is False
    assert config_crypto.is_encrypted_file(tmp_path) is False


def test_config_builder_output_loads():
    data = yaml.safe_load(generate_simple_config([("192.0.2.1", "host-1", "SELRelay")]))
    conf = Configuration("configuration", env_prefix="TEST_CONF_", init_env=False)
    assert conf.load_from_mapping(data)
    assert not conf["load_errors"]
    assert conf.apply_command_section("scan") == ({}, [])


@pytest.mark.usefixtures("init_env")
def test_initialize_section_errors_dont_leak_to_other_commands(tmp_path):
    # Regression test: errors from the 'pull' section used to remain after it was removed
    path = _write_config(tmp_path, {"pull": {"excluded_modules": 5}})
    with pytest.raises(PeatError, match="refusing to run"):
        _init(path, "pull")

    _init(path, "scan")
    assert not config["load_errors"]


@pytest.mark.usefixtures("init_env")
def test_initialize_section_out_dir_beats_top_level(tmp_path, caplog):
    path = _write_config(
        tmp_path,
        {"out_dir": str(tmp_path / "top"), "scan": {"out_dir": str(tmp_path / "scan")}},
    )
    initialize_peat({"func": "scan", "config_file": str(path), "run_name": "run1"})
    assert config.OUT_DIR == tmp_path / "scan"
    assert config.RUN_DIR == tmp_path / "scan" / "run1"
    assert config.LOG_DIR.parent == config.RUN_DIR
    assert "Applied the 'scan' section of the config: out_dir" in caplog.text

    # "-o" on the command line beats both
    initialize_peat(
        {
            "func": "scan",
            "config_file": str(path),
            "run_name": "run2",
            "out_dir": str(tmp_path / "cli"),
        }
    )
    assert config.OUT_DIR == tmp_path / "cli"
    assert config.RUN_DIR == tmp_path / "cli" / "run2"


@pytest.mark.usefixtures("init_env")
def test_initialize_logs_overridden_section_values(tmp_path, caplog, mocker):
    path = _write_config(tmp_path, {"pull": {"debug": 1, "intensive_scan": True}})
    mocker.patch.dict("os.environ", {"PEAT_DEBUG": "2"})
    config.load_from_environment()

    _init(path, "pull")
    assert "Applied the 'pull' section of the config: intensive_scan" in caplog.text
    assert (
        "Options in the 'pull' section of the config that are overridden by "
        "environment variables or command line arguments: debug"
    ) in caplog.text


@pytest.mark.usefixtures("init_env")
def test_initialize_load_errors_dont_log_secrets(caplog, mocker):
    # A malformed environment variable with credentials must not end up in the logs
    mocker.patch.dict(
        "os.environ",
        {
            "PEAT_DEVICE_OPTIONS": '{"sel": {"user": "admin", "pass": "hunter2" "x": 1}}',
            "PEAT_MAX_THREADS": "hunter2",
        },
    )
    config.load_from_environment()
    _init(None, "scan")
    assert "Failed to load configuration option 'device_options'" in caplog.text
    assert "Failed to load configuration option 'max_threads'" in caplog.text
    assert "hunter2" not in caplog.text
    assert "admin" not in caplog.text
