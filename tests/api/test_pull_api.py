from unittest.mock import MagicMock

import pytest

from peat import PeatError, config, datastore, state
from peat.api.pull_api import pull
from peat.module_selection import ModuleExclusions, compile_targets


def test_pull_static(mocker):
    mocker.patch.object(datastore, "objects", [])
    assert not pull([], "", [])


# ---------------------------------------------------------------------------
# pull --skip-scan
# ---------------------------------------------------------------------------


def _mock_module(name="MockModule"):
    """Return a minimal DeviceModule stand-in that reports a successful pull."""
    mod = MagicMock()
    mod.__name__ = name
    mod.pull.return_value = True
    mod.elastic = MagicMock(return_value={})
    return mod


@pytest.fixture
def _skip_scan_base(mocker, tmp_path):
    """Apply patches common to all skip-scan tests: clean datastore, reset
    error state, redirect file output to tmp_path, and stub out summary
    saving so no real files are written."""
    mocker.patch.object(datastore, "objects", [])
    mocker.patch.dict(state["CONFIG"], {"error": False})
    mocker.patch.dict(
        config["CONFIG"],
        {"DEVICE_DIR": tmp_path / "devices", "TEMP_DIR": tmp_path / "temp"},
    )
    mocker.patch("peat.api.pull_api.utils.save_results_summary")
    mocker.patch("peat.api.pull_api.module_api.lookup_names", return_value=[])


@pytest.mark.usefixtures("_skip_scan_base")
def test_returns_none_with_no_valid_ips(mocker):
    """An empty target list should short-circuit and return None."""
    mocker.patch.dict(config["CONFIG"], {"HOSTS": []})
    mocker.patch("peat.api.pull_api.module_api.lookup_types", return_value=[])

    result = pull([], "unicast_ip", [], skip_scan=True)

    assert result is None


@pytest.mark.usefixtures("_skip_scan_base")
def test_raises_with_multiple_modules_and_no_host_map(mocker):
    """Specifying more than one device type without per-host peat_module
    mappings in the config is ambiguous and should raise PeatError."""
    mocker.patch.dict(config["CONFIG"], {"HOSTS": []})
    mod1, mod2 = _mock_module("Mod1"), _mock_module("Mod2")
    mocker.patch("peat.api.pull_api.module_api.lookup_types", return_value=[mod1, mod2])

    with pytest.raises(PeatError):
        pull(["192.168.0.1"], "unicast_ip", ["Mod1", "Mod2"], skip_scan=True)


@pytest.mark.usefixtures("_skip_scan_base")
def test_uses_fallback_module_when_no_host_map(mocker):
    """When no per-host mapping exists but a single -d module is given,
    that module should be used for all targets."""
    mocker.patch.dict(config["CONFIG"], {"HOSTS": []})
    mod = _mock_module()
    mocker.patch("peat.api.pull_api.module_api.lookup_types", return_value=[mod])

    result = pull(["192.168.0.1"], "unicast_ip", ["MockModule"], skip_scan=True)

    assert result is not None
    dev = datastore.get("192.168.0.1")
    assert dev._module is mod


@pytest.mark.usefixtures("_skip_scan_base")
def test_uses_per_host_module_from_config(mocker):
    """A peat_module defined under a host entry in the YAML config should
    take precedence over any fallback module."""
    mocker.patch.dict(
        config["CONFIG"],
        {
            "HOSTS": [{"identifiers": {"ip": "192.168.0.1"}, "peat_module": "MockModule"}],
        },
    )
    mod = _mock_module()
    mocker.patch(
        "peat.api.pull_api.module_api.lookup_types",
        side_effect=lambda names, **_: [mod] if names else [],
    )

    result = pull(["192.168.0.1"], "unicast_ip", [], skip_scan=True)

    assert result is not None
    dev = datastore.get("192.168.0.1")
    assert dev._module is mod


@pytest.mark.usefixtures("_skip_scan_base")
def test_skips_ip_with_no_resolved_module(mocker):
    """An IP that cannot be mapped to any module should cause pull to
    return None and set state.error to True."""
    mocker.patch.dict(config["CONFIG"], {"HOSTS": []})
    mocker.patch("peat.api.pull_api.module_api.lookup_types", return_value=[])

    result = pull(["192.168.0.1"], "unicast_ip", [], skip_scan=True)

    assert result is None
    assert state.error is True


@pytest.mark.usefixtures("_skip_scan_base")
def test_devices_marked_active_and_verified(mocker):
    """Devices built by skip-scan should be pre-marked as active and
    verified so the pull loop treats them as confirmed targets."""
    mocker.patch.dict(config["CONFIG"], {"HOSTS": []})
    mod = _mock_module()
    mocker.patch("peat.api.pull_api.module_api.lookup_types", return_value=[mod])

    pull(["192.168.0.1"], "unicast_ip", ["MockModule"], skip_scan=True)

    dev = datastore.get("192.168.0.1")
    assert dev._is_active is True
    assert dev._is_verified is True


# ---------------------------------------------------------------------------
# Module exclusions (excluded_modules)
# ---------------------------------------------------------------------------


def _patch_exclusions(mocker, global_mods=(), per_target=None) -> ModuleExclusions:
    """Exclusions for mock modules, which can't be resolved by name."""
    exclusions = ModuleExclusions({})
    exclusions.global_mods.update(global_mods)
    for mod, targets in (per_target or {}).items():
        exclusions.per_target[mod] = compile_targets(mod.__name__, targets)
    mocker.patch("peat.api.pull_api.get_exclusions", return_value=exclusions)
    return exclusions


@pytest.mark.usefixtures("isolated_config", "_skip_scan_base")
def test_skip_scan_global_exclusion_reduces_to_one_module(mocker):
    """'-d sel -x SELRTAC,SEL3620 --skip-scan' should work (one module remains)."""
    mod1, mod2 = _mock_module("Mod1"), _mock_module("Mod2")
    mocker.patch("peat.api.pull_api.module_api.lookup_types", return_value=[mod1, mod2])
    _patch_exclusions(mocker, global_mods=[mod2])

    result = pull(["192.0.2.1"], "unicast_ip", ["Mod1", "Mod2"], skip_scan=True)

    assert result is not None
    assert datastore.get("192.0.2.1")._module is mod1
    mod1.pull.assert_called_once()
    mod2.pull.assert_not_called()


@pytest.mark.usefixtures("isolated_config", "_skip_scan_base")
def test_skip_scan_multiple_modules_error_lists_modules(mocker):
    mod1, mod2 = _mock_module("Mod1"), _mock_module("Mod2")
    mocker.patch("peat.api.pull_api.module_api.lookup_types", return_value=[mod1, mod2])
    _patch_exclusions(mocker)

    with pytest.raises(PeatError, match="Mod1, Mod2"):
        pull(["192.0.2.1"], "unicast_ip", ["Mod1", "Mod2"], skip_scan=True)


@pytest.mark.usefixtures("isolated_config", "_skip_scan_base")
def test_skip_scan_per_ip_exclusion_skips_host(mocker, caplog):
    mod = _mock_module()
    mocker.patch("peat.api.pull_api.module_api.lookup_types", return_value=[mod])
    _patch_exclusions(mocker, per_target={mod: ["192.0.2.2"]})

    result = pull(["192.0.2.1", "192.0.2.2"], "unicast_ip", ["MockModule"], skip_scan=True)

    assert result is not None
    assert result["pull_devices"] == ["192.0.2.1"]
    mod.pull.assert_called_once()
    assert datastore.search("192.0.2.2", "ip") is None
    assert "Skipping pull from 192.0.2.2" in caplog.text


@pytest.mark.usefixtures("isolated_config", "_skip_scan_base")
def test_skip_scan_peat_module_excluded_no_fallback(mocker):
    """The host's peat_module is excluded: no other module is used instead."""
    config.HOSTS = [{"identifiers": {"ip": "192.0.2.1"}, "peat_module": "Mod1"}]
    mod1, mod2 = _mock_module("Mod1"), _mock_module("Mod2")
    mocker.patch(
        "peat.api.pull_api.module_api.lookup_types",
        side_effect=lambda names, **_: [mod1] if names == ["Mod1"] else [mod2],
    )
    _patch_exclusions(mocker, per_target={mod1: ["192.0.2.1"]})

    assert pull(["192.0.2.1"], "unicast_ip", ["Mod2"], skip_scan=True) is None
    mod1.pull.assert_not_called()
    mod2.pull.assert_not_called()


@pytest.mark.usefixtures("isolated_config", "_skip_scan_base")
def test_pull_skips_excluded_verified_device(mocker, caplog):
    """Final check before pulling, for devices found by the scan."""
    mod1, mod2 = _mock_module("Mod1"), _mock_module("Mod2")
    devices = []
    for ip, mod in [("192.0.2.1", mod1), ("192.0.2.2", mod2)]:
        dev = datastore.get(ip)
        dev._is_active = True
        dev._is_verified = True
        dev._module = mod
        devices.append(dev)
    mocker.patch(
        "peat.api.pull_api.scan",
        return_value={"hosts_verified": ["x"], "scan_targets": ["192.0.2.0/30"]},
    )
    mocker.patch("peat.api.pull_api.module_api.lookup_types", return_value=[mod1])
    _patch_exclusions(mocker, per_target={mod2: ["192.0.2.2"]})

    result = pull(["192.0.2.0/30"], "unicast_ip", ["Mod1", "Mod2"])

    assert result is not None
    mod1.pull.assert_called_once_with(devices[0])
    mod2.pull.assert_not_called()
    assert "Skipping pull from 192.0.2.2" in caplog.text


@pytest.mark.usefixtures("isolated_config", "_skip_scan_base")
def test_pull_modules_summary_filtered(mocker):
    mod1, mod2 = _mock_module("Mod1"), _mock_module("Mod2")
    mocker.patch("peat.api.pull_api.module_api.lookup_types", return_value=[mod1, mod2])
    mock_names = mocker.patch(
        "peat.api.pull_api.module_api.lookup_names",
        side_effect=lambda mods: [m.__name__ for m in mods],
    )
    _patch_exclusions(mocker, global_mods=[mod2])

    result = pull(["192.0.2.1"], "unicast_ip", ["Mod1", "Mod2"], skip_scan=True)
    assert result["pull_modules"] == ["Mod1"]
    mock_names.assert_called()
