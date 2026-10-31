import pytest

from peat import PeatError, SELRelay, datastore, push


def test_push(mocker, tmp_path):
    mocker.patch.object(datastore, "objects")

    # Bad input source
    with pytest.raises(PeatError):
        push([], "", [], input_source=None, push_type="")

    # Bad push type
    with pytest.raises(PeatError):
        push([], "", [], input_source=tmp_path, push_type="invalidpushtype")

    # Skip scan
    with pytest.raises(PeatError):
        push([], "unicast_ip", ["clx", "extra"], tmp_path, "config", skip_scan=True)
    assert not push([], "unicast_ip", ["clx"], tmp_path, "config", skip_scan=True)

    # with scan
    assert not push([], "unicast_ip", ["clx"], tmp_path, "config")


# ---------------------------------------------------------------------------
# Module exclusions (excluded_modules)
# ---------------------------------------------------------------------------


@pytest.fixture
def push_file(mocker, tmp_path):
    mocker.patch.object(datastore, "objects", [])
    path = tmp_path / "SET_1.TXT"
    path.write_text("test", encoding="utf-8")
    return path


def test_push_skip_scan_no_modules_raises(isolated_config, push_file):
    # Regression test: this used to raise an IndexError
    isolated_config.EXCLUDED_MODULES = {"selrelay": True}
    with pytest.raises(PeatError, match="No PEAT module is available"):
        push(["192.0.2.1"], "unicast_ip", ["selrelay"], push_file, "config", skip_scan=True)

    with pytest.raises(PeatError, match="No PEAT module is available"):
        push(["192.0.2.1"], "unicast_ip", ["notamodule"], push_file, "config", skip_scan=True)


@pytest.mark.usefixtures("isolated_config")
def test_push_skip_scan_multiple_modules_raises(push_file):
    with pytest.raises(PeatError, match="matches more than 1 module"):
        push(["192.0.2.1"], "unicast_ip", ["sel"], push_file, "config", skip_scan=True)


def test_push_skip_scan_alias_with_exclusions(isolated_config, push_file, mocker):
    mock_push = mocker.patch.object(SELRelay, "push", return_value=True)
    isolated_config.EXCLUDED_MODULES = {"SELRTAC": True, "SEL3620": True}
    assert push(["192.0.2.1"], "unicast_ip", ["sel"], push_file, "config", skip_scan=True)
    mock_push.assert_called_once()


def test_push_per_ip_exclusion(isolated_config, push_file, mocker, caplog):
    mock_push = mocker.patch.object(SELRelay, "push", return_value=True)
    isolated_config.EXCLUDED_MODULES = {"selrelay": ["192.0.2.2"]}

    assert push(["192.0.2.1", "192.0.2.2"], "unicast_ip", ["selrelay"], push_file, "config", True)
    mock_push.assert_called_once()
    assert mock_push.call_args.kwargs["dev"].ip == "192.0.2.1"
    assert datastore.search("192.0.2.2", "ip") is None
    assert "Skipping push to 192.0.2.2" in caplog.text

    # Every target excluded
    mock_push.reset_mock()
    isolated_config.EXCLUDED_MODULES = {"selrelay": ["192.0.2.0/24"]}
    assert not push(["192.0.2.3"], "unicast_ip", ["selrelay"], push_file, "config", True)
    mock_push.assert_not_called()


def test_push_skips_excluded_verified_device(isolated_config, push_file, mocker, caplog):
    mock_push = mocker.patch.object(SELRelay, "push", return_value=True)
    for ip in ["192.0.2.1", "192.0.2.2"]:
        dev = datastore.get(ip)
        dev._is_active = True
        dev._is_verified = True
        dev._module = SELRelay
    mocker.patch("peat.api.push_api.scan", return_value={"hosts_verified": ["x"]})
    isolated_config.EXCLUDED_MODULES = {"selrelay": ["192.0.2.1"]}

    assert push(["192.0.2.0/30"], "unicast_ip", ["selrelay"], push_file, "config")
    mock_push.assert_called_once()
    assert mock_push.call_args.kwargs["dev"].ip == "192.0.2.2"
    assert "Skipping push to 192.0.2.1" in caplog.text


@pytest.mark.usefixtures("isolated_config")
def test_push_exception_logging_uses_device(push_file, mocker, caplog):
    # Regression test: this used to raise a NameError ("dev" instead of "device")
    mocker.patch.object(SELRelay, "push", side_effect=RuntimeError("boom"))
    assert push(["192.0.2.1"], "unicast_ip", ["selrelay"], push_file, "config", True) is False
    assert "Failed to push to 192.0.2.1" in caplog.text


def test_push_skip_scan_expanded_alias_with_exclusions(isolated_config, push_file, mocker):
    """'peat push -d sel -x selrtac,sel3620 --push-skip-scan' (names expanded by the CLI)"""
    mock_push = mocker.patch.object(SELRelay, "push", return_value=True)
    isolated_config.EXCLUDED_MODULES = {"SELRTAC": True, "SEL3620": True}
    types = ["SEL3620", "SELRTAC", "SELRelay"]
    assert push(["192.0.2.1"], "unicast_ip", types, push_file, "config", skip_scan=True)
    mock_push.assert_called_once()

    isolated_config.EXCLUDED_MODULES = {}
    with pytest.raises(PeatError, match="more than 1 device type"):
        push(["192.0.2.1"], "unicast_ip", types, push_file, "config", skip_scan=True)
