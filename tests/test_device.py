import pytest

from peat import SCEPTRE, ControlLogix, DeviceData, DeviceModule, SELRelay, config, datastore


def test_device_method_implemented():
    assert ControlLogix.method_implemented("_parse") is False
    assert SELRelay.method_implemented("_parse")
    assert SCEPTRE.method_implemented("_parse")


def test_device_base_methods():
    """
    This is mostly for coverage purposes.
    """
    dev = DeviceData()
    assert DeviceModule._pull(dev) is None
    assert DeviceModule._push(dev, "", "config") is None
    assert DeviceModule._parse(None, None) is None


class _DirModule(DeviceModule):
    """Minimal module that parses directories."""

    @classmethod
    def _parse(cls, file, dev=None):  # noqa: ARG003
        return DeviceData(ip="192.0.2.1")


@pytest.fixture
def parse_env(mocker, tmp_path):
    temp_dir = tmp_path / "temp"
    temp_dir.mkdir()
    mocker.patch.dict(config["CONFIG"], {"TEMP_DIR": temp_dir, "DEVICE_DIR": None})
    mocker.patch.object(datastore, "objects", [])
    input_dir = tmp_path / "relay_export"
    input_dir.mkdir()
    (input_dir / "SET_1.TXT").write_text("settings", encoding="utf-8")
    return input_dir, temp_dir / "relay_export"


def test_device_parse_copies_links_as_links(parse_env, tmp_path):
    input_dir, copied = parse_env
    outside = tmp_path / "outside_secret.txt"
    outside.write_text("secret from elsewhere on the system", encoding="utf-8")
    (input_dir / "CFG.TXT").symlink_to(outside)

    assert _DirModule.parse(input_dir) is not None

    assert (copied / "SET_1.TXT").read_text(encoding="utf-8") == "settings"
    # Previously, the link target's contents were copied into the results
    assert (copied / "CFG.TXT").is_symlink()


def test_device_parse_dangling_link(parse_env, tmp_path):
    input_dir, copied = parse_env
    (input_dir / "dangling.txt").symlink_to(tmp_path / "missing")

    # Previously, shutil.Error and the parse failed
    assert _DirModule.parse(input_dir) is not None
    assert (copied / "SET_1.TXT").is_file()
    assert (copied / "dangling.txt").is_symlink()
