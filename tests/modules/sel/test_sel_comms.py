import pytest

from peat import DeviceData, config, datastore
from peat.modules.sel import sel_comms
from peat.modules.sel.sel_relay import SELRelay
from peat.protocols import FTP


class _FakeRelayFTP(FTP):
    """FTP client for a relay whose NLST output names an absolute directory."""

    def __init__(self, listing: dict[str | None, list[str]]) -> None:
        super().__init__("127.0.0.1")
        self.listing = listing

    def nlst_files(self, directory: str | None = None) -> list[str]:
        return self.listing.get(directory, [])

    def download_binary(self, filename, save_path=None, save_to_file=True):  # noqa: ARG002
        return f"data for {filename}".encode()


def test_pull_files_directory_name_contained(mocker, tmp_path):
    mocker.patch.object(datastore, "objects", [])
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path / "devices"})
    dev = DeviceData(ip="127.0.0.1")
    dev._module = SELRelay

    # Entries without a "." are treated as directories by populate_file_listing()
    hostile_dir = (tmp_path / "sel_escape").as_posix()
    if "." in hostile_dir:
        pytest.skip("temporary directory path contains a '.'")

    comms = _FakeRelayFTP({None: ["SET_ALL.TXT", hostile_dir], hostile_dir: ["SET_1.CFG"]})
    files = sel_comms.pull_files(dev, comms)
    assert files

    relay_dir = dev.get_sub_dir("relay_files")
    written = sorted(p for p in tmp_path.rglob("*") if p.is_file())
    assert written
    for path in written:
        assert path.is_relative_to(relay_dir), path
    assert not (tmp_path / "sel_escape").exists()
