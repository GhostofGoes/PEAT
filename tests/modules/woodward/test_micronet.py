import ftplib

from peat import DeviceData, config, utils
from peat.modules.woodward.micronet import MicroNet


class _FakeMicronetFTP:
    """Minimal stand-in for peat.protocols.FTP serving a hostile directory tree."""

    def __init__(self, tree: dict[str, dict[str, list[str]]]) -> None:
        self.tree = tree
        self.cwd_path = "/"

    def cmd(self, command: str) -> str:
        if command == "PWD":
            return f'257 "{self.cwd_path}"'
        return "213 20240101000000"  # MDTM

    def dir(self):
        node = self.tree[self.cwd_path]
        return node["files"] + node["dirs"], []

    def nlst(self, name: str) -> list[str]:
        return [name] if name in self.tree[self.cwd_path]["files"] else []

    def file_size(self, name: str) -> int:
        return 4 if name in self.tree[self.cwd_path]["files"] else 0

    def cwd(self, name: str) -> None:
        if name not in self.tree:
            raise ftplib.error_perm(f"550 {name}: No such file or directory")
        self.cwd_path = name

    def download_binary(self, filename: str, save_path, save_to_file: bool = True):  # noqa: ARG002
        utils.write_file(b"data", save_path)
        return b"data"


def test_pull_all_files_contained(mocker, tmp_path):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path / "devices"})
    dev = DeviceData(ip="127.0.0.1")
    out_dir = dev.get_out_dir()

    ftp = _FakeMicronetFTP(
        {
            "/": {"files": ["../../../micronet_escape.txt", "ok.txt"], "dirs": ["../../../../d"]},
            "../../../../d": {"files": ["evil.txt"], "dirs": []},
        }
    )
    MicroNet.pull_all_files(dev, "/", out_dir, ftp)

    written = sorted(p for p in tmp_path.rglob("*") if p.is_file())
    assert len(written) == 3
    for path in written:
        assert path.is_relative_to(out_dir), path
    assert (out_dir / "ok.txt").is_file()
    assert (out_dir / "d" / "evil.txt").is_file()
