import io
import tarfile

import pytest

from peat import DeviceData, config, datastore
from peat.modules.schneider.sage.sage import Sage


def _add_file(tar: tarfile.TarFile, name: str, data: bytes = b"pwned\n") -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    tar.addfile(info, io.BytesIO(data))


def _add_symlink(tar: tarfile.TarFile, name: str, target: str) -> None:
    info = tarfile.TarInfo(name)
    info.type = tarfile.SYMTYPE
    info.linkname = target
    tar.addfile(info)


@pytest.fixture
def sage_env(mocker, tmp_path):
    mocker.patch.object(datastore, "objects", [])
    mocker.patch.dict(
        config["CONFIG"], {"DEVICE_DIR": tmp_path / "devices", "TEMP_DIR": tmp_path / "temp"}
    )
    outside = tmp_path / "outside"
    outside.mkdir()
    archive = tmp_path / "input" / "sage_backup.tar.gz"
    archive.parent.mkdir()
    return DeviceData(ip="127.0.0.1"), archive, outside


def test_sage_parse_tarball_traversal_contained(sage_env, tmp_path):
    dev, archive, outside = sage_env
    # Malicious tarball built in the test (never stored in the repository)
    with tarfile.open(archive, "w:gz") as tar:
        _add_file(tar, "ata0a/notes.txt", b"benign\n")
        _add_file(tar, "../../../../traversal.txt")
        _add_file(tar, (outside / "absolute.txt").as_posix())

    Sage._parse(archive, dev)

    raw_dir = dev.get_sub_dir("sage_backup_raw_files")
    assert (raw_dir / "ata0a" / "notes.txt").read_bytes() == b"benign\n"
    assert list(outside.iterdir()) == []
    assert not list(tmp_path.rglob("traversal.txt"))
    for path in tmp_path.rglob("*.txt"):
        assert path.is_relative_to(raw_dir), path


def test_sage_parse_tarball_links_skipped(sage_env, tmp_path):
    dev, archive, outside = sage_env
    with tarfile.open(archive, "w:gz") as tar:
        _add_file(tar, "ata0a/notes.txt", b"benign\n")
        _add_symlink(tar, "ata0a/link", outside.as_posix())
        _add_file(tar, "ata0a/link/through_symlink.txt")
        _add_symlink(tar, "ata0a/passwd.txt", "/etc/passwd")

    Sage._parse(archive, dev)

    raw_dir = dev.get_sub_dir("sage_backup_raw_files")
    assert (raw_dir / "ata0a" / "notes.txt").read_bytes() == b"benign\n"
    assert not any(p.is_symlink() for p in tmp_path.rglob("*"))
    assert list(outside.iterdir()) == []
    for path in tmp_path.rglob("*.txt"):
        assert path.is_relative_to(raw_dir), path
