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


def _add_dir(tar: tarfile.TarFile, name: str) -> None:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE
    info.mode = 0o755  # TarInfo defaults to 0o644, which an unprivileged user can't traverse
    tar.addfile(info)


@pytest.mark.parametrize("data_filter", [True, False])
def test_sage_parse_tarball_unsafe_dir_skipped(sage_env, tmp_path, monkeypatch, data_filter):
    dev, archive, _ = sage_env
    with tarfile.open(archive, "w:gz") as tar:
        _add_dir(tar, "../dirup")
        _add_dir(tar, "ata0a")
        _add_file(tar, "ata0a/notes.txt", b"benign\n")

    if not data_filter:
        # Python 3.11.0 - 3.11.3 have no PEP 706 extraction filters
        monkeypatch.delattr(tarfile, "data_filter")
        monkeypatch.setattr(
            tarfile.TarFile, "extraction_filter", staticmethod(tarfile.fully_trusted_filter)
        )

    Sage._parse(archive, dev)

    raw_dir = dev.get_sub_dir("sage_backup_raw_files")
    # One hostile directory doesn't stop the safe members from being extracted
    assert (raw_dir / "ata0a" / "notes.txt").read_bytes() == b"benign\n"
    assert not list(tmp_path.rglob("dirup"))
