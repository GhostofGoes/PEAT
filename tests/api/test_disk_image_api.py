import json
import os
import plistlib
import shutil
import stat
import subprocess
import tempfile
import textwrap
import time
from pathlib import Path

import pytest

from peat import config, consts, datastore, utils
from peat.api import disk_image_api
from peat.api.disk_image_api import (
    UnlockSecrets,
    find_files,
    is_bitlocker,
    is_disk_image,
    is_image_attached_windows,
    is_luks,
    mount_image_windows,
    read_volume_header,
    remove_dataless_files,
    search_image,
    search_volumes_windows,
    validate_image_mounting_macos,
    validate_image_mounting_windows,
)
from peat.api.parse_api import parse


def _is_project_file(path: str | Path) -> bool:
    """The files the tests look for: SEL relay settings (SET_ALL.TXT) and databases (.rdb)."""
    name = Path(path).name.lower()
    return name == "set_all.txt" or name.endswith(".rdb")


def _search_dir(
    source: Path | str,
    results: Path,
    exclude_system_dirs: bool | None = None,
    recursive: bool = True,
) -> bool:
    """
    Find the project files in a directory with :func:`find_files`, and copy them to
    ``results``, adding a number to the name of files with the same name.
    """
    files = find_files(source, exclude_system_dirs, recursive)
    if files is None:
        return False

    for file in remove_dataless_files([Path(f) for f in files if _is_project_file(f)]):
        dest = results / file.name
        count = 1
        while dest.exists():
            dest = results / f"{file.name}.{count}"
            count += 1
        results.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(file, dest)

    return True


def _handler(results: Path) -> disk_image_api.VolumeHandler:
    """Handler for :func:`search_image` that copies the project files on each volume."""
    return lambda volume: _search_dir(volume, results, exclude_system_dirs=True)


def _search_image(source: str | Path, password_file: str | Path | None = None) -> bool:
    """Search a disk image, and copy the project files on it to ``./found``."""
    return search_image(source, _handler(Path.cwd() / "found"), password_file)


def _make_source(source: Path) -> None:
    (source / "Projects" / "relay1").mkdir(parents=True)
    (source / "Projects" / "relay1" / "SET_ALL.TXT").write_text("relay1", encoding="utf-8")
    (source / "Projects" / "relay2.rdb").write_text("relay2", encoding="utf-8")
    (source / "Projects" / "notes.txt").write_text("not a project file", encoding="utf-8")
    # Excluded system directories are skipped, case-insensitively, at the root
    (source / "WINDOWS" / "System32").mkdir(parents=True)
    (source / "WINDOWS" / "System32" / "excluded.rdb").write_text("x", encoding="utf-8")
    (source / "$Recycle.Bin").mkdir()
    (source / "$Recycle.Bin" / "deleted.rdb").write_text("x", encoding="utf-8")
    # Excluded names deeper in the tree aren't skipped
    (source / "Projects" / "Windows").mkdir()
    (source / "Projects" / "Windows" / "nested.rdb").write_text("nested", encoding="utf-8")


def test_search_image_bad_args(tmp_path):
    assert _search_image("") is False
    assert _search_image(tmp_path) is False  # Directories aren't disk images
    (tmp_path / "notes.txt").write_text("not an image", encoding="utf-8")
    assert _search_image(tmp_path / "notes.txt") is False


def test_is_disk_image(tmp_path, monkeypatch):
    for name in ["disk.vmdk", "DISK.VHDX", "disk.img", "disk.qcow2", "disk.iso", "disk.bin"]:
        (tmp_path / name).write_bytes(b"")
    assert is_disk_image(tmp_path / "disk.vmdk") is True
    assert is_disk_image(tmp_path / "DISK.VHDX") is True
    assert is_disk_image(str(tmp_path / "disk.img")) is True
    assert is_disk_image(tmp_path / "disk.qcow2") is True
    assert is_disk_image(tmp_path / "disk.iso") is True
    assert is_disk_image(tmp_path / "disk.bin") is False  # Usually firmware
    assert is_disk_image(tmp_path / "nonexistent.vmdk") is False

    # Sparse bundles are directories, and are only disk images on macOS
    (tmp_path / "disk.sparsebundle").mkdir()
    (tmp_path / "dir.vmdk").mkdir()
    monkeypatch.setattr(consts, "MACOS", False)
    assert is_disk_image(tmp_path / "disk.sparsebundle") is False
    monkeypatch.setattr(consts, "MACOS", True)
    assert is_disk_image(tmp_path / "disk.sparsebundle") is True
    assert is_disk_image(tmp_path / "dir.vmdk") is False


def test_find_files_bad_args():
    assert find_files(Path("NONEXISTENT")) is None


def test_find_files_skip_dirs(tmp_path):
    _make_source(tmp_path)
    found = find_files(tmp_path, skip_dirs=[tmp_path / "Projects" / "relay1", tmp_path / "x"])
    assert str(tmp_path / "Projects" / "relay2.rdb") in found
    assert not any("relay1" in f for f in found)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="Needs FIFOs (POSIX-only)")
def test_find_files_only_regular_files(tmp_path):
    """FIFOs would block forever when they're read, e.g. to check file signatures."""
    _make_source(tmp_path)
    os.mkfifo(tmp_path / "Projects" / "pipe.rdb")
    os.symlink(tmp_path / "Projects" / "relay2.rdb", tmp_path / "link.rdb")
    found = [Path(f).name for f in find_files(tmp_path)]
    assert "pipe.rdb" not in found
    assert "link.rdb" in found  # Links to regular files are kept


def _fake_linux_mount(monkeypatch, calls: list) -> None:
    monkeypatch.setattr(consts, "WINDOWS", False)
    monkeypatch.setattr(consts, "MACOS", False)
    monkeypatch.setattr(disk_image_api, "validate_image_mounting", lambda: True)
    monkeypatch.setattr(disk_image_api, "mount_image", lambda *_: calls.append("mount") or True)
    monkeypatch.setattr(
        disk_image_api, "unmount_image", lambda *_: calls.append("unmount") or True
    )


def test_search_image_linux(tmp_path, monkeypatch):
    image = tmp_path / "disk.vmdk"
    image.write_bytes(b"")
    calls = []
    _fake_linux_mount(monkeypatch, calls)
    mounts = []

    assert search_image(image, lambda volume: mounts.append(volume) or True) is True
    assert calls == ["mount", "unmount"]
    assert not Path(mounts[0]).exists()  # The temporary mount point is deleted


def test_search_image_linux_interrupted(tmp_path, monkeypatch):
    image = tmp_path / "disk.img"
    image.write_bytes(b"")
    calls = []
    _fake_linux_mount(monkeypatch, calls)
    mounts = []

    def _interrupt(volume):
        mounts.append(volume)
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        search_image(image, _interrupt)
    assert calls == ["mount", "unmount"]  # Unmounted, even though it was interrupted
    assert not Path(mounts[0]).exists()


def test_search_files(tmp_path):
    source = tmp_path / "source"
    results = tmp_path / "results"
    _make_source(source)

    assert _search_dir(source, results, exclude_system_dirs=True) is True
    found = sorted(p.relative_to(results).as_posix() for p in results.rglob("*") if p.is_file())
    assert found == ["SET_ALL.TXT", "nested.rdb", "relay2.rdb"]


def test_search_not_mount_point(tmp_path):
    # System directories are only skipped by default in the root of a drive or mount
    source = tmp_path / "source"
    results = tmp_path / "results"
    _make_source(source)

    assert _search_dir(source, results) is True
    found = sorted(p.name for p in results.rglob("*") if p.is_file())
    assert found == ["SET_ALL.TXT", "deleted.rdb", "excluded.rdb", "nested.rdb", "relay2.rdb"]


def test_search_junctions(tmp_path, monkeypatch):
    source = tmp_path / "source"
    results = tmp_path / "results"
    _make_source(source)
    junction = str(source / "Projects" / "relay1")
    real_lstat = os.lstat

    # Only defined on Windows
    monkeypatch.setattr(stat, "IO_REPARSE_TAG_MOUNT_POINT", 0xA0000003, raising=False)

    class _Stat:
        st_reparse_tag = stat.IO_REPARSE_TAG_MOUNT_POINT

    monkeypatch.setattr(consts, "WINDOWS", True)
    monkeypatch.setattr(os, "lstat", lambda p: _Stat() if str(p) == junction else real_lstat(p))

    assert _search_dir(source, results) is True
    assert not (results / "SET_ALL.TXT").exists()
    assert (results / "relay2.rdb").is_file()


def test_search_unreadable_root(tmp_path, monkeypatch):
    def _scandir(path):
        raise PermissionError(13, "Permission denied", path)

    monkeypatch.setattr(os, "scandir", _scandir)
    assert _search_dir(tmp_path, tmp_path / "results") is False


def test_search_not_recursive(tmp_path):
    (tmp_path / "top.rdb").write_text("top", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "sub.rdb").write_text("sub", encoding="utf-8")
    results = tmp_path / "results"

    assert _search_dir(tmp_path, results, recursive=False) is True
    assert [p.name for p in results.rglob("*.rdb")] == ["top.rdb"]


def test_remove_dataless_files(tmp_path, monkeypatch):
    files = [tmp_path / "a.rdb", tmp_path / "b.rdb"]
    for file in files:
        file.write_text("x", encoding="utf-8")

    # Only macOS has dataless files
    monkeypatch.setattr(consts, "MACOS", False)
    monkeypatch.setattr(disk_image_api, "_is_dataless", lambda _: True)
    assert remove_dataless_files(files) == files

    monkeypatch.setattr(consts, "MACOS", True)
    monkeypatch.setattr(disk_image_api, "_is_dataless", lambda p: p == files[0])
    assert remove_dataless_files(files) == files[1:]


@pytest.mark.parametrize(
    ("image", "superuser", "tools", "expected"),
    [
        ("disk.vhdx", True, ["powershell"], True),
        ("disk.VHD", True, ["powershell"], True),
        ("disk.iso", False, ["powershell"], True),
        ("disk.vhdx", False, ["powershell"], False),
        ("disk.vhdx", True, [], False),
        ("disk.img", True, ["powershell"], False),
        ("disk.vmdk", True, ["powershell", "qemu-img"], True),
    ],
)
def test_validate_image_mounting_windows(monkeypatch, image, superuser, tools, expected):
    monkeypatch.setattr(shutil, "which", lambda cmd: cmd if cmd in tools else None)
    monkeypatch.setattr(utils, "are_we_superuser", lambda: superuser)
    assert validate_image_mounting_windows(Path(image)) is expected


def _fake_powershell(
    monkeypatch,
    mount: tuple[int, str] = (0, json.dumps({"volumes": []})),
    attached: str = "False",
    calls: list | None = None,
):
    """Fake the PowerShell scripts: (returncode, stdout) for mount, and the attached state."""

    def _run(script, image):
        if calls is not None:
            calls.append((script, image))
        if script == disk_image_api._PS_MOUNT_SCRIPT:
            returncode, stdout = mount
        elif script == disk_image_api._PS_ATTACHED_SCRIPT:
            returncode, stdout = 0, attached
        else:
            returncode, stdout = 0, ""
        return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr="error")

    monkeypatch.setattr(disk_image_api, "_run_powershell", _run)


def _scripts(calls: list) -> list[str]:
    names = {
        disk_image_api._PS_ATTACHED_SCRIPT: "attached",
        disk_image_api._PS_MOUNT_SCRIPT: "mount",
        disk_image_api._PS_UNMOUNT_SCRIPT: "unmount",
    }
    return [names[c[0]] for c in calls]


def test_mount_image_windows(monkeypatch):
    vol = {"drive_letter": "E", "path": "", "filesystem": "NTFS", "label": "DATA"}
    _fake_powershell(monkeypatch, (0, json.dumps({"volumes": [vol]})))
    assert mount_image_windows(Path("disk.vhdx")) == [vol]

    # Single volume serialized as an object instead of a list, and no volumes
    _fake_powershell(monkeypatch, (0, json.dumps({"volumes": vol})))
    assert mount_image_windows(Path("disk.vhdx")) == [vol]
    _fake_powershell(monkeypatch, (0, json.dumps({"volumes": None})))
    assert mount_image_windows(Path("disk.vhdx")) == []

    # Output printed before the JSON is ignored
    _fake_powershell(monkeypatch, (0, "warning\n" + json.dumps({"volumes": [vol]})))
    assert mount_image_windows(Path("disk.vhdx")) == [vol]

    _fake_powershell(monkeypatch, (1, ""))
    assert mount_image_windows(Path("disk.vhdx")) is None
    _fake_powershell(monkeypatch, (0, "not json"))
    assert mount_image_windows(Path("disk.vhdx")) is None


def test_is_image_attached_windows(monkeypatch):
    _fake_powershell(monkeypatch, attached="True")
    assert is_image_attached_windows(Path("disk.vhdx")) is True
    _fake_powershell(monkeypatch, attached="False")
    assert is_image_attached_windows(Path("disk.vhdx")) is False
    _fake_powershell(monkeypatch, attached="")
    assert is_image_attached_windows(Path("disk.vhdx")) is None


def test_run_powershell_timeout(monkeypatch):
    def _timeout(*args, **kwargs):  # noqa: ARG001
        raise subprocess.TimeoutExpired("powershell", 1)

    monkeypatch.setattr(subprocess, "run", _timeout)
    assert disk_image_api._run_powershell("", Path("disk.vhdx")).returncode == 1


def test_search_volumes_windows(tmp_path):
    source = tmp_path / "volume"
    _make_source(source)
    results = tmp_path / "results"
    volumes = [
        {"drive_letter": "", "path": "", "filesystem": "Unknown", "label": "ext4"},
        {"drive_letter": "", "path": str(source), "filesystem": "NTFS", "label": "DATA"},
    ]

    assert search_volumes_windows(volumes, _handler(results)) is True
    assert (results / "relay2.rdb").is_file()
    assert search_volumes_windows(volumes[:1], _handler(results)) is False
    assert search_volumes_windows([], _handler(results)) is False


def _setup_image_windows(tmp_path, monkeypatch, name: str = "disk.vhdx") -> tuple[Path, str]:
    volume = tmp_path / "volume"
    _make_source(volume)
    image = tmp_path / name
    image.write_bytes(b"")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(consts, "WINDOWS", True)
    monkeypatch.setattr(disk_image_api, "validate_image_mounting_windows", lambda _: True)

    vol = {"drive_letter": "", "path": str(volume), "filesystem": "NTFS", "label": ""}
    return image, json.dumps({"volumes": [vol]})


BITLOCKER_HEADER = b"\xeb\x58\x90-FVE-FS-" + bytes(501)


def test_is_bitlocker():
    assert is_bitlocker(BITLOCKER_HEADER) is True
    assert is_bitlocker(b"\xeb\x52\x90NTFS    " + bytes(501)) is False
    assert is_bitlocker(b"") is False


def test_read_volume_header(tmp_path):
    volume = tmp_path / "volume"
    volume.write_bytes(BITLOCKER_HEADER + bytes(8192))
    assert read_volume_header(str(volume)) == BITLOCKER_HEADER + bytes(4096 - 512)
    assert read_volume_header(str(tmp_path / "nonexistent")) == b""


def test_search_volumes_windows_bitlocker(tmp_path, monkeypatch, caplog):
    headers = {"\\\\?\\Volume{locked}": BITLOCKER_HEADER}
    monkeypatch.setattr(disk_image_api, "read_volume_header", lambda p: headers.get(p, b""))
    volumes = [
        {
            "drive_letter": "E",
            "path": "\\\\?\\Volume{locked}\\",
            "filesystem": "Unknown",
            "label": "",
        },
        {
            "drive_letter": "",
            "path": "\\\\?\\Volume{ext4}\\",
            "filesystem": "Unknown",
            "label": "",
        },
    ]

    assert search_volumes_windows(volumes, _handler(tmp_path / "results")) is False
    assert "encrypted with BitLocker" in caplog.text
    assert caplog.text.count("encrypted with BitLocker") == 1
    assert "filesystem isn't readable by Windows" in caplog.text

    # Lock status from Get-BitLockerVolume
    caplog.clear()
    volumes[1]["bitlocker"] = "Locked"
    assert search_volumes_windows(volumes[1:], _handler(tmp_path / "results")) is False
    assert "encrypted with BitLocker" in caplog.text


@pytest.mark.parametrize("already_attached", [False, True])
def test_search_image_windows(tmp_path, monkeypatch, already_attached):
    image, out = _setup_image_windows(tmp_path, monkeypatch)
    calls = []
    _fake_powershell(monkeypatch, (0, out), str(already_attached), calls)

    assert _search_image(str(image)) is True
    results = tmp_path / "found"
    assert (results / "SET_ALL.TXT").is_file()
    assert not (results / "excluded.rdb").exists()  # System directories are skipped

    if already_attached:
        assert _scripts(calls) == ["attached", "mount"]  # Left attached
    else:
        assert _scripts(calls) == ["attached", "mount", "unmount"]
    assert all(c[1] == image for c in calls)


@pytest.mark.parametrize("already_attached", [False, True])
def test_search_image_windows_mount_fails(tmp_path, monkeypatch, already_attached):
    # Mounting can fail after the image was attached, so it's always unmounted,
    # unless it was attached before PEAT started
    image, _ = _setup_image_windows(tmp_path, monkeypatch)
    calls = []
    _fake_powershell(monkeypatch, (1, ""), str(already_attached), calls)

    assert _search_image(str(image)) is False
    if already_attached:
        assert _scripts(calls) == ["attached", "mount"]
    else:
        assert _scripts(calls) == ["attached", "mount", "unmount"]


def test_search_image_windows_interrupted(tmp_path, monkeypatch):
    image, _ = _setup_image_windows(tmp_path, monkeypatch)
    calls = []
    _fake_powershell(monkeypatch, calls=calls)

    def _interrupt(*args):  # noqa: ARG001
        raise KeyboardInterrupt

    monkeypatch.setattr(disk_image_api, "mount_image_windows", _interrupt)
    with pytest.raises(KeyboardInterrupt):
        _search_image(str(image))
    assert _scripts(calls) == ["attached", "unmount"]


def test_search_image_windows_not_an_image(tmp_path, monkeypatch):
    image, _ = _setup_image_windows(tmp_path, monkeypatch)
    calls = []
    _fake_powershell(monkeypatch, attached="", calls=calls)

    assert _search_image(str(image)) is False
    assert _scripts(calls) == ["attached"]  # Nothing to unmount


def test_search_image_windows_converts(tmp_path, monkeypatch):
    image, out = _setup_image_windows(tmp_path, monkeypatch, "disk.img")

    def _qemu_img(args):
        assert args[:4] == ["qemu-img", "convert", "-O", "vhdx"]
        Path(args[-1]).write_bytes(b"")
        return 0

    monkeypatch.setattr(subprocess, "call", _qemu_img)
    calls = []
    _fake_powershell(monkeypatch, (0, out), calls=calls)

    assert _search_image(str(image)) is True
    converted = calls[0][1]
    assert converted.name == "disk.vhdx"
    assert converted.parent.parent == tmp_path
    assert converted.parent.name.startswith("peat_image_")
    assert not list(tmp_path.glob("peat_image_*"))  # Cleaned up


def test_search_image_windows_convert_interrupted(tmp_path, monkeypatch):
    image, _ = _setup_image_windows(tmp_path, monkeypatch, "disk.img")

    def _qemu_img(args):
        Path(args[-1]).write_bytes(b"partial")
        raise KeyboardInterrupt

    monkeypatch.setattr(subprocess, "call", _qemu_img)
    calls = []
    _fake_powershell(monkeypatch, calls=calls)

    with pytest.raises(KeyboardInterrupt):
        _search_image(str(image))
    assert not calls  # Nothing was mounted
    assert not list(tmp_path.glob("peat_image_*"))  # Cleaned up


def _diskpart(script: str, tmp_path: Path) -> None:
    script_path = tmp_path / "diskpart.txt"
    script_path.write_text(textwrap.dedent(script), encoding="utf-8")
    proc = subprocess.run(
        ["diskpart", "/s", str(script_path)],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


@pytest.mark.slow
@pytest.mark.skipif(not consts.WINDOWS, reason="Windows-only")
def test_search_vhdx_windows(tmp_path, monkeypatch, caplog):
    """Create a real VHDX image with diskpart, then search it."""
    if not utils.are_we_superuser():
        pytest.skip("Mounting VHDX images requires Administrator")

    image = tmp_path / "peat_test.vhdx"
    mount_dir = tmp_path / "mnt"
    mount_dir.mkdir()

    _diskpart(
        f"""
        create vdisk file="{image}" maximum=64 type=expandable
        select vdisk file="{image}"
        attach vdisk
        create partition primary
        format fs=ntfs quick label=PEATTEST
        assign mount="{mount_dir}"
        """,
        tmp_path,
    )
    try:
        _make_source(mount_dir)
    finally:
        _diskpart(
            f"""
            select vdisk file="{image}"
            detach vdisk
            """,
            tmp_path,
        )

    work_dir = tmp_path / "work"
    work_dir.mkdir()
    monkeypatch.chdir(work_dir)

    caplog.set_level("DEBUG")
    assert _search_image(str(image)) is True, caplog.text
    results = work_dir / "found"
    found = sorted(p.relative_to(results).as_posix() for p in results.rglob("*") if p.is_file())
    assert found == ["SET_ALL.TXT", "nested.rdb", "relay2.rdb"]
    assert (results / "relay2.rdb").read_text(encoding="utf-8") == "relay2"

    # The image is unmounted when the search finishes
    proc = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            f"(Get-DiskImage -ImagePath '{image}').Attached",
        ],
        capture_output=True,
        encoding="utf-8",
        check=True,
    )
    assert proc.stdout.strip() == "False"


# --------------------------------------------------------------------------------------
# macOS
# --------------------------------------------------------------------------------------


def _found(results: Path) -> list[str]:
    return sorted(p.relative_to(results).as_posix() for p in results.rglob("*") if p.is_file())


def _make_macos_source(source: Path) -> None:
    """A macOS volume, with system directories that are skipped, and ones that aren't."""
    _make_source(source)
    for skipped in [
        "System/Volumes/Data/Users/peat",
        "private/var/db",
        "private/var/folders/xy",
        ".fseventsd",
        ".Spotlight-V100",
    ]:
        # macOS may create some of these itself when the volume is mounted
        (source / skipped).mkdir(parents=True, exist_ok=True)
        (source / skipped / "excluded.rdb").write_text("x", encoding="utf-8")
    # Nested exclusions only skip that path, not its parents or siblings
    (source / "private" / "etc").mkdir(parents=True)
    (source / "private" / "etc" / "etc.rdb").write_text("etc", encoding="utf-8")
    (source / "Users" / "peat").mkdir(parents=True)
    (source / "Users" / "peat" / "user.rdb").write_text("user", encoding="utf-8")


MACOS_EXPECTED = [
    "SET_ALL.TXT",
    "etc.rdb",
    "nested.rdb",
    "relay2.rdb",
    "user.rdb",
]


def test_search_macos_system_dirs(tmp_path):
    source = tmp_path / "source"
    results = tmp_path / "results"
    _make_macos_source(source)

    assert _search_dir(source, results, exclude_system_dirs=True) is True
    assert _found(results) == MACOS_EXPECTED

    # Not skipped by default when the source isn't the root of a mounted volume
    assert _search_dir(source, tmp_path / "results2") is True
    assert len(_found(tmp_path / "results2")) == 12


def test_search_macos_root(tmp_path, monkeypatch):
    """The root of a live macOS system ("/") also skips mount points and the Data volume."""
    source = tmp_path / "source"
    _make_macos_source(source)
    for mount_dir in ["Volumes/Backup", "dev", "home/peat"]:
        (source / mount_dir).mkdir(parents=True)
        (source / mount_dir / "excluded.rdb").write_text("x", encoding="utf-8")
    (source / "System" / "Library").mkdir(parents=True)
    (source / "System" / "Library" / "system.rdb").write_text("x", encoding="utf-8")
    monkeypatch.setattr(disk_image_api, "_is_macos_root", lambda s: s == str(source))

    results = tmp_path / "results"
    assert _search_dir(source, results, exclude_system_dirs=True) is True
    assert _found(results) == MACOS_EXPECTED

    # The Data volume is never searched as part of "/", since it would be searched
    # twice, through the firmlinks in "/" (e.g. "/Users"), and in the Data volume
    data_volume_file = str(source / "System" / "Volumes" / "Data" / "Users" / "peat")
    files = find_files(source, exclude_system_dirs=False)
    assert "system.rdb" in [Path(f).name for f in files]
    assert not any(f.startswith(data_volume_file) for f in files)
    assert len([f for f in files if _is_project_file(f)]) == 15  # Everything but the Data volume


def test_search_macos_full_disk_access(tmp_path, monkeypatch, caplog):
    source = tmp_path / "source"
    _make_source(source)
    protected = str(source / "Projects")
    real_scandir = os.scandir

    def _scandir(path):
        if str(path) == protected:
            raise PermissionError(1, "Operation not permitted", path)
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", _scandir)
    monkeypatch.setattr(consts, "MACOS", True)

    assert _search_dir(source, tmp_path / "results") is True
    assert "Full Disk Access" in caplog.text
    assert "Administrator" not in caplog.text

    # The source itself is protected
    caplog.clear()
    assert _search_dir(protected, tmp_path / "results") is False
    assert "Full Disk Access" in caplog.text

    # Regular permission errors, and other platforms
    caplog.clear()
    monkeypatch.setattr(consts, "MACOS", False)
    assert _search_dir(source, tmp_path / "results") is True
    assert "Full Disk Access" not in caplog.text
    assert "Administrator or root" in caplog.text


def test_search_macos_dataless(tmp_path, monkeypatch, caplog):
    """Files in iCloud Drive that haven't been downloaded are skipped."""
    source = tmp_path / "source"
    _make_source(source)
    (source / "iCloud").mkdir()
    (source / "iCloud" / "cloud.rdb").write_text("x", encoding="utf-8")
    dataless = {str(source / "Projects" / "relay2.rdb"), str(source / "iCloud")}
    real_lstat = os.lstat

    class _Stat:
        st_flags = disk_image_api.SF_DATALESS

    monkeypatch.setattr(consts, "MACOS", True)
    monkeypatch.setattr(os, "lstat", lambda p: _Stat() if str(p) in dataless else real_lstat(p))

    results = tmp_path / "results"
    assert _search_dir(source, results, exclude_system_dirs=True) is True
    assert _found(results) == ["SET_ALL.TXT", "nested.rdb"]
    assert "hasn't been downloaded" in caplog.text
    assert "Skipped 1 directories in iCloud Drive" in caplog.text


def test_is_luks():
    assert is_luks(b"LUKS\xba\xbe\x00\x02" + bytes(100)) is True
    assert is_luks(BITLOCKER_HEADER) is False
    assert is_luks(b"") is False


def test_unlock_secrets(tmp_path, monkeypatch):
    password_file = tmp_path / "passwords.txt"
    password_file.write_bytes(b"\xef\xbb\xbffirst\r\n\r\n second \nthird")
    secrets = UnlockSecrets(password_file)
    assert secrets.load() is True
    assert list(secrets.candidates("vol")) == ["first", " second ", "third"]
    secrets.remember("third")
    secrets.remember("other")
    assert list(secrets.candidates("vol")) == ["other", "first", " second ", "third"]

    password_file.write_text("\n\n", encoding="utf-8")
    assert UnlockSecrets(password_file).load() is False
    assert UnlockSecrets(tmp_path / "nonexistent.txt").load() is False

    # Prompts in a terminal, if there isn't a password file
    monkeypatch.setattr(UnlockSecrets, "can_prompt", staticmethod(lambda: True))
    answers = iter(["typed", ""])
    monkeypatch.setattr(disk_image_api.getpass, "getpass", lambda _prompt: next(answers))
    assert list(UnlockSecrets().candidates("vol")) == ["typed"]
    monkeypatch.setattr(UnlockSecrets, "can_prompt", staticmethod(lambda: False))
    assert list(UnlockSecrets().candidates("vol")) == []


def test_parse_plist():
    data = {"system-entities": [{"dev-entry": "/dev/disk4"}]}
    text = plistlib.dumps(data).decode()
    assert disk_image_api._parse_plist(text) == data
    assert disk_image_api._parse_plist("expected CRC32 $12345678\n" + text) == data
    assert disk_image_api._parse_plist("hdiutil: attach failed") is None
    assert disk_image_api._parse_plist("<?xml version='1.0'?><plist><dict>") is None
    assert disk_image_api._parse_plist(plistlib.dumps([1, 2]).decode()) is None


# Output of "hdiutil attach -plist" for a DMG with a GUID partition table and an APFS
# container, with one volume that hdiutil mounted
HDIUTIL_ATTACH_APFS = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>system-entities</key>
	<array>
		<dict>
			<key>content-hint</key>
			<string>GUID_partition_scheme</string>
			<key>dev-entry</key>
			<string>/dev/disk4</string>
			<key>potentially-mountable</key>
			<false/>
			<key>unmapped-content-hint</key>
			<string>GUID_partition_scheme</string>
		</dict>
		<dict>
			<key>content-hint</key>
			<string>Apple_APFS</string>
			<key>dev-entry</key>
			<string>/dev/disk4s1</string>
			<key>potentially-mountable</key>
			<false/>
			<key>unmapped-content-hint</key>
			<string>7C3457EF-0000-11AA-AA11-00306543ECAC</string>
		</dict>
		<dict>
			<key>content-hint</key>
			<string>EF57347C-0000-11AA-AA11-00306543ECAC</string>
			<key>dev-entry</key>
			<string>/dev/disk5</string>
			<key>potentially-mountable</key>
			<false/>
			<key>unmapped-content-hint</key>
			<string>EF57347C-0000-11AA-AA11-00306543ECAC</string>
		</dict>
		<dict>
			<key>content-hint</key>
			<string>41504653-0000-11AA-AA11-00306543ECAC</string>
			<key>dev-entry</key>
			<string>/dev/disk5s1</string>
			<key>mount-point</key>
			<string>MOUNT_POINT</string>
			<key>potentially-mountable</key>
			<true/>
			<key>unmapped-content-hint</key>
			<string>41504653-0000-11AA-AA11-00306543ECAC</string>
			<key>volume-kind</key>
			<string>apfs</string>
		</dict>
	</array>
</dict>
</plist>
"""


class FakeMacOS:
    """
    Fake hdiutil and diskutil commands, for a disk image with an APFS container
    (``/dev/disk4``, with the container on ``/dev/disk5``). Volumes that are "mounted"
    are directories in ``tmp_path``, with the files from :func:`_make_macos_source`.
    """

    def __init__(self, tmp_path: Path, monkeypatch) -> None:
        self.calls: list[tuple[list[str], bytes]] = []
        self.mounted = tmp_path / "mounted_vol"
        _make_macos_source(self.mounted)
        self.attach_output = HDIUTIL_ATTACH_APFS.replace("MOUNT_POINT", str(self.mounted))
        self.attached_images: list[dict] = []
        self.encrypted = False
        self.dmg_password = "dmg password"
        self.apfs_password = "apfs password"
        self.apfs_volumes: list[dict] = [
            {"DeviceIdentifier": "disk5s1", "Name": "PEATTEST", "Roles": []},
        ]
        self.apfs_store = "disk4s1"
        self.detach_failures = 0
        self.attach_error: BaseException | None = None
        self.on_attach = None
        self.unlocked: set[str] = set()

        monkeypatch.setattr(consts, "MACOS", True)
        monkeypatch.setattr(consts, "WINDOWS", False)
        monkeypatch.setattr(disk_image_api, "MACOS_MOUNT_ROOT_PARENT", str(tmp_path))
        monkeypatch.setattr(disk_image_api, "MACOS_DETACH_RETRY_DELAY", 0)
        monkeypatch.setattr(
            shutil, "which", lambda cmd: cmd if cmd in ["hdiutil", "diskutil"] else None
        )
        monkeypatch.setattr(disk_image_api, "_run_command", self.run)

    @staticmethod
    def _result(args, returncode=0, stdout="", stderr=""):
        return subprocess.CompletedProcess(args, returncode, stdout=stdout, stderr=stderr)

    def _plist(self, args, data):
        return self._result(args, stdout=plistlib.dumps(data).decode())

    def run(self, args, input_data=b"", timeout=None):  # noqa: ARG002
        self.calls.append((list(args), input_data))
        cmd = args[:2] if args[0] == "hdiutil" else args[:3]

        if cmd == ["hdiutil", "info"]:
            return self._plist(args, {"images": self.attached_images})
        elif cmd == ["hdiutil", "isencrypted"]:
            return self._plist(args, {"encrypted": self.encrypted})
        elif cmd == ["hdiutil", "attach"]:
            if self.on_attach:
                self.on_attach()
            if self.attach_error:
                raise self.attach_error
            if self.encrypted and (
                "-stdinpass" not in args or input_data != self.dmg_password.encode() + b"\0"
            ):
                return self._result(
                    args, 1, stderr="hdiutil: attach failed - Authentication error"
                )
            return self._result(args, stdout=self.attach_output)
        elif cmd == ["hdiutil", "detach"]:
            if self.detach_failures:
                self.detach_failures -= 1
                return self._result(args, 16, stderr="hdiutil: couldn't eject - Resource busy")
            return self._result(args)
        elif cmd == ["diskutil", "apfs", "list"]:
            container = {
                "ContainerReference": "disk5",
                "DesignatedPhysicalStore": self.apfs_store,
                "PhysicalStores": [{"DeviceIdentifier": self.apfs_store}],
                "Volumes": self.apfs_volumes,
            }
            other = {  # A container on the host, which is ignored
                "ContainerReference": "disk3",
                "PhysicalStores": [{"DeviceIdentifier": "disk0s2"}],
                "Volumes": [{"DeviceIdentifier": "disk3s1", "Name": "Macintosh HD"}],
            }
            return self._plist(args, {"Containers": [other, container]})
        elif cmd == ["diskutil", "apfs", "unlockVolume"]:
            if input_data != self.apfs_password.encode():
                return self._result(args, 1, stderr="Error unlocking APFS Volume")
            self.unlocked.add(args[3])
            return self._result(args)
        elif cmd == ["diskutil", "info", "-plist"]:
            mount_point = str(self.mounted) if args[3] == "/dev/disk5s1" else ""
            return self._plist(args, {"MountPoint": mount_point})
        elif cmd == ["diskutil", "mount", "readOnly"]:
            mount_point = Path(args[4])
            _make_source(mount_point)
            (mount_point / f"{Path(args[5]).name}.rdb").write_text("mounted", encoding="utf-8")
            return self._result(args)
        raise AssertionError(f"Unexpected command: {args}")

    def commands(self) -> list[str]:
        return [" ".join(c[0][:3] if c[0][0] == "diskutil" else c[0][:2]) for c in self.calls]

    def args_of(self, command: str) -> list[list[str]]:
        return [c[0] for c in self.calls if " ".join(c[0]).startswith(command)]


@pytest.fixture
def fake_macos(tmp_path, monkeypatch):
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    monkeypatch.chdir(work_dir)
    return FakeMacOS(tmp_path, monkeypatch)


def _macos_image(tmp_path: Path, name: str = "disk.dmg") -> Path:
    image = tmp_path / name
    image.write_bytes(b"")
    return image


def _assert_no_secrets(fake: FakeMacOS, caplog, *secrets: str) -> None:
    for args, _ in fake.calls:
        for secret in secrets:
            assert not any(secret in arg for arg in args)
    for secret in secrets:
        assert secret not in caplog.text


def test_search_image_macos(tmp_path, fake_macos, caplog):
    image = _macos_image(tmp_path)
    fake_macos.apfs_volumes += [
        {"DeviceIdentifier": "disk5s2", "Name": "Second", "Roles": []},
        {"DeviceIdentifier": "disk5s3", "Name": "Preboot", "Roles": ["Preboot"]},
    ]

    assert _search_image(str(image)) is True, caplog.text
    # Both volumes are searched: the one hdiutil mounted, and the one PEAT mounted
    found = _found(tmp_path / "work" / "found")
    assert "user.rdb" in found
    assert "disk5s2.rdb" in found
    assert "disk5s3.rdb" not in found
    assert not any("excluded" in f for f in found)

    attach = fake_macos.args_of("hdiutil attach")[0]
    for flag in ["-readonly", "-nobrowse", "-plist", "-mountrandom"]:
        assert flag in attach
    assert attach[-1] == str(image)
    assert "-imagekey" not in attach
    mount_root = Path(attach[attach.index("-mountrandom") + 1])
    assert mount_root.parent == tmp_path
    assert mount_root.name.startswith("peat_image_")
    assert not mount_root.exists()  # Cleaned up

    mounts = fake_macos.args_of("diskutil mount readOnly")
    assert [m[-1] for m in mounts] == ["/dev/disk5s2"]
    assert fake_macos.args_of("hdiutil detach") == [["hdiutil", "detach", "/dev/disk4"]]
    assert fake_macos.commands()[-1] == "hdiutil detach"


def test_search_image_macos_already_attached(tmp_path, fake_macos):
    image = _macos_image(tmp_path)
    fake_macos.attached_images = [
        {
            "image-path": str(image),
            "system-entities": [
                {"dev-entry": "/dev/disk4", "content-hint": "FDisk_partition_scheme"},
                {"dev-entry": "/dev/disk4s1", "mount-point": str(fake_macos.mounted)},
            ],
        }
    ]

    assert _search_image(str(image)) is True
    assert "user.rdb" in _found(tmp_path / "work" / "found")
    # Not attached again, and left attached
    assert fake_macos.commands() == ["hdiutil info"]


def test_search_image_macos_raw(tmp_path, fake_macos):
    image = _macos_image(tmp_path, "disk.img")

    assert _search_image(str(image)) is True
    attach = fake_macos.args_of("hdiutil attach")[0]
    assert attach[-3:] == ["-imagekey", "diskimage-class=CRawDiskImage", str(image)]
    assert "hdiutil isencrypted" not in fake_macos.commands()


def test_search_image_macos_encrypted_dmg(tmp_path, fake_macos, caplog):
    image = _macos_image(tmp_path)
    fake_macos.encrypted = True
    password_file = tmp_path / "passwords.txt"
    password_file.write_text(f"wrong password\n{fake_macos.dmg_password}\n", encoding="utf-8")

    assert _search_image(str(image), password_file) is True, caplog.text
    attaches = [c for c in fake_macos.calls if c[0][:2] == ["hdiutil", "attach"]]
    assert [c[1] for c in attaches] == [b"wrong password\0", b"dmg password\0"]
    assert all("-stdinpass" in c[0] for c in attaches)
    assert "user.rdb" in _found(tmp_path / "work" / "found")
    assert fake_macos.args_of("hdiutil detach") == [["hdiutil", "detach", "/dev/disk4"]]
    _assert_no_secrets(fake_macos, caplog, "wrong password", fake_macos.dmg_password)


def test_search_image_macos_encrypted_dmg_no_password(tmp_path, fake_macos, caplog):
    image = _macos_image(tmp_path)
    fake_macos.encrypted = True

    assert _search_image(str(image)) is False
    assert "--password-file" in caplog.text
    assert "hdiutil attach" not in fake_macos.commands()
    assert "hdiutil detach" not in fake_macos.commands()


def test_search_image_macos_locked_apfs(tmp_path, fake_macos, caplog):
    image = _macos_image(tmp_path)
    fake_macos.apfs_volumes.append(
        {"DeviceIdentifier": "disk5s2", "Name": "Secret", "Roles": [], "Locked": True}
    )
    password_file = tmp_path / "passwords.txt"
    password_file.write_text(f"{fake_macos.apfs_password}\n", encoding="utf-8")

    assert _search_image(str(image), str(password_file)) is True, caplog.text
    assert fake_macos.unlocked == {"/dev/disk5s2"}
    assert fake_macos.args_of("diskutil apfs unlockVolume") == [
        ["diskutil", "apfs", "unlockVolume", "/dev/disk5s2", "-stdinpassphrase", "-nomount"]
    ]
    assert "disk5s2.rdb" in _found(tmp_path / "work" / "found")
    _assert_no_secrets(fake_macos, caplog, fake_macos.apfs_password)


def test_search_image_macos_encrypted_apfs_without_locked_key(tmp_path, fake_macos):
    """Volumes that are encrypted and not mounted are locked, if diskutil doesn't say."""
    image = _macos_image(tmp_path)
    fake_macos.apfs_volumes.append(
        {"DeviceIdentifier": "disk5s2", "Name": "Secret", "Roles": [], "FileVault": True}
    )
    password_file = tmp_path / "passwords.txt"
    password_file.write_text(f"{fake_macos.apfs_password}\n", encoding="utf-8")

    assert _search_image(str(image), str(password_file)) is True
    assert fake_macos.unlocked == {"/dev/disk5s2"}


def test_search_image_macos_locked_apfs_wrong_password(tmp_path, fake_macos, caplog):
    image = _macos_image(tmp_path)
    fake_macos.apfs_volumes.append(
        {"DeviceIdentifier": "disk5s2", "Name": "Secret", "Roles": [], "Locked": True}
    )
    password_file = tmp_path / "passwords.txt"
    password_file.write_text("wrong\n", encoding="utf-8")

    # The other volume is still searched
    assert _search_image(str(image), str(password_file)) is True
    assert "none of the 1 passwords tried unlocked it" in caplog.text
    assert "diskutil mount readOnly" not in fake_macos.commands()
    assert "user.rdb" in _found(tmp_path / "work" / "found")

    # Without a password, it's skipped
    caplog.clear()
    assert _search_image(str(image)) is True
    assert "Skipping volume 'Secret' (/dev/disk5s2), it's encrypted with APFS" in caplog.text


@pytest.mark.parametrize(
    ("header", "message"),
    [
        (BITLOCKER_HEADER, "encrypted with BitLocker"),
        (b"LUKS\xba\xbe" + bytes(100), "encrypted with LUKS"),
        (b"", "macOS can't mount its filesystem"),
    ],
    ids=["bitlocker", "luks", "ext4"],
)
def test_search_image_macos_unreadable_volumes(
    tmp_path, fake_macos, monkeypatch, caplog, header, message
):
    image = _macos_image(tmp_path)
    fake_macos.apfs_store = "disk9s1"  # Not on the image
    fake_macos.attach_output = plistlib.dumps(
        {
            "system-entities": [
                {"dev-entry": "/dev/disk4", "content-hint": "GUID_partition_scheme"},
                {"dev-entry": "/dev/disk4s1", "content-hint": "Microsoft Basic Data"},
                {"dev-entry": "/dev/disk4s2", "content-hint": "Apple_Free"},
            ]
        }
    ).decode()
    read = []
    monkeypatch.setattr(disk_image_api, "read_volume_header", lambda p: read.append(p) or header)

    assert _search_image(str(image)) is False
    assert read == ["/dev/rdisk4s1"]
    assert message in caplog.text
    assert "run PEAT on Linux" in caplog.text
    assert "No volumes on the image could be mounted" in caplog.text
    assert fake_macos.args_of("hdiutil detach") == [["hdiutil", "detach", "/dev/disk4"]]


def test_search_image_macos_detach_retries(tmp_path, fake_macos, caplog):
    image = _macos_image(tmp_path)
    fake_macos.detach_failures = disk_image_api.MACOS_DETACH_ATTEMPTS - 1

    assert _search_image(str(image)) is True
    detaches = fake_macos.args_of("hdiutil detach")
    assert len(detaches) == disk_image_api.MACOS_DETACH_ATTEMPTS
    assert detaches[-1] == ["hdiutil", "detach", "/dev/disk4", "-force"]
    assert all("-force" not in d for d in detaches[:-1])

    # It still fails when forced
    caplog.clear()
    fake_macos.calls.clear()
    fake_macos.detach_failures = disk_image_api.MACOS_DETACH_ATTEMPTS
    assert _search_image(str(image)) is True  # The search succeeded
    assert "hdiutil detach /dev/disk4 -force" in caplog.text
    assert "Disk images" in caplog.text


def test_search_image_macos_attach_fails(tmp_path, fake_macos):
    image = _macos_image(tmp_path)
    fake_macos.attach_output = "hdiutil: attach failed - not recognized"

    assert _search_image(str(image)) is False
    # The output couldn't be parsed, and it isn't attached, so there's nothing to detach
    assert "hdiutil detach" not in fake_macos.commands()
    assert not list(tmp_path.glob("peat_image_*"))


def test_search_image_macos_attach_interrupted(tmp_path, fake_macos):
    image = _macos_image(tmp_path)
    fake_macos.attach_error = KeyboardInterrupt()

    def _attached():
        # The image was attached before hdiutil was interrupted
        fake_macos.attached_images = [
            {"image-path": str(image), "system-entities": [{"dev-entry": "/dev/disk4"}]}
        ]

    fake_macos.on_attach = _attached

    with pytest.raises(KeyboardInterrupt):
        _search_image(str(image))
    assert fake_macos.args_of("hdiutil detach") == [["hdiutil", "detach", "/dev/disk4"]]
    assert not list(tmp_path.glob("peat_image_*"))


def test_search_image_macos_search_interrupted(tmp_path, fake_macos):
    image = _macos_image(tmp_path)

    def _interrupt(*args, **kwargs):  # noqa: ARG001
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        search_image(str(image), _interrupt)
    # Detached, even though the search was interrupted
    assert fake_macos.args_of("hdiutil detach") == [["hdiutil", "detach", "/dev/disk4"]]


def test_search_image_macos_converts(tmp_path, fake_macos, monkeypatch):
    image = _macos_image(tmp_path, "disk.vmdk")
    info = {"format": "vmdk", "virtual-size": 64 * 1024**2, "actual-size": 1024**2}
    monkeypatch.setattr(disk_image_api, "qemu_img_info", lambda _: info)
    monkeypatch.setattr(
        shutil, "which", lambda cmd: cmd if cmd in ["hdiutil", "diskutil", "qemu-img"] else None
    )

    def _qemu_img(args):
        assert args[:4] == ["qemu-img", "convert", "-O", "raw"]
        Path(args[-1]).write_bytes(b"")
        return 0

    monkeypatch.setattr(subprocess, "call", _qemu_img)

    assert _search_image(str(image)) is True
    attach = fake_macos.args_of("hdiutil attach")[0]
    converted = Path(attach[-1])
    assert converted.name == "disk.img"
    assert converted.parent.name.startswith("peat_image_")
    assert attach[-3:-1] == ["-imagekey", "diskimage-class=CRawDiskImage"]
    assert not list((tmp_path / "work").glob("peat_image_*"))  # Cleaned up


def test_search_image_macos_needs_qemu_img(tmp_path, fake_macos, caplog):
    image = _macos_image(tmp_path, "disk.qcow2")
    assert _search_image(str(image)) is False
    assert "brew install qemu" in caplog.text
    assert not fake_macos.calls


@pytest.mark.parametrize(
    ("name", "info", "expected"),
    [
        ("disk.dmg", None, "native"),
        ("disk.SPARSEIMAGE", None, "native"),
        ("disk.iso", {"format": "raw"}, "native"),
        ("disk.img", None, "raw"),
        ("disk.dd", None, "raw"),
        ("disk.img", {"format": "qcow2"}, "convert"),
        ("disk-flat.vmdk", {"format": "raw"}, "raw"),
        ("disk.vmdk", {"format": "vmdk"}, "convert"),
        ("disk.vmdk", None, "convert"),
        ("disk.vhd", {"format": "vpc"}, "convert"),
        ("disk.image", {"format": "dmg"}, "native"),
    ],
)
def test_image_kind_macos(monkeypatch, name, info, expected):
    monkeypatch.setattr(disk_image_api, "qemu_img_info", lambda _: info)
    assert disk_image_api.image_kind_macos(Path(name)) == expected


def test_validate_image_mounting_macos(monkeypatch):
    tools = ["hdiutil", "diskutil"]
    monkeypatch.setattr(shutil, "which", lambda cmd: cmd if cmd in tools else None)
    assert validate_image_mounting_macos(Path("disk.dmg"), "native") is True
    assert validate_image_mounting_macos(Path("disk.vmdk"), "convert") is False
    tools.append("qemu-img")
    assert validate_image_mounting_macos(Path("disk.vmdk"), "convert") is True
    tools.clear()
    assert validate_image_mounting_macos(Path("disk.dmg"), "native") is False


def test_qemu_img_info(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda cmd: cmd)
    output = json.dumps({"format": "qcow2", "virtual-size": 1024, "actual-size": 512})

    def _run(args, **kwargs):  # noqa: ARG001
        assert args == ["qemu-img", "info", "--output=json", "disk.img"]
        return subprocess.CompletedProcess(args, 0, stdout=output, stderr="")

    monkeypatch.setattr(disk_image_api, "_run_command", _run)
    assert disk_image_api.qemu_img_info(Path("disk.img"))["format"] == "qcow2"

    output = "not json"
    assert disk_image_api.qemu_img_info(Path("disk.img")) is None
    monkeypatch.setattr(shutil, "which", lambda _: None)
    assert disk_image_api.qemu_img_info(Path("disk.img")) is None


def test_check_conversion_space(tmp_path, monkeypatch, caplog):
    usage = shutil.disk_usage(tmp_path)
    monkeypatch.setattr(shutil, "disk_usage", lambda _: usage._replace(free=100 * 1024**2))
    source = Path("disk.qcow2")

    big = {"format": "qcow2", "virtual-size": 10 * 1024**3, "actual-size": 50 * 1024**2}
    assert disk_image_api.check_conversion_space(source, tmp_path, big) is True
    assert "may need up to" in caplog.text

    full = {"format": "qcow2", "virtual-size": 10 * 1024**3, "actual-size": 200 * 1024**2}
    assert disk_image_api.check_conversion_space(source, tmp_path, full) is False
    assert "Not enough free disk space" in caplog.text

    # Unknown, e.g. qemu-img isn't installed
    monkeypatch.setattr(disk_image_api, "qemu_img_info", lambda _: None)
    assert disk_image_api.check_conversion_space(source, tmp_path) is True


def test_search_image_password_file_missing(tmp_path, fake_macos, caplog):
    image = _macos_image(tmp_path)
    assert _search_image(str(image), tmp_path / "nonexistent.txt") is False
    assert "Failed to read password file" in caplog.text
    assert not fake_macos.calls


def test_search_sparsebundle_is_an_image(tmp_path, fake_macos):
    bundle = tmp_path / "disk.sparsebundle"
    (bundle / "bands").mkdir(parents=True)
    assert _search_image(str(bundle)) is True
    assert fake_macos.args_of("hdiutil attach")[0][-1] == str(bundle)


@pytest.mark.slow
@pytest.mark.skipif(not consts.MACOS, reason="macOS-only")
@pytest.mark.parametrize("exclude_system_dirs", [None, False])
def test_search_macos_live_root(monkeypatch, exclude_system_dirs):
    """
    Search "/" on a real Mac, without going deeper than two directories down.
    The Data volume (/System/Volumes/Data) is never searched, since everything
    in it is also in "/", through firmlinks (e.g. /Users).
    """
    real_walk = os.walk
    visited: dict[str, list[str]] = {}

    def _walk(top, *args, **kwargs):
        for root, dirnames, filenames in real_walk(top, *args, **kwargs):
            yield root, dirnames, filenames
            visited[root] = list(dirnames)  # After find_files() pruned it
            if root != "/" and root.count("/") >= 2:
                dirnames.clear()

    monkeypatch.setattr(os, "walk", _walk)

    assert find_files("/", exclude_system_dirs=exclude_system_dirs) is not None
    assert "/Users" in visited
    assert "/System/Volumes/Data" not in visited
    assert "Data" not in visited.get("/System/Volumes", [])

    if exclude_system_dirs is None:  # "/" is a mount point, so system dirs are skipped
        for skipped in ["System", "Volumes", "dev", "cores"]:
            assert skipped not in visited["/"]
        assert "Users" in visited["/"]
        assert "private" in visited["/"]
        assert not {"db", "vm", "folders"} & set(visited.get("/private/var", []))
    else:
        assert "/System/Volumes" in visited


# Tests that create and attach real disk images with hdiutil. They're only run
# in their own CI job (see "macOS Disk Image Tests" in tests.yml), since they
# change the state of the system, and hdiutil can't run in parallel test workers
# or under CodeQL's tracing. Set PEAT_TEST_MACOS_IMAGES=1 to run them on a Mac.
macos_image_test = pytest.mark.skipif(
    not (consts.MACOS and os.environ.get("PEAT_TEST_MACOS_IMAGES")),
    reason="macOS-only, set PEAT_TEST_MACOS_IMAGES=1 to create and attach disk images",
)


def _run(args: list[str], input_data: bytes | None = None) -> str:
    proc = subprocess.run(args, input=input_data, capture_output=True, check=False)
    assert proc.returncode == 0, f"{args} failed: {proc.stdout!r} {proc.stderr!r}"
    return proc.stdout.decode("utf-8", errors="replace")


def _run_plist(args: list[str], input_data: bytes | None = None) -> dict:
    data = disk_image_api._parse_plist(_run(args, input_data))
    assert data is not None, args
    return data


def _attach(image: Path, password: str = "", readonly: bool = False) -> tuple[str, list[str]]:
    """Attach an image, and return its device and the mount points of its volumes."""
    args = ["hdiutil", "attach", "-nobrowse", "-noautoopen", "-plist"]
    if readonly:
        args.append("-readonly")
    if password:
        args.append("-stdinpass")
    entities = _run_plist([*args, str(image)], password.encode() or None)["system-entities"]
    mounts = [e["mount-point"] for e in entities if e.get("mount-point")]
    return disk_image_api._whole_disk(entities), mounts


def _detach(device: str) -> None:
    for attempt in range(5):
        args = ["hdiutil", "detach", device] + (["-force"] if attempt == 4 else [])
        if subprocess.run(args, capture_output=True, check=False).returncode == 0:
            return
        time.sleep(2)
    raise AssertionError(f"Failed to detach {device}")


def _writable(mount_point: Path) -> None:
    """Make the root of a volume writable, if it's owned by root (e.g. a new APFS volume)."""
    if not os.access(mount_point, os.W_OK):
        _run(["sudo", "-n", "chown", str(os.getuid()), str(mount_point)])


def _is_attached(image: Path) -> bool:
    images = _run_plist(["hdiutil", "info", "-plist"]).get("images", [])
    return disk_image_api.find_attached_image_macos(image, images) is not None


def _create_image(
    image: Path, fs: str, layout: str = "GPTSPUD", password: str = "", source=_make_macos_source
) -> Path:
    """Create a DMG image with one volume, with the files from ``source`` on it."""
    args = ["hdiutil", "create", "-size", "64m", "-fs", fs, "-volname", "PEATTEST"]
    args.extend(["-layout", layout])
    if password:
        # Without a null byte at the end, unlike PEAT, to check it's not part of the password
        args.extend(["-encryption", "AES-256", "-stdinpass"])
    _run([*args, str(image)], password.encode() or None)

    device, mounts = _attach(image, password)
    try:
        assert len(mounts) == 1, mounts
        _writable(Path(mounts[0]))
        source(Path(mounts[0]))
    finally:
        _detach(device)

    assert not _is_attached(image)
    return image


def _convert_to_raw(image: Path, raw: Path) -> Path:
    """Convert a DMG to a raw disk image, with a ".cdr" extension (DVD/CD master)."""
    _run(["hdiutil", "convert", str(image), "-format", "UDTO", "-o", str(raw.with_suffix(""))])
    cdr = raw.with_suffix(".cdr")
    if cdr != raw:
        cdr.rename(raw)
    return raw


def _search_real(image, tmp_path, monkeypatch, caplog, password_file=None) -> list[str]:
    """Search an image, check it was detached, and return what was found."""
    # A new directory each time, since some tests search the same image twice
    work_dir = Path(tempfile.mkdtemp(prefix=f"work_{image.name}_", dir=tmp_path))
    monkeypatch.chdir(work_dir)
    caplog.clear()
    caplog.set_level("DEBUG")

    assert _search_image(str(image), password_file) is True, caplog.text
    assert not _is_attached(image), "The image is still attached"
    return _found(work_dir / "found")


@macos_image_test
@pytest.mark.slow
def test_parse_macos_real_dmg(tmp_path, monkeypatch, mocker, caplog):
    """Parse the SCEPTRE configs from sceptre-bennu on a real DMG image with peat parse."""
    data_files = Path(__file__).resolve().parent.parent / "modules" / "sandia" / "data_files"
    image = _create_image(
        tmp_path / "sceptre.dmg",
        "APFS",
        source=lambda volume: shutil.copytree(data_files, volume / "Projects"),
    )
    parse_files = tmp_path / "parse_files"
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "SUMMARIES_DIR": tmp_path / "summaries",
            "TEMP_DIR": tmp_path / "temp",
            "PARSE_FILES_DIR": parse_files,
        },
    )
    mocker.patch.object(datastore, "objects", [])
    monkeypatch.chdir(tmp_path)
    caplog.set_level("DEBUG")

    summary = parse(image, ["SCEPTRE"])
    assert summary["disk_images"] == [image.as_posix()], caplog.text
    assert summary["num_parse_successes"] == 3, caplog.text
    assert not _is_attached(image), "The image is still attached"
    assert _found(parse_files / "sceptre.dmg") == [
        "volume_1/Projects/bp/dnp3-client.xml",
        "volume_1/Projects/ep/bacnet-client.xml",
        "volume_1/Projects/ep/sunspec-server.xml",
    ]


@macos_image_test
@pytest.mark.slow
@pytest.mark.parametrize(
    ("fs", "layout"),
    [
        ("MS-DOS FAT32", "MBRSPUD"),
        ("ExFAT", "GPTSPUD"),
        ("HFS+", "GPTSPUD"),
        ("APFS", "GPTSPUD"),
        ("APFS", "NONE"),
    ],
)
def test_search_macos_real_dmg(tmp_path, monkeypatch, caplog, fs, layout):
    image = _create_image(tmp_path / "peat_test.dmg", fs, layout)
    assert _search_real(image, tmp_path, monkeypatch, caplog) == MACOS_EXPECTED


@macos_image_test
@pytest.mark.slow
@pytest.mark.parametrize("suffix", [".img", ".cdr", ".dd"])
def test_search_macos_real_raw(tmp_path, monkeypatch, caplog, suffix):
    dmg = _create_image(tmp_path / "base.dmg", "MS-DOS FAT32", "MBRSPUD")
    raw = _convert_to_raw(dmg, tmp_path / f"raw{suffix}")
    assert _search_real(raw, tmp_path, monkeypatch, caplog) == MACOS_EXPECTED


@macos_image_test
@pytest.mark.slow
def test_search_macos_real_iso(tmp_path, monkeypatch, caplog):
    source = tmp_path / "iso_source"
    _make_source(source)
    image = tmp_path / "peat_test.iso"
    _run(["hdiutil", "makehybrid", "-iso", "-joliet", "-o", str(image), str(source)])
    found = _search_real(image, tmp_path, monkeypatch, caplog)
    # Plain ISO 9660 names are upper case, Joliet names keep their case
    assert sorted(f.lower() for f in found) == [
        "nested.rdb",
        "relay2.rdb",
        "set_all.txt",
    ]


@macos_image_test
@pytest.mark.slow
def test_search_macos_real_already_attached(tmp_path, monkeypatch, caplog):
    image = _create_image(tmp_path / "attached.dmg", "APFS")
    device, _ = _attach(image, readonly=True)
    try:
        monkeypatch.chdir(tmp_path)
        assert _search_image(str(image)) is True, caplog.text
        assert _found(tmp_path / "found") == MACOS_EXPECTED
        assert _is_attached(image), "An image that was already attached was detached"
    finally:
        _detach(device)


@macos_image_test
@pytest.mark.slow
def test_search_macos_real_encrypted_dmg(tmp_path, monkeypatch, caplog):
    password = "PEAT disk image test"
    image = _create_image(tmp_path / "encrypted.dmg", "APFS", password=password)

    # Without a password (there's no terminal to prompt in)
    monkeypatch.chdir(tmp_path)
    assert _search_image(str(image)) is False
    assert "it's encrypted" in caplog.text
    assert not _is_attached(image)

    password_file = tmp_path / "passwords.txt"
    password_file.write_text(f"wrong password\n{password}\n", encoding="utf-8")
    found = _search_real(image, tmp_path, monkeypatch, caplog, password_file)
    assert found == MACOS_EXPECTED
    assert password not in caplog.text


def _apfs_container(device: str) -> str:
    """The APFS container on an attached image (e.g. "disk5")."""
    disk = Path(device).name
    for container in _run_plist(["diskutil", "apfs", "list", "-plist"])["Containers"]:
        stores = [s["DeviceIdentifier"] for s in container.get("PhysicalStores", [])]
        if any(s == disk or s.startswith(f"{disk}s") for s in stores):
            return container["ContainerReference"]
    raise AssertionError(f"No APFS container on {device}")


@macos_image_test
@pytest.mark.slow
def test_search_macos_real_encrypted_apfs_volume(tmp_path, monkeypatch, caplog):
    password = "PEAT APFS test"
    # APFS only allows one volume per 512 MiB of container, so the container has
    # to be bigger than that to add a second volume. A sparse image keeps the file small.
    image = tmp_path / "apfs_encrypted.sparseimage"
    _run(
        [
            "hdiutil",
            "create",
            "-size",
            "1100m",
            "-type",
            "SPARSE",
            "-fs",
            "APFS",
            "-volname",
            "PEATTEST",
            str(image),
        ]
    )

    # Add an encrypted volume to the APFS container, and put the files on it
    device, _ = _attach(image)
    try:
        container = _apfs_container(device)
        _run(
            [
                "diskutil",
                "apfs",
                "addVolume",
                container,
                "APFS",
                "PEATENC",
                "-passphrase",
                password,
            ]
        )
        containers = _run_plist(["diskutil", "apfs", "list", "-plist"])["Containers"]
        volumes = [
            vol
            for c in containers
            if c["ContainerReference"] == container
            for vol in c.get("Volumes", [])
        ]
        print(volumes)  # noqa: T201
        encrypted = next(vol for vol in volumes if vol.get("Name") == "PEATENC")
        info = _run_plist(["diskutil", "info", "-plist", encrypted["DeviceIdentifier"]])
        mount_point = info.get("MountPoint")
        assert mount_point, info
        _writable(Path(mount_point))
        _make_macos_source(Path(mount_point))
    finally:
        _detach(device)

    # Without a password, only the unencrypted (empty) volume is searched
    assert _search_real(image, tmp_path, monkeypatch, caplog) == []
    assert "it's encrypted with APFS encryption and locked" in caplog.text

    password_file = tmp_path / "passwords.txt"
    password_file.write_text(f"wrong password\n{password}\n", encoding="utf-8")
    found = _search_real(image, tmp_path, monkeypatch, caplog, password_file)
    assert found == MACOS_EXPECTED
    assert "Unlocked encrypted APFS volume 'PEATENC'" in caplog.text
    assert password not in caplog.text


@macos_image_test
@pytest.mark.slow
@pytest.mark.skipif(not shutil.which("qemu-img"), reason="requires qemu-img (brew install qemu)")
@pytest.mark.parametrize(
    ("qemu_format", "suffix"),
    [("qcow2", ".qcow2"), ("vmdk", ".vmdk"), ("vhdx", ".vhdx"), ("vpc", ".vhd")],
)
def test_search_macos_real_qemu(tmp_path, monkeypatch, caplog, qemu_format, suffix):
    dmg = _create_image(tmp_path / "base.dmg", "MS-DOS FAT32", "MBRSPUD")
    raw = _convert_to_raw(dmg, tmp_path / "base.img")
    image = tmp_path / f"disk{suffix}"
    _run(["qemu-img", "convert", "-f", "raw", "-O", qemu_format, str(raw), str(image)])

    assert _search_real(image, tmp_path, monkeypatch, caplog) == MACOS_EXPECTED
    assert "Converting" in caplog.text
    assert not list((tmp_path / f"work_{image.name}").glob("peat_image_*"))
