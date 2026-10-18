import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

from peat import config, consts, utils
from peat.api import pillage_api
from peat.api.pillage_api import (
    check_file_conditions,
    copy_file,
    is_valid_file,
    mount_image_windows,
    pillage,
    search,
    search_volumes_windows,
    validate_image_mounting_windows,
)

PILLAGE_CONFIG = {
    "auto_copy": True,
    "recursive": True,
    "default": {"locations": [], "filenames": [], "extensions": []},
    "brands": {
        "SEL": {"locations": [], "filenames": ["set_all.txt"], "extensions": ["rdb"]},
    },
}


@pytest.fixture
def pillage_config(monkeypatch):
    monkeypatch.setattr(config, "PILLAGE", PILLAGE_CONFIG)


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


def test_pillage_bad_args():
    assert pillage("") is False


def test_search():
    assert search(Path("NONEXISTENT"), None) is False


def test_search_files(tmp_path, pillage_config):  # noqa: ARG001
    source = tmp_path / "source"
    results = tmp_path / "results"
    _make_source(source)

    assert search(source, results) is True
    found = sorted(p.relative_to(results).as_posix() for p in results.rglob("*") if p.is_file())
    assert found == ["SEL/SET_ALL.TXT", "SEL/nested.rdb", "SEL/relay2.rdb"]


def test_search_not_recursive(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "PILLAGE", {**PILLAGE_CONFIG, "recursive": False})
    (tmp_path / "top.rdb").write_text("top", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "sub.rdb").write_text("sub", encoding="utf-8")
    results = tmp_path / "results"

    assert search(tmp_path, results) is True
    assert [p.name for p in results.rglob("*.rdb")] == ["top.rdb"]


def test_search_duplicate_names(tmp_path, pillage_config):  # noqa: ARG001
    source = tmp_path / "source"
    for name in ["a", "b"]:
        (source / name).mkdir(parents=True)
        (source / name / "set_all.txt").write_text(name, encoding="utf-8")
    results = tmp_path / "results"

    assert search(source, results) is True
    assert sorted(p.name for p in (results / "SEL").iterdir()) == ["set_all.txt", "set_all.txt.1"]


def test_pillage_directory(tmp_path, monkeypatch, pillage_config):  # noqa: ARG001
    source = tmp_path / "source"
    _make_source(source)
    monkeypatch.chdir(tmp_path)

    assert pillage(str(source)) is True
    assert (tmp_path / "pillage_results" / "SEL" / "relay2.rdb").is_file()


def test_copy_file_error(tmp_path):
    # Failing to copy one file (e.g. it's locked on Windows) shouldn't stop pillage
    copy_file(tmp_path / "nonexistent.rdb", tmp_path / "results" / "nonexistent.rdb")
    assert not (tmp_path / "results" / "nonexistent.rdb").exists()


def test_is_valid_file(tmp_path):
    assert is_valid_file(tmp_path) == (False, "")


def test_check_file_conditions(tmp_path):
    assert check_file_conditions(tmp_path, {}) == (False, "")
    assert check_file_conditions(Path("SET_ALL.txt"), {"filenames": ["set_all.TXT"]}) == (
        True,
        "FILENAME",
    )
    assert check_file_conditions(Path("relay.RDB"), {"extensions": ["rdb"]}) == (
        True,
        "EXTENSION",
    )


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


def _fake_powershell(monkeypatch, returncode: int, stdout: str, calls: list | None = None):
    def _run(script, image):
        if calls is not None:
            calls.append((script, image))
        return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr="error")

    monkeypatch.setattr(pillage_api, "_run_powershell", _run)


def test_mount_image_windows(monkeypatch):
    vol = {"drive_letter": "E", "path": "", "filesystem": "NTFS", "label": "DATA"}
    out = json.dumps({"already_attached": False, "volumes": [vol]})
    _fake_powershell(monkeypatch, 0, out)
    assert mount_image_windows(Path("disk.vhdx")) == {
        "already_attached": False,
        "volumes": [vol],
    }

    # Single volume serialized as an object instead of a list, and no volumes
    _fake_powershell(monkeypatch, 0, json.dumps({"already_attached": True, "volumes": vol}))
    assert mount_image_windows(Path("disk.vhdx"))["volumes"] == [vol]
    _fake_powershell(monkeypatch, 0, json.dumps({"already_attached": False, "volumes": None}))
    assert mount_image_windows(Path("disk.vhdx"))["volumes"] == []

    _fake_powershell(monkeypatch, 1, "")
    assert mount_image_windows(Path("disk.vhdx")) is None


def test_search_volumes_windows(tmp_path, pillage_config):  # noqa: ARG001
    source = tmp_path / "volume"
    _make_source(source)
    results = tmp_path / "results"
    volumes = [
        {"drive_letter": "", "path": "", "filesystem": "Unknown", "label": "ext4"},
        {"drive_letter": "", "path": str(source), "filesystem": "NTFS", "label": "DATA"},
    ]

    assert search_volumes_windows(volumes, results) is True
    assert (results / "SEL" / "relay2.rdb").is_file()
    assert search_volumes_windows(volumes[:1], results) is False
    assert search_volumes_windows([], results) is False


@pytest.mark.parametrize("already_attached", [False, True])
def test_pillage_image_windows(tmp_path, monkeypatch, pillage_config, already_attached):  # noqa: ARG001
    volume = tmp_path / "volume"
    _make_source(volume)
    image = tmp_path / "disk.vhdx"
    image.write_bytes(b"")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(consts, "WINDOWS", True)
    monkeypatch.setattr(pillage_api, "validate_image_mounting_windows", lambda _: True)

    vol = {"drive_letter": "", "path": str(volume), "filesystem": "NTFS", "label": ""}
    calls = []
    out = json.dumps({"already_attached": already_attached, "volumes": [vol]})
    _fake_powershell(monkeypatch, 0, out, calls)

    assert pillage(str(image)) is True
    assert (tmp_path / "pillage_results" / "SEL" / "SET_ALL.TXT").is_file()

    scripts = [c[0] for c in calls]
    assert scripts[0] == pillage_api._PS_MOUNT_SCRIPT
    if already_attached:
        assert len(scripts) == 1  # left attached
    else:
        assert scripts[1] == pillage_api._PS_UNMOUNT_SCRIPT
    assert all(c[1] == image.resolve() for c in calls)


def test_pillage_image_windows_converts(tmp_path, monkeypatch, pillage_config):  # noqa: ARG001
    volume = tmp_path / "volume"
    _make_source(volume)
    image = tmp_path / "disk.img"
    image.write_bytes(b"")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(consts, "WINDOWS", True)
    monkeypatch.setattr(pillage_api, "validate_image_mounting_windows", lambda _: True)

    def _qemu_img(args):
        assert args[:4] == ["qemu-img", "convert", "-O", "vhdx"]
        Path(args[-1]).write_bytes(b"")
        return 0

    monkeypatch.setattr(subprocess, "call", _qemu_img)
    calls = []
    vol = {"drive_letter": "", "path": str(volume), "filesystem": "NTFS", "label": ""}
    _fake_powershell(
        monkeypatch, 0, json.dumps({"already_attached": False, "volumes": [vol]}), calls
    )

    assert pillage(str(image)) is True
    assert calls[0][1] == (tmp_path / "pillage_temp" / "disk.vhdx").resolve()
    assert not (tmp_path / "pillage_temp").exists()  # cleaned up


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
def test_pillage_vhdx_windows(tmp_path, monkeypatch, caplog, pillage_config):  # noqa: ARG001
    """Create a real VHDX image with diskpart, then pillage it."""
    if not utils.are_we_superuser():
        pytest.skip("Mounting VHDX images requires Administrator")

    image = tmp_path / "pillage_test.vhdx"
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
    assert pillage(str(image)) is True, caplog.text
    results = work_dir / "pillage_results"
    found = sorted(p.relative_to(results).as_posix() for p in results.rglob("*") if p.is_file())
    assert found == ["SEL/SET_ALL.TXT", "SEL/nested.rdb", "SEL/relay2.rdb"]
    assert (results / "SEL" / "relay2.rdb").read_text(encoding="utf-8") == "relay2"

    # The image is unmounted when pillage finishes
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
