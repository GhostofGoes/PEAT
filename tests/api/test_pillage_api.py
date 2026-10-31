import hashlib
import json
import os
import shutil
import stat
import struct
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest

from peat import config
from peat.api import pillage_api, pillage_image
from peat.api.pillage_api import (
    check_file_conditions,
    is_valid_file,
    pillage,
    search,
    select_backend,
)

# Files the example config matches in the "fat12_mbr" images (/WINDOWS is excluded)
FAT_MATCHES = {
    "p1:/SEL/SET_ALL.TXT": ("SEL", b"synthetic SEL settings\r\n"),
    "p1:/SEL/sub/relay.rdb": ("SEL", b"synthetic SEL RDB\r\n"),
    "p1:/Other/set_all.txt": ("SEL", b"second synthetic SEL settings\r\n"),
    "p1:/project.L5X": ("L5X", b"<RSLogix5000Content/>\r\n"),
}


def test_pillage_bad_args(monkeypatch):
    monkeypatch.setitem(config["runtime_configs"], "PILLAGE", {})
    assert pillage("") is False


def test_search():
    assert search(Path("NONEXISTENT"), None) is False


def test_is_valid_file(tmp_path, monkeypatch):
    monkeypatch.setitem(config["runtime_configs"], "PILLAGE", {})
    assert is_valid_file(tmp_path) == (False, "")


def test_check_file_conditions(tmp_path):
    assert check_file_conditions(tmp_path, {}) == (False, "")
    conditions = {"filenames": ["SET_ALL.txt"], "extensions": ["rdb"]}
    assert check_file_conditions(Path("set_all.TXT"), conditions) == (True, "FILENAME")
    assert check_file_conditions(PurePosixPath("p1:/a/b.RDB"), conditions) == (True, "EXTENSION")
    assert check_file_conditions(Path("b.rdbx"), conditions) == (False, "")


def load_summary(tmp_path: Path) -> dict:
    return json.loads((tmp_path / "summaries" / "pillage-summary.json").read_text())


def copied_files(results: Path) -> dict[str, bytes]:
    return {
        p.relative_to(results).as_posix(): p.read_bytes()
        for p in sorted(results.rglob("*"))
        if p.is_file()
    }


# --- Directories ---


def make_source_tree(root: Path) -> None:
    files = {
        "SEL/set_all.txt": "settings 1",
        "Other/SET_ALL.txt": "settings 2",
        "deep/er/relay.RDB": "rdb",
        "windows/skip.rdb": "excluded",
        "plant.l5x": "l5x",
        "readme.md": "nope",
    }
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)


@pytest.mark.usefixtures("pillage_config")
def test_pillage_directory_absolute_path(tmp_path):
    source = tmp_path / "source"
    make_source_tree(source)
    assert pillage(str(source.resolve())) is True

    results = copied_files(Path("pillage_results"))
    # "windows" is excluded case-insensitively, even when the source is an absolute path
    assert sorted(results.values()) == sorted([b"settings 1", b"settings 2", b"rdb", b"l5x"])
    assert results["L5X/plant.l5x"] == b"l5x"
    assert results["SEL/relay.RDB"] == b"rdb"


def test_pillage_directory_not_recursive(pillage_config, tmp_path):
    pillage_config["recursive"] = False
    source = tmp_path / "source"
    make_source_tree(source)
    assert pillage(str(source)) is True
    assert copied_files(Path("pillage_results")) == {"L5X/plant.l5x": b"l5x"}


@pytest.mark.usefixtures("pillage_config")
def test_pillage_skips_peat_output_directories(monkeypatch):
    # e.g. "peat pull" results in ./peat_results, then "peat pillage" in the same directory
    out_dir = Path.cwd() / "peat_results"
    monkeypatch.setitem(config["runtime_configs"], "OUT_DIR", out_dir)
    monkeypatch.setitem(config["runtime_configs"], "RUN_DIR", out_dir / "run")
    (out_dir / "old_run/devices/192.0.2.10").mkdir(parents=True)
    (out_dir / "old_run/devices/192.0.2.10/SET_ALL.TXT").write_text("pulled")
    (Path.cwd() / "SEL").mkdir()
    (Path.cwd() / "SEL/set_all.txt").write_text("found")
    assert pillage(None) is True
    assert copied_files(Path("pillage_results")) == {"SEL/set_all.txt": b"found"}

    # Pillaging the output directory itself works
    assert pillage(str(out_dir)) is True
    assert copied_files(Path("pillage_results"))["SEL/SET_ALL.TXT"] == b"pulled"


def test_is_output_dir(tmp_path, monkeypatch):
    out = tmp_path / "Out"
    out.mkdir()
    output_dirs = {"out": [str(out)], "missing": [str(tmp_path / "missing")]}
    assert pillage_api._is_output_dir(str(out), output_dirs) is True
    assert pillage_api._is_output_dir(str(tmp_path / "x" / "Out"), output_dirs) is False
    assert pillage_api._is_output_dir(str(tmp_path / "missing"), output_dirs) is False
    assert pillage_api._is_output_dir(str(tmp_path / "other"), output_dirs) is False
    # Names are matched case-insensitively, then compared with samefile()
    monkeypatch.setattr(os.path, "samefile", lambda a, b: a.lower() == b.lower())
    assert pillage_api._is_output_dir(str(tmp_path / "OUT"), output_dirs) is True


@pytest.mark.usefixtures("pillage_config")
def test_pillage_defaults_to_current_directory():
    make_source_tree(Path.cwd())
    assert pillage(None) is True
    assert len(copied_files(Path("pillage_results"))) == 4

    # The results directory itself is not searched, so the previous results aren't copied
    assert pillage(None) is True
    assert len(copied_files(Path("pillage_results"))) == 8


@pytest.mark.usefixtures("pillage_config")
def test_pillage_directory_copy_error_continues(tmp_path, monkeypatch):
    source = tmp_path / "source"
    make_source_tree(source)
    real_copyfile = shutil.copyfile

    def _copyfile(src, dst, *args, **kwargs):
        if src.endswith("plant.l5x"):
            raise PermissionError(13, "The process cannot access the file", src)
        return real_copyfile(src, dst, *args, **kwargs)

    monkeypatch.setattr(shutil, "copyfile", _copyfile)
    assert pillage(str(source)) is True
    results = copied_files(Path("pillage_results"))
    assert len(results) == 3
    assert "L5X/plant.l5x" not in results


@pytest.mark.usefixtures("pillage_config")
def test_search_logs_walk_errors(tmp_path, monkeypatch):
    errors = []
    monkeypatch.setattr(pillage_api, "_log_walk_error", errors.append)
    real_walk = os.walk

    def _walk(top, onerror=None, **kwargs):
        onerror(PermissionError(13, "Access is denied", os.path.join(top, "locked")))
        yield from real_walk(top, onerror=onerror, **kwargs)

    monkeypatch.setattr(os, "walk", _walk)
    (tmp_path / "source").mkdir()
    assert search(tmp_path / "source", Path("pillage_results")) is True
    assert len(errors) == 1
    pillage_api._log_walk_error(errors[0])  # Doesn't raise


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
@pytest.mark.usefixtures("pillage_config")
def test_search_skips_directory_links(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "set_all.txt").write_text("outside")
    source = tmp_path / "source"
    source.mkdir()
    (source / "link").symlink_to(outside, target_is_directory=True)
    assert search(source, Path("pillage_results")) is True
    assert copied_files(Path("pillage_results")) == {}


@pytest.mark.parametrize(
    ("tag", "expected"),
    [
        (0xA0000003, True),  # IO_REPARSE_TAG_MOUNT_POINT (junction)
        (0xA000000C, True),  # IO_REPARSE_TAG_SYMLINK
        (0xA000001D, True),  # IO_REPARSE_TAG_LX_SYMLINK (WSL)
        (None, True),  # Unknown tag
        (0x9000601A, False),  # IO_REPARSE_TAG_CLOUD_6 (OneDrive folder)
        (0x80000013, False),  # IO_REPARSE_TAG_DEDUP
    ],
)
def test_is_link_or_junction(tmp_path, monkeypatch, tag, expected):
    (tmp_path / "dir").mkdir()
    assert pillage_api._is_link_or_junction(str(tmp_path / "dir")) is False
    assert pillage_api._is_link_or_junction(str(tmp_path / "missing")) is False

    # Windows: a directory with the reparse point attribute
    st = SimpleNamespace(
        st_mode=stat.S_IFDIR | 0o755, st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT
    )
    if tag is not None:
        st.st_reparse_tag = tag
    monkeypatch.setattr(os, "lstat", lambda _p: st)
    assert pillage_api._is_link_or_junction("C:\\Users\\x\\Application Data") is expected


# --- Disk images (library backend) ---


@pytest.mark.usefixtures("pillage_config")
def test_pillage_e01(pillage_image_path, tmp_path):
    image = pillage_image_path("fat12_mbr.E01")
    assert pillage(str(image)) is True

    results = Path("pillage_results")
    summary = load_summary(tmp_path)
    assert summary["backend"] == "library"
    assert summary["source_type"] == "image"
    assert summary["image_format"] == "ewf"
    assert summary["image_info"]["headers"]["case_number"] == "PEAT-CASE-1"
    assert summary["volumes"][0]["filesystem"] == "fat"
    assert summary["num_files_copied"] == 4
    assert summary["num_errors"] == 0

    copied = {entry["source"]: entry for entry in summary["files_copied"]}
    assert set(copied) == set(FAT_MATCHES)
    for source, (brand, data) in FAT_MATCHES.items():
        entry = copied[source]
        assert entry["brand"] == brand
        # The names "SET_ALL.TXT" and "set_all.txt" collide on case-insensitive filesystems
        assert Path(entry["destination"]).parent == results / brand
        assert Path(entry["destination"]).read_bytes() == data
        assert entry["size"] == len(data)
        assert entry["sha256"] == hashlib.sha256(data).hexdigest()
    assert len(copied_files(results)) == 4


@pytest.mark.parametrize("image", ["fat12_mbr.img.xz", "fat12_mbr.vhdx.xz", "ntfs.img.xz"])
@pytest.mark.usefixtures("pillage_config")
def test_pillage_images_without_mounting(pillage_image_path, image, monkeypatch):
    monkeypatch.setattr(pillage_api, "mount_image", pytest.fail)
    assert pillage(str(pillage_image_path(image))) is True
    assert copied_files(Path("pillage_results"))


@pytest.mark.usefixtures("pillage_config")
def test_pillage_image_name_collisions(pillage_image_path):
    image = str(pillage_image_path("fat12_mbr.img.xz"))
    assert pillage(image) is True
    assert pillage(image) is True
    results = copied_files(Path("pillage_results"))
    assert len(results) == 8
    assert results["L5X/project.L5X"] == results["L5X/project.L5X.1"]


def test_pillage_image_max_file_size(pillage_config, pillage_image_path, tmp_path):
    pillage_config["max_file_size"] = 24
    assert pillage(str(pillage_image_path("fat12_mbr.img.xz"))) is True
    summary = load_summary(tmp_path)
    # SET_ALL.TXT (24 bytes), relay.rdb (19) and project.L5X (23) are copied
    assert summary["num_files_copied"] == 3
    assert summary["num_files_skipped"] == 1


@pytest.mark.parametrize("value", ["lots", -1, 0, None, [1]])
@pytest.mark.parametrize("option", ["max_file_size", "max_total_size"])
def test_max_size_option_invalid(pillage_config, option, value):
    pillage_config[option] = value
    assert pillage_api._max_size_option(option, 1234) == 1234
    pillage_config[option] = "4096"
    assert pillage_api._max_size_option(option, 1234) == 4096


def test_pillage_image_max_total_size(pillage_config, pillage_image_path, tmp_path):
    pillage_config["max_total_size"] = 50
    assert pillage(str(pillage_image_path("fat12_mbr.img.xz"))) is False
    summary = load_summary(tmp_path)
    # project.L5X (23 bytes) and SET_ALL.TXT (24) are copied, then it stops
    assert summary["num_files_copied"] == 2
    assert summary["total_size_copied"] == 47
    assert "max_total_size" in summary["stopped_early"]
    assert len(copied_files(Path("pillage_results"))) == 2


def test_pillage_image_low_disk_space(pillage_config, pillage_image_path, tmp_path, monkeypatch):
    image = pillage_image_path("fat12_mbr.img.xz")

    def _low_disk_usage(_path):
        used = sum(len(data) for data in copied_files(Path("pillage_results")).values())
        return SimpleNamespace(free=pillage_api.MIN_FREE_SPACE + 50 - used)

    monkeypatch.setattr(shutil, "disk_usage", _low_disk_usage)
    assert pillage(str(image)) is False
    summary = load_summary(tmp_path)
    # project.L5X (23 bytes) and SET_ALL.TXT (24) fit, relay.rdb (19) doesn't
    assert summary["num_files_copied"] == 2
    assert "free disk space" in summary["stopped_early"]

    # The free space is unknown: don't stop
    def _disk_usage(_path):
        raise OSError("not supported")

    monkeypatch.setattr(shutil, "disk_usage", _disk_usage)
    pillage_config["max_total_size"] = None
    assert pillage(str(image)) is True


@pytest.mark.usefixtures("pillage_config")
def test_pillage_image_hard_links_copied_once(pillage_image_path, tmp_path):
    assert pillage(str(pillage_image_path("ntfs.img.xz"))) is True
    summary = load_summary(tmp_path)
    copied = {entry["source"] for entry in summary["files_copied"]}
    assert "p0:/Users/eng/OneDrive/Projects/plant.L5X" in copied  # Reparse point folder
    assert "p0:/Project.RDB" in copied
    assert "p0:/SEL/hardlink.rdb" not in copied
    assert summary["duplicates"] == [
        {"source": "p0:/SEL/hardlink.rdb", "same_as": "pillage_results/SEL/Project.RDB"}
    ]


def cross_linked_fat(disk: bytearray, copies: int) -> bytearray:
    """Make root directory entries of the fat12_mbr disk point at the clusters of project.L5X."""
    part = 64 * 512
    bps, _, reserved, num_fats, num_root = struct.unpack_from("<HBHBH", disk, part + 11)
    fat_sectors = struct.unpack_from("<H", disk, part + 22)[0]
    root = part + (reserved + num_fats * fat_sectors) * bps
    entries = [root + i * 32 for i in range(num_root)]
    project = next(e for e in entries if disk[e : e + 11] == b"PROJECT L5X")
    free = [e for e in entries if disk[e] == 0]
    for i, entry in enumerate(free[:copies]):
        disk[entry : entry + 32] = disk[project : project + 32]
        disk[entry : entry + 8] = f"DUP{i:05d}".encode()
    return disk


@pytest.mark.usefixtures("pillage_config")
def test_pillage_image_cross_linked_fat_copied_once(pillage_image_path, tmp_path):
    raw = pillage_image_path("fat12_mbr.img.xz")
    raw.write_bytes(cross_linked_fat(bytearray(raw.read_bytes()), 100))
    assert pillage(str(raw)) is True
    summary = load_summary(tmp_path)
    assert summary["num_files_copied"] == 4
    assert len(summary["duplicates"]) == 100
    assert {d["same_as"] for d in summary["duplicates"]} == {"pillage_results/L5X/project.L5X"}
    assert len(copied_files(Path("pillage_results"))) == 4


def test_pillage_image_auto_copy_prompt(pillage_config, pillage_image_path, monkeypatch, tmp_path):
    pillage_config["auto_copy"] = False
    answers = iter(["Y", "N", "N", "N"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))
    assert pillage(str(pillage_image_path("fat12_mbr.img.xz"))) is True
    summary = load_summary(tmp_path)
    assert summary["num_files_copied"] == 1
    assert summary["num_files_skipped"] == 3


def test_unique_destination(tmp_path):
    assert pillage_api._unique_destination(tmp_path, "a.txt") == tmp_path / "a.txt"
    (tmp_path / "a.txt").write_text("x")
    (tmp_path / "a.txt.1").write_text("x")
    assert pillage_api._unique_destination(tmp_path, "a.txt") == tmp_path / "a.txt.2"
    # Names from images are untrusted
    assert pillage_api._unique_destination(tmp_path, "..") == tmp_path / "unnamed"
    assert pillage_api._unique_destination(tmp_path, "../../etc/passwd") == tmp_path / "passwd"
    assert pillage_api._unique_destination(tmp_path, "CON") == tmp_path / "CON_"
    assert pillage_api._unique_destination(tmp_path, 'a:b*?"<>|.txt').parent == tmp_path


def test_copy_image_file_read_error(tmp_path):
    class BrokenEntry:
        def read_buffer_at_offset(self, size, offset):
            if offset:
                raise OSError("unable to read data")
            return b"x" * min(size, 4)

    img_file = pillage_image.ImageFile(1, PurePosixPath("/a.txt"), 10, BrokenEntry())
    dst = tmp_path / "out" / "a.txt"
    assert pillage_api._copy_image_file(img_file, dst) is None
    assert not dst.exists()  # Partial copies are removed

    # Existing files are never overwritten
    dst.write_text("existing")
    assert pillage_api._copy_image_file(img_file, dst) is None
    assert dst.read_text() == "existing"


# --- Backend selection ---


@pytest.fixture
def backend_env(pillage_config, monkeypatch, tmp_path):
    """Control if the library backend supports the image and if mounting is possible."""
    state = {"lib_ok": True, "mount_ok": True, "mount_checked": 0, "config": pillage_config}
    real_check = pillage_image.check_library_support

    def _check_library_support(fmt):
        if not state["lib_ok"]:
            raise pillage_image.UnsupportedImageError("the Python module 'pyewf' is not available")
        real_check(fmt)

    def _validate_image_mounting():
        state["mount_checked"] += 1
        return state["mount_ok"]

    monkeypatch.setattr(pillage_image, "check_library_support", _check_library_support)
    monkeypatch.setattr(pillage_api, "validate_image_mounting", _validate_image_mounting)
    image = tmp_path / "disk.img"
    image.write_bytes(bytes(4096))
    state["image"] = image
    return state


@pytest.mark.parametrize(
    ("requested", "lib_ok", "mount_ok", "expected"),
    [
        ("auto", True, True, "library"),
        ("auto", True, False, "library"),
        ("AUTO", False, True, "mount"),
        ("auto", False, False, None),
        ("library", True, False, "library"),
        ("library", False, True, None),
        ("mount", True, True, "mount"),
        ("mount", True, False, None),
        ("bogus", True, True, None),
        (None, True, True, "library"),
    ],
)
def test_select_backend(backend_env, monkeypatch, requested, lib_ok, mount_ok, expected):
    monkeypatch.setitem(config["runtime_configs"], "PILLAGE_BACKEND", requested)
    backend_env.update(lib_ok=lib_ok, mount_ok=mount_ok)
    assert select_backend(backend_env["image"]) == expected


def test_select_backend_unsupported_format(backend_env, pillage_config):
    pillage_config["image_format"] = "vdi"
    assert select_backend(backend_env["image"]) == "mount"
    pillage_config["image_format"] = "not-a-format"
    assert select_backend(backend_env["image"]) is None


@pytest.mark.parametrize("image", ["fat12_mbr.E01", "split.001"])
def test_mount_backend_refuses_ewf_and_split_raw(
    backend_env, pillage_image_path, monkeypatch, image
):
    if image == "split.001":
        path = pillage_image_path("fat12_mbr.img.xz").rename(backend_env["image"].parent / image)
        path.with_suffix(".002").write_bytes(bytes(512))
    else:
        path = pillage_image_path(image)
    monkeypatch.setitem(config["runtime_configs"], "PILLAGE_BACKEND", "mount")
    assert select_backend(path) is None
    assert pillage(str(path)) is False
    assert backend_env["mount_checked"] == 0


def test_mount_backend_single_part_split_raw(backend_env, monkeypatch, pillage_config):
    # A single ".001" file is a raw image, qemu-nbd can mount it
    monkeypatch.setitem(config["runtime_configs"], "PILLAGE_BACKEND", "mount")
    path = backend_env["image"].rename(backend_env["image"].with_suffix(".001"))
    assert select_backend(path) == "mount"
    assert backend_env["mount_checked"] == 1

    # A split raw image without a numeric extension
    pillage_config["image_format"] = "split_raw"
    path = path.rename(path.with_suffix(".img"))
    assert select_backend(path) is None
    assert backend_env["mount_checked"] == 1


def test_auto_falls_back_to_mount_for_unsupported_filesystem(backend_env, monkeypatch):
    mounted = []

    def _mount_image(source, _mount_point):
        mounted.append(source)
        return False

    monkeypatch.setattr(pillage_api, "mount_image", _mount_image)
    # Zeros: no supported filesystem, so the library backend can't read it
    assert pillage(str(backend_env["image"])) is False
    assert mounted == [backend_env["image"]]
    assert backend_env["mount_checked"] == 1
    assert not Path("pillage_temp").exists()


def test_library_backend_does_not_fall_back(backend_env, monkeypatch):
    monkeypatch.setitem(config["runtime_configs"], "PILLAGE_BACKEND", "library")
    monkeypatch.setattr(pillage_api, "mount_image", pytest.fail)
    assert pillage(str(backend_env["image"])) is False
    assert backend_env["mount_checked"] == 0


@pytest.mark.usefixtures("pillage_config")
def test_pillage_corrupt_image(pillage_image_path, tmp_path, monkeypatch):
    monkeypatch.setattr(pillage_api, "mount_image", pytest.fail)
    good = pillage_image_path("fat12_mbr.E01").read_bytes()
    bad = tmp_path / "bad.E01"
    bad.write_bytes(good[: len(good) // 2])
    assert pillage(str(bad)) is False

    # Corrupt VM disks: the error is logged, nothing is raised
    for name, head in (
        ("bad.vhdx", b"vhdxfile"),
        ("bad.qcow2", b"QFI\xfb"),
        ("bad.vmdk", b"KDMV"),
    ):
        (tmp_path / name).write_bytes(head + bytes(range(256)) * 16)
        assert pillage(str(tmp_path / name)) is False


@pytest.mark.usefixtures("pillage_config")
def test_pillage_unexpected_os_error(pillage_image_path, monkeypatch):
    def _search_image(_source, _results):
        raise OSError("unable to read")

    monkeypatch.setattr(pillage_api, "search_image", _search_image)
    assert pillage(str(pillage_image_path("fat12_mbr.img.xz"))) is False
