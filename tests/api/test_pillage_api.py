import os
from pathlib import Path

import pytest

from peat import config, consts
from peat.api import pillage_api
from peat.api.pillage_api import (
    check_file_conditions,
    copy_file,
    is_valid_file,
    mount_image,
    pillage,
    remove_nbd_device,
    search,
)

# TODO: actual tests of pillage functionality. This is just a stub.


def test_pillage_bad_args():
    assert pillage("") is False


def test_search():
    assert search(Path("NONEXISTENT"), None) is False


def test_is_valid_file(tmp_path):
    assert is_valid_file(tmp_path) == (False, "")


def test_check_file_conditions(tmp_path):
    assert check_file_conditions(tmp_path, {}) == (False, "")
    # TODO: test filename match
    # TODO: test extension match


@pytest.fixture
def pillage_config(mocker):
    conf = {
        "auto_copy": True,
        "recursive": True,
        "brands": {"SEL": {"filenames": ["set_all.txt"], "extensions": ["rdb", "apx", "txt"]}},
    }
    mocker.patch.dict(config["CONFIG"], {"PILLAGE": conf})
    return conf


def _results(results: Path) -> list[str]:
    return sorted(p.relative_to(results).as_posix() for p in results.rglob("*") if p.is_file())


@pytest.mark.skipif(not consts.POSIX, reason="requires symlinks")
def test_search_skips_symlinks(tmp_path, pillage_config):  # noqa: ARG001
    secret = tmp_path / "host_secret.txt"
    secret.write_text("root:x:0:0:root:/root:/bin/bash\n", encoding="utf-8")
    source = tmp_path / "source"
    (source / "sub").mkdir(parents=True)
    (source / "sub" / "SET_ALL.TXT").write_text("real relay settings", encoding="utf-8")
    (source / "station.apx").symlink_to(secret)  # symlink to a host file
    (source / "huge.rdb").symlink_to("/dev/null")  # symlink to a device node
    (source / "linked_dir").symlink_to(tmp_path, target_is_directory=True)

    results = tmp_path / "results"
    assert search(source, results) is True
    assert _results(results) == ["SEL/SET_ALL.TXT"]


@pytest.mark.skipif(not consts.POSIX, reason="requires FIFOs")
def test_search_skips_fifo(tmp_path, pillage_config):  # noqa: ARG001
    source = tmp_path / "source"
    source.mkdir()
    os.mkfifo(source / "pipe.rdb")  # would block a plain open()
    (source / "SET_ALL.TXT").write_text("real relay settings", encoding="utf-8")

    results = tmp_path / "results"
    assert search(source, results) is True
    assert _results(results) == ["SEL/SET_ALL.TXT"]


def test_search_skips_oversized_files(tmp_path, pillage_config):
    pillage_config["max_file_size"] = 10
    source = tmp_path / "source"
    source.mkdir()
    (source / "small.rdb").write_bytes(b"x" * 10)
    (source / "big.rdb").write_bytes(b"x" * 11)

    results = tmp_path / "results"
    assert search(source, results) is True
    assert _results(results) == ["SEL/small.rdb"]


def test_search_excluded_dirs_absolute_source(tmp_path, pillage_config):  # noqa: ARG001
    source = (tmp_path / "mnt" / "image").resolve()  # absolute, multi-component path
    (source / "Windows" / "System32").mkdir(parents=True)
    (source / "Windows" / "System32" / "set_all.txt").write_text("x", encoding="utf-8")
    (source / "Users" / "Windows").mkdir(parents=True)
    (source / "Users" / "Windows" / "set_all.txt").write_text("y", encoding="utf-8")

    results = tmp_path / "results"
    assert search(source, results) is True
    # Only top-level excluded directories are skipped
    assert _results(results) == ["SEL/set_all.txt"]
    assert (results / "SEL" / "set_all.txt").read_text(encoding="utf-8") == "y"


@pytest.fixture
def sys_block(mocker, tmp_path):
    """Fake /sys/block with Network Block Devices: nbd0 and nbd1 in use, nbd2 free."""
    block = tmp_path / "sys_block"
    for name, size, pid in [
        ("nbd0", "0", "1234"),  # connected (has a pid), e.g. by another program
        ("nbd1", "2097152", None),  # has a size
        ("nbd2", "0", None),
        ("nbd10", "0", None),
        ("loop0", "0", None),
    ]:
        (block / name).mkdir(parents=True)
        (block / name / "size").write_text(f"{size}\n", encoding="utf-8")
        if pid:
            (block / name / "pid").write_text(f"{pid}\n", encoding="utf-8")
    mocker.patch.object(pillage_api, "SYS_BLOCK_DIR", block, create=True)
    mocker.patch.object(pillage_api, "NBD_DEVICE", None, create=True)
    return block


def test_mount_image_hardened_options(mocker, tmp_path, sys_block):  # noqa: ARG001
    mocker.patch("peat.api.pillage_api.list_loaded_modules", return_value=["nbd"])
    mocker.patch("peat.api.pillage_api.time.sleep")
    call = mocker.patch("peat.api.pillage_api.subprocess.call", return_value=0)

    assert mount_image(tmp_path / "disk.img", tmp_path / "mnt") is True
    mount_args = next(c.args[0] for c in call.call_args_list if c.args[0][0] == "mount")
    options = mount_args[mount_args.index("-o") + 1].split(",")
    assert {"ro", "nodev", "nosuid", "noexec"} <= set(options)


def test_search_size_limit_enforced_while_copying(mocker, tmp_path, pillage_config):
    # e.g. a pseudo-file (procfs/sysfs) that reports a size of 0, or a file
    # that grows after it's checked
    pillage_config["max_file_size"] = 10
    source = tmp_path / "source"
    source.mkdir()
    (source / "small.rdb").write_bytes(b"x" * 10)
    (source / "grows.rdb").write_bytes(b"x" * 11)

    real_lstat = os.lstat

    def lstat_reports_zero(path, *args, **kwargs):
        st = real_lstat(path, *args, **kwargs)
        if Path(path).name != "grows.rdb":
            return st
        return os.stat_result((*tuple(st)[:6], 0, *tuple(st)[7:]))

    mocker.patch("peat.api.pillage_api.os.lstat", side_effect=lstat_reports_zero)

    results = tmp_path / "results"
    assert search(source, results) is True
    assert _results(results) == ["SEL/small.rdb"]


@pytest.mark.skipif(os.open not in os.supports_dir_fd, reason="requires dir_fd support")
def test_copy_file_symlinked_parent_dir(tmp_path):
    # e.g. a directory swapped for a symbolic link after os.walk() listed it
    source = tmp_path / "source"
    source.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "SET_ALL.TXT").write_text("host file", encoding="utf-8")
    (source / "real").mkdir()
    (source / "real" / "SET_ALL.TXT").write_text("relay settings", encoding="utf-8")
    (source / "swapped").symlink_to(outside, target_is_directory=True)

    dst = tmp_path / "results" / "SET_ALL.TXT"
    assert copy_file(source / "swapped" / "SET_ALL.TXT", dst, base=source) is False
    assert not dst.exists()

    assert copy_file(source / "real" / "SET_ALL.TXT", dst, base=source) is True
    assert dst.read_text(encoding="utf-8") == "relay settings"


@pytest.mark.parametrize(
    ("option", "filename", "expected"),
    [
        (None, "disk.qcow2", "raw"),  # the default is raw, never probed
        ("raw", "disk.qcow2", "raw"),
        ("QCOW2", "disk.img", "qcow2"),
        ("vmdk", "disk.img", "vmdk"),
        ("auto", "disk.qcow2", "qcow2"),
        ("auto", "disk.VHDX", "vhdx"),
        ("auto", "disk.vhd", "vpc"),
        ("auto", "disk.dd", "raw"),
        ("auto", "disk", "raw"),
        ("bochs", "disk.img", None),  # not a supported format
    ],
)
def test_get_image_format(mocker, option, filename, expected):
    mocker.patch.dict(config["CONFIG"], {"PILLAGE": {"image_format": option}})
    assert pillage_api.get_image_format(Path(filename)) == expected


def test_find_free_nbd_device(sys_block):
    assert pillage_api.find_free_nbd_device() == "/dev/nbd2"
    (sys_block / "nbd2" / "pid").write_text("99", encoding="utf-8")
    assert pillage_api.find_free_nbd_device() == "/dev/nbd10"
    (sys_block / "nbd10" / "size").write_text("512", encoding="utf-8")
    assert pillage_api.find_free_nbd_device() is None


@pytest.mark.parametrize(("option", "expected"), [(None, "raw"), ("vdi", "vdi")])
def test_mount_image_qemu_nbd_args(mocker, tmp_path, sys_block, option, expected):  # noqa: ARG001
    """qemu-nbd must be given the format (no probing) and a free device (not nbd1)."""
    mocker.patch.dict(config["CONFIG"], {"PILLAGE": {"image_format": option}})
    mocker.patch("peat.api.pillage_api.list_loaded_modules", return_value=["nbd"])
    mocker.patch("peat.api.pillage_api.time.sleep")
    mocker.patch("peat.api.pillage_api.subprocess.check_output", return_value=b"{}")
    call = mocker.patch("peat.api.pillage_api.subprocess.call", return_value=0)
    image = tmp_path / "disk.img"

    assert mount_image(image, tmp_path / "mnt") is True
    nbd_args = call.call_args_list[0].args[0]
    assert nbd_args == ["qemu-nbd", "-r", "-f", expected, "-c", "/dev/nbd2", str(image)]
    mount_args = call.call_args_list[1].args[0]
    assert mount_args[0] == "mount"
    assert "/dev/nbd2p1" in mount_args

    # Disconnects the device that was connected
    assert remove_nbd_device() is True
    assert call.call_args_list[2].args[0] == ["qemu-nbd", "-d", "/dev/nbd2"]


def test_mount_image_refuses_backing_file(mocker, tmp_path, sys_block):  # noqa: ARG001
    mocker.patch.dict(config["CONFIG"], {"PILLAGE": {"image_format": "qcow2"}})
    mocker.patch("peat.api.pillage_api.list_loaded_modules", return_value=["nbd"])
    info = b'{"format": "qcow2", "backing-filename": "/etc/shadow"}'
    check_output = mocker.patch("peat.api.pillage_api.subprocess.check_output", return_value=info)
    call = mocker.patch("peat.api.pillage_api.subprocess.call", return_value=0)
    image = tmp_path / "disk.qcow2"

    assert mount_image(image, tmp_path / "mnt") is False
    assert check_output.call_args.args[0] == [
        "qemu-img",
        "info",
        "--output=json",
        "-f",
        "qcow2",
        str(image),
    ]
    call.assert_not_called()


def test_mount_image_no_free_nbd_device(mocker, tmp_path, sys_block):
    mocker.patch.dict(config["CONFIG"], {"PILLAGE": {}})
    mocker.patch("peat.api.pillage_api.list_loaded_modules", return_value=["nbd"])
    call = mocker.patch("peat.api.pillage_api.subprocess.call", return_value=0)
    for name in ["nbd2", "nbd10"]:
        (sys_block / name / "pid").write_text("1", encoding="utf-8")

    assert mount_image(tmp_path / "disk.img", tmp_path / "mnt") is False
    call.assert_not_called()
    # Nothing was connected, so nothing (e.g. another program's nbd1) is disconnected
    assert remove_nbd_device() is True
    call.assert_not_called()
