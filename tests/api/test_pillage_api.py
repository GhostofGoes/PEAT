import os
from pathlib import Path

import pytest

from peat import config, consts
from peat.api.pillage_api import (
    check_file_conditions,
    is_valid_file,
    mount_image,
    pillage,
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


def test_mount_image_hardened_options(mocker, tmp_path):
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
