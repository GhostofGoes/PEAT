import os
import shutil
from pathlib import Path

import pytest

from peat import __version__, config, datastore, state, utils
from peat.api import disk_image_api
from peat.api.parse_api import collect_file_patterns, parse, pillage


def test_parse_api_parse_bad_args(top_datapath, tmp_path, mocker):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "SUMMARIES_DIR": tmp_path / "summaries",
            "TEMP_DIR": tmp_path / "temp",
        },
    )
    mocker.patch.object(datastore, "objects", [])

    assert parse(top_datapath("test_load_from_file.json"), ["nopeinvaliddev"]) is None
    assert parse(top_datapath("test_load_from_file.json"), []) is None
    assert parse([top_datapath("test_load_from_file.json")], ["nopeinvaliddev"]) is None
    assert parse([top_datapath("test_load_from_file.json")], []) is None


def test_parse_api_parse_failures(top_datapath, tmp_path, mocker, assert_glob_path):
    parse_path = tmp_path / "summaries"
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "SUMMARIES_DIR": parse_path,
            "TEMP_DIR": tmp_path / "temp",
            "DEBUG": 1,
        },
    )
    mocker.patch.object(datastore, "objects", [])

    summary = parse([top_datapath("test_load_from_file.json")], ["SCEPTRE"])  # type: dict

    assert summary
    assert summary["peat_version"] == __version__
    assert summary["peat_run_id"]
    assert summary["parse_duration"]
    assert summary["parse_modules"] == ["SCEPTRE"]
    assert summary["input_paths"] == [top_datapath("test_load_from_file.json")]
    assert len(summary["files_parsed"]) == 1
    assert summary["num_files_parsed"] == 1
    assert summary["num_parse_successes"] == 0
    assert summary["num_parse_failures"] == 1
    assert len(summary["parse_failures"]) == 1
    assert not summary["parse_results"]

    assert_glob_path(parse_path, "parse-summary.json")


# Data from: https://github.com/sandialabs/sceptre-bennu/tree/main/data/configs
def test_parse_api_multiple_files(test_dir, tmp_path, mocker, assert_glob_path, assert_no_errors):
    parse_path = tmp_path / "summaries"
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "SUMMARIES_DIR": parse_path,
            "TEMP_DIR": tmp_path / "temp",
            "DEBUG": 1,
        },
    )
    mocker.patch.object(datastore, "objects", [])

    datafiles_path = test_dir / "modules" / "sandia" / "data_files"
    paths = [
        datafiles_path / "bp" / "dnp3-client.xml",
        datafiles_path / "ep" / "bacnet-client.xml",
        datafiles_path / "ep" / "sunspec-server.xml",
    ]
    modules = ["SCEPTRE", "SELRelay"]

    summary = parse(paths, modules)  # type: dict

    assert summary
    assert summary["peat_version"] == __version__
    assert summary["peat_run_id"]
    assert summary["parse_duration"]
    assert summary["parse_modules"] == modules
    assert "input_path" not in summary  # ensure old variable name isn't present
    assert summary["input_paths"] == paths
    assert len(summary["files_parsed"]) == 3
    assert summary["num_files_parsed"] == 3
    assert summary["num_parse_successes"] == 3
    assert summary["num_parse_failures"] == 0
    assert not summary["parse_failures"]
    assert len(summary["parse_results"]) == 3

    assert_glob_path(parse_path, "parse-summary.json")
    assert_no_errors()


@pytest.fixture
def parse_config(tmp_path, mocker):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "SUMMARIES_DIR": tmp_path / "summaries",
            "TEMP_DIR": tmp_path / "temp",
            "PARSE_FILES_DIR": tmp_path / "parse_files",
            "DEBUG": 1,
        },
    )
    mocker.patch.object(datastore, "objects", [])
    mocker.patch.dict(state["CONFIG"], {"error": False})
    return tmp_path / "parse_files"


@pytest.fixture
def sceptre_dir(test_dir, tmp_path) -> Path:
    """
    A directory tree with the SCEPTRE configs from sceptre-bennu, and a file
    that isn't parsed by any module, ``hashtest.txt`` (from tests/data_files).
    """
    source = tmp_path / "source"
    shutil.copytree(test_dir / "modules" / "sandia" / "data_files", source / "Projects")
    shutil.copy(test_dir / "data_files" / "hashtest.txt", source / "Projects" / "bp")
    return source


SCEPTRE_FILES = ["Projects/bp/dnp3-client.xml", "Projects/ep/bacnet-client.xml"]


def _files(path: Path) -> list[str]:
    return sorted(p.relative_to(path).as_posix() for p in path.rglob("*") if p.is_file())


def _fake_search_image(volumes: list[Path], result: bool = True, calls: list | None = None):
    """Fake :func:`disk_image_api.search_image`, with volumes that are directories."""

    def _search_image(image, handler, password_file=None):
        if calls is not None:
            calls.append((image, password_file))
        for volume in volumes:
            handler(str(volume))
        return result

    return _search_image


def test_parse_directory_not_copied(parse_config, sceptre_dir):
    summary = parse(sceptre_dir, ["SCEPTRE"])
    assert summary["num_parse_successes"] == 3
    assert summary["disk_images"] == []
    assert summary["files_collected"] == []
    assert not parse_config.exists()


def test_parse_copy_files(parse_config, sceptre_dir, assert_no_errors):
    summary = parse(sceptre_dir, ["SCEPTRE"], copy_files=True)
    assert summary["num_parse_successes"] == 3
    # Paths relative to the directory are kept, and files that aren't parsed aren't copied
    assert _files(parse_config) == [
        "source/Projects/bp/dnp3-client.xml",
        "source/Projects/ep/bacnet-client.xml",
        "source/Projects/ep/sunspec-server.xml",
    ]
    original = sceptre_dir / "Projects" / "bp" / "dnp3-client.xml"
    copy = parse_config / "source" / "Projects" / "bp" / "dnp3-client.xml"
    assert copy.read_bytes() == original.read_bytes()
    assert_no_errors()


def test_parse_copy_files_single_file(parse_config, sceptre_dir):
    file = sceptre_dir / "Projects" / "bp" / "dnp3-client.xml"
    other = sceptre_dir / "Projects" / "ep" / "bacnet-client.xml"
    shutil.copy(other, sceptre_dir / "dnp3-client.xml")  # Same name, different file

    summary = parse([file, sceptre_dir / "dnp3-client.xml"], ["SCEPTRE"], copy_files=True)
    assert summary["num_parse_successes"] == 2
    assert _files(parse_config) == ["dnp3-client.xml", "dnp3-client.xml_2"]
    assert (parse_config / "dnp3-client.xml_2").read_bytes() == other.read_bytes()


@pytest.mark.usefixtures("parse_config")
def test_parse_not_recursive(sceptre_dir, mocker):
    shutil.copy(sceptre_dir / "Projects" / "ep" / "sunspec-server.xml", sceptre_dir)
    summary = parse(sceptre_dir, ["SCEPTRE"], sub_dirs=False)
    assert summary["files_parsed"] == [(sceptre_dir / "sunspec-server.xml").as_posix()]

    mocker.patch.dict(config["CONFIG"], {"PARSE_RECURSIVE": False})
    assert parse(sceptre_dir, ["SCEPTRE"])["num_files_parsed"] == 1


def test_parse_collect_file_patterns(parse_config, sceptre_dir, mocker):
    mocker.patch.dict(config["CONFIG"], {"COLLECT_FILE_PATTERNS": ["HASHTEST.*", "*.xml"]})
    summary = parse(sceptre_dir, ["SCEPTRE"])

    # Files that are parsed aren't collected, even if they match a pattern
    assert summary["num_parse_successes"] == 3
    assert summary["files_collected"] == [
        (parse_config / "source" / "Projects" / "bp" / "hashtest.txt").as_posix()
    ]
    assert summary["num_files_collected"] == 1
    assert _files(parse_config) == ["source/Projects/bp/hashtest.txt"]


@pytest.mark.usefixtures("parse_config")
def test_parse_pillage_config_deprecated(sceptre_dir, mocker, caplog):
    pillage_config = {
        "auto_copy": False,
        "recursive": False,
        "default": {"locations": [], "filenames": [], "extensions": []},
        "brands": {"Other": {"filenames": ["HashTest.txt"], "extensions": ["rdb"]}},
    }
    mocker.patch.dict(config["CONFIG"], {"PILLAGE": pillage_config})
    assert collect_file_patterns() == ["HashTest.txt", "*.rdb"]
    assert "'pillage' configuration section is deprecated" in caplog.text

    summary = parse(sceptre_dir, ["SCEPTRE"])
    assert summary["num_files_collected"] == 1
    assert summary["num_parse_successes"] == 3  # "recursive" is ignored


def test_parse_disk_image(parse_config, sceptre_dir, tmp_path, mocker, assert_no_errors):
    image = tmp_path / "workstation.vmdk"
    shutil.copy(sceptre_dir / "Projects" / "bp" / "hashtest.txt", image)
    # A second volume, with a system directory in its root that's skipped
    volume2 = tmp_path / "volume2"
    (volume2 / "Windows").mkdir(parents=True)
    shutil.copy(sceptre_dir / "Projects" / "ep" / "bacnet-client.xml", volume2 / "Windows")
    shutil.copy(sceptre_dir / "Projects" / "ep" / "sunspec-server.xml", volume2)
    calls = []
    mocker.patch.object(
        disk_image_api, "search_image", _fake_search_image([sceptre_dir, volume2], calls=calls)
    )
    mocker.patch.dict(config["CONFIG"], {"COLLECT_FILE_PATTERNS": ["hashtest.txt"]})

    summary = parse(image, ["SCEPTRE"], password_file="passwords.txt")
    assert calls == [(image, "passwords.txt")]
    assert summary["disk_images"] == [image.as_posix()]

    # The files on the image are copied, then the copies are parsed
    image_dir = parse_config / "workstation.vmdk"
    assert _files(image_dir) == [
        "volume_1/Projects/bp/dnp3-client.xml",
        "volume_1/Projects/bp/hashtest.txt",
        "volume_1/Projects/ep/bacnet-client.xml",
        "volume_1/Projects/ep/sunspec-server.xml",
        "volume_2/sunspec-server.xml",
    ]
    assert summary["num_parse_successes"] == 4
    assert all(path.startswith(image_dir.as_posix()) for path in summary["files_parsed"])
    assert summary["files_collected"] == [
        (image_dir / "volume_1" / "Projects" / "bp" / "hashtest.txt").as_posix()
    ]
    assert not state.error
    assert_no_errors()


@pytest.mark.usefixtures("parse_config")
def test_parse_disk_image_search_fails(tmp_path, mocker):
    image = tmp_path / "workstation.vhdx"
    image.write_bytes(b"")
    mocker.patch.object(disk_image_api, "search_image", _fake_search_image([], result=False))

    summary = parse(image, ["SCEPTRE"])
    assert summary["disk_images"] == [image.as_posix()]
    assert summary["num_files_parsed"] == 0
    assert state.error


@pytest.mark.usefixtures("parse_config")
def test_parse_disk_image_without_parse_files_dir(sceptre_dir, tmp_path, mocker):
    image = tmp_path / "workstation.qcow2"
    image.write_bytes(b"")
    mocker.patch.object(disk_image_api, "search_image", _fake_search_image([sceptre_dir]))
    mocker.patch.dict(config["CONFIG"], {"PARSE_FILES_DIR": None})

    summary = parse(image, ["SCEPTRE"])
    assert summary["num_parse_successes"] == 3
    # The copies are parsed from a temporary directory, which is deleted
    assert not any(Path(path).exists() for path in summary["files_parsed"])


@pytest.mark.usefixtures("parse_config")
def test_parse_disk_image_parsed_by_module(sceptre_dir, mocker):
    """Files with a disk image extension are parsed if a module parses them."""
    image = sceptre_dir / "config.img"
    shutil.copy(sceptre_dir / "Projects" / "bp" / "dnp3-client.xml", image)
    search_image = mocker.patch.object(disk_image_api, "search_image")

    summary = parse(image, ["SCEPTRE"])
    assert summary["num_parse_successes"] == 1
    assert summary["disk_images"] == []
    search_image.assert_not_called()


@pytest.mark.usefixtures("parse_config")
def test_parse_password_file_not_image(sceptre_dir, caplog):
    assert parse(sceptre_dir, ["SCEPTRE"], password_file="passwords.txt")
    assert "Ignoring the password file" in caplog.text


def test_pillage_deprecated(parse_config, sceptre_dir, caplog):
    assert pillage(str(sceptre_dir)) is True
    assert "'peat pillage' is deprecated" in caplog.text
    assert len(_files(parse_config)) == 3  # Files are always copied

    assert pillage(str(sceptre_dir / "nonexistent")) is False


def test_parse_skips_output_dirs(parse_config, sceptre_dir, mocker):
    """The results of earlier runs aren't parsed or copied again, e.g. 'peat parse .'"""
    out_dir = sceptre_dir / "peat_results"
    shutil.copytree(sceptre_dir / "Projects", out_dir / "old_run" / "parse_files" / "Projects")
    mocker.patch.dict(config["CONFIG"], {"OUT_DIR": out_dir})

    summary = parse(sceptre_dir, ["SCEPTRE"], copy_files=True)
    assert summary["num_parse_successes"] == 3
    assert not any("peat_results" in path for path in summary["files_parsed"])
    assert len(_files(parse_config)) == 3


def test_parse_copy_and_collect_same_directory(parse_config, sceptre_dir, mocker):
    mocker.patch.dict(config["CONFIG"], {"COLLECT_FILE_PATTERNS": ["hashtest.txt"]})
    parse(sceptre_dir, ["SCEPTRE"], copy_files=True)
    # Copied and collected files go in the same directory
    assert [p.name for p in parse_config.iterdir()] == ["source"]
    assert len(_files(parse_config)) == 4


@pytest.mark.usefixtures("parse_config")
def test_parse_copy_files_without_parse_files_dir(sceptre_dir, mocker, caplog):
    mocker.patch.dict(config["CONFIG"], {"PARSE_FILES_DIR": None})
    assert parse(sceptre_dir, ["SCEPTRE"], copy_files=True)["num_parse_successes"] == 3
    assert "PARSE_FILES_DIR isn't set" in caplog.text


def test_parse_disk_image_not_recursive(parse_config, sceptre_dir, tmp_path, mocker):
    """Only the top directory of volumes is searched, but the copies are still parsed."""
    image = tmp_path / "workstation.vmdk"
    image.write_bytes(b"")
    shutil.copy(sceptre_dir / "Projects" / "ep" / "sunspec-server.xml", sceptre_dir)
    mocker.patch.object(disk_image_api, "search_image", _fake_search_image([sceptre_dir]))

    summary = parse(image, ["SCEPTRE"], sub_dirs=False)
    assert summary["files_parsed"] == [
        (parse_config / "workstation.vmdk" / "volume_1" / "sunspec-server.xml").as_posix()
    ]


@pytest.mark.skipif(not hasattr(os, "symlink") or os.name == "nt", reason="POSIX-only")
def test_parse_disk_image_links_outside_volume(parse_config, sceptre_dir, tmp_path, mocker):
    """Links on an image to files outside the volume (e.g. on the host) aren't followed."""
    image = tmp_path / "workstation.vmdk"
    image.write_bytes(b"")
    outside = tmp_path / "host"
    outside.mkdir()
    shutil.copy(sceptre_dir / "Projects" / "ep" / "sunspec-server.xml", outside / "host.xml")
    os.symlink(outside / "host.xml", sceptre_dir / "link.xml")
    os.symlink("bp/dnp3-client.xml", sceptre_dir / "Projects" / "inside.xml")
    mocker.patch.object(disk_image_api, "search_image", _fake_search_image([sceptre_dir]))

    summary = parse(image, ["SCEPTRE"])
    copied = _files(parse_config / "workstation.vmdk")
    assert "volume_1/link.xml" not in copied
    assert not any("host.xml" in path for path in copied)
    assert summary["num_parse_successes"] == 3


@pytest.mark.usefixtures("parse_config")
def test_parse_disk_image_collect_without_parse_files_dir(sceptre_dir, tmp_path, mocker):
    image = tmp_path / "workstation.vmdk"
    image.write_bytes(b"")
    mocker.patch.object(disk_image_api, "search_image", _fake_search_image([sceptre_dir]))
    mocker.patch.dict(
        config["CONFIG"], {"PARSE_FILES_DIR": None, "COLLECT_FILE_PATTERNS": ["hashtest.txt"]}
    )

    summary = parse(image, ["SCEPTRE"])
    assert summary["files_collected"] == []  # Not listed, since they'd be deleted
    assert summary["num_parse_successes"] == 3


def test_parse_copy_failure_is_an_error(parse_config, sceptre_dir, mocker):
    mocker.patch.object(utils, "copy_file", side_effect=PermissionError(13, "Permission denied"))
    assert parse(sceptre_dir, ["SCEPTRE"], copy_files=True)
    assert not parse_config.exists()
    assert state.error
