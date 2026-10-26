import io
import tarfile

from peat import DeviceData, config, datastore
from peat.modules.sel.sel_rtac import SELRTAC


def _add_file(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    tar.addfile(info, io.BytesIO(data))


def test_rtac_parse_tarball_unsafe_members_skipped(mocker, tmp_path):
    mocker.patch.object(datastore, "objects", [])
    mocker.patch.dict(
        config["CONFIG"], {"DEVICE_DIR": tmp_path / "devices", "TEMP_DIR": tmp_path / "temp"}
    )
    xml = b"<?xml version='1.0'?><Root></Root>"

    # Malicious RTAC export built in the test (never stored in the repository)
    archive = tmp_path / "input" / "rtacexport.tar.gz"
    archive.parent.mkdir()
    with tarfile.open(archive, "w:gz") as tar:
        _add_file(tar, "Project/benign.xml", xml)
        _add_file(tar, "../../../../../rtac_traversal.xml", xml)
        _add_file(tar, "/rtac_absolute.xml", xml)
        link = tarfile.TarInfo("Project/passwd.xml")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tar.addfile(link)

    dev = DeviceData(ip="127.0.0.1")
    SELRTAC._parse(archive, dev)

    extracted = dev.get_out_dir() / "extracted_files"
    names = sorted(p.relative_to(extracted).as_posix() for p in extracted.rglob("*.xml"))
    # The traversal member is skipped, the leading "/" is stripped from the absolute one
    assert names == ["Project/benign.xml", "rtac_absolute.xml"]
    assert "Project/passwd.xml" not in dev.extra["existing_files"]
    assert not list(tmp_path.rglob("rtac_traversal.xml"))
