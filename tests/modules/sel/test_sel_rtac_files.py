"""
Tests for the hashing of the files that the RTAC pull downloads or writes,
and the members of parsed RTAC project export tarballs.
"""

import hashlib
import io
import tarfile
from datetime import UTC, datetime

import pytest
import requests

from peat import SELRTAC, DeviceData, config, datastore
from peat.modules.sel import sel_rtac
from peat.modules.sel.sel_http import SELHTTP

RTAC_URL = "https://192.0.2.20:443"

# Synthetic files in the RTAC file repository (names and contents made up for the tests)
REPOSITORY_FILES = {
    "backup_config.tar.gz": b"\x1f\x8b\x08\x00 binary \x00\xff data",
    "notes.txt": b"Commissioned 2024-05-01\r\n",
}
# A synthetic Sequence of Events log, in the same CSV layout as soe.csv
SOE_CSV = b'"1","2024-05-01 12:00:00.000","Information","User admin logged in"\n'


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


@pytest.fixture
def dev(mocker, tmp_path) -> DeviceData:
    mocker.patch.dict(
        config["CONFIG"],
        {"DEVICE_DIR": tmp_path / "devices", "TEMP_DIR": tmp_path / "temp"},
    )
    mocker.patch.object(datastore, "objects", [])
    device = DeviceData(ip="192.0.2.20")
    device._module = SELRTAC
    return device


@pytest.fixture
def no_device_dir(mocker, dev):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": None})
    dev._out_dir = None


@pytest.fixture
def rtac_web(requests_mock):
    """Mocked RTAC web server for the file repository and the SOE log."""

    def _download(request, context):
        filename = request.qs["filename"][0] if "filename" in request.qs else ""
        for name, content in REPOSITORY_FILES.items():
            if name.lower() == filename:
                return content
        context.status_code = 404
        return b"Not Found"

    requests_mock.post(f"{RTAC_URL}/download.sel", content=_download)
    requests_mock.get(f"{RTAC_URL}/soe.csv", content=SOE_CSV)
    return requests_mock


@pytest.fixture
def selhttp() -> SELHTTP:
    session = SELHTTP("192.0.2.20", 443, 5.0)
    session.rtac_logged_in = True
    session.session_id = "0123456789"
    return session


def _list_files(dev: DeviceData, names) -> None:
    dev.extra["web_files"] = {
        name: {"name": name, "size": 100, "timestamp": datetime(2024, 5, 1, 8, 30, tzinfo=UTC)}
        for name in names
    }


def _download_and_record(session, dev, syslog: bool = True):
    with sel_rtac._capture_downloads(session, SELRTAC._web_download_pages) as downloads:
        result = session.download_http_files(dev)
        if syslog:
            session.view_syslog(dev)
    SELRTAC._record_web_downloads(dev, downloads, "https")
    return result


# ---------- Web downloads ----------


@pytest.mark.usefixtures("rtac_web")
def test_repository_files_are_hashed(dev, selhttp):
    _list_files(dev, [*REPOSITORY_FILES, "missing.bin"])

    result = _download_and_record(selhttp, dev)
    assert result == {
        "backup_config.tar.gz": "success",
        "notes.txt": "success",
        "missing.bin": "failure",
    }

    files = {f.name: f for f in dev.files}
    # Only files from the repository are recorded, not other pages such as soe.csv
    assert set(files) == {"backup_config.tar.gz", "notes.txt"}
    assert (dev.get_out_dir() / "http_files" / "soe.csv").is_file()

    for name, content in REPOSITORY_FILES.items():
        recorded = files[name]
        assert recorded.hash.sha256 == sha256(content)
        assert recorded.hash.md5 == hashlib.md5(content).hexdigest().upper()
        assert recorded.size == len(content)
        assert recorded.local_path == (dev.get_out_dir() / name).resolve()
        assert recorded.local_path.read_bytes() == content
        assert recorded.mtime == datetime(2024, 5, 1, 8, 30, tzinfo=UTC)
        assert recorded.peat_module == "SELRTAC"
        assert recorded.extra == {
            "source": "web_download",
            "transport": "https",
            "listed_size": 100,
        }
        assert sha256(content) in dev.related.hash

    # The hook is removed after the downloads
    assert selhttp.session.hooks["response"] == []


@pytest.mark.usefixtures("rtac_web")
def test_repository_file_with_existing_name(dev, selhttp):
    # A file with the same name from an earlier pull
    existing = dev.get_out_dir() / "notes.txt"
    existing.parent.mkdir(parents=True)
    existing.write_bytes(b"old contents")
    _list_files(dev, ["notes.txt"])

    _download_and_record(selhttp, dev)

    recorded = next(f for f in dev.files if f.name == "notes.txt")
    # SELHTTP writes "notes.txt.1", which is the file with the hashed contents
    assert recorded.local_path == (dev.get_out_dir() / "notes.txt.1").resolve()
    assert recorded.hash.sha256 == sha256(REPOSITORY_FILES["notes.txt"])


@pytest.mark.usefixtures("no_device_dir", "rtac_web")
def test_repository_files_without_device_dir(dev, selhttp):
    _list_files(dev, REPOSITORY_FILES)

    # NOTE: SELHTTP.view_syslog() needs a device output directory
    _download_and_record(selhttp, dev, syslog=False)

    files = {f.name: f for f in dev.files}
    assert set(files) == set(REPOSITORY_FILES)
    for name, content in REPOSITORY_FILES.items():
        assert files[name].hash.sha256 == sha256(content)
        assert files[name].local_path is None


def test_capture_downloads_only_successful_downloads(requests_mock, selhttp):
    requests_mock.post(f"{RTAC_URL}/download.sel", status_code=500, content=b"error")
    requests_mock.post(f"{RTAC_URL}/index.sel", content=b"<html></html>")

    with sel_rtac._capture_downloads(selhttp, SELRTAC._web_download_pages) as downloads:
        selhttp.session.post(f"{RTAC_URL}/download.sel", params={"filename": "a.txt"})
        selhttp.session.post(f"{RTAC_URL}/index.sel")
    assert downloads == []

    # Removed even if there's an exception
    with pytest.raises(RuntimeError):
        with sel_rtac._capture_downloads(selhttp, ("/index.sel",)):
            raise RuntimeError("failed")
    assert selhttp.session.hooks["response"] == []


@pytest.mark.usefixtures("rtac_web")
def test_capture_downloads_keeps_only_hashes(dev, selhttp):
    # The responses (and their contents) aren't kept until the end of the pull
    _list_files(dev, REPOSITORY_FILES)

    with sel_rtac._capture_downloads(selhttp, SELRTAC._web_download_pages) as downloads:
        selhttp.download_http_files(dev)

    assert len(downloads) == len(REPOSITORY_FILES)
    for (url, digest), content in zip(downloads, REPOSITORY_FILES.values(), strict=True):
        assert isinstance(url, str)
        assert "/download.sel?" in url
        assert isinstance(digest, sel_rtac._Digest)
        assert digest.size == len(content)
        assert digest.sha256 == hashlib.sha256(content).hexdigest()
        assert digest.hashes["sha256"] == sha256(content)


def test_capture_downloads_hashing_error(mocker, requests_mock, selhttp, caplog):
    # A failure to hash a file doesn't break the download
    requests_mock.post(f"{RTAC_URL}/download.sel", content=b"data")
    mocker.patch.object(sel_rtac._Digest, "of", side_effect=ValueError("bad hash algorithm"))

    with sel_rtac._capture_downloads(selhttp, SELRTAC._web_download_pages) as downloads:
        response = selhttp.session.post(f"{RTAC_URL}/download.sel", params={"filename": "a"})

    assert response.content == b"data"
    assert downloads == []
    assert "Failed to hash the download" in caplog.text


class FakeDownloadsWeb:
    """Stand-in for SELHTTP that downloads one repository file and the SOE log."""

    def __init__(self):
        self.session = requests.Session()
        self.rtac_logged_in = True

    def disconnect(self):
        pass

    def _empty(self, _dev):
        return {}

    view_dashboard = view_usagepolicy = view_features = view_accounts = _empty
    view_user_roles = view_ldap = view_ip_tables = _empty

    def view_filesondevice(self, dev):
        dev.extra["web_files"] = {"notes.txt": {"name": "notes.txt", "size": 25}}
        return {"web_files": dev.extra["web_files"]}

    def download_http_files(self, dev):
        response = self.session.post(f"{RTAC_URL}/download.sel", params={"filename": "notes.txt"})
        dev.write_file(response.content, "notes.txt")
        return {"notes.txt": "success"}

    def view_syslog(self, dev):
        response = self.session.get(f"{RTAC_URL}/soe.csv")
        dev.write_file(response.text, "soe.csv", out_dir=dev.get_sub_dir("http_files"))
        return {"web_syslog_events": ["User admin logged in"]}


@pytest.mark.usefixtures("rtac_web")
def test_pull_web_hashes_downloads(dev, mocker):
    mocker.patch.object(sel_rtac, "sleep")
    dev._cache["web_session"] = FakeDownloadsWeb()

    SELRTAC.pull_web(dev, "https")

    files = {f.name: f for f in dev.files}
    assert set(files) == {"notes.txt", "pulled-web-config.json"}
    assert files["notes.txt"].hash.sha256 == sha256(REPOSITORY_FILES["notes.txt"])
    assert files["notes.txt"].extra["listed_size"] == 25
    assert files["notes.txt"].local_path.read_bytes() == REPOSITORY_FILES["notes.txt"]
    assert dev._cache["web_session"].session.hooks["response"] == []


# ---------- Files written by the pull ----------


class FakeCursor:
    """psycopg2 cursor with one row in "device_info" and nothing in other tables."""

    def __init__(self):
        self.description = None
        self._rows = []

    def execute(self, statement, _args=()):
        if statement == "SELECT * from device_info;":
            self.description = [("device_info_id",), ("host_name",), ("fw_release_version",)]
            self._rows = [(1, "SEL3530-4-0030A702E165", "R150")]
        else:
            self.description = None
            self._rows = []

    def fetchall(self):
        return self._rows

    def close(self):
        pass


class FakeConnection:
    def commit(self):
        pass

    def close(self):
        pass


def test_pull_postgres_files_are_hashed(dev):
    dev._cache["pg_conn"] = FakeConnection()
    dev._cache["pg_cursor"] = FakeCursor()

    config_data = SELRTAC.pull_postgres(dev)
    assert config_data["device_info"] == {
        1: {
            "device_info_id": 1,
            "host_name": "SEL3530-4-0030A702E165",
            "fw_release_version": "R150",
        }
    }
    assert dev.hostname == "SEL3530-4-0030A702E165"

    files = {f.name: f for f in dev.files}
    assert set(files) == {"raw-pulled-postgres-config.txt", "pulled-postgres-config.json"}
    for name, recorded in files.items():
        written = dev.get_out_dir() / name
        assert recorded.local_path == written.resolve()
        assert recorded.hash.sha256 == sha256(written.read_bytes())
        assert recorded.extra == {"source": "command_output", "transport": "postgres"}
    assert '"host_name": "SEL3530-4-0030A702E165"' in (
        dev.get_out_dir() / "pulled-postgres-config.json"
    ).read_text(encoding="utf-8")


def test_written_file_hashes_without_device_dir(dev, mocker):
    """The hash of a written file is the same if file output is disabled."""
    data = {"device_info": {"1": {"host_name": "SEL-3530", "count": 3}}}
    with_dir = SELRTAC._write_and_record_file(dev, data, "pulled-web-config.json", "derived")
    text = SELRTAC._write_and_record_file(dev, data, "raw-config.txt", "derived")

    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": None})
    dev2 = DeviceData(ip="192.0.2.21")
    without_dir = SELRTAC._write_and_record_file(dev2, data, "pulled-web-config.json", "derived")
    text2 = SELRTAC._write_and_record_file(dev2, data, "raw-config.txt", "derived")

    assert with_dir.local_path is not None
    assert without_dir.local_path is None
    assert with_dir.hash == without_dir.hash
    assert with_dir.hash.sha256 == sha256(with_dir.local_path.read_bytes())
    assert text.hash == text2.hash
    assert text.hash.sha256 == sha256(str(data).encode("utf-8"))


def test_written_file_with_existing_name(dev):
    first = SELRTAC._write_and_record_file(dev, "first", "ssl-certificate.pem", "derived")
    second = SELRTAC._write_and_record_file(dev, "second", "ssl-certificate.pem", "derived")

    assert first.local_path.name == "ssl-certificate.pem"
    assert second.local_path.name == "ssl-certificate.pem.1"
    assert second.local_path.read_text(encoding="utf-8") == "second"
    assert second.hash.sha256 == sha256(b"second")
    assert [f.name for f in dev.files] == ["ssl-certificate.pem", "ssl-certificate.pem"]


# ---------- Parsed project export tarballs ----------


def _tarball(path, members: dict[str, bytes], mtime: int = 1714552200):
    with tarfile.open(path, "w:gz") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = mtime
            tar.addfile(info, io.BytesIO(data))


def test_parsed_tarball_members_are_hashed(dev, tmp_path):
    main_controller = (
        b"<RTACModule><MainController><MainTask><CycleTime>100</CycleTime>"
        b"</MainTask></MainController></RTACModule>"
    )
    members = {
        "export/SEL_RTAC/System/Main Controller.xml": main_controller,
        "export/SEL_RTAC/project.selaprj": b"\x00\xff\xfe binary data",
        "../escape.xml": main_controller,
    }
    tarball = tmp_path / "hashing-rtac.tar.gz"
    _tarball(tarball, members)

    parsed = SELRTAC._parse(tarball, dev)

    files = {str(f.path): f for f in parsed.files}
    # Unsafe members aren't extracted or recorded
    assert set(files) == {
        "export/SEL_RTAC/System/Main Controller.xml",
        "export/SEL_RTAC/project.selaprj",
    }
    for member_name, recorded in files.items():
        data = members[member_name]
        assert recorded.hash.sha256 == sha256(data)
        assert recorded.size == len(data)
        assert (
            recorded.local_path
            == (parsed.get_out_dir() / "extracted_files" / member_name).resolve()
        )
        assert recorded.local_path.read_bytes() == data
        assert recorded.mtime == datetime.fromtimestamp(1714552200, UTC)
        assert recorded.extra == {"source": "parse_input", "archive": "hashing-rtac.tar.gz"}
        assert member_name in parsed.related.files
    assert files["export/SEL_RTAC/project.selaprj"].name == "project.selaprj"


def test_parsed_tarball_member_with_invalid_mtime(dev, tmp_path):
    # An out-of-range modification time (saved in a pax header) doesn't stop the parse
    members = {"export/SEL_RTAC/notes.txt": b"made by hand"}
    tarball = tmp_path / "mtime-rtac.tar.gz"
    _tarball(tarball, members, mtime=10**12)
    with tarfile.open(tarball) as tar:
        assert tar.getmembers()[0].mtime == 10**12
        assert sel_rtac._tar_member_mtime(tar.getmembers()[0]) is None

    parsed = SELRTAC._parse(tarball, dev)

    assert len(parsed.files) == 1
    recorded = parsed.files[0]
    assert recorded.hash.sha256 == sha256(b"made by hand")
    assert str(recorded.path) == "export/SEL_RTAC/notes.txt"
    assert recorded.local_path.read_bytes() == b"made by hand"
    # Without a valid time in the tarball, the data model uses the time of the extracted file
    assert recorded.mtime == datetime.fromtimestamp(recorded.local_path.stat().st_mtime)


@pytest.mark.usefixtures("no_device_dir")
def test_parsed_tarball_members_without_device_dir(dev, tmp_path):
    members = {"export/SEL_RTAC/notes.txt": b"no output directory"}
    tarball = tmp_path / "nodir-rtac.tar.gz"
    _tarball(tarball, members, mtime=0)

    parsed = SELRTAC._parse(tarball, dev)

    assert len(parsed.files) == 1
    assert parsed.files[0].hash.sha256 == sha256(b"no output directory")
    assert parsed.files[0].local_path is None
    assert parsed.files[0].mtime is None
